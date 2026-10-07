"""Offline privacy and media-API tests; no school credentials or ML packages."""
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

import private_material_worker as worker


def sample_manifest():
    return {
        'version': 1, 'job_id': 'b' * 32,
        'lecture': {'course_id': '100', 'sub_id': '200', 'course_title': '示例课程',
                    'sub_title': '第一讲', 'date': '2026-10-07', 'duration_hint_s': 0},
        'transcript_segments': [{'start_ms': 0, 'end_ms': 1000, 'text': '官方讲课文字'}],
        'audio': None, 'ppt': [],
    }


def real_bucketer_without_image_dependencies():
    # Exercise the real bucketer formatting while avoiding its unrelated image
    # hash/Pillow imports. Text-dedup internals have their own upstream tests.
    dedup = types.ModuleType('src.ai.ppt_dedup')
    dedup.clean_ppt_text = lambda text: text
    dedup.dedup_text_subset = lambda pages: pages
    path = Path(__file__).parent / 'src' / 'ai' / 'bucketer.py'
    spec = importlib.util.spec_from_file_location('_test_offline_bucketer', path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'src.ai.ppt_dedup': dedup}):
        spec.loader.exec_module(module)
    return lambda transcript, segments, pages: module.assemble(transcript, segments, pages)[0]


class MaterialWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.zip_path = self.root / 'bundle.zip'
        self.work_dir = self.root / 'processing'
        self.addCleanup(patch.stopall)
        patch.object(worker, '_assemble_prompt', real_bucketer_without_image_dependencies()).start()

    def write_bundle(self, manifest=None, files=None, extra=None, raw_manifest=None):
        manifest = sample_manifest() if manifest is None else manifest
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.zip_path, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json', raw_manifest if raw_manifest is not None
                                 else json.dumps(manifest, ensure_ascii=False))
                for name, data in (files or {}).items():
                    archive.writestr(name, data)
                for name, data in extra or []:
                    archive.writestr(name, data)

    def run_bundle(self, **kwargs):
        result = worker.process_bundle(self.zip_path, self.work_dir, **kwargs)
        self.assertEqual(list(self.work_dir.iterdir()), [], 'expanded materials must be removed')
        return result

    def test_official_transcript_and_ocr_are_bucketed_without_asr(self):
        manifest = sample_manifest()
        manifest['ppt'] = [{'file': 'ppt/000001.jpg', 'created_sec': 20},
                           {'file': 'ppt/000002.jpg', 'created_sec': 620}]
        self.write_bundle(manifest, {'ppt/000001.jpg': b'fake image',
                                     'ppt/000002.jpg': b'fake image'})
        ocr = Mock(return_value='投影片上的定理')
        asr = Mock(side_effect=AssertionError('official transcript must skip ASR'))
        with patch.object(worker, '_check_image'):
            result = self.run_bundle(ocr_factory=lambda: ocr, transcriber_factory=asr)
        self.assertEqual(result['errors'], [])
        item = result['items'][0]
        self.assertEqual(item['sub_id'], '200')
        self.assertIn('官方讲课文字', item['prompt'])
        self.assertIn('投影片上的定理', item['prompt'])
        self.assertIn('10:20', item['prompt'])
        ocr.assert_called_once_with(b'fake image')
        asr.assert_not_called()

    def test_zip_traversal_absolute_and_unexpected_entries_rejected(self):
        for name in ('../escape.txt', '/tmp/escape.txt', 'C:/escape.txt',
                     'ppt/../../escape.jpg', 'ppt\\000001.jpg', 'password.txt'):
            with self.subTest(name=name):
                self.write_bundle(extra=[(name, b'sensitive')])
                self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_INVALID'])
                self.assertFalse((self.root / 'escape.txt').exists())

    def test_duplicate_and_symlink_entries_rejected(self):
        self.write_bundle(extra=[('manifest.json', b'{}')])
        self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_INVALID'])
        manifest = sample_manifest()
        manifest['ppt'] = [{'file': 'ppt/000001.jpg', 'created_sec': 0}]
        self.write_bundle(manifest)
        with zipfile.ZipFile(self.zip_path, 'a') as archive:
            entry = zipfile.ZipInfo('ppt/000001.jpg')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, '../outside')
        self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_INVALID'])

    def test_secret_fields_rejected_at_every_manifest_level(self):
        for location, field in [('root', 'cookies'), ('root', 'password'), ('root', 'api_key'),
                                ('lecture', 'authorization'), ('segment', 'url'), ('ppt', 'headers')]:
            with self.subTest(location=location, field=field):
                manifest = sample_manifest()
                files = {}
                if location == 'root':
                    manifest[field] = 'never upload this'
                elif location == 'lecture':
                    manifest['lecture'][field] = 'never upload this'
                elif location == 'segment':
                    manifest['transcript_segments'][0][field] = 'never upload this'
                else:
                    manifest['ppt'] = [{'file': 'ppt/000001.jpg', 'created_sec': 0,
                                        field: 'never upload this'}]
                    files['ppt/000001.jpg'] = b'fake'
                self.write_bundle(manifest, files)
                self.assertEqual(self.run_bundle(), {'items': [], 'errors': ['BUNDLE_INVALID']})

    def test_invalid_types_dates_duplicate_json_and_missing_files_rejected(self):
        bad_manifests = []
        for name, value in [('version', True), ('audio', 'https://icourse.fudan.edu.cn/video'),
                            ('transcript_segments', {'text': 'not a list'})]:
            manifest = sample_manifest()
            manifest[name] = value
            bad_manifests.append(manifest)
        for name, value in [('duration_hint_s', float('nan')), ('date', '2026-02-31'), ('course_id', 100)]:
            manifest = sample_manifest()
            manifest['lecture'][name] = value
            bad_manifests.append(manifest)
        manifest = sample_manifest()
        manifest['audio'] = 'audio.flac'
        bad_manifests.append(manifest)
        for manifest in bad_manifests:
            self.write_bundle(manifest)
            self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_INVALID'])
        self.write_bundle(raw_manifest='{"version":1,"version":1}')
        self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_INVALID'])

    def test_expansion_and_per_image_limits(self):
        manifest = sample_manifest()
        manifest['ppt'] = [{'file': 'ppt/000001.jpg', 'created_sec': 0}]
        self.write_bundle(manifest, {'ppt/000001.jpg': b'a' * 500})
        with patch.object(worker, 'MAX_PPT_BYTES', 100):
            self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_TOO_LARGE'])
        with patch.object(worker, 'MAX_UNPACKED', 400):
            self.assertEqual(self.run_bundle()['errors'], ['BUNDLE_TOO_LARGE'])

    def test_audio_uses_original_tail_interface_and_local_ffmpeg_only(self):
        manifest = sample_manifest()
        manifest['transcript_segments'] = []
        manifest['audio'] = 'audio.flac'
        manifest['lecture']['duration_hint_s'] = 1
        self.write_bundle(manifest, {'audio.flac': b'fLaCfake'})
        process = Mock(returncode=0)
        process.poll.return_value = 0
        process.wait.return_value = 0
        def spawn(command, **kwargs):
            self.assertIn('file,pipe', command)
            self.assertEqual(command[command.index('-i') - 1], 'flac')
            self.assertNotIn('-headers', command)
            self.assertTrue(all('http' not in value for value in command))
            self.assertEqual(kwargs['stderr'], worker.subprocess.DEVNULL)
            Path(command[-1]).write_bytes(b'\0' * 64000)
            return process
        transcriber = Mock()
        def transcribe(audio_path, ffmpeg_proc, stderr_chunks, timeout):
            self.assertTrue(Path(audio_path).is_file())
            self.assertEqual(Path(audio_path).suffix, '.f32le')
            self.assertIs(ffmpeg_proc, process)
            self.assertEqual(stderr_chunks, [])
            self.assertEqual(timeout, 18000)
            return '离线识别文字', [{'start_ms': 0, 'end_ms': 1000, 'text': '离线识别文字'}]
        transcriber.transcribe_tail.side_effect = transcribe
        with patch.object(worker.subprocess, 'Popen', side_effect=spawn):
            result = self.run_bundle(transcriber_factory=lambda: transcriber)
        self.assertEqual(result['errors'], [])
        self.assertIn('离线识别文字', result['items'][0]['prompt'])
        transcriber.transcribe_tail.assert_called_once()

    def test_incomplete_audio_never_reaches_asr(self):
        manifest = sample_manifest()
        manifest.update(audio='audio.flac', transcript_segments=[])
        manifest['lecture']['duration_hint_s'] = 100
        self.write_bundle(manifest, {'audio.flac': b'fLaCfake'})
        process = Mock(returncode=0)
        process.poll.return_value = 0
        def spawn(command, **kwargs):
            Path(command[-1]).write_bytes(b'\0' * 64000)
            return process
        factory = Mock()
        with patch.object(worker.subprocess, 'Popen', side_effect=spawn):
            self.assertEqual(self.run_bundle(transcriber_factory=factory)['errors'], ['AUDIO_INCOMPLETE'])
        factory.assert_not_called()

    def test_errors_and_logs_never_include_upstream_content(self):
        manifest = sample_manifest()
        manifest['ppt'] = [{'file': 'ppt/000001.jpg', 'created_sec': 0}]
        self.write_bundle(manifest, {'ppt/000001.jpg': b'fake'})
        def bad_ocr(_image):
            print('sensitive upstream diagnostic')
            raise RuntimeError('secret-token-in-url')
        captured = io.StringIO()
        with patch.object(worker, '_check_image'), patch('sys.stdout', captured), patch('sys.stderr', captured):
            result = self.run_bundle(ocr_factory=lambda: bad_ocr)
        self.assertEqual(captured.getvalue(), '')
        self.assertEqual(result['errors'], ['PPT_OCR_INCOMPLETE'])
        self.assertNotIn('secret-token', json.dumps(result))

    def test_upstream_bundle_error_is_still_sanitized(self):
        self.write_bundle()
        with patch.object(worker, '_assemble_prompt', side_effect=worker.BundleError('private secret')):
            result = self.run_bundle()
        self.assertEqual(result, {'items': [], 'errors': ['MATERIAL_PROCESSING_FAILED']})

    def test_expected_job_id_is_bound_before_media_processing(self):
        self.write_bundle()
        with patch.object(worker, '_process') as process:
            result = self.run_bundle(expected_job_id='c' * 32)
        self.assertEqual(result, {'items': [], 'errors': ['BUNDLE_INVALID']})
        process.assert_not_called()
        self.assertEqual(self.run_bundle(expected_job_id='b' * 32)['errors'], [])


if __name__ == '__main__':
    unittest.main()
