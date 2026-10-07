"""Offline privacy/routing/material tests; no real school, FFmpeg or credentials."""

import io
import json
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import private_material_collect as collect


JOB = "a" * 32
LECTURE = {"sub_id": "321", "sub_title": "课堂", "date": "2026-10-07", "has_playback": True, "duration_hint_s": 600}
SEGMENTS = [{"start_ms": 0, "end_ms": 600_000, "text": "课堂文字稿"}]


def response(chunks, *, url="https://icourse.fudan.edu.cn/media", status=200, headers=None):
    reply = Mock()
    reply.url = url
    reply.status_code = status
    reply.headers = headers or {}
    reply.iter_content.return_value = iter(chunks)
    return reply


class MaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.client = Mock()
        self.client.get_ppt_list.return_value = []
        self.client.get_transcript_segments.return_value = SEGMENTS
        self.space = patch.object(collect, "_ensure_space")
        self.space.start()
        self.addCleanup(self.space.stop)
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def run_collect(self, lecture=None):
        return collect.collect_lecture(self.client, "123", "课程", lecture or LECTURE, self.root, JOB)

    def read_manifest(self, path):
        with zipfile.ZipFile(path) as archive:
            return json.loads(archive.read("manifest.json")), archive.namelist()

    def test_official_transcript_no_video_and_strict_manifest(self):
        lecture = dict(LECTURE, password="secret-password", account="secret-account", url="https://secret.example")
        self.client.get_transcript_segments.return_value = [dict(SEGMENTS[0], cookie="secret-cookie")]
        self.client.get_ppt_list.return_value = [{"created_sec": 600, "pptimgurl": "https://icourse.fudan.edu.cn/a.jpg?token=secret-token", "account": "secret-account"}]
        self.client.vpn.get.return_value = response([b"dummy-image"])
        path = self.run_collect(lecture)
        manifest, names = self.read_manifest(path)
        self.assertEqual(set(manifest), {"version", "job_id", "lecture", "transcript_segments", "audio", "ppt"})
        self.assertEqual(set(manifest["lecture"]), {"course_id", "sub_id", "course_title", "sub_title", "date", "duration_hint_s"})
        self.assertEqual(manifest["transcript_segments"], SEGMENTS)
        self.assertIsNone(manifest["audio"])
        self.assertEqual(manifest["ppt"], [{"file": "ppt/000001.jpg", "created_sec": 600}])
        self.assertEqual(names, ["manifest.json", "ppt/000001.jpg"])
        serialized = json.dumps(manifest)
        for secret in ("secret-password", "secret-account", "secret-cookie", "secret-token", "https://"):
            self.assertNotIn(secret, serialized)
        self.client.get_sub_info.assert_not_called()
        self.client.get_video_url.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_unopened_lecture_never_downloaded(self):
        with self.assertRaisesRegex(collect.MaterialCollectionError, "未开放"):
            self.run_collect(dict(LECTURE, has_playback=False))
        self.client.get_ppt_list.assert_not_called()
        self.client.vpn.get.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_review_gate_nested_fallback_never_used(self):
        self.client.get_transcript_segments.return_value = []
        self.client.get_sub_info.return_value = {"content": {"playback": {"url": "https://icourse.fudan.edu.cn/hidden.mp4"}}}
        with self.assertRaisesRegex(collect.MaterialCollectionError, "未开放"):
            self.run_collect()
        self.client.get_video_url.assert_not_called()
        self.client.get_sub_detail.assert_not_called()
        self.client.sign_video_url.assert_not_called()
        self.client.vpn.get.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_gaps_and_tail_require_asr(self):
        self.assertTrue(collect._official_transcript_usable(SEGMENTS, 1800))
        self.assertFalse(collect._official_transcript_usable(SEGMENTS, 1801))
        self.assertFalse(collect._official_transcript_usable([{"start_ms": 1_200_001, "end_ms": 1_300_000}]))
        self.assertFalse(collect._official_transcript_usable(SEGMENTS + [{"start_ms": 1_800_001, "end_ms": 1_900_000}]))

    def test_unknown_duration_official_text_falls_back_to_normal_playback(self):
        self.assertFalse(collect._official_transcript_usable(SEGMENTS, 0))
        self.client.get_sub_info.return_value = {"content": {"playback": {"url": "https://icourse.fudan.edu.cn/hidden.mp4"}}}
        with self.assertRaisesRegex(collect.MaterialCollectionError, "未开放"):
            self.run_collect(dict(LECTURE, duration_hint_s=0))
        self.client.get_sub_info.assert_called_once()
        self.client.get_video_url.assert_not_called()
        self.client.vpn.get.assert_not_called()

    def test_cloud_segment_contract_limits_before_upload(self):
        for segments in ([SEGMENTS[0]] * 50_001,
                         [{"start_ms": 0, "end_ms": 86_400_001, "text": "overflow"}],
                         [{"start_ms": 0, "end_ms": 1, "text": "x" * 100_001}],
                         [{"start_ms": 0, "end_ms": 1, "text": "nul\x00text"}]):
            self.assertEqual(collect._transcript_segments(segments), [])
        self.assertEqual(collect._transcript_segments([{"start_ms": 0, "end_ms": 86_400_000, "text": "valid"}]),
                         [{"start_ms": 0, "end_ms": 86_400_000, "text": "valid"}])

    def test_manifest_over_two_mib_falls_back_before_media(self):
        # Text alone is below 2MiB, but 50k segment dictionaries exceed it.
        self.client.get_transcript_segments.return_value = [{"start_ms": 0, "end_ms": 600_000, "text": "x"}] * 50_000
        self.client.get_sub_info.return_value = {}
        with self.assertRaisesRegex(collect.MaterialCollectionError, "未开放"):
            self.run_collect()
        self.client.get_sub_info.assert_called_once()
        self.client.vpn.get.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_manifest_dates_and_24_hour_ppt_rejected_locally(self):
        with self.assertRaisesRegex(collect.MaterialCollectionError, "云端处理要求"):
            self.run_collect(dict(LECTURE, date="2026-02-30"))
        self.client.get_ppt_list.return_value = [{"created_sec": 86_401, "pptimgurl": "https://icourse.fudan.edu.cn/ppt.jpg"}]
        with self.assertRaisesRegex(collect.MaterialCollectionError, "时间信息"):
            self.run_collect()
        self.client.vpn.get.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_stream_limit_removes_partial_and_closes_response(self):
        reply = response([b"abcd", b"ef"])
        self.client.vpn.get.return_value = reply
        with self.assertRaisesRegex(collect.MaterialCollectionError, "上限"):
            collect._download(self.client, "https://icourse.fudan.edu.cn/video.mp4", self.root / "source.mp4", 5)
        reply.close.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])
        kwargs = self.client.vpn.get.call_args.kwargs
        self.assertTrue(kwargs["stream"])
        self.assertFalse(kwargs["allow_redirects"])

    def test_declared_limit_rejected_before_writing(self):
        reply = response([b"unused"], headers={"Content-Length": "30"})
        self.client.vpn.get.return_value = reply
        with self.assertRaisesRegex(collect.MaterialCollectionError, "上限"):
            collect._download(self.client, "https://icourse.fudan.edu.cn/video.mp4", self.root / "source.mp4", 5)
        reply.iter_content.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_http_webvpn_foreign_and_credential_urls_rejected(self):
        for url in ("http://icourse.fudan.edu.cn/v.mp4", "https://webvpn.fudan.edu.cn/v.mp4", "https://x.webvpn.fudan.edu.cn/v.mp4", "https://icourse.fudan.edu.cn.evil.test/v.mp4", "https://user:password@icourse.fudan.edu.cn/v.mp4", "https://icourse.fudan.edu.cn:8080/v.mp4"):
            with self.subTest(url=url), self.assertRaises(collect.MaterialCollectionError):
                collect._download(self.client, url, self.root / "source.mp4", 5)
        self.client.vpn.get.assert_not_called()

    def test_external_redirect_is_not_followed(self):
        reply = response([], status=302, headers={"Location": "https://other.test/secret?ticket=value"})
        self.client.vpn.get.return_value = reply
        with self.assertRaises(collect.MaterialCollectionError) as caught:
            collect._download(self.client, "https://icourse.fudan.edu.cn/a.jpg", self.root / "a.jpg", 50)
        self.assertNotIn("ticket", str(caught.exception))
        self.client.vpn.get.assert_called_once()
        reply.close.assert_called_once()

    def test_failed_conversion_has_no_stderr_and_removes_video(self):
        video, audio = self.root / "source.mp4", self.root / "audio.flac"
        video.write_bytes(b"video")
        audio.write_bytes(b"partial")
        fake = types.SimpleNamespace(get_ffmpeg_exe=lambda: "ffmpeg.exe")
        with patch.dict(sys.modules, {"imageio_ffmpeg": fake}), patch.object(
                collect.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "dummy", stderr="secret-cookie https://school")) as run:
            with self.assertRaises(collect.MaterialCollectionError) as caught:
                collect._convert_audio(video, audio, 100)
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("https", str(caught.exception))
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertFalse(video.exists())
        self.assertFalse(audio.exists())

    def test_audio_fallback_signed_download_and_local_ffmpeg_paths(self):
        self.client.get_transcript_segments.return_value = []
        self.client.get_sub_info.return_value = {"now": "1234", "video_list": {"a": {"preview_url": "https://icourse.fudan.edu.cn/a.mp4"}}}
        self.client.sign_video_url.return_value = "https://icourse.fudan.edu.cn/a.mp4?signature=secret"
        self.client.vpn.get.return_value = response([b"dummy-video"])
        commands = []
        def fake_run(command, **kwargs):
            commands.append(command)
            Path(command[-1]).write_bytes(b"fLaC-dummy")
        fake = types.SimpleNamespace(get_ffmpeg_exe=lambda: "ffmpeg.exe")
        with patch.dict(sys.modules, {"imageio_ffmpeg": fake}), patch.object(collect.subprocess, "run", side_effect=fake_run):
            path = self.run_collect()
        manifest, names = self.read_manifest(path)
        self.assertEqual(manifest["audio"], "audio.flac")
        self.assertEqual(names, ["manifest.json", "audio.flac"])
        self.assertEqual(manifest["transcript_segments"], [])
        self.client.sign_video_url.assert_called_once_with("https://icourse.fudan.edu.cn/a.mp4", now=1234)
        self.assertNotIn("https://", " ".join(commands[0]))
        self.assertNotIn("secret", " ".join(commands[0]))
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_ppt_limits_and_error_cleanup(self):
        self.client.get_ppt_list.return_value = [{"created_sec": 0, "pptimgurl": "https://icourse.fudan.edu.cn/a.jpg"}]
        self.client.vpn.get.return_value = response([b"12345"])
        with patch.object(collect, "MAX_PPT_BYTES", 4), self.assertRaises(collect.MaterialCollectionError):
            self.run_collect()
        self.assertEqual(list(self.root.iterdir()), [])
        self.client.get_ppt_list.return_value = [{}] * 1001
        with self.assertRaisesRegex(collect.MaterialCollectionError, "数量"):
            self.run_collect()

    def test_disk_space_and_existing_archive_protected(self):
        self.space.stop()
        with patch.object(collect.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1)), self.assertRaisesRegex(collect.MaterialCollectionError, "磁盘空间"):
            self.run_collect()
        self.space.start()
        existing = self.root / f"materials-{JOB}-321.zip"
        existing.write_bytes(b"previous")
        with self.assertRaisesRegex(collect.MaterialCollectionError, "已经存在"):
            self.run_collect()
        self.assertEqual(existing.read_bytes(), b"previous")

    def test_upstream_exception_is_sanitized(self):
        def fail(*args):
            print("cookie=secret https://private")
            raise RuntimeError("password=secret")
        self.client.get_ppt_list.side_effect = fail
        with self.assertRaises(collect.MaterialCollectionError) as caught:
            self.run_collect()
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("secret", self.output.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
