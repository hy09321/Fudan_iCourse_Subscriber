"""Offline boundary tests for encrypted material orchestration."""

import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import requests
from nacl.public import PrivateKey, SealedBox

import private_campus_local as local
from private_material_protocol import encrypt_bundle, validate_material_job


JOB_ID = 'a' * 32
BLOB_URL = 'https://release-assets.githubusercontent.com/synthetic/material.enc?sig=dummy'


def response(payload=None, status=200, location=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode() if payload is not None else b''
    result._content_consumed = True
    if location:
        result.headers['Location'] = location
    return result


def job():
    return {'version': 2, 'job_id': JOB_ID, 'expires_at': int(time.time()) + 21600,
            'input_key': base64.b64encode(b'I' * 32).decode(),
            'result_key': base64.b64encode(b'R' * 32).decode(), 'asset_url': BLOB_URL}


class MaterialGitHubTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.notes = self.root / 'private_notes'
        self.patch_notes = patch.object(local, 'NOTES', self.notes)
        self.patch_root = patch.object(local, 'ROOT', self.root)
        self.patch_notes.start()
        self.patch_root.start()
        self.addCleanup(self.patch_notes.stop)
        self.addCleanup(self.patch_root.stop)
        self.gh = local.MaterialGitHub('dummy-github-token')
        self.addCleanup(self.gh.close)

    def encrypted(self):
        original = self.root / 'synthetic.zip'
        original.write_bytes(b'synthetic nonprivate material')
        destination = self.root / 'synthetic.enc'
        encrypt_bundle(original, destination, b'I' * 32, JOB_ID)
        return destination

    def release(self, **changes):
        value = {'id': 123, 'draft': True, 'tag_name': 'ics-private-' + JOB_ID,
                 'upload_url': f'https://uploads.github.com/repos/{self.gh.repo}/releases/123/assets{{?name,label}}'}
        value.update(changes)
        return value

    def test_secret_only_contains_validated_v2_packet(self):
        private_key = PrivateKey.generate()
        public = {'key': base64.b64encode(bytes(private_key.public_key)).decode(), 'key_id': 'dummy-key-id'}
        self.gh.call = Mock(side_effect=[public, None])
        value = job()
        self.gh.put_job('ICS_SESSION_' + JOB_ID.upper(), value)
        body = self.gh.call.call_args_list[1].kwargs['json']
        decoded = SealedBox(private_key).decrypt(base64.b64decode(body['encrypted_value']))
        self.assertEqual(json.loads(decoded), value)
        self.assertEqual(set(body), {'encrypted_value', 'key_id'})
        journal = json.loads(self.gh._journal_path(JOB_ID).read_text())
        self.assertEqual(set(journal), local.JOURNAL_FIELDS)
        self.assertTrue(journal['secret_pending'])
        saved = self.gh._journal_path(JOB_ID).read_text()
        for forbidden in (BLOB_URL, value['input_key'], value['result_key'], 'dummy-github-token'):
            self.assertNotIn(forbidden, saved)

    def test_extra_secret_fields_rejected_before_api(self):
        self.gh.call = Mock()
        value = job()
        value['password'] = 'dummy-do-not-send'
        with self.assertRaises(ValueError):
            self.gh.put_job('ICS_SESSION_' + JOB_ID.upper(), value)
        self.gh.call.assert_not_called()
        self.assertFalse(self.gh.journal_dir.exists())

    def test_upload_and_delete_exact_draft_with_ciphertext_only(self):
        encrypted = self.encrypted()
        self.gh.call = Mock(return_value=self.release())
        uploaded = []

        def fake_post(url, **kwargs):
            uploaded.append(kwargs['data'].read())
            self.assertEqual(url, f'https://uploads.github.com/repos/{self.gh.repo}/releases/123/assets')
            self.assertFalse(kwargs['allow_redirects'])
            self.assertTrue(kwargs['verify'])
            return response({'id': 456, 'state': 'uploaded', 'size': encrypted.stat().st_size,
                             'name': 'materials-' + JOB_ID + '.enc'}, 201)

        self.gh.http.post = Mock(side_effect=fake_post)
        self.gh.http.get = Mock(side_effect=[response(status=302, location=BLOB_URL), response(self.release())])
        self.gh.http.delete = Mock(return_value=response(status=204))
        self.assertEqual(self.gh.upload_material(encrypted, JOB_ID), BLOB_URL)
        self.assertEqual(uploaded, [encrypted.read_bytes()])
        self.assertNotIn(b'synthetic nonprivate material', uploaded[0])
        self.assertTrue(self.gh.call.call_args.kwargs['json']['draft'])
        self.assertTrue(self.gh.cleanup_job(JOB_ID))
        self.assertFalse(self.gh._journal_path(JOB_ID).exists())

    def test_rejects_foreign_upload_url_before_token_request(self):
        self.gh.call = Mock(return_value=self.release(upload_url='https://outside.example/upload'))
        self.gh.http.post = Mock()
        with self.assertRaises(local.UserError):
            self.gh.upload_material(self.encrypted(), JOB_ID)
        self.gh.http.post.assert_not_called()
        self.assertTrue(self.gh._read_journal(JOB_ID)['release_pending'])

    def test_rejects_plaintext_before_any_upload(self):
        path = self.root / 'plaintext.zip'
        path.write_bytes(b'plain synthetic material' * 10)
        self.gh.call = Mock()
        with self.assertRaises(local.UserError):
            self.gh.upload_material(path, JOB_ID)
        self.gh.call.assert_not_called()

    def test_binary_200_does_not_fall_back_to_token_handoff(self):
        encrypted = self.encrypted()
        self.gh.call = Mock(return_value=self.release())
        self.gh.http.post = Mock(return_value=response({
            'id': 456, 'state': 'uploaded', 'size': encrypted.stat().st_size,
            'name': 'materials-' + JOB_ID + '.enc'}, 201))
        self.gh.http.get = Mock(return_value=response(status=200))
        with self.assertRaises(local.UserError) as caught:
            self.gh.upload_material(encrypted, JOB_ID)
        self.assertNotIn('dummy-github-token', str(caught.exception))
        self.assertEqual(self.gh.http.get.call_count, 1)

    def test_pending_unknown_creation_recovered_by_exact_tag(self):
        self.gh._record(JOB_ID, release_pending=True)
        unrelated = self.release(id=999, tag_name='a-real-release')
        self.gh.call = Mock(return_value=[unrelated, self.release()])
        self.gh.http.get = Mock(return_value=response(self.release()))
        self.gh.http.delete = Mock(return_value=response(status=204))
        self.assertTrue(self.gh.cleanup_pending())
        self.gh.http.delete.assert_called_once()
        self.assertTrue(self.gh.http.delete.call_args.args[0].endswith('/releases/123'))

    def test_unrelated_or_published_release_never_deleted(self):
        self.gh._record(JOB_ID, release_pending=True, release_id=123)
        self.gh.http.get = Mock(return_value=response(self.release(draft=False)))
        self.gh.http.delete = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(self.gh.cleanup_job(JOB_ID))
        self.gh.http.delete.assert_not_called()
        self.assertTrue(self.gh._journal_path(JOB_ID).exists())

    def test_cleanup_failure_journal_has_identifiers_not_secrets(self):
        self.gh._record(JOB_ID, release_pending=True, release_id=123)
        self.gh.http.get = Mock(side_effect=requests.ConnectionError('secret-raw-url'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(self.gh.cleanup_pending())
        self.assertNotIn('secret-raw-url', output.getvalue())
        self.assertEqual(set(json.loads(self.gh._journal_path(JOB_ID).read_text())), local.JOURNAL_FIELDS)

    def test_login_diagnostic_never_contains_account_or_exception_text(self):
        campus = Mock()
        campus.login.side_effect = RuntimeError('raw-url-ticket-private')
        with patch.object(local, 'CampusSession', return_value=campus):
            with self.assertRaises(local.UserError):
                local._login_campus('dummy-user-private', 'dummy-password-private')
        saved = (self.root / 'logs' / 'campus-login-diagnostic.json').read_text()
        for value in ('raw-url-ticket-private', 'dummy-user-private', 'dummy-password-private'):
            self.assertNotIn(value, saved)
        self.assertEqual(json.loads(saved)['error_type'], 'OtherError')
        campus.session.close.assert_called_once()

    def test_safe_campus_error_detail_is_retained(self):
        campus = Mock()
        campus.login.side_effect = local.CampusAccessError('UIS 认证失败：学校服务返回 HTTP 403。')
        with patch.object(local, 'CampusSession', return_value=campus):
            with self.assertRaisesRegex(local.UserError, 'HTTP 403'):
                local._login_campus('dummy-user', 'dummy-password')
        saved = json.loads((self.root / 'logs' / 'campus-login-diagnostic.json').read_text())
        self.assertIn('HTTP 403', saved['detail'])

    def test_cleanup_precedes_unavailable_school(self):
        events = []
        gh = Mock()
        gh.cleanup_pending.side_effect = lambda: events.append('cleanup') or True
        gh.preflight.side_effect = lambda: events.append('preflight')

        def unavailable():
            events.append('school')
            raise local.UserError('学校网络不可用。')

        with patch.object(local, 'MaterialGitHub', return_value=gh), patch.object(
                local.getpass, 'getpass', return_value='dummy-token'), patch.object(
                local, '_require_reachable', side_effect=unavailable), patch('builtins.input') as ask, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(local.UserError):
                local.cloud_extract_campus()
        self.assertEqual(events, ['cleanup', 'preflight', 'school'])
        ask.assert_not_called()
        gh.close.assert_called_once()


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.notes = Path(self.temporary.name) / 'notes'
        self.patch_notes = patch.object(local, 'NOTES', self.notes)
        self.patch_notes.start()
        self.addCleanup(self.patch_notes.stop)
        self.client = Mock()
        self.client.check_alive.return_value = True
        self.client.get_course_detail.return_value = {'title': 'Synthetic class', 'lectures': [
            {'sub_id': '101', 'sub_title': 'One', 'date': '2026-10-02', 'has_playback': True},
            {'sub_id': '102', 'sub_title': 'Two', 'date': '2026-10-03', 'has_playback': True},
            {'sub_id': '103', 'sub_title': 'Old', 'date': '2026-09-01', 'has_playback': True},
            {'sub_id': '104', 'sub_title': 'Closed', 'date': '2026-10-03', 'has_playback': False},
        ]}
        self.gh = Mock()
        self.gh.upload_material.return_value = BLOB_URL
        self.gh.cleanup_job.return_value = True
        self.directories = []

    def collect(self, client, course_id, title, lecture, directory, job_id):
        self.directories.append(Path(directory))
        target = Path(directory) / 'synthetic.zip'
        target.write_bytes(b'synthetic material ' + lecture['sub_id'].encode())
        return target

    def returned(self, value, sid='101'):
        validate_material_job(value)
        self.notes.mkdir(parents=True, exist_ok=True)
        target = self.notes / ('received-' + sid + '.json')
        target.write_text(json.dumps({'items': [{'course_id': '20', 'sub_id': sid,
            'course_title': 'Synthetic class', 'sub_title': 'Lecture', 'date': '2026-10-02',
            'prompt': 'Synthetic course text'}], 'errors': []}), encoding='utf-8')
        return target

    def test_partial_result_survives_next_failure_and_materials_are_removed(self):
        count = 0

        def run(value):
            nonlocal count
            count += 1
            if count == 1:
                return self.returned(value)
            raise RuntimeError('do-not-log-token')

        self.gh.run.side_effect = run
        output = io.StringIO()
        with patch.object(local, 'collect_lecture', side_effect=self.collect), contextlib.redirect_stdout(output):
            path = local.process_courses(self.client, self.gh, ['20'], '2026-10-01', set())
        result = json.loads(path.read_text())
        self.assertEqual([i['sub_id'] for i in result['items']], ['101'])
        self.assertEqual(result['errors'], ['CLOUD_EXTRACTION_FAILED:102'])
        self.assertNotIn('do-not-log-token', output.getvalue())
        self.assertEqual(self.gh.cleanup_job.call_count, 2)
        self.assertTrue(all(not path.exists() for path in self.directories))
        for call in self.gh.run.call_args_list:
            # The successful in-memory job is cleared immediately after saving.
            value = call.args[0]
            if value:
                self.assertEqual(set(value), {'version', 'job_id', 'expires_at', 'input_key', 'result_key', 'asset_url'})

    def test_interrupt_keeps_checkpoint_and_runs_cleanup(self):
        self.gh.run.side_effect = KeyboardInterrupt()
        with patch.object(local, 'collect_lecture', side_effect=self.collect), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                local.process_courses(self.client, self.gh, ['20'], '2026-10-01', set())
        self.assertEqual(len(list(self.notes.glob('input-*.json'))), 1)
        self.gh.cleanup_job.assert_called_once()
        self.assertTrue(all(not path.exists() for path in self.directories))

    def test_completed_old_and_closed_lectures_not_uploaded(self):
        with patch.object(local, 'collect_lecture') as collect, contextlib.redirect_stdout(io.StringIO()):
            path = local.process_courses(self.client, self.gh, ['20'], '2026-10-01', {'101', '102'})
        collect.assert_not_called()
        self.gh.upload_material.assert_not_called()
        self.assertEqual(json.loads(path.read_text()), {'items': [], 'errors': []})

    def test_mismatched_cloud_lecture_never_enters_aggregate(self):
        value = job()
        path = self.returned(value, '999')
        aggregate = {'items': [], 'errors': []}
        with self.assertRaises(local.UserError):
            local._merge_result(aggregate, path, '20', '101')
        self.assertEqual(aggregate, {'items': [], 'errors': []})


if __name__ == '__main__':
    unittest.main()
