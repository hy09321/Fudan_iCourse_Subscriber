"""Offline security regression tests; no network or real credentials."""
import base64
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
import zipfile

import requests
from nacl.public import PrivateKey, SealedBox
import private_local
from private_local import GitHub, make_job, UserError
from private_protocol import validate_job, encrypt_result, decrypt_result, session_cookies


def sample_job():
    jar = requests.cookies.RequestsCookieJar()
    jar.set('test_session', 'temporary-cookie', domain='webvpn.fudan.edu.cn', path='/', secure=True)
    return make_job(session_cookies(jar), ['123'], '2026-01-01', [])


class PrivacyTests(unittest.TestCase):
    def test_only_webvpn_cookies_exported(self):
        jar = requests.cookies.RequestsCookieJar()
        for domain in ('webvpn.fudan.edu.cn', 'id.fudan.edu.cn', 'evilwebvpn.fudan.edu.cn', 'example.com'):
            jar.set('session', 'test', domain=domain)
        self.assertEqual([c['domain'] for c in session_cookies(jar)], ['webvpn.fudan.edu.cn'])

    def test_sensitive_fields_rejected_before_upload(self):
        for field in ('password', 'student_id', 'api_key', 'github_token', 'UISPSW', 'DEEPSEEK_API_KEY'):
            job = sample_job()
            job[field] = 'MUST_NOT_UPLOAD'
            gh = GitHub('fake-token')
            gh.call = Mock()
            with self.assertRaises(ValueError):
                gh.put_job('ICS_SESSION_TEST', job)
            gh.call.assert_not_called()

    def test_expired_and_foreign_sessions_rejected(self):
        job = sample_job()
        job['expires_at'] = time.time() - 1
        with self.assertRaises(ValueError):
            validate_job(job)
        job = sample_job()
        job['cookies'][0]['domain'] = 'id.fudan.edu.cn'
        with self.assertRaises(ValueError):
            validate_job(job)

    def test_result_authentication_and_no_plaintext(self):
        job = sample_job()
        key = validate_job(job)
        result = {'items': [{'prompt': 'PRIVATE COURSE TEXT'}], 'errors': []}
        encrypted = encrypt_result(result, key, job['job_id'])
        self.assertNotIn(b'PRIVATE COURSE TEXT', encrypted)
        self.assertEqual(decrypt_result(encrypted, key, job['job_id']), result)
        for blob, job_id in ((encrypted[:-1] + bytes([encrypted[-1] ^ 1]), job['job_id']),
                             (encrypted, 'other-job')):
            with self.assertRaises(ValueError):
                decrypt_result(blob, key, job_id)

    def test_github_receives_sealed_allowlisted_payload(self):
        private_key = PrivateKey.generate()
        job = sample_job()
        calls = []
        gh = GitHub('fake-token')
        def call(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == 'GET':
                return {'key': base64.b64encode(bytes(private_key.public_key)).decode(), 'key_id': '123'}
        gh.call = call
        gh.put_job('ICS_SESSION_TEST', job)
        uploaded = calls[1][2]['json']
        decoded = json.loads(SealedBox(private_key).decrypt(base64.b64decode(uploaded['encrypted_value'])))
        self.assertEqual(decoded, job)
        self.assertNotIn('temporary-cookie', json.dumps(uploaded))

    def test_dispatch_failure_removes_temporary_secret(self):
        gh = GitHub('fake-token')
        gh.put_job = Mock()
        gh.remove_job = Mock(return_value=True)
        gh.call = Mock(side_effect=[{'state': 'active'}, UserError('dispatch failed')])
        with self.assertRaises(UserError):
            gh.run(sample_job())
        gh.remove_job.assert_called_once()

    def test_queued_run_deletes_secret_before_processing(self):
        gh = GitHub('fake-token')
        job = sample_job()
        events = []
        gh.put_job = lambda *a: events.append('upload')
        gh.remove_job = lambda *a: events.append('delete-secret') or True
        def call(method, path, **kwargs):
            if path.endswith('/private-manual.yml'):
                return {'state': 'active'}
            if path.endswith('/dispatches'):
                events.append('dispatch')
                self.assertEqual(set(kwargs['json']['inputs']), {'job_id', 'secret_name', 'test_mode'})
                return None
            if path.endswith('/private-manual.yml/runs'):
                return {'workflow_runs': [{'id': 123, 'display_title': 'private-' + job['job_id']}]}
            events.append('poll')
            return {'status': 'completed', 'conclusion': 'success'}
        gh.call = call
        gh.download = lambda *a: events.append('download') or Path('result')
        gh.run(job)
        self.assertEqual(events, ['upload', 'dispatch', 'delete-secret', 'poll', 'download'])

    def test_artifact_redirect_does_not_receive_github_token(self):
        gh = GitHub('NEVER_SEND_TO_BLOB')
        job = sample_job()
        key = validate_job(job)
        encrypted = encrypt_result({'items': [], 'errors': []}, key, job['job_id'])
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('result.enc', encrypted)
        gh.call = Mock(side_effect=[{'artifacts': [{'id': 99, 'name': 'private-result-' + job['job_id'], 'expired': False}]}, None])
        gh.http.get = Mock(return_value=Mock(status_code=302, headers={'Location': 'https://example.com/signed-result'}))
        downloaded = Mock(content=buffer.getvalue())
        with tempfile.TemporaryDirectory() as tmp, patch.object(private_local, 'NOTES', Path(tmp)), patch('private_local.requests.get', return_value=downloaded) as fetch:
            path = gh.download(123, job)
            self.assertTrue(path.exists())
            fetch.assert_called_once_with('https://example.com/signed-result', timeout=120)

    def test_local_imports_do_not_load_heavy_models(self):
        import sys
        from src.api.webvpn import WebVPNSession
        from src.ai.summarizer import SYSTEM_PROMPT
        self.assertTrue(SYSTEM_PROMPT)
        for name in ('sherpa_onnx', 'onnxruntime', 'numpy', 'rapidocr_onnxruntime'):
            self.assertNotIn(name, sys.modules)


if __name__ == '__main__':
    unittest.main()
