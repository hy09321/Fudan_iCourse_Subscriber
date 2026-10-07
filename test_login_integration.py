import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import requests
import private_local


class LoginIntegrationTests(unittest.TestCase):
    def test_failure_saves_safe_diagnostic_without_credentials(self):
        marker = 'PRIVATE-ACCOUNT-PASSWORD-COOKIE-MARKER'
        vpn = SimpleNamespace(session=requests.Session(),
                              login=Mock(side_effect=RuntimeError(marker)),
                              authenticate_icourse=Mock())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(private_local, 'ROOT', root), patch('src.api.webvpn.WebVPNSession', return_value=vpn):
                with self.assertRaises(private_local.UserError) as caught:
                    private_local.login_locally(marker, marker)
            saved = (root / 'logs' / 'login-diagnostic.json').read_text(encoding='utf-8')
            self.assertNotIn(marker, saved)
            self.assertNotIn(marker, str(caught.exception))
            self.assertIn('WEBVPN_LOGIN', saved)
            self.assertIsInstance(json.loads(saved), dict)
            vpn.authenticate_icourse.assert_not_called()

    def test_success_exports_session_but_never_logs_cookie(self):
        vpn = SimpleNamespace(session=requests.Session(), login=Mock(), authenticate_icourse=Mock())
        vpn.session.cookies.set('session', 'PRIVATE-SESSION-MARKER', domain='webvpn.fudan.edu.cn', path='/')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(private_local, 'ROOT', root), patch('src.api.webvpn.WebVPNSession', return_value=vpn), patch('src.api.icourse.ICourseClient.check_alive', return_value=True):
                cookies = private_local.login_locally('synthetic-account', 'synthetic-password')
            self.assertEqual(cookies[0]['value'], 'PRIVATE-SESSION-MARKER')
            saved = (root / 'logs' / 'login-diagnostic.json').read_text(encoding='utf-8')
            self.assertNotIn('PRIVATE-SESSION-MARKER', saved)
            self.assertNotIn('synthetic-', saved)

    def test_diagnostic_menu_does_not_request_github_or_upload_session(self):
        with patch('builtins.input', return_value='3'), patch('private_campus_local.diagnose_campus') as diagnose, patch.object(private_local, 'GitHub') as github, contextlib.redirect_stdout(io.StringIO()):
            private_local.main()
        github.assert_not_called()
        diagnose.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
