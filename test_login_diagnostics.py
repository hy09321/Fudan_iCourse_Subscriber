"""Offline tests: diagnostics must never persist credentials or server prose."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import requests

from private_login_diagnostics import LoginDiagnostics, STAGE_LABELS


SECRET = 'SENSITIVE_MARKER_DO_NOT_RECORD'


def response(url, body, status=200, content_type='application/json'):
    result = requests.Response()
    result.url = url
    result.status_code = status
    result.headers = {'Content-Type': content_type, 'Set-Cookie': SECRET,
                      'Location': 'https://example.invalid/?ticket=' + SECRET}
    result._content = (body if isinstance(body, str) else json.dumps(body)).encode()
    return result


class LoginDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'logs/login-diagnostic.json'
        self.diag = LoginDiagnostics(self.path)

    def persisted(self, exc=None):
        self.diag.finish(False, exc)
        text = self.path.read_text(encoding='utf-8')
        self.assertNotIn(SECRET, text)
        self.assertNotIn(SECRET, self.diag.failure_message())
        return json.loads(text)

    def test_auth_response_is_allowlisted_and_includes_safe_code(self):
        result = response('https://id.fudan.edu.cn/idp/authn/authExecute?password=' + SECRET,
                          {'code': '401', 'message': '用户名或密码错误 ' + SECRET,
                           'loginToken': SECRET, 'data': {'password': SECRET}}, 200)
        self.diag._on_response(result)
        log = self.persisted(RuntimeError(SECRET))
        self.assertEqual(log['stage'], 'WEBVPN_AUTH_SUBMIT')
        self.assertEqual(log['events'][-1], {'stage': 'WEBVPN_AUTH_SUBMIT', 'http_status': 200,
                         'content': 'json', 'code': '401', 'category': 'ACCOUNT_REJECTED'})
        self.assertIn('业务码 401', self.diag.failure_message())
        self.assertIn('不能据此确定密码输入有误', self.diag.failure_message())

    def test_unknown_stage_url_fields_and_non_numeric_code_do_not_leak(self):
        self.diag.set_stage(SECRET)
        self.diag._on_response(response('https://' + SECRET + '.invalid/' + SECRET,
                                        {'code': SECRET, 'message': SECRET}))
        self.diag._event(password=SECRET, http_status=SECRET, error=SECRET,
                         category=SECRET, content=SECRET, code=SECRET)
        log = self.persisted(type(SECRET, (Exception,), {})(SECRET))
        self.assertEqual(log['stage'], 'UNKNOWN')
        self.assertEqual(log['error'], 'PROGRAM_ERROR')
        self.assertEqual(log['events'][-1], {'stage': 'UNKNOWN', 'code': 'non_numeric'})

    def test_fixed_message_categories_without_raw_text(self):
        for message, category in [('请完成短信验证 ' + SECRET, 'SECOND_FACTOR_REQUIRED'),
                                  ('captcha required ' + SECRET, 'CAPTCHA_REQUIRED')]:
            self.diag._on_response(response('https://webvpn.fudan.edu.cn/https/ENC/idp/authn/authExecute',
                                            {'code': 400, 'msg': message}))
            log = self.persisted(RuntimeError(SECRET))
            self.assertEqual(log['events'][-1]['category'], category)
            self.assertEqual(log['stage'], 'ICOURSE_AUTH_SUBMIT')

    def test_infosimple_never_inspects_user_messages(self):
        self.diag._on_response(response('https://webvpn.fudan.edu.cn/https/ENC/userapi/v1/infosimple',
                                        {'code': 200, 'msg': 'captcha ' + SECRET,
                                         'data': {'id': SECRET, 'phone': SECRET}}))
        log = self.persisted()
        self.assertNotIn('category', log['events'][-1])
        self.assertEqual(log['stage'], 'ICOURSE_VERIFY')

    def test_network_exception_allowlist_and_attach(self):
        for exception_type, expected in [(requests.exceptions.SSLError, 'SSL'),
                                         (requests.exceptions.ProxyError, 'PROXY'),
                                         (requests.exceptions.ReadTimeout, 'TIMEOUT'),
                                         (requests.exceptions.ConnectionError, 'CONNECTION'),
                                         (requests.exceptions.MissingSchema, 'URL')]:
            diag = LoginDiagnostics(self.path)
            vpn = Mock()
            vpn.session = requests.Session()
            vpn.session.request = Mock(side_effect=exception_type(SECRET))
            diag.attach(vpn)
            with self.assertRaises(exception_type) as caught:
                vpn.session.get('https://id.fudan.edu.cn/idp/authn/getJsPublicKey?key=' + SECRET,
                                headers={'Authorization': SECRET})
            diag.finish(False, caught.exception)
            log_text = self.path.read_text(encoding='utf-8')
            self.assertNotIn(SECRET, log_text)
            log = json.loads(log_text)
            self.assertEqual(log['error'], expected)
            self.assertEqual(log['stage'], 'WEBVPN_PUBLIC_KEY')
            self.assertIn(diag._on_response, vpn.session.hooks['response'])
            vpn.session.close()

    def test_html_json_http_and_code_boundaries(self):
        self.diag._on_response(response('https://id.fudan.edu.cn/idp/authn/queryAuthMethods',
                                        '<html>' + SECRET + '</html>', 503, 'text/html'))
        self.assertIn('HTTP 503', self.diag.failure_message())
        self.assertIn('学校服务', self.diag.failure_message())
        self.assertIn('响应类型 HTML', self.diag.failure_message())
        for code in (SECRET, True, 1234567, -1234567, {'secret': SECRET}, ['secret']):
            self.diag._on_response(response('https://id.fudan.edu.cn/idp/authn/authExecute', {'code': code}))
            self.assertEqual(self.diag.events[-1]['code'], 'non_numeric')
        for code in (-1, '-401'):
            self.diag._on_response(response('https://id.fudan.edu.cn/idp/authn/authExecute', {'code': code}))
            self.assertEqual(self.diag.events[-1]['code'], str(code))
        self.diag._on_response(response('https://id.fudan.edu.cn/idp/authn/queryAuthMethods', SECRET))
        self.assertEqual(self.persisted()['events'][-1]['error'], 'JSON')

    def test_logs_overwrite_and_are_bounded_and_write_error_is_nonfatal(self):
        for _ in range(100):
            self.diag.set_stage('VERIFY')
            self.diag._event(http_status=200)
        self.assertEqual(len(self.persisted()['events']), 60)
        self.diag.finish(True)
        self.assertTrue(json.loads(self.path.read_text(encoding='utf-8'))['success'])
        self.diag.path = Path(self.temp.name)
        self.assertFalse(self.diag.finish(False, RuntimeError(SECRET)))
        self.assertFalse(self.diag.saved)


if __name__ == '__main__':
    unittest.main()
