"""Offline tests: fake responses only, no account or live school requests."""

import json
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import requests

from src.api.campus import CampusAccessError, CampusSession, ICOURSE_BASE, IDP_BASE, probe_campus_access


def reply(url, payload=None, *, status=200, location=None, text=""):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response._content = json.dumps(payload).encode() if payload is not None else text.encode()
    response._content_consumed = True
    response.encoding = "utf-8"
    if location:
        response.headers["Location"] = location
    return response


INFO = ICOURSE_BASE + "/userapi/v1/infosimple"
BAD_INFO = lambda: reply(INFO, {"code": 401})
GOOD_INFO = lambda: reply(INFO, {"code": 0, "data": {"id": "dummy"}})


class CampusTests(unittest.TestCase):
    def make_session(self, responses):
        client = CampusSession()
        client.session.request = Mock(side_effect=responses)
        self.addCleanup(client.session.close)
        return client

    def full_flow(self, *, final=None, ticket=None):
        return [
            BAD_INFO(),
            reply(ICOURSE_BASE + "/casapi/index.php", status=302,
                  location=IDP_BASE + "/idp/authCenter/authenticate?service=dummy"),
            reply(IDP_BASE + "/idp/authCenter/authenticate", status=302,
                  location="/ac/?lck=dummy-context"),
            reply(IDP_BASE + "/ac/?lck=dummy-context", text="<html>Login</html>"),
            BAD_INFO(),
            reply(IDP_BASE + "/idp/authn/queryAuthMethods", {
                "code": 200, "data": [{"moduleCode": "userAndPwd", "authChainCode": "dummy-chain"}]}),
            reply(IDP_BASE + "/idp/authn/getJsPublicKey", {"code": 200, "data": "dummy-key"}),
            reply(IDP_BASE + "/idp/authn/authExecute", {"code": 200, "loginToken": "dummy-token"}),
            reply(IDP_BASE + "/idp/authCenter/authnEngine", text=(
                'var locationValue="' + (ticket or ICOURSE_BASE + '/casapi/index.php?r=auth/login&amp;ticket=dummy-ticket') + '";')),
            reply(ICOURSE_BASE + "/casapi/index.php?ticket=dummy-ticket", status=302, location="/"),
            reply(ICOURSE_BASE + "/", text="<html>iCourse</html>"),
            final or GOOD_INFO(),
        ]

    def test_full_original_domain_cas_and_no_webvpn(self):
        client = self.make_session(self.full_flow())
        with patch("src.api.campus.WebVPNSession._encrypt_password", return_value="dummy-rsa") as encrypt, patch(
                "src.api.webvpn.get_vpn_url", side_effect=AssertionError("WebVPN must never run")), patch(
                "src.api.webvpn.WebVPNSession.login", side_effect=AssertionError("WebVPN must never run")):
            self.assertTrue(client.login("dummy-user", "dummy-password"))
        self.assertTrue(client.logged_in)
        encrypt.assert_called_once()
        self.assertFalse(client.session.trust_env)
        self.assertTrue(client.session.verify)
        for call in client.session.request.call_args_list:
            method, url = call.args
            self.assertIn(urlsplit(url).hostname, {"id.fudan.edu.cn", "icourse.fudan.edu.cn"})
            self.assertTrue(call.kwargs["verify"])
            self.assertEqual(call.kwargs["proxies"], {})
            self.assertFalse(call.kwargs["allow_redirects"])
            if "authPara" in call.kwargs.get("json", {}):
                self.assertEqual(url, IDP_BASE + "/idp/authn/authExecute")
                self.assertEqual(call.kwargs["json"]["authPara"]["password"], "dummy-rsa")

    def test_existing_icourse_session_is_idempotent(self):
        client = self.make_session([GOOD_INFO(), GOOD_INFO()])
        self.assertTrue(client.authenticate_icourse())
        self.assertTrue(client.authenticate_icourse())
        self.assertEqual(client.session.request.call_count, 2)

    def test_existing_cas_returns_directly_without_new_credentials(self):
        client = self.make_session([
            BAD_INFO(),
            reply(ICOURSE_BASE + "/casapi/index.php", status=302,
                  location="/?ticket=dummy-existing"),
            reply(ICOURSE_BASE + "/?ticket=dummy-existing", text="iCourse"),
            GOOD_INFO(),
        ])
        self.assertTrue(client.authenticate_icourse())
        self.assertTrue(all(call.args[0] == "GET" for call in client.session.request.call_args_list))

    def test_bad_final_html_or_business_code_fails(self):
        for final in [reply(INFO, text="<html>login</html>"), reply(INFO, {"code": 401}),
                      reply(INFO, {"code": True}), reply(INFO, {"data": {}})]:
            with self.subTest(final=final.text):
                client = self.make_session(self.full_flow(final=final))
                with patch("src.api.campus.WebVPNSession._encrypt_password", return_value="dummy-rsa"):
                    with self.assertRaises(CampusAccessError):
                        client.login("dummy-user", "dummy-password")
                self.assertFalse(client.logged_in)

    def test_credentials_not_replayed_on_auth_redirect(self):
        responses = self.full_flow()
        responses[7] = reply(IDP_BASE + "/idp/authn/authExecute", status=307,
                             location="https://outside.example/collect")
        client = self.make_session(responses)
        with patch("src.api.campus.WebVPNSession._encrypt_password", return_value="dummy-rsa"):
            with self.assertRaises(CampusAccessError):
                client.login("dummy-user", "dummy-password")
        self.assertEqual(client.session.request.call_count, 8)

    def test_rejects_foreign_ticket_before_request(self):
        client = self.make_session(self.full_flow(ticket="https://outside.example/?ticket=dummy"))
        with patch("src.api.campus.WebVPNSession._encrypt_password", return_value="dummy-rsa"):
            with self.assertRaises(CampusAccessError):
                client.login("dummy-user", "dummy-password")
        self.assertEqual(client.session.request.call_count, 9)

    def test_rejects_foreign_redirect_before_request(self):
        client = self.make_session([reply(ICOURSE_BASE + "/", status=302,
                                          location="https://outside.example/")])
        with self.assertRaises(CampusAccessError):
            client.get(ICOURSE_BASE + "/")
        self.assertEqual(client.session.request.call_count, 1)

    def test_strict_tls_and_original_url_interfaces(self):
        client = self.make_session([reply(ICOURSE_BASE + "/")] * 4)
        for method in (client.get, client.get_raw, client.post, client.post_raw):
            method(ICOURSE_BASE + "/")
        for bad in ["http://icourse.fudan.edu.cn/", "https://webvpn.fudan.edu.cn/",
                    "https://nested.webvpn.fudan.edu.cn/",
                    "https://icourse.fudan.edu.cn@outside.example/",
                    "https://icourse.fudan.edu.cn:8443/"]:
            with self.assertRaises(CampusAccessError):
                client.get(bad)
        with self.assertRaises(CampusAccessError):
            client.get(ICOURSE_BASE, verify=False)
        with self.assertRaises(CampusAccessError):
            client.get(ICOURSE_BASE, proxies={"https": "http://127.0.0.1:9999"})
        self.assertEqual(client.session.request.call_count, 4)

    def test_status_diagnostics_keep_numbers_but_never_response_text(self):
        with self.assertRaisesRegex(CampusAccessError, 'HTTP 403'):
            CampusSession._json(reply(INFO, status=403, text='sensitive-body'), '校验')
        with self.assertRaisesRegex(CampusAccessError, '业务码 401'):
            CampusSession._json(reply(INFO, {'code': 401, 'msg': 'sensitive-body'}), '校验')
        with self.assertRaises(CampusAccessError) as caught:
            CampusSession._json(reply(INFO, {'code': 'sensitive-body'}), '校验')
        self.assertNotIn('sensitive-body', str(caught.exception))

    def test_network_diagnostics_are_fixed_and_distinguish_timeout(self):
        client = self.make_session([])
        client.session.request.side_effect = requests.Timeout('sensitive-url')
        with self.assertRaisesRegex(CampusAccessError, '超时') as caught:
            client.get(ICOURSE_BASE)
        self.assertNotIn('sensitive-url', str(caught.exception))

    def test_probe_no_credentials_bounded_timeout_and_no_redirect(self):
        fake_session = requests.Session()
        fake_session.get = Mock(return_value=reply(ICOURSE_BASE + "/", text="iCourse"))
        with patch("src.api.campus.requests.Session", return_value=fake_session):
            result = probe_campus_access(timeout=999)
        self.assertTrue(result["reachable"])
        self.assertFalse(fake_session.trust_env)
        kwargs = fake_session.get.call_args.kwargs
        self.assertEqual(kwargs["timeout"], (10.0, 10.0))
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertNotIn("auth", kwargs)
        self.assertNotIn("cookies", kwargs)

    def test_probe_reports_failure_without_exception_detail(self):
        fake_session = requests.Session()
        fake_session.get = Mock(side_effect=requests.exceptions.ConnectTimeout("sensitive-url"))
        with patch("src.api.campus.requests.Session", return_value=fake_session):
            result = probe_campus_access()
        self.assertEqual(result, {"reachable": False, "status_code": None, "reason": "network"})


if __name__ == "__main__":
    unittest.main()
