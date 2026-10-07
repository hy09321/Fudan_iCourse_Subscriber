"""iCourse over the current campus/aTrust route, without WebVPN rewriting.

Authentication is local.  HTTP proxy settings are deliberately ignored; Windows
routing (including aTrust's virtual interface) still applies to every connection.
"""

import html
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import requests

from src.api.webvpn import WebVPNSession
from src.runtime import config


ICOURSE_BASE = "https://icourse.fudan.edu.cn"
IDP_BASE = "https://id.fudan.edu.cn"
AUTH_HOSTS = frozenset({"icourse.fudan.edu.cn", "id.fudan.edu.cn"})
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 8


class CampusAccessError(RuntimeError):
    """An error whose message contains no response, credential, or ticket data."""


def _checked_url(url, *, auth_only=False):
    """Reject HTTP, foreign hosts, WebVPN, userinfo and non-HTTPS ports."""
    if not isinstance(url, str) or any(ord(c) < 32 for c in url) or "\\" in url:
        raise CampusAccessError("学校请求地址无效。")
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        valid_host = host in AUTH_HOSTS if auth_only else (
            host.endswith(".fudan.edu.cn") and host != "webvpn.fudan.edu.cn"
            and not host.endswith(".webvpn.fudan.edu.cn")
        )
        if (parts.scheme != "https" or not valid_host or parts.username is not None
                or parts.password is not None or parts.port not in (None, 443)):
            raise ValueError
    except ValueError:
        raise CampusAccessError("拒绝向非学校 HTTPS 地址发送请求。") from None
    # A CAS service ticket is only consumed by iCourse, never another service.
    if "ticket" in parse_qs(parts.query) and host != "icourse.fudan.edu.cn":
        raise CampusAccessError("CAS 票据接收地址不正确。")
    return url


def _lck_from_url(url):
    parts = urlsplit(url)
    if parts.hostname != "id.fudan.edu.cn":
        return None
    for source in (parts.query, parts.fragment.partition("?")[2], parts.fragment):
        values = parse_qs(source).get("lck", [])
        if values and 0 < len(values[0]) <= 1024 and not any(
                ord(c) < 32 for c in values[0]):
            return values[0]
    return None


class CampusSession:
    """Drop-in original-URL requests interface for the iCourse API client."""

    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = True
        self.session.proxies.clear()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.logged_in = False

    def _request(self, method, url, *, auth_only=False, **kwargs):
        _checked_url(url, auth_only=auth_only)
        if kwargs.get("verify", True) is not True or kwargs.get("proxies"):
            raise CampusAccessError("学校连接必须验证 TLS 证书并使用系统路由。")
        kwargs["verify"] = True
        kwargs["proxies"] = {}
        kwargs["allow_redirects"] = False
        kwargs.setdefault("timeout", (5, 30))
        # Keep these invariants even if an integration reused this Session.
        self.session.trust_env = False
        self.session.verify = True
        self.session.proxies.clear()
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            raise CampusAccessError("学校连接的 TLS 证书验证失败。") from None
        except requests.exceptions.Timeout:
            raise CampusAccessError("连接学校服务超时。请确认 aTrust 或校园网连接后重试。") from None
        except requests.exceptions.ConnectionError:
            raise CampusAccessError("无法建立学校网络连接。请确认 aTrust 或校园网连接后重试。") from None
        except requests.exceptions.RequestException:
            raise CampusAccessError(
                "无法连接学校服务。校外请确认 aTrust 已连接；校内请确认使用校园网。"
            ) from None

    def _follow_get(self, url, *, auth_only=False, **kwargs):
        visited = []
        for _ in range(MAX_REDIRECTS + 1):
            response = self._request("GET", url, auth_only=auth_only, **kwargs)
            visited.append(response.url or url)
            if response.status_code not in REDIRECT_CODES:
                return response, visited
            location = response.headers.get("Location")
            if not location:
                response.close()
                raise CampusAccessError("学校登录跳转缺少目标地址。")
            try:
                next_url = _checked_url(
                    urljoin(response.url or url, html.unescape(location)),
                    auth_only=auth_only,
                )
            finally:
                response.close()
            url = next_url
            kwargs.pop("params", None)
        raise CampusAccessError("学校登录跳转次数过多。")

    def get(self, url, **kwargs):
        follow = kwargs.pop("allow_redirects", True)
        if follow:
            return self._follow_get(url, **kwargs)[0]
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        # Never automatically replay a POST body after a 307/308 response.
        kwargs.pop("allow_redirects", None)
        return self._request("POST", url, **kwargs)

    get_raw = get
    post_raw = post

    @staticmethod
    def _json(response, stage, *, require_code=False):
        if response.status_code != 200:
            status = response.status_code if type(response.status_code) is int else "未知"
            raise CampusAccessError(f"{stage}失败：学校服务返回 HTTP {status}。")
        try:
            data = response.json()
        except ValueError:
            raise CampusAccessError(f"{stage}失败：学校服务未返回有效 JSON。") from None
        if not isinstance(data, dict):
            raise CampusAccessError(f"{stage}失败：学校服务响应格式异常。")
        code = data.get("code")
        if (require_code or code is not None) and (
                isinstance(code, bool) or str(code) not in ("0", "200")):
            safe_code = str(code) if type(code) in (int, str) and re.fullmatch(r"-?[0-9]{1,8}", str(code)) else "未知"
            raise CampusAccessError(f"{stage}失败：学校服务未确认成功（业务码 {safe_code}）。")
        return data

    def _verify_session(self):
        response = self._request(
            "GET", ICOURSE_BASE + "/userapi/v1/infosimple", auth_only=True,
            timeout=(5, 10),
        )
        try:
            self._json(response, "iCourse 会话校验", require_code=True)
            return True
        except CampusAccessError:
            return False
        finally:
            response.close()

    def login(self, student_id, password):
        return self.authenticate_icourse(student_id, password)

    def authenticate_icourse(self, student_id=None, password=None):
        """Use an existing CAS login, or authenticate directly at Fudan's IDP.

        Credentials are never stored on the object, read from configuration,
        printed, or passed to a redirect destination.
        """
        self.logged_in = False
        if self._verify_session():
            self.logged_in = True
            return True

        cas_url = ICOURSE_BASE + "/casapi/index.php?" + urlencode({
            "r": "auth/login", "school_login": "1",
            "tenant_code": config.TENANT_CODE, "forward": ICOURSE_BASE + "/",
        })
        response, visited = self._follow_get(cas_url, auth_only=True)
        if response.status_code != 200:
            response.close()
            raise CampusAccessError("iCourse CAS 登录入口返回异常状态。")
        lck = next((value for url in visited if (value := _lck_from_url(url))), None)
        # Some IDP versions render the SPA location in HTML instead of an HTTP
        # redirect. Only accept context rendered by the exact official IDP host.
        if not lck and urlsplit(response.url or visited[-1]).hostname == "id.fudan.edu.cn":
            match = re.search(r"[?&]lck=([^&\s\"'<>]{1,1024})", html.unescape(response.text[:16384]))
            if match:
                lck = parse_qs("lck=" + match.group(1)).get("lck", [None])[0]
        response.close()
        if self._verify_session():
            self.logged_in = True
            return True
        if not lck:
            raise CampusAccessError("学校 CAS 未提供有效认证上下文，请重新登录。")
        if not isinstance(student_id, str) or not student_id or not isinstance(password, str) or not password:
            raise CampusAccessError("本次需要在本机输入复旦学号和 UIS 密码。")

        headers = {"Referer": IDP_BASE + "/ac/", "Origin": IDP_BASE}
        response = self._request(
            "POST", IDP_BASE + "/idp/authn/queryAuthMethods", auth_only=True,
            json={"lck": lck, "entityId": ICOURSE_BASE}, headers=headers,
        )
        try:
            methods = self._json(response, "认证方式查询")
        finally:
            response.close()
        method_list = methods.get("data")
        chain = next((m.get("authChainCode") for m in method_list
                      if isinstance(m, dict) and m.get("moduleCode") == "userAndPwd"), None) if isinstance(method_list, list) else None
        if not isinstance(chain, str) or not chain:
            raise CampusAccessError("学校未开放当前密码认证方式，可能需要浏览器完成二次验证。")

        response = self._request(
            "GET", IDP_BASE + "/idp/authn/getJsPublicKey", auth_only=True,
            headers=headers,
        )
        try:
            key = self._json(response, "认证公钥获取").get("data")
        finally:
            response.close()
        if not isinstance(key, str) or not key:
            raise CampusAccessError("学校认证公钥无效。")
        try:
            # This is a pure local RSA operation; no WebVPN helper performs I/O.
            encrypted = WebVPNSession._encrypt_password(self, password, key)
        except (ValueError, TypeError, IndexError):
            raise CampusAccessError("学校认证公钥无法使用。") from None
        response = self._request(
            "POST", IDP_BASE + "/idp/authn/authExecute", auth_only=True,
            headers=headers, json={
                "authModuleCode": "userAndPwd", "authChainCode": chain,
                "entityId": ICOURSE_BASE,
                "requestType": methods.get("requestType", "chain_type"),
                "lck": lck,
                "authPara": {"loginName": student_id, "password": encrypted, "verifyCode": ""},
            },
        )
        try:
            result = self._json(response, "UIS 认证", require_code=True)
        finally:
            response.close()
        if str(result.get("code")) != "200":
            raise CampusAccessError("UIS 未确认认证成功。")
        token = result.get("loginToken")
        if not isinstance(token, str) or not token:
            raise CampusAccessError("UIS 未返回登录凭据，可能需要完成二次验证。")

        engine_url = IDP_BASE + "/idp/authCenter/authnEngine"
        response = self._request(
            "POST", engine_url, auth_only=True, headers=headers,
            data={"loginToken": token},
        )
        if response.status_code in REDIRECT_CODES:
            location = response.headers.get("Location", "")
            ticket_url = urljoin(response.url or engine_url, html.unescape(location)) if location else ""
        elif response.status_code == 200:
            body = response.text[:131072]
            match = re.search(r"locationValue\s*=\s*([\"'])(.*?)\1", body, re.S)
            if not match:
                match = re.search(r"(https://[^\s\"'<>]*[?&]ticket=[^\s\"'<>]*)", body)
                location = match.group(1) if match else ""
            else:
                location = match.group(2)
            ticket_url = urljoin(response.url or engine_url, html.unescape(location)) if location else ""
            if (not ticket_url or urlsplit(ticket_url).hostname != "icourse.fudan.edu.cn"
                    or not parse_qs(urlsplit(ticket_url).query).get("ticket")):
                response.close()
                raise CampusAccessError("UIS 未返回有效的 iCourse CAS 票据。")
        else:
            ticket_url = ""
        response.close()
        if not ticket_url:
            raise CampusAccessError("UIS 未返回有效的 iCourse CAS 跳转。")
        response, _ = self._follow_get(ticket_url, auth_only=True)
        response.close()
        if not self._verify_session():
            raise CampusAccessError("iCourse 未确认登录成功，学校会话校验失败。")
        self.logged_in = True
        return True


def probe_campus_access(timeout=5.0):
    """Check original-domain HTTPS reachability without cookies or credentials.

    This does not claim the user is on campus, logged in, or authorized. It does
    not inspect process names, change routes, follow login redirects, or use a
    proxy. Connect/read waits are capped at 10 seconds each.
    """
    timeout = max(0.5, min(float(timeout), 10.0))
    session = requests.Session()
    session.trust_env = False
    session.verify = True
    session.proxies.clear()
    try:
        response = session.get(
            ICOURSE_BASE + "/", timeout=(timeout, timeout), verify=True,
            proxies={}, allow_redirects=False, stream=True,
        )
        try:
            code = response.status_code
            if code in REDIRECT_CODES:
                target = urljoin(ICOURSE_BASE + "/", response.headers.get("Location", ""))
                try:
                    _checked_url(target, auth_only=True)
                except CampusAccessError:
                    return {"reachable": False, "status_code": code, "reason": "unexpected_redirect"}
                return {"reachable": True, "status_code": code, "reason": "ok"}
            return {"reachable": 200 <= code < 300 or code in (401, 403),
                    "status_code": code, "reason": "ok" if 200 <= code < 300 else "http"}
        finally:
            response.close()
    except requests.exceptions.SSLError:
        return {"reachable": False, "status_code": None, "reason": "tls"}
    except requests.exceptions.RequestException:
        return {"reachable": False, "status_code": None, "reason": "network"}
    finally:
        session.close()
