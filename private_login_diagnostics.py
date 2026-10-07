"""Allowlisted login diagnostics. Never store requests or response bodies."""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import requests


STAGE_LABELS = {
    'UNKNOWN': '登录流程',
    'WEBVPN_LOGIN': 'WebVPN 登录',
    'WEBVPN_CONTEXT': '获取 WebVPN 登录上下文',
    'WEBVPN_AUTH_METHODS': '查询 WebVPN 认证方式',
    'WEBVPN_PUBLIC_KEY': '获取 WebVPN 加密公钥',
    'WEBVPN_AUTH_SUBMIT': '提交 WebVPN 认证',
    'WEBVPN_TICKET': '获取 WebVPN 登录票据',
    'WEBVPN_SESSION': '建立 WebVPN 会话',
    'ICOURSE_LOGIN': 'iCourse 登录',
    'ICOURSE_CAS': '发起 iCourse CAS 登录',
    'ICOURSE_AUTH_METHODS': '查询 iCourse 认证方式',
    'ICOURSE_PUBLIC_KEY': '获取 iCourse 加密公钥',
    'ICOURSE_AUTH_SUBMIT': '提交 iCourse 认证',
    'ICOURSE_TICKET': '获取 iCourse 登录票据',
    'ICOURSE_VERIFY': '校验 iCourse 会话',
    'VERIFY': '校验 iCourse 会话',
}
ERROR_LABELS = {
    'SSL': 'TLS 证书或加密连接校验失败',
    'PROXY': '代理连接失败',
    'TIMEOUT': '连接或响应超时',
    'CONNECTION': '网络连接失败',
    'JSON': '服务返回的数据不是预期的 JSON',
    'REDIRECT': '登录跳转次数过多',
    'HTTP': '服务返回 HTTP 错误',
    'URL': '登录跳转地址格式异常',
    'PROGRAM_ERROR': '登录流程未完成，需要根据当前步骤排查',
}
CATEGORY_LABELS = {
    'CAPTCHA_REQUIRED': '学校认证页面要求验证码或人机验证',
    'SECOND_FACTOR_REQUIRED': '学校认证页面要求额外身份验证',
    'ACCOUNT_REJECTED': '学校认证服务拒绝了本次账号认证，不能据此确定密码输入有误',
    'SERVICE_ERROR': '学校服务返回异常状态',
}
AUTH_SUFFIXES = {
    '/idp/authCenter/authenticate': 'CONTEXT',
    '/idp/authn/queryAuthMethods': 'AUTH_METHODS',
    '/idp/authn/getJsPublicKey': 'PUBLIC_KEY',
    '/idp/authn/authExecute': 'AUTH_SUBMIT',
    '/idp/authCenter/authnEngine': 'TICKET',
}
AUTH_STAGES = frozenset(s for s in STAGE_LABELS if s.endswith(
    ('AUTH_METHODS', 'AUTH_SUBMIT', 'TICKET')))


def _stage_for_url(url):
    # Only compare fixed host/path constants. Never preserve a parsed URL.
    try:
        parsed = urlsplit(url)
        host, path = parsed.hostname, parsed.path
    except (TypeError, ValueError):
        return None
    if host not in ('id.fudan.edu.cn', 'webvpn.fudan.edu.cn', 'icourse.fudan.edu.cn'):
        return None
    if host == 'webvpn.fudan.edu.cn' and path in ('', '/', '/login', '/login/'):
        return 'WEBVPN_SESSION'
    if path.endswith('/userapi/v1/infosimple'):
        return 'ICOURSE_VERIFY'
    if path.endswith('/casapi/index.php'):
        return 'ICOURSE_CAS'
    for suffix, step in AUTH_SUFFIXES.items():
        if path.endswith(suffix):
            prefix = 'WEBVPN' if host == 'id.fudan.edu.cn' else 'ICOURSE'
            stage = prefix + '_' + step
            return stage if stage in STAGE_LABELS else 'ICOURSE_CAS'
    return None


def _error_kind(exc):
    # No exception messages, arbitrary class names, reprs, or tracebacks.
    for exception_type, label in (
        (requests.exceptions.SSLError, 'SSL'),
        (requests.exceptions.ProxyError, 'PROXY'),
        (requests.exceptions.Timeout, 'TIMEOUT'),
        (requests.exceptions.ConnectionError, 'CONNECTION'),
        (json.JSONDecodeError, 'JSON'),
        (requests.exceptions.JSONDecodeError, 'JSON'),
        (requests.exceptions.TooManyRedirects, 'REDIRECT'),
        (requests.exceptions.HTTPError, 'HTTP'),
        (requests.exceptions.InvalidURL, 'URL'),
        (requests.exceptions.InvalidSchema, 'URL'),
        (requests.exceptions.MissingSchema, 'URL'),
    ):
        if isinstance(exc, exception_type):
            return label
    return 'PROGRAM_ERROR'


def _business_code(value):
    if type(value) is int and -999999 <= value <= 999999:
        return str(value)
    if type(value) is str and re.fullmatch(r'-?[0-9]{1,6}', value):
        return value
    return 'non_numeric'


def _message_category(data):
    # Inspect only a small fixed set of authentication message fields; never
    # convert objects to strings and never return their contents.
    messages = [data.get(key) for key in ('msg', 'message', 'errorMessage', 'errMsg')]
    for value in messages:
        if type(value) is not str:
            continue
        value = value[:2048].casefold()
        if any(term in value for term in ('二次验证', '二次认证', '双重认证', '动态口令',
                                          '短信验证', '多因素', 'second factor', 'two-factor', 'mfa', 'otp')):
            return 'SECOND_FACTOR_REQUIRED'
        if any(term in value for term in ('验证码', '人机验证', 'captcha')):
            return 'CAPTCHA_REQUIRED'
        if any(term in value for term in ('密码错误', '用户名或密码', '账号或密码', '账户或密码',
                                          '账号已锁', '账户已锁', '认证失败', 'invalid credential',
                                          'incorrect password', 'account locked', 'authentication failed')):
            return 'ACCOUNT_REJECTED'
    return None


class LoginDiagnostics:
    def __init__(self, path):
        self.path = Path(path)
        self.stage = 'UNKNOWN'
        self.events = []
        self.error = None
        self.success = False
        self.saved = False

    def set_stage(self, stage):
        self.stage = stage if type(stage) is str and stage in STAGE_LABELS else 'UNKNOWN'

    def _event(self, **fields):
        event = {'stage': self.stage if self.stage in STAGE_LABELS else 'UNKNOWN'}
        # Explicit field and value allowlists even for this internal method.
        status = fields.get('http_status')
        if type(status) is int and 100 <= status <= 599:
            event['http_status'] = status
        if fields.get('content') in ('json', 'html', 'other'):
            event['content'] = fields['content']
        if 'code' in fields:
            event['code'] = _business_code(fields['code'])
        if type(fields.get('category')) is str and fields['category'] in CATEGORY_LABELS:
            event['category'] = fields['category']
        if type(fields.get('error')) is str and fields['error'] in ERROR_LABELS:
            event['error'] = fields['error']
        self.events.append(event)
        self.events = self.events[-60:]

    def _on_response(self, response, *args, **kwargs):
        # Diagnostic failure must not change the authentication result.
        try:
            found = _stage_for_url(response.url)
            if found:
                self.set_stage(found)
            kind = response.headers.get('Content-Type', '').lower().split(';', 1)[0].strip()
            content = 'json' if kind == 'application/json' or kind.endswith('+json') else (
                'html' if kind in ('text/html', 'application/xhtml+xml') else 'other')
            fields = {'http_status': response.status_code, 'content': content}
            if content == 'json':
                try:
                    data = response.json()
                except (ValueError, requests.exceptions.RequestException):
                    fields['error'] = 'JSON'
                else:
                    if type(data) is dict:
                        # infosimple's user data is never examined.
                        if 'code' in data:
                            fields['code'] = _business_code(data['code'])
                        if self.stage in AUTH_STAGES:
                            category = _message_category(data)
                            if category:
                                fields['category'] = category
            if type(response.status_code) is int and response.status_code >= 400:
                fields.setdefault('category', 'SERVICE_ERROR')
            self._event(**fields)
        except Exception:
            pass
        return response

    def attach(self, vpn):
        session = vpn.session
        session.hooks.setdefault('response', []).append(self._on_response)
        original = session.request

        def request(method, url, **kwargs):
            found = _stage_for_url(url)
            if found:
                self.set_stage(found)
            try:
                return original(method, url, **kwargs)
            except Exception as exc:
                self._event(error=_error_kind(exc))
                raise

        session.request = request

    def finish(self, success, exc=None):
        self.success = success is True
        self.error = _error_kind(exc) if exc is not None else (None if self.success else 'PROGRAM_ERROR')
        document = {'version': 1, 'success': self.success, 'stage': self.stage,
                    'error': self.error, 'events': self.events}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
            self.saved = True
        except (OSError, ValueError):
            self.saved = False
        return self.saved

    def failure_message(self):
        event = next((e for e in reversed(self.events) if e['stage'] == self.stage), {})
        label = STAGE_LABELS.get(self.stage, STAGE_LABELS['UNKNOWN'])
        reason = CATEGORY_LABELS.get(event.get('category'))
        if self.error and self.error != 'PROGRAM_ERROR':
            reason = ERROR_LABELS[self.error]
        if not reason:
            reason = ERROR_LABELS.get(event.get('error'), ERROR_LABELS['PROGRAM_ERROR'])
        details = []
        if 'http_status' in event:
            details.append('HTTP ' + str(event['http_status']))
        if 'code' in event:
            details.append('业务码 ' + event['code'])
        if 'content' in event:
            details.append('响应类型 ' + {'json': 'JSON', 'html': 'HTML', 'other': '其他'}[event['content']])
        suffix = '（' + '，'.join(details) + '）' if details else ''
        return label + '失败：' + reason + suffix + '。'
