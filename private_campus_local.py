"""Local campus/aTrust collection; only encrypted course material goes to GitHub."""

import base64
import contextlib
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
from urllib.parse import urlsplit

import requests
from nacl.public import PublicKey, SealedBox

from private_local import GitHub, UserError, ROOT, NOTES, REPO
from private_material_collect import collect_lecture, MaterialCollectionError
from private_material_protocol import (
    MAGIC, MAX_ENCRYPTED, encrypt_bundle, validate_asset_url, validate_material_job,
)
from src.api.campus import CampusAccessError, CampusSession, probe_campus_access
from src.api.icourse import ICourseClient


WORKFLOW = 'private-material.yml'
JOURNAL_FIELDS = {'version', 'repo', 'job_id', 'release_id', 'release_pending', 'secret_pending'}
ID_RE = re.compile(r'[0-9]{1,32}')
JOB_RE = re.compile(r'[0-9a-f]{32}')


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _valid_id(value):
    return type(value) is int and 0 < value < 10**24


class MaterialGitHub(GitHub):
    """Use a private draft release as transient, encrypted input storage.

    Cleanup journals contain identifiers only. A lost response during release
    creation is recovered by looking up the exact random tag on the next run.
    """

    def __init__(self, token, repo=REPO, workflow=WORKFLOW):
        super().__init__(token, repo=repo, workflow=workflow)
        self.journal_dir = NOTES / 'pending-material-cleanup'

    def _journal_path(self, job_id):
        if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id):
            raise UserError('本次任务标识无效。')
        return self.journal_dir / (job_id + '.json')

    def _read_journal(self, job_id):
        path = self._journal_path(job_id)
        if not path.exists():
            return {'version': 1, 'repo': self.repo, 'job_id': job_id, 'release_id': None,
                    'release_pending': False, 'secret_pending': False}
        if path.stat().st_size > 4096:
            raise UserError('本机清理记录格式异常，请保留文件以便检查。')
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            if (not isinstance(value, dict) or set(value) != JOURNAL_FIELDS
                    or value['version'] != 1 or value['repo'] != self.repo or value['job_id'] != job_id
                    or type(value['release_pending']) is not bool or type(value['secret_pending']) is not bool
                    or (value['release_id'] is not None and not _valid_id(value['release_id']))):
                raise ValueError
            return value
        except (ValueError, KeyError, TypeError):
            raise UserError('本机清理记录格式异常，请保留文件以便检查。') from None

    def _record(self, job_id, **changes):
        value = self._read_journal(job_id)
        value.update(changes)
        # Explicitly enumerate saved fields so a URL/key can never reach disk.
        if set(value) != JOURNAL_FIELDS:
            raise UserError('清理记录字段无效。')
        _atomic_json(self._journal_path(job_id), value)

    def preflight(self):
        workflow = self.call('GET', '/actions/workflows/' + self.workflow)
        if not isinstance(workflow, dict) or workflow.get('state') != 'active':
            raise UserError('请先启用 GitHub 的 Private Campus Materials 工作流。')

    def put_job(self, name, job):
        validate_material_job(job)
        if name != 'ICS_SESSION_' + job['job_id'].upper():
            raise UserError('临时 Secret 名称不匹配。')
        self._record(job['job_id'], secret_pending=True)
        public = self.call('GET', '/actions/secrets/public-key')
        encrypted = SealedBox(PublicKey(base64.b64decode(public['key'], validate=True))).encrypt(
            json.dumps(job, separators=(',', ':')).encode('utf-8'))
        self.call('PUT', '/actions/secrets/' + name, json={
            'encrypted_value': base64.b64encode(encrypted).decode('ascii'), 'key_id': public['key_id']})

    def remove_job(self, name):
        if not re.fullmatch(r'ICS_SESSION_[0-9A-F]{32}', name):
            raise UserError('拒绝删除名称不匹配的 Secret。')
        removed = super().remove_job(name)
        if removed:
            job_id = name[len('ICS_SESSION_'):].lower()
            self._record(job_id, secret_pending=False)
        return removed

    def _upload_url(self, value, release_id):
        if not isinstance(value, str):
            raise UserError('GitHub 素材上传地址无效。')
        if value.endswith('{?name,label}'):
            value = value[:-len('{?name,label}')]
        expected_path = f'/repos/{self.repo}/releases/{release_id}/assets'
        try:
            parsed = urlsplit(value)
            if (parsed.scheme != 'https' or parsed.hostname != 'uploads.github.com'
                    or parsed.port not in (None, 443) or parsed.username is not None or parsed.password is not None
                    or parsed.path != expected_path or parsed.query or parsed.fragment
                    or '\\' in value or any(ord(c) < 33 for c in value)):
                raise ValueError
        except ValueError:
            raise UserError('拒绝向非 GitHub 素材上传地址发送令牌。') from None
        return value

    def upload_material(self, encrypted_path, job_id):
        """Upload ciphertext and return a short-lived URL, never an API token."""
        path = Path(encrypted_path)
        size = path.stat().st_size
        with path.open('rb') as source:
            if not len(MAGIC) + 28 < size <= MAX_ENCRYPTED or source.read(len(MAGIC)) != MAGIC:
                raise UserError('只允许上传本机已加密的课程素材。')
        # Persist the random identity before the first mutation, so an unknown
        # POST outcome remains recoverable without saving any secret.
        self._record(job_id, release_pending=True)
        release = self.call('POST', '/releases', json={
            'tag_name': 'ics-private-' + job_id, 'target_commitish': 'main',
            'name': 'ics-private-' + job_id, 'draft': True, 'prerelease': False,
            'body': 'Temporary encrypted input. Managed by the local iCourse helper.',
        })
        release_id = release.get('id') if isinstance(release, dict) else None
        if not _valid_id(release_id):
            raise UserError('GitHub 未返回有效的临时素材编号。')
        self._record(job_id, release_id=release_id)
        if release.get('draft') is not True or release.get('tag_name') != 'ics-private-' + job_id:
            raise UserError('GitHub 临时素材不是预期的草稿，已停止上传。')
        upload_url = self._upload_url(release.get('upload_url'), release_id)
        name = 'materials-' + job_id + '.enc'
        with path.open('rb') as source:
            response = self.http.post(
                upload_url, params={'name': name}, data=source,
                headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(size)},
                timeout=(10, 600), allow_redirects=False, verify=True,
            )
        try:
            if response.status_code != 201:
                raise UserError('加密素材上传失败，请检查 GitHub 令牌的 Contents 读写权限和网络。')
            try:
                asset = response.json()
            except ValueError:
                raise UserError('GitHub 未返回有效的素材上传结果。') from None
        finally:
            response.close()
        if (not isinstance(asset, dict) or not _valid_id(asset.get('id')) or asset.get('state') != 'uploaded'
                or asset.get('name') != name or asset.get('size') != size):
            raise UserError('加密素材上传结果未通过完整性检查。')
        response = self.http.get(
            self.base + '/releases/assets/' + str(asset['id']),
            headers={'Accept': 'application/octet-stream'}, stream=True,
            timeout=45, allow_redirects=False, verify=True,
        )
        try:
            # GitHub may return 200 with the binary body. That is unusable for a
            # runner without an API token; never fall back to sharing the token.
            if response.status_code != 302:
                raise UserError('GitHub 没有提供临时素材下载地址，本次已停止；不会向云端提供令牌。')
            try:
                return validate_asset_url(response.headers.get('Location', ''))
            except ValueError:
                raise UserError('GitHub 临时素材下载地址未通过检查。') from None
        finally:
            response.close()

    def _release_is_ours(self, release, job_id):
        return (isinstance(release, dict) and release.get('draft') is True
                and release.get('tag_name') == 'ics-private-' + job_id and _valid_id(release.get('id')))

    def _delete_release(self, release_id, job_id):
        response = self.http.get(self.base + f'/releases/{release_id}',
                                 timeout=30, allow_redirects=False, verify=True)
        try:
            if response.status_code == 404:
                return True
            if response.status_code != 200:
                return False
            release = response.json()
            if not self._release_is_ours(release, job_id) or release['id'] != release_id:
                return False
        finally:
            response.close()
        response = self.http.delete(self.base + f'/releases/{release_id}',
                                    timeout=30, allow_redirects=False, verify=True)
        try:
            return response.status_code in (204, 404)
        finally:
            response.close()

    def cleanup_job(self, job_id):
        """Delete only our exact draft and Secret; retain IDs on uncertainty."""
        try:
            value = self._read_journal(job_id)
            if value['secret_pending']:
                self.remove_job('ICS_SESSION_' + job_id.upper())
                value = self._read_journal(job_id)
            if value['release_pending']:
                release_id = value['release_id']
                complete = False
                if release_id is not None:
                    complete = self._delete_release(release_id, job_id)
                else:
                    # Resolve an unknown create response using only the saved
                    # random identity. Stop after a bounded 1,000 releases.
                    for page in range(1, 11):
                        releases = self.call('GET', '/releases', params={'per_page': 100, 'page': page})
                        if not isinstance(releases, list):
                            break
                        matches = [r for r in releases if self._release_is_ours(r, job_id)]
                        if matches:
                            complete = all(self._delete_release(r['id'], job_id) for r in matches)
                            break
                        if len(releases) < 100:
                            complete = True
                            break
                if complete:
                    self._record(job_id, release_pending=False, release_id=None)
                value = self._read_journal(job_id)
            if not value['release_pending'] and not value['secret_pending']:
                self._journal_path(job_id).unlink(missing_ok=True)
                return True
        except Exception:
            pass
        print('本次云端临时素材或 Secret 尚未确认删除；已保留不含秘密的清理编号，下次输入令牌后重试。')
        return False

    def cleanup_pending(self):
        if not self.journal_dir.exists():
            return True
        paths = list(self.journal_dir.glob('*.json'))
        if len(paths) > 1000:
            raise UserError('待清理记录过多，请先检查本机清理目录。')
        success = True
        for path in paths:
            if not JOB_RE.fullmatch(path.stem):
                continue
            success = self.cleanup_job(path.stem) and success
        return success

    def close(self):
        self.http.headers.pop('Authorization', None)
        self.http.close()


def _diagnostic(stage, success, error=None):
    # Deliberately do not attach Requests hooks: URLs, headers and bodies never
    # enter this log, and exception text is not serialized.
    path = ROOT / 'logs' / 'campus-login-diagnostic.json'
    kind = type(error).__name__ if error is not None else None
    allowed = {'CampusAccessError', 'UserError', 'ConnectionError', 'Timeout', 'SSLError'}
    value = {'version': 1, 'time_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
             'mode': 'campus_system_route', 'stage': stage, 'success': bool(success),
             'error_type': kind if kind in allowed else ('OtherError' if kind else None)}
    # CampusAccessError is our own fixed-message error, never an HTTP body or
    # Requests exception. Retain its safe stage/status information for diagnosis.
    if isinstance(error, CampusAccessError):
        value['detail'] = str(error)
    try:
        _atomic_json(path, value)
    except OSError:
        return False
    return True


def _require_reachable():
    result = probe_campus_access(timeout=5)
    if not result.get('reachable'):
        _diagnostic('NETWORK_PROBE', False)
        if result.get('reason') == 'tls':
            raise UserError('学校连接的 TLS 证书未通过验证，已停止连接。')
        raise UserError('暂时无法连接 iCourse 原始地址。校外请先连接 aTrust；校内请连接校园网后重试。')


def _login_campus(student_id, password):
    campus = CampusSession()
    stage = 'CAMPUS_LOGIN'
    try:
        campus.login(student_id, password)
        stage = 'ICOURSE_VERIFY'
        if not ICourseClient(campus).check_alive():
            raise UserError('登录校验失败。')
        _diagnostic(stage, True)
        return campus
    except Exception as exc:
        campus.session.close()
        saved = _diagnostic(stage, False, exc)
        notice = ('\n脱敏日志：' + str(ROOT / 'logs' / 'campus-login-diagnostic.json')) if saved else ''
        detail = str(exc) if isinstance(exc, CampusAccessError) else '学校直连登录未成功。请确认 aTrust 或校园网连接，及学校是否要求二次验证。'
        raise UserError(detail + notice) from None


def diagnose_campus():
    print('仅检查本机 iCourse 直连登录；不使用 GitHub，不上传密码或会话。')
    _require_reachable()
    student_id = input('复旦学号（仅用于本机登录）：').strip()
    password = getpass.getpass('UIS 密码（不保存，不回显）：')
    try:
        campus = _login_campus(student_id, password)
        campus.session.close()
        print('本机 iCourse 原始域名登录和会话校验成功，流量使用当前校园网/aTrust 路由。')
    finally:
        del student_id, password


def _courses_and_date():
    courses = [value.strip() for value in input('课程 ID（英文逗号分隔）：').split(',') if value.strip()]
    courses = list(dict.fromkeys(courses))
    if not 1 <= len(courses) <= 30 or any(not ID_RE.fullmatch(value) for value in courses):
        raise UserError('请输入 1 至 30 个纯数字课程 ID。')
    default = (dt.date.today() - dt.timedelta(days=7)).isoformat()
    since = input(f'从哪天开始处理 YYYY-MM-DD（回车为 {default}）：').strip() or default
    try:
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', since):
            raise ValueError
        dt.date.fromisoformat(since)
    except ValueError:
        raise UserError('日期格式无效，请使用 YYYY-MM-DD。') from None
    return courses, since


def _read_completed():
    path = NOTES / 'completed.json'
    if not path.exists():
        return set()
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, list) or any(not isinstance(s, str) or not ID_RE.fullmatch(s) for s in value):
            raise ValueError
        return set(value)
    except (OSError, ValueError):
        raise UserError('本机已完成课次记录格式异常，请保留文件以便检查。') from None


def _merge_result(aggregate, path, course_id, sub_id):
    path = Path(path)
    if path.stat().st_size > 100 * 1024**2:
        raise UserError('云端返回的课次文本过大。')
    result = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(result, dict) or not isinstance(result.get('items'), list) or not isinstance(result.get('errors'), list):
        raise UserError('云端课次文本格式异常。')
    clean_items = []
    for item in result['items']:
        fields = {'course_id', 'sub_id', 'course_title', 'sub_title', 'date', 'prompt'}
        if (not isinstance(item, dict) or set(item) != fields or item['course_id'] != course_id
                or item['sub_id'] != sub_id or any(not isinstance(item[f], str) for f in fields)
                or not item['prompt'].strip()):
            raise UserError('云端返回的课次编号或文本格式不匹配。')
        clean_items.append(item)
    if len(clean_items) > 1:
        raise UserError('云端返回了多余课次。')
    errors = []
    for error in result['errors']:
        if not isinstance(error, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', error):
            raise UserError('云端返回了未知错误格式。')
        errors.append(error + ':' + sub_id)
    aggregate['items'].extend(clean_items)
    aggregate['errors'].extend(errors)


def _quiet_call(method, *args, **kwargs):
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        return method(*args, **kwargs)


def process_courses(client, gh, courses, since, completed):
    """Collect/upload one lecture at a time, committing partial results locally."""
    aggregate = {'items': [], 'errors': []}
    target = NOTES / ('input-' + secrets.token_hex(16) + '.json')
    _atomic_json(target, aggregate)
    seen = set()
    gh.preflight()
    for course_id in courses:
        if not _quiet_call(client.check_alive):
            aggregate['errors'].append('SESSION_EXPIRED')
            _atomic_json(target, aggregate)
            break
        try:
            detail = _quiet_call(client.get_course_detail, course_id)
            lectures = detail['lectures']
            title = detail['title']
            if not isinstance(lectures, list) or not isinstance(title, str):
                raise ValueError
        except Exception:
            aggregate['errors'].append('COURSE_UNAVAILABLE:' + course_id)
            _atomic_json(target, aggregate)
            continue
        for lecture in lectures:
            if not isinstance(lecture, dict) or lecture.get('has_playback') is not True:
                continue
            sub_id = str(lecture.get('sub_id', ''))
            date = lecture.get('date', '') or str(lecture.get('sub_title', ''))[:10]
            if not ID_RE.fullmatch(sub_id) or sub_id in completed or (course_id, sub_id) in seen:
                continue
            seen.add((course_id, sub_id))
            try:
                if not isinstance(date, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', date):
                    raise ValueError
                dt.date.fromisoformat(date)
            except ValueError:
                aggregate['errors'].append('LECTURE_DATE_INVALID:' + sub_id)
                _atomic_json(target, aggregate)
                continue
            if date < since:
                continue
            if not _quiet_call(client.check_alive):
                aggregate['errors'].append('SESSION_EXPIRED')
                _atomic_json(target, aggregate)
                return target
            print('处理课程 ' + course_id + '，课次 ' + sub_id + '；已取回的结果会逐课保存。')
            job_id = secrets.token_hex(16)
            stage = 'LOCAL_COLLECTION_FAILED'
            try:
                with tempfile.TemporaryDirectory(prefix='icourse-material-') as directory:
                    directory = Path(directory)
                    archive = Path(collect_lecture(client, course_id, title, {**lecture, 'date': date}, directory, job_id))
                    if archive.resolve().parent != directory.resolve() or not archive.is_file():
                        raise UserError('本机素材包位置无效。')
                    input_key = secrets.token_bytes(32)
                    encrypted = directory / ('materials-' + job_id + '.enc')
                    encrypt_bundle(archive, encrypted, input_key, job_id)
                    archive.unlink()
                    stage = 'MATERIAL_UPLOAD_FAILED'
                    asset_url = gh.upload_material(encrypted, job_id)
                    job = {'version': 2, 'job_id': job_id, 'expires_at': int(time.time()) + 21600,
                           'input_key': base64.b64encode(input_key).decode('ascii'),
                           'result_key': base64.b64encode(secrets.token_bytes(32)).decode('ascii'),
                           'asset_url': asset_url}
                    validate_material_job(job)
                    stage = 'CLOUD_EXTRACTION_FAILED'
                    result_path = gh.run(job)
                    _merge_result(aggregate, result_path, course_id, sub_id)
                    _atomic_json(target, aggregate)
                    job.clear()
                    del input_key, asset_url
            except Exception as exc:
                aggregate['errors'].append(stage + ':' + sub_id)
                _atomic_json(target, aggregate)
                print('本课次未完成（' + stage + '），已有结果已保留。')
                if isinstance(exc, (MaterialCollectionError, CampusAccessError, UserError)):
                    print(str(exc))
            finally:
                gh.cleanup_job(job_id)
    _atomic_json(target, aggregate)
    if not aggregate['items']:
        print('本次没有新取回的课次文本；可检查日期、课次开放状态或处理提示。')
    return target


def cloud_extract_campus():
    print('校外请先连接 aTrust；校内连接校园网即可。学校会话始终只留在本机。')
    gh = None
    campus = None
    try:
        print('GitHub 令牌需要仅限此仓库的 Contents、Actions、Secrets 读写权限。')
        token = getpass.getpass('GitHub 仓库访问令牌（只在本机使用，不保存、不上传云端）：').strip()
        try:
            if not token:
                raise UserError('GitHub 令牌不能为空。')
            gh = MaterialGitHub(token)
        finally:
            del token
        if not gh.cleanup_pending():
            raise UserError('上次临时文件尚未清理成功，请确认令牌权限和网络后重试。')
        gh.preflight()
        _require_reachable()
        student_id = input('复旦学号（仅用于本机登录）：').strip()
        password = getpass.getpass('UIS 密码（不保存，不回显）：')
        try:
            campus = _login_campus(student_id, password)
        finally:
            del student_id, password
        courses, since = _courses_and_date()
        completed = _read_completed()
        return process_courses(ICourseClient(campus), gh, courses, since, completed)
    finally:
        if campus is not None:
            campus.session.close()
        if gh is not None:
            gh.close()
