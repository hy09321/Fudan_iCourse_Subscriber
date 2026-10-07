"""Small local controller: interactive credentials, cloud extraction, local LLM.

Never writes credentials to disk or sends school passwords/model keys to GitHub.
Default mode uses locally collected encrypted materials, not school cookies.
The legacy WebVPN helper remains for compatibility. All runs are interactive.
"""
import base64
import contextlib
import datetime as dt
import getpass
import io
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import sys
import time
import zipfile
from email.message import EmailMessage

import requests
from nacl.public import PublicKey, SealedBox
from private_protocol import validate_job, session_cookies, decrypt_result

ROOT = Path(__file__).resolve().parent
NOTES = ROOT / 'private_notes'
REPO = 'hy09321/Fudan_iCourse_Subscriber'
WORKFLOW = 'private-manual.yml'


class UserError(Exception):
    pass


class GitHub:
    def __init__(self, token, repo=REPO, workflow=WORKFLOW):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
            raise UserError('仓库名称格式错误。')
        self.repo = repo
        self.workflow = workflow
        self.base = 'https://api.github.com/repos/' + repo
        self.http = requests.Session()
        self.http.headers.update({'Authorization': 'Bearer ' + token,
                                  'Accept': 'application/vnd.github+json',
                                  'X-GitHub-Api-Version': '2022-11-28'})

    def call(self, method, path, **kwargs):
        response = self.http.request(method, self.base + path, timeout=45,
                                     allow_redirects=False, **kwargs)
        if not 200 <= response.status_code < 300:
            raise UserError(f'GitHub 请求失败（HTTP {response.status_code}）。请检查仓库及令牌的 Actions、Secrets、Contents 权限。')
        return response.json() if response.content else None

    def put_job(self, name, job):
        validate_job(job)
        public = self.call('GET', '/actions/secrets/public-key')
        encrypted = SealedBox(PublicKey(base64.b64decode(public['key']))).encrypt(
            json.dumps(job).encode())
        self.call('PUT', '/actions/secrets/' + name,
                  json={'encrypted_value': base64.b64encode(encrypted).decode(),
                        'key_id': public['key_id']})

    def remove_job(self, name):
        for attempt in range(3):
            try:
                response = self.http.delete(self.base + '/actions/secrets/' + name,
                                            timeout=30, allow_redirects=False)
                if response.status_code in (204, 404):
                    return True
            except requests.RequestException:
                pass
            if attempt < 2:
                time.sleep(2)
        print('临时 Secret 未能删除。恢复网络后，请在以下页面删除：' + name)
        print('https://github.com/' + self.repo + '/settings/secrets/actions')
        return False

    def run(self, job):
        # Preflight before uploading anything; never auto-enable the old workflow.
        workflow = self.call('GET', '/actions/workflows/' + self.workflow)
        if workflow['state'] != 'active':
            raise UserError('请在 GitHub 启用对应的 Private 工作流。')
        secret_name = 'ICS_SESSION_' + job['job_id'].upper()
        run_id = None
        uploaded = False
        secret_removed = False
        completed = False
        try:
            # Set before upload, so a lost HTTP response still triggers cleanup.
            uploaded = True
            self.put_job(secret_name, job)
            self.call('POST', '/actions/workflows/' + self.workflow + '/dispatches', json={
                'ref': 'main', 'inputs': {'job_id': job['job_id'],
                                        'secret_name': secret_name, 'test_mode': False}})
            job.get('cookies', []).clear()
            print('已提交本次加密任务。等待云端处理；请保持本窗口和网络连接。')
            deadline = time.monotonic() + 7 * 3600
            last_status = None
            queue_deadline = time.monotonic() + 900
            while time.monotonic() < deadline:
                if run_id is None:
                    runs = self.call('GET', '/actions/workflows/' + self.workflow + '/runs',
                                     params={'event': 'workflow_dispatch', 'per_page': 100})['workflow_runs']
                    matching = [r for r in runs if r.get('display_title') == 'private-' + job['job_id']]
                    if not matching:
                        if time.monotonic() > queue_deadline:
                            raise UserError('15 分钟内未找到任务；请查看 GitHub Actions 状态。')
                        time.sleep(12)
                        continue
                    run_id = matching[0]['id']
                    print('任务：https://github.com/' + self.repo + '/actions/runs/' + str(run_id))
                    # Repository Secrets are snapshotted when the run is queued.
                    secret_removed = self.remove_job(secret_name)
                    if secret_removed:
                        print('本次临时 Secret 已从仓库配置删除；排队任务持有本次处理参数。')
                run = self.call('GET', '/actions/runs/' + str(run_id))
                status = run['status']
                if status != last_status:
                    print('云端状态：' + status)
                    last_status = status
                if status == 'completed':
                    completed = True
                    if run['conclusion'] != 'success':
                        raise UserError('云端任务未成功，状态：' + str(run['conclusion']) + '。没有上传密码或模型 Key。')
                    return self.download(run_id, job)
                time.sleep(20)
            raise UserError('等待任务超时。请重新运行。')
        finally:
            if uploaded and not secret_removed:
                self.remove_job(secret_name)
            if run_id and not completed:
                try:
                    self.call('POST', f'/actions/runs/{run_id}/cancel')
                    print('已请求取消尚未完成的云端任务。')
                except Exception:
                    print('未能确认取消，请在 GitHub Actions 中检查本次任务。')

    def download(self, run_id, job):
        artifacts = self.call('GET', f'/actions/runs/{run_id}/artifacts')['artifacts']
        expected = 'private-result-' + job['job_id']
        artifact = next((a for a in artifacts if a['name'] == expected and not a['expired']), None)
        if artifact is None:
            raise UserError('云端未产生结果文件。')
        artifact_id = artifact['id']
        response = self.http.get(self.base + f'/actions/artifacts/{artifact_id}/zip',
                                 timeout=45, allow_redirects=False)
        if response.status_code != 302 or not response.headers.get('Location', '').startswith('https://'):
            raise UserError('无法取得结果下载地址。')
        # Critically: the GitHub Authorization header is NOT sent to blob storage.
        payload = requests.get(response.headers['Location'], timeout=120)
        payload.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(payload.content)) as archive:
            info = archive.getinfo('result.enc')
            if info.file_size > 100 * 1024 * 1024:
                raise UserError('结果文件过大。')
            result = decrypt_result(archive.read(info), base64.b64decode(job['result_key']), job['job_id'])
        NOTES.mkdir(exist_ok=True)
        result_path = NOTES / ('input-' + job['job_id'] + '.json')
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        try:
            self.call('DELETE', f'/actions/artifacts/{artifact_id}')
            print('加密结果已取回，云端 artifact 已删除。')
        except Exception:
            print('加密结果已取回；云端副本未能删除，将按 1 天保留期过期。')
        return result_path


def login_locally(student_id, password):
    from src.api.webvpn import WebVPNSession
    from src.api.icourse import ICourseClient
    from private_login_diagnostics import LoginDiagnostics
    vpn = WebVPNSession()
    diagnostic_path = ROOT / 'logs' / 'login-diagnostic.json'
    diagnostic = LoginDiagnostics(diagnostic_path)
    diagnostic.attach(vpn)
    try:
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            diagnostic.set_stage('WEBVPN_LOGIN')
            vpn.login(student_id, password)
            diagnostic.set_stage('ICOURSE_LOGIN')
            vpn.authenticate_icourse(student_id, password)
            diagnostic.set_stage('ICOURSE_VERIFY')
            if not ICourseClient(vpn).check_alive():
                raise UserError('本机复旦登录校验失败。')
        cookies = session_cookies(vpn.session.cookies)
        if not cookies:
            raise UserError('登录成功但没有可移交的 WebVPN 会话。')
        diagnostic.finish(True)
        return cookies
    except Exception as exc:
        diagnostic.finish(False, exc)
        log_notice = ('\n本机脱敏诊断日志：' + str(diagnostic_path)) if diagnostic.saved else '\n未能写入诊断日志，请保留上方脱敏错误提示。'
        raise UserError(diagnostic.failure_message() + log_notice) from None
    finally:
        vpn.session.close()


def diagnose_login():
    print('仅检查本机复旦登录，不需要 GitHub 令牌，也不会创建云端任务。')
    student_id = input('复旦学号（仅用于本机登录）：').strip()
    password = getpass.getpass('UIS 密码（不保存，不回显）：')
    try:
        print('正在检查本机登录，脱敏日志只记录步骤、状态码及错误类别……')
        cookies = login_locally(student_id, password)
        cookies.clear()
        print('本机复旦登录和 iCourse 会话校验成功。没有上传会话到 GitHub。')
    finally:
        del password, student_id


def make_job(cookies, courses, since, skip_ids):
    job = {'version': 1, 'job_id': secrets.token_hex(16),
           'expires_at': int(time.time()) + 21600, 'cookies': cookies,
           'course_ids': courses, 'since': since, 'skip_ids': skip_ids,
           'result_key': base64.b64encode(secrets.token_bytes(32)).decode()}
    validate_job(job)
    return job


def cloud_extract():
    token = getpass.getpass('GitHub 仓库访问令牌（不保存，不回显）：').strip()
    gh = GitHub(token)
    del token
    try:
        student_id = input('复旦学号（仅用于本机登录）：').strip()
        password = getpass.getpass('UIS 密码（不保存，不回显）：')
        print('正在本机登录复旦……')
        cookies = login_locally(student_id, password)
        del password, student_id
        courses = [s.strip() for s in input('课程 ID（英文逗号分隔）：').split(',') if s.strip()]
        default_date = (dt.date.today() - dt.timedelta(days=7)).isoformat()
        since = input(f'从哪天开始处理 YYYY-MM-DD（回车为 {default_date}）：').strip() or default_date
        dt.date.fromisoformat(since)
        state = NOTES / 'completed.json'
        skip_ids = json.loads(state.read_text(encoding='utf-8')) if state.exists() else []
        job = make_job(cookies, courses, since, skip_ids)
        return gh.run(job)
    finally:
        gh.http.headers.pop('Authorization', None)
        gh.http.close()


def summarize_local(path):
    from openai import OpenAI
    from src.runtime.config import MODEL_PROVIDERS
    from src.ai.summarizer import SYSTEM_PROMPT
    result = json.loads(path.read_text(encoding='utf-8'))
    if result.get('errors'):
        print('云端处理提示：' + '; '.join(result['errors']))
    items = result.get('items', [])
    if not items:
        print('没有可生成摘要的课次。若提示 SESSION_REJECTED，说明会话可能不支持跨 IP；不要改用上传密码。')
        return []
    providers = [p for p in MODEL_PROVIDERS if p['name'] in ('modelscope', 'deepseek', 'gemini')]
    print('模型服务：' + ' / '.join(f'{i + 1} {p["name"]}' for i, p in enumerate(providers)))
    choice = input('选择服务（默认 1）：').strip() or '1'
    if not choice.isdigit() or not 1 <= int(choice) <= len(providers):
        raise UserError('服务选项无效。')
    provider = providers[int(choice) - 1]
    model = input(f'模型名称（回车为 {provider["models"][0]}）：').strip() or provider['models'][0]
    api_key = getpass.getpass('模型 API Key（只在本机调用该服务，不保存、不上传 GitHub）：').strip()
    client = OpenAI(api_key=api_key, base_url=provider['default_base_url'],
                    timeout=240, max_retries=1)
    del api_key
    NOTES.mkdir(exist_ok=True)
    completed_path = NOTES / 'completed.json'
    completed = set(json.loads(completed_path.read_text(encoding='utf-8'))) if completed_path.exists() else set()
    files = []
    try:
        for item in items:
            sub_id = item['sub_id']
            if not re.fullmatch(r'\d{1,30}', sub_id):
                raise UserError('结果中包含无效课次编号。')
            target = NOTES / (sub_id + '.md')
            if sub_id in completed and target.exists():
                files.append(target)
                continue
            print('本机调用模型生成：' + item['course_title'] + ' / ' + item['sub_title'])
            try:
                response = client.chat.completions.create(model=model, messages=[
                    {'role': 'system', 'content': SYSTEM_PROMPT},
                    {'role': 'user', 'content': '课程：' + item['course_title'] + '\n' + item['prompt']}])
                summary = response.choices[0].message.content
                if not summary:
                    raise UserError('模型没有返回摘要。')
                target.write_text('# ' + item['course_title'] + '\n\n## ' + item['sub_title'] + '\n\n' + summary,
                                  encoding='utf-8')
                files.append(target)
                completed.add(sub_id)
                completed_path.write_text(json.dumps(sorted(completed)), encoding='utf-8')
            except Exception as exc:
                # Avoid printing provider responses that can contain credentials.
                print('此课次生成失败（' + type(exc).__name__ + '）。原始结果已保留，可用“仅生成摘要”重试。')
    finally:
        client.close()
    return files


def email_local(files):
    if not files or input('是否将笔记发送给自己？输入 y 发送，回车跳过：').strip().lower() != 'y':
        return
    sender = input('发件 QQ 邮箱：').strip()
    receiver = input('你的收件邮箱：').strip()
    password = getpass.getpass('QQ SMTP 授权码（仅本机使用、不保存）：')
    message = EmailMessage()
    message['From'], message['To'] = sender, receiver
    message['Subject'] = 'iCourse 课程笔记 ' + dt.date.today().isoformat()
    message.set_content('本次课程笔记见附件。')
    for path in files:
        message.add_attachment(path.read_bytes(), maintype='text', subtype='markdown', filename=path.name)
    try:
        with smtplib.SMTP_SSL('smtp.qq.com', 465, timeout=30) as smtp:
            smtp.login(sender, password)
            smtp.send_message(message)
        print('邮件已发送。')
    except Exception:
        print('邮件发送失败；笔记仍保存在本机。')
    finally:
        del password


def main():
    print('iCourse 手动隐私版：复旦密码、模型 Key、GitHub 令牌均在本机输入，不保存到文件。')
    print('学校连接使用 aTrust／校园网；云端仅接收加密课程素材，不接收学校登录会话。')
    print('请保持本窗口开启；Ctrl+C 可取消并清理本次临时文件。')
    print('1 本机读取课程，云端语音识别和 OCR，然后本机生成摘要\n2 对已取回的结果生成摘要（无需重新登录复旦）\n3 仅诊断 aTrust／校园网登录（无需 GitHub 令牌）')
    mode = input('选择（默认 1）：').strip() or '1'
    if mode == '3':
        from private_campus_local import diagnose_campus
        diagnose_campus()
        return
    elif mode == '2':
        candidates = sorted(NOTES.glob('input-*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise UserError('尚无本机结果。请先选择 1。')
        for i, path in enumerate(candidates[:20], 1):
            print(f'{i} {path.name}')
        number = input('选择结果编号（默认 1）：').strip() or '1'
        if not number.isdigit() or not 1 <= int(number) <= min(20, len(candidates)):
            raise UserError('结果编号无效。')
        path = candidates[int(number) - 1]
    elif mode == '1':
        from private_campus_local import cloud_extract_campus
        path = cloud_extract_campus()
    else:
        raise UserError('选项无效。')
    files = summarize_local(path)
    print('笔记目录：' + str(NOTES))
    email_local(files)


if __name__ == '__main__':
    # The campus controller imports this module's shared API. Reuse this exact
    # module when launched as a script, including the same UserError class.
    sys.modules['private_local'] = sys.modules[__name__]
    try:
        main()
    except KeyboardInterrupt:
        print('\n已取消。')
        sys.exit(130)
    except UserError as exc:
        print(str(exc))
        sys.exit(1)
    except Exception as exc:
        print('运行失败（' + type(exc).__name__ + '）。请检查网络和输入；不输出含凭据的诊断信息。')
        sys.exit(1)
