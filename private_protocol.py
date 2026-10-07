"""The only data contract shared by the local helper and the cloud worker.

School passwords, model API keys and GitHub tokens are deliberately absent.
"""
import base64
import json
import re
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FIELDS = {'version', 'job_id', 'expires_at', 'cookies', 'course_ids',
          'since', 'skip_ids', 'result_key'}
MAGIC = b'ICS-PRIVATE-1\0'


def validate_job(job, *, check_expiry=True):
    if not isinstance(job, dict) or set(job) != FIELDS or job['version'] != 1:
        raise ValueError('Unexpected job fields')
    if not re.fullmatch(r'[0-9a-f]{32}', job['job_id']):
        raise ValueError('Invalid job ID')
    if check_expiry and not time.time() < job['expires_at'] <= time.time() + 21660:
        raise ValueError('Session handoff expired; log in again locally')
    key = base64.b64decode(job['result_key'], validate=True)
    if len(key) != 32:
        raise ValueError('Invalid result encryption key')
    if not isinstance(job['course_ids'], list) or not 1 <= len(job['course_ids']) <= 30:
        raise ValueError('Choose 1 to 30 courses')
    if any(not isinstance(i, str) or not re.fullmatch(r'\d{1,20}', i)
           for i in job['course_ids']):
        raise ValueError('Invalid course IDs')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', job['since']):
        raise ValueError('Invalid starting date')
    if not isinstance(job['skip_ids'], list) or any(
            not isinstance(i, str) or not re.fullmatch(r'\d{1,30}', i)
            for i in job['skip_ids']):
        raise ValueError('Invalid completed lecture IDs')
    if not isinstance(job['cookies'], list) or not job['cookies']:
        raise ValueError('No WebVPN session cookies')
    cookie_fields = {'name', 'value', 'domain', 'path', 'secure', 'expires'}
    for cookie in job['cookies']:
        if not isinstance(cookie, dict) or set(cookie) != cookie_fields:
            raise ValueError('Unexpected cookie fields')
        domain = cookie['domain'].lstrip('.').lower()
        if domain != 'webvpn.fudan.edu.cn' and not domain.endswith('.webvpn.fudan.edu.cn'):
            raise ValueError('Only WebVPN cookies may leave this computer')
        for field in ('name', 'value', 'path'):
            if not isinstance(cookie[field], str) or any(c in cookie[field] for c in '\r\n\0'):
                raise ValueError('Invalid cookie')
    if len(json.dumps(job).encode()) > 45000:
        raise ValueError('Session too large for GitHub Secrets')
    return key


def session_cookies(jar):
    return [dict(name=c.name, value=c.value, domain=c.domain, path=c.path,
                 secure=c.secure, expires=c.expires)
            for c in jar if c.domain.lstrip('.').lower() == 'webvpn.fudan.edu.cn'
            or c.domain.lstrip('.').lower().endswith('.webvpn.fudan.edu.cn')]


def encrypt_result(result, key, job_id):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(job_id.encode('ascii'))
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(result, ensure_ascii=False).encode())
    return MAGIC + nonce + tag + ciphertext


def decrypt_result(blob, key, job_id):
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28:
        raise ValueError('Invalid encrypted result')
    data = blob[len(MAGIC):]
    cipher = AES.new(key, AES.MODE_GCM, nonce=data[:12])
    cipher.update(job_id.encode('ascii'))
    return json.loads(cipher.decrypt_and_verify(data[28:], data[12:28]))
