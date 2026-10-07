"""Version 2: encrypted course materials, with no school session handoff."""
import base64
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FIELDS = {'version', 'job_id', 'expires_at', 'input_key', 'result_key', 'asset_url'}
MAGIC = b'ICS-MATERIAL-2\0'
MAX_BUNDLE = 512 * 1024 * 1024
MAX_ENCRYPTED = MAX_BUNDLE + len(MAGIC) + 28
ASSET_HOSTS = {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}


def validate_asset_url(url):
    if not isinstance(url, str) or len(url) > 16000 or '\\' in url or any(ord(c) < 33 for c in url):
        raise ValueError('Invalid asset URL')
    p = urlsplit(url)
    if (p.scheme != 'https' or p.hostname not in ASSET_HOSTS or p.port not in (None, 443)
            or p.username is not None or p.password is not None or p.fragment):
        raise ValueError('Unexpected asset host')
    return url


def validate_material_job(job, *, check_expiry=True):
    if not isinstance(job, dict) or set(job) != FIELDS or type(job['version']) is not int or job['version'] != 2:
        raise ValueError('Unexpected material job fields')
    if not isinstance(job['job_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', job['job_id']):
        raise ValueError('Invalid job ID')
    if type(job['expires_at']) is not int:
        raise ValueError('Invalid expiry')
    if check_expiry and not time.time() < job['expires_at'] <= time.time() + 21660:
        raise ValueError('Material job expired')
    keys = []
    for field in ('input_key', 'result_key'):
        if not isinstance(job[field], str):
            raise ValueError('Invalid encryption key')
        key = base64.b64decode(job[field], validate=True)
        if len(key) != 32:
            raise ValueError('Invalid encryption key')
        keys.append(key)
    validate_asset_url(job['asset_url'])
    return tuple(keys)


def encrypt_bundle(source, destination, key, job_id):
    source, destination = Path(source), Path(destination)
    if not 0 < source.stat().st_size <= MAX_BUNDLE:
        raise ValueError('Material bundle size limit')
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(MAGIC + job_id.encode('ascii'))
    total = 0
    try:
        with source.open('rb') as src, destination.open('wb') as dst:
            dst.write(MAGIC + nonce + bytes(16))
            while chunk := src.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BUNDLE:
                    raise ValueError('Material bundle size limit')
                dst.write(cipher.encrypt(chunk))
            dst.seek(len(MAGIC) + 12)
            dst.write(cipher.digest())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def decrypt_bundle(source, destination, key, job_id):
    source, destination = Path(source), Path(destination)
    if not len(MAGIC) + 28 < source.stat().st_size <= MAX_ENCRYPTED:
        raise ValueError('Encrypted bundle size limit')
    # Never expose partially authenticated plaintext as the final ZIP.
    pending = destination.with_name(destination.name + '.partial')
    try:
        with source.open('rb') as src, pending.open('wb') as dst:
            if src.read(len(MAGIC)) != MAGIC:
                raise ValueError('Invalid encrypted material')
            nonce, tag = src.read(12), src.read(16)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(MAGIC + job_id.encode('ascii'))
            total = 0
            while chunk := src.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BUNDLE:
                    raise ValueError('Material bundle size limit')
                dst.write(cipher.decrypt(chunk))
            cipher.verify(tag)
        pending.replace(destination)
    finally:
        pending.unlink(missing_ok=True)
    return destination
