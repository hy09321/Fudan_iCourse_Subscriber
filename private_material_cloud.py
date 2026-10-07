"""Fetch encrypted materials early, then perform offline ASR/OCR on a runner."""
import json
import os
from pathlib import Path
import sys
import tempfile
import requests

from private_material_protocol import (
    MAX_ENCRYPTED, decrypt_bundle, validate_material_job,
)
from private_protocol import encrypt_result


def read_job(*, check_expiry=True):
    raw = os.environ.pop('ICS_MATERIAL_JOB', '')
    job = json.loads(raw)
    validate_material_job(job, check_expiry=check_expiry)
    if job['job_id'] != os.environ.get('ICS_JOB_ID'):
        raise ValueError('Job mismatch')
    return job


def fetch_material(job, directory):
    key, _ = validate_material_job(job)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    encrypted = directory / 'input.enc'
    try:
        # No GitHub token, school cookie or Authorization header is available.
        with requests.Session() as session:
            session.trust_env = False
            with session.get(job['asset_url'], stream=True, timeout=(20, 120),
                             allow_redirects=False) as response:
                if response.status_code != 200:
                    raise ValueError('Material download failed or link expired')
                total = 0
                with encrypted.open('wb') as output:
                    for chunk in response.iter_content(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_ENCRYPTED:
                            raise ValueError('Material download too large')
                        output.write(chunk)
        return decrypt_bundle(encrypted, directory / 'input.zip', key, job['job_id'])
    finally:
        encrypted.unlink(missing_ok=True)


def self_test():
    from private_material_protocol import encrypt_bundle
    from private_protocol import decrypt_result
    from private_material_worker import process_bundle
    from PIL import Image, ImageDraw, ImageFont
    import io
    import zipfile
    job_id = '1' * 32
    manifest = {
        'version': 1, 'job_id': job_id,
        'lecture': {'course_id': '1', 'sub_id': '2', 'course_title': 'Synthetic',
                    'sub_title': 'Test', 'date': '2026-10-07', 'duration_hint_s': 1},
        'transcript_segments': [{'start_ms': 0, 'end_ms': 1000, 'text': 'Offline integration test.'}],
        'audio': None, 'ppt': [{'file': 'ppt/000001.jpg', 'created_sec': 0}],
    }
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        source = folder / 'source.zip'
        picture = Image.new('RGB', (1200, 300), 'white')
        draw = ImageDraw.Draw(picture)
        draw.text((50, 80), 'CLOUD OCR TEST', fill='black', font=ImageFont.load_default(size=70))
        pixels = io.BytesIO()
        picture.save(pixels, format='JPEG')
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('manifest.json', json.dumps(manifest))
            archive.writestr('ppt/000001.jpg', pixels.getvalue())
        key = os.urandom(32)
        encrypt_bundle(source, folder / 'input.enc', key, job_id)
        decrypt_bundle(folder / 'input.enc', folder / 'verified.zip', key, job_id)
        result = process_bundle(folder / 'verified.zip', folder / 'worker', expected_job_id=job_id)
        assert result['items'] and not result['errors'], 'Offline processing failed'
        assert 'CLOUD' in result['items'][0]['prompt'].upper(), 'Cloud OCR did not recognize synthetic image'
        assert decrypt_result(encrypt_result(result, key, job_id), key, job_id) == result
        # Prove the installed cloud wheels can import; no school access occurs.
        from src.ai.transcriber import Transcriber
        from src.ai.ocr import ocr_image_text
    print('Encrypted material integration and cloud dependency imports passed.')


def main():
    if os.environ.get('ICS_TEST_MODE') == 'true':
        if '--fetch' not in sys.argv:
            self_test()
        return 0
    job = read_job(check_expiry='--fetch' in sys.argv)
    directory = Path(os.environ['ICS_MATERIAL_DIR'])
    if '--fetch' in sys.argv:
        fetch_material(job, directory)
        print('Encrypted material authenticated. School credentials were not provided.')
        return 0
    from private_material_worker import process_bundle
    _, result_key = validate_material_job(job, check_expiry=False)
    result = process_bundle(directory / 'input.zip', directory / 'work', expected_job_id=job['job_id'])
    output = Path(os.environ['ICS_RESULT_DIR'])
    output.mkdir(parents=True, exist_ok=True)
    (output / 'result.enc').write_bytes(encrypt_result(result, result_key, job['job_id']))
    print('Encrypted result ready.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Material processing failed. No private diagnostic data is published.')
        sys.exit(1)
