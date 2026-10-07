import base64
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from private_material_protocol import (
    validate_material_job, validate_asset_url, encrypt_bundle, decrypt_bundle,
)


class MaterialProtocolTests(unittest.TestCase):
    def job(self):
        return dict(version=2, job_id='a' * 32, expires_at=int(time.time()) + 3600,
                    input_key=base64.b64encode(b'i' * 32).decode(),
                    result_key=base64.b64encode(b'r' * 32).decode(),
                    asset_url='https://release-assets.githubusercontent.com/test?sig=dummy')

    def test_contract_cannot_accept_credentials_or_school_session(self):
        for field in ('password', 'cookies', 'token', 'api_key'):
            job = self.job()
            job[field] = 'PRIVATE'
            with self.assertRaises(ValueError):
                validate_material_job(job)
        self.assertEqual(validate_material_job(self.job()), (b'i' * 32, b'r' * 32))

    def test_asset_host_and_expiry_restrictions(self):
        for url in ('http://release-assets.githubusercontent.com/x',
                    'https://release-assets.githubusercontent.com.attacker.test/x',
                    'https://user@release-assets.githubusercontent.com/x',
                    'https://release-assets.githubusercontent.com:444/x',
                    'https://icourse.fudan.edu.cn/x'):
            with self.assertRaises(ValueError):
                validate_asset_url(url)
        job = self.job()
        job['expires_at'] = int(time.time()) - 1
        with self.assertRaises(ValueError):
            validate_material_job(job)

    def test_streaming_round_trip_and_authentication_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            src, enc, out = [folder / name for name in ('src.zip', 'in.enc', 'out.zip')]
            src.write_bytes(b'material' * 200000)
            encrypt_bundle(src, enc, b'i' * 32, 'a' * 32)
            decrypt_bundle(enc, out, b'i' * 32, 'a' * 32)
            self.assertEqual(src.read_bytes(), out.read_bytes())
            out.unlink()
            with self.assertRaises(ValueError):
                decrypt_bundle(enc, out, b'i' * 32, 'b' * 32)
            self.assertFalse(out.exists())
            self.assertFalse(out.with_name('out.zip.partial').exists())
            blob = bytearray(enc.read_bytes()); blob[-1] ^= 1; enc.write_bytes(blob)
            with self.assertRaises(ValueError):
                decrypt_bundle(enc, out, b'i' * 32, 'a' * 32)
            self.assertFalse(out.exists())

    def test_size_limit_leaves_no_ciphertext(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, enc = Path(tmp) / 'src', Path(tmp) / 'enc'
            src.write_bytes(b'too large')
            with patch('private_material_protocol.MAX_BUNDLE', 3), self.assertRaises(ValueError):
                encrypt_bundle(src, enc, b'i' * 32, 'a' * 32)
            self.assertFalse(enc.exists())


if __name__ == '__main__':
    unittest.main()
