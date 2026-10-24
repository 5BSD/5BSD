# SPDX-License-Identifier: BSD-2-Clause
import os
import datetime
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from auth_update import ATTRIBUTES, DATABASE, PKCS7, create, serialize


class AuthUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='5bsd-auth-test-')
        cls.root = Path(cls.temp.name)
        cls.openssl = os.environ.get('FIRMWARE_TEST_OPENSSL', '/usr/bin/openssl')
        for name in ('signer', 'other'):
            subprocess.run([cls.openssl, 'req', '-new', '-x509', '-newkey', 'rsa:2048',
                            '-noenc', '-keyout', str(cls.root / (name + '.key')),
                            '-out', str(cls.root / (name + '.pem')), '-days', '1',
                            '-subj', '/CN=Disposable auth test ' + name],
                           check=True, capture_output=True)
        cls.time = datetime.datetime(2026, 10, 24, 12, 0, 0, tzinfo=datetime.timezone.utc)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_serialization(self):
        stamp, message = serialize('db', self.time, b'payload')
        self.assertEqual(len(stamp), 16)
        self.assertEqual(message[:4], b'd\0b\0')
        self.assertEqual(message[4:20], DATABASE.bytes_le)
        self.assertEqual(message[20:24], struct.pack('<I', ATTRIBUTES))
        self.assertEqual(stamp[7:], bytes(9))
        self.assertEqual(message[24:], stamp + b'payload')

    def test_invalid_inputs(self):
        for variable, time in (('BootOrder', self.time), ('db', self.time.replace(tzinfo=None)),
                               ('db', self.time.replace(microsecond=1))):
            self.assertRaises(ValueError, serialize, variable, time, b'payload')

    def test_signature_binding(self):
        output = self.root / 'test.auth'
        payload = b'test variable value'
        create(self.openssl, 'db', self.time, payload, self.root / 'signer.key',
               self.root / 'signer.pem', output)
        blob = output.read_bytes()
        length, revision, kind = struct.unpack_from('<IHH', blob, 16)
        self.assertEqual((revision, kind), (0x0200, 0x0EF1))
        self.assertEqual(blob[24:40], PKCS7.bytes_le)
        self.assertEqual(blob[16 + length:], payload)
        signature = self.root / 'signature.der'
        signature.write_bytes(blob[40:16 + length])
        for variable, time, value in (('db', self.time, payload),
                                     ('dbx', self.time, payload),
                                     ('db', self.time + datetime.timedelta(seconds=1), payload),
                                     ('db', self.time, payload + b'x')):
            content = self.root / 'content'
            content.write_bytes(serialize(variable, time, value)[1])
            result = subprocess.run([self.openssl, 'cms', '-verify', '-binary',
                                     '-inform', 'DER', '-in', str(signature),
                                     '-content', str(content), '-noverify'], capture_output=True)
            self.assertEqual(result.returncode == 0,
                             variable == 'db' and time == self.time and value == payload)

    def test_wrong_private_key(self):
        output = self.root / 'wrong.auth'
        with self.assertRaises(subprocess.CalledProcessError):
            create(self.openssl, 'db', self.time, b'value', self.root / 'other.key',
                   self.root / 'signer.pem', output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
