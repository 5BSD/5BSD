# SPDX-License-Identifier: BSD-2-Clause
"""Real cryptographic checks for the VM runner; never starts a guest."""
import base64
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from run import certificate, sign_manifest


class ManifestSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix='runner-signing-')
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.root = Path(cls.workspace.name)
        cls.key, cls.cert = certificate(cls.root, 'generation')
        cls.other_key, cls.other_cert = certificate(cls.root, 'other')

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.boot = Path(self.directory.name)
        self.manifest = b'kernel/kernel sha256=' + b'a' * 64 + b'\n'
        (self.boot / 'manifest').write_bytes(self.manifest)

    def assert_unpublished(self):
        self.assertEqual((self.boot / 'manifest').read_bytes(), self.manifest)
        self.assertEqual({p.name for p in self.boot.iterdir()}, {'manifest'})

    def test_signature_matches_staged_manifest(self):
        sign_manifest(self.boot, self.key, self.cert)
        public = subprocess.check_output(['openssl', 'x509', '-in',
            str(self.boot / 'manifest.certs'), '-pubkey', '-noout'])
        (self.boot / 'public.pem').write_bytes(public)
        armor = (self.boot / 'manifest.sig').read_bytes().splitlines()
        (self.boot / 'signature').write_bytes(base64.b64decode(b''.join(armor[1:-1])))
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify',
            str(self.boot / 'public.pem'), '-signature', str(self.boot / 'signature'),
            str(self.boot / 'manifest')], check=True, capture_output=True)
        self.assertEqual((self.boot / 'manifest').read_bytes(), self.manifest)
        self.assertNotIn(b'PRIVATE KEY', (self.boot / 'manifest.certs').read_bytes())

    def test_mismatched_key_never_publishes(self):
        with self.assertRaises(subprocess.CalledProcessError):
            sign_manifest(self.boot, self.other_key, self.cert)
        self.assert_unpublished()

    def test_mixed_certificate_never_publishes_private_material(self):
        mixed = self.root / 'mixed.pem'
        mixed.write_bytes(self.cert.read_bytes() + self.key.read_bytes())
        try:
            with self.assertRaisesRegex(ValueError, 'certificate-only'):
                sign_manifest(self.boot, self.key, mixed)
            self.assert_unpublished()
        finally:
            mixed.unlink()

    def test_nonprivate_key_rejected(self):
        key = self.root / 'nonprivate.key'
        shutil.copyfile(self.key, key)
        key.chmod(0o644)
        try:
            with self.assertRaisesRegex(ValueError, 'nonprivate key'):
                sign_manifest(self.boot, key, self.cert)
            self.assert_unpublished()
        finally:
            key.unlink()


class GenerationArguments(unittest.TestCase):
    def rejected(self, extra, message):
        result = subprocess.run(['/usr/local/bin/python3.12', '-B',
            str(Path(__file__).with_name('run.py')), '--root', '/nonexistent',
            '--work', '/nonexistent', '--vars-tool', '/nonexistent', *extra],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(message, result.stderr)

    def test_generation_cases_require_explicit_signer(self):
        for case in ('firmware-signed-manifest', 'revoked-generation-manifest'):
            with self.subTest(case=case):
                self.rejected(['--case', case], 'require explicit generation key and certificate')

    def test_incomplete_pair(self):
        for option in ('--generation-key', '--generation-certificate'):
            with self.subTest(option=option):
                self.rejected([option, '/nonexistent'], 'both key and certificate')

    def test_explicit_independent_cases_required(self):
        pair = ['--generation-key', '/nonexistent', '--generation-certificate', '/nonexistent']
        for case in (None, 'second-db-cert', 'second-dbx-cert', 'second-dbx-hash'):
            with self.subTest(case=case):
                self.rejected(pair + ([] if case is None else ['--case', case]),
                    'explicit cases independent')


if __name__ == '__main__':
    unittest.main()
