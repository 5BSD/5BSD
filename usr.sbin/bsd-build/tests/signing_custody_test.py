# SPDX-License-Identifier: BSD-2-Clause
"""Direct signing entrypoint preflight; no key generation or signing occurs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(os.environ.get('BSD_BUILD_SIGN_STAGE',
    str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/sign-stage.sh')))

class SigningCustody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        (self.stage / 'METALOG').write_text('# empty preflight fixture\n')
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.key = self.private / 'key'
        self.key.write_text('not a real signing key; preflight must not read it\n')
        self.key.chmod(0o600)

    def check(self, message, key=None):
        before = (self.stage / 'METALOG').read_bytes()
        before_entries = sorted(str(p.relative_to(self.stage)) for p in self.stage.rglob('*'))
        result = subprocess.run(['sh', str(SCRIPT), '-r', str(self.stage),
            '-k', str(key or self.key)], capture_output=True, text=True, timeout=10,
            env=dict(os.environ, CAPSIGN='/nonexistent/signing-must-not-run'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual((self.stage / 'METALOG').read_bytes(), before)
        self.assertEqual(sorted(str(p.relative_to(self.stage)) for p in self.stage.rglob('*')), before_entries)
        self.assertFalse(list(self.root.glob('stage.signing.*')))

    def test_private_key_reaches_next_preflight_gate(self):
        self.check('no system bundles in stage')

    def test_group_or_world_access_rejected(self):
        for mode in (0o640, 0o604, 0o620, 0o601):
            with self.subTest(mode=oct(mode)):
                self.key.chmod(mode)
                self.check('private key must not be accessible')

    def test_writable_parent_rejected(self):
        for mode in (0o770, 0o707):
            with self.subTest(mode=oct(mode)):
                self.private.chmod(mode)
                self.check('private key directory must not be writable')
        self.private.chmod(0o700)

    def test_key_inside_stage_rejected_including_ancestor_alias(self):
        staged = self.stage / 'owner-key'
        staged.write_bytes(self.key.read_bytes())
        staged.chmod(0o600)
        before = staged.read_bytes()
        self.check('private key must be outside the staged image', staged)
        alias = self.root / 'stage-alias'
        alias.symlink_to(self.stage, target_is_directory=True)
        self.check('private key must be outside the staged image', alias / staged.name)
        self.assertEqual(staged.read_bytes(), before)

    def test_nonregular_keys_rejected_without_blocking(self):
        fifo = self.private / 'fifo'
        os.mkfifo(fifo, 0o600)
        for key in (fifo, self.private, self.private / 'missing'):
            with self.subTest(key=key):
                self.check('regular file, not a symlink', key)

    def test_symlink_rejected(self):
        link = self.private / 'link'
        link.symlink_to(self.key)
        self.check('regular file, not a symlink', link)

if __name__ == '__main__':
    unittest.main()
