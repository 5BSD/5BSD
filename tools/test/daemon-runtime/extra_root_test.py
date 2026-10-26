# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from extra_root import stage_extra_root


class ExtraRoot(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'input'
        self.target = Path(self.temp.name) / 'stage'
        self.source.mkdir(); self.target.mkdir()

    def test_additive_input_hashes_and_directory_metadata(self):
        (self.source / 'tests').mkdir()
        (self.source / 'tests/data').write_bytes(b'fixture')
        (self.target / 'tests').mkdir(mode=0o700)
        result = stage_extra_root(self.source, self.target)
        self.assertEqual(result['files_sha256'], {'tests/data': hashlib.sha256(b'fixture').hexdigest()})
        self.assertEqual((self.target / 'tests/data').read_bytes(), b'fixture')
        self.assertEqual((self.target / 'tests').stat().st_mode & 0o777, 0o700)

    def test_conflict_rejected_before_any_copy(self):
        (self.source / 'a').write_text('new')
        (self.source / 'z').write_text('replacement')
        (self.target / 'z').write_text('runner')
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            stage_extra_root(self.source, self.target)
        self.assertFalse((self.target / 'a').exists())
        self.assertEqual((self.target / 'z').read_text(), 'runner')

    def test_explicit_shared_file_keeps_existing_inode(self):
        for root in (self.source, self.target):
            (root / 'library').write_bytes(b'identical dependency')
        target = self.target / 'library'; target.chmod(0o444)
        before = target.stat()
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        result = stage_extra_root(self.source, self.target, {'library': digest})
        self.assertEqual(result['shared_files_sha256'], {'library': digest})
        self.assertEqual((target.stat().st_ino, target.stat().st_mode), (before.st_ino, before.st_mode))

    def test_shared_file_requires_expected_bytes_and_explicit_permission(self):
        for root in (self.source, self.target):
            (root / 'library').write_bytes(b'input')
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            stage_extra_root(self.source, self.target)
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            stage_extra_root(self.source, self.target, {'library': '0' * 64})
        digest = hashlib.sha256(b'input').hexdigest()
        (self.source / 'library').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            stage_extra_root(self.source, self.target, {'library': digest})

    def test_symlink_and_special_file_rejected(self):
        for kind in ('link', 'fifo'):
            with self.subTest(kind=kind):
                path = self.source / kind
                if kind == 'link':
                    path.symlink_to('/tmp')
                else:
                    os.mkfifo(path)
                with self.assertRaisesRegex(ValueError, 'regular files'):
                    stage_extra_root(self.source, self.target)
                path.unlink()

    def test_target_directory_alias_rejected(self):
        (self.source / 'directory').mkdir()
        (self.target / 'directory').symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            stage_extra_root(self.source, self.target)

    def test_metalog_unsafe_path_rejected(self):
        (self.source / 'ambiguous name').write_text('data')
        with self.assertRaisesRegex(ValueError, 'METALOG'):
            stage_extra_root(self.source, self.target)


if __name__ == '__main__':
    unittest.main()
