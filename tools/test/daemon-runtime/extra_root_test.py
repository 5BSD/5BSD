# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from extra_root import stage_extra_root, mtree_escape


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

    def test_private_and_public_modes_preserved(self):
        for name, mode in [('spwd.db', 0o600), ('passwd', 0o644), ('tool', 0o555)]:
            path = self.source / name
            path.write_bytes(b'fixture')
            path.chmod(mode)
        result = stage_extra_root(self.source, self.target)
        self.assertEqual(result['file_modes'], {'spwd.db': 0o600, 'passwd': 0o644, 'tool': 0o555})
        for name, mode in result['file_modes'].items():
            self.assertEqual((self.target / name).stat().st_mode & 0o7777, mode)

    def test_hardlinks_preserved_but_identical_copies_distinct(self):
        (self.source / 'test').write_bytes(b'program')
        (self.source / 'test').chmod(0o555)
        os.link(self.source / 'test', self.source / '[')
        (self.source / 'copy').write_bytes(b'program')
        result = stage_extra_root(self.source, self.target)
        self.assertEqual(result['hardlinks'], {'test': '['})
        self.assertEqual((self.target / 'test').stat().st_ino,
                         (self.target / '[').stat().st_ino)
        self.assertNotEqual((self.target / 'test').stat().st_ino,
                            (self.target / 'copy').stat().st_ino)

    def test_hardlink_to_existing_shared_anchor(self):
        (self.source / 'z').write_bytes(b'program')
        os.link(self.source / 'z', self.source / 'a')
        (self.target / 'z').write_bytes(b'program')
        before = (self.target / 'z').stat().st_ino
        expected = hashlib.sha256(b'program').hexdigest()
        result = stage_extra_root(self.source, self.target, {'z': expected})
        self.assertEqual(result['hardlinks'], {'a': 'z'})
        self.assertEqual((self.target / 'a').stat().st_ino, before)

    def test_distinct_shared_inodes_rejected(self):
        (self.source / 'a').write_bytes(b'program')
        os.link(self.source / 'a', self.source / 'b')
        for name in ('a', 'b'):
            (self.target / name).write_bytes(b'program')
        expected = hashlib.sha256(b'program').hexdigest()
        with self.assertRaisesRegex(ValueError, 'different inodes'):
            stage_extra_root(self.source, self.target,
                             {'a': expected, 'b': expected})

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
                with self.assertRaisesRegex(ValueError, 'regular files|symlink'):
                    stage_extra_root(self.source, self.target)
                path.unlink()

    def test_internal_aliases_preserved(self):
        (self.source / 'C.UTF-8').mkdir()
        (self.source / 'C.UTF-8/LC_CTYPE').write_bytes(b'locale')
        (self.source / 'sr_RS.UTF-8@latin').mkdir()
        (self.source / 'sr_RS.UTF-8@latin/LC_CTYPE').symlink_to('../C.UTF-8/LC_CTYPE')
        (self.source / 'alias').symlink_to('sr_RS.UTF-8@latin/LC_CTYPE')
        result = stage_extra_root(self.source, self.target)
        self.assertEqual(result['symlinks']['alias'], 'sr_RS.UTF-8@latin/LC_CTYPE')
        self.assertTrue((self.target / 'alias').is_symlink())
        self.assertEqual((self.target / 'alias').read_bytes(), b'locale')

    def test_invalid_aliases_rejected_before_copy(self):
        (self.source / 'file').write_bytes(b'fixture')
        for link in ['../escape', '/etc/passwd', 'missing', 'alias', '.']:
            with self.subTest(link=link):
                (self.source / 'alias').symlink_to(link)
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    stage_extra_root(self.source, self.target)
                self.assertFalse((self.target / 'file').exists())
                (self.source / 'alias').unlink()

    def test_mtree_special_program_name(self):
        self.assertEqual(mtree_escape('./bin/['), './bin/\\133')
        (self.source / '[').write_bytes(b'program')
        stage_extra_root(self.source, self.target)
        self.assertEqual((self.target / '[').read_bytes(), b'program')

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
