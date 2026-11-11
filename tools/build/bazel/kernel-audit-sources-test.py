# SPDX-License-Identifier: BSD-2-Clause
"""Source-discovery coverage and unsupported-topology failure tests."""
from pathlib import Path
import os
import tempfile
import unittest
from kernel_audit_sources import inventory


class SourceInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'kern').mkdir()
        (self.root / 'kern/existing.c').write_text('/* no lookup yet */\n')

    def test_all_source_contents_are_action_inputs_across_packages(self):
        (self.root / 'kern/BUILD.bazel').write_text('')
        (self.root / 'kern/future.h').write_text('/* no current DQ token */\n')
        (self.root / 'kern/unrelated.txt').write_text('NDINIT\n')
        got = inventory(self.root)
        self.assertEqual(got['files'], ['kern/existing.c', 'kern/future.h'])
        (self.root / 'kern/existing.c').write_text('NDINIT(/* new call */);\n')
        self.assertEqual(inventory(self.root), got)
        # The filename set stays stable on content changes: the action consumes
        # those bytes directly, rather than a repository content-filter result.

    def test_addition_deletion_and_new_directories_change_namespace(self):
        before = inventory(self.root)
        (self.root / 'new/empty').mkdir(parents=True)
        (self.root / 'new/added.c').write_text('NDINIT(0);\n')
        after = inventory(self.root)
        self.assertEqual(set(after['files']) - set(before['files']), {'new/added.c'})
        self.assertIn('new/empty', after['directories'])
        (self.root / 'kern/existing.c').unlink()
        self.assertNotIn('kern/existing.c', inventory(self.root)['files'])

    def test_source_links_are_never_silently_omitted_or_dereferenced(self):
        source = self.root / 'kern/existing.c'
        (self.root / 'referent').write_text('NDINIT(0);\n')
        source.unlink()
        source.symlink_to('../referent')
        with self.assertRaisesRegex(ValueError, 'regular C/header'):
            inventory(self.root)

    def test_directory_links_fail_instead_of_hiding_subtrees(self):
        (self.root / 'alias').symlink_to('kern', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directory-link'):
            inventory(self.root)

    def test_fifo_and_unsafe_names_are_rejected(self):
        fifo = self.root / 'kern/pipe.c'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'regular C/header'):
            inventory(self.root)
        fifo.unlink()
        (self.root / 'kern/white space.c').write_text('NDINIT(0);\n')
        with self.assertRaisesRegex(ValueError, 'source path'):
            inventory(self.root)

    def test_missing_root_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            inventory(self.root / 'missing')


if __name__ == '__main__':
    unittest.main()
