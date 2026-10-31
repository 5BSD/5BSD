#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Selection and no-follow traversal checks for book inventory discovery."""
from pathlib import Path
import tempfile
import unittest
from book_inventory_sources import inventory


class InventoryTests(unittest.TestCase):
    def test_selection_and_membership_watches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = ['README', 'Makefile', 'sub/Makefile.inc', 'sub/options.mk',
                     'man/example.1', 'man/template.5.in', 'man/example.txt',
                     'sys/net/example.c', 'sys/net/example.h', 'sys/net/ignored.S',
                     'other/example.c', '.git/ignored.1', 'sub/.git/ignored.8']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            (root / 'alias.1').symlink_to(root / 'man/example.1')
            (root / 'sub/loop').symlink_to(root / 'sub', target_is_directory=True)
            result = inventory(root)
            self.assertEqual(result['groups']['man'],
                             ['Makefile', 'man/example.1', 'man/template.5.in',
                              'sub/Makefile.inc', 'sub/options.mk'])
            self.assertEqual(result['groups']['sysctl'],
                             ['sys/net/example.c', 'sys/net/example.h'])
            self.assertIn('README', result['entries'])
            self.assertIn('alias.1', result['entries'])
            self.assertIn('sub/loop', result['entries'])
            self.assertNotIn('sub/loop', result['directories'])
            self.assertFalse(any('.git' in Path(p).parts for p in result['entries']))

    def test_file_to_directory_changes_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'unselected'
            path.write_text('not a generator input')
            before = inventory(root)
            self.assertIn('unselected', before['entries'])
            path.unlink()
            path.mkdir()
            (path / 'new.1').write_text('manual')
            after = inventory(root)
            self.assertEqual(after['groups']['man'], ['unselected/new.1'])
            self.assertIn('unselected', after['directories'])


if __name__ == '__main__':
    unittest.main()
