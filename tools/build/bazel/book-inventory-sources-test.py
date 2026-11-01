#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Selection and no-follow traversal checks for book inventory discovery."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from book_inventory_sources import inventory

CHECKER = Path(__file__).resolve().parents[3] / 'docs/book/tools/check-book.sh'


class InventoryTests(unittest.TestCase):
    def test_selection_and_directory_watches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = ['README', 'Makefile', 'sub/Makefile.inc', 'sub/options.mk',
                     'man/example.1', 'man/template.5.in', 'man/example.txt',
                     'sys/net/example.c', 'sys/net/example.h', 'sys/net/ignored.S',
                     'other/example.c', '.git/ignored.1', 'sub/.git/ignored.8']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('SYSCTL_NODE(_kern_example, OID_AUTO, example, CTLFLAG_RW, 0, "");'
                                if name == 'sys/net/example.c' else name)
            (root / 'alias.1').symlink_to(root / 'man/example.1')
            (root / 'sub/loop').symlink_to(root / 'sub', target_is_directory=True)
            result = inventory(root)
            self.assertEqual(result['groups']['man'],
                             ['Makefile', 'man/example.1', 'man/template.5.in',
                              'sub/Makefile.inc', 'sub/options.mk'])
            self.assertEqual(result['groups']['sysctl'],
                             ['sys/net/example.c', 'sys/net/example.h'])
            self.assertIn('.', result['directories'])
            self.assertIn('sub', result['directories'])
            self.assertNotIn('sub/loop', result['directories'])
            self.assertFalse(any('.git' in Path(p).parts for p in result['directories']))

    def test_file_to_directory_changes_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'unselected'
            path.write_text('not a generator input')
            before = inventory(root)
            self.assertEqual(before['groups']['man'], [])
            path.unlink()
            path.mkdir()
            (path / 'new.1').write_text('manual')
            after = inventory(root)
            self.assertEqual(after['groups']['man'], ['unselected/new.1'])
            self.assertIn('unselected', after['directories'])

    def test_declared_file_lists_match_root_generator_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            (root / 'sys/net').mkdir(parents=True)
            (root / 'docs/Makefile').write_text('MAN= alpha.1 \\\n    beta.8\nMLINKS= alpha.1 alias.1\n')
            (root / 'docs/alpha.1').write_text('manual page\n')
            (root / 'sys/net/example.c').write_text(
                'SYSCTL_INT(_kern_test, OID_AUTO, value, CTLFLAG_RW, 0, "");\n')
            (root / 'sys/net/example.h').write_text('no inventory declaration\n')
            data = inventory(root)
            for group in ('man', 'sysctl'):
                listed = root / (group + '.paths')
                listed.write_text(''.join(str(root / name) + '\n'
                                          for name in data['groups'][group]))
                root_mode = subprocess.run(
                    ['/bin/sh', str(CHECKER), '-g', group, str(root)],
                    check=True, capture_output=True).stdout
                list_mode = subprocess.run(
                    ['/bin/sh', str(CHECKER), '-g', group, '-i', str(listed)],
                    check=True, capture_output=True).stdout
                self.assertEqual(list_mode, root_mode, group)


if __name__ == '__main__':
    unittest.main()
