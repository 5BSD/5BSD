#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import tempfile
import unittest
from tree_file import extract

class TreeFileTests(unittest.TestCase):
    def test_regular_empty_and_sandbox_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); tree = root / 'tree'; tree.mkdir()
            source = root / 'artifact'; source.write_bytes(b'header\n')
            (tree / 'sandbox-link').symlink_to(source)
            (tree / 'empty').write_bytes(b'')
            (tree / 'nested').mkdir(); (tree / 'nested/header').write_bytes(b'nested\n')
            for member, expected in [('sandbox-link', b'header\n'), ('empty', b''), ('nested/header', b'nested\n')]:
                with self.subTest(member=member):
                    extract(tree, member, root / 'output')
                    self.assertEqual((root / 'output').read_bytes(), expected)
    def test_invalid_member(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for member in ['', '../escape', '/absolute', 'a//b', './a', 'a\\b', 'absent']:
                with self.subTest(member=member):
                    with self.assertRaises(ValueError):extract(root, member, root / 'output')
                    self.assertFalse((root / 'output').exists())

if __name__ == '__main__':unittest.main()
