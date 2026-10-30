#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Keep absent source includes without accepting undeclared object/host roots."""
from pathlib import Path
import tempfile
import unittest
from libmd_paths import rewrite_includes


class Paths(unittest.TestCase):
    def test_missing_source_keeps_order_and_does_not_create_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); src = root/'src'; obj = root/'obj'
            src.mkdir(); obj.mkdir(); (src/'existing').mkdir()
            missing = src/'missing'
            flags, dirs = rewrite_includes(['-I'+str(missing), '-isystem', str(src/'existing')], src, obj)
            self.assertEqual(flags, ['-Isources/missing', '-isystem', 'sources/existing'])
            self.assertEqual(dirs, [missing, src/'existing'])
            self.assertFalse(missing.exists())

    def test_missing_host_and_object_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); src = root/'src'; obj = root/'obj'
            src.mkdir(); obj.mkdir()
            (src/'escape').symlink_to(root/'outside')
            for path in (obj/'missing', root/'outside', src/'escape'):
                with self.subTest(path=path), self.assertRaises((ValueError, FileNotFoundError)):
                    rewrite_includes(['-I'+str(path)], src, obj)


if __name__ == '__main__':
    unittest.main()
