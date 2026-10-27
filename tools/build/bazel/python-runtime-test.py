#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import sys
import tempfile
from pathlib import Path
import unittest
from python_runtime import inventory

class RuntimeInventoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stdlib = self.root / ('python%d.%d' % sys.version_info[:2])
        (self.stdlib/'encodings').mkdir(parents=True)
        (self.stdlib/'encodings/__init__.py').write_text('# fixture\n')

    def test_excludes_packages_and_bytecode(self):
        for folder in ('site-packages', '__pycache__'):
            (self.stdlib/folder).mkdir()
            (self.stdlib/folder/'unrelated.py').write_text('raise Exception()\n')
        (self.stdlib/'stale.pyc').write_bytes(b'cache')
        files, extensions, info = inventory(sys.executable, self.stdlib)
        self.assertEqual(list(files.values()), [self.stdlib/'encodings/__init__.py'])
        self.assertEqual(extensions, {})
        self.assertEqual(info['stdlib'], str(self.stdlib))

    def test_rejects_escaping_file(self):
        outside = self.root/'outside.py'; outside.write_text('# outside\n')
        (self.stdlib/'escape.py').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            inventory(sys.executable, self.stdlib)

    def test_rejects_directory_symlink(self):
        outside = self.root/'outside';outside.mkdir()
        (self.stdlib/'escape').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directory symlinks'):
            inventory(sys.executable, self.stdlib)

    def test_rejects_version_mismatch(self):
        other = self.root/'python0.0';self.stdlib.rename(other)
        with self.assertRaisesRegex(ValueError, 'version'):
            inventory(sys.executable, other)

if __name__ == '__main__':
    unittest.main()
