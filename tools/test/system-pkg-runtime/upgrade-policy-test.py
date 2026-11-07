# SPDX-License-Identifier: BSD-2-Clause
"""Reject unsafe upgrade paths and incomplete/mixed package inventories."""
import unittest
import os
from pathlib import Path
import sys
root=Path(os.environ["TEST_SRCDIR"])/os.environ["TEST_WORKSPACE"] if "TEST_SRCDIR" in os.environ else Path(__file__).resolve().parents[3]
sys.path.insert(0,str(root/"tools/build/bazel"))
from upgrade_runtime import absolute, package_rows

class UpgradeInputs(unittest.TestCase):
    def test_canonical_paths(self):
        self.assertEqual(absolute('/home/user/data'),'/home/user/data')
        for value in ('relative','//home','/home/../root','/home/./file','/a b','/a\nfile','/nul\0'):
            with self.subTest(value=value),self.assertRaises(ValueError):absolute(value)

    def test_complete_version_set(self):
        self.assertEqual(package_rows(b'lib 2\napp 2\n',{'app','lib'},'2'),2)
        for data in (b'app 2\n',b'app 2\nlib 1\n',b'app 2\napp 2\n',b'app 2\nlib 2\nextra 2\n',b'app 2 extra\nlib 2\n'):
            with self.subTest(data=data),self.assertRaises(ValueError):package_rows(data,{'app','lib'},'2')

if __name__=='__main__':unittest.main()
