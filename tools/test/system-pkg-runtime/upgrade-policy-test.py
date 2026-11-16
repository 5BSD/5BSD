# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Reject unsafe upgrade paths and incomplete/mixed package inventories."""
import unittest
import os
from pathlib import Path
import sys
root=Path(os.environ["TEST_SRCDIR"])/os.environ["TEST_WORKSPACE"] if "TEST_SRCDIR" in os.environ else Path(__file__).resolve().parents[3]
sys.path.insert(0,str(root/"tools/build/bazel"))
from upgrade_runtime import absolute, package_rows, family_names

class UpgradeInputs(unittest.TestCase):
    def test_canonical_paths(self):
        self.assertEqual(absolute('/home/user/data'),'/home/user/data')
        for value in ('relative','//home','/home/../root','/home/./file','/a b','/a\nfile','/nul\0'):
            with self.subTest(value=value),self.assertRaises(ValueError):absolute(value)

    def test_complete_version_set(self):
        self.assertEqual(package_rows(b'lib 2\napp 2\n',{'app','lib'},'2'),2)
        for data in (b'app 2\n',b'app 2\nlib 1\n',b'app 2\napp 2\n',b'app 2\nlib 2\nextra 2\n',b'app 2 extra\nlib 2\n'):
            with self.subTest(data=data),self.assertRaises(ValueError):package_rows(data,{'app','lib'},'2')

    def test_separate_generation_inventories(self):
        old={'format':1,'version':'1','prefix':'5BSD','packages':{'lib':{},'old':{}}}
        new={'format':1,'version':'2','prefix':'5BSD','packages':{'lib':{},'new':{}}}
        a=family_names(old,'1',2);b=family_names(new,'2',2)
        self.assertEqual(b-a,{'5BSD-new'})
        self.assertEqual(a-b,{'5BSD-old'})
        package_rows(b'5BSD-lib 1\n5BSD-old 1\n',a,'1')
        with self.assertRaises(ValueError):package_rows(b'5BSD-lib 1\n5BSD-old 1\n',b,'1')
        for document,version,count in [(old,'2',2),(old,'1',3),
                (dict(old,packages=['lib','old']),'1',2),
                (dict(old,packages={'lib':{},'-unsafe':{}}),'1',2),
                (dict(old,packages={'lib':{},42:{}}),'1',2),
                (dict(old,format=True),'1',2)]:
            with self.subTest(document=document,version=version,count=count),self.assertRaises(ValueError):
                family_names(document,version,count)

if __name__=='__main__':unittest.main()
