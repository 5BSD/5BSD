#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import json
from pathlib import Path
import tempfile
import unittest
import atf_results
from libmd_environment import digest

class ModuleReceipts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'bazel-bin').mkdir()
        for name,data in [('fixture.so',b'module'),('dependency.so',b'library')]:
            (self.root/'bazel-bin'/name).write_bytes(data)
        (self.root/'elf-runtime-check.py').write_text('driver')
        self.module=dict(name='fixture.so',binary='fixture.so',libraries={'dep.so':'dependency.so'})
        self.path=self.root/'module-runtime-fixture.so/receipt.json';self.path.parent.mkdir()
        self.record=dict(status='passed',execution_mode='trace-only',arguments=[],
            binary_sha256=digest(self.root/'bazel-bin/fixture.so'),
            driver_sha256=digest(self.root/'elf-runtime-check.py'),
            libraries={'dep.so':dict(sha256=digest(self.root/'bazel-bin/dependency.so'))})
    def check(self):
        self.path.write_text(json.dumps(self.record))
        return atf_results.verify_modules(self.root,self.root,[self.module])
    def test_valid(self):
        self.assertEqual(set(self.check()),{'fixture.so'})
    def test_wrong_execution_mode(self):
        self.record['execution_mode']='execute'
        with self.assertRaises(ValueError):self.check()
    def test_changed_module(self):
        (self.root/'bazel-bin/fixture.so').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.check()
    def test_changed_dependency(self):
        (self.root/'bazel-bin/dependency.so').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.check()
    def test_missing_dependency(self):
        self.record['libraries']={}
        with self.assertRaises(ValueError):self.check()
    def test_duplicate(self):
        self.check()
        with self.assertRaises(ValueError):
            atf_results.verify_modules(self.root,self.root,[self.module,self.module])

if __name__=='__main__':unittest.main()
