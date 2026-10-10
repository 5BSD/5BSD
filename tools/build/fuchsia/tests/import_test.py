#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Black-box regressions for pinned archive verification and extraction."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

IMPORTER=Path(__file__).resolve().parents[1]/'import.py'

class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='fidl-import-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.cache=self.root/'cache'
        self.cache.mkdir()

    def archive(self, name='upstream/header.h'):
        path=self.root/'fixture.tar'
        with tarfile.open(path,'w') as archive:
            entry=tarfile.TarInfo(name)
            entry.mode=0o644
            entry.mtime=int(time.time())+86400
            payload=b'verified header data\n'
            entry.size=len(payload)
            archive.addfile(entry,io.BytesIO(payload))
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        cached=self.cache/digest
        path.rename(cached)
        self.lock=self.root/'sources.json'
        self.lock.write_text(json.dumps({'sources':[{'path':'fixture',
            'strip_components':1,'sha256':digest,
            'url':'https://unused.invalid/archive'}],'metadata':{}}))
        return cached,payload

    def run_import(self):
        return subprocess.run([sys.executable,str(IMPORTER),'--lock',str(self.lock),
            '--cache',str(self.cache),'--dest',str(self.root/'dest')],
            text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    def test_future_archive_timestamp_does_not_force_rebuilds(self):
        _,payload=self.archive()
        result=self.run_import()
        self.assertEqual(result.returncode,0,result.stdout)
        header=self.root/'dest/fixture/header.h'
        self.assertEqual(header.read_bytes(),payload)
        self.assertEqual(header.stat().st_mode&0o777,0o644)
        self.assertEqual(header.stat().st_mtime,1)

    def test_corrupt_cache_is_rejected_before_extracting(self):
        cached,_=self.archive()
        cached.write_bytes(b'corrupt')
        result=self.run_import()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Corrupt cache file',result.stdout)
        self.assertEqual(list((self.root/'dest').rglob('*')),[])

    def test_parent_path_in_archive_is_rejected(self):
        self.archive('../escaped.h')
        result=self.run_import()
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Unsafe archive path',result.stdout)
        self.assertFalse((self.root/'escaped.h').exists())

if __name__=='__main__':
    unittest.main()
