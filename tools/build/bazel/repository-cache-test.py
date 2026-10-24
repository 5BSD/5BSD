#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location('cache', Path(__file__).with_name('repository-cache.py'))
cache = importlib.util.module_from_spec(spec); spec.loader.exec_module(cache)


class CacheExport(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.archive = self.root/'dist.zip'
        self.output = self.root/'export'; self.data = b'module contents\n'
        self.hash = hashlib.sha256(self.data).hexdigest()
        self.member = cache.PREFIX + self.hash + '/file'

    def prepare(self, members):
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, data in members: z.writestr(name, data)
        return cache.digest(self.archive)

    def test_exact_bytes_and_receipt(self):
        sha = self.prepare([(self.member, self.data), ('README', b'ignored')])
        result = cache.export_cache(self.archive, sha, self.output)
        self.assertEqual(result['entry_count'], 1)
        self.assertEqual((self.output/'cache/content_addressable/sha256'/self.hash/'file').read_bytes(), self.data)
        self.assertFalse((self.output/'cache.pending').exists())
        self.assertEqual(json.loads((self.output/'receipt.json').read_text())['result'], 'PASS')
        with self.assertRaises(FileExistsError): cache.export_cache(self.archive, sha, self.output)

    def test_wrong_archive_pin_before_output(self):
        self.prepare([(self.member, self.data)])
        with self.assertRaises(ValueError): cache.export_cache(self.archive, '0'*64, self.output)
        self.assertFalse(self.output.exists())

    def test_corrupt_cache_has_no_complete_cache(self):
        sha = self.prepare([(self.member, b'wrong')])
        with self.assertRaises(ValueError): cache.export_cache(self.archive, sha, self.output)
        self.assertFalse((self.output/'cache').exists())
        self.assertEqual(json.loads((self.output/'receipt.json').read_text())['result'], 'FAIL')

    def test_traversal_and_special_members(self):
        link = zipfile.ZipInfo(self.member); link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for i, name in enumerate([cache.PREFIX+'../escape', link]):
            sha = self.prepare([(name, self.data)])
            with self.assertRaises(ValueError): cache.export_cache(self.archive, sha, self.root/str(i))
        self.assertFalse((self.root/'escape').exists())

    def test_duplicate_and_empty_rejected(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            for i, members in enumerate([[(self.member,self.data)]*2, [('README',b'nothing')]]):
                sha = self.prepare(members)
                with self.assertRaises(ValueError): cache.export_cache(self.archive, sha, self.root/str(i))


if __name__ == '__main__': unittest.main()
