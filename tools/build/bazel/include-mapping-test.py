#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check source/generated include separation, ordering and rejected mappings."""
from pathlib import Path
import tempfile
import unittest
from libmd_paths import rewrite_includes

class IncludeMappingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / 'source'; self.src.mkdir()
        self.obj = self.root / 'objects'; self.obj.mkdir()
        self.component = self.src / 'lib/another'; self.component.mkdir(parents=True)
        self.generated = self.obj / 'lib/another'

    def test_cold_generated_directory_and_order(self):
        flags = ['-DORDER=1', '-I', str(self.component), '-I' + str(self.generated), '-DORDER=2']
        result, headers = rewrite_includes(flags, self.src, self.obj,
            generated_directories={self.generated: 'generated/another'})
        self.assertEqual(result, ['-DORDER=1', '-I', 'sources/lib/another', '-Igenerated/another', '-DORDER=2'])
        self.assertEqual(headers, [self.component])
        self.assertFalse(self.generated.exists())

    def test_existing_object_headers_not_collected(self):
        self.generated.mkdir(parents=True)
        (self.generated / 'stale.h').write_text('#error stale Make header\n')
        result, headers = rewrite_includes(['-I'+str(self.generated)], self.src, self.obj,
            generated_directories={self.generated: 'generated/another'})
        self.assertEqual(headers, [])
        self.assertEqual(result, ['-Igenerated/another'])

    def test_unknown_object_directory_rejected(self):
        self.generated.mkdir(parents=True)
        with self.assertRaises(ValueError):
            rewrite_includes(['-I'+str(self.generated)], self.src, self.obj)

    def test_bad_mappings_rejected(self):
        for source, target in [(self.src,'generated/x'),(self.obj,'generated/x'),
                               (self.generated,'../escape'),(self.generated,'/absolute'),(self.generated,'.')]:
            with self.subTest(source=source,target=target), self.assertRaises(ValueError):
                rewrite_includes([],self.src,self.obj,generated_directories={source:target})

    def test_component_path_is_not_libmd_specific(self):
        result, headers = rewrite_includes(['-I'+str(self.component)],self.src,self.obj,component=self.component)
        self.assertEqual(result,['-Isources/lib/another'])
        self.assertEqual(headers,[self.component])

    def test_include_search_classes_and_order(self):
        flags = ['-iquote', str(self.component), '-isystem'+str(self.component), '-idirafter', str(self.component)]
        result, headers = rewrite_includes(flags, self.src, self.obj)
        self.assertEqual(result, ['-iquote', 'sources/lib/another', '-isystemsources/lib/another', '-idirafter', 'sources/lib/another'])
        self.assertEqual(headers, [self.component])

    def test_system_generated_inputs_not_scanned(self):
        result, headers = rewrite_includes(['-isystem',str(self.generated)],self.src,self.obj,
            generated_directories={self.generated:'generated/another'})
        self.assertEqual(result,['-isystem','generated/another'])
        self.assertEqual(headers,[])

    def test_system_include_without_argument(self):
        for flag in ['-isystem','-iquote','-idirafter']:
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                rewrite_includes([flag],self.src,self.obj)

    def test_missing_directory_argument(self):
        with self.assertRaises(ValueError):
            rewrite_includes(['-I'],self.src,self.obj)

if __name__ == '__main__':
    unittest.main()
