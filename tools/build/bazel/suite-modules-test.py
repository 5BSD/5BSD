#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import unittest
import configured_tests

class SuiteModules(unittest.TestCase):
    def setUp(self):
        self.program = dict(metadata=dict(BINDIR='/usr/tests/example'))
    def module(self, name='fixture.so', directory='/usr/tests/example'):
        return dict(component='tests/fixture', metadata=dict(LIB='', PROG='',
            SHLIB_NAME=name, SHLIBDIR=directory))
    def test_selects_by_installation_directory(self):
        selected = self.module()
        other = self.module('elsewhere.so','/usr/tests/other')
        self.assertEqual(configured_tests.suite_modules(self.program,[selected,other]),
            {'fixture.so':selected})
    def test_ordinary_library_is_not_a_fixture(self):
        candidate = self.module();candidate['metadata']['LIB']='fixture'
        self.assertEqual(configured_tests.suite_modules(self.program,[candidate]),{})
    def test_duplicate_destination_rejected(self):
        with self.assertRaises(ValueError):
            configured_tests.suite_modules(self.program,[self.module(),self.module()])
    def test_output_traversal_rejected(self):
        with self.assertRaises(ValueError):
            configured_tests.suite_modules(self.program,[self.module('../fixture.so')])
    def test_relative_suite_directory_rejected(self):
        self.program['metadata']['BINDIR']='tests/example'
        with self.assertRaises(ValueError):
            configured_tests.suite_modules(self.program,[])

if __name__=='__main__':unittest.main()
