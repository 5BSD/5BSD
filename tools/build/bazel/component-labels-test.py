#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Component packages must preserve distinct identities and safe output paths."""
import unittest
from component_labels import package, label, artifact, generated_directory, relative

class Labels(unittest.TestCase):
    def test_same_names_in_distinct_components(self):
        self.assertEqual(label('lib/libauditd','auditd'),'//components/lib/libauditd:auditd')
        self.assertEqual(label('usr.sbin/auditd','auditd'),'//components/usr.sbin/auditd:auditd')
        self.assertEqual(label('lib/atf/libatf-c/tests','build_test'),'//components/lib/atf/libatf-c/tests:build_test')
        self.assertNotEqual(label('lib/atf/libatf-c/tests','build_test'),label('lib/atf/libatf-c++/tests','build_test'))
    def test_artifacts_and_generated_include_paths(self):
        component={'component':'lib/libc'}
        self.assertEqual(package(component),'components/lib/libc')
        self.assertEqual(artifact(component,'libc.so.7'),'components/lib/libc/libc.so.7')
        self.assertEqual(generated_directory(component,'generated/c'),'$(GENDIR)/components/lib/libc/generated/c')
    def test_noncanonical_and_escaping_paths(self):
        for value in ('', '.', '/lib/foo','../foo','lib/../foo','lib//foo','./lib/foo','lib/foo/','lib/foo:bar','lib/foo\nbar',None):
            with self.subTest(value=value),self.assertRaises(ValueError):relative(value)
    def test_target_path_does_not_replace_package_identity(self):
        self.assertEqual(label('lib/libc','generated/c/read.S'),'//components/lib/libc:generated/c/read.S')
        for value in ('/outside','../outside','//other:target'):
            with self.assertRaises(ValueError):label('lib/libc',value)

if __name__=='__main__':unittest.main()
