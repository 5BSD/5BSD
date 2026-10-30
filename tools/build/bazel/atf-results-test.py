#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Case coverage must not disappear behind a passing outer test runner."""
import unittest
import tempfile
from pathlib import Path
from atf_results import compare_cases, artifact_path, runtime_binary

class Cases(unittest.TestCase):
    def test_outcomes_remain_distinct(self):
        rows=[dict(name='a',result_type='passed'),dict(name='b',result_type='skipped'),dict(name='c',result_type='expected_failure')]
        self.assertEqual(compare_cases('ident: a\nident: b\nident: c\n',rows),
                         dict(passed=1,skipped=1,expected_failure=1))
    def test_order_independent(self):
        rows=[dict(name='b',result_type='passed'),dict(name='a',result_type='passed')]
        self.assertEqual(compare_cases('ident: a\nident: b\n',rows),dict(passed=2))
    def test_empty_duplicate_or_incomplete_inventory_rejected(self):
        row=dict(name='a',result_type='passed')
        for listing,rows in [('',[]),('ident: a\nident: a\n',[row,row]),
                             ('ident: a\n',[]),('ident: a\n',[row,row]),
                             ('ident: b\n',[row])]:
            with self.subTest(listing=listing,rows=rows),self.assertRaises(ValueError):
                compare_cases(listing,rows)
    def test_failed_broken_missing_or_unknown_result_rejected(self):
        for kind in ('failed','broken',None,'unknown'):
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'lacks a result'):
                compare_cases('ident: a\n',[dict(name='a',result_type=kind)])

class ArtifactPaths(unittest.TestCase):
    def test_nested_paths_preserve_program_basename(self):
        path=artifact_path('components/lib/libc/tests/stdlib/clearenv_test')
        self.assertEqual(path.name,'clearenv_test')
        self.assertEqual(str(path),'components/lib/libc/tests/stdlib/clearenv_test')
    def test_noncanonical_or_escaping_paths_rejected(self):
        for value in ('','.', '/absolute','../outside','a/../outside','a//b','./a','a/',None,7):
            with self.subTest(value=value),self.assertRaises(ValueError):
                artifact_path(value)

class RuntimeInvocation(unittest.TestCase):
    def test_suite_copy_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace=Path(directory);root=workspace/'bazel-bin';(root/'nested/suite').mkdir(parents=True)
            (root/'nested/program').write_bytes(b'executable')
            (root/'nested/suite/program').write_bytes(b'executable')
            check=dict(binary='nested/program',invocation='nested/suite/program')
            self.assertEqual(runtime_binary(workspace,check),root/'nested/suite/program')
            self.assertEqual(runtime_binary(workspace,dict(binary='nested/program')),root/'nested/program')
            (root/'nested/suite/program').write_bytes(b'substitute')
            with self.assertRaises(ValueError):runtime_binary(workspace,check)
    def test_invocation_traversal_rejected(self):
        with self.assertRaises(ValueError):
            runtime_binary(Path('/tmp'),dict(binary='program',invocation='../other'))

if __name__=='__main__':unittest.main()
