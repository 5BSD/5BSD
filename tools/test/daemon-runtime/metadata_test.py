# SPDX-License-Identifier: BSD-2-Clause
import unittest
import json
from atf_metadata import parse_listing, cases_completed, apply_case_budgets, parse_runtime_description

HEADER = 'Content-Type: application/X-atf-tp; version="1"\n\n'

class MetadataTest(unittest.TestCase):
    def test_declared_contract(self):
        result = parse_listing(HEADER + 'ident: first\nhas.cleanup: true\ntimeout: 180\n\nident: second\n')
        self.assertEqual(result, {'first': {'timeout': 180, 'cleanup': True},
                                  'second': {'timeout': 40, 'cleanup': False}})

    def test_rejected_contracts(self):
        for body in ('', 'ident: x\nident: y', 'ident: x\n\nident: x',
                     'ident: ../escape', 'ident: x\nhas.cleanup: yes',
                     'ident: x\ntimeout: 0', 'ident: x\ntimeout: -1',
                     'ident: x\ntimeout: 1.5', 'ident: x\ntimeout: 3601',
                     'ident: x\ntimeout: 30\ntimeout: 60'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_listing(HEADER + body)
        with self.assertRaises(ValueError):
            parse_listing('ident: x')

class CompletionTest(unittest.TestCase):
    def test_cleanup_required(self):
        metadata = [dict(program='/tests/x', case='cleanup', cleanup=True)]
        body = 'RUNTIME_CASE_PASS /tests/x:cleanup\n'
        cleanup = 'RUNTIME_CLEANUP_PASS /tests/x:cleanup\n'
        self.assertTrue(cases_completed(body + cleanup, metadata))
        for output in (body, cleanup, body + cleanup + cleanup,
                       body + body + cleanup, body + cleanup + 'RUNTIME_CLEANUP_FAIL x'):
            with self.subTest(output=output):
                self.assertFalse(cases_completed(output, metadata))

    def test_no_cleanup_and_empty(self):
        metadata = [dict(program='/tests/x', case='plain', cleanup=False)]
        self.assertTrue(cases_completed('RUNTIME_CASE_PASS /tests/x:plain', metadata))
        self.assertFalse(cases_completed('RUNTIME_CASE_PASS /tests/x:plain\nRUNTIME_CLEANUP_PASS /tests/x:plain', metadata))
        self.assertFalse(cases_completed('', []))

class BudgetTest(unittest.TestCase):
    def setUp(self):
        self.metadata = [dict(program='/tests/atf_suite_0', case='build', timeout=3600, cleanup=True),
                         dict(program='/tests/support', case='support', timeout=40, cleanup=False)]
        self.suites = [dict(source='tools/test/construction/test', alias='atf_suite_0', cases=['build'])]
        self.identity = 'tools/test/construction/test:build'

    def apply(self, specifications, suites=None, outer=9000):
        return apply_case_budgets(self.metadata, self.suites if suites is None else suites, specifications, outer)

    def test_explicit_budget_preserves_contract(self):
        result = self.apply([self.identity + '=7200'])
        self.assertEqual(result[0]['timeout'], 7200)
        self.assertEqual(result[0]['declared_timeout'], 3600)
        self.assertEqual(result[0]['budget_input'], self.identity + '=7200')
        self.assertTrue(result[0]['cleanup'])
        self.assertEqual(result[1], self.metadata[1])
        self.assertEqual(self.metadata[0]['timeout'], 3600)
        self.assertEqual(self.apply([]), self.metadata)
        output = ('RUNTIME_CASE_PASS /tests/atf_suite_0:build\n'
                  'RUNTIME_CLEANUP_PASS /tests/atf_suite_0:build\n'
                  'RUNTIME_CASE_PASS /tests/support:support\n')
        self.assertTrue(cases_completed(output, result))
        self.assertFalse(cases_completed(output + 'RUNTIME_CASE_FAIL timeout=7200\n', result))
        self.assertFalse(cases_completed(output.replace('RUNTIME_CLEANUP_PASS /tests/atf_suite_0:build\n', ''), result))

    def test_rejected_budget_inputs(self):
        for specifications in ([self.identity + '=' + value] for value in
                               ('0', '-1', '1.5', '01', '86401', '9000', '7200x', '')):
            with self.subTest(specifications=specifications), self.assertRaises(ValueError):
                self.apply(specifications)
        for specifications in ([self.identity + '=7200', self.identity + '=7200'],
                               ['unknown:build=7200'], [self.identity + '.wrong=7200']):
            with self.subTest(specifications=specifications), self.assertRaises(ValueError):
                self.apply(specifications)
        with self.assertRaises(ValueError):
            self.apply([self.identity + '=7200'], self.suites + self.suites)
        with self.assertRaises(ValueError):
            apply_case_budgets([], self.suites, [self.identity + '=7200'], 9000)

class RuntimeDescriptionTest(unittest.TestCase):
    def test_compatible_contract(self):
        value = dict(format=1, case_metadata_version=1,
                     maximum_case_timeout=86400, cleanup=True)
        self.assertEqual(parse_runtime_description(json.dumps(value)), value)

    def test_missing_malformed_and_incompatible_contracts(self):
        value = dict(format=1, case_metadata_version=1,
                     maximum_case_timeout=86400, cleanup=True)
        invalid = ['', 'not json', '[]', '{}',
                   '{"format":1,"format":1}', json.dumps(dict(value, extra=1))]
        for key, replacement in [('format', True), ('case_metadata_version', 2),
                                 ('maximum_case_timeout', True),
                                 ('maximum_case_timeout', 0),
                                 ('maximum_case_timeout', 86401), ('cleanup', False)]:
            invalid.append(json.dumps(dict(value, **{key: replacement})))
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_runtime_description(text)

if __name__ == '__main__':
    unittest.main()
