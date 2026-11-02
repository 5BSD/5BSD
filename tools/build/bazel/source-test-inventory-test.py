#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import json
import unittest
from source_graph import parse_test_inventory, test_inventory_command, test_results

def inventory(label, compatible=True):
    return json.dumps(dict(label=label, compatible=compatible)) + '\n'

def event(label,status='PASSED'):
    return dict(id=dict(testSummary=dict(label=label)),testSummary=dict(overallStatus=status))

class TestInventory(unittest.TestCase):
    def test_query_preserves_configuration(self):
        command=['bazel','--output_user_root=/state','test','--platforms=//:target','--//cfg:flag=false','--build_event_json_file=/events','--execution_log_json_file=/log','--noexecution_log_sort','--output_groups=default,metadata','//:archive','//:suite']
        query=test_inventory_command(command,['//:archive','//:suite'],['//:suite'])
        self.assertEqual(query[:5],['bazel','--output_user_root=/state','cquery','--platforms=//:target','--//cfg:flag=false'])
        self.assertEqual(query[-1],'tests(set("//:suite"))')
        self.assertNotIn('//:archive',query)
        self.assertFalse(any(a.startswith('--build_event_json') for a in query))
    def test_compact_log_is_not_passed_to_inventory_query(self):
        command=['bazel','test','--execution_log_compact_file=/log','--noexecution_log_sort','--//cfg:enabled=true','//:suite']
        query=test_inventory_command(command,['//:suite'],['//:suite'])
        self.assertNotIn('--execution_log_compact_file=/log',query)
        self.assertNotIn('--noexecution_log_sort',query)
        self.assertIn('--//cfg:enabled=true',query)
        self.assertEqual(query[-1],'tests(set("//:suite"))')
    def test_query_quotes_label_punctuation(self):
        command=['bazel','test','//:a+b']
        self.assertEqual(test_inventory_command(command,['//:a+b'],['//:a+b'])[-1],
                         'tests(set("//:a+b"))')
    def test_canonical_labels(self):
        self.assertEqual(parse_test_inventory(inventory('@@//:b')+inventory('//:a')),(['//:a','//:b'],[]))
    def test_empty_invalid_duplicate(self):
        for text in ['', '42', inventory('@external//:test'), inventory('//:test')+inventory('@@//:test')]:
            with self.subTest(text=text),self.assertRaises(ValueError):parse_test_inventory(text)
    def test_configured_incompatible_members_are_retained(self):
        self.assertEqual(parse_test_inventory(inventory('//:active')+inventory('@@//:disabled',False)),
                         (['//:active'],['//:disabled']))
    def test_all_incompatible_request_is_not_a_passing_empty_suite(self):
        with self.assertRaisesRegex(ValueError,'no compatible'):
            parse_test_inventory(inventory('//:disabled',False))
    def test_ambiguous_compatibility_fails_closed(self):
        for record in ['"//:old-untyped"', '{}', '{"label":"//:a"}',
                       '{"label":"//:a","compatible":0}', '{"label":"//:a","compatible":"false"}',
                       '{"label":"//:a","compatible":true,"ignored":1}']:
            with self.subTest(record=record),self.assertRaises(ValueError):
                parse_test_inventory(record)
    def test_duplicate_across_active_and_incompatible_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):
            parse_test_inventory(inventory('//:a')+inventory('@@//:a',False))
    def test_incompatible_member_must_not_report_execution(self):
        active,excluded=parse_test_inventory(inventory('//:active')+inventory('//:disabled',False))
        self.assertEqual(excluded,['//:disabled'])
        self.assertEqual(test_results([event('//:active')],active),{'//:active':'PASSED'})
        for status in ['PASSED','FAILED','NO_STATUS']:
            with self.subTest(status=status),self.assertRaises(ValueError):
                test_results([event('//:active'),event('//:disabled',status)],active)
    def test_expanded_suite_matches_individual_results(self):
        self.assertEqual(test_results([event('//:a'),event('//:b')],['//:a','//:b']),{'//:a':'PASSED','//:b':'PASSED'})
    def test_missing_extra_failed_skipped(self):
        for results in [[event('//:a')],[event('//:a'),event('//:b'),event('//:other')],[event('//:a'),event('//:b','FAILED')],[event('//:a'),event('//:b','NO_STATUS')]]:
            with self.subTest(results=results),self.assertRaises(ValueError):test_results(results,['//:a','//:b'])
    def test_duplicate_summary_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):test_results([event('//:a'),event('//:a')],['//:a'])
    def test_build_only_rejects_unexpected_test_execution(self):
        self.assertEqual(test_results([],[]),{})
        with self.assertRaises(ValueError):test_results([event('//:a')],[])
if __name__=='__main__':unittest.main()
