#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import unittest
from source_graph import parse_test_inventory, test_inventory_command, test_results

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
    def test_query_quotes_label_punctuation(self):
        command=['bazel','test','//:a+b']
        self.assertEqual(test_inventory_command(command,['//:a+b'],['//:a+b'])[-1],
                         'tests(set("//:a+b"))')
    def test_canonical_labels(self):
        self.assertEqual(parse_test_inventory('"@@//:b"\n"//:a"\n'),['//:a','//:b'])
    def test_empty_invalid_duplicate(self):
        for text in ['', '42', '"@external//:test"', '"//:test"\n"@@//:test"']:
            with self.subTest(text=text),self.assertRaises(ValueError):parse_test_inventory(text)
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
