#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
import json
import unittest
from pathlib import Path
from source_graph import parse_target_inventory, target_inventory_command, validate_target_binding, parse_test_inventory, test_inventory_command, test_artifact_command, test_results, validate_selected_tests, validate_requested_selector

def inventory(label, compatible=True):
    return json.dumps(dict(label=label, compatible=compatible)) + '\n'

def event(label,status='PASSED'):
    return dict(id=dict(testSummary=dict(label=label)),testSummary=dict(overallStatus=status))

class TestInventory(unittest.TestCase):
    def test_profiles_belong_to_their_invocation_phase(self):
        command=['bazel','test','--profile=/evidence/main.json.gz',
                 '--build_event_json_file=/evidence/main.events.json',
                 '--execution_log_compact_file=/evidence/main.compact','//:suite']
        query=test_inventory_command(command,['//:suite'],['//:suite'])
        self.assertFalse(any(value.startswith('--profile=') for value in query))
        artifacts=test_artifact_command(command,['//:suite'],['//:case'],Path('/evidence'),'compact')
        self.assertIn('--profile=/evidence/test-artifacts.profile.json.gz',artifacts)
        self.assertNotIn('--profile=/evidence/main.json.gz',artifacts)
        self.assertIn('--profile=/evidence/main.json.gz',command)

    def test_query_preserves_configuration(self):
        command=['bazel','--output_user_root=/state','test','--platforms=//:target','--//cfg:flag=false','--build_event_json_file=/events','--execution_log_json_file=/log','--noexecution_log_sort','--output_groups=default,metadata','//:archive','//:suite']
        query=test_inventory_command(command,['//:archive','//:suite'],['//:suite'])
        self.assertEqual(query[:5],['bazel','--output_user_root=/state','cquery','--platforms=//:target','--//cfg:flag=false'])
        self.assertEqual(query[-1],'config(tests(set("//:suite")), target)')
        self.assertNotIn('//:archive',query)
        self.assertFalse(any(a.startswith('--build_event_json') for a in query))
    def test_compact_log_is_not_passed_to_inventory_query(self):
        command=['bazel','test','--execution_log_compact_file=/log','--noexecution_log_sort','--//cfg:enabled=true','//:suite']
        query=test_inventory_command(command,['//:suite'],['//:suite'])
        self.assertNotIn('--execution_log_compact_file=/log',query)
        self.assertNotIn('--noexecution_log_sort',query)
        self.assertIn('--//cfg:enabled=true',query)
        self.assertEqual(query[-1],'config(tests(set("//:suite")), target)')
    def test_query_quotes_label_punctuation(self):
        command=['bazel','test','//:a+b']
        self.assertEqual(test_inventory_command(command,['//:a+b'],['//:a+b'])[-1],
                         'config(tests(set("//:a+b")), target)')
    def test_kernel_query_requires_artifact_provider(self):
        query=test_inventory_command(['bazel','test','//:host'],['//:host'],['//:host'],host_artifacts_only=True)
        self.assertIn('BsdHostArtifactTestInfo', next(v for v in query if v.startswith('--starlark:expr=')))
    def test_kernel_artifact_inventory_accepts_only_explicit_host_contract(self):
        good=json.dumps(dict(label='//:host',compatible=True,host_artifact=True))
        self.assertEqual(parse_test_inventory(good,host_artifacts_only=True),(['//:host'],[]))
        for value in [False,0,'true',None]:
            bad=json.dumps(dict(label='//:target',compatible=True,host_artifact=value))
            with self.subTest(value=value),self.assertRaises(ValueError):
                parse_test_inventory(bad,host_artifacts_only=True)
        with self.assertRaises(ValueError):
            parse_test_inventory(inventory('//:missing_marker'),host_artifacts_only=True)
    def test_kernel_disabled_target_is_recorded_without_execution(self):
        active=json.dumps(dict(label='//:host',compatible=True,host_artifact=True))
        disabled=json.dumps(dict(label='//:target',compatible=False,host_artifact=False))
        self.assertEqual(parse_test_inventory(active+'\n'+disabled,host_artifacts_only=True),(['//:host'],['//:target']))
    def test_empty_selector_is_not_hidden_by_another_passing_test(self):
        for selector in ['//:empty_suite', '//:alias_to_suite', '//:not_a_test']:
            with self.subTest(selector=selector), self.assertRaisesRegex(ValueError, 'requested test selector .*no compatible'):
                validate_requested_selector(selector, '', ['//:unrelated_passing_test'], [])
    def test_all_incompatible_selector_is_not_hidden_by_other_tests(self):
        with self.assertRaisesRegex(ValueError, 'no compatible'):
            validate_requested_selector('//:suite', inventory('//:disabled', False), ['//:other'], ['//:disabled'])
    def test_selector_retains_active_and_excluded_members(self):
        self.assertEqual(validate_requested_selector('//:suite', inventory('//:a')+inventory('//:b',False),
            ['//:a','//:other'], ['//:b']), dict(requested='//:suite',expanded=['//:a'],incompatible=['//:b']))
    def test_selector_cannot_introduce_members_missing_from_combined_query(self):
        for text in [inventory('//:unaccounted'), inventory('//:a')+inventory('//:unaccounted',False)]:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'differs from combined'):
                validate_requested_selector('//:suite', text, ['//:a'], [])
    def test_selector_keeps_cross_host_artifact_contract(self):
        with self.assertRaisesRegex(ValueError, 'host artifact'):
            validate_requested_selector('//:suite', json.dumps(dict(label='//:a',compatible=True,host_artifact=False)),
                ['//:a'], [], host_artifacts_only=True)
    def test_selected_target_tests_must_match_requested_inventory(self):
        validate_selected_tests(['//:a','//:b'],['//:b','//:a'])
        for selected in [[],['//:a'],['//:a','//:b','//:unrequested']]:
            with self.subTest(selected=selected),self.assertRaises(ValueError):
                validate_selected_tests(['//:a','//:b'],selected)
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

class TargetInventory(unittest.TestCase):
    def test_query_keeps_configuration_and_quotes_selectors(self):
        command = ['bazel', '--output_user_root=/state', 'test', '--platforms=//:target',
                   '--//cfg:enabled=false', '--profile=/profile', '--build_event_json_file=/events', '//:product']
        query = target_inventory_command(command, ['//:product'], ['//:alias+name'])
        self.assertEqual(query[:5], ['bazel', '--output_user_root=/state', 'cquery', '--platforms=//:target', '--//cfg:enabled=false'])
        self.assertEqual(query[-1], 'config(set("//:alias+name"), target)')
        self.assertNotIn('--profile=/profile', query)
        self.assertNotIn('--build_event_json_file=/events', query)

    def test_build_only_query(self):
        query = target_inventory_command(['bazel', 'build', '--platforms=//:target', '//:product'],
                                         ['//:product'], ['//:product'])
        self.assertEqual(query[:3], ['bazel', 'cquery', '--platforms=//:target'])

    def test_invalid_operation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'one build or test operation'):
            target_inventory_command(['bazel', 'run', '//:product'], ['//:product'], ['//:product'])

    def test_target_suffix_must_match(self):
        with self.assertRaisesRegex(ValueError, 'exact selected target suffix'):
            target_inventory_command(['bazel', 'test', '//:a'], ['//:b'], ['//:b'])

    def test_canonical_and_external_labels(self):
        self.assertEqual(parse_target_inventory(inventory('@@//:source') + inventory('@@sdk+//:tool')),
                         {'//:source': True, '@@sdk+//:tool': True})

    def test_empty_invalid_and_duplicate_records(self):
        for text in ['', '42', inventory('//:a') + inventory('@@//:a'),
                     json.dumps({'label': '//:a', 'compatible': 1}), inventory('//bad label:target')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_target_inventory(text)

    def test_alias_binding_preserves_actual_identity(self):
        self.assertEqual(validate_target_binding('//:alias', {'//:actual': True}, {'//:actual': True}),
                         {'requested': '//:alias', 'configured': '//:actual'})

    def test_external_alias_binding(self):
        self.assertEqual(validate_target_binding('//:alias', {'@@sdk+//:tool': True},
                         {'@@sdk+//:tool': True})['configured'], '@@sdk+//:tool')

    def test_incompatible_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'incompatible'):
            validate_target_binding('//:alias', {'//:actual': False}, {'//:actual': False})

    def test_inconsistent_alias_queries_are_rejected(self):
        for selected in [{}, {'//:other': True}, {'//:a': True, '//:b': True}, {'//:a': False}]:
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_target_binding('//:alias', selected, {'//:a': True})


if __name__=='__main__':unittest.main()
