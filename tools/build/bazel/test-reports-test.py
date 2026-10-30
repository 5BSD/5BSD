#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from test_reports import case_counts, snapshot, snapshot_failure

class Reports(unittest.TestCase):
    def test_outcomes(self):
        self.assertEqual(case_counts('<testsuites><testsuite><testcase/>'
            '<testcase><skipped message="expected_failure: known"/></testcase>'
            '<testcase><skipped message="unavailable"/></testcase>'
            '<testcase><failure/></testcase></testsuite></testsuites>'),
            dict(passed=1, expected_failure=1, skipped=1, failed=1))

    def test_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xml = root / 'test.xml'
            xml.write_text('<testsuite><testcase><skipped message="expected_failure: issue"/></testcase></testsuite>')
            event = dict(id=dict(testResult=dict(label='//:a', run=1, shard=1, attempt=1)),
                         testResult=dict(status='PASSED', testActionOutput=[dict(name='test.xml', uri=xml.as_uri())]))
            receipt = snapshot([event], root / 'out', ['//:a'])
            self.assertFalse(receipt['all_reported_cases_passed'])
            self.assertEqual(receipt['case_counts'], dict(expected_failure=1))
            xml.unlink()
            self.assertTrue((root / 'out/0/test.xml').exists())
            saved = json.loads((root / 'out/manifest.json').read_text())
            self.assertEqual(saved['results'][0]['action_status'], 'PASSED')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                snapshot([], root / 'missing', ['//:a'])
            event['testResult']['testActionOutput'] = []
            with self.assertRaisesRegex(ValueError, 'lacks XML'):
                snapshot([event], root / 'noxml', ['//:a'])

    def test_no_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = snapshot([], Path(tmp) / 'reports', [])
            self.assertEqual(result['case_counts'], {})
            self.assertFalse(result['all_reported_cases_passed'])

    def test_failed_partial_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / 'test.log'
            log.write_text('timeout diagnostic\n')
            event = dict(id=dict(testResult=dict(label='//:timeout', run=1, shard=1, attempt=1)),
                testResult=dict(status='TIMEOUT', testActionOutput=[dict(name='test.log', uri=log.as_uri())]))
            stream = root / 'events.json'
            stream.write_text(json.dumps(event) + '\n{"truncated":')
            result = snapshot_failure(stream, root / 'reports')
            self.assertFalse(result['inventory_complete'])
            self.assertFalse(result['all_reported_cases_passed'])
            self.assertEqual(result['observed_tests'], ['//:timeout'])
            self.assertEqual(result['event_errors'][0]['line'], 2)
            manifest = json.loads((root / 'reports/manifest.json').read_text())
            self.assertTrue(manifest['results'][0]['case_evidence_missing'])
            self.assertEqual((root / 'reports/0/test.log').read_text(), log.read_text())

    def test_failed_malformed_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xml = root / 'test.xml'
            xml.write_text('<testsuite>')
            event = dict(id=dict(testResult=dict(label='//:bad', run=1)),
                testResult=dict(status='FAILED', testActionOutput=[dict(name='test.xml', uri=xml.as_uri())]))
            stream = root / 'events.json'
            stream.write_text(json.dumps(event) + '\n')
            result = snapshot_failure(stream, root / 'reports')
            self.assertFalse(result['all_reported_cases_passed'])
            manifest = json.loads((root / 'reports/manifest.json').read_text())
            self.assertIn('xml_error', manifest['results'][0])
            self.assertEqual((root / 'reports/0/test.xml').read_bytes(), xml.read_bytes())
            with self.assertRaises(ET.ParseError):
                snapshot([event], root / 'strict', ['//:bad'])

    def test_failed_run_with_passing_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xml = root / 'test.xml'
            xml.write_text('<testsuite><testcase/></testsuite>')
            event = dict(id=dict(testResult=dict(label='//:pass', run=1)),
                testResult=dict(status='PASSED', testActionOutput=[dict(name='test.xml', uri=xml.as_uri())]))
            stream = root / 'events.json'
            stream.write_text(json.dumps(event) + '\n')
            result = snapshot_failure(stream, root / 'reports')
            self.assertEqual(result['case_counts'], {'passed': 1})
            self.assertFalse(result['all_reported_cases_passed'])
            self.assertFalse(result['inventory_complete'])

if __name__ == '__main__':
    unittest.main()
