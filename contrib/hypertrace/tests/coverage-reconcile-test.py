#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Integrity regressions for coverage reconciliation, using synthetic LLVM data."""
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest

reconcile = runpy.run_path(str(Path(__file__).with_name('coverage-reconcile.py')))['reconcile']

class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root/'source.c'
        self.source.write_text('int f(void) { return 1; }\n')
        sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.inventory = {'configurations': [{'arch':'amd64', 'snapshot':False,
            'target':'component', 'status':'evaluated', 'inputs':[
                {'kind':'SRCS','name':'source.c','path':'source.c','sha256':sha}]}]}
        self.export = {'type':'llvm.coverage.json.export','data':[{'files':[
            {'filename':str(self.source), 'summary':{
                k:{'count':100,'covered':97} for k in ('lines','branches','functions')}}]}]}
        self.provenance = {'source_sha256':{str(self.source):sha}}
    def report(self):
        return reconcile(self.inventory,self.export,self.provenance,self.root,'amd64',False)
    def status(self):
        return self.report()['components'][0]['inputs'][0]['status']
    def test_high_partial_coverage_never_certifies_component(self):
        r = self.report()
        self.assertFalse(r['coverage_accepted'])
        c = r['components'][0]
        self.assertFalse(c['coverage_accepted'])
        self.assertTrue(c['mapped_subset_metrics']['lines']['mapped_subset_meets_97'])
    def test_missing_export_keeps_input_visible(self):
        self.export['data'][0]['files'] = []
        self.assertEqual(self.status(),'no-executable-mapping-established')
        self.assertIsNone(self.report()['components'][0]['mapped_subset_metrics']['lines']['percent'])
    def test_same_basename_does_not_match(self):
        self.export['data'][0]['files'][0]['filename'] = str(self.root/'other/source.c')
        self.assertEqual(self.status(),'no-executable-mapping-established')
    def test_changed_source_is_rejected(self):
        self.source.write_text('int f(void) { return 2; }\n')
        self.assertEqual(self.status(),'inventory-source-changed')
    def test_unproven_export_source_is_rejected(self):
        self.provenance['source_sha256'] = {}
        self.assertEqual(self.status(),'export-source-provenance-unverified')
    def test_duplicate_mapping_is_rejected(self):
        self.export['data'][0]['files'] *= 2
        with self.assertRaises(ValueError): self.report()
    def test_generated_input_remains_visible(self):
        i = self.inventory['configurations'][0]['inputs'][0]
        i.update(path=None,name='parser.c')
        self.assertEqual(self.status(),'unresolved-or-generated')
    def test_wrong_configuration_is_rejected(self):
        self.inventory['configurations'][0]['arch']='aarch64'
        with self.assertRaises(ValueError): self.report()
    def test_duplicate_input_does_not_inflate_denominator(self):
        self.inventory['configurations'][0]['inputs'] *= 2
        self.assertEqual(self.report()['components'][0]['mapped_subset_metrics']['lines']['count'],100)
    def test_multiple_exports_require_prior_merge(self):
        self.export['data'] *= 2
        with self.assertRaises(ValueError): self.report()
    def test_below_threshold_is_visible(self):
        self.export['data'][0]['files'][0]['summary']['branches']['covered']=96
        self.assertFalse(self.report()['components'][0]['mapped_subset_metrics']['branches']['mapped_subset_meets_97'])

if __name__ == '__main__': unittest.main()
