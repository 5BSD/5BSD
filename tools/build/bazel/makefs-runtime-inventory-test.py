#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile native complete-suite ownership with the original maintained scripts."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import re
import unittest
import tempfile
import runtime_profile

root = Path(__file__).parent
workspace = Path(os.environ['TEST_SRCDIR'])/os.environ['TEST_WORKSPACE'] if 'TEST_SRCDIR' in os.environ else root.parents[2]
suites = workspace/'usr.sbin/makefs/tests'
spec = importlib.util.spec_from_file_location('checker', root/'makefs-runtime-check.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class InventoryTest(unittest.TestCase):
    def test_all_selected_source_cases_and_original_skips(self):
        inventory = json.loads((suites/'runtime_suite_inventory.json').read_text())
        self.assertEqual(inventory['format'],1)
        self.assertTrue({'makefs_cd9660_tests','makefs_ffs_tests','makefs_msdos_tests'} <= set(inventory['suites']))
        self.assertLessEqual(set(inventory['suites']),{'makefs_cd9660_tests','makefs_ffs_tests','makefs_msdos_tests','makefs_zfs_tests'})
        for name,suite in inventory['suites'].items():
            text = (suites/(name+'.sh')).read_text()
            declared = re.findall(r'^atf_test_case ([A-Za-z0-9_]+)',text,re.M)
            registered = re.findall(r'^\s*atf_add_test_case ([A-Za-z0-9_]+)',text,re.M)
            self.assertCountEqual(declared,registered)
            self.assertEqual(suite['cases'],registered)
            self.assertEqual(suite['policy']['required_user'],'root')
            self.assertEqual(suite['program'],'/usr/tests/usr.sbin/makefs/'+name)
            self.assertEqual(len(suite['source_skips']),3 if name=='makefs_cd9660_tests' else 0)
            for case,reason in suite['source_skips'].items():
                self.assertIn(case,declared)
                self.assertIn('atf_skip "'+reason+'"',text)

    def test_uniform_emulation_profile_preserves_source_deadline(self):
        for factor in [1,3,5,20]:
            profile=runtime_profile.validate({'timeout_scale':factor})
            for source_timeout in [300,600,3600]:
                self.assertEqual(runtime_profile.deadline(source_timeout,profile),source_timeout*factor)
        for source_timeout in [0,3601,True,1.5]:
            with self.subTest(source=source_timeout),self.assertRaises(ValueError):
                runtime_profile.deadline(source_timeout,{'timeout_scale':1})
        for invalid in [{}, {'timeout_scale':0}, {'timeout_scale':21}, {'timeout_scale':True},
                        {'timeout_scale':1.5}, {'timeout_scale':'3'}, {'timeout_scale':3,'compression':10},None]:
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):runtime_profile.validate(invalid)

    def test_failure_diagnostic_preserves_complete_captured_record(self):
        record={'suite':'makefs_zfs_tests','case':'compression','state':'FAIL',
                'body':{'status':124,'stdout':'long output\n'*10000,'stderr':'actual error\n'},
                'cleanup':{'status':0,'stdout':'','stderr':''},'restored_inventory':False}
        output=io.StringIO()
        with contextlib.redirect_stdout(output):checker.failure_report(record)
        lines=output.getvalue().splitlines()
        self.assertEqual(lines[0],'MAKEFS_CASE_FAILURE_REPORT_BEGIN')
        self.assertEqual(lines[-1],'MAKEFS_CASE_FAILURE_REPORT_END')
        self.assertEqual(json.loads(lines[1]),{'truncated':False,'record':record})

    def test_missing_programs_and_escape_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with self.assertRaisesRegex(ValueError,'declared runtime programs missing: mtree'):
                checker.require_programs(root,['mtree'])
            (root/'usr/sbin').mkdir(parents=True)
            program=root/'usr/sbin/mtree';program.write_text('fixture');program.chmod(0o555)
            self.assertEqual(checker.require_programs(root,['mtree']),{'mtree':'/usr/sbin/mtree'})
            program.unlink();program.symlink_to('/bin/sh')
            with self.assertRaisesRegex(ValueError,'declared runtime programs missing'):
                checker.require_programs(root,['mtree'])

    def test_listing_retains_requirements_timeout_cleanup(self):
        actual=checker.listing('Content-Type: application/X-atf-tp; version="1"\n\nident: sample\nhas.cleanup: true\ntimeout: 600\nrequire.progs: strings\n')
        self.assertEqual(actual['sample'],{'ident':'sample','has.cleanup':'true','timeout':'600','require.progs':'strings'})
        checker.reconcile({'cases':['sample'],'source_skips':{},'policy':{'required_user':'root'}},actual)

    def test_missing_extra_duplicate_cases_rejected(self):
        suite={'cases':['sample'],'source_skips':{},'policy':{'required_user':'root'}}
        for actual in [{},{'extra':{}},{'sample':{},'extra':{}}]:
            with self.subTest(actual=actual),self.assertRaises(ValueError):checker.reconcile(suite,actual)
        with self.assertRaises(ValueError):checker.reconcile({**suite,'cases':['sample','sample']},{'sample':{}})

    def test_weakened_privilege_and_unknown_skip_rejected(self):
        suite={'cases':['sample'],'source_skips':{},'policy':{'required_user':'root'}}
        with self.assertRaises(ValueError):checker.reconcile({**suite,'policy':{'required_user':'unprivileged'}},{'sample':{}})
        with self.assertRaises(ValueError):checker.reconcile({**suite,'source_skips':{'missing':'reason'}},{'sample':{}})

    def test_malformed_listing_and_timeout_rejected(self):
        prefix='Content-Type: application/X-atf-tp; version="1"\n\n'
        for text in ['wrong',prefix+'ident: sample\nident: twice',prefix+'ident: sample\ntimeout: 0',prefix+'ident: sample\ntimeout: 3601',prefix+'ident: sample\nhas.cleanup: maybe',prefix+'ident: sample\n\nident: sample']:
            with self.subTest(text=text),self.assertRaises(ValueError):checker.listing(text)

if __name__=='__main__':unittest.main()
