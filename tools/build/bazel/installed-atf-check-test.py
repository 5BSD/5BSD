# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import sys
import time
spec=importlib.util.spec_from_file_location('checker',Path(__file__).with_name('installed-atf-check.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Contracts(unittest.TestCase):
    def plan(self):return dict(format=1,programs=[dict(path='/usr/tests/lib/libc/locale/iconv_test',case_user='all',stdin_tty_cases=[])])
    def test_real_stdin_terminal_is_opt_in(self):
        for terminal in [False,True]:
            with self.subTest(terminal=terminal):
                result=m.run_process([sys.executable,'-c','import os; print(os.isatty(0))'],dict(os.environ),terminal,5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,str(terminal).encode()+b'\n')
    def test_timeout_kills_children_holding_output_pipes(self):
        start=time.monotonic()
        result=m.run_process([sys.executable,'-c','import os,time; os.fork(); time.sleep(60)'],dict(os.environ),timeout=1)
        self.assertEqual(result.returncode,124)
        self.assertLess(time.monotonic()-start,10)
        self.assertIn(b'phase timeout',result.stderr)
    def test_child_exit_race_at_deadline_still_reports_timeout(self):
        class Exited:
            pid=123
            calls=0
            def communicate(self,timeout=None):
                self.calls+=1
                if self.calls==1:raise m.subprocess.TimeoutExpired(['fixture'],1)
                return b'',b''
        with patch.object(m.subprocess,'Popen',return_value=Exited()),patch.object(m.os,'killpg',side_effect=ProcessLookupError):
            self.assertEqual(m.run_process(['fixture'],{},timeout=1).returncode,124)
    def test_nonzero_child_exit_is_preserved(self):
        result=m.run_process([sys.executable,'-c','raise SystemExit(17)'],dict(os.environ),timeout=5)
        self.assertEqual(result.returncode,17)
    def test_expected_failure_is_distinct_from_a_pass(self):
        self.assertEqual(m.case_outcome('passed'),'passed')
        self.assertEqual(m.case_outcome('expected_failure: original known issue'),'expected_failure')
        self.assertEqual(m.case_outcome('skipped: missing resource'),'skipped')
    def test_malformed_or_unexpected_results_fail(self):
        for text in ['', 'expected_failure:', 'expected_failure: ', 'expected_failure: a\npassed', 'failed: unexpected pass', 'broken: failed']:
            with self.subTest(text=text):self.assertEqual(m.case_outcome(text),'failed')
    def test_valid_explicit_plan(self):self.assertEqual(m.validate_plan(self.plan()),self.plan())
    def test_unsafe_or_noncanonical_paths(self):
        for path in ['/bin/tool','relative','/usr/tests/../escape','/usr/tests//tool','/usr/tests/tool\n']:
            p=self.plan();p['programs'][0]['path']=path
            with self.subTest(path=path),self.assertRaises(ValueError):m.validate_plan(p)
    def test_empty_duplicate_or_unknown_plan_fields(self):
        for p in [dict(format=1,programs=[]),dict(format=True,programs=[]),dict(format=1,programs=[],ignored=True),dict(format=2,programs=[])]:
            with self.subTest(p=p),self.assertRaises(ValueError):m.validate_plan(p)
        p=self.plan();p['programs']*=2
        with self.assertRaises(ValueError):m.validate_plan(p)
    def test_bad_case_policies(self):
        for key,value in [('case_user','other'),('stdin_tty_cases',['x','x']),('stdin_tty_cases',['../x'])]:
            p=self.plan();p['programs'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_plan(p)
    def test_original_metadata_retains_user_cleanup_deadline(self):
        text='Content-Type: application/X-atf-tp; version="1"\n\nident: jail\nrequire.user: root\nhas.cleanup: true\ntimeout: 45\n'
        self.assertEqual(m.parse_listing(text)['jail'],dict(ident='jail',**{'require.user':'root','has.cleanup':'true','timeout':'45'}))
    def test_invalid_case_metadata_fails(self):
        prefix='Content-Type: application/X-atf-tp; version="1"\n\n'
        for value in ['', 'ident: x\nident: y', 'ident: ../x', 'ident: x\ntimeout: 0', 'ident: x\ntimeout: 4000', 'ident: x\nhas.cleanup: yes','ident: x\nrequire.user: someuser']:
            with self.subTest(value=value),self.assertRaises(ValueError):m.parse_listing(prefix+value)
if __name__=='__main__':unittest.main()
