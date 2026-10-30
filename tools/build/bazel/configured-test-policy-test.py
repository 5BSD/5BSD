#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check literal Kyua metadata and declared test-environment translation."""
import ast
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import configured_tests
import unittest
from configured_test_policy import metadata,translate

class Policy(unittest.TestCase):
    def setUp(self):
        self.policy=dict(metadata='',environment='PATH=/bin:/sbin:/usr/bin:/usr/sbin LD_LIBRARY_PATH=/lib:/usr/lib',default_library_paths='/lib /usr/lib',kyuafile='auto',suite='FreeBSD')
    def test_literals_and_program_override(self):
        self.assertEqual(metadata('timeout=10 required_programs="one two" is_exclusive=true timeout=20'),dict(timeout=20,required_programs='one two',is_exclusive=True))
    def test_no_implicit_timeout(self):
        result=translate(self.policy)
        self.assertEqual(result['metadata'],{})
        self.assertNotIn('LD_LIBRARY_PATH',result['environment'])
        self.assertEqual(result['environment']['PATH'],'/bin:/sbin:/usr/bin:/usr/sbin')
    def test_declared_environment_remains_literal(self):
        self.policy['environment']+=" MESSAGE='two words $(false)'"
        self.assertEqual(translate(self.policy)['environment']['MESSAGE'],'two words $(false)')
    def test_custom_loader_search_rejected(self):
        self.policy['environment']+=' LD_LIBRARY_PATH=/custom:/lib:/usr/lib'
        with self.assertRaisesRegex(ValueError,'custom test library'):translate(self.policy)
    def test_other_loader_override_rejected(self):
        self.policy['environment']+=' LD_PRELOAD=/some/library'
        with self.assertRaisesRegex(ValueError,'loader override'):translate(self.policy)
    def test_custom_kyuafile_rejected(self):
        for value in ('yes','no'):
            self.policy['kyuafile']=value
            with self.subTest(value=value),self.assertRaises(ValueError):translate(self.policy)
    def test_expressions_and_identity_rejected(self):
        for value in ('timeout=os.execute("true")','name="another"','timeout=1; os.exit()','required_files=["a"]','timeout=1.5'):
            with self.subTest(value=value),self.assertRaises(ValueError):metadata(value)
    def test_json_only_escapes_rejected(self):
        for value in (r'required_files="\u0041"',r'required_files="a\/b"'):
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'Lua support'):metadata(value)
        self.assertEqual(metadata(r'required_files="a\\b"'),{'required_files':r'a\b'})
    def test_exclusive_scheduler_policy(self):
        for value,expected in (('true',['exclusive']),('false',[])):
            self.policy['metadata']='is_exclusive='+value
            result=translate(self.policy)
            self.assertEqual(result['tags'],expected)
            self.assertEqual(result['metadata']['is_exclusive'],value=='true')
        for value in ('1','"true"'):
            self.policy['metadata']='is_exclusive='+value
            with self.assertRaisesRegex(ValueError,'boolean'):translate(self.policy)
    def test_emitted_runner_retains_policy(self):
        self.policy['metadata']='is_exclusive=true timeout=123'
        self.policy['environment']+=" MESSAGE='two words'"
        component=dict(metadata=dict(PROG='example'),test_policy=self.policy)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'toolchain/bin').mkdir(parents=True)
            for name in ('extra_kyua','extra_python'):
                (root/'toolchain/bin'/name).touch()
            with patch.object(configured_tests,'runtime_libraries',return_value={}):
                lines=configured_tests.emit(root,[component],[(component,'example_test_program')])
            call=ast.parse(lines[-1]).body[0].value
            attrs={v.arg:ast.literal_eval(v.value) for v in call.keywords}
            self.assertEqual(attrs['tags'],['exclusive'])
            self.assertEqual(json.loads(attrs['test_metadata']),dict(is_exclusive=True,timeout=123))
            self.assertEqual(attrs['test_environment']['MESSAGE'],'two words')
            self.assertEqual(attrs['suite'],'FreeBSD')
            self.assertEqual(attrs['case_timeout'],0)
    def test_missing_policy_rejected(self):
        with self.assertRaisesRegex(ValueError,'regenerate'):translate(None)
        bad=copy.deepcopy(self.policy);del bad['environment']
        with self.assertRaises(ValueError):translate(bad)

if __name__=='__main__':unittest.main()
