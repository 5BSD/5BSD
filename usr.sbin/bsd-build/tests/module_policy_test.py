# SPDX-License-Identifier: BSD-2-Clause
import copy
import importlib.util
import os
from pathlib import Path
import unittest

helper = os.environ.get('BSD_BUILD_CONSTRUCTION_HELPER') or str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/construction.py')
spec = importlib.util.spec_from_file_location('construction', helper)
construction = importlib.util.module_from_spec(spec); spec.loader.exec_module(construction)
modules = construction.modules


class ModulePolicy(unittest.TestCase):
    def setUp(self):
        entries = {'/usr/sbin/kldxref': {'type':'file','mode':0o555,'sha256':'a'*64},
                   '/modules/a.ko': {'type':'file','mode':0o444,'sha256':'b'*64},
                   '/modules/ignored.txt': {'type':'file','mode':0o444,'sha256':'c'*64}}
        self.inventory = {'packages':[{'name':'kernel','archive_sha256':'d'*64,'entries':entries}]}
        self.observed = copy.deepcopy(entries)
        self.observed['/modules'] = {'type':'directory'}
        self.policy = {'format':1,'program':'/usr/sbin/kldxref','groups':[{
            'directory':'/modules','packages':['*'],'patterns':['*.ko'],'required':True,
            'output':{'name':'linker.hints','uid':0,'gid':0,'mode':0o444,'flags_set':0,'replace':False}}]}

    def prepare(self):
        return modules.prepare(self.inventory,self.observed,self.policy)

    def test_inventory_selection_and_bindings(self):
        plan = self.prepare(); action = plan['actions'][0]
        self.assertEqual(action['inputs'], ['/modules/a.ko'])
        self.assertEqual(action['argv'], ['/usr/sbin/kldxref','-o','/modules/linker.hints','/modules/a.ko'])
        self.assertEqual(action['input_payloads'], {'/modules/a.ko':'b'*64})
        self.assertEqual(plan['selections'][0]['inputs'][0]['archive_sha256'], 'd'*64)
        self.assertFalse(plan['inputs_authenticated'])

    def test_required_and_optional_empty(self):
        self.policy['groups'][0]['packages']=['absent']
        with self.assertRaisesRegex(ValueError,'empty'): self.prepare()
        self.policy['groups'][0]['required']=False
        self.assertEqual(self.prepare()['actions'],[])
        self.assertEqual(self.prepare()['selections'][0]['inputs'],[])

    def test_changed_or_aliased_payloads(self):
        for field,value in [('sha256','e'*64),('type','symlink'),('hardlinks',['/alias'])]:
            old=copy.deepcopy(self.observed)
            self.observed['/modules/a.ko'][field]=value
            with self.subTest(field=field), self.assertRaises(ValueError): self.prepare()
            self.observed=old

    def test_explicit_replacement_binds_package(self):
        name='/modules/linker.hints'
        item={'type':'file','mode':0o644,'sha256':'e'*64}
        self.inventory['packages'][0]['entries'][name]=dict(item)
        self.observed[name]=dict(item)
        self.policy['groups'][0]['output']['replace']=True
        action=self.prepare()['actions'][0]
        self.assertEqual(action['package_sha256'],'d'*64)
        self.assertEqual(action['replacement_payload']['sha256'],'e'*64)
        self.assertTrue(action['outputs'][name]['replace'])
        self.observed[name]['sha256']='f'*64
        with self.assertRaises(ValueError): self.prepare()

    def test_replacement_cannot_approve_unowned_or_input_file(self):
        self.policy['groups'][0]['output']['replace']=True
        self.observed['/modules/linker.hints']={'type':'file','sha256':'e'*64}
        with self.assertRaises(ValueError): self.prepare()
        self.policy['groups'][0]['output']['name']='a.ko'
        with self.assertRaisesRegex(ValueError,'overlaps'): self.prepare()

    def test_generator_binding(self):
        self.observed['/usr/sbin/kldxref']['sha256']='f'*64
        with self.assertRaises(ValueError): self.prepare()

    def test_stale_output_rejected_even_if_optional(self):
        self.observed['/modules/linker.hints']={'type':'file'}
        with self.assertRaisesRegex(ValueError,'absent'): self.prepare()
        self.policy['groups'][0].update(required=False,patterns=['none'])
        with self.assertRaisesRegex(ValueError,'absent'): self.prepare()

    def test_duplicate_directories_and_owners(self):
        self.policy['groups']*=2
        with self.assertRaisesRegex(ValueError,'duplicate'): self.prepare()
        self.policy['groups']=self.policy['groups'][:1]
        self.inventory['packages']*=2
        with self.assertRaisesRegex(ValueError,'ambiguous'): self.prepare()

    def test_output_and_pattern_validation(self):
        original=copy.deepcopy(self.policy)
        for key,value in [('name','../escape'),('uid',True),('mode',-1),('flags_set',2**64)]:
            self.policy=copy.deepcopy(original);self.policy['groups'][0]['output'][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): self.prepare()
        for value in ([],[''],['a/b'],[1]):
            self.policy=copy.deepcopy(original);self.policy['groups'][0]['patterns']=value
            with self.subTest(value=value), self.assertRaises(ValueError): self.prepare()

    def test_policy_schema(self):
        original=copy.deepcopy(self.policy)
        for value in ([],{},dict(original,format=True),dict(original,extra=1)):
            self.policy=value
            with self.subTest(value=value), self.assertRaises(ValueError): self.prepare()

    def test_selection_hash_changes_with_policy(self):
        before=self.prepare()
        self.policy['groups'][0]['patterns']=['*.txt']
        after=self.prepare()
        self.assertNotEqual(before['selection_sha256'],after['selection_sha256'])
        self.assertNotEqual(before['policy_sha256'],after['policy_sha256'])

    def test_recheck_input_binding_before_execution(self):
        action=self.prepare()['actions'][0]
        self.observed['/modules/a.ko']['sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'changed after selection'):
            construction.check_action_inputs(action,self.observed)


if __name__=='__main__': unittest.main()
