# SPDX-License-Identifier: BSD-2-Clause
"""Native retained policy-binding checks; not read-only mount or boot qualification."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

base=Path(__file__).parent
v=load('verify_retained',base/'verify_retained.py')
t=load('installation_transport',base/'installation_transport.py')
f=load('fixture_stage',base/'fixture_stage.py')
c=load('construction',base.parents[1]/'build/capimage/construction.py')


class Bindings(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.root=self.base/'artifact';self.root.mkdir()
        self.candidate=self.root/'work/candidate';self.candidate.mkdir(parents=True)
        self.output=self.root/'work/constructed';self.output.mkdir()
        source=self.base/'source';source.write_bytes(b'explicit configuration')
        self.policy=dict(format=1,entries={'/etc/example.conf':dict(source=str(source),
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),size=source.stat().st_size,
            uid=0,gid=0,mode=0o444,replaces=['a'*64])})
        policy_file=self.base/'policy.json';policy_file.write_text(json.dumps(self.policy))
        transport=t.stage(policy_file,f.Fixture(self.base,self.base,self.root))
        self.saved=self.output/'installation-transport.json';self.saved.write_text(json.dumps(transport))
        self.translated,_=t.verify(self.root/'tests')
        directory=dict(type='directory',uid=0,gid=0,mode=0o755,flags_set=0)
        self.initial=dict(format=1,entries={'/':dict(directory,source='layout',replaces=[])})
        self.inventory=dict(format=1,scope='package-payload-inventory',construction={'actions':[]},
            packages=[dict(name='fixture',archive_sha256='a'*64,config=['/etc/example.conf'],directories={},
            entries={'/etc':directory,'/etc/example.conf':dict(type='file',uid=0,gid=0,mode=0o644,
                flags_set=0,size=8,sha256=hashlib.sha256(b'baseline').hexdigest())})])
        expected=dict(self.translated['entries']['/etc/example.conf']);del expected['source']
        expected.update(type='file',flags_set=0,source='installation policy sha256:'+c.digest(self.translated))
        self.generated=copy.deepcopy(self.initial);self.generated['entries']['/etc/example.conf']=expected
        self.built=dict(installation_configuration=dict(policy_sha256=c.digest(self.translated),
            records={'/etc/example.conf':copy.deepcopy(expected)},sources={'/etc/example.conf':'/tests/installation-inputs/0'}))

    def check(self):
        v.verify_installation(self.root,self.candidate,'/work/constructed',self.built,
            self.generated,self.initial,self.inventory,c)

    def test_exact_policy_bindings(self):self.check()

    def test_unrequested_relocation_receipt_cannot_be_ignored(self):
        self.built['installation_relocation'] = {'scope': 'trusted-builder-installation-relocation'}
        with self.assertRaisesRegex(ValueError, 'relocation receipt presence differs from policy'):
            self.check()

    def test_changed_generated_metadata(self):
        self.generated['entries']['/etc/example.conf']['mode']=0o666
        with self.assertRaisesRegex(ValueError,'differs from explicit inputs'):self.check()

    def test_changed_receipt(self):
        for key,value in (('policy_sha256','b'*64),('sources',{}),('records',{})):
            original=self.built['installation_configuration'][key]
            self.built['installation_configuration'][key]=value
            with self.assertRaisesRegex(ValueError,'differs from explicit inputs'):self.check()
            self.built['installation_configuration'][key]=original

    def test_replacement_requires_package_configuration(self):
        self.inventory['packages'][0]['config']=[]
        with self.assertRaisesRegex(ValueError,'configuration owner'):self.check()

    def test_changed_saved_transport(self):
        self.saved.write_text('{}')
        with self.assertRaisesRegex(ValueError,'transport receipt differs'):self.check()

    def test_same_size_transported_input(self):
        target=self.root/'tests/installation-inputs/0'
        target.write_bytes(b'X'*target.stat().st_size)
        with self.assertRaisesRegex(ValueError,'source digest differs'):self.check()

    def test_changed_transported_input(self):
        (self.root/'tests/installation-inputs/0').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError,'source size differs'):self.check()


class Relocations(unittest.TestCase):
    def setUp(self):
        directory = dict(type='directory', uid=0, gid=0, mode=0o755, flags_set=0,
                         mtime=1, mtime_nsec=0)
        payload = dict(type='file', uid=0, gid=0, mode=0o600, flags_set=0,
                       size=4, sha256=hashlib.sha256(b'data').hexdigest(), mtime=1, mtime_nsec=0)
        program = dict(payload, mode=0o555)
        requirement = dict(name='data', program='/tool', path='/input', type='file',
                           lifetime='persistent', purpose='fixture persistent state')
        self.inventory = dict(format=1, scope='package-payload-inventory',
            construction={'actions': []}, packages=[dict(name='fixture', archive_sha256='a'*64,
            entries={'/input':payload, '/tool':program}, directories={},
            manifest={'annotations': {'5bsd.state-requirements':json.dumps(
                {'format':1, 'requirements':[requirement]})}})])
        self.initial = dict(format=1, entries={'/':dict(
            {key:value for key,value in directory.items() if key not in ('mtime','mtime_nsec')},
            source='explicit fixture', replaces=[])})
        self.before = {'/':directory, '/input':payload, '/tool':program}
        self.policy = dict(format=4, entries={'/input':dict(operation='relocate',
            target='/moved', package='fixture', requirement='data')})
        self.make_evidence(self.before)

    def make_evidence(self, before):
        plan = c.installations.prepare_relocations(self.inventory, before, self.initial,
            self.policy, c._construction_context())
        self.objects = copy.deepcopy(before)
        self.objects['/moved'] = self.objects.pop('/input')
        self.objects['/input'] = {key:value for key,value in plan['records']['/input'].items()
                                 if key not in ('source','replaces')}
        self.objects['/'].update(mtime=2)
        self.generated = copy.deepcopy(self.initial)
        self.generated['entries'].update(plan['records'])
        self.built = dict(receipts=[], installation_configuration=dict(records={},
            after_sha256=c.digest(before)), installation_relocation=dict(plan,
            scope='trusted-builder-installation-relocation', before_sha256=c.digest(before),
            after_sha256=c.digest(self.objects)))

    def check(self):
        return v.verify_relocations(Path('/unused'), c, self.inventory, self.initial,
            self.built, self.generated, self.objects, self.policy)

    def test_reconstructs_parent_timestamps_and_file_provenance(self):
        result = self.check()
        self.assertEqual(result['moves'], 1)
        self.assertFalse(result['generation_authenticated'])
        self.assertFalse(result['runtime_authority_assigned'])

    def test_receipt_changes_are_rejected(self):
        original = copy.deepcopy(self.built)
        for key,value in (('inputs',{}),('records',{}),('moves',{}),
                          ('parent_observations',{}),('runtime_storage_authorized',True),
                          ('after_sha256','b'*64),('before_sha256','b'*64)):
            self.built = copy.deepcopy(original)
            self.built['installation_relocation'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()

    def test_parent_mode_cannot_be_disguised_as_timestamp_change(self):
        self.built['installation_relocation']['parent_observations']['/']['mode'] = 0o777
        with self.assertRaisesRegex(ValueError, 'parent metadata'):
            self.check()

    def test_consistent_forged_content_does_not_replace_package_provenance(self):
        forged = copy.deepcopy(self.before)
        forged['/input']['sha256'] = hashlib.sha256(b'fake').hexdigest()
        self.make_evidence(forged)
        with self.assertRaisesRegex(ValueError, 'prior declared content'):
            self.check()

    def test_extra_final_generated_record_is_rejected(self):
        self.generated['entries']['/extra'] = copy.deepcopy(self.generated['entries']['/moved'])
        with self.assertRaisesRegex(ValueError, 'final manifest'):
            self.check()

    def test_predecessor_chain_must_match(self):
        self.built['installation_configuration']['after_sha256'] = 'b'*64
        with self.assertRaisesRegex(ValueError, 'predecessor'):
            self.check()

    def test_generated_input_is_bound_to_its_construction_receipt(self):
        payload = self.inventory['packages'][0]['entries'].pop('/input')
        self.make_evidence(self.before)
        record = {key:value for key,value in payload.items() if key not in ('mtime','mtime_nsec')}
        record['replaces'] = []
        receipt = dict(action={'name':'fixture'}, outputs={'/input':record},
            before_sha256='b'*64, after_sha256=c.digest(self.before))
        receipt['sha256'] = c.digest(receipt)
        self.built['receipts'] = [receipt]
        self.built['installation_configuration']['after_sha256'] = 'b'*64
        self.assertEqual(self.check()['moves'], 1)
        receipt['outputs']['/input']['sha256'] = 'c'*64
        with self.assertRaisesRegex(ValueError, 'receipt chain'):
            self.check()


if __name__=='__main__':unittest.main()
