# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

helper = os.environ.get('BSD_BUILD_CONSTRUCTION_HELPER') or str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/construction.py')
spec = importlib.util.spec_from_file_location('construction', helper)
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class Installation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'; self.root.mkdir()
        self.target = self.root / 'policy'; self.target.write_bytes(b'package baseline')
        self.target.chmod(0o644)
        for p in (self.target, self.root):
            os.chflags(p, 0)
        self.observed = c.generation.scan(self.root)
        self.inventory = dict(format=1,scope='package-payload-inventory',
            construction={'actions':[]},packages=[dict(name='fixture',archive_sha256='a'*64,
            config=['/policy'],entries={'/policy': self.observed['/policy']},directories={})])
        self.generated = dict(format=1,entries={'/':dict(type='directory',uid=os.getuid(),gid=self.observed['/']['gid'],
            mode=self.observed['/']['mode'],flags_set=0,source='test layout',replaces=[])})
        self.source = self.base / 'input'; self.source.write_bytes(b'installation configuration')
        self.policy = dict(format=1,entries={'/policy':dict(source=str(self.source),
            sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),size=self.source.stat().st_size,
            uid=0,gid=0,mode=0o600,replaces=['a'*64])})

    def test_preflight_needs_no_candidate_filesystem(self):
        candidate = self.base / 'not-created'
        with patch.object(c.generation, 'scan', side_effect=AssertionError('must not scan a candidate')):
            plan = c.installations.preflight(self.inventory, self.generated,
                                            self.policy, candidate, c)
        self.assertEqual(plan['records']['/policy']['sha256'],
                         self.policy['entries']['/policy']['sha256'])
        self.assertFalse(candidate.exists())
        self.assertEqual(self.target.read_bytes(), b'package baseline')

    def test_preflight_rejects_stale_archive_for_config_and_template(self):
        for template in (False, True):
            with self.subTest(template=template):
                if template:
                    self.template_policy()
                self.policy['entries']['/policy']['replaces'] = ['b' * 64]
                with self.assertRaisesRegex(ValueError, 'exact package inputs'):
                    c.installations.preflight(self.inventory, self.generated,
                                              self.policy, self.base / 'absent', c)

    def test_preflight_checks_source_bytes(self):
        self.source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'explicit size/hash'):
            c.installations.preflight(self.inventory, self.generated,
                                      self.policy, self.base / 'absent', c)

    def test_cli_preflight_rejects_stale_owner_before_extraction(self):
        self.policy['entries']['/policy']['replaces'] = ['b' * 64]
        self.inventory['packages'][0]['archive'] = str(self.base / 'archive.pkg')
        argv = ['construction.py', '--root', str(self.root), '--output',
                str(self.base / 'output'), '--inventory', str(self.base / 'inventory'),
                '--generated', str(self.base / 'generated'), '--installation-policy',
                str(self.base / 'installation'), '--extract-tar', '/usr/bin/tar']
        with patch('sys.argv', argv), \
             patch.object(c.generation, 'read_json', side_effect=[(self.inventory, None), (self.generated, None)]), \
             patch.object(c.modules, 'read_policy', return_value=self.policy), \
             patch.object(c, 'inventory_from_archives', return_value=self.inventory):
            # Extraction of this nonempty root would fail for a different
            # reason. The ownership mismatch must be rejected first.
            with self.assertRaisesRegex(ValueError, 'exact package inputs'):
                c.main()
        self.assertEqual(self.target.read_bytes(), b'package baseline')
        self.assertFalse((self.base / 'output').exists())

    def template_policy(self):
        import json
        package = self.inventory['packages'][0]
        package['config'] = []
        package['manifest'] = {'annotations': {'5bsd.installation-templates':
            json.dumps({'format': 1, 'paths': ['/policy']})}}
        self.policy['format'] = 5
        self.policy['entries']['/policy']['operation'] = 'replace-template'

    def test_immutable_template_replacement_is_explicit(self):
        self.template_policy()
        plan = self.prepare()
        self.assertEqual(plan['records']['/policy']['sha256'],
                         self.policy['entries']['/policy']['sha256'])
        self.assertEqual(self.target.read_bytes(), b'package baseline')
        self.assertFalse(plan['runtime_storage_authorized'])

    def test_template_does_not_enable_ordinary_replacement(self):
        self.template_policy()
        self.policy['entries']['/policy']['operation'] = 'replace'
        with self.assertRaisesRegex(ValueError, 'configuration owner'):
            self.prepare()

    def test_template_requires_new_format_and_exact_owner(self):
        self.template_policy()
        self.policy['format'] = 4
        with self.assertRaisesRegex(ValueError, 'unknown installation operation'):
            self.prepare()
        self.policy['format'] = 5
        self.policy['entries']['/policy']['replaces'] = ['b' * 64]
        with self.assertRaises(ValueError):
            self.prepare()

    def test_template_declarations_reject_unsafe_payloads(self):
        self.template_policy()
        package = self.inventory['packages'][0]
        for update in ({'type': 'symlink'}, {'mode': 0o755}, {'flags_set': 1}):
            with self.subTest(update=update):
                saved = dict(package['entries']['/policy'])
                package['entries']['/policy'].update(update)
                with self.assertRaisesRegex(ValueError, 'owned nonexecutable'):
                    self.prepare()
                package['entries']['/policy'] = saved
        package['config'] = ['/policy']
        with self.assertRaisesRegex(ValueError, 'owned nonexecutable'):
            self.prepare()

    def test_template_declaration_schema_rejected(self):
        import json
        self.template_policy()
        package = self.inventory['packages'][0]
        for document in ({'format': True, 'paths': ['/policy']},
                         {'format': 1, 'paths': ['/policy', '/policy']},
                         {'format': 1, 'paths': ['/missing']},
                         {'format': 1, 'paths': ['/x/../policy']},
                         {'format': 1, 'paths': []}):
            with self.subTest(document=document):
                package['manifest']['annotations']['5bsd.installation-templates'] = json.dumps(document)
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_undeclared_template_replacement_rejected(self):
        self.template_policy()
        self.inventory['packages'][0]['manifest']['annotations'] = {}
        with self.assertRaisesRegex(ValueError, 'template owner'):
            self.prepare()

    def prepare(self):
        return c.installations.prepare(self.inventory,self.observed,self.generated,self.policy,self.root,c)

    def alias(self):
        import json
        program = self.root / 'daemon'
        program.write_bytes(b'fixture executable'); program.chmod(0o555); os.chflags(program, 0)
        os.chflags(self.root, 0)
        self.observed = c.generation.scan(self.root)
        package = self.inventory['packages'][0]
        package['entries']['/daemon'] = self.observed['/daemon']
        package['manifest'] = {'annotations': {'5bsd.state-requirements': json.dumps({
            'format': 1, 'requirements': [{'name': 'socket', 'program': '/daemon',
            'path': '/log', 'type': 'socket', 'lifetime': 'boot', 'purpose': 'local messages'}]})}}
        self.policy = {'format': 3, 'entries': {'/log': {'operation': 'alias',
            'target': '/state/log', 'package': 'fixture', 'requirement': 'socket'}}}

    def test_declared_alias_is_not_runtime_authority(self):
        self.alias()
        plan = self.prepare()
        self.assertEqual(plan['records']['/log']['target'], '/state/log')
        self.assertEqual(plan['sources'], {})
        self.assertFalse(plan['runtime_storage_authorized'])
        self.assertFalse((self.root / 'log').exists())
        # Exercise the same context passed by the constructor, not just this module.
        self.assertEqual(plan, c.installations.prepare(self.inventory, self.observed,
            self.generated, self.policy, self.root, c._construction_context()))

    def template_and_alias(self):
        import json
        self.alias()
        for name in ('etc', 'state'):
            directory = self.root / name
            directory.mkdir()
            os.chflags(directory, 0)
        os.chflags(self.root, 0)
        self.observed = c.generation.scan(self.root)
        for name in ('/etc', '/state'):
            self.generated['entries'][name] = dict(
                **{key: self.observed[name][key] for key in ('type', 'uid', 'gid', 'mode', 'flags_set')},
                source='explicit fixture topology', replaces=[])
        annotation = self.inventory['packages'][0]['manifest']['annotations']
        document = json.loads(annotation['5bsd.state-requirements'])
        document['requirements'][0].update(name='compatibility', path='/etc/motd',
                                           type='file', purpose='generated message compatibility path')
        annotation['5bsd.state-requirements'] = json.dumps(document)
        self.policy = {'format': 3, 'entries': {
            '/etc/motd.template': dict(operation='create', source=str(self.source),
                sha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
                size=self.source.stat().st_size, uid=0, gid=0, mode=0o644, replaces=[]),
            '/etc/motd': dict(operation='alias', target='/state/motd',
                package='fixture', requirement='compatibility')}}

    def test_template_and_alias_partition_without_mutation(self):
        self.template_and_alias()
        plan = self.prepare()
        self.assertEqual(plan['records']['/etc/motd']['target'], '/state/motd')
        self.assertEqual(plan['records']['/etc/motd.template']['sha256'],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertFalse(plan['runtime_storage_authorized'])
        proposed = {**self.observed, **plan['records']}
        layout = c.generation.storage_layout(self.inventory, proposed,
            dict(format=1, boundaries=[dict(path='/state', content='ordinary')]))
        self.assertIn('/etc/motd', layout['immutable_objects'])
        self.assertIn('/etc/motd.template', layout['immutable_objects'])
        row, = layout['requirements']
        self.assertEqual(row['resolved_path'], '/state/motd')
        self.assertEqual(row['content'], 'ordinary')
        self.assertFalse(layout['runtime_authority_assigned'])
        self.assertEqual(list((self.root / 'etc').iterdir()), [])

    def test_template_and_alias_preserve_occupied_destinations(self):
        self.template_and_alias()
        for name in ('/etc/motd', '/etc/motd.template'):
            with self.subTest(path=name):
                target = self.root / name.lstrip('/')
                target.write_bytes(b'owner supplied legacy message')
                os.chflags(target, 0)
                self.observed = c.generation.scan(self.root)
                with self.assertRaisesRegex(ValueError, 'absent.*unowned'):
                    self.prepare()
                self.assertEqual(target.read_bytes(), b'owner supplied legacy message')
                target.unlink()

    def test_declared_directory_mapping_alias(self):
        import json
        self.alias()
        annotation = self.inventory['packages'][0]['manifest']['annotations']
        document = json.loads(annotation['5bsd.state-requirements'])
        document['format'] = 2
        document['requirements'][0].update(path='/fallback', type='directory',
                                           directory_mapping='/log')
        annotation['5bsd.state-requirements'] = json.dumps(document)
        self.observed['/state'] = {'type': 'directory'}
        self.observed['/state/log'] = {'type': 'directory'}
        plan = self.prepare()
        self.assertEqual(plan['records']['/log']['target'], '/state/log')
        self.assertFalse(plan['runtime_storage_authorized'])
        self.observed['/state/log'] = {'type': 'file'}
        with self.assertRaisesRegex(ValueError, 'target type'):
            self.prepare()

    def relocation(self):
        import json
        self.alias()
        annotation = self.inventory['packages'][0]['manifest']['annotations']
        document = json.loads(annotation['5bsd.state-requirements'])
        document['requirements'][0].update(path='/policy', type='file', lifetime='persistent')
        annotation['5bsd.state-requirements'] = json.dumps(document)
        self.policy = {'format': 4, 'entries': {'/policy': {'operation': 'relocate',
            'target': '/moved', 'package': 'fixture', 'requirement': 'socket'}}}

    def relocation_plan(self):
        return c.installations.prepare_relocations(self.inventory, self.observed,
            self.generated, self.policy, c._construction_context())

    def test_relocation_preserves_file_and_exact_package_replacement(self):
        self.relocation()
        self.assertEqual(self.prepare()['records'], {})
        plan = self.relocation_plan()
        self.assertEqual(plan['records']['/moved']['sha256'], self.observed['/policy']['sha256'])
        self.assertEqual(plan['records']['/moved']['mode'], self.observed['/policy']['mode'])
        self.assertEqual(plan['records']['/policy']['target'], '/moved')
        self.assertEqual(plan['records']['/policy']['replaces'], ['a' * 64])
        self.assertFalse(plan['runtime_storage_authorized'])
        self.assertFalse((self.root / 'moved').exists())
        self.assertFalse((self.root / 'policy').is_symlink())

    def test_relocation_rejects_unsafe_source_and_target(self):
        self.relocation()
        original = copy.deepcopy(self.observed['/policy'])
        for changes in ({'type': 'symlink'}, {'flags_set': 1}, {'mode': 0o755},
                        {'hardlinks': ['/policy', '/other']}):
            self.observed['/policy'] = dict(original, **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.relocation_plan()
        self.observed['/policy'] = original
        for target in ('/policy', '/daemon', '/missing/target', '/'):
            self.policy['entries']['/policy']['target'] = target
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.relocation_plan()

    def test_relocation_requires_declared_file_requirement(self):
        self.relocation()
        for key, value in (('package', 'foreign'), ('requirement', 'unknown')):
            original = self.policy['entries']['/policy'][key]
            self.policy['entries']['/policy'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'matching file'):
                self.prepare()
            self.policy['entries']['/policy'][key] = original

    @unittest.skipUnless(os.geteuid() == 0, 'real relocation requires builder VM')
    def test_constructor_relocates_and_reconciles(self):
        self.relocation()
        report = c.construct(self.root, self.inventory, self.generated,
            self.base / 'report', installation_policy=self.policy)
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual((self.root / 'moved').read_bytes(), b'package baseline')
        self.assertEqual(os.readlink(self.root / 'policy'), '/moved')
        self.assertFalse(report['installation_relocation']['runtime_storage_authorized'])
        helper = os.environ.get('BSD_BUILD_RETAINED_HELPER') or str(
            Path(__file__).resolve().parents[3] / 'tools/test/construction/verify_retained.py')
        spec = importlib.util.spec_from_file_location('retained_verifier', helper)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        generated, _ = c.generation.read_json(self.base / 'report/generated.json')
        objects = c.require_match(self.root, self.inventory, generated)
        checked = verifier.verify_relocations(self.root, c, self.inventory, self.generated,
            report, generated, objects, self.policy)
        self.assertEqual(checked['moves'], 1)
        self.assertFalse(checked['generation_authenticated'])

    @unittest.skipUnless(os.geteuid() == 0, 'real relocation requires builder VM')
    def test_interrupted_relocation_never_publishes_success(self):
        import json
        self.relocation()
        replace = os.replace
        def interrupt(source, target):
            if Path(source).name.startswith('.relocation-'):
                raise OSError('injected interruption after file move')
            return replace(source, target)
        with patch.object(c.installations.os, 'replace', side_effect=interrupt):
            with self.assertRaisesRegex(OSError, 'injected interruption'):
                c.construct(self.root, self.inventory, self.generated,
                    self.base / 'report', installation_policy=self.policy)
        self.assertEqual((self.root / 'moved').read_bytes(), b'package baseline')
        self.assertFalse((self.base / 'report/generated.json').exists())
        report = json.loads((self.base / 'report/construction.json').read_text())
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(list(self.root.glob('.relocation-*')), [])

    def test_alias_rejects_collisions_and_unknown_requirements(self):
        self.alias()
        for key, value in [('package', 'foreign'), ('requirement', 'unknown'),
                           ('target', '/log'), ('target', '../outside'), ('target', '/')]:
            saved = copy.deepcopy(self.policy)
            self.policy['entries']['/log'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.prepare()
            self.policy = saved
        self.observed['/log'] = {'type': 'file'}
        with self.assertRaisesRegex(ValueError, 'absent and unowned'): self.prepare()

    def test_alias_rejects_target_cycle_and_type_mismatch(self):
        self.alias()
        self.observed['/state'] = {'type': 'symlink', 'target': '/log'}
        with self.assertRaisesRegex(ValueError, 'alias chain'): self.prepare()
        self.observed['/state'] = {'type': 'directory'}
        self.observed['/state/log'] = {'type': 'file'}
        with self.assertRaisesRegex(ValueError, 'target type'): self.prepare()

    def test_generator_cannot_opt_into_symlink_output(self):
        self.alias()
        (self.root / 'log').symlink_to('/state/log')
        record = {'type': 'symlink', 'target': '/state/log'}
        with self.assertRaisesRegex(ValueError, 'regular file'):
            c.finalize_outputs(self.root, {'outputs': {'/log': record}},
                               self.observed, c.generation.scan(self.root))

    def test_alias_metadata_requires_matching_link_before_mutation(self):
        self.alias()
        record = self.prepare()['records']['/log']
        for actual in ({'type': 'file'}, {'type': 'symlink', 'target': '/elsewhere'}):
            with self.subTest(actual=actual), patch.object(c.os, 'chown') as chown:
                with self.assertRaisesRegex(ValueError, 'alias changed'):
                    c.finalize_outputs(self.root, {'outputs': {'/log': record}},
                        self.observed, {**self.observed, '/log': actual}, allow_aliases=True)
                chown.assert_not_called()

    @unittest.skipUnless(os.geteuid()==0, 'real root alias installation requires builder VM')
    def test_constructor_installs_declared_alias(self):
        self.alias()
        baseline = copy.deepcopy(self.inventory)
        report = c.construct(self.root, self.inventory, self.generated,
            self.base/'report', installation_policy=self.policy)
        self.assertEqual(report['result'], 'PASS')
        link = self.root / 'log'
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), '/state/log')
        self.assertEqual(link.lstat().st_uid, 0)
        self.assertEqual(link.lstat().st_mode & 0o7777, 0o777)
        self.assertEqual(self.inventory, baseline)
        self.assertFalse(report['installation_configuration']['runtime_storage_authorized'])

    def test_explicit_input_preserves_package_baseline(self):
        before=copy.deepcopy(self.inventory)
        plan=self.prepare()
        self.assertEqual(before,self.inventory)
        self.assertFalse(plan['runtime_storage_authorized'])
        self.assertFalse(plan['inputs_authenticated'])
        self.assertEqual(plan['records']['/policy']['sha256'],self.policy['entries']['/policy']['sha256'])
        self.assertEqual(self.target.read_bytes(),b'package baseline')

    def test_package_membership_is_required(self):
        self.inventory['packages'][0]['config']=[]
        with self.assertRaisesRegex(ValueError,'configuration owner'):self.prepare()

    def test_exact_package_provenance(self):
        for owners in ([],['b'*64],['a'*64,'a'*64]):
            self.policy['entries']['/policy']['replaces']=owners
            with self.assertRaises(ValueError):self.prepare()

    def creation(self):
        self.policy['format'] = 2
        item = self.policy['entries'].pop('/policy')
        item.update(operation='create', replaces=[])
        self.policy['entries']['/site.conf'] = item
        return item

    def test_explicit_creation(self):
        self.creation()
        plan = self.prepare()
        self.assertEqual(plan['records']['/site.conf']['replaces'], [])
        self.assertFalse((self.root/'site.conf').exists())
        self.assertFalse(plan['runtime_storage_authorized'])

    def test_creation_cannot_replace_existing_object(self):
        self.creation()
        self.policy['entries']['/policy'] = self.policy['entries'].pop('/site.conf')
        with self.assertRaisesRegex(ValueError, 'absent unowned'): self.prepare()

    def test_creation_cannot_claim_package_or_generator_output(self):
        item = self.creation()
        item['replaces'] = ['a'*64]
        with self.assertRaisesRegex(ValueError, 'absent unowned'): self.prepare()
        item['replaces'] = []
        self.inventory['construction']['actions'] = [dict(outputs={'/site.conf': {}})]
        with self.assertRaisesRegex(ValueError, 'conflicts'): self.prepare()

    def test_creation_requires_declared_parent(self):
        self.creation()
        self.policy['entries']['/missing/site.conf'] = self.policy['entries'].pop('/site.conf')
        with self.assertRaisesRegex(ValueError, 'parent'): self.prepare()

    def test_operation_is_explicit_in_format_two(self):
        self.policy['format'] = 2
        with self.assertRaisesRegex(ValueError, 'fields'): self.prepare()
        self.policy['entries']['/policy']['operation'] = 'replace'
        self.prepare()
        self.policy['entries']['/policy']['operation'] = 'anything'
        with self.assertRaisesRegex(ValueError, 'operation'): self.prepare()

    @unittest.skipUnless(os.geteuid()==0, 'real root installation requires builder VM')
    def test_constructor_creates_and_reconciles(self):
        self.creation()
        report = c.construct(self.root,self.inventory,self.generated,self.base/'report',installation_policy=self.policy)
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual((self.root/'site.conf').read_bytes(), self.source.read_bytes())
        self.assertEqual((self.root/'site.conf').stat().st_mode & 0o7777, 0o600)

    def test_planned_generator_collision_precedes_installation(self):
        self.creation()
        for helper, option in ((c.modules, 'module_policy'), (c.libraries, 'library_policy')):
            with self.subTest(option=option):
                plan = {'actions': [{'outputs': {'/site.conf': {}}}]}
                with patch.object(helper, 'prepare', return_value=plan), \
                        patch.object(c.installations, 'install') as install:
                    with self.assertRaisesRegex(ValueError, 'planned generator output'):
                        c.construct(self.root,self.inventory,self.generated,self.base/'report',
                            installation_policy=self.policy, **{option: {}})
                    install.assert_not_called()
                    self.assertFalse((self.base/'report').exists())
                    self.assertFalse((self.root/'site.conf').exists())

    def test_changed_source(self):
        self.source.write_bytes(b'different bytes')
        with self.assertRaisesRegex(ValueError,'size/hash'):self.prepare()

    def test_symlink_and_fifo_sources(self):
        for kind in ('symlink','fifo'):
            bad=self.base / kind
            if kind=='symlink':bad.symlink_to(self.source)
            else:os.mkfifo(bad)
            self.policy['entries']['/policy']['source']=str(bad)
            with self.assertRaises(ValueError):self.prepare()

    def test_source_inside_candidate(self):
        self.policy['entries']['/policy']['source']=str(self.target)
        with self.assertRaisesRegex(ValueError,'outside candidate'):self.prepare()

    def test_destination_alias_flags_and_parent(self):
        original=copy.deepcopy(self.observed)
        for field,value in (('type','symlink'),('hardlinks',['/policy','/other']),('flags_set',1)):
            self.observed=copy.deepcopy(original);self.observed['/policy'][field]=value
            with self.assertRaisesRegex(ValueError,'unaliased'):self.prepare()
        self.observed=copy.deepcopy(original);self.observed['/']['type']='symlink'
        with self.assertRaisesRegex(ValueError,'parent'):self.prepare()

    def test_unsafe_metadata(self):
        item=self.policy['entries']['/policy']
        for mode in (0o666,0o755,0o4600):
            item['mode']=mode
            with self.assertRaisesRegex(ValueError,'nonexecutable'):self.prepare()
        item['mode']=0o600;item['uid']=1001
        with self.assertRaisesRegex(ValueError,'root-owned'):self.prepare()

    def test_generator_conflict(self):
        self.inventory['construction']['actions']=[dict(outputs={'/policy':{}})]
        with self.assertRaisesRegex(ValueError,'conflicts'):self.prepare()

    def test_existing_generated_conflict(self):
        self.generated['entries']['/policy']={}
        with self.assertRaisesRegex(ValueError,'conflicts'):self.prepare()

    @unittest.skipUnless(os.geteuid()==0,'real root installation is qualified in the builder VM')
    def test_constructor_installs_and_records_replacement(self):
        baseline=copy.deepcopy(self.inventory)
        report=c.construct(self.root,self.inventory,self.generated,self.base/'report',installation_policy=self.policy)
        self.assertEqual(report['result'],'PASS')
        self.assertEqual(self.target.read_bytes(),self.source.read_bytes())
        self.assertEqual(self.target.stat().st_mode & 0o7777,0o600)
        self.assertEqual(self.inventory,baseline)
        self.assertEqual(report['installation_configuration']['policy_sha256'],c.digest(self.policy))
        self.assertTrue((self.base/'report/generated.json').is_file())

    def test_preflight_failure_keeps_baseline_and_creates_no_report(self):
        self.source.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            c.construct(self.root,self.inventory,self.generated,self.base/'report',installation_policy=self.policy)
        self.assertEqual(self.target.read_bytes(),b'package baseline')
        self.assertFalse((self.base/'report/generated.json').exists())
        self.assertFalse((self.base/'report').exists())

    @unittest.skipUnless(os.geteuid()==0,'real root installation is qualified in the builder VM')
    def test_input_changed_after_preflight_records_failure(self):
        original_install = c.installations.install
        def changed_input(*args, **kwargs):
            self.source.write_bytes(b'changed after preflight')
            return original_install(*args, **kwargs)
        with patch.object(c.installations, 'install', side_effect=changed_input):
            with self.assertRaises(ValueError):
                c.construct(self.root,self.inventory,self.generated,self.base/'report',installation_policy=self.policy)
        self.assertEqual(self.target.read_bytes(), b'package baseline')
        self.assertFalse((self.base/'report/generated.json').exists())
        import json
        self.assertEqual(json.loads((self.base/'report/construction.json').read_text())['result'],'FAIL')


if __name__=='__main__':unittest.main()
