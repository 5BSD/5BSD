# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

helper = os.environ.get('BSD_BUILD_GENERATION_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/generation_check.py')
spec = importlib.util.spec_from_file_location('generation_check', helper)
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)


class ExpectedTopology(unittest.TestCase):
    def objects(self, parent_type, root_type='directory'):
        def item(kind):
            result = dict(type=kind, uid=0, gid=0, mode=0o755, flags_set=0,
                          source='explicit topology fixture', replaces=[])
            if kind == 'symlink':
                result['target'] = '/elsewhere'
            if kind == 'file':
                result.update(size=0, sha256=hashlib.sha256(b'').hexdigest())
            return result
        return {'format': 1, 'entries': {
            '/': item(root_type), '/state': item(parent_type),
            '/state/record': item('file')}}

    def check(self, generated):
        return generation.expected_objects({'format': 1,
            'scope': 'package-payload-inventory', 'packages': []}, generated)

    def test_rejects_declared_non_directory_ancestor(self):
        for kind in ('file', 'symlink'):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'non-directory ancestor'):
                self.check(self.objects(kind))

    def test_root_must_be_directory_even_without_children(self):
        for kind in ('file', 'symlink'):
            generated = self.objects('directory', root_type=kind)
            generated['entries'] = {'/': generated['entries']['/']}
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'root.*directory'):
                self.check(generated)

    def test_leaf_alias_is_not_a_directory_conflict(self):
        generated = self.objects('directory')
        generated['entries']['/alias'] = dict(generated['entries']['/state'],
            type='symlink', target='/state')
        self.assertEqual(self.check(generated)['/alias']['target'], '/state')


class StateAliasReview(unittest.TestCase):
    def setUp(self):
        self.tree = {'/': {'type': 'directory'}, '/run': {'type': 'directory'},
            '/state': {'type': 'directory'}, '/state/service': {'type': 'directory'},
            '/state/log': {'type': 'socket'}, '/run/log': {'type': 'symlink', 'target': '../state/log'}}

    def test_relative_and_absolute_links(self):
        for target in ('../state/log', '/state/log'):
            self.tree['/run/log']['target'] = target
            row = generation.state_alias_review('/run/log', self.tree)
            self.assertEqual('resolved', row['status'])
            self.assertEqual('/state/log', row['resolved_path'])
            self.assertEqual('socket', row['resolved_type'])
            self.assertEqual([{'path': '/run/log', 'target': target}], row['links'])

    def test_parent_is_processed_after_link(self):
        self.tree['/run/alias'] = {'type': 'symlink', 'target': '/state/service'}
        self.tree['/run/log']['target'] = 'alias/../log'
        row = generation.state_alias_review('/run/log', self.tree)
        self.assertEqual('/state/log', row['resolved_path'])
        self.assertEqual('resolved', row['status'])
        self.assertEqual(2, len(row['links']))

    def test_cycles_expansion_and_root_escape(self):
        for target in ('log', '/run/log', '/run/log/child'):
            self.tree['/run/log']['target'] = target
            self.assertEqual('cycle-or-limit', generation.state_alias_review('/run/log', self.tree)['status'])
        self.tree['/run/log']['target'] = '../../outside'
        self.assertEqual('above-root', generation.state_alias_review('/run/log', self.tree)['status'])

    def test_missing_runtime_target_is_not_host_lookup(self):
        self.tree['/run/log']['target'] = '/etc/passwd'
        row = generation.state_alias_review('/run/log', self.tree)
        self.assertEqual('missing', row['status'])
        self.assertEqual('/etc', row['resolved_path'])
        self.assertEqual(['passwd'], row['remaining_components'])

    def test_non_directory_and_trailing_slash(self):
        for target in ('/state/log/child', '/state/log/'):
            self.tree['/run/log']['target'] = target
            self.assertEqual('non-directory', generation.state_alias_review('/run/log', self.tree)['status'])


class ImmutableCodeReferences(unittest.TestCase):
    def setUp(self):
        self.observed = {'/': dict(type='directory'), '/lib': dict(type='directory'),
            '/lib/loader': dict(type='file', sha256='a' * 64),
            '/interp': dict(type='symlink', target='/lib/loader')}
        self.layout = dict(immutable_objects=list(self.observed))

    def resolve(self, path='/interp'):
        return generation.immutable_code_reference(path, self.observed, self.layout)

    def test_candidate_alias_and_digest(self):
        result = self.resolve()
        self.assertEqual(result['resolved_path'], '/lib/loader')
        self.assertEqual(result['sha256'], 'a' * 64)
        self.assertEqual(result['links'], [dict(path='/interp', target='/lib/loader')])

    def test_each_lookup_component_must_be_immutable(self):
        for path in self.observed:
            with self.subTest(path=path):
                self.layout['immutable_objects'] = [p for p in self.observed if p != path]
                with self.assertRaisesRegex(ValueError, 'mutable storage'):
                    self.resolve()

    def test_missing_cycle_and_nonfile_fail(self):
        for target in ('/missing', '/interp', '/lib'):
            with self.subTest(target=target):
                self.observed['/interp']['target'] = target
                with self.assertRaisesRegex(ValueError, 'not a resolved file'):
                    self.resolve()

    def test_mutable_hardlink_fails(self):
        self.observed['/lib/loader']['hardlinks'] = ['/lib/loader', '/state/copy']
        with self.assertRaisesRegex(ValueError, 'mutable storage'):
            self.resolve()

    def test_link_parent_lookup_cannot_hide_mutable_traversal(self):
        self.observed['/state'] = dict(type='directory')
        self.observed['/state/link'] = dict(type='symlink', target='/lib')
        self.observed['/interp']['target'] = '/state/link/../lib/loader'
        with self.assertRaisesRegex(ValueError, 'mutable storage'):
            self.resolve()


class Reconciliation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o755)
        os.chown(self.root, os.getuid(), os.getgid())
        self.archive_hash = 'a' * 64
        self.package = {'name': 'sample-system', 'archive_sha256': self.archive_hash,
                        'entries': {}, 'directories': {}}
        self.inventory = {'format': 1, 'scope': 'package-payload-inventory',
                          'packages': [self.package]}
        self.generated = {'format': 1, 'entries': {'/': self.directory_input()}}

    def directory_input(self):
        return {'type': 'directory', 'uid': os.getuid(), 'gid': os.getgid(),
                'mode': 0o755, 'flags_set': 0, 'source': 'fixture layout', 'replaces': []}

    def file(self, path, data=b'package payload', named=False):
        target = self.root / path.lstrip('/')
        target.write_bytes(data)
        target.chmod(0o644)
        os.utime(target, ns=(1700000000000000000, 1700000000000000000))
        item = {'type': 'file', 'uid': os.getuid(), 'gid': os.getgid(),
                'mode': 0o644, 'flags_set': 0, 'mtime': 1700000000, 'mtime_nsec': 0,
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if named:
            item.update(uid=65534, gid=65534, uname='generation-owner', gname='generation-group')
        self.package['entries'][path] = item
        return target

    def clear_fixture_archive_flags(self):
        # ZFS sets UF_ARCHIVE on creation/modification. Prepare explicit fixture
        # metadata; the production checker neither clears nor ignores flags.
        for path in [self.root, *self.root.rglob('*')]:
            if not path.is_symlink() and path.stat().st_flags:
                os.chflags(path, 0)

    def run_check(self):
        self.clear_fixture_archive_flags()
        return generation.reconcile(self.root, self.inventory, self.generated)

    def code_policy(self, data=b'#!/bin/sh\nexit 0\n'):
        self.file('/consumer', data)
        self.file('/policy', b'policy')
        return dict(format=2, boundaries=[], protected_consumers=[dict(
            consumer='/consumer', package_archive_sha256=self.archive_hash,
            inputs=[dict(path='/policy', presence='required')])])

    def reconcile_code(self, policy):
        self.clear_fixture_archive_flags()
        return generation.reconcile(self.root, self.inventory, self.generated, policy)

    def test_consumer_code_metadata_bound_to_real_elf(self):
        source = self.base / 'consumer.c'
        source.write_text('int main(void) { return 0; }\n')
        binary = self.base / 'consumer'
        subprocess.run(['cc', str(source), '-Wl,-rpath,/selected/library', '-Wl,--dynamic-linker,/interpreter',
                        '-o', str(binary)], check=True, capture_output=True)
        # The dependency binding checks reconciled placement and bytes, not
        # whether this fixture object implements the interpreter ABI.
        self.file('/interpreter', binary.read_bytes())
        result = self.reconcile_code(self.code_policy(binary.read_bytes()))
        code = result['protected_consumer_code']
        row = code['consumers'][0]
        self.assertEqual(row['sha256'], self.package['entries']['/consumer']['sha256'])
        self.assertEqual(row['package_archive_sha256'], self.archive_hash)
        self.assertEqual(row['kind'], 'elf')
        self.assertIn('/selected/library', (row['metadata']['rpath'], row['metadata']['runpath']))
        self.assertTrue(row['metadata']['needed'])
        self.assertEqual(row['interpreter_reference']['resolved_path'], '/interpreter')
        self.assertEqual(row['interpreter_reference']['sha256'],
                         self.package['entries']['/interpreter']['sha256'])
        self.assertFalse(code['dependency_coverage_complete'])
        self.assertFalse(code['runtime_enforcement_verified'])
        (self.root / 'interpreter').unlink()
        del self.package['entries']['/interpreter']
        with self.assertRaisesRegex(ValueError, 'code reference is not a resolved file'):
            self.reconcile_code(self.code_policy(binary.read_bytes()))

    def test_declared_bip_image_is_required_before_reconciliation_succeeds(self):
        source = self.base / 'manager.c'; binary = self.base / 'manager'
        source.write_text('int main(void) { return 0; }\n')
        subprocess.run(['cc', str(source), '-Wl,--dynamic-linker,/interpreter',
                        '-o', str(binary)], check=True, capture_output=True)
        elf = generation.elf_inspector()
        metadata = elf.inspect(binary.read_bytes())
        target = {key: metadata[key] for key in ('elf_class', 'byte_order', 'machine')}
        target['page_size'] = os.sysconf('SC_PAGE_SIZE')
        def policy(data):
            self.file('/interpreter', data)
            value = self.code_policy(data)
            value.update(format=3, target_elf=target)
            value['protected_consumers'][0]['code_loading'] = 'bip'
            return value
        with self.assertRaisesRegex(ValueError, 'restrictive feature note'):
            self.reconcile_code(policy(binary.read_bytes()))
        subprocess.run([os.environ.get('BSD_BUILD_ELFCTL', 'elfctl'), '-e', '+biprestrict',
                        str(binary)], check=True, capture_output=True)
        selected = policy(binary.read_bytes())
        result = self.reconcile_code(selected)['protected_consumer_code']
        admission = result['consumers'][0]['bip_image_admission']
        self.assertTrue(admission['metadata_valid'])
        self.assertEqual(admission['target'], target)
        self.assertFalse(admission['runtime_enforcement_verified'])
        self.assertFalse(result['configured_manager_coverage_complete'])
        wrong = copy.deepcopy(selected); wrong['target_elf']['machine'] ^= 1
        with self.assertRaisesRegex(ValueError, 'target ELF profile'):
            self.reconcile_code(wrong)
        for profile in ({}, {**target, 'page_size': True}, {**target, 'page_size': 12345},
                        {**target, 'extra': 1}):
            wrong = copy.deepcopy(selected); wrong['target_elf'] = profile
            with self.assertRaisesRegex(ValueError, 'target ELF profile'):
                self.reconcile_code(wrong)
        wrong = copy.deepcopy(selected); wrong['protected_consumers'][0]['code_loading'] = 'signed'
        with self.assertRaisesRegex(ValueError, 'code-loading requirement'):
            self.reconcile_code(wrong)
        with self.assertRaisesRegex(ValueError, 'requires native ELF'):
            self.reconcile_code(policy(b'#!/bin/sh\nexit 0\n'))

    def test_consumer_nonelf_not_reported_as_complete(self):
        result = self.reconcile_code(self.code_policy())['protected_consumer_code']
        self.assertEqual(result['consumers'][0]['kind'], 'non-elf')
        self.assertIsNone(result['consumers'][0]['metadata'])
        self.assertFalse(result['dependency_coverage_complete'])

    def test_declared_consumer_malformed_elf_fails(self):
        with self.assertRaisesRegex(ValueError, 'not an ELF object'):
            self.reconcile_code(self.code_policy(b'\x7fELFtruncated'))

    def test_consumer_changed_after_scan_rejected(self):
        policy = self.code_policy()
        observed = generation.scan(self.root)
        layout = generation.storage_layout(self.inventory, observed, policy)
        target = self.root / 'consumer'
        for substitute in ('bytes', 'symlink', 'fifo'):
            with self.subTest(substitute=substitute):
                target.unlink()
                if substitute == 'bytes':
                    target.write_bytes(b'x' * observed['/consumer']['size'])
                elif substitute == 'symlink':
                    target.symlink_to(self.root / 'policy')
                else:
                    os.mkfifo(target)
                with self.assertRaises((OSError, ValueError)):
                    generation.protected_consumer_code(self.root, observed, layout)

    def test_exact_tree_passes_without_claiming_authentication(self):
        self.file('/program')
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        self.assertFalse(result['inputs_authenticated'])
        self.assertFalse(result['generation_authenticated'])
        self.assertFalse(result['bip_policy_applied'])

    def declared_consumer(self):
        program = self.file('/program', b'original executable')
        program.chmod(0o755)
        self.package['entries']['/program']['mode'] = 0o755
        requirement = {'name': 'records', 'program': '/program',
            'path': '/var/records', 'type': 'directory',
            'lifetime': 'persistent', 'purpose': 'service records'}
        self.package['manifest'] = {'annotations': {
            '5bsd.state-requirements': json.dumps({'format': 1,
                'requirements': [requirement]})}}
        return program

    def generated_consumer(self, item):
        self.generated['entries']['/program'] = dict(item, uid=os.getuid(),
            gid=os.getgid(), flags_set=0, source='explicit replacement fixture',
            replaces=[self.archive_hash])

    def test_state_consumer_matches_completed_payload_without_authority(self):
        self.declared_consumer()
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        binding, = result['state_consumer_bindings']
        self.assertTrue(binding['payload_matches'])
        self.assertFalse(binding['authority_assigned'])
        self.assertFalse(result['bip_policy_applied'])

    def test_state_consumer_hardlink_matches_completed_bytes(self):
        self.declared_consumer()
        os.link(self.root / 'program', self.root / 'alias')
        self.package['entries']['/alias'] = dict(
            self.package['entries']['/program'], type='hardlink', target='/program')
        annotation = self.package['manifest']['annotations']
        declaration = json.loads(annotation['5bsd.state-requirements'])
        declaration['requirements'][0]['program'] = '/alias'
        annotation['5bsd.state-requirements'] = json.dumps(declaration)
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        self.assertTrue(result['state_consumer_bindings'][0]['payload_matches'])

    def test_generated_replacement_cannot_inherit_state_declaration(self):
        program = self.declared_consumer()
        data = b'different executable'
        program.write_bytes(data)
        self.generated_consumer({'type': 'file', 'mode': 0o755,
            'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        result = self.run_check()
        self.assertEqual(result['result'], 'FAIL')
        self.assertEqual([d['reason'] for d in result['differences']],
            ['state-consumer-binding'])

    def test_nonexecutable_replacement_cannot_satisfy_state_consumer(self):
        program = self.declared_consumer()
        data = program.read_bytes()
        program.chmod(0o644)
        self.generated_consumer({'type': 'file', 'mode': 0o644,
            'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        result = self.run_check()
        self.assertEqual([d['reason'] for d in result['differences']],
            ['state-consumer-binding'])

    def test_symlink_replacement_cannot_satisfy_state_consumer(self):
        program = self.declared_consumer()
        self.file('/target', program.read_bytes()).chmod(0o755)
        self.package['entries']['/target']['mode'] = 0o755
        program.unlink()
        program.symlink_to('target')
        self.generated_consumer({'type': 'symlink', 'mode': 0o755,
            'target': 'target'})
        # Symlink permissions are platform metadata, not the target's mode.
        metadata = program.lstat()
        self.generated['entries']['/program']['mode'] = metadata.st_mode & 0o7777
        self.generated['entries']['/program']['flags_set'] = metadata.st_flags
        result = self.run_check()
        self.assertEqual([d['reason'] for d in result['differences']],
            ['state-consumer-binding'])

    def state_directory(self, name):
        (self.root / name.lstrip('/')).mkdir(mode=0o755)
        self.generated['entries'][name] = self.directory_input()

    def state_row(self, result):
        review = result['state_layout_review']
        self.assertEqual(review['scope'], 'observed-generation-state-layout')
        self.assertFalse(review['authority_assigned'])
        self.assertFalse(review['mount_coverage_approved'])
        row, = review['requirements']
        return row

    def test_state_layout_reports_missing_components(self):
        self.declared_consumer()
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        row = self.state_row(result)
        self.assertEqual((row['resolution'], row['first_missing_component'],
                          row['nearest_existing_directory']), ('missing', '/var', '/'))
        self.state_directory('/var')
        row = self.state_row(self.run_check())
        self.assertEqual((row['first_missing_component'], row['nearest_existing_directory']),
                         ('/var/records', '/var'))
        self.assertEqual(row['covered_objects'], [])

    def test_state_layout_maps_contents_and_crossing_hardlinks(self):
        self.declared_consumer()
        self.state_directory('/var')
        self.state_directory('/var/records')
        self.file('/var/records/data')
        self.file('/var/records-other')
        os.link(self.root / 'var/records/data', self.root / 'outside')
        self.package['entries']['/outside'] = dict(
            self.package['entries']['/var/records/data'], type='hardlink',
            target='/var/records/data')
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        row = self.state_row(result)
        self.assertEqual(row['resolution'], 'existing')
        self.assertEqual(row['covered_objects'], ['/var/records', '/var/records/data'])
        self.assertEqual(row['cross_boundary_hardlinks'],
                         {'/var/records/data': ['/outside']})
        self.assertEqual(row['policy_review'], 'required')

    def test_state_layout_does_not_follow_symlink_ancestor(self):
        self.declared_consumer()
        self.state_directory('/other')
        self.state_directory('/other/records')
        (self.root / 'var').symlink_to('other')
        meta = (self.root / 'var').lstat()
        self.generated['entries']['/var'] = dict(type='symlink', target='other',
            uid=meta.st_uid, gid=meta.st_gid, mode=meta.st_mode & 0o7777,
            flags_set=meta.st_flags, source='explicit alias fixture', replaces=[])
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        row = self.state_row(result)
        self.assertEqual(row['resolution'], 'blocked-ancestor')
        self.assertEqual(row['blocked_ancestor'], '/var')
        self.assertIsNone(row['observed_object'])
        self.assertEqual(row['covered_objects'], [])
        self.assertEqual(row['alias_review']['status'], 'resolved')
        self.assertEqual(row['alias_review']['resolved_path'], '/other/records')
        self.assertEqual(row['alias_review']['links'], [{'path': '/var', 'target': 'other'}])
        self.assertFalse(result['state_layout_review']['authority_assigned'])
        self.assertFalse(result['state_layout_review']['mount_coverage_approved'])

    def test_state_layout_reports_file_ancestor_and_leaf_mismatch(self):
        self.declared_consumer()
        self.file('/var')
        row = self.state_row(self.run_check())
        self.assertEqual((row['resolution'], row['blocked_ancestor']),
                         ('blocked-ancestor', '/var'))
        (self.root / 'var').unlink()
        del self.package['entries']['/var']
        self.state_directory('/var')
        self.file('/var/records')
        row = self.state_row(self.run_check())
        self.assertEqual(row['resolution'], 'type-mismatch')
        self.assertEqual(row['observed_object'], '/var/records')
        self.assertEqual(row['covered_objects'], [])

    def test_file_state_reports_alias_outside_its_boundary(self):
        self.declared_consumer()
        self.state_directory('/var')
        self.file('/var/records')
        os.link(self.root / 'var/records', self.root / 'alias')
        self.package['entries']['/alias'] = dict(
            self.package['entries']['/var/records'], type='hardlink', target='/var/records')
        annotation = self.package['manifest']['annotations']
        declaration = json.loads(annotation['5bsd.state-requirements'])
        declaration['requirements'][0]['type'] = 'file'
        annotation['5bsd.state-requirements'] = json.dumps(declaration)
        result = self.run_check()
        self.assertEqual(result['result'], 'PASS')
        row = self.state_row(result)
        self.assertEqual(row['covered_objects'], ['/var/records'])
        self.assertEqual(row['cross_boundary_hardlinks'], {'/var/records': ['/alias']})

    def test_no_state_declarations_infers_no_writable_paths(self):
        self.file('/program')
        review = self.run_check()['state_layout_review']
        self.assertEqual(review['requirements'], [])
        self.assertFalse(review['authority_assigned'])

    def layout_fixture(self):
        self.declared_consumer()
        self.state_directory('/var')
        self.state_directory('/var/records')
        self.file('/var/records/seed')
        self.clear_fixture_archive_flags()
        return {'format': 1, 'boundaries': [{'path': '/var/records', 'content': 'ordinary'}]}

    def layout_check(self, policy):
        self.clear_fixture_archive_flags()
        return generation.reconcile(self.root, self.inventory, self.generated, policy)

    def mapping_declaration(self, **changes):
        annotation = self.package['manifest']['annotations']
        declaration = json.loads(annotation['5bsd.state-requirements'])
        declaration['format'] = 2
        declaration['requirements'][0]['directory_mapping'] = '/route'
        declaration['requirements'][0].update(changes)
        annotation['5bsd.state-requirements'] = json.dumps(declaration)

    def mapping_alias(self, target):
        (self.root / 'route').symlink_to(target)
        item = (self.root / 'route').lstat()
        self.package['entries']['/route'] = dict(type='symlink', target=target,
            uid=item.st_uid, gid=item.st_gid, mode=item.st_mode & 0o7777,
            flags_set=item.st_flags)

    def test_directory_mapping_is_selected_from_reconciled_objects(self):
        policy = self.layout_fixture()
        self.mapping_declaration()
        result = self.layout_check(policy)
        self.assertEqual(result['storage_layout']['requirements'][0]['selected_path'], '/var/records')
        self.mapping_alias('/var/records')
        result = self.layout_check(policy)
        row, = result['storage_layout']['requirements']
        self.assertEqual(row['path'], '/var/records')
        self.assertEqual(row['selected_path'], '/route')
        self.assertEqual(row['resolved_path'], '/var/records')
        self.assertEqual(row['boundary'], '/var/records')
        review, = result['state_layout_review']['requirements']
        self.assertEqual(review['selected_path'], '/route')
        self.assertFalse(result['storage_layout']['runtime_authority_assigned'])
        with self.assertRaisesRegex(ValueError, 'lacks a writable boundary'):
            self.layout_check({'format': 1, 'boundaries': []})

    def test_present_directory_mapping_never_falls_back(self):
        policy = self.layout_fixture()
        self.mapping_declaration()
        for target in ('/missing', '/route', '/var/records/seed'):
            self.mapping_alias(target)
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'invalid present'):
                self.layout_check(policy)
            (self.root / 'route').unlink()
        del self.package['entries']['/route']
        self.file('/route')
        with self.assertRaisesRegex(ValueError, 'invalid present'):
            self.layout_check(policy)

    def test_directory_mapping_schema_cannot_change_file_requirements(self):
        self.layout_fixture()
        for changes in ({'type': 'file'}, {'directory_mapping': '/'},
                        {'directory_mapping': '/var/records'},
                        {'directory_mapping': '/var/../route'},
                        {'directory_mapping': None}):
            self.mapping_declaration(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                generation.pkg.state_requirements([self.package])
            self.mapping_declaration(type='directory')
        annotation = self.package['manifest']['annotations']
        document = json.loads(annotation['5bsd.state-requirements'])
        document['format'] = 1
        annotation['5bsd.state-requirements'] = json.dumps(document)
        with self.assertRaisesRegex(ValueError, 'fields'):
            generation.pkg.state_requirements([self.package])

    def protected_mapping_fixture(self):
        policy = self.layout_fixture()
        self.state_directory('/protected-records')
        policy['boundaries'].append({'path': '/protected-records', 'content': 'protected'})
        self.mapping_declaration()
        return policy

    def test_protected_state_rejects_ordinary_mapping_alias(self):
        policy = self.protected_mapping_fixture()
        self.configuration_alias('/var/records/relay', '/protected-records')
        self.mapping_alias('/var/records/relay')
        with self.assertRaisesRegex(ValueError, 'protected state traverses ordinary'):
            self.layout_check(policy)

    def test_protected_state_rejects_ordinary_directory_before_dotdot(self):
        policy = self.protected_mapping_fixture()
        self.state_directory('/var/records/child')
        self.mapping_alias('/var/records/child/../../../protected-records')
        with self.assertRaisesRegex(ValueError, 'protected state traverses ordinary'):
            self.layout_check(policy)

    def test_protected_state_rejects_absent_ordinary_mapping(self):
        policy = self.protected_mapping_fixture()
        self.mapping_declaration(path='/protected-records',
                                 directory_mapping='/var/records/route')
        with self.assertRaisesRegex(ValueError, 'protected state traverses ordinary'):
            self.layout_check(policy)

    def test_protected_state_accepts_absent_immutable_mapping(self):
        policy = self.protected_mapping_fixture()
        self.mapping_declaration(path='/protected-records')
        result = self.layout_check(policy)
        self.assertEqual(result['result'], 'PASS')
        row, = result['storage_layout']['requirements']
        self.assertEqual(row['content'], 'protected')
        self.assertEqual(row['resolved_path'], '/protected-records')

    def test_protected_state_accepts_immutable_mapping_alias(self):
        policy = self.protected_mapping_fixture()
        self.mapping_alias('/protected-records')
        result = self.layout_check(policy)
        self.assertEqual(result['result'], 'PASS')
        row, = result['storage_layout']['requirements']
        self.assertEqual(row['content'], 'protected')
        self.assertEqual(row['resolved_path'], '/protected-records')
        self.assertFalse(result['storage_layout']['runtime_authority_assigned'])

    def test_storage_layout_preserves_seed_and_assigns_requirements(self):
        policy = self.layout_fixture()
        result = self.layout_check(policy)
        layout = result['storage_layout']
        self.assertEqual(result['result'], 'PASS')
        self.assertIn('/program', layout['immutable_objects'])
        self.assertNotIn('/var/records/seed', layout['immutable_objects'])
        self.assertEqual(layout['boundaries'][0]['seed_objects']['/var/records/seed'],
                         result['objects']['/var/records/seed'])
        self.assertEqual(layout['requirements'][0]['boundary'], '/var/records')
        for key in ('runtime_authority_assigned', 'seed_installed', 'attachments_constructed'):
            self.assertFalse(layout[key])

    def test_storage_layout_rejects_overlap_alias_and_missing_root(self):
        policy = self.layout_fixture()
        for path in ('/', '/var', '/var/records'):
            other = copy.deepcopy(policy)
            other['boundaries'].append({'path': path, 'content': 'protected'})
            with self.assertRaises(ValueError):
                self.layout_check(other)
        policy['boundaries'][0]['path'] = '/missing'
        with self.assertRaisesRegex(ValueError, 'physical existing'):
            self.layout_check(policy)

    def test_storage_layout_allows_ordinary_config_alias(self):
        policy = self.layout_fixture()
        (self.root / 'configuration').symlink_to('/var/records/seed')
        self.package['entries']['/configuration'] = dict(type='symlink',
            target='/var/records/seed', uid=os.getuid(), gid=os.getgid(),
            mode=0o755, flags_set=0)
        self.package['entries']['/configuration']['mode'] = (self.root / 'configuration').lstat().st_mode & 0o7777
        self.package['entries']['/configuration']['flags_set'] = (self.root / 'configuration').lstat().st_flags
        self.package['config'] = ['/configuration']
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')

    def configuration_alias(self, path, target):
        alias = self.root / path.lstrip('/')
        alias.symlink_to(target)
        item = alias.lstat()
        self.package['entries'][path] = dict(type='symlink', target=target,
            uid=item.st_uid, gid=item.st_gid, mode=item.st_mode & 0o7777,
            flags_set=item.st_flags)

    def test_storage_config_allows_ordinary_intermediate_alias(self):
        policy = self.layout_fixture()
        self.file('/immutable-config')
        self.configuration_alias('/var/records/route', '/immutable-config')
        self.configuration_alias('/configuration', '/var/records/route')
        self.package['config'] = ['/configuration']
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')

    def test_storage_config_allows_ordinary_directory_before_dotdot(self):
        policy = self.layout_fixture()
        self.file('/immutable-config')
        self.state_directory('/var/records/child')
        self.configuration_alias('/configuration',
            '/var/records/child/../../../immutable-config')
        self.package['config'] = ['/configuration']
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')

    def test_storage_config_allows_immutable_alias_chain(self):
        policy = self.layout_fixture()
        self.file('/immutable-config')
        self.configuration_alias('/route', '/immutable-config')
        self.configuration_alias('/configuration', '/route')
        self.package['config'] = ['/configuration']
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')

    def test_storage_layout_rejects_crossing_hardlinks(self):
        policy = self.layout_fixture()
        os.link(self.root / 'var/records/seed', self.root / 'outside')
        self.package['entries']['/outside'] = dict(self.package['entries']['/var/records/seed'],
            type='hardlink', target='/var/records/seed')
        with self.assertRaisesRegex(ValueError, 'hardlink crosses'):
            self.layout_check(policy)

    def test_storage_layout_rejects_unreconciled_tree_and_uncovered_state(self):
        policy = self.layout_fixture()
        (self.root / 'extra').write_text('unexplained')
        with self.assertRaisesRegex(ValueError, 'exactly reconciled'):
            self.layout_check(policy)
        (self.root / 'extra').unlink()
        with self.assertRaisesRegex(ValueError, 'lacks a writable boundary'):
            self.layout_check({'format': 1, 'boundaries': []})

    def test_storage_layout_ordinary_allows_executables_and_package_config(self):
        policy = self.layout_fixture()
        self.package['config'] = ['/var/records/seed']
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')
        del self.package['config']
        (self.root / 'var/records/seed').chmod(0o755)
        self.package['entries']['/var/records/seed']['mode'] = 0o755
        self.assertEqual(self.layout_check(policy)['result'], 'PASS')

    def test_unexplained_file_and_directory(self):
        self.file('/program')
        (self.root / 'extra').mkdir()
        (self.root / 'extra/data').write_bytes(b'undeclared')
        result = self.run_check()
        self.assertEqual({d['path'] for d in result['differences']}, {'/extra', '/extra/data'})

    def test_construction_declaration_does_not_approve_output(self):
        self.file('/program')
        (self.root / 'policy').write_bytes(b'unverified generator output')
        self.inventory['construction'] = {
            'status': 'declared-not-executed', 'outputs_approved': False,
            'actions': [{'package': 'sample-system', 'name': 'policy',
                         'outputs': {'/policy': {'type': 'file', 'uid': os.getuid(),
                             'gid': os.getgid(), 'mode': 0o644, 'flags_set': 0,
                             'replace': False}}}]}
        result = self.run_check()
        self.assertEqual(result['result'], 'FAIL')
        self.assertEqual(result['differences'], [{'path': '/policy', 'reason': 'unexplained-object'}])

    def test_package_config_not_exempt(self):
        path = self.file('/policy')
        self.package['config'] = ['/policy']
        path.write_bytes(b'root changed policy')
        result = self.run_check()
        self.assertEqual(result['result'], 'FAIL')
        self.assertIn('sha256', result['differences'][0]['fields'])

    def test_missing_object(self):
        self.file('/program').unlink()
        result = self.run_check()
        self.assertEqual(result['differences'], [{'path': '/program', 'reason': 'missing-object'}])

    def test_mode_and_flags_are_checked(self):
        target = self.file('/program')
        target.chmod(0o666)
        result = self.run_check()
        self.assertIn('mode', result['differences'][0]['fields'])
        target.chmod(0o644)
        os.chflags(target, 1)  # UF_NODUMP is writable by the owner.
        result = generation.reconcile(self.root, self.inventory, self.generated)
        self.assertIn('flags_set', result['differences'][0]['fields'])

    def test_generated_file_requires_explicit_content_and_source(self):
        data = b'generated policy input'
        target = self.root / 'policy'
        target.write_bytes(data)
        target.chmod(0o600)
        item = dict(self.directory_input(), type='file', mode=0o600,
                    size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.generated['entries']['/policy'] = item
        self.assertEqual(self.run_check()['result'], 'PASS')
        item['source'] = ''
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.run_check()

    def test_package_replacement_requires_exact_input(self):
        target = self.file('/policy')
        target.write_bytes(b'site policy')
        item = dict(self.directory_input(), type='file', mode=0o644, size=11,
                    sha256=hashlib.sha256(b'site policy').hexdigest())
        self.generated['entries']['/policy'] = item
        for replacement in ([], ['b' * 64], [self.archive_hash, self.archive_hash]):
            item['replaces'] = replacement
            with self.assertRaises(ValueError):
                self.run_check()
        item['replaces'] = [self.archive_hash]
        self.assertEqual(self.run_check()['result'], 'PASS')

    def test_symlink_target_checked_without_traversal(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'secret').write_bytes(b'not generation content')
        (self.root / 'alias').symlink_to(outside)
        info = (self.root / 'alias').lstat()
        item = dict(self.directory_input(), type='symlink', target=str(outside),
                    mode=info.st_mode & 0o7777, flags_set=info.st_flags)
        self.generated['entries']['/alias'] = item
        self.assertEqual(self.run_check()['result'], 'PASS')
        item['target'] = '/different'
        result = self.run_check()
        self.assertEqual(set(result['objects']), {'/', '/alias'})
        self.assertIn('target', result['differences'][0]['fields'])

    def test_root_symlink_refused(self):
        alias = self.base / 'alias'; alias.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, 'alternate directory'):
            generation.scan(alias)

    def test_hardlink_bytes_read_once_but_cache_never_crosses_scans(self):
        payload = self.root / 'payload'
        body = b'x' * 4096
        payload.write_bytes(body)
        for name in ('alias-a', 'alias-b'):
            os.link(payload, self.root / name)
        library = generation.pkg.archive_library()
        original = library.archive_read_data
        count = [0]
        def read(*args):
            value = original(*args)
            count[0] += max(value, 0)
            return value
        library.archive_read_data = read
        with patch.object(generation.pkg, 'archive_library', return_value=library):
            first = generation.scan(self.root)
            self.assertEqual(count[0], len(body))
            payload.write_bytes(b'y' * len(body))
            second = generation.scan(self.root)
            self.assertEqual(count[0], 2 * len(body))
        for name in ('payload', 'alias-a', 'alias-b'):
            self.assertEqual(len(first['/' + name]['hardlinks']), 3)
            self.assertEqual(first['/' + name]['sha256'], hashlib.sha256(body).hexdigest())
            self.assertEqual(second['/' + name]['sha256'], hashlib.sha256(b'y' * len(body)).hexdigest())

    def test_external_hardlink_refused(self):
        path = self.file('/program')
        os.link(path, self.base / 'outside-link')
        with self.assertRaisesRegex(ValueError, 'hardlink escapes'):
            self.run_check()

    def test_generated_replacement_cannot_invalidate_package_hardlink(self):
        self.file('/program')
        self.package['entries']['/alias'] = dict(self.package['entries']['/program'],
            type='hardlink', target='/program')
        self.generated['entries']['/program'] = dict(type='symlink',
            uid=os.getuid(), gid=os.getgid(), mode=0o755, flags_set=0,
            source='explicit alias replacement', replaces=[self.archive_hash],
            target='/elsewhere')
        with self.assertRaisesRegex(ValueError, 'hardlink.*regular.*target'):
            generation.expected_objects(self.inventory, self.generated)

    def test_hardlink_cycle_rejected_before_filesystem_scan(self):
        self.file('/program')
        for name, target in (('/first', '/second'), ('/second', '/first')):
            self.package['entries'][name] = dict(self.package['entries']['/program'],
                type='hardlink', target=target)
        with self.assertRaisesRegex(ValueError, 'cyclic.*hardlink'):
            generation.expected_objects(self.inventory, self.generated)

    def test_declared_hardlink_set_and_unexpected_alias(self):
        path = self.file('/program')
        os.link(path, self.root / 'alias')
        self.package['entries']['/alias'] = dict(self.package['entries']['/program'], type='hardlink', target='/program')
        self.assertEqual(self.run_check()['result'], 'PASS')
        os.link(path, self.root / 'extra')
        result = self.run_check()
        self.assertEqual(result['result'], 'FAIL')
        self.assertTrue(any('hardlinks' in d.get('fields', {}) for d in result['differences']))

    def test_special_object_refused(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(ValueError, 'unsupported generation object'):
            self.run_check()

    def test_xattr_not_discarded(self):
        target = self.file('/program')
        subprocess.run(['setextattr', 'user', 'generation-test', 'value', str(target)], check=True)
        with self.assertRaisesRegex(ValueError, 'ACL/xattr'):
            self.run_check()

    def test_acl_not_discarded(self):
        target = self.file('/program')
        result = subprocess.run(['setfacl', '-m', 'u:12345:r:allow', str(target)],
                                capture_output=True)
        if result.returncode:
            # POSIX.1e ACL filesystems use the three-field user entry.
            subprocess.run(['setfacl', '-m', 'u:12345:r', str(target)], check=True)
        with self.assertRaisesRegex(ValueError, 'ACL/xattr'):
            self.run_check()

    def test_changed_owner_policy_changes_expected_numeric_identity(self):
        self.accounts()
        self.file('/program', named=True)
        different_uid = 0 if os.getuid() != 0 else 12345
        self.file('/etc/master.passwd', f'generation-owner:*:{different_uid}:{os.getgid()}::0:0:Owner:/:/bin/sh\n'.encode())
        result = self.run_check()
        changed = next(d for d in result['differences'] if d['path'] == '/program')
        self.assertEqual(changed['fields']['uid'], {'expected':different_uid,'actual':os.getuid()})

    def accounts(self):
        (self.root / 'etc').mkdir(mode=0o755)
        self.generated['entries']['/etc'] = self.directory_input()
        self.file('/etc/master.passwd', f'generation-owner:*:{os.getuid()}:{os.getgid()}::0:0:Owner:/:/bin/sh\n'.encode())
        self.file('/etc/group', f'generation-group:*:{os.getgid()}:\n'.encode())

    def test_ownership_comes_from_generation_accounts(self):
        self.accounts()
        self.file('/program', named=True)
        self.assertEqual(self.run_check()['result'], 'PASS')

    def relocated_accounts(self, absolute=False):
        self.accounts()
        self.file('/program', named=True)
        self.state_directory('/state')
        self.state_directory('/state/accounts')
        for name in ('master.passwd', 'group'):
            source = '/etc/' + name
            target = '/state/accounts/' + name
            (self.root / source.lstrip('/')).rename(self.root / target.lstrip('/'))
            original = self.package['entries'][source]
            self.generated['entries'][target] = {
                key: original[key] for key in ('type', 'uid', 'gid', 'mode',
                                               'flags_set', 'size', 'sha256')}
            self.generated['entries'][target].update(source='explicit relocation fixture', replaces=[])
            link = target if absolute else 'accounts/' + name
            (self.root / source.lstrip('/')).symlink_to(link)
            actual = (self.root / source.lstrip('/')).lstat()
            self.generated['entries'][source] = dict(type='symlink', target=link,
                uid=actual.st_uid, gid=actual.st_gid, mode=actual.st_mode & 0o7777,
                flags_set=actual.st_flags, source='explicit relocation fixture',
                replaces=[self.archive_hash])
        if not absolute:
            (self.root / 'etc/accounts').symlink_to('../state/accounts')
            actual = (self.root / 'etc/accounts').lstat()
            self.generated['entries']['/etc/accounts'] = dict(type='symlink',
                target='../state/accounts', uid=actual.st_uid, gid=actual.st_gid,
                mode=actual.st_mode & 0o7777, flags_set=actual.st_flags,
                source='explicit directory mapping fixture', replaces=[])

    def test_ownership_uses_declared_relative_account_alias_chain(self):
        self.relocated_accounts()
        self.assertEqual(self.run_check()['result'], 'PASS')

    def test_ownership_uses_declared_absolute_candidate_account_alias(self):
        self.relocated_accounts(absolute=True)
        self.assertEqual(self.run_check()['result'], 'PASS')

    def test_account_alias_substitution_rejected_even_with_identical_bytes(self):
        self.relocated_accounts()
        source = self.root / 'etc/master.passwd'
        source.unlink()
        source.symlink_to('/state/accounts/master.passwd')
        with self.assertRaisesRegex(ValueError, 'not matched to declared path'):
            self.run_check()

    def test_relocated_account_content_change_rejected(self):
        self.relocated_accounts()
        (self.root / 'state/accounts/master.passwd').write_text('root:*:0:0::0:0:Root:/:/bin/sh\n')
        with self.assertRaisesRegex(ValueError, 'not matched to declared content'):
            self.run_check()

    def test_account_alias_never_reads_absolute_host_target(self):
        self.relocated_accounts(absolute=True)
        outside = self.base / 'host-master.passwd'
        outside.write_text('root:*:0:0::0:0:Root:/:/bin/sh\n')
        source = self.root / 'etc/master.passwd'
        source.unlink()
        source.symlink_to(outside)
        self.generated['entries']['/etc/master.passwd']['target'] = str(outside)
        with self.assertRaisesRegex(ValueError, 'not matched to declared path'):
            self.run_check()

    def test_resolved_account_read_refuses_post_scan_symlink(self):
        self.relocated_accounts()
        self.clear_fixture_archive_flags()
        expected = generation.expected_objects(self.inventory, self.generated)
        observed = generation.scan(self.root)
        target = self.root / 'state/accounts/master.passwd'
        target.unlink()
        target.symlink_to(self.base / 'outside')
        with self.assertRaises(OSError):
            generation.account_maps(self.root, expected, observed)

    def test_changed_account_input_refused(self):
        self.accounts()
        self.file('/program', named=True)
        (self.root / 'etc/master.passwd').write_text('generation-owner:*:0:0::0:0:Root:/:/bin/sh\n')
        with self.assertRaisesRegex(ValueError, 'not matched'):
            self.run_check()

    def test_unknown_owner_has_no_host_fallback(self):
        self.accounts()
        self.file('/program', named=True)
        self.package['entries']['/program']['uname'] = 'root'
        with self.assertRaisesRegex(ValueError, 'unknown generation owner root'):
            self.run_check()

    def test_shared_directory_timestamp_is_not_a_conflict(self):
        (self.root / 'shared').mkdir(mode=0o755)
        item = {k:v for k,v in self.directory_input().items() if k not in ('source','replaces')}
        self.package['entries']['/shared'] = dict(item, mtime=10)
        second = copy.deepcopy(self.package)
        second['archive_sha256'] = 'b' * 64
        second['entries']['/shared']['mtime'] = 20
        self.inventory['packages'].append(second)
        self.assertEqual(self.run_check()['result'], 'PASS')
        replacement = self.directory_input()
        replacement['replaces'] = [self.archive_hash]
        self.generated['entries']['/shared'] = replacement
        with self.assertRaisesRegex(ValueError, 'exact package inputs'):
            self.run_check()

    def test_command_records_failure_and_refuses_output_alias(self):
        self.file('/program')
        self.clear_fixture_archive_flags()
        inventory = self.base / 'inventory.json'
        generated = self.base / 'generated.json'
        inventory.write_text(json.dumps(self.inventory))
        generated.write_text(json.dumps(self.generated))
        args = ['python3.12', helper, '--root', str(self.root), '--inventory', str(inventory),
                '--generated', str(generated)]
        output = self.base / 'reports/accepted'
        result = subprocess.run([*args, '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((output / 'reconciliation.json').read_text())
        self.assertEqual(record['result'], 'PASS')
        self.assertEqual(record['input_sha256']['generated'], hashlib.sha256(generated.read_bytes()).hexdigest())
        (self.root / 'program').write_bytes(b'changed')
        output = self.base / 'reports/rejected'
        result = subprocess.run([*args, '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads((output / 'reconciliation.json').read_text())['result'], 'FAIL')
        alias = self.base / 'output-alias'; alias.symlink_to(self.root)
        result = subprocess.run([*args, '--output', str(alias / 'inside')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('outside generation', result.stderr)
        self.assertFalse((self.root / 'inside').exists())

    def test_generated_schema_and_paths_fail_closed(self):
        for key,value in [('unknown',1), ('uid',True), ('mode',0o10000)]:
            with self.subTest(key=key):
                generated = copy.deepcopy(self.generated)
                generated['entries']['/'][key] = value
                with self.assertRaises(ValueError):
                    generation.expected_objects(self.inventory,generated)
        for path in ['/a/../b','relative','//alias']:
            generated = {'format':1,'entries':{path:self.directory_input()}}
            with self.assertRaises(ValueError):
                generation.expected_objects(self.inventory,generated)

    def test_manifest_directory_assertion_is_not_ignored(self):
        item = {k:v for k,v in self.directory_input().items() if k not in ('source','replaces')}
        self.package['entries']['/shared'] = item
        for declaration in ({'perm': '0777'}, {'fflags': 'schg'}, {'unknown': 1}):
            self.package['directories']['/shared'] = declaration
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'directory metadata'):
                generation.expected_objects(self.inventory, self.generated)

    def test_directory_declarations_are_order_independent(self):
        self.package['directories']['/shared'] = {'uname': 'root', 'gname': 'wheel', 'perm': '0755'}
        second = copy.deepcopy(self.package)
        second['archive_sha256'] = 'b' * 64
        second['directories']['/shared']['perm'] = '0777'
        for packages in ([self.package, second], [second, self.package]):
            with self.assertRaisesRegex(ValueError, 'directory metadata'):
                generation.expected_objects(dict(self.inventory, packages=packages), self.generated)

    def test_declared_system_file_flags_are_preserved(self):
        self.package['directories']['/shared'] = {'uname': 'root', 'gname': 'wheel',
                                                 'perm': '0555', 'fflags': 'schg'}
        expected = generation.expected_objects(self.inventory, self.generated)
        self.assertEqual(expected['/shared']['flags_set'], 0x20000)  # FreeBSD SF_IMMUTABLE
        self.assertEqual(expected['/shared']['mode'], 0o555)

    def test_shared_directory_named_placeholders_and_order(self):
        header = {'type': 'directory', 'mode': 0o755, 'flags_set': 0,
                  'uid': 65534, 'gid': 65534, 'uname': 'root', 'gname': 'wheel'}
        self.package['entries']['/shared'] = header
        second = copy.deepcopy(self.package)
        second['archive_sha256'] = 'b' * 64
        second['entries']['/shared'].update(uid=0, gid=0)
        second['directories']['/shared'] = {'perm': '755', 'uname': 'root', 'gname': 'wheel'}
        results = []
        for packages in ([self.package, second], [second, self.package]):
            results.append(generation.expected_objects(dict(self.inventory, packages=packages), self.generated))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]['/shared']['uname'], 'root')

    def test_named_owner_cannot_erase_independent_numeric_owner(self):
        self.package['entries']['/shared'] = {'type': 'directory', 'mode': 0o755,
                                              'flags_set': 0, 'uid': 23, 'gid': 24}
        second = copy.deepcopy(self.package)
        second['archive_sha256'] = 'b' * 64
        second['entries']['/shared'].update(uname='root', gname='wheel')
        for packages in ([self.package, second], [second, self.package]):
            with self.assertRaisesRegex(ValueError, 'ambiguous package directory metadata ownership'):
                generation.expected_objects(dict(self.inventory, packages=packages), self.generated)

    def test_header_and_other_package_declaration_order(self):
        self.package['entries']['/shared'] = {'type': 'directory', 'mode': 0o755,
                                              'flags_set': 0, 'uname': 'root', 'gname': 'wheel'}
        second = copy.deepcopy(self.package)
        second['archive_sha256'] = 'b' * 64
        second['entries'] = {}
        second['directories']['/shared'] = {'perm': '0777'}
        for packages in ([self.package, second], [second, self.package]):
            with self.assertRaisesRegex(ValueError, 'conflicting package directory metadata'):
                generation.expected_objects(dict(self.inventory, packages=packages), self.generated)

    def test_partial_declaration_cannot_invent_ownership(self):
        self.package['directories']['/shared'] = {'perm': '0755'}
        with self.assertRaisesRegex(ValueError, 'incomplete package directory metadata'):
            generation.expected_objects(self.inventory, self.generated)


class ProtectedConsumerInputs(unittest.TestCase):
    def setUp(self):
        self.digest = hashlib.sha256(b'consumer').hexdigest()
        self.archive = hashlib.sha256(b'archive').hexdigest()
        self.tree = {p: dict(type='directory', mode=0o755) for p in
                     ('/', '/lib', '/etc', '/state')}
        self.tree['/lib/consumer.so'] = dict(type='file', mode=0o644, sha256=self.digest)
        self.tree['/etc/policy'] = dict(type='file', mode=0o600, sha256='a' * 64)
        # Generated output: deliberately absent from package config/entries.
        self.tree['/etc/policy.db'] = dict(type='file', mode=0o600, sha256='b' * 64)
        self.inventory = {'packages': [dict(name='consumer', archive_sha256=self.archive,
            entries={'/lib/consumer.so': dict(self.tree['/lib/consumer.so'])}, config=['/etc/policy'])]}
        self.declaration = dict(consumer='/lib/consumer.so', package_archive_sha256=self.archive,
            inputs=[dict(path='/etc/policy', presence='required'),
                    dict(path='/etc/policy.db', presence='optional')])
        self.policy = dict(format=2, boundaries=[dict(path='/state', content='ordinary')],
                           protected_consumers=[self.declaration])

    def check(self):
        return generation.storage_layout(self.inventory, self.tree, self.policy)

    def test_generated_input_bound_without_inferring_complete_coverage(self):
        result = self.check()['protected_inputs']
        row, = result['bindings']
        self.assertEqual(row['consumer_sha256'], self.digest)
        self.assertEqual(row['inputs'][1]['sha256'], 'b' * 64)
        self.assertFalse(result['dependency_coverage_complete'])
        self.assertFalse(result['runtime_enforcement_verified'])

    def test_database_redirect_into_mutable_storage_rejected(self):
        self.tree['/state/database'] = self.tree['/etc/policy.db']
        self.tree['/etc/policy.db'] = dict(type='symlink', target='/state/database')
        for content in ('ordinary', 'protected'):
            self.policy['boundaries'][0]['content'] = content
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, 'traverses mutable'):
                self.check()

    def test_return_to_immutable_still_rejected(self):
        self.tree['/state/back'] = dict(type='symlink', target='/etc/policy')
        self.tree['/etc/policy.db'] = dict(type='symlink', target='/state/back')
        with self.assertRaisesRegex(ValueError, 'traverses mutable'):
            self.check()

    def test_immutable_alias_and_optional_missing_leaf(self):
        self.tree['/etc/policy.db'] = dict(type='symlink', target='policy')
        self.assertEqual(self.check()['protected_inputs']['bindings'][0]['inputs'][1]['sha256'], 'a' * 64)
        del self.tree['/etc/policy.db']
        row = self.check()['protected_inputs']['bindings'][0]['inputs'][1]
        self.assertEqual(row['resolution']['status'], 'missing')
        self.assertNotIn('sha256', row)

    def test_missing_optional_in_mutable_namespace_rejected(self):
        self.declaration['inputs'][1]['path'] = '/state/missing.db'
        with self.assertRaisesRegex(ValueError, 'traverses mutable'):
            self.check()

    def test_missing_required_and_missing_parent_rejected(self):
        for path in ('/etc/missing', '/missing-parent/policy'):
            self.declaration['inputs'][0]['path'] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'resolved regular file'):
                self.check()
        self.declaration['inputs'][0]['presence'] = 'optional'
        with self.assertRaisesRegex(ValueError, 'resolved regular file'):
            self.check()

    def test_symlink_limit_matches_target_source(self):
        header = Path(__file__).resolve().parents[3] / 'sys/sys/param.h'
        if not header.is_file():
            self.skipTest('target source header unavailable; not a runtime test')
        limit = re.search(r'^#define\s+MAXSYMLINKS\s+(\d+)\s*$',
                          header.read_text(), re.MULTILINE)
        self.assertIsNotNone(limit)
        self.assertEqual(generation.TARGET_MAXSYMLINKS, int(limit.group(1)))

    def test_target_symlink_limit_for_protected_inputs(self):
        original = copy.deepcopy(self.tree)
        for presence in ('required', 'optional'):
            for count in (32, 33):
                with self.subTest(presence=presence, links=count):
                    self.tree = copy.deepcopy(original)
                    for index in range(count):
                        target = f'link{index + 1}' if index + 1 < count else 'policy'
                        self.tree[f'/etc/link{index}'] = dict(type='symlink', target=target)
                    self.declaration['inputs'][0] = dict(path='/etc/link0', presence=presence)
                    if count == 32:
                        row = self.check()['protected_inputs']['bindings'][0]['inputs'][0]
                        self.assertEqual(row['sha256'], 'a' * 64)
                        self.assertEqual(len(row['resolution']['links']), count)
                    else:
                        with self.assertRaisesRegex(ValueError, 'resolved regular file'):
                            self.check()

    def test_bad_types_and_cycles_rejected(self):
        for item in (dict(type='directory'), dict(type='socket'),
                     dict(type='symlink', target='policy.db')):
            self.tree['/etc/policy.db'] = item
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, 'resolved regular file'):
                self.check()

    def test_consumer_identity_not_inherited_by_replacements(self):
        for item in (dict(type='file', sha256='c' * 64),
                     dict(type='symlink', target='/etc/policy')):
            self.tree['/lib/consumer.so'] = item
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, 'payload mismatch'):
                self.check()

    def test_wrong_archive_or_mutable_consumer_rejected(self):
        self.declaration['package_archive_sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'exact package owner'):
            self.check()
        self.declaration['package_archive_sha256'] = self.archive
        self.policy['boundaries'].append(dict(path='/lib', content='protected'))
        with self.assertRaisesRegex(ValueError, 'traverses mutable'):
            self.check()

    def test_schema_is_strict(self):
        good = copy.deepcopy(self.policy)
        for mutate in (lambda p: p.update(format=True), lambda p: p.update(format=3),
                       lambda p: p.update(extra=True), lambda p: p.pop('protected_consumers'),
                       lambda p: p.update(protected_consumers={})):
            self.policy = copy.deepcopy(good)
            mutate(self.policy)
            with self.assertRaises(ValueError):
                self.check()

    def test_duplicate_or_empty_declarations_rejected(self):
        good = copy.deepcopy(self.policy)
        self.policy['protected_consumers'].append(copy.deepcopy(self.declaration))
        with self.assertRaisesRegex(ValueError, 'duplicate protected consumer'):
            self.check()
        self.policy = copy.deepcopy(good)
        row = self.policy['protected_consumers'][0]
        row['inputs'].append(copy.deepcopy(row['inputs'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate protected input'):
            self.check()
        row['inputs'] = []
        with self.assertRaisesRegex(ValueError, 'explicit inputs'):
            self.check()

    def test_legacy_policy_does_not_claim_input_coverage(self):
        del self.policy['protected_consumers']
        self.policy['format'] = 1
        self.assertNotIn('protected_inputs', self.check())


if __name__ == '__main__':
    unittest.main()
