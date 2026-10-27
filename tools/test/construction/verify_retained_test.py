#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Native adversarial boundary checks; not full retained-system qualification."""
import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('verify_retained', Path(__file__).with_name('verify_retained.py'))
verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'artifact'
        self.root.mkdir()
        (self.root / 'record').write_bytes(b'retained input')

    def test_regular_input(self):
        self.assertEqual(verifier.rooted(self.root, '/record').read_bytes(), b'retained input')

    def test_traversal_and_noncanonical_paths(self):
        for name in ('relative', '/', '/../record', '/a/../record', '/./record', '//record'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier.rooted(self.root, name)

    def test_symlink_leaf(self):
        (self.root / 'alias').symlink_to('record')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            verifier.rooted(self.root, '/alias')

    def test_symlink_parent(self):
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            verifier.rooted(self.root, '/alias/record')

    def test_wrong_object_type(self):
        with self.assertRaisesRegex(ValueError, 'object type'):
            verifier.rooted(self.root, '/record', directory=True)
        (self.root / 'directory').mkdir()
        with self.assertRaisesRegex(ValueError, 'object type'):
            verifier.rooted(self.root, '/directory')

    def test_artifact_cannot_supply_verifier_code(self):
        helper = self.root / 'helpers'; helper.mkdir()
        with self.assertRaisesRegex(ValueError, 'helpers cannot come from'):
            verifier.load_helpers(helper, self.root)

    def test_writable_artifact_refused_before_loading_helpers(self):
        self.assertFalse(os.statvfs(self.root).f_flag & os.ST_RDONLY)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            verifier.verify(self.root, '/work', self.root / 'helpers', self.root / 'sqlite')

    def test_diagnostics_bounded_and_missing_outputs(self):
        workspace = self.root / 'work'; workspace.mkdir()
        record = workspace / 'retained-builder.json'
        record.write_bytes(b'x' * 8192 + b'RUNTIME_VM_PASS\n')
        result = verifier.construction_diagnostics(self.root, '/work')
        self.assertFalse(result['candidate_verified'])
        item = result['records']['retained-builder.json']
        self.assertTrue(item['truncated'])
        self.assertEqual(len(item['tail_utf8'].encode()), 4096)
        self.assertFalse(result['records']['construction/constructed/database/receipt.json']['present'])

    def test_diagnostics_refuse_symlink(self):
        workspace = self.root / 'work'; workspace.mkdir()
        (workspace / 'retained-builder.json').symlink_to(self.root / 'record')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            verifier.construction_diagnostics(self.root, '/work')

    def test_existing_output_preserved(self):
        output = Path(self.temp.name) / 'report'
        output.write_bytes(b'previous evidence')
        result = subprocess.run(['/usr/local/bin/python3.12', '-I', '-S', '-B',
            str(Path(__file__).with_name('verify_retained.py')), '--root', str(self.root),
            '--helpers', str(self.root / 'helpers'), '--sqlite', str(self.root / 'sqlite'),
            '--work-directory', '/work', '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('output must be new', result.stderr)
        self.assertEqual(output.read_bytes(), b'previous evidence')


class ImageWorkspaceArguments(unittest.TestCase):
    def command(self):
        result = ['/usr/local/bin/python3.12', '-B',
                  str(Path(__file__).with_name('verify-retained-vm.py'))]
        for name in ('boot-root', 'world', 'python-prefix', 'objtop', 'fixture-objtop',
                     'work', 'qemu-data', 'sqlite', 'input-disk'):
            result.extend(['--' + name, '/nonexistent-verifier-input'])
        for name in ('qemu', 'kernconf', 'input-disk-sha256', 'retained-work'):
            result.extend(['--' + name, 'unused'])
        return result + ['--input-partition', '2']

    def test_split_image_requires_complete_binding_selection(self):
        image = ['--image-makefs', '/nonexistent-makefs', '--image-work-directory', '/root/image',
                 '--output-disk-mib', '64', '--storage-layout-policy', '/nonexistent-layout']
        selections = [[], ['--storage-bindings', '/nonexistent-bindings'],
                      ['--storage-bindings', '/nonexistent-bindings', '--capsule-validator', '/nonexistent-validator',
                       '--capsule-validator-sha256', 'INVALID']]
        for selection in selections:
            with self.subTest(selection=selection):
                result = subprocess.run(self.command() + image + selection, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('split image requires', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_storage_bindings_require_split_image_mode(self):
        result = subprocess.run(self.command() + ['--storage-bindings', '/nonexistent-bindings',
            '--capsule-validator', '/nonexistent-validator', '--capsule-validator-sha256', '0'*64],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('split image requires', result.stderr)

    def test_input_mount_directory_is_canonical(self):
        for path in ('relative', '/', '/mnt/../tmp', '/mnt//input', '/mnt/input/', '/mnt/input\n'):
            with self.subTest(path=path):
                result = subprocess.run(self.command() + ['--input-mount-directory', path],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('canonical absolute guest path', result.stderr)

    def test_invalid_cpu_counts_rejected_before_staging(self):
        for value in ('0', '5', '-1', '2.5'):
            with self.subTest(value=value):
                result = subprocess.run(self.command() + ['--cpus', value],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('--cpus', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_image_workspace_required_and_unused_rejected(self):
        for extra in (['--image-makefs', '/nonexistent-makefs', '--output-disk-mib', '64'],
                      ['--image-work-directory', '/root/image']):
            result = subprocess.run(self.command() + extra, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('image export requires --image-work-directory', result.stderr)

    def test_noncanonical_guest_workspace_rejected_before_staging(self):
        for path in ('relative', '/', '//root/image', '/root/../image', '/root/./image',
                     '/root/image/', '/root/image\n'):
            with self.subTest(path=path):
                result = subprocess.run(self.command() + ['--image-makefs', '/nonexistent-makefs',
                    '--output-disk-mib', '64', '--image-work-directory', path],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('canonical absolute guest path', result.stderr)


class StateInitializationArguments(unittest.TestCase):
    command = ImageWorkspaceArguments.command

    def options(self):
        return ['--state-allocation', '/nonexistent-allocation',
                '--state-disk', '/nonexistent-state-disk',
                '--state-disk-sha256', '0' * 64,
                '--state-work-directory', '/root/state-initialization',
                '--storage-layout-policy', '/nonexistent-layout',
                '--output-disk-mib', '128']

    def refused(self, options, expected):
        result = subprocess.run(self.command() + options, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(expected, result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_partial_state_inputs(self):
        self.refused(['--state-allocation', '/nonexistent-allocation'],
                     'state initialization requires allocation')

    def test_state_budget_requires_larger_vm_budget(self):
        self.refused(self.options(), 'case budget below the VM budget')
        self.refused(self.options() + ['--vm-timeout', '4000', '--state-case-timeout', '4000'],
                     'case budget below the VM budget')

    def test_state_and_image_modes_exclusive(self):
        self.refused(self.options() + ['--vm-timeout', '4000', '--image-work-directory', '/root/image'],
                     'without image export')

    def test_state_workspace_canonical(self):
        for value in ('/', 'relative', '/root/../state', '/root/./state', '/root/state/', '/root/state\n'):
            with self.subTest(value=value):
                self.refused(self.options() + ['--vm-timeout', '4000', '--state-work-directory', value],
                             'canonical absolute guest path')

    def test_state_budget_needs_state_mode(self):
        self.refused(['--state-case-timeout', '100'], 'requires state initialization')

    def test_missing_state_disk(self):
        self.refused(self.options() + ['--vm-timeout', '4000'], 'state source disk size or hash differs')


class StateReview(unittest.TestCase):
    def setUp(self):
        helper = Path(__file__).resolve().parents[2] / 'build/capimage/construction.py'
        spec = importlib.util.spec_from_file_location('construction', helper)
        self.constructor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.constructor)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        program = self.root / 'program'
        program.write_bytes(b'package executable fixture')
        program.chmod(0o755)
        (self.root / 'var').mkdir()
        self.objects = self.constructor.generation.scan(self.root)
        declaration = {'name': 'records', 'program': '/program',
            'path': '/var/records', 'type': 'directory',
            'lifetime': 'persistent', 'purpose': 'fixture service records'}
        self.package = {'name': 'fixture', 'archive_sha256': 'a' * 64,
            'entries': {'/program': copy.deepcopy(self.objects['/program'])},
            'manifest': {'annotations': {'5bsd.state-requirements': json.dumps(
                {'format': 1, 'requirements': [declaration]})}}}
        self.inventory = {'format': 1, 'packages': [self.package]}

    def review(self):
        return verifier.reviewed_state(self.constructor, self.inventory,
            self.constructor.generation.scan(self.root))

    def test_constructed_layout_recomputed_from_final_objects(self):
        policy = dict(format=1, boundaries=[dict(path='/var', content='ordinary')])
        layout = self.constructor.generation.storage_layout(self.inventory, self.objects, policy)
        binding = dict(policy_sha256=self.constructor.digest(policy),
            layout_sha256=self.constructor.digest(layout),
            filesystem_sha256=self.constructor.digest(self.objects),
            authority_assigned=False, coverage_complete=False, runtime_qualified=False)
        check = lambda saved, bound, selected=policy: verifier.verify_constructed_layout(
            self.constructor, self.inventory, self.objects, selected, saved, bound)
        self.assertEqual(check(layout, binding), binding)
        changed = copy.deepcopy(layout)
        changed['boundaries'][0]['seed_objects'] = {}
        forged = dict(binding, layout_sha256=self.constructor.digest(changed))
        with self.assertRaisesRegex(ValueError, 'storage layout differs'):
            check(changed, forged)
        for key in ('policy_sha256', 'filesystem_sha256', 'layout_sha256'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'storage layout differs'):
                check(layout, dict(binding, **{key: '0' * 64}))
        for key in ('authority_assigned', 'coverage_complete', 'runtime_qualified'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'storage layout differs'):
                check(layout, dict(binding, **{key: True}))
        selected = dict(format=1, boundaries=[dict(path='/var', content='protected')])
        with self.assertRaisesRegex(ValueError, 'storage layout differs'):
            check(layout, binding, selected)

    def test_explicit_layout_covers_declared_state(self):
        policy = self.root / 'layout.json'
        policy.write_text(json.dumps(dict(format=1,
            boundaries=[dict(path='/var', content='ordinary')])))
        result = verifier.reviewed_layout(self.constructor, self.inventory, self.objects, policy)
        self.assertEqual(result['requirements'][0]['boundary'], '/var')
        self.assertEqual(result['boundaries'][0]['seed_object_count'], 1)
        self.assertEqual(result['filesystem_sha256'], self.constructor.digest(self.objects))
        self.assertFalse(result['runtime_qualified'])
        self.assertFalse(result['coverage_complete'])
        policy.write_text(json.dumps(dict(format=1, boundaries=[])))
        with self.assertRaisesRegex(ValueError, 'lacks a writable boundary'):
            verifier.reviewed_layout(self.constructor, self.inventory, self.objects, policy)

    def test_layout_allows_ordinary_package_configuration(self):
        self.package['config'] = ['/var/settings']
        (self.root / 'var/settings').write_bytes(b'security configuration')
        policy = self.root / 'layout.json'
        policy.write_text(json.dumps(dict(format=1,
            boundaries=[dict(path='/var', content='ordinary')])))
        result = verifier.reviewed_layout(self.constructor, self.inventory,
            self.constructor.generation.scan(self.root), policy)
        self.assertEqual(result['boundaries'][0]['content'], 'ordinary')
        self.assertEqual(result['boundaries'][0]['seed_object_count'], 2)
        self.assertFalse(result['authority_assigned'])
        self.assertFalse(result['coverage_complete'])
        self.assertFalse(result['runtime_qualified'])

    def test_missing_state_is_retained_without_authority(self):
        report = self.review()
        self.assertEqual(report['inventory_sha256'], self.constructor.digest(self.inventory))
        self.assertEqual(report['filesystem_sha256'], self.constructor.digest(self.objects))
        self.assertFalse(report['authority_assigned'])
        self.assertFalse(report['coverage_complete'])
        self.assertFalse(report['runtime_qualified'])
        self.assertTrue(report['consumer_bindings'][0]['payload_matches'])
        declaration, = report['declarations']['requirements']
        self.assertEqual(declaration['lifetime'], 'persistent')
        self.assertEqual(declaration['program'], '/program')
        self.assertFalse(report['declarations']['runtime_paths_complete'])
        row, = report['layout']['requirements']
        self.assertEqual(row['resolution'], 'missing')
        self.assertEqual(row['first_missing_component'], '/var/records')
        self.assertEqual(row['nearest_existing_directory'], '/var')
        self.assertFalse(report['layout']['mount_coverage_approved'])

    def test_replaced_consumer_is_rejected(self):
        (self.root / 'program').write_bytes(b'different executable')
        with self.assertRaisesRegex(ValueError, 'state consumer differs'):
            self.review()

    def test_alias_is_recorded_as_blocked_not_followed(self):
        (self.root / 'var').rmdir()
        (self.root / 'var').symlink_to('elsewhere')
        row, = self.review()['layout']['requirements']
        self.assertEqual(row['resolution'], 'blocked-ancestor')
        self.assertEqual(row['blocked_ancestor'], '/var')
        self.assertIsNone(row['observed_object'])

    def test_no_declarations_does_not_certify_coverage(self):
        self.package['manifest'] = {}
        report = self.review()
        self.assertEqual(report['consumer_bindings'], [])
        self.assertEqual(report['declarations']['packages_without_declarations'], ['fixture'])
        self.assertEqual(report['layout']['requirements'], [])
        self.assertFalse(report['coverage_complete'])


class CollectedReport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.vm = self.work / 'vm'; self.vm.mkdir()
        self.report = dict(result='PASS', scope='retained-builder-post-shutdown-consistency',
            generation_authenticated=False, policy_approval_verified=False,
            normal_boot_qualified=False, inventory_sha256='a' * 64,
            filesystem_sha256='b' * 64, state_review=dict(
                scope='retained-generation-state-review', inventory_sha256='a' * 64,
                filesystem_sha256='b' * 64, authority_assigned=False,
                coverage_complete=False, runtime_qualified=False))
        self.result = dict(result='PASS', forced_termination=False, qemu_exit=0,
            input_disk_readonly=True, input_disk_sha256='c' * 64,
            input_disk_final_sha256='c' * 64)

    def prepare(self, count=1):
        serial = ('RETAINED_VERIFICATION_RESULT ' + json.dumps(self.report) + '\n') * count
        (self.vm / 'serial.log').write_text(serial)
        self.result['serial_sha256'] = hashlib.sha256(serial.encode()).hexdigest()
        (self.vm / 'result.json').write_text(json.dumps(self.result))

    def test_positive_report_retains_bindings_without_authority(self):
        self.prepare()
        result = verifier.collect_verification(self.work)
        self.assertEqual(result['report'], self.report)
        self.assertEqual(result['input_disk_sha256'], 'c' * 64)
        self.assertFalse(result['generation_authenticated'])
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(json.loads((self.work / 'verification.json').read_text()), result)

    def test_relocation_report_binding_and_limits(self):
        original = dict(policy_sha256='d'*64, receipt_sha256='e'*64,
            filesystem_sha256='b'*64, moves=1, generation_authenticated=False,
            runtime_authority_assigned=False)
        for key, value in (('filesystem_sha256','f'*64),('moves',True),('moves',0),
                           ('generation_authenticated',True),('runtime_authority_assigned',True),
                           ('policy_sha256','invalid'),('receipt_sha256',None)):
            self.report['construction_relocation'] = dict(original, **{key:value})
            self.prepare()
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'relocation review'):
                verifier.collect_verification(self.work)
        self.report['construction_relocation'] = original
        self.prepare()
        result = verifier.collect_verification(self.work)
        self.assertEqual(result['report']['construction_relocation'], original)

    def test_layout_policy_requires_bound_review(self):
        selected = self.work / 'extra/tests/storage-layout-policy.json'
        selected.parent.mkdir(parents=True)
        selected.write_text('{"format":1,"boundaries":[]}')
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'storage layout review'):
            verifier.collect_verification(self.work)
        original = dict(scope='retained-generation-storage-layout',
            policy_file_sha256=hashlib.sha256(selected.read_bytes()).hexdigest(),
            inventory_sha256='a' * 64, filesystem_sha256='b' * 64,
            authority_assigned=False, coverage_complete=False, runtime_qualified=False)
        for key, value in [('policy_file_sha256', 'd' * 64),
                ('filesystem_sha256', 'd' * 64), ('inventory_sha256', 'd' * 64),
                ('authority_assigned', True), ('coverage_complete', True),
                ('runtime_qualified', True)]:
            self.report['storage_layout_review'] = dict(original, **{key: value})
            self.prepare()
            with self.assertRaisesRegex(ValueError, 'storage layout review'):
                verifier.collect_verification(self.work)
        self.report['storage_layout_review'] = original
        self.prepare()
        self.assertEqual(verifier.collect_verification(self.work)['report']['storage_layout_review'], original)

    def test_unselected_layout_review_refused(self):
        self.report['storage_layout_review'] = {}
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'lacks selected policy'):
            verifier.collect_verification(self.work)

    def test_forced_or_changed_vm_is_rejected(self):
        original = copy.deepcopy(self.result)
        for key, value in [('forced_termination', True), ('input_disk_readonly', False),
                ('input_disk_final_sha256', 'd' * 64), ('qemu_exit', 1), ('result', 'FAIL')]:
            with self.subTest(key=key):
                self.result = dict(original, **{key: value}); self.prepare()
                with self.assertRaisesRegex(ValueError, 'VM evidence'):
                    verifier.collect_verification(self.work)
                self.assertFalse((self.work / 'verification.json').exists())

    def test_changed_serial_is_rejected(self):
        self.prepare()
        with (self.vm / 'serial.log').open('a') as stream:
            stream.write('changed after VM result\n')
        with self.assertRaisesRegex(ValueError, 'VM evidence'):
            verifier.collect_verification(self.work)

    def test_missing_or_duplicate_reports_are_rejected(self):
        for count in (0, 2):
            self.prepare(count)
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                verifier.collect_verification(self.work)

    def test_state_review_cannot_change_generation_or_claim_authority(self):
        original = copy.deepcopy(self.report['state_review'])
        for key, value in [('inventory_sha256', 'd' * 64),
                ('filesystem_sha256', 'd' * 64), ('authority_assigned', True),
                ('coverage_complete', True), ('runtime_qualified', True)]:
            with self.subTest(key=key):
                self.report['state_review'] = dict(original, **{key: value}); self.prepare()
                with self.assertRaisesRegex(ValueError, 'state review'):
                    verifier.collect_verification(self.work)

    def test_missing_review_does_not_pass(self):
        del self.report['state_review']; self.prepare()
        with self.assertRaisesRegex(ValueError, 'state review'):
            verifier.collect_verification(self.work)

    def test_existing_evidence_is_not_overwritten(self):
        self.prepare()
        output = self.work / 'verification.json'; output.write_text('prior evidence')
        with self.assertRaises(FileExistsError):
            verifier.collect_verification(self.work)
        self.assertEqual(output.read_text(), 'prior evidence')


class LayoutReceiptBinding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'receipt.json'
        self.path.write_bytes(b'{"full_observation":"' + b'x' * (2 * 1024 * 1024) + b'"}')

    def test_complete_bytes_and_bounded_serial_record(self):
        binding = verifier.layout_receipt_binding(self.path)
        self.assertEqual(binding['sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(binding['bytes'], self.path.stat().st_size)
        self.assertLess(len(json.dumps(binding)), 256)
        verifier.verify_layout_receipt_binding(self.path, binding)

    def test_materialization_result_must_match_hashed_bytes(self):
        expected = json.loads(self.path.read_bytes())
        binding = verifier.layout_receipt_binding(self.path, expected=expected)
        verifier.verify_layout_receipt_binding(self.path, binding)
        with self.assertRaisesRegex(ValueError, 'materialization'):
            verifier.layout_receipt_binding(self.path, expected={'different': True})

    def test_same_size_tampering_rejected(self):
        binding = verifier.layout_receipt_binding(self.path)
        with self.path.open('r+b') as stream:
            stream.seek(1000000); stream.write(b'y')
        with self.assertRaisesRegex(ValueError, 'differs'):
            verifier.verify_layout_receipt_binding(self.path, binding)

    def test_missing_or_extended_binding_rejected(self):
        binding = verifier.layout_receipt_binding(self.path)
        for bad in (None, {}, {**binding, 'ignored': True}, {**binding, 'bytes': 1},
                    {**binding, 'format': True}, {**binding, 'bytes': float(binding['bytes'])}):
            with self.assertRaises(ValueError):
                verifier.verify_layout_receipt_binding(self.path, bad)

    def test_symlink_empty_and_oversize_rejected(self):
        alias = self.path.with_name('alias'); alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            verifier.layout_receipt_binding(alias)
        self.path.write_bytes(b'')
        with self.assertRaises(ValueError):
            verifier.layout_receipt_binding(self.path)
        with self.path.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            verifier.layout_receipt_binding(self.path)


if __name__ == '__main__':
    unittest.main()
