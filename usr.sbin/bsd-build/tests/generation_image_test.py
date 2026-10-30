# SPDX-License-Identifier: BSD-2-Clause
"""Actual archive/receipt preflight; image execution has separate VM coverage."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
import tempfile
import subprocess
from unittest.mock import patch
from construction_test import Construction

helper = os.environ.get('BSD_BUILD_IMAGE_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/generation_image.py')
spec = importlib.util.spec_from_file_location('generation_image', helper)
image = importlib.util.module_from_spec(spec); spec.loader.exec_module(image)


class RequiredPolicySelection(unittest.TestCase):
    def test_format3_rejects_missing_selection_before_accessing_candidate(self):
        policy = dict(format=3, boundaries=[])
        with self.assertRaisesRegex(ValueError, 'BIP format-3 images have been retired'):
            image.materialize_layout('/nonexistent-candidate', {}, {}, policy, {},
                                     '/nonexistent-output')
        with self.assertRaisesRegex(ValueError, 'BIP format-3 images have been retired'):
            image.verify_layout('/nonexistent-output', {}, {}, policy)
        for version in (1, 2):
            image.validate_layout_version(dict(format=version))

    def test_cli_rejects_omission_before_image_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            policy = base / 'policy.json'
            policy.write_text('{"format":3,"boundaries":[]}')
            command = [os.sys.executable, '-B', helper, '--storage-layout-policy', str(policy)]
            for key in ('root', 'inventory', 'generated', 'construction-receipt', 'output',
                        'makefs', 'mdconfig', 'mount', 'umount'):
                command.extend(['--' + key, str(base / key)])
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('BIP format-3 images have been retired', result.stderr)
            self.assertFalse((base / 'output').exists())


class ImagePreflight(unittest.TestCase):
    def setUp(self):
        self.fixture = Construction()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.actions = []
        self.inventory = self.fixture.inventory()
        self.receipt = self.fixture.run_construct(self.inventory)
        self.generated = json.loads((self.fixture.output / 'generated.json').read_text())

    def prepare(self, receipt=None, generated=None):
        return image.prepare(self.fixture.root, self.inventory,
            self.generated if generated is None else generated,
            self.receipt if receipt is None else receipt)

    def test_matching_complete_receipt(self):
        root, observed = self.prepare()
        self.assertEqual(root, self.fixture.root)
        self.assertEqual(image.construction.digest(observed), self.receipt['filesystem_sha256'])

    def test_incomplete_or_mismatched_receipt(self):
        for key, value in [('result', 'RUNNING'), ('scope', 'other'),
                           ('inventory_sha256', '0' * 64), ('generated_sha256', '0' * 64),
                           ('filesystem_sha256', '0' * 64)]:
            receipt = dict(self.receipt, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'receipt'):
                self.prepare(receipt)

    def test_altered_generated_inputs(self):
        generated = copy.deepcopy(self.generated)
        generated['entries']['/']['mode'] = 0o777
        with self.assertRaisesRegex(ValueError, 'receipt'):
            self.prepare(generated=generated)

    def test_changed_payload(self):
        self.fixture.write('/input', b'changed after completion')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.prepare()

    def test_symlink_root(self):
        alias = self.fixture.base / 'alias'; alias.symlink_to(self.fixture.root)
        with self.assertRaisesRegex(ValueError, 'nonsymlink'):
            image.prepare(alias, self.inventory, self.generated, self.receipt)


class BootArchiveTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'; self.root.mkdir()
        boot = self.root / 'boot'; boot.mkdir()
        (boot / 'kernel').mkdir()
        (boot / 'kernel/kernel').write_bytes(b'kernel fixture\x00')
        (boot / 'future package file').write_bytes(b'not a hand-selected program')
        os.link(boot / 'kernel/kernel', self.root / 'kernel-alias')
        (boot / 'kernel-link').symlink_to('kernel/kernel')
        (boot / 'absolute-link').symlink_to('/boot/kernel/kernel')
        os.utime(boot / 'kernel/kernel', ns=(1792359985123456789, 1792359985123456789))
        self.observed = image.construction.generation.scan(self.root)
        self.output = self.base / 'boot.tar'

    def test_complete_namespace_and_metadata_binding(self):
        import tarfile
        report = image.boot_archive(self.root, self.observed, self.output)
        self.assertEqual(report['source_observation_sha256'], image.construction.digest(self.observed))
        self.assertEqual(report['entries'], {n:v for n,v in self.observed.items()
                         if n == '/boot' or n.startswith('/boot/')})
        self.assertEqual(report['entries']['/boot/kernel/kernel']['hardlinks'],
                         ['/boot/kernel/kernel', '/kernel-alias'])
        self.assertTrue(report['metadata_reconstruction_required'])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        with tarfile.open(self.output) as archive:
            self.assertIn('boot/future package file', archive.getnames())
            self.assertEqual(archive.extractfile('boot/kernel/kernel').read(), b'kernel fixture\x00')
            self.assertEqual(archive.getmember('boot/absolute-link').linkname, '/boot/kernel/kernel')
            self.assertEqual(archive.getmember('boot/kernel/kernel').pax_headers['mtime'], '1792359985.123456789')

    def test_changed_or_extra_input_refused(self):
        for change in ('changed', 'extra'):
            with self.subTest(change=change):
                path = self.root / 'boot' / ('kernel/kernel' if change == 'changed' else 'extra')
                original = path.read_bytes() if path.exists() else None
                path.write_bytes(b'new bytes')
                with self.assertRaisesRegex(ValueError, 'changed before'):
                    image.boot_archive(self.root, self.observed, self.output)
                self.assertFalse(self.output.exists())
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
                self.observed = image.construction.generation.scan(self.root)

    def test_existing_output_preserved(self):
        self.output.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError):
            image.boot_archive(self.root, self.observed, self.output)
        self.assertEqual(self.output.read_bytes(), b'preserve')

    def test_output_inside_generation_refused(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            image.boot_archive(self.root, self.observed, self.root / 'boot.tar')

    def test_missing_or_symlink_boot_refused(self):
        for kind in ('missing', 'symlink'):
            candidate = self.base / kind; candidate.mkdir()
            if kind == 'symlink':
                (candidate / 'boot').symlink_to(self.root / 'boot')
            observed = image.construction.generation.scan(candidate)
            with self.assertRaisesRegex(ValueError, 'complete boot directory'):
                image.boot_archive(candidate, observed, self.output)


class PartitionTests(unittest.TestCase):
    setUp = BootArchiveTests.setUp

    def test_projection_preserves_seeds_and_rebases_links(self):
        state = self.root / 'state'; state.mkdir(mode=0o770)
        (state / 'one').write_bytes(b'seed')
        os.link(state / 'one', state / 'two')
        observed = image.construction.generation.scan(self.root)
        snapshot = copy.deepcopy(observed)
        layout, images = image.partitions({'packages': []}, observed,
            {'format': 1, 'boundaries': [{'path': '/state', 'content': 'ordinary'}]})
        self.assertEqual(observed, snapshot)
        base, seed = images
        self.assertNotIn('/state/one', base['observed'])
        self.assertEqual(base['observed']['/state']['uid'], 0)
        self.assertEqual(base['observed']['/state']['mode'], 0o755)
        self.assertEqual(seed['observed']['/'], observed['/state'])
        self.assertEqual(seed['observed']['/one']['hardlinks'], ['/one', '/two'])
        self.assertEqual(seed['sources']['/one'], '/state/one')
        self.assertEqual(set(base['observed']) | set(layout['boundaries'][0]['seed_objects']), set(observed))

    def test_boot_partition_must_be_unchanged(self):
        observed = image.construction.generation.scan(self.root)
        projection = dict(content='immutable', boundary=None, observed=copy.deepcopy(observed))
        image.validate_boot_projection(observed, projection)
        projection['observed'].pop('/boot/kernel/kernel')
        with self.assertRaisesRegex(ValueError, 'unchanged immutable'):
            image.validate_boot_projection(observed, projection)
        projection['observed'] = observed
        projection['content'] = 'protected'
        with self.assertRaisesRegex(ValueError, 'unchanged immutable'):
            image.validate_boot_projection(observed, projection)

    def test_cross_partition_hardlink_refused(self):
        state = self.root / 'state'; state.mkdir()
        os.link(self.root / 'boot/kernel/kernel', state / 'alias')
        observed = image.construction.generation.scan(self.root)
        with self.assertRaisesRegex(ValueError, 'hardlink crosses'):
            image.partitions({'packages': []}, observed,
                {'format': 1, 'boundaries': [{'path': '/state', 'content': 'protected'}]})


class LayoutReceiptTests(unittest.TestCase):
    """Synthetic transport records; actual filesystem readback is a VM test."""
    setUp = BootArchiveTests.setUp

    def fixture(self):
        state = self.root / 'state'; state.mkdir()
        (state / 'value').write_bytes(b'seed')
        self.observed = image.construction.generation.scan(self.root)
        self.inventory = {'packages': []}
        self.policy = {'format': 1, 'boundaries': [{'path': '/state', 'content': 'ordinary'}]}
        layout, projections = image.partitions(self.inventory, self.observed, self.policy)
        self.work = self.base / 'images'; self.work.mkdir()
        digest = image.construction.digest
        report = dict(format=1, scope='trusted-builder-storage-images', result='PASS',
            layout=layout, source_observation_sha256=digest(self.observed),
            policy_sha256=digest(self.policy), input_bindings={}, images=[],
            generation_authenticated=False, activation_authorized=False,
            seeds_installed=False, attachments_constructed=False)
        for index, projection in enumerate(projections):
            directory = 'base' if index == 0 else 'seed-' + str(index)
            folder = self.work / directory; folder.mkdir()
            (folder / 'system.ufs').write_bytes(b'synthetic image transport ' + str(index).encode())
            (folder / 'filesystem.mtree').write_bytes(b'synthetic manifest')
            receipt = dict(format=1, scope='trusted-builder-partition-image', result='PASS',
                partition_content=projection['content'], partition_boundary=projection['boundary'],
                input_bindings={}, source_observation_sha256=digest(self.observed),
                expected_observation_sha256=digest(projection['observed']),
                readback_observation_sha256=digest(projection['observed']),
                image_sha256=image.file_hash(folder / 'system.ufs'),
                image_bytes=(folder / 'system.ufs').stat().st_size,
                manifest_sha256=image.file_hash(folder / 'filesystem.mtree'),
                inputs_authenticated=False, generation_authenticated=False, activation_authorized=False)
            image.construction.write_record(folder / 'receipt.json', receipt)
            report['images'].append(dict(directory=directory, boundary=projection['boundary'],
                content=projection['content'], observations=projection['observed'], receipt=receipt))
        self.report = report
        self.save()

    def save(self):
        image.construction.write_record(self.work / 'receipt.json', self.report)

    def verify(self):
        return image.verify_layout(self.work, self.observed, self.inventory, self.policy)

    def test_selected_inputs_and_explicit_scope(self):
        self.fixture()
        checked = self.verify()
        self.assertEqual(len(checked['images']), 2)
        self.assertFalse(checked['filesystem_readback_repeated'])
        self.assertFalse(checked['generation_authenticated'])
        self.policy['boundaries'][0]['content'] = 'protected'
        with self.assertRaisesRegex(ValueError, 'selected construction inputs'):
            self.verify()

    def test_changed_image_manifest_or_child_receipt(self):
        self.fixture()
        for name in ('system.ufs', 'filesystem.mtree', 'receipt.json'):
            path = self.work / 'seed-1' / name
            original = path.read_bytes()
            path.write_bytes(b'{}')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            path.write_bytes(original)

    def test_missing_extra_reordered_and_escaped_images(self):
        self.fixture()
        original = copy.deepcopy(self.report['images'])
        for entries in (original[:1], original + original[:1], list(reversed(original)),
                        [dict(original[0], directory='../outside'), original[1]]):
            self.report['images'] = entries; self.save()
            with self.assertRaises(ValueError):
                self.verify()

    def test_symlink_artifact_and_directory_rejected(self):
        self.fixture()
        for path in (self.work / 'seed-1/system.ufs', self.work / 'seed-1'):
            moved = self.base / 'moved'; path.rename(moved); path.symlink_to(moved)
            with self.assertRaisesRegex(ValueError, 'physical|nonsymlink'):
                self.verify()
            path.unlink(); moved.rename(path)

    def test_false_readback_and_scope_claim_rejected(self):
        self.fixture()
        receipt = self.report['images'][0]['receipt']
        for key, value in (('readback_observation_sha256', '0' * 64),
                           ('activation_authorized', True), ('result', 'FAIL')):
            original = receipt[key]; receipt[key] = value
            image.construction.write_record(self.work / 'base/receipt.json', receipt); self.save()
            with self.assertRaisesRegex(ValueError, 'readback'):
                self.verify()
            receipt[key] = original


class SeedInitializationTests(unittest.TestCase):
    def setUp(self):
        BootArchiveTests.setUp(self)
        spec = importlib.util.spec_from_file_location('seed_initialize', Path(helper).with_name('seed_initialize.py'))
        self.seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.seed)
        self.target = self.base / 'state'; self.target.mkdir()
        self.work = self.base / 'initialization'

    def initialize(self, expected=None, target=None):
        return self.seed.initialize(self.root, target or self.target,
            self.observed if expected is None else expected, Path('/usr/bin/tar').resolve(), self.work)

    def test_real_archive_copy_preserves_all_observations(self):
        report = self.initialize()
        self.assertEqual(report['result'], 'PASS')
        self.assertFalse(report['dataset_identity_verified'])
        self.assertEqual(image.construction.generation.scan(self.target), self.observed)
        self.assertEqual(image.construction.generation.scan(self.root), self.observed)

    def test_zero_flags_on_hardlinked_seed(self):
        os.chflags(self.root / 'kernel-alias', 0)
        self.observed = image.construction.generation.scan(self.root)
        self.assertEqual(self.initialize()['result'], 'PASS')
        self.assertEqual(image.construction.generation.scan(self.target), self.observed)

    def test_existing_state_is_preserved(self):
        (self.target / 'existing').write_bytes(b'user data')
        before = image.construction.generation.scan(self.target)
        with self.assertRaisesRegex(ValueError, 'existing state'):
            self.initialize()
        self.assertEqual(image.construction.generation.scan(self.target), before)
        self.assertFalse(self.work.exists())

    def test_partial_archive_failure_retains_state_and_refuses_retry(self):
        real_run = self.seed.subprocess.run
        def fail_extraction(argv, **kwargs):
            if '-xpf' in argv:
                (self.target / 'partial').write_bytes(b'partial state retained')
                return subprocess.CompletedProcess(argv, 1, '', 'injected extraction failure')
            return real_run(argv, **kwargs)
        with patch.object(self.seed.subprocess, 'run', side_effect=fail_extraction):
            with self.assertRaises(subprocess.CalledProcessError):
                self.initialize()
        self.assertEqual((self.target / 'partial').read_bytes(), b'partial state retained')
        self.assertFalse((self.work / 'receipt.json').exists())
        self.assertEqual(json.loads((self.work / 'construction.json').read_text())['result'], 'FAIL')
        before = image.construction.generation.scan(self.target)
        with self.assertRaisesRegex(ValueError, 'existing state'):
            self.initialize()
        self.assertEqual(image.construction.generation.scan(self.target), before)
        self.assertEqual(image.construction.generation.scan(self.root), self.observed)

    def test_symlink_destination_and_overlap_rejected(self):
        alias = self.base / 'alias'; alias.symlink_to(self.target)
        with self.assertRaisesRegex(ValueError, 'physical'):
            self.initialize(target=alias)
        nested = self.root / 'nested'; nested.mkdir()
        with self.assertRaisesRegex(ValueError, 'disjoint'):
            self.initialize(target=nested)
        self.assertFalse(self.work.exists())

    def test_stale_seed_rejected_before_output(self):
        changed = copy.deepcopy(self.observed); changed['/']['mode'] = 0
        with self.assertRaisesRegex(ValueError, 'selected observations'):
            self.initialize(expected=changed)
        self.assertFalse(self.work.exists())
        self.assertEqual(list(self.target.iterdir()), [])


class SeedDatasetInputTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('seed_dataset', Path(helper).with_name('seed_dataset.py'))
        self.dataset = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.dataset)

    def test_execution_mount_policy_is_exact(self):
        for executable, setuid in (('off', 'off'), ('on', 'off'), ('on', 'on')):
            selected = {'exec': executable, 'setuid': setuid}
            options = {'rw'} | ({'noexec'} if executable == 'off' else set()) | \
                ({'nosuid'} if setuid == 'off' else set())
            self.assertTrue(self.dataset.execution_mount_matches(options, selected))
            self.assertFalse(self.dataset.execution_mount_matches(options | {'ro'}, selected))
            for flag in ('noexec', 'nosuid'):
                self.assertFalse(self.dataset.execution_mount_matches(options ^ {flag}, selected))
        self.assertEqual(self.dataset.execution_policy(), {'exec': 'off', 'setuid': 'off'})

    def test_initialize_inherits_only_receipted_execution(self):
        receipt = dict(format=1, scope='offline-new-state-allocation', result='PASS',
            pool_synced=True, left_unmounted=True, dataset_identity_verified=True,
            generation_authenticated=False, activation_authorized=False, runtime_class_assigned=False,
            empty_observation_sha256='a' * 64, dataset='pool/state/new', pool_guid='1', parent_guid='2')
        for selected in (None, {'exec': 'on', 'setuid': 'off'}, {'exec': 'on', 'setuid': 'on'}):
            candidate = dict(receipt)
            if selected is not None:
                candidate['execution'] = selected
            with patch.object(self.dataset, '_provision') as provision:
                self.dataset.initialize_allocated('/absent', {}, candidate, {}, '/absent-work')
            self.assertEqual(provision.call_args.kwargs['execution'],
                selected or {'exec': 'off', 'setuid': 'off'})
        for invalid in (None, {}, {'exec': 'off', 'setuid': 'on'}):
            with patch.object(self.dataset, '_provision') as provision, self.assertRaises(ValueError):
                self.dataset.initialize_allocated('/absent', {}, dict(receipt, execution=invalid), {}, '/absent-work')
            provision.assert_not_called()

    def test_canonical_child_names(self):
        self.assertEqual(self.dataset.dataset_name('pool/state/service-1'), 'pool/state/service-1')
        for name in ('pool', '/pool/state', 'pool//state', 'pool/../state',
                     'pool/state@snapshot', 'pool/state#bookmark', '-pool/state', 'pool/state;cmd', None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.dataset.dataset_name(name)

    def test_invalid_identity_rejected_before_any_filesystem_access(self):
        for guid in ('0', '-1', '', '12\n', str(2**64), 123):
            with self.subTest(guid=guid), self.assertRaisesRegex(ValueError, 'GUIDs'):
                self.dataset.provision('/absent-source', {}, 'pool/state/new', guid, '1', {}, '/absent-work')


    def test_incomplete_allocation_receipts_refused(self):
        for receipt in ({}, {'format': 1, 'scope': 'offline-new-state-allocation',
                            'result': 'RUNNING'},
                        {'format': 1, 'scope': 'offline-new-state-dataset', 'result': 'PASS'}):
            with self.assertRaisesRegex(ValueError, 'completed empty dataset allocation'):
                self.dataset.initialize_allocated('/absent', {}, receipt, {}, '/absent-work')


class SourceGuards(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'root';self.root.mkdir()
        self.payload=self.root/'payload';self.payload.write_bytes(b'original')
        self.observed=image.construction.generation.scan(self.root)
        self.output=self.base/'output';self.mutate=False;self.fail=False
        self.projections=[dict(boundary=None,content='immutable',observed=self.observed),dict(boundary='/state',content='ordinary',observed={})]

    def worker(self, root, observed, tools, work, **kwargs):
        if self.fail:raise ValueError('image readback mismatch')
        work=Path(work);work.mkdir()
        report=dict(result='PASS')
        if self.mutate:self.payload.write_bytes(b'changed')
        return report

    def layout(self):
        with patch.object(image.os,'geteuid',return_value=0), patch.object(image,'partitions',return_value=({},self.projections)), patch.object(image,'_materialize',side_effect=self.worker), patch.object(image,'verify_layout',return_value={}):
            return image.materialize_layout(self.root,self.observed,{}, {},{},self.output)

    def test_verity_policy_reaches_only_immutable_base(self):
        # The partitioner is mocked here; supply its required staging slots in
        # that synthetic projection. This test checks argument routing only.
        self.projections[0]['observed'] = dict(self.observed, **{
            '/.mount': dict(type='directory',uid=0,mode=0o755),
            '/dev': dict(type='directory',uid=0,mode=0o755)})
        selected=dict(format=1,block_size=4096,salt_hex='aabb')
        bindings=dict(verity_policy=selected,verity_policy_file_sha256='1'*64)
        with patch.object(image.os,'geteuid',return_value=0), patch.object(image,'partitions',return_value=({},self.projections)), patch.object(image,'_materialize',side_effect=self.worker) as worker, patch.object(image,'verify_layout',return_value={}):
            result=image.materialize_layout(self.root,self.observed,{}, {},{},
                                            self.output,input_bindings=bindings)
        self.assertEqual(result['input_bindings'],bindings)
        self.assertEqual(worker.call_args_list[0].kwargs['verity_policy'],selected)
        self.assertIsNone(worker.call_args_list[1].kwargs['verity_policy'])

    def test_layout_two_source_scans_for_multiple_images(self):
        real=image.construction.generation.scan
        with patch.object(image.construction.generation,'scan',wraps=real) as scan:
            self.assertEqual(self.layout()['result'],'PASS')
            self.assertEqual(scan.call_count,2)

    def test_layout_rejects_preexisting_mutation(self):
        self.payload.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'before layout'):self.layout()
        self.assertFalse(self.output.exists())

    def test_layout_rejects_mutation_during_image_work(self):
        self.mutate=True
        with self.assertRaisesRegex(ValueError,'during layout'):self.layout()
        self.assertFalse((self.output/'receipt.json').exists())
        self.assertFalse(list(self.output.glob('*/receipt.json')))
        self.assertEqual(json.loads((self.output/'construction.json').read_text())['result'],'FAIL')

    def test_layout_does_not_accept_failed_image(self):
        self.fail=True
        with self.assertRaisesRegex(ValueError,'image readback mismatch'):self.layout()
        self.assertFalse((self.output/'receipt.json').exists())

    def test_standalone_rejects_mutation_and_removes_receipt(self):
        self.mutate=True
        with patch.object(image.os,'geteuid',return_value=0),patch.object(image,'_materialize',side_effect=self.worker):
            with self.assertRaisesRegex(ValueError,'during image'):
                image.materialize(self.root,self.observed,{},self.output)
        self.assertFalse((self.output/'receipt.json').exists())
        self.assertFalse(list(self.output.glob('*/receipt.json')))
        self.assertEqual(json.loads((self.output/'construction.json').read_text())['result'],'FAIL')

    def test_standalone_success_checks_source_twice(self):
        real=image.construction.generation.scan
        with patch.object(image.os,'geteuid',return_value=0),patch.object(image,'_materialize',side_effect=self.worker),patch.object(image.construction.generation,'scan',wraps=real) as scan:
            self.assertEqual(image.materialize(self.root,self.observed,{},self.output)['result'],'PASS')
            self.assertEqual(scan.call_count,2)

    def test_standalone_receipt_waits_for_final_scan(self):
        real=image.construction.generation.scan
        def scan(root):
            self.assertFalse((self.output/'receipt.json').exists())
            return real(root)
        with patch.object(image.os,'geteuid',return_value=0),patch.object(image,'_materialize',side_effect=self.worker),patch.object(image.construction.generation,'scan',side_effect=scan):
            image.materialize(self.root,self.observed,{},self.output)
        self.assertTrue((self.output/'receipt.json').is_file())

    def test_layout_receipts_wait_for_final_scan(self):
        real=image.construction.generation.scan
        def scan(root):
            self.assertFalse((self.output/'receipt.json').exists())
            self.assertFalse(list(self.output.glob('*/receipt.json')))
            return real(root)
        with patch.object(image.construction.generation,'scan',side_effect=scan):
            self.layout()
        self.assertEqual(len(list(self.output.glob('*/receipt.json'))),2)


if __name__ == '__main__':
    unittest.main(defaultTest=['SourceGuards', 'RequiredPolicySelection', 'ImagePreflight', 'BootArchiveTests', 'PartitionTests', 'LayoutReceiptTests', 'SeedInitializationTests', 'SeedDatasetInputTests'])
