# SPDX-License-Identifier: BSD-2-Clause
"""Filesystem/receipt tests; execution and jail lifecycle are mocked explicitly."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

helper = os.environ.get('BSD_BUILD_CONSTRUCTION_HELPER') or str(
    Path(__file__).resolve().parents[3] / 'tools/build/capimage/construction.py')
spec = importlib.util.spec_from_file_location('construction', helper)
construction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(construction)


class Construction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.output = self.base / 'root', self.base / 'report'
        self.root.mkdir(mode=0o755)
        os.chown(self.root, os.getuid(), os.getgid())
        self.write('/tool', b'fixture executable', 0o755)
        self.write('/input', b'explicit input')
        if self.root.stat().st_flags:
            os.chflags(self.root, 0)
        self.metadata = {'type': 'file', 'uid': os.getuid(), 'gid': os.getgid(),
                         'mode': 0o644, 'flags_set': 0, 'replace': False}
        self.actions = [{'name': 'derive', 'argv': ['/tool', '/input'], 'inputs': ['/input'],
                         'outputs': {'/output': self.metadata}}]
        self.initial = {'format': 1, 'entries': {'/': {'type': 'directory',
            'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o755, 'flags_set': 0,
            'source': 'explicit test layout', 'replaces': []}}}
        self.calls = []

    def write(self, path, data=b'derived', mode=0o644):
        target = self.root / path.lstrip('/')
        target.write_bytes(data)
        target.chmod(mode)
        os.chown(target, os.getuid(), os.getgid())
        os.utime(target, (1700000000, 1700000000))
        # Fixture metadata is explicit; ZFS sets UF_ARCHIVE on writes/utimes.
        if target.stat().st_flags:
            os.chflags(target, 0)

    def inventory(self, manifest_fields=None):
        archive_path = self.base / 'fixture.pkg'
        entries = [p for p in self.root.iterdir() if p.is_file()]
        manifest = {'name': 'fixture', 'version': '1',
                    'files': {'/' + p.name: {} for p in entries},
                    'annotations': {'5bsd.construction': json.dumps({'format': 1, 'actions': self.actions})}}
        if manifest_fields is not None:
            manifest.update(manifest_fields)
        if not self.actions:
            manifest.pop('annotations', None)
        with tarfile.open(archive_path, 'w:gz') as archive:
            data = json.dumps(manifest).encode()
            header = tarfile.TarInfo('+MANIFEST'); header.size = len(data)
            archive.addfile(header, io.BytesIO(data))
            for path in entries:
                data = path.read_bytes(); metadata = path.stat()
                header = tarfile.TarInfo('/' + path.name)
                header.mode = metadata.st_mode & 0o7777
                header.uid, header.gid = os.getuid(), os.getgid()
                header.size, header.mtime = len(data), 1700000000
                archive.addfile(header, io.BytesIO(data))
        if self.root.stat().st_flags:
            os.chflags(self.root, 0)
        return construction.pkg.inventory_packages([archive_path])

    def execute(self, root, argv, log, timeout):
        self.calls.append(argv)
        self.assertEqual(root, self.root)
        self.write('/output')
        log.write_text('fixture executor; no jail or generator was run\n')

    def test_planned_output_hash_accepts_exact_content(self):
        inventory = self.inventory()
        inventory['construction']['actions'][0]['planned_hashes'] = {
            '/output': hashlib.sha256(b'derived').hexdigest()}
        self.assertEqual(self.run_construct(inventory)['result'], 'PASS')

    def test_planned_output_hash_rejects_partial_content(self):
        inventory = self.inventory()
        inventory['construction']['actions'][0]['planned_hashes'] = {
            '/output': hashlib.sha256(b'complete ordered output').hexdigest()}
        with self.assertRaisesRegex(ValueError, 'approved search order'):
            self.run_construct(inventory)
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def run_construct(self, inventory=None, execute=None):
        return construction.construct(self.root, inventory or self.inventory(), self.initial,
                                      self.output, execute=execute or self.execute)

    def test_final_storage_layout_includes_generated_output(self):
        policy = {'format': 1, 'boundaries': []}
        report = construction.construct(self.root, self.inventory(), self.initial,
            self.output, execute=self.execute, storage_layout_policy=policy)
        layout = json.loads((self.output / 'storage-layout.json').read_text())
        self.assertIn('/output', layout['immutable_objects'])
        self.assertEqual(report['storage_layout']['layout_sha256'], construction.digest(layout))
        self.assertEqual(report['storage_layout']['filesystem_sha256'], report['filesystem_sha256'])
        self.assertEqual(report['storage_layout']['policy_sha256'], construction.digest(policy))
        self.assertFalse(report['storage_layout']['runtime_qualified'])

    def protected_input_policy(self, inventory, path='/output', boundaries=None):
        return dict(format=2, boundaries=boundaries or [], protected_consumers=[dict(
            consumer='/tool', package_archive_sha256=inventory['packages'][0]['archive_sha256'],
            inputs=[dict(path=path, presence='required')])])

    def test_protected_generated_input_bound_after_construction(self):
        inventory = self.inventory()
        policy = self.protected_input_policy(inventory)
        self.assertFalse((self.root / 'output').exists())
        report = construction.construct(self.root, inventory, self.initial,
            self.output, execute=self.execute, storage_layout_policy=policy)
        layout = json.loads((self.output / 'storage-layout.json').read_text())
        row, = layout['protected_inputs']['bindings'][0]['inputs']
        self.assertEqual(row['sha256'], hashlib.sha256(b'derived').hexdigest())
        self.assertEqual(report['storage_layout']['layout_sha256'], construction.digest(layout))
        self.assertEqual(report['storage_layout']['policy_sha256'], construction.digest(policy))
        generated = json.loads((self.output / 'generated.json').read_text())
        reconciled = construction.generation.reconcile(self.root, inventory, generated, policy)
        self.assertEqual(reconciled['result'], 'PASS')
        self.assertEqual(reconciled['storage_layout'], layout)
        self.assertEqual(reconciled['protected_consumer_code'], report['protected_consumer_code'])
        self.assertFalse(report['protected_consumer_code']['dependency_coverage_complete'])
        self.assertEqual(report['protected_consumer_code']['consumers'][0]['kind'], 'non-elf')
        self.assertFalse(reconciled['generation_authenticated'])
        # Unexplained changes are rejected before any successful input binding.
        self.write('/output', b'changed after construction')
        with self.assertRaisesRegex(ValueError, 'exactly reconciled'):
            construction.generation.reconcile(self.root, inventory, generated, policy)

    def test_missing_protected_input_prevents_success_receipts(self):
        inventory = self.inventory()
        policy = self.protected_input_policy(inventory, '/missing-policy')
        with self.assertRaisesRegex(ValueError, 'resolved regular file'):
            construction.construct(self.root, inventory, self.initial,
                self.output, execute=self.execute, storage_layout_policy=policy)
        self.assertTrue(self.calls)
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertFalse((self.output / 'storage-layout.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def test_generated_policy_in_ordinary_storage_prevents_success_receipts(self):
        (self.root / 'state').mkdir(mode=0o755)
        os.chflags(self.root / 'state', 0)
        self.initial['entries']['/state'] = dict(self.initial['entries']['/'])
        self.actions[0]['outputs'] = {'/state/output': self.metadata}
        inventory = self.inventory()
        policy = self.protected_input_policy(inventory, '/state/output',
            [dict(path='/state', content='ordinary')])
        def execute(root, argv, log, timeout):
            self.calls.append(argv)
            self.write('/state/output')
            log.write_text('fixture executor; no jail or generator was run\n')
        with self.assertRaisesRegex(ValueError, 'traverses mutable'):
            construction.construct(self.root, inventory, self.initial,
                self.output, execute=execute, storage_layout_policy=policy)
        self.assertTrue(self.calls)
        self.assertTrue((self.root / 'state/output').is_file())
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertFalse((self.output / 'storage-layout.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def test_invalid_final_layout_refuses_success_and_manifest(self):
        policy = {'format': 1, 'boundaries': [{'path': '/output', 'content': 'ordinary'}]}
        with self.assertRaisesRegex(ValueError, 'physical existing directories'):
            construction.construct(self.root, self.inventory(), self.initial,
                self.output, execute=self.execute, storage_layout_policy=policy)
        self.assertTrue(self.calls)
        self.assertTrue((self.root / 'output').is_file())
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertFalse((self.output / 'storage-layout.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def certificate_fixture(self):
        self.actions = []
        for path in ('/store', '/store/trusted', '/store/denied'):
            (self.root / path.lstrip('/')).mkdir()
            self.initial['entries'][path] = dict(self.initial['entries']['/'])
        for path in ('/store/trusted', '/store/denied', '/store'):
            os.chflags(self.root / path.lstrip('/'), 0)
        policy = {'format': 1, 'name': 'certificates', 'program': '/tool',
                  'selections': [], 'files': [{'path': '/input', 'role': 'trusted'}],
                  'overrides': [], 'outputs': {'trusted_directory': '/store/trusted',
                  'untrusted_directory': '/store/denied', 'bundle': '/store/bundle',
                  'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o444, 'flags_set': 0}}
        return self.inventory(), policy

    def test_certificate_size_mismatch_is_not_approved(self):
        inventory, policy = self.certificate_fixture()
        def execute(root, argv, log, timeout):
            if '-n' in argv:
                log.write_text('./store/bundle type=file uname=root gname=wheel mode=0444 size=9\n')
            else:
                self.write('/store/bundle', b'short')
                log.write_text('mock certificate execution\n')
        with self.assertRaisesRegex(ValueError, 'planned size'):
            construction.construct(self.root, inventory, self.initial, self.output,
                                   execute=execute, certificate_policy=policy)
        self.assertFalse((self.output / 'generated.json').exists())
        report = json.loads((self.output / 'construction.json').read_text())
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['receipts'], [])

    def test_certificate_planner_changes_are_not_approved(self):
        inventory, policy = self.certificate_fixture()
        def execute(root, argv, log, timeout):
            log.write_text('./store/bundle type=file uname=root gname=wheel mode=0444 size=0\n')
            self.write('/unexpected', b'planner changed candidate')
        with self.assertRaisesRegex(ValueError, 'planning modified'):
            construction.construct(self.root, inventory, self.initial, self.output,
                                   execute=execute, certificate_policy=policy)
        self.assertFalse((self.output / 'generated.json').exists())

    def test_receipt_records_checked_output(self):
        result = self.run_construct()
        self.assertEqual(result['result'], 'PASS')
        self.assertFalse(result['inputs_authenticated'])
        self.assertFalse(result['generation_authenticated'])
        receipt = result['receipts'][0]
        generated = json.loads((self.output / 'generated.json').read_text())
        self.assertEqual(generated['entries']['/output']['sha256'], hashlib.sha256(b'derived').hexdigest())
        self.assertEqual(generated['entries']['/output']['source'], 'construction receipt sha256:' + receipt['sha256'])
        self.assertEqual(receipt['inputs']['/input']['sha256'], hashlib.sha256(b'explicit input').hexdigest())
        self.assertEqual(result['generated_sha256'], construction.digest(generated))

    def test_input_change_stops_execution(self):
        inventory = self.inventory()
        self.write('/input', b'not authorized')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.run_construct(inventory)
        self.assertFalse(self.calls)
        self.assertFalse(self.output.exists())

    def test_explicit_site_input_is_bound_to_receipt(self):
        inventory = self.inventory()
        self.write('/input', b'approved site input')
        actual = construction.generation.scan(self.root)['/input']
        self.initial['entries']['/input'] = {k: actual[k] for k in
            ('type', 'uid', 'gid', 'mode', 'flags_set', 'size', 'sha256')}
        self.initial['entries']['/input'].update(source='explicit site input',
            replaces=[inventory['packages'][0]['archive_sha256']])
        result = self.run_construct(inventory)
        self.assertEqual(result['receipts'][0]['inputs']['/input']['sha256'], actual['sha256'])

    def test_missing_output_directory_prevents_execution(self):
        self.actions[0]['outputs'] = {'/missing/output': self.metadata}
        with self.assertRaisesRegex(ValueError, 'output directory'):
            self.run_construct()
        self.assertFalse(self.calls)
        self.assertFalse(self.output.exists())

    def test_preapproved_output_rejected(self):
        inventory = self.inventory()
        self.initial['entries']['/output'] = {}
        with self.assertRaisesRegex(ValueError, 'preapproved'):
            self.run_construct(inventory)
        self.assertFalse(self.calls)

    def test_declared_output_metadata_applied(self):
        def execute(*args):
            self.execute(*args)
            (self.root / 'output').chmod(0o666)
        self.run_construct(execute=execute)
        self.assertEqual((self.root / 'output').stat().st_mode & 0o7777, 0o644)

    def test_unknown_side_effect_rejected(self):
        def execute(*args):
            self.execute(*args)
            self.write('/unexplained')
        with self.assertRaisesRegex(ValueError, 'unexplained construction object'):
            self.run_construct(execute=execute)
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def test_modified_source_rejected(self):
        def execute(*args):
            self.execute(*args)
            self.write('/input', b'changed by generator')
        with self.assertRaisesRegex(ValueError, 'undeclared construction change'):
            self.run_construct(execute=execute)

    def test_symlink_output_rejected(self):
        def execute(*args):
            (self.root / 'output').symlink_to('input')
        with self.assertRaisesRegex(ValueError, 'unaliased regular file'):
            self.run_construct(execute=execute)

    def test_hardlink_output_rejected(self):
        def execute(*args):
            os.link(self.root / 'input', self.root / 'output')
        with self.assertRaisesRegex(ValueError, 'unaliased regular file'):
            self.run_construct(execute=execute)

    def test_missing_output_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unaliased regular file'):
            self.run_construct(execute=lambda *args: None)

    def test_execution_or_cleanup_failure_cannot_approve(self):
        for error in [subprocess.CalledProcessError(1, ['/tool']), TimeoutError('descendants remain')]:
            with self.subTest(error=error):
                destination = self.base / type(error).__name__
                def execute(*args):
                    self.write('/output')
                    raise error
                inventory = self.inventory()
                with self.assertRaises(type(error)):
                    construction.construct(self.root, inventory, self.initial, destination, execute=execute)
                self.assertFalse((destination / 'generated.json').exists())
                (self.root / 'output').unlink()

    def test_failed_final_receipt_removes_generated_manifest(self):
        writer = construction.write_record
        def fail_final_receipt(path, value):
            if path.name == 'construction.json' and value.get('result') == 'PASS':
                raise OSError('injected final receipt failure')
            writer(path, value)
        with patch.object(construction, 'write_record', side_effect=fail_final_receipt):
            with self.assertRaisesRegex(OSError, 'final receipt failure'):
                self.run_construct()
        self.assertFalse((self.output / 'generated.json').exists())
        self.assertEqual(json.loads((self.output / 'construction.json').read_text())['result'], 'FAIL')

    def test_archive_dependency_checks_precede_construction(self):
        cases = [
            ({'deps': {'runtime': {'origin': 'base/runtime', 'version': '1'}}}, 'lacks dependencies'),
            ({'deps': []}, 'invalid dependency map'),
            ({'conflicts': ['fixture']}, 'declare package conflicts'),
            ({'conflicts': 'fixture'}, 'invalid package conflicts'),
            ({'deps': {'runtime': {'origin': 'base/runtime'}}}, 'invalid dependency identity'),
            ({'shlibs_required': ['libmissing.so.1']}, 'lacks shared-library providers'),
        ]
        for fields, message in cases:
            with self.subTest(fields=fields):
                record = self.inventory(fields)
                # Caller-written derived metadata cannot hide archive requirements.
                record['packages'][0]['manifest'].pop('deps', None)
                record['packages'][0]['manifest'].pop('shlibs_required', None)
                with self.assertRaisesRegex(ValueError, message):
                    construction.inventory_from_archives(record)
                self.assertFalse(self.output.exists())
                self.assertEqual(self.calls, [])

    def test_archive_dependency_provider_identity_and_version(self):
        record = self.inventory({'deps': {'runtime': {'origin': 'base/runtime', 'version': '1'}},
                                 'shlibs_required': ['libruntime.so.1']})
        consumer = Path(record['packages'][0]['archive'])
        provider = self.base / 'runtime.pkg'
        for origin in ('wrong/runtime', 'base/runtime'):
            manifest = {'name': 'runtime', 'origin': origin, 'version': '2',
                        'files': {}, 'shlibs_provided': ['libruntime.so.1']}
            with tarfile.open(provider, 'w:gz') as archive:
                data = json.dumps(manifest).encode()
                header = tarfile.TarInfo('+MANIFEST'); header.size = len(data)
                archive.addfile(header, io.BytesIO(data))
            record = construction.pkg.inventory_packages([consumer, provider])
            with self.subTest(origin=origin):
                if origin != 'base/runtime':
                    with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                        construction.inventory_from_archives(record)
                else:
                    fresh = construction.inventory_from_archives(record)
                    self.assertEqual([p['name'] for p in fresh['packages']], ['fixture', 'runtime'])
                    # The recorded dependency version is not an exact solver pin.
                    self.assertEqual(fresh['packages'][1]['version'], '2')

    def test_archive_change_rejected(self):
        inventory = self.inventory()
        Path(inventory['packages'][0]['archive']).touch()
        inventory['packages'][0]['archive_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'archive changed'):
            construction.inventory_from_archives(inventory)

    def test_injected_derived_plan_is_ignored(self):
        inventory = self.inventory()
        inventory['construction']['actions'][0]['argv'] = ['/unpackaged-tool']
        fresh = construction.inventory_from_archives(inventory)
        self.assertEqual(fresh['construction']['actions'][0]['argv'], ['/tool', '/input'])

    def test_package_replacement_is_explicit(self):
        self.write('/output', b'original package data')
        self.metadata['replace'] = True
        inventory = self.inventory()
        self.run_construct(inventory)
        generated = json.loads((self.output / 'generated.json').read_text())
        self.assertEqual(generated['entries']['/output']['replaces'], [inventory['packages'][0]['archive_sha256']])


class JailLifecycle(unittest.TestCase):
    def test_descendants_must_disappear_before_return(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'log'
            with patch.object(construction, 'find_jail', side_effect=[None, '7', '7', '7', None]), \
                 patch.object(construction, 'command') as command, patch.object(construction.time, 'sleep') as sleep:
                construction.run_jailed(Path('/private/root'), ['/tool', 'argument with spaces'], log, 9)
                self.assertEqual(command.call_args_list[1].args[0], ['/usr/sbin/jexec', '7', '/tool', 'argument with spaces'])
                self.assertIn('-r', command.call_args_list[2].args[0])
                sleep.assert_called_once_with(0.1)

    def test_execution_failure_still_removes_jail(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(construction, 'find_jail', side_effect=[None, '7', '7', None]), \
                 patch.object(construction, 'command', side_effect=[None, subprocess.CalledProcessError(1, ['/tool']), None]) as command:
                with self.assertRaises(subprocess.CalledProcessError):
                    construction.run_jailed(Path('/private/root'), ['/tool'], Path(directory) / 'log', 9)
                self.assertIn('-r', command.call_args_list[-1].args[0])

    def test_identity_mismatch_refuses_removal(self):
        with patch.object(construction, 'jail_list', return_value=[{'jid': 7, 'name': 'selected', 'path': '/elsewhere'}]):
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                construction.find_jail('selected', Path('/private/root'))

    def test_no_ambient_environment_or_descriptors(self):
        with patch.object(construction.subprocess, 'run') as run:
            construction.command(['/tool'], timeout=10)
            self.assertEqual(run.call_args.kwargs['env'], construction.ENVIRONMENT)
            self.assertTrue(run.call_args.kwargs['close_fds'])
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs['umask'], 0o022)


if __name__ == '__main__':
    unittest.main()
