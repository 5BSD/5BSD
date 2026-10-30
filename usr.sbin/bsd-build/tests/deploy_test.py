import copy
from contextlib import redirect_stdout
import importlib.util
import hashlib
import io
import json
import tarfile
import shutil
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
helper = os.environ.get('BSD_BUILD_DEPLOY_HELPER', str(Path(__file__).resolve().parents[3] / 'tools/build/capimage/deploy.py'))
spec = importlib.util.spec_from_file_location('deploy', helper)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentFootprint(unittest.TestCase):
    def test_be_fixture_consumes_candidate_record_and_unmounts_on_failure(self):
        spec = importlib.util.spec_from_file_location('be_fixture',
            Path(__file__).with_name('be_vm_test.py'))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        for reject in (False, True):
            with self.subTest(target_rejected=reject), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                target = directory / 'candidate'
                target.mkdir()
                (target / 'etc').mkdir()
                (target / 'etc/clone-sentinel').write_text('source remains unchanged\n')
                source = {'guid': '1'}
                candidate = {'command': ['bectl', '-r', 'test/ROOT'],
                             'dataset': 'test/ROOT/candidate', 'guid': '2',
                             'origin': 'test/ROOT/base@snapshot'}
                def check(*args):
                    self.assertEqual(args, (target, source, 'candidate'))
                    if reject:
                        raise ValueError('target rejected')
                helper = SimpleNamespace(
                    be_source=lambda *a, **k: source,
                    be_create=lambda *a: candidate,
                    be_check_target=check,
                    zfs_properties=lambda dataset: {'readonly': 'on'})
                with patch.object(fixture, 'run') as run:
                    if reject:
                        with self.assertRaisesRegex(ValueError, 'target rejected'):
                            fixture.check_clone(helper, 'test/ROOT', directory,
                                'base', 'candidate', [])
                    else:
                        fixture.check_clone(helper, 'test/ROOT', directory,
                            'base', 'candidate', [])
                    self.assertEqual(run.call_args_list, [
                        unittest.mock.call('bectl', '-r', 'test/ROOT', 'mount', 'candidate', target),
                        unittest.mock.call('bectl', '-r', 'test/ROOT', 'unmount', 'candidate')])
                self.assertEqual((target / 'etc/clone-sentinel').read_text(),
                    'source remains unchanged\n' if reject else 'candidate only\n')

    def test_be_property_fixture_rejects_changed_values_and_remaining_clones(self):
        spec = importlib.util.spec_from_file_location('be_fixture',
            Path(__file__).with_name('be_vm_test.py'))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        for alternate in ('', '/guest/alternate'):
            for defect in (None, 'quota', 'special', 'prefix', 'remaining-child', 'missing-source'):
                with self.subTest(alternate=alternate, defect=defect):
                    root = 'private/ROOT'
                    source = root + '/properties-test'
                    candidate = root + '/properties-copy-test'
                    calls = []
                    def command(*args):
                        calls.append(args)
                        if args[:2] == ('/sbin/zfs', 'get'):
                            prop, dataset = args[-2:]
                            if prop in ('quota', 'refquota'):
                                value = {'quota': '123456789', 'refquota': '98765432'}[prop]
                                return '118M' if defect == 'quota' and dataset == candidate else value
                            if prop == 'canmount':
                                return 'noauto'
                            suffix = dataset[len(candidate):] if dataset.startswith(candidate) else dataset[len(source):]
                            value = {'': alternate or '/', '/data': alternate + '/var/property-test',
                                     '/none': 'none', '/legacy': 'legacy'}[suffix]
                            if dataset.startswith(candidate):
                                if defect == 'special' and suffix == '/none':
                                    return '/'
                                if defect == 'prefix' and suffix == '/data':
                                    return alternate + value + '/wrong'
                            return value
                        if args[:2] == ('/sbin/zfs', 'list'):
                            names = [source + suffix for suffix in ('', '/data', '/none', '/legacy')]
                            if defect == 'remaining-child':
                                names.append(candidate + '/data')
                            if defect == 'missing-source':
                                names.remove(source + '/legacy')
                            return '\n'.join(names)
                        return ''
                    output = io.StringIO()
                    with patch.object(fixture, 'run', side_effect=command), redirect_stdout(output):
                        if defect:
                            with self.assertRaises(AssertionError):
                                fixture.check_clone_properties(root, 'test', alternate)
                        else:
                            fixture.check_clone_properties(root, 'test', alternate)
                    self.assertEqual('BE_VM_PASS' in output.getvalue(), defect is None)
                    if defect in ('quota', 'special', 'prefix'):
                        self.assertFalse(any('destroy' in args for args in calls))

    def test_be_activation_fixture_requires_selection_preservation_and_retry(self):
        spec = importlib.util.spec_from_file_location('be_fixture',
            Path(__file__).with_name('be_vm_test.py'))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        root = 'private/ROOT'
        source = root + '/activation-source-test'
        candidate = root + '/activation-copy-test'
        prior = root + '/base'
        for defect in (None, 'failed-selection', 'replaced', 'retry', 'restore', 'removal'):
            with self.subTest(defect=defect):
                state = {'bootfs': prior, 'origin': source + '@conflict', 'guid': '2'}
                def command(*args):
                    if args[:2] == ('/sbin/zpool', 'get'):
                        return state['bootfs']
                    if args[:2] == ('/sbin/zfs', 'get'):
                        return state[args[-2]]
                    if args[:2] == ('/sbin/zfs', 'list'):
                        return '\n'.join([source, prior] + ([candidate] if defect == 'removal' else []))
                    if args[:4] == ('bectl', '-r', root, 'activate'):
                        if args[-1] == prior:
                            if defect != 'restore':
                                state['bootfs'] = prior
                        else:
                            if defect != 'retry':
                                state['bootfs'] = candidate
                            state['origin'] = '-'
                    return ''
                def refused(*args):
                    self.assertEqual(args, ('bectl', '-r', root, 'activate', 'activation-copy-test'))
                    if defect == 'failed-selection':
                        state['bootfs'] = candidate
                    if defect == 'replaced':
                        state['guid'] = 'replacement'
                output = io.StringIO()
                with patch.object(fixture, 'run', side_effect=command), \
                     patch.object(fixture, 'refuse', side_effect=refused), redirect_stdout(output):
                    if defect:
                        with self.assertRaises(AssertionError):
                            fixture.check_activation_failure(root, 'test')
                    else:
                        fixture.check_activation_failure(root, 'test')
                self.assertEqual('BE_VM_PASS' in output.getvalue(), defect is None)

    def test_be_fixture_refuses_disabled_assertions_before_actions(self):
        fixture = Path(__file__).with_name('be_vm_test.py')
        for flags, setting in ((['-O'], None), (['-OO'], None), ([], '1')):
            with self.subTest(flags=flags, environment=setting):
                environment = dict(os.environ)
                environment.pop('PYTHONOPTIMIZE', None)
                if setting is not None:
                    environment['PYTHONOPTIMIZE'] = setting
                # --help guarantees the unfixed fixture cannot reach guest or
                # pool operations. The guard must refuse even before parsing.
                result = subprocess.run([sys.executable, '-B', *flags,
                    str(fixture), '--help'], env=environment,
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requires Python assertions enabled', result.stderr)
                self.assertNotIn('BE_VM_COMMAND', result.stdout)

    def test_private_builder_parent_requires_ownership_and_exact_mode(self):
        root = Path('/builder/candidate')
        for uid, mode in ((0, 0o40755), (0, 0o40777), (1001, 0o40700)):
            with self.subTest(uid=uid, mode=mode), \
                 patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=uid, st_mode=mode)):
                with self.assertRaisesRegex(ValueError, 'root-owned mode-0700'):
                    deploy.private_builder_parent(root)
        with patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o40700)):
            deploy.private_builder_parent(root)

    def test_package_and_generated_paths_cover_new_locations(self):
        paths = deploy.deployment_private_paths({
            '/site/engine/lib/module.so': {'type': 'file'},
            '/owner/policy': {'type': 'directory'}})
        self.assertIn('site/engine/lib', paths)
        self.assertIn('owner/policy', paths)
        self.assertNotIn('site/engine/lib/module.so', paths)
        mounts = [('zroot/ROOT/current', Path('/'), 'zfs', ['rw']),
                  ('zroot/site', Path('/site/engine'), 'zfs', ['rw'])]
        with patch.object(deploy, 'mount_inventory', return_value=mounts), \
             patch.object(deploy, 'zfs_properties', return_value={'guid': '1'}):
            with self.assertRaisesRegex(ValueError, 'shared or separately mounted'):
                deploy.be_source(private_paths=paths)

    def test_candidate_nested_mount_outside_payload_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = {'root': 'zroot/ROOT', 'private_paths':
                      deploy.deployment_private_paths({})}
            mounts = [('zroot/ROOT/new', root, 'zfs', ['rw']),
                      ('shared', root / 'unlisted-data', 'zfs', ['rw'])]
            with patch.object(deploy, 'mount_inventory', return_value=mounts):
                with self.assertRaisesRegex(ValueError, 'nested mount'):
                    deploy.be_check_target(root, source, 'new')

    def test_new_package_parent_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'site').symlink_to('/tmp')
            source = {'root': 'zroot/ROOT', 'private_paths':
                      deploy.deployment_private_paths({'/site/program': {'type': 'file'}})}
            with patch.object(deploy, 'mount_inventory', return_value=[
                    ('zroot/ROOT/new', root, 'zfs', ['rw'])]):
                with self.assertRaisesRegex(ValueError, 'not private'):
                    deploy.be_check_target(root, source, 'new')


class Deployment(unittest.TestCase):
    def test_literal_file_repository_url(self):
        repository = Path('/tmp/FreeBSD:16:amd64 space %23 # repository')
        definition = json.loads(deploy.repository_definition(repository, Path('/tmp/key.pub')))
        self.assertEqual(definition['bsd_build']['url'], 'file://' + str(repository))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        os.chown(self.base, os.getuid(), os.getgid())
        self.repo = self.base / 'custom-publication/generation'
        self.repo.mkdir(parents=True)
        (self.repo / 'publication.json').write_text('{}')
        self.runs = self.base / 'runs'
        self.runs.mkdir()
        self.key = self.base / 'public'
        self.key.write_text('mock public key')
        self.tool = self.base / 'tool'
        self.tool.write_text('#!/bin/sh\nexit 0\n')
        self.tool.chmod(0o755)
        self.generated = self.base / 'generated.json'
        self.generated.write_text(json.dumps({'format': 1, 'entries': {
            path: {'type': 'directory', 'uid': os.getuid(), 'gid': os.getgid(),
                   'mode': 0o755, 'flags_set': 0, 'source': 'declared fixture layout', 'replaces': []}
            for path in ('/', '/dev', '/var', '/var/db', '/var/db/pkg', '/bin', '/etc', '/fixture')}}))
        self.calls = []
        self.construction_annotation = None
        self.shlibs_required = []
        self.dependencies = {}
        self.fail_at = None
        self.verification_error = None
        self.verification_calls = []
        self.devfs_mounts = set()
        self.names = ['5BSD-set-base', '5BSD-kernel-generic', '5BSD-hardware-abi-test-1']
        self.hardware = SimpleNamespace(
            copy_public_key=shutil.copyfile,
            verify=lambda path: {'abi': 'FreeBSD:16:amd64', 'osversion': 1600018},
            manifest=lambda path: {'name': '5BSD-set-base'},
            sha256=lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest())

    def run_command(self, *args, capture=False):
        words = list(map(str, args))
        self.calls.append(words)
        if words[0] == 'bectl' and words[3] == 'mount':
            Path(words[-1]).mkdir()
        if 'fetch' in words:
            target = Path(words[words.index('fetch') + 4]) / 'All'
            target.mkdir(parents=True)
            # Real archive framing exercises the production inventory reader;
            # package authentication and BE lifecycle are mocked in this unit test.
            for name in self.names:
                path = '/bin/example' if name == '5BSD-set-base' else '/fixture/' + name
                manifest = {'name': name, 'origin': 'base/' + name, 'version': '1', 'files': {path: {}},
                            'shlibs_required': self.shlibs_required}
                if name == '5BSD-set-base' and self.dependencies:
                    manifest['deps'] = self.dependencies
                if self.construction_annotation is not None:
                    manifest['annotations'] = {'5bsd.construction': self.construction_annotation}
                with tarfile.open(target / (name + '.pkg'), 'w:gz') as archive:
                    data = json.dumps(manifest).encode()
                    entry = tarfile.TarInfo('+MANIFEST'); entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
                    entry = tarfile.TarInfo(path); entry.size = 4
                    entry.uid, entry.gid = os.getuid(), os.getgid()
                    archive.addfile(entry, io.BytesIO(b'file'))
        if words[0] == 'chroot' and 'install' in words:
            # Simulate package installation, but run the real filesystem
            # reconciliation against the resulting candidate in these tests.
            root = Path(words[1])
            for name in self.names:
                target = root / ('bin/example' if name == '5BSD-set-base' else 'fixture/' + name)
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(b'file')
                target.chmod(0o644)
                os.utime(target, (0, 0))
        if words[0] == 'umount':
            root = Path(words[1]).parent
            # Explicit fixture metadata; the production reconciler does not
            # clear or disregard ZFS UF_ARCHIVE or any other flag.
            for path in (root, *root.rglob('*')):
                if not path.is_symlink():
                    os.chflags(path, 0)
        if self.fail_at and self.fail_at(words):
            raise subprocess.CalledProcessError(1, words)
        if words[:4] == ['mount', '-t', 'devfs', 'devfs']:
            self.devfs_mounts.add(words[-1])
        if words[0] == 'umount':
            self.devfs_mounts.discard(words[-1])
        if words[:2] == ['/sbin/mount', '-p']:
            output = 'zroot/ROOT/current / zfs rw 0 0\n'
            for call in self.calls:
                if call[0] == 'bectl' and len(call) > 4 and call[3] == 'mount':
                    output += 'zroot/ROOT/' + call[-2] + ' ' + call[-1] + ' zfs rw 0 0\n'
            output += ''.join('devfs ' + path + ' devfs rw 0 0\n' for path in sorted(self.devfs_mounts))
            return SimpleNamespace(stdout=output, stderr='')
        if words[:2] == ['/sbin/zfs', 'get']:
            if words[-2] == 'guid' and '@' in words[-1]:
                return SimpleNamespace(stdout='7\n', stderr='')
            created = [call for call in self.calls if call[0] == 'bectl' and call[3] == 'create']
            target = created and words[-1] == 'zroot/ROOT/' + created[-1][-1]
            source = created[-1][created[-1].index('-e')+1] if created else 'current'
            origin = 'zroot/ROOT/' + (source if '@' in source else source + '@fixture') if target else '-'
            return SimpleNamespace(stdout='guid\t' + ('2' if target else '1') + '\norigin\t' + origin + '\nreadonly\toff\n', stderr='')
        return SimpleNamespace(stdout=('FreeBSD:16:amd64\n' if words[-2:] == ['config', 'ABI'] else '\n'.join(self.names) + '\n' if 'rquery' in words else ''), stderr='')

    def run_verifier(self, args, **kwargs):
        self.verification_calls.append((args, kwargs))
        if self.verification_error is not None:
            raise subprocess.CalledProcessError(self.verification_error, args)
        return SimpleNamespace(returncode=0)

    def invoke(self, *extra, plan=False):
        argv = ['deploy', '--repository', str(self.repo), '--pkg-public-key', str(self.key),
                '--public-key', str(self.key), '--capsign', str(self.tool),
                '--generated', str(self.generated), *extra]
        if plan:
            argv.append('--plan')
        with patch.object(sys, 'argv', argv), \
             patch.object(deploy, 'RUN_ROOT', self.runs), patch.object(deploy.os, 'geteuid', return_value=0), \
             patch.object(deploy, 'private_builder_parent') as parent_check, \
             patch.object(deploy, 'load_hardware', return_value=self.hardware), \
             patch.object(deploy, 'command', side_effect=self.run_command), \
             patch.object(deploy.subprocess, 'run', side_effect=self.run_verifier):
            deploy.main()
            if '--root' in extra and not plan:
                parent_check.assert_called_once_with(Path(extra[extra.index('--root') + 1]))
            else:
                parent_check.assert_not_called()

    def test_plan_no_mutation(self):
        before = sorted(self.base.rglob('*'))
        output = io.StringIO()
        with redirect_stdout(output):
            self.invoke('--bootenv', 'review', plan=True)
        self.assertIn('trusted-builder preparation; live BIP update/activation is not implemented', output.getvalue())
        self.assertEqual(before, sorted(self.base.rglob('*')))
        self.assertEqual([], self.calls)

    def test_bundle_verification_failure_retains_candidate_without_success(self):
        self.verification_error = 1
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())
        self.assertEqual([words[3] for words in self.calls if words[0] == 'bectl'],
                         ['create', 'mount', 'unmount'])
        self.assertFalse(self.devfs_mounts)
        work, = self.runs.glob('deploy-*')
        self.assertTrue((work / 'root').is_dir())
        self.assertFalse((work / 'reconciliation.json').exists())
        (args, kwargs), = self.verification_calls
        self.assertEqual(Path(args[1]), Path(deploy.__file__).resolve().with_name('verify-stage.sh'))
        self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['env']['CAPSIGN'], str(self.tool))

    def test_fetch_failure_before_be_creation(self):
        self.fail_at = lambda words: 'fetch' in words
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_reconciliation_records_candidate_identity(self):
        self.invoke('--bootenv', 'review')
        report = json.loads(next(self.runs.glob('deploy-*/reconciliation.json')).read_text())
        self.assertEqual(report['deployment_target'], {
            'kind': 'boot-environment', 'dataset': 'zroot/ROOT/review',
            'guid': '2', 'origin': 'zroot/ROOT/current@fixture'})
        self.assertFalse(report['generation_authenticated'])

    def test_replacement_during_reconciliation_prevents_report(self):
        loader = deploy.load_generation_check
        identity_check = deploy.be_check_candidate_identity
        scanned = False
        def load():
            module = loader()
            reconcile = module.reconcile
            def scan(*args):
                nonlocal scanned
                report = reconcile(*args)
                scanned = True
                return report
            module.reconcile = scan
            return module
        def check(candidate):
            if scanned:
                raise ValueError('candidate identity changed during scan')
            return identity_check(candidate)
        output = io.StringIO()
        with patch.object(deploy, 'load_generation_check', side_effect=load), \
             patch.object(deploy, 'be_check_candidate_identity', side_effect=check), \
             redirect_stdout(output), self.assertRaisesRegex(ValueError, 'identity changed'):
            self.invoke('--bootenv', 'review')
        self.assertTrue(scanned)
        self.assertFalse(list(self.runs.glob('deploy-*/reconciliation.json')))
        self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())
        self.assertFalse(any(w[0] == 'bectl' and w[3] == 'unmount' for w in self.calls))

    def test_success_unmounts_without_activation(self):
        self.invoke('--bootenv', 'review')
        be = [[words[0], words[3]] for words in self.calls if words[0] == 'bectl']
        self.assertEqual(be, [['bectl', 'create'], ['bectl', 'mount'], ['bectl', 'unmount']])
        self.assertTrue(any(words[0] == 'umount' for words in self.calls))
        self.assertTrue(any('chroot' == words[0] and 'install' in words for words in self.calls))

    def test_actual_pkg_plugin_configuration(self):
        pkg = Path(os.environ.get('BSD_BUILD_DYNAMIC_PKG', '/usr/local/sbin/pkg'))
        if not pkg.is_file():
            self.skipTest('dynamic pkg executable required')
        baseline = subprocess.run([str(pkg), '-C', '/dev/null',
                                   'config', 'PKG_ENABLE_PLUGINS'],
            env=dict(os.environ, PKG_ENABLE_PLUGINS='yes'),
            capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(baseline.stdout.strip(), 'yes',
                         'probe requires plugin-capable dynamic pkg')
        self.invoke('--bootenv', 'review')
        commands = [words for words in self.calls if 'update' in words]
        self.assertEqual(len(commands), 2)
        for words in commands:
            options = [words[i + 1] for i, word in enumerate(words[:-1])
                       if word == '-o' and 'ENABLE_PLUGINS=' in words[i + 1]]
            self.assertEqual(len(options), 1)
            # Query the actual dynamic implementation. Static pkg always
            # disables plugins, which would conceal a misspelled option.
            result = subprocess.run([str(pkg), '-C', '/dev/null', '-o', options[0],
                                     'config', 'PKG_ENABLE_PLUGINS'],
                env=dict(os.environ, PKG_ENABLE_PLUGINS='yes'),
                capture_output=True, text=True, timeout=30, check=True)
            self.assertEqual(result.stdout.strip(), 'no')

    def test_payload_inventory_precedes_be_creation(self):
        self.invoke('--bootenv', 'review')
        record = next(self.runs.glob('deploy-*/package-inventory.json'))
        inventory = json.loads(record.read_text())
        self.assertEqual(inventory['authentication']['method'], 'pkg-fetch-from-verified-catalogue')
        self.assertFalse(inventory['filesystem_reconciled'])
        self.assertFalse(inventory['bip_policy_applied'])
        package = next(p for p in inventory['packages'] if p['name'] == '5BSD-set-base')
        self.assertEqual(list(package['entries']), ['/bin/example'])

    def test_invalid_construction_prevents_destination_creation(self):
        self.construction_annotation = '{"format":1,"actions":[],"approve_all":true}'
        for option, target in [('--bootenv', 'review'), ('--root', str(self.base / 'newroot'))]:
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, 'construction'):
                self.invoke(option, target)
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))
        self.assertFalse((self.base / 'newroot').exists())
        self.assertFalse(any(words[0] == 'chroot' for words in self.calls))

    def test_missing_selected_package_prevents_be_creation(self):
        def drop_after_fetch(words):
            if 'fetch' in words:
                target = Path(words[words.index('fetch') + 4]) / 'All'
                (target / '5BSD-kernel-generic.pkg').unlink()
            return False
        self.fail_at = drop_after_fetch
        with self.assertRaisesRegex(ValueError, 'lacks selected packages'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_dependency_closure(self):
        first = {'name': 'base', 'manifest': {'name': 'base', 'origin': 'base/base', 'version': '1', 'deps': {'runtime': {'origin': 'base/runtime', 'version': '1'}}}}
        second = {'name': 'runtime', 'manifest': {'name': 'runtime', 'origin': 'base/runtime', 'version': '1'}}
        with self.assertRaisesRegex(ValueError, 'lacks dependencies'):
            deploy.require_package_closure({'packages': [first]}, ['base'])
        self.assertEqual(deploy.require_package_closure({'packages': [first, second]}, ['base']),
                         ['base', 'runtime'])
        first['manifest']['deps'] = []
        with self.assertRaisesRegex(ValueError, 'invalid dependency map'):
            deploy.require_package_closure({'packages': [first]}, ['base'])

    def dependency_fixture(self):
        first = {'name': 'base', 'manifest': {'name': 'base', 'origin': 'base/base', 'version': '1',
                 'deps': {'runtime': {'origin': 'base/runtime', 'version': '1'}}}}
        second = {'name': 'runtime', 'manifest': {'name': 'runtime', 'origin': 'base/runtime', 'version': '1'}}
        return first, second

    def test_selected_conflicts_and_malformed_records(self):
        for conflicts, message in [(['runtime'], 'declare package conflicts'),
                                   ('runtime', 'invalid package conflicts'),
                                   ([None], 'invalid package conflicts')]:
            first, second = self.dependency_fixture()
            first['manifest']['conflicts'] = conflicts
            with self.subTest(conflicts=conflicts):
                with self.assertRaisesRegex(ValueError, message):
                    deploy.require_package_closure({'packages': [first, second]}, ['base'])
        first, second = self.dependency_fixture()
        first['manifest']['conflicts'] = ['not-selected', 'not-selected']
        self.assertEqual(deploy.require_package_closure({'packages': [first, second]}, ['base']),
                         ['base', 'runtime'])

    def test_dependency_origin_mismatch(self):
        first, second = self.dependency_fixture()
        second['manifest']['origin'] = 'different/runtime'
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            deploy.require_package_closure({'packages': [first, second]}, ['base'])

    def test_dependency_recorded_version_is_not_a_pin(self):
        for version in ('2', '0.9'):
            first, second = self.dependency_fixture()
            second['manifest']['version'] = version
            with self.subTest(version=version):
                self.assertEqual(deploy.require_package_closure(
                    {'packages': [first, second]}, ['base']), ['base', 'runtime'])
        # This is closure validation, not approval to downgrade a generation.

    def test_incomplete_dependency_identity(self):
        first, second = self.dependency_fixture()
        del first['manifest']['deps']['runtime']['origin']
        with self.assertRaisesRegex(ValueError, 'invalid dependency identity'):
            deploy.require_package_closure({'packages': [first, second]}, ['base'])

    def test_duplicate_package_identity(self):
        first, second = self.dependency_fixture()
        with self.assertRaisesRegex(ValueError, 'duplicate or inconsistent'):
            deploy.require_package_closure({'packages': [first, second, copy.deepcopy(second)]}, ['base'])

    def test_exact_transitive_closure(self):
        first, second = self.dependency_fixture()
        leaf = {'name': 'leaf', 'manifest': {'name': 'leaf', 'origin': 'base/leaf', 'version': '3'}}
        second['manifest']['deps'] = {'leaf': {'origin': 'base/leaf', 'version': '3'}}
        self.assertEqual(deploy.require_package_closure({'packages': [leaf, second, first]}, ['base']),
                         ['base', 'leaf', 'runtime'])

    def test_dependency_mismatch_prevents_be_creation(self):
        self.dependencies = {'5BSD-kernel-generic': {'origin': 'different/kernel', 'version': '1'}}
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_unrequested_archive_prevents_be_creation(self):
        self.names.append('unexpected-extra')
        with self.assertRaisesRegex(ValueError, 'unrequested packages'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_missing_library_prevents_be_creation(self):
        self.shlibs_required = ['lib-not-in-generation.so.1']
        with self.assertRaisesRegex(ValueError, 'lacks shared-library providers'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_library_closure_uses_only_selected_manifests(self):
        check = deploy.package_closure.require_shared_libraries
        consumer = dict(name='consumer', shlibs_required=['libc.so.7'])
        with self.assertRaisesRegex(ValueError, 'consumer: libc.so.7'):
            check([consumer])
        check([consumer, dict(name='provider', shlibs_provided=['libc.so.7'])])
        with self.assertRaisesRegex(ValueError, 'lacks shared-library providers'):
            check([consumer, dict(name='wrong-abi', shlibs_provided=['libc.so.7:32'])])
        check([dict(name='self', shlibs_required=['libself.so.1'], shlibs_provided=['libself.so.1'])])
        for field in ('shlibs_required', 'shlibs_provided'):
            for value in ('lib.so.1', [True], [''], ['../lib.so.1'], ['lib.so.1'] * 2):
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'invalid shlibs'):
                    check([dict(name='bad', **{field: value})])

    def test_fetch_diagnostic_prevents_be_creation(self):
        command = self.run_command
        def diagnostic(*args, **kwargs):
            result = command(*args, **kwargs)
            if 'fetch' in list(map(str, args)):
                result.stderr = 'archive verification failed'
            return result
        self.run_command = diagnostic
        with self.assertRaisesRegex(ValueError, 'archive verification failed'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_generated_parent_alias_refused_before_be_creation(self):
        generated = json.loads(self.generated.read_text())
        generated['entries']['/fixture'].update(type='symlink', target='/elsewhere')
        self.generated.write_text(json.dumps(generated))
        with self.assertRaisesRegex(ValueError, 'non-directory ancestor'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] in ('bectl', 'chroot') for words in self.calls))

    def test_invalid_inventory_prevents_be_creation(self):
        def reject(archives):
            raise ValueError('payload conflict')
        invalid = SimpleNamespace(inventory_packages=reject)
        with patch.object(deploy, 'load_package_inventory', return_value=invalid), self.assertRaisesRegex(ValueError, 'payload conflict'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' for words in self.calls))

    def test_source_changes_do_not_replace_inventory_inputs(self):
        (self.repo / 'source-sentinel').write_text('generation-a')
        def mutate_after_fetch(words):
            if 'fetch' in words:
                (self.repo / 'source-sentinel').write_text('generation-b')
                self.key.write_text('replacement key')
            if words[0] == 'chroot' and 'install' in words:
                inputs = next(Path(words[1]).glob('.bsd-build-*'))
                self.assertEqual((inputs / 'repository/source-sentinel').read_text(), 'generation-a')
                self.assertEqual((inputs / 'repository.pub').read_text(), 'mock public key')
            return False
        self.fail_at = mutate_after_fetch
        self.invoke('--bootenv', 'review')
        run = next(self.runs.glob('deploy-*'))
        record = json.loads((run / 'package-inventory.json').read_text())
        self.assertEqual(record['authentication']['snapshot'], str(run / 'repository'))
        self.assertEqual((run / 'repository/source-sentinel').read_text(), 'generation-a')
        self.assertEqual((run / 'repository.pub').read_text(), 'mock public key')
        self.assertEqual((run / 'code.pub').read_text(), 'mock public key')
        self.assertTrue(any(str(run / 'repository') in p.read_text() for p in (run / 'repos').glob('*')))

    def test_explicit_snapshot_clone(self):
        self.invoke('--bootenv', 'review', '--clone-from', 'rescue@checkpoint')
        create = next(w for w in self.calls if w[0] == 'bectl' and w[3] == 'create')
        self.assertEqual(create, ['bectl', '-r', 'zroot/ROOT', 'create', '-r', '-e', 'rescue@checkpoint', 'review'])
        self.assertIn(['/sbin/zfs', 'set', 'readonly=off', 'zroot/ROOT/review'], self.calls)
        self.assertFalse(any('activate' in w or 'destroy' in w for w in self.calls))

    def test_mount_failure_attempts_unmount(self):
        self.fail_at = lambda words: words[0] == 'bectl' and words[3] == 'mount'
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertTrue(any(w[0] == 'bectl' and w[3] == 'unmount' for w in self.calls))
        self.assertFalse(any(w[0] == 'chroot' for w in self.calls))

    def test_shared_database_refused(self):
        mounts = [('zroot/ROOT/current', Path('/'), 'zfs', ['rw']),
                  ('zroot/pkg', Path('/var/db/pkg'), 'zfs', ['rw'])]
        with patch.object(deploy, 'mount_inventory', return_value=mounts), \
             patch.object(deploy, 'zfs_properties', return_value={'guid':'1','origin':'-','readonly':'off'}):
            with self.assertRaisesRegex(ValueError, 'shared or separately mounted'):
                deploy.be_source(private_paths=deploy.deployment_private_paths({}))

    def test_changed_source_identity_refused_before_create(self):
        source = {'root': 'zroot/ROOT', 'selector': 'current',
                  'source': 'zroot/ROOT/current', 'guid': '1'}
        with patch.object(deploy, 'command') as command, \
             patch.object(deploy, 'zfs_properties', return_value={
                 'guid': '9', 'origin': '-', 'readonly': 'on'}):
            with self.assertRaisesRegex(ValueError, 'source identity changed'):
                deploy.be_create('review', source)
        command.assert_not_called()

    def test_source_replacement_during_create_retains_candidate(self):
        source = {'root': 'zroot/ROOT', 'selector': 'current',
                  'source': 'zroot/ROOT/current', 'guid': '1'}
        def properties(dataset):
            if dataset == 'zroot/ROOT/review':
                return {'guid': '2', 'origin': 'zroot/ROOT/current@x', 'readonly': 'on'}
            return {'guid': '9' if calls else '1', 'origin': '-', 'readonly': 'on'}
        calls = []
        with patch.object(deploy, 'command', side_effect=lambda *a, **k: calls.append(a)), \
             patch.object(deploy, 'zfs_properties', side_effect=properties):
            with self.assertRaisesRegex(ValueError, 'source identity changed'):
                deploy.be_create('review', source)
        self.assertEqual(calls, [('bectl', '-r', 'zroot/ROOT', 'create',
                                 '-r', '-e', 'current', 'review')])

    def test_dataset_properties_require_unambiguous_identity(self):
        valid = 'guid\t7\norigin\tzroot/ROOT/current@snapshot\nreadonly\toff\n'
        bad = [valid + 'guid\t8\n', valid + 'origin\tother@snapshot\n',
               valid + 'readonly\ton\n', valid + 'unexpected\tx\n',
               valid.replace('guid\t7\n', ''), valid + '\n',
               valid.replace('origin\tzroot/ROOT/current@snapshot', 'origin\t'),
               valid.replace('readonly\toff', 'readonly\tunknown'),
               valid.replace('guid\t7', 'guid\t7\textra')]
        bad += [valid.replace('guid\t7', 'guid\t' + value)
                for value in ('0', str(2**64), '-1', '\u0667', '7 8', '')]
        for output, diagnostic in [(value, '') for value in bad] + [(valid, 'warning')]:
            with self.subTest(output=output, diagnostic=diagnostic), \
                 patch.object(deploy, 'command', return_value=SimpleNamespace(
                     stdout=output, stderr=diagnostic)):
                with self.assertRaisesRegex(ValueError, 'invalid ZFS identity'):
                    deploy.zfs_properties('zroot/ROOT/review')
        for guid in ('1', str(2**64 - 1)):
            with patch.object(deploy, 'command', return_value=SimpleNamespace(
                    stdout=valid.replace('guid\t7', 'guid\t' + guid), stderr='')):
                self.assertEqual(deploy.zfs_properties('zroot/ROOT/review'),
                    dict(guid=guid, origin='zroot/ROOT/current@snapshot', readonly='off'))

    def test_snapshot_guid_query_rejects_ambiguous_identity(self):
        for output, diagnostic in (('', ''), ('0\n', ''), ('-\n', ''),
                ('7\n8\n', ''), (str(2**64) + '\n', ''), ('7\n', 'warning'),
                ('\u0667\n', '')):
            with self.subTest(output=output, diagnostic=diagnostic), \
                 patch.object(deploy, 'command', return_value=SimpleNamespace(
                     stdout=output, stderr=diagnostic)):
                with self.assertRaisesRegex(ValueError, 'invalid ZFS GUID'):
                    deploy.zfs_guid('zroot/ROOT/current@selected')

    def test_snapshot_identity_captured_and_rechecked(self):
        snapshot = 'zroot/ROOT/current@selected'
        calls = []
        snapshot_reads = []
        def properties(dataset):
            return {'guid': '2' if dataset.endswith('/review') else '1',
                    'origin': snapshot if dataset.endswith('/review') else '-',
                    'readonly': 'on'}
        def command(*args, **kwargs):
            if args[:2] == ('/sbin/zfs', 'get'):
                self.assertEqual(args[-2:], ('guid', snapshot))
                snapshot_reads.append(args[-1])
                return SimpleNamespace(stdout='7\n', stderr='')
            calls.append(args)
        with patch.object(deploy, 'mount_inventory', return_value=[]), \
             patch.object(deploy, 'zfs_properties', side_effect=properties), \
             patch.object(deploy, 'command', side_effect=command):
            source = deploy.be_source('current@selected', 'zroot/ROOT', private_paths=[])
            self.assertEqual(source.get('snapshot_guid'), '7')
            deploy.be_create('review', source)
        self.assertEqual(len(snapshot_reads), 3)
        self.assertEqual(calls[-1], ('/sbin/zfs', 'set', 'readonly=off', 'zroot/ROOT/review'))

    def test_snapshot_replacement_refused_without_writable_candidate(self):
        for during in (False, True):
            with self.subTest(during_creation=during):
                source = {'root': 'zroot/ROOT', 'selector': 'current@selected',
                          'source': 'zroot/ROOT/current', 'guid': '1', 'snapshot_guid': '7'}
                calls = []
                def properties(dataset):
                    return {'guid': '2' if dataset.endswith('/review') else '1',
                            'origin': 'zroot/ROOT/current@selected', 'readonly': 'on'}
                def command(*args, **kwargs):
                    if args[:2] == ('/sbin/zfs', 'get'):
                        return SimpleNamespace(stdout=('7' if during and not calls else '9') + '\n', stderr='')
                    calls.append(args)
                with patch.object(deploy, 'zfs_properties', side_effect=properties), \
                     patch.object(deploy, 'command', side_effect=command):
                    with self.assertRaisesRegex(ValueError, 'snapshot identity changed'):
                        deploy.be_create('review', source)
                self.assertEqual(calls, [('bectl', '-r', 'zroot/ROOT', 'create',
                    '-r', '-e', 'current@selected', 'review')] if during else [])

    def test_active_alias_refused_before_mount(self):
        source = {'root':'zroot/ROOT', 'selector':'current', 'source':'zroot/ROOT/current', 'guid':'1'}
        calls = []
        with patch.object(deploy, 'command', side_effect=lambda *a,**k:calls.append(a)), \
             patch.object(deploy, 'zfs_properties', return_value={'guid':'1','origin':'zroot/ROOT/current@x','readonly':'off'}):
            with self.assertRaisesRegex(ValueError, 'independent clone'):
                deploy.be_create('review', source)
        self.assertFalse(any('mount' in call or 'set' in call for call in calls))

    def test_candidate_identity_checks_origin_and_propagates_query_failure(self):
        candidate = dict(dataset='zroot/ROOT/review', guid='2',
                         origin='zroot/ROOT/current@selected')
        with patch.object(deploy, 'zfs_properties', return_value=dict(
                guid='2', origin='zroot/ROOT/current@other')):
            with self.assertRaisesRegex(ValueError, 'candidate identity changed'):
                deploy.be_check_candidate_identity(candidate)
        with patch.object(deploy, 'zfs_properties', side_effect=ValueError('query failed')):
            with self.assertRaisesRegex(ValueError, 'query failed'):
                deploy.be_check_candidate_identity(candidate)

    def test_candidate_replaced_before_writable_is_retained(self):
        source = dict(root='zroot/ROOT', selector='current',
                      source='zroot/ROOT/current', guid='1')
        reads = []
        def properties(dataset):
            if dataset.endswith('/review'):
                reads.append(dataset)
                return dict(guid='2' if len(reads) == 1 else '9',
                            origin='zroot/ROOT/current@x', readonly='on')
            return dict(guid='1', origin='-', readonly='on')
        with patch.object(deploy, 'zfs_properties', side_effect=properties), \
             patch.object(deploy, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'candidate identity changed'):
                deploy.be_create('review', source)
        command.assert_called_once_with('bectl', '-r', 'zroot/ROOT', 'create',
                                       '-r', '-e', 'current', 'review')

    def test_candidate_replacement_prevents_mount_or_cleanup_by_name(self):
        for fail_at_check in (2, 3, 4):
            with self.subTest(check=fail_at_check):
                self.calls.clear()
                checks = []
                actual_check = deploy.be_check_candidate_identity
                def check(candidate):
                    checks.append(candidate.copy())
                    if len(checks) >= fail_at_check:
                        raise ValueError('candidate identity changed: fixture')
                    return actual_check(candidate)
                output = io.StringIO()
                with patch.object(deploy, 'be_check_candidate_identity', side_effect=check), \
                     redirect_stdout(output), self.assertRaisesRegex(ValueError, 'candidate identity changed'):
                    self.invoke('--bootenv', 'review')
                operations = [w[3] for w in self.calls if w[0] == 'bectl']
                self.assertNotIn('unmount', operations)
                self.assertNotIn('destroy', operations)
                self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())
                if fail_at_check == 2:
                    self.assertNotIn('mount', operations)
                if fail_at_check <= 3:
                    self.assertFalse(any(w[0] == 'chroot' for w in self.calls))

    def test_replaced_candidate_prevents_devfs_cleanup(self):
        for installation_fails in (False, True):
            with self.subTest(installation_fails=installation_fails):
                self.calls.clear()
                actual_check = deploy.be_check_candidate_identity
                def check(candidate):
                    if any(words[0] == 'chroot' and 'install' in words
                           for words in self.calls):
                        raise ValueError('candidate identity changed: fixture')
                    return actual_check(candidate)
                self.fail_at = (lambda words: words[0] == 'chroot' and
                                'install' in words) if installation_fails else None
                output = io.StringIO()
                with patch.object(deploy, 'be_check_candidate_identity', side_effect=check), \
                     redirect_stdout(output), self.assertRaisesRegex(ValueError, 'candidate identity changed'):
                    self.invoke('--bootenv', 'review')
                self.assertFalse(any(words[0] == 'umount' for words in self.calls))
                operations = [words[3] for words in self.calls if words[0] == 'bectl']
                self.assertEqual(operations, ['create', 'mount'])
                self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())

    def test_builder_directory_alias_is_resolved_before_mount(self):
        physical = self.runs
        alias = self.base / 'runs-alias'
        alias.symlink_to(physical, target_is_directory=True)
        self.runs = alias
        self.invoke('--bootenv', 'review')
        mounts = [words for words in self.calls if words[:4] == ['mount', '-t', 'devfs', 'devfs']]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(Path(mounts[0][-1]).is_relative_to(physical))

    def test_unknown_devfs_identity_retains_mount(self):
        with patch.object(deploy, 'devfs_identity', side_effect=ValueError('identity query failed')):
            with self.assertRaisesRegex(ValueError, 'devfs identity changed'):
                self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'umount' for words in self.calls))
        self.assertFalse(any(words[0] == 'bectl' and words[3] == 'unmount' for words in self.calls))

    def test_devfs_replacement_prevents_all_cleanup(self):
        actual = deploy.devfs_identity
        calls = []
        def replaced(path):
            value = actual(path)
            calls.append(value)
            return value if len(calls) == 1 else (value[0], value[1], value[2] ^ 1)
        output = io.StringIO()
        with patch.object(deploy, 'devfs_identity', side_effect=replaced), \
             redirect_stdout(output), self.assertRaisesRegex(ValueError, 'devfs identity changed'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'umount' for words in self.calls))
        self.assertFalse(any(words[0] == 'bectl' and words[3] == 'unmount' for words in self.calls))
        self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())

    def test_devfs_identity_rejects_redirected_and_foreign_mounts(self):
        path = self.base / 'mount'
        path.mkdir()
        valid = [('devfs', path, 'devfs', ['rw'])]
        for rows in ([], valid * 2, [('other', path, 'ufs', ['rw'])],
                     valid + [('other', path / 'nested', 'zfs', ['rw'])]):
            with self.subTest(rows=rows), patch.object(deploy, 'mount_inventory', return_value=rows):
                with self.assertRaisesRegex(ValueError, 'devfs mount topology changed'):
                    deploy.devfs_identity(path)
        with patch.object(deploy, 'mount_inventory', return_value=valid):
            first = deploy.devfs_identity(path)
            self.assertEqual(first, deploy.devfs_identity(path))
        alias = self.base / 'alias'
        alias.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'devfs path was redirected'):
            deploy.devfs_identity(alias)
        with patch.object(deploy, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'devfs identity changed'):
                deploy.unmount_devfs(path, None)
            command.assert_not_called()

    def test_unmount_failure_retains_mounted_root(self):
        self.fail_at = lambda words: words[0] == 'umount'
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(words[0] == 'bectl' and words[3] == 'unmount' for words in self.calls))
        roots = list(self.runs.glob('deploy-*/root'))
        self.assertEqual(len(roots), 1)
        self.assertTrue((roots[0] / 'dev').is_dir())

    def test_be_create_failure_never_mounts_or_removes_existing_target(self):
        self.fail_at = lambda words: words[0] == 'bectl' and words[3] == 'create'
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        operations = [words[3] for words in self.calls if words[0] == 'bectl']
        self.assertEqual(operations, ['create'])
        self.assertFalse(any(words[0] == 'chroot' for words in self.calls))
        self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())

    def test_be_unmount_failure_never_reports_deployment_success(self):
        self.fail_at = lambda words: words[0] == 'bectl' and words[3] == 'unmount'
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(subprocess.CalledProcessError):
            self.invoke('--bootenv', 'review')
        self.assertNotIn('DEPLOYMENT_VERIFIED', output.getvalue())
        operations = [words[3] for words in self.calls if words[0] == 'bectl']
        self.assertEqual(operations, ['create', 'mount', 'unmount'])
        work, = self.runs.glob('deploy-*')
        # Successful filesystem validation must not hide failed lifecycle cleanup.
        self.assertEqual(json.loads((work / 'reconciliation.json').read_text())['result'], 'PASS')
        self.assertTrue((work / 'root').is_dir())

    def test_reconciliation_records_complete_candidate(self):
        root = self.base / 'candidate'
        # Determine this filesystem's chmod flag semantics on a separate,
        # controlled object before deployment. Never derive accepted metadata
        # from the candidate or its reconciliation differences.
        probe = self.base / 'metadata-probe'
        probe.mkdir(mode=0o700)
        os.chflags(probe, 0)
        probe.chmod(0o755)
        generated = json.loads(self.generated.read_text())
        generated['entries']['/']['flags_set'] = probe.stat().st_flags
        self.generated.write_text(json.dumps(generated))
        self.invoke('--root', str(root))
        run = next(self.runs.glob('deploy-*'))
        result = json.loads((run / 'reconciliation.json').read_text())
        self.assertEqual(result['result'], 'PASS')
        self.assertIn('/bin/example', result['objects'])
        self.assertEqual(len(result['objects']), 11)
        self.assertFalse(result['generation_authenticated'])
        self.assertFalse(result['bip_policy_applied'])
        self.assertTrue((run / 'generated.json').is_file())

    def test_unexplained_policy_prevents_deployment_success(self):
        def add_policy(words):
            if words[0] == 'chroot' and 'install' in words:
                (Path(words[1]) / 'etc/unapproved-policy').write_text('unexpected')
            return False
        self.fail_at = add_policy
        with self.assertRaisesRegex(ValueError, 'filesystem reconciliation failed'):
            self.invoke('--bootenv', 'review')
        run = next(self.runs.glob('deploy-*'))
        result = json.loads((run / 'reconciliation.json').read_text())
        self.assertEqual(result['result'], 'FAIL')
        self.assertIn({'path': '/etc/unapproved-policy', 'reason': 'unexplained-object'}, result['differences'])
        self.assertTrue(any(w[0] == 'bectl' and w[3] == 'unmount' for w in self.calls))
        self.assertTrue((run / 'root/etc/unapproved-policy').is_file())

    def test_changed_payload_prevents_deployment_success(self):
        def change_payload(words):
            if words[0] == 'chroot' and 'install' in words:
                (Path(words[1]) / 'bin/example').write_bytes(b'changed')
            return False
        self.fail_at = change_payload
        with self.assertRaisesRegex(ValueError, 'filesystem reconciliation failed'):
            self.invoke('--bootenv', 'review')
        result = json.loads(next(self.runs.glob('deploy-*/reconciliation.json')).read_text())
        difference = next(d for d in result['differences'] if d['path'] == '/bin/example')
        self.assertIn('sha256', difference['fields'])
        self.assertTrue(any(w[0] == 'bectl' and w[3] == 'unmount' for w in self.calls))

    def test_generated_metadata_validated_before_be_creation(self):
        self.generated.write_text(json.dumps({'format': 1, 'entries': {'/': {'type': 'directory'}}}))
        with self.assertRaisesRegex(ValueError, 'incomplete generated'):
            self.invoke('--bootenv', 'review')
        self.assertFalse(any(w[0] == 'bectl' for w in self.calls))

    def test_generated_input_frozen_before_fetch(self):
        original = self.generated.read_bytes()
        def change_input(words):
            if 'fetch' in words:
                self.generated.write_text('{}')
            return False
        self.fail_at = change_input
        self.invoke('--bootenv', 'review')
        run = next(self.runs.glob('deploy-*'))
        self.assertEqual((run / 'generated.json').read_bytes(), original)
        self.assertEqual(json.loads((run / 'reconciliation.json').read_text())['result'], 'PASS')

    def test_existing_root_unchanged(self):
        root = self.base / 'existing'
        root.mkdir()
        (root / 'sentinel').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            self.invoke('--root', str(root))
        self.assertEqual('preserve', (root / 'sentinel').read_text())
        self.assertEqual([], self.calls)


if __name__ == '__main__':
    unittest.main()
