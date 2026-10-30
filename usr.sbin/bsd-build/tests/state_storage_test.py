#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import json
import subprocess
from unittest.mock import patch
import importlib.util
from pathlib import Path
import tempfile
import unittest

helper = Path(__file__).with_name('state_storage.py')
if not helper.exists():
    helper = Path('/usr/src/tools/build/capimage/state_storage.py')
spec = importlib.util.spec_from_file_location('state_storage', helper)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Plans(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        tool = self.root / 'selected-tool'; tool.write_bytes(b'fixture tool'); tool.chmod(0o700)
        self.selected = dict(path=str(tool), sha256=hashlib.sha256(tool.read_bytes()).hexdigest())
        self.plan = dict(format=1, operation='allocate', dataset='chosen/state/new',
            pool_guid='1', parent_guid='2', timeout=60,
            tools={n: dict(self.selected) for n in ('zfs', 'zpool', 'mount')})

    def test_initialization_restores_mountpoint_after_identity_read_failure(self):
        self.check_mount_setup_failure(False)

    def test_initialization_does_not_clean_up_replacement_dataset(self):
        self.check_mount_setup_failure(True)

    def test_initialization_records_cleanup_query_failure(self):
        self.check_mount_setup_failure(False, cleanup_failure=True)

    def check_mount_setup_failure(self, replacement, cleanup_failure=False):
        source = self.root / 'seed'; source.mkdir()
        work = self.root / 'initialize-failure'
        selected = 'chosen/state/new'
        tools = {name: self.root / 'selected-tool' for name in ('zfs', 'zpool', 'mount', 'tar')}
        properties = dict(guid='3', type='filesystem', mounted='no',
                          canmount='noauto', mountpoint='legacy', exec='off',
                          setuid='off', devices='off', readonly='off')
        commands = []
        failed = False
        def execute(argv, **kwargs):
            nonlocal failed
            args = argv[1:]; commands.append(args)
            if args[:1] == ['set']:
                key, value = args[1].split('=', 1); properties[key] = value
                output = ''
            elif args[:1] == ['list']:
                output = 'chosen/state\n' + selected + '\n'
            elif args[:1] == ['get']:
                key, name = args[-2:]
                if name == selected:
                    if key == 'guid' and failed and cleanup_failure:
                        raise subprocess.CalledProcessError(2, argv, stderr='cleanup GUID query failed')
                    if key == 'guid' and properties['mountpoint'] != 'legacy' and not failed:
                        failed = True
                        if replacement:
                            properties['guid'] = '4'
                        else:
                            raise subprocess.CalledProcessError(1, argv, stderr='injected GUID read failure')
                    output = properties[key]
                else:
                    output = '1' if name == 'chosen' else ('2' if key == 'guid' else 'filesystem')
            else:
                self.fail('unexpected mutation: ' + repr(args))
            return subprocess.CompletedProcess(argv, 0, output, '')
        allocation = dict(format=1, scope='offline-new-state-allocation', result='PASS',
            pool_synced=True, left_unmounted=True, dataset_identity_verified=True,
            generation_authenticated=False, activation_authorized=False,
            runtime_class_assigned=False, empty_observation_sha256='a'*64,
            dataset=selected, pool_guid='1', parent_guid='2', dataset_guid='3')
        with patch.object(m.dataset.os, 'geteuid', return_value=0), \
             patch.object(m.image.construction.generation, 'scan', return_value={}), \
             patch.object(m.dataset.subprocess, 'run', side_effect=execute):
            with self.assertRaises(ValueError if replacement else subprocess.CalledProcessError) as caught:
                m.dataset.initialize_allocated(source, {}, allocation, tools, work)
        self.assertTrue(failed)
        if not replacement:
            self.assertEqual(caught.exception.returncode, 1)
        self.assertEqual(properties['mountpoint'], str(work/'mounted') if replacement or cleanup_failure else 'legacy')
        report = json.loads((work / 'construction.json').read_text())
        self.assertEqual(report['result'], 'FAIL')
        self.assertTrue(report['dataset_retained'])
        self.assertEqual(report['dataset_guid'], '3')
        self.assertFalse((work / 'receipt.json').exists())
        self.assertEqual([args[0] for args in commands].count('set'), 1 if replacement or cleanup_failure else 2)
        self.assertEqual(report['cleanup']['status'], 'failed' if cleanup_failure else
                         'refused-identity-mismatch' if replacement else 'completed')
        if cleanup_failure:
            self.assertIn('exit status 2', report['cleanup']['error'])

    def test_execution_selection_is_explicit_and_validated(self):
        for execution in ({'exec': 'off', 'setuid': 'off'},
                          {'exec': 'on', 'setuid': 'off'},
                          {'exec': 'on', 'setuid': 'on'}):
            with self.subTest(execution=execution):
                self.plan['execution'] = execution
                self.assertEqual(m.prepare(self.plan)[0], 'allocate')
        for execution in (None, {}, {'exec': 'on'}, {'exec': True, 'setuid': 'off'},
                          {'exec': 'off', 'setuid': 'on'},
                          {'exec': 'on', 'setuid': 'off', 'devices': 'on'}):
            with self.subTest(execution=execution), self.assertRaises(ValueError):
                self.plan['execution'] = execution
                m.prepare(self.plan)

    def test_initialize_cannot_override_allocation_execution(self):
        plan = self.initialization_plan()
        plan['execution'] = {'exec': 'on', 'setuid': 'on'}
        with self.assertRaisesRegex(ValueError, 'operation or fields'):
            m.prepare(plan)

    def test_cli_passes_execution_selection_to_allocation(self):
        self.plan['execution'] = {'exec': 'on', 'setuid': 'off'}
        plan = self.root / 'plan.json'; plan.write_text(json.dumps(self.plan))
        work = self.root / 'work'
        def allocate(*args, **kwargs):
            self.assertEqual(kwargs['execution'], self.plan['execution'])
            self.assertEqual(kwargs['timeout'], 60)
            self.assertEqual(args[:3], ('chosen/state/new', '1', '2'))
            work.mkdir()
        with patch('sys.argv', ['state_storage.py', '--plan', str(plan), '--output', str(work)]), \
             patch.object(m.dataset, 'allocate', side_effect=allocate) as call:
            m.main()
        call.assert_called_once()
        self.assertFalse(json.loads((work / 'request.json').read_text())['activation_authorized'])

    def simulate_allocation(self, execution, drift=False, sync_drift=None, tool_drift=False):
        tools = {}
        for name in ('zfs', 'zpool', 'mount'):
            path = self.root / name
            path.write_text('simulated executable')
            path.chmod(0o700)
            tools[name] = path
        work = self.root / ('allocation-' + execution['exec'] + '-' + execution['setuid'] +
                            ('-' + sync_drift[0] if sync_drift else ''))
        properties = {'guid': '3', 'mounted': 'no', 'type': 'filesystem'}
        commands = []
        def run(argv, **kwargs):
            name, *args = argv
            name = Path(name).name
            commands.append((name, args))
            output = ''
            if name == 'zpool':
                if args[0] == 'get':
                    output = '1'
                else:
                    self.assertEqual(args, ['sync', 'chosen'])
                    if sync_drift:
                        properties[sync_drift[0]] = sync_drift[1]
                    if tool_drift:
                        tools['zpool'].write_text('changed during final sync')
            elif name == 'mount':
                flags = ['rw']
                if properties['exec'] == 'off': flags.append('noexec')
                if properties['setuid'] == 'off': flags.append('nosuid')
                output = 'chosen/state/new ' + properties['mountpoint'] + ' zfs ' + ','.join(flags) + ' 0 0'
            elif args[0] == 'list':
                output = 'chosen/state'
            elif args[0] == 'get':
                key, target = args[-2:]
                output = ({'guid': '2', 'type': 'filesystem'}[key]
                    if target == 'chosen/state' else properties[key])
            elif args[0] == 'create':
                for index, value in enumerate(args):
                    if value == '-o':
                        key, selected = args[index + 1].split('=', 1)
                        properties[key] = selected
            elif args[0] == 'mount':
                properties['mounted'] = 'yes'
            elif args[0] == 'unmount':
                properties['mounted'] = 'no'
                if drift: properties['exec'] = 'off'
            elif args[0] == 'set':
                key, selected = args[1].split('=', 1)
                properties[key] = selected
            else:
                self.fail('unexpected ZFS command: ' + repr(args))
            return subprocess.CompletedProcess(argv, 0, output + '\n', '')
        with patch.object(m.dataset.os, 'geteuid', return_value=0), \
             patch.object(m.dataset.subprocess, 'run', side_effect=run):
            if drift or sync_drift or tool_drift:
                message = 'final dataset property differs' if sync_drift else 'execution policy changed'
                if tool_drift:
                    message = 'provisioning tool changed'
                with self.assertRaisesRegex(ValueError, message):
                    m.dataset.allocate('chosen/state/new', '1', '2', tools, work, execution=execution)
                self.assertFalse((work / 'receipt.json').exists())
                self.assertEqual(json.loads((work / 'construction.json').read_text())['result'], 'FAIL')
            else:
                report = m.dataset.allocate('chosen/state/new', '1', '2', tools, work, execution=execution)
                self.assertEqual(report['execution'], execution)
                self.assertEqual(report['result'], 'PASS')
                self.assertEqual(properties['mountpoint'], 'legacy')
                self.assertEqual(properties['mounted'], 'no')
                self.assertEqual(properties['devices'], 'off')
                self.assertFalse(report['activation_authorized'])
                create = next(args for name, args in commands if name == 'zfs' and args[0] == 'create')
                for key, value in execution.items():
                    self.assertIn(key + '=' + value, create)
            self.assertFalse(any(name == 'zfs' and args[0] == 'destroy' for name, args in commands))

    def test_allocation_commands_and_receipts_preserve_execution(self):
        for executable, setuid in (('off', 'off'), ('on', 'off'), ('on', 'on')):
            with self.subTest(executable=executable, setuid=setuid):
                self.simulate_allocation({'exec': executable, 'setuid': setuid})

    def test_changed_execution_policy_cannot_publish_success(self):
        self.simulate_allocation({'exec': 'on', 'setuid': 'off'}, drift=True)

    def test_final_property_changes_cannot_publish_success(self):
        for key, changed in {'type': 'volume', 'mounted': 'yes',
                'mountpoint': '/unexpected', 'canmount': 'on', 'devices': 'on',
                'readonly': 'on', 'exec': 'off', 'setuid': 'on'}.items():
            with self.subTest(property=key):
                self.simulate_allocation({'exec': 'on', 'setuid': 'off'},
                                         sync_drift=(key, changed))

    def test_tool_changed_during_final_sync_cannot_publish_success(self):
        self.simulate_allocation({'exec': 'off', 'setuid': 'off'}, tool_drift=True)

    def test_explicit_allocation_inputs_preserved(self):
        operation, inputs, tools = m.prepare(self.plan)
        self.assertEqual(operation, 'allocate')
        self.assertEqual(inputs, ['chosen/state/new', '1', '2'])
        self.assertEqual(set(tools), {'zfs', 'zpool', 'mount'})
        self.assertEqual(list(self.root.iterdir()), [self.root / 'selected-tool'])

    def initialization_plan(self):
        source = self.root / 'seed'; source.mkdir()
        plan = dict(format=1, operation='initialize', source=str(source), timeout=60,
            tools={n: dict(self.selected) for n in ('zfs', 'zpool', 'mount', 'tar')})
        for name, document in [('observation', {'/': {'type': 'directory'}}),
                               ('allocation', {'format': 1})]:
            path = self.root / (name + '.json'); path.write_text(json.dumps(document))
            plan[name] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        return plan

    def test_initialization_preserves_selected_documents(self):
        plan = self.initialization_plan()
        operation, inputs, tools = m.prepare(plan)
        self.assertEqual(operation, 'initialize')
        self.assertEqual(inputs, [self.root / 'seed', {'/': {'type': 'directory'}}, {'format': 1}])
        self.assertEqual(set(tools), {'zfs', 'zpool', 'mount', 'tar'})

    def test_changed_initialization_documents_refused(self):
        plan = self.initialization_plan()
        for name in ('observation', 'allocation'):
            path = Path(plan[name]['path']); original = path.read_bytes()
            path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                m.prepare(plan)
            path.write_bytes(original)

    def test_change_between_hash_and_parse_refused(self):
        plan = self.initialization_plan()
        reader = m.image.construction.generation.read_json
        def changed_read(path):
            Path(path).write_bytes(b'{}')
            return reader(path)
        with patch.object(m.image.construction.generation, 'read_json', side_effect=changed_read):
            with self.assertRaisesRegex(ValueError, 'changed while reading'):
                m.prepare(plan)

    def test_root_or_aliased_seed_refused(self):
        plan = self.initialization_plan()
        alias = self.root / 'alias'; alias.symlink_to('seed')
        for source in ('/', str(alias)):
            plan['source'] = source
            with self.assertRaisesRegex(ValueError, 'canonical alternate directory'):
                m.prepare(plan)

    def test_changed_tool_refused(self):
        (self.root / 'selected-tool').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            m.prepare(self.plan)

    def test_symlink_tool_refused(self):
        alias = self.root / 'alias'; alias.symlink_to('selected-tool')
        self.plan['tools']['zfs']['path'] = str(alias)
        with self.assertRaisesRegex(ValueError, 'canonical regular'):
            m.prepare(self.plan)

    def test_missing_tools_and_extra_fields_refused(self):
        for key in ('zfs', 'zpool', 'mount'):
            plan = copy.deepcopy(self.plan); del plan['tools'][key]
            with self.assertRaisesRegex(ValueError, 'every required tool'):
                m.prepare(plan)
        self.plan['allow_existing'] = True
        with self.assertRaisesRegex(ValueError, 'operation or fields'):
            m.prepare(self.plan)

    def test_invalid_deadlines_refused(self):
        for value in (0, -1, True, 86401, '60'):
            self.plan['timeout'] = value
            with self.assertRaisesRegex(ValueError, 'timeout'):
                m.prepare(self.plan)


if __name__ == '__main__':
    unittest.main()
