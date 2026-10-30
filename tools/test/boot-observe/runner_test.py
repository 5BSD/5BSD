# SPDX-License-Identifier: BSD-2-Clause
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch, call

spec=importlib.util.spec_from_file_location('observe',Path(__file__).with_name('run.py'))
observe=importlib.util.module_from_spec(spec);spec.loader.exec_module(observe)


class Policy(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        def binding(name):
            path=self.root/name;path.write_bytes(name.encode());path.chmod(0o700)
            return {'path':str(path),'sha256':observe.digest(path)}
        self.policy={'format':1,'qemu':binding('qemu'),'qemu_data':str(self.root),
            'firmware_code':binding('code'),'firmware_variables':binding('vars'),
            'boot_media':binding('media'),'data_disks':[binding('state')],
            'cpus':2,'memory_mib':1024,'seconds':30,'ssh_forward_port':None}

    def test_input_bindings(self):
        self.assertEqual(len(observe.validate(self.policy)),5)
        Path(self.policy['boot_media']['path']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash differs'):observe.validate(self.policy)

    def test_alias_rejected(self):
        alias=self.root/'alias';alias.symlink_to(self.policy['boot_media']['path'])
        self.policy['boot_media']['path']=str(alias)
        with self.assertRaisesRegex(ValueError,'aliased'):observe.validate(self.policy)

    def test_duplicates_and_unknown_fields(self):
        with self.assertRaises(ValueError):json.loads('{"format":1,"format":1}',object_pairs_hook=observe.unique)
        self.policy['extra']=True
        with self.assertRaises(ValueError):observe.validate(self.policy)

    def test_numeric_bounds(self):
        for name,value in [('cpus',True),('seconds',0),('memory_mib',1),('ssh_forward_port',22),('ssh_forward_port',True)]:
            p=copy.deepcopy(self.policy);p[name]=value
            with self.assertRaises(ValueError):observe.validate(p)

    def test_duplicate_disk_binding(self):
        self.policy['data_disks'].append(self.policy['boot_media'])
        with self.assertRaisesRegex(ValueError,'duplicate input'):observe.validate(self.policy)

    def test_network_and_storage_arguments(self):
        args=observe.command(self.policy,self.root,self.root/'private-vars',[self.root/'private-state'])
        self.assertIn('none',args)
        self.assertIn('if=none,id=system,format=raw,readonly=on,file='+self.policy['boot_media']['path'],args)
        self.assertIn('if=none,id=data0,format=raw,file='+str(self.root/'private-state'),args)
        self.assertNotIn(self.policy['data_disks'][0]['path'],args)
        self.policy['ssh_forward_port']=22229
        args=observe.command(self.policy,self.root,self.root/'private-vars',[])
        self.assertIn('user,id=isolated,restrict=on,hostfwd=tcp:127.0.0.1:22229-:22',args)
        self.assertNotIn('-kernel',args)
        self.assertNotIn('-append',args)

    def test_path_argument_injection(self):
        for path in ('relative','/tmp/file,readonly=off','/tmp/file\n'):
            with self.assertRaises(ValueError):observe.canonical(path)


class SSHProbe(unittest.TestCase):
    def setUp(self):
        Policy.setUp(self)
        self.policy.update(format=2, ssh_forward_port=22229)
        def binding(name):
            path = self.root / name; path.write_bytes(name.encode()); path.chmod(0o700)
            return {'path': str(path), 'sha256': observe.digest(path)}
        self.policy['ssh_probe'] = dict(client=binding('ssh'), known_hosts=binding('hosts'),
            identity=binding('identity'), user='testuser', command='id -u',
            stdout_sha256=observe.hashlib.sha256(b'1001\n').hexdigest())

    def test_policy_and_pinned_command(self):
        self.assertEqual(len(observe.validate(self.policy)), 8)
        argv = observe.ssh_command(self.policy)
        for option in ('StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
                'IdentityAgent=none', 'BatchMode=yes', 'PermitLocalCommand=no',
                'GlobalKnownHostsFile=/dev/null', 'ControlPath=none',
                'CertificateFile=/dev/null', 'PubkeyAcceptedAlgorithms=-*-cert-v01@openssh.com',
                'PreferredAuthentications=publickey', 'HostbasedAuthentication=no'):
            self.assertIn(option, argv)
        self.assertEqual(argv[-4:], ['-l', 'testuser', '127.0.0.1', 'id -u'])
        self.assertEqual(argv[1:3], ['-F', '/dev/null'])

    def test_rejects_missing_forwarding_and_unsafe_inputs(self):
        for field, value in [('user', '-other'), ('stdout_sha256', 'wrong'),
                             ('command', ''), ('command', 'bad\0command')]:
            p = copy.deepcopy(self.policy); p['ssh_probe'][field] = value
            with self.assertRaises(ValueError): observe.validate(p)
        p = copy.deepcopy(self.policy); p['ssh_forward_port'] = None
        with self.assertRaises(ValueError): observe.validate(p)
        for path in ('/tmp/%h', '/tmp/${HOME}/key', '/tmp/has space', '/tmp/a"b', '/tmp/a' + chr(92) + 'b'):
            p = copy.deepcopy(self.policy); p['ssh_probe']['known_hosts']['path'] = path
            with self.assertRaisesRegex(ValueError, 'expansion'): observe.validate(p)
        Path(self.policy['ssh_probe']['identity']['path']).chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private'): observe.validate(self.policy)

    def test_public_sidecar_presence_bytes_and_aliases(self):
        path = Path(self.policy['ssh_probe']['identity']['path'] + '.pub')
        before = observe.identity_public_input(self.policy)
        self.assertEqual(before, {'path': str(path), 'sha256': None})
        path.write_bytes(b'public key')
        present = observe.identity_public_input(self.policy)
        self.assertNotEqual(before, present)
        self.assertEqual(present['sha256'], observe.digest(path))
        path.write_bytes(b'changed key')
        self.assertNotEqual(present, observe.identity_public_input(self.policy))
        path.unlink(); path.symlink_to(self.root / 'identity')
        with self.assertRaisesRegex(ValueError, 'aliased'):
            observe.identity_public_input(self.policy)
        path.unlink()
        self.assertEqual(before, observe.identity_public_input(self.policy))

    def test_attempt_matches_bytes_and_exit_status(self):
        def run(*args, **kwargs):
            self.assertNotIn('SSH_AUTH_SOCK', kwargs['env'])
            self.assertEqual(kwargs['timeout'], 2)
            kwargs['stdout'].write(b'1001\n')
            kwargs['stderr'].write(b'diagnostic')
            return SimpleNamespace(returncode=0)
        with patch.object(observe.subprocess, 'run', side_effect=run):
            result = observe.probe_ssh(self.policy, self.root, 0, 2)
        self.assertTrue(result['matched'])
        self.assertEqual((self.root / 'ssh-0.stderr').read_bytes(), b'diagnostic')
        self.policy['ssh_probe']['stdout_sha256'] = '0' * 64
        with patch.object(observe.subprocess, 'run', side_effect=run):
            self.assertFalse(observe.probe_ssh(self.policy, self.root, 1, 2)['matched'])
        self.policy['ssh_probe']['stdout_sha256'] = observe.hashlib.sha256(b'').hexdigest()
        with patch.object(observe.subprocess, 'run', return_value=SimpleNamespace(returncode=255)):
            self.assertFalse(observe.probe_ssh(self.policy, self.root, 2, 2)['matched'])
        with patch.object(observe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('ssh', 2)):
            result = observe.probe_ssh(self.policy, self.root, 3, 2)
        self.assertTrue(result['timed_out']); self.assertFalse(result['matched'])

    def test_missing_probe_cannot_be_observed_success(self):
        lifecycle = {'error': None, 'guest_poweroff': True}
        self.assertEqual(observe.observation_result([], lifecycle, False, 0, False,
            ssh_required=True), 'SSH_PROBE_FAILED')
        self.assertEqual(observe.observation_result([], lifecycle, False, 0, False,
            ssh_required=True, ssh_matched=True), 'OBSERVED')
        self.assertEqual(observe.observation_result(['input'], lifecycle, False, 0, False,
            ssh_required=True, ssh_matched=True), 'INPUT_CHANGED')


class DataInventory(unittest.TestCase):
    def test_content_and_namespace_changes_are_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'empty').mkdir()
            rom = root / 'rom.bin'; rom.write_bytes(b'ROM1')
            original = observe.data_inventory(root)
            self.assertEqual(original['empty'], {'type': 'directory'})
            self.assertEqual(original['rom.bin']['sha256'], observe.digest(rom))
            rom.write_bytes(b'ROM2')
            self.assertNotEqual(original, observe.data_inventory(root))
            rom.write_bytes(b'ROM1')
            self.assertEqual(original, observe.data_inventory(root))
            rom.rename(root / 'renamed.bin')
            self.assertNotEqual(original, observe.data_inventory(root))
            (root / 'empty').rmdir()
            self.assertNotEqual(original, observe.data_inventory(root))

    def test_links_and_special_files_are_rejected(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'rom'; target.write_bytes(b'rom')
            alias = root / 'alias'; alias.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'physical'):
                observe.data_inventory(root)
            alias.unlink(); alias.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'physical'):
                observe.data_inventory(root)
            alias.unlink(); os.mkfifo(alias)
            with self.assertRaisesRegex(ValueError, 'physical'):
                observe.data_inventory(root)


class SerialScanning(unittest.TestCase):
    def test_append_scanning_is_linear_and_markers_span_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'serial.log'
            for marker in observe.SerialFailureDetector.markers:
                for split in range(1, len(marker)):
                    with self.subTest(marker=marker, split=split):
                        detector = observe.SerialFailureDetector()
                        data = b'x' * 65534 + marker[:split]
                        path.write_bytes(data)
                        self.assertFalse(detector.scan(path))
                        for _ in range(3):
                            self.assertFalse(detector.scan(path))
                        self.assertEqual(detector.bytes_read, len(data))
                        with path.open('ab') as stream:
                            stream.write(marker[split:])
                        self.assertTrue(detector.scan(path))
                        self.assertEqual(detector.bytes_read, 65534 + len(marker))

    def test_replacement_truncation_missing_and_sticky_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'serial.log'
            detector = observe.SerialFailureDetector()
            self.assertFalse(detector.scan(path))
            path.write_bytes(b'ordinary startup' * 20)
            self.assertFalse(detector.scan(path))
            path.write_bytes(b'panic: truncated log')
            self.assertTrue(detector.scan(path))
            replacement = Path(directory) / 'replacement'
            replacement.write_bytes(b'ordinary shutdown')
            replacement.replace(path)
            self.assertTrue(detector.scan(path))
            path.unlink()
            self.assertTrue(detector.scan(path))
            detector = observe.SerialFailureDetector()
            path.write_bytes(b'ordinary startup')
            self.assertFalse(detector.scan(path))
            replacement.write_bytes(b'mountroot>')
            replacement.replace(path)
            self.assertTrue(detector.scan(path))

    def test_fifo_and_symlink_do_not_read_external_input(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'serial.log'
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                observe.SerialFailureDetector().scan(path)
            path.unlink()
            path.symlink_to(Path(directory) / 'missing')
            with self.assertRaises(OSError):
                observe.SerialFailureDetector().scan(path)


class Outcomes(unittest.TestCase):
    def result(self, code=0, forced=False, failure=False, guest=True, error=None, changed=()):
        return observe.observation_result(changed,
            {'guest_poweroff': guest, 'error': error}, failure, code, forced)

    def test_requires_guest_shutdown(self):
        self.assertEqual(self.result(), 'OBSERVED')
        self.assertEqual(self.result(guest=False), 'HARNESS_FAILURE')
        for code in (-15, -9, 1):
            self.assertEqual(self.result(code=code), 'HARNESS_FAILURE')

    def test_timeout_including_kill_fallback(self):
        for code in (0, -15, -9):
            self.assertEqual(self.result(code=code, forced=True, guest=False),
                'OBSERVATION_TIMEOUT')

    def test_fatal_output_after_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory)/'serial.log'
            self.assertFalse(observe.fatal_serial(serial))
            serial.write_text('booting\npanic: late failure\n')
            self.assertEqual(self.result(failure=observe.fatal_serial(serial)),
                'GUEST_FAILURE')
            self.assertEqual(self.result(failure=True, forced=True), 'GUEST_FAILURE')

    def test_evidence_failure_precedence(self):
        self.assertEqual(self.result(error='collector failed'), 'HARNESS_FAILURE')
        self.assertEqual(self.result(changed=['media'], failure=True), 'INPUT_CHANGED')


class ObservationFlow(unittest.TestCase):
    setUp = SSHProbe.setUp

    def run_observation(self, matched=True, mutation=None):
        data = self.root / 'qemu-data'; data.mkdir()
        (data / 'rom').write_bytes(b'explicit ROM')
        self.policy['qemu_data'] = str(data)
        policy = self.root / 'policy.json'; policy.write_text(json.dumps(self.policy))
        work = self.root / 'observation'
        process = Mock(returncode=0)
        # One observation iteration, then ordinary guest exit and cleanup.
        process.poll.side_effect = [None, 0, 0]
        shutdown = Mock()
        shutdown.arguments = []
        shutdown.finish.return_value = {'error': None, 'guest_poweroff': True}
        module = SimpleNamespace(ShutdownEvidence=lambda directory: shutdown)
        loader = SimpleNamespace(exec_module=lambda module: None)
        def probe(policy, directory, attempt, timeout):
            self.assertEqual(attempt, 0)
            self.assertGreater(timeout, 0); self.assertLessEqual(timeout, 5)
            if mutation == 'public-key':
                Path(policy['ssh_probe']['identity']['path'] + '.pub').write_bytes(b'added key')
            elif mutation == 'rom':
                (data / 'rom').write_bytes(b'changed ROM')
            elif mutation == 'panic':
                (directory / 'serial.log').write_bytes(b'panic: after SSH command\n')
            return {'attempt': attempt, 'exit_code': 0 if matched else 255,
                    'timed_out': False, 'stdout_sha256': 'a' * 64,
                    'stderr_sha256': 'b' * 64, 'matched': matched}
        with patch.object(observe.Path, 'is_relative_to', return_value=True), \
             patch.object(observe.importlib.util, 'spec_from_file_location',
                          return_value=SimpleNamespace(loader=loader)), \
             patch.object(observe.importlib.util, 'module_from_spec', return_value=module), \
             patch.object(observe.subprocess, 'Popen', return_value=process), \
             patch.object(observe, 'probe_ssh', side_effect=probe) as attempted, \
             patch.object(observe.time, 'sleep'), \
             patch('builtins.print'), \
             patch.object(sys, 'argv', ['run.py', '--policy', str(policy), '--work', str(work)]):
            status = observe.main()
        attempted.assert_called_once()
        process.terminate.assert_not_called(); process.kill.assert_not_called()
        shutdown.finish.assert_called_once()
        result = json.loads((work / 'result.json').read_text())
        attempts = json.loads((work / 'ssh-attempts.json').read_text())
        self.assertEqual(result['ssh_probe']['attempts'], attempts)
        self.assertEqual(result['ssh_probe']['matched'], matched)
        for field in ('normal_boot_qualified', 'ssh_qualified',
                      'secure_boot_qualified', 'system_integrity_qualified'):
            self.assertFalse(result[field])
        return status, result

    def test_matched_probe_and_poweroff_records_only_observation(self):
        status, report = self.run_observation()
        self.assertEqual((status, report['result']), (0, 'OBSERVED'))

    def test_clean_poweroff_does_not_hide_failed_probe(self):
        status, report = self.run_observation(matched=False)
        self.assertEqual((status, report['result']), (1, 'SSH_PROBE_FAILED'))

    def test_added_public_key_invalidates_matched_probe(self):
        status, report = self.run_observation(mutation='public-key')
        self.assertEqual((status, report['result']), (1, 'INPUT_CHANGED'))
        self.assertIn(self.policy['ssh_probe']['identity']['path'] + '.pub', report['changed_inputs'])

    def test_changed_rom_invalidates_matched_probe(self):
        status, report = self.run_observation(mutation='rom')
        self.assertEqual((status, report['result']), (1, 'INPUT_CHANGED'))
        self.assertIn(self.policy['qemu_data'], report['changed_inputs'])

    def test_final_serial_failure_overrides_matched_probe(self):
        status, report = self.run_observation(mutation='panic')
        self.assertEqual((status, report['result']), (1, 'GUEST_FAILURE'))


class ProcessCleanup(unittest.TestCase):
    setUp = Policy.setUp

    def check_start_failure(self, kill_needed):
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps(self.policy))
        work = self.root / 'observation'
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = ([subprocess.TimeoutExpired('fixture', 10), 0]
                                    if kill_needed else [0])
        shutdown = Mock()
        shutdown.arguments = []
        shutdown.start.side_effect = RuntimeError('collector could not start')
        module = SimpleNamespace(ShutdownEvidence=lambda directory: shutdown)
        loader = SimpleNamespace(exec_module=lambda module: None)
        # Only the test work-root admission is substituted. All outputs remain
        # in this private temporary directory, and Popen never starts a process.
        with patch.object(observe.Path, 'is_relative_to', return_value=True), \
             patch.object(observe.importlib.util, 'spec_from_file_location',
                          return_value=SimpleNamespace(loader=loader)), \
             patch.object(observe.importlib.util, 'module_from_spec', return_value=module), \
             patch.object(observe.subprocess, 'Popen', return_value=process), \
             patch.object(sys, 'argv', ['run.py', '--policy', str(policy), '--work', str(work)]):
            with self.assertRaisesRegex(RuntimeError, 'collector could not start'):
                observe.main()
        process.terminate.assert_called_once_with()
        if kill_needed:
            process.kill.assert_called_once_with()
            self.assertEqual(process.wait.call_args_list, [call(timeout=10), call()])
        else:
            process.kill.assert_not_called()
            process.wait.assert_called_once_with(timeout=10)
        self.assertFalse((work / 'result.json').exists())

    def test_collector_start_failure_terminates_child(self):
        self.check_start_failure(False)

    def test_collector_start_failure_kills_unresponsive_child(self):
        self.check_start_failure(True)


if __name__=='__main__':unittest.main()
