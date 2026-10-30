#!/usr/local/bin/python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Host cleanup is allowed only after complete guest assertion evidence."""
import unittest
from program_report import program_results, provider_continuity
from run import isolation_io_completed, crypto_rejected, capsule_case_completed, capsule_completed, provider_completed, rtld_completed

class ProcessControlEvidence(unittest.TestCase):
    def test_both_lifetimes_must_pass_once(self):
        from run import process_control_completed
        permanent = 'PROTECTED_SPAWN_PASS before-exec, exec, fork, root attacks, descriptor control and core policy'
        ordinary = 'BIP_EXEC_GUARD_PASS before-exec-denied ordinary-exec-debug-signal-schedule'
        asynchronous = 'PROTECTED_SIGIO_PASS direct and group denial; live and exited origins; ordinary and self delivery controls'
        cleanup = 'SIGIO_CLEANUP_PASS'
        complete = permanent + '\n' + ordinary + '\n' + asynchronous + '\n' + cleanup
        self.assertTrue(process_control_completed(complete))
        for incomplete in ('', permanent, ordinary, complete + permanent,
                           complete.replace(asynchronous, 'PROTECTED_SIGIO_PASS direct and group denial; ordinary and self delivery controls'),
                           complete.replace(cleanup, ''),
                           complete + '\n' + cleanup,
                           complete.replace(cleanup, 'SIGIO_CLEANUP'),
                           complete.replace(cleanup, 'prefix-' + cleanup),
                           permanent + '\n' + ordinary,
                           complete + '\n' + asynchronous,
                           complete.replace(asynchronous, 'PROTECTED_SIGIO_PASS'),
                           complete + ordinary, complete + 'PROTECTED_SPAWN_FAIL',
                           complete + 'BIP_EXEC_GUARD_FAIL',
                           complete + '\nSIGIO_CLEANUP_FAIL result=1',
                           complete + '\nPROTECTED_SIGIO_CASE_FAIL target=group'):
            self.assertFalse(process_control_completed(incomplete))



class RcAdmissionEvidence(unittest.TestCase):
    def test_refusal_requires_launch_failure_and_no_child_evidence(self):
        from run import boot_preparation_rejected
        text = ('rc bootstrap authority unavailable: Permission denied; '
                'refusing protected launch\nstartup: cannot launch /etc/rc\n')
        case = 'capsule-rc-authority-missing'
        self.assertTrue(boot_preparation_rejected(text, case))
        self.assertFalse(boot_preparation_rejected('', case))
        self.assertFalse(boot_preparation_rejected(text.splitlines()[0], case))
        for marker in ('CAPSULE_BOOTSTRAP_PASS', 'CAPSULE_TEST_COMPLETE',
                       'PROGRAM_PASS', 'going to single user mode',
                       'Enter full pathname of shell'):
            with self.subTest(marker=marker):
                self.assertFalse(boot_preparation_rejected(text + marker, case))


class IsolationIOEvidence(unittest.TestCase):
    def test_complete_marker_required(self):
        marker = 'ISOLATION_IO_PASS inherited denial, bounded read grant, ceiling and release\n'
        self.assertTrue(isolation_io_completed(marker))
        for text in ('', marker * 2, marker + 'ISOLATION_IO_FAIL', marker[:-8]):
            self.assertFalse(isolation_io_completed(text))


COMPLETE = """CAPSULE_BOOTSTRAP_PASS
SYSTEM_GATE_DENY_PASS
AUDIT_CONDITION_PASS status readable, administration denied, condition unchanged
AUDIT_TRAIL_DENIAL_PASS repeated refusal, pathname cleanup, file and condition unchanged
CONSOLE_OUTPUT_ONLY_PASS
default service identity validated
capprotect shield active
startup: running /etc/rc
capsule_proto: switchboard ready
protected runtime storage ready
PROTECTED_RUNTIME_PASS
protected temporary storage ready:
STORAGE_PASS
PROGRAM_PASS /bin/sh script-pipeline-and-redirection
PROGRAM_PASS /bin/cat read-back
PROGRAM_PASS /bin/cp copy-content
PROGRAM_PASS /bin/mv move-content
PROGRAM_PASS /bin/rm remove-file
PROGRAM_PASS /bin/mkdir create-directory
PROGRAM_PASS /usr/bin/mktemp private-directory
PROGRAM_PASS /usr/bin/sort sort-content
PROGRAM_PASS /usr/sbin/pwd_mkdb alternate-account-databases
PROGRAM_PASS /usr/bin/cap_mkdb text-input-database-construction
CAPSULE_ROOT_POWEROFF_DENIED
CAPSULE_TEST_COMPLETE
"""
NATIVE = """CRYPTO_BOOTSTRAP_PASS provider sign/verify, corrupt signature and control escalation denied
NATIVE_SOFTWARE_SERVICE_PASS
"""


class CompletionTest(unittest.TestCase):
    def test_complete_evidence(self):
        self.assertTrue(capsule_completed(COMPLETE))
        self.assertTrue(capsule_completed(COMPLETE + NATIVE, native=True))

    def test_completion_marker_is_not_enough(self):
        self.assertFalse(capsule_completed("CAPSULE_TEST_COMPLETE\n"))
        for line in COMPLETE.splitlines():
            with self.subTest(missing=line):
                self.assertFalse(capsule_completed(COMPLETE.replace(line + "\n", "")))

    def test_failure_after_success(self):
        for failure in ("SYSTEM_GATE_FAIL", "CAPSULE_BOOTSTRAP_FAIL",
                        "STORAGE_FAIL", "panic:",
                        "Fatal trap", "lock order reversal", "SECUREBOOT_VM_FAIL"):
            with self.subTest(failure=failure):
                self.assertFalse(capsule_completed(COMPLETE + failure))

    def test_native_requires_all_provider_evidence(self):
        self.assertFalse(capsule_completed(COMPLETE, native=True))
        for line in NATIVE.splitlines():
            with self.subTest(missing=line):
                self.assertFalse(capsule_completed(
                    COMPLETE + NATIVE.replace(line + "\n", "", 1), native=True))
        self.assertFalse(capsule_completed(COMPLETE + NATIVE + "NATIVE_SERVICE_FAIL", native=True))

    def test_retired_native_marker_cannot_qualify_software_fixture(self):
        legacy = NATIVE.replace('NATIVE_SOFTWARE_SERVICE_PASS', 'NATIVE_SERVICE_PASS')
        self.assertFalse(capsule_completed(COMPLETE + legacy, native=True))

    def test_duplicate_crypto_completion_is_not_a_pass(self):
        marker = NATIVE.splitlines()[0]
        self.assertFalse(capsule_completed(COMPLETE + NATIVE + marker + "\n", native=True))

    def test_duplicate_program_marker_is_not_a_pass(self):
        self.assertFalse(capsule_completed(COMPLETE + "PROGRAM_PASS /bin/cat read-back\n"))


class CryptoRejectionTest(unittest.TestCase):
    evidence = ('CRYPTO_BOOTSTRAP_DENIED provider unavailable, independent provider operational, direct control denied\n'
                'service system.Crypto/bsdcrypto: exited status 13 (pid 36)\n')

    def test_requires_both_probe_and_refusal(self):
        self.assertTrue(crypto_rejected(self.evidence))
        for line in self.evidence.splitlines():
            self.assertFalse(crypto_rejected(self.evidence.replace(line + '\n', '')))
        self.assertFalse(crypto_rejected(self.evidence * 2))
        self.assertFalse(capsule_case_completed(self.evidence, 'capsule-native-crypto-absent'))
        self.assertTrue(capsule_case_completed(COMPLETE + self.evidence, 'capsule-native-crypto-absent'))
        self.assertFalse(capsule_case_completed(COMPLETE, 'capsule-native-crypto-wrong'))

    def test_interleaved_marker_is_not_evidence(self):
        marker = self.evidence.splitlines()[0]
        for damaged in ('daemon log' + marker, marker + 'daemon log', marker[:-1]):
            self.assertFalse(crypto_rejected(self.evidence.replace(marker, damaged)))

    def test_readiness_or_failure_invalidates_rejection(self):
        for marker in ('NATIVE_SERVICE_FAIL', 'CRYPTO_BOOTSTRAP_PASS', 'panic:',
                       'Fatal trap', 'lock order reversal',
                       'service system.Crypto/bsdcrypto: application reported ready',
                       "naming: 'system.Crypto' registered"):
            self.assertFalse(crypto_rejected(self.evidence + marker))


class CryptoReportTest(unittest.TestCase):
    path = '/Capabilities/System/Crypto.cap/Units/bsdcrypto.unit/bin/BSDCrypto'

    def status(self, text):
        return program_results([self.path], text)[0]['status']

    def test_operation_evidence(self):
        marker = NATIVE.splitlines()[0] + '\n'
        self.assertEqual(self.status(marker), 'tested-pass')
        self.assertEqual(self.status(''), 'included-not-exercised')
        self.assertNotEqual(self.status(marker * 2), 'tested-pass')
        for failure in ('NATIVE_SERVICE_FAIL', 'panic:', 'Fatal trap', 'lock order reversal'):
            self.assertNotEqual(self.status(marker + failure), 'tested-pass')

    def test_ready_is_only_startup(self):
        self.assertEqual(self.status('service system.Crypto/bsdcrypto: application reported ready'),
                         'started-only')


class RtldCompletionTest(unittest.TestCase):
    complete = '\n'.join(['RTLD_POLICY_CHECK ' + name for name in
        ('authenticated-root', 'writable-0', 'foreign-readonly-0',
         'writable-1', 'foreign-readonly-1', 'writable-2', 'foreign-readonly-2',
         'fifo', 'hints-writable', 'hints-foreign-readonly', 'hints-fifo',
         'ordinary-libmap-independent', 'ordinary-hints-independent')]
        + ['RTLD_POLICY_CHECK object-' + source + '-' + mode
           for source in ('approved', 'writable', 'readonly', 'fifo')
           for mode in ('name', 'path', 'fd')]
        + ['RTLD_POLICY_CHECK ordinary-' + source + '-' + mode
           for source in ('approved', 'writable', 'readonly')
           for mode in ('name', 'path', 'fd')] + ['RTLD_POLICY_PASS']) + '\n'

    def test_all_checks_required_once(self):
        self.assertTrue(rtld_completed(self.complete))
        for line in self.complete.splitlines():
            self.assertFalse(rtld_completed(self.complete.replace(line + '\n', '')))
            self.assertFalse(rtld_completed(self.complete + line + '\n'))
        self.assertFalse(rtld_completed('RTLD_POLICY_PASS\n'))

    def test_failure_is_not_completion(self):
        for error in ('RTLD_POLICY_FAIL', 'panic:', 'Fatal trap', 'lock order reversal'):
            self.assertFalse(rtld_completed(self.complete + error))





class ProviderCompletionTest(unittest.TestCase):
    complete = "\n".join(('service system.Filesystem/bsdfilesystem: application reported ready',
        'service test.StorageClient/client: application reported ready',
        'RC_HOSTID_PASS startup caches reset kernel-and-file-denials',
        'STORAGE_WORKER_MANAGEMENT_CHECK result=1',
        'STORAGE_CHANNEL_AFTER_FORK result=-1 errno=13',
        'STORAGE_RETAINED_AFTER_FORK read=-1 read_errno=13 write=-1 write_errno=13',
        'STORAGE_RETAINED_AFTER_CLEAR read=-1 read_errno=13 write=-1 write_errno=13',
        'STORAGE_PROVIDER_PASS phase=created challenge=' + 'a' * 32 + ' scopes=4',
        *(f'STORAGE_AFTER_RELEASE scope={scope} op={op} result=-1 errno=13'
          for scope in range(4) for op in ('read', 'write', 'open')),
        *('STORAGE_NAMESPACE_AFTER_' + stage + ' op=' + op + ' result=-1 errno=13'
          for stage in ('FORK', 'CLEAR') for op in ('open', 'create', 'truncate', 'setmode')))) + "\n"

    def test_worker_management_required(self):
        marker = 'STORAGE_WORKER_MANAGEMENT_CHECK result=1'
        for replacement in ('', 'STORAGE_WORKER_MANAGEMENT_CHECK result=0',
                            'STORAGE_WORKER_MANAGEMENT_CHECK result=2'):
            self.assertFalse(provider_completed(self.complete.replace(marker, replacement)))
        self.assertFalse(provider_completed(self.complete + marker + '\n'))

    def test_retained_release_required(self):
        marker = 'STORAGE_AFTER_RELEASE scope=0 op=read result=-1 errno=13'
        for replacement in ('', marker.replace('result=-1', 'result=1'),
                            marker.replace('errno=13', 'errno=9')):
            self.assertFalse(provider_completed(self.complete.replace(marker, replacement)))
        self.assertFalse(provider_completed(self.complete + marker + '\n'))

    def test_provider_restart_requires_actual_relaunch(self):
        restart = (self.complete +
            'service system.Filesystem/bsdfilesystem: started pid 40 uid 0\n'
            'service system.Filesystem/bsdfilesystem: exited status 75 (pid 40)\n'
            'service system.Filesystem/bsdfilesystem: started pid 50 uid 0\n'
            'service system.Filesystem/bsdfilesystem: application reported ready\n'
            'STORAGE_PROVIDER_RESTART recovered=1 read=-1 read_errno=1 write=-1 write_errno=1\n')
        self.assertTrue(provider_completed(restart, restart=True))
        self.assertFalse(provider_completed(restart))
        self.assertFalse(provider_completed(self.complete, restart=True))
        for before, after in (('pid 50', 'pid 40'), ('status 75', 'status 0'),
                              ('recovered=1', 'recovered=0'), ('read=-1 read_errno=1', 'read=1 read_errno=0'),
                              ('write_errno=1', 'write_errno=9')):
            self.assertFalse(provider_completed(restart.replace(before, after), restart=True))
        self.assertFalse(provider_completed(restart +
            'service system.Filesystem/bsdfilesystem: exited status 75 (pid 50)\n', restart=True))

    def test_channel_invocation_denial_required(self):
        marker = 'STORAGE_CHANNEL_AFTER_FORK result=-1 errno=13'
        for result in ('result=0 errno=0', 'result=-1 errno=9', 'result=-2 errno=0'):
            self.assertFalse(provider_completed(self.complete.replace(marker,
                'STORAGE_CHANNEL_AFTER_FORK ' + result)))
        self.assertFalse(provider_completed(self.complete + marker + '\n'))

    def test_operation_evidence_required(self):
        self.assertTrue(provider_completed(self.complete))
        for line in self.complete.splitlines():
            self.assertFalse(provider_completed(self.complete.replace(line + '\n', '')))
        self.assertFalse(provider_completed(self.complete + 'STORAGE_PROVIDER_FAIL client line=1'))
        self.assertFalse(provider_completed(self.complete + 'required storage-root grant unavailable'))
        self.assertFalse(provider_completed(self.complete + 'panic:'))
        self.assertFalse(provider_completed(self.complete + 'service test.StorageClient/client: exited status 1'))
        self.assertFalse(provider_completed(self.complete + 'service system.Filesystem/bsdfilesystem: exited status 0'))
        self.assertFalse(provider_completed(self.complete + self.complete))


    def test_retained_access_cannot_be_hidden_by_success_marker(self):
        for operation in ('read', 'write'):
            for result in (f'{operation}=1 {operation}_errno=0', f'{operation}=-1 {operation}_errno=9', f'{operation}=-2 {operation}_errno=0'):
                self.assertFalse(provider_completed(self.complete.replace(f'{operation}=-1 {operation}_errno=13', result)))
        self.assertFalse(provider_completed(self.complete + 'STORAGE_RETAINED_AFTER_CLEAR read=-1 read_errno=13 write=-1 write_errno=13\n'))

    def test_each_retained_phase_is_independent(self):
        for stage in ('FORK', 'CLEAR'):
            prefix = 'STORAGE_RETAINED_AFTER_' + stage
            good = prefix + ' read=-1 read_errno=13 write=-1 write_errno=13'
            for bad in ('read=1 read_errno=0 write=-1 write_errno=13',
                        'read=-1 read_errno=13 write=1 write_errno=0',
                        'read=-1 read_errno=9 write=-1 write_errno=13'):
                self.assertFalse(provider_completed(self.complete.replace(good, prefix + ' ' + bad)))
            self.assertFalse(provider_completed(self.complete + good + '\n'))

    def test_namespace_denials_are_independent(self):
        for stage in ('FORK', 'CLEAR'):
            for operation in ('open', 'create', 'truncate', 'setmode'):
                prefix = 'STORAGE_NAMESPACE_AFTER_' + stage + ' op=' + operation
                good = prefix + ' result=-1 errno=13'
                for bad in ('result=0 errno=0', 'result=-1 errno=9', 'result=-2 errno=0'):
                    self.assertFalse(provider_completed(self.complete.replace(good, prefix + ' ' + bad)))
                self.assertFalse(provider_completed(self.complete + good + '\n'))
                self.assertTrue(provider_completed(self.complete.replace(good, prefix + ' result=-1 errno=1')))

    def test_phase_and_challenge_are_required(self):
        self.assertTrue(provider_completed(self.complete, 'created', 'a' * 32))
        self.assertFalse(provider_completed(self.complete, 'recovered', 'a' * 32))
        self.assertFalse(provider_completed(self.complete, 'created', 'b' * 32))
        recovered = self.complete.replace('phase=created', 'phase=recovered')
        self.assertTrue(provider_completed(recovered, 'recovered', 'a' * 32))
        self.assertFalse(provider_completed(self.complete + 'STORAGE_PROVIDER_PASS malformed'))
        self.assertFalse(provider_completed(self.complete.replace('scopes=4', 'scopes=3')))

    def test_reboot_requires_disk_root_and_firmware_continuity(self):
        first = {'result': 'PASS', 'storage_phase': 'created', 'storage_challenge': 'a' * 32,
                 'storage_disk_before_sha256': '1' * 64, 'storage_disk_after_sha256': '2' * 64,
                 'root_image_sha256': '3' * 64, 'firmware_variables_after_sha256': '4' * 64,
                 'storage_disk_path': '/private/storage.img'}
        second = {'result': 'PASS', 'storage_phase': 'recovered', 'storage_challenge': 'a' * 32,
                  'storage_disk_before_sha256': '2' * 64, 'root_image_sha256': '3' * 64,
                  'firmware_variables_before_sha256': '4' * 64, 'storage_disk_path': '/private/storage.img'}
        self.assertTrue(provider_continuity(first, second))
        for key in second:
            with self.subTest(missing=key):
                self.assertFalse(provider_continuity(first, {k:v for k,v in second.items() if k != key}))
        for key in ('storage_disk_before_sha256', 'root_image_sha256', 'firmware_variables_before_sha256'):
            with self.subTest(changed=key):
                self.assertFalse(provider_continuity(first, dict(second, **{key: '9' * 64})))
        self.assertFalse(provider_continuity(first, dict(second, storage_phase='created')))
        self.assertFalse(provider_continuity(first, dict(second, storage_challenge='b' * 32)))
        self.assertFalse(provider_continuity(first, dict(second, storage_disk_path='/reset/storage.img')))
        self.assertFalse(provider_continuity(dict(first, storage_disk_before_sha256='2' * 64), second))
        self.assertFalse(provider_continuity(dict(first, result='FAIL'), second))

    def test_provider_requires_host_identity_checks(self):
        marker = 'RC_HOSTID_PASS startup caches reset kernel-and-file-denials'
        self.assertFalse(provider_completed(self.complete.replace(marker, '')))
        self.assertFalse(provider_completed(self.complete + '\n' + marker))
        self.assertFalse(provider_completed(self.complete + '\nRC_HOSTID_FAIL'))

    def test_program_report_distinguishes_readiness_and_operation(self):
        path = '/Capabilities/System/Filesystem.cap/Units/bsdfilesystem.unit/bin/BSDFilesystem'
        self.assertEqual(program_results([path], '')[0]['status'], 'included-not-exercised')
        ready = 'service system.Filesystem/bsdfilesystem: application reported ready'
        self.assertEqual(program_results([path], ready)[0]['status'], 'started-only')
        self.assertEqual(program_results([path], self.complete)[0]['status'], 'tested-pass')
        self.assertEqual(program_results([path], self.complete + 'STORAGE_PROVIDER_FAIL')[0]['status'], 'started-only')


if __name__ == "__main__":
    unittest.main()

class RetiredStorageProfile(unittest.TestCase):
    def test_anchor_profile_rejected(self):
        from run import full_case_names
        with self.assertRaisesRegex(ValueError, 'invalid suite profile'):
            full_case_names(True, 'anchor')

if __name__ == '__main__':
    unittest.main()
