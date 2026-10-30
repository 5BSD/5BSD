# SPDX-License-Identifier: BSD-2-Clause
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import verify_evidence as verifier


def synthetic_boot(integrity=False):
    """Parser fixture, never firmware or guest execution evidence."""
    text = ('SECUREBOOT_VM_PASS\nRUNTIME_PROCESS_PASS\n'
        'RUNTIME_PROCESS_NAMESPACE_PASS\nRUNTIME_PROCESS_NAMESPACE_SHARING_PASS\n'
        'INVOCATION_PASS\nINVOCATION_CURRENT_PASS\nLEASE_PASS\n'
        '"file BOOTX64.EFI"\n' + 'SECUREBOOT_DENIED fixture\n' * 20 +
        'AUTHROOT_CHECK fixture\n' * 8)
    if not integrity:
        return text + 'SYSTEM_INTEGRITY_ABSENT\n'
    text += ('SYSTEM_INTEGRITY_PASS\nINIT_LIFETIME_PASS\nSYSTEM_GATE_PASS\n'
        'SYSTEM_GATE_AUTHORITY_PASS\nSYSTEM_ACCOUNTING_PASS\nSYSTEM_GATE_REAUTHORIZE_PASS\n'
        'SYSTEM_ENTROPY_CONTROL_PASS ordinary harvest write; hardware sources preserved; unprivileged and seed-bypass writes denied\n'
        'BIP_HOSTNAME_PASS root change and restore; nonroot denied\n'
        'ISOLATION_IO_PASS inherited denial, bounded read grant, ceiling and release\n'
        'PROTECTED_SPAWN_PASS before-exec, exec, fork, root attacks, descriptor control and core policy\n'
        'PROTECTED_SIGIO_PASS direct and group denial; live and exited origins; ordinary and self delivery controls\n'
        'SIGIO_CLEANUP_PASS\n'
        'BIP_EXEC_GUARD_PASS before-exec-denied ordinary-exec-debug-signal-schedule\n'
        'RTLD_POLICY_PASS\n')
    rtld = ['authenticated-root', 'fifo', 'hints-writable', 'hints-foreign-readonly',
            'hints-fifo', 'ordinary-libmap-independent', 'ordinary-hints-independent']
    rtld += [f'{kind}-{i}' for i in range(3) for kind in ('writable', 'foreign-readonly')]
    rtld += [f'object-{source}-{mode}' for source in ('approved', 'writable', 'readonly', 'fifo')
             for mode in ('name', 'path', 'fd')]
    rtld += [f'ordinary-{source}-{mode}' for source in ('approved', 'writable', 'readonly')
             for mode in ('name', 'path', 'fd')]
    return text + ''.join('RTLD_POLICY_CHECK ' + marker + '\n' for marker in rtld)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / 'input'
        self.input.write_bytes(b'trusted fixture input')
        self.report = dict(schema='org.5bsd.secureboot-test.v1', result='PASS',
                           complete_suite=True, mandatory_integrity=False, inputs={str(self.input): self.hash(self.input)},
                           requested_cases=['approved'], cases=[self.case('approved')])

    @staticmethod
    def hash(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def case(self, name):
        directory = self.root / name
        directory.mkdir()
        case = dict(name=name, result='PASS', explicit_evidence=True, qemu_exit=0,
                    expected='boot', forced_termination=False, root_image_sha256=None)
        for key, filename in [('serial_sha256', 'serial.log'), ('firmware_sha256', 'firmware.log'),
                ('disk_sha256', 'guest.img'), ('firmware_variables_after_sha256', 'vars.fd')]:
            path = directory / filename
            path.write_text(synthetic_boot() if filename == 'serial.log' else
                'ResetType Shutdown' if filename == 'firmware.log' else filename)
            case[key] = self.hash(path)
        return case

    def run_verify(self, require_complete=False):
        (self.root / 'result.json').write_text(json.dumps(self.report))
        return verifier.verify(self.root, require_complete)

    def test_generation_rejections_require_the_specific_reason(self):
        reasons = {'firmware-signed-manifest': 'BR_ERR_X509_NOT_TRUSTED',
                   'revoked-generation-manifest': 'Certificate is on forbidden list'}
        for name, reason in reasons.items():
            case = self.case(name)
            case.update(expected='loader', forced_termination=True,
                        terminated_after_rejection=True, terminated_after_completion=False)
            self.report.update(complete_suite=False, requested_cases=[name], cases=[case],
                               manifest_signer='explicit-generation')
            serial = self.root / name / 'serial.log'
            valid = ('cannot verify: /boot/manifest.certs: ' + reason + '\n'
                     'Secure Boot: verification failed: /boot/lua/loader.lua (-1)\n')
            for evidence in (valid, 'Secure Boot: verification failed: unrelated\n',
                    valid.replace(reason, 'cannot read certificates'),
                    valid.replace('/boot/manifest.certs:', '/boot/other.certs:'),
                    valid + 'SECUREBOOT_GUEST_STARTED\n',
                    valid + 'SECUREBOOT_VM_PASS\n', valid + 'Fatal trap\n'):
                with self.subTest(name=name, evidence=evidence):
                    serial.write_text(evidence)
                    case['serial_sha256'] = self.hash(serial)
                    if evidence == valid:
                        self.run_verify()
                    else:
                        with self.assertRaisesRegex(ValueError, 'generation trust rejection'):
                            self.run_verify()
            serial.write_text(valid)
            case['serial_sha256'] = self.hash(serial)
            self.report['manifest_signer'] = 'firmware-db'
            with self.assertRaisesRegex(ValueError, 'classification differs'):
                self.run_verify()

    def test_full_suite_flag_cannot_certify_one_case(self):
        self.report['mandatory_integrity'] = True
        self.report['suite_profile'] = dict(integrity=True, storage='none')
        (self.root / 'result.json').write_text(json.dumps(self.report))
        with self.assertRaisesRegex(ValueError, 'suite case plan'):
            verifier.verify(self.root, True)

    def test_canonical_full_plan_and_missing_case(self):
        for integrity in (False, True):
            names = verifier.full_case_names(integrity)
            for name in names:
                if name == 'approved' or (self.root / name).exists():
                    continue
                self.case(name)
            cases = []
            for name in names:
                item = dict(self.report['cases'][0], name=name)
                if name in verifier.BOOT_CASES:
                    item.update(expected='boot', forced_termination=False)
                    serial = self.root / name / 'serial.log'
                    serial.write_text(synthetic_boot(integrity))
                    item['serial_sha256'] = self.hash(serial)
                else:
                    item.update(expected='loader', forced_termination=True,
                                terminated_after_rejection=True, terminated_after_completion=False)
                for key, filename in [('serial_sha256', 'serial.log'), ('firmware_sha256', 'firmware.log'), ('disk_sha256', 'guest.img'), ('firmware_variables_after_sha256', 'vars.fd')]:
                    item[key] = self.hash(self.root / name / filename)
                cases.append(item)
            self.report.update(mandatory_integrity=integrity,
                               suite_profile=dict(integrity=integrity, storage='none'),
                               requested_cases=names, cases=cases)
            self.run_verify(require_complete=True)
            self.report['suite_profile']['storage'] = 'provider'
            with self.assertRaisesRegex(ValueError, 'suite case plan'):
                self.run_verify(require_complete=True)
            self.report['suite_profile']['storage'] = 'none'
            self.report['cases'] = cases[:-1]
            self.report['requested_cases'] = names[:-1]
            with self.assertRaisesRegex(ValueError, 'suite case plan'):
                self.run_verify(require_complete=True)

    def test_boot_summary_cannot_replace_guest_assertions(self):
        case = self.report['cases'][0]
        serial = self.root / 'approved/serial.log'
        for integrity in (False, True):
            valid = synthetic_boot(integrity)
            self.report['mandatory_integrity'] = integrity
            serial.write_text(valid); case['serial_sha256'] = self.hash(serial)
            self.run_verify()
            bad = ['', 'SECUREBOOT_VM_PASS\n', valid + 'panic: failed after success\n',
                   valid + 'Fatal trap\n', synthetic_boot(not integrity)]
            bad += [valid.replace(line + '\n', '', 1) for line in valid.splitlines()
                    if line != '"file BOOTX64.EFI"']
            for text in bad:
                with self.subTest(integrity=integrity, text=text[:80]):
                    serial.write_text(text)
                    case['serial_sha256'] = self.hash(serial)
                    with self.assertRaisesRegex(ValueError, 'accepted boot assertions'):
                        self.run_verify()

    def test_entropy_control_requires_one_exact_result(self):
        valid = synthetic_boot(True)
        marker = next(line for line in valid.splitlines()
                      if line.startswith('SYSTEM_ENTROPY_CONTROL_PASS'))
        self.assertTrue(verifier.boot_completed(valid, 'ResetType Shutdown',
                                               False, 0, True, 'approved'))
        for text in (valid.replace(marker + '\n', ''), valid + marker + '\n',
                     valid.replace(marker, marker.split()[0]),
                     valid.replace(marker, 'prefix ' + marker)):
            with self.subTest(text=text):
                self.assertFalse(verifier.boot_completed(text, 'ResetType Shutdown',
                                                        False, 0, True, 'approved'))

    def test_boot_requires_firmware_shutdown_and_integrity_mode(self):
        case = self.report['cases'][0]
        firmware = self.root / 'approved/firmware.log'
        firmware.write_text('no shutdown observed')
        case['firmware_sha256'] = self.hash(firmware)
        with self.assertRaisesRegex(ValueError, 'accepted boot assertions'):
            self.run_verify()
        firmware.write_text('ResetType Shutdown')
        case['firmware_sha256'] = self.hash(firmware)
        for mode in (None, 0, 'false'):
            self.report['mandatory_integrity'] = mode
            with self.assertRaisesRegex(ValueError, 'accepted boot assertions'):
                self.run_verify()
        self.assertFalse(verifier.boot_completed(synthetic_boot().replace('"file BOOTX64.EFI"', ''),
            'ResetType Shutdown', False, 0, False, 'boot-options'))

    def test_accepted_boot_cannot_be_relabelled_negative(self):
        case = self.report['cases'][0]
        case.update(expected='firmware', forced_termination=True,
                    terminated_after_rejection=True, terminated_after_completion=False)
        with self.assertRaisesRegex(ValueError, 'case classification differs'):
            self.run_verify()

    def test_valid_evidence_has_limited_scope(self):
        result = self.run_verify()
        self.assertEqual(len(result['verified_files']), 5)
        self.assertFalse(result['installed_system_qualified'])
        self.assertFalse(result['mandatory_persistent_storage_qualified'])

    def test_modified_input_or_serial_is_rejected(self):
        for path in (self.input, self.root / 'approved/serial.log'):
            original = path.read_bytes()
            path.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'retained evidence changed'):
                self.run_verify()
            path.write_bytes(original)

    def test_incomplete_or_failed_run_is_rejected(self):
        for key, value in [('complete_suite', False), ('result', 'RUNNING'), ('result', 'FAIL')]:
            original = self.report[key]
            self.report[key] = value
            with self.assertRaises(ValueError):
                self.run_verify(require_complete=True)
            self.report[key] = original

    def test_missing_duplicate_and_unrequested_cases_are_rejected(self):
        original = copy.deepcopy(self.report)
        for names in ([], ['approved', 'approved'], ['other']):
            self.report['requested_cases'] = names
            with self.assertRaises(ValueError):
                self.run_verify()
            self.report = copy.deepcopy(original)

    def test_forced_boot_and_missing_evidence_are_rejected(self):
        case = self.report['cases'][0]
        for key, value in [('forced_termination', True), ('explicit_evidence', False), ('qemu_exit', 1)]:
            original = case[key]
            case[key] = value
            with self.assertRaises(ValueError):
                self.run_verify()
            case[key] = original

    def test_negative_case_requires_rejection(self):
        case = self.case('unsigned-loader')
        self.report.update(cases=[case], requested_cases=['unsigned-loader'])
        case.update(expected='firmware', forced_termination=True,
                    terminated_after_rejection=False, terminated_after_completion=False)
        with self.assertRaisesRegex(ValueError, 'lacks recorded rejection'):
            self.run_verify()
        case['terminated_after_rejection'] = True
        self.run_verify()





    def storage_pair(self):
        from runner_test import ProviderCompletionTest
        a, b = (self.case(name) for name in ('capsule-storage', 'capsule-storage-reboot'))
        disk = self.root / 'storage.img'
        disk.write_bytes(b'persisted data')
        for c, phase in ((a, 'created'), (b, 'recovered')):
            c.update(expected='capsule', forced_termination=True,
                     terminated_after_completion=True, terminated_after_rejection=False,
                     storage_phase=phase, storage_challenge='a' * 32,
                     storage_disk_path=str(disk), storage_disk_before_sha256=self.hash(disk),
                     storage_disk_after_sha256=self.hash(disk),
                     firmware_variables_before_sha256=c['firmware_variables_after_sha256'])
            serial = self.root / c['name'] / 'serial.log'
            serial.write_text(ProviderCompletionTest.complete.replace('phase=created', 'phase=' + phase))
            c['serial_sha256'] = self.hash(serial)
        self.report.update(cases=[a, b], requested_cases=[a['name'], b['name']],
                           storage_reboot_continuity='PASS')
        return a, b

    def test_provider_report_cannot_replace_observation(self):
        a, b = self.storage_pair()
        serial = self.root / a['name'] / 'serial.log'
        original = serial.read_text()
        serial.write_text(original.replace('scope=0 op=read result=-1', 'scope=0 op=read result=1'))
        a['serial_sha256'] = self.hash(serial)
        with self.assertRaisesRegex(ValueError, 'provider acceptance'):
            self.run_verify()
        serial.write_text(original)
        a['serial_sha256'] = self.hash(serial)
        self.report['provider_crash'] = True
        with self.assertRaisesRegex(ValueError, 'provider acceptance'):
            self.run_verify()
        self.report['provider_crash'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'invalid provider crash mode'):
            self.run_verify()

    def test_retired_storage_cases_rejected(self):
        for name in ('storage-anchor', 'storage-mapped', 'storage-attached', 'storage-ordinary', 'capsule-session-storage'):
            case = self.case(name)
            case['expected'] = 'storage-anchor'
            self.report.update(cases=[case], requested_cases=[name])
            with self.assertRaisesRegex(ValueError, 'retired BIP storage case'):
                self.run_verify()

    def test_storage_handoff_and_final_bytes(self):
        a, b = self.storage_pair()
        self.assertTrue(self.run_verify()['storage_continuity_verified'])
        for key in ('storage_challenge', 'storage_disk_before_sha256', 'firmware_variables_before_sha256'):
            original = b[key]
            b[key] = 'changed'
            with self.assertRaises(ValueError):
                self.run_verify()
            b[key] = original
        Path(b['storage_disk_path']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'retained evidence changed'):
            self.run_verify()


    def test_retired_session_metadata_rejected(self):
        for field, value in (('session_storage_principals', ['a', 'b', 'denied']),
                             ('provider_lifecycle', True)):
            self.report[field] = value
            with self.assertRaisesRegex(ValueError, 'retired session storage metadata'):
                self.run_verify()
            del self.report[field]

    def test_retired_session_policy_receipts_rejected(self):
        for suffix in ('invalid', 'nul-key', 'unknown-right', 'include'):
            name = 'capsule-session-policy-' + suffix
            case = self.case(name)
            case['expected'] = 'session-policy'
            self.report.update(cases=[case], requested_cases=[name])
            with self.assertRaisesRegex(ValueError, 'retired session policy case'):
                self.run_verify()

    def test_missing_storage_boot(self):
        self.storage_pair()
        self.report['cases'].pop()
        self.report['requested_cases'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete storage boot pair'):
            self.run_verify()


if __name__ == '__main__':
    unittest.main()
