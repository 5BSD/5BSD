# SPDX-License-Identifier: BSD-2-Clause
import unittest
from evidence import execution, rejection, authenticated_update, authenticated_replay

ATTEMPT = 'BdsDxe: loading Boot0001 "UEFI Misc Device" from PciRoot(0x0)/Pci(0x2,0x0)'
DENIAL = ATTEMPT.replace('loading ', 'failed to load ') + ': Access Denied'
END = 'BdsDxe: No bootable option or device was found.'
VALID = '\n'.join((ATTEMPT, DENIAL, END))


class EvidenceTest(unittest.TestCase):
    def test_authenticated_update(self):
        lines = ['AUTH_UPDATE_UNAUTHORIZED_REJECTED', 'AUTH_UPDATE_ACCEPTED',
                 'AUTH_UPDATE_REPLAY_REJECTED', 'AUTH_UPDATE_PASS']
        self.assertTrue(authenticated_update('\n'.join(lines)))
        for changed in (lines[:-1], lines[1:], lines[::-1], lines + [lines[-1]],
                        lines + ['AUTH_UPDATE_FAIL']):
            self.assertFalse(authenticated_update('\n'.join(changed)))

    def test_persistent_replay(self):
        lines = ['AUTH_PERSISTED_REPLAY_REJECTED', 'AUTH_NEWER_UPDATE_ACCEPTED',
                 'AUTH_NEWER_REPLAY_REJECTED', 'AUTH_REPLAY_PASS']
        self.assertTrue(authenticated_replay('\n'.join(lines)))
        for changed in (lines[:-1], lines[1:], lines[::-1], lines + [lines[-1]],
                        lines + ['AUTH_UPDATE_FAIL']):
            self.assertFalse(authenticated_replay('\n'.join(changed)))

    def test_denial(self):
        self.assertTrue(rejection(VALID))

    def test_variable_identity(self):
        self.assertTrue(rejection(VALID.replace('Boot0001', 'Boot00AB').replace('Pci(0x2,0x0)', 'Pci(0x5,0x0)')))

    def test_ansi_console(self):
        self.assertTrue(rejection('\x1b[2J\x1b[01;01H\x1b[=3h' + VALID))

    def test_missing_evidence(self):
        for text in ('', END, ATTEMPT, DENIAL, ATTEMPT + '\n' + END):
            with self.subTest(text=text): self.assertFalse(rejection(text))

    def test_wrong_device(self):
        self.assertFalse(rejection(VALID.replace(DENIAL, DENIAL.replace('Boot0001', 'Boot0002'))))

    def test_wrong_failure(self):
        self.assertFalse(rejection(VALID.replace('Access Denied', 'Not Found')))

    def test_extra_attempt(self):
        self.assertFalse(rejection(VALID + '\n' + ATTEMPT.replace('Boot0001', 'Boot0002')))

    def test_execution_contradiction(self):
        for extra in ('FIRMWARE_PROBE_EXECUTED', 'FIRMWARE_PROBE_VARIABLE_FAILURE', ATTEMPT.replace('loading ', 'starting ')):
            with self.subTest(extra=extra): self.assertFalse(rejection(VALID + '\n' + extra))

    def test_order_and_duplicates(self):
        self.assertFalse(rejection('\n'.join((DENIAL, ATTEMPT, END))))
        self.assertFalse(rejection(VALID + '\n' + DENIAL))
        self.assertFalse(rejection(VALID + '\n' + END))

    def test_execution_state(self):
        good = 'FIRMWARE_PROBE SecureBoot=1\nFIRMWARE_PROBE SetupMode=0\nFIRMWARE_PROBE_EXECUTED\n'
        self.assertTrue(execution(good, True))
        self.assertFalse(execution(good, False))
        self.assertFalse(execution(good + 'FIRMWARE_PROBE_EXECUTED\n', True))
        self.assertFalse(execution(good + 'FIRMWARE_PROBE_VARIABLE_FAILURE\n', True))


if __name__ == '__main__':
    unittest.main()
