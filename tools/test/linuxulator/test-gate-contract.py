#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Keep independently maintained guest, host and ATF unshare contracts aligned."""
import importlib.util
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qemu_gate', HERE / 'qemu-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateContractTest(unittest.TestCase):
    def test_guest_unshare_cases_match_verifier(self):
        script = (HERE / 'guest-gate.sh').read_text()
        loops = re.findall(r'for case in ([^;\n]+); do\s*\n'
                           r'[^\n]*/root/linux_unshare "\$case"', script)
        self.assertEqual(len(loops), 1)
        cases = loops[0].split()
        self.assertEqual(len(cases), len(set(cases)), 'duplicate guest cases')
        self.assertEqual(set(cases), gate.UNSHARE_CASES)
        self.assertEqual(len(cases) * 2 * 3, 102)

    def test_atf_unshare_registration_matches_guest_contract(self):
        source = HERE.parents[2] / 'tests/sys/kern/linux_unshare_test.sh'
        cases = re.findall(r'^\s*atf_add_test_case (\w+)\s*$',
                           source.read_text(), re.M)
        self.assertEqual(len(cases), len(set(cases)), 'duplicate ATF cases')
        self.assertEqual(set(cases), gate.UNSHARE_CASES | {'capmode'})


class ArtifactContractTest(unittest.TestCase):
    def setUp(self):
        self.manifest = {'/boot/kernel/kernel': 'a' * 64, '/root/probe': 'b' * 64}
        self.rows = [f'SHA256 ({p}) = {h}' for p, h in self.manifest.items()]
        self.console = '\n'.join(['GATE_ARTIFACTS_BEGIN', *self.rows,
                                  'GATE_ARTIFACTS_END']) + '\n'

    def test_complete(self):
        self.assertEqual(gate.artifact_errors(self.console, self.manifest), [])

    def test_corrupt_hashes(self):
        for text in [self.console.replace(self.rows[0] + '\n', ''),
                     self.console.replace(self.rows[0], self.rows[1]),
                     self.console.replace('a' * 64, 'c' * 64),
                     self.console.replace(self.rows[0], self.rows[0] + '\n' + self.rows[1])]:
            with self.subTest(text=text):
                self.assertTrue(gate.artifact_errors(text, self.manifest))

    def test_markers(self):
        for text in [self.console.replace('GATE_ARTIFACTS_END', ''),
                     self.console + 'GATE_ARTIFACTS_BEGIN\n',
                     'GATE_ARTIFACTS_END\nGATE_ARTIFACTS_BEGIN\n']:
            with self.subTest(text=text):
                self.assertTrue(gate.artifact_errors(text, self.manifest))

    def test_empty_manifest(self):
        self.assertTrue(gate.artifact_errors(self.console, {}))


if __name__ == '__main__':
    unittest.main()
