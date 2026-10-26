# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real CLI preflight without touching images or launching QEMU."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

class MemoryCLI(unittest.TestCase):
    def invoke(self, value):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            work = root / 'must-not-be-created'
            command = [sys.executable, '-B', str(pathlib.Path(__file__).with_name('run-vm.py')),
                '--root', str(root), '--objtop', str(root), '--work', str(work),
                '--qemu', str(root / 'absent-qemu'), '--qemu-data', str(root)]
            if value is not None:
                command += ['--memory-mib', str(value)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertFalse(work.exists())
            self.assertEqual(result.returncode, 2)
            return result.stderr

    def test_outside_budget_rejected_before_paths(self):
        for value in [-1, 0, 511, 2049, 4096, 999999999999999999999]:
            with self.subTest(value=value):
                self.assertIn('guest RAM must be between 512 and 2048 MiB', self.invoke(value))

    def test_boundaries_and_default_reach_path_guard(self):
        for value in [None, 512, 1024, 2048]:
            with self.subTest(value=value):
                self.assertIn('fixtures must use standard /usr/obj/usr/src staging', self.invoke(value))

    def test_noninteger_rejected(self):
        for value in ['2G', '2048.0', 'NaN']:
            with self.subTest(value=value):
                self.assertIn('invalid int value', self.invoke(value))

if __name__ == '__main__':
    unittest.main()
