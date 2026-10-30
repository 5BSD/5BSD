# SPDX-License-Identifier: BSD-2-Clause
"""Check VM preflight refusals before staging or launching QEMU."""
from pathlib import Path
import subprocess
import unittest


class Arguments(unittest.TestCase):
    def command(self):
        result = ['/usr/local/bin/python3.12', '-B', str(Path(__file__).with_name('readback-state-vm.py'))]
        for name in ('boot-root','world','python-prefix','objtop','fixture-objtop','work','qemu-data','initialization','input-disk'):
            result += ['--'+name, '/nonexistent-readback-input']
        return result + ['--qemu', '/nonexistent-qemu', '--kernconf', 'GENERIC']

    def refused(self, options, message):
        result = subprocess.run(self.command()+options,capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertIn(message,result.stderr)
        self.assertNotIn('Traceback',result.stderr)

    def test_invalid_time_budget(self):
        for values in (['--case-timeout','0'],['--case-timeout','2100'],['--vm-timeout','86401']):
            with self.subTest(values=values): self.refused(values,'case timeout')

    def test_invalid_capacity(self):
        for values in (['--root-mib','63'],['--memory-mib','511']):
            with self.subTest(values=values): self.refused(values,'invalid root or memory')

    def test_missing_initialization(self):
        self.refused([],'initialization must be a regular')


if __name__ == '__main__': unittest.main()
