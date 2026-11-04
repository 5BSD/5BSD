# SPDX-License-Identifier: BSD-2-Clause
"""Run both real userboot interpreters with the original hosted callback harness."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
for name in ['program', 'loader', 'lua', 'forth']:
    parser.add_argument('--' + name, type=Path, required=True)
parser.add_argument('--libraries', type=Path, nargs='+', required=True)
args, remaining = parser.parse_known_args()
sys.argv[1:] = remaining


class SharedUserboot(unittest.TestCase):
    def exercise(self, interpreter, library, status):
        libraries = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in args.libraries}))
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(args.loader), '-o', 'LIBRARY_PATH=' + libraries, '--',
                                     str(args.program), '-b', str(library.resolve(strict=True)), '-h', directory],
                                    input='echo USERBOOT_CALLBACK_PROBE\nshow script.lang\nquit\n',
                                    env={'LC_ALL': 'C', 'autoboot_delay': 'NO'}, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, status, (result.stdout, result.stderr))
            self.assertIn('Consoles: userboot', result.stdout)
            self.assertIn('User boot ' + interpreter + ', Revision', result.stdout)
            self.assertIn('USERBOOT_CALLBACK_PROBE', result.stdout.splitlines())
            self.assertIn('lua' if interpreter == 'lua' else 'forth', result.stdout.splitlines())
            self.assertEqual(result.stderr, '')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_lua_callback_console_and_environment(self):
        self.exercise('lua', args.lua, 1)

    def test_forth_callback_console_and_environment(self):
        self.exercise('4th', args.forth, 0)


if __name__ == '__main__':
    unittest.main()
