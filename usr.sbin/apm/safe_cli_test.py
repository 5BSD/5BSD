# SPDX-License-Identifier: BSD-2-Clause
"""Only invalid single options returning before open(/dev/apm); no power IO."""
import argparse
import os
from pathlib import Path
import subprocess
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--program', type=Path)
parser.add_argument('--library-directory', action='append', default=[], type=Path)
options, tests = parser.parse_known_args()
if options.program is None:
    root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
    program = root / 'usr.sbin/apm/apm'
    libraries = [root / name for name in ['lib/libc', 'lib/libsys']]
else:
    program = options.program.resolve(strict=True)
    libraries = [p.resolve(strict=True) for p in options.library_directory]
environment = {'PATH': '', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': ':'.join(map(str, libraries))}


class SafeCLI(unittest.TestCase):
    def invalid(self, option):
        self.assertNotEqual(os.geteuid(), 0)
        result = subprocess.run([str(program), option], env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('illegal option -- ' + option[-1], result.stderr)
        self.assertIn('usage: apm [-abltzZ]', result.stderr)
        self.assertNotIn("can't open", result.stderr)

    def test_help_is_invalid(self):
        self.invalid('-h')

    def test_unknown_option(self):
        self.invalid('-?')

    def test_declared_runtime(self):
        trace = dict(environment, LD_TRACE_LOADED_OBJECTS='1',
                     LD_TRACE_LOADED_OBJECTS_FMT1='%o|%p\\n',
                     LD_TRACE_LOADED_OBJECTS_FMT2='%o|%p\\n')
        result = subprocess.run([str(program)], env=trace, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        paths = []
        for line in result.stdout.splitlines():
            name, path = line.split('|')
            if name == path == '[vdso]':
                continue
            self.assertIn(Path(path).parent, libraries)
            self.assertTrue(Path(path).is_file())
            paths.append(path)
        self.assertTrue(paths)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *tests])
