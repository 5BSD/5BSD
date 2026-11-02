# SPDX-License-Identifier: BSD-2-Clause
"""Only command-line branches that return before connecting to any service."""
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
    program = root / 'usr.sbin/wpa/hostapd_cli/hostapd_cli'
    libraries = [root / name for name in ['lib/libc', 'lib/libsys', 'lib/libutil',
                 'secure/lib/libssl', 'secure/lib/libcrypto', 'lib/libthr']]
else:
    program = options.program.resolve(strict=True)
    libraries = [path.resolve(strict=True) for path in options.library_directory]
environment = {'PATH': '', 'LC_ALL': 'C',
               'LD_LIBRARY_PATH': ':'.join(map(str, libraries))}


class Client(unittest.TestCase):
    def invoke(self, *arguments):
        self.assertNotEqual(os.geteuid(), 0)
        return subprocess.run([str(program), *arguments], env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_help(self):
        result = self.invoke('-h')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('usage: hostapd_cli', result.stderr)
        self.assertIn('commands:', result.stderr)

    def test_version(self):
        result = self.invoke('-v')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[0], r'^hostapd_cli v\S+$')
        self.assertIn('Jouni Malinen', lines[1])

    def test_unknown_option(self):
        result = self.invoke('-Z')
        self.assertEqual(result.returncode, 255)
        self.assertEqual(result.stdout, '')
        self.assertIn('usage: hostapd_cli', result.stderr)
        self.assertIn('illegal option -- Z', result.stderr)

    def test_declared_runtime(self):
        self.assertNotEqual(os.geteuid(), 0)
        trace = dict(environment, LD_TRACE_LOADED_OBJECTS='1',
                     LD_TRACE_LOADED_OBJECTS_FMT1='%o|%p\\n',
                     LD_TRACE_LOADED_OBJECTS_FMT2='%o|%p\\n')
        result = subprocess.run([str(program)], env=trace, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        loaded = []
        for line in result.stdout.splitlines():
            fields = line.split('|')
            self.assertEqual(len(fields), 2, line)
            name, path = fields
            if name == path == '[vdso]':
                continue
            self.assertIn(Path(path).parent, libraries, line)
            self.assertTrue(Path(path).is_file(), line)
            loaded.append(name)
        self.assertTrue(loaded)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *tests])
