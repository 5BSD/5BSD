# SPDX-License-Identifier: BSD-2-Clause
"""Real dynamic CSV encoding with explicit native artifacts; no host encoder."""
import os
from pathlib import Path
import subprocess
import unittest

root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
directory = root / 'lib/libxo/encoder/csv'
driver = directory / 'encoder_test_driver'
plugin = directory / 'csv.enc.so'
libraries = [root / name for name in ['lib/libc', 'lib/libsys', 'lib/libxo/libxo', 'lib/libutil']]
environment = {'PATH': '', 'LC_ALL': 'C', 'LD_LIBRARY_PATH': ':'.join(map(str, libraries))}


class Encoder(unittest.TestCase):
    def invoke(self, options=''):
        self.assertNotEqual(os.geteuid(), 0)
        return subprocess.run([str(driver), str(plugin), options], env=environment,
                              capture_output=True, timeout=10)

    def test_quoting(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, b'name,value\n"a,""b""",42\n')

    def test_no_header(self):
        result = self.invoke('no-header')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, b'"a,""b""",42\n')

    def test_dos(self):
        result = self.invoke('dos')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, b'name,value\r\n"a,""b""",42\r\n')

    def test_unknown_option(self):
        result = self.invoke('unknown-option')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'unknown', result.stderr.lower())

    def test_declared_runtime(self):
        trace = dict(environment, LD_TRACE_LOADED_OBJECTS='1',
                     LD_TRACE_LOADED_OBJECTS_FMT1='%o|%p\\n',
                     LD_TRACE_LOADED_OBJECTS_FMT2='%o|%p\\n')
        result = subprocess.run([str(driver)], env=trace, capture_output=True,
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
    unittest.main()
