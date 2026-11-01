# SPDX-License-Identifier: BSD-2-Clause
"""Client option exits after initialization and before remote-host queries."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest


class ClientOptionsTest(unittest.TestCase):
    def test_help_and_version(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        programs = [(name, root / 'usr.sbin/ntp' / name / name)
                    for name in ['ntpdc', 'ntpq']]
        programs = [(name, path) for name, path in programs if path.is_file()]
        self.assertEqual(len(programs), 1, 'one explicitly declared client required')
        name, program = programs[0]
        generated = (program.parent / 'version.generated/version.c').read_text()
        versions = re.findall(r'const char \* Version = "([^"\n]*)";', generated)
        self.assertEqual(len(versions), 1, 'one declared generated version required')
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            environment = {'HOME': temporary, 'LC_ALL': 'C',
                           'LD_LIBRARY_PATH': os.environ['LD_LIBRARY_PATH']}
            for option in ['--help', '--version']:
                with self.subTest(program=name, option=option):
                    result = subprocess.run([str(program), option], cwd=temporary,
                                            env=environment, capture_output=True,
                                            text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(name, result.stdout)
                    if option == '--help':
                        self.assertIn('Usage:', result.stdout)
                        self.assertRegex(result.stdout, r'(?m)^\s+opt\s+version\s+')
                        self.assertRegex(result.stdout, r'(?m)^\s+-\?\s+no\s+help\s+')
                    else:
                        self.assertEqual(result.stdout, versions[0] + '\n')


if __name__ == '__main__':
    unittest.main()
