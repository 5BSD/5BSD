# SPDX-License-Identifier: BSD-2-Clause
"""Exercise option exits without clock changes, network requests or key output."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class OptionsTest(unittest.TestCase):
    def test_options_exit_without_creating_files(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        programs = [(n, root / 'usr.sbin/ntp' / n / n)
                    for n in ['ntpdate', 'ntp-keygen', 'sntp']]
        programs = [(n, p) for n, p in programs if p.is_file()]
        self.assertEqual(len(programs), 1, 'one explicitly declared program required')
        name, program = programs[0]
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            environment = {'HOME': temporary, 'LC_ALL': 'C',
                           'LD_LIBRARY_PATH': os.environ['LD_LIBRARY_PATH']}
            if name == 'ntpdate':
                # Missing arguments reaches usage before any server query/clock change.
                result = subprocess.run([str(program)], cwd=temporary, env=environment,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('usage:', result.stderr)
                self.assertIn('server ...', result.stderr)
            else:
                # Make obtains Version from libntp; retain that exact ownership.
                generated = (root / 'usr.sbin/ntp/libntp/version.generated/version.c').read_text()
                versions = re.findall(r'const char \* Version = "([^"\n]*)";', generated)
                self.assertEqual(len(versions), 1)
                for option in ['--help', '--version']:
                    with self.subTest(program=name, option=option):
                        result = subprocess.run([str(program), option], cwd=temporary,
                                                env=environment, capture_output=True,
                                                text=True, timeout=20)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        if option == '--help':
                            self.assertIn(name, result.stdout)
                            self.assertIn('Usage:', result.stdout)
                            self.assertRegex(result.stdout, r'(?m)^\s+-\?\s+no\s+help\s+')
                        else:
                            self.assertEqual(result.stdout, versions[0] + '\n')
            self.assertEqual(list(Path(temporary).iterdir()), [], 'option exit created state')


if __name__ == '__main__':
    unittest.main()
