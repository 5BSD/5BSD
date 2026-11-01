# SPDX-License-Identifier: BSD-2-Clause
"""Option exits are parsed before daemon logging, clock control or networking."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class OptionsTest(unittest.TestCase):
    def test_help_and_version(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        program = root / 'usr.sbin/ntp/ntpd/ntpd'
        generated = (program.parent / 'version.generated/version.c').read_text()
        versions = re.findall(r'const char \* Version = "([^"\n]*)";', generated)
        self.assertEqual(len(versions), 1)
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            environment = {'HOME': temporary, 'LC_ALL': 'C',
                           'LD_LIBRARY_PATH': os.environ['LD_LIBRARY_PATH']}
            for option in ['--help', '--version']:
                with self.subTest(option=option):
                    result = subprocess.run([str(program), option], cwd=temporary,
                                            env=environment, capture_output=True,
                                            text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if option == '--help':
                        self.assertIn('ntpd', result.stdout)
                        self.assertIn('Usage:', result.stdout)
                        self.assertRegex(result.stdout, r'(?m)^\s+-\?\s+no\s+help\s+')
                    else:
                        self.assertEqual(result.stdout, versions[0] + '\n')
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
