# SPDX-License-Identifier: BSD-2-Clause
"""Only ntptime's help path: exits before reading or changing the host clock."""
import os
from pathlib import Path
import subprocess
import unittest


class HelpTest(unittest.TestCase):
    def test_help_exits_before_clock_operations(self):
        root=Path(os.environ['TEST_SRCDIR'])/os.environ['TEST_WORKSPACE']
        result=subprocess.run([str(root/'usr.sbin/ntp/ntptime/ntptime'),'-h'],
            capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stdout,'')
        self.assertIn('usage:',result.stderr)
        self.assertIn('display this help info',result.stderr)


if __name__=='__main__':unittest.main()
