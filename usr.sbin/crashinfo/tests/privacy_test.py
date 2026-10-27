#!/usr/bin/env python3
"""Exercise report creation without a dump or any debugger execution."""
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'crashinfo.sh'

class ReportPrivacy(unittest.TestCase):
    def test_batch_report_is_private_with_permissive_caller_umask(self):
        for caller_umask in (0o022, 0o000):
            with self.subTest(caller_umask=oct(caller_umask)):
                with tempfile.TemporaryDirectory(prefix='crashinfo-privacy-') as tmp:
                    # No vmcore exists. The actual script must stop before
                    # invoking a debugger, regardless of whether gdb is installed.
                    result = subprocess.run(['/bin/sh', str(SOURCE), '-b', '-d', tmp,
                                             '-n', '0'], umask=caller_umask,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    report = Path(tmp) / 'core.txt.0'
                    self.assertTrue(report.is_file())
                    self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
                    self.assertFalse((Path(tmp) / 'vmcore.0').exists())
                    self.assertEqual(os.readlink(Path(tmp) / 'core.txt.last'), str(report))

if __name__ == '__main__':
    unittest.main()
