#!/usr/bin/env python3
"""Reject the obsolete default-policy option rather than silently ignoring it."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class DefaultPolicyConfig(unittest.TestCase):
    def test_obsolete_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            cf = p / 'TEST'
            cf.write_text('include GENERIC\nident PF_POLICY_CONFIG\ndevice pf\n'
                          'options PF_DEFAULT_TO_DROP\n')
            r = subprocess.run([os.environ.get('CONFIG', '/usr/sbin/config'),
                                '-s', str(ROOT / 'sys'), '-d', str(p / 'obj'), str(cf)],
                               cwd=ROOT / 'sys/amd64/conf', text=True, capture_output=True)
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('unknown option "PF_DEFAULT_TO_DROP"', r.stderr)

if __name__ == '__main__':
    unittest.main()
