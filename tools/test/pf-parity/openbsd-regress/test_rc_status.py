#!/usr/bin/env python3
"""Exercise the actual RC status function against the vendor CLI contract."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[4]

class RcStatus(unittest.TestCase):
    def test_enabled_disabled_error_and_missing_device(self):
        source=Path(os.environ.get('PF_RC_SOURCE', ROOT/'libexec/rc/rc.d/pf')).read_text()
        body=re.search(r'pf_status\(\)\n\{.*?\n\}',source,re.S).group(0)
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'device').symlink_to('/dev/null')
            mock=p/'pfctl'
            mock.write_text('''#!/bin/sh
[ "$#" = 2 ] && [ "$1" = -s ] && [ "$2" = info ] || exit 91
case "$STATE" in
 enabled) printf 'Status: Enabled                                  Debug: err\\nfixture counters\\n';;
 disabled) printf 'Status: Disabled                                 Debug: err\\nfixture counters\\n';;
 error) echo 'backend diagnostic' >&2; exit 7;;
esac
''')
            mock.chmod(0o755)
            code='pf_program='+str(mock)+'\n'+body.replace('/dev/pf',str(p/'device'))+'\npf_status\n'
            for state, expected in [('enabled',0),('disabled',1),('error',7)]:
                result=subprocess.run(['sh','-c',code],env=dict(os.environ,STATE=state),text=True,capture_output=True)
                self.assertEqual(result.returncode,expected,(state,result.stdout,result.stderr))
                if state=='error':self.assertIn('backend diagnostic',result.stderr)
                else:self.assertIn('fixture counters',result.stdout)
            (p/'device').unlink()
            result=subprocess.run(['sh','-c',code],env=dict(os.environ,STATE='enabled'),text=True,capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertIn('pf.ko is not loaded',result.stdout)

if __name__=='__main__':unittest.main()
