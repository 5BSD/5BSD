#!/usr/bin/env python3
"""Actual bsd.pkg.mk must finish creating archives before staging them."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]

class PackageOrder(unittest.TestCase):
    def test_parallel_archive_then_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p/'fixture.plist').write_text('/fixture\n')
            (p/'fixture.ucl').write_text('comment="fixture"\n')
            tool = p/'tools.py'
            tool.write_text('#!' + sys.executable + '\n' + '''import sys,time
from pathlib import Path
if 'create' in sys.argv:
 time.sleep(0.25)
 Path('5BSD-fixture-1.pkg').write_text('completed archive\\n')
else:
 Path(sys.argv[-1]).write_text('fixture metadata\\n')
''')
            tool.chmod(0o755)
            (p/'Makefile').write_text('WORLDPACKAGE=fixture\nSUBPACKAGES=\n'
                'SRCTOP='+str(ROOT)+'\nREPODIR='+str(p/'repo')+'\n'
                'PKG_VERSION=1\nPKG_ABI=FreeBSD:16:amd64\n'
                'WSTAGEDIR='+str(p)+'\nPKG_CMD='+str(tool)+'\nFLUA='+str(tool)+'\n'
                '.include <bsd.pkg.mk>\n')
            subprocess.run(['make','-m',str(ROOT/'share/mk'),'-j16','all','stagepackages'],
                           cwd=p,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual((p/'repo/FreeBSD:16:amd64/1/5BSD-fixture-1.pkg').read_text(),
                             'completed archive\n')

    def test_maintained_clean_is_separate_invocation(self):
        source=(ROOT/'Makefile.inc1').read_text()
        block=source[source.index('create-world-packages:'):source.index('create-sets-packages-jobs:')]
        self.assertNotIn('clean all stagepackages',block)
        self.assertEqual(block.count('${CROSSENV} ${MAKE} -C ${.CURDIR}/packages'),2)
        self.assertIn('\n\t    clean\n\t${CROSSENV}',block)
        self.assertIn('\n\t    stagepackages\n',block)

if __name__=='__main__':
    unittest.main()
