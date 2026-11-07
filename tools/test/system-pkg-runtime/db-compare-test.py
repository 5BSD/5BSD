# SPDX-License-Identifier: BSD-2-Clause
"""Read-only logical comparison of actual pwd_mkdb-generated databases."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

root=Path(os.environ['TEST_SRCDIR'])/os.environ['TEST_WORKSPACE']
sys.path.insert(0,str(root/'tools/build/bazel'))
from generate_accounts import generate

class DatabaseCompare(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR'])
        self.addCleanup(self.temporary.cleanup)
        self.work=Path(self.temporary.name)
        self.tool=root/'tools/test/system-pkg-runtime/db_compare'
        self.builder=root/'usr.sbin/pwd_mkdb/pwd_mkdb'
        self.master='root:*:0:0::0:0:Root:/root:/bin/sh\nuser:*:2001:65533::0:0:User:/home/user:/bin/sh\n'

    def database(self,name,master):
        source=self.work/(name+'.master');source.write_text(master)
        output=self.work/name
        generate(str(self.builder),source,str(root/'etc/shells'),output)
        return output

    def compare(self,left,right,success):
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for directory in (left,right) for p in directory.glob('*.db')}
        for name in ('pwd.db','spwd.db'):
            result=subprocess.run([str(self.tool),str(left/name),str(right/name)],capture_output=True,text=True)
            self.assertEqual(result.returncode==0,success,(name,result.stdout,result.stderr))
            if success:self.assertRegex(result.stdout,r'^DB_RECORDS_EQUAL [1-9][0-9]*\n$')
        self.assertEqual(before,{p:hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_equivalent_databases(self):
        self.compare(self.database('left',self.master),self.database('right',self.master),True)

    def test_changed_records(self):
        self.compare(self.database('left',self.master),self.database('right',self.master.replace(':2001:',':2002:')),False)

    def test_additional_records_in_either_direction(self):
        left=self.database('left',self.master)
        right=self.database('right',self.master+'extra:*:2002:65533::0:0:Extra:/home/extra:/bin/sh\n')
        self.compare(left,right,False);self.compare(right,left,False)

if __name__=='__main__':unittest.main()
