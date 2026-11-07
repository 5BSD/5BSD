# SPDX-License-Identifier: BSD-2-Clause
import unittest
from mtree_reconcile import reconcile

class MtreeReconcile(unittest.TestCase):
    def setUp(self):
        self.old='a'*64;self.new='b'*64
        self.spec=('. type=dir uid=0 gid=0 mode=0755 flags=none\n'
            './file type=file uid=0 gid=0 mode=0444 flags=schg sha256digest='+self.old+'\n'
            './marker type=file uid=0 gid=0 mode=0644 flags=none sha256digest='+self.old+'\n').encode()
        self.log=('.:      flags ("none" is not "uarch")\nfile: \n\tflags ("schg" is not "schg,uarch")\n'
            '\tsha256digest (0x'+self.old+', 0x'+self.new+')\n./marker missing\n').encode()

    def check(self,log=None,hashes=None,consumed=('/marker',),tracking=True):
        return reconcile(self.log if log is None else log,self.spec,{'/file':self.new} if hashes is None else hashes,consumed,tracking)

    def test_only_independently_verified_changes(self):
        result=self.check()
        self.assertEqual([r['field'] for r in result],['zfs_archive','zfs_archive','verified_content','consumed'])
        self.assertEqual(self.check(b'',{},(),False),[])

    def test_security_metadata_and_unknown_diagnostics_fail(self):
        for log in (self.log.replace(b'schg,uarch',b'uarch'),
                    self.log.replace(b'schg,uarch',b'schg,sappnd,uarch'),
                    self.log.replace(b'flags ("none" is not "uarch")',b'uid (0, 1001)'),
                    self.log+b'mtree: unreadable: Permission denied\n',
                    self.log+b'unknown: flags ("none" is not "uarch")\n',
                    self.log+b'./file missing\n', self.log+b'file: \n'):
            with self.subTest(log=log),self.assertRaises(ValueError):self.check(log)

    def test_missing_or_mismatched_proofs_fail(self):
        for kwargs in ({'hashes':{}},{'hashes':{'/file':'c'*64}}, {'consumed':()},
                       {'tracking':False},{'log':self.log.replace(b'./marker missing\n',b'')},
                       {'log':self.log+self.log},
                       {'log':self.log.replace(self.old.encode(),b'd'*64)}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.check(**kwargs)

if __name__=='__main__':unittest.main()
