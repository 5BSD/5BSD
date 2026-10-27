# SPDX-License-Identifier: BSD-2-Clause
"""Actual VFS export classification and mount-flag update blocks."""
from pathlib import Path
import resource,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/param.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#ifndef MNTK_ASYNC
#define MNTK_ASYNC 0x00000001
#endif
#define KASSERT(c,m) assert(c)
struct mount {uint64_t mnt_flag;unsigned mnt_kern_flag;};
'''
MAIN=r'''
int main(void) {
 const uint64_t export=MNT_UPDATE|MNT_EXPORTED;
 assert(classify(export,false,true));
 assert(!classify(export,true,true));
 assert(!classify(export,false,false));
 for(unsigned bit=0;bit<64;bit++) {
  uint64_t flag=UINT64_C(1)<<bit;
  bool permitted=(flag & export)!=0;
  assert(classify(export|flag,false,true)==permitted);
 }
 const uint64_t protected=MNT_RDONLY|MNT_ROOTFS|MNT_NOSUID|MNT_NOEXEC|
  MNT_NOSYMFOLLOW|MNT_NOATIME|MNT_ASYNC;
 struct mount m={.mnt_flag=protected,.mnt_kern_flag=MNTK_ASYNC};
 assert(update(&m,export,true)==0);
 assert(m.mnt_flag==(protected|MNT_UPDATE));
 assert(m.mnt_kern_flag==MNTK_ASYNC);
 for(unsigned bit=0;bit<64;bit++) {
  uint64_t old=UINT64_C(1)<<bit;
  m=(struct mount){.mnt_flag=old};
  assert(update(&m,export,true)==0);
  assert(m.mnt_flag==(old|MNT_UPDATE));
 }
 /* Ordinary remounts retain their explicit option-changing behavior. */
 m=(struct mount){.mnt_flag=protected,.mnt_kern_flag=MNTK_ASYNC};
 assert(update(&m,MNT_UPDATE|MNT_RDONLY|MNT_NOEXEC,false)==0);
 assert((m.mnt_flag&MNT_NOEXEC)!=0 && (m.mnt_flag&MNT_NOSUID)==0);
 assert((m.mnt_flag&MNT_ASYNC)==0 && (m.mnt_kern_flag&MNTK_ASYNC)==0);
 m=(struct mount){0};
 assert(update(&m,MNT_UPDATE|MNT_UNION,false)==MNT_UNION);
 assert((m.mnt_flag&MNT_UNION)==0);
 return 0;
}
'''
class Exports(unittest.TestCase):
    def test_export_flags_and_classification(self):
        s=(ROOT/'sys/kern/vfs_mount.c').read_text()
        begin=s.index('\tif (has_nonexport ||')
        end=s.index('\n\t/*',begin)
        classify=s[begin:end]
        begin=s.index('\tif (only_export) {\n\t\tKASSERT')
        end=s.index('\n\trootvp =',begin)
        update=s[begin:end]
        body=('static bool classify(uint64_t fsflags,bool has_nonexport,bool only_export) {\n'+classify+
            '\nreturn only_export;\n}\nstatic uint64_t update(struct mount *mp,uint64_t fsflags,bool only_export) {\nuint64_t mnt_union=0;\n'+update+'\nreturn mnt_union;\n}\n')
        with tempfile.TemporaryDirectory(prefix='export-flags-') as directory:
            p=Path(directory)
            for mutation in (False,True):
                candidate=body.replace('if (only_export) {','if (false) {',1) if mutation else body
                (p/'test.c').write_text(PRE+candidate+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(ROOT/'sys'),str(p/'test.c'),'-o',str(p/'test')],check=True)
                result=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=10,
                    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutation:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('protected|MNT_UPDATE',result.stderr)
                else:self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
