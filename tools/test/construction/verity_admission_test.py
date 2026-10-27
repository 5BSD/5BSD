# SPDX-License-Identifier: BSD-2-Clause
"""Actual final mountroot gate with injected descriptor/mount checks."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <geom/verity/g_verity_verify.h>
struct mount {int unused;};
struct vnode {struct mount *v_mount;};
static struct mount mounted;
static struct vnode node={&mounted},*rootvnode=&node;
static bool root_mount_verity_requested;
static int decode_error,busy_error,check_error,held,checked,panicked;
static jmp_buf escape;
static void panic(const char *format,...) __attribute__((noreturn));
static void panic(const char *format,...) {(void)format;panicked=1;longjmp(escape,1);}
static int g_verity_preload_decode(struct g_verity_root *root) {
 memset(root,0,sizeof(*root));root->root_hash[0]=42;return decode_error;
}
static int vfs_busy(struct mount *mp,int flags) {
 assert(mp==&mounted && flags==0 && !held);
 if(busy_error)return busy_error;held=1;return 0;
}
static void vfs_unbusy(struct mount *mp) {assert(mp==&mounted && held);held=0;}
static int g_verity_check_ufs_root(struct mount *mp,const struct g_verity_root *expected) {
 assert(mp==&mounted && held && expected->root_hash[0]==42);checked++;return check_error;
}
"""
MAIN=r"""
int main(void) {
 for(int scenario=0;scenario<9;scenario++) {
  decode_error=busy_error=check_error=held=checked=panicked=0;
  root_mount_verity_requested=false;rootvnode=&node;node.v_mount=&mounted;
  if(scenario==0 || scenario==1)decode_error=ENOENT;
  if(scenario==1)root_mount_verity_requested=true;
  if(scenario==2)decode_error=EINVAL;
  if(scenario==3)decode_error=EEXIST;
  if(scenario==4)rootvnode=NULL;
  if(scenario==5)node.v_mount=NULL;
  if(scenario==6)busy_error=EBUSY;
  if(scenario==7)check_error=EAUTH;
  if(setjmp(escape)==0)vfs_mountroot_check_verity();
  assert(panicked==(scenario>=1 && scenario<=7));
  assert(checked==(scenario>=7) && !held);
 }
 return 0;
}
"""
class Admission(unittest.TestCase):
    def test_final_root_failure_stops_admission(self):
        source=(ROOT/'sys/kern/vfs_mountroot.c').read_text()
        start=source.index('static void\nvfs_mountroot_check_verity(')
        function=source[start:source.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+function+MAIN)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)
    def test_strict_mountpoint_selection(self):
        source=(ROOT/'sys/kern/vfs_mountroot.c').read_text()
        functions=[]
        for signature in ('static bool\nvfs_mountroot_strict_placement(',
                          'static int\nvfs_mountroot_placement_check('):
            start=source.index(signature)
            functions.append(source[start:source.index('\n}\n',start)+3])
        pre=PRE.replace('struct vnode {struct mount *v_mount;};',
            'struct vnode {struct mount *v_mount; int v_type; void *v_mountedhere;};')
        pre=pre.replace('node={&mounted}', 'node={&mounted, 1, NULL}')
        # Reuse only the descriptor and panic stubs, not admission-only stubs.
        pre=pre[:pre.index('static int vfs_busy(')]
        pre=pre.replace('decode_error,busy_error,check_error,held,checked,panicked',
                        'decode_error,panicked')
        main=r"""
int main(void) {
 struct mount foreign;
 struct vnode point={&mounted, VDIR, NULL};
 for(int scenario=0;scenario<4;scenario++) {
  root_mount_verity_requested=scenario==1;
  decode_error=scenario<2 ? ENOENT : (scenario==2 ? EINVAL : 0);
  panicked=0;
  if(setjmp(escape)==0)
   assert(vfs_mountroot_strict_placement()==(scenario==3));
  assert(panicked==(scenario==1 || scenario==2));
 }
 assert(vfs_mountroot_placement_check(&point,true)==0);
 assert(vfs_mountroot_placement_check(rootvnode,true)==EAUTH);
 point.v_mount=&foreign;
 assert(vfs_mountroot_placement_check(&point,true)==EAUTH);
 assert(vfs_mountroot_placement_check(&point,false)==0);
 point.v_mount=&mounted;point.v_mountedhere=&foreign;
 assert(vfs_mountroot_placement_check(&point,true)==EAUTH);
 point.v_mountedhere=NULL;point.v_type=2;
 assert(vfs_mountroot_placement_check(&point,true)==ENOTDIR);
 assert(vfs_mountroot_placement_check(&point,false)==ENOTDIR);
 return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'test.c';binary=Path(directory)/'test'
            c.write_text('#define GEOM_VERITY 1\n#define VDIR 1\n'+pre+'\n'.join(functions)+main)
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(ROOT/'sys'),str(c),'-o',str(binary)],check=True)
            subprocess.run([str(binary)],check=True,timeout=10)

    def test_gate_precedes_completion_and_callbacks(self):
        source=(ROOT/'sys/kern/vfs_mountroot.c').read_text()
        source=source[source.index('void\nvfs_mountroot(void)'):]
        gate=source.index('vfs_mountroot_check_verity();')
        self.assertLess(source.index('sbuf_delete(sb);'),gate)
        for operation in ('inittodr(timebase);','prison0.pr_root = rootvnode;',
                          'atomic_store_rel_int(&root_mount_complete, 1);',
                          'EVENTHANDLER_INVOKE(mountroot);'):
            self.assertLess(gate,source.index(operation))
if __name__=='__main__':unittest.main()
