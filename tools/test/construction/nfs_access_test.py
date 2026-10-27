# SPDX-License-Identifier: BSD-2-Clause
"""Actual NFS access helper: request credentials, mandatory denial, DAC fallback."""
from pathlib import Path
import resource,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#define MAC 1
#define VWRITE 2
#define VREAD 4
#define VDELETE 8
#define VDELETE_CHILD 16
#define VEXPLICIT_DENY 32
#define VREG 1
#define VDIR 2
#define VLNK 3
#define MNT_RDONLY 1
#define LK_SHARED 1
#define NFSACCESS_DELETE 1
#define NFSACCCHK_NOOVERRIDE 0
#define NFSACCCHK_ALLOWROOT 1
#define NFSACCCHK_ALLOWOWNER 2
#define NFSEXITCODE(e) ((void)(e))
typedef int accmode_t;typedef uint32_t u_int32_t;
struct mount {int mnt_flag;};struct vnode {struct mount *v_mount;int v_type;};
struct ucred {int cr_uid;};struct thread {struct ucred *td_ucred;};
struct nfsexstuff {int ro;};struct vattr {int va_uid;};
static struct mount mount;static struct vnode node={&mount,VREG};
static struct ucred request,ambient={.cr_uid=999};
static struct thread td={.td_ucred=&ambient};
static int denial,dac_error,checks,accesses,attrs,locks,unlocks;
#define NFSVNO_EXRDONLY(e) ((e)->ro)
static int NFSVOPLOCK(struct vnode *v,int flags) {assert(v==&node&&flags==LK_SHARED);locks++;return 0;}
static void NFSVOPUNLOCK(struct vnode *v) {assert(v==&node);unlocks++;}
#define VOP_IS_TEXT(v) 0
static int mac_vnode_check_access(struct ucred *c,struct vnode *v,int mode) {
 assert(c==&request && c!=td.td_ucred && v==&node && mode==VREAD);checks++;return denial;
}
static int VOP_ACCESSX(struct vnode *v,int mode,struct ucred *c,struct thread *t) {
 assert(v==&node&&mode==VREAD&&c==&request&&t==&td);accesses++;return dac_error;
}
static int VOP_GETATTR(struct vnode *v,struct vattr *a,struct ucred *c) {
 assert(v==&node&&c==&request);attrs++;a->va_uid=request.cr_uid;return 0;
}
'''
MAIN=r'''
int main(void) {
 struct nfsexstuff exp={0};unsigned count=0;
 for(int d=0;d<3;d++)for(int locked=0;locked<2;locked++)
 for(int uid=0;uid<2;uid++)for(int override=0;override<4;override++)
 for(int dac=0;dac<2;dac++) {
  request.cr_uid=uid?100:0;denial=d==0?0:d==1?EPERM:EACCES;dac_error=dac?EACCES:0;
  checks=accesses=attrs=locks=unlocks=0;
  int expected=denial?denial:dac_error;
  if(!denial&&dac_error&&((!uid&&(override&NFSACCCHK_ALLOWROOT)) ||
      (override&NFSACCCHK_ALLOWOWNER)))expected=0;
  assert(nfsvno_accchk(&node,VREAD,&request,&exp,&td,override,locked,0)==expected);
  assert(checks==1 && accesses==!denial && locks==!locked && unlocks==!locked);
  if(denial)assert(attrs==0);
  count++;
 }
 assert(count==96);return 0;
}
'''
class Access(unittest.TestCase):
    def test_request_credential_and_nonoverridable_denial(self):
        s=(ROOT/'sys/fs/nfsserver/nfs_nfsdport.c').read_text()
        start=s.index('int\nnfsvno_accchk(');end=s.index('\n}\n',start)+3;body=s[start:end]
        with tempfile.TemporaryDirectory(prefix='nfs-access-') as directory:
            p=Path(directory)
            for mutation in (False,True):
                candidate=body
                if mutation:candidate=body.replace('error = mac_vnode_check_access(cred, vp, accmode);','error = mac_vnode_check_access(cred, vp, accmode) * 0;')
                (p/'test.c').write_text(PRE+candidate+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
                result=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=10,
                    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutation:
                    self.assertNotEqual(result.returncode,0);self.assertIn('nfsvno_accchk',result.stderr)
                else:self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
