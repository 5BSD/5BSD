# SPDX-License-Identifier: BSD-2-Clause
"""Actual NFS setattr helper with injected policy and metadata backends."""
from pathlib import Path
import resource,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#define MAC 1
#define VNOVAL (-1)
#define VREG 1
#define MNT_EXPORTED 1
#define NFSPROC_SETATTR 1
#define NFSEXITCODE(e) ((void)(e))
struct vattr {u_quad_t va_size;uid_t va_uid;gid_t va_gid;mode_t va_mode;u_long va_flags;struct timespec va_atime,va_mtime,va_birthtime;};
struct nfsvattr {struct vattr na_vattr;};struct nfsexstuff {int unused;};
struct mount {int mnt_flag;};struct vnode {int v_type;struct mount *v_mount;};
struct ucred {int unused;};struct thread {int unused;};
static struct mount mp={MNT_EXPORTED};static struct vnode node={VREG,&mp};
static struct ucred request;static struct thread td;static struct nfsvattr original;
static int nfsrv_devidcnt,deny,seen,local,proxy,last;
static struct vattr local_attrs;
static int check(int bit,struct ucred *c,struct vnode *v) {
 assert(c==&request&&v==&node&&!local&&!proxy&&bit>last);last=bit;seen|=1<<bit;
 return deny==bit?EACCES:0;
}
static int mac_vnode_check_write(struct ucred *c,struct ucred *f,struct vnode *v) {assert(f==c);return check(1,c,v);}
static int mac_vnode_check_truncate(struct ucred *c,struct vnode *v) {return check(2,c,v);}
static int mac_vnode_check_setowner(struct ucred *c,struct vnode *v,uid_t u,gid_t g) {assert(u==original.na_vattr.va_uid&&g==original.na_vattr.va_gid);return check(3,c,v);}
static int mac_vnode_check_setmode(struct ucred *c,struct vnode *v,mode_t m) {assert(m==original.na_vattr.va_mode);return check(4,c,v);}
static int mac_vnode_check_setflags(struct ucred *c,struct vnode *v,u_long f) {assert(f==original.na_vattr.va_flags);return check(5,c,v);}
static int mac_vnode_check_setutimes(struct ucred *c,struct vnode *v,struct timespec a,struct timespec m) {assert(a.tv_sec==original.na_vattr.va_atime.tv_sec&&m.tv_sec==original.na_vattr.va_mtime.tv_sec);return check(6,c,v);}
static int VOP_SETATTR(struct vnode *v,struct vattr *a,struct ucred *c) {assert(v==&node&&c==&request);local_attrs=*a;local++;return 0;}
static int nfsrv_proxyds(struct vnode *v,int off,int count,struct ucred *c,struct thread *t,int op,...) {assert(v==&node&&off==0&&count==0&&c==&request&&t==&td&&op==NFSPROC_SETATTR);proxy++;return ENOENT;}
'''
MAIN=r'''
int main(void) {
 for(int mask=0;mask<128;mask++)for(deny=0;deny<=6;deny++)for(nfsrv_devidcnt=0;nfsrv_devidcnt<2;nfsrv_devidcnt++) {
  struct nfsvattr attrs;memset(&attrs,0xff,sizeof(attrs));
  if(mask&1)attrs.na_vattr.va_size=8192;
  if(mask&2)attrs.na_vattr.va_uid=100;
  if(mask&4)attrs.na_vattr.va_gid=200;
  if(mask&8)attrs.na_vattr.va_mode=0640;
  if(mask&16)attrs.na_vattr.va_flags=1;
  if(mask&32)attrs.na_vattr.va_mtime=(struct timespec){123,0};
  if(mask&64)attrs.na_vattr.va_birthtime=(struct timespec){456,0};
  original=attrs;seen=local=proxy=last=0;
  int wanted=(mask&1?6:0)|((mask&6)?8:0)|(mask&8?16:0)|(mask&16?32:0)|(mask&32?64:0);
  int denied=deny&&(wanted&(1<<deny));
  assert(nfsvno_setattr(&node,&attrs,&request,&td,NULL)==(denied?EACCES:0));
  assert(!memcmp(&attrs,&original,sizeof(attrs)));
  if(denied) {assert(!local&&!proxy);assert((seen&(1<<deny))!=0);assert((seen>>deny)==1);}
  else {
   assert(seen==wanted);
   int suppress_size=nfsrv_devidcnt&&(mask&1);
   int needs_local=!suppress_size || (mask&~1);
   assert(local==!!needs_local);
   if(local) {
    struct vattr expected=original.na_vattr;
    if(suppress_size)expected.va_size=VNOVAL;
    assert(!memcmp(&local_attrs,&expected,sizeof(expected)));
   }
  }
 }
 return 0;
}
'''
class Setattr(unittest.TestCase):
    def test_complete_preflight_before_mutation(self):
        s=(ROOT/'sys/fs/nfsserver/nfs_nfsdport.c').read_text();start=s.index('int\nnfsvno_setattr(');body=s[start:s.index('\n}\n',start)+3]
        with tempfile.TemporaryDirectory(prefix='nfs-setattr-') as directory:
            p=Path(directory)
            for mutation in (None,"denial","selection"):
                selected=body
                if mutation == "denial":
                    selected=body.replace('error = mac_vnode_check_truncate(cred, vp);','error = mac_vnode_check_truncate(cred, vp) * 0;')
                if mutation == "selection":
                    needle='\t\t    nvap->na_vattr.va_flags != VNOVAL ||\n\t\t    nvap->na_vattr.va_birthtime.tv_sec != VNOVAL ||\n'
                    self.assertEqual(body.count(needle),1)
                    selected=body.replace(needle,'')
                (p/'test.c').write_text(PRE+selected+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare',str(p/'test.c'),'-o',str(p/'test')],check=True)
                result=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=10,
                    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutation:
                    self.assertNotEqual(result.returncode,0);self.assertIn('nfsvno_setattr' if mutation=='denial' else 'local==',result.stderr)
                else:self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
