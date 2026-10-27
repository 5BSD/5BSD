# SPDX-License-Identifier: BSD-2-Clause
"""Actual NFS read/write helpers with injected MAC, proxy and local I/O."""
from pathlib import Path
import resource,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define MAC 1
#define NFSPROC_READDS 1
#define NFSPROC_WRITEDS 2
#define NFSV4OP_READ 0
#define NFSV4OP_WRITE 1
#define NFSWRITE_FILESYNC 2
#define NFSWRITE_UNSTABLE 0
#define NFSM_RNDUP(n) (((n)+3)&~3)
#define IO_NODELOCKED 1
#define IO_SYNC 2
#define IO_SEQSHIFT 8
#define UIO_READ 1
#define UIO_WRITE 2
#define UIO_SYSSPACE 1
#define M_TEMP 0
#define NFSEXITCODE(e) ((void)(e))
#define VNET(v) (v)
struct vnode {int unused;};struct ucred {int uid;};struct thread {int unused;};
struct mbuf {int unused;};struct iovec {int unused;};
struct uio {struct iovec *uio_iov;int uio_iovcnt,uio_resid,uio_rw,uio_segflg;off_t uio_offset;struct thread *uio_td;};
struct nfsheur {int nh_seqcount;off_t nh_nextoff;};
static struct {int srvbytes[2];} stats,*nfsstatsv1_p=&stats;
static struct vnode node;static struct ucred request;static struct thread td;
static struct mbuf buffer;static struct iovec vector;static struct nfsheur heur;
static int denial,proxy_result,local_error,checks,proxies,reads,writes,allocations,releases,freed;
#define NFSUIOPROC(u,p) ((u)->uio_td=(p))
static int check(struct ucred *a,struct ucred *f,struct vnode *v) {
 assert(a==&request&&f==&request&&v==&node);assert(!proxies&&!allocations);checks++;return denial;
}
#define mac_vnode_check_read check
#define mac_vnode_check_write check
static int nfsrv_proxyds(struct vnode *v,off_t off,int count,struct ucred *c,struct thread *p,int op,...) {
 assert(v==&node&&off==0&&count==8&&c==&request&&p==&td);
 assert(op==NFSPROC_READDS||op==NFSPROC_WRITEDS);assert(checks==1&&!denial);proxies++;return proxy_result;
}
static int nfsrv_createiovec(int n,struct mbuf **a,struct mbuf **b,struct iovec **iv) {
 assert(n==8);allocations++;*a=*b=&buffer;*iv=&vector;return 1;
}
static int nfsrv_createiovec_extpgs(int n,int size,struct mbuf **a,struct mbuf **b,struct iovec **iv) {
 assert(size==4096);return nfsrv_createiovec(n,a,b,iv);
}
static int nfsrv_createiovecw(int n,struct mbuf *m,char *c,struct iovec **iv,int *cnt) {
 (void)c;assert(n==8&&m==&buffer);allocations++;*iv=&vector;*cnt=1;return 0;
}
static struct nfsheur *nfsrv_sequential_heuristic(struct uio *u,struct vnode *v) {(void)u;assert(v==&node);return &heur;}
static int io(struct vnode *v,struct uio *u,int flags,struct ucred *c) {
 assert(v==&node&&c==&request&&(flags&IO_NODELOCKED)&&checks==1&&!denial);
 u->uio_resid=0;u->uio_offset=8;return local_error;
}
static int VOP_READ(struct vnode *v,struct uio *u,int f,struct ucred *c) {reads++;return io(v,u,f,c);}
static int VOP_WRITE(struct vnode *v,struct uio *u,int f,struct ucred *c) {writes++;return io(v,u,f,c);}
static void release(struct iovec *iv,int kind) {assert(iv==&vector&&kind==M_TEMP);releases++;}
#define free release
static void m_freem(struct mbuf *m) {assert(m==&buffer);freed++;}
static struct mbuf *nfsrv_adj(struct mbuf *m,int a,int b) {(void)a;(void)b;return m;}
'''
MAIN=r'''
int main(void) {
 for(int op=0;op<2;op++)for(int d=0;d<3;d++)for(int proxy=0;proxy<3;proxy++)
 for(int local=0;local<2;local++)for(int ext=0;ext<2;ext++) {
  denial=d==0?0:d==1?EPERM:EACCES;
  proxy_result=proxy==0?0:proxy==1?ENOENT:EIO;local_error=local?EIO:0;
  checks=proxies=reads=writes=allocations=releases=freed=0;
  struct mbuf *head=&buffer,*tail=&buffer;int stable=ext?NFSWRITE_FILESYNC:NFSWRITE_UNSTABLE;
  int original=stable;
  int expected=denial?denial:proxy_result==ENOENT?local_error:proxy_result;
  int result=op?nfsvno_write(&node,0,8,&stable,&buffer,NULL,&request,&td):
   nfsvno_read(&node,0,8,&request,ext?4096:0,&td,&head,&tail);
  assert(result==expected && checks==1);
  assert(proxies==!denial);
  int local_io=!denial&&proxy_result==ENOENT;
  assert(reads==(!op&&local_io)&&writes==(op&&local_io));
  assert(allocations==local_io&&releases==local_io);
  if(denial) {assert(!freed);if(op)assert(stable==original);else assert(head==NULL&&tail==NULL);}
 }
 return 0;
}
'''
class IO(unittest.TestCase):
    def test_denial_precedes_both_io_paths(self):
        s=(ROOT/'sys/fs/nfsserver/nfs_nfsdport.c').read_text();body=''
        for name in ('nfsvno_read','nfsvno_write'):
            begin=s.index('int\n'+name+'(');body+=s[begin:s.index('\n}\n',begin)+3]
        with tempfile.TemporaryDirectory(prefix='nfs-io-') as directory:
            p=Path(directory)
            for mutation in (False,True):
                candidate=body.replace('error = mac_vnode_check_write(cred, cred, vp);','error = mac_vnode_check_write(cred, cred, vp) * 0;') if mutation else body
                (p/'test.c').write_text(PRE+candidate+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
                result=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=10,
                    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutation:
                    self.assertNotEqual(result.returncode,0);self.assertIn('!denial',result.stderr)
                else:self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
