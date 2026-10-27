# SPDX-License-Identifier: BSD-2-Clause
"""Actual isolation filehandle hook with injected claim lookup and enforcement."""
from pathlib import Path
import resource,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
PRE=r'''
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>
struct ucred {int owner;};struct vnode {int claimed;};struct label {int unused;};
struct fi_claim {uint64_t fi_nonce;};
static struct fi_claim claim={.fi_nonce=42};
static unsigned fi_claim_count;static int fi_lock,locked,lookups,denials,probes,audit;
static unsigned atomic_load_acq_int(unsigned *v) {return *v;}
static void rw_rlock(int *p) {assert(p==&fi_lock && !locked);locked=1;}
static void rw_runlock(int *p) {assert(p==&fi_lock && locked);locked=0;}
static struct fi_claim *fi_claim_lookup(struct vnode *v) {assert(locked);lookups++;return v->claimed?&claim:NULL;}
static int fi_deny(int error) {assert(!locked && error==EACCES);denials++;return audit?0:error;}
#define SDT_PROBE3(provider,module,function,name,kind,owner,actor) do { \
 assert(!locked && (owner)==42 && (actor)==0);probes++; \
} while(0)
'''
MAIN=r'''
int main(void) {
 for(audit=0;audit<2;audit++)
 for(unsigned count=0;count<2;count++)
 for(int claimed=0;claimed<2;claimed++)
 for(int owner=0;owner<2;owner++) {
  struct vnode v={claimed};struct ucred c={owner};
  fi_claim_count=count;lookups=denials=probes=0;
  int expected=count&&claimed&&!audit?EACCES:0;
  assert(fi_check_fh(&c,&v,NULL)==expected);
  assert(!locked && lookups==(int)count);
  assert(denials==(int)(count&&claimed) && probes==denials);
 }
 return 0;
}
'''
class Handles(unittest.TestCase):
    def test_claimed_handles_and_empty_fast_path(self):
        s=(ROOT/'sys/dev/mac_capability/mac_capability_isolation.c').read_text()
        begin=s.index('static int\nfi_check_fh(');end=s.index('\n}\n',begin)+3
        body=s[begin:end]
        self.assertIn('.mpo_vnode_check_fh\t\t= fi_check_fh,',s)
        with tempfile.TemporaryDirectory(prefix='isolation-fh-') as directory:
            p=Path(directory)
            for mutation in (False,True):
                selected=body.replace('return (fi_deny(EACCES));','return (fi_deny(EACCES) * 0);') if mutation else body
                (p/'test.c').write_text(PRE+selected+MAIN)
                subprocess.run(['cc','-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
                result=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=10,
                    preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutation:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('fi_check_fh',result.stderr)
                else:self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
