# SPDX-License-Identifier: BSD-2-Clause
"""Actual vnode-check control flow with injected claims/locks, not kernel races."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <sys/types.h>
#include <sys/resource.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
struct ucred { uint64_t nonce; };
struct vnode { int unused; };
struct mac_capability_authorization { int captured; };
struct fi_claim { uint64_t fi_nonce, fi_id; };
static struct fi_claim claim;
static struct fi_claim *current;
static int fi_lock, fi_auth_lock, snapshots, authorizations, nonce_reads, mutation;
static void *curthread;
static unsigned atomic_load_acq_int(volatile unsigned *count) { return *count; }
static uint64_t mac_capability_proc_nonce(struct ucred *cred) {
 nonce_reads++;return cred->nonce;
}
static void rw_rlock(int *lock) { assert(*lock==0);*lock=1; }
static void rw_runlock(int *lock) { assert(*lock==1);*lock=0; }
static struct fi_claim *fi_claim_lookup(struct vnode *vp) {
 (void)vp;assert(fi_lock==1);return current;
}
static void mac_capability_authorization_snapshot(void *td,
 struct mac_capability_authorization *context) {
 (void)td;assert(fi_lock==0 && fi_auth_lock==0);snapshots++;context->captured=1;
 if(mutation==1) current=NULL;
 if(mutation==2) claim.fi_id=20;
 if(mutation==3) { claim.fi_id=20;claim.fi_nonce=2; }
}
static bool fi_is_authorized(struct mac_capability_authorization *context,
 uint64_t caller,uint64_t owner,uint64_t id,uint64_t actions) {
 assert(fi_lock==1 && fi_auth_lock==1 && context->captured==1);
 authorizations++;
 return caller==2 && owner==1 && id==10 && actions==1;
}
static int fi_deny(int error) { return error; }
#define SDT_PROBE3(p,m,f,n,a,b,c) do { (void)(a);(void)(b);(void)(c); } while(0)
#define SDT_PROBE5(p,m,f,n,a,b,c,d,e) do { (void)(a);(void)(b);(void)(c);(void)(d);(void)(e); } while(0)
'''
MAIN = r'''
static void run(unsigned count, bool exists, uint64_t caller, int change,
 int expected, int expected_snapshots, int expected_authorizations) {
 struct ucred cred={.nonce=caller};struct vnode vnode={0};
 volatile unsigned claims=count;
 claim=(struct fi_claim){.fi_nonce=1,.fi_id=10};current=exists?&claim:NULL;
 fi_lock=fi_auth_lock=snapshots=authorizations=nonce_reads=0;mutation=change;
 assert(fi_check_vp_common(&cred,&vnode,&claims,"test",1)==expected);
 assert(snapshots==expected_snapshots && authorizations==expected_authorizations);
 assert(fi_lock==0 && fi_auth_lock==0);
 assert(nonce_reads==(count?1:0));
}
int main(void) {
 struct rlimit core={0,0};assert(setrlimit(RLIMIT_CORE,&core)==0);
 run(0,false,2,0,0,0,0);       /* no claims: atomic fast path */
 run(1,false,2,0,0,0,0);       /* unrelated claim: no process snapshot */
 run(1,true,1,0,0,0,0);        /* owner: no process snapshot */
 run(1,true,0,0,EACCES,0,0);   /* nonce zero: no grant lookup */
 run(1,true,2,0,0,1,1);        /* current grant permits access */
 run(1,true,3,0,EACCES,1,1);   /* foreign nonce denied */
 run(1,true,2,2,EACCES,1,1);   /* same owner, new claim ID: old grant denied */
 run(1,true,2,1,0,1,0);        /* claim removed while snapshotting */
 run(1,true,2,3,0,1,0);        /* caller became owner of replacement */
 return 0;
}
'''


class Snapshot(unittest.TestCase):
    def test_actual_vnode_check_reclassifies_after_snapshot(self):
        source = (ROOT / 'sys/dev/mac_capability/mac_capability_isolation.c').read_text()
        start = source.index('static int\nfi_check_vp_common(')
        function = source[start:source.index('\n}\n', start) + 3]
        # Demonstrate that the test catches retaining the pre-snapshot claim
        # identity after reacquiring the lock. The production file is untouched.
        self.assertEqual(function.count('goto retry;'), 1)
        stale = function.replace('retry:\n', '').replace(
            'goto retry;', 'rw_rlock(&fi_lock);')
        with tempfile.TemporaryDirectory(prefix='isolation-snapshot-') as directory:
            cfile, binary = Path(directory) / 'test.c', Path(directory) / 'test'
            for name, body, succeeds in [('actual', function, True),
                                         ('stale-claim-mutant', stale, False)]:
                with self.subTest(name=name):
                    cfile.write_text(PRE + body + MAIN)
                    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(cfile),
                                    '-o', str(binary)], check=True)
                    result = subprocess.run([str(binary)], capture_output=True,
                                            timeout=10)
                    self.assertEqual(result.returncode == 0, succeeds,
                                     result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
