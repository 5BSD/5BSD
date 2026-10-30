# SPDX-License-Identifier: BSD-2-Clause
"""Actual default vnode counter code, with native atomics and injected vnode state.

Includes actual vnode-pager write-count transitions with injected VM objects.
This does not exercise live mappings, mount lifetime or raw storage.
"""
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PRE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#define MPASS(x) assert(x)
#define VNASSERT(x,v,m) assert(x)
#define __diagused __attribute__((unused))
#define VIRF_TEXT_REF 1
struct mount { int unused; };
struct vnode { _Atomic int v_writecount; struct mount *v_mount; unsigned flags; _Atomic int refs; };
struct vop_is_text_args { struct vnode *a_vp; };
struct vop_set_text_args { struct vnode *a_vp; };
struct vop_unset_text_args { struct vnode *a_vp; };
struct vop_add_writecount_args { struct vnode *a_vp; int a_inc; };
#define atomic_load_int(p) atomic_load(p)
#define atomic_fcmpset_int(p,n,v) atomic_compare_exchange_weak(p,n,v)
static unsigned vn_irflag_read(struct vnode *v) { return v->flags; }
static void vref(struct vnode *v) { atomic_fetch_add(&v->refs,1); }
static void vunref(struct vnode *v) { assert(atomic_fetch_sub(&v->refs,1)>0); }
static void vlazy(struct vnode *v) { (void)v; }
'''
PAGER_PRE = r'''
#include <stdint.h>
typedef uint64_t vm_ooffset_t;
typedef uintptr_t vm_offset_t;
struct vm_object {
 int type;
 struct { struct { vm_ooffset_t writemappings; } vnp; } un_pager;
 struct vnode *handle;
};
typedef struct vm_object *vm_object_t;
#define OBJT_VNODE 1
static unsigned object_locks;
#define VM_OBJECT_WLOCK(o) do { (void)(o); assert(object_locks++==0); } while(0)
#define VM_OBJECT_WUNLOCK(o) do { (void)(o); assert(object_locks--==1); } while(0)
#define ASSERT_VOP_LOCKED(v,m) ((void)(v))
#define CTR3(...) ((void)0)
#define VOP_ADD_WRITECOUNT_CHECKED(v,n) do { \
 struct vop_add_writecount_args a={(v),(n)}; \
 assert(vop_stdadd_writecount_nomsync(&a)==0); \
} while(0)
'''

MAIN = r'''
static struct vnode node;
static int pin(void) { struct vop_set_text_args a={&node}; return vop_stdset_text(&a); }
static int unpin(void) { struct vop_unset_text_args a={&node}; return vop_stdunset_text(&a); }
static int writer(int n) { struct vop_add_writecount_args a={&node,n}; return vop_stdadd_writecount_nomsync(&a); }
static pthread_barrier_t start, finish;
static int results[2];
static void *race(void *arg) {
 long role=(long)arg;
 for(int i=0;i<10000;i++) {
  pthread_barrier_wait(&start);
  results[role]=role?writer(1):pin();
  pthread_barrier_wait(&finish);
  pthread_barrier_wait(&start);
  if(results[role]==0) assert((role?writer(-1):unpin())==0);
  pthread_barrier_wait(&finish);
 }
 return NULL;
}
int main(void) {
 for(unsigned flag=0;flag<=1;flag++) {
  node.flags=flag;
  assert(writer(1)==0); assert(writer(1)==0);
  assert(pin()==ETXTBSY); assert(node.v_writecount==2);
  assert(writer(-1)==0); assert(pin()==ETXTBSY);
  assert(writer(-1)==0); assert(pin()==0); assert(pin()==0);
  assert(node.v_writecount==-2); assert(node.refs==(int)flag);
  assert(writer(1)==ETXTBSY); assert(unpin()==0);
  assert(writer(1)==ETXTBSY); assert(unpin()==0);
  assert(node.v_writecount==0 && node.refs==0);
  assert(unpin()==EINVAL); assert(writer(1)==0); assert(writer(-1)==0);
 }
 /* A live shared mapping retains a writer after the open writer closes. */
 struct vm_object mapped={.type=OBJT_VNODE,.handle=&node};
 assert(writer(1)==0);
 vnode_pager_update_writecount(&mapped,0,4096);
 assert(node.v_writecount==2 && object_locks==0);
 assert(writer(-1)==0); /* Close the original writable descriptor. */
 assert(node.v_writecount==1 && pin()==ETXTBSY);
 vnode_pager_update_writecount(&mapped,0,4096);
 assert(mapped.un_pager.vnp.writemappings==8192);
 assert(node.v_writecount==1 && pin()==ETXTBSY);
 vnode_pager_update_writecount(&mapped,4096,0);
 assert(node.v_writecount==1 && pin()==ETXTBSY);
 vnode_pager_update_writecount(&mapped,4096,0);
 assert(node.v_writecount==0 && object_locks==0);
 assert(pin()==0 && unpin()==0);
 mapped.type=0;
 vnode_pager_update_writecount(&mapped,0,4096);
 assert(node.v_writecount==0 && object_locks==0);
 node.flags=VIRF_TEXT_REF;
 assert(pthread_barrier_init(&start,NULL,3)==0);
 assert(pthread_barrier_init(&finish,NULL,3)==0);
 pthread_t threads[2];
 for(long n=0;n<2;n++) assert(pthread_create(&threads[n],NULL,race,(void *)n)==0);
 for(int i=0;i<10000;i++) {
  pthread_barrier_wait(&start); pthread_barrier_wait(&finish);
  assert((results[0]==0 && results[1]==ETXTBSY) ||
         (results[1]==0 && results[0]==ETXTBSY));
  assert(node.v_writecount==(results[0]==0?-1:1));
  pthread_barrier_wait(&start); pthread_barrier_wait(&finish);
  assert(node.v_writecount==0 && node.refs==0);
 }
 for(int n=0;n<2;n++) assert(pthread_join(threads[n],NULL)==0);
 puts("text pins: writer exclusion, nested lifetime, reference balance, pager accounting, 10000 acquisition races passed");
 return 0;
}
'''

class TextPinTest(unittest.TestCase):
    def test_actual_counter_and_mutation(self):
        source = (ROOT/'sys/kern/vfs_default.c').read_text()
        begin = source.index('static int\nvop_stdis_text(')
        end = source.index('\nint\nvop_stdneed_inactive(', begin)
        body = source[begin:end]
        pager = (ROOT/'sys/vm/vnode_pager.c').read_text()
        begin = pager.index('static void\nvnode_pager_update_writecount(')
        end = pager.index('\nstatic void\nvnode_pager_release_writecount(', begin)
        pager = pager[begin:end]
        with tempfile.TemporaryDirectory(prefix='text-pin-') as tmp:
            path = Path(tmp)
            for mutated in (None, "pin", "pager"):
                candidate = body
                selected_pager = pager
                if mutated == "pin":
                    needle = 'if (__predict_false(n > 0)) {\n\t\t\treturn (ETXTBSY);'
                    self.assertEqual(candidate.count(needle), 1)
                    candidate = candidate.replace(needle, 'if (__predict_false(n > 0)) {\n\t\t\treturn (0);')
                if mutated == "pager":
                    needle = 'VOP_ADD_WRITECOUNT_CHECKED(vp, 1);'
                    self.assertEqual(pager.count(needle), 1)
                    selected_pager = pager.replace(needle, '(void)vp;')
                (path/'test.c').write_text(PRE+candidate+PAGER_PRE+selected_pager+MAIN)
                subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',
                    '-Wno-unused-function','-pthread',str(path/'test.c'),
                    '-o',str(path/'test')],check=True)
                result = subprocess.run([str(path/'test')],capture_output=True,text=True,
                    timeout=30, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
                if mutated:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('pin()==ETXTBSY' if mutated == 'pin' else
                        'node.v_writecount==2',result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    print(result.stdout,end='')

if __name__ == '__main__':
    unittest.main()
