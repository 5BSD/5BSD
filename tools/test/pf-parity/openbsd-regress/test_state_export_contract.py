#!/usr/bin/env python3
"""Check the actual raw-state snapshot guard without changing display queries."""
from pathlib import Path
import os,shlex,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[4]
STUBS=r'''
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#define PFTM_UNLINKED 99
#define RW_READ 1
#define RW_INTR 2
struct item { SLIST_ENTRY(item) entry; };
SLIST_HEAD(items,item);
struct pf_state {
 TAILQ_ENTRY(pf_state) entry_list;
 int timeout;
 unsigned delay,tag,qid,pqid,statelim,sourcelim;
 struct items match_rules,src_nodes,linkage;
};
TAILQ_HEAD(pf_state_queue,pf_state);
struct pfsync_state { unsigned id; };
struct pfioc_states { size_t ps_len; struct pfsync_state *ps_states; };
static struct { unsigned states; } pf_status;
static struct { int pfs_rwl,pfs_mtx; struct pf_state_queue pfs_list; } pf_state_list;
static int locks,exports;
static struct pf_state *append_during_copy;
static int rw_enter(int *l,int flags){(void)l;(void)flags;assert(!locks);locks++;return 0;}
static void rw_exit(int *l){(void)l;assert(locks==1);locks--;}
static void mtx_enter(int *l){(void)l;assert(locks==1);}
static void mtx_leave(int *l){(void)l;}
static void pf_state_export(struct pfsync_state *p,struct pf_state *s){(void)s;assert(locks==1);exports++;p->id=42;}
static int copyout(const void *src,void *dst,size_t len){
 memcpy(dst,src,len);
 if(append_during_copy){TAILQ_INSERT_TAIL(&pf_state_list.pfs_list,append_during_copy,entry_list);pf_status.states++;append_during_copy=NULL;}
 return 0;
}
'''
MAIN=r'''
int main(void) {
 struct pf_state a={0},b={0},c={.delay=99};struct item item={0};
 struct pfsync_state records[3];struct pfioc_states query={0};
 unsigned *fields[]={&a.delay,&a.tag,&a.qid,&a.pqid,&a.statelim,&a.sourcelim};
 struct items *lists[]={&a.match_rules,&a.src_nodes,&a.linkage};
 TAILQ_INIT(&pf_state_list.pfs_list);TAILQ_INSERT_TAIL(&pf_state_list.pfs_list,&a,entry_list);pf_status.states=1;
 assert(pf_states_get(&query,1)==0 && query.ps_len==sizeof(records[0]) && !locks);
 query.ps_states=records;query.ps_len=sizeof(records);
 assert(pf_states_get(&query,1)==0 && exports==1 && query.ps_len==sizeof(records[0]) && !locks);
 for(unsigned i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
  *fields[i]=1;query.ps_len=sizeof(records);exports=0;
  assert(pf_states_get(&query,1)==EOPNOTSUPP && !exports && !locks);
  query.ps_len=sizeof(records);assert(pf_states_get(&query,0)==0 && exports==1 && !locks);
  *fields[i]=0;
 }
 for(unsigned i=0;i<sizeof(lists)/sizeof(lists[0]);i++) {
  SLIST_INSERT_HEAD(lists[i],&item,entry);query.ps_len=sizeof(records);exports=0;
  assert(pf_states_get(&query,1)==EOPNOTSUPP && !exports && !locks);
  query.ps_len=sizeof(records);assert(pf_states_get(&query,0)==0 && exports==1 && !locks);
  SLIST_REMOVE_HEAD(lists[i],entry);
 }
 TAILQ_INSERT_TAIL(&pf_state_list.pfs_list,&b,entry_list);pf_status.states=2;b.delay=50;
 query.ps_len=sizeof(records[0]);exports=0;
 assert(pf_states_get(&query,1)==0 && exports==1 && query.ps_len==sizeof(records[0]) && !locks);
 query.ps_len=sizeof(records);exports=0;
 assert(pf_states_get(&query,1)==EOPNOTSUPP && exports==1 && !locks);
 b.timeout=PFTM_UNLINKED;query.ps_len=sizeof(records);exports=0;
 assert(pf_states_get(&query,1)==0 && exports==1 && !locks);
 /* A concurrent insertion after the captured tail is excluded, then
  * validated on the next snapshot.  No emitted record escapes the guard. */
 b.timeout=0;b.delay=0;append_during_copy=&c;query.ps_len=sizeof(records);exports=0;
 assert(pf_states_get(&query,1)==0 && exports==2 && query.ps_len==2*sizeof(records[0]) && !locks);
 query.ps_len=sizeof(records);exports=0;
 assert(pf_states_get(&query,1)==EOPNOTSUPP && exports==2 && !locks);
 query.ps_len=sizeof(records);exports=0;
 assert(pf_states_get(&query,0)==0 && exports==3 && !locks);
 return 0;
}
'''
class ExportContract(unittest.TestCase):
 def test_checked_snapshot_and_legacy_display(self):
  source=(ROOT/'contrib/openbsd-pf/sys/net/pf_ioctl.c').read_text()
  body=source[source.index('int\npf_states_get('):source.index('\nint\npfioctl(')]
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);(p/'test.c').write_text(STUBS+body+MAIN)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':unittest.main()
