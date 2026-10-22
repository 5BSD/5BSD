#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
a = s.index('static dtrace_state_t *dtrace_handle_states;')
b = s.index('#endif', a)
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define ASSERT assert
#define MUTEX_HELD(x) 1
typedef struct state { struct state *dts_handle_next; uint64_t dts_handle_serial; } dtrace_state_t;
typedef struct { uint64_t generation[2], serial; uint32_t retired, reserved; } dtrace_handle_lifetime_t;
'''
fixture += s[a:b]
ioctl = (root / 'sys/cddl/dev/dtrace/dtrace_ioctl.c').read_text()
ia = ioctl.index('\tcase DTRACEIOC_HANDLE_ID:')
ib = ioctl.index('\tcase DTRACEIOC_DRAINABLE:', ia)
fixture += r'''
#define DTRACEIOC_HANDLE_ID 23
#define DTRACEIOC_HANDLE_QUERY 24
static int dtrace_lock, held;
static void mutex_enter(int *lock) { assert(lock == &dtrace_lock && !held); held=1; }
static void mutex_exit(int *lock) { assert(lock == &dtrace_lock && held); held=0; }
static int dispatch(dtrace_state_t *state, int cmd, void *addr) {
 int error=0;
 switch(cmd) {
''' + ioctl[ia:ib] + 'default: return ENOTTY; } }\n'
fixture += r''' 
static dtrace_handle_lifetime_t identity(dtrace_state_t *s) {
 dtrace_handle_lifetime_t q = { .serial=s->dts_handle_serial };
 memcpy(q.generation,dtrace_handle_generation,sizeof(q.generation)); return q;
}
int main(void) {
 dtrace_state_t a={0},b={0},c={0};
 dtrace_handle_register(&a); dtrace_handle_lifetime_t qa=identity(&a);
 dtrace_handle_register(&b); dtrace_handle_lifetime_t qb=identity(&b);
 dtrace_handle_register(&c); dtrace_handle_lifetime_t qc=identity(&c);
 assert(qa.serial != qb.serial && qb.serial != qc.serial);
 dtrace_handle_lifetime_t via_ioctl; memset(&via_ioctl,0xff,sizeof(via_ioctl));
 assert(dispatch(&a,DTRACEIOC_HANDLE_ID,&via_ioctl)==0 && !held);
 assert(memcmp(&qa,&via_ioctl,sizeof(qa))==0);
 assert(dispatch(&c,DTRACEIOC_HANDLE_QUERY,&via_ioctl)==0 && !via_ioctl.retired && !held);
 assert(dtrace_handle_query(&qa)==0 && qa.retired==0);
 /* No retirement is visible until the state destructor unlinks it. */
 assert(dtrace_handle_query(&qa)==0 && qa.retired==0);
 dtrace_handle_unregister(&b); assert(dtrace_handle_query(&qb)==0 && qb.retired==1);
 assert(dtrace_handle_query(&qa)==0 && qa.retired==0);
 dtrace_handle_unregister(&c); assert(dtrace_handle_query(&qc)==0 && qc.retired==1);
 dtrace_handle_unregister(&a); assert(dtrace_handle_query(&qa)==0 && qa.retired==1);
 assert(dispatch(&c,DTRACEIOC_HANDLE_QUERY,&via_ioctl)==0 && via_ioctl.retired && !held);
 /* Reusing an allocation address cannot resurrect an old state identity. */
 dtrace_handle_register(&a); dtrace_handle_lifetime_t newer=identity(&a);
 assert(newer.serial!=qa.serial); qa.retired=0;
 assert(dtrace_handle_query(&qa)==0 && qa.retired==1);
 for (unsigned i=0;i<5;i++) {
  dtrace_handle_lifetime_t bad=newer;
  if(i==0)bad.serial=0;
  if(i==1)bad.serial=UINT64_MAX;
  if(i==2)bad.generation[0]^=1;
  if(i==3)bad.reserved=1;
  if(i==4)bad.retired=1;
  dtrace_handle_lifetime_t before=bad;
  assert(dtrace_handle_query(&bad)==(i==1||i==2?ESTALE:EINVAL));
  assert(memcmp(&bad,&before,sizeof(bad))==0);
 }
 dtrace_handle_unregister(&a);
 /* A new module lifetime cannot attest retirement of an old identity. */
 dtrace_handle_serial=0; memset(dtrace_handle_generation,0,sizeof(dtrace_handle_generation));
 dtrace_handle_register(&a); newer.retired=0;
 assert(dtrace_handle_query(&newer)==ESTALE);
 dtrace_handle_unregister(&a); assert(dtrace_handle_states==NULL);
 return 0;
}
'''
(out / 'lifetime.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
    str(out/'lifetime.c'),'-o',str(out/'lifetime')],check=True)
subprocess.run([str(out/'lifetime')],cwd=out,check=True,timeout=30)
print('PASS: state lifetime registration, destruction, address reuse and stale-generation refusal')
