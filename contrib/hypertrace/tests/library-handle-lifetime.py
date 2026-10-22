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
s = (root/'cddl/contrib/opensolaris/lib/libdtrace/common/dt_work.c').read_text()
a = s.index('int\ndtrace_handle_identity(')
b = s.index('#endif', a)
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
typedef struct { int error; } dtrace_hdl_t;
typedef struct { uint64_t generation[2], serial; uint32_t retired, reserved; } dtrace_handle_lifetime_t;
#define DTRACEIOC_HANDLE_ID 23
#define DTRACEIOC_HANDLE_QUERY 24
static int mode, calls;
static int dt_set_errno(dtrace_hdl_t *dtp, int error) { dtp->error=error; return -1; }
static int dt_ioctl(dtrace_hdl_t *dtp, int command, void *data) {
 (void)dtp; calls++; dtrace_handle_lifetime_t *q=data;
 if (mode==1 || mode==2) { memset(q,0xff,sizeof(*q)); errno=mode==1?ENOTTY:EIO; return -1; }
 if (command==DTRACEIOC_HANDLE_ID) *q=(dtrace_handle_lifetime_t){.generation={1,2},.serial=3};
 else assert(command==DTRACEIOC_HANDLE_QUERY && q->serial==3 && q->generation[0]==1 && q->generation[1]==2);
 if(mode==3)q->serial=0;
 if(mode==4)q->generation[0]=q->generation[1]=0;
 if(mode==5)q->reserved=1;
 if(mode==6)q->retired=2;
 if(mode==7)q->retired=1;
 return 0;
}
'''
fixture += s[a:b]
fixture += r'''
int main(void) {
 dtrace_hdl_t dtp={0};
 const dtrace_handle_lifetime_t expected={.generation={1,2},.serial=3};
 for(mode=0;mode<8;mode++) {
  dtrace_handle_lifetime_t out, sentinel; memset(&out,0xa5,sizeof(out));sentinel=out;
  int status=dtrace_handle_identity(&dtp,&out);
  assert(status==(mode==0?0:-1));
  if(status==0)assert(memcmp(&out,&expected,sizeof(out))==0);
  else { assert(memcmp(&out,&sentinel,sizeof(out))==0); assert(dtp.error==(mode==1?ENOTTY:mode==2?EIO:EPROTO)); }
  int retired=42;
  status=dtrace_handle_retired(&dtp,&expected,&retired);
  assert(status==((mode==0||mode==7)?0:-1));
  if(status==0)assert(retired==(mode==7));
  else { assert(retired==42);assert(dtp.error==(mode==1?ENOTTY:mode==2?EIO:EPROTO)); }
 }
 calls=0; int retired=42;dtrace_handle_lifetime_t out;
 assert(dtrace_handle_identity(NULL,&out)==-1 && errno==EINVAL);
 assert(dtrace_handle_identity(&dtp,NULL)==-1 && dtp.error==EINVAL);
 assert(dtrace_handle_retired(NULL,&expected,&retired)==-1 && errno==EINVAL);
 assert(dtrace_handle_retired(&dtp,NULL,&retired)==-1 && dtp.error==EINVAL);
 assert(dtrace_handle_retired(&dtp,&expected,NULL)==-1 && dtp.error==EINVAL);
 for(unsigned i=0;i<4;i++) {
  out=expected;
  if(i==0)out.serial=0;
  if(i==1)out.generation[0]=out.generation[1]=0;
  if(i==2)out.retired=1;
  if(i==3)out.reserved=1;
  assert(dtrace_handle_retired(&dtp,&out,&retired)==-1 && dtp.error==EINVAL);
 }
 assert(calls==0 && retired==42);return 0;
}
'''
(out/'library.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
    str(out/'library.c'),'-o',str(out/'library')],check=True)
subprocess.run([str(out/'library')],cwd=out,check=True,timeout=30)
print('PASS: libdtrace handle identity/query validation, unsupported ioctl and unchanged failure outputs')
