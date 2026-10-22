#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
from pathlib import Path
import subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root / 'usr.sbin/bhyve/migration_session.c').read_text()
parts = []
for name in ('prod_local_hello', 'prod_dest_local_hello'):
    a = s.index('static int\n' + name + '(')
    b = s.index('\n}', a) + 2
    parts.append(s[a:b])
fixture = r'''
#define BHYVE_SNAPSHOT 1
#include <assert.h>
#include "migration_fresh_preflight.h"
static bool tracing, fail_sync;
static int hello_error, syncs;
int __real_fsync(int);
int __wrap_fsync(int fd) {
 syncs++;
 if (fail_sync) { errno=EIO; return -1; }
 return __real_fsync(fd);
}
struct migration_prod_source { void *ctx; int recovery_dirfd; struct migration_recovery_record recovery; };
struct migration_prod_dest { void *ctx; int recovery_dirfd; struct migration_recovery_record recovery; };
static bool hypertrace_initialized(void) { return tracing; }
int migration_prod_fill_hello(struct vmctx *ctx, struct migration_hello *hello) {
 (void)ctx;
 memset(hello, 0, sizeof(*hello)); hello->capability_flags=MIGRATION_CAP_PRECOPY;
 return hello_error;
}
'''+ '\n'.join(parts) + r'''
int main(void) {
 char directory[]="preflight.XXXXXX"; assert(mkdtemp(directory));
 int fd=open(directory,O_RDONLY|O_DIRECTORY); assert(fd>=0);
 FILE *file=tmpfile(); assert(file);
 for (int side=0; side<2; side++) for (int mode=0; mode<9; mode++) {
  struct migration_prod_source src={.recovery_dirfd=fd};
  struct migration_prod_dest dst={.recovery_dirfd=fd};
  struct migration_hello hello;
  tracing=mode!=0; fail_sync=mode==6; hello_error=mode==8?EIO:0; syncs=0;
  memset(src.recovery.source_certificate_sha256,3,32);
  memset(src.recovery.destination_certificate_sha256,4,32);
  if (mode==1) memset(src.recovery.source_certificate_sha256,0,32);
  if (mode==2) memset(src.recovery.destination_certificate_sha256,0,32);
  if (mode==3) src.recovery_dirfd=-1;
  if (mode==4) src.recovery_dirfd=fileno(file);
  assert(fchmod(fd,mode==5?0755:0700)==0);
  dst.recovery=src.recovery; dst.recovery_dirfd=src.recovery_dirfd;
  int error=side?prod_local_hello(&src,&hello):prod_dest_local_hello(&dst,&hello);
  if (mode==0 || mode==7) assert(error==0);
  else assert(error!=0);
  assert(hello.capability_flags==(MIGRATION_CAP_PRECOPY | (mode==7?MIGRATION_CAP_HYPERTRACE_FRESH:0)));
  assert(syncs==((mode==6||mode==7)?1:0));
 }
 assert(fchmod(fd,0700)==0); close(fd); fclose(file); assert(rmdir(directory)==0);
 return 0;
}
'''
(out / 'preflight.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+str(root/'sys'),'-I'+str(root/'usr.sbin/bhyve'),str(out/'preflight.c'),
 '-Wl,--wrap=fsync','-lmd','-o',str(out/'preflight')], check=True)
subprocess.run([str(out/'preflight')],cwd=out,check=True,timeout=30)
print('PASS: both production HELLO callbacks enforce certificate pins, private directory and durable sync before FRESH advertisement')
