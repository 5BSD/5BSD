#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual ACPI callback retirement with an in-flight callback; no VM."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/amd64/pm.c').read_text()
parts=[]
for sig in ('void\nsci_retire(', 'static void\npower_button_handler('):
 a=s.index(sig); parts.append(s[a:s.index('\n}',a)+2])
fixture=r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
struct vmctx { int live; };
enum ev_type { EVF_SIGNAL };
static pthread_mutex_t pm_lock=PTHREAD_MUTEX_INITIALIZER;
static bool sci_retiring;
static uint16_t pm1_status;
#define PM1_PWRBTN_STS 0x100
static atomic_bool entered, release_callback, retire_started, retired;
static int calls;
static void sci_update(struct vmctx *ctx) {
 assert(ctx && ctx->live); calls++; atomic_store(&entered,true);
 while (!atomic_load(&release_callback)) usleep(100);
 assert(ctx->live);
}
'''+'\n'.join(parts)+r'''
static void *callback(void *ctx) { power_button_handler(0,EVF_SIGNAL,ctx); return NULL; }
static void *retire(void *unused) {
 (void)unused; atomic_store(&retire_started,true); sci_retire();
 atomic_store(&retired,true); return NULL;
}
int main(void) {
 struct vmctx ctx={.live=1}; pthread_t cb, retire_thread;
 assert(pthread_create(&cb,NULL,callback,&ctx)==0);
 while (!atomic_load(&entered)) usleep(100);
 assert(pthread_create(&retire_thread,NULL,retire,NULL)==0);
 while (!atomic_load(&retire_started)) usleep(100);
 usleep(10000); assert(!atomic_load(&retired));
 atomic_store(&release_callback,true);
 assert(pthread_join(cb,NULL)==0 && pthread_join(retire_thread,NULL)==0);
 assert(atomic_load(&retired) && calls==1);
 ctx.live=0; pm1_status=0;
 power_button_handler(0,EVF_SIGNAL,NULL);
 assert(calls==1 && pm1_status==0);
 sci_retire(); power_button_handler(0,EVF_SIGNAL,NULL); assert(calls==1);
 return 0;
}
'''
(out/'acpi.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined',str(out/'acpi.c'),'-o',str(out/'acpi')],check=True)
subprocess.run([str(out/'acpi')],check=True,timeout=30)
print('PASS: retirement drains an in-flight ACPI callback and fences later signal callbacks')
