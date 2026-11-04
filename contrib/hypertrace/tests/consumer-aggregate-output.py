#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual consumer worker and its host startup argument, rootless."""
from pathlib import Path
import re, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
s = (root/'cddl/contrib/opensolaris/cmd/dtrace/dtrace.c').read_text()
a = s.index('typedef struct dtrace_workarg {')
b = s.index('/* Called with the handle lock held', a)
worker = s[a:b]
startup = s[s.index('process_new_pgp('):s.index('execute_new_pgp(dtrace_prog_t')]
arg = re.search(r'pthread_create\(&worktd, NULL, dtc_work, ([^)]+)\)', startup).group(1)
local = s[s.index('process_elf(dtrace_cmd_t'):s.index('process_elf_hypertrace(dtrace_cmd_t')]
local_arg = re.search(r'pthread_create\(&g_worktd, NULL, dtc_work, ([^)]+)\)', local).group(1)
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct { void *dc_consume_probe, *dc_consume_rec, *dc_get_buf, *dc_put_buf; } dtrace_consumer_t;
static void *chew, *chewrec, *g_otel;
static FILE *g_ofp;
static int g_psc, g_pslive, g_status;
static atomic_int g_session_stop, g_intr, g_stop, g_proc_wake, g_siginfo;
static atomic_int g_newline, g_impatient, g_output_worker_done;
static pthread_mutex_t g_pgplistmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_pgpcond = PTHREAD_COND_INITIALIZER;
static int formatted, prints, ticks, finishes, discarded;
#define DTRACE_STATUS_STOPPED 1
#define DTRACE_STATUS_EXITED 2
#define DTRACE_WORKSTATUS_DONE 0
#define DTRACE_WORKSTATUS_OKAY 1
#define E_ERROR 1
#define dtp_lock() ((void)0)
#define dtp_unlock() ((void)0)
#define dtrace_oformat_setup(x) ((void)0)
#define dtrace_sleep(x) ((void)0)
#define dtrace_status(x) 0
#define dtotel_session_bridge(x) (x)
#define dtotel_aggregate(x) 0
#define dtrace_oformat(x) formatted
#define dtrace_aggregate_print(a,b,c) (++prints, 0)
#define oprintf(...) ((void)0)
#define dtrace_stop(x) 0
#define dtrace_work_consumer(a,b,c,d) ((void)(c), DTRACE_WORKSTATUS_DONE)
#define dtrace_errno(x) 0
#define dfatal(...) abort()
#define dtotel_session_tick(x) (++ticks, 0)
#define dtrace_oformat_discard(x) (++discarded)
#define dtrace_oformat_teardown(x) ((void)0)
static void otel_finish(int finish) { if(g_otel){finishes += finish;g_otel=NULL;} }
''' + worker + r'''
static void run(int mode, int expected) {
 prints=ticks=finishes=discarded=0;
 formatted=mode==1 || mode==2;
 g_otel=mode==3?(void *)1:NULL;
 atomic_store(&g_intr,1);
 atomic_store(&g_session_stop,mode==4);
 atomic_store(&g_impatient,mode==5);
 atomic_store(&g_output_worker_done,0);
 HOST_OPTIONS
 dtc_work(HOST_ARGUMENT);
 assert(prints==expected);
 assert(atomic_load(&g_output_worker_done));
 if(mode==3)assert(ticks==1 && finishes==1);
 if(mode==4)assert(discarded==1);
}
int main(void) {
 run(0,1); /* Ordinary host aggregation at SIGINT. */
 run(1,0); /* Formatter owns output. */
 run(2,1); /* -O requests final aggregation with formatter. */
 run(3,0); /* OTel owns export. */
 run(4,0); /* Revoked session discards output. */
 run(5,0); /* Impatient shutdown must not print. */
 prints=0;formatted=0;g_otel=NULL;
 atomic_store(&g_session_stop,0);atomic_store(&g_impatient,0);
 dtc_work(LOCAL_ARGUMENT);assert(prints==1);
 prints=0;
 atomic_store(&g_session_stop,0);atomic_store(&g_impatient,0);
 dtc_work(NULL);assert(prints==0); /* Guest/link worker stays silent. */
 return 0;
}
'''
options = 'g_host_workarg.print_upon_exit = mode == 2;' if 'g_host_workarg' in worker else ''
fixture = fixture.replace('HOST_ARGUMENT', arg).replace('HOST_OPTIONS', options).replace('LOCAL_ARGUMENT', local_arg)
(out/'worker.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-Wno-unused-value',
    '-Wno-unused-but-set-variable','-fsanitize=address,undefined','-pthread',
    str(out/'worker.c'),'-o',str(out/'worker')],check=True)
subprocess.run([str(out/'worker')],check=True,timeout=30)
print('PASS: actual host worker aggregation, formatter/-O, OTel, revocation, impatient shutdown, and silent guest worker')
