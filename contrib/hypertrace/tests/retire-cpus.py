#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual vCPU retirement bookkeeping with pthreads; no VM operations."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'usr.sbin/bhyve/bhyverun.c').read_text()
start = source.index('static atomic_bool migration_retiring_cpus;')
end = source.index('/* Migration acknowledgments are taken', start)
delete = source.index('void\nfbsdrun_deletecpu(')
body = source[start:end] + source[delete:source.index('int\nfbsdrun_suspendcpu(', delete)]
fixture = r'''
#include <sys/param.h>
#include <sys/cpuset.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define BSP 0
#define BHYVE_EXIT_ERROR 4
#define EPRINTLN(...) fprintf(stderr, __VA_ARGS__)
static int guest_ncpus=4;
static cpuset_t cpumask;
static struct { pthread_t thread; bool thread_created, thread_joined; } vcpu_info[4];
static atomic_int ready, live;
static int joins, fail_join;
static int test_join(pthread_t thread, void **result) {
    joins++;
    if (joins == fail_join) return EBUSY;
    return pthread_join(thread, result);
}
void fbsdrun_deletecpu(int);
static void sci_retire(void) {}
static void console_input_retire(void) {}
static void fbsdrun_migration_retire_wake(void) {}
#define pthread_join test_join
''' + body + r'''
#undef pthread_join
static void *worker(void *arg) {
    int id=(int)(intptr_t)arg;
    atomic_fetch_add(&ready, 1);
    while (!fbsdrun_cpus_retiring()) usleep(100);
    assert(atomic_load(&live)); /* Context remains owned until every join. */
    fbsdrun_retirecpu_if_requested(id);
    abort();
}
int main(void) {
    assert(fbsdrun_retire_cpus_wait()==EINVAL);
    atomic_store(&live, 1);
    for (int i=0;i<guest_ncpus;i++) CPU_SET(i, &cpumask);
    for (int i=0;i<guest_ncpus;i++) {
        assert(pthread_create(&vcpu_info[i].thread,NULL,worker,(void *)(intptr_t)i)==0);
        vcpu_info[i].thread_created=true;
    }
    while (atomic_load(&ready)!=guest_ncpus) usleep(100);
    fail_join=2;
    fbsdrun_retire_cpus_begin();
    assert(fbsdrun_retire_cpus_wait()==EBUSY);
    assert(vcpu_info[0].thread_joined && !vcpu_info[1].thread_joined);
    fail_join=0;
    assert(fbsdrun_retire_cpus_wait()==0 && joins==5);
    assert(CPU_EMPTY(&cpumask));
    atomic_store(&live, 0);
    assert(fbsdrun_retire_cpus_wait()==0 && joins==5);
    puts("PASS: controller survives BSP/AP retirement; partial joins retry exactly once");
}
'''
(out / 'retire-cpus.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread',
    '-fsanitize=address,undefined',str(out / 'retire-cpus.c'),
    '-o',str(out / 'retire-cpus')],check=True)
subprocess.run([str(out / 'retire-cpus')],check=True,timeout=30)
