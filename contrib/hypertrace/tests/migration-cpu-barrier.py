#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Actual userspace vCPU barrier with real pthreads and faulted VM ioctls."""
from pathlib import Path
import subprocess,sys
root=Path(__file__).resolve().parents[3]
out=Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True,exist_ok=True)
s=(root/'usr.sbin/bhyve/bhyverun.c').read_text()
a=s.index('/* Migration acknowledgments are taken')
b=s.index('#ifdef __amd64__\nstatic int\nkernel_startup_request',a)
fixture=r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
struct vmctx { int unused; };
static int guest_ncpus=2, mode, resume_error, resumes;
static atomic_bool retiring, requested, release_work, pause_done;
static atomic_int escaped;
static bool runnable;
static int pause_error, clocks;
static struct vmctx ctx;
static bool fbsdrun_cpus_retiring(void) { return atomic_load(&retiring); }
static int vm_suspend_all_cpus(struct vmctx *vm) {
 assert(vm==&ctx);atomic_store(&requested,true);
 if (mode==3) { errno=EIO;return -1; } return 0;
}
static int vm_resume_all_cpus(struct vmctx *vm) {
 assert(vm==&ctx);resumes++;errno=resume_error;return resume_error?-1:0;
}
static int test_timedwait(pthread_cond_t *cv,pthread_mutex_t *mtx,const struct timespec *deadline) {
 if (mode==1 || mode==2) return ETIMEDOUT;
 return pthread_cond_timedwait(cv,mtx,deadline);
}
static int test_clock_gettime(clockid_t clock, struct timespec *value) {
 clocks++; assert(clock==CLOCK_MONOTONIC);
 if (mode>=4) { errno=EIO;return -1; }
 return clock_gettime(clock,value);
}
#define clock_gettime test_clock_gettime
#define pthread_cond_timedwait test_timedwait
'''+s[a:b]+r'''
#undef pthread_cond_timedwait
#undef clock_gettime
static void *cpu(void *arg) {
 (void)arg;
 while (!atomic_load(&release_work)) usleep(100);
 fbsdrun_migration_cpu_point();
 if (!fbsdrun_cpus_retiring()) atomic_fetch_add(&escaped,1);
 return NULL;
}
static void *pause_cpus(void *arg) {
 (void)arg;pause_error=fbsdrun_migration_pause_cpus(&ctx,&runnable);
 atomic_store(&pause_done,true);return NULL;
}
int main(void) {
 for (mode=0;mode<7;mode++) {
  pid_t child=fork();assert(child>=0);
  if (child==0) {
   pthread_t workers[2], controller;
   if (mode>=4) {
    atomic_store(&migration_cpu_hold,mode==5);
    atomic_store(&retiring,mode==6);
    int error=fbsdrun_migration_pause_cpus(&ctx,&runnable);
    assert(error==(mode==4?EIO:EBUSY));
    assert(runnable==(mode==4) && clocks==(mode==4?1:0));
    assert(!atomic_load(&requested) && resumes==0);
    assert(atomic_load(&migration_cpu_hold)==(mode==5));
    _exit(0);
   }
   if (mode!=0) {
    resume_error=mode==2?EIO:0;
    int error=fbsdrun_migration_pause_cpus(&ctx,&runnable);
    assert(error==(mode==1?ETIMEDOUT:EIO));
    assert(runnable==(mode!=2) && resumes==1);
    assert(atomic_load(&migration_cpu_hold)==(mode==2));
    if (mode!=2) _exit(0);
   } else {
    for (int i=0;i<2;i++) assert(pthread_create(&workers[i],NULL,cpu,NULL)==0);
    assert(pthread_create(&controller,NULL,pause_cpus,NULL)==0);
    while (!atomic_load(&requested)) usleep(100);
    usleep(10000);assert(!atomic_load(&pause_done));
   }
   atomic_store(&release_work,true);
   if (mode==2) {
    for (int i=0;i<2;i++) assert(pthread_create(&workers[i],NULL,cpu,NULL)==0);
    for (;;) {
     pthread_mutex_lock(&migration_cpu_mutex);int parked=migration_cpu_parked;
     pthread_mutex_unlock(&migration_cpu_mutex);if(parked==2)break;usleep(100);
    }
    assert(atomic_load(&escaped)==0);
    atomic_store(&retiring,true);fbsdrun_migration_retire_wake();
    assert(fbsdrun_migration_resume_cpus(&ctx)==ECANCELED);
   } else {
    assert(pthread_join(controller,NULL)==0 && pause_error==0 && !runnable);
    assert(migration_cpu_parked==2 && atomic_load(&escaped)==0);
    resume_error=EBUSY;assert(fbsdrun_migration_resume_cpus(&ctx)==EBUSY);
    assert(atomic_load(&migration_cpu_hold) && atomic_load(&escaped)==0);
    resume_error=0;assert(fbsdrun_migration_resume_cpus(&ctx)==0);
   }
   for(int i=0;i<2;i++)assert(pthread_join(workers[i],NULL)==0);
   assert(atomic_load(&escaped)==(mode==0?2:0));
   _exit(0);
  }
  int status;assert(waitpid(child,&status,0)==child);
  assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
 }
 return 0;
}
'''
(out/'barrier.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined',str(out/'barrier.c'),'-o',str(out/'barrier')],check=True)
subprocess.run([str(out/'barrier')],check=True,timeout=30)
loop=s[s.index('static void\nvm_loop('):s.index('static int\nnum_vcpus_allowed(')]
assert loop.index('fbsdrun_migration_cpu_point();') < loop.index('error = vm_run(')
assert 'fbsdrun_migration_retire_wake();' in s[s.index('void\nfbsdrun_retire_cpus_begin('):s.index('bool\nfbsdrun_cpus_retiring(')]
print('PASS: delayed CPU acknowledgments, bounded timeout, failed rollback fence, and retirement wakeup without guest execution')
