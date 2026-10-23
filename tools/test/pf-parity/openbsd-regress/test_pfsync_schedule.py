#!/usr/bin/env python3
"""Check pfsync's actual schedule gate against an in-flight callback/restart."""
from pathlib import Path
import os, re, shlex, subprocess, tempfile, unittest
ROOT=Path(__file__).resolve().parents[4]
STUBS=r'''
#include <assert.h>
#include <stdint.h>
#include <pthread.h>
struct mutex { pthread_mutex_t lock; };
struct pfsync_softc { struct mutex sc_sched_mtx; unsigned sc_scheduling; };
struct taskq { int unused; }; struct task { int unused; }; struct timeout { int unused; };
static unsigned tasks, timers;
static void mtx_enter(struct mutex *m) { assert(!pthread_mutex_lock(&m->lock)); }
static void mtx_leave(struct mutex *m) { assert(!pthread_mutex_unlock(&m->lock)); }
static void task_add(struct taskq *q, struct task *t) { (void)q; (void)t; tasks++; }
static void timeout_add_nsec(struct timeout *t, uint64_t n) { (void)t; assert(n==10); timers++; }
'''
MAIN=r'''
static pthread_barrier_t callback_started, callback_resume;
static void *callback(void *arg) {
 struct pfsync_softc *sc=arg;
 pthread_barrier_wait(&callback_started);
 pthread_barrier_wait(&callback_resume);
 /* Callback was already running when teardown closed scheduling. */
 pfsync_schedule_timeout(sc, 0, 10);
 pfsync_schedule_task(sc, 0, 0);
 return 0;
}
int main(void) {
 struct pfsync_softc sc={.sc_sched_mtx={PTHREAD_MUTEX_INITIALIZER}};
 pthread_t thread;
 assert(!pthread_barrier_init(&callback_started,0,2));
 assert(!pthread_barrier_init(&callback_resume,0,2));
 for(unsigned round=0;round<20;round++) {
  pfsync_schedule_set(&sc,1);
  pfsync_schedule_task(&sc,0,0);pfsync_schedule_timeout(&sc,0,10);
  assert(tasks==round+1 && timers==round+1);
  assert(!pthread_create(&thread,0,callback,&sc));
  pthread_barrier_wait(&callback_started);
  pfsync_schedule_set(&sc,0);
  pthread_barrier_wait(&callback_resume);
  assert(!pthread_join(thread,0));
  assert(tasks==round+1 && timers==round+1);
 }
 assert(!pthread_mutex_destroy(&sc.sc_sched_mtx.lock));
 return 0;
}
'''
class ScheduleOwnership(unittest.TestCase):
 def test_running_callback_cannot_rearm_after_close_and_restart_works(self):
  source=(ROOT/'contrib/openbsd-pf/sys/net/if_pfsync.c').read_text()
  # All local scheduling must pass through the owner gate.
  self.assertEqual(len(re.findall(r'\btask_add\s*\(',source)),1)
  self.assertEqual(len(re.findall(r'\btimeout_add_\w+\s*\(',source)),1)
  body=source[source.index('static void\npfsync_schedule_set('):source.index('static int\npfsync_clone_create(')]
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);(p/'test.c').write_text(STUBS+body+MAIN)
   subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-Wall','-Wextra','-Werror','-pthread',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':unittest.main()
