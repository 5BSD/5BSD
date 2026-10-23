#!/usr/bin/env python3
"""Exercise actual interface hook registration, departure and drain ordering."""
from pathlib import Path
import os, shlex, subprocess, tempfile, unittest
ROOT = Path(__file__).resolve().parents[4]
STUBS = r'''
#include <sys/queue.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
struct ifnet { unsigned if_flags; char if_xname[16]; };
struct task { void (*t_func)(void *); void *t_arg; int pending, drained; };
struct taskq { int unused; };
struct mtx { int unused; };
static struct taskq *systq;
static int lock, netlock, calls, drains, adds, late_attempts, unregisters;
static struct ifnet *departing;
#define IFF_DYING 0x10000
#define M_PF 0
#define M_NOWAIT 1
#define M_USE_RESERVE 2
#define M_WAITOK 4
#define M_ZERO 8
#define MTX_DEF 0
#define MTX_SYSINIT(...)
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
#define NET_LOCK() do { assert(!netlock); netlock = 1; } while (0)
#define NET_UNLOCK() do { assert(netlock); netlock = 0; } while (0)
static void mtx_lock(struct mtx *m) { (void)m; assert(!lock); lock = 1; }
static void mtx_unlock(struct mtx *m) { (void)m; assert(lock); lock = 0; }
static int obsd_pf_nosleep(void) { return 0; }
static void *allocate(size_t n) { return calloc(1,n); }
static void discard(void *p) { free(p); }
#define malloc(n, type, flags) ((void)(flags), allocate(n))
#define free(p, type) discard(p)
static int task_del(struct taskq *q, struct task *t) { (void)q; t->pending = 0; return 1; }
static int task_add(struct taskq *q, struct task *t) {
 (void)q; assert(lock); assert(!t->drained); t->pending++; adds++; return 1;
}
static void taskq_del_barrier(struct taskq *, struct task *) __attribute__((unused));
'''
MAIN = r'''
static int expected_drains;
static struct task late;
static void taskq_del_barrier(struct taskq *q, struct task *t) {
 struct obsd_ifhook *h;
 (void)q; assert(!lock && !netlock);
 /* Model a registration racing with the unlocked draining phase. */
 obsd_hook_add(departing, &late, OBSD_HOOK_LINK); late_attempts++;
 TAILQ_FOREACH(h, &obsd_ifhooks, h_entry) assert(h->h_ifp != departing);
 /* A running callback can unregister itself; this must not deadlock or
  * invalidate the detached registration list being drained. */
 obsd_hook_del(departing, t, OBSD_HOOK_LINK); unregisters++;
 t->pending = 0; t->drained = 1; drains++;
}
static void detached(void *arg) {
 struct task *t = arg;
 assert(netlock && !lock && t->drained && drains == expected_drains);
 calls++;
 obsd_hook_del(departing, t, OBSD_HOOK_DETACH);
 obsd_hook_add(departing, &late, OBSD_HOOK_DETACH); late_attempts++;
}
static void exercise(unsigned flags) {
 struct ifnet target = {0}, other = {0};
 struct task tasks[60] = {0}, unrelated = {0}, replacement = {0};
 departing = &target; expected_drains = 60;
 calls = drains = adds = late_attempts = unregisters = 0;
 /* More than the old 16-element batch, mixed kinds and queued work. */
 for (int i = 0; i < 60; i++) {
  tasks[i].t_func = detached; tasks[i].t_arg = &tasks[i];
  obsd_hook_add(&target, &tasks[i], i % 3 + 1);
  obsd_hook_add(&target, &tasks[i], i % 3 + 1); /* duplicate is a no-op */
 }
 obsd_hook_add(&other, &unrelated, OBSD_HOOK_LINK);
 obsd_ifhooks_run(&target, OBSD_HOOK_LINK); assert(adds == 20);
 target.if_flags = flags;
 obsd_ifhooks_run(&target, OBSD_HOOK_DETACH);
 assert(calls == 20 && drains == 60 && !lock && !netlock);
 assert(late_attempts == 80 && unregisters == 60);
 for (int i = 0; i < 60; i++) assert(tasks[i].drained && !tasks[i].pending);
 obsd_ifhooks_run(&target, OBSD_HOOK_LINK); assert(adds == 20);
 obsd_ifhooks_run(&other, OBSD_HOOK_LINK); assert(adds == 21);
 obsd_hook_del(&other, &unrelated, OBSD_HOOK_LINK);
 assert(TAILQ_EMPTY(&obsd_ifhooks));
 /* Dying interfaces stay closed. A completed VNET move may reattach. */
 obsd_hook_add(&target, &replacement, OBSD_HOOK_LINK);
 if (flags & IFF_DYING) assert(TAILQ_EMPTY(&obsd_ifhooks));
 else {
  assert(!TAILQ_EMPTY(&obsd_ifhooks));
  obsd_ifhooks_run(&target, OBSD_HOOK_LINK); assert(adds == 22);
  obsd_hook_del(&target, &replacement, OBSD_HOOK_LINK);
 }
 assert(TAILQ_EMPTY(&obsd_ifhooks));
}
int main(void) { exercise(0); exercise(IFF_DYING); return 0; }
'''
class HookLifecycle(unittest.TestCase):
 def test_registration_departure_and_draining(self):
  source = (ROOT/'sys/netpfil/openbsd-pf/openbsd_compat.c').read_text()
  start = source.index('struct obsd_ifhook {')
  end = source.index('\nvoid\nif_addrhook_add', start)
  with tempfile.TemporaryDirectory() as temp:
   p = Path(temp); (p/'test.c').write_text(STUBS + source[start:end] + MAIN)
   subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
       ['-Wall', '-Wextra', '-Werror', str(p/'test.c'), '-o', str(p/'test')], check=True)
   subprocess.run([str(p/'test')], check=True)
if __name__ == '__main__': unittest.main()
