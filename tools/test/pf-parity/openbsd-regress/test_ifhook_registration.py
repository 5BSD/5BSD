#!/usr/bin/env python3
"""Exercise the real hook add path while a departure token is present."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
STUBS = r'''
#include <sys/queue.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
struct ifnet { unsigned if_flags; char if_xname[16]; };
struct task { int unused; };
struct mtx { int unused; };
#define IFF_DYING 0x10000
#define M_PF 0
#define M_NOWAIT 1
#define M_USE_RESERVE 2
#define M_WAITOK 4
#define M_ZERO 8
#define MTX_DEF 0
#define MTX_SYSINIT(...)
static int locked;
static void mtx_lock(struct mtx *m) { (void)m; assert(!locked); locked = 1; }
static void mtx_unlock(struct mtx *m) { (void)m; assert(locked); locked = 0; }
static int obsd_pf_nosleep(void) { return 0; }
static void *allocate(size_t n) { return calloc(1, n); }
static void discard(void *p) { free(p); }
#define malloc(n, type, flags) ((void)(flags), allocate(n))
#define free(p, type) discard(p)
'''
MAIN = r'''
static unsigned count(struct ifnet *ifp) {
 struct obsd_ifhook *h; unsigned n = 0;
 TAILQ_FOREACH(h, &obsd_ifhooks, h_entry) if (h->h_ifp == ifp) n++;
 return n;
}
int main(void) {
 struct ifnet moving = {0}, dying = {.if_flags = IFF_DYING};
 struct task task = {0};
 struct obsd_ifclosing closing = {.c_ifp = &moving};
 TAILQ_INSERT_TAIL(&obsd_ifclosing, &closing, c_entry);
 obsd_hook_add(&moving, &task, OBSD_HOOK_LINK);
 assert(count(&moving) == 0 && !locked);
 obsd_hook_add(&dying, &task, OBSD_HOOK_LINK);
 assert(count(&dying) == 0 && !locked);
 TAILQ_REMOVE(&obsd_ifclosing, &closing, c_entry);
 obsd_hook_add(&moving, &task, OBSD_HOOK_LINK);
 obsd_hook_add(&moving, &task, OBSD_HOOK_LINK);
 assert(count(&moving) == 1 && !locked);
 struct obsd_ifhook *h = TAILQ_FIRST(&obsd_ifhooks);
 TAILQ_REMOVE(&obsd_ifhooks, h, h_entry); free(h, M_PF);
 return 0;
}
'''


class HookRegistration(unittest.TestCase):
    def test_departure_gate_and_move_reopen(self):
        source = (ROOT / 'sys/netpfil/openbsd-pf/openbsd_compat.c').read_text()
        start = source.index('struct obsd_ifhook {')
        end = source.index('\nstatic void\nobsd_hook_del(', start)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / 'test.c').write_text(STUBS + source[start:end] + MAIN)
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                ['-Wall', '-Wextra', '-Werror', str(path / 'test.c'),
                 '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
