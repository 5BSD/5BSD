#!/usr/bin/env python3
"""Compile actual PF lock adapters with enabled and disabled assertions."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
STUBS = r'''
#include <assert.h>
struct sx { int unused; };
struct rwlock { int unused; };
static struct sx sx;
static struct rwlock rw;
static int evaluations, assertions;
#define SA_XLOCKED 1
#define SA_SLOCKED 2
#define SA_LOCKED 3
#define SA_UNLOCKED 4
#define RA_WLOCKED 5
#define RA_RLOCKED 6
#define RA_LOCKED 7
#define RA_UNLOCKED 8
static struct sx *get_sx(void) { evaluations++; return &sx; }
static struct rwlock *get_rw(void) { evaluations++; return &rw; }
#ifdef INVARIANTS
static void check_sx(struct sx *p, int flag) {
 assert(p == &sx); assert(flag == assertions + 1); assertions++;
}
static void check_rw(struct rwlock *p, int flag) {
 assert(p == &rw); assert(flag == assertions + 1); assertions++;
}
#define sx_assert(p, f) check_sx((p), (f))
#define rw_assert(p, f) check_rw((p), (f))
#else
#define sx_assert(p, f) (void)0
#define rw_assert(p, f)
#endif
'''
MAIN = r'''
int main(void) {
 rw_assert_wrlock(get_sx());
 rw_assert_rdlock(get_sx());
 rw_assert_anylock(get_sx());
 rw_assert_unlocked(get_sx());
 rw_assert_wrlock(get_rw());
 rw_assert_rdlock(get_rw());
 rw_assert_anylock(get_rw());
 rw_assert_unlocked(get_rw());
#ifdef INVARIANTS
 assert(assertions == 8); assert(evaluations == 8);
#else
 assert(assertions == 0); assert(evaluations == 0);
#endif
 return 0;
}
'''

class LockAssertions(unittest.TestCase):
    def check_mode(self, invariants):
        source = (ROOT / 'sys/netpfil/openbsd-pf/openbsd_compat.h').read_text()
        adapters = source[source.index('#define\t_OBSD_RW('):
                          source.index('static __inline int\nobsd_rw_enter(')]
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p / 'test.c').write_text(STUBS + adapters + MAIN)
            command = shlex.split(os.environ.get('CC', 'cc'))
            command += ['-std=gnu17', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function']
            if invariants:
                command += ['-DINVARIANTS']
            subprocess.run(command + [str(p / 'test.c'), '-o', str(p / 'test')],
                           check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_invariants_dispatch_and_single_evaluation(self):
        self.check_mode(True)

    def test_nodebug_no_argument_evaluation(self):
        self.check_mode(False)

if __name__ == '__main__':
    unittest.main()
