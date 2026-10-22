#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the process-descriptor birth identity used by crash recovery."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/kern/sys_procdesc.c').read_text()
start = source.index('static int\nprocdesc_ioctl(')
end = source.index('\n}', start) + 2
(out / 'procdesc-birth.inc').write_text(source[start:end] + '\n')
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys'),
    str(Path(__file__).with_suffix('.c')),
    '-o', str(out / 'procdesc-birth-test')], check=True)
subprocess.run([str(out / 'procdesc-birth-test')], check=True, timeout=30)

# Exercise the actual exit hook as well as its query, without a running kernel.
a = source.index('bool\nprocdesc_exit(')
b = source.index('\nvoid\nprocdesc_jobstate(', a)
fixture = r'''
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/procdesc.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct procdesc {
 int pd_flags, pd_fpcount, pd_xexit, pd_xsig, pd_selinfo;
 uint32_t pd_reaper_exit;
};
struct proc {
 struct procdesc *p_procdesc;
 int p_flag, p_treeflag, p_xexit, p_xsig, p_zombieref;
 LIST_HEAD(, proc) p_reaplist;
 LIST_ENTRY(proc) link;
};
#define P_WEXIT 1
#define P_TREE_REAPER 2
#define PZOMBIEREF_PARENT 4
#define PDF_EXITED 4
#define SA_XLOCKED 1
#define MA_OWNED 1
static int proctree_lock, locked;
#define sx_assert(lock, state) assert((lock)==&proctree_lock && (state)==SA_XLOCKED)
#define PROC_LOCK_ASSERT(p, state) assert((p)!=NULL && (state)==MA_OWNED)
#define MPASS(condition) assert(condition)
#define KASSERT(condition, message) assert(condition)
#define PROCDESC_LOCK(pd) do { assert((pd)!=NULL && !locked);locked=1; } while(0)
#define PROCDESC_UNLOCK(pd) do { assert((pd)!=NULL && locked);locked=0; } while(0)
#define KNOTE_LOCKED(list, hint) assert(locked)
static void selwakeup(void *p) { assert(p!=NULL && locked); }
static void wakeup(void *p) { assert(p!=NULL && !locked); }
''' + source[a:b] + r'''
int main(void) {
 struct proc p={.p_flag=P_WEXIT,.p_zombieref=PZOMBIEREF_PARENT};
 LIST_INIT(&p.p_reaplist);
 assert(procdesc_exit(&p));
 struct procdesc pd={.pd_fpcount=1};p.p_procdesc=&pd;
 p.p_xexit=7;p.p_xsig=9;
 assert(procdesc_exit(&p));
 assert(pd.pd_reaper_exit==PD_REAPER_EXITED);
 assert(pd.pd_flags==PDF_EXITED && pd.pd_xexit==7 && pd.pd_xsig==9);
 p.p_treeflag=P_TREE_REAPER;p.p_zombieref=0;
 assert(!procdesc_exit(&p));
 assert(pd.pd_reaper_exit==(PD_REAPER_EXITED|PD_REAPER_OWNED|PD_REAPER_EMPTY));
 struct proc child={0};LIST_INSERT_HEAD(&p.p_reaplist,&child,link);
 assert(!procdesc_exit(&p));
 assert(pd.pd_reaper_exit==(PD_REAPER_EXITED|PD_REAPER_OWNED));
 /* Later descendant removal cannot retroactively turn the exit into proof. */
 LIST_REMOVE(&child,link);
 assert(pd.pd_reaper_exit==(PD_REAPER_EXITED|PD_REAPER_OWNED));
 puts("PASS: exit hook snapshots owned empty/nonempty reaper sets before notification");
 return 0;
}
'''
(out/'procdesc-exit.c').write_text(fixture)
subprocess.run(['cc','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
    '-I'+str(root/'sys'),str(out/'procdesc-exit.c'),
    '-o',str(out/'procdesc-exit-test')],check=True)
subprocess.run([str(out/'procdesc-exit-test')],check=True,timeout=30)
