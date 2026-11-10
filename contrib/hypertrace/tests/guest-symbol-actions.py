#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production symbol action arms with host and virtual probes."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use the /usr/obj object root')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\t\t\tcase DTRACEACT_SYM:',
    source.index('\t\t\tcase DTRACEACT_PRINTM: {'))
end = source.index('\n\t\t\tcase DTRACEACT_EXIT:', start)
arms = source[start:end]
early_start = source.index('\t\t\t/* These actions operate on or resolve')
early = source[early_start:
    source.index('\n\t\t\tswitch (act->dta_kind) {', early_start)]
assert 'case DTRACEACT_USYM:' in early
assert 'case DTRACEACT_UADDR:' not in early
header = (root / 'sys/sys/hypertrace.h').read_text()
macros = header[header.index('#define HYPERTRACE_USTACK_GUEST_TAG'):
    header.index('/* Version 2', header.index('#define HYPERTRACE_USTACK_GUEST_TAG'))]
fixture = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A failed ASSERT is a debug-kernel panic: trap it where a case expects one. */
static jmp_buf assert_trap;
static int assert_armed;
#define ASSERT(x) do { if (!(x)) { assert(assert_armed); \
    longjmp(assert_trap, 1); } } while (0)
#define ASSERT_TRIPS(stmt) do { assert_armed = 1; \
    if (setjmp(assert_trap) == 0) { stmt; assert(!"ASSERT held"); } \
    assert_armed = 0; } while (0)
enum {
    DTRACEACT_SYM = 1, DTRACEACT_MOD, DTRACEACT_USYM,
    DTRACEACT_UMOD, DTRACEACT_UADDR, DTRACEACT_STOP, DTRACEACT_BREAKPOINT,
    DTRACEACT_PANIC, DTRACEACT_CHILL, DTRACEACT_RAISE, DTRACEACT_IMMSTACK,
    DTRACEACT_JSTACK
};
#define CPU_DTRACE_ILLOP 8
#define DTRACE_STORE(type, base, offset, value) \
    (*(type *)((base) + (offset)) = (value))
UADDR_MACROS
struct probe { unsigned dtpr_vmid; };
struct hypertrace_args { int htr_pid; };
struct { struct hypertrace_args *dtms_htrargs; } mstate;
struct process { int p_pid; };
static struct process *curproc;
static int allow_kernel = 1, allow_proc = 1;
static int dtrace_priv_kernel(void *state) { (void)state; return allow_kernel; }
static int dtrace_priv_proc(void *state) { (void)state; return allow_proc; }

static int
run(int kind, struct probe *probe, unsigned *flags, unsigned char output[32])
{
    uintptr_t val = 0x1234;
    size_t valoffs = 0;
    unsigned char *tomax = output;
    void *state = NULL;
    int completed = 0;
    struct action { int dta_kind; } action_record = {kind};
    struct action *act = &action_record;

    for (int action = 0; action < 1; action++) {
PRODUCTION_EARLY
        switch (kind) {
PRODUCTION_ARMS
        default: assert(0);
        }
        completed++;
    }
    return completed;
}

int
main(void)
{
    struct probe guest = {7}, host = {0};
    struct hypertrace_args guest_args = {321};
    struct process process = {73};
    unsigned char output[32];
    unsigned flags;
    int kinds[] = {DTRACEACT_SYM, DTRACEACT_MOD, DTRACEACT_USYM,
        DTRACEACT_UMOD};

    mstate.dtms_htrargs = &guest_args;

    for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        memset(output, 0x5a, sizeof(output));
        curproc = NULL;
        flags = 0;
        assert(run(kinds[i], &guest, &flags, output) == 0);
        assert(flags == CPU_DTRACE_ILLOP && output[0] == 0x5a);
    }
    memset(output, 0x5a, sizeof(output));
    flags = 0;
    assert(run(DTRACEACT_UADDR, &guest, &flags, output) == 0 && flags == 0);
    assert(*(uint64_t *)output == HYPERTRACE_UADDR_ENCODE(7, 321) &&
        *(uint64_t *)(output + sizeof(uint64_t)) == 0x1234);
    allow_proc = 0;
    memset(output, 0x5a, sizeof(output));
    flags = 0;
    assert(run(DTRACEACT_UADDR, &guest, &flags, output) == 0 &&
        flags == 0 && output[0] == 0x5a);
    allow_proc = 1;
    /* dtrace_probe() passes hypertrace arguments for every virtual probe. */
    mstate.dtms_htrargs = NULL;
    memset(output, 0x5a, sizeof(output));
    flags = 0;
    ASSERT_TRIPS(run(DTRACEACT_UADDR, &guest, &flags, output));
    assert(flags == 0 && output[0] == 0x5a);
    curproc = &process;
    memset(output, 0x5a, sizeof(output));
    flags = 0;
    assert(run(DTRACEACT_SYM, &host, &flags, output) == 1 && flags == 0);
    assert(output[0] == 0x5a);
    flags = 0;
    assert(run(DTRACEACT_USYM, &host, &flags, output) == 0 && flags == 0);
    assert(*(uint64_t *)output == 73 &&
        *(uint64_t *)(output + sizeof(uint64_t)) == 0x1234);
    allow_kernel = 0;
    flags = 0;
    assert(run(DTRACEACT_MOD, &host, &flags, output) == 0 && flags == 0);
    allow_proc = 0;
    flags = 0;
    assert(run(DTRACEACT_UADDR, &host, &flags, output) == 0 && flags == 0);
    puts("PASS: guest UADDR records VM/PID/PC; symbol actions reject host context");
    return 0;
}
'''.replace('PRODUCTION_EARLY', early).replace('PRODUCTION_ARMS', arms) \
    .replace('UADDR_MACROS', macros)
path = out / 'guest-symbol-actions.c'
path.write_text(fixture)
binary = out / 'guest-symbol-actions'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
