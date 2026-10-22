#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production guest case conversion across scan and copy faults."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\tcase DIF_SUBR_TOUPPER:')
end = source.index('\n#ifdef illumos', start)
arm = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define DIF_SUBR_TOUPPER 1
#define DIF_SUBR_TOLOWER 2
#define DTRACEOPT_STRSIZE 0
#define CPU_DTRACE_ILLOP 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_BADADDR 4
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
#define DTRACE_CPUFLAG_SET(bit) (*flags |= (bit))
#define DTRACE_INSCRATCH(ms, n) \
    ((ms)->dtms_scratch_base + (ms)->dtms_scratch_size - \
    (ms)->dtms_scratch_ptr >= (n))
#define ASSERT(x) assert(x)

struct state { uintptr_t dtms_scratch_base, dtms_scratch_ptr;
    size_t dtms_scratch_size; };
struct options { uint64_t dts_options[1]; };
struct treg { uintptr_t dttk_value; const void *dttk_vmhdl; };
struct reg { uintptr_t dttr_value; const void *dttr_vmhdl; };
static const unsigned char guest[] = {'a', 'B', 'c', 0};
static unsigned *active_flags;
static int reads, fault_on_read;

static uint8_t
dtrace_load8(const void *tag, uintptr_t addr)
{
    ++reads;
    if (reads == fault_on_read) {
        *active_flags |= CPU_DTRACE_BADADDR;
        return 0;
    }
    if (tag == NULL)
        return *(const uint8_t *)addr;
    if (addr < 0x1000 || addr >= 0x1000 + sizeof(guest)) {
        *active_flags |= CPU_DTRACE_BADADDR;
        return 0;
    }
    return guest[addr - 0x1000];
}

static size_t
dtrace_strlen(const void *tag, const char *s, size_t limit)
{
    size_t n;
    for (n = 0; n < limit; n++) {
        if (dtrace_load8(tag, (uintptr_t)s + n) == 0 ||
            (*active_flags & CPU_DTRACE_FAULT) != 0)
            break;
    }
    return n;
}

static int
dtrace_canload_tagged(uintptr_t addr, const void *tag, size_t len,
    struct state *ms, void *vs)
{
    (void)addr; (void)tag; (void)len; (void)ms; (void)vs;
    return 1;
}

static void
run(int subr, struct state *mstate, struct options *state,
    struct treg tupregs[1], struct reg regs[1], unsigned *flags)
{
    const int rd = 0;
    uintptr_t illegal = 0;
    uintptr_t *illval = &illegal;
    void *vstate = NULL;
    active_flags = flags;
    switch (subr) {
PRODUCTION_ARM
    default: assert(0);
    }
}

int
main(void)
{
    unsigned char scratch[32];
    struct state ms = {(uintptr_t)scratch, (uintptr_t)scratch,
        sizeof(scratch)};
    struct options opt = {{8}};
    struct treg args[1] = {{0x1000, &ms}};
    struct reg result[1] = {{123, &ms}};
    unsigned flags;

    flags = 0; reads = 0; fault_on_read = -1;
    run(DIF_SUBR_TOUPPER, &ms, &opt, args, result, &flags);
    assert(flags == 0 && strcmp((char *)scratch, "ABC") == 0);
    assert(result[0].dttr_value == (uintptr_t)scratch);
    assert(ms.dtms_scratch_ptr == (uintptr_t)scratch + 8);

    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    flags = 0; reads = 0;
    run(DIF_SUBR_TOLOWER, &ms, &opt, args, result, &flags);
    assert(flags == 0 && strcmp((char *)scratch, "abc") == 0);

    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    flags = 0; reads = 0; fault_on_read = 2;
    run(DIF_SUBR_TOUPPER, &ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    flags = 0; reads = 0; fault_on_read = 6;
    run(DIF_SUBR_TOUPPER, &ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    opt.dts_options[0] = 0;
    flags = 0; reads = 0; fault_on_read = -1;
    run(DIF_SUBR_TOUPPER, &ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_ILLOP && reads == 0);
    puts("PASS: guest case conversion faults do not publish scratch");
    return 0;
}
'''.replace('PRODUCTION_ARM', arm)
source_file = out / 'guest-casefold.c'
source_file.write_text(fixture)
binary = out / 'guest-casefold'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
