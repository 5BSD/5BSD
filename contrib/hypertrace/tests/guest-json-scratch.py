#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production JSON scratch partition and guest fault handling."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\tcase DIF_SUBR_JSON: {')
end = source.index('\n\tcase DIF_SUBR_TOUPPER:', start)
arm = source[start:end]
fixture = r'''
#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stddef.h>
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
#define DIF_SUBR_JSON 1
#define DTRACEOPT_STRSIZE 0
#define CPU_DTRACE_BADADDR 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
#define DTRACE_CPUFLAG_SET(bit) (*flags |= (bit))
#define DTRACE_INSCRATCH(ms, n) \
    ((ms)->dtms_scratch_base + (ms)->dtms_scratch_size - \
    (ms)->dtms_scratch_ptr >= (n))

struct state { uintptr_t dtms_scratch_base, dtms_scratch_ptr;
    size_t dtms_scratch_size; };
struct options { uint64_t dts_options[1]; };
struct treg { uintptr_t dttk_value; const void *dttk_vmhdl; };
struct reg { uintptr_t dttr_value; const void *dttr_vmhdl; };
static const unsigned char json_bytes[] = {'{', '}', 0};
static const unsigned char selector_bytes[] = {'k', 0};
static unsigned *active_flags;
static int reads, fault_on_read, parser_fault;
static uintptr_t illegal;

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
    if (addr >= 0x1000 && addr < 0x1000 + sizeof(json_bytes))
        return json_bytes[addr - 0x1000];
    if (addr >= 0x2000 && addr < 0x2000 + sizeof(selector_bytes))
        return selector_bytes[addr - 0x2000];
    *active_flags |= CPU_DTRACE_BADADDR;
    return 0;
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

static char *
dtrace_json(const void *tag, uint64_t size, uintptr_t json,
    char *elemlist, int nelems, char *dest)
{
    (void)tag; (void)json;
    if (nelems != 1 || elemlist[0] != 'k')
        return NULL;
    memset(dest, 'Q', size);
    dest[size] = 0;
    if (parser_fault)
        *active_flags |= CPU_DTRACE_BADADDR;
    return dest;
}

static void
run(struct state *mstate, struct options *state, struct treg tupregs[2],
    struct reg regs[1], unsigned *flags)
{
    const int rd = 0;
    uintptr_t *illval = &illegal;
    void *vstate = NULL;
    active_flags = flags;
    switch (DIF_SUBR_JSON) {
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
    struct treg args[2] = {{0x1000, &ms}, {0x2000, &ms}};
    struct reg result[1] = {{123, &ms}};
    unsigned flags;

    memset(scratch, 0x5a, sizeof(scratch));
    flags = 0; reads = 0; fault_on_read = -1; parser_fault = 0;
    run(&ms, &opt, args, result, &flags);
    assert(flags == 0 && result[0].dttr_value == (uintptr_t)scratch);
    assert(ms.dtms_scratch_ptr == (uintptr_t)scratch + 9);
    assert(memcmp(scratch, "QQQQQQQQ", 8) == 0);
    assert(scratch[9] == 'k' && scratch[10] == 0);

    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    flags = 0; reads = 0; fault_on_read = 6;
    run(&ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    flags = 0; reads = 0; fault_on_read = -1; parser_fault = 1;
    run(&ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    parser_fault = 0;
    ms.dtms_scratch_size = 10;
    flags = 0; reads = 0;
    run(&ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_NOSCRATCH && result[0].dttr_value == 0);

    /* A JSON address whose string limit wraps is refused before reading. */
    args[0].dttk_value = UINTPTR_MAX - 4;
    flags = 0; reads = 0; illegal = 0;
    run(&ms, &opt, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && reads == 0 &&
        illegal == UINTPTR_MAX - 4 && result[0].dttr_value == 0);
    args[0].dttk_value = 0x1000;

    /* DTRACEOPT_STRSIZE is a non-negative option. */
    opt.dts_options[0] = UINT64_MAX;
    flags = 0; reads = 0;
    ASSERT_TRIPS(run(&ms, &opt, args, result, &flags));
    assert(flags == 0 && reads == 0);
    puts("PASS: JSON scratch partition and guest faults");
    return 0;
}
'''.replace('PRODUCTION_ARM', arm)
source_file = out / 'guest-json-scratch.c'
source_file.write_text(fixture)
binary = out / 'guest-json-scratch'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
