#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production memref and memstr interpreter arms without a VM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('\tcase DIF_SUBR_MEMREF: {')
end = source.index('\n#ifndef illumos', start)
memref = source[start:end]
start = source.index('\tcase DIF_SUBR_MEMSTR: {', end)
end = source.index('\n#endif', start)
memstr = source[start:end]
start = source.index('\t\t\tcase DTRACEACT_PRINTM: {')
end = source.index('\n\t\t\tcase DTRACEACT_CHILL:', start)
printm = source[start:end]
start = source.index('\t\t\tif (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF ||', end)
end = source.index('\n\t\t\tswitch (size)', start)
byref = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(x) assert(x)
#define DIF_SUBR_MEMREF 1
#define DIF_SUBR_MEMSTR 2
#define DTRACEACT_PRINTM 3
#define DIF_TF_BYREF 1
#define DIF_TF_BYUREF 2
#define CPU_DTRACE_ILLOP 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_BADADDR 4
#define CPU_DTRACE_DROP 8
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
#define DTRACE_CPUFLAG_SET(bit) (*flags |= (bit))
#define DTRACE_CPUFLAG_ISSET(bit) ((*flags & (bit)) != 0)
#define DTRACE_INSCRATCH(ms, n) \
    ((ms)->dtms_scratch_base + (ms)->dtms_scratch_size - \
    (ms)->dtms_scratch_ptr >= (n))
#define DTRACE_INSCRATCHPTR(ms, p, n) \
    ((p) >= (ms)->dtms_scratch_base && \
    (p) - (ms)->dtms_scratch_base <= (ms)->dtms_scratch_size && \
    (n) <= (ms)->dtms_scratch_size - ((p) - (ms)->dtms_scratch_base))
#define DTRACE_STORE(type, buf, offs, value) \
    (*(type *)((buf) + (offs)) = (value))
#define P2ROUNDUP(x, n) (((x) + (n) - 1) & ~((n) - 1))

struct probe { uint16_t dtpr_vmid; };
struct state {
    uintptr_t dtms_scratch_base;
    uintptr_t dtms_scratch_ptr;
    size_t dtms_scratch_size;
    struct probe *dtms_probe;
    const void *dtms_vmhdl;
};
struct difo_mock { struct { size_t dtdt_size; unsigned dtdt_flags; }
    dtdo_rtype; };
struct act_mock { int dta_kind, dta_intuple; };
struct treg { uintptr_t dttk_value; const void *dttk_vmhdl; };
struct reg { uintptr_t dttr_value; const void *dttr_vmhdl; };
static size_t dtrace_memstr_max;
static int fault_after = -1;
static const unsigned char guest[] = {'a', 0, 'b', 'd'};

static int
dtrace_canload_tagged(uintptr_t addr, const void *tag, size_t size,
    struct state *ms, void *vs)
{
    (void)addr; (void)tag; (void)size; (void)ms; (void)vs;
    return 1;
}

static uint8_t
dtrace_load8(const void *tag, uintptr_t addr)
{
    extern unsigned *active_flags;
    if (tag == NULL)
        return *(const uint8_t *)addr;
    if (addr < 0x1000 || addr >= 0x1000 + sizeof(guest) ||
        (fault_after >= 0 && addr - 0x1000 >= (uintptr_t)fault_after)) {
        *active_flags |= CPU_DTRACE_BADADDR;
        return 0;
    }
    return guest[addr - 0x1000];
}

static void
dtrace_bcopy(const void *tag, const void *source, void *destination,
    size_t length)
{
    extern unsigned *active_flags;
    unsigned char *bytes = destination;
    for (size_t i = 0; i < length; i++) {
        bytes[i] = dtrace_load8(tag, (uintptr_t)source + i);
        if (*active_flags & CPU_DTRACE_FAULT)
            return;
    }
}

unsigned *active_flags;
static unsigned vcanload_calls, byref_calls;
static const void *byref_tag;
static size_t byref_length;
static int
dtrace_vcanload(const void *tag, void *source, void *type,
    void *remain, struct state *ms, void *vs)
{
    (void)tag; (void)source; (void)type; (void)remain;
    (void)ms; (void)vs;
    vcanload_calls++;
    return 1;
}
static void
dtrace_store_by_ref(struct state *ms, struct difo_mock *dp,
    unsigned char *out, size_t length, size_t *offset, uintptr_t *value,
    uint64_t end, int intuple, int kind, const void *tag, void *state)
{
    (void)ms; (void)dp; (void)end; (void)intuple; (void)kind; (void)state;
    byref_calls++;
    byref_tag = tag;
    byref_length = length;
    if (tag == NULL)
        memcpy(out + *offset, (const void *)*value, length);
    *offset += length;
}
static void
run(int subr, struct state *mstate, struct treg tupregs[3],
    struct reg regs[1], unsigned *flags)
{
    const int rd = 0;
    void *vstate = NULL;
    active_flags = flags;
    switch (subr) {
PRODUCTION_MEMREF
PRODUCTION_MEMSTR
    default: assert(0);
    }
}

static void
run_printm(struct state *state, uintptr_t *value, size_t *offset,
    size_t *sizep, unsigned *flags, unsigned char output[32], int full)
{
    struct state mstate = *state;
    struct probe *probe = mstate.dtms_probe;
    struct difo_mock difo = {{15, DIF_TF_BYREF}}, *dp = &difo;
    struct act_mock action = {DTRACEACT_PRINTM, 0}, *act = &action;
    uintptr_t val = *value;
    size_t valoffs = *offset, size = *sizep;
    unsigned char *tomax = output;
    const void *retvmhdl = probe->dtpr_vmid ? state->dtms_vmhdl : NULL;
    size_t tracememsize = 0;
    void *vstate = NULL, *state_handle = NULL;

    for (int action = 0; action < 1; action++) {
        switch (DTRACEACT_PRINTM) {
PRODUCTION_PRINTM
        default: assert(0);
        }
        if (full) {
#define state state_handle
PRODUCTION_BYREF
#undef state
        }
    }
    *value = val;
    *offset = valoffs;
    *sizep = size;
}

int
main(void)
{
    union { uintptr_t align; unsigned char bytes[64]; } scratch;
    struct probe host = {0}, virtual = {1};
    struct state ms = {(uintptr_t)scratch.bytes,
        (uintptr_t)scratch.bytes, sizeof(scratch.bytes), &virtual, &virtual};
    struct treg args[3] = {{0x1000, &virtual}, {4, NULL}, {0, NULL}};
    struct reg result[1] = {{123, &virtual}};
    unsigned flags = 0;

    memset(scratch.bytes, 0x5a, sizeof(scratch.bytes));
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == 0 && result[0].dttr_value == ms.dtms_scratch_base);
    assert(((uintptr_t *)scratch.bytes)[0] ==
        ms.dtms_scratch_base + 2 * sizeof(uintptr_t));
    assert(((uintptr_t *)scratch.bytes)[1] == 4);
    assert(memcmp(scratch.bytes + 2 * sizeof(uintptr_t), guest, 4) == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base +
        2 * sizeof(uintptr_t) + 4);

    uintptr_t value = result[0].dttr_value;
    size_t offset = 0, printsize = 0;
    unsigned char output[32];
    memset(output, 0x5a, sizeof(output));
    flags = 0;
    run_printm(&ms, &value, &offset, &printsize, &flags, output, 1);
    assert(flags == 0 && printsize == 4 &&
        value == ms.dtms_scratch_base + 2 * sizeof(uintptr_t) &&
        offset == sizeof(size_t) + 4 && *(size_t *)output == 4 &&
        memcmp(output + sizeof(size_t), guest, 4) == 0 &&
        byref_calls == 1 && byref_tag == NULL && byref_length == 4 &&
        vcanload_calls == 0);

    memcpy(scratch.bytes, guest, 4);
    ms.dtms_scratch_ptr = ms.dtms_scratch_base + 4;
    args[0].dttk_value = ms.dtms_scratch_base;
    args[0].dttk_vmhdl = NULL;
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == 0 && result[0].dttr_value ==
        ms.dtms_scratch_base + sizeof(uintptr_t) &&
        ((uintptr_t *)result[0].dttr_value)[0] == ms.dtms_scratch_base);

    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    args[0].dttk_value = 0x1000;
    args[0].dttk_vmhdl = &virtual;
    fault_after = 2;
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0 &&
        ms.dtms_scratch_ptr == ms.dtms_scratch_base);
    fault_after = -1;
    args[0].dttk_vmhdl = &host;
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_ILLOP && result[0].dttr_value == 0);
    args[0].dttk_vmhdl = NULL;
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_ILLOP && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    ms.dtms_probe = &host;
    args[0].dttk_vmhdl = &virtual;
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_ILLOP && result[0].dttr_value == 0 &&
        ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    args[0].dttk_vmhdl = NULL;
    args[1].dttk_value = 7;
    ms.dtms_scratch_size = sizeof(uintptr_t);
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_NOSCRATCH);

    ms.dtms_scratch_size = sizeof(scratch.bytes);
    flags = 0;
    run(DIF_SUBR_MEMREF, &ms, args, result, &flags);
    assert(flags == 0 && result[0].dttr_value == ms.dtms_scratch_base);
    assert(((uintptr_t *)scratch.bytes)[0] == 0x1000);
    assert(((uintptr_t *)scratch.bytes)[1] == 7);

    value = 0xdeadbeef;
    offset = printsize = 0;
    memset(output, 0x5a, sizeof(output));
    ms.dtms_probe = &virtual;
    flags = 0;
    run_printm(&ms, &value, &offset, &printsize, &flags, output, 0);
    assert(flags == CPU_DTRACE_BADADDR && value == 0xdeadbeef &&
        offset == 0 && output[0] == 0x5a);
    value = (uintptr_t)scratch.bytes;
    flags = 0;
    run_printm(&ms, &value, &offset, &printsize, &flags, output, 0);
    assert(flags == CPU_DTRACE_BADADDR && offset == 0 &&
        output[0] == 0x5a);
    ms.dtms_probe = &host;
    value = (uintptr_t)scratch.bytes;
    flags = 0;
    run_printm(&ms, &value, &offset, &printsize, &flags, output, 0);
    assert(flags == 0 && value == 0x1000 && offset == sizeof(size_t) &&
        printsize == 7 && *(size_t *)output == 7);

    ((uintptr_t *)scratch.bytes)[0] = ms.dtms_scratch_base +
        2 * sizeof(uintptr_t);
    ((uintptr_t *)scratch.bytes)[1] = 4;
    memcpy(scratch.bytes + 2 * sizeof(uintptr_t), guest, 4);
    ms.dtms_scratch_ptr = ms.dtms_scratch_base +
        2 * sizeof(uintptr_t) + 4;
    value = ms.dtms_scratch_base;
    offset = printsize = 0;
    flags = 0;
    unsigned before_vcanload = vcanload_calls;
    run_printm(&ms, &value, &offset, &printsize, &flags, output, 1);
    assert(flags == 0 && offset == sizeof(size_t) + 4 &&
        vcanload_calls == before_vcanload + 1 &&
        memcmp(output + sizeof(size_t), guest, 4) == 0);

    ms.dtms_probe = &virtual;
    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    args[0].dttk_vmhdl = &virtual;
    args[1].dttk_value = '_';
    args[2].dttk_value = 5;
    fault_after = 2;
    flags = 0;
    run(DIF_SUBR_MEMSTR, &ms, args, result, &flags);
    assert(flags == CPU_DTRACE_BADADDR && result[0].dttr_value == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    fault_after = -1;
    flags = 0;
    run(DIF_SUBR_MEMSTR, &ms, args, result, &flags);
    assert(flags == 0 && result[0].dttr_value == ms.dtms_scratch_base);
    assert(memcmp(scratch.bytes, "a_bd", 5) == 0);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base + 5);
    puts("PASS: guest memref copies into scratch, printm validates provenance, memstr faults do not publish");
    return 0;
}
'''.replace('PRODUCTION_MEMREF', memref).replace('PRODUCTION_MEMSTR', memstr).replace('PRODUCTION_PRINTM', printm).replace('PRODUCTION_BYREF', byref)
source_file = out / 'guest-memref.c'
source_file.write_text(fixture)
binary = out / 'guest-memref'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
