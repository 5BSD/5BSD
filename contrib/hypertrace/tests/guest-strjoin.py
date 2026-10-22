#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production strjoin with guest faults in both inputs."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static char *\ndtrace_strjoin(')
end = source.index('\n/*\n * Emulate the execution', start)
arm = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define DTRACEOPT_STRSIZE 0
#define CPU_DTRACE_BADADDR 1
#define CPU_DTRACE_NOSCRATCH 2
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
#define DTRACE_CPUFLAG_SET(bit) (flags |= (bit))
#define DTRACE_CPUFLAG_ISSET(bit) ((flags & (bit)) != 0)
#define DTRACE_INSCRATCH(ms, n) \
    ((ms)->dtms_scratch_base + (ms)->dtms_scratch_size - \
    (ms)->dtms_scratch_ptr >= (n))

typedef struct { uint64_t dts_options[1]; } dtrace_state_t;
typedef struct { uintptr_t dtms_scratch_base, dtms_scratch_ptr;
    size_t dtms_scratch_size; } dtrace_mstate_t;
typedef struct { int unused; } dtrace_vstate_t;
static unsigned flags;
static int reads, fault_on_read;
static const char first[] = "abc";
static const char second[] = "XYZ";

static int
dtrace_strcanload(uint64_t addr, size_t size, const void *tag,
    size_t *remain, dtrace_mstate_t *ms, dtrace_vstate_t *vs)
{
    (void)addr; (void)tag; (void)ms; (void)vs;
    *remain = size;
    return 1;
}

static uint8_t
dtrace_load8(const void *tag, uintptr_t addr)
{
    ++reads;
    if (reads == fault_on_read) {
        flags |= CPU_DTRACE_BADADDR;
        return 0;
    }
    if (tag == NULL)
        return *(const uint8_t *)addr;
    if (addr >= 0x1000 && addr < 0x1000 + sizeof(first))
        return first[addr - 0x1000];
    if (addr >= 0x2000 && addr < 0x2000 + sizeof(second))
        return second[addr - 0x2000];
    flags |= CPU_DTRACE_BADADDR;
    return 0;
}

PRODUCTION_ARM

int
main(void)
{
    char scratch[32];
    dtrace_state_t state = {{16}};
    dtrace_mstate_t ms = {(uintptr_t)scratch, (uintptr_t)scratch,
        sizeof(scratch)};
    dtrace_vstate_t vs = {0};
    char *result;

    flags = 0; reads = 0; fault_on_read = -1;
    result = dtrace_strjoin(&state, &ms, &vs, &state, &state,
        0x1000, 0x2000);
    assert(flags == 0 && result == scratch);
    assert(strcmp(scratch, "abcXYZ") == 0);
    assert(ms.dtms_scratch_ptr == (uintptr_t)scratch + 7);

    ms.dtms_scratch_ptr = ms.dtms_scratch_base;
    flags = 0; reads = 0; fault_on_read = 2;
    result = dtrace_strjoin(&state, &ms, &vs, &state, &state,
        0x1000, 0x2000);
    assert(result == NULL && flags == CPU_DTRACE_BADADDR);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    flags = 0; reads = 0; fault_on_read = 6;
    result = dtrace_strjoin(&state, &ms, &vs, &state, &state,
        0x1000, 0x2000);
    assert(result == NULL && flags == CPU_DTRACE_BADADDR);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);

    state.dts_options[0] = 4;
    flags = 0; reads = 0; fault_on_read = -1;
    result = dtrace_strjoin(&state, &ms, &vs, &state, &state,
        0x1000, 0x2000);
    assert(result == NULL && flags == CPU_DTRACE_NOSCRATCH);
    assert(ms.dtms_scratch_ptr == ms.dtms_scratch_base);
    puts("PASS: guest strjoin faults do not publish scratch");
    return 0;
}
'''.replace('PRODUCTION_ARM', arm)
source_file = out / 'guest-strjoin.c'
source_file.write_text(fixture)
binary = out / 'guest-strjoin'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
