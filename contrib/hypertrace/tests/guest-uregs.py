#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the production guest UREGS helper over a frozen synthetic VM."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
match = re.search(r'static int\ndtrace_guest_trapframe\(', source)
if match is None:
    raise SystemExit('Missing guest trapframe helper')
ureg = source.index('static int\ndtrace_guest_ureg(', match.start())
helper = source[match.start():source.index('\n}', ureg) + 2]
fixture = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef unsigned int uint_t;
enum { CPU_DTRACE_ILLOP = 1, CPU_DTRACE_BADADDR = 2,
    CPU_DTRACE_FAULT = CPU_DTRACE_ILLOP | CPU_DTRACE_BADADDR };
struct trapframe { uint64_t rax, rip; };
struct thread { uint8_t padding[24]; struct trapframe *td_frame; };
typedef struct { void *htr_curthread; } hypertrace_args_t;
typedef struct { hypertrace_args_t *dtms_htrargs;
    const void *dtms_vmhdl; } dtrace_mstate_t;
static struct { unsigned cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[curcpu].cpuc_dtrace_flags |= (flag))
#define DTRACE_CPUFLAG_ISSET(flag) ((cpu_core[curcpu].cpuc_dtrace_flags & (flag)) != 0)
static uint8_t guest_mem[0x4000];
static const int guest_handle = 1;
static int reads, fail_on;
static int guest_copy(const void *h, uint64_t addr, void *dst, size_t len)
{
    assert(h == &guest_handle && len != 0);
    reads++;
    if (reads == fail_on || addr > sizeof(guest_mem) ||
        len > sizeof(guest_mem) - addr)
        return -1;
    memcpy(dst, guest_mem + addr, len);
    return 0;
}
static int (*hypertrace_guest_copyin)(const void *, uint64_t, void *, size_t)
    = guest_copy;
static uint64_t dtrace_getreg(struct trapframe *frame, uint_t ndx)
{
    if (ndx == 0) return frame->rax;
    if (ndx == 1) return frame->rip;
    DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
    return 0;
}
HELPER
static void reset(void)
{
    cpu_core[0].cpuc_dtrace_flags = 0;
    cpu_core[0].cpuc_dtrace_illval = 0;
    reads = 0; fail_on = 0;
    hypertrace_guest_copyin = guest_copy;
}
int main(void)
{
    const uintptr_t thread_addr = 0x1000, frame_addr = 0x2000;
    const struct trapframe frame = { 0x1234, 0x5678 };
    const size_t field = offsetof(struct thread, td_frame);
    hypertrace_args_t args = { (void *)thread_addr };
    dtrace_mstate_t mstate = { &args, &guest_handle };
    uint64_t value = UINT64_MAX;
    memcpy(guest_mem + thread_addr + field, &frame_addr,
        sizeof(frame_addr));
    memcpy(guest_mem + frame_addr, &frame, sizeof(frame));
    reset();
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 1 &&
        value == frame.rax && reads == 2);
    reset();
    assert(dtrace_guest_ureg(&mstate, 1, &value) == 1 &&
        value == frame.rip && reads == 2);
    reset(); value = UINT64_MAX; mstate.dtms_htrargs = NULL;
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
        reads == 0 && value == UINT64_MAX);
    mstate.dtms_htrargs = &args;
    reset(); args.htr_curthread = NULL;
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        reads == 0);
    reset(); args.htr_curthread = (void *)(UINTPTR_MAX - field + 1);
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
        reads == 0);
    args.htr_curthread = (void *)thread_addr;
    reset(); fail_on = 1;
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_illval == thread_addr + field &&
        reads == 1);
    reset(); fail_on = 2;
    assert(dtrace_guest_ureg(&mstate, 0, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_illval == frame_addr && reads == 2);
    reset();
    assert(dtrace_guest_ureg(&mstate, 99, &value) == 0 &&
        cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP);
    puts("PASS: guest UREGS uses translated frozen trapframe and fails closed");
    return 0;
}
'''.replace('HELPER', helper)
source_file = out / 'guest-uregs.c'
source_file.write_text(fixture)
binary = out / 'guest-uregs'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)],
    check=True)
subprocess.run([str(binary)], check=True, timeout=30)
