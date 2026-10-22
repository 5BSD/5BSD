#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Execute the production DIF store arms against host and tagged guest data."""
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
start = source.index('\t\tcase DIF_OP_COPYS:')
end = source.index('\t\tcase DIF_OP_HYPERCALL:', start)
arms = source[start:end]
match = re.search(r'static int\ndtrace_canload_tagged\(', source)
if match is None:
    raise SystemExit('Missing tagged guest authorization helper')
helper = source[match.start():source.index('\n}', match.start()) + 2]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { DIF_OP_COPYS, DIF_OP_STB, DIF_OP_STH, DIF_OP_STW, DIF_OP_STX };
enum { CPU_DTRACE_ILLOP = 1, CPU_DTRACE_BADADDR = 2,
    CPU_DTRACE_BADALIGN = 4, CPU_DTRACE_KPRIV = 8,
    DTRACE_ACCESS_KERNEL = 1 };
struct reg { uint64_t dttr_value; const void *dttr_vmhdl; };
struct probe { int dtpr_vmid; };
struct mstate { struct probe *dtms_probe; const void *dtms_vmhdl;
    unsigned dtms_access; };
static struct probe probe = { 1 };
static struct { unsigned cpuc_dtrace_flags; uint64_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[curcpu].cpuc_dtrace_flags |= (flag))
typedef struct mstate dtrace_mstate_t;
typedef struct { int unused; } dtrace_vstate_t;
static uint64_t scratch;
static unsigned copies;
static unsigned allow_guest = 1;
static const void *active_guest;
static int dtrace_canstore(uint64_t p, size_t n, dtrace_mstate_t *m,
    dtrace_vstate_t *v)
{
    (void)m; (void)v;
    return p == (uintptr_t)&scratch && n <= sizeof(scratch);
}
static int dtrace_canload(uint64_t p, size_t n, dtrace_mstate_t *m,
    dtrace_vstate_t *v)
{
    (void)p; (void)n; (void)m; (void)v;
    return 1;
}
HELPER
static void dtrace_bcopy(const void *h, const void *src, void *dst, size_t n)
{
    (void)h;
    copies++;
    memcpy(dst, src, n);
}
static struct reg run(int op, const void *source_tag, const void *dest_tag,
    uint64_t source, uint64_t length, unsigned *out_flags)
{
    struct reg regs[3] = {{ source, source_tag }, { length, NULL },
        { (uintptr_t)&scratch, dest_tag }};
    const int r1 = 0, r2 = 1, rd = 2;
    dtrace_mstate_t context = { &probe, active_guest,
        allow_guest ? DTRACE_ACCESS_KERNEL : 0 };
    dtrace_mstate_t *mstate = &context;
    dtrace_vstate_t state = { 0 }, *vstate = &state;
    cpu_core[curcpu].cpuc_dtrace_flags = 0;
    unsigned *flags = &cpu_core[curcpu].cpuc_dtrace_flags;
    uint64_t illval_store = 0;
    uint64_t *illval = &illval_store;
    switch (op) {
ARMS
    default: assert(0);
    }
    *out_flags = *flags;
    return regs[rd];
}
int main(void)
{
    const uint64_t data = UINT64_C(0x1122334455667788);
    const int guest = 1;
    unsigned flags;
    for (int op = DIF_OP_STB; op <= DIF_OP_STX; op++) {
        scratch = 0; copies = 0;
        struct reg dest = run(op, NULL, NULL, data, 0, &flags);
        uint64_t mask = op == DIF_OP_STB ? UINT8_MAX :
            op == DIF_OP_STH ? UINT16_MAX :
            op == DIF_OP_STW ? UINT32_MAX : UINT64_MAX;
        assert(scratch == (data & mask));
        assert(dest.dttr_vmhdl == NULL && flags == 0);
        scratch = 0; copies = 0;
        dest = run(op, &guest, NULL, data, 0, &flags);
        assert(scratch == 0 && dest.dttr_vmhdl == NULL);
        assert(flags == CPU_DTRACE_ILLOP && copies == 0);
        scratch = 0; copies = 0;
        dest = run(op, NULL, &guest, data, 0, &flags);
        assert(scratch == 0 && dest.dttr_vmhdl == &guest);
        assert(flags == CPU_DTRACE_ILLOP && copies == 0);
    }
    scratch = 0; copies = 0;
    active_guest = &guest;
    struct reg dest = run(DIF_OP_COPYS, &guest, NULL,
        (uintptr_t)&data, sizeof(data), &flags);
    assert(scratch == data && flags == 0 && copies == 1);
    assert(dest.dttr_vmhdl == NULL);
    scratch = 0; copies = 0;
    dest = run(DIF_OP_COPYS, NULL, &guest,
        (uintptr_t)&data, sizeof(data), &flags);
    assert(scratch == 0 && flags == CPU_DTRACE_ILLOP && copies == 0);
    assert(dest.dttr_vmhdl == &guest);
    scratch = 0; copies = 0; allow_guest = 0;
    dest = run(DIF_OP_COPYS, &guest, NULL,
        (uintptr_t)&data, sizeof(data), &flags);
    assert(scratch == 0 && flags == CPU_DTRACE_KPRIV && copies == 0);
    allow_guest = 1; active_guest = &scratch;
    dest = run(DIF_OP_COPYS, &guest, NULL,
        (uintptr_t)&data, sizeof(data), &flags);
    assert(scratch == 0 && flags == CPU_DTRACE_ILLOP && copies == 0);
    puts("PASS: DIF stores preserve host scratch and reject tagged destinations/values");
    return 0;
}
'''.replace('ARMS', arms).replace('HELPER', helper)
source_file = out / 'guest-store.c'
source_file.write_text(fixture)
binary = out / 'guest-store'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
