#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the production DIF string-tuple push with guest authorization."""
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
start = source.index('\t\tcase DIF_OP_PUSHTR:')
end = source.index('\t\tcase DIF_OP_PUSHTV:', start)
arm = source[start:end]
match = re.search(r'static int\ndtrace_canload_tagged\(', source)
if match is None:
    raise SystemExit('Missing tagged guest authorization helper')
helper = source[match.start():source.index('\n}', match.start()) + 2]
fixture = r'''
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { DIF_OP_PUSHTR = 1, DIF_TYPE_STRING = 2, DIF_DTR_NREGS = 8,
    CPU_DTRACE_TUPOFLOW = 1, CPU_DTRACE_ILLOP = 2,
    CPU_DTRACE_KPRIV = 4, CPU_DTRACE_BADADDR = 8,
    DTRACE_ACCESS_KERNEL = 1 };
struct probe { unsigned dtpr_vmid; };
typedef struct { struct probe *dtms_probe; const void *dtms_vmhdl;
    unsigned dtms_access; } dtrace_mstate_t;
typedef struct { int unused; } dtrace_vstate_t;
struct reg { uint64_t dttr_value; const void *dttr_vmhdl; };
struct key { uint64_t dttk_value; const void *dttk_vmhdl;
    uint64_t dttk_size; };
static struct { unsigned cpuc_dtrace_flags; uint64_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[curcpu].cpuc_dtrace_flags |= (flag))
static struct probe probe = { 1 };
static const int guest = 1, other_guest = 2;
static unsigned reads;
static const size_t dtrace_strsize_default = 64;
static int dtrace_canload(uint64_t addr, size_t size, dtrace_mstate_t *m,
    dtrace_vstate_t *v)
{
    (void)addr; (void)size; (void)m; (void)v;
    return 1;
}
HELPER
static size_t dtrace_strlen(const void *vmhdl, const char *s, size_t limit)
{
    reads++;
    if (vmhdl != NULL) {
        assert(vmhdl == &guest && (uintptr_t)s == 0x1000);
        return 3;
    }
    return strnlen(s, limit);
}
static struct key run(uint64_t addr, const void *tag, unsigned access,
    unsigned *faults)
{
    struct reg regs[3] = { {0} };
    struct key tupregs[DIF_DTR_NREGS] = { {0} };
    dtrace_mstate_t context = { &probe, &guest, access };
    dtrace_mstate_t *mstate = &context;
    dtrace_vstate_t state = {0}, *vstate = &state;
    unsigned *flags = &cpu_core[0].cpuc_dtrace_flags;
    unsigned ttop = 0, rd = 0, r1 = DIF_TYPE_STRING, r2 = 1;
    regs[rd].dttr_value = addr;
    regs[rd].dttr_vmhdl = tag;
    regs[r2].dttr_value = 16;
    *flags = 0;
    reads = 0;
    switch (DIF_OP_PUSHTR) {
ARM
    default: assert(0);
    }
    *faults = *flags;
    if (*flags != 0)
        assert(ttop == 0 && reads == 0);
    else
        assert(ttop == 1 && reads == 1);
    return tupregs[0];
}
int main(void)
{
    unsigned faults;
    struct key value = run(0x1000, &guest, 0, &faults);
    assert(faults == CPU_DTRACE_KPRIV && value.dttk_size == 0);
    value = run(0x1000, &other_guest, DTRACE_ACCESS_KERNEL, &faults);
    assert(faults == CPU_DTRACE_ILLOP && value.dttk_size == 0);
    value = run(0, &guest, DTRACE_ACCESS_KERNEL, &faults);
    assert(faults == CPU_DTRACE_BADADDR && value.dttk_size == 0);
    value = run(0x1000, &guest, DTRACE_ACCESS_KERNEL, &faults);
    assert(faults == 0 && value.dttk_size == 4 && value.dttk_vmhdl == &guest);
    value = run((uintptr_t)"host", NULL, 0, &faults);
    assert(faults == 0 && value.dttk_size == 5 && value.dttk_vmhdl == NULL);
    puts("PASS: DIF string tuple authorizes guest before scanning");
    return 0;
}
'''.replace('ARM', arm).replace('HELPER', helper)
source_file = out / 'guest-pushtr.c'
source_file.write_text(fixture)
binary = out / 'guest-pushtr'
subprocess.run(['cc', '-D_GNU_SOURCE', '-std=c11', '-Wall', '-Wextra',
    '-Werror', '-fsanitize=address,undefined', str(source_file),
    '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
