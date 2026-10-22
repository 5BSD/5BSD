#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production DIF scalar-read dispatch with a frozen guest handle."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static uint64_t\ndtrace_guest_load(')
end = source.index('\n\n#define DTRACE_LOADFUNC', start)
production = source[start:end]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define CPU_DTRACE_BADADDR 4
#define CPU_DTRACE_NOFAULT 8
#define CPU_DTRACE_FAULT CPU_DTRACE_BADADDR
static struct { uint16_t cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
static uint8_t guest[8192];
static int copies, translations, fail_copy, no_backend;
static int guest_copyin(const void *handle, uint64_t gla, void *dst, size_t len)
{
    assert(handle == guest);
    assert((cpu_core[0].cpuc_dtrace_flags & CPU_DTRACE_NOFAULT) != 0);
    ++copies;
    if (no_backend) return EOPNOTSUPP;
    if (fail_copy || gla < 0x1000 ||
        gla - 0x1000 > sizeof(guest) - len) return EFAULT;
    memcpy(dst, guest + gla - 0x1000, len);
    return 0;
}
static int (*hypertrace_guest_copyin)(const void *, uint64_t, void *, size_t)
    = guest_copyin;
static void *dtrace_get_paging(const void *handle)
{
    assert(handle == guest);
    return guest;
}
static int dtrace_gla2hva(void *paging, uint64_t gla, uint64_t *hva)
{
    assert(paging == guest);
    ++translations;
    if (gla < 0x1000 || gla >= 0x1000 + sizeof(guest)) return EFAULT;
    *hva = (uintptr_t)(guest + gla - 0x1000);
    return 0;
}
PRODUCTION
int main(void)
{
    uint64_t value;
    for (size_t i = 0; i < sizeof(guest); ++i) guest[i] = (uint8_t)i;
    value = dtrace_guest_load(guest, 0x1000 + PAGE_SIZE - 3, 8);
    assert(value == UINT64_C(0x0403020100fffefd));
    assert(copies == 1 && translations == 0 &&
        cpu_core[0].cpuc_dtrace_flags == 0);
    cpu_core[0].cpuc_dtrace_flags = CPU_DTRACE_NOFAULT;
    assert(dtrace_guest_load(guest, 0x1000, 1) == 0);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_NOFAULT);
    fail_copy = 1;
    cpu_core[0].cpuc_dtrace_flags = 0;
    value = dtrace_guest_load(guest, 0x1000, 4);
    assert(value == 0 && copies == 3 && translations == 0);
    assert(cpu_core[0].cpuc_dtrace_flags & CPU_DTRACE_BADADDR);
    assert(cpu_core[0].cpuc_dtrace_illval == 0x1000);
    fail_copy = 0;
    no_backend = 1;
    cpu_core[0].cpuc_dtrace_flags = 0;
    value = dtrace_guest_load(guest, 0x1000 + PAGE_SIZE - 3, 8);
    assert(value == UINT64_C(0x0403020100fffefd));
    assert(translations == 2 &&
        (cpu_core[0].cpuc_dtrace_flags & CPU_DTRACE_BADADDR) == 0);
    puts("PASS: frozen guest copy, fault, and amd64 translation fallback");
}
'''.replace('PRODUCTION', production)
cfile = out / 'guest-scalar-read.c'
cfile.write_text(fixture)
binary = out / 'guest-scalar-read'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
