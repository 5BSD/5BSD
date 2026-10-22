#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run DTrace's production associative-key comparator with guest faults."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_bcmp(')
end = source.index('\n\n/*\n * Zero the specified region', start)
comparison = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { CPU_DTRACE_BADADDR = 4, CPU_DTRACE_FAULT = CPU_DTRACE_BADADDR };
static struct { uint16_t cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
static const int guest_tag = 1;
static const uint8_t guest_bytes[4] = { 'a', 'b', 'c', 'd' };
static int fault_after = -1;
static int reads;

static uint8_t
dtrace_load8(const void *vmhdl, uintptr_t addr)
{
    reads++;
    if (vmhdl == NULL)
        return *(const uint8_t *)addr;
    if (addr < 0x1000 || addr >= 0x1000 + sizeof(guest_bytes) ||
        (fault_after >= 0 && addr - 0x1000 >= (uintptr_t)fault_after)) {
        cpu_core[0].cpuc_dtrace_flags |= CPU_DTRACE_BADADDR;
        cpu_core[0].cpuc_dtrace_illval = addr;
        return 0;
    }
    return guest_bytes[addr - 0x1000];
}

COMPARISON

int
main(void)
{
    const uint8_t key[4] = { 'a', 'b', 'c', 'd' };
    const uint8_t false_match[4] = { 'a', 'b', 0, 'd' };

    assert(dtrace_bcmp(&guest_tag, (const void *)0x1000, key, 4) == 0);
    assert(cpu_core[0].cpuc_dtrace_flags == 0);
    fault_after = 2;
    reads = 0;
    assert(dtrace_bcmp(&guest_tag, (const void *)0x1000,
        false_match, 4) == 1);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    assert(reads == 3);

    cpu_core[0].cpuc_dtrace_flags = 0;
    fault_after = -1;
    reads = 0;
    assert(dtrace_bcmp(&guest_tag, (const void *)(UINTPTR_MAX - 1),
        key, 4) == 1);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    assert(reads == 0);

    cpu_core[0].cpuc_dtrace_flags = 0;
    assert(dtrace_bcmp(NULL, key, key, 4) == 0);
    assert(dtrace_bcmp(NULL, key, "abce", 4) == 1);
    puts("PASS: guest key faults cannot compare equal");
    return 0;
}
'''.replace('COMPARISON', comparison)
source_file = out / 'guest-key-compare.c'
source_file.write_text(fixture)
binary = out / 'guest-key-compare'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
