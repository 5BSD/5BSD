#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise production DTrace byte/string copies with guest faults and wrap."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static void\ndtrace_bcopy(')
end = source.index('\n\n/*\n * Copy src to dst using safe memory accesses, up to',
    start)
copy_arm = source[start:end]
start = source.index('static void\ndtrace_strcpy(')
end = source.index('\n\n/*\n * Copy src to dst', start)
string_arm = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(x) assert(x)
enum { CPU_DTRACE_BADADDR = 4, CPU_DTRACE_FAULT = CPU_DTRACE_BADADDR };
static struct { uint16_t cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0;
static const int guest_tag = 1;
static const uint8_t guest_bytes[8] = { 'a', 'b', 'c', 'd', 'e', 0, 'x', 'y' };
static int fault_after = -1;

static uint8_t
dtrace_load8(const void *vmhdl, uintptr_t addr)
{
    if (vmhdl == NULL)
        return *(const uint8_t *)addr;
    if (addr == UINTPTR_MAX)
        return 'x';
    if (addr < 0x1000 || addr >= 0x1000 + sizeof(guest_bytes) ||
        (fault_after >= 0 && addr - 0x1000 >= (uintptr_t)fault_after)) {
        cpu_core[curcpu].cpuc_dtrace_flags |= CPU_DTRACE_BADADDR;
        cpu_core[curcpu].cpuc_dtrace_illval = addr;
        return 0;
    }
    return guest_bytes[addr - 0x1000];
}

PRODUCTION_COPY
PRODUCTION_STRING

static void
clear_fault(void)
{
    cpu_core[curcpu].cpuc_dtrace_flags = 0;
    cpu_core[curcpu].cpuc_dtrace_illval = 0;
    fault_after = -1;
}

int
main(void)
{
    uint8_t dst[10];
    uint8_t overlap[] = "abcdefgh";

    memset(dst, 'Z', sizeof(dst));
    dtrace_bcopy(&guest_tag, (const void *)0x1000, dst, 5);
    assert(memcmp(dst, "abcde", 5) == 0 && dst[5] == 'Z');
    assert(cpu_core[0].cpuc_dtrace_flags == 0);

    clear_fault();
    memset(dst, 'Z', sizeof(dst));
    fault_after = 3;
    dtrace_bcopy(&guest_tag, (const void *)0x1000, dst, 5);
    assert(memcmp(dst, "abc", 3) == 0 && dst[3] == 'Z');
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);

    clear_fault();
    dtrace_bcopy(NULL, overlap, overlap + 2, 6);
    assert(memcmp(overlap, "ababcdef", 8) == 0);

    clear_fault();
    memset(dst, 'Z', sizeof(dst));
    dtrace_bcopy(&guest_tag, (const void *)(UINTPTR_MAX - 1), dst, 4);
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    assert(dst[0] == 'Z' && dst[3] == 'Z');

    clear_fault();
    memset(dst, 'Z', sizeof(dst));
    dtrace_strcpy(&guest_tag, (const void *)0x1000, dst, sizeof(dst));
    assert(memcmp(dst, "abcde", 6) == 0 && dst[6] == 'Z');

    clear_fault();
    memset(dst, 'Z', sizeof(dst));
    fault_after = 2;
    dtrace_strcpy(&guest_tag, (const void *)0x1000, dst, sizeof(dst));
    assert(dst[0] == 'a' && dst[1] == 'b' && dst[2] == 'Z');
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);

    clear_fault();
    memset(dst, 'Z', sizeof(dst));
    dtrace_strcpy(&guest_tag, (const void *)UINTPTR_MAX, dst, 2);
    assert(dst[0] == 'x' && dst[1] == 'Z');
    assert(cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR);
    assert(cpu_core[0].cpuc_dtrace_illval == UINTPTR_MAX);

    puts("PASS: guest byte copies stop at faults and address wrap");
    return 0;
}
'''.replace('PRODUCTION_COPY', copy_arm).replace('PRODUCTION_STRING', string_arm)
source_file = out / 'guest-byte-copy.c'
source_file.write_text(fixture)
binary = out / 'guest-byte-copy'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
