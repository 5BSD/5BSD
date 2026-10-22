#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Check that production restricted DIF loads authorize tagged guest RAM."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
start = source.index('static int\ndtrace_canload_tagged(')
end = source.index('{', start) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
helper = source[start:end]
start = source.index('static int\ndtrace_canload_guest_host(')
end = source.index('{', start) + 1
depth = 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
guest_host_helper = source[start:end]
start = source.index('\t\tcase DIF_OP_RLDSB:')
end = source.index('\t\t/* On a virtual probe, user loads', start)
arms = source[start:end]
fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
enum { CPU_DTRACE_ILLOP = 1, CPU_DTRACE_KPRIV = 2,
    CPU_DTRACE_BADADDR = 4, DTRACE_ACCESS_KERNEL = 8 };
enum { DIF_OP_RLDSB, DIF_OP_LDSB, DIF_OP_RLDSH, DIF_OP_LDSH,
    DIF_OP_RLDSW, DIF_OP_LDSW, DIF_OP_RLDUB, DIF_OP_LDUB,
    DIF_OP_RLDUH, DIF_OP_LDUH, DIF_OP_RLDUW, DIF_OP_LDUW,
    DIF_OP_RLDX, DIF_OP_LDX };
typedef struct { uint64_t dttr_value; const void *dttr_vmhdl; } dtrace_reg_t;
typedef struct { int dtpr_vmid; } dtrace_probe_t;
typedef struct { const char *dtdo_strtab; size_t dtdo_strlen; } dtrace_difo_t;
typedef struct { int unused; } dtrace_vstate_t;
typedef struct {
    dtrace_probe_t *dtms_probe;
    const void *dtms_vmhdl;
    unsigned dtms_access;
    dtrace_difo_t *dtms_difo;
} dtrace_mstate_t;
static struct { unsigned cpuc_dtrace_flags; uintptr_t cpuc_dtrace_illval; }
    cpu_core[1];
static const int curcpu = 0, guest_tag = 1, other_tag = 2;
static uint64_t host_value = UINT64_C(0x1111111111111111);
static uint64_t scratch_value = UINT64_C(0x2222222222222222);
static const uint64_t string_value = UINT64_C(0x3333333333333333);
static uint64_t guest_value = UINT64_C(0x8080808080808080);
static int host_checks, host_reads, guest_reads;
#define DTRACE_CPUFLAG_SET(flag) (cpu_core[0].cpuc_dtrace_flags |= (flag))
#define DTRACE_INRANGE(addr, size, base, length) \
    ((base) != NULL && (addr) >= (uintptr_t)(base) && \
    (size) <= (length) && (addr) - (uintptr_t)(base) <= (length) - (size))
static int dtrace_canload(uint64_t addr, size_t size,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
    (void)mstate; (void)vstate;
    ++host_checks;
    return addr == (uintptr_t)&host_value && size <= sizeof(host_value);
}
static int dtrace_canstore(uint64_t addr, size_t size,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
    (void)mstate; (void)vstate;
    return addr == (uintptr_t)&scratch_value &&
        size <= sizeof(scratch_value);
}
PRODUCTION_HELPER
PRODUCTION_GUEST_HOST_HELPER
static uint64_t load(const void *tag, uintptr_t addr, size_t length)
{
    uint64_t value = 0;
    if (tag == NULL) {
        ++host_reads;
        memcpy(&value, (const void *)addr, length);
    } else {
        assert(tag == &guest_tag);
        ++guest_reads;
        memcpy(&value, &guest_value, length);
    }
    return value;
}
static uint8_t dtrace_load8(const void *tag, uintptr_t addr)
{ return (uint8_t)load(tag, addr, 1); }
static uint16_t dtrace_load16(const void *tag, uintptr_t addr)
{ return (uint16_t)load(tag, addr, 2); }
static uint32_t dtrace_load32(const void *tag, uintptr_t addr)
{ return (uint32_t)load(tag, addr, 4); }
static uint64_t dtrace_load64(const void *tag, uintptr_t addr)
{ return load(tag, addr, 8); }
static dtrace_reg_t run(int op, int vmid, const void *tag,
    uintptr_t addr, unsigned access)
{
    dtrace_probe_t probe = {vmid};
    dtrace_difo_t difo = {(const char *)&string_value,
        sizeof(string_value)};
    dtrace_mstate_t machine = {&probe, &guest_tag, access, &difo};
    dtrace_mstate_t *mstate = &machine;
    dtrace_vstate_t state = {0};
    dtrace_vstate_t *vstate = &state;
    dtrace_reg_t regs[2] = {{addr, tag}, {UINT64_MAX, tag}};
    const int r1 = 0, rd = 1;
    cpu_core[0].cpuc_dtrace_flags = 0;
    cpu_core[0].cpuc_dtrace_illval = 0;
    switch (op) {
PRODUCTION_ARMS
    default: assert(0);
    }
    return regs[rd];
}
int main(void)
{
    const int ops[] = {DIF_OP_RLDSB, DIF_OP_RLDSH, DIF_OP_RLDSW,
        DIF_OP_RLDUB, DIF_OP_RLDUH, DIF_OP_RLDUW, DIF_OP_RLDX};
    const size_t sizes[] = {1, 2, 4, 1, 2, 4, 8};
    const int plain_ops[] = {DIF_OP_LDSB, DIF_OP_LDSH, DIF_OP_LDSW,
        DIF_OP_LDUB, DIF_OP_LDUH, DIF_OP_LDUW, DIF_OP_LDX};
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i) {
        host_checks = host_reads = guest_reads = 0;
        dtrace_reg_t result = run(ops[i], 0, NULL,
            (uintptr_t)&host_value, 0);
        assert(result.dttr_value != UINT64_MAX &&
            host_checks == 1 && host_reads == 1 && guest_reads == 0);
        host_checks = host_reads = guest_reads = 0;
        result = run(ops[i], 1, &guest_tag,
            (uintptr_t)&host_value, 0);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV &&
            cpu_core[0].cpuc_dtrace_illval == (uintptr_t)&host_value &&
            host_checks == 0 && host_reads == 0 && guest_reads == 0);
        result = run(ops[i], 1, &guest_tag,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value != UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == 0 &&
            host_checks == 0 && host_reads == 0 && guest_reads == 1);
        guest_reads = 0;
        result = run(ops[i], 1, &other_tag,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
            guest_reads == 0);
        result = run(ops[i], 1, &guest_tag, 0, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
            guest_reads == 0);
        if (sizes[i] > 1) {
            result = run(ops[i], 1, &guest_tag, UINTPTR_MAX,
                DTRACE_ACCESS_KERNEL);
            assert(result.dttr_value == UINT64_MAX &&
                cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
                guest_reads == 0);
        }
    }
    for (size_t i = 0; i < sizeof(plain_ops) / sizeof(plain_ops[0]); ++i) {
        host_reads = guest_reads = 0;
        dtrace_reg_t result = run(plain_ops[i], 1, NULL,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_BADADDR &&
            cpu_core[0].cpuc_dtrace_illval == (uintptr_t)&host_value &&
            host_reads == 0 && guest_reads == 0);
        result = run(plain_ops[i], 1, NULL,
            (uintptr_t)&scratch_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value != UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == 0 && host_reads == 1);
        result = run(plain_ops[i], 1, NULL,
            (uintptr_t)&string_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value != UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == 0 && host_reads == 2);
        result = run(plain_ops[i], 1, &guest_tag,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value != UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == 0 && guest_reads == 1);
        result = run(plain_ops[i], 1, &other_tag,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_ILLOP &&
            guest_reads == 1);
        result = run(plain_ops[i], 1, &guest_tag,
            (uintptr_t)&host_value, 0);
        assert(result.dttr_value == UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == CPU_DTRACE_KPRIV &&
            guest_reads == 1);
        result = run(plain_ops[i], 0, NULL,
            (uintptr_t)&host_value, DTRACE_ACCESS_KERNEL);
        assert(result.dttr_value != UINT64_MAX &&
            cpu_core[0].cpuc_dtrace_flags == 0);
    }
    puts("PASS: guest loads reject untagged host pointers and preserve owned storage");
}
'''.replace('PRODUCTION_HELPER', helper).replace(
    'PRODUCTION_GUEST_HOST_HELPER', guest_host_helper).replace(
    'PRODUCTION_ARMS', arms)
cfile = out / 'guest-restricted-load.c'
cfile.write_text(fixture)
binary = out / 'guest-restricted-load'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
