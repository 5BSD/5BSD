#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the production DIF user-load arms with host and guest addresses."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c').read_text()
helper_start = source.index('/* User-load DIF on a virtual probe')
helper_end = source.index('/* Copy a guest user buffer', helper_start)
helper = source[helper_start:helper_end]
start = source.index('\t\tcase DIF_OP_ULDSB:')
end = source.index('\t\tcase DIF_OP_RET:', start)
arms = source[start:end]
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

enum { DIF_OP_ULDSB, DIF_OP_ULDSH, DIF_OP_ULDSW, DIF_OP_ULDUB,
    DIF_OP_ULDUH, DIF_OP_ULDUW, DIF_OP_ULDX };
enum { CPU_DTRACE_ILLOP = 1, CPU_DTRACE_NOFAULT = 2,
    CPU_DTRACE_BADADDR = 4, CPU_DTRACE_UPRIV = 8 };
typedef unsigned int uint_t;
typedef struct reg { uint64_t dttr_value; const void *dttr_vmhdl; } dtrace_reg_t;
struct probe { int dtpr_vmid; };
struct guest_args { uint32_t htr_pid; };
typedef struct machine_state { struct probe *dtms_probe;
    const void *dtms_vmhdl; struct guest_args *dtms_htrargs; } dtrace_mstate_t;
typedef struct state { int allowed; } dtrace_state_t;
static struct { uintptr_t cpuc_dtrace_illval; } cpu_core[1];
static int curcpu;
static int guest_handle, other_handle;
static uint64_t guest_value = UINT64_C(0xfffffffffffffffe);
static unsigned flags, host_reads, guest_reads;
static int copy_error;
static uint32_t guest_pid = 77;
static int guest_args_present = 1;
#define DTRACE_CPUFLAG_SET(flag) (flags |= (flag))
#define DTRACE_CPUFLAG_CLEAR(flag) (flags &= ~(flag))
#define DIF_INSTR_OP(instr) (instr)
static int dtrace_priv_proc(dtrace_state_t *state) {
    if (state->allowed) return 1;
    flags |= CPU_DTRACE_UPRIV;
    return 0;
}
static int guest_user_copyin(const void *handle, uint64_t addr,
    void *dst, size_t len) {
    assert(handle == &guest_handle);
    guest_reads++;
    if (copy_error) return copy_error;
    if (addr < 0x1000 || len > 8 || addr > 0x1008 - len) return EFAULT;
    memcpy(dst, (const uint8_t *)&guest_value + (addr - 0x1000), len);
    return 0;
}
static int (*hypertrace_guest_user_copyin)(const void *, uint64_t,
    void *, size_t) = guest_user_copyin;
static uint8_t dtrace_fuword8(const void *p) { uint8_t v; host_reads++; memcpy(&v, p, sizeof(v)); return v; }
static uint16_t dtrace_fuword16(const void *p) { uint16_t v; host_reads++; memcpy(&v, p, sizeof(v)); return v; }
static uint32_t dtrace_fuword32(const void *p) { uint32_t v; host_reads++; memcpy(&v, p, sizeof(v)); return v; }
static uint64_t dtrace_fuword64(const void *p) { uint64_t v; host_reads++; memcpy(&v, p, sizeof(v)); return v; }
HELPER
static dtrace_reg_t run(int op, int vmid, const void *tag, uintptr_t addr,
    int allowed, unsigned *result_flags)
{
    struct probe probe = { .dtpr_vmid = vmid };
    struct guest_args args = { .htr_pid = guest_pid };
    dtrace_mstate_t machine = { .dtms_probe = &probe,
        .dtms_vmhdl = &guest_handle,
        .dtms_htrargs = guest_args_present ? &args : NULL };
    dtrace_mstate_t *mstate = &machine;
    dtrace_state_t process = { .allowed = allowed };
    dtrace_state_t *state = &process;
    dtrace_reg_t regs[2] = {{ .dttr_value = addr, .dttr_vmhdl = tag },
        { .dttr_value = UINT64_MAX, .dttr_vmhdl = tag }};
    const int r1 = 0, rd = 1;
    int instr = op;
    flags = 0;
    switch (op) {
ARMS
    default: assert(0);
    }
    *result_flags = flags;
    return regs[rd];
}
int main(void)
{
    const uint64_t value = UINT64_C(0xfffffffffffffffe);
    const uint64_t expected[] = {
        UINT64_MAX - 1, UINT64_MAX - 1, UINT64_MAX - 1,
        0xfe, 0xfffe, 0xfffffffe, UINT64_MAX - 1
    };
    unsigned flags;
    for (int op = DIF_OP_ULDSB; op <= DIF_OP_ULDX; op++) {
        host_reads = guest_reads = 0;
        dtrace_reg_t result = run(op, 0, NULL, (uintptr_t)&value, 1, &flags);
        assert(result.dttr_value == expected[op]);
        assert(result.dttr_vmhdl == NULL && flags == 0 && host_reads == 1);
        host_reads = guest_reads = 0;
        result = run(op, 1, NULL, 0x1000, 1, &flags);
        assert(result.dttr_value == expected[op] &&
            result.dttr_vmhdl == &guest_handle && flags == 0);
        assert(guest_reads == 1 && host_reads == 0);
        result = run(op, 1, &guest_handle, 0x1000, 1, &flags);
        assert(result.dttr_value == expected[op] &&
            result.dttr_vmhdl == &guest_handle && flags == 0);
        host_reads = guest_reads = 0;
        result = run(op, 1, &other_handle, 0x1000, 1, &flags);
        assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL);
        assert(flags == CPU_DTRACE_ILLOP && guest_reads == 0 && host_reads == 0);
        result = run(op, 1, NULL, 0x1000, 0, &flags);
        assert(result.dttr_value == 0 && flags == CPU_DTRACE_UPRIV);
        assert(guest_reads == 0);
        result = run(op, 0, &guest_handle, 0x1000, 1, &flags);
        assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL);
        assert(flags == CPU_DTRACE_ILLOP && host_reads == 0);
    }
    guest_reads = 0;
    dtrace_reg_t result = run(DIF_OP_ULDX, 1, NULL, 0, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_BADADDR &&
        guest_reads == 0 && cpu_core[0].cpuc_dtrace_illval == 0);
    copy_error = EFAULT;
    result = run(DIF_OP_ULDX, 1, NULL, 0x1000, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_BADADDR &&
        cpu_core[0].cpuc_dtrace_illval == 0x1000);
    copy_error = EOPNOTSUPP;
    result = run(DIF_OP_ULDX, 1, NULL, 0x1000, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_ILLOP);
    copy_error = 0;
    guest_reads = 0;
    result = run(DIF_OP_ULDX, 1, NULL, UINTPTR_MAX - 3, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_BADADDR &&
        guest_reads == 0);
    guest_pid = 0;
    guest_reads = 0;
    result = run(DIF_OP_ULDX, 1, NULL, 0x1000, 1, &flags);
    assert(result.dttr_value == 0 && result.dttr_vmhdl == NULL &&
        flags == CPU_DTRACE_BADADDR && guest_reads == 0 &&
        cpu_core[0].cpuc_dtrace_illval == 0x1000);
    guest_pid = 77;
    guest_args_present = 0;
    result = run(DIF_OP_ULDX, 1, NULL, 0x1000, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_ILLOP &&
        guest_reads == 0);
    guest_args_present = 1;
    hypertrace_guest_user_copyin = NULL;
    result = run(DIF_OP_ULDX, 1, NULL, 0x1000, 1, &flags);
    assert(result.dttr_value == 0 && flags == CPU_DTRACE_ILLOP &&
        guest_reads == 0);
    puts("PASS: guest DIF user loads use guest user-page copy and retain provenance");
    return 0;
}
'''.replace('HELPER', helper).replace('ARMS', arms)
source_file = out / 'guest-userload.c'
source_file.write_text(fixture)
binary = out / 'guest-userload'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(source_file), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
