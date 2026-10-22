#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Test the production riscv64 HyperTrace SBI version and probe paths."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
host = (root / 'sys/riscv/vmm/vmm.c').read_text()
guest = (root / 'sys/riscv/include/bhyve_hypercall.h').read_text()
sbi = (root / 'sys/riscv/include/sbi.h').read_text()
abi = (root / 'sys/sys/hypertrace.h').read_text()
pcstack_start = abi.index('static __inline int\nhypertrace_pcstack_valid(')
pcstack_helper = abi[pcstack_start:abi.index('\n}', pcstack_start) + 2]
extension = re.search(r'^#define\s+SBI_EXT_ID_HYPERTRACE\s+(0x[0-9a-fA-F]+)',
                      sbi, re.MULTILINE)
if extension is None or int(extension[1], 16) in (0x08485452, 0x08485453,
                                                 0x08485454):
    raise SystemExit('RISC-V must use a distinct HyperTrace extension ID')
start = host.index('static void\nvm_handle_hypertrace_ecall(')
host_helper = host[start:host.index('\n}', start) + 2]
start = guest.index('static __inline int\nbhyve_hypercalls_enabled(')
guest_helper = guest[start:guest.index('\n}', start) + 2]
fixture = r'''
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SBI_EXT_ID_HYPERTRACE 0x08485455
#define SBI_HYPERTRACE_PROBE 2
#define SBI_HYPERTRACE_QUERY 1
#define SBI_HYPERTRACE_VERSION 5
#define HYPERTRACE_ARGS_WALLTIME_VALID 1ULL
#define HYPERTRACE_STACK_MAX_FRAMES 64U
#define SBI_SUCCESS 0
#define SBI_ERR_NOT_SUPPORTED -2
#define SBI_ERR_INVALID_PARAM -3
#define SBI_ERR_INVALID_ADDRESS -5
#define SBI_ERR_DENIED -4
#define VM_REG_GUEST_A0 0
#define VM_REG_GUEST_A1 1
#define KASSERT(test, message) assert(test)
#define SBI_CALL0(ext, fn) sbi_call0((ext), (fn))
typedef int hypertrace_id_t;
typedef struct { uint64_t value; unsigned htr_curcpu;
    unsigned htr_entry; uint64_t htr_stackdepth, htr_caller, htr_vtimestamp;
    uint64_t htr_timestamp, htr_walltimestamp, htr_present;
    uintptr_t *htr_pcstack; uint32_t htr_pcstack_count;
    uint32_t htr_pcstack_reserved;
} hypertrace_args_t;
PCSTACK_HELPER
struct vcpu { unsigned vcpuid; uint64_t a0, a1; };
struct vm_exit { struct { struct { uint64_t args[8]; } ecall; } u; };
struct vm_guest_paging { int unused; };
struct vm_hdl { struct vcpu *vcpu; struct vm_guest_paging *paging;
    uint64_t tid; };
struct sbi_ret { long error, value; };
static unsigned supplied_entry = 1;
static uint64_t supplied_present = HYPERTRACE_ARGS_WALLTIME_VALID;
static uintptr_t *supplied_stack;
static uint32_t supplied_stack_count, supplied_stack_reserved;
static int copy_error, probe_error, copies, fires;
static long extension_present = 1, query_error, query_version = 5;
static int vm_hypertrace_copyin(struct vcpu *vcpu,
    struct vm_guest_paging *paging, uint64_t addr, void *dst, size_t len)
{
    hypertrace_args_t *args = dst;
    assert(vcpu != NULL && paging != NULL && addr == 0x1000 &&
        len == sizeof(*args));
    copies++;
    if (copy_error)
        return -1;
    args->value = 42;
    args->htr_curcpu = 999;
    args->htr_entry = supplied_entry;
    args->htr_stackdepth = 0x77;
    args->htr_caller = 0xbeef;
    args->htr_vtimestamp = 0x12345678;
    args->htr_timestamp = 0x23456789;
    args->htr_walltimestamp = 0x3456789a;
    args->htr_present = supplied_present;
    args->htr_pcstack = supplied_stack;
    args->htr_pcstack_count = supplied_stack_count;
    args->htr_pcstack_reserved = supplied_stack_reserved;
    return 0;
}
static int hypertrace_probe(const void *handle, hypertrace_id_t id,
    hypertrace_args_t *args)
{
    const struct vm_hdl *h = handle;
    assert(id == 7 && args->value == 42 && args->htr_curcpu == 3 &&
        args->htr_entry == 1 && args->htr_stackdepth == 0x77 &&
        args->htr_caller == 0xbeef && args->htr_vtimestamp == 0x12345678 &&
        args->htr_timestamp == 0x23456789 &&
        args->htr_walltimestamp == 0x3456789a &&
        args->htr_present == HYPERTRACE_ARGS_WALLTIME_VALID &&
        h->vcpu->vcpuid == 3 && h->tid == 4);
    fires++;
    return probe_error;
}
static int vm_set_register(struct vcpu *vcpu, int reg, uint64_t value)
{
    if (reg == VM_REG_GUEST_A0) vcpu->a0 = value;
    else if (reg == VM_REG_GUEST_A1) vcpu->a1 = value;
    else assert(0);
    return 0;
}
static long sbi_probe_extension(long id)
{
    assert(id == SBI_EXT_ID_HYPERTRACE);
    return extension_present;
}
static struct sbi_ret sbi_call0(long id, long fn)
{
    assert(id == SBI_EXT_ID_HYPERTRACE && fn == SBI_HYPERTRACE_QUERY);
    return (struct sbi_ret){ query_error, query_version };
}
HOST_HELPER
GUEST_HELPER
int main(void)
{
    struct vcpu vcpu = { .vcpuid = 3 };
    struct vm_exit exit = { 0 };
    assert(bhyve_hypercalls_enabled() == 1);
    query_version = 2;
    assert(bhyve_hypercalls_enabled() == 0);
    query_version = 1;
    assert(bhyve_hypercalls_enabled() == 0);
    query_version = 3;
    assert(bhyve_hypercalls_enabled() == 0);
    query_version = 4;
    assert(bhyve_hypercalls_enabled() == 0);
    query_version = 5;
    query_error = SBI_ERR_NOT_SUPPORTED;
    assert(bhyve_hypercalls_enabled() == 0);
    query_error = 0;
    extension_present = 0;
    assert(bhyve_hypercalls_enabled() == 0);
    extension_present = 1;
    exit.u.ecall.args[6] = SBI_HYPERTRACE_QUERY;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert(vcpu.a0 == SBI_SUCCESS && vcpu.a1 == SBI_HYPERTRACE_VERSION &&
        copies == 0 && fires == 0);
    exit.u.ecall.args[6] = SBI_HYPERTRACE_PROBE;
    exit.u.ecall.args[0] = 7;
    exit.u.ecall.args[1] = 0x1000;
    exit.u.ecall.args[2] = 4;
    supplied_entry = 2;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_PARAM && vcpu.a1 == 0 &&
        copies == 1 && fires == 0);
    supplied_entry = 1;
    supplied_present = 2;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_PARAM &&
        copies == 2 && fires == 0);
    supplied_present = HYPERTRACE_ARGS_WALLTIME_VALID;
    supplied_stack_count = HYPERTRACE_STACK_MAX_FRAMES + 1;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_PARAM &&
        copies == 3 && fires == 0);
    supplied_stack_count = 0;
    supplied_stack_reserved = 1;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_PARAM &&
        copies == 4 && fires == 0);
    supplied_stack_reserved = 0;
    supplied_stack = (uintptr_t *)(UINTPTR_MAX - 7);
    supplied_stack_count = 2;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_PARAM &&
        copies == 5 && fires == 0);
    supplied_stack = 0;
    supplied_stack_count = 0;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert(vcpu.a0 == SBI_SUCCESS && vcpu.a1 == 0 &&
        copies == 6 && fires == 1);
    copy_error = 1;
    vm_handle_hypertrace_ecall(&vcpu, &exit);
    assert((int64_t)vcpu.a0 == SBI_ERR_INVALID_ADDRESS &&
        copies == 7 && fires == 1);
    puts("PASS: riscv64 SBI version, entry validation, and probe dispatch");
    return 0;
}
'''.replace('HOST_HELPER', host_helper).replace('GUEST_HELPER', guest_helper)
fixture = fixture.replace('PCSTACK_HELPER', pcstack_helper)
fixture = fixture.replace('0x08485455', extension[1], 1)
path = out / 'riscv-version.c'
path.write_text(fixture)
binary = out / 'riscv-version'
subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(path), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
