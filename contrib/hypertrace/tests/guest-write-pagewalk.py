#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile each production VMM guest-user write callback against page holds."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define VM_PROT_WRITE 2
#define PAGING_MODE_FLAT 0
#define VM_GP_MMU_ENABLED 1
#define VM_GP_M_MASK 6
#define VM_GP_HYPERTRACE_USER 8
struct vcpu { int live; };
struct vm_guest_paging { int paging_mode, cpl; unsigned flags; };
struct vm_hdl { struct vcpu *vcpu; struct vm_guest_paging *paging; };
static uint8_t ram[PAGE_SIZE * 2];
static int translations, holds, releases, second_readonly;
static int second_guest_readonly, translation_fault;
static int
vm_gla2gpa_nofault(struct vcpu *vcpu, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *fault)
{
    assert(vcpu != NULL && prot == VM_PROT_WRITE);
#if TEST_ARCH == 1
    assert(paging->cpl == 3);
#elif TEST_ARCH == 2
    assert((paging->flags & VM_GP_M_MASK) == 0);
    assert((paging->flags & VM_GP_MMU_ENABLED) != 0);
#else
    assert((paging->flags & VM_GP_HYPERTRACE_USER) != 0);
#endif
    translations++;
    *fault = translation_fault ||
        (second_guest_readonly && gla >= 0x2000) || gla < 0x1000 ||
        gla >= 0x1000 + sizeof(ram);
    if (!*fault) *gpa = gla - 0x1000;
    return 0;
}
static void *
vm_gpa_hold(struct vcpu *vcpu, uint64_t gpa, size_t length, int prot,
    void **cookie)
{
    assert(vcpu != NULL && prot == VM_PROT_WRITE && cookie != NULL);
    holds++;
    if (gpa >= sizeof(ram) || length > sizeof(ram) - gpa ||
        (second_readonly && gpa >= PAGE_SIZE)) return NULL;
    *cookie = ram + gpa;
    return ram + gpa;
}
static void vm_gpa_release(void *cookie) {
    assert(cookie != NULL); releases++;
}
CALLBACK
static void reset(void) {
    memset(ram, 0, sizeof(ram)); translations = holds = releases = 0;
    second_readonly = second_guest_readonly = translation_fault = 0;
}
int main(void) {
    struct vcpu cpu = { .live = 1 };
    struct vm_guest_paging paging = { .paging_mode = 1, .cpl = 0,
        .flags = VM_GP_MMU_ENABLED | VM_GP_M_MASK };
    struct vm_hdl handle = { .vcpu = &cpu, .paging = &paging };
    const uint8_t bytes[8] = { 1,2,3,4,5,6,7,8 };
    reset();
    assert(vmm_priv_guest_user_copyout(&handle, 0x1ffc, bytes, 8) == 0);
    assert(translations == 2 && holds == 2 && releases == 2);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 8) == 0);
    assert(paging.cpl == 0 &&
        paging.flags == (VM_GP_MMU_ENABLED | VM_GP_M_MASK));
    reset(); second_readonly = 1;
    assert(vmm_priv_guest_user_copyout(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 2 && holds == 2 && releases == 1);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 4) == 0);
    assert(ram[PAGE_SIZE] == 0);
    reset(); second_guest_readonly = 1;
    assert(vmm_priv_guest_user_copyout(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 2 && holds == 1 && releases == 1);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 4) == 0);
    assert(ram[PAGE_SIZE] == 0);
    reset(); translation_fault = 1;
    assert(vmm_priv_guest_user_copyout(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 1 && holds == 0);
    reset();
    assert(vmm_priv_guest_user_copyout(&handle, 0, bytes, 8) == EINVAL);
    assert(vmm_priv_guest_user_copyout(&handle, UINT64_MAX - 3,
        bytes, 8) == EINVAL);
    assert(vmm_priv_guest_user_copyout(&handle, 0x1000, bytes, 9) == EINVAL);
    assert(translations == 0);
#if TEST_ARCH == 1
    paging.paging_mode = PAGING_MODE_FLAT;
    assert(vmm_priv_guest_user_copyout(&handle, 0x1000, bytes, 8) ==
        EOPNOTSUPP);
#elif TEST_ARCH == 2
    paging.flags = 0;
    assert(vmm_priv_guest_user_copyout(&handle, 0x1000, bytes, 8) ==
        EOPNOTSUPP);
#endif
    puts("PASS: guest user write checks translation, page hold and bounds");
    return 0;
}
'''

for arch, number in [('amd64', 1), ('arm64', 2), ('riscv', 3)]:
    source = (root / f'sys/{arch}/vmm/vmm.c').read_text()
    marker = '\nstatic int\nvmm_priv_guest_user_copyout('
    start = source.index(marker) + 1
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    callback = source[start:end]
    cfile = out / f'guest-write-{arch}.c'
    cfile.write_text(fixture.replace('CALLBACK', callback))
    binary = out / f'guest-write-{arch}'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
        f'-DTEST_ARCH={number}', '-fsanitize=address,undefined', str(cfile),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
