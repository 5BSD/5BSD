#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile each production VMM guest-user write callback and check its writes."""
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
struct pmap { int locked; };
struct vcpu { int live; void *cookie; };
struct vm_guest_paging { int paging_mode, cpl; unsigned flags; };
struct vm_hdl { struct vcpu *vcpu; struct vm_guest_paging *paging;
    struct pmap *pmap; };
static uint8_t ram[PAGE_SIZE * 2];
static int translations, holds, releases, second_readonly;
static int second_guest_readonly, translation_fault;
static struct pmap vm_pmap = { 1 };
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
#if TEST_ARCH == 3
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
#else
/*
 * amd64 and arm64 write through the probe-context copier, which is tested
 * with real tables elsewhere (pagewalk.py, arm64-hypertrace-copy.py).  This
 * model keeps its contract: translate every page first, then copy all or
 * nothing.
 */
static int
model_copy(struct vcpu *vcpu, struct vm_guest_paging *paging, uint64_t gla,
    void *buffer, size_t length, int prot)
{
    uint64_t gpa[2];
    size_t done, chunk;
    int fault, n;

    assert(prot == VM_PROT_WRITE && length != 0 && length <= PAGE_SIZE);
    for (done = 0, n = 0; done < length; done += chunk, n++) {
        vm_gla2gpa_nofault(vcpu, paging, gla + done, prot, &gpa[n], &fault);
        if (fault || (second_readonly && gpa[n] >= PAGE_SIZE))
            return EFAULT;
        chunk = MIN(length - done, PAGE_SIZE - (gpa[n] & PAGE_MASK));
    }
    for (done = 0, n = 0; done < length; done += chunk, n++) {
        chunk = MIN(length - done, PAGE_SIZE - (gpa[n] & PAGE_MASK));
        memcpy(ram + gpa[n], (uint8_t *)buffer + done, chunk);
    }
    return 0;
}
#if TEST_ARCH == 1
static struct vcpu *current_vcpu;
static int
dtrace_guest_copy(struct vm_guest_paging *paging, uint64_t gla, void *buffer,
    size_t length, int prot)
{
    return model_copy(current_vcpu, paging, gla, buffer, length, prot);
}
#else
static int
dtrace_vmm_guest_copy(void *vcpui, struct vm_guest_paging *paging,
    struct pmap *pmap, uint64_t gla, void *buffer, size_t length, int prot)
{
    assert(pmap == &vm_pmap && pmap->locked);
    return model_copy(vcpui, paging, gla, buffer, length, prot);
}
#endif
#endif
CALLBACK
static void reset(void) {
    memset(ram, 0, sizeof(ram)); translations = holds = releases = 0;
    second_readonly = second_guest_readonly = translation_fault = 0;
}
int main(void) {
    struct vcpu cpu = { .live = 1 };
    struct vm_guest_paging paging = { .paging_mode = 1, .cpl = 0,
        .flags = VM_GP_MMU_ENABLED | VM_GP_M_MASK };
    struct vm_hdl handle = { .vcpu = &cpu, .paging = &paging,
        .pmap = &vm_pmap };
    const uint8_t bytes[8] = { 1,2,3,4,5,6,7,8 };
    cpu.cookie = &cpu;
#if TEST_ARCH == 1
    current_vcpu = &cpu;
#endif
    reset();
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == 0);
    assert(translations == 2);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 8) == 0);
    assert(paging.cpl == 0 &&
        paging.flags == (VM_GP_MMU_ENABLED | VM_GP_M_MASK));
#if TEST_ARCH == 3
    assert(holds == 2 && releases == 2);
    /* The page-hold path writes the first page before the second fails. */
    reset(); second_readonly = 1;
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 2 && holds == 2 && releases == 1);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 4) == 0);
    assert(ram[PAGE_SIZE] == 0);
    reset(); second_guest_readonly = 1;
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 2 && holds == 1 && releases == 1);
    assert(memcmp(ram + PAGE_SIZE - 4, bytes, 4) == 0);
    assert(ram[PAGE_SIZE] == 0);
#else
    /* The probe-context copier writes nothing unless both pages resolve. */
    static const uint8_t zero[8];
    reset(); second_readonly = 1;
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(memcmp(ram + PAGE_SIZE - 4, zero, 8) == 0);
    reset(); second_guest_readonly = 1;
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(memcmp(ram + PAGE_SIZE - 4, zero, 8) == 0);
#endif
    reset(); translation_fault = 1;
    assert(COPYOUT(&handle, 0x1ffc, bytes, 8) == EFAULT);
    assert(translations == 1 && holds == 0);
    reset();
    assert(COPYOUT(&handle, 0, bytes, 8) == EINVAL);
    assert(COPYOUT(&handle, UINT64_MAX - 3, bytes, 8) == EINVAL);
    assert(COPYOUT(&handle, 0x1000, bytes, 9) == EINVAL);
    assert(translations == 0);
#if TEST_ARCH == 1
    paging.paging_mode = PAGING_MODE_FLAT;
    assert(COPYOUT(&handle, 0x1000, bytes, 8) == EOPNOTSUPP);
#elif TEST_ARCH == 2
    paging.flags = 0;
    assert(COPYOUT(&handle, 0x1000, bytes, 8) == EOPNOTSUPP);
#endif
    puts("PASS: guest user write checks translation, bounds and partial writes");
    return 0;
}
'''

# amd64 and arm64 name their probe-context hooks dtrace_; riscv's still holds
# pages and is not probe-context safe.
for arch, number, name in [('amd64', 1, 'dtrace_vmm_guest_user_copyout'),
                           ('arm64', 2, 'dtrace_vmm_guest_user_copyout'),
                           ('riscv', 3, 'vmm_priv_guest_user_copyout')]:
    source = (root / f'sys/{arch}/vmm/vmm.c').read_text()
    marker = '\nstatic int\n' + name + '('
    start = source.index(marker) + 1
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    callback = source[start:end]
    cfile = out / f'guest-write-{arch}.c'
    cfile.write_text(fixture.replace('CALLBACK', callback)
        .replace('COPYOUT', name))
    binary = out / f'guest-write-{arch}'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
        f'-DTEST_ARCH={number}', '-fsanitize=address,undefined', str(cfile),
        '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
