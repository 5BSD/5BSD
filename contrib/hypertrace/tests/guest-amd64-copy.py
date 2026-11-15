#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the amd64 guest scalar and trapframe copy hooks."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'):
    raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/amd64/vmm/vmm.c').read_text()
def extract(name):
    start = source.index('static int\n' + name + '(')
    body = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[body] == '{') - (source[body] == '}')
        body += 1
    return source[start:body]
production = extract('dtrace_vmm_guest_copyin') + '\n' + extract('dtrace_vmm_guest_user_copyin')
fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE - 1)
#define VM_PROT_READ 1
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define PAGING_MODE_FLAT 0
#define PAGING_MODE_64 1
struct vcpu { int unused; };
struct vm_guest_paging { int cpl, paging_mode; };
struct trapframe { uint8_t bytes[32]; };
struct vm_hdl { struct vcpu *vcpu; struct vm_guest_paging *paging; };
static unsigned char guest[2 * PAGE_SIZE];
static int copies, deny_second;
static int require_user;
/*
 * The production copier, dtrace_guest_copy(), is exercised with real page
 * tables by pagewalk.py.  This model keeps its contract: user access needs
 * cpl 3, and nothing is copied unless the whole range translates.
 */
static int dtrace_guest_copy(struct vm_guest_paging *paging, uint64_t gla,
    void *buffer, size_t length, int prot)
{
    assert(paging != NULL && buffer != NULL && prot == VM_PROT_READ);
    assert(length != 0 && length <= PAGE_SIZE);
    ++copies;
    if (require_user && paging->cpl != 3)
        return EFAULT;
    if (gla < 0x1000 || gla - 0x1000 > sizeof(guest) - length)
        return EFAULT;
    if (deny_second && gla - 0x1000 + length > PAGE_SIZE)
        return EFAULT;
    memcpy(buffer, guest + (gla - 0x1000), length);
    return 0;
}
PRODUCTION
int main(void)
{
    struct vcpu vcpu = {0};
    struct vm_guest_paging paging = { .paging_mode = PAGING_MODE_64 };
    struct vm_hdl handle = {&vcpu, &paging};
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(guest); ++i) guest[i] = (uint8_t)i;
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == 0);
    assert(value == UINT64_C(0x0403020100fffefd) && copies == 1);
    deny_second = 1;
    value = UINT64_C(0xfeedface12345678);
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == EFAULT);
    assert(value == UINT64_C(0xfeedface12345678) && copies == 2);
    deny_second = 0;
    assert(dtrace_vmm_guest_copyin(&handle, 0, &value, 1) == EINVAL);
    assert(dtrace_vmm_guest_copyin(&handle, UINT64_MAX - 3, &value, 8) ==
        EINVAL);
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000, &value,
        sizeof(struct trapframe) + 1) == EINVAL);
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000, &value, 0) == EINVAL);
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000, NULL, 1) == EINVAL);
    assert(dtrace_vmm_guest_copyin(NULL, 0x1000, &value, 1) == EINVAL);
    assert(copies == 2);
    struct trapframe frame = {{0}};
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 16,
        &frame, sizeof(frame)) == 0);
    assert(memcmp(&frame, guest + PAGE_SIZE - 16, sizeof(frame)) == 0);
    require_user = 1;
    assert(dtrace_vmm_guest_copyin(&handle, 0x1000, &value, 1) == EFAULT);
    assert(dtrace_vmm_guest_user_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == 0);
    assert(value == UINT64_C(0x0403020100fffefd));
    assert(paging.cpl == 0);
    assert(dtrace_vmm_guest_user_copyin(&handle, 0x1000, &value, 9) == EINVAL);
    paging.paging_mode = PAGING_MODE_FLAT;
    assert(dtrace_vmm_guest_user_copyin(&handle, 0x1000, &value, 1) ==
        EOPNOTSUPP);
    puts("PASS: amd64 guest scalar/trapframe hooks bound and forward copies");
}
'''.replace('PRODUCTION', production)
cfile = out / 'guest-amd64-copy.c'
cfile.write_text(fixture)
binary = out / 'guest-amd64-copy'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
