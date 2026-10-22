#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise bounded amd64 guest scalar and trapframe copies across held pages."""
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
production = extract('vmm_priv_guest_copyin') + '\n' + extract('vmm_priv_guest_user_copyin')
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
static int translations, holds, releases, deny_second, deny_hold;
static int deny_hold_second;
static int require_user;
static int vm_gla2gpa_nofault(struct vcpu *vcpu,
    struct vm_guest_paging *paging, uint64_t gla, int prot,
    uint64_t *gpa, int *fault)
{
    assert(vcpu != NULL && paging != NULL && prot == VM_PROT_READ);
    ++translations;
    if (require_user && paging->cpl != 3) {
        *fault = 1;
        return 0;
    }
    if (gla < 0x1000 || gla >= 0x1000 + sizeof(guest)) {
        *fault = 1;
        return 0;
    }
    *gpa = gla - 0x1000;
    *fault = deny_second && *gpa >= PAGE_SIZE;
    return 0;
}
static void *vm_gpa_hold(struct vcpu *vcpu, uint64_t gpa, size_t length,
    int prot, void **cookie)
{
    assert(vcpu != NULL && prot == VM_PROT_READ);
    assert(length != 0 && length <= PAGE_SIZE - (gpa & PAGE_MASK));
    ++holds;
    if (deny_hold || (deny_hold_second && gpa >= PAGE_SIZE)) return NULL;
    *cookie = guest;
    return guest + gpa;
}
static void vm_gpa_release(void *cookie)
{
    assert(cookie == guest);
    ++releases;
}
PRODUCTION
int main(void)
{
    struct vcpu vcpu = {0};
    struct vm_guest_paging paging = { .paging_mode = PAGING_MODE_64 };
    struct vm_hdl handle = {&vcpu, &paging};
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(guest); ++i) guest[i] = (uint8_t)i;
    assert(vmm_priv_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == 0);
    assert(value == UINT64_C(0x0403020100fffefd));
    assert(translations == 2 && holds == 2 && releases == 2);
    deny_second = 1;

    value = UINT64_C(0xfeedface12345678);
    assert(vmm_priv_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == EFAULT);
    assert(value == UINT64_C(0xfeedface12345678));
    assert(translations == 4 && holds == 3 && releases == 3);
    deny_second = 0;
    deny_hold_second = 1;
    assert(vmm_priv_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == EFAULT);
    assert(value == UINT64_C(0xfeedface12345678));
    assert(holds == 5 && releases == 4);
    deny_hold_second = 0;
    deny_hold = 1;
    assert(vmm_priv_guest_copyin(&handle, 0x1000, &value, 1) == EFAULT);
    assert(value == UINT64_C(0xfeedface12345678));
    assert(holds == 6 && releases == 4);
    assert(vmm_priv_guest_copyin(&handle, UINT64_MAX - 3, &value, 8) ==
        EINVAL);
    assert(vmm_priv_guest_copyin(&handle, 0x1000, &value,
        sizeof(struct trapframe) + 1) == EINVAL);
    assert(vmm_priv_guest_copyin(NULL, 0x1000, &value, 1) == EINVAL);
    deny_hold = 0;
    struct trapframe frame = {{0}};
    assert(vmm_priv_guest_copyin(&handle, 0x1000 + PAGE_SIZE - 16,
        &frame, sizeof(frame)) == 0);
    assert(memcmp(&frame, guest + PAGE_SIZE - 16, sizeof(frame)) == 0);
    require_user = 1;
    assert(vmm_priv_guest_user_copyin(&handle, 0x1000 + PAGE_SIZE - 3,
        &value, 8) == 0);
    assert(value == UINT64_C(0x0403020100fffefd));
    assert(paging.cpl == 0);
    assert(vmm_priv_guest_user_copyin(&handle, 0x1000, &value, 9) == EINVAL);
    paging.paging_mode = PAGING_MODE_FLAT;
    assert(vmm_priv_guest_user_copyin(&handle, 0x1000, &value, 1) ==
        EOPNOTSUPP);
    puts("PASS: amd64 guest scalar/trapframe pages held and released exactly");
}
'''.replace('PRODUCTION', production)
cfile = out / 'guest-amd64-copy.c'
cfile.write_text(fixture)
binary = out / 'guest-amd64-copy'
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', str(cfile), '-o', str(binary)], check=True)
subprocess.run([str(binary)], check=True, timeout=30)
