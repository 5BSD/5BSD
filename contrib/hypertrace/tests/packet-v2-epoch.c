/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define HYPERTRACE_MAX_VMS 1024
#define KASSERT(expr, message) assert(expr)
#define atomic_load_acq_64(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define atomic_store_rel_64(ptr, value) \
    __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
static volatile uint64_t mbufid_v2_vm_epochs[HYPERTRACE_MAX_VMS];
#include "packet-v2-epoch.inc"

int
main(void)
{
    const uint64_t old = UINT64_C(0x128900ab), next = UINT64_C(0x765432cd);

    assert(!mbufid_v2_vm_epoch_current(0, old));
    assert(!mbufid_v2_vm_epoch_current(HYPERTRACE_MAX_VMS, old));
    assert(!mbufid_v2_vm_epoch_current(7, old));
    mbufid_v2_vm_epoch_publish(7, old);
    assert(mbufid_v2_vm_epoch_current(7, old));
    assert(!mbufid_v2_vm_epoch_current(7, next));
    mbufid_v2_vm_epoch_revoke(7, old);
    assert(!mbufid_v2_vm_epoch_current(7, old));
    mbufid_v2_vm_epoch_publish(7, next);
    assert(!mbufid_v2_vm_epoch_current(7, old));
    assert(mbufid_v2_vm_epoch_current(7, next));
    mbufid_v2_vm_epoch_revoke(7, next);
    puts("PASS: published VM epoch, revocation, numeric VMID reuse");
    return (0);
}
