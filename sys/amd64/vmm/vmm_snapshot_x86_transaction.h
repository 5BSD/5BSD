/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _AMD64_VMM_VMM_SNAPSHOT_X86_TRANSACTION_H_
#define	_AMD64_VMM_VMM_SNAPSHOT_X86_TRANSACTION_H_
#include <sys/types.h>
#include <dev/vmm/vmm_snapshot_state.h>
#include "vmm_snapshot_x86_state.h"
struct vmm_snapshot_x86_vcpu_stage {
	uint32_t instance;
	struct vmm_snapshot_vcpu_common common;
	struct vmm_snapshot_vcpu_x86 x86;
	struct vmm_snapshot_vcpu_x86_fpu fpu;
};
struct vmm_snapshot_x86_transaction {
	struct vmm_snapshot_vm_common vm;
	uint32_t vcpu_count;
};
int vmm_snapshot_x86_transaction_size(uint32_t, size_t *);
int vmm_snapshot_x86_transaction_encode(
    const struct vmm_snapshot_x86_transaction *,
    const struct vmm_snapshot_x86_vcpu_stage *, size_t,
    void *, size_t, size_t *);
int vmm_snapshot_x86_transaction_decode(const void *, size_t,
    struct vmm_snapshot_x86_vcpu_stage *, size_t,
    struct vmm_snapshot_x86_transaction *);
int vmm_snapshot_x86_transaction_validate_destination(
    const struct vmm_snapshot_x86_transaction *,
    const struct vmm_snapshot_x86_vcpu_stage *, size_t, uint32_t,
    const uint32_t *, size_t);
int vmm_snapshot_x86_transaction_restore_preflight(
    const struct vmm_snapshot_x86_transaction *,
    const struct vmm_snapshot_x86_vcpu_stage *, size_t, uint32_t,
    const uint32_t *, const uint8_t *, size_t);
#endif
