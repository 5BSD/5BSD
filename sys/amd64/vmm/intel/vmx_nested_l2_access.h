/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_ACCESS_H_
#define	_VMM_INTEL_VMX_NESTED_L2_ACCESS_H_

#include <sys/types.h>

#include "vmx_nested_l2_portable.h"

/*
 * Value-only accessors for an L2 image while no hardware VMCS is current.
 * These identifiers deliberately do not reuse bhyve's VM_REG_* ABI: the
 * portable state model remains independent of one host VMM interface.
 */
enum vmx_nested_l2_scalar {
	VMX_NESTED_L2_CR0 = 0,
	VMX_NESTED_L2_CR3,
	VMX_NESTED_L2_CR4,
	VMX_NESTED_L2_DR7,
	VMX_NESTED_L2_SYSENTER_CS,
	VMX_NESTED_L2_SYSENTER_ESP,
	VMX_NESTED_L2_SYSENTER_EIP,
	VMX_NESTED_L2_PAT,
	VMX_NESTED_L2_EFER,
	VMX_NESTED_L2_RSP,
	VMX_NESTED_L2_RIP,
	VMX_NESTED_L2_RFLAGS,
	VMX_NESTED_L2_PENDING_DEBUG,
	VMX_NESTED_L2_DEBUGCTL,
	VMX_NESTED_L2_ACTIVITY,
	VMX_NESTED_L2_INTERRUPTIBILITY,
	VMX_NESTED_L2_IN_SMM,
	VMX_NESTED_L2_SCALAR_COUNT,
};

enum vmx_nested_l2_table {
	VMX_NESTED_L2_GDTR = 0,
	VMX_NESTED_L2_IDTR,
	VMX_NESTED_L2_TABLE_COUNT,
};

struct vmx_nested_l2_table_value {
	uint64_t	base;
	uint32_t	limit;
};

int	vmx_nested_l2_scalar_get(
	    const struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_l2_scalar, uint64_t *);
int	vmx_nested_l2_scalar_set(
	    struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_l2_scalar, uint64_t);
int	vmx_nested_l2_segment_get(
	    const struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_guest_segment_id,
	    struct vmx_nested_guest_segment *);
int	vmx_nested_l2_segment_set(
	    struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_guest_segment_id,
	    const struct vmx_nested_guest_segment *);
int	vmx_nested_l2_table_get(
	    const struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_l2_table, struct vmx_nested_l2_table_value *);
int	vmx_nested_l2_table_set(
	    struct vmx_nested_l2_portable_state *,
	    enum vmx_nested_l2_table,
	    const struct vmx_nested_l2_table_value *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_ACCESS_H_ */
