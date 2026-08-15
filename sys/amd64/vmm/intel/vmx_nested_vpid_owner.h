/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VPID_OWNER_H_
#define	_VMM_INTEL_VMX_NESTED_VPID_OWNER_H_

#include "vmx_nested_types.h"

/*
 * Intel VPIDs are 16-bit identifiers and translations are local to a logical
 * processor.  amd64 currently supports at most 1024 logical processors, but
 * keep this runtime-only owner independent of the kernel's SMP build option
 * so the value-model tests can exercise migration as well.
 */
#define	VMX_NESTED_VPID_CPU_LIMIT	1024U
#define	VMX_NESTED_VPID_CPU_WORDS	\
	(VMX_NESTED_VPID_CPU_LIMIT / 64U)

/*
 * A VPID02 is destination-local runtime state.  It is deliberately owned for
 * the lifetime of one vCPU instead of one VMCS12 entry.  vmcs01_vpid and
 * effective_vpid are both hardware VPID namespace values and must differ.
 * L1's virtual VPID12 is tracked separately in portable execution state.
 * The host allocator guarantees uniqueness from other vCPUs, and validation
 * retains the VMCS01 inequality as a fail-closed ownership invariant.
 * VPID02 is never serialized.
 */
struct vmx_nested_vpid_owner {
	uint16_t	vmcs01_vpid;
	uint16_t	effective_vpid;
	uint64_t	resident_cpus[VMX_NESTED_VPID_CPU_WORDS];
	bool		active;
	bool		pending_flush;
	bool		callback_active;
};

struct vmx_nested_vpid_owner_ops {
	int	(*allocate)(void *, uint16_t *);
	void	(*release)(void *, uint16_t);
};

void	vmx_nested_vpid_owner_init(struct vmx_nested_vpid_owner *);
int	vmx_nested_vpid_owner_validate(
	    const struct vmx_nested_vpid_owner *);
int	vmx_nested_vpid_restore_destination_validate(
	    const struct vmx_nested_vpid_owner *);
int	vmx_nested_vpid_owner_acquire(struct vmx_nested_vpid_owner *,
	    uint16_t, const struct vmx_nested_vpid_owner_ops *, void *);
int	vmx_nested_vpid_owner_request_flush(struct vmx_nested_vpid_owner *);
bool	vmx_nested_vpid_owner_flush_required(
	    const struct vmx_nested_vpid_owner *);
int	vmx_nested_vpid_owner_flush_required_on_cpu(
	    const struct vmx_nested_vpid_owner *, uint32_t, bool *);
int	vmx_nested_vpid_owner_flush_complete(struct vmx_nested_vpid_owner *);
int	vmx_nested_vpid_owner_flush_complete_on_cpu(
	    struct vmx_nested_vpid_owner *, uint32_t);
int	vmx_nested_vpid_owner_release(struct vmx_nested_vpid_owner *,
	    const struct vmx_nested_vpid_owner_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_VPID_OWNER_H_ */
