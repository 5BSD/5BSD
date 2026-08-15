/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS02_LEASE_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS02_LEASE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_entry.h"
#include "vmx_nested_vmcs02_bind.h"

enum vmx_nested_vmcs02_lease_kind {
	VMX_NESTED_VMCS02_LEASE_VIRTUAL_APIC = 1,
	VMX_NESTED_VMCS02_LEASE_APIC_ACCESS,
	VMX_NESTED_VMCS02_LEASE_POSTED_INTERRUPT,
};

/*
 * A lease converts an L1 guest-physical resource into an L0-controlled
 * hardware address whose lifetime is bounded by one frozen VMCS02 resource
 * generation.  cookie is opaque to the common layer and is never saved.
 */
struct vmx_nested_vmcs02_lease {
	enum vmx_nested_vmcs02_lease_kind kind;
	uint64_t	guest_address;
	uint64_t	host_address;
	uint64_t	length;
	uint64_t	alignment;
	uintptr_t	cookie;
};

struct vmx_nested_vmcs02_lease_ops {
	/*
	 * Calls run only in a fallible frozen-vCPU preparation or release
	 * transaction and may enter guest-page mapping code.  They must never
	 * run from an irreversible finalizer or retain any argument.  The
	 * transaction snapshots this table before the first call and overwrites
	 * callback-side owner mutation at its commit or rollback boundary.
	 */
	int	(*acquire)(void *, enum vmx_nested_vmcs02_lease_kind,
		    uint64_t, uint64_t, uint64_t,
		    struct vmx_nested_vmcs02_lease *);
	/*
	 * Releasing a successfully acquired lease must not fail.  Providers
	 * defer any fallible teardown until after the mapping is no longer
	 * hardware-visible.
	 */
	void	(*release)(void *, const struct vmx_nested_vmcs02_lease *);
};

struct vmx_nested_vmcs02_lease_owner {
	struct vmx_nested_vmcs02_id id;
	uint64_t	next_generation;
	uint64_t	active_generation;
	struct vmx_nested_vmcs02_lease lease[3];
	uint32_t	count;
	bool		active;
	bool		callback_active;
};

void	vmx_nested_vmcs02_lease_owner_init(
	    struct vmx_nested_vmcs02_lease_owner *);
int	vmx_nested_vmcs02_lease_owner_validate(
	    const struct vmx_nested_vmcs02_lease_owner *);
int	vmx_nested_vmcs02_lease_acquire(
	    struct vmx_nested_vmcs02_lease_owner *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_entry_controls *,
	    const struct vmx_nested_vmcs02_lease_ops *, void *,
	    const struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_vmcs02_resources *);
int	vmx_nested_vmcs02_lease_release(
	    struct vmx_nested_vmcs02_lease_owner *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    const struct vmx_nested_vmcs02_lease_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS02_LEASE_H_ */
