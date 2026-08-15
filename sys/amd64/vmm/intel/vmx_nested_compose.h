/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_COMPOSE_H_
#define	_VMM_INTEL_VMX_NESTED_COMPOSE_H_

#include "vmx_nested_types.h"

/*
 * Every control bit has exactly one composition class.  L0-owned bits come
 * only from the outer VMM, L1-owned bits come only from VMCS12, and merged
 * bits are the union of both requests.  For emulated bits, L1's architectural
 * effect is implemented in software while L0's setting is still forwarded
 * to VMCS02.  The latter distinction is essential for VM-entry and VM-exit
 * controls: L1's operation is emulated even when L0 needs the identically
 * numbered hardware control for its own transition.
 */
struct vmx_nested_control_policy {
	uint32_t	l0_owned;
	uint32_t	l1_owned;
	uint32_t	merged;
	uint32_t	emulated;
};

struct vmx_nested_vmcs02_controls {
	uint32_t	pinbased;
	uint32_t	primary;
	uint32_t	secondary;
	uint32_t	vmexit;
	uint32_t	vmentry;
};

struct vmx_nested_vmcs02_policy {
	struct vmx_nested_control_policy	pinbased;
	struct vmx_nested_control_policy	primary;
	struct vmx_nested_control_policy	secondary;
	struct vmx_nested_control_policy	vmexit;
	struct vmx_nested_control_policy	vmentry;
};

struct vmx_nested_vmcs02_capabilities {
	uint64_t	pinbased;
	uint64_t	primary;
	uint64_t	secondary;
	uint64_t	vmexit;
	uint64_t	vmentry;
};

bool	vmx_nested_control_policy_valid(
	    const struct vmx_nested_control_policy *);
int	vmx_nested_control_policy_validate(
	    const struct vmx_nested_control_policy *, uint64_t, uint64_t);
int	vmx_nested_vmcs02_policy_validate(
	    const struct vmx_nested_vmcs02_policy *,
	    const struct vmx_nested_vmcs02_capabilities *,
	    const struct vmx_nested_vmcs02_capabilities *);
/*
 * Construct the conservative production policy.  Execution controls are
 * merged because either level may require an exit.  VM-exit and VM-entry
 * controls requested by L1 are emulated around the L2 transition; VMCS02
 * retains only L0's controls.
 */
int	vmx_nested_vmcs02_policy_build(
	    const struct vmx_nested_vmcs02_capabilities *,
	    const struct vmx_nested_vmcs02_capabilities *,
	    struct vmx_nested_vmcs02_policy *);
int	vmx_nested_control_compose(uint32_t, uint32_t,
	    const struct vmx_nested_control_policy *, uint64_t, uint32_t *);
int	vmx_nested_vmcs02_controls_compose(
	    const struct vmx_nested_vmcs02_controls *,
	    const struct vmx_nested_vmcs02_controls *,
	    const struct vmx_nested_vmcs02_policy *,
	    const struct vmx_nested_vmcs02_capabilities *,
	    struct vmx_nested_vmcs02_controls *);

#endif /* _VMM_INTEL_VMX_NESTED_COMPOSE_H_ */
