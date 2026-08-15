/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_MSR_STATE_H_
#define	_VMM_INTEL_VMX_NESTED_MSR_STATE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_msr.h"

struct vmx_nested_capabilities;
struct vmx_nested_guest_arch_state;
struct vmx_nested_guest_control_state;

/*
 * Software-owned L2 MSRs which are not represented by VMCS guest-state
 * fields.  This value-only bank may be snapshotted and rolled back without
 * ever exposing an L1 value to host hardware.
 */
struct vmx_nested_software_msrs {
	uint64_t	star;
	uint64_t	lstar;
	uint64_t	cstar;
	uint64_t	sfmask;
	uint64_t	kgsbase;
	uint64_t	tsc_aux;
};

#define	VMX_NESTED_SOFTWARE_MSR_COUNT	6U

/*
 * Produce the fixed hardware transition list for software-owned guest MSRs.
 * The list uses architectural MSR numbers and is independent of bhyve's
 * private guest_msrs[] indexing.  TSC_AUX is omitted when unavailable.
 */
int	vmx_nested_software_msr_list(
	    const struct vmx_nested_software_msrs *, bool,
	    struct vmx_nested_msr_entry *, uint32_t, uint32_t *);
int	vmx_nested_software_msr_capture(bool,
	    const struct vmx_nested_msr_apply_ops *, void *,
	    struct vmx_nested_software_msrs *);

struct vmx_nested_virtual_msr {
	const struct vmx_nested_capabilities	*capabilities;
	struct vmx_nested_guest_control_state	*control;
	struct vmx_nested_guest_arch_state	*arch;
	struct vmx_nested_software_msrs		*software;
	bool	syscall_available;
	bool	tsc_aux_available;
};

int	vmx_nested_virtual_msr_validate_write(void *, uint32_t, uint64_t,
	    bool);
int	vmx_nested_virtual_msr_validate_read(void *, uint32_t, bool);
int	vmx_nested_virtual_msr_read(void *, uint32_t, uint64_t *);
int	vmx_nested_virtual_msr_write(void *, uint32_t, uint64_t);

const struct vmx_nested_msr_apply_ops *
	vmx_nested_virtual_msr_apply_ops(void);

#endif /* _VMM_INTEL_VMX_NESTED_MSR_STATE_H_ */
