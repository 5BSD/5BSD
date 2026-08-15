/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_INTEL_H_

#include "vmx_nested_entry_environment.h"

struct vmx_vcpu;
struct vmx_nested_entry_event_plan;
struct vmx_nested_l2_portable_state;
struct vmx_nested_vmcs02_capabilities;
struct vmx_nested_vmcs02_resources;
struct vmx_nested_vmcs02_plan;
struct vmx_nested_vmcs02_program;
struct vmx_nested_software_msrs;

/*
 * Capture VMCS01 while the vCPU is frozen and its hardware VMCS is clear.
 * The function leaves the hardware VMCS clear on every return path.
 */
int	vmx_nested_entry_environment_intel_capture(struct vmx_vcpu *,
	    const struct vmx_nested_entry_environment_capture *,
	    struct vmx_nested_entry_environment *,
	    struct vmx_nested_vmcs02_resources *);
/*
 * Capture from an already-current VMCS01 without changing the current-VMCS
 * association.  The caller pins execution in a critical section.  This is
 * the final-entry form used after per-CPU VMCS01 host fields have been
 * refreshed on the CPU that will run VMCS02.
 */
int	vmx_nested_entry_environment_intel_capture_current(struct vmx_vcpu *,
	    const struct vmx_nested_entry_environment_capture *,
	    struct vmx_nested_entry_environment *,
	    struct vmx_nested_vmcs02_resources *);
/*
 * Recompose and encode the retained frozen entry on the final host CPU.
 * VMCS01 must already be current in a critical section.  This operation
 * neither sleeps nor rereads L1 memory, and publishes no output unless the
 * refreshed resources still match the retained generation.
 */
int	vmx_nested_entry_environment_intel_final_program(struct vmx_vcpu *,
	    const struct vmx_nested_entry_event_plan *,
	    struct vmx_nested_entry_environment *,
	    struct vmx_nested_vmcs02_plan *,
	    struct vmx_nested_software_msrs *,
	    struct vmx_nested_vmcs02_program *);
/*
 * Recompose a cold portable L2 image against the destination VMCS01.
 * This refreshes L0 host state, TSC composition, VPID selection, and fixed
 * physical resources without rereading a VMCS12 MSR list.
 */
int	vmx_nested_entry_environment_intel_rebind_portable(
	    struct vmx_vcpu *,
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_vmcs02_capabilities *,
	    struct vmx_nested_entry_environment *,
	    struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_vmcs02_plan *);
/*
 * Refresh a frozen portable rebind from VMCS01 on the final execution CPU.
 * The already-acquired resource generation remains authoritative; every
 * fixed VMCS01 resource is revalidated before outputs are published.
 */
int	vmx_nested_entry_environment_intel_refresh_portable_current(
	    struct vmx_vcpu *,
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_vmcs02_capabilities *,
	    const struct vmx_nested_vmcs02_resources *,
	    struct vmx_nested_entry_environment *,
	    struct vmx_nested_vmcs02_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_INTEL_H_ */
