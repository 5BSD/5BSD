/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_TSC_AUX_H_
#define	_VMM_INTEL_VMX_NESTED_TSC_AUX_H_

#include <sys/types.h>

/*
 * Runtime-only ownership of the hardware IA32_TSC_AUX value.  PAUSED means
 * that L2 remains the active nested execution, but L1's value is installed
 * while the host handles an L0 exit with interrupts enabled.
 */
enum vmx_nested_tsc_aux_residency {
	VMX_NESTED_TSC_AUX_L1 = 0,
	VMX_NESTED_TSC_AUX_L2,
	VMX_NESTED_TSC_AUX_L2_PAUSED,
};

enum vmx_nested_tsc_aux_guest_bank {
	VMX_NESTED_TSC_AUX_GUEST_L1 = 0,
	VMX_NESTED_TSC_AUX_GUEST_L2,
};

int	vmx_nested_tsc_aux_value_validate(uint64_t);
int	vmx_nested_tsc_aux_guest_bank(
	    enum vmx_nested_tsc_aux_residency,
	    enum vmx_nested_tsc_aux_guest_bank *);
int	vmx_nested_tsc_aux_enter_l2(
	    enum vmx_nested_tsc_aux_residency *);
int	vmx_nested_tsc_aux_pause_l2(
	    enum vmx_nested_tsc_aux_residency *);
int	vmx_nested_tsc_aux_resume_l2(
	    enum vmx_nested_tsc_aux_residency *);
int	vmx_nested_tsc_aux_leave_l2(
	    enum vmx_nested_tsc_aux_residency *,
	    enum vmx_nested_tsc_aux_residency *);
int	vmx_nested_tsc_aux_rollback_leave(
	    enum vmx_nested_tsc_aux_residency *,
	    enum vmx_nested_tsc_aux_residency);
int	vmx_nested_tsc_aux_rollback_enter(
	    enum vmx_nested_tsc_aux_residency *);

#endif /* _VMM_INTEL_VMX_NESTED_TSC_AUX_H_ */
