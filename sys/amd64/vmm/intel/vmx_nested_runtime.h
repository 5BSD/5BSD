/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_RUNTIME_H_
#define	_VMM_INTEL_VMX_NESTED_RUNTIME_H_

#include <sys/types.h>

/*
 * L1 architectural values which VM entry leaves unchanged when the
 * corresponding VMCS12 load control is clear.  These are captured before
 * switching away from VMCS01.  A nested VM exit computes a new effective L1
 * runtime state according to the VM-exit controls; it does not blindly
 * restore this snapshot.
 */
struct vmx_nested_l1_runtime_state {
	uint64_t	dr7;
	uint64_t	debugctl;
	uint64_t	pat;
	uint64_t	efer;
};

#endif /* _VMM_INTEL_VMX_NESTED_RUNTIME_H_ */
