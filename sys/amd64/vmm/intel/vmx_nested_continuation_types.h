/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTINUATION_TYPES_H_
#define	_VMM_INTEL_VMX_NESTED_CONTINUATION_TYPES_H_

/*
 * Value-only completion selected for an L0-owned nested exit.  This lives
 * outside the continuation state-machine header so frozen internal handoffs
 * do not depend on the context that owns those handoffs.
 */
enum vmx_nested_l0_completion {
	VMX_NESTED_L0_COMPLETE_RESUME_L2 = 0,
	VMX_NESTED_L0_COMPLETE_REFLECT_L1,
};

#endif /* _VMM_INTEL_VMX_NESTED_CONTINUATION_TYPES_H_ */
