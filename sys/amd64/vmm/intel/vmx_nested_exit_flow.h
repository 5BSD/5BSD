/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EXIT_FLOW_H_
#define	_VMM_INTEL_VMX_NESTED_EXIT_FLOW_H_

#include <sys/types.h>

#include "vmx_nested_reflect.h"

enum vmx_nested_l0_exit_result {
	VMX_NESTED_L0_EXIT_NOT_RUN = 0,
	VMX_NESTED_L0_EXIT_HANDLED,
	VMX_NESTED_L0_EXIT_USER,
};

enum vmx_nested_exit_flow_action {
	VMX_NESTED_EXIT_FLOW_EPT_WALK = 0,
	VMX_NESTED_EXIT_FLOW_REFLECT,
	VMX_NESTED_EXIT_FLOW_RESUME_HOT,
	VMX_NESTED_EXIT_FLOW_FREEZE_RESUME,
	VMX_NESTED_EXIT_FLOW_FREEZE_REFLECT,
};

struct vmx_nested_exit_flow_input {
	enum vmx_nested_outer_exit_dispatch	dispatch;
	enum vmx_nested_exit_action		route;
	enum vmx_nested_l0_exit_result		l0_result;
};

int	vmx_nested_exit_flow_prepare(
	    const struct vmx_nested_exit_flow_input *,
	    enum vmx_nested_exit_flow_action *);

#endif /* _VMM_INTEL_VMX_NESTED_EXIT_FLOW_H_ */
