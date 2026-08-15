/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_INTEL_H_

#include "vmx_nested_compose.h"

int	vmx_nested_control_capabilities_intel_read(
	    struct vmx_nested_vmcs02_capabilities *);

#endif /* _VMM_INTEL_VMX_NESTED_CONTROL_CAPABILITIES_INTEL_H_ */
