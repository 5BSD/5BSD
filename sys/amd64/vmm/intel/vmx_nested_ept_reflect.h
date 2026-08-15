/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_REFLECT_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_REFLECT_H_

#include "vmx_nested_ept_handoff.h"
#include "vmx_nested_reflect.h"

/*
 * Convert an L0 EPT02 miss into the prospective L1-visible EPT12 exit.
 * The source is a value-only snapshot of VMCS02 exit information.  The
 * result remains value-only and is not committed to VMCS12 by this helper.
 */
int	vmx_nested_ept_reflection_information(
	    const struct vmx_nested_ept_handoff_result *,
	    const struct vmx_nested_exit_information *,
	    struct vmx_nested_exit_information *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_REFLECT_H_ */
