/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_FIELDS_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_FIELDS_H_

#include <sys/types.h>

#include "vmx_nested_guest.h"

enum vmx_nested_segment_field {
	VMX_NESTED_SEGMENT_SELECTOR = 0,
	VMX_NESTED_SEGMENT_LIMIT,
	VMX_NESTED_SEGMENT_ACCESS,
	VMX_NESTED_SEGMENT_BASE,
};

/*
 * Translate the architecture-neutral segment order to Intel's VMCS field
 * encodings.  Intel orders LDTR before TR; the common model orders TR before
 * LDTR so callers must never derive these encodings arithmetically.
 */
int	vmx_nested_vmcs_segment_encoding(
	    enum vmx_nested_guest_segment_id,
	    enum vmx_nested_segment_field, uint32_t *);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_FIELDS_H_ */
