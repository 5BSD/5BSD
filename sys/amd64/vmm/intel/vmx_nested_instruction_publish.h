/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_PUBLISH_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_PUBLISH_H_

#include <sys/types.h>

#include "vmx_nested_context.h"
#include "vmx_nested_instruction_capture.h"

/*
 * Capture one hardware VMX-instruction exit and, when it represents a
 * fault-free operand, bind it to the context's authoritative generation and
 * virtual-machine state.  Architectural exceptions are returned without
 * publishing an internal operation.  Outputs are unchanged on host errors.
 */
int	vmx_nested_instruction_capture_publish(
	    struct vmx_nested_context *,
	    const struct vmx_nested_instruction_capture_input *,
	    struct vmx_nested_instruction_capture_result *,
	    struct vmx_nested_instruction_handoff_id *);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_PUBLISH_H_ */
