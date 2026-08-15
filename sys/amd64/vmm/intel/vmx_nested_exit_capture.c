/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_exit_capture.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state_range.h"

int
vmx_nested_exit_capture(const struct vmx_nested_exit_capture_ops *ops,
    void *arg, struct vmx_nested_exit_information *information)
{
	struct vmx_nested_exit_capture_ops ops_snapshot;
	struct vmx_nested_exit_information candidate;
	uint64_t value;
	int error;

	if (ops == NULL || ops->read == NULL || information == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(information,
	    sizeof(*information), ops, sizeof(*ops)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;

	memset(&candidate, 0, sizeof(candidate));
#define	NVMX_CAPTURE64(field, name) do {					\
	error = ops->read(arg, (name), &candidate.field);		\
	if (error != 0)							\
		return (error);						\
} while (0)
#define	NVMX_CAPTURE32(field, name) do {					\
	error = ops->read(arg, (name), &value);				\
	if (error != 0)							\
		return (error);						\
	if (value > UINT32_MAX)						\
		return (ERANGE);						\
	candidate.field = (uint32_t)value;				\
} while (0)
	NVMX_CAPTURE64(exit_qualification,
	    VMX_NESTED_EXIT_CAPTURE_QUALIFICATION);
	NVMX_CAPTURE64(guest_linear_address,
	    VMX_NESTED_EXIT_CAPTURE_GUEST_LINEAR_ADDRESS);
	NVMX_CAPTURE64(guest_physical_address,
	    VMX_NESTED_EXIT_CAPTURE_GUEST_PHYSICAL_ADDRESS);
	NVMX_CAPTURE32(exit_reason, VMX_NESTED_EXIT_CAPTURE_REASON);
	NVMX_CAPTURE32(exit_interruption_info,
	    VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_INFO);
	NVMX_CAPTURE32(exit_interruption_error,
	    VMX_NESTED_EXIT_CAPTURE_INTERRUPTION_ERROR);
	NVMX_CAPTURE32(idt_vectoring_info,
	    VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_INFO);
	NVMX_CAPTURE32(idt_vectoring_error,
	    VMX_NESTED_EXIT_CAPTURE_IDT_VECTORING_ERROR);
	NVMX_CAPTURE32(exit_instruction_length,
	    VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_LENGTH);
	NVMX_CAPTURE32(exit_instruction_info,
	    VMX_NESTED_EXIT_CAPTURE_INSTRUCTION_INFO);
	NVMX_CAPTURE32(entry_interruption_info,
	    VMX_NESTED_EXIT_CAPTURE_ENTRY_INTERRUPTION_INFO);
#undef NVMX_CAPTURE32
#undef NVMX_CAPTURE64

	*information = candidate;
	return (0);
}
