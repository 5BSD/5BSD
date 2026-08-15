/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#endif

#include <machine/vmm.h>

#include "../../dev/vmm/vmm_address_range.h"

#include "vmm_event_state.h"
#include "vmm_intinfo.h"

bool
vmm_event_range_valid(const void *base, size_t length)
{

	return (vmm_address_range_valid(base, length));
}

bool
vmm_event_ranges_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{

	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

int
vmm_event_state_exception_intinfo(const struct vmm_event_state *state,
    uint64_t *intinfop)
{
	uint64_t intinfo;

	if (state == NULL || intinfop == NULL ||
	    (state->flags & ~VMM_EVENT_STATE_F_VALID) != 0)
		return (EINVAL);
	intinfo = 0;
	if ((state->flags & VMM_EVENT_STATE_F_EXCEPTION_PENDING) != 0) {
		if (state->exception_vector >= 32 ||
		    state->exception_vector == 8 ||
		    state->exception_class <= VMM_EVENT_EXCEPTION_NONE ||
		    state->exception_class >= VMM_EVENT_EXCEPTION_CLASS_LAST ||
		    ((state->exception_class == VMM_EVENT_EXCEPTION_ICEBP ||
		    state->exception_class == VMM_EVENT_EXCEPTION_TASK_SWITCH) &&
		    state->exception_vector != 1))
			return (EINVAL);
		intinfo = VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION |
		    state->exception_vector;
		if ((state->flags & VMM_EVENT_STATE_F_EXCEPTION_ERROR) != 0) {
			intinfo |= VM_INTINFO_DEL_ERRCODE;
			intinfo |= (uint64_t)state->exception_error << 32;
		} else if (state->exception_error != 0) {
			return (EINVAL);
		}
	} else if ((state->flags & VMM_EVENT_STATE_F_EXCEPTION_ERROR) != 0 ||
	    state->exception_vector != 0 || state->exception_error != 0 ||
	    state->exception_class != VMM_EVENT_EXCEPTION_NONE) {
		return (EINVAL);
	}
	*intinfop = intinfo;
	return (0);
}

int
vmm_event_state_validate(const struct vmm_event_state *state)
{
	struct vm_intinfo_plan plan;
	uint64_t exception;
	int error;

	if (state == NULL)
		return (EINVAL);
	error = vmm_event_state_exception_intinfo(state, &exception);
	if (error != 0)
		return (error);
	return (vm_intinfo_plan(state->exitintinfo, exception, &plan));
}

bool
vmm_event_state_equal(const struct vmm_event_state *left,
    const struct vmm_event_state *right)
{

	if (left == NULL || right == NULL)
		return (false);
	return (left->flags == right->flags &&
	    left->exitintinfo == right->exitintinfo &&
	    left->exception_vector == right->exception_vector &&
	    left->exception_error == right->exception_error &&
	    left->exception_class == right->exception_class);
}

int
vmm_event_capture_commit_validate(uint64_t generation_before,
    uint64_t generation_after, size_t expected, size_t captured)
{

	if (captured != expected)
		return (EINVAL);
	if (generation_before != generation_after)
		return (EAGAIN);
	return (0);
}
