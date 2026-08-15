/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_state_range.h"
#include "vmx_nested_timer.h"

int
vmx_nested_timer_state_validate(const struct vmx_nested_timer_state *state,
    bool enabled)
{

	if (state == NULL)
		return (EINVAL);
	if (!enabled)
		return (state->deadline_ticks == 0 && state->remaining == 0 &&
		    !state->armed && !state->expired ? 0 : EINVAL);
	if ((!state->armed && state->deadline_ticks != 0) ||
	    state->expired != (state->remaining == 0))
		return (EINVAL);
	return (0);
}

int
vmx_nested_timer_prepare(uint32_t initial_value,
    struct vmx_nested_timer_state *state)
{
	struct vmx_nested_timer_state candidate;

	if (state == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.remaining = initial_value;
	candidate.expired = initial_value == 0;
	*state = candidate;
	return (0);
}

int
vmx_nested_timer_start(uint64_t l1_virtual_tsc, uint8_t rate,
    uint32_t initial_value, struct vmx_nested_timer_state *state)
{
	struct vmx_nested_timer_state candidate;
	uint64_t now;

	if (state == NULL || rate > 31)
		return (EINVAL);
	now = l1_virtual_tsc >> rate;
	memset(&candidate, 0, sizeof(candidate));
	candidate.deadline_ticks = now + initial_value;
	candidate.remaining = initial_value;
	candidate.armed = true;
	candidate.expired = initial_value == 0;
	*state = candidate;
	return (0);
}

int
vmx_nested_timer_remaining(uint64_t l1_virtual_tsc, uint8_t rate,
    uint64_t deadline_ticks, struct vmx_nested_timer_state *state)
{
	struct vmx_nested_timer_state candidate;
	uint64_t delta, now;

	if (state == NULL || rate > 31)
		return (EINVAL);
	now = l1_virtual_tsc >> rate;
	delta = deadline_ticks - now;
	memset(&candidate, 0, sizeof(candidate));
	candidate.deadline_ticks = deadline_ticks;
	candidate.armed = true;
	if (delta > 0xffffffffULL) {
		candidate.remaining = 0;
		candidate.expired = true;
	} else {
		candidate.remaining = (uint32_t)delta;
		candidate.expired = delta == 0;
	}
	*state = candidate;
	return (0);
}

int
vmx_nested_timer_exit(const struct vmx_nested_timer_exit_input *input,
    struct vmx_nested_timer_exit_plan *plan)
{
	struct vmx_nested_timer_exit_plan candidate;
	struct vmx_nested_timer_state state;
	int error;

	if (input == NULL || plan == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(input, sizeof(*input), plan,
	    sizeof(*plan)))
		return (EINVAL);
	error = vmx_nested_timer_remaining(input->l1_virtual_tsc, input->rate,
	    input->deadline_ticks, &state);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	candidate.expired = input->timer_expired_exit || state.expired;
	if (input->save_value) {
		candidate.write_value = true;
		candidate.value = candidate.expired ? 0 : state.remaining;
	}
	*plan = candidate;
	return (0);
}
