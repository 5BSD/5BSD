/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_TIMER_H_
#define	_VMM_INTEL_VMX_NESTED_TIMER_H_

#include "vmx_nested_types.h"

struct vmx_nested_timer_state {
	/* Units are L1 virtual-TSC ticks after the IA32_VMX_MISC shift. */
	uint64_t	deadline_ticks;
	uint32_t	remaining;
	bool		armed;
	bool		expired;
};

struct vmx_nested_timer_exit_input {
	uint64_t	l1_virtual_tsc;
	uint64_t	deadline_ticks;
	uint8_t		rate;
	bool		save_value;
	bool		timer_expired_exit;
};

struct vmx_nested_timer_exit_plan {
	bool		write_value;
	bool		expired;
	uint32_t	value;
};

/*
 * Validate the canonical software representation.  An enabled timer may be
 * either prepared (unarmed, before the final entry boundary) or armed.  A
 * disabled timer is represented entirely by zeroes.  Once enabled, a zero
 * remaining value and expiration are equivalent so freeze/thaw cannot
 * change an ambiguous zero into an expired timer.
 */
int	vmx_nested_timer_state_validate(
	    const struct vmx_nested_timer_state *, bool);
int	vmx_nested_timer_prepare(uint32_t,
	    struct vmx_nested_timer_state *);
int	vmx_nested_timer_start(uint64_t, uint8_t, uint32_t,
	    struct vmx_nested_timer_state *);
int	vmx_nested_timer_remaining(uint64_t, uint8_t, uint64_t,
	    struct vmx_nested_timer_state *);
int	vmx_nested_timer_exit(const struct vmx_nested_timer_exit_input *,
	    struct vmx_nested_timer_exit_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_TIMER_H_ */
