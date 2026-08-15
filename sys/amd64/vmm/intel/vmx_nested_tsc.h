/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_TSC_H_
#define	_VMM_INTEL_VMX_NESTED_TSC_H_

#include "vmx_nested_types.h"

#include "vmx_nested_timer.h"

#define	VMX_NESTED_TSC_FRAC_BITS	48U
#define	VMX_NESTED_TSC_MULTIPLIER_ONE	(1ULL << \
	    VMX_NESTED_TSC_FRAC_BITS)

struct vmx_nested_tsc_offsets {
	uint64_t l1_offset;
	uint64_t l2_offset;
	bool l2_offset_enabled;
};

struct vmx_nested_tsc_plan {
	uint64_t vmcs02_offset;
	uint64_t vmcs01_offset;
};

struct vmx_nested_tsc_scale_input {
	uint64_t l1_offset;
	uint64_t l1_multiplier;
	uint64_t l2_offset;
	uint64_t l2_multiplier;
	bool l1_scaling_enabled;
	bool l2_offset_enabled;
	bool l2_scaling_enabled;
};

struct vmx_nested_tsc_scale_plan {
	uint64_t vmcs01_offset;
	uint64_t vmcs01_multiplier;
	uint64_t vmcs02_offset;
	uint64_t vmcs02_multiplier;
	bool vmcs01_scaling_enabled;
	bool vmcs02_scaling_enabled;
};

struct vmx_nested_tsc_write_input {
	struct vmx_nested_tsc_scale_input	current;
	struct vmx_nested_timer_state		timer;
	uint64_t				write_host_tsc;
	uint64_t				timer_host_tsc;
	uint64_t				target_tsc;
	uint8_t					timer_rate;
	bool					timer_enabled;
};

struct vmx_nested_tsc_write_plan {
	struct vmx_nested_tsc_scale_input	updated;
	struct vmx_nested_tsc_scale_plan	composed;
	struct vmx_nested_timer_state		timer;
};

/*
 * Compose the architectural, modulo-2^64 TSC offset for VMCS02.  TSC scaling
 * callers use vmx_nested_tsc_scale_plan() when either level enables scaling.
 */
int	vmx_nested_tsc_offset_plan(const struct vmx_nested_tsc_offsets *,
	    struct vmx_nested_tsc_plan *);
uint64_t vmx_nested_tsc_virtual_ticks(uint64_t, uint64_t);
int	vmx_nested_tsc_scale_compose(
	    const struct vmx_nested_tsc_scale_input *,
	    struct vmx_nested_tsc_scale_plan *);
uint64_t vmx_nested_tsc_scaled_ticks(uint64_t, uint64_t, uint64_t);
int	vmx_nested_tsc_write_plan(
	    const struct vmx_nested_tsc_write_input *,
	    struct vmx_nested_tsc_write_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_TSC_H_ */
