/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_STATE_H_
#define	_VMM_INTEL_VMX_NESTED_STATE_H_

#include "vmx_nested_types.h"

#define	VMX_NESTED_STATE_F_VMXON		0x00000001U
#define	VMX_NESTED_STATE_F_GUEST_MODE		0x00000002U
#define	VMX_NESTED_STATE_F_RUN_PENDING		0x00000004U
#define	VMX_NESTED_STATE_F_MTF_PENDING		0x00000008U
#define	VMX_NESTED_STATE_F_SHADOW_VALID		0x00000010U
#define	VMX_NESTED_STATE_F_PREEMPT_DEADLINE	0x00000020U
#define	VMX_NESTED_STATE_F_CURRENT_LAUNCHED	0x00000040U

#define	VMX_NESTED_STATE_INVALID_GPA	UINT64_MAX
#define	VMX_NESTED_STATE_HEADER_SIZE	96U
#define	VMX_NESTED_STATE_FIELD_SIZE	16U
#define	VMX_NESTED_STATE_MAX_FIELDS	512U
#define	VMX_NESTED_STATE_MAX_SIZE				\
	(VMX_NESTED_STATE_HEADER_SIZE + 2U *			\
	 VMX_NESTED_STATE_MAX_FIELDS * VMX_NESTED_STATE_FIELD_SIZE)

struct vmx_nested_field {
	uint32_t encoding;
	uint8_t width;
	uint64_t value;
};

struct vmx_nested_capabilities;

struct vmx_nested_state {
	uint32_t flags;
	uint64_t vmxon_gpa;
	uint64_t current_vmcs_gpa;
	uint64_t preemption_timer_deadline_ticks;
	uint64_t capability_signature;
	uint64_t schema_signature;
	uint64_t vmx_epoch;
	uint64_t feature_control;
	uint32_t revision_id;
	uint32_t abort_indicator;
	const struct vmx_nested_field *vmcs_fields;
	uint32_t vmcs_field_count;
	const struct vmx_nested_field *shadow_fields;
	uint32_t shadow_field_count;
};

struct vmx_nested_state_view {
	uint32_t flags;
	uint64_t vmxon_gpa;
	uint64_t current_vmcs_gpa;
	uint64_t preemption_timer_deadline_ticks;
	uint64_t capability_signature;
	uint64_t schema_signature;
	uint64_t vmx_epoch;
	uint64_t feature_control;
	uint32_t revision_id;
	uint32_t abort_indicator;
	uint32_t vmcs_field_count;
	uint32_t shadow_field_count;
	const uint8_t *vmcs_wire;
	const uint8_t *shadow_wire;
};

/*
 * The encoder requires non-overlapping source and destination storage.
 * A decoded view borrows its field storage from the input buffer, which must
 * remain immutable and live until the view is no longer used.
 */
int	vmx_nested_state_size(const struct vmx_nested_state *, size_t *);
int	vmx_nested_state_encode(const struct vmx_nested_state *, void *,
	    size_t, size_t *);
int	vmx_nested_state_decode(const void *, size_t,
	    struct vmx_nested_state_view *);
int	vmx_nested_state_view_field(const struct vmx_nested_state_view *, bool,
	    uint32_t, struct vmx_nested_field *);
int	vmx_nested_state_compatible(const struct vmx_nested_state_view *,
	    uint64_t, uint64_t, uint32_t);
int	vmx_nested_state_destination_validate(
	    const struct vmx_nested_state_view *,
	    const struct vmx_nested_capabilities *);

#endif /* _VMM_INTEL_VMX_NESTED_STATE_H_ */
