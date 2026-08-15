/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CHECKPOINT_H_
#define	_VMM_INTEL_VMX_NESTED_CHECKPOINT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_state.h"

struct vmx_nested_capabilities;
struct vmx_nested_context;
struct vmx_nested_control_msr_state;
struct vmx_nested_entry_runtime;
struct vmx_nested_field;
struct vmx_nested_l0_continuation;
struct vmx_nested_l2_portable_state;
struct vmx_nested_state;
struct vmx_nested_vmcs12_snapshot;
struct vmx_nested_vmcs_registry;

/*
 * One length-delimited, architecture-defined nested-VMX checkpoint record.
 * The view borrows both sections from the immutable input record.
 */
struct vmx_nested_checkpoint_view {
	struct vmx_nested_state_view state;
	const uint8_t *registry_wire;
	size_t registry_length;
	const uint8_t *l2_wire;
	size_t l2_length;
};

int	vmx_nested_checkpoint_size(const struct vmx_nested_state *,
	    const struct vmx_nested_vmcs_registry *, size_t *);
int	vmx_nested_checkpoint_encode(const struct vmx_nested_state *,
	    const struct vmx_nested_vmcs_registry *, void *, size_t, size_t *);
int	vmx_nested_checkpoint_active_size(const struct vmx_nested_state *,
	    const struct vmx_nested_vmcs_registry *,
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_l2_portable_state *, size_t *);
int	vmx_nested_checkpoint_active_encode(
	    const struct vmx_nested_state *,
	    const struct vmx_nested_vmcs_registry *,
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_l2_portable_state *, void *, size_t,
	    size_t *);
int	vmx_nested_checkpoint_decode(const void *, size_t,
	    struct vmx_nested_checkpoint_view *);
int	vmx_nested_checkpoint_restore(struct vmx_nested_vmcs_registry *,
	    const struct vmx_nested_capabilities *, const void *, size_t,
	    struct vmx_nested_checkpoint_view *);
int	vmx_nested_checkpoint_capture(const struct vmx_nested_context *,
	    const struct vmx_nested_control_msr_state *,
	    const struct vmx_nested_vmcs_registry *, uint32_t,
	    struct vmx_nested_field *, uint32_t, struct vmx_nested_state *);
int	vmx_nested_checkpoint_active_capture(
	    const struct vmx_nested_context *,
	    const struct vmx_nested_control_msr_state *,
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_vmcs_registry *, uint32_t,
	    struct vmx_nested_field *, uint32_t,
	    const struct vmx_nested_field *, uint32_t,
	    struct vmx_nested_state *);
int	vmx_nested_checkpoint_context_restore(struct vmx_nested_context *,
	    struct vmx_nested_control_msr_state *,
	    struct vmx_nested_vmcs_registry *, uint32_t,
	    const struct vmx_nested_checkpoint_view *, bool);
int	vmx_nested_checkpoint_active_context_restore(
	    struct vmx_nested_context *,
	    struct vmx_nested_control_msr_state *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *,
	    struct vmx_nested_vmcs12_snapshot *,
	    struct vmx_nested_vmcs_registry *, uint32_t,
	    const struct vmx_nested_checkpoint_view *, bool);

#endif /* _VMM_INTEL_VMX_NESTED_CHECKPOINT_H_ */
