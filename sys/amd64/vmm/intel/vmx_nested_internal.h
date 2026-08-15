/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INTERNAL_H_
#define	_VMM_INTEL_VMX_NESTED_INTERNAL_H_

#include "vmx_nested_ept_handoff.h"
#include "vmx_nested_continuation_handoff.h"
#include "vmx_nested_instruction_handoff.h"
#include "vmx_nested_refreeze_types.h"
#include "vmx_nested_vmexit_handoff.h"
#include "vmx_nested_vmentry_handoff.h"

enum vmx_nested_internal_kind {
	VMX_NESTED_INTERNAL_NONE = 0,
	VMX_NESTED_INTERNAL_EPT,
	VMX_NESTED_INTERNAL_INSTRUCTION,
	VMX_NESTED_INTERNAL_VMEXIT,
	VMX_NESTED_INTERNAL_VMENTRY_REJECT,
	VMX_NESTED_INTERNAL_LATE_VMENTRY,
	VMX_NESTED_INTERNAL_CONTINUATION,
	VMX_NESTED_INTERNAL_REFREEZE,
};

struct vmx_nested_internal {
	enum vmx_nested_internal_kind kind;
	union {
		struct vmx_nested_ept_handoff ept;
		struct vmx_nested_instruction_handoff instruction;
		struct vmx_nested_vmexit_handoff vmexit;
		struct vmx_nested_vmentry_handoff vmentry;
		struct vmx_nested_continuation_handoff continuation;
		struct vmx_nested_refreeze_request refreeze;
	} operation;
};

void	vmx_nested_internal_init(struct vmx_nested_internal *);
int	vmx_nested_internal_publish_ept(struct vmx_nested_internal *,
	    const struct vmx_nested_ept_handoff_request *);
int	vmx_nested_internal_publish_instruction(struct vmx_nested_internal *,
	    const struct vmx_nested_instruction_handoff_request *);
int	vmx_nested_internal_publish_vmexit(struct vmx_nested_internal *,
	    const struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_internal_publish_vmentry_reject(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_internal_publish_late_vmentry(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_internal_publish_continuation(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_continuation_handoff_request *);
int	vmx_nested_internal_publish_refreeze(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_refreeze_request *);
int	vmx_nested_internal_handle_ept(struct vmx_nested_internal *,
	    const struct vmx_nested_ept_handoff_id *,
	    const struct vmx_nested_ept_memory *,
	    const struct vmx_nested_ept_handoff_ops *, void *);
int	vmx_nested_internal_handle_instruction(struct vmx_nested_internal *,
	    const struct vmx_nested_instruction_handoff_id *,
	    const struct vmx_nested_instruction_handoff_ops *, void *);
int	vmx_nested_internal_handle_vmexit(struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmexit_handoff_ops *, void *);
int	vmx_nested_internal_handle_vmentry_reject(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmentry_handoff_ops *, void *);
int	vmx_nested_internal_handle_late_vmentry(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmentry_handoff_ops *, void *);
int	vmx_nested_internal_handle_continuation(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_continuation_handoff_ops *, void *);
int	vmx_nested_internal_take_ept(struct vmx_nested_internal *,
	    const struct vmx_nested_ept_handoff_id *,
	    struct vmx_nested_ept_handoff_result *);
int	vmx_nested_internal_take_instruction(struct vmx_nested_internal *,
	    const struct vmx_nested_instruction_handoff_id *,
	    struct vmx_nested_instruction_handoff_result *);
int	vmx_nested_internal_take_vmexit(struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_internal_take_vmentry_reject(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_internal_take_late_vmentry(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_internal_take_continuation(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_continuation_handoff_request *,
	    struct vmx_nested_continuation_handoff_result *);
int	vmx_nested_internal_take_refreeze(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_refreeze_request *);
int	vmx_nested_internal_cancel_ept(struct vmx_nested_internal *,
	    const struct vmx_nested_ept_handoff_id *);
int	vmx_nested_internal_cancel_instruction(struct vmx_nested_internal *,
	    const struct vmx_nested_instruction_handoff_id *);
int	vmx_nested_internal_cancel_vmexit(struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_internal_cancel_vmentry_reject(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_internal_cancel_late_vmentry(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_internal_cancel_continuation(
	    struct vmx_nested_internal *,
	    const struct vmx_nested_vmcs02_id *);

#endif /* _VMM_INTEL_VMX_NESTED_INTERNAL_H_ */
