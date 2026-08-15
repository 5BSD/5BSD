/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTINUATION_HANDOFF_H_
#define	_VMM_INTEL_VMX_NESTED_CONTINUATION_HANDOFF_H_

#include "vmx_nested_types.h"

#include "vmx_nested_continuation_types.h"
#include "vmx_nested_vmcs02.h"

enum vmx_nested_continuation_handoff_state {
	VMX_NESTED_CONTINUATION_HANDOFF_IDLE = 0,
	VMX_NESTED_CONTINUATION_HANDOFF_PENDING,
	VMX_NESTED_CONTINUATION_HANDOFF_HANDLING,
	VMX_NESTED_CONTINUATION_HANDOFF_RESOLVED,
};

enum vmx_nested_continuation_handoff_disposition {
	VMX_NESTED_CONTINUATION_RESUME_PREPARED = 0,
	VMX_NESTED_CONTINUATION_REFLECTED,
	VMX_NESTED_CONTINUATION_MTF_REFLECTED,
};

struct vmx_nested_continuation_handoff_request {
	struct vmx_nested_vmcs02_id id;
	uint64_t	exit_sequence;
	uint64_t	portable_generation;
	enum vmx_nested_l0_completion completion;
};

static __inline bool
vmx_nested_continuation_handoff_request_equal(
    const struct vmx_nested_continuation_handoff_request *a,
    const struct vmx_nested_continuation_handoff_request *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(&a->id, &b->id) &&
	    a->exit_sequence == b->exit_sequence &&
	    a->portable_generation == b->portable_generation &&
	    a->completion == b->completion);
}

struct vmx_nested_continuation_handoff_result {
	enum vmx_nested_continuation_handoff_disposition disposition;
};

struct vmx_nested_continuation_handoff {
	struct vmx_nested_continuation_handoff_request request;
	struct vmx_nested_continuation_handoff_result result;
	enum vmx_nested_continuation_handoff_state state;
};

struct vmx_nested_continuation_handoff_ops {
	int	(*handle)(void *,
		    const struct vmx_nested_continuation_handoff_request *,
		    struct vmx_nested_continuation_handoff_result *);
};

struct vmx_nested_l0_continuation;

int	vmx_nested_continuation_handoff_request_build(
	    const struct vmx_nested_l0_continuation *,
	    struct vmx_nested_continuation_handoff_request *);
void	vmx_nested_continuation_handoff_init(
	    struct vmx_nested_continuation_handoff *);
int	vmx_nested_continuation_handoff_publish(
	    struct vmx_nested_continuation_handoff *,
	    const struct vmx_nested_continuation_handoff_request *);
int	vmx_nested_continuation_handoff_handle(
	    struct vmx_nested_continuation_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_continuation_handoff_ops *, void *);
int	vmx_nested_continuation_handoff_take(
	    struct vmx_nested_continuation_handoff *,
	    const struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_continuation_handoff_request *,
	    struct vmx_nested_continuation_handoff_result *);
int	vmx_nested_continuation_handoff_cancel(
	    struct vmx_nested_continuation_handoff *,
	    const struct vmx_nested_vmcs02_id *);

#endif /* _VMM_INTEL_VMX_NESTED_CONTINUATION_HANDOFF_H_ */
