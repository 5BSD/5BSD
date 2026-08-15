/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_COLD_REFLECT_H_
#define	_VMM_INTEL_VMX_NESTED_COLD_REFLECT_H_

#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_event.h"
#include "vmx_nested_l2_portable.h"

/*
 * Replace a resolved cold-continuation handoff with the immutable VM-exit
 * handoff consumed by the ordinary frozen L1 publication transaction.
 * VMCS02 resources were already released by freeze, so runtime records a
 * distinct resource-free captured state.
 */
int	vmx_nested_cold_reflect_publish(struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l2_portable_state *);

/*
 * Publish a synthetic monitor-trap VM exit after an L0-emulated instruction.
 * This is deliberately distinct from the original continuation's reflected
 * exit: the continuation was RESUME_L2, while MTF arbitration selected a new
 * architectural exit at the completed instruction boundary.  All owners are
 * copied, validated, and advanced transactionally; the pending MTF bit is
 * consumed only with the successful handoff publication.
 */
int	vmx_nested_cold_mtf_reflect_publish(struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *, uint64_t);

/*
 * Commit one consuming startup plan at the exact pending cold RESUME_L2
 * boundary.  REFLECT_L1 atomically replaces the pending continuation with a
 * synthetic nested exit.  DISCARD preserves the continuation and consumes
 * only the generation-bound portable MTF owner requested by the plan.  L0
 * application and common-claim release remain outside this Intel-private
 * helper.
 */
int	vmx_nested_cold_startup_commit(struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_startup_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_COLD_REFLECT_H_ */
