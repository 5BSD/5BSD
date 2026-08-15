/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_HOT_EXIT_H_
#define	_VMM_INTEL_VMX_NESTED_HOT_EXIT_H_

#include <sys/types.h>

#include "vmx_nested_context.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"

/*
 * Establish and resolve the hot ownership interval around one L0-handled
 * VMCS02 exit.  begin() is transactional: failure leaves the runtime in
 * GUEST and the continuation idle.  resume() is valid only after L0 has
 * completely handled the exit in-kernel.
 */
int	vmx_nested_hot_exit_begin(
	    struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    enum vmx_nested_exit_action);
int	vmx_nested_hot_exit_resume(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_l0_continuation_ops *, void *);
int	vmx_nested_hot_exit_freeze_publish(
	    struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_l0_continuation_ops *, void *);

/*
 * Freeze one userspace-bound L0 exit and publish the exact cold
 * continuation that the next frozen handler must resolve.  The callback
 * owns architecture-specific capture; the coordinator owns all state
 * transitions and publication.
 */
int	vmx_nested_hot_exit_publish(
	    struct vmx_nested_context *,
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    enum vmx_nested_exit_action,
	    const struct vmx_nested_l0_continuation_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_HOT_EXIT_H_ */
