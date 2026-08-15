/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_MTF_OWNER_H_
#define	_VMM_INTEL_VMX_NESTED_MTF_OWNER_H_

#include "vmx_nested_types.h"

#include "vmx_nested_l2_portable.h"
#include "vmx_nested_event.h"

/*
 * Runtime owner for a monitor-trap exit after a cold continuation has
 * successfully re-entered L2.  The portable generation names the exact
 * instruction boundary that created the obligation; the VMCS02 identity
 * prevents a later VMCS12 execution from consuming it.  This structure is
 * never serialized directly.  Checkpoint first moves the owner back into a
 * freshly captured, strictly newer portable L2 image.  The owner is a
 * CPU-pinned, single-threaded transaction object; callers must not access it
 * concurrently.
 */
struct vmx_nested_mtf_owner {
	struct vmx_nested_vmcs02_id	id;
	uint64_t			origin_generation;
	bool				pending;
	bool				callback_active;
};

struct vmx_nested_mtf_owner_ops {
	/*
	 * Publication completes synchronously.  The callback must not retain any
	 * argument pointer and, when used by the VM run loop, must not sleep.
	 * Returning zero is the sole signal that the immutable exit was published.
	 */
	int	(*publish)(void *, const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_exit_information *);
};

void	vmx_nested_mtf_owner_init(struct vmx_nested_mtf_owner *);
int	vmx_nested_mtf_owner_validate(
	    const struct vmx_nested_mtf_owner *);
int	vmx_nested_mtf_owner_take_portable(
	    struct vmx_nested_mtf_owner *,
	    struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_vmcs02_plan *, uint64_t);
int	vmx_nested_mtf_owner_put_portable(
	    struct vmx_nested_mtf_owner *,
	    struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_vmcs02_plan *);
int	vmx_nested_mtf_owner_peek(
	    const struct vmx_nested_mtf_owner *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    struct vmx_nested_exit_information *);
int	vmx_nested_mtf_owner_consume(struct vmx_nested_mtf_owner *,
	    const struct vmx_nested_vmcs02_id *, uint64_t);
int	vmx_nested_mtf_owner_reflect(struct vmx_nested_mtf_owner *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    const struct vmx_nested_mtf_owner_ops *, void *);
int	vmx_nested_mtf_owner_resolve(struct vmx_nested_mtf_owner *,
	    const struct vmx_nested_vmcs02_id *, uint64_t,
	    const struct vmx_nested_mtf_plan *,
	    const struct vmx_nested_mtf_owner_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_MTF_OWNER_H_ */
