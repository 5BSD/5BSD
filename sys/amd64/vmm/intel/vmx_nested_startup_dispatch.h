/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_STARTUP_DISPATCH_H_
#define	_VMM_INTEL_VMX_NESTED_STARTUP_DISPATCH_H_

#include <sys/types.h>

#include "vmx_nested_startup_transaction.h"

enum vmx_nested_startup_dispatch_state {
	VMX_NESTED_STARTUP_DISPATCH_EMPTY = 0,
	VMX_NESTED_STARTUP_DISPATCH_CLAIMED,
	VMX_NESTED_STARTUP_DISPATCH_ACTIVE,
	VMX_NESTED_STARTUP_DISPATCH_POISONED,
	VMX_NESTED_STARTUP_DISPATCH_STATE_LAST,
};

enum vmx_nested_startup_dispatch_result {
	VMX_NESTED_STARTUP_DISPATCH_IDLE = 0,
	VMX_NESTED_STARTUP_DISPATCH_RETAINED,
	VMX_NESTED_STARTUP_DISPATCH_CONSUMED,
};

/*
 * Durable, caller-synchronized runtime-only owner for one target vCPU.  Its
 * embedded claim and transaction survive return from an interrupted
 * initiating thread.  The callback table and adapter argument must have
 * stable addresses and immutable function identities for the complete
 * non-empty lifetime.  The complete callback table is required before claim
 * acquisition so every retained state always has a check, abort, and finish
 * path.  A compound side-effect and release operation executes through one
 * captured callback snapshot, so corruption cannot redirect its second call.
 * None of these values is serialized or exposed to a guest or management
 * process.
 */
struct vmx_nested_startup_dispatch {
	struct vmm_startup_event_claim claim;
	struct vmx_nested_startup_transaction transaction;
	uintptr_t storage_cookie;
	uintptr_t ops_cookie;
	uintptr_t arg_cookie;
	enum vmx_nested_startup_dispatch_state state;
};

struct vmx_nested_startup_dispatch_ops {
	int	(*claim_begin)(void *, struct vmm_startup_event_claim *);
	int	(*claim_check)(void *, const struct vmm_startup_event_claim *);
	int	(*claim_abort)(void *, struct vmm_startup_event_claim *);
	int	(*derive)(void *, const struct vmm_startup_event_claim *,
	    struct vmx_nested_startup_input *);
	struct vmx_nested_startup_transaction_ops transaction;
};

void	vmx_nested_startup_dispatch_init(
	    struct vmx_nested_startup_dispatch *);
int	vmx_nested_startup_dispatch_validate(
	    const struct vmx_nested_startup_dispatch *);
int	vmx_nested_startup_dispatch_step(
	    struct vmx_nested_startup_dispatch *,
	    const struct vmx_nested_startup_dispatch_ops *, void *,
	    enum vmx_nested_startup_dispatch_result *);
int	vmx_nested_startup_dispatch_cleanup(
	    struct vmx_nested_startup_dispatch *,
	    const struct vmx_nested_startup_dispatch_ops *, void *);
int	vmx_nested_startup_dispatch_cleanup_check(
	    const struct vmx_nested_startup_dispatch *,
	    const struct vmx_nested_startup_dispatch_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_STARTUP_DISPATCH_H_ */
