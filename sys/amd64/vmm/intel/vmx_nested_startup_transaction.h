/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_STARTUP_TRANSACTION_H_
#define	_VMM_INTEL_VMX_NESTED_STARTUP_TRANSACTION_H_

#include "vmx_nested_types.h"

#include <dev/vmm/vmm_startup_event.h>

#include "vmx_nested_event.h"
#include "vmx_nested_startup_policy.h"

enum vmx_nested_startup_transaction_state {
	VMX_NESTED_STARTUP_TRANSACTION_EMPTY = 0,
	VMX_NESTED_STARTUP_TRANSACTION_PLANNED,
	VMX_NESTED_STARTUP_TRANSACTION_EXECUTING,
	VMX_NESTED_STARTUP_TRANSACTION_RETAINED,
	VMX_NESTED_STARTUP_TRANSACTION_FINISH_PENDING,
	VMX_NESTED_STARTUP_TRANSACTION_RELEASING,
	VMX_NESTED_STARTUP_TRANSACTION_COMPLETE,
	VMX_NESTED_STARTUP_TRANSACTION_POISONED,
	VMX_NESTED_STARTUP_TRANSACTION_STATE_LAST,
};

/*
 * Private, runtime-only contract between the Intel owner inventory and the
 * common L0 INIT/SIPI finalizer.  Keeping the blockers named makes additions
 * to struct vmx_vcpu fail closed: a new owner must be classified before the
 * production adapter can declare the transition infallible.
 */
#define	VMX_NESTED_L0_STARTUP_PREFLIGHT_VERSION	1U
#define	VMX_NESTED_L0_STARTUP_CONTEXT		(UINT64_C(1) << 0)
#define	VMX_NESTED_L0_STARTUP_CONTINUATION	(UINT64_C(1) << 1)
#define	VMX_NESTED_L0_STARTUP_RUNTIME		(UINT64_C(1) << 2)
#define	VMX_NESTED_L0_STARTUP_MTF		(UINT64_C(1) << 3)
#define	VMX_NESTED_L0_STARTUP_THAW		(UINT64_C(1) << 4)
#define	VMX_NESTED_L0_STARTUP_REFREEZE		(UINT64_C(1) << 5)
#define	VMX_NESTED_L0_STARTUP_PORTABLE		(UINT64_C(1) << 6)
#define	VMX_NESTED_L0_STARTUP_VMCS02		(UINT64_C(1) << 7)
#define	VMX_NESTED_L0_STARTUP_EPT		(UINT64_C(1) << 8)
#define	VMX_NESTED_L0_STARTUP_LEASES		(UINT64_C(1) << 9)
#define	VMX_NESTED_L0_STARTUP_WORKSPACE		(UINT64_C(1) << 10)
#define	VMX_NESTED_L0_STARTUP_EXIT_MSR		(UINT64_C(1) << 11)
#define	VMX_NESTED_L0_STARTUP_PREPARED		(UINT64_C(1) << 12)
#define	VMX_NESTED_L0_STARTUP_HARDWARE_MSR	(UINT64_C(1) << 13)
#define	VMX_NESTED_L0_STARTUP_VPID		(UINT64_C(1) << 14)
#define	VMX_NESTED_L0_STARTUP_HOT_FAILURE	(UINT64_C(1) << 15)
#define	VMX_NESTED_L0_STARTUP_VMCS_REGISTRY	(UINT64_C(1) << 16)
#define	VMX_NESTED_L0_STARTUP_BLOCKERS		\
	((UINT64_C(1) << 17) - 1)

struct vmx_nested_l0_startup_preflight {
	uint64_t context_generation;
	uint64_t blockers;
	uint32_t version;
	enum vmx_nested_startup_kind kind;
};

/*
 * Runtime-only binding between one exact common claim and one Intel plan.
 * No pointer or transaction value is serialized or exposed to a guest.
 */
struct vmx_nested_startup_transaction {
	struct vmx_nested_startup_plan plan;
	uint64_t owner_id;
	uint64_t claim_id;
	uintptr_t state_cookie;
	uintptr_t claim_cookie;
	uintptr_t storage_cookie;
	uint32_t vcpuid;
	enum vmx_nested_startup_transaction_state state;
};

struct vmx_nested_startup_transaction_ops {
	/*
	 * Fallible preparation for an L0 operation.  This callback may discard
	 * only destination-local derived runtime state which is explicitly safe
	 * to reconstruct after either success or rejection.  It must not change
	 * architectural state, the common claim, or the transaction.  A retry
	 * must be idempotent.
	 */
	int	(*prepare_l0)(void *, enum vmx_nested_startup_kind, uint8_t);
	/*
	 * Report the architectural boundary and its errno independently.  Only a
	 * COMMITTED/zero or RETRY/positive pair is valid.  FAIL_STOP, an unknown
	 * disposition, or a contradictory pair poisons the durable outer owner.
	 * The callback must always initialize *errorp.
	 */
	enum vmx_nested_startup_machine_disposition
		(*apply_l0)(void *, enum vmx_nested_startup_kind, uint8_t,
		    int *errorp);
	/*
	 * Commit one complete active-L2 decision against the still-frozen
	 * target image.  The callback must revalidate the complete plan before
	 * publishing any nested owner; a partial exit tuple is not sufficient
	 * provenance for reflection or MTF disposal.
	 */
	int	(*commit_active_l2)(void *,
	    const struct vmx_nested_startup_plan *);

	/* Exact common-claim release operations. */
	int	(*claim_finish)(void *, struct vmm_startup_event_claim *);
};

void	vmx_nested_startup_transaction_init(
	    struct vmx_nested_startup_transaction *);
int	vmx_nested_startup_transaction_validate(
	    const struct vmx_nested_startup_transaction *);
bool	vmx_nested_startup_transaction_equal(
	    const struct vmx_nested_startup_transaction *,
	    const struct vmx_nested_startup_transaction *);
int	vmx_nested_l0_startup_preflight_validate(
	    const struct vmx_nested_l0_startup_preflight *);
int	vmx_nested_startup_transaction_begin(
	    struct vmx_nested_startup_transaction *,
	    struct vmm_startup_event_claim *,
	    const struct vmx_nested_startup_input *);
int	vmx_nested_startup_transaction_replan(
	    struct vmx_nested_startup_transaction *,
	    struct vmm_startup_event_claim *,
	    const struct vmx_nested_startup_input *);
int	vmx_nested_startup_transaction_execute(
	    struct vmx_nested_startup_transaction *,
	    struct vmm_startup_event_claim *,
	    const struct vmx_nested_startup_transaction_ops *, void *);
int	vmx_nested_startup_transaction_release(
	    struct vmx_nested_startup_transaction *,
	    struct vmm_startup_event_claim *,
	    const struct vmx_nested_startup_transaction_ops *, void *);
int	vmx_nested_startup_transaction_resolve(
	    struct vmx_nested_startup_transaction *,
	    struct vmm_startup_event_claim *,
	    const struct vmx_nested_startup_transaction_ops *, void *);

#endif /* _VMM_INTEL_VMX_NESTED_STARTUP_TRANSACTION_H_ */
