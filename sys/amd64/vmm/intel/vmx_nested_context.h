/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CONTEXT_H_
#define	_VMM_INTEL_VMX_NESTED_CONTEXT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_instruction.h"
#include "vmx_nested_internal.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_vmcs02.h"

enum vmx_nested_context_phase {
	VMX_NESTED_CONTEXT_ROOT = 0,
	VMX_NESTED_CONTEXT_ENTRY_PENDING,
	VMX_NESTED_CONTEXT_GUEST,
	VMX_NESTED_CONTEXT_EXIT_PENDING,
	VMX_NESTED_CONTEXT_ABORTED,
};

enum vmx_nested_internal_dispatch {
	VMX_NESTED_INTERNAL_DISPATCH_HANDLE = 0,
	VMX_NESTED_INTERNAL_DISPATCH_COMMIT,
};

/*
 * Runtime-only origin of a VMLAUNCH/VMRESUME whose preliminary instruction
 * checks succeeded.  Full VM-entry validation may still need to reproduce
 * VMfailValid flags/RIP or synthesize an entry-failure VM exit.
 */
struct vmx_nested_vmentry_origin {
	uint64_t rflags;
	uint8_t instruction_length;
	bool launch;
	bool valid;
};

/*
 * The single owner for per-vCPU nested execution state.  Runtime pointers
 * remain confined to the handoff and commit objects and are never serialized.
 * state_generation fences reset/restore; execution_epoch fences one L2 run.
 */
struct vmx_nested_context {
	struct vmx_nested_machine machine;
	struct vmx_nested_internal internal;
	struct vmx_nested_vmcs02_commit vmcs02;
	uint64_t state_generation;
	uint64_t execution_epoch;
	uint64_t handoff_epoch;
	enum vmx_nested_context_phase phase;
	uint32_t abort_indicator;
	struct vmx_nested_vmentry_origin entry_origin;
};

struct vmx_nested_l0_continuation;

/*
 * Apply the non-memory architectural effects of one completed instruction.
 * The callback must update RFLAGS, RIP, and an optional output register as
 * one all-or-nothing operation.  It must not update context-owned nested
 * machine state.  A nonzero return leaves the resolved handoff consumable for
 * a retry.
 */
struct vmx_nested_instruction_commit_ops {
	int (*commit)(void *,
	    const struct vmx_nested_instruction_handoff_result *);
};

/*
 * Commit one reflected EPT12 exit as a single architectural transition.
 * The callback must update the owned VMCS12 exit fields, save L2 state, and
 * restore L1 runtime state atomically.  A nonzero return leaves both the
 * resolved handoff and the L2 execution phase intact for a frozen-vCPU retry.
 */
struct vmx_nested_ept_reflection_commit_ops {
	int (*commit)(void *, const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_ept_handoff_result *);
};

/*
 * Commit one ordinary nested VM exit.  The callback owns all fallible L1
 * processor and VMCS12 publication work.  A failure leaves EXIT_PENDING so
 * the frozen owner can retry from the same captured L2 state.
 */
struct vmx_nested_vmexit_commit_ops {
	int (*commit)(void *, const struct vmx_nested_vmcs02_id *);
};

/*
 * Publish the VMX-abort indicator before consuming a captured VM exit.
 * The callback must be idempotent: a successful publication followed by an
 * internal take failure can be retried without repeating any preceding
 * VM-exit MSR stores.
 */
struct vmx_nested_vmexit_abort_ops {
	int (*publish)(void *, const struct vmx_nested_vmcs02_id *, uint32_t);
};

struct vmx_nested_vmentry_resolution {
	struct vmx_nested_vmcs02_id id;
	struct vmx_nested_vmentry_origin origin;
	struct vmx_nested_vmentry_result result;
	uint64_t rflags;
	uint8_t rip_advance;
};

/*
 * Commit every L1-visible effect of a rejected full VM entry.  A failure
 * leaves ENTRY_PENDING and the origin intact so the frozen owner can retry
 * without rereading VMCS12 or guest memory.
 */
struct vmx_nested_vmentry_resolution_ops {
	int (*commit)(void *,
	    const struct vmx_nested_vmentry_resolution *);
};

void	vmx_nested_context_init(struct vmx_nested_context *);
int	vmx_nested_context_destroy(struct vmx_nested_context *, bool);
int	vmx_nested_context_quiesce(const struct vmx_nested_context *);
/*
 * Validate the stable architectural half of an active L2 execution.  This
 * does not by itself make GUEST checkpointable; the caller must also prove
 * that the hardware owner is detached and a matching portable image exists.
 */
int	vmx_nested_context_guest_validate(
	    const struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * Validate the only checkpointable active-L2 scheduling boundary: a cold
 * continuation paired with its still-pending, value-only continuation
 * handoff.  The handoff is reconstructed on restore; callback-active or
 * already-resolved handoffs are not portable.
 */
int	vmx_nested_context_guest_continuation_validate(
	    const struct vmx_nested_context *,
	    const struct vmx_nested_l0_continuation *);
int	vmx_nested_context_reset(struct vmx_nested_context *, bool);
int	vmx_nested_context_begin_entry(struct vmx_nested_context *, uint64_t,
	    struct vmx_nested_vmcs02_id *);
int	vmx_nested_context_commit_entry(struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *);
/*
 * Publish successful hardware entry to both ownership state machines only
 * after validating the complete pair.  This avoids a run-loop window where
 * VMCS02 is architecturally launched but the high-level context still says
 * ENTRY_PENDING.
 */
int	vmx_nested_context_commit_hardware_entry(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_context_cancel_entry(struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_context_resolve_vmentry(
	    struct vmx_nested_context *, const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmentry_result *, bool,
	    const struct vmx_nested_vmentry_resolution_ops *, void *,
	    struct vmx_nested_vmentry_resolution *);
int	vmx_nested_context_begin_exit(struct vmx_nested_context *,
	    struct vmx_nested_vmcs02_id *);
int	vmx_nested_context_commit_exit(struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *);
int	vmx_nested_context_commit_vmexit(
	    struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *, bool,
	    const struct vmx_nested_vmexit_commit_ops *, void *);
int	vmx_nested_context_publish_vmexit(
	    struct vmx_nested_context *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_l2_runtime_state *);
/*
 * Atomically publish an immediate, value-only nested exit before any
 * hardware VMCS02 entry.  This performs the successful-entry context
 * transition, the prepared-resource-to-captured runtime transition, and the
 * immutable VM-exit handoff as one candidate-copy transaction.
 */
int	vmx_nested_context_publish_synthetic_vmexit(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_exit_information *,
	    const struct vmx_nested_l2_runtime_state *);
int	vmx_nested_context_commit_published_vmexit(
	    struct vmx_nested_context *, bool,
	    const struct vmx_nested_vmexit_commit_ops *, void *,
	    struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_context_abort_published_vmexit(
	    struct vmx_nested_context *, bool, uint32_t,
	    const struct vmx_nested_vmexit_abort_ops *, void *,
	    struct vmx_nested_vmexit_handoff_request *);
int	vmx_nested_context_abort_published_vmentry(
	    struct vmx_nested_context *, bool, uint32_t,
	    const struct vmx_nested_vmexit_abort_ops *, void *,
	    struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_context_abort(struct vmx_nested_context *, uint32_t);
int	vmx_nested_context_publish_instruction(struct vmx_nested_context *,
	    const struct vmx_nested_instruction_handoff_request *,
	    struct vmx_nested_instruction_handoff_id *);
int	vmx_nested_context_commit_instruction(struct vmx_nested_context *,
	    const struct vmx_nested_instruction_handoff_id *, bool,
	    const struct vmx_nested_instruction_commit_ops *, void *,
	    struct vmx_nested_instruction_handoff_result *);
int	vmx_nested_context_commit_vmentry_instruction(
	    struct vmx_nested_context *,
	    const struct vmx_nested_instruction_handoff_id *, bool,
	    struct vmx_nested_vmcs02_id *,
	    struct vmx_nested_instruction_handoff_result *);
int	vmx_nested_context_cancel_instruction(struct vmx_nested_context *,
	    const struct vmx_nested_instruction_handoff_id *, bool);
int	vmx_nested_context_publish_ept(struct vmx_nested_context *,
	    const struct vmx_nested_ept_handoff_request *,
	    struct vmx_nested_ept_handoff_id *);
int	vmx_nested_context_commit_ept_population(
	    struct vmx_nested_context *,
	    const struct vmx_nested_ept_handoff_id *, bool,
	    struct vmx_nested_ept_handoff_result *);
int	vmx_nested_context_commit_ept_reflection(
	    struct vmx_nested_context *,
	    const struct vmx_nested_ept_handoff_id *, bool,
	    const struct vmx_nested_ept_reflection_commit_ops *, void *,
	    struct vmx_nested_ept_handoff_result *);
int	vmx_nested_context_cancel_ept(struct vmx_nested_context *,
	    const struct vmx_nested_ept_handoff_id *, bool);
int	vmx_nested_context_validate_internal(
	    const struct vmx_nested_context *, bool);
int	vmx_nested_context_internal_dispatch(
	    const struct vmx_nested_context *, bool,
	    enum vmx_nested_internal_dispatch *);

#endif /* _VMM_INTEL_VMX_NESTED_CONTEXT_H_ */
