/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EVENT_H_
#define	_VMM_INTEL_VMX_NESTED_EVENT_H_

#include "vmx_nested_types.h"

struct vmx_nested_exit_information;
struct vmx_nested_context;
struct vmx_nested_entry_runtime;
struct vmx_nested_l0_continuation;
struct vmx_nested_l2_portable_state;

enum vmx_nested_event_kind {
	VMX_NESTED_EVENT_EXTERNAL_INTERRUPT = 0,
	VMX_NESTED_EVENT_NMI,
};

enum vmx_nested_event_action {
	VMX_NESTED_EVENT_ACTION_NONE = 0,
	VMX_NESTED_EVENT_ACTION_DEFER,
	VMX_NESTED_EVENT_ACTION_WAIT_FOR_WINDOW,
	VMX_NESTED_EVENT_ACTION_REFLECT_WINDOW,
	VMX_NESTED_EVENT_ACTION_REFLECT_EVENT,
	VMX_NESTED_EVENT_ACTION_INJECT_L2,
};

struct vmx_nested_event_input {
	enum vmx_nested_event_kind kind;
	uint8_t		vector;
	bool pending;
	bool vector_valid;
	bool guest_blocked;
	bool nested_entry_pending;
	bool reinjection_pending;
	bool l1_event_exiting;
	bool l1_window_exiting;
	bool acknowledge_on_exit;
};

struct vmx_nested_event_plan {
	enum vmx_nested_event_kind kind;
	enum vmx_nested_event_action action;
	bool arm_interrupt_window;
	bool arm_nmi_window;
	bool consume_event;
	bool block_nmi;
	bool interruption_info_valid;
	uint8_t vector;
};

enum vmx_nested_mtf_action {
	VMX_NESTED_MTF_NONE = 0,
	VMX_NESTED_MTF_DEFER,
	VMX_NESTED_MTF_DISCARD,
	VMX_NESTED_MTF_REFLECT,
};

enum vmx_nested_debug_event_class {
	VMX_NESTED_DEBUG_NONE = 0,
	VMX_NESTED_DEBUG_FAULT,
	VMX_NESTED_DEBUG_TRAP,
	VMX_NESTED_DEBUG_ICEBP,
	VMX_NESTED_DEBUG_TASK_SWITCH,
};

enum vmx_nested_exception_provenance {
	VMX_NESTED_EXCEPTION_NONE = 0,
	VMX_NESTED_EXCEPTION_FAULT,
	VMX_NESTED_EXCEPTION_TRAP,
	VMX_NESTED_EXCEPTION_ICEBP,
	VMX_NESTED_EXCEPTION_TASK_SWITCH,
	VMX_NESTED_EXCEPTION_LAST,
};

/*
 * Intel-private value copy of the architecture-shared event transaction.
 * This is neither the kernel owner nor a serialized layout.  The hot adapter
 * converts these named values from one coherent vm_intinfo_snapshot before
 * invoking the rootless planner.
 */
struct vmx_nested_mtf_event_snapshot {
	uint64_t exitintinfo;
	uint64_t exception;
	enum vmx_nested_exception_provenance exception_class;
	bool valid;
	bool triple_fault;
};

/*
 * Value-only arbitration at an instruction boundary.  The architecture
 * adapter must classify exception sources before calling this helper:
 * fault-like exceptions, ICEBP, and a TSS-T #DB are high priority, while
 * trap-like #DB state is low priority.  The INIT flag means that INIT has
 * passed the nested-entry and reinjection blockers and is being processed
 * while the vCPU is in wait-for-SIPI; wait-for-SIPI by itself is not a reason
 * to discard MTF.  The helper never consumes the owner; REFLECT and DISCARD
 * become mutations only in a later generation-checked commit.
 */
struct vmx_nested_mtf_input {
	bool pending;
	bool nested_entry_pending;
	bool reinjection_pending;
	bool init_processed_in_wait_for_sipi;
	bool high_priority_non_debug_pending;
	enum vmx_nested_debug_event_class debug_event;
};

struct vmx_nested_mtf_plan {
	enum vmx_nested_mtf_action action;
	bool consume_mtf;
};

enum vmx_nested_startup_kind {
	VMX_NESTED_STARTUP_NONE = 0,
	VMX_NESTED_STARTUP_INIT,
	VMX_NESTED_STARTUP_SIPI,
	VMX_NESTED_STARTUP_KIND_LAST,
};

enum vmx_nested_startup_action {
	VMX_NESTED_STARTUP_ACTION_NONE = 0,
	VMX_NESTED_STARTUP_ACTION_APPLY_L0,
	VMX_NESTED_STARTUP_ACTION_REFLECT_L1,
	VMX_NESTED_STARTUP_ACTION_RETAIN_RETRY,
	VMX_NESTED_STARTUP_ACTION_DISCARD,
};

/*
 * Value-only INIT/SIPI arbitration for one exact common startup claim.
 * The caller commits the common claim only after APPLY_L0 or REFLECT_L1 has
 * completed its external side effect.  RETAIN_RETRY keeps the exact claim
 * resident until the frozen target can replan it.
 * DISCARD consumes an architecturally ignored event.  The special INIT-in-WFS
 * result is the only authoritative request to discard a pending MTF owner.
 */
struct vmx_nested_startup_input {
	enum vmx_nested_startup_kind kind;
	uint8_t vector;
	bool active_l2;
	bool vmx_operation;
	bool nested_entry_pending;
	bool continuation_pending;
	bool reinjection_pending;
	bool wait_for_sipi;
	bool mtf_pending;
};

struct vmx_nested_startup_plan {
	enum vmx_nested_startup_kind kind;
	enum vmx_nested_startup_action action;
	uint32_t exit_reason;
	uint64_t exit_qualification;
	uint8_t vector;
	bool active_l2;
	bool consume_claim;
	bool discard_mtf;
};

/*
 * Priority is architectural, not the declaration order used by callers.
 * RESET and machine check remain L0-owned, and hardware-owned TPR-threshold
 * exits are composed separately, so none enter this software arbitration
 * domain.  Intel leaves priority within the external-intervention class
 * implementation-dependent; this interface deliberately chooses a stable
 * SMI, INIT, SIPI order.
 */
enum vmx_nested_pending_event {
	VMX_NESTED_PENDING_SMI		= (1U << 0),
	VMX_NESTED_PENDING_INIT		= (1U << 1),
	VMX_NESTED_PENDING_SIPI		= (1U << 2),
	VMX_NESTED_PENDING_HIGH_EXCEPTION	= (1U << 3),
	VMX_NESTED_PENDING_MTF		= (1U << 4),
	VMX_NESTED_PENDING_LOW_EXCEPTION	= (1U << 5),
	VMX_NESTED_PENDING_PREEMPT_TIMER	= (1U << 6),
	VMX_NESTED_PENDING_NMI_WINDOW	= (1U << 7),
	VMX_NESTED_PENDING_NMI		= (1U << 8),
	VMX_NESTED_PENDING_INTERRUPT_WINDOW	= (1U << 9),
	VMX_NESTED_PENDING_EXTERNAL_INTERRUPT	= (1U << 10),
};

#define	VMX_NESTED_PENDING_ALL					\
	(VMX_NESTED_PENDING_SMI | VMX_NESTED_PENDING_INIT |		\
	 VMX_NESTED_PENDING_SIPI |					\
	 VMX_NESTED_PENDING_HIGH_EXCEPTION | VMX_NESTED_PENDING_MTF |	\
	 VMX_NESTED_PENDING_LOW_EXCEPTION |				\
	 VMX_NESTED_PENDING_PREEMPT_TIMER |				\
	 VMX_NESTED_PENDING_NMI_WINDOW | VMX_NESTED_PENDING_NMI |	\
	 VMX_NESTED_PENDING_INTERRUPT_WINDOW |				\
	 VMX_NESTED_PENDING_EXTERNAL_INTERRUPT)

/*
 * Plan one maskable interrupt or NMI after higher-priority exception/MTF/timer
 * arbitration has completed.  APICv and posted interrupts are deliberately
 * outside this baseline path.
 */
int	vmx_nested_event_plan(const struct vmx_nested_event_input *,
	    struct vmx_nested_event_plan *);
int	vmx_nested_event_plan_validate(
	    const struct vmx_nested_event_plan *);
int	vmx_nested_event_reflected_exit(
	    const struct vmx_nested_event_plan *,
	    struct vmx_nested_exit_information *);
int	vmx_nested_event_window_controls(uint32_t, uint32_t, uint32_t,
	    const struct vmx_nested_event_plan *, uint32_t *);

/*
 * Select, but do not consume, the highest-priority eligible nested event.
 * The caller owns pending state and computes eligibility (including activity
 * state and interruptibility); returning a single bit makes consumption an
 * explicit commit after the corresponding injection or VM exit succeeds.
 */
int	vmx_nested_event_select(uint32_t pending, uint32_t *selected);
int	vmx_nested_mtf_plan(const struct vmx_nested_mtf_input *,
	    struct vmx_nested_mtf_plan *);
int	vmx_nested_mtf_plan_validate(const struct vmx_nested_mtf_plan *);
int	vmx_nested_mtf_input_from_snapshot(
	    const struct vmx_nested_mtf_event_snapshot *, bool, bool, bool,
	    struct vmx_nested_mtf_input *);
int	vmx_nested_startup_plan(const struct vmx_nested_startup_input *,
	    struct vmx_nested_startup_plan *);
int	vmx_nested_startup_plan_validate(
	    const struct vmx_nested_startup_plan *);
/*
 * Derive startup arbitration facts from one frozen target vCPU.  Active L2
 * is accepted only at the detached cold-continuation boundary.  ENTRY_PENDING
 * is a no-entry retry blocker, not evidence that L2 has executed.  The
 * portable-valid flag is the caller's authoritative storage owner; stale
 * bytes in inactive portable storage are ignored and never serialized here.
 */
int	vmx_nested_startup_input_from_frozen_target(
	    enum vmx_nested_startup_kind, uint8_t,
	    const struct vmx_nested_context *,
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_l2_portable_state *, bool,
	    struct vmx_nested_startup_input *);

#endif /* _VMM_INTEL_VMX_NESTED_EVENT_H_ */
