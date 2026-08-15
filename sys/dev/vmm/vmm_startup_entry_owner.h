/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_ENTRY_OWNER_H_
#define	_DEV_VMM_VMM_STARTUP_ENTRY_OWNER_H_

#include <sys/types.h>

#include <dev/vmm/vmm_startup_event.h>
#include <dev/vmm/vmm_startup_mode.h>

/*
 * Stack-owned value bundle for one future synchronous machine run.  Its two
 * observations intentionally have different capture windows: the
 * notification handoff brackets frozen dispatch, while the coordinator token
 * describes the resulting post-dispatch event state.  No pointer, callback,
 * architecture residency, or portable state belongs here.
 */
struct vmm_startup_entry_owner {
	struct vmm_startup_event_run_token coordinator;
	struct vmm_startup_entry_handoff notification;
	struct vmm_startup_entry_runtime runtime;
	struct vmm_startup_entry_loop loop;
	/*
	 * A non-entering guard may be held here while a private adapter reverses
	 * CPU-local preparation.  This is stack-only common control state; it is
	 * never save state or an adapter-specific result.
	 */
	struct vmm_startup_entry_runtime_result deferred;
	/* A terminal result retained after a real guest entry and before cleanup. */
	struct vmm_startup_entry_loop_result deferred_exit;
	uint8_t deferred_kind;
	uint8_t deferred_reserved8[3];
	uint8_t phase;
	uint8_t armed;
	uint16_t reserved16;
	uint32_t reserved32;
};

enum vmm_startup_entry_owner_deferred_kind {
	VMM_STARTUP_ENTRY_OWNER_DEFERRED_NONE = 0,
	VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY,
	VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY,
	VMM_STARTUP_ENTRY_OWNER_DEFERRED_KIND_LAST,
};

enum vmm_startup_entry_owner_phase {
	VMM_STARTUP_ENTRY_OWNER_BOUND = 0,
	VMM_STARTUP_ENTRY_OWNER_CRITICAL,
	VMM_STARTUP_ENTRY_OWNER_GUEST_FPU,
	VMM_STARTUP_ENTRY_OWNER_RUNNING,
	/* Checked for one hardware attempt, but no guest execution is committed. */
	VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING,
	VMM_STARTUP_ENTRY_OWNER_IN_GUEST,
	VMM_STARTUP_ENTRY_OWNER_RECHECK,
	VMM_STARTUP_ENTRY_OWNER_DEFERRED,
	VMM_STARTUP_ENTRY_OWNER_RETURNABLE,
	VMM_STARTUP_ENTRY_OWNER_REFROZEN,
	VMM_STARTUP_ENTRY_OWNER_HOST_FPU,
	VMM_STARTUP_ENTRY_OWNER_COMPLETE,
	VMM_STARTUP_ENTRY_OWNER_PHASE_LAST,
};

int	vmm_startup_entry_owner_validate(
	    const struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_init(
	    const struct vmm_startup_event_run_token *,
	    const struct vmm_startup_entry_handoff *,
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_admit(
	    const struct vmm_startup_event_run_token *,
	    const struct vmm_startup_entry_admission *,
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_enter_critical(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_restore_guest_fpu(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_publish_running(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_guard_before(
	    struct vmm_startup_entry_owner *, int, int,
	    struct vmm_startup_entry_runtime_result *);
/*
 * Like guard_before, except a replay/error remains DEFERRED until the
 * adapter resolves it after private cleanup.  ENTER_GUEST is committed
 * immediately because it has no deferred result.
 */
int	vmm_startup_entry_owner_guard_before_defer(
	    struct vmm_startup_entry_owner *, int, int,
	    struct vmm_startup_entry_runtime_result *);
/*
 * Like the deferred guard, but retain a successful admission in
 * ENTRY_PENDING until the architecture adapter can prove guest execution.
 */
int	vmm_startup_entry_owner_guard_before_attempt(
	    struct vmm_startup_entry_owner *, int, int,
	    struct vmm_startup_entry_runtime_result *);
int	vmm_startup_entry_owner_commit_attempt(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_abort_attempt(
	    struct vmm_startup_entry_owner *,
	    struct vmm_startup_entry_loop_result *);
/* A conclusively unentered hardware attempt has a terminal adapter error. */
int	vmm_startup_entry_owner_abort_attempt_error(
	    struct vmm_startup_entry_owner *, int,
	    struct vmm_startup_entry_loop_result *);
/* terminal_error is zero to preserve the deferred guard result. */
int	vmm_startup_entry_owner_resolve_deferred(
	    struct vmm_startup_entry_owner *, int,
	    struct vmm_startup_entry_loop_result *);
/*
 * Retain an unhandled post-entry result until private guest-residency cleanup
 * completes.  This intentionally has no result output: only the resolver may
 * publish a returnable result after the private inverse has succeeded.
 * Handled exits continue to use the ordinary one-phase guard.
 */
int	vmm_startup_entry_owner_guard_after_defer(
	    struct vmm_startup_entry_owner *, int);
/* terminal_error is zero to preserve the deferred post-entry result. */
int	vmm_startup_entry_owner_resolve_deferred_after(
	    struct vmm_startup_entry_owner *, int,
	    struct vmm_startup_entry_loop_result *);
int	vmm_startup_entry_owner_guard_after(
	    struct vmm_startup_entry_owner *, bool, int,
	    struct vmm_startup_entry_loop_result *);
int	vmm_startup_entry_owner_software_exit(
	    struct vmm_startup_entry_owner *,
	    struct vmm_startup_entry_loop_result *);
int	vmm_startup_entry_owner_fail_before_entry(
	    struct vmm_startup_entry_owner *, int,
	    struct vmm_startup_entry_loop_result *);
int	vmm_startup_entry_owner_publish_frozen(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_save_guest_fpu(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_exit_critical(
	    struct vmm_startup_entry_owner *);
int	vmm_startup_entry_owner_retire(
	    struct vmm_startup_entry_owner *, int, int,
	    struct vmm_startup_entry_loop_result *);

#endif /* _DEV_VMM_VMM_STARTUP_ENTRY_OWNER_H_ */
