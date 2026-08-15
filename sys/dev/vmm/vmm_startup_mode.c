/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include <dev/vmm/vmm_startup_mode.h>
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_startup_mode_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left == NULL || right == NULL || left_length == 0 ||
	    right_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

void
vmm_startup_mode_init(struct vmm_startup_mode *mode)
{

	if (mode != NULL)
		memset(mode, 0, sizeof(*mode));
}

int
vmm_startup_mode_validate(const struct vmm_startup_mode *mode)
{

	if (mode == NULL || mode->owner >= VMM_STARTUP_OWNER_LAST ||
	    mode->execution >= VMM_STARTUP_EXECUTION_LAST ||
	    mode->locked > 1 || mode->reserved8 != 0 ||
	    mode->reserved32 != 0)
		return (EINVAL);
	if (mode->locked != 0 &&
	    ((mode->owner == VMM_STARTUP_OWNER_USERSPACE &&
	    mode->execution != VMM_STARTUP_EXECUTION_USERSPACE_RESUME) ||
	    (mode->owner == VMM_STARTUP_OWNER_KERNEL &&
	    mode->execution != VMM_STARTUP_EXECUTION_PRESTARTED_WAIT)))
		return (EINVAL);
	return (0);
}

int
vmm_startup_mode_configure(struct vmm_startup_mode *mode,
    enum vmm_startup_owner owner)
{

	if (vmm_startup_mode_validate(mode) != 0 ||
	    (owner != VMM_STARTUP_OWNER_USERSPACE &&
	    owner != VMM_STARTUP_OWNER_KERNEL))
		return (EINVAL);
	if (mode->locked != 0)
		return (EBUSY);
	mode->owner = owner;
	return (0);
}

int
vmm_startup_mode_configure_execution(struct vmm_startup_mode *mode,
    enum vmm_startup_execution execution)
{

	if (vmm_startup_mode_validate(mode) != 0 ||
	    (execution != VMM_STARTUP_EXECUTION_USERSPACE_RESUME &&
	    execution != VMM_STARTUP_EXECUTION_PRESTARTED_WAIT))
		return (EINVAL);
	if (mode->locked != 0)
		return (EBUSY);
	mode->execution = execution;
	return (0);
}

int
vmm_startup_mode_lock(struct vmm_startup_mode *mode)
{

	if (vmm_startup_mode_validate(mode) != 0)
		return (EINVAL);
	if ((mode->owner == VMM_STARTUP_OWNER_USERSPACE &&
	    mode->execution != VMM_STARTUP_EXECUTION_USERSPACE_RESUME) ||
	    (mode->owner == VMM_STARTUP_OWNER_KERNEL &&
	    mode->execution != VMM_STARTUP_EXECUTION_PRESTARTED_WAIT))
		return (EINVAL);
	mode->locked = 1;
	return (0);
}

int
vmm_startup_action_plan(const struct vmm_startup_mode *mode,
    enum vmm_startup_event_kind kind, bool startup_wait,
    bool bootstrap_processor,
    struct vmm_startup_action_plan *plan)
{
	struct vmm_startup_action_plan candidate;

	if (vmm_startup_mode_validate(mode) != 0 || plan == NULL ||
	    mode->locked == 0 || kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    vmm_startup_mode_overlap(mode, sizeof(*mode), plan,
	    sizeof(*plan)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	if (kind == VMM_STARTUP_EVENT_INIT) {
		candidate.action = mode->owner == VMM_STARTUP_OWNER_KERNEL ?
		    VMM_STARTUP_ACTION_APPLY_KERNEL_INIT :
		    VMM_STARTUP_ACTION_EXIT_USERSPACE_INIT;
		/*
		 * Preserve the historical userspace exit contract.  Under the
		 * complete kernel-owned contract, an AP enters wait-for-SIPI while
		 * the BSP starts executing the bootstrap path after INIT.
		 */
		candidate.startup_wait = mode->owner ==
		    VMM_STARTUP_OWNER_USERSPACE || !bootstrap_processor;
	} else if (!startup_wait) {
		candidate.action = VMM_STARTUP_ACTION_DISCARD_SIPI;
	} else {
		candidate.action = mode->owner == VMM_STARTUP_OWNER_KERNEL ?
		    VMM_STARTUP_ACTION_APPLY_KERNEL_SIPI :
		    VMM_STARTUP_ACTION_EXIT_USERSPACE_SIPI;
		candidate.startup_wait = 0;
	}
	*plan = candidate;
	return (0);
}

int
vmm_startup_delivery_validate(const struct vmm_startup_delivery *delivery)
{

	if (delivery == NULL || delivery->owner >= VMM_STARTUP_OWNER_LAST ||
	    delivery->kernel_publication > 1 || delivery->reserved16 != 0 ||
	    delivery->reserved32 != 0)
		return (EINVAL);
	/*
	 * The kernel route exists only as an atomically published target set;
	 * a userspace route must never carry publication authority.
	 */
	if ((delivery->owner == VMM_STARTUP_OWNER_KERNEL) !=
	    (delivery->kernel_publication != 0))
		return (EINVAL);
	return (0);
}

/*
 * Decide the delivery route for one INIT/SIPI publication without any side
 * effect.  'cancelled' and 'checkpoint_active' are coordinator observations
 * the caller must sample under the coordinator transaction lock; the decision
 * is valid only while that lock remains held.  Routing failures are closed:
 * a caller receiving an error must not fall back to the other route, because
 * the same event could then be delivered through both owners.
 */
int
vmm_startup_delivery_decide(const struct vmm_startup_mode *mode,
    enum vmm_startup_event_kind kind, uint8_t vector, size_t target_count,
    bool cancelled, bool checkpoint_active,
    struct vmm_startup_delivery *delivery)
{
	struct vmm_startup_delivery candidate;

	if (vmm_startup_mode_validate(mode) != 0 || delivery == NULL ||
	    mode->locked == 0 || kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (kind == VMM_STARTUP_EVENT_INIT && vector != 0) ||
	    target_count == 0 ||
	    vmm_startup_mode_overlap(mode, sizeof(*mode), delivery,
	    sizeof(*delivery)))
		return (EINVAL);
	/* A cancelled coordinator admits no further delivery on any route. */
	if (cancelled)
		return (ECANCELED);
	memset(&candidate, 0, sizeof(candidate));
	candidate.owner = mode->owner;
	if (mode->owner == VMM_STARTUP_OWNER_KERNEL) {
		/*
		 * An active coordinator transaction holds the published event
		 * set immutable, so the kernel route cannot publish.  Fail
		 * closed instead of falling back to the historical userspace
		 * exit, which could deliver the same event twice.  The
		 * userspace route publishes nothing and remains unaffected,
		 * preserving the historical exit contract exactly.
		 */
		if (checkpoint_active)
			return (EBUSY);
		candidate.kernel_publication = 1;
	}
	*delivery = candidate;
	return (0);
}

int
vmm_startup_dispatch_plan(enum vmm_startup_dispatch_result result,
    struct vmm_startup_dispatch_plan *plan)
{
	struct vmm_startup_dispatch_plan candidate;

	if (plan == NULL || result < VMM_STARTUP_DISPATCH_IDLE ||
	    result >= VMM_STARTUP_DISPATCH_RESULT_LAST)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	if (result == VMM_STARTUP_DISPATCH_CONSUMED)
		candidate.replay_lifecycle = 1;
	else
		candidate.enter_guest = 1;
	*plan = candidate;
	return (0);
}

int
vmm_startup_entry_snapshot_validate(
    const struct vmm_startup_entry_snapshot *snapshot)
{

	if (snapshot == NULL || snapshot->rendezvous > 1 ||
	    snapshot->suspended > 1 || snapshot->reqidle > 1 ||
	    snapshot->debugged > 1 || snapshot->waiting > 1 ||
	    snapshot->reserved8[0] != 0 || snapshot->reserved8[1] != 0 ||
	    snapshot->reserved8[2] != 0 || snapshot->reserved32 != 0)
		return (EINVAL);
	return (0);
}

int
vmm_startup_entry_pre_dispatch(
    const struct vmm_startup_entry_snapshot *snapshot,
    enum vmm_startup_entry_action *action)
{
	enum vmm_startup_entry_action candidate;

	if (vmm_startup_entry_snapshot_validate(snapshot) != 0 ||
	    action == NULL || vmm_startup_mode_overlap(snapshot,
	    sizeof(*snapshot), action, sizeof(*action)))
		return (EINVAL);
	if (snapshot->rendezvous != 0)
		candidate = VMM_STARTUP_ENTRY_SERVICE_RENDEZVOUS;
	else if (snapshot->suspended != 0)
		candidate = VMM_STARTUP_ENTRY_SERVICE_SUSPEND;
	else if (snapshot->reqidle != 0)
		candidate = VMM_STARTUP_ENTRY_SERVICE_REQIDLE;
	else if (snapshot->debugged != 0)
		candidate = VMM_STARTUP_ENTRY_RETURN_DEBUG;
	else
		candidate = VMM_STARTUP_ENTRY_DISPATCH;
	*action = candidate;
	return (0);
}

int
vmm_startup_entry_post_dispatch(
    const struct vmm_startup_entry_snapshot *snapshot,
    enum vmm_startup_dispatch_result result,
    enum vmm_startup_entry_action *action)
{
	enum vmm_startup_entry_action candidate, pre_action;

	if (vmm_startup_entry_snapshot_validate(snapshot) != 0 ||
	    result < VMM_STARTUP_DISPATCH_IDLE ||
	    result >= VMM_STARTUP_DISPATCH_RESULT_LAST || action == NULL ||
	    vmm_startup_mode_overlap(snapshot, sizeof(*snapshot), action,
	    sizeof(*action)) ||
	    vmm_startup_entry_pre_dispatch(snapshot, &pre_action) != 0 ||
	    pre_action != VMM_STARTUP_ENTRY_DISPATCH)
		return (EINVAL);
	if (result == VMM_STARTUP_DISPATCH_CONSUMED)
		candidate = VMM_STARTUP_ENTRY_REPLAY;
	else if (result == VMM_STARTUP_DISPATCH_IDLE &&
	    snapshot->waiting != 0)
		candidate = VMM_STARTUP_ENTRY_WAIT;
	else
		candidate = VMM_STARTUP_ENTRY_ENTER_GUEST;
	*action = candidate;
	return (0);
}

int
vmm_startup_entry_handoff_validate(
    const struct vmm_startup_entry_handoff *handoff)
{

	if (handoff == NULL || handoff->notification_generation == 0 ||
	    handoff->armed != 1 || handoff->reserved != 0)
		return (EINVAL);
	return (0);
}

int
vmm_startup_entry_handoff_capture(uint64_t notification_generation_before,
    enum vmm_startup_dispatch_result result,
    uint64_t notification_generation_after,
    struct vmm_startup_entry_handoff *handoff)
{
	struct vmm_startup_entry_handoff candidate;
	uint64_t expected_generation;
	int error;

	if (notification_generation_before == 0 ||
	    notification_generation_after == 0 ||
	    result < VMM_STARTUP_DISPATCH_IDLE ||
	    result >= VMM_STARTUP_DISPATCH_RESULT_LAST || handoff == NULL ||
	    handoff->notification_generation != 0 || handoff->armed != 0 ||
	    handoff->reserved != 0)
		return (EINVAL);
	expected_generation = notification_generation_before;
	/*
	 * A successful consumed dispatch releases exactly one claim and its
	 * wrapper advances the startup notification generation exactly once.
	 * IDLE and RETAINED do not release a claim.  Any other change represents
	 * a publication in the otherwise silent FROZEN notification window and
	 * must be replayed before the handoff can be armed.
	 */
	if (result == VMM_STARTUP_DISPATCH_CONSUMED) {
		error = vmm_startup_notification_advance(
		    notification_generation_before, &expected_generation);
		if (error != 0)
			return (error);
	}
	if (notification_generation_after != expected_generation)
		return (EAGAIN);
	memset(&candidate, 0, sizeof(candidate));
	candidate.notification_generation = notification_generation_after;
	candidate.armed = 1;
	*handoff = candidate;
	return (0);
}

int
vmm_startup_entry_handoff_check(uint64_t notification_generation,
    const struct vmm_startup_entry_handoff *handoff)
{

	if (notification_generation == 0 ||
	    vmm_startup_entry_handoff_validate(handoff) != 0)
		return (EINVAL);
	if (notification_generation != handoff->notification_generation)
		return (EAGAIN);
	return (0);
}

int
vmm_startup_entry_handoff_disarm(uint64_t notification_generation,
    struct vmm_startup_entry_handoff *handoff)
{
	int error;

	error = vmm_startup_entry_handoff_check(notification_generation,
	    handoff);
	if (error != 0)
		return (error);
	memset(handoff, 0, sizeof(*handoff));
	return (0);
}

int
vmm_startup_entry_admission_validate(
    const struct vmm_startup_entry_admission *admission)
{
	if (admission == NULL ||
	    admission->action <= VMM_STARTUP_ENTRY_DISPATCH ||
	    admission->action >= VMM_STARTUP_ENTRY_ACTION_LAST ||
	    admission->reserved8[0] != 0 || admission->reserved8[1] != 0 ||
	    admission->reserved8[2] != 0 || admission->reserved32 != 0)
		return (EINVAL);
	if (admission->action == VMM_STARTUP_ENTRY_ENTER_GUEST)
		return (vmm_startup_entry_handoff_validate(&admission->handoff));
	/*
	 * An unarmed handoff is a semantic state, not an all-bits-zero native
	 * object representation.  Keep this private common value free of padding
	 * and future-layout assumptions so it remains suitable for non-amd64
	 * callers as well as the current AMD64 implementation.
	 */
	if (admission->handoff.notification_generation != 0 ||
	    admission->handoff.armed != 0 || admission->handoff.reserved != 0)
		return (EINVAL);
	return (0);
}

int
vmm_startup_entry_dispatch_admit(
    const struct vmm_startup_entry_snapshot *before,
    const struct vmm_startup_entry_snapshot *after,
    enum vmm_startup_dispatch_result result,
    uint64_t notification_generation_before,
    uint64_t notification_generation_after,
    struct vmm_startup_entry_admission *admission)
{
	struct vmm_startup_entry_admission candidate;
	enum vmm_startup_entry_action action;
	int error;

	if (vmm_startup_entry_snapshot_validate(before) != 0 ||
	    vmm_startup_entry_snapshot_validate(after) != 0 ||
	    result < VMM_STARTUP_DISPATCH_IDLE ||
	    result >= VMM_STARTUP_DISPATCH_RESULT_LAST || admission == NULL ||
	    vmm_startup_mode_overlap(before, sizeof(*before), admission,
	    sizeof(*admission)) ||
	    vmm_startup_mode_overlap(after, sizeof(*after), admission,
	    sizeof(*admission)))
		return (EINVAL);
	error = vmm_startup_entry_pre_dispatch(before, &action);
	if (error != 0 || action != VMM_STARTUP_ENTRY_DISPATCH)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	error = vmm_startup_entry_handoff_capture(
	    notification_generation_before, result,
	    notification_generation_after, &candidate.handoff);
	if (error != 0)
		return (error);

	/*
	 * Lifecycle work published while the machine callback ran takes priority
	 * over replay, wait, and hardware entry.  It is not malformed merely
	 * because it was absent from the pre-dispatch snapshot.
	 */
	error = vmm_startup_entry_pre_dispatch(after, &action);
	if (error != 0)
		return (error);
	if (action == VMM_STARTUP_ENTRY_DISPATCH) {
		error = vmm_startup_entry_post_dispatch(after, result, &action);
		if (error != 0)
			return (error);
	}
	candidate.action = action;
	if (action != VMM_STARTUP_ENTRY_ENTER_GUEST)
		memset(&candidate.handoff, 0, sizeof(candidate.handoff));
	error = vmm_startup_entry_admission_validate(&candidate);
	if (error != 0)
		return (error);
	*admission = candidate;
	return (0);
}

uint64_t
vmm_startup_notification_generation_capture(uint64_t generation)
{

	/* Reserve zero for an unarmed handoff. */
	return (generation == 0 ? 1 : generation);
}

int
vmm_startup_notification_advance(uint64_t current, uint64_t *next)
{
	uint64_t candidate;

	if (next == NULL)
		return (EINVAL);
	if (current == UINT64_MAX)
		return (EOVERFLOW);
	candidate = current == 0 ? 1 : current + 1;
	*next = candidate;
	return (0);
}

int
vmm_startup_entry_runtime_validate(
    const struct vmm_startup_entry_runtime *runtime)
{

	if (runtime == NULL ||
	    runtime->phase >= VMM_STARTUP_ENTRY_RUNTIME_PHASE_LAST ||
	    runtime->critical > 1 || runtime->guest_fpu > 1 ||
	    runtime->running > 1 || runtime->reserved != 0)
		return (EINVAL);
	switch (runtime->phase) {
	case VMM_STARTUP_ENTRY_RUNTIME_FROZEN:
		return (runtime->critical == 0 && runtime->guest_fpu == 0 &&
		    runtime->running == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_CRITICAL:
		return (runtime->critical == 1 && runtime->guest_fpu == 0 &&
		    runtime->running == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU:
		return (runtime->critical == 1 && runtime->guest_fpu == 1 &&
		    runtime->running == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_RUNNING:
	case VMM_STARTUP_ENTRY_RUNTIME_CHECKED:
		return (runtime->critical == 1 && runtime->guest_fpu == 1 &&
		    runtime->running == 1 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_REFROZEN:
		return (runtime->critical == 1 && runtime->guest_fpu == 1 &&
		    runtime->running == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU:
		return (runtime->critical == 1 && runtime->guest_fpu == 0 &&
		    runtime->running == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_COMPLETE:
		return (runtime->critical == 0 && runtime->guest_fpu == 0 &&
		    runtime->running == 0 ? 0 : EINVAL);
	default:
		return (EINVAL);
	}
}

void
vmm_startup_entry_runtime_init(struct vmm_startup_entry_runtime *runtime)
{

	if (runtime == NULL)
		return;
	memset(runtime, 0, sizeof(*runtime));
}

int
vmm_startup_entry_runtime_enter_critical(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_FROZEN)
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_CRITICAL;
	candidate.critical = 1;
	*runtime = candidate;
	return (0);
}

int
vmm_startup_entry_runtime_restore_guest_fpu(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CRITICAL)
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU;
	candidate.guest_fpu = 1;
	*runtime = candidate;
	return (0);
}

int
vmm_startup_entry_runtime_publish_running(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU)
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_RUNNING;
	candidate.running = 1;
	*runtime = candidate;
	return (0);
}

/*
 * Compose independent positive-errno observations without making the result
 * depend on check order.  EAGAIN is a replay request, a terminal error
 * dominates replay, equal terminal errors retain their identity, and
 * conflicting terminal errors fail closed as EPROTO.
 */
static int
vmm_startup_entry_error_compose(int first, int second, int third)
{
	const int errors[] = { first, second, third };
	int terminal;
	bool replay;
	size_t i;

	terminal = 0;
	replay = false;
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		if (errors[i] == 0)
			continue;
		if (errors[i] == EAGAIN) {
			replay = true;
			continue;
		}
		if (terminal == 0)
			terminal = errors[i];
		else if (terminal != errors[i])
			return (EPROTO);
	}
	if (terminal != 0)
		return (terminal);
	return (replay ? EAGAIN : 0);
}

int
vmm_startup_entry_runtime_check(struct vmm_startup_entry_runtime *runtime,
    int coordinator_error, int notification_error,
    struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_runtime candidate;
	struct vmm_startup_entry_runtime_result candidate_result;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    (runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_RUNNING &&
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CHECKED) ||
	    result == NULL || coordinator_error < 0 || notification_error < 0 ||
	    vmm_startup_mode_overlap(runtime, sizeof(*runtime), result,
	    sizeof(*result)))
		return (EINVAL);
	memset(&candidate_result, 0, sizeof(candidate_result));
	if (coordinator_error == 0 && notification_error == 0) {
		candidate_result.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST;
		candidate = *runtime;
		/* Every backend hardware re-entry repeats this same check. */
		candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_CHECKED;
		*runtime = candidate;
	} else {
		/*
		 * One startup publication can invalidate both observations.  Collapse
		 * two retry reports to one replay instead of treating the expected
		 * race as malformed.  A terminal error dominates EAGAIN; equal
		 * terminal errors retain their identity, while conflicting terminal
		 * errors fail closed without making the result depend on check order.
		 */
		candidate_result.error = vmm_startup_entry_error_compose(
		    coordinator_error, notification_error, 0);
		candidate_result.action = candidate_result.error == EAGAIN ?
		    VMM_STARTUP_ENTRY_RUNTIME_REPLAY :
		    VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR;
	}
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_runtime_publish_frozen(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    (runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_RUNNING &&
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_CHECKED))
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_REFROZEN;
	candidate.running = 0;
	*runtime = candidate;
	return (0);
}

int
vmm_startup_entry_runtime_save_guest_fpu(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_REFROZEN)
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU;
	candidate.guest_fpu = 0;
	*runtime = candidate;
	return (0);
}

int
vmm_startup_entry_runtime_exit_critical(
    struct vmm_startup_entry_runtime *runtime)
{
	struct vmm_startup_entry_runtime candidate;

	if (vmm_startup_entry_runtime_validate(runtime) != 0 ||
	    runtime->phase != VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU)
		return (EINVAL);
	candidate = *runtime;
	candidate.phase = VMM_STARTUP_ENTRY_RUNTIME_COMPLETE;
	candidate.critical = 0;
	*runtime = candidate;
	return (0);
}

static int vmm_startup_entry_runtime_result_validate(
    const struct vmm_startup_entry_runtime_result *);

static int
vmm_startup_entry_loop_result_validate(
    const struct vmm_startup_entry_loop_result *result)
{

	if (result == NULL || result->error < 0 ||
	    result->action >= VMM_STARTUP_ENTRY_LOOP_ACTION_LAST ||
	    result->reserved8[0] != 0 || result->reserved8[1] != 0 ||
	    result->reserved8[2] != 0)
		return (EINVAL);
	switch (result->action) {
	case VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT:
	case VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT:
		return (result->error == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_LOOP_REPLAY:
		return (result->error == EAGAIN ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR:
		return (result->error > 0 && result->error != EAGAIN ? 0 :
		    EINVAL);
	default:
		return (EINVAL);
	}
}

int
vmm_startup_entry_loop_validate(const struct vmm_startup_entry_loop *loop)
{
	uint8_t i;

	if (loop == NULL ||
	    loop->phase >= VMM_STARTUP_ENTRY_LOOP_PHASE_LAST ||
	    vmm_startup_entry_loop_result_validate(&loop->disposition) != 0)
		return (EINVAL);
	for (i = 0; i < sizeof(loop->reserved8); i++) {
		if (loop->reserved8[i] != 0)
			return (EINVAL);
	}
	if (loop->phase <= VMM_STARTUP_ENTRY_LOOP_IN_GUEST &&
	    (loop->disposition.error != 0 ||
	    loop->disposition.action !=
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT))
		return (EINVAL);
	if (loop->phase == VMM_STARTUP_ENTRY_LOOP_CHECKED) {
		if (loop->entry_count == UINT64_MAX ||
		    loop->check_count != loop->entry_count + 1)
			return (EINVAL);
	} else if (loop->check_count != loop->entry_count) {
		return (EINVAL);
	}
	return (0);
}

static int
vmm_startup_entry_runtime_result_validate(
    const struct vmm_startup_entry_runtime_result *result)
{

	if (result == NULL || result->error < 0 ||
	    result->action >= VMM_STARTUP_ENTRY_RUNTIME_ACTION_LAST ||
	    result->reserved8[0] != 0 || result->reserved8[1] != 0 ||
	    result->reserved8[2] != 0)
		return (EINVAL);
	switch (result->action) {
	case VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST:
		return (result->error == 0 ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_REPLAY:
		return (result->error == EAGAIN ? 0 : EINVAL);
	case VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR:
		return (result->error > 0 && result->error != EAGAIN ? 0 :
		    EINVAL);
	default:
		return (EINVAL);
	}
}

void
vmm_startup_entry_loop_init(struct vmm_startup_entry_loop *loop)
{

	if (loop == NULL)
		return;
	memset(loop, 0, sizeof(*loop));
}

int
vmm_startup_entry_loop_check(struct vmm_startup_entry_loop *loop,
    const struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    vmm_startup_entry_runtime_result_validate(result) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *loop;
	if (result->action == VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		if (candidate.check_count == UINT64_MAX)
			return (EOVERFLOW);
		candidate.check_count++;
		candidate.phase = VMM_STARTUP_ENTRY_LOOP_CHECKED;
	} else {
		candidate.disposition.error = result->error;
		candidate.disposition.action =
		    result->action == VMM_STARTUP_ENTRY_RUNTIME_REPLAY ?
		    VMM_STARTUP_ENTRY_LOOP_REPLAY :
		    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
		candidate.phase = VMM_STARTUP_ENTRY_LOOP_RETURNABLE;
	}
	*loop = candidate;
	return (0);
}

int
vmm_startup_entry_loop_enter(struct vmm_startup_entry_loop *loop)
{
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_CHECKED)
		return (EINVAL);
	candidate = *loop;
	candidate.entry_count++;
	candidate.phase = VMM_STARTUP_ENTRY_LOOP_IN_GUEST;
	*loop = candidate;
	return (0);
}

int
vmm_startup_entry_loop_software_exit_checked(struct vmm_startup_entry_loop *loop,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_CHECKED || result == NULL ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *loop;
	memset(&candidate_result, 0, sizeof(candidate_result));
	candidate_result.action =
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT;
	candidate.disposition = candidate_result;
	/*
	 * CHECKED records an admission that has not yet become a guest entry.
	 * A rejected hardware attempt returns as software, so it must not leave a
	 * fictitious check/entry imbalance in the completed loop record.
	 */
	if (candidate.check_count == 0)
		return (EINVAL);
	candidate.check_count--;
	candidate.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE;
	if (vmm_startup_entry_loop_validate(&candidate) != 0)
		return (EINVAL);
	*loop = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_loop_fail_checked(struct vmm_startup_entry_loop *loop,
    int error, struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_CHECKED || error <= 0 ||
	    error == EAGAIN || result == NULL ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *loop;
	memset(&candidate_result, 0, sizeof(candidate_result));
	candidate_result.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
	candidate_result.error = error;
	candidate.disposition = candidate_result;
	/* See software_exit_checked(): no guest entry consumed this check. */
	if (candidate.check_count == 0)
		return (EINVAL);
	candidate.check_count--;
	candidate.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE;
	if (vmm_startup_entry_loop_validate(&candidate) != 0)
		return (EINVAL);
	*loop = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_loop_exit(struct vmm_startup_entry_loop *loop,
    bool handled, int backend_error)
{
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_IN_GUEST ||
	    backend_error < 0 || (handled && backend_error != 0))
		return (EINVAL);
	candidate = *loop;
	if (handled) {
		candidate.phase = VMM_STARTUP_ENTRY_LOOP_NEED_CHECK;
	} else {
		candidate.disposition.error = backend_error;
		candidate.disposition.action = backend_error == 0 ?
		    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT :
		    (backend_error == EAGAIN ?
		    VMM_STARTUP_ENTRY_LOOP_REPLAY :
		    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
		candidate.phase = VMM_STARTUP_ENTRY_LOOP_RETURNABLE;
	}
	*loop = candidate;
	return (0);
}

static int
vmm_startup_entry_loop_return_before_entry(
    struct vmm_startup_entry_loop *loop, bool software_exit, int error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate_result;
	struct vmm_startup_entry_loop candidate;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_NEED_CHECK || result == NULL ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)) || (software_exit && error != 0) ||
	    (!software_exit && error <= 0))
		return (EINVAL);
	candidate = *loop;
	memset(&candidate_result, 0, sizeof(candidate_result));
	candidate_result.error = error;
	if (software_exit) {
		candidate_result.action =
		    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT;
	} else if (error == EAGAIN) {
		candidate_result.action = VMM_STARTUP_ENTRY_LOOP_REPLAY;
	} else {
		candidate_result.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
	}
	candidate.disposition = candidate_result;
	candidate.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE;
	if (vmm_startup_entry_loop_validate(&candidate) != 0)
		return (EINVAL);
	*loop = candidate;
	*result = candidate_result;
	return (0);
}

int
vmm_startup_entry_loop_software_exit(struct vmm_startup_entry_loop *loop,
    struct vmm_startup_entry_loop_result *result)
{

	return (vmm_startup_entry_loop_return_before_entry(loop, true, 0,
	    result));
}

int
vmm_startup_entry_loop_fail_before_entry(
    struct vmm_startup_entry_loop *loop, int error,
    struct vmm_startup_entry_loop_result *result)
{

	return (vmm_startup_entry_loop_return_before_entry(loop, false, error,
	    result));
}

int
vmm_startup_entry_loop_finish(struct vmm_startup_entry_loop *loop,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop candidate;
	struct vmm_startup_entry_loop_result candidate_result;

	if (vmm_startup_entry_loop_validate(loop) != 0 ||
	    loop->phase != VMM_STARTUP_ENTRY_LOOP_RETURNABLE || result == NULL ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)))
		return (EINVAL);
	candidate = *loop;
	candidate_result = loop->disposition;
	candidate.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE;
	*loop = candidate;
	*result = candidate_result;
	return (0);
}

/*
 * Compose the final coordinator/notification validation with the backend
 * loop's check-and-enter transition.  Keeping both owners on local copies is
 * essential: a valid runtime observation must not advance to CHECKED if a
 * malformed or stale loop owner prevents the matching hardware-entry record.
 */
int
vmm_startup_entry_guard_before(struct vmm_startup_entry_runtime *runtime,
    struct vmm_startup_entry_loop *loop, int coordinator_error,
    int notification_error, struct vmm_startup_entry_runtime_result *result)
{
	struct vmm_startup_entry_runtime runtime_candidate;
	struct vmm_startup_entry_runtime_result result_candidate;
	struct vmm_startup_entry_loop loop_candidate;
	int error;

	if (runtime == NULL || loop == NULL || result == NULL ||
	    vmm_startup_mode_overlap(runtime, sizeof(*runtime), loop,
	    sizeof(*loop)) ||
	    vmm_startup_mode_overlap(runtime, sizeof(*runtime), result,
	    sizeof(*result)) ||
	    vmm_startup_mode_overlap(loop, sizeof(*loop), result,
	    sizeof(*result)))
		return (EINVAL);
	runtime_candidate = *runtime;
	loop_candidate = *loop;
	error = vmm_startup_entry_runtime_check(&runtime_candidate,
	    coordinator_error, notification_error, &result_candidate);
	if (error != 0)
		return (error);
	error = vmm_startup_entry_loop_check(&loop_candidate,
	    &result_candidate);
	if (error != 0)
		return (error);
	if (result_candidate.action ==
	    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST) {
		error = vmm_startup_entry_loop_enter(&loop_candidate);
		if (error != 0)
			return (error);
	}
	*runtime = runtime_candidate;
	*loop = loop_candidate;
	*result = result_candidate;
	return (0);
}

/*
 * Record one actual hardware return.  A backend-handled exit remains inside
 * the synchronous machine run and therefore accepts neither an error nor a
 * return result.  An unhandled exit atomically owns and publishes the normal,
 * replay, or terminal-error disposition while completing the loop.  Both
 * forms commit only after every transition validates on a local copy.
 */
int
vmm_startup_entry_guard_after(struct vmm_startup_entry_loop *loop,
    bool handled, int backend_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result result_candidate;
	struct vmm_startup_entry_loop loop_candidate;
	int error;

	if (loop == NULL || backend_error < 0 ||
	    (handled && (backend_error != 0 || result != NULL)) ||
	    (!handled && result == NULL) ||
	    (result != NULL && vmm_startup_mode_overlap(loop, sizeof(*loop),
	    result, sizeof(*result))))
		return (EINVAL);
	loop_candidate = *loop;
	error = vmm_startup_entry_loop_exit(&loop_candidate, handled,
	    backend_error);
	if (error != 0)
		return (error);
	if (!handled) {
		error = vmm_startup_entry_loop_finish(&loop_candidate,
		    &result_candidate);
		if (error != 0)
			return (error);
	}
	*loop = loop_candidate;
	if (!handled)
		*result = result_candidate;
	return (0);
}

/*
 * Arbitrate the backend's owned return with the final coordinator and
 * notification observations made after common code has refrozen the vCPU.
 * This closes the interval after the last hardware return: a publication in
 * that interval must replay even though there will be no further backend
 * entry check.  The backend's terminal error remains terminal, while
 * conflicting terminal observations fail closed.
 */
int
vmm_startup_entry_guard_complete(
    const struct vmm_startup_entry_loop_result *backend_result,
    int coordinator_error, int notification_error,
    struct vmm_startup_entry_loop_result *result)
{
	struct vmm_startup_entry_loop_result candidate;
	int error;

	if (vmm_startup_entry_loop_result_validate(backend_result) != 0 ||
	    coordinator_error < 0 || notification_error < 0 || result == NULL ||
	    vmm_startup_mode_overlap(backend_result, sizeof(*backend_result),
	    result, sizeof(*result)))
		return (EINVAL);
	error = vmm_startup_entry_error_compose(backend_result->error,
	    coordinator_error, notification_error);
	memset(&candidate, 0, sizeof(candidate));
	candidate.error = error;
	if (error == 0) {
		candidate.action = backend_result->action ==
		    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT ?
		    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT :
		    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT;
	} else if (error == EAGAIN) {
		candidate.action = VMM_STARTUP_ENTRY_LOOP_REPLAY;
	} else {
		candidate.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
	}
	*result = candidate;
	return (0);
}
