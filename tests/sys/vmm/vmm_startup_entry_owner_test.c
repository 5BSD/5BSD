/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_event.c"
#include "../../../sys/dev/vmm/vmm_startup_mode.c"
#include "../../../sys/dev/vmm/vmm_startup_entry_owner.c"

static void
entry_owner_complete_backend(
    const struct vmm_startup_event_run_token *token,
    const struct vmm_startup_entry_handoff *handoff, int backend_error,
    struct vmm_startup_entry_owner *owner)
{
	struct vmm_startup_entry_loop_result backend;
	struct vmm_startup_entry_runtime_result decision;

	memset(owner, 0, sizeof(*owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(token, handoff, owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(decision.action,
	    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(owner, false,
	    backend_error, &backend), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(owner), 0);
}

static void
entry_owner_make_runtime(uint8_t phase,
    struct vmm_startup_entry_runtime *runtime)
{

	memset(runtime, 0, sizeof(*runtime));
	runtime->phase = phase;
	switch (phase) {
	case VMM_STARTUP_ENTRY_RUNTIME_CRITICAL:
		runtime->critical = 1;
		break;
	case VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU:
		runtime->critical = 1;
		runtime->guest_fpu = 1;
		break;
	case VMM_STARTUP_ENTRY_RUNTIME_RUNNING:
	case VMM_STARTUP_ENTRY_RUNTIME_CHECKED:
		runtime->critical = 1;
		runtime->guest_fpu = 1;
		runtime->running = 1;
		break;
	case VMM_STARTUP_ENTRY_RUNTIME_REFROZEN:
		runtime->critical = 1;
		runtime->guest_fpu = 1;
		break;
	case VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU:
		runtime->critical = 1;
		break;
	default:
		break;
	}
}

static void
entry_owner_make_loop(uint8_t phase, uint64_t count, uint8_t action,
    struct vmm_startup_entry_loop *loop)
{

	memset(loop, 0, sizeof(*loop));
	loop->phase = phase;
	loop->entry_count = count;
	loop->check_count = phase == VMM_STARTUP_ENTRY_LOOP_CHECKED ?
	    count + 1 : count;
	loop->disposition.action = action;
	loop->disposition.error = action == VMM_STARTUP_ENTRY_LOOP_REPLAY ?
	    EAGAIN : (action == VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR ? EIO : 0);
}

static bool
entry_owner_tuple_expected(const struct vmm_startup_entry_owner *owner)
{
	bool returned;

	if (vmm_startup_entry_runtime_validate(&owner->runtime) != 0 ||
	    vmm_startup_entry_loop_validate(&owner->loop) != 0)
		return (false);
	returned = owner->loop.phase == VMM_STARTUP_ENTRY_LOOP_COMPLETE &&
	    (owner->loop.entry_count != 0 || owner->loop.disposition.action !=
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
	switch (owner->phase) {
	case VMM_STARTUP_ENTRY_OWNER_BOUND:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_FROZEN && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_NEED_CHECK &&
		    owner->loop.entry_count == 0);
	case VMM_STARTUP_ENTRY_OWNER_CRITICAL:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CRITICAL && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_NEED_CHECK &&
		    owner->loop.entry_count == 0);
	case VMM_STARTUP_ENTRY_OWNER_GUEST_FPU:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_NEED_CHECK &&
		    owner->loop.entry_count == 0);
	case VMM_STARTUP_ENTRY_OWNER_RUNNING:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_RUNNING && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_NEED_CHECK &&
		    owner->loop.entry_count == 0);
	case VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_CHECKED &&
		    owner->loop.check_count == owner->loop.entry_count + 1);
	case VMM_STARTUP_ENTRY_OWNER_IN_GUEST:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_IN_GUEST &&
		    owner->loop.entry_count != 0);
	case VMM_STARTUP_ENTRY_OWNER_RECHECK:
		return (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED && owner->loop.phase ==
		    VMM_STARTUP_ENTRY_LOOP_NEED_CHECK &&
		    owner->loop.entry_count != 0);
	case VMM_STARTUP_ENTRY_OWNER_RETURNABLE:
		return (returned && ((owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_RUNNING &&
		    owner->loop.entry_count == 0) || (owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_CHECKED &&
		    (owner->loop.entry_count != 0 ||
		    owner->loop.disposition.action ==
		    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT ||
		    owner->loop.disposition.action ==
		    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR))));
	case VMM_STARTUP_ENTRY_OWNER_REFROZEN:
		return (returned && owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_REFROZEN);
	case VMM_STARTUP_ENTRY_OWNER_HOST_FPU:
		return (returned && owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_HOST_FPU);
	case VMM_STARTUP_ENTRY_OWNER_COMPLETE:
		return (returned && owner->runtime.phase ==
		    VMM_STARTUP_ENTRY_RUNTIME_COMPLETE);
	default:
		return (false);
	}
}

ATF_TC_WITHOUT_HEAD(entry_owner_binds_post_dispatch_values);
ATF_TC_BODY(entry_owner_binds_post_dispatch_values, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 11,
		.generation = 7,
		.next_claim_id = 3,
		.vcpuid = 2,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner before, malformed, owner, valid;
	struct vmm_startup_event_run_token bad_token;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(19,
	    VMM_STARTUP_DISPATCH_RETAINED, 19, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	ATF_CHECK_EQ(owner.armed, 1);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_BOUND);
	ATF_CHECK_EQ(owner.coordinator.owner_id, token.owner_id);
	ATF_CHECK_EQ(owner.coordinator.generation, token.generation);
	ATF_CHECK_EQ(owner.coordinator.vcpuid, token.vcpuid);
	ATF_CHECK_EQ(owner.notification.notification_generation, 19);
	ATF_CHECK_EQ(owner.runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_FROZEN);
	ATF_CHECK_EQ(owner.loop.phase, VMM_STARTUP_ENTRY_LOOP_NEED_CHECK);
	valid = owner;

	/* Construction is single-use and preserves an existing owner. */
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* Malformed inputs and owner aliasing are failure-atomic. */
	bad_token = token;
	bad_token.reserved = 1;
	memset(&owner, 0, sizeof(owner));
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_init(&bad_token, &handoff,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	handoff.reserved = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	handoff.reserved = 0;
	ATF_CHECK_EQ(vmm_startup_entry_owner_init(
	    &owner.coordinator, &handoff, &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	malformed = before;
	malformed.armed = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = before;
	malformed.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);

	/* Separately valid member states cannot form an impossible owner. */
	malformed = valid;
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&malformed.loop,
	    &(const struct vmm_startup_entry_runtime_result) {
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	    }), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = valid;
	malformed.loop.check_count = 4;
	malformed.loop.entry_count = 4;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_owner_requires_entry_admission);
ATF_TC_BODY(entry_owner_requires_entry_admission, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 17,
		.generation = 13,
		.next_claim_id = 7,
		.vcpuid = 4,
	};
	struct vmm_startup_entry_admission admission;
	struct vmm_startup_entry_owner before, owner;
	struct vmm_startup_entry_snapshot pre, post;
	union {
		struct vmm_startup_entry_admission admission;
		struct vmm_startup_entry_owner owner;
	} alias, alias_before;

	(void)tc;
	memset(&pre, 0, sizeof(pre));
	memset(&post, 0, sizeof(post));
	memset(&admission, 0, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&pre, &post,
	    VMM_STARTUP_DISPATCH_IDLE, 41, 41, &admission), 0);
	ATF_REQUIRE_EQ(admission.action, VMM_STARTUP_ENTRY_ENTER_GUEST);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	/* A constructed owner is single-use and is preserved on rejection. */
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* No non-entry admission may be detached from its action and promoted. */
	post.rendezvous = 1;
	memset(&admission, 0, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&pre, &post,
	    VMM_STARTUP_DISPATCH_IDLE, 51, 51, &admission), 0);
	ATF_REQUIRE_EQ(admission.action,
	    VMM_STARTUP_ENTRY_SERVICE_RENDEZVOUS);
	memset(&owner, 0, sizeof(owner));
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	memset(&post, 0, sizeof(post));
	post.waiting = 1;
	memset(&admission, 0, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&pre, &post,
	    VMM_STARTUP_DISPATCH_IDLE, 61, 61, &admission), 0);
	ATF_REQUIRE_EQ(admission.action, VMM_STARTUP_ENTRY_WAIT);
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	memset(&post, 0, sizeof(post));
	memset(&admission, 0, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&pre, &post,
	    VMM_STARTUP_DISPATCH_CONSUMED, 71, 72, &admission), 0);
	ATF_REQUIRE_EQ(admission.action, VMM_STARTUP_ENTRY_REPLAY);
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* Malformed, null, and overlapping values are failure-atomic. */
	admission.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(NULL, &admission,
	    &owner), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, NULL, &owner),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &admission, NULL),
	    EINVAL);

	memset(&post, 0, sizeof(post));
	memset(&alias, 0, sizeof(alias));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&pre, &post,
	    VMM_STARTUP_DISPATCH_IDLE, 81, 81, &alias.admission), 0);
	alias_before = alias;
	ATF_CHECK_EQ(vmm_startup_entry_owner_admit(&token, &alias.admission,
	    &alias.owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&alias, &alias_before, sizeof(alias)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_owner_preparation_is_ordered_and_failure_atomic);
ATF_TC_BODY(entry_owner_preparation_is_ordered_and_failure_atomic, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 23,
		.generation = 9,
		.next_claim_id = 5,
		.vcpuid = 3,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner before, malformed, owner;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(31,
	    VMM_STARTUP_DISPATCH_IDLE, 31, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);

	/* Skipping the critical and FPU phases preserves the complete owner. */
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_running(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_CRITICAL);
	ATF_CHECK_EQ(owner.runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_CRITICAL);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_enter_critical(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_running(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_GUEST_FPU);
	ATF_CHECK_EQ(owner.runtime.phase,
	    VMM_STARTUP_ENTRY_RUNTIME_GUEST_FPU);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	/* A valid loop with a forged history is invalid for this outer phase. */
	malformed = owner;
	malformed.loop.check_count = 2;
	malformed.loop.entry_count = 2;
	ATF_CHECK_EQ(vmm_startup_entry_loop_validate(&malformed.loop), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	before = malformed;
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_running(&malformed),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&malformed, &before, sizeof(malformed)), 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RUNNING);
	ATF_CHECK_EQ(owner.runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_RUNNING);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_running(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* Individually valid phases remain invalid when paired incorrectly. */
	malformed = owner;
	malformed.phase = VMM_STARTUP_ENTRY_OWNER_GUEST_FPU;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_validate(&malformed.runtime), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_validate(&malformed.loop), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_owner_loop_unwind_and_retirement_are_owned);
ATF_TC_BODY(entry_owner_loop_unwind_and_retirement_are_owned, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 37,
		.generation = 12,
		.next_claim_id = 8,
		.vcpuid = 4,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_loop_result backend, backend_before, final,
	    final_before;
	struct vmm_startup_entry_owner before, owner, zero;
	struct vmm_startup_entry_runtime_result decision, decision_before;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(41,
	    VMM_STARTUP_DISPATCH_RETAINED, 41, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);

	/* Bad observations and an aliased output cannot partially enter. */
	before = owner;
	memset(&decision, 0xa5, sizeof(decision));
	decision_before = decision;
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_before(&owner, -1, 0,
	    &decision), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&decision, &decision_before, sizeof(decision)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    (struct vmm_startup_entry_runtime_result *)(void *)&owner.coordinator),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_CHECK_EQ(decision.action, VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_IN_GUEST);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	/* A handled exit owns no result and must recheck before re-entry. */
	before = owner;
	memset(&backend, 0xa5, sizeof(backend));
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_after(&owner, true, EIO,
	    NULL), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    &backend), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RECHECK);
	before = owner;
	owner.loop.check_count = UINT64_MAX;
	owner.loop.entry_count = UINT64_MAX;
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	memset(&decision, 0xa5, sizeof(decision));
	decision_before = decision;
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), EOVERFLOW);
	ATF_CHECK_EQ(owner.loop.check_count, UINT64_MAX);
	ATF_CHECK_EQ(owner.loop.entry_count, UINT64_MAX);
	ATF_CHECK_EQ(memcmp(&decision, &decision_before, sizeof(decision)), 0);
	owner = before;
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_IN_GUEST);
	ATF_CHECK_EQ(owner.loop.entry_count, 2);

	before = owner;
	memset(&backend, 0xa5, sizeof(backend));
	backend_before = backend;
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_after(&owner, false, -1,
	    &backend), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&backend, &backend_before, sizeof(backend)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, false, EIO,
	    &backend), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(backend.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(backend.error, EIO);

	/* Retirement is legal only after the complete common unwind. */
	before = owner;
	memset(&final, 0xa5, sizeof(final));
	final_before = final;
	ATF_CHECK_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0, &final),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&final, &final_before, sizeof(final)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_REFROZEN);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_HOST_FPU);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_COMPLETE);

	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_retire(&owner, -1, 0, &final),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&final, &final_before, sizeof(final)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    (struct vmm_startup_entry_loop_result *)(void *)&owner.notification),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, EAGAIN, 0,
	    &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(final.error, EIO);
	memset(&zero, 0, sizeof(zero));
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);

	/* Drift before the first entry completes as replay and then retires. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, EAGAIN, 0,
	    &decision), 0);
	ATF_CHECK_EQ(decision.action, VMM_STARTUP_ENTRY_RUNTIME_REPLAY);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	/* A zero-entry completion is never evidence of a hardware VM exit. */
	before = owner;
	owner.loop.disposition.action = VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT;
	owner.loop.disposition.error = 0;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), EINVAL);
	owner = before;
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(final.error, EAGAIN);
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_owner_final_arbitration_preserves_domains);
ATF_TC_BODY(entry_owner_final_arbitration_preserves_domains, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 43,
		.generation = 15,
		.next_claim_id = 9,
		.vcpuid = 5,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_loop_result final;
	struct vmm_startup_entry_owner owner, zero;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(47,
	    VMM_STARTUP_DISPATCH_IDLE, 47, &handoff), 0);
	memset(&zero, 0, sizeof(zero));

	/* Final drift overrides an otherwise normal backend VM exit. */
	entry_owner_complete_backend(&token, &handoff, 0, &owner);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, EAGAIN, 0,
	    &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(final.error, EAGAIN);
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);

	/* Conflicting final terminal errors fail closed independent of order. */
	entry_owner_complete_backend(&token, &handoff, 0, &owner);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, EIO, ESTALE,
	    &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(final.error, EPROTO);
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);

	/* One or equal terminal errors retain their identity over replay. */
	entry_owner_complete_backend(&token, &handoff, EBUSY, &owner);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, EAGAIN, EBUSY,
	    &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(final.error, EBUSY);
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_owner_distinguishes_preentry_returns);
ATF_TC_BODY(entry_owner_distinguishes_preentry_returns, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 61,
		.generation = 21,
		.next_claim_id = 13,
		.vcpuid = 7,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_loop_result before_result, final, result;
	struct vmm_startup_entry_owner before, owner, zero;
	struct vmm_startup_entry_runtime_result decision;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(67,
	    VMM_STARTUP_DISPATCH_IDLE, 67, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_software_exit(&owner, &result),
	    0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0, &final), 0);
	ATF_CHECK_EQ(final.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(final.error, 0);
	memset(&zero, 0, sizeof(zero));
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);

	/* The same typed exit is reachable after one backend-handled entry. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_software_exit(&owner, &result),
	    0);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	/* A failed hot preparation retains the earlier hardware-entry count. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_fail_before_entry(&owner, EAGAIN,
	    &result), 0);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_fail_before_entry(&owner, EIO,
	    &result), 0);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);

	/* A hardware-exit label remains impossible without an entry record. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_software_exit(&owner, &result),
	    0);
	before = owner;
	owner.loop.disposition.action =
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), EINVAL);
	owner = before;

	/* Pre-entry failure is typed and failure-atomic. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	before = owner;
	memset(&result, 0xa5, sizeof(result));
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_owner_fail_before_entry(&owner, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_fail_before_entry(&owner, EIO,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
}

/*
 * This is a source-edge model, rather than evidence that a backend has been
 * installed.  It ties the five currently inventoried hardware-entry shapes
 * to the same stack owner contract: ordinary VMX, nested cold entry, nested
 * resumed entry, nested hot re-entry, and SVM.  A real adapter must retain
 * these distinctions for backend unwind, but it may not bypass the common
 * before-entry, after-entry, and retirement sequence.
 */
static void
entry_owner_run_backend_shape(const struct vmm_startup_event_run_token *token,
    const struct vmm_startup_entry_handoff *handoff, unsigned int handled,
    bool preentry, bool software_exit, int terminal_error,
    uint64_t expected_entries)
{
	struct vmm_startup_entry_loop_result final, result;
	struct vmm_startup_entry_owner owner, zero;
	struct vmm_startup_entry_runtime_result decision;
	unsigned int i;

	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(token, handoff, &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	if (preentry) {
		if (software_exit) {
			ATF_REQUIRE_EQ(vmm_startup_entry_owner_software_exit(&owner,
			    &result), 0);
			ATF_CHECK_EQ(result.action,
			    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
		} else {
			ATF_REQUIRE_EQ(vmm_startup_entry_owner_fail_before_entry(&owner,
			    terminal_error, &result), 0);
			ATF_CHECK_EQ(result.action, terminal_error == EAGAIN ?
			    VMM_STARTUP_ENTRY_LOOP_REPLAY :
			    VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
			ATF_CHECK_EQ(result.error, terminal_error);
		}
	} else {
		for (i = 0; i <= handled; i++) {
			ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0,
			    0, &decision), 0);
			ATF_REQUIRE_EQ(decision.action,
			    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
			ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner,
			    i != handled, i == handled ? terminal_error : 0,
			    i == handled ? &result : NULL), 0);
		}
	}
	ATF_CHECK_EQ(owner.loop.entry_count, expected_entries);
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0, &final), 0);
	if (software_exit) {
		ATF_CHECK_EQ(final.action,
		    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
		ATF_CHECK_EQ(final.error, 0);
	} else if (terminal_error == EAGAIN) {
		ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
		ATF_CHECK_EQ(final.error, EAGAIN);
	} else if (terminal_error != 0) {
		ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
		ATF_CHECK_EQ(final.error, terminal_error);
	} else {
		ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
		ATF_CHECK_EQ(final.error, 0);
	}
	memset(&zero, 0, sizeof(zero));
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_owner_backend_edge_shapes);
ATF_TC_BODY(entry_owner_backend_edge_shapes, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 71,
		.generation = 23,
		.next_claim_id = 17,
		.vcpuid = 8,
	};
	struct vmm_startup_entry_handoff handoff;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(73,
	    VMM_STARTUP_DISPATCH_IDLE, 73, &handoff), 0);

	/* One terminal entry covers ordinary VMX and nested cold start. */
	entry_owner_run_backend_shape(&token, &handoff, 0, false, false, 0, 1);
	entry_owner_run_backend_shape(&token, &handoff, 0, false, false, 0, 1);
	/* Nested resume and hot paths must recheck before each further entry. */
	entry_owner_run_backend_shape(&token, &handoff, 1, false, false, 0, 2);
	entry_owner_run_backend_shape(&token, &handoff, 2, false, false, 0, 3);
	/* SVM uses the identical one-entry common contract. */
	entry_owner_run_backend_shape(&token, &handoff, 0, false, false, 0, 1);
	/* No-entry paths preserve typed software and preparation outcomes. */
	entry_owner_run_backend_shape(&token, &handoff, 0, true, true, 0, 0);
	entry_owner_run_backend_shape(&token, &handoff, 0, true, false, EAGAIN,
	    0);
	entry_owner_run_backend_shape(&token, &handoff, 0, true, false, EIO, 0);
	/* A staged backend rejection remains a typed pre-entry outcome. */
	entry_owner_run_backend_shape(&token, &handoff, 0, true, false,
	    EOPNOTSUPP, 0);
}

/*
 * A machine backend can finish hardware preparation and then decline the
 * final common admission.  This is neither a hardware VM exit nor a backend
 * error: the owner already carries the typed replay/error result.  VMX and
 * SVM have different hardware cleanup at this point, but must return the
 * same portable state product to vm_run().
 */
ATF_TC_WITHOUT_HEAD(entry_owner_declined_final_admission_is_noentry);
ATF_TC_BODY(entry_owner_declined_final_admission_is_noentry, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 73,
		.generation = 29,
		.next_claim_id = 19,
		.vcpuid = 10,
	};
	struct vmm_startup_entry_loop_result final;
	struct vmm_startup_entry_runtime_result decision;
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner owner, zero;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(79,
	    VMM_STARTUP_DISPATCH_IDLE, 79, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff, &owner),
	    0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);

	/* A final coordinator drift declines entry before VMX/VMRUN executes. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, EAGAIN, 0,
	    &decision), 0);
	ATF_CHECK_EQ(decision.action, VMM_STARTUP_ENTRY_RUNTIME_REPLAY);
	ATF_CHECK_EQ(decision.error, EAGAIN);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0, &final), 0);
	ATF_CHECK_EQ(final.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(final.error, EAGAIN);
	memset(&zero, 0, sizeof(zero));
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_owner_deferred_preentry_resolution);
ATF_TC_BODY(entry_owner_deferred_preentry_resolution, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 79,
		.generation = 31,
		.next_claim_id = 19,
		.vcpuid = 9,
	};
	struct vmm_startup_entry_loop_result result, result_before;
	struct vmm_startup_entry_runtime_result decision;
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner before, owner, zero;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(83,
	    VMM_STARTUP_DISPATCH_RETAINED, 83, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);

	/* A replay is observed once but cannot retire before private cleanup. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_defer(&owner,
	    EAGAIN, 0, &decision), 0);
	ATF_CHECK_EQ(decision.action, VMM_STARTUP_ENTRY_RUNTIME_REPLAY);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_DEFERRED);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(owner.loop.check_count, 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_frozen(&owner), EINVAL);
	before = owner;
	memset(&result, 0xa5, sizeof(result));
	result_before = result;
	ATF_CHECK_EQ(vmm_startup_entry_owner_resolve_deferred(&owner, EAGAIN,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	/* A resolver result may never alias state retained for private cleanup. */
	ATF_CHECK_EQ(vmm_startup_entry_owner_resolve_deferred(&owner, EIO,
	    &owner.loop.disposition), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* A terminal teardown dominates the retained replay. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_resolve_deferred(&owner, EIO,
	    &result), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	memset(&zero, 0, sizeof(zero));
	ATF_CHECK_EQ(memcmp(&owner, &zero, sizeof(owner)), 0);

	/* Preserving a terminal guard result retains its exact error. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_defer(&owner,
	    EBUSY, 0, &decision), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_DEFERRED);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_resolve_deferred(&owner, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EBUSY);

	/* A successful admission retains ordinary one-phase enter semantics. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_defer(&owner,
	    0, 0, &decision), 0);
	ATF_CHECK_EQ(decision.action,
	    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_IN_GUEST);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(vmm_startup_entry_owner_resolve_deferred(&owner, 0,
	    &result), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_owner_state_product_is_exact);
ATF_TC_BODY(entry_owner_state_product_is_exact, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 53,
		.generation = 17,
		.next_claim_id = 11,
		.vcpuid = 6,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner owner;
	uint64_t count;
	uint8_t action, loop_phase, owner_phase, runtime_phase;
	bool expected;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(59,
	    VMM_STARTUP_DISPATCH_RETAINED, 59, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	for (owner_phase = 0;
	    owner_phase < VMM_STARTUP_ENTRY_OWNER_PHASE_LAST; owner_phase++) {
		for (runtime_phase = 0;
		    runtime_phase < VMM_STARTUP_ENTRY_RUNTIME_PHASE_LAST;
		    runtime_phase++) {
			for (loop_phase = 0;
			    loop_phase < VMM_STARTUP_ENTRY_LOOP_PHASE_LAST;
			    loop_phase++) {
				for (count = 0; count <= 1; count++) {
					for (action = 0;
					    action < VMM_STARTUP_ENTRY_LOOP_ACTION_LAST;
					    action++) {
						owner.phase = owner_phase;
						entry_owner_make_runtime(runtime_phase,
						    &owner.runtime);
						entry_owner_make_loop(loop_phase, count,
						    action, &owner.loop);
						expected = entry_owner_tuple_expected(&owner);
						ATF_CHECK_EQ_MSG(
						    vmm_startup_entry_owner_validate(&owner) == 0,
						    expected,
						    "owner=%u runtime=%u loop=%u count=%ju action=%u",
						    owner_phase, runtime_phase, loop_phase,
						    (uintmax_t)count, action);
					}
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(entry_owner_deferred_state_product_is_exact);
ATF_TC_BODY(entry_owner_deferred_state_product_is_exact, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 83,
		.generation = 37,
		.next_claim_id = 23,
		.vcpuid = 10,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner owner, malformed;
	uint64_t count;
	uint8_t action, runtime_phase;
	bool expected;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(89,
	    VMM_STARTUP_DISPATCH_RETAINED, 89, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	owner.phase = VMM_STARTUP_ENTRY_OWNER_DEFERRED;
	owner.deferred_kind = VMM_STARTUP_ENTRY_OWNER_DEFERRED_PRE_ENTRY;
	owner.loop.phase = VMM_STARTUP_ENTRY_LOOP_NEED_CHECK;
	owner.deferred.error = EAGAIN;
	owner.deferred.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY;
	for (runtime_phase = 0;
	    runtime_phase < VMM_STARTUP_ENTRY_RUNTIME_PHASE_LAST;
	    runtime_phase++) {
		for (count = 0; count <= 1; count++) {
			entry_owner_make_runtime(runtime_phase, &owner.runtime);
			owner.loop.entry_count = count;
			owner.loop.check_count = count;
			expected = (runtime_phase ==
			    VMM_STARTUP_ENTRY_RUNTIME_RUNNING && count == 0) ||
			    (runtime_phase == VMM_STARTUP_ENTRY_RUNTIME_CHECKED &&
			    count == 1);
			ATF_CHECK_EQ_MSG(vmm_startup_entry_owner_validate(&owner) == 0,
			    expected, "runtime=%u entries=%ju", runtime_phase,
			    (uintmax_t)count);
		}
	}

	/* Each separately plausible deferred field mutation must be rejected. */
	entry_owner_make_runtime(VMM_STARTUP_ENTRY_RUNTIME_RUNNING,
	    &owner.runtime);
	owner.loop.entry_count = 0;
	owner.loop.check_count = 0;
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	malformed = owner;
	malformed.deferred.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred.error = 0;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred.error = EIO;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred.reserved8[0] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.loop.phase = VMM_STARTUP_ENTRY_LOOP_COMPLETE;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	for (action = 0; action < VMM_STARTUP_ENTRY_LOOP_ACTION_LAST;
	    action++) {
		malformed = owner;
		malformed.loop.disposition.action = action;
		malformed.loop.disposition.error = action ==
		    VMM_STARTUP_ENTRY_LOOP_REPLAY ? EAGAIN :
		    (action == VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR ? EIO : 0);
		/* NEED_CHECK has no completed disposition yet. */
		ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed),
		    action == VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT ? 0 : EINVAL);
	}
}

ATF_TC_WITHOUT_HEAD(entry_owner_deferred_postentry_resolution);
ATF_TC_BODY(entry_owner_deferred_postentry_resolution, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 97,
		.generation = 41,
		.next_claim_id = 29,
		.vcpuid = 11,
	};
	struct vmm_startup_entry_loop_result result, result_before;
	struct vmm_startup_entry_runtime_result decision;
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner before, malformed, owner;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(101,
	    VMM_STARTUP_DISPATCH_RETAINED, 101, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);

	/* A guest exit must not become returnable before private freeze/detach. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after_defer(&owner, EAGAIN),
	    0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_DEFERRED);
	ATF_CHECK_EQ(owner.deferred_kind,
	    VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY);
	ATF_CHECK_EQ(owner.loop.phase, VMM_STARTUP_ENTRY_LOOP_IN_GUEST);
	ATF_CHECK_EQ(owner.deferred_exit.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(owner.deferred_exit.error, EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_owner_publish_frozen(&owner), EINVAL);
	malformed = owner;
	malformed.deferred_exit.action =
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred_exit.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY;
	malformed.deferred.error = EAGAIN;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	malformed = owner;
	malformed.deferred_reserved8[0] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
	before = owner;
	memset(&result, 0xa5, sizeof(result));
	result_before = result;
	ATF_CHECK_EQ(vmm_startup_entry_owner_resolve_deferred_after(&owner,
	    EAGAIN, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	/* Do not allow a final result to overwrite the deferred owner itself. */
	ATF_CHECK_EQ(vmm_startup_entry_owner_resolve_deferred_after(&owner,
	    EIO, &owner.loop.disposition), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	/* A terminal detach must dominate an otherwise replayable guest result. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_resolve_deferred_after(&owner,
	    EIO, &result), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.error, EIO);

	/* A successful freeze preserves an ordinary VMEXIT result. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after_defer(&owner, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_resolve_deferred_after(&owner, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
	ATF_CHECK_EQ(result.error, 0);

	/* Handled exits use the existing recheck path, never a terminal defer. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before(&owner, 0, 0,
	    &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RECHECK);
	ATF_CHECK_EQ(vmm_startup_entry_owner_guard_after_defer(&owner, 0), EINVAL);
}

/*
 * Pre-entry and post-entry deferred owners intentionally have different
 * proofs.  The former may retain a declined admission without an entry;
 * the latter may be created only after an entered guest has produced a
 * terminal result.  Enumerate the small state product here instead of
 * deriving it from an adapter's private unwind implementation.
 */
ATF_TC_WITHOUT_HEAD(entry_owner_deferred_postentry_state_product_is_exact);
ATF_TC_BODY(entry_owner_deferred_postentry_state_product_is_exact, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 103,
		.generation = 47,
		.next_claim_id = 37,
		.vcpuid = 12,
	};
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner malformed, owner;
	uint64_t count;
	uint8_t action, loop_phase, runtime_phase;
	bool expected;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(109,
	    VMM_STARTUP_DISPATCH_RETAINED, 109, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	owner.phase = VMM_STARTUP_ENTRY_OWNER_DEFERRED;
	owner.deferred_kind = VMM_STARTUP_ENTRY_OWNER_DEFERRED_POST_ENTRY;

	/* Only CHECKED/IN_GUEST with a proven entry is a post-entry defer. */
	for (runtime_phase = 0;
	    runtime_phase < VMM_STARTUP_ENTRY_RUNTIME_PHASE_LAST;
	    runtime_phase++) {
		for (loop_phase = 0;
		    loop_phase < VMM_STARTUP_ENTRY_LOOP_PHASE_LAST; loop_phase++) {
			for (count = 0; count <= 1; count++) {
				entry_owner_make_runtime(runtime_phase, &owner.runtime);
				entry_owner_make_loop(loop_phase, count,
				    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT, &owner.loop);
				expected = runtime_phase ==
				    VMM_STARTUP_ENTRY_RUNTIME_CHECKED && loop_phase ==
				    VMM_STARTUP_ENTRY_LOOP_IN_GUEST && count == 1;
				ATF_CHECK_EQ_MSG(vmm_startup_entry_owner_validate(&owner) == 0,
				    expected, "runtime=%u loop=%u entries=%ju",
				    runtime_phase, loop_phase, (uintmax_t)count);
			}
		}
	}

	entry_owner_make_runtime(VMM_STARTUP_ENTRY_RUNTIME_CHECKED,
	    &owner.runtime);
	entry_owner_make_loop(VMM_STARTUP_ENTRY_LOOP_IN_GUEST, 1,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT, &owner.loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_validate(&owner), 0);
	for (action = 0; action < VMM_STARTUP_ENTRY_LOOP_ACTION_LAST;
	    action++) {
		malformed = owner;
		malformed.deferred_exit.action = action;
		malformed.deferred_exit.error = action ==
		    VMM_STARTUP_ENTRY_LOOP_REPLAY ? EAGAIN :
		    (action == VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR ? EIO : 0);
		expected = action == VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT ||
		    action == VMM_STARTUP_ENTRY_LOOP_REPLAY ||
		    action == VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR;
		ATF_CHECK_EQ_MSG(vmm_startup_entry_owner_validate(&malformed) == 0,
		    expected, "deferred post-entry action=%u", action);
	}
	malformed = owner;
	malformed.deferred_exit.reserved8[2] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_owner_validate(&malformed), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_owner_hardware_attempt_is_not_guest_entry);
ATF_TC_BODY(entry_owner_hardware_attempt_is_not_guest_entry, tc)
{
	const struct vmm_startup_event_run_token token = {
		.owner_id = 109,
		.generation = 43,
		.next_claim_id = 31,
		.vcpuid = 13,
	};
	struct vmm_startup_entry_loop_result result, result_before;
	struct vmm_startup_entry_runtime_result decision;
	struct vmm_startup_entry_handoff handoff;
	struct vmm_startup_entry_owner before, owner;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(107,
	    VMM_STARTUP_DISPATCH_RETAINED, 107, &handoff), 0);
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);

	/* Successful admission is still pending until execution is proved. */
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_attempt(&owner, 0,
	    0, &decision), 0);
	ATF_CHECK_EQ(decision.action, VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING);
	ATF_CHECK_EQ(owner.loop.phase, VMM_STARTUP_ENTRY_LOOP_CHECKED);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(owner.loop.check_count, 1);
	before = owner;
	memset(&result, 0xa5, sizeof(result));
	result_before = result;
	ATF_CHECK_EQ(vmm_startup_entry_owner_abort_attempt(&owner,
	    &owner.loop.disposition), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_abort_attempt(&owner, &result), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(owner.loop.check_count, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(result.error, 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);

	/* A conclusive no-entry terminal error also preserves zero entries. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_attempt(&owner, 0,
	    0, &decision), 0);
	before = owner;
	memset(&result, 0xa5, sizeof(result));
	result_before = result;
	ATF_CHECK_EQ(vmm_startup_entry_owner_abort_attempt_error(&owner, EAGAIN,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_abort_attempt_error(&owner, EIO,
	    &result), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_RETURNABLE);
	ATF_CHECK_EQ(owner.loop.entry_count, 0);
	ATF_CHECK_EQ(owner.loop.check_count, 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_frozen(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_save_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_exit_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_retire(&owner, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);

	/* A proved entry commits exactly once and then uses normal exit handling. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_attempt(&owner, 0,
	    0, &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_commit_attempt(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_IN_GUEST);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_commit_attempt(&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_owner_abort_attempt(&owner, &result),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_owner_abort_attempt_error(&owner, EIO,
	    &result), EINVAL);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, false, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);

	/* A later no-entry attempt retains prior real-entry history exactly. */
	memset(&owner, 0, sizeof(owner));
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_init(&token, &handoff,
	    &owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_enter_critical(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_restore_guest_fpu(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_publish_running(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_attempt(&owner, 0,
	    0, &decision), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_commit_attempt(&owner), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_after(&owner, true, 0,
	    NULL), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_guard_before_attempt(&owner, 0,
	    0, &decision), 0);
	ATF_CHECK_EQ(owner.phase, VMM_STARTUP_ENTRY_OWNER_ENTRY_PENDING);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(owner.loop.check_count, 2);
	before = owner;
	ATF_CHECK_EQ(vmm_startup_entry_owner_abort_attempt_error(&owner, EIO,
	    &owner.loop.disposition), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_owner_abort_attempt_error(&owner, EIO,
	    &result), 0);
	ATF_CHECK_EQ(owner.loop.entry_count, 1);
	ATF_CHECK_EQ(owner.loop.check_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, entry_owner_binds_post_dispatch_values);
	ATF_TP_ADD_TC(tp, entry_owner_requires_entry_admission);
	ATF_TP_ADD_TC(tp,
	    entry_owner_preparation_is_ordered_and_failure_atomic);
	ATF_TP_ADD_TC(tp, entry_owner_loop_unwind_and_retirement_are_owned);
	ATF_TP_ADD_TC(tp, entry_owner_final_arbitration_preserves_domains);
	ATF_TP_ADD_TC(tp, entry_owner_distinguishes_preentry_returns);
	ATF_TP_ADD_TC(tp, entry_owner_backend_edge_shapes);
	ATF_TP_ADD_TC(tp, entry_owner_declined_final_admission_is_noentry);
	ATF_TP_ADD_TC(tp, entry_owner_deferred_preentry_resolution);
	ATF_TP_ADD_TC(tp, entry_owner_state_product_is_exact);
	ATF_TP_ADD_TC(tp, entry_owner_deferred_state_product_is_exact);
	ATF_TP_ADD_TC(tp, entry_owner_deferred_postentry_resolution);
	ATF_TP_ADD_TC(tp, entry_owner_deferred_postentry_state_product_is_exact);
	ATF_TP_ADD_TC(tp, entry_owner_hardware_attempt_is_not_guest_entry);
	return (atf_no_error());
}
