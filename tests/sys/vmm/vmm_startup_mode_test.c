/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_mode.c"

ATF_TC_WITHOUT_HEAD(default_preserves_userspace_contract);
ATF_TC_BODY(default_preserves_userspace_contract, tc)
{
	struct vmm_startup_action_plan plan;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, true, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_EXIT_USERSPACE_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 1);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, true, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_EXIT_USERSPACE_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);
}

ATF_TC_WITHOUT_HEAD(kernel_owner_ap_transitions);
ATF_TC_BODY(kernel_owner_ap_transitions, tc)
{
	struct vmm_startup_action_plan plan;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, true, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 1);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, true, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, false, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_DISCARD_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);
}

ATF_TC_WITHOUT_HEAD(kernel_owner_bsp_init_remains_runnable);
ATF_TC_BODY(kernel_owner_bsp_init_remains_runnable, tc)
{
	struct vmm_startup_action_plan plan;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, true, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 0);
}

ATF_TC_WITHOUT_HEAD(selection_is_immutable);
ATF_TC_BODY(selection_is_immutable, tc)
{
	struct vmm_startup_mode before, mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	before = mode;
	ATF_CHECK_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_USERSPACE), EBUSY);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
	ATF_CHECK_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_USERSPACE_RESUME), EBUSY);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
}

ATF_TC_WITHOUT_HEAD(execution_contract_must_match_owner);
ATF_TC_BODY(execution_contract_must_match_owner, tc)
{
	struct vmm_startup_mode before, mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	before = mode;
	ATF_CHECK_EQ(vmm_startup_mode_lock(&mode), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);

	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	before = mode;
	ATF_CHECK_EQ(vmm_startup_mode_lock(&mode), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
}

ATF_TC_WITHOUT_HEAD(rejection_is_failure_atomic);
ATF_TC_BODY(rejection_is_failure_atomic, tc)
{
	struct vmm_startup_action_plan before, plan;
	struct vmm_startup_mode mode, mode_before;

	(void)tc;
	vmm_startup_mode_init(&mode);
	memset(&plan, 0xa5, sizeof(plan));
	before = plan;
	ATF_CHECK_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, false, &plan), EINVAL);
	ATF_CHECK_EQ(memcmp(&plan, &before, sizeof(plan)), 0);
	mode_before = mode;
	ATF_CHECK_EQ(vmm_startup_mode_configure(&mode,
	    (enum vmm_startup_owner)VMM_STARTUP_OWNER_LAST), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);
	ATF_CHECK_EQ(vmm_startup_mode_configure(&mode,
	    (enum vmm_startup_owner)-1), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);
	ATF_CHECK_EQ(vmm_startup_mode_configure_execution(&mode,
	    (enum vmm_startup_execution)VMM_STARTUP_EXECUTION_LAST), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);
	ATF_CHECK_EQ(vmm_startup_mode_configure_execution(&mode,
	    (enum vmm_startup_execution)-1), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);
	mode.reserved32 = 1;
	mode_before = mode;
	ATF_CHECK_EQ(vmm_startup_mode_lock(&mode), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);

	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	mode_before = mode;
	ATF_CHECK_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, false,
	    (struct vmm_startup_action_plan *)(void *)&mode), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &mode_before, sizeof(mode)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_owner_selection);
ATF_TC_BODY(delivery_owner_selection, tc)
{
	struct vmm_startup_delivery delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	/* Default userspace owner: historical exit route, no publication. */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(delivery.kernel_publication, 0);
	ATF_CHECK_EQ(delivery.reserved16, 0);
	ATF_CHECK_EQ(delivery.reserved32, 0);
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0xab, 2, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(delivery.kernel_publication, 0);
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);

	/* Kernel owner: the caller must publish the whole set atomically. */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 4, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_KERNEL);
	ATF_CHECK_EQ(delivery.kernel_publication, 1);
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 1, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_KERNEL);
	ATF_CHECK_EQ(delivery.kernel_publication, 1);
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_rejects_invalid_kind);
ATF_TC_BODY(delivery_rejects_invalid_kind, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_NONE, 0, 1, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_KIND_LAST, 0, 1, false, false, &delivery),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    (enum vmm_startup_event_kind)-1, 0, 1, false, false, &delivery),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	/* INIT carries no vector; a nonzero vector is a malformed request. */
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 1, 1, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_rejects_empty_target_set);
ATF_TC_BODY(delivery_rejects_empty_target_set, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 0, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 0, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_cancellation_fails_closed);
ATF_TC_BODY(delivery_cancellation_fails_closed, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, true, false, &delivery), ECANCELED);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);

	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 1, true, false, &delivery),
	    ECANCELED);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	/* Cancellation dominates a simultaneously active transaction. */
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 1, true, true, &delivery),
	    ECANCELED);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_checkpoint_blocks_only_kernel_route);
ATF_TC_BODY(delivery_checkpoint_blocks_only_kernel_route, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	/*
	 * The kernel route would publish into a set held immutable by the
	 * active coordinator transaction: fail closed with no fallback.
	 */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, true, &delivery), EBUSY);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 1, false, true, &delivery), EBUSY);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);

	/*
	 * The historical userspace exit publishes nothing, so an active
	 * transaction must not change its behavior.
	 */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, true, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(delivery.kernel_publication, 0);
}

ATF_TC_WITHOUT_HEAD(delivery_requires_locked_owner_after_reset);
ATF_TC_BODY(delivery_requires_locked_owner_after_reset, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	memset(&delivery, 0xa5, sizeof(delivery));
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_KERNEL);

	/*
	 * A reset returns the handshake mode to its unlocked default; no
	 * route may be selected again until the next generation relocks it.
	 */
	vmm_startup_mode_init(&mode);
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 1, false, false, &delivery), EINVAL);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_rejects_aliased_output);
ATF_TC_BODY(delivery_rejects_aliased_output, tc)
{
	struct vmm_startup_mode before, mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	before = mode;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, false,
	    (struct vmm_startup_delivery *)(void *)&mode), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 1, false, false, NULL), EINVAL);
	ATF_CHECK_EQ(memcmp(&mode, &before, sizeof(mode)), 0);
}

ATF_TC_WITHOUT_HEAD(delivery_validation_is_exact);
ATF_TC_BODY(delivery_validation_is_exact, tc)
{
	struct vmm_startup_delivery delivery;

	(void)tc;
	memset(&delivery, 0, sizeof(delivery));
	delivery.owner = VMM_STARTUP_OWNER_USERSPACE;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);
	/* A userspace route must never carry publication authority. */
	delivery.kernel_publication = 1;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	delivery.owner = VMM_STARTUP_OWNER_KERNEL;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);
	/* A kernel route exists only as a published set. */
	delivery.kernel_publication = 0;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	delivery.kernel_publication = 2;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	delivery.kernel_publication = 1;
	delivery.reserved16 = 1;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	delivery.reserved16 = 0;
	delivery.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	delivery.reserved32 = 0;
	delivery.owner = VMM_STARTUP_OWNER_LAST;
	ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), EINVAL);
	ATF_CHECK_EQ(vmm_startup_delivery_validate(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(dispatch_result_run_policy);
ATF_TC_BODY(dispatch_result_run_policy, tc)
{
	struct vmm_startup_dispatch_plan plan;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_dispatch_plan(VMM_STARTUP_DISPATCH_IDLE,
	    &plan), 0);
	ATF_CHECK_EQ(plan.enter_guest, 1);
	ATF_CHECK_EQ(plan.replay_lifecycle, 0);
	ATF_CHECK_EQ(plan.reserved16, 0);
	ATF_CHECK_EQ(plan.reserved32, 0);
	ATF_REQUIRE_EQ(vmm_startup_dispatch_plan(VMM_STARTUP_DISPATCH_RETAINED,
	    &plan), 0);
	ATF_CHECK_EQ(plan.enter_guest, 1);
	ATF_CHECK_EQ(plan.replay_lifecycle, 0);
	ATF_REQUIRE_EQ(vmm_startup_dispatch_plan(VMM_STARTUP_DISPATCH_CONSUMED,
	    &plan), 0);
	ATF_CHECK_EQ(plan.enter_guest, 0);
	ATF_CHECK_EQ(plan.replay_lifecycle, 1);
}

ATF_TC_WITHOUT_HEAD(dispatch_result_rejection_is_failure_atomic);
ATF_TC_BODY(dispatch_result_rejection_is_failure_atomic, tc)
{
	struct vmm_startup_dispatch_plan before, plan;

	(void)tc;
	memset(&plan, 0xa5, sizeof(plan));
	before = plan;
	ATF_CHECK_EQ(vmm_startup_dispatch_plan(
	    VMM_STARTUP_DISPATCH_RESULT_LAST, &plan), EINVAL);
	ATF_CHECK_EQ(memcmp(&plan, &before, sizeof(plan)), 0);
	ATF_CHECK_EQ(vmm_startup_dispatch_plan(
	    (enum vmm_startup_dispatch_result)-1, &plan), EINVAL);
	ATF_CHECK_EQ(memcmp(&plan, &before, sizeof(plan)), 0);
	ATF_CHECK_EQ(vmm_startup_dispatch_plan(VMM_STARTUP_DISPATCH_IDLE,
	    NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_arbitration_exhaustive);
ATF_TC_BODY(entry_arbitration_exhaustive, tc)
{
	struct vmm_startup_entry_snapshot snapshot;
	enum vmm_startup_dispatch_result result;
	enum vmm_startup_entry_action action, expected;
	unsigned int bits;

	(void)tc;
	for (bits = 0; bits < 32; bits++) {
		memset(&snapshot, 0, sizeof(snapshot));
		snapshot.rendezvous = (bits >> 0) & 1;
		snapshot.suspended = (bits >> 1) & 1;
		snapshot.reqidle = (bits >> 2) & 1;
		snapshot.debugged = (bits >> 3) & 1;
		snapshot.waiting = (bits >> 4) & 1;
		if (snapshot.rendezvous != 0)
			expected = VMM_STARTUP_ENTRY_SERVICE_RENDEZVOUS;
		else if (snapshot.suspended != 0)
			expected = VMM_STARTUP_ENTRY_SERVICE_SUSPEND;
		else if (snapshot.reqidle != 0)
			expected = VMM_STARTUP_ENTRY_SERVICE_REQIDLE;
		else if (snapshot.debugged != 0)
			expected = VMM_STARTUP_ENTRY_RETURN_DEBUG;
		else
			expected = VMM_STARTUP_ENTRY_DISPATCH;
		ATF_REQUIRE_EQ(vmm_startup_entry_pre_dispatch(&snapshot,
		    &action), 0);
		ATF_CHECK_EQ(action, expected);
		for (result = VMM_STARTUP_DISPATCH_IDLE;
		    result < VMM_STARTUP_DISPATCH_RESULT_LAST; result++) {
			if (expected != VMM_STARTUP_ENTRY_DISPATCH) {
				ATF_CHECK_EQ(vmm_startup_entry_post_dispatch(&snapshot,
				    result, &action), EINVAL);
				continue;
			}
			ATF_REQUIRE_EQ(vmm_startup_entry_post_dispatch(&snapshot,
			    result, &action), 0);
			if (result == VMM_STARTUP_DISPATCH_CONSUMED)
				expected = VMM_STARTUP_ENTRY_REPLAY;
			else if (result == VMM_STARTUP_DISPATCH_IDLE &&
			    snapshot.waiting != 0)
				expected = VMM_STARTUP_ENTRY_WAIT;
			else
				expected = VMM_STARTUP_ENTRY_ENTER_GUEST;
			ATF_CHECK_EQ(action, expected);
			expected = VMM_STARTUP_ENTRY_DISPATCH;
		}
	}
}

ATF_TC_WITHOUT_HEAD(entry_arbitration_rejection_is_failure_atomic);
ATF_TC_BODY(entry_arbitration_rejection_is_failure_atomic, tc)
{
	struct vmm_startup_entry_snapshot snapshot;
	enum vmm_startup_entry_action action, before;

	(void)tc;
	memset(&snapshot, 0, sizeof(snapshot));
	action = before = VMM_STARTUP_ENTRY_RETURN_DEBUG;
	snapshot.waiting = 2;
	ATF_CHECK_EQ(vmm_startup_entry_pre_dispatch(&snapshot, &action),
	    EINVAL);
	ATF_CHECK_EQ(action, before);
	snapshot.waiting = 0;
	snapshot.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_entry_post_dispatch(&snapshot,
	    VMM_STARTUP_DISPATCH_IDLE, &action), EINVAL);
	ATF_CHECK_EQ(action, before);
	memset(&snapshot, 0, sizeof(snapshot));
	ATF_CHECK_EQ(vmm_startup_entry_post_dispatch(&snapshot,
	    VMM_STARTUP_DISPATCH_RESULT_LAST, &action), EINVAL);
	ATF_CHECK_EQ(action, before);
	ATF_CHECK_EQ(vmm_startup_entry_pre_dispatch(&snapshot,
	    (enum vmm_startup_entry_action *)(void *)&snapshot), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_snapshot_validation_is_exact);
ATF_TC_BODY(entry_snapshot_validation_is_exact, tc)
{
	struct vmm_startup_entry_snapshot snapshot;

	(void)tc;
	memset(&snapshot, 0, sizeof(snapshot));
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(&snapshot), 0);
	snapshot.rendezvous = 1;
	snapshot.suspended = 1;
	snapshot.reqidle = 1;
	snapshot.debugged = 1;
	snapshot.waiting = 1;
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(&snapshot), 0);
	snapshot.waiting = 2;
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(&snapshot), EINVAL);
	snapshot.waiting = 0;
	snapshot.reserved8[2] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(&snapshot), EINVAL);
	snapshot.reserved8[2] = 0;
	snapshot.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(&snapshot), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_snapshot_validate(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_dispatch_admission_is_exact);
ATF_TC_BODY(entry_dispatch_admission_is_exact, tc)
{
	struct vmm_startup_entry_admission admission, before_admission;
	struct vmm_startup_entry_handoff empty_handoff;
	struct vmm_startup_entry_snapshot before, after;
	enum vmm_startup_dispatch_result result;
	enum vmm_startup_entry_action expected;
	union {
		struct vmm_startup_entry_snapshot snapshot;
		struct vmm_startup_entry_admission admission;
	} overlap;
	uint64_t generation_after;
	unsigned int bits, pre_bits;

	(void)tc;
	memset(&before, 0, sizeof(before));
	memset(&empty_handoff, 0, sizeof(empty_handoff));
	for (bits = 0; bits < 32; bits++) {
		memset(&after, 0, sizeof(after));
		after.rendezvous = (bits >> 0) & 1;
		after.suspended = (bits >> 1) & 1;
		after.reqidle = (bits >> 2) & 1;
		after.debugged = (bits >> 3) & 1;
		after.waiting = (bits >> 4) & 1;
		for (result = VMM_STARTUP_DISPATCH_IDLE;
		    result < VMM_STARTUP_DISPATCH_RESULT_LAST; result++) {
			generation_after = result == VMM_STARTUP_DISPATCH_CONSUMED ?
			    101 : 100;
			memset(&admission, 0xa5, sizeof(admission));
			ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&before,
			    &after, result, 100, generation_after, &admission), 0);
			if (after.rendezvous != 0)
				expected = VMM_STARTUP_ENTRY_SERVICE_RENDEZVOUS;
			else if (after.suspended != 0)
				expected = VMM_STARTUP_ENTRY_SERVICE_SUSPEND;
			else if (after.reqidle != 0)
				expected = VMM_STARTUP_ENTRY_SERVICE_REQIDLE;
			else if (after.debugged != 0)
				expected = VMM_STARTUP_ENTRY_RETURN_DEBUG;
			else if (result == VMM_STARTUP_DISPATCH_CONSUMED)
				expected = VMM_STARTUP_ENTRY_REPLAY;
			else if (result == VMM_STARTUP_DISPATCH_IDLE &&
			    after.waiting != 0)
				expected = VMM_STARTUP_ENTRY_WAIT;
			else
				expected = VMM_STARTUP_ENTRY_ENTER_GUEST;
			ATF_CHECK_EQ(admission.action, expected);
			ATF_CHECK_EQ(vmm_startup_entry_admission_validate(
			    &admission), 0);
			if (expected == VMM_STARTUP_ENTRY_ENTER_GUEST) {
				ATF_CHECK_EQ(admission.handoff.armed, 1);
				ATF_CHECK_EQ(admission.handoff.notification_generation,
				    generation_after);
			} else {
				ATF_CHECK_EQ(memcmp(&admission.handoff,
				    &empty_handoff, sizeof(empty_handoff)), 0);
			}
		}
	}

	/*
	 * RETAINED is not a sleep result.  The guest must run to remove the
	 * architectural blocker which kept the claim live; unlike IDLE, no
	 * independent notification is guaranteed to wake a retained waiter.
	 */
	memset(&before, 0, sizeof(before));
	memset(&after, 0, sizeof(after));
	after.waiting = 1;
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_RETAINED, 300, 300, &admission), 0);
	ATF_CHECK_EQ(admission.action, VMM_STARTUP_ENTRY_ENTER_GUEST);
	ATF_CHECK_EQ(admission.handoff.armed, 1);
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_IDLE, 300, 300, &admission), 0);
	ATF_CHECK_EQ(admission.action, VMM_STARTUP_ENTRY_WAIT);
	ATF_CHECK_EQ(memcmp(&admission.handoff, &empty_handoff,
	    sizeof(empty_handoff)), 0);

	/* Non-entry actions require a semantically empty handoff field-by-field. */
	memset(&admission, 0, sizeof(admission));
	admission.action = VMM_STARTUP_ENTRY_WAIT;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), 0);
	admission.handoff.notification_generation = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.handoff.notification_generation = 0;
	admission.handoff.armed = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.handoff.armed = 0;
	admission.handoff.reserved = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);

	/*
	 * Independently enumerate the pre-dispatch product.  In particular,
	 * waiting without lifecycle work remains dispatchable: a pending SIPI
	 * must have the opportunity to clear the predicate before any sleep.
	 */
	memset(&after, 0, sizeof(after));
	for (pre_bits = 0; pre_bits < 32; pre_bits++) {
		memset(&before, 0, sizeof(before));
		before.rendezvous = (pre_bits >> 0) & 1;
		before.suspended = (pre_bits >> 1) & 1;
		before.reqidle = (pre_bits >> 2) & 1;
		before.debugged = (pre_bits >> 3) & 1;
		before.waiting = (pre_bits >> 4) & 1;
		for (result = VMM_STARTUP_DISPATCH_IDLE;
		    result < VMM_STARTUP_DISPATCH_RESULT_LAST; result++) {
			generation_after = result == VMM_STARTUP_DISPATCH_CONSUMED ?
			    201 : 200;
			memset(&admission, 0xa5, sizeof(admission));
			before_admission = admission;
			if (before.rendezvous != 0 || before.suspended != 0 ||
			    before.reqidle != 0 || before.debugged != 0) {
				ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before,
				    &after, result, 200, generation_after,
				    &admission), EINVAL);
				ATF_CHECK_EQ(memcmp(&admission, &before_admission,
				    sizeof(admission)), 0);
				continue;
			}
			ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&before,
			    &after, result, 200, generation_after, &admission), 0);
			expected = result == VMM_STARTUP_DISPATCH_CONSUMED ?
			    VMM_STARTUP_ENTRY_REPLAY : VMM_STARTUP_ENTRY_ENTER_GUEST;
			ATF_CHECK_EQ(admission.action, expected);
		}
	}

	/* A pre-existing lifecycle request means dispatch was never admissible. */
	memset(&before, 0, sizeof(before));
	memset(&after, 0, sizeof(after));
	memset(&admission, 0xa5, sizeof(admission));
	before.rendezvous = 1;
	before_admission = admission;
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_IDLE, 1, 1, &admission), EINVAL);
	ATF_CHECK_EQ(memcmp(&admission, &before_admission,
	    sizeof(admission)), 0);

	memset(&before, 0, sizeof(before));
	after.reserved8[1] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_IDLE, 1, 1, &admission), EINVAL);
	ATF_CHECK_EQ(memcmp(&admission, &before_admission,
	    sizeof(admission)), 0);
	memset(&after, 0, sizeof(after));
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_IDLE, 10, 11, &admission), EAGAIN);
	ATF_CHECK_EQ(memcmp(&admission, &before_admission,
	    sizeof(admission)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_CONSUMED, UINT64_MAX, UINT64_MAX,
	    &admission), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&admission, &before_admission,
	    sizeof(admission)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_RESULT_LAST, 1, 1, &admission), EINVAL);
	ATF_CHECK_EQ(memcmp(&admission, &before_admission,
	    sizeof(admission)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before, &after,
	    VMM_STARTUP_DISPATCH_IDLE, 1, 1, NULL), EINVAL);

	memset(&overlap, 0, sizeof(overlap));
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&overlap.snapshot,
	    &after, VMM_STARTUP_DISPATCH_IDLE, 1, 1,
	    &overlap.admission), EINVAL);
	memset(&overlap, 0, sizeof(overlap));
	memset(&before, 0, sizeof(before));
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&before,
	    &overlap.snapshot, VMM_STARTUP_DISPATCH_IDLE, 1, 1,
	    &overlap.admission), EINVAL);

	memset(&admission, 0, sizeof(admission));
	admission.action = VMM_STARTUP_ENTRY_DISPATCH;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.action = VMM_STARTUP_ENTRY_ACTION_LAST;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.action = VMM_STARTUP_ENTRY_WAIT;
	admission.handoff.armed = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	memset(&admission, 0, sizeof(admission));
	admission.action = VMM_STARTUP_ENTRY_ENTER_GUEST;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.handoff.notification_generation = 1;
	admission.handoff.armed = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), 0);
	admission.reserved32 = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	admission.reserved32 = 0;
	admission.reserved8[2] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_handoff_detects_preentry_notification);
ATF_TC_BODY(entry_handoff_detects_preentry_notification, tc)
{
	struct vmm_startup_entry_handoff handoff;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(41,
	    VMM_STARTUP_DISPATCH_CONSUMED, 42, &handoff), 0);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_check(42, &handoff), 0);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_check(43, &handoff), EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_disarm(43, &handoff), EAGAIN);
	ATF_CHECK_EQ(handoff.notification_generation, 42);
	ATF_CHECK_EQ(handoff.armed, 1);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_disarm(42, &handoff), 0);
	ATF_CHECK_EQ(handoff.notification_generation, 0);
	ATF_CHECK_EQ(handoff.armed, 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(51,
	    VMM_STARTUP_DISPATCH_IDLE, 51, &handoff), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_disarm(51, &handoff), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(61,
	    VMM_STARTUP_DISPATCH_RETAINED, 61, &handoff), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_disarm(61, &handoff), 0);

	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(71,
	    VMM_STARTUP_DISPATCH_IDLE, 72, &handoff), EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(81,
	    VMM_STARTUP_DISPATCH_RETAINED, 82, &handoff), EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(91,
	    VMM_STARTUP_DISPATCH_CONSUMED, 91, &handoff), EAGAIN);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(101,
	    VMM_STARTUP_DISPATCH_CONSUMED, 103, &handoff), EAGAIN);
	ATF_CHECK_EQ(memcmp(&handoff,
	    &(struct vmm_startup_entry_handoff){ 0 }, sizeof(handoff)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_handoff_rejection_is_failure_atomic);
ATF_TC_BODY(entry_handoff_rejection_is_failure_atomic, tc)
{
	struct vmm_startup_entry_handoff before, handoff;

	(void)tc;
	memset(&handoff, 0, sizeof(handoff));
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(0,
	    VMM_STARTUP_DISPATCH_IDLE, 1, &handoff), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(1,
	    VMM_STARTUP_DISPATCH_IDLE, 0, &handoff), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(1,
	    (enum vmm_startup_dispatch_result)-1, 1, &handoff), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(1,
	    VMM_STARTUP_DISPATCH_RESULT_LAST, 1, &handoff), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(UINT64_MAX,
	    VMM_STARTUP_DISPATCH_CONSUMED, UINT64_MAX, &handoff), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&handoff, &(struct vmm_startup_entry_handoff){ 0 },
	    sizeof(handoff)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_capture(UINT64_MAX,
	    VMM_STARTUP_DISPATCH_IDLE, UINT64_MAX, &handoff), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_handoff_disarm(UINT64_MAX, &handoff), 0);
	handoff.reserved = 1;
	before = handoff;
	ATF_CHECK_EQ(vmm_startup_entry_handoff_capture(1,
	    VMM_STARTUP_DISPATCH_IDLE, 1, &handoff), EINVAL);
	ATF_CHECK_EQ(memcmp(&handoff, &before, sizeof(handoff)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_check(1, &handoff), EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_handoff_disarm(1, &handoff), EINVAL);
	ATF_CHECK_EQ(memcmp(&handoff, &before, sizeof(handoff)), 0);
}

ATF_TC_WITHOUT_HEAD(notification_generation_boundaries);
ATF_TC_BODY(notification_generation_boundaries, tc)
{
	uint64_t next;

	(void)tc;
	ATF_CHECK_EQ(vmm_startup_notification_generation_capture(0), 1);
	ATF_CHECK_EQ(vmm_startup_notification_generation_capture(1), 1);
	ATF_CHECK_EQ(vmm_startup_notification_generation_capture(UINT64_MAX),
	    UINT64_MAX);
	next = 99;
	ATF_REQUIRE_EQ(vmm_startup_notification_advance(0, &next), 0);
	ATF_CHECK_EQ(next, 1);
	ATF_REQUIRE_EQ(vmm_startup_notification_advance(1, &next), 0);
	ATF_CHECK_EQ(next, 2);
	ATF_REQUIRE_EQ(vmm_startup_notification_advance(UINT64_MAX - 1,
	    &next), 0);
	ATF_CHECK_EQ(next, UINT64_MAX);
	next = 73;
	ATF_CHECK_EQ(vmm_startup_notification_advance(UINT64_MAX, &next),
	    EOVERFLOW);
	ATF_CHECK_EQ(next, 73);
	ATF_CHECK_EQ(vmm_startup_notification_advance(1, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(entry_runtime_exact_unwind);
ATF_TC_BODY(entry_runtime_exact_unwind, tc)
{
	struct vmm_startup_entry_runtime runtime;
	struct vmm_startup_entry_runtime_result result;

	(void)tc;
	vmm_startup_entry_runtime_init(&runtime);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);
	memset(&result, 0xa5, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_check(&runtime, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.reserved8[0], 0);
	ATF_CHECK_EQ(result.reserved8[1], 0);
	ATF_CHECK_EQ(result.reserved8[2], 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_CHECKED);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_frozen(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_save_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_exit_critical(&runtime), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_COMPLETE);
	ATF_CHECK_EQ(runtime.critical, 0);
	ATF_CHECK_EQ(runtime.guest_fpu, 0);
	ATF_CHECK_EQ(runtime.running, 0);
}

ATF_TC_WITHOUT_HEAD(entry_runtime_replay_and_error_unwind);
ATF_TC_BODY(entry_runtime_replay_and_error_unwind, tc)
{
	struct vmm_startup_entry_runtime before, runtime;
	struct vmm_startup_entry_runtime_result result;
	const struct {
		int coordinator;
		int notification;
		int expected;
	} errors[] = {
		{ EAGAIN, 0, EAGAIN },
		{ 0, EAGAIN, EAGAIN },
		{ EAGAIN, EAGAIN, EAGAIN },
		{ EBUSY, 0, EBUSY },
		{ 0, EINVAL, EINVAL },
		{ EBUSY, EAGAIN, EBUSY },
		{ EAGAIN, EBUSY, EBUSY },
		{ EAGAIN, EINVAL, EINVAL },
		{ EINVAL, EAGAIN, EINVAL },
		{ EBUSY, EBUSY, EBUSY },
		{ EBUSY, EINVAL, EPROTO },
		{ EINVAL, EBUSY, EPROTO },
	};
	size_t i;

	(void)tc;
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		int error;

		error = errors[i].expected;
		vmm_startup_entry_runtime_init(&runtime);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(
		    &runtime), 0);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(
		    &runtime), 0);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(
		    &runtime), 0);
		before = runtime;
		memset(&result, 0, sizeof(result));
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_check(&runtime,
		    errors[i].coordinator, errors[i].notification, &result), 0);
		ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);
		ATF_CHECK_EQ(result.error, error);
		ATF_CHECK_EQ(result.action, error == EAGAIN ?
		    VMM_STARTUP_ENTRY_RUNTIME_REPLAY :
		    VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR);
		ATF_CHECK_EQ(result.reserved8[0], 0);
		ATF_CHECK_EQ(result.reserved8[1], 0);
		ATF_CHECK_EQ(result.reserved8[2], 0);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_frozen(
		    &runtime), 0);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_save_guest_fpu(
		    &runtime), 0);
		ATF_REQUIRE_EQ(vmm_startup_entry_runtime_exit_critical(
		    &runtime), 0);
		ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_COMPLETE);
	}
}

ATF_TC_WITHOUT_HEAD(entry_runtime_rechecks_each_hardware_entry);
ATF_TC_BODY(entry_runtime_rechecks_each_hardware_entry, tc)
{
	struct vmm_startup_entry_runtime before, runtime;
	struct vmm_startup_entry_runtime_result result;

	(void)tc;
	vmm_startup_entry_runtime_init(&runtime);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);

	memset(&result, 0xff, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_check(&runtime, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_CHECKED);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);

	/* A backend-internal exit and re-entry must validate the same guard. */
	memset(&result, 0xff, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_check(&runtime, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_CHECKED);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);

	/* Publication between backend entries forces common frozen replay. */
	before = runtime;
	memset(&result, 0, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_check(&runtime, EAGAIN,
	    EAGAIN, &result), 0);
	ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_RUNTIME_REPLAY);

	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_frozen(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_save_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_exit_critical(&runtime), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_COMPLETE);
}

ATF_TC_WITHOUT_HEAD(entry_runtime_rejects_invalid_order);
ATF_TC_BODY(entry_runtime_rejects_invalid_order, tc)
{
	struct vmm_startup_entry_runtime before, malformed, runtime;
	struct vmm_startup_entry_runtime_result before_result, result;

	(void)tc;
	vmm_startup_entry_runtime_init(&runtime);
	before = runtime;
	memset(&result, 0xa5, sizeof(result));
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_runtime_publish_running(&runtime),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_runtime_check(&runtime, 0, 0, &result),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);
	before = runtime;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_check(&runtime, -1, 0, &result),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_runtime_check(&runtime, 0, 0,
	    (struct vmm_startup_entry_runtime_result *)(void *)&runtime),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);

	malformed = runtime;
	malformed.reserved = 1;
	before = malformed;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_check(&malformed, 0, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&malformed, &before, sizeof(malformed)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);

	malformed = runtime;
	malformed.critical = 2;
	before = malformed;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_publish_frozen(&malformed),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&malformed, &before, sizeof(malformed)), 0);

	malformed = runtime;
	malformed.phase = VMM_STARTUP_ENTRY_RUNTIME_COMPLETE;
	before = malformed;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_publish_frozen(&malformed),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&malformed, &before, sizeof(malformed)), 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_frozen(&runtime), 0);
	before = runtime;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_exit_critical(&runtime), EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_save_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_exit_critical(&runtime), 0);
	before = runtime;
	ATF_CHECK_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before, sizeof(runtime)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_loop_requires_check_before_each_entry);
ATF_TC_BODY(entry_loop_requires_check_before_each_entry, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	struct vmm_startup_entry_loop loop;
	struct vmm_startup_entry_loop_result result;

	(void)tc;
	vmm_startup_entry_loop_init(&loop);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_NEED_CHECK);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_NEED_CHECK);
	ATF_CHECK_EQ(vmm_startup_entry_loop_enter(&loop), EINVAL);

	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_CHECK_EQ(loop.check_count, 2);
	ATF_CHECK_EQ(loop.entry_count, 2);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, false, 0), 0);
	result = (struct vmm_startup_entry_loop_result){
		.error = EBUSY,
		.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR,
	};
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_finish(&loop, &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
	ATF_CHECK_EQ(result.reserved8[0], 0);
	ATF_CHECK_EQ(result.reserved8[1], 0);
	ATF_CHECK_EQ(result.reserved8[2], 0);
}

ATF_TC_WITHOUT_HEAD(entry_loop_drift_after_handled_exit_returns);
ATF_TC_BODY(entry_loop_drift_after_handled_exit_returns, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	const struct vmm_startup_entry_runtime_result replay = {
		.error = EAGAIN,
		.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY,
	};
	struct vmm_startup_entry_loop loop;
	struct vmm_startup_entry_loop_result result;

	(void)tc;
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &replay), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_RETURNABLE);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(vmm_startup_entry_loop_enter(&loop), EINVAL);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_finish(&loop, &result), 0);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
}

ATF_TC_WITHOUT_HEAD(entry_loop_distinguishes_no_entry_returns);
ATF_TC_BODY(entry_loop_distinguishes_no_entry_returns, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	struct vmm_startup_entry_loop_result before_result, result;
	struct vmm_startup_entry_loop before, loop;

	(void)tc;
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_software_exit(&loop, &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 0);
	ATF_CHECK_EQ(loop.entry_count, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(result.error, 0);

	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, EAGAIN,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, EIO,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);

	/* A later software exit retains the prior handled-entry history. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_software_exit(&loop, &result), 0);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);

	/* A failed preparation before the next entry retains prior history. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, EAGAIN,
	    &result), 0);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, EIO,
	    &result), 0);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);

	/* Invalid shape and aliasing preserve both values. */
	vmm_startup_entry_loop_init(&loop);
	memset(&result, 0xa5, sizeof(result));
	before = loop;
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_fail_before_entry(&loop, -1,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_software_exit(&loop,
	    (struct vmm_startup_entry_loop_result *)(void *)&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_loop_owns_return_disposition);
ATF_TC_BODY(entry_loop_owns_return_disposition, tc)
{
	struct vmm_startup_entry_runtime_result replay = {
		.error = EAGAIN,
		.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY,
	};
	struct vmm_startup_entry_runtime_result terminal = {
		.error = EBUSY,
		.action = VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR,
	};
	struct vmm_startup_entry_loop_result result;
	struct vmm_startup_entry_loop loop;

	(void)tc;
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &replay), 0);
	replay.error = EBUSY;
	replay.action = VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR;
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_finish(&loop, &result), 0);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.reserved8[0], 0);
	ATF_CHECK_EQ(result.reserved8[1], 0);
	ATF_CHECK_EQ(result.reserved8[2], 0);

	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &terminal), 0);
	terminal.error = EAGAIN;
	terminal.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY;
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_finish(&loop, &result), 0);
	ATF_CHECK_EQ(result.error, EBUSY);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
}

ATF_TC_WITHOUT_HEAD(entry_loop_rejects_malformed_and_overflow);
ATF_TC_BODY(entry_loop_rejects_malformed_and_overflow, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	const struct vmm_startup_entry_runtime_result bad_results[] = {
		{ .error = EBUSY,
		  .action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST },
		{ .error = 0, .action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY },
		{ .error = EAGAIN,
		  .action = VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR },
		{ .error = -1,
		  .action = VMM_STARTUP_ENTRY_RUNTIME_RETURN_ERROR },
		{ .error = EBUSY,
		  .action = VMM_STARTUP_ENTRY_RUNTIME_ACTION_LAST },
		{ .error = 0,
		  .action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
		  .reserved8 = { 1, 0, 0 } },
	};
	struct vmm_startup_entry_loop_result result, result_before;
	struct vmm_startup_entry_loop before, loop;
	size_t i;

	(void)tc;
	vmm_startup_entry_loop_init(&loop);
	for (i = 0; i < sizeof(bad_results) / sizeof(bad_results[0]); i++) {
		before = loop;
		ATF_CHECK_EQ(vmm_startup_entry_loop_check(&loop,
		    &bad_results[i]), EINVAL);
		ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	}
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_check(&loop,
	    (const struct vmm_startup_entry_runtime_result *)(const void *)&loop),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);

	loop.check_count = UINT64_MAX;
	loop.entry_count = UINT64_MAX;
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_check(&loop, &enter), EOVERFLOW);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);

	loop = (struct vmm_startup_entry_loop){ 0 };
	loop.reserved8[6] = 1;
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_check(&loop, &enter), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	loop = (struct vmm_startup_entry_loop){
		.check_count = 2,
		.entry_count = 0,
		.phase = VMM_STARTUP_ENTRY_LOOP_CHECKED,
	};
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_enter(&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	loop = (struct vmm_startup_entry_loop){
		.disposition = {
			.error = EBUSY,
			.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR,
		},
		.phase = VMM_STARTUP_ENTRY_LOOP_NEED_CHECK,
	};
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_check(&loop, &enter), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);

	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop,
	    &(const struct vmm_startup_entry_runtime_result){
		.error = EAGAIN,
		.action = VMM_STARTUP_ENTRY_RUNTIME_REPLAY,
	    }), 0);
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_finish(&loop, NULL), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_finish(&loop,
	    (struct vmm_startup_entry_loop_result *)(void *)&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	result = (struct vmm_startup_entry_loop_result){
		.error = EBUSY,
		.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR,
	};
	result_before = result;
	loop.disposition.reserved8[2] = 1;
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_finish(&loop, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
	loop = (struct vmm_startup_entry_loop){
		.disposition = {
			.error = 0,
			.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR,
		},
		.phase = VMM_STARTUP_ENTRY_LOOP_RETURNABLE,
	};
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_finish(&loop, &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &result_before, sizeof(result)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_guard_admission_is_failure_atomic);
ATF_TC_BODY(entry_guard_admission_is_failure_atomic, tc)
{
	struct vmm_startup_entry_runtime_result before_result, result;
	struct vmm_startup_entry_runtime before_runtime, runtime;
	struct vmm_startup_entry_loop_result loop_result;
	struct vmm_startup_entry_loop before_loop, loop;

	(void)tc;
	vmm_startup_entry_runtime_init(&runtime);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);
	vmm_startup_entry_loop_init(&loop);
	memset(&result, 0xa5, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_CHECKED);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_IN_GUEST);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST);
	ATF_CHECK_EQ(result.error, 0);

	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, EAGAIN,
	    EAGAIN, &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_RETURNABLE);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_RUNTIME_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_finish(&loop, &loop_result), 0);
	ATF_CHECK_EQ(loop_result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(loop_result.error, EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_frozen(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_save_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_exit_critical(&runtime), 0);
	ATF_CHECK_EQ(runtime.phase, VMM_STARTUP_ENTRY_RUNTIME_COMPLETE);

	/* A late loop validation failure cannot advance the runtime alone. */
	vmm_startup_entry_runtime_init(&runtime);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);
	vmm_startup_entry_loop_init(&loop);
	loop.reserved8[0] = 1;
	memset(&result, 0x5a, sizeof(result));
	before_runtime = runtime;
	before_loop = loop;
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before_runtime, sizeof(runtime)), 0);
	ATF_CHECK_EQ(memcmp(&loop, &before_loop, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);

	ATF_CHECK_EQ(vmm_startup_entry_guard_before(&runtime,
	    (struct vmm_startup_entry_loop *)(void *)&runtime, 0, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&runtime, &before_runtime, sizeof(runtime)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_guard_return_is_failure_atomic);
ATF_TC_BODY(entry_guard_return_is_failure_atomic, tc)
{
	struct vmm_startup_entry_runtime_result admission;
	struct vmm_startup_entry_runtime runtime;
	struct vmm_startup_entry_loop_result before_result, result;
	struct vmm_startup_entry_loop before, loop;

	(void)tc;
	vmm_startup_entry_runtime_init(&runtime);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_enter_critical(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_restore_guest_fpu(&runtime), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_runtime_publish_running(&runtime), 0);
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &admission), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_after(&loop, true, 0, NULL), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_NEED_CHECK);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);

	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &admission), 0);
	memset(&result, 0xa5, sizeof(result));
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_after(&loop, false, 0,
	    &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 2);
	ATF_CHECK_EQ(loop.entry_count, 2);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
	ATF_CHECK_EQ(result.error, 0);

	/* Post-entry retry and terminal failures retain their exact domain. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &admission), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_after(&loop, false, EAGAIN,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &admission), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_after(&loop, false, EIO,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);

	/* Shape and alias failures preserve both owner and caller output. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_before(&runtime, &loop, 0, 0,
	    &admission), 0);
	memset(&result, 0x5a, sizeof(result));
	before = loop;
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_guard_after(&loop, true, EIO, NULL),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_guard_after(&loop, false, -1, &result),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_guard_after(&loop, true, 0, &result),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_guard_after(&loop, false, 0, NULL),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_guard_after(&loop, false, 0,
	    (struct vmm_startup_entry_loop_result *)(void *)&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
}

ATF_TC_WITHOUT_HEAD(entry_guard_completion_closes_final_return_window);
ATF_TC_BODY(entry_guard_completion_closes_final_return_window, tc)
{
	const struct vmm_startup_entry_loop_result normal = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT,
	};
	const struct vmm_startup_entry_loop_result software = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT,
	};
	const struct vmm_startup_entry_loop_result replay = {
		.error = EAGAIN,
		.action = VMM_STARTUP_ENTRY_LOOP_REPLAY,
	};
	const struct vmm_startup_entry_loop_result terminal = {
		.error = EIO,
		.action = VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR,
	};
	struct vmm_startup_entry_loop_result before, malformed, result;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&normal, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_VMEXIT);
	ATF_CHECK_EQ(result.error, 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&software, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(result.error, 0);

	/* Drift after the last hardware exit overrides a normal return. */
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&normal, EAGAIN, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&software, EAGAIN, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&normal, EAGAIN,
	    EAGAIN, &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&replay, 0, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_REPLAY);
	ATF_CHECK_EQ(result.error, EAGAIN);

	/* A backend or owner terminal error dominates replay. */
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&terminal, EAGAIN, 0,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&normal, EIO, EIO,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_REQUIRE_EQ(vmm_startup_entry_guard_complete(&normal, EIO, ESTALE,
	    &result), 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EPROTO);

	/* Malformed input and aliasing preserve caller output exactly. */
	memset(&result, 0xa5, sizeof(result));
	before = result;
	ATF_CHECK_EQ(vmm_startup_entry_guard_complete(&normal, -1, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	malformed = normal;
	malformed.reserved8[1] = 1;
	ATF_CHECK_EQ(vmm_startup_entry_guard_complete(&malformed, 0, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_guard_complete(&normal, 0, 0, NULL),
	    EINVAL);
	ATF_CHECK_EQ(vmm_startup_entry_guard_complete(&result, 0, 0,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&result, &before, sizeof(result)), 0);
}

/*
 * Step-7 scenario coverage.  These cases compose the already-tested primitive
 * decisions into the exact frozen INIT/SIPI machine-transaction and
 * wait-for-SIPI scheduler scenarios named by the nested-VMX requirement ledger
 * (NVMX-EVENT-048/050/058/102).  They exercise only the common,
 * architecture-neutral decision functions; the Intel adapter binds these to
 * vmm_x86_startup_machine_execute and the AMD adapter remains fail-closed.
 */

/*
 * NVMX-EVENT-102 / NVMX-EVENT-058: under kernel ownership a single INIT target
 * set restarts the BSP at its reset path (no wait) while every AP enters
 * wait-for-SIPI, decided purely from the per-target architectural BSP role.
 */
ATF_TC_WITHOUT_HEAD(startup_init_ap_waits_while_bsp_restarts);
ATF_TC_BODY(startup_init_ap_waits_while_bsp_restarts, tc)
{
	struct vmm_startup_action_plan plan;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);

	/* The BSP restarts at the reset vector and must remain runnable. */
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, true, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 0);

	/* A non-BSP AP enters wait-for-SIPI on the same INIT. */
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 1);

	/*
	 * The historical userspace owner never leaves the BSP runnable in the
	 * kernel; it suspends every INIT destination and preserves the exit.
	 */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_INIT, false, true, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_EXIT_USERSPACE_INIT);
	ATF_CHECK_EQ(plan.startup_wait, 1);
}

/*
 * NVMX-EVENT-050: a SIPI is applied only to a target already in wait-for-SIPI;
 * a SIPI to any other run state is architecturally discarded.
 */
ATF_TC_WITHOUT_HEAD(startup_sipi_accepted_only_in_wait_for_sipi);
ATF_TC_BODY(startup_sipi_accepted_only_in_wait_for_sipi, tc)
{
	struct vmm_startup_action_plan plan;
	struct vmm_startup_mode mode;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);

	/* Accepted: target is waiting; the CS:RIP startup state is applied. */
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, true, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_APPLY_KERNEL_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);

	/* Not waiting: the SIPI is discarded and no state changes. */
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, false, false, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_DISCARD_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);

	/* The BSP role does not make a non-waiting SIPI acceptable. */
	memset(&plan, 0xa5, sizeof(plan));
	ATF_REQUIRE_EQ(vmm_startup_action_plan(&mode,
	    VMM_STARTUP_EVENT_SIPI, false, true, &plan), 0);
	ATF_CHECK_EQ(plan.action, VMM_STARTUP_ACTION_DISCARD_SIPI);
	ATF_CHECK_EQ(plan.startup_wait, 0);
}

/*
 * NVMX-EVENT-050 / NVMX-EVENT-058: a mixed BSP+AP kernel target set of any size
 * routes to exactly one atomic kernel publication, and a cancelled or
 * checkpoint-frozen coordinator fails that route closed without a partial
 * output that a fallback could deliver twice.  NVMX-EVENT-048: the default
 * userspace owner never publishes for any target set.
 */
ATF_TC_WITHOUT_HEAD(startup_mixed_target_publishes_one_kernel_set);
ATF_TC_BODY(startup_mixed_target_publishes_one_kernel_set, tc)
{
	struct vmm_startup_delivery before, delivery;
	struct vmm_startup_mode mode;
	size_t counts[] = { 1, 2, 8, 64 };
	size_t i;

	(void)tc;
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure(&mode,
	    VMM_STARTUP_OWNER_KERNEL), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_configure_execution(&mode,
	    VMM_STARTUP_EXECUTION_PRESTARTED_WAIT), 0);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);

	for (i = 0; i < nitems(counts); i++) {
		memset(&delivery, 0xa5, sizeof(delivery));
		ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
		    VMM_STARTUP_EVENT_INIT, 0, counts[i], false, false,
		    &delivery), 0);
		ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_KERNEL);
		ATF_CHECK_EQ(delivery.kernel_publication, 1);
		ATF_CHECK_EQ(vmm_startup_delivery_validate(&delivery), 0);

		memset(&delivery, 0xa5, sizeof(delivery));
		ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
		    VMM_STARTUP_EVENT_SIPI, 0xab, counts[i], false, false,
		    &delivery), 0);
		ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_KERNEL);
		ATF_CHECK_EQ(delivery.kernel_publication, 1);
	}

	/* A cancelled coordinator admits no route and leaves output intact. */
	memset(&delivery, 0xa5, sizeof(delivery));
	before = delivery;
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 8, true, false, &delivery), ECANCELED);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);

	/* An active checkpoint blocks only the kernel publication route. */
	ATF_CHECK_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_SIPI, 0x10, 8, false, true, &delivery), EBUSY);
	ATF_CHECK_EQ(memcmp(&delivery, &before, sizeof(delivery)), 0);

	/* The default userspace owner publishes nothing, whatever the set. */
	vmm_startup_mode_init(&mode);
	ATF_REQUIRE_EQ(vmm_startup_mode_lock(&mode), 0);
	ATF_REQUIRE_EQ(vmm_startup_delivery_decide(&mode,
	    VMM_STARTUP_EVENT_INIT, 0, 64, false, false, &delivery), 0);
	ATF_CHECK_EQ(delivery.owner, VMM_STARTUP_OWNER_USERSPACE);
	ATF_CHECK_EQ(delivery.kernel_publication, 0);
}

/*
 * NVMX-EVENT-058: a waiting AP sleeps on a generation-bound event and cannot
 * lose a wakeup.  A dispatch that consumes a SIPI claim advances the
 * notification generation exactly once and replays; a wake published in the
 * otherwise silent frozen window is observed as a generation mismatch and
 * forces a replay instead of a lost sleep; only a truly quiescent window lets
 * the AP wait.
 */
ATF_TC_WITHOUT_HEAD(startup_wait_for_sipi_wakeup_not_lost);
ATF_TC_BODY(startup_wait_for_sipi_wakeup_not_lost, tc)
{
	struct vmm_startup_entry_snapshot waiting, runnable;
	struct vmm_startup_entry_admission admission;

	(void)tc;
	memset(&waiting, 0, sizeof(waiting));
	waiting.waiting = 1;
	memset(&runnable, 0, sizeof(runnable));

	/* Quiescent frozen window: the AP is allowed to sleep. */
	memset(&admission, 0xa5, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&waiting, &waiting,
	    VMM_STARTUP_DISPATCH_IDLE, 100, 100, &admission), 0);
	ATF_CHECK_EQ(admission.action, VMM_STARTUP_ENTRY_WAIT);
	ATF_CHECK_EQ(admission.handoff.armed, 0);
	/* A wait admission must carry no armed handoff residue whatsoever. */
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), 0);

	/* A concurrent wake published while frozen forces a replay, not sleep. */
	memset(&admission, 0xa5, sizeof(admission));
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&waiting, &waiting,
	    VMM_STARTUP_DISPATCH_IDLE, 100, 101, &admission), EAGAIN);

	/* A consumed SIPI claim advances the generation once and replays. */
	memset(&admission, 0xa5, sizeof(admission));
	ATF_REQUIRE_EQ(vmm_startup_entry_dispatch_admit(&waiting, &runnable,
	    VMM_STARTUP_DISPATCH_CONSUMED, 100, 101, &admission), 0);
	ATF_CHECK_EQ(admission.action, VMM_STARTUP_ENTRY_REPLAY);
	ATF_CHECK_EQ(admission.handoff.armed, 0);
	ATF_CHECK_EQ(vmm_startup_entry_admission_validate(&admission), 0);

	/* A consumed claim with an extra frozen-window publication replays. */
	memset(&admission, 0xa5, sizeof(admission));
	ATF_CHECK_EQ(vmm_startup_entry_dispatch_admit(&waiting, &runnable,
	    VMM_STARTUP_DISPATCH_CONSUMED, 100, 102, &admission), EAGAIN);
}

/*
 * A CHECKED loop records an admission whose hardware entry has not yet
 * happened.  Rejecting that admission as a software exit must undo the pending
 * check (so the completed record shows no fictitious entry), publish a
 * software-exit disposition with no error, and complete the loop.  Prior
 * committed entry history must survive intact.
 */
ATF_TC_WITHOUT_HEAD(entry_loop_software_exit_from_checked);
ATF_TC_BODY(entry_loop_software_exit_from_checked, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	struct vmm_startup_entry_loop_result before_result, result;
	struct vmm_startup_entry_loop before, loop;

	(void)tc;

	/* First admission ever: undoing it leaves a balanced empty record. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_CHECKED);
	ATF_REQUIRE_EQ(loop.check_count, 1);
	ATF_REQUIRE_EQ(loop.entry_count, 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_software_exit_checked(&loop,
	    &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 0);
	ATF_CHECK_EQ(loop.entry_count, 0);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.reserved8[0], 0);
	ATF_CHECK_EQ(result.reserved8[1], 0);
	ATF_CHECK_EQ(result.reserved8[2], 0);

	/* A rejected re-check after a completed entry retains that entry. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_CHECKED);
	ATF_REQUIRE_EQ(loop.check_count, 2);
	ATF_REQUIRE_EQ(loop.entry_count, 1);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_software_exit_checked(&loop,
	    &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action,
	    VMM_STARTUP_ENTRY_LOOP_RETURN_SOFTWARE_EXIT);
	ATF_CHECK_EQ(result.error, 0);

	/* Wrong phase, NULL result, and aliasing all fail atomically. */
	vmm_startup_entry_loop_init(&loop);
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_software_exit_checked(&loop,
	    &result), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);

	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	memset(&result, 0xa5, sizeof(result));
	before = loop;
	before_result = result;
	ATF_CHECK_EQ(vmm_startup_entry_loop_software_exit_checked(&loop, NULL),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_software_exit_checked(&loop,
	    (struct vmm_startup_entry_loop_result *)(void *)&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)), 0);
}

/*
 * Failing a CHECKED admission behaves like the software-exit rejection but
 * records a terminal error disposition.  Only positive, non-EAGAIN errors are
 * terminal; EAGAIN (replay) and non-positive values must be rejected.
 */
ATF_TC_WITHOUT_HEAD(entry_loop_fail_from_checked);
ATF_TC_BODY(entry_loop_fail_from_checked, tc)
{
	const struct vmm_startup_entry_runtime_result enter = {
		.error = 0,
		.action = VMM_STARTUP_ENTRY_RUNTIME_ENTER_GUEST,
	};
	const int bad_errors[] = { 0, -1, EAGAIN };
	struct vmm_startup_entry_loop_result before_result, result;
	struct vmm_startup_entry_loop before, loop;
	size_t i;

	(void)tc;

	/* A terminal failure completes the loop and undoes the pending check. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_CHECKED);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_checked(&loop, EIO,
	    &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 0);
	ATF_CHECK_EQ(loop.entry_count, 0);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_CHECK_EQ(result.reserved8[0], 0);
	ATF_CHECK_EQ(result.reserved8[1], 0);
	ATF_CHECK_EQ(result.reserved8[2], 0);

	/* Prior committed entry history survives a later terminal failure. */
	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_enter(&loop), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_exit(&loop, true, 0), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_fail_checked(&loop, EBUSY,
	    &result), 0);
	ATF_CHECK_EQ(loop.phase, VMM_STARTUP_ENTRY_LOOP_COMPLETE);
	ATF_CHECK_EQ(loop.check_count, 1);
	ATF_CHECK_EQ(loop.entry_count, 1);
	ATF_CHECK_EQ(result.action, VMM_STARTUP_ENTRY_LOOP_RETURN_ERROR);
	ATF_CHECK_EQ(result.error, EBUSY);

	/* Non-terminal error codes are rejected atomically. */
	for (i = 0; i < sizeof(bad_errors) / sizeof(bad_errors[0]); i++) {
		vmm_startup_entry_loop_init(&loop);
		ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
		memset(&result, 0xa5, sizeof(result));
		before = loop;
		before_result = result;
		ATF_CHECK_EQ(vmm_startup_entry_loop_fail_checked(&loop,
		    bad_errors[i], &result), EINVAL);
		ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
		ATF_CHECK_EQ(memcmp(&result, &before_result, sizeof(result)),
		    0);
	}

	/* Wrong phase, NULL result, and aliasing all fail atomically. */
	vmm_startup_entry_loop_init(&loop);
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_fail_checked(&loop, EIO, &result),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);

	vmm_startup_entry_loop_init(&loop);
	ATF_REQUIRE_EQ(vmm_startup_entry_loop_check(&loop, &enter), 0);
	before = loop;
	ATF_CHECK_EQ(vmm_startup_entry_loop_fail_checked(&loop, EIO, NULL),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
	ATF_CHECK_EQ(vmm_startup_entry_loop_fail_checked(&loop, EIO,
	    (struct vmm_startup_entry_loop_result *)(void *)&loop), EINVAL);
	ATF_CHECK_EQ(memcmp(&loop, &before, sizeof(loop)), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, default_preserves_userspace_contract);
	ATF_TP_ADD_TC(tp, kernel_owner_ap_transitions);
	ATF_TP_ADD_TC(tp, kernel_owner_bsp_init_remains_runnable);
	ATF_TP_ADD_TC(tp, startup_init_ap_waits_while_bsp_restarts);
	ATF_TP_ADD_TC(tp, startup_sipi_accepted_only_in_wait_for_sipi);
	ATF_TP_ADD_TC(tp, startup_mixed_target_publishes_one_kernel_set);
	ATF_TP_ADD_TC(tp, startup_wait_for_sipi_wakeup_not_lost);
	ATF_TP_ADD_TC(tp, selection_is_immutable);
	ATF_TP_ADD_TC(tp, execution_contract_must_match_owner);
	ATF_TP_ADD_TC(tp, rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, delivery_owner_selection);
	ATF_TP_ADD_TC(tp, delivery_rejects_invalid_kind);
	ATF_TP_ADD_TC(tp, delivery_rejects_empty_target_set);
	ATF_TP_ADD_TC(tp, delivery_cancellation_fails_closed);
	ATF_TP_ADD_TC(tp, delivery_checkpoint_blocks_only_kernel_route);
	ATF_TP_ADD_TC(tp, delivery_requires_locked_owner_after_reset);
	ATF_TP_ADD_TC(tp, delivery_rejects_aliased_output);
	ATF_TP_ADD_TC(tp, delivery_validation_is_exact);
	ATF_TP_ADD_TC(tp, dispatch_result_run_policy);
	ATF_TP_ADD_TC(tp, dispatch_result_rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, entry_arbitration_exhaustive);
	ATF_TP_ADD_TC(tp, entry_arbitration_rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, entry_snapshot_validation_is_exact);
	ATF_TP_ADD_TC(tp, entry_dispatch_admission_is_exact);
	ATF_TP_ADD_TC(tp, entry_handoff_detects_preentry_notification);
	ATF_TP_ADD_TC(tp, entry_handoff_rejection_is_failure_atomic);
	ATF_TP_ADD_TC(tp, notification_generation_boundaries);
	ATF_TP_ADD_TC(tp, entry_runtime_exact_unwind);
	ATF_TP_ADD_TC(tp, entry_runtime_replay_and_error_unwind);
	ATF_TP_ADD_TC(tp, entry_runtime_rechecks_each_hardware_entry);
	ATF_TP_ADD_TC(tp, entry_runtime_rejects_invalid_order);
	ATF_TP_ADD_TC(tp, entry_loop_requires_check_before_each_entry);
	ATF_TP_ADD_TC(tp, entry_loop_drift_after_handled_exit_returns);
	ATF_TP_ADD_TC(tp, entry_loop_distinguishes_no_entry_returns);
	ATF_TP_ADD_TC(tp, entry_loop_software_exit_from_checked);
	ATF_TP_ADD_TC(tp, entry_loop_fail_from_checked);
	ATF_TP_ADD_TC(tp, entry_loop_owns_return_disposition);
	ATF_TP_ADD_TC(tp, entry_loop_rejects_malformed_and_overflow);
	ATF_TP_ADD_TC(tp, entry_guard_admission_is_failure_atomic);
	ATF_TP_ADD_TC(tp, entry_guard_return_is_failure_atomic);
	ATF_TP_ADD_TC(tp,
	    entry_guard_completion_closes_final_return_window);
	return (atf_no_error());
}
