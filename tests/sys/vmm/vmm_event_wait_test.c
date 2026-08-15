/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_event_wait.c"

#define	WAIT_OWNER	UINT64_C(0x7911)

ATF_TC_WITHOUT_HEAD(generation_lifecycle);
ATF_TC_BODY(generation_lifecycle, tc)
{
	struct vmm_event_wait_state state;
	struct vmm_event_wait_ticket ticket;
	bool changed;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	changed = true;
	ATF_REQUIRE_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), 0);
	ATF_CHECK(!changed);
	ATF_REQUIRE_EQ(vmm_event_wait_signal_locked(&state), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), 0);
	ATF_CHECK(changed);
	ATF_REQUIRE_EQ(vmm_event_wait_ticket_release(&ticket), 0);
}

ATF_TC_WITHOUT_HEAD(cancel_and_overflow);
ATF_TC_BODY(cancel_and_overflow, tc)
{
	struct vmm_event_wait_state state;
	struct vmm_event_wait_ticket ticket;
	bool changed;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_cancel_locked(&state), 0);
	changed = false;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), ECANCELED);
	ATF_CHECK(!changed);
	ATF_CHECK_EQ(vmm_event_wait_signal_locked(&state), ECANCELED);
	ATF_REQUIRE_EQ(vmm_event_wait_cancel_locked(&state), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_ticket_release(&ticket), 0);

	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	state.generation = UINT64_MAX - 1;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	ATF_CHECK_EQ(vmm_event_wait_signal_locked(&state), EOVERFLOW);
	ATF_CHECK_EQ(state.generation, UINT64_MAX - 1);
	ATF_CHECK_EQ(state.cancelled, 1);
	changed = false;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), ECANCELED);
	ATF_CHECK(!changed);
	ATF_REQUIRE_EQ(vmm_event_wait_ticket_release(&ticket), 0);

	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	state.generation = UINT64_MAX;
	ATF_CHECK_EQ(vmm_event_wait_signal_locked(&state), EOVERFLOW);
	ATF_CHECK_EQ(state.cancelled, 1);
	memset(&ticket, 0, sizeof(ticket));
	ATF_CHECK_EQ(vmm_event_wait_prepare_locked(&state, &ticket),
	    ECANCELED);
}

ATF_TC_WITHOUT_HEAD(exact_storage_identity);
ATF_TC_BODY(exact_storage_identity, tc)
{
	struct vmm_event_wait_state copied_state, state;
	struct vmm_event_wait_ticket copied_ticket, ticket;
	bool changed;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	copied_ticket = ticket;
	changed = true;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &copied_ticket,
	    &changed), ESTALE);
	ATF_CHECK(changed);
	copied_state = state;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&copied_state, &ticket,
	    &changed), EINVAL);
	ATF_REQUIRE_EQ(vmm_event_wait_ticket_release(&ticket), 0);
}

ATF_TC_WITHOUT_HEAD(transactional_rejection);
ATF_TC_BODY(transactional_rejection, tc)
{
	struct vmm_event_wait_state before, state;
	struct vmm_event_wait_ticket ticket, ticket_before;
	bool changed;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	before = state;
	ticket_before = ticket;
	changed = true;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    (bool *)&ticket.generation), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK(memcmp(&ticket, &ticket_before, sizeof(ticket)) == 0);
	ATF_CHECK(changed);
	ATF_CHECK_EQ(vmm_event_wait_prepare_locked(&state, &ticket), EBUSY);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK(memcmp(&ticket, &ticket_before, sizeof(ticket)) == 0);
	ticket.generation = 0;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), ESTALE);
	ATF_CHECK_EQ(vmm_event_wait_ticket_release(&ticket), ESTALE);
	ticket = ticket_before;
	ticket.generation = state.generation + 1;
	ATF_CHECK_EQ(vmm_event_wait_changed_locked(&state, &ticket,
	    &changed), ESTALE);
	ATF_CHECK_EQ(vmm_event_wait_ticket_release(&ticket), 0);
}

ATF_TC_WITHOUT_HEAD(post_wake_always_replays_predicate);
ATF_TC_BODY(post_wake_always_replays_predicate, tc)
{
	struct vmm_event_wait_state state;
	struct vmm_event_wait_ticket ticket;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_wait_init(&state, WAIT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_wait_prepare_locked(&state, &ticket), 0);
	ATF_CHECK_EQ(vmm_event_wait_wake_result_locked(&state, &ticket, 0),
	    EAGAIN);
	ATF_CHECK_EQ(vmm_event_wait_wake_result_locked(&state, &ticket, EINTR),
	    EINTR);
	ATF_REQUIRE_EQ(vmm_event_wait_signal_locked(&state), 0);
	ATF_CHECK_EQ(vmm_event_wait_wake_result_locked(&state, &ticket, 0),
	    EAGAIN);
	ATF_REQUIRE_EQ(vmm_event_wait_cancel_locked(&state), 0);
	ATF_CHECK_EQ(vmm_event_wait_wake_result_locked(&state, &ticket, 0),
	    ECANCELED);
	state.cancelled = 0;
	ticket.owner_id++;
	ATF_CHECK_EQ(vmm_event_wait_wake_result_locked(&state, &ticket, 0),
	    ESTALE);
	ATF_REQUIRE_EQ(vmm_event_wait_ticket_release(&ticket), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, generation_lifecycle);
	ATF_TP_ADD_TC(tp, cancel_and_overflow);
	ATF_TP_ADD_TC(tp, exact_storage_identity);
	ATF_TP_ADD_TC(tp, transactional_rejection);
	ATF_TP_ADD_TC(tp, post_wake_always_replays_predicate);
	return (atf_no_error());
}
