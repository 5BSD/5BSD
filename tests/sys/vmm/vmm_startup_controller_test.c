/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_startup_controller.c"

#define	CONTROLLER_OWNER	UINT64_C(0x7101)
#define	CONTROLLER_ID		UINT64_C(0x7202)

ATF_TC_WITHOUT_HEAD(claim_and_exact_check);
ATF_TC_BODY(claim_and_exact_check, tc)
{
	struct vmm_startup_controller_state state;
	struct vmm_startup_controller_ticket ticket;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&state,
	    CONTROLLER_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID), 0);
	ATF_CHECK_EQ(vmm_startup_controller_validate(&state), 0);
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &ticket), 0);
	ATF_CHECK_EQ(state.phase, VMM_STARTUP_CONTROLLER_CLAIMED);
	ATF_CHECK_EQ(state.controller_id, CONTROLLER_ID);
}

ATF_TC_WITHOUT_HEAD(ticket_empty_is_named_state);
ATF_TC_BODY(ticket_empty_is_named_state, tc)
{
	struct vmm_startup_controller_ticket ticket;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_CHECK(startup_controller_ticket_empty(&ticket));
	ticket.reserved8[nitems(ticket.reserved8) - 1] = 1;
	ATF_CHECK(!startup_controller_ticket_empty(&ticket));
	ticket.reserved8[nitems(ticket.reserved8) - 1] = 0;
	ticket.state_cookie = 1;
	ATF_CHECK(!startup_controller_ticket_empty(&ticket));
}

ATF_TC_WITHOUT_HEAD(copied_and_cross_owner_tickets_fail);
ATF_TC_BODY(copied_and_cross_owner_tickets_fail, tc)
{
	struct vmm_startup_controller_state other, state;
	struct vmm_startup_controller_ticket copied, other_ticket, ticket;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	memset(&other_ticket, 0, sizeof(other_ticket));
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&state,
	    CONTROLLER_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&other,
	    CONTROLLER_OWNER + 1), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&other, &other_ticket,
	    CONTROLLER_ID + 1), 0);
	copied = ticket;
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &copied), ESTALE);
	ATF_CHECK_EQ(vmm_startup_controller_check(&other, &ticket), ESTALE);
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &other_ticket),
	    ESTALE);
	ATF_CHECK_EQ(vmm_startup_controller_claim(&state, &copied,
	    CONTROLLER_ID + 1), EBUSY);
}

ATF_TC_WITHOUT_HEAD(abort_invalidates_and_allows_fresh_claim);
ATF_TC_BODY(abort_invalidates_and_allows_fresh_claim, tc)
{
	struct vmm_startup_controller_state state;
	struct vmm_startup_controller_ticket old, ticket;
	uint64_t generation;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&state,
	    CONTROLLER_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID), 0);
	old = ticket;
	generation = state.generation;
	ATF_REQUIRE_EQ(vmm_startup_controller_abort(&state, &ticket), 0);
	ATF_CHECK_EQ(state.phase, VMM_STARTUP_CONTROLLER_UNCLAIMED);
	ATF_CHECK_EQ(state.generation, generation + 1);
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &old), ESTALE);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID + 1), 0);
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &ticket), 0);
}

ATF_TC_WITHOUT_HEAD(exhaustion_and_alias_reject_without_mutation);
ATF_TC_BODY(exhaustion_and_alias_reject_without_mutation, tc)
{
	struct vmm_startup_controller_state before, state;
	struct vmm_startup_controller_ticket before_ticket, ticket;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&state,
	    CONTROLLER_OWNER), 0);
	state.generation = UINT64_MAX;
	before = state;
	before_ticket = ticket;
	ATF_CHECK_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID), EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK(memcmp(&ticket, &before_ticket, sizeof(ticket)) == 0);
	ATF_CHECK_EQ(vmm_startup_controller_claim(&state,
	    (struct vmm_startup_controller_ticket *)(void *)&state,
	    CONTROLLER_ID), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
}

ATF_TC_WITHOUT_HEAD(retire_is_terminal_and_ticket_forget_is_local);
ATF_TC_BODY(retire_is_terminal_and_ticket_forget_is_local, tc)
{
	struct vmm_startup_controller_state state;
	struct vmm_startup_controller_ticket ticket;
	uint64_t generation;

	(void)tc;
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_startup_controller_init(&state,
	    CONTROLLER_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID), 0);
	generation = state.generation;
	ATF_REQUIRE_EQ(vmm_startup_controller_retire(&state), 0);
	ATF_CHECK_EQ(state.phase, VMM_STARTUP_CONTROLLER_REVOKED);
	ATF_CHECK_EQ(state.controller_id, 0);
	ATF_CHECK_EQ(state.generation, generation + 1);
	ATF_CHECK_EQ(vmm_startup_controller_check(&state, &ticket), ECANCELED);
	ATF_REQUIRE_EQ(vmm_startup_controller_ticket_forget(&ticket), 0);
	ATF_CHECK_EQ(vmm_startup_controller_retire(&state), 0);
	ATF_CHECK_EQ(vmm_startup_controller_claim(&state, &ticket,
	    CONTROLLER_ID + 1), ECANCELED);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, claim_and_exact_check);
	ATF_TP_ADD_TC(tp, ticket_empty_is_named_state);
	ATF_TP_ADD_TC(tp, copied_and_cross_owner_tickets_fail);
	ATF_TP_ADD_TC(tp, abort_invalidates_and_allows_fresh_claim);
	ATF_TP_ADD_TC(tp, exhaustion_and_alias_reject_without_mutation);
	ATF_TP_ADD_TC(tp, retire_is_terminal_and_ticket_forget_is_local);
	return (atf_no_error());
}
