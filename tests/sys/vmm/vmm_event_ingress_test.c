/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_event_ingress.c"

#define TEST_OWNER UINT64_C(0x1122334455667788)
#define TEST_NMI UINT64_C(0x1)
#define TEST_EXTINT UINT64_C(0x2)
#define TEST_VALID (TEST_NMI | TEST_EXTINT)

ATF_TC_WITHOUT_HEAD(lifecycle);
ATF_TC_BODY(lifecycle, tc)
{
	struct vmm_event_ingress state;
	struct vmm_event_ingress_lease lease;
	struct vmm_event_ingress_ticket ticket;
	uint64_t deferred;

	(void)tc;
	memset(&state, 0xa5, sizeof(state));
	memset(&lease, 0, sizeof(lease));
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&state, TEST_OWNER), 0);
	ATF_CHECK_EQ(vmm_event_ingress_validate(&state), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&state, &ticket), 0);
	ATF_CHECK_EQ(state.active_publishers, 1);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&state, &lease), 0);
	ATF_CHECK_EQ(state.mode, VMM_EVENT_INGRESS_DRAINING);
	ATF_CHECK_EQ(vmm_event_ingress_publisher_enter(&state,
	    &(struct vmm_event_ingress_ticket){ 0 }), EBUSY);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&state, TEST_NMI,
	    TEST_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&state, TEST_NMI,
	    TEST_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&state, &ticket), 0);
	ATF_CHECK_EQ(state.mode, VMM_EVENT_INGRESS_QUIESCED);
	deferred = UINT64_MAX;
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_finish(&state, &lease,
	    &deferred), 0);
	ATF_CHECK_EQ(deferred, TEST_NMI);
	ATF_CHECK_EQ(state.mode, VMM_EVENT_INGRESS_OPEN);
	ATF_CHECK_EQ(state.publisher_generation, 2);
	ATF_CHECK_EQ(vmm_event_ingress_validate(&state), 0);
}

ATF_TC_WITHOUT_HEAD(immediate_and_abort);
ATF_TC_BODY(immediate_and_abort, tc)
{
	struct vmm_event_ingress state;
	struct vmm_event_ingress_lease lease;
	struct vmm_event_ingress_ticket ticket;
	uint64_t deferred;

	(void)tc;
	memset(&lease, 0, sizeof(lease));
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&state, TEST_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&state, &lease), 0);
	ATF_CHECK_EQ(state.mode, VMM_EVENT_INGRESS_QUIESCED);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&state, TEST_EXTINT,
	    TEST_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_abort(&state, &lease,
	    &deferred), 0);
	ATF_CHECK_EQ(deferred, TEST_EXTINT);
	ATF_CHECK_EQ(state.publisher_generation, 2);

	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&state, &ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&state, &lease), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&state, TEST_NMI,
	    TEST_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_abort(&state, &lease,
	    &deferred), 0);
	ATF_CHECK_EQ(deferred, TEST_NMI);
	ATF_CHECK_EQ(state.publisher_generation, 2);
	ATF_CHECK_EQ(state.active_publishers, 1);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&state, &ticket), 0);
	ATF_CHECK_EQ(state.active_publishers, 0);
}

ATF_TC_WITHOUT_HEAD(transactional_failures);
ATF_TC_BODY(transactional_failures, tc)
{
	struct vmm_event_ingress before, state;
	struct vmm_event_ingress moved;
	struct vmm_event_ingress_lease lease, lease_before, copied_lease, wrong;
	struct vmm_event_ingress_ticket copied_ticket, ticket, ticket_before;
	uint64_t deferred;

	(void)tc;
	memset(&lease, 0, sizeof(lease));
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&state, TEST_OWNER), 0);
	before = state;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_enter(&state,
	    (struct vmm_event_ingress_ticket *)&state), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_begin(&state,
	    (struct vmm_event_ingress_lease *)&state), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	moved = state;
	ATF_CHECK_EQ(vmm_event_ingress_validate(&moved), EINVAL);

	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&state, &lease), 0);
	before = state;
	lease_before = lease;
	deferred = UINT64_C(0xfeedface);
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_finish(&state, &lease,
	    (uint64_t *)&state), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK(memcmp(&lease, &lease_before, sizeof(lease)) == 0);
	ATF_CHECK_EQ(deferred, UINT64_C(0xfeedface));
	wrong = lease;
	wrong.owner_id++;
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_finish(&state, &wrong,
	    &deferred), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK_EQ(deferred, UINT64_C(0xfeedface));
	copied_lease = lease;
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_finish(&state, &copied_lease,
	    &deferred), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK_EQ(deferred, UINT64_C(0xfeedface));
	ATF_CHECK_EQ(vmm_event_ingress_defer_idempotent(&state, 0,
	    TEST_VALID), EINVAL);
	ATF_CHECK_EQ(vmm_event_ingress_defer_idempotent(&state, TEST_VALID,
	    TEST_VALID), EINVAL);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_abort(&state, &lease,
	    &deferred), 0);

	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&state, &ticket), 0);
	ticket_before = ticket;
	before = state;
	copied_ticket = ticket;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_exit(&state, &copied_ticket),
	    ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ticket.owner_id++;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_exit(&state, &ticket), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ticket = ticket_before;
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&state, &ticket), 0);
	before = state;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_exit(&state, &ticket), ESTALE);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
}

ATF_TC_WITHOUT_HEAD(overflow_and_validation);
ATF_TC_BODY(overflow_and_validation, tc)
{
	struct vmm_event_ingress before, state;
	struct vmm_event_ingress_lease lease;
	struct vmm_event_ingress_ticket ticket;
	uint64_t deferred;

	(void)tc;
	memset(&lease, 0, sizeof(lease));
	memset(&ticket, 0, sizeof(ticket));
	ATF_CHECK_EQ(vmm_event_ingress_init(NULL, TEST_OWNER), EINVAL);
	ATF_CHECK_EQ(vmm_event_ingress_init(&state, 0), EINVAL);
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&state, TEST_OWNER), 0);
	state.active_publishers = UINT32_MAX;
	before = state;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_enter(&state, &ticket),
	    EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	state.active_publishers = 0;
	state.last_lease_id = UINT64_MAX;
	before = state;
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_begin(&state, &lease),
	    EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);

	state.last_lease_id = 0;
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&state, &lease), 0);
	state.publisher_generation = UINT64_MAX;
	before = state;
	deferred = UINT64_C(0xa5a5);
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_finish(&state, &lease,
	    &deferred), EOVERFLOW);
	ATF_CHECK(memcmp(&state, &before, sizeof(state)) == 0);
	ATF_CHECK_EQ(deferred, UINT64_C(0xa5a5));

	state = (struct vmm_event_ingress) { 0 };
	ATF_CHECK_EQ(vmm_event_ingress_validate(&state), EINVAL);
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&state, TEST_OWNER), 0);
	state.mode = VMM_EVENT_INGRESS_DRAINING;
	ATF_CHECK_EQ(vmm_event_ingress_validate(&state), EINVAL);
	state.mode = VMM_EVENT_INGRESS_QUIESCED;
	ATF_CHECK_EQ(vmm_event_ingress_validate(&state), EINVAL);
}

ATF_TC_WITHOUT_HEAD(cross_state_isolation);
ATF_TC_BODY(cross_state_isolation, tc)
{
	struct vmm_event_ingress left, left_before, right, right_before;
	struct vmm_event_ingress_lease left_lease, right_lease;
	struct vmm_event_ingress_ticket left_ticket, right_ticket;
	uint64_t deferred;

	(void)tc;
	memset(&left_lease, 0, sizeof(left_lease));
	memset(&right_lease, 0, sizeof(right_lease));
	memset(&left_ticket, 0, sizeof(left_ticket));
	memset(&right_ticket, 0, sizeof(right_ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&left, TEST_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&right, TEST_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&left,
	    &left_ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&right,
	    &right_ticket), 0);
	left_before = left;
	right_before = right;
	ATF_CHECK_EQ(vmm_event_ingress_publisher_exit(&right, &left_ticket),
	    ESTALE);
	ATF_CHECK(memcmp(&left, &left_before, sizeof(left)) == 0);
	ATF_CHECK(memcmp(&right, &right_before, sizeof(right)) == 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&left,
	    &left_ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&right,
	    &right_ticket), 0);

	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&left,
	    &left_lease), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_begin(&right,
	    &right_lease), 0);
	left_before = left;
	right_before = right;
	deferred = UINT64_C(0xfeedface);
	ATF_CHECK_EQ(vmm_event_ingress_quiesce_finish(&right, &left_lease,
	    &deferred), ESTALE);
	ATF_CHECK(memcmp(&left, &left_before, sizeof(left)) == 0);
	ATF_CHECK(memcmp(&right, &right_before, sizeof(right)) == 0);
	ATF_CHECK_EQ(deferred, UINT64_C(0xfeedface));
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_abort(&left, &left_lease,
	    &deferred), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_quiesce_abort(&right, &right_lease,
	    &deferred), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, lifecycle);
	ATF_TP_ADD_TC(tp, immediate_and_abort);
	ATF_TP_ADD_TC(tp, transactional_failures);
	ATF_TP_ADD_TC(tp, overflow_and_validation);
	ATF_TP_ADD_TC(tp, cross_state_isolation);
	return (atf_no_error());
}
