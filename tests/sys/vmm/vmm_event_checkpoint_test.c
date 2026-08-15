/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/dev/vmm/vmm_event_ingress.c"
#include "../../../sys/dev/vmm/vmm_event_checkpoint.c"

#define LEFT_OWNER UINT64_C(0x1111)
#define RIGHT_OWNER UINT64_C(0x2222)
#define CHECKPOINT_OWNER UINT64_C(0x3333)
#define DEFER_NMI UINT64_C(0x1)
#define DEFER_EXTINT UINT64_C(0x2)
#define DEFER_VALID (DEFER_NMI | DEFER_EXTINT)

static void
setup_pair(struct vmm_event_ingress states[2],
    struct vmm_event_checkpoint_entry entries[2],
    struct vmm_event_checkpoint *checkpoint)
{

	memset(entries, 0, 2 * sizeof(entries[0]));
	memset(checkpoint, 0, sizeof(*checkpoint));
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&states[0], LEFT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_init(&states[1], RIGHT_OWNER), 0);
	entries[0].state = &states[0];
	entries[1].state = &states[1];
}

ATF_TC_WITHOUT_HEAD(group_lifecycle);
ATF_TC_BODY(group_lifecycle, tc)
{
	struct vmm_event_checkpoint checkpoint;
	struct vmm_event_checkpoint_entry entries[2];
	struct vmm_event_ingress states[2];
	struct vmm_event_ingress_ticket ticket;
	bool ready;

	(void)tc;
	setup_pair(states, entries, &checkpoint);
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&states[0],
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), 0);
	ATF_CHECK_EQ(states[0].mode, VMM_EVENT_INGRESS_DRAINING);
	ATF_CHECK_EQ(states[1].mode, VMM_EVENT_INGRESS_QUIESCED);
	ready = true;
	ATF_REQUIRE_EQ(vmm_event_checkpoint_ready(&checkpoint, &ready), 0);
	ATF_CHECK(!ready);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&states[1],
	    DEFER_NMI, DEFER_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&states[0], &ticket),
	    0);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&states[0],
	    DEFER_EXTINT, DEFER_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_ready(&checkpoint, &ready), 0);
	ATF_CHECK(ready);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_finish(&checkpoint), 0);
	ATF_CHECK_EQ(entries[0].deferred_mask, DEFER_EXTINT);
	ATF_CHECK_EQ(entries[1].deferred_mask, DEFER_NMI);
	ATF_CHECK_EQ(states[0].mode, VMM_EVENT_INGRESS_OPEN);
	ATF_CHECK_EQ(states[1].mode, VMM_EVENT_INGRESS_OPEN);
	ATF_CHECK_EQ(checkpoint.active, 0);
}

ATF_TC_WITHOUT_HEAD(group_abort_draining);
ATF_TC_BODY(group_abort_draining, tc)
{
	struct vmm_event_checkpoint checkpoint;
	struct vmm_event_checkpoint_entry entries[2];
	struct vmm_event_ingress states[2];
	struct vmm_event_ingress_ticket ticket;

	(void)tc;
	setup_pair(states, entries, &checkpoint);
	memset(&ticket, 0, sizeof(ticket));
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_enter(&states[0],
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), 0);
	ATF_REQUIRE_EQ(vmm_event_ingress_defer_idempotent(&states[0],
	    DEFER_NMI, DEFER_VALID), 0);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_abort(&checkpoint), 0);
	ATF_CHECK_EQ(entries[0].deferred_mask, DEFER_NMI);
	ATF_CHECK_EQ(states[0].mode, VMM_EVENT_INGRESS_OPEN);
	ATF_CHECK_EQ(states[0].active_publishers, 1);
	ATF_REQUIRE_EQ(vmm_event_ingress_publisher_exit(&states[0], &ticket),
	    0);
}

ATF_TC_WITHOUT_HEAD(group_transactional_failures);
ATF_TC_BODY(group_transactional_failures, tc)
{
	struct vmm_event_checkpoint before, checkpoint, copied;
	struct vmm_event_checkpoint_entry entries[2], entries_before[2];
	struct vmm_event_ingress states[2], states_before[2];
	bool ready;

	(void)tc;
	setup_pair(states, entries, &checkpoint);
	entries[1].state = entries[0].state;
	memcpy(states_before, states, sizeof(states));
	memcpy(entries_before, entries, sizeof(entries));
	ATF_CHECK_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), EINVAL);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	ATF_CHECK(memcmp(entries, entries_before, sizeof(entries)) == 0);
	ATF_CHECK_EQ(checkpoint.active, 0);

	setup_pair(states, entries, &checkpoint);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), 0);
	before = checkpoint;
	memcpy(states_before, states, sizeof(states));
	memcpy(entries_before, entries, sizeof(entries));
	copied = checkpoint;
	ready = true;
	ATF_CHECK_EQ(vmm_event_checkpoint_ready(&copied, &ready), EINVAL);
	ATF_CHECK(ready);
	ATF_CHECK(memcmp(&checkpoint, &before, sizeof(checkpoint)) == 0);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	ATF_CHECK(memcmp(entries, entries_before, sizeof(entries)) == 0);
	ATF_CHECK_EQ(vmm_event_checkpoint_ready(&checkpoint,
	    (bool *)&entries[0].deferred_mask), EINVAL);
	ATF_CHECK(memcmp(&checkpoint, &before, sizeof(checkpoint)) == 0);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	ATF_CHECK(memcmp(entries, entries_before, sizeof(entries)) == 0);

	entries[1].state = &states[0];
	ATF_CHECK_EQ(vmm_event_checkpoint_finish(&checkpoint), EINVAL);
	ATF_CHECK(memcmp(&checkpoint, &before, sizeof(checkpoint)) == 0);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	entries[1] = entries_before[1];
	ATF_REQUIRE_EQ(vmm_event_checkpoint_abort(&checkpoint), 0);
}

ATF_TC_WITHOUT_HEAD(group_overflow_and_alias);
ATF_TC_BODY(group_overflow_and_alias, tc)
{
	struct vmm_event_checkpoint before, checkpoint;
	struct vmm_event_checkpoint_entry entries[2], entries_before[2];
	struct vmm_event_ingress states[2], states_before[2];

	(void)tc;
	setup_pair(states, entries, &checkpoint);
	ATF_CHECK_EQ(vmm_event_checkpoint_begin(&checkpoint,
	    (struct vmm_event_checkpoint_entry *)(UINTPTR_MAX -
	    sizeof(struct vmm_event_checkpoint_entry) + 2), 2,
	    CHECKPOINT_OWNER), EINVAL);
	states[1].publisher_generation = UINT64_MAX;
	memcpy(states_before, states, sizeof(states));
	memcpy(entries_before, entries, sizeof(entries));
	ATF_CHECK_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), EOVERFLOW);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	ATF_CHECK(memcmp(entries, entries_before, sizeof(entries)) == 0);

	setup_pair(states, entries, &checkpoint);
	ATF_CHECK_EQ(vmm_event_checkpoint_begin(
	    (struct vmm_event_checkpoint *)&entries[0], entries, 2,
	    CHECKPOINT_OWNER), EINVAL);
	ATF_REQUIRE_EQ(vmm_event_checkpoint_begin(&checkpoint, entries, 2,
	    CHECKPOINT_OWNER), 0);
	before = checkpoint;
	states[0].publisher_generation = UINT64_MAX;
	memcpy(states_before, states, sizeof(states));
	memcpy(entries_before, entries, sizeof(entries));
	ATF_CHECK_EQ(vmm_event_checkpoint_finish(&checkpoint), EOVERFLOW);
	ATF_CHECK(memcmp(&checkpoint, &before, sizeof(checkpoint)) == 0);
	ATF_CHECK(memcmp(states, states_before, sizeof(states)) == 0);
	ATF_CHECK(memcmp(entries, entries_before, sizeof(entries)) == 0);
	states[0].publisher_generation = 1;
	ATF_REQUIRE_EQ(vmm_event_checkpoint_abort(&checkpoint), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, group_lifecycle);
	ATF_TP_ADD_TC(tp, group_abort_draining);
	ATF_TP_ADD_TC(tp, group_transactional_failures);
	ATF_TP_ADD_TC(tp, group_overflow_and_alias);
	return (atf_no_error());
}
