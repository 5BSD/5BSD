/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int quota_daemon_main(void);
#define main quota_daemon_main
#include "../logcmp.c"
#undef main

ATF_TC_WITHOUT_HEAD(client_quota);
ATF_TC_BODY(client_quota, tc)
{
	struct worker_state entries[LOGCMP_MAX_ACTOR_SESSIONS_PER_SHARD];
	struct worker_state *head = NULL;

	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < nitems(entries); i++) {
		ATF_REQUIRE(pool_actor_admit(head, "org.test.busy"));
		strlcpy(entries[i].actor, "org.test.busy", sizeof(entries[i].actor));
		entries[i].next = head;
		head = &entries[i];
	}
	ATF_CHECK(!pool_actor_admit(head, "org.test.busy"));
	ATF_CHECK(pool_actor_admit(head, "org.test.peer"));
	/* Removing the exiting session returns its client's admission slot. */
	head = head->next;
	ATF_CHECK(pool_actor_admit(head, "org.test.busy"));
	ATF_CHECK(pool_actor_admit(head, "org.test.peer"));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, client_quota);
	return (atf_no_error());
}
