/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int quota_daemon_main(void);
#define main quota_daemon_main
#include "../bsddevice.c"
#undef main

ATF_TC_WITHOUT_HEAD(client_quota);
ATF_TC_BODY(client_quota, tc)
{
	struct device_worker_ent entries[DEVICE_MAX_LABEL_WORKERS];
	struct service_process *head = NULL;

	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < nitems(entries); i++) {
		ATF_REQUIRE(device_worker_admit(head, "org.test.busy"));
		strlcpy(entries[i].label, "org.test.busy", sizeof(entries[i].label));
		entries[i].process.next = head;
		head = &entries[i].process;
	}
	ATF_CHECK(!device_worker_admit(head, "org.test.busy"));
	ATF_CHECK(device_worker_admit(head, "org.test.peer"));
	/* Removing the exiting session returns its client's admission slot. */
	head = head->next;
	ATF_CHECK(device_worker_admit(head, "org.test.busy"));
	ATF_CHECK(device_worker_admit(head, "org.test.peer"));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, client_quota);
	return (atf_no_error());
}
