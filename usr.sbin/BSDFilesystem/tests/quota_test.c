/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int quota_daemon_main(void);
#define main quota_daemon_main
#include "../request.c"
#undef main

ATF_TC_WITHOUT_HEAD(client_quota);
ATF_TC_BODY(client_quota, tc)
{
	struct fs_worker entries[FS_MAX_LABEL_WORKERS];
	struct fs_worker *head = NULL;

	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < nitems(entries); i++) {
		ATF_REQUIRE(fs_worker_admit(head, "org.test.busy"));
		strlcpy(entries[i].label, "org.test.busy", sizeof(entries[i].label));
		entries[i].next = head;
		head = &entries[i];
	}
	ATF_CHECK(!fs_worker_admit(head, "org.test.busy"));
	ATF_CHECK(fs_worker_admit(head, "org.test.peer"));
	/* Removing the exiting session returns its client's admission slot. */
	head = head->next;
	ATF_CHECK(fs_worker_admit(head, "org.test.busy"));
	ATF_CHECK(fs_worker_admit(head, "org.test.peer"));
}
ATF_TC_WITHOUT_HEAD(worker_shutdown);
ATF_TC_BODY(worker_shutdown, tc)
{
	struct fs_worker *head = NULL, *entry;
	int descriptors[2], status;
	pid_t children[2];

	for (unsigned i = 0; i < nitems(descriptors); i++) {
		entry = calloc(1, sizeof(*entry));
		ATF_REQUIRE(entry != NULL);
		children[i] = pdfork(&entry->pd, PD_CLOEXEC);
		ATF_REQUIRE(children[i] >= 0);
		if (children[i] == 0)
			for (;;)
				pause();
		descriptors[i] = entry->pd;
		entry->next = head;
		head = entry;
	}
	ATF_REQUIRE_EQ(0, fs_workers_stop(&head));
	ATF_CHECK(head == NULL);
	for (unsigned i = 0; i < nitems(descriptors); i++) {
		ATF_CHECK_ERRNO(EBADF, fcntl(descriptors[i], F_GETFD) == -1);
		ATF_CHECK_ERRNO(ECHILD, waitpid(children[i], &status, WNOHANG) == -1);
	}
	ATF_CHECK_EQ(0, fs_workers_stop(&head));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, client_quota);
	ATF_TP_ADD_TC(tp, worker_shutdown);
	return (atf_no_error());
}
