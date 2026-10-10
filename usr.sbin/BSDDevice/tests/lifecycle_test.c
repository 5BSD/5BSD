/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int bsddevice_main(void);
#define main bsddevice_main
#include "../bsddevice.c"
#undef main

ATF_TC(worker_cleanup);
ATF_TC_HEAD(worker_cleanup, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Controlled exit kills and reaps PD_DAEMON workers and closes handles");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(worker_cleanup, tc)
{
	struct device_worker_ent *head = NULL, *entry;
	size_t count = 0;
	int descriptors[3], pipefd[2], status;
	pid_t pids[3];
	char byte;

	ATF_REQUIRE_EQ(0, pipe(pipefd));
	for (size_t i = 0; i < nitems(pids); i++) {
		entry = calloc(1, sizeof(*entry));
		ATF_REQUIRE(entry != NULL);
		pids[i] = pdfork(&entry->pd, PD_CLOEXEC | PD_DAEMON);
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			if (i == 0)
				_exit(0);
			for (;;)
				pause();
		}
		descriptors[i] = entry->pd;
		entry->next = head;
		head = entry;
		count++;
	}
	close(pipefd[1]);
	ATF_REQUIRE_EQ(0, device_workers_stop(&head, &count));
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	/* No surviving child retains the pipe writer. */
	ATF_CHECK_EQ(0, read(pipefd[0], &byte, 1));
	close(pipefd[0]);
	for (size_t i = 0; i < nitems(pids); i++) {
		ATF_CHECK_ERRNO(EBADF, fcntl(descriptors[i], F_GETFD) == -1);
		ATF_CHECK_ERRNO(ECHILD, waitpid(pids[i], &status, WNOHANG) == -1);
	}
	ATF_CHECK_EQ(0, device_workers_stop(&head, &count));
}

ATF_TC_WITHOUT_HEAD(cleanup_reports_failure);
ATF_TC_BODY(cleanup_reports_failure, tc)
{
	struct device_worker_ent *head;
	size_t count = 1;

	head = calloc(1, sizeof(*head));
	ATF_REQUIRE(head != NULL);
	head->pd = -1;
	ATF_CHECK_ERRNO(EBADF, device_workers_stop(&head, &count) == -1);
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, worker_cleanup);
	ATF_TP_ADD_TC(tp, cleanup_reports_failure);
	return (atf_no_error());
}
