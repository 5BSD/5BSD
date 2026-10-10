/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#undef VMD_TESTING
int bsdvm_main(int, char **);
#define main bsdvm_main
#include "../bsdvm.c"
#undef main

ATF_TC(worker_windows);
ATF_TC_HEAD(worker_windows, tc)
{
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(worker_windows, tc)
{
	struct vmd_worker_ent *head = NULL, *node;
	size_t count = 0;
	uint32_t base, idx = 0;
	pid_t pids[2];
	int fds[2], status;

	for (size_t i = 0; i < nitems(pids); i++) {
		ATF_REQUIRE_EQ(0, resolve_window("org.test.worker", &base, &idx));
		node = calloc(1, sizeof(*node));
		ATF_REQUIRE(node != NULL);
		node->widx = idx;
		pids[i] = pdfork(&node->pd, PD_CLOEXEC | PD_DAEMON);
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0)
			for (;;)
				pause();
		fds[i] = node->pd;
		node->next = head;
		head = node;
		count++;
	}
	ATF_CHECK_EQ(2, g_windows[idx].refs);
	/* Keep a handle whose child was already reaped: pdwait returns ESRCH. */
	ATF_REQUIRE_EQ(0, pdkill(fds[0], SIGKILL));
	ATF_REQUIRE(pdwait(fds[0], &status, WEXITED, NULL, NULL) != -1);
	ATF_REQUIRE_EQ(0, vmd_workers_stop(&head, &count));
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(0, g_windows[idx].refs);
	ATF_CHECK(!g_windows[idx].used);
	for (size_t i = 0; i < nitems(pids); i++) {
		ATF_CHECK_ERRNO(EBADF, fcntl(fds[i], F_GETFD) == -1);
		ATF_CHECK_ERRNO(ECHILD, waitpid(pids[i], &status, WNOHANG) == -1);
	}
	ATF_CHECK_EQ(0, vmd_workers_stop(&head, &count));
}

ATF_TC_WITHOUT_HEAD(failed_stop_retains_window);
ATF_TC_BODY(failed_stop_retains_window, tc)
{
	struct vmd_worker_ent *head;
	size_t count = 1;
	uint32_t base, idx;

	ATF_REQUIRE_EQ(0, resolve_window("org.test.failed", &base, &idx));
	head = calloc(1, sizeof(*head));
	ATF_REQUIRE(head != NULL);
	head->pd = -1;
	head->widx = idx;
	ATF_CHECK_ERRNO(EBADF, vmd_workers_stop(&head, &count) == -1);
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(1, g_windows[idx].refs);
	ATF_CHECK(g_windows[idx].used);
	window_release(idx);
}

ATF_TC_WITHOUT_HEAD(failed_exit_reap_retains_window);
ATF_TC_BODY(failed_exit_reap_retains_window, tc)
{
	struct vmd_worker_ent *head;
	size_t count = 1;
	uint32_t base, idx;

	ATF_REQUIRE_EQ(0, resolve_window("org.test.exit", &base, &idx));
	head = calloc(1, sizeof(*head));
	ATF_REQUIRE(head != NULL);
	head->pd = -1;
	head->widx = idx;
	ATF_CHECK_ERRNO(EBADF, vmd_worker_remove(&head, head, &count) == -1);
	ATF_CHECK_EQ(NULL, head);
	ATF_CHECK_EQ(0, count);
	ATF_CHECK_EQ(1, g_windows[idx].refs);
	ATF_CHECK(g_windows[idx].used);
	window_release(idx);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, worker_windows);
	ATF_TP_ADD_TC(tp, failed_exit_reap_retains_window);
	ATF_TP_ADD_TC(tp, failed_stop_retains_window);
	return (atf_no_error());
}
