/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
int network_daemon_main(void);
#define main network_daemon_main
#include "../networkcmp.c"
#undef main

ATF_TC_WITHOUT_HEAD(label_admission);
ATF_TC_BODY(label_admission, tc)
{
	struct net_worker_ent entries[NETWORKCMP_MAX_LABEL_WORKERS];
	struct service_process *head = NULL;

	memset(entries, 0, sizeof(entries));
	for (unsigned i = 0; i < nitems(entries); i++) {
		ATF_REQUIRE(net_worker_admit(head, "org.test.busy"));
		strlcpy(entries[i].label, "org.test.busy", sizeof(entries[i].label));
		entries[i].process.next = head;
		head = &entries[i].process;
	}
	ATF_CHECK(!net_worker_admit(head, "org.test.busy"));
	ATF_CHECK(net_worker_admit(head, "org.test.peer"));
	/* Exiting a session returns capacity only for its authenticated label. */
	head = head->next;
	ATF_CHECK(net_worker_admit(head, "org.test.busy"));
	ATF_CHECK(net_worker_admit(head, "org.test.peer"));
}

ATF_TC_WITHOUT_HEAD(worker_shutdown);
ATF_TC_BODY(worker_shutdown, tc)
{
	struct service_process *head = NULL;
	struct net_worker_ent *entry;
	int descriptors[2];
	pid_t child;

	for (unsigned i = 0; i < nitems(descriptors); i++) {
		entry = calloc(1, sizeof(*entry));
		ATF_REQUIRE(entry != NULL);
		child = pdfork(&entry->process.pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
		ATF_REQUIRE(child >= 0);
		if (child == 0)
			for (;;)
				pause();
		descriptors[i] = entry->process.pd;
		entry->process.next = head;
		head = &entry->process;
	}
	ATF_REQUIRE_EQ(0, service_processes_stop(&head));
	ATF_CHECK(head == NULL);
	for (unsigned i = 0; i < nitems(descriptors); i++)
		ATF_CHECK_ERRNO(EBADF, fcntl(descriptors[i], F_GETFD) == -1);
	ATF_CHECK_ERRNO(ECHILD, waitpid(-1, NULL, WNOHANG) == -1);
	ATF_CHECK_EQ(0, service_processes_stop(&head));
}

ATF_TC_WITHOUT_HEAD(parent_descriptors_do_not_fork);
ATF_TC_BODY(parent_descriptors_do_not_fork, tc)
{
	int pd, kq, status;
	pid_t child, probe;

	child = pdfork(&pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		for (;;)
			pause();
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, service_harden_fd(pd, 0));
	ATF_REQUIRE_EQ(0, service_harden_fd(kq, 0));
	probe = fork();
	ATF_REQUIRE(probe >= 0);
	if (probe == 0) {
		if (fcntl(pd, F_GETFD) != -1 || errno != EBADF)
			_exit(1);
		if (fcntl(kq, F_GETFD) != -1 || errno != EBADF)
			_exit(2);
		_exit(0);
	}
	ATF_REQUIRE_EQ(probe, waitpid(probe, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* Parent supervision authority remains usable. */
	ATF_REQUIRE_EQ(0, pdkill(pd, SIGKILL));
	ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
	close(pd);
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, label_admission);
	ATF_TP_ADD_TC(tp, worker_shutdown);
	ATF_TP_ADD_TC(tp, parent_descriptors_do_not_fork);
	return (atf_no_error());
}
