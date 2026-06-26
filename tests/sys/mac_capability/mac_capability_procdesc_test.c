/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Tests for procdesc lifecycle events (NOTE_FORK, NOTE_EXEC, NOTE_EXIT).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static int
pd_kevent_poll(int kq, struct kevent *out, int timeout_ms)
{
	struct timespec ts;

	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
	return (kevent(kq, NULL, 0, out, 1, &ts));
}

/* ----------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------- */

ATF_TC(procdesc_note_exit);
ATF_TC_HEAD(procdesc_note_exit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "EVFILT_PROCDESC delivers NOTE_EXIT when child exits");
}
ATF_TC_BODY(procdesc_note_exit, tc)
{
	struct kevent kev;
	int kq, pd, status, n;
	pid_t pid;

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(42);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, pd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	n = pd_kevent_poll(kq, &kev, 2000);
	ATF_REQUIRE(n == 1);
	ATF_CHECK(kev.fflags & NOTE_EXIT);

	waitpid(pid, &status, 0);
	close(pd);
	close(kq);
}

ATF_TC(procdesc_note_fork);
ATF_TC_HEAD(procdesc_note_fork, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "EVFILT_PROCDESC delivers NOTE_FORK when child forks");
}
ATF_TC_BODY(procdesc_note_fork, tc)
{
	struct kevent kev;
	int kq, pd, status, n, sv[2];
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		pid_t grandchild;
		char buf;

		close(sv[0]);
		/* Wait for parent to set up kqueue */
		read(sv[1], &buf, 1);
		/* Fork a grandchild */
		grandchild = fork();
		if (grandchild == 0)
			_exit(0);
		waitpid(grandchild, NULL, 0);
		close(sv[1]);
		_exit(0);
	}
	close(sv[1]);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, pd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_FORK | NOTE_EXIT, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Tell child to fork */
	write(sv[0], "g", 1);
	close(sv[0]);

	/* Collect events — should get NOTE_FORK and then NOTE_EXIT */
	int got_fork = 0, got_exit = 0;
	for (int i = 0; i < 5; i++) {
		n = pd_kevent_poll(kq, &kev, 2000);
		if (n <= 0)
			break;
		if (kev.fflags & NOTE_FORK)
			got_fork = 1;
		if (kev.fflags & NOTE_EXIT)
			got_exit = 1;
		if (got_fork && got_exit)
			break;
	}
	ATF_CHECK_MSG(got_fork, "did not receive NOTE_FORK");
	ATF_CHECK_MSG(got_exit, "did not receive NOTE_EXIT");

	waitpid(pid, &status, 0);
	close(pd);
	close(kq);
}

ATF_TC(procdesc_note_exec);
ATF_TC_HEAD(procdesc_note_exec, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "EVFILT_PROCDESC delivers NOTE_EXEC when child execs");
}
ATF_TC_BODY(procdesc_note_exec, tc)
{
	struct kevent kev;
	int kq, pd, status, n, sv[2];
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char buf;

		close(sv[0]);
		/* Wait for parent to set up kqueue */
		read(sv[1], &buf, 1);
		close(sv[1]);
		/* Exec — this replaces the process image */
		execl("/bin/sh", "sh", "-c", "exit 0", NULL);
		_exit(127);
	}
	close(sv[1]);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, pd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_EXEC | NOTE_EXIT, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	/* Tell child to exec */
	write(sv[0], "g", 1);
	close(sv[0]);

	/* Collect events — should get NOTE_EXEC and then NOTE_EXIT */
	int got_exec = 0, got_exit = 0;
	for (int i = 0; i < 5; i++) {
		n = pd_kevent_poll(kq, &kev, 2000);
		if (n <= 0)
			break;
		if (kev.fflags & NOTE_EXEC)
			got_exec = 1;
		if (kev.fflags & NOTE_EXIT)
			got_exit = 1;
		if (got_exec && got_exit)
			break;
	}
	ATF_CHECK_MSG(got_exec, "did not receive NOTE_EXEC");
	ATF_CHECK_MSG(got_exit, "did not receive NOTE_EXIT");

	waitpid(pid, &status, 0);
	close(pd);
	close(kq);
}

ATF_TC(procdesc_note_all);
ATF_TC_HEAD(procdesc_note_all, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "EVFILT_PROCDESC delivers FORK+EXEC+EXIT in sequence");
}
ATF_TC_BODY(procdesc_note_all, tc)
{
	struct kevent kev;
	int kq, pd, status, n, sv[2];
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		pid_t grandchild;
		char buf;

		close(sv[0]);
		read(sv[1], &buf, 1);
		/* Fork a grandchild */
		grandchild = fork();
		if (grandchild == 0)
			_exit(0);
		waitpid(grandchild, NULL, 0);
		close(sv[1]);
		/* Exec */
		execl("/bin/sh", "sh", "-c", "exit 0", NULL);
		_exit(127);
	}
	close(sv[1]);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, pd, EVFILT_PROCDESC, EV_ADD,
	    NOTE_FORK | NOTE_EXEC | NOTE_EXIT, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	write(sv[0], "g", 1);
	close(sv[0]);

	int got_fork = 0, got_exec = 0, got_exit = 0;
	for (int i = 0; i < 10; i++) {
		n = pd_kevent_poll(kq, &kev, 2000);
		if (n <= 0)
			break;
		if (kev.fflags & NOTE_FORK)
			got_fork = 1;
		if (kev.fflags & NOTE_EXEC)
			got_exec = 1;
		if (kev.fflags & NOTE_EXIT)
			got_exit = 1;
		if (got_fork && got_exec && got_exit)
			break;
	}
	ATF_CHECK_MSG(got_fork, "did not receive NOTE_FORK");
	ATF_CHECK_MSG(got_exec, "did not receive NOTE_EXEC");
	ATF_CHECK_MSG(got_exit, "did not receive NOTE_EXIT");

	waitpid(pid, &status, 0);
	close(pd);
	close(kq);
}

/* ----------------------------------------------------------------
 * Registration
 * ---------------------------------------------------------------- */

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, procdesc_note_exit);
	ATF_TP_ADD_TC(tp, procdesc_note_fork);
	ATF_TP_ADD_TC(tp, procdesc_note_exec);
	ATF_TP_ADD_TC(tp, procdesc_note_all);

	return (atf_no_error());
}
