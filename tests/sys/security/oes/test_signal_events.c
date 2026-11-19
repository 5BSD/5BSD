/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES signal and process event tests.
 * Require actor/target-matched events and successful underlying operations.
 */
#include "test_common.h"

#include <sys/ptrace.h>
#include <signal.h>

static int
open_notify(oes_event_type_t *events, int count)
{
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (-1);
	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0 ||
	    test_subscribe(fd, events, count, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

/*
 * The actor of each case is a child of the test (test_in_child()): the test
 * opened the client, so the events it causes itself are never delivered to
 * that client (oes(4), "A client's own processes").
 */
static int
kill_target(void *arg)
{

	return (kill(*(pid_t *)arg, SIGTERM) == 0 ? 0 : errno);
}

static pid_t
spawn_pauser(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		for (;;)
			pause();
	}
	return (pid);
}

static int
test_signal_to_child(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	test_msg_buf buf;
	pid_t target, actor;
	int fd, status;

	TEST_BEGIN("signal to another process");
	fd = open_notify(events, 1);
	if (fd < 0)
		return (1);
	target = spawn_pauser();
	if (target < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(fd);
		return (1);
	}
	actor = test_in_child(kill_target, &target, &status);
	if (actor < 0 || !test_child_ok(status)) {
		TEST_FAIL("actor kill failed");
		kill(target, SIGKILL);
	}
	if (test_wait_event_pid(fd, actor, OES_EVENT_NOTIFY_SIGNAL, 2000,
	    &buf.msg) != 0)
		TEST_FAIL("missing sender-matched signal event");
	else {
		ASSERT_MSG(buf.msg.em_event_data.signal.signum == SIGTERM,
		    "wrong signal number");
		ASSERT_MSG(buf.msg.em_event_data.signal.target.ep_pid == target,
		    "wrong signal target");
	}
	ASSERT_MSG(waitpid(target, &status, 0) == target &&
	    WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM,
	    "target did not receive SIGTERM");
	close(fd);
	TEST_PASS();
	return (0);
}

static volatile sig_atomic_t got_sigusr1;

static void
sigusr1_handler(int sig __unused)
{
	got_sigusr1 = 1;
}

/* In the actor: signal itself, then the target (the marker). */
static int
signal_self_then_target(void *arg)
{
	struct sigaction sa;

	got_sigusr1 = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL) < 0)
		return (10);
	if (kill(getpid(), SIGUSR1) != 0 || !got_sigusr1)
		return (11);
	if (kill(*(pid_t *)arg, SIGTERM) != 0)
		return (12);
	return (0);
}

static int
test_signal_self(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	pid_t target, actor;
	int fd, status;

	TEST_BEGIN("signal to self (SIGUSR1): no event");
	fd = open_notify(events, 1);
	if (fd < 0)
		return (1);
	/*
	 * No event: p_cansignal() permits a process to signal itself before
	 * it reaches any check, mac_proc_check_signal() included, so there is
	 * nothing for OES to observe (oes.4).  The absence is judged against
	 * the actor's later signal to another process, which must arrive.
	 */
	target = spawn_pauser();
	if (target < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(fd);
		return (1);
	}
	actor = test_in_child(signal_self_then_target, &target, &status);
	ASSERT_MSG(actor > 0 && test_child_ok(status),
	    "actor: self signal or marker signal failed (status %#x)", status);
	{
		test_msg_buf buf;
		struct timespec start, now;
		int self_events = 0, marker = 0;

		clock_gettime(CLOCK_MONOTONIC, &start);
		while (!marker) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - start.tv_sec >= 5)
				break;
			if (test_wait_event(fd, &buf.msg, 100) != 0 ||
			    buf.msg.em_event != OES_EVENT_NOTIFY_SIGNAL ||
			    buf.msg.em_process.ep_pid != actor)
				continue;
			if (buf.msg.em_event_data.signal.target.ep_pid ==
			    actor)
				self_events++;
			else if (buf.msg.em_event_data.signal.target.ep_pid ==
			    target)
				marker = 1;
		}
		(void)waitpid(target, NULL, 0);
		ASSERT_MSG(marker, "the later signal to another process was "
		    "not delivered");
		ASSERT_MSG(self_events == 0, "%d events for a signal a "
		    "process sent to itself; none is documented",
		    self_events);
	}
	close(fd);
	TEST_PASS();
	return (0);
}

/*
 * In the actor: fork a tracee, report its pid, attach, wait for the stop,
 * detach, then kill and reap it.
 */
static int
ptrace_actor(void *arg)
{
	int report = *(int *)arg, status;
	pid_t tracee;

	tracee = spawn_pauser();
	if (tracee < 0)
		return (20);
	if (write(report, &tracee, sizeof(tracee)) != sizeof(tracee))
		return (21);
	if (ptrace(PT_ATTACH, tracee, NULL, 0) < 0) {
		kill(tracee, SIGKILL);
		return (22);
	}
	if (waitpid(tracee, &status, 0) != tracee || !WIFSTOPPED(status))
		return (23);
	if (ptrace(PT_DETACH, tracee, (caddr_t)1, 0) != 0)
		return (24);
	if (kill(tracee, SIGKILL) != 0)
		return (25);
	if (waitpid(tracee, &status, 0) != tracee || !WIFSIGNALED(status) ||
	    WTERMSIG(status) != SIGKILL)
		return (26);
	return (0);
}

static int
test_ptrace_event(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_PTRACE };
	test_msg_buf buf;
	pid_t actor, tracee = -1;
	int fd, status, p[2];

	TEST_BEGIN("ptrace attach event");
	fd = open_notify(events, 1);
	if (fd < 0)
		return (1);
	if (pipe(p) != 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}
	actor = test_in_child(ptrace_actor, &p[1], &status);
	close(p[1]);
	ASSERT_MSG(read(p[0], &tracee, sizeof(tracee)) == sizeof(tracee),
	    "no tracee pid from the actor");
	close(p[0]);
	ASSERT_MSG(actor > 0 && test_child_ok(status),
	    "actor ptrace sequence failed (status %#x)", status);
	if (test_wait_event_pid(fd, actor, OES_EVENT_NOTIFY_PTRACE, 2000,
	    &buf.msg) != 0)
		TEST_FAIL("missing actor-matched ptrace event");
	else
		ASSERT_MSG(buf.msg.em_event_data.ptrace.target.ep_pid == tracee,
		    "wrong ptrace target");
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_setuid_setgid_events(void)
{
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_SETUID, OES_EVENT_NOTIFY_SETGID
	};
	test_msg_buf buf;
	uid_t uid = getuid();
	gid_t gid = getgid();
	pid_t child;
	int fd, status, got_uid = 0, got_gid = 0;

	TEST_BEGIN("setuid/setgid events");
	fd = open_notify(events, 2);
	if (fd < 0)
		return (1);
	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(fd);
		return (1);
	}
	if (child == 0) {
		close(fd);
		_exit(setgid(gid) == 0 && setuid(uid) == 0 ? 0 : 1);
	}
	ASSERT_MSG(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0, "child identity calls failed");
	for (int i = 0; i < 10 && (!got_uid || !got_gid); i++) {
		if (test_wait_event(fd, &buf.msg, 200) != 0 ||
		    buf.msg.em_process.ep_pid != child)
			continue;
		if (buf.msg.em_event == OES_EVENT_NOTIFY_SETUID &&
		    buf.msg.em_event_data.setuid.uid == uid)
			got_uid = 1;
		if (buf.msg.em_event == OES_EVENT_NOTIFY_SETGID &&
		    buf.msg.em_event_data.setgid.gid == gid)
			got_gid = 1;
	}
	ASSERT_MSG(got_uid && got_gid, "missing child UID/GID events");
	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	int failed = 0;

	TEST_SUITE_BEGIN("signal events");
	failed += test_signal_to_child();
	failed += test_signal_self();
	failed += test_ptrace_event();
	failed += test_setuid_setgid_events();
	TEST_SUITE_END("signal events");
	return (failed != 0);
}
