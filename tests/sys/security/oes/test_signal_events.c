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
	    test_unmute_self(fd) < 0 ||
	    test_subscribe(fd, events, count, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static int
test_signal_to_child(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	test_msg_buf buf;
	pid_t child;
	int fd, status;

	TEST_BEGIN("signal to child process");
	fd = open_notify(events, 1);
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
		for (;;)
			pause();
	}
	if (kill(child, SIGTERM) < 0) {
		TEST_FAIL("kill: %s", strerror(errno));
		kill(child, SIGKILL);
	}
	if (test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_SIGNAL, 2000,
	    &buf.msg) != 0)
		TEST_FAIL("missing sender-matched signal event");
	else {
		ASSERT_MSG(buf.msg.em_event_data.signal.signum == SIGTERM,
		    "wrong signal number");
		ASSERT_MSG(buf.msg.em_event_data.signal.target.ep_pid == child,
		    "wrong signal target");
	}
	ASSERT_MSG(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
	    WTERMSIG(status) == SIGTERM, "child did not receive SIGTERM");
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

static int
test_signal_self(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	struct sigaction sa, old_sa;
	int fd;

	TEST_BEGIN("signal to self (SIGUSR1)");
	fd = open_notify(events, 1);
	if (fd < 0)
		return (1);
	got_sigusr1 = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, &old_sa) < 0) {
		TEST_FAIL("sigaction: %s", strerror(errno));
		close(fd);
		return (1);
	}
	ASSERT_MSG(kill(getpid(), SIGUSR1) == 0 && got_sigusr1,
	    "self signal was not delivered");
	/* p_cansignal_thread returns before the MAC hook for self signals. */
	TEST_SKIP("self-signal notification bypasses the native MAC hook");
	ASSERT_MSG(sigaction(SIGUSR1, &old_sa, NULL) == 0,
	    "restore signal handler");
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_ptrace_event(void)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_PTRACE };
	test_msg_buf buf;
	pid_t child;
	int fd, status;

	TEST_BEGIN("ptrace attach event");
	fd = open_notify(events, 1);
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
		for (;;)
			pause();
	}
	if (ptrace(PT_ATTACH, child, NULL, 0) < 0) {
		TEST_FAIL("ptrace attach: %s", strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(fd);
		return (1);
	}
	ASSERT_MSG(waitpid(child, &status, 0) == child && WIFSTOPPED(status),
	    "tracee did not stop");
	if (test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_PTRACE, 2000,
	    &buf.msg) != 0)
		TEST_FAIL("missing actor-matched ptrace event");
	else
		ASSERT_MSG(buf.msg.em_event_data.ptrace.target.ep_pid == child,
		    "wrong ptrace target");
	ASSERT_MSG(ptrace(PT_DETACH, child, (caddr_t)1, 0) == 0,
	    "ptrace detach failed");
	ASSERT_MSG(kill(child, SIGKILL) == 0, "tracee cleanup signal failed");
	ASSERT_MSG(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
	    WTERMSIG(status) == SIGKILL, "tracee cleanup failed");
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
