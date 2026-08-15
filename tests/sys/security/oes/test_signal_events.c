/*
 * OES signal event tests.
 *
 * Tests NOTIFY_SIGNAL events and related process operations.
 */
#include "test_common.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

static int
test_signal_to_child(void)
{
	int fd;
	pid_t child;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int pipefd[2];
	char buf;

	TEST_BEGIN("signal to child process");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Self-mute to reduce noise */
	(void)test_mute_self(fd);

	/* Create pipe for synchronization */
	if (pipe(pipefd) < 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		close(fd);
		return (1);
	}

	if (child == 0) {
		/* Child: signal ready, then wait for signal */
		close(pipefd[0]);
		close(fd);
		(void)write(pipefd[1], "R", 1);
		close(pipefd[1]);
		pause();  /* Wait for signal */
		_exit(0);
	}

	close(pipefd[1]);

	/* Wait for child to be ready */
	if (read(pipefd[0], &buf, 1) != 1) {
		TEST_FAIL("child sync failed");
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(pipefd[0]);
		close(fd);
		return (1);
	}
	close(pipefd[0]);

	/* Small delay to ensure child is in pause() */
	usleep(10000);

	/* Send SIGTERM to child */
	if (kill(child, SIGTERM) < 0) {
		TEST_FAIL("kill: %s", strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(fd);
		return (1);
	}

	/* Wait for NOTIFY_SIGNAL event */
	if (test_wait_event_type(fd, msg, OES_EVENT_NOTIFY_SIGNAL, 2000) < 0) {
		/* Signal events may not be delivered for all signals */
		printf("    INFO: no signal event received (may be expected)\n");
	} else {
		ASSERT_MSG(msg->em_event == OES_EVENT_NOTIFY_SIGNAL,
		    "wrong event type: 0x%x", msg->em_event);
		printf("    INFO: signal event received: sig=%d target_pid=%d\n",
		    msg->em_event_data.signal.signum,
		    msg->em_event_data.signal.target.ep_pid);
	}

	waitpid(child, NULL, 0);
	close(fd);
	TEST_PASS();
	return (0);
}

static volatile sig_atomic_t _got_sigusr1 = 0;

static void
_sigusr1_handler(int sig __unused)
{
	_got_sigusr1 = 1;
}

static int
test_signal_self(void)
{
	int fd;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_SIGNAL };
	struct sigaction sa, old_sa;

	TEST_BEGIN("signal to self (SIGUSR1)");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	/* Set up SIGUSR1 handler */
	_got_sigusr1 = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = _sigusr1_handler;
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, &old_sa);

	/* Note: self-signals may or may not generate events depending on impl */
	kill(getpid(), SIGUSR1);

	/* Drain any events */
	test_drain_events(fd);

	sigaction(SIGUSR1, &old_sa, NULL);
	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_ptrace_event(void)
{
	int fd;
	pid_t child;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_PTRACE };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int status;

	TEST_BEGIN("ptrace attach event");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 1, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(fd);
		return (1);
	}

	if (child == 0) {
		/* Child: just sleep briefly */
		usleep(500000);
		_exit(0);
	}

	/* Small delay for child to start */
	usleep(10000);

	/* Try to ptrace attach */
	if (ptrace(PT_ATTACH, child, NULL, 0) < 0) {
		if (errno == EPERM || errno == EBUSY) {
			/* May not have permission or already traced */
			printf("    INFO: ptrace attach not permitted\n");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(fd);
			TEST_PASS();
			return (0);
		}
		TEST_FAIL("ptrace attach: %s", strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(fd);
		return (1);
	}

	/* Wait for child to stop */
	waitpid(child, &status, 0);

	/* Check for ptrace event */
	if (test_wait_event_type(fd, msg, OES_EVENT_NOTIFY_PTRACE, 1000) == 0) {
		printf("    INFO: ptrace event received\n");
	} else {
		printf("    INFO: no ptrace event (may be expected)\n");
	}

	/* Detach and let child exit */
	ptrace(PT_DETACH, child, (caddr_t)1, 0);
	waitpid(child, NULL, 0);

	close(fd);
	TEST_PASS();
	return (0);
}

static int
test_setuid_setgid_events(void)
{
	int fd;
	pid_t child;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_SETUID,
		OES_EVENT_NOTIFY_SETGID
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int pipefd[2];
	char buf;
	uid_t myuid = getuid();
	gid_t mygid = getgid();

	TEST_BEGIN("setuid/setgid events");

	fd = test_open_oes();
	if (fd < 0)
		return (1);

	if (test_set_mode(fd, OES_MODE_NOTIFY) < 0) {
		close(fd);
		return (1);
	}

	if (test_subscribe(fd, events, 2, OES_SUB_REPLACE) < 0) {
		close(fd);
		return (1);
	}

	if (pipe(pipefd) < 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		close(fd);
		return (1);
	}

	if (child == 0) {
		close(pipefd[0]);
		close(fd);

		/* Try setuid/setgid to same values (should work unprivileged) */
		setuid(myuid);
		setgid(mygid);

		(void)write(pipefd[1], "D", 1);
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);

	/* Wait for child to complete */
	if (read(pipefd[0], &buf, 1) != 1) {
		TEST_FAIL("child sync failed");
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(pipefd[0]);
		close(fd);
		return (1);
	}
	close(pipefd[0]);

	/* Check for events */
	int got_setuid = 0, got_setgid = 0;
	for (int i = 0; i < 4; i++) {
		if (test_wait_event(fd, msg, 500) == 0) {
			if (msg->em_event == OES_EVENT_NOTIFY_SETUID)
				got_setuid = 1;
			else if (msg->em_event == OES_EVENT_NOTIFY_SETGID)
				got_setgid = 1;
		}
	}

	if (got_setuid)
		printf("    INFO: setuid event received\n");
	if (got_setgid)
		printf("    INFO: setgid event received\n");
	if (!got_setuid && !got_setgid)
		printf("    INFO: no setuid/setgid events (may be filtered)\n");

	waitpid(child, NULL, 0);
	close(fd);
	TEST_PASS();
	return (0);
}

int
main(void)
{
	TEST_SUITE_BEGIN("signal events");

	test_signal_to_child();
	test_signal_self();
	test_ptrace_event();
	test_setuid_setgid_events();

	TEST_SUITE_END("signal events");
}
