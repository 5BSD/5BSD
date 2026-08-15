/*
 * OES NOTIFY_CLOSE test.  Closing a file's last vnode reference must generate a
 * NOTIFY_CLOSE event, delivered via the mac_vnode_check_close hook.  Close is
 * not deniable, so this is a NOTIFY-only event.
 */
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

int
main(void)
{
	int fd, pipefd[2];
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_CLOSE };
	oes_message_t evmsg;
	pid_t pid;
	int status;

	TEST_SUITE_BEGIN("notify_close");

	fd = test_open_oes();
	if (fd < 0) {
		TEST_SKIP("cannot open %s (oes module loaded?): %s",
		    OES_DEVICE_PATH, strerror(errno));
		return (0);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		TEST_FAIL("OES_IOC_SET_MODE: %s", strerror(errno));
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		TEST_FAIL("OES_IOC_SUBSCRIBE: %s", strerror(errno));
		close(fd);
		return (1);
	}

	if (pipe(pipefd) != 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		close(fd);
		return (1);
	}
	if (pid == 0) {
		char tmpl[] = "/tmp/oes_close.XXXXXX";
		char c;
		int tfd;

		/* Wait until the parent is ready, then open+close a real file. */
		close(pipefd[1]);
		(void)read(pipefd[0], &c, 1);
		tfd = mkstemp(tmpl);
		if (tfd < 0)
			_exit(1);
		(void)close(tfd);	/* the vnode close we expect to observe */
		(void)unlink(tmpl);
		_exit(0);
	}

	close(pipefd[0]);
	(void)write(pipefd[1], "g", 1);
	close(pipefd[1]);

	if (test_wait_event_pid(fd, pid, OES_EVENT_NOTIFY_CLOSE, 5000,
	    &evmsg) == 0)
		TEST_PASS();
	else
		TEST_FAIL("no NOTIFY_CLOSE observed for child pid %d",
		    (int)pid);

	(void)waitpid(pid, &status, 0);
	close(fd);
	TEST_SUITE_END("notify_close");
	return (0);	/* harness forces non-zero exit if any assertion failed */
}
