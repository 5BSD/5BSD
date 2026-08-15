/*
 * OES multiple-clients-across-processes test.
 *
 * Two independent processes each open their own /dev/oes client (per-open
 * cdevpriv state) and subscribe to NOTIFY_OPEN.  A third, unrelated process
 * then performs a file open.  BOTH clients must observe the resulting event,
 * proving that clients are per-open and per-process and that events fan out to
 * every subscribed client rather than a single owner.
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

static int
open_client_subscribe_open(void)
{
	static oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	int fd;

	fd = test_open_oes();
	if (fd < 0)
		return (-1);

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		close(fd);
		return (-1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

int
main(void)
{
	int fdA;
	int ready[2], gotpid[2], go[2];
	pid_t bpid, tpid;
	int tstatus, bstatus, rc_b;
	oes_message_t evmsg;

	TEST_SUITE_BEGIN("multi_process_clients");

	fdA = open_client_subscribe_open();
	if (fdA < 0) {
		TEST_SKIP("cannot open/subscribe %s (oes module loaded?): %s",
		    OES_DEVICE_PATH, strerror(errno));
		return (0);
	}

	if (pipe(ready) != 0 || pipe(gotpid) != 0 || pipe(go) != 0) {
		TEST_FAIL("pipe: %s", strerror(errno));
		return (1);
	}

	/* Client B lives in its own process with its own /dev/oes open. */
	bpid = fork();
	if (bpid < 0) {
		TEST_FAIL("fork B: %s", strerror(errno));
		return (1);
	}
	if (bpid == 0) {
		pid_t target;
		int fdB, r;

		fdB = open_client_subscribe_open();
		(void)write(ready[1], fdB < 0 ? "F" : "R", 1);
		if (fdB < 0)
			_exit(2);
		if (read(gotpid[0], &target, sizeof(target)) !=
		    (ssize_t)sizeof(target))
			_exit(3);
		r = test_wait_event_pid(fdB, target, OES_EVENT_NOTIFY_OPEN,
		    5000, &evmsg);
		close(fdB);
		_exit(r == 0 ? 0 : 1);
	}

	/* Wait until B has subscribed. */
	{
		char c = 0;

		close(ready[1]);
		(void)read(ready[0], &c, 1);
		if (c != 'R') {
			TEST_FAIL("client B failed to open/subscribe");
			(void)waitpid(bpid, &bstatus, 0);
			return (1);
		}
	}

	/* An unrelated target process performs the observed open(). */
	tpid = fork();
	if (tpid < 0) {
		TEST_FAIL("fork target: %s", strerror(errno));
		return (1);
	}
	if (tpid == 0) {
		char tmpl[] = "/tmp/oes_mpc.XXXXXX";
		char c;
		int tfd;

		close(go[1]);
		(void)read(go[0], &c, 1);	/* wait for release */
		tfd = mkstemp(tmpl);
		if (tfd >= 0) {
			(void)close(tfd);
			(void)unlink(tmpl);
		}
		_exit(0);
	}

	/* Hand B the target pid, then release the target. */
	(void)write(gotpid[1], &tpid, sizeof(tpid));
	(void)write(go[1], "g", 1);

	/* Client A must observe the target's open. */
	if (test_wait_event_pid(fdA, tpid, OES_EVENT_NOTIFY_OPEN, 5000,
	    &evmsg) == 0)
		TEST_PASS();
	else
		TEST_FAIL("client A did not observe the target open");

	(void)waitpid(tpid, &tstatus, 0);
	(void)waitpid(bpid, &bstatus, 0);
	rc_b = WIFEXITED(bstatus) ? WEXITSTATUS(bstatus) : -1;

	/* Client B, a separate process, must independently observe it too. */
	if (rc_b == 0)
		TEST_PASS();
	else
		TEST_FAIL("client B (separate process) did not observe the "
		    "target open (rc=%d)", rc_b);

	close(fdA);
	TEST_SUITE_END("multi_process_clients");
	return (0);	/* harness forces non-zero exit if any assertion failed */
}
