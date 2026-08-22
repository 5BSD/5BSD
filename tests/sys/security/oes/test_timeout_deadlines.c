/*
 * OES timeout and deadline tests.
 *
 * Tests behavior when AUTH responses miss deadlines.
 * Verifies timeout action settings work correctly.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/*
 * Test setting and getting timeout action.
 */
static int
test_set_get_timeout_action(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_deadline_miss_mode_args action, retrieved;

	printf("  Testing set/get timeout action...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Set timeout action to ALLOW */
	memset(&action, 0, sizeof(action));
	action.edma_mode = OES_DEADLINE_MISS_FAIL_OPEN;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) < 0) {
		perror("OES_IOC_SET_DEADLINE_MISS_MODE (FAIL_OPEN)");
		close(fd);
		return (1);
	}

	/* Verify it was set */
	memset(&retrieved, 0, sizeof(retrieved));
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MISS_MODE, &retrieved) < 0) {
		perror("OES_IOC_GET_DEADLINE_MISS_MODE");
		close(fd);
		return (1);
	}

	if (retrieved.edma_mode != OES_DEADLINE_MISS_FAIL_OPEN) {
		fprintf(stderr, "FAIL: expected ALLOW, got %u\n",
		    retrieved.edma_mode);
		close(fd);
		return (1);
	}

	/* Set timeout action to DENY */
	action.edma_mode = OES_DEADLINE_MISS_FAIL_CLOSED;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) < 0) {
		perror("OES_IOC_SET_DEADLINE_MISS_MODE (FAIL_CLOSED)");
		close(fd);
		return (1);
	}

	/* Verify it was set */
	memset(&retrieved, 0, sizeof(retrieved));
	if (ioctl(fd, OES_IOC_GET_DEADLINE_MISS_MODE, &retrieved) < 0) {
		perror("OES_IOC_GET_DEADLINE_MISS_MODE");
		close(fd);
		return (1);
	}

	if (retrieved.edma_mode != OES_DEADLINE_MISS_FAIL_CLOSED) {
		fprintf(stderr, "FAIL: expected DENY, got %u\n",
		    retrieved.edma_mode);
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: set/get timeout action works\n");
	return (0);
}

/*
 * Test invalid timeout action values.
 */
static int
test_invalid_timeout_action(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_deadline_miss_mode_args action;

	printf("  Testing invalid timeout action values...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Try invalid action value */
	memset(&action, 0, sizeof(action));
	action.edma_mode = 0xDEADBEEF;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) == 0) {
		printf("    FAIL: invalid action accepted\n");
		close(fd);
		return (1);
	}
	if (errno != EINVAL) {
		printf("    FAIL: invalid action errno=%d, expected EINVAL\n",
		    errno);
		close(fd);
		return (1);
	}

	memset(&action, 0, sizeof(action));
	action.edma_mode = OES_DEADLINE_MISS_FAIL_OPEN;
	action.edma_reserved = 1;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) == 0 ||
	    errno != EINVAL) {
		printf("    FAIL: non-zero reserved field accepted\n");
		close(fd);
		return (1);
	}

	close(fd);
	printf("    PASS: invalid action correctly rejected\n");
	return (0);
}

/*
 * Test deadline field in AUTH events.
 */
static int
test_deadline_field(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct oes_event_deadline_args deadline;
	pid_t pid;
	struct timespec now;
	long remaining_ms;

	printf("  Testing deadline field in AUTH events...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}
	memset(&deadline, 0, sizeof(deadline));
	deadline.oeda_event = OES_EVENT_AUTH_EXEC;
	deadline.oeda_milliseconds = 1500;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MAX, &deadline) < 0) {
		perror("OES_IOC_SET_DEADLINE_MAX");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork and exec to generate AUTH_EXEC */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child - exec something simple */
		execl("/usr/bin/true", "true", NULL);
		_exit(1);
	}

	if (test_wait_event_pid(fd, pid, OES_EVENT_AUTH_EXEC, 2500, msg) != 0) {
		printf("    FAIL: no AUTH_EXEC event for child\n");
		waitpid(pid, NULL, 0);
		close(fd);
		return (1);
	}
	clock_gettime(CLOCK_MONOTONIC, &now);
	remaining_ms = (msg->em_deadline.tv_sec - now.tv_sec) * 1000L +
	    (msg->em_deadline.tv_nsec - now.tv_nsec) / 1000000L;
	if (remaining_ms <= 0 || remaining_ms > 1500) {
		printf("    FAIL: per-event deadline remaining=%ldms\n",
		    remaining_ms);
		close(fd);
		waitpid(pid, NULL, 0);
		return (1);
	}
	{
		oes_response_t resp;

		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_ALLOW;
		if (write(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
			perror("write AUTH response");
			close(fd);
			waitpid(pid, NULL, 0);
			return (1);
		}
	}
	waitpid(pid, NULL, 0);
	close(fd);
	printf("    PASS: per-event maximum controls AUTH deadline\n");
	return (0);
}

/*
 * Test late response handling.
 * This test intentionally delays response past deadline.
 */
static int
test_late_response(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_deadline_miss_mode_args action;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	pid_t pid;
	ssize_t n;
	int i, status;

	printf("  Testing late response (timeout behavior)...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = OES_MIN_DEADLINE_MS;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Set timeout action to ALLOW so the child doesn't block forever */
	memset(&action, 0, sizeof(action));
	action.edma_mode = OES_DEADLINE_MISS_FAIL_OPEN;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) < 0) {
		perror("OES_IOC_SET_DEADLINE_MISS_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork child that will do a file open */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		/* Child - open a file (will block waiting for AUTH) */
		int tmpfd = open("/etc/passwd", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		_exit(0);
	}

	/* Parent - read the child's AUTH event but DON'T respond. */
	if (test_wait_event_pid(fd, pid, OES_EVENT_AUTH_OPEN, 2000, msg) == 0) {
		oes_response_t resp;

		printf("    INFO: got AUTH event, NOT responding immediately\n");

		/* Bound the wait without relying on signal() restart semantics. */
		for (i = 0; i < 500; i++) {
			if (waitpid(pid, &status, WNOHANG) == pid)
				break;
			usleep(10000);
		}
		if (i == 500) {
			(void)kill(pid, SIGKILL);
			(void)waitpid(pid, &status, 0);
			printf("    FAIL: child remained blocked past deadline\n");
			close(fd);
			return (1);
		}

		/* Try to respond now (should be too late). */
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_ALLOW;
		n = write(fd, &resp, sizeof(resp));
		if (n >= 0 || (errno != ESRCH && errno != EALREADY)) {
			printf("    FAIL: late response was not rejected: %s\n",
			    n < 0 ? strerror(errno) : "accepted");
			close(fd);
			return (1);
		}

		close(fd);
		printf("    PASS: timeout unblocks child and rejects late response\n");
		return (0);
	}

	/* If we get here, wait for child and clean up */
	waitpid(pid, NULL, 0);
	close(fd);
	printf("    FAIL: no AUTH_OPEN event received for child\n");
	return (1);
}

/*
 * Test response to wrong message ID.
 */
static int
test_wrong_message_id(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	pid_t pid;
	ssize_t n;
	int failed = 0, received = 0;

	printf("  Testing response with wrong message ID...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork and exec */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		execl("/usr/bin/true", "true", NULL);
		_exit(1);
	}

	if (test_wait_event_pid(fd, pid, OES_EVENT_AUTH_EXEC, 2000, msg) == 0) {
			received = 1;
			/* Try response with wrong ID */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id + 12345;  /* Wrong ID */
			resp.er_result = OES_AUTH_ALLOW;

			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: wrong ID rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    FAIL: wrong message ID accepted\n");
				failed = 1;
			}

			/* Now send correct response */
			resp.er_id = msg->em_id;
			(void)write(fd, &resp, sizeof(resp));
	}

	waitpid(pid, NULL, 0);
	close(fd);
	if (!received) {
		printf("    FAIL: no AUTH_EXEC event received\n");
		return (1);
	}
	return (failed);
}

/*
 * Test duplicate response.
 */
static int
test_duplicate_response(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	pid_t pid;
	ssize_t n;
	int failed = 0, received = 0;

	printf("  Testing duplicate response...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		execl("/usr/bin/true", "true", NULL);
		_exit(1);
	}

	if (test_wait_event_pid(fd, pid, OES_EVENT_AUTH_EXEC, 2000, msg) == 0) {
			received = 1;
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;

			/* First response */
			n = write(fd, &resp, sizeof(resp));
			if (n != sizeof(resp)) {
				printf("    FAIL: first response failed\n");
				failed = 1;
			}

			/* Second response (duplicate) */
			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: duplicate response rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    FAIL: duplicate response accepted\n");
				failed = 1;
			}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	if (!received) {
		printf("    FAIL: no AUTH_EXEC event received\n");
		return (1);
	}
	return (failed);
}

/*
 * Test response with invalid result code.
 */
static int
test_invalid_result_code(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;
	pid_t pid;
	ssize_t n;
	int failed = 0, received = 0;

	printf("  Testing response with invalid result code...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		execl("/usr/bin/true", "true", NULL);
		_exit(1);
	}

	if (test_wait_event_pid(fd, pid, OES_EVENT_AUTH_EXEC, 2000, msg) == 0) {
			received = 1;
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = 0xBADBAD;  /* Invalid result */

			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: invalid result rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    FAIL: invalid result accepted\n");
				failed = 1;
			}

			/* Send valid response so child can proceed */
			resp.er_result = OES_AUTH_ALLOW;
			(void)write(fd, &resp, sizeof(resp));
	}

	waitpid(pid, NULL, 0);
	close(fd);
	if (!received) {
		printf("    FAIL: no AUTH_EXEC event received\n");
		return (1);
	}
	return (failed);
}

/*
 * Test partial write of response.
 */
static int
test_partial_response_write(void)
{
	int fd;
	struct oes_mode_args mode;
	oes_response_t resp;
	ssize_t n;

	printf("  Testing partial response write...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Write only part of a response structure */
	memset(&resp, 0, sizeof(resp));
	resp.er_id = 12345;
	resp.er_result = OES_AUTH_ALLOW;

	/* Write less than full struct */
	n = write(fd, &resp, sizeof(resp) - 4);
	if (n < 0) {
		printf("    PASS: partial write rejected: %s\n", strerror(errno));
	} else {
		printf("    FAIL: partial write returned %zd\n", n);
		close(fd);
		return (1);
	}

	close(fd);
	return (0);
}

static int
test_queue_full_fail_closed(void)
{
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_deadline_miss_mode_args action;
	oes_event_type_t event = OES_EVENT_AUTH_OPEN;
	struct pollfd pfd;
	pid_t first, second;
	int fd, i, status;

	printf("  Testing fail-closed AUTH queue saturation...\n");
	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = 5000;
	mode.ema_queue_size = 1;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0)
		goto fail;
	memset(&action, 0, sizeof(action));
	action.edma_mode = OES_DEADLINE_MISS_FAIL_CLOSED;
	if (ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &action) < 0)
		goto fail;
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = &event;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0)
		goto fail;

	first = fork();
	if (first < 0)
		goto fail;
	if (first == 0) {
		int target;

		close(fd);
		target = open("/etc/passwd", O_RDONLY);
		if (target >= 0)
			close(target);
		_exit(0);
	}
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 2000) <= 0 || (pfd.revents & POLLIN) == 0) {
		printf("    FAIL: first AUTH event did not fill queue\n");
		close(fd);
		(void)waitpid(first, NULL, 0);
		return (1);
	}

	second = fork();
	if (second < 0) {
		close(fd);
		(void)waitpid(first, NULL, 0);
		return (1);
	}
	if (second == 0) {
		int target, saved_errno;

		close(fd);
		target = open("/etc/passwd", O_RDONLY);
		saved_errno = errno;
		if (target >= 0)
			close(target);
		_exit(target < 0 && saved_errno == EACCES ? 0 : 1);
	}

	for (i = 0; i < 200; i++) {
		if (waitpid(second, &status, WNOHANG) == second)
			break;
		usleep(10000);
	}
	close(fd); /* Releases the queued first request with DENY as well. */
	(void)waitpid(first, NULL, 0);
	if (i == 200) {
		(void)kill(second, SIGKILL);
		(void)waitpid(second, NULL, 0);
		printf("    FAIL: queue-full AUTH request did not unblock\n");
		return (1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("    FAIL: queue-full AUTH request did not fail closed\n");
		return (1);
	}
	printf("    PASS: per-client DENY applies to dropped AUTH messages\n");
	return (0);
fail:
	perror("queue saturation setup");
	close(fd);
	return (1);
}

int
main(void)
{
	int failed = 0;

	printf("Testing timeout and deadline handling...\n");

	failed += test_set_get_timeout_action();
	failed += test_invalid_timeout_action();
	failed += test_deadline_field();
	failed += test_late_response();
	failed += test_wrong_message_id();
	failed += test_duplicate_response();
	failed += test_invalid_result_code();
	failed += test_partial_response_write();
	failed += test_queue_full_fail_closed();

	if (failed > 0) {
		printf("timeout deadlines: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("timeout deadlines: ok\n");
	return (0);
}
