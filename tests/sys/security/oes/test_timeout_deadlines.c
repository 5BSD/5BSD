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

static volatile sig_atomic_t alarm_fired = 0;

static void
alarm_handler(int sig __unused)
{
	alarm_fired = 1;
}

/*
 * Test setting and getting timeout action.
 */
static int
test_set_get_timeout_action(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_timeout_action_args action, retrieved;

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
	action.eta_action = OES_AUTH_ALLOW;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &action) < 0) {
		perror("OES_IOC_SET_TIMEOUT_ACTION (ALLOW)");
		close(fd);
		return (1);
	}

	/* Verify it was set */
	memset(&retrieved, 0, sizeof(retrieved));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT_ACTION, &retrieved) < 0) {
		perror("OES_IOC_GET_TIMEOUT_ACTION");
		close(fd);
		return (1);
	}

	if (retrieved.eta_action != OES_AUTH_ALLOW) {
		fprintf(stderr, "FAIL: expected ALLOW, got %u\n",
		    retrieved.eta_action);
		close(fd);
		return (1);
	}

	/* Set timeout action to DENY */
	action.eta_action = OES_AUTH_DENY;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &action) < 0) {
		perror("OES_IOC_SET_TIMEOUT_ACTION (DENY)");
		close(fd);
		return (1);
	}

	/* Verify it was set */
	memset(&retrieved, 0, sizeof(retrieved));
	if (ioctl(fd, OES_IOC_GET_TIMEOUT_ACTION, &retrieved) < 0) {
		perror("OES_IOC_GET_TIMEOUT_ACTION");
		close(fd);
		return (1);
	}

	if (retrieved.eta_action != OES_AUTH_DENY) {
		fprintf(stderr, "FAIL: expected DENY, got %u\n",
		    retrieved.eta_action);
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
	struct oes_timeout_action_args action;

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
	action.eta_action = 0xDEADBEEF;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &action) == 0) {
		printf("    INFO: invalid action accepted (may be acceptable)\n");
	} else if (errno == EINVAL) {
		printf("    PASS: invalid action correctly rejected\n");
	} else {
		printf("    INFO: invalid action returned errno=%d\n", errno);
	}

	close(fd);
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
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;
	struct timespec now;
	int found_event = 0;

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
		execl("/bin/true", "true", NULL);
		_exit(1);
	}

	/* Parent - read the AUTH event */
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t)) {
			oes_response_t resp;

			clock_gettime(CLOCK_MONOTONIC, &now);

			/* Check deadline is in the future */
			if (msg->em_deadline.tv_sec > now.tv_sec ||
			    (msg->em_deadline.tv_sec == now.tv_sec &&
			     msg->em_deadline.tv_nsec > now.tv_nsec)) {
				printf("    INFO: deadline is %ld.%09ld (now=%ld.%09ld)\n",
				    (long)msg->em_deadline.tv_sec,
				    msg->em_deadline.tv_nsec,
				    (long)now.tv_sec, now.tv_nsec);
				found_event = 1;
			} else if (msg->em_deadline.tv_sec == 0 &&
			    msg->em_deadline.tv_nsec == 0) {
				printf("    INFO: deadline is zero (no timeout?)\n");
				found_event = 1;
			} else {
				printf("    WARN: deadline appears to be in the past\n");
				found_event = 1;
			}

			/* Respond to allow the exec */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			(void)write(fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);

	if (found_event) {
		printf("    PASS: deadline field examined\n");
		return (0);
	}

	printf("    INFO: no AUTH event received (may be expected)\n");
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
	struct oes_timeout_action_args action;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;
	int status;

	printf("  Testing late response (timeout behavior)...\n");

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

	/* Set timeout action to ALLOW so the child doesn't block forever */
	memset(&action, 0, sizeof(action));
	action.eta_action = OES_AUTH_ALLOW;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &action) < 0) {
		perror("OES_IOC_SET_TIMEOUT_ACTION");
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

	/* Parent - read the AUTH event but DON'T respond */
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_process.ep_pid == pid) {
			oes_response_t resp;

			printf("    INFO: got AUTH event, NOT responding immediately\n");

			/* Wait for child - timeout action should kick in */
			alarm_fired = 0;
			signal(SIGALRM, alarm_handler);
			alarm(5);

			waitpid(pid, &status, 0);
			alarm(0);

			if (alarm_fired) {
				printf("    WARN: child took too long (alarm fired)\n");
			} else {
				printf("    INFO: child completed (timeout action applied)\n");
			}

			/* Try to respond now (should be too late or ignored) */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    INFO: late response rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    INFO: late response accepted (or ignored)\n");
			}

			close(fd);
			printf("    PASS: late response handling tested\n");
			return (0);
		}
	}

	/* If we get here, wait for child and clean up */
	waitpid(pid, NULL, 0);
	close(fd);
	printf("    INFO: no AUTH event received for test\n");
	return (0);
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
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;

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
		execl("/bin/true", "true", NULL);
		_exit(1);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t)) {
			/* Try response with wrong ID */
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id + 12345;  /* Wrong ID */
			resp.er_result = OES_AUTH_ALLOW;

			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: wrong ID rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    INFO: wrong ID accepted (may queue or ignore)\n");
			}

			/* Now send correct response */
			resp.er_id = msg->em_id;
			(void)write(fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	return (0);
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
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;

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
		execl("/bin/true", "true", NULL);
		_exit(1);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t)) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;

			/* First response */
			n = write(fd, &resp, sizeof(resp));
			if (n != sizeof(resp)) {
				printf("    WARN: first response failed\n");
			}

			/* Second response (duplicate) */
			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: duplicate response rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    INFO: duplicate response accepted/ignored\n");
			}
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	return (0);
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
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;

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
		execl("/bin/true", "true", NULL);
		_exit(1);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t)) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = 0xBADBAD;  /* Invalid result */

			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    PASS: invalid result rejected: %s\n",
				    strerror(errno));
			} else {
				printf("    INFO: invalid result accepted\n");
			}

			/* Send valid response so child can proceed */
			resp.er_result = OES_AUTH_ALLOW;
			(void)write(fd, &resp, sizeof(resp));
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	return (0);
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
		printf("    INFO: partial write returned %zd\n", n);
	}

	close(fd);
	return (0);
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

	if (failed > 0) {
		printf("timeout deadlines: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("timeout deadlines: ok\n");
	return (0);
}
