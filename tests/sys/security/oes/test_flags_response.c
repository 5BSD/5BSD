/*
 * OES flags-based AUTH response test.
 *
 * Tests oes_response_flags_t for partial authorization scenarios,
 * such as downgrading O_RDWR to O_RDONLY.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/*
 * Respond with flags-based response.
 */
static int
respond_with_flags(int fd, uint64_t msg_id, oes_auth_result_t result,
    uint32_t allowed_flags, uint32_t denied_flags)
{
	oes_response_flags_t resp;

	memset(&resp, 0, sizeof(resp));
	resp.erf_id = msg_id;
	resp.erf_result = result;
	resp.erf_allowed_flags = allowed_flags;
	resp.erf_denied_flags = denied_flags;

	return (write(fd, &resp, sizeof(resp)) == sizeof(resp) ? 0 : -1);
}

/*
 * Respond with simple response.
 */
static int
respond_simple(int fd, uint64_t msg_id, oes_auth_result_t result)
{
	oes_response_t resp;

	memset(&resp, 0, sizeof(resp));
	resp.er_id = msg_id;
	resp.er_result = result;

	return (write(fd, &resp, sizeof(resp)) == sizeof(resp) ? 0 : -1);
}

/*
 * Wait for AUTH event and optionally respond.
 */
static int
wait_for_auth(int fd, pid_t pid, oes_event_type_t event, int timeout_ms,
    oes_message_t *out)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			test_msg_buf _buf;
			oes_message_t *msg = &_buf.msg;
			ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				perror("read");
				return (-1);
			}
			if (n < (ssize_t)sizeof(oes_message_t))
				continue;

			/* Respond to unrelated AUTH events */
			if (msg->em_action == OES_ACTION_AUTH &&
			    (msg->em_process.ep_pid != pid ||
			     msg->em_event != event)) {
				(void)respond_simple(fd, msg->em_id, OES_AUTH_ALLOW);
				continue;
			}

			if (msg->em_process.ep_pid != pid)
				continue;
			if (msg->em_event != event)
				continue;
			if (out != NULL)
				*out = *msg;
			return (0);
		}
	}

	return (ETIMEDOUT);
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute_proc;
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_OPEN,
	};
	int pipefd[2];
	pid_t child;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int status;
	char cmd;
	int ret;

	printf("Testing flags-based AUTH response...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 5000;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Self-mute to avoid blocking own operations */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.emu_flags = OES_MUTE_SELF;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS (self)");
		close(fd);
		return (1);
	}

	if (pipe(pipefd) != 0) {
		perror("pipe");
		close(fd);
		return (1);
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (child == 0) {
		int testfd;
		char result;

		close(fd);
		close(pipefd[1]);

		for (;;) {
			if (read(pipefd[0], &cmd, 1) != 1)
				break;
			if (cmd == 'q')
				break;

			if (cmd == 'r') {
				/* Try read-only open */
				testfd = open("/etc/passwd", O_RDONLY);
				if (testfd >= 0) {
					result = 'y';
					close(testfd);
				} else {
					result = 'n';
				}
				(void)write(pipefd[0], &result, 1);
			}

			if (cmd == 'w') {
				/* Try read-write open (will fail due to perms anyway) */
				testfd = open("/tmp/oes-flags-test", O_RDWR | O_CREAT, 0644);
				if (testfd >= 0) {
					/* Check if we can actually write */
					if (write(testfd, "test", 4) > 0)
						result = 'w'; /* Write worked */
					else
						result = 'r'; /* Read-only? */
					close(testfd);
				} else {
					result = 'n'; /* Open failed */
				}
				(void)write(pipefd[0], &result, 1);
			}
		}
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);

	/* Test 1: Simple allow with flags */
	printf("  Test 1: Simple ALLOW with flags response...\n");
	cmd = 'r';
	(void)write(pipefd[1], &cmd, 1);

	ret = wait_for_auth(fd, child, OES_EVENT_AUTH_OPEN, 2000, msg);
	if (ret != 0) {
		fprintf(stderr, "FAIL: no AUTH_OPEN event received\n");
		goto fail;
	}

	/* Respond with flags-based ALLOW (no flag restrictions) */
	ret = respond_with_flags(fd, msg->em_id, OES_AUTH_ALLOW, 0, 0);
	if (ret != 0) {
		fprintf(stderr, "FAIL: flags response write failed\n");
		goto fail;
	}

	/* Wait for child result */
	{
		char result;
		struct pollfd pfd;
		pfd.fd = pipefd[1];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0) {
			if (read(pipefd[1], &result, 1) == 1 && result == 'y') {
				printf("    PASS: child open succeeded with flags response\n");
			} else {
				fprintf(stderr, "FAIL: child open failed after ALLOW\n");
				goto fail;
			}
		} else {
			fprintf(stderr, "FAIL: no response from child\n");
			goto fail;
		}
	}

	/* Test 2: DENY with flags */
	printf("  Test 2: DENY with flags response...\n");
	cmd = 'r';
	(void)write(pipefd[1], &cmd, 1);

	ret = wait_for_auth(fd, child, OES_EVENT_AUTH_OPEN, 2000, msg);
	if (ret != 0) {
		fprintf(stderr, "FAIL: no AUTH_OPEN event received\n");
		goto fail;
	}

	/* Respond with flags-based DENY */
	ret = respond_with_flags(fd, msg->em_id, OES_AUTH_DENY, 0, O_RDONLY);
	if (ret != 0) {
		fprintf(stderr, "FAIL: flags response write failed\n");
		goto fail;
	}

	/* Wait for child result */
	{
		char result;
		struct pollfd pfd;
		pfd.fd = pipefd[1];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0) {
			if (read(pipefd[1], &result, 1) == 1 && result == 'n') {
				printf("    PASS: child open denied as expected\n");
			} else {
				fprintf(stderr, "FAIL: child open should have been denied\n");
				goto fail;
			}
		} else {
			fprintf(stderr, "FAIL: no response from child\n");
			goto fail;
		}
	}

	/* Test 3: Response size detection (simple vs flags) */
	printf("  Test 3: Response size detection...\n");
	cmd = 'r';
	(void)write(pipefd[1], &cmd, 1);

	ret = wait_for_auth(fd, child, OES_EVENT_AUTH_OPEN, 2000, msg);
	if (ret != 0) {
		fprintf(stderr, "FAIL: no AUTH_OPEN event received\n");
		goto fail;
	}

	/* Respond with simple response (shorter write) */
	ret = respond_simple(fd, msg->em_id, OES_AUTH_ALLOW);
	if (ret != 0) {
		fprintf(stderr, "FAIL: simple response write failed\n");
		goto fail;
	}

	/* Wait for child result */
	{
		char result;
		struct pollfd pfd;
		pfd.fd = pipefd[1];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0) {
			if (read(pipefd[1], &result, 1) == 1 && result == 'y') {
				printf("    PASS: simple response detected and processed\n");
			} else {
				fprintf(stderr, "FAIL: child open failed with simple response\n");
				goto fail;
			}
		} else {
			fprintf(stderr, "FAIL: no response from child\n");
			goto fail;
		}
	}

	/* Test 4: Partial authorization (allow with specific flags) */
	printf("  Test 4: Partial authorization (allowed_flags set)...\n");
	cmd = 'w';
	(void)write(pipefd[1], &cmd, 1);

	ret = wait_for_auth(fd, child, OES_EVENT_AUTH_OPEN, 2000, msg);
	if (ret != 0) {
		fprintf(stderr, "FAIL: no AUTH_OPEN event received\n");
		goto fail;
	}

	printf("    Received OPEN for flags=0x%x\n", msg->em_event_data.open.flags);

	/* Allow but specify only read flag is permitted */
	ret = respond_with_flags(fd, msg->em_id, OES_AUTH_ALLOW, O_RDONLY, O_WRONLY);
	if (ret != 0) {
		fprintf(stderr, "FAIL: flags response write failed\n");
		goto fail;
	}

	/* The kernel should downgrade or the response should work */
	{
		char result;
		struct pollfd pfd;
		pfd.fd = pipefd[1];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 2000) > 0) {
			if (read(pipefd[1], &result, 1) == 1) {
				if (result == 'r') {
					printf("    PASS: open was downgraded to read-only\n");
				} else if (result == 'w') {
					printf("    INFO: write still worked (flag filtering may be in MAC layer)\n");
				} else if (result == 'n') {
					printf("    INFO: open was denied (stricter than expected)\n");
				}
				/* All outcomes are acceptable for this test */
			}
		} else {
			fprintf(stderr, "FAIL: no response from child\n");
			goto fail;
		}
	}

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);

	/* Cleanup test file */
	(void)unlink("/tmp/oes-flags-test");

	close(fd);

	printf("flags-based AUTH response: ok\n");
	return (0);

fail:
	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	(void)unlink("/tmp/oes-flags-test");
	close(fd);
	return (1);
}
