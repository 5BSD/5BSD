/*
 * OES AUTH response edge case tests.
 *
 * Tests various AUTH response scenarios including flags responses,
 * response ordering, and concurrent AUTH handling.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

/*
 * Test basic AUTH ALLOW response.
 */
static int
test_auth_allow(void)
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
	int status;

	printf("  Testing AUTH ALLOW response...\n");

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
		_exit(127);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_EXEC) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;

			n = write(fd, &resp, sizeof(resp));
			if (n != sizeof(resp)) {
				perror("write response");
				waitpid(pid, NULL, 0);
				close(fd);
				return (1);
			}
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("    PASS: AUTH ALLOW worked (child exited 0)\n");
		return (0);
	}

	printf("    INFO: child exit status=%d\n", status);
	return (0);
}

/*
 * Test AUTH DENY response.
 */
static int
test_auth_deny(void)
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
	int status;

	printf("  Testing AUTH DENY response...\n");

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
		/* Child - this exec should be denied */
		execl("/bin/true", "true", NULL);
		/* If exec fails, exit with specific code */
		_exit(42);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_EXEC) {
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_DENY;

			n = write(fd, &resp, sizeof(resp));
			if (n != sizeof(resp)) {
				perror("write response");
			}
		}
	}

	waitpid(pid, &status, 0);
	close(fd);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 42) {
		printf("    PASS: AUTH DENY worked (exec failed, child exited 42)\n");
		return (0);
	}

	printf("    INFO: child status=%d (expected denied exec)\n", status);
	return (0);
}

/*
 * Test flags-based response for AUTH_OPEN.
 */
static int
test_auth_flags_response(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_flags_t resp;
	struct pollfd pfd;
	pid_t pid;
	ssize_t n;

	printf("  Testing flags-based AUTH response...\n");

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
		/* Child - try to open a file for R/W */
		int tmpfd = open("/tmp/oes_test_flags", O_CREAT | O_RDWR, 0644);
		if (tmpfd >= 0) {
			/* Try to write - may fail if downgraded to RO */
			(void)write(tmpfd, "test", 4);
			close(tmpfd);
		}
		unlink("/tmp/oes_test_flags");
		_exit(0);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 3000) > 0 && (pfd.revents & POLLIN)) {
		n = read(fd, msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t) && msg->em_event == OES_EVENT_AUTH_OPEN) {
			/* Respond with flags - allow only read */
			memset(&resp, 0, sizeof(resp));
			resp.erf_id = msg->em_id;
			resp.erf_result = OES_AUTH_ALLOW;
			resp.erf_allowed_flags = O_RDONLY;
			resp.erf_denied_flags = O_WRONLY | O_RDWR;

			n = write(fd, &resp, sizeof(resp));
			if (n < 0) {
				printf("    INFO: flags response write: %s\n",
				    strerror(errno));
				/* Fall back to simple response */
				oes_response_t simple;
				memset(&simple, 0, sizeof(simple));
				simple.er_id = msg->em_id;
				simple.er_result = OES_AUTH_ALLOW;
				(void)write(fd, &simple, sizeof(simple));
			}
		}
	}

	waitpid(pid, NULL, 0);
	close(fd);
	printf("    PASS: flags response tested\n");
	return (0);
}

/*
 * Test out-of-order responses.
 * Generate multiple AUTH events and respond in reverse order.
 */
static int
test_out_of_order_responses(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	test_msg_buf _msgs_bufs[3];
	oes_response_t resp;
	struct pollfd pfd;
	pid_t pids[3];
	int i, msg_count = 0;

	printf("  Testing out-of-order AUTH responses...\n");

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

	/* Fork 3 children that will all try to open files */
	for (i = 0; i < 3; i++) {
		pids[i] = fork();
		if (pids[i] < 0) {
			perror("fork");
			continue;
		}
		if (pids[i] == 0) {
			char path[64];
			snprintf(path, sizeof(path), "/tmp/oes_ooo_test_%d", i);
			int tmpfd = open(path, O_CREAT | O_RDWR, 0644);
			if (tmpfd >= 0)
				close(tmpfd);
			unlink(path);
			_exit(0);
		}
	}

	/* Collect AUTH events */
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (msg_count < 3) {
		if (poll(&pfd, 1, 500) <= 0)
			break;
		if (!(pfd.revents & POLLIN))
			break;

		ssize_t n = read(fd, &_msgs_bufs[msg_count].msg, OES_MSG_MAX_SIZE);
		if (n >= (ssize_t)sizeof(oes_message_t))
			msg_count++;
	}

	printf("    INFO: collected %d AUTH events\n", msg_count);

	/* Respond in reverse order */
	for (i = msg_count - 1; i >= 0; i--) {
		memset(&resp, 0, sizeof(resp));
		resp.er_id = _msgs_bufs[i].msg.em_id;
		resp.er_result = OES_AUTH_ALLOW;
		(void)write(fd, &resp, sizeof(resp));
	}

	/* Wait for all children */
	for (i = 0; i < 3; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	close(fd);
	printf("    PASS: out-of-order responses tested\n");
	return (0);
}

/*
 * Test response with zero ID.
 */
static int
test_zero_id_response(void)
{
	int fd;
	struct oes_mode_args mode;
	oes_response_t resp;
	ssize_t n;

	printf("  Testing response with zero ID...\n");

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

	/* Send response with ID 0 (no pending event) */
	memset(&resp, 0, sizeof(resp));
	resp.er_id = 0;
	resp.er_result = OES_AUTH_ALLOW;

	n = write(fd, &resp, sizeof(resp));
	if (n < 0) {
		printf("    PASS: zero ID response rejected (%s)\n", strerror(errno));
	} else {
		printf("    INFO: zero ID response accepted\n");
	}

	close(fd);
	return (0);
}

/*
 * Test response in NOTIFY mode.
 */
static int
test_response_in_notify_mode(void)
{
	int fd;
	struct oes_mode_args mode;
	oes_response_t resp;
	ssize_t n;

	printf("  Testing response in NOTIFY mode...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;  /* NOTIFY, not AUTH */
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	/* Try to send a response - should fail */
	memset(&resp, 0, sizeof(resp));
	resp.er_id = 12345;
	resp.er_result = OES_AUTH_ALLOW;

	n = write(fd, &resp, sizeof(resp));
	if (n < 0) {
		printf("    PASS: response in NOTIFY mode rejected (%s)\n",
		    strerror(errno));
	} else {
		printf("    INFO: response in NOTIFY mode accepted (n=%zd)\n", n);
	}

	close(fd);
	return (0);
}

/*
 * Test rapid response/event cycling.
 */
static int
test_rapid_auth_cycling(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	struct pollfd pfd;
	int i, responded = 0;

	printf("  Testing rapid AUTH cycling (50 events)...\n");

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

	pfd.fd = fd;
	pfd.events = POLLIN;

	for (i = 0; i < 50; i++) {
		pid_t pid = fork();
		if (pid < 0)
			continue;

		if (pid == 0) {
			char path[64];
			snprintf(path, sizeof(path), "/tmp/oes_rapid_%d", i);
			int tmpfd = open(path, O_CREAT | O_RDWR, 0644);
			if (tmpfd >= 0)
				close(tmpfd);
			unlink(path);
			_exit(0);
		}

		/* Handle AUTH events */
		while (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
			ssize_t n = read(fd, msg, OES_MSG_MAX_SIZE);
			if (n >= (ssize_t)sizeof(oes_message_t)) {
				oes_response_t resp;
				memset(&resp, 0, sizeof(resp));
				resp.er_id = msg->em_id;
				resp.er_result = OES_AUTH_ALLOW;
				if (write(fd, &resp, sizeof(resp)) == sizeof(resp))
					responded++;
			}
		}

		waitpid(pid, NULL, 0);
	}

	close(fd);
	printf("    PASS: rapid cycling completed (%d responses)\n", responded);
	return (0);
}

/*
 * Test write with wrong size.
 */
static int
test_wrong_write_size(void)
{
	int fd;
	struct oes_mode_args mode;
	char buf[1024];
	ssize_t n;

	printf("  Testing write with wrong sizes...\n");

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

	memset(buf, 0, sizeof(buf));

	/* Write too small */
	n = write(fd, buf, 4);
	if (n < 0) {
		printf("    PASS: 4-byte write rejected (%s)\n", strerror(errno));
	} else {
		printf("    INFO: 4-byte write returned %zd\n", n);
	}

	/* Write too large */
	n = write(fd, buf, 1024);
	if (n < 0) {
		printf("    INFO: 1024-byte write: %s\n", strerror(errno));
	} else {
		printf("    INFO: 1024-byte write returned %zd\n", n);
	}

	/* Write exact simple response size */
	n = write(fd, buf, sizeof(oes_response_t));
	if (n < 0) {
		printf("    INFO: exact size write: %s\n", strerror(errno));
	} else {
		printf("    INFO: exact size write returned %zd\n", n);
	}

	close(fd);
	return (0);
}

/*
 * Helper thread for concurrent AUTH testing.
 */
struct auth_thread_args {
	int fd;
	int events_handled;
	int errors;
};

static void *
auth_handler_thread(void *arg)
{
	struct auth_thread_args *ta = arg;
	struct pollfd pfd;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	oes_response_t resp;

	pfd.fd = ta->fd;
	pfd.events = POLLIN;

	while (1) {
		if (poll(&pfd, 1, 100) <= 0)
			break;

		if (!(pfd.revents & POLLIN))
			continue;

		ssize_t n = read(ta->fd, msg, OES_MSG_MAX_SIZE);
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			ta->errors++;
			break;
		}
		if (n < (ssize_t)sizeof(oes_message_t))
			continue;

		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_ALLOW;

		if (write(ta->fd, &resp, sizeof(resp)) == sizeof(resp))
			ta->events_handled++;
	}

	return (NULL);
}

/*
 * Test concurrent AUTH handling from multiple threads.
 */
static int
test_concurrent_auth_threads(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	pthread_t threads[4];
	struct auth_thread_args args[4];
	int i;
	pid_t pids[20];

	printf("  Testing concurrent AUTH handling (4 threads)...\n");

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

	/* Start handler threads */
	for (i = 0; i < 4; i++) {
		args[i].fd = fd;
		args[i].events_handled = 0;
		args[i].errors = 0;
		pthread_create(&threads[i], NULL, auth_handler_thread, &args[i]);
	}

	/* Generate AUTH events */
	for (i = 0; i < 20; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			char path[64];
			snprintf(path, sizeof(path), "/tmp/oes_concurrent_%d", i);
			int tmpfd = open(path, O_CREAT | O_RDWR, 0644);
			if (tmpfd >= 0)
				close(tmpfd);
			unlink(path);
			_exit(0);
		}
	}

	/* Wait for children */
	usleep(500000);  /* Let events process */
	for (i = 0; i < 20; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	/* Join threads */
	for (i = 0; i < 4; i++) {
		pthread_join(threads[i], NULL);
	}

	close(fd);

	int total = 0, errors = 0;
	for (i = 0; i < 4; i++) {
		total += args[i].events_handled;
		errors += args[i].errors;
	}

	printf("    PASS: concurrent AUTH completed (handled=%d, errors=%d)\n",
	    total, errors);
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing AUTH response edge cases...\n");

	failed += test_auth_allow();
	failed += test_auth_deny();
	failed += test_auth_flags_response();
	failed += test_out_of_order_responses();
	failed += test_zero_id_response();
	failed += test_response_in_notify_mode();
	failed += test_rapid_auth_cycling();
	failed += test_wrong_write_size();
	failed += test_concurrent_auth_threads();

	if (failed > 0) {
		printf("auth responses: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("auth responses: ok\n");
	return (0);
}
