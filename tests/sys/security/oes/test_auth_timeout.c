/*
 * OES AUTH timeout test (default action applied on timeout).
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

static int
wait_for_open_event(int fd, pid_t pid, int timeout_ms, oes_message_t *out)
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
			if (msg->em_event != OES_EVENT_AUTH_OPEN)
				continue;
			if (msg->em_action != OES_ACTION_AUTH)
				continue;
			if (msg->em_process.ep_pid != pid)
				continue;
			if (out != NULL)
				*out = *msg;
			return (0);
		}
	}

	return (ETIMEDOUT);
}

static int
wait_for_child_errno(int fd, int timeout_ms, int *out_errno)
{
	struct pollfd pfd;
	struct timespec start;

	pfd.fd = fd;
	pfd.events = POLLIN;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;
		int err;
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			n = read(fd, &err, sizeof(err));
			if (n == (ssize_t)sizeof(err)) {
				if (out_errno != NULL)
					*out_errno = err;
				return (0);
			}
		}
	}

	return (ETIMEDOUT);
}

int
main(void)
{
	int fd;
	int ctl_pipe[2];
	int res_pipe[2];
	struct oes_mode_args mode;
	struct oes_timeout_action_args timeout_action;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_invert_args invert;
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_OPEN,
	};
	pid_t child;
	int status;
	int err;
	char cmd = 'g';
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_timeout_ms = 200;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (1);
	}

	memset(&timeout_action, 0, sizeof(timeout_action));
	timeout_action.eta_action = OES_AUTH_DENY;
	if (ioctl(fd, OES_IOC_SET_TIMEOUT_ACTION, &timeout_action) < 0) {
		perror("OES_IOC_SET_TIMEOUT_ACTION");
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

	memset(&invert, 0, sizeof(invert));
	invert.emi_type = OES_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	if (ioctl(fd, OES_IOC_SET_MUTE_INVERT, &invert) < 0) {
		perror("OES_IOC_SET_MUTE_INVERT");
		close(fd);
		return (1);
	}

	if (pipe(ctl_pipe) != 0 || pipe(res_pipe) != 0) {
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
		int child_err = 0;
		int child_fd;

		close(fd);
		close(ctl_pipe[1]);
		close(res_pipe[0]);
		if (read(ctl_pipe[0], &cmd, 1) != 1)
			_exit(1);
		child_fd = open("/etc/hosts", O_RDONLY);
		if (child_fd < 0)
			child_err = errno;
		else
			close(child_fd);
		(void)write(res_pipe[1], &child_err, sizeof(child_err));
		_exit(0);
	}

	close(ctl_pipe[0]);
	close(res_pipe[1]);

	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = (uint64_t)child;
	mute.emu_token.ept_genid = 0;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_MUTE_PROCESS");
		goto fail;
	}

	(void)write(ctl_pipe[1], &cmd, 1);

	if (wait_for_open_event(fd, child, 2000, msg) != 0) {
		fprintf(stderr, "expected AUTH open event\n");
		goto fail;
	}

	if (wait_for_child_errno(res_pipe[0], 2000, &err) != 0) {
		fprintf(stderr, "timeout waiting for child result\n");
		goto fail;
	}

	if (err != EACCES) {
		fprintf(stderr, "expected EACCES on timeout, got %d\n", err);
		goto fail;
	}

	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd);

	printf("auth timeout: ok\n");
	return (0);

fail:
	(void)waitpid(child, &status, 0);
	close(ctl_pipe[1]);
	close(res_pipe[0]);
	close(fd);
	return (1);
}
