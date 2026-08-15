/*
 * OES multi-client NOTIFY fan-out test.
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
wait_for_exec(int fd, pid_t pid, int timeout_ms)
{
	test_msg_buf _buf;
	oes_message_t *msg = &_buf.msg;
	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct timespec now;
		long elapsed_ms;
		int remaining;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= timeout_ms)
			break;

		remaining = timeout_ms - (int)elapsed_ms;
		if (remaining > 100)
			remaining = 100;

		if (test_wait_event(fd, msg, remaining) != 0)
			continue;

		if (msg->em_process.ep_pid != pid)
			continue;
		if (msg->em_event != OES_EVENT_NOTIFY_EXEC)
			continue;
		if (msg->em_action != OES_ACTION_NOTIFY)
			continue;
		return (0);
	}

	return (ETIMEDOUT);
}

static int
setup_notify_client(int *out_fd)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_EXEC,
	};

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (-1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		return (-1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = sizeof(events) / sizeof(events[0]);
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (-1);
	}

	*out_fd = fd;
	return (0);
}

int
main(void)
{
	int fd1;
	int fd2;
	pid_t pid;
	int status;
	int rc1;
	int rc2;

	if (setup_notify_client(&fd1) != 0)
		return (1);
	if (setup_notify_client(&fd2) != 0) {
		close(fd1);
		return (1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd1);
		close(fd2);
		return (1);
	}
	if (pid == 0) {
		close(fd1);
		close(fd2);
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}

	rc1 = wait_for_exec(fd1, pid, 3000);
	rc2 = wait_for_exec(fd2, pid, 3000);
	(void)waitpid(pid, &status, 0);
	close(fd1);
	close(fd2);

	if (rc1 != 0 || rc2 != 0) {
		fprintf(stderr, "missing exec event: fd1=%d fd2=%d\n",
		    rc1, rc2);
		return (1);
	}

	printf("multi-client notify: ok\n");
	return (0);
}
