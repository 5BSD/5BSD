/*
 * OES PASSIVE mode smoke test (AUTH -> NOTIFY conversion).
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

		if (msg->em_event == OES_EVENT_AUTH_EXEC) {
			fprintf(stderr, "received AUTH exec in PASSIVE mode\n");
			return (-1);
		}

		if (msg->em_event == OES_EVENT_NOTIFY_EXEC &&
		    msg->em_action == OES_ACTION_NOTIFY) {
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
	oes_event_type_t events[] = {
		OES_EVENT_AUTH_EXEC,
	};
	pid_t pid;
	int status;
	int rc;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_PASSIVE;
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

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(fd);
		return (1);
	}

	if (pid == 0) {
		close(fd);
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}

	rc = wait_for_exec(fd, pid, 5000);
	(void)waitpid(pid, &status, 0);
	close(fd);

	if (rc != 0) {
		if (rc == ETIMEDOUT)
			fprintf(stderr, "PASSIVE exec timeout\n");
		return (1);
	}

	printf("passive mode: ok\n");
	return (0);
}
