/*
 * OES mute/self-mute/inversion smoke test.
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
wait_for_any_event(int fd, pid_t pid, int timeout_ms)
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
		return (0);
	}

	return (ETIMEDOUT);
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_invert_args invert;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
	};
	int pipefd[2];
	pid_t child;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	int status;
	char cmd;
	int ret;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
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

	/* Self-mute should suppress events from this process. */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_MUTE_PROCESS (self)");
		close(fd);
		return (1);
	}

	(void)open("/etc/passwd", O_RDONLY);
	ret = wait_for_any_event(fd, getpid(), 500);
	if (ret == 0) {
		fprintf(stderr, "self-mute failed (saw own event)\n");
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
		close(fd);
		close(pipefd[1]);
		for (;;) {
			if (read(pipefd[0], &cmd, 1) != 1)
				break;
			if (cmd == 'q')
				break;
			if (cmd == 'o')
				(void)open("/etc/hosts", O_RDONLY);
		}
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);

	/* Child open -> capture token, then mute child. */
	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, msg);
	if (ret != 0) {
		fprintf(stderr, "expected child open event\n");
		goto fail;
	}

	memset(&mute, 0, sizeof(mute));
	mute.emu_token = msg->em_process.ep_token;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
		perror("OES_IOC_MUTE_PROCESS");
		goto fail;
	}

	/* Muted child should not generate events. */
	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "mute failed (event still delivered)\n");
		goto fail;
	}

	/* Invert muting: only muted processes should deliver events. */
	memset(&invert, 0, sizeof(invert));
	invert.emi_type = OES_MUTE_INVERT_PROCESS;
	invert.emi_invert = 1;
	if (ioctl(fd, OES_IOC_SET_MUTE_INVERT, &invert) < 0) {
		perror("OES_IOC_SET_MUTE_INVERT");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "mute inversion failed (missing event)\n");
		goto fail;
	}

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);

	printf("mute: ok\n");
	return (0);

fail:
	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);
	return (1);
}
