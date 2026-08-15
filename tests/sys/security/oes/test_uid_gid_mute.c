/*
 * OES UID/GID muting test.
 */
#include <sys/ioctl.h>
#include <sys/wait.h>

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
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	struct oes_mute_uid_args uid_mute;
	struct oes_mute_gid_args gid_mute;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
	};
	int pipefd[2];
	pid_t child;
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

	/* Self-mute to avoid noise from this process. */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) < 0) {
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

	/* Test 1: Verify child events are received normally. */
	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "expected child open event (baseline)\n");
		goto fail;
	}

	/* Test 2: Mute our own UID and verify child events are suppressed. */
	memset(&uid_mute, 0, sizeof(uid_mute));
	uid_mute.emu_uid = getuid();
	if (ioctl(fd, OES_IOC_MUTE_UID, &uid_mute) < 0) {
		perror("OES_IOC_MUTE_UID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "UID mute failed (event still delivered)\n");
		goto fail;
	}

	/* Test 3: Unmute UID and verify events resume. */
	if (ioctl(fd, OES_IOC_UNMUTE_UID, &uid_mute) < 0) {
		perror("OES_IOC_UNMUTE_UID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "UID unmute failed (event missing)\n");
		goto fail;
	}

	/* Test 4: Mute our own GID and verify child events are suppressed. */
	memset(&gid_mute, 0, sizeof(gid_mute));
	gid_mute.emg_gid = getgid();
	if (ioctl(fd, OES_IOC_MUTE_GID, &gid_mute) < 0) {
		perror("OES_IOC_MUTE_GID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "GID mute failed (event still delivered)\n");
		goto fail;
	}

	/* Test 5: Unmute GID and verify events resume. */
	if (ioctl(fd, OES_IOC_UNMUTE_GID, &gid_mute) < 0) {
		perror("OES_IOC_UNMUTE_GID");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "GID unmute failed (event missing)\n");
		goto fail;
	}

	/* Test 6: Mute both UID and GID, then unmute all. */
	if (ioctl(fd, OES_IOC_MUTE_UID, &uid_mute) < 0) {
		perror("OES_IOC_MUTE_UID (2)");
		goto fail;
	}
	if (ioctl(fd, OES_IOC_MUTE_GID, &gid_mute) < 0) {
		perror("OES_IOC_MUTE_GID (2)");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "UID+GID mute failed (event still delivered)\n");
		goto fail;
	}

	if (ioctl(fd, OES_IOC_UNMUTE_ALL_UIDS, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_UIDS");
		goto fail;
	}
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_GIDS, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_GIDS");
		goto fail;
	}

	cmd = 'o';
	(void)write(pipefd[1], &cmd, 1);
	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 2000, NULL);
	if (ret != 0) {
		fprintf(stderr, "unmute all UIDs/GIDs failed (event missing)\n");
		goto fail;
	}

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);

	printf("uid_gid_mute: ok\n");
	return (0);

fail:
	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);
	return (1);
}
