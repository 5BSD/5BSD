/*
 * OES unmount event test.
 *
 * Tests NOTIFY_UNMOUNT event by mounting and unmounting a filesystem.
 * Tries tmpfs first, falls back to mdmfs (memory disk).
 * Requires root privileges.
 */
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/stat.h>
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

#define TEST_MOUNTPOINT	"/tmp/oes_test_mount"
#define TEST_MDFILE	"/tmp/oes_test_md"

static int
read_events(int fd, int *unmount_seen, const char *expected_path)
{
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;

	for (;;) {
		if (test_wait_event(fd, msg, 10) != 0)
			return (0);

		if (msg->em_event == OES_EVENT_NOTIFY_UNMOUNT) {
			fprintf(stderr, "  got NOTIFY_UNMOUNT: mountpoint=%s fstype=%s\n",
			    oes_msg_string(msg, msg->em_event_data.unmount.mountpoint.ef_path_off),
			    msg->em_event_data.unmount.fstype);
			if (expected_path != NULL &&
			    strstr(oes_msg_string(msg, msg->em_event_data.unmount.mountpoint.ef_path_off),
			    expected_path) != NULL) {
				*unmount_seen = 1;
			} else if (expected_path == NULL) {
				*unmount_seen = 1;
			}
		}
	}
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_UNMOUNT,
	};
	int unmount_seen = 0;
	struct pollfd pfd;
	struct timespec start;
	int ret;

	printf("Testing NOTIFY_UNMOUNT event...\n");

	if (geteuid() != 0) {
		printf("SKIP: test requires root\n");
		return (0);
	}

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
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

	/*
	 * Clear the default self-mute so we can see our own unmount events.
	 * (security.oes.default_self_mute=1 would otherwise block them.)
	 */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}

	/* Create mountpoint */
	(void)rmdir(TEST_MOUNTPOINT);
	if (mkdir(TEST_MOUNTPOINT, 0755) < 0 && errno != EEXIST) {
		perror("mkdir mountpoint");
		close(fd);
		return (1);
	}

	/* Try tmpfs first */
	ret = mount("tmpfs", TEST_MOUNTPOINT, MNT_NOSUID | MNT_NOEXEC, NULL);
	if (ret < 0) {
		int tmpfs_errno = errno;
		fprintf(stderr, "  tmpfs mount failed: %s, trying mdmfs\n",
		    strerror(tmpfs_errno));

		/* Try mdmfs as fallback - create and mount memory disk */
		char cmd[256];
		snprintf(cmd, sizeof(cmd),
		    "mdmfs -s 1m md %s 2>/dev/null", TEST_MOUNTPOINT);
		ret = system(cmd);
		if (ret != 0) {
			if (tmpfs_errno == EPERM || tmpfs_errno == ENOTSUP ||
			    tmpfs_errno == EOPNOTSUPP) {
				printf("SKIP: mount not permitted (jail/securelevel)\n");
			} else {
				fprintf(stderr, "FAIL: neither tmpfs nor mdmfs mount worked\n");
				fprintf(stderr, "  tmpfs error: %s\n", strerror(tmpfs_errno));
			}
			rmdir(TEST_MOUNTPOINT);
			close(fd);
			return (ret != 0 && (tmpfs_errno == EPERM ||
			    tmpfs_errno == ENOTSUP || tmpfs_errno == EOPNOTSUPP)) ? 0 : 1;
		}
		fprintf(stderr, "  using mdmfs instead of tmpfs\n");
	}

	/* Unmount - this should trigger the event */
	if (unmount(TEST_MOUNTPOINT, 0) < 0) {
		perror("unmount");
		rmdir(TEST_MOUNTPOINT);
		close(fd);
		return (1);
	}

	/* Wait for and read events */
	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (1) {
		struct timespec now;
		long elapsed_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 2000)
			break;

		if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
			if (read_events(fd, &unmount_seen, "oes_test_mount") < 0) {
				rmdir(TEST_MOUNTPOINT);
				close(fd);
				return (1);
			}
		}

		if (unmount_seen)
			break;
	}

	rmdir(TEST_MOUNTPOINT);
	close(fd);

	if (!unmount_seen) {
		fprintf(stderr, "FAIL: NOTIFY_UNMOUNT not received\n");
		return (1);
	}

	printf("  PASS: NOTIFY_UNMOUNT received\n");
	printf("unmount event: ok\n");
	return (0);
}
