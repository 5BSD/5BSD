/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES unmount event test.
 *
 * Tests NOTIFY_UNMOUNT event by mounting and unmounting a tmpfs.  The mount
 * point is in the test's own work directory, not under /tmp: /tmp is itself a
 * tmpfs in the test guests, and a file system mounted and unmounted on a
 * tmpfs directory records a tmpfs -> <fs> lock order that WITNESS reports
 * against the system's <fs> -> tmpfs order (a /tmp on UFS) as a reversal.
 * tmpfs has no mount(2) (cmount) entry: it is mounted with nmount(2).  Kyua
 * runs it as root (required_user); a refused mount is a failure, since the
 * case then tested nothing.
 */
#include <sys/param.h>
#include <sys/uio.h>
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

#define TEST_MOUNTDIR	"oes_test_mount"

static char mountpoint[PATH_MAX];

static int
mount_tmpfs(const char *path)
{
	struct iovec iov[6];

	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "tmpfs");
	iov[1].iov_len = sizeof("tmpfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, path);
	iov[3].iov_len = strlen(path) + 1;
	iov[4].iov_base = __DECONST(char *, "from");
	iov[4].iov_len = sizeof("from");
	iov[5].iov_base = __DECONST(char *, "tmpfs");
	iov[5].iov_len = sizeof("tmpfs");
	return (nmount(iov, nitems(iov), MNT_NOSUID | MNT_NOEXEC));
}

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

	printf("Testing NOTIFY_UNMOUNT event...\n");

	if (geteuid() != 0) {
		fprintf(stderr, "FAIL: test requires root (required_user=root)\n");
		return (1);
	}
	if (getcwd(mountpoint, sizeof(mountpoint) - sizeof(TEST_MOUNTDIR) - 1) == NULL) {
		perror("getcwd");
		return (1);
	}
	strlcat(mountpoint, "/" TEST_MOUNTDIR, sizeof(mountpoint));

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
	(void)rmdir(mountpoint);
	if (mkdir(mountpoint, 0755) < 0 && errno != EEXIST) {
		perror("mkdir mountpoint");
		close(fd);
		return (1);
	}

	if (mount_tmpfs(mountpoint) < 0) {
		fprintf(stderr, "FAIL: tmpfs mount on %s: %s\n", mountpoint,
		    strerror(errno));
		rmdir(mountpoint);
		close(fd);
		return (1);
	}

	/* Unmount - this should trigger the event */
	if (unmount(mountpoint, 0) < 0) {
		perror("unmount");
		rmdir(mountpoint);
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
				rmdir(mountpoint);
				close(fd);
				return (1);
			}
		}

		if (unmount_seen)
			break;
	}

	rmdir(mountpoint);
	close(fd);

	if (!unmount_seen) {
		fprintf(stderr, "FAIL: NOTIFY_UNMOUNT not received\n");
		return (1);
	}

	printf("  PASS: NOTIFY_UNMOUNT received\n");
	printf("unmount event: ok\n");
	return (0);
}
