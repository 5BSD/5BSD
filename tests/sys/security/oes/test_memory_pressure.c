/*
 * OES memory pressure and resource exhaustion tests.
 *
 * Tests behavior under resource constraints including
 * many clients, many muted entries, and queue exhaustion.
 */
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/resource.h>
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
 * Test opening many OES clients.
 */
static int
test_many_clients(void)
{
	int fds[100];
	int i, opened = 0, failed = 0;

	printf("  Testing many concurrent clients (100)...\n");

	for (i = 0; i < 100; i++) {
		fds[i] = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fds[i] < 0) {
			if (opened == 0) {
				perror("open /dev/oes (first)");
				return (1);
			}
			failed++;
		} else {
			opened++;
		}
	}

	printf("    INFO: opened %d clients, %d failed\n", opened, failed);

	/* Close all */
	for (i = 0; i < 100; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	printf("    PASS: many clients tested\n");
	return (0);
}

/*
 * Test many clients all in AUTH mode.
 */
static int
test_many_auth_clients(void)
{
	int fds[50];
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_AUTH_EXEC };
	int i, configured = 0;

	printf("  Testing many AUTH clients (50)...\n");

	for (i = 0; i < 50; i++) {
		fds[i] = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fds[i] < 0) {
			continue;
		}

		memset(&mode, 0, sizeof(mode));
		mode.ema_mode = OES_MODE_AUTH;
		if (ioctl(fds[i], OES_IOC_SET_MODE, &mode) < 0) {
			close(fds[i]);
			fds[i] = -1;
			continue;
		}

		memset(&sub, 0, sizeof(sub));
		sub.esa_events = events;
		sub.esa_count = 1;
		sub.esa_flags = OES_SUB_REPLACE;
		if (ioctl(fds[i], OES_IOC_SUBSCRIBE, &sub) < 0) {
			close(fds[i]);
			fds[i] = -1;
			continue;
		}

		configured++;
	}

	printf("    INFO: configured %d AUTH clients\n", configured);

	/* Close all */
	for (i = 0; i < 50; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}

	printf("    PASS: many AUTH clients tested\n");
	return (0);
}

/*
 * Test many muted processes.
 */
static int
test_many_muted_processes(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_EXEC };
	pid_t pids[100];
	int i, muted = 0;

	printf("  Testing many muted processes (100)...\n");

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
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Fork many children and mute them */
	for (i = 0; i < 100; i++) {
		pids[i] = fork();
		if (pids[i] < 0)
			continue;

		if (pids[i] == 0) {
			/* Child - sleep briefly then exit */
			usleep(100000);
			_exit(0);
		}

		/* Parent - mute the child by token */
		memset(&mute, 0, sizeof(mute));
		mute.emu_token.ept_id = pids[i];
		mute.emu_token.ept_genid = 0;  /* Generation may not match */
		mute.emu_flags = 0;

		if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) == 0) {
			muted++;
		}
	}

	printf("    INFO: muted %d processes\n", muted);

	/* Wait for all children */
	for (i = 0; i < 100; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	close(fd);
	printf("    PASS: many muted processes tested\n");
	return (0);
}

/*
 * Test many muted paths.
 */
static int
test_many_muted_paths(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_path_args mute;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	int i, muted = 0;

	printf("  Testing many muted paths (200)...\n");

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
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Mute many paths */
	for (i = 0; i < 200; i++) {
		memset(&mute, 0, sizeof(mute));
		snprintf(mute.emp_path, sizeof(mute.emp_path),
		    "/tmp/mute_test_%04d", i);
		mute.emp_type = OES_MUTE_PATH_LITERAL;

		if (ioctl(fd, OES_IOC_MUTE_PATH, &mute) == 0) {
			muted++;
		} else if (muted > 0 && errno == ENOMEM) {
			printf("    INFO: hit memory limit at %d paths\n", muted);
			break;
		}
	}

	printf("    INFO: muted %d paths\n", muted);

	/* Clear all */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PATHS) < 0) {
		printf("    INFO: UNMUTE_ALL_PATHS: %s\n", strerror(errno));
	}

	close(fd);
	printf("    PASS: many muted paths tested\n");
	return (0);
}

/*
 * Test event queue exhaustion.
 */
static int
test_queue_exhaustion(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	pid_t pids[500];
	int i, spawned = 0;
	int queue_full_detected = 0;

	printf("  Testing event queue exhaustion (500 events)...\n");

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
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		return (1);
	}

	/* Spawn many processes that generate events */
	for (i = 0; i < 500; i++) {
		pids[i] = fork();
		if (pids[i] < 0)
			continue;

		if (pids[i] == 0) {
			/* Child - open many files */
			int j;
			for (j = 0; j < 10; j++) {
				int tmpfd = open("/etc/passwd", O_RDONLY);
				if (tmpfd >= 0)
					close(tmpfd);
			}
			_exit(0);
		}
		spawned++;
	}

	/* Don't read - let queue fill up */
	usleep(500000);

	/* Now try to read - check for dropped events */
	int count = 0;
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	while (test_wait_event(fd, msg, 100) == 0)
		count++;

	/* Wait for children */
	for (i = 0; i < 500; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], NULL, 0);
	}

	close(fd);

	printf("    INFO: spawned %d, received %d events\n", spawned, count);
	if (queue_full_detected || count < spawned * 5) {
		printf("    INFO: dropped events detected (queue full)\n");
	}
	printf("    PASS: queue exhaustion tested\n");
	return (0);
}

/*
 * Test rapid open/close of clients.
 */
static int
test_rapid_open_close(void)
{
	int i;
	int succeeded = 0;

	printf("  Testing rapid open/close cycles (1000)...\n");

	for (i = 0; i < 1000; i++) {
		int fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fd >= 0) {
			close(fd);
			succeeded++;
		}
	}

	printf("    INFO: %d open/close cycles succeeded\n", succeeded);
	printf("    PASS: rapid open/close tested\n");
	return (0);
}

/*
 * Test decision cache filling.
 */
static int
test_cache_filling(void)
{
	int fd;
	struct oes_mode_args mode;
	oes_cache_entry_t entry;
	int i, added = 0;

	printf("  Testing decision cache filling...\n");

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

	/* Add many cache entries */
	for (i = 0; i < 1000; i++) {
		memset(&entry, 0, sizeof(entry));
		entry.ece_key.eck_event = OES_EVENT_AUTH_EXEC;
		entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
		entry.ece_key.eck_process.ept_id = 1000 + i;
		entry.ece_key.eck_process.ept_genid = 1;
		entry.ece_key.eck_file.eft_id = i + 1;
		entry.ece_key.eck_file.eft_dev = 0;
		entry.ece_result = OES_AUTH_ALLOW;
		entry.ece_ttl_ms = 1000;

		if (ioctl(fd, OES_IOC_CACHE_ADD, &entry) == 0) {
			added++;
		} else if (errno == ENOMEM || errno == ENOSPC) {
			printf("    INFO: cache full at %d entries\n", added);
			break;
		}
	}

	printf("    INFO: added %d cache entries\n", added);

	/* Clear cache */
	if (ioctl(fd, OES_IOC_CACHE_CLEAR) < 0) {
		printf("    INFO: CACHE_CLEAR: %s\n", strerror(errno));
	}

	close(fd);
	printf("    PASS: cache filling tested\n");
	return (0);
}

/*
 * Test file descriptor limits.
 */
static int
test_fd_limits(void)
{
	struct rlimit rl;
	int *fds;
	rlim_t soft_limit;
	int i, opened = 0;

	printf("  Testing near fd limit...\n");

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		perror("getrlimit");
		return (1);
	}

	soft_limit = rl.rlim_cur;
	if (soft_limit > 1024) {
		soft_limit = 1024;  /* Don't go crazy */
	}

	printf("    INFO: fd limit is %llu\n", (unsigned long long)soft_limit);

	fds = malloc(soft_limit * sizeof(int));
	if (fds == NULL) {
		perror("malloc");
		return (1);
	}

	/* Open many fds to approach limit */
	for (i = 0; i < (int)soft_limit - 10; i++) {
		fds[i] = open("/dev/null", O_RDONLY);
		if (fds[i] < 0)
			break;
		opened++;
	}

	printf("    INFO: opened %d /dev/null fds\n", opened);

	/* Now try to open OES */
	int oes_fd = open("/dev/oes", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (oes_fd >= 0) {
		printf("    PASS: opened OES near fd limit\n");
		close(oes_fd);
	} else {
		printf("    INFO: couldn't open OES near limit: %s\n",
		    strerror(errno));
	}

	/* Clean up */
	for (i = 0; i < opened; i++) {
		close(fds[i]);
	}
	free(fds);

	return (0);
}

/*
 * Test subscribe/unsubscribe cycling.
 */
static int
test_subscribe_cycling(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events1[] = { OES_EVENT_NOTIFY_EXEC };
	oes_event_type_t events2[] = { OES_EVENT_NOTIFY_OPEN, OES_EVENT_NOTIFY_FORK };
	oes_event_type_t events3[] = { OES_EVENT_NOTIFY_EXIT };
	int i;

	printf("  Testing rapid subscribe cycling (500 times)...\n");

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

	for (i = 0; i < 500; i++) {
		memset(&sub, 0, sizeof(sub));
		sub.esa_flags = OES_SUB_REPLACE;

		switch (i % 3) {
		case 0:
			sub.esa_events = events1;
			sub.esa_count = 1;
			break;
		case 1:
			sub.esa_events = events2;
			sub.esa_count = 2;
			break;
		case 2:
			sub.esa_events = events3;
			sub.esa_count = 1;
			break;
		}

		if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
			perror("OES_IOC_SUBSCRIBE");
			close(fd);
			return (1);
		}
	}

	close(fd);
	printf("    PASS: subscribe cycling completed\n");
	return (0);
}

int
main(void)
{
	int failed = 0;

	printf("Testing memory pressure and resource exhaustion...\n");

	failed += test_many_clients();
	failed += test_many_auth_clients();
	failed += test_many_muted_processes();
	failed += test_many_muted_paths();
	failed += test_queue_exhaustion();
	failed += test_rapid_open_close();
	failed += test_cache_filling();
	failed += test_fd_limits();
	failed += test_subscribe_cycling();

	if (failed > 0) {
		printf("memory pressure: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("memory pressure: ok\n");
	return (0);
}
