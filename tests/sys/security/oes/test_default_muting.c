/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * OES default muting sysctl tests.
 *
 * Tests security.oes.default_muted_paths and related sysctls.
 * Requires root privileges.
 */
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>
#include "test_common.h"

static int
test_read_default_paths_sysctl(void)
{
	char buf[1024];
	size_t len = sizeof(buf);
	int ret;

	printf("  Testing read security.oes.default_muted_paths...\n");

	ret = sysctlbyname("security.oes.default_muted_paths", buf, &len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    FAIL: sysctl not found (module not loaded?)\n");
			return (1);
		}
		perror("sysctlbyname");
		return (1);
	}

	printf("    current value: '%s'\n", buf);
	printf("    PASS: read default_muted_paths\n");
	return (0);
}

/*
 * security.oes.default_self_mute is gone: a client never receives its own
 * processes' events, unconditionally (oes(4), "A client's own processes").
 */
static int
test_no_default_self_mute_sysctl(void)
{
	int val;
	size_t len = sizeof(val);

	printf("  Testing security.oes.default_self_mute is absent...\n");

	if (sysctlbyname("security.oes.default_self_mute", &val, &len, NULL,
	    0) == 0 || errno != ENOENT) {
		printf("    FAIL: security.oes.default_self_mute exists\n");
		return (1);
	}
	printf("    PASS: no default_self_mute sysctl\n");
	return (0);
}

static int
test_write_default_paths_sysctl(void)
{
	char old_val[1024];
	char new_val[] = "/dev:/proc";
	size_t old_len = sizeof(old_val);
	int ret;

	printf("  Testing write security.oes.default_muted_paths...\n");

	if (geteuid() != 0) {
		printf("    SKIP: requires root\n");
		return (0);
	}

	/* Save old value */
	ret = sysctlbyname("security.oes.default_muted_paths", old_val, &old_len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    FAIL: sysctl not found (module not loaded?)\n");
			return (1);
		}
		perror("sysctlbyname (read)");
		return (1);
	}

	/* Write new value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    new_val, strlen(new_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (write)");
		return (1);
	}

	/* Restore old value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    old_val, strlen(old_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (restore)");
		return (1);
	}

	printf("    PASS: write default_muted_paths\n");
	return (0);
}

static int
test_default_mute_applied(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_get_muted_paths_args get_paths;
	struct oes_muted_path_entry entries[16];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	char old_val[1024];
	char new_val[] = "/usr/share";
	size_t old_len = sizeof(old_val);
	int ret;
	size_t i;
	int found = 0, mutable = 0;

	printf("  Testing default muting applied on mode set...\n");

	if (geteuid() != 0) {
		printf("    SKIP: requires root\n");
		return (0);
	}

	/* Save old sysctl value */
	ret = sysctlbyname("security.oes.default_muted_paths", old_val, &old_len, NULL, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			printf("    FAIL: sysctl not found (module not loaded?)\n");
			return (1);
		}
		perror("sysctlbyname (read)");
		return (1);
	}

	/* Set test value */
	ret = sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    new_val, strlen(new_val) + 1);
	if (ret < 0) {
		perror("sysctlbyname (write)");
		return (1);
	}

	/* Open new client and set mode */
	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		/* Restore */
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	/* Query muted paths - should include /usr/share */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
		    old_val, strlen(old_val) + 1);
		return (1);
	}

	for (i = 0; i < get_paths.egmpa_actual && i < 16; i++) {
		if (strstr(entries[i].emp_path, "/usr/share") != NULL) {
			found = 1;
			break;
		}
	}
	if (found && ioctl(fd, OES_IOC_UNMUTE_ALL_PATHS) == 0) {
		memset(&get_paths, 0, sizeof(get_paths));
		get_paths.egmpa_entries = entries;
		get_paths.egmpa_count = 16;
		if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) == 0 &&
		    get_paths.egmpa_actual == 0)
			mutable = 1;
	}

	close(fd);

	/* Restore old sysctl value */
	sysctlbyname("security.oes.default_muted_paths", NULL, NULL,
	    old_val, strlen(old_val) + 1);

	if (found && mutable) {
		printf("    PASS: default muted path applied and removable\n");
		return (0);
	}
	printf("    FAIL: default muted path was %s and %s\n",
	    found ? "applied" : "not applied",
	    mutable ? "removable" : "not removable");
	return (1);
}

/*
 * The rule that replaced the default self-mute is not a mute: a new client
 * lists no self entry, and clearing every process mute does not let it
 * receive its opener's events.  The fence is an open by a child, which is
 * not a reader of the client.
 */
static int
test_own_events_not_a_mute(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_get_muted_processes_args get_procs;
	struct oes_muted_process_entry entries[16];
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	test_msg_buf buf;
	size_t i;
	pid_t mypid = getpid(), child;
	int own = 0, fence = 0, listed = 0, status, tfd;

	printf("  Testing own events are not a removable mute...\n");

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open /dev/oes");
		return (1);
	}
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = 1;
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) < 0 ||
	    ioctl(fd, OES_IOC_SUBSCRIBE, &sub) < 0) {
		perror("client setup");
		close(fd);
		return (1);
	}

	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		return (1);
	}
	for (i = 0; i < get_procs.egmp_actual && i < 16; i++)
		if (entries[i].emp_token.ept_id == (uint64_t)mypid)
			listed = 1;

	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}
	tfd = open("/etc/passwd", O_RDONLY);
	if (tfd >= 0)
		close(tfd);
	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	if (child == 0) {
		close(fd);
		tfd = open("/etc/hosts", O_RDONLY);
		_exit(tfd >= 0 ? 0 : 1);
	}
	(void)waitpid(child, &status, 0);
	while (!fence && test_wait_event(fd, &buf.msg,
	    OES_TEST_DEADLINE_MS) == 0) {
		if (buf.msg.em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (buf.msg.em_process.ep_pid == mypid)
			own++;
		else if (buf.msg.em_process.ep_pid == child)
			fence = 1;
	}
	close(fd);

	if (!listed && fence && own == 0) {
		printf("    PASS: no self entry, own events never delivered\n");
		return (0);
	}
	printf("    FAIL: self entry %s, fence %s, %d own events\n",
	    listed ? "listed" : "absent", fence ? "seen" : "not seen", own);
	return (1);
}

int
main(void)
{
	int failed = 0;

	printf("Testing default muting sysctls...\n");

	failed += test_read_default_paths_sysctl();
	failed += test_no_default_self_mute_sysctl();
	failed += test_write_default_paths_sysctl();
	failed += test_default_mute_applied();
	failed += test_own_events_not_a_mute();

	if (failed > 0) {
		printf("default muting: FAILED (%d tests)\n", failed);
		return (1);
	}

	printf("default muting: ok\n");
	return (0);
}
