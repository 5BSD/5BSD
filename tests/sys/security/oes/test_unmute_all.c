/*
 * OES unmute-all test.
 *
 * Tests OES_IOC_UNMUTE_ALL_PROCESSES, OES_IOC_UNMUTE_ALL_PATHS,
 * and OES_IOC_UNMUTE_ALL_TARGET_PATHS.
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
	struct oes_mute_args mute_proc;
	struct oes_mute_path_args mute_path;
	struct oes_get_muted_processes_args get_procs;
	struct oes_get_muted_paths_args get_paths;
	struct oes_muted_process_entry proc_entries[16];
	struct oes_muted_path_entry path_entries[16];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
	};
	int ret;

	printf("Testing unmute-all...\n");

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

	/* ========== Test OES_IOC_UNMUTE_ALL_PROCESSES ========== */

	/* Mute self */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.emu_flags = OES_MUTE_SELF;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS");
		close(fd);
		return (1);
	}

	/* Verify self is muted */
	ret = test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_OPEN, 500,
	    NULL);
	(void)open("/etc/passwd", O_RDONLY);
	if (ret == 0) {
		fprintf(stderr, "FAIL: self not muted\n");
		close(fd);
		return (1);
	}

	/* Unmute all processes */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}

	/* Verify muted processes list is empty */
	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = proc_entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		return (1);
	}

	if (get_procs.egmp_actual != 0) {
		fprintf(stderr, "FAIL: muted processes not cleared (count=%zu)\n",
		    get_procs.egmp_actual);
		close(fd);
		return (1);
	}
	printf("  PASS: OES_IOC_UNMUTE_ALL_PROCESSES cleared all muted processes\n");

	/* Verify events now delivered */
	(void)open("/etc/hosts", O_RDONLY);
	ret = test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_OPEN, 1000,
	    NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: OPEN not delivered after unmute-all\n");
		close(fd);
		return (1);
	}
	printf("  PASS: events delivered after unmute-all processes\n");

	/* ========== Test OES_IOC_UNMUTE_ALL_PATHS ========== */

	/* Mute multiple paths */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/etc/passwd", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	strlcpy(mute_path.emp_path, "/etc/hosts", sizeof(mute_path.emp_path));
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	strlcpy(mute_path.emp_path, "/etc/group", sizeof(mute_path.emp_path));
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	/* Verify paths are muted */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}

	if (get_paths.egmpa_actual < 3) {
		fprintf(stderr, "FAIL: expected at least 3 muted paths, got %zu\n",
		    get_paths.egmpa_actual);
		close(fd);
		return (1);
	}
	printf("  Added %zu muted paths\n", get_paths.egmpa_actual);

	/* Unmute all paths */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PATHS, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PATHS");
		close(fd);
		return (1);
	}

	/* Verify paths list is empty */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}

	if (get_paths.egmpa_actual != 0) {
		fprintf(stderr, "FAIL: muted paths not cleared (count=%zu)\n",
		    get_paths.egmpa_actual);
		close(fd);
		return (1);
	}
	printf("  PASS: OES_IOC_UNMUTE_ALL_PATHS cleared all muted paths\n");

	/* ========== Test OES_IOC_UNMUTE_ALL_TARGET_PATHS ========== */

	/* Mute target paths */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/tmp/target1", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;
	mute_path.emp_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH (target)");
		close(fd);
		return (1);
	}

	strlcpy(mute_path.emp_path, "/tmp/target2", sizeof(mute_path.emp_path));
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH (target)");
		close(fd);
		return (1);
	}

	/* Also add a regular path mute to verify it's not cleared */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/etc/passwd", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;
	mute_path.emp_flags = 0; /* Not target */
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	/* Verify target paths exist */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	get_paths.egmpa_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS (target)");
		close(fd);
		return (1);
	}

	if (get_paths.egmpa_actual < 2) {
		fprintf(stderr, "FAIL: expected at least 2 muted target paths, got %zu\n",
		    get_paths.egmpa_actual);
		close(fd);
		return (1);
	}
	printf("  Added %zu muted target paths\n", get_paths.egmpa_actual);

	/* Unmute all target paths */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_TARGET_PATHS, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_TARGET_PATHS");
		close(fd);
		return (1);
	}

	/* Verify target paths cleared */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	get_paths.egmpa_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS (target)");
		close(fd);
		return (1);
	}

	if (get_paths.egmpa_actual != 0) {
		fprintf(stderr, "FAIL: target paths not cleared (count=%zu)\n",
		    get_paths.egmpa_actual);
		close(fd);
		return (1);
	}
	printf("  PASS: OES_IOC_UNMUTE_ALL_TARGET_PATHS cleared target paths\n");

	/* Verify regular paths still exist */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	get_paths.egmpa_flags = 0; /* Regular paths */
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}

	if (get_paths.egmpa_actual < 1) {
		fprintf(stderr, "FAIL: regular paths should not be cleared\n");
		close(fd);
		return (1);
	}
	printf("  PASS: regular paths preserved after unmute-all-target-paths\n");

	/* Cleanup */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PATHS, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PATHS (cleanup)");
	}

	close(fd);

	printf("unmute-all: ok\n");
	return (0);
}
