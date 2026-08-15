/*
 * OES per-event muting test.
 *
 * Tests OES_IOC_MUTE_PROCESS_EVENTS, OES_IOC_UNMUTE_PROCESS_EVENTS,
 * OES_IOC_MUTE_PATH_EVENTS, and OES_IOC_UNMUTE_PATH_EVENTS.
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
	struct oes_mute_process_events_args mute_proc;
	struct oes_mute_path_events_args mute_path;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
		OES_EVENT_NOTIFY_ACCESS,
	};
	int pipefd[2];
	pid_t child;
	int status;
	char cmd;
	int ret;

	printf("Testing per-event muting...\n");

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

	/*
	 * Clear the default self-mute first (security.oes.default_self_mute=1
	 * would otherwise block ALL events from ourselves, not just per-event).
	 */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}

	/* Self-mute only OPEN events, not ACCESS */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.empe_flags = OES_MUTE_SELF;
	mute_proc.empe_count = 1;
	mute_proc.empe_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS_EVENTS (self)");
		close(fd);
		return (1);
	}

	/* Verify mute was applied */
	{
		struct oes_get_muted_processes_args get_procs;
		struct oes_muted_process_entry proc_entries[4];
		size_t i;

		memset(&get_procs, 0, sizeof(get_procs));
		get_procs.egmp_entries = proc_entries;
		get_procs.egmp_count = 4;
		if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) == 0) {
			fprintf(stderr, "  DEBUG: muted_count=%zu, my_pid=%d\n",
			    get_procs.egmp_actual, getpid());
			for (i = 0; i < get_procs.egmp_actual && i < 4; i++) {
				fprintf(stderr, "    entry[%zu]: pid=%llu event_count=%u\n",
				    i, (unsigned long long)proc_entries[i].emp_token.ept_id,
				    proc_entries[i].emp_event_count);
			}
		}
	}

	/* Trigger an OPEN event - should be muted */
	(void)open("/etc/passwd", O_RDONLY);

	ret = test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_OPEN, 500,
	    NULL);
	if (ret == 0) {
		fprintf(stderr, "FAIL: self-muted OPEN event still delivered\n");
		close(fd);
		return (1);
	}
	printf("  PASS: self per-event mute suppressed OPEN\n");

	/* Trigger an ACCESS event - should NOT be muted */
	(void)access("/etc/passwd", R_OK);

	ret = test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_ACCESS, 1000,
	    NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: ACCESS event not delivered (should not be muted)\n");
		close(fd);
		return (1);
	}
	printf("  PASS: ACCESS event delivered (not muted)\n");

	/* Unmute OPEN events */
	if (ioctl(fd, OES_IOC_UNMUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_UNMUTE_PROCESS_EVENTS (self)");
		close(fd);
		return (1);
	}

	/* Trigger OPEN again - should now be delivered */
	(void)open("/etc/hosts", O_RDONLY);

	ret = test_wait_event_pid(fd, getpid(), OES_EVENT_NOTIFY_OPEN, 1000,
	    NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: OPEN event not delivered after unmute\n");
		close(fd);
		return (1);
	}
	printf("  PASS: OPEN event delivered after unmute\n");

	/* Now test per-event path muting */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.empae_path, "/etc/passwd", sizeof(mute_path.empae_path));
	mute_path.empae_type = OES_MUTE_PATH_LITERAL;
	mute_path.empae_count = 1;
	mute_path.empae_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PATH_EVENTS, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH_EVENTS");
		close(fd);
		return (1);
	}

	/* Test with child process */
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
			if (cmd == 'p')
				(void)open("/etc/passwd", O_RDONLY);
			if (cmd == 'h')
				(void)open("/etc/hosts", O_RDONLY);
		}
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);

	/* Child opens /etc/passwd - path-muted for OPEN */
	cmd = 'p';
	(void)write(pipefd[1], &cmd, 1);
	usleep(100000);

	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 500, NULL);
	if (ret == 0) {
		fprintf(stderr, "FAIL: path-muted OPEN still delivered\n");
		goto fail;
	}
	printf("  PASS: path per-event mute suppressed OPEN for /etc/passwd\n");

	/* Child opens /etc/hosts - NOT path-muted */
	cmd = 'h';
	(void)write(pipefd[1], &cmd, 1);

	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 1000, NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: non-muted path OPEN not delivered\n");
		goto fail;
	}
	printf("  PASS: OPEN for /etc/hosts delivered (different path)\n");

	/* Unmute the path */
	if (ioctl(fd, OES_IOC_UNMUTE_PATH_EVENTS, &mute_path) < 0) {
		perror("OES_IOC_UNMUTE_PATH_EVENTS");
		goto fail;
	}

	/* Now /etc/passwd should deliver OPEN */
	cmd = 'p';
	(void)write(pipefd[1], &cmd, 1);

	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 1000, NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: OPEN for /etc/passwd not delivered after unmute\n");
		goto fail;
	}
	printf("  PASS: OPEN for /etc/passwd delivered after unmute\n");

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);

	/*
	 * Test mute-all upgrade: per-event mute followed by full mute
	 * should upgrade to mute-all (em_events cleared to zeros).
	 */
	printf("  Testing mute-all upgrades per-event mute...\n");

	/* Clear all mutes first */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}

	/* Step 1: Per-event mute self for OPEN only */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.empe_flags = OES_MUTE_SELF;
	mute_proc.empe_count = 1;
	mute_proc.empe_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS_EVENTS (per-event)");
		close(fd);
		return (1);
	}

	/* Verify per-event mute: event_count should be 1 */
	{
		struct oes_get_muted_processes_args get_procs;
		struct oes_muted_process_entry proc_entries[4];
		size_t i;
		int found = 0;

		memset(&get_procs, 0, sizeof(get_procs));
		get_procs.egmp_entries = proc_entries;
		get_procs.egmp_count = 4;
		if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
			perror("OES_IOC_GET_MUTED_PROCESSES");
			close(fd);
			return (1);
		}
		for (i = 0; i < get_procs.egmp_actual && i < 4; i++) {
			if (proc_entries[i].emp_token.ept_id == (uint64_t)getpid()) {
				if (proc_entries[i].emp_event_count != 1) {
					fprintf(stderr,
					    "FAIL: expected 1 muted event, got %u\n",
					    proc_entries[i].emp_event_count);
					close(fd);
					return (1);
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "FAIL: self not in muted list after per-event mute\n");
			close(fd);
			return (1);
		}
	}
	printf("    PASS: per-event mute shows 1 event\n");

	/* Step 2: Full mute-all self (should upgrade) */
	{
		struct oes_mute_args mute_all;

		memset(&mute_all, 0, sizeof(mute_all));
		mute_all.emu_flags = OES_MUTE_SELF;
		if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute_all) < 0) {
			perror("OES_IOC_MUTE_PROCESS (mute-all)");
			close(fd);
			return (1);
		}
	}

	/* Verify upgrade: event_count should now be 0 (mute-all) */
	{
		struct oes_get_muted_processes_args get_procs;
		struct oes_muted_process_entry proc_entries[4];
		size_t i;
		int found = 0;

		memset(&get_procs, 0, sizeof(get_procs));
		get_procs.egmp_entries = proc_entries;
		get_procs.egmp_count = 4;
		if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
			perror("OES_IOC_GET_MUTED_PROCESSES");
			close(fd);
			return (1);
		}
		for (i = 0; i < get_procs.egmp_actual && i < 4; i++) {
			if (proc_entries[i].emp_token.ept_id == (uint64_t)getpid()) {
				if (proc_entries[i].emp_event_count != 0) {
					fprintf(stderr,
					    "FAIL: mute-all should upgrade to event_count=0, got %u\n",
					    proc_entries[i].emp_event_count);
					close(fd);
					return (1);
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "FAIL: self not in muted list after mute-all\n");
			close(fd);
			return (1);
		}
	}
	printf("    PASS: mute-all upgraded per-event mute (event_count=0)\n");

	close(fd);

	printf("per-event muting: ok\n");
	return (0);

fail:
	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
	close(fd);
	return (1);
}
