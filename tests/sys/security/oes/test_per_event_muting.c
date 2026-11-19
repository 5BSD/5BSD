/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

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
	 * The events come from a child driven over a pipe: the test opened the
	 * client, so its own events never reach it (oes(4), "A client's own
	 * processes").  The child never touches the client.
	 */
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
			if (cmd == 'a')
				(void)access("/etc/passwd", R_OK);
		}
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);

	/* Mute only the child's OPEN events, not ACCESS */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.empe_token.ept_id = (uint64_t)child;
	mute_proc.empe_count = 1;
	mute_proc.empe_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS_EVENTS");
		goto fail;
	}

	/*
	 * The child opens (muted), then checks access (not muted).  Events of
	 * one process arrive in order, so the ACCESS event is the fence: no
	 * OPEN of the child may come before it.
	 */
	cmd = 'p';
	(void)write(pipefd[1], &cmd, 1);
	cmd = 'a';
	(void)write(pipefd[1], &cmd, 1);
	{
		test_msg_buf buf;
		int opens = 0;

		ret = -1;
		for (;;) {
			if (test_wait_event(fd, &buf.msg, 1000) != 0)
				break;
			if (buf.msg.em_process.ep_pid != child)
				continue;
			if (buf.msg.em_event == OES_EVENT_NOTIFY_OPEN)
				opens++;
			if (buf.msg.em_event == OES_EVENT_NOTIFY_ACCESS) {
				ret = 0;
				break;
			}
		}
		if (ret != 0) {
			fprintf(stderr, "FAIL: ACCESS event not delivered (should not be muted)\n");
			goto fail;
		}
		if (opens != 0) {
			fprintf(stderr, "FAIL: per-event-muted OPEN event still delivered\n");
			goto fail;
		}
	}
	printf("  PASS: process per-event mute suppressed OPEN\n");
	printf("  PASS: ACCESS event delivered (not muted)\n");

	/* Unmute OPEN events */
	if (ioctl(fd, OES_IOC_UNMUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_UNMUTE_PROCESS_EVENTS");
		goto fail;
	}

	/* Trigger OPEN again - should now be delivered */
	cmd = 'h';
	(void)write(pipefd[1], &cmd, 1);

	ret = test_wait_event_pid(fd, child, OES_EVENT_NOTIFY_OPEN, 1000,
	    NULL);
	if (ret != 0) {
		fprintf(stderr, "FAIL: OPEN event not delivered after unmute\n");
		goto fail;
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

	/*
	 * Test mute-all upgrade: per-event mute followed by full mute
	 * should upgrade to mute-all (em_events cleared to zeros).
	 */
	printf("  Testing mute-all upgrades per-event mute...\n");

	/* Clear all mutes first */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		goto fail;
	}

	/* Step 1: Per-event mute of the child for OPEN only */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.empe_token.ept_id = (uint64_t)child;
	mute_proc.empe_count = 1;
	mute_proc.empe_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS_EVENTS (per-event)");
		goto fail;
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
			goto fail;
		}
		for (i = 0; i < get_procs.egmp_actual && i < 4; i++) {
			if (proc_entries[i].emp_token.ept_id == (uint64_t)child) {
				if (proc_entries[i].emp_event_count != 1) {
					fprintf(stderr,
					    "FAIL: expected 1 muted event, got %u\n",
					    proc_entries[i].emp_event_count);
					goto fail;
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "FAIL: child not in muted list after per-event mute\n");
			goto fail;
		}
	}
	printf("    PASS: per-event mute shows 1 event\n");

	/* Step 2: Full mute-all of the child (should upgrade) */
	{
		struct oes_mute_args mute_all;

		memset(&mute_all, 0, sizeof(mute_all));
		mute_all.emu_token.ept_id = (uint64_t)child;
		if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute_all) < 0) {
			perror("OES_IOC_MUTE_PROCESS (mute-all)");
			goto fail;
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
			goto fail;
		}
		for (i = 0; i < get_procs.egmp_actual && i < 4; i++) {
			if (proc_entries[i].emp_token.ept_id == (uint64_t)child) {
				if (proc_entries[i].emp_event_count != 0) {
					fprintf(stderr,
					    "FAIL: mute-all should upgrade to event_count=0, got %u\n",
					    proc_entries[i].emp_event_count);
					goto fail;
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "FAIL: child not in muted list after mute-all\n");
			goto fail;
		}
	}
	printf("    PASS: mute-all upgraded per-event mute (event_count=0)\n");

	cmd = 'q';
	(void)write(pipefd[1], &cmd, 1);
	(void)waitpid(child, &status, 0);
	close(pipefd[1]);
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
