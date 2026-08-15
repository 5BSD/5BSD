/*
 * OES query muted lists test.
 *
 * Tests OES_IOC_GET_MUTED_PROCESSES and OES_IOC_GET_MUTED_PATHS.
 */
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	struct oes_mute_args mute_proc;
	struct oes_mute_process_events_args mute_proc_ev;
	struct oes_mute_path_args mute_path;
	struct oes_mute_path_events_args mute_path_ev;
	struct oes_get_muted_processes_args get_procs;
	struct oes_get_muted_paths_args get_paths;
	struct oes_muted_process_entry proc_entries[16];
	struct oes_muted_path_entry path_entries[16];
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
	};
	int ret;
	size_t i;

	printf("Testing query muted lists...\n");

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

	/* Verify empty muted lists initially */
	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = proc_entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		return (1);
	}
	/* Note: may have self-mute from previous tests, so just verify ioctl works */
	printf("  Initial muted processes: %zu\n", get_procs.egmp_actual);

	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}
	printf("  Initial muted paths: %zu\n", get_paths.egmpa_actual);

	/* Self-mute with all events */
	memset(&mute_proc, 0, sizeof(mute_proc));
	mute_proc.emu_flags = OES_MUTE_SELF;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS, &mute_proc) < 0) {
		perror("OES_IOC_MUTE_PROCESS (self)");
		close(fd);
		return (1);
	}

	/* Query and verify self is in list */
	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = proc_entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		return (1);
	}

	if (get_procs.egmp_actual < 1) {
		fprintf(stderr, "FAIL: self-mute not in muted list\n");
		close(fd);
		return (1);
	}

	/* Find our process in the list */
	ret = 0;
	for (i = 0; i < get_procs.egmp_actual; i++) {
		if (proc_entries[i].emp_token.ept_id == (uint64_t)getpid()) {
			if (proc_entries[i].emp_event_count != 0) {
				fprintf(stderr, "FAIL: full mute should have event_count=0\n");
				close(fd);
				return (1);
			}
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fprintf(stderr, "FAIL: self not found in muted processes list\n");
		close(fd);
		return (1);
	}
	printf("  PASS: self found in muted processes (all events)\n");

	/* Unmute self */
	if (ioctl(fd, OES_IOC_UNMUTE_PROCESS, &mute_proc) < 0) {
		perror("OES_IOC_UNMUTE_PROCESS");
		close(fd);
		return (1);
	}

	/* Now self-mute with specific events */
	memset(&mute_proc_ev, 0, sizeof(mute_proc_ev));
	mute_proc_ev.empe_flags = OES_MUTE_SELF;
	mute_proc_ev.empe_count = 2;
	mute_proc_ev.empe_events[0] = OES_EVENT_NOTIFY_OPEN;
	mute_proc_ev.empe_events[1] = OES_EVENT_NOTIFY_ACCESS;
	if (ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute_proc_ev) < 0) {
		perror("OES_IOC_MUTE_PROCESS_EVENTS");
		close(fd);
		return (1);
	}

	/* Query and verify specific events are listed */
	memset(&get_procs, 0, sizeof(get_procs));
	get_procs.egmp_entries = proc_entries;
	get_procs.egmp_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &get_procs) < 0) {
		perror("OES_IOC_GET_MUTED_PROCESSES");
		close(fd);
		return (1);
	}

	ret = 0;
	for (i = 0; i < get_procs.egmp_actual; i++) {
		if (proc_entries[i].emp_token.ept_id == (uint64_t)getpid()) {
			if (proc_entries[i].emp_event_count != 2) {
				fprintf(stderr, "FAIL: expected 2 events, got %u\n",
				    proc_entries[i].emp_event_count);
				close(fd);
				return (1);
			}
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fprintf(stderr, "FAIL: self not found in per-event muted list\n");
		close(fd);
		return (1);
	}
	printf("  PASS: self found in muted processes (2 specific events)\n");

	/* Test path muting queries */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/etc/passwd", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH");
		close(fd);
		return (1);
	}

	/* Query paths */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}

	ret = 0;
	for (i = 0; i < get_paths.egmpa_actual; i++) {
		if (strcmp(path_entries[i].emp_path, "/etc/passwd") == 0) {
			if (path_entries[i].emp_event_count != 0) {
				fprintf(stderr, "FAIL: full path mute should have event_count=0\n");
				close(fd);
				return (1);
			}
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fprintf(stderr, "FAIL: /etc/passwd not found in muted paths\n");
		close(fd);
		return (1);
	}
	printf("  PASS: /etc/passwd found in muted paths (all events)\n");

	/* Add per-event path mute */
	memset(&mute_path_ev, 0, sizeof(mute_path_ev));
	strlcpy(mute_path_ev.empae_path, "/etc/hosts", sizeof(mute_path_ev.empae_path));
	mute_path_ev.empae_type = OES_MUTE_PATH_LITERAL;
	mute_path_ev.empae_count = 1;
	mute_path_ev.empae_events[0] = OES_EVENT_NOTIFY_OPEN;
	if (ioctl(fd, OES_IOC_MUTE_PATH_EVENTS, &mute_path_ev) < 0) {
		perror("OES_IOC_MUTE_PATH_EVENTS");
		close(fd);
		return (1);
	}

	/* Query paths again */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS");
		close(fd);
		return (1);
	}

	ret = 0;
	for (i = 0; i < get_paths.egmpa_actual; i++) {
		if (strcmp(path_entries[i].emp_path, "/etc/hosts") == 0) {
			if (path_entries[i].emp_event_count != 1) {
				fprintf(stderr, "FAIL: expected 1 event for /etc/hosts, got %u\n",
				    path_entries[i].emp_event_count);
				close(fd);
				return (1);
			}
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fprintf(stderr, "FAIL: /etc/hosts not found in muted paths\n");
		close(fd);
		return (1);
	}
	printf("  PASS: /etc/hosts found in muted paths (1 specific event)\n");

	/* Test target path query */
	memset(&mute_path, 0, sizeof(mute_path));
	strlcpy(mute_path.emp_path, "/tmp/target", sizeof(mute_path.emp_path));
	mute_path.emp_type = OES_MUTE_PATH_LITERAL;
	mute_path.emp_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_MUTE_PATH, &mute_path) < 0) {
		perror("OES_IOC_MUTE_PATH (target)");
		close(fd);
		return (1);
	}

	/* Query target paths */
	memset(&get_paths, 0, sizeof(get_paths));
	get_paths.egmpa_entries = path_entries;
	get_paths.egmpa_count = 16;
	get_paths.egmpa_flags = OES_MUTE_PATH_FLAG_TARGET;
	if (ioctl(fd, OES_IOC_GET_MUTED_PATHS, &get_paths) < 0) {
		perror("OES_IOC_GET_MUTED_PATHS (target)");
		close(fd);
		return (1);
	}

	ret = 0;
	for (i = 0; i < get_paths.egmpa_actual; i++) {
		if (strcmp(path_entries[i].emp_path, "/tmp/target") == 0) {
			ret = 1;
			break;
		}
	}
	if (!ret) {
		fprintf(stderr, "FAIL: /tmp/target not found in muted target paths\n");
		close(fd);
		return (1);
	}
	printf("  PASS: /tmp/target found in muted target paths\n");

	close(fd);

	printf("query muted lists: ok\n");
	return (0);
}
