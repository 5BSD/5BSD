/*
 * OES process info test.
 *
 * Tests that process events contain correct:
 * - ABI information (FreeBSD vs Linux binary detection)
 * - Parent process info (ppid, pcomm)
 * - Executable path, thread, lineage, and availability metadata
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
read_fork_event(int fd, oes_message_t *out_msg)
{
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		struct timespec now;
		long elapsed_ms;
		int remaining;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms > 2000)
			break;

		remaining = 2000 - (int)elapsed_ms;
		if (remaining > 100)
			remaining = 100;

		if (test_wait_event(fd, msg, remaining) != 0)
			continue;
		if (msg->em_event != OES_EVENT_NOTIFY_FORK)
			continue;

		memcpy(out_msg, msg, msg->em_size);
		return (0);
	}
	return (-1);
}

int
main(void)
{
	int fd;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_FORK,
	};
	test_msg_buf _msg_buf;
	oes_message_t *msg = &_msg_buf.msg;
	pid_t child, mypid;
	int status;
	int errors = 0;
	char my_comm[20];

	printf("Testing process info (ABI, parent)...\n");

	/* Get our own info for comparison */
	mypid = getpid();
	/* Our comm name is test_process_info (truncated) */
	strlcpy(my_comm, "test_process_in", sizeof(my_comm));

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
	 * Clear the default self-mute so we can see our own fork events.
	 * (security.oes.default_self_mute=1 would otherwise block them.)
	 */
	if (ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES, NULL) < 0) {
		perror("OES_IOC_UNMUTE_ALL_PROCESSES");
		close(fd);
		return (1);
	}

	/* Fork a child to generate event */
	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return (1);
	}
	if (child == 0) {
		/* Child - just exit */
		_exit(0);
	}

	/* Parent - wait for fork event */
	if (read_fork_event(fd, msg) < 0) {
		fprintf(stderr, "FAIL: no FORK event received\n");
		waitpid(child, &status, 0);
		close(fd);
		return (1);
	}

	waitpid(child, &status, 0);
	close(fd);

	/* Verify child info from fork event */
	oes_process_t *proc = &msg->em_event_data.fork.child;

	printf("  Child PID: %d (expected around %d)\n", proc->ep_pid, child);
	printf("  Parent PID: %d (expected %d)\n", proc->ep_ppid, mypid);
	printf("  Parent comm: '%s'\n", proc->ep_pcomm);
	printf("  ABI: %d (EP_ABI_FREEBSD=%d, EP_ABI_LINUX=%d)\n",
	    proc->ep_abi, EP_ABI_FREEBSD, EP_ABI_LINUX);
	printf("  Flags: 0x%x (EP_FLAG_LINUX=0x%x)\n",
	    proc->ep_flags, EP_FLAG_LINUX);
	printf("  Meta flags: 0x%x\n", proc->ep_meta_flags);
	printf("  Executable path: '%s'\n",
	    oes_msg_string(msg, proc->ep_path_off));

	/* Test 1: Parent PID should be us */
	if (proc->ep_ppid != mypid) {
		fprintf(stderr, "  FAIL: ep_ppid=%d, expected %d\n",
		    proc->ep_ppid, mypid);
		errors++;
	} else {
		printf("  PASS: Parent PID correct\n");
	}

	/* Test 2: Parent comm should match our name */
	if (strncmp(proc->ep_pcomm, "test_process_in", 15) != 0) {
		fprintf(stderr, "  FAIL: ep_pcomm='%s', expected 'test_process_in*'\n",
		    proc->ep_pcomm);
		errors++;
	} else {
		printf("  PASS: Parent comm correct\n");
	}

	/* Test 3: ABI should be FreeBSD (not Linux) */
	if (proc->ep_abi != EP_ABI_FREEBSD) {
		fprintf(stderr, "  FAIL: ep_abi=%d, expected EP_ABI_FREEBSD (%d)\n",
		    proc->ep_abi, EP_ABI_FREEBSD);
		errors++;
	} else {
		printf("  PASS: ABI is FreeBSD\n");
	}

	/* Test 4: EP_FLAG_LINUX should NOT be set */
	if (proc->ep_flags & EP_FLAG_LINUX) {
		fprintf(stderr, "  FAIL: EP_FLAG_LINUX is set for native binary\n");
		errors++;
	} else {
		printf("  PASS: EP_FLAG_LINUX not set\n");
	}

	/* Test 5: fork inherits the executable identity cached at exec. */
	if (proc->ep_path_off == 0 ||
	    oes_msg_string(msg, proc->ep_path_off)[0] == '\0' ||
	    (proc->ep_meta_flags & OES_PROC_META_PATH_UNAVAILABLE) != 0) {
		fprintf(stderr, "  FAIL: executable path is unavailable\n");
		errors++;
	} else {
		printf("  PASS: executable path inherited across fork\n");
	}

	/* Test 6: core lineage and scheduling snapshot is populated. */
	if (proc->ep_original_ppid != mypid || proc->ep_num_threads == 0 ||
	    proc->ep_state == 0) {
		fprintf(stderr, "  FAIL: extended process snapshot incomplete\n");
		errors++;
	} else {
		printf("  PASS: extended process snapshot populated\n");
	}

	/* Test 7: message carries wall-clock and triggering-thread metadata. */
	if (msg->em_wall_time.tv_sec == 0 ||
	    (msg->em_thread.et_flags & OES_THREAD_META_PRESENT) == 0 ||
	    msg->em_thread.et_id == 0) {
		fprintf(stderr, "  FAIL: message time/thread metadata missing\n");
		errors++;
	} else {
		printf("  PASS: message time/thread metadata populated\n");
	}

	if (errors > 0) {
		fprintf(stderr, "FAIL: %d test(s) failed\n", errors);
		return (1);
	}

	printf("process info: ok\n");
	return (0);
}
