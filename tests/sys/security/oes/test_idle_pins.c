/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pins of OES behaviour that idle gating must keep (P-O*), and of the
 * per-event work it removes (D-O*).
 *
 * The P-O cases hold on a kernel without the idle gates and must hold
 * unchanged with them: with nobody listening every operation succeeds; a
 * subscription delivers from the moment its ioctl returns; a deny is
 * enforced and stops being enforced when the subscription goes; the strict
 * settings deny exactly as before when no client is open; a cached decision
 * is dropped by a change made outside the client's scope; OES stays
 * compiled in; closing a client releases every thread waiting on it.
 *
 * The D-O cases measure what happens with nobody listening.  Before the
 * gates every fork and exit allocated an 8 KB event that nobody received;
 * OES_IDLE_GATED selects which of the two answers the kernel under test
 * must give.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

#include "test_idle_common.h"

#ifndef OES_IDLE_GATED
#define	OES_IDLE_GATED	1	/* hooks return at their gate when idle */
#endif

#define	FORKS		1000

static char work_file[PATH_MAX];
static ino_t work_ino;

static void
pin_no_client_everything_succeeds(void)
{
	char other[PATH_MAX + 8], buf[4];
	struct stat sb;
	pid_t pid;
	void *p;
	int fd, status;

	TEST_BEGIN("P-O1 no client: file, mapping, exec and signal operations");
	ASSERT_MSG(idle_sysctl_int("security.oes.require_auth_clients") == 0 &&
	    idle_sysctl_int("security.oes.auth_fail_closed") == 0 &&
	    idle_sysctl_int("security.oes.default_deadline_miss_mode") ==
	    OES_DEADLINE_MISS_FAIL_OPEN, "a strict OES setting is on");
	fd = open(work_file, O_RDWR);
	ASSERT_MSG(fd >= 0, "open: %s", strerror(errno));
	if (fd < 0)
		return;
	ASSERT_MSG(write(fd, "abcd", 4) == 4, "write: %s", strerror(errno));
	ASSERT_MSG(pread(fd, buf, 4, 0) == 4, "read: %s", strerror(errno));
	ASSERT_MSG(fstat(fd, &sb) == 0, "fstat: %s", strerror(errno));
	ASSERT_MSG(stat(work_file, &sb) == 0, "stat: %s", strerror(errno));
	snprintf(other, sizeof(other), "%s.mv", work_file);
	ASSERT_MSG(rename(work_file, other) == 0 && rename(other, work_file) ==
	    0, "rename: %s", strerror(errno));
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_MSG(p != MAP_FAILED, "mmap: %s", strerror(errno));
	if (p != MAP_FAILED) {
		ASSERT_MSG(mprotect(p, 4096, PROT_READ) == 0, "mprotect: %s",
		    strerror(errno));
		(void)munmap(p, 4096);
	}
	(void)close(fd);
	pid = fork();
	if (pid == 0) {
		execl("/usr/bin/true", "true", (char *)NULL);
		_exit(127);
	}
	ASSERT_MSG(pid > 0 && waitpid(pid, &status, 0) == pid &&
	    WIFEXITED(status) && WEXITSTATUS(status) == 0, "exec true");
	ASSERT_MSG(kill(getpid(), 0) == 0, "kill 0: %s", strerror(errno));
}

static void
pin_subscribe_delivers_at_once(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	struct idle_worker w;
	int fd;

	TEST_BEGIN("P-O2 an open right after SUBSCRIBE returns is delivered");
	if (idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("worker: %s", strerror(errno));
		return;
	}
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	if (fd >= 0) {
		ASSERT_MSG(test_set_mode(fd, OES_MODE_NOTIFY) == 0 &&
		    test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0,
		    "subscribe: %s", strerror(errno));
		(void)idle_worker_send(&w, IW_OPEN);
		ASSERT_MSG(idle_worker_result(&w, 5000) == 0, "worker open");
		ASSERT_MSG(idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000,
		    NULL) == 0, "open record not delivered");
		(void)close(fd);
	}
	idle_worker_stop(&w);
}

static volatile sig_atomic_t rename_stop;

static void
rename_stop_handler(int sig __unused)
{

	rename_stop = 1;
}

static void
pin_rename_subscribe_mid_loop(void)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_RENAME;
	char a[PATH_MAX + 8], b[PATH_MAX + 8];
	struct timespec start;
	test_msg_buf buf;
	pid_t pid;
	int fd, n, status;

	TEST_BEGIN("P-O3 subscribing to RENAME during a rename loop");
	snprintf(a, sizeof(a), "%s.ra", work_file);
	snprintf(b, sizeof(b), "%s.rb", work_file);
	fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("create: %s", strerror(errno));
		return;
	}
	(void)close(fd);
	pid = fork();
	if (pid == 0) {
		int errors = 0;

		(void)signal(SIGUSR1, rename_stop_handler);
		while (!rename_stop) {
			if (rename(a, b) != 0 || rename(b, a) != 0) {
				printf("    rename loop: %s\n", strerror(errno));
				errors++;
				if (errors > 10)
					break;
			}
		}
		_exit(errors == 0 ? 0 : 1);
	}
	idle_sleep_ms(300);
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0 && test_set_mode(fd, OES_MODE_NOTIFY) == 0 &&
	    test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0,
	    "subscribe RENAME: %s", strerror(errno));
	n = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (fd >= 0 && n < 20 && idle_elapsed_ms(&start) < 10000) {
		if (test_wait_event(fd, &buf.msg, 100) == 0 &&
		    buf.msg.em_event == ev && buf.msg.em_process.ep_pid == pid)
			n++;
	}
	ASSERT_MSG(n >= 20, "only %d rename records", n);
	if (fd >= 0)
		(void)close(fd);
	idle_sleep_ms(100);
	(void)kill(pid, SIGUSR1);
	ASSERT_MSG(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0, "rename loop saw errors (status %#x)",
	    status);
	(void)unlink(a);
	(void)unlink(b);
}

static void
pin_deny_then_unsubscribe(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct idle_worker w;
	test_msg_buf buf;
	int err, fd;

	TEST_BEGIN("P-O4 a scoped AUTH deny, then success after unsubscribe");
	fd = idle_scoped_client(OES_MODE_AUTH, 10000, &ev, 1);
	if (fd < 0) {
		TEST_FAIL("client: %s", strerror(errno));
		return;
	}
	if (idle_worker_start(&w, work_file) != 0) {
		TEST_FAIL("worker: %s", strerror(errno));
		(void)close(fd);
		return;
	}
	(void)idle_worker_send(&w, IW_OPEN);
	if (idle_wait_event(fd, w.iw_pid, ev, work_ino, 5000, &buf.msg) == 0)
		(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_DENY);
	else
		TEST_FAIL("AUTH_OPEN not delivered");
	err = idle_worker_result(&w, 5000);
	ASSERT_MSG(err == EACCES, "denied open returned %d", err);
	ASSERT_MSG(test_subscribe(fd, &ev, 1, OES_SUB_REMOVE) == 0,
	    "unsubscribe: %s", strerror(errno));
	(void)idle_worker_send(&w, IW_OPEN);
	err = idle_worker_result(&w, 5000);
	ASSERT_MSG(err == 0, "open after unsubscribe returned %d", err);
	idle_worker_stop(&w);
	(void)close(fd);
}

/*
 * One open between two sysctl writes with no client open.  Every AUTH
 * operation in the guest is denied between the writes, so nothing else
 * runs there: no output, no allocation that could fault a file page.
 */
static void
pin_strict_no_client(const char *knob, int on, int expect_errno)
{
	int fd, err, off, set;

	off = 0;
	set = on;
	err = 0;
	if (sysctlbyname(knob, NULL, NULL, &set, sizeof(set)) != 0) {
		TEST_FAIL("set %s: %s", knob, strerror(errno));
		return;
	}
	fd = open("/etc/passwd", O_RDONLY);
	if (fd < 0)
		err = errno;
	if (sysctlbyname(knob, NULL, NULL, &off, sizeof(off)) != 0) {
		/* Retry: the guest must not stay fail-closed. */
		(void)sysctlbyname(knob, NULL, NULL, &off, sizeof(off));
	}
	if (fd >= 0)
		(void)close(fd);
	ASSERT_MSG(idle_sysctl_int(knob) == 0, "%s not restored", knob);
	ASSERT_MSG(err == expect_errno, "%s=%d: open returned %d, expected %d",
	    knob, on, err, expect_errno);
	fd = open("/etc/passwd", O_RDONLY);
	ASSERT_MSG(fd >= 0, "%s restored: open failed: %s", knob,
	    strerror(errno));
	if (fd >= 0)
		(void)close(fd);
}

static void
pin_strict_settings(void)
{

	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		printf("    note: mlockall: %s\n", strerror(errno));
	TEST_BEGIN("P-O5 require_auth_clients denies an AUTH open, no client");
	pin_strict_no_client("security.oes.require_auth_clients", 1, EACCES);
	TEST_BEGIN("P-O6 auth_fail_closed denies an AUTH open, no client");
	pin_strict_no_client("security.oes.auth_fail_closed", 1, EACCES);
	TEST_BEGIN("P-O7 deadline-miss fail closed alone allows, no client");
	pin_strict_no_client("security.oes.default_deadline_miss_mode",
	    OES_DEADLINE_MISS_FAIL_CLOSED, 0);
	(void)munlockall();
}

static void
pin_outside_write_drops_cache(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct idle_worker outside, child;
	oes_cache_entry_t entry;
	struct oes_stats st;
	test_msg_buf buf;
	int err, fd;

	TEST_BEGIN("P-O8 a write outside the scope drops a cached allow");
	/* Forked before the scope exists: outside it. */
	if (idle_worker_start(&outside, work_file) != 0) {
		TEST_FAIL("outside worker: %s", strerror(errno));
		return;
	}
	fd = idle_scoped_client(OES_MODE_AUTH, 10000, &ev, 1);
	if (fd < 0 || idle_worker_start(&child, work_file) != 0) {
		TEST_FAIL("client or child: %s", strerror(errno));
		idle_worker_stop(&outside);
		if (fd >= 0)
			(void)close(fd);
		return;
	}
	(void)idle_worker_send(&child, IW_OPEN);
	if (idle_wait_event(fd, child.iw_pid, ev, work_ino, 5000, &buf.msg) !=
	    0) {
		TEST_FAIL("first AUTH_OPEN not delivered");
		goto out;
	}
	memset(&entry, 0, sizeof(entry));
	entry.ece_key.eck_event = OES_EVENT_AUTH_OPEN;
	entry.ece_key.eck_flags = OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE;
	entry.ece_key.eck_op_flags = buf.msg.em_event_data.open.access;
	entry.ece_key.eck_process = buf.msg.em_process.ep_token;
	entry.ece_key.eck_exec_id = buf.msg.em_process.ep_exec_id;
	entry.ece_key.eck_file = buf.msg.em_event_data.open.file.ef_token;
	entry.ece_result = OES_AUTH_ALLOW;
	entry.ece_ttl_ms = 60000;
	ASSERT_MSG(ioctl(fd, OES_IOC_CACHE_ADD, &entry) == 0, "cache add: %s",
	    strerror(errno));
	(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_ALLOW);
	err = idle_worker_result(&child, 5000);
	ASSERT_MSG(err == 0, "first open returned %d", err);

	/* Cached: answered without an event. */
	(void)idle_worker_send(&child, IW_OPEN);
	err = idle_worker_result(&child, 5000);
	ASSERT_MSG(err == 0, "cached open returned %d", err);
	ASSERT_MSG(idle_wait_event(fd, child.iw_pid, ev, work_ino, 300,
	    NULL) != 0, "cached open still delivered");

	(void)idle_worker_send(&outside, IW_WRITE);
	err = idle_worker_result(&outside, 5000);
	ASSERT_MSG(err == 0, "outside write returned %d", err);
	memset(&st, 0, sizeof(st));
	ASSERT_MSG(ioctl(fd, OES_IOC_GET_STATS, &st) == 0 &&
	    st.es_cache_entries == 0, "cache holds %u entries after the write",
	    st.es_cache_entries);

	(void)idle_worker_send(&child, IW_OPEN);
	if (idle_wait_event(fd, child.iw_pid, ev, work_ino, 5000, &buf.msg) ==
	    0)
		(void)idle_respond(fd, buf.msg.em_id, OES_AUTH_ALLOW);
	else
		TEST_FAIL("reopen after the outside write not delivered");
	err = idle_worker_result(&child, 5000);
	ASSERT_MSG(err == 0, "reopen returned %d", err);
out:
	idle_worker_stop(&child);
	idle_worker_stop(&outside);
	(void)close(fd);
}

/* The linker file that holds module name, or -1. */
static int
file_of_module(const char *name)
{
	struct module_stat ms;
	int fileid, modid;

	for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
		for (modid = kldfirstmod(fileid); modid > 0;
		    modid = modfnext(modid)) {
			ms.version = sizeof(ms);
			if (modstat(modid, &ms) == 0 &&
			    strcmp(ms.name, name) == 0)
				return (fileid);
		}
	}
	return (-1);
}

static void
pin_compiled_in(void)
{
	int fd, fileid, rc, uerr, lerr;

	TEST_BEGIN("P-O9 OES is present, cannot be unloaded or loaded again");
	ASSERT_MSG(modfind("oes") >= 0, "module oes not present: %s",
	    strerror(errno));
	fileid = file_of_module("oes");
	ASSERT_MSG(fileid == 1, "module oes is in linker file %d, not the "
	    "kernel", fileid);
	rc = kldunload(fileid > 0 ? fileid : 1);
	uerr = rc == 0 ? 0 : errno;
	rc = kldload("oes");
	lerr = rc >= 0 ? 0 : errno;
	printf("    kldunload(file %d): %s; kldload(\"oes\"): %s\n", fileid,
	    uerr == 0 ? "succeeded" : strerror(uerr),
	    lerr == 0 ? "succeeded" : strerror(lerr));
	/* As observed on the kernel before idle gating (2026-11-15). */
	ASSERT_MSG(uerr == EEXIST, "kldunload: errno %d, expected EEXIST", uerr);
	ASSERT_MSG(lerr == EEXIST, "kldload: errno %d, expected EEXIST", lerr);
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	if (fd >= 0)
		(void)close(fd);
}

static void
pin_close_releases_waiters(void)
{
	oes_event_type_t ev = OES_EVENT_AUTH_OPEN;
	struct idle_worker w[8];
	struct timespec start;
	test_msg_buf buf;
	int fd, i, got, err;
	long ms;

	TEST_BEGIN("P-O10 closing a silent AUTH client releases 8 blocked opens");
	fd = idle_scoped_client(OES_MODE_AUTH, 30000, &ev, 1);
	if (fd < 0) {
		TEST_FAIL("client: %s", strerror(errno));
		return;
	}
	for (i = 0; i < 8; i++) {
		w[i].iw_pid = -1;
		if (idle_worker_start(&w[i], work_file) != 0) {
			TEST_FAIL("worker %d: %s", i, strerror(errno));
			break;
		}
		(void)idle_worker_send(&w[i], IW_OPEN);
	}
	got = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (got < 8 && idle_elapsed_ms(&start) < 10000) {
		if (test_wait_event(fd, &buf.msg, 100) == 0 &&
		    buf.msg.em_event == ev)
			got++;
	}
	ASSERT_MSG(got == 8, "%d of 8 opens reached the client", got);
	clock_gettime(CLOCK_MONOTONIC, &start);
	(void)close(fd);
	for (i = 0; i < 8; i++) {
		if (w[i].iw_pid <= 0)
			continue;
		err = idle_worker_result(&w[i], 5000);
		ms = idle_elapsed_ms(&start);
		ASSERT_MSG(err != -1 && ms <= 2000,
		    "worker %d: open returned %d after %ld ms", i, err, ms);
		idle_worker_stop(&w[i]);
	}
}

static void
pin_idle_allocations(void)
{
	uint64_t before, after;
	int fd;

	TEST_BEGIN("D-O1 no client: allocations per fork and exit");
	before = idle_oes_mallocs();
	ASSERT_MSG(idle_fork_exit(FORKS) == 0, "fork loop: %s",
	    strerror(errno));
	after = idle_oes_mallocs();
	printf("    %d fork+exit: %ju oes allocations\n", FORKS,
	    (uintmax_t)(after - before));
#if OES_IDLE_GATED
	ASSERT_MSG(after - before < FORKS / 5, "%ju allocations for %d "
	    "fork+exit with nobody listening", (uintmax_t)(after - before),
	    FORKS);
#else
	ASSERT_MSG(after - before >= 2 * FORKS * 9 / 10, "%ju allocations for "
	    "%d fork+exit; the ungated kernel allocates two events each",
	    (uintmax_t)(after - before), FORKS);
#endif

	TEST_BEGIN("D-O2 client open, subscribed to nothing: same");
	fd = test_open_oes();
	ASSERT_MSG(fd >= 0 && test_set_mode(fd, OES_MODE_NOTIFY) == 0,
	    "client: %s", strerror(errno));
	before = idle_oes_mallocs();
	ASSERT_MSG(idle_fork_exit(FORKS) == 0, "fork loop: %s",
	    strerror(errno));
	after = idle_oes_mallocs();
	if (fd >= 0)
		(void)close(fd);
	printf("    %d fork+exit: %ju oes allocations\n", FORKS,
	    (uintmax_t)(after - before));
#if OES_IDLE_GATED
	ASSERT_MSG(after - before < FORKS / 5, "%ju allocations for %d "
	    "fork+exit with a client subscribed to nothing",
	    (uintmax_t)(after - before), FORKS);
#else
	ASSERT_MSG(after - before >= 2 * FORKS * 9 / 10, "%ju allocations for "
	    "%d fork+exit; the ungated kernel allocates two events each",
	    (uintmax_t)(after - before), FORKS);
#endif
}

int
main(void)
{
	struct stat sb;
	int fd;

	TEST_SUITE_BEGIN("OES idle pins");
	snprintf(work_file, sizeof(work_file), "./oes-idle-pin.%d",
	    (int)getpid());
	fd = open(work_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0 || ftruncate(fd, 4096) != 0 || fstat(fd, &sb) != 0) {
		TEST_FAIL("work file: %s", strerror(errno));
		return (1);
	}
	(void)close(fd);
	work_ino = sb.st_ino;

	pin_no_client_everything_succeeds();
	pin_subscribe_delivers_at_once();
	pin_rename_subscribe_mid_loop();
	pin_deny_then_unsubscribe();
	pin_strict_settings();
	pin_outside_write_drops_cache();
	pin_compiled_in();
	pin_close_releases_waiters();
	pin_idle_allocations();

	(void)unlink(work_file);
	TEST_SUITE_END("OES idle pins");
	return (0);
}
