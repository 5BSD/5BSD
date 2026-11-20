/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * A client and the events its own processes cause (oes(4), "A client's own
 * processes"; oes-no-self-events.md rows N1-N13).
 *
 * Every case counts NOTIFY_OPEN events of a probe file opened by the process
 * under test, then waits for a fence: an open of a marker file by another
 * process that is not a reader of the client.  Events are delivered in
 * order per client, so once the fence arrives every earlier event has; the
 * wait has a deadline the case states, nothing sleeps for time.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"
#include "self_events_expect.h"

struct paths {
	char	probe[PATH_MAX];
	char	marker[PATH_MAX];
};

static void
paths_init(struct paths *p)
{

	ATF_REQUIRE(getcwd(p->probe, sizeof(p->probe)) != NULL);
	strlcpy(p->marker, p->probe, sizeof(p->marker));
	strlcat(p->probe, "/probe", sizeof(p->probe));
	strlcat(p->marker, "/marker", sizeof(p->marker));
	ATF_REQUIRE(close(open(p->probe, O_WRONLY | O_CREAT, 0644)) == 0);
	ATF_REQUIRE(close(open(p->marker, O_WRONLY | O_CREAT, 0644)) == 0);
}

static void
open_close(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	close(fd);
}

/* A NOTIFY_OPEN client of the given scope (0: global). */
static int
open_client(bool descendants)
{
	oes_event_type_t events[] = { OES_EVENT_NOTIFY_OPEN };
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	if (descendants)
		ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_NOTIFY) == 0);
	ATF_REQUIRE(test_subscribe(fd, events, nitems(events),
	    OES_SUB_REPLACE) == 0);
	return (fd);
}

/* A child that opens path when released; returns its pid and gate. */
static pid_t
fence_child(const char *path, int *gate)
{
	int p[2];
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(p[1]);
		if (read(p[0], &c, 1) != 1)
			_exit(1);
		open_close(path);
		_exit(0);
	}
	close(p[0]);
	*gate = p[1];
	return (pid);
}

static void
release(int gate, pid_t pid)
{
	int status;

	ATF_REQUIRE(write(gate, "g", 1) == 1);
	close(gate);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
}

/*
 * Read fd until fence's NOTIFY_OPEN arrives; return how many NOTIFY_OPEN
 * events of subject arrived before it, and their ep_flags in *flags.
 */
static int
count_until_fence(int fd, pid_t subject, pid_t fence, uint32_t *flags)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	int n = 0;

	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) == 0,
		    "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (msg->em_process.ep_pid == fence)
			return (n);
		if (msg->em_process.ep_pid == subject) {
			n++;
			if (flags != NULL)
				*flags = msg->em_process.ep_flags;
		}
	}
}

/*
 * As count_until_fence(), counting only NOTIFY_OPENs of path by any of the
 * n subjects.  The file is matched by its inode and device: these open
 * records need not carry a path (OES fills it only where it can resolve
 * one without the vnode lock).
 */
static int
count_path_until_fence(int fd, const pid_t *subjects, int n, const char *path,
    pid_t fence)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	struct stat sb;
	int count = 0;

	ATF_REQUIRE(stat(path, &sb) == 0);
	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) == 0,
		    "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_NOTIFY_OPEN)
			continue;
		if (msg->em_process.ep_pid == fence)
			return (count);
		for (int i = 0; i < n; i++)
			if (msg->em_process.ep_pid == subjects[i] &&
			    msg->em_event_data.open.file.ef_ino ==
			    (uint64_t)sb.st_ino &&
			    msg->em_event_data.open.file.ef_dev ==
			    (uint64_t)sb.st_dev)
				count++;
	}
}

ATF_TC(n1_opener_global);
ATF_TC_HEAD(n1_opener_global, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N1: a global client does not receive its opener's events");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n1_opener_global, tc)
{
	struct paths p;
	pid_t fence;
	int fd, gate;

	paths_init(&p);
	fd = open_client(false);
	fence = fence_child(p.marker, &gate);
	open_close(p.probe);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, getpid(), fence, NULL), 0);
	close(fd);
}

ATF_TC(n2_opener_descendants);
ATF_TC_HEAD(n2_opener_descendants, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N2: a descendants-scoped client does not receive its opener's events (pin: it does before the reader rule)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n2_opener_descendants, tc)
{
	struct paths p;
	pid_t fence;
	int fd, gate;

	paths_init(&p);
	fd = open_client(true);
	fence = fence_child(p.marker, &gate);
	open_close(p.probe);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, getpid(), fence, NULL),
	    SELF_EVENTS_DESCENDANTS);
	close(fd);
}

ATF_TC(n3_unmute_self);
ATF_TC_HEAD(n3_unmute_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N3: unmuting OES_MUTE_SELF (pin: succeeds and the opener sees its own events; after: EINVAL and it does not)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n3_unmute_self, tc)
{
	struct paths p;
	pid_t fence;
	int fd, gate, rv, error;

	paths_init(&p);
	fd = open_client(false);
	rv = test_unmute_self(fd);
	error = rv == 0 ? 0 : errno;
	ATF_CHECK_EQ_MSG(error, SELF_UNMUTE_ERRNO, "unmute self: %s",
	    strerror(error));
	fence = fence_child(p.marker, &gate);
	open_close(p.probe);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, getpid(), fence, NULL),
	    SELF_EVENTS_UNMUTED);
	close(fd);
}

ATF_TC(n4_default_self_mute_sysctl);
ATF_TC_HEAD(n4_default_self_mute_sysctl, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N4: security.oes.default_self_mute (pin: exists, and 0 lets a new client see its opener; after: absent)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(n4_default_self_mute_sysctl, tc)
{
	struct paths p;
	size_t len;
	pid_t fence;
	int fd, gate, old, zero = 0, rv;

	paths_init(&p);
	len = sizeof(old);
	rv = sysctlbyname("security.oes.default_self_mute", &old, &len, NULL,
	    0);
	if (!SELF_MUTE_SYSCTL) {
		ATF_CHECK_ERRNO(ENOENT, rv == -1);
		return;
	}
	ATF_REQUIRE_MSG(rv == 0, "sysctl: %s", strerror(errno));
	ATF_REQUIRE(sysctlbyname("security.oes.default_self_mute", NULL, NULL,
	    &zero, sizeof(zero)) == 0);
	fd = open_client(false);
	ATF_REQUIRE(sysctlbyname("security.oes.default_self_mute", NULL, NULL,
	    &old, sizeof(old)) == 0);
	fence = fence_child(p.marker, &gate);
	open_close(p.probe);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, getpid(), fence, NULL), 1);
	close(fd);
}

ATF_TC(n5_mute_inversion);
ATF_TC_HEAD(n5_mute_inversion, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N5: with process mutes inverted, a client does not receive its opener's events (pin: it does, the self entry inverts)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n5_mute_inversion, tc)
{
	struct oes_mute_invert_args inv;
	struct oes_mute_args mute;
	struct paths p;
	pid_t fence;
	int fd, gate;

	paths_init(&p);
	fd = open_client(false);
	fence = fence_child(p.marker, &gate);
	/* Inverted: only listed processes are delivered; list the fence. */
	memset(&mute, 0, sizeof(mute));
	mute.emu_token.ept_id = (uint64_t)fence;
	ATF_REQUIRE(ioctl(fd, OES_IOC_MUTE_PROCESS, &mute) == 0);
	memset(&inv, 0, sizeof(inv));
	inv.emi_type = OES_MUTE_INVERT_PROCESS;
	inv.emi_invert = 1;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_MUTE_INVERT, &inv) == 0);
	open_close(p.probe);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, getpid(), fence, NULL),
	    SELF_EVENTS_INVERTED);
	close(fd);
}

/* Send fd over sock (SCM_RIGHTS). */
static void
send_fd(int sock, int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))], c = 'f';
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
	    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;

	memset(cbuf, 0, sizeof(cbuf));
	cm = CMSG_FIRSTHDR(&m);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	ATF_REQUIRE(sendmsg(sock, &m, 0) == 1);
}

static int
recv_fd(int sock)
{
	char cbuf[CMSG_SPACE(sizeof(int))], c;
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
	    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;
	int fd;

	if (recvmsg(sock, &m, 0) != 1)
		return (-1);
	cm = CMSG_FIRSTHDR(&m);
	if (cm == NULL || cm->cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return (fd);
}

/*
 * The receiver C of a passed client: optionally reads once first (a
 * nonblocking read with no event joins it as a reader), opens the probe,
 * then counts its own events until the fence (spawned and released by C),
 * and exits with the count, or 100 + a step on failure.
 */
static int
receiver(int sock, const char *probe, const char *marker, bool read_first,
    bool also_d)
{
	test_msg_buf buf;
	pid_t fence;
	int fd, gate, n;

	fd = recv_fd(sock);
	if (fd < 0)
		return (101);
	if (read_first)
		(void)read(fd, &buf, sizeof(buf));
	open_close(probe);
	if (also_d) {
		/* Let the parent's second client see our probe first. */
		char c = 'p';

		if (write(sock, &c, 1) != 1)
			return (102);
	}
	fence = fence_child(marker, &gate);
	release(gate, fence);
	n = count_until_fence(fd, getpid(), fence, NULL);
	return (n);
}

ATF_TC(n6_passed_client_receiver);
ATF_TC_HEAD(n6_passed_client_receiver, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N6: a client passed over SCM_RIGHTS to a process that reads it does not deliver that process's events to it (pin: it does)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n6_passed_client_receiver, tc)
{
	struct paths p;
	int sv[2], fd, status;
	pid_t c;

	paths_init(&p);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		_exit(receiver(sv[1], p.probe, p.marker, true, false));
	}
	close(sv[1]);
	fd = open_client(false);
	send_fd(sv[0], fd);
	close(fd);
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ_MSG(WEXITSTATUS(status), SELF_EVENTS_RECEIVER,
	    "receiver saw %d of its own events", WEXITSTATUS(status));
}

ATF_TC(n7_join_ioctl);
ATF_TC_HEAD(n7_join_ioctl, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N7: OES_IOC_JOIN (pin: unknown, ENOTTY)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n7_join_ioctl, tc)
{
	int fd, rv;

	fd = open_client(false);
#ifdef OES_IOC_JOIN
	rv = ioctl(fd, OES_IOC_JOIN);
	ATF_CHECK_EQ_MSG(rv, 0, "OES_IOC_JOIN: %s", strerror(errno));
#else
	/* The next free 'E' command the design gives it. */
	rv = ioctl(fd, _IO('E', SELF_JOIN_NR));
	ATF_CHECK_ERRNO(ENOTTY, rv == -1);
#endif
	close(fd);
}

ATF_TC(n13_reader_flagged_oes_client);
ATF_TC_HEAD(n13_reader_flagged_oes_client, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N9/N13: another client D sees a passed client's reader, flagged EP_FLAG_OES_CLIENT (pin: not flagged)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n13_reader_flagged_oes_client, tc)
{
	struct paths p;
	uint32_t flags = 0;
	pid_t c, fence;
	int sv[2], fd, d, status, gate;
	char ch;

	paths_init(&p);
	d = open_client(true);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		close(d);
		_exit(receiver(sv[1], p.probe, p.marker, true, true));
	}
	close(sv[1]);
	fd = open_client(false);
	send_fd(sv[0], fd);
	close(fd);
	/* The receiver has opened its probe. */
	ATF_REQUIRE(read(sv[0], &ch, 1) == 1);
	fence = fence_child(p.marker, &gate);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(d, c, fence, &flags), 1);
	ATF_CHECK_EQ_MSG((flags & EP_FLAG_OES_CLIENT) != 0,
	    SELF_READER_FLAGGED, "ep_flags %#x", flags);
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	close(d);
}

/* Receive a passed client, join it with OES_IOC_JOIN only, open probe. */
static int
joiner(int sock, const char *probe)
{
	char c = 'j';
	int fd;

	fd = recv_fd(sock);
	if (fd < 0)
		return (101);
	if (ioctl(fd, OES_IOC_JOIN) != 0)
		return (102);
	open_close(probe);
	if (write(sock, &c, 1) != 1)
		return (103);
	/* Hold the client until the parent has counted. */
	if (read(sock, &c, 1) != 1)
		return (104);
	return (0);
}

ATF_TC(n7b_join_before_first_read);
ATF_TC_HEAD(n7b_join_before_first_read, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N6/N7: a receiver that only calls OES_IOC_JOIN is a reader at once: its opens are not delivered to the client, nor are the opener's");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n7b_join_before_first_read, tc)
{
	struct paths p;
	pid_t c, fence, subjects[2];
	int sv[2], fd, gate, status;
	char ch;

	paths_init(&p);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		_exit(joiner(sv[1], p.probe));
	}
	close(sv[1]);
	fd = open_client(false);
	send_fd(sv[0], fd);
	ATF_REQUIRE(read(sv[0], &ch, 1) == 1);
	open_close(p.probe);		/* the opener */
	fence = fence_child(p.marker, &gate);
	release(gate, fence);
	subjects[0] = c;
	subjects[1] = getpid();
	ATF_CHECK_EQ(count_path_until_fence(fd, subjects, 2, p.probe, fence),
	    0);
	ATF_REQUIRE(write(sv[0], "x", 1) == 1);
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(fd);
}

/*
 * N8: a reader's exec ends its membership.  The receiver joins, opens the
 * probe (hidden), then execs cat(1) on the probe with the client still
 * open: the new image is not a reader until it joins, so its open of the
 * probe is delivered.
 */
static int
exec_after_join(int sock, const char *probe)
{
	char *const argv[] = { __DECONST(char *, "cat"),
	    __DECONST(char *, probe), NULL };
	int fd, devnull;

	fd = recv_fd(sock);
	if (fd < 0)
		return (101);
	if (ioctl(fd, OES_IOC_JOIN) != 0)
		return (102);
	open_close(probe);
	devnull = open("/dev/null", O_WRONLY);
	if (devnull < 0 || dup2(devnull, STDOUT_FILENO) < 0)
		return (103);
	execv("/bin/cat", argv);
	return (104);
}

ATF_TC(n8_exec_ends_membership);
ATF_TC_HEAD(n8_exec_ends_membership, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N8: a reader that executes a new image stops being a reader: the old image's opens are hidden from the client, the new image's are delivered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n8_exec_ends_membership, tc)
{
	struct paths p;
	pid_t c, fence;
	int sv[2], fd, gate, status, n;

	paths_init(&p);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		_exit(exec_after_join(sv[1], p.probe));
	}
	close(sv[1]);
	fd = open_client(false);
	send_fd(sv[0], fd);
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "receiver status %#x", status);
	fence = fence_child(p.marker, &gate);
	release(gate, fence);
	/* Two opens of the probe by c: only the one after exec arrives. */
	n = count_path_until_fence(fd, &c, 1, p.probe, fence);
	ATF_CHECK_EQ_MSG(n, 1, "%d opens of %s by %d delivered", n, p.probe,
	    (int)c);
	close(fd);
}

ATF_TC(n9_two_readers);
ATF_TC_HEAD(n9_two_readers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N9: two readers of one client: neither one's opens reach that client; another client sees both");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n9_two_readers, tc)
{
	struct paths p;
	pid_t r[2], fence;
	int sv[2][2], fd, d, gate, status, i, n;
	char ch;

	paths_init(&p);
	d = open_client(true);
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) == 0);
		r[i] = fork();
		ATF_REQUIRE(r[i] >= 0);
		if (r[i] == 0) {
			close(sv[i][0]);
			close(d);
			_exit(joiner(sv[i][1], p.probe));
		}
		close(sv[i][1]);
	}
	fd = open_client(false);
	for (i = 0; i < 2; i++) {
		send_fd(sv[i][0], fd);
		ATF_REQUIRE(read(sv[i][0], &ch, 1) == 1);
	}
	fence = fence_child(p.marker, &gate);
	release(gate, fence);
	n = count_path_until_fence(fd, r, 2, p.probe, fence);
	ATF_CHECK_EQ_MSG(n, 0, "the shared client got %d", n);
	n = count_path_until_fence(d, r, 2, p.probe, fence);
	ATF_CHECK_EQ_MSG(n, 2, "the other client got %d", n);
	for (i = 0; i < 2; i++) {
		ATF_REQUIRE(write(sv[i][0], "x", 1) == 1);
		ATF_REQUIRE(waitpid(r[i], &status, 0) == r[i]);
	}
	close(fd);
	close(d);
}

/* ------------------------------------------------------------------ */
/* Deferred delivery, the answer requirement, the trylock fallback. */

/* A client of the given scope subscribed to events[0..n). */
static int
open_client_events(bool descendants, const oes_event_type_t *events, int n)
{
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	if (descendants)
		ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_NOTIFY) == 0);
	ATF_REQUIRE(test_subscribe(fd, __DECONST(oes_event_type_t *, events),
	    n, OES_SUB_REPLACE) == 0);
	return (fd);
}

/*
 * A signal fence: a child that sends SIGCONT (ignored by default) to the
 * test process when released; its NOTIFY_SIGNAL is deferred like the
 * events counted before it.  Not to itself: p_cansignal(9) answers a
 * process signalling itself before the MAC check, so no event is made.
 */
static pid_t
signal_fence(int *gate)
{
	int p[2];
	pid_t pid;
	char c;

	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(p[1]);
		if (read(p[0], &c, 1) != 1)
			_exit(1);
		_exit(kill(getppid(), SIGCONT) == 0 ? 0 : 1);
	}
	close(p[0]);
	*gate = p[1];
	return (pid);
}

/*
 * Count the NOTIFY_FORK and NOTIFY_SIGNAL events whose subject is pid until
 * fence's NOTIFY_SIGNAL.
 */
static void
count_fork_signal_until_fence(int fd, pid_t pid, pid_t fence, int *forks,
    int *signals)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;

	*forks = *signals = 0;
	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, OES_TEST_DEADLINE_MS) ==
		    0, "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_process.ep_pid == fence &&
		    msg->em_event == OES_EVENT_NOTIFY_SIGNAL)
			return;
		if (msg->em_process.ep_pid != pid)
			continue;
		if (msg->em_event == OES_EVENT_NOTIFY_FORK)
			(*forks)++;
		else if (msg->em_event == OES_EVENT_NOTIFY_SIGNAL)
			(*signals)++;
	}
}

/*
 * The receiver of a passed client: join, fork a child and signal it (two
 * deferred events with the receiver as subject), reap it; then, if exec_path
 * is set, execute it with the client's descriptor as argv[1] (the new image
 * joins at once: oes_join_helper).
 */
static int
deferred_actor(int sock, const char *exec_path)
{
	char fdstr[16];
	int fd, status;
	pid_t g;

	fd = recv_fd(sock);
	if (fd < 0)
		return (101);
	if (ioctl(fd, OES_IOC_JOIN) != 0)
		return (102);
	g = fork();
	if (g < 0)
		return (103);
	if (g == 0) {
		pause();
		_exit(0);
	}
	if (kill(g, SIGTERM) != 0 || waitpid(g, &status, 0) != g)
		return (104);
	if (exec_path == NULL)
		return (0);
	snprintf(fdstr, sizeof(fdstr), "%d", fd);
	execl(exec_path, "oes_join_helper", fdstr, (char *)NULL);
	return (105);
}

#define	DEFER_HOLD	"debug.mac_capability.test_issuer_oes_defer_hold"

/* Arm (1) or release (0) the test kernel's deferred-delivery hold point. */
static int
defer_hold(int v)
{

	return (sysctlbyname(DEFER_HOLD, NULL, NULL, &v, sizeof(v)));
}

/*
 * The deferred task does not run from here until hold is released, so the
 * actor's fork and signal events stay queued while it execs and the new
 * image joins.  On a kernel that drains the task before dropping the old
 * entry, that join releases the hold and waits; the events are matched
 * against the old entry, still published.  On one that does not, the join
 * returns, the actor exits, and only the release below lets the task
 * deliver, against a set the old entry has left: the leak is certain, not
 * a race.
 */
static void
deferred_case(const atf_tc_t *tc, bool exec_rejoin)
{
	static const oes_event_type_t events[] = { OES_EVENT_NOTIFY_FORK,
	    OES_EVENT_NOTIFY_SIGNAL };
	char helper[PATH_MAX];
	pid_t c, fence;
	int sv[2], x, d, gate, status, forks, signals;

	snprintf(helper, sizeof(helper), "%s/oes_join_helper",
	    atf_tc_get_config_var(tc, "srcdir"));
	d = open_client_events(true, events, nitems(events));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		close(d);
		_exit(deferred_actor(sv[1], exec_rejoin ? helper : NULL));
	}
	close(sv[1]);
	x = open_client_events(false, events, nitems(events));
	if (exec_rejoin)
		ATF_REQUIRE_MSG(defer_hold(1) == 0, "%s: %s", DEFER_HOLD,
		    strerror(errno));
	send_fd(sv[0], x);
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	if (exec_rejoin)
		ATF_REQUIRE(defer_hold(0) == 0);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "actor status %#x", status);
	fence = signal_fence(&gate);
	release(gate, fence);
	/*
	 * The receiver's own fork and signal (its SIGTERM to its child) never
	 * reach its client; the other client sees one of each.
	 */
	count_fork_signal_until_fence(x, c, fence, &forks, &signals);
	ATF_CHECK_EQ_MSG(forks, 0, "own forks delivered: %d", forks);
	ATF_CHECK_EQ_MSG(signals, 0, "own signals delivered: %d", signals);
	count_fork_signal_until_fence(d, c, fence, &forks, &signals);
	ATF_CHECK_EQ_MSG(forks, 1, "forks seen by the other client: %d", forks);
	ATF_CHECK_EQ_MSG(signals, 1, "signals seen by the other client: %d",
	    signals);
	close(x);
	close(d);
}

ATF_TC(n14_deferred_fork_signal);
ATF_TC_HEAD(n14_deferred_fork_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Deferred delivery: a joined receiver's own fork is not delivered to its client, and another client sees it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n14_deferred_fork_signal, tc)
{

	deferred_case(tc, false);
}

ATF_TC_WITH_CLEANUP(n15_exec_rejoin_deferred);
ATF_TC_HEAD(n15_exec_rejoin_deferred, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Review D1: a reader whose deferred fork event is held queued (test kernel hold point) execs and its new image joins at once (compacting the old entry); the queued event still does not reach its client");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* The hold stops every client's deferred delivery. */
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(n15_exec_rejoin_deferred, tc)
{
	int v;
	size_t len = sizeof(v);

	if (sysctlbyname(DEFER_HOLD, &v, &len, NULL, 0) != 0)
		atf_tc_skip("DEFERRED_STACK_TIER: needs a "
		    "MAC_CAPABILITY_TEST_PERMISSIVE kernel (%s)",
		    DEFER_HOLD);
	ATF_REQUIRE_EQ_MSG(v, 0, "%s already armed", DEFER_HOLD);
	deferred_case(tc, true);
}
ATF_TC_CLEANUP(n15_exec_rejoin_deferred, tc)
{

	(void)defer_hold(0);
}

/* An AUTH_OPEN client of the test's descendants, fail-closed. */
static int
open_auth_client(void)
{
	oes_event_type_t events[] = { OES_EVENT_AUTH_OPEN };
	struct oes_mode_args mode;
	struct oes_deadline_miss_mode_args miss;
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_AUTH;
	mode.ema_default_deadline_ms = OES_TEST_DEADLINE_MS;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_MODE, &mode) == 0);
	memset(&miss, 0, sizeof(miss));
	miss.edma_mode = OES_DEADLINE_MISS_FAIL_CLOSED;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_DEADLINE_MISS_MODE, &miss) == 0);
	ATF_REQUIRE(test_subscribe(fd, events, nitems(events),
	    OES_SUB_REPLACE) == 0);
	return (fd);
}

enum auth_actor { AUTH_JOIN_FULL, AUTH_JOIN_READONLY, AUTH_NO_JOIN };

/* Receive the AUTH client, set it up as told, open probe; exit errno. */
static int
auth_actor(int sock, const char *probe, enum auth_actor how)
{
	cap_rights_t rights;
	const cap_ioctl_t cmds[] = { OES_IOC_JOIN };
	int fd, pfd;

	fd = recv_fd(sock);
	if (fd < 0)
		return (101);
	if (how == AUTH_JOIN_READONLY &&
	    (cap_rights_limit(fd, cap_rights_init(&rights, CAP_READ,
	    CAP_EVENT, CAP_IOCTL)) != 0 ||
	    cap_ioctls_limit(fd, cmds, nitems(cmds)) != 0))
		return (102);
	if (how != AUTH_NO_JOIN && ioctl(fd, OES_IOC_JOIN) != 0)
		return (103);
	pfd = open(probe, O_RDONLY);
	if (pfd < 0)
		return (errno);
	close(pfd);
	return (0);
}

/*
 * Answer every AUTH event on y with ALLOW until fence's; return how many
 * came from subject.
 */
static int
answer_until_fence(int y, pid_t subject, pid_t fence)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	oes_response_t resp;
	pid_t from;
	int n = 0;

	for (;;) {
		ATF_REQUIRE_MSG(test_wait_event(y, msg, OES_TEST_DEADLINE_MS) == 0,
		    "no fence event within %d ms", OES_TEST_DEADLINE_MS);
		if (msg->em_event != OES_EVENT_AUTH_OPEN)
			continue;
		from = msg->em_process.ep_pid;
		memset(&resp, 0, sizeof(resp));
		resp.er_id = msg->em_id;
		resp.er_result = OES_AUTH_ALLOW;
		ATF_REQUIRE(write(y, &resp, sizeof(resp)) == sizeof(resp));
		if (from == fence)
			return (n);
		if (from == subject)
			n++;
	}
}

/*
 * want_delivered 1: the actor's AUTH_OPEN must reach the client; it is
 * answered when it arrives, and the actor's exit follows.  0: the actor's
 * open must complete without the client (were it delivered, nobody would
 * answer it and the fail-closed deadline would refuse it), and a fence
 * afterwards shows nothing of the actor's was queued.
 */
static void
auth_case(enum auth_actor how, int want_delivered)
{
	test_msg_buf buf;
	oes_message_t *msg = &buf.msg;
	oes_response_t resp;
	struct paths p;
	pid_t c, fence;
	int sv[2], y, gate, status, n;

	paths_init(&p);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	/*
	 * The client first: a descendants scope covers the processes forked
	 * after it was set (the scope marker is inherited at fork), so the
	 * actor must be forked afterwards.  It drops its inherited copy and
	 * uses only the descriptor it is sent.
	 */
	y = open_auth_client();
	c = fork();
	ATF_REQUIRE(c >= 0);
	if (c == 0) {
		close(sv[0]);
		close(y);
		_exit(auth_actor(sv[1], p.probe, how));
	}
	close(sv[1]);
	send_fd(sv[0], y);
	if (want_delivered) {
		for (;;) {
			ATF_REQUIRE_MSG(test_wait_event(y, msg,
			    OES_TEST_DEADLINE_MS) == 0,
			    "no AUTH_OPEN from the actor within %d ms",
			    OES_TEST_DEADLINE_MS);
			if (msg->em_event != OES_EVENT_AUTH_OPEN)
				continue;
			memset(&resp, 0, sizeof(resp));
			resp.er_id = msg->em_id;
			resp.er_result = OES_AUTH_ALLOW;
			ATF_REQUIRE(write(y, &resp, sizeof(resp)) ==
			    sizeof(resp));
			if (msg->em_process.ep_pid == c)
				break;
		}
	}
	ATF_REQUIRE(waitpid(c, &status, 0) == c);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "actor status %#x", status);
	if (!want_delivered) {
		fence = fence_child(p.marker, &gate);
		ATF_REQUIRE(write(gate, "g", 1) == 1);
		close(gate);
		n = answer_until_fence(y, c, fence);
		ATF_REQUIRE(waitpid(fence, &status, 0) == fence);
		ATF_CHECK_EQ_MSG(n, 0, "%d of the actor's AUTH_OPENs delivered",
		    n);
	}
	close(y);
}

ATF_TC(n16_auth_reader_can_answer);
ATF_TC_HEAD(n16_auth_reader_can_answer, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner D4: a joined receiver whose descriptor can answer (open for writing, CAP_WRITE) gets an implicit allow for its own AUTH_OPEN; nothing is delivered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n16_auth_reader_can_answer, tc)
{

	auth_case(AUTH_JOIN_FULL, 0);
}

ATF_TC(n16b_auth_readonly_reader);
ATF_TC_HEAD(n16b_auth_readonly_reader, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Owner D4: a joined receiver whose descriptor lacks CAP_WRITE cannot exempt itself: its own AUTH_OPEN is delivered and answered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n16b_auth_readonly_reader, tc)
{

	auth_case(AUTH_JOIN_READONLY, 1);
}

ATF_TC(n10_auth_before_join);
ATF_TC_HEAD(n10_auth_before_join, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "N10, the owner-accepted window: a receiver that has not joined is not a reader, so its AUTH_OPEN reaches the client (answered here)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n10_auth_before_join, tc)
{

	auth_case(AUTH_NO_JOIN, 1);
}

ATF_TC(n17_trylock_fallback);
ATF_TC_HEAD(n17_trylock_fallback, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Review H1: with the test kernel's fail point forcing the unlocked record fill for the opener, its own opens still do not reach its client");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(n17_trylock_fallback, tc)
{
	struct paths p;
	size_t len;
	pid_t fence;
	int fd, gate, me, off = 0, v;

	len = sizeof(v);
	if (sysctlbyname("debug.mac_capability.test_issuer_oes_trylock_fail",
	    &v, &len, NULL, 0) != 0)
		atf_tc_skip("DEFERRED_STACK_TIER: no "
		    "debug.mac_capability.test_issuer_oes_trylock_fail: "
		    "needs GENERIC-TEST (vm-provider.sh KERNEL_TIER=test)");
	paths_init(&p);
	fd = open_client(false);
	me = getpid();
	ATF_REQUIRE(sysctlbyname("debug.mac_capability.test_issuer_oes_trylock_fail",
	    NULL, NULL, &me, sizeof(me)) == 0);
	open_close(p.probe);
	ATF_REQUIRE(sysctlbyname("debug.mac_capability.test_issuer_oes_trylock_fail",
	    NULL, NULL, &off, sizeof(off)) == 0);
	fence = fence_child(p.marker, &gate);
	release(gate, fence);
	ATF_CHECK_EQ(count_until_fence(fd, me, fence, NULL), 0);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, n1_opener_global);
	ATF_TP_ADD_TC(tp, n2_opener_descendants);
	ATF_TP_ADD_TC(tp, n3_unmute_self);
	ATF_TP_ADD_TC(tp, n4_default_self_mute_sysctl);
	ATF_TP_ADD_TC(tp, n5_mute_inversion);
	ATF_TP_ADD_TC(tp, n6_passed_client_receiver);
	ATF_TP_ADD_TC(tp, n7_join_ioctl);
	ATF_TP_ADD_TC(tp, n13_reader_flagged_oes_client);
	ATF_TP_ADD_TC(tp, n7b_join_before_first_read);
	ATF_TP_ADD_TC(tp, n8_exec_ends_membership);
	ATF_TP_ADD_TC(tp, n9_two_readers);
	ATF_TP_ADD_TC(tp, n10_auth_before_join);
	ATF_TP_ADD_TC(tp, n14_deferred_fork_signal);
	ATF_TP_ADD_TC(tp, n15_exec_rejoin_deferred);
	ATF_TP_ADD_TC(tp, n16_auth_reader_can_answer);
	ATF_TP_ADD_TC(tp, n16b_auth_readonly_reader);
	ATF_TP_ADD_TC(tp, n17_trylock_fallback);
	return (atf_no_error());
}
