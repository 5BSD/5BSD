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
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"
#include "self_events_expect.h"

/* The longest an event the kernel has generated may take to arrive. */
#define	EVENT_DEADLINE_MS	30000

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
		ATF_REQUIRE_MSG(test_wait_event(fd, msg, EVENT_DEADLINE_MS) == 0,
		    "no fence event within %d ms", EVENT_DEADLINE_MS);
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
	return (atf_no_error());
}
