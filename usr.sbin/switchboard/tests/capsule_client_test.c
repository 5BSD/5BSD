/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capsule_client_test -- SwitchBoard's capability-channel RPC client
 * (capsule_client.c, mac_capability_direct.c) against real channels, with a
 * forked peer standing in for Capsule.
 *
 * Capability channels are kqueue-only: poll(2) answers POLLNVAL
 * (b08ea010c98).  A client that waits for a reply with poll(2) never
 * sleeps; on SwitchBoard's non-blocking Capsule channel it spins on EAGAIN
 * until the reply arrives.  These cases pin that a reply wait sleeps (it
 * costs a small part of its wall time in CPU), that Capsule's death ends the
 * wait with ECONNRESET, that stale replies (with descriptors too) are dropped
 * rather than wedging the channel or answering the wrong request, and the
 * existing behaviour around it: a prompt reply, the release burst, and the
 * direct channel mint.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "switchboard.h"

/* The direct-mint code reads SwitchBoard's descriptors from here. */
struct switchboard_state sd;

/*
 * How long the stand-in Capsule holds a reply in the slow cases.  It only
 * has to be long enough for the client to be waiting; nothing is asserted
 * against it.
 */
#define	SLOW_REPLY_MS	1000

static int
chan_create(int fds[2])
{
	struct module_stat ms;
	int modid;

	modid = modfind("sys/mac_capability_channel_create");
	ATF_REQUIRE_MSG(modid >= 0,
	    "syscall module sys/mac_capability_channel_create not found");
	ms.version = sizeof(ms);
	ATF_REQUIRE(modstat(modid, &ms) == 0);
	return (syscall(ms.data.intval, fds));
}

/*
 * A channel pair laid out as SwitchBoard holds its Capsule channel: P[0] is
 * SwitchBoard's end, non-blocking (switchboard.c), and P[1] is Capsule's.
 */
static void
pair(int P[2])
{

	ATF_REQUIRE_MSG(chan_create(P) == 0, "channel pair: %s",
	    strerror(errno));
	ATF_REQUIRE(fcntl(P[0], F_SETFL, O_NONBLOCK) == 0);
	/*
	 * The client logs dropped replies; connect the log socket now so it
	 * is not mistaken for a leaked descriptor.
	 */
	openlog("capsule_client_test", LOG_NDELAY, LOG_USER);
}

static int
peer_reply(int fd, uint64_t token, int32_t status, int attach)
{
	struct mac_capability_sendmsg_args sa;
	struct capsule_reply rpl;

	rpl.status = status;
	memset(&sa, 0, sizeof(sa));
	sa.payload = &rpl;
	sa.payload_len = sizeof(rpl);
	sa.reply_token = token;
	if (attach >= 0) {
		sa.fds = &attach;
		sa.nfds = 1;
	}
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

/* Blocking receive of one request on the peer end; returns its token. */
static int
peer_request(int fd, uint32_t *op, uint64_t *token)
{
	struct mac_capability_recvmsg_args ra;
	char buf[4096];

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0 ||
	    ra.payload_len < sizeof(*op))
		return (-1);
	memcpy(op, buf, sizeof(*op));
	*token = ra.reply_token;
	return (0);
}

static int
pipe_read_end(void)
{
	int p[2];

	if (pipe(p) != 0)
		return (-1);
	close(p[1]);
	return (p[0]);
}

enum peer_mode {
	PEER_PROMPT,		/* reply at once */
	PEER_SLOW,		/* reply after SLOW_REPLY_MS */
	PEER_STALE_FIRST,	/* a reply with another token, then the reply */
	PEER_STALE_FD_FIRST,	/* the same, the stale one carrying a pipe */
	PEER_CLOSE,		/* read the request, close without replying */
	PEER_SLOW_DIE,		/* read the request, exit after SLOW_REPLY_MS */
};

/*
 * Fork a stand-in Capsule on P[1] that answers one request of type want_op
 * with status 0, then stays connected until the parent closes P[0].  The
 * parent closes its copy of P[1].
 */
static pid_t
peer_start(int P[2], enum peer_mode mode, uint32_t want_op)
{
	struct timespec slow;
	uint64_t token;
	uint32_t op;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid != 0) {
		close(P[1]);
		return (pid);
	}
	close(P[0]);
	slow.tv_sec = SLOW_REPLY_MS / 1000;
	slow.tv_nsec = (SLOW_REPLY_MS % 1000) * 1000000L;
	if (peer_request(P[1], &op, &token) != 0 || op != want_op)
		_exit(10);
	switch (mode) {
	case PEER_PROMPT:
		break;
	case PEER_SLOW:
		(void)nanosleep(&slow, NULL);
		break;
	case PEER_STALE_FIRST:
		if (peer_reply(P[1], token + 1000, EIO, -1) != 0)
			_exit(11);
		break;
	case PEER_STALE_FD_FIRST:
		if (peer_reply(P[1], token + 1000, 0, pipe_read_end()) != 0)
			_exit(11);
		break;
	case PEER_CLOSE:
		_exit(0);
	case PEER_SLOW_DIE:
		(void)nanosleep(&slow, NULL);
		_exit(0);
	}
	if (peer_reply(P[1], token, 0, -1) != 0)
		_exit(12);
	/*
	 * Stay connected until the parent closes its end: a closed peer
	 * makes the parent's end read ready (EV_EOF).
	 */
	(void)peer_request(P[1], &op, &token);
	_exit(0);
}

/* Close SwitchBoard's end, then reap the stand-in. */
static void
peer_finish(int P[2], pid_t pid)
{
	int status;

	close(P[0]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "peer status %#x", status);
}

struct cost {
	struct timespec	wall;
	struct rusage	ru;
};

static void
cost_start(struct cost *c)
{

	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &c->wall) == 0);
	ATF_REQUIRE(getrusage(RUSAGE_SELF, &c->ru) == 0);
}

/*
 * A wait for a reply sleeps: a blocked receive costs a few system calls, a
 * spinning one its whole wait.  Half the wall time separates the two.
 */
static void
cost_check_slept(const struct cost *c)
{
	struct timespec now;
	struct rusage ru;
	struct timeval u, s;
	double wall_ms, cpu_ms;

	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
	ATF_REQUIRE(getrusage(RUSAGE_SELF, &ru) == 0);
	wall_ms = (now.tv_sec - c->wall.tv_sec) * 1e3 +
	    (now.tv_nsec - c->wall.tv_nsec) / 1e6;
	timersub(&ru.ru_utime, &c->ru.ru_utime, &u);
	timersub(&ru.ru_stime, &c->ru.ru_stime, &s);
	cpu_ms = (u.tv_sec + s.tv_sec) * 1e3 + (u.tv_usec + s.tv_usec) / 1e3;
	ATF_CHECK_MSG(cpu_ms < wall_ms / 2,
	    "waiting for the reply used %.1f ms CPU in %.1f ms", cpu_ms,
	    wall_ms);
}

/*
 * Whether a message (or EOF) is queued on fd now: the channel's EVFILT_READ
 * as the SwitchBoard event loop sees it.
 */
static int
readable_now(int fd)
{
	struct kevent kev;
	struct timespec zero = { 0, 0 };
	int kq, n;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	n = kevent(kq, &kev, 1, &kev, 1, &zero);
	ATF_REQUIRE_MSG(n >= 0, "kevent: %s", strerror(errno));
	close(kq);
	return (n);
}

/* The lowest descriptor number free in this process. */
static int
lowest_free_fd(void)
{
	int fd;

	fd = dup(STDIN_FILENO);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	return (fd);
}

static struct svc_manifest *
system_manifest(void)
{
	struct svc_manifest *m;

	m = calloc(1, sizeof(*m));
	ATF_REQUIRE(m != NULL);
	m->cap_system = 1;
	return (m);
}

#define	CHANNEL_TC_HEAD(name, text)					\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", text);				\
	atf_tc_set_md_var(tc, "require.kmods",				\
	    "mac_capability mac_capability_channel");			\
}

CHANNEL_TC_HEAD(rpc_prompt_reply,
    "an RPC answered at once returns Capsule's status")
ATF_TC_BODY(rpc_prompt_reply, tc)
{
	int P[2];
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_PROMPT, CAPSULE_OP_READY);
	ATF_CHECK_EQ_MSG(0, capsule_send_ready(P[0]), "%s", strerror(errno));
	ATF_CHECK_EQ(0, readable_now(P[0]));
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(rpc_slow_reply_waited,
    "an RPC whose reply is slow waits for it, asleep")
ATF_TC_BODY(rpc_slow_reply_waited, tc)
{
	struct cost c;
	int P[2];
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_SLOW, CAPSULE_OP_READY);
	cost_start(&c);
	ATF_CHECK_EQ_MSG(0, capsule_send_ready(P[0]), "%s", strerror(errno));
	cost_check_slept(&c);
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(rpc_stale_reply_drained,
    "a reply with another token is dropped and the matching reply taken")
ATF_TC_BODY(rpc_stale_reply_drained, tc)
{
	int P[2];
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_STALE_FIRST, CAPSULE_OP_READY);
	ATF_CHECK_EQ_MSG(0, capsule_send_ready(P[0]), "%s", strerror(errno));
	ATF_CHECK_EQ(0, readable_now(P[0]));
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(rpc_stale_fd_reply_drained,
    "a stale reply carrying a descriptor ahead of a status-only reply is "
    "dropped, its descriptor closed, and the RPC answered")
ATF_TC_BODY(rpc_stale_fd_reply_drained, tc)
{
	int P[2], before, r, saved;
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_STALE_FD_FIRST, CAPSULE_OP_READY);
	before = lowest_free_fd();
	r = capsule_send_ready(P[0]);
	saved = errno;
	ATF_CHECK_EQ_MSG(0, r, "%s", strerror(saved));
	ATF_CHECK_EQ(0, readable_now(P[0]));
	ATF_CHECK_EQ_MSG(before, lowest_free_fd(),
	    "the stale reply's descriptor was not closed");
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(rpc_peer_closed,
    "an RPC whose peer closes without replying fails with ECONNRESET")
ATF_TC_BODY(rpc_peer_closed, tc)
{
	int P[2], r, saved;
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_CLOSE, CAPSULE_OP_READY);
	r = capsule_send_ready(P[0]);
	saved = errno;
	ATF_CHECK_EQ(-1, r);
	if (r == -1)
		ATF_CHECK_EQ_MSG(ECONNRESET, saved, "%s", strerror(saved));
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(rpc_peer_dies_while_waiting,
    "Capsule's death while an RPC waits ends the wait with ECONNRESET; "
    "the wait sleeps")
ATF_TC_BODY(rpc_peer_dies_while_waiting, tc)
{
	struct cost c;
	int P[2], r, saved;
	pid_t pid;

	pair(P);
	pid = peer_start(P, PEER_SLOW_DIE, CAPSULE_OP_READY);
	cost_start(&c);
	r = capsule_send_ready(P[0]);
	saved = errno;
	cost_check_slept(&c);
	ATF_CHECK_EQ(-1, r);
	if (r == -1)
		ATF_CHECK_EQ_MSG(ECONNRESET, saved, "%s", strerror(saved));
	peer_finish(P, pid);
}

CHANNEL_TC_HEAD(release_prompt_replies,
    "a manifest release sends one request per gate class and takes the "
    "reply")
ATF_TC_BODY(release_prompt_replies, tc)
{
	struct svc_manifest *m;
	int P[2];
	pid_t pid;

	m = system_manifest();
	pair(P);
	pid = peer_start(P, PEER_PROMPT, CAPSULE_OP_RELEASE_SYSTEM);
	ATF_CHECK_EQ(1, capsule_release_manifest(P[0], m));
	ATF_CHECK_EQ(0, readable_now(P[0]));
	peer_finish(P, pid);
	free(m);
}

CHANNEL_TC_HEAD(release_slow_reply_waited,
    "a manifest release waits for a slow reply, asleep")
ATF_TC_BODY(release_slow_reply_waited, tc)
{
	struct svc_manifest *m;
	struct cost c;
	int P[2];
	pid_t pid;

	m = system_manifest();
	pair(P);
	pid = peer_start(P, PEER_SLOW, CAPSULE_OP_RELEASE_SYSTEM);
	cost_start(&c);
	ATF_CHECK_EQ(1, capsule_release_manifest(P[0], m));
	cost_check_slept(&c);
	ATF_CHECK_EQ(0, readable_now(P[0]));
	peer_finish(P, pid);
	free(m);
}

CHANNEL_TC_HEAD(release_matches_token,
    "a manifest release does not take a stale reply for its own")
ATF_TC_BODY(release_matches_token, tc)
{
	struct svc_manifest *m;
	int P[2];
	pid_t pid;

	m = system_manifest();
	pair(P);
	pid = peer_start(P, PEER_STALE_FIRST, CAPSULE_OP_RELEASE_SYSTEM);
	ATF_CHECK_EQ(1, capsule_release_manifest(P[0], m));
	ATF_CHECK_EQ_MSG(0, readable_now(P[0]),
	    "the release's own reply was left queued");
	peer_finish(P, pid);
	free(m);
}

ATF_TC(create_channel_direct);
ATF_TC_HEAD(create_channel_direct, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "mac_cap_create_channel mints a connected pair from the channel "
	    "service, waiting on a blocking instance");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(create_channel_direct, tc)
{
	struct mac_capability_connect_args ca;
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	char buf[8];
	int ctl, a, b;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl == -1)
		atf_tc_skip("/dev/mac_capability: %s (claimed by the plane "
		    "with isolation enforced)", strerror(errno));
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "channel", sizeof(ca.name));
	ATF_REQUIRE_MSG(ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == 0,
	    "connect channel: %s", strerror(errno));
	close(ctl);
	sd.capsule_channel_fd = -1;
	sd.channel_svc_fd = ca.fd;
	a = b = -1;
	ATF_REQUIRE_EQ_MSG(0, mac_cap_create_channel(&a, &b), "%s",
	    strerror(errno));
	ATF_REQUIRE(a >= 0 && b >= 0);
	memset(&sa, 0, sizeof(sa));
	sa.payload = "ping";
	sa.payload_len = 4;
	ATF_REQUIRE(ioctl(a, MAC_CAPABILITY_SENDMSG, &sa) == 0);
	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_REQUIRE(ioctl(b, MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_CHECK(ra.payload_len == 4 && memcmp(buf, "ping", 4) == 0);
	close(a);
	close(b);
	close(ca.fd);
}

CHANNEL_TC_HEAD(unexpected_message_dropped,
    "a message queued outside an RPC is dropped with its descriptors and "
    "the channel stops reading ready")
ATF_TC_BODY(unexpected_message_dropped, tc)
{
	int P[2], before, fd;

	pair(P);
	/* Nothing queued: nothing dropped. */
	ATF_CHECK_EQ(0, capsule_drop_unexpected(P[0]));
	before = lowest_free_fd();
	fd = pipe_read_end();
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(peer_reply(P[1], 42, 0, fd) == 0);
	close(fd);
	/* Level-triggered: the queued message keeps the channel ready. */
	ATF_CHECK_EQ(1, readable_now(P[0]));
	ATF_CHECK_EQ(1, readable_now(P[0]));
	ATF_CHECK_EQ(1, capsule_drop_unexpected(P[0]));
	ATF_CHECK_EQ_MSG(0, readable_now(P[0]),
	    "the channel still reads ready after the message was dropped");
	ATF_CHECK_EQ_MSG(before, lowest_free_fd(),
	    "the message's descriptor was not closed");
	close(P[0]);
	close(P[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rpc_prompt_reply);
	ATF_TP_ADD_TC(tp, rpc_slow_reply_waited);
	ATF_TP_ADD_TC(tp, rpc_stale_reply_drained);
	ATF_TP_ADD_TC(tp, rpc_stale_fd_reply_drained);
	ATF_TP_ADD_TC(tp, rpc_peer_closed);
	ATF_TP_ADD_TC(tp, rpc_peer_dies_while_waiting);
	ATF_TP_ADD_TC(tp, release_prompt_replies);
	ATF_TP_ADD_TC(tp, release_slow_reply_waited);
	ATF_TP_ADD_TC(tp, release_matches_token);
	ATF_TP_ADD_TC(tp, create_channel_direct);
	ATF_TP_ADD_TC(tp, unexpected_message_dropped);
	return (0);
}
