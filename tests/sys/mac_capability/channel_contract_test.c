/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The channel contract on dev, pinned before channels become a descriptor
 * type of their own (5bsd-designs/channel-ipc-promotion.md, slice S0).
 *
 * The cases create ends with mac_capability_channel_create() (libchannel)
 * and use the raw mac_capability ioctls.  They are of two kinds:
 *
 *   r*   regression pins: dev's behaviour, which every later slice keeps
 *        (R1-R15 of the design);
 *   p0_* fails-before pins: what dev does wrong, marked with
 *        atf_tc_expect_fail() or atf_tc_expect_timeout() naming dev's
 *        behaviour; the slice that fixes it removes the marker (P0.1, P0.2,
 *        P0.4, P0.5, P0.7).
 *
 * Nothing here waits for a guessed time.  A case that must act while a
 * thread sleeps learns of the sleep from dtrace(1) (sched:::sleep, through
 * sleep_watch.h does), and the cases that count kernel events read the
 * count back through a marker system call the consumer exits on.  dtrace
 * runs only in a test guest, where dtraceall is preloaded (the plane refuses
 * a late kldload); every fbt probe names its module and function.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/cap_process.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>
#include <channel.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"
#include "mac_capability_test_helpers.h"
#include "sleep_watch.h"

#define	CHANNEL_KMODS	"mac_capability mac_capability_channel"


/* ---------------------------------------------------------------------
 * Channel helpers
 * --------------------------------------------------------------------- */

static void
pair(int fds[2])
{

	ATF_REQUIRE_MSG(mac_capability_channel_create(fds) == 0,
	    "mac_capability_channel_create: %s", strerror(errno));
}

static int
send_fds(int fd, const void *buf, size_t len, const int *fds, int nfds,
    uint64_t token, uint32_t flags)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = buf;
	sa.payload_len = len;
	sa.fds = fds;
	sa.nfds = nfds;
	sa.reply_token = token;
	sa.flags = flags;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

static int
send_msg(int fd, const void *buf, size_t len)
{

	return (send_fds(fd, buf, len, NULL, 0, 0, 0));
}

/*
 * Receive one message; returns 0 or -1 with errno.  *lenp is the payload
 * length, *nfdsp the number of descriptors stored in fds (at most maxfds),
 * *tokenp the reply token.  `flags` are RECV_F_* input flags; with
 * RECV_F_WAIT the wait has no limit.
 */
static int
recv_fds(int fd, void *buf, size_t len, uint32_t *lenp, int *fds,
    uint32_t maxfds, uint32_t *nfdsp, uint64_t *tokenp, uint32_t flags)
{
	struct mac_capability_recvmsg_args ra;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = len;
	ra.fds = fds;
	ra.nfds = maxfds;
	ra.flags = flags;
	if ((flags & MAC_CAPABILITY_RECV_F_WAIT) != 0)
		ra._reserved[0] = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) != 0)
		return (-1);
	if (lenp != NULL)
		*lenp = ra.payload_len;
	if (nfdsp != NULL)
		*nfdsp = ra.nfds;
	if (tokenp != NULL)
		*tokenp = ra.reply_token;
	return (0);
}

static int
recv_msg(int fd, void *buf, size_t len, uint32_t *lenp)
{

	return (recv_fds(fd, buf, len, lenp, NULL, 0, NULL, NULL, 0));
}

/* A receive that does not wait: EAGAIN when nothing is queued. */
static int
recv_nb(int fd, void *buf, size_t len, uint32_t *lenp, uint64_t *tokenp)
{
	int fl, r, saved;

	fl = fcntl(fd, F_GETFL);
	ATF_REQUIRE(fl >= 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0);
	r = recv_fds(fd, buf, len, lenp, NULL, 0, NULL, tokenp, 0);
	saved = errno;
	ATF_REQUIRE(fcntl(fd, F_SETFL, fl) == 0);
	errno = saved;
	return (r);
}

/* Receive exactly `expect` (a string) as the next message, waiting. */
static void
expect_next(int fd, const char *expect)
{
	char buf[64];
	uint32_t len;

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE_MSG(recv_fds(fd, buf, sizeof(buf) - 1, &len, NULL, 0, NULL,
	    NULL, MAC_CAPABILITY_RECV_F_WAIT) == 0, "receive \"%s\": %s",
	    expect, strerror(errno));
	ATF_CHECK_MSG(len == strlen(expect) && memcmp(buf, expect, len) == 0,
	    "received \"%s\", want \"%s\"", buf, expect);
}

static void
expect_empty(int fd)
{
	char buf[64];

	ATF_CHECK_ERRNO(EAGAIN, recv_nb(fd, buf, sizeof(buf), NULL, NULL) == -1);
}

static uint64_t
badge_of(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0,
	    "GETINFO: %s", strerror(errno));
	ATF_REQUIRE(info.badge != 0);
	return (info.badge);
}

/* Fill fd's send queue; returns the number of messages it took. */
static int
fill(int fd)
{
	int n;

	for (n = 0; send_msg(fd, "fill", 4) == 0; n++)
		;
	ATF_REQUIRE_EQ_MSG(EAGAIN, errno, "fill: %s", strerror(errno));
	ATF_REQUIRE(n > 0);
	return (n);
}

static uint64_t
mono_ns(void)
{
	struct timespec ts;

	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return ((uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec);
}

static int
set_direct(int value)
{
	size_t len;
	int old;

	len = sizeof(old);
	if (sysctlbyname("kern.mac_capability.direct_delivery", &old, &len,
	    &value, sizeof(value)) != 0)
		return (-1);
	return (old);
}

static int
xfer_set(int fd, int state)
{

	return (cap_xfer_limit(fd, state));
}

/* Whether a descriptor is still open in this process. */
static bool
fd_open(int fd)
{

	return (fcntl(fd, F_GETFD) != -1 || errno != EBADF);
}

static ino_t
ino_of(int fd)
{
	struct stat sb;

	ATF_REQUIRE_MSG(fstat(fd, &sb) == 0, "fstat %d: %s", fd,
	    strerror(errno));
	return (sb.st_ino);
}

static void
wait_child(pid_t pid, const char *what)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "%s exited with status %#x", what, status);
}

/* Create a jail with a name unique to this process and attach to it. */
static int
jail_enter(const char *tag)
{
	char name[64];

	snprintf(name, sizeof(name), "chan_s0_%s_%d", tag, (int)getpid());
	return (jail_setv(JAIL_CREATE | JAIL_ATTACH, "name", name, "path", "/",
	    NULL));
}

/* ---------------------------------------------------------------------
 * Signals for the wait cases
 * --------------------------------------------------------------------- */

static atomic_int signals_taken;
static sem_t signal_handled;

static void
on_signal(int signo __unused)
{

	atomic_fetch_add(&signals_taken, 1);
	(void)sem_post(&signal_handled);	/* async-signal-safe */
}

static void
catch_sigusr1(int flags)
{
	struct sigaction sa;

	ATF_REQUIRE(sem_init(&signal_handled, 0, 0) == 0);
	atomic_store(&signals_taken, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sa.sa_flags = flags;
	sigemptyset(&sa.sa_mask);
	ATF_REQUIRE(sigaction(SIGUSR1, &sa, NULL) == 0);
}

static void
wait_handled(void)
{

	while (sem_wait(&signal_handled) == -1 && errno == EINTR)
		;
}

/*
 * The helper thread of the wait cases: it waits for the test thread to
 * sleep in a wait of `kind`, then acts.  It never fails the case itself;
 * the test thread checks what it recorded.
 */
enum helper_act {
	ACT_SIGNAL,		/* signal it once */
	ACT_SIGNAL_RESLEEP_SEND, /* signal, wait for the restarted sleep, send */
	ACT_CLOSE,		/* close `fd` (the peer's last descriptor) */
};

struct helper {
	struct sleep_watch *watch;
	enum helper_act	act;
	char		kind;
	pthread_t	target;
	long		target_tid;
	int		fd;		/* ACT_*_SEND: send here; ACT_CLOSE */
	int64_t		timo[2];	/* the sleeps' timeouts */
	int		nsleeps;	/* sleeps seen */
	bool		done;		/* acted as asked */
};

static void *
helper_run(void *arg)
{
	struct helper *h = arg;

	if (!sleep_watch_next(h->watch, h->kind, h->target_tid, &h->timo[0]))
		return (NULL);
	h->nsleeps = 1;
	switch (h->act) {
	case ACT_SIGNAL:
		pthread_kill(h->target, SIGUSR1);
		h->done = true;
		break;
	case ACT_SIGNAL_RESLEEP_SEND:
		pthread_kill(h->target, SIGUSR1);
		wait_handled();
		/* Only a restarted call sleeps again. */
		if (!sleep_watch_next(h->watch, h->kind, h->target_tid, &h->timo[1]))
			return (NULL);
		h->nsleeps = 2;
		h->done = send_msg(h->fd, "wake", 4) == 0;
		break;
	case ACT_CLOSE:
		h->done = close(h->fd) == 0;
		break;
	}
	return (NULL);
}

static void
helper_start(struct helper *h, pthread_t *thread, struct sleep_watch *watch,
    enum helper_act act, char kind, int fd)
{

	memset(h, 0, sizeof(*h));
	h->watch = watch;
	h->act = act;
	h->kind = kind;
	h->fd = fd;
	h->target = pthread_self();
	ATF_REQUIRE(thr_self(&h->target_tid) == 0);
	ATF_REQUIRE(pthread_create(thread, NULL, helper_run, h) == 0);
}

/* ---------------------------------------------------------------------
 * Regression pins (R1-R15): pass on dev and stay passing.
 * --------------------------------------------------------------------- */

/*
 * R1.  1000 messages arrive in the order sent, each with the descriptors it
 * was sent with.  A sender thread waits for room (SEND_F_WAIT); messages
 * carry 0, 1 or 2 of four pipes in turn, and the receiver checks each
 * received descriptor names the pipe the message was sent with.
 */
#define	R1_COUNT	1000
#define	R1_PIPES	4

struct r1_sender {
	int	fd;
	int	pipes[R1_PIPES][2];
	int	error;		/* 0, or the errno of the failed send */
	int	failed_at;
};

static void *
r1_send(void *arg)
{
	struct r1_sender *s = arg;
	int fds[2], i, nfds;
	uint32_t seq;

	for (i = 0; i < R1_COUNT; i++) {
		seq = i;
		nfds = i % 3;
		fds[0] = s->pipes[i % R1_PIPES][1];
		fds[1] = s->pipes[(i + 1) % R1_PIPES][1];
		if (send_fds(s->fd, &seq, sizeof(seq), fds, nfds, 0,
		    MAC_CAPABILITY_SEND_F_WAIT) != 0) {
			s->error = errno;
			s->failed_at = i;
			break;
		}
	}
	return (NULL);
}

ATF_TC(r1_fifo_with_descriptors);
ATF_TC_HEAD(r1_fifo_with_descriptors, tc)
{
	atf_tc_set_md_var(tc, "descr", "R1: 1000 messages with descriptors "
	    "arrive in order, each with its own descriptors");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r1_fifo_with_descriptors, tc)
{
	struct r1_sender s;
	pthread_t thread;
	ino_t ino[R1_PIPES];
	int P[2], fds[4], i, j;
	uint32_t len, nfds, seq;
	bool order_ok, fds_ok;

	pair(P);
	memset(&s, 0, sizeof(s));
	s.fd = P[0];
	for (j = 0; j < R1_PIPES; j++) {
		ATF_REQUIRE(pipe(s.pipes[j]) == 0);
		ino[j] = ino_of(s.pipes[j][1]);
	}
	ATF_REQUIRE(pthread_create(&thread, NULL, r1_send, &s) == 0);
	order_ok = fds_ok = true;
	for (i = 0; i < R1_COUNT; i++) {
		ATF_REQUIRE_MSG(recv_fds(P[1], &seq, sizeof(seq), &len, fds,
		    nitems(fds), &nfds, NULL, MAC_CAPABILITY_RECV_F_WAIT) == 0,
		    "receive %d: %s", i, strerror(errno));
		if (len != sizeof(seq) || seq != (uint32_t)i) {
			if (order_ok)
				ATF_CHECK_MSG(false, "message %d carries %u",
				    i, seq);
			order_ok = false;
		}
		if (nfds != (uint32_t)(i % 3)) {
			if (fds_ok)
				ATF_CHECK_MSG(false, "message %d carries %u "
				    "descriptors, want %d", i, nfds, i % 3);
			fds_ok = false;
		}
		for (j = 0; j < (int)nfds; j++) {
			if (fds_ok && ino_of(fds[j]) !=
			    ino[(i + j) % R1_PIPES]) {
				ATF_CHECK_MSG(false, "message %d descriptor "
				    "%d names the wrong pipe", i, j);
				fds_ok = false;
			}
			close(fds[j]);
		}
	}
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	ATF_CHECK_MSG(s.error == 0, "send %d: %s", s.failed_at,
	    strerror(s.error));
	expect_empty(P[1]);
	close(P[0]);
	close(P[1]);
}

/*
 * R2.  Everything a process sent before its end went away is read by the
 * peer, in order, with its descriptors; only then does the peer see the
 * death (ECONNRESET).  The sender is a child that exits.
 */
#define	R2_COUNT	100

ATF_TC(r2_sent_before_close_readable);
ATF_TC_HEAD(r2_sent_before_close_readable, tc)
{
	atf_tc_set_md_var(tc, "descr", "R2: messages sent before the peer's "
	    "end closed are all readable, then the peer's death");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r2_sent_before_close_readable, tc)
{
	char buf[16];
	int P[2], pfd[2], fd, i;
	uint32_t len, nfds, seq;
	pid_t child;

	pair(P);
	ATF_REQUIRE(pipe(pfd) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(P[1]);
		for (i = 0; i < R2_COUNT; i++) {
			seq = i;
			if (send_fds(P[0], &seq, sizeof(seq), &pfd[1],
			    i % 10 == 0 ? 1 : 0, 0, 0) != 0)
				_exit(1);
		}
		_exit(0);
	}
	close(P[0]);
	close(pfd[1]);
	/* The child's exit closed its end: everything it sent was sent. */
	wait_child(child, "sender");
	for (i = 0; i < R2_COUNT; i++) {
		fd = -1;
		ATF_REQUIRE_MSG(recv_fds(P[1], &seq, sizeof(seq), &len, &fd, 1,
		    &nfds, NULL, 0) == 0, "receive %d: %s", i,
		    strerror(errno));
		ATF_CHECK_EQ_MSG((uint32_t)i, seq, "message %d", i);
		ATF_CHECK_EQ_MSG(i % 10 == 0 ? 1u : 0u, nfds, "message %d", i);
		if (nfds == 1)
			close(fd);
	}
	/* Drained: the peer's death, waiting or not. */
	ATF_CHECK_ERRNO(ECONNRESET, recv_msg(P[1], buf, sizeof(buf), NULL) ==
	    -1);
	ATF_CHECK_ERRNO(ECONNRESET, recv_fds(P[1], buf, sizeof(buf), NULL,
	    NULL, 0, NULL, NULL, MAC_CAPABILITY_RECV_F_WAIT) == -1);
	close(P[1]);
	close(pfd[0]);
}

/*
 * R3.  Transfer states: a CAP_XFER_NONE descriptor is refused; a
 * CAP_XFER_ONCE one is sent once and then refused; one named twice in one
 * message is refused, and the refusal consumes nothing, neither its own
 * transfer nor another descriptor's in the same message.
 */
ATF_TC(r3_transfer_states);
ATF_TC_HEAD(r3_transfer_states, tc)
{
	atf_tc_set_md_var(tc, "descr", "R3: CAP_XFER_NONE refused, "
	    "CAP_XFER_ONCE sent once, named twice refused consuming nothing");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r3_transfer_states, tc)
{
	int P[2], none[2], once[2], other[2], fds[3], got[3];
	uint32_t nfds;
	char buf[8];

	pair(P);
	ATF_REQUIRE(pipe(none) == 0);
	ATF_REQUIRE(pipe(once) == 0);
	ATF_REQUIRE(pipe(other) == 0);
	ATF_REQUIRE(xfer_set(none[0], CAP_XFER_NONE) == 0);
	ATF_REQUIRE(xfer_set(once[0], CAP_XFER_ONCE) == 0);
	ATF_REQUIRE(xfer_set(other[0], CAP_XFER_ONCE) == 0);

	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    send_fds(P[0], "none", 4, &none[0], 1, 0, 0) == -1);

	/* Named twice, after another one-shot descriptor: all refused. */
	fds[0] = other[0];
	fds[1] = once[0];
	fds[2] = once[0];
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    send_fds(P[0], "twice", 5, fds, 3, 0, 0) == -1);
	expect_empty(P[1]);

	/* Nothing was consumed: each still goes once, and only once. */
	ATF_CHECK_EQ_MSG(0, send_fds(P[0], "once", 4, &once[0], 1, 0, 0),
	    "first send of the one-shot: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(0, send_fds(P[0], "other", 5, &other[0], 1, 0, 0),
	    "first send of the other one-shot: %s", strerror(errno));
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    send_fds(P[0], "again", 5, &once[0], 1, 0, 0) == -1);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    send_fds(P[0], "again", 5, &other[0], 1, 0, 0) == -1);

	/* The peer has exactly the two accepted messages. */
	for (int i = 0; i < 2; i++) {
		memset(buf, 0, sizeof(buf));
		ATF_REQUIRE(recv_fds(P[1], buf, sizeof(buf) - 1, NULL, got,
		    nitems(got), &nfds, NULL, 0) == 0);
		ATF_CHECK_STREQ(i == 0 ? "once" : "other", buf);
		ATF_CHECK_EQ(1u, nfds);
		if (nfds >= 1) {
			/* What arrives cannot be passed on. */
			ATF_CHECK_ERRNO(ENOTCAPABLE,
			    xfer_set(got[0], CAP_XFER_ONCE) == -1);
			close(got[0]);
		}
	}
	expect_empty(P[1]);
	close(P[0]);
	close(P[1]);
}

/*
 * R4.  A per-descriptor expectation (SENDMSG_V2) narrows the delivered copy
 * only: the receiver gets read rights alone, the sender keeps its own.
 */
ATF_TC(r4_spec_narrows_copy_only);
ATF_TC_HEAD(r4_spec_narrows_copy_only, tc)
{
	atf_tc_set_md_var(tc, "descr", "R4: an expectation narrows the "
	    "delivered copy; the sender keeps its rights");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r4_spec_narrows_copy_only, tc)
{
	struct mac_capability_sendmsg_v2_args sa;
	struct mac_capability_recvmsg_v4_args ra;
	struct mac_capability_fd_spec spec;
	struct mac_capability_fd_info info;
	cap_rights_t rights;
	int P[2], sv[2], got;
	char c;

	pair(P);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	memset(&spec, 0, sizeof(spec));
	spec.type = MAC_CAPABILITY_FD_TYPE_ANY;
	spec.rights = MAC_CAPABILITY_FD_RIGHT_READ;
	memset(&sa, 0, sizeof(sa));
	sa.message.payload = "r";
	sa.message.payload_len = 1;
	sa.message.fds = &sv[0];
	sa.message.nfds = 1;
	sa.fd_specs = &spec;
	ATF_REQUIRE_MSG(ioctl(P[0], MAC_CAPABILITY_SENDMSG_V2, &sa) == 0,
	    "SENDMSG_V2: %s", strerror(errno));

	got = -1;
	memset(&ra, 0, sizeof(ra));
	ra.v3.message.payload = &c;
	ra.v3.message.payload_len = 1;
	ra.v3.message.fds = &got;
	ra.v3.message.nfds = 1;
	ra.fd_info = &info;
	ATF_REQUIRE_MSG(ioctl(P[1], MAC_CAPABILITY_RECVMSG_V4, &ra) == 0,
	    "RECVMSG_V4: %s", strerror(errno));
	ATF_REQUIRE_EQ(1u, ra.v3.message.nfds);
	ATF_CHECK_EQ(MAC_CAPABILITY_FD_TYPE_SOCKET, info.type);
	/* An expectation of any type asks for CAP_READ alone. */
	ATF_CHECK_EQ_MSG(MAC_CAPABILITY_FD_RIGHT_READ |
	    MAC_CAPABILITY_FD_RIGHTS_EXACT, info.rights, "rights %#x",
	    info.rights);

	/* The copy reads and cannot write. */
	ATF_REQUIRE(cap_rights_get(got, &rights) == 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_READ));
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK_ERRNO(ENOTCAPABLE, write(got, "x", 1) == -1);
	ATF_REQUIRE(write(sv[1], "y", 1) == 1);
	ATF_CHECK(read(got, &c, 1) == 1 && c == 'y');

	/* The sender's descriptor is unchanged. */
	ATF_REQUIRE(cap_rights_get(sv[0], &rights) == 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK_EQ(1, write(sv[0], "z", 1));
	ATF_CHECK(read(sv[1], &c, 1) == 1 && c == 'z');
	close(got);
	close(sv[0]);
	close(sv[1]);
	close(P[0]);
	close(P[1]);
}

/*
 * R5.  SEND_F_MOVE closes the sender's descriptors only once the message
 * is accepted: refused (an unmet expectation, a full queue), they stay.
 */
static int
send_move(int fd, int movefd, uint32_t type)
{
	struct mac_capability_sendmsg_v2_args sa;
	struct mac_capability_fd_spec spec;

	memset(&spec, 0, sizeof(spec));
	spec.type = type;
	memset(&sa, 0, sizeof(sa));
	sa.message.payload = "move";
	sa.message.payload_len = 4;
	sa.message.fds = &movefd;
	sa.message.nfds = 1;
	sa.message.flags = MAC_CAPABILITY_SEND_F_MOVE;
	sa.fd_specs = &spec;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG_V2, &sa));
}

ATF_TC(r5_move_closes_on_acceptance);
ATF_TC_HEAD(r5_move_closes_on_acceptance, tc)
{
	atf_tc_set_md_var(tc, "descr", "R5: SEND_F_MOVE closes the sender's "
	    "descriptor only when the message is accepted");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r5_move_closes_on_acceptance, tc)
{
	int P[2], pfd[2], got, filled;
	uint32_t nfds;
	char buf[8];

	pair(P);
	ATF_REQUIRE(pipe(pfd) == 0);

	/* Refused for its expectation: still open. */
	ATF_CHECK_ERRNO(EFTYPE, send_move(P[0], pfd[1],
	    MAC_CAPABILITY_FD_TYPE_SOCKET) == -1);
	ATF_CHECK(fd_open(pfd[1]));

	/* Refused for a full queue: still open. */
	filled = fill(P[0]);
	ATF_CHECK_ERRNO(EAGAIN, send_move(P[0], pfd[1],
	    MAC_CAPABILITY_FD_TYPE_ANY) == -1);
	ATF_CHECK(fd_open(pfd[1]));
	for (int i = 0; i < filled; i++)
		ATF_REQUIRE(recv_msg(P[1], buf, sizeof(buf), NULL) == 0);
	expect_empty(P[1]);

	/* Accepted: closed, and the peer holds the pipe's write end. */
	ATF_CHECK_EQ_MSG(0, send_move(P[0], pfd[1],
	    MAC_CAPABILITY_FD_TYPE_ANY), "send: %s", strerror(errno));
	ATF_CHECK(!fd_open(pfd[1]));
	got = -1;
	ATF_REQUIRE(recv_fds(P[1], buf, sizeof(buf), NULL, &got, 1, &nfds,
	    NULL, 0) == 0);
	ATF_REQUIRE_EQ(1u, nfds);
	ATF_CHECK_EQ(1, write(got, "m", 1));
	ATF_CHECK(read(pfd[0], buf, 1) == 1 && buf[0] == 'm');
	close(got);
	close(pfd[0]);
	close(P[0]);
	close(P[1]);
}

/*
 * R6.  A receive whose buffers are too small, for the payload or for the
 * descriptors, fails with EMSGSIZE and leaves the message, descriptors
 * included, at the head of the queue for a receive with room.  The
 * required sizes are not checked: the kernel writes them into its copy of
 * the arguments, but ioctl(2) copies the arguments out only on success
 * (sys_generic.c:814), so dev cannot report them.  The native call of S2
 * and S3 reports them, and its form of this case adds that assertion.
 */
ATF_TC(r6_emsgsize_keeps_message);
ATF_TC_HEAD(r6_emsgsize_keeps_message, tc)
{
	atf_tc_set_md_var(tc, "descr", "R6: a too-small receive buffer gives "
	    "EMSGSIZE and keeps the message");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r6_emsgsize_keeps_message, tc)
{
	static const char big[] = "a payload of some length";
	char buf[64];
	int P[2], pfd[2], two[2], got[2];
	uint32_t len, nfds;

	pair(P);
	ATF_REQUIRE(pipe(pfd) == 0);
	two[0] = pfd[0];
	two[1] = pfd[1];
	ATF_REQUIRE(send_fds(P[0], big, sizeof(big), two, 2, 0, 0) == 0);
	ATF_REQUIRE(send_msg(P[0], "next", 4) == 0);

	/* Payload buffer too small. */
	ATF_CHECK_ERRNO(EMSGSIZE, recv_fds(P[1], buf, 4, NULL, got, 2, NULL,
	    NULL, 0) == -1);
	/* Descriptor buffer too small, and none at all. */
	ATF_CHECK_ERRNO(EMSGSIZE, recv_fds(P[1], buf, sizeof(buf), NULL, got,
	    1, NULL, NULL, 0) == -1);
	ATF_CHECK_ERRNO(EMSGSIZE, recv_fds(P[1], buf, sizeof(buf), NULL, NULL,
	    0, NULL, NULL, 0) == -1);

	/* The message is still first, whole. */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE_MSG(recv_fds(P[1], buf, sizeof(buf), &len, got, 2, &nfds,
	    NULL, 0) == 0, "receive: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(big), len);
	ATF_CHECK_STREQ(big, buf);
	ATF_CHECK_EQ(2u, nfds);
	if (nfds == 2) {
		ATF_CHECK_EQ(ino_of(pfd[0]), ino_of(got[0]));
		close(got[0]);
		close(got[1]);
	}
	expect_next(P[1], "next");
	close(pfd[0]);
	close(pfd[1]);
	close(P[0]);
	close(P[1]);
}

/*
 * R7.  CHANNEL_CALL hands the caller the reply carrying its token; events
 * and other replies that arrive meanwhile stay queued, in order, for
 * RECVMSG.  The peer is a child that answers the request with an event, an
 * unrelated reply and then the reply.
 */
#define	R7_TOKEN	0x7777
#define	R7_OTHER	0x9999

ATF_TC(r7_call_reply_to_caller);
ATF_TC_HEAD(r7_call_reply_to_caller, tc)
{
	atf_tc_set_md_var(tc, "descr", "R7: a call's reply goes to the "
	    "caller; events and other replies stay queued");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r7_call_reply_to_caller, tc)
{
	struct mac_capability_channel_call_args ca;
	char reply[16], buf[16];
	uint64_t token;
	uint32_t len;
	int P[2];
	pid_t child;

	pair(P);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(P[0]);
		if (recv_fds(P[1], buf, sizeof(buf), &len, NULL, 0, NULL,
		    &token, MAC_CAPABILITY_RECV_F_WAIT) != 0 ||
		    token != R7_TOKEN || len != 7 || memcmp(buf, "request", 7))
			_exit(1);
		if (send_fds(P[1], "event", 5, NULL, 0, 0, 0) != 0 ||
		    send_fds(P[1], "other", 5, NULL, 0, R7_OTHER, 0) != 0 ||
		    send_fds(P[1], "answer", 6, NULL, 0, R7_TOKEN, 0) != 0)
			_exit(2);
		_exit(0);
	}
	close(P[1]);
	memset(&ca, 0, sizeof(ca));
	ca.request.message.payload = "request";
	ca.request.message.payload_len = 7;
	ca.request.message.reply_token = R7_TOKEN;
	ca.reply.v3.message.payload = reply;
	ca.reply.v3.message.payload_len = sizeof(reply);
	ca.timeout_ms = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	memset(reply, 0, sizeof(reply));
	ATF_REQUIRE_MSG(ioctl(P[0], MAC_CAPABILITY_CHANNEL_CALL, &ca) == 0,
	    "CHANNEL_CALL: %s", strerror(errno));
	ATF_CHECK_EQ(6u, ca.reply.v3.message.payload_len);
	ATF_CHECK_STREQ("answer", reply);
	ATF_CHECK_EQ((uint64_t)R7_TOKEN, ca.reply.v3.message.reply_token);
	wait_child(child, "peer");

	/* What came before the reply is still queued, in order. */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv_nb(P[0], buf, sizeof(buf), &len, &token) == 0);
	ATF_CHECK_STREQ("event", buf);
	ATF_CHECK_EQ(0u, token);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv_nb(P[0], buf, sizeof(buf), &len, &token) == 0);
	ATF_CHECK_STREQ("other", buf);
	ATF_CHECK_EQ((uint64_t)R7_OTHER, token);
	/* Then the peer's death: nothing else, no second copy of the reply. */
	ATF_CHECK_ERRNO(ECONNRESET,
	    recv_nb(P[0], buf, sizeof(buf), &len, &token) == -1);
	close(P[0]);
}

/*
 * R8.  A receive with an absolute deadline (RECV_F_DEADLINE) that a signal
 * with SA_RESTART interrupts sleeps again, after the restart, until the
 * same deadline: both sleeps carry the same absolute timeout, the one the
 * deadline names.  The deadline lies an hour ahead and is never reached; a
 * message the helper sends after the restarted sleep ends the receive.
 */
ATF_TC(r8_deadline_kept_across_restart);
ATF_TC_HEAD(r8_deadline_kept_across_restart, tc)
{
	atf_tc_set_md_var(tc, "descr", "R8: an absolute receive deadline is "
	    "kept across an SA_RESTART restart");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r8_deadline_kept_across_restart, tc)
{
	struct mac_capability_recvmsg_args ra;
	struct timespec ts;
	struct helper h;
	struct sleep_watch watch;
	pthread_t thread;
	uint64_t deadline;
	int64_t want;
	char buf[16];
	int P[2], r;

	pair(P);
	catch_sigusr1(SA_RESTART);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	helper_start(&h, &thread, &watch, ACT_SIGNAL_RESLEEP_SEND, 'R', P[0]);
	deadline = mono_ns() + 3600ULL * 1000000000;
	ts.tv_sec = deadline / 1000000000;
	ts.tv_nsec = deadline % 1000000000;
	want = tstosbt_sat(ts);
	memset(&ra, 0, sizeof(ra));
	memset(buf, 0, sizeof(buf));
	ra.payload = buf;
	ra.payload_len = sizeof(buf) - 1;
	ra.flags = MAC_CAPABILITY_RECV_F_WAIT | MAC_CAPABILITY_RECV_F_DEADLINE;
	ra._reserved[0] = (uint32_t)deadline;
	ra._reserved[1] = (uint32_t)(deadline >> 32);
	r = ioctl(P[1], MAC_CAPABILITY_RECVMSG, &ra);
	ATF_CHECK_MSG(r == 0, "receive: %s", strerror(errno));
	sleep_watch_end(&watch);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	sleep_watch_stop(&watch);
	ATF_CHECK_STREQ("wake", buf);
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	ATF_REQUIRE_EQ_MSG(2, h.nsleeps, "saw %d sleeps", h.nsleeps);
	ATF_CHECK_MSG(h.timo[0] == want, "first sleep until %jd, deadline %jd",
	    (intmax_t)h.timo[0], (intmax_t)want);
	ATF_CHECK_MSG(h.timo[1] == h.timo[0],
	    "restarted sleep until %jd, first until %jd", (intmax_t)h.timo[1],
	    (intmax_t)h.timo[0]);
	close(P[0]);
	close(P[1]);
}

/*
 * R9.  A signal whose handler has no SA_RESTART ends a channel wait with
 * EINTR and consumes nothing: a waiting receive takes no message (the next
 * one sent is received whole), and a send waiting for room sends nothing
 * and neither moves nor spends the one-shot descriptor it carries.
 */
ATF_TC(r9_eintr_consumes_nothing);
ATF_TC_HEAD(r9_eintr_consumes_nothing, tc)
{
	atf_tc_set_md_var(tc, "descr", "R9: a handler without SA_RESTART "
	    "ends a receive or send wait with EINTR, nothing consumed");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r9_eintr_consumes_nothing, tc)
{
	struct mac_capability_sendmsg_v2_args sa;
	struct helper h;
	struct sleep_watch watch;
	pthread_t thread;
	char buf[16];
	int P[2], pfd[2], got, filled;
	uint32_t nfds;

	pair(P);
	ATF_REQUIRE(pipe(pfd) == 0);
	ATF_REQUIRE(xfer_set(pfd[1], CAP_XFER_ONCE) == 0);
	catch_sigusr1(0);

	/* A waiting receive. */
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	helper_start(&h, &thread, &watch, ACT_SIGNAL, 'R', -1);
	ATF_CHECK_ERRNO(EINTR, recv_fds(P[1], buf, sizeof(buf), NULL, NULL, 0,
	    NULL, NULL, MAC_CAPABILITY_RECV_F_WAIT) == -1);
	sleep_watch_end(&watch);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	sleep_watch_stop(&watch);
	ATF_CHECK(h.done);
	ATF_REQUIRE(send_msg(P[0], "after", 5) == 0);
	expect_next(P[1], "after");

	/* A send waiting for room, moving a one-shot descriptor. */
	filled = fill(P[0]);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	helper_start(&h, &thread, &watch, ACT_SIGNAL, 'S', -1);
	memset(&sa, 0, sizeof(sa));
	sa.message.payload = "late";
	sa.message.payload_len = 4;
	sa.message.fds = &pfd[1];
	sa.message.nfds = 1;
	sa.message.flags = MAC_CAPABILITY_SEND_F_WAIT |
	    MAC_CAPABILITY_SEND_F_MOVE;
	ATF_CHECK_ERRNO(EINTR, ioctl(P[0], MAC_CAPABILITY_SENDMSG_V2, &sa) ==
	    -1);
	sleep_watch_end(&watch);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	sleep_watch_stop(&watch);
	ATF_CHECK(h.done);
	ATF_CHECK_EQ(2, atomic_load(&signals_taken));
	ATF_CHECK_MSG(fd_open(pfd[1]), "the moved descriptor was closed");
	/* Only the fillers are queued. */
	for (int i = 0; i < filled; i++)
		expect_next(P[1], "fill");
	expect_empty(P[1]);
	/* The one-shot descriptor still goes, once. */
	sa.message.flags = MAC_CAPABILITY_SEND_F_MOVE;
	ATF_CHECK_EQ_MSG(0, ioctl(P[0], MAC_CAPABILITY_SENDMSG_V2, &sa),
	    "send after EINTR: %s", strerror(errno));
	got = -1;
	ATF_REQUIRE(recv_fds(P[1], buf, sizeof(buf), NULL, &got, 1, &nfds,
	    NULL, 0) == 0);
	ATF_CHECK_EQ(1u, nfds);
	if (nfds == 1)
		close(got);
	close(pfd[0]);
	close(P[0]);
	close(P[1]);
}

/*
 * R10.  Every message is stamped with its sender: credentials (uid, jail)
 * in the trailer and the process (pid, identity) in the V2 stamp.  The
 * sender is a child that enters a jail of its own and changes its uid
 * before it sends; it reports its identity first, as an unjailed process
 * may ask for it.
 */
#define	R10_UID		65534

ATF_TC(r10_stamp_names_sender);
ATF_TC_HEAD(r10_stamp_names_sender, tc)
{
	atf_tc_set_md_var(tc, "descr", "R10: the stamp carries the sender's "
	    "uid, pid, identity and jail");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r10_stamp_names_sender, tc)
{
	struct mac_capability_recvmsg_v2_args ra;
	struct mac_cap_process_info info;
	struct {
		uint64_t identity;
		int32_t	jid;
	} said;
	int P[2];
	pid_t child;

	pair(P);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(P[1]);
		memset(&said, 0, sizeof(said));
		if (cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info) != 0)
			_exit(1);
		said.identity = info.identity;
		said.jid = jail_enter("r10");
		if (said.jid < 0)
			_exit(2);
		if (setgid(R10_UID) != 0 || setuid(R10_UID) != 0)
			_exit(3);
		_exit(send_msg(P[0], &said, sizeof(said)) == 0 ? 0 : 4);
	}
	close(P[0]);
	wait_child(child, "sender");
	memset(&ra, 0, sizeof(ra));
	memset(&said, 0, sizeof(said));
	ra.message.payload = &said;
	ra.message.payload_len = sizeof(said);
	ATF_REQUIRE_MSG(ioctl(P[1], MAC_CAPABILITY_RECVMSG_V2, &ra) == 0,
	    "RECVMSG_V2: %s", strerror(errno));
	ATF_REQUIRE_EQ(sizeof(said), ra.message.payload_len);
	ATF_CHECK_EQ((uint32_t)R10_UID, ra.message.trailer.uid);
	ATF_CHECK(said.jid > 0);
	ATF_CHECK_EQ(said.jid, ra.message.trailer.prison_id);
	ATF_CHECK_EQ(child, ra.process.pid);
	ATF_CHECK(said.identity != 0);
	ATF_CHECK_EQ(said.identity, ra.process.identity);
	close(P[1]);
}

/*
 * R11.  A process in capability mode creates a pair and uses it.
 */
ATF_TC(r11_create_in_capability_mode);
ATF_TC_HEAD(r11_create_in_capability_mode, tc)
{
	atf_tc_set_md_var(tc, "descr", "R11: a pair is created and used in "
	    "capability mode");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(r11_create_in_capability_mode, tc)
{
	pid_t child;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		char buf[8];
		uint32_t len;
		int fds[2];

		if (cap_enter() != 0)
			_exit(1);
		if (mac_capability_channel_create(fds) != 0)
			_exit(2);
		if (send_msg(fds[0], "cap", 3) != 0 ||
		    recv_msg(fds[1], buf, sizeof(buf), &len) != 0 ||
		    len != 3 || memcmp(buf, "cap", 3) != 0)
			_exit(3);
		_exit(0);
	}
	wait_child(child, "capability-mode child");
}

/*
 * R12.  The process slot hands its channel only to a process of the
 * prison it was installed from: GET in a jailed descendant is EPERM, while
 * the unjailed process that installed it gets a descriptor.  The slot is
 * installed in a child, so the case's own slot is untouched.
 */
ATF_TC(r12_get_in_other_prison_eperm);
ATF_TC_HEAD(r12_get_in_other_prison_eperm, tc)
{
	atf_tc_set_md_var(tc, "descr", "R12: GET of the process slot from "
	    "another prison is EPERM");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r12_get_in_other_prison_eperm, tc)
{
	int P[2];
	pid_t child;

	pair(P);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		int fd, status;
		pid_t jailed;

		if (cap_process(MAC_CAP_PROCESS_SET, P[0], 0, NULL) != 0)
			_exit(1);
		fd = cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL);
		if (fd < 0)
			_exit(2);
		close(fd);
		jailed = fork();
		if (jailed < 0)
			_exit(3);
		if (jailed == 0) {
			if (jail_enter("r12") < 0)
				_exit(4);
			if (cap_process(MAC_CAP_PROCESS_GET, -1, 0, NULL) != -1)
				_exit(5);
			_exit(errno == EPERM ? 0 : 6);
		}
		if (waitpid(jailed, &status, 0) != jailed ||
		    !WIFEXITED(status))
			_exit(7);
		_exit(WEXITSTATUS(status) == 0 ? 0 :
		    10 + WEXITSTATUS(status));
	}
	wait_child(child, "slot holder");
	close(P[0]);
	close(P[1]);
}

/*
 * R13.  A process shielded with CP_SF_NOFDRECV refuses descriptors that
 * arrive as SCM_RIGHTS, and still receives the ones that arrive on a
 * channel it holds.
 */
static int
capprotect_shield(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int fd;

	fd = mac_capability_connect("capprotect");
	if (fd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static int
scm_send(int sock, int fd)
{
	union {
		struct cmsghdr	align;
		char		data[CMSG_SPACE(sizeof(int))];
	} control;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char byte = 'u';

	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.data;
	msg.msg_controllen = sizeof(control.data);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	return (sendmsg(sock, &msg, 0) == 1 ? 0 : -1);
}

static int
scm_recv(int sock)
{
	union {
		struct cmsghdr	align;
		char		data[CMSG_SPACE(sizeof(int))];
	} control;
	struct msghdr msg;
	struct iovec iov;
	char byte;

	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.data;
	msg.msg_controllen = sizeof(control.data);
	return (recvmsg(sock, &msg, 0) == -1 ? -1 : 0);
}

ATF_TC(r13_nofdrecv_admits_channel_receipt);
ATF_TC_HEAD(r13_nofdrecv_admits_channel_receipt, tc)
{
	atf_tc_set_md_var(tc, "descr", "R13: CP_SF_NOFDRECV refuses "
	    "SCM_RIGHTS and admits a descriptor received on a channel");
	atf_tc_set_md_var(tc, "require.kmods",
	    CHANNEL_KMODS " mac_capability_capprotect");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r13_nofdrecv_admits_channel_receipt, tc)
{
	int P[2], sv[2], pfd[2], got, shield;
	uint32_t nfds;
	char c;

	pair(P);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	ATF_REQUIRE(pipe(pfd) == 0);
	shield = capprotect_shield(CP_SF_NOFDRECV);
	ATF_REQUIRE_MSG(shield >= 0, "shield: %s", strerror(errno));

	ATF_REQUIRE(scm_send(sv[0], pfd[0]) == 0);
	ATF_CHECK_ERRNO(EACCES, scm_recv(sv[1]) == -1);

	ATF_REQUIRE(send_fds(P[0], "c", 1, &pfd[0], 1, 0, 0) == 0);
	got = -1;
	ATF_REQUIRE_MSG(recv_fds(P[1], &c, 1, NULL, &got, 1, &nfds, NULL,
	    0) == 0, "channel receipt: %s", strerror(errno));
	ATF_REQUIRE_EQ(1u, nfds);
	ATF_REQUIRE(write(pfd[1], "x", 1) == 1);
	ATF_CHECK(read(got, &c, 1) == 1 && c == 'x');

	/* And SCM_RIGHTS is still refused after it. */
	ATF_REQUIRE(scm_send(sv[0], pfd[0]) == 0);
	ATF_CHECK_ERRNO(EACCES, scm_recv(sv[1]) == -1);
	close(got);
	close(shield);
	close(pfd[0]);
	close(pfd[1]);
	close(sv[0]);
	close(sv[1]);
	close(P[0]);
	close(P[1]);
}

/*
 * R14.  Once the peer has closed and its messages are read, a receive
 * fails with ECONNRESET, whether it was already waiting when the peer
 * closed or comes after.
 */
ATF_TC(r14_recv_after_peer_close_econnreset);
ATF_TC_HEAD(r14_recv_after_peer_close_econnreset, tc)
{
	atf_tc_set_md_var(tc, "descr", "R14: a receive after the peer closed "
	    "and the queue drained fails with ECONNRESET");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r14_recv_after_peer_close_econnreset, tc)
{
	struct helper h;
	struct sleep_watch watch;
	pthread_t thread;
	char buf[16];
	int P[2];

	pair(P);
	ATF_REQUIRE(send_msg(P[0], "last", 4) == 0);
	expect_next(P[1], "last");
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	/* The peer closes while the receive waits. */
	helper_start(&h, &thread, &watch, ACT_CLOSE, 'R', P[0]);
	ATF_CHECK_ERRNO(ECONNRESET, recv_fds(P[1], buf, sizeof(buf), NULL,
	    NULL, 0, NULL, NULL, MAC_CAPABILITY_RECV_F_WAIT) == -1);
	sleep_watch_end(&watch);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	sleep_watch_stop(&watch);
	ATF_CHECK(h.done);
	/* And every receive after it. */
	ATF_CHECK_ERRNO(ECONNRESET, recv_msg(P[1], buf, sizeof(buf), NULL) ==
	    -1);
	ATF_CHECK_ERRNO(ECONNRESET, recv_nb(P[1], buf, sizeof(buf), NULL,
	    NULL) == -1);
	close(P[1]);
}

/*
 * R15.  A CHANNEL_CALL interrupted by a signal with SA_RESTART is not
 * resent: dev ends the call with EINTR (it maps ERESTART to EINTR) and the
 * peer has received the request exactly once.  S3 restates the case for
 * the native call, which resumes the wait instead.
 */
ATF_TC(r15_call_not_resent);
ATF_TC_HEAD(r15_call_not_resent, tc)
{
	atf_tc_set_md_var(tc, "descr", "R15: a call interrupted by an "
	    "SA_RESTART signal is not resent");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(r15_call_not_resent, tc)
{
	struct mac_capability_channel_call_args ca;
	struct helper h;
	struct sleep_watch watch;
	pthread_t thread;
	char reply[16], buf[16];
	uint64_t token;
	int P[2], r;

	pair(P);
	catch_sigusr1(SA_RESTART);
	sleep_watch_start(&watch, SLEEP_WATCH_ANY_LEN);
	helper_start(&h, &thread, &watch, ACT_SIGNAL, 'C', -1);
	memset(&ca, 0, sizeof(ca));
	ca.request.message.payload = "request";
	ca.request.message.payload_len = 7;
	ca.request.message.reply_token = 0x15;
	ca.reply.v3.message.payload = reply;
	ca.reply.v3.message.payload_len = sizeof(reply);
	ca.timeout_ms = MAC_CAPABILITY_RECV_WAIT_FOREVER;
	r = ioctl(P[0], MAC_CAPABILITY_CHANNEL_CALL, &ca);
	ATF_CHECK_EQ(-1, r);
	ATF_CHECK_EQ_MSG(EINTR, errno, "errno %d (%s)", errno,
	    strerror(errno));
	sleep_watch_end(&watch);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	sleep_watch_stop(&watch);
	ATF_CHECK(h.done);
	ATF_CHECK_EQ(1, atomic_load(&signals_taken));
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(recv_nb(P[1], buf, sizeof(buf), NULL, &token) == 0);
	ATF_CHECK_STREQ("request", buf);
	ATF_CHECK_EQ(0x15u, token);
	expect_empty(P[1]);
	close(P[0]);
	close(P[1]);
}

/* ---------------------------------------------------------------------
 * Fails-before pins: dev's defects, each marked until its slice.
 * --------------------------------------------------------------------- */

/* P0.1 (marker removed in S2): poll(2) reports a queued message. */
ATF_TC(p0_1_poll_reports_queued_message);
ATF_TC_HEAD(p0_1_poll_reports_queued_message, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.1: poll(POLLIN) with a queued "
	    "message returns POLLIN");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(p0_1_poll_reports_queued_message, tc)
{
	struct pollfd pfd;
	int P[2];

	pair(P);
	ATF_REQUIRE(send_msg(P[0], "queued", 6) == 0);
	pfd.fd = P[1];
	pfd.events = POLLIN;
	pfd.revents = 0;
	atf_tc_expect_fail("dev: poll(2) on a channel answers POLLNVAL "
	    "(mac_capability_dev.c mac_capability_instance_poll)");
	ATF_CHECK_EQ(1, poll(&pfd, 1, 0));
	ATF_CHECK_EQ_MSG(POLLIN, pfd.revents, "revents %#x", pfd.revents);
	close(P[0]);
	close(P[1]);
}

/* P0.2 (marker removed in S3): a send after the peer closed. */
ATF_TC(p0_2_send_after_peer_close_econnreset);
ATF_TC_HEAD(p0_2_send_after_peer_close_econnreset, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.2: a send after the peer closed "
	    "fails with ECONNRESET");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
}
ATF_TC_BODY(p0_2_send_after_peer_close_econnreset, tc)
{
	int P[2], r;

	pair(P);
	ATF_REQUIRE(close(P[0]) == 0);
	r = send_msg(P[1], "x", 1);
	ATF_REQUIRE_EQ(-1, r);
	atf_tc_expect_fail("dev: a send after the peer closed fails with "
	    "EPIPE (mac_capability_dev.c:568-572)");
	ATF_CHECK_EQ_MSG(ECONNRESET, errno, "errno %d (%s)", errno,
	    strerror(errno));
	close(P[1]);
}

/*
 * P0.4 (marker removed in S2).  The last close of an end whose queue
 * carries the last reference to a pipe's write end frees it before
 * close(2) returns: the reaper is not involved (no
 * mac_capability:::reap-defer from this process) and the pipe's reader
 * sees POLLHUP at once.
 */
static const char reap_script[] =
    "BEGIN { printf(\"READY\\n\"); }\n"
    "mac_capability:::reap-defer /pid == $1/ { n++; }\n"
    "syscall::getpgid:entry /pid == $1 && arg0 == $2/ {\n"
    "	printf(\"COUNT %d\\n\", n); exit(0); }\n";

ATF_TC(p0_4_last_close_frees_in_closer);
ATF_TC_HEAD(p0_4_last_close_frees_in_closer, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.4: the last close of an end "
	    "frees the descriptors its queue carries before close returns");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p0_4_last_close_frees_in_closer, tc)
{
	struct kevent ev;
	struct pollfd pfd;
	struct sleep_watch dt;
	char mark[32];
	int P[2], pp[2], kq;
	long n;

	pair(P);
	ATF_REQUIRE(pipe(pp) == 0);
	ATF_REQUIRE(send_fds(P[0], "carry", 5, &pp[1], 1, 0, 0) == 0);
	ATF_REQUIRE(close(pp[1]) == 0);
	/* The message is in P[1]'s queue (not still on its way). */
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&ev, P[1], EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &ev, 1, &ev, 1, NULL) == 1);
	ATF_REQUIRE(ev.data == 1);
	close(kq);

	snprintf(mark, sizeof(mark), "%d", SLEEP_WATCH_MARK);
	sleep_watch_dtrace(&dt, reap_script, mark, NULL);
	ATF_REQUIRE(close(P[1]) == 0);
	pfd.fd = pp[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE(poll(&pfd, 1, 0) >= 0);
	n = sleep_watch_count(&dt);
	atf_tc_expect_fail("dev: the closer hands the message to the "
	    "mac_capability reaper (reap-defer fires; deterministic)");
	ATF_CHECK_EQ_MSG(0, n, "reap-defer fired %ld times", n);
	ATF_CHECK_MSG((pfd.revents & POLLHUP) != 0,
	    "the pipe's write end was still open when close returned "
	    "(revents %#x)", pfd.revents);
	close(pp[0]);
	close(P[0]);
}

/*
 * P0.5 (marker removed in S2, where the case is vacuous: new ends have no
 * dispatch task).  With direct delivery off, so that every message goes
 * through the channel's dispatch task, and no sender asleep, forwarding
 * 10 000 messages makes no wakeup() call for send room.  dev makes one per
 * message, whether or not a sender sleeps (mac_capability_kern.c:748-749).
 *
 * What is counted is that call alone: the wakeup() calls the dispatch task
 * makes after the handler has returned (mac_capability:::dispatch-done)
 * and before it takes the next message or returns, for messages of this
 * case's sending end (the probe names the sender's badge).  The handler's
 * own forwarding wakes the receiver, which may rightly be asleep, and is
 * not counted; nor is the wakeup on the instance itself (its address, the
 * task's argument) with which the task drops its reference as it returns,
 * which wakes a close waiting for the references to go.  A last message, received before the count is read, makes
 * sure the dispatch task has finished with every counted one: the task
 * takes one message after another, so the last one is forwarded only after
 * the one before it has been dealt with.
 */
#define	P05_COUNT	10000
#define	P05_BATCH	100
#define	P05_SAVED	"direct_delivery.saved"

static const char dispatch_script[] =
    "BEGIN { printf(\"READY\\n\"); }\n"
    "fbt:kernel:mac_capability_dispatch_task:entry {\n"
    "	self->d = 1; self->s = arg0; }\n"
    "fbt:kernel:mac_capability_dispatch_task:return {\n"
    "	self->d = 0; self->tail = 0; }\n"
    "mac_capability:::dispatch /self->d/ { self->tail = 0; }\n"
    "mac_capability:::dispatch-done /self->d && arg1 == $3/ {\n"
    "	self->tail = 1; }\n"
    "fbt:kernel:wakeup:entry /self->tail && arg0 != self->s/ { n++; }\n"
    "syscall::getpgid:entry /pid == $1 && arg0 == $2/ {\n"
    "	printf(\"COUNT %d\\n\", n); exit(0); }\n";

ATF_TC_WITH_CLEANUP(p0_5_dispatch_no_wakeup_without_sleeper);
ATF_TC_HEAD(p0_5_dispatch_no_wakeup_without_sleeper, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.5: the dispatch task makes no "
	    "send-room wakeup() when no sender sleeps");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p0_5_dispatch_no_wakeup_without_sleeper, tc)
{
	char mark[32], badge[32], buf[8];
	struct sleep_watch dt;
	FILE *fp;
	int P[2], i, j, saved;
	long n;

	pair(P);
	snprintf(mark, sizeof(mark), "%d", SLEEP_WATCH_MARK);
	snprintf(badge, sizeof(badge), "%ju", (uintmax_t)badge_of(P[0]));
	saved = set_direct(0);
	ATF_REQUIRE_MSG(saved >= 0, "kern.mac_capability.direct_delivery: %s",
	    strerror(errno));
	/* For the cleanup, which restores it if the body does not. */
	fp = fopen(P05_SAVED, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "%d\n", saved);
	ATF_REQUIRE(fclose(fp) == 0);
	sleep_watch_dtrace(&dt, dispatch_script, mark, badge);
	/* Batches well under the queue limits: no send ever waits. */
	for (i = 0; i < P05_COUNT; i += P05_BATCH) {
		for (j = 0; j < P05_BATCH; j++)
			ATF_REQUIRE_MSG(send_msg(P[0], "m", 1) == 0,
			    "send %d: %s", i + j, strerror(errno));
		for (j = 0; j < P05_BATCH; j++)
			ATF_REQUIRE_MSG(recv_fds(P[1], buf, sizeof(buf), NULL,
			    NULL, 0, NULL, NULL, MAC_CAPABILITY_RECV_F_WAIT) ==
			    0, "receive %d: %s", i + j, strerror(errno));
	}
	ATF_REQUIRE(send_msg(P[0], "last", 4) == 0);
	expect_next(P[1], "last");
	n = sleep_watch_count(&dt);
	ATF_REQUIRE(set_direct(saved) == 0);
	ATF_REQUIRE(unlink(P05_SAVED) == 0);
	close(P[0]);
	close(P[1]);
	/* Either none (the fix) or one for each message (dev's defect). */
	ATF_REQUIRE_MSG(n == 0 || n >= P05_COUNT, "%ld send-room wakeup() "
	    "calls for %d messages: neither none nor one per message", n,
	    P05_COUNT);
	atf_tc_expect_fail("dev: the dispatch task calls wakeup() for send "
	    "room after every message whether or not anyone sleeps "
	    "(mac_capability_kern.c:748-749)");
	ATF_CHECK_EQ_MSG(0, n, "%ld send-room wakeup() calls for %d messages",
	    n, P05_COUNT);
}
ATF_TC_CLEANUP(p0_5_dispatch_no_wakeup_without_sleeper, tc)
{
	FILE *fp;
	int saved;

	(void)tc;
	/* The body removes the file once it has restored the value. */
	fp = fopen(P05_SAVED, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &saved) == 1)
		(void)sysctlbyname("kern.mac_capability.direct_delivery", NULL,
		    NULL, &saved, sizeof(saved));
	fclose(fp);
}

/*
 * P0.7 (case restated in S1, retired in S6): channel ends referenced only
 * from each other's queues are never freed
 * (2026-11-24-mac-capability-channel-end-cycle-leak.md).  A dtrace
 * consumer started before the closes exits when
 * mac_capability:::instance-finalize fires for B's badge; the case waits,
 * without a limit, for that consumer's exit and for EOF on a pipe whose
 * write end rides with B.  On dev neither comes: the case runs into its
 * timeout, which is expected.
 */
static const char finalize_script[] =
    "BEGIN { printf(\"READY\\n\"); }\n"
    "mac_capability:::instance-finalize /arg1 == $2/ { exit(0); }\n";

static void
cycle_wait_freed(int fd_a, int fd_b, int pipe_read, uint64_t badge)
{
	struct kevent ev[2];
	struct sleep_watch dt;
	char arg[32];
	bool exited, eof;
	int kq, n;

	snprintf(arg, sizeof(arg), "%ju", (uintmax_t)badge);
	sleep_watch_dtrace(&dt, finalize_script, arg, NULL);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&ev[0], dt.pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
	EV_SET(&ev[1], pipe_read, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, ev, 2, NULL, 0, NULL) == 0);
	ATF_REQUIRE(close(fd_a) == 0);
	ATF_REQUIRE(close(fd_b) == 0);
	atf_tc_expect_timeout("dev: channel end cycle leak");
	exited = eof = false;
	while (!exited || !eof) {
		n = kevent(kq, NULL, 0, ev, 1, NULL);
		if (n == -1 && errno == EINTR)
			continue;
		ATF_REQUIRE(n == 1);
		if (ev[0].filter == EVFILT_PROC)
			exited = true;
		else if ((ev[0].flags & EV_EOF) != 0)
			eof = true;
		else {
			/* Readable without EOF: nothing was written. */
			ATF_REQUIRE_MSG(false, "pipe readable without EOF");
		}
	}
	close(kq);
	fclose(dt.out);
	dt.out = NULL;
	(void)waitpid(dt.pid, NULL, 0);
}

ATF_TC(p0_7_cycle_two_messages_freed);
ATF_TC_HEAD(p0_7_cycle_two_messages_freed, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.7: two ends each carried only in "
	    "the other's queue are freed once both descriptors close");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	/*
	 * The only bound on the case, which on dev always runs into it; on
	 * a kernel without the leak the wait ends on the finalize and EOF
	 * events.  Below the 300 s default to limit what a dev run costs.
	 */
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(p0_7_cycle_two_messages_freed, tc)
{
	int P[2], pp[2], fds[2];
	uint64_t badge_b;

	pair(P);
	ATF_REQUIRE(pipe(pp) == 0);
	badge_b = badge_of(P[1]);
	/* A over A: it waits in B's queue. */
	ATF_REQUIRE_MSG(send_fds(P[0], "A", 1, &P[0], 1, 0, 0) == 0,
	    "send A on A: %s", strerror(errno));
	/* B over B, with the pipe's write end: it waits in A's queue. */
	fds[0] = P[1];
	fds[1] = pp[1];
	ATF_REQUIRE_MSG(send_fds(P[1], "B", 1, fds, 2, 0, 0) == 0,
	    "send B on B: %s", strerror(errno));
	ATF_REQUIRE(close(pp[1]) == 0);
	cycle_wait_freed(P[0], P[1], pp[0], badge_b);
	close(pp[0]);
}

/*
 * The record's first shape, as a second case: B sent on A waits in B's
 * own queue; closing B, then A (which revokes B), leaves B referenced
 * only from its own queue.
 */
ATF_TC(p0_7_own_peer_in_own_queue_freed);
ATF_TC_HEAD(p0_7_own_peer_in_own_queue_freed, tc)
{
	atf_tc_set_md_var(tc, "descr", "P0.7: an end carried only in its own "
	    "queue is freed once both descriptors close");
	atf_tc_set_md_var(tc, "require.kmods", CHANNEL_KMODS);
	atf_tc_set_md_var(tc, "require.progs", SLEEP_WATCH_PROG);
	atf_tc_set_md_var(tc, "require.user", "root");
	/*
	 * The only bound on the case, which on dev always runs into it; on
	 * a kernel without the leak the wait ends on the finalize and EOF
	 * events.  Below the 300 s default to limit what a dev run costs.
	 */
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(p0_7_own_peer_in_own_queue_freed, tc)
{
	int P[2], pp[2], fds[2];
	uint64_t badge_b;

	pair(P);
	ATF_REQUIRE(pipe(pp) == 0);
	badge_b = badge_of(P[1]);
	/* B over A, with the pipe's write end: it waits in B's own queue. */
	fds[0] = P[1];
	fds[1] = pp[1];
	ATF_REQUIRE_MSG(send_fds(P[0], "B", 1, fds, 2, 0, 0) == 0,
	    "send B on A: %s", strerror(errno));
	ATF_REQUIRE(close(pp[1]) == 0);
	cycle_wait_freed(P[1], P[0], pp[0], badge_b);
	close(pp[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, r1_fifo_with_descriptors);
	ATF_TP_ADD_TC(tp, r2_sent_before_close_readable);
	ATF_TP_ADD_TC(tp, r3_transfer_states);
	ATF_TP_ADD_TC(tp, r4_spec_narrows_copy_only);
	ATF_TP_ADD_TC(tp, r5_move_closes_on_acceptance);
	ATF_TP_ADD_TC(tp, r6_emsgsize_keeps_message);
	ATF_TP_ADD_TC(tp, r7_call_reply_to_caller);
	ATF_TP_ADD_TC(tp, r8_deadline_kept_across_restart);
	ATF_TP_ADD_TC(tp, r9_eintr_consumes_nothing);
	ATF_TP_ADD_TC(tp, r10_stamp_names_sender);
	ATF_TP_ADD_TC(tp, r11_create_in_capability_mode);
	ATF_TP_ADD_TC(tp, r12_get_in_other_prison_eperm);
	ATF_TP_ADD_TC(tp, r13_nofdrecv_admits_channel_receipt);
	ATF_TP_ADD_TC(tp, r14_recv_after_peer_close_econnreset);
	ATF_TP_ADD_TC(tp, r15_call_not_resent);
	ATF_TP_ADD_TC(tp, p0_1_poll_reports_queued_message);
	ATF_TP_ADD_TC(tp, p0_2_send_after_peer_close_econnreset);
	ATF_TP_ADD_TC(tp, p0_4_last_close_frees_in_closer);
	ATF_TP_ADD_TC(tp, p0_5_dispatch_no_wakeup_without_sleeper);
	ATF_TP_ADD_TC(tp, p0_7_cycle_two_messages_freed);
	ATF_TP_ADD_TC(tp, p0_7_own_peer_in_own_queue_freed);
	return (atf_no_error());
}
