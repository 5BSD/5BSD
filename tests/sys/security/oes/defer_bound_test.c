/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The deferred-delivery queue's byte bound, its per-uid share and the
 * events-lost marker (oes(4) "Deferred delivery", "Lost events").
 *
 * The test kernel's hold point debug.mac_capability.test_issuer_oes_defer_hold
 * parks the delivery task before it takes an event off the queue, so the
 * queue fills one write at a time and nothing is timed: every count below is
 * exact.  Only the test's events reach the queue: the producers run in a
 * jail and the only client is scoped to it ("While every open client is
 * jail-scoped, events of subjects that none of them covers are discarded
 * before any memory is allocated").  Each producer is told to write over a
 * socket, which makes no pipe event, and writes one byte to its own pipe,
 * which makes one OES_EVENT_NOTIFY_PIPE_WRITE.
 *
 * Admission (oes_mac.c oes_defer_admits()): an entry of charge c from a uid
 * holding u bytes, with T bytes queued and bound L, is queued only if
 * u + c <= L - (T + c).  With one producer's entries all of one charge c, a
 * uid alone therefore stops at exactly floor(L / (2c)) entries.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define	DEFER_HOLD	"debug.mac_capability.test_issuer_oes_defer_hold"
#define	MAX_BYTES	"security.oes.defer_max_bytes"
#define	JAIL_NAME	"oes_defer_bound"
#define	SAVED		"defer_max_bytes.saved"
/* Producer uids: unprivileged, distinct from each other and from root. */
#define	UID_A		65530
#define	UID_B		65531

static u_long
sysctl_ul(const char *name)
{
	u_long v;
	u_int u;
	size_t len;

	v = 0;
	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0,
	    "%s: %s", name, strerror(errno));
	if (len == sizeof(u)) {
		memcpy(&u, &v, sizeof(u));
		v = u;
	}
	return (v);
}

static void
set_max_bytes(u_long v)
{

	ATF_REQUIRE_MSG(sysctlbyname(MAX_BYTES, NULL, NULL, &v,
	    sizeof(v)) == 0, "%s=%lu: %s", MAX_BYTES, v, strerror(errno));
}

static int
defer_hold(int v)
{

	return (sysctlbyname(DEFER_HOLD, NULL, NULL, &v, sizeof(v)));
}

static void
require_test_kernel(void)
{
	int v;
	size_t len;

	len = sizeof(v);
	if (sysctlbyname(DEFER_HOLD, &v, &len, NULL, 0) != 0)
		atf_tc_skip(
		    "DEFERRED_STACK_TIER: no %s: %s (test kernels only)",
		    DEFER_HOLD, strerror(errno));
}

/* Keep the bound the system had, for the cleanup. */
static void
save_max_bytes(void)
{
	FILE *f;

	f = fopen(SAVED, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%lu\n", sysctl_ul(MAX_BYTES));
	ATF_REQUIRE(fclose(f) == 0);
}

static void
cleanup_common(void)
{
	FILE *f;
	u_long v;
	int jid;

	(void)defer_hold(0);
	f = fopen(SAVED, "r");
	if (f != NULL) {
		if (fscanf(f, "%lu", &v) == 1)
			(void)sysctlbyname(MAX_BYTES, NULL, NULL, &v,
			    sizeof(v));
		fclose(f);
	}
	jid = jail_getid(JAIL_NAME);
	if (jid > 0)
		(void)jail_remove(jid);
}

static uint64_t
nosleep_drops(int fd)
{
	struct oes_stats st;

	memset(&st, 0, sizeof(st));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_STATS, &st) == 0,
	    "OES_IOC_GET_STATS: %s", strerror(errno));
	return (st.es_nosleep_drops);
}

/* A jailed producer of pipe-write events, run as uid. */
struct producer {
	pid_t	pid;
	int	sock;
};

static void
producer_start(struct producer *pr, int jid, uid_t uid)
{
	int sv[2], p[2];
	char c;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pr->pid = fork();
	ATF_REQUIRE(pr->pid >= 0);
	if (pr->pid == 0) {
		/*
		 * Keep only this socket: an inherited end of another
		 * producer's socket would keep that producer from seeing
		 * end of file when the test closes it.
		 */
		if (dup2(sv[1], STDERR_FILENO + 1) < 0)
			_exit(3);
		closefrom(STDERR_FILENO + 2);
		sv[1] = STDERR_FILENO + 1;
		if (jail_attach(jid) != 0 || setgid(uid) != 0 ||
		    setuid(uid) != 0 || pipe(p) != 0)
			_exit(1);
		/* 'w': one write, answered with its result; EOF: exit. */
		while (read(sv[1], &c, 1) == 1) {
			c = write(p[1], "x", 1) == 1 ? 'y' : 'n';
			if (write(sv[1], &c, 1) != 1)
				_exit(2);
		}
		_exit(0);
	}
	close(sv[1]);
	pr->sock = sv[0];
}

/* One pipe write by the producer; it must succeed whatever OES does. */
static void
producer_write(struct producer *pr)
{
	char c;

	c = 'w';
	ATF_REQUIRE(write(pr->sock, &c, 1) == 1);
	ATF_REQUIRE(read(pr->sock, &c, 1) == 1);
	ATF_REQUIRE_MSG(c == 'y', "producer %d: the pipe write failed",
	    (int)pr->pid);
}

static void
producer_stop(struct producer *pr)
{
	int status;

	close(pr->sock);
	ATF_REQUIRE(waitpid(pr->pid, &status, 0) == pr->pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "producer status %#x", status);
}

static int
make_jail(void)
{
	int jid;

	jid = jail_setv(JAIL_CREATE, "name", JAIL_NAME, "path", "/",
	    "persist", NULL, NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	return (jid);
}

/*
 * The only client: NOTIFY_PIPE_WRITE of the jail's processes, with a queue
 * that holds whatever a bound of limit bytes can queue (each entry holds
 * at least security.oes.defer_entry_min), so it loses nothing itself.
 */
static int
open_jail_client(int jid, u_long limit)
{
	struct oes_jail_scope_args args;
	struct oes_mode_args mode;
	oes_event_type_t ev = OES_EVENT_NOTIFY_PIPE_WRITE;
	int fd;

	if (sysctl_ul("security.oes.clients") != 0)
		atf_tc_skip("another OES client is open: its events would share "
		    "the deferred queue and the counts would not be exact");
	fd = test_open_oes();
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));
	memset(&args, 0, sizeof(args));
	args.ejs_jid = jid;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SET_JAIL_SCOPE, &args) == 0,
	    "OES_IOC_SET_JAIL_SCOPE: %s", strerror(errno));
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	mode.ema_queue_size = (uint32_t)MIN(UINT32_MAX,
	    limit / sysctl_ul("security.oes.defer_entry_min") + 1);
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_MODE, &mode) == 0);
	ATF_REQUIRE(test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0);
	if (sysctl_ul("security.oes.clients") != 1)
		atf_tc_skip("another OES client opened with this one");
	return (fd);
}

/*
 * Park the delivery task with one event of pr queued; return that
 * event's charge.  The task parks only at the top of a round, after the
 * previous round has returned every charge, so what is queued now is the
 * one event.
 */
static u_long
park_with_one(struct producer *pr)
{
	u_long c;

	ATF_REQUIRE_MSG(defer_hold(1) == 0, "%s: %s", DEFER_HOLD,
	    strerror(errno));
	producer_write(pr);
	ATF_REQUIRE_MSG(defer_hold(3) == 0, "%s=3: %s", DEFER_HOLD,
	    strerror(errno));
	ATF_REQUIRE_EQ(sysctl_ul("security.oes.defer_depth"), 1);
	c = sysctl_ul("security.oes.defer_bytes");
	ATF_REQUIRE(c > 0);
	return (c);
}

/*
 * Write until a write adds no entry.  Every write before it must add
 * exactly one entry of charge c; return the depth at the stop.
 */
static u_long
fill(struct producer *pr, int fd, u_long c, u_long expect)
{
	u_long d, b;
	uint64_t drops;

	for (;;) {
		d = sysctl_ul("security.oes.defer_depth");
		b = sysctl_ul("security.oes.defer_bytes");
		ATF_REQUIRE_EQ_MSG(b, d * c, "queued %lu bytes in %lu "
		    "entries of %lu", b, d, c);
		ATF_REQUIRE_MSG(d <= expect, "queued %lu entries, the share "
		    "allows %lu", d, expect);
		drops = nosleep_drops(fd);
		producer_write(pr);
		if (sysctl_ul("security.oes.defer_depth") == d) {
			ATF_REQUIRE_EQ(nosleep_drops(fd), drops + 1);
			return (d);
		}
		ATF_REQUIRE_EQ(nosleep_drops(fd), drops);
	}
}

/* Next message from fd, waiting for it; reads may return several. */
static struct test_event_reader reader;

static void
next_msg(int fd, oes_message_t *msg)
{

	ATF_REQUIRE_MSG(test_event_reader_next(&reader, fd, msg, INFTIM) == 0,
	    "read: %s", strerror(errno));
}

/* Nothing more to read. */
static void
require_empty(int fd, oes_message_t *msg)
{

	ATF_REQUIRE_EQ(reader.ter_len, 0);
	ATF_REQUIRE(read(fd, msg, OES_MSG_MAX_SIZE) == -1 && errno == EAGAIN);
}
static oes_message_t *
msg_alloc(void)
{
	oes_message_t *msg;

	msg = malloc(OES_MSG_MAX_SIZE);
	ATF_REQUIRE(msg != NULL);
	return (msg);
}

/*
 * After the hold is released: the marker first, with exactly lost
 * deferred losses, then exactly n pipe writes, of which nb by pid b.
 */
static void
read_back(int fd, uint64_t lost, u_long n, pid_t b, u_long nb)
{
	oes_message_t *msg;
	uint64_t last;
	u_long i, seen_b;

	msg = msg_alloc();
	if (lost != 0) {
		next_msg(fd, msg);
		ATF_REQUIRE_EQ_MSG(msg->em_event, OES_EVENT_NOTIFY_LOST,
		    "first message %#x, not the events-lost marker",
		    msg->em_event);
		ATF_CHECK_EQ(msg->em_event_data.lost.el_unsent, lost);
		ATF_CHECK_EQ(msg->em_event_data.lost.el_queue, 0);
		ATF_CHECK_EQ(msg->em_event_data.lost.el_count, lost);
	}
	last = 0;
	seen_b = 0;
	for (i = 0; i < n; i++) {
		next_msg(fd, msg);
		ATF_REQUIRE_EQ_MSG(msg->em_event, OES_EVENT_NOTIFY_PIPE_WRITE,
		    "message %lu: event %#x", i, msg->em_event);
		/* Delivered in queue (write) order. */
		ATF_REQUIRE(msg->em_seq_num > last);
		last = msg->em_seq_num;
		if (msg->em_process.ep_pid == b)
			seen_b++;
	}
	ATF_CHECK_EQ(seen_b, nb);
	/* Nothing else: the refused events are gone, and no marker follows. */
	ATF_REQUIRE_EQ(sysctl_ul("security.oes.defer_depth"), 0);
	require_empty(fd, msg);
	free(msg);
}

/* floor(L / (2c)): where a uid alone stops. */
static u_long
share_stop(u_long limit, u_long c)
{

	return (limit / (2 * c));
}

ATF_TC_WITH_CLEANUP(fill_to_share);
ATF_TC_HEAD(fill_to_share, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A uid alone fills the deferred queue to exactly its share; "
	    "every refused event is counted and reported by the lost marker "
	    "before the queued events, and the writes all succeed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fill_to_share, tc)
{
	struct producer a;
	u_long c, limit, d;
	uint64_t drops0;
	int fd, jid, i, extra;

	require_test_kernel();
	save_max_bytes();
	/* The floor: small enough that the client's queue holds it all. */
	set_max_bytes(1);
	limit = sysctl_ul(MAX_BYTES);
	jid = make_jail();
	fd = open_jail_client(jid, limit);
	producer_start(&a, jid, UID_A);
	drops0 = nosleep_drops(fd);

	c = park_with_one(&a);
	d = fill(&a, fd, c, share_stop(limit, c));
	ATF_REQUIRE_EQ_MSG(d, share_stop(limit, c),
	    "stopped at %lu entries of %lu with the bound %lu", d, c, limit);
	/* Refused once full: each further write is one more loss. */
	extra = 3;
	for (i = 0; i < extra; i++) {
		producer_write(&a);
		ATF_REQUIRE_EQ(sysctl_ul("security.oes.defer_depth"), d);
	}
	ATF_REQUIRE_EQ(nosleep_drops(fd), drops0 + 1 + extra);

	ATF_REQUIRE(defer_hold(0) == 0);
	read_back(fd, 1 + extra, d, -1, 0);
	producer_stop(&a);
	close(fd);
}
ATF_TC_CLEANUP(fill_to_share, tc)
{

	cleanup_common();
}

ATF_TC_WITH_CLEANUP(share_two_uids);
ATF_TC_HEAD(share_two_uids, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A uid that floods the deferred queue stops at its share and "
	    "another uid's event is still queued and delivered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(share_two_uids, tc)
{
	struct producer a, b;
	u_long c, limit, d, bytes;
	uint64_t drops;
	int fd, jid;

	require_test_kernel();
	save_max_bytes();
	set_max_bytes(1);
	limit = sysctl_ul(MAX_BYTES);
	jid = make_jail();
	fd = open_jail_client(jid, limit);
	producer_start(&a, jid, UID_A);
	producer_start(&b, jid, UID_B);

	c = park_with_one(&a);
	d = fill(&a, fd, c, share_stop(limit, c));
	ATF_REQUIRE_EQ(d, share_stop(limit, c));
	/* The other uid: 0 + c' <= L - (d*c + c') holds, so it is queued. */
	drops = nosleep_drops(fd);
	bytes = sysctl_ul("security.oes.defer_bytes");
	producer_write(&b);
	ATF_REQUIRE_EQ_MSG(sysctl_ul("security.oes.defer_depth"), d + 1,
	    "the second uid's event was refused with the first at its share");
	ATF_REQUIRE_EQ(nosleep_drops(fd), drops);
	ATF_REQUIRE(sysctl_ul("security.oes.defer_bytes") > bytes);
	/* The flooder is still held at its share. */
	producer_write(&a);
	ATF_REQUIRE_EQ(sysctl_ul("security.oes.defer_depth"), d + 1);
	ATF_REQUIRE_EQ(nosleep_drops(fd), drops + 1);

	ATF_REQUIRE(defer_hold(0) == 0);
	/* The refusal that stopped the fill, and the flooder's last write. */
	read_back(fd, 2, d + 1, b.pid, 1);
	producer_stop(&a);
	producer_stop(&b);
	close(fd);
}
ATF_TC_CLEANUP(share_two_uids, tc)
{

	cleanup_common();
}

ATF_TC_WITH_CLEANUP(bound_scales);
ATF_TC_HEAD(bound_scales, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The deferred queue's stop follows security.oes.defer_max_bytes: "
	    "doubling the bound doubles what a uid may queue");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(bound_scales, tc)
{
	struct producer a;
	u_long c, limit, d[2];
	int fd, jid, k;

	require_test_kernel();
	save_max_bytes();
	set_max_bytes(1);
	limit = sysctl_ul(MAX_BYTES);
	jid = make_jail();
	fd = open_jail_client(jid, limit << 1);
	producer_start(&a, jid, UID_A);

	for (k = 0; k < 2; k++) {
		set_max_bytes(limit << k);
		ATF_REQUIRE_EQ(sysctl_ul(MAX_BYTES), limit << k);
		c = park_with_one(&a);
		d[k] = fill(&a, fd, c, share_stop(limit << k, c));
		ATF_REQUIRE_EQ_MSG(d[k], share_stop(limit << k, c),
		    "bound %lu: stopped at %lu entries of %lu", limit << k,
		    d[k], c);
		ATF_REQUIRE(defer_hold(0) == 0);
		read_back(fd, 1, d[k], -1, 0);
	}
	/* floor(2L / 2c) is 2 floor(L / 2c) or one more. */
	ATF_CHECK_MSG(d[1] == 2 * d[0] || d[1] == 2 * d[0] + 1,
	    "bound %lu: %lu entries, bound %lu: %lu", limit, d[0], 2 * limit,
	    d[1]);
	producer_stop(&a);
	close(fd);
}
ATF_TC_CLEANUP(bound_scales, tc)
{

	cleanup_common();
}

ATF_TC_WITH_CLEANUP(floor_cap_default);
ATF_TC_HEAD(floor_cap_default, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "security.oes.defer_max_bytes is raised to its floor, lowered to "
	    "vm.kmem_size, and 0 restores min(hw.physmem, vm.kmem_size) / 64");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(floor_cap_default, tc)
{
	u_long floor, kmem, def;

	save_max_bytes();
	floor = 2 * sysctl_ul("hw.ncpu") *
	    sysctl_ul("security.oes.defer_entry_max");
	kmem = sysctl_ul("vm.kmem_size");
	set_max_bytes(1);
	ATF_CHECK_EQ(sysctl_ul(MAX_BYTES), floor);
	set_max_bytes(kmem + 1);
	ATF_CHECK_EQ(sysctl_ul(MAX_BYTES), kmem);
	set_max_bytes(0);
	def = MIN(sysctl_ul("hw.physmem"), kmem) / 64;
	if (def < floor)
		def = floor;
	ATF_CHECK_EQ(sysctl_ul(MAX_BYTES), def);
}
ATF_TC_CLEANUP(floor_cap_default, tc)
{

	cleanup_common();
}

ATF_TC_WITH_CLEANUP(compaction);
ATF_TC_HEAD(compaction, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A queued deferred event holds memory for its own size, not a "
	    "maximum-size message");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(compaction, tc)
{
	struct producer a;
	u_long c;
	int fd, jid;

	require_test_kernel();
	save_max_bytes();
	jid = make_jail();
	fd = open_jail_client(jid, sysctl_ul(MAX_BYTES));
	producer_start(&a, jid, UID_A);
	c = park_with_one(&a);
	ATF_CHECK_MSG(c < sysctl_ul("security.oes.defer_entry_max"),
	    "a pipe write holds %lu bytes, a maximum-size event %lu", c,
	    sysctl_ul("security.oes.defer_entry_max"));
	ATF_REQUIRE(defer_hold(0) == 0);
	read_back(fd, 0, 1, -1, 0);
	producer_stop(&a);
	close(fd);
}
ATF_TC_CLEANUP(compaction, tc)
{

	cleanup_common();
}

/* A client queue of QUEUE_SIZE events; the child opens it OPENS times. */
#define	QUEUE_SIZE	4
#define	OPENS		(QUEUE_SIZE + 3)

ATF_TC(queue_full_marker);
ATF_TC_HEAD(queue_full_marker, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Events a client's full queue discards are reported by the "
	    "lost marker, read first, with their exact count");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(queue_full_marker, tc)
{
	struct oes_mode_args mode;
	oes_event_type_t ev = OES_EVENT_NOTIFY_OPEN;
	oes_message_t *msg;
	char path[] = "queue_full.XXXXXX";
	pid_t pid;
	int fd, f, i, status;

	f = mkstemp(path);
	ATF_REQUIRE(f >= 0);
	close(f);
	fd = test_open_oes();
	ATF_REQUIRE(fd >= 0);
	/* Only this test's child: open events are made everywhere. */
	ATF_REQUIRE(test_set_descendants_scope(fd) == 0);
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	mode.ema_queue_size = QUEUE_SIZE;
	ATF_REQUIRE(ioctl(fd, OES_IOC_SET_MODE, &mode) == 0);
	ATF_REQUIRE(test_subscribe(fd, &ev, 1, OES_SUB_REPLACE) == 0);

	/* A child: a client never sees its own process's events. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		for (i = 0; i < OPENS; i++) {
			f = open(path, O_RDONLY);
			if (f < 0)
				_exit(1);
			close(f);
		}
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Delivered by the opening thread: all done before it exited. */
	msg = msg_alloc();
	next_msg(fd, msg);
	ATF_REQUIRE_EQ_MSG(msg->em_event, OES_EVENT_NOTIFY_LOST,
	    "first message %#x, not the events-lost marker", msg->em_event);
	ATF_CHECK_EQ(msg->em_event_data.lost.el_queue, OPENS - QUEUE_SIZE);
	ATF_CHECK_EQ(msg->em_event_data.lost.el_unsent, 0);
	ATF_CHECK_EQ(msg->em_event_data.lost.el_count, OPENS - QUEUE_SIZE);
	for (i = 0; i < QUEUE_SIZE; i++) {
		next_msg(fd, msg);
		ATF_CHECK_EQ(msg->em_event, OES_EVENT_NOTIFY_OPEN);
		ATF_CHECK_EQ(msg->em_process.ep_pid, pid);
	}
	require_empty(fd, msg);
	free(msg);
	close(fd);
	unlink(path);
}

ATF_TC_WITHOUT_HEAD(lost_not_subscribable);
ATF_TC_BODY(lost_not_subscribable, tc)
{
	oes_event_type_t ev = OES_EVENT_NOTIFY_LOST;
	int fd;

	fd = test_open_oes();
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(test_set_mode(fd, OES_MODE_NOTIFY) == 0);
	ATF_REQUIRE_ERRNO(EINVAL, test_subscribe(fd, &ev, 1,
	    OES_SUB_REPLACE) == -1);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fill_to_share);
	ATF_TP_ADD_TC(tp, share_two_uids);
	ATF_TP_ADD_TC(tp, bound_scales);
	ATF_TP_ADD_TC(tp, floor_cap_default);
	ATF_TP_ADD_TC(tp, compaction);
	ATF_TP_ADD_TC(tp, queue_full_marker);
	ATF_TP_ADD_TC(tp, lost_not_subscribable);
	return (atf_no_error());
}
