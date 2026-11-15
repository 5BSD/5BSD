/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Who may operate a queue, and what its descriptor does in the descriptor
 * table (sc-q).
 *
 * A queue belongs to the process that opened it.  Its descriptor is pinned
 * to that process's descriptor table: no fork child has it, it is gone
 * after execve(2), and it cannot be sent over a local socket, taken with
 * pddupfd(2) or given to a mac_capability service (that last is
 * tests/sys/mac_capability, channel_send_pinned).  The one other process
 * that can reach the queue is one that shares the owner's table (rfork(2)
 * without RFFDG); it is refused EPERM on every operation.  The queue dies
 * when its owner exits, execs or leaves a shared table, whoever still
 * holds the file: from then on every caller is answered ENXIO, and the
 * descriptors the queue served fail EIO.  Nothing here says what becomes
 * of the programs the queue served beyond those descriptors.
 *
 * The first three cases were committed with the values a kernel without
 * the owner rule gives (the queue as a bearer token); the commit that
 * introduced the rule changed their expectations in the same diff.
 *
 * No subject below makes an ATF call: each runs in a child and reports
 * over a pipe.
 */

#include <sys/param.h>
#include <sys/aio.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ttycom.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	SET(rr, call) do {						\
	errno = 0;							\
	(rr).rv = (call);						\
	(rr).err = (rr).rv == -1 ? errno : 0;				\
} while (0)

/* Every way into the queue's cdevsw, one slot each. */
enum {
	OP_STATS,		/* DQ_IOC_GET_STATS */
	OP_STATS2,		/* DQ_IOC_GET_STATS2 */
	OP_FIONBIO,
	OP_READ,		/* non-blocking, nothing pending */
	OP_READ_SHORT,		/* a buffer smaller than a record */
	OP_NOTTY,		/* an ioctl the queue does not have */
	OP_POLL,		/* poll(2): rv, and revents in ops_res */
	OP_KEVENT,		/* EVFILT_READ registration */
	OP_OBSERVER,		/* DQ_IOC_MINT_OBSERVER */
	OP_MINT,		/* DQ_IOC_MINT */
	OP_REVOKE,		/* DQ_IOC_REVOKE */
	OP_ATTACH,		/* DQ_IOC_ATTACH */
	OP_CLOSE,		/* close(2), where the subject closes */
	OP_N
};

static const char *const op_names[OP_N] = {
	[OP_STATS] = "GET_STATS",
	[OP_STATS2] = "GET_STATS2",
	[OP_FIONBIO] = "FIONBIO",
	[OP_READ] = "read",
	[OP_READ_SHORT] = "short read",
	[OP_NOTTY] = "unknown ioctl",
	[OP_POLL] = "poll",
	[OP_KEVENT] = "kevent",
	[OP_OBSERVER] = "MINT_OBSERVER",
	[OP_MINT] = "MINT",
	[OP_REVOKE] = "REVOKE",
	[OP_ATTACH] = "ATTACH",
	[OP_CLOSE] = "close",
};

struct ops_res {
	struct dqt_rr	 r[OP_N];
	uint64_t	 id;		/* ds_queue_id, 0 without statistics */
	int		 revents;
	struct dqt_rr	 sel;		/* select(2) for reading, 100 ms */
	bool		 done;		/* the subject got to the end */
};

/* What a caller the queue serves is told (rv -1 with this errno; 0: ok). */
static const int ops_served[OP_N] = {
	[OP_READ] = EAGAIN,
	[OP_READ_SHORT] = EINVAL,
	[OP_NOTTY] = ENOTTY,
};

/*
 * The operations that post nothing: a later reader still finds the queue
 * empty.
 */
static void
ops_quiet(int q, struct ops_res *res)
{
	struct dq_stats st;
	struct dq_stats2 st2;
	struct kevent kev;
	struct pollfd pfd;
	struct timeval tv;
	fd_set rset;
	char buf[4096];
	int fl, kq, on;

	SET(res->r[OP_STATS], dq_get_stats(q, &st));
	res->id = res->r[OP_STATS].rv == 0 ? st.ds_queue_id : 0;
	SET(res->r[OP_STATS2], dq_get_stats2(q, &st2));
	/*
	 * FIONBIO to the value the open file already has is answered by
	 * kern_ioctl() without the device, for any caller.  Where an
	 * earlier caller set it, clear it first: that reaches the device.
	 */
	fl = fcntl(q, F_GETFL);
	if (fl != -1 && (fl & O_NONBLOCK) != 0) {
		on = 0;
		SET(res->r[OP_FIONBIO], ioctl(q, FIONBIO, &on));
	} else
		res->r[OP_FIONBIO].rv = 0;
	if (res->r[OP_FIONBIO].rv == 0) {
		on = 1;
		SET(res->r[OP_FIONBIO], ioctl(q, FIONBIO, &on));
	}
	SET(res->r[OP_READ], read(q, buf, sizeof(buf)));
	SET(res->r[OP_READ_SHORT], read(q, buf, 1));
	SET(res->r[OP_NOTTY], ioctl(q, TIOCEXCL));
	pfd.fd = q;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	SET(res->r[OP_POLL], poll(&pfd, 1, 0));
	res->revents = pfd.revents;
	/*
	 * select(2) has no way to say POLLNVAL: for a caller the queue
	 * refuses it never reports the queue ready, and an empty queue is
	 * not readable for its owner either.
	 */
	FD_ZERO(&rset);
	FD_SET(q, &rset);
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	SET(res->sel, select(q + 1, &rset, NULL, NULL, &tv));
	kq = kqueue();
	if (kq == -1) {
		res->r[OP_KEVENT].rv = -2;
		res->r[OP_KEVENT].err = errno;
	} else {
		EV_SET(&kev, q, EVFILT_READ, EV_ADD, 0, 0, NULL);
		SET(res->r[OP_KEVENT], kevent(kq, &kev, 1, NULL, 0, NULL));
		(void)close(kq);
	}
}

/* The operations that make things; target is a process descriptor. */
static void
ops_make(int q, const struct dq_ident_file *ident, int target,
    struct ops_res *res)
{
	struct dq_policy pol;
	uint64_t object;
	int fd, reason;

	SET(res->r[OP_OBSERVER], dq_mint_observer(q, 0));
	dq_policy_default(&pol);
	object = 0;
	fd = -1;
	SET(res->r[OP_MINT], dq_mint_file(q, ident, &pol, &object, &fd,
	    &reason));
	SET(res->r[OP_REVOKE], dq_revoke(q, object));
	SET(res->r[OP_ATTACH], dq_attach(q, target));
	res->done = true;
}

/* Every operation answered as the opener is answered. */
static void
check_served(const char *who, const struct ops_res *res, uint64_t id)
{
	int op;

	ATF_CHECK_MSG(res->done, "%s: did not finish", who);
	for (op = 0; op < OP_N; op++) {
		if (op == OP_CLOSE)
			continue;
		if (ops_served[op] != 0)
			ATF_CHECK_MSG(res->r[op].rv == -1 &&
			    res->r[op].err == ops_served[op],
			    "%s: %s: rv %ld errno %d, want errno %d", who,
			    op_names[op], res->r[op].rv, res->r[op].err,
			    ops_served[op]);
		else
			ATF_CHECK_MSG(res->r[op].rv >= 0,
			    "%s: %s: rv %ld errno %d, want success", who,
			    op_names[op], res->r[op].rv, res->r[op].err);
	}
	ATF_CHECK_EQ_MSG(id, res->id, "%s: queue id %ju, want %ju", who,
	    (uintmax_t)res->id, (uintmax_t)id);
	ATF_CHECK_EQ_MSG(0, res->sel.rv, "%s: select returned %ld errno %d",
	    who, res->sel.rv, res->sel.err);
	ATF_CHECK_EQ_MSG(1, res->r[OP_POLL].rv, "%s: poll returned %ld", who,
	    res->r[OP_POLL].rv);
	ATF_CHECK_EQ_MSG(POLLOUT, res->revents, "%s: revents %#x, want "
	    "POLLOUT", who, res->revents);
}

/*
 * Every operation refused with the one errno: the caller is not the owner
 * (EPERM) or the queue has died (ENXIO).  poll(2) has no errno to give and
 * reports POLLNVAL.
 */
static void
check_refused(const char *who, const struct ops_res *res, int want)
{
	int op;

	ATF_CHECK_MSG(res->done, "%s: did not finish", who);
	for (op = 0; op < OP_N; op++) {
		if (op == OP_CLOSE || op == OP_POLL)
			continue;
		ATF_CHECK_MSG(res->r[op].rv == -1 && res->r[op].err == want,
		    "%s: %s: rv %ld errno %d, want errno %d", who,
		    op_names[op], res->r[op].rv, res->r[op].err, want);
	}
	ATF_CHECK_EQ_MSG(1, res->r[OP_POLL].rv, "%s: poll returned %ld", who,
	    res->r[OP_POLL].rv);
	ATF_CHECK_EQ_MSG(POLLNVAL, res->revents, "%s: revents %#x, want "
	    "POLLNVAL", who, res->revents);
	ATF_CHECK_EQ_MSG(0, res->sel.rv, "%s: select returned %ld errno %d",
	    who, res->sel.rv, res->sel.err);
}

static void
make_ident(struct dq_ident_file *ident)
{
	static char path[DQT_PATH_MAX];
	struct statfs sfs;
	struct stat sb;
	int fd;

	fd = dqt_make_oracle("owner_oracle", "pin", 3, path, sizeof(path));
	dqt_ident_of(fd, path, ident, &sb, &sfs);
	(void)close(fd);
}

/* An idle process behind a process descriptor; -1 if it cannot be made. */
static int
idle_target(void)
{
	int pd;

	switch (pdfork(&pd, 0)) {
	case -1:
		return (-1);
	case 0:
		/* Hold nothing of the test's: its pipes report by end of file. */
		closefrom(3);
		for (;;)
			(void)pause();
	}
	return (pd);
}

static void
idle_target_end(int pd)
{
	int status;

	if (pd == -1)
		return;
	(void)pdkill(pd, SIGKILL);
	(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	(void)close(pd);
}

static bool
read_all(int fd, void *buf, size_t len)
{
	char *p = buf;
	ssize_t n;
	size_t off;

	for (off = 0; off < len; off += (size_t)n) {
		n = read(fd, p + off, len - off);
		if (n <= 0)
			return (false);
	}
	return (true);
}

/* kern.dq.queues: the queues that exist.  This program runs alone. */
static u_int
queues_now(void)
{
	u_int n;

	if (!dqt_sysctl_get_uint("kern.dq.queues", &n))
		return (UINT_MAX);
	return (n);
}

/* The last close unlists a queue; the count returns within the bound. */
static bool
queues_settle(u_int want)
{
	int i;

	for (i = 0; i < 100; i++) {
		if (queues_now() == want)
			return (true);
		dqt_msleep(50);
	}
	return (false);
}

/* How many of this process's descriptors are the queue device. */
static int
scan_queues(void)
{
	struct stat dev, sb;
	int fd, max, n;

	if (stat(DQ_DEVICE, &dev) != 0 || !S_ISCHR(dev.st_mode))
		return (101);
	max = getdtablesize();
	if (max > 4096)
		max = 4096;
	n = 0;
	for (fd = 0; fd < max; fd++) {
		if (fstat(fd, &sb) == 0 && S_ISCHR(sb.st_mode) &&
		    sb.st_rdev == dev.st_rdev)
			n++;
	}
	return (n > 100 ? 100 : n);
}

/*
 * A child's verdict on the number q, for its exit status: 0 when it holds
 * no queue under any number and q is not open at all.
 */
static int
probe_child(int q)
{
	struct stat sb;
	int n;

	n = scan_queues();
	if (n != 0)
		return (n);
	if (fstat(q, &sb) != -1 || errno != EBADF)
		return (102);
	return (0);
}

/*
 * A sharer of the opener's descriptor table
 */

/*
 * F_SETFL by the sharer on the queue the opener runs non-blocking.  A call
 * that changes O_NONBLOCK or O_ASYNC asks the device, which refuses a
 * process that is not the owner, and the flags stay as they were; a call
 * that changes another status flag asks nobody.
 */
enum {
	SF_CLEAR_NONBLOCK,	/* F_SETFL, 0 */
	SF_SET_ASYNC,		/* F_SETFL, O_NONBLOCK | O_ASYNC */
	SF_SET_APPEND,		/* F_SETFL, O_NONBLOCK | O_APPEND */
	SF_RESTORE,		/* F_SETFL, O_NONBLOCK */
	SF_N
};

struct sharer_setfl {
	struct dqt_rr	 r[SF_N];
	int		 getfl[SF_N];	/* F_GETFL after each */
};

static void
sharer_setfl(int q, struct sharer_setfl *sf)
{
	static const int flags[SF_N] = { 0, O_NONBLOCK | O_ASYNC,
	    O_NONBLOCK | O_APPEND, O_NONBLOCK };
	int i;

	for (i = 0; i < SF_N; i++) {
		SET(sf->r[i], fcntl(q, F_SETFL, flags[i]));
		sf->getfl[i] = fcntl(q, F_GETFL);
	}
}

struct sharer_res {
	struct ops_res	 opener;
	struct ops_res	 sharer;
	struct dqt_rr	 attach_sharer;	/* the opener's ATTACH of the sharer */
	int		 sharer_status;	/* wait status, -1: not collected */
	struct sharer_setfl setfl;	/* the sharer's F_SETFL calls */
	struct dqt_rr	 opener_read;	/* the opener's read after them */
};

/*
 * The opener: opens the queue as libdq does, then rfork(2)s a process that
 * shares its descriptor table and runs every operation on the same
 * descriptor number.  The opener's quiet operations run first and its
 * making ones last, after the sharer's, so that each reader finds the
 * queue empty and the owner is seen to work throughout.  The sharer stays
 * until the opener has tried to attach it.
 */
static void
child_opener_sharer(void *arg, void *result)
{
	const struct dq_ident_file *ident = arg;
	struct sharer_res *res = result;
	struct ops_res sres;
	struct sharer_setfl ssf;
	pid_t pid;
	int gp[2], pd, q, rp[2], status, t_opener, t_sharer;
	char b, buf[4096];

	res->sharer_status = -1;
	q = dq_open();
	if (q == -1 || pipe(rp) != 0 || pipe(gp) != 0)
		_exit(6);
	/* Forked: neither holds the O_CLOFORK queue. */
	t_opener = idle_target();
	t_sharer = idle_target();
	if (t_opener == -1 || t_sharer == -1)
		_exit(7);
	ops_quiet(q, &res->opener);

	pid = pdrfork(&pd, 0, RFPROC | RFPROCDESC);
	if (pid == -1)
		_exit(8);
	if (pid == 0) {
		memset(&sres, 0, sizeof(sres));
		ops_quiet(q, &sres);
		ops_make(q, ident, t_sharer, &sres);
		memset(&ssf, 0, sizeof(ssf));
		sharer_setfl(q, &ssf);
		(void)write(rp[1], &sres, sizeof(sres));
		(void)write(rp[1], &ssf, sizeof(ssf));
		(void)read(gp[0], &b, 1);
		_exit(0);
	}
	if (!read_all(rp[0], &res->sharer, sizeof(res->sharer)) ||
	    !read_all(rp[0], &res->setfl, sizeof(res->setfl)))
		_exit(9);
	/* Still non-blocking, whatever the sharer asked for. */
	SET(res->opener_read, read(q, buf, sizeof(buf)));
	/* It holds the queue (its table does): EBUSY, as before sc-q. */
	SET(res->attach_sharer, dq_attach(q, pd));
	(void)write(gp[1], "x", 1);
	if (pdwait(pd, &status, WEXITED, NULL, NULL) == 0)
		res->sharer_status = status;
	ops_make(q, ident, t_opener, &res->opener);
	idle_target_end(t_opener);
	idle_target_end(t_sharer);
}

/* S6.  Before sc-q this case was sharer_operates: every row succeeded. */
ATF_TC(sharer_cannot_operate);
ATF_TC_HEAD(sharer_cannot_operate, tc)
{
	atf_tc_set_md_var(tc, "descr", "a process sharing the owner's "
	    "descriptor table (rfork without RFFDG) may not operate the "
	    "queue: statistics, FIONBIO, read, kevent, observer and object "
	    "mint, revoke, attach are EPERM and poll reports POLLNVAL; the "
	    "owner works before and after, and its ATTACH of the sharer is "
	    "EBUSY");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sharer_cannot_operate, tc)
{
	struct dq_ident_file *ident;
	struct sharer_res res;

	dqt_require_test_access();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_opener_sharer, ident, &res, sizeof(res));
	ATF_REQUIRE_MSG(res.opener.id != 0, "the opener has no queue");
	check_served("opener", &res.opener, res.opener.id);
	ATF_CHECK_MSG(WIFEXITED(res.sharer_status) &&
	    WEXITSTATUS(res.sharer_status) == 0, "sharer: status %#x",
	    res.sharer_status);
	check_refused("sharer", &res.sharer, EPERM);
	ATF_CHECK_EQ_MSG(0, res.sharer.id, "sharer: read queue id %ju",
	    (uintmax_t)res.sharer.id);
	ATF_CHECK_MSG(res.attach_sharer.rv == -1 &&
	    res.attach_sharer.err == EBUSY, "ATTACH of the sharer: rv %ld "
	    "errno %d, want EBUSY", res.attach_sharer.rv,
	    res.attach_sharer.err);
	/* The two refused calls change nothing, the allowed one one flag. */
	ATF_CHECK_MSG(res.setfl.r[SF_CLEAR_NONBLOCK].rv == -1 &&
	    res.setfl.r[SF_CLEAR_NONBLOCK].err == EPERM,
	    "sharer: F_SETFL 0: rv %ld errno %d, want EPERM",
	    res.setfl.r[SF_CLEAR_NONBLOCK].rv,
	    res.setfl.r[SF_CLEAR_NONBLOCK].err);
	ATF_CHECK_EQ_MSG(O_RDWR | O_NONBLOCK,
	    res.setfl.getfl[SF_CLEAR_NONBLOCK], "F_GETFL %#x after the "
	    "refused clear", res.setfl.getfl[SF_CLEAR_NONBLOCK]);
	ATF_CHECK_MSG(res.setfl.r[SF_SET_ASYNC].rv == -1 &&
	    res.setfl.r[SF_SET_ASYNC].err == EPERM,
	    "sharer: F_SETFL O_NONBLOCK|O_ASYNC: rv %ld errno %d, want EPERM",
	    res.setfl.r[SF_SET_ASYNC].rv, res.setfl.r[SF_SET_ASYNC].err);
	ATF_CHECK_EQ_MSG(O_RDWR | O_NONBLOCK, res.setfl.getfl[SF_SET_ASYNC],
	    "F_GETFL %#x after the refused O_ASYNC",
	    res.setfl.getfl[SF_SET_ASYNC]);
	ATF_CHECK_EQ_MSG(0, res.setfl.r[SF_SET_APPEND].rv,
	    "sharer: F_SETFL O_NONBLOCK|O_APPEND: errno %d",
	    res.setfl.r[SF_SET_APPEND].err);
	ATF_CHECK_EQ(O_RDWR | O_NONBLOCK | O_APPEND,
	    res.setfl.getfl[SF_SET_APPEND]);
	ATF_CHECK_EQ(0, res.setfl.r[SF_RESTORE].rv);
	ATF_CHECK_EQ(O_RDWR | O_NONBLOCK, res.setfl.getfl[SF_RESTORE]);
	ATF_CHECK_MSG(res.opener_read.rv == -1 &&
	    res.opener_read.err == EAGAIN, "the opener's read afterwards: "
	    "rv %ld errno %d, want EAGAIN", res.opener_read.rv,
	    res.opener_read.err);
	free(ident);
}

struct outlive_arg {
	const struct dq_ident_file *ident;
	int		 go;		/* read: the opener is gone */
	int		 rep;		/* write: the sharer's ops_res */
};

/* What the sharer reads from the kqueue the opener registered the queue on. */
struct outlive_eof {
	struct dqt_rr	 kev;		/* kevent(2): the number of events */
	int		 flags;		/* of the event */
	int		 ident;		/* its descriptor */
	int		 q;		/* the queue's number */
};

/*
 * The opener exits and leaves the sharer with the table.  The sharer waits
 * for the test, which has by then reaped the opener, and never returns to
 * the harness.  It is the only process that can reach a queue whose owner
 * is gone: the descriptor does not survive an exec and no child has it.
 */
static void
child_opener_exits(void *arg, void *result)
{
	struct outlive_arg *a = arg;
	struct ops_res *res = result;
	struct ops_res sres;
	struct outlive_eof eof;
	struct kevent kev;
	struct timespec ts;
	pid_t pid;
	int kq, q, target;
	char b;

	q = dq_open();
	if (q == -1)
		_exit(6);
	target = idle_target();
	if (target == -1)
		_exit(7);
	ops_quiet(q, res);
	/* The owner's own registration, in a kqueue the table keeps. */
	kq = kqueue();
	if (kq == -1)
		_exit(10);
	EV_SET(&kev, q, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0)
		_exit(11);
	res->done = true;

	pid = rfork(RFPROC);
	if (pid == -1)
		_exit(8);
	if (pid != 0)
		return;
	memset(&sres, 0, sizeof(sres));
	if (read(a->go, &b, 1) != 1)
		_exit(9);
	/*
	 * The filter the owner registered reports the queue's death to
	 * whoever reads that kqueue: readiness, not an operation.
	 */
	memset(&eof, 0, sizeof(eof));
	memset(&kev, 0, sizeof(kev));
	ts.tv_sec = 10;
	ts.tv_nsec = 0;
	SET(eof.kev, kevent(kq, NULL, 0, &kev, 1, &ts));
	eof.flags = kev.flags;
	eof.ident = (int)kev.ident;
	eof.q = q;
	ops_quiet(q, &sres);
	ops_make(q, a->ident, target, &sres);
	/* The last close of the queue. */
	SET(sres.r[OP_CLOSE], close(q));
	idle_target_end(target);
	(void)write(a->rep, &sres, sizeof(sres));
	(void)write(a->rep, &eof, sizeof(eof));
	_exit(0);
}

ATF_TC(sharer_outlives_opener);
ATF_TC_HEAD(sharer_outlives_opener, tc)
{
	atf_tc_set_md_var(tc, "descr", "the owner exits while a process "
	    "sharing its descriptor table holds the queue: the queue has "
	    "died, every operation by the sharer is ENXIO (never EPERM, "
	    "never success), poll reports POLLNVAL, and its close, the "
	    "last, succeeds and leaves no queue behind");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sharer_outlives_opener, tc)
{
	struct dq_ident_file *ident;
	struct dqt_child ch;
	struct outlive_arg a;
	struct ops_res opener, sharer;
	struct outlive_eof eof;
	u_int before;
	int go[2], rep[2];
	char b;

	dqt_require_test_access();
	before = queues_now();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(rep));
	a.ident = ident;
	a.go = go[0];
	a.rep = rep[1];
	memset(&opener, 0, sizeof(opener));
	dqt_spawn(&ch, child_opener_exits, &a);
	/* The sharer alone holds these ends, so its death is end of file. */
	(void)close(go[0]);
	(void)close(rep[1]);
	dqt_collect(&ch, &opener, sizeof(opener));
	ATF_REQUIRE_MSG(opener.done && opener.id != 0,
	    "the opener has no queue");

	/* The opener has been reaped: it is out of the table. */
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&sharer, 0, sizeof(sharer));
	ATF_REQUIRE_MSG(read_all(rep[0], &sharer, sizeof(sharer)),
	    "no report from the sharer");
	memset(&eof, 0, sizeof(eof));
	ATF_REQUIRE_MSG(read_all(rep[0], &eof, sizeof(eof)),
	    "no kqueue report from the sharer");
	ATF_CHECK_EQ_MSG(1, eof.kev.rv, "kevent returned %ld errno %d",
	    eof.kev.rv, eof.kev.err);
	ATF_CHECK_EQ(eof.q, eof.ident);
	ATF_CHECK_MSG((eof.flags & EV_EOF) != 0, "event flags %#x lack "
	    "EV_EOF", eof.flags);
	/* S11.  Before sc-q the sharer was served here, as the opener. */
	check_refused("sharer", &sharer, ENXIO);
	ATF_CHECK_EQ_MSG(0, sharer.r[OP_CLOSE].rv, "close: errno %d",
	    sharer.r[OP_CLOSE].err);
	/* It has exited: nothing else holds the write end. */
	ATF_CHECK_EQ(0, read(rep[0], &b, 1));
	ATF_CHECK_MSG(queues_settle(before), "kern.dq.queues is %u, was %u",
	    queues_now(), before);
	(void)close(go[1]);
	(void)close(rep[0]);
	free(ident);
}

/*
 * The queue's descriptor in the descriptor table: the columns of
 * tests/sys/kern/cap_xfer_test.c install_states_unchanged, for a queue.
 */

struct qd_row {
	int	fd;		/* the number, -1 if it could not be made */
	int	getfd;		/* F_GETFD */
	int	getfl;		/* F_GETFL */
	int	dup_errno;	/* dup(2): 0 or errno */
	int	dup_getfd;	/* F_GETFD of the dup */
	int	fork_errno;	/* GET_STATS in a fork(2) child: 0 or errno */
	int	dupfork_errno;	/* the same on the dup */
	int	exec_status;	/* sh -c ': <&fd' after fork: 0 has it, 2 not */
	int	scm_errno;	/* sendmsg(SCM_RIGHTS): 0 or errno */
	int	scm_getfd;	/* F_GETFD of the received copy */
	int	scm_stats;	/* GET_STATS on the received copy: 0 or errno */
	int	pddup_errno;	/* the parent's pddupfd(2): 0 or errno */
	int	pddup_getfd;	/* F_GETFD of the parent's copy */
	int	pddup_stats;	/* GET_STATS on the parent's copy: 0 or errno */
};

enum qd_kind {
	QD_RAW,			/* open(2) with O_RDWR alone */
	QD_LIBDQ,		/* dq_open(3): O_CLOEXEC | O_CLOFORK */
	QD_NKINDS
};

static const struct {
	const char	*name;
	struct qd_row	 want;
} qd_table[QD_NKINDS] = {
	/*
	 * Before sc-q: open(O_RDWR) read back 0, was inherited by fork and
	 * exec, sent and taken; dq_open()'s descriptor was kept from fork
	 * and exec by its two flags only, and its dup was inherited.  Now
	 * the two are alike: the flags are forced at open, a dup reads back
	 * 0 and is still not inherited (the flags are advisory for a pinned
	 * file), and nothing transfers.  -1: no copy to look at.
	 */
	[QD_RAW] = { "open(O_RDWR)", {
		.getfd = FD_CLOEXEC | FD_CLOFORK, .getfl = O_RDWR,
		.dup_errno = 0, .dup_getfd = 0,
		.fork_errno = EBADF, .dupfork_errno = EBADF, .exec_status = 2,
		.scm_errno = ENOTCAPABLE, .scm_getfd = -1, .scm_stats = -1,
		.pddup_errno = ENOTCAPABLE, .pddup_getfd = -1,
		.pddup_stats = -1 } },
	[QD_LIBDQ] = { "dq_open()", {
		.getfd = FD_CLOEXEC | FD_CLOFORK, .getfl = O_RDWR,
		.dup_errno = 0, .dup_getfd = 0,
		.fork_errno = EBADF, .dupfork_errno = EBADF, .exec_status = 2,
		.scm_errno = ENOTCAPABLE, .scm_getfd = -1, .scm_stats = -1,
		.pddup_errno = ENOTCAPABLE, .pddup_getfd = -1,
		.pddup_stats = -1 } },
};

static int
qd_stats(int fd)
{
	struct dq_stats st;

	return (dq_get_stats(fd, &st) == 0 ? 0 : errno);
}

/* Probe fd in a fork(2) child; returns its exit status, -1 on failure. */
static int
qd_fork_probe(int fd, bool exec)
{
	char cmd[32];
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0) {
		if (!exec)
			_exit(qd_stats(fd));
		snprintf(cmd, sizeof(cmd), ": <&%d", fd);
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static int
qd_sendfd(int sock, int fd)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct msghdr msg;
	struct iovec iov;
	char b = 'q';

	memset(&msg, 0, sizeof(msg));
	memset(&ctl, 0, sizeof(ctl));
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);
	ctl.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	ctl.hdr.cmsg_level = SOL_SOCKET;
	ctl.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&ctl.hdr), &fd, sizeof(fd));
	return (sendmsg(sock, &msg, 0) == 1 ? 0 : errno);
}

static int
qd_recvfd(int sock)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct msghdr msg;
	struct iovec iov;
	char b;
	int fd;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);
	if (recvmsg(sock, &msg, MSG_DONTWAIT) != 1 ||
	    msg.msg_controllen < CMSG_LEN(sizeof(int)) ||
	    ctl.hdr.cmsg_level != SOL_SOCKET || ctl.hdr.cmsg_type != SCM_RIGHTS)
		return (-1);
	memcpy(&fd, CMSG_DATA(&ctl.hdr), sizeof(fd));
	return (fd);
}

/*
 * The subject: opens the queue, fills the row, reports it on rep and holds
 * the descriptor until the test has tried pddupfd(2) and writes on cmd.
 */
static void
qd_subject(enum qd_kind kind, int rep, int cmd)
{
	struct qd_row row;
	int d, fd, sp[2];
	char c;

	memset(&row, 0xff, sizeof(row));
	fd = kind == QD_RAW ? open(DQ_DEVICE, O_RDWR) : dq_open();
	row.fd = fd;
	/* sh(1) takes a single digit in "<&n". */
	if (fd == -1 || fd > 9)
		goto out;
	row.getfd = fcntl(fd, F_GETFD);
	row.getfl = fcntl(fd, F_GETFL);
	row.fork_errno = qd_fork_probe(fd, false);
	row.exec_status = qd_fork_probe(fd, true);
	d = dup(fd);
	row.dup_errno = d == -1 ? errno : 0;
	if (d != -1) {
		row.dup_getfd = fcntl(d, F_GETFD);
		row.dupfork_errno = qd_fork_probe(d, false);
		(void)close(d);
	}
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sp) != 0) {
		row.fd = -1;
		goto out;
	}
	row.scm_errno = qd_sendfd(sp[0], fd);
	if (row.scm_errno == 0 && (d = qd_recvfd(sp[1])) != -1) {
		row.scm_getfd = fcntl(d, F_GETFD);
		row.scm_stats = qd_stats(d);
		(void)close(d);
	}
	(void)close(sp[0]);
	(void)close(sp[1]);
out:
	if (write(rep, &row, sizeof(row)) != sizeof(row))
		_exit(1);
	(void)read(cmd, &c, 1);
	_exit(0);
}

#define	QD_CHECK(field)							\
	ATF_CHECK_EQ_MSG(want->field, row.field,			\
	    "%s: " #field " is %d (%#x), expected %d (%#x)", name,	\
	    row.field, row.field, want->field, want->field)

ATF_TC(queue_descriptor_states);
ATF_TC_HEAD(queue_descriptor_states, tc)
{
	atf_tc_set_md_var(tc, "descr", "the queue's descriptor, opened with "
	    "open(2) and with dq_open(3): its descriptor and status flags, "
	    "what dup(2) copies, whether fork(2) and execve(2) pass it on, "
	    "and whether it can be sent (SCM_RIGHTS) or taken (pddupfd)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(queue_descriptor_states, tc)
{
	const struct qd_row *want;
	struct qd_row row;
	const char *name;
	pid_t pid;
	int cmd[2], copy, kind, pd, rep[2], status;

	dqt_require_test_access();
	for (kind = 0; kind < QD_NKINDS; kind++) {
		name = qd_table[kind].name;
		want = &qd_table[kind].want;
		ATF_REQUIRE_EQ(0, pipe(rep));
		ATF_REQUIRE_EQ(0, pipe(cmd));
		pid = pdfork(&pd, 0);
		ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
		if (pid == 0) {
			if (dup2(rep[1], 3) != 3 || dup2(cmd[0], 4) != 4)
				_exit(1);
			closefrom(5);
			qd_subject(kind, 3, 4);
		}
		(void)close(rep[1]);
		(void)close(cmd[0]);
		ATF_REQUIRE_MSG(read_all(rep[0], &row, sizeof(row)),
		    "%s: no report", name);
		ATF_REQUIRE_MSG(row.fd >= 0 && row.fd <= 9,
		    "%s: could not be made (fd %d)", name, row.fd);

		errno = 0;
		copy = pddupfd(pd, row.fd, 0);
		row.pddup_errno = copy == -1 ? errno : 0;
		row.pddup_getfd = -1;
		row.pddup_stats = -1;
		if (copy != -1) {
			row.pddup_getfd = fcntl(copy, F_GETFD);
			row.pddup_stats = qd_stats(copy);
			ATF_REQUIRE_EQ(0, close(copy));
		}
		ATF_REQUIRE_EQ(1, write(cmd[1], "x", 1));
		ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "%s: subject status %#x", name, status);
		(void)close(pd);
		(void)close(rep[0]);
		(void)close(cmd[1]);

		printf("%s: fd %d getfd %#x getfl %#x dup %d/%#x fork %d "
		    "dupfork %d exec %d scm %d/%#x/%d pddupfd %d/%#x/%d\n",
		    name, row.fd, row.getfd, row.getfl, row.dup_errno,
		    row.dup_getfd, row.fork_errno, row.dupfork_errno,
		    row.exec_status, row.scm_errno, row.scm_getfd,
		    row.scm_stats, row.pddup_errno, row.pddup_getfd,
		    row.pddup_stats);
		QD_CHECK(getfd);
		QD_CHECK(getfl);
		QD_CHECK(dup_errno);
		QD_CHECK(dup_getfd);
		QD_CHECK(fork_errno);
		QD_CHECK(dupfork_errno);
		QD_CHECK(exec_status);
		QD_CHECK(scm_errno);
		QD_CHECK(scm_getfd);
		QD_CHECK(scm_stats);
		QD_CHECK(pddup_errno);
		QD_CHECK(pddup_getfd);
		QD_CHECK(pddup_stats);
	}
}

/*
 * Inheritance
 */

static char helper_path[DQT_PATH_MAX];

static void
helper_locate(const atf_tc_t *tc)
{

	snprintf(helper_path, sizeof(helper_path), "%s/dq_owner_helper",
	    atf_tc_get_config_var(tc, "srcdir"));
	ATF_REQUIRE_MSG(access(helper_path, X_OK) == 0, "%s: %s",
	    helper_path, strerror(errno));
}

struct rd_arg {
	int		 fd;
};
struct rd_res {
	struct dqt_rr	 r;
	unsigned char	 buf[16];
};

static void
child_read16(void *arg, void *result)
{
	struct rd_arg *a = arg;
	struct rd_res *res = result;

	SET(res->r, read(a->fd, res->buf, sizeof(res->buf)));
}

enum { K_FORK, K_VFORK, K_PDFORK, K_RFFDG, K_SPAWN, K_N };
static const char *const k_names[K_N] = { "fork", "vfork", "pdfork",
    "rfork(RFPROC | RFFDG)", "posix_spawn" };

extern char **environ;

/* S1. */
ATF_TC(fork_not_inherited);
ATF_TC_HEAD(fork_not_inherited, tc)
{
	atf_tc_set_md_var(tc, "descr", "a queue whose close-on-fork and "
	    "close-on-exec flags were cleared (F_SETFD 0 succeeds and reads "
	    "back 0) is in no child made by fork, vfork, pdfork, "
	    "rfork(RFPROC | RFFDG) or posix_spawn, under any number; the "
	    "parent's queue serves a request afterwards");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fork_not_inherited, tc)
{
	static unsigned char data[4096];
	static char path[DQT_PATH_MAX];
	char *const argv[] = { helper_path, NULL };
	struct dqt_ctl c;
	struct dqt_object *o;
	struct rd_arg a;
	struct rd_res res;
	pid_t pid;
	int k, oracle, pd, status;

	helper_locate(tc);
	dqt_fill(data, sizeof(data), 71);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	ATF_REQUIRE_EQ(FD_CLOEXEC | FD_CLOFORK, fcntl(c.q, F_GETFD));
	ATF_REQUIRE_EQ(0, fcntl(c.q, F_SETFD, 0));
	ATF_CHECK_EQ(0, fcntl(c.q, F_GETFD));
	/* The control for the scan: this process holds exactly one. */
	ATF_REQUIRE_EQ(1, scan_queues());

	for (k = 0; k < K_N; k++) {
		pd = -1;
		status = -1;
		switch (k) {
		case K_FORK:
			pid = fork();
			break;
		case K_VFORK:
			pid = vfork();
			if (pid == 0)
				_exit(probe_child(c.q));
			break;
		case K_PDFORK:
			pid = pdfork(&pd, 0);
			break;
		case K_RFFDG:
			pid = rfork(RFPROC | RFFDG);
			break;
		default:
			ATF_REQUIRE_EQ_MSG(0, posix_spawn(&pid, helper_path,
			    NULL, NULL, argv, environ), "posix_spawn");
			break;
		}
		ATF_REQUIRE_MSG(pid != -1, "%s: %s", k_names[k],
		    strerror(errno));
		if (pid == 0)
			_exit(probe_child(c.q));
		if (k == K_PDFORK) {
			ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL,
			    NULL));
			(void)close(pd);
		} else
			ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "%s: the child holds a queue (status %#x)", k_names[k],
		    status);
	}

	/* The owner's queue is alive and serving. */
	ATF_CHECK_EQ(1, scan_queues());
	o = dqt_mint(&c, oracle, path, data, sizeof(data), NULL);
	a.fd = o->fd;
	memset(&res, 0, sizeof(res));
	dqt_run_child(child_read16, &a, &res, sizeof(res));
	ATF_CHECK_EQ_MSG((long)sizeof(res.buf), res.r.rv, "served read: rv "
	    "%ld errno %d", res.r.rv, res.r.err);
	ATF_CHECK_EQ(0, memcmp(res.buf, data, sizeof(res.buf)));
	dqt_fini(&c);
	(void)close(oracle);
}

#define	STORM_FORKERS	3
#define	STORM_FORKS	2000

struct storm {
	atomic_bool	 stop;
	atomic_uint	 opens;
	atomic_uint	 open_failures;
	atomic_uint	 forks;
	atomic_uint	 holders;	/* children that held a queue */
	atomic_uint	 errors;
};

static void *
storm_opener(void *arg)
{
	struct storm *st = arg;
	int fd;

	while (!atomic_load(&st->stop)) {
		/* The widest window: no close-on flag asked for. */
		fd = open(DQ_DEVICE, O_RDWR);
		if (fd == -1) {
			atomic_fetch_add(&st->open_failures, 1);
			continue;
		}
		atomic_fetch_add(&st->opens, 1);
		(void)close(fd);
	}
	return (NULL);
}

static void *
storm_forker(void *arg)
{
	struct storm *st = arg;
	pid_t pid;
	int status;

	while (atomic_fetch_add(&st->forks, 1) < STORM_FORKS) {
		pid = fork();
		if (pid == 0)
			_exit(scan_queues() == 0 ? 0 : 1);
		if (pid == -1 || waitpid(pid, &status, 0) != pid ||
		    !WIFEXITED(status)) {
			atomic_fetch_add(&st->errors, 1);
			continue;
		}
		if (WEXITSTATUS(status) != 0)
			atomic_fetch_add(&st->holders, 1);
	}
	return (NULL);
}

/* S3. */
ATF_TC(open_fork_storm);
ATF_TC_HEAD(open_fork_storm, tc)
{
	atf_tc_set_md_var(tc, "descr", "one thread opens and closes the "
	    "queue device without close-on flags while three threads fork: "
	    "no child of 2000 ever holds a queue (the pinned states are in "
	    "the table entry from its first instant)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(open_fork_storm, tc)
{
	static struct storm st;
	pthread_t opener, forker[STORM_FORKERS];
	int i;

	dqt_require_test_access();
	ATF_REQUIRE_EQ(0, pthread_create(&opener, NULL, storm_opener, &st));
	for (i = 0; i < STORM_FORKERS; i++)
		ATF_REQUIRE_EQ(0, pthread_create(&forker[i], NULL,
		    storm_forker, &st));
	for (i = 0; i < STORM_FORKERS; i++)
		ATF_REQUIRE_EQ(0, pthread_join(forker[i], NULL));
	atomic_store(&st.stop, true);
	ATF_REQUIRE_EQ(0, pthread_join(opener, NULL));
	printf("opens %u (failed %u), holders %u, errors %u\n",
	    atomic_load(&st.opens), atomic_load(&st.open_failures),
	    atomic_load(&st.holders), atomic_load(&st.errors));
	ATF_CHECK_EQ(0, atomic_load(&st.holders));
	ATF_CHECK_EQ(0, atomic_load(&st.errors));
	ATF_CHECK_EQ(0, atomic_load(&st.open_failures));
	/* The two did overlap. */
	ATF_CHECK_MSG(atomic_load(&st.opens) >= 100, "only %u opens",
	    atomic_load(&st.opens));
}

/*
 * The owner goes: what becomes of the queue
 */

enum end_how {
	END_EXEC,		/* execve, table not shared */
	END_EXEC_SHARED,	/* execve while a sharer holds the table */
	END_EXEC_HELD,		/* the same, and the new image keeps running */
	END_EXIT_SHARED,	/* exit while a sharer holds the table */
	END_RFCFDG_SHARED,	/* rfork(RFCFDG): leaves the shared table */
	END_RFFDG_SHARED,	/* rfork(RFFDG): leaves the shared table */
	END_DAEMON,		/* daemon(3): the opener is the exiting parent */
	END_N
};
static const char *const end_names[END_N] = {
	[END_EXEC] = "execve",
	[END_EXEC_SHARED] = "execve, shared table",
	[END_EXEC_HELD] = "execve, shared table, image still running",
	[END_EXIT_SHARED] = "exit, shared table",
	[END_RFCFDG_SHARED] = "rfork(RFCFDG), shared table",
	[END_RFFDG_SHARED] = "rfork(RFFDG), shared table",
	[END_DAEMON] = "daemon(3)",
};

/* What the subject tells the test before it goes. */
struct end_rep {
	pid_t		 holder;	/* reads the served descriptor */
	pid_t		 sharer;	/* 0: none */
	int		 after;		/* a later image or process: its probe */
	uint64_t	 id;		/* the queue */
};

/* The test's ends, at fixed numbers in the subject. */
#define	END_GO		10	/* read: the test lets the holder read */
#define	END_HREP	11	/* write: the holder's struct dqt_rr */
#define	END_REP		12	/* write: struct end_rep */

/*
 * The subject: opens a queue, mints a served descriptor into a child that
 * is not attached (the holder), optionally leaves a sharer of its table,
 * then goes in the way asked.  The holder reads the served descriptor when
 * the test says so: with the queue alive that read would wait for a
 * controller that never answers.
 */
static void
end_subject(enum end_how how, const struct dq_ident_file *ident)
{
	struct dq_policy pol;
	struct dq_stats st;
	struct dqt_rr r;
	struct end_rep rep;
	uint64_t object;
	unsigned char buf[16];
	char *const argv[] = { helper_path, NULL };
	int fd, q, reason;
	char b;

	memset(&rep, 0, sizeof(rep));
	rep.after = -1;
	q = dq_open();
	if (q == -1 || fcntl(q, F_SETFD, 0) != 0)
		_exit(20);
	dq_policy_default(&pol);
	if (dq_mint_file(q, ident, &pol, &object, &fd, &reason) != 0 ||
	    dq_get_stats(q, &st) != 0)
		_exit(21);
	rep.id = st.ds_queue_id;

	rep.holder = fork();
	if (rep.holder == -1)
		_exit(22);
	if (rep.holder == 0) {
		(void)close(END_REP);
		if (read(END_GO, &b, 1) != 1)
			_exit(0);
		SET(r, read(fd, buf, sizeof(buf)));
		(void)write(END_HREP, &r, sizeof(r));
		_exit(0);
	}
	(void)close(fd);
	if (how != END_EXEC && how != END_DAEMON) {
		rep.sharer = rfork(RFPROC);
		if (rep.sharer == -1)
			_exit(23);
		if (rep.sharer == 0) {
			for (;;)
				(void)pause();
		}
	}

	switch (how) {
	case END_EXEC:
	case END_EXEC_SHARED:
		if (write(END_REP, &rep, sizeof(rep)) != sizeof(rep))
			_exit(24);
		execv(helper_path, argv);
		_exit(25);
	case END_EXEC_HELD:
		if (write(END_REP, &rep, sizeof(rep)) != sizeof(rep))
			_exit(24);
		execl(helper_path, helper_path, "hold", (char *)NULL);
		_exit(25);
	case END_EXIT_SHARED:
		if (write(END_REP, &rep, sizeof(rep)) != sizeof(rep))
			_exit(24);
		_exit(0);
	case END_RFCFDG_SHARED:
		/* The pipe ends go with the table: report first. */
		if (write(END_REP, &rep, sizeof(rep)) != sizeof(rep))
			_exit(24);
		if (rfork(RFCFDG) == -1)
			_exit(26);
		_exit(scan_queues());
	case END_RFFDG_SHARED:
		if (rfork(RFFDG) == -1)
			_exit(26);
		rep.after = probe_child(q);
		if (write(END_REP, &rep, sizeof(rep)) != sizeof(rep))
			_exit(24);
		_exit(0);
	case END_DAEMON:
		/* The parent, the opener, exits in daemon(3). */
		if (daemon(1, 1) != 0)
			_exit(27);
		rep.after = probe_child(q);
		(void)write(END_REP, &rep, sizeof(rep));
		_exit(0);
	default:
		_exit(28);
	}
}

static bool
read_within(int fd, void *buf, size_t len, int ms)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, ms) != 1)
		return (false);
	return (read_all(fd, buf, len));
}

/* Move a descriptor to a number not below min. */
static int
fd_above(int fd, int min)
{
	int nfd;

	nfd = fcntl(fd, F_DUPFD, min);
	ATF_REQUIRE_MSG(nfd != -1, "F_DUPFD: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, close(fd));
	return (nfd);
}

/* Run one subject and check that its queue died where it went. */
static void
end_check(enum end_how how, const struct dq_ident_file *ident)
{
	const char *name = end_names[how];
	struct end_rep rep;
	struct dqt_rr r;
	pid_t pid;
	int go[2], held, hrep[2], i, pd, prep[2], status;
	bool got;

	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(hrep));
	ATF_REQUIRE_EQ(0, pipe(prep));
	/*
	 * The subject moves its three ends to fixed numbers: start them
	 * above those, whatever else this test has open.
	 */
	for (i = 0; i < 2; i++) {
		go[i] = fd_above(go[i], END_REP + 1);
		hrep[i] = fd_above(hrep[i], END_REP + 1);
		prep[i] = fd_above(prep[i], END_REP + 1);
	}
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		if (dup2(go[0], END_GO) != END_GO ||
		    dup2(hrep[1], END_HREP) != END_HREP ||
		    dup2(prep[1], END_REP) != END_REP)
			_exit(19);
		closefrom(END_REP + 1);
		(void)close(go[0]);
		(void)close(go[1]);
		(void)close(hrep[0]);
		(void)close(hrep[1]);
		(void)close(prep[0]);
		(void)close(prep[1]);
		end_subject(how, ident);
	}
	(void)close(go[0]);
	(void)close(hrep[1]);
	(void)close(prep[1]);

	memset(&rep, 0, sizeof(rep));
	ATF_REQUIRE_MSG(read_within(prep[0], &rep, sizeof(rep), 30000),
	    "%s: no report from the subject", name);
	if (how == END_EXEC_HELD) {
		/*
		 * The new image says what it holds and stays.  The process
		 * that opened the queue is alive, as another program, and a
		 * sharer of its old table holds the queue's file: only the
		 * exec itself can have ended the queue.  (An image that
		 * exits at once ends it at that exit, whatever exec did.)
		 */
		held = -1;
		ATF_REQUIRE_MSG(read_within(prep[0], &held, sizeof(held),
		    30000), "%s: no report from the new image", name);
		ATF_CHECK_EQ_MSG(0, held, "%s: the new image holds %d queue "
		    "descriptors", name, held);
	} else {
		ATF_REQUIRE_EQ_MSG(0, pdwait(pd, &status, WEXITED, NULL,
		    NULL), "%s: pdwait", name);
		/*
		 * The subject's status is its last image's or its own probe:
		 * no queue descriptor after the exec, none in the emptied
		 * table.
		 */
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "%s: subject status %#x", name, status);
	}
	if (how == END_RFFDG_SHARED || how == END_DAEMON)
		ATF_CHECK_EQ_MSG(0, rep.after, "%s: the later process holds "
		    "a queue (%d)", name, rep.after);

	/* The queue has died: the holder is answered, and with EIO. */
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&r, 0, sizeof(r));
	got = read_within(hrep[0], &r, sizeof(r), 20000);
	ATF_CHECK_MSG(got, "%s: the holder's read was not answered: the "
	    "queue %ju outlived its owner", name, (uintmax_t)rep.id);
	if (got)
		ATF_CHECK_MSG(r.rv == -1 && r.err == EIO, "%s: the holder's "
		    "read: rv %ld errno %d, want EIO", name, r.rv, r.err);
	(void)kill(rep.holder, SIGKILL);
	if (rep.sharer != 0)
		(void)kill(rep.sharer, SIGKILL);
	if (how == END_EXEC_HELD) {
		(void)pdkill(pd, SIGKILL);
		(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	}
	(void)close(pd);
	(void)close(go[1]);
	(void)close(hrep[0]);
	(void)close(prep[0]);
}

/* S4.  The plan's name for this case was exec_closes_and_kills. */
ATF_TC(exec_ends_queue);
ATF_TC_HEAD(exec_ends_queue, tc)
{
	atf_tc_set_md_var(tc, "descr", "the owner execs with the queue's "
	    "close-on-exec flag cleared, alone and while a process sharing "
	    "its table still holds the queue: the new image has no queue "
	    "descriptor and a descriptor the queue served fails EIO, also "
	    "while the new image is still running");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(exec_ends_queue, tc)
{
	struct dq_ident_file *ident;
	u_int before;

	dqt_require_test_access();
	helper_locate(tc);
	before = queues_now();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	end_check(END_EXEC, ident);
	end_check(END_EXEC_SHARED, ident);
	end_check(END_EXEC_HELD, ident);
	ATF_CHECK_MSG(queues_settle(before), "kern.dq.queues is %u, was %u",
	    queues_now(), before);
	free(ident);
}

ATF_TC(owner_leaves_shared_table);
ATF_TC_HEAD(owner_leaves_shared_table, tc)
{
	atf_tc_set_md_var(tc, "descr", "the owner exits, or leaves the "
	    "table with rfork(RFCFDG) or rfork(RFFDG), while a process "
	    "sharing the table still holds the queue: the queue dies there "
	    "and a descriptor it served fails EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(owner_leaves_shared_table, tc)
{
	struct dq_ident_file *ident;
	u_int before;

	dqt_require_test_access();
	helper_locate(tc);
	before = queues_now();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	end_check(END_EXIT_SHARED, ident);
	end_check(END_RFCFDG_SHARED, ident);
	end_check(END_RFFDG_SHARED, ident);
	ATF_CHECK_MSG(queues_settle(before), "kern.dq.queues is %u, was %u",
	    queues_now(), before);
	free(ident);
}

/*
 * An attached program whose supervisor is gone
 */

struct orphan_res {
	struct dqt_rr	 stat, open, sock, pair, pipe;
	struct dqt_rr	 child_stat;	/* stat(2) in a child forked afterwards */
	bool		 done;
};

#define	ORPHAN_GO	10	/* read: the supervisor is gone */
#define	ORPHAN_REP	11	/* write: struct orphan_res */
#define	ORPHAN_HOLD	12	/* write: the helper's "hold" report */

/*
 * The supervisor: attaches a child, leaves a sharer of its table holding
 * the queue's file (so that the queue dies of its owner's exit and not of
 * a last close), and exits.  The attached child is not signalled.  Once
 * the test says so it tries to obtain new things.
 */
enum orphan_how {
	ORPHAN_EXIT,		/* the owner exits */
	ORPHAN_EXEC,		/* the owner execs another image */
	ORPHAN_RFFDG		/* the owner leaves the shared table and lives */
};

static void
orphan_supervisor(enum orphan_how how)
{
	struct orphan_res res;
	struct stat sb;
	pid_t pid;
	int fds[2], pd, q, status;
	char b;

	q = dq_open();
	if (q == -1)
		_exit(20);
	pid = pdfork(&pd, PD_DAEMON);
	if (pid == -1)
		_exit(21);
	if (pid == 0) {
		memset(&res, 0, sizeof(res));
		if (read(ORPHAN_GO, &b, 1) != 1)
			_exit(0);
		SET(res.stat, stat("/", &sb));
		SET(res.open, open("/dev/null", O_RDONLY));
		SET(res.sock, socket(PF_INET, SOCK_DGRAM, 0));
		SET(res.pair, socketpair(PF_UNIX, SOCK_STREAM, 0, fds));
		/* Not a name and not a socket: never consulted. */
		SET(res.pipe, pipe(fds));
		pid = fork();
		if (pid == 0)
			_exit(stat("/", &sb) == -1 ? errno : 0);
		res.child_stat.rv = -2;
		if (pid != -1 && waitpid(pid, &status, 0) == pid &&
		    WIFEXITED(status)) {
			res.child_stat.rv = WEXITSTATUS(status) == 0 ? 0 : -1;
			res.child_stat.err = WEXITSTATUS(status);
		}
		res.done = true;
		(void)write(ORPHAN_REP, &res, sizeof(res));
		_exit(0);
	}
	if (dq_attach(q, pd) != 0)
		_exit(22);
	pid = rfork(RFPROC);
	if (pid == -1)
		_exit(23);
	if (pid == 0) {
		for (;;)
			(void)pause();
	}
	/* The sharer's pid, for the test to end it. */
	if (write(ORPHAN_REP, &pid, sizeof(pid)) != sizeof(pid))
		_exit(24);
	switch (how) {
	case ORPHAN_EXEC:
		/*
		 * The image reports the queue descriptors it has (none) and
		 * stays: the queue is then seen to have ended at the exec,
		 * not at the exit of the process that owned it.
		 */
		if (dup2(ORPHAN_REP, ORPHAN_HOLD) == -1)
			_exit(28);
		execl(helper_path, helper_path, "hold", (char *)NULL);
		_exit(25);
	case ORPHAN_RFFDG:
		if (rfork(RFFDG) == -1)
			_exit(26);
		/* Alive, in a table of its own that has no queue. */
		if (write(ORPHAN_REP, "u", 1) != 1)
			_exit(27);
		for (;;)
			(void)pause();
	default:
		_exit(0);
	}
}

static void
orphan_check(enum orphan_how how)
{
	struct orphan_res res;
	pid_t pid, sharer;
	int go[2], nq, pd, rep[2], status;
	char b;

	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(rep));
	ATF_REQUIRE(go[1] < ORPHAN_GO && rep[1] < ORPHAN_GO);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		if (dup2(go[0], ORPHAN_GO) != ORPHAN_GO ||
		    dup2(rep[1], ORPHAN_REP) != ORPHAN_REP)
			_exit(19);
		closefrom(ORPHAN_REP + 1);
		(void)close(go[0]);
		(void)close(go[1]);
		(void)close(rep[0]);
		(void)close(rep[1]);
		orphan_supervisor(how);
	}
	(void)close(go[0]);
	(void)close(rep[1]);
	sharer = 0;
	ATF_REQUIRE_MSG(read_within(rep[0], &sharer, sizeof(sharer), 30000),
	    "no report from the supervisor");
	if (how == ORPHAN_RFFDG) {
		/* The owner has left the table and goes on running. */
		ATF_REQUIRE_MSG(read_within(rep[0], &b, 1, 30000) && b == 'u',
		    "the supervisor did not leave its table");
	} else if (how == ORPHAN_EXEC) {
		/* The new image is running, with no queue descriptor. */
		nq = -1;
		ATF_REQUIRE_MSG(read_within(rep[0], &nq, sizeof(nq), 30000),
		    "no report from the exec'd image");
		ATF_REQUIRE_EQ_MSG(0, nq, "the exec'd image has %d queue "
		    "descriptors", nq);
	} else {
		ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "supervisor: status %#x", status);
	}

	/* The queue has no owner; its attached program is still there. */
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&res, 0, sizeof(res));
	ATF_REQUIRE_MSG(read_within(rep[0], &res, sizeof(res), 30000),
	    "no report from the attached program");
	ATF_CHECK(res.done);
	ATF_CHECK_MSG(res.stat.rv == -1 && res.stat.err == EIO,
	    "stat: rv %ld errno %d, want EIO", res.stat.rv, res.stat.err);
	ATF_CHECK_MSG(res.open.rv == -1 && res.open.err == EIO,
	    "open: rv %ld errno %d, want EIO", res.open.rv, res.open.err);
	ATF_CHECK_MSG(res.sock.rv == -1 && res.sock.err == EACCES,
	    "socket: rv %ld errno %d, want EACCES", res.sock.rv,
	    res.sock.err);
	ATF_CHECK_MSG(res.pair.rv == -1 && res.pair.err == EACCES,
	    "socketpair: rv %ld errno %d, want EACCES", res.pair.rv,
	    res.pair.err);
	ATF_CHECK_MSG(res.pipe.rv == 0, "pipe: rv %ld errno %d, want 0",
	    res.pipe.rv, res.pipe.err);
	ATF_CHECK_MSG(res.child_stat.rv == -1 && res.child_stat.err == EIO,
	    "stat in a later child: rv %ld errno %d, want EIO",
	    res.child_stat.rv, res.child_stat.err);
	(void)kill(sharer, SIGKILL);
	if (how != ORPHAN_EXIT) {
		/* The owner (or the image it became) was running all along. */
		ATF_CHECK_EQ(0, pdkill(pd, SIGKILL));
		(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	}
	(void)close(pd);
	(void)close(go[1]);
	(void)close(rep[0]);
}

ATF_TC(orphan_gets_nothing_new);
ATF_TC_HEAD(orphan_gets_nothing_new, tc)
{
	atf_tc_set_md_var(tc, "descr", "a program attached to a queue whose "
	    "owner exited (the queue's file still held by a sharer of the "
	    "owner's table) goes on running and obtains nothing new by "
	    "name: stat and open are EIO, socket and socketpair EACCES, in "
	    "a child it forks too; pipe, which names nothing, succeeds");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(orphan_gets_nothing_new, tc)
{

	dqt_require_test_access();
	dqt_require_plane();
	helper_locate(tc);
	orphan_check(ORPHAN_EXIT);
}

ATF_TC(orphan_after_exec_or_unshare);
ATF_TC_HEAD(orphan_after_exec_or_unshare, tc)
{
	atf_tc_set_md_var(tc, "descr", "the same for a program attached to "
	    "a queue whose owner called execve, and whose owner left the "
	    "shared descriptor table with rfork(RFFDG) and is still running: "
	    "the queue died there, the program was not signalled and "
	    "obtains nothing new by name");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(orphan_after_exec_or_unshare, tc)
{

	dqt_require_test_access();
	dqt_require_plane();
	helper_locate(tc);
	orphan_check(ORPHAN_EXEC);
	orphan_check(ORPHAN_RFFDG);
}

/*
 * Transfer and copies
 */

struct xfer_res {
	int	stream_send;	/* sendmsg(SCM_RIGHTS): 0 or errno */
	int	stream_recv;	/* the peer's recv afterwards: 0 or errno */
	int	dgram_send;
	int	dgram_recv;
	int	xfer_unlimited;	/* cap_xfer_limit(): 0 or errno */
	int	xfer_once;
	int	xfer_none;
	int	cloexec_unlocked;
	int	cloexec_once;
	int	cloexec_locked;
	int	clofork_unlocked;
	int	clofork_once;
	int	clofork_locked;
	int	stats;		/* GET_STATS afterwards: 0 or errno */
};

static int
peer_recv(int sock)
{
	char b;

	return (recv(sock, &b, 1, MSG_DONTWAIT) == -1 ? errno : 0);
}

#define	ERRNO_OF(call)	((call) == -1 ? errno : 0)

static void
child_transfer(void *arg __unused, void *result)
{
	struct xfer_res *res = result;
	int q, sp[2];

	memset(res, 0xff, sizeof(*res));
	q = dq_open();
	if (q == -1)
		_exit(6);
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sp) != 0)
		_exit(7);
	res->stream_send = qd_sendfd(sp[0], q);
	res->stream_recv = peer_recv(sp[1]);
	(void)close(sp[0]);
	(void)close(sp[1]);
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sp) != 0)
		_exit(7);
	res->dgram_send = qd_sendfd(sp[0], q);
	res->dgram_recv = peer_recv(sp[1]);
	(void)close(sp[0]);
	(void)close(sp[1]);

	/* The three states only tighten, and are as tight as they go. */
	res->xfer_unlimited = ERRNO_OF(cap_xfer_limit(q, CAP_XFER_UNLIMITED));
	res->xfer_once = ERRNO_OF(cap_xfer_limit(q, CAP_XFER_ONCE));
	res->xfer_none = ERRNO_OF(cap_xfer_limit(q, CAP_XFER_NONE));
	res->cloexec_unlocked = ERRNO_OF(cap_cloexec_limit(q,
	    CAP_CLOEXEC_UNLOCKED));
	res->cloexec_once = ERRNO_OF(cap_cloexec_limit(q, CAP_CLOEXEC_ONCE));
	res->cloexec_locked = ERRNO_OF(cap_cloexec_limit(q,
	    CAP_CLOEXEC_LOCKED));
	res->clofork_unlocked = ERRNO_OF(cap_clofork_limit(q,
	    CAP_CLOFORK_UNLOCKED));
	res->clofork_once = ERRNO_OF(cap_clofork_limit(q, CAP_CLOFORK_ONCE));
	res->clofork_locked = ERRNO_OF(cap_clofork_limit(q,
	    CAP_CLOFORK_LOCKED));
	res->stats = qd_stats(q);
}

#define	XF_CHECK(field, want)						\
	ATF_CHECK_EQ_MSG((want), res.field, #field " is %d, expected %d",\
	    res.field, (want))

/*
 * S5.  pddupfd(2) is queue_descriptor_states' last column; the
 * mac_capability channel sends are that suite's channel_send_pinned.
 */
ATF_TC(transfer_refused);
ATF_TC_HEAD(transfer_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "the queue descriptor is refused "
	    "ENOTCAPABLE by sendmsg(SCM_RIGHTS) on a stream and on a "
	    "datagram socket and nothing reaches the peer; its transfer, "
	    "close-on-exec and close-on-fork states cannot be loosened; the "
	    "queue still answers its owner");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(transfer_refused, tc)
{
	struct xfer_res res;

	dqt_require_test_access();
	dqt_run_child(child_transfer, NULL, &res, sizeof(res));
	XF_CHECK(stream_send, ENOTCAPABLE);
	XF_CHECK(stream_recv, EAGAIN);
	XF_CHECK(dgram_send, ENOTCAPABLE);
	XF_CHECK(dgram_recv, EAGAIN);
	XF_CHECK(xfer_unlimited, ENOTCAPABLE);
	XF_CHECK(xfer_once, ENOTCAPABLE);
	XF_CHECK(xfer_none, 0);
	XF_CHECK(cloexec_unlocked, ENOTCAPABLE);
	XF_CHECK(cloexec_once, ENOTCAPABLE);
	XF_CHECK(cloexec_locked, 0);
	XF_CHECK(clofork_unlocked, ENOTCAPABLE);
	XF_CHECK(clofork_once, ENOTCAPABLE);
	XF_CHECK(clofork_locked, 0);
	XF_CHECK(stats, 0);
}

enum { CP_DUP, CP_DUP2, CP_DUPFD, CP_DUPFD_CLOEXEC, CP_FDESC, CP_N };
static const char *const cp_names[CP_N] = { "dup", "dup2", "F_DUPFD",
    "F_DUPFD_CLOEXEC", "open of fdesc/N" };
/*
 * F_GETFD of each copy, advisory for a queue: the request's own flags for
 * the dups; an fdescfs open copies the entry it names, flags and all
 * (dupfdopen), here those of dq_open().
 */
static const int cp_getfd[CP_N] = { 0, 0, 0, FD_CLOEXEC,
    FD_CLOEXEC | FD_CLOFORK };

struct cp_row {
	int	fd;		/* the copy, or -1 */
	int	err;		/* errno when it could not be made */
	int	getfd;
	int	getfl;
	int	stats;		/* GET_STATS in the owner: 0 or errno */
	int	fork_stats;	/* GET_STATS in a fork child: 0 or errno */
	int	scm;		/* sendmsg(SCM_RIGHTS): 0 or errno */
};

/*
 * The subject: makes every kind of copy, fills a row for each, clears the
 * close-on-exec flag of all of them and becomes the helper, whose exit
 * status counts the queue descriptors it was given.
 */
static void
copies_subject(int rep)
{
	struct cp_row row[CP_N];
	char path[64];
	char *const argv[] = { helper_path, NULL };
	int i, q, sp[2];

	memset(row, 0xff, sizeof(row));
	q = dq_open();
	if (q == -1 || socketpair(PF_UNIX, SOCK_STREAM, 0, sp) != 0)
		_exit(20);
	snprintf(path, sizeof(path), "%s/%d", DQT_FDESC_DIR, q);
	for (i = 0; i < CP_N; i++) {
		errno = 0;
		switch (i) {
		case CP_DUP:
			row[i].fd = dup(q);
			break;
		case CP_DUP2:
			row[i].fd = dup2(q, 40);
			break;
		case CP_DUPFD:
			row[i].fd = fcntl(q, F_DUPFD, 50);
			break;
		case CP_DUPFD_CLOEXEC:
			row[i].fd = fcntl(q, F_DUPFD_CLOEXEC, 60);
			break;
		default:
			row[i].fd = open(path, O_RDWR);
			break;
		}
		row[i].err = errno;
		if (row[i].fd == -1)
			continue;
		row[i].getfd = fcntl(row[i].fd, F_GETFD);
		row[i].getfl = fcntl(row[i].fd, F_GETFL);
		row[i].stats = qd_stats(row[i].fd);
		row[i].fork_stats = qd_fork_probe(row[i].fd, false);
		row[i].scm = qd_sendfd(sp[0], row[i].fd);
		(void)fcntl(row[i].fd, F_SETFD, 0);
	}
	(void)fcntl(q, F_SETFD, 0);
	if (write(rep, row, sizeof(row)) != sizeof(row))
		_exit(21);
	execv(helper_path, argv);
	_exit(22);
}

/* S7. */
ATF_TC_WITH_CLEANUP(dup_carries_states);
ATF_TC_HEAD(dup_carries_states, tc)
{
	atf_tc_set_md_var(tc, "descr", "dup, dup2, F_DUPFD, F_DUPFD_CLOEXEC "
	    "and an fdescfs open of the queue descriptor each give a copy "
	    "that works in the owner, shows O_RDWR alone in F_GETFL and, in "
	    "F_GETFD, the request's own flags (the named entry's for the "
	    "fdescfs open), and is in no fork child, "
	    "cannot be sent, and is absent after exec even with its "
	    "close-on-exec flag cleared");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dup_carries_states, tc)
{
	struct cp_row row[CP_N];
	pid_t pid;
	int i, pd, rep[2], status;

	dqt_require_test_access();
	helper_locate(tc);
	dqt_mount_fdesc(NULL);
	ATF_REQUIRE_EQ(0, pipe(rep));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(pid != -1, "pdfork: %s", strerror(errno));
	if (pid == 0) {
		if (dup2(rep[1], 3) != 3)
			_exit(19);
		closefrom(4);
		copies_subject(3);
	}
	(void)close(rep[1]);
	ATF_REQUIRE_MSG(read_within(rep[0], row, sizeof(row), 30000),
	    "no report from the subject");
	ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the exec'd image holds a queue (status %#x)", status);
	for (i = 0; i < CP_N; i++) {
		printf("%s: fd %d errno %d getfd %#x getfl %#x stats %d "
		    "fork %d scm %d\n", cp_names[i], row[i].fd, row[i].err,
		    row[i].getfd, row[i].getfl, row[i].stats,
		    row[i].fork_stats, row[i].scm);
		ATF_CHECK_MSG(row[i].fd != -1, "%s: errno %d", cp_names[i],
		    row[i].err);
		if (row[i].fd == -1)
			continue;
		ATF_CHECK_EQ_MSG(cp_getfd[i], row[i].getfd, "%s: F_GETFD "
		    "%#x", cp_names[i], row[i].getfd);
		ATF_CHECK_EQ_MSG(O_RDWR, row[i].getfl, "%s: F_GETFL %#x",
		    cp_names[i], row[i].getfl);
		ATF_CHECK_EQ_MSG(0, row[i].stats, "%s: GET_STATS errno %d",
		    cp_names[i], row[i].stats);
		ATF_CHECK_EQ_MSG(EBADF, row[i].fork_stats, "%s: in a fork "
		    "child: %d, want EBADF", cp_names[i], row[i].fork_stats);
		ATF_CHECK_EQ_MSG(ENOTCAPABLE, row[i].scm, "%s: sendmsg: %d, "
		    "want ENOTCAPABLE", cp_names[i], row[i].scm);
	}
	(void)close(pd);
	(void)close(rep[0]);
}
ATF_TC_CLEANUP(dup_carries_states, tc)
{

	dqt_umount_fdesc();
}

/*
 * Other callers
 */

#define	AIO_UNSAFE	"vfs.aio.enable_unsafe"

static void
aio_unsafe_restore(void)
{
	FILE *f;
	u_int old;

	f = fopen("aio_unsafe.save", "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%u", &old) == 1)
		dqt_sysctl_set_uint(AIO_UNSAFE, old);
	(void)fclose(f);
}

static void
child_second_open(void *arg __unused, void *result)
{
	struct ops_res *res = result;
	int q;

	q = dq_open();
	if (q == -1)
		_exit(6);
	ops_quiet(q, res);
	res->done = true;
}

/* S8. */
ATF_TC_WITH_CLEANUP(owner_only_misc);
ATF_TC_HEAD(owner_only_misc, tc)
{
	atf_tc_set_md_var(tc, "descr", "aio_read(2) on the queue is not the "
	    "owner reading: EOPNOTSUPP while unsafe AIO is off, EPERM from "
	    "the AIO daemon when it is on; a supervisor that opens and then "
	    "calls daemon(3) has lost its queue (the opener exited); a "
	    "second process's open is another queue");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(owner_only_misc, tc)
{
	static char buf[4096];
	struct dq_ident_file *ident;
	struct dq_stats st;
	struct ops_res second;
	struct aiocb cb;
	FILE *f;
	u_int old;
	int error, i, q;

	helper_locate(tc);
	q = dqt_open_queue();
	ATF_REQUIRE_EQ(0, dq_get_stats(q, &st));

	/* aio_read(2). */
	ATF_REQUIRE(dqt_sysctl_get_uint(AIO_UNSAFE, &old));
	f = fopen("aio_unsafe.save", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%u\n", old);
	ATF_REQUIRE_EQ(0, fclose(f));
	dqt_sysctl_set_uint(AIO_UNSAFE, 0);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = q;
	cb.aio_buf = buf;
	cb.aio_nbytes = sizeof(buf);
	errno = 0;
	ATF_CHECK_EQ(-1, aio_read(&cb));
	ATF_CHECK_EQ_MSG(EOPNOTSUPP, errno, "aio_read, unsafe off: errno %d",
	    errno);
	dqt_sysctl_set_uint(AIO_UNSAFE, 1);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = q;
	cb.aio_buf = buf;
	cb.aio_nbytes = sizeof(buf);
	ATF_REQUIRE_EQ_MSG(0, aio_read(&cb), "aio_read, unsafe on: %s",
	    strerror(errno));
	error = EINPROGRESS;
	for (i = 0; i < 200 && error == EINPROGRESS; i++) {
		dqt_msleep(50);
		error = aio_error(&cb);
	}
	ATF_CHECK_EQ_MSG(EPERM, error, "aio_error: %d, want EPERM", error);
	if (error != EINPROGRESS)
		ATF_CHECK_EQ(-1, aio_return(&cb));
	else
		(void)aio_cancel(q, &cb);
	aio_unsafe_restore();

	/* daemon(3). */
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	end_check(END_DAEMON, ident);
	free(ident);

	/* A second process: its own queue, which it operates. */
	memset(&second, 0, sizeof(second));
	dqt_run_child(child_second_open, NULL, &second, sizeof(second));
	ATF_CHECK_MSG(second.id != 0 && second.id != st.ds_queue_id,
	    "second open: queue id %ju, the first is %ju",
	    (uintmax_t)second.id, (uintmax_t)st.ds_queue_id);
	ATF_CHECK_EQ_MSG(-1, second.r[OP_READ].rv, "second open: read %ld",
	    second.r[OP_READ].rv);
	ATF_CHECK_EQ(EAGAIN, second.r[OP_READ].err);
	/* The first is untouched by all of the above. */
	ATF_CHECK_EQ(0, dq_get_stats(q, &st));
	(void)close(q);
}
ATF_TC_CLEANUP(owner_only_misc, tc)
{

	aio_unsafe_restore();
}

/*
 * Races
 */

/* InUse of the "dq" malloc type, from vmstat -m; -1 if it cannot be read. */
static long
dq_malloc_inuse(void)
{
	char line[256], name[64];
	FILE *p;
	long use, found;

	p = popen("/usr/bin/vmstat -m", "r");
	if (p == NULL)
		return (-1);
	found = -1;
	while (fgets(line, sizeof(line), p) != NULL) {
		if (sscanf(line, "%63s %ld", name, &use) == 2 &&
		    strcmp(name, "dq") == 0)
			found = use;
	}
	(void)pclose(p);
	return (found);
}

static void *
reopen_forever(void *arg __unused)
{
	int fd;

	for (;;) {
		fd = open(DQ_DEVICE, O_RDWR);
		if (fd != -1)
			(void)close(fd);
	}
	return (NULL);
}

#define	EXIT_STORM	2000

/*
 * One round: the owner makes a sharer of its table and exits while the
 * sharer closes the queue's number and another thread of the owner is
 * opening queues.  A wrong answer is a byte on bad.
 */
static void
exit_storm_owner(int bad, int round)
{
	struct dq_stats st;
	pthread_t thr;
	pid_t pid;
	int q, rv;

	q = dq_open();
	if (q == -1) {
		(void)write(bad, "o", 1);
		_exit(0);
	}
	pid = rfork(RFPROC);
	if (pid == -1) {
		(void)write(bad, "r", 1);
		_exit(0);
	}
	if (pid == 0) {
		/* Never served: the owner refuses it, or the queue is dead. */
		rv = dq_get_stats(q, &st);
		if (rv != -1 || (errno != EPERM && errno != ENXIO))
			(void)write(bad, "s", 1);
		if ((round & 1) != 0)
			(void)sched_yield();
		if (close(q) != 0)
			(void)write(bad, "c", 1);
		_exit(0);
	}
	if (pthread_create(&thr, NULL, reopen_forever, NULL) != 0)
		(void)write(bad, "t", 1);
	if ((round & 2) != 0)
		(void)sched_yield();
	_exit(0);
}

/* S9. */
ATF_TC(exit_close_storm);
ATF_TC_HEAD(exit_close_storm, tc)
{
	atf_tc_set_md_var(tc, "descr", "2000 times: the owner exits while a "
	    "sharer of its table closes the queue and another of its "
	    "threads opens queues; the sharer is answered EPERM or ENXIO "
	    "only, and no queue and no dq memory is left behind");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "1800");
}
ATF_TC_BODY(exit_close_storm, tc)
{
	char badbuf[64];
	struct pollfd pfd;
	ssize_t n;
	pid_t pid;
	long mem_before, mem_now;
	u_int before;
	int bad[2], i, nbad, status;

	dqt_require_test_access();
	before = queues_now();
	mem_before = dq_malloc_inuse();
	ATF_REQUIRE_MSG(mem_before >= 0, "vmstat -m has no dq type");
	ATF_REQUIRE_EQ(0, pipe(bad));
	for (i = 0; i < EXIT_STORM; i++) {
		pid = fork();
		ATF_REQUIRE_MSG(pid != -1, "fork: %s", strerror(errno));
		if (pid == 0) {
			(void)close(bad[0]);
			exit_storm_owner(bad[1], i);
		}
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "round %d: owner status %#x", i, status);
	}
	/* End of file once every sharer has exited. */
	(void)close(bad[1]);
	nbad = 0;
	pfd.fd = bad[0];
	pfd.events = POLLIN;
	for (;;) {
		ATF_REQUIRE_MSG(poll(&pfd, 1, 60000) == 1,
		    "sharers still running");
		n = read(bad[0], badbuf, sizeof(badbuf));
		if (n <= 0)
			break;
		printf("wrong answers: %.*s\n", (int)n, badbuf);
		nbad += (int)n;
	}
	(void)close(bad[0]);
	ATF_CHECK_EQ_MSG(0, nbad, "%d wrong answers", nbad);
	ATF_CHECK_MSG(queues_settle(before), "kern.dq.queues is %u, was %u",
	    queues_now(), before);
	mem_now = -1;
	for (i = 0; i < 100; i++) {
		mem_now = dq_malloc_inuse();
		if (mem_now == mem_before)
			break;
		dqt_msleep(50);
	}
	ATF_CHECK_EQ_MSG(mem_before, mem_now, "dq malloc type: %ld in use, "
	    "was %ld", mem_now, mem_before);
}

#define	INSPECT_ROUNDS	200

/* S10. */
ATF_TC(inspect_vs_close);
ATF_TC_HEAD(inspect_vs_close, tc)
{
	atf_tc_set_md_var(tc, "descr", "200 times, while another process "
	    "reads this one's descriptor table (kern.proc.filedesc, kcmp): "
	    "the owner closes its queue with an unattached reader of a "
	    "served descriptor waiting, and the reader fails EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "1800");
}
ATF_TC_BODY(inspect_vs_close, tc)
{
	static char evbuf[65536];
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct kinfo_file *kif;
	struct dqt_rr r;
	uint64_t object;
	unsigned char buf[16];
	pid_t holder, inspector, self;
	u_int before;
	int cnt, fd, hp[2], i, q, reason, status;

	dqt_require_test_access();
	before = queues_now();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	make_ident(ident);
	self = getpid();
	inspector = fork();
	ATF_REQUIRE(inspector != -1);
	if (inspector == 0) {
		for (;;) {
			kif = kinfo_getfile(self, &cnt);
			free(kif);
			for (fd = 3; fd < 12; fd++)
				(void)kcmp(self, self, KCMP_FILE, fd, fd);
		}
	}
	dq_policy_default(&pol);
	for (i = 0; i < INSPECT_ROUNDS; i++) {
		q = dq_open();
		ATF_REQUIRE_MSG(q != -1, "round %d: %s", i, strerror(errno));
		ATF_REQUIRE_EQ(0, dq_mint_file(q, ident, &pol, &object, &fd,
		    &reason));
		ATF_REQUIRE_EQ(0, pipe(hp));
		holder = fork();
		ATF_REQUIRE(holder != -1);
		if (holder == 0) {
			SET(r, read(fd, buf, sizeof(buf)));
			(void)write(hp[1], &r, sizeof(r));
			_exit(0);
		}
		(void)close(hp[1]);
		/* Its request is in the queue: it is waiting. */
		ATF_REQUIRE_MSG(read(q, evbuf, sizeof(evbuf)) > 0,
		    "round %d: queue read: %s", i, strerror(errno));
		ATF_REQUIRE_EQ(0, close(q));
		memset(&r, 0, sizeof(r));
		ATF_REQUIRE_MSG(read_within(hp[0], &r, sizeof(r), 20000),
		    "round %d: the reader was not answered", i);
		ATF_REQUIRE_MSG(r.rv == -1 && r.err == EIO, "round %d: rv "
		    "%ld errno %d, want EIO", i, r.rv, r.err);
		ATF_REQUIRE_EQ(holder, waitpid(holder, &status, 0));
		(void)close(fd);
		(void)close(hp[0]);
	}
	(void)kill(inspector, SIGKILL);
	ATF_REQUIRE_EQ(inspector, waitpid(inspector, &status, 0));
	ATF_CHECK_MSG(queues_settle(before), "kern.dq.queues is %u, was %u",
	    queues_now(), before);
	free(ident);
}

/*
 * The Linux ABI (L8)
 */

#define	LX_NRES		10
#define	LINUX_EPERM	1
#define	LINUX_EAGAIN	11
#define	LINUX_EINVAL	22

/* Run dq_owner_linux with its four words; collect its answers. */
static void
run_owner_linux(const atf_tc_t *tc, long mode, long pid, long qfd, long plain,
    long *lr)
{
	char *const argv[] = { __DECONST(char *, "dq_owner_linux"), NULL };
	char *const envp[] = { NULL };
	long in[4] = { mode, pid, qfd, plain };
	pid_t child;
	int image, ip[2], op[2], status;

	/* Built with the tests (Makefile); missing, the row fails. */
	dqt_copy_helper(tc, "dq_owner_linux", "dq_owner_linux");
	image = open("dq_owner_linux", O_RDONLY);
	ATF_REQUIRE(image != -1);
	ATF_REQUIRE_EQ(0, pipe(ip));
	ATF_REQUIRE_EQ(0, pipe(op));
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		if (dup2(ip[0], STDIN_FILENO) != STDIN_FILENO ||
		    dup2(op[1], STDOUT_FILENO) != STDOUT_FILENO)
			_exit(126);
		(void)close(ip[0]);
		(void)close(ip[1]);
		(void)close(op[0]);
		(void)close(op[1]);
		fexecve(image, argv, envp);
		_exit(127);
	}
	(void)close(ip[0]);
	(void)close(op[1]);
	(void)close(image);
	ATF_REQUIRE_EQ((ssize_t)sizeof(in), write(ip[1], in, sizeof(in)));
	ATF_REQUIRE_MSG(read_within(op[0], lr, LX_NRES * sizeof(*lr), 60000),
	    "no answers from dq_owner_linux");
	(void)close(ip[1]);
	(void)close(op[0]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	/* 127: the Linux ABI is not loaded.  Not a skip either. */
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "dq_owner_linux: status %#x", status);
}

ATF_TC(linux_pidfd_getfd_refused);
ATF_TC_HEAD(linux_pidfd_getfd_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a Linux process holding a pidfd of "
	    "a native queue owner is refused the queue by pidfd_getfd "
	    "(EPERM) and still gets an ordinary descriptor of that process");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* The program is amd64 Linux: the one permitted kind of skip. */
	atf_tc_set_md_var(tc, "require.arch", "amd64");
}
ATF_TC_BODY(linux_pidfd_getfd_refused, tc)
{
	struct dq_stats st;
	long lr[LX_NRES];
	int plain, q;

	q = dqt_open_queue();
	plain = open("/dev/null", O_RDWR);
	ATF_REQUIRE(plain != -1);
	memset(lr, 0x55, sizeof(lr));
	run_owner_linux(tc, 0, getpid(), q, plain, lr);
	ATF_CHECK_MSG(lr[0] >= 0, "pidfd_open: %ld", lr[0]);
	ATF_CHECK_EQ_MSG(-LINUX_EPERM, lr[1], "pidfd_getfd of the queue: "
	    "%ld", lr[1]);
	ATF_CHECK_MSG(lr[2] >= 0, "pidfd_getfd of /dev/null: %ld", lr[2]);
	ATF_CHECK_EQ(0, dq_get_stats(q, &st));
	(void)close(plain);
	(void)close(q);
}

ATF_TC(linux_unshare_files);
ATF_TC_HEAD(linux_unshare_files, tc)
{
	atf_tc_set_md_var(tc, "descr", "a Linux queue owner and a process "
	    "sharing its table (clone with CLONE_FILES) are both refused "
	    "unshare(CLONE_FILES), which would drop the queue (EINVAL); "
	    "the sharer may not read the queue (EPERM) and the owner's "
	    "queue is alive afterwards");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.arch", "amd64");
}
ATF_TC_BODY(linux_unshare_files, tc)
{
	long lr[LX_NRES];

	dqt_require_test_access();
	memset(lr, 0x55, sizeof(lr));
	run_owner_linux(tc, 1, 0, 0, 0, lr);
	ATF_CHECK_MSG(lr[3] >= 0, "open: %ld", lr[3]);
	ATF_CHECK_MSG(lr[4] > 0, "clone: %ld", lr[4]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[5], "the sharer's unshare: %ld",
	    lr[5]);
	ATF_CHECK_EQ_MSG(-LINUX_EPERM, lr[6], "the sharer's read: %ld",
	    lr[6]);
	ATF_CHECK_EQ_MSG(-LINUX_EINVAL, lr[7], "the owner's unshare: %ld",
	    lr[7]);
	ATF_CHECK_EQ_MSG(0, lr[8], "the owner's FIONBIO: %ld", lr[8]);
	ATF_CHECK_EQ_MSG(-LINUX_EAGAIN, lr[9], "the owner's read: %ld",
	    lr[9]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sharer_cannot_operate);
	ATF_TP_ADD_TC(tp, sharer_outlives_opener);
	ATF_TP_ADD_TC(tp, queue_descriptor_states);
	ATF_TP_ADD_TC(tp, fork_not_inherited);
	ATF_TP_ADD_TC(tp, open_fork_storm);
	ATF_TP_ADD_TC(tp, exec_ends_queue);
	ATF_TP_ADD_TC(tp, owner_leaves_shared_table);
	ATF_TP_ADD_TC(tp, orphan_gets_nothing_new);
	ATF_TP_ADD_TC(tp, orphan_after_exec_or_unshare);
	ATF_TP_ADD_TC(tp, transfer_refused);
	ATF_TP_ADD_TC(tp, dup_carries_states);
	ATF_TP_ADD_TC(tp, owner_only_misc);
	ATF_TP_ADD_TC(tp, exit_close_storm);
	ATF_TP_ADD_TC(tp, inspect_vs_close);
	ATF_TP_ADD_TC(tp, linux_pidfd_getfd_refused);
	ATF_TP_ADD_TC(tp, linux_unshare_files);
	return (atf_no_error());
}
