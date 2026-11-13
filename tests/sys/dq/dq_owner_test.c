/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Who may operate a queue, and what its descriptor does in the descriptor
 * table (sc-q).
 *
 * These cases record what the kernel answers BEFORE the queue has an owner:
 * the descriptor is a bearer token.  A process that shares the opener's
 * descriptor table (rfork(2) without RFFDG) operates the queue like the
 * opener, and goes on doing so after the opener has exited, the queue
 * living until the last close; the descriptor is inherited by fork(2) and
 * across execve(2) unless the opener asked otherwise, passes over a local
 * socket, and is taken by pddupfd(2).  The commit that gives the queue an
 * owner changes the expected values here, in the same diff as the kernel.
 *
 * No subject below makes an ATF call: each runs in a child and reports
 * over a pipe.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ttycom.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
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
	char buf[4096];
	int kq, on;

	SET(res->r[OP_STATS], dq_get_stats(q, &st));
	res->id = res->r[OP_STATS].rv == 0 ? st.ds_queue_id : 0;
	SET(res->r[OP_STATS2], dq_get_stats2(q, &st2));
	on = 1;
	SET(res->r[OP_FIONBIO], ioctl(q, FIONBIO, &on));
	SET(res->r[OP_READ], read(q, buf, sizeof(buf)));
	SET(res->r[OP_READ_SHORT], read(q, buf, 1));
	SET(res->r[OP_NOTTY], ioctl(q, TIOCEXCL));
	pfd.fd = q;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;
	SET(res->r[OP_POLL], poll(&pfd, 1, 0));
	res->revents = pfd.revents;
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
	ATF_CHECK_EQ_MSG(1, res->r[OP_POLL].rv, "%s: poll returned %ld", who,
	    res->r[OP_POLL].rv);
	ATF_CHECK_EQ_MSG(POLLOUT, res->revents, "%s: revents %#x, want "
	    "POLLOUT", who, res->revents);
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

/*
 * A sharer of the opener's descriptor table
 */

struct sharer_res {
	struct ops_res	 opener;
	struct ops_res	 sharer;
	int		 sharer_status;	/* wait status, -1: not collected */
};

/*
 * The opener: opens the queue as libdq does, then rfork(2)s a process that
 * shares its descriptor table and runs every operation on the same
 * descriptor number.  The opener's quiet operations run first and its
 * making ones last, so that each reader finds the queue empty.
 */
static void
child_opener_sharer(void *arg, void *result)
{
	const struct dq_ident_file *ident = arg;
	struct sharer_res *res = result;
	struct ops_res sres;
	pid_t pid;
	int q, rp[2], status, t_opener, t_sharer;

	res->sharer_status = -1;
	q = dq_open();
	if (q == -1 || pipe(rp) != 0)
		_exit(6);
	/* Forked: neither holds the O_CLOFORK queue. */
	t_opener = idle_target();
	t_sharer = idle_target();
	if (t_opener == -1 || t_sharer == -1)
		_exit(7);
	ops_quiet(q, &res->opener);

	pid = rfork(RFPROC);
	if (pid == -1)
		_exit(8);
	if (pid == 0) {
		memset(&sres, 0, sizeof(sres));
		ops_quiet(q, &sres);
		ops_make(q, ident, t_sharer, &sres);
		(void)write(rp[1], &sres, sizeof(sres));
		_exit(0);
	}
	if (read_all(rp[0], &res->sharer, sizeof(res->sharer)) &&
	    waitpid(pid, &status, 0) == pid)
		res->sharer_status = status;
	ops_make(q, ident, t_opener, &res->opener);
	idle_target_end(t_opener);
	idle_target_end(t_sharer);
}

ATF_TC(sharer_operates);
ATF_TC_HEAD(sharer_operates, tc)
{
	atf_tc_set_md_var(tc, "descr", "a process sharing the opener's "
	    "descriptor table (rfork without RFFDG) operates the queue: "
	    "statistics, FIONBIO, read, poll, kevent, observer and object "
	    "mint, revoke, attach, each answered as the opener is");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sharer_operates, tc)
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
	check_served("sharer", &res.sharer, res.opener.id);
	free(ident);
}

struct outlive_arg {
	const struct dq_ident_file *ident;
	int		 go;		/* read: the opener is gone */
	int		 rep;		/* write: the sharer's ops_res */
};

/*
 * The opener exits and leaves the sharer with the table.  The sharer waits
 * for the test, which has by then reaped the opener, and never returns to
 * the harness.
 */
static void
child_opener_exits(void *arg, void *result)
{
	struct outlive_arg *a = arg;
	struct ops_res *res = result;
	struct ops_res sres;
	pid_t pid;
	int q, target;
	char b;

	q = dq_open();
	if (q == -1)
		_exit(6);
	target = idle_target();
	if (target == -1)
		_exit(7);
	ops_quiet(q, res);
	res->done = true;

	pid = rfork(RFPROC);
	if (pid == -1)
		_exit(8);
	if (pid != 0)
		return;
	memset(&sres, 0, sizeof(sres));
	if (read(a->go, &b, 1) != 1)
		_exit(9);
	ops_quiet(q, &sres);
	ops_make(q, a->ident, target, &sres);
	/* The last close of the queue. */
	SET(sres.r[OP_CLOSE], close(q));
	idle_target_end(target);
	(void)write(a->rep, &sres, sizeof(sres));
	_exit(0);
}

ATF_TC(sharer_outlives_opener);
ATF_TC_HEAD(sharer_outlives_opener, tc)
{
	atf_tc_set_md_var(tc, "descr", "the opener exits while a process "
	    "sharing its descriptor table holds the queue: the queue lives "
	    "on, the sharer operates it as before, and closes it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sharer_outlives_opener, tc)
{
	struct dq_ident_file *ident;
	struct dqt_child ch;
	struct outlive_arg a;
	struct ops_res opener, sharer;
	int go[2], rep[2], status;
	char b;

	dqt_require_test_access();
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
	status = dqt_wait(&ch, &opener, sizeof(opener));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "opener: status %#x", status);
	ATF_REQUIRE_MSG(opener.done && opener.id != 0,
	    "the opener has no queue");

	/* The opener has been reaped: it is out of the table. */
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&sharer, 0, sizeof(sharer));
	ATF_REQUIRE_MSG(read_all(rep[0], &sharer, sizeof(sharer)),
	    "no report from the sharer");
	check_served("sharer", &sharer, opener.id);
	ATF_CHECK_EQ_MSG(0, sharer.r[OP_CLOSE].rv, "close: errno %d",
	    sharer.r[OP_CLOSE].err);
	/* It has exited: nothing else holds the write end. */
	ATF_CHECK_EQ(0, read(rep[0], &b, 1));
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
	[QD_RAW] = { "open(O_RDWR)", {
		.getfd = 0, .getfl = O_RDWR, .dup_errno = 0, .dup_getfd = 0,
		.fork_errno = 0, .dupfork_errno = 0, .exec_status = 0,
		.scm_errno = 0, .scm_getfd = 0, .scm_stats = 0,
		.pddup_errno = 0, .pddup_getfd = FD_CLOEXEC,
		.pddup_stats = 0 } },
	[QD_LIBDQ] = { "dq_open()", {
		.getfd = FD_CLOEXEC | FD_CLOFORK, .getfl = O_RDWR,
		.dup_errno = 0, .dup_getfd = 0,
		.fork_errno = EBADF, .dupfork_errno = 0, .exec_status = 2,
		.scm_errno = 0, .scm_getfd = 0, .scm_stats = 0,
		.pddup_errno = 0, .pddup_getfd = FD_CLOEXEC,
		.pddup_stats = 0 } },
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sharer_operates);
	ATF_TP_ADD_TC(tp, sharer_outlives_opener);
	ATF_TP_ADD_TC(tp, queue_descriptor_states);
	return (atf_no_error());
}
