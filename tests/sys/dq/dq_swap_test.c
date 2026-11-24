/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * The SWAP answer to an open (DQ_RESOLVE_SWAP, dq(4)): the supervisor
 * names a descriptor it holds and the kernel installs that open file as
 * the result of the attached program's open(2).
 *
 * The supervisor here is the test's own thread: it reads the queue,
 * answers the open of the name under test through a per-case function
 * and passes everything else.  The program is an attached child (pdfork,
 * DQ_IOC_ATTACH) whose results come back over a pipe.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	SW_NRES		24
#define	SW_UID		65534		/* nobody */

struct sw;
typedef void sw_answer_t(struct sw *, const struct dq_event *,
    const struct dq_resolve_body *);

struct sw {
	struct dqt_ctl	 c;
	const char	*name;		/* the open to answer: path suffix */
	sw_answer_t	*answer;
	const char	*name2;		/* a second one, or NULL */
	sw_answer_t	*answer2;
	int		 pd;		/* the program, while it runs */
	bool		 expect_killed;	/* the case kills the program */
	int		 answered;	/* opens of name seen */
	uint32_t	 accept;	/* of the last one */
	uint32_t	 mode;
	unsigned	 after;		/* records after the first answer that
					   are not a RESOLVE */
	unsigned	 after_resolve;	/* RESOLVE records after it */
	char		 cwd[PATH_MAX];
};

/* What the program reports: system call results and a few values. */
struct sw_res {
	struct dqt_rr	 r[SW_NRES];
	ino_t		 ino;
	off_t		 size;
	mode_t		 mode;
	int		 kftype;
	int		 fdflags;
	int		 flflags;
	char		 data[64];
};

static void
sw_write_file(const char *path, const char *text, mode_t mode)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ((ssize_t)strlen(text), write(fd, text, strlen(text)));
	ATF_REQUIRE_EQ(0, fchmod(fd, mode));
	ATF_REQUIRE_EQ(0, close(fd));
}

static void
sw_read_file(const char *path, char *buf, size_t len)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", path, strerror(errno));
	n = read(fd, buf, len - 1);
	ATF_REQUIRE(n >= 0);
	buf[n] = '\0';
	(void)close(fd);
}

static void
sw_init(struct sw *x, const char *name, sw_answer_t *answer)
{

	dqt_require_plane();
	memset(x, 0, sizeof(*x));
	dqt_init_manual(&x->c);
	x->name = name;
	x->answer = answer;
	ATF_REQUIRE(getcwd(x->cwd, sizeof(x->cwd)) != NULL);
	/* The program may be another user: let it search the work dir. */
	ATF_REQUIRE_EQ(0, chmod(".", 0755));
}

static bool
sw_is_target(const char *name, const struct dq_resolve_body *rb,
    const char *path)
{
	size_t nl, pl;

	if (name == NULL || rb->drs_op != DQ_ROP_OPEN)
		return (false);
	nl = strlen(name);
	pl = strlen(path);
	return (pl >= nl && strcmp(path + pl - nl, name) == 0 &&
	    (pl == nl || path[pl - nl - 1] == '/'));
}

static void
sw_handle(struct sw *x, const struct dq_event *ev)
{
	const struct dq_resolve_body *rb;
	const char *path;

	if (ev->de_op != DQ_OP_RESOLVE) {
		if (x->answered > 0)
			x->after++;
		if (ev->de_id != 0)
			(void)dq_reply(x->c.q, ev->de_id, EIO, NULL, 0);
		return;
	}
	ATF_REQUIRE_EQ(0, dq_event_resolve(ev, &rb, &path, NULL, NULL, NULL));
	if (sw_is_target(x->name, rb, path)) {
		x->answered++;
		x->accept = rb->drs_accept;
		x->mode = rb->drs_mode;
		x->answer(x, ev, rb);
		return;
	}
	if (sw_is_target(x->name2, rb, path)) {
		x->answer2(x, ev, rb);
		return;
	}
	if (x->answered > 0)
		x->after_resolve++;
	if (dq_reply_resolve_pass(x->c.q, ev->de_id) != 0 && errno != ESRCH)
		atf_tc_fail("PASS of \"%s\": %s", path, strerror(errno));
}

static void
sw_event(const struct dq_event *ev, void *arg)
{

	sw_handle(arg, ev);
}

/* Serve the queue until the program has exited; collect its result. */
static void
sw_run(struct sw *x, dqt_child_fn fn, void *arg, struct sw_res *res)
{
	struct dqt_achild ch;
	int error, status;

	dqt_attach_spawn(&x->c, &ch, fn, arg);
	x->pd = ch.pd;
	error = dqt_serve_until(x->c.q, ch.pd, NULL, sw_event, x, 30000);
	if (error == ETIMEDOUT)
		atf_tc_fail("the program neither asked nor exited");
	ATF_REQUIRE_EQ_MSG(0, error, "serving the queue: %s", strerror(error));
	x->pd = -1;
	status = dqt_attach_wait(&ch, res, sizeof(*res));
	if (x->expect_killed)
		ATF_REQUIRE_MSG(WIFSIGNALED(status) &&
		    WTERMSIG(status) == SIGKILL,
		    "the program was not killed, status %#x", status);
	else
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "the program failed, status %#x", status);
}

/* The supervisor's own open for an answer, as dq(4) asks for it. */
static int
sw_open(const char *path, int flags)
{
	int fd;

	fd = open(path, flags | O_CLOEXEC | O_CLOFORK);
	ATF_REQUIRE_MSG(fd != -1, "supervisor open %s: %s", path,
	    strerror(errno));
	return (fd);
}

/* A raw SWAP reply: len bytes of {reply, swap}. */
static int
sw_reply_raw(struct sw *x, uint64_t id, int fd, uint32_t flags,
    uint64_t spare, size_t len)
{
	struct {
		struct dq_resolve_reply	rr;
		struct dq_resolve_swap	rw;
		char			pad[8];
	} r;

	memset(&r, 0, sizeof(r));
	r.rr.drr_kind = DQ_RESOLVE_SWAP;
	r.rw.drw_fd = fd;
	r.rw.drw_flags = flags;
	r.rw.drw_spare[1] = spare;
	return (dq_reply(x->c.q, id, 0, &r, len));
}
#define	SW_REPLY_LEN	(sizeof(struct dq_resolve_reply) + \
	    sizeof(struct dq_resolve_swap))

/* A refused reply: the errno, and the descriptor still open. */
#define	SW_REFUSED(x, ev, fd, flags, want) do {				\
	ATF_CHECK_ERRNO(want, dq_reply_resolve_swap((x)->c.q,		\
	    (ev)->de_id, fd, flags) == -1);				\
	if ((fd) >= 0)							\
		ATF_CHECK(fcntl(fd, F_GETFD) != -1);			\
} while (0)

/*
 * Case: a regular file.  The program's descriptor is the substitute's
 * real open file, and nothing after the open reaches the queue.
 */
static void
p_regular(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct kinfo_file kif;
	struct stat st;
	int fd;

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY | O_CLOEXEC));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], fstat(fd, &st));
	res->ino = st.st_ino;
	res->size = st.st_size;
	DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	res->fdflags = fcntl(fd, F_GETFD);
	res->flflags = fcntl(fd, F_GETFL);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	DQT_RR(res->r[3], fcntl(fd, F_KINFO, &kif));
	res->kftype = kif.kf_type;
	DQT_RR(res->r[4], lseek(fd, 0, SEEK_SET));
	DQT_RR(res->r[5], read(fd, res->data, 4));
	DQT_RR(res->r[6], lseek(fd, 0, SEEK_CUR));
	DQT_RR(res->r[7], flock(fd, LOCK_SH));
	DQT_RR(res->r[8], close(fd));
}

static void
a_regular(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb)
{
	int fd;

	ATF_CHECK(dq_resolve_accepts(rb, DQ_RESOLVE_SWAP));
	ATF_CHECK(dq_resolve_accepts(rb, DQ_RESOLVE_FD));
	fd = sw_open("subst", O_RDONLY);
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	/* The take closed the supervisor's descriptor (Q6). */
	ATF_CHECK_ERRNO(EBADF, fcntl(fd, F_GETFD) == -1);
	/* A second reply finds no event and takes nothing. */
	fd = sw_open("subst", O_RDONLY);
	ATF_CHECK_ERRNO(ESRCH, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
	    0) == -1);
	ATF_CHECK_EQ(0, close(fd));
}

ATF_TC_WITHOUT_HEAD(swap_regular);
ATF_TC_BODY(swap_regular, tc)
{
	struct sw x;
	struct sw_res res;
	struct stat st;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	ATF_REQUIRE_EQ(0, stat("subst", &st));
	sw_init(&x, "orig", a_regular);
	sw_run(&x, p_regular, NULL, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ(O_RDONLY | O_CLOEXEC, (int)x.mode);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(st.st_ino, res.ino);
	ATF_CHECK_EQ(10, res.size);
	ATF_CHECK_EQ(10, res.r[2].rv);
	ATF_CHECK_EQ(FD_CLOEXEC, res.fdflags);
	ATF_CHECK_EQ(O_RDONLY, res.flflags & O_ACCMODE);
	ATF_CHECK_EQ(0, res.r[3].rv);
	ATF_CHECK_EQ(KF_TYPE_VNODE, res.kftype);
	ATF_CHECK_EQ(0, res.r[4].rv);
	ATF_CHECK_EQ(4, res.r[5].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "SUBS", 4));
	ATF_CHECK_EQ(4, res.r[6].rv);
	ATF_CHECK_EQ(0, res.r[7].rv);
	ATF_CHECK_EQ(0, res.r[8].rv);
	/* fstat, read, lseek, flock and close made no event of any kind. */
	ATF_CHECK_EQ(0, x.after);
	dqt_fini(&x.c);
}

/*
 * Case: what the kernel refuses to the supervisor.  Every refusal leaves
 * the supervisor's descriptor open and the event in flight, so the last,
 * correct reply still answers the same open.
 */
static void
p_plain_open(void *arg, void *result)
{
	struct sw_res *res = result;
	int fd, flags;

	flags = arg != NULL ? *(int *)arg : O_RDONLY;
	DQT_RR(res->r[0], fd = open("orig", flags, 0644));
	if (fd == -1)
		return;
	DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	DQT_RR(res->r[8], close(fd));
}

static void
a_refusals(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd, fd2, kq, pfd[2], sv[2];

	/* Not a descriptor. */
	SW_REFUSED(x, ev, -1, 0, EBADF);
	/* Not a vnode: a pipe, a socket; a kqueue cannot be passed at all. */
	ATF_REQUIRE_EQ(0, pipe2(pfd, O_CLOEXEC));
	SW_REFUSED(x, ev, pfd[0], 0, EOPNOTSUPP);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
	    sv));
	SW_REFUSED(x, ev, sv[0], 0, EOPNOTSUPP);
	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	SW_REFUSED(x, ev, kq, 0, EOPNOTSUPP);
	(void)close(pfd[0]);
	(void)close(pfd[1]);
	(void)close(sv[0]);
	(void)close(sv[1]);
	(void)close(kq);
	/*
	 * The queue itself is pinned to this process and goes nowhere: the
	 * transfer policy refuses it before any other rule sees it.  Any
	 * other device: not a regular file.
	 */
	SW_REFUSED(x, ev, x->c.q, 0, ENOTCAPABLE);
	fd = sw_open("/dev/null", O_RDONLY);
	SW_REFUSED(x, ev, fd, 0, EOPNOTSUPP);
	(void)close(fd);
	/* Another reference to the open file. */
	fd = sw_open("subst", O_RDONLY);
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 != -1);
	SW_REFUSED(x, ev, fd, 0, EBUSY);
	(void)close(fd2);
	/* A reply flag that does not exist, a spare word, a short reply. */
	SW_REFUSED(x, ev, fd, 0x2, EINVAL);
	SW_REFUSED(x, ev, fd, 0x80000000, EINVAL);
	ATF_CHECK_ERRNO(EINVAL, sw_reply_raw(x, ev->de_id, fd, 0, 1,
	    SW_REPLY_LEN) == -1);
	ATF_CHECK_ERRNO(EINVAL, sw_reply_raw(x, ev->de_id, fd, 0, 0,
	    SW_REPLY_LEN - 8) == -1);
	ATF_CHECK_ERRNO(EINVAL, sw_reply_raw(x, ev->de_id, fd, 0, 0,
	    SW_REPLY_LEN + 8) == -1);
	/* "Created" for a request that could not create. */
	SW_REFUSED(x, ev, fd, DQ_SWAP_F_CREATED, EINVAL);
	(void)close(fd);
	/* Not the access mode asked for. */
	fd = sw_open("subst", O_RDWR);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	fd = sw_open("subst", O_WRONLY);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	fd = sw_open("subst", O_PATH);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	/* Not the status flags asked for. */
	fd = sw_open("subst", O_RDONLY | O_NONBLOCK);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	fd = sw_open("subst", O_RDONLY | O_APPEND);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	/* An entry that may not be transferred. */
	fd = sw_open("subst", O_RDONLY);
	ATF_REQUIRE_EQ(0, cap_xfer_limit(fd, CAP_XFER_NONE));
	SW_REFUSED(x, ev, fd, 0, ENOTCAPABLE);
	(void)close(fd);
	/*
	 * A transfer-once entry is not consumed by a refusal: after the
	 * EBUSY it still answers.
	 */
	fd = sw_open("subst", O_RDONLY);
	ATF_REQUIRE_EQ(0, cap_xfer_limit(fd, CAP_XFER_ONCE));
	fd2 = dup(fd);
	ATF_REQUIRE(fd2 != -1);
	SW_REFUSED(x, ev, fd, 0, EBUSY);
	(void)close(fd2);
	/* Nor by a reply whose header is refused. */
	{
		struct {
			struct dq_resolve_reply	rr;
			struct dq_resolve_swap	rw;
		} r;

		memset(&r, 0, sizeof(r));
		r.rr.drr_kind = DQ_RESOLVE_SWAP;
		r.rr.drr_pad0 = 1;
		r.rw.drw_fd = fd;
		ATF_CHECK_ERRNO(EINVAL, dq_reply(x->c.q, ev->de_id, 0, &r,
		    sizeof(r)) == -1);
	}
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

ATF_TC_WITHOUT_HEAD(swap_refused_to_supervisor);
ATF_TC_BODY(swap_refused_to_supervisor, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_refusals);
	sw_run(&x, p_plain_open, NULL, &res);
	/* One open, one event, answered after all the refusals. */
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(10, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "SUBSTITUTE", 10));
	dqt_fini(&x.c);
}

/*
 * Case: only an open takes SWAP.  stat(2) and chdir(2) of the name do
 * not offer it, and a SWAP reply to them is EINVAL with the event left
 * in flight.
 */
static void
p_notopen(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct stat st;

	DQT_RR(res->r[0], stat("orig", &st));
	res->size = st.st_size;
	DQT_RR(res->r[1], chdir("dir"));
}

/* STAT and CHDIR never accept SWAP: the reply is EINVAL, then PASS. */
struct notopen_arg {
	int		 q;
	int		 fd;
	int		 nstat, nchdir;
};

static void
notopen_event(const struct dq_event *ev, void *arg)
{
	struct notopen_arg *na = arg;
	const struct dq_resolve_body *rb;
	const char *path;

	if (ev->de_op != DQ_OP_RESOLVE)
		return;
	ATF_REQUIRE_EQ(0, dq_event_resolve(ev, &rb, &path, NULL, NULL, NULL));
	if (rb->drs_op == DQ_ROP_STAT || rb->drs_op == DQ_ROP_CHDIR) {
		if (rb->drs_op == DQ_ROP_STAT)
			na->nstat++;
		else
			na->nchdir++;
		ATF_CHECK(!dq_resolve_accepts(rb, DQ_RESOLVE_SWAP));
		ATF_CHECK_ERRNO(EINVAL, dq_reply_resolve_swap(na->q,
		    ev->de_id, na->fd, 0) == -1);
	}
	ATF_CHECK_EQ(0, dq_reply_resolve_pass(na->q, ev->de_id));
}

ATF_TC_WITHOUT_HEAD(swap_only_for_open);
ATF_TC_BODY(swap_only_for_open, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sw_res res;
	struct notopen_arg na;

	dqt_require_plane();
	sw_write_file("orig", "ORIGINAL", 0644);
	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	dqt_init_manual(&c);
	memset(&na, 0, sizeof(na));
	na.q = c.q;
	na.fd = sw_open("orig", O_RDONLY);
	dqt_attach_spawn(&c, &ch, p_notopen, NULL);
	ATF_REQUIRE_EQ(0, dqt_serve_until(c.q, ch.pd, NULL, notopen_event, &na,
	    30000));
	dqt_attach_collect(&ch, &res, sizeof(res));
	ATF_CHECK(na.nstat >= 1);
	ATF_CHECK(na.nchdir >= 1);
	ATF_CHECK_EQ(0, res.r[0].rv);
	ATF_CHECK_EQ(8, res.size);
	ATF_CHECK_EQ(0, res.r[1].rv);
	(void)close(na.fd);
	dqt_fini(&c);
}

/*
 * Case: O_EXLOCK.  The lock is taken by the kernel for the program, on
 * the swapped open file, and only if the supervisor's entry carries
 * CAP_FLOCK.
 */
static void
p_exlock(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd, fd2;

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY | O_EXLOCK));
	if (fd == -1)
		return;
	/* "subst" by its own name is passed: a second open file of it. */
	DQT_RR(res->r[1], fd2 = open("subst", O_RDONLY));
	DQT_RR(res->r[2], flock(fd2, LOCK_EX | LOCK_NB));
	DQT_RR(res->r[3], close(fd));
	DQT_RR(res->r[4], flock(fd2, LOCK_EX | LOCK_NB));
	(void)close(fd2);
}

static void
a_exlock(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	cap_rights_t rights;
	int fd;

	fd = sw_open("subst", O_RDONLY);
	ATF_REQUIRE_EQ(0, cap_rights_limit(fd, cap_rights_init(&rights,
	    CAP_READ, CAP_FSTAT, CAP_SEEK)));
	SW_REFUSED(x, ev, fd, 0, ENOTCAPABLE);
	(void)close(fd);
	fd = sw_open("subst", O_RDONLY);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

ATF_TC_WITHOUT_HEAD(swap_exlock);
ATF_TC_BODY(swap_exlock, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_exlock);
	sw_run(&x, p_exlock, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK(res.r[1].rv >= 0);
	/* The program's open holds the exclusive lock on the substitute. */
	ATF_CHECK_EQ(-1, res.r[2].rv);
	ATF_CHECK_EQ(EWOULDBLOCK, res.r[2].err);
	/* Its close releases it: the program was the only holder. */
	ATF_CHECK_EQ(0, res.r[3].rv);
	ATF_CHECK_EQ(0, res.r[4].rv);
	dqt_fini(&x.c);
}

/*
 * Case: O_TRUNC.  The supervisor opens without O_TRUNC; the kernel
 * truncates the supplied file for the program.
 */
static void
a_wronly(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_WRONLY);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

static void
p_write(void *arg, void *result)
{
	struct sw_res *res = result;
	int fd, flags;

	flags = *(int *)arg;
	if ((flags & 0x40000000) != 0) {
		flags &= ~0x40000000;
		DQT_RR(res->r[9], setgid(SW_UID));
		DQT_RR(res->r[10], setuid(SW_UID));
	}
	DQT_RR(res->r[0], fd = open("orig", flags, 0444));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], write(fd, "new", 3));
	DQT_RR(res->r[8], close(fd));
}

ATF_TC_WITHOUT_HEAD(swap_trunc);
ATF_TC_BODY(swap_trunc, tc)
{
	struct sw x;
	struct sw_res res;
	char buf[64];
	int flags;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_wronly);
	flags = O_WRONLY | O_TRUNC;
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(3, res.r[1].rv);
	sw_read_file("subst", buf, sizeof(buf));
	ATF_CHECK_STREQ("new", buf);
	sw_read_file("orig", buf, sizeof(buf));
	ATF_CHECK_STREQ("ORIGINAL", buf);
	dqt_fini(&x.c);
}

/*
 * Case: the program's own permission.  The supervisor (root) can open
 * the substitute; the program (another user) could not have opened it.
 * The reply succeeds, the program's open fails as its own open of that
 * file would, nothing is installed, and an O_TRUNC does not truncate.
 */
ATF_TC_WITHOUT_HEAD(swap_program_denied);
ATF_TC_BODY(swap_program_denied, tc)
{
	struct sw x;
	struct sw_res res;
	char buf[64];
	int flags;

	/* Readable by its owner (root) only. */
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0600);
	sw_init(&x, "orig", a_regular);
	flags = O_RDONLY | 0x40000000;
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_EQ(0, res.r[10].rv);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EACCES, res.r[0].err);
	dqt_fini(&x.c);

	/* Readable by all, writable by root: a truncating open is refused. */
	ATF_REQUIRE_EQ(0, chmod("subst", 0644));
	sw_init(&x, "orig", a_wronly);
	flags = O_WRONLY | O_TRUNC | 0x40000000;
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EACCES, res.r[0].err);
	sw_read_file("subst", buf, sizeof(buf));
	ATF_CHECK_STREQ("SUBSTITUTE", buf);
	dqt_fini(&x.c);

	/* Once the program's user may read it, the same swap succeeds. */
	sw_init(&x, "orig", a_regular);
	flags = O_RDONLY | 0x40000000;
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	dqt_fini(&x.c);
}

/*
 * Case: a file created for the open.  Base lets open(O_CREAT, 0444)
 * return a writable descriptor of the file it created.  With the
 * supervisor's declaration and the file owned by the program's user the
 * swap does the same; without the declaration, or with a file of another
 * owner, the program's write permission is checked and refused.
 */
static uid_t created_owner;
static uint32_t created_flags;

static void
a_created(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb)
{
	int fd;

	ATF_CHECK((rb->drs_mode & O_CREAT) != 0);
	(void)unlink("made");
	fd = open("made", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_CLOFORK,
	    0444);
	ATF_REQUIRE_MSG(fd != -1, "create: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, fchown(fd, created_owner, (gid_t)-1));
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
	    created_flags));
}

ATF_TC_WITHOUT_HEAD(swap_created);
ATF_TC_BODY(swap_created, tc)
{
	struct sw x;
	struct sw_res res;
	char buf[64];
	int flags;

	flags = O_WRONLY | O_CREAT | O_TRUNC | 0x40000000;

	/* Declared, and the program's user owns it: as base. */
	created_owner = SW_UID;
	created_flags = DQ_SWAP_F_CREATED;
	sw_init(&x, "orig", a_created);
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(3, res.r[1].rv);
	sw_read_file("made", buf, sizeof(buf));
	ATF_CHECK_STREQ("new", buf);
	dqt_fini(&x.c);

	/* Not declared: an existing 0444 file, checked. */
	created_flags = 0;
	sw_init(&x, "orig", a_created);
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EACCES, res.r[0].err);
	dqt_fini(&x.c);

	/* Declared, but another user's file: the declaration is ignored. */
	created_owner = 0;
	created_flags = DQ_SWAP_F_CREATED;
	sw_init(&x, "orig", a_created);
	sw_run(&x, p_write, &flags, &res);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EACCES, res.r[0].err);
	dqt_fini(&x.c);
}

/*
 * Case: O_PATH.  Any vnode may answer an O_PATH open, a device included:
 * it is a reference to the node, as the program's own O_PATH open gives.
 */
static void
p_opath(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct stat st;
	char b;
	int fd;

	DQT_RR(res->r[0], fd = open("orig", O_PATH));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], fstat(fd, &st));
	res->mode = st.st_mode;
	DQT_RR(res->r[2], read(fd, &b, 1));
	(void)close(fd);
}

static void
a_opath(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	/* A full open of the device does not answer an O_PATH request. */
	fd = sw_open("/dev/null", O_RDONLY);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	fd = sw_open("/dev/null", O_PATH);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

ATF_TC_WITHOUT_HEAD(swap_opath_device);
ATF_TC_BODY(swap_opath_device, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_init(&x, "orig", a_opath);
	sw_run(&x, p_opath, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK(S_ISCHR(res.mode));
	ATF_CHECK_EQ(-1, res.r[2].rv);
	ATF_CHECK_EQ(EBADF, res.r[2].err);
	dqt_fini(&x.c);
}

/*
 * Case: a directory.  Lookups relative to the swapped directory are the
 * kernel's own, in the directory the supervisor chose.
 */
static void
p_dir(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int dfd, fd;

	DQT_RR(res->r[0], dfd = open("orig", O_RDONLY | O_DIRECTORY));
	if (dfd == -1)
		return;
	DQT_RR(res->r[1], fd = openat(dfd, "inside", O_RDONLY));
	if (fd != -1) {
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
		(void)close(fd);
	}
	(void)close(dfd);
}

static void
a_dir(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	/* A regular file does not answer an O_DIRECTORY open. */
	fd = sw_open("subst/inside", O_RDONLY);
	SW_REFUSED(x, ev, fd, 0, EFTYPE);
	(void)close(fd);
	fd = sw_open("subst", O_RDONLY | O_DIRECTORY);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

ATF_TC_WITHOUT_HEAD(swap_directory);
ATF_TC_BODY(swap_directory, tc)
{
	struct sw x;
	struct sw_res res;

	ATF_REQUIRE_EQ(0, mkdir("orig", 0755));
	ATF_REQUIRE_EQ(0, mkdir("subst", 0755));
	sw_write_file("orig/inside", "IN-ORIGINAL", 0644);
	sw_write_file("subst/inside", "IN-SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_dir);
	sw_run(&x, p_dir, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_MSG(res.r[1].rv >= 0, "openat: %s", strerror(res.r[1].err));
	ATF_CHECK_EQ(13, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "IN-SUBSTITUTE", 13));
	dqt_fini(&x.c);
}

/*
 * Case: no free descriptor.  The program's open fails EMFILE after the
 * supervisor's reply succeeded; the file is dropped, not leaked into the
 * program, and the next open works.
 */
static void
p_emfile(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct rlimit rl, save;
	int fd, i;

	/* Fill every number below the limit. */
	DQT_RR(res->r[9], getrlimit(RLIMIT_NOFILE, &save));
	rl = save;
	rl.rlim_cur = 32;
	DQT_RR(res->r[10], setrlimit(RLIMIT_NOFILE, &rl));
	for (i = 0; i < 64; i++) {
		if (dup(0) == -1)
			break;
	}
	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	DQT_RR(res->r[11], setrlimit(RLIMIT_NOFILE, &save));
	DQT_RR(res->r[1], fd = open("orig", O_RDONLY));
	if (fd != -1)
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
}

ATF_TC_WITHOUT_HEAD(swap_emfile);
ATF_TC_BODY(swap_emfile, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_regular);
	sw_run(&x, p_emfile, NULL, &res);
	ATF_CHECK_EQ(2, x.answered);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EMFILE, res.r[0].err);
	ATF_CHECK_MSG(res.r[1].rv >= 0, "open: %s", strerror(res.r[1].err));
	ATF_CHECK_EQ(10, res.r[2].rv);
	dqt_fini(&x.c);
}

/*
 * The supervisor is gone.  Nothing is killed: the program keeps the real
 * descriptors it holds, a swapped one included, and obtains nothing new
 * by name.  In these cases the test closes the queue itself and keeps the
 * program's process descriptor, so the program lives to report: a program
 * killed with its supervisor would have tested pdfork(2), not the queue.
 */
struct sw_gone {
	int		 held[2];	/* program: my open has returned */
	int		 gone[2];	/* test: the queue is closed */
};

/* Serve the queue until the open under test has been answered n times. */
static int sw_answered_want;

static bool
sw_answered_enough(void *arg)
{
	struct sw *x = arg;

	return (x->answered >= sw_answered_want);
}

static void
sw_serve_answered(struct sw *x, int n)
{
	int error;

	sw_answered_want = n;
	error = dqt_serve_until(x->c.q, -1, sw_answered_enough, sw_event, x,
	    30000);
	if (error == ETIMEDOUT)
		atf_tc_fail("the program did not ask");
	ATF_REQUIRE_EQ_MSG(0, error, "serving the queue: %s", strerror(error));
}

/* Wait until the process sleeps on the named wait channel message. */
static void
a_rdwr(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDWR);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

/*
 * Case: a swapped descriptor outlives the supervisor.  The program reads
 * and writes through it after the queue is gone, and every new call that
 * names a path fails EIO.
 */
static void
p_gone_holder(void *arg, void *result)
{
	struct sw_res *res = result;
	struct sw_gone *g = arg;
	struct stat st;
	char b;
	int fd, fd2;

	DQT_RR(res->r[0], fd = open("orig", O_RDWR));
	b = 'h';
	(void)write(g->held[1], &b, 1);
	(void)read(g->gone[0], &b, 1);
	if (fd == -1)
		return;
	DQT_RR(res->r[1], pwrite(fd, "AFTER", 5, 0));
	DQT_RR(res->r[2], pread(fd, res->data, sizeof(res->data) - 1, 0));
	DQT_RR(res->r[3], fstat(fd, &st));
	res->ino = st.st_ino;
	DQT_RR(res->r[4], fd2 = dup(fd));
	DQT_RR(res->r[5], open("orig", O_RDONLY));
	DQT_RR(res->r[6], open("subst", O_RDONLY));
	DQT_RR(res->r[7], stat("subst", &st));
	DQT_RR(res->r[8], close(fd));
}

ATF_TC_WITHOUT_HEAD(swap_survives_supervisor);
ATF_TC_BODY(swap_survives_supervisor, tc)
{
	struct sw x;
	struct sw_res res;
	struct sw_gone g;
	struct dqt_achild ch;
	struct pollfd pfd;
	struct stat st;
	char b;
	char text[64];
	int status;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	ATF_REQUIRE_EQ(0, stat("subst", &st));
	sw_init(&x, "orig", a_rdwr);
	ATF_REQUIRE_EQ(0, pipe(g.held));
	ATF_REQUIRE_EQ(0, pipe(g.gone));
	dqt_attach_spawn(&x.c, &ch, p_gone_holder, &g);
	sw_serve_answered(&x, 1);
	pfd.fd = g.held[0];
	pfd.events = POLLIN;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, 30000));
	ATF_REQUIRE_EQ(1, read(g.held[0], &b, 1));

	dqt_close_queue(&x.c);
	ATF_REQUIRE_EQ(1, write(g.gone[1], &b, 1));
	status = dqt_attach_wait(&ch, &res, sizeof(res));
	/* Not killed: it ran to its own exit. */
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the program did not survive, status %#x", status);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(5, res.r[1].rv);
	ATF_CHECK_EQ(10, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "AFTERITUTE", 10));
	ATF_CHECK_EQ(0, res.r[3].rv);
	ATF_CHECK_EQ(st.st_ino, res.ino);
	ATF_CHECK(res.r[4].rv >= 0);
	/* Nothing new by name: not the swapped name, not any other. */
	ATF_CHECK_EQ(-1, res.r[5].rv);
	ATF_CHECK_EQ(EIO, res.r[5].err);
	ATF_CHECK_EQ(-1, res.r[6].rv);
	ATF_CHECK_EQ(EIO, res.r[6].err);
	ATF_CHECK_EQ(-1, res.r[7].rv);
	ATF_CHECK_EQ(EIO, res.r[7].err);
	ATF_CHECK_EQ(0, res.r[8].rv);
	sw_read_file("subst", text, sizeof(text));
	ATF_CHECK_STREQ("AFTERITUTE", text);
	sw_read_file("orig", text, sizeof(text));
	ATF_CHECK_STREQ("ORIGINAL", text);
	(void)close(g.held[0]);
	(void)close(g.held[1]);
	(void)close(g.gone[0]);
	(void)close(g.gone[1]);
	dqt_fini(&x.c);
}

/*
 * Case: the supervisor goes between its reply and the install.  The
 * program's open asked for O_EXLOCK and the test holds that lock on
 * another open file of the substitute, so the program, answered, sleeps
 * in the lock with the swapped file in hand and not yet in its table.
 * The queue is closed there; then the lock is let go.
 *
 * A program whose supervisor is gone is given nothing new: the open fails
 * EIO, as its lookups do from then on, nothing is installed, and the lock
 * taken for it goes with the file.
 */
static void
p_exlock_late(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct stat st;
	int fd, next;

	/* The number the open will be given. */
	next = dup(0);
	(void)close(next);
	DQT_RR(res->r[0], fd = open("orig", O_RDONLY | O_EXLOCK));
	if (fd != -1) {
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
		DQT_RR(res->r[8], close(fd));
	} else
		DQT_RR(res->r[4], fcntl(next, F_GETFD));
	DQT_RR(res->r[3], stat("orig", &st));
}

ATF_TC_WITHOUT_HEAD(swap_supervisor_gone_before_install);
ATF_TC_BODY(swap_supervisor_gone_before_install, tc)
{
	struct sw x;
	struct sw_res res;
	struct dqt_achild ch;
	int lockfd;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	lockfd = open("subst", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(lockfd != -1);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_EX));
	sw_init(&x, "orig", a_regular);
	dqt_attach_spawn(&x.c, &ch, p_exlock_late, NULL);
	sw_serve_answered(&x, 1);
	ATF_REQUIRE_MSG(dqt_wait_wmesg(ch.pid, "lockf", 30000),
	    "the program is not waiting for the lock");

	dqt_close_queue(&x.c);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_UN));
	dqt_attach_collect(&ch, &res, sizeof(res));
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ_MSG(-1, res.r[0].rv, "the open returned %ld", res.r[0].rv);
	ATF_CHECK_EQ(EIO, res.r[0].err);
	/* The number the descriptor would have had is still free. */
	ATF_CHECK_EQ(-1, res.r[4].rv);
	ATF_CHECK_EQ(EBADF, res.r[4].err);
	/* The next call by name fails the same way. */
	ATF_CHECK_EQ(-1, res.r[3].rv);
	ATF_CHECK_EQ(EIO, res.r[3].err);
	/* The file was dropped: the lock taken for the program is gone. */
	ATF_CHECK_EQ(0, flock(lockfd, LOCK_EX | LOCK_NB));
	(void)close(lockfd);
	dqt_fini(&x.c);
}

/*
 * Case: the same with O_TRUNC.  The first test of the queue is made before
 * the lock and the truncation and the last as the descriptor is entered;
 * the queue dies in between, while the program sleeps in the lock.  The
 * open fails EIO after it has truncated the file, as an open(2) that fails
 * EMFILE has truncated: the documented remainder.
 */
static void
p_exlock_trunc_late(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd, next;

	next = dup(0);
	(void)close(next);
	DQT_RR(res->r[0], fd = open("orig", O_WRONLY | O_TRUNC | O_EXLOCK));
	if (fd != -1)
		DQT_RR(res->r[8], close(fd));
	else
		DQT_RR(res->r[4], fcntl(next, F_GETFD));
}

ATF_TC_WITHOUT_HEAD(swap_supervisor_gone_after_trunc);
ATF_TC_BODY(swap_supervisor_gone_after_trunc, tc)
{
	struct sw x;
	struct sw_res res;
	struct dqt_achild ch;
	char text[64];
	int lockfd;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	lockfd = open("subst", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(lockfd != -1);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_EX));
	sw_init(&x, "orig", a_wronly);
	dqt_attach_spawn(&x.c, &ch, p_exlock_trunc_late, NULL);
	sw_serve_answered(&x, 1);
	ATF_REQUIRE_MSG(dqt_wait_wmesg(ch.pid, "lockf", 30000),
	    "the program is not waiting for the lock");
	/* Nothing is truncated while the open waits for its lock. */
	sw_read_file("subst", text, sizeof(text));
	ATF_CHECK_STREQ("SUBSTITUTE", text);

	dqt_close_queue(&x.c);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_UN));
	dqt_attach_collect(&ch, &res, sizeof(res));
	ATF_CHECK_EQ_MSG(-1, res.r[0].rv, "the open returned %ld", res.r[0].rv);
	ATF_CHECK_EQ(EIO, res.r[0].err);
	ATF_CHECK_EQ(-1, res.r[4].rv);
	ATF_CHECK_EQ(EBADF, res.r[4].err);
	/* Truncated by the open that then failed; the original untouched. */
	sw_read_file("subst", text, sizeof(text));
	ATF_CHECK_STREQ("", text);
	sw_read_file("orig", text, sizeof(text));
	ATF_CHECK_STREQ("ORIGINAL", text);
	ATF_CHECK_EQ(0, flock(lockfd, LOCK_EX | LOCK_NB));
	(void)close(lockfd);
	dqt_fini(&x.c);
}

/*
 * Case: the same, with the supervisor a process of its own that exits
 * while a process sharing its descriptor table still holds the queue's
 * file.  No last close happens: the queue dies of its owner's exit, and
 * that is enough for the install to be refused.  The program was made
 * with PD_DAEMON, so nothing but the queue's death reaches it.
 */
struct sw_exit_rep {
	pid_t		 sharer;
	pid_t		 prog;
};

static bool
sw_read_within(int fd, void *buf, size_t len, int ms)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, ms) != 1)
		return (false);
	return (read(fd, buf, len) == (ssize_t)len);
}

/*
 * The forked supervisor's handler (no ATF): SWAP the open of "orig",
 * PASS other RESOLVEs, answer anything else EIO.  A failure is its exit
 * status.
 */
struct exit_sup {
	int		 q;
	int		 fail;		/* nonzero: _exit with it */
	bool		 answered;
};

static bool
exit_sup_done(void *arg)
{
	const struct exit_sup *es = arg;

	return (es->answered || es->fail != 0);
}

static void
exit_sup_event(const struct dq_event *ev, void *arg)
{
	struct exit_sup *es = arg;
	const struct dq_resolve_body *rb;
	const char *path;
	size_t pl;
	int fd;

	if (es->fail != 0)
		return;
	if (ev->de_op != DQ_OP_RESOLVE) {
		if (ev->de_id != 0)
			(void)dq_reply(es->q, ev->de_id, EIO, NULL, 0);
		return;
	}
	if (dq_event_resolve(ev, &rb, &path, NULL, NULL, NULL) != 0) {
		es->fail = 26;
		return;
	}
	pl = strlen(path);
	if (rb->drs_op != DQ_ROP_OPEN || pl < 4 ||
	    strcmp(path + pl - 4, "orig") != 0) {
		(void)dq_reply_resolve_pass(es->q, ev->de_id);
		return;
	}
	fd = open("subst", O_RDONLY | O_CLOEXEC | O_CLOFORK);
	if (fd == -1 || dq_reply_resolve_swap(es->q, ev->de_id, fd, 0) != 0) {
		es->fail = 27;
		return;
	}
	es->answered = true;
}

/* The supervisor process; exits 0 once the program waits in the lock. */
static void
sw_exit_supervisor(int rep, int progrep)
{
	struct sw_exit_rep er;
	struct exit_sup es;
	struct sw_res res;
	struct stat st;
	char b;
	int fd, go[2], keep, pd, q;

	q = dq_open();
	if (q == -1 || pipe(go) != 0)
		_exit(20);
	er.prog = pdfork(&pd, PD_DAEMON);
	if (er.prog == -1)
		_exit(21);
	if (er.prog == 0) {
		if (read(go[0], &b, 1) != 1)
			_exit(0);
		memset(&res, 0, sizeof(res));
		DQT_RR(res.r[1], keep = open("keep", O_RDONLY));
		DQT_RR(res.r[0], fd = open("orig", O_RDONLY | O_EXLOCK));
		/* What it held before, it keeps; by name, nothing new. */
		DQT_RR(res.r[2], read(keep, res.data, sizeof(res.data) - 1));
		DQT_RR(res.r[3], stat("subst", &st));
		DQT_RR(res.r[5], open("keep", O_RDONLY));
		(void)write(progrep, &res, sizeof(res));
		_exit(0);
	}
	if (dq_attach(q, pd) != 0)
		_exit(22);
	er.sharer = rfork(RFPROC);
	if (er.sharer == -1)
		_exit(23);
	if (er.sharer == 0) {
		for (;;)
			(void)pause();
	}
	if (write(rep, &er, sizeof(er)) != sizeof(er) ||
	    write(go[1], "g", 1) != 1)
		_exit(24);
	memset(&es, 0, sizeof(es));
	es.q = q;
	if (dqt_serve_until(q, -1, exit_sup_done, exit_sup_event, &es,
	    30000) != 0)
		_exit(25);
	if (es.fail != 0)
		_exit(es.fail);
	if (!dqt_wait_wmesg(er.prog, "lockf", 30000))
		_exit(28);
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(swap_owner_exit_before_install);
ATF_TC_BODY(swap_owner_exit_before_install, tc)
{
	struct sw_exit_rep er;
	struct sw_res res;
	pid_t pid;
	int lockfd, prep[2], rep[2], status;

	dqt_require_test_access();
	dqt_require_plane();
	ATF_REQUIRE_EQ(0, chmod(".", 0755));
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_write_file("keep", "KEPT", 0644);
	lockfd = open("subst", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(lockfd != -1);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_EX));
	ATF_REQUIRE_EQ(0, pipe(rep));
	ATF_REQUIRE_EQ(0, pipe(prep));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		sw_exit_supervisor(rep[1], prep[1]);
	memset(&er, 0, sizeof(er));
	ATF_REQUIRE_MSG(sw_read_within(rep[0], &er, sizeof(er), 30000),
	    "no report from the supervisor");
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "supervisor: status %#x", status);

	/* The owner is gone, its table is not: now let the open finish. */
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_UN));
	memset(&res, 0, sizeof(res));
	ATF_REQUIRE_MSG(sw_read_within(prep[0], &res, sizeof(res), 30000),
	    "no report from the program");
	ATF_CHECK_MSG(res.r[1].rv >= 0, "open of keep: %s",
	    strerror(res.r[1].err));
	ATF_CHECK_EQ_MSG(-1, res.r[0].rv, "the open returned %ld", res.r[0].rv);
	ATF_CHECK_EQ(EIO, res.r[0].err);
	ATF_CHECK_EQ(4, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "KEPT", 4));
	ATF_CHECK_EQ(-1, res.r[3].rv);
	ATF_CHECK_EQ(EIO, res.r[3].err);
	ATF_CHECK_EQ(-1, res.r[5].rv);
	ATF_CHECK_EQ(EIO, res.r[5].err);
	ATF_CHECK_EQ(0, flock(lockfd, LOCK_EX | LOCK_NB));
	(void)kill(er.sharer, SIGKILL);
	(void)close(lockfd);
	(void)close(rep[0]);
	(void)close(rep[1]);
	(void)close(prep[0]);
	(void)close(prep[1]);
}

/*
 * Case: the same, raced.  The supervisor replies and closes the queue at
 * once, many times.  Each open either returns the working descriptor (it
 * was installed before the queue died) or fails EIO with nothing
 * installed; never anything else.
 */
#define	SW_RACE_ROUNDS	200
#define	SW_RACE_PASSES	3

static void
a_quick(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

static void
p_race_open(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd, next;

	next = dup(0);
	(void)close(next);
	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd != -1)
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	else
		DQT_RR(res->r[4], fcntl(next, F_GETFD));
}

/* One round: the outcome is counted; anything but the two fails. */
static void
sw_race_round(int pass, int i, int *installed, int *refused)
{
	struct sw x;
	struct sw_res res;
	struct dqt_achild ch;

	sw_init(&x, "orig", a_quick);
	dqt_attach_spawn(&x.c, &ch, p_race_open, NULL);
	sw_serve_answered(&x, 1);
	dqt_close_queue(&x.c);
	dqt_attach_collect(&ch, &res, sizeof(res));
	if (res.r[0].rv >= 0) {
		(*installed)++;
		ATF_REQUIRE_EQ_MSG(10, res.r[2].rv,
		    "pass %d round %d: read %ld errno %d", pass, i,
		    res.r[2].rv, res.r[2].err);
		ATF_REQUIRE_EQ(0, memcmp(res.data, "SUBSTITUTE", 10));
	} else {
		(*refused)++;
		ATF_REQUIRE_EQ_MSG(EIO, res.r[0].err,
		    "pass %d round %d: open errno %d", pass, i, res.r[0].err);
		ATF_REQUIRE_EQ(-1, res.r[4].rv);
		ATF_REQUIRE_EQ(EBADF, res.r[4].err);
	}
	dqt_fini(&x.c);
}

ATF_TC(swap_supervisor_gone_race);
ATF_TC_HEAD(swap_supervisor_gone_race, tc)
{
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(swap_supervisor_gone_race, tc)
{
	size_t len;
	int i, installed, ncpu, pass, refused;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	len = sizeof(ncpu);
	ATF_REQUIRE_EQ(0, sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0));
	/*
	 * With one CPU the close and the install cannot overlap, and which
	 * comes first is the scheduler's choice: the race cannot be run.
	 * Said before anything is checked, so that the skip hides nothing.
	 */
	if (ncpu == 1)
		atf_tc_skip("race not exercised: one CPU");
	installed = refused = 0;
	/*
	 * Both outcomes are wanted, and neither is owed by a correct kernel
	 * in any one pass: up to SW_RACE_PASSES passes, ending with the
	 * first that has seen both.
	 */
	for (pass = 0; pass < SW_RACE_PASSES &&
	    (installed == 0 || refused == 0); pass++) {
		for (i = 0; i < SW_RACE_ROUNDS; i++)
			sw_race_round(pass, i, &installed, &refused);
	}
	printf("installed before the death %d, refused %d, in %d passes of "
	    "%d rounds\n", installed, refused, pass, SW_RACE_ROUNDS);
	/* A race that only ever went one way has tested one side of it. */
	ATF_CHECK_MSG(installed > 0 && refused > 0, "race not exercised: "
	    "one way only, %d installed, %d refused in %d passes", installed,
	    refused, pass);
}

/*
 * Case: two files no open could have produced.  open(O_CREAT) of an
 * existing directory is EISDIR in base, and only an O_PATH | O_NOFOLLOW
 * open ends at a symbolic link: neither answers any other request.
 */
static int types_dir, types_link;

static void
p_flags_open(void *arg, void *result)
{
	struct sw_res *res = result;
	struct stat st;
	int fd;

	DQT_RR(res->r[0], fd = open("orig", *(int *)arg, 0644));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], fstat(fd, &st));
	res->mode = st.st_mode;
	DQT_RR(res->r[8], close(fd));
}

static void
a_types(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb)
{
	int fd, flags;

	flags = (int)rb->drs_mode & (O_ACCMODE | O_PATH);
	if (types_dir) {
		fd = sw_open("substdir", flags);
		SW_REFUSED(x, ev, fd, 0, EFTYPE);
		(void)close(fd);
	}
	if (types_link) {
		fd = sw_open("substlink", O_PATH | O_NOFOLLOW);
		if (types_link == 1) {
			SW_REFUSED(x, ev, fd, 0, EFTYPE);
			(void)close(fd);
			fd = sw_open("subst", flags);
		}
	} else
		fd = sw_open("subst", flags);
	/* Taken: the kernel has closed fd. */
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
}

ATF_TC_WITHOUT_HEAD(swap_refused_types);
ATF_TC_BODY(swap_refused_types, tc)
{
	struct sw x;
	struct sw_res res;
	int flags;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	ATF_REQUIRE_EQ(0, mkdir("substdir", 0755));
	ATF_REQUIRE_EQ(0, symlink("subst", "substlink"));

	/* O_CREAT without O_DIRECTORY: not a directory. */
	types_dir = 1;
	types_link = 0;
	flags = O_RDONLY | O_CREAT;
	sw_init(&x, "orig", a_types);
	sw_run(&x, p_flags_open, &flags, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK(S_ISREG(res.mode));
	dqt_fini(&x.c);

	/* O_PATH that follows: not a symbolic link. */
	types_dir = 0;
	types_link = 1;
	flags = O_PATH;
	sw_init(&x, "orig", a_types);
	sw_run(&x, p_flags_open, &flags, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK(S_ISREG(res.mode));
	dqt_fini(&x.c);

	/* O_PATH | O_NOFOLLOW: the link itself. */
	types_link = 2;
	flags = O_PATH | O_NOFOLLOW;
	sw_init(&x, "orig", a_types);
	sw_run(&x, p_flags_open, &flags, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK(S_ISLNK(res.mode));
	dqt_fini(&x.c);
}

/*
 * Case: DQ_SWAP_F_NOXFER.  The installed entry may not be sent on; an
 * entry installed without the flag may, as a descriptor the program
 * opened itself.
 */
static uint32_t noxfer_flags;

static void
p_send(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd, sv[2];

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	if (res->r[1].rv == -1)
		return;
	DQT_RR(res->r[2], dqt_send_fd(sv[0], fd));
}

static void
a_noxfer(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
	    noxfer_flags));
}

ATF_TC_WITHOUT_HEAD(swap_noxfer);
ATF_TC_BODY(swap_noxfer, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);

	noxfer_flags = 0;
	sw_init(&x, "orig", a_noxfer);
	sw_run(&x, p_send, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(0, res.r[1].rv);
	ATF_CHECK_EQ_MSG(0, res.r[2].rv, "dqt_send_fd: %s",
	    strerror(res.r[2].err));
	dqt_fini(&x.c);

	noxfer_flags = DQ_SWAP_F_NOXFER;
	sw_init(&x, "orig", a_noxfer);
	sw_run(&x, p_send, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(0, res.r[1].rv);
	ATF_CHECK_EQ(-1, res.r[2].rv);
	ATF_CHECK_EQ(ENOTCAPABLE, res.r[2].err);
	dqt_fini(&x.c);
}

/*
 * Case: a swap answered from a served (proxy) directory.  There the
 * supervisor is the namespace: the open of a name under the directory
 * takes no PASS and is offered SWAP.  Once the program has narrowed the
 * directory descriptor the lookup is a restricted one: the kernel checks a
 * served answer against the directory's presented path, has nothing to
 * check a real file against, and so offers FD alone; a SWAP reply is
 * EINVAL.  What a limited directory descriptor leaves of the installed
 * rights is dq_start_test:fd_install_limits, for the FD answer it still
 * takes.
 */
static int proxydir_opens;
static int proxydir_bits;	/* per open: 1 SWAP, 2 FD, 4 PASS offered */
static int proxydir_swap_errno;

static void
p_proxydir(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	cap_rights_t lim;
	int dfd, fd;

	DQT_RR(res->r[0], dfd = open("pdir", O_RDONLY | O_DIRECTORY));
	if (dfd == -1)
		return;
	/* Through the directory as the supervisor gave it. */
	DQT_RR(res->r[1], fd = openat(dfd, "f", O_RDONLY));
	if (fd != -1) {
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
		(void)close(fd);
	}
	/* Narrowed: no CAP_WRITE, no CAP_SEEK. */
	DQT_RR(res->r[5], cap_rights_limit(dfd, cap_rights_init(&lim, CAP_LOOKUP,
	    CAP_READ, CAP_FSTAT)));
	DQT_RR(res->r[6], openat(dfd, "f", O_RDONLY));
	(void)close(dfd);
}

static void
a_proxydir(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	struct dq_ident_file *id;
	struct dq_policy pol;
	char presented[PATH_MAX];
	uint64_t obj;
	int32_t reason;

	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	snprintf(presented, sizeof(presented), "%s/pdir", x->cwd);
	ATF_REQUIRE_EQ(0, dq_ident_from_lstat(id, presented, AT_FDCWD,
	    "realdir"));
	dq_policy_default_dir(&pol);
	reason = 0;
	ATF_CHECK_EQ_MSG(0, dq_reply_resolve_fd(x->c.q, ev->de_id, DQ_KIND_DIR,
	    0, id, &pol, &obj, &reason), "FD (directory): %s, reason %d",
	    strerror(errno), reason);
	free(id);
}

static void
a_proxydir_file(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb)
{
	int bits, fd;

	bits = (dq_resolve_accepts(rb, DQ_RESOLVE_SWAP) ? 1 : 0) |
	    (dq_resolve_accepts(rb, DQ_RESOLVE_FD) ? 2 : 0) |
	    (dq_resolve_accepts(rb, DQ_RESOLVE_PASS) ? 4 : 0);
	proxydir_bits |= bits << (4 * proxydir_opens);
	fd = sw_open("subst", O_RDONLY);
	if (proxydir_opens++ == 0) {
		ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
		    0));
	} else {
		/* Not offered: the reply is refused, the event still waits. */
		errno = 0;
		(void)dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0);
		proxydir_swap_errno = errno;
		ATF_CHECK_EQ(0, dq_reply_resolve_errno(x->c.q, ev->de_id,
		    EACCES));
		(void)close(fd);
	}
}

ATF_TC_WITHOUT_HEAD(swap_from_proxy_directory);
ATF_TC_BODY(swap_from_proxy_directory, tc)
{
	struct sw x;
	struct sw_res res;

	ATF_REQUIRE_EQ(0, mkdir("realdir", 0755));
	sw_write_file("subst", "SUBSTITUTE", 0644);
	proxydir_opens = proxydir_bits = proxydir_swap_errno = 0;
	sw_init(&x, "pdir", a_proxydir);
	x.name2 = "f";
	x.answer2 = a_proxydir_file;
	sw_run(&x, p_proxydir, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open of the served directory: %s",
	    strerror(res.r[0].err));
	ATF_CHECK_EQ(2, proxydir_opens);
	/* The directory as given: SWAP and FD, no PASS; the swap answers. */
	ATF_CHECK_EQ_MSG(1 | 2, proxydir_bits & 0xf, "accept bits %#x",
	    proxydir_bits & 0xf);
	ATF_CHECK_MSG(res.r[1].rv >= 0, "openat: %s", strerror(res.r[1].err));
	ATF_CHECK_EQ(10, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "SUBSTITUTE", 10));
	/* Narrowed: FD alone, a SWAP reply EINVAL, the errno answer taken. */
	ATF_CHECK_EQ(0, res.r[5].rv);
	ATF_CHECK_EQ_MSG(2, (proxydir_bits >> 4) & 0xf, "accept bits %#x",
	    (proxydir_bits >> 4) & 0xf);
	ATF_CHECK_EQ(EINVAL, proxydir_swap_errno);
	ATF_CHECK_EQ(-1, res.r[6].rv);
	ATF_CHECK_EQ(EACCES, res.r[6].err);
	dqt_fini(&x.c);
}

/*
 * Case: the requester is killed while its open waits.  The supervisor's
 * later reply finds no event (ESRCH); its descriptor stays open and
 * nothing was taken from it.
 */
static bool killed_once;	/* the answer's entry is CAP_XFER_ONCE */

/* The INTERRUPT for the killed open; RESOLVEs pass; nothing else comes. */
struct killed_wait {
	int		 q;
	uint64_t	 id;
	bool		 interrupted;
};

static bool
killed_done(void *arg)
{

	return (((struct killed_wait *)arg)->interrupted);
}

static void
killed_event(const struct dq_event *ev, void *arg)
{
	struct killed_wait *kw = arg;
	const struct dq_interrupt_body *ib;
	size_t bodylen;

	if (ev->de_op == DQ_OP_INTERRUPT) {
		ib = dq_event_body(ev, &bodylen);
		if (ib != NULL && bodylen >= sizeof(*ib) &&
		    ib->din_id == kw->id)
			kw->interrupted = true;
	} else if (ev->de_op == DQ_OP_RESOLVE)
		ATF_CHECK_EQ(0, dq_reply_resolve_pass(kw->q, ev->de_id));
	else
		ATF_CHECK_MSG(false, "unexpected event, op %u", ev->de_op);
}

static void
a_killed(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	struct killed_wait kw;
	int fd, sv[2];
	bool interrupted;

	fd = sw_open("subst", O_RDONLY);
	if (killed_once)
		ATF_REQUIRE_EQ(0, cap_xfer_limit(fd, CAP_XFER_ONCE));
	ATF_REQUIRE_EQ(0, pdkill(x->pd, SIGKILL));
	/* The kernel tells the supervisor the event was abandoned. */
	memset(&kw, 0, sizeof(kw));
	kw.q = x->c.q;
	kw.id = ev->de_id;
	(void)dqt_serve_until(x->c.q, -1, killed_done, killed_event, &kw,
	    DQT_WAIT_MS);
	interrupted = kw.interrupted;
	ATF_CHECK_MSG(interrupted, "no INTERRUPT for the killed open");
	ATF_CHECK_ERRNO(ESRCH, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
	    0) == -1);
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	if (killed_once) {
		/*
		 * The event was gone before the reply looked for it, so the
		 * kernel never took the file and the entry's one transfer is
		 * still there: it can be sent once, and not twice.  (Only a
		 * requester that leaves while the kernel holds the file
		 * costs the entry its transfer, dq(4).)
		 */
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
		ATF_CHECK_EQ_MSG(0, DQT_ERRNO_OF(dqt_send_fd(sv[0], fd)),
		    "the entry was consumed by a reply that found no event");
		ATF_CHECK_EQ(ENOTCAPABLE, DQT_ERRNO_OF(dqt_send_fd(sv[0], fd)));
		(void)close(sv[0]);
		(void)close(sv[1]);
	}
	(void)close(fd);
}

ATF_TC_WITHOUT_HEAD(swap_requester_killed);
ATF_TC_BODY(swap_requester_killed, tc)
{
	struct sw x;
	struct sw_res res;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	killed_once = false;
	sw_init(&x, "orig", a_killed);
	x.expect_killed = true;
	sw_run(&x, p_plain_open, NULL, &res);
	ATF_CHECK_EQ(1, x.answered);
	dqt_fini(&x.c);

	/* The same with a transfer-once entry. */
	killed_once = true;
	sw_init(&x, "orig", a_killed);
	x.expect_killed = true;
	sw_run(&x, p_plain_open, NULL, &res);
	ATF_CHECK_EQ(1, x.answered);
	dqt_fini(&x.c);
}

/*
 * Case: a Linux program.  Its open(2) enters the same wrapper, so the
 * swap answers it as it answers a native one.
 */
static void
p_linux(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	char *const argv[] = { __DECONST(char *, "dq_swap_linux"), NULL };
	char *const envp[] = { NULL };
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		execve("./dq_swap_linux", argv, envp);
		_exit(127);
	}
	res->r[0].rv = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
}

ATF_TC(swap_linux);
ATF_TC_HEAD(swap_linux, tc)
{
	atf_tc_set_md_var(tc, "require.arch", "amd64");
}
ATF_TC_BODY(swap_linux, tc)
{
	struct sw x;
	struct sw_res res;

	/* Built with the tests (Makefile); missing, the row fails. */
	dqt_copy_helper(tc, "dq_swap_linux", "dq_swap_linux");
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_regular);
	sw_run(&x, p_linux, NULL, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ_MSG(0, res.r[0].rv, "Linux program: bits %#lx",
	    res.r[0].rv);
	dqt_fini(&x.c);
}

/*
 * Admission, consumption and completion (transparency rows T-S03 to
 * T-S06, T-S09, T-S12; C3): a substitute that carries state of its own
 * is refused, the take closes the supervisor's descriptor, and the
 * completion runs as the program's own open.
 */

/* What the supervisor saw: its reply's result and the state after it. */
static struct {
	int	 reply_err;	/* the first reply's errno, 0 if accepted */
	int	 nreplies;	/* replies accepted */
	int	 seek_err;	/* T-S12: lseek of the kept descriptor */
	int	 setfl_err;	/* T-S12: F_SETFL of it */
	int	 close_err;	/* T-S12: close of it */
	int	 gate[2];	/* the supervisor lets the program go on */
	int	 holder;	/* a third open file holding a lock, or -1 */
	int	 release_ms;	/* the holder closes after this, 0: never */
	pthread_t releaser;
	bool	 releasing;
	int	 lockop;	/* the supervisor's own flock (0: none) */
	int	 ofd;		/* F_RDLCK: an OFD read lock (-1: none) */
	bool	 ofd_unlock;	/* released again before the reply */
	int	 oflags;	/* the supervisor's own open */
	bool	 slash;		/* the request had DQ_RF_TRAILINGSLASH */
	int	 fallback_lock;	/* flock of the fresh answer (0: none) */
	int	 fallback_errno; /* answer the refused open with it instead */
} pin;

static void
pin_reset(void)
{

	memset(&pin, 0, sizeof(pin));
	pin.holder = -1;
	pin.ofd = -1;
	pin.gate[0] = pin.gate[1] = -1;
	pin.oflags = O_RDONLY;
}

static void *
pin_release(void *arg __unused)
{

	dqt_msleep(pin.release_ms);
	(void)close(pin.holder);
	return (NULL);
}

/* A third open file of path holds a flock of op until release_ms pass. */
static void pin_join(void);

static void
pin_hold_lock(const char *path, int op, int release_ms)
{

	/*
	 * One holder at a time: the last one has released.  O_CLOFORK: a
	 * forked requester sharing the holder's open file would keep its
	 * lock past the release.
	 */
	pin_join();
	pin.holder = open(path, O_RDONLY | O_CLOEXEC | O_CLOFORK);
	ATF_REQUIRE(pin.holder != -1);
	ATF_REQUIRE_EQ(0, flock(pin.holder, op | LOCK_NB));
	pin.release_ms = release_ms;
	ATF_REQUIRE_EQ(0, pthread_create(&pin.releaser, NULL, pin_release,
	    NULL));
	pin.releasing = true;
}

static void
pin_join(void)
{

	if (pin.releasing)
		ATF_CHECK_EQ(0, pthread_join(pin.releaser, NULL));
	pin.releasing = false;
}

/*
 * Reply with fd and record the result; on a refusal the descriptor is
 * still ours and is closed, and a fresh one (with pin.fallback_lock) or
 * pin.fallback_errno answers, so the program always finishes.  An
 * accepted reply took the descriptor: the kernel closed it (dq(4), Q6).
 */
static void
pin_reply(struct sw *x, const struct dq_event *ev, int fd, const char *path,
    int oflags)
{

	if (dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0) == 0) {
		if (pin.nreplies++ == 0)
			pin.reply_err = 0;
		return;
	}
	if (pin.nreplies == 0)
		pin.reply_err = errno;
	ATF_CHECK_EQ(0, close(fd));
	if (pin.fallback_errno != 0) {
		ATF_CHECK_EQ(0, dq_reply_resolve_errno(x->c.q, ev->de_id,
		    pin.fallback_errno));
		return;
	}
	fd = sw_open(path, oflags);
	if (pin.fallback_lock != 0)
		ATF_REQUIRE_EQ(0, flock(fd, pin.fallback_lock | LOCK_NB));
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	pin.nreplies++;
}

/* A fresh plain answer. */
static void
a_plain(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	pin_reply(x, ev, fd, "subst", O_RDONLY);
}

/* T-S03: the supervisor has read from its file. */
static void
a_offset(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	char buf[4];
	int fd;

	fd = sw_open("subst", O_RDONLY);
	ATF_REQUIRE_EQ(4, read(fd, buf, sizeof(buf)));
	pin_reply(x, ev, fd, "subst", O_RDONLY);
}

ATF_TC_WITHOUT_HEAD(swap_offset_carried);
ATF_TC_BODY(swap_offset_carried, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_offset);
	sw_run(&x, p_plain_open, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	/*
	 * A file that was read is refused (it was accepted, and the
	 * program's first read began mid-file); the fresh one reads whole.
	 */
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ(10, res.r[2].rv);
	ATF_CHECK_EQ(0, memcmp(res.data, "SUBSTITUTE", 10));
	dqt_fini(&x.c);
}

/*
 * The program holds the open file it was given; a second open file of
 * the substitute, by its own name (passed), probes the locks on it.
 */
static void
p_lockprobe(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct flock fl;
	int fd, fd2;

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd == -1)
		return;
	DQT_RR(res->r[1], fd2 = open("subst", O_RDWR));
	if (fd2 == -1)
		return;
	DQT_RR(res->r[2], flock(fd2, LOCK_EX | LOCK_NB));
	(void)flock(fd2, LOCK_UN);
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	DQT_RR(res->r[3], fcntl(fd2, F_OFD_SETLK, &fl));
	(void)close(fd2);
	DQT_RR(res->r[8], close(fd));
}

static void
a_locked(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	struct flock fl;
	int fd;

	fd = sw_open("subst", O_RDONLY);
	if (pin.lockop != 0)
		ATF_REQUIRE_EQ(0, flock(fd, pin.lockop | LOCK_NB));
	if (pin.ofd != -1) {
		memset(&fl, 0, sizeof(fl));
		fl.l_type = pin.ofd;
		fl.l_whence = SEEK_SET;
		ATF_REQUIRE_EQ(0, fcntl(fd, F_OFD_SETLK, &fl));
		if (pin.ofd_unlock) {
			fl.l_type = F_UNLCK;
			ATF_REQUIRE_EQ(0, fcntl(fd, F_OFD_SETLK, &fl));
		}
	}
	pin_reply(x, ev, fd, "subst", O_RDONLY);
}

ATF_TC_WITHOUT_HEAD(swap_flock_carried);
ATF_TC_BODY(swap_flock_carried, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	pin.lockop = LOCK_EX;
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_locked);
	sw_run(&x, p_lockprobe, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	/*
	 * A flock the open did not ask for is refused (the program held it,
	 * and another open file could not take it); then nothing is held.
	 */
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ_MSG(0, res.r[2].rv, "flock probe: %s",
	    strerror(res.r[2].err));
	dqt_fini(&x.c);
}

ATF_TC_WITHOUT_HEAD(swap_ofdlock_carried);
ATF_TC_BODY(swap_ofdlock_carried, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	pin.ofd = F_RDLCK;
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_locked);
	sw_run(&x, p_lockprobe, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	/* An OFD lock is refused (the program's open file held it). */
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ_MSG(0, res.r[3].rv, "OFD probe: %s",
	    strerror(res.r[3].err));
	dqt_fini(&x.c);

	/*
	 * A lock taken and released again: FHASOFDLOCK is sticky, so the
	 * file is refused too (it was accepted).
	 */
	pin_reset();
	pin.ofd = F_RDLCK;
	pin.ofd_unlock = true;
	sw_init(&x, "orig", a_locked);
	sw_run(&x, p_lockprobe, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ_MSG(0, res.r[3].rv, "OFD probe: %s",
	    strerror(res.r[3].err));
	dqt_fini(&x.c);
}

/*
 * T-S03, T-S04: an O_CREAT | O_EXCL | O_EXLOCK open answered with a file
 * the supervisor created, which a third open file locks (shared) before
 * the program's lock is taken.
 */
static void
p_excl_lock(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	long start;
	int fd;

	start = dqt_now_ms();
	DQT_RR(res->r[0], fd = open("newfile", O_RDWR | O_CREAT | O_EXCL |
	    O_EXLOCK, 0644));
	res->size = dqt_now_ms() - start;	/* the open's time, ms */
	if (fd != -1)
		DQT_RR(res->r[8], close(fd));
}

static int	excl_third_err;	/* a third open file's LOCK_SH, errno */

static void
a_excl_lock(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd, third;

	fd = open("newsubst", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
	    O_CLOFORK, 0644);
	ATF_REQUIRE_MSG(fd != -1, "create: %s", strerror(errno));
	if (pin.lockop != 0)
		ATF_REQUIRE_EQ(0, flock(fd, pin.lockop | LOCK_NB));
	if (pin.lockop == LOCK_EX) {
		/* The supervisor's lock keeps a third locker out. */
		third = open("newsubst", O_RDONLY | O_CLOEXEC | O_CLOFORK);
		ATF_REQUIRE(third != -1);
		excl_third_err = DQT_ERRNO_OF(flock(third, LOCK_SH | LOCK_NB));
		(void)close(third);
	} else
		pin_hold_lock("newsubst", LOCK_SH, 1500);
	pin_reply(x, ev, fd, "newsubst", O_RDWR);
}

ATF_TC_WITHOUT_HEAD(swap_excl_exlock_third_locker);
ATF_TC_BODY(swap_excl_exlock_third_locker, tc)
{
	struct sw x;
	struct sw_res res;

	/*
	 * A created file without the supervisor's lock is refused: a third
	 * locker could come between the creation and the program's lock
	 * (its exclusive lock waited for one; base never waits here,
	 * F_FIRSTOPEN).  The supervisor then answers EAGAIN, at once.
	 */
	pin_reset();
	pin.fallback_errno = EAGAIN;
	sw_init(&x, "newfile", a_excl_lock);
	sw_run(&x, p_excl_lock, NULL, &res);
	pin_join();
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EAGAIN, res.r[0].err);
	ATF_CHECK_MSG(res.size < 1300, "the open took %jd ms",
	    (intmax_t)res.size);
	dqt_fini(&x.c);
	ATF_REQUIRE_EQ(0, unlink("newsubst"));

	/*
	 * The supervisor locks what it creates before it answers: no third
	 * locker gets in, and the program's lock is taken at once.
	 */
	pin_reset();
	pin.lockop = LOCK_EX;
	sw_init(&x, "newfile", a_excl_lock);
	sw_run(&x, p_excl_lock, NULL, &res);
	ATF_CHECK_EQ(0, pin.reply_err);
	ATF_CHECK_EQ(EWOULDBLOCK, excl_third_err);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_MSG(res.size < 1300, "the open took %jd ms",
	    (intmax_t)res.size);
	dqt_fini(&x.c);
}

ATF_TC_WITHOUT_HEAD(swap_excl_lock_upgrade_third_sh);
ATF_TC_BODY(swap_excl_lock_upgrade_third_sh, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	/* The supervisor hands over a shared lock for an O_EXLOCK request. */
	pin.lockop = LOCK_SH;
	sw_init(&x, "newfile", a_excl_lock);
	sw_run(&x, p_excl_lock, NULL, &res);
	pin_join();
	ATF_CHECK_EQ(0, pin.reply_err);
	/*
	 * The upgrade to exclusive is not waited for (it waited for the
	 * third shared lock): the open fails EIO at once, a bad answer.
	 */
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(EIO, res.r[0].err);
	ATF_CHECK_MSG(res.size < 1300, "the open took %jd ms",
	    (intmax_t)res.size);
	dqt_fini(&x.c);
}

/*
 * T-S04: an O_EXLOCK wait under SA_RESTART.  A real file restarts the
 * open after the handler and waits on; so does the swapped one, which
 * consults the supervisor again (it answered EINTR).
 */
static void
pin_alarm(int sig __unused)
{
}

/*
 * open(path, O_EXLOCK) under a SIGALRM handler with SA_RESTART, the alarm
 * at 1 s; the open's result and its time.
 */
static void
p_exlock_signal(void *arg, void *result)
{
	struct sw_res *res = result;
	struct sigaction sa;
	long start;
	int fd;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = pin_alarm;
	sa.sa_flags = SA_RESTART;
	(void)sigaction(SIGALRM, &sa, NULL);
	(void)alarm(1);
	start = dqt_now_ms();
	DQT_RR(res->r[0], fd = open(arg, O_RDONLY | O_EXLOCK));
	res->size = dqt_now_ms() - start;
	(void)alarm(0);
	if (fd != -1)
		DQT_RR(res->r[8], close(fd));
}

ATF_TC_WITHOUT_HEAD(swap_exlock_signal);
ATF_TC_BODY(swap_exlock_signal, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);

	/*
	 * The real control, unattached: the open is restarted after the
	 * handler and waits for the lock, released 2.5 s from now.
	 */
	pin_hold_lock("subst", LOCK_EX, 2500);
	memset(&res, 0, sizeof(res));
	dqt_run_child(p_exlock_signal, __DECONST(char *, "subst"), &res,
	    sizeof(res));
	pin_join();
	ATF_CHECK_MSG(res.r[0].rv >= 0, "real open: %s",
	    strerror(res.r[0].err));
	ATF_CHECK_MSG(res.size >= 2000, "the real open took %jd ms",
	    (intmax_t)res.size);

	/* The swap: the same lock, held again for 2.5 s. */
	pin_hold_lock("subst", LOCK_EX, 2500);
	sw_init(&x, "orig", a_plain);
	sw_run(&x, p_exlock_signal, __DECONST(char *, "orig"), &res);
	pin_join();
	/* The restart is a new open: the supervisor answers twice. */
	ATF_CHECK_EQ(2, x.answered);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "swapped open: %s",
	    strerror(res.r[0].err));
	ATF_CHECK_MSG(res.size >= 2000, "the swapped open took %jd ms",
	    (intmax_t)res.size);
	dqt_fini(&x.c);
}

/*
 * T-S05: a trailing slash.  The real file's open(2) is ENOTDIR; a swap of
 * a non-directory is refused and a served FD answer of one is ENOTDIR (both
 * were accepted).
 */
static void
p_slash(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd;

	DQT_RR(res->r[1], fd = open("subst/", O_RDONLY));
	if (fd != -1)
		(void)close(fd);
	DQT_RR(res->r[0], fd = open("orig/", O_RDONLY));
	if (fd != -1)
		DQT_RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	if (fd != -1)
		(void)close(fd);
}

static void
a_slash(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb)
{
	int fd;

	pin.slash = (rb->drs_rflags & DQ_RF_TRAILINGSLASH) != 0;
	fd = sw_open("subst", O_RDONLY);
	if (dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0) == 0) {
		pin.nreplies++;
		pin.reply_err = 0;
	} else {
		pin.reply_err = errno;
		(void)close(fd);
		ATF_CHECK_EQ(0, dq_reply_resolve_pass(x->c.q, ev->de_id));
	}
}

static void
a_slash_fd(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	char path[PATH_MAX];
	uint64_t object;

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	ATF_REQUIRE(realpath("subst", path) != NULL);
	ATF_REQUIRE_EQ(0, stat(path, &st));
	ATF_REQUIRE_EQ(0, statfs(path, &sfs));
	ATF_REQUIRE_EQ(0, dq_ident_from_stat(ident, path, &st, &sfs, -1));
	dq_policy_default(&pol);
	pin.reply_err = dq_reply_resolve_fd(x->c.q, ev->de_id, DQ_KIND_FILE,
	    0, ident, &pol, &object, NULL) == 0 ? 0 : errno;
	free(ident);
}

ATF_TC_WITHOUT_HEAD(swap_trailing_slash);
ATF_TC_BODY(swap_trailing_slash, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig/", a_slash);
	sw_run(&x, p_slash, NULL, &res);
	ATF_CHECK_EQ(-1, res.r[1].rv);
	ATF_CHECK_EQ(ENOTDIR, res.r[1].err);
	ATF_CHECK_EQ(1, x.answered);
	/*
	 * The RESOLVE carries DQ_RF_TRAILINGSLASH (it did not: namei sets
	 * TRAILINGSLASH only while it walks, after the consult), a regular
	 * file is refused for "orig/", and the passed open is ENOTDIR.
	 */
	ATF_CHECK(pin.slash);
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(ENOTDIR, res.r[0].err);
	dqt_fini(&x.c);
}

ATF_TC_WITHOUT_HEAD(fd_trailing_slash);
ATF_TC_BODY(fd_trailing_slash, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig/", a_slash_fd);
	sw_run(&x, p_slash, NULL, &res);
	ATF_CHECK_EQ(1, x.answered);
	ATF_CHECK_EQ(0, pin.reply_err);
	/* The program's completion refuses a file for "orig/" (it took it). */
	ATF_CHECK_EQ(-1, res.r[0].rv);
	ATF_CHECK_EQ(ENOTDIR, res.r[0].err);
	dqt_fini(&x.c);
}

/*
 * T-S06: the supervisor's entry carries states of its own: a sticky
 * O_RESOLVE_BENEATH, and mmap only in capability mode.
 */
static void
p_states(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	void *p;
	int fd;

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd == -1)
		return;
	res->fdflags = fcntl(fd, F_GETFD);
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	res->r[1].rv = p == MAP_FAILED ? -1 : 0;
	res->r[1].err = p == MAP_FAILED ? errno : 0;
	if (p != MAP_FAILED)
		(void)munmap(p, 4096);
	DQT_RR(res->r[8], close(fd));
}

static void
a_states(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	/* UF_RESOLVE_BENEATH, sticky once set. */
	ATF_REQUIRE_EQ(0, fcntl(fd, F_SETFD, FD_CLOEXEC | FD_CLOFORK |
	    FD_RESOLVE_BENEATH));
	ATF_REQUIRE((fcntl(fd, F_GETFD) & FD_RESOLVE_BENEATH) != 0);
	ATF_REQUIRE_EQ(0, cap_mmap_capmode(fd));
	pin_reply(x, ev, fd, "subst", O_RDONLY);
}

ATF_TC_WITHOUT_HEAD(swap_entry_states);
ATF_TC_BODY(swap_entry_states, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_states);
	sw_run(&x, p_states, NULL, &res);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	/*
	 * Refused (both states became the program's); the fresh answer
	 * carries neither.
	 */
	ATF_CHECK_EQ(EFTYPE, pin.reply_err);
	ATF_CHECK((res.fdflags & FD_RESOLVE_BENEATH) == 0);
	ATF_CHECK_EQ_MSG(0, res.r[1].rv, "mmap: %s", strerror(res.r[1].err));
	dqt_fini(&x.c);
}

/*
 * T-S12: after the reply the supervisor tries to move the offset and set
 * O_NONBLOCK through its descriptor; the program then looks at its own.
 */
static void
p_retained(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	char c;
	int fd;

	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd == -1)
		return;
	(void)read(pin.gate[0], &c, 1);
	DQT_RR(res->r[1], lseek(fd, 0, SEEK_CUR));
	res->flflags = fcntl(fd, F_GETFL);
	DQT_RR(res->r[8], close(fd));
}

static void
a_retained(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	pin.reply_err = dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0) == 0 ?
	    0 : errno;
	pin.seek_err = DQT_ERRNO_OF(lseek(fd, 5, SEEK_SET));
	pin.setfl_err = DQT_ERRNO_OF(fcntl(fd, F_SETFL, O_NONBLOCK));
	ATF_REQUIRE_EQ(1, write(pin.gate[1], "g", 1));
	pin.close_err = DQT_ERRNO_OF(close(fd));
}

ATF_TC_WITHOUT_HEAD(swap_entry_retained);
ATF_TC_BODY(swap_entry_retained, tc)
{
	struct sw x;
	struct sw_res res;

	pin_reset();
	ATF_REQUIRE_EQ(0, pipe(pin.gate));
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_retained);
	sw_run(&x, p_retained, NULL, &res);
	ATF_CHECK_EQ(0, pin.reply_err);
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	/*
	 * The take closed the supervisor's descriptor: nothing it does
	 * reaches the program's open file (it stayed open and shared the
	 * offset and the status flags).
	 */
	ATF_CHECK_EQ(EBADF, pin.seek_err);
	ATF_CHECK_EQ(EBADF, pin.setfl_err);
	ATF_CHECK_EQ(EBADF, pin.close_err);
	ATF_CHECK_EQ(0, res.r[1].rv);
	ATF_CHECK((res.flflags & O_NONBLOCK) == 0);
	(void)close(pin.gate[0]);
	(void)close(pin.gate[1]);
	dqt_fini(&x.c);
}

/*
 * R2-H1: a reply that races the program's interruption.  The program
 * opens in a loop with a short timer; every reply's result is checked
 * against what is left of the supervisor's descriptor: 0 and ECANCELED
 * took it, ESRCH did not.  debug.dq.delay_swap_take holds the first
 * replies between the take and the event lookup for a second, so the
 * program's timer fires there and ECANCELED is exercised.
 */
#define	LATE_ROUNDS	200
#define	LATE_DELAYED	3
#define	DELAY_SWAP_TAKE	"debug.dq.delay_swap_take"

static struct {
	int	 ok, srch, canceled, other;
	int	 bad;		/* a result that contradicts the descriptor */
} late;

static void
p_late(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	struct sigaction sa;
	struct itimerval it;
	int fd, i;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = pin_alarm;
	(void)sigaction(SIGALRM, &sa, NULL);
	for (i = 0; i < LATE_ROUNDS; i++) {
		memset(&it, 0, sizeof(it));
		/* 50 us to 50 ms: some opens lose to the timer, some win. */
		it.it_value.tv_usec = 50 + (i * 997) % 50000;
		(void)setitimer(ITIMER_REAL, &it, NULL);
		fd = open("orig", O_RDONLY);
		memset(&it, 0, sizeof(it));
		(void)setitimer(ITIMER_REAL, &it, NULL);
		if (fd != -1) {
			res->r[0].rv++;
			(void)close(fd);
		} else if (errno == EINTR)
			res->r[1].rv++;
		else
			res->r[2].rv++;
	}
}

static void
a_late(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	bool open_after;
	int error, fd;

	fd = sw_open("subst", O_RDONLY);
	error = dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0) == 0 ? 0 :
	    errno;
	/* Nothing else opens a file meanwhile: the number is not reused. */
	open_after = fcntl(fd, F_GETFD) != -1;
	if (error == 0)
		late.ok++;
	else if (error == ESRCH)
		late.srch++;
	else if (error == ECANCELED)
		late.canceled++;
	else
		late.other++;
	if (open_after != (error != 0 && error != ECANCELED))
		late.bad++;
	if (open_after)
		(void)close(fd);
}

ATF_TC_WITH_CLEANUP(swap_late_reply_consumed);
ATF_TC_HEAD(swap_late_reply_consumed, tc)
{
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(swap_late_reply_consumed, tc)
{
	struct sw x;
	struct sw_res res;

	dqt_require_fault_knob(DELAY_SWAP_TAKE);
	pin_reset();
	memset(&late, 0, sizeof(late));
	dqt_sysctl_save_set_uint(DELAY_SWAP_TAKE, LATE_DELAYED);
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_init(&x, "orig", a_late);
	/* The program's timer must be able to end its lookups (D192). */
	ATF_REQUIRE_EQ(0, dq_queue_set_flags(x.c.q, DQ_QF_INTR, 0, NULL));
	sw_run(&x, p_late, NULL, &res);
	ATF_REQUIRE(dqt_sysctl_restore(DELAY_SWAP_TAKE));
	printf("late: %d answered, %d ESRCH, %d ECANCELED, %d other; program: "
	    "%ld opened, %ld EINTR, %ld other\n", late.ok, late.srch,
	    late.canceled, late.other, res.r[0].rv, res.r[1].rv, res.r[2].rv);
	ATF_CHECK_EQ(0, late.other);
	ATF_CHECK_EQ(0, res.r[2].rv);
	/* Each outcome says truly whether the descriptor was taken (Q6). */
	ATF_CHECK_EQ(0, late.bad);
	/* The race was run: a delayed take lost to the program's timer. */
	ATF_CHECK_MSG(late.canceled > 0, "no reply was ECANCELED");
	ATF_CHECK_MSG(late.ok > 0, "no reply was accepted");
	dqt_fini(&x.c);
}
ATF_TC_CLEANUP(swap_late_reply_consumed, tc)
{

	(void)dqt_sysctl_restore(DELAY_SWAP_TAKE);
}

/*
 * T-S09: the MAC open notification for the program's own credential.
 * Counted for the program's pid with the mac_framework probe (mac_test,
 * preloaded in the test guests, implements the hook), and inotify's
 * IN_OPEN on the substitute, which only the supervisor's open raises.
 */
#define	DTRACE		"/usr/sbin/dtrace"

static void
p_gated_open(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	char c;
	int fd;

	(void)read(pin.gate[0], &c, 1);
	DQT_RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd != -1)
		(void)close(fd);
	/* The control: an open of a real file, passed. */
	DQT_RR(res->r[1], fd = open("real", O_RDONLY));
	if (fd != -1)
		(void)close(fd);
}

ATF_TC(swap_notify_open);
ATF_TC_HEAD(swap_notify_open, tc)
{
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(swap_notify_open, tc)
{
	struct inotify_event *ie;
	struct dqt_achild ch;
	struct sw x;
	struct sw_res res;
	char prog[512], line[256], ibuf[4096];
	FILE *out;
	ssize_t n;
	long count;
	pid_t dpid;
	int error, in, nopen, pfd[2], status, wd;
	char *p;

	ATF_REQUIRE_MSG(access(DTRACE, X_OK) == 0, "no %s", DTRACE);
	pin_reset();
	ATF_REQUIRE_EQ(0, pipe(pin.gate));
	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	sw_write_file("real", "REAL", 0644);
	in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	ATF_REQUIRE(in != -1);
	wd = inotify_add_watch(in, "subst", IN_OPEN);
	ATF_REQUIRE(wd != -1);
	sw_init(&x, "orig", a_plain);
	dqt_attach_spawn(&x.c, &ch, p_gated_open, NULL);
	x.pd = ch.pd;

	(void)snprintf(prog, sizeof(prog),
	    "BEGIN { printf(\"ready\\n\"); } "
	    "mac_framework::vnode_notify_open:mac-check-ok /pid == %d/ "
	    "{ n++; } END { printf(\"count %%d\\n\", n); }", (int)ch.pid);
	ATF_REQUIRE_EQ(0, pipe(pfd));
	dpid = fork();
	ATF_REQUIRE(dpid != -1);
	if (dpid == 0) {
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)dup2(pfd[1], STDERR_FILENO);
		(void)close(pfd[0]);
		execl(DTRACE, "dtrace", "-q", "-n", prog, (char *)NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	out = fdopen(pfd[0], "r");
	ATF_REQUIRE(out != NULL);
	count = -1;
	while (fgets(line, sizeof(line), out) != NULL) {
		if (strcmp(line, "ready\n") == 0) {
			count = 0;
			break;
		}
		printf("dtrace: %s", line);
	}
	ATF_REQUIRE_EQ(1, write(pin.gate[1], "g", 1));
	error = dqt_serve_until(x.c.q, ch.pd, NULL, sw_event, &x, 30000);
	ATF_REQUIRE_EQ_MSG(0, error, "serving the queue: %s", strerror(error));
	x.pd = -1;
	status = dqt_attach_wait(&ch, &res, sizeof(res));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_MSG(count == 0, "dtrace did not start");
	(void)kill(dpid, SIGINT);
	count = -1;
	while (fgets(line, sizeof(line), out) != NULL)
		if (sscanf(line, "count %ld", &count) == 1)
			break;
	(void)fclose(out);
	(void)waitpid(dpid, &status, 0);
	ATF_REQUIRE_MSG(count != -1, "dtrace printed no count");

	nopen = 0;
	while ((n = read(in, ibuf, sizeof(ibuf))) > 0) {
		for (p = ibuf; p < ibuf + n; p += sizeof(*ie) + ie->len) {
			ie = (struct inotify_event *)(void *)p;
			if ((ie->mask & IN_OPEN) != 0)
				nopen++;
		}
	}
	ATF_CHECK_MSG(res.r[0].rv >= 0, "open: %s", strerror(res.r[0].err));
	ATF_CHECK_MSG(res.r[1].rv >= 0, "real open: %s",
	    strerror(res.r[1].err));
	/* The supervisor's open of the substitute, and nothing else. */
	ATF_CHECK_EQ(1, nopen);
	/*
	 * The swapped open notifies the policies for the program, as its
	 * own open would (it did not: only the control's open did).
	 */
	ATF_CHECK_EQ_MSG(2, count, "vnode_notify_open fired %ld times",
	    count);
	(void)close(in);
	(void)close(pin.gate[0]);
	(void)close(pin.gate[1]);
	dqt_fini(&x.c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, swap_regular);
	ATF_TP_ADD_TC(tp, swap_refused_to_supervisor);
	ATF_TP_ADD_TC(tp, swap_only_for_open);
	ATF_TP_ADD_TC(tp, swap_exlock);
	ATF_TP_ADD_TC(tp, swap_trunc);
	ATF_TP_ADD_TC(tp, swap_program_denied);
	ATF_TP_ADD_TC(tp, swap_survives_supervisor);
	ATF_TP_ADD_TC(tp, swap_supervisor_gone_before_install);
	ATF_TP_ADD_TC(tp, swap_supervisor_gone_after_trunc);
	ATF_TP_ADD_TC(tp, swap_owner_exit_before_install);
	ATF_TP_ADD_TC(tp, swap_supervisor_gone_race);
	ATF_TP_ADD_TC(tp, swap_refused_types);
	ATF_TP_ADD_TC(tp, swap_created);
	ATF_TP_ADD_TC(tp, swap_opath_device);
	ATF_TP_ADD_TC(tp, swap_directory);
	ATF_TP_ADD_TC(tp, swap_emfile);
	ATF_TP_ADD_TC(tp, swap_noxfer);
	ATF_TP_ADD_TC(tp, swap_from_proxy_directory);
	ATF_TP_ADD_TC(tp, swap_requester_killed);
	ATF_TP_ADD_TC(tp, swap_linux);
	ATF_TP_ADD_TC(tp, swap_offset_carried);
	ATF_TP_ADD_TC(tp, swap_flock_carried);
	ATF_TP_ADD_TC(tp, swap_ofdlock_carried);
	ATF_TP_ADD_TC(tp, swap_excl_exlock_third_locker);
	ATF_TP_ADD_TC(tp, swap_excl_lock_upgrade_third_sh);
	ATF_TP_ADD_TC(tp, swap_exlock_signal);
	ATF_TP_ADD_TC(tp, swap_trailing_slash);
	ATF_TP_ADD_TC(tp, fd_trailing_slash);
	ATF_TP_ADD_TC(tp, swap_entry_states);
	ATF_TP_ADD_TC(tp, swap_entry_retained);
	ATF_TP_ADD_TC(tp, swap_late_reply_consumed);
	ATF_TP_ADD_TC(tp, swap_notify_open);
	return (atf_no_error());
}
