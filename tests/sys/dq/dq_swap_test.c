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
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
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

#define	SW_BUFSIZE	(256 * 1024)
#define	SW_NRES		24
#define	SW_UID		65534		/* nobody */

struct sw;
typedef void sw_answer_t(struct sw *, const struct dq_event *,
    const struct dq_resolve_body *);

struct sw {
	struct dqt_ctl	 c;
	const char	*name;		/* the open to answer: path suffix */
	sw_answer_t	*answer;
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

#define	RR(slot, call) do {						\
	errno = 0;							\
	(slot).rv = (long)(call);					\
	(slot).err = (slot).rv == -1 ? errno : 0;			\
} while (0)

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
sw_is_target(const struct sw *x, const struct dq_resolve_body *rb,
    const char *path)
{
	size_t nl, pl;

	if (rb->drs_op != DQ_ROP_OPEN)
		return (false);
	nl = strlen(x->name);
	pl = strlen(path);
	return (pl >= nl && strcmp(path + pl - nl, x->name) == 0 &&
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
	if (sw_is_target(x, rb, path)) {
		x->answered++;
		x->accept = rb->drs_accept;
		x->mode = rb->drs_mode;
		x->answer(x, ev, rb);
		return;
	}
	if (x->answered > 0)
		x->after_resolve++;
	if (dq_reply_resolve_pass(x->c.q, ev->de_id) != 0 && errno != ESRCH)
		atf_tc_fail("PASS of \"%s\": %s", path, strerror(errno));
}

/* Serve the queue until the program has exited; collect its result. */
static void
sw_run(struct sw *x, dqt_child_fn fn, void *arg, struct sw_res *res)
{
	struct dqt_achild ch;
	struct pollfd pfd[2];
	const struct dq_event *ev;
	char *buf;
	ssize_t got;
	int status;
	bool hup;

	buf = malloc(SW_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(fcntl(x->c.q, F_SETFL, O_NONBLOCK) != -1);
	dqt_attach_spawn(&x->c, &ch, fn, arg);
	for (hup = false; !hup;) {
		pfd[0].fd = x->c.q;
		pfd[0].events = POLLIN;
		pfd[1].fd = ch.pd;
		pfd[1].events = POLLHUP;
		pfd[0].revents = pfd[1].revents = 0;
		if (poll(pfd, 2, 30000) <= 0)
			atf_tc_fail("the program neither asked nor exited");
		hup = (pfd[1].revents & POLLHUP) != 0;
		while (dq_read_events(x->c.q, buf, SW_BUFSIZE, &got) == 0 &&
		    got > 0) {
			for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
			    ev = dq_event_next(buf, (size_t)got, ev))
				sw_handle(x, ev);
		}
	}
	status = dqt_attach_wait(&ch, res, sizeof(*res));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the program failed, status %#x", status);
	free(buf);
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

	RR(res->r[0], fd = open("orig", O_RDONLY | O_CLOEXEC));
	if (fd == -1)
		return;
	RR(res->r[1], fstat(fd, &st));
	res->ino = st.st_ino;
	res->size = st.st_size;
	RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	res->fdflags = fcntl(fd, F_GETFD);
	res->flflags = fcntl(fd, F_GETFL);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	RR(res->r[3], fcntl(fd, F_KINFO, &kif));
	res->kftype = kif.kf_type;
	RR(res->r[4], lseek(fd, 0, SEEK_SET));
	RR(res->r[5], read(fd, res->data, 4));
	RR(res->r[6], lseek(fd, 0, SEEK_CUR));
	RR(res->r[7], flock(fd, LOCK_SH));
	RR(res->r[8], close(fd));
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
	/* The reply does not close the supervisor's descriptor. */
	ATF_CHECK(fcntl(fd, F_GETFD) != -1);
	/* A second reply finds no event and consumes nothing. */
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
	RR(res->r[0], fd = open("orig", flags, 0644));
	if (fd == -1)
		return;
	RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	RR(res->r[8], close(fd));
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
	 * The queue itself: the reply ioctl holds a reference to it, so the
	 * sole-reference rule refuses it before its type is looked at.  Any
	 * other device: not a regular file.
	 */
	SW_REFUSED(x, ev, x->c.q, 0, EBUSY);
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
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
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

	RR(res->r[0], stat("orig", &st));
	res->size = st.st_size;
	RR(res->r[1], chdir("dir"));
}

ATF_TC_WITHOUT_HEAD(swap_only_for_open);
ATF_TC_BODY(swap_only_for_open, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct pollfd pfd[2];
	struct sw_res res;
	const struct dq_event *ev;
	const struct dq_resolve_body *rb;
	const char *path;
	char *buf;
	ssize_t got;
	int fd, nstat, nchdir, status;
	bool hup;

	dqt_require_plane();
	sw_write_file("orig", "ORIGINAL", 0644);
	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	dqt_init_manual(&c);
	buf = malloc(SW_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(fcntl(c.q, F_SETFL, O_NONBLOCK) != -1);
	fd = sw_open("orig", O_RDONLY);
	nstat = nchdir = 0;
	dqt_attach_spawn(&c, &ch, p_notopen, NULL);
	for (hup = false; !hup;) {
		pfd[0].fd = c.q;
		pfd[0].events = POLLIN;
		pfd[1].fd = ch.pd;
		pfd[1].events = POLLHUP;
		pfd[0].revents = pfd[1].revents = 0;
		ATF_REQUIRE(poll(pfd, 2, 30000) > 0);
		hup = (pfd[1].revents & POLLHUP) != 0;
		while (dq_read_events(c.q, buf, SW_BUFSIZE, &got) == 0 &&
		    got > 0) {
			for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
			    ev = dq_event_next(buf, (size_t)got, ev)) {
				if (ev->de_op != DQ_OP_RESOLVE)
					continue;
				ATF_REQUIRE_EQ(0, dq_event_resolve(ev, &rb,
				    &path, NULL, NULL, NULL));
				if (rb->drs_op == DQ_ROP_STAT ||
				    rb->drs_op == DQ_ROP_CHDIR) {
					if (rb->drs_op == DQ_ROP_STAT)
						nstat++;
					else
						nchdir++;
					ATF_CHECK(!dq_resolve_accepts(rb,
					    DQ_RESOLVE_SWAP));
					ATF_CHECK_ERRNO(EINVAL,
					    dq_reply_resolve_swap(c.q,
					    ev->de_id, fd, 0) == -1);
				}
				ATF_CHECK_EQ(0, dq_reply_resolve_pass(c.q,
				    ev->de_id));
			}
		}
	}
	status = dqt_attach_wait(&ch, &res, sizeof(res));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK(nstat >= 1);
	ATF_CHECK(nchdir >= 1);
	ATF_CHECK_EQ(0, res.r[0].rv);
	ATF_CHECK_EQ(8, res.size);
	ATF_CHECK_EQ(0, res.r[1].rv);
	(void)close(fd);
	free(buf);
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

	RR(res->r[0], fd = open("orig", O_RDONLY | O_EXLOCK));
	if (fd == -1)
		return;
	/* "subst" by its own name is passed: a second open file of it. */
	RR(res->r[1], fd2 = open("subst", O_RDONLY));
	RR(res->r[2], flock(fd2, LOCK_EX | LOCK_NB));
	RR(res->r[3], close(fd));
	RR(res->r[4], flock(fd2, LOCK_EX | LOCK_NB));
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
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
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
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
}

static void
p_write(void *arg, void *result)
{
	struct sw_res *res = result;
	int fd, flags;

	flags = *(int *)arg;
	if ((flags & 0x40000000) != 0) {
		flags &= ~0x40000000;
		RR(res->r[9], setgid(SW_UID));
		RR(res->r[10], setuid(SW_UID));
	}
	RR(res->r[0], fd = open("orig", flags, 0444));
	if (fd == -1)
		return;
	RR(res->r[1], write(fd, "new", 3));
	RR(res->r[8], close(fd));
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
	(void)close(fd);
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

	RR(res->r[0], fd = open("orig", O_PATH));
	if (fd == -1)
		return;
	RR(res->r[1], fstat(fd, &st));
	res->mode = st.st_mode;
	RR(res->r[2], read(fd, &b, 1));
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
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
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

	RR(res->r[0], dfd = open("orig", O_RDONLY | O_DIRECTORY));
	if (dfd == -1)
		return;
	RR(res->r[1], fd = openat(dfd, "inside", O_RDONLY));
	if (fd != -1) {
		RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
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
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
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
	RR(res->r[9], getrlimit(RLIMIT_NOFILE, &save));
	rl = save;
	rl.rlim_cur = 32;
	RR(res->r[10], setrlimit(RLIMIT_NOFILE, &rl));
	for (i = 0; i < 64; i++) {
		if (dup(0) == -1)
			break;
	}
	RR(res->r[0], fd = open("orig", O_RDONLY));
	RR(res->r[11], setrlimit(RLIMIT_NOFILE, &save));
	RR(res->r[1], fd = open("orig", O_RDONLY));
	if (fd != -1)
		RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
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
static void
sw_serve_answered(struct sw *x, char *buf, int n)
{
	struct pollfd pfd;
	const struct dq_event *ev;
	ssize_t got;

	while (x->answered < n) {
		pfd.fd = x->c.q;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 30000) <= 0)
			atf_tc_fail("the program did not ask");
		while (dq_read_events(x->c.q, buf, SW_BUFSIZE, &got) == 0 &&
		    got > 0) {
			for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
			    ev = dq_event_next(buf, (size_t)got, ev))
				sw_handle(x, ev);
		}
	}
}

/* Wait until the process sleeps on the named wait channel message. */
static bool
sw_wait_wmesg(pid_t pid, const char *wmesg, int ms)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	for (; ms > 0; ms -= 10) {
		len = sizeof(kp);
		if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) == 0 &&
		    strcmp(kp.ki_wmesg, wmesg) == 0)
			return (true);
		dqt_msleep(10);
	}
	return (false);
}

static void
a_rdwr(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDWR);
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
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

	RR(res->r[0], fd = open("orig", O_RDWR));
	b = 'h';
	(void)write(g->held[1], &b, 1);
	(void)read(g->gone[0], &b, 1);
	if (fd == -1)
		return;
	RR(res->r[1], pwrite(fd, "AFTER", 5, 0));
	RR(res->r[2], pread(fd, res->data, sizeof(res->data) - 1, 0));
	RR(res->r[3], fstat(fd, &st));
	res->ino = st.st_ino;
	RR(res->r[4], fd2 = dup(fd));
	RR(res->r[5], open("orig", O_RDONLY));
	RR(res->r[6], open("subst", O_RDONLY));
	RR(res->r[7], stat("subst", &st));
	RR(res->r[8], close(fd));
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
	char *buf, b;
	char text[64];
	int status;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	ATF_REQUIRE_EQ(0, stat("subst", &st));
	sw_init(&x, "orig", a_rdwr);
	ATF_REQUIRE_EQ(0, pipe(g.held));
	ATF_REQUIRE_EQ(0, pipe(g.gone));
	buf = malloc(SW_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(fcntl(x.c.q, F_SETFL, O_NONBLOCK) != -1);
	dqt_attach_spawn(&x.c, &ch, p_gone_holder, &g);
	sw_serve_answered(&x, buf, 1);
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
	free(buf);
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
	RR(res->r[0], fd = open("orig", O_RDONLY | O_EXLOCK));
	if (fd != -1) {
		RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
		RR(res->r[8], close(fd));
	} else
		RR(res->r[4], fcntl(next, F_GETFD));
	RR(res->r[3], stat("orig", &st));
}

ATF_TC_WITHOUT_HEAD(swap_supervisor_gone_before_install);
ATF_TC_BODY(swap_supervisor_gone_before_install, tc)
{
	struct sw x;
	struct sw_res res;
	struct dqt_achild ch;
	char *buf;
	int lockfd, status;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	lockfd = open("subst", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(lockfd != -1);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_EX));
	sw_init(&x, "orig", a_regular);
	buf = malloc(SW_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(fcntl(x.c.q, F_SETFL, O_NONBLOCK) != -1);
	dqt_attach_spawn(&x.c, &ch, p_exlock_late, NULL);
	sw_serve_answered(&x, buf, 1);
	ATF_REQUIRE_MSG(sw_wait_wmesg(ch.pid, "lockf", 30000),
	    "the program is not waiting for the lock");

	dqt_close_queue(&x.c);
	ATF_REQUIRE_EQ(0, flock(lockfd, LOCK_UN));
	status = dqt_attach_wait(&ch, &res, sizeof(res));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "the program failed, status %#x", status);
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
	free(buf);
	dqt_fini(&x.c);
}

/*
 * Case: the same, raced.  The supervisor replies and closes the queue at
 * once, many times.  Each open either returns the working descriptor (it
 * was installed before the queue died) or fails EIO with nothing
 * installed; never anything else.
 */
#define	SW_RACE_ROUNDS	200

static void
a_quick(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd, 0));
	(void)close(fd);
}

static void
p_race_open(void *arg __unused, void *result)
{
	struct sw_res *res = result;
	int fd, next;

	next = dup(0);
	(void)close(next);
	RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd != -1)
		RR(res->r[2], read(fd, res->data, sizeof(res->data) - 1));
	else
		RR(res->r[4], fcntl(next, F_GETFD));
}

ATF_TC(swap_supervisor_gone_race);
ATF_TC_HEAD(swap_supervisor_gone_race, tc)
{
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(swap_supervisor_gone_race, tc)
{
	struct sw x;
	struct sw_res res;
	struct dqt_achild ch;
	char *buf;
	int i, installed, refused, status;

	sw_write_file("orig", "ORIGINAL", 0644);
	sw_write_file("subst", "SUBSTITUTE", 0644);
	buf = malloc(SW_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	installed = refused = 0;
	for (i = 0; i < SW_RACE_ROUNDS; i++) {
		sw_init(&x, "orig", a_quick);
		ATF_REQUIRE(fcntl(x.c.q, F_SETFL, O_NONBLOCK) != -1);
		dqt_attach_spawn(&x.c, &ch, p_race_open, NULL);
		sw_serve_answered(&x, buf, 1);
		dqt_close_queue(&x.c);
		status = dqt_attach_wait(&ch, &res, sizeof(res));
		ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "round %d: the program failed, status %#x", i, status);
		if (res.r[0].rv >= 0) {
			installed++;
			ATF_REQUIRE_EQ_MSG(10, res.r[2].rv,
			    "round %d: read %ld errno %d", i, res.r[2].rv,
			    res.r[2].err);
			ATF_REQUIRE_EQ(0, memcmp(res.data, "SUBSTITUTE", 10));
		} else {
			refused++;
			ATF_REQUIRE_EQ_MSG(EIO, res.r[0].err,
			    "round %d: open errno %d", i, res.r[0].err);
			ATF_REQUIRE_EQ(-1, res.r[4].rv);
			ATF_REQUIRE_EQ(EBADF, res.r[4].err);
		}
		dqt_fini(&x.c);
	}
	printf("installed before the death %d, refused %d\n", installed,
	    refused);
	free(buf);
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
	struct msghdr msg;
	struct iovec iov;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} cm;
	char b;
	int fd, sv[2];

	RR(res->r[0], fd = open("orig", O_RDONLY));
	if (fd == -1)
		return;
	RR(res->r[1], socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	if (res->r[1].rv == -1)
		return;
	memset(&msg, 0, sizeof(msg));
	memset(&cm, 0, sizeof(cm));
	b = 'x';
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cm.buf;
	msg.msg_controllen = sizeof(cm.buf);
	cm.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	cm.hdr.cmsg_level = SOL_SOCKET;
	cm.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&cm.hdr), &fd, sizeof(fd));
	RR(res->r[2], sendmsg(sv[0], &msg, 0));
}

static void
a_noxfer(struct sw *x, const struct dq_event *ev,
    const struct dq_resolve_body *rb __unused)
{
	int fd;

	fd = sw_open("subst", O_RDONLY);
	ATF_CHECK_EQ(0, dq_reply_resolve_swap(x->c.q, ev->de_id, fd,
	    noxfer_flags));
	(void)close(fd);
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
	ATF_CHECK_EQ_MSG(1, res.r[2].rv, "sendmsg: %s",
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
	ATF_TP_ADD_TC(tp, swap_supervisor_gone_race);
	ATF_TP_ADD_TC(tp, swap_created);
	ATF_TP_ADD_TC(tp, swap_opath_device);
	ATF_TP_ADD_TC(tp, swap_directory);
	ATF_TP_ADD_TC(tp, swap_emfile);
	ATF_TP_ADD_TC(tp, swap_noxfer);
	return (atf_no_error());
}
