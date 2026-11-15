/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libdq: the record walkers and typed accessors (no device needed), and
 * dq_serve_file() answering each stage 1b-i operation from a backing file
 * (needs /dev/dq; fails without it).  The controller is a thread of the
 * test process that hands every record to dq_serve_file(); requesters are
 * forked children that inherit the minted descriptor (the queue is
 * O_CLOFORK).  The oracle is the backing file itself, or a second real file
 * holding the same bytes, operated on the same way.
 */

#include <sys/param.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#include "dq_test.h"

#define	DATA_LEN	8192

static unsigned char data[DATA_LEN];

/*
 * Walkers and accessors
 */

/* Append a record of op with body[bodylen] (padded to 8) at *off. */
static struct dq_event *
put_record(char *buf, size_t *off, uint32_t op, uint32_t flags,
    const void *body, size_t bodylen)
{
	struct dq_event *ev;
	size_t size;

	size = roundup2(sizeof(*ev) + bodylen, 8);
	ev = (struct dq_event *)(void *)(buf + *off);
	memset(ev, 0, size);
	ev->de_version = DQ_API_VERSION;
	ev->de_size = (uint32_t)size;
	ev->de_op = op;
	ev->de_flags = flags;
	ev->de_id = *off + 1;
	if (bodylen != 0)
		memcpy(ev + 1, body, bodylen);
	*off += size;
	return (ev);
}

ATF_TC_WITHOUT_HEAD(walk_padded_records);
ATF_TC_BODY(walk_padded_records, tc)
{
	char buf[1024], wbody[sizeof(struct dq_write_body) + 37];
	char rbody[sizeof(struct dq_reply_record) + 24];
	struct dq_write_body *wb;
	struct dq_reply_record *rr;
	const struct dq_write_body *wbp;
	const struct dq_reply_record *rrp;
	const struct dq_read_body *rbp;
	const struct dq_event *ev;
	struct dq_read_body rb;
	const void *p;
	size_t off, len;
	int n;

	off = 0;
	memset(wbody, 0, sizeof(wbody));
	wb = (struct dq_write_body *)(void *)wbody;
	wb->dw_offset = 100;
	wb->dw_len = 37;
	memset(wb + 1, 'w', 37);
	(void)put_record(buf, &off, DQ_OP_WRITE, 0, wbody, sizeof(wbody));
	ATF_CHECK_EQ(sizeof(struct dq_event) + 16 + 40, off);
	memset(&rb, 0, sizeof(rb));
	rb.dr_offset = 7;
	rb.dr_len = 9;
	(void)put_record(buf, &off, DQ_OP_READ, 0, &rb, sizeof(rb));
	memset(rbody, 0, sizeof(rbody));
	rr = (struct dq_reply_record *)(void *)rbody;
	rr->drr_id = 1;
	rr->drr_len = 20;
	memset(rr + 1, 'r', 20);
	(void)put_record(buf, &off, DQ_OP_REPLY, DQ_EVENT_F_OBSERVED, rbody,
	    sizeof(*rr) + 20);
	(void)put_record(buf, &off, DQ_OP_REPLY,
	    DQ_EVENT_F_OBSERVED | DQ_EVENT_F_NODATA, rbody, sizeof(*rr));

	n = 0;
	for (ev = dq_event_first(buf, off); ev != NULL;
	    ev = dq_event_next(buf, off, ev))
		n++;
	ATF_CHECK_EQ(4, n);
	/* A buffer cut inside the last record: three whole ones. */
	n = 0;
	for (ev = dq_event_first(buf, off - 8); ev != NULL;
	    ev = dq_event_next(buf, off - 8, ev))
		n++;
	ATF_CHECK_EQ(3, n);

	ev = dq_event_first(buf, off);
	ATF_REQUIRE_EQ(0, dq_event_write(ev, &wbp, &p, &len));
	ATF_CHECK_EQ(100, wbp->dw_offset);
	ATF_CHECK_EQ(37, len);
	ATF_CHECK(memcmp(p, wb + 1, 37) == 0);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_read(ev, &rbp));
	ATF_CHECK_EQ(EINVAL, errno);
	ev = dq_event_next(buf, off, ev);
	ATF_REQUIRE_EQ(0, dq_event_read(ev, &rbp));
	ATF_CHECK_EQ(7, rbp->dr_offset);
	ev = dq_event_next(buf, off, ev);
	ATF_REQUIRE_EQ(0, dq_event_reply_record(ev, &rrp, &p, &len));
	ATF_CHECK_EQ(20, len);
	ATF_REQUIRE(p != NULL);
	ATF_CHECK_EQ('r', ((const char *)p)[19]);
	ev = dq_event_next(buf, off, ev);
	ATF_REQUIRE_EQ(0, dq_event_reply_record(ev, &rrp, &p, &len));
	ATF_CHECK_EQ(20, len);	/* lengths kept */
	ATF_CHECK(p == NULL);	/* bytes removed */
}

ATF_TC_WITHOUT_HEAD(accessor_bounds);
ATF_TC_BODY(accessor_bounds, tc)
{
	char buf[256], body[sizeof(struct dq_ioctl_body) + 8];
	struct dq_ioctl_body *ib;
	const struct dq_ioctl_body *ibp;
	const struct dq_lock_body *lb;
	struct dq_event *ev;
	const void *in;
	size_t off, len;

	/* An IOCTL whose dio_len claims more than the record holds. */
	off = 0;
	memset(body, 0, sizeof(body));
	ib = (struct dq_ioctl_body *)(void *)body;
	ib->dio_cmd = 1;
	ib->dio_len = 64;
	ev = put_record(buf, &off, DQ_OP_IOCTL, 0, body, sizeof(body));
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_ioctl(ev, &ibp, &in, &len));
	ATF_CHECK_EQ(EINVAL, errno);
	ib = (struct dq_ioctl_body *)(void *)(ev + 1);
	ib->dio_len = 8;
	ATF_CHECK_EQ(0, dq_event_ioctl(ev, &ibp, &in, &len));
	ATF_CHECK_EQ(8, len);
	ib->dio_len = 0;
	ATF_CHECK_EQ(0, dq_event_ioctl(ev, &ibp, &in, &len));
	ATF_CHECK(in == NULL);
	/* A LOCK record too short for its body. */
	off = 0;
	ev = put_record(buf, &off, DQ_OP_LOCK, 0, body, 16);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_lock(ev, &lb));
	ATF_CHECK_EQ(EINVAL, errno);
	/* A record of no fixed size is refused by the walker. */
	ev->de_size = sizeof(*ev) + 4;
	ATF_CHECK(dq_event_first(buf, sizeof(buf)) == NULL);
}

ATF_TC_WITHOUT_HEAD(async_accessors);
ATF_TC_BODY(async_accessors, tc)
{
	char buf[256], wbody[sizeof(struct dq_write_body) + 4096];
	const struct dq_write_body *wbp;
	const struct dq_read_body *rbp;
	struct dq_write_body *wb;
	struct dq_read_body rb;
	struct dq_event *ev;
	char *big;
	const void *p;
	size_t off, len;

	/* READ_ASYNC has the READ body. */
	off = 0;
	memset(&rb, 0, sizeof(rb));
	rb.dr_offset = 8192;
	rb.dr_len = 4096;
	ev = put_record(buf, &off, DQ_OP_READ_ASYNC, 0, &rb, sizeof(rb));
	ATF_REQUIRE_EQ(0, dq_event_read(ev, &rbp));
	ATF_CHECK_EQ(8192, rbp->dr_offset);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_write(ev, &wbp, &p, &len));
	ATF_CHECK_EQ(EINVAL, errno);
	/* WRITE_ASYNC has the WRITE body and a page of data. */
	big = malloc(sizeof(struct dq_event) + sizeof(wbody));
	ATF_REQUIRE(big != NULL);
	memset(wbody, 0, sizeof(wbody));
	wb = (struct dq_write_body *)(void *)wbody;
	wb->dw_offset = 4096;
	wb->dw_len = 4096;
	memset(wb + 1, 'p', 4096);
	off = 0;
	ev = put_record(big, &off, DQ_OP_WRITE_ASYNC, 0, wbody, sizeof(wbody));
	ATF_REQUIRE_EQ(0, dq_event_write(ev, &wbp, &p, &len));
	ATF_CHECK_EQ(4096, wbp->dw_offset);
	ATF_CHECK_EQ(0, wbp->dw_flags);
	ATF_CHECK_EQ(4096, len);
	ATF_CHECK_EQ('p', ((const char *)p)[4095]);
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_WRITE_ASYNC, ENOSPC));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_WRITE_ASYNC, EPIPE));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_READ_ASYNC, EPIPE));
	free(big);
}

ATF_TC_WITHOUT_HEAD(resolve_accessor);
ATF_TC_BODY(resolve_accessor, tc)
{
	char buf[512], body[sizeof(struct dq_resolve_body) + 64];
	const struct dq_resolve_body *rbp;
	struct dq_resolve_body *rb;
	struct dq_event *ev;
	const char *p1, *p2, *sp, *sp2, *rp;
	uint64_t root;
	size_t off;
	char *s;

	/* 1c-iii-c appended the served root (drs_root, a fifth string). */
	ATF_REQUIRE_EQ(112, sizeof(struct dq_resolve_body));
	memset(body, 0, sizeof(body));
	rb = (struct dq_resolve_body *)(void *)body;
	rb->drs_op = DQ_ROP_RENAME;
	rb->drs_flags = DQ_RCLASS_USER;
	rb->drs_pathlen = 3;
	rb->drs_path2len = 4;
	rb->drs_startpathlen = 0;
	rb->drs_startpath2len = 2;
	rb->drs_rflags = DQ_RF_STARTPATH2_VALID;
	rb->drs_root = 7;
	rb->drs_rootpathlen = 2;
	s = (char *)(rb + 1);
	memcpy(s, "a/b\0c/de\0\0/x\0/r\0", 16);
	off = 0;
	ev = put_record(buf, &off, DQ_OP_RESOLVE, 0, body,
	    sizeof(*rb) + 16);
	ATF_REQUIRE_EQ(0, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_STREQ("/x", sp2);
	ATF_REQUIRE_EQ(0, dq_event_resolve_root(ev, NULL, &root, &rp));
	ATF_CHECK_EQ(7, root);
	ATF_CHECK_STREQ("/r", rp);
	ATF_CHECK_EQ(0, rbp->drs_pad2);
	ATF_CHECK_EQ(0, rbp->drs_accept);
	ATF_CHECK_EQ(0, rbp->drs_cmode);
	ATF_CHECK_EQ(DQ_ROP_RENAME, rbp->drs_op);
	ATF_CHECK_STREQ("a/b", p1);
	ATF_CHECK_STREQ("c/de", p2);
	ATF_CHECK_STREQ("", sp);
	/* A length that runs past the record, or a missing NUL. */
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_path2len = 200;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_EQ(EINVAL, errno);
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_path2len = 3;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_EQ(EINVAL, errno);
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_path2len = 4;
	/* The fourth and fifth strings must end where their lengths say. */
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_startpath2len = 5;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_EQ(EINVAL, errno);
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_startpath2len = 2;
	((struct dq_resolve_body *)(void *)(ev + 1))->drs_rootpathlen = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_EQ(EINVAL, errno);
	/* Another operation. */
	ev->de_op = DQ_OP_READ;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_event_resolve(ev, &rbp, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_RESOLVE, EACCES));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_RESOLVE, EPIPE));
	/* socket(2) and socketpair(2) have their own list (1c-ii). */
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_RESOLVE, ENOBUFS));
	ATF_CHECK(dq_resolve_errno_allowed(DQ_ROP_SOCKET, EACCES));
	ATF_CHECK(dq_resolve_errno_allowed(DQ_ROP_SOCKETPAIR, EMFILE));
	ATF_CHECK(!dq_resolve_errno_allowed(DQ_ROP_SOCKET, ENOENT));
	ATF_CHECK(!dq_resolve_errno_allowed(DQ_ROP_OPEN, ENOBUFS));
	ATF_CHECK(dq_resolve_errno_allowed(DQ_ROP_OPEN, ENOENT));

	/* A SOCKET body: five empty strings, the request in the fixed part. */
	memset(body, 0, sizeof(body));
	rb->drs_op = DQ_ROP_SOCKET;
	rb->drs_flags = DQ_RCLASS_USER;
	rb->drs_rflags = DQ_RF_USER;
	rb->drs_start_kind = DQ_START_NONE;
	rb->drs_domain = 2;
	rb->drs_type = 1;
	rb->drs_protocol = 6;
	off = 0;
	ev = put_record(buf, &off, DQ_OP_RESOLVE, 0, body, sizeof(*rb) + 5);
	ATF_REQUIRE_EQ(0, dq_event_resolve(ev, &rbp, &p1, &p2, &sp, &sp2));
	ATF_CHECK_STREQ("", p1);
	ATF_CHECK_EQ(DQ_ROP_SOCKET, rbp->drs_op);
	ATF_CHECK_EQ(DQ_START_NONE, rbp->drs_start_kind);
	ATF_CHECK_EQ(2, rbp->drs_domain);
	ATF_CHECK_EQ(1, rbp->drs_type);
	ATF_CHECK_EQ(6, rbp->drs_protocol);
}

ATF_TC_WITHOUT_HEAD(errno_allow_lists);
ATF_TC_BODY(errno_allow_lists, tc)
{

	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_WRITE, ENOSPC));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_WRITE, EPIPE));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_SETATTR, EROFS));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_SETATTR, EACCES));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_SETATTR, ESTALE));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_SETATTR, EAGAIN));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_WRITE, ESTALE));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_FALLOCATE, EDQUOT));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_FSYNC, EIO));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_FSYNC, ENOSPC));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_FSYNC, EPERM));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_FALLOCATE, EOPNOTSUPP));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_FSPACECTL, ENODEV));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_FALLOCATE, ENODEV));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_LOCK, EDEADLK));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_LOCK, EPERM));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_IOCTL, ENOTTY));
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_IOCTL, ENOSPC));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_READ, EPIPE));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_WRITE, 0));
}

/*
 * dq_serve_file() against a backing file
 */

struct ctl {
	int		 q;
	int		 backing;
	pthread_t	 thr;
	volatile bool	 stop;
	struct dq_serve_state *st;
	struct dq_ident_file ident;
	struct dq_serve_opts opts;
	uint64_t	 object;
	int		 fd;
	unsigned	 failures;
	unsigned	 ops[DQ_OP_REPLY + 1];
	pthread_mutex_t	 mtx;
};

static void *
serve_loop(void *arg)
{
	struct ctl *c = arg;
	const struct dq_event *ev;
	struct pollfd pfd;
	const void *body;
	size_t bodylen, size;
	ssize_t got;
	char *buf;

	size = 256 * 1024;
	buf = malloc(size);
	while (!c->stop) {
		pfd.fd = c->q;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		if (dq_read_events(c->q, buf, size, &got) != 0)
			continue;
		for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
		    ev = dq_event_next(buf, (size_t)got, ev)) {
			body = dq_event_body(ev, &bodylen);
			pthread_mutex_lock(&c->mtx);
			if (ev->de_op <= DQ_OP_REPLY)
				c->ops[ev->de_op]++;
			pthread_mutex_unlock(&c->mtx);
			if (dq_serve_file(c->q, ev, body, bodylen, c->backing,
			    &c->opts) != 0) {
				pthread_mutex_lock(&c->mtx);
				c->failures++;
				pthread_mutex_unlock(&c->mtx);
			}
		}
	}
	free(buf);
	return (NULL);
}

static char backing_path[PATH_MAX];

static void
ctl_start(struct ctl *c, unsigned seed, uint32_t events)
{
	struct dq_policy pol;
	struct statfs sfs;
	struct stat sb;
	size_t i;
	int fd, flags, reason;

	memset(c, 0, sizeof(*c));
	for (i = 0; i < sizeof(data); i++)
		data[i] = (unsigned char)(i * 7 + seed);
	fd = open("backing", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ((ssize_t)sizeof(data), write(fd, data, sizeof(data)));
	ATF_REQUIRE(realpath("backing", backing_path) != NULL);
	c->backing = fd;
	c->q = dqt_open_queue();
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_REQUIRE_EQ(0, fstatfs(fd, &sfs));
	ATF_REQUIRE_EQ(0, dq_ident_from_stat(&c->ident, backing_path, &sb,
	    &sfs, fd));
	dq_policy_default(&pol);
	pol.dp_write = DQ_EVENT;
	pol.dp_ioctl = DQ_EVENT;
	pol.dp_mmap_shared_write = DQ_ALLOW;
	pol.dp_events = events;
	ATF_REQUIRE_MSG(dq_mint_file_flags(c->q, &c->ident, &pol,
	    DQ_MINT_F_WRITE, &c->object, &c->fd, &reason) == 0,
	    "mint: %s (reason %d)", strerror(errno), reason);
	c->st = dq_serve_state_create();
	ATF_REQUIRE(c->st != NULL);
	c->opts.so_state = c->st;
	c->opts.so_ident = &c->ident;
	c->opts.so_flags = DQ_SERVE_F_SYNC_IDENT;
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&c->mtx, NULL));
	flags = fcntl(c->q, F_GETFL);
	ATF_REQUIRE_EQ(0, fcntl(c->q, F_SETFL, flags | O_NONBLOCK));
	ATF_REQUIRE_EQ(0, pthread_create(&c->thr, NULL, serve_loop, c));
}

static void
ctl_stop(struct ctl *c)
{

	c->stop = true;
	(void)pthread_join(c->thr, NULL);
	ATF_CHECK_EQ_MSG(0, c->failures, "dq_serve_file failed %u times",
	    c->failures);
	(void)close(c->fd);
	dq_serve_state_destroy(c->st);
	(void)close(c->q);
	(void)close(c->backing);
	(void)pthread_mutex_destroy(&c->mtx);
}

/* Run fn(arg, result) in a forked requester; result comes back by pipe. */
static void
requester(void (*fn)(void *, void *), void *arg, void *result, size_t len)
{
	char buf[4096];
	ssize_t n;
	pid_t pid;
	int pfd[2], status;

	ATF_REQUIRE(len <= sizeof(buf));
	ATF_REQUIRE_EQ(0, pipe(pfd));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)close(pfd[0]);
		memset(buf, 0, sizeof(buf));
		fn(arg, buf);
		(void)write(pfd[1], buf, len);
		_exit(0);
	}
	(void)close(pfd[1]);
	n = read(pfd[0], result, len);
	ATF_CHECK_EQ((ssize_t)len, n);
	(void)close(pfd[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

struct rr {
	long		 rv;
	int		 err;
};

struct io_res {
	struct rr	 r[12];
	struct stat	 st;
	unsigned char	 buf[64];
	struct spacectl_range rmsr;
	struct flock	 fl;
};

#define	DO(i, expr) do {						\
	r->r[i].rv = (long)(expr);					\
	r->r[i].err = r->r[i].rv == -1 ? errno : 0;			\
} while (0)

static void
child_io(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct io_res *r = result;
	struct spacectl_range rq;
	unsigned char w[16];
	int e;

	memset(w, 0xee, sizeof(w));
	DO(0, pread(fd, r->buf, sizeof(r->buf), 100));
	DO(1, pwrite(fd, w, sizeof(w), 200));
	(void)fcntl(fd, F_SETFL, O_APPEND);
	DO(2, write(fd, w, sizeof(w)));
	DO(3, lseek(fd, 0, SEEK_CUR));
	(void)fcntl(fd, F_SETFL, 0);
	DO(4, fchmod(fd, 0600));
	DO(5, fsync(fd));
	DO(6, fdatasync(fd));
	e = posix_fallocate(fd, 0, DATA_LEN * 2);
	r->r[7].rv = e == 0 ? 0 : -1;
	r->r[7].err = e;
	rq.r_offset = 1024;	/* clear of the bytes written at 200 */
	rq.r_len = 512;
	DO(8, fspacectl(fd, SPACECTL_DEALLOC, &rq, 0, &r->rmsr));
	DO(9, ioctl(fd, FIODTYPE, &e));
	DO(10, ftruncate(fd, DATA_LEN + 16));
	DO(11, fstat(fd, &r->st));
}

ATF_TC(serve_each_op);
ATF_TC_HEAD(serve_each_op, tc)
{
	atf_tc_set_md_var(tc, "descr", "dq_serve_file answers READ, WRITE "
	    "(positioned and appending), SETATTR, FSYNC (both modes), "
	    "FALLOCATE, FSPACECTL, IOCTL (ENOTTY) and GETATTR from a backing "
	    "file, and the bytes and attributes are the backing file's");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(serve_each_op, tc)
{
	struct ctl c;
	struct io_res r;
	struct stat bs;
	unsigned char got[16], w[16];
	int fd;

	ctl_start(&c, 1, DQ_EVENTS_GETATTR);
	fd = c.fd;
	memset(&r, 0, sizeof(r));
	requester(child_io, &fd, &r, sizeof(r));
	ATF_CHECK_EQ(64, r.r[0].rv);
	ATF_CHECK(memcmp(r.buf, data + 100, 64) == 0);
	ATF_CHECK_EQ(16, r.r[1].rv);
	ATF_CHECK_EQ(16, r.r[2].rv);
	/* The append went to the backing end and moved the offset there. */
	ATF_CHECK_EQ(DATA_LEN + 16, r.r[3].rv);
	ATF_CHECK_EQ(0, r.r[4].rv);
	ATF_CHECK_EQ(0, r.r[5].rv);
	ATF_CHECK_EQ(0, r.r[6].rv);
	if (r.r[7].rv != 0)
		ATF_CHECK_EQ(posix_fallocate(c.backing, 0, DATA_LEN * 2),
		    r.r[7].err);
	ATF_CHECK_EQ_MSG(0, r.r[8].rv, "fspacectl: %s", strerror(r.r[8].err));
	ATF_CHECK_EQ(1536, r.rmsr.r_offset);
	ATF_CHECK_EQ(0, r.rmsr.r_len);
	ATF_CHECK_EQ(ENOTTY, r.r[9].err);
	ATF_CHECK_EQ(0, r.r[10].rv);
	ATF_CHECK_EQ(0, r.r[11].rv);

	ATF_REQUIRE_EQ(0, fstat(c.backing, &bs));
	ATF_CHECK_EQ(bs.st_size, r.st.st_size);
	ATF_CHECK_EQ(bs.st_mode, r.st.st_mode);
	ATF_CHECK_EQ(bs.st_mtim.tv_sec, r.st.st_mtim.tv_sec);
	ATF_CHECK_EQ(bs.st_mtim.tv_nsec, r.st.st_mtim.tv_nsec);
	ATF_CHECK_EQ(bs.st_blocks, r.st.st_blocks);
	memset(w, 0xee, sizeof(w));
	ATF_REQUIRE_EQ(16, pread(c.backing, got, sizeof(got), 200));
	ATF_CHECK(memcmp(got, w, 16) == 0);
	ATF_REQUIRE_EQ(16, pread(c.backing, got, sizeof(got), DATA_LEN));
	ATF_CHECK(memcmp(got, w, 16) == 0);
	/* The deallocated range reads as zeros. */
	memset(w, 0, sizeof(w));
	ATF_REQUIRE_EQ(16, pread(c.backing, got, sizeof(got), 1024 + 496));
	ATF_CHECK(memcmp(got, w, 16) == 0);
	ATF_CHECK(c.ops[DQ_OP_GETATTR] >= 1);
	ATF_CHECK_EQ(2, c.ops[DQ_OP_FSYNC]);
	ctl_stop(&c);
}

struct lock_arg {
	int		 fd;
	int		 ready[2], go[2];
};

static void
child_hold_lock(void *arg, void *result)
{
	struct lock_arg *a = arg;
	struct rr *r = result;
	struct flock fl;
	char b;

	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_len = 10;
	r->rv = fcntl(a->fd, F_SETLK, &fl);
	r->err = r->rv == -1 ? errno : 0;
	b = 'r';
	(void)write(a->ready[1], &b, 1);
	(void)read(a->go[0], &b, 1);
}

static void
child_try_lock(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct io_res *r = result;

	memset(&r->fl, 0, sizeof(r->fl));
	r->fl.l_type = F_WRLCK;
	r->fl.l_whence = SEEK_SET;
	r->fl.l_start = 5;
	r->fl.l_len = 1;
	DO(0, fcntl(fd, F_SETLK, &r->fl));
	DO(1, fcntl(fd, F_GETLK, &r->fl));
	DO(2, flock(fd, LOCK_EX | LOCK_NB));
}

ATF_TC(serve_locks);
ATF_TC_HEAD(serve_locks, tc)
{
	atf_tc_set_md_var(tc, "descr", "dq_serve_file proxies each lock owner "
	    "onto its own open of the backing file: a second process conflicts "
	    "(EAGAIN, GETLK names the range), and the holder's exit "
	    "(UNLOCK_ALL) frees it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(serve_locks, tc)
{
	struct ctl c;
	struct lock_arg a;
	struct io_res r;
	char buf[sizeof(struct rr)];
	pid_t pid;
	int status, fd, waited;
	char b;

	ctl_start(&c, 2, 0);
	a.fd = c.fd;
	ATF_REQUIRE_EQ(0, pipe(a.ready));
	ATF_REQUIRE_EQ(0, pipe(a.go));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		child_hold_lock(&a, buf);
		_exit(((struct rr *)(void *)buf)->rv == 0 ? 0 : 1);
	}
	ATF_REQUIRE_EQ(1, read(a.ready[0], &b, 1));
	fd = c.fd;
	memset(&r, 0, sizeof(r));
	requester(child_try_lock, &fd, &r, sizeof(r));
	ATF_CHECK_EQ(EAGAIN, r.r[0].err);
	ATF_CHECK_EQ(0, r.r[1].rv);
	ATF_CHECK_EQ(F_WRLCK, r.fl.l_type);
	ATF_CHECK_EQ(0, r.fl.l_start);
	ATF_CHECK_EQ(10, r.fl.l_len);
	ATF_CHECK_EQ(EWOULDBLOCK, r.r[2].err);
	ATF_CHECK(dq_serve_state_owners(c.st) >= 2);
	b = 'g';
	(void)write(a.go[1], &b, 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	for (waited = 0; waited < 5000; waited += 10) {
		pthread_mutex_lock(&c.mtx);
		b = c.ops[DQ_OP_UNLOCK_ALL] >= 2;
		pthread_mutex_unlock(&c.mtx);
		if (b)
			break;
		usleep(10000);
	}
	memset(&r, 0, sizeof(r));
	requester(child_try_lock, &fd, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.r[0].rv, "after release: %s",
	    strerror(r.r[0].err));
	ctl_stop(&c);
}

static void
child_map_write(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct io_res *r = result;
	unsigned char *p;

	p = mmap(NULL, DATA_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		r->r[0].rv = -1;
		r->r[0].err = errno;
		return;
	}
	/* A fault (READ) and a store, then the write-back (WRITE_ASYNC). */
	memcpy(r->buf, p + 4096, 16);
	p[4096 + 5] = 0x77;
	DO(1, msync(p, DATA_LEN, MS_SYNC));
	DO(2, munmap(p, DATA_LEN));
}

ATF_TC(serve_mmap_writeback);
ATF_TC_HEAD(serve_mmap_writeback, tc)
{
	atf_tc_set_md_var(tc, "descr", "dq_serve_file answers a fault's READ "
	    "and the WRITE_ASYNC of msync: the mapping holds the backing bytes "
	    "and the store reaches the backing file at its offset");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(serve_mmap_writeback, tc)
{
	struct ctl c;
	struct io_res r;
	unsigned char got;
	int fd;

	ctl_start(&c, 3, 0);
	fd = c.fd;
	memset(&r, 0, sizeof(r));
	requester(child_map_write, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ_MSG(0, r.r[0].rv, "mmap: %s", strerror(r.r[0].err));
	ATF_CHECK(memcmp(r.buf, data + 4096, 16) == 0);
	ATF_CHECK_EQ_MSG(0, r.r[1].rv, "msync: %s", strerror(r.r[1].err));
	ATF_CHECK_EQ(0, r.r[2].rv);
	ATF_REQUIRE_EQ(1, pread(c.backing, &got, 1, 4096 + 5));
	ATF_CHECK_EQ(0x77, got);
	ATF_CHECK(c.ops[DQ_OP_WRITE_ASYNC] >= 1);
	ctl_stop(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, walk_padded_records);
	ATF_TP_ADD_TC(tp, accessor_bounds);
	ATF_TP_ADD_TC(tp, errno_allow_lists);
	ATF_TP_ADD_TC(tp, serve_each_op);
	ATF_TP_ADD_TC(tp, serve_locks);
	ATF_TP_ADD_TC(tp, async_accessors);
	ATF_TP_ADD_TC(tp, serve_mmap_writeback);
	ATF_TP_ADD_TC(tp, resolve_accessor);
	return (atf_no_error());
}
