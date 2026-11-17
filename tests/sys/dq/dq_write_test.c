/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Writes (D95): write(2) and its relatives on a writable served file are
 * WRITE events, one per kern.dq.max_io chunk, answered here by
 * dq_serve_file() from a backing file.  The oracle is a second real file
 * holding the same bytes: every call runs on both in the requester, and
 * the return values, errnos, offsets and the resulting bytes are compared.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <aio.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	8192
#define	MAX_OPS		8

static unsigned char data[DATA_LEN];
static char backing_path[DQT_PATH_MAX];
static char oracle_path[DQT_PATH_MAX];

static void
setup_flags(struct dqt_fixture *f, unsigned seed, uint32_t mflags)
{

	dqt_fill(data, sizeof(data), seed);
	dqt_fixture_init(f, data, sizeof(data), backing_path, oracle_path, NULL,
	    mflags);
}

static void
setup(struct dqt_fixture *f, unsigned seed)
{

	setup_flags(f, seed, DQ_MINT_F_WRITE);
}

/* The two files hold the same bytes. */
static void
check_same_contents(struct dqt_fixture *f)
{
	struct stat bs, os;
	unsigned char *b, *o;

	ATF_REQUIRE_EQ(0, fstat(f->backing, &bs));
	ATF_REQUIRE_EQ(0, fstat(f->oracle, &os));
	ATF_REQUIRE_EQ_MSG(os.st_size, bs.st_size, "size: served %jd oracle %jd",
	    (intmax_t)bs.st_size, (intmax_t)os.st_size);
	b = malloc((size_t)bs.st_size + 1);
	o = malloc((size_t)os.st_size + 1);
	ATF_REQUIRE(b != NULL && o != NULL);
	ATF_REQUIRE_EQ(bs.st_size, pread(f->backing, b, (size_t)bs.st_size, 0));
	ATF_REQUIRE_EQ(os.st_size, pread(f->oracle, o, (size_t)os.st_size, 0));
	ATF_CHECK(memcmp(b, o, (size_t)bs.st_size) == 0);
	free(b);
	free(o);
}

/* A pair of results: the served descriptor's and the oracle's. */
struct pair {
	struct dqt_rr	 s, o;
	off_t		 soff, ooff;	/* lseek(fd, 0, SEEK_CUR) after */
};

struct ops_res {
	struct pair	 p[MAX_OPS];
	int		 n;
	struct stat	 sst, ost;
};

struct ops_arg {
	int		 sfd, ofd;
	int		 which;
};

#define	BOTH(r, call) do {						\
	int _fd;							\
	struct pair *_p;						\
									\
	if ((r)->n >= (int)nitems((r)->p))				\
		_exit(DQT_EXIT_NORESULT);	/* a child: no ATF */	\
	_p = &(r)->p[(r)->n++];						\
	_fd = a->sfd;							\
	_p->s.rv = (long)(call);					\
	_p->s.err = _p->s.rv == -1 ? errno : 0;				\
	_p->soff = lseek(_fd, 0, SEEK_CUR);				\
	_fd = a->ofd;							\
	_p->o.rv = (long)(call);					\
	_p->o.err = _p->o.rv == -1 ? errno : 0;				\
	_p->ooff = lseek(_fd, 0, SEEK_CUR);				\
} while (0)

static void
check_pairs(const struct ops_res *r)
{
	int i;

	for (i = 0; i < r->n; i++) {
		ATF_CHECK_EQ_MSG(r->p[i].o.rv, r->p[i].s.rv,
		    "op %d: served %ld oracle %ld", i, r->p[i].s.rv,
		    r->p[i].o.rv);
		ATF_CHECK_EQ_MSG(r->p[i].o.err, r->p[i].s.err,
		    "op %d: served errno %d oracle %d", i, r->p[i].s.err,
		    r->p[i].o.err);
		ATF_CHECK_EQ_MSG(r->p[i].ooff, r->p[i].soff,
		    "op %d: served offset %jd oracle %jd", i,
		    (intmax_t)r->p[i].soff, (intmax_t)r->p[i].ooff);
	}
}

static void
child_family(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	struct iovec iov[3];
	char buf[300];

	memset(buf, 'a', 100);
	memset(buf + 100, 'b', 100);
	memset(buf + 200, 'c', 100);
	iov[0].iov_base = buf;
	iov[0].iov_len = 7;
	iov[1].iov_base = buf + 100;
	iov[1].iov_len = 150;
	iov[2].iov_base = buf + 250;
	iov[2].iov_len = 50;
	BOTH(r, write(_fd, buf, 100));
	BOTH(r, pwrite(_fd, buf + 100, 100, 50));
	BOTH(r, writev(_fd, iov, 3));
	/* Past the end: the hole is zeros. */
	BOTH(r, pwrite(_fd, buf, 10, DATA_LEN + 4000));
	BOTH(r, write(_fd, buf, 0));
	BOTH(r, pwrite(_fd, buf, 10, -1));
	(void)fstat(a->sfd, &r->sst);
	(void)fstat(a->ofd, &r->ost);
}

ATF_TC(write_pwrite_writev);
ATF_TC_HEAD(write_pwrite_writev, tc)
{
	atf_tc_set_md_var(tc, "descr", "write, pwrite and writev (into a "
	    "hole, of length 0, at a negative offset) answer as on the real "
	    "file; the bytes, the offsets and st_size agree");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(write_pwrite_writev, tc)
{
	struct dqt_fixture f;
	struct ops_arg a;
	struct ops_res r;

	setup(&f, 1);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_family, &a, &r, sizeof(r));
	check_pairs(&r);
	check_same_contents(&f);
	ATF_CHECK_EQ(r.ost.st_size, r.sst.st_size);
	/* Length 0 and the negative offset posted nothing: 4 writes. */
	dqt_lock(&f.c);
	ATF_CHECK_EQ(4, f.c.events[DQ_OP_WRITE]);
	ATF_REQUIRE(f.c.nwr >= 4);
	ATF_CHECK_EQ(0, f.c.wr[0].offset);
	ATF_CHECK_EQ(100, f.c.wr[0].len);
	ATF_CHECK_EQ(50, f.c.wr[1].offset);
	ATF_CHECK_EQ(100, f.c.wr[2].offset);	/* the implicit offset */
	ATF_CHECK_EQ(207, f.c.wr[2].len);
	ATF_CHECK_EQ(0, f.c.wr[0].flags);
	dqt_unlock(&f.c);
	dqt_fixture_fini(&f);
}

static void
child_aio(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	const struct aiocb *list[1];
	struct aiocb cb;
	char buf[64];
	int fds[2], i;

	memset(buf, 'z', sizeof(buf));
	fds[0] = a->sfd;
	fds[1] = a->ofd;
	for (i = 0; i < 2; i++) {
		struct dqt_rr *rr = i == 0 ? &r->p[0].s : &r->p[0].o;

		memset(&cb, 0, sizeof(cb));
		cb.aio_fildes = fds[i];
		cb.aio_buf = buf;
		cb.aio_nbytes = sizeof(buf);
		cb.aio_offset = 300;
		if (aio_write(&cb) == -1) {
			rr->rv = -1;
			rr->err = errno;
			continue;
		}
		list[0] = &cb;
		while (aio_error(&cb) == EINPROGRESS)
			(void)aio_suspend(list, 1, NULL);
		rr->err = aio_error(&cb);
		rr->rv = aio_return(&cb);
	}
	r->n = 1;
}

ATF_TC(aio_write);
ATF_TC_HEAD(aio_write, tc)
{
	atf_tc_set_md_var(tc, "descr", "aio_write: as aio_read, EOPNOTSUPP "
	    "unless vfs.aio.enable_unsafe (aio(4) trusts only local vnodes); "
	    "with it the aio daemon posts the WRITE and the bytes land");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(aio_write, tc)
{
	struct dqt_fixture f;
	struct ops_arg a;
	struct ops_res r;
	u_int unsafe;

	setup(&f, 2);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_aio, &a, &r, sizeof(r));
	ATF_CHECK_EQ(64, r.p[0].o.rv);
	if (dqt_sysctl_get_uint("vfs.aio.enable_unsafe", &unsafe) && unsafe == 0) {
		ATF_CHECK_EQ(-1, r.p[0].s.rv);
		ATF_CHECK_EQ(EOPNOTSUPP, r.p[0].s.err);
		dqt_lock(&f.c);
		ATF_CHECK_EQ(0, f.c.events[DQ_OP_WRITE]);
		dqt_unlock(&f.c);
	} else {
		ATF_CHECK_EQ(64, r.p[0].s.rv);
		check_same_contents(&f);
		dqt_lock(&f.c);
		ATF_CHECK((f.c.last_caller.dc_flags & DQ_CALLER_F_KERNEL) != 0);
		dqt_unlock(&f.c);
	}
	dqt_fixture_fini(&f);
}

static void
child_append(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	char buf[10];

	memset(buf, 'A', sizeof(buf));
	(void)fcntl(a->sfd, F_SETFL, O_APPEND);
	(void)fcntl(a->ofd, F_SETFL, O_APPEND);
	(void)lseek(a->sfd, 0, SEEK_SET);
	(void)lseek(a->ofd, 0, SEEK_SET);
	BOTH(r, write(_fd, buf, sizeof(buf)));
	/* pwrite on an O_APPEND descriptor appends too (FOF_APPEND rule). */
	BOTH(r, pwrite(_fd, buf, 3, 0));
	BOTH(r, write(_fd, buf, 1));
	(void)fstat(a->sfd, &r->sst);
	(void)fstat(a->ofd, &r->ost);
}

ATF_TC(append);
ATF_TC_HEAD(append, tc)
{
	atf_tc_set_md_var(tc, "descr", "O_APPEND: DQ_WRITE_F_APPEND, the "
	    "controller's end of file is where the bytes go and the implicit "
	    "offset becomes offset + written, as on the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(append, tc)
{
	struct dqt_fixture f;
	struct ops_arg a;
	struct ops_res r;
	int i;

	setup(&f, 3);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_append, &a, &r, sizeof(r));
	check_pairs(&r);
	check_same_contents(&f);
	ATF_CHECK_EQ(r.ost.st_size, r.sst.st_size);
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(3, f.c.nwr);
	for (i = 0; i < 3; i++)
		ATF_CHECK((f.c.wr[i].flags & DQ_WRITE_F_APPEND) != 0);
	dqt_unlock(&f.c);
	dqt_fixture_fini(&f);
}

static void
child_appender(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct dqt_rr *r = result;
	char buf[8];
	int i;

	memset(buf, (int)('0' + getpid() % 10), sizeof(buf));
	r->rv = 0;
	for (i = 0; i < 20; i++) {
		if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
			r->rv = -1;
			r->err = errno;
			return;
		}
	}
}

ATF_TC(append_two_writers);
ATF_TC_HEAD(append_two_writers, tc)
{
	atf_tc_set_md_var(tc, "descr", "two appenders interleaved: every "
	    "record lands whole at the end, none is lost or overwritten");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(append_two_writers, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch[2];
	struct dqt_rr r[2];
	struct stat st;
	unsigned char *buf;
	off_t off;
	int i;

	setup(&f, 4);
	ATF_REQUIRE_EQ(0, fcntl(f.o->fd, F_SETFL, O_APPEND));
	for (i = 0; i < 2; i++)
		dqt_spawn(&ch[i], child_appender, &f.o->fd);
	for (i = 0; i < 2; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ_MSG(0, r[i].rv, "appender %d: %s", i,
		    strerror(r[i].err));
	}
	ATF_REQUIRE_EQ(0, fstat(f.backing, &st));
	ATF_CHECK_EQ(DATA_LEN + 2 * 20 * 8, st.st_size);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &st));
	ATF_CHECK_EQ(DATA_LEN + 2 * 20 * 8, st.st_size);
	/* Every 8-byte record past the original end is one writer's. */
	buf = malloc(2 * 20 * 8);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE_EQ(2 * 20 * 8, pread(f.backing, buf, 2 * 20 * 8, DATA_LEN));
	for (off = 0; off < 2 * 20 * 8; off += 8) {
		for (i = 1; i < 8; i++)
			ATF_CHECK_EQ(buf[off], buf[off + i]);
	}
	free(buf);
	dqt_fixture_fini(&f);
}

static void
child_sync_flags(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	char buf[4];

	memset(buf, 's', sizeof(buf));
	(void)fcntl(a->sfd, F_SETFL, O_FSYNC);
	(void)fcntl(a->ofd, F_SETFL, O_FSYNC);
	BOTH(r, pwrite(_fd, buf, sizeof(buf), 0));
	(void)fcntl(a->sfd, F_SETFL, O_DSYNC);
	(void)fcntl(a->ofd, F_SETFL, O_DSYNC);
	BOTH(r, pwrite(_fd, buf, sizeof(buf), 8));
	(void)fcntl(a->sfd, F_SETFL, O_FSYNC | O_DSYNC);
	(void)fcntl(a->ofd, F_SETFL, O_FSYNC | O_DSYNC);
	BOTH(r, pwrite(_fd, buf, sizeof(buf), 16));
	(void)fcntl(a->sfd, F_SETFL, 0);
	(void)fcntl(a->ofd, F_SETFL, 0);
	BOTH(r, pwrite(_fd, buf, sizeof(buf), 24));
}

ATF_TC(sync_flags);
ATF_TC_HEAD(sync_flags, tc)
{
	atf_tc_set_md_var(tc, "descr", "O_SYNC is DQ_WRITE_F_SYNC, O_DSYNC "
	    "DQ_WRITE_F_DSYNC, both together SYNC alone (a full sync "
	    "dominates, as vn_write computes ioflag), neither 0");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sync_flags, tc)
{
	struct dqt_fixture f;
	struct ops_arg a;
	struct ops_res r;

	setup(&f, 5);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_sync_flags, &a, &r, sizeof(r));
	check_pairs(&r);
	check_same_contents(&f);
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(4, f.c.nwr);
	ATF_CHECK_EQ(DQ_WRITE_F_SYNC, f.c.wr[0].flags);
	ATF_CHECK_EQ(DQ_WRITE_F_DSYNC, f.c.wr[1].flags);
	ATF_CHECK_EQ(DQ_WRITE_F_SYNC, f.c.wr[2].flags);
	ATF_CHECK_EQ(0, f.c.wr[3].flags);
	dqt_unlock(&f.c);
	dqt_fixture_fini(&f);
}

struct big_arg {
	int		 fd;
	size_t		 len;
	off_t		 off;
};

static volatile sig_atomic_t got_signal;

static void
on_signal(int sig __unused)
{

	got_signal = 1;
}

static void
child_big_pwrite(void *arg, void *result)
{
	struct big_arg *a = arg;
	struct dqt_rr *r = result;
	struct sigaction sa;
	char *buf;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;	/* no SA_RESTART */
	(void)sigaction(SIGUSR1, &sa, NULL);
	buf = malloc(a->len);
	memset(buf, 'B', a->len);
	r->rv = pwrite(a->fd, buf, a->len, a->off);
	r->err = r->rv == -1 ? errno : 0;
	free(buf);
}

/* Answer the held event i as a write of n bytes at off. */
static void
answer_write(struct dqt_fixture *f, int i, uint64_t n, uint64_t off)
{

	ATF_REQUIRE_MSG(dq_reply_write(f->c.q, dqt_held_id(&f->c, i), n,
	    off) == 0,
	    "dq_reply_write: %s", strerror(errno));
}

ATF_TC(short_write);
ATF_TC_HEAD(short_write, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller that takes fewer bytes "
	    "ends the call with that count (a short write) and posts no "
	    "further chunk; a reply count above dw_len is EINVAL and the event "
	    "stays in flight");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(short_write, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;
	struct stat st;
	u_int max_io;

	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.max_io", &max_io));
	setup(&f, 6);
	dqt_hold(&f.c, true);
	a.fd = f.o->fd;
	a.len = (size_t)max_io + 100;
	a.off = 0;
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(DQ_OP_WRITE, f.c.held[0].op);
	dqt_unlock(&f.c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_write(f.c.q, dqt_held_id(&f.c, 0),
	    (uint64_t)max_io + 1, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	answer_write(&f, 0, 5, 0);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(5, r.rv);
	/* A second chunk would have been posted before the fence. */
	dqt_fence(&f.c);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(1, f.c.nheld);	/* no second chunk */
	/* The kernel's size follows the controller's word, not the request. */
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &st));
	dqt_unlock(&f.c);
	ATF_CHECK_EQ(DATA_LEN, st.st_size);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

/*
 * A write of two max_io chunks; the first is accepted, and while the
 * second waits the requester is signalled (SIGUSR1, caught, no
 * SA_RESTART).  pol: the object's policy (NULL: the default).
 */
static void
mid_chunk_start(struct dqt_fixture *f, const struct dq_policy *pol,
    struct dqt_child *ch, struct big_arg *a, u_int *max_io)
{

	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.max_io", max_io));
	dqt_fill(data, sizeof(data), 7);
	dqt_fixture_init(f, data, sizeof(data), backing_path, oracle_path,
	    pol, DQ_MINT_F_WRITE);
	dqt_hold(&f->c, true);
	a->fd = f->o->fd;
	a->len = 2 * (size_t)*max_io;
	a->off = 0;
	dqt_spawn(ch, child_big_pwrite, a);
	ATF_REQUIRE(dqt_wait_held(&f->c, 1, DQT_WAIT_MS));
	answer_write(f, 0, *max_io, 0);
	ATF_REQUIRE(dqt_wait_held(&f->c, 2, DQT_WAIT_MS));
	dqt_lock(&f->c);
	ATF_REQUIRE_EQ(2, f->c.nwr);
	ATF_CHECK_EQ((uint64_t)*max_io, f->c.wr[1].offset);
	ATF_CHECK_EQ(*max_io, f->c.wr[1].len);
	dqt_unlock(&f->c);
	ATF_REQUIRE_EQ(0, kill(ch->pid, SIGUSR1));
}

ATF_TC(eintr_mid_chunk_intr);
ATF_TC_HEAD(eintr_mid_chunk_intr, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_PF_INTR: a signal while the second "
	    "max_io chunk waits: INTERRUPT names it and the call returns the "
	    "bytes of the accepted chunk (the short count), not EINTR");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(eintr_mid_chunk_intr, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct dq_policy pol;
	struct big_arg a;
	struct dqt_rr r;
	u_int max_io;

	dqt_policy_write(&pol);
	pol.dp_flags = DQ_PF_INTR;
	mid_chunk_start(&f, &pol, &ch, &a, &max_io);
	ATF_CHECK(dqt_wait_interrupts(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(f.c.held[1].id, f.c.interrupted[0]);
	dqt_unlock(&f.c);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG((long)max_io, r.rv, "rv %ld errno %d", r.rv, r.err);
	/* The late reply to the abandoned chunk is ESRCH. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_write(f.c.q, dqt_held_id(&f.c, 1), max_io,
	    max_io));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

ATF_TC(signal_mid_write_uninterruptible);
ATF_TC_HEAD(signal_mid_write_uninterruptible, tc)
{
	atf_tc_set_md_var(tc, "descr", "the default policy: a signal while the "
	    "second chunk waits does not end the write, which completes when "
	    "the controller answers, as a local file system's (D192)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(signal_mid_write_uninterruptible, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;
	u_int max_io;

	mid_chunk_start(&f, NULL, &ch, &a, &max_io);
	/* Nothing is abandoned: the write still waits for its answer. */
	dqt_msleep(300);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.ninterrupted);
	dqt_unlock(&f.c);
	answer_write(&f, 1, max_io, max_io);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG((long)(2 * max_io), r.rv, "rv %ld errno %d", r.rv,
	    r.err);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

ATF_TC(short_count_default);
ATF_TC_HEAD(short_count_default, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller errno on the second chunk "
	    "after the first was accepted: the write returns the accepted "
	    "bytes (D194, ZFS's rule; the errno was returned and the count "
	    "lost)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(short_count_default, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;
	struct stat st;
	u_int max_io;

	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.max_io", &max_io));
	setup(&f, 8);
	dqt_hold(&f.c, true);
	a.fd = f.o->fd;
	a.len = 2 * (size_t)max_io;
	a.off = 0;
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	answer_write(&f, 0, max_io, 0);
	ATF_REQUIRE(dqt_wait_held(&f.c, 2, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_reply(f.c.q, dqt_held_id(&f.c, 1), ENOSPC, NULL,
	    0));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG((long)max_io, r.rv, "rv %ld errno %d", r.rv, r.err);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &st));
	ATF_CHECK(st.st_size >= (off_t)max_io);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

static volatile sig_atomic_t got_xfsz;

static void
on_xfsz(int sig __unused)
{

	got_xfsz++;
}

struct fsize_res {
	struct ops_res	 ops;
	int		 xfsz;
};

static void
child_fsize(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct fsize_res *fr = result;
	struct ops_res *r = &fr->ops;
	struct rlimit rl;
	struct sigaction sa;
	char buf[100];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_xfsz;
	(void)sigaction(SIGXFSZ, &sa, NULL);
	rl.rlim_cur = rl.rlim_max = DATA_LEN + 50;
	(void)setrlimit(RLIMIT_FSIZE, &rl);
	memset(buf, 'f', sizeof(buf));
	/* Clamped at the limit: 50 of 100. */
	BOTH(r, pwrite(_fd, buf, sizeof(buf), DATA_LEN));
	/* At the limit: EFBIG with SIGXFSZ. */
	BOTH(r, pwrite(_fd, buf, sizeof(buf), DATA_LEN + 50));
	/* Below it, whole. */
	BOTH(r, pwrite(_fd, buf, sizeof(buf), 0));
	fr->xfsz = got_xfsz;
}

ATF_TC(rlimit_fsize);
ATF_TC_HEAD(rlimit_fsize, tc)
{
	atf_tc_set_md_var(tc, "descr", "RLIMIT_FSIZE clamps a write that "
	    "crosses it and refuses one at it with EFBIG and SIGXFSZ, as on "
	    "the real file; the clamped tail is not posted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rlimit_fsize, tc)
{
	struct dqt_fixture f;
	struct ops_arg a;
	struct fsize_res r;

	setup(&f, 8);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_fsize, &a, &r, sizeof(r));
	check_pairs(&r.ops);
	ATF_CHECK_EQ(50, r.ops.p[0].s.rv);
	ATF_CHECK_EQ(EFBIG, r.ops.p[1].s.err);
	/* One SIGXFSZ per file. */
	ATF_CHECK_EQ(2, r.xfsz);
	check_same_contents(&f);
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(2, f.c.nwr);
	ATF_CHECK_EQ(50, f.c.wr[0].len);
	dqt_unlock(&f.c);
	dqt_fixture_fini(&f);
}

struct note_res {
	int		 nev;
	u_int		 fflags[4];
	struct dqt_rr	 w1, w2;
};

static void
child_write_notes(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct note_res *r = result;
	struct kevent kev, out[4];
	struct timespec ts = { 1, 0 };
	char buf[10];
	int kq, n, i;

	memset(buf, 'n', sizeof(buf));
	kq = kqueue();
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE | NOTE_EXTEND, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	r->w1.rv = pwrite(fd, buf, sizeof(buf), 0);	/* inside: WRITE */
	n = kevent(kq, NULL, 0, out, 4, &ts);
	for (i = 0; i < n && r->nev < 4; i++)
		r->fflags[r->nev++] = out[i].fflags;
	r->w2.rv = pwrite(fd, buf, sizeof(buf), DATA_LEN);	/* EXTEND */
	n = kevent(kq, NULL, 0, out, 4, &ts);
	for (i = 0; i < n && r->nev < 4; i++)
		r->fflags[r->nev++] = out[i].fflags;
	(void)close(kq);
}

ATF_TC(notes_and_size);
ATF_TC_HEAD(notes_and_size, tc)
{
	atf_tc_set_md_var(tc, "descr", "a write raises NOTE_WRITE, and "
	    "NOTE_EXTEND when it ends past di_size, which then follows; a "
	    "read-only object refuses write with EBADF before any event");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(notes_and_size, tc)
{
	struct dqt_fixture f;
	struct note_res r;
	struct stat st;
	char buf[4];

	setup(&f, 9);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_write_notes, &f.o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(10, r.w1.rv);
	ATF_CHECK_EQ(10, r.w2.rv);
	ATF_REQUIRE_EQ(2, r.nev);
	ATF_CHECK_EQ(NOTE_WRITE, r.fflags[0]);
	ATF_CHECK_EQ(NOTE_WRITE | NOTE_EXTEND, r.fflags[1]);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &st));
	ATF_CHECK_EQ(DATA_LEN + 10, st.st_size);
	dqt_fixture_fini(&f);

	/* Read-only: the generic layer's EBADF, in the controller, no event. */
	setup_flags(&f, 10, 0);
	memset(buf, 'x', sizeof(buf));
	errno = 0;
	ATF_CHECK_EQ(-1, write(f.o->fd, buf, sizeof(buf)));
	ATF_CHECK_EQ(EBADF, errno);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.records);
	dqt_unlock(&f.c);
	dqt_fixture_fini(&f);
}

ATF_TC(controller_errnos);
ATF_TC_HEAD(controller_errnos, tc)
{
	atf_tc_set_md_var(tc, "descr", "an allowed errno (ENOSPC) reaches the "
	    "writer as itself; one outside WRITE's allow-list (EPIPE) arrives "
	    "as EIO, no SIGPIPE, and counts in ds2_bad_replies");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(controller_errnos, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;
	struct dq_stats2 st;

	setup(&f, 11);
	dqt_hold(&f.c, true);
	a.fd = f.o->fd;
	a.len = 10;
	a.off = 0;
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_reply(f.c.q, dqt_held_id(&f.c, 0), ENOSPC, NULL,
	    0));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(ENOSPC, r.err);
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 2, DQT_WAIT_MS));
	/* An errno with a body is EINVAL; the event stays in flight. */
	{
		struct dq_write_reply wr = { 0, 0 };

		errno = 0;
		ATF_CHECK_EQ(-1, dq_reply(f.c.q, dqt_held_id(&f.c, 1), ENOSPC,
		    &wr,
		    sizeof(wr)));
		ATF_CHECK_EQ(EINVAL, errno);
		/* So is a reply body of the wrong size. */
		errno = 0;
		ATF_CHECK_EQ(-1, dq_reply(f.c.q, dqt_held_id(&f.c, 1), 0, &wr,
		    8));
		ATF_CHECK_EQ(EINVAL, errno);
	}
	ATF_REQUIRE_EQ(0, dq_reply(f.c.q, dqt_held_id(&f.c, 1), EPIPE, NULL,
	    0));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EIO, r.err);
	dqt_stats2(&f.c, &st);
	ATF_CHECK_EQ(1, st.ds2_bad_replies);
	ATF_CHECK(!dq_reply_errno_allowed(DQ_OP_WRITE, EPIPE));
	ATF_CHECK(dq_reply_errno_allowed(DQ_OP_WRITE, ENOSPC));
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

static long
elapsed_ms(const struct timespec *t0)
{
	struct timespec t1;

	(void)clock_gettime(CLOCK_MONOTONIC, &t1);
	return ((t1.tv_sec - t0->tv_sec) * 1000 +
	    (t1.tv_nsec - t0->tv_nsec) / 1000000);
}

ATF_TC(edeadlk_while_held);
ATF_TC_HEAD(edeadlk_while_held, tc)
{
	atf_tc_set_md_var(tc, "descr", "K-B1: while a requester's write is "
	    "held by the controller (its range lock taken), the controller's "
	    "own write, read and ftruncate of the object are EDEADLK at once, "
	    "checked before any lock, not a wait on the requester's range");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* An old kernel waits on the range lock forever: bound it. */
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(edeadlk_while_held, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;
	struct timespec t0;
	char buf[8];

	setup(&f, 12);
	dqt_hold(&f.c, true);
	a.fd = f.o->fd;
	a.len = 10;
	a.off = 0;
	/* An implicit-offset write would take the whole file; pwrite [0,10). */
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));

	memset(buf, 'c', sizeof(buf));
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	errno = 0;
	ATF_CHECK_EQ(-1, pwrite(f.o->fd, buf, sizeof(buf), 0));
	ATF_CHECK_EQ(EDEADLK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, pread(f.o->fd, buf, sizeof(buf), 0));
	ATF_CHECK_EQ(EDEADLK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, write(f.o->fd, buf, sizeof(buf)));
	ATF_CHECK_EQ(EDEADLK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, ftruncate(f.o->fd, 1));
	ATF_CHECK_EQ(EDEADLK, errno);
	ATF_CHECK_MSG(elapsed_ms(&t0) < 2000, "took %ld ms", elapsed_ms(&t0));
	/* Nothing the controller tried reached its own queue. */
	dqt_lock(&f.c);
	ATF_CHECK_EQ(1, f.c.nwr);
	dqt_unlock(&f.c);

	answer_write(&f, 0, 10, 0);
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(10, r.rv);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

ATF_TC(reply_offset_and_zero);
ATF_TC_HEAD(reply_offset_and_zero, tc)
{
	atf_tc_set_md_var(tc, "descr", "K-N1: a reply to a positioned write "
	    "naming another offset is EINVAL to the controller and the event "
	    "stays in flight; K-N2: written 0 with errno 0 for a non-empty "
	    "chunk reaches the writer as EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_offset_and_zero, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct big_arg a;
	struct dqt_rr r;

	setup(&f, 13);
	dqt_hold(&f.c, true);
	a.fd = f.o->fd;
	a.len = 10;
	a.off = 100;
	dqt_spawn(&ch, child_big_pwrite, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(1, f.c.nwr);
	ATF_CHECK_EQ(0, f.c.wr[0].flags & DQ_WRITE_F_APPEND);
	dqt_unlock(&f.c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_write(f.c.q, dqt_held_id(&f.c, 0), 10, 101));
	ATF_CHECK_EQ(EINVAL, errno);
	/* Still in flight: the correct offset with nothing written. */
	ATF_CHECK_EQ(0, dq_reply_write(f.c.q, dqt_held_id(&f.c, 0), 0, 100));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EIO, r.err);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

/*
 * T-A02: the attributes fstat(2) shows after a served write, against what
 * stat(2) of the backing file shows.  The requester stats, writes 16
 * bytes and stats again.
 */
struct times_res {
	struct dqt_rr	 w;
	struct stat	 before, after;
};

static void
child_write_times(void *arg, void *result)
{
	struct times_res *r = result;
	int fd = *(int *)arg;
	char buf[16];

	memset(buf, 'm', sizeof(buf));
	(void)fstat(fd, &r->before);
	/* A clock tick past the open-time times. */
	dqt_msleep(20);
	DQT_RR(r->w, pwrite(fd, buf, sizeof(buf), DATA_LEN - 8));
	(void)fstat(fd, &r->after);
}

ATF_TC(mtime_after_write);
ATF_TC_HEAD(mtime_after_write, tc)
{
	atf_tc_set_md_var(tc, "descr", "fstat(2) after a served write shows "
	    "the times, size and blocks of the backing file (T-A02)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mtime_after_write, tc)
{
	struct dqt_fixture f;
	struct times_res r;
	struct stat bs;
	int fd;

	setup(&f, 14);
	fd = f.o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_write_times, &fd, &r, sizeof(r));
	ATF_REQUIRE_EQ(16, r.w.rv);
	ATF_REQUIRE_EQ(0, fstat(f.backing, &bs));
	ATF_CHECK_EQ(DATA_LEN + 8, bs.st_size);
	ATF_CHECK_EQ(bs.st_size, r.after.st_size);
	/* The backing file's times moved. */
	ATF_REQUIRE(timespeccmp(&bs.st_mtim, &r.before.st_mtim, >));
	/*
	 * The served file's times are the backing file's, from the reply's
	 * post-operation attributes (fstat kept the open-time ones).
	 */
	ATF_CHECK(timespeccmp(&r.after.st_mtim, &bs.st_mtim, ==));
	ATF_CHECK(timespeccmp(&r.after.st_ctim, &bs.st_ctim, ==));
	ATF_CHECK_EQ(bs.st_blocks, r.after.st_blocks);
	dqt_fixture_fini(&f);
}

/*
 * C7 (R2-H3): the size of the post-operation attributes is a lower bound.
 * A requester writes 10 bytes at 100 and fstats; the controller answers
 * with a block whose size is above, or below, what the write proves.
 */
#define	POSTOP_SEC	4000000000LL	/* later than any stamp (2096) */

struct postop_res {
	struct dqt_rr	 w;
	struct stat	 before, after;
};

static void
child_write_fstat(void *arg, void *result)
{
	struct postop_res *r = result;
	int fd = *(int *)arg;
	char buf[10];

	memset(buf, 'p', sizeof(buf));
	(void)fstat(fd, &r->before);
	dqt_msleep(20);
	DQT_RR(r->w, pwrite(fd, buf, sizeof(buf), 100));
	(void)fstat(fd, &r->after);
}

static void
postop_round(struct dqt_fixture *f, uint64_t size, struct postop_res *r,
    uint64_t *ignored)
{
	struct dq_postop_attr pa;
	struct dq_write_reply wr;
	struct dqt_child ch;
	uint64_t n0, n1;
	size_t len;
	int fd;

	/*
	 * kern.dq.postop_ignored is system-wide: its delta across this one
	 * reply is this reply's, since this program runs alone (Makefile)
	 * and no other program sends a block that is ignored.
	 */
	len = sizeof(n0);
	ATF_REQUIRE_EQ(0, sysctlbyname("kern.dq.postop_ignored", &n0, &len,
	    NULL, 0));
	dqt_hold(&f->c, true);
	fd = f->o->fd;
	memset(r, 0, sizeof(*r));
	dqt_spawn(&ch, child_write_fstat, &fd);
	ATF_REQUIRE(dqt_wait_held(&f->c, 1, DQT_WAIT_MS));
	memset(&pa, 0, sizeof(pa));
	pa.dpa_valid = DQ_PA_SIZE | DQ_PA_MTIME | DQ_PA_CTIME;
	pa.dpa_size = size;
	pa.dpa_mtime.tv_sec = pa.dpa_ctime.tv_sec = POSTOP_SEC;
	memset(&wr, 0, sizeof(wr));
	wr.dwr_written = 10;
	wr.dwr_offset = 100;
	ATF_REQUIRE_MSG(dq_reply_postop(f->c.q, dqt_held_id(&f->c, 0), &wr,
	    sizeof(wr), &pa) == 0, "dq_reply_postop: %s", strerror(errno));
	dqt_collect(&ch, r, sizeof(*r));
	dqt_hold(&f->c, false);
	len = sizeof(n1);
	ATF_REQUIRE_EQ(0, sysctlbyname("kern.dq.postop_ignored", &n1, &len,
	    NULL, 0));
	*ignored = n1 - n0;
}

ATF_TC(postop_size_larger_accepted);
ATF_TC_HEAD(postop_size_larger_accepted, tc)
{
	atf_tc_set_md_var(tc, "descr", "post-operation attributes whose size "
	    "is above the write's end are applied: the backing file may have "
	    "grown by another writer (C7, R2-H3)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(postop_size_larger_accepted, tc)
{
	struct dqt_fixture f;
	struct postop_res r;
	uint64_t ignored;

	setup(&f, 16);
	postop_round(&f, DATA_LEN + 100, &r, &ignored);
	ATF_CHECK_EQ(10, r.w.rv);
	ATF_CHECK_EQ(0, ignored);
	ATF_CHECK_EQ(DATA_LEN + 100, r.after.st_size);
	ATF_CHECK_EQ(POSTOP_SEC, r.after.st_mtim.tv_sec);
	ATF_CHECK_EQ(POSTOP_SEC, r.after.st_ctim.tv_sec);
	dqt_fixture_fini(&f);
}

ATF_TC(postop_size_smaller_ignored);
ATF_TC_HEAD(postop_size_smaller_ignored, tc)
{
	atf_tc_set_md_var(tc, "descr", "post-operation attributes whose size "
	    "is below the write's end are ignored and counted; the write "
	    "succeeds (C7, R2-H3)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(postop_size_smaller_ignored, tc)
{
	struct dqt_fixture f;
	struct postop_res r;
	uint64_t ignored;

	setup(&f, 17);
	postop_round(&f, 50, &r, &ignored);
	ATF_CHECK_EQ(10, r.w.rv);
	ATF_CHECK_EQ(1, ignored);
	/*
	 * Nothing of the block: the size is the kernel's and the times are
	 * its stamp, as with no block.
	 */
	ATF_CHECK_EQ(r.before.st_size, r.after.st_size);
	ATF_CHECK(r.after.st_mtim.tv_sec != POSTOP_SEC);
	ATF_CHECK(r.after.st_ctim.tv_sec != POSTOP_SEC);
	ATF_CHECK(timespeccmp(&r.after.st_mtim, &r.before.st_mtim, >));
	dqt_fixture_fini(&f);
}

/*
 * Review 1 H1: two disjoint extending writers whose replies carry
 * post-operation sizes, answered A (the smaller end) then B, with A's
 * apply held back a second (debug.dq.delay_postop_apply) so that B's
 * larger size is applied first.  The presented size, the backing file and
 * the mapping must end at B's end: no apply may move the size back.
 */
#define	TWO_A_OFF	(DATA_LEN)
#define	TWO_B_OFF	(DATA_LEN + 6000)
#define	TWO_LEN		100
#define	DELAY_POSTOP	"debug.dq.delay_postop_apply"

static void
child_pwrite_at(void *arg, void *result)
{
	struct big_arg *a = arg;
	struct dqt_rr *r = result;
	char buf[TWO_LEN];

	memset(buf, a->off == TWO_A_OFF ? 'A' : 'B', sizeof(buf));
	DQT_RR(*r, pwrite(a->fd, buf, a->len, a->off));
}

struct two_map_res {
	int		 sig_a, sig_b;
	unsigned char	 va, vb;
	struct stat	 st;
};

/* A requester's view: its fstat, and its mapping of both writes. */
static void
child_two_map(void *arg, void *result)
{
	struct two_map_res *r = result;
	int fd = *(int *)arg;
	unsigned char *p;
	size_t maplen;

	(void)fstat(fd, &r->st);
	maplen = TWO_B_OFF + TWO_LEN;
	p = mmap(NULL, maplen, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	r->sig_b = dqt_touch(p + TWO_B_OFF + 50, false, 0, &r->vb);
	r->sig_a = dqt_touch(p + TWO_A_OFF + 50, false, 0, &r->va);
	(void)munmap(p, maplen);
}

static void
two_reply(struct dqt_fixture *f, int i, off_t off)
{
	struct dq_postop_attr pa;
	struct dq_write_reply wr;
	struct stat bs;
	char buf[TWO_LEN];

	/* The controller's write, then what fstat says of its file. */
	memset(buf, off == TWO_A_OFF ? 'A' : 'B', sizeof(buf));
	ATF_REQUIRE_EQ(TWO_LEN, pwrite(f->backing, buf, TWO_LEN, off));
	ATF_REQUIRE_EQ(0, fstat(f->backing, &bs));
	dq_postop_from_stat(&pa, &bs, DQ_PA_SIZE | DQ_PA_MTIME | DQ_PA_CTIME);
	memset(&wr, 0, sizeof(wr));
	wr.dwr_written = TWO_LEN;
	wr.dwr_offset = (uint64_t)off;
	ATF_REQUIRE_MSG(dq_reply_postop(f->c.q, dqt_held_id(&f->c, i), &wr,
	    sizeof(wr), &pa) == 0, "dq_reply_postop: %s", strerror(errno));
}

ATF_TC_WITH_CLEANUP(postop_two_writers_size);
ATF_TC_HEAD(postop_two_writers_size, tc)
{
	atf_tc_set_md_var(tc, "descr", "two disjoint extending writers whose "
	    "post-operation sizes are applied out of order end with the "
	    "larger size, the backing file's, and a mapping to it (review 1 "
	    "H1)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(postop_two_writers_size, tc)
{
	struct dqt_fixture f;
	struct dqt_child cha, chb;
	struct big_arg a, b;
	struct dqt_rr ra, rb;
	struct two_map_res m;
	struct stat bs;
	int fd, ia, ib;

	dqt_require_fault_knob(DELAY_POSTOP);
	setup(&f, 18);
	dqt_hold(&f.c, true);
	a.fd = b.fd = f.o->fd;
	a.len = b.len = TWO_LEN;
	a.off = TWO_A_OFF;
	b.off = TWO_B_OFF;
	dqt_spawn(&cha, child_pwrite_at, &a);
	dqt_spawn(&chb, child_pwrite_at, &b);
	ATF_REQUIRE(dqt_wait_held(&f.c, 2, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ia = f.c.wr[0].offset == TWO_A_OFF ? 0 : 1;
	ib = 1 - ia;
	ATF_REQUIRE_EQ(TWO_B_OFF, f.c.wr[ib].offset);
	dqt_unlock(&f.c);
	/* A's apply waits a second; B's reply lands meanwhile. */
	dqt_sysctl_save_set_uint(DELAY_POSTOP, 1);
	two_reply(&f, ia, TWO_A_OFF);
	dqt_msleep(100);
	two_reply(&f, ib, TWO_B_OFF);
	dqt_collect(&chb, &rb, sizeof(rb));
	dqt_collect(&cha, &ra, sizeof(ra));
	ATF_REQUIRE(dqt_sysctl_restore(DELAY_POSTOP));
	ATF_CHECK_EQ(TWO_LEN, ra.rv);
	ATF_CHECK_EQ(TWO_LEN, rb.rv);

	ATF_REQUIRE_EQ(0, fstat(f.backing, &bs));
	ATF_CHECK_EQ(TWO_B_OFF + TWO_LEN, bs.st_size);
	/* The mapping reaches B's bytes: the VM object was not cut. */
	dqt_hold(&f.c, false);
	memset(&m, 0, sizeof(m));
	fd = f.o->fd;
	dqt_run_child(child_two_map, &fd, &m, sizeof(m));
	ATF_CHECK_EQ_MSG(bs.st_size, m.st.st_size, "presented size %jd, "
	    "backing %jd", (intmax_t)m.st.st_size, (intmax_t)bs.st_size);
	ATF_CHECK_EQ_MSG(0, m.sig_b, "B's page: signal %d", m.sig_b);
	ATF_CHECK_EQ_MSG(0, m.sig_a, "A's page: signal %d", m.sig_a);
	ATF_CHECK_EQ('B', m.vb);
	ATF_CHECK_EQ('A', m.va);
	dqt_fixture_fini(&f);
}
ATF_TC_CLEANUP(postop_two_writers_size, tc)
{

	(void)dqt_sysctl_restore(DELAY_POSTOP);
}

/*
 * T-A24: fspacectl(2) past the end of the file.  vop_stddeallocate
 * answers {EOF, 0}, or {offset, 0} past it, which the requester then
 * sees; the served file's controller says the same and is refused.
 */
struct space_res {
	struct dqt_rr		 r;
	struct spacectl_range	 rm;
};

static void
child_space_past_eof(void *arg, void *result)
{
	struct space_res *r = result;
	struct spacectl_range rq;
	int fd = *(int *)arg;

	rq.r_offset = DATA_LEN - 100;
	rq.r_len = 1000;
	DQT_RR(r->r, fspacectl(fd, SPACECTL_DEALLOC, &rq, 0, &r->rm));
}

ATF_TC(fspacectl_past_eof);
ATF_TC_HEAD(fspacectl_past_eof, tc)
{
	atf_tc_set_md_var(tc, "descr", "fspacectl(2) of a range that ends "
	    "past the end of the file (T-A24)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(fspacectl_past_eof, tc)
{
	struct dqt_fixture f;
	struct dq_policy pol;
	struct space_res s, o;
	int fd;

	dqt_policy_write(&pol);
	pol.dp_deadline_ms = 1000;
	dqt_fill(data, sizeof(data), 15);
	dqt_fixture_init(&f, data, sizeof(data), backing_path, oracle_path,
	    &pol, DQ_MINT_F_WRITE);
	memset(&o, 0, sizeof(o));
	fd = f.oracle;
	dqt_run_child(child_space_past_eof, &fd, &o, sizeof(o));
	ATF_CHECK_EQ(0, o.r.rv);
	ATF_CHECK_EQ(DATA_LEN, o.rm.r_offset);
	ATF_CHECK_EQ(0, o.rm.r_len);
	memset(&s, 0, sizeof(s));
	fd = f.o->fd;
	dqt_run_child(child_space_past_eof, &fd, &s, sizeof(s));
	/*
	 * The controller's {EOF, 0} is accepted and reaches the requester
	 * unchanged, as the real file's (it was refused, EINVAL to the
	 * controller, and the requester failed EIO at its deadline).
	 */
	ATF_CHECK_EQ_MSG(0, s.r.rv, "fspacectl: %s", strerror(s.r.err));
	ATF_CHECK_EQ(o.rm.r_offset, s.rm.r_offset);
	ATF_CHECK_EQ(o.rm.r_len, s.rm.r_len);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.reply_failures);
	dqt_unlock(&f.c);
	dqt_fini(&f.c);
	(void)close(f.backing);
	(void)close(f.oracle);
}

/*
 * Review 1 H1: a deallocation changes no size, so an FSPACECTL reply's
 * post-operation size is not applied, even one that would shrink the file.
 */
static void
child_space_mid(void *arg, void *result)
{
	struct space_res *r = result;
	struct spacectl_range rq;
	int fd = *(int *)arg;

	rq.r_offset = 0;
	rq.r_len = 4096;
	DQT_RR(r->r, fspacectl(fd, SPACECTL_DEALLOC, &rq, 0, &r->rm));
}

ATF_TC(postop_fspacectl_no_size);
ATF_TC_HEAD(postop_fspacectl_no_size, tc)
{
	atf_tc_set_md_var(tc, "descr", "the size of an FSPACECTL reply's "
	    "post-operation block is not applied: a deallocation changes none "
	    "(review 1 H1)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(postop_fspacectl_no_size, tc)
{
	struct dqt_fixture f;
	struct dq_postop_attr pa;
	struct dq_fspacectl_reply sr;
	struct dqt_child ch;
	struct space_res s;
	struct stat st;
	int fd;

	setup(&f, 19);
	dqt_hold(&f.c, true);
	fd = f.o->fd;
	memset(&s, 0, sizeof(s));
	dqt_spawn(&ch, child_space_mid, &fd);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	memset(&pa, 0, sizeof(pa));
	pa.dpa_valid = DQ_PA_SIZE;
	pa.dpa_size = 10;		/* a shrink, were it applied */
	sr.dscr_offset = 4096;
	sr.dscr_len = 0;
	ATF_REQUIRE_MSG(dq_reply_postop(f.c.q, dqt_held_id(&f.c, 0), &sr,
	    sizeof(sr), &pa) == 0, "dq_reply_postop: %s", strerror(errno));
	dqt_collect(&ch, &s, sizeof(s));
	ATF_CHECK_EQ_MSG(0, s.r.rv, "fspacectl: %s", strerror(s.r.err));
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &st));
	ATF_CHECK_EQ(DATA_LEN, st.st_size);
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, write_pwrite_writev);
	ATF_TP_ADD_TC(tp, aio_write);
	ATF_TP_ADD_TC(tp, append);
	ATF_TP_ADD_TC(tp, append_two_writers);
	ATF_TP_ADD_TC(tp, sync_flags);
	ATF_TP_ADD_TC(tp, short_write);
	ATF_TP_ADD_TC(tp, eintr_mid_chunk_intr);
	ATF_TP_ADD_TC(tp, signal_mid_write_uninterruptible);
	ATF_TP_ADD_TC(tp, short_count_default);
	ATF_TP_ADD_TC(tp, rlimit_fsize);
	ATF_TP_ADD_TC(tp, notes_and_size);
	ATF_TP_ADD_TC(tp, controller_errnos);
	ATF_TP_ADD_TC(tp, edeadlk_while_held);
	ATF_TP_ADD_TC(tp, reply_offset_and_zero);
	ATF_TP_ADD_TC(tp, mtime_after_write);
	ATF_TP_ADD_TC(tp, postop_size_larger_accepted);
	ATF_TP_ADD_TC(tp, postop_size_smaller_ignored);
	ATF_TP_ADD_TC(tp, postop_two_writers_size);
	ATF_TP_ADD_TC(tp, postop_fspacectl_no_size);
	ATF_TP_ADD_TC(tp, fspacectl_past_eof);
	return (atf_no_error());
}
