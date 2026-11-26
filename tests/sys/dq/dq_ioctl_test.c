/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ioctls (D99, N6): under dp_ioctl = DQ_EVENT every command a regular file
 * does not answer locally is an IOCTL event carrying the generic layer's
 * post-copyin argument (IOC_IN, and the int of an int-sized IOC_VOID) and
 * answered with errno + out[IOCPARM_LEN] for IOC_OUT.  The commands here
 * are private to the test ('j' numbers above every DQ_IOC_*), served by a
 * dq_serve_file() ioctl handler.
 */

#include <sys/param.h>
#include <sys/filio.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	DATA_LEN	4096

struct dqt_in {
	uint64_t	 a;
	uint32_t	 b;
	uint32_t	 c;
};
struct dqt_out {
	uint64_t	 x, y, z;
};
struct dqt_ptr {
	void		*p;
	size_t		 len;
};

#define	DQT_IOC_IN	_IOW('j', 100, struct dqt_in)
#define	DQT_IOC_OUT	_IOR('j', 101, struct dqt_out)
#define	DQT_IOC_INOUT	_IOWR('j', 102, uint64_t)
#define	DQT_IOC_VOIDINT	_IOWINT('j', 103)
#define	DQT_IOC_VOID0	_IO('j', 104)
#define	DQT_IOC_PTR	_IOW('j', 105, struct dqt_ptr)

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

/* The controller's handler. */
static int
handler(int backing __unused, const struct dq_ioctl_body *ib, const void *in,
    void *out, size_t outlen, void *arg __unused)
{
	const struct dqt_in *di;
	struct dqt_out *dout;
	uint64_t v;
	int iv;

	switch (ib->dio_cmd) {
	case DQT_IOC_IN:
		if (ib->dio_len != sizeof(*di))
			return (EINVAL);
		di = in;
		return (di->a == 0x1122334455667788ULL && di->b == 9 &&
		    di->c == 10 ? 0 : EINVAL);
	case DQT_IOC_OUT:
		if (ib->dio_len != 0 || outlen != sizeof(*dout))
			return (EINVAL);
		dout = out;
		dout->x = 1;
		dout->y = 2;
		dout->z = 3;
		return (0);
	case DQT_IOC_INOUT:
		if (ib->dio_len != sizeof(v) || outlen != sizeof(v))
			return (EINVAL);
		memcpy(&v, in, sizeof(v));
		v++;
		memcpy(out, &v, sizeof(v));
		return (0);
	case DQT_IOC_VOIDINT:
		if (ib->dio_len != sizeof(int))
			return (EINVAL);
		memcpy(&iv, in, sizeof(iv));
		return (iv == 7 ? 0 : ENXIO);
	case DQT_IOC_VOID0:
		return (ib->dio_len == 0 ? 0 : EINVAL);
	case DQT_IOC_PTR:
		/* An embedded pointer cannot be followed: refuse. */
		return (ENOTTY);
	default:
		return (ENOTTY);
	}
}

struct ioctl_res {
	struct dqt_rr	 in, out, inout, voidint, voidint_bad, void0, ptr;
	struct dqt_rr	 fiodtype, setown, oracle_fiodtype, oracle_setown;
	struct dqt_out	 o;
	uint64_t	 v;
};

struct ioctl_arg {
	int		 fd, oracle;
};

static void
child_ioctls(void *arg, void *result)
{
	struct ioctl_arg *a = arg;
	struct ioctl_res *r = result;
	struct dqt_in di;
	struct dqt_ptr dp;
	int type;

	di.a = 0x1122334455667788ULL;
	di.b = 9;
	di.c = 10;
	DQT_RR(r->in, ioctl(a->fd, DQT_IOC_IN, &di));
	memset(&r->o, 0, sizeof(r->o));
	DQT_RR(r->out, ioctl(a->fd, DQT_IOC_OUT, &r->o));
	r->v = 41;
	DQT_RR(r->inout, ioctl(a->fd, DQT_IOC_INOUT, &r->v));
	DQT_RR(r->voidint, ioctl(a->fd, DQT_IOC_VOIDINT, 7));
	DQT_RR(r->voidint_bad, ioctl(a->fd, DQT_IOC_VOIDINT, 8));
	DQT_RR(r->void0, ioctl(a->fd, DQT_IOC_VOID0));
	dp.p = &di;
	dp.len = sizeof(di);
	DQT_RR(r->ptr, ioctl(a->fd, DQT_IOC_PTR, &dp));
	DQT_RR(r->fiodtype, ioctl(a->fd, FIODTYPE, &type));
	DQT_RR(r->oracle_fiodtype, ioctl(a->oracle, FIODTYPE, &type));
	DQT_RR(r->setown, fcntl(a->fd, F_SETOWN, getpid()));
	DQT_RR(r->oracle_setown, fcntl(a->oracle, F_SETOWN, getpid()));
}

ATF_TC(shapes);
ATF_TC_HEAD(shapes, tc)
{
	atf_tc_set_md_var(tc, "descr", "IOC_IN, IOC_OUT, IOC_INOUT, VOID-int "
	    "and VOID-0 commands carry exactly their argument and receive "
	    "exactly IOCPARM_LEN bytes; a pointer-embedding command is the "
	    "controller's ENOTTY; FIODTYPE and F_SETOWN answer as on the real "
	    "file (ENOTTY from the default handler)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shapes, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct ioctl_arg a;
	struct ioctl_res r;
	int backing, oracle;

	dqt_fill(data, sizeof(data), 1);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	oracle = open(path, O_RDONLY);
	ATF_REQUIRE(oracle != -1);
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	o->sopts.so_ioctl = handler;
	a.fd = o->fd;
	a.oracle = oracle;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_ioctls, &a, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.in.rv, "IN: %s", strerror(r.in.err));
	ATF_CHECK_EQ_MSG(0, r.out.rv, "OUT: %s", strerror(r.out.err));
	ATF_CHECK_EQ(1, r.o.x);
	ATF_CHECK_EQ(2, r.o.y);
	ATF_CHECK_EQ(3, r.o.z);
	ATF_CHECK_EQ(0, r.inout.rv);
	ATF_CHECK_EQ(42, r.v);
	ATF_CHECK_EQ(0, r.voidint.rv);
	ATF_CHECK_EQ(ENXIO, r.voidint_bad.err);
	ATF_CHECK_EQ(0, r.void0.rv);
	ATF_CHECK_EQ(ENOTTY, r.ptr.err);
	ATF_CHECK_EQ(r.oracle_fiodtype.rv, r.fiodtype.rv);
	ATF_CHECK_EQ(r.oracle_fiodtype.err, r.fiodtype.err);
	ATF_CHECK_EQ(r.oracle_setown.rv, r.setown.rv);
	ATF_CHECK_EQ(r.oracle_setown.err, r.setown.err);
	/* The bodies the kernel posted: lengths per shape, never a pointer. */
	dqt_lock(&c);
	printf("IOCTL records: %u\n", c.events[DQ_OP_IOCTL]);
	/* One record per ioctl that reaches the controller. */
	ATF_CHECK_EQ(9, c.events[DQ_OP_IOCTL]);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(backing);
	(void)close(oracle);
}

struct one_ioctl_arg {
	int		 fd;
	unsigned long	 cmd;
};

static void
child_one_ioctl(void *arg, void *result)
{
	struct one_ioctl_arg *a = arg;
	struct dqt_rr *r = result;
	struct dqt_out o;
	struct dqt_in in;

	memset(&in, 0, sizeof(in));
	if (a->cmd == DQT_IOC_OUT)
		r->rv = ioctl(a->fd, a->cmd, &o);
	else
		r->rv = ioctl(a->fd, a->cmd, &in);
	r->err = r->rv == -1 ? errno : 0;
}

ATF_TC(reply_rules);
ATF_TC_HEAD(reply_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "N6: an IOC_OUT reply must be exactly "
	    "IOCPARM_LEN bytes, an IN reply or an errno reply carries none "
	    "(EINVAL, the event stays in flight); an errno outside IOCTL's "
	    "allow-list is EIO; the body is the cmd and in[] of the shape");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_rules, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct dqt_child ch;
	struct one_ioctl_arg a;
	struct dqt_rr r;
	struct dqt_out out;
	struct statfs sfs;
	struct stat sb;
	int oracle;

	dqt_fill(data, sizeof(data), 2);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(oracle, path, id, &sb, &sfs);
	dq_policy_default(&pol);
	pol.dp_ioctl = DQ_EVENT;
	o = dqt_mint_ident(&c, id, &pol, data, sizeof(data));
	free(id);
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.cmd = DQT_IOC_OUT;
	dqt_spawn(&ch, child_one_ioctl, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(DQT_IOC_OUT, o->last_ioctl.dio_cmd);
	ATF_CHECK_EQ(0, o->last_ioctl.dio_len);
	dqt_unlock(&c);
	memset(&out, 0, sizeof(out));
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, dqt_held_id(&c, 0), 0, &out, 8));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, dqt_held_id(&c, 0), 0, NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, dqt_held_id(&c, 0), ENXIO, &out,
	    sizeof(out)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_reply_ioctl(c.q, dqt_held_id(&c, 0), 0, &out,
	    sizeof(out)));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.rv);

	a.cmd = DQT_IOC_IN;
	dqt_spawn(&ch, child_one_ioctl, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 2, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(DQT_IOC_IN, o->last_ioctl.dio_cmd);
	ATF_CHECK_EQ(sizeof(struct dqt_in), o->last_ioctl.dio_len);
	dqt_unlock(&c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, dqt_held_id(&c, 1), 0, &out, 8));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_reply_ioctl(c.q, dqt_held_id(&c, 1), EPIPE, NULL,
	    0));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.err);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(deny_and_local);
ATF_TC_HEAD(deny_and_local, tc)
{
	atf_tc_set_md_var(tc, "descr", "dp_ioctl = DQ_DENY answers ENOTTY "
	    "without an event; FIONREAD, FIONBIO and FIOASYNC stay local under "
	    "DQ_EVENT; the controller's own process is refused an "
	    "event-posting ioctl, FIOSEEKDATA included (C21), with EDEADLK");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deny_and_local, tc)
{
	struct dqt_ctl c;
	struct dqt_object *deny, *ev;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat sb;
	struct dqt_in in;
	off_t off;
	int n, on, oracle;

	dqt_fill(data, sizeof(data), 3);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), path,
	    sizeof(path));
	dqt_init(&c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(oracle, path, id, &sb, &sfs);
	dq_policy_default(&pol);
	deny = dqt_mint_ident(&c, id, &pol, data, sizeof(data));
	pol.dp_ioctl = DQ_EVENT;
	ev = dqt_mint_ident(&c, id, &pol, data, sizeof(data));
	free(id);
	memset(&in, 0, sizeof(in));
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(deny->fd, DQT_IOC_IN, &in));
	ATF_CHECK_EQ(ENOTTY, errno);
	ATF_CHECK_EQ(0, ioctl(ev->fd, FIONREAD, &n));
	ATF_CHECK_EQ(DATA_LEN, n);
	on = 1;
	ATF_CHECK_EQ(0, ioctl(ev->fd, FIONBIO, &on));
	on = 0;
	ATF_CHECK_EQ(0, ioctl(ev->fd, FIONBIO, &on));
	ATF_CHECK_EQ(0, ioctl(ev->fd, FIOASYNC, &on));
	/* Forwarded under DQ_EVENT (C21): refused here as every event is. */
	off = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(ev->fd, FIOSEEKDATA, &off));
	ATF_CHECK_EQ(EDEADLK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(ev->fd, DQT_IOC_IN, &in));
	ATF_CHECK_EQ(EDEADLK, errno);
	/* Everything posted before the fence has been recorded. */
	dqt_fence(&c);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Holes (C21): FIOSEEKDATA and FIOSEEKHOLE, and lseek(2)'s SEEK_DATA and
 * SEEK_HOLE through them, are IOCTL events under DQ_EVENT; this handler
 * runs them on the backing file, as a supervisor serving its files does.
 */
static int
seek_handler(int backing, const struct dq_ioctl_body *ib, const void *in,
    void *out, size_t outlen, void *arg __unused)
{
	off_t v;

	switch (ib->dio_cmd) {
	case FIOSEEKDATA:
	case FIOSEEKHOLE:
		if (ib->dio_len != sizeof(v) || outlen != sizeof(v))
			return (EINVAL);
		memcpy(&v, in, sizeof(v));
		if (ioctl(backing, ib->dio_cmd, &v) == -1)
			return (errno);
		memcpy(out, &v, sizeof(v));
		return (0);
	default:
		return (ENOTTY);
	}
}

#define	SPARSE_SIZE	(4 * 1024 * 1024)
#define	SPARSE_DATA	(2 * 1024 * 1024)	/* one data run, then a hole */

/*
 * A file with a hole, the data run, and a hole to its end.  The case fails
 * (not skips) when the work directory's file system reports no hole: the
 * pin would compare nothing.
 */
static int
make_sparse(char *p, size_t plen)
{
	unsigned char buf[8192];
	off_t d;
	int fd;

	fd = open("sparse", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, ftruncate(fd, SPARSE_SIZE));
	dqt_fill(buf, sizeof(buf), 7);
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf), pwrite(fd, buf, sizeof(buf),
	    SPARSE_DATA));
	ATF_REQUIRE_EQ(0, fsync(fd));
	ATF_REQUIRE(realpath("sparse", p) != NULL && strlen(p) < plen);
	d = lseek(fd, 0, SEEK_DATA);
	ATF_REQUIRE_MSG(d > 0, "the work directory's file system reports "
	    "no leading hole (SEEK_DATA 0 = %jd): nothing to compare",
	    (intmax_t)d);
	return (fd);
}

#define	SEEK_OPS	8

struct seek_arg {
	int		 fd, oracle;
	bool		 ioctls;	/* FIOSEEK*, else lseek */
};

struct seek_res {
	struct dqt_rr	 s[SEEK_OPS], o[SEEK_OPS];
	off_t		 sv[SEEK_OPS], ov[SEEK_OPS];
	int		 n;
};

static void
seek_one(int fd, bool ioctls, int whence, off_t off, struct dqt_rr *r,
    off_t *v)
{

	if (ioctls) {
		*v = off;
		DQT_RR(*r, ioctl(fd, whence == SEEK_DATA ? FIOSEEKDATA :
		    FIOSEEKHOLE, v));
	} else {
		DQT_RR(*r, lseek(fd, off, whence));
		*v = lseek(fd, 0, SEEK_CUR);
	}
}

static void
child_seek(void *arg, void *result)
{
	static const struct {
		int	 whence;
		off_t	 off;
	} ops[] = {
		{ SEEK_DATA, 0 },
		{ SEEK_HOLE, 0 },
		{ SEEK_DATA, SPARSE_DATA + 100 },
		{ SEEK_HOLE, SPARSE_DATA + 100 },
		{ SEEK_DATA, SPARSE_DATA + 1024 * 1024 },	/* hole to EOF */
		{ SEEK_HOLE, SPARSE_SIZE - 1 },
		{ SEEK_DATA, SPARSE_SIZE },			/* at EOF */
		{ SEEK_HOLE, -1 },
	};
	struct seek_arg *a = arg;
	struct seek_res *r = result;
	int i;

	for (i = 0; i < (int)nitems(ops); i++) {
		seek_one(a->fd, a->ioctls, ops[i].whence, ops[i].off, &r->s[i],
		    &r->sv[i]);
		seek_one(a->oracle, a->ioctls, ops[i].whence, ops[i].off,
		    &r->o[i], &r->ov[i]);
	}
	r->n = nitems(ops);
}

static void
seek_case(bool ioctls)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct seek_arg a;
	struct seek_res r;
	int backing, i;

	backing = make_sparse(path, sizeof(path));
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	o->sopts.so_ioctl = seek_handler;
	a.fd = o->fd;
	a.oracle = open(path, O_RDONLY);
	ATF_REQUIRE(a.oracle != -1);
	a.ioctls = ioctls;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_seek, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(SEEK_OPS, r.n);
	for (i = 0; i < r.n; i++) {
		ATF_CHECK_EQ_MSG(r.o[i].rv, r.s[i].rv,
		    "op %d: served %ld oracle %ld", i, r.s[i].rv, r.o[i].rv);
		DQT_CHECK_ERRNO(r.o[i].err, r.s[i].err, "seek errno");
		ATF_CHECK_EQ_MSG(r.ov[i], r.sv[i],
		    "op %d: served offset %jd oracle %jd", i,
		    (intmax_t)r.sv[i], (intmax_t)r.ov[i]);
	}
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(a.oracle);
	(void)close(backing);
}

ATF_TC(seek_data_forwarded);
ATF_TC_HEAD(seek_data_forwarded, tc)
{
	atf_tc_set_md_var(tc, "descr", "lseek SEEK_DATA and SEEK_HOLE on a "
	    "served file under DQ_EVENT answer the backing file's holes, as "
	    "on the real file (dev: the whole presented size is data, "
	    "SEEK_DATA 0 is 0)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek_data_forwarded, tc)
{

	seek_case(false);
}

ATF_TC(fioseekhole_forwarded);
ATF_TC_HEAD(fioseekhole_forwarded, tc)
{
	atf_tc_set_md_var(tc, "descr", "ioctl FIOSEEKDATA and FIOSEEKHOLE on "
	    "a served file under DQ_EVENT answer the backing file's holes, as "
	    "on the real file (dev: answered from the presented size)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fioseekhole_forwarded, tc)
{

	seek_case(true);
}

struct seek_local_res {
	struct dqt_rr	 data0, hole0, eof;
	off_t		 fio;
	struct dqt_rr	 fior;
};

static void
child_seek_local(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct seek_local_res *r = result;

	DQT_RR(r->data0, lseek(fd, 0, SEEK_DATA));
	DQT_RR(r->hole0, lseek(fd, 0, SEEK_HOLE));
	DQT_RR(r->eof, lseek(fd, SPARSE_SIZE, SEEK_DATA));
	r->fio = SPARSE_DATA + 1024 * 1024;
	DQT_RR(r->fior, ioctl(fd, FIOSEEKHOLE, &r->fio));
}

ATF_TC(seek_no_handler_local);
ATF_TC_HEAD(seek_no_handler_local, tc)
{
	atf_tc_set_md_var(tc, "descr", "a supervisor without an ioctl handler "
	    "(ENOTTY) leaves SEEK_DATA, SEEK_HOLE and FIOSEEKHOLE the "
	    "presented size's answer: the whole file is data (regression pin "
	    "of dev's answer)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek_no_handler_local, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct seek_local_res r;
	int backing, fd;

	backing = make_sparse(path, sizeof(path));
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	fd = o->fd;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_seek_local, &fd, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.data0.rv);
	ATF_CHECK_EQ(SPARSE_SIZE, r.hole0.rv);
	ATF_CHECK_EQ(-1, r.eof.rv);
	DQT_CHECK_ERRNO(ENXIO, r.eof.err, "SEEK_DATA at the end");
	ATF_CHECK_EQ(0, r.fior.rv);
	ATF_CHECK_EQ(SPARSE_SIZE, r.fio);
	dqt_fini(&c);
	(void)close(backing);
}

/*
 * A file of size bytes with 4096-byte data runs at the offsets in runs[]
 * (the rest holes), fsynced; its path in p.
 */
static int
make_runs(const char *name, off_t size, const off_t *runs, int nruns,
    char *p, size_t plen)
{
	unsigned char buf[4096];
	int fd, i;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, ftruncate(fd, size));
	dqt_fill(buf, sizeof(buf), 9);
	for (i = 0; i < nruns; i++)
		ATF_REQUIRE_EQ((ssize_t)sizeof(buf), pwrite(fd, buf,
		    sizeof(buf), runs[i]));
	ATF_REQUIRE_EQ(0, fsync(fd));
	ATF_REQUIRE(realpath(name, p) != NULL && strlen(p) < plen);
	return (fd);
}

/* Data runs added to a backing file after its object was minted. */
static void
add_runs(int fd, const off_t *runs, int nruns)
{
	unsigned char buf[4096];
	int i;

	dqt_fill(buf, sizeof(buf), 9);
	for (i = 0; i < nruns; i++)
		ATF_REQUIRE_EQ((ssize_t)sizeof(buf), pwrite(fd, buf,
		    sizeof(buf), runs[i]));
	ATF_REQUIRE_EQ(0, fsync(fd));
}

#define	SMALL_OPS	4

struct small_arg {
	int		 fd, oracle;
	struct {
		int	 whence;
		off_t	 off;
	} ops[SMALL_OPS];
	int		 nops;
};

struct small_res {
	off_t		 end;		/* the served file's SEEK_END */
	struct dqt_rr	 s[SMALL_OPS], o[SMALL_OPS];
	off_t		 sv[SMALL_OPS], ov[SMALL_OPS];
};

static void
child_small(void *arg, void *result)
{
	struct small_arg *a = arg;
	struct small_res *r = result;
	off_t cur;
	int i;

	/* The presented size, leaving the offset as the oracle's. */
	cur = lseek(a->fd, 0, SEEK_CUR);
	r->end = lseek(a->fd, 0, SEEK_END);
	if (cur == -1 || lseek(a->fd, cur, SEEK_SET) != cur)
		_exit(DQT_EXIT_NORESULT);
	for (i = 0; i < a->nops; i++) {
		seek_one(a->fd, false, a->ops[i].whence, a->ops[i].off,
		    &r->s[i], &r->sv[i]);
		seek_one(a->oracle, false, a->ops[i].whence, a->ops[i].off,
		    &r->o[i], &r->ov[i]);
	}
}

static void
small_check(const struct small_arg *a, const struct small_res *r,
    const char *what)
{
	int i;

	ATF_REQUIRE_EQ_MSG(SPARSE_SIZE, r->end, "%s: presented size %jd, "
	    "want %d (the backing file grew after the mint)", what,
	    (intmax_t)r->end, SPARSE_SIZE);
	for (i = 0; i < a->nops; i++) {
		ATF_CHECK_EQ_MSG(r->o[i].rv, r->s[i].rv,
		    "%s op %d: served %ld oracle %ld", what, i, r->s[i].rv,
		    r->o[i].rv);
		DQT_CHECK_ERRNO(r->o[i].err, r->s[i].err, "seek errno");
		ATF_CHECK_EQ_MSG(r->ov[i], r->sv[i],
		    "%s op %d: served offset %jd oracle %jd", what, i,
		    (intmax_t)r->sv[i], (intmax_t)r->ov[i]);
	}
}

ATF_TC(seek_presented_smaller);
ATF_TC_HEAD(seek_presented_smaller, tc)
{
	atf_tc_set_md_var(tc, "descr", "SEEK_DATA and SEEK_HOLE on a served "
	    "file whose backing file grew past the presented size answer "
	    "within the presented size, as a real file of that size: data "
	    "past it is ENXIO, a hole past it is the end, and a start at the "
	    "end is ENXIO with no event (dev: the whole presented size is "
	    "data)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek_presented_smaller, tc)
{
	/* A: data at 2 MB and across the presented end. */
	static const off_t a_runs[] = { SPARSE_DATA, SPARSE_SIZE - 4096 };
	static const off_t a_more[] = { SPARSE_SIZE };
	/* B: data at 2 MB, a hole to the presented end, data past it. */
	static const off_t b_runs[] = { SPARSE_DATA };
	static const off_t b_more[] = { SPARSE_SIZE + 1024 * 1024 };
	char opath[DQT_PATH_MAX];
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct small_arg a;
	struct small_res r;
	unsigned served;
	int backing, backing_a, oracle, oracle_a;

	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;

	backing = make_runs("bigger_a", SPARSE_SIZE, a_runs, nitems(a_runs),
	    path, sizeof(path));
	ATF_REQUIRE_MSG(lseek(backing, 0, SEEK_DATA) > 0, "the work "
	    "directory's file system reports no leading hole: nothing to "
	    "compare");
	oracle = make_runs("oracle_a", SPARSE_SIZE, a_runs, nitems(a_runs),
	    opath, sizeof(opath));
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	o->sopts.so_ioctl = seek_handler;
	add_runs(backing, a_more, nitems(a_more));
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.oracle = oracle;
	a.ops[0].whence = SEEK_HOLE;	/* the run crosses the end */
	a.ops[0].off = SPARSE_SIZE - 100;
	a.ops[1].whence = SEEK_DATA;
	a.ops[1].off = SPARSE_SIZE - 100;
	a.ops[2].whence = SEEK_DATA;	/* the hole before the last run */
	a.ops[2].off = SPARSE_DATA + 1024 * 1024;
	a.nops = 3;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_small, &a, &r, sizeof(r));
	small_check(&a, &r, "crossing run");

	/* A start at the presented end: ENXIO, posted to no one. */
	dqt_lock(&c);
	served = o->served;
	dqt_unlock(&c);
	a.ops[0].whence = SEEK_DATA;
	a.ops[0].off = SPARSE_SIZE;
	a.ops[1].whence = SEEK_HOLE;
	a.ops[1].off = SPARSE_SIZE;
	a.nops = 2;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_small, &a, &r, sizeof(r));
	small_check(&a, &r, "at the end");
	dqt_lock(&c);
	ATF_CHECK_EQ_MSG(served, o->served, "%u events posted for a start "
	    "at the presented end", o->served - served);
	dqt_unlock(&c);
	/* Open until dqt_fini: the object's CLOSE is served from it. */
	backing_a = backing;
	oracle_a = oracle;

	backing = make_runs("bigger_b", SPARSE_SIZE, b_runs, nitems(b_runs),
	    path, sizeof(path));
	oracle = make_runs("oracle_b", SPARSE_SIZE, b_runs, nitems(b_runs),
	    opath, sizeof(opath));
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	o->sopts.so_ioctl = seek_handler;
	add_runs(backing, b_more, nitems(b_more));
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.oracle = oracle;
	a.ops[0].whence = SEEK_DATA;	/* the next data is past the end */
	a.ops[0].off = SPARSE_DATA + 1024 * 1024;
	a.ops[1].whence = SEEK_HOLE;
	a.ops[1].off = SPARSE_DATA + 1024 * 1024;
	a.nops = 2;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_small, &a, &r, sizeof(r));
	small_check(&a, &r, "hole to the end");
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
	(void)close(backing);
	(void)close(oracle_a);
	(void)close(backing_a);
}

ATF_TC(seek_dense_forwarded);
ATF_TC_HEAD(seek_dense_forwarded, tc)
{
	atf_tc_set_md_var(tc, "descr", "SEEK_DATA and SEEK_HOLE forwarded to "
	    "a supervisor for a file with no holes answer the whole file as "
	    "data, as on the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(seek_dense_forwarded, tc)
{
	unsigned char buf[8192];
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct small_arg a;
	struct small_res r;
	off_t off;
	int backing;

	backing = open("dense", O_RDWR | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(backing != -1);
	dqt_fill(buf, sizeof(buf), 11);
	for (off = 0; off < SPARSE_SIZE; off += sizeof(buf))
		ATF_REQUIRE_EQ((ssize_t)sizeof(buf), pwrite(backing, buf,
		    sizeof(buf), off));
	ATF_REQUIRE_EQ(0, fsync(backing));
	ATF_REQUIRE(realpath("dense", path) != NULL);
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;
	o = dqt_mint_backing(&c, backing, path, &pol, DQ_MINT_F_WRITE);
	o->sopts.so_ioctl = seek_handler;
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.oracle = open(path, O_RDONLY);
	ATF_REQUIRE(a.oracle != -1);
	a.ops[0].whence = SEEK_DATA;
	a.ops[0].off = 0;
	a.ops[1].whence = SEEK_HOLE;
	a.ops[1].off = 0;
	a.ops[2].whence = SEEK_HOLE;
	a.ops[2].off = SPARSE_SIZE - 1;
	a.ops[3].whence = SEEK_DATA;
	a.ops[3].off = SPARSE_SIZE - 1;
	a.nops = 4;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_small, &a, &r, sizeof(r));
	small_check(&a, &r, "dense");
	ATF_CHECK_EQ(0, r.s[0].rv);
	ATF_CHECK_EQ(SPARSE_SIZE, r.s[1].rv);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(a.oracle);
	(void)close(backing);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, shapes);
	ATF_TP_ADD_TC(tp, reply_rules);
	ATF_TP_ADD_TC(tp, deny_and_local);
	ATF_TP_ADD_TC(tp, seek_data_forwarded);
	ATF_TP_ADD_TC(tp, fioseekhole_forwarded);
	ATF_TP_ADD_TC(tp, seek_no_handler_local);
	ATF_TP_ADD_TC(tp, seek_presented_smaller);
	ATF_TP_ADD_TC(tp, seek_dense_forwarded);
	return (atf_no_error());
}
