/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

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

#define	RR(field, expr) do {						\
	r->field.rv = (long)(expr);					\
	r->field.err = r->field.rv == -1 ? errno : 0;			\
} while (0)

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
	RR(in, ioctl(a->fd, DQT_IOC_IN, &di));
	memset(&r->o, 0, sizeof(r->o));
	RR(out, ioctl(a->fd, DQT_IOC_OUT, &r->o));
	r->v = 41;
	RR(inout, ioctl(a->fd, DQT_IOC_INOUT, &r->v));
	RR(voidint, ioctl(a->fd, DQT_IOC_VOIDINT, 7));
	RR(voidint_bad, ioctl(a->fd, DQT_IOC_VOIDINT, 8));
	RR(void0, ioctl(a->fd, DQT_IOC_VOID0));
	dp.p = &di;
	dp.len = sizeof(di);
	RR(ptr, ioctl(a->fd, DQT_IOC_PTR, &dp));
	RR(fiodtype, ioctl(a->fd, FIODTYPE, &type));
	RR(oracle_fiodtype, ioctl(a->oracle, FIODTYPE, &type));
	RR(setown, fcntl(a->fd, F_SETOWN, getpid()));
	RR(oracle_setown, fcntl(a->oracle, F_SETOWN, getpid()));
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
	ATF_CHECK(c.events[DQ_OP_IOCTL] >= 9);
	ATF_CHECK_EQ(0, c.reply_failures);
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
	ATF_CHECK_EQ(DQT_IOC_OUT, o->last_ioctl.dio_cmd);
	ATF_CHECK_EQ(0, o->last_ioctl.dio_len);
	memset(&out, 0, sizeof(out));
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, c.held[0].id, 0, &out, 8));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, c.held[0].id, 0, NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, c.held[0].id, ENXIO, &out,
	    sizeof(out)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_reply_ioctl(c.q, c.held[0].id, 0, &out,
	    sizeof(out)));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.rv);

	a.cmd = DQT_IOC_IN;
	dqt_spawn(&ch, child_one_ioctl, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 2, DQT_WAIT_MS));
	ATF_CHECK_EQ(DQT_IOC_IN, o->last_ioctl.dio_cmd);
	ATF_CHECK_EQ(sizeof(struct dqt_in), o->last_ioctl.dio_len);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply_ioctl(c.q, c.held[1].id, 0, &out, 8));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_reply_ioctl(c.q, c.held[1].id, EPIPE, NULL, 0));
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
	    "without an event; FIONREAD, FIONBIO, FIOASYNC and FIOSEEKDATA stay "
	    "local under DQ_EVENT; the controller's own process is refused "
	    "an event-posting ioctl with EDEADLK");
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
	off = 0;
	ATF_CHECK_EQ(0, ioctl(ev->fd, FIOSEEKDATA, &off));
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(ev->fd, DQT_IOC_IN, &in));
	ATF_CHECK_EQ(EDEADLK, errno);
	dqt_msleep(100);
	ATF_CHECK_EQ(0, c.records);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, shapes);
	ATF_TP_ADD_TC(tp, reply_rules);
	ATF_TP_ADD_TC(tp, deny_and_local);
	return (atf_no_error());
}
