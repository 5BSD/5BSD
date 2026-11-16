/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * kqueue notes (D100, B7): the kernel raises EVFILT_VNODE notes on a served
 * object's own operations as the VOP post hooks do (READ, WRITE/EXTEND,
 * ATTRIB, REVOKE), NOTE_OPEN and NOTE_CLOSE/CLOSE_WRITE on the other objects
 * of the same identity (di_dev, di_ino) on the same queue, and the
 * controller pushes the rest with DQ_IOC_PUSH.  The watcher is a kqueue in
 * the controller process (registering posts nothing); the operations run in
 * forked requesters.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	4096

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

#define	ALL_NOTES	(NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | \
	NOTE_LINK | NOTE_RENAME | NOTE_REVOKE | NOTE_OPEN | NOTE_CLOSE | \
	NOTE_CLOSE_WRITE | NOTE_READ)

static int
watch(int fd)
{
	struct kevent kev;
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, ALL_NOTES, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	return (kq);
}

/* The notes that arrived within ms, accumulated. */
static u_int
notes(int kq, int ms)
{
	struct kevent kev;
	struct timespec ts;
	u_int got;

	got = 0;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	while (kevent(kq, NULL, 0, &kev, 1, &ts) == 1) {
		got |= kev.fflags;
		ts.tv_sec = 0;
		ts.tv_nsec = 50 * 1000000L;
	}
	return (got);
}

/*
 * Nothing arrived but the fence: a note pushed to o now.  The kqueue is
 * EV_CLEAR and accumulates; a note raised before the push is reported
 * with it.
 */
static u_int
notes_fenced(int kq, struct dqt_ctl *c, struct dqt_object *o)
{

	ATF_REQUIRE_EQ(0, dq_push_vnode_note(c->q, o->id, NOTE_ATTRIB));
	return (notes(kq, 500));
}

static int backing;

static struct dqt_object *
setup(struct dqt_ctl *c, unsigned seed)
{

	dqt_fill(data, sizeof(data), seed);
	backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(backing);
	backing = open(path, O_RDWR);
	ATF_REQUIRE(backing != -1);
	dqt_init(c);
	return (dqt_mint_backing(c, backing, path, NULL, DQ_MINT_F_WRITE));
}

static void
teardown(struct dqt_ctl *c)
{

	dqt_fini(c);
	(void)close(backing);
}

enum op { OP_READ, OP_WRITE_IN, OP_WRITE_EXTEND, OP_FCHMOD, OP_TRUNCATE,
    OP_FALLOCATE, OP_FSPACECTL };

struct op_arg {
	int		 fd;
	enum op		 op;
};

static void
child_op(void *arg, void *result)
{
	struct op_arg *a = arg;
	struct dqt_rr *r = result;
	struct spacectl_range rq;
	char buf[16];

	memset(buf, 'n', sizeof(buf));
	switch (a->op) {
	case OP_READ:
		r->rv = pread(a->fd, buf, sizeof(buf), 0);
		break;
	case OP_WRITE_IN:
		r->rv = pwrite(a->fd, buf, sizeof(buf), 0);
		break;
	case OP_WRITE_EXTEND:
		r->rv = pwrite(a->fd, buf, sizeof(buf), DATA_LEN * 4);
		break;
	case OP_FCHMOD:
		r->rv = fchmod(a->fd, 0600);
		break;
	case OP_TRUNCATE:
		r->rv = ftruncate(a->fd, 10);
		break;
	case OP_FALLOCATE:
		r->err = posix_fallocate(a->fd, 0, DATA_LEN * 8);
		r->rv = r->err == 0 ? 0 : -1;
		return;
	case OP_FSPACECTL:
		rq.r_offset = 0;
		rq.r_len = 16;
		r->rv = fspacectl(a->fd, SPACECTL_DEALLOC, &rq, 0, NULL);
		break;
	}
	r->err = r->rv == -1 ? errno : 0;
}

static u_int
run_op(struct dqt_object *o, int kq, enum op op, struct dqt_rr *r)
{
	struct op_arg a;

	a.fd = o->fd;
	a.op = op;
	memset(r, 0, sizeof(*r));
	dqt_run_child(child_op, &a, r, sizeof(*r));
	return (notes(kq, 500));
}

ATF_TC(kernel_raised);
ATF_TC_HEAD(kernel_raised, tc)
{
	atf_tc_set_md_var(tc, "descr", "READ raises NOTE_READ; a write inside "
	    "the file NOTE_WRITE, past it NOTE_WRITE|NOTE_EXTEND; fchmod and "
	    "ftruncate NOTE_ATTRIB; a growing fallocate NOTE_WRITE|EXTEND; "
	    "fspacectl NOTE_WRITE; SETIDENT NOTE_ATTRIB; revoke NOTE_REVOKE "
	    "with EV_EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kernel_raised, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqt_rr r;
	struct kevent kev;
	struct timespec ts = { 1, 0 };
	u_int got;
	int kq;

	o = setup(&c, 1);
	kq = watch(o->fd);
	ATF_CHECK_EQ(NOTE_READ, run_op(o, kq, OP_READ, &r));
	ATF_CHECK_EQ(NOTE_WRITE, run_op(o, kq, OP_WRITE_IN, &r));
	ATF_CHECK_EQ(NOTE_WRITE | NOTE_EXTEND,
	    run_op(o, kq, OP_WRITE_EXTEND, &r));
	got = run_op(o, kq, OP_FCHMOD, &r);
	ATF_CHECK((got & NOTE_ATTRIB) != 0);
	got = run_op(o, kq, OP_TRUNCATE, &r);
	ATF_CHECK((got & NOTE_ATTRIB) != 0);
	got = run_op(o, kq, OP_FALLOCATE, &r);
	if (r.rv == 0)
		ATF_CHECK_EQ(NOTE_WRITE | NOTE_EXTEND, got & ~NOTE_ATTRIB);
	else
		ATF_CHECK_EQ(0, got & (NOTE_WRITE | NOTE_EXTEND));
	got = run_op(o, kq, OP_FSPACECTL, &r);
	if (r.rv == 0)
		ATF_CHECK((got & NOTE_WRITE) != 0);
	ATF_REQUIRE_EQ(0, dq_set_ident(c.q, o->id, &o->ident));
	ATF_CHECK_EQ(NOTE_ATTRIB, notes(kq, 500));
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &ts));
	ATF_CHECK((kev.fflags & NOTE_REVOKE) != 0);
	ATF_CHECK((kev.flags & EV_EOF) != 0);
	(void)close(kq);
	teardown(&c);
}

ATF_TC(siblings);
ATF_TC_HEAD(siblings, tc)
{
	atf_tc_set_md_var(tc, "descr", "NOTE_OPEN at a mint and NOTE_CLOSE / "
	    "NOTE_CLOSE_WRITE (by the closing descriptor's FWRITE) at a last "
	    "close reach the other objects of the same (di_dev, di_ino) on the "
	    "same queue, and nothing else: not another identity, not another "
	    "queue");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(siblings, tc)
{
	struct dqt_ctl c, c2;
	struct dqt_object *o, *ro, *rw, *other, *far;
	struct dq_ident_file *id;
	struct dq_policy pol;
	int kq;

	o = setup(&c, 2);
	kq = watch(o->fd);
	dqt_policy_write(&pol);
	ro = dqt_mint_ident(&c, &o->ident, &pol, data, sizeof(data));
	ATF_CHECK_EQ(NOTE_OPEN, notes(kq, 500));
	(void)close(ro->fd);
	ro->fd = -1;
	ATF_CHECK_EQ(NOTE_CLOSE, notes(kq, 500));
	rw = dqt_mint_ident_flags(&c, &o->ident, &pol, DQ_MINT_F_WRITE, data,
	    sizeof(data));
	ATF_CHECK_EQ(NOTE_OPEN, notes(kq, 500));
	(void)close(rw->fd);
	rw->fd = -1;
	ATF_CHECK_EQ(NOTE_CLOSE_WRITE, notes(kq, 500));

	/* Another identity on the same queue: nothing. */
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	*id = o->ident;
	id->di_ino++;
	other = dqt_mint_ident(&c, id, &pol, data, sizeof(data));
	(void)close(other->fd);
	other->fd = -1;
	ATF_CHECK_EQ(NOTE_ATTRIB, notes_fenced(kq, &c, o));
	/* The same identity on another queue: nothing. */
	dqt_init(&c2);
	far = dqt_mint_ident(&c2, &o->ident, &pol, data, sizeof(data));
	(void)close(far->fd);
	far->fd = -1;
	ATF_CHECK_EQ(NOTE_ATTRIB, notes_fenced(kq, &c, o));
	dqt_fini(&c2);
	free(id);
	(void)close(kq);
	teardown(&c);
}

ATF_TC(pushed);
ATF_TC_HEAD(pushed, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_PUSH NOTIFY_VNODE raises each "
	    "accepted note (DELETE, WRITE, EXTEND, ATTRIB, LINK, RENAME, OPEN, "
	    "CLOSE, CLOSE_WRITE, READ) and a combination; ds2_pushes counts "
	    "them");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pushed, tc)
{
	static const u_int each[] = { NOTE_DELETE, NOTE_WRITE, NOTE_EXTEND,
	    NOTE_ATTRIB, NOTE_LINK, NOTE_RENAME, NOTE_OPEN, NOTE_CLOSE,
	    NOTE_CLOSE_WRITE, NOTE_READ, NOTE_WRITE | NOTE_EXTEND };
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_stats2 st;
	size_t i;
	int kq;

	o = setup(&c, 3);
	kq = watch(o->fd);
	for (i = 0; i < nitems(each); i++) {
		ATF_REQUIRE_MSG(dq_push_vnode_note(c.q, o->id, each[i]) == 0,
		    "push %#x: %s", each[i], strerror(errno));
		ATF_CHECK_EQ_MSG(each[i], notes(kq, 300), "note %#x", each[i]);
	}
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(nitems(each), st.ds2_pushes);
	/* Nothing reached the controller as an event. */
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	(void)close(kq);
	teardown(&c);
}

ATF_TC(push_refusals);
ATF_TC_HEAD(push_refusals, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_PUSH refuses note 0, "
	    "NOTE_REVOKE (the REVOKE ioctl's), an unknown bit, a wrong "
	    "version, nonzero padding and an unknown or 1b-ii op with EINVAL, "
	    "an unknown object with ESRCH; none is counted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(push_refusals, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_push_args pa;
	struct dq_stats2 st;
	int kq;

	o = setup(&c, 4);
	kq = watch(o->fd);
#define	REFUSED(call, want) do {					\
	errno = 0;							\
	ATF_CHECK_EQ(-1, (call));					\
	ATF_CHECK_EQ_MSG(want, errno, "%s: errno %d", #call, errno);	\
} while (0)
	REFUSED(dq_push_vnode_note(c.q, o->id, 0), EINVAL);
	REFUSED(dq_push_vnode_note(c.q, o->id, NOTE_REVOKE), EINVAL);
	REFUSED(dq_push_vnode_note(c.q, o->id, NOTE_WRITE | NOTE_REVOKE),
	    EINVAL);
	REFUSED(dq_push_vnode_note(c.q, o->id, 0x80000000u), EINVAL);
	REFUSED(dq_push_vnode_note(c.q, o->id + 1000, NOTE_WRITE), ESRCH);
	memset(&pa, 0, sizeof(pa));
	pa.dp_version = DQ_API_VERSION + 1;
	pa.dp_op = DQ_PUSH_NOTIFY_VNODE;
	pa.dp_object = o->id;
	pa.dp_note = NOTE_WRITE;
	REFUSED(ioctl(c.q, DQ_IOC_PUSH, &pa), EINVAL);
	pa.dp_version = DQ_API_VERSION;
	pa.dp_pad0 = 1;
	REFUSED(ioctl(c.q, DQ_IOC_PUSH, &pa), EINVAL);
	pa.dp_pad0 = 0;
	pa.dp_op = DQ_PUSH_INVALIDATE;
	REFUSED(ioctl(c.q, DQ_IOC_PUSH, &pa), EINVAL);
	pa.dp_op = 99;
	REFUSED(ioctl(c.q, DQ_IOC_PUSH, &pa), EINVAL);
#undef REFUSED
	ATF_CHECK_EQ(NOTE_ATTRIB, notes_fenced(kq, &c, o));
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(1, st.ds2_pushes);		/* the fence's */
	/* An observer cannot push: its ioctl set is the stats commands. */
	{
		int obs = dq_mint_observer(c.q, 0);

		ATF_REQUIRE(obs != -1);
		errno = 0;
		ATF_CHECK_EQ(-1, dq_push_vnode_note(obs, o->id, NOTE_WRITE));
		ATF_CHECK_EQ(ENOTCAPABLE, errno);
		(void)close(obs);
	}
	(void)close(kq);
	teardown(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kernel_raised);
	ATF_TP_ADD_TC(tp, siblings);
	ATF_TP_ADD_TC(tp, pushed);
	ATF_TP_ADD_TC(tp, push_refusals);
	return (atf_no_error());
}
