/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Page operations without a waiting requester (B1-B5, I11): WRITE_ASYNC
 * from msync, close and the page daemon, bounded per queue by
 * kern.dq.max_inflight_bytes, each with a deadline the queue enforces; the
 * controller going away completes every pending page operation so no
 * munmap or close waits for it; a shrink fails the page operations past
 * the new end.  Runs alone: it changes kern.dq.max_inflight_bytes.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	NPAGES		8
#define	DATA_LEN	(NPAGES * 4096)
#define	MAX_INFLIGHT_BYTES	"kern.dq.max_inflight_bytes"

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

struct fixture {
	struct dqt_ctl	 c;
	struct dqt_object *o;
	int		 backing;
};

static void
setup(struct fixture *f, unsigned seed, int deadline_ms, uint32_t events)
{
	struct dq_policy pol;

	ATF_REQUIRE_EQ(4096, getpagesize());
	dqt_fill(data, sizeof(data), seed);
	f->backing = dqt_make_oracle("backing", data, sizeof(data), path,
	    sizeof(path));
	(void)close(f->backing);
	f->backing = open(path, O_RDWR);
	ATF_REQUIRE(f->backing != -1);
	dqt_init(&f->c);
	dqt_policy_write(&pol);
	pol.dp_mmap_shared_write = DQ_ALLOW;
	pol.dp_deadline_ms = deadline_ms;
	pol.dp_events = events;
	f->o = dqt_mint_backing(&f->c, f->backing, path, &pol,
	    DQ_MINT_F_WRITE);
}

static void
teardown(struct fixture *f)
{

	dqt_fini(&f->c);
	(void)close(f->backing);
}

/* Poll the extended counters until pred holds or ms pass. */
static bool
wait_stats2(struct dqt_ctl *c, bool (*pred)(const struct dq_stats2 *,
    uint64_t), uint64_t arg, int ms, struct dq_stats2 *out)
{
	int64_t deadline;

	deadline = dqt_now_ms() + ms;
	for (;;) {
		dqt_stats2(c, out);
		if (pred(out, arg))
			return (true);
		if (dqt_now_ms() >= deadline)
			return (false);
		dqt_msleep(10);
	}
}

static bool
pred_pending(const struct dq_stats2 *st, uint64_t n)
{

	return (st->ds2_async_pending >= n);
}

static bool
pred_deadlines(const struct dq_stats2 *st, uint64_t n)
{

	return (st->ds2_async_deadlines >= n);
}

static bool
pred_dropped(const struct dq_stats2 *st, uint64_t n)
{

	return (st->ds2_close_dropped >= n);
}

struct dirty_arg {
	struct dqt_sync	 s;
	int		 fd;
	int		 npages;	/* pages dirtied, from page 0 */
	int		 first;		/* first page dirtied */
	int		 again;		/* msync a second time after a post */
	int		 unmap_close;	/* munmap and close, no msync */
};

struct dirty_res {
	int		 sig;
	int		 rv1, err1, rv2, err2;
	int		 unmap, closed;
};

static void
child_dirty(void *arg, void *result)
{
	struct dirty_arg *a = arg;
	struct dirty_res *r = result;
	unsigned char *p;
	int i;

	p = mmap(NULL, DATA_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, a->fd, 0);
	if (p == MAP_FAILED)
		_exit(3);
	/*
	 * Fault every page in while the controller answers (a fault posts a
	 * READ; a stalled controller would leave the fault waiting until its
	 * deadline and SIGBUS).  Then hand over: the test stalls or holds
	 * the controller, and the stores below are soft faults on resident
	 * pages, which post nothing and only dirty them.
	 */
	for (i = 0; i < NPAGES; i++)
		r->sig |= dqt_touch(p + i * 4096, false, 0, NULL);
	dqt_sync_post(a->s.toparent[1]);
	if (!dqt_sync_wait(a->s.tochild[0], 4 * DQT_WAIT_MS))
		_exit(5);
	for (i = a->first; i < a->first + a->npages; i++)
		r->sig |= dqt_touch(p + i * 4096 + 1, true, (unsigned char)i,
		    NULL);
	if (a->unmap_close) {
		r->unmap = munmap(p, DATA_LEN);
		r->closed = close(a->fd);
		return;
	}
	r->rv1 = msync(p, DATA_LEN, MS_SYNC);
	r->err1 = r->rv1 == -1 ? errno : 0;
	if (a->again) {
		dqt_sync_post(a->s.toparent[1]);
		(void)dqt_sync_wait(a->s.tochild[0], 4 * DQT_WAIT_MS);
		r->rv2 = msync(p, DATA_LEN, MS_SYNC);
		r->err2 = r->rv2 == -1 ? errno : 0;
	}
	r->unmap = munmap(p, DATA_LEN);
	r->closed = close(a->fd);
}

/*
 * Start a dirtying requester: it faults its pages in while the controller
 * answers, then the controller is stalled (paused: events stay queued) or
 * holding (events are read and not answered) before the stores.
 */
static void
start_dirty(struct fixture *f, struct dirty_arg *a, struct dqt_child *ch,
    bool hold)
{

	dqt_sync_init(&a->s);
	dqt_spawn(ch, child_dirty, a);
	ATF_REQUIRE_MSG(dqt_sync_wait(a->s.toparent[0], 4 * DQT_WAIT_MS),
	    "the requester did not fault its pages in");
	if (hold)
		dqt_hold(&f->c, true);
	else
		dqt_pause(&f->c);
	dqt_sync_post(a->s.tochild[1]);
}

/* Temporary diagnostics for the VM runs: counters and the ops seen. */
static void
diag(struct fixture *f, const char *where)
{
	struct dq_stats2 st;

	if (f->c.q == -1)
		return;
	dqt_stats2(&f->c, &st);
	dqt_lock(&f->c);
	fprintf(stderr, "diag %s: async_pending %ju async_bytes %ju "
	    "async_deadlines %ju close_dropped %ju interrupts %ju | READ %u "
	    "WRITE_ASYNC %u INTERRUPT %u CLOSE %u held %d\n", where,
	    (uintmax_t)st.ds2_async_pending, (uintmax_t)st.ds2_async_bytes,
	    (uintmax_t)st.ds2_async_deadlines, (uintmax_t)st.ds2_close_dropped,
	    (uintmax_t)st.ds2_interrupts, f->c.events[DQ_OP_READ],
	    f->c.events[DQ_OP_WRITE_ASYNC], f->c.events[DQ_OP_INTERRUPT],
	    f->c.events[DQ_OP_CLOSE], f->c.nheld);
	dqt_unlock(&f->c);
}

static void
check_backing_dirtied(struct fixture *f, int first, int npages)
{
	unsigned char got;
	int i;

	for (i = first; i < first + npages; i++) {
		ATF_REQUIRE_EQ(1, pread(f->backing, &got, 1, i * 4096 + 1));
		ATF_CHECK_EQ_MSG((unsigned char)i, got, "page %d", i);
	}
}

ATF_TC_WITH_CLEANUP(inflight_bytes_bound);
ATF_TC_HEAD(inflight_bytes_bound, tc)
{
	atf_tc_set_md_var(tc, "descr", "with the controller stalled, the "
	    "WRITE_ASYNC bytes pending never exceed kern.dq.max_inflight_bytes "
	    "(the rest waits as dirty pages), the host stays responsive, and "
	    "msync(MS_SYNC) completes with every byte once the controller "
	    "answers");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(inflight_bytes_bound, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_stats2 st;
	struct stat sb;
	int i, status;

	dqt_sysctl_save_set_uint(MAX_INFLIGHT_BYTES, 2 * 4096);

	setup(&f, 1, DQ_DEADLINE_DEFAULT, 0);
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = NPAGES;
	start_dirty(&f, &a, &ch, false);
	if (!wait_stats2(&f.c, pred_pending, 1, DQT_WAIT_MS, &st)) {
		diag(&f, "no async pending");
		atf_tc_fail("no WRITE_ASYNC pending");
	}
	for (i = 0; i < 20; i++) {
		dqt_stats2(&f.c, &st);
		ATF_CHECK_MSG(st.ds2_async_bytes <= 2 * 4096,
		    "async bytes %ju over the bound",
		    (uintmax_t)st.ds2_async_bytes);
		/* The host answers meanwhile. */
		ATF_CHECK_EQ(0, stat(path, &sb));
		dqt_msleep(10);
	}
	dqt_resume(&f.c);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ_MSG(0, r.rv1, "msync: %s", strerror(r.err1));
	check_backing_dirtied(&f, 0, NPAGES);
	teardown(&f);
}
ATF_TC_CLEANUP(inflight_bytes_bound, tc)
{

	(void)dqt_sysctl_restore(MAX_INFLIGHT_BYTES);
}

ATF_TC(deadline_leaves_dirty);
ATF_TC_HEAD(deadline_leaves_dirty, tc)
{
	atf_tc_set_md_var(tc, "descr", "a WRITE_ASYNC that misses its deadline "
	    "fails msync(MS_SYNC) with EIO and is counted in "
	    "ds2_async_deadlines; the page stays dirty and a later msync, "
	    "answered, writes it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deadline_leaves_dirty, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_stats2 st;
	int status;

	setup(&f, 2, 300, 0);
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 1;
	a.first = 2;
	a.again = 1;
	start_dirty(&f, &a, &ch, false);
	/* The first msync came back (EIO by the deadline). */
	ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], 4 * DQT_WAIT_MS));
	if (!wait_stats2(&f.c, pred_deadlines, 1, DQT_WAIT_MS, &st)) {
		diag(&f, "no async deadline");
		ATF_CHECK_MSG(false, "no async deadline counted");
	}
	dqt_resume(&f.c);
	dqt_sync_post(a.s.tochild[1]);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(-1, r.rv1);
	ATF_CHECK_EQ(EIO, r.err1);
	ATF_CHECK_EQ_MSG(0, r.rv2, "second msync: %s", strerror(r.err2));
	check_backing_dirtied(&f, 2, 1);
	teardown(&f);
}

ATF_TC(controller_exit_completes);
ATF_TC_HEAD(controller_exit_completes, tc)
{
	atf_tc_set_md_var(tc, "descr", "I11: with page write-backs pending "
	    "and the controller stalled, closing the queue completes them: "
	    "msync returns (EIO), and munmap and close return");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(controller_exit_completes, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_stats2 st;
	int status;

	setup(&f, 3, 0, 0);	/* no deadline for syscalls; pages get one */
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 2;
	start_dirty(&f, &a, &ch, false);
	if (!wait_stats2(&f.c, pred_pending, 1, DQT_WAIT_MS, &st)) {
		diag(&f, "no async pending");
		atf_tc_fail("no WRITE_ASYNC pending");
	}
	dqt_close_queue(&f.c);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(-1, r.rv1);
	ATF_CHECK_EQ(EIO, r.err1);
	ATF_CHECK_EQ(0, r.unmap);
	ATF_CHECK_EQ(0, r.closed);
	teardown(&f);
}

ATF_TC(close_dropped_counted);
ATF_TC_HEAD(close_dropped_counted, tc)
{
	atf_tc_set_md_var(tc, "descr", "dirty pages whose write-back after the "
	    "last close misses the deadline are dropped and counted in "
	    "ds2_close_dropped; munmap and close returned at once");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_dropped_counted, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_stats2 st;
	int status;

	setup(&f, 4, 300, 0);
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 1;
	a.unmap_close = 1;
	start_dirty(&f, &a, &ch, false);
	(void)close(f.o->fd);
	f.o->fd = -1;
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(0, r.unmap);
	ATF_CHECK_EQ(0, r.closed);
	if (!wait_stats2(&f.c, pred_dropped, 1, 4 * DQT_WAIT_MS, &st)) {
		diag(&f, "nothing dropped");
		ATF_CHECK_MSG(false, "ds2_close_dropped stayed 0");
	}
	ATF_CHECK(st.ds2_async_deadlines >= 1);
	dqt_resume(&f.c);
	teardown(&f);
}

ATF_TC(shrink_fails_pending);
ATF_TC_HEAD(shrink_fails_pending, tc)
{
	atf_tc_set_md_var(tc, "descr", "a SETIDENT that shrinks the file below "
	    "a delivered WRITE_ASYNC fails it: the controller's late reply is "
	    "ESRCH, an INTERRUPT names it, and the writer's msync returns");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shrink_fails_pending, tc)
{
	struct fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_ident_file *id;
	uint32_t op;
	int status;

	setup(&f, 5, DQ_DEADLINE_DEFAULT, 0);
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 1;
	a.first = NPAGES - 1;
	start_dirty(&f, &a, &ch, true);
	if (!dqt_wait_held(&f.c, 1, DQT_WAIT_MS)) {
		diag(&f, "nothing held");
		atf_tc_fail("no event held");
	}
	dqt_lock(&f.c);
	op = f.c.held[0].op;
	dqt_unlock(&f.c);
	if (op != DQ_OP_WRITE_ASYNC)
		diag(&f, "first held");
	dqt_lock(&f.c);
	ATF_REQUIRE_EQ(DQ_OP_WRITE_ASYNC, f.c.held[0].op);
	ATF_CHECK_EQ((NPAGES - 1) * 4096, f.c.held[0].offset);
	dqt_unlock(&f.c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	*id = f.o->ident;
	id->di_size = 4096;
	ATF_REQUIRE_EQ(0, dq_set_ident(f.c.q, f.o->id, id));
	free(id);
	errno = 0;
	dqt_lock(&f.c);
	ATF_CHECK_EQ(-1, dq_reply_write(f.c.q, f.c.held[0].id,
	    f.c.held[0].len, f.c.held[0].offset));
	dqt_unlock(&f.c);
	ATF_CHECK_EQ(ESRCH, errno);
	ATF_CHECK(dqt_wait_interrupts(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(f.c.held[0].id, f.c.interrupted[0]);
	dqt_unlock(&f.c);
	dqt_hold(&f.c, false);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, inflight_bytes_bound);
	ATF_TP_ADD_TC(tp, deadline_leaves_dirty);
	ATF_TP_ADD_TC(tp, controller_exit_completes);
	ATF_TP_ADD_TC(tp, close_dropped_counted);
	ATF_TP_ADD_TC(tp, shrink_fails_pending);
	return (atf_no_error());
}
