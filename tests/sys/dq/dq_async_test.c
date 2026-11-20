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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	NPAGES		8
#define	DATA_LEN	(NPAGES * 4096)
#define	MAX_INFLIGHT_BYTES	"kern.dq.max_inflight_bytes"

static unsigned char data[DATA_LEN];
static char path[DQT_PATH_MAX];

static void
setup(struct dqt_fixture *f, unsigned seed, int deadline_ms, uint32_t events)
{
	struct dq_policy pol;

	ATF_REQUIRE_EQ(4096, getpagesize());
	dqt_fill(data, sizeof(data), seed);
	dqt_policy_write(&pol);
	pol.dp_mmap_shared_write = DQ_ALLOW;
	pol.dp_deadline_ms = deadline_ms;
	pol.dp_events = events;
	dqt_fixture_init(f, data, sizeof(data), path, NULL, &pol,
	    DQ_MINT_F_WRITE);
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
start_dirty(struct dqt_fixture *f, struct dirty_arg *a, struct dqt_child *ch,
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
diag(struct dqt_fixture *f, const char *where)
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
check_backing_dirtied(struct dqt_fixture *f, int first, int npages)
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
	struct dqt_fixture f;
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
	dqt_fixture_fini(&f);
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
	struct dqt_fixture f;
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
	dqt_fixture_fini(&f);
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
	struct dqt_fixture f;
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
	dqt_fixture_fini(&f);
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
	struct dqt_fixture f;
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
	dqt_fixture_fini(&f);
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
	struct dqt_fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_ident_file *id;
	uint32_t op;
	int error, rv, status;

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
	rv = dq_reply_write(f.c.q, f.c.held[0].id, f.c.held[0].len,
	    f.c.held[0].offset);
	error = errno;		/* before the unlock can change it */
	dqt_unlock(&f.c);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ESRCH, error);
	ATF_CHECK(dqt_wait_interrupts(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(f.c.held[0].id, f.c.interrupted[0]);
	dqt_unlock(&f.c);
	dqt_hold(&f.c, false);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	dqt_fixture_fini(&f);
}

/*
 * A full queue refuses msync's write-back AGAIN; msync then sleeps for a
 * room event ("dqroom", dq_async_wait), with no timer but the page
 * deadline.  The object's page deadline here is far past the case's
 * timeout, so a wait that only the deadline ends shows as the case timing
 * out.  The one slot is taken by a read of a second object with no
 * deadline, left unread (the controller paused).
 */
#define	LONG_DEADLINE_MS	600000	/* past every case timeout here */
#define	DROP_WAKEUP		"debug.dq.drop_wakeup"
#define	WAKEUPS_DROPPED		"debug.dq.wakeups_dropped"
#define	WAKE_ASYNC_ROOM		0x0100	/* DQ_WAKE_* of dq_var.h */
#define	WAKE_DESTROY		0x0200

struct fill_res {
	ssize_t	rv;
	int	err;
};

static void
child_fill_read(void *arg, void *result)
{
	struct fill_res *r = result;
	char buf[16];

	r->rv = pread(*(int *)arg, buf, sizeof(buf), 0);
	r->err = r->rv == -1 ? errno : 0;
}

static bool
posted_reach(const struct dq_stats *st, uintptr_t n)
{

	return (st->ds_events_posted >= n);
}

/*
 * The writer's msync asleep in "dqroom" behind the filler's read; the
 * controller paused.  fillfd is the second object's descriptor.
 */
static void
room_setup(struct dqt_fixture *f, unsigned seed, struct dirty_arg *a,
    struct dqt_child *ch, struct dqt_child *chf, int *fillfd)
{
	struct dqt_object *fo;
	struct dq_policy pol;
	struct dq_stats st;

	setup(f, seed, LONG_DEADLINE_MS, 0);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	fo = dqt_mint_backing(&f->c, f->backing, path, &pol, 0);
	*fillfd = fo->fd;
	memset(a, 0, sizeof(*a));
	a->fd = f->o->fd;
	a->npages = 1;
	dqt_sync_init(&a->s);
	dqt_spawn(ch, child_dirty, a);
	ATF_REQUIRE_MSG(dqt_sync_wait(a->s.toparent[0], 4 * DQT_WAIT_MS),
	    "the requester did not fault its pages in");
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(f->c.q, 1));
	dqt_pause(&f->c);
	dqt_stats(&f->c, &st);
	dqt_spawn(chf, child_fill_read, fillfd);
	ATF_REQUIRE(dqt_wait_stats(&f->c, posted_reach,
	    st.ds_events_posted + 1, DQT_WAIT_MS));
	dqt_sync_post(a->s.tochild[1]);
	ATF_REQUIRE_MSG(dqt_wait_wmesg(ch->pid, "dqroom", DQT_WAIT_MS),
	    "msync did not wait for room");
}

static void
room_finish(struct dqt_fixture *f, struct dqt_child *ch)
{
	struct dirty_res r;
	int status;

	status = dqt_wait(ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ_MSG(0, r.rv1, "msync: %s", strerror(r.err1));
	check_backing_dirtied(f, 0, 1);
	dqt_fixture_fini(f);
}

ATF_TC(msync_again_full);
ATF_TC_HEAD(msync_again_full, tc)
{
	atf_tc_set_md_var(tc, "descr", "msync(MS_SYNC) refused AGAIN by a "
	    "full queue sleeps until the slot frees, then writes the page "
	    "back (the room event ends its wait, not the page deadline)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(msync_again_full, tc)
{
	struct dirty_arg a;
	struct dqt_fixture f;
	struct dqt_child ch, chf;
	struct fill_res fr;
	int fillfd;

	room_setup(&f, 11, &a, &ch, &chf, &fillfd);
	dqt_resume(&f.c);
	dqt_collect(&chf, &fr, sizeof(fr));
	ATF_CHECK_EQ(16, fr.rv);
	room_finish(&f, &ch);
}

ATF_TC(msync_depth_rise);
ATF_TC_HEAD(msync_depth_rise, tc)
{
	atf_tc_set_md_var(tc, "descr", "msync(MS_SYNC) refused AGAIN by a "
	    "full queue posts its write-back as soon as the controller raises "
	    "the depth (a room event), with the slot still taken");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(msync_depth_rise, tc)
{
	struct dirty_arg a;
	struct dqt_fixture f;
	struct dqt_child ch, chf;
	struct dq_stats2 st;
	struct fill_res fr;
	int fillfd;

	room_setup(&f, 12, &a, &ch, &chf, &fillfd);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(f.c.q, 2));
	/*
	 * Still paused: the write-back is posted beside the filler.  The
	 * case's timeout is the hang detector.
	 */
	ATF_REQUIRE(wait_stats2(&f.c, pred_pending, 1, INT_MAX, &st));
	dqt_resume(&f.c);
	dqt_collect(&chf, &fr, sizeof(fr));
	ATF_CHECK_EQ(16, fr.rv);
	room_finish(&f, &ch);
}

ATF_TC(msync_revoke_room);
ATF_TC_HEAD(msync_revoke_room, tc)
{
	atf_tc_set_md_var(tc, "descr", "msync(MS_SYNC) waiting for room ends "
	    "when its object is revoked (the revoke is a room event), not at "
	    "the page deadline");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(msync_revoke_room, tc)
{
	struct dirty_arg a;
	struct dqt_fixture f;
	struct dqt_child ch, chf;
	struct dirty_res r;
	struct fill_res fr;
	int fillfd, status;

	room_setup(&f, 13, &a, &ch, &chf, &fillfd);
	ATF_REQUIRE_EQ(0, dq_revoke(f.c.q, f.o->id));
	/* Still paused; the case's timeout is the hang detector. */
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(-1, r.rv1);
	ATF_CHECK_EQ(EIO, r.err1);
	dqt_resume(&f.c);
	dqt_collect(&chf, &fr, sizeof(fr));
	ATF_CHECK_EQ(16, fr.rv);
	dqt_fixture_fini(&f);
}

static u_long
wakeups_dropped(void)
{
	u_long n;
	size_t len;

	len = sizeof(n);
	ATF_REQUIRE_MSG(sysctlbyname(WAKEUPS_DROPPED, &n, &len, NULL, 0) == 0,
	    "%s: %s", WAKEUPS_DROPPED, strerror(errno));
	return (n);
}

ATF_TC_WITH_CLEANUP(wake_async_room);
ATF_TC_HEAD(wake_async_room, tc)
{
	atf_tc_set_md_var(tc, "descr", "msync(MS_SYNC) waiting for room ends "
	    "only by the room event's wakeup: with it dropped, the freed slot "
	    "leaves msync asleep (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(wake_async_room, tc)
{
	struct dirty_arg a;
	struct dqt_fixture f;
	struct dqt_child ch, chf;
	struct fill_res fr;
	u_long before;
	int fillfd;

	dqt_require_fault_knob(DROP_WAKEUP);
	room_setup(&f, 14, &a, &ch, &chf, &fillfd);
	before = wakeups_dropped();
	dqt_sysctl_save_set_uint(DROP_WAKEUP, WAKE_ASYNC_ROOM);
	dqt_resume(&f.c);
	/* The slot was read off (the dropped room event) before the answer. */
	dqt_collect(&chf, &fr, sizeof(fr));
	ATF_CHECK_EQ(16, fr.rv);
	ATF_CHECK(wakeups_dropped() > before);
	ATF_CHECK_MSG(dqt_wait_wmesg(ch.pid, "dqroom", 0), "msync left "
	    "\"dqroom\" with the room event's wakeup dropped: something polls "
	    "or another wakeup reached it");
	ATF_REQUIRE(dqt_sysctl_restore(DROP_WAKEUP));
	/* The release: a depth raise is a room event too. */
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(f.c.q, 2));
	room_finish(&f, &ch);
}
ATF_TC_CLEANUP(wake_async_room, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TC(close_destroy_deadline);
ATF_TC_HEAD(close_destroy_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "a dirty page whose write-back after "
	    "the last close a full queue refuses is dropped and counted at the "
	    "page deadline (the destroy task's one timeout), with no "
	    "write-back posted");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_destroy_deadline, tc)
{
	struct dqt_fixture f;
	struct dqt_object *fo;
	struct dqt_child ch, chf;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_policy pol;
	struct dq_stats2 st;
	struct dq_stats st1;
	struct fill_res fr;
	int fillfd, status;

	setup(&f, 15, 300, 0);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	fo = dqt_mint_backing(&f.c, f.backing, path, &pol, 0);
	fillfd = fo->fd;
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 1;
	a.unmap_close = 1;
	dqt_sync_init(&a.s);
	dqt_spawn(&ch, child_dirty, &a);
	ATF_REQUIRE_MSG(dqt_sync_wait(a.s.toparent[0], 4 * DQT_WAIT_MS),
	    "the requester did not fault its pages in");
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(f.c.q, 1));
	dqt_pause(&f.c);
	dqt_stats(&f.c, &st1);
	dqt_spawn(&chf, child_fill_read, &fillfd);
	ATF_REQUIRE(dqt_wait_stats(&f.c, posted_reach,
	    st1.ds_events_posted + 1, DQT_WAIT_MS));
	(void)close(f.o->fd);
	f.o->fd = -1;
	dqt_sync_post(a.s.tochild[1]);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.sig, "signal %d in the requester", r.sig);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(0, r.unmap);
	ATF_CHECK_EQ(0, r.closed);
	/* The case's timeout is the hang detector. */
	ATF_REQUIRE(wait_stats2(&f.c, pred_dropped, 1, INT_MAX, &st));
	ATF_CHECK_EQ_MSG(0, st.ds2_async_deadlines, "a write-back was "
	    "posted and missed its deadline: the queue was not full");
	dqt_resume(&f.c);
	dqt_collect(&chf, &fr, sizeof(fr));
	ATF_CHECK_EQ(16, fr.rv);
	dqt_fixture_fini(&f);
}

ATF_TC_WITH_CLEANUP(wake_destroy);
ATF_TC_HEAD(wake_destroy, tc)
{
	atf_tc_set_md_var(tc, "descr", "the destroy task of a closed object "
	    "waiting for its write-back runs again only by the completion's "
	    "kick: with it dropped, the object stays until another kick (no "
	    "polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_destroy, tc)
{
	struct dqt_fixture f;
	struct dqt_child ch;
	struct dirty_arg a;
	struct dirty_res r;
	struct dq_stats st;
	struct dqt_held h;
	u_long before;
	int status;

	dqt_require_fault_knob(DROP_WAKEUP);
	setup(&f, 16, DQ_DEADLINE_DEFAULT, DQ_EVENTS_CLOSE);
	memset(&a, 0, sizeof(a));
	a.fd = f.o->fd;
	a.npages = 1;
	a.unmap_close = 1;
	start_dirty(&f, &a, &ch, true);
	(void)close(f.o->fd);
	f.o->fd = -1;
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* The destroy task's write-back, held. */
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	dqt_lock(&f.c);
	h = f.c.held[0];
	dqt_unlock(&f.c);
	ATF_REQUIRE_EQ(DQ_OP_WRITE_ASYNC, h.op);
	before = wakeups_dropped();
	dqt_sysctl_save_set_uint(DROP_WAKEUP, WAKE_DESTROY);
	ATF_REQUIRE_EQ(0, dq_reply_write(f.c.q, h.id, h.len, h.offset));
	/*
	 * The completion runs on a task: until it dropped its kick, then
	 * one look that the object is still there (live, no CLOSE).  The
	 * case's timeout is the hang detector.
	 */
	while (wakeups_dropped() <= before)
		dqt_msleep(1);
	dqt_stats(&f.c, &st);
	ATF_CHECK_EQ_MSG(1, st.ds_objects_live, "the object went with the "
	    "completion's kick dropped: something polls or another kick "
	    "reached the task");
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, f.c.events[DQ_OP_CLOSE]);
	dqt_unlock(&f.c);
	ATF_REQUIRE(dqt_sysctl_restore(DROP_WAKEUP));
	/* The release: a revoke holds and drops the pager, a kick. */
	ATF_REQUIRE_EQ(0, dq_revoke(f.c.q, f.o->id));
	dqt_hold(&f.c, false);
	dqt_fixture_fini(&f);
}
ATF_TC_CLEANUP(wake_destroy, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, inflight_bytes_bound);
	ATF_TP_ADD_TC(tp, deadline_leaves_dirty);
	ATF_TP_ADD_TC(tp, controller_exit_completes);
	ATF_TP_ADD_TC(tp, close_dropped_counted);
	ATF_TP_ADD_TC(tp, shrink_fails_pending);
	ATF_TP_ADD_TC(tp, msync_again_full);
	ATF_TP_ADD_TC(tp, msync_depth_rise);
	ATF_TP_ADD_TC(tp, msync_revoke_room);
	ATF_TP_ADD_TC(tp, wake_async_room);
	ATF_TP_ADD_TC(tp, close_destroy_deadline);
	ATF_TP_ADD_TC(tp, wake_destroy);
	return (atf_no_error());
}
