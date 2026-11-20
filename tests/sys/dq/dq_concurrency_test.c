/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Concurrency: replies in any order, interruption, a full queue, the
 * EDEADLK rule, the per-object in-flight bound, two queue readers, and a
 * fault in the controller's read buffer.  The in-flight bound case changes
 * kern.dq.max_inflight_per_object, so the program is exclusive.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

#define	DATA_LEN	65536
#define	NTHREADS	8

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

static const char inflight_sysctl[] = "kern.dq.max_inflight_per_object";

/* Stats predicates for dqt_wait_stats: no fixed sleeps on a loaded guest. */
static bool
posted_or_dropped_is(const struct dq_stats *st, uintptr_t n)
{

	return (st->ds_events_posted + st->ds_events_dropped >= (uint64_t)n);
}

static bool
inflight_is_zero(const struct dq_stats *st, uintptr_t unused __unused)
{

	return (st->ds_inflight == 0 && st->ds_queue_current == 0);
}

struct thr_arg {
	int		 fd;
	off_t		 offset;
	size_t		 len;
	int		 rounds;
	long		 rv;
	int		 err;
	uint64_t	 hash;
};

static void *
pread_thread(void *arg)
{
	struct thr_arg *t = arg;
	unsigned char *buf;
	int i;

	buf = malloc(t->len);
	for (i = 0; i < t->rounds; i++) {
		t->rv = pread(t->fd, buf, t->len, t->offset);
		t->err = t->rv == -1 ? errno : 0;
		if (t->rv > 0)
			t->hash = dqt_digest(buf, (size_t)t->rv);
	}
	free(buf);
	return (NULL);
}

struct threads_arg {
	int		 fd;
	size_t		 len;
	int		 rounds;
};

struct threads_res {
	long		 rv[NTHREADS];
	int		 err[NTHREADS];
	uint64_t	 hash[NTHREADS];
};

/* NTHREADS threads, each reading its own slice. */
static void
child_threads(void *arg, void *result)
{
	struct threads_arg *a = arg;
	struct threads_res *r = result;
	struct thr_arg t[NTHREADS];
	pthread_t thr[NTHREADS];
	int i;

	for (i = 0; i < NTHREADS; i++) {
		memset(&t[i], 0, sizeof(t[i]));
		t[i].fd = a->fd;
		t[i].offset = (off_t)i * (DATA_LEN / NTHREADS);
		t[i].len = a->len;
		t[i].rounds = a->rounds;
		pthread_create(&thr[i], NULL, pread_thread, &t[i]);
	}
	for (i = 0; i < NTHREADS; i++) {
		pthread_join(thr[i], NULL);
		r->rv[i] = t[i].rv;
		r->err[i] = t[i].err;
		r->hash[i] = t[i].hash;
	}
}

/* The default policy with DQ_PF_INTR: waits end on a signal (D192). */
static struct dq_policy *
policy_intr(struct dq_policy *pol)
{

	dq_policy_default(pol);
	pol->dp_flags = DQ_PF_INTR;
	return (pol);
}

/* Rounds of a race before it is reported as not exercised. */
#define	RACE_ROUNDS_MAX	200
/* The bounds of reply_racing_signal's adaptive timer. */
#define	RACE_TIMER_MIN_US	100
#define	RACE_TIMER_MAX_US	100000

struct one_read_arg {
	int		 fd;
	size_t		 len;
	int		 alarm_us;	/* 0: no timer */
	bool		 catch_alrm;	/* catch SIGALRM, no SA_RESTART */
};

struct one_read_res {
	struct dqt_rr	 rr;
	int		 signals;
};

static volatile sig_atomic_t signals_seen;

static void
on_signal(int sig __unused)
{

	signals_seen++;
}

/* read(2) once, with an optional SIGALRM (no SA_RESTART) on the way. */
static void
child_one_read(void *arg, void *result)
{
	struct one_read_arg *a = arg;
	struct one_read_res *r = result;
	struct sigaction sa;
	struct itimerval it;
	unsigned char buf[4096];

	if (a->alarm_us != 0 || a->catch_alrm) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_signal;
		sigaction(SIGALRM, &sa, NULL);
	}
	if (a->alarm_us != 0) {
		memset(&it, 0, sizeof(it));
		it.it_value.tv_sec = a->alarm_us / 1000000;
		it.it_value.tv_usec = a->alarm_us % 1000000;
		setitimer(ITIMER_REAL, &it, NULL);
	}
	r->rr.rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->rr.err = r->rr.rv == -1 ? errno : 0;
	r->signals = signals_seen;
}

/*
 * pread(2) at offset 0: positional (FOF_OFFSET), so several requesters on
 * the one inherited struct file do not serialize in foffset_lock_uio before
 * posting, which read(2) does exactly as on a real file (design 9).
 */
static void
child_one_pread(void *arg, void *result)
{
	struct one_read_arg *a = arg;
	struct one_read_res *r = result;
	unsigned char buf[4096];

	r->rr.rv = pread(a->fd, buf, MIN(a->len, sizeof(buf)), 0);
	r->rr.err = r->rr.rv == -1 ? errno : 0;
	r->signals = 0;
}

ATF_TC(threads_replies_reversed);
ATF_TC_HEAD(threads_replies_reversed, tc)
{
	atf_tc_set_md_var(tc, "descr", "eight threads pread at once and the "
	    "controller answers each batch last first: every thread gets its "
	    "own bytes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(threads_replies_reversed, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct threads_arg a;
	struct threads_res r;
	struct dqt_child ch;
	int i, oracle;

	dqt_fill(data, sizeof(data), 61);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dqt_set_order(&c, DQT_ORDER_REVERSE);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	/* Pause so the eight events pile up into one batch. */
	dqt_pause(&c);
	a.fd = o->fd;
	a.len = 4096;
	a.rounds = 1;
	dqt_spawn(&ch, child_threads, &a);
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, NTHREADS, DQT_WAIT_MS));
	dqt_resume(&c);
	dqt_collect(&ch, &r, sizeof(r));
	for (i = 0; i < NTHREADS; i++) {
		ATF_CHECK_EQ_MSG(4096, r.rv[i], "thread %d: %ld (errno %d)", i,
		    r.rv[i], r.err[i]);
		ATF_CHECK_EQ_MSG(dqt_digest(data + i * (DATA_LEN / NTHREADS), 4096),
		    r.hash[i], "thread %d got the wrong bytes", i);
	}
	dqt_lock(&c);
	ATF_CHECK_EQ(NTHREADS, c.events[DQ_OP_READ]);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(sigalrm_read_intr);
ATF_TC_HEAD(sigalrm_read_intr, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal during a delivered READ of a "
	    "DQ_PF_INTR object: the requester gets EINTR, the controller an "
	    "INTERRUPT record, and its late reply ESRCH (an NFS intr mount)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sigalrm_read_intr, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct one_read_arg a;
	struct one_read_res r;
	struct dq_stats st;
	struct dqt_child ch;
	int oracle;

	dqt_fill(data, sizeof(data), 62);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data),
	    policy_intr(&pol));
	dqt_hold(&c, true);

	/*
	 * The signal is sent once the controller holds the READ: the read
	 * is then delivered and waiting, whatever the machine's load (a
	 * timer could fire before the delivery and test nothing).
	 */
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	a.catch_alrm = true;
	dqt_spawn(&ch, child_one_read, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch.pid, DQT_WMESG_REPLY, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGALRM));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EINTR, r.rr.err);
	ATF_CHECK_EQ(1, r.signals);
	/* The controller had read it, so the abandonment is announced. */
	dqt_lock(&c);
	ATF_REQUIRE_EQ(1, c.nheld);
	dqt_unlock(&c);
	ATF_REQUIRE(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(c.held[0].id, c.interrupted[0]);
	ATF_CHECK_EQ(1, c.events[DQ_OP_INTERRUPT]);
	dqt_unlock(&c);
	/* INTERRUPT needs no answer: de_id 0 is never in flight. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 100));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_interrupts);
	ATF_CHECK_EQ(1, st.ds_late_replies);
	ATF_CHECK_EQ(0, st.ds_inflight);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(reply_racing_signal);
ATF_TC_HEAD(reply_racing_signal, tc)
{
	atf_tc_set_md_var(tc, "descr", "a reply racing a signal on a "
	    "DQ_PF_INTR object: either the data arrives and no INTERRUPT is "
	    "posted, or EINTR and exactly one INTERRUPT (the state decides "
	    "first, D91 item 7)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_racing_signal, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct one_read_arg a;
	struct one_read_res r;
	struct dq_stats st;
	int hi, i, lo, oracle, ndata, neintr, us;

	dqt_fill(data, sizeof(data), 63);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data),
	    policy_intr(&pol));

	/*
	 * The timer is steered to where the reply lands, however fast or
	 * loaded the guest: lo is the longest timer seen to fire first
	 * (EINTR), hi the shortest seen to lose (data).  Without both, the
	 * timer doubles after an EINTR and halves after data; with both, it
	 * is the midpoint, kept from collapsing onto either bound, so the
	 * rounds go both ways.  At least 20 rounds, and more until both
	 * outcomes have been seen.  The reply leaves 2 ms after the READ is
	 * read, which keeps the window above the timer granularity.
	 */
	dqt_set_reply_delay(&c, 2);
	ndata = neintr = 0;
	lo = 0;
	hi = 0;
	us = 2000;
	memset(&a, 0, sizeof(a));
	for (i = 0; i < RACE_ROUNDS_MAX && (i < 20 || ndata == 0 ||
	    neintr == 0); i++) {
		a.fd = o->fd;
		a.len = 100;
		a.alarm_us = us;
		dqt_run_child(child_one_read, &a, &r, sizeof(r));
		if (r.rr.rv == 100) {
			ndata++;
			if (hi == 0 || us < hi)
				hi = us;
		} else {
			ATF_CHECK_EQ(-1, r.rr.rv);
			ATF_CHECK_EQ(EINTR, r.rr.err);
			neintr++;
			if (us > lo)
				lo = us;
		}
		if (hi == 0)
			us = MIN(us * 2, RACE_TIMER_MAX_US);
		else if (lo == 0)
			us = MAX(us / 2, RACE_TIMER_MIN_US);
		else if (hi > lo)
			/* Alternate just below and just above the midpoint. */
			us = (lo + hi) / 2 + ((i & 1) != 0 ? 1 : -1) *
			    MAX((hi - lo) / 4, 100);
		else
			/* The bounds crossed (noise): widen around them. */
			us = (i & 1) != 0 ? lo + 500 : MAX(hi - 500,
			    RACE_TIMER_MIN_US);
	}
	printf("%d rounds: %d data, %d EINTR (EINTR up to %d us, data from "
	    "%d us)\n", i, ndata, neintr, lo, hi);
	/* Every record has reached the queue once nothing is in flight. */
	ATF_CHECK(dqt_wait_stats(&c, inflight_is_zero, 0, DQT_WAIT_MS));
	dqt_stats(&c, &st);
	/*
	 * A READ the controller read ends in exactly one of: its reply
	 * consumed (data), or the controller's reply late (ESRCH) because the
	 * waiter gave up.  The late case is an INTERRUPT record when the event
	 * had been delivered, or nothing at all for a dead delivery (copied
	 * while the waiter withdrew it PENDING).  An EINTR before any copy is
	 * never seen by the controller.
	 */
	dqt_lock(&c);
	ATF_CHECK_EQ_MSG(ndata + c.reply_failures, c.events[DQ_OP_READ],
	    "READ %u data %d late %u", c.events[DQ_OP_READ], ndata,
	    c.reply_failures);
	ATF_CHECK(c.events[DQ_OP_INTERRUPT] <= c.reply_failures);
	ATF_CHECK(c.reply_failures <= (unsigned)neintr);
	ATF_CHECK_EQ(c.events[DQ_OP_INTERRUPT], st.ds_interrupts);
	ATF_CHECK_EQ(c.reply_failures, st.ds_late_replies);
	if (c.reply_failures != 0)
		ATF_CHECK_EQ(ESRCH, c.last_reply_errno);
	dqt_unlock(&c);
	ATF_CHECK_EQ(0, st.ds_inflight);
	/*
	 * A race seen going one way only has tested one side of it.  This
	 * fails rather than skips: atf_tc_skip would hide the checks above.
	 */
	ATF_CHECK_MSG(ndata != 0 && neintr != 0, "race not exercised: %d "
	    "data, %d EINTR in %d rounds", ndata, neintr, i);
	dqt_fini(&c);
	(void)close(oracle);
}

/* Wait until the queue's waited posts have waited for a slot n times. */
static bool
full_waits_reach(struct dqt_ctl *c, uint64_t n, int ms)
{
	struct dq_stats2 st;
	int64_t end;

	end = dqt_now_ms() + ms;
	for (;;) {
		dqt_stats2(c, &st);
		if (st.ds2_full_waits >= n)
			return (true);
		if (dqt_now_ms() >= end)
			return (false);
		dqt_msleep(5);
	}
}

ATF_TC(full_waits_then_posts);
ATF_TC_HEAD(full_waits_then_posts, tc)
{
	atf_tc_set_md_var(tc, "descr", "a full queue makes a waited post wait "
	    "for a slot and then post (D205), with no drop and no de_seq gap "
	    "(it failed EIO at once and counted a drop)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_waits_then_posts, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r[3];
	struct dqt_child ch[3];
	struct dq_stats st;
	struct dq_stats2 st2;
	int i, oracle;

	dqt_fill(data, sizeof(data), 64);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 2));

	dqt_pause(&c);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	for (i = 0; i < 3; i++)
		dqt_spawn(&ch[i], child_one_pread, &a);
	/* Two posted, the third waiting for a slot. */
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, 2, DQT_WAIT_MS));
	ATF_CHECK(full_waits_reach(&c, 1, DQT_WAIT_MS));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(2, st.ds_queue_current);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	dqt_resume(&c);
	for (i = 0; i < 3; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ_MSG(100, r[i].rr.rv, "reader %d: rv %ld errno %d",
		    i, r[i].rr.rv, r[i].rr.err);
	}
	dqt_lock(&c);
	ATF_CHECK_EQ_MSG(3, c.nseqs, "nseqs %d last_seq %ju", c.nseqs,
	    (uintmax_t)c.last_seq);
	ATF_CHECK_EQ_MSG(3, c.last_seq, "no gap: nseqs %d last_seq %ju",
	    c.nseqs, (uintmax_t)c.last_seq);
	dqt_unlock(&c);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	ATF_CHECK_EQ(3, st.ds_events_posted);
	dqt_stats2(&c, &st2);
	ATF_CHECK(st2.ds2_full_waits >= 1);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(full_deadline_eio);
ATF_TC_HEAD(full_deadline_eio, tc)
{
	atf_tc_set_md_var(tc, "descr", "a waited post that waits for a slot "
	    "of a full queue is bounded by its deadline: EIO, counted as a "
	    "deadline miss, nothing posted (D205)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_deadline_eio, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o0, *o1;
	struct dq_policy pol;
	struct one_read_arg a0, a1;
	struct one_read_res r0, r1;
	struct dqt_child ch0, ch1;
	struct dq_stats st;
	int64_t start, ms;
	int oracle;

	dqt_fill(data, sizeof(data), 65);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o0 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	pol.dp_deadline_ms = 300;
	o1 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));

	/* The one slot taken by a read with no deadline, never read. */
	dqt_pause(&c);
	memset(&a0, 0, sizeof(a0));
	a0.fd = o0->fd;
	a0.len = 100;
	dqt_spawn(&ch0, child_one_pread, &a0);
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	a1 = a0;
	a1.fd = o1->fd;
	start = dqt_now_ms();
	dqt_spawn(&ch1, child_one_pread, &a1);
	dqt_collect(&ch1, &r1, sizeof(r1));
	ms = dqt_now_ms() - start;
	ATF_CHECK_EQ(-1, r1.rr.rv);
	ATF_CHECK_EQ(EIO, r1.rr.err);
	ATF_CHECK_MSG(ms >= 250 && ms < 3000, "took %jd ms", (intmax_t)ms);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_events_posted);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	ATF_CHECK_EQ(1, st.ds_deadline_misses);
	dqt_resume(&c);
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(100, r0.rr.rv);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(full_close_wakes);
ATF_TC_HEAD(full_close_wakes, tc)
{
	atf_tc_set_md_var(tc, "descr", "a post waiting for a slot of a full "
	    "queue with no deadline ends EIO when the queue dies: the close "
	    "wakes it (D205)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_close_wakes, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct one_read_arg a;
	struct one_read_res r[2];
	struct dqt_child ch[2];
	int i, oracle;

	dqt_fill(data, sizeof(data), 66);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	/*
	 * No deadline and the default (uninterruptible) mode: the slot wait
	 * has no timer, so only a wakeup ends it.  On a dying queue the
	 * failures free no slot one by one; the death's own
	 * wakeup(&q->q_space) is the only way out (wake_die_space drops it
	 * on a knob-tier kernel and the wait does not end).
	 */
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));
	dqt_pause(&c);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch[0], child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_stats(&c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	dqt_spawn(&ch[1], child_one_pread, &a);
	ATF_REQUIRE(full_waits_reach(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch[1].pid, "dqfull", DQT_WAIT_MS));
	dqt_fini(&c);		/* the queue's last descriptor */
	/* The case's timeout is the hang detector: the wait must end. */
	for (i = 0; i < 2; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ_MSG(-1, r[i].rr.rv, "reader %d", i);
		ATF_CHECK_EQ_MSG(EIO, r[i].rr.err, "reader %d", i);
	}
	(void)close(oracle);
}

ATF_TC(full_revoke_wakes);
ATF_TC_HEAD(full_revoke_wakes, tc)
{
	atf_tc_set_md_var(tc, "descr", "a post of a DQ_PF_INTR object with no "
	    "deadline waiting for a slot of a full queue ends EIO at once when "
	    "its object is revoked (review 2)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_revoke_wakes, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o0, *o1;
	struct dq_policy pol;
	struct one_read_arg a0, a1;
	struct one_read_res r0, r1;
	struct dqt_child ch0, ch1;
	int oracle;

	dqt_fill(data, sizeof(data), 67);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o0 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	policy_intr(&pol);
	pol.dp_deadline_ms = 0;
	o1 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));

	/* The one slot taken by o0's read, unread. */
	dqt_pause(&c);
	memset(&a0, 0, sizeof(a0));
	a0.fd = o0->fd;
	a0.len = 100;
	dqt_spawn(&ch0, child_one_pread, &a0);
	ATF_REQUIRE(dqt_wait_stats(&c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	a1 = a0;
	a1.fd = o1->fd;
	dqt_spawn(&ch1, child_one_pread, &a1);
	ATF_REQUIRE(full_waits_reach(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch1.pid, "dqfull", DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o1->id));
	/*
	 * Still paused, so no slot frees: only the revoke's wakeup ends the
	 * wait, and the case's timeout is the hang detector.
	 */
	dqt_collect(&ch1, &r1, sizeof(r1));
	ATF_CHECK_EQ(-1, r1.rr.rv);
	ATF_CHECK_EQ(EIO, r1.rr.err);
	dqt_resume(&c);
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(100, r0.rr.rv);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Every dq wait is event-driven (owner, 2026-11-19; dq-served-wait-model.md
 * section 3): the waiter has no timer to fall back on, so each wakeup it
 * depends on must be the only way out.  These knob-tier cases prove it,
 * one wakeup each: with that wakeup dropped (debug.dq.drop_wakeup, options
 * DQ_FAULT_INJECTION) the waiter stays asleep; the normal cases
 * (full_close_wakes, full_revoke_wakes, inflight_bound, ...) prove the
 * wakeup ends the wait.  No proof waits a while to see the waiter stay
 * asleep: the kernel counts each wakeup it drops, per site, and wakes the
 * test at the drop (debug.dq.wakeup_drop_wait), so the test takes the
 * moment the waiter's only way out was taken.  It then looks once that
 * the waiter is still in its sleep (its wmesg) and that the sleep has no
 * timeout (debug.dq.thread_sleeps): a wait re-checking its state on a
 * timer, as the 100 ms slices before D402 did, has one.  SIGKILL then
 * releases the waiter.
 */
#define	DROP_WAKEUP	"debug.dq.drop_wakeup"
/* DQ_WAKE_* of sys/dev/dq/dq_var.h. */
#define	WAKE_ANSWER		0x0001
#define	WAKE_FAIL		0x0002
#define	WAKE_INFLIGHT		0x0004
#define	WAKE_REQUESTER		0x0008
#define	WAKE_SLOT		0x0010
#define	WAKE_DIE_SPACE		0x0020
#define	WAKE_REVOKE_SPACE	0x0040
#define	WAKE_REVOKE_QUOTA	0x0080
#define	WAKE_PASS		0x0400

/*
 * Drop the wakeups of mask; returns how many wakeups of site (a bit of
 * mask: the one the proof waits for) were dropped before.
 */
static uint64_t
wake_drop(u_int mask, u_int site)
{
	uint64_t before;

	before = dqt_drop_count(site);
	dqt_sysctl_save_set_uint(DROP_WAKEUP, mask);
	return (before);
}

/*
 * The waiter's only way out, site, was dropped n times since before (the
 * kernel wakes the test at the drop: dqt_drop_wait).  Then, looked at
 * once: the waiter is still in its sleep, and that sleep has no timeout
 * (a wait re-checking on a timer would have one).  Then the wakeups go
 * and it is killed.
 */
static void
wake_dropped_holds(struct dqt_child *ch, const char *wmesg, u_int site,
    uint64_t before, uint64_t n, const char *what)
{
	uint64_t left;
	int status;

	dqt_drop_wait(site, before + n);
	left = 0;
	ATF_CHECK_MSG(dqt_sleep_left(ch->pid, wmesg, &left), "%s: the waiter "
	    "left %s with its wakeup dropped: another wakeup reached it", what,
	    wmesg);
	ATF_CHECK_EQ_MSG(0, left, "%s: the sleep in %s has a timeout (%ju ms "
	    "left): a timer, not the event, could end it", what, wmesg,
	    (uintmax_t)left);
	ATF_REQUIRE(dqt_sysctl_restore(DROP_WAKEUP));
	(void)kill(ch->pid, SIGKILL);
	ATF_REQUIRE_EQ(ch->pid, waitpid(ch->pid, &status, 0));
	(void)close(ch->pipefd);
}

/*
 * For a quota wait under dqt_hold: the waiter, once woken, would post and
 * then wait for an answer that is held.  It must still be in its quota
 * sleep, and its event not posted (the held events stay at n).
 */
static void
wake_dropped_unposted(struct dqt_ctl *c, int n, struct dqt_child *ch,
    const char *wmesg, u_int site, uint64_t before, uint64_t ndrop,
    const char *what)
{

	dqt_drop_wait(site, before + ndrop);
	ATF_CHECK_MSG(!dqt_wait_held(c, n + 1, 0), "%s: the post went on with "
	    "its wakeup dropped", what);
	wake_dropped_holds(ch, wmesg, site, before, ndrop, what);
}

static struct dqt_object *
wake_object(struct dqt_ctl *c, int oracle)
{
	struct dq_policy pol;

	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;		/* no deadline ends the wait */
	return (dqt_mint(c, oracle, oracle_path, data, sizeof(data), &pol));
}

static int
wake_setup(struct dqt_ctl *c, unsigned seed)
{
	int oracle;

	dqt_require_fault_knob(DROP_WAKEUP);
	dqt_fill(data, sizeof(data), seed);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(c);
	return (oracle);
}

ATF_TC_WITH_CLEANUP(wake_answer);
ATF_TC_HEAD(wake_answer, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read waiting for its answer ends "
	    "only by the reply's wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_answer, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_child ch;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 70);
	o = wake_object(&c, oracle);
	dqt_hold(&c, true);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	before = wake_drop(WAKE_ANSWER, WAKE_ANSWER);
	ATF_REQUIRE_EQ(0, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 100));
	wake_dropped_holds(&ch, DQT_WMESG_REPLY, WAKE_ANSWER, before, 1,
	    "answer");
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(wake_answer, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TC_WITH_CLEANUP(wake_fail);
ATF_TC_HEAD(wake_fail, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read whose event a revoke fails "
	    "ends only by the failure's wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_fail, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_child ch;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 71);
	o = wake_object(&c, oracle);
	dqt_hold(&c, true);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	before = wake_drop(WAKE_FAIL, WAKE_FAIL);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	wake_dropped_holds(&ch, DQT_WMESG_REPLY, WAKE_FAIL, before, 1,
	    "failure");
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(wake_fail, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

/*
 * A full queue of depth 1: the first read's event takes the slot, unread
 * (the harness paused); the second read waits in "dqfull".
 */
static void
wake_full(struct dqt_ctl *c, struct dqt_object *o0, struct dqt_object *o1,
    struct dqt_child *ch0, struct dqt_child *ch1, struct one_read_arg *a0,
    struct one_read_arg *a1)
{

	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c->q, 1));
	dqt_pause(c);
	memset(a0, 0, sizeof(*a0));
	a0->fd = o0->fd;
	a0->len = 100;
	dqt_spawn(ch0, child_one_pread, a0);
	ATF_REQUIRE(dqt_wait_stats(c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	*a1 = *a0;
	a1->fd = o1->fd;
	dqt_spawn(ch1, child_one_pread, a1);
	ATF_REQUIRE(full_waits_reach(c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch1->pid, "dqfull", DQT_WAIT_MS));
}

ATF_TC_WITH_CLEANUP(wake_die_space);
ATF_TC_HEAD(wake_die_space, tc)
{
	atf_tc_set_md_var(tc, "descr", "a post waiting for a slot of a full "
	    "queue ends at the queue's death only by the death's own wakeup: "
	    "the failures free no slot on a dying queue (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_die_space, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a0, a1;
	struct one_read_res r0;
	struct dqt_child ch0, ch1;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 72);
	o = wake_object(&c, oracle);
	wake_full(&c, o, o, &ch0, &ch1, &a0, &a1);
	before = wake_drop(WAKE_DIE_SPACE, WAKE_DIE_SPACE);
	dqt_fini(&c);		/* the queue's last descriptor */
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(EIO, r0.rr.err);
	wake_dropped_holds(&ch1, "dqfull", WAKE_DIE_SPACE, before, 1,
	    "the queue's death");
	(void)close(oracle);
}
ATF_TC_CLEANUP(wake_die_space, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TC_WITH_CLEANUP(wake_revoke_space);
ATF_TC_HEAD(wake_revoke_space, tc)
{
	atf_tc_set_md_var(tc, "descr", "a post waiting for a slot of a full "
	    "queue ends at its object's revoke only by the revoke's wakeup "
	    "(no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_revoke_space, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o0, *o1;
	struct one_read_arg a0, a1;
	struct one_read_res r0;
	struct dqt_child ch0, ch1;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 73);
	o0 = wake_object(&c, oracle);
	o1 = wake_object(&c, oracle);
	wake_full(&c, o0, o1, &ch0, &ch1, &a0, &a1);
	before = wake_drop(WAKE_REVOKE_SPACE, WAKE_REVOKE_SPACE);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o1->id));
	wake_dropped_holds(&ch1, "dqfull", WAKE_REVOKE_SPACE, before, 1,
	    "the revoke");
	dqt_resume(&c);
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(100, r0.rr.rv);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(wake_revoke_space, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TC_WITH_CLEANUP(wake_slot);
ATF_TC_HEAD(wake_slot, tc)
{
	atf_tc_set_md_var(tc, "descr", "a post waiting for a slot of a full "
	    "queue ends when the controller reads the queue only by the freed "
	    "slot's wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_slot, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a0, a1;
	struct one_read_res r0;
	struct dqt_child ch0, ch1;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 74);
	o = wake_object(&c, oracle);
	wake_full(&c, o, o, &ch0, &ch1, &a0, &a1);
	before = wake_drop(WAKE_SLOT, WAKE_SLOT);
	dqt_resume(&c);		/* the slot is read off and answered */
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(100, r0.rr.rv);
	wake_dropped_holds(&ch1, "dqfull", WAKE_SLOT, before, 1,
	    "the freed slot");
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(wake_slot, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
}

ATF_TC_WITH_CLEANUP(wake_inflight);
ATF_TC_HEAD(wake_inflight, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read waiting for its object's "
	    "in-flight slot ends only by the slot's wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_inflight, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r0;
	struct dqt_child ch0, ch1;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 75);
	dqt_sysctl_save_set_uint(inflight_sysctl, 1);
	o = wake_object(&c, oracle);
	dqt_hold(&c, true);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch0, child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_spawn(&ch1, child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_wmesg(ch1.pid, DQT_WMESG_INFLIGHT, DQT_WAIT_MS));
	before = wake_drop(WAKE_INFLIGHT, WAKE_INFLIGHT);
	ATF_REQUIRE_EQ(0, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 100));
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(100, r0.rr.rv);
	wake_dropped_unposted(&c, 1, &ch1, DQT_WMESG_INFLIGHT, WAKE_INFLIGHT,
	    before, 1, "the object's in-flight slot");
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(wake_inflight, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(inflight_sysctl);
}

/* Two reads of one requester (one process), from two threads. */
struct wake_req_arg {
	int	fd[2];
};

static void *
wake_req_thread(void *arg)
{
	char buf[16];

	(void)pread(*(int *)arg, buf, sizeof(buf), 0);
	return (NULL);
}

static void
child_two_reads(void *arg, void *result __unused)
{
	struct wake_req_arg *a = arg;
	pthread_t t;
	char buf[16];

	if (pthread_create(&t, NULL, wake_req_thread, &a->fd[0]) != 0)
		_exit(3);
	(void)pread(a->fd[1], buf, sizeof(buf), 0);
	(void)pthread_join(t, NULL);
}

static const char requester_sysctl[] = "kern.dq.max_inflight_per_requester";

ATF_TC_WITH_CLEANUP(wake_requester);
ATF_TC_HEAD(wake_requester, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read waiting for its requester's "
	    "in-flight slot ends only by the slot's wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_requester, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o0, *o1;
	struct wake_req_arg a;
	struct dqt_child ch;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 76);
	dqt_sysctl_save_set_uint(requester_sysctl, 1);
	o0 = wake_object(&c, oracle);
	o1 = wake_object(&c, oracle);
	dqt_hold(&c, true);
	a.fd[0] = o0->fd;
	a.fd[1] = o1->fd;
	dqt_spawn(&ch, child_two_reads, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch.pid, "dqreq", DQT_WAIT_MS));
	before = wake_drop(WAKE_REQUESTER, WAKE_REQUESTER);
	ATF_REQUIRE_EQ(0, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 16));
	/* The answered thread drops the wakeup as it returns. */
	wake_dropped_unposted(&c, 1, &ch, "dqreq", WAKE_REQUESTER, before, 1,
	    "the requester's in-flight slot");
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(requester_sysctl));
}
ATF_TC_CLEANUP(wake_requester, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(requester_sysctl);
}

/*
 * A revoke wakes its object's quota waiters (DQ_WAKE_REVOKE_QUOTA): the
 * waiter in "dqinfl" looks again and fails EIO.  The in-flight read the
 * revoke fails frees the object's slot too, so that wakeup (INFLIGHT) is
 * dropped in both cases: revoke_quota_wakes proves the revoke's wakeup
 * alone ends the wait, wake_revoke_quota that nothing else does.
 */
static void
revoke_quota_setup(struct dqt_ctl *c, int oracle, struct dqt_object **op,
    struct dqt_child *ch0, struct dqt_child *ch1, struct one_read_arg *a)
{

	dqt_sysctl_save_set_uint(inflight_sysctl, 1);
	*op = wake_object(c, oracle);
	dqt_hold(c, true);
	memset(a, 0, sizeof(*a));
	a->fd = (*op)->fd;
	a->len = 100;
	dqt_spawn(ch0, child_one_pread, a);
	ATF_REQUIRE(dqt_wait_held(c, 1, DQT_WAIT_MS));
	dqt_spawn(ch1, child_one_pread, a);
	ATF_REQUIRE(dqt_wait_wmesg(ch1->pid, DQT_WMESG_INFLIGHT,
	    DQT_WAIT_MS));
}

ATF_TC_WITH_CLEANUP(revoke_quota_wakes);
ATF_TC_HEAD(revoke_quota_wakes, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read waiting for its object's "
	    "in-flight slot ends EIO when the object is revoked, by the "
	    "revoke's own wakeup (the freed slot's wakeup dropped)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoke_quota_wakes, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r0, r1;
	struct dqt_child ch0, ch1;
	int oracle;

	oracle = wake_setup(&c, 77);
	revoke_quota_setup(&c, oracle, &o, &ch0, &ch1, &a);
	(void)wake_drop(WAKE_INFLIGHT, WAKE_INFLIGHT);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	/* The case's timeout is the hang detector. */
	dqt_collect(&ch1, &r1, sizeof(r1));
	ATF_CHECK_EQ(-1, r1.rr.rv);
	ATF_CHECK_EQ(EIO, r1.rr.err);
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(EIO, r0.rr.err);
	ATF_REQUIRE(dqt_sysctl_restore(DROP_WAKEUP));
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(revoke_quota_wakes, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(inflight_sysctl);
}

ATF_TC_WITH_CLEANUP(wake_revoke_quota);
ATF_TC_HEAD(wake_revoke_quota, tc)
{
	atf_tc_set_md_var(tc, "descr", "a read waiting for its object's "
	    "in-flight slot when the object is revoked ends only by the "
	    "revoke's quota wakeup (no polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_revoke_quota, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r0;
	struct dqt_child ch0, ch1;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 78);
	revoke_quota_setup(&c, oracle, &o, &ch0, &ch1, &a);
	before = wake_drop(WAKE_INFLIGHT | WAKE_REVOKE_QUOTA,
	    WAKE_REVOKE_QUOTA);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	dqt_collect(&ch0, &r0, sizeof(r0));
	ATF_CHECK_EQ(EIO, r0.rr.err);
	/* The revoke's wakeup, and the slot ch0's failed read freed. */
	wake_dropped_holds(&ch1, DQT_WMESG_INFLIGHT, WAKE_REVOKE_QUOTA, before,
	    1,
	    "the revoke's quota wakeup");
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(wake_revoke_quota, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(inflight_sysctl);
}

/*
 * The hand-off of a slot's wakeup (pw_pass, DQ_WAKE_PASS): a slot waiter
 * woken for a slot it cannot take, because a quota filled while it slept,
 * passes the wakeup to the next slot waiter.  The quota is the object's
 * in-flight bound (1): the requester bound cannot tell the test's children
 * apart, since every process of one capability identity is one requester
 * (dc_nonce; the first version of these cases used it, and W waited in
 * "dqreq" behind the filler).  F's read of Z holds the one slot, unread;
 * A and B read X; W reads Y, at the lowest timesharing priority (nice 20,
 * no privilege needed), so each wakeup_one picks A or B first.  The first
 * slot freed goes to one of them; the second wakes the other, which finds
 * room but sleeps on X's bound and must pass the wakeup on, or W sleeps on
 * with a slot free.
 */
struct pass_ctx {
	struct one_read_arg	 af, ax, aw;
	struct dqt_child	 chf, cha, chb, chw;
};

static void
child_low_pread(void *arg, void *result)
{

	if (setpriority(PRIO_PROCESS, 0, PRIO_MAX) != 0)
		_exit(4);
	child_one_pread(arg, result);
}

static void
pass_wait_full(struct dqt_child *ch, const char *who)
{
	int st;

	if (dqt_wait_wmesg(ch->pid, "dqfull", DQT_WAIT_MS))
		return;
	if (waitpid(ch->pid, &st, WNOHANG) == ch->pid)
		atf_tc_fail("%s exited (status %#x) before its wait", who, st);
	atf_tc_fail("%s is not waiting in \"dqfull\"", who);
}

static void
pass_setup(struct dqt_ctl *c, int oracle, struct pass_ctx *x)
{
	struct dqt_object *ox, *oy, *oz;

	dqt_sysctl_save_set_uint(inflight_sysctl, 1);
	ox = wake_object(c, oracle);
	oy = wake_object(c, oracle);
	oz = wake_object(c, oracle);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c->q, 1));
	dqt_pause(c);
	memset(x, 0, sizeof(*x));
	x->af.fd = oz->fd;
	x->af.len = 16;
	x->ax = x->aw = x->af;
	x->ax.fd = ox->fd;
	x->aw.fd = oy->fd;
	dqt_spawn(&x->chf, child_one_pread, &x->af);	/* the slot, unread */
	ATF_REQUIRE(dqt_wait_stats(c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	dqt_spawn(&x->chw, child_low_pread, &x->aw);
	pass_wait_full(&x->chw, "W");
	dqt_spawn(&x->cha, child_one_pread, &x->ax);
	pass_wait_full(&x->cha, "A");
	dqt_spawn(&x->chb, child_one_pread, &x->ax);
	pass_wait_full(&x->chb, "B");
	dqt_hold(c, true);
}

static void
pass_cleanup(struct dqt_ctl *c, struct pass_ctx *x)
{
	struct dqt_child *ch[4] = { &x->chf, &x->cha, &x->chb, &x->chw };
	int i, status;

	for (i = 0; i < 4; i++) {
		if (ch[i]->pid == -1)
			continue;
		(void)kill(ch[i]->pid, SIGKILL);
		(void)waitpid(ch[i]->pid, &status, 0);
		(void)close(ch[i]->pipefd);
	}
	dqt_hold(c, false);
	dqt_fini(c);
}

ATF_TC_WITH_CLEANUP(full_pass_wakes);
ATF_TC_HEAD(full_pass_wakes, tc)
{
	atf_tc_set_md_var(tc, "descr", "a slot waiter woken for a slot its "
	    "object's in-flight bound keeps it from taking passes the wakeup "
	    "on: the next slot waiter posts");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_pass_wakes, tc)
{
	struct dqt_ctl c;
	struct pass_ctx x;
	int oracle;

	oracle = wake_setup(&c, 79);
	pass_setup(&c, oracle, &x);
	dqt_resume(&c);
	/*
	 * F's, one of A's and B's, and W's reads: held.  The case's timeout
	 * is the hang detector.
	 */
	ATF_REQUIRE(dqt_wait_held(&c, 3, INT_MAX));
	ATF_CHECK(dqt_wait_wmesg(x.cha.pid, DQT_WMESG_INFLIGHT, 0) ||
	    dqt_wait_wmesg(x.chb.pid, DQT_WMESG_INFLIGHT, 0));
	pass_cleanup(&c, &x);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(full_pass_wakes, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(inflight_sysctl);
}

ATF_TC_WITH_CLEANUP(wake_pass);
ATF_TC_HEAD(wake_pass, tc)
{
	atf_tc_set_md_var(tc, "descr", "a slot waiter after one woken for a "
	    "slot it cannot take ends only by the passed-on wakeup (no "
	    "polling)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wake_pass, tc)
{
	struct dqt_ctl c;
	struct pass_ctx x;
	uint64_t before;
	int oracle;

	oracle = wake_setup(&c, 80);
	pass_setup(&c, oracle, &x);
	before = wake_drop(WAKE_PASS, WAKE_PASS);
	dqt_resume(&c);
	dqt_drop_wait(WAKE_PASS, before + 1);
	ATF_CHECK_MSG(!dqt_wait_held(&c, 3, 0), "W posted with the passed-on "
	    "wakeup dropped");
	wake_dropped_holds(&x.chw, "dqfull", WAKE_PASS, before, 1,
	    "the passed-on wakeup");
	x.chw.pid = -1;
	pass_cleanup(&c, &x);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(wake_pass, tc)
{

	(void)dqt_sysctl_restore(DROP_WAKEUP);
	(void)dqt_sysctl_restore(inflight_sysctl);
}

/* Read exactly one record (a READ) off a manual queue. */
static uint64_t
read_one_record(int q)
{
	char buf[sizeof(struct dq_event) + sizeof(struct dq_read_body)];
	const struct dq_event *ev;
	ssize_t n;

	n = read(q, buf, sizeof(buf));
	ATF_REQUIRE_MSG(n == (ssize_t)sizeof(buf), "read %zd: %s", n,
	    strerror(errno));
	ev = (const struct dq_event *)(void *)buf;
	ATF_REQUIRE_EQ(DQ_OP_READ, ev->de_op);
	return (ev->de_id);
}

ATF_TC(full_signal_one);
ATF_TC_HEAD(full_signal_one, tc)
{
	atf_tc_set_md_var(tc, "descr", "three posts waiting for the slot of a "
	    "full queue and one slot freed: exactly one posts (D205)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(full_signal_one, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct one_read_arg a;
	struct one_read_res r[4];
	struct dqt_child ch[4];
	struct dq_stats st;
	uint64_t id;
	int i, oracle;

	dqt_fill(data, sizeof(data), 67);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init_manual(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch[0], child_one_pread, &a);
	ATF_REQUIRE(dqt_wait_stats(&c, posted_or_dropped_is, 1, DQT_WAIT_MS));
	for (i = 1; i < 4; i++)
		dqt_spawn(&ch[i], child_one_pread, &a);
	ATF_REQUIRE(full_waits_reach(&c, 3, DQT_WAIT_MS));
	/* One record read off: one slot. */
	id = read_one_record(c.q);
	dqt_msleep(500);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ_MSG(2, st.ds_events_posted, "one slot, %ju posts",
	    (uintmax_t)st.ds_events_posted);
	ATF_CHECK_EQ(1, st.ds_queue_current);
	/* Answer everything, one record at a time. */
	ATF_REQUIRE_EQ(0, dq_reply(c.q, id, 0, data, 100));
	for (i = 1; i < 4; i++) {
		id = read_one_record(c.q);
		ATF_REQUIRE_EQ(0, dq_reply(c.q, id, 0, data, 100));
	}
	for (i = 0; i < 4; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ_MSG(100, r[i].rr.rv, "reader %d: errno %d", i,
		    r[i].rr.err);
	}
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(4, st.ds_events_posted);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(edeadlk_controller);
ATF_TC_HEAD(edeadlk_controller, tc)
{
	atf_tc_set_md_var(tc, "descr", "the process holding the queue is "
	    "refused posting operations with EDEADLK, and not fstat, F_KINFO, "
	    "lseek or close");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(edeadlk_controller, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o, *og;
	struct dq_policy pol;
	struct kinfo_file kif;
	struct stat st;
	unsigned char buf[16];
	int d, oracle;

	dqt_fill(data, sizeof(data), 65);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_GETATTR;
	og = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);

	errno = 0;
	ATF_CHECK_EQ(-1, read(o->fd, buf, sizeof(buf)));
	ATF_CHECK_EQ(EDEADLK, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, pread(o->fd, buf, sizeof(buf), 10));
	ATF_CHECK_EQ(EDEADLK, errno);
	/* fstat posts only when GETATTR is an event. */
	ATF_CHECK_EQ(0, fstat(o->fd, &st));
	errno = 0;
	ATF_CHECK_EQ(-1, fstat(og->fd, &st));
	ATF_CHECK_EQ(EDEADLK, errno);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	ATF_CHECK_EQ(0, fcntl(og->fd, F_KINFO, &kif));
	ATF_CHECK_EQ(10, lseek(o->fd, 10, SEEK_SET));
	d = dup(o->fd);
	ATF_REQUIRE(d != -1);
	ATF_CHECK_EQ(0, close(d));
	/* Nothing reached the queue: everything before the fence is seen. */
	dqt_fence(&c);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

struct pd_arg {
	int		 fd;
};

ATF_TC(edeadlk_pdfork);
ATF_TC_HEAD(edeadlk_pdfork, tc)
{
	atf_tc_set_md_var(tc, "descr", "a helper sharing the controller's "
	    "descriptor table (pdrfork without RFFDG) is refused too: the "
	    "test is by the queue in the table, not by pid (D16)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(edeadlk_pdfork, tc)
{
	struct dq_ident_file *ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	struct dqt_rr r;
	uint64_t object;
	ssize_t n;
	int fd, oracle, pd, pfd[2], q, reason, status;
	pid_t pid;

	dqt_fill(data, sizeof(data), 66);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	q = dqt_open_queue();
	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	dqt_ident_of(oracle, oracle_path, ident, &st, &sfs);
	dq_policy_default(&pol);
	ATF_REQUIRE_EQ(0, dq_mint_file(q, ident, &pol, &object, &fd, &reason));

	/*
	 * No fork child holds the queue (sc-q); the one other process that
	 * has it in its table is one that shares the table.  It may not
	 * operate the queue, and it is refused on the queue's objects like
	 * the controller.  The table is shared: nothing is closed here
	 * until the helper has reported.
	 */
	ATF_REQUIRE_EQ(0, pipe(pfd));
	pid = pdrfork(&pd, 0, RFPROC | RFPROCDESC);
	ATF_REQUIRE_MSG(pid != -1, "pdrfork: %s", strerror(errno));
	if (pid == 0) {
		unsigned char buf[16];

		r.rv = read(fd, buf, sizeof(buf));
		r.err = r.rv == -1 ? errno : 0;
		(void)write(pfd[1], &r, sizeof(r));
		_exit(0);
	}
	n = read(pfd[0], &r, sizeof(r));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r), n);
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EDEADLK, r.err);
	ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
	(void)close(pfd[0]);
	(void)close(pfd[1]);
	(void)close(pd);
	free(ident);
	(void)close(fd);
	(void)close(q);
	(void)close(oracle);
}

ATF_TC_WITH_CLEANUP(inflight_bound);
ATF_TC_HEAD(inflight_bound, tc)
{
	atf_tc_set_md_var(tc, "descr", "with kern.dq.max_inflight_per_object "
	    "= 2 a third requester waits for a slot instead of posting");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(inflight_bound, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r[3];
	struct dqt_child ch[3];
	struct dq_stats st;
	int64_t deadline;
	int i, n, oracle;

	dqt_sysctl_save_set_uint(inflight_sysctl, 2);

	dqt_fill(data, sizeof(data), 67);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	dqt_pause(&c);
	a.fd = o->fd;
	a.len = 100;
	a.alarm_us = 0;
	for (i = 0; i < 3; i++)
		dqt_spawn(&ch[i], child_one_pread, &a);
	/*
	 * Two posted; the third sleeps in dq_event_post_wait ("dqinfl").  Wait
	 * for the two, then for the third to sleep there.
	 */
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, 2, DQT_WAIT_MS));
	deadline = dqt_now_ms() + DQT_WAIT_MS;
	for (;;) {
		for (i = n = 0; i < 3; i++)
			if (dqt_wait_wmesg(ch[i].pid, DQT_WMESG_INFLIGHT, 0))
				n++;
		if (n != 0 || dqt_now_ms() >= deadline)
			break;
		dqt_msleep(10);
	}
	ATF_REQUIRE_EQ_MSG(1, n, "%d requesters wait for a slot, not 1", n);
	dqt_stats(&c, &st);
#define	INFL_FMT "current %ju posted %ju dropped %ju delivered %ju " \
	"inflight %ju; harness reads %u paused_reads %u records %u"
#define	INFL_ARGS \
	(uintmax_t)st.ds_queue_current, (uintmax_t)st.ds_events_posted, \
	(uintmax_t)st.ds_events_dropped, (uintmax_t)st.ds_events_delivered, \
	(uintmax_t)st.ds_inflight, c.reads, c.paused_reads, c.records
	dqt_lock(&c);
	ATF_CHECK_EQ_MSG(2, st.ds_queue_current, INFL_FMT, INFL_ARGS);
	ATF_CHECK_EQ_MSG(2, st.ds_events_posted, INFL_FMT, INFL_ARGS);
	ATF_CHECK_EQ_MSG(0, st.ds_events_dropped, INFL_FMT, INFL_ARGS);
	dqt_unlock(&c);
#undef INFL_FMT
#undef INFL_ARGS
	dqt_resume(&c);
	for (i = 0; i < 3; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ_MSG(100, r[i].rr.rv, "child %d: %ld errno %d", i,
		    r[i].rr.rv, r[i].rr.err);
	}
	dqt_lock(&c);
	ATF_CHECK_EQ(3, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(inflight_sysctl));
}
ATF_TC_CLEANUP(inflight_bound, tc)
{

	(void)dqt_sysctl_restore(inflight_sysctl);
}

static int
cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x < y ? -1 : x > y);
}

ATF_TC(two_readers);
ATF_TC_HEAD(two_readers, tc)
{
	atf_tc_set_md_var(tc, "descr", "two controller threads reading one "
	    "queue see every event exactly once (q_rdsx serializes the copies)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(two_readers, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct threads_arg a;
	struct threads_res r;
	struct dq_stats st;
	int i, oracle;

	dqt_fill(data, sizeof(data), 68);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init_manual(&c);
	dqt_start(&c, 2);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	a.fd = o->fd;
	a.len = 4096;
	a.rounds = 8;
	dqt_run_child(child_threads, &a, &r, sizeof(r));
	for (i = 0; i < NTHREADS; i++) {
		ATF_CHECK_EQ(4096, r.rv[i]);
		ATF_CHECK_EQ(dqt_digest(data + i * (DATA_LEN / NTHREADS), 4096),
		    r.hash[i]);
	}
	dqt_stop(&c);
	dqt_lock(&c);
	printf("batches: reader 0 %u, reader 1 %u\n", c.thr_batches[0],
	    c.thr_batches[1]);
	ATF_CHECK_EQ(NTHREADS * 8, c.events[DQ_OP_READ]);
	ATF_REQUIRE_EQ(NTHREADS * 8, c.nseqs);
	qsort(c.seqs, (size_t)c.nseqs, sizeof(c.seqs[0]), cmp_u64);
	for (i = 0; i < c.nseqs; i++)
		ATF_CHECK_EQ_MSG((uint64_t)i + 1, c.seqs[i],
		    "seq %d is %ju: a duplicate or a gap", i,
		    (uintmax_t)c.seqs[i]);
	dqt_unlock(&c);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	ATF_CHECK_EQ(NTHREADS * 8, st.ds_events_delivered);
	ATF_CHECK_EQ(NTHREADS * 8, st.ds_replies);
	/* One reader that read every batch has shared nothing. */
	dqt_lock(&c);
	ATF_CHECK_MSG(c.thr_batches[0] != 0 && c.thr_batches[1] != 0,
	    "race not exercised: reader 0 read %u batches, reader 1 %u",
	    c.thr_batches[0], c.thr_batches[1]);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(efault_mid_batch);
ATF_TC_HEAD(efault_mid_batch, tc)
{
	atf_tc_set_md_var(tc, "descr", "a fault in the controller's buffer: "
	    "EFAULT when nothing was copied, a short batch otherwise, and no "
	    "event is lost");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(efault_mid_batch, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r[2];
	struct dqt_child ch[2];
	struct dq_stats st;
	const struct dq_event *ev;
	char *map, *good;
	const size_t recsize = sizeof(struct dq_event) + sizeof(struct dq_read_body);
	size_t pagesize;
	ssize_t got;
	uint64_t ids[2], seqs[2];
	int i, oracle, waited;

	pagesize = (size_t)getpagesize();
	dqt_fill(data, sizeof(data), 69);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init_manual(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	a.fd = o->fd;
	a.len = 100;
	a.alarm_us = 0;
	for (i = 0; i < 2; i++)
		dqt_spawn(&ch[i], child_one_pread, &a);
	for (waited = 0; waited < DQT_WAIT_MS; waited += 10) {
		dqt_stats(&c, &st);
		if (st.ds_queue_current == 2)
			break;
		dqt_msleep(10);
	}
	ATF_REQUIRE_EQ(2, st.ds_queue_current);

	/* Two pages, the second unreadable and unwritable. */
	map = mmap(NULL, 2 * pagesize, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(map != MAP_FAILED);
	ATF_REQUIRE_EQ(0, mprotect(map + pagesize, pagesize, PROT_NONE));

	/*
	 * B2: the first record ends 30 bytes before the bad page and the
	 * second would cross into it.  The copied record is returned (it is
	 * delivered, dequeued and in flight) and the uncopied one stays
	 * queued.
	 */
	good = map + pagesize - (recsize + 30);
	got = read(c.q, good, 3 * recsize);
	ATF_REQUIRE_EQ_MSG((ssize_t)recsize, got, "read %zd: %s", got,
	    strerror(errno));
	ev = dq_event_first(good, (size_t)got);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(DQ_OP_READ, ev->de_op);
	ids[0] = ev->de_id;
	seqs[0] = ev->de_seq;
	dqt_stats(&c, &st);
	ATF_CHECK_EQ_MSG(1, st.ds_queue_current, "current %ju inflight %ju",
	    (uintmax_t)st.ds_queue_current, (uintmax_t)st.ds_inflight);
	ATF_CHECK_EQ(1, st.ds_inflight);
	/* The first event is usable: its reply is accepted. */
	ATF_CHECK_EQ(0, dq_reply(c.q, ids[0], 0, data, 100));

	/* Nothing fits a bad buffer: EFAULT, the second event still queued. */
	errno = 0;
	ATF_CHECK_EQ(-1, read(c.q, map + pagesize, 2 * recsize));
	ATF_CHECK_EQ(EFAULT, errno);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_queue_current);

	got = read(c.q, map, pagesize);
	ATF_REQUIRE_EQ((ssize_t)recsize, got);
	ev = dq_event_first(map, (size_t)got);
	ATF_REQUIRE(ev != NULL);
	ids[1] = ev->de_id;
	seqs[1] = ev->de_seq;
	ATF_CHECK_EQ(seqs[0] + 1, seqs[1]);
	ATF_CHECK(ids[0] != ids[1]);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_queue_current);
	ATF_CHECK_EQ(1, st.ds_inflight);
	ATF_CHECK_EQ(2, st.ds_events_delivered);

	ATF_CHECK_EQ(0, dq_reply(c.q, ids[1], 0, data, 100));
	for (i = 0; i < 2; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		ATF_CHECK_EQ(100, r[i].rr.rv);
	}
	(void)munmap(map, 2 * pagesize);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, threads_replies_reversed);
	ATF_TP_ADD_TC(tp, sigalrm_read_intr);
	ATF_TP_ADD_TC(tp, reply_racing_signal);
	ATF_TP_ADD_TC(tp, full_waits_then_posts);
	ATF_TP_ADD_TC(tp, full_deadline_eio);
	ATF_TP_ADD_TC(tp, full_close_wakes);
	ATF_TP_ADD_TC(tp, full_revoke_wakes);
	ATF_TP_ADD_TC(tp, wake_answer);
	ATF_TP_ADD_TC(tp, wake_fail);
	ATF_TP_ADD_TC(tp, wake_die_space);
	ATF_TP_ADD_TC(tp, wake_revoke_space);
	ATF_TP_ADD_TC(tp, wake_slot);
	ATF_TP_ADD_TC(tp, wake_inflight);
	ATF_TP_ADD_TC(tp, wake_requester);
	ATF_TP_ADD_TC(tp, revoke_quota_wakes);
	ATF_TP_ADD_TC(tp, wake_revoke_quota);
	ATF_TP_ADD_TC(tp, full_pass_wakes);
	ATF_TP_ADD_TC(tp, wake_pass);
	ATF_TP_ADD_TC(tp, full_signal_one);
	ATF_TP_ADD_TC(tp, edeadlk_controller);
	ATF_TP_ADD_TC(tp, edeadlk_pdfork);
	ATF_TP_ADD_TC(tp, inflight_bound);
	ATF_TP_ADD_TC(tp, two_readers);
	ATF_TP_ADD_TC(tp, efault_mid_batch);
	return (atf_no_error());
}
