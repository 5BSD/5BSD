/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Concurrency: replies in any order, interruption, a full queue, the
 * EDEADLK rule, the per-object in-flight bound, two queue readers, and a
 * fault in the controller's read buffer.  The in-flight bound case changes
 * kern.dq.max_inflight_per_object, so the program is exclusive.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	65536
#define	NTHREADS	8

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

static const char inflight_sysctl[] = "kern.dq.max_inflight_per_object";
static const char inflight_saved[] = "max_inflight_per_object.saved";

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

static uint64_t
digest(const void *p, size_t len)
{
	const unsigned char *b = p;
	uint64_t h;
	size_t i;

	h = 14695981039346656037ULL;
	for (i = 0; i < len; i++) {
		h ^= b[i];
		h *= 1099511628211ULL;
	}
	return (h);
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
			t->hash = digest(buf, (size_t)t->rv);
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

struct one_read_arg {
	int		 fd;
	size_t		 len;
	int		 alarm_us;	/* 0: no signal */
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

	if (a->alarm_us != 0) {
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_signal;
		sigaction(SIGALRM, &sa, NULL);
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
	c.order = DQT_ORDER_REVERSE;
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
		ATF_CHECK_EQ_MSG(digest(data + i * (DATA_LEN / NTHREADS), 4096),
		    r.hash[i], "thread %d got the wrong bytes", i);
	}
	dqt_lock(&c);
	ATF_CHECK_EQ(NTHREADS, c.events[DQ_OP_READ]);
	ATF_CHECK_EQ(0, c.reply_failures);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(sigalrm_interrupt);
ATF_TC_HEAD(sigalrm_interrupt, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal during a delivered READ: the "
	    "requester gets EINTR, the controller an INTERRUPT record, and its "
	    "late reply ESRCH");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sigalrm_interrupt, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r;
	struct dq_stats st;
	int oracle;

	dqt_fill(data, sizeof(data), 62);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.len = 100;
	a.alarm_us = 200000;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
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
	dqt_lock(&c);
	ATF_CHECK_EQ(-1, dq_reply(c.q, c.held[0].id, 0, data, 100));
	dqt_unlock(&c);
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
	atf_tc_set_md_var(tc, "descr", "a reply racing a signal: either the "
	    "data arrives and no INTERRUPT is posted, or EINTR and exactly one "
	    "INTERRUPT (the state decides first, D91 item 7)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_racing_signal, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r;
	struct dq_stats st;
	int i, oracle, ndata, neintr;

	dqt_fill(data, sizeof(data), 63);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);

	ndata = neintr = 0;
	for (i = 0; i < 20; i++) {
		a.fd = o->fd;
		a.len = 100;
		a.alarm_us = 1000 + 500 * (i % 8);
		dqt_run_child(child_one_read, &a, &r, sizeof(r));
		if (r.rr.rv == 100)
			ndata++;
		else {
			ATF_CHECK_EQ(-1, r.rr.rv);
			ATF_CHECK_EQ(EINTR, r.rr.err);
			neintr++;
		}
	}
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
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(depth_exhausted);
ATF_TC_HEAD(depth_exhausted, tc)
{
	atf_tc_set_md_var(tc, "descr", "a full queue fails the requester with "
	    "EIO, counts a drop and leaves a de_seq gap");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(depth_exhausted, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct one_read_res r[3], r4;
	struct dqt_child ch[3];
	struct dq_stats st;
	int i, neio, nok, oracle;

	dqt_fill(data, sizeof(data), 64);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 2));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(2, st.ds_queue_depth);

	dqt_pause(&c);
	a.fd = o->fd;
	a.len = 100;
	a.alarm_us = 0;
	for (i = 0; i < 3; i++)
		dqt_spawn(&ch[i], child_one_pread, &a);
	/* Three attempts: two posted, one dropped (seq taken, EIO). */
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, 3, DQT_WAIT_MS));
	dqt_stats(&c, &st);
#define	DEPTH_FMT "current %ju dropped %ju posted %ju delivered %ju " \
	"inflight %ju highwater %ju; harness reads %u paused_reads %u " \
	"records %u"
#define	DEPTH_ARGS (uintmax_t)st.ds_queue_current, \
	(uintmax_t)st.ds_events_dropped, (uintmax_t)st.ds_events_posted, \
	(uintmax_t)st.ds_events_delivered, (uintmax_t)st.ds_inflight, \
	(uintmax_t)st.ds_queue_highwater, c.reads, c.paused_reads, c.records
	ATF_CHECK_EQ_MSG(2, st.ds_queue_current, DEPTH_FMT, DEPTH_ARGS);
	ATF_CHECK_EQ_MSG(1, st.ds_events_dropped, DEPTH_FMT, DEPTH_ARGS);
	ATF_CHECK_EQ_MSG(2, st.ds_events_posted, DEPTH_FMT, DEPTH_ARGS);
	dqt_resume(&c);
	neio = nok = 0;
	for (i = 0; i < 3; i++) {
		dqt_collect(&ch[i], &r[i], sizeof(r[i]));
		if (r[i].rr.rv == 100)
			nok++;
		else if (r[i].rr.rv == -1 && r[i].rr.err == EIO)
			neio++;
	}
	ATF_CHECK_EQ_MSG(2, nok, "ok %d eio %d: rv/errno %ld/%d %ld/%d %ld/%d",
	    nok, neio, r[0].rr.rv, r[0].rr.err, r[1].rr.rv, r[1].rr.err,
	    r[2].rr.rv, r[2].rr.err);
	ATF_CHECK_EQ_MSG(1, neio, "ok %d eio %d", nok, neio);
	/* One more event makes the gap visible wherever the drop fell. */
	dqt_run_child(child_one_pread, &a, &r4, sizeof(r4));
	ATF_CHECK_EQ_MSG(100, r4.rr.rv, "rv %ld errno %d", r4.rr.rv, r4.rr.err);
	dqt_lock(&c);
	ATF_CHECK_EQ_MSG(3, c.nseqs, "nseqs %d last_seq %ju", c.nseqs,
	    (uintmax_t)c.last_seq);
	ATF_CHECK_EQ_MSG(4, c.last_seq, "nseqs %d last_seq %ju", c.nseqs,
	    (uintmax_t)c.last_seq);
	ATF_CHECK_EQ_MSG(1, c.last_seq - (uint64_t)c.nseqs, "nseqs %d last_seq %ju",
	    c.nseqs, (uintmax_t)c.last_seq);
	dqt_unlock(&c);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ_MSG(1, st.ds_events_dropped, DEPTH_FMT, DEPTH_ARGS);
	ATF_CHECK_EQ_MSG(2, st.ds_queue_highwater, DEPTH_FMT, DEPTH_ARGS);
#undef DEPTH_FMT
#undef DEPTH_ARGS
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
	/* Nothing reached the queue. */
	dqt_msleep(100);
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
	FILE *fp;
	u_int old;
	int i, oracle;

	ATF_REQUIRE(dqt_sysctl_get_uint(inflight_sysctl, &old));
	fp = fopen(inflight_saved, "w");
	ATF_REQUIRE(fp != NULL);
	fprintf(fp, "%u\n", old);
	fclose(fp);
	dqt_sysctl_set_uint(inflight_sysctl, 2);

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
	 * for the two, then give the third time to have reached its sleep.
	 */
	ATF_CHECK(dqt_wait_stats(&c, posted_or_dropped_is, 2, DQT_WAIT_MS));
	dqt_msleep(200);
	dqt_stats(&c, &st);
#define	INFL_FMT "current %ju posted %ju dropped %ju delivered %ju " \
	"inflight %ju; harness reads %u paused_reads %u records %u"
#define	INFL_ARGS \
	(uintmax_t)st.ds_queue_current, (uintmax_t)st.ds_events_posted, \
	(uintmax_t)st.ds_events_dropped, (uintmax_t)st.ds_events_delivered, \
	(uintmax_t)st.ds_inflight, c.reads, c.paused_reads, c.records
	ATF_CHECK_EQ_MSG(2, st.ds_queue_current, INFL_FMT, INFL_ARGS);
	ATF_CHECK_EQ_MSG(2, st.ds_events_posted, INFL_FMT, INFL_ARGS);
	ATF_CHECK_EQ_MSG(0, st.ds_events_dropped, INFL_FMT, INFL_ARGS);
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
	dqt_sysctl_set_uint(inflight_sysctl, old);
}
ATF_TC_CLEANUP(inflight_bound, tc)
{
	FILE *fp;
	u_int old;

	fp = fopen(inflight_saved, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%u", &old) == 1)
		(void)sysctlbyname(inflight_sysctl, NULL, NULL, &old,
		    sizeof(old));
	fclose(fp);
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
		ATF_CHECK_EQ(digest(data + i * (DATA_LEN / NTHREADS), 4096),
		    r.hash[i]);
	}
	/* The readers are stopped: their records are read without the lock. */
	dqt_stop(&c);
	ATF_CHECK_EQ(NTHREADS * 8, c.events[DQ_OP_READ]);
	ATF_REQUIRE_EQ(NTHREADS * 8, c.nseqs);
	qsort(c.seqs, (size_t)c.nseqs, sizeof(c.seqs[0]), cmp_u64);
	for (i = 0; i < c.nseqs; i++)
		ATF_CHECK_EQ_MSG((uint64_t)i + 1, c.seqs[i],
		    "seq %d is %ju: a duplicate or a gap", i,
		    (uintmax_t)c.seqs[i]);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	ATF_CHECK_EQ(NTHREADS * 8, st.ds_events_delivered);
	ATF_CHECK_EQ(NTHREADS * 8, st.ds_replies);
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
	ATF_TP_ADD_TC(tp, sigalrm_interrupt);
	ATF_TP_ADD_TC(tp, reply_racing_signal);
	ATF_TP_ADD_TC(tp, depth_exhausted);
	ATF_TP_ADD_TC(tp, edeadlk_controller);
	ATF_TP_ADD_TC(tp, edeadlk_pdfork);
	ATF_TP_ADD_TC(tp, inflight_bound);
	ATF_TP_ADD_TC(tp, two_readers);
	ATF_TP_ADD_TC(tp, efault_mid_batch);
	return (atf_no_error());
}
