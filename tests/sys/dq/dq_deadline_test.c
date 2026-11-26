/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Deadlines (design 15, D3): an unanswered event fails the requester with
 * EIO when the object's deadline passes; dp_deadline_ms = 0 waits for the
 * reply; SIGKILL always breaks a wait (I12).  The withdraw_* cases pin how
 * both waited posts give an event up (pending or delivered, deadline or
 * signal).
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dqt.h"

#define	DATA_LEN	8192

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct timed_arg {
	int		 fd;
	size_t		 len;
};

struct timed_res {
	struct dqt_rr	 rr;
	long		 elapsed_ms;
};

/* read(2) once and time it. */
static void
child_timed_read(void *arg, void *result)
{
	struct timed_arg *a = arg;
	struct timed_res *r = result;
	unsigned char buf[4096];
	long start;

	start = dqt_now_ms();
	r->rr.rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->rr.err = r->rr.rv == -1 ? errno : 0;
	r->elapsed_ms = dqt_now_ms() - start;
}

ATF_TC(small_deadline_eio);
ATF_TC_HEAD(small_deadline_eio, tc)
{
	atf_tc_set_md_var(tc, "descr", "an event unanswered past dp_deadline_ms "
	    "fails the requester with EIO and counts a deadline miss");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(small_deadline_eio, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct timed_arg a;
	struct timed_res r;
	struct dq_stats st;
	int n, oracle;

	dqt_fill(data, sizeof(data), 71);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 200;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_timed_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EIO, r.rr.err);
	ATF_CHECK_MSG(r.elapsed_ms >= 200, "returned after %ld ms",
	    r.elapsed_ms);
	ATF_CHECK_MSG(r.elapsed_ms < 5000, "returned after %ld ms",
	    r.elapsed_ms);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_deadline_misses);
	ATF_CHECK_EQ(0, st.ds_inflight);
	/*
	 * The deadline runs from the post, so whether the controller read
	 * the event before it is up to the scheduler: a loaded guest may not
	 * run the reader thread within 200 ms.  A withdrawn pending event can
	 * never be read afterwards, so after the fence the held count says
	 * which it was.  Still pending, it was withdrawn silently with no
	 * record (withdraw_read_pending_deadline pins that).  Read, the
	 * expiry abandons a delivered event exactly as EINTR does (design
	 * 8.2): one INTERRUPT record naming it, and the controller's reply
	 * is late.
	 */
	dqt_fence(&c);
	dqt_lock(&c);
	n = c.nheld;
	dqt_unlock(&c);
	printf("the controller read the event before its deadline: %s\n",
	    n == 1 ? "yes" : "no");
	if (n == 0) {
		ATF_CHECK_EQ(0, dqt_events(&c, DQ_OP_INTERRUPT));
		dqt_fini(&c);
		(void)close(oracle);
		return;
	}
	ATF_REQUIRE_EQ(1, n);
	ATF_REQUIRE(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(c.held[0].id, c.interrupted[0]);
	ATF_CHECK_EQ(1, c.events[DQ_OP_INTERRUPT]);
	dqt_unlock(&c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 100));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(deadline_zero_waits);
ATF_TC_HEAD(deadline_zero_waits, tc)
{
	atf_tc_set_md_var(tc, "descr", "dp_deadline_ms = 0 waits for the reply "
	    "however late");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deadline_zero_waits, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct timed_arg a;
	struct timed_res r;
	struct dq_stats st;
	int oracle;

	dqt_fill(data, sizeof(data), 72);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_set_reply_delay(&c, 600);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_timed_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(100, r.rr.rv);
	ATF_CHECK_MSG(r.elapsed_ms >= 600, "returned after %ld ms",
	    r.elapsed_ms);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_deadline_misses);
	ATF_CHECK_EQ(1, st.ds_replies);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(default_deadline_accepted);
ATF_TC_HEAD(default_deadline_accepted, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_DEADLINE_DEFAULT is accepted and "
	    "answered through kern.dq.default_deadline_ms; a smaller value is "
	    "refused");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(default_deadline_accepted, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct dq_ident_file *ident;
	struct timed_arg a;
	struct timed_res r;
	uint64_t object;
	int fd, oracle, reason;

	dqt_fill(data, sizeof(data), 73);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	ATF_CHECK_EQ(DQ_DEADLINE_DEFAULT, pol.dp_deadline_ms);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_timed_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(100, r.rr.rv);

	ident = calloc(1, sizeof(*ident));
	ATF_REQUIRE(ident != NULL);
	*ident = o->ident;
	pol.dp_deadline_ms = DQ_DEADLINE_DEFAULT - 1;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_mint_file(c.q, ident, &pol, &object, &fd, &reason));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(DQ_REASON_POLICY, reason);
	free(ident);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(setpolicy_deadline);
ATF_TC_HEAD(setpolicy_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_SETPOLICY changes the deadline "
	    "of a minted object; the next event uses it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setpolicy_deadline, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct timed_arg a;
	struct timed_res r;
	struct dq_stats st;
	int oracle;

	dqt_fill(data, sizeof(data), 74);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	pol.dp_deadline_ms = 200;
	ATF_REQUIRE_MSG(dq_set_policy(c.q, o->id, &pol) == 0,
	    "DQ_IOC_SETPOLICY: %s", strerror(errno));
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_timed_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EIO, r.rr.err);
	ATF_CHECK(r.elapsed_ms >= 200);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_deadline_misses);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(sigkill_breaks_wait);
ATF_TC_HEAD(sigkill_breaks_wait, tc)
{
	atf_tc_set_md_var(tc, "descr", "SIGKILL breaks a requester's wait with "
	    "no deadline; the delivered event becomes an INTERRUPT (I12)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(sigkill_breaks_wait, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct timed_arg a;
	struct timed_res r;
	struct dqt_child ch;
	struct dq_stats st;
	int oracle, status;

	dqt_fill(data, sizeof(data), 75);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_timed_read, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGKILL));
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(SIGKILL, WTERMSIG(status));
	ATF_REQUIRE(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(c.held[0].id, c.interrupted[0]);
	dqt_unlock(&c);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_interrupts);
	ATF_CHECK_EQ(0, st.ds_inflight);
	ATF_CHECK_EQ(0, st.ds_deadline_misses);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * T-R03: the quota sleep before a post.  QUOTA_HOLDERS threads of the
 * child pread the first object and are held unanswered; once the
 * controller holds them all, the child's main thread preads the second
 * object (the same one for the per-object quota) and times the call.
 * SIGALRM, with a handler installed without SA_RESTART, arrives after
 * alarm_s seconds (0: none); the holders block it, so it interrupts the
 * main thread.
 */
#define	QUOTA_HOLDERS	2

struct quota_arg {
	int		 hold_fd;	/* the holders' object */
	int		 fd;		/* the timed read's */
	int		 go[2];		/* the test says: all held */
	unsigned	 alarm_s;
};

static void
quota_alarm(int sig __unused)
{
}

static void *
quota_holder(void *arg)
{
	unsigned char buf[16];

	(void)pread(*(int *)arg, buf, sizeof(buf), 0);
	return (NULL);
}

static void
child_quota_read(void *argp, void *result)
{
	struct quota_arg *a = argp;
	struct timed_res *r = result;
	struct sigaction sa;
	pthread_t thr[QUOTA_HOLDERS];
	sigset_t set, oset;
	unsigned char buf[16];
	long start;
	int i;
	char c;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = quota_alarm;
	(void)sigaction(SIGALRM, &sa, NULL);
	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	(void)pthread_sigmask(SIG_BLOCK, &set, &oset);
	for (i = 0; i < QUOTA_HOLDERS; i++)
		(void)pthread_create(&thr[i], NULL, quota_holder, &a->hold_fd);
	(void)pthread_sigmask(SIG_SETMASK, &oset, NULL);
	if (read(a->go[0], &c, 1) != 1)
		_exit(DQT_EXIT_NOGO);
	if (a->alarm_s != 0)
		(void)alarm(a->alarm_s);
	start = dqt_now_ms();
	r->rr.rv = pread(a->fd, buf, sizeof(buf), 0);
	r->rr.err = r->rr.rv == -1 ? errno : 0;
	r->elapsed_ms = dqt_now_ms() - start;
	(void)alarm(0);
	/* The holders end with the process. */
}

static void
quota_run(struct dqt_ctl *c, struct quota_arg *a, struct timed_res *r)
{
	struct dqt_child ch;

	ATF_REQUIRE(pipe(a->go) == 0);
	dqt_spawn(&ch, child_quota_read, a);
	ATF_REQUIRE(dqt_wait_held(c, QUOTA_HOLDERS, DQT_WAIT_MS));
	ATF_REQUIRE(write(a->go[1], "g", 1) == 1);
	dqt_collect(&ch, r, sizeof(*r));
	(void)close(a->go[0]);
	(void)close(a->go[1]);
}

#define	QUOTA_REQUESTER	"kern.dq.max_inflight_per_requester"
#define	QUOTA_OBJECT	"kern.dq.max_inflight_per_object"

ATF_TC_WITH_CLEANUP(quota_requester_bounded);
ATF_TC_HEAD(quota_requester_bounded, tc)
{
	atf_tc_set_md_var(tc, "descr", "the per-requester quota held by "
	    "events of a deadline-0 object: a read of a 200 ms object waits "
	    "for its post no longer than its deadline (T-R03)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(quota_requester_bounded, tc)
{
	struct dqt_ctl c;
	struct dqt_object *x, *y;
	struct dq_policy pol;
	struct quota_arg a;
	struct timed_res r;
	int oracle;

	dqt_sysctl_save_set_uint(QUOTA_REQUESTER, QUOTA_HOLDERS);
	dqt_fill(data, sizeof(data), 76);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	x = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	pol.dp_deadline_ms = 200;
	y = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);

	memset(&a, 0, sizeof(a));
	a.hold_fd = x->fd;
	a.fd = y->fd;
	a.alarm_s = 1;
	quota_run(&c, &a, &r);
	/*
	 * The quota sleep is bounded by the event's 200 ms deadline: EIO
	 * then, well before the 1 s signal (it waited for the signal).
	 */
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EIO, r.rr.err);
	ATF_CHECK_MSG(r.elapsed_ms >= 150 && r.elapsed_ms < 900,
	    "returned after %ld ms", r.elapsed_ms);
	/* Only the holders' events were ever posted. */
	dqt_lock(&c);
	ATF_CHECK_EQ(QUOTA_HOLDERS, c.nheld);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(QUOTA_REQUESTER));
}
ATF_TC_CLEANUP(quota_requester_bounded, tc)
{

	(void)dqt_sysctl_restore(QUOTA_REQUESTER);
}

ATF_TC_WITH_CLEANUP(quota_object_one_deadline);
ATF_TC_HEAD(quota_object_one_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "the per-object quota held by events "
	    "of the same 1 s policy: the read behind it fails EIO at its own "
	    "deadline (T-R03)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(quota_object_one_deadline, tc)
{
	struct dqt_ctl c;
	struct dqt_object *x;
	struct dq_policy pol;
	struct quota_arg a;
	struct timed_res r;
	int oracle;

	dqt_sysctl_save_set_uint(QUOTA_OBJECT, QUOTA_HOLDERS);
	dqt_fill(data, sizeof(data), 77);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 1000;
	x = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);

	memset(&a, 0, sizeof(a));
	a.hold_fd = x->fd;
	a.fd = x->fd;
	quota_run(&c, &a, &r);
	ATF_CHECK_EQ(-1, r.rr.rv);
	ATF_CHECK_EQ(EIO, r.rr.err);
	/*
	 * The event's deadline is absolute, taken before the quota sleep:
	 * the holders' expiry wakes the sleeper just before it, and the
	 * post then waits only what is left.  One deadline in all.
	 */
	ATF_CHECK_MSG(r.elapsed_ms >= 950 && r.elapsed_ms <= 1600,
	    "returned after %ld ms", r.elapsed_ms);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(QUOTA_OBJECT));
}
ATF_TC_CLEANUP(quota_object_one_deadline, tc)
{

	(void)dqt_sysctl_restore(QUOTA_OBJECT);
}

/*
 * The withdrawal of a waited event its requester gave up on, for both
 * waited posts (an object's READ and an attached process's RESOLVE), each
 * way it can be given up: the event still pending (the controller never
 * read it) or delivered (it did), by the deadline or by a caught signal of
 * an interruptible wait.  Pending: the controller sees nothing of it, no
 * INTERRUPT, and only the deadline is counted.  Delivered: one INTERRUPT
 * names it, the deadline counts a miss and the signal an interrupt, and
 * the late reply is ESRCH.  Either way the requester's next call on the
 * same queue is posted and answered, so nothing it held (the slot, the
 * quotas) is left behind.
 */
enum wd_at { WD_PENDING, WD_DELIVERED };
enum wd_by { WD_DEADLINE, WD_SIGNAL };

struct wd_arg {
	int		 fd;		/* READ: the served file */
	int		 go[2];		/* the test says: post the second call */
};

struct wd_res {
	struct dqt_rr	 first;
	struct dqt_rr	 second;
	int		 signals;
};

static volatile sig_atomic_t wd_signals;

static void
wd_on_signal(int sig __unused)
{

	wd_signals++;
}

/* Catch sig without SA_RESTART, so a caught signal ends the call. */
static void
wd_catch(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = wd_on_signal;
	(void)sigaction(sig, &sa, NULL);
}

static void
wd_child_read(void *argp, void *result)
{
	struct wd_arg *a = argp;
	struct wd_res *r = result;
	unsigned char buf[100];
	char g;

	wd_catch(SIGALRM);
	DQT_RR(r->first, pread(a->fd, buf, sizeof(buf), 0));
	if (read(a->go[0], &g, 1) != 1)
		_exit(DQT_EXIT_NOGO);
	DQT_RR(r->second, pread(a->fd, buf, sizeof(buf), 0));
	r->signals = wd_signals;
}

static void
wd_child_stat(void *argp, void *result)
{
	struct wd_arg *a = argp;
	struct wd_res *r = result;
	struct stat sb;
	char g;

	wd_catch(SIGUSR1);
	DQT_RR(r->first, stat("wd-first", &sb));
	if (read(a->go[0], &g, 1) != 1)
		_exit(DQT_EXIT_NOGO);
	DQT_RR(r->second, stat("wd-second", &sb));
	r->signals = wd_signals;
}

/* Nothing queued and nothing in flight: the event was withdrawn. */
static bool
wd_pred_withdrawn(const struct dq_stats *st, uintptr_t unused __unused)
{

	return (st->ds_queue_current == 0 && st->ds_inflight == 0);
}

/*
 * Bring the first call to where it is given up: pending or delivered
 * (held), then signalled if by is WD_SIGNAL; wait until it is withdrawn.
 */
static void
wd_give_up(struct dqt_ctl *c, pid_t pid, int sig, enum wd_at at,
    enum wd_by by)
{

	if (at == WD_PENDING)
		ATF_REQUIRE(dqt_wait_stats(c, dqt_pred_current, 1,
		    DQT_WAIT_MS));
	else
		ATF_REQUIRE(dqt_wait_held(c, 1, DQT_WAIT_MS));
	if (by == WD_SIGNAL) {
		ATF_REQUIRE(dqt_wait_wmesg(pid, DQT_WMESG_REPLY,
		    DQT_WAIT_MS));
		ATF_REQUIRE_EQ(0, kill(pid, sig));
	}
	ATF_REQUIRE(dqt_wait_stats(c, wd_pred_withdrawn, 0, DQT_WAIT_MS));
}

/* What the controller saw of the first event, and the counters. */
static void
wd_check(struct dqt_ctl *c, const struct wd_res *r, enum wd_at at,
    enum wd_by by, uint64_t interrupts_before, bool resolve)
{
	struct dq_stats st;
	uint64_t id;
	int rv;

	ATF_CHECK_EQ(-1, r->first.rv);
	ATF_CHECK_EQ(by == WD_DEADLINE ? EIO : EINTR, r->first.err);
	ATF_CHECK_EQ(by == WD_SIGNAL ? 1 : 0, r->signals);
	ATF_CHECK_MSG(r->second.rv >= 0, "second call: %s",
	    strerror(r->second.err));
	dqt_stats(c, &st);
	ATF_CHECK_EQ(by == WD_DEADLINE ? 1u : 0u, st.ds_deadline_misses);
	ATF_CHECK_EQ(at == WD_DELIVERED && by == WD_SIGNAL ? 1u : 0u,
	    st.ds_interrupts - interrupts_before);
	ATF_CHECK_EQ(0, st.ds_inflight);
	ATF_CHECK_EQ(0, st.ds_queue_current);
	if (at == WD_PENDING) {
		/* Withdrawn silently: no record of it, no INTERRUPT. */
		dqt_msleep(200);
		ATF_CHECK_EQ(0, dqt_events(c, DQ_OP_INTERRUPT));
		return;
	}
	ATF_REQUIRE(dqt_wait_interrupts(c, 1, DQT_WAIT_MS));
	dqt_lock(c);
	ATF_CHECK_EQ(1, c->ninterrupted);
	ATF_CHECK_EQ(c->held[0].id, c->interrupted[0]);
	dqt_unlock(c);
	id = dqt_held_id(c, 0);
	errno = 0;
	rv = resolve ? dq_reply_resolve_pass(c->q, id) :
	    dq_reply(c->q, id, 0, data, 100);
	ATF_CHECK_EQ(-1, rv);
	ATF_CHECK_EQ(ESRCH, errno);
}

static void
wd_object(enum wd_at at, enum wd_by by, unsigned seed)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct dqt_child ch;
	struct wd_arg a;
	struct wd_res r;
	int oracle;

	dqt_fill(data, sizeof(data), seed);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	if (by == WD_DEADLINE) {
		pol.dp_deadline_ms = 300;
	} else {
		pol.dp_deadline_ms = 0;
		pol.dp_flags = DQ_PF_INTR;
	}
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	if (at == WD_PENDING)
		dqt_pause(&c);
	else
		dqt_hold(&c, true);

	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	ATF_REQUIRE_EQ(0, pipe(a.go));
	dqt_spawn(&ch, wd_child_read, &a);
	wd_give_up(&c, ch.pid, SIGALRM, at, by);
	if (at == WD_PENDING)
		dqt_resume(&c);
	else
		dqt_hold(&c, false);
	ATF_REQUIRE_EQ(1, write(a.go[1], "g", 1));
	memset(&r, 0, sizeof(r));
	dqt_collect(&ch, &r, sizeof(r));
	/* Pending: the controller read only the second READ. */
	ATF_CHECK_EQ(at == WD_PENDING ? 1u : 2u, dqt_events(&c, DQ_OP_READ));
	wd_check(&c, &r, at, by, 0, false);
	dqt_fini(&c);
	(void)close(a.go[0]);
	(void)close(a.go[1]);
	(void)close(oracle);
}

#define	DEFAULT_DEADLINE	"kern.dq.default_deadline_ms"

static void
wd_resolve(enum wd_at at, enum wd_by by)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct dq_stats st;
	struct wd_arg a;
	struct wd_res r;
	int fd;

	fd = open("wd-second", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	(void)close(fd);
	if (by == WD_DEADLINE)
		dqt_sysctl_save_set_uint(DEFAULT_DEADLINE, 300);
	dqt_init(&c);
	if (by == WD_SIGNAL)
		ATF_REQUIRE_EQ(0, dq_queue_set_flags(c.q, DQ_QF_INTR, 0,
		    NULL));
	if (at == WD_PENDING)
		dqt_pause(&c);
	else
		dqt_resolve_hold(&c, "wd-first", 0);
	dqt_stats(&c, &st);

	memset(&a, 0, sizeof(a));
	ATF_REQUIRE_EQ(0, pipe(a.go));
	dqt_attach_spawn(&c, &ch, wd_child_stat, &a);
	wd_give_up(&c, ch.pid, SIGUSR1, at, by);
	if (at == WD_PENDING)
		dqt_resume(&c);
	else
		dqt_resolve_hold(&c, "", 0);
	ATF_REQUIRE_EQ(1, write(a.go[1], "g", 1));
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(at == WD_PENDING ? 0 : 1,
	    dqt_count_resolve(&c, "wd-first", 0));
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "wd-second", 0));
	wd_check(&c, &r, at, by, st.ds_interrupts, true);
	dqt_fini(&c);
	(void)close(a.go[0]);
	(void)close(a.go[1]);
	if (by == WD_DEADLINE)
		ATF_REQUIRE(dqt_sysctl_restore(DEFAULT_DEADLINE));
}

#define	WD_OBJECT_TC(name, at, by, seed)				\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", "a READ given up " #at " by "	\
	    #by ": the withdrawal's errno, record and counters");	\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "timeout", "60");				\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	wd_object(at, by, seed);					\
}

#define	WD_RESOLVE_TC(name, at, by)					\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", "a RESOLVE given up " #at " by "	\
	    #by ": the withdrawal's errno, record and counters");	\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "timeout", "60");				\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	wd_resolve(at, by);						\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	if ((by) == WD_DEADLINE)					\
		(void)dqt_sysctl_restore(DEFAULT_DEADLINE);		\
}

/*
 * A READ given up delivered by a signal caught with SA_RESTART: the wait
 * ends with ERESTART, which withdraws the event as EINTR does (one
 * INTERRUPT names it, one interrupt counted, its late reply is ESRCH), and
 * the restarted pread(2) posts a new READ whose answer the caller gets.
 */
struct wr_res {
	struct dqt_rr	 rr;
	int		 signals;
	int		 same;
};

static void
wr_child_read(void *argp, void *result)
{
	struct wd_arg *a = argp;
	struct wr_res *r = result;
	struct sigaction sa;
	unsigned char buf[100];

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = wd_on_signal;
	sa.sa_flags = SA_RESTART;
	(void)sigaction(SIGALRM, &sa, NULL);
	DQT_RR(r->rr, pread(a->fd, buf, sizeof(buf), 0));
	r->signals = wd_signals;
	r->same = r->rr.rv == (ssize_t)sizeof(buf) &&
	    memcmp(buf, data, sizeof(buf)) == 0;
}

ATF_TC(withdraw_read_delivered_restart);
ATF_TC_HEAD(withdraw_read_delivered_restart, tc)
{
	atf_tc_set_md_var(tc, "descr", "a READ given up delivered by an "
	    "SA_RESTART signal: one INTERRUPT, then the restarted READ is "
	    "posted and answered");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(withdraw_read_delivered_restart, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct dqt_child ch;
	struct dq_stats st;
	struct wd_arg a;
	struct wr_res r;
	uint64_t first, second;
	int oracle;

	dqt_fill(data, sizeof(data), 85);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	pol.dp_flags = DQ_PF_INTR;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);

	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	dqt_spawn(&ch, wr_child_read, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_wmesg(ch.pid, DQT_WMESG_REPLY, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, kill(ch.pid, SIGALRM));
	/* The restarted READ is posted and held in its turn. */
	ATF_REQUIRE(dqt_wait_held(&c, 2, DQT_WAIT_MS));
	ATF_REQUIRE(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	first = dqt_held_id(&c, 0);
	second = dqt_held_id(&c, 1);
	ATF_CHECK(first != second);
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.ninterrupted);
	ATF_CHECK_EQ(first, c.interrupted[0]);
	dqt_unlock(&c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, first, 0, data, 100));
	ATF_CHECK_EQ(ESRCH, errno);
	ATF_REQUIRE_EQ(0, dq_reply(c.q, second, 0, data, 100));
	memset(&r, 0, sizeof(r));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(100, r.rr.rv, "restarted pread: %s",
	    strerror(r.rr.err));
	ATF_CHECK(r.same);
	ATF_CHECK_EQ(1, r.signals);
	ATF_CHECK_EQ(2u, dqt_events(&c, DQ_OP_READ));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1u, st.ds_interrupts);
	ATF_CHECK_EQ(0u, st.ds_deadline_misses);
	ATF_CHECK_EQ(0, st.ds_inflight);
	ATF_CHECK_EQ(0, st.ds_queue_current);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

WD_OBJECT_TC(withdraw_read_pending_deadline, WD_PENDING, WD_DEADLINE, 81)
WD_OBJECT_TC(withdraw_read_pending_signal, WD_PENDING, WD_SIGNAL, 82)
WD_OBJECT_TC(withdraw_read_delivered_deadline, WD_DELIVERED, WD_DEADLINE, 83)
WD_OBJECT_TC(withdraw_read_delivered_signal, WD_DELIVERED, WD_SIGNAL, 84)
WD_RESOLVE_TC(withdraw_resolve_pending_deadline, WD_PENDING, WD_DEADLINE)
WD_RESOLVE_TC(withdraw_resolve_pending_signal, WD_PENDING, WD_SIGNAL)
WD_RESOLVE_TC(withdraw_resolve_delivered_deadline, WD_DELIVERED, WD_DEADLINE)
WD_RESOLVE_TC(withdraw_resolve_delivered_signal, WD_DELIVERED, WD_SIGNAL)

/*
 * The deadline-0 matrix (rev 8 3.5 B1, owed by C8; round 2 R2-0): every
 * object wait that catches no signal, on an object with no deadline,
 * whose answer the controller holds, while the process goes away or its
 * main thread leaves:
 * - exit_sibling: thread B calls _exit(0).  The waiter sees the exit's
 *   single-threading and gives its event up: the process exits 0 and the
 *   controller gets the INTERRUPT;
 * - sigkill: the test sends SIGKILL: killed, one INTERRUPT;
 * - pthread_exit_main: the main thread calls pthread_exit(3).  The
 *   process is not dying: the wait goes on until the controller answers,
 *   the call completes with that answer, and no INTERRUPT is posted.
 * The case timeout is the hang detector: no wait here has a deadline.
 */
enum d0_site { D0_READ, D0_WRITE, D0_FSTAT, D0_FSYNC };
enum d0_end { D0_EXIT_SIBLING, D0_SIGKILL, D0_PTHREAD_EXIT_MAIN };

struct d0_arg {
	int		 fd;
	enum d0_site	 site;
	enum d0_end	 end;
	int		 go[2];		/* the test: end now */
	int		 gone[2];	/* the joiner: main has exited */
	pthread_t	 main;
};

/* The site's call: 0, or its errno. */
static int
d0_call(const struct d0_arg *a)
{
	unsigned char buf[16];
	struct stat sb;

	switch (a->site) {
	case D0_READ:
		return (pread(a->fd, buf, sizeof(buf), 0) ==
		    (ssize_t)sizeof(buf) ? 0 : errno);
	case D0_WRITE:
		memset(buf, 'w', sizeof(buf));
		return (pwrite(a->fd, buf, 10, 0) == 10 ? 0 : errno);
	case D0_FSTAT:
		return (fstat(a->fd, &sb) == 0 ? 0 : errno);
	case D0_FSYNC:
		return (fsync(a->fd) == 0 ? 0 : errno);
	}
	return (EINVAL);
}

static void *
d0_waiter(void *arg)
{
	struct d0_arg *a = arg;
	int error;

	error = d0_call(a);
	/* After pthread_exit_main this thread ends the process. */
	if (a->end == D0_PTHREAD_EXIT_MAIN)
		_exit(error == 0 ? 0 : 10);
	return (NULL);
}

static void *
d0_joiner(void *arg)
{
	struct d0_arg *a = arg;

	(void)pthread_join(a->main, NULL);
	(void)write(a->gone[1], "x", 1);
	return (NULL);
}

static void
d0_child(struct d0_arg *a)
{
	pthread_t thr, joiner;
	char ch;

	if (pthread_create(&thr, NULL, d0_waiter, a) != 0)
		_exit(3);
	if (a->end == D0_PTHREAD_EXIT_MAIN) {
		a->main = pthread_self();
		if (pthread_create(&joiner, NULL, d0_joiner, a) != 0)
			_exit(3);
	}
	if (read(a->go[0], &ch, 1) != 1)
		_exit(4);
	if (a->end == D0_PTHREAD_EXIT_MAIN)
		pthread_exit(NULL);
	_exit(0);
}

static void
d0_answer(struct dqt_ctl *c, struct dqt_object *o, enum d0_site site)
    __requires_unlocked(c->mtx)
{
	uint64_t id;
	int rv;

	id = dqt_held_id(c, 0);
	switch (site) {
	case D0_READ:
		rv = dq_reply(c->q, id, 0, data, 16);
		break;
	case D0_WRITE:
		rv = dq_reply_write(c->q, id, 10, 0);
		break;
	case D0_FSTAT:
		rv = dq_reply(c->q, id, 0, &o->ident, sizeof(o->ident));
		break;
	case D0_FSYNC:
	default:
		rv = dq_reply(c->q, id, 0, NULL, 0);
		break;
	}
	ATF_REQUIRE_MSG(rv == 0, "reply: %s", strerror(errno));
}

static void
d0_case(enum d0_site site, enum d0_end end, unsigned seed)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct d0_arg a;
	int oracle, status;
	pid_t pid;
	char ch;

	dqt_fill(data, sizeof(data), seed);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_deadline_ms = 0;
	if (site == D0_FSTAT)
		pol.dp_events |= DQ_EVENTS_GETATTR;
	{
		struct dq_ident_file id;
		struct statfs sfs;
		struct stat sb;

		dqt_ident_of(oracle, oracle_path, &id, &sb, &sfs);
		o = dqt_mint_ident_flags(&c, &id, &pol, DQ_MINT_F_WRITE, data,
		    sizeof(data));
	}
	dqt_hold(&c, true);
	memset(&a, 0, sizeof(a));
	a.fd = o->fd;
	a.site = site;
	a.end = end;
	ATF_REQUIRE_EQ(0, pipe(a.go));
	ATF_REQUIRE_EQ(0, pipe(a.gone));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		d0_child(&a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	switch (end) {
	case D0_EXIT_SIBLING:
		ATF_REQUIRE_EQ(1, write(a.go[1], "g", 1));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "status %#x", status);
		ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
		break;
	case D0_SIGKILL:
		ATF_REQUIRE_EQ(0, kill(pid, SIGKILL));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFSIGNALED(status) &&
		    WTERMSIG(status) == SIGKILL, "status %#x", status);
		ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
		break;
	case D0_PTHREAD_EXIT_MAIN:
		ATF_REQUIRE_EQ(1, write(a.go[1], "g", 1));
		/* The joiner says the main thread is gone. */
		ATF_REQUIRE_EQ(1, read(a.gone[0], &ch, 1));
		d0_answer(&c, o, site);
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "the waiting call failed or the process died: status %#x",
		    status);
		/* Every record posted before the fence has been read. */
		dqt_fence(&c);
		dqt_lock(&c);
		ATF_CHECK_EQ(0, c.ninterrupted);
		dqt_unlock(&c);
		break;
	}
	(void)close(a.go[0]);
	(void)close(a.go[1]);
	(void)close(a.gone[0]);
	(void)close(a.gone[1]);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

#define	D0_TC(name, site, end, seed)					\
ATF_TC(name);								\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", "deadline-0 matrix: " #site	\
	    " waiting with no deadline, ended by " #end);	\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "timeout", "60");				\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	d0_case(site, end, seed);					\
}

D0_TC(read_deadline0_sigkill, D0_READ, D0_SIGKILL, 90)
D0_TC(read_deadline0_pthread_exit_main, D0_READ, D0_PTHREAD_EXIT_MAIN, 91)
D0_TC(write_deadline0_exit_sibling, D0_WRITE, D0_EXIT_SIBLING, 92)
D0_TC(write_deadline0_sigkill, D0_WRITE, D0_SIGKILL, 93)
D0_TC(write_deadline0_pthread_exit_main, D0_WRITE, D0_PTHREAD_EXIT_MAIN, 94)
D0_TC(fstat_deadline0_exit_sibling, D0_FSTAT, D0_EXIT_SIBLING, 95)
D0_TC(fstat_deadline0_sigkill, D0_FSTAT, D0_SIGKILL, 96)
D0_TC(fstat_deadline0_pthread_exit_main, D0_FSTAT, D0_PTHREAD_EXIT_MAIN, 97)
D0_TC(fsync_deadline0_exit_sibling, D0_FSYNC, D0_EXIT_SIBLING, 98)
D0_TC(fsync_deadline0_sigkill, D0_FSYNC, D0_SIGKILL, 99)
D0_TC(fsync_deadline0_pthread_exit_main, D0_FSYNC, D0_PTHREAD_EXIT_MAIN, 100)

/*
 * The quota sleep × exit_sibling (rev 8 3.5 B1): thread H holds the
 * object's one in-flight slot (a READ the controller holds); thread A's
 * READ of the same deadline-0 object sleeps for that quota; thread B
 * calls _exit(0).  The sleep sees the exit's single-threading and ends:
 * the process exits 0, and only H's delivered READ gets an INTERRUPT (A's
 * was never posted).  The sleep is seen through the knob tier's hook
 * (debug.dq.quota_sleep_wait), not a poll.
 */
struct d0q_arg {
	int		 fd;
	int		 go[2];
	int		 armed[2];
};

static void *
d0q_reader(void *arg)
{
	unsigned char buf[16];

	(void)pread(*(int *)arg, buf, sizeof(buf), 0);
	return (NULL);
}

ATF_TC_WITH_CLEANUP(quota_deadline0_exit_sibling);
ATF_TC_HEAD(quota_deadline0_exit_sibling, tc)
{
	atf_tc_set_md_var(tc, "descr", "deadline-0 matrix: a READ asleep for "
	    "the per-object in-flight quota is ended by a sibling's _exit; "
	    "the posted READ alone gets an INTERRUPT (rev 8 3.5)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(quota_deadline0_exit_sibling, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	pthread_t h, a;
	uint64_t slept;
	int fd, go[2], oracle, status;
	pid_t pid;
	char ch;

	dqt_require_fault_knob("debug.dq.quota_sleep_wait");
	dqt_sysctl_save_set_uint(QUOTA_OBJECT, 1);
	dqt_fill(data, sizeof(data), 101);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_deadline_ms = 0;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	dqt_hold(&c, true);
	fd = o->fd;
	ATF_REQUIRE_EQ(0, pipe(go));
	slept = dqt_quota_sleeps(DQT_QUOTA_OBJECT);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (pthread_create(&h, NULL, d0q_reader, &fd) != 0)
			_exit(3);
		if (read(go[0], &ch, 1) != 1)
			_exit(4);
		if (pthread_create(&a, NULL, d0q_reader, &fd) != 0)
			_exit(3);
		if (read(go[0], &ch, 1) != 1)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	dqt_quota_sleep_wait(DQT_QUOTA_OBJECT, slept + 1);
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "status %#x", status);
	ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	dqt_fence(&c);
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.ninterrupted);
	ATF_CHECK_EQ(1, c.nheld);	/* A's READ was never posted */
	dqt_unlock(&c);
	(void)close(go[0]);
	(void)close(go[1]);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	ATF_REQUIRE(dqt_sysctl_restore(QUOTA_OBJECT));
}
ATF_TC_CLEANUP(quota_deadline0_exit_sibling, tc)
{

	(void)dqt_sysctl_restore(QUOTA_OBJECT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, small_deadline_eio);
	ATF_TP_ADD_TC(tp, deadline_zero_waits);
	ATF_TP_ADD_TC(tp, default_deadline_accepted);
	ATF_TP_ADD_TC(tp, setpolicy_deadline);
	ATF_TP_ADD_TC(tp, sigkill_breaks_wait);
	ATF_TP_ADD_TC(tp, quota_requester_bounded);
	ATF_TP_ADD_TC(tp, quota_object_one_deadline);
	ATF_TP_ADD_TC(tp, withdraw_read_pending_deadline);
	ATF_TP_ADD_TC(tp, withdraw_read_pending_signal);
	ATF_TP_ADD_TC(tp, withdraw_read_delivered_deadline);
	ATF_TP_ADD_TC(tp, withdraw_read_delivered_signal);
	ATF_TP_ADD_TC(tp, withdraw_read_delivered_restart);
	ATF_TP_ADD_TC(tp, withdraw_resolve_pending_deadline);
	ATF_TP_ADD_TC(tp, withdraw_resolve_pending_signal);
	ATF_TP_ADD_TC(tp, withdraw_resolve_delivered_deadline);
	ATF_TP_ADD_TC(tp, withdraw_resolve_delivered_signal);
	ATF_TP_ADD_TC(tp, read_deadline0_sigkill);
	ATF_TP_ADD_TC(tp, read_deadline0_pthread_exit_main);
	ATF_TP_ADD_TC(tp, write_deadline0_exit_sibling);
	ATF_TP_ADD_TC(tp, write_deadline0_sigkill);
	ATF_TP_ADD_TC(tp, write_deadline0_pthread_exit_main);
	ATF_TP_ADD_TC(tp, fstat_deadline0_exit_sibling);
	ATF_TP_ADD_TC(tp, fstat_deadline0_sigkill);
	ATF_TP_ADD_TC(tp, fstat_deadline0_pthread_exit_main);
	ATF_TP_ADD_TC(tp, fsync_deadline0_exit_sibling);
	ATF_TP_ADD_TC(tp, fsync_deadline0_sigkill);
	ATF_TP_ADD_TC(tp, fsync_deadline0_pthread_exit_main);
	ATF_TP_ADD_TC(tp, quota_deadline0_exit_sibling);
	return (atf_no_error());
}
