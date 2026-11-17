/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Deadlines (design 15, D3): an unanswered event fails the requester with
 * EIO when the object's deadline passes; dp_deadline_ms = 0 waits for the
 * reply; SIGKILL always breaks a wait (I12).
 */

#include <sys/param.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
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
	int oracle;

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
	 * The controller had read it, so the expiry abandons a delivered event
	 * exactly as EINTR does (design 8.2): one INTERRUPT record naming it,
	 * and the controller's reply is late.  An event still pending would
	 * have been withdrawn silently with no record.
	 */
	dqt_lock(&c);
	ATF_REQUIRE_EQ(1, c.nheld);
	dqt_unlock(&c);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, small_deadline_eio);
	ATF_TP_ADD_TC(tp, deadline_zero_waits);
	ATF_TP_ADD_TC(tp, default_deadline_accepted);
	ATF_TP_ADD_TC(tp, setpolicy_deadline);
	ATF_TP_ADD_TC(tp, sigkill_breaks_wait);
	ATF_TP_ADD_TC(tp, quota_requester_bounded);
	ATF_TP_ADD_TC(tp, quota_object_one_deadline);
	return (atf_no_error());
}
