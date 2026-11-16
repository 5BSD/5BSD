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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dq_test.h"

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

static long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

/* read(2) once and time it. */
static void
child_timed_read(void *arg, void *result)
{
	struct timed_arg *a = arg;
	struct timed_res *r = result;
	unsigned char buf[4096];
	long start;

	start = now_ms();
	r->rr.rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->rr.err = r->rr.rv == -1 ? errno : 0;
	r->elapsed_ms = now_ms() - start;
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
	dqt_lock(&c);
	ATF_CHECK_EQ(-1, dq_reply(c.q, c.held[0].id, 0, data, 100));
	dqt_unlock(&c);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, small_deadline_eio);
	ATF_TP_ADD_TC(tp, deadline_zero_waits);
	ATF_TP_ADD_TC(tp, default_deadline_accepted);
	ATF_TP_ADD_TC(tp, setpolicy_deadline);
	ATF_TP_ADD_TC(tp, sigkill_breaks_wait);
	return (atf_no_error());
}
