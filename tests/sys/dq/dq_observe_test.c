/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The dq.observe service (D90): the system's view of every queue and
 * object, reached through /dev/mac_capability by a credential that may
 * open /dev/dq itself (stage 1a admission; the capsule rule is stage 4).
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	8192
#define	MAX_LIST	256

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct one_read_arg {
	int		 fd;
	size_t		 len;
};

static void
child_one_read(void *arg, void *result)
{
	struct one_read_arg *a = arg;
	struct dqt_rr *r = result;
	unsigned char buf[4096];

	r->rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->err = r->rv == -1 ? errno : 0;
}

static int
connect_or_skip(void)
{
	int svc;

	svc = dq_observe_connect();
	if (svc == -1) {
		if (errno == ENOENT)
			atf_tc_skip("%s: %s", DQ_MAC_CAPABILITY_DEVICE,
			    strerror(errno));
		atf_tc_fail("dq_observe_connect: %s", strerror(errno));
	}
	return (svc);
}

/* Find this queue in a full listing, paging through it. */
static bool
find_queue(int svc, uint64_t id, struct dqo_queue_info *out)
{
	struct dqo_queue_info *buf;
	size_t count, i;
	uint64_t first, total;
	bool found;

	buf = calloc(MAX_LIST, sizeof(*buf));
	ATF_REQUIRE(buf != NULL);
	found = false;
	first = 0;
	do {
		ATF_REQUIRE_MSG(dq_observe_list_queues(svc, first, buf, MAX_LIST,
		    &count, &total) == 0, "list queues: %s", strerror(errno));
		for (i = 0; i < count; i++) {
			if (buf[i].qi_id == id) {
				*out = buf[i];
				found = true;
			}
		}
		first += count;
	} while (count != 0 && first < total && !found);
	free(buf);
	return (found);
}

ATF_TC(connect_as_root);
ATF_TC_HEAD(connect_as_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "a root credential connects to "
	    "dq.observe and lists queues");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(connect_as_root, tc)
{
	struct dqo_queue_info buf[4];
	size_t count;
	uint64_t total;
	int q, svc;

	q = dqt_open_queue();
	svc = connect_or_skip();
	ATF_REQUIRE_EQ(0, dq_observe_list_queues(svc, 0, buf, nitems(buf),
	    &count, &total));
	ATF_CHECK(total >= 1);
	ATF_CHECK(count >= 1 && count <= nitems(buf));
	/* Paging past the end answers no entries and the same total. */
	ATF_REQUIRE_EQ(0, dq_observe_list_queues(svc, total, buf, nitems(buf),
	    &count, &total));
	ATF_CHECK_EQ(0, count);
	/* An empty buffer is a count: no entries, the total. */
	ATF_REQUIRE_EQ(0, dq_observe_list_queues(svc, 0, NULL, 0, &count,
	    &total));
	ATF_CHECK_EQ(0, count);
	ATF_CHECK(total >= 1);
	(void)close(svc);
	(void)close(q);
}

ATF_TC(list_queues);
ATF_TC_HEAD(list_queues, tc)
{
	atf_tc_set_md_var(tc, "descr", "the listing names this queue with its "
	    "controller pid, object count, pending and in-flight counts");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_queues, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqo_queue_info qi;
	struct dq_stats st;
	struct one_read_arg a;
	struct dqt_rr r;
	int obs, oracle, svc;

	dqt_fill(data, sizeof(data), 91);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	svc = connect_or_skip();
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	(void)dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	obs = dq_mint_observer(c.q, 0);
	ATF_REQUIRE(obs != -1);
	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(100, r.rv);

	dqt_stats(&c, &st);
	ATF_REQUIRE(find_queue(svc, st.ds_queue_id, &qi));
	ATF_CHECK_EQ(getpid(), qi.qi_pid);
	ATF_CHECK_EQ(getuid(), qi.qi_uid);
	ATF_CHECK_EQ(2, qi.qi_objects);
	ATF_CHECK_EQ(0, qi.qi_pending);
	ATF_CHECK_EQ(0, qi.qi_inflight);
	ATF_CHECK_EQ(st.ds_events_posted, qi.qi_posted);
	ATF_CHECK_EQ(1, qi.qi_posted);
	ATF_CHECK_EQ(0, qi.qi_dropped);
	ATF_CHECK_EQ(1, qi.qi_observers);
	ATF_CHECK_EQ(0, qi.qi_flags & DQO_QF_CLOSING);

	/* A held event shows as pending, then in flight. */
	dqt_pause(&c);
	{
		struct dqt_child ch;
		int status, waited;

		dqt_spawn(&ch, child_one_read, &a);
		/* Wait for the post rather than a fixed sleep (4-vCPU guest). */
		for (waited = 0; waited < DQT_WAIT_MS; waited += 10) {
			ATF_REQUIRE(find_queue(svc, st.ds_queue_id, &qi));
			if (qi.qi_pending != 0)
				break;
			dqt_msleep(10);
		}
		ATF_CHECK_EQ(1, qi.qi_pending);
		ATF_CHECK_EQ(0, qi.qi_inflight);
		dqt_hold(&c, true);
		dqt_resume(&c);
		ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
		ATF_REQUIRE(find_queue(svc, st.ds_queue_id, &qi));
		ATF_CHECK_EQ(0, qi.qi_pending);
		ATF_CHECK_EQ(1, qi.qi_inflight);
		ATF_REQUIRE_EQ(0, dq_reply(c.q, c.held[0].id, 0, data, 100));
		status = dqt_wait(&ch, &r, sizeof(r));
		ATF_CHECK(status == 0);
		ATF_CHECK_EQ(100, r.rv);
	}
	(void)close(obs);
	(void)close(svc);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(list_objects);
ATF_TC_HEAD(list_objects, tc)
{
	atf_tc_set_md_var(tc, "descr", "the object listing of a queue names "
	    "each object's id, kind, state, dev/ino, size, mode and path; an "
	    "unknown queue is ESRCH");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(list_objects, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o1, *o2;
	struct dqo_object_info oi[4];
	struct dq_stats st;
	size_t count, i;
	uint64_t total;
	int oracle, svc;
	bool saw1, saw2;

	dqt_fill(data, sizeof(data), 92);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	svc = connect_or_skip();
	o1 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	o2 = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o2->id));
	dqt_stats(&c, &st);

	ATF_REQUIRE_MSG(dq_observe_list_objects(svc, st.ds_queue_id, 0, oi,
	    nitems(oi), &count, &total) == 0, "list objects: %s",
	    strerror(errno));
	ATF_CHECK_EQ(2, total);
	ATF_REQUIRE_EQ(2, count);
	saw1 = saw2 = false;
	for (i = 0; i < count; i++) {
		ATF_CHECK_EQ(DQ_KIND_FILE, oi[i].oi_kind);
		ATF_CHECK_EQ(o1->ident.di_dev, oi[i].oi_dev);
		ATF_CHECK_EQ(o1->ident.di_ino, oi[i].oi_ino);
		ATF_CHECK_EQ(o1->ident.di_size, oi[i].oi_size);
		ATF_CHECK_EQ(o1->ident.di_mode, oi[i].oi_mode);
		ATF_CHECK_EQ(0, oi[i].oi_inflight);
		ATF_CHECK_EQ(0, strncmp(oracle_path, oi[i].oi_path,
		    sizeof(oi[i].oi_path) - 1));
		if (oi[i].oi_id == o1->id) {
			saw1 = true;
			ATF_CHECK_EQ(DQO_OS_LIVE, oi[i].oi_state);
		} else if (oi[i].oi_id == o2->id) {
			saw2 = true;
			ATF_CHECK_EQ(DQO_OS_REVOKED, oi[i].oi_state);
		}
	}
	ATF_CHECK(saw1 && saw2);
	/* Paging: one at a time. */
	ATF_REQUIRE_EQ(0, dq_observe_list_objects(svc, st.ds_queue_id, 1, oi,
	    1, &count, &total));
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(2, total);
	ATF_REQUIRE_EQ(0, dq_observe_list_objects(svc, st.ds_queue_id, 2, oi,
	    nitems(oi), &count, &total));
	ATF_CHECK_EQ(0, count);
	/* A closed object leaves the table. */
	ATF_REQUIRE_EQ(0, close(o1->fd));
	o1->fd = -1;
	ATF_REQUIRE_EQ(0, dq_observe_list_objects(svc, st.ds_queue_id, 0, oi,
	    nitems(oi), &count, &total));
	ATF_CHECK_EQ(1, total);
	ATF_CHECK_EQ(1, count);
	ATF_CHECK_EQ(o2->id, oi[0].oi_id);

	errno = 0;
	ATF_CHECK_EQ(-1, dq_observe_list_objects(svc, st.ds_queue_id + 100000,
	    0, oi, nitems(oi), &count, &total));
	ATF_CHECK_EQ(ESRCH, errno);
	(void)close(svc);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(subscribe);
ATF_TC_HEAD(subscribe, tc)
{
	atf_tc_set_md_var(tc, "descr", "subscribing to a queue yields an "
	    "observer descriptor that sees its events and replies");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(subscribe, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_stats st, st2;
	struct one_read_arg a;
	struct dqt_rr r;
	struct pollfd pfd;
	const struct dq_event *ev;
	char buf[1024];
	ssize_t got;
	int n, obs, oracle, svc;

	dqt_fill(data, sizeof(data), 93);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	svc = connect_or_skip();
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_stats(&c, &st);

	errno = 0;
	ATF_CHECK_EQ(-1, dq_observe_subscribe(svc, st.ds_queue_id + 100000));
	ATF_CHECK_EQ(ESRCH, errno);
	obs = dq_observe_subscribe(svc, st.ds_queue_id);
	ATF_REQUIRE_MSG(obs != -1, "subscribe: %s", strerror(errno));
	dqt_stats(&c, &st2);
	ATF_CHECK_EQ(1, st2.ds_observers);
	ATF_REQUIRE_EQ(0, dq_get_stats(obs, &st2));
	ATF_CHECK_EQ(st.ds_queue_id, st2.ds_queue_id);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(100, r.rv);
	pfd.fd = obs;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE_EQ(1, poll(&pfd, 1, DQT_WAIT_MS));
	got = read(obs, buf, sizeof(buf));
	ATF_REQUIRE(got > 0);
	n = 0;
	for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
	    ev = dq_event_next(buf, (size_t)got, ev)) {
		ATF_CHECK((ev->de_flags & DQ_EVENT_F_OBSERVED) != 0);
		ATF_CHECK(ev->de_op == DQ_OP_READ || ev->de_op == DQ_OP_REPLY);
		n++;
	}
	/* The event and its reply, possibly in two reads. */
	if (n < 2) {
		ATF_REQUIRE_EQ(1, poll(&pfd, 1, DQT_WAIT_MS));
		got = read(obs, buf, sizeof(buf));
		ATF_REQUIRE(got > 0);
		for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
		    ev = dq_event_next(buf, (size_t)got, ev))
			n++;
	}
	ATF_CHECK_EQ(2, n);
	(void)close(obs);
	(void)close(svc);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, connect_as_root);
	ATF_TP_ADD_TC(tp, list_queues);
	ATF_TP_ADD_TC(tp, list_objects);
	ATF_TP_ADD_TC(tp, subscribe);
	return (atf_no_error());
}
