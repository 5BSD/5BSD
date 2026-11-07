/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Observer descriptors (design 7.2): a copy of every event and every reply
 * on a queue, lengths and never bytes, on a descriptor that can read and
 * ask for statistics and nothing else.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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
#define	OBS_BUFSIZE	65536

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

/* Read observer records until n have arrived or the wait is over. */
static int
collect(int obs, char *buf, size_t len, const struct dq_event **recs, int n,
    int ms)
{
	const struct dq_event *ev;
	struct pollfd pfd;
	size_t off;
	ssize_t got;
	int count, waited;

	off = 0;
	count = 0;
	for (waited = 0; count < n && waited < ms; waited += 50) {
		pfd.fd = obs;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 50) <= 0)
			continue;
		got = read(obs, buf + off, len - off);
		if (got <= 0)
			break;
		for (ev = dq_event_first(buf + off, (size_t)got); ev != NULL;
		    ev = dq_event_next(buf + off, (size_t)got, ev)) {
			if (count < n)
				recs[count] = ev;
			count++;
		}
		off += (size_t)got;
	}
	return (count);
}

ATF_TC(sees_events_and_replies);
ATF_TC_HEAD(sees_events_and_replies, tc)
{
	atf_tc_set_md_var(tc, "descr", "an observer receives a copy of each "
	    "event and a DQ_OP_REPLY record for each reply, with lengths and "
	    "not bytes (D41)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sees_events_and_replies, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_rr r;
	const struct dq_event *recs[4];
	const struct dq_read_body *rb;
	const struct dq_reply_record *rr;
	struct dq_stats st;
	char *buf;
	size_t bodylen;
	int n, obs, obs_data, oracle;

	dqt_fill(data, sizeof(data), 81);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	obs = dq_mint_observer(c.q, 0);
	ATF_REQUIRE_MSG(obs != -1, "DQ_IOC_MINT_OBSERVER: %s", strerror(errno));
	obs_data = dq_mint_observer(c.q, DQ_OBS_F_DATA);
	ATF_REQUIRE(obs_data != -1);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(2, st.ds_observers);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(100, r.rv);

	buf = malloc(OBS_BUFSIZE);
	ATF_REQUIRE(buf != NULL);
	n = collect(obs, buf, OBS_BUFSIZE, recs, 2, DQT_WAIT_MS);
	ATF_REQUIRE_EQ(2, n);
	/* The event, flagged as a copy, with its READ body. */
	ATF_CHECK_EQ(DQ_API_VERSION, recs[0]->de_version);
	ATF_CHECK_EQ(DQ_OP_READ, recs[0]->de_op);
	ATF_CHECK_EQ(DQ_EVENT_F_OBSERVED, recs[0]->de_flags);
	ATF_CHECK_EQ(o->id, recs[0]->de_object);
	ATF_CHECK_EQ(1, recs[0]->de_seq);	/* the observer's own sequence */
	ATF_CHECK(recs[0]->de_id != 0);
	ATF_CHECK_EQ(sizeof(struct dq_event) + sizeof(*rb), recs[0]->de_size);
	rb = dq_event_body(recs[0], &bodylen);
	ATF_CHECK_EQ(sizeof(*rb), bodylen);
	ATF_CHECK_EQ(0, rb->dr_offset);
	ATF_CHECK_EQ(100, rb->dr_len);
	ATF_CHECK_EQ(c.last_caller.dc_pid, recs[0]->de_caller.dc_pid);
	/* The reply: id, errno and length; no data. */
	ATF_CHECK_EQ(DQ_OP_REPLY, recs[1]->de_op);
	ATF_CHECK_EQ(DQ_EVENT_F_OBSERVED, recs[1]->de_flags);
	ATF_CHECK_EQ(recs[0]->de_id, recs[1]->de_id);
	ATF_CHECK_EQ(2, recs[1]->de_seq);
	ATF_CHECK_EQ(sizeof(struct dq_event) + sizeof(*rr), recs[1]->de_size);
	rr = dq_event_body(recs[1], &bodylen);
	ATF_CHECK_EQ(sizeof(*rr), bodylen);
	ATF_CHECK_EQ(recs[0]->de_id, rr->drr_id);
	ATF_CHECK_EQ(0, rr->drr_errno);
	ATF_CHECK_EQ(100, rr->drr_len);

	/*
	 * DQ_OBS_F_DATA: in stage 1a no event body carries data (READ asks
	 * for an offset and a length) and the reply bytes belong to the
	 * waiter (dq_observer.c), so a data observer sees the same records.
	 */
	n = collect(obs_data, buf, OBS_BUFSIZE, recs, 2, DQT_WAIT_MS);
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK_EQ(sizeof(struct dq_event) + sizeof(*rb), recs[0]->de_size);
	ATF_CHECK_EQ(sizeof(struct dq_event) + sizeof(*rr), recs[1]->de_size);
	ATF_CHECK((recs[1]->de_flags & DQ_EVENT_F_NODATA) == 0);

	free(buf);
	(void)close(obs);
	(void)close(obs_data);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_observers);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(rights_and_transfer);
ATF_TC_HEAD(rights_and_transfer, tc)
{
	atf_tc_set_md_var(tc, "descr", "an observer answers DQ_IOC_GET_STATS "
	    "only (other ioctls ENOTCAPABLE), is read-only, locked close-on-"
	    "exec and close-on-fork, and cannot be sent");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rights_and_transfer, tc)
{
	struct dq_event rec;
	struct dqt_ctl c;
	struct dq_stats st, st2;
	struct dq_reply rep;
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	struct stat sb;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	int obs, on, sv[2];

	dqt_init_manual(&c);
	obs = dq_mint_observer(c.q, 0);
	ATF_REQUIRE(obs != -1);

	ATF_REQUIRE_EQ(0, dq_get_stats(c.q, &st));
	ATF_REQUIRE_EQ(0, dq_get_stats(obs, &st2));
	ATF_CHECK_EQ(st.ds_queue_id, st2.ds_queue_id);
	ATF_CHECK_EQ(1, st2.ds_observers);
	/*
	 * fc_ioctls = { DQ_IOC_GET_STATS }: cap_ioctl_check refuses every
	 * other command before the fileop runs, so the answer is
	 * ENOTCAPABLE rather than the fileop's ENOTTY.
	 */
	memset(&rep, 0, sizeof(rep));
	rep.dr_version = DQ_API_VERSION;
	rep.dr_id = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(obs, DQ_IOC_REPLY, &rep));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	/* FIONBIO and FIOASYNC are in its ioctl set: the fileop's own arm. */
	on = 1;
	ATF_CHECK_EQ_MSG(0, ioctl(obs, FIONBIO, &on), "FIONBIO: %s",
	    strerror(errno));
	/* A record-sized buffer: a smaller one is EINVAL before anything else. */
	errno = 0;
	ATF_CHECK_EQ(-1, read(obs, &rec, sizeof(rec)));	/* empty, non-blocking */
	ATF_CHECK_EQ(EAGAIN, errno);
	on = 0;
	ATF_CHECK_EQ(0, ioctl(obs, FIONBIO, &on));
	ATF_CHECK_EQ(0, ioctl(obs, FIOASYNC, &on));
	/* No CAP_WRITE: Capsicum refuses before the fileop's EBADF. */
	errno = 0;
	ATF_CHECK_EQ(-1, write(obs, &on, sizeof(on)));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	/* A character-device-like descriptor with no node behind it. */
	ATF_REQUIRE_EQ(0, fstat(obs, &sb));
	ATF_CHECK(S_ISCHR(sb.st_mode));
	/* CAP_FCNTL limited to GETFL/SETFL: O_NONBLOCK can be set. */
	ATF_CHECK(fcntl(obs, F_GETFL) != -1);
	ATF_CHECK_EQ(0, fcntl(obs, F_SETFL, fcntl(obs, F_GETFL) | O_NONBLOCK));
	ATF_CHECK_EQ(0, fcntl(obs, F_SETFL, fcntl(obs, F_GETFL) & ~O_NONBLOCK));
	ATF_CHECK_EQ(FD_CLOEXEC | FD_CLOFORK,
	    fcntl(obs, F_GETFD) & (FD_CLOEXEC | FD_CLOFORK));

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	byte = 'x';
	iov.iov_base = &byte;
	iov.iov_len = 1;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &obs, sizeof(int));
	errno = 0;
	ATF_CHECK_EQ(-1, sendmsg(sv[0], &msg, 0));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	(void)close(sv[0]);
	(void)close(sv[1]);
	(void)close(obs);
	dqt_fini(&c);
}

ATF_TC(read_rules);
ATF_TC_HEAD(read_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "observer read(2): EINVAL below a "
	    "header, ENOBUFS when the first record does not fit, EAGAIN when "
	    "empty and non-blocking, EOF once the queue is gone");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(read_rules, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_rr r;
	struct kevent kev;
	struct timespec zero = { 0, 0 };
	struct pollfd pfd;
	const size_t recsize = sizeof(struct dq_event) + sizeof(struct dq_read_body);
	char buf[4 * (sizeof(struct dq_event) + sizeof(struct dq_reply_record))];
	int flags, kq, obs, oracle;

	dqt_fill(data, sizeof(data), 82);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	obs = dq_mint_observer(c.q, 0);
	ATF_REQUIRE(obs != -1);
	flags = fcntl(obs, F_GETFL);
	ATF_REQUIRE_EQ(0, fcntl(obs, F_SETFL, flags | O_NONBLOCK));

	errno = 0;
	ATF_CHECK_EQ(-1, read(obs, buf, sizeof(struct dq_event) - 1));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, read(obs, buf, sizeof(buf)));
	ATF_CHECK_EQ(EAGAIN, errno);
	pfd.fd = obs;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_CHECK_EQ(0, poll(&pfd, 1, 0));

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(100, r.rv);
	/* Two records wait: a 120-byte READ copy and a 120-byte REPLY. */
	pfd.revents = 0;
	ATF_CHECK_EQ(1, poll(&pfd, 1, DQT_WAIT_MS));
	ATF_CHECK((pfd.revents & POLLIN) != 0);
	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev, obs, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &zero));
	ATF_CHECK_EQ(2, kev.data);	/* records, for an observer */
	errno = 0;
	ATF_CHECK_EQ(-1, read(obs, buf, recsize - 1));
	ATF_CHECK_EQ(ENOBUFS, errno);
	/* Exactly one fits: the batch stops at a whole record. */
	ATF_CHECK_EQ((ssize_t)recsize, read(obs, buf, recsize + 10));
	ATF_CHECK_EQ((ssize_t)recsize, read(obs, buf, sizeof(buf)));
	errno = 0;
	ATF_CHECK_EQ(-1, read(obs, buf, sizeof(buf)));
	ATF_CHECK_EQ(EAGAIN, errno);

	/* The queue goes away: the observer drains, then reads end of file. */
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ(100, r.rv);
	dqt_close_queue(&c);
	pfd.revents = 0;
	ATF_CHECK_EQ(1, poll(&pfd, 1, DQT_WAIT_MS));
	ATF_CHECK((pfd.revents & POLLHUP) != 0);
	ATF_CHECK_EQ((ssize_t)(2 * recsize), read(obs, buf, sizeof(buf)));
	ATF_CHECK_EQ(0, read(obs, buf, sizeof(buf)));
	ATF_REQUIRE_EQ(1, kevent(kq, NULL, 0, &kev, 1, &zero));
	ATF_CHECK((kev.flags & EV_EOF) != 0);
	(void)close(kq);
	(void)close(obs);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(set_queue_depth_bounds);
ATF_TC_HEAD(set_queue_depth_bounds, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_SET_QUEUE_DEPTH accepts 1.."
	    "kern.dq.queue_depth and refuses 0 and anything above with EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(set_queue_depth_bounds, tc)
{
	struct dqt_ctl c;
	struct dq_stats st;
	u_int sysdepth;

	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.queue_depth", &sysdepth));
	dqt_init_manual(&c);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(sysdepth, st.ds_queue_depth);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_queue_depth(c.q, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_queue_depth(c.q, sysdepth + 1));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_set_queue_depth(c.q, 1));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_queue_depth);
	ATF_CHECK_EQ(0, dq_set_queue_depth(c.q, sysdepth));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(sysdepth, st.ds_queue_depth);
	dqt_fini(&c);
}

ATF_TC(mint_observer_args);
ATF_TC_HEAD(mint_observer_args, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_MINT_OBSERVER refuses an unknown "
	    "flag, a wrong version and a nonzero pad with EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_observer_args, tc)
{
	struct dqt_ctl c;
	struct dq_observer_args args;

	dqt_init_manual(&c);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_mint_observer(c.q, DQ_OBS_F_DATA << 1));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(&args, 0, sizeof(args));
	args.do_version = DQ_API_VERSION + 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(c.q, DQ_IOC_MINT_OBSERVER, &args));
	ATF_CHECK_EQ(EINVAL, errno);
	args.do_version = DQ_API_VERSION;
	args.do_pad0 = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(c.q, DQ_IOC_MINT_OBSERVER, &args));
	ATF_CHECK_EQ(EINVAL, errno);
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sees_events_and_replies);
	ATF_TP_ADD_TC(tp, rights_and_transfer);
	ATF_TP_ADD_TC(tp, read_rules);
	ATF_TP_ADD_TC(tp, set_queue_depth_bounds);
	ATF_TP_ADD_TC(tp, mint_observer_args);
	return (atf_no_error());
}
