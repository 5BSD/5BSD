/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * OES file events on a served descriptor (D89): a NOTIFY client sees
 * FILE_READ, FILE_STAT and FILE_CLOSE carrying the presented identity
 * (OES_FILE_META_PRESENTED), and one DQ_REPLY per controller reply with a
 * count and never content (D41).  A read of a real file produces no file
 * event (D18: the hooks return at once for anything but DTYPE_DQ).
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <liboes.h>

#include "dq_test.h"

#define	DATA_LEN	8192
#define	READ_LEN	100
#define	EVENT_WAIT_MS	5000
#define	NO_EVENT_MS	700

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

static const oes_event_type_t served_events[] = {
	OES_EVENT_NOTIFY_FILE_READ,
	OES_EVENT_NOTIFY_FILE_STAT,
	OES_EVENT_NOTIFY_FILE_CLOSE,
	OES_EVENT_NOTIFY_DQ_REPLY,
};

/* What a child did; the pipe carries the results. */
struct req_arg {
	int		 fd;
};

struct req_res {
	struct dqt_rr	 rd;
	struct dqt_rr	 st;
};

static void
child_read_stat(void *arg, void *result)
{
	struct req_arg *a = arg;
	struct req_res *r = result;
	unsigned char buf[READ_LEN];
	struct stat sb;

	r->rd.rv = read(a->fd, buf, sizeof(buf));
	r->rd.err = r->rd.rv == -1 ? errno : 0;
	r->st.rv = fstat(a->fd, &sb);
	r->st.err = r->st.rv == -1 ? errno : 0;
	/*
	 * An explicit close(2): the hook fires on every close of a served
	 * descriptor, while a process exit (fdescfree) never calls it.
	 */
	(void)close(a->fd);
}

static oes_client_t *
client_or_skip(void)
{
	struct oes_mute_args mute;
	oes_client_t *client;
	int error;

	client = oes_client_create();
	if (client == NULL) {
		error = errno;
		atf_tc_skip("/dev/oes: %s", strerror(error));
	}
	ATF_REQUIRE_MSG(oes_set_mode(client, OES_MODE_NOTIFY, 0, 0) == 0,
	    "oes_set_mode: %s", strerror(errno));
	/*
	 * security.oes.default_self_mute makes the first SET_MODE mute this
	 * process; the controller's own close(2) and its DQ_REPLY come from
	 * here, so lift it.
	 */
	memset(&mute, 0, sizeof(mute));
	mute.emu_flags = OES_MUTE_SELF;
	ATF_REQUIRE_MSG(ioctl(oes_client_fd(client), OES_IOC_UNMUTE_PROCESS,
	    &mute) == 0, "unmute self: %s", strerror(errno));
	ATF_REQUIRE_MSG(oes_subscribe(client, served_events,
	    nitems(served_events), OES_SUB_REPLACE) == 0, "oes_subscribe: %s",
	    strerror(errno));
	return (client);
}

static long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

/*
 * Collected messages: one copy of the first message of each event type
 * from the process(es) of interest.
 */
struct seen {
	oes_message_t	*read;
	oes_message_t	*stat;
	oes_message_t	*close;
	oes_message_t	*reply;
};

static bool
seen_all(const struct seen *s)
{

	return (s->read != NULL && s->stat != NULL && s->close != NULL &&
	    s->reply != NULL);
}

/* Read until every expected event arrived or the wait is over. */
static void
collect(oes_client_t *client, struct seen *s, pid_t requester, pid_t controller,
    int ms)
{
	const oes_message_t *msg;
	long start;
	pid_t pid;

	start = now_ms();
	while (!seen_all(s) && now_ms() - start < ms) {
		if (oes_read_event(client, &msg, false) != 0) {
			if (errno != EAGAIN)
				atf_tc_fail("oes_read_event: %s", strerror(errno));
			dqt_msleep(10);
			continue;
		}
		pid = msg->em_process.ep_pid;
		switch (msg->em_event) {
		case OES_EVENT_NOTIFY_FILE_READ:
			if (pid == requester && s->read == NULL)
				s->read = oes_message_copy(msg);
			break;
		case OES_EVENT_NOTIFY_FILE_STAT:
			if (pid == requester && s->stat == NULL)
				s->stat = oes_message_copy(msg);
			break;
		case OES_EVENT_NOTIFY_FILE_CLOSE:
			/* The requester's exit or the controller's close. */
			if ((pid == requester || pid == controller) &&
			    s->close == NULL)
				s->close = oes_message_copy(msg);
			break;
		case OES_EVENT_NOTIFY_DQ_REPLY:
			if (pid == controller && s->reply == NULL)
				s->reply = oes_message_copy(msg);
			break;
		default:
			break;
		}
	}
}

static void
check_presented(const oes_message_t *msg, const oes_file_t *file,
    const struct dq_ident_file *ident)
{

	ATF_CHECK_MSG((file->ef_meta_flags & OES_FILE_META_PRESENTED) != 0,
	    "event %#x: ef_meta_flags %#x lacks PRESENTED", msg->em_event,
	    file->ef_meta_flags);
	ATF_CHECK_STREQ(oracle_path, oes_msg_string(msg, file->ef_path_off));
	ATF_CHECK_EQ(ident->di_ino, file->ef_ino);
	ATF_CHECK_EQ(ident->di_dev, file->ef_dev);
}

ATF_TC(served_file_events);
ATF_TC_HEAD(served_file_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "a served read, fstat and close reach "
	    "an OES NOTIFY client as FILE_READ/STAT/CLOSE with the presented "
	    "identity, and each reply as DQ_REPLY with a count only");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(served_file_events, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqo_queue_info qi[8];
	struct dq_stats st;
	struct req_arg a;
	struct req_res r;
	struct dqt_child ch;
	struct seen s;
	const oes_event_presented_t *rep;
	oes_client_t *client;
	uint64_t nonce, total;
	size_t count, i;
	int oracle, status, svc;
	bool have_nonce;

	dqt_fill(data, sizeof(data), 111);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	client = client_or_skip();

	/* The controller's identity nonce, as dq.observe reports it. */
	have_nonce = false;
	nonce = 0;
	dqt_stats(&c, &st);
	svc = dq_observe_connect();
	if (svc != -1) {
		if (dq_observe_list_queues(svc, 0, qi, nitems(qi), &count,
		    &total) == 0) {
			for (i = 0; i < count; i++) {
				if (qi[i].qi_id == st.ds_queue_id) {
					nonce = qi[i].qi_nonce;
					have_nonce = true;
				}
			}
		}
		(void)close(svc);
	}

	a.fd = o->fd;
	dqt_spawn(&ch, child_read_stat, &a);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(READ_LEN, r.rd.rv);
	ATF_REQUIRE_EQ(0, r.st.rv);
	/* The controller's own close(2): a second FILE_CLOSE, from this pid. */
	ATF_REQUIRE_EQ(0, close(o->fd));
	o->fd = -1;

	memset(&s, 0, sizeof(s));
	collect(client, &s, ch.pid, getpid(), EVENT_WAIT_MS);
	ATF_REQUIRE_MSG(s.read != NULL, "no NOTIFY_FILE_READ from %d", ch.pid);
	ATF_REQUIRE_MSG(s.stat != NULL, "no NOTIFY_FILE_STAT from %d", ch.pid);
	ATF_REQUIRE_MSG(s.close != NULL, "no NOTIFY_FILE_CLOSE");
	/* Unmuted above, so the controller's reply is always reported. */
	ATF_REQUIRE_MSG(s.reply != NULL, "no NOTIFY_DQ_REPLY from %d", getpid());

	check_presented(s.read, &s.read->em_event_data.rw.file, &o->ident);
	check_presented(s.stat, &s.stat->em_event_data.stat.file, &o->ident);
	check_presented(s.close, &s.close->em_event_data.close.file, &o->ident);

	/* DQ_REPLY: the controller's reply to the READ, a count, no content. */
	rep = &s.reply->em_event_data.dq_reply;
	check_presented(s.reply, &rep->file, &o->ident);
	ATF_CHECK_EQ(o->id, rep->object);
	ATF_CHECK_EQ(DQ_OP_READ, rep->op);
	ATF_CHECK_EQ(0, rep->error);
	ATF_CHECK_EQ(READ_LEN, rep->count);
	if (have_nonce)
		ATF_CHECK_EQ_MSG(nonce, rep->controller_nonce,
		    "nonce %ju want %ju", (uintmax_t)rep->controller_nonce,
		    (uintmax_t)nonce);
	ATF_CHECK_EQ(getpid(), s.reply->em_process.ep_pid);
	/* D41: the served bytes are nowhere in the message. */
	ATF_CHECK(memmem(s.reply, s.reply->em_struct_size, data, 16) == NULL);
	ATF_CHECK(memmem(s.read, s.read->em_struct_size, data, 16) == NULL);

	oes_message_free(s.read);
	oes_message_free(s.stat);
	oes_message_free(s.close);
	oes_message_free(s.reply);
	oes_client_destroy(client);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(real_file_no_events);
ATF_TC_HEAD(real_file_no_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "read and fstat of a real file produce "
	    "no FILE_READ/FILE_STAT: the hooks are gated on DTYPE_DQ (D18)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(real_file_no_events, tc)
{
	struct req_arg a;
	struct req_res r;
	struct dqt_child ch;
	struct seen s;
	oes_client_t *client;
	int oracle, q, status;

	q = dqt_open_queue();	/* skip when the device is absent */
	dqt_fill(data, sizeof(data), 112);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	client = client_or_skip();

	a.fd = oracle;
	dqt_spawn(&ch, child_read_stat, &a);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE_EQ(READ_LEN, r.rd.rv);
	ATF_REQUIRE_EQ(0, r.st.rv);

	/* A bounded negative wait: nothing from that process may arrive. */
	memset(&s, 0, sizeof(s));
	collect(client, &s, ch.pid, -1, NO_EVENT_MS);
	ATF_CHECK_MSG(s.read == NULL, "FILE_READ for a real file");
	ATF_CHECK_MSG(s.stat == NULL, "FILE_STAT for a real file");
	ATF_CHECK_MSG(s.close == NULL, "FILE_CLOSE for a real file");
	if (s.read != NULL)
		oes_message_free(s.read);
	if (s.stat != NULL)
		oes_message_free(s.stat);
	if (s.close != NULL)
		oes_message_free(s.close);
	oes_client_destroy(client);
	(void)close(oracle);
	(void)close(q);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, served_file_events);
	ATF_TP_ADD_TC(tp, real_file_no_events);
	return (atf_no_error());
}
