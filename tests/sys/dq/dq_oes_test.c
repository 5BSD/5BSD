/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * OES file events on a served descriptor (D89): a NOTIFY client sees
 * FILE_READ, FILE_STAT and FILE_CLOSE carrying the presented identity
 * (OES_FILE_META_PRESENTED), and one DQ_REPLY per controller reply with a
 * count and never content (D41).  The stage 1b operations on a writable
 * served object raise FILE_WRITE, FILE_SETATTR, FILE_FSYNC, FILE_LOCK,
 * FILE_IOCTL and FILE_MMAP with their payloads.  The same operations on a
 * real file produce no file event (D18: the hooks return at once for
 * anything but DTYPE_DQ).
 */

#include <sys/param.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
	OES_EVENT_NOTIFY_FILE_WRITE,
	OES_EVENT_NOTIFY_FILE_SETATTR,
	OES_EVENT_NOTIFY_FILE_FSYNC,
	OES_EVENT_NOTIFY_FILE_LOCK,
	OES_EVENT_NOTIFY_FILE_IOCTL,
	OES_EVENT_NOTIFY_FILE_MMAP,
};

/* The stage 1b events, in the order child_ops runs their operations. */
static const oes_event_type_t ops_events[] = {
	OES_EVENT_NOTIFY_FILE_WRITE,
	OES_EVENT_NOTIFY_FILE_SETATTR,
	OES_EVENT_NOTIFY_FILE_FSYNC,
	OES_EVENT_NOTIFY_FILE_LOCK,
	OES_EVENT_NOTIFY_FILE_IOCTL,
	OES_EVENT_NOTIFY_FILE_MMAP,
};
#define	NOPS		nitems(ops_events)
#define	OPS_MODE	0640
#define	OPS_LOCK_START	16
#define	OPS_LOCK_LEN	32

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

/*
 * One of each stage 1b operation, on a descriptor open for writing.  Each
 * result is the system call's, so the parent can tell an operation that
 * never reached its hook from an event that went missing.
 */
struct ops_res {
	struct dqt_rr	 r[NOPS];
	struct dqt_rr	 unlock;
};

static void
child_ops(void *arg, void *result)
{
	struct req_arg *a = arg;
	struct ops_res *r = result;
	struct flock fl;
	void *p;
	int n;

	DQT_RR(r->r[0], pwrite(a->fd, "w", 1, 0));
	DQT_RR(r->r[1], fchmod(a->fd, OPS_MODE));
	DQT_RR(r->r[2], fsync(a->fd));
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = OPS_LOCK_START;
	fl.l_len = OPS_LOCK_LEN;
	DQT_RR(r->r[3], fcntl(a->fd, F_SETLK, &fl));
	fl.l_type = F_UNLCK;
	r->unlock.rv = fcntl(a->fd, F_SETLK, &fl);
	r->unlock.err = r->unlock.rv == -1 ? errno : 0;
	DQT_RR(r->r[4], ioctl(a->fd, FIONREAD, &n));
	p = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, a->fd, 0);
	r->r[5].rv = p == MAP_FAILED ? -1 : 0;
	r->r[5].err = p == MAP_FAILED ? errno : 0;
	if (p != MAP_FAILED)
		(void)munmap(p, getpagesize());
#undef RR
}

/* The first message of each stage 1b event from pid. */
static void
collect_ops(oes_client_t *client, oes_message_t *got[NOPS], pid_t pid,
    int ms)
{
	const oes_message_t *msg;
	long start;
	size_t i, have;

	start = dqt_now_ms();
	for (have = 0; have < NOPS && dqt_now_ms() - start < ms;) {
		if (oes_read_event(client, &msg, false) != 0) {
			if (errno != EAGAIN)
				atf_tc_fail("oes_read_event: %s", strerror(errno));
			dqt_msleep(10);
			continue;
		}
		if (msg->em_process.ep_pid != pid)
			continue;
		for (i = 0; i < NOPS; i++) {
			if (msg->em_event == ops_events[i] && got[i] == NULL) {
				got[i] = oes_message_copy(msg);
				have++;
			}
		}
	}
}

static oes_client_t *
oes_client_open(void)
{
	struct oes_mute_args mute;
	oes_client_t *client;
	int error;

	client = oes_client_create();
	if (client == NULL) {
		error = errno;
		atf_tc_fail("/dev/oes: %s", strerror(error));
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

	start = dqt_now_ms();
	while (!seen_all(s) && dqt_now_ms() - start < ms) {
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
	client = oes_client_open();

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
	dqt_require_exit0(status, "child");
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

ATF_TC(served_ops_events);
ATF_TC_HEAD(served_ops_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "write, fchmod, fsync, a record lock, an "
	    "ioctl and mmap on a writable served object reach an OES NOTIFY "
	    "client as FILE_WRITE/SETATTR/FSYNC/LOCK/IOCTL/MMAP with the "
	    "presented identity and the operation's detail");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(served_ops_events, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct req_arg a;
	struct ops_res r;
	struct dqt_child ch;
	oes_message_t *got[NOPS];
	const oes_event_file_setattr_t *sa;
	const oes_event_file_lock_t *lk;
	const oes_event_mmap_t *mm;
	oes_client_t *client;
	size_t i;
	int backing, status;

	dqt_fill(data, sizeof(data), 113);
	backing = dqt_make_rw("backing", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dqt_policy_write(&pol);
	pol.dp_ioctl = DQ_EVENT;
	pol.dp_mmap_shared_write = DQ_ALLOW;
	o = dqt_mint_backing(&c, backing, oracle_path, &pol, DQ_MINT_F_WRITE);
	client = oes_client_open();

	a.fd = o->fd;
	dqt_spawn(&ch, child_ops, &a);
	status = dqt_wait(&ch, &r, sizeof(r));
	dqt_require_exit0(status, "child");
	for (i = 0; i < NOPS; i++)
		ATF_CHECK_MSG(r.r[i].rv != -1, "operation %zu (event %#x): %s",
		    i, ops_events[i], strerror(r.r[i].err));
	ATF_CHECK_MSG(r.unlock.rv != -1, "unlock: %s", strerror(r.unlock.err));

	memset(got, 0, sizeof(got));
	collect_ops(client, got, ch.pid, EVENT_WAIT_MS);
	for (i = 0; i < NOPS; i++)
		ATF_REQUIRE_MSG(got[i] != NULL, "no event %#x from %d",
		    ops_events[i], ch.pid);

	check_presented(got[0], &got[0]->em_event_data.rw.file, &o->ident);

	sa = &got[1]->em_event_data.file_setattr;
	check_presented(got[1], &sa->file, &o->ident);
	ATF_CHECK_EQ(OES_FILE_SETATTR_MODE, sa->mask);
	ATF_CHECK_EQ(OPS_MODE, sa->mode & ALLPERMS);

	check_presented(got[2], &got[2]->em_event_data.fsync.file, &o->ident);

	lk = &got[3]->em_event_data.file_lock;
	check_presented(got[3], &lk->file, &o->ident);
	ATF_CHECK_EQ(F_SETLK, lk->op);
	ATF_CHECK_EQ(F_WRLCK, lk->type);
	ATF_CHECK_EQ(SEEK_SET, lk->whence);
	ATF_CHECK_EQ(OPS_LOCK_START, lk->start);
	ATF_CHECK_EQ(OPS_LOCK_LEN, lk->len);

	check_presented(got[4], &got[4]->em_event_data.file_ioctl.file,
	    &o->ident);
	ATF_CHECK_EQ((uint64_t)FIONREAD, got[4]->em_event_data.file_ioctl.cmd);

	mm = &got[5]->em_event_data.mmap;
	check_presented(got[5], &mm->file, &o->ident);
	ATF_CHECK_EQ(PROT_READ, mm->prot);
	ATF_CHECK((mm->flags & MAP_SHARED) != 0);
	ATF_CHECK_EQ((uint64_t)getpagesize(), mm->len);

	for (i = 0; i < NOPS; i++)
		oes_message_free(got[i]);
	oes_client_destroy(client);
	dqt_fini(&c);
	(void)close(backing);
}

ATF_TC(real_file_no_ops_events);
ATF_TC_HEAD(real_file_no_ops_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "the same stage 1b operations on a "
	    "real file raise none of the served-descriptor events (D18)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(real_file_no_ops_events, tc)
{
	struct req_arg a;
	struct ops_res r;
	struct dqt_child ch;
	oes_message_t *got[NOPS];
	oes_client_t *client;
	size_t i;
	int fd, q, status;

	q = dqt_open_queue();	/* fails when the device is absent */
	dqt_fill(data, sizeof(data), 114);
	fd = dqt_make_rw("real", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	client = oes_client_open();

	a.fd = fd;
	dqt_spawn(&ch, child_ops, &a);
	status = dqt_wait(&ch, &r, sizeof(r));
	dqt_require_exit0(status, "child");
	/* Every operation must have run, or the negative proves nothing. */
	for (i = 0; i < NOPS; i++)
		ATF_REQUIRE_MSG(r.r[i].rv != -1, "operation %zu on a real "
		    "file: %s", i, strerror(r.r[i].err));

	memset(got, 0, sizeof(got));
	collect_ops(client, got, ch.pid, NO_EVENT_MS);
	for (i = 0; i < NOPS; i++) {
		ATF_CHECK_MSG(got[i] == NULL, "event %#x for a real file",
		    ops_events[i]);
		if (got[i] != NULL)
			oes_message_free(got[i]);
	}
	oes_client_destroy(client);
	(void)close(fd);
	(void)close(q);
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

	q = dqt_open_queue();	/* fails when the device is absent */
	dqt_fill(data, sizeof(data), 112);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	client = oes_client_open();

	a.fd = oracle;
	dqt_spawn(&ch, child_read_stat, &a);
	status = dqt_wait(&ch, &r, sizeof(r));
	dqt_require_exit0(status, "child");
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
	ATF_TP_ADD_TC(tp, served_ops_events);
	ATF_TP_ADD_TC(tp, real_file_no_ops_events);
	return (atf_no_error());
}
