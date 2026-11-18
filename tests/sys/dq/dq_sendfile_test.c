/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * sendfile(2) of a served file (D104): the pages are filled by READ_ASYNC
 * events (answered as READ), sent from the dq pager object.  The oracle is
 * sendfile of a real file of the same length over the same kind of socket;
 * the served bytes are the controller's (here a redacted copy).
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dqt.h"

#define	DATA_LEN	70000		/* several socket-buffer fills */

static unsigned char data[DATA_LEN];
static unsigned char redacted[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct sf_arg {
	int		 fd;
	int		 sock;
	int		 other;		/* the peer end, closed in the child */
	int		 go;		/* -1, or wait for a byte before SO_ERROR */
};

struct sf_res {
	struct dqt_rr	 r;
	off_t		 sbytes;
	int		 so_error;	/* SO_ERROR of the socket after the call */
};

static void
child_sendfile(void *arg, void *result)
{
	struct sf_arg *a = arg;
	struct sf_res *r = result;

	(void)close(a->other);
	r->sbytes = 0;
	r->r.rv = sendfile(a->fd, a->sock, 0, 0, NULL, &r->sbytes, 0);
	r->r.err = r->r.rv == -1 ? errno : 0;
	if (a->go != -1)
		(void)dqt_sync_wait(a->go, 4 * DQT_WAIT_MS);
	{
		socklen_t len = sizeof(r->so_error);

		(void)getsockopt(a->sock, SOL_SOCKET, SO_ERROR, &r->so_error,
		    &len);
	}
	(void)close(a->sock);
}

/* Run a sendfile of fd in a child; collect what arrives into buf. */
static size_t
send_and_collect(int fd, unsigned char *buf, size_t cap, struct sf_res *r)
{
	struct dqt_child ch;
	struct sf_arg a;
	struct pollfd pfd;
	size_t got;
	ssize_t n;
	int sv[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	a.fd = fd;
	a.sock = sv[0];
	a.other = sv[1];
	a.go = -1;
	dqt_spawn(&ch, child_sendfile, &a);
	(void)close(sv[0]);
	got = 0;
	for (;;) {
		pfd.fd = sv[1];
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 4 * DQT_WAIT_MS) != 1)
			break;
		n = read(sv[1], buf + got, cap - got);
		if (n <= 0)
			break;
		got += (size_t)n;
		if (got == cap)
			break;
	}
	(void)close(sv[1]);
	dqt_collect(&ch, r, sizeof(*r));
	return (got);
}

ATF_TC(oracle_redacted);
ATF_TC_HEAD(oracle_redacted, tc)
{
	atf_tc_set_md_var(tc, "descr", "sendfile of a served file sends the "
	    "controller's bytes (a redacted copy), the same count as sendfile "
	    "of the real file sends its own; pages come through READ_ASYNC");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(oracle_redacted, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct sf_res rs, ro;
	unsigned char *bs, *bo;
	size_t i, ns, no;
	int oracle;

	dqt_fill(data, sizeof(data), 1);
	memcpy(redacted, data, sizeof(data));
	for (i = 0; i < sizeof(redacted); i += 997)
		redacted[i] = '*';
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, redacted, sizeof(redacted), NULL);
	bs = malloc(DATA_LEN + 1);
	bo = malloc(DATA_LEN + 1);
	ATF_REQUIRE(bs != NULL && bo != NULL);
	memset(&rs, 0, sizeof(rs));
	ns = send_and_collect(o->fd, bs, DATA_LEN + 1, &rs);
	memset(&ro, 0, sizeof(ro));
	no = send_and_collect(oracle, bo, DATA_LEN + 1, &ro);
	ATF_CHECK_EQ_MSG(0, rs.r.rv, "served sendfile: %s", strerror(rs.r.err));
	ATF_CHECK_EQ(ro.r.rv, rs.r.rv);
	ATF_CHECK_EQ(ro.sbytes, rs.sbytes);
	ATF_CHECK_EQ(DATA_LEN, ns);
	ATF_CHECK_EQ(no, ns);
	ATF_CHECK(memcmp(bs, redacted, DATA_LEN) == 0);
	ATF_CHECK(memcmp(bo, data, DATA_LEN) == 0);
	dqt_lock(&c);
	ATF_CHECK(c.events[DQ_OP_READ_ASYNC] >= 1);
	dqt_unlock(&c);
	free(bs);
	free(bo);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(revoke_eio);
ATF_TC_HEAD(revoke_eio, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sendfile whose pages are being "
	    "filled when the object is revoked fails with EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoke_eio, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqt_child ch;
	struct sf_arg a;
	struct sf_res r;
	unsigned char buf[4096];
	int gop[2];
	int oracle, sv[2];

	dqt_fill(data, sizeof(data), 2);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_hold(&c, true);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	a.fd = o->fd;
	a.sock = sv[0];
	a.other = sv[1];
	ATF_REQUIRE_EQ(0, pipe(gop));
	a.go = gop[0];
	dqt_spawn(&ch, child_sendfile, &a);
	(void)close(sv[0]);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(DQ_OP_READ_ASYNC, c.held[0].op);
	dqt_unlock(&c);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	dqt_sync_post(gop[1]);
	/* Drain whatever was sent before the revoke. */
	while (read(sv[1], buf, sizeof(buf)) > 0)
		continue;
	(void)close(sv[1]);
	dqt_collect(&ch, &r, sizeof(r));
	/*
	 * The pages are filled asynchronously: a failed fill aborts the
	 * transfer and the socket reports EIO (so_error).  The call itself may
	 * have returned already, or fail with EIO (the size check after the
	 * revoke) or with EPIPE/ENOTCONN from the aborted socket.
	 */
	ATF_CHECK_MSG((r.r.rv == -1 && (r.r.err == EIO || r.r.err == EPIPE ||
	    r.r.err == ENOTCONN)) || r.so_error == EIO,
	    "sendfile rv %ld errno %d sbytes %jd so_error %d", r.r.rv,
	    r.r.err, (intmax_t)r.sbytes, r.so_error);
	ATF_CHECK(r.sbytes < DATA_LEN);
	/* The late reply finds nothing in flight. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, dqt_held_id(&c, 0), 0, data, 16));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Not ready data and the end of the stream.  sendfile(2) to a unix(4)
 * stream socket puts the pages, not ready until their READ_ASYNC fills are
 * answered, straight into the reader's receive buffer, and returns.  Run 36
 * of the plane-on VM suite lost data in oracle_redacted this way: the
 * sender closed its socket at once, read(2), poll(2) and kevent(2) reported
 * EOF before the data, and it was readied after the reader had gone.  The
 * tests below hold the fills while the sender closes, shuts down, stays or
 * reconnects, check that the reader sees no EOF (read, poll, select,
 * kevent), then answer the fills (the bytes, or an error) with a reader
 * blocked in read(2), which uipc_ready()/uipc_abort() must wake.
 */
#define	NR_LEN		(2 * 4096 + 1000)	/* three pages, the last part */
#define	NR_LEN2		4096
#define	NR_PATH		"nr.sock"

static unsigned char data2[NR_LEN2];

/* Wait until the held READ_ASYNC fills of object id cover want bytes. */
static bool
held_bytes(struct dqt_ctl *c, uint64_t id, size_t want)
    __requires_unlocked(c->mtx)
{
	size_t held;
	int i, waited;

	for (waited = 0;; waited += 10) {
		dqt_lock(c);
		for (held = 0, i = 0; i < c->nheld; i++)
			if (c->held[i].op == DQ_OP_READ_ASYNC &&
			    c->held[i].object == id)
				held += c->held[i].len;
		dqt_unlock(c);
		if (held >= want)
			return (true);
		if (waited >= DQT_WAIT_MS)
			return (false);
		dqt_msleep(10);
	}
}

/* Answer the held READ_ASYNC fills of o: its bytes, or error. */
static void
answer_fills(struct dqt_ctl *c, struct dqt_object *o,
    const unsigned char *bytes, size_t len, int error)
    __requires_unlocked(c->mtx)
{
	struct dqt_held *h;
	size_t n;
	int i, rv;

	dqt_lock(c);
	for (i = 0; i < c->nheld; i++) {
		h = &c->held[i];
		if (h->op != DQ_OP_READ_ASYNC || h->object != o->id)
			continue;
		n = h->offset >= len ? 0 : MIN(h->len, len - h->offset);
		rv = error == 0 ?
		    dq_reply(c->q, h->id, 0, bytes + h->offset, n) :
		    dq_reply(c->q, h->id, error, NULL, 0);
		ATF_CHECK_EQ_MSG(0, rv, "dq_reply: %s", strerror(errno));
	}
	dqt_unlock(c);
}

/* Not readable, no EOF: recv, poll, select and kevent agree. */
static void
check_not_readable(int fd, int kq, const char *when)
{
	struct timespec ts0 = { 0, 0 };
	struct timeval tv0 = { 0, 0 };
	struct pollfd pfd;
	struct kevent kev;
	fd_set rs;
	unsigned char b;
	ssize_t n;
	int rv;

	errno = 0;
	n = recv(fd, &b, 1, MSG_DONTWAIT);
	ATF_CHECK_MSG(n == -1 && errno == EAGAIN, "%s: recv %zd, errno %d",
	    when, n, errno);
	pfd.fd = fd;
	pfd.events = POLLIN | POLLRDNORM;
	pfd.revents = 0;
	rv = poll(&pfd, 1, 0);
	ATF_CHECK_MSG(rv == 0 && pfd.revents == 0, "%s: poll %d, revents %#x",
	    when, rv, pfd.revents);
	/* With the write side asked too: maybe POLLOUT, never a hangup. */
	pfd.events = POLLIN | POLLRDNORM | POLLOUT;
	pfd.revents = 0;
	(void)poll(&pfd, 1, 0);
	ATF_CHECK_MSG((pfd.revents & (POLLIN | POLLRDNORM | POLLHUP)) == 0,
	    "%s: poll with POLLOUT, revents %#x", when, pfd.revents);
	FD_ZERO(&rs);
	FD_SET(fd, &rs);
	rv = select(fd + 1, &rs, NULL, NULL, &tv0);
	ATF_CHECK_MSG(rv == 0, "%s: select %d", when, rv);
	rv = kevent(kq, NULL, 0, &kev, 1, &ts0);
	ATF_CHECK_MSG(rv == 0, "%s: kevent %d, flags %#x, data %jd", when, rv,
	    rv > 0 ? kev.flags : 0, rv > 0 ? (intmax_t)kev.data : 0);
}

/* EOF now: kevent says so too. */
static void
check_eof_event(int kq)
{
	struct timespec ts0 = { 0, 0 };
	struct kevent kev;
	int rv;

	rv = kevent(kq, NULL, 0, &kev, 1, &ts0);
	ATF_CHECK_EQ(1, rv);
	ATF_CHECK_MSG(rv == 1 && (kev.flags & EV_EOF) != 0,
	    "kevent at EOF: flags %#x", rv == 1 ? kev.flags : 0);
}

static int
read_kqueue(int fd)
{
	struct kevent kev;
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, &kev, 1, NULL, 0, NULL));
	return (kq);
}

/* A thread blocked in read(2) until EOF or an error. */
struct reader {
	pthread_t	 thr;
	pthread_mutex_t	 mtx;
	pthread_cond_t	 cv;
	int		 fd;
	unsigned char	*buf;
	size_t		 cap;
	size_t		 got;
	ssize_t		 last;
	int		 err;
	bool		 done;
};

static void *
reader_main(void *arg)
{
	struct reader *rd = arg;
	ssize_t n;

	for (;;) {
		n = read(rd->fd, rd->buf + rd->got, rd->cap - rd->got);
		if (n <= 0)
			break;
		rd->got += (size_t)n;
		if (rd->got == rd->cap)
			break;
	}
	pthread_mutex_lock(&rd->mtx);
	rd->last = n;
	rd->err = n == -1 ? errno : 0;
	rd->done = true;
	pthread_cond_broadcast(&rd->cv);
	pthread_mutex_unlock(&rd->mtx);
	return (NULL);
}

static void
reader_start(struct reader *rd, int fd, unsigned char *buf, size_t cap)
{

	memset(rd, 0, sizeof(*rd));
	rd->fd = fd;
	rd->buf = buf;
	rd->cap = cap;
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&rd->mtx, NULL));
	ATF_REQUIRE_EQ(0, pthread_cond_init(&rd->cv, NULL));
	ATF_REQUIRE_EQ(0, pthread_create(&rd->thr, NULL, reader_main, rd));
	/* It blocks in read(2), so that the answer has to wake it. */
	ATF_REQUIRE_MSG(dqt_wait_wmesg(getpid(), "sbwait", DQT_WAIT_MS),
	    "the reader thread did not block in read(2)");
}

static bool
reader_wait(struct reader *rd, int ms)
{
	struct timespec ts;
	bool done;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (long)(ms % 1000) * 1000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	pthread_mutex_lock(&rd->mtx);
	while (!rd->done &&
	    pthread_cond_timedwait(&rd->cv, &rd->mtx, &ts) == 0)
		continue;
	done = rd->done;
	pthread_mutex_unlock(&rd->mtx);
	return (done);
}

/* Join the reader, releasing it with shutdown(2) if it is still stuck. */
static void
reader_finish(struct reader *rd)
{

	if (!reader_wait(rd, 0))
		(void)shutdown(rd->fd, SHUT_RDWR);
	(void)pthread_join(rd->thr, NULL);
	pthread_mutex_destroy(&rd->mtx);
	pthread_cond_destroy(&rd->cv);
}

/* Check the reader's outcome: the bytes then EOF, or error and no data. */
static void
check_reader(struct reader *rd, const unsigned char *bytes, size_t len,
    int error)
{

	ATF_CHECK_MSG(reader_wait(rd, 2 * DQT_WAIT_MS),
	    "the reader was not woken (got %zu)", rd->got);
	if (!rd->done)
		return;
	if (error == 0) {
		ATF_CHECK_EQ_MSG(0, rd->last, "read at the end: %zd, errno %d",
		    rd->last, rd->err);
		ATF_CHECK_EQ(len, rd->got);
		ATF_CHECK(rd->got != len || memcmp(rd->buf, bytes, len) == 0);
	} else {
		ATF_CHECK_MSG(rd->last == -1 && rd->err == EPIPE,
		    "read after the failed fill: %zd, errno %d", rd->last,
		    rd->err);
		ATF_CHECK_EQ(0, rd->got);
		ATF_CHECK_EQ(0, read(rd->fd, rd->buf, rd->cap));
	}
}

enum nr_mode {
	NR_CLOSE,		/* the sender closes its socket */
	NR_SHUT_WR,		/* the sender shuts down writing, stays */
	NR_SHUT_RD,		/* the reader shuts down reading, connected */
	NR_SHUT_RD_CLOSED,	/* ... after the sender closed */
};

struct nr_arg {
	int		 fd;
	int		 sock;
	int		 other;
	int		 how;		/* -1, or shutdown(2) after sendfile */
	bool		 linger;	/* keep the socket open until go */
	int		 ready;
	int		 go;
};

struct nr_res {
	struct dqt_rr	 r;
	off_t		 sbytes;
	struct dqt_rr	 sh;
	int		 so_error;	/* the sender's SO_ERROR before close */
};

static void
child_nr(void *arg, void *result)
{
	struct nr_arg *a = arg;
	struct nr_res *r = result;

	(void)close(a->other);
	r->sbytes = 0;
	r->r.rv = sendfile(a->fd, a->sock, 0, 0, NULL, &r->sbytes, 0);
	r->r.err = r->r.rv == -1 ? errno : 0;
	r->sh.rv = 0;
	r->sh.err = 0;
	if (a->how != -1) {
		r->sh.rv = shutdown(a->sock, a->how);
		r->sh.err = r->sh.rv == -1 ? errno : 0;
	}
	if (!a->linger)
		(void)close(a->sock);
	dqt_sync_post(a->ready);
	if (a->linger) {
		(void)dqt_sync_wait(a->go, 8 * DQT_WAIT_MS);
		socklen_t len = sizeof(r->so_error);

		(void)getsockopt(a->sock, SOL_SOCKET, SO_ERROR, &r->so_error,
		    &len);
		(void)close(a->sock);
	}
}

static void
not_ready_end(enum nr_mode mode, int error, unsigned seed)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqt_child ch;
	struct dqt_sync s;
	struct nr_arg a;
	struct nr_res r;
	struct reader rd;
	unsigned char *buf;
	int kq, oracle, rv, status, sv[2];

	dqt_fill(data, NR_LEN, seed);
	oracle = dqt_make_oracle("oracle", data, NR_LEN, oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, NR_LEN, NULL);
	dqt_hold(&c, true);
	dqt_sync_init(&s);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	a.fd = o->fd;
	a.sock = sv[0];
	a.other = sv[1];
	a.how = mode == NR_SHUT_WR ? SHUT_WR : -1;
	a.linger = mode == NR_SHUT_WR || mode == NR_SHUT_RD;
	a.ready = s.toparent[1];
	a.go = s.tochild[0];
	memset(&r, 0, sizeof(r));
	dqt_spawn(&ch, child_nr, &a);
	(void)close(sv[0]);
	ATF_REQUIRE(dqt_sync_wait(s.toparent[0], DQT_WAIT_MS));
	if (!a.linger) {
		/* The sender has returned, closed its end and exited. */
		status = dqt_wait(&ch, &r, sizeof(r));
		ATF_REQUIRE_EQ(0, status);
		ATF_REQUIRE_EQ_MSG(0, r.r.rv, "sendfile: %s",
		    strerror(r.r.err));
		ATF_REQUIRE_EQ(NR_LEN, r.sbytes);
	}
	ATF_REQUIRE_MSG(held_bytes(&c, o->id, NR_LEN),
	    "the READ_ASYNC fills do not cover the file");

	kq = read_kqueue(sv[1]);
	check_not_readable(sv[1], kq, "before the fill");
	buf = malloc(NR_LEN + 1);
	ATF_REQUIRE(buf != NULL);
	reader_start(&rd, sv[1], buf, NR_LEN + 1);
	if (mode == NR_SHUT_RD || mode == NR_SHUT_RD_CLOSED) {
		/*
		 * The blocked reader is released at once, with EOF; the fills
		 * answered afterwards find nothing to ready.
		 */
		errno = 0;
		rv = shutdown(sv[1], SHUT_RD);
		if (mode == NR_SHUT_RD)
			ATF_CHECK_EQ_MSG(0, rv, "shutdown: %s",
			    strerror(errno));
		else
			ATF_CHECK_MSG(rv == -1 && errno == ENOTCONN,
			    "shutdown of the disconnected reader: %d, "
			    "errno %d", rv, errno);
		ATF_CHECK_MSG(reader_wait(&rd, DQT_WAIT_MS),
		    "shutdown(SHUT_RD) did not release the reader");
		if (rd.done) {
			ATF_CHECK_EQ_MSG(0, rd.last, "read: %zd, errno %d",
			    rd.last, rd.err);
			ATF_CHECK_EQ(0, rd.got);
		}
		answer_fills(&c, o, data, NR_LEN, error);
		dqt_msleep(100);
		if (mode == NR_SHUT_RD) {
			int soerr = -1;
			socklen_t len = sizeof(soerr);

			/* Only reading was shut: the connection stays. */
			ATF_CHECK_EQ(0, getsockopt(sv[1], SOL_SOCKET,
			    SO_ERROR, &soerr, &len));
			ATF_CHECK_EQ_MSG(0, soerr, "SO_ERROR %d", soerr);
			ATF_CHECK_EQ_MSG(1, send(sv[1], "x", 1, MSG_NOSIGNAL),
			    "write to the sender: %s", strerror(errno));
		}
	} else {
		answer_fills(&c, o, data, NR_LEN, error);
		check_reader(&rd, data, NR_LEN, error);
	}
	reader_finish(&rd);
	check_eof_event(kq);

	if (a.linger) {
		dqt_sync_post(s.tochild[1]);
		status = dqt_wait(&ch, &r, sizeof(r));
		ATF_CHECK_EQ(0, status);
		ATF_CHECK_EQ_MSG(0, r.r.rv, "sendfile: %s", strerror(r.r.err));
		ATF_CHECK_EQ(NR_LEN, r.sbytes);
		ATF_CHECK_EQ_MSG(0, r.sh.rv, "shutdown: %s",
		    strerror(r.sh.err));
		/* A failed fill reports on the sender (sendfile_iodone). */
		if (mode == NR_SHUT_RD)
			ATF_CHECK_EQ_MSG(error, r.so_error,
			    "the sender's SO_ERROR %d", r.so_error);
	}
	(void)close(kq);
	(void)close(sv[1]);
	free(buf);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(closed_before_fill);
ATF_TC_HEAD(closed_before_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender that closes its unix(4) "
	    "socket before the READ_ASYNC fills are answered: the reader gets "
	    "every byte, and EOF only after the last (read, poll, select, "
	    "kevent)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(closed_before_fill, tc)
{

	not_ready_end(NR_CLOSE, 0, 4);
}

ATF_TC(closed_before_failed_fill);
ATF_TC_HEAD(closed_before_failed_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender that closes its unix(4) "
	    "socket before a READ_ASYNC fill fails: the not ready data is cut "
	    "off the reader's buffer, which reports EPIPE, then EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(closed_before_failed_fill, tc)
{

	not_ready_end(NR_CLOSE, EIO, 5);
}

ATF_TC(shut_wr_before_fill);
ATF_TC_HEAD(shut_wr_before_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender that shuts down writing "
	    "(and stays connected) before the READ_ASYNC fills are answered: "
	    "the reader gets every byte, then EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_wr_before_fill, tc)
{

	not_ready_end(NR_SHUT_WR, 0, 6);
}

ATF_TC(shut_wr_before_failed_fill);
ATF_TC_HEAD(shut_wr_before_failed_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender that shuts down writing "
	    "before a READ_ASYNC fill fails: the reader gets EPIPE, then EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_wr_before_failed_fill, tc)
{

	not_ready_end(NR_SHUT_WR, EIO, 7);
}

ATF_TC(shut_rd_releases_reader);
ATF_TC_HEAD(shut_rd_releases_reader, tc)
{
	atf_tc_set_md_var(tc, "descr", "shutdown(SHUT_RD) from another thread "
	    "while a reader waits for not ready data (fill held, sender "
	    "connected) returns at once and the reader gets EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_rd_releases_reader, tc)
{

	not_ready_end(NR_SHUT_RD, 0, 8);
}

ATF_TC(shut_rd_releases_reader_closed);
ATF_TC_HEAD(shut_rd_releases_reader_closed, tc)
{
	atf_tc_set_md_var(tc, "descr", "shutdown(SHUT_RD) of a disconnected "
	    "reader waiting for its closed sender's not ready data: ENOTCONN, "
	    "and the reader is released with EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_rd_releases_reader_closed, tc)
{

	not_ready_end(NR_SHUT_RD_CLOSED, 0, 9);
}

/*
 * The fill fails after the reader's shutdown(SHUT_RD) cut the not ready
 * data: uipc_abort runs for a sendfile sender whose peer holds nothing of
 * the transfer (uxst_fnrdy NULL), and must not drop it.  The reader's
 * SO_ERROR stays 0 and it can still write; the sender gets EIO.  (The
 * uipc_sendfile_wait hang, sendfile to an already shut peer, is
 * shut_rd_peer_sendfile, which never reaches the abort.)
 */
ATF_TC(shut_rd_releases_reader_failed_fill);
ATF_TC_HEAD(shut_rd_releases_reader_failed_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "shutdown(SHUT_RD) releases a reader "
	    "waiting for not ready data; the fill then fails: the connection "
	    "is not dropped (reader SO_ERROR 0, can write), sender SO_ERROR EIO");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_rd_releases_reader_failed_fill, tc)
{

	not_ready_end(NR_SHUT_RD, EIO, 13);
}

/*
 * sendfile to a peer that has shut down reading: EPIPE at once (no wait for
 * space the shut buffer never gets back, no SIGPIPE), and the connection is
 * not aborted: the peer's SO_ERROR stays 0 and it can still write.  This
 * covers the uipc_sendfile_wait hang (a blocking sendfile to a shut peer
 * used to sleep forever); it fails before any I/O, so never reaches
 * uipc_abort (see shut_rd_releases_reader_failed_fill for that).
 */
struct sr_arg {
	int		 fd;
	int		 sock;
	int		 other;
	int		 ready;
	int		 go;
};

struct sr_res {
	struct dqt_rr	 r;
	off_t		 sbytes;
	ssize_t		 n;		/* recv of the peer's byte */
	int		 err;
};

static void
child_shut_peer(void *arg, void *result)
{
	struct sr_arg *a = arg;
	struct sr_res *r = result;
	unsigned char b;

	(void)close(a->other);
	r->sbytes = 0;
	r->r.rv = sendfile(a->fd, a->sock, 0, 0, NULL, &r->sbytes, 0);
	r->r.err = r->r.rv == -1 ? errno : 0;
	dqt_sync_post(a->ready);
	(void)dqt_sync_wait(a->go, 8 * DQT_WAIT_MS);
	r->n = recv(a->sock, &b, 1, MSG_DONTWAIT);
	r->err = r->n == -1 ? errno : 0;
	(void)close(a->sock);
}

ATF_TC(shut_rd_peer_sendfile);
ATF_TC_HEAD(shut_rd_peer_sendfile, tc)
{
	atf_tc_set_md_var(tc, "descr", "sendfile of a served file to a peer "
	    "that did shutdown(SHUT_RD) fails with EPIPE at once and does not "
	    "abort the connection: the peer keeps SO_ERROR 0 and can write");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shut_rd_peer_sendfile, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqt_child ch;
	struct dqt_sync s;
	struct sr_arg a;
	struct sr_res r;
	socklen_t len;
	int oracle, soerr, status, sv[2];

	dqt_fill(data, NR_LEN, 12);
	oracle = dqt_make_oracle("oracle", data, NR_LEN, oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, NR_LEN, NULL);
	dqt_hold(&c, true);
	dqt_sync_init(&s);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	ATF_REQUIRE_EQ(0, shutdown(sv[1], SHUT_RD));
	a.fd = o->fd;
	a.sock = sv[0];
	a.other = sv[1];
	a.ready = s.toparent[1];
	a.go = s.tochild[0];
	memset(&r, 0, sizeof(r));
	dqt_spawn(&ch, child_shut_peer, &a);
	(void)close(sv[0]);
	ATF_REQUIRE_MSG(dqt_sync_wait(s.toparent[0], DQT_WAIT_MS),
	    "sendfile to the shut peer did not return");
	/* Any fill already posted completes against nothing. */
	answer_fills(&c, o, data, NR_LEN, 0);
	dqt_msleep(100);
	soerr = -1;
	len = sizeof(soerr);
	ATF_CHECK_EQ(0, getsockopt(sv[1], SOL_SOCKET, SO_ERROR, &soerr, &len));
	ATF_CHECK_EQ_MSG(0, soerr, "the shut peer's SO_ERROR %d", soerr);
	ATF_CHECK_EQ_MSG(1, send(sv[1], "x", 1, MSG_NOSIGNAL),
	    "the shut peer's write: %s", strerror(errno));
	dqt_sync_post(s.tochild[1]);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_MSG(r.r.rv == -1 && r.r.err == EPIPE,
	    "sendfile: %ld, errno %d", r.r.rv, r.r.err);
	ATF_CHECK_EQ(0, r.sbytes);
	ATF_CHECK_EQ_MSG(1, r.n, "the sender's recv: %zd, errno %d", r.n,
	    r.err);
	(void)close(sv[1]);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * Reconnect: the sender's not ready data stays with its former peer.  The
 * child sends file 1 on s (to r) and file 2 on r (to s), both held.  File
 * 2's fill fails: r's abort drops s (unp_drop), which stays open,
 * disconnected, and connects to a new peer.  Then file 1's fill is
 * answered: the old receiver r gets its bytes (or EPIPE), and the new peer
 * is left alone.
 */
struct rc_arg {
	int		 fd1;
	int		 fd2;
	int		 s;
	int		 r;
	int		 ready;
	int		 go;
};

struct rc_res {
	struct dqt_rr	 sf1;
	struct dqt_rr	 sf2;
	struct dqt_rr	 conn;
	off_t		 sb1;
	off_t		 sb2;
};

static void
child_reconnect(void *arg, void *result)
{
	struct rc_arg *a = arg;
	struct rc_res *r = result;
	struct sockaddr_un sun;

	r->sb1 = r->sb2 = 0;
	r->sf1.rv = sendfile(a->fd1, a->s, 0, 0, NULL, &r->sb1, 0);
	r->sf1.err = r->sf1.rv == -1 ? errno : 0;
	r->sf2.rv = sendfile(a->fd2, a->r, 0, 0, NULL, &r->sb2, 0);
	r->sf2.err = r->sf2.rv == -1 ? errno : 0;
	(void)close(a->r);
	dqt_sync_post(a->ready);
	(void)dqt_sync_wait(a->go, 8 * DQT_WAIT_MS);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, NR_PATH, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	r->conn.rv = connect(a->s, (struct sockaddr *)&sun, sun.sun_len);
	r->conn.err = r->conn.rv == -1 ? errno : 0;
	dqt_sync_post(a->ready);
	(void)dqt_sync_wait(a->go, 8 * DQT_WAIT_MS);
	(void)close(a->s);
}

static void
reconnect_before_fill(int error, unsigned seed)
{
	struct dqt_ctl c;
	struct dqt_object *o1, *o2;
	struct dqt_child ch;
	struct dqt_sync s;
	struct rc_arg a;
	struct rc_res r;
	struct reader rd;
	struct sockaddr_un sun;
	struct pollfd pfd;
	socklen_t len;
	unsigned char *buf, b;
	char path2[DQT_PATH_MAX];
	ssize_t n;
	int cs, kq, l, oracle, oracle2, soerr, status, sv[2], waited;

	dqt_fill(data, NR_LEN, seed);
	dqt_fill(data2, NR_LEN2, seed + 100);
	oracle = dqt_make_oracle("oracle", data, NR_LEN, oracle_path,
	    sizeof(oracle_path));
	oracle2 = dqt_make_oracle("oracle2", data2, NR_LEN2, path2,
	    sizeof(path2));
	dqt_init(&c);
	o1 = dqt_mint(&c, oracle, oracle_path, data, NR_LEN, NULL);
	o2 = dqt_mint(&c, oracle2, path2, data2, NR_LEN2, NULL);
	dqt_hold(&c, true);

	l = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(l >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, NR_PATH, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	(void)unlink(NR_PATH);
	ATF_REQUIRE_EQ_MSG(0, bind(l, (struct sockaddr *)&sun, sun.sun_len),
	    "bind: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, listen(l, 1));

	dqt_sync_init(&s);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	a.fd1 = o1->fd;
	a.fd2 = o2->fd;
	a.s = sv[0];
	a.r = sv[1];
	a.ready = s.toparent[1];
	a.go = s.tochild[0];
	memset(&r, 0, sizeof(r));
	dqt_spawn(&ch, child_reconnect, &a);
	(void)close(sv[0]);
	ATF_REQUIRE(dqt_sync_wait(s.toparent[0], DQT_WAIT_MS));
	ATF_REQUIRE_MSG(held_bytes(&c, o1->id, NR_LEN),
	    "file 1's fills do not cover it");
	ATF_REQUIRE_MSG(held_bytes(&c, o2->id, NR_LEN2),
	    "file 2's fills do not cover it");

	/*
	 * r's own sendfile fails: its abort drops s.  sendfile_iodone sets
	 * r's SO_ERROR (EIO) after the abort; reading it clears it.
	 */
	answer_fills(&c, o2, data2, NR_LEN2, EIO);
	for (waited = 0;; waited += 10) {
		soerr = 0;
		len = sizeof(soerr);
		ATF_REQUIRE_EQ(0, getsockopt(sv[1], SOL_SOCKET, SO_ERROR,
		    &soerr, &len));
		if (soerr != 0 || waited >= DQT_WAIT_MS)
			break;
		dqt_msleep(10);
	}
	ATF_REQUIRE_EQ_MSG(EIO, soerr, "r's SO_ERROR %d", soerr);
	kq = read_kqueue(sv[1]);
	check_not_readable(sv[1], kq, "after the disconnect");

	/* s reconnects to a new peer. */
	dqt_sync_post(s.tochild[1]);
	pfd.fd = l;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_REQUIRE_EQ_MSG(1, poll(&pfd, 1, DQT_WAIT_MS),
	    "no connection from the reconnecting sender");
	cs = accept(l, NULL, NULL);
	ATF_REQUIRE(cs >= 0);
	ATF_REQUIRE(dqt_sync_wait(s.toparent[0], DQT_WAIT_MS));
	check_not_readable(sv[1], kq, "after the reconnect");

	buf = malloc(NR_LEN + 1);
	ATF_REQUIRE(buf != NULL);
	reader_start(&rd, sv[1], buf, NR_LEN + 1);
	answer_fills(&c, o1, data, NR_LEN, error);
	check_reader(&rd, data, NR_LEN, error);
	reader_finish(&rd);
	check_eof_event(kq);

	/* The new peer is untouched: no data, no error, still connected. */
	errno = 0;
	n = recv(cs, &b, 1, MSG_DONTWAIT);
	ATF_CHECK_MSG(n == -1 && errno == EAGAIN,
	    "the new peer: recv %zd, errno %d", n, errno);
	soerr = -1;
	len = sizeof(soerr);
	ATF_CHECK_EQ(0, getsockopt(cs, SOL_SOCKET, SO_ERROR, &soerr, &len));
	ATF_CHECK_EQ_MSG(0, soerr, "the new peer's SO_ERROR %d", soerr);

	dqt_sync_post(s.tochild[1]);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(0, status);
	ATF_CHECK_EQ_MSG(0, r.sf1.rv, "sendfile 1: %s", strerror(r.sf1.err));
	ATF_CHECK_EQ(NR_LEN, r.sb1);
	ATF_CHECK_EQ_MSG(0, r.sf2.rv, "sendfile 2: %s", strerror(r.sf2.err));
	ATF_CHECK_EQ(NR_LEN2, r.sb2);
	ATF_CHECK_EQ_MSG(0, r.conn.rv, "reconnect: %s", strerror(r.conn.err));

	(void)close(cs);
	(void)close(l);
	(void)unlink(NR_PATH);
	(void)close(kq);
	(void)close(sv[1]);
	free(buf);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
	(void)close(oracle2);
}

ATF_TC(reconnect_before_fill);
ATF_TC_HEAD(reconnect_before_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender disconnected (by its peer's "
	    "aborted sendfile) that reconnects before its READ_ASYNC fills are "
	    "answered: the former peer gets every byte, the new one nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reconnect_before_fill, tc)
{

	reconnect_before_fill(0, 10);
}

ATF_TC(reconnect_before_failed_fill);
ATF_TC_HEAD(reconnect_before_failed_fill, tc)
{
	atf_tc_set_md_var(tc, "descr", "a sender that reconnects before its "
	    "READ_ASYNC fill fails: the former peer gets EPIPE, then EOF; the "
	    "new peer is not dropped");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reconnect_before_failed_fill, tc)
{

	reconnect_before_fill(EIO, 11);
}

ATF_TC(controller_edeadlk);
ATF_TC_HEAD(controller_edeadlk, tc)
{
	atf_tc_set_md_var(tc, "descr", "the controller's own sendfile of a "
	    "served file is EDEADLK at once (its pages would wait on itself)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(controller_edeadlk, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	off_t sbytes;
	int oracle, sv[2];

	dqt_fill(data, sizeof(data), 3);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	sbytes = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, sendfile(o->fd, sv[0], 0, 100, NULL, &sbytes, 0));
	ATF_CHECK_EQ(EDEADLK, errno);
	ATF_CHECK_EQ(0, sbytes);
	dqt_lock(&c);
	ATF_CHECK_EQ(0, c.records);
	dqt_unlock(&c);
	(void)close(sv[0]);
	(void)close(sv[1]);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, oracle_redacted);
	ATF_TP_ADD_TC(tp, revoke_eio);
	ATF_TP_ADD_TC(tp, closed_before_fill);
	ATF_TP_ADD_TC(tp, closed_before_failed_fill);
	ATF_TP_ADD_TC(tp, shut_wr_before_fill);
	ATF_TP_ADD_TC(tp, shut_wr_before_failed_fill);
	ATF_TP_ADD_TC(tp, shut_rd_releases_reader);
	ATF_TP_ADD_TC(tp, shut_rd_releases_reader_closed);
	ATF_TP_ADD_TC(tp, shut_rd_releases_reader_failed_fill);
	ATF_TP_ADD_TC(tp, shut_rd_peer_sendfile);
	ATF_TP_ADD_TC(tp, reconnect_before_fill);
	ATF_TP_ADD_TC(tp, reconnect_before_failed_fill);
	ATF_TP_ADD_TC(tp, controller_edeadlk);
	return (atf_no_error());
}
