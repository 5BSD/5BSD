/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * sendfile(2) of a served file (D104): the pages are filled by READ_ASYNC
 * events (answered as READ), sent from the dq pager object.  The oracle is
 * sendfile of a real file of the same length over the same kind of socket;
 * the served bytes are the controller's (here a redacted copy).
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

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
	int sv[2], status;

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
	status = dqt_wait(&ch, r, sizeof(*r));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "sender status %#x", status);
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
	ATF_CHECK(c.events[DQ_OP_READ_ASYNC] >= 1);
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
	int oracle, status, sv[2];

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
	ATF_CHECK_EQ(DQ_OP_READ_ASYNC, c.held[0].op);
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	dqt_sync_post(gop[1]);
	/* Drain whatever was sent before the revoke. */
	while (read(sv[1], buf, sizeof(buf)) > 0)
		continue;
	(void)close(sv[1]);
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_CHECK(WIFEXITED(status));
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
	ATF_CHECK_EQ(-1, dq_reply(c.q, c.held[0].id, 0, data, 16));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_hold(&c, false);
	dqt_fini(&c);
	(void)close(oracle);
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
	ATF_CHECK_EQ(0, c.records);
	(void)close(sv[0]);
	(void)close(sv[1]);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, oracle_redacted);
	ATF_TP_ADD_TC(tp, revoke_eio);
	ATF_TP_ADD_TC(tp, controller_edeadlk);
	return (atf_no_error());
}
