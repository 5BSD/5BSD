/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Lifecycle: CLOSE at the last reference, ids never reused, REVOKE, the
 * controller going away, and the transfer rule of a minted descriptor.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	8192

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct one_read_arg {
	int		 fd;
	size_t		 len;
};

/* read(2) once; the pipe carries the result. */
static void
child_one_read(void *arg, void *result)
{
	struct one_read_arg *a = arg;
	struct dqt_rr *r = result;
	unsigned char buf[4096];

	r->rv = read(a->fd, buf, MIN(a->len, sizeof(buf)));
	r->err = r->rv == -1 ? errno : 0;
}

/*
 * The object is still referenced: it is still counted live (a CLOSE is
 * posted only after it retires), and no CLOSE was due before the fence's.
 */
static void
no_close_yet(struct dqt_ctl *c)
{
	struct dq_stats2 st;

	dqt_close_fence(c);
	dqt_stats2(c, &st);
	ATF_CHECK_EQ_MSG(1, st.ds2_objects_live, "%ju objects live",
	    (uintmax_t)st.ds2_objects_live);
	dqt_lock(c);
	ATF_CHECK_EQ(0, c->events[DQ_OP_CLOSE]);
	dqt_unlock(c);
}

ATF_TC_WITH_CLEANUP(close_once);
ATF_TC_HEAD(close_once, tc)
{
	atf_tc_set_md_var(tc, "descr", "CLOSE is posted once, at the last "
	    "reference across dup, fork and a /dev/fd reopen");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_once, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_policy pol;
	struct one_read_arg a;
	struct dqt_rr r;
	char link[64];
	int d, oracle, reopen;

	/* A private fdescfs for the reopen reference (the guest has no /dev/fd). */
	dqt_mount_fdesc(NULL);
	dqt_fill(data, sizeof(data), 51);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_CLOSE;
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);

	d = dup(o->fd);
	ATF_REQUIRE(d != -1);
	/* fdescfs answers ENODEV and dupfdopen shares the file. */
	snprintf(link, sizeof(link), "%s/%d", DQT_FDESC_DIR, o->fd);
	reopen = open(link, O_RDONLY);
	ATF_REQUIRE_MSG(reopen != -1, "open %s: %s", link, strerror(errno));
	/* A child's copies go away at its exit: no CLOSE yet. */
	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(100, r.rv);
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.events[DQ_OP_READ]);
	dqt_unlock(&c);
	no_close_yet(&c);

	ATF_REQUIRE_EQ(0, close(o->fd));
	o->fd = -1;
	ATF_REQUIRE_EQ(0, close(d));
	no_close_yet(&c);
	ATF_REQUIRE_EQ(0, close(reopen));
	ATF_CHECK(dqt_wait_events(&c, DQ_OP_CLOSE, 1, DQT_WAIT_MS));
	/* A second CLOSE would have been dispatched before the fence's. */
	dqt_close_fence(&c);
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.events[DQ_OP_CLOSE]);
	ATF_CHECK_EQ(1, o->closes);
	dqt_unlock(&c);
	/*
	 * Series ii: CLOSE is posted by the deferred destroy task after the
	 * write-back of any dirty pages, as a kernel caller (pid 0); the
	 * record needs no answer.
	 */
	dqt_lock(&c);
	ATF_CHECK((c.op_caller[DQ_OP_CLOSE].dc_flags & DQ_CALLER_F_KERNEL) != 0);
	ATF_CHECK_EQ(0, c.op_caller[DQ_OP_CLOSE].dc_pid);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}
ATF_TC_CLEANUP(close_once, tc)
{
	dqt_umount_fdesc();
}

ATF_TC(ids_never_reused);
ATF_TC_HEAD(ids_never_reused, tc)
{
	atf_tc_set_md_var(tc, "descr", "object ids increase and are never "
	    "reused after close or revoke");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ids_never_reused, tc)
{
	struct dqt_ctl c;
	struct dqt_object *a, *b, *d, *e, *f;
	struct dq_stats st;
	int oracle;

	dqt_fill(data, sizeof(data), 52);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	a = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	b = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	d = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_CHECK(a->id < b->id && b->id < d->id);

	ATF_REQUIRE_EQ(0, close(a->fd));	/* retires a */
	a->fd = -1;
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, b->id));
	e = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_CHECK(e->id > d->id);
	ATF_REQUIRE_EQ(0, close(e->fd));
	e->fd = -1;
	f = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_CHECK(f->id > e->id);

	dqt_stats(&c, &st);
	ATF_CHECK_EQ(5, st.ds_objects_total);
	ATF_CHECK_EQ(3, st.ds_objects_live);	/* b (revoked), d, f */
	ATF_CHECK_EQ(1, st.ds_objects_revoked);
	/* A retired id is unknown to the control ioctls. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_revoke(c.q, a->id));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(revoke);
ATF_TC_HEAD(revoke, tc)
{
	atf_tc_set_md_var(tc, "descr", "REVOKE: reads answer EIO, the frozen "
	    "identity keeps answering, NOTE_REVOKE fires and READ/WRITE knotes "
	    "report EV_EOF");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoke, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_rr r;
	struct kevent kev[3], out[3];
	struct timespec zero = { 0, 0 };
	struct stat before, after;
	struct statfs sfs;
	struct kinfo_file kif;
	struct pollfd pfd;
	int i, kq, n, oracle;
	bool rd, wr, vn;

	dqt_fill(data, sizeof(data), 53);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	ATF_REQUIRE_EQ(0, fstat(o->fd, &before));

	kq = kqueue();
	ATF_REQUIRE(kq != -1);
	EV_SET(&kev[0], o->fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	EV_SET(&kev[1], o->fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
	EV_SET(&kev[2], o->fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_REVOKE, 0,
	    NULL);
	ATF_REQUIRE_EQ(0, kevent(kq, kev, 3, NULL, 0, NULL));
	/* Drain the initial readiness of READ (data) and WRITE (always). */
	(void)kevent(kq, NULL, 0, out, 3, &zero);

	a.fd = o->fd;
	a.len = 100;
	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(100, r.rv);

	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	/* Idempotent: the object is still in the table, already revoked. */
	ATF_CHECK_EQ(0, dq_revoke(c.q, o->id));

	dqt_run_child(child_one_read, &a, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EIO, r.err);
	dqt_lock(&c);
	ATF_CHECK_EQ(1, c.events[DQ_OP_READ]);	/* nothing was posted */

	/* Design 9: fstat, F_KINFO, fstatfs, fpathconf keep answering. */
	ATF_REQUIRE_EQ(0, fstat(o->fd, &after));
	dqt_unlock(&c);
	dqt_check_stat_eq(&after, &before);
	memset(&kif, 0, sizeof(kif));
	kif.kf_structsize = sizeof(kif);
	ATF_REQUIRE_EQ(0, fcntl(o->fd, F_KINFO, &kif));
	ATF_CHECK_STREQ(oracle_path, kif.kf_path);
	ATF_CHECK_EQ(0, fstatfs(o->fd, &sfs));
	ATF_CHECK(fpathconf(o->fd, _PC_NAME_MAX) > 0);
	ATF_CHECK_EQ(100, lseek(o->fd, 100, SEEK_SET));
	pfd.fd = o->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	ATF_CHECK_EQ(1, poll(&pfd, 1, 0));

	n = kevent(kq, NULL, 0, out, 3, &zero);
	ATF_REQUIRE_EQ(3, n);
	rd = wr = vn = false;
	for (i = 0; i < n; i++) {
		switch (out[i].filter) {
		case EVFILT_READ:
			rd = true;
			ATF_CHECK((out[i].flags & EV_EOF) != 0);
			break;
		case EVFILT_WRITE:
			wr = true;
			ATF_CHECK((out[i].flags & EV_EOF) != 0);
			break;
		case EVFILT_VNODE:
			vn = true;
			ATF_CHECK((out[i].fflags & NOTE_REVOKE) != 0);
			ATF_CHECK((out[i].flags & EV_EOF) != 0);
			break;
		}
	}
	ATF_CHECK(rd && wr && vn);
	(void)close(kq);

	errno = 0;
	ATF_CHECK_EQ(-1, dq_revoke(c.q, o->id + 1000));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC(revoke_wakes_waiter);
ATF_TC_HEAD(revoke_wakes_waiter, tc)
{
	atf_tc_set_md_var(tc, "descr", "REVOKE fails a delivered event with EIO "
	    "and a late reply to it is ESRCH");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoke_wakes_waiter, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct one_read_arg a;
	struct dqt_child ch;
	struct dqt_rr r;
	struct dq_stats st;
	int oracle;

	dqt_fill(data, sizeof(data), 54);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dqt_hold(&c, true);

	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_one_read, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_REQUIRE_EQ(0, dq_revoke(c.q, o->id));
	dqt_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EIO, r.err);

	/* The event left the in-flight tree with the revoke. */
	errno = 0;
	dqt_lock(&c);
	ATF_CHECK_EQ(-1, dq_reply(c.q, c.held[0].id, 0, data, 100));
	dqt_unlock(&c);
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(1, st.ds_late_replies);
	ATF_CHECK_EQ(0, st.ds_inflight);
	ATF_CHECK_EQ(1, st.ds_objects_revoked);
	dqt_fini(&c);
	(void)close(oracle);
}

struct exit_arg {
	int		 fd;
	int		 fd_getattr;
};

struct exit_res {
	struct dqt_rr	 rd;
	struct dqt_rr	 st;
	struct dqt_rr	 st_getattr;
	struct dqt_rr	 pl;
	struct stat	 sb;
};

/* After the controller is gone: every posting operation is EIO, at once. */
static void
child_after_exit(void *arg, void *result)
{
	struct exit_arg *a = arg;
	struct exit_res *r = result;
	struct pollfd pfd;
	struct stat sb;
	unsigned char buf[100];

	r->rd.rv = read(a->fd, buf, sizeof(buf));
	r->rd.err = r->rd.rv == -1 ? errno : 0;
	r->st.rv = fstat(a->fd, &r->sb);
	r->st.err = r->st.rv == -1 ? errno : 0;
	r->st_getattr.rv = fstat(a->fd_getattr, &sb);
	r->st_getattr.err = r->st_getattr.rv == -1 ? errno : 0;
	pfd.fd = a->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	r->pl.rv = poll(&pfd, 1, 0);
	r->pl.err = r->pl.rv == -1 ? errno : 0;
}

ATF_TC(controller_exit);
ATF_TC_HEAD(controller_exit, tc)
{
	atf_tc_set_md_var(tc, "descr", "when the queue closes every object is "
	    "revoked: reads and GETATTR stats answer EIO without hanging, the "
	    "frozen identity still answers");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(controller_exit, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o, *og;
	struct dq_policy pol;
	struct exit_arg a;
	struct exit_res r;
	struct stat before;
	int oracle;

	dqt_fill(data, sizeof(data), 55);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_GETATTR;
	og = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), &pol);
	ATF_REQUIRE_EQ(0, fstat(o->fd, &before));

	/* The controller exits: its last reference to the queue goes. */
	dqt_close_queue(&c);

	a.fd = o->fd;
	a.fd_getattr = og->fd;
	dqt_run_child(child_after_exit, &a, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.rd.rv);
	ATF_CHECK_EQ(EIO, r.rd.err);
	ATF_CHECK_EQ(0, r.st.rv);
	dqt_check_stat_eq(&r.sb, &before);
	/*
	 * dq_stat posts GETATTR only while the object is live and the queue
	 * open; afterwards the frozen identity answers (dq_file.c).
	 */
	ATF_CHECK_EQ(0, r.st_getattr.rv);
	ATF_CHECK_EQ(1, r.pl.rv);
	/* The descriptors still close cleanly. */
	ATF_CHECK_EQ(0, close(o->fd));
	o->fd = -1;
	ATF_CHECK_EQ(0, close(og->fd));
	og->fd = -1;
	dqt_fini(&c);
	(void)close(oracle);
}

/* What the unattached holder saw, in the order it saw it. */
struct holder_res {
	struct dqt_rr	 before;	/* read while the supervisor lives */
	struct dqt_rr	 after;		/* read after it has exited */
	struct dqt_rr	 st;		/* fstat after */
	struct dqt_rr	 cl;		/* close after */
	int		 attached;	/* PROC_NO_NEW_PRIVS_STATUS: ATTACH sets it */
};

/*
 * The supervisor's queue and object, in a forked child: libdq only, and an
 * exit status (60 + step) where a body would have failed.
 */
static int
sup_mint(int oracle, int *qp)
{
	struct dq_ident_file ident;
	struct dq_policy pol;
	struct statfs sfs;
	struct stat st;
	uint64_t id;
	int fd, q;

	q = dq_open();
	if (q == -1)
		_exit(60);
	if (fstat(oracle, &st) != 0 || fstatfs(oracle, &sfs) != 0 ||
	    dq_ident_from_stat(&ident, oracle_path, &st, &sfs, oracle) != 0)
		_exit(61);
	dq_policy_default(&pol);
	if (dq_mint_file(q, &ident, &pol, &id, &fd, NULL) != 0)
		_exit(62);
	*qp = q;
	return (fd);
}

/* Answer the first READ on q from data; any other waited event EIO. */
static int
sup_serve_read(int q)
{
	static char buf[65536];
	const struct dq_read_body *rb;
	const struct dq_event *ev;
	ssize_t got;
	size_t len;

	for (;;) {
		if (dq_read_events(q, buf, sizeof(buf), &got) != 0)
			return (-1);
		for (ev = dq_event_first(buf, (size_t)got); ev != NULL;
		    ev = dq_event_next(buf, (size_t)got, ev)) {
			if (ev->de_op != DQ_OP_READ) {
				if (ev->de_id != 0)
					(void)dq_reply(q, ev->de_id, EIO, NULL,
					    0);
				continue;
			}
			if (dq_event_read(ev, &rb) != 0)
				return (-1);
			len = rb->dr_offset >= sizeof(data) ? 0 :
			    MIN(rb->dr_len, sizeof(data) - rb->dr_offset);
			return (dq_reply(q, ev->de_id, 0,
			    data + (len != 0 ? rb->dr_offset : 0), len));
		}
	}
}

ATF_TC(unattached_holder_survives);
ATF_TC_HEAD(unattached_holder_survives, tc)
{
	atf_tc_set_md_var(tc, "descr", "a process that inherited a minted "
	    "descriptor but was never attached outlives the exit of the "
	    "supervisor process: its next read fails EIO, nothing signals "
	    "it, and it exits 0 by itself");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(unattached_holder_survives, tc)
{
	struct holder_res r;
	struct procctl_reaper_status rs;
	struct stat sb;
	unsigned char buf[100];
	sigset_t all, pend;
	pid_t holder, sup;
	int fd, go[2], hp[2], oracle, q, ready[2], res[2], sig, status;
	char b;

	dqt_require_plane();
	/*
	 * The holder is the supervisor's child and is orphaned by its exit;
	 * as the reaper this process becomes its parent and reads its exit
	 * status, which is the pin.
	 */
	ATF_REQUIRE_EQ(0, procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL));
	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(hp));
	ATF_REQUIRE_EQ(0, pipe(ready));
	ATF_REQUIRE_EQ(0, pipe(res));
	dqt_fill(data, sizeof(data), 56);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));

	sup = fork();
	ATF_REQUIRE_MSG(sup != -1, "fork: %s", strerror(errno));
	if (sup == 0) {
		/*
		 * The supervisor: a queue and one object, made with libdq
		 * alone (no ATF call in a forked child); it answers the
		 * holder's first read itself.
		 */
		fd = sup_mint(oracle, &q);
		holder = fork();
		if (holder == -1)
			_exit(70);
		if (holder == 0) {
			/*
			 * The holder: every signal blocked, so that one sent
			 * to it stays pending and is seen below.
			 */
			sigfillset(&all);
			(void)sigprocmask(SIG_BLOCK, &all, NULL);
			memset(&r, 0, sizeof(r));
			r.before.rv = read(fd, buf, sizeof(buf));
			r.before.err = r.before.rv == -1 ? errno : 0;
			if (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS,
			    &r.attached) != 0)
				r.attached = -1;
			if (write(ready[1], "r", 1) != 1)
				_exit(71);
			if (read(go[0], &b, 1) != 1)
				_exit(72);
			r.after.rv = pread(fd, buf, sizeof(buf), 4096);
			r.after.err = r.after.rv == -1 ? errno : 0;
			r.st.rv = fstat(fd, &sb);
			r.st.err = r.st.rv == -1 ? errno : 0;
			r.cl.rv = close(fd);
			r.cl.err = r.cl.rv == -1 ? errno : 0;
			if (write(res[1], &r, sizeof(r)) != sizeof(r))
				_exit(73);
			/*
			 * Nothing pending.  The supervisor was reaped before
			 * the go byte: its exit had finished, and whatever
			 * its exit sends had been sent.
			 */
			sigemptyset(&pend);
			(void)sigpending(&pend);
			for (sig = 1; sig < NSIG; sig++)
				if (sigismember(&pend, sig))
					_exit(100 + sig);
			_exit(0);
		}
		if (write(hp[1], &holder, sizeof(holder)) != sizeof(holder))
			_exit(74);
		/* Serve the holder's first read, then exit: not a close. */
		if (sup_serve_read(q) != 0)
			_exit(76);
		if (read(ready[0], &b, 1) != 1)
			_exit(75);
		_exit(0);
	}
	(void)close(go[0]);
	(void)close(ready[1]);
	(void)close(res[1]);
	(void)close(hp[1]);
	ATF_REQUIRE_EQ((ssize_t)sizeof(holder), read(hp[0], &holder,
	    sizeof(holder)));

	/* The supervisor has exited and been reaped: its queue is closed. */
	ATF_REQUIRE_EQ(sup, waitpid(sup, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "supervisor status %#x", status);

	/* The holder is this process's child now, and alive. */
	ATF_REQUIRE_EQ(0, procctl(P_PID, getpid(), PROC_REAP_STATUS, &rs));
	ATF_CHECK_EQ_MSG(1, (int)rs.rs_children, "%u children",
	    rs.rs_children);
	ATF_CHECK_EQ_MSG(0, waitpid(holder, &status, WNOHANG),
	    "the holder did not outlive the supervisor: status %#x", status);
	ATF_CHECK_EQ(0, kill(holder, 0));

	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&r, 0xff, sizeof(r));
	ATF_REQUIRE_EQ((ssize_t)sizeof(r), read(res[0], &r, sizeof(r)));
	ATF_CHECK_EQ_MSG((long)sizeof(buf), r.before.rv,
	    "read while served: %ld errno %d", r.before.rv, r.before.err);
	ATF_CHECK_EQ_MSG(PROC_NO_NEW_PRIVS_DISABLE, r.attached,
	    "the holder looks attached (no_new_privs %d)", r.attached);
	ATF_CHECK_EQ(-1, r.after.rv);
	ATF_CHECK_EQ_MSG(EIO, r.after.err, "read after: errno %d",
	    r.after.err);
	ATF_CHECK_EQ_MSG(0, r.st.rv, "fstat after: errno %d", r.st.err);
	ATF_CHECK_EQ_MSG(0, r.cl.rv, "close after: errno %d", r.cl.err);

	/* It exits by itself, 0, no signal having been sent to it. */
	ATF_REQUIRE_EQ(holder, waitpid(holder, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "holder status %#x (exit 100+N: signal N was pending)", status);
	(void)close(oracle);
}

ATF_TC(scm_rights_refused);
ATF_TC_HEAD(scm_rights_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a minted descriptor is installed "
	    "CAP_XFER_NONE: sendmsg(SCM_RIGHTS) of it fails with ENOTCAPABLE "
	    "(I6)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(scm_rights_refused, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	char byte;
	int oracle, sv[2];

	dqt_fill(data, sizeof(data), 56);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
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
	memcpy(CMSG_DATA(cm), &o->fd, sizeof(int));
	errno = 0;
	ATF_CHECK_EQ(-1, sendmsg(sv[0], &msg, 0));
	ATF_CHECK_EQ(ENOTCAPABLE, errno);
	/* The real file travels; only the served one is refused. */
	memcpy(CMSG_DATA(cm), &oracle, sizeof(int));
	ATF_CHECK_EQ(1, sendmsg(sv[0], &msg, 0));
	/* dup and fork share it; the dup is as untransferable. */
	ATF_CHECK(dup(o->fd) >= 0);
	(void)close(sv[0]);
	(void)close(sv[1]);
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TC_WITH_CLEANUP(devfd_reopen_shares_queue);
ATF_TC_HEAD(devfd_reopen_shares_queue, tc)
{
	atf_tc_set_md_var(tc, "descr", "open of the queue's fdescfs fd link "
	    "is a dup of the same queue (fdescfs dupfdopen), not a new open");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(devfd_reopen_shares_queue, tc)
{
	struct dqt_ctl c;
	struct dq_stats st1, st2;
	char link[64];
	int fd2;

	/*
	 * A private fdescfs instance in the work directory (the guest may not
	 * mount one on /dev/fd), plain: its nodes are VCHR, so open(2) of one
	 * reaches fdesc_open and dupfdopen instead of following a link.
	 */
	dqt_mount_fdesc(NULL);
	dqt_init_manual(&c);
	snprintf(link, sizeof(link), "%s/%d", DQT_FDESC_DIR, c.q);
	fd2 = open(link, O_RDWR);
	ATF_REQUIRE_MSG(fd2 != -1, "open %s: %s", link, strerror(errno));
	/*
	 * fdesc_open answers ENODEV with td_dupfd set and dupfdopen shares
	 * the existing struct file, so no d_open runs: the same queue, the
	 * same kernel-wide id.  Only a path open of /dev/dq creates a queue.
	 */
	ATF_REQUIRE_EQ(0, dq_get_stats(c.q, &st1));
	ATF_REQUIRE_EQ(0, dq_get_stats(fd2, &st2));
	ATF_CHECK_EQ(st1.ds_queue_id, st2.ds_queue_id);
	(void)close(fd2);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(devfd_reopen_shares_queue, tc)
{
	dqt_umount_fdesc();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, close_once);
	ATF_TP_ADD_TC(tp, ids_never_reused);
	ATF_TP_ADD_TC(tp, revoke);
	ATF_TP_ADD_TC(tp, revoke_wakes_waiter);
	ATF_TP_ADD_TC(tp, controller_exit);
	ATF_TP_ADD_TC(tp, unattached_holder_survives);
	ATF_TP_ADD_TC(tp, scm_rights_refused);
	ATF_TP_ADD_TC(tp, devfd_reopen_shares_queue);
	return (atf_no_error());
}
