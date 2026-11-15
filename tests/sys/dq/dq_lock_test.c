/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Locks (D98, B6, N11): fcntl(2) record locks, OFD locks and flock(2) on a
 * served file are LOCK events the requester waits for without a deadline;
 * close and exit release them with UNLOCK_ALL, posted without waiting and
 * only for an object that ever locked.  The controller here is
 * dq_serve_file(), which proxies each owner onto its own open of a backing
 * file, so conflicts between requesters are the backing file's.  The oracle
 * is a second real file locked the same way by the same processes.
 *
 * Declared difference: dq_serve_file() answers F_GETLK with l_pid -1 (it
 * proxies through OFD locks and does not track which owner holds the
 * blocker); a real file reports the POSIX owner's pid.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	4096
#define	MAX_OPS		10

static unsigned char data[DATA_LEN];
static char backing_path[DQT_PATH_MAX];
static char oracle_path[DQT_PATH_MAX];

struct fixture {
	struct dqt_ctl	 c;
	struct dqt_object *o;
	int		 backing;
	int		 oracle;
};

static int
open_rw(const char *name, char *path)
{
	int fd;

	fd = dqt_make_oracle(name, data, sizeof(data), path, DQT_PATH_MAX);
	(void)close(fd);
	fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

static void
setup_pol(struct fixture *f, unsigned seed, const struct dq_policy *pol)
{

	dqt_fill(data, sizeof(data), seed);
	f->backing = open_rw("backing", backing_path);
	f->oracle = open_rw("oracle", oracle_path);
	dqt_init(&f->c);
	f->o = dqt_mint_backing(&f->c, f->backing, backing_path, pol,
	    DQ_MINT_F_WRITE);
}

static void
setup(struct fixture *f, unsigned seed)
{

	setup_pol(f, seed, NULL);
}

static void
teardown(struct fixture *f)
{

	dqt_lock(&f->c);
	ATF_CHECK_EQ_MSG(0, f->c.reply_failures, "reply failures: last %d",
	    f->c.last_reply_errno);
	dqt_unlock(&f->c);
	dqt_fini(&f->c);
	(void)close(f->backing);
	(void)close(f->oracle);
}

/*
 * A requester that holds what it locked until told to go: it writes one
 * byte to ready once its locks are set, then waits for one byte on go.
 */
struct holder_arg {
	int		 sfd, ofd;
	int		 ready[2], go[2];
	short		 type;
	off_t		 start, len;
	int		 cmd;		/* F_SETLK or F_OFD_SETLK; 0: flock */
};

struct holder_res {
	struct dqt_rr	 s, o;
	pid_t		 pid;
};

static void
setfl(struct flock *fl, short type, off_t start, off_t len)
{

	memset(fl, 0, sizeof(*fl));
	fl->l_type = type;
	fl->l_whence = SEEK_SET;
	fl->l_start = start;
	fl->l_len = len;
}

static void
child_holder(void *arg, void *result)
{
	struct holder_arg *a = arg;
	struct holder_res *r = result;
	struct flock fl;
	char b;

	(void)close(a->ready[0]);
	(void)close(a->go[1]);
	r->pid = getpid();
	if (a->cmd == 0) {
		r->s.rv = flock(a->sfd, LOCK_EX | LOCK_NB);
		r->s.err = r->s.rv == -1 ? errno : 0;
		r->o.rv = flock(a->ofd, LOCK_EX | LOCK_NB);
		r->o.err = r->o.rv == -1 ? errno : 0;
	} else {
		setfl(&fl, a->type, a->start, a->len);
		r->s.rv = fcntl(a->sfd, a->cmd, &fl);
		r->s.err = r->s.rv == -1 ? errno : 0;
		setfl(&fl, a->type, a->start, a->len);
		r->o.rv = fcntl(a->ofd, a->cmd, &fl);
		r->o.err = r->o.rv == -1 ? errno : 0;
	}
	b = 'r';
	(void)write(a->ready[1], &b, 1);
	(void)read(a->go[0], &b, 1);
}

static void
holder_start(struct holder_arg *a, struct dqt_child *ch)
{
	char b;

	ATF_REQUIRE_EQ(0, pipe(a->ready));
	ATF_REQUIRE_EQ(0, pipe(a->go));
	dqt_spawn(ch, child_holder, a);
	(void)close(a->ready[1]);
	(void)close(a->go[0]);
	ATF_REQUIRE_EQ(1, read(a->ready[0], &b, 1));
	(void)close(a->ready[0]);
}

static void
holder_release(struct holder_arg *a, struct dqt_child *ch,
    struct holder_res *r)
{
	char b;

	b = 'g';
	(void)write(a->go[1], &b, 1);
	(void)close(a->go[1]);
	dqt_collect(ch, r, sizeof(*r));
}

/* A second requester's attempts, each on both files. */
struct probe {
	int		 cmd;		/* fcntl command; 0 = flock(how) */
	int		 how;
	short		 type;
	off_t		 start, len;
};

struct probe_arg {
	int		 sfd, ofd;
	int		 n;
	struct probe	 p[MAX_OPS];
};

struct probe_res {
	struct dqt_rr	 s[MAX_OPS], o[MAX_OPS];
	struct flock	 sfl[MAX_OPS], ofl[MAX_OPS];
};

static void
child_probe(void *arg, void *result)
{
	struct probe_arg *a = arg;
	struct probe_res *r = result;
	int i, k, fd;

	for (i = 0; i < a->n; i++) {
		for (k = 0; k < 2; k++) {
			struct dqt_rr *rr = k == 0 ? &r->s[i] : &r->o[i];
			struct flock *fl = k == 0 ? &r->sfl[i] : &r->ofl[i];

			fd = k == 0 ? a->sfd : a->ofd;
			if (a->p[i].cmd == 0) {
				rr->rv = flock(fd, a->p[i].how);
			} else {
				setfl(fl, a->p[i].type, a->p[i].start,
				    a->p[i].len);
				rr->rv = fcntl(fd, a->p[i].cmd, fl);
			}
			rr->err = rr->rv == -1 ? errno : 0;
		}
	}
}

static void
check_probe(const struct probe_arg *a, const struct probe_res *r)
{
	int i;

	for (i = 0; i < a->n; i++) {
		ATF_CHECK_EQ_MSG(r->o[i].rv, r->s[i].rv,
		    "probe %d: served %ld oracle %ld", i, r->s[i].rv,
		    r->o[i].rv);
		ATF_CHECK_EQ_MSG(r->o[i].err, r->s[i].err,
		    "probe %d: served errno %d oracle %d", i, r->s[i].err,
		    r->o[i].err);
		if (a->p[i].cmd == F_GETLK || a->p[i].cmd == F_OFD_GETLK) {
			ATF_CHECK_EQ(r->ofl[i].l_type, r->sfl[i].l_type);
			ATF_CHECK_EQ(r->ofl[i].l_start, r->sfl[i].l_start);
			ATF_CHECK_EQ(r->ofl[i].l_len, r->sfl[i].l_len);
			ATF_CHECK_EQ(SEEK_SET, r->sfl[i].l_whence);
		}
	}
}

#define	PROBE(a, c, h, t, s, l) do {					\
	(a)->p[(a)->n].cmd = (c);					\
	(a)->p[(a)->n].how = (h);					\
	(a)->p[(a)->n].type = (t);					\
	(a)->p[(a)->n].start = (s);					\
	(a)->p[(a)->n].len = (l);					\
	(a)->n++;							\
} while (0)

/* The UNLOCK_ALL records naming owner of kind. */
static int
count_unlocks(struct dqt_ctl *c, const struct dqt_object *o, uint32_t kind,
    uint64_t owner)
{
	int i, n;

	dqt_lock(c);
	for (i = n = 0; i < o->nunlocks; i++) {
		if (o->unlocks[i].dua_kind == kind &&
		    o->unlocks[i].dua_owner == owner)
			n++;
	}
	dqt_unlock(c);
	return (n);
}

static bool
cond_unlocks(struct dqt_ctl *c __unused, uintptr_t o, uintptr_t n)
{

	return (((const struct dqt_object *)o)->nunlocks >= (int)n);
}

static bool
wait_unlocks(struct dqt_ctl *c, const struct dqt_object *o, int n)
{

	return (dqt_wait_cond(c, cond_unlocks, (uintptr_t)o, (uintptr_t)n,
	    DQT_WAIT_MS));
}

ATF_TC(posix_oracle);
ATF_TC_HEAD(posix_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "a POSIX write lock held by one "
	    "process: another's F_SETLK, F_GETLK, F_OFD_SETLK and flock answer "
	    "as on the real file; owner and dl_pid are the leader's pid; exit "
	    "posts UNLOCK_ALL once per owner and nothing for an object that "
	    "never locked; the range is free afterwards");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(posix_oracle, tc)
{
	struct fixture f;
	struct dqt_object *sib, *other;
	struct dq_ident_file *id;
	struct dqt_child ch;
	struct holder_arg h;
	struct holder_res hr;
	struct probe_arg pa;
	struct probe_res pr;
	int i;

	setup(&f, 1);
	/*
	 * Two more objects the requesters inherit and never lock through: a
	 * sibling (same di_dev, di_ino), which the POSIX lock on f.o marks,
	 * so the holder's exit closing its descriptor of it posts
	 * UNLOCK_ALL{POSIX, holder} there too (a real file releases a
	 * process's locks at the close of any of its descriptors); and an
	 * object of another identity, which sees nothing.
	 */
	sib = dqt_mint_backing(&f.c, f.backing, backing_path, NULL,
	    DQ_MINT_F_WRITE);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	*id = f.o->ident;
	id->di_ino++;
	other = dqt_mint_ident(&f.c, id, NULL, data, sizeof(data));
	free(id);
	memset(&h, 0, sizeof(h));
	h.sfd = f.o->fd;
	h.ofd = f.oracle;
	h.cmd = F_SETLK;
	h.type = F_WRLCK;
	h.start = 0;
	h.len = 100;
	holder_start(&h, &ch);

	memset(&pa, 0, sizeof(pa));
	pa.sfd = f.o->fd;
	pa.ofd = f.oracle;
	PROBE(&pa, F_SETLK, 0, F_RDLCK, 50, 10);	/* EAGAIN */
	PROBE(&pa, F_SETLK, 0, F_RDLCK, 100, 10);	/* free */
	PROBE(&pa, F_GETLK, 0, F_WRLCK, 0, 0);		/* the holder's */
	PROBE(&pa, F_GETLK, 0, F_RDLCK, 200, 10);	/* F_UNLCK */
	PROBE(&pa, F_OFD_SETLK, 0, F_WRLCK, 0, 10);	/* EAGAIN */
	PROBE(&pa, 0, LOCK_EX | LOCK_NB, 0, 0, 0);	/* EWOULDBLOCK */
	PROBE(&pa, F_SETLK, 0, F_UNLCK, 100, 10);	/* a waited UNLCK */
	memset(&pr, 0, sizeof(pr));
	dqt_run_child(child_probe, &pa, &pr, sizeof(pr));
	check_probe(&pa, &pr);
	ATF_CHECK_EQ(EAGAIN, pr.s[0].err);
	ATF_CHECK_EQ(F_WRLCK, pr.sfl[2].l_type);
	ATF_CHECK_EQ(-1, pr.sfl[2].l_pid);	/* declared: dq_serve_file */
	ATF_CHECK_EQ(F_UNLCK, pr.sfl[3].l_type);

	holder_release(&h, &ch, &hr);
	ATF_CHECK_EQ(0, hr.s.rv);
	ATF_CHECK_EQ(0, hr.o.rv);
	/* The holder's lock body: kind, owner, pid, range. */
	dqt_lock(&f.c);
	ATF_REQUIRE(f.o->nlocks >= 1);
	ATF_CHECK_EQ(DQ_LOCK_SETLK, f.o->locks[0].dl_op);
	ATF_CHECK_EQ(DQ_LOCK_POSIX, f.o->locks[0].dl_kind);
	ATF_CHECK_EQ(F_WRLCK, f.o->locks[0].dl_type);
	ATF_CHECK_EQ(0, f.o->locks[0].dl_start);
	ATF_CHECK_EQ(100, f.o->locks[0].dl_len);
	ATF_CHECK_EQ((uint64_t)hr.pid, f.o->locks[0].dl_owner);
	ATF_CHECK_EQ(hr.pid, f.o->locks[0].dl_pid);
	/* The probe's OFD and flock bodies carry the hashed owner, pid -1. */
	for (i = 0; i < f.o->nlocks; i++) {
		if (f.o->locks[i].dl_kind != DQ_LOCK_POSIX) {
			ATF_CHECK_EQ(-1, f.o->locks[i].dl_pid);
			ATF_CHECK(f.o->locks[i].dl_owner != (uint64_t)hr.pid);
		}
		if (f.o->locks[i].dl_type == F_UNLCK)
			ATF_CHECK_EQ(DQ_LOCK_UNLCK, f.o->locks[i].dl_op);
	}
	dqt_unlock(&f.c);
	/* Exit released the holder's POSIX locks: one UNLOCK_ALL. */
	ATF_REQUIRE(wait_unlocks(&f.c, f.o, 2));
	ATF_CHECK_EQ(1, count_unlocks(&f.c, f.o, DQ_LOCK_POSIX,
	    (uint64_t)hr.pid));
	ATF_REQUIRE(wait_unlocks(&f.c, sib, 1));
	ATF_CHECK_EQ(1, count_unlocks(&f.c, sib, DQ_LOCK_POSIX,
	    (uint64_t)hr.pid));
	ATF_CHECK_EQ(0, sib->nlocks);
	dqt_lock(&f.c);
	ATF_CHECK_EQ(0, other->nunlocks);
	ATF_CHECK_EQ(0, other->nlocks);
	dqt_unlock(&f.c);

	/* The range is free for a third process. */
	memset(&pa, 0, sizeof(pa));
	pa.sfd = f.o->fd;
	pa.ofd = f.oracle;
	PROBE(&pa, F_SETLK, 0, F_WRLCK, 0, 100);
	memset(&pr, 0, sizeof(pr));
	dqt_run_child(child_probe, &pa, &pr, sizeof(pr));
	check_probe(&pa, &pr);
	ATF_CHECK_EQ(0, pr.s[0].rv);
	teardown(&f);
}

struct wait_arg {
	int		 fd;
	int		 cmd;
};

static void
on_usr1(int sig __unused)
{
}

static void
child_setlkw(void *arg, void *result)
{
	struct wait_arg *a = arg;
	struct dqt_rr *r = result;
	struct sigaction sa;
	struct flock fl;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_usr1;
	(void)sigaction(SIGUSR1, &sa, NULL);
	setfl(&fl, F_WRLCK, 0, 10);
	r->rv = fcntl(a->fd, a->cmd, &fl);
	r->err = r->rv == -1 ? errno : 0;
}

ATF_TC(setlkw_no_deadline);
ATF_TC_HEAD(setlkw_no_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "F_SETLKW blocks past the object's "
	    "deadline (LOCK waits have none) until the holder releases, then "
	    "succeeds; ds2_locks counts LOCK events");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setlkw_no_deadline, tc)
{
	struct fixture f;
	struct dq_policy pol;
	struct dqt_child hch, wch;
	struct holder_arg h;
	struct holder_res hr;
	struct wait_arg w;
	struct dqt_rr r;
	struct dq_stats2 st;
	int status;

	dqt_policy_write(&pol);
	pol.dp_deadline_ms = 200;
	setup_pol(&f, 2, &pol);
	memset(&h, 0, sizeof(h));
	h.sfd = f.o->fd;
	h.ofd = f.oracle;
	h.cmd = F_SETLK;
	h.type = F_WRLCK;
	h.len = 100;
	holder_start(&h, &hch);
	w.fd = f.o->fd;
	w.cmd = F_SETLKW;
	dqt_spawn(&wch, child_setlkw, &w);
	ATF_REQUIRE(dqt_wait_locks(&f.c, f.o, 2, DQT_WAIT_MS));
	dqt_lock(&f.c);
	ATF_CHECK_EQ(DQ_LOCK_SETLKW, f.o->locks[1].dl_op);
	dqt_unlock(&f.c);
	dqt_msleep(800);	/* four deadlines */
	ATF_CHECK_EQ(0, waitpid(wch.pid, &status, WNOHANG));
	dqt_stats2(&f.c, &st);
	ATF_CHECK_EQ(0, st.ds2_deadline_misses);
	ATF_CHECK(st.ds2_locks >= 2);
	holder_release(&h, &hch, &hr);
	dqt_collect(&wch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.rv, "F_SETLKW: %s", strerror(r.err));
	teardown(&f);
}

ATF_TC(setlkw_interrupt);
ATF_TC_HEAD(setlkw_interrupt, tc)
{
	atf_tc_set_md_var(tc, "descr", "a signal ends a blocked F_SETLKW "
	    "with EINTR and posts INTERRUPT for its LOCK; dq_serve_file "
	    "cancels the proxied wait, so the lock is never granted to the "
	    "gone waiter; OFD F_OFD_SETLKW the same");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setlkw_interrupt, tc)
{
	struct fixture f;
	struct dqt_child hch, wch;
	struct holder_arg h;
	struct holder_res hr;
	struct wait_arg w;
	struct probe_arg pa;
	struct probe_res pr;
	struct dqt_rr r;
	int k;

	setup(&f, 3);
	memset(&h, 0, sizeof(h));
	h.sfd = f.o->fd;
	h.ofd = f.oracle;
	h.cmd = F_SETLK;
	h.type = F_WRLCK;
	h.len = 100;
	holder_start(&h, &hch);
	for (k = 0; k < 2; k++) {
		w.fd = f.o->fd;
		w.cmd = k == 0 ? F_SETLKW : F_OFD_SETLKW;
		dqt_spawn(&wch, child_setlkw, &w);
		ATF_REQUIRE(dqt_wait_locks(&f.c, f.o, 2 + k, DQT_WAIT_MS));
		/* The waiter sleeps for the LOCK's reply: signal it there. */
		ATF_REQUIRE(dqt_wait_wmesg(wch.pid, DQT_WMESG_REPLY,
		    DQT_WAIT_MS));
		ATF_REQUIRE_EQ(0, kill(wch.pid, SIGUSR1));
		dqt_collect(&wch, &r, sizeof(r));
		ATF_CHECK_EQ(-1, r.rv);
		ATF_CHECK_EQ(EINTR, r.err);
		ATF_CHECK(dqt_wait_interrupts(&f.c, k + 1, DQT_WAIT_MS));
	}
	holder_release(&h, &hch, &hr);
	/*
	 * Nobody holds the range: the waiters' proxies were cancelled.  The
	 * INTERRUPTs and the holder's UNLOCK_ALL were served before the
	 * fence's READ.
	 */
	dqt_fence(&f.c);
	memset(&pa, 0, sizeof(pa));
	pa.sfd = f.o->fd;
	pa.ofd = f.oracle;
	PROBE(&pa, F_SETLK, 0, F_WRLCK, 0, 10);
	memset(&pr, 0, sizeof(pr));
	dqt_run_child(child_probe, &pa, &pr, sizeof(pr));
	check_probe(&pa, &pr);
	ATF_CHECK_EQ(0, pr.s[0].rv);
	teardown(&f);
}

ATF_TC(flock_owners_and_release);
ATF_TC_HEAD(flock_owners_and_release, tc)
{
	atf_tc_set_md_var(tc, "descr", "flock owners are per open file: two "
	    "objects of one file conflict as two opens of the real file do; "
	    "the lock outlives the locking process while another reference to "
	    "the open file exists and is released (UNLOCK_ALL, kind FLOCK) at "
	    "the last close");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(flock_owners_and_release, tc)
{
	struct fixture f;
	struct dqt_object *o2;
	struct dqt_child ch;
	struct holder_arg h;
	struct holder_res hr;
	struct probe_arg pa;
	struct probe_res pr;
	uint64_t owner;
	int oracle2;

	setup(&f, 4);
	o2 = dqt_mint_backing(&f.c, f.backing, backing_path, NULL,
	    DQ_MINT_F_WRITE);
	oracle2 = open(oracle_path, O_RDWR);
	ATF_REQUIRE(oracle2 != -1);
	memset(&h, 0, sizeof(h));
	h.sfd = f.o->fd;
	h.ofd = f.oracle;
	h.cmd = 0;
	holder_start(&h, &ch);
	holder_release(&h, &ch, &hr);
	ATF_CHECK_EQ(0, hr.s.rv);
	ATF_CHECK_EQ(0, hr.o.rv);
	dqt_lock(&f.c);
	ATF_REQUIRE(f.o->nlocks >= 1);
	ATF_CHECK_EQ(DQ_LOCK_FLOCK, f.o->locks[0].dl_kind);
	ATF_CHECK_EQ(0, f.o->locks[0].dl_start);
	ATF_CHECK_EQ(0, f.o->locks[0].dl_len);
	ATF_CHECK_EQ(-1, f.o->locks[0].dl_pid);
	owner = f.o->locks[0].dl_owner;
	dqt_unlock(&f.c);
	/* This process still references both open files: still locked. */
	memset(&pa, 0, sizeof(pa));
	pa.sfd = o2->fd;
	pa.ofd = oracle2;
	PROBE(&pa, 0, LOCK_EX | LOCK_NB, 0, 0, 0);
	memset(&pr, 0, sizeof(pr));
	dqt_run_child(child_probe, &pa, &pr, sizeof(pr));
	check_probe(&pa, &pr);
	ATF_CHECK_EQ(EWOULDBLOCK, pr.s[0].err);
	dqt_lock(&f.c);
	ATF_REQUIRE(o2->nlocks >= 1);
	ATF_CHECK(o2->locks[0].dl_owner != owner);	/* another open */
	ATF_CHECK_EQ(0, count_unlocks(&f.c, f.o, DQ_LOCK_FLOCK, owner));
	dqt_unlock(&f.c);
	/* The last references go: the locks with them. */
	(void)close(f.o->fd);
	f.o->fd = -1;
	(void)close(f.oracle);
	f.oracle = open(oracle_path, O_RDWR);
	ATF_REQUIRE(wait_unlocks(&f.c, f.o, 1));
	ATF_CHECK_EQ(1, count_unlocks(&f.c, f.o, DQ_LOCK_FLOCK, owner));
	memset(&pr, 0, sizeof(pr));
	dqt_run_child(child_probe, &pa, &pr, sizeof(pr));
	check_probe(&pa, &pr);
	ATF_CHECK_EQ(0, pr.s[0].rv);
	(void)close(oracle2);
	teardown(&f);
}

/*
 * The reply ioctl releases the requester and then tells the MAC policies
 * about the requester's file.  debug.dq.delay_reply_notify makes it sleep
 * one second between the two, in which the requester here closes the last
 * descriptor of the open file it just locked and asks for the lock through
 * another open file.
 */
#define	DELAY_NOTIFY	"debug.dq.delay_reply_notify"
#define	LASTCLOSE_MIN_MS	100	/* of the second the reply sleeps */

struct lastclose_arg {
	int		 sfd, sfd2;
	int		 how;
	int		 go[2];
};

struct lastclose_res {
	struct dqt_rr	 lock, close, probe, unlock;
	long		 close_ms;	/* how long close(2) took */
};

static void
child_lastclose(void *arg, void *result)
{
	struct lastclose_arg *a = arg;
	struct lastclose_res *r = result;
	struct timespec t0, t1;
	char b;

	/* Wait until this process has the only descriptor of sfd's file. */
	(void)close(a->go[1]);
	if (read(a->go[0], &b, 1) != 1)
		_exit(3);
	r->lock.rv = flock(a->sfd, a->how);
	r->lock.err = r->lock.rv == -1 ? errno : 0;
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	r->close.rv = close(a->sfd);
	r->close.err = r->close.rv == -1 ? errno : 0;
	(void)clock_gettime(CLOCK_MONOTONIC, &t1);
	timespecsub(&t1, &t0, &t1);
	r->close_ms = t1.tv_sec * 1000 + t1.tv_nsec / 1000000;
	r->probe.rv = flock(a->sfd2, LOCK_EX | LOCK_NB);
	r->probe.err = r->probe.rv == -1 ? errno : 0;
	r->unlock.rv = flock(a->sfd2, LOCK_UN);
	r->unlock.err = r->unlock.rv == -1 ? errno : 0;
}

static void
lastclose_round(int how)
{
	struct fixture f;
	struct dqt_object *o2;
	struct dqt_child ch;
	struct lastclose_arg a;
	struct lastclose_res r;
	uint64_t owner;
	u_int left;
	int status;
	char b;

	setup(&f, 9);
	o2 = dqt_mint_backing(&f.c, f.backing, backing_path, NULL,
	    DQ_MINT_F_WRITE);
	memset(&a, 0, sizeof(a));
	a.sfd = f.o->fd;
	a.sfd2 = o2->fd;
	a.how = how;
	ATF_REQUIRE_EQ(0, pipe(a.go));
	dqt_spawn(&ch, child_lastclose, &a);
	(void)close(a.go[0]);
	(void)close(f.o->fd);
	f.o->fd = -1;
	/* The next reply about an open file is the lock's. */
	dqt_knob_arm(DELAY_NOTIFY, 1);
	b = 'g';
	ATF_REQUIRE_EQ(1, write(a.go[1], &b, 1));
	(void)close(a.go[1]);
	memset(&r, 0, sizeof(r));
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE(dqt_sysctl_get_uint(DELAY_NOTIFY, &left));
	dqt_knob_disarm(DELAY_NOTIFY);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "how %#x: the requester: status %#x", how, status);
	ATF_CHECK_EQ_MSG(0, left, "how %#x: no reply was delayed", how);
	ATF_CHECK_EQ_MSG(0, r.lock.rv, "how %#x: flock: errno %d", how,
	    r.lock.err);
	ATF_CHECK_EQ_MSG(0, r.close.rv, "how %#x: close: errno %d", how,
	    r.close.err);
	ATF_CHECK_EQ_MSG(0, r.probe.rv, "how %#x: the lock outlived the last "
	    "close of its open file: flock through another open file: %s",
	    how, strerror(r.probe.err));
	ATF_CHECK_EQ_MSG(0, r.unlock.rv, "how %#x: unlock: errno %d", how,
	    r.unlock.err);
	/*
	 * The close was made inside the delayed reply only if it waited
	 * for it: a close that returned at once and a probe that got the
	 * lock would show nothing (the reply was done before the close).
	 */
	printf("how %#x: close(2) took %ld ms\n", how, r.close_ms);
	if (r.probe.rv == 0)
		ATF_CHECK_MSG(r.close_ms >= LASTCLOSE_MIN_MS, "how %#x: the "
		    "close took %ld ms: it did not meet the delayed reply, "
		    "so the round shows nothing", how, r.close_ms);
	pthread_mutex_lock(&f.c.mtx);
	ATF_REQUIRE(f.o->nlocks >= 1);
	owner = f.o->locks[0].dl_owner;
	pthread_mutex_unlock(&f.c.mtx);
	ATF_CHECK_EQ(1, count_unlocks(&f.c, f.o, DQ_LOCK_FLOCK, owner));
	teardown(&f);
}

ATF_TC_WITH_CLEANUP(flock_gone_when_last_close_returns);
ATF_TC_HEAD(flock_gone_when_last_close_returns, tc)
{
	atf_tc_set_md_var(tc, "descr", "a flock is released by the last "
	    "close of its open file before that close returns, as on a real "
	    "file: the next request through another open file gets the lock "
	    "even when the reply that granted the first is still telling the "
	    "MAC policies about the closed file (the first request "
	    "non-blocking, then blocking)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(flock_gone_when_last_close_returns, tc)
{

	lastclose_round(LOCK_EX | LOCK_NB);
	lastclose_round(LOCK_EX);
}
ATF_TC_CLEANUP(flock_gone_when_last_close_returns, tc)
{

	dqt_knob_disarm(DELAY_NOTIFY);
}

struct norm_res {
	struct dqt_rr	 r[6];
};

static void
child_norm(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct norm_res *r = result;
	struct flock fl;
	int i;

	i = 0;
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_END;
	fl.l_start = -10;
	fl.l_len = 5;
	r->r[i].rv = fcntl(fd, F_SETLK, &fl);
	r->r[i].err = errno;
	i++;
	fl.l_whence = SEEK_SET;
	fl.l_start = 100;
	fl.l_len = -20;			/* [80, 100) */
	r->r[i].rv = fcntl(fd, F_SETLK, &fl);
	r->r[i].err = errno;
	i++;
	fl.l_start = 0;
	fl.l_len = -1;			/* EINVAL locally */
	r->r[i].rv = fcntl(fd, F_SETLK, &fl);
	r->r[i].err = errno;
	i++;
	fl.l_whence = SEEK_END;
	fl.l_start = OFF_MAX;		/* EOVERFLOW locally */
	fl.l_len = 1;
	r->r[i].rv = fcntl(fd, F_SETLK, &fl);
	r->r[i].err = errno;
	i++;
	fl.l_whence = SEEK_SET;
	fl.l_start = 10;
	fl.l_len = 0;			/* to the end */
	r->r[i].rv = fcntl(fd, F_SETLK, &fl);
	r->r[i].err = errno;
}

ATF_TC(normalisation_and_errnos);
ATF_TC_HEAD(normalisation_and_errnos, tc)
{
	atf_tc_set_md_var(tc, "descr", "the LOCK range is lockf's: SEEK_END "
	    "from di_size, a negative length folded, 0 to the end; a negative "
	    "start EINVAL and a SEEK_END overflow EOVERFLOW before any event; "
	    "the controller's EDEADLK reaches the requester, an errno outside "
	    "LOCK's allow-list (EPERM) is EIO; the controller's own process "
	    "is refused with EDEADLK (D16)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(normalisation_and_errnos, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct norm_res r;
	struct statfs sfs;
	struct stat sb;
	struct flock fl;
	int oracle;

	dqt_fill(data, sizeof(data), 5);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(oracle, oracle_path, id, &sb, &sfs);
	dqt_policy_write(&pol);
	o = dqt_mint_ident_flags(&c, id, &pol, 0, data, sizeof(data));
	free(id);
	o->serve_errno = EDEADLK;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_norm, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(EDEADLK, r.r[0].err);
	ATF_CHECK_EQ(EINVAL, r.r[2].err);
	ATF_CHECK_EQ(EOVERFLOW, r.r[3].err);
	dqt_lock(&c);
	ATF_REQUIRE_EQ(3, o->nlocks);
	ATF_CHECK_EQ(DATA_LEN - 10, o->locks[0].dl_start);
	ATF_CHECK_EQ(5, o->locks[0].dl_len);
	ATF_CHECK_EQ(80, o->locks[1].dl_start);
	ATF_CHECK_EQ(20, o->locks[1].dl_len);
	ATF_CHECK_EQ(10, o->locks[2].dl_start);
	ATF_CHECK_EQ(0, o->locks[2].dl_len);
	dqt_unlock(&c);
	o->serve_errno = EPERM;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_norm, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	/* In the controller process: refused before posting. */
	setfl(&fl, F_RDLCK, 0, 10);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(o->fd, F_SETLK, &fl));
	ATF_CHECK_EQ(EDEADLK, errno);
	dqt_lock(&c);
	ATF_CHECK_EQ(6, o->nlocks);
	dqt_unlock(&c);
	dqt_fini(&c);
	(void)close(oracle);
}

/*
 * A POSIX owner that locks through object A (and maybe B, a sibling of
 * the same identity), and on the oracle through two opens of the real
 * file.  Step 1: lock; report.  Step 2: close the second descriptor of
 * each; report.  Step 3: exit.
 */
struct sib_arg {
	int		 a, b, oa, ob;
	bool		 lock_b;
	int		 ready[2], go[2];
};

struct sib_res {
	struct dqt_rr	 sa, sb, oa, ob;
	pid_t		 pid;
};

static void
child_sibling_owner(void *arg, void *result)
{
	struct sib_arg *s = arg;
	struct sib_res *r = result;
	struct flock fl;
	char b;

	(void)close(s->ready[0]);
	(void)close(s->go[1]);
	r->pid = getpid();
	setfl(&fl, F_WRLCK, 0, 10);
	r->sa.rv = fcntl(s->a, F_SETLK, &fl);
	r->sa.err = r->sa.rv == -1 ? errno : 0;
	setfl(&fl, F_WRLCK, 0, 10);
	r->oa.rv = fcntl(s->oa, F_SETLK, &fl);
	r->oa.err = r->oa.rv == -1 ? errno : 0;
	if (s->lock_b) {
		/* The same owner through a second open: no conflict. */
		setfl(&fl, F_WRLCK, 0, 10);
		r->sb.rv = fcntl(s->b, F_SETLK, &fl);
		r->sb.err = r->sb.rv == -1 ? errno : 0;
		setfl(&fl, F_WRLCK, 0, 10);
		r->ob.rv = fcntl(s->ob, F_SETLK, &fl);
		r->ob.err = r->ob.rv == -1 ? errno : 0;
	}
	b = '1';
	(void)write(s->ready[1], &b, 1);
	(void)read(s->go[0], &b, 1);
	/* Closing any descriptor of the file releases the owner's locks. */
	(void)close(s->b);
	(void)close(s->ob);
	b = '2';
	(void)write(s->ready[1], &b, 1);
	(void)read(s->go[0], &b, 1);
}

static void
sib_step(struct sib_arg *s)
{
	char b;

	b = 'g';
	ATF_REQUIRE_EQ(1, write(s->go[1], &b, 1));
	ATF_REQUIRE_EQ(1, read(s->ready[0], &b, 1));
}

static void
sib_probe(int sfd, int ofd, struct probe_res *pr)
{
	struct probe_arg pa;

	memset(&pa, 0, sizeof(pa));
	pa.sfd = sfd;
	pa.ofd = ofd;
	PROBE(&pa, F_SETLK, 0, F_WRLCK, 0, 10);
	PROBE(&pa, F_SETLK, 0, F_UNLCK, 0, 10);
	memset(pr, 0, sizeof(*pr));
	dqt_run_child(child_probe, &pa, pr, sizeof(*pr));
	check_probe(&pa, pr);
}

ATF_TC(posix_spans_siblings);
ATF_TC_HEAD(posix_spans_siblings, tc)
{
	atf_tc_set_md_var(tc, "descr", "a POSIX owner is a process per file: "
	    "two objects of one identity are two opens of it, the owner never "
	    "conflicts with itself through them, and closing either "
	    "descriptor releases its locks (UNLOCK_ALL on that object, even "
	    "one the owner never locked through), as on the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(posix_spans_siblings, tc)
{
	struct fixture f;
	struct dqt_object *b;
	struct dqt_child ch;
	struct sib_arg s;
	struct sib_res r;
	struct probe_res pr;
	int k, ob;

	for (k = 0; k < 2; k++) {
		setup(&f, 10 + k);
		b = dqt_mint_backing(&f.c, f.backing, backing_path, NULL,
		    DQ_MINT_F_WRITE);
		ob = open(oracle_path, O_RDWR);
		ATF_REQUIRE(ob != -1);
		memset(&s, 0, sizeof(s));
		s.a = f.o->fd;
		s.b = b->fd;
		s.oa = f.oracle;
		s.ob = ob;
		s.lock_b = k == 0;
		ATF_REQUIRE_EQ(0, pipe(s.ready));
		ATF_REQUIRE_EQ(0, pipe(s.go));
		dqt_spawn(&ch, child_sibling_owner, &s);
		(void)close(s.ready[1]);
		(void)close(s.go[0]);
		{
			char c1;

			ATF_REQUIRE_EQ(1, read(s.ready[0], &c1, 1));
		}
		/* Held: another process conflicts on both files. */
		sib_probe(f.o->fd, f.oracle, &pr);
		ATF_CHECK_EQ(EAGAIN, pr.s[0].err);
		/* The owner closes its second descriptor of each file. */
		sib_step(&s);
		ATF_REQUIRE(wait_unlocks(&f.c, b, 1));
		/* The UNLOCK_ALL was served before the fence's READ. */
		dqt_fence(&f.c);
		sib_probe(f.o->fd, f.oracle, &pr);
		ATF_CHECK_EQ_MSG(0, pr.s[0].rv, "after the close (lock_b %d): %s",
		    k == 0, strerror(pr.s[0].err));
		{
			char c1 = 'g';

			(void)write(s.go[1], &c1, 1);
		}
		(void)close(s.go[1]);
		(void)close(s.ready[0]);
		dqt_collect(&ch, &r, sizeof(r));
		ATF_CHECK_EQ(0, r.sa.rv);
		ATF_CHECK_EQ(0, r.oa.rv);
		if (k == 0) {
			ATF_CHECK_EQ_MSG(0, r.sb.rv, "second open: %s",
			    strerror(r.sb.err));
			ATF_CHECK_EQ(r.ob.rv, r.sb.rv);
		}
		ATF_CHECK_EQ(1, count_unlocks(&f.c, b, DQ_LOCK_POSIX,
		    (uint64_t)r.pid));
		(void)close(ob);
		teardown(&f);
	}
}

static int
count_fds(void)
{
	int fd, n;

	for (fd = n = 0; fd < 4096; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	}
	return (n);
}

static void
child_getlk(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct dqt_rr *r = result;
	struct flock fl;

	setfl(&fl, F_WRLCK, 0, 10);
	r->rv = fcntl(fd, F_GETLK, &fl);
	r->err = r->rv == -1 ? errno : (int)fl.l_type;
}

ATF_TC(getlk_creates_no_owner);
ATF_TC_HEAD(getlk_creates_no_owner, tc)
{
	atf_tc_set_md_var(tc, "descr", "F_GETLK by 100 distinct processes "
	    "leaves dq_serve_file with no owner and the controller's "
	    "descriptor count unchanged (a query opens and closes a temporary "
	    "open)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(getlk_creates_no_owner, tc)
{
	struct fixture f;
	struct dqt_rr r;
	int before, i, after;

	setup(&f, 12);
	before = count_fds();
	for (i = 0; i < 100; i++) {
		memset(&r, 0, sizeof(r));
		dqt_run_child(child_getlk, &f.o->fd, &r, sizeof(r));
		ATF_REQUIRE_EQ_MSG(0, r.rv, "F_GETLK %d: %s", i, strerror(r.err));
		ATF_CHECK_EQ(F_UNLCK, r.err);
	}
	after = count_fds();
	ATF_CHECK_EQ_MSG(before, after, "descriptors %d before, %d after",
	    before, after);
	ATF_CHECK_EQ(0, dq_serve_state_owners(f.c.lockstate));
	/* events[] counts every LOCK; locks[] keeps the first DQT_MAX_LOCKS. */
	dqt_lock(&f.c);
	ATF_CHECK_EQ(100, f.c.events[DQ_OP_LOCK]);
	ATF_CHECK_EQ(MIN(100, DQT_MAX_LOCKS), f.o->nlocks);
	ATF_CHECK_EQ(DQ_LOCK_GETLK, f.o->locks[0].dl_op);
	dqt_unlock(&f.c);
	teardown(&f);
}


static bool
pred_current(const struct dq_stats *st, uintptr_t n)
{

	return (st->ds_queue_current >= n);
}

static void
child_read_one(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct dqt_rr *r = result;
	char buf[16];

	r->rv = pread(fd, buf, sizeof(buf), 0);
	r->err = r->rv == -1 ? errno : 0;
}

ATF_TC(unlock_all_over_depth);
ATF_TC_HEAD(unlock_all_over_depth, tc)
{
	atf_tc_set_md_var(tc, "descr", "K-B3: UNLOCK_ALL is never dropped: "
	    "with the depth at 1 and one event pending, a close still posts "
	    "it, beyond the depth, counted in ds2_overdepth and not in "
	    "ds_events_dropped");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unlock_all_over_depth, tc)
{
	struct dqt_ctl c;
	struct dqt_object *o;
	struct dqt_child lch, rch;
	struct holder_arg h;
	struct holder_res hr;
	struct dqt_rr r;
	struct dq_stats st;
	struct dq_stats2 st2;
	int oracle;

	dqt_fill(data, sizeof(data), 13);
	oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&c);
	o = dqt_mint(&c, oracle, oracle_path, data, sizeof(data), NULL);
	o->serve_errno = EAGAIN;	/* the lock is refused; o_locked is set */
	memset(&h, 0, sizeof(h));
	h.sfd = o->fd;
	h.ofd = oracle;
	h.cmd = F_SETLK;
	h.type = F_RDLCK;
	h.len = 1;
	holder_start(&h, &lch);
	ATF_REQUIRE(dqt_wait_locks(&c, o, 1, DQT_WAIT_MS));

	dqt_pause(&c);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));
	dqt_spawn(&rch, child_read_one, &o->fd);
	ATF_REQUIRE(dqt_wait_stats(&c, pred_current, 1, DQT_WAIT_MS));
	/* The locker exits: its UNLOCK_ALL goes past the full queue. */
	holder_release(&h, &lch, &hr);
	ATF_CHECK(dqt_wait_stats(&c, pred_current, 2, DQT_WAIT_MS));
	dqt_stats(&c, &st);
	ATF_CHECK_EQ(0, st.ds_events_dropped);
	dqt_stats2(&c, &st2);
	ATF_CHECK_EQ(1, st2.ds2_overdepth);

	dqt_resume(&c);
	dqt_collect(&rch, &r, sizeof(r));
	ATF_CHECK_EQ(16, r.rv);
	ATF_CHECK(dqt_wait_events(&c, DQ_OP_UNLOCK_ALL, 1, DQT_WAIT_MS));
	ATF_CHECK_EQ(1, count_unlocks(&c, o, DQ_LOCK_POSIX,
	    (uint64_t)hr.pid));
	dqt_fini(&c);
	(void)close(oracle);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, posix_oracle);
	ATF_TP_ADD_TC(tp, setlkw_no_deadline);
	ATF_TP_ADD_TC(tp, setlkw_interrupt);
	ATF_TP_ADD_TC(tp, flock_owners_and_release);
	ATF_TP_ADD_TC(tp, flock_gone_when_last_close_returns);
	ATF_TP_ADD_TC(tp, normalisation_and_errnos);
	ATF_TP_ADD_TC(tp, posix_spans_siblings);
	ATF_TP_ADD_TC(tp, getlk_creates_no_owner);
	ATF_TP_ADD_TC(tp, unlock_all_over_depth);
	return (atf_no_error());
}
