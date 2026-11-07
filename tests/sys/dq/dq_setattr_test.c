/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Attributes (D96, N4): fchmod, fchown, futimens, fchflags and ftruncate on
 * a served file post SETATTR after the DAC and privilege checks a vnode
 * applies, and dq_serve_file() applies the masked fields to a backing file.
 * The oracle is a second real file with the same owner and mode: every
 * call runs on both in the requester and the answers and the resulting
 * attributes are compared field by field.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/stat.h>
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
#define	MAX_OPS		12
#define	NOBODY		65534

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
open_rw(const char *name, char *path, uid_t uid, gid_t gid, mode_t mode)
{
	int fd;

	fd = dqt_make_oracle(name, data, sizeof(data), path, DQT_PATH_MAX);
	(void)close(fd);
	ATF_REQUIRE_EQ(0, chown(path, uid, gid));
	ATF_REQUIRE_EQ(0, chmod(path, mode));
	fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "open %s: %s", path, strerror(errno));
	return (fd);
}

/* Both files owned by uid:gid with mode; the object presents the backing. */
static void
setup_as(struct fixture *f, unsigned seed, uid_t uid, gid_t gid, mode_t mode,
    uint32_t mflags)
{

	dqt_fill(data, sizeof(data), seed);
	f->backing = open_rw("backing", backing_path, uid, gid, mode);
	f->oracle = open_rw("oracle", oracle_path, uid, gid, mode);
	dqt_init(&f->c);
	f->o = dqt_mint_backing(&f->c, f->backing, backing_path, NULL, mflags);
}

static void
teardown(struct fixture *f)
{

	ATF_CHECK_EQ_MSG(0, f->c.reply_failures, "reply failures: last %d",
	    f->c.last_reply_errno);
	dqt_fini(&f->c);
	(void)close(f->backing);
	(void)close(f->oracle);
}

struct pair {
	struct dqt_rr	 s, o;
};

struct ops_res {
	struct pair	 p[MAX_OPS];
	int		 n;
	struct stat	 sst, ost;
	u_int		 notes;		/* EVFILT_VNODE fflags on the served fd */
	int		 failed;	/* the child could not drop privilege */
};

struct ops_arg {
	int		 sfd, ofd;
	uid_t		 uid;		/* 0: stay root */
};

#define	BOTH(r, call) do {						\
	int _fd;							\
	struct pair *_p = &(r)->p[(r)->n++];				\
	_fd = a->sfd;							\
	_p->s.rv = (long)(call);					\
	_p->s.err = _p->s.rv == -1 ? errno : 0;				\
	_fd = a->ofd;							\
	_p->o.rv = (long)(call);					\
	_p->o.err = _p->o.rv == -1 ? errno : 0;				\
} while (0)

static bool
child_become(const struct ops_arg *a, struct ops_res *r)
{

	if (a->uid == 0)
		return (true);
	if (setgroups(0, NULL) != 0 || setgid(NOBODY) != 0 ||
	    setuid(a->uid) != 0) {
		r->failed = errno;
		return (false);
	}
	return (true);
}

static void
check_pair(const struct ops_res *r, int i, const char *what)
{

	ATF_CHECK_EQ_MSG(r->p[i].o.rv, r->p[i].s.rv, "%s: served %ld oracle %ld",
	    what, r->p[i].s.rv, r->p[i].o.rv);
	ATF_CHECK_EQ_MSG(r->p[i].o.err, r->p[i].s.err,
	    "%s: served errno %d oracle %d", what, r->p[i].s.err,
	    r->p[i].o.err);
}

/* The fields a SETATTR can change, served against oracle. */
static void
check_attrs(const struct stat *s, const struct stat *o, bool times)
{

	ATF_CHECK_EQ_MSG(o->st_mode, s->st_mode, "mode %o oracle %o",
	    s->st_mode, o->st_mode);
	ATF_CHECK_EQ(o->st_uid, s->st_uid);
	ATF_CHECK_EQ(o->st_gid, s->st_gid);
	ATF_CHECK_EQ(o->st_size, s->st_size);
	ATF_CHECK_EQ_MSG(o->st_flags, s->st_flags, "flags %#x oracle %#x",
	    s->st_flags, o->st_flags);
	if (times) {
		ATF_CHECK_EQ(o->st_mtim.tv_sec, s->st_mtim.tv_sec);
		ATF_CHECK_EQ(o->st_mtim.tv_nsec, s->st_mtim.tv_nsec);
		ATF_CHECK_EQ(o->st_atim.tv_sec, s->st_atim.tv_sec);
		ATF_CHECK_EQ(o->st_atim.tv_nsec, s->st_atim.tv_nsec);
	}
}

static void
child_root_ops(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	struct kevent kev;
	struct timespec ts[2], zero = { 0, 0 };
	int kq;

	kq = kqueue();
	EV_SET(&kev, a->sfd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_ATTRIB, 0,
	    NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	/* The sizes first: a truncate moves the backing file's mtime. */
	BOTH(r, ftruncate(_fd, 100));
	BOTH(r, ftruncate(_fd, DATA_LEN * 2));
	BOTH(r, fchmod(_fd, 0640));
	BOTH(r, fchown(_fd, NOBODY, NOBODY));
	BOTH(r, fchown(_fd, -1, 0));
	BOTH(r, fchown(_fd, -1, -1));
	ts[0].tv_sec = 1000;
	ts[0].tv_nsec = 5;
	ts[1].tv_sec = 2000000;
	ts[1].tv_nsec = 7;
	BOTH(r, futimens(_fd, ts));
	/* UTIME_OMIT keeps a time; the mtime set explicitly. */
	ts[0].tv_nsec = UTIME_OMIT;
	ts[1].tv_sec = 3000000;
	ts[1].tv_nsec = 9;
	BOTH(r, futimens(_fd, ts));
	BOTH(r, fchflags(_fd, UF_NODUMP));
	BOTH(r, fchflags(_fd, 0));
	(void)fstat(a->sfd, &r->sst);
	(void)fstat(a->ofd, &r->ost);
	if (kevent(kq, NULL, 0, &kev, 1, &zero) == 1)
		r->notes = kev.fflags;
	(void)close(kq);
}

ATF_TC(root_oracle);
ATF_TC_HEAD(root_oracle, tc)
{
	atf_tc_set_md_var(tc, "descr", "as root: fchmod, fchown (both, one, "
	    "neither), futimens (explicit, UTIME_OMIT), ftruncate (shrink, "
	    "grow), fchflags answer and leave the attributes the real file "
	    "has; NOTE_ATTRIB fires; ctime is set; the empty fchown posts "
	    "nothing");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(root_oracle, tc)
{
	struct fixture f;
	struct ops_arg a;
	struct ops_res r;
	struct timespec before;
	static const char *const names[] = { "ftruncate shrink",
	    "ftruncate grow", "fchmod", "fchown both",
	    "fchown gid", "fchown none", "futimens", "futimens omit",
	    "fchflags set",
	    "fchflags clear" };
	int i;

	setup_as(&f, 1, 0, 0, 0644, DQ_MINT_F_WRITE);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &before));
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	a.uid = 0;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_root_ops, &a, &r, sizeof(r));
	for (i = 0; i < r.n; i++)
		check_pair(&r, i, names[i]);
	check_attrs(&r.sst, &r.ost, true);
	ATF_CHECK(r.sst.st_ctim.tv_sec >= before.tv_sec);
	ATF_CHECK((r.notes & NOTE_ATTRIB) != 0);
	/* Every call but the empty fchown posted one SETATTR. */
	ATF_CHECK_EQ(9, f.c.events[DQ_OP_SETATTR]);
	/* The backing file holds the same as the oracle. */
	{
		struct stat bs;

		ATF_REQUIRE_EQ(0, fstat(f.backing, &bs));
		check_attrs(&bs, &r.ost, true);
	}
	teardown(&f);
}

static void
child_unpriv(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;

	if (!child_become(a, r))
		return;
	/* The owner without privilege. */
	BOTH(r, fchmod(_fd, 01644));		/* sticky: EFTYPE */
	BOTH(r, fchflags(_fd, SF_ARCHIVED));	/* system flag: EPERM */
	BOTH(r, fchown(_fd, 0, -1));		/* give away: EPERM */
	BOTH(r, fchown(_fd, -1, 0));		/* foreign group: EPERM */
	BOTH(r, fchmod(_fd, 0600));		/* allowed */
	BOTH(r, futimens(_fd, NULL));		/* allowed */
	(void)fstat(a->sfd, &r->sst);
	(void)fstat(a->ofd, &r->ost);
	/* Served only: the kernel's own refusals. */
	r->p[r->n].s.rv = fchmod(a->sfd, 04600);
	r->p[r->n].s.err = errno;
	r->n++;
	r->p[r->n].s.rv = fchflags(a->sfd, 0x00400000 | 0x40000000);
	r->p[r->n].s.err = errno;
	r->n++;
}

ATF_TC(owner_unprivileged);
ATF_TC_HEAD(owner_unprivileged, tc)
{
	atf_tc_set_md_var(tc, "descr", "the owner without privilege: sticky "
	    "EFTYPE, a system flag EPERM, giving the file or its group away "
	    "EPERM, chmod and utimes(NULL) served; set-id bits EPERM (I3) and "
	    "unknown flags EOPNOTSUPP, refused by the kernel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(owner_unprivileged, tc)
{
	struct fixture f;
	struct ops_arg a;
	struct ops_res r;
	int i;

	setup_as(&f, 2, NOBODY, NOBODY, 0644, DQ_MINT_F_WRITE);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	a.uid = NOBODY;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_unpriv, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ_MSG(0, r.failed, "setuid: %s", strerror(r.failed));
	for (i = 0; i < 6; i++)
		check_pair(&r, i, "unprivileged owner");
	ATF_CHECK_EQ(EFTYPE, r.p[0].s.err);
	ATF_CHECK_EQ(EPERM, r.p[1].s.err);
	ATF_CHECK_EQ(EPERM, r.p[2].s.err);
	ATF_CHECK_EQ(EPERM, r.p[3].s.err);
	check_attrs(&r.sst, &r.ost, false);
	ATF_CHECK_EQ(-1, r.p[6].s.rv);
	ATF_CHECK_EQ(EPERM, r.p[6].s.err);
	ATF_CHECK_EQ(-1, r.p[7].s.rv);
	ATF_CHECK_EQ(EOPNOTSUPP, r.p[7].s.err);
	/* Only the two allowed calls reached the controller. */
	ATF_CHECK_EQ(2, f.c.events[DQ_OP_SETATTR]);
	ATF_CHECK((f.o->last_setattr.dsa_mask & DQ_SETATTR_F_UTIMES_NULL) != 0);
	teardown(&f);
}

static void
child_nonowner(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	struct timespec ts[2];

	if (!child_become(a, r))
		return;
	ts[0].tv_sec = ts[1].tv_sec = 5;
	ts[0].tv_nsec = ts[1].tv_nsec = 0;
	BOTH(r, fchmod(_fd, 0600));		/* EPERM */
	BOTH(r, fchflags(_fd, UF_NODUMP));	/* EPERM */
	BOTH(r, futimens(_fd, ts));		/* EPERM: not the owner */
	BOTH(r, futimens(_fd, NULL));		/* write permission suffices */
}

ATF_TC(nonowner);
ATF_TC_HEAD(nonowner, tc)
{
	atf_tc_set_md_var(tc, "descr", "a non-owner with write permission: "
	    "chmod, chflags and explicit times EPERM before any event; "
	    "utimes(NULL) is served (VWRITE suffices)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonowner, tc)
{
	struct fixture f;
	struct ops_arg a;
	struct ops_res r;
	int i;

	setup_as(&f, 3, 0, 0, 0666, DQ_MINT_F_WRITE);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	a.uid = NOBODY;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_nonowner, &a, &r, sizeof(r));
	ATF_REQUIRE_EQ_MSG(0, r.failed, "setuid: %s", strerror(r.failed));
	for (i = 0; i < r.n; i++)
		check_pair(&r, i, "non-owner");
	ATF_CHECK_EQ(EPERM, r.p[0].s.err);
	ATF_CHECK_EQ(0, r.p[3].s.rv);
	ATF_CHECK_EQ(1, f.c.events[DQ_OP_SETATTR]);
	teardown(&f);
}

static void
child_birthtime(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;
	struct timespec ts[2];

	ts[0].tv_sec = 100;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec = 100;	/* long before the file was born */
	ts[1].tv_nsec = 0;
	BOTH(r, futimens(_fd, ts));
	(void)fstat(a->sfd, &r->sst);
	(void)fstat(a->ofd, &r->ost);
}

ATF_TC(birthtime_pullback);
ATF_TC_HEAD(birthtime_pullback, tc)
{
	atf_tc_set_md_var(tc, "descr", "a modification time earlier than the "
	    "birth time pulls the birth time back with it (vn_setattr), "
	    "visible in the body as DQ_SETATTR_BIRTHTIME");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(birthtime_pullback, tc)
{
	struct fixture f;
	struct ops_arg a;
	struct ops_res r;

	setup_as(&f, 4, 0, 0, 0644, DQ_MINT_F_WRITE);
	a.sfd = f.o->fd;
	a.ofd = f.oracle;
	a.uid = 0;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_birthtime, &a, &r, sizeof(r));
	check_pair(&r, 0, "futimens");
	ATF_CHECK_EQ(100, r.sst.st_birthtim.tv_sec);
	if (r.ost.st_birthtim.tv_sec != -1)	/* a filesystem with one */
		ATF_CHECK_EQ(r.ost.st_birthtim.tv_sec, r.sst.st_birthtim.tv_sec);
	ATF_CHECK((f.o->last_setattr.dsa_mask & DQ_SETATTR_BIRTHTIME) != 0);
	ATF_CHECK_EQ(100, f.o->last_setattr.dsa_birthtime.tv_sec);
	teardown(&f);
}

static void
child_readonly(void *arg, void *result)
{
	struct ops_arg *a = arg;
	struct ops_res *r = result;

	BOTH(r, fchmod(_fd, 0600));
	BOTH(r, ftruncate(_fd, 10));
}

ATF_TC(readonly_object);
ATF_TC_HEAD(readonly_object, tc)
{
	atf_tc_set_md_var(tc, "descr", "ownership governs: a read-only object "
	    "(dp_write = DENY) posts SETATTR for fchmod as a read-only "
	    "descriptor on a real file is allowed it; ftruncate is the "
	    "generic layer's EINVAL without an event");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(readonly_object, tc)
{
	struct fixture f;
	struct dq_policy pol;
	struct ops_arg a;
	struct ops_res r;
	int ro;

	dqt_fill(data, sizeof(data), 5);
	f.backing = open_rw("backing", backing_path, 0, 0, 0644);
	f.oracle = open_rw("oracle", oracle_path, 0, 0, 0644);
	ro = open(oracle_path, O_RDONLY);
	ATF_REQUIRE(ro != -1);
	dqt_init(&f.c);
	dq_policy_default(&pol);
	f.o = dqt_mint_backing(&f.c, f.backing, backing_path, &pol, 0);
	a.sfd = f.o->fd;
	a.ofd = ro;
	a.uid = 0;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_readonly, &a, &r, sizeof(r));
	check_pair(&r, 0, "fchmod");
	check_pair(&r, 1, "ftruncate");
	ATF_CHECK_EQ(0, r.p[0].s.rv);
	ATF_CHECK_EQ(EINVAL, r.p[1].s.err);
	ATF_CHECK_EQ(1, f.c.events[DQ_OP_SETATTR]);
	(void)close(ro);
	teardown(&f);
}

ATF_TC_WITH_CLEANUP(fdesc_setattr);
ATF_TC_HEAD(fdesc_setattr, tc)
{
	atf_tc_set_md_var(tc, "descr", "chmod, chown and utimes through "
	    "fdescfs's /dev/fd/N reach the object's fo_setattr and are served "
	    "as on the real file");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdesc_setattr, tc)
{
	struct fixture f;
	struct stat ss, os;
	struct timeval tv[2];
	char sp[64], op[64];
	int status;
	pid_t pid;

	setup_as(&f, 6, 0, 0, 0644, DQ_MINT_F_WRITE);
	dqt_mount_fdesc(NULL);
	(void)snprintf(sp, sizeof(sp), DQT_FDESC_DIR "/%d", f.o->fd);
	(void)snprintf(op, sizeof(op), DQT_FDESC_DIR "/%d", f.oracle);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		tv[0].tv_sec = tv[1].tv_sec = 4000000;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (chmod(sp, 0600) != 0 || chmod(op, 0600) != 0 ||
		    chown(sp, NOBODY, -1) != 0 || chown(op, NOBODY, -1) != 0 ||
		    utimes(sp, tv) != 0 || utimes(op, tv) != 0)
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "status %#x", status);
	ATF_REQUIRE_EQ(0, fstat(f.o->fd, &ss));
	ATF_REQUIRE_EQ(0, fstat(f.oracle, &os));
	ATF_CHECK_EQ(os.st_mode, ss.st_mode);
	ATF_CHECK_EQ(os.st_uid, ss.st_uid);
	ATF_CHECK_EQ(os.st_mtim.tv_sec, ss.st_mtim.tv_sec);
	ATF_CHECK(f.c.events[DQ_OP_SETATTR] >= 3);
	teardown(&f);
}
ATF_TC_CLEANUP(fdesc_setattr, tc)
{

	dqt_umount_fdesc();
}

/* A memory-served object of the oracle's bytes with these flags. */
static struct dqt_object *
mint_flagged(struct fixture *f, uint32_t flags)
{
	struct dq_ident_file *id;
	struct dq_policy pol;
	struct dqt_object *o;
	struct statfs sfs;
	struct stat sb;

	id = calloc(1, sizeof(*id));
	ATF_REQUIRE(id != NULL);
	dqt_ident_of(f->oracle, oracle_path, id, &sb, &sfs);
	id->di_flags = flags;
	dqt_policy_write(&pol);
	o = dqt_mint_ident_flags(&f->c, id, &pol, DQ_MINT_F_WRITE, data,
	    sizeof(data));
	free(id);
	return (o);
}

struct snap_res {
	struct dqt_rr	 w, x, ro;
};

static void
child_snapshot_chmod(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct snap_res *r = result;

	r->w.rv = fchmod(fd, 0644);
	r->w.err = r->w.rv == -1 ? errno : 0;
	r->x.rv = fchmod(fd, 0555);
	r->x.err = r->x.rv == -1 ? errno : 0;
	r->ro.rv = fchmod(fd, 0444);
	r->ro.err = r->ro.rv == -1 ? errno : 0;
}

ATF_TC(snapshot_mode);
ATF_TC_HEAD(snapshot_mode, tc)
{
	atf_tc_set_md_var(tc, "descr", "K-N4: on an SF_SNAPSHOT identity a "
	    "mode with any write or execute bit is EPERM before any event, as "
	    "ufs_chmod refuses it; a read-only mode is the controller's to "
	    "answer");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(snapshot_mode, tc)
{
	struct fixture f;
	struct dqt_object *o;
	struct snap_res r;

	setup_as(&f, 7, 0, 0, 0644, DQ_MINT_F_WRITE);
	o = mint_flagged(&f, SF_SNAPSHOT);
	o->serve_errno = EROFS;
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_snapshot_chmod, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(EPERM, r.w.err);
	ATF_CHECK_EQ(EPERM, r.x.err);
	ATF_CHECK_EQ(EROFS, r.ro.err);
	ATF_CHECK_EQ(1, f.c.events[DQ_OP_SETATTR]);
	teardown(&f);
}

static volatile sig_atomic_t xfsz;

static void
on_xfsz(int sig __unused)
{

	xfsz++;
}

struct trunc_res {
	struct dqt_rr	 t;
	int		 xfsz;
};

static void
child_truncate_limited(void *arg, void *result)
{
	int fd = *(int *)arg;
	struct trunc_res *r = result;
	struct sigaction sa;
	struct rlimit rl;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_xfsz;
	(void)sigaction(SIGXFSZ, &sa, NULL);
	rl.rlim_cur = rl.rlim_max = 100;
	(void)setrlimit(RLIMIT_FSIZE, &rl);
	r->t.rv = ftruncate(fd, 1000);
	r->t.err = r->t.rv == -1 ? errno : 0;
	r->xfsz = xfsz;
}

ATF_TC(truncate_checks_attributes_first);
ATF_TC_HEAD(truncate_checks_attributes_first, tc)
{
	atf_tc_set_md_var(tc, "descr", "K-N4: ftruncate of an immutable "
	    "identity past RLIMIT_FSIZE is the attribute refusal (EPERM), "
	    "without SIGXFSZ: the limit is checked after the attributes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(truncate_checks_attributes_first, tc)
{
	struct fixture f;
	struct dqt_object *o;
	struct trunc_res r;

	setup_as(&f, 8, 0, 0, 0644, DQ_MINT_F_WRITE);
	o = mint_flagged(&f, UF_IMMUTABLE);
	memset(&r, 0, sizeof(r));
	dqt_run_child(child_truncate_limited, &o->fd, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.t.rv);
	ATF_CHECK_EQ(EPERM, r.t.err);
	ATF_CHECK_EQ(0, r.xfsz);
	ATF_CHECK_EQ(0, f.c.events[DQ_OP_SETATTR]);
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, root_oracle);
	ATF_TP_ADD_TC(tp, owner_unprivileged);
	ATF_TP_ADD_TC(tp, nonowner);
	ATF_TP_ADD_TC(tp, birthtime_pullback);
	ATF_TP_ADD_TC(tp, readonly_object);
	ATF_TP_ADD_TC(tp, fdesc_setattr);
	ATF_TP_ADD_TC(tp, snapshot_mode);
	ATF_TP_ADD_TC(tp, truncate_checks_attributes_first);
	return (atf_no_error());
}
