/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue round 2, R2-5 C17 (ux-7 items 10 and 11): presentation
 * rows.
 *
 * Item 10 (D200): a process's working-directory, root and jail rows in
 * KERN_PROC_FILEDESC come in the order CWD, ROOT, JAIL whether the
 * directories are real or served, as procstat(1) and lsof expect; a dead
 * served cwd or root (its reference could not be taken at inheritance)
 * gives the row a reclaimed directory gives, a VBAD row with an empty path,
 * in KERN_PROC_FILEDESC and KERN_PROC_CWD.  The oracle of the dead row is
 * a forcibly unmounted tmpfs.
 *
 * Item 11 (D201): a served object's statfs is presented to its reader.
 * A reader with a served root of the object's queue sees f_mntonname
 * relative to that root ("/" for a mount at or above it); any other reader
 * sees the controller's name, as a chrooted, unjailed reader sees a real
 * mount's name.  A jailed reader without PRIV_VFS_GENERATION gets
 * enforce_statfs applied as for a real mount; the oracle is the same file
 * through a real descriptor on a nullfs mount inside (and outside) the
 * jail.  A reader both jailed and under a served root sees what a jailed
 * real-mount reader sees: the served root stands for the jail's root
 * (review F-P2).
 *
 * Item 17 (Linux statx mount ids) is not here: the ids exist on dev
 * (linux_dq_fp_mount_id), and the linprocfs mountinfo rows for them can
 * only be reached through a Linux binary's statx.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/procdesc.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <jail.h>
#include <libutil.h>
#include <pthread.h>
#include <stdatomic.h>

#include "dqt_tree.h"

#define	JAIL_ORDER	"dq_present_order"
#define	JAIL_STATFS	"dq_present_statfs"
#define	FAIL_FHOLD	"debug.dqres.fail_fhold"

/*
 * Parked children.  A child keeps the pipe ends it needs and the
 * descriptors in keep (as 5, 6, ... in that order), closes everything
 * else (no directory is inherited: jail_attach and a served root's
 * attach refuse one), enters the jail jid when it is not 0, says it is
 * ready, waits for the go, runs fn with its input (3) and output (4)
 * descriptors and exits 0.  The parent attaches it between ready and go
 * when the case needs it.  fn ends by reading its input to EOF: the
 * parent closes its end (park_release) when it has read what it needs.
 */
#define	PARK_IN		3
#define	PARK_OUT	4
#define	PARK_KEEP	5
#define	PARK_KEEP_MAX	8

typedef void (*park_fn)(void *arg, int in, int out);

struct park {
	pid_t	pid;
	int	pd;
	int	to;		/* the parent's write end */
	int	from;		/* the parent's read end */
};

static void
park_wait_eof(int in)
{
	char c;

	while (read(in, &c, 1) > 0)
		continue;
}

static void
park_start(struct park *p, int jid, const int *keep, int nkeep, park_fn fn,
    void *arg)
{
	int high[2 + PARK_KEEP_MAX], to[2], from[2], i, n;
	char c;

	ATF_REQUIRE(nkeep <= PARK_KEEP_MAX);
	ATF_REQUIRE(pipe(to) == 0 && pipe(from) == 0);
	p->pid = pdfork(&p->pd, 0);
	ATF_REQUIRE(p->pid >= 0);
	if (p->pid == 0) {
		/* Above everything first, so the dup2 below never clobbers. */
		n = 0;
		high[n++] = fcntl(to[0], F_DUPFD, 100);
		high[n++] = fcntl(from[1], F_DUPFD, 100);
		for (i = 0; i < nkeep; i++)
			high[n++] = fcntl(keep[i], F_DUPFD, 100);
		for (i = 0; i < n; i++)
			if (high[i] == -1 || dup2(high[i], PARK_IN + i) == -1)
				_exit(70);
		closefrom(PARK_IN + n);
		if (jid > 0 && jail_attach(jid) != 0) {
			c = 'j';
			(void)write(PARK_OUT, &c, 1);
			_exit(71);
		}
		c = 'r';
		if (write(PARK_OUT, &c, 1) != 1 || read(PARK_IN, &c, 1) != 1)
			_exit(72);
		fn(arg, PARK_IN, PARK_OUT);
		_exit(0);
	}
	(void)close(to[0]);
	(void)close(from[1]);
	p->to = to[1];
	p->from = from[0];
	ATF_REQUIRE_EQ_MSG(1, read(p->from, &c, 1), "the parked child died "
	    "before it was ready");
	ATF_REQUIRE_MSG(c == 'r', "the parked child could not enter jail %d",
	    jid);
}

static void
park_go(struct park *p)
{

	ATF_REQUIRE_EQ(1, write(p->to, "g", 1));
}

static void
park_release(struct park *p)
{

	if (p->to != -1) {
		(void)close(p->to);
		p->to = -1;
	}
}

static void
park_finish(struct park *p, const char *what)
{
	int status;

	park_release(p);
	ATF_REQUIRE_EQ(0, pdwait(p->pd, &status, WEXITED, NULL, NULL));
	dqt_require_exit0(status, what);
	(void)close(p->from);
	(void)close(p->pd);
}

/*
 * The CWD, ROOT and JAIL rows of a process, in the order the kernel gave
 * them, with the fields the comparisons need.
 */
#define	NDIRROW	6

struct dirrow {
	int	fd;
	int	type;
	int	vtype;
	int	flags;
	int	status;
	int	refcount;
	int64_t	offset;
	char	path[PATH_MAX];
};

struct dirrows {
	int		err;
	int		n;
	int		ncwd, nroot, njail;
	char		order[NDIRROW + 1];	/* C, R, J */
	struct dirrow	r[NDIRROW];
};

static void
dirrow_of(const struct kinfo_file *kif, struct dirrow *d)
{

	d->fd = kif->kf_fd;
	d->type = kif->kf_type;
	d->vtype = kif->kf_vnode_type;
	d->flags = kif->kf_flags;
	d->status = kif->kf_status;
	d->refcount = kif->kf_ref_count;
	d->offset = kif->kf_offset;
	strlcpy(d->path, kif->kf_path, sizeof(d->path));
}

static void
dirrows_of(pid_t pid, struct dirrows *dr)
{
	struct kinfo_file *kif;
	int cnt, i;
	char c;

	memset(dr, 0, sizeof(*dr));
	kif = kinfo_getfile(pid, &cnt);
	if (kif == NULL) {
		dr->err = errno;
		return;
	}
	for (i = 0; i < cnt; i++) {
		switch (kif[i].kf_fd) {
		case KF_FD_TYPE_CWD:
			c = 'C';
			dr->ncwd++;
			break;
		case KF_FD_TYPE_ROOT:
			c = 'R';
			dr->nroot++;
			break;
		case KF_FD_TYPE_JAIL:
			c = 'J';
			dr->njail++;
			break;
		default:
			continue;
		}
		if (dr->n < NDIRROW) {
			dirrow_of(&kif[i], &dr->r[dr->n]);
			dr->order[dr->n] = c;
			dr->n++;
		}
	}
	free(kif);
}

/* KERN_PROC_CWD's one row. */
static int
proc_cwd_row(pid_t pid, struct dirrow *d)
{
	struct kinfo_file kif;
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_CWD;
	mib[3] = pid;
	len = sizeof(kif);
	memset(&kif, 0, sizeof(kif));
	memset(d, 0, sizeof(*d));
	if (sysctl(mib, 4, &kif, &len, NULL, 0) != 0)
		return (errno);
	dirrow_of(&kif, d);
	return (0);
}

static void
check_dirrow_eq(const struct dirrow *want, const struct dirrow *got,
    const char *what)
{

	ATF_CHECK_EQ_MSG(want->fd, got->fd, "%s: kf_fd", what);
	ATF_CHECK_EQ_MSG(want->type, got->type, "%s: kf_type", what);
	ATF_CHECK_EQ_MSG(want->vtype, got->vtype, "%s: kf_vnode_type %d, "
	    "want %d", what, got->vtype, want->vtype);
	ATF_CHECK_EQ_MSG(want->flags, got->flags, "%s: kf_flags %#x, want "
	    "%#x", what, got->flags, want->flags);
	ATF_CHECK_EQ_MSG(want->status, got->status, "%s: kf_status %#x, want "
	    "%#x", what, got->status, want->status);
	ATF_CHECK_EQ_MSG(want->refcount, got->refcount, "%s: kf_ref_count",
	    what);
	ATF_CHECK_EQ_MSG(want->offset, got->offset, "%s: kf_offset", what);
	ATF_CHECK_STREQ_MSG(want->path, got->path, "%s: kf_path", what);
}

static int
mount_fs(const char *type, const char *target, const char *src)
{
	struct iovec iov[6];
	int n;

	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, type);
	iov[1].iov_len = strlen(type) + 1;
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, target);
	iov[3].iov_len = strlen(target) + 1;
	n = 4;
	if (src != NULL) {
		iov[4].iov_base = __DECONST(char *, "target");
		iov[4].iov_len = sizeof("target");
		iov[5].iov_base = __DECONST(char *, src);
		iov[5].iov_len = strlen(src) + 1;
		n = 6;
	}
	return (nmount(iov, n, 0));
}

/* mkdir and mount at the work directory's dir; the absolute path in abs. */
static void
mount_at(const char *type, const char *dir, const char *src, char *abs)
{

	ATF_REQUIRE_EQ(0, mkdir(dir, 0755));
	ATF_REQUIRE(realpath(dir, abs) != NULL);
	ATF_REQUIRE_EQ_MSG(0, mount_fs(type, abs, src), "mount %s at %s: %s",
	    type, abs, strerror(errno));
}

static void
unmount_quiet(const char *dir)
{
	char abs[PATH_MAX];

	if (realpath(dir, abs) != NULL)
		(void)unmount(abs, MNT_FORCE);
}

/*
 * kinfo_row_order_served (A-item 10).  A jailed process (jail path "/", so
 * the JAIL row exists) in four states: unattached, attached with real
 * starts, attached with a served cwd, attached with a served cwd and root.
 * Its own view and another process's view of its rows are CWD, ROOT,
 * JAIL, each once.  dev puts the served rows after JAIL.
 */
static void
rows_self_fn(void *arg __unused, int in, int out)
{
	struct dirrows dr;

	dirrows_of(getpid(), &dr);
	(void)write(out, &dr, sizeof(dr));
	park_wait_eof(in);
}

static void
check_order(const struct dirrows *dr, const char *who, const char *state)
{

	ATF_CHECK_EQ_MSG(0, dr->err, "%s, %s: kinfo_getfile: %s", state, who,
	    strerror(dr->err));
	ATF_CHECK_EQ_MSG(1, dr->ncwd, "%s, %s: %d CWD rows", state, who,
	    dr->ncwd);
	ATF_CHECK_EQ_MSG(1, dr->nroot, "%s, %s: %d ROOT rows", state, who,
	    dr->nroot);
	ATF_CHECK_EQ_MSG(1, dr->njail, "%s, %s: %d JAIL rows", state, who,
	    dr->njail);
	ATF_CHECK_STREQ_MSG("CRJ", dr->order, "%s, %s: the rows came as %s",
	    state, who, dr->order);
}

DQT_TREE_TC_CLEANUP(kinfo_row_order_served);
ATF_TC_BODY(kinfo_row_order_served, tc)
{
	static const struct {
		const char	*name;
		bool		 attach;
		bool		 cwd;
		bool		 root;
	} st[] = {
		{ "unattached", false, false, false },
		{ "attached, real cwd and root", true, false, false },
		{ "served cwd, real root", true, true, false },
		{ "served cwd and root", true, true, true },
	};
	struct dqt_tree s;
	struct dirrows self, other;
	struct park p;
	size_t i;
	int jid;

	jid = jail_setv(JAIL_CREATE, "path", "/", "name", JAIL_ORDER,
	    "persist", "true", NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	for (i = 0; i < nitems(st); i++) {
		park_start(&p, jid, NULL, 0, rows_self_fn, NULL);
		if (st[i].attach)
			ATF_REQUIRE_MSG(dq_attach_starts(s.q, p.pd,
			    st[i].root ? s.sroot : -1,
			    st[i].cwd ? s.sroot : -1) == 0,
			    "%s: attach: %s", st[i].name, strerror(errno));
		park_go(&p);
		ATF_REQUIRE_EQ(sizeof(self), dqt_read_full(p.from, &self,
		    sizeof(self)));
		dirrows_of(p.pid, &other);
		park_finish(&p, st[i].name);
		check_order(&self, "own view", st[i].name);
		check_order(&other, "another process's view", st[i].name);
	}
	dqt_tree_stop(&s);
}
ATF_TC_CLEANUP(kinfo_row_order_served, tc)
{
	int jid;

	jid = jail_getid(JAIL_ORDER);
	if (jid != -1)
		(void)jail_remove(jid);
}

/*
 * kinfo_dead_cwd_row (A-item 10, T-knob).  A dead served cwd and root
 * (debug.dqres.fail_fhold makes the fork's inheritance fail their fhold,
 * as a reference count about to overflow does) give the rows a forcibly
 * unmounted cwd and root give: VBAD, an empty path, no KF_ATTR_VALID,
 * FREAD, in KERN_PROC_FILEDESC and KERN_PROC_CWD.  dev has no knob; its
 * dead rows are missing and KERN_PROC_CWD is EINVAL.
 */
struct oracle_arg {
	char	dir[PATH_MAX];
};

static void
oracle_fn(void *arg, int in, int out)
{
	struct oracle_arg *a = arg;
	int error;

	error = 0;
	if (chroot(a->dir) != 0 || chdir("/") != 0)
		error = errno;
	(void)write(out, &error, sizeof(error));
	park_wait_eof(in);
}

struct dead_res {
	int	knob_err;
	pid_t	g;
};

static void
dead_fn(void *arg __unused, int in, int out)
{
	struct dead_res r;
	int me, status;

	me = getpid();
	r.knob_err = DQT_ERRNO_OF(sysctlbyname(FAIL_FHOLD, NULL, NULL, &me,
	    sizeof(me)));
	r.g = fork();
	if (r.g == 0) {
		/* The process whose inheritance failed: parked until EOF. */
		park_wait_eof(in);
		_exit(0);
	}
	(void)write(out, &r, sizeof(r));
	park_wait_eof(in);
	if (r.g > 0 && (waitpid(r.g, &status, 0) != r.g ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0))
		_exit(80);
}

DQT_TREE_TC_CLEANUP(kinfo_dead_cwd_row);
ATF_TC_BODY(kinfo_dead_cwd_row, tc)
{
	struct oracle_arg oa;
	struct dqt_tree s;
	struct dirrows ora, dead;
	struct dirrow oracwd, deadcwd;
	struct dead_res dr;
	struct park p;
	size_t len;
	int error, knob, oraerr, deaderr;

	dqt_require_fault_knob(FAIL_FHOLD);

	/* The oracle: cwd and root on a tmpfs, then a forced unmount. */
	mount_at("tmpfs", "o", NULL, oa.dir);
	park_start(&p, 0, NULL, 0, oracle_fn, &oa);
	park_go(&p);
	ATF_REQUIRE_EQ(sizeof(error), dqt_read_full(p.from, &error,
	    sizeof(error)));
	ATF_REQUIRE_EQ_MSG(0, error, "oracle chroot: %s", strerror(error));
	ATF_REQUIRE_EQ_MSG(0, unmount(oa.dir, MNT_FORCE), "unmount -f: %s",
	    strerror(errno));
	dirrows_of(p.pid, &ora);
	oraerr = proc_cwd_row(p.pid, &oracwd);
	park_finish(&p, "oracle");
	ATF_REQUIRE_EQ(0, ora.err);
	/*
	 * chroot(2) of an unjailed process also sets its jail directory
	 * (pwd_chroot), so the oracle has a JAIL row; the attached process
	 * below is not chrooted and has none.  Only CWD and ROOT compare.
	 */
	ATF_REQUIRE_STREQ_MSG("CRJ", ora.order, "oracle rows %s", ora.order);
	ATF_REQUIRE_EQ_MSG(KF_VTYPE_VBAD, ora.r[0].vtype, "the oracle's "
	    "cwd is not reclaimed (vtype %d)", ora.r[0].vtype);
	ATF_REQUIRE_EQ_MSG(0, oraerr, "oracle KERN_PROC_CWD: %s",
	    strerror(oraerr));

	/* The served process forks with the knob armed for itself. */
	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	park_start(&p, 0, NULL, 0, dead_fn, NULL);
	ATF_REQUIRE_MSG(dq_attach_starts(s.q, p.pd, s.sroot, s.sroot) == 0,
	    "attach: %s", strerror(errno));
	park_go(&p);
	ATF_REQUIRE_EQ(sizeof(dr), dqt_read_full(p.from, &dr, sizeof(dr)));
	ATF_REQUIRE_EQ_MSG(0, dr.knob_err, "%s: %s", FAIL_FHOLD,
	    strerror(dr.knob_err));
	ATF_REQUIRE_MSG(dr.g > 0, "fork failed in the attached process");
	dirrows_of(dr.g, &dead);
	deaderr = proc_cwd_row(dr.g, &deadcwd);
	len = sizeof(knob);
	ATF_REQUIRE_EQ(0, sysctlbyname(FAIL_FHOLD, &knob, &len, NULL, 0));
	park_finish(&p, "served");
	dqt_tree_stop(&s);

	ATF_CHECK_EQ_MSG(0, knob, "%s was not consumed by the fork (%d)",
	    FAIL_FHOLD, knob);
	ATF_CHECK_EQ(0, dead.err);
	ATF_CHECK_STREQ_MSG("CR", dead.order, "dead served rows came as "
	    "\"%s\"", dead.order);
	if (dead.n == 2) {
		check_dirrow_eq(&ora.r[0], &dead.r[0], "dead cwd row");
		check_dirrow_eq(&ora.r[1], &dead.r[1], "dead root row");
	}
	ATF_CHECK_EQ_MSG(0, deaderr, "KERN_PROC_CWD of a dead served cwd: %s",
	    strerror(deaderr));
	if (deaderr == 0)
		check_dirrow_eq(&oracwd, &deadcwd, "KERN_PROC_CWD");
}
ATF_TC_CLEANUP(kinfo_dead_cwd_row, tc)
{

	unmount_quiet("o");
	(void)sysctlbyname(FAIL_FHOLD, NULL, NULL, &(int){ 0 }, sizeof(int));
}

/*
 * export_lockdance_contended (A9).  One thread of the target changes its
 * working directory between two directories as fast as it can (each
 * change takes PWDDESC_XLOCK) while this process reads its rows: every
 * row set has the CWD row once, before the ROOT row, naming one of the
 * directories.  With served directories, and with real ones as the
 * control.  An INVARIANTS + WITNESS kernel's console is read by the
 * tier's console step.  The read count is the stress, not a timing: each
 * read meets the churn at a different point.
 */
#define	LOCKDANCE_READS	1000

struct churn_arg {
	char		 a[PATH_MAX];
	char		 b[PATH_MAX];
	atomic_bool	 stop;
	unsigned long	 n;
	int		 errors;
};

static void *
churn_thread(void *argp)
{
	struct churn_arg *a = argp;

	while (!atomic_load(&a->stop)) {
		if (chdir(a->a) != 0)
			a->errors++;
		if (chdir(a->b) != 0)
			a->errors++;
		a->n++;
	}
	return (NULL);
}

struct churn_res {
	int		started;
	unsigned long	n;
	int		errors;
};

static void
churn_fn(void *arg, int in, int out)
{
	struct churn_arg *a = arg;
	struct churn_res r;
	pthread_t t;

	memset(&r, 0, sizeof(r));
	atomic_store(&a->stop, false);
	r.started = pthread_create(&t, NULL, churn_thread, a);
	(void)write(out, &r.started, sizeof(r.started));
	park_wait_eof(in);
	if (r.started == 0) {
		atomic_store(&a->stop, true);
		(void)pthread_join(t, NULL);
	}
	r.n = a->n;
	r.errors = a->errors;
	(void)write(out, &r, sizeof(r));
}

static void
lockdance(struct park *p, const char *what, const char *const *paths,
    int npaths)
{
	struct dirrows dr;
	struct dirrow cwd;
	struct churn_res r;
	int bad, error, i, j, k, started;
	bool known;

	ATF_REQUIRE_EQ(sizeof(started), dqt_read_full(p->from, &started,
	    sizeof(started)));
	ATF_REQUIRE_EQ_MSG(0, started, "%s: pthread_create: %s", what,
	    strerror(started));
	bad = 0;
	for (i = 0; i < LOCKDANCE_READS; i++) {
		dirrows_of(p->pid, &dr);
		error = proc_cwd_row(p->pid, &cwd);
		known = false;
		for (k = 0; k < npaths; k++)
			if (dr.n > 0 && strcmp(dr.r[0].path, paths[k]) == 0)
				known = true;
		for (j = 0; j < npaths; j++)
			if (error == 0 && strcmp(cwd.path, paths[j]) == 0)
				break;
		if (dr.err != 0 || dr.ncwd != 1 || dr.nroot != 1 ||
		    strcmp(dr.order, "CR") != 0 || !known || error != 0 ||
		    j == npaths) {
			if (bad++ == 0)
				ATF_CHECK_MSG(false, "%s: read %d: err %d, %d "
				    "CWD and %d ROOT rows as \"%s\", CWD \"%s\", "
				    "KERN_PROC_CWD %d \"%s\"", what, i, dr.err,
				    dr.ncwd, dr.nroot, dr.order,
				    dr.n > 0 ? dr.r[0].path : "",
				    error, cwd.path);
		}
	}
	park_release(p);
	ATF_REQUIRE_EQ(sizeof(r), dqt_read_full(p->from, &r, sizeof(r)));
	park_finish(p, what);
	ATF_CHECK_EQ_MSG(0, bad, "%s: %d of %d row sets malformed", what, bad,
	    LOCKDANCE_READS);
	ATF_CHECK_EQ_MSG(0, r.errors, "%s: %d failed chdir", what, r.errors);
	ATF_CHECK_MSG(r.n > 0, "%s: the churn never ran", what);
}

/* Set before each fork; each child churns its own copy. */
static struct churn_arg churn;

DQT_TREE_TC(export_lockdance_contended);
ATF_TC_BODY(export_lockdance_contended, tc)
{
	struct churn_arg *a;
	struct dqt_tree s;
	struct park p;
	char rd[PATH_MAX], rde[PATH_MAX], top[PATH_MAX], sd[PATH_MAX],
	    sde[PATH_MAX];
	const char *paths[3];

	a = &churn;

	/* Served: chdir between /d and /d/e under the served root. */
	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	strlcpy(a->a, "/d", sizeof(a->a));
	strlcpy(a->b, "/d/e", sizeof(a->b));
	/* This process is unattached: it sees the raw di_path. */
	snprintf(top, sizeof(top), "%s", s.backing);
	snprintf(sd, sizeof(sd), "%s/d", s.backing);
	snprintf(sde, sizeof(sde), "%s/d/e", s.backing);
	paths[0] = top;
	paths[1] = sd;
	paths[2] = sde;
	park_start(&p, 0, NULL, 0, churn_fn, a);
	ATF_REQUIRE_MSG(dq_attach_starts(s.q, p.pd, s.sroot, s.sroot) == 0,
	    "attach: %s", strerror(errno));
	park_go(&p);
	lockdance(&p, "served", paths, 3);
	dqt_tree_stop(&s);

	/* The control: real directories, unattached. */
	ATF_REQUIRE_EQ(0, mkdir("r", 0755));
	ATF_REQUIRE_EQ(0, mkdir("r/d", 0755));
	ATF_REQUIRE_EQ(0, mkdir("r/d/e", 0755));
	ATF_REQUIRE(realpath("r/d", rd) != NULL);
	ATF_REQUIRE(realpath("r/d/e", rde) != NULL);
	strlcpy(a->a, rd, sizeof(a->a));
	strlcpy(a->b, rde, sizeof(a->b));
	ATF_REQUIRE(getcwd(top, sizeof(top)) != NULL);
	paths[0] = top;
	paths[1] = rd;
	paths[2] = rde;
	park_start(&p, 0, NULL, 0, churn_fn, a);
	park_go(&p);
	lockdance(&p, "real", paths, 3);
}

/*
 * statfs of a served object (item 11).  The fields compared are the ones
 * a mount does not change while the case runs (fstatfs_test's set less
 * f_blocks, a live value on tmpfs).
 */
static void
check_statfs_eq(const struct statfs *want, const struct statfs *got,
    const char *what)
{

	ATF_CHECK_EQ_MSG(want->f_type, got->f_type, "%s: f_type", what);
	ATF_CHECK_EQ_MSG(want->f_flags, got->f_flags, "%s: f_flags", what);
	ATF_CHECK_EQ_MSG(want->f_bsize, got->f_bsize, "%s: f_bsize", what);
	ATF_CHECK_EQ_MSG(want->f_iosize, got->f_iosize, "%s: f_iosize", what);
	ATF_CHECK_EQ_MSG(want->f_namemax, got->f_namemax, "%s: f_namemax",
	    what);
	ATF_CHECK_EQ_MSG(want->f_owner, got->f_owner, "%s: f_owner", what);
	ATF_CHECK_EQ_MSG(want->f_fsid.val[0], got->f_fsid.val[0],
	    "%s: f_fsid[0] %#x, want %#x", what, got->f_fsid.val[0],
	    want->f_fsid.val[0]);
	ATF_CHECK_EQ_MSG(want->f_fsid.val[1], got->f_fsid.val[1],
	    "%s: f_fsid[1] %#x, want %#x", what, got->f_fsid.val[1],
	    want->f_fsid.val[1]);
	ATF_CHECK_STREQ_MSG(want->f_fstypename, got->f_fstypename,
	    "%s: f_fstypename", what);
	ATF_CHECK_STREQ_MSG(want->f_mntfromname, got->f_mntfromname,
	    "%s: f_mntfromname", what);
	ATF_CHECK_STREQ_MSG(want->f_mntonname, got->f_mntonname,
	    "%s: f_mntonname", what);
}

/*
 * statfs_jail_enforce{0,1,2} (D201, QX-12).  A jail at jr with
 * enforce_statfs N.  Three files, each through a real descriptor (the
 * oracle) and a served object minted from it (the same statfs, the same
 * di_path): jr/m/f on a nullfs mount inside the jail, outm/f on a nullfs
 * mount outside it, jr/g on the mount holding the jail root.  A process in
 * the jail sees the same fstatfs through both.  dev presents the served
 * ones unfiltered: enforce_statfs 1 and 2 differ.
 */
#define	NSTATFS	3

struct statfs_res {
	int		err[2 * NSTATFS];
	struct statfs	sf[2 * NSTATFS];	/* real, then served */
};

static void
statfs_fn(void *arg __unused, int in, int out)
{
	struct statfs_res r;
	int i;

	memset(&r, 0, sizeof(r));
	for (i = 0; i < 2 * NSTATFS; i++)
		r.err[i] = DQT_ERRNO_OF(fstatfs(PARK_KEEP + i, &r.sf[i]));
	(void)write(out, &r, sizeof(r));
	park_wait_eof(in);
}

static void
statfs_jail(int enforce)
{
	static const char *const what[NSTATFS] = {
		"nullfs inside the jail", "nullfs outside the jail",
		"the jail root's mount",
	};
	struct statfs_res r;
	struct dqt_ctl c;
	struct dqt_object *o;
	struct park p;
	char jr[PATH_MAX], m[PATH_MAX], outm[PATH_MAX], src[PATH_MAX],
	    path[NSTATFS][PATH_MAX], name[64], enf[8];
	int keep[2 * NSTATFS], i, jid;

	ATF_REQUIRE_EQ(0, mkdir("jr", 0755));
	ATF_REQUIRE(realpath("jr", jr) != NULL);
	ATF_REQUIRE_EQ(0, mkdir("src_in", 0755));
	dqt_tree_file("src_in", "f", "in\n");
	ATF_REQUIRE_EQ(0, mkdir("src_out", 0755));
	dqt_tree_file("src_out", "f", "out\n");
	dqt_tree_file("jr", "g", "g\n");
	ATF_REQUIRE(realpath("src_in", src) != NULL);
	mount_at("nullfs", "jr/m", src, m);
	ATF_REQUIRE(realpath("src_out", src) != NULL);
	mount_at("nullfs", "outm", src, outm);
	snprintf(path[0], PATH_MAX, "%s/f", m);
	snprintf(path[1], PATH_MAX, "%s/f", outm);
	snprintf(path[2], PATH_MAX, "%s/g", jr);

	dqt_init(&c);
	for (i = 0; i < NSTATFS; i++) {
		keep[i] = open(path[i], O_RDONLY);
		ATF_REQUIRE_MSG(keep[i] >= 0, "open %s: %s", path[i],
		    strerror(errno));
		o = dqt_mint(&c, keep[i], path[i], "x\n", 2, NULL);
		ATF_REQUIRE(o != NULL);
		keep[NSTATFS + i] = o->fd;
	}
	snprintf(name, sizeof(name), "%s%d", JAIL_STATFS, enforce);
	snprintf(enf, sizeof(enf), "%d", enforce);
	jid = jail_setv(JAIL_CREATE, "path", jr, "name", name, "persist",
	    "true", "enforce_statfs", enf, NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	park_start(&p, jid, keep, 2 * NSTATFS, statfs_fn, NULL);
	park_go(&p);
	ATF_REQUIRE_EQ(sizeof(r), dqt_read_full(p.from, &r, sizeof(r)));
	park_finish(&p, "jailed reader");
	for (i = 0; i < NSTATFS; i++)
		(void)close(keep[i]);
	dqt_fini(&c);

	for (i = 0; i < 2 * NSTATFS; i++)
		ATF_REQUIRE_EQ_MSG(0, r.err[i], "fstatfs %d: %s", i,
		    strerror(r.err[i]));
	/* The oracle is what prison_enforce_statfs gives. */
	if (enforce == 0) {
		ATF_REQUIRE_STREQ(m, r.sf[0].f_mntonname);
		ATF_REQUIRE_STREQ(outm, r.sf[1].f_mntonname);
	} else {
		ATF_REQUIRE_STREQ(enforce == 1 ? "/m" : "[restricted]",
		    r.sf[0].f_mntonname);
		ATF_REQUIRE_STREQ("[restricted]", r.sf[1].f_mntonname);
		ATF_REQUIRE_STREQ("/", r.sf[2].f_mntonname);
	}
	for (i = 0; i < NSTATFS; i++)
		check_statfs_eq(&r.sf[i], &r.sf[NSTATFS + i], what[i]);
}

static void
statfs_jail_cleanup(int enforce)
{
	char name[64];
	int jid;

	snprintf(name, sizeof(name), "%s%d", JAIL_STATFS, enforce);
	jid = jail_getid(name);
	if (jid != -1)
		(void)jail_remove(jid);
	unmount_quiet("jr/m");
	unmount_quiet("outm");
}

#define	STATFS_JAIL_TC(n)						\
DQT_TREE_TC_CLEANUP(statfs_jail_enforce##n);				\
ATF_TC_BODY(statfs_jail_enforce##n, tc)					\
{									\
	statfs_jail(n);							\
}									\
ATF_TC_CLEANUP(statfs_jail_enforce##n, tc)				\
{									\
	statfs_jail_cleanup(n);						\
}

STATFS_JAIL_TC(0)
STATFS_JAIL_TC(1)
STATFS_JAIL_TC(2)

/*
 * statfs_jail_served_root_enforce{1,2} (D201, review F-P2).  A reader
 * that is both in a jail (path mnt/t, enforce_statfs N) and attached with
 * a served root of that same directory sees a served object's statfs
 * exactly as a real-mount reader in that jail sees the backing file's:
 * for the mount below the root (mnt/t/sub, presented "/sub") the name and
 * f_fsid kept at 1, "[restricted]" and a zero f_fsid at 2; for the mount
 * holding the root ("/") the name kept and f_fsid zero at 2.  The oracle
 * is the same jailed process's fstatfs of real descriptors of the two
 * files, which enforce_statfs filters as for any real mount (a real
 * descriptor's fstatfs is unchanged under a served root); the oracle's
 * own values are asserted too, so the comparison cannot pass vacuously.
 * The fix commit 81cd9388fd5 kept a presented name at 2 and only zeroed
 * f_fsid, so a jailed served-root reader learned "/sub" where a real
 * reader got "[restricted]": enforce2 fails there and passes with the
 * rule applied.  The program runs alone (is_exclusive in the Makefile),
 * as the other jail cases do.
 */
#define	JAIL_SROOT	"dq_present_statfs_sroot"
#define	NSRJ		5

struct srj_res {
	int		err[NSRJ];
	/* real sub/x, real d/f, statfs /sub/x, statfs /d/f, fstatfs /sub/x */
	struct statfs	sf[NSRJ];
};

static void
srj_fn(void *arg __unused, int in, int out)
{
	struct srj_res r;
	int fd;

	memset(&r, 0, sizeof(r));
	r.err[0] = DQT_ERRNO_OF(fstatfs(PARK_KEEP, &r.sf[0]));
	r.err[1] = DQT_ERRNO_OF(fstatfs(PARK_KEEP + 1, &r.sf[1]));
	r.err[2] = DQT_ERRNO_OF(statfs("/sub/x", &r.sf[2]));
	r.err[3] = DQT_ERRNO_OF(statfs("/d/f", &r.sf[3]));
	fd = open("/sub/x", O_RDONLY);
	r.err[4] = fd < 0 ? errno : DQT_ERRNO_OF(fstatfs(fd, &r.sf[4]));
	if (fd >= 0)
		(void)close(fd);
	(void)write(out, &r, sizeof(r));
	park_wait_eof(in);
}

static void
statfs_jail_served_root(int enforce)
{
	struct srj_res r;
	struct statfs sub, top;
	struct dqt_tree s;
	struct park p;
	char jr[PATH_MAX], mnt[PATH_MAX], submnt[PATH_MAX], name[64], enf[8];
	int keep[2], i, jid;

	mount_at("tmpfs", "mnt", NULL, mnt);
	dqt_tree_make("mnt/t");
	mount_at("tmpfs", "mnt/t/sub", NULL, submnt);
	dqt_tree_file("mnt/t/sub", "x", "x\n");
	ATF_REQUIRE(realpath("mnt/t", jr) != NULL);
	/* The unjailed view: the fsids the jail keeps at 1. */
	ATF_REQUIRE_EQ(0, statfs("mnt/t/sub/x", &sub));
	ATF_REQUIRE_EQ(0, statfs("mnt/t/d/f", &top));
	ATF_REQUIRE_STREQ(submnt, sub.f_mntonname);
	ATF_REQUIRE_STREQ(mnt, top.f_mntonname);
	ATF_REQUIRE(sub.f_fsid.val[0] != 0 || sub.f_fsid.val[1] != 0);
	ATF_REQUIRE(top.f_fsid.val[0] != 0 || top.f_fsid.val[1] != 0);
	keep[0] = open("mnt/t/sub/x", O_RDONLY);
	keep[1] = open("mnt/t/d/f", O_RDONLY);
	ATF_REQUIRE(keep[0] >= 0 && keep[1] >= 0);

	dqt_tree_start(&s, "mnt/t", DQ_TREE_F_ROOT);
	snprintf(name, sizeof(name), "%s%d", JAIL_SROOT, enforce);
	snprintf(enf, sizeof(enf), "%d", enforce);
	jid = jail_setv(JAIL_CREATE, "path", jr, "name", name, "persist",
	    "true", "enforce_statfs", enf, NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	/* Jailed first (jail_attach chroots), then the served root. */
	park_start(&p, jid, keep, 2, srj_fn, NULL);
	ATF_REQUIRE_MSG(dq_attach_starts(s.q, p.pd, s.sroot, s.sroot) == 0,
	    "attach: %s", strerror(errno));
	park_go(&p);
	ATF_REQUIRE_EQ(sizeof(r), dqt_read_full(p.from, &r, sizeof(r)));
	park_finish(&p, "jailed served-root reader");
	dqt_tree_stop(&s);
	(void)close(keep[0]);
	(void)close(keep[1]);

	for (i = 0; i < NSRJ; i++)
		ATF_REQUIRE_EQ_MSG(0, r.err[i], "statfs %d: %s", i,
		    strerror(r.err[i]));
	/* The oracle is what prison_enforce_statfs gives the real reader. */
	if (enforce == 1) {
		ATF_REQUIRE_STREQ("/sub", r.sf[0].f_mntonname);
		ATF_REQUIRE_EQ(sub.f_fsid.val[0], r.sf[0].f_fsid.val[0]);
		ATF_REQUIRE_EQ(sub.f_fsid.val[1], r.sf[0].f_fsid.val[1]);
		ATF_REQUIRE_EQ(top.f_fsid.val[0], r.sf[1].f_fsid.val[0]);
		ATF_REQUIRE_EQ(top.f_fsid.val[1], r.sf[1].f_fsid.val[1]);
	} else {
		ATF_REQUIRE_STREQ("[restricted]", r.sf[0].f_mntonname);
		ATF_REQUIRE_EQ(0, r.sf[0].f_fsid.val[0]);
		ATF_REQUIRE_EQ(0, r.sf[0].f_fsid.val[1]);
		ATF_REQUIRE_EQ(0, r.sf[1].f_fsid.val[0]);
		ATF_REQUIRE_EQ(0, r.sf[1].f_fsid.val[1]);
	}
	ATF_REQUIRE_STREQ("/", r.sf[1].f_mntonname);
	check_statfs_eq(&r.sf[0], &r.sf[2], "statfs /sub/x, below the root");
	check_statfs_eq(&r.sf[0], &r.sf[4], "fstatfs /sub/x, below the root");
	check_statfs_eq(&r.sf[1], &r.sf[3], "statfs /d/f, the root's mount");
}

static void
statfs_jail_served_root_cleanup(int enforce)
{
	char name[64];
	int jid;

	snprintf(name, sizeof(name), "%s%d", JAIL_SROOT, enforce);
	jid = jail_getid(name);
	if (jid != -1)
		(void)jail_remove(jid);
	unmount_quiet("mnt/t/sub");
	unmount_quiet("mnt");
}

#define	STATFS_JAIL_SROOT_TC(n)						\
DQT_TREE_TC_CLEANUP(statfs_jail_served_root_enforce##n);		\
ATF_TC_BODY(statfs_jail_served_root_enforce##n, tc)			\
{									\
	statfs_jail_served_root(n);					\
}									\
ATF_TC_CLEANUP(statfs_jail_served_root_enforce##n, tc)			\
{									\
	statfs_jail_served_root_cleanup(n);				\
}

STATFS_JAIL_SROOT_TC(1)
STATFS_JAIL_SROOT_TC(2)

/*
 * statfs_unjailed_nonroot_oracle (D201).  An unjailed uid-1001 reader
 * without a served root: statfs(2) of a served name and fstatfs(2) of a
 * served descriptor give the controller's f_mntonname raw and its f_fsid
 * unchanged, the same as fstatfs(2) of a real descriptor of the backing
 * file on that (non-root) mount: FreeBSD hides neither from an unjailed
 * caller.  dev's tree controller presents every mount as "/".
 */
struct nonroot_res {
	int		err[3];
	struct statfs	sf[3];	/* statfs, fstatfs served, fstatfs real */
};

static void
nonroot_fn(void *arg, void *out)
{
	struct nonroot_res *r = out;
	int fd, realfd;

	realfd = *(int *)arg;
	r->err[0] = DQT_ERRNO_OF(statfs("d/f", &r->sf[0]));
	fd = open("d/f", O_RDONLY);
	r->err[1] = fd < 0 ? errno : DQT_ERRNO_OF(fstatfs(fd, &r->sf[1]));
	r->err[2] = DQT_ERRNO_OF(fstatfs(realfd, &r->sf[2]));
	if (fd >= 0)
		(void)close(fd);
}

DQT_TREE_TC_CLEANUP(statfs_unjailed_nonroot_oracle);
ATF_TC_BODY(statfs_unjailed_nonroot_oracle, tc)
{
	struct nonroot_res r;
	struct dqt_tree s;
	char mnt[PATH_MAX];
	int realfd;

	/* uid 1001 searches the work directory. */
	ATF_REQUIRE_EQ(0, chmod(".", 0755));
	mount_at("tmpfs", "mnt", NULL, mnt);
	dqt_tree_make("mnt/t");
	realfd = open("mnt/t/d/f", O_RDONLY);
	ATF_REQUIRE(realfd >= 0);
	dqt_tree_start(&s, "mnt/t", 0);
	memset(&r, 0, sizeof(r));
	dqt_require_exit0(dqt_tree_child_uid(&s, -1, s.sroot, 1001,
	    nonroot_fn, &realfd, &r, sizeof(r)), "uid 1001 reader");
	dqt_tree_stop(&s);
	(void)close(realfd);
	DQT_CHECK_ERRNO(0, r.err[0], "statfs of a served name");
	DQT_CHECK_ERRNO(0, r.err[1], "fstatfs of a served descriptor");
	ATF_REQUIRE_EQ_MSG(0, r.err[2], "fstatfs of the real file: %s",
	    strerror(r.err[2]));
	ATF_REQUIRE_STREQ(mnt, r.sf[2].f_mntonname);
	check_statfs_eq(&r.sf[2], &r.sf[0], "statfs, served name");
	check_statfs_eq(&r.sf[2], &r.sf[1], "fstatfs, served descriptor");
}
ATF_TC_CLEANUP(statfs_unjailed_nonroot_oracle, tc)
{

	unmount_quiet("mnt");
}

/*
 * statfs_served_root (D201).  Under a served root of the object's queue,
 * f_mntonname is presented relative to the root: "/" for the mount the
 * root lives on (at or above it), "/sub" for a mount below it; f_fsid and
 * the rest unchanged.  dev's tree controller presents every mount as "/".
 */
struct sroot_res {
	int		err[3];
	struct statfs	sf[3];	/* /d/f, /sub/x, fstatfs /sub/x */
};

static void
sroot_fn(void *arg __unused, void *out)
{
	struct sroot_res *r = out;
	int fd;

	r->err[0] = DQT_ERRNO_OF(statfs("/d/f", &r->sf[0]));
	r->err[1] = DQT_ERRNO_OF(statfs("/sub/x", &r->sf[1]));
	fd = open("/sub/x", O_RDONLY);
	r->err[2] = fd < 0 ? errno : DQT_ERRNO_OF(fstatfs(fd, &r->sf[2]));
	if (fd >= 0)
		(void)close(fd);
}

DQT_TREE_TC_CLEANUP(statfs_served_root);
ATF_TC_BODY(statfs_served_root, tc)
{
	struct sroot_res r;
	struct statfs top, sub;
	struct dqt_tree s;
	char mnt[PATH_MAX], submnt[PATH_MAX];

	mount_at("tmpfs", "mnt", NULL, mnt);
	dqt_tree_make("mnt/t");
	mount_at("tmpfs", "mnt/t/sub", NULL, submnt);
	dqt_tree_file("mnt/t/sub", "x", "x\n");
	ATF_REQUIRE_EQ(0, statfs("mnt/t/d/f", &top));
	ATF_REQUIRE_EQ(0, statfs("mnt/t/sub/x", &sub));
	ATF_REQUIRE_STREQ(mnt, top.f_mntonname);
	ATF_REQUIRE_STREQ(submnt, sub.f_mntonname);
	dqt_tree_start(&s, "mnt/t", DQ_TREE_F_ROOT);
	memset(&r, 0, sizeof(r));
	dqt_require_exit0(dqt_tree_child(&s, s.sroot, s.sroot, sroot_fn,
	    NULL, &r, sizeof(r)), "child");
	dqt_tree_stop(&s);
	DQT_CHECK_ERRNO(0, r.err[0], "statfs /d/f");
	DQT_CHECK_ERRNO(0, r.err[1], "statfs /sub/x");
	DQT_CHECK_ERRNO(0, r.err[2], "fstatfs /sub/x");
	/* The presented names; everything else as the real mount's. */
	strlcpy(top.f_mntonname, "/", sizeof(top.f_mntonname));
	strlcpy(sub.f_mntonname, "/sub", sizeof(sub.f_mntonname));
	check_statfs_eq(&top, &r.sf[0], "statfs /d/f");
	check_statfs_eq(&sub, &r.sf[1], "statfs /sub/x");
	check_statfs_eq(&sub, &r.sf[2], "fstatfs /sub/x");
}
ATF_TC_CLEANUP(statfs_served_root, tc)
{

	unmount_quiet("mnt/t/sub");
	unmount_quiet("mnt");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, kinfo_row_order_served);
	ATF_TP_ADD_TC(tp, kinfo_dead_cwd_row);
	ATF_TP_ADD_TC(tp, export_lockdance_contended);
	ATF_TP_ADD_TC(tp, statfs_jail_enforce0);
	ATF_TP_ADD_TC(tp, statfs_jail_enforce1);
	ATF_TP_ADD_TC(tp, statfs_jail_enforce2);
	ATF_TP_ADD_TC(tp, statfs_jail_served_root_enforce1);
	ATF_TP_ADD_TC(tp, statfs_jail_served_root_enforce2);
	ATF_TP_ADD_TC(tp, statfs_unjailed_nonroot_oracle);
	ATF_TP_ADD_TC(tp, statfs_served_root);
	return (atf_no_error());
}
