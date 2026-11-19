/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Standing rules (dq-standing-decisions, stage 1): answers a queue gives
 * without posting RESOLVE.  The harness controller (dqt_ctl) records every
 * event it is posted and answers PASS (or a chosen errno); a covered
 * lookup must post nothing, count in ds2_standing_pass or
 * ds2_standing_deny, and return what the controller's reply would have
 * made it return.  Every lookup a rule does not decide posts as before.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/procdesc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libdq.h>

#include "dqt.h"
#include "dqt_tree.h"

#define	DQ_TC_HEAD_BODY(name)						\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "require.user", "root");		\
		atf_tc_set_md_var(tc, "timeout", "180");		\
	}
#define	DQ_TC(name)	ATF_TC(name); DQ_TC_HEAD_BODY(name)
#define	DQ_TC_CLEANUP(name)	ATF_TC_WITH_CLEANUP(name); DQ_TC_HEAD_BODY(name)

#define	OP(rop)		DQ_STANDING_OP(DQ_ROP_ ## rop)

/* The work directory's real path, and names under it. */
static char wd[PATH_MAX];

static void
wd_init(void)
{

	ATF_REQUIRE(realpath(".", wd) != NULL);
	/* The harness records 127 bytes of a path. */
	ATF_REQUIRE_MSG(strlen(wd) + 48 < DQT_RPATH, "work directory %s too "
	    "long for the records", wd);
}

/* wd/rel, in one of eight rotating buffers. */
static const char *
at(const char *rel)
{
	static char buf[8][PATH_MAX];
	static int i;
	char *p;

	p = buf[i++ % 8];
	snprintf(p, PATH_MAX, "%s/%s", wd, rel);
	return (p);
}

static void
mkfile(const char *path)
{
	int fd;

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ(2, write(fd, "x\n", 2));
	(void)close(fd);
}

static void
mkdirs(const char *path)
{

	ATF_REQUIRE_MSG(mkdir(path, 0755) == 0 || errno == EEXIST, "%s: %s",
	    path, strerror(errno));
}

static uint64_t
rule_ok(int q, int rootfd, const char *path, uint32_t flags, uint32_t ops,
    uint32_t action, int error)
{
	uint64_t id;

	id = 0;
	ATF_REQUIRE_MSG(dq_standing_add(q, rootfd, path, flags, ops, action,
	    error, &id) == 0, "standing rule %s: %s", path, strerror(errno));
	ATF_REQUIRE(id != 0);
	return (id);
}

/* The events of op (0: any) whose path is exactly path. */
static int
nposted(struct dqt_ctl *c, uint32_t op, const char *path)
{
	int i, n;

	n = 0;
	dqt_lock(c);
	for (i = 0; i < c->nrs; i++)
		if ((op == 0 || c->rs[i].op == op) &&
		    strcmp(c->rs[i].path, path) == 0)
			n++;
	dqt_unlock(c);
	return (n);
}

static int
nresolves(struct dqt_ctl *c)
{
	int n;

	dqt_lock(c);
	n = c->nrs;
	dqt_unlock(c);
	return (n);
}

/*
 * A child's script: each step one call, its result and (for the stat
 * family) the attributes it returned.
 */
enum kind {
	K_STAT, K_LSTAT, K_ACCESS, K_OPEN, K_READLINK, K_CHROOT, K_CHDIR,
	K_STATAT, K_OPENAT, K_DIRFD, K_CAPENTER, K_EMPTYSTAT
};
#define	NSTEPS		12

struct step {
	enum kind	 kind;
	int		 flags;
	char		 path[256];
};

struct steps {
	int		 n;
	struct step	 s[NSTEPS];
};

struct sres {
	struct dqt_rr	 r[NSTEPS];
	struct stat	 st[NSTEPS];
};

static void
step(struct steps *s, enum kind kind, const char *path, int flags)
{

	ATF_REQUIRE(s->n < NSTEPS);
	s->s[s->n].kind = kind;
	s->s[s->n].flags = flags;
	strlcpy(s->s[s->n].path, path, sizeof(s->s[0].path));
	s->n++;
}

static void
c_steps(void *arg, void *result)
{
	const struct steps *s = arg;
	struct sres *r = result;
	char buf[PATH_MAX];
	int dfd, fd, i;

	dfd = -1;
	for (i = 0; i < s->n; i++) {
		switch (s->s[i].kind) {
		case K_STAT:
			DQT_RR(r->r[i], stat(s->s[i].path, &r->st[i]));
			break;
		case K_LSTAT:
			DQT_RR(r->r[i], lstat(s->s[i].path, &r->st[i]));
			break;
		case K_ACCESS:
			DQT_RR(r->r[i], access(s->s[i].path, F_OK));
			break;
		case K_OPEN:
			DQT_RR(r->r[i], open(s->s[i].path, s->s[i].flags,
			    0644));
			if (r->r[i].rv >= 0) {
				(void)fstat((int)r->r[i].rv, &r->st[i]);
				(void)close((int)r->r[i].rv);
			}
			break;
		case K_READLINK:
			DQT_RR(r->r[i], readlink(s->s[i].path, buf,
			    sizeof(buf)));
			break;
		case K_CHROOT:
			DQT_RR(r->r[i], chroot(s->s[i].path));
			break;
		case K_CHDIR:
			DQT_RR(r->r[i], chdir(s->s[i].path));
			break;
		case K_DIRFD:
			/* The directory later steps start at. */
			DQT_RR(r->r[i], open(s->s[i].path, O_RDONLY |
			    O_DIRECTORY));
			dfd = (int)r->r[i].rv;
			break;
		case K_STATAT:
			DQT_RR(r->r[i], fstatat(dfd, s->s[i].path, &r->st[i],
			    s->s[i].flags));
			break;
		case K_OPENAT:
			DQT_RR(r->r[i], openat(dfd, s->s[i].path,
			    s->s[i].flags));
			if (r->r[i].rv >= 0) {
				(void)fstat((int)r->r[i].rv, &r->st[i]);
				(void)close((int)r->r[i].rv);
			}
			break;
		case K_CAPENTER:
			DQT_RR(r->r[i], cap_enter());
			break;
		case K_EMPTYSTAT:
			/* The file itself (AT_EMPTY_PATH). */
			fd = open(s->s[i].path, O_RDONLY);
			DQT_RR(r->r[i], fd == -1 ? -1 :
			    fstatat(fd, "", &r->st[i], AT_EMPTY_PATH));
			if (fd != -1)
				(void)close(fd);
			break;
		}
	}
}

/* Run the script attached to c's queue (or unattached when c is NULL). */
static void
run_steps(struct dqt_ctl *c, const struct steps *s, struct sres *r)
{

	memset(r, 0, sizeof(*r));
	if (c == NULL)
		dqt_run_child(c_steps, __DECONST(void *, s), r, sizeof(*r));
	else
		dqt_attach_run(c, c_steps, __DECONST(void *, s), r,
		    sizeof(*r));
}

#define	CHECK_RR(res, i, want) do {					\
	char _ws[64], _gs[64];						\
									\
	(void)strerror_r((want), _ws, sizeof(_ws));			\
	(void)strerror_r((res)->r[(i)].err, _gs, sizeof(_gs));		\
	ATF_CHECK_EQ_MSG((want), (res)->r[(i)].err,			\
	    "step %d: want %d (%s), got %d (%s)", (int)(i), (want), _ws,\
	    (res)->r[(i)].err, _gs);					\
} while (0)

static void
stats2(struct dqt_ctl *c, uint64_t *pass, uint64_t *deny)
{
	struct dq_stats2 st;

	dqt_stats2(c, &st);
	*pass = st.ds2_standing_pass;
	*deny = st.ds2_standing_deny;
}

/*
 * Validation (dq-standing-decisions §4.3): every ADD and DEL refusal, in
 * dq.4's order.
 */
static void
rule_init(struct dq_standing_rule *r, const char *path, uint32_t ops)
{

	memset(r, 0, sizeof(*r));
	r->dqs_version = DQ_API_VERSION;
	r->dqs_flags = DQ_STANDING_F_SUBTREE;
	r->dqs_ops = ops;
	r->dqs_action = DQ_STANDING_PASS;
	r->dqs_rootfd = -1;
	r->dqs_pathlen = (uint32_t)strlen(path);
	memcpy(r->dqs_path, path, r->dqs_pathlen);
}

#define	ADD_REFUSED(q, r, want) do {					\
	DQT_CHECK_REFUSED(ioctl((q), DQ_IOC_STANDING_ADD, (r)), (want));\
} while (0)

DQ_TC(validation);
ATF_TC_BODY(validation, tc)
{
	static const uint32_t excluded[] = { DQ_ROP_RENAME, DQ_ROP_LINK,
	    DQ_ROP_SOCKET, DQ_ROP_SOCKETPAIR, DQ_ROP_CONNECT, DQ_ROP_BIND,
	    DQ_ROP_INTERNAL };
	static const char *const unnormalized[] = { "", "relative", "/a/",
	    "//a", "/a//b", "/a/./b", "/a/../b", "/.", "/.." };
	static const int badnos[] = { 0, EAGAIN, EINTR, ENOTCAPABLE, EPIPE,
	    -1 };
	struct dq_standing_rule r;
	struct dqt_ctl c;
	struct dqt_object *o;
	cap_rights_t rights;
	char path[DQ_PATH_MAX + 1];
	uint64_t id, ids[DQ_STANDING_MAX];
	u_int i;
	int fd, dfd, ofd, q, rop;

	ATF_REQUIRE_EQ(1064, sizeof(struct dq_standing_rule));
	ATF_REQUIRE_EQ(32, __offsetof(struct dq_standing_rule, dqs_id));
	ATF_REQUIRE_EQ(320, sizeof(struct dq_stats2));
	q = dqt_open_queue();

	/* The rule itself: EINVAL. */
	rule_init(&r, "/a", OP(STAT));
	r.dqs_version++;
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", OP(STAT));
	r.dqs_flags = 0x4;
	ADD_REFUSED(q, &r, EINVAL);
	for (i = 0; i < 2; i++) {
		rule_init(&r, "/a", OP(STAT));
		r.dqs_action = i == 0 ? 0 : DQ_STANDING_ASK + 1;
		ADD_REFUSED(q, &r, EINVAL);
	}
	rule_init(&r, "/a", OP(STAT));
	r.dqs_pad0 = 1;
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", 0);
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", 1);			/* no operation 0 */
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", 1u << (DQ_ROP_MAX + 1));
	ADD_REFUSED(q, &r, EINVAL);
	for (i = 0; i < nitems(excluded); i++) {
		rule_init(&r, "/a", OP(STAT) |
		    DQ_STANDING_OP(excluded[i]));
		ADD_REFUSED(q, &r, EINVAL);
		ATF_CHECK((DQ_STANDING_OPS_ALL &
		    DQ_STANDING_OP(excluded[i])) == 0);
	}
	for (i = 0; i < nitems(unnormalized); i++) {
		rule_init(&r, unnormalized[i], OP(STAT));
		ADD_REFUSED(q, &r, EINVAL);
	}
	/*
	 * EXEC_INTERP only in an exact rule (review M1): the interpreter
	 * lookup is not consulted again at symbolic links.  Neither mask
	 * names it.
	 */
	rule_init(&r, "/a", OP(STAT) | OP(EXEC_INTERP));
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", OP(EXEC_INTERP));
	r.dqs_rootfd = 1000;
	ADD_REFUSED(q, &r, EINVAL);
	ATF_CHECK((DQ_STANDING_OPS_ALL & OP(EXEC_INTERP)) == 0);
	ATF_CHECK((DQ_STANDING_OPS_READ & OP(EXEC_INTERP)) == 0);
	ATF_CHECK((DQ_STANDING_OPS_READ & ~DQ_STANDING_OPS_ALL) == 0);
	/* Not NUL-terminated at dqs_pathlen; an inner NUL; too long. */
	rule_init(&r, "/abc", OP(STAT));
	r.dqs_pathlen = 2;
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/abc", OP(STAT));
	r.dqs_path[2] = '\0';
	ADD_REFUSED(q, &r, EINVAL);
	rule_init(&r, "/a", OP(STAT));
	r.dqs_pathlen = DQ_PATH_MAX;
	ADD_REFUSED(q, &r, EINVAL);
	memset(path, 'a', sizeof(path));
	path[0] = '/';
	path[DQ_PATH_MAX] = '\0';
	DQT_CHECK_REFUSED(dq_standing_add(q, -1, path, 0, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL), ENAMETOOLONG);
	DQT_CHECK_REFUSED(dq_standing_add(q, -1, NULL, 0, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL), EINVAL);
	/* The errno: only with ERRNO, from the allow-list, not EAGAIN... */
	for (i = 0; i < nitems(badnos); i++) {
		rule_init(&r, "/a", OP(STAT));
		r.dqs_action = DQ_STANDING_ERRNO;
		r.dqs_errno = badnos[i];
		ADD_REFUSED(q, &r, EINVAL);
	}
	rule_init(&r, "/a", OP(STAT));
	r.dqs_errno = EACCES;
	ADD_REFUSED(q, &r, EINVAL);
	r.dqs_action = DQ_STANDING_ASK;
	ADD_REFUSED(q, &r, EINVAL);
	/* EINVAL comes before the root is looked at. */
	rule_init(&r, "/a", 0);
	r.dqs_rootfd = 1000;
	ADD_REFUSED(q, &r, EINVAL);

	/* The root. */
	wd_init();
	mkdirs(at("vd"));
	mkfile(at("vf"));
	rule_init(&r, "/a", OP(STAT));
	r.dqs_rootfd = -2;
	ADD_REFUSED(q, &r, EBADF);
	r.dqs_rootfd = 1000;
	ADD_REFUSED(q, &r, EBADF);
	dfd = open(at("vd"), O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(dfd, &rights));
	r.dqs_rootfd = dfd;
	ADD_REFUSED(q, &r, ENOTCAPABLE);
	(void)close(dfd);
	fd = open(at("vf"), O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	r.dqs_rootfd = fd;
	ADD_REFUSED(q, &r, ENOTDIR);
	(void)close(fd);
	/* A served descriptor of another queue: no vnode. */
	ofd = dqt_make_oracle("vo", "x", 1, path, sizeof(path));
	dqt_init(&c);
	o = dqt_mint(&c, ofd, path, "x", 1, NULL);
	r.dqs_rootfd = o->fd;
	ADD_REFUSED(q, &r, EINVAL);
	dqt_fini(&c);
	(void)close(ofd);

	/* Each operation of DQ_STANDING_OPS_ALL alone, then all. */
	for (rop = 1; rop <= DQ_ROP_MAX; rop++) {
		if ((DQ_STANDING_OPS_ALL & DQ_STANDING_OP(rop)) == 0)
			continue;
		id = rule_ok(q, -1, "/ops", 0, DQ_STANDING_OP(rop),
		    DQ_STANDING_PASS, 0);
		ATF_CHECK_EQ(0, dq_standing_del(q, id));
	}
	id = rule_ok(q, -1, "/ops", DQ_STANDING_F_OPEN_WRITE,
	    DQ_STANDING_OPS_ALL, DQ_STANDING_ERRNO, ENOENT);
	ATF_CHECK_EQ(0, dq_standing_del(q, id));
	id = rule_ok(q, -1, "/ops", DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	ATF_CHECK_EQ(0, dq_standing_del(q, id));
	id = rule_ok(q, -1, "/ops", 0, DQ_STANDING_OPS_ALL | OP(EXEC_INTERP),
	    DQ_STANDING_PASS, 0);
	ATF_CHECK_EQ(0, dq_standing_del(q, id));

	/* EEXIST: same root and path, overlapping operations. */
	id = rule_ok(q, -1, "/e", 0, OP(STAT) | OP(OPEN), DQ_STANDING_PASS, 0);
	DQT_CHECK_REFUSED(dq_standing_add(q, -1, "/e", DQ_STANDING_F_SUBTREE,
	    OP(OPEN), DQ_STANDING_ASK, 0, NULL), EEXIST);
	(void)rule_ok(q, -1, "/e", 0, OP(ACCESS), DQ_STANDING_ASK, 0);
	dfd = open(at("vd"), O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	(void)rule_ok(q, dfd, "/e", 0, OP(STAT), DQ_STANDING_PASS, 0);
	(void)close(dfd);
	(void)rule_ok(q, -1, "/e/f", 0, OP(STAT), DQ_STANDING_PASS, 0);

	/* DEL: ESRCH for an unknown id, and for one deleted already. */
	DQT_CHECK_REFUSED(dq_standing_del(q, 0), ESRCH);
	DQT_CHECK_REFUSED(dq_standing_del(q, id + 1000), ESRCH);
	ATF_CHECK_EQ(0, dq_standing_del(q, id));
	DQT_CHECK_REFUSED(dq_standing_del(q, id), ESRCH);
	ATF_CHECK_EQ(0, dq_standing_flush(q));
	ATF_CHECK_EQ(0, dq_standing_flush(q));

	/* ENOSPC past DQ_STANDING_MAX; EEXIST comes first; ids distinct. */
	for (i = 0; i < DQ_STANDING_MAX; i++) {
		snprintf(path, sizeof(path), "/n%u", i);
		ids[i] = rule_ok(q, -1, path, 0, OP(STAT), DQ_STANDING_PASS, 0);
		ATF_CHECK(i == 0 || ids[i] > ids[i - 1]);
	}
	DQT_CHECK_REFUSED(dq_standing_add(q, -1, "/full", 0, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL), ENOSPC);
	DQT_CHECK_REFUSED(dq_standing_add(q, -1, "/n0", 0, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL), EEXIST);
	ATF_CHECK_EQ(0, dq_standing_del(q, ids[7]));
	(void)rule_ok(q, -1, "/full", 0, OP(STAT), DQ_STANDING_PASS, 0);
	ATF_CHECK_EQ(0, dq_standing_flush(q));
	(void)rule_ok(q, -1, "/n0", 0, OP(STAT), DQ_STANDING_PASS, 0);
	(void)close(q);
}

/*
 * ADD after the queue's death is ENXIO (review 2 N4): only a process that
 * shares the dead owner's descriptor table can still reach the queue
 * (dq_owner_test sharer_outlives_opener); an unpinned caller would get
 * EPERM first.
 */
struct death_arg {
	int		 go;		/* read: the opener is gone */
	int		 rep;		/* write: the sharer's results */
};

struct death_res {
	bool		 opened;
	struct dqt_rr	 r[3];
};

static void
c_opener_dies(void *arg, void *result)
{
	struct death_arg *a = arg;
	struct death_res *res = result;
	struct death_res sres;
	pid_t pid;
	int q;
	char b;

	q = dq_open();
	if (q == -1)
		_exit(6);
	if (dq_standing_add(q, -1, "/", DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL) != 0)
		_exit(7);
	res->opened = true;
	pid = rfork(RFPROC);
	if (pid == -1)
		_exit(8);
	if (pid != 0)
		return;
	/* The sharer: wait until the opener has been reaped. */
	memset(&sres, 0, sizeof(sres));
	if (read(a->go, &b, 1) != 1)
		_exit(9);
	DQT_RR(sres.r[0], dq_standing_add(q, -1, "/x", 0, OP(STAT),
	    DQ_STANDING_PASS, 0, NULL));
	DQT_RR(sres.r[1], dq_standing_del(q, 1));
	DQT_RR(sres.r[2], dq_standing_flush(q));
	(void)write(a->rep, &sres, sizeof(sres));
	_exit(0);
}

DQ_TC(add_after_death);
ATF_TC_BODY(add_after_death, tc)
{
	struct dqt_child ch;
	struct death_arg a;
	struct death_res opener, sharer;
	int go[2], rep[2], i;

	dqt_require_test_access();
	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(rep));
	a.go = go[0];
	a.rep = rep[1];
	memset(&opener, 0, sizeof(opener));
	dqt_spawn(&ch, c_opener_dies, &a);
	(void)close(go[0]);
	(void)close(rep[1]);
	dqt_collect(&ch, &opener, sizeof(opener));
	ATF_REQUIRE_MSG(opener.opened, "the opener has no queue");
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&sharer, 0, sizeof(sharer));
	ATF_REQUIRE_EQ((ssize_t)sizeof(sharer), (ssize_t)dqt_read_full(rep[0],
	    &sharer, sizeof(sharer)));
	for (i = 0; i < 3; i++)
		CHECK_RR(&sharer, i, ENXIO);
	(void)close(go[1]);
	(void)close(rep[0]);
}

/*
 * A /usr/share subtree STAT rule: the stat posts nothing, counts once in
 * ds2_standing_pass and returns what it returns unattached.
 */
DQ_TC(pass_no_event);
ATF_TC_BODY(pass_no_event, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, u;
	uint64_t pass, deny;

	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, "/usr/share", 0);
	step(&s, K_STAT, "/usr/share/misc", 0);
	run_steps(NULL, &s, &u);
	CHECK_RR(&u, 0, 0);
	dqt_init(&c);
	stats2(&c, &pass, &deny);
	ATF_CHECK_EQ(0, pass);
	ATF_CHECK_EQ(0, deny);
	(void)rule_ok(c.q, -1, "/usr/share", DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, u.r[1].err);
	dqt_check_stat_eq(&r.st[0], &u.st[0]);
	ATF_CHECK_EQ(0, nposted(&c, 0, "/usr/share"));
	ATF_CHECK_EQ(0, nposted(&c, 0, "/usr/share/misc"));
	stats2(&c, &pass, &deny);
	ATF_CHECK_EQ_MSG(2, pass, "ds2_standing_pass %ju", (uintmax_t)pass);
	ATF_CHECK_EQ(0, deny);
	dqt_fini(&c);
}

DQ_TC(exact_vs_subtree);
ATF_TC_BODY(exact_vs_subtree, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	uint64_t id;

	wd_init();
	mkdirs(at("sx"));
	mkdirs(at("sx/a"));
	mkfile(at("sx/a/f"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("sx/a"), 0);
	step(&s, K_STAT, at("sx/a/f"), 0);
	step(&s, K_STAT, at("sx"), 0);
	dqt_init(&c);
	id = rule_ok(c.q, -1, at("sx/a"), 0, OP(STAT), DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("sx/a")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("sx/a/f")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("sx")));
	ATF_CHECK_EQ(0, dq_standing_del(c.q, id));
	(void)rule_ok(c.q, -1, at("sx/a"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("sx/a")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("sx/a/f")));
	ATF_CHECK_EQ(2, nposted(&c, DQ_ROP_STAT, at("sx")));
	dqt_fini(&c);
}

DQ_TC(component_aligned);
ATF_TC_BODY(component_aligned, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;

	wd_init();
	mkdirs(at("ca"));
	mkdirs(at("ca/lib"));
	mkdirs(at("ca/lib32"));
	mkfile(at("ca/lib/x"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("ca/lib32"), 0);
	step(&s, K_STAT, at("ca/lib/x"), 0);
	step(&s, K_STAT, at("ca/lib"), 0);
	step(&s, K_STAT, at("ca/li"), 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("ca/lib"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	CHECK_RR(&r, 2, 0);
	CHECK_RR(&r, 3, ENOENT);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("ca/lib32")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("ca/lib/x")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("ca/lib")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("ca/li")));
	dqt_fini(&c);
}

/*
 * Empty components and "." are skipped and a trailing slash matches the
 * directory (the walk still applies it); any ".." posts.
 */
DQ_TC(dot_and_slashes);
ATF_TC_BODY(dot_and_slashes, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, u;
	char p[5][PATH_MAX];
	int i;

	wd_init();
	mkdirs(at("dt"));
	mkdirs(at("dt/x"));
	mkfile(at("dt/f"));
	snprintf(p[0], sizeof(p[0]), "%s//dt/./x", wd);
	snprintf(p[1], sizeof(p[1]), "%s/dt/x/", wd);
	snprintf(p[2], sizeof(p[2]), "%s/./dt/x/.", wd);
	snprintf(p[3], sizeof(p[3]), "%s/dt/f/", wd);	/* ENOTDIR */
	snprintf(p[4], sizeof(p[4]), "%s/dt/../dt/x", wd);
	memset(&s, 0, sizeof(s));
	for (i = 0; i < 5; i++)
		step(&s, K_STAT, p[i], 0);
	run_steps(NULL, &s, &u);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("dt"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	for (i = 0; i < 5; i++) {
		CHECK_RR(&r, i, u.r[i].err);
		ATF_CHECK_EQ_MSG(i == 4 ? 1 : 0, nposted(&c, DQ_ROP_STAT, p[i]),
		    "%s", p[i]);
	}
	CHECK_RR(&r, 3, ENOTDIR);
	dqt_fini(&c);
}

/*
 * OPEN covers read-class opens only (O_RDONLY without O_CREAT or
 * O_TRUNC; O_PATH and O_DIRECTORY read), unless the rule has
 * DQ_STANDING_F_OPEN_WRITE.
 */
DQ_TC(open_mode_class);
ATF_TC_BODY(open_mode_class, tc)
{
	static const int rd[] = { O_RDONLY, O_RDONLY | O_PATH,
	    O_RDONLY | O_CLOEXEC };
	static const int wr[] = { O_WRONLY, O_RDWR, O_RDONLY | O_CREAT,
	    O_RDONLY | O_TRUNC };
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	char p[PATH_MAX];
	u_int i;
	int n;

	wd_init();
	mkdirs(at("om"));
	mkdirs(at("omw"));
	memset(&s, 0, sizeof(s));
	for (i = 0; i < nitems(rd); i++) {
		snprintf(p, sizeof(p), "%s/om/r%u", wd, i);
		mkfile(p);
		step(&s, K_OPEN, p, rd[i]);
	}
	for (i = 0; i < nitems(wr); i++) {
		snprintf(p, sizeof(p), "%s/om/w%u", wd, i);
		mkfile(p);
		step(&s, K_OPEN, p, wr[i]);
	}
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("om"), DQ_STANDING_F_SUBTREE, OP(OPEN),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	for (i = 0; i < nitems(rd); i++) {
		snprintf(p, sizeof(p), "%s/om/r%u", wd, i);
		ATF_CHECK_MSG(r.r[i].rv >= 0, "%s: %d", p, r.r[i].err);
		ATF_CHECK_EQ_MSG(0, nposted(&c, DQ_ROP_OPEN, p), "%s", p);
	}
	for (i = 0; i < nitems(wr); i++) {
		snprintf(p, sizeof(p), "%s/om/w%u", wd, i);
		ATF_CHECK_EQ_MSG(1, nposted(&c, DQ_ROP_OPEN, p),
		    "%s (flags %#x)", p, wr[i]);
	}
	/* With DQ_STANDING_F_OPEN_WRITE: every class. */
	memset(&s, 0, sizeof(s));
	for (i = 0; i < nitems(wr); i++) {
		snprintf(p, sizeof(p), "%s/omw/w%u", wd, i);
		if ((wr[i] & O_CREAT) == 0)
			mkfile(p);
		step(&s, K_OPEN, p, wr[i]);
	}
	(void)rule_ok(c.q, -1, at("omw"), DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, OP(OPEN), DQ_STANDING_PASS, 0);
	n = nresolves(&c);
	run_steps(&c, &s, &r);
	for (i = 0; i < nitems(wr); i++)
		if ((wr[i] & O_TRUNC) == 0)
			CHECK_RR(&r, i, 0);
	ATF_CHECK_EQ(n, nresolves(&c));
	ATF_CHECK_EQ(0, access(at("omw/w2"), F_OK));	/* created */
	dqt_fini(&c);
}

DQ_TC(op_mask);
ATF_TC_BODY(op_mask, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;

	wd_init();
	mkdirs(at("opm"));
	mkfile(at("opm/f"));
	ATF_REQUIRE_EQ(0, symlink("f", at("opm/l")));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("opm/f"), 0);
	step(&s, K_ACCESS, at("opm/f"), 0);
	step(&s, K_READLINK, at("opm/l"), 0);
	step(&s, K_OPEN, at("opm/f"), O_RDONLY);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("opm"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	ATF_CHECK_EQ(1, r.r[2].rv);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("opm/f")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_ACCESS, at("opm/f")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_READLINK, at("opm/l")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_OPEN, at("opm/f")));
	dqt_fini(&c);
}

/*
 * The longest fitting path decides: "/" PASS with an ASK beneath it posts
 * what is under the ASK and covers the rest; an exact PASS under the ASK
 * covers its one name.
 */
DQ_TC(longest_wins_ask);
ATF_TC_BODY(longest_wins_ask, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	uint64_t pass, deny;

	wd_init();
	mkdirs(at("home"));
	mkfile(at("home/x"));
	mkfile(at("home/y"));
	mkfile(at("other"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("home/x"), 0);
	step(&s, K_STAT, "/etc", 0);
	step(&s, K_STAT, at("other"), 0);
	step(&s, K_STAT, at("home"), 0);
	step(&s, K_STAT, at("home/y"), 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	(void)rule_ok(c.q, -1, at("home"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_ASK, 0);
	(void)rule_ok(c.q, -1, at("home/y"), 0, OP(STAT), DQ_STANDING_PASS,
	    0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("home/x")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, "/etc"));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("other")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("home")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("home/y")));
	stats2(&c, &pass, &deny);
	ATF_CHECK_EQ_MSG(3, pass, "ds2_standing_pass %ju", (uintmax_t)pass);
	dqt_fini(&c);
}

/*
 * An errno rule answers as a reply of that errno does: before the walk,
 * so EACCES on a name that does not exist (not ENOENT), and an O_CREAT
 * that creates nothing.
 */
DQ_TC(deny_errno_order);
ATF_TC_BODY(deny_errno_order, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, want;
	uint64_t pass, deny;
	int i;

	wd_init();
	mkdirs(at("dn"));
	mkfile(at("dn/f"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("dn/missing"), 0);
	step(&s, K_OPEN, at("dn/new"), O_WRONLY | O_CREAT);
	step(&s, K_STAT, at("dn/f"), 0);
	step(&s, K_ACCESS, at("dn/f"), 0);
	dqt_init(&c);
	/* The controller's own EACCES: the oracle. */
	dqt_resolve_fail(&c, "/dn/", EACCES);
	run_steps(&c, &s, &want);
	dqt_resolve_fail(&c, "", 0);
	ATF_CHECK_EQ(4, nresolves(&c));
	(void)rule_ok(c.q, -1, at("dn"), DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, OP(STAT) | OP(OPEN) | OP(ACCESS),
	    DQ_STANDING_ERRNO, EACCES);
	run_steps(&c, &s, &r);
	for (i = 0; i < 4; i++) {
		CHECK_RR(&r, i, EACCES);
		CHECK_RR(&r, i, want.r[i].err);
	}
	ATF_CHECK_EQ(4, nresolves(&c));
	ATF_CHECK_EQ(-1, access(at("dn/new"), F_OK));
	stats2(&c, &pass, &deny);
	ATF_CHECK_EQ(0, pass);
	ATF_CHECK_EQ_MSG(4, deny, "ds2_standing_deny %ju", (uintmax_t)deny);
	dqt_fini(&c);
}

DQ_TC(dotdot_posts);
ATF_TC_BODY(dotdot_posts, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	char p[2][PATH_MAX];

	wd_init();
	mkdirs(at("dd"));
	mkfile(at("dd/x"));
	snprintf(p[0], sizeof(p[0]), "%s/dd/../dd/x", wd);
	snprintf(p[1], sizeof(p[1]), "%s/dd/x/..", wd);
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, p[0], 0);
	step(&s, K_STAT, p[1], 0);
	step(&s, K_STAT, at("dd/x"), 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, ENOTDIR);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, p[0]));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, p[1]));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("dd/x")));
	dqt_fini(&c);
}

/*
 * A covered name that is a symbolic link out of the rule's tree: the
 * re-consultation of the target is matched again, not covered, posted,
 * and the controller's EACCES is the answer.
 */
DQ_TC(symlink_out_asks);
ATF_TC_BODY(symlink_out_asks, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	int i;

	wd_init();
	mkdirs(at("so"));
	ATF_REQUIRE_EQ(0, symlink("/etc/master.passwd", at("so/l")));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("so/l"), 0);
	dqt_init(&c);
	dqt_resolve_fail(&c, "master.passwd", EACCES);
	(void)rule_ok(c.q, -1, at("so"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, EACCES);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("so/l")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, "/etc/master.passwd"));
	i = dqt_find_resolve(&c, "master.passwd", DQ_ROP_STAT, 0);
	ATF_REQUIRE(i != -1);
	dqt_resolve_at(&c, i, &rs);
	ATF_CHECK_EQ(DQ_START_REAL_ROOT, rs.start_kind);
	ATF_CHECK((rs.rflags & DQ_RF_SYMLINK_RESTART) != 0);
	dqt_fini(&c);
}

/*
 * The root qualifies every rule: after chroot(2) the old root's rules no
 * longer match (the old name posts), and a rule on the new root does.
 */
DQ_TC(chroot_root_qualifier);
ATF_TC_BODY(chroot_root_qualifier, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	int dfd;

	wd_init();
	mkdirs(at("cr"));
	mkfile(at("cr/f"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("cr/f"), 0);
	step(&s, K_CHROOT, at("cr"), 0);
	step(&s, K_STAT, "/f", 0);
	step(&s, K_STAT, at("cr/f"), 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("cr"), DQ_STANDING_F_SUBTREE, OP(STAT),
	    DQ_STANDING_PASS, 0);
	dfd = open(at("cr"), O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	(void)rule_ok(c.q, dfd, "/f", 0, OP(STAT), DQ_STANDING_PASS, 0);
	(void)close(dfd);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	CHECK_RR(&r, 2, 0);
	CHECK_RR(&r, 3, ENOENT);
	/* Before the chroot covered, after it posted (and absent). */
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("cr/f")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, "/f"));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_CHROOT, at("cr")));
	dqt_fini(&c);
}

/*
 * A jailed process: a rule on the jail's root covers its absolute names;
 * its relative names post, as everywhere (Q16).
 */
#define	JAIL_NAME	"dq_standing_jail"

struct jres {
	struct dqt_rr	 r[4];
};

static void
jail_child(int go, int rep)
{
	struct jres res;
	struct stat st;
	char b;

	memset(&res, 0, sizeof(res));
	/* Jailed: the parent attaches only now (an attached process cannot
	   enter a jail). */
	b = 'j';
	if (write(rep, &b, 1) != 1 || read(go, &b, 1) != 1)
		_exit(9);
	DQT_RR(res.r[0], stat("/f", &st));
	DQT_RR(res.r[1], stat("f", &st));
	DQT_RR(res.r[2], stat("/g", &st));
	(void)write(rep, &res, sizeof(res));
	_exit(0);
}

DQ_TC_CLEANUP(jail_root);
ATF_TC_BODY(jail_root, tc)
{
	struct dqt_ctl c;
	struct jres res;
	pid_t pid;
	int dfd, go[2], gofd, jid, pd, rep[2], repfd, status;
	char b;

	wd_init();
	mkdirs(at("jr"));
	mkfile(at("jr/f"));
	mkfile(at("jr/g"));
	jid = jail_setv(JAIL_CREATE, "path", at("jr"), "name", JAIL_NAME,
	    "persist", "true", NULL);
	ATF_REQUIRE_MSG(jid != -1, "jail_setv: %s", jail_errmsg);
	dqt_init(&c);
	dfd = open(at("jr"), O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd >= 0);
	(void)rule_ok(c.q, dfd, "/f", 0, OP(STAT), DQ_STANDING_PASS, 0);
	/* The same name under the global root is another rule. */
	(void)rule_ok(c.q, -1, "/g", 0, OP(STAT), DQ_STANDING_PASS, 0);
	(void)close(dfd);
	ATF_REQUIRE_EQ(0, pipe(go));
	ATF_REQUIRE_EQ(0, pipe(rep));
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		/*
		 * No directory descriptor inherited from the runner:
		 * jail_attach refuses a process holding one.
		 */
		gofd = fcntl(go[0], F_DUPFD, 100);
		repfd = fcntl(rep[1], F_DUPFD, 100);
		if (gofd == -1 || repfd == -1 || dup2(gofd, 3) == -1 ||
		    dup2(repfd, 4) == -1)
			_exit(6);
		closefrom(5);
		if (jail_attach(jid) != 0)
			_exit(5);
		jail_child(3, 4);
	}
	(void)close(go[0]);
	(void)close(rep[1]);
	ATF_REQUIRE_EQ_MSG(1, read(rep[0], &b, 1), "the child did not enter "
	    "the jail");
	ATF_REQUIRE_MSG(dq_attach(c.q, pd) == 0, "attach: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(1, write(go[1], "g", 1));
	memset(&res, 0, sizeof(res));
	(void)close(go[1]);
	go[1] = -1;
	(void)dqt_read_full(rep[0], &res, sizeof(res));
	ATF_REQUIRE_EQ(0, pdwait(pd, &status, WEXITED, NULL, NULL));
	dqt_require_exit0(status, "jailed child");
	CHECK_RR(&res, 0, 0);
	CHECK_RR(&res, 1, 0);
	CHECK_RR(&res, 2, 0);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, "/f"));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, "f"));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, "/g"));
	(void)close(rep[0]);
	(void)close(pd);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(jail_root, tc)
{
	int jid;

	jid = jail_getid(JAIL_NAME);
	if (jid != -1)
		(void)jail_remove(jid);
}

/*
 * Served starts and served roots are never decided by a rule: a "/" PASS
 * of every operation still posts them.  The same process's real absolute
 * names are covered.
 */
struct served_arg {
	int		 sroot;
};

static void
c_served_start(void *arg, void *out)
{
	struct served_arg *a = arg;
	struct jres *r = out;
	struct stat st;

	DQT_RR(r->r[0], fstatat(a->sroot, "a", &st, 0));
	DQT_RR(r->r[1], stat("/etc", &st));
}

static void
c_served_root(void *arg __unused, void *out)
{
	struct jres *r = out;
	struct stat st;

	DQT_RR(r->r[0], stat("/a", &st));
}

static int
tree_count(struct dqt_tree *s, uint32_t op, const char *path)
{
	int i, n;

	n = 0;
	pthread_mutex_lock(&s->mtx);
	for (i = 0; i < s->nev; i++)
		if (s->ev[i].op == op && strcmp(s->ev[i].path, path) == 0)
			n++;
	pthread_mutex_unlock(&s->mtx);
	return (n);
}

DQ_TC(served_start_posts);
ATF_TC_BODY(served_start_posts, tc)
{
	struct dqt_tree s;
	struct served_arg a;
	struct jres r;
	struct dq_stats2 st;
	int status;

	dqt_tree_make("t");
	dqt_tree_start(&s, "t", 0);
	(void)rule_ok(s.q, -1, "/", DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	a.sroot = s.sroot;
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child_ex(&s, -1, -1, true, false, c_served_start,
	    &a, &r, sizeof(r));
	dqt_require_exit0(status, "child");
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, 0);
	ATF_CHECK_EQ(1, tree_count(&s, DQ_ROP_STAT, "a"));
	ATF_CHECK_EQ(0, tree_count(&s, DQ_ROP_STAT, "/etc"));
	ATF_REQUIRE_EQ(0, dq_get_stats2(s.q, &st));
	ATF_CHECK(st.ds2_standing_pass >= 1);
	dqt_tree_stop(&s);
}

DQ_TC(served_root_posts);
ATF_TC_BODY(served_root_posts, tc)
{
	struct dqt_tree s;
	struct jres r;
	int status;

	dqt_tree_make("t");
	dqt_tree_start(&s, "t", DQ_TREE_F_ROOT);
	(void)rule_ok(s.q, -1, "/", DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	memset(&r, 0, sizeof(r));
	status = dqt_tree_child(&s, s.sroot, s.sroot, c_served_root, NULL, &r,
	    sizeof(r));
	dqt_require_exit0(status, "child");
	CHECK_RR(&r, 0, 0);
	ATF_CHECK_EQ(1, tree_count(&s, DQ_ROP_STAT, "/a"));
	dqt_tree_stop(&s);
}

/*
 * The Linux ABI (dq_standing_linux, a freestanding Linux program): under
 * an ABI root (compat.linux.emul_path names a directory) no rule decides,
 * a "/" PASS rule notwithstanding; without one the program's lookups are
 * native ones, and only RINROOT (openat2 RESOLVE_IN_ROOT, whose
 * "absolute" name is relative to its descriptor) still posts.
 */
#define	LINUX_FD	9

static void
c_linux(void *arg, void *out)
{
	const char *dir = arg;
	struct jres *r = out;
	char *const argv[] = { __DECONST(char *, "dq_standing_linux"), NULL };
	char *const envp[] = { NULL };
	pid_t pid;
	int fd, status;

	fd = open(dir, O_RDONLY | O_DIRECTORY);
	DQT_RR(r->r[0], fd);
	if (fd < 0)
		return;
	pid = fork();
	if (pid == 0) {
		if (dup2(fd, LINUX_FD) != LINUX_FD)
			_exit(126);
		execve("./dq_standing_linux", argv, envp);
		_exit(127);
	}
	r->r[1].rv = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
	(void)close(fd);
}

static void
linux_setup(const atf_tc_t *tc, struct dqt_ctl *c, const char *emul)
{

	dqt_copy_helper(tc, "dq_standing_linux", "dq_standing_linux");
	wd_init();
	mkdirs(at("lx"));
	mkfile(at("lx/rin-f"));
	dqt_sysctl_save("compat.linux.emul_path");
	ATF_REQUIRE_MSG(sysctlbyname("compat.linux.emul_path", NULL, NULL,
	    emul, strlen(emul) + 1) == 0, "compat.linux.emul_path: %s",
	    strerror(errno));
	dqt_init(c);
	(void)rule_ok(c->q, -1, "/", DQ_STANDING_F_SUBTREE,
	    DQ_STANDING_OPS_READ, DQ_STANDING_PASS, 0);
}

static int
nposted_rflag(struct dqt_ctl *c, uint32_t op, const char *path,
    uint32_t rflag)
{
	int i, n;

	n = 0;
	dqt_lock(c);
	for (i = 0; i < c->nrs; i++)
		if (c->rs[i].op == op && strcmp(c->rs[i].path, path) == 0 &&
		    (c->rs[i].rflags & rflag) == rflag)
			n++;
	dqt_unlock(c);
	return (n);
}

ATF_TC_WITH_CLEANUP(rinroot_posts);
ATF_TC_HEAD(rinroot_posts, tc)
{
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "linux64");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(rinroot_posts, tc)
{
	struct dqt_ctl c;
	struct jres r;

	linux_setup(tc, &c, "/nonexistent-dq-standing");
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_linux, __DECONST(char *, at("lx")), &r,
	    sizeof(r));
	CHECK_RR(&r, 0, 0);
	ATF_CHECK_EQ_MSG(0, r.r[1].rv, "dq_standing_linux: status %ld",
	    r.r[1].rv);
	/* A native-like Linux process: its absolute stat is covered... */
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, "/etc"));
	/* ...and its RINROOT open, matching "/" by text, posts. */
	ATF_CHECK_EQ(1, nposted_rflag(&c, DQ_ROP_OPEN, "/rin-f",
	    DQ_RF_RINROOT));
	dqt_fini(&c);
}
ATF_TC_CLEANUP(rinroot_posts, tc)
{

	(void)dqt_sysctl_restore("compat.linux.emul_path");
}

ATF_TC_WITH_CLEANUP(linux_abi_posts);
ATF_TC_HEAD(linux_abi_posts, tc)
{
	atf_tc_set_md_var(tc, "require.arch", "amd64");
	atf_tc_set_md_var(tc, "require.kmods", "linux64");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(linux_abi_posts, tc)
{
	struct dqt_ctl c;
	struct jres r;
	char emul[PATH_MAX];

	ATF_REQUIRE(realpath(".", emul) != NULL);
	strlcat(emul, "/emul", sizeof(emul));
	ATF_REQUIRE_EQ(0, mkdir(emul, 0755));
	linux_setup(tc, &c, emul);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_linux, __DECONST(char *, at("lx")), &r,
	    sizeof(r));
	CHECK_RR(&r, 0, 0);
	ATF_CHECK_EQ_MSG(0, r.r[1].rv, "dq_standing_linux: status %ld",
	    r.r[1].rv);
	ATF_CHECK(nposted(&c, DQ_ROP_STAT, "/etc") >= 1);
	ATF_CHECK(nposted_rflag(&c, DQ_ROP_OPEN, "/rin-f",
	    DQ_RF_RINROOT) >= 1);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(linux_abi_posts, tc)
{

	(void)dqt_sysctl_restore("compat.linux.emul_path");
}

/*
 * An exact EXEC_INTERP rule for the run-time linker: a dynamic image's
 * interpreter lookup (class 3) posts nothing; without the rule it posts.
 */
static void
c_exec(void *arg __unused, void *out)
{
	struct jres *r = out;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		execl("/bin/test", "test", "-d", "/", (char *)NULL);
		_exit(127);
	}
	r->r[0].rv = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
}

DQ_TC(exec_interp_exact);
ATF_TC_BODY(exec_interp_exact, tc)
{
	struct dqt_ctl c;
	struct jres r;
	uint64_t pass, deny;
	int n;

	dqt_init(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_exec, NULL, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.r[0].rv);
	n = nposted(&c, DQ_ROP_EXEC_INTERP, "/libexec/ld-elf.so.1");
	ATF_REQUIRE_EQ_MSG(1, n, "%d interpreter events unattached", n);
	(void)rule_ok(c.q, -1, "/libexec/ld-elf.so.1", 0, OP(EXEC_INTERP),
	    DQ_STANDING_PASS, 0);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_exec, NULL, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.r[0].rv);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_EXEC_INTERP,
	    "/libexec/ld-elf.so.1"));
	ATF_CHECK_EQ(2, nposted(&c, DQ_ROP_EXEC, "/bin/test"));
	stats2(&c, &pass, &deny);
	ATF_CHECK_EQ(1, pass);
	dqt_fini(&c);
}

/*
 * Review M1: the interpreter lookup (class 3) is not consulted again at
 * symbolic links (dqres_namei_symlink), so a subtree rule naming
 * EXEC_INTERP would pass a link out of its tree.  A #! script in a tree
 * whose interpreter is a link out of it: under a subtree rule of every
 * operation a subtree may name the script's exec posts nothing, its
 * interpreter lookup still posts and its answer decides the exec; a
 * subtree rule naming EXEC_INTERP is EINVAL and changes nothing.
 */
#define	INTERP_ENOENT	66

static void
c_exec_script(void *arg, void *out)
{
	const char *path = arg;
	struct jres *r = out;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		execl(path, path, (char *)NULL);
		_exit(errno == ENOENT ? INTERP_ENOENT : 127);
	}
	r->r[0].rv = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
}

DQ_TC(exec_interp_subtree_link);
ATF_TC_BODY(exec_interp_subtree_link, tc)
{
	struct dqt_ctl c;
	struct jres r;
	char script[PATH_MAX], interp[PATH_MAX];
	int fd;

	wd_init();
	mkdirs(at("il"));
	strlcpy(interp, at("il/l"), sizeof(interp));
	strlcpy(script, at("il/s"), sizeof(script));
	ATF_REQUIRE_EQ(0, symlink("/bin/sh", interp));
	fd = open(script, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(dprintf(fd, "#!%s\nexit 0\n", interp) > 0);
	(void)close(fd);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("il"), DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_exec_script, script, &r, sizeof(r));
	ATF_CHECK_EQ(0, r.r[0].rv);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_EXEC, script));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_EXEC_INTERP, interp));
	/* The controller's answer to the interpreter decides the exec. */
	dqt_resolve_fail(&c, "il/l", ENOENT);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_exec_script, script, &r, sizeof(r));
	ATF_CHECK_EQ(INTERP_ENOENT, r.r[0].rv);
	ATF_CHECK_EQ(2, nposted(&c, DQ_ROP_EXEC_INTERP, interp));
	/* A subtree rule naming EXEC_INTERP is refused, not installed. */
	ATF_REQUIRE_EQ(0, dq_standing_flush(c.q));
	DQT_CHECK_REFUSED(dq_standing_add(c.q, -1, at("il"),
	    DQ_STANDING_F_SUBTREE, OP(EXEC) | OP(EXEC_INTERP),
	    DQ_STANDING_PASS, 0, NULL), EINVAL);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_exec_script, script, &r, sizeof(r));
	ATF_CHECK_EQ(INTERP_ENOENT, r.r[0].rv);
	ATF_CHECK_EQ(3, nposted(&c, DQ_ROP_EXEC_INTERP, interp));
	dqt_fini(&c);
}

/*
 * Rules apply to the attached process's descendants, across fork and
 * exec: test(1) in a grandchild stats a covered name with no event.
 */
static void
c_fork_exec(void *arg, void *out)
{
	const char *path = arg;
	struct jres *r = out;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		execl("/bin/test", "test", "-f", path, (char *)NULL);
		_exit(127);
	}
	r->r[0].rv = pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) ? -1 : WEXITSTATUS(status);
}

DQ_TC(fork_exec_inherit);
ATF_TC_BODY(fork_exec_inherit, tc)
{
	struct dqt_ctl c;
	struct jres r;
	uint64_t pass, deny;

	wd_init();
	mkdirs(at("fe"));
	mkfile(at("fe/f"));
	dqt_init(&c);
	(void)rule_ok(c.q, -1, at("fe"), DQ_STANDING_F_SUBTREE, OP(STAT) |
	    OP(ACCESS), DQ_STANDING_PASS, 0);
	memset(&r, 0, sizeof(r));
	dqt_attach_run(&c, c_fork_exec, __DECONST(char *, at("fe/f")), &r,
	    sizeof(r));
	ATF_CHECK_EQ(0, r.r[0].rv);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_EXEC, "/bin/test"));
	ATF_CHECK_EQ(0, nposted(&c, 0, at("fe/f")));
	stats2(&c, &pass, &deny);
	ATF_CHECK(pass >= 1);
	dqt_fini(&c);
}

/*
 * The controller's death ends its rules: a covered lookup afterwards fails
 * closed with EIO, as every lookup of an attached process does.
 */
struct death_sync {
	struct dqt_sync	 sy;
	char		 path[PATH_MAX];
};

static void
c_covered_twice(void *arg, void *out)
{
	struct death_sync *d = arg;
	struct jres *r = out;
	struct stat st;

	DQT_RR(r->r[0], stat(d->path, &st));
	dqt_sync_post(d->sy.toparent[1]);
	if (!dqt_sync_wait(d->sy.tochild[0], 30000))
		_exit(8);
	DQT_RR(r->r[1], stat(d->path, &st));
}

DQ_TC(controller_death_fails_closed);
ATF_TC_BODY(controller_death_fails_closed, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct death_sync d;
	struct jres r;

	wd_init();
	mkfile(at("cd"));
	strlcpy(d.path, at("cd"), sizeof(d.path));
	dqt_sync_init(&d.sy);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, d.path, 0, OP(STAT), DQ_STANDING_PASS, 0);
	dqt_attach_spawn(&c, &ch, c_covered_twice, &d);
	ATF_REQUIRE(dqt_sync_wait(d.sy.toparent[0], 30000));
	dqt_close_queue(&c);
	dqt_sync_post(d.sy.tochild[1]);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, EIO);
	dqt_fini(&c);
}

/* A deleted rule decides nothing: the next lookup posts. */
DQ_TC(del_then_posts);
ATF_TC_BODY(del_then_posts, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	uint64_t id;

	wd_init();
	mkfile(at("dp"));
	memset(&s, 0, sizeof(s));
	step(&s, K_STAT, at("dp"), 0);
	dqt_init(&c);
	id = rule_ok(c.q, -1, at("dp"), 0, OP(STAT), DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("dp")));
	ATF_REQUIRE_EQ(0, dq_standing_del(c.q, id));
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, at("dp")));
	(void)rule_ok(c.q, -1, at("dp"), 0, OP(STAT), DQ_STANDING_PASS, 0);
	ATF_REQUIRE_EQ(0, dq_standing_flush(c.q));
	run_steps(&c, &s, &r);
	ATF_CHECK_EQ(2, nposted(&c, DQ_ROP_STAT, at("dp")));
	dqt_fini(&c);
}

/*
 * Eight threads stat a name while the controller adds the rule covering it
 * and removes it again 10000 times, by DEL or by FLUSH: no panic or
 * lock-order report, every lookup either covered or posted, never both or
 * neither, and none fails.
 */
#define	STRESS_THREADS	8
#define	STRESS_LOOKUPS	1500
#define	STRESS_CHANGES	10000

struct stress {
	char		 path[PATH_MAX];
	int		 fails;
};

static void *
stress_thread(void *arg)
{
	struct stress *s = arg;
	struct stat st;
	int i;

	for (i = 0; i < STRESS_LOOKUPS; i++)
		if (stat(s->path, &st) != 0)
			__atomic_add_fetch(&s->fails, 1, __ATOMIC_RELAXED);
	return (NULL);
}

static void
c_stress(void *arg, void *out)
{
	struct stress *s = arg;
	struct jres *r = out;
	pthread_t thr[STRESS_THREADS];
	int i;

	for (i = 0; i < STRESS_THREADS; i++)
		if (pthread_create(&thr[i], NULL, stress_thread, s) != 0)
			_exit(7);
	for (i = 0; i < STRESS_THREADS; i++)
		(void)pthread_join(thr[i], NULL);
	r->r[0].rv = s->fails;
}

static void
stress_changes(bool flush)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct stress s;
	struct jres r;
	struct dq_stats2 st;
	uint64_t id;
	int i;

	wd_init();
	mkfile(at("st"));
	memset(&s, 0, sizeof(s));
	strlcpy(s.path, at("st"), sizeof(s.path));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, c_stress, &s);
	for (i = 0; i < STRESS_CHANGES; i++) {
		id = rule_ok(c.q, -1, s.path, 0, OP(STAT), DQ_STANDING_PASS, 0);
		if (flush)
			ATF_REQUIRE_EQ(0, dq_standing_flush(c.q));
		else
			ATF_REQUIRE_EQ(0, dq_standing_del(c.q, id));
	}
	/* Some lookups also run while the rule stays. */
	(void)rule_ok(c.q, -1, s.path, 0, OP(STAT), DQ_STANDING_PASS, 0);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ_MSG(0, r.r[0].rv, "%ld lookups failed", r.r[0].rv);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ_MSG((uint64_t)STRESS_THREADS * STRESS_LOOKUPS,
	    st.ds2_standing_pass + st.ds2_resolves, "standing pass %ju + "
	    "resolves %ju", (uintmax_t)st.ds2_standing_pass,
	    (uintmax_t)st.ds2_resolves);
	ATF_CHECK_EQ(0, st.ds2_resolve_failclosed);
	printf("standing pass %ju, posted %ju\n",
	    (uintmax_t)st.ds2_standing_pass, (uintmax_t)st.ds2_resolves);
	dqt_fini(&c);
}

ATF_TC(stress_change_while_lookups);
ATF_TC_HEAD(stress_change_while_lookups, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(stress_change_while_lookups, tc)
{

	stress_changes(false);
}

ATF_TC(stress_flush_while_lookups);
ATF_TC_HEAD(stress_flush_while_lookups, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "900");
}
ATF_TC_BODY(stress_flush_while_lookups, tc)
{

	stress_changes(true);
}

/*
 * The controller closes its queue while eight threads stat a covered name
 * (review L1), once each thread has reported its first successful stat:
 * each lookup returns 0 or EIO, a thread never succeeds after its first
 * EIO, nothing failed closed before the close, and every thread meets the
 * close.  STRESS_DEADLINE only stops a thread that never sees the close.
 */
#define	STRESS_EIO	20
#define	STRESS_DEADLINE	120	/* s */

struct stress_close {
	char		 path[PATH_MAX];
	struct dqt_sync	 sy;
	long		 ok, eio, other, ok_after_eio, threads_eio;
};

struct stress_close_res {
	long		 ok, eio, other, ok_after_eio, threads_eio;
};

static void *
stress_close_thread(void *arg)
{
	struct stress_close *s = arg;
	struct timespec now, end;
	struct stat st;
	bool posted;
	int eio;

	(void)clock_gettime(CLOCK_MONOTONIC, &end);
	end.tv_sec += STRESS_DEADLINE;
	posted = false;
	for (eio = 0; eio < STRESS_EIO;) {
		if (stat(s->path, &st) == 0) {
			__atomic_add_fetch(&s->ok, 1, __ATOMIC_RELAXED);
			/* The parent closes once every thread got one. */
			if (!posted) {
				dqt_sync_post(s->sy.toparent[1]);
				posted = true;
			}
			if (eio > 0)
				__atomic_add_fetch(&s->ok_after_eio, 1,
				    __ATOMIC_RELAXED);
		} else if (errno == EIO) {
			eio++;
			__atomic_add_fetch(&s->eio, 1, __ATOMIC_RELAXED);
		} else
			__atomic_add_fetch(&s->other, 1, __ATOMIC_RELAXED);
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec >= end.tv_sec)
			break;
	}
	if (eio > 0)
		__atomic_add_fetch(&s->threads_eio, 1, __ATOMIC_RELAXED);
	return (NULL);
}

static void
c_stress_close(void *arg, void *out)
{
	struct stress_close *s = arg;
	struct stress_close_res *r = out;
	pthread_t thr[STRESS_THREADS];
	int i;

	for (i = 0; i < STRESS_THREADS; i++)
		if (pthread_create(&thr[i], NULL, stress_close_thread, s) != 0)
			_exit(7);
	for (i = 0; i < STRESS_THREADS; i++)
		(void)pthread_join(thr[i], NULL);
	r->ok = s->ok;
	r->eio = s->eio;
	r->other = s->other;
	r->ok_after_eio = s->ok_after_eio;
	r->threads_eio = s->threads_eio;
}

ATF_TC(stress_close_while_lookups);
ATF_TC_HEAD(stress_close_while_lookups, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "600");
}
ATF_TC_BODY(stress_close_while_lookups, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct stress_close s;
	struct stress_close_res r;
	struct dq_stats2 st;
	int i;

	wd_init();
	mkfile(at("sc"));
	memset(&s, 0, sizeof(s));
	strlcpy(s.path, at("sc"), sizeof(s.path));
	dqt_sync_init(&s.sy);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, s.path, 0, OP(STAT), DQ_STANDING_PASS, 0);
	dqt_attach_spawn(&c, &ch, c_stress_close, &s);
	/* Every thread has had a covered stat succeed. */
	for (i = 0; i < STRESS_THREADS; i++)
		ATF_REQUIRE_MSG(dqt_sync_wait(s.sy.toparent[0], 30000),
		    "%d of %d threads reported a covered stat", i,
		    STRESS_THREADS);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_resolve_failclosed);
	ATF_CHECK(st.ds2_standing_pass >= STRESS_THREADS);
	dqt_close_queue(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	printf("ok %ld, EIO %ld, other %ld, ok after EIO %ld, threads that "
	    "met the close %ld\n", r.ok, r.eio, r.other, r.ok_after_eio,
	    r.threads_eio);
	ATF_CHECK_EQ(0, r.other);
	ATF_CHECK_EQ(0, r.ok_after_eio);
	ATF_CHECK(r.ok > 0);
	ATF_CHECK_EQ(STRESS_THREADS, r.threads_eio);
	dqt_fini(&c);
}

/*
 * Absolute names only (dq-standing-decisions Q16, §4.9): a relative start
 * (the working directory, a directory descriptor, a relative symbolic
 * link's directory) always posts, a "/" rule notwithstanding.
 */
DQ_TC(relative_starts_post);
ATF_TC_BODY(relative_starts_post, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct steps s;
	struct sres r;
	int i, k, n;

	wd_init();
	mkdirs(at("rs"));
	mkfile(at("rs/f"));
	ATF_REQUIRE_EQ(0, symlink("f", at("rs/l")));
	memset(&s, 0, sizeof(s));
	step(&s, K_CHDIR, at("rs"), 0);
	step(&s, K_STAT, "f", 0);
	step(&s, K_DIRFD, at("rs"), 0);
	step(&s, K_STATAT, "f", 0);
	step(&s, K_STAT, at("rs/l"), 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE,
	    DQ_STANDING_OPS_READ, DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	for (k = 0; k < s.n; k++)
		ATF_CHECK_MSG(r.r[k].rv >= 0, "step %d: %d", k, r.r[k].err);
	/* The absolute ones are covered. */
	ATF_CHECK_EQ(0, nposted(&c, 0, at("rs")));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_STAT, at("rs/l")));
	/* "f" from the cwd, from the descriptor, and as the link target. */
	ATF_CHECK_EQ(3, nposted(&c, DQ_ROP_STAT, "f"));
	n = 0;
	for (i = dqt_find_resolve(&c, "f", DQ_ROP_STAT, 0); i != -1;
	    i = dqt_find_resolve(&c, "f", DQ_ROP_STAT, i + 1)) {
		dqt_resolve_at(&c, i, &rs);
		if (strcmp(rs.path, "f") != 0)
			continue;
		n |= rs.start_kind == DQ_START_REAL_CWD ? 1 :
		    rs.start_kind == DQ_START_REAL_DIRFD ? 2 :
		    rs.start_kind == DQ_START_REAL_SYMDIR ? 4 : 8;
	}
	ATF_CHECK_EQ_MSG(7, n, "start kinds seen %#x", n);
	dqt_fini(&c);
}

/*
 * A rule never relaxes the walk (review 1 L8).  Under absolute-only every
 * one of these lookups is relative, so each also posts (review 2 N2); the
 * results equal the unattached ones whatever decides.
 */
DQ_TC(never_relaxes_beneath);
ATF_TC_BODY(never_relaxes_beneath, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, u;
	char lnk[PATH_MAX];

	wd_init();
	mkdirs(at("nb"));
	mkfile(at("outside"));
	snprintf(lnk, sizeof(lnk), "%s/nb/esc", wd);
	ATF_REQUIRE_EQ(0, symlink("../outside", lnk));
	memset(&s, 0, sizeof(s));
	step(&s, K_DIRFD, at("nb"), 0);
	step(&s, K_OPENAT, "esc", O_RDONLY | O_RESOLVE_BENEATH);
	step(&s, K_OPEN, lnk, O_RDONLY | O_RESOLVE_BENEATH);
	run_steps(NULL, &s, &u);
	CHECK_RR(&u, 1, ENOTCAPABLE);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	CHECK_RR(&r, 1, ENOTCAPABLE);
	CHECK_RR(&r, 2, u.r[2].err);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_OPEN, "esc"));
	/* An absolute name under O_RESOLVE_BENEATH is refused unposted. */
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_OPEN, lnk));
	dqt_fini(&c);
}

DQ_TC(never_relaxes_capmode);
ATF_TC_BODY(never_relaxes_capmode, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, u;
	int k;

	wd_init();
	mkdirs(at("nc"));
	mkfile(at("outside"));
	mkfile(at("nc/in"));
	ATF_REQUIRE_EQ(0, symlink("../outside", at("nc/esc")));
	memset(&s, 0, sizeof(s));
	step(&s, K_DIRFD, at("nc"), 0);
	step(&s, K_CAPENTER, "", 0);
	step(&s, K_OPENAT, "esc", O_RDONLY);
	step(&s, K_OPENAT, "in", O_RDONLY);
	step(&s, K_OPENAT, "/etc/passwd", O_RDONLY);
	run_steps(NULL, &s, &u);
	CHECK_RR(&u, 2, ENOTCAPABLE);
	CHECK_RR(&u, 3, 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE |
	    DQ_STANDING_F_OPEN_WRITE, DQ_STANDING_OPS_ALL, DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	for (k = 0; k < s.n; k++)
		CHECK_RR(&r, k, u.r[k].err);
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_OPEN, "esc"));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_OPEN, "in"));
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_OPEN, "/etc/passwd"));
	dqt_fini(&c);
}

/* fstatat(fd, "", AT_EMPTY_PATH): the attributes it gives unattached. */
DQ_TC(emptypath_same);
ATF_TC_BODY(emptypath_same, tc)
{
	struct dqt_ctl c;
	struct steps s;
	struct sres r, u;

	wd_init();
	mkdirs(at("ep"));
	mkfile(at("ep/f"));
	memset(&s, 0, sizeof(s));
	step(&s, K_EMPTYSTAT, at("ep/f"), 0);
	run_steps(NULL, &s, &u);
	CHECK_RR(&u, 0, 0);
	dqt_init(&c);
	(void)rule_ok(c.q, -1, "/", DQ_STANDING_F_SUBTREE,
	    DQ_STANDING_OPS_READ, DQ_STANDING_PASS, 0);
	run_steps(&c, &s, &r);
	CHECK_RR(&r, 0, 0);
	dqt_check_stat_eq(&r.st[0], &u.st[0]);
	/* The open is covered; the empty path's dirfd start posts. */
	ATF_CHECK_EQ(0, nposted(&c, DQ_ROP_OPEN, at("ep/f")));
	ATF_CHECK_EQ(1, nposted(&c, DQ_ROP_STAT, ""));
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, add_after_death);
	ATF_TP_ADD_TC(tp, pass_no_event);
	ATF_TP_ADD_TC(tp, exact_vs_subtree);
	ATF_TP_ADD_TC(tp, component_aligned);
	ATF_TP_ADD_TC(tp, dot_and_slashes);
	ATF_TP_ADD_TC(tp, open_mode_class);
	ATF_TP_ADD_TC(tp, op_mask);
	ATF_TP_ADD_TC(tp, longest_wins_ask);
	ATF_TP_ADD_TC(tp, deny_errno_order);
	ATF_TP_ADD_TC(tp, dotdot_posts);
	ATF_TP_ADD_TC(tp, symlink_out_asks);
	ATF_TP_ADD_TC(tp, chroot_root_qualifier);
	ATF_TP_ADD_TC(tp, jail_root);
	ATF_TP_ADD_TC(tp, served_start_posts);
	ATF_TP_ADD_TC(tp, served_root_posts);
	ATF_TP_ADD_TC(tp, rinroot_posts);
	ATF_TP_ADD_TC(tp, linux_abi_posts);
	ATF_TP_ADD_TC(tp, exec_interp_exact);
	ATF_TP_ADD_TC(tp, exec_interp_subtree_link);
	ATF_TP_ADD_TC(tp, fork_exec_inherit);
	ATF_TP_ADD_TC(tp, controller_death_fails_closed);
	ATF_TP_ADD_TC(tp, del_then_posts);
	ATF_TP_ADD_TC(tp, stress_change_while_lookups);
	ATF_TP_ADD_TC(tp, stress_flush_while_lookups);
	ATF_TP_ADD_TC(tp, stress_close_while_lookups);
	ATF_TP_ADD_TC(tp, relative_starts_post);
	ATF_TP_ADD_TC(tp, never_relaxes_beneath);
	ATF_TP_ADD_TC(tp, never_relaxes_capmode);
	ATF_TP_ADD_TC(tp, emptypath_same);
	return (atf_no_error());
}
