/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Refusals: every MINT reason, the policy set outside stage 1a, reply and
 * control ioctl errors, a non-root open, and the module refusing to unload.
 * Expected values follow dq_ident_validate, dq_policy_validate,
 * dq_queue_reply and dq_dev.c.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dq_test.h"

#define	DATA_LEN	8192
#define	NOBODY_UID	65534

static unsigned char data[DATA_LEN];
static char oracle_path[DQT_PATH_MAX];

struct fixture {
	struct dqt_ctl	 c;
	struct dq_ident_file ident;	/* a valid identity to mutate */
	struct dq_policy pol;
	int		 oracle;
};

static void
setup(struct fixture *f, unsigned seed)
{
	struct statfs sfs;
	struct stat st;

	dqt_fill(data, sizeof(data), seed);
	f->oracle = dqt_make_oracle("oracle", data, sizeof(data), oracle_path,
	    sizeof(oracle_path));
	dqt_init(&f->c);
	dqt_ident_of(f->oracle, oracle_path, &f->ident, &st, &sfs);
	dq_policy_default(&f->pol);
}

/* A mint that must fail with EINVAL and this reason. */
static void
expect_reason(struct fixture *f, const struct dq_ident_file *ident,
    const struct dq_policy *pol, int want, const char *what)
{
	uint64_t object;
	int fd, reason;

	reason = -1;
	errno = 0;
	fd = -1;
	ATF_CHECK_EQ_MSG(-1, dq_mint_file(f->c.q, ident, pol, &object, &fd,
	    &reason), "%s: mint succeeded", what);
	ATF_CHECK_EQ_MSG(EINVAL, errno, "%s: errno %d", what, errno);
	ATF_CHECK_EQ_MSG(want, reason, "%s: reason %d want %d", what, reason,
	    want);
	if (fd != -1)
		(void)close(fd);
}

ATF_TC(mint_reasons_identity);
ATF_TC_HEAD(mint_reasons_identity, tc)
{
	atf_tc_set_md_var(tc, "descr", "every identity refusal of "
	    "dq_ident_validate names its reason");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_reasons_identity, tc)
{
	struct fixture f;
	struct dq_ident_file *id;
	struct dq_mint_args *args;
	char *slash;
	uint64_t object;
	int fd, reason;

	setup(&f, 101);
	id = calloc(1, sizeof(*id));
	args = calloc(1, sizeof(*args));
	ATF_REQUIRE(id != NULL && args != NULL);

	/* Sanity: the unmodified identity mints. */
	ATF_REQUIRE_EQ(0, dq_mint_file(f.c.q, &f.ident, &f.pol, &object, &fd,
	    NULL));
	(void)close(fd);

	/* The argument header: version and kind, checked before anything. */
	/* A failing ioctl copies nothing back: the reason comes by pointer. */
	args->dm_version = DQ_API_VERSION + 1;
	args->dm_kind = DQ_KIND_FILE;
	args->dm_ident = f.ident;
	args->dm_policy = f.pol;
	args->dm_reasonp = &reason;
	reason = -1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_MINT, args));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(DQ_REASON_VERSION, reason);
	args->dm_version = DQ_API_VERSION;
	/* A directory mints (1c-iii-b), but not with a file's identity. */
	args->dm_kind = DQ_KIND_DIR;
	reason = -1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_MINT, args));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(DQ_REASON_TYPE, reason);
	/* A symbolic link exists only as a RESOLVE answer. */
	args->dm_kind = DQ_KIND_SYMLINK;
	reason = -1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_MINT, args));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(DQ_REASON_KIND, reason);
	args->dm_kind = DQ_KIND_SOCKET;
	reason = -1;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_MINT, args));
	ATF_CHECK_EQ(DQ_REASON_KIND, reason);
	/* A NULL pointer is allowed: the refusal is still EINVAL. */
	args->dm_reasonp = NULL;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_MINT, args));
	ATF_CHECK_EQ(EINVAL, errno);

	/* DQ_REASON_PATH */
	*id = f.ident;
	strlcpy(id->di_path, "relative/path", sizeof(id->di_path));
	id->di_pathlen = strlen(id->di_path);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "relative path");
	*id = f.ident;
	strlcpy(id->di_path, "//double", sizeof(id->di_path));
	id->di_pathlen = strlen(id->di_path);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "empty component");
	*id = f.ident;
	strlcpy(id->di_path, "/a/./b", sizeof(id->di_path));
	id->di_pathlen = strlen(id->di_path);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "dot component");
	*id = f.ident;
	strlcpy(id->di_path, "/a/..", sizeof(id->di_path));
	id->di_pathlen = strlen(id->di_path);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "dotdot component");
	*id = f.ident;
	strlcpy(id->di_path, "/a/b/", sizeof(id->di_path));
	id->di_pathlen = strlen(id->di_path);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "trailing slash");
	*id = f.ident;
	id->di_pathlen = 0;
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "pathlen 0");
	*id = f.ident;
	id->di_pathlen = DQ_PATH_MAX;
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "pathlen DQ_PATH_MAX");
	*id = f.ident;
	id->di_pathlen--;	/* di_path[di_pathlen] is not NUL */
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "pathlen short");
	*id = f.ident;
	memset(id->di_path, 'a', sizeof(id->di_path));
	id->di_path[0] = '/';
	id->di_pathlen = DQ_PATH_MAX - 1;
	expect_reason(&f, id, &f.pol, DQ_REASON_PATH, "unterminated path");

	/* DQ_REASON_STRING: a statfs string without its NUL. */
	*id = f.ident;
	memset(id->di_statfs.ds_mntonname, 'a', sizeof(id->di_statfs.ds_mntonname));
	expect_reason(&f, id, &f.pol, DQ_REASON_STRING, "mntonname unterminated");
	*id = f.ident;
	memset(id->di_statfs.ds_fstypename, 'a', sizeof(id->di_statfs.ds_fstypename));
	expect_reason(&f, id, &f.pol, DQ_REASON_STRING, "fstypename unterminated");
	*id = f.ident;
	memset(id->di_statfs.ds_mntfromname, 'a',
	    sizeof(id->di_statfs.ds_mntfromname));
	expect_reason(&f, id, &f.pol, DQ_REASON_STRING, "mntfromname unterminated");

	/* DQ_REASON_MNTNAME: not a component-boundary prefix of di_path. */
	*id = f.ident;
	id->di_statfs.ds_mntonname[0] = '\0';
	expect_reason(&f, id, &f.pol, DQ_REASON_MNTNAME, "empty mntonname");
	*id = f.ident;
	strlcpy(id->di_statfs.ds_mntonname, "/zz-not-a-prefix",
	    sizeof(id->di_statfs.ds_mntonname));
	expect_reason(&f, id, &f.pol, DQ_REASON_MNTNAME, "mntonname not a prefix");
	*id = f.ident;
	strlcpy(id->di_statfs.ds_mntonname, "relative",
	    sizeof(id->di_statfs.ds_mntonname));
	expect_reason(&f, id, &f.pol, DQ_REASON_MNTNAME, "relative mntonname");
	/* A prefix that ends inside a component, and one with a trailing slash. */
	slash = strchr(oracle_path + 1, '/');
	if (slash != NULL && slash - oracle_path > 2) {
		*id = f.ident;
		memcpy(id->di_statfs.ds_mntonname, oracle_path,
		    (size_t)(slash - oracle_path) - 1);
		id->di_statfs.ds_mntonname[slash - oracle_path - 1] = '\0';
		expect_reason(&f, id, &f.pol, DQ_REASON_MNTNAME,
		    "mntonname inside a component");
		*id = f.ident;
		memcpy(id->di_statfs.ds_mntonname, oracle_path,
		    (size_t)(slash - oracle_path) + 1);
		id->di_statfs.ds_mntonname[slash - oracle_path + 1] = '\0';
		expect_reason(&f, id, &f.pol, DQ_REASON_MNTNAME,
		    "mntonname with a trailing slash");
	}

	/* DQ_REASON_NAMEMAX */
	*id = f.ident;
	id->di_statfs.ds_namemax = 0;
	expect_reason(&f, id, &f.pol, DQ_REASON_NAMEMAX, "namemax 0");

	/* DQ_REASON_MODE, TYPE, SETID */
	*id = f.ident;
	id->di_mode = S_IFREG | 0644 | 0200000;
	expect_reason(&f, id, &f.pol, DQ_REASON_MODE, "mode bits outside");
	*id = f.ident;
	id->di_mode = S_IFDIR | 0755;
	expect_reason(&f, id, &f.pol, DQ_REASON_TYPE, "directory type");
	*id = f.ident;
	id->di_mode = S_IFCHR | 0644;
	expect_reason(&f, id, &f.pol, DQ_REASON_TYPE, "character device type");
	*id = f.ident;
	id->di_mode = S_IFREG | S_ISUID | 0755;
	expect_reason(&f, id, &f.pol, DQ_REASON_SETID, "setuid");
	*id = f.ident;
	id->di_mode = S_IFREG | S_ISGID | 0755;
	expect_reason(&f, id, &f.pol, DQ_REASON_SETID, "setgid");
	/* The sticky bit is an ordinary permission bit. */
	*id = f.ident;
	id->di_mode = S_IFREG | S_ISVTX | 0644;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, id, &f.pol, &object, &fd, NULL));
	(void)close(fd);

	/* DQ_REASON_BLKSIZE, SIZE, TIME */
	*id = f.ident;
	id->di_blksize = 512;
	expect_reason(&f, id, &f.pol, DQ_REASON_BLKSIZE, "blksize 512");
	*id = f.ident;
	id->di_blksize = 0;
	expect_reason(&f, id, &f.pol, DQ_REASON_BLKSIZE, "blksize 0");
	*id = f.ident;
	id->di_size = (uint64_t)OFF_MAX + 1;
	expect_reason(&f, id, &f.pol, DQ_REASON_SIZE, "size > OFF_MAX");
	*id = f.ident;
	id->di_size = OFF_MAX;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, id, &f.pol, &object, &fd, NULL));
	(void)close(fd);
	*id = f.ident;
	id->di_atime.tv_nsec = 1000000000;
	expect_reason(&f, id, &f.pol, DQ_REASON_TIME, "atime nsec 1e9");
	*id = f.ident;
	id->di_mtime.tv_nsec = -1;
	expect_reason(&f, id, &f.pol, DQ_REASON_TIME, "mtime nsec negative");
	*id = f.ident;
	id->di_ctime.tv_nsec = 1000000000;
	expect_reason(&f, id, &f.pol, DQ_REASON_TIME, "ctime nsec 1e9");
	*id = f.ident;
	id->di_birthtime.tv_nsec = 1000000000;
	expect_reason(&f, id, &f.pol, DQ_REASON_TIME, "birthtime nsec 1e9");

	/* DQ_REASON_PATHCONF: a slot beyond the names the kernel knows. */
	*id = f.ident;
	id->di_pathconf.dp_valid |= (uint64_t)1 << DQ_PC_NCOUNT;
	expect_reason(&f, id, &f.pol, DQ_REASON_PATHCONF, "unknown pathconf slot");
	*id = f.ident;
	id->di_pathconf.dp_valid |= (uint64_t)1 << (DQ_PC_SLOTS - 1);
	expect_reason(&f, id, &f.pol, DQ_REASON_PATHCONF, "last pathconf slot");

	/* Nonzero padding is a version mismatch. */
	*id = f.ident;
	id->di_pad0 = 1;
	expect_reason(&f, id, &f.pol, DQ_REASON_VERSION, "di_pad0");
	*id = f.ident;
	id->di_statfs.ds_pad0 = 1;
	expect_reason(&f, id, &f.pol, DQ_REASON_VERSION, "ds_pad0");
	*id = f.ident;
	id->di_statfs.ds_pad1 = 1;
	expect_reason(&f, id, &f.pol, DQ_REASON_VERSION, "ds_pad1");

	free(id);
	free(args);
	dqt_fini(&f.c);
	(void)close(f.oracle);
}

ATF_TC(mint_reasons_policy);
ATF_TC_HEAD(mint_reasons_policy, tc)
{
	atf_tc_set_md_var(tc, "descr", "a policy outside the stage 1b-i set is "
	    "DQ_REASON_POLICY, a rights version mismatch DQ_REASON_RIGHTS, a bad "
	    "dm_flags DQ_REASON_FLAGS");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mint_reasons_policy, tc)
{
	struct fixture f;
	struct dq_policy p;
	uint64_t object;
	int fd;

	setup(&f, 102);

	p = f.pol;
	p.dp_cache = DQ_CACHE_DATA;
	/* Stage 1b-ii: the data cache is served. */
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	p = f.pol;
	p.dp_cache = 7;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "cache out of range");
	p = f.pol;
	p.dp_cache = DQ_CACHE_ATTR;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	/* Stage 1b-i: served writes are accepted, read-only or writable. */
	p = f.pol;
	p.dp_write = DQ_EVENT;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	{
		int reason = -1;

		ATF_CHECK_EQ(0, dq_mint_file_flags(f.c.q, &f.ident, &p,
		    DQ_MINT_F_WRITE, &object, &fd, &reason));
		ATF_CHECK_EQ(DQ_REASON_NONE, reason);
		ATF_CHECK_EQ(O_RDWR, fcntl(fd, F_GETFL) & O_ACCMODE);
		(void)close(fd);
		/* DQ_MINT_F_WRITE needs dp_write == DQ_EVENT. */
		p = f.pol;
		reason = -1;
		errno = 0;
		ATF_CHECK_EQ(-1, dq_mint_file_flags(f.c.q, &f.ident, &p,
		    DQ_MINT_F_WRITE, &object, &fd, &reason));
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_EQ(DQ_REASON_FLAGS, reason);
		/* Unknown dm_flags bits, with and without a write policy. */
		reason = -1;
		errno = 0;
		ATF_CHECK_EQ(-1, dq_mint_file_flags(f.c.q, &f.ident, &p,
		    DQ_MINT_F_WRITE << 1, &object, &fd, &reason));
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_EQ(DQ_REASON_FLAGS, reason);
		p.dp_write = DQ_EVENT;
		reason = -1;
		errno = 0;
		ATF_CHECK_EQ(-1, dq_mint_file_flags(f.c.q, &f.ident, &p,
		    DQ_MINT_F_WRITE | 0x80000000u, &object, &fd, &reason));
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_EQ(DQ_REASON_FLAGS, reason);
	}
	p = f.pol;
	p.dp_write = DQ_ALLOW;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "write ALLOW");
	p = f.pol;
	p.dp_exec = DQ_ALLOW;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "exec ALLOW");
	/* D87: mmap_shared_write ALLOW with write DENY is refused as such. */
	p = f.pol;
	p.dp_mmap_shared_write = DQ_ALLOW;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY,
	    "mmap_shared_write ALLOW with write DENY");
	/* With write EVENT it is accepted (1b-ii). */
	p.dp_write = DQ_EVENT;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	p.dp_mmap_shared_write = 7;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY,
	    "mmap_shared_write out of range");
	p = f.pol;
	p.dp_lock = DQ_DENY;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "lock DENY");
	p = f.pol;
	p.dp_lock = DQ_ALLOW;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "lock ALLOW");
	p = f.pol;
	p.dp_ioctl = DQ_EVENT;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	p = f.pol;
	p.dp_ioctl = DQ_ALLOW;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "ioctl ALLOW");
	p = f.pol;
	p.dp_deadline_ms = DQ_DEADLINE_DEFAULT - 1;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "deadline below default");
	p = f.pol;
	p.dp_events = DQ_EVENTS_RCVD;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "events RCVD");
	p = f.pol;
	p.dp_events = DQ_EVENTS_SOCKOPT;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "events SOCKOPT");
	p = f.pol;
	p.dp_events = DQ_EVENTS_SET_TEXT;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "events SET_TEXT");
	p = f.pol;
	p.dp_events = DQ_EVENTS_GETATTR | DQ_EVENTS_CLOSE;
	ATF_CHECK_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	(void)close(fd);
	p = f.pol;
	p.dp_pad0 = 1;
	expect_reason(&f, &f.ident, &p, DQ_REASON_POLICY, "dp_pad0");

	p = f.pol;
	p.dp_rights_version = CAP_RIGHTS_VERSION + 1;
	expect_reason(&f, &f.ident, &p, DQ_REASON_RIGHTS, "rights version");
	p = f.pol;
	memset(&p.dp_rights, 0xff, sizeof(p.dp_rights));
	expect_reason(&f, &f.ident, &p, DQ_REASON_RIGHTS, "invalid rights");
	/* Narrowed rights are accepted and installed. */
	p = f.pol;
	cap_rights_init(&p.dp_rights, CAP_READ, CAP_FSTAT, CAP_SEEK);
	ATF_REQUIRE_EQ(0, dq_mint_file(f.c.q, &f.ident, &p, &object, &fd, NULL));
	{
		cap_rights_t got;
		struct statfs sfs;

		ATF_REQUIRE_EQ(0, cap_rights_get(fd, &got));
		ATF_CHECK(cap_rights_is_set(&got, CAP_READ));
		ATF_CHECK(!cap_rights_is_set(&got, CAP_FSTATFS));
		errno = 0;
		ATF_CHECK_EQ(-1, fstatfs(fd, &sfs));
		ATF_CHECK_EQ(ENOTCAPABLE, errno);
	}
	(void)close(fd);
	dqt_fini(&f.c);
	(void)close(f.oracle);
}

static void
child_open_as_nobody(void *arg __unused, void *result)
{
	struct dqt_rr *r = result;

	if (setgid(NOBODY_UID) != 0 || setuid(NOBODY_UID) != 0) {
		r->rv = -2;
		r->err = errno;
		return;
	}
	r->rv = open(DQ_DEVICE, O_RDWR);
	r->err = r->rv == -1 ? errno : 0;
	if (r->rv >= 0)
		(void)close((int)r->rv);
}

ATF_TC(nonroot_open_refused);
ATF_TC_HEAD(nonroot_open_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a non-root process cannot open /dev/dq "
	    "(D85: 0600 node, then priv_check(PRIV_DRIVER))");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nonroot_open_refused, tc)
{
	struct dqt_rr r;
	int q;

	q = dqt_open_queue();	/* skip when the device is absent */
	dqt_run_child(child_open_as_nobody, NULL, &r, sizeof(r));
	ATF_REQUIRE_MSG(r.rv != -2, "setuid: %s", strerror(r.err));
	ATF_CHECK_EQ(-1, r.rv);
	/*
	 * The node's mode refuses first (EACCES from the permission check);
	 * the privilege check behind it would answer EPERM.  Either is the
	 * refusal D85 requires.
	 */
	ATF_CHECK_MSG(r.err == EACCES || r.err == EPERM, "errno %d", r.err);
	(void)close(q);
}

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

struct stat_res {
	struct dqt_rr	 rr;
	struct stat	 st;
};

static void
child_fstat(void *arg, void *result)
{
	struct one_read_arg *a = arg;
	struct stat_res *r = result;

	r->rr.rv = fstat(a->fd, &r->st);
	r->rr.err = r->rr.rv == -1 ? errno : 0;
}

ATF_TC(reply_errors);
ATF_TC_HEAD(reply_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "DQ_IOC_REPLY: unknown id ESRCH, "
	    "oversize or malformed EINVAL, unreadable data EFAULT, wrong body "
	    "for the operation EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_errors, tc)
{
	struct fixture f;
	struct dqt_object *o, *og;
	struct dq_policy pol;
	struct dq_reply rep;
	struct dq_ident_file *bad;
	struct dq_stats st;
	struct one_read_arg a;
	struct dqt_child ch;
	struct dqt_rr r;
	struct stat_res sr;
	u_int max_io;
	int status;

	setup(&f, 103);
	ATF_REQUIRE(dqt_sysctl_get_uint("kern.dq.max_io", &max_io));
	o = dqt_mint_ident(&f.c, &f.ident, &f.pol, data, sizeof(data));
	dq_policy_default(&pol);
	pol.dp_events = DQ_EVENTS_GETATTR;
	og = dqt_mint_ident(&f.c, &f.ident, &pol, data, sizeof(data));

	/* Argument checks run before the id is looked up. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, 12345, 0, NULL, 0));
	ATF_CHECK_EQ(ESRCH, errno);
	dqt_stats(&f.c, &st);
	ATF_CHECK_EQ(1, st.ds_late_replies);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, 0, 0, NULL, 0));	/* never an id */
	ATF_CHECK_EQ(ESRCH, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, 12345, 0, data, (size_t)max_io + 1));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, 12345, -1, NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, 12345, ELAST + 1, NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(&rep, 0, sizeof(rep));
	rep.dr_version = DQ_API_VERSION + 1;
	rep.dr_id = 12345;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_REPLY, &rep));
	ATF_CHECK_EQ(EINVAL, errno);
	rep.dr_version = DQ_API_VERSION;
	rep.dr_pad0 = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_REPLY, &rep));
	ATF_CHECK_EQ(EINVAL, errno);
	rep.dr_pad0 = 0;
	rep.dr_len = 10;
	rep.dr_data = NULL;	/* copied in before the lookup */
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_REPLY, &rep));
	ATF_CHECK_EQ(EFAULT, errno);
	dqt_stats(&f.c, &st);
	ATF_CHECK_EQ(2, st.ds_late_replies);	/* only the two ESRCH counted */

	/* A READ in flight: the body must fit the asked length and errno. */
	dqt_hold(&f.c, true);
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_one_read, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 1, DQT_WAIT_MS));
	ATF_CHECK_EQ(DQ_OP_READ, f.c.held[0].op);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[0].id, 0, data, 101));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[0].id, EIO, data, 1));
	ATF_CHECK_EQ(EINVAL, errno);
	dqt_stats(&f.c, &st);
	ATF_CHECK_EQ(1, st.ds_inflight);	/* a refused reply changes nothing */
	ATF_CHECK_EQ(0, dq_reply(f.c.q, f.c.held[0].id, EACCES, NULL, 0));
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(-1, r.rv);
	ATF_CHECK_EQ(EACCES, r.err);
	/* Answered: a second reply is late. */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[0].id, 0, NULL, 0));
	ATF_CHECK_EQ(ESRCH, errno);

	/* A GETATTR in flight: exactly one identity that validates. */
	a.fd = og->fd;
	dqt_spawn(&ch, child_fstat, &a);
	ATF_REQUIRE(dqt_wait_held(&f.c, 2, DQT_WAIT_MS));
	ATF_CHECK_EQ(DQ_OP_GETATTR, f.c.held[1].op);
	bad = calloc(1, sizeof(*bad));
	ATF_REQUIRE(bad != NULL);
	*bad = f.ident;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[1].id, 0, bad, 10));
	ATF_CHECK_EQ(EINVAL, errno);
	bad->di_mode = S_IFDIR | 0755;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[1].id, 0, bad, sizeof(*bad)));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(f.c.q, f.c.held[1].id, EIO, bad, sizeof(*bad)));
	ATF_CHECK_EQ(EINVAL, errno);
	*bad = f.ident;
	bad->di_size = 4242;
	ATF_CHECK_EQ(0, dq_reply(f.c.q, f.c.held[1].id, 0, bad, sizeof(*bad)));
	status = dqt_wait(&ch, &sr, sizeof(sr));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(0, sr.rr.rv);
	ATF_CHECK_EQ(4242, sr.st.st_size);	/* the reply became the identity */
	free(bad);
	dqt_stats(&f.c, &st);
	ATF_CHECK_EQ(0, st.ds_inflight);
	ATF_CHECK_EQ(2, st.ds_replies);
	dqt_fini(&f.c);
	(void)close(f.oracle);
}

ATF_TC(control_errors);
ATF_TC_HEAD(control_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "REVOKE, SETIDENT, SETPOLICY and the "
	    "queue's read(2) and unknown ioctls answer the documented errnos");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(control_errors, tc)
{
	struct fixture f;
	struct dqt_object *o;
	struct dq_object_args oa;
	struct dq_setident_args *sia;
	struct dq_setpolicy_args spa;
	struct dq_policy p;
	struct dq_ident_file *id;
	struct one_read_arg a;
	struct dqt_child ch;
	struct dqt_rr r;
	struct dq_stats st;
	const struct dq_event *ev;
	char buf[256];
	const size_t recsize = sizeof(struct dq_event) + sizeof(struct dq_read_body);
	ssize_t got;
	int flags, status, type;

	setup(&f, 104);
	o = dqt_mint_ident(&f.c, &f.ident, &f.pol, data, sizeof(data));

	/* REVOKE */
	memset(&oa, 0, sizeof(oa));
	oa.doa_version = DQ_API_VERSION + 1;
	oa.doa_object = o->id;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_REVOKE, &oa));
	ATF_CHECK_EQ(EINVAL, errno);
	oa.doa_version = DQ_API_VERSION;
	oa.doa_pad0 = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_REVOKE, &oa));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_revoke(f.c.q, o->id + 1));
	ATF_CHECK_EQ(ESRCH, errno);

	/* SETIDENT */
	id = calloc(1, sizeof(*id));
	sia = calloc(1, sizeof(*sia));
	ATF_REQUIRE(id != NULL && sia != NULL);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_ident(f.c.q, o->id + 1, &f.ident));
	ATF_CHECK_EQ(ESRCH, errno);
	*id = f.ident;
	id->di_blksize = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_ident(f.c.q, o->id, id));
	ATF_CHECK_EQ(EINVAL, errno);
	sia->dsi_version = DQ_API_VERSION + 1;
	sia->dsi_object = o->id;
	sia->dsi_ident = f.ident;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_SETIDENT, sia));
	ATF_CHECK_EQ(EINVAL, errno);
	sia->dsi_version = DQ_API_VERSION;
	sia->dsi_pad0 = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_SETIDENT, sia));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, dq_set_ident(f.c.q, o->id, &f.ident));

	/* SETPOLICY: only cache, deadline and events may change. */
	p = f.pol;
	p.dp_deadline_ms = 5000;
	p.dp_cache = DQ_CACHE_ATTR;
	p.dp_events = DQ_EVENTS_CLOSE;
	ATF_CHECK_EQ(0, dq_set_policy(f.c.q, o->id, &p));
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_policy(f.c.q, o->id + 1, &p));
	ATF_CHECK_EQ(ESRCH, errno);
	p = f.pol;
	cap_rights_init(&p.dp_rights, CAP_READ);	/* valid, but not as minted */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_policy(f.c.q, o->id, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	p = f.pol;
	p.dp_write = DQ_EVENT;	/* invalid in stage 1a before the comparison */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_set_policy(f.c.q, o->id, &p));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(&spa, 0, sizeof(spa));
	spa.dsp_version = DQ_API_VERSION + 1;
	spa.dsp_object = o->id;
	spa.dsp_policy = f.pol;
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, DQ_IOC_SETPOLICY, &spa));
	ATF_CHECK_EQ(EINVAL, errno);

	/*
	 * FIODTYPE is answered by devfs for every character device (D_TYPEMASK
	 * of the cdevsw flags: 0 for the queue) before the driver sees it;
	 * FIONBIO/FIOASYNC are the driver's own; anything else is ENOTTY.
	 */
	type = -1;
	ATF_CHECK_EQ_MSG(0, ioctl(f.c.q, FIODTYPE, &type), "FIODTYPE: %s",
	    strerror(errno));
	ATF_CHECK_EQ(0, type);
	errno = 0;
	ATF_CHECK_EQ(-1, ioctl(f.c.q, FIOSEEKDATA, &type));
	ATF_CHECK_EQ(ENOTTY, errno);
	flags = 1;
	ATF_CHECK_EQ(0, ioctl(f.c.q, FIOASYNC, &flags));
	flags = 0;
	ATF_CHECK_EQ(0, ioctl(f.c.q, FIOASYNC, &flags));

	/* read(2) on the queue: EINVAL, EAGAIN, ENOBUFS. */
	dqt_stop(&f.c);		/* this test reads the queue itself */
	errno = 0;
	ATF_CHECK_EQ(-1, read(f.c.q, buf, sizeof(struct dq_event) - 1));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, read(f.c.q, buf, sizeof(buf)));	/* O_NONBLOCK set */
	ATF_CHECK_EQ(EAGAIN, errno);
	a.fd = o->fd;
	a.len = 100;
	dqt_spawn(&ch, child_one_read, &a);
	for (flags = 0; flags < DQT_WAIT_MS; flags += 10) {
		dqt_stats(&f.c, &st);
		if (st.ds_queue_current == 1)
			break;
		dqt_msleep(10);
	}
	ATF_REQUIRE_EQ(1, st.ds_queue_current);
	errno = 0;
	ATF_CHECK_EQ(-1, read(f.c.q, buf, recsize - 1));
	ATF_CHECK_EQ(ENOBUFS, errno);
	got = read(f.c.q, buf, sizeof(buf));
	ATF_REQUIRE_EQ((ssize_t)recsize, got);
	ev = dq_event_first(buf, (size_t)got);
	ATF_REQUIRE(ev != NULL);
	ATF_CHECK_EQ(DQ_OP_READ, ev->de_op);
	ATF_CHECK_EQ(o->id, ev->de_object);
	ATF_CHECK_EQ(ch.pid, ev->de_caller.dc_pid);
	ATF_CHECK_EQ(getpid(), ev->de_caller.dc_ppid);
	ATF_CHECK_EQ(0, ev->de_caller.dc_flags & DQ_CALLER_F_KERNEL);
	ATF_CHECK_EQ(0, dq_reply(f.c.q, ev->de_id, 0, data, 100));
	status = dqt_wait(&ch, &r, sizeof(r));
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(100, r.rv);

	free(id);
	free(sia);
	dqt_fini(&f.c);
	(void)close(f.oracle);
}

ATF_TC(kldunload_refused);
ATF_TC_HEAD(kldunload_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "the dq module never unloads");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.progs", "kldstat kldunload");
}
ATF_TC_BODY(kldunload_refused, tc)
{
	int q;

	q = dqt_open_queue();
	if (system("kldstat -q -m dq") != 0)
		atf_tc_skip("no dq module is registered");
	/* Static: not a file to unload; loaded: MOD_UNLOAD answers EBUSY. */
	ATF_CHECK(system("kldunload dq >/dev/null 2>&1") != 0);
	ATF_CHECK_EQ(0, system("kldstat -q -m dq"));
	/* The device still works. */
	(void)close(q);
	q = dqt_open_queue();
	(void)close(q);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mint_reasons_identity);
	ATF_TP_ADD_TC(tp, mint_reasons_policy);
	ATF_TP_ADD_TC(tp, nonroot_open_refused);
	ATF_TP_ADD_TC(tp, reply_errors);
	ATF_TP_ADD_TC(tp, control_errors);
	ATF_TP_ADD_TC(tp, kldunload_refused);
	return (atf_no_error());
}
