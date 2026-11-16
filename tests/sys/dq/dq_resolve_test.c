/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * RESOLVE (stage 1c-i): every name an attached process resolves is posted
 * before the lookup runs, with the operation, the class (the requester's
 * own path, a path for a kernel consumer, a kernel-origin lookup) and the
 * path(s); the controller answers PASS or an errno.  The oracle for PASS
 * is the same sequence of calls run unattached: results must be equal.
 * Then the wait rules: errno answers, the allow-list, deadlines, a dead
 * controller, signals (first consultation restarts, rename never does),
 * the path-swap race, queue depth, and I5 (what an attached process may
 * not become).
 */

#include <sys/param.h>
#include <sys/extattr.h>
#include <sys/imgact_binmisc.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/ktrace.h>
#include <sys/linker.h>
#include <sys/mdioctl.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ucred.h>

#include <ufs/ufs/extattr.h>
#include <ufs/ufs/quota.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dq_test.h"

/*
 * The families.  Each step is one call on a tagged path, run first
 * unattached (the oracle, in directory "oracle") and then attached (in
 * "attached"); the results must agree and the attached run must post the
 * listed event.
 */
enum step {
	S_OPEN, S_OPENAT, S_STAT, S_LSTAT, S_ACCESS, S_SYMLINK, S_READLINK,
	S_MKDIR, S_RMDIR, S_LINK, S_RENAME, S_UNLINK, S_TRUNCATE, S_CHMOD,
	S_CHOWN, S_UTIMES, S_MKFIFO, S_MKNOD, S_CHDIR, S_CHROOT, S_EXEC,
	S_INTERP, S_KTRACE, S_KLDLOAD, S_BIND, S_CONNECT, S_SENDTO, S_NSTEPS
};

struct expect {
	const char	*tag;		/* in the event's path or path2 */
	uint32_t	 op;
	uint32_t	 cls;
	bool		 pending;	/* kernel half not yet in (1c-i notes) */
};

static const struct expect expects[S_NSTEPS] = {
	[S_OPEN] = { "rt-open", DQ_ROP_OPEN, DQ_RCLASS_USER, false },
	[S_OPENAT] = { "rt-openat", DQ_ROP_OPEN, DQ_RCLASS_USER, false },
	[S_STAT] = { "rt-open", DQ_ROP_STAT, DQ_RCLASS_USER, false },
	[S_LSTAT] = { "rt-lstat", DQ_ROP_STAT, DQ_RCLASS_USER, false },
	[S_ACCESS] = { "rt-open", DQ_ROP_ACCESS, DQ_RCLASS_USER, false },
	[S_SYMLINK] = { "rt-symlink", DQ_ROP_SYMLINK, DQ_RCLASS_USER, false },
	[S_READLINK] = { "rt-symlink", DQ_ROP_READLINK, DQ_RCLASS_USER, false },
	[S_MKDIR] = { "rt-mkdir", DQ_ROP_MKDIR, DQ_RCLASS_USER, false },
	[S_RMDIR] = { "rt-mkdir", DQ_ROP_RMDIR, DQ_RCLASS_USER, false },
	[S_LINK] = { "rt-link", DQ_ROP_LINK, DQ_RCLASS_USER, false },
	[S_RENAME] = { "rt-renamed", DQ_ROP_RENAME, DQ_RCLASS_USER, false },
	[S_UNLINK] = { "rt-renamed", DQ_ROP_UNLINK, DQ_RCLASS_USER, false },
	[S_TRUNCATE] = { "rt-open", DQ_ROP_TRUNCATE, DQ_RCLASS_USER, false },
	[S_CHMOD] = { "rt-open", DQ_ROP_SETATTR, DQ_RCLASS_USER, false },
	[S_CHOWN] = { "rt-open", DQ_ROP_SETATTR, DQ_RCLASS_USER, false },
	[S_UTIMES] = { "rt-open", DQ_ROP_SETATTR, DQ_RCLASS_USER, false },
	[S_MKFIFO] = { "rt-fifo", DQ_ROP_MKFIFO, DQ_RCLASS_USER, false },
	[S_MKNOD] = { "rt-mknod", DQ_ROP_MKNOD, DQ_RCLASS_USER, false },
	[S_CHDIR] = { "rt-cdir", DQ_ROP_CHDIR, DQ_RCLASS_USER, false },
	[S_CHROOT] = { "rt-croot", DQ_ROP_CHROOT, DQ_RCLASS_USER, false },
	[S_EXEC] = { "rt-script", DQ_ROP_EXEC, DQ_RCLASS_USER, false },
	[S_INTERP] = { "/bin/sh", DQ_ROP_EXEC_INTERP, DQ_RCLASS_KERNEL, false },
	[S_KTRACE] = { "rt-ktrace", DQ_ROP_INTERNAL, DQ_RCLASS_KCONSUMER,
	    false },
	[S_KLDLOAD] = { "rt-kld.ko", DQ_ROP_INTERNAL, DQ_RCLASS_KCONSUMER,
	    false },
	[S_BIND] = { "rt-sock", DQ_ROP_BIND, DQ_RCLASS_USER, false },
	[S_CONNECT] = { "rt-sock", DQ_ROP_CONNECT, DQ_RCLASS_USER, false },
	[S_SENDTO] = { "rt-dsock", DQ_ROP_CONNECT, DQ_RCLASS_USER, false },
};

struct fam_res {
	long		 rv[S_NSTEPS];
	int		 err[S_NSTEPS];
	ino_t		 sh_ino;	/* stat("/bin/sh") through the lookup */
};

#define	STEP(r, s, call) do {						\
	errno = 0;							\
	(r)->rv[s] = (long)(call);					\
	(r)->err[s] = (r)->rv[s] == -1 ? errno : 0;			\
} while (0)

/* Run an image in a child and return its exit status (or -1). */
static long
run_image(const char *path, char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0) {
		execv(path, argv);
		_exit(126);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static long
chroot_child(const char *dir)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);
	if (pid == 0)
		_exit(chroot(dir) == 0 ? 0 : errno);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return (-1);
	return (WEXITSTATUS(status));
}

static void
child_families(void *arg, void *result)
{
	const char *dir = arg;
	struct fam_res *r = result;
	struct sockaddr_un sun;
	struct stat sb;
	char buf[64], *const shargv[] = { __DECONST(char *, "rt-script"),
	    NULL };
	int fd, s, s2;

	if (chdir(dir) != 0)
		_exit(4);
	/* Descriptor numbers differ between the runs: 0 or -1. */
	STEP(r, S_OPEN, (fd = open("rt-open", O_CREAT | O_RDWR, 0644)) == -1 ?
	    -1 : 0);
	if (fd != -1)
		(void)close(fd);
	STEP(r, S_OPENAT, (fd = openat(AT_FDCWD, "rt-openat",
	    O_CREAT | O_WRONLY, 0644)) == -1 ? -1 : 0);
	if (fd != -1)
		(void)close(fd);
	STEP(r, S_STAT, stat("rt-open", &sb));
	STEP(r, S_LSTAT, lstat("rt-lstat-missing", &sb));
	STEP(r, S_ACCESS, access("rt-open", R_OK));
	STEP(r, S_SYMLINK, symlink("rt-open", "rt-symlink"));
	STEP(r, S_READLINK, readlink("rt-symlink", buf, sizeof(buf)));
	STEP(r, S_MKDIR, mkdir("rt-mkdir", 0755));
	STEP(r, S_RMDIR, rmdir("rt-mkdir"));
	STEP(r, S_LINK, link("rt-open", "rt-link"));
	STEP(r, S_RENAME, rename("rt-link", "rt-renamed"));
	STEP(r, S_UNLINK, unlink("rt-renamed"));
	STEP(r, S_TRUNCATE, truncate("rt-open", 10));
	STEP(r, S_CHMOD, chmod("rt-open", 0600));
	STEP(r, S_CHOWN, chown("rt-open", 0, 0));
	STEP(r, S_UTIMES, utimes("rt-open", NULL));
	STEP(r, S_MKFIFO, mkfifo("rt-fifo", 0644));
	STEP(r, S_MKNOD, mknod("rt-mknod", S_IFCHR | 0600, 0));
	(void)mkdir("rt-cdir", 0755);
	STEP(r, S_CHDIR, chdir("rt-cdir"));
	(void)chdir("..");
	(void)mkdir("rt-croot", 0755);
	STEP(r, S_CHROOT, chroot_child("rt-croot"));
	fd = open("rt-script", O_CREAT | O_TRUNC | O_WRONLY, 0755);
	if (fd != -1) {
		(void)write(fd, "#!/bin/sh\nexit 5\n", 17);
		(void)close(fd);
	}
	STEP(r, S_EXEC, run_image("./rt-script", shargv));
	r->rv[S_INTERP] = r->rv[S_EXEC];	/* the same exec */
	STEP(r, S_KTRACE, ktrace("rt-ktrace", KTROP_SET, KTRFAC_SYSCALL,
	    getpid()));
	if (r->rv[S_KTRACE] == 0)
		(void)ktrace(NULL, KTROP_CLEARFILE, 0, 0);
	STEP(r, S_KLDLOAD, kldload("./rt-kld.ko"));
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, "rt-sock", sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	STEP(r, S_BIND, bind(s, (struct sockaddr *)&sun, sun.sun_len));
	(void)listen(s, 1);
	s2 = socket(AF_UNIX, SOCK_STREAM, 0);
	STEP(r, S_CONNECT, connect(s2, (struct sockaddr *)&sun, sun.sun_len));
	(void)close(s2);
	(void)close(s);
	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)strlcpy(sun.sun_path, "rt-dsock", sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	STEP(r, S_SENDTO, sendto(s, "x", 1, 0, (struct sockaddr *)&sun,
	    sun.sun_len));
	(void)close(s);
	r->sh_ino = stat("/bin/sh", &sb) == 0 ? sb.st_ino : 0;
}

static void
child_plain(void *arg, void *result)
{

	child_families(arg, result);
}

ATF_TC(families);
ATF_TC_HEAD(families, tc)
{
	atf_tc_set_md_var(tc, "descr", "each path-taking syscall family posts "
	    "one RESOLVE with its op, class and path (rename and link carry "
	    "both paths; exec's #! interpreter is class 3; ktrace and a "
	    "kldload path are class 2) and, answered PASS, returns what the "
	    "unattached run returns (fast-path lookups declined, results "
	    "unchanged)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(families, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct fam_res o, a;
	struct dq_stats2 st;
	struct stat sb;
	int i, k;

	ATF_REQUIRE_EQ(0, mkdir("oracle", 0755));
	ATF_REQUIRE_EQ(0, mkdir("attached", 0755));
	memset(&o, 0, sizeof(o));
	dqt_run_child(child_plain, __DECONST(void *, "oracle"), &o, sizeof(o));

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_families,
	    __DECONST(void *, "attached"));
	memset(&a, 0, sizeof(a));
	dqt_attach_collect(&ch, &a, sizeof(a));
	for (k = 0; k < S_NSTEPS; k++) {
		ATF_CHECK_EQ_MSG(o.rv[k], a.rv[k], "step %d (%s): rv attached "
		    "%ld unattached %ld", k, expects[k].tag, a.rv[k], o.rv[k]);
		ATF_CHECK_EQ_MSG(o.err[k], a.err[k], "step %d (%s): errno "
		    "attached %d unattached %d", k, expects[k].tag, a.err[k],
		    o.err[k]);
		i = dqt_find_resolve(&c, expects[k].tag, expects[k].op, 0);
		if (i == -1 && expects[k].pending) {
			fprintf(stderr, "step %d (%s): not consulted yet "
			    "(kernel half pending)\n", k, expects[k].tag);
			continue;
		}
		ATF_CHECK_MSG(i != -1, "step %d (%s): no RESOLVE of op %u", k,
		    expects[k].tag, expects[k].op);
		if (i == -1)
			continue;
		dqt_resolve_at(&c, i, &rs);
		ATF_CHECK_EQ_MSG(expects[k].cls, rs.cls,
		    "step %d (%s): class %u", k, expects[k].tag, rs.cls);
		if (expects[k].cls == DQ_RCLASS_USER)
			ATF_CHECK((rs.rflags & DQ_RF_USER) != 0);
		else
			ATF_CHECK((rs.rflags & DQ_RF_USER) == 0);
		if (expects[k].cls == DQ_RCLASS_KCONSUMER)
			ATF_CHECK((rs.rflags & DQ_RF_KCONSUMER) != 0);
	}
	/* RENAME and LINK carry both paths in one event. */
	i = dqt_find_resolve(&c, "rt-link", DQ_ROP_RENAME, 0);
	if (i != -1) {
		dqt_lock(&c);
		ATF_CHECK(strstr(c.rs[i].path, "rt-link") != NULL);
		ATF_CHECK(strstr(c.rs[i].path2, "rt-renamed") != NULL);
		dqt_unlock(&c);
	}
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-renamed", DQ_ROP_RENAME));
	i = dqt_find_resolve(&c, "rt-link", DQ_ROP_LINK, 0);
	if (i != -1) {
		dqt_lock(&c);
		ATF_CHECK(strstr(c.rs[i].path, "rt-open") != NULL);
		ATF_CHECK(strstr(c.rs[i].path2, "rt-link") != NULL);
		dqt_unlock(&c);
	}
	/* Lookups resolve to the same objects. */
	ATF_REQUIRE_EQ(0, stat("/bin/sh", &sb));
	ATF_CHECK_EQ(sb.st_ino, a.sh_ino);
	dqt_stats2(&c, &st);
	ATF_CHECK_EQ(0, st.ds2_resolve_unmarked);
	ATF_CHECK_EQ(0, st.ds2_resolve_failclosed);
	ATF_CHECK(st.ds2_resolve_kernel >= 2);
	dqt_fini(&c);
}

struct one_res {
	struct dqt_rr	 r[4];
	long		 elapsed_ms;
};

static long
ms_since(const struct timespec *t0)
{
	struct timespec t1;

	(void)clock_gettime(CLOCK_MONOTONIC, &t1);
	return ((t1.tv_sec - t0->tv_sec) * 1000 +
	    (t1.tv_nsec - t0->tv_nsec) / 1000000);
}

static void
child_deny(void *arg __unused, void *result)
{
	struct one_res *r = result;
	struct stat sb;
	int fd;

	fd = open("rt-deny", O_CREAT | O_RDWR, 0644);
	r->r[0].rv = fd;
	r->r[0].err = fd == -1 ? errno : 0;
	r->r[1].rv = stat("rt-deny", &sb);
	r->r[1].err = r->r[1].rv == -1 ? errno : 0;
	r->r[2].rv = stat("rt-other", &sb);
	r->r[2].err = r->r[2].rv == -1 ? errno : 0;
}

ATF_TC(errno_answers);
ATF_TC_HEAD(errno_answers, tc)
{
	atf_tc_set_md_var(tc, "descr", "an errno answer is the syscall's "
	    "result and the real namespace is untouched (O_CREAT created "
	    "nothing); an errno outside the RESOLVE allow-list arrives as EIO "
	    "and counts in ds2_bad_replies; a PASS reply of the wrong size "
	    "or kind is EINVAL to the controller");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(errno_answers, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;
	struct dq_stats2 st;

	dqt_init(&c);
	dqt_resolve_fail(&c, "rt-deny", EACCES);
	dqt_attach_spawn(&c, &ch, child_deny, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EACCES, r.r[0].err);
	ATF_CHECK_EQ(EACCES, r.r[1].err);
	ATF_CHECK_EQ(ENOENT, r.r[2].err);
	ATF_CHECK_EQ(-1, access("rt-deny", F_OK));

	dqt_resolve_fail(&c, NULL, EPIPE);	/* not on the list */
	dqt_attach_spawn(&c, &ch, child_deny, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_EQ(EIO, r.r[1].err);
	ATF_CHECK_EQ(ENOENT, r.r[2].err);
	dqt_stats2(&c, &st);
	/* The two lookups of rt-deny, each answered EPIPE: two bad replies. */
	ATF_CHECK_EQ_MSG(2, st.ds2_bad_replies, "ds2_bad_replies %ju",
	    (uintmax_t)st.ds2_bad_replies);
	dqt_fini(&c);
}

ATF_TC(reply_validation);
ATF_TC_HEAD(reply_validation, tc)
{
	atf_tc_set_md_var(tc, "descr", "a RESOLVE reply other than an errno "
	    "with no body or exactly PASS (another kind, a padded PASS, a body "
	    "with an errno) is EINVAL and the event stays in flight");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(reply_validation, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;
	struct dq_resolve_reply rr;
	char big[16];
	uint64_t id;

	dqt_init(&c);
	dqt_resolve_hold(&c, "rt-deny", 0);
	dqt_attach_spawn(&c, &ch, child_deny, NULL);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	id = dqt_held_id(&c, 0);
	dqt_lock(&c);
	ATF_CHECK_EQ(DQ_OP_RESOLVE, c.held[0].op);
	dqt_unlock(&c);
	memset(&rr, 0, sizeof(rr));
	rr.drr_kind = DQ_RESOLVE_FD;	/* 1c-iii */
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, 0, &rr, sizeof(rr)));
	ATF_CHECK_EQ(EINVAL, errno);
	rr.drr_kind = DQ_RESOLVE_PASS;
	rr.drr_pad0 = 1;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, 0, &rr, sizeof(rr)));
	ATF_CHECK_EQ(EINVAL, errno);
	memset(big, 0, sizeof(big));
	((struct dq_resolve_reply *)(void *)big)->drr_kind = DQ_RESOLVE_PASS;
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, 0, big, sizeof(big)));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, EACCES, &rr, sizeof(rr)));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, dq_reply(c.q, id, 0, NULL, 0));
	ATF_CHECK_EQ(EINVAL, errno);
	/* Still in flight: answer it, then let the rest through. */
	dqt_resolve_hold(&c, "", 0);
	ATF_CHECK_EQ(0, dq_reply_resolve_errno(c.q, id, EROFS));
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EROFS, r.r[0].err);
	dqt_fini(&c);
}

#define	DEFAULT_DEADLINE	"kern.dq.default_deadline_ms"

static void
child_hold_stat(void *arg, void *result)
{
	const char *path = arg;
	struct one_res *r = result;
	struct timespec t0;
	struct stat sb;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	r->r[0].rv = stat(path, &sb);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
	r->elapsed_ms = ms_since(&t0);
	/* After a failure: the real namespace stays out of reach. */
	r->r[1].rv = stat("/bin/sh", &sb);
	r->r[1].err = r->r[1].rv == -1 ? errno : 0;
	r->r[2].rv = open("/etc/passwd", O_RDONLY);
	r->r[2].err = r->r[2].rv == -1 ? errno : 0;
}

ATF_TC_WITH_CLEANUP(deadline_eio);
ATF_TC_HEAD(deadline_eio, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unanswered user-origin RESOLVE "
	    "fails with EIO at kern.dq.default_deadline_ms and an INTERRUPT "
	    "names it; the next lookups are consulted again");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(deadline_eio, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;

	dqt_sysctl_save_set_uint(DEFAULT_DEADLINE, 500);

	dqt_init(&c);
	dqt_resolve_hold(&c, "rt-hold", 0);
	dqt_attach_spawn(&c, &ch, child_hold_stat,
	    __DECONST(void *, "rt-hold"));
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_MSG(r.elapsed_ms >= 400 && r.elapsed_ms < 5000,
	    "waited %ld ms", r.elapsed_ms);
	ATF_CHECK_EQ(0, r.r[1].rv);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	ATF_CHECK(dqt_wait_interrupts(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_CHECK_EQ(c.held[0].id, c.interrupted[0]);
	dqt_unlock(&c);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(deadline_eio, tc)
{

	(void)dqt_sysctl_restore(DEFAULT_DEADLINE);
}

ATF_TC(controller_exit_fails_closed);
ATF_TC_HEAD(controller_exit_fails_closed, tc)
{
	atf_tc_set_md_var(tc, "descr", "when the controller's queue closes, "
	    "the waiting lookup fails with EIO and every later lookup of the "
	    "attached process fails with EIO: the real namespace is never "
	    "reached without a controller");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(controller_exit_fails_closed, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;

	dqt_init(&c);
	dqt_resolve_hold(&c, "rt-exit", 0);
	dqt_attach_spawn(&c, &ch, child_hold_stat,
	    __DECONST(void *, "rt-exit"));
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_close_queue(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_EQ(EIO, r.r[1].err);
	ATF_CHECK_EQ(EIO, r.r[2].err);
	dqt_fini(&c);
}

static char swapbuf[32];

static void
on_usr1(int sig __unused)
{

	/* The bytes a restarted lookup copies in again. */
	memcpy(swapbuf, "rt-swap-B", sizeof("rt-swap-B"));
}

struct sig_arg {
	int		 restart;	/* SA_RESTART */
	int		 rename;	/* rename rt-ren-a rt-ren-b */
	int		 swap;		/* stat(swapbuf) */
};

static void
child_signal(void *arg, void *result)
{
	struct sig_arg *a = arg;
	struct one_res *r = result;
	struct sigaction sa;
	struct stat sb;

	memset(&sa, 0, sizeof(sa));
	/* Caught: the handler only matters to the swap case. */
	sa.sa_handler = on_usr1;
	sa.sa_flags = a->restart ? SA_RESTART : 0;
	(void)sigaction(SIGUSR1, &sa, NULL);
	memcpy(swapbuf, "rt-swap-A", sizeof("rt-swap-A"));
	if (a->rename)
		r->r[0].rv = rename("rt-ren-a", "rt-ren-b");
	else if (a->swap)
		r->r[0].rv = stat(swapbuf, &sb);
	else
		r->r[0].rv = stat("rt-sig", &sb);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
}

/* Hold the first event matching match, release later ones, signal. */
static void
signal_during(struct dqt_ctl *c, struct dqt_achild *ch, struct sig_arg *a,
    const char *match, struct one_res *r)
    __requires_unlocked(c->mtx)
{

	dqt_resolve_hold(c, match, 0);
	dqt_attach_spawn(c, ch, child_signal, a);
	ATF_REQUIRE(dqt_wait_held(c, 1, DQT_WAIT_MS));
	dqt_resolve_hold(c, "", 0);
	ATF_REQUIRE_EQ(0, pdkill(ch->pd, SIGUSR1));
	memset(r, 0, sizeof(*r));
	dqt_attach_collect(ch, r, sizeof(*r));
	ATF_CHECK(dqt_wait_interrupts(c, 1, DQT_WAIT_MS));
	dqt_lock(c);
	ATF_CHECK_EQ(c->held[0].id, c->interrupted[0]);
	dqt_unlock(c);
}

ATF_TC(signal_restart_rules);
ATF_TC_HEAD(signal_restart_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "a caught signal during a lookup's first "
	    "consultation: with SA_RESTART the syscall restarts and posts again "
	    "(the abandoned event gets INTERRUPT), without it EINTR; rename "
	    "never restarts (EINTR, nothing renamed)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(signal_restart_rules, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sig_arg a;
	struct one_res r;
	int fd;

	dqt_init(&c);
	memset(&a, 0, sizeof(a));
	a.restart = 1;
	signal_during(&c, &ch, &a, "rt-sig", &r);
	ATF_CHECK_EQ(ENOENT, r.r[0].err);	/* restarted and PASSed */
	ATF_CHECK_EQ(2, dqt_count_resolve(&c, "rt-sig", DQ_ROP_STAT));
	dqt_fini(&c);

	dqt_init(&c);
	a.restart = 0;
	signal_during(&c, &ch, &a, "rt-sig", &r);
	ATF_CHECK_EQ(EINTR, r.r[0].err);
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-sig", DQ_ROP_STAT));
	dqt_fini(&c);

	fd = open("rt-ren-a", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	(void)close(fd);
	dqt_init(&c);
	a.restart = 1;
	a.rename = 1;
	signal_during(&c, &ch, &a, "rt-ren", &r);
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ(EINTR, r.r[0].err);
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-ren-b", DQ_ROP_RENAME));
	ATF_CHECK_EQ(0, access("rt-ren-a", F_OK));
	ATF_CHECK_EQ(-1, access("rt-ren-b", F_OK));
	dqt_fini(&c);
}

ATF_TC(path_swap_reconsults);
ATF_TC_HEAD(path_swap_reconsults, tc)
{
	atf_tc_set_md_var(tc, "descr", "B1: the path buffer changes between "
	    "the first consultation and the restart (a signal handler rewrites "
	    "it): the restart posts a second event with the new bytes; the "
	    "first is never PASSed");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(path_swap_reconsults, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct sig_arg a;
	struct one_res r;
	int i;

	dqt_init(&c);
	memset(&a, 0, sizeof(a));
	a.restart = 1;
	a.swap = 1;
	signal_during(&c, &ch, &a, "rt-swap-A", &r);
	ATF_CHECK_EQ(ENOENT, r.r[0].err);
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-swap-A", DQ_ROP_STAT));
	i = dqt_find_resolve(&c, "rt-swap-B", DQ_ROP_STAT, 0);
	ATF_CHECK_MSG(i != -1, "the restart did not re-consult the new bytes");
	dqt_fini(&c);
}

struct depth_arg {
	struct dqt_sync	 s;
};

static void
child_depth(void *arg, void *result)
{
	struct depth_arg *a = arg;
	struct one_res *r = result;
	struct stat sb;
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0)
		_exit(stat("rt-depth-g", &sb) == -1 ? errno : 0);
	/* The grandchild's RESOLVE now fills the queue. */
	if (!dqt_sync_wait(a->s.tochild[0], 4 * DQT_WAIT_MS))
		_exit(5);
	r->r[0].rv = stat("rt-depth-c", &sb);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
	(void)waitpid(pid, &status, 0);
	r->r[1].rv = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool
pred_dropped(const struct dq_stats *st, uintptr_t n)
{

	return (st->ds_events_dropped >= n);
}

ATF_TC(depth_exhausted);
ATF_TC_HEAD(depth_exhausted, tc)
{
	atf_tc_set_md_var(tc, "descr", "a RESOLVE posted to a full queue fails "
	    "the lookup with EIO at once, counted as a drop (sequence gap)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(depth_exhausted, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct depth_arg a;
	struct one_res r;
	struct dq_stats st;

	dqt_init(&c);
	ATF_REQUIRE_EQ(0, dq_set_queue_depth(c.q, 1));
	dqt_sync_init(&a.s);
	dqt_pause(&c);
	dqt_attach_spawn(&c, &ch, child_depth, &a);
	ATF_REQUIRE(dqt_wait_stats(&c, dqt_pred_current, 1, DQT_WAIT_MS));
	dqt_sync_post(a.s.tochild[1]);
	/* The child's own lookup is refused at once (a drop). */
	ATF_CHECK(dqt_wait_stats(&c, pred_dropped, 1, DQT_WAIT_MS));
	dqt_stats(&c, &st);
	ATF_CHECK(st.ds_events_dropped >= 1);
	dqt_resume(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(EIO, r.r[0].err);
	ATF_CHECK_EQ(ENOENT, r.r[1].rv);
	dqt_fini(&c);
}

/*
 * I5: an attached process cannot gain privilege.
 */

struct i5_arg {
	int		 jid;
	int		 coredir;	/* run a crashing grandchild */
};

struct i5_res {
	char		 idout[32];
	struct dqt_rr	 setcred, jail_attach, nnp;
	int		 core_status;
};

/* Run ./rt-id -u and capture its output. */
static void
run_id(char *out, size_t outlen)
{
	int p[2], status;
	ssize_t n;
	pid_t pid;

	out[0] = '\0';
	if (pipe(p) != 0)
		return;
	pid = fork();
	if (pid == -1) {
		(void)close(p[0]);
		(void)close(p[1]);
		return;
	}
	if (pid == 0) {
		(void)dup2(p[1], STDOUT_FILENO);
		execl("./rt-id", "rt-id", "-u", (char *)NULL);
		_exit(126);
	}
	(void)close(p[1]);
	n = read(p[0], out, outlen - 1);
	out[n > 0 ? n : 0] = '\0';
	(void)close(p[0]);
	/* A child that did not exit 0 has printed no answer. */
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		out[0] = '\0';
}

static void
child_i5(void *arg, void *result)
{
	struct i5_arg *a = arg;
	struct i5_res *r = result;
	struct setcred wc;
	struct rlimit rl;
	pid_t pid;
	int status, v;

	run_id(r->idout, sizeof(r->idout));
	memset(&wc, 0, sizeof(wc));
	r->setcred.rv = setcred(0, &wc, sizeof(wc));
	r->setcred.err = r->setcred.rv == -1 ? errno : 0;
	if (a->jid > 0) {
		r->jail_attach.rv = jail_attach(a->jid);
		r->jail_attach.err = r->jail_attach.rv == -1 ? errno : 0;
	}
	r->nnp.rv = procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_STATUS, &v);
	r->nnp.err = v;
	if (a->coredir) {
		pid = fork();
		if (pid == 0) {
			rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
			(void)setrlimit(RLIMIT_CORE, &rl);
			(void)signal(SIGABRT, SIG_DFL);
			abort();
		}
		(void)waitpid(pid, &status, 0);
		r->core_status = status;
	}
}

static void
make_setid_copy(void)
{
	char buf[8192];
	ssize_t n;
	int in, out;

	in = open("/usr/bin/id", O_RDONLY);
	ATF_REQUIRE(in != -1);
	out = open("rt-id", O_CREAT | O_TRUNC | O_WRONLY, 0755);
	ATF_REQUIRE(out != -1);
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE_EQ(n, write(out, buf, (size_t)n));
	(void)close(in);
	(void)close(out);
	ATF_REQUIRE_EQ(0, chown("rt-id", 65534, 65534));
	ATF_REQUIRE_EQ(0, chmod("rt-id", 04755));
}

#define	I5_JAIL	"dqt_i5"

ATF_TC_WITH_CLEANUP(i5_no_new_privileges);
ATF_TC_HEAD(i5_no_new_privileges, tc)
{
	atf_tc_set_md_var(tc, "descr", "I5: a set-user-id image exec'd "
	    "attached runs with the unchanged uid (unattached: the owner's); "
	    "setcred(2) and jail_attach(2) are EPERM; P2_NO_NEW_PRIVS is "
	    "visible through procctl; a crash dumps no core");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(i5_no_new_privileges, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct i5_arg a;
	struct i5_res o, r;

	make_setid_copy();
	memset(&a, 0, sizeof(a));
	a.jid = jail_setv(JAIL_CREATE, "path", "/", "name", I5_JAIL,
	    "persist", NULL, NULL);
	ATF_REQUIRE_MSG(a.jid > 0, "jail %s: %s", I5_JAIL, jail_errmsg);
	a.coredir = 1;
	memset(&o, 0, sizeof(o));
	dqt_run_child(child_i5, &a, &o, sizeof(o));

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_i5, &a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	/* The oracle: unattached, the set-id copy runs as its owner. */
	ATF_REQUIRE_STREQ_MSG("65534\n", o.idout, "the work directory "
	    "ignores set-id bits: the exec row cannot be taken");
	ATF_CHECK_STREQ("0\n", r.idout);
	ATF_CHECK_EQ(-1, r.setcred.rv);
	ATF_CHECK_EQ(EPERM, r.setcred.err);
	ATF_CHECK_EQ(-1, r.jail_attach.rv);
	ATF_CHECK_EQ(EPERM, r.jail_attach.err);
	ATF_CHECK_EQ(0, jail_remove(a.jid));
	ATF_CHECK_EQ(0, r.nnp.rv);
	ATF_CHECK_EQ(PROC_NO_NEW_PRIVS_ENABLE, r.nnp.err);
	ATF_CHECK(WIFSIGNALED(r.core_status));
	ATF_CHECK_MSG(!WCOREDUMP(r.core_status), "an attached process dumped "
	    "core");
	dqt_fini(&c);
}
ATF_TC_CLEANUP(i5_no_new_privileges, tc)
{
	int jid;

	/* A persistent jail left behind would refuse the next run's create. */
	jid = jail_getid(I5_JAIL);
	if (jid > 0)
		(void)jail_remove(jid);
}

/*
 * Two-path calls: link with AT_SYMLINK_FOLLOW, renameat and linkat with an
 * absolute second path and with differing directory descriptors.  Each
 * posts exactly one event carrying both paths, and returns what the
 * unattached run returns.
 */
enum twostep { T_LINKF, T_RENAME_ABS, T_LINK_ABS, T_RENAME_FDS,
    T_LINK_FDS, T_NSTEPS };
static const char *const two_tag[T_NSTEPS] = { "rt2-linkf",
    "rt2-rabs", "rt2-labs", "rt2-rfds", "rt2-lfds" };
static const uint32_t two_op[T_NSTEPS] = { DQ_ROP_LINK, DQ_ROP_RENAME,
    DQ_ROP_LINK, DQ_ROP_RENAME, DQ_ROP_LINK };
/* The second path's own start: relative to the cwd, absolute, a dirfd. */
static const uint32_t two_start2[T_NSTEPS] = { DQ_START_REAL_CWD,
    DQ_START_REAL_ROOT, DQ_START_REAL_ROOT, DQ_START_REAL_DIRFD,
    DQ_START_REAL_DIRFD };

struct two_res {
	long		 rv[T_NSTEPS];
	int		 err[T_NSTEPS];
};

static void
child_two_path(void *arg, void *result)
{
	const char *dir = arg;
	struct two_res *r = result;
	char cwd[PATH_MAX], abs[PATH_MAX + 32];
	int d1, d2, fd;

	if (chdir(dir) != 0 || getcwd(cwd, sizeof(cwd)) == NULL)
		_exit(4);
	fd = open("rt2-src", O_CREAT | O_WRONLY, 0644);
	if (fd != -1)
		(void)close(fd);
	(void)symlink("rt2-src", "rt2-sl");
	(void)mkdir("rt2-dir", 0755);
	d1 = open(".", O_RDONLY | O_DIRECTORY);
	d2 = open("rt2-dir", O_RDONLY | O_DIRECTORY);

	/* link(2) of a symlink, following it. */
	STEP(r, T_LINKF, linkat(AT_FDCWD, "rt2-sl", AT_FDCWD, "rt2-linkf",
	    AT_SYMLINK_FOLLOW));
	/* An absolute second path. */
	(void)snprintf(abs, sizeof(abs), "%s/rt2-rabs", cwd);
	STEP(r, T_RENAME_ABS, renameat(AT_FDCWD, "rt2-linkf", AT_FDCWD, abs));
	(void)snprintf(abs, sizeof(abs), "%s/rt2-labs", cwd);
	STEP(r, T_LINK_ABS, linkat(AT_FDCWD, "rt2-src", AT_FDCWD, abs, 0));
	/* Differing directory descriptors. */
	STEP(r, T_RENAME_FDS, renameat(d1, "rt2-labs", d2, "rt2-rfds"));
	STEP(r, T_LINK_FDS, linkat(d2, "rt2-rfds", d1, "rt2-lfds", 0));
	(void)close(d1);
	(void)close(d2);
}

static void
child_two_plain(void *arg, void *result)
{

	child_two_path(arg, result);
}

ATF_TC(two_path_calls);
ATF_TC_HEAD(two_path_calls, tc)
{
	atf_tc_set_md_var(tc, "descr", "link with AT_SYMLINK_FOLLOW, renameat "
	    "and linkat with an absolute second path and with differing "
	    "directory descriptors: one event per call carrying both paths "
	    "(and the second start kind), results as unattached");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(two_path_calls, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct two_res o, a;
	int i, k, n;

	ATF_REQUIRE_EQ(0, mkdir("oracle", 0755));
	ATF_REQUIRE_EQ(0, mkdir("attached", 0755));
	memset(&o, 0, sizeof(o));
	dqt_run_child(child_two_plain, __DECONST(void *, "oracle"), &o,
	    sizeof(o));
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_two_path,
	    __DECONST(void *, "attached"));
	memset(&a, 0, sizeof(a));
	dqt_attach_collect(&ch, &a, sizeof(a));
	for (k = 0; k < T_NSTEPS; k++) {
		ATF_CHECK_EQ_MSG(o.rv[k], a.rv[k], "%s: rv attached %ld "
		    "unattached %ld", two_tag[k], a.rv[k], o.rv[k]);
		ATF_CHECK_EQ_MSG(o.err[k], a.err[k], "%s: errno attached %d "
		    "unattached %d", two_tag[k], a.err[k], o.err[k]);
		n = dqt_count_resolve(&c, two_tag[k], two_op[k]);
		ATF_CHECK_EQ_MSG(1, n, "%s: %d events of op %u", two_tag[k], n,
		    two_op[k]);
		i = dqt_find_resolve(&c, two_tag[k], two_op[k], 0);
		if (i != -1) {
			dqt_resolve_at(&c, i, &rs);
			ATF_CHECK_MSG(rs.path[0] != '\0' && rs.path2[0] != '\0',
			    "%s: path \"%s\" path2 \"%s\"", two_tag[k], rs.path,
			    rs.path2);
		}
		if (i != -1) {
			dqt_lock(&c);
			ATF_CHECK_EQ_MSG(two_start2[k], c.rs[i].start2_kind,
			    "%s: start2_kind %u want %u", two_tag[k],
			    c.rs[i].start2_kind, two_start2[k]);
			dqt_unlock(&c);
			/* Two real starts: PASS, OK or an errno (D170). */
			dqt_lock(&c);
			ATF_CHECK_EQ_MSG(DQ_RACCEPT(DQ_RESOLVE_PASS) |
			    DQ_RACCEPT(DQ_RESOLVE_OK), c.rs[i].accept,
			    "%s: drs_accept %#x", two_tag[k], c.rs[i].accept);
			dqt_unlock(&c);
		}
	}
	dqt_fini(&c);
}

/*
 * The second path of a rename is re-copied by its own lookup after the
 * consultation: a sibling thread rewrites it while the controller holds
 * the event.  The kernel must see the difference (ERELOOKUP, the rename
 * loops) and consult again with the new bytes; the PASS given for the old
 * bytes never covers the new ones.
 */
static char rv_path2[64];

struct rv_arg {
	struct dqt_sync	 s;
};

static void *
rv_rewriter(void *arg)
{
	struct rv_arg *a = arg;

	if (dqt_sync_wait(a->s.tochild[0], 4 * DQT_WAIT_MS)) {
		memcpy(rv_path2, "rt-sv-B2", sizeof("rt-sv-B2"));
		dqt_sync_post(a->s.toparent[1]);
	}
	return (NULL);
}

static void
child_rename_swap(void *arg, void *result)
{
	struct rv_arg *a = arg;
	struct one_res *r = result;
	pthread_t thr;
	int fd;

	memcpy(rv_path2, "rt-sv-B1", sizeof("rt-sv-B1"));
	fd = open("rt-sv-A", O_CREAT | O_WRONLY, 0644);
	if (fd != -1)
		(void)close(fd);
	if (pthread_create(&thr, NULL, rv_rewriter, a) != 0)
		_exit(5);
	r->r[0].rv = rename("rt-sv-A", rv_path2);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
	(void)pthread_join(thr, NULL);
}

ATF_TC(slot_revalidation);
ATF_TC_HEAD(slot_revalidation, tc)
{
	atf_tc_set_md_var(tc, "descr", "rename's second path rewritten by a "
	    "sibling thread while the controller holds the event: the kernel "
	    "re-consults with the new bytes (ERELOOKUP); refusing them fails "
	    "the rename with EACCES and creates neither name");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(slot_revalidation, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct rv_arg a;
	struct one_res r;
	int i;

	dqt_init(&c);
	dqt_sync_init(&a.s);
	dqt_resolve_hold(&c, "rt-sv-B1", 0);
	dqt_attach_spawn(&c, &ch, child_rename_swap, &a);
	ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
	dqt_lock(&c);
	ATF_REQUIRE_EQ(DQ_OP_RESOLVE, c.held[0].op);
	dqt_unlock(&c);
	/* Rewrite path2 while the event is held, then PASS the old bytes. */
	dqt_sync_post(a.s.tochild[1]);
	ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], DQT_WAIT_MS));
	/* The second consultation (the new bytes) is refused. */
	/* Refusal first, then release: no consultation slips through. */
	dqt_resolve_fail(&c, "rt-sv-B2", EACCES);
	dqt_resolve_hold(&c, "", 0);
	dqt_lock(&c);
	ATF_REQUIRE_EQ(0, dq_reply_resolve_pass(c.q, c.held[0].id));
	dqt_unlock(&c);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	i = dqt_find_resolve(&c, "rt-sv-B2", DQ_ROP_RENAME, 0);
	ATF_CHECK_MSG(i != -1, "the new second path was never consulted");
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-sv-B1", DQ_ROP_RENAME));
	/* The PASS for the old bytes covered nothing: refused, nothing moved. */
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ_MSG(EACCES, r.r[0].err, "rename: %s",
	    strerror(r.r[0].err));
	ATF_CHECK_EQ(0, access("rt-sv-A", F_OK));
	ATF_CHECK_EQ(-1, access("rt-sv-B2", F_OK));
	ATF_CHECK_EQ(-1, access("rt-sv-B1", F_OK));
	dqt_fini(&c);
}

/*
 * Kernel-consumer paths (class 2): swapon/swapoff of an md vnode device,
 * quotactl(Q_QUOTAON)'s quota file, unmount of a tmpfs, a nullfs mount's
 * mount point and target, extattrctl with a NULL file name.  A row whose
 * prerequisite is missing fails (one skip policy: a row not taken is not a
 * pass), except quotactl's, which needs a file system with quotas.
 */
#define	KC_MD_SAVED	"rt-md.unit"

struct kc_arg {
	char		 md[32];	/* /dev/mdN, or "" */
	char		 tmpfs[PATH_MAX];	/* mounted tmpfs, or "" */
	char		 nullsrc[PATH_MAX];
	char		 nullmnt[PATH_MAX];
};

struct kc_res {
	struct dqt_rr	 swapon, swapoff, quotaon, unmount, nullmount,
			 nullunmount, extattrctl;
};

static int
nullfs_mount(const char *src, const char *mnt)
{
	struct iovec iov[6];

	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "nullfs");
	iov[1].iov_len = sizeof("nullfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, mnt);
	iov[3].iov_len = strlen(mnt) + 1;
	iov[4].iov_base = __DECONST(char *, "target");
	iov[4].iov_len = sizeof("target");
	iov[5].iov_base = __DECONST(char *, src);
	iov[5].iov_len = strlen(src) + 1;
	return (nmount(iov, 6, 0));
}

static void
child_kconsumers(void *arg, void *result)
{
	struct kc_arg *a = arg;
	struct kc_res *r = result;

	if (a->md[0] != '\0') {
		DQT_RR(r->swapon, swapon(a->md));
		if (r->swapon.rv == 0)
			DQT_RR(r->swapoff, swapoff(a->md, 0));
	}
	DQT_RR(r->quotaon, quotactl(".", QCMD(Q_QUOTAON, USRQUOTA), 0,
	    __DECONST(char *, "rt-quota.user")));
	if (a->tmpfs[0] != '\0')
		DQT_RR(r->unmount, unmount(a->tmpfs, 0));
	DQT_RR(r->nullmount, nullfs_mount(a->nullsrc, a->nullmnt));
	if (r->nullmount.rv == 0)
		DQT_RR(r->nullunmount, unmount(a->nullmnt, 0));
	DQT_RR(r->extattrctl, extattrctl("rt-eactl-dir", UFS_EXTATTR_CMD_STOP, NULL, 0,
	    NULL));
}

static int
run_cmd(const char *cmd, char *out, size_t outlen)
{
	FILE *p;
	size_t n;

	p = popen(cmd, "r");
	if (p == NULL)
		return (-1);
	n = fread(out, 1, outlen - 1, p);
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '))
		out[--n] = '\0';
	return (pclose(p));
}

/* A class-2 event naming tag exists. */
static void
check_kconsumer(struct dqt_ctl *c, const char *tag, const char *what)
{
	struct dqt_resolve_seen rs;
	int i;

	for (i = dqt_find_resolve(c, tag, 0, 0); i != -1;
	    i = dqt_find_resolve(c, tag, 0, i + 1)) {
		dqt_resolve_at(c, i, &rs);
		if (rs.cls == DQ_RCLASS_KCONSUMER)
			break;
	}
	ATF_CHECK_MSG(i != -1, "%s: no class-2 RESOLVE naming \"%s\"", what,
	    tag);
	if (i != -1)
		ATF_CHECK((rs.rflags & DQ_RF_KCONSUMER) != 0 &&
		    (rs.rflags & DQ_RF_USER) == 0);
}

/* How many class-2 events of op (0: any) name tag. */
static int
count_kconsumer(struct dqt_ctl *c, const char *tag, uint32_t op)
    __requires_unlocked(c->mtx)
{
	int i, n;

	n = 0;
	dqt_lock(c);
	for (i = 0; i < c->nrs; i++) {
		if (c->rs[i].cls == DQ_RCLASS_KCONSUMER &&
		    (op == 0 || c->rs[i].op == op) &&
		    strstr(c->rs[i].path, tag) != NULL)
			n++;
	}
	dqt_unlock(c);
	return (n);
}

ATF_TC_WITH_CLEANUP(kernel_consumer_rows);
ATF_TC_HEAD(kernel_consumer_rows, tc)
{
	atf_tc_set_md_var(tc, "descr", "class-2 consultations: swapon and "
	    "swapoff of an md device, quotactl Q_QUOTAON's quota file (UFS), "
	    "unmount of a tmpfs, a nullfs mount's mount point and target, "
	    "extattrctl with a NULL file name (no EFAULT)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(kernel_consumer_rows, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct kc_arg a;
	struct kc_res r;
	char cwd[PATH_MAX], out[64], cmd[PATH_MAX + 64];
	FILE *fp;
	int fd;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	memset(&a, 0, sizeof(a));
	/* An md vnode device to swap on. */
	fd = open("rt-swapfile", O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 8 * 1024 * 1024));
	(void)close(fd);
	if (run_cmd("mdconfig -a -t vnode -f rt-swapfile 2>/dev/null", out,
	    sizeof(out)) == 0 && strncmp(out, "md", 2) == 0) {
		(void)snprintf(a.md, sizeof(a.md), "/dev/%s", out);
		fp = fopen(KC_MD_SAVED, "w");
		if (fp != NULL) {
			(void)fprintf(fp, "%s\n", out);
			(void)fclose(fp);
		}
	} else
		ATF_CHECK_MSG(false, "row not taken: no md device for swapon "
		    "(%s)", out);
	/* A tmpfs to unmount. */
	ATF_REQUIRE_EQ(0, mkdir("rt-tmpfs", 0755));
	if (run_cmd("mount -t tmpfs tmpfs rt-tmpfs 2>&1", out,
	    sizeof(out)) == 0)
		(void)snprintf(a.tmpfs, sizeof(a.tmpfs), "%s/rt-tmpfs", cwd);
	else
		ATF_CHECK_MSG(false, "row not taken: no tmpfs to unmount (%s)",
		    out);
	ATF_REQUIRE_EQ(0, mkdir("rt-nullsrc", 0755));
	ATF_REQUIRE_EQ(0, mkdir("rt-nullmnt", 0755));
	ATF_REQUIRE_EQ(0, mkdir("rt-eactl-dir", 0755));
	(void)snprintf(a.nullsrc, sizeof(a.nullsrc), "%s/rt-nullsrc", cwd);
	(void)snprintf(a.nullmnt, sizeof(a.nullmnt), "%s/rt-nullmnt", cwd);

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_kconsumers, &a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));

	if (a.md[0] != '\0') {
		ATF_CHECK_EQ_MSG(0, r.swapon.rv, "swapon %s: %s", a.md,
		    strerror(r.swapon.err));
		check_kconsumer(&c, a.md + 5, "swapon");
		if (r.swapon.rv == 0) {
			ATF_CHECK_EQ(0, r.swapoff.rv);
			/* swapon's event and swapoff's own. */
			ATF_CHECK_EQ_MSG(2, count_kconsumer(&c, a.md + 5, 0),
			    "class-2 events naming %s: %d (want swapon's and "
			    "swapoff's)", a.md, count_kconsumer(&c, a.md + 5, 0));
		}
	}
	/*
	 * The quota file is opened by the file system's quotaon (ufs_quota.c),
	 * so the row needs UFS with options QUOTA.  The work directory of
	 * the test guests has no quotas: this row is not taken there, and
	 * says so in the output.
	 */
	if (r.quotaon.rv == -1 && (r.quotaon.err == EOPNOTSUPP ||
	    r.quotaon.err == EINVAL))
		printf("row not taken: quotas unavailable here (%s)\n",
		    strerror(r.quotaon.err));
	else
		check_kconsumer(&c, "rt-quota.user", "quotactl Q_QUOTAON");
	if (a.tmpfs[0] != '\0') {
		ATF_CHECK_EQ_MSG(0, r.unmount.rv, "unmount: %s",
		    strerror(r.unmount.err));
		check_kconsumer(&c, "rt-tmpfs", "unmount");
	}
	ATF_CHECK_EQ_MSG(0, r.nullmount.rv, "nullfs mount: %s",
	    strerror(r.nullmount.err));
	check_kconsumer(&c, "rt-nullmnt", "nullfs mount point");
	check_kconsumer(&c, "rt-nullsrc", "nullfs target");
	ATF_CHECK_MSG(r.extattrctl.err != EFAULT, "extattrctl with a NULL "
	    "file name: EFAULT");
	ATF_CHECK_EQ_MSG(1, count_kconsumer(&c, "rt-eactl-dir",
	    DQ_ROP_INTERNAL), "extattrctl: no class-2 INTERNAL event naming "
	    "its directory");
	dqt_fini(&c);
	(void)snprintf(cmd, sizeof(cmd), "umount -f %s/rt-nullmnt "
	    "%s/rt-tmpfs 2>/dev/null", cwd, cwd);
	(void)system(cmd);
}
ATF_TC_CLEANUP(kernel_consumer_rows, tc)
{
	char unit[32], cmd[128];
	FILE *fp;

	(void)system("umount -f rt-nullmnt rt-tmpfs 2>/dev/null");
	(void)system("swapoff /dev/$(cat " KC_MD_SAVED " 2>/dev/null) "
	    "2>/dev/null");
	fp = fopen(KC_MD_SAVED, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%31s", unit) == 1) {
		(void)snprintf(cmd, sizeof(cmd), "mdconfig -d -u %s", unit);
		(void)system(cmd);
	}
	(void)fclose(fp);
}

/*
 * Round-5 rows: what an attached caller may not hand the kernel by path
 * (an md vnode attach, an imgact_binmisc interpreter: EPERM), unmount of a
 * path that does not resolve (its error, no fallback to matching the
 * mount-on name), and fhlink posting LINK for its new name.
 */
struct r5_arg {
	fhandle_t	 fh;
	int		 have_fh;
	int		 have_binmisc;
};

struct r5_res {
	struct dqt_rr	 mdattach, binmisc, unmount, fhlink;
};

static void
child_round5(void *arg, void *result)
{
	struct r5_arg *a = arg;
	struct r5_res *r = result;
	struct md_ioctl mdio;
	ximgact_binmisc_entry_t xbe;
	char file[] = "rt-mdfile";
	int fd;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	if (fd != -1) {
		memset(&mdio, 0, sizeof(mdio));
		mdio.md_version = MDIOVERSION;
		mdio.md_type = MD_VNODE;
		mdio.md_file = file;
		mdio.md_options = MD_AUTOUNIT | MD_CLUSTER | MD_READONLY;
		/* A valid size, as mdconfig sets it, so only the refusal can fail it. */
		mdio.md_mediasize = 1024 * 1024;
		mdio.md_sectorsize = 512;
		DQT_RR(r->mdattach, ioctl(fd, MDIOCATTACH, &mdio));
		if (r->mdattach.rv == 0) {
			/* Not refused: undo it. */
			(void)ioctl(fd, MDIOCDETACH, &mdio);
		}
		(void)close(fd);
	} else {
		r->mdattach.rv = -2;
		r->mdattach.err = errno;
	}
	if (a->have_binmisc) {
		memset(&xbe, 0, sizeof(xbe));
		xbe.xbe_version = IBE_VERSION;
		xbe.xbe_flags = IBF_ENABLED;
		(void)strlcpy(xbe.xbe_name, "dqt_binmisc", IBE_NAME_MAX);
		(void)strlcpy(xbe.xbe_interpreter, "/bin/sh",
		    IBE_INTERP_LEN_MAX);
		memcpy(xbe.xbe_magic, "DQTBM1", 6);
		xbe.xbe_msize = 6;
		DQT_RR(r->binmisc, sysctlbyname(IBE_SYSCTL_NAME_ADD, NULL, NULL, &xbe,
		    sizeof(xbe)));
		if (r->binmisc.rv == 0)
			(void)sysctlbyname(IBE_SYSCTL_NAME_REMOVE, NULL, NULL,
			    &xbe, sizeof(xbe));
	}
	DQT_RR(r->unmount, unmount("rt-no-such-mount/x", 0));
	if (a->have_fh)
		DQT_RR(r->fhlink, fhlink(&a->fh, "rt-fh-link"));
}

ATF_TC(attached_kernel_paths);
ATF_TC_HEAD(attached_kernel_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "an attached caller is refused an md "
	    "vnode attach and an imgact_binmisc add with EPERM; unmount of a "
	    "path that does not resolve returns that error without matching "
	    "the mount-on name; fhlink posts LINK for its new name");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(attached_kernel_paths, tc)
{
	struct dqt_resolve_seen rs;
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct r5_arg a;
	struct r5_res r;
	size_t len;
	int fd, i;

	memset(&a, 0, sizeof(a));
	fd = open("rt-mdfile", O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 1024 * 1024));
	(void)close(fd);
	fd = open("rt-fh-src", O_CREAT | O_RDWR, 0644);
	ATF_REQUIRE(fd != -1);
	(void)close(fd);
	a.have_fh = getfh("rt-fh-src", &a.fh) == 0;
	ATF_CHECK_MSG(a.have_fh, "row not taken: getfh: %s", strerror(errno));
	len = 0;
	a.have_binmisc = sysctlbyname(IBE_SYSCTL_NAME_LIST, NULL, &len, NULL,
	    0) == 0;
	ATF_CHECK_MSG(a.have_binmisc, "row not taken: imgact_binmisc is not "
	    "loaded");

	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, child_round5, &a);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	if (r.mdattach.rv == -2)
		ATF_CHECK_MSG(false, "row not taken: no /dev/mdctl (%s)",
		    strerror(r.mdattach.err));
	else {
		ATF_CHECK_EQ(-1, r.mdattach.rv);
		ATF_CHECK_EQ_MSG(EPERM, r.mdattach.err, "md vnode attach: %s",
		    strerror(r.mdattach.err));
	}
	if (a.have_binmisc) {
		ATF_CHECK_EQ(-1, r.binmisc.rv);
		ATF_CHECK_EQ_MSG(EPERM, r.binmisc.err, "binmisc add: %s",
		    strerror(r.binmisc.err));
	}
	ATF_CHECK_EQ(-1, r.unmount.rv);
	ATF_CHECK_EQ_MSG(ENOENT, r.unmount.err, "unmount: %s",
	    strerror(r.unmount.err));
	if (a.have_fh) {
		ATF_CHECK_EQ_MSG(0, r.fhlink.rv, "fhlink: %s",
		    strerror(r.fhlink.err));
		i = dqt_find_resolve(&c, "rt-fh-link", DQ_ROP_LINK, 0);
		ATF_CHECK_MSG(i != -1, "fhlink posted no LINK");
		if (i != -1) {
			dqt_resolve_at(&c, i, &rs);
			ATF_CHECK_EQ(DQ_RCLASS_USER, rs.cls);
		}
		ATF_CHECK_EQ(0, access("rt-fh-link", F_OK));
	}
	dqt_fini(&c);
}

/*
 * Consult-ahead (swapon): the path is consulted before the swap code looks
 * it up; if a sibling thread changes the path bytes, or the working
 * directory a relative path starts from, between the consultation and
 * the use, the call fails with EIO and nothing is added.
 */
#define	AH_MD_SAVED	"rt-ahead-md.unit"

static char ah_path[64];

struct ah_arg {
	struct dqt_sync	 s;
	int		 chdir_variant;	/* else rewrite the bytes */
	char		 md[32];	/* mdN */
};

static void *
ah_sibling(void *arg)
{
	struct ah_arg *a = arg;

	if (dqt_sync_wait(a->s.tochild[0], 4 * DQT_WAIT_MS)) {
		if (a->chdir_variant)
			(void)chdir("/");
		else
			(void)strlcpy(ah_path, "/dev/null", sizeof(ah_path));
		dqt_sync_post(a->s.toparent[1]);
	}
	return (NULL);
}

static void
child_ahead(void *arg, void *result)
{
	struct ah_arg *a = arg;
	struct one_res *r = result;
	pthread_t thr;

	if (a->chdir_variant) {
		if (chdir("/dev") != 0)
			_exit(4);
		(void)strlcpy(ah_path, a->md, sizeof(ah_path));
	} else
		(void)snprintf(ah_path, sizeof(ah_path), "/dev/%s", a->md);
	if (pthread_create(&thr, NULL, ah_sibling, a) != 0)
		_exit(5);
	r->r[0].rv = swapon(ah_path);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
	(void)pthread_join(thr, NULL);
	if (r->r[0].rv == 0) {
		char p[64];

		(void)snprintf(p, sizeof(p), "/dev/%s", a->md);
		(void)swapoff(p, 0);
	}
}

static bool
swap_has(const char *md)
{
	char cmd[128], out[256];

	(void)snprintf(cmd, sizeof(cmd), "swapctl -l 2>/dev/null | grep -w %s",
	    md);
	return (run_cmd(cmd, out, sizeof(out)) == 0 && out[0] != '\0');
}

ATF_TC_WITH_CLEANUP(swapon_consult_ahead);
ATF_TC_HEAD(swapon_consult_ahead, tc)
{
	atf_tc_set_md_var(tc, "descr", "swapon's path consulted ahead: a "
	    "sibling thread that rewrites the path bytes, or changes the "
	    "working directory of a relative path, while the controller holds "
	    "the consultation makes swapon fail with EIO, nothing added");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(swapon_consult_ahead, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct ah_arg a;
	struct one_res r;
	char out[64];
	FILE *fp;
	int fd, k;

	fd = open("rt-ahead-swap", O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 8 * 1024 * 1024));
	(void)close(fd);
	if (run_cmd("mdconfig -a -t vnode -f rt-ahead-swap 2>/dev/null", out,
	    sizeof(out)) != 0 || strncmp(out, "md", 2) != 0)
		atf_tc_fail("no md device");
	fp = fopen(AH_MD_SAVED, "w");
	if (fp != NULL) {
		(void)fprintf(fp, "%s\n", out);
		(void)fclose(fp);
	}
	for (k = 0; k < 2; k++) {
		memset(&a, 0, sizeof(a));
		a.chdir_variant = k;
		(void)strlcpy(a.md, out, sizeof(a.md));
		dqt_sync_init(&a.s);
		dqt_init(&c);
		dqt_resolve_hold(&c, a.md, 0);
		dqt_attach_spawn(&c, &ch, child_ahead, &a);
		ATF_REQUIRE(dqt_wait_held(&c, 1, DQT_WAIT_MS));
		dqt_sync_post(a.s.tochild[1]);
		ATF_REQUIRE(dqt_sync_wait(a.s.toparent[0], DQT_WAIT_MS));
		dqt_resolve_hold(&c, "", 0);
		dqt_lock(&c);
		ATF_REQUIRE_EQ(0, dq_reply_resolve_pass(c.q, c.held[0].id));
		dqt_unlock(&c);
		memset(&r, 0, sizeof(r));
		dqt_attach_collect(&ch, &r, sizeof(r));
		ATF_CHECK_EQ_MSG(-1, r.r[0].rv, "%s variant: swapon succeeded",
		    k ? "chdir" : "rewrite");
		ATF_CHECK_EQ_MSG(EIO, r.r[0].err, "%s variant: %s",
		    k ? "chdir" : "rewrite", strerror(r.r[0].err));
		ATF_CHECK_MSG(!swap_has(a.md), "%s added as swap", a.md);
		dqt_fini(&c);
	}
}
ATF_TC_CLEANUP(swapon_consult_ahead, tc)
{
	char unit[32], cmd[128];
	FILE *fp;

	fp = fopen(AH_MD_SAVED, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%31s", unit) == 1) {
		(void)snprintf(cmd, sizeof(cmd), "swapoff /dev/%s 2>/dev/null; "
		    "mdconfig -d -u %s", unit, unit);
		(void)system(cmd);
	}
	(void)fclose(fp);
}

static void
child_unmount_refused(void *arg __unused, void *result)
{
	struct one_res *r = result;

	r->r[0].rv = unmount("rt-umnt", 0);
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
}

ATF_TC_WITH_CLEANUP(unmount_refused);
ATF_TC_HEAD(unmount_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "a controller refusing an unmount's "
	    "path (EACCES) keeps the file system mounted: no fallback to the "
	    "mount-on name bypasses the answer");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(unmount_refused, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;
	struct statfs sfs;
	char out[128];

	ATF_REQUIRE_EQ(0, mkdir("rt-umnt", 0755));
	if (run_cmd("mount -t tmpfs tmpfs rt-umnt 2>&1", out, sizeof(out)) != 0)
		atf_tc_fail("no tmpfs: %s", out);
	dqt_init(&c);
	dqt_resolve_fail(&c, "rt-umnt", EACCES);
	dqt_attach_spawn(&c, &ch, child_unmount_refused, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ_MSG(EACCES, r.r[0].err, "unmount: %s",
	    strerror(r.r[0].err));
	ATF_REQUIRE_EQ(0, statfs("rt-umnt", &sfs));
	ATF_CHECK_STREQ("tmpfs", sfs.f_fstypename);
	ATF_CHECK(dqt_count_resolve(&c, "rt-umnt", 0) >= 1);
	dqt_fini(&c);
}
ATF_TC_CLEANUP(unmount_refused, tc)
{

	(void)system("umount -f rt-umnt 2>/dev/null");
}

static void
child_link_again(void *arg __unused, void *result)
{
	struct one_res *r = result;

	r->r[0].rv = link("rt-lagain-src", "rt-lagain-dst");
	r->r[0].err = r->r[0].rv == -1 ? errno : 0;
}

ATF_TC(link_eagain_eio);
ATF_TC_HEAD(link_eagain_eio, tc)
{
	atf_tc_set_md_var(tc, "descr", "an EAGAIN answer to link (which "
	    "loops on EAGAIN internally) reaches the caller as EIO after "
	    "exactly one event");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "60");
}
ATF_TC_BODY(link_eagain_eio, tc)
{
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct one_res r;
	int fd;

	fd = open("rt-lagain-src", O_CREAT | O_WRONLY, 0644);
	ATF_REQUIRE(fd != -1);
	(void)close(fd);
	dqt_init(&c);
	dqt_resolve_fail(&c, "rt-lagain", EAGAIN);
	dqt_attach_spawn(&c, &ch, child_link_again, NULL);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	ATF_CHECK_EQ(-1, r.r[0].rv);
	ATF_CHECK_EQ_MSG(EIO, r.r[0].err, "link: %s", strerror(r.r[0].err));
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "rt-lagain", DQ_ROP_LINK));
	ATF_CHECK_EQ(-1, access("rt-lagain-dst", F_OK));
	dqt_fini(&c);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, families);
	ATF_TP_ADD_TC(tp, errno_answers);
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, deadline_eio);
	ATF_TP_ADD_TC(tp, controller_exit_fails_closed);
	ATF_TP_ADD_TC(tp, signal_restart_rules);
	ATF_TP_ADD_TC(tp, path_swap_reconsults);
	ATF_TP_ADD_TC(tp, depth_exhausted);
	ATF_TP_ADD_TC(tp, i5_no_new_privileges);
	ATF_TP_ADD_TC(tp, two_path_calls);
	ATF_TP_ADD_TC(tp, slot_revalidation);
	ATF_TP_ADD_TC(tp, kernel_consumer_rows);
	ATF_TP_ADD_TC(tp, attached_kernel_paths);
	ATF_TP_ADD_TC(tp, swapon_consult_ahead);
	ATF_TP_ADD_TC(tp, unmount_refused);
	ATF_TP_ADD_TC(tp, link_eagain_eio);
	return (atf_no_error());
}
