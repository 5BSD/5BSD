/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * ".." does not need search permission on the directory it starts from
 * when the walk stays at a root or crosses from a mount root to the
 * covered vnode: vfs_lookup() handles those before it searches.  The
 * answer must not depend on whether the lookup runs lockless.  Each case
 * runs with vfs.cache.param.fast_lookup on and off as uid 65534, and
 * prints whether lockless lookup was in force
 * (vfs.cache.param.fast_lookup_active, where the kernel has it).
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	FAST_LOOKUP		"vfs.cache.param.fast_lookup"
#define	FAST_LOOKUP_ACTIVE	"vfs.cache.param.fast_lookup_active"
#define	NOBODY			65534

static void
set_fast_lookup(int v)
{

	ATF_REQUIRE_MSG(sysctlbyname(FAST_LOOKUP, NULL, NULL, &v,
	    sizeof(v)) == 0, "set %s=%d: %s", FAST_LOOKUP, v, strerror(errno));
}

static void
cleanup_fast_lookup(void)
{
	int v = 1;

	(void)sysctlbyname(FAST_LOOKUP, NULL, NULL, &v, sizeof(v));
}

static void
report_mode(int v)
{
	size_t len;
	int active;

	len = sizeof(active);
	if (sysctlbyname(FAST_LOOKUP_ACTIVE, &active, &len, NULL, 0) == 0)
		printf("%s=%d: lockless lookup %s\n", FAST_LOOKUP, v,
		    active ? "active" : "not active");
	else
		printf("%s=%d: %s not present\n", FAST_LOOKUP, v,
		    FAST_LOOKUP_ACTIVE);
}

/*
 * Run fn in a child; the child's exit status is 0 on success, else the
 * errno of the failing call (or 200+ for a setup step).
 */
static int
in_child(int (*fn)(void *), void *arg)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(fn(arg));
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

/* B-29: ".." from an unsearchable mount root. */
struct mnt_arg {
	int		mfd;
	struct stat	want;
};

static int
mnt_dotdot(void *argp)
{
	struct mnt_arg *arg = argp;
	struct stat sb;

	if (setgid(NOBODY) != 0 || setuid(NOBODY) != 0)
		return (201);
	if (fstatat(arg->mfd, "..", &sb, 0) != 0)
		return (errno);
	if (sb.st_dev != arg->want.st_dev || sb.st_ino != arg->want.st_ino)
		return (202);
	return (0);
}

ATF_TC_WITH_CLEANUP(mount_root_dotdot);
ATF_TC_HEAD(mount_root_dotdot, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "fstatat(mount root, \"..\") succeeds without search permission "
	    "on the mount root, lockless or not");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(mount_root_dotdot, tc)
{
	struct mnt_arg arg;
	int mode, rc;

	ATF_REQUIRE(mkdir("S", 0755) == 0);
	ATF_REQUIRE(chmod(".", 0755) == 0);
	ATF_REQUIRE(mkdir("S/m", 0755) == 0);
	ATF_REQUIRE_MSG(system("mount -t tmpfs tmpfs S/m") == 0,
	    "mount tmpfs failed");
	ATF_REQUIRE(chown("S/m", 0, 0) == 0);
	ATF_REQUIRE(chmod("S/m", 0700) == 0);
	ATF_REQUIRE(stat("S", &arg.want) == 0);
	arg.mfd = open("S/m", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(arg.mfd >= 0);
	for (mode = 1; mode >= 0; mode--) {
		set_fast_lookup(mode);
		report_mode(mode);
		/* Twice: the first walk may only fill the name cache. */
		(void)in_child(mnt_dotdot, &arg);
		rc = in_child(mnt_dotdot, &arg);
		ATF_CHECK_MSG(rc == 0, "fast_lookup=%d: fstatat(mfd, \"..\") "
		    "as uid %d: %s (%d), want success with the identity of S",
		    mode, NOBODY, rc < 200 ? strerror(rc) : "setup", rc);
	}
	close(arg.mfd);
	cleanup_fast_lookup();
}
ATF_TC_CLEANUP(mount_root_dotdot, tc)
{

	cleanup_fast_lookup();
	(void)unmount("S/m", MNT_FORCE);
}

/* B-30: "/.." at an unsearchable process root. */
struct root_arg {
	char		root[PATH_MAX];
	struct stat	want;
};

static int
root_dotdot(void *argp)
{
	struct root_arg *arg = argp;
	struct stat sb;

	if (chroot(arg->root) != 0)
		return (203);
	if (setgid(NOBODY) != 0 || setuid(NOBODY) != 0)
		return (201);
	if (stat("/..", &sb) != 0)
		return (errno);
	if (sb.st_dev != arg->want.st_dev || sb.st_ino != arg->want.st_ino)
		return (202);
	return (0);
}

ATF_TC_WITH_CLEANUP(chroot_root_dotdot);
ATF_TC_HEAD(chroot_root_dotdot, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "stat(\"/..\") at a 0700 root-owned chroot succeeds as another "
	    "user, lockless or not");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(chroot_root_dotdot, tc)
{
	struct root_arg arg;
	int mode, rc;

	ATF_REQUIRE(mkdir("R", 0700) == 0);
	ATF_REQUIRE(chown("R", 0, 0) == 0);
	ATF_REQUIRE(chmod("R", 0700) == 0);
	ATF_REQUIRE(realpath("R", arg.root) != NULL);
	ATF_REQUIRE(stat("R", &arg.want) == 0);
	for (mode = 1; mode >= 0; mode--) {
		set_fast_lookup(mode);
		report_mode(mode);
		(void)in_child(root_dotdot, &arg);
		rc = in_child(root_dotdot, &arg);
		ATF_CHECK_MSG(rc == 0, "fast_lookup=%d: stat(\"/..\") in a "
		    "chroot as uid %d: %s (%d), want success with the identity "
		    "of the root", mode, NOBODY,
		    rc < 200 ? strerror(rc) : "setup", rc);
	}
	cleanup_fast_lookup();
}
ATF_TC_CLEANUP(chroot_root_dotdot, tc)
{

	cleanup_fast_lookup();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mount_root_dotdot);
	ATF_TP_ADD_TC(tp, chroot_root_dotdot);
	return (atf_no_error());
}
