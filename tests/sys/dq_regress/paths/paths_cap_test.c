/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Capsicum and beneath-only lookups on the path calls.
 *
 * What it tries to break: namei_setup gained a consultation after "every
 * capability-mode refusal" and a served-start branch; dqres pre-checks a
 * posted path against the same rules (vfs.lookup_cap_dotdot, STRICTREL,
 * BENEATH).  For an unattached process namei_setup's own checks must give
 * 3f330ee172d's answers: ECAPMODE for AT_FDCWD in capability mode,
 * ENOTCAPABLE for absolute paths and for ".." escaping the start, the
 * empty-path ENOENT before any of them, rights checks (with CAP_LOOKUP
 * added) before the lookup, vfs.lookup_cap_dotdot=0 refusing every ".."
 * in capability mode and for limited descriptors but not for
 * O_RESOLVE_BENEATH alone, and the target-side rights of renameat/linkat.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "paths_common.h"

#define	DOTDOT	"vfs.lookup_cap_dotdot"

/* In a child: report the first failed expectation by line and exit. */
#define	C_ERR(call, err) do {						\
	long _r;							\
									\
	errno = 0;							\
	_r = (long)(call);						\
	if (_r != -1 || errno != (err)) {				\
		fprintf(stderr, "line %d: %s: %ld errno %d, want %d\n",	\
		    __LINE__, #call, _r, errno, (int)(err));		\
		failures++;						\
	}								\
} while (0)

#define	C_OK(call) do {							\
	long _r;							\
									\
	errno = 0;							\
	_r = (long)(call);						\
	if (_r == -1) {							\
		fprintf(stderr, "line %d: %s: errno %d, want success\n",\
		    __LINE__, #call, errno);				\
		failures++;						\
	}								\
} while (0)

static int failures;

static void
in_child(void (*fn)(void))
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		failures = 0;
		fn();
		_exit(failures > 100 ? 100 : failures);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child: status %#x (%d failed expectations; see stderr)", status,
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

static void
tree(void)
{

	pc_mkfile("outside", "o\n");
	pc_mkdir("top");
	pc_mkdir("top/sub");
	pc_mkfile("top/f", "f\n");
	pc_mkfile("top/sub/g", "g\n");
	pc_symlink("../outside", "top/up");
	pc_symlink("/", "top/abs");
	pc_symlink("../f", "top/sub/back");
	pc_symlink("sub/back", "top/chain");
}

static int
opened(int dfd, const char *path, int flags)
{
	int fd;

	fd = openat(dfd, path, flags, 0644);
	if (fd >= 0)
		close(fd);
	return (fd < 0 ? -1 : 0);
}

static void
child_capmode(void)
{
	struct stat sb;
	char buf[64];
	int dfd, fd;

	dfd = open("top", O_DIRECTORY | O_RDONLY);
	if (dfd < 0 || cap_enter() != 0)
		_exit(99);
	/* AT_FDCWD: ECAPMODE from namei_setup. */
	C_ERR(openat(AT_FDCWD, "top/f", O_RDONLY), ECAPMODE);
	C_ERR(openat(AT_FDCWD, "/", O_RDONLY), ECAPMODE);
	C_ERR(open("top/f", O_RDONLY), ECAPMODE);
	C_ERR(fstatat(AT_FDCWD, "top/f", &sb, 0), ECAPMODE);
	C_ERR(faccessat(AT_FDCWD, "top", F_OK, 0), ECAPMODE);
	C_ERR(mkdirat(AT_FDCWD, "newd", 0755), ECAPMODE);
	C_ERR(unlinkat(AT_FDCWD, "outside", 0), ECAPMODE);
	C_ERR(readlinkat(AT_FDCWD, "top/up", buf, sizeof(buf)), ECAPMODE);
	C_ERR(fstatat(AT_FDCWD, "", &sb, AT_EMPTY_PATH), ECAPMODE);
	/*
	 * The empty-path ENOENT comes before namei_setup, so before the
	 * capability-mode test.
	 */
	C_ERR(openat(AT_FDCWD, "", O_RDONLY), ENOENT);
	C_ERR(fstatat(AT_FDCWD, "", &sb, 0), ENOENT);
	/* ...and the path copy before that. */
	C_ERR(openat(AT_FDCWD, NULL, O_RDONLY), EFAULT);
	/* Absolute paths relative to a descriptor: ENOTCAPABLE. */
	C_ERR(openat(dfd, "/", O_RDONLY), ENOTCAPABLE);
	C_ERR(fstatat(dfd, "//top", &sb, 0), ENOTCAPABLE);
	C_ERR(mkdirat(dfd, "/x", 0755), ENOTCAPABLE);
	/* ".." escaping the start (vfs.lookup_cap_dotdot=1 by default). */
	C_ERR(openat(dfd, "..", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(dfd, "../outside", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(dfd, "sub/../../outside", O_RDONLY), ENOTCAPABLE);
	C_ERR(fstatat(dfd, "sub/../..", &sb, 0), ENOTCAPABLE);
	/* Links leaving the start. */
	C_ERR(openat(dfd, "up", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(dfd, "abs", O_RDONLY), ENOTCAPABLE);
	/* Inside the start everything works. */
	C_OK(opened(dfd, "f", O_RDONLY));
	C_OK(opened(dfd, "sub/back", O_RDONLY));
	C_OK(opened(dfd, "chain", O_RDONLY));
	C_OK(fstatat(dfd, "", &sb, AT_EMPTY_PATH));
	C_OK(fstatat(dfd, "sub/..", &sb, 0));
	C_OK(mkdirat(dfd, "newd", 0755));
	C_OK(symlinkat("/anywhere", dfd, "newd/s"));
	C_OK(readlinkat(dfd, "newd/s", buf, sizeof(buf)));
	C_ERR(fstatat(dfd, "newd/s", &sb, 0), ENOTCAPABLE);
	C_OK(unlinkat(dfd, "newd/s", 0));
	C_OK(unlinkat(dfd, "newd", AT_REMOVEDIR));
	C_OK(renameat(dfd, "f", dfd, "f2"));
	C_OK(linkat(dfd, "f2", dfd, "f3", 0));
	C_OK(fchmodat(dfd, "f3", 0600, 0));
	C_OK(utimensat(dfd, "f3", NULL, 0));
	C_OK(faccessat(dfd, "f3", R_OK, 0));
	C_OK(unlinkat(dfd, "f3", 0));
	C_OK(renameat(dfd, "f2", dfd, "f"));
	/* Two paths: each is checked when its lookup runs. */
	C_ERR(renameat(dfd, "missing", AT_FDCWD, "x"), ENOENT);
	C_ERR(renameat(dfd, "f", AT_FDCWD, "x"), ECAPMODE);
	C_ERR(renameat(AT_FDCWD, "missing", dfd, "x"), ECAPMODE);
	C_ERR(renameat(dfd, "f", dfd, "../x"), ENOTCAPABLE);
	C_ERR(linkat(dfd, "f", AT_FDCWD, "x", 0), ECAPMODE);
	C_ERR(linkat(dfd, "f", dfd, "/x", 0), ENOTCAPABLE);
	C_ERR(linkat(dfd, "missing", dfd, "/x", 0), ENOENT);
	/* An fd opened in capability mode stays usable relative to dfd. */
	fd = openat(dfd, "sub", O_DIRECTORY | O_RDONLY);
	if (fd < 0)
		failures++;
	else {
		C_ERR(openat(fd, "../f", O_RDONLY), ENOTCAPABLE);
		C_OK(opened(fd, "g", O_RDONLY));
		close(fd);
	}
}

ATF_TC_WITHOUT_HEAD(capmode);
ATF_TC_BODY(capmode, tc)
{
	struct stat sb;

	tree();
	in_child(child_capmode);
	/* Nothing escaped. */
	ATF_CHECK(stat("outside", &sb) == 0);
	ATF_CHECK(stat("newd", &sb) == -1 && errno == ENOENT);
	ATF_CHECK(stat("x", &sb) == -1 && errno == ENOENT);
	ATF_CHECK(stat("top/f", &sb) == 0);
}

static void
child_limited(void)
{
	cap_rights_t r;
	struct stat sb;
	char buf[64];
	int full, look, look2, nolook, ffd;

	full = open("top", O_DIRECTORY | O_RDONLY);
	look = open("top", O_DIRECTORY | O_RDONLY);
	nolook = open("top", O_DIRECTORY | O_RDONLY);
	ffd = open("top/f", O_RDONLY);
	if (full < 0 || look < 0 || nolook < 0 || ffd < 0)
		_exit(99);
	if (cap_rights_limit(look, cap_rights_init(&r, CAP_LOOKUP)) != 0 ||
	    cap_rights_limit(nolook, cap_rights_init(&r, CAP_READ, CAP_FSTAT,
	    CAP_FCHMOD)) != 0 ||
	    cap_rights_limit(ffd, cap_rights_init(&r, CAP_FSTAT)) != 0)
		_exit(98);
	/* The operation's right, plus CAP_LOOKUP, is needed. */
	C_ERR(openat(look, "f", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(look, "f", O_PATH), ENOTCAPABLE);
	C_ERR(fstatat(look, "f", &sb, 0), ENOTCAPABLE);
	C_ERR(faccessat(look, "f", F_OK, 0), ENOTCAPABLE);
	C_ERR(fchmodat(look, "f", 0600, 0), ENOTCAPABLE);
	C_ERR(fchownat(look, "f", (uid_t)-1, (gid_t)-1, 0), ENOTCAPABLE);
	C_ERR(chflagsat(look, "f", 0, 0), ENOTCAPABLE);
	C_ERR(utimensat(look, "f", NULL, 0), ENOTCAPABLE);
	C_ERR(mkdirat(look, "x", 0755), ENOTCAPABLE);
	C_ERR(mkfifoat(look, "x", 0644), ENOTCAPABLE);
	C_ERR(symlinkat("t", look, "x"), ENOTCAPABLE);
	C_ERR(unlinkat(look, "f", 0), ENOTCAPABLE);
	/* readlinkat needs only CAP_LOOKUP (NDINIT_AT, no rights). */
	C_OK(readlinkat(look, "up", buf, sizeof(buf)));
	/* Rights are checked before the lookup: ENOTCAPABLE, not ENOENT. */
	C_ERR(fstatat(look, "missing", &sb, 0), ENOTCAPABLE);
	C_ERR(unlinkat(look, "missing", 0), ENOTCAPABLE);
	/*
	 * Without CAP_LOOKUP nothing is looked up relative to it.  (nolook
	 * has no CAP_MKDIRAT: that right includes CAP_LOOKUP.)
	 */
	C_ERR(openat(nolook, "f", O_RDONLY), ENOTCAPABLE);
	C_ERR(fstatat(nolook, "f", &sb, 0), ENOTCAPABLE);
	C_ERR(fchmodat(nolook, "f", 0600, 0), ENOTCAPABLE);
	C_ERR(mkdirat(nolook, "x", 0755), ENOTCAPABLE);
	/* ...not even the descriptor itself with AT_EMPTY_PATH. */
	C_ERR(fstatat(nolook, "", &sb, AT_EMPTY_PATH), ENOTCAPABLE);
	C_ERR(fstatat(ffd, "", &sb, AT_EMPTY_PATH), ENOTCAPABLE);
	C_OK(fstat(ffd, &sb));
	/* An absolute path ignores the descriptor and its rights. */
	C_OK(opened(look, "/", O_RDONLY));
	C_OK(opened(nolook, "/", O_RDONLY));
	/* A limited descriptor makes the lookup strictly relative. */
	look2 = open("top", O_DIRECTORY | O_RDONLY);
	if (look2 < 0 || cap_rights_limit(look2, cap_rights_init(&r,
	    CAP_LOOKUP, CAP_READ, CAP_FSTAT)) != 0)
		_exit(97);
	close(look);
	look = look2;
	C_OK(opened(look, "f", O_RDONLY));
	C_OK(opened(look, "sub/../f", O_RDONLY));
	C_ERR(openat(look, "../outside", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(look, "up", O_RDONLY), ENOTCAPABLE);
	C_ERR(openat(look, "abs", O_RDONLY), ENOTCAPABLE);
	C_ERR(fstatat(look, "..", &sb, 0), ENOTCAPABLE);
	/* The full descriptor is not strictly relative. */
	C_OK(opened(full, "../outside", O_RDONLY));
	C_OK(opened(full, "up", O_RDONLY));
	close(full);
	close(look);
	close(nolook);
	close(ffd);
}

ATF_TC_WITHOUT_HEAD(limited_rights);
ATF_TC_BODY(limited_rights, tc)
{

	tree();
	in_child(child_limited);
}

static void
child_two_fds(void)
{
	cap_rights_t r;
	int full, nosrc, notgt, nounlink, nolinksrc, nolinktgt;

	full = open("top", O_DIRECTORY | O_RDONLY);
	nosrc = open("top", O_DIRECTORY | O_RDONLY);
	notgt = open("top", O_DIRECTORY | O_RDONLY);
	nounlink = open("top", O_DIRECTORY | O_RDONLY);
	nolinksrc = open("top", O_DIRECTORY | O_RDONLY);
	nolinktgt = open("top", O_DIRECTORY | O_RDONLY);
	if (full < 0 || nosrc < 0 || notgt < 0 || nounlink < 0 ||
	    nolinksrc < 0 || nolinktgt < 0)
		_exit(99);
	if (cap_rights_limit(nosrc, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_RENAMEAT_TARGET, CAP_UNLINKAT)) != 0 ||
	    cap_rights_limit(notgt, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_RENAMEAT_SOURCE, CAP_UNLINKAT)) != 0 ||
	    cap_rights_limit(nounlink, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_RENAMEAT_TARGET)) != 0 ||
	    cap_rights_limit(nolinksrc, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_LINKAT_TARGET)) != 0 ||
	    cap_rights_limit(nolinktgt, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_LINKAT_SOURCE)) != 0)
		_exit(98);
	/* renameat: CAP_RENAMEAT_SOURCE on the first, _TARGET on the second. */
	C_ERR(renameat(nosrc, "f", full, "g"), ENOTCAPABLE);
	C_ERR(renameat(full, "f", notgt, "g"), ENOTCAPABLE);
	C_ERR(renameat2(full, "f", notgt, "g", AT_RENAME_NOREPLACE),
	    ENOTCAPABLE);
	/* The source's rights fail before its missing name is noticed. */
	C_ERR(renameat(nosrc, "missing", full, "g"), ENOTCAPABLE);
	/* The source's lookup fails before the target's rights are checked. */
	C_ERR(renameat(full, "missing", notgt, "g"), ENOENT);
	/* Replacing an existing target also needs CAP_UNLINKAT there. */
	C_OK(renameat(full, "f", nounlink, "fresh"));
	C_ERR(renameat(full, "fresh", nounlink, "sub/g"), ENOTCAPABLE);
	C_OK(renameat(full, "fresh", nounlink, "f"));
	/* linkat */
	C_ERR(linkat(nolinksrc, "f", full, "l1", 0), ENOTCAPABLE);
	C_ERR(linkat(full, "f", nolinktgt, "l1", 0), ENOTCAPABLE);
	C_ERR(linkat(full, "missing", nolinktgt, "l1", 0), ENOENT);
	C_OK(linkat(nolinktgt, "f", nolinksrc, "l1", 0));
	C_OK(unlinkat(full, "l1", 0));
	close(full);
	close(nosrc);
	close(notgt);
	close(nounlink);
	close(nolinksrc);
	close(nolinktgt);
}

ATF_TC_WITHOUT_HEAD(two_fd_rights);
ATF_TC_BODY(two_fd_rights, tc)
{
	struct stat sb;

	tree();
	in_child(child_two_fds);
	ATF_CHECK(stat("top/f", &sb) == 0);
	ATF_CHECK(stat("top/sub/g", &sb) == 0);
	ATF_CHECK(stat("top/g", &sb) == -1 && errno == ENOENT);
}

ATF_TC_WITHOUT_HEAD(resolve_beneath_at);
ATF_TC_BODY(resolve_beneath_at, tc)
{
	struct timespec ts[2];
	struct stat sb;
	int dfd;

	tree();
	dfd = open("top", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dfd >= 0);
	ts[0].tv_sec = ts[1].tv_sec = 0;
	ts[0].tv_nsec = ts[1].tv_nsec = UTIME_OMIT;
	CHECK_OK(fstatat(dfd, "sub/../f", &sb, AT_RESOLVE_BENEATH));
	CHECK_OK(fstatat(dfd, "chain", &sb, AT_RESOLVE_BENEATH));
	CHECK_ERR(fstatat(dfd, "../outside", &sb, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(fstatat(dfd, "up", &sb, AT_RESOLVE_BENEATH), ENOTCAPABLE);
	CHECK_OK(fstatat(dfd, "up", &sb, AT_RESOLVE_BENEATH |
	    AT_SYMLINK_NOFOLLOW));
	CHECK_ERR(fstatat(dfd, "/", &sb, AT_RESOLVE_BENEATH), ENOTCAPABLE);
	CHECK_ERR(fstatat(AT_FDCWD, "/", &sb, AT_RESOLVE_BENEATH), ENOTCAPABLE);
	CHECK_ERR(fstatat(AT_FDCWD, "..", &sb, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(faccessat(dfd, "../outside", F_OK, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(fchmodat(dfd, "../outside", 0600, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(fchownat(dfd, "../outside", (uid_t)-1, (gid_t)-1,
	    AT_RESOLVE_BENEATH), ENOTCAPABLE);
	CHECK_ERR(chflagsat(dfd, "../outside", 0, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(utimensat(dfd, "../outside", ts, AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(unlinkat(dfd, "../outside", AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	CHECK_ERR(linkat(dfd, "../outside", dfd, "x", AT_RESOLVE_BENEATH),
	    ENOTCAPABLE);
	/* linkat's AT_RESOLVE_BENEATH applies to the source only. */
	CHECK_OK(linkat(dfd, "f", dfd, "../linked", AT_RESOLVE_BENEATH));
	ATF_CHECK(stat("linked", &sb) == 0);
	CHECK_OK(faccessat(dfd, "sub/g", R_OK, AT_RESOLVE_BENEATH));
	CHECK_OK(utimensat(dfd, "sub/g", ts, AT_RESOLVE_BENEATH));
	ATF_CHECK(stat("outside", &sb) == 0);
	close(dfd);
}

/* Restore vfs.lookup_cap_dotdot from the value saved in the work dir. */
static void
save_dotdot(void)
{
	FILE *f;
	int v;

	if (!pc_sysctl_get(DOTDOT, &v))
		atf_tc_skip("%s absent", DOTDOT);
	f = fopen("dotdot.orig", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%d\n", v);
	fclose(f);
}

static void
restore_dotdot(void)
{
	FILE *f;
	int v;

	f = fopen("dotdot.orig", "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d", &v) == 1)
		(void)pc_sysctl_set(DOTDOT, v);
	fclose(f);
}

static int dotdot_mode;

static void
child_dotdot(void)
{
	cap_rights_t r;
	struct stat sb;
	int dfd, look;

	dfd = open("top", O_DIRECTORY | O_RDONLY);
	look = open("top", O_DIRECTORY | O_RDONLY);
	if (dfd < 0 || look < 0 || cap_rights_limit(look, cap_rights_init(&r,
	    CAP_LOOKUP, CAP_READ, CAP_FSTAT)) != 0)
		_exit(99);
	if (dotdot_mode == 0) {
		/*
		 * vfs.lookup_cap_dotdot=0: no ".." at all for strictly
		 * relative lookups (limited descriptor, capability mode)...
		 */
		C_ERR(fstatat(look, "sub/..", &sb, 0), ENOTCAPABLE);
		C_ERR(openat(look, "sub/back", O_RDONLY), ENOTCAPABLE);
		/* ...but O_RESOLVE_BENEATH alone keeps its tracked "..". */
		C_OK(fstatat(dfd, "sub/..", &sb, AT_RESOLVE_BENEATH));
		C_OK(opened(dfd, "sub/back", O_RDONLY | O_RESOLVE_BENEATH));
		C_ERR(fstatat(dfd, "..", &sb, AT_RESOLVE_BENEATH), ENOTCAPABLE);
		/* A full descriptor outside capability mode is unaffected. */
		C_OK(fstatat(dfd, "../outside", &sb, 0));
		if (cap_enter() != 0)
			_exit(98);
		C_ERR(fstatat(dfd, "sub/..", &sb, 0), ENOTCAPABLE);
		C_ERR(opened(dfd, "sub/../f", O_RDONLY), ENOTCAPABLE);
		C_ERR(opened(dfd, "sub/back", O_RDONLY), ENOTCAPABLE);
		C_OK(opened(dfd, "sub/g", O_RDONLY));
	} else {
		C_OK(fstatat(look, "sub/..", &sb, 0));
		C_OK(opened(look, "sub/back", O_RDONLY));
		C_ERR(fstatat(look, "..", &sb, 0), ENOTCAPABLE);
		if (cap_enter() != 0)
			_exit(98);
		C_OK(fstatat(dfd, "sub/..", &sb, 0));
		C_OK(opened(dfd, "sub/../f", O_RDONLY));
		C_OK(opened(dfd, "sub/back", O_RDONLY));
		C_ERR(fstatat(dfd, "sub/../..", &sb, 0), ENOTCAPABLE);
	}
}

ATF_TC_WITH_CLEANUP(lookup_cap_dotdot);
ATF_TC_HEAD(lookup_cap_dotdot, tc)
{

	atf_tc_set_md_var(tc, "descr", "vfs.lookup_cap_dotdot 0 and 1 for "
	    "capability mode, limited descriptors and O_RESOLVE_BENEATH");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(lookup_cap_dotdot, tc)
{

	tree();
	save_dotdot();
	ATF_REQUIRE(pc_sysctl_set(DOTDOT, 0));
	dotdot_mode = 0;
	in_child(child_dotdot);
	ATF_REQUIRE(pc_sysctl_set(DOTDOT, 1));
	dotdot_mode = 1;
	in_child(child_dotdot);
	restore_dotdot();
}
ATF_TC_CLEANUP(lookup_cap_dotdot, tc)
{

	restore_dotdot();
}

static void
child_derived_rights(void)
{
	cap_rights_t r, got;
	char c;
	int dfd, fd;

	dfd = open("top", O_DIRECTORY | O_RDONLY);
	if (dfd < 0 || cap_rights_limit(dfd, cap_rights_init(&r, CAP_LOOKUP,
	    CAP_READ, CAP_FSTAT)) != 0 || cap_enter() != 0)
		_exit(99);
	/* A file opened through a limited directory inherits its rights. */
	fd = openat(dfd, "f", O_RDONLY);
	if (fd < 0) {
		failures++;
		return;
	}
	C_OK(read(fd, &c, 1));
	C_ERR(write(fd, "x", 1), ENOTCAPABLE);
	if (cap_rights_get(fd, &got) != 0 ||
	    cap_rights_is_set(&got, CAP_WRITE) ||
	    !cap_rights_is_set(&got, CAP_READ))
		failures++;
	/* Asking for more than the directory has is refused. */
	C_ERR(openat(dfd, "f", O_RDWR), ENOTCAPABLE);
	C_ERR(openat(dfd, "new", O_RDWR | O_CREAT, 0644), ENOTCAPABLE);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(derived_rights);
ATF_TC_BODY(derived_rights, tc)
{
	struct stat sb;

	tree();
	in_child(child_derived_rights);
	ATF_CHECK(stat("top/new", &sb) == -1 && errno == ENOENT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, capmode);
	ATF_TP_ADD_TC(tp, limited_rights);
	ATF_TP_ADD_TC(tp, two_fd_rights);
	ATF_TP_ADD_TC(tp, resolve_beneath_at);
	ATF_TP_ADD_TC(tp, lookup_cap_dotdot);
	ATF_TP_ADD_TC(tp, derived_rights);
	return (atf_no_error());
}
