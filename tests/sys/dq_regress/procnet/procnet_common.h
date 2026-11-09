/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared helpers of the procnet regression programs.
 *
 * Every case runs in a process that is NOT attached to a dq(4) controller
 * and asserts what the kernel did before DescriptorQueue stage 1c (commit
 * 3f330ee172d).  The one exception is the socket(2) errno order with a
 * full descriptor table (D139/D155): those cases assert the new order and,
 * when the configuration variable "pre1c" is true (kyua -v
 * test_suites.FreeBSD.pre1c=yes, atf: -v pre1c=yes), the upstream order
 * instead, so that one program serves both kernels.
 *
 * Children report an errno (0 for success) as their exit status; values
 * from PN_X_BASE up are harness failures, never errnos.
 */

#ifndef _PROCNET_COMMON_H_
#define	_PROCNET_COMMON_H_

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An unprivileged identity with no passwd entry, and nobody. */
#define	PN_UID		4242
#define	PN_GID		4242
#define	PN_NOBODY	65534
#define	PN_NOGROUP	65533

/* Child exit statuses that are not errnos. */
#define	PN_X_BASE	200
#define	PN_X_DROP	(PN_X_BASE + 1)	/* could not drop privileges */
#define	PN_X_SETUP	(PN_X_BASE + 2)	/* setup in the child failed */
#define	PN_X_WRONG	(PN_X_BASE + 3)	/* a result the child checks */

static inline const char *
pn_errname(int e)
{

	if (e == 0)
		return ("success");
	if (e >= PN_X_BASE)
		return ("harness failure in child");
	return (strerror(e));
}

/* errno of a call that returns -1 on failure, 0 on success. */
#define	PN_ERR(expr)	(errno = 0, (expr) == -1 ? errno : 0)

/* strerror(3) shares one buffer: copy the first name before the second. */
#define	PN_CHECK_ERRNO(exp, got, what) do {				\
	char _pn[64];							\
	int _pe = (exp), _pg = (got);					\
	strlcpy(_pn, pn_errname(_pe), sizeof(_pn));			\
	ATF_CHECK_MSG(_pe == _pg, "%s: expected %s (%d), got %s (%d)",	\
	    (what), _pn, _pe, pn_errname(_pg), _pg);			\
} while (0)

#define	PN_EXPECT(exp, expr)	PN_CHECK_ERRNO((exp), PN_ERR(expr), #expr)

/* The "pre1c" switch of the one documented change (see above). */
static inline bool
pn_pre1c(const atf_tc_t *tc)
{

	return (atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false));
}

static inline void
pn_drop(uid_t uid, gid_t gid)
{
	gid_t g;

	g = gid;
	if (setgroups(1, &g) != 0 || setgid(gid) != 0 || setuid(uid) != 0)
		_exit(PN_X_DROP);
}

static inline int
pn_wait(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			atf_tc_fail("waitpid: %s", strerror(errno));
	}
	return (status);
}

/*
 * Run fn(arg) in a child, as uid/gid unless uid is 0, and return its exit
 * status: an errno, 0, or a PN_X_* value.  A child killed by a signal is a
 * failure of the case.
 */
static inline int
pn_child(int (*fn)(void *), void *arg, uid_t uid, gid_t gid)
{
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE_MSG(pid != -1, "fork: %s", strerror(errno));
	if (pid == 0) {
		if (uid != 0)
			pn_drop(uid, gid);
		_exit(fn(arg));
	}
	status = pn_wait(pid);
	ATF_REQUIRE_MSG(WIFEXITED(status), "child status %#x", status);
	return (WEXITSTATUS(status));
}

/* The directory the test program (and procnet_helper) is installed in. */
static inline void
pn_srcfile(const atf_tc_t *tc, const char *name, char *buf, size_t len)
{
	const char *src;

	src = atf_tc_get_config_var(tc, "srcdir");
	ATF_REQUIRE((size_t)snprintf(buf, len, "%s/%s", src, name) < len);
}

/* A canonical absolute path for a name in the current directory. */
static inline void
pn_cwdpath(const char *name, char *buf, size_t len)
{
	char cwd[PATH_MAX];

	ATF_REQUIRE(realpath(".", cwd) != NULL);
	ATF_REQUIRE((size_t)snprintf(buf, len, "%s/%s", cwd, name) < len);
}

/*
 * A world-traversable directory /tmp/procnet.<name> (the kyua work
 * directory may be private to root): removed first, created 0755.
 * Cleanups call pn_pubdir_remove(name).
 */
static inline void
pn_pubdir_remove(const char *name)
{
	char cmd[PATH_MAX + 32];

	snprintf(cmd, sizeof(cmd), "rm -rf /tmp/procnet.%s", name);
	(void)system(cmd);
}

static inline void
pn_pubdir(const char *name, char *buf, size_t len)
{
	char tmp[PATH_MAX];

	pn_pubdir_remove(name);
	ATF_REQUIRE((size_t)snprintf(tmp, sizeof(tmp), "/tmp/procnet.%s",
	    name) < sizeof(tmp));
	ATF_REQUIRE_MSG(mkdir(tmp, 0755) == 0, "mkdir %s: %s", tmp,
	    strerror(errno));
	ATF_REQUIRE(chmod(tmp, 0755) == 0);
	ATF_REQUIRE(realpath(tmp, buf) != NULL);
	ATF_REQUIRE(strlen(buf) < len);
}

static inline void
pn_copyfile(const char *from, const char *to, mode_t mode)
{
	char buf[65536];
	ssize_t n;
	int in, out;

	in = open(from, O_RDONLY);
	ATF_REQUIRE_MSG(in >= 0, "open %s: %s", from, strerror(errno));
	(void)unlink(to);
	out = open(to, O_WRONLY | O_CREAT | O_EXCL, 0700);
	ATF_REQUIRE_MSG(out >= 0, "open %s: %s", to, strerror(errno));
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE(write(out, buf, (size_t)n) == n);
	ATF_REQUIRE(n == 0);
	ATF_REQUIRE(fchmod(out, mode) == 0);
	ATF_REQUIRE(close(out) == 0);
	ATF_REQUIRE(close(in) == 0);
}

static inline void
pn_writefile(const char *path, const void *data, size_t len, mode_t mode)
{
	int fd;

	(void)unlink(path);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE_MSG(fd >= 0, "open %s: %s", path, strerror(errno));
	if (len > 0)
		ATF_REQUIRE(write(fd, data, len) == (ssize_t)len);
	ATF_REQUIRE(fchmod(fd, mode) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

/*
 * Fill the descriptor table: every descriptor below the returned limit is
 * open and RLIMIT_NOFILE equals it, so falloc() fails with EMFILE.  Only
 * for children (it changes the process).
 */
static inline int
pn_fill_fdtable(void)
{
	struct rlimit rl;
	int fd, hi, i;

	hi = 0;
	for (i = 0; i < 64; i++) {
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0)
			return (-1);
		if (fd > hi)
			hi = fd;
	}
	/* Close the holes below hi. */
	for (i = 0; i < hi; i++) {
		if (fcntl(i, F_GETFD) == -1 && errno == EBADF) {
			if (dup2(hi, i) == -1)
				return (-1);
		}
	}
	rl.rlim_cur = rl.rlim_max = (rlim_t)hi + 1;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		return (-1);
	/* The table is full: EMFILE for anything that takes a slot. */
	if (open("/dev/null", O_RDONLY) != -1 || errno != EMFILE)
		return (-1);
	return (hi + 1);
}

#endif /* !_PROCNET_COMMON_H_ */
