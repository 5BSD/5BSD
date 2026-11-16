/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The vm.objects sysctl names each POSIX shared memory object by its path.
 * A jailed reader gets the paths as its jail sees them, the way
 * kern.ipc.posix_shm_list and fstat(1) present them: an object under the
 * jail's root with the root taken off, an object anywhere else with no
 * path at all.  A reader outside any jail gets every path as it is.
 *
 * FreeBSD gave a jailed reader every object's path as the host sees it,
 * the other jails' and the host's among them.  That is the one behaviour
 * this file expects to differ from the pre-project kernel, on purpose
 * (D242); run against that kernel (test_suites.FreeBSD.pre1c=yes) the
 * jailed readers are expected to see what FreeBSD showed them.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	JAIL_A		"vm_objects_shm_jail_a"
#define	JAIL_AB		"vm_objects_shm_jail_ab"
#define	HOST_SHM	"/vm_objects_shm_jail.host"

static void
iov_set(struct iovec *iov, const void *base, size_t len)
{
	iov->iov_base = __DECONST(void *, base);
	iov->iov_len = len;
}

/*
 * Create a persistent jail rooted at a directory of the work directory and
 * return the root as the kernel recorded it.
 */
static int
jail_make(const char *name, const char *dir, char *root, size_t rootlen)
{
	struct iovec iov[6];
	char path[PATH_MAX];
	int jid;

	ATF_REQUIRE_EQ(0, mkdir(dir, 0755));
	ATF_REQUIRE(realpath(dir, path) != NULL);
	iov_set(&iov[0], "name", sizeof("name"));
	iov_set(&iov[1], name, strlen(name) + 1);
	iov_set(&iov[2], "path", sizeof("path"));
	iov_set(&iov[3], path, strlen(path) + 1);
	iov_set(&iov[4], "persist", sizeof("persist"));
	iov_set(&iov[5], NULL, 0);
	jid = jail_set(iov, nitems(iov), JAIL_CREATE);
	ATF_REQUIRE_MSG(jid >= 0, "jail_set(%s): %s", name, strerror(errno));

	iov_set(&iov[0], "jid", sizeof("jid"));
	iov_set(&iov[1], &jid, sizeof(jid));
	iov_set(&iov[2], "path", sizeof("path"));
	iov_set(&iov[3], root, rootlen);
	ATF_REQUIRE_MSG(jail_get(iov, 4, 0) == jid, "jail_get(%s): %s", name,
	    strerror(errno));
	return (jid);
}

static void
jail_unmake(const char *name)
{
	struct iovec iov[2];
	int jid;

	iov_set(&iov[0], "name", sizeof("name"));
	iov_set(&iov[1], name, strlen(name) + 1);
	jid = jail_get(iov, nitems(iov), 0);
	if (jid >= 0)
		(void)jail_remove(jid);
}

/*
 * Run fn(arg) in a child, in the jail unless jid is 0, and return what it
 * returned, which is not negative.
 */
static int
run_in(int jid, int (*fn)(void *), void *arg)
{
	pid_t pid;
	int fds[2], res, status;

	ATF_REQUIRE_EQ(0, pipe(fds));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		res = -1;
		if (jid == 0 || jail_attach(jid) == 0)
			res = fn(arg);
		(void)write(fds[1], &res, sizeof(res));
		_exit(0);
	}
	close(fds[1]);
	res = -1;
	(void)read(fds[0], &res, sizeof(res));
	close(fds[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(res >= 0, "the child in jail %d failed", jid);
	return (res);
}

/* Create a named object; it stays until it is unlinked. */
static int
shm_make(void *arg)
{
	int fd;

	fd = shm_open(arg, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0 || ftruncate(fd, getpagesize()) != 0)
		return (-1);
	return (0);
}

/*
 * Which of the paths vm.objects gives for a POSIX shared memory object, as
 * a bit each.
 */
#define	NPATHS	7

static int
shm_paths_listed(void *arg)
{
	const char **paths = arg;
	struct kinfo_vmobject *kvo;
	char *buf, *p;
	size_t len;
	int i, seen;

	buf = NULL;
	for (;;) {
		if (sysctlbyname("vm.objects", NULL, &len, NULL, 0) != 0)
			return (-1);
		len = len * 2;
		buf = reallocf(buf, len);
		if (buf == NULL)
			return (-1);
		if (sysctlbyname("vm.objects", buf, &len, NULL, 0) == 0)
			break;
		if (errno != ENOMEM)
			return (-1);
	}
	seen = 0;
	for (p = buf; p < buf + len; p += kvo->kvo_structsize) {
		kvo = (struct kinfo_vmobject *)(void *)p;
		if (kvo->kvo_structsize <= 0)
			return (-1);
		if ((kvo->kvo_flags & KVMO_FLAG_POSIXSHM) == 0)
			continue;
		for (i = 0; i < NPATHS; i++)
			if (strcmp(kvo->kvo_path, paths[i]) == 0)
				seen |= 1 << i;
	}
	free(buf);
	return (seen);
}

ATF_TC_WITH_CLEANUP(shm_jail);
ATF_TC_HEAD(shm_jail, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shm_jail, tc)
{
	char root_a[PATH_MAX], root_ab[PATH_MAX];
	char full_own[PATH_MAX], full_x[PATH_MAX], cut_x[PATH_MAX];
	const char *paths[NPATHS];
	FILE *f;
	int a, ab, seen;
	bool pre1c;

	pre1c = atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false);

	/*
	 * The second jail's root has the first one's as a prefix of the
	 * string, not of the path: <dir>/a and <dir>/ab.
	 */
	a = jail_make(JAIL_A, "a", root_a, sizeof(root_a));
	ab = jail_make(JAIL_AB, "ab", root_ab, sizeof(root_ab));
	ATF_REQUIRE(strlen(root_ab) == strlen(root_a) + 1);
	ATF_REQUIRE(strncmp(root_ab, root_a, strlen(root_a)) == 0);

	ATF_REQUIRE_EQ(0, run_in(a, shm_make, __DECONST(void *, "/own")));
	ATF_REQUIRE_EQ(0, run_in(ab, shm_make, __DECONST(void *, "/x")));
	ATF_REQUIRE_EQ(0, run_in(0, shm_make, __DECONST(void *, HOST_SHM)));
	snprintf(full_own, sizeof(full_own), "%s/own", root_a);
	snprintf(full_x, sizeof(full_x), "%s/x", root_ab);
	/* What taking the first jail's root off the second's object leaves. */
	snprintf(cut_x, sizeof(cut_x), "%s", full_x + strlen(root_a));

	/* The cleanup unlinks by these names. */
	f = fopen("shm.names", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%s\n%s\n", full_own, full_x);
	fclose(f);

	paths[0] = full_own;
	paths[1] = full_x;
	paths[2] = HOST_SHM;
	paths[3] = "/own";
	paths[4] = "/x";
	paths[5] = cut_x;
	paths[6] = "";
#define	SEEN(i)		((seen & (1 << (i))) != 0)

	/* Outside a jail: every object, by the host's path. */
	seen = run_in(0, shm_paths_listed, paths);
	ATF_CHECK_MSG(SEEN(0) && SEEN(1) && SEEN(2), "host reader: %#x", seen);
	ATF_CHECK_MSG(!SEEN(3) && !SEEN(4) && !SEEN(5), "host reader: %#x",
	    seen);

	/*
	 * In the first jail: its own object by the jail's path; the other
	 * jail's and the host's are there with no path.
	 */
	seen = run_in(a, shm_paths_listed, paths);
	if (pre1c) {
		ATF_CHECK_MSG(SEEN(0) && SEEN(1) && SEEN(2) && !SEEN(3),
		    "jailed reader on FreeBSD: %#x", seen);
	} else {
		ATF_CHECK_MSG(SEEN(3), "own object not listed: %#x", seen);
		ATF_CHECK_MSG(!SEEN(0) && !SEEN(1) && !SEEN(2),
		    "host paths shown in the jail: %#x", seen);
		ATF_CHECK_MSG(!SEEN(4) && !SEEN(5),
		    "other jail's object shown: %#x", seen);
		ATF_CHECK_MSG(SEEN(6), "hidden objects not listed: %#x",
		    seen);
	}

	/* In the second: the same, the other way round. */
	seen = run_in(ab, shm_paths_listed, paths);
	if (pre1c) {
		ATF_CHECK_MSG(SEEN(0) && SEEN(1) && SEEN(2) && !SEEN(4),
		    "jailed reader on FreeBSD: %#x", seen);
	} else {
		ATF_CHECK_MSG(SEEN(4), "own object not listed: %#x", seen);
		ATF_CHECK_MSG(!SEEN(0) && !SEEN(1) && !SEEN(2) && !SEEN(3),
		    "paths from outside the jail shown: %#x", seen);
	}
#undef SEEN
}
ATF_TC_CLEANUP(shm_jail, tc)
{
	char name[PATH_MAX];
	FILE *f;

	f = fopen("shm.names", "r");
	if (f != NULL) {
		while (fgets(name, sizeof(name), f) != NULL) {
			name[strcspn(name, "\n")] = '\0';
			(void)shm_unlink(name);
		}
		fclose(f);
	}
	(void)shm_unlink(HOST_SHM);
	jail_unmake(JAIL_A);
	jail_unmake(JAIL_AB);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, shm_jail);
	return (atf_no_error());
}
