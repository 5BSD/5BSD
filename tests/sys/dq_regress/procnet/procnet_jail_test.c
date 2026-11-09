/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * jail_set(2) with a path and jail_attach(2) of unattached processes, as
 * before stage 1c.
 *
 * Stage 1c consults the jail root's lookup in kern_jail_set (a kernel
 * consumer intent) and refuses jail_attach of an ATTACHED process in
 * do_jail_attach()/pwd_chroot_chdir().  For other processes: a relative
 * path is resolved from the cwd, the root becomes the process's root and
 * cwd at attach, also with other threads present, and the errors are
 * unchanged.
 *
 * Expectations from 3f330ee172d: kern_jail.c kern_jail_set() (path:
 * namei FOLLOW, ENOTDIR for a non-directory, vn_fullpath of the result as
 * pr_path), do_jail_attach() and pwd_chroot_chdir() in vfs_mountroot.c /
 * kern_descrip.c.
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <jail.h>
#include <pthread.h>

#include "procnet_common.h"

static void
pn_jail_remove_named(const char *name)
{
	int jid;

	jid = jail_getid(name);
	if (jid > 0)
		(void)jail_remove(jid);
}

/* A persistent jail named "name" rooted at "path"; -1 and errno on error. */
static int
pn_jail_create(const char *name, const char *path)
{

	return (jail_setv(JAIL_CREATE, "name", name, "path", path,
	    "persist", NULL, NULL));
}

static void
pn_jail_path(int jid, char *buf, size_t len)
{
	char jidstr[16];

	snprintf(jidstr, sizeof(jidstr), "%d", jid);
	buf[0] = '\0';
	ATF_REQUIRE_MSG(jail_getv(0, "jid", jidstr, "path", buf, NULL) == jid,
	    "jail_getv: %s", jail_errmsg);
	(void)len;
}

ATF_TC_WITH_CLEANUP(jail_set_absolute);
ATF_TC_HEAD(jail_set_absolute, tc)
{
	atf_tc_set_md_var(tc, "descr", "jail_set(2) with an absolute path "
	    "records it; attach makes it root and cwd");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
attach_check(void *arg)
{
	char cwd[PATH_MAX];
	struct stat st;
	int jid = *(int *)arg;

	if (jail_attach(jid) != 0)
		return (errno);
	if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/") != 0)
		return (PN_X_WRONG);
	if (stat("/procnet_marker", &st) != 0)
		return (PN_X_WRONG);
	if (stat("/..", &st) != 0 || stat("/procnet_marker", &st) != 0)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_BODY(jail_set_absolute, tc)
{
	char root[PATH_MAX], jpath[MAXPATHLEN];
	int jid;

	ATF_REQUIRE(mkdir("root", 0755) == 0);
	pn_writefile("root/procnet_marker", "m", 1, 0644);
	ATF_REQUIRE(realpath("root", root) != NULL);
	jid = pn_jail_create("procnet_abs", root);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pn_jail_path(jid, jpath, sizeof(jpath));
	ATF_CHECK_STREQ(root, jpath);
	PN_CHECK_ERRNO(0, pn_child(attach_check, &jid, 0, 0), "attach");
}
ATF_TC_CLEANUP(jail_set_absolute, tc)
{
	pn_jail_remove_named("procnet_abs");
}

ATF_TC_WITH_CLEANUP(jail_set_relative);
ATF_TC_HEAD(jail_set_relative, tc)
{
	atf_tc_set_md_var(tc, "descr", "jail_set(2) with a relative path "
	    "resolves it from the cwd and records the full path; \"..\" and "
	    "a symlink too");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_set_relative, tc)
{
	char root[PATH_MAX], jpath[MAXPATHLEN];
	int jid;

	ATF_REQUIRE(mkdir("root", 0755) == 0);
	ATF_REQUIRE(mkdir("sub", 0755) == 0);
	pn_writefile("root/procnet_marker", "m", 1, 0644);
	ATF_REQUIRE(realpath("root", root) != NULL);

	jid = pn_jail_create("procnet_rel", "root");
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pn_jail_path(jid, jpath, sizeof(jpath));
	ATF_CHECK_STREQ(root, jpath);
	PN_CHECK_ERRNO(0, pn_child(attach_check, &jid, 0, 0),
	    "attach (relative)");
	(void)jail_remove(jid);

	ATF_REQUIRE(chdir("sub") == 0);
	jid = pn_jail_create("procnet_rel", "../root");
	ATF_REQUIRE(chdir("..") == 0);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pn_jail_path(jid, jpath, sizeof(jpath));
	ATF_CHECK_STREQ(root, jpath);
	(void)jail_remove(jid);

	ATF_REQUIRE(symlink("root", "rootlink") == 0);
	jid = pn_jail_create("procnet_rel", "rootlink");
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pn_jail_path(jid, jpath, sizeof(jpath));
	ATF_CHECK_STREQ(root, jpath);
	PN_CHECK_ERRNO(0, pn_child(attach_check, &jid, 0, 0),
	    "attach (symlink)");
}
ATF_TC_CLEANUP(jail_set_relative, tc)
{
	pn_jail_remove_named("procnet_rel");
}

/* jail_set(2) through the raw syscall, to see its errno. */
static int
pn_jail_set_raw(const char *name, const char *path)
{
	struct iovec iov[6];

	iov[0].iov_base = __DECONST(char *, "name");
	iov[0].iov_len = sizeof("name");
	iov[1].iov_base = __DECONST(char *, name);
	iov[1].iov_len = strlen(name) + 1;
	iov[2].iov_base = __DECONST(char *, "path");
	iov[2].iov_len = sizeof("path");
	iov[3].iov_base = __DECONST(char *, path);
	iov[3].iov_len = strlen(path) + 1;
	iov[4].iov_base = __DECONST(char *, "persist");
	iov[4].iov_len = sizeof("persist");
	iov[5].iov_base = NULL;
	iov[5].iov_len = 0;
	return (PN_ERR(jail_set(iov, 6, JAIL_CREATE)));
}

static int
jail_set_unpriv(void *arg __unused)
{

	return (pn_jail_set_raw("procnet_unpriv", "/"));
}

ATF_TC_WITH_CLEANUP(jail_set_errors);
ATF_TC_HEAD(jail_set_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "jail_set(2) path errors: missing is "
	    "ENOENT, a file ENOTDIR, a dangling symlink ENOENT, over "
	    "MAXPATHLEN ENAMETOOLONG; unprivileged is EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_set_errors, tc)
{
	char *longpath;

	pn_writefile("file", "x", 1, 0644);
	ATF_REQUIRE(symlink("nowhere", "dangling") == 0);
	PN_CHECK_ERRNO(ENOENT, pn_jail_set_raw("procnet_err", "missing"),
	    "missing path");
	PN_CHECK_ERRNO(ENOTDIR, pn_jail_set_raw("procnet_err", "file"),
	    "file as path");
	PN_CHECK_ERRNO(ENOENT, pn_jail_set_raw("procnet_err", "dangling"),
	    "dangling symlink");
	PN_CHECK_ERRNO(ENOTDIR, pn_jail_set_raw("procnet_err", "file/x"),
	    "through a file");
	longpath = malloc(MAXPATHLEN + 16);
	ATF_REQUIRE(longpath != NULL);
	memset(longpath, 'a', MAXPATHLEN + 8);
	longpath[MAXPATHLEN + 8] = '\0';
	/*
	 * kern_jail_set(): a "path" option longer than MAXPATHLEN is
	 * ENAMETOOLONG before the lookup.
	 */
	PN_CHECK_ERRNO(ENAMETOOLONG, pn_jail_set_raw("procnet_err",
	    longpath), "path over MAXPATHLEN");
	free(longpath);
	PN_CHECK_ERRNO(EPERM, pn_child(jail_set_unpriv, NULL, PN_UID, PN_GID),
	    "unprivileged jail_set");
	ATF_CHECK(jail_getid("procnet_err") < 0);
}
ATF_TC_CLEANUP(jail_set_errors, tc)
{
	pn_jail_remove_named("procnet_err");
	pn_jail_remove_named("procnet_unpriv");
}

static void *
pn_sleeper(void *arg __unused)
{

	for (;;)
		pause();
	return (NULL);
}

static int
attach_threads(void *arg)
{
	pthread_t thr[4];
	int i;

	for (i = 0; i < 4; i++)
		if (pthread_create(&thr[i], NULL, pn_sleeper, NULL) != 0)
			return (PN_X_SETUP);
	return (attach_check(arg));
}

ATF_TC_WITH_CLEANUP(jail_attach_threads);
ATF_TC_HEAD(jail_attach_threads, tc)
{
	atf_tc_set_md_var(tc, "descr", "jail_attach(2) from a process with "
	    "other threads succeeds and changes root and cwd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_attach_threads, tc)
{
	char root[PATH_MAX];
	int jid;

	ATF_REQUIRE(mkdir("root", 0755) == 0);
	pn_writefile("root/procnet_marker", "m", 1, 0644);
	ATF_REQUIRE(realpath("root", root) != NULL);
	jid = pn_jail_create("procnet_thr", root);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	PN_CHECK_ERRNO(0, pn_child(attach_threads, &jid, 0, 0),
	    "attach with threads");
}
ATF_TC_CLEANUP(jail_attach_threads, tc)
{
	pn_jail_remove_named("procnet_thr");
}

static int
attach_only(void *arg)
{

	return (PN_ERR(jail_attach(*(int *)arg)));
}

ATF_TC_WITH_CLEANUP(jail_attach_errors);
ATF_TC_HEAD(jail_attach_errors, tc)
{
	atf_tc_set_md_var(tc, "descr", "jail_attach(2): an unknown jid is "
	    "EINVAL, unprivileged EPERM, a removed jail EINVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_attach_errors, tc)
{
	int jid, bad;

	bad = 999999;
	PN_CHECK_ERRNO(EINVAL, pn_child(attach_only, &bad, 0, 0),
	    "unknown jid");
	jid = pn_jail_create("procnet_atterr", "/");
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	PN_CHECK_ERRNO(EPERM, pn_child(attach_only, &jid, PN_UID, PN_GID),
	    "unprivileged attach");
	ATF_REQUIRE(jail_remove(jid) == 0);
	PN_CHECK_ERRNO(EINVAL, pn_child(attach_only, &jid, 0, 0),
	    "removed jail");
}
ATF_TC_CLEANUP(jail_attach_errors, tc)
{
	pn_jail_remove_named("procnet_atterr");
}

static int
attach_dotdot(void *arg)
{
	struct stat st;
	int jid = *(int *)arg;

	if (jail_attach(jid) != 0)
		return (errno);
	/* Inside, "/.." stays at the jail root. */
	if (chdir("/..") != 0 || stat("procnet_marker", &st) != 0)
		return (PN_X_WRONG);
	/* And an absolute "/../.." too. */
	if (stat("/../../procnet_marker", &st) != 0)
		return (PN_X_WRONG);
	return (0);
}

ATF_TC_WITH_CLEANUP(jail_attach_root_escape);
ATF_TC_HEAD(jail_attach_root_escape, tc)
{
	atf_tc_set_md_var(tc, "descr", "after jail_attach(2) \"..\" from the "
	    "root stays in the jail");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_attach_root_escape, tc)
{
	char root[PATH_MAX];
	int jid;

	ATF_REQUIRE(mkdir("root", 0755) == 0);
	pn_writefile("root/procnet_marker", "m", 1, 0644);
	ATF_REQUIRE(realpath("root", root) != NULL);
	jid = pn_jail_create("procnet_esc", root);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	PN_CHECK_ERRNO(0, pn_child(attach_dotdot, &jid, 0, 0),
	    "attach and dot-dot");
}
ATF_TC_CLEANUP(jail_attach_root_escape, tc)
{
	pn_jail_remove_named("procnet_esc");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, jail_set_absolute);
	ATF_TP_ADD_TC(tp, jail_set_relative);
	ATF_TP_ADD_TC(tp, jail_set_errors);
	ATF_TP_ADD_TC(tp, jail_attach_threads);
	ATF_TP_ADD_TC(tp, jail_attach_errors);
	ATF_TP_ADD_TC(tp, jail_attach_root_escape);
	return (atf_no_error());
}
