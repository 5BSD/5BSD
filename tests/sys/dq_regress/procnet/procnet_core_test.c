/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Core dumps of unattached processes, as before stage 1c.
 *
 * Stage 1c makes coredump() treat an ATTACHED process as RLIMIT_CORE 0
 * (D153) and wraps corefile_open()'s lookup.  For other processes a core
 * is still written under the kern.corefile name, RLIMIT_CORE 0 still
 * suppresses it, kern.sugid_coredump still governs set-id processes, and
 * corefile_open()/coredump_vnode() still refuse a symlink, a hard-linked
 * or foreign-owned existing file.
 *
 * Expectations from 3f330ee172d: kern_ucoredump.c coredump(),
 * coredump_vnode.c corefile_open() (O_NOFOLLOW, O_EXCL for P_SUGID,
 * %N %P %U expansion) and coredump_vnode() (VREG, nlink 1, owner).
 *
 * The image is procnet_helper ("abort"), so p_comm is "procnet_helper".
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include "procnet_common.h"

extern char **environ;

#define	PN_COMM		"procnet_helper"
#define	CORE_SAVE	"procnet_core.saved"

/*
 * Save kern.corefile and kern.sugid_coredump in the work directory (the
 * cleanup restores them) and check the switches a core needs.
 */
static void
core_setup(void)
{
	char corefile[MAXPATHLEN];
	size_t len;
	int v, sugid;
	FILE *f;

	len = sizeof(v);
	if (sysctlbyname("kern.coredump", &v, &len, NULL, 0) == 0 && v == 0)
		atf_tc_skip("kern.coredump is 0");
	len = sizeof(v);
	if (sysctlbyname("kern.compress_user_cores", &v, &len, NULL, 0) ==
	    0 && v != 0)
		atf_tc_skip("kern.compress_user_cores is set");
	len = sizeof(corefile);
	ATF_REQUIRE(sysctlbyname("kern.corefile", corefile, &len, NULL,
	    0) == 0);
	len = sizeof(sugid);
	ATF_REQUIRE(sysctlbyname("kern.sugid_coredump", &sugid, &len, NULL,
	    0) == 0);
	f = fopen(CORE_SAVE, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%d\n%s\n", sugid, corefile);
	ATF_REQUIRE(fclose(f) == 0);
}

static void
core_restore(void)
{
	char corefile[MAXPATHLEN];
	int sugid;
	FILE *f;

	f = fopen(CORE_SAVE, "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%d\n", &sugid) == 1 &&
	    fgets(corefile, sizeof(corefile), f) != NULL) {
		corefile[strcspn(corefile, "\n")] = '\0';
		(void)sysctlbyname("kern.corefile", NULL, NULL, corefile,
		    strlen(corefile) + 1);
		(void)sysctlbyname("kern.sugid_coredump", NULL, NULL, &sugid,
		    sizeof(sugid));
	}
	fclose(f);
}

static void
set_corefile(const char *pattern)
{

	ATF_REQUIRE_MSG(sysctlbyname("kern.corefile", NULL, NULL, pattern,
	    strlen(pattern) + 1) == 0, "kern.corefile: %s", strerror(errno));
}

static void
set_sugid(int v)
{

	ATF_REQUIRE(sysctlbyname("kern.sugid_coredump", NULL, NULL, &v,
	    sizeof(v)) == 0);
}

/*
 * Run "image abort" in dir with RLIMIT_CORE = limit (RLIM_INFINITY for
 * none), as uid/gid unless uid is 0; return the wait status and the pid.
 */
static int
run_abort(const char *image, const char *dir, rlim_t limit, uid_t uid,
    gid_t gid, pid_t *pidp)
{
	char *argv[] = { __DECONST(char *, PN_COMM),
	    __DECONST(char *, "abort"), NULL };
	struct rlimit rl;
	pid_t pid;
	int status;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (chdir(dir) != 0)
			_exit(PN_X_SETUP);
		rl.rlim_cur = rl.rlim_max = limit;
		if (setrlimit(RLIMIT_CORE, &rl) != 0)
			_exit(PN_X_SETUP);
		if (uid != 0)
			pn_drop(uid, gid);
		execve(image, argv, environ);
		_exit(PN_X_SETUP);
	}
	status = pn_wait(pid);
	ATF_REQUIRE_MSG(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
	    "status %#x", status);
	if (pidp != NULL)
		*pidp = pid;
	return (status);
}

static void
helper(const atf_tc_t *tc, char *buf, size_t len)
{

	pn_srcfile(tc, "procnet_helper", buf, len);
}

ATF_TC_WITH_CLEANUP(core_default_name);
ATF_TC_HEAD(core_default_name, tc)
{
	atf_tc_set_md_var(tc, "descr", "abort(3) dumps core as %N.core in "
	    "the cwd: WCOREDUMP set, a regular file owned by the process");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_default_name, tc)
{
	char img[PATH_MAX], dir[PATH_MAX];
	struct stat st;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	set_corefile("%N.core");
	ATF_REQUIRE(realpath(".", dir) != NULL);
	status = run_abort(img, dir, RLIM_INFINITY, 0, 0, NULL);
	ATF_CHECK_MSG(WCOREDUMP(status), "no core flag, status %#x", status);
	ATF_REQUIRE_MSG(stat(PN_COMM ".core", &st) == 0, "%s.core: %s",
	    PN_COMM, strerror(errno));
	ATF_CHECK(S_ISREG(st.st_mode));
	ATF_CHECK_EQ(0u, st.st_uid);
	ATF_CHECK_EQ(1u, (unsigned)st.st_nlink);
	ATF_CHECK(st.st_size > 0);
	/* cmode S_IRUSR | S_IWUSR. */
	ATF_CHECK_EQ(0600, st.st_mode & 07777);
}
ATF_TC_CLEANUP(core_default_name, tc)
{
	core_restore();
}

ATF_TC_WITH_CLEANUP(core_pattern);
ATF_TC_HEAD(core_pattern, tc)
{
	atf_tc_set_md_var(tc, "descr", "kern.corefile %N, %P, %U and %% "
	    "expand, an absolute pattern lands in its directory whatever "
	    "the cwd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_pattern, tc)
{
	char img[PATH_MAX], dir[PATH_MAX], pattern[PATH_MAX];
	char name[PATH_MAX];
	struct stat st;
	pid_t pid;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	ATF_REQUIRE(mkdir("cores", 0755) == 0);
	ATF_REQUIRE(mkdir("elsewhere", 0755) == 0);
	ATF_REQUIRE(realpath("cores", dir) != NULL);
	snprintf(pattern, sizeof(pattern), "%s/%%N-%%P-%%U-%%%%.c", dir);
	set_corefile(pattern);
	status = run_abort(img, "elsewhere", RLIM_INFINITY, 0, 0, &pid);
	ATF_CHECK_MSG(WCOREDUMP(status), "no core flag, status %#x", status);
	snprintf(name, sizeof(name), "cores/%s-%d-0-%%.c", PN_COMM, pid);
	ATF_CHECK_MSG(stat(name, &st) == 0, "%s: %s", name, strerror(errno));
	ATF_CHECK(stat("elsewhere/" PN_COMM ".core", &st) != 0);
}
ATF_TC_CLEANUP(core_pattern, tc)
{
	core_restore();
}

ATF_TC_WITH_CLEANUP(core_rlimit);
ATF_TC_HEAD(core_rlimit, tc)
{
	atf_tc_set_md_var(tc, "descr", "RLIMIT_CORE 0 creates no core file "
	    "and no core flag; a tiny limit gives no core flag");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_rlimit, tc)
{
	char img[PATH_MAX], dir[PATH_MAX];
	struct stat st;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	set_corefile("%N.core");
	ATF_REQUIRE(realpath(".", dir) != NULL);
	status = run_abort(img, dir, 0, 0, 0, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core flag with RLIMIT_CORE 0");
	ATF_CHECK_MSG(stat(PN_COMM ".core", &st) != 0 && errno == ENOENT,
	    "a core file exists with RLIMIT_CORE 0");

	/*
	 * A limit smaller than the core: the dumper fails; the file may
	 * exist (created, then truncated), but the status has no core flag.
	 */
	status = run_abort(img, dir, 1, 0, 0, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core flag with RLIMIT_CORE 1");
}
ATF_TC_CLEANUP(core_rlimit, tc)
{
	core_restore();
}

ATF_TC_WITH_CLEANUP(core_unpriv);
ATF_TC_HEAD(core_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unprivileged process dumps core "
	    "owned by itself where it may write, and none where it may not");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_unpriv, tc)
{
	char img[PATH_MAX], dir[PATH_MAX], ro[PATH_MAX], name[PATH_MAX];
	struct stat st;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	set_corefile("%N.core");
	pn_pubdir("core_unpriv", dir, sizeof(dir));
	snprintf(ro, sizeof(ro), "%s/ro", dir);
	ATF_REQUIRE(mkdir(ro, 0755) == 0);
	snprintf(name, sizeof(name), "%s/rw", dir);
	ATF_REQUIRE(mkdir(name, 0755) == 0);
	ATF_REQUIRE(chown(name, PN_UID, PN_GID) == 0);

	status = run_abort(img, name, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(WCOREDUMP(status), "no core flag, status %#x", status);
	snprintf(name, sizeof(name), "%s/rw/%s.core", dir, PN_COMM);
	ATF_REQUIRE_MSG(stat(name, &st) == 0, "%s: %s", name,
	    strerror(errno));
	ATF_CHECK_EQ((unsigned)PN_UID, st.st_uid);

	status = run_abort(img, ro, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core flag in a read-only dir");
	snprintf(name, sizeof(name), "%s/%s.core", ro, PN_COMM);
	ATF_CHECK(stat(name, &st) != 0);
}
ATF_TC_CLEANUP(core_unpriv, tc)
{
	core_restore();
	pn_pubdir_remove("core_unpriv");
}

ATF_TC_WITH_CLEANUP(core_existing_file);
ATF_TC_HEAD(core_existing_file, tc)
{
	atf_tc_set_md_var(tc, "descr", "an existing core name that is a "
	    "symlink (O_NOFOLLOW), has two links, or belongs to another uid "
	    "is not written; a plain own file is truncated and rewritten");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_existing_file, tc)
{
	char img[PATH_MAX], dir[PATH_MAX], name[PATH_MAX], victim[PATH_MAX];
	struct stat st;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	set_corefile("%N.core");
	pn_pubdir("core_existing", dir, sizeof(dir));
	ATF_REQUIRE(chmod(dir, 01777) == 0);
	snprintf(name, sizeof(name), "%s/%s.core", dir, PN_COMM);
	snprintf(victim, sizeof(victim), "%s/victim", dir);

	/* A symlink to a file the process could write. */
	pn_writefile(victim, "precious", 8, 0666);
	ATF_REQUIRE(symlink(victim, name) == 0);
	status = run_abort(img, dir, RLIM_INFINITY, 0, 0, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core written through a symlink");
	ATF_REQUIRE(stat(victim, &st) == 0);
	ATF_CHECK_EQ(8, st.st_size);
	ATF_REQUIRE(unlink(name) == 0);

	/* A second link to the victim. */
	ATF_REQUIRE(link(victim, name) == 0);
	status = run_abort(img, dir, RLIM_INFINITY, 0, 0, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core written to a hard link");
	ATF_REQUIRE(stat(victim, &st) == 0);
	ATF_CHECK_EQ(8, st.st_size);
	ATF_REQUIRE(unlink(name) == 0);

	/* Owned by another uid (but writable by the dumper). */
	pn_writefile(name, "theirs", 6, 0666);
	ATF_REQUIRE(chown(name, PN_UID + 7, PN_GID) == 0);
	status = run_abort(img, dir, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "core written to a foreign file");
	ATF_REQUIRE(stat(name, &st) == 0);
	ATF_CHECK_EQ(6, st.st_size);
	ATF_REQUIRE(unlink(name) == 0);

	/* Its own: truncated and rewritten. */
	pn_writefile(name, "old", 3, 0600);
	status = run_abort(img, dir, RLIM_INFINITY, 0, 0, NULL);
	ATF_CHECK_MSG(WCOREDUMP(status), "no core over an own file");
	ATF_REQUIRE(stat(name, &st) == 0);
	ATF_CHECK(st.st_size > 3);
}
ATF_TC_CLEANUP(core_existing_file, tc)
{
	core_restore();
	pn_pubdir_remove("core_existing");
}

ATF_TC_WITH_CLEANUP(core_sugid);
ATF_TC_HEAD(core_sugid, tc)
{
	atf_tc_set_md_var(tc, "descr", "a set-id process dumps no core with "
	    "kern.sugid_coredump 0, does with 1, and never over an existing "
	    "file (O_EXCL)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_sugid, tc)
{
	char img[PATH_MAX], dir[PATH_MAX], setid[PATH_MAX], name[PATH_MAX];
	struct statfs sf;
	struct stat st;
	int status;

	core_setup();
	helper(tc, img, sizeof(img));
	set_corefile("%N.core");
	pn_pubdir("core_sugid", dir, sizeof(dir));
	ATF_REQUIRE(statfs(dir, &sf) == 0);
	if ((sf.f_flags & (MNT_NOSUID | MNT_NOEXEC)) != 0)
		atf_tc_skip("%s is nosuid or noexec", dir);
	ATF_REQUIRE(chmod(dir, 01777) == 0);
	snprintf(setid, sizeof(setid), "%s/%s", dir, PN_COMM);
	pn_copyfile(img, setid, 0755);
	ATF_REQUIRE(chown(setid, PN_NOBODY, PN_NOGROUP) == 0);
	ATF_REQUIRE(chmod(setid, 04755) == 0);
	snprintf(name, sizeof(name), "%s/%s.core", dir, PN_COMM);

	set_sugid(0);
	status = run_abort(setid, dir, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "set-id core with sugid_coredump 0");
	ATF_CHECK(stat(name, &st) != 0);

	set_sugid(1);
	status = run_abort(setid, dir, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(WCOREDUMP(status), "no set-id core with "
	    "sugid_coredump 1");
	ATF_REQUIRE_MSG(stat(name, &st) == 0, "%s: %s", name,
	    strerror(errno));
	/* Written with the effective uid. */
	ATF_CHECK_EQ((unsigned)PN_NOBODY, st.st_uid);

	/* Again: the file exists, O_EXCL refuses it. */
	status = run_abort(setid, dir, RLIM_INFINITY, PN_UID, PN_GID, NULL);
	ATF_CHECK_MSG(!WCOREDUMP(status), "set-id core over an existing file");
}
ATF_TC_CLEANUP(core_sugid, tc)
{
	core_restore();
	pn_pubdir_remove("core_sugid");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, core_default_name);
	ATF_TP_ADD_TC(tp, core_pattern);
	ATF_TP_ADD_TC(tp, core_rlimit);
	ATF_TP_ADD_TC(tp, core_unpriv);
	ATF_TP_ADD_TC(tp, core_existing_file);
	ATF_TP_ADD_TC(tp, core_sugid);
	return (atf_no_error());
}
