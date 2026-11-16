/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * execve(2)/fexecve(2) of unattached processes, as before stage 1c.
 *
 * Stage 1c reads the attached state once in do_execve() under P_INEXEC,
 * may clear credential_changing and skip IS_AUTHORITY_PREPARE, and wraps
 * the image and #! interpreter lookups (and the ELF PT_INTERP lookup) in
 * intents.  For a process that is not attached all of it must be inert:
 * set-id images still change credentials, #! and PT_INTERP fail exactly as
 * before, AT_EXECPATH and kern.proc.pathname are the same, and the errno
 * order of E2BIG/ENOENT/EACCES/ENOEXEC is unchanged.
 *
 * Expectations from 3f330ee172d: kern_exec.c do_execve() and
 * exec_args_add_fname(), imgact_shell.c exec_shell_imgact(),
 * imgact_elf.c get_interp()/load_interp(), exec_image_vnode.c.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <elf.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include "procnet_common.h"

extern char **environ;

struct pn_run {
	const char	*path;		/* execve(2) path, or NULL: fexecve */
	int		 fd;		/* fexecve(2) descriptor */
	char *const	*argv;
	const char	*cwd;		/* chdir(2) first, or NULL */
	uid_t		 uid;		/* drop to uid/gid first unless 0 */
	gid_t		 gid;
	int		 pdeathsig;	/* PROC_PDEATHSIG_CTL first unless 0 */
	/* Results. */
	int		 exec_errno;	/* errno of a failed exec, else 0 */
	bool		 exec_failed;
	int		 status;	/* wait status of the child */
	char		 out[8192];	/* its standard output */
};

static void
pn_run(struct pn_run *r)
{
	ssize_t n;
	size_t off;
	pid_t pid;
	int e, outp[2], errp[2];

	ATF_REQUIRE(pipe(outp) == 0);
	ATF_REQUIRE(pipe2(errp, O_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		close(outp[0]);
		close(errp[0]);
		if (dup2(outp[1], STDOUT_FILENO) == -1)
			_exit(PN_X_SETUP);
		if (r->cwd != NULL && chdir(r->cwd) != 0)
			_exit(PN_X_SETUP);
		if (r->pdeathsig != 0 && procctl(P_PID, 0, PROC_PDEATHSIG_CTL,
		    &r->pdeathsig) != 0)
			_exit(PN_X_SETUP);
		if (r->uid != 0)
			pn_drop(r->uid, r->gid);
		if (r->path != NULL)
			execve(r->path, r->argv, environ);
		else
			fexecve(r->fd, r->argv, environ);
		e = errno;
		(void)write(errp[1], &e, sizeof(e));
		_exit(127);
	}
	close(outp[1]);
	close(errp[1]);
	r->exec_failed = false;
	r->exec_errno = 0;
	n = read(errp[0], &e, sizeof(e));
	if (n == (ssize_t)sizeof(e)) {
		r->exec_failed = true;
		r->exec_errno = e;
	}
	close(errp[0]);
	off = 0;
	while (off < sizeof(r->out) - 1 &&
	    (n = read(outp[0], r->out + off, sizeof(r->out) - 1 - off)) > 0)
		off += (size_t)n;
	r->out[off] = '\0';
	close(outp[0]);
	r->status = pn_wait(pid);
}

static void
pn_run_path(struct pn_run *r, const char *path, char *const *argv)
{

	memset(r, 0, sizeof(*r));
	r->path = path;
	r->fd = -1;
	r->argv = argv;
}

/* The exec succeeded and the image exited 0. */
static void
pn_require_ran(const struct pn_run *r, const char *what)
{

	ATF_REQUIRE_MSG(!r->exec_failed, "%s: exec failed: %s", what,
	    strerror(r->exec_errno));
	ATF_REQUIRE_MSG(WIFEXITED(r->status) && WEXITSTATUS(r->status) == 0,
	    "%s: image status %#x", what, r->status);
}

static void
pn_require_exec_errno(const struct pn_run *r, int expected, const char *what)
{

	ATF_REQUIRE_MSG(r->exec_failed, "%s: exec succeeded, expected %s",
	    what, strerror(expected));
	PN_CHECK_ERRNO(expected, r->exec_errno, what);
}

/* Line n (0-based) of the output. */
static void
pn_line(const char *out, int n, char *buf, size_t len)
{
	const char *p, *e;

	p = out;
	while (n-- > 0) {
		p = strchr(p, '\n');
		ATF_REQUIRE_MSG(p != NULL, "short output: \"%s\"", out);
		p++;
	}
	e = strchr(p, '\n');
	if (e == NULL)
		e = p + strlen(p);
	ATF_REQUIRE((size_t)(e - p) < len);
	memcpy(buf, p, (size_t)(e - p));
	buf[e - p] = '\0';
}

struct pn_ids {
	unsigned ru, eu, su, rg, eg, sg;
};

static struct pn_ids
pn_parse_ids(const struct pn_run *r)
{
	struct pn_ids ids;

	ATF_REQUIRE_MSG(sscanf(r->out, "%u %u %u %u %u %u", &ids.ru, &ids.eu,
	    &ids.su, &ids.rg, &ids.eg, &ids.sg) == 6, "ids: \"%s\"", r->out);
	return (ids);
}

static void
pn_helper(const atf_tc_t *tc, char *buf, size_t len)
{

	pn_srcfile(tc, "procnet_helper", buf, len);
}

static void
pn_skip_nosuid(const char *dir)
{
	struct statfs sf;

	ATF_REQUIRE(statfs(dir, &sf) == 0);
	if ((sf.f_flags & MNT_NOSUID) != 0)
		atf_tc_skip("%s is on a nosuid file system", dir);
	if ((sf.f_flags & MNT_NOEXEC) != 0)
		atf_tc_skip("%s is on a noexec file system", dir);
}

/*
 * A set-id copy of the helper owned by nobody, in a public directory.
 */
static void
pn_setid_helper(const atf_tc_t *tc, const char *casename, mode_t mode,
    char *path, size_t len)
{
	char dir[PATH_MAX], helper[PATH_MAX];

	pn_helper(tc, helper, sizeof(helper));
	pn_pubdir(casename, dir, sizeof(dir));
	pn_skip_nosuid(dir);
	ATF_REQUIRE((size_t)snprintf(path, len, "%s/setid", dir) < len);
	pn_copyfile(helper, path, 0755);
	ATF_REQUIRE(chown(path, PN_NOBODY, PN_NOGROUP) == 0);
	ATF_REQUIRE(chmod(path, mode) == 0);
}

/* --- set-id images --------------------------------------------------- */

ATF_TC_WITH_CLEANUP(setuid_by_root);
ATF_TC_HEAD(setuid_by_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "root executing a setuid image owned "
	    "by nobody gets euid and saved uid nobody, ruid 0");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_by_root, tc)
{
	char path[PATH_MAX];
	char *argv[] = { __DECONST(char *, "setid"),
	    __DECONST(char *, "ids"), NULL };
	struct pn_run r;
	struct pn_ids ids;

	pn_setid_helper(tc, "setuid_by_root", 04755, path, sizeof(path));
	pn_run_path(&r, path, argv);
	pn_run(&r);
	pn_require_ran(&r, "setuid image");
	ids = pn_parse_ids(&r);
	ATF_CHECK_EQ(0u, ids.ru);
	ATF_CHECK_EQ((unsigned)PN_NOBODY, ids.eu);
	ATF_CHECK_EQ((unsigned)PN_NOBODY, ids.su);
	ATF_CHECK_EQ(0u, ids.rg);
	ATF_CHECK_EQ(0u, ids.eg);
	ATF_CHECK_EQ(0u, ids.sg);
}
ATF_TC_CLEANUP(setuid_by_root, tc)
{
	pn_pubdir_remove("setuid_by_root");
}

ATF_TC_WITH_CLEANUP(setuid_by_unpriv);
ATF_TC_HEAD(setuid_by_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "an unprivileged user executing a "
	    "setuid image owned by nobody gets euid and saved uid nobody");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_by_unpriv, tc)
{
	char path[PATH_MAX];
	char *argv[] = { __DECONST(char *, "setid"),
	    __DECONST(char *, "ids"), NULL };
	struct pn_run r;
	struct pn_ids ids;

	pn_setid_helper(tc, "setuid_by_unpriv", 04755, path, sizeof(path));
	pn_run_path(&r, path, argv);
	r.uid = PN_UID;
	r.gid = PN_GID;
	pn_run(&r);
	pn_require_ran(&r, "setuid image");
	ids = pn_parse_ids(&r);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.ru);
	ATF_CHECK_EQ((unsigned)PN_NOBODY, ids.eu);
	ATF_CHECK_EQ((unsigned)PN_NOBODY, ids.su);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.rg);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.eg);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.sg);
}
ATF_TC_CLEANUP(setuid_by_unpriv, tc)
{
	pn_pubdir_remove("setuid_by_unpriv");
}

ATF_TC_WITH_CLEANUP(setgid_by_unpriv);
ATF_TC_HEAD(setgid_by_unpriv, tc)
{
	atf_tc_set_md_var(tc, "descr", "a setgid image changes egid and the "
	    "saved gid only");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setgid_by_unpriv, tc)
{
	char path[PATH_MAX];
	char *argv[] = { __DECONST(char *, "setid"),
	    __DECONST(char *, "ids"), NULL };
	struct pn_run r;
	struct pn_ids ids;

	pn_setid_helper(tc, "setgid_by_unpriv", 02755, path, sizeof(path));
	pn_run_path(&r, path, argv);
	r.uid = PN_UID;
	r.gid = PN_GID;
	pn_run(&r);
	pn_require_ran(&r, "setgid image");
	ids = pn_parse_ids(&r);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.ru);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.eu);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.su);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.rg);
	ATF_CHECK_EQ((unsigned)PN_NOGROUP, ids.eg);
	ATF_CHECK_EQ((unsigned)PN_NOGROUP, ids.sg);
}
ATF_TC_CLEANUP(setgid_by_unpriv, tc)
{
	pn_pubdir_remove("setgid_by_unpriv");
}

ATF_TC_WITH_CLEANUP(setuid_script_ignored);
ATF_TC_HEAD(setuid_script_ignored, tc)
{
	atf_tc_set_md_var(tc, "descr", "a setuid #! script does not change "
	    "credentials (execve_nosetid() on the interpreter pass)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_script_ignored, tc)
{
	char dir[PATH_MAX], helper[PATH_MAX], script[PATH_MAX];
	char text[PATH_MAX + 16];
	char *argv[] = { __DECONST(char *, "script"), NULL };
	struct pn_run r;
	struct pn_ids ids;

	pn_helper(tc, helper, sizeof(helper));
	pn_pubdir("setuid_script", dir, sizeof(dir));
	pn_skip_nosuid(dir);
	snprintf(script, sizeof(script), "%s/script", dir);
	snprintf(text, sizeof(text), "#!%s ids\n", helper);
	pn_writefile(script, text, strlen(text), 0755);
	ATF_REQUIRE(chown(script, PN_NOBODY, PN_NOGROUP) == 0);
	ATF_REQUIRE(chmod(script, 06755) == 0);
	pn_run_path(&r, script, argv);
	r.uid = PN_UID;
	r.gid = PN_GID;
	pn_run(&r);
	pn_require_ran(&r, "setuid script");
	ids = pn_parse_ids(&r);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.eu);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.su);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.eg);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.sg);
}
ATF_TC_CLEANUP(setuid_script_ignored, tc)
{
	pn_pubdir_remove("setuid_script");
}

ATF_TC(saved_ids_reset);
ATF_TC_HEAD(saved_ids_reset, tc)
{
	atf_tc_set_md_var(tc, "descr", "exec of a plain image sets the saved "
	    "ids to the effective ids (POSIX saved-id behaviour as built)");
	atf_tc_set_md_var(tc, "require.user", "root");
}

static int
saved_ids_child(void *arg)
{
	char *const *argv = arg;

	if (setresgid(PN_GID, PN_GID + 1, PN_GID + 2) != 0 ||
	    setresuid(PN_UID, PN_UID + 1, PN_UID + 2) != 0)
		return (PN_X_SETUP);
	execve(argv[0], argv, environ);
	return (errno);
}

ATF_TC_BODY(saved_ids_reset, tc)
{
	char helper[PATH_MAX];
	char *argv[3];
	struct pn_ids ids;
	pid_t pid;
	ssize_t n;
	int p[2], status;
	char out[256];

	pn_helper(tc, helper, sizeof(helper));
	argv[0] = helper;
	argv[1] = __DECONST(char *, "ids");
	argv[2] = NULL;
	ATF_REQUIRE(pipe(p) == 0);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		close(p[0]);
		dup2(p[1], STDOUT_FILENO);
		_exit(saved_ids_child(argv));
	}
	close(p[1]);
	n = read(p[0], out, sizeof(out) - 1);
	close(p[0]);
	status = pn_wait(pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "status %#x", status);
	ATF_REQUIRE(n > 0);
	out[n] = '\0';
	ATF_REQUIRE(sscanf(out, "%u %u %u %u %u %u", &ids.ru, &ids.eu,
	    &ids.su, &ids.rg, &ids.eg, &ids.sg) == 6);
	ATF_CHECK_EQ((unsigned)PN_UID, ids.ru);
	ATF_CHECK_EQ((unsigned)PN_UID + 1, ids.eu);
	ATF_CHECK_EQ((unsigned)PN_UID + 1, ids.su);
	ATF_CHECK_EQ((unsigned)PN_GID, ids.rg);
	ATF_CHECK_EQ((unsigned)PN_GID + 1, ids.eg);
	ATF_CHECK_EQ((unsigned)PN_GID + 1, ids.sg);
}

ATF_TC_WITH_CLEANUP(setuid_clears_pdeathsig);
ATF_TC_HEAD(setuid_clears_pdeathsig, tc)
{
	atf_tc_set_md_var(tc, "descr", "a credential-changing exec clears "
	    "PROC_PDEATHSIG_CTL; a plain exec keeps it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(setuid_clears_pdeathsig, tc)
{
	char path[PATH_MAX], helper[PATH_MAX];
	char *argv[] = { __DECONST(char *, "x"),
	    __DECONST(char *, "pdeathsig"), NULL };
	struct pn_run r;

	pn_setid_helper(tc, "setuid_pdeathsig", 04755, path, sizeof(path));
	pn_run_path(&r, path, argv);
	r.pdeathsig = SIGUSR1;
	pn_run(&r);
	pn_require_ran(&r, "setuid image");
	ATF_CHECK_EQ_MSG(0, atoi(r.out), "pdeathsig after setuid exec: %s",
	    r.out);

	pn_helper(tc, helper, sizeof(helper));
	pn_run_path(&r, helper, argv);
	r.pdeathsig = SIGUSR1;
	pn_run(&r);
	pn_require_ran(&r, "plain image");
	ATF_CHECK_EQ_MSG(SIGUSR1, atoi(r.out), "pdeathsig after plain exec: "
	    "%s", r.out);
}
ATF_TC_CLEANUP(setuid_clears_pdeathsig, tc)
{
	pn_pubdir_remove("setuid_pdeathsig");
}

/* --- #! interpreters ------------------------------------------------- */

static void
pn_script(const char *name, const char *text, mode_t mode)
{

	pn_writefile(name, text, strlen(text), mode);
}

ATF_TC(shebang_relative_interp);
ATF_TC_HEAD(shebang_relative_interp, tc)
{
	atf_tc_set_md_var(tc, "descr", "a relative #! interpreter is looked "
	    "up from the process's cwd, not the script's directory");
}
ATF_TC_BODY(shebang_relative_interp, tc)
{
	char helper[PATH_MAX], script[PATH_MAX], cwd[PATH_MAX];
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(mkdir("d", 0755) == 0);
	ATF_REQUIRE(symlink(helper, "d/interp") == 0);
	pn_script("d/s", "#!interp exit\n", 0755);
	ATF_REQUIRE(realpath(".", cwd) != NULL);
	snprintf(script, sizeof(script), "%s/d/s", cwd);

	/* From d: "interp" resolves. */
	pn_run_path(&r, script, argv);
	r.cwd = "d";
	pn_run(&r);
	pn_require_ran(&r, "relative interpreter from its directory");

	/* From the parent: it does not, although the script is in d. */
	pn_run_path(&r, script, argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOENT, "relative interpreter elsewhere");
}

ATF_TC(shebang_missing_interp);
ATF_TC_HEAD(shebang_missing_interp, tc)
{
	atf_tc_set_md_var(tc, "descr", "a missing #! interpreter is ENOENT "
	    "from execve(2), and the caller survives");
}
ATF_TC_BODY(shebang_missing_interp, tc)
{
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_script("s", "#!/nonexistent/procnet/interp\n", 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOENT, "missing interpreter");
	ATF_CHECK(WIFEXITED(r.status) && WEXITSTATUS(r.status) == 127);
}

ATF_TC(shebang_directory_interp);
ATF_TC_HEAD(shebang_directory_interp, tc)
{
	atf_tc_set_md_var(tc, "descr", "a directory as #! interpreter is "
	    "EACCES (not a regular file)");
}
ATF_TC_BODY(shebang_directory_interp, tc)
{
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_script("s", "#!/tmp\n", 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "directory interpreter");
}

ATF_TC(shebang_symlink_interp);
ATF_TC_HEAD(shebang_symlink_interp, tc)
{
	atf_tc_set_md_var(tc, "descr", "a #! interpreter reached through a "
	    "symlink runs; argv[0] is the name as written; AT_EXECPATH is "
	    "the interpreter as written and kern.proc.pathname the target");
}
ATF_TC_BODY(shebang_symlink_interp, tc)
{
	char helper[PATH_MAX], link[PATH_MAX], text[PATH_MAX + 32];
	char rhelper[PATH_MAX], line[PATH_MAX], script[PATH_MAX];
	char *argv[] = { __DECONST(char *, "s"), __DECONST(char *, "A"),
	    NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(realpath(helper, rhelper) != NULL);
	pn_cwdpath("link", link, sizeof(link));
	ATF_REQUIRE(symlink(helper, "link") == 0);
	pn_cwdpath("s", script, sizeof(script));

	snprintf(text, sizeof(text), "#!%s args\n", link);
	pn_script("s", text, 0755);
	pn_run_path(&r, script, argv);
	pn_run(&r);
	pn_require_ran(&r, "symlinked interpreter");
	/* argc 4: interpreter, option, script, the caller's "A". */
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ("4", line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(link, line);
	pn_line(r.out, 2, line, sizeof(line));
	ATF_CHECK_STREQ("args", line);
	pn_line(r.out, 3, line, sizeof(line));
	ATF_CHECK_STREQ(script, line);
	pn_line(r.out, 4, line, sizeof(line));
	ATF_CHECK_STREQ("A", line);

	snprintf(text, sizeof(text), "#!%s paths\n", link);
	pn_script("s", text, 0755);
	pn_run_path(&r, script, argv);
	pn_run(&r);
	pn_require_ran(&r, "symlinked interpreter, paths");
	/*
	 * The interpreter pass looks up args->fname = the interpreter name
	 * as written; it is absolute, so AT_EXECPATH is that string.
	 */
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(link, line);
	/*
	 * kern.proc.pathname: p_textdvp/p_binname of the followed lookup,
	 * i.e. the target (to be confirmed on the pre-1c kernel).
	 */
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(rhelper, line);
}

ATF_TC(shebang_too_long);
ATF_TC_HEAD(shebang_too_long, tc)
{
	atf_tc_set_md_var(tc, "descr", "a #! interpreter name of MAXINTERP "
	    "bytes or more is ENAMETOOLONG before any lookup");
}
ATF_TC_BODY(shebang_too_long, tc)
{
	char text[MAXINTERP + 64];
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;
	size_t i;

	strlcpy(text, "#!/", sizeof(text));
	for (i = 3; i < MAXINTERP + 2; i++)
		text[i] = 'a';
	text[i++] = '\n';
	text[i] = '\0';
	pn_script("s", text, 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENAMETOOLONG, "interpreter too long");
}

ATF_TC(shebang_no_newline);
ATF_TC_HEAD(shebang_no_newline, tc)
{
	atf_tc_set_md_var(tc, "descr", "a #! line that reaches the end of "
	    "the file without a newline is ENOEXEC (opte == maxp)");
}
ATF_TC_BODY(shebang_no_newline, tc)
{
	char helper[PATH_MAX], text[PATH_MAX + 16];
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	snprintf(text, sizeof(text), "#!%s exit", helper);
	pn_script("s", text, 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "no newline");

	/* The same line with its newline runs. */
	snprintf(text, sizeof(text), "#!%s exit\n", helper);
	pn_script("s", text, 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_ran(&r, "with newline");
}

ATF_TC(shebang_empty);
ATF_TC_HEAD(shebang_empty, tc)
{
	atf_tc_set_md_var(tc, "descr", "a #! line without an interpreter "
	    "(only blanks) is ENOEXEC");
}
ATF_TC_BODY(shebang_empty, tc)
{
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_script("s", "#!   \t\n", 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "empty #!");
}

ATF_TC(shebang_nested);
ATF_TC_HEAD(shebang_nested, tc)
{
	atf_tc_set_md_var(tc, "descr", "a #! script as the interpreter of a "
	    "#! script is ENOEXEC");
}
ATF_TC_BODY(shebang_nested, tc)
{
	char helper[PATH_MAX], text[PATH_MAX + 16], inner[PATH_MAX];
	char *argv[] = { __DECONST(char *, "outer"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	snprintf(text, sizeof(text), "#!%s exit\n", helper);
	pn_script("inner", text, 0755);
	pn_cwdpath("inner", inner, sizeof(inner));
	snprintf(text, sizeof(text), "#!%s\n", inner);
	pn_script("outer", text, 0755);

	pn_run_path(&r, "./inner", argv);
	pn_run(&r);
	pn_require_ran(&r, "inner script alone");

	pn_run_path(&r, "./outer", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "nested #!");
}

ATF_TC(shebang_args_layout);
ATF_TC_HEAD(shebang_args_layout, tc)
{
	atf_tc_set_md_var(tc, "descr", "#! options are one argument with "
	    "trailing blanks trimmed; argv[0] is replaced, the script path "
	    "and the remaining arguments follow");
}
ATF_TC_BODY(shebang_args_layout, tc)
{
	char helper[PATH_MAX], text[PATH_MAX + 32], line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "zero"), __DECONST(char *, "B"),
	    __DECONST(char *, "C D"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	snprintf(text, sizeof(text), "#! \t%s   args  x\t \nignored\n",
	    helper);
	pn_script("s", text, 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_ran(&r, "options");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ("5", line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(helper, line);
	pn_line(r.out, 2, line, sizeof(line));
	ATF_CHECK_STREQ("args  x", line);
	pn_line(r.out, 3, line, sizeof(line));
	ATF_CHECK_STREQ("./s", line);
	pn_line(r.out, 4, line, sizeof(line));
	ATF_CHECK_STREQ("B", line);
	pn_line(r.out, 5, line, sizeof(line));
	ATF_CHECK_STREQ("C D", line);
}

ATF_TC(shebang_not_executable);
ATF_TC_HEAD(shebang_not_executable, tc)
{
	atf_tc_set_md_var(tc, "descr", "a script without an execute bit is "
	    "EACCES even for root; an interpreter without one too");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(shebang_not_executable, tc)
{
	char helper[PATH_MAX], text[PATH_MAX + 32];
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	snprintf(text, sizeof(text), "#!%s exit\n", helper);
	pn_script("s", text, 0644);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "script mode 0644");

	pn_copyfile(helper, "interp", 0644);
	pn_script("s", "#!./interp exit\n", 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "interpreter mode 0644");
}

ATF_TC(shebang_execpath);
ATF_TC_HEAD(shebang_execpath, tc)
{
	atf_tc_set_md_var(tc, "descr", "for a #! script AT_EXECPATH and "
	    "kern.proc.pathname name the interpreter, not the script");
}
ATF_TC_BODY(shebang_execpath, tc)
{
	char helper[PATH_MAX], rhelper[PATH_MAX], text[PATH_MAX + 32];
	char line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(realpath(helper, rhelper) != NULL);
	snprintf(text, sizeof(text), "#!%s paths\n", rhelper);
	pn_script("s", text, 0755);
	pn_run_path(&r, "./s", argv);
	pn_run(&r);
	pn_require_ran(&r, "script");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(rhelper, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(rhelper, line);
}

/* --- ELF PT_INTERP --------------------------------------------------- */

/*
 * Copy the dynamic helper to "to" and overwrite the last byte of its
 * PT_INTERP string: with a digit ('\0' kept) or the terminator itself.
 */
static void
pn_patch_interp(const atf_tc_t *tc, const char *to, bool unterminate)
{
	char helper[PATH_MAX];
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	char c;
	int fd, i;
	bool found;

	pn_helper(tc, helper, sizeof(helper));
	pn_copyfile(helper, to, 0755);
	fd = open(to, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pread(fd, &eh, sizeof(eh), 0) == (ssize_t)sizeof(eh));
	ATF_REQUIRE(memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0);
	if (eh.e_ident[EI_CLASS] != ELFCLASS64)
		atf_tc_skip("not an ELF64 helper");
	found = false;
	for (i = 0; i < eh.e_phnum; i++) {
		ATF_REQUIRE(pread(fd, &ph, sizeof(ph), (off_t)(eh.e_phoff +
		    (size_t)i * eh.e_phentsize)) == (ssize_t)sizeof(ph));
		if (ph.p_type != PT_INTERP)
			continue;
		found = true;
		ATF_REQUIRE(ph.p_filesz >= 3);
		if (unterminate) {
			c = 'X';
			ATF_REQUIRE(pwrite(fd, &c, 1,
			    (off_t)(ph.p_offset + ph.p_filesz - 1)) == 1);
		} else {
			/* "/libexec/ld-elf.so.1" -> "/libexec/ld-elf.so.7" */
			c = '7';
			ATF_REQUIRE(pwrite(fd, &c, 1,
			    (off_t)(ph.p_offset + ph.p_filesz - 2)) == 1);
		}
	}
	ATF_REQUIRE_MSG(found, "the helper has no PT_INTERP");
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(elf_interp_missing);
ATF_TC_HEAD(elf_interp_missing, tc)
{
	atf_tc_set_md_var(tc, "descr", "a PT_INTERP naming a missing file "
	    "fails after the old image is gone: the process exits on "
	    "SIGABRT (kern_exit), execve(2) does not return");
}
ATF_TC_BODY(elf_interp_missing, tc)
{
	char *argv[] = { __DECONST(char *, "img"), __DECONST(char *, "exit"),
	    NULL };
	struct pn_run r;

	if (access("/libexec/ld-elf.so.7", F_OK) == 0)
		atf_tc_skip("/libexec/ld-elf.so.7 exists");
	pn_patch_interp(tc, "img", false);
	pn_run_path(&r, "./img", argv);
	pn_run(&r);
	ATF_CHECK_MSG(!r.exec_failed, "execve returned %s",
	    strerror(r.exec_errno));
	ATF_CHECK_MSG(WIFSIGNALED(r.status) && WTERMSIG(r.status) == SIGABRT,
	    "status %#x", r.status);
	ATF_CHECK_MSG(!WCOREDUMP(r.status), "core dumped");
}

ATF_TC(elf_interp_unterminated);
ATF_TC_HEAD(elf_interp_unterminated, tc)
{
	atf_tc_set_md_var(tc, "descr", "a PT_INTERP without its terminating "
	    "NUL is ENOEXEC from execve(2) (before the old image goes)");
}
ATF_TC_BODY(elf_interp_unterminated, tc)
{
	char *argv[] = { __DECONST(char *, "img"), __DECONST(char *, "exit"),
	    NULL };
	struct pn_run r;

	pn_patch_interp(tc, "img", true);
	pn_run_path(&r, "./img", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "unterminated PT_INTERP");
}

ATF_TC(elf_static_execpath);
ATF_TC_HEAD(elf_static_execpath, tc)
{
	atf_tc_set_md_var(tc, "descr", "an image without PT_INTERP runs and "
	    "gets AT_EXECPATH and kern.proc.pathname");
}
ATF_TC_BODY(elf_static_execpath, tc)
{
	char helper[PATH_MAX], rhelper[PATH_MAX], line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "s"), __DECONST(char *, "paths"),
	    NULL };
	struct pn_run r;

	pn_srcfile(tc, "procnet_helper_static", helper, sizeof(helper));
	ATF_REQUIRE(realpath(helper, rhelper) != NULL);
	pn_run_path(&r, rhelper, argv);
	pn_run(&r);
	pn_require_ran(&r, "static image");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(rhelper, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(rhelper, line);
}

/* --- AT_EXECPATH and kern.proc.pathname ------------------------------ */

ATF_TC(execpath_absolute);
ATF_TC_HEAD(execpath_absolute, tc)
{
	atf_tc_set_md_var(tc, "descr", "absolute exec: AT_EXECPATH is the "
	    "path as given, kern.proc.pathname the same file");
}
ATF_TC_BODY(execpath_absolute, tc)
{
	char helper[PATH_MAX], img[PATH_MAX], line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "img"), __DECONST(char *, "paths"),
	    NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	pn_copyfile(helper, "img", 0755);
	pn_cwdpath("img", img, sizeof(img));
	pn_run_path(&r, img, argv);
	pn_run(&r);
	pn_require_ran(&r, "absolute");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
}

ATF_TC(execpath_relative);
ATF_TC_HEAD(execpath_relative, tc)
{
	atf_tc_set_md_var(tc, "descr", "relative exec, also through \"..\": "
	    "AT_EXECPATH and kern.proc.pathname are the full path");
}
ATF_TC_BODY(execpath_relative, tc)
{
	char helper[PATH_MAX], img[PATH_MAX], line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "img"), __DECONST(char *, "paths"),
	    NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(mkdir("sub", 0755) == 0);
	pn_copyfile(helper, "img", 0755);
	pn_cwdpath("img", img, sizeof(img));

	pn_run_path(&r, "./img", argv);
	pn_run(&r);
	pn_require_ran(&r, "./img");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);

	pn_run_path(&r, "../img", argv);
	r.cwd = "sub";
	pn_run(&r);
	pn_require_ran(&r, "../img");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
}

ATF_TC(execpath_symlink);
ATF_TC_HEAD(execpath_symlink, tc)
{
	atf_tc_set_md_var(tc, "descr", "exec through a symlink: an absolute "
	    "name is AT_EXECPATH as given, a relative one the target's full "
	    "path; kern.proc.pathname is the target either way");
}
ATF_TC_BODY(execpath_symlink, tc)
{
	char helper[PATH_MAX], img[PATH_MAX], link[PATH_MAX];
	char line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "l"), __DECONST(char *, "paths"),
	    NULL };
	struct pn_run r;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(mkdir("real", 0755) == 0);
	pn_copyfile(helper, "real/img", 0755);
	pn_cwdpath("real/img", img, sizeof(img));
	ATF_REQUIRE(symlink("real/img", "link") == 0);
	pn_cwdpath("link", link, sizeof(link));

	pn_run_path(&r, link, argv);
	pn_run(&r);
	pn_require_ran(&r, "absolute symlink");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(link, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);

	/*
	 * Relative: IS_PATH() resolves the followed vnode, its directory
	 * and last component (vn_fullpath_hardlink), i.e. the target.
	 * To be confirmed on the pre-1c kernel.
	 */
	pn_run_path(&r, "./link", argv);
	pn_run(&r);
	pn_require_ran(&r, "relative symlink");
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
}

ATF_TC(fexecve_paths);
ATF_TC_HEAD(fexecve_paths, tc)
{
	atf_tc_set_md_var(tc, "descr", "fexecve(2) of an image opened by "
	    "path runs, with AT_EXECPATH from vn_fullpath(); of a script, "
	    "the interpreter sees /dev/fd/N as the script name");
}
ATF_TC_BODY(fexecve_paths, tc)
{
	char helper[PATH_MAX], img[PATH_MAX], line[PATH_MAX];
	char text[PATH_MAX + 32], devfd[32];
	char *argv[] = { __DECONST(char *, "img"), __DECONST(char *, "paths"),
	    NULL };
	char *sargv[] = { __DECONST(char *, "s"), NULL };
	struct pn_run r;
	int fd;

	pn_helper(tc, helper, sizeof(helper));
	pn_copyfile(helper, "img", 0755);
	pn_cwdpath("img", img, sizeof(img));
	fd = open("img", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	memset(&r, 0, sizeof(r));
	r.fd = fd;
	r.argv = argv;
	pn_run(&r);
	pn_require_ran(&r, "fexecve");
	/*
	 * exec_image_vnode_from_vnode(): vn_fullpath() of the vnode; the
	 * name was just looked up, so it is cached (to be confirmed).
	 */
	pn_line(r.out, 0, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	pn_line(r.out, 1, line, sizeof(line));
	ATF_CHECK_STREQ(img, line);
	close(fd);

	snprintf(text, sizeof(text), "#!%s args\n", helper);
	pn_script("s", text, 0755);
	fd = open("s", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	memset(&r, 0, sizeof(r));
	r.fd = fd;
	r.argv = sargv;
	pn_run(&r);
	pn_require_ran(&r, "fexecve script");
	snprintf(devfd, sizeof(devfd), "/dev/fd/%d", fd);
	pn_line(r.out, 3, line, sizeof(line));
	ATF_CHECK_STREQ(devfd, line);
	close(fd);

	/* A directory descriptor is EACCES. */
	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	memset(&r, 0, sizeof(r));
	r.fd = fd;
	r.argv = sargv;
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "fexecve of a directory");
	close(fd);

	/* A closed descriptor is EBADF. */
	memset(&r, 0, sizeof(r));
	r.fd = 1000;
	r.argv = sargv;
	pn_run(&r);
	pn_require_exec_errno(&r, EBADF, "fexecve of a closed descriptor");
}

/* --- exec racing a sibling thread's chdir ---------------------------- */

static volatile bool chdir_stop;
static volatile u_int chdir_gen;
static const char *chdir_dir;

/*
 * Flip the cwd, counting each chdir(2) that returned.  The count lets the
 * exec loop wait for a completed flip between attempts: execve(2)
 * single-threads the process, which restarts a sibling's interruptible
 * sleep (ERESTART), so a chdir(2) that sleeps, as an attached process's
 * consultation does, could otherwise be restarted by every attempt and
 * never return.
 */
static void *
chdir_loop(void *arg __unused)
{

	while (!chdir_stop) {
		(void)chdir("/");
		__atomic_add_fetch(&chdir_gen, 1, __ATOMIC_RELEASE);
		(void)chdir(chdir_dir);
		__atomic_add_fetch(&chdir_gen, 1, __ATOMIC_RELEASE);
	}
	return (NULL);
}

/* Wait (60 s at most) for a chdir(2) completed after generation g. */
static bool
chdir_wait(u_int g)
{
	struct timespec t0, t;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	while (__atomic_load_n(&chdir_gen, __ATOMIC_ACQUIRE) == g) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t);
		if (t.tv_sec - t0.tv_sec >= 60)
			return (false);
		sched_yield();
	}
	return (true);
}

ATF_TC(exec_chdir_race);
ATF_TC_HEAD(exec_chdir_race, tc)
{
	atf_tc_set_md_var(tc, "descr", "a relative execve(2) while a sibling "
	    "thread flips the cwd either fails with ENOENT or runs the image "
	    "from the right directory with consistent paths");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(exec_chdir_race, tc)
{
	char helper[PATH_MAX], dir[PATH_MAX], img[PATH_MAX], line[PATH_MAX];
	char *argv[] = { __DECONST(char *, "procnet_race_img"),
	    __DECONST(char *, "paths"), NULL };
	pthread_t thr;
	pid_t pid;
	ssize_t n;
	int i, status, p[2], ran, attempts;
	char out[2 * PATH_MAX + 8];
	u_int gen;

	pn_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE(mkdir("racedir", 0755) == 0);
	pn_copyfile(helper, "racedir/procnet_race_img", 0755);
	ATF_REQUIRE(realpath("racedir", dir) != NULL);
	snprintf(img, sizeof(img), "%s/procnet_race_img", dir);
	ATF_REQUIRE(access("/procnet_race_img", F_OK) != 0);

	ran = 0;
	for (i = 0; i < 64; i++) {
		ATF_REQUIRE(pipe(p) == 0);
		pid = fork();
		ATF_REQUIRE(pid != -1);
		if (pid == 0) {
			close(p[0]);
			dup2(p[1], STDOUT_FILENO);
			chdir_dir = dir;
			if (pthread_create(&thr, NULL, chdir_loop, NULL) != 0)
				_exit(PN_X_SETUP);
			for (attempts = 0; attempts < 10000; attempts++) {
				gen = __atomic_load_n(&chdir_gen,
				    __ATOMIC_ACQUIRE);
				execve("./procnet_race_img", argv, environ);
				if (errno != ENOENT)
					_exit(errno);
				/* The next attempt races a newer cwd. */
				if (!chdir_wait(gen))
					_exit(ETIMEDOUT);
			}
			_exit(ENOENT);
		}
		close(p[1]);
		n = 0;
		memset(out, 0, sizeof(out));
		while ((size_t)n < sizeof(out) - 1) {
			ssize_t k = read(p[0], out + n,
			    sizeof(out) - 1 - (size_t)n);
			if (k <= 0)
				break;
			n += k;
		}
		close(p[0]);
		status = pn_wait(pid);
		ATF_REQUIRE_MSG(WIFEXITED(status), "status %#x", status);
		if (WEXITSTATUS(status) == ENOENT)
			continue;
		ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0, "exec: %s",
		    pn_errname(WEXITSTATUS(status)));
		ran++;
		pn_line(out, 0, line, sizeof(line));
		ATF_CHECK_STREQ(img, line);
		pn_line(out, 1, line, sizeof(line));
		ATF_CHECK_STREQ(img, line);
	}
	ATF_CHECK_MSG(ran > 0, "the image never ran");
}

/* --- E2BIG, ENOEXEC, EACCES ordering --------------------------------- */

static char **
pn_huge_argv(void)
{
	static char **v;
	static char *arg;
	size_t i, n;

	if (v != NULL)
		return (v);
	/* 4 MiB of arguments: more than ARG_MAX (256 KiB on amd64). */
	n = 64;
	arg = malloc(65536 + 1);
	ATF_REQUIRE(arg != NULL);
	memset(arg, 'x', 65536);
	arg[65536] = '\0';
	v = calloc(n + 2, sizeof(*v));
	ATF_REQUIRE(v != NULL);
	v[0] = __DECONST(char *, "big");
	for (i = 1; i <= n; i++)
		v[i] = arg;
	v[n + 1] = NULL;
	return (v);
}

ATF_TC(e2big_ordering);
ATF_TC_HEAD(e2big_ordering, tc)
{
	atf_tc_set_md_var(tc, "descr", "arguments over ARG_MAX are E2BIG "
	    "before the lookup: for a missing file, a garbage file and a "
	    "directory alike; a path over PATH_MAX is E2BIG too");
}
ATF_TC_BODY(e2big_ordering, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	char *longpath;
	struct pn_run r;

	ATF_REQUIRE((size_t)ARG_MAX < 64 * 65536);
	pn_script("garbage", "\177garbage-not-an-image\n", 0755);

	pn_run_path(&r, "/nonexistent/procnet", pn_huge_argv());
	pn_run(&r);
	pn_require_exec_errno(&r, E2BIG, "huge argv, missing file");

	pn_run_path(&r, "./garbage", pn_huge_argv());
	pn_run(&r);
	pn_require_exec_errno(&r, E2BIG, "huge argv, garbage file");

	pn_run_path(&r, "/", pn_huge_argv());
	pn_run(&r);
	pn_require_exec_errno(&r, E2BIG, "huge argv, directory");

	/* exec_args_add_fname(): ENAMETOOLONG from copyinstr is E2BIG. */
	longpath = malloc(2 * PATH_MAX);
	ATF_REQUIRE(longpath != NULL);
	memset(longpath, 'a', 2 * PATH_MAX - 1);
	longpath[2 * PATH_MAX - 1] = '\0';
	pn_run_path(&r, longpath, argv);
	pn_run(&r);
	pn_require_exec_errno(&r, E2BIG, "path over PATH_MAX");
	free(longpath);
}

ATF_TC(enoexec_eacces);
ATF_TC_HEAD(enoexec_eacces, tc)
{
	atf_tc_set_md_var(tc, "descr", "garbage and empty executables are "
	    "ENOEXEC; no execute bit or a directory is EACCES, which wins "
	    "over ENOEXEC; a missing file ENOENT; a NULL argv EFAULT");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enoexec_eacces, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	struct pn_run r;

	pn_script("garbage", "\177garbage-not-an-image\n", 0755);
	pn_script("garbage_nx", "\177garbage-not-an-image\n", 0644);
	pn_script("empty", "", 0755);
	ATF_REQUIRE(mkdir("dir", 0755) == 0);

	pn_run_path(&r, "./garbage", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "garbage");

	pn_run_path(&r, "./empty", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOEXEC, "empty");

	pn_run_path(&r, "./garbage_nx", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "garbage without x");

	pn_run_path(&r, "./dir", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, EACCES, "directory");

	pn_run_path(&r, "./missing", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOENT, "missing");

	pn_run_path(&r, "./garbage/x", argv);
	pn_run(&r);
	pn_require_exec_errno(&r, ENOTDIR, "through a file");

	pn_run_path(&r, "./garbage", NULL);
	pn_run(&r);
	pn_require_exec_errno(&r, EFAULT, "NULL argv");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, setuid_by_root);
	ATF_TP_ADD_TC(tp, setuid_by_unpriv);
	ATF_TP_ADD_TC(tp, setgid_by_unpriv);
	ATF_TP_ADD_TC(tp, setuid_script_ignored);
	ATF_TP_ADD_TC(tp, saved_ids_reset);
	ATF_TP_ADD_TC(tp, setuid_clears_pdeathsig);
	ATF_TP_ADD_TC(tp, shebang_relative_interp);
	ATF_TP_ADD_TC(tp, shebang_missing_interp);
	ATF_TP_ADD_TC(tp, shebang_directory_interp);
	ATF_TP_ADD_TC(tp, shebang_symlink_interp);
	ATF_TP_ADD_TC(tp, shebang_too_long);
	ATF_TP_ADD_TC(tp, shebang_no_newline);
	ATF_TP_ADD_TC(tp, shebang_empty);
	ATF_TP_ADD_TC(tp, shebang_nested);
	ATF_TP_ADD_TC(tp, shebang_args_layout);
	ATF_TP_ADD_TC(tp, shebang_not_executable);
	ATF_TP_ADD_TC(tp, shebang_execpath);
	ATF_TP_ADD_TC(tp, elf_interp_missing);
	ATF_TP_ADD_TC(tp, elf_interp_unterminated);
	ATF_TP_ADD_TC(tp, elf_static_execpath);
	ATF_TP_ADD_TC(tp, execpath_absolute);
	ATF_TP_ADD_TC(tp, execpath_relative);
	ATF_TP_ADD_TC(tp, execpath_symlink);
	ATF_TP_ADD_TC(tp, fexecve_paths);
	ATF_TP_ADD_TC(tp, exec_chdir_race);
	ATF_TP_ADD_TC(tp, e2big_ordering);
	ATF_TP_ADD_TC(tp, enoexec_eacces);
	return (atf_no_error());
}
