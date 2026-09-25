/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests for exec of dynamically linked images from capability mode.
 *
 * The ELF image activator may resolve exactly one path on behalf of a
 * capability-mode process: its brand's own interpreter.  A PT_INTERP the
 * image chose must still fail with ECAPMODE before any lookup happens, and
 * the kern.elf<N>.capmode_interp knob must close the door entirely.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/elf.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#define	HELPER		"capmode_interp_helper"
#define	FOREIGN_HELPER	"capmode_interp_foreign_helper"
#define	STATIC_HELPER	"capmode_interp_static_helper"
#define	BRAND_INTERP	"/libexec/ld-elf.so.1"

/*
 * exec_from_capmode() result space: the helper's own exit code (0 or
 * 201..206), the errno a refused exec returned to the child, COMM_MISMATCH
 * when the helper ran under the wrong command name, or, when the kernel had
 * already replaced the address space before the interpreter failed to load,
 * SIGNALED plus the signal that ended the child.
 */
#define	SIGNALED	1000
#define	COMM_MISMATCH	2000

#if __ELF_WORD_SIZE == 64
#define	CAPMODE_INTERP_SYSCTL	"kern.elf64.capmode_interp"
#else
#define	CAPMODE_INTERP_SYSCTL	"kern.elf32.capmode_interp"
#endif

/*
 * fexecve(2) "path" from a child that entered capability mode first, with
 * /lib and /usr/lib delivered to rtld as LD_LIBRARY_PATH_FDS.  Returns the
 * child's exit status: the helper's own code on success, the errno the
 * exec failed with, SIGNALED plus a signal, or COMM_MISMATCH when the
 * helper ran but the kernel did not name the process after it.  "capmode"
 * false runs the same exec un-sandboxed as a control.
 *
 * The helper cannot read kern.proc.pid from capability mode, so it reports
 * readiness on a pipe (its fd 3) and waits on another (fd 4) while this
 * process reads its command name.
 */
static int
exec_from_capmode(const char *path, const char *comm, bool capmode)
{
	struct kinfo_proc kp;
	char fds[64], c;
	char *const argv[] = { __DECONST(char *, comm),
	    __DECONST(char *, comm), NULL };
	char *envp[2];
	size_t len;
	ssize_t n;
	pid_t pid;
	int fd, libfd, usrlibfd, ready[2], go[2], status, mib[4];
	bool comm_ok;

	/* A helper that exits before reading its go byte must not kill us. */
	ATF_REQUIRE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(go) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/*
		 * pipe(2) may itself have handed out 3 or 4; move the ends
		 * the helper uses to their fixed numbers first, then close
		 * only originals that are not those numbers.
		 */
		if (dup2(ready[1], 3) != 3 || dup2(go[0], 4) != 4)
			_exit(errno);
		if (ready[0] != 3 && ready[0] != 4)
			(void)close(ready[0]);
		if (ready[1] != 3 && ready[1] != 4)
			(void)close(ready[1]);
		if (go[0] != 3 && go[0] != 4)
			(void)close(go[0]);
		if (go[1] != 3 && go[1] != 4)
			(void)close(go[1]);
		libfd = open("/lib", O_DIRECTORY | O_RDONLY);
		usrlibfd = open("/usr/lib", O_DIRECTORY | O_RDONLY);
		fd = open(path, O_EXEC);
		if (libfd < 0 || usrlibfd < 0 || fd < 0)
			_exit(errno);
		snprintf(fds, sizeof(fds), "LD_LIBRARY_PATH_FDS=%d:%d",
		    libfd, usrlibfd);
		envp[0] = fds;
		envp[1] = NULL;
		if (capmode && cap_enter() != 0)
			_exit(errno);
		fexecve(fd, argv, envp);
		_exit(errno);
	}
	ATF_REQUIRE(close(ready[1]) == 0);
	ATF_REQUIRE(close(go[0]) == 0);
	comm_ok = true;
	n = read(ready[0], &c, 1);
	if (n == 1) {
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = KERN_PROC_PID;
		mib[3] = pid;
		len = sizeof(kp);
		ATF_REQUIRE(sysctl(mib, 4, &kp, &len, NULL, 0) == 0);
		/* The kernel keeps at most MAXCOMLEN bytes of the name. */
		comm_ok = strncmp(kp.ki_comm, comm, MAXCOMLEN) == 0;
		if (!comm_ok)
			printf("command name %s, expected %s\n", kp.ki_comm,
			    comm);
		(void)write(go[1], "G", 1);
	}
	ATF_REQUIRE(close(ready[0]) == 0);
	ATF_REQUIRE(close(go[1]) == 0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	if (WIFSIGNALED(status))
		return (SIGNALED + WTERMSIG(status));
	ATF_REQUIRE_MSG(WIFEXITED(status), "child neither exited nor was "
	    "signaled");
	if (WEXITSTATUS(status) == 0 && !comm_ok)
		return (COMM_MISMATCH);
	return (WEXITSTATUS(status));
}

static void
helper_path(const atf_tc_t *tc, const char *name, char *buf, size_t len)
{
	ATF_REQUIRE(snprintf(buf, len, "%s/%s",
	    atf_tc_get_config_var(tc, "srcdir"), name) < (int)len);
}

static void
copy_file(const char *from, const char *to, mode_t mode)
{
	char buf[65536];
	ssize_t n;
	int in, out;

	in = open(from, O_RDONLY);
	ATF_REQUIRE(in >= 0);
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
	ATF_REQUIRE(out >= 0);
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE(write(out, buf, n) == n);
	ATF_REQUIRE(n == 0);
	ATF_REQUIRE(close(in) == 0);
	ATF_REQUIRE(close(out) == 0);
}

/*
 * Point "path"'s PT_INTERP at "interp".  The foreign helper is linked with
 * a long placeholder interpreter so the real one fits in place.
 */
static void
set_interp(const char *path, const char *interp)
{
	Elf_Ehdr ehdr;
	Elf_Phdr phdr;
	size_t len;
	int fd, i;
	bool found;

	len = strlen(interp) + 1;
	fd = open(path, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pread(fd, &ehdr, sizeof(ehdr), 0) == sizeof(ehdr));
	ATF_REQUIRE(IS_ELF(ehdr));
	found = false;
	for (i = 0; i < ehdr.e_phnum; i++) {
		ATF_REQUIRE(pread(fd, &phdr, sizeof(phdr),
		    ehdr.e_phoff + i * ehdr.e_phentsize) == sizeof(phdr));
		if (phdr.p_type != PT_INTERP)
			continue;
		ATF_REQUIRE_MSG(len <= phdr.p_filesz,
		    "interpreter path %zu bytes does not fit PT_INTERP %ju",
		    len, (uintmax_t)phdr.p_filesz);
		{
			char *buf;

			buf = calloc(1, phdr.p_filesz);
			ATF_REQUIRE(buf != NULL);
			memcpy(buf, interp, len);
			ATF_REQUIRE(pwrite(fd, buf, phdr.p_filesz,
			    phdr.p_offset) == (ssize_t)phdr.p_filesz);
			free(buf);
		}
		found = true;
		break;
	}
	ATF_REQUIRE_MSG(found, "no PT_INTERP in %s", path);
	ATF_REQUIRE(close(fd) == 0);
}

/* A copy of the helper whose PT_INTERP is a private copy of rtld. */
static void
make_foreign(const atf_tc_t *tc, char *path, size_t len)
{
	char src[MAXPATHLEN], interp[MAXPATHLEN], cwd[MAXPATHLEN];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(snprintf(interp, sizeof(interp), "%s/rtld-copy", cwd) <
	    (int)sizeof(interp));
	copy_file(BRAND_INTERP, interp, 0555);
	helper_path(tc, FOREIGN_HELPER, src, sizeof(src));
	ATF_REQUIRE(snprintf(path, len, "%s/%s", cwd, FOREIGN_HELPER) <
	    (int)len);
	copy_file(src, path, 0755);
	set_interp(path, interp);
}

static bool
knob_enabled(void)
{
	bool val;
	size_t len;

	len = sizeof(val);
	if (sysctlbyname(CAPMODE_INTERP_SYSCTL, &val, &len, NULL, 0) != 0)
		atf_tc_skip("%s is not present in this kernel",
		    CAPMODE_INTERP_SYSCTL);
	return (val);
}

static void
set_knob(bool val)
{
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(CAPMODE_INTERP_SYSCTL, NULL, NULL,
	    &val, sizeof(val)), "%s: %s", CAPMODE_INTERP_SYSCTL,
	    strerror(errno));
}

ATF_TC(brand_interp_capmode);
ATF_TC_HEAD(brand_interp_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "A dynamic image whose PT_INTERP is "
	    "the brand's rtld execs from capability mode, and the process is "
	    "named after the program, not the interpreter");
}
ATF_TC_BODY(brand_interp_capmode, tc)
{
	char path[MAXPATHLEN];
	int rc;

	if (!knob_enabled())
		atf_tc_skip("%s is disabled", CAPMODE_INTERP_SYSCTL);
	helper_path(tc, HELPER, path, sizeof(path));
	ATF_CHECK_EQ_MSG(0, (rc = exec_from_capmode(path, HELPER, true)),
	    "helper result %d", rc);
}

ATF_TC(foreign_interp_capmode);
ATF_TC_HEAD(foreign_interp_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "A dynamic image whose PT_INTERP is "
	    "any other path, even a working copy of rtld, is refused with "
	    "ECAPMODE from capability mode");
}
ATF_TC_BODY(foreign_interp_capmode, tc)
{
	char path[MAXPATHLEN];
	int rc;

	make_foreign(tc, path, sizeof(path));
	/* Control: the image and its private interpreter are sound. */
	ATF_REQUIRE_EQ_MSG(202,
	    (rc = exec_from_capmode(path, FOREIGN_HELPER, false)),
	    "foreign-interpreter helper outside capability mode: %d", rc);
	ATF_CHECK_EQ_MSG(ECAPMODE,
	    (rc = exec_from_capmode(path, FOREIGN_HELPER, true)),
	    "foreign interpreter from capability mode: %d", rc);
}

ATF_TC(missing_interp_capmode);
ATF_TC_HEAD(missing_interp_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "A PT_INTERP that does not exist is "
	    "refused with ECAPMODE, not ENOENT: no lookup ever happens");
}
ATF_TC_BODY(missing_interp_capmode, tc)
{
	char path[MAXPATHLEN], src[MAXPATHLEN];
	int rc;

	helper_path(tc, FOREIGN_HELPER, src, sizeof(src));
	ATF_REQUIRE(snprintf(path, sizeof(path), "%s", FOREIGN_HELPER) <
	    (int)sizeof(path));
	copy_file(src, path, 0755);
	set_interp(path, "/nonexistent/ld-elf.so.1");
	/*
	 * Control: outside capability mode the lookup happens after the old
	 * address space is gone, so the kernel ends the child with a signal
	 * rather than returning ENOENT.  From capability mode the refusal
	 * comes before that point and the child survives to report ECAPMODE.
	 */
	rc = exec_from_capmode(path, FOREIGN_HELPER, false);
	ATF_REQUIRE_MSG(rc >= SIGNALED, "missing interpreter outside "
	    "capability mode: %d", rc);
	ATF_CHECK_EQ_MSG(ECAPMODE,
	    (rc = exec_from_capmode(path, FOREIGN_HELPER, true)),
	    "missing interpreter from capability mode: %d", rc);
}

ATF_TC(brand_prefix_capmode);
ATF_TC_HEAD(brand_prefix_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr", "A PT_INTERP that merely extends the "
	    "brand's interpreter path is not the brand's interpreter");
}
ATF_TC_BODY(brand_prefix_capmode, tc)
{
	char path[MAXPATHLEN], src[MAXPATHLEN];
	int rc;

	helper_path(tc, FOREIGN_HELPER, src, sizeof(src));
	ATF_REQUIRE(snprintf(path, sizeof(path), "%s", FOREIGN_HELPER) <
	    (int)sizeof(path));
	copy_file(src, path, 0755);
	set_interp(path, BRAND_INTERP "/");
	ATF_CHECK_EQ_MSG(ECAPMODE,
	    (rc = exec_from_capmode(path, FOREIGN_HELPER, true)),
	    "brand-prefix interpreter from capability mode: %d", rc);
}

ATF_TC_WITH_CLEANUP(knob_disabled);
ATF_TC_HEAD(knob_disabled, tc)
{
	atf_tc_set_md_var(tc, "descr", "With the sysctl off, even the brand's "
	    "own interpreter is refused from capability mode");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(knob_disabled, tc)
{
	char path[MAXPATHLEN];
	int rc;

	if (!knob_enabled())
		atf_tc_skip("%s is already disabled", CAPMODE_INTERP_SYSCTL);
	helper_path(tc, HELPER, path, sizeof(path));
	set_knob(false);
	ATF_CHECK_EQ_MSG(ECAPMODE, (rc = exec_from_capmode(path, HELPER, true)),
	    "brand interpreter with the knob off: %d", rc);
	set_knob(true);
	ATF_CHECK_EQ_MSG(0, (rc = exec_from_capmode(path, HELPER, true)),
	    "brand interpreter with the knob back on: %d", rc);
}
ATF_TC_CLEANUP(knob_disabled, tc)
{
	bool val;

	val = true;
	(void)sysctlbyname(CAPMODE_INTERP_SYSCTL, NULL, NULL, &val,
	    sizeof(val));
}

ATF_TC_WITH_CLEANUP(static_unaffected);
ATF_TC_HEAD(static_unaffected, tc)
{
	atf_tc_set_md_var(tc, "descr", "A static image has no interpreter "
	    "and execs from capability mode regardless of the knob");
}
ATF_TC_CLEANUP(static_unaffected, tc)
{
	bool val;

	val = true;
	(void)sysctlbyname(CAPMODE_INTERP_SYSCTL, NULL, NULL, &val,
	    sizeof(val));
}
ATF_TC_BODY(static_unaffected, tc)
{
	char path[MAXPATHLEN];
	int rc;

	helper_path(tc, STATIC_HELPER, path, sizeof(path));
	ATF_CHECK_EQ_MSG(0, (rc = exec_from_capmode(path, STATIC_HELPER, true)),
	    "static helper: %d", rc);
	if (geteuid() != 0)
		return;
	set_knob(false);
	ATF_CHECK_EQ_MSG(0, (rc = exec_from_capmode(path, STATIC_HELPER, true)),
	    "static helper with the knob off: %d", rc);
	set_knob(true);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, brand_interp_capmode);
	ATF_TP_ADD_TC(tp, foreign_interp_capmode);
	ATF_TP_ADD_TC(tp, missing_interp_capmode);
	ATF_TP_ADD_TC(tp, brand_prefix_capmode);
	ATF_TP_ADD_TC(tp, knob_disabled);
	ATF_TP_ADD_TC(tp, static_unaffected);
	return (atf_no_error());
}
