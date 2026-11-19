/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * Exec guard pins (BX-0, capability-broker-rules.md 8.1): how exec
 * behaves today, with no exec guard, so the guard slices can show which
 * answers they change and that every other one stays.  Each case names
 * its row (P1-P16) and the slice at which it is meant to flip, or
 * "never".  Unattached means the image runs without PROC_NO_NEW_PRIVS,
 * which a dq ATTACH sets.
 *
 * Covered elsewhere: the DQ_IOC_ATTACH child rule (a child that exec'd
 * is EBUSY: dq_attach_test:attach_refusals, failed_exec_still_attachable)
 * and DQ_ATTACH_F_NODIRS (dq_cwd_test).  Not pinned here: P8 and P13 need
 * fixtures the guard slices bring (dq_interp_stub, a grantbylabel exec
 * transition); P15's refusal cannot be reached on amd64, where every ELF
 * brand has BI_CAN_EXEC_DYN.  An exec held inside its commit (P_INEXEC,
 * execve_block_wait) is pinned in dq_exec_test:exec_held_at_interp, which
 * can hold one: a served tree's controller withholds the ELF
 * interpreter's answer.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/elf.h>
#include <sys/inotify.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <grp.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <libutil.h>
#include <signal.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dqt.h"

extern char **environ;

#define	HELPER		"dq_execpin_helper"
#define	PIN_USER	1001

/* What one exec did: its errno (0: the image ran), status and output. */
struct pin_run {
	int	exec_errno;
	int	status;
	char	out[256];
};

typedef void (*pin_pre_fn)(void *arg);

/* The image pin_image opened, for an exec with no path. */
static int pin_fd = -1;

/*
 * Fork; in the child run pre (if any), then execve path (execvp when
 * usepath; fexecve of pin_fd when path is NULL).  The child's stdout is
 * captured; a failed exec reports its errno over a close-on-exec pipe,
 * which stays empty when the image ran.
 */
static void
pin_exec(const char *path, char *const argv[], bool usepath, pin_pre_fn pre,
    void *arg, struct pin_run *r)
{
	int out[2], err[2], e;
	ssize_t n;
	pid_t pid;

	memset(r, 0, sizeof(*r));
	ATF_REQUIRE_EQ(0, pipe(out));
	ATF_REQUIRE_EQ(0, pipe2(err, O_CLOEXEC));
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)close(out[0]);
		(void)close(err[0]);
		if (dup2(out[1], STDOUT_FILENO) == -1)
			_exit(125);
		if (pre != NULL)
			pre(arg);
		if (path == NULL)
			fexecve(pin_fd, argv, environ);
		else if (usepath)
			execvp(path, argv);
		else
			execve(path, argv, environ);
		e = errno;
		(void)write(err[1], &e, sizeof(e));
		_exit(126);
	}
	(void)close(out[1]);
	(void)close(err[1]);
	n = read(err[0], &r->exec_errno, sizeof(r->exec_errno));
	ATF_REQUIRE(n == 0 || n == sizeof(r->exec_errno));
	(void)close(err[0]);
	(void)dqt_read_full(out[0], r->out, sizeof(r->out) - 1);
	(void)close(out[0]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &r->status, 0));
}

/* The image ran, exited 0 and printed line. */
static void
pin_check_ran(const struct pin_run *r, const char *line)
{
	char buf[32];

	ATF_REQUIRE_MSG(r->exec_errno == 0, "exec: %s",
	    strerror(r->exec_errno));
	ATF_CHECK_MSG(WIFEXITED(r->status) && WEXITSTATUS(r->status) == 0,
	    "status: %s", dqt_status_str(r->status, buf, sizeof(buf)));
	ATF_CHECK_MSG(strstr(r->out, line) != NULL, "output \"%s\", not "
	    "\"%s\"", r->out, line);
}

/*
 * The ELF image at path: its header and program headers, read into ph
 * (at most nph).  Returns the number of program headers.
 */
static int
pin_elf(const char *path, Elf_Ehdr *eh, Elf_Phdr *ph, int nph, int *fdp)
{
	int fd;

	fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", path, strerror(errno));
	ATF_REQUIRE_EQ((ssize_t)sizeof(*eh), pread(fd, eh, sizeof(*eh), 0));
	ATF_REQUIRE(memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0);
	ATF_REQUIRE_EQ(sizeof(*ph), eh->e_phentsize);
	ATF_REQUIRE(eh->e_phnum <= nph);
	ATF_REQUIRE_EQ((ssize_t)(eh->e_phnum * sizeof(*ph)),
	    pread(fd, ph, eh->e_phnum * sizeof(*ph), (off_t)eh->e_phoff));
	*fdp = fd;
	return (eh->e_phnum);
}

/* The PT_INTERP of the image at path, into buf, and its file offset. */
static off_t
pin_interp(const char *path, char *buf, size_t len)
{
	Elf_Ehdr eh;
	Elf_Phdr ph[64];
	int fd, i, n;

	n = pin_elf(path, &eh, ph, (int)nitems(ph), &fd);
	for (i = 0; i < n; i++) {
		if (ph[i].p_type != PT_INTERP)
			continue;
		ATF_REQUIRE(ph[i].p_filesz > 1 && ph[i].p_filesz <= len);
		ATF_REQUIRE_EQ((ssize_t)ph[i].p_filesz, pread(fd, buf,
		    ph[i].p_filesz, (off_t)ph[i].p_offset));
		ATF_REQUIRE(buf[ph[i].p_filesz - 1] == '\0');
		(void)close(fd);
		return ((off_t)ph[i].p_offset);
	}
	ATF_REQUIRE_MSG(false, "%s has no PT_INTERP", path);
	return (-1);
}

/*
 * The helper copied into the work directory as "image" with mode, and
 * opened O_EXEC as pin_fd: a child that changed its credential or prison
 * execs it by path from the work directory, and again with fexecve(2).
 * A set-uid pin needs a file system that honours set-uid: the work
 * directory's must, or the pin fails rather than look elsewhere.
 */
static void
pin_image(const atf_tc_t *tc, mode_t mode)
{
	struct statfs sf;

	if ((mode & S_ISUID) != 0) {
		ATF_REQUIRE_EQ(0, statfs(".", &sf));
		ATF_REQUIRE_MSG((sf.f_flags & MNT_NOSUID) == 0,
		    "the work directory's file system (%s) is mounted nosuid",
		    sf.f_mntonname);
	}
	dqt_copy_helper(tc, HELPER, "image");
	ATF_REQUIRE_EQ(0, chown("image", 0, 0));
	ATF_REQUIRE_EQ(0, chmod("image", mode));
	pin_fd = open("image", O_EXEC | O_CLOEXEC);
	ATF_REQUIRE_MSG(pin_fd != -1, "open image: %s", strerror(errno));
	/*
	 * The path variants run "./image" from the inherited cwd: only the
	 * work directory itself needs to be searchable, not its parents.
	 */
	ATF_REQUIRE_EQ(0, chmod(".", 0711));
}

/* What uid 1001 with gid 1001 and no other group prints (P2). */
#define	PIN_USER_CRED	"res=1001,1001,1001 gres=1001,1001,1001 groups=1001"

static void
pre_user(void *arg __unused)
{
	gid_t g = PIN_USER;

	if (setgroups(1, &g) != 0 || setgid(PIN_USER) != 0 ||
	    setuid(PIN_USER) != 0)
		_exit(124);
}

/* P1: an exec in a jail is not attached (flips at BX-4: a t1 scope). */
struct jail_arg {
	int	jid;
	int	dirfd;		/* the work directory, opened outside */
};

static void
pre_jail(void *arg)
{
	struct jail_arg *a = arg;

	/* jail_attach moves the cwd to the jail's root: come back. */
	if (jail_attach(a->jid) != 0 || fchdir(a->dirfd) != 0)
		_exit(124);
}

ATF_TC_WITH_CLEANUP(p1_jail_unattached);
ATF_TC_HEAD(p1_jail_unattached, tc)
{
	atf_tc_set_md_var(tc, "descr", "P1: an exec inside a jail runs "
	    "unattached, by path and by fexecve (flips at BX-4 with the "
	    "jail's scope and ATTACH)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p1_jail_unattached, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r, rf;
	struct jail_arg a;

	pin_image(tc, 0755);
	a.dirfd = open(".", O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(a.dirfd != -1);
	a.jid = jail_setv(JAIL_CREATE, "name", "dqpin_t1", "path", "/",
	    "persist", NULL, NULL);
	ATF_REQUIRE_MSG(a.jid > 0, "jail_setv: %s", jail_errmsg);
	pin_exec("./image", argv, false, pre_jail, &a, &r);
	pin_exec(NULL, argv, false, pre_jail, &a, &rf);
	(void)jail_remove(a.jid);
	pin_check_ran(&r, "uid=0 euid=0 nnp=0");
	pin_check_ran(&rf, "uid=0 euid=0 nnp=0");
}
ATF_TC_CLEANUP(p1_jail_unattached, tc)
{
	int jid;

	jid = jail_getid("dqpin_t1");
	if (jid > 0)
		(void)jail_remove(jid);
}

ATF_TC(p2_user_unattached);
ATF_TC_HEAD(p2_user_unattached, tc)
{
	atf_tc_set_md_var(tc, "descr", "P2: an exec by uid 1001 (gid and "
	    "groups 1001) runs unattached with that credential, by path and "
	    "by fexecve (flips at BX-4 with a scope whose Broker takes it)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p2_user_unattached, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r;

	pin_image(tc, 0755);
	pin_exec("./image", argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=1001 nnp=0");
	pin_check_ran(&r, PIN_USER_CRED);
	pin_exec(NULL, argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=1001 nnp=0");
	pin_check_ran(&r, PIN_USER_CRED);
}

/* Write a file of len bytes of b (or text when text != NULL), mode. */
static void
pin_file(const char *name, const char *text, int b, size_t len, mode_t mode)
{
	char buf[256];
	int fd;

	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, mode);
	ATF_REQUIRE_MSG(fd != -1, "%s: %s", name, strerror(errno));
	if (text != NULL) {
		ATF_REQUIRE_EQ((ssize_t)strlen(text),
		    write(fd, text, strlen(text)));
	} else {
		memset(buf, b, sizeof(buf));
		ATF_REQUIRE(len <= sizeof(buf));
		ATF_REQUIRE_EQ((ssize_t)len, write(fd, buf, len));
	}
	ATF_REQUIRE_EQ(0, fchmod(fd, mode));
	ATF_REQUIRE_EQ(0, close(fd));
}

static void
pre_write_open(void *arg)
{

	/* Kept open for writing across the exec attempt. */
	if (open((const char *)arg, O_WRONLY) == -1)
		_exit(124);
}

static void
pre_capmode(void *arg __unused)
{

	if (cap_enter() != 0)
		_exit(124);
}

static int
pin_errno(const char *path, char *const argv[], pin_pre_fn pre, void *arg)
{
	struct pin_run r;

	pin_exec(path, argv, false, pre, arg, &r);
	return (r.exec_errno);
}

/*
 * Two broken copies of the helper: "badphdr", whose header gives a wrong
 * program header size, and "badinterp", whose PT_INTERP names a file
 * that does not exist (the last character of the real one changed).
 */
static void
pin_badelf(const atf_tc_t *tc)
{
	Elf_Ehdr eh;
	char interp[PATH_MAX];
	off_t off;
	int fd;

	dqt_copy_helper(tc, HELPER, "badphdr");
	fd = open("badphdr", O_RDWR);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ((ssize_t)sizeof(eh), pread(fd, &eh, sizeof(eh), 0));
	eh.e_phentsize = 1;
	ATF_REQUIRE_EQ((ssize_t)sizeof(eh), pwrite(fd, &eh, sizeof(eh), 0));
	ATF_REQUIRE_EQ(0, close(fd));

	dqt_copy_helper(tc, HELPER, "badinterp");
	off = pin_interp("badinterp", interp, sizeof(interp));
	interp[strlen(interp) - 1] ^= 0x20;
	ATF_REQUIRE_MSG(access(interp, F_OK) == -1 && errno == ENOENT,
	    "%s exists", interp);
	fd = open("badinterp", O_WRONLY);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ((ssize_t)strlen(interp), pwrite(fd, interp,
	    strlen(interp), off));
	ATF_REQUIRE_EQ(0, close(fd));
}

ATF_TC(p3_exec_errnos);
ATF_TC_HEAD(p3_exec_errnos, tc)
{
	atf_tc_set_md_var(tc, "descr", "P3: execve's refusals and their "
	    "order: missing file ENOENT, mode 0644 EACCES (before the magic), "
	    "bad magic ENOEXEC, an ELF header with a bad program header size "
	    "ENOEXEC, open for writing ETXTBSY (before the magic), arguments "
	    "past ARG_MAX E2BIG (before the lookup, the image and capability "
	    "mode), a missing #! interpreter ENOENT, capability mode ECAPMODE; "
	    "a missing ELF interpreter is found only after the old image is "
	    "gone: SIGABRT (never flips)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p3_exec_errnos, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	char *big[3], buf[32];
	struct pin_run r;
	long argmax;

	dqt_copy_helper(tc, HELPER, "helper");
	pin_file("noexec", NULL, 0x5a, 64, 0644);
	pin_file("badmagic", NULL, 0x5a, 64, 0755);
	pin_file("busy-bad", NULL, 0x5a, 64, 0755);
	dqt_copy_helper(tc, HELPER, "busy");
	pin_file("nointerp", "#!/nonexistent/dqpin-interp\n", 0, 0, 0755);
	pin_badelf(tc);

	ATF_CHECK_EQ(ENOENT, pin_errno("./missing", argv, NULL, NULL));
	ATF_CHECK_EQ(EACCES, pin_errno("./noexec", argv, NULL, NULL));
	ATF_CHECK_EQ(ENOEXEC, pin_errno("./badmagic", argv, NULL, NULL));
	ATF_CHECK_EQ(ETXTBSY, pin_errno("./busy", argv, pre_write_open,
	    __DECONST(char *, "busy")));
	ATF_CHECK_EQ(ETXTBSY, pin_errno("./busy-bad", argv, pre_write_open,
	    __DECONST(char *, "busy-bad")));
	ATF_CHECK_EQ(ENOENT, pin_errno("./nointerp", argv, NULL, NULL));
	ATF_CHECK_EQ(ECAPMODE, pin_errno("./helper", argv, pre_capmode,
	    NULL));
	ATF_CHECK_EQ(ENOEXEC, pin_errno("./badphdr", argv, NULL, NULL));
	pin_exec("./badinterp", argv, false, NULL, NULL, &r);
	ATF_CHECK_EQ(0, r.exec_errno);
	ATF_CHECK_MSG(WIFSIGNALED(r.status) && WTERMSIG(r.status) == SIGABRT,
	    "missing PT_INTERP: %s", dqt_status_str(r.status, buf,
	    sizeof(buf)));

	argmax = sysconf(_SC_ARG_MAX);
	ATF_REQUIRE(argmax > 0);
	big[0] = __DECONST(char *, "x");
	big[1] = malloc((size_t)argmax + 1);
	ATF_REQUIRE(big[1] != NULL);
	memset(big[1], 'a', (size_t)argmax);
	big[1][argmax] = '\0';
	big[2] = NULL;
	ATF_CHECK_EQ(E2BIG, pin_errno("./helper", big, NULL, NULL));
	/*
	 * The arguments are copied in before the name is looked up, the image
	 * is read and capability mode is checked (sys_execve).
	 */
	ATF_CHECK_EQ(E2BIG, pin_errno("./badmagic", big, NULL, NULL));
	ATF_CHECK_EQ(E2BIG, pin_errno("./missing", big, NULL, NULL));
	ATF_CHECK_EQ(E2BIG, pin_errno("./helper", big, pre_capmode, NULL));
	free(big[1]);
}

/* P4: an attached process's exec stays attached (never flips). */
struct p4_res {
	struct pin_run	 run;
};

static void
p4_child(void *arg, void *result)
{
	struct p4_res *res = result;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "dqpin-probe-p4"), NULL };

	pin_exec((const char *)arg, argv, false, NULL, NULL, &res->run);
}

ATF_TC(p4_attached_exec);
ATF_TC_HEAD(p4_attached_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "P4: an attached process's child "
	    "execs and stays attached: PROC_NO_NEW_PRIVS set, its lookup "
	    "posted as RESOLVE (never flips)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p4_attached_exec, tc)
{
	char path[PATH_MAX];
	struct dqt_ctl c;
	struct dqt_achild ch;
	struct p4_res r;

	dqt_copy_helper(tc, HELPER, "helper");
	ATF_REQUIRE(realpath("helper", path) != NULL);
	dqt_init(&c);
	dqt_attach_spawn(&c, &ch, p4_child, path);
	memset(&r, 0, sizeof(r));
	dqt_attach_collect(&ch, &r, sizeof(r));
	pin_check_ran(&r.run, "uid=0 euid=0 nnp=1");
	ATF_CHECK_EQ(1, dqt_count_resolve(&c, "dqpin-probe-p4", 0));
	dqt_fini(&c);
}

ATF_TC(p5_setuid_root);
ATF_TC_HEAD(p5_setuid_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "P5: a set-uid-root image run by uid "
	    "1001 has euid and saved uid 0, its gids and groups unchanged, by "
	    "path and by fexecve (flips at BX-4 when attached: euid "
	    "unchanged)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p5_setuid_root, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r;

	pin_image(tc, 04755);
	pin_exec("./image", argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=0 nnp=0");
	pin_check_ran(&r, "res=1001,0,0 gres=1001,1001,1001 groups=1001");
	pin_exec(NULL, argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=0 nnp=0");
	pin_check_ran(&r, "res=1001,0,0 gres=1001,1001,1001 groups=1001");
}

ATF_TC(p6_execvp_text);
ATF_TC_HEAD(p6_execvp_text, tc)
{
	atf_tc_set_md_var(tc, "descr", "P6: execvp of a 0755 text file "
	    "without #! runs it with /bin/sh (never flips)");
}
ATF_TC_BODY(p6_execvp_text, tc)
{
	char *argv[] = { __DECONST(char *, "plain"), NULL };
	struct pin_run r;
	char buf[32];

	pin_file("plain", "echo dqpin-sh; exit 7\n", 0, 0, 0755);
	pin_exec("./plain", argv, true, NULL, NULL, &r);
	ATF_REQUIRE_MSG(r.exec_errno == 0, "execvp: %s",
	    strerror(r.exec_errno));
	ATF_CHECK_MSG(WIFEXITED(r.status) && WEXITSTATUS(r.status) == 7,
	    "status: %s", dqt_status_str(r.status, buf, sizeof(buf)));
	ATF_CHECK(strstr(r.out, "dqpin-sh") != NULL);
}

ATF_TC(p7_rtld_direct);
ATF_TC_HEAD(p7_rtld_direct, tc)
{
	atf_tc_set_md_var(tc, "descr", "P7: the run-time linker (the "
	    "helper's PT_INTERP) run directly loads and runs a program (flips "
	    "at BX-6: MAPS and DENY)");
}
ATF_TC_BODY(p7_rtld_direct, tc)
{
	char *argv[] = { __DECONST(char *, "ld-elf.so.1"),
	    __DECONST(char *, "./helper"), NULL };
	char rtld[PATH_MAX];
	struct pin_run r;

	dqt_copy_helper(tc, HELPER, "helper");
	(void)pin_interp("helper", rtld, sizeof(rtld));
	pin_exec(rtld, argv, false, NULL, NULL, &r);
	pin_check_ran(&r, "nnp=0");
}

/* P9: the image is a memfd copy, named to ld-elf.so.1 by -f. */
static void
pre_memfd(void *arg)
{
	char **argv = arg, buf[8192];
	ssize_t n;
	int fd, in;

	in = open("helper", O_RDONLY);
	fd = memfd_create("dqpin", 0);
	/* rtld -f refuses an image without an execute bit. */
	if (in == -1 || fd == -1 || fchmod(fd, 0755) != 0)
		_exit(124);
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(fd, buf, (size_t)n) != n)
			_exit(124);
	(void)close(in);
	(void)snprintf(argv[2], 16, "%d", fd);
}

ATF_TC(p9_memfd_rtld);
ATF_TC_HEAD(p9_memfd_rtld, tc)
{
	atf_tc_set_md_var(tc, "descr", "P9: ld-elf.so.1 -f runs a program "
	    "from a memfd copy (flips at BX-6: shm DENY)");
}
ATF_TC_BODY(p9_memfd_rtld, tc)
{
	char fdarg[16], rtld[PATH_MAX];
	char *argv[] = { __DECONST(char *, "ld-elf.so.1"),
	    __DECONST(char *, "-f"), fdarg, __DECONST(char *, "helper"),
	    NULL };
	struct pin_run r;

	dqt_copy_helper(tc, HELPER, "helper");
	(void)pin_interp("helper", rtld, sizeof(rtld));
	fdarg[0] = '\0';
	pin_exec(rtld, argv, false, pre_memfd, argv, &r);
	pin_check_ran(&r, "nnp=0");
}

/* P10: fexecve(2) of a pty slave, revoked when arg is non-NULL. */
static void
pre_revoked_pty(void *arg)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	const char *name;
	int m, s;

	m = posix_openpt(O_RDWR | O_NOCTTY);
	if (m == -1 || grantpt(m) != 0 || unlockpt(m) != 0)
		_exit(124);
	name = ptsname(m);
	if (name == NULL)
		_exit(124);
	s = open(name, O_RDWR | O_NOCTTY);
	if (s == -1 || (arg != NULL && revoke(name) != 0))
		_exit(124);
	(void)fexecve(s, argv, environ);
	_exit(100 + errno);	/* the errno, as the exit status */
}

ATF_TC(p10_fexecve_revoked_pty);
ATF_TC_HEAD(p10_fexecve_revoked_pty, tc)
{
	atf_tc_set_md_var(tc, "descr", "P10: fexecve(2) of a revoked pty "
	    "slave is EBADF, no panic; of a live one EACCES, a device is not "
	    "a regular file (never flips)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p10_fexecve_revoked_pty, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	struct pin_run r;
	char buf[32];
	int revoked = 1;

	/* pre_revoked_pty exits with 100 + fexecve's errno. */
	pin_exec("./never-reached", argv, false, pre_revoked_pty, NULL, &r);
	ATF_CHECK_MSG(WIFEXITED(r.status) &&
	    WEXITSTATUS(r.status) == 100 + EACCES, "live: %s",
	    dqt_status_str(r.status, buf, sizeof(buf)));
	pin_exec("./never-reached", argv, false, pre_revoked_pty, &revoked,
	    &r);
	ATF_CHECK_MSG(WIFEXITED(r.status) &&
	    WEXITSTATUS(r.status) == 100 + EBADF, "revoked: %s",
	    dqt_status_str(r.status, buf, sizeof(buf)));
}

ATF_TC(p11_mmap_read);
ATF_TC_HEAD(p11_mmap_read, tc)
{
	atf_tc_set_md_var(tc, "descr", "P11: mmap(PROT_READ) of an "
	    "executable and of a data file succeeds (never flips)");
}
ATF_TC_BODY(p11_mmap_read, tc)
{
	const char *names[] = { "helper", "data" };
	struct stat sb;
	void *p;
	u_int i;
	int fd;

	dqt_copy_helper(tc, HELPER, "helper");
	pin_file("data", "dqpin data\n", 0, 0, 0644);
	for (i = 0; i < nitems(names); i++) {
		fd = open(names[i], O_RDONLY);
		ATF_REQUIRE(fd != -1);
		ATF_REQUIRE_EQ(0, fstat(fd, &sb));
		p = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd,
		    0);
		ATF_CHECK_MSG(p != MAP_FAILED, "%s: %s", names[i],
		    strerror(errno));
		if (p != MAP_FAILED)
			ATF_CHECK_EQ(0, munmap(p, (size_t)sb.st_size));
		p = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd,
		    0);
		ATF_CHECK(p != MAP_FAILED);
		if (p != MAP_FAILED)
			ATF_CHECK_EQ(0, munmap(p, (size_t)sb.st_size));
		ATF_CHECK_EQ(0, close(fd));
	}
}

/*
 * P12's stall capture, for diagnosis only: with the configuration
 * variable dq_p12_stall_ms set, a watchdog thread waits for each spawn to
 * complete, and when one has not completed within that many milliseconds
 * it writes every thread's state (ps) and kernel stack (procstat -kk
 * -a, in the background: it waits out an exec held in its commit) to
 * standard error, which kyua keeps with the result, once per stalled
 * spawn.  Unset, there is no watchdog.
 */
struct p12_watch {
	pthread_mutex_t	 mtx;
	pthread_cond_t	 cv;
	long		 done;		/* spawns completed */
	bool		 stop;
	long		 stall_ms;
	int		 captures;
};

static void *
p12_watchdog(void *arg)
{
	struct p12_watch *w = arg;
	struct timespec dl;
	char cmd[512];
	long seen, captured;
	int rc;

	captured = -1;
	pthread_mutex_lock(&w->mtx);
	while (!w->stop) {
		seen = w->done;
		(void)clock_gettime(CLOCK_MONOTONIC, &dl);
		dl.tv_sec += w->stall_ms / 1000;
		dl.tv_nsec += (w->stall_ms % 1000) * 1000000;
		if (dl.tv_nsec >= 1000000000) {
			dl.tv_sec++;
			dl.tv_nsec -= 1000000000;
		}
		rc = 0;
		while (!w->stop && w->done == seen && rc != ETIMEDOUT)
			rc = pthread_cond_timedwait(&w->cv, &w->mtx, &dl);
		if (w->stop || w->done != seen || captured == seen)
			continue;
		captured = seen;
		w->captures++;
		pthread_mutex_unlock(&w->mtx);
		fprintf(stderr, "p12: spawn %ld stalled %ld ms\n", seen,
		    w->stall_ms);
		snprintf(cmd, sizeof(cmd), "{ date -u; sysctl vm.loadavg "
		    "kern.cp_times; ps -axHwwo pid,ppid,lwp,state,wchan,"
		    "mwchan,time,command; } 1>&2; (procstat -kk -a 1>&2 &)");
		(void)system(cmd);
		pthread_mutex_lock(&w->mtx);
	}
	pthread_mutex_unlock(&w->mtx);
	return (NULL);
}

ATF_TC(p12_thousand_true);
ATF_TC_HEAD(p12_thousand_true, tc)
{
	atf_tc_set_md_var(tc, "descr", "P12: 1000 posix_spawn(2)s of "
	    "/usr/bin/true complete; the time is information (flips at BX-1: "
	    "the hold's fast path fires 1000 times).  dq_p12_rounds repeats "
	    "the 1000; dq_p12_stall_ms arms the stall capture");
}
ATF_TC_BODY(p12_thousand_true, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	struct timespec t0, t1, ts, te;
	struct p12_watch w;
	pthread_condattr_t ca;
	pthread_t wt;
	long ms, worst, rounds, i, n;
	pid_t pid;
	int failed, status;
	long worst_i;

	rounds = atf_tc_has_config_var(tc, "dq_p12_rounds") ?
	    strtol(atf_tc_get_config_var(tc, "dq_p12_rounds"), NULL, 10) : 1;
	ATF_REQUIRE(rounds >= 1);
	n = rounds * 1000;
	memset(&w, 0, sizeof(w));
	if (atf_tc_has_config_var(tc, "dq_p12_stall_ms")) {
		w.stall_ms = strtol(atf_tc_get_config_var(tc,
		    "dq_p12_stall_ms"), NULL, 10);
		ATF_REQUIRE(w.stall_ms > 0);
		ATF_REQUIRE_EQ(0, pthread_mutex_init(&w.mtx, NULL));
		ATF_REQUIRE_EQ(0, pthread_condattr_init(&ca));
		ATF_REQUIRE_EQ(0, pthread_condattr_setclock(&ca,
		    CLOCK_MONOTONIC));
		ATF_REQUIRE_EQ(0, pthread_cond_init(&w.cv, &ca));
		(void)pthread_condattr_destroy(&ca);
		ATF_REQUIRE_EQ(0, pthread_create(&wt, NULL, p12_watchdog, &w));
	}
	failed = 0;
	worst = 0;
	worst_i = -1;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t0));
	for (i = 0; i < n; i++) {
		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
		ATF_REQUIRE_EQ(0, posix_spawn(&pid, "/usr/bin/true", NULL,
		    NULL, argv, environ));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &te));
		if (w.stall_ms != 0) {
			pthread_mutex_lock(&w.mtx);
			w.done++;
			pthread_cond_signal(&w.cv);
			pthread_mutex_unlock(&w.mtx);
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			failed++;
		ms = (long)((te.tv_sec - ts.tv_sec) * 1000 +
		    (te.tv_nsec - ts.tv_nsec) / 1000000);
		if (ms > worst) {
			worst = ms;
			worst_i = i;
		}
		/* Progress, so a timed-out run shows where it stalled. */
		if ((i + 1) % 100 == 0)
			fprintf(stderr, "p12: %ld execs, %ld ms\n", i + 1,
			    (long)((te.tv_sec - t0.tv_sec) * 1000 +
			    (te.tv_nsec - t0.tv_nsec) / 1000000));
	}
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t1));
	if (w.stall_ms != 0) {
		pthread_mutex_lock(&w.mtx);
		w.stop = true;
		pthread_cond_signal(&w.cv);
		pthread_mutex_unlock(&w.mtx);
		ATF_REQUIRE_EQ(0, pthread_join(wt, NULL));
		printf("p12: %d stall captures\n", w.captures);
	}
	ATF_CHECK_EQ(0, failed);
	printf("p12: %ld execs in %ld ms, slowest %ld ms (#%ld)\n", n,
	    (long)((t1.tv_sec - t0.tv_sec) * 1000 +
	    (t1.tv_nsec - t0.tv_nsec) / 1000000), worst, worst_i);
}

ATF_TC(p14_posix_spawn);
ATF_TC_HEAD(p14_posix_spawn, tc)
{
	atf_tc_set_md_var(tc, "descr", "P14: posix_spawn(2) by root runs "
	    "the image unattached (never flips outside routed scopes)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p14_posix_spawn, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	posix_spawn_file_actions_t fa;
	char out[256];
	pid_t pid;
	int p[2], status;

	dqt_copy_helper(tc, HELPER, "helper");
	ATF_REQUIRE_EQ(0, pipe(p));
	ATF_REQUIRE_EQ(0, posix_spawn_file_actions_init(&fa));
	ATF_REQUIRE_EQ(0, posix_spawn_file_actions_adddup2(&fa, p[1],
	    STDOUT_FILENO));
	ATF_REQUIRE_EQ(0, posix_spawn(&pid, "./helper", &fa, NULL, argv,
	    environ));
	(void)close(p[1]);
	memset(out, 0, sizeof(out));
	(void)dqt_read_full(p[0], out, sizeof(out) - 1);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_MSG(strstr(out, "uid=0 euid=0 nnp=0") != NULL, "%s", out);
	(void)posix_spawn_file_actions_destroy(&fa);
	(void)close(p[0]);
}

/* P16: the inotify events of the changes the exec cache will note. */
static int
pin_inotify_count(int ifd, uint32_t mask)
{
	char buf[4096];
	struct inotify_event *ev;
	ssize_t n;
	size_t off;
	int count;

	count = 0;
	for (;;) {
		n = read(ifd, buf, sizeof(buf));
		if (n <= 0)
			break;
		for (off = 0; off < (size_t)n;
		    off += sizeof(*ev) + ev->len) {
			ev = (struct inotify_event *)(void *)(buf + off);
			if ((ev->mask & mask) != 0)
				count++;
		}
	}
	return (count);
}

/*
 * inotify queues an event in the changing call itself, so each count is
 * read right after its call returns: nothing to wait for.  The file is
 * dir/changed.
 */
static void
p16_changes(const char *dir, int ifd, int counts[3])
{
	char path[PATH_MAX], *p;
	int fd;

	snprintf(path, sizeof(path), "%s/changed", dir);
	fd = open(path, O_RDWR | O_APPEND);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(4, write(fd, "more", 4));
	counts[0] = ifd == -1 ? 0 : pin_inotify_count(ifd, IN_MODIFY);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 2));
	counts[1] = ifd == -1 ? 0 : pin_inotify_count(ifd, IN_MODIFY);
	ATF_REQUIRE_EQ(0, ftruncate(fd, getpagesize()));
	if (ifd != -1)
		(void)pin_inotify_count(ifd, IN_ALL_EVENTS);
	p = mmap(NULL, (size_t)getpagesize(), PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	p[0] = 'X';
	ATF_REQUIRE_EQ(0, msync(p, (size_t)getpagesize(), MS_SYNC));
	ATF_REQUIRE_EQ(0, munmap(p, (size_t)getpagesize()));
	counts[2] = ifd == -1 ? 0 : pin_inotify_count(ifd, IN_MODIFY);
	ATF_REQUIRE_EQ(0, close(fd));
}

/*
 * The IN_MODIFY of an msync'ed store through a shared mapping depends on
 * the file system; the rows are what the plane-on guest measured.  A
 * file system with no row fails, so a new one gets a measured row.
 */
static const struct {
	const char	*fstype;
	int		 mapped;
} p16_mapped[] = {
	{ "ufs",	1 },
	{ "tmpfs",	0 },
};

static void
p16_on(const char *dir)
{
	char path[PATH_MAX];
	struct statfs sf;
	int counts[3], ifd, wd;
	u_int i;

	ATF_REQUIRE_EQ(0, statfs(dir, &sf));
	for (i = 0; i < nitems(p16_mapped); i++)
		if (strcmp(p16_mapped[i].fstype, sf.f_fstypename) == 0)
			break;
	ATF_REQUIRE_MSG(i < nitems(p16_mapped), "no P16 row for %s (%s)",
	    sf.f_fstypename, sf.f_mntonname);
	snprintf(path, sizeof(path), "%s/changed", dir);
	pin_file(path, "abcdefgh", 0, 0, 0644);
	p16_changes(dir, -1, counts);

	ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	ATF_REQUIRE_MSG(ifd != -1, "inotify_init1: %s", strerror(errno));
	wd = inotify_add_watch(ifd, path, IN_ALL_EVENTS);
	ATF_REQUIRE_MSG(wd != -1, "inotify_add_watch: %s", strerror(errno));
	p16_changes(dir, ifd, counts);
	ATF_CHECK_EQ_MSG(1, counts[0], "%s: append: %d IN_MODIFY",
	    sf.f_fstypename, counts[0]);
	ATF_CHECK_EQ_MSG(1, counts[1], "%s: ftruncate: %d IN_MODIFY",
	    sf.f_fstypename, counts[1]);
	ATF_CHECK_EQ_MSG(p16_mapped[i].mapped, counts[2],
	    "%s: mapped store: %d IN_MODIFY", sf.f_fstypename, counts[2]);
	ATF_CHECK_EQ(0, close(ifd));
}

#define	P16_TMPFS	"tmpfs"

ATF_TC_WITH_CLEANUP(p16_changes_inotify);
ATF_TC_HEAD(p16_changes_inotify, tc)
{
	atf_tc_set_md_var(tc, "descr", "P16: append, ftruncate and a write "
	    "through a shared mapping succeed with and without an inotify "
	    "watch, on the work directory's file system and on tmpfs; a "
	    "watch sees one IN_MODIFY each for the append and the truncate, "
	    "and for the msync'ed store what the file system raises (never "
	    "flips; BX-1 adds the change-note sites)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p16_changes_inotify, tc)
{
	struct iovec iov[4];

	p16_on(".");
	ATF_REQUIRE_EQ(0, mkdir(P16_TMPFS, 0755));
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "tmpfs");
	iov[1].iov_len = sizeof("tmpfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, P16_TMPFS);
	iov[3].iov_len = sizeof(P16_TMPFS);
	ATF_REQUIRE_MSG(nmount(iov, nitems(iov), 0) == 0, "mount tmpfs: %s",
	    strerror(errno));
	p16_on(P16_TMPFS);
	ATF_REQUIRE_EQ(0, unmount(P16_TMPFS, 0));
}
ATF_TC_CLEANUP(p16_changes_inotify, tc)
{

	(void)unmount(P16_TMPFS, MNT_FORCE);
}

ATF_TC(vfork_waits_for_exec);
ATF_TC_HEAD(vfork_waits_for_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "vfork(2)'s parent resumes after "
	    "the child's exec: the child already has the image's name.  That "
	    "the parent waits through an exec held inside its commit is "
	    "pinned in dq_exec_test:exec_held_at_interp");
}
ATF_TC_BODY(vfork_waits_for_exec, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct kinfo_proc *kp;
	int devnull, status;
	pid_t pid;

	dqt_copy_helper(tc, HELPER, "helper");
	devnull = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(devnull != -1);
	pid = vfork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)dup2(devnull, STDOUT_FILENO);
		execve("./helper", argv, environ);
		_exit(126);
	}
	kp = kinfo_getproc(pid);
	ATF_REQUIRE(kp != NULL);
	ATF_CHECK_STREQ("helper", kp->ki_comm);
	free(kp);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	(void)close(devnull);
}

ATF_TC(ptrace_exec_stop_io);
ATF_TC_HEAD(ptrace_exec_stop_io, tc)
{
	atf_tc_set_md_var(tc, "descr", "a traced child's exec stops with "
	    "PL_FLAG_EXEC after the exec completed, and the debugger's PT_IO "
	    "reads the new image's ELF header there.  It does not reach "
	    "execve_block: the target is stopped, not in exec (see "
	    "dq_exec_test:exec_held_at_interp)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ptrace_exec_stop_io, tc)
{
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct ptrace_lwpinfo pl;
	struct ptrace_io_desc io;
	struct kinfo_vmentry *vm;
	char magic[4];
	int status, n, i, devnull;
	uintptr_t base;
	pid_t pid;

	dqt_copy_helper(tc, HELPER, "helper");
	devnull = open("/dev/null", O_WRONLY);
	ATF_REQUIRE(devnull != -1);
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		(void)dup2(devnull, STDOUT_FILENO);
		if (ptrace(PT_TRACE_ME, 0, NULL, 0) != 0)
			_exit(124);
		(void)raise(SIGSTOP);
		execve("./helper", argv, environ);
		_exit(126);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	ATF_REQUIRE_EQ(0, ptrace(PT_CONTINUE, pid, (caddr_t)1, 0));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
	ATF_REQUIRE_EQ(0, ptrace(PT_LWPINFO, pid, (caddr_t)&pl, sizeof(pl)));
	ATF_CHECK((pl.pl_flags & PL_FLAG_EXEC) != 0);

	/* The image's first mapping starts with its ELF header. */
	vm = kinfo_getvmmap(pid, &n);
	ATF_REQUIRE(vm != NULL && n > 0);
	base = 0;
	for (i = 0; i < n; i++) {
		if (vm[i].kve_type == KVME_TYPE_VNODE &&
		    strstr(vm[i].kve_path, "helper") != NULL) {
			base = (uintptr_t)vm[i].kve_start;
			break;
		}
	}
	free(vm);
	ATF_REQUIRE_MSG(base != 0, "no mapping of the image");
	io.piod_op = PIOD_READ_D;
	io.piod_offs = (void *)base;
	io.piod_addr = magic;
	io.piod_len = sizeof(magic);
	ATF_REQUIRE_EQ(0, ptrace(PT_IO, pid, (caddr_t)&io, 0));
	ATF_CHECK_EQ(sizeof(magic), io.piod_len);
	ATF_CHECK(memcmp(magic, "\177ELF", 4) == 0);
	ATF_REQUIRE_EQ(0, ptrace(PT_DETACH, pid, (caddr_t)1, 0));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	(void)close(devnull);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, p1_jail_unattached);
	ATF_TP_ADD_TC(tp, p2_user_unattached);
	ATF_TP_ADD_TC(tp, p3_exec_errnos);
	ATF_TP_ADD_TC(tp, p4_attached_exec);
	ATF_TP_ADD_TC(tp, p5_setuid_root);
	ATF_TP_ADD_TC(tp, p6_execvp_text);
	ATF_TP_ADD_TC(tp, p7_rtld_direct);
	ATF_TP_ADD_TC(tp, p9_memfd_rtld);
	ATF_TP_ADD_TC(tp, p10_fexecve_revoked_pty);
	ATF_TP_ADD_TC(tp, p11_mmap_read);
	ATF_TP_ADD_TC(tp, p12_thousand_true);
	ATF_TP_ADD_TC(tp, p14_posix_spawn);
	ATF_TP_ADD_TC(tp, p16_changes_inotify);
	ATF_TP_ADD_TC(tp, vfork_waits_for_exec);
	ATF_TP_ADD_TC(tp, ptrace_exec_stop_io);
	return (atf_no_error());
}
