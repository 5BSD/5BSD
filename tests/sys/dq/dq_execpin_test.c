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
 * brand has BI_CAN_EXEC_DYN.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/inotify.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
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
#define	PIN_DIRFILE	"pindir"	/* the shared directory's name */
#define	RTLD		"/libexec/ld-elf.so.1"

/* What one exec did: its errno (0: the image ran), status and output. */
struct pin_run {
	int	exec_errno;
	int	status;
	char	out[256];
};

typedef void (*pin_pre_fn)(void *arg);

/*
 * Fork; in the child run pre (if any), then execve path (execvp when
 * usepath).  The child's stdout is captured; a failed exec reports its
 * errno over a close-on-exec pipe, which stays empty when the image ran.
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
		if (usepath)
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
 * A directory others may search, on a file system that honours set-uid
 * (the work directory is private to root, /tmp may be nosuid), holding a
 * copy of the helper.  Its name is kept in the work directory for the
 * cleanup.
 */
static void
pin_dir(const atf_tc_t *tc, char *dir, size_t len)
{
	static const char *const bases[] = { "/tmp", "/var/tmp", "/root" };
	struct statfs sf;
	char path[PATH_MAX];
	FILE *f;
	u_int i;

	for (i = 0; i < nitems(bases); i++)
		if (statfs(bases[i], &sf) == 0 &&
		    (sf.f_flags & MNT_NOSUID) == 0)
			break;
	ATF_REQUIRE_MSG(i < nitems(bases), "no file system without nosuid");
	ATF_REQUIRE((size_t)snprintf(dir, len, "%s/dqpin.XXXXXX", bases[i]) <
	    len);
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	ATF_REQUIRE_EQ(0, chmod(dir, 0755));
	f = fopen(PIN_DIRFILE, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%s\n", dir);
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE((size_t)snprintf(path, sizeof(path), "%s/%s", dir,
	    HELPER) < sizeof(path));
	dqt_copy_helper(tc, HELPER, path);
}

static void
pin_dir_cleanup(void)
{
	char dir[PATH_MAX], cmd[PATH_MAX + 16];
	FILE *f;

	f = fopen(PIN_DIRFILE, "r");
	if (f == NULL)
		return;
	if (fgets(dir, sizeof(dir), f) != NULL) {
		dir[strcspn(dir, "\n")] = '\0';
		if (strncmp(dir, "/", 1) == 0 && strstr(dir, "/dqpin.") != NULL) {
			(void)snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
			(void)system(cmd);
		}
	}
	(void)fclose(f);
}

static void
pre_user(void *arg __unused)
{

	if (setgid(PIN_USER) != 0 || setuid(PIN_USER) != 0)
		_exit(124);
}

/* P1: an exec in a jail is not attached (flips at BX-4: a t1 scope). */
static void
pre_jail(void *arg)
{

	if (jail_attach(*(int *)arg) != 0)
		_exit(124);
}

ATF_TC_WITH_CLEANUP(p1_jail_unattached);
ATF_TC_HEAD(p1_jail_unattached, tc)
{
	atf_tc_set_md_var(tc, "descr", "P1: an exec inside a jail runs "
	    "unattached (flips at BX-4 with the jail's scope and ATTACH)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p1_jail_unattached, tc)
{
	char dir[PATH_MAX], path[PATH_MAX];
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r;
	int jid;

	pin_dir(tc, dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/%s", dir, HELPER);
	jid = jail_setv(JAIL_CREATE, "name", "dqpin_t1", "path", "/",
	    "persist", NULL, NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pin_exec(path, argv, false, pre_jail, &jid, &r);
	(void)jail_remove(jid);
	pin_check_ran(&r, "uid=0 euid=0 nnp=0");
}
ATF_TC_CLEANUP(p1_jail_unattached, tc)
{
	int jid;

	jid = jail_getid("dqpin_t1");
	if (jid > 0)
		(void)jail_remove(jid);
	pin_dir_cleanup();
}

ATF_TC_WITH_CLEANUP(p2_user_unattached);
ATF_TC_HEAD(p2_user_unattached, tc)
{
	atf_tc_set_md_var(tc, "descr", "P2: an exec by uid 1001 runs "
	    "unattached (flips at BX-4 with a scope whose Broker takes it)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p2_user_unattached, tc)
{
	char dir[PATH_MAX], path[PATH_MAX];
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r;

	pin_dir(tc, dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/%s", dir, HELPER);
	pin_exec(path, argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=1001 nnp=0");
}
ATF_TC_CLEANUP(p2_user_unattached, tc)
{

	pin_dir_cleanup();
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

ATF_TC(p3_exec_errnos);
ATF_TC_HEAD(p3_exec_errnos, tc)
{
	atf_tc_set_md_var(tc, "descr", "P3: execve's refusals and their "
	    "order: missing file ENOENT, mode 0644 EACCES (before the magic), "
	    "bad magic ENOEXEC, open for writing ETXTBSY (before the magic), "
	    "arguments past ARG_MAX E2BIG, a missing #! interpreter ENOENT, "
	    "capability mode ECAPMODE (never flips)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p3_exec_errnos, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	char *big[3];
	long argmax;

	dqt_copy_helper(tc, HELPER, "helper");
	pin_file("noexec", NULL, 0x5a, 64, 0644);
	pin_file("badmagic", NULL, 0x5a, 64, 0755);
	pin_file("busy-bad", NULL, 0x5a, 64, 0755);
	dqt_copy_helper(tc, HELPER, "busy");
	pin_file("nointerp", "#!/nonexistent/dqpin-interp\n", 0, 0, 0755);

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

	argmax = sysconf(_SC_ARG_MAX);
	ATF_REQUIRE(argmax > 0);
	big[0] = __DECONST(char *, "x");
	big[1] = malloc((size_t)argmax + 1);
	ATF_REQUIRE(big[1] != NULL);
	memset(big[1], 'a', (size_t)argmax);
	big[1][argmax] = '\0';
	big[2] = NULL;
	ATF_CHECK_EQ(E2BIG, pin_errno("./helper", big, NULL, NULL));
	/* The image's own refusals come after the arguments are copied. */
	ATF_CHECK_EQ(E2BIG, pin_errno("./badmagic", big, NULL, NULL));
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

ATF_TC_WITH_CLEANUP(p5_setuid_root);
ATF_TC_HEAD(p5_setuid_root, tc)
{
	atf_tc_set_md_var(tc, "descr", "P5: a set-uid-root image run by uid "
	    "1001 has euid 0 (flips at BX-4 when attached: euid unchanged)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p5_setuid_root, tc)
{
	char dir[PATH_MAX], path[PATH_MAX];
	char *argv[] = { __DECONST(char *, HELPER), NULL };
	struct pin_run r;

	pin_dir(tc, dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/%s", dir, HELPER);
	ATF_REQUIRE_EQ(0, chown(path, 0, 0));
	ATF_REQUIRE_EQ(0, chmod(path, 04755));
	pin_exec(path, argv, false, pre_user, NULL, &r);
	pin_check_ran(&r, "uid=1001 euid=0 nnp=0");
}
ATF_TC_CLEANUP(p5_setuid_root, tc)
{

	pin_dir_cleanup();
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
	atf_tc_set_md_var(tc, "descr", "P7: ld-elf.so.1 run directly loads "
	    "and runs a program (flips at BX-6: MAPS and DENY)");
}
ATF_TC_BODY(p7_rtld_direct, tc)
{
	char *argv[] = { __DECONST(char *, "ld-elf.so.1"),
	    __DECONST(char *, "./helper"), NULL };
	struct pin_run r;

	dqt_copy_helper(tc, HELPER, "helper");
	pin_exec(RTLD, argv, false, NULL, NULL, &r);
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
	char fdarg[16];
	char *argv[] = { __DECONST(char *, "ld-elf.so.1"),
	    __DECONST(char *, "-f"), fdarg, __DECONST(char *, "helper"),
	    NULL };
	struct pin_run r;

	dqt_copy_helper(tc, HELPER, "helper");
	fdarg[0] = '\0';
	pin_exec(RTLD, argv, false, pre_memfd, argv, &r);
	pin_check_ran(&r, "nnp=0");
}

/* P10: fexecve(2) of a revoked pty slave. */
static void
pre_revoked_pty(void *arg __unused)
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
	if (s == -1 || revoke(name) != 0)
		_exit(124);
	(void)fexecve(s, argv, environ);
	_exit(100 + errno);	/* the errno, as the exit status */
}

ATF_TC(p10_fexecve_revoked_pty);
ATF_TC_HEAD(p10_fexecve_revoked_pty, tc)
{
	atf_tc_set_md_var(tc, "descr", "P10: fexecve(2) of a revoked pty "
	    "slave is EBADF, no panic (never flips)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(p10_fexecve_revoked_pty, tc)
{
	char *argv[] = { __DECONST(char *, "x"), NULL };
	struct pin_run r;

	char buf[32];

	/* pre_revoked_pty exits with 100 + fexecve's errno. */
	pin_exec("./never-reached", argv, false, pre_revoked_pty, NULL, &r);
	ATF_CHECK_MSG(WIFEXITED(r.status) &&
	    WEXITSTATUS(r.status) == 100 + EBADF, "status: %s",
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

ATF_TC(p12_thousand_true);
ATF_TC_HEAD(p12_thousand_true, tc)
{
	atf_tc_set_md_var(tc, "descr", "P12: 1000 posix_spawn(2)s of "
	    "/usr/bin/true complete; the time is information (flips at BX-1: "
	    "the hold's fast path fires 1000 times)");
	atf_tc_set_md_var(tc, "timeout", "600");
}
ATF_TC_BODY(p12_thousand_true, tc)
{
	char *argv[] = { __DECONST(char *, "true"), NULL };
	struct timespec t0, t1, ts, te;
	long ms, worst;
	pid_t pid;
	int i, failed, status, worst_i;

	failed = 0;
	worst = 0;
	worst_i = -1;
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t0));
	for (i = 0; i < 1000; i++) {
		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
		ATF_REQUIRE_EQ(0, posix_spawn(&pid, "/usr/bin/true", NULL,
		    NULL, argv, environ));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
		ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &te));
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
			fprintf(stderr, "p12: %d execs, %ld ms\n", i + 1,
			    (long)((te.tv_sec - t0.tv_sec) * 1000 +
			    (te.tv_nsec - t0.tv_nsec) / 1000000));
	}
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &t1));
	ATF_CHECK_EQ(0, failed);
	printf("p12: 1000 execs in %ld ms, slowest %ld ms (#%d)\n",
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

static void
p16_changes(int ifd, int counts[3])
{
	char *p;
	int fd;

	fd = open("changed", O_RDWR | O_APPEND);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE_EQ(4, write(fd, "more", 4));
	dqt_msleep(100);
	counts[0] = ifd == -1 ? 0 : pin_inotify_count(ifd, IN_MODIFY);
	ATF_REQUIRE_EQ(0, ftruncate(fd, 2));
	dqt_msleep(100);
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
	dqt_msleep(100);
	counts[2] = ifd == -1 ? 0 : pin_inotify_count(ifd, IN_MODIFY);
	ATF_REQUIRE_EQ(0, close(fd));
}

ATF_TC(p16_changes_inotify);
ATF_TC_HEAD(p16_changes_inotify, tc)
{
	atf_tc_set_md_var(tc, "descr", "P16: append, ftruncate and a write "
	    "through a shared mapping succeed with and without an inotify "
	    "watch; a watch sees one IN_MODIFY each for the append, the "
	    "truncate and the msync'ed store through the mapping (never "
	    "flips; BX-1 adds the change-note sites)");
}
ATF_TC_BODY(p16_changes_inotify, tc)
{
	int counts[3], ifd, wd;

	pin_file("changed", "abcdefgh", 0, 0, 0644);
	p16_changes(-1, counts);

	ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	ATF_REQUIRE_MSG(ifd != -1, "inotify_init1: %s", strerror(errno));
	wd = inotify_add_watch(ifd, "changed", IN_ALL_EVENTS);
	ATF_REQUIRE_MSG(wd != -1, "inotify_add_watch: %s", strerror(errno));
	p16_changes(ifd, counts);
	ATF_CHECK_EQ_MSG(1, counts[0], "append: %d IN_MODIFY", counts[0]);
	ATF_CHECK_EQ_MSG(1, counts[1], "ftruncate: %d IN_MODIFY", counts[1]);
	ATF_CHECK_EQ_MSG(1, counts[2], "mapped store: %d IN_MODIFY",
	    counts[2]);
	ATF_CHECK_EQ(0, close(ifd));
}

ATF_TC(vfork_waits_for_exec);
ATF_TC_HEAD(vfork_waits_for_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "vfork(2)'s parent resumes only "
	    "once the child's exec committed: the child already has the "
	    "image's name (a held exec will hold the parent too)");
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
	    "PL_FLAG_EXEC and the debugger's PT_IO reads the new image there "
	    "(proc_rwmem's execve_block: a held exec must not wedge it)");
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
