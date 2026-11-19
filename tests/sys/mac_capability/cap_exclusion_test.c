/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Base exclusion (oes-core-exemption.md rev 2.1 with the rev 3 delta):
 * pins of today's behaviour on the paths the series changes, and the
 * exclusion mechanics.
 *
 * Tiers (vm-provider.sh):
 *  - Cases that issue software authority need an issuer.  Off PID 1 only a
 *    GENERIC-TEST kernel booted with kern.mac_capability.test_issuer=1
 *    gives one (STACK_TIER=1 KERNEL_TIER=test PLANE_OFF=1); elsewhere they
 *    skip, saying so.
 *  - The pid1_* cases run on every tier against the real PID 1 (Capsule on
 *    the plane-on tier, init(8) with PLANE_OFF=1).
 *  - The switchboard_* cases need a running switchboard(8) (plane-on).
 *
 * Every pin names its row of the design (P1-P48) and the commit at which
 * it is meant to flip, or "never".  Interfaces whose answer depends on the
 * tier (a capprotect shield on Capsule) are pinned per tier.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/event.h>
#include <sys/ktrace.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	P2_CAP_EXCLUDED_BIT	0x20000000	/* sys/proc.h P2_CAP_EXCLUDED */
#define	HELPER			"cap_exclusion_helper"

extern char **environ;

static int
op(int cmd, int fd, void *data)
{

	return (syscall(SYS_cap_process, cmd, fd, 0, data));
}

static void
helper_path(const atf_tc_t *tc, char *buf, size_t len)
{

	snprintf(buf, len, "%s/%s", atf_tc_get_config_var(tc, "srcdir"),
	    HELPER);
}

/* p_flag2 of pid, as kern.proc.pid reports it. */
static int
proc_flag2(pid_t pid, unsigned *flag2)
{
	struct kinfo_proc kp;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
	size_t len = sizeof(kp);

	mib[3] = pid;
	if (sysctl(mib, nitems(mib), &kp, &len, NULL, 0) != 0)
		return (errno);
	if (len == 0)
		return (ESRCH);
	*flag2 = (unsigned)kp.ki_flag2;
	return (0);
}

static bool
proc_excluded(pid_t pid)
{
	unsigned flag2;

	ATF_REQUIRE_EQ_MSG(proc_flag2(pid, &flag2), 0, "kern.proc.pid %d",
	    (int)pid);
	return ((flag2 & P2_CAP_EXCLUDED_BIT) != 0);
}

/* The issuer a test may use, or -1 (the caller skips). */
static int
test_issuer(void)
{
	int enabled, fd;
	size_t len = sizeof(enabled);

	if (sysctlbyname("kern.mac_capability.test_issuer", &enabled, &len,
	    NULL, 0) != 0 || enabled != 1)
		return (-1);
	fd = op(CAP_AUTH_ISSUER_CREATE, -1, NULL);
	return (fd);
}

static int
require_issuer(void)
{
	int issuer;

	issuer = test_issuer();
	if (issuer < 0)
		atf_tc_skip("no test issuer: needs GENERIC-TEST with "
		    "kern.mac_capability.test_issuer=1, boot not anchored "
		    "(vm-provider.sh STACK_TIER=1)");
	return (issuer);
}

/* A managed token constrained to the image open on fd, with flags. */
static int
constrained_token(int issuer, int image, uint32_t flags, int *error)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	int token;

	token = op(CAP_AUTH_ISSUE, issuer, &spec);
	ATF_REQUIRE_MSG(token >= 0, "issue: %s", strerror(errno));
	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.flags = flags;
	c.nexec = 1;
	c.executable_fds[0] = image;
	*error = op(CAP_AUTH_CONSTRAIN, issuer, &c) == 0 ? 0 : errno;
	return (token);
}

/* What one exec in a child did. */
struct run {
	int	exec_errno;	/* 0: the image ran */
	int	status;
	char	out[512];
};

typedef int (*pre_fn)(void *);

/*
 * Fork; in the child install token (if >= 0), run pre (if any; a non-zero
 * return is reported as the exec errno), then execve path (fexecve of fd
 * when path is NULL).  The child's stdout is captured; a failed exec
 * reports its errno over a close-on-exec pipe, which stays empty when the
 * image ran.
 */
static void
run_child(int token, pre_fn pre, void *arg, const char *path, int fd,
    char *const argv[], struct run *r)
{
	int out[2], err[2], e;
	ssize_t n;
	size_t off;
	pid_t pid;

	memset(r, 0, sizeof(*r));
	ATF_REQUIRE(pipe(out) == 0);
	ATF_REQUIRE(pipe2(err, O_CLOEXEC) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(out[0]);
		close(err[0]);
		if (dup2(out[1], STDOUT_FILENO) < 0)
			_exit(126);
		e = 0;
		if (token >= 0 && op(CAP_AUTH_INSTALL, token, NULL) != 0)
			e = errno;
		if (e == 0 && pre != NULL)
			e = pre(arg);
		if (e == 0) {
			if (path != NULL)
				execv(path, argv);
			else
				fexecve(fd, argv, environ);
			e = errno;
		}
		(void)write(err[1], &e, sizeof(e));
		_exit(127);
	}
	close(out[1]);
	close(err[1]);
	off = 0;
	while ((n = read(out[0], r->out + off,
	    sizeof(r->out) - 1 - off)) > 0)
		off += n;
	r->out[off] = '\0';
	if (read(err[0], &e, sizeof(e)) == sizeof(e))
		r->exec_errno = e;
	close(out[0]);
	close(err[0]);
	ATF_REQUIRE(waitpid(pid, &r->status, 0) == pid);
	printf("child: exec_errno=%d status=%#x out=%s\n", r->exec_errno,
	    r->status, r->out);
}

/* Copy the helper into dir (a fresh file, its own vnode). */
static void
copy_helper(const atf_tc_t *tc, const char *dst)
{
	char src[PATH_MAX], cmd[2 * PATH_MAX + 32];

	helper_path(tc, src, sizeof(src));
	snprintf(cmd, sizeof(cmd), "cp %s %s && chmod 0755 %s", src, dst, dst);
	ATF_REQUIRE_EQ_MSG(system(cmd), 0, "%s", cmd);
}

/*
 * Mount a fresh md(4)-backed UFS on dir: a file system whose vnodes support
 * the text pin a software authority needs (tmpfs does not), and that a
 * test may force-unmount.  The md unit is recorded in dir.md.
 */
static void
mount_md_ufs(const char *dir)
{
	char cmd[3 * PATH_MAX + 160];

	ATF_REQUIRE(mkdir(dir, 0755) == 0 || errno == EEXIST);
	snprintf(cmd, sizeof(cmd), "md=$(mdconfig -a -t malloc -s 16m) && "
	    "echo $md > %s.md && newfs /dev/$md > /dev/null && "
	    "mount /dev/$md %s", dir, dir);
	ATF_REQUIRE_EQ_MSG(system(cmd), 0, "%s", cmd);
}

/* After dir was unmounted: release its md unit. */
static void
release_md(const char *dir)
{
	char cmd[PATH_MAX + 64];

	snprintf(cmd, sizeof(cmd), "mdconfig -d -u $(cat %s.md)", dir);
	ATF_CHECK_EQ_MSG(system(cmd), 0, "%s", cmd);
}

/* ------------------------------------------------------------------ */

ATF_TC(test_process_not_excluded);
ATF_TC_HEAD(test_process_not_excluded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An ordinary process (this test) is never excluded (never)");
}
ATF_TC_BODY(test_process_not_excluded, tc)
{

	ATF_CHECK(!proc_excluded(getpid()));
	ATF_CHECK(!proc_excluded(getppid()));
}

ATF_TC(pid1_exclusion_bit);
ATF_TC_HEAD(pid1_exclusion_bit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X1: PID 1 is excluded, whatever image it runs (set from commit 2)");
}
ATF_TC_BODY(pid1_exclusion_bit, tc)
{

	ATF_CHECK(proc_excluded(1));
}

ATF_TC(core_role_refused);
ATF_TC_HEAD(core_role_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P1: CAP_AUTH_CONSTRAIN with flags 0x40 (CAP_AUTH_ROLE_CORE) is accepted, as 0x2 is (flipped in commit 2)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(core_role_refused, tc)
{
	char path[PATH_MAX];
	int issuer, image, token, error;

	issuer = require_issuer();
	helper_path(tc, path, sizeof(path));
	image = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	token = constrained_token(issuer, image, 0x40, &error);
	ATF_CHECK_EQ_MSG(error, 0, "constrain 0x40: %s", strerror(error));
	close(token);
	close(image);
	close(issuer);
}

ATF_TC(script_authority_flags0);
ATF_TC_HEAD(script_authority_flags0, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P17: a #! script pinned by a flags-0 authority runs, the authority not applied (never)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(script_authority_flags0, tc)
{
	char *const argv[] = { __DECONST(char *, "script"), NULL };
	struct run r;
	char path[PATH_MAX];
	int issuer, image, token, error, fd;

	issuer = require_issuer();
	ATF_REQUIRE(getcwd(path, sizeof(path)) != NULL);
	strlcat(path, "/script", sizeof(path));
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(dprintf(fd, "#!/bin/sh\necho ran\n") > 0);
	close(fd);
	image = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	token = constrained_token(issuer, image, 0, &error);
	ATF_REQUIRE_EQ_MSG(error, 0, "constrain: %s", strerror(error));
	run_child(token, NULL, NULL, path, -1, argv, &r);
	ATF_CHECK_EQ(r.exec_errno, 0);
	ATF_CHECK_STREQ(r.out, "ran\n");
	close(token);
	close(image);
	close(issuer);
}

static int
clear_then_info(void *arg)
{
	struct cap_authority_info info;

	(void)arg;
	if (op(CAP_AUTH_CLEAR, -1, NULL) != 0)
		return (errno);
	memset(&info, 0xff, sizeof(info));
	if (op(CAP_AUTH_INFO, -1, &info) != 0)
		return (errno);
	return (info.valid == 0 ? 0 : 200);
}

ATF_TC(clear_then_info);
ATF_TC_HEAD(clear_then_info, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P18: CAP_AUTH_CLEAR then CAP_AUTH_INFO reports valid == 0 (never)");
}
ATF_TC_BODY(clear_then_info, tc)
{
	char *const argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	char path[PATH_MAX];
	struct run r;

	helper_path(tc, path, sizeof(path));
	run_child(-1, clear_then_info, NULL, path, -1, argv, &r);
	ATF_CHECK_EQ(r.exec_errno, 0);
}

/* P46: fexecve of a revoked terminal, as an unprivileged user. */
static int
revoked_pty_fexecve(void *arg)
{
	char *const argv[] = { __DECONST(char *, "x"), NULL };
	const char *slave;
	int master, fd;

	(void)arg;
	if (setgid(65534) != 0 || setuid(65534) != 0)
		return (201);
	master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 ||
	    (slave = ptsname(master)) == NULL)
		return (202);
	fd = open(slave, O_RDONLY | O_NOCTTY);
	if (fd < 0)
		return (203);
	if (revoke(slave) != 0)
		return (204);
	fexecve(fd, argv, environ);
	return (errno);
}

ATF_TC(revoked_pty_fexecve);
ATF_TC_HEAD(revoked_pty_fexecve, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P46: fexecve of a revoked pty slave fails with EBADF and nothing panics (never)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(revoked_pty_fexecve, tc)
{
	struct run r;

	run_child(-1, revoked_pty_fexecve, NULL, NULL, -1, NULL, &r);
	ATF_CHECK_EQ_MSG(r.exec_errno, EBADF, "fexecve: %d", r.exec_errno);
}

/* P47: fexecve of an O_PATH descriptor after a forced unmount. */
struct p47 {
	int	token;
	int	fd;
	int	ready[2];
	int	go[2];
};

static int
p47_child(void *arg)
{
	struct p47 *s = arg;
	char *const argv[] = { __DECONST(char *, "x"), NULL };
	char c = 0;

	/* The parent unmounts between these two pipe bytes. */
	if (write(s->ready[1], &c, 1) != 1 || read(s->go[0], &c, 1) != 1)
		return (205);
	fexecve(s->fd, argv, environ);
	return (errno);
}

static void
p47_case(const atf_tc_t *tc, uint32_t flags, bool want_authority)
{
	struct p47 s;
	char dir[PATH_MAX], file[PATH_MAX], cmd[PATH_MAX + 32], c;
	int issuer = -1, image, error, status;
	pid_t pid;

	ATF_REQUIRE(getcwd(dir, sizeof(dir)) != NULL);
	strlcat(dir, want_authority ? "/p47a" : "/p47", sizeof(dir));
	mount_md_ufs(dir);
	snprintf(file, sizeof(file), "%s/x", dir);
	copy_helper(tc, file);
	s.token = -1;
	if (want_authority) {
		issuer = test_issuer();
		if (issuer >= 0) {
			image = open(file, O_RDONLY | O_CLOEXEC);
			ATF_REQUIRE(image >= 0);
			s.token = constrained_token(issuer, image, flags,
			    &error);
			ATF_REQUIRE_EQ_MSG(error, 0, "constrain: %s",
			    strerror(error));
			close(image);
		} else
			printf("no test issuer: P47 without an authority\n");
	}
	s.fd = open(file, O_PATH | O_CLOEXEC);
	ATF_REQUIRE(s.fd >= 0);
	ATF_REQUIRE(pipe(s.ready) == 0 && pipe(s.go) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int e = 0;

		if (s.token >= 0 && op(CAP_AUTH_INSTALL, s.token, NULL) != 0)
			e = errno;
		if (e == 0)
			e = p47_child(&s);
		_exit(e > 255 ? 255 : e);
	}
	ATF_REQUIRE(read(s.ready[0], &c, 1) == 1);
	close(s.fd);
	if (s.token >= 0)
		close(s.token);
	if (issuer >= 0)
		close(issuer);
	snprintf(cmd, sizeof(cmd), "umount -f %s", dir);
	ATF_REQUIRE_EQ_MSG(system(cmd), 0, "%s", cmd);
	release_md(dir);
	ATF_REQUIRE(write(s.go[1], &c, 1) == 1);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ_MSG(WEXITSTATUS(status), EBADF, "fexecve after umount -f: %d",
	    WEXITSTATUS(status));
}

ATF_TC(forced_unmount_opath);
ATF_TC_HEAD(forced_unmount_opath, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P47: fexecve of an O_PATH descriptor after umount -f fails with EBADF, with and without an authority on the image (never)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(forced_unmount_opath, tc)
{

	p47_case(tc, 0, false);
	p47_case(tc, 0, true);
}

/* P48: a failing IS_CHECK under a selected authority leaks nothing. */
static int
cap_token_refs(int token, struct cap_authority_info *info)
{

	return (op(CAP_AUTH_TOKEN_INFO, token, info));
}

static void
p48_case(const atf_tc_t *tc, uint32_t flags)
{
	char *const argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	struct cap_authority_info before, after;
	struct run r;
	char dir[PATH_MAX], file[PATH_MAX], cmd[PATH_MAX + 64];
	int issuer, image, token, error;

	issuer = require_issuer();
	ATF_REQUIRE(getcwd(dir, sizeof(dir)) != NULL);
	strlcat(dir, flags != 0 ? "/p48c" : "/p48", sizeof(dir));
	mount_md_ufs(dir);
	snprintf(file, sizeof(file), "%s/x", dir);
	copy_helper(tc, file);
	image = open(file, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	token = constrained_token(issuer, image, flags, &error);
	ATF_REQUIRE_EQ_MSG(error, 0, "constrain: %s", strerror(error));
	ATF_REQUIRE(cap_token_refs(token, &before) == 0);

	/* (a) no execute permission */
	ATF_REQUIRE(chmod(file, 0644) == 0);
	run_child(token, NULL, NULL, file, -1, argv, &r);
	ATF_CHECK_EQ_MSG(r.exec_errno, EACCES, "mode 0644: %d", r.exec_errno);
	ATF_REQUIRE(cap_token_refs(token, &after) == 0);
	ATF_CHECK_EQ(before.references, after.references);
	ATF_CHECK_EQ(before.valid, after.valid);

	/*
	 * (b) noexec mount.  A token is installed once (the child of (a)
	 * consumed it, though its exec failed): constrain a second one.
	 */
	close(token);
	token = constrained_token(issuer, image, flags, &error);
	ATF_REQUIRE_EQ_MSG(error, 0, "constrain: %s", strerror(error));
	ATF_REQUIRE(cap_token_refs(token, &before) == 0);
	ATF_REQUIRE(chmod(file, 0755) == 0);
	snprintf(cmd, sizeof(cmd), "mount -u -o noexec %s", dir);
	ATF_REQUIRE_EQ_MSG(system(cmd), 0, "%s", cmd);
	run_child(token, NULL, NULL, file, -1, argv, &r);
	ATF_CHECK_EQ_MSG(r.exec_errno, EACCES, "noexec: %d", r.exec_errno);
	ATF_REQUIRE(cap_token_refs(token, &after) == 0);
	ATF_CHECK_EQ(before.references, after.references);
	ATF_CHECK_EQ(before.valid, after.valid);

	close(image);
	close(token);
	close(issuer);
	snprintf(cmd, sizeof(cmd), "umount %s", dir);
	ATF_CHECK_EQ(system(cmd), 0);
	release_md(dir);
}

ATF_TC(ischeck_failure_no_leak);
ATF_TC_HEAD(ischeck_failure_no_leak, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P48: an exec refused by IS_CHECK (mode, noexec) under a selected authority is EACCES and leaves the token's references unchanged (never)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ischeck_failure_no_leak, tc)
{

	p48_case(tc, 0);
}

/* ------------------------------------------------------------------ */
/*
 * The p_candebug(9) and p_caninspect(9) interfaces against a target
 * (rev 3 delta 1.4).  Each returns 0 or the errno the interface gave.
 */

static int
iface_ptrace(pid_t pid)
{
	int status;

	if (ptrace(PT_ATTACH, pid, NULL, 0) != 0)
		return (errno);
	(void)waitpid(pid, &status, 0);
	(void)ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	return (0);
}

static int
iface_sysctl_read(pid_t pid, int what, int extra, bool has_extra)
{
	int mib[5] = { CTL_KERN, KERN_PROC, what, pid, extra };
	size_t len = 0;
	void *buf;
	int error;

	if (sysctl(mib, has_extra ? 5 : 4, NULL, &len, NULL, 0) != 0)
		return (errno);
	len = len * 2 + 4096;
	buf = malloc(len);
	ATF_REQUIRE(buf != NULL);
	error = sysctl(mib, has_extra ? 5 : 4, buf, &len, NULL, 0) != 0 ?
	    errno : 0;
	free(buf);
	return (error);
}

static int
iface_sysctl_rewrite(pid_t pid, int what, int extra, bool has_extra,
    size_t size)
{
	int mib[5] = { CTL_KERN, KERN_PROC, what, pid, extra };
	char buf[64];
	size_t len = size;

	if (sysctl(mib, has_extra ? 5 : 4, buf, &len, NULL, 0) != 0)
		return (errno);
	if (sysctl(mib, has_extra ? 5 : 4, NULL, NULL, buf, len) != 0)
		return (errno);
	return (0);
}

static int
iface_kcmp(pid_t pid)
{

	return (syscall(SYS_kcmp, getpid(), pid, KCMP_FILE, 0, 0) < 0 ?
	    errno : 0);
}

static int
iface_pdopenpid(pid_t pid)
{
	int fd;

	fd = pdopenpid(pid, 0);
	if (fd < 0)
		return (errno);
	close(fd);
	return (0);
}

static int
iface_ktrace(pid_t pid)
{
	char path[PATH_MAX];
	int error = 0;

	ATF_REQUIRE(getcwd(path, sizeof(path)) != NULL);
	strlcat(path, "/ktrace.out", sizeof(path));
	ATF_REQUIRE(close(open(path, O_WRONLY | O_CREAT, 0600)) == 0);
	if (ktrace(path, KTROP_SET, KTRFAC_SYSCALL, pid) != 0)
		error = errno;
	(void)ktrace(path, KTROP_CLEAR, KTRFAC_SYSCALL, pid);
	return (error);
}

static int
iface_procctl(pid_t pid, int cmd)
{
	int v = cmd == PROC_NO_NEW_PRIVS_CTL ? 0 : 99;

	return (procctl(P_PID, pid, cmd, &v) == 0 ? 0 : errno);
}

/*
 * linprocfs (5BSD retired procfs): open <dir>/<pid>/<node>.  Its debug-class
 * nodes (mem, the fd directory) are visible only to a process that can
 * debug the target (linprocfs_common_candebug()), so a refusal is ENOENT.
 */
static int
iface_linprocfs(const char *dir, pid_t pid, const char *node)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%d/%s", dir, (int)pid, node);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);
	close(fd);
	return (0);
}

struct iface_row {
	const char	*name;
	bool		 inspect;	/* p_caninspect(9): never refused */
	int		 got;
};

static void
run_interfaces(pid_t pid, struct iface_row *rows, size_t *nrows)
{
	static const struct { int cmd; const char *name; } ctls[] = {
		{ PROC_TRACE_CTL, "procctl-trace" },
		{ PROC_TRAPCAP_CTL, "procctl-trapcap" },
		{ PROC_ASLR_CTL, "procctl-aslr" },
		{ PROC_PROTMAX_CTL, "procctl-protmax" },
		{ PROC_STACKGAP_CTL, "procctl-stackgap" },
		{ PROC_NO_NEW_PRIVS_CTL, "procctl-nnp" },
		{ PROC_WXMAP_CTL, "procctl-wxmap" },
		{ PROC_LOGSIGEXIT_CTL, "procctl-logsigexit" },
	};
	char dir[PATH_MAX], cmd[PATH_MAX + 32];
	size_t n = 0;

#define	ROW(nm, insp, expr) do {					\
	rows[n].name = (nm);						\
	rows[n].inspect = (insp);					\
	rows[n].got = (expr);						\
	n++;								\
} while (0)
	ROW("P20 ptrace-attach", false, iface_ptrace(pid));
	ATF_REQUIRE(getcwd(dir, sizeof(dir)) != NULL);
	strlcat(dir, "/linproc", sizeof(dir));
	ATF_REQUIRE(mkdir(dir, 0755) == 0 || errno == EEXIST);
	snprintf(cmd, sizeof(cmd), "mount -t linprocfs linprocfs %s", dir);
	ATF_REQUIRE_EQ_MSG(system(cmd), 0, "%s", cmd);
	ROW("P21 linprocfs-mem", false, iface_linprocfs(dir, pid, "mem"));
	ROW("P45 linprocfs-fd", false, iface_linprocfs(dir, pid, "fd"));
	snprintf(cmd, sizeof(cmd), "umount %s", dir);
	ATF_CHECK_EQ(system(cmd), 0);
	ROW("P23 kern.proc.filedesc", false,
	    iface_sysctl_read(pid, KERN_PROC_FILEDESC, 0, false));
	ROW("P24 kern.proc.cwd", false,
	    iface_sysctl_read(pid, KERN_PROC_CWD, 0, false));
	ROW("P25 kern.proc.env", false,
	    iface_sysctl_read(pid, KERN_PROC_ENV, 0, false));
	ROW("P26 kern.proc.auxv", true,
	    iface_sysctl_read(pid, KERN_PROC_AUXV, 0, false));
	ROW("P27 kern.proc.vmmap", true,
	    iface_sysctl_read(pid, KERN_PROC_VMMAP, 0, false));
	ROW("P28 kern.proc.kstack", true,
	    iface_sysctl_read(pid, KERN_PROC_KSTACK, 0, false));
	ROW("P29 kern.proc.rlimit-write", false,
	    iface_sysctl_rewrite(pid, KERN_PROC_RLIMIT, RLIMIT_CORE, true,
	    sizeof(struct rlimit)));
	ROW("P30 kern.proc.ps_strings", true,
	    iface_sysctl_read(pid, KERN_PROC_PS_STRINGS, 0, false));
	ROW("P31 kern.proc.umask", true,
	    iface_sysctl_read(pid, KERN_PROC_UMASK, 0, false));
	ROW("P32 kern.proc.osrel-write", false,
	    iface_sysctl_rewrite(pid, KERN_PROC_OSREL, 0, false, sizeof(int)));
	ROW("P33 kern.proc.sigtramp", true,
	    iface_sysctl_read(pid, KERN_PROC_SIGTRAMP, 0, false));
	ROW("P34 kern.proc.sigfastblk", true,
	    iface_sysctl_read(pid, KERN_PROC_SIGFASTBLK, 0, false));
	ROW("P35 kern.proc.vm_layout", true,
	    iface_sysctl_read(pid, KERN_PROC_VM_LAYOUT, 0, false));
	ROW("P36 kern.proc.kqueue", false,
	    iface_sysctl_read(pid, KERN_PROC_KQUEUE, 0, true));
	ROW("P37 kcmp", false, iface_kcmp(pid));
	ROW("P38 pdopenpid", false, iface_pdopenpid(pid));
	ROW("P40 ktrace", false, iface_ktrace(pid));
	for (size_t i = 0; i < nitems(ctls); i++)
		ROW(ctls[i].name, false, iface_procctl(pid, ctls[i].cmd));
#undef ROW
	*nrows = n;
	for (size_t i = 0; i < n; i++)
		printf("%s pid %d: %d (%s)\n", rows[i].name, (int)pid,
		    rows[i].got, rows[i].got == 0 ? "ok" : strerror(rows[i].got));
}

#define	MAX_ROWS	40

/*
 * Today's answers for a target, recorded on the pre-change kernel (commit
 * 1) and kept as the pin: debug rows flip to a refusal in commit 4 only
 * where they answered 0; inspect rows never change.
 */
struct expect_row {
	const char	*name;
	int		 want;
};

static void
check_interfaces(pid_t pid, const struct expect_row *want, size_t nwant)
{
	struct iface_row rows[MAX_ROWS];
	size_t n;

	run_interfaces(pid, rows, &n);
	ATF_REQUIRE_EQ(n, nwant);
	for (size_t i = 0; i < n; i++) {
		ATF_REQUIRE_STREQ(rows[i].name, want[i].name);
		ATF_CHECK_EQ_MSG(rows[i].got, want[i].want,
		    "%s: got %d (%s), want %d (%s)", rows[i].name, rows[i].got,
		    strerror(rows[i].got), want[i].want,
		    strerror(want[i].want));
	}
}

#include "cap_exclusion_pins.h"

static bool
plane_on(void)
{
	char name[64];
	size_t len = sizeof(name);
	struct kinfo_proc *kp;

	kp = kinfo_getproc(1);
	if (kp == NULL)
		return (false);
	strlcpy(name, kp->ki_comm, sizeof(name));
	free(kp);
	(void)len;
	return (strcmp(name, "capsule") == 0);
}

ATF_TC(pid1_debug_interfaces);
ATF_TC_HEAD(pid1_debug_interfaces, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P20-P41 against PID 1 as root: today's answers (cap_exclusion_pins.h); debug rows flip in commit 4, inspect rows never");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(pid1_debug_interfaces, tc)
{

	if (plane_on())
		check_interfaces(1, pins_pid1_capsule,
		    nitems(pins_pid1_capsule));
	else
		check_interfaces(1, pins_pid1_init, nitems(pins_pid1_init));
}

static pid_t
switchboard_pid(void)
{
	struct kinfo_proc *kp;
	int cnt;
	pid_t pid = -1;

	kp = kinfo_getallproc(&cnt);
	ATF_REQUIRE(kp != NULL);
	for (int i = 0; i < cnt; i++) {
		if (kp[i].ki_ppid == 1 &&
		    strcmp(kp[i].ki_comm, "switchboard") == 0) {
			pid = kp[i].ki_pid;
			break;
		}
	}
	free(kp);
	return (pid);
}

ATF_TC(switchboard_exclusion_bit);
ATF_TC_HEAD(switchboard_exclusion_bit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P6: switchboard is excluded (flipped in commit 3); the Core spine units are, BSDNotify (class system) and this test are not");
}
ATF_TC_BODY(switchboard_exclusion_bit, tc)
{
	static const char *const core[] = { "BSDAudit", "BSDCrypto",
	    "BSDExtension", "BSDFilesystem", "BSDLog", "BSDPower", "BSDSysctl",
	    "BSDTime" };
	struct kinfo_proc *kp;
	int cnt, seen = 0;
	pid_t pid;

	pid = switchboard_pid();
	if (pid < 0)
		atf_tc_skip("no switchboard (plane-on tier only)");
	ATF_CHECK(proc_excluded(pid));
	kp = kinfo_getallproc(&cnt);
	ATF_REQUIRE(kp != NULL);
	for (int i = 0; i < cnt; i++) {
		bool is_core = false;

		if (kp[i].ki_ppid != pid)
			continue;
		for (size_t j = 0; j < nitems(core); j++)
			if (strcmp(kp[i].ki_comm, core[j]) == 0)
				is_core = true;
		if (is_core) {
			seen++;
			ATF_CHECK_MSG((kp[i].ki_flag2 & P2_CAP_EXCLUDED_BIT) != 0,
			    "Core unit %s (pid %d) not excluded", kp[i].ki_comm,
			    kp[i].ki_pid);
		} else if (strcmp(kp[i].ki_comm, "BSDNotify") == 0)
			ATF_CHECK_MSG((kp[i].ki_flag2 & P2_CAP_EXCLUDED_BIT) == 0,
			    "BSDNotify (pid %d) excluded", kp[i].ki_pid);
	}
	free(kp);
	printf("%d Core units running\n", seen);
	ATF_CHECK(seen > 0);
}

ATF_TC(switchboard_debug_interfaces);
ATF_TC_HEAD(switchboard_debug_interfaces, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "P20-P41 against switchboard as root: today's answers; debug rows flip in commits 3+4, inspect rows never");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(switchboard_debug_interfaces, tc)
{
	pid_t pid;

	pid = switchboard_pid();
	if (pid < 0)
		atf_tc_skip("no switchboard (plane-on tier only)");
	check_interfaces(pid, pins_switchboard, nitems(pins_switchboard));
}

/* ------------------------------------------------------------------ */
/*
 * Exclusion mechanics (X rows).  A test process cannot be a child of PID
 * 1, so each case's child first marks itself excluded with the test
 * kernel's debug.mac_capability.test_issuer_exclude_self, standing in for
 * PID 1's fork chain; the knob exists only where test issuers do.
 */

static int
exclude_self(void *arg)
{
	int one = 1;

	(void)arg;
	if (sysctlbyname("debug.mac_capability.test_issuer_exclude_self", NULL,
	    NULL, &one, sizeof(one)) != 0)
		return (errno);
	return (0);
}

static uint64_t
counter(const char *name)
{
	uint64_t v;
	size_t len = sizeof(v);

	ATF_REQUIRE_MSG(sysctlbyname(name, &v, &len, NULL, 0) == 0, "%s: %s",
	    name, strerror(errno));
	return (v);
}

/* The helper's report line number n (0-based) of r. */
static bool
report_n(const struct run *r, int n, unsigned *flag2, unsigned *valid)
{
	const char *line = r->out;

	for (; n > 0 && line != NULL; n--) {
		line = strchr(line, '\n');
		if (line != NULL)
			line++;
	}
	return (line != NULL &&
	    sscanf(line, "flag2=%x valid=%u", flag2, valid) == 2);
}

struct xcase {
	int	issuer;
	int	image;		/* the helper, opened */
	char	helper[PATH_MAX];
};

static void
xcase_init(const atf_tc_t *tc, struct xcase *x)
{

	x->issuer = require_issuer();
	helper_path(tc, x->helper, sizeof(x->helper));
	x->image = open(x->helper, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(x->image >= 0);
}

static void
xcase_fini(struct xcase *x)
{

	close(x->image);
	close(x->issuer);
}

static int
core_token(struct xcase *x, uint32_t flags)
{
	int token, error;

	token = constrained_token(x->issuer, x->image, flags, &error);
	ATF_REQUIRE_EQ_MSG(error, 0, "constrain %#x: %s", flags,
	    strerror(error));
	return (token);
}

static void
expect_report(const struct run *r, int line, bool excluded, unsigned valid)
{
	unsigned flag2, v;

	ATF_REQUIRE_EQ_MSG(r->exec_errno, 0, "exec: %s",
	    strerror(r->exec_errno));
	ATF_REQUIRE_MSG(report_n(r, line, &flag2, &v), "no report %d: %s",
	    line, r->out);
	ATF_CHECK_EQ_MSG((flag2 & P2_CAP_EXCLUDED_BIT) != 0, excluded,
	    "report %d: flag2 %#x", line, flag2);
	ATF_CHECK_EQ_MSG(v, valid, "report %d: valid %u", line, v);
}

ATF_TC(x3_exec_without_authority_clears);
ATF_TC_HEAD(x3_exec_without_authority_clears, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X3: an excluded process that executes an image without a Core authority is not excluded");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x3_exec_without_authority_clears, tc)
{
	struct xcase x;
	struct run r;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };

	xcase_init(tc, &x);
	run_child(-1, exclude_self, NULL, x.helper, -1, argv, &r);
	expect_report(&r, 0, false, 0);
	xcase_fini(&x);
}

ATF_TC(x4_core_exec_sets);
ATF_TC_HEAD(x4_core_exec_sets, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X4/X12: an excluded process that executes the image its installed Core authority pins stays excluded (flags 0x40 and 0x42); granted counts it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x4_core_exec_sets, tc)
{
	static const uint32_t flags[] = { 0x40, 0x42 };
	struct xcase x;
	struct run r;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	uint64_t granted;
	int token;

	xcase_init(tc, &x);
	for (size_t i = 0; i < nitems(flags); i++) {
		token = core_token(&x, flags[i]);
		granted = counter("security.cap_exclusion.granted");
		run_child(token, exclude_self, NULL, x.helper, -1, argv, &r);
		expect_report(&r, 0, true, 1);
		ATF_CHECK_EQ(counter("security.cap_exclusion.granted"),
		    granted + 1);
		close(token);
	}
	xcase_fini(&x);
}

ATF_TC(x5_x7_other_image_clears);
ATF_TC_HEAD(x5_x7_other_image_clears, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X5: a Core image that executes another image is not excluded there; X7: a copy of the pinned image at another path is another vnode, not excluded and without authority");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x5_x7_other_image_clears, tc)
{
	struct xcase x;
	struct run r;
	char copy[PATH_MAX];
	int token;

	xcase_init(tc, &x);
	ATF_REQUIRE(getcwd(copy, sizeof(copy)) != NULL);
	strlcat(copy, "/copy", sizeof(copy));
	copy_helper(tc, copy);
	{
		char *argv[] = { __DECONST(char *, HELPER),
		    __DECONST(char *, "exec"), copy,
		    __DECONST(char *, "report"), NULL };

		token = core_token(&x, 0x40);
		run_child(token, exclude_self, NULL, x.helper, -1, argv, &r);
		expect_report(&r, 0, true, 1);
		expect_report(&r, 1, false, 0);
		close(token);
	}
	{
		char *argv[] = { __DECONST(char *, HELPER),
		    __DECONST(char *, "report"), NULL };

		token = core_token(&x, 0x40);
		run_child(token, exclude_self, NULL, copy, -1, argv, &r);
		expect_report(&r, 0, false, 0);
		close(token);
	}
	xcase_fini(&x);
}

ATF_TC(x6_not_excluded_never_acquires);
ATF_TC_HEAD(x6_not_excluded_never_acquires, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X6: a process that is not excluded installs a Core token and executes the pinned image: it gets the authority, not exclusion");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x6_not_excluded_never_acquires, tc)
{
	struct xcase x;
	struct run r;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	uint64_t granted;
	int token;

	xcase_init(tc, &x);
	token = core_token(&x, 0x40);
	granted = counter("security.cap_exclusion.granted");
	run_child(token, NULL, NULL, x.helper, -1, argv, &r);
	expect_report(&r, 0, false, 1);
	ATF_CHECK_EQ(counter("security.cap_exclusion.granted"), granted);
	close(token);
	xcase_fini(&x);
}

ATF_TC(x8_pinned_image_text_busy);
ATF_TC_HEAD(x8_pinned_image_text_busy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X8: the image a Core authority pins cannot be opened for writing (ETXTBSY)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x8_pinned_image_text_busy, tc)
{
	char copy[PATH_MAX];
	struct xcase x;
	int image, token, error;

	xcase_init(tc, &x);
	ATF_REQUIRE(getcwd(copy, sizeof(copy)) != NULL);
	strlcat(copy, "/pinned", sizeof(copy));
	copy_helper(tc, copy);
	image = open(copy, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	token = constrained_token(x.issuer, image, 0x40, &error);
	ATF_REQUIRE_EQ(error, 0);
	ATF_CHECK_ERRNO(ETXTBSY, open(copy, O_WRONLY) == -1);
	close(token);
	close(image);
	xcase_fini(&x);
}

/* X2, X9: fork inherits; an excluded parent's ptrace attach clears. */
static int
x2_x9_pre(void *arg)
{
	unsigned flag2;
	int status, sync[2];
	pid_t gc;
	char c;

	(void)arg;
	if (exclude_self(NULL) != 0)
		return (errno);
	if (pipe(sync) != 0)
		return (errno);
	gc = fork();
	if (gc < 0)
		return (errno);
	if (gc == 0) {
		close(sync[1]);
		(void)read(sync[0], &c, 1);
		_exit(0);
	}
	close(sync[0]);
	if (proc_flag2(gc, &flag2) != 0)
		return (210);
	printf("fork flag2=%#x\n", flag2);
	if (ptrace(PT_ATTACH, gc, NULL, 0) != 0)
		return (errno);
	if (waitpid(gc, &status, 0) != gc)
		return (211);
	if (proc_flag2(gc, &flag2) != 0)
		return (212);
	printf("attached flag2=%#x\n", flag2);
	if (ptrace(PT_DETACH, gc, (caddr_t)1, 0) != 0)
		return (errno);
	if (proc_flag2(gc, &flag2) != 0)
		return (213);
	printf("detached flag2=%#x\n", flag2);
	fflush(stdout);
	close(sync[1]);
	(void)waitpid(gc, &status, 0);
	return (0);
}

ATF_TC(x2_x9_fork_and_trace);
ATF_TC_HEAD(x2_x9_fork_and_trace, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X2: a fork child of an excluded process is excluded; X9: when its excluded parent ptrace-attaches it, it is no longer excluded, also after the detach");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x2_x9_fork_and_trace, tc)
{
	struct xcase x;
	struct run r;
	unsigned f1, f2, f3;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };

	xcase_init(tc, &x);
	run_child(-1, x2_x9_pre, NULL, x.helper, -1, argv, &r);
	ATF_REQUIRE_EQ_MSG(r.exec_errno, 0, "pre: %d", r.exec_errno);
	ATF_REQUIRE(sscanf(r.out, "fork flag2=%x\nattached flag2=%x\n"
	    "detached flag2=%x", &f1, &f2, &f3) == 3);
	ATF_CHECK((f1 & P2_CAP_EXCLUDED_BIT) != 0);
	ATF_CHECK((f2 & P2_CAP_EXCLUDED_BIT) == 0);
	ATF_CHECK((f3 & P2_CAP_EXCLUDED_BIT) == 0);
	xcase_fini(&x);
}

static int
ktrace_self(void *arg)
{
	char path[PATH_MAX];

	if (exclude_self(NULL) != 0)
		return (errno);
	snprintf(path, sizeof(path), "%s", (const char *)arg);
	if (ktrace(path, KTROP_SET, KTRFAC_SYSCALL, getpid()) != 0)
		return (errno);
	return (0);
}

static int
nnp_self(void *arg)
{
	int v = PROC_NO_NEW_PRIVS_ENABLE;

	(void)arg;
	if (exclude_self(NULL) != 0)
		return (errno);
	return (procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &v) == 0 ?
	    0 : errno);
}

ATF_TC(x10_x16_traced_or_nnp_clears);
ATF_TC_HEAD(x10_x16_traced_or_nnp_clears, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X10: a ktraced process executing its Core image is not excluded; X16: nor is one with no_new_privs");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x10_x16_traced_or_nnp_clears, tc)
{
	struct xcase x;
	struct run r;
	char trace[PATH_MAX];
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	int token;

	xcase_init(tc, &x);
	ATF_REQUIRE(getcwd(trace, sizeof(trace)) != NULL);
	strlcat(trace, "/ktrace.out", sizeof(trace));
	ATF_REQUIRE(close(open(trace, O_WRONLY | O_CREAT, 0600)) == 0);
	token = core_token(&x, 0x40);
	run_child(token, ktrace_self, trace, x.helper, -1, argv, &r);
	expect_report(&r, 0, false, 0);
	close(token);
	token = core_token(&x, 0x40);
	run_child(token, nnp_self, NULL, x.helper, -1, argv, &r);
	expect_report(&r, 0, false, 0);
	close(token);
	xcase_fini(&x);
}

ATF_TC(x11_jail_clears);
ATF_TC_HEAD(x11_jail_clears, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X11: a Core image that enters a jail is no longer excluded");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x11_jail_clears, tc)
{
	struct xcase x;
	struct run r;
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "jail"), NULL };
	int token;

	xcase_init(tc, &x);
	token = core_token(&x, 0x40);
	run_child(token, exclude_self, NULL, x.helper, -1, argv, &r);
	expect_report(&r, 0, false, 0);
	close(token);
	xcase_fini(&x);
}

ATF_TC(x13_x14_role_shapes);
ATF_TC_HEAD(x13_x14_role_shapes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X13: the Core role with two images is EINVAL; X14: a Core authority cannot be registered as an application (EINVAL)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x13_x14_role_shapes, tc)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	struct cap_authority_application app;
	struct xcase x;
	int token, image2;

	xcase_init(tc, &x);
	image2 = open("/bin/sh", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image2 >= 0);
	token = op(CAP_AUTH_ISSUE, x.issuer, &spec);
	ATF_REQUIRE(token >= 0);
	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.flags = CAP_AUTH_ROLE_CORE;
	c.nexec = 2;
	c.executable_fds[0] = x.image;
	c.executable_fds[1] = image2;
	ATF_CHECK_ERRNO(EINVAL, op(CAP_AUTH_CONSTRAIN, x.issuer, &c) == -1);
	close(token);
	token = core_token(&x, CAP_AUTH_ROLE_CORE);
	app.token_fd = token;
	app.reserved = 0;
	ATF_CHECK_ERRNO(EINVAL, op(CAP_AUTH_REGISTER_APP, x.issuer, &app) == -1);
	close(token);
	close(image2);
	xcase_fini(&x);
}

ATF_TC(x17_core_script_refused);
ATF_TC_HEAD(x17_core_script_refused, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X17: an exec predicted excluded whose image is a #! script fails with EACCES and refused_interp counts it; P17's flags-0 script still runs");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x17_core_script_refused, tc)
{
	char *const argv[] = { __DECONST(char *, "script"), NULL };
	struct xcase x;
	struct run r;
	char path[PATH_MAX];
	uint64_t refused;
	int image, token, error, fd;

	xcase_init(tc, &x);
	ATF_REQUIRE(getcwd(path, sizeof(path)) != NULL);
	strlcat(path, "/script", sizeof(path));
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(dprintf(fd, "#!/bin/sh\necho ran\n") > 0);
	close(fd);
	image = open(path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	token = constrained_token(x.issuer, image, CAP_AUTH_ROLE_CORE, &error);
	ATF_REQUIRE_EQ(error, 0);
	refused = counter("security.cap_exclusion.refused_interp");
	run_child(token, exclude_self, NULL, path, -1, argv, &r);
	ATF_CHECK_EQ_MSG(r.exec_errno, EACCES, "exec: %d", r.exec_errno);
	ATF_CHECK_EQ(counter("security.cap_exclusion.refused_interp"),
	    refused + 1);
	close(token);
	close(image);
	xcase_fini(&x);
}

/* X19: the issuer is revoked between install and exec. */
struct x19 {
	int	ready[2];
	int	go[2];
	int	issuer;
	int	token;
};

static int
x19_pre(void *arg)
{
	struct x19 *s = arg;
	char c = 0;

	if (exclude_self(NULL) != 0)
		return (errno);
	/* Drop this process's copies: only then can the parent revoke. */
	close(s->issuer);
	close(s->token);
	if (write(s->ready[1], &c, 1) != 1 || read(s->go[0], &c, 1) != 1)
		return (214);
	return (0);
}

ATF_TC(x19_revoked_issuer_not_excluded);
ATF_TC_HEAD(x19_revoked_issuer_not_excluded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X19: a Core token whose issuer is closed before the exec selects nothing: the new image is not excluded");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x19_revoked_issuer_not_excluded, tc)
{
	char *argv[] = { __DECONST(char *, HELPER),
	    __DECONST(char *, "report"), NULL };
	char helper[PATH_MAX], c;
	struct x19 s;
	unsigned flag2, valid;
	int out[2], status, image, error;
	pid_t pid;

	helper_path(tc, helper, sizeof(helper));
	s.issuer = require_issuer();
	image = open(helper, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	s.token = constrained_token(s.issuer, image, CAP_AUTH_ROLE_CORE,
	    &error);
	ATF_REQUIRE_EQ(error, 0);
	close(image);
	ATF_REQUIRE(pipe(s.ready) == 0 && pipe(s.go) == 0 && pipe(out) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		dup2(out[1], STDOUT_FILENO);
		if (op(CAP_AUTH_INSTALL, s.token, NULL) != 0 ||
		    x19_pre(&s) != 0)
			_exit(120);
		execv(helper, argv);
		_exit(121);
	}
	close(out[1]);
	ATF_REQUIRE(read(s.ready[0], &c, 1) == 1);
	close(s.issuer);
	close(s.token);
	ATF_REQUIRE(write(s.go[1], &c, 1) == 1);
	memset(&flag2, 0, sizeof(flag2));
	{
		char buf[256];
		ssize_t n;
		size_t off = 0;

		while ((n = read(out[0], buf + off, sizeof(buf) - 1 - off)) > 0)
			off += n;
		buf[off] = '\0';
		printf("child: %s", buf);
		ATF_REQUIRE(sscanf(buf, "flag2=%x valid=%u", &flag2,
		    &valid) == 2);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK((flag2 & P2_CAP_EXCLUDED_BIT) == 0);
	ATF_CHECK_EQ(valid, 0);
}

ATF_TC(x21_interpreter_pass_not_excluded);
ATF_TC_HEAD(x21_interpreter_pass_not_excluded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "X21: a Core authority pinning an ELF used as a #! interpreter never excludes the script's run (rule 4); granted unchanged");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(x21_interpreter_pass_not_excluded, tc)
{
	char *const argv[] = { __DECONST(char *, "script"), NULL };
	struct xcase x;
	struct run r;
	char path[PATH_MAX];
	uint64_t granted;
	int token, fd;

	xcase_init(tc, &x);
	ATF_REQUIRE(getcwd(path, sizeof(path)) != NULL);
	strlcat(path, "/interp-script", sizeof(path));
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(dprintf(fd, "#!%s report\n", x.helper) > 0);
	close(fd);
	token = core_token(&x, CAP_AUTH_ROLE_CORE);
	granted = counter("security.cap_exclusion.granted");
	run_child(token, exclude_self, NULL, path, -1, argv, &r);
	expect_report(&r, 0, false, 1);
	ATF_CHECK_EQ(counter("security.cap_exclusion.granted"), granted);
	close(token);
	xcase_fini(&x);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_process_not_excluded);
	ATF_TP_ADD_TC(tp, pid1_exclusion_bit);
	ATF_TP_ADD_TC(tp, core_role_refused);
	ATF_TP_ADD_TC(tp, script_authority_flags0);
	ATF_TP_ADD_TC(tp, clear_then_info);
	ATF_TP_ADD_TC(tp, revoked_pty_fexecve);
	ATF_TP_ADD_TC(tp, forced_unmount_opath);
	ATF_TP_ADD_TC(tp, ischeck_failure_no_leak);
	ATF_TP_ADD_TC(tp, pid1_debug_interfaces);
	ATF_TP_ADD_TC(tp, switchboard_exclusion_bit);
	ATF_TP_ADD_TC(tp, switchboard_debug_interfaces);
	ATF_TP_ADD_TC(tp, x2_x9_fork_and_trace);
	ATF_TP_ADD_TC(tp, x3_exec_without_authority_clears);
	ATF_TP_ADD_TC(tp, x4_core_exec_sets);
	ATF_TP_ADD_TC(tp, x5_x7_other_image_clears);
	ATF_TP_ADD_TC(tp, x6_not_excluded_never_acquires);
	ATF_TP_ADD_TC(tp, x8_pinned_image_text_busy);
	ATF_TP_ADD_TC(tp, x10_x16_traced_or_nnp_clears);
	ATF_TP_ADD_TC(tp, x11_jail_clears);
	ATF_TP_ADD_TC(tp, x13_x14_role_shapes);
	ATF_TP_ADD_TC(tp, x17_core_script_refused);
	ATF_TP_ADD_TC(tp, x19_revoked_issuer_not_excluded);
	ATF_TP_ADD_TC(tp, x21_interpreter_pass_not_excluded);
	return (atf_no_error());
}
