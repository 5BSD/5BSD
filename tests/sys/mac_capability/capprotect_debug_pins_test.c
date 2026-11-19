/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pins of the debug and inspect answers for capprotect-shielded and
 * no-ambient (PD_PROTECTED) processes: ptrace, the kern.proc sysctls,
 * procctl, procdesc and linprocfs callers, the Unix debug rules, the
 * protector and token holders, and what MAC policies and OES are asked.
 *
 * Design: /home/koryheard/5bsd-designs/dtrace-under-shield-minimal.md
 * (section 6).  A case pins what the running kernel answers; the commit
 * that changes an answer changes the pin and says so in its comment.
 *
 * The fixture is capprotect_usdt_helper, driven over a socket; ptrace and
 * the protector role are played by capprotect_protector_helper (the
 * "agent"), a separate process, because capprotect recognises the
 * protector and token holders by PID.  Run in a guest only.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/module.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jail.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"
#include "test_common.h"	/* tests/sys/security/oes */

#define	FIXTURE_NAME	"capprotect_usdt_helper"
#define	AGENT_NAME	"capprotect_protector_helper"

#define	SHIELD_SELF	(CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_SIGKILL)
#define	CANARY_SECRET	0x1122334455667788ULL
#define	CANARY_WRITTEN	0x0badc0de0badc0deULL
#define	CANARY_INITIAL	0x5ec2e75ec2e75ec2ULL	/* capprotect_usdt_helper.c */

/* A fixture process tree driven over one socket. */
struct fx {
	pid_t		pid;	/* the process the test forked or spawned */
	int		sock;	/* the test's end of the control socket */
	uintptr_t	canary;	/* address of the canary in every process */
	pid_t		server;	/* the process now serving commands */
};

/* A capprotect_protector_helper process. */
struct agent {
	pid_t		pid;
	int		sock;
};

static char fixture_path[MAXPATHLEN];
static char agent_path[MAXPATHLEN];

static void
paths_init(const atf_tc_t *tc)
{
	const char *srcdir;

	srcdir = atf_tc_get_config_var(tc, "srcdir");
	snprintf(fixture_path, sizeof(fixture_path), "%s/%s", srcdir,
	    FIXTURE_NAME);
	snprintf(agent_path, sizeof(agent_path), "%s/%s", srcdir, AGENT_NAME);
	ATF_REQUIRE_MSG(access(fixture_path, X_OK) == 0, "%s: %s",
	    fixture_path, strerror(errno));
	ATF_REQUIRE_MSG(access(agent_path, X_OK) == 0, "%s: %s", agent_path,
	    strerror(errno));
}

static void __printflike(2, 3)
send_line(int s, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	ATF_REQUIRE(n > 0 && (size_t)n < sizeof(buf) - 1);
	buf[n++] = '\n';
	ATF_REQUIRE_MSG(send(s, buf, n, MSG_NOSIGNAL) == n, "send: %s",
	    strerror(errno));
}

/* Send a command line with a descriptor attached. */
static void
send_line_fd(int s, const char *line, int fd)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char buf[128];
	int n;

	n = snprintf(buf, sizeof(buf), "%s\n", line);
	iov.iov_base = buf;
	iov.iov_len = n;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(&control, 0, sizeof(control));
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	ATF_REQUIRE(sendmsg(s, &msg, 0) == n);
}

/*
 * Receive one reply line; a descriptor that arrives with it is stored in
 * *fdp when fdp is not NULL.  Fails the case on end of file.
 */
static void
recv_line(int s, char *buf, size_t len, int *fdp)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	size_t n;
	ssize_t r;
	char c;

	if (fdp != NULL)
		*fdp = -1;
	for (n = 0;;) {
		iov.iov_base = &c;
		iov.iov_len = 1;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);
		r = recvmsg(s, &msg, 0);
		if (r < 0 && errno == EINTR)
			continue;
		ATF_REQUIRE_MSG(r == 1, "control socket closed after \"%.*s\"",
		    (int)n, buf);
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS) {
				ATF_REQUIRE(fdp != NULL);
				memcpy(fdp, CMSG_DATA(cmsg), sizeof(int));
			}
		}
		if (c == '\n')
			break;
		if (n + 1 < len)
			buf[n++] = c;
	}
	buf[n] = '\0';
}

/* Receive a line that starts with tag; return the rest. */
static void
expect_line(int s, const char *tag, char *rest, size_t len)
{
	char buf[256];
	size_t tl;

	recv_line(s, buf, sizeof(buf), NULL);
	tl = strlen(tag);
	ATF_REQUIRE_MSG(strncmp(buf, tag, tl) == 0 &&
	    (buf[tl] == ' ' || buf[tl] == '\0'),
	    "expected \"%s ...\", got \"%s\"", tag, buf);
	strlcpy(rest, buf[tl] == ' ' ? buf + tl + 1 : "", len);
}

static void
parse_ready(struct fx *f, const char *line)
{
	unsigned long long addr, value;
	int pid;

	ATF_REQUIRE_MSG(sscanf(line, "pid=%d canary=%llx value=%llx", &pid,
	    &addr, &value) == 3, "bad READY line \"%s\"", line);
	f->server = pid;
	f->canary = (uintptr_t)addr;
}

/*
 * Fork and exec the fixture in mode.  uid, when not -1, is the identity
 * the fixture runs as.  pdfork with pdflags when pdp is not NULL.
 */
static void
fixture_start_as(struct fx *f, const char *mode, uid_t uid, int *pdp,
    int pdflags)
{
	char rest[256];
	int sv[2];
	pid_t pid;

	memset(f, 0, sizeof(*f));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = pdp != NULL ? pdfork(pdp, pdflags) : fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(sv[0]);
		if (dup2(sv[1], STDIN_FILENO) < 0 ||
		    dup2(sv[1], STDOUT_FILENO) < 0)
			_exit(120);
		closefrom(3);
		if (uid != (uid_t)-1 && (setgroups(1, &uid) != 0 ||
		    setgid(uid) != 0 || setuid(uid) != 0))
			_exit(121);
		execl(fixture_path, fixture_path, mode, (char *)NULL);
		_exit(122);
	}
	close(sv[1]);
	f->pid = pid;
	f->sock = sv[0];
	expect_line(f->sock, "READY", rest, sizeof(rest));
	parse_ready(f, rest);
	ATF_REQUIRE_EQ(f->server, pid);
}

static void
fixture_start(struct fx *f, const char *mode)
{

	fixture_start_as(f, mode, (uid_t)-1, NULL, 0);
}

/*
 * Close the control socket, so every fixture process exits, and reap the
 * process the test started.  Returns its wait status.
 */
static int
fixture_stop(struct fx *f)
{
	int status;

	close(f->sock);
	f->sock = -1;
	status = 0;
	if (f->pid > 0) {
		while (waitpid(f->pid, &status, 0) < 0)
			ATF_REQUIRE(errno == EINTR);
	}
	f->pid = 0;
	return (status);
}

static uint64_t
fixture_canary(struct fx *f)
{
	char rest[64];

	send_line(f->sock, "canary");
	expect_line(f->sock, "CANARY", rest, sizeof(rest));
	return (strtoull(rest, NULL, 16));
}

static void
fixture_set(struct fx *f, uint64_t v)
{
	char rest[64];

	send_line(f->sock, "set %" PRIx64, v);
	expect_line(f->sock, "SET", rest, sizeof(rest));
}

static void
agent_start(struct agent *a, int fixture_end)
{
	int sv[2];
	pid_t pid;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(sv[0]);
		if (dup2(sv[1], STDIN_FILENO) < 0 ||
		    dup2(sv[1], STDOUT_FILENO) < 0)
			_exit(120);
		if (fixture_end >= 0 && (dup2(fixture_end, 3) < 0 ||
		    dup2(fixture_end, 4) < 0))
			_exit(121);
		closefrom(fixture_end >= 0 ? 5 : 3);
		execl(agent_path, AGENT_NAME, fixture_path, (char *)NULL);
		_exit(122);
	}
	close(sv[1]);
	a->pid = pid;
	a->sock = sv[0];
}

static int
agent_stop(struct agent *a)
{
	int status;

	close(a->sock);
	status = 0;
	while (waitpid(a->pid, &status, 0) < 0)
		ATF_REQUIRE(errno == EINTR);
	return (status);
}

/* Run an agent command; return the errno it reports, and *valp if any. */
static int __printflike(4, 5)
agent_do(struct agent *a, const char *tag, uint64_t *valp, const char *fmt,
    ...)
{
	char buf[256], rest[128];
	unsigned long long v;
	va_list ap;
	int error;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	send_line(a->sock, "%s", buf);
	expect_line(a->sock, tag, rest, sizeof(rest));
	v = 0;
	ATF_REQUIRE(sscanf(rest, "%d %llx", &error, &v) >= 1);
	if (valp != NULL)
		*valp = v;
	return (error);
}

static int
agent_attach(struct agent *a, pid_t pid)
{

	return (agent_do(a, "ATTACH", NULL, "attach %d", (int)pid));
}

static int
agent_read(struct agent *a, pid_t pid, uintptr_t addr, uint64_t *valp)
{

	return (agent_do(a, "READ", valp, "read %d %jx", (int)pid,
	    (uintmax_t)addr));
}

static int
agent_write(struct agent *a, pid_t pid, uintptr_t addr, uint64_t v)
{

	return (agent_do(a, "WRITE", NULL, "write %d %jx %" PRIx64, (int)pid,
	    (uintmax_t)addr, v));
}

static int
agent_detach(struct agent *a, pid_t pid)
{

	return (agent_do(a, "DETACH", NULL, "detach %d", (int)pid));
}

/*
 * The agent spawns the fixture in mode, with pdflags and protection flags;
 * the fixture's control socket is handed back in *f.
 */
static void
agent_spawn(struct agent *a, struct fx *f, int pdflags, uint32_t protect,
    const char *mode)
{
	char rest[256];
	int sv[2], pid, error;

	memset(f, 0, sizeof(*f));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	agent_start(a, sv[1]);
	close(sv[1]);
	send_line(a->sock, "spawn %x %x %s", pdflags, protect, mode);
	expect_line(a->sock, "SPAWNED", rest, sizeof(rest));
	ATF_REQUIRE(sscanf(rest, "%d %d", &pid, &error) == 2);
	ATF_REQUIRE_MSG(pid > 0 && error == 0, "spawn: pid %d error %d", pid,
	    error);
	f->sock = sv[0];
	f->pid = 0;	/* the agent's child, reaped by the agent */
	expect_line(f->sock, "READY", rest, sizeof(rest));
	parse_ready(f, rest);
	ATF_REQUIRE_EQ(f->server, pid);
	f->pid = 0;
}

/*
 * The full debug probe a prober runs against a target: attach, read the
 * canary, write it, detach.  Returns the attach errno; a successful attach
 * also checks the read and the write.
 */
static int
probe_rw(struct agent *a, pid_t target, uintptr_t canary, uint64_t expect,
    uint64_t newval)
{
	uint64_t v;
	int error;

	error = agent_attach(a, target);
	if (error != 0)
		return (error);
	ATF_CHECK_EQ(agent_read(a, target, canary, &v), 0);
	ATF_CHECK_EQ_MSG(v, expect, "read %#jx, expected %#jx", (uintmax_t)v,
	    (uintmax_t)expect);
	ATF_CHECK_EQ(agent_write(a, target, canary, newval), 0);
	ATF_CHECK_EQ(agent_detach(a, target), 0);
	return (0);
}

static int
sysctl_proc(int what, pid_t pid)
{
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = what;
	mib[3] = pid;
	len = 0;
	return (sysctl(mib, 4, NULL, &len, NULL, 0) == 0 ? 0 : errno);
}

/* The debug errno of mode, through PT_ATTACH by a foreign agent. */
ATF_TC(pin_ptrace_attach);
ATF_TC_HEAD(pin_ptrace_attach, tc)
{
	atf_tc_set_md_var(tc, "descr", "PT_ATTACH by a foreign process: "
	    "plain 0, self-shielded EACCES, protected EACCES, PD_PROTECTED "
	    "EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_ptrace_attach, tc)
{
	struct agent prober, launcher;
	struct fx f;

	paths_init(tc);
	agent_start(&prober, -1);

	fixture_start(&f, "plain");
	ATF_CHECK_EQ(probe_rw(&prober, f.pid, f.canary, CANARY_INITIAL,
	    CANARY_INITIAL), 0);
	fixture_stop(&f);

	fixture_start(&f, "self");
	ATF_CHECK_EQ(agent_attach(&prober, f.pid), EACCES);
	fixture_stop(&f);

	agent_spawn(&launcher, &f, 0, CP_SF_PTRACE, "plain");
	ATF_CHECK_EQ(agent_attach(&prober, f.server), EACCES);
	fixture_stop(&f);
	agent_stop(&launcher);

	agent_spawn(&launcher, &f, PD_PROTECTED, 0, "plain");
	ATF_CHECK_EQ(agent_attach(&prober, f.server), EPERM);
	fixture_stop(&f);
	agent_stop(&launcher);

	agent_stop(&prober);
}

ATF_TC(pin_ptrace_trace_me);
ATF_TC_HEAD(pin_ptrace_trace_me, tc)
{
	atf_tc_set_md_var(tc, "descr", "PT_TRACE_ME in a PD_PROTECTED child "
	    "is refused with EPERM");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_ptrace_trace_me, tc)
{
	int pd, status;
	pid_t pid;

	pid = pdfork(&pd, PD_PROTECTED);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(ptrace(PT_TRACE_ME, 0, NULL, 0) == 0 ? 0 :
		    errno == EPERM ? 1 : 2);
	ATF_REQUIRE(pdwait(pd, &status, WEXITED, NULL, NULL) == 0);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	    "status %#x (exit 1 is EPERM)", status);
	close(pd);
}

/*
 * The debug-class callers that stay under p_candebug.  probe returns the
 * errno a root caller gets for pid.
 */
typedef int (*probe_fn)(pid_t pid);

static int
probe_env(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_ENV, pid));
}

static int
probe_filedesc(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_FILEDESC, pid));
}

static int
probe_cwd(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_CWD, pid));
}

static int
probe_kqueue(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_KQUEUE, pid));
}

static int
probe_kcmp(pid_t pid)
{
	return (kcmp(pid, getpid(), KCMP_VM, 0, 0) >= 0 ? 0 : errno);
}

static int
probe_procctl_setter(pid_t pid)
{
	int arg = PROC_ASLR_NOFORCE;

	return (procctl(P_PID, pid, PROC_ASLR_CTL, &arg) == 0 ? 0 : errno);
}

static int
probe_pdopenpid(pid_t pid)
{
	int fd;

	fd = pdopenpid(pid, 0);
	if (fd < 0)
		return (errno);
	close(fd);
	return (0);
}

static int
probe_pddupfd(pid_t pid)
{
	int pd, fd, error;

	/* pdopenpid itself needs p_candebug; open the descriptor as the parent. */
	pd = pdopenpid(pid, 0);
	if (pd < 0)
		return (errno);
	fd = pddupfd(pd, 0, 0);
	error = fd < 0 ? errno : 0;
	if (fd >= 0)
		close(fd);
	close(pd);
	return (error);
}

/* The inspect-class callers (they move to p_caninspect with S1d). */
static int
probe_vmmap(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_VMMAP, pid));
}

static int
probe_vm_layout(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_VM_LAYOUT, pid));
}

static int
probe_auxv(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_AUXV, pid));
}

static int
probe_ps_strings(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_PS_STRINGS, pid));
}

static int
probe_sigtramp(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_SIGTRAMP, pid));
}

static int
probe_sigfastblk(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_SIGFASTBLK, pid));
}

static int
probe_umask(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_UMASK, pid));
}

static int
probe_kstack(pid_t pid)
{
	return (sysctl_proc(KERN_PROC_KSTACK, pid));
}

/*
 * Run probe as root against a plain fixture, a self-shielded one and a
 * PD_PROTECTED one, and check the three errnos.
 */
static void
pin_probe(const atf_tc_t *tc, const char *name, probe_fn probe, int plain,
    int shielded, int noambient)
{
	struct agent launcher;
	struct fx f;
	int error;

	paths_init(tc);
	fixture_start(&f, "plain");
	error = probe(f.pid);
	ATF_CHECK_EQ_MSG(error, plain, "%s of a plain process: %d, "
	    "expected %d", name, error, plain);
	fixture_stop(&f);

	fixture_start(&f, "self");
	error = probe(f.pid);
	ATF_CHECK_EQ_MSG(error, shielded, "%s of a shielded process: %d, "
	    "expected %d", name, error, shielded);
	fixture_stop(&f);

	agent_spawn(&launcher, &f, PD_PROTECTED, 0, "plain");
	error = probe(f.server);
	ATF_CHECK_EQ_MSG(error, noambient, "%s of a PD_PROTECTED process: "
	    "%d, expected %d", name, error, noambient);
	fixture_stop(&f);
	agent_stop(&launcher);
}

#define	PIN_PROBE(tcname, fn, plain, shielded, noambient, what)		\
ATF_TC(tcname);								\
ATF_TC_HEAD(tcname, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", what);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "timeout", "120");			\
}									\
ATF_TC_BODY(tcname, tc)							\
{									\
	pin_probe(tc, #fn, fn, plain, shielded, noambient);		\
}

/* Debug class: unchanged by the inspect/debug split. */
PIN_PROBE(pin_sysctl_env, probe_env, 0, EACCES, EPERM,
    "kern.proc.env stays debug-class")
PIN_PROBE(pin_sysctl_filedesc, probe_filedesc, 0, EACCES, EPERM,
    "kern.proc.filedesc stays debug-class")
PIN_PROBE(pin_sysctl_cwd, probe_cwd, 0, EACCES, EPERM,
    "kern.proc.cwd stays debug-class")
PIN_PROBE(pin_sysctl_kqueue, probe_kqueue, 0, EACCES, EPERM,
    "kern.proc.kqueue stays debug-class (it exports udata)")
PIN_PROBE(pin_kcmp, probe_kcmp, 0, EACCES, EPERM,
    "kcmp(2) stays debug-class")
PIN_PROBE(pin_procctl_setters, probe_procctl_setter, 0, EACCES, EPERM,
    "procctl(2) setters stay debug-class")
PIN_PROBE(pin_pdopenpid, probe_pdopenpid, 0, EACCES, EPERM,
    "pdopenpid(2) stays debug-class")
PIN_PROBE(pin_pddupfd, probe_pddupfd, 0, EACCES, EPERM,
    "pddupfd(2) stays debug-class")

/*
 * Inspect class (p_caninspect(9)): the shield and no-ambient refuse debug,
 * not inspect.  They were EACCES and EPERM while these callers asked the
 * debug question.
 */
PIN_PROBE(pin_sysctl_vmmap, probe_vmmap, 0, 0, 0,
    "kern.proc.vmmap of protected processes")
PIN_PROBE(pin_sysctl_vm_layout, probe_vm_layout, 0, 0, 0,
    "kern.proc.vm_layout of protected processes")
PIN_PROBE(pin_sysctl_auxv, probe_auxv, 0, 0, 0,
    "kern.proc.auxv of protected processes")
PIN_PROBE(pin_sysctl_ps_strings, probe_ps_strings, 0, 0, 0,
    "kern.proc.ps_strings of protected processes")
PIN_PROBE(pin_sysctl_sigtramp, probe_sigtramp, 0, 0, 0,
    "kern.proc.sigtramp of protected processes")
PIN_PROBE(pin_sysctl_sigfastblk, probe_sigfastblk, 0, 0, 0,
    "kern.proc.sigfastblk of protected processes")
PIN_PROBE(pin_sysctl_umask, probe_umask, 0, 0, 0,
    "kern.proc.umask of protected processes")
PIN_PROBE(pin_sysctl_kstack, probe_kstack, 0, 0, 0,
    "kern.proc.kstack of protected processes")

/* linprocfs, when it is mounted at /compat/linux/proc. */
static bool
linprocfs_path(char *buf, size_t len, pid_t pid, const char *file)
{
	struct stat st;

	if (stat("/compat/linux/proc/self", &st) != 0)
		return (false);
	snprintf(buf, len, "/compat/linux/proc/%d/%s", (int)pid, file);
	return (true);
}

static int
linprocfs_read(pid_t pid, const char *file)
{
	char path[MAXPATHLEN], buf[64];
	int fd, error;

	if (!linprocfs_path(path, sizeof(path), pid, file))
		return (-1);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);
	error = read(fd, buf, sizeof(buf)) < 0 ? errno : 0;
	close(fd);
	return (error);
}

static void
linprocfs_case(const atf_tc_t *tc, const char *const *files,
    const int *expect)
{
	char path[MAXPATHLEN];
	struct fx f;
	int error;

	if (!linprocfs_path(path, sizeof(path), getpid(), "maps"))
		atf_tc_skip("linprocfs is not mounted at /compat/linux/proc");
	paths_init(tc);
	fixture_start(&f, "self");
	for (; *files != NULL; files++, expect++) {
		error = linprocfs_read(f.pid, *files);
		ATF_CHECK_EQ_MSG(error, *expect, "linprocfs %s: %d, expected %d",
		    *files, error, *expect);
	}
	fixture_stop(&f);
}

ATF_TC(pin_linprocfs_mem_environ_fd);
ATF_TC_HEAD(pin_linprocfs_mem_environ_fd, tc)
{
	atf_tc_set_md_var(tc, "descr", "linprocfs mem, environ and fd of a "
	    "shielded process stay debug-class");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_linprocfs_mem_environ_fd, tc)
{
	static const char *const files[] = { "mem", "environ", "fd", NULL };
	static const int expect[] = { ENOENT, ENOENT, ENOENT };

	/* Debug class: the files are hidden from a caller that may not debug. */
	linprocfs_case(tc, files, expect);
}

ATF_TC(pin_linprocfs_maps_auxv);
ATF_TC_HEAD(pin_linprocfs_maps_auxv, tc)
{
	atf_tc_set_md_var(tc, "descr", "linprocfs maps and auxv of a "
	    "shielded process");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_linprocfs_maps_auxv, tc)
{
	static const char *const files[] = { "maps", "auxv", NULL };
	static const int expect[] = { 0, 0 };

	/*
	 * Inspect class: readable.  As debug checks, maps was EACCES and
	 * auxv hidden (ENOENT).
	 */
	linprocfs_case(tc, files, expect);
}

/*
 * The Unix rules of p_candebug, through kern.proc.vmmap: they stay the same
 * for inspect (design section 2.5).  Each prober is a forked child; it
 * exits with the errno it got.
 */
static int
vmmap_as(uid_t uid, pid_t target)
{
	int status;
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (uid != (uid_t)-1 && (setgroups(1, &uid) != 0 ||
		    setgid(uid) != 0 || setuid(uid) != 0))
			_exit(250);
		_exit(probe_vmmap(target));
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC(pin_inspect_unix_rules);
ATF_TC_HEAD(pin_inspect_unix_rules, tc)
{
	atf_tc_set_md_var(tc, "descr", "The Unix debug rules (another uid, "
	    "P_SUGID, PROC_TRACE_CTL_DISABLE, a jail) answer the same "
	    "errnos for kern.proc.vmmap");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inspect_unix_rules, tc)
{
	struct fx f;
	int gate[2], arg, jid, status;
	pid_t pid;
	char c;

	paths_init(tc);

	/* Another uid, without privilege. */
	fixture_start_as(&f, "plain", 65533, NULL, 0);
	ATF_CHECK_EQ(vmmap_as(65534, f.pid), EPERM);
	ATF_CHECK_EQ(vmmap_as(65533, f.pid), 0);
	ATF_CHECK_EQ(vmmap_as((uid_t)-1, f.pid), 0);
	fixture_stop(&f);

	/* P_SUGID: the target changed its credentials and did not exec. */
	ATF_REQUIRE(pipe(gate) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(gate[1]);
		gid_t g = 65533;

		if (setgroups(1, &g) != 0 || setgid(g) != 0 || setuid(65533) != 0)
			_exit(1);
		(void)read(gate[0], &c, 1);
		_exit(0);
	}
	close(gate[0]);
	ATF_CHECK_EQ(vmmap_as(65533, pid), EPERM);
	ATF_CHECK_EQ(vmmap_as((uid_t)-1, pid), 0);
	close(gate[1]);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	/* PROC_TRACE_CTL_DISABLE: root keeps PRIV_DEBUG_DENIED. */
	fixture_start_as(&f, "plain", 65533, NULL, 0);
	ATF_CHECK_EQ(vmmap_as(65533, f.pid), 0);
	arg = PROC_TRACE_CTL_DISABLE;
	ATF_REQUIRE(procctl(P_PID, f.pid, PROC_TRACE_CTL, &arg) == 0);
	ATF_CHECK_EQ(vmmap_as(65533, f.pid), EPERM);
	ATF_CHECK_EQ(vmmap_as((uid_t)-1, f.pid), 0);
	fixture_stop(&f);

	/* A jailed root cannot reach a process outside its jail. */
	fixture_start(&f, "plain");
	jid = jail_setv(JAIL_CREATE, "name", "capprotect_pins", "path", "/",
	    "persist", NULL, NULL);
	ATF_REQUIRE_MSG(jid > 0, "jail_setv: %s", jail_errmsg);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (jail_attach(jid) != 0)
			_exit(250);
		_exit(probe_vmmap(f.pid));
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == ESRCH,
	    "jailed vmmap status %#x", status);
	(void)jail_remove(jid);
	fixture_stop(&f);
}

ATF_TC(pin_protector_passes);
ATF_TC_HEAD(pin_protector_passes, tc)
{
	atf_tc_set_md_var(tc, "descr", "The protector of a CP_OP_PROTECT "
	    "target attaches, reads its memory and maps it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_protector_passes, tc)
{
	struct agent protector;
	struct fx f;

	paths_init(tc);
	agent_spawn(&protector, &f, 0, CP_SF_PTRACE, "plain");
	fixture_set(&f, CANARY_SECRET);
	ATF_CHECK_EQ(probe_rw(&protector, f.server, f.canary, CANARY_SECRET,
	    CANARY_WRITTEN), 0);
	ATF_CHECK_EQ(agent_do(&protector, "VMMAP", NULL, "vmmap %d",
	    (int)f.server), 0);
	ATF_CHECK_EQ(fixture_canary(&f), CANARY_WRITTEN);
	fixture_stop(&f);
	agent_stop(&protector);
}

/* Mint a token with flags from a fixture's shield and give it to agent a. */
static int
give_token(struct fx *f, struct agent *a, uint32_t flags)
{
	char rest[64];
	int token, error;

	send_line(f->sock, "mint %x", flags);
	recv_line(f->sock, rest, sizeof(rest), &token);
	ATF_REQUIRE_MSG(strcmp(rest, "MINT 0") == 0 && token >= 0,
	    "mint: \"%s\"", rest);
	send_line_fd(a->sock, "authorize", token);
	close(token);
	expect_line(a->sock, "AUTHORIZE", rest, sizeof(rest));
	error = atoi(rest);
	return (error);
}

ATF_TC(pin_token_passes);
ATF_TC_HEAD(pin_token_passes, tc)
{
	atf_tc_set_md_var(tc, "descr", "An activated CP_SF_PTRACE token "
	    "attaches a self-shielded process; a process without one does not");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_token_passes, tc)
{
	struct agent holder, other;
	struct fx f;

	paths_init(tc);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	agent_start(&holder, -1);
	agent_start(&other, -1);
	ATF_REQUIRE_EQ(give_token(&f, &holder, CP_SF_PTRACE), 0);
	ATF_CHECK_EQ(probe_rw(&holder, f.pid, f.canary, CANARY_SECRET,
	    CANARY_SECRET), 0);
	ATF_CHECK_EQ(agent_attach(&other, f.pid), EACCES);
	agent_stop(&other);
	agent_stop(&holder);
	fixture_stop(&f);
}

ATF_TC(pin_ptrace_token_inspects);
ATF_TC_HEAD(pin_ptrace_token_inspects, tc)
{
	atf_tc_set_md_var(tc, "descr", "Debug implies inspect: a CP_SF_PTRACE "
	    "token holder that may attach may also map the process");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_ptrace_token_inspects, tc)
{
	struct agent holder;
	struct fx f;

	paths_init(tc);
	fixture_start(&f, "self");
	agent_start(&holder, -1);
	ATF_REQUIRE_EQ(give_token(&f, &holder, CP_SF_PTRACE), 0);
	ATF_CHECK_EQ(agent_attach(&holder, f.pid), 0);
	ATF_CHECK_EQ(agent_detach(&holder, f.pid), 0);
	ATF_CHECK_EQ(agent_do(&holder, "VMMAP", NULL, "vmmap %d", f.pid), 0);
	agent_stop(&holder);
	fixture_stop(&f);
}

static unsigned int
mac_test_counter(const char *name)
{
	char oid[128];
	unsigned int v;
	size_t len;

	snprintf(oid, sizeof(oid), "security.mac.test.counter.%s", name);
	len = sizeof(v);
	ATF_REQUIRE_MSG(sysctlbyname(oid, &v, &len, NULL, 0) == 0, "%s: %s",
	    oid, strerror(errno));
	return (v);
}

ATF_TC(pin_mac_test_counters);
ATF_TC_HEAD(pin_mac_test_counters, tc)
{
	atf_tc_set_md_var(tc, "descr", "kern.proc.vmmap of another process "
	    "asks the MAC policies their inspect question");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_mac_test_counters, tc)
{
	struct fx f;
	unsigned int before, after, debug;

	if (modfind("mac_test") < 0)
		atf_tc_skip("mac_test is not loaded (LOADER_EXTRA="
		    "mac_test_load=YES)");
	paths_init(tc);
	fixture_start(&f, "plain");
	/* kern.proc.vmmap asks proc_check_inspect, not proc_check_debug. */
	before = mac_test_counter("proc_check_inspect");
	debug = mac_test_counter("proc_check_debug");
	ATF_REQUIRE_EQ(probe_vmmap(f.pid), 0);
	after = mac_test_counter("proc_check_inspect");
	ATF_CHECK_MSG(after > before, "proc_check_inspect %u -> %u", before,
	    after);
	ATF_CHECK_EQ(mac_test_counter("proc_check_debug"), debug);
	fixture_stop(&f);
}

ATF_TC(pin_oes_notify_ptrace);
ATF_TC_HEAD(pin_oes_notify_ptrace, tc)
{
	atf_tc_set_md_var(tc, "descr", "PT_ATTACH by another process produces "
	    "an OES NOTIFY_PTRACE event; kern.proc.vmmap produces none");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_oes_notify_ptrace, tc)
{
	struct oes_subscribe_args sargs;
	struct oes_mode_args margs;
	oes_event_type_t event = OES_EVENT_NOTIFY_PTRACE;
	test_msg_buf buf;
	struct agent prober;
	struct fx f;
	int oes;

	oes = test_open_oes();
	if (oes < 0)
		atf_tc_skip("%s: %s", OES_DEVICE_PATH, strerror(errno));
	paths_init(tc);
	memset(&margs, 0, sizeof(margs));
	margs.ema_mode = OES_MODE_NOTIFY;
	ATF_REQUIRE(ioctl(oes, OES_IOC_SET_MODE, &margs) == 0);
	memset(&sargs, 0, sizeof(sargs));
	sargs.esa_events = &event;
	sargs.esa_count = 1;
	sargs.esa_flags = OES_SUB_REPLACE;
	ATF_REQUIRE(ioctl(oes, OES_IOC_SUBSCRIBE, &sargs) == 0);
	ATF_REQUIRE(test_mute_self(oes) == 0);

	fixture_start(&f, "plain");
	agent_start(&prober, -1);
	test_drain_events(oes);
	/*
	 * The vmmap is an inspect check, and OES reports nothing for it (Q4).
	 * It was reported as NOTIFY_PTRACE while it was a debug check.
	 */
	ATF_REQUIRE_EQ(agent_do(&prober, "VMMAP", NULL, "vmmap %d", f.pid), 0);
	ATF_CHECK_EQ(test_wait_event_pid(oes, prober.pid,
	    OES_EVENT_NOTIFY_PTRACE, 2000, &buf.msg), ETIMEDOUT);
	test_drain_events(oes);
	ATF_REQUIRE_EQ(agent_attach(&prober, f.pid), 0);
	ATF_CHECK_EQ(test_wait_event_pid(oes, prober.pid,
	    OES_EVENT_NOTIFY_PTRACE, 5000, &buf.msg), 0);
	ATF_CHECK_EQ(agent_detach(&prober, f.pid), 0);
	agent_stop(&prober);
	fixture_stop(&f);
	close(oes);
}

ATF_TC(pin_veriexec_notrace_inspect);
ATF_TC_HEAD(pin_veriexec_notrace_inspect, tc)
{
	atf_tc_set_md_var(tc, "descr", "Veriexec NOTRACE images stay "
	    "uninspectable through the debug fallback");
}
ATF_TC_BODY(pin_veriexec_notrace_inspect, tc)
{

	atf_tc_skip("no Veriexec-enforcing guest tier exists (vm-provider.sh "
	    "has none); the fallback is argued from source");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pin_ptrace_attach);
	ATF_TP_ADD_TC(tp, pin_ptrace_trace_me);
	ATF_TP_ADD_TC(tp, pin_sysctl_env);
	ATF_TP_ADD_TC(tp, pin_sysctl_filedesc);
	ATF_TP_ADD_TC(tp, pin_sysctl_cwd);
	ATF_TP_ADD_TC(tp, pin_sysctl_kqueue);
	ATF_TP_ADD_TC(tp, pin_kcmp);
	ATF_TP_ADD_TC(tp, pin_procctl_setters);
	ATF_TP_ADD_TC(tp, pin_pdopenpid);
	ATF_TP_ADD_TC(tp, pin_pddupfd);
	ATF_TP_ADD_TC(tp, pin_sysctl_vmmap);
	ATF_TP_ADD_TC(tp, pin_sysctl_vm_layout);
	ATF_TP_ADD_TC(tp, pin_sysctl_auxv);
	ATF_TP_ADD_TC(tp, pin_sysctl_ps_strings);
	ATF_TP_ADD_TC(tp, pin_sysctl_sigtramp);
	ATF_TP_ADD_TC(tp, pin_sysctl_sigfastblk);
	ATF_TP_ADD_TC(tp, pin_sysctl_umask);
	ATF_TP_ADD_TC(tp, pin_sysctl_kstack);
	ATF_TP_ADD_TC(tp, pin_linprocfs_mem_environ_fd);
	ATF_TP_ADD_TC(tp, pin_linprocfs_maps_auxv);
	ATF_TP_ADD_TC(tp, pin_inspect_unix_rules);
	ATF_TP_ADD_TC(tp, pin_protector_passes);
	ATF_TP_ADD_TC(tp, pin_token_passes);
	ATF_TP_ADD_TC(tp, pin_ptrace_token_inspects);
	ATF_TP_ADD_TC(tp, pin_mac_test_counters);
	ATF_TP_ADD_TC(tp, pin_oes_notify_ptrace);
	ATF_TP_ADD_TC(tp, pin_veriexec_notrace_inspect);

	return (atf_no_error());
}
