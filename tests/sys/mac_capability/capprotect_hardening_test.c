/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Pins of the capprotect shield's gaps against debuggers:
 *
 *   - a child that shares a shielded process's memory (vfork, RFMEM,
 *     posix_spawn) is debuggable, and through it the shielded memory;
 *   - a fork or unshare copy of a shielded process's memory is debuggable
 *     until it execs;
 *   - shielding a process that a debugger already traces leaves the tracer
 *     attached.
 *
 * Design: /home/koryheard/5bsd-designs/shield-hardening.md (section 4).  A
 * case pins what the running kernel answers; the commit that changes an
 * answer changes the pin and says so in its comment.
 *
 * The fixture is capprotect_share_helper, driven over a socket; ptrace and
 * the protector role are played by capprotect_protector_helper (the
 * "agent"), a separate process, because capprotect recognises the
 * protector and token holders by PID.  Run in a guest only.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
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

#define	FIXTURE_NAME	"capprotect_share_helper"
#define	AGENT_NAME	"capprotect_protector_helper"

#define	SHIELD_SELF	(CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_SIGKILL)
#define	CANARY_SECRET	0x1122334455667788ULL
#define	CANARY_WRITTEN	0x0badc0de0badc0deULL
#define	CANARY_INITIAL	0x5ec2e75ec2e75ec2ULL	/* capprotect_share_helper.c */

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
		if (uid != (uid_t)-1 && (setgid(uid) != 0 || setuid(uid) != 0))
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

/* Split the fixture (vfork, rfmem, fork, unshare); return the child. */
static pid_t
fixture_split(struct fx *f, const char *how)
{
	char rest[64];
	int pid;

	send_line(f->sock, "%s", how);
	expect_line(f->sock, "CHILD", rest, sizeof(rest));
	pid = atoi(rest);
	ATF_REQUIRE_MSG(pid > 0, "%s failed: %s", how, rest);
	f->server = pid;
	return (pid);
}

/* End the serving child; return the canary the resumed parent reports. */
static uint64_t
fixture_join(struct fx *f, pid_t child)
{
	unsigned long long canary;
	char rest[128];
	int pid, status;

	send_line(f->sock, "exit");
	expect_line(f->sock, "RESUMED", rest, sizeof(rest));
	ATF_REQUIRE(sscanf(rest, "child=%d status=%d canary=%llx", &pid,
	    &status, &canary) == 3);
	ATF_REQUIRE_EQ(pid, child);
	f->server = f->pid;
	return (canary);
}

static int
fixture_shield(struct fx *f, uint32_t flags)
{
	char rest[64];

	send_line(f->sock, "shield %x", flags);
	expect_line(f->sock, "SHIELD", rest, sizeof(rest));
	return (atoi(rest));
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

/* The fixture's SPAWNED line, once posix_spawn has returned. */
static const char *
spawn_reply(int sock)
{
	static char buf[256];

	recv_line(sock, buf, sizeof(buf), NULL);
	return (buf);
}

/*
 * Open the FIFO that the posix_spawn child opens as its file action, as
 * its writer.  Fails the test, with the child's state, if the child does
 * not open it within ten seconds, instead of blocking for ever.
 */
static int
fifo_writer(const char *fifo, pid_t child, int sock)
{
	struct kinfo_proc kp;
	size_t len;
	int fd, mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

	for (int tries = 0; tries < 100; tries++) {
		fd = open(fifo, O_WRONLY | O_NONBLOCK);
		if (fd >= 0)
			return (fd);
		ATF_REQUIRE_MSG(errno == ENXIO, "open %s: %s", fifo,
		    strerror(errno));
		usleep(100000);
	}
	mib[3] = child;
	len = sizeof(kp);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0)
		atf_tc_fail("the posix_spawn child %d is gone: %s", (int)child,
		    spawn_reply(sock));
	atf_tc_fail("the posix_spawn child %d never opened the FIFO: "
	    "stat %d flags %#x wmesg %s", (int)child, (int)kp.ki_stat,
	    (unsigned)kp.ki_flag, kp.ki_wmesg);
}

/*
 * The posix_spawn child sleeps in the open of the FIFO.  A PT_ATTACH that
 * reaches it before that sleep leaves a SIGSTOP that interrupts the open
 * (EINTR), and posix_spawn fails; wait for the sleep first.
 */
static void
wait_fifo_open(pid_t child, int sock)
{
	struct kinfo_proc kp;
	size_t len;
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

	mib[3] = child;
	for (int tries = 0; tries < 200; tries++) {
		len = sizeof(kp);
		if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0)
			atf_tc_fail("the posix_spawn child %d is gone: %s",
			    (int)child, spawn_reply(sock));
		if (kp.ki_stat == SSLEEP && strcmp(kp.ki_wmesg, "fifoor") == 0)
			return;
		usleep(50000);
	}
	atf_tc_fail("the posix_spawn child %d did not sleep in the FIFO "
	    "open: stat %d wmesg %s", (int)child, (int)kp.ki_stat, kp.ki_wmesg);
}

/* The child of parent, found through kern.proc (a posix_spawn child). */
static pid_t
child_of(pid_t parent)
{
	struct kinfo_proc *kp;
	size_t len;
	pid_t child;
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };

	for (int tries = 0; tries < 100; tries++) {
		len = 0;
		ATF_REQUIRE(sysctl(mib, 3, NULL, &len, NULL, 0) == 0);
		len += len / 4;
		kp = malloc(len);
		ATF_REQUIRE(kp != NULL);
		ATF_REQUIRE(sysctl(mib, 3, kp, &len, NULL, 0) == 0);
		child = 0;
		for (size_t i = 0; i < len / sizeof(*kp); i++) {
			if (kp[i].ki_ppid == parent)
				child = kp[i].ki_pid;
		}
		free(kp);
		if (child != 0)
			return (child);
		usleep(50000);
	}
	atf_tc_fail("no child of %d appeared", (int)parent);
}

/*
 * The vfork and RFMEM child of a shielded process shares its vmspace.
 * Today a foreign debugger attaches the unshielded child and reads and
 * writes the shielded parent's memory (the hole of
 * 2026-11-17-ptrace-vfork-child-shared-vmspace-shield-bypass.md).
 */
static void
shared_child_case(const char *how)
{
	struct agent prober;
	struct fx f;
	pid_t child;

	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	child = fixture_split(&f, how);
	agent_start(&prober, -1);
	/*
	 * The child inherits the parent's ptrace shield until it execs (it
	 * was attached, read and written: the parent's memory).
	 */
	ATF_CHECK_EQ(probe_rw(&prober, child, f.canary, CANARY_SECRET,
	    CANARY_WRITTEN), EACCES);
	ATF_CHECK_EQ(fixture_canary(&f), CANARY_SECRET);
	agent_stop(&prober);
	ATF_CHECK_EQ(fixture_join(&f, child), CANARY_SECRET);
	fixture_stop(&f);
}

ATF_TC(pin_ptrace_vfork_child_shared_vmspace);
ATF_TC_HEAD(pin_ptrace_vfork_child_shared_vmspace, tc)
{
	atf_tc_set_md_var(tc, "descr", "A vfork, RFMEM or posix_spawn child "
	    "of a ptrace-shielded process gives a foreign debugger the "
	    "parent's memory");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(pin_ptrace_vfork_child_shared_vmspace, tc)
{
	struct agent prober, protector;
	struct fx f;
	char rest[128], cwd[MAXPATHLEN], fifo[MAXPATHLEN];
	pid_t child;
	int wfd;

	paths_init(tc);
	shared_child_case("vfork");
	shared_child_case("rfmem");

	/*
	 * posix_spawn (RFSPAWN): the child blocks in a file action, the open
	 * of a FIFO, while it still shares the parent's memory.
	 */
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(fifo, sizeof(fifo), "%s/spawn.fifo", cwd);
	ATF_REQUIRE(mkfifo(fifo, 0600) == 0);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	send_line(f.sock, "spawn %s", fifo);
	child = child_of(f.pid);
	wait_fifo_open(child, f.sock);
	agent_start(&prober, -1);
	ATF_CHECK_EQ(probe_rw(&prober, child, f.canary, CANARY_SECRET,
	    CANARY_WRITTEN), EACCES);
	agent_stop(&prober);
	wfd = fifo_writer(fifo, child, f.sock);
	expect_line(f.sock, "SPAWNED", rest, sizeof(rest));
	ATF_CHECK_MSG(atoi(rest) == child, "SPAWNED %s, expected %d", rest,
	    (int)child);
	expect_line(f.sock, "RESUMED", rest, sizeof(rest));
	close(wfd);
	ATF_CHECK_EQ(fixture_canary(&f), CANARY_SECRET);
	fixture_stop(&f);

	/*
	 * Q12: the parent's protector is not the child's: the child's
	 * protector is its parent (it attached the child before).
	 */
	agent_spawn(&protector, &f, 0, CP_SF_PTRACE, "plain");
	fixture_set(&f, CANARY_SECRET);
	child = fixture_split(&f, "vfork");
	ATF_CHECK_EQ(probe_rw(&protector, child, f.canary, CANARY_SECRET,
	    CANARY_WRITTEN), EACCES);
	ATF_CHECK_EQ(fixture_join(&f, child), CANARY_SECRET);
	fixture_stop(&f);
	agent_stop(&protector);
}

ATF_TC(pin_ptrace_fork_child_copy);
ATF_TC_HEAD(pin_ptrace_fork_child_copy, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child of a ptrace-shielded "
	    "process holds a debuggable copy of its memory until it execs");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_ptrace_fork_child_copy, tc)
{
	struct agent prober;
	struct fx f;
	char rest[256];
	pid_t child;
	uint64_t v;

	paths_init(tc);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	child = fixture_split(&f, "fork");
	agent_start(&prober, -1);
	/*
	 * The copy inherits the parent's ptrace shield until it execs (it was
	 * readable: 2026-11-17-shield-fork-copy-memory-exposed.md).
	 */
	ATF_CHECK_EQ(agent_attach(&prober, child), EACCES);
	v = 0;
	ATF_CHECK_EQ(agent_read(&prober, child, f.canary, &v), EACCES);

	/* After exec of an unprotected image the child is debuggable. */
	send_line(f.sock, "exec");
	expect_line(f.sock, "READY", rest, sizeof(rest));
	ATF_CHECK_EQ(agent_attach(&prober, child), 0);
	ATF_CHECK_EQ(agent_detach(&prober, child), 0);
	agent_stop(&prober);
	fixture_join(&f, child);
	fixture_stop(&f);
}

ATF_TC(pin_ptrace_unshare_copy);
ATF_TC_HEAD(pin_ptrace_unshare_copy, tc)
{
	atf_tc_set_md_var(tc, "descr", "An RFMEM child of a ptrace-shielded "
	    "process that unshares (rfork(0)) holds a debuggable copy");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_ptrace_unshare_copy, tc)
{
	struct agent prober;
	struct fx f;
	pid_t child;
	uint64_t v;

	paths_init(tc);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	child = fixture_split(&f, "unshare");
	agent_start(&prober, -1);
	/* The shield inherited at the RFMEM fork stays (it was readable). */
	ATF_CHECK_EQ(agent_attach(&prober, child), EACCES);
	v = 0;
	ATF_CHECK_EQ(agent_read(&prober, child, f.canary, &v), EACCES);
	agent_stop(&prober);
	fixture_join(&f, child);
	fixture_stop(&f);
}

/*
 * Whether this kernel was built with options CAPPROTECT_TEST_ALLOW_TRACED
 * (GENERIC-TEST): its configuration text names the option.
 */
static bool
test_allow_traced(void)
{
	char *conf;
	size_t len;
	bool found;

	len = 0;
	if (sysctlbyname("kern.conftxt", NULL, &len, NULL, 0) != 0)
		return (false);
	conf = malloc(len + 1);
	ATF_REQUIRE(conf != NULL);
	ATF_REQUIRE(sysctlbyname("kern.conftxt", conf, &len, NULL, 0) == 0);
	conf[len] = '\0';
	found = strstr(conf, "CAPPROTECT_TEST_ALLOW_TRACED") != NULL;
	free(conf);
	return (found);
}

/* CP_OP_PROTECT of the process behind pd; returns 0 or the errno. */
static int
protect_pd(int pd, uint32_t flags, int *cfdp)
{
	struct mac_capability_connect_args conn;
	struct mac_capability_call_args ca;
	struct cp_request req;
	int ctl;

	ctl = open("/dev/mac_capability", O_RDWR);
	ATF_REQUIRE(ctl >= 0);
	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, "capprotect", sizeof(conn.name));
	ATF_REQUIRE(ioctl(ctl, MAC_CAPABILITY_CONNECT, &conn) == 0);
	close(ctl);
	*cfdp = conn.fd;
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_PROTECT;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.req_fds = &pd;
	ca.req_nfds = 1;
	return (ioctl(*cfdp, MAC_CAPABILITY_CALL, &ca) == 0 ? 0 : errno);
}

ATF_TC(pin_shield_while_traced);
ATF_TC_HEAD(pin_shield_while_traced, tc)
{
	atf_tc_set_md_var(tc, "descr", "Shielding a traced process is refused "
	    "with EBUSY, except on a CAPPROTECT_TEST_ALLOW_TRACED test kernel");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "180");
}
ATF_TC_BODY(pin_shield_while_traced, tc)
{
	struct agent tracer;
	struct fx f;
	uint64_t v;
	int pd, status, cfd, want;
	bool test_kernel;

	paths_init(tc);
	test_kernel = test_allow_traced();
	/*
	 * Release kernels refuse (the shield used to be applied under the
	 * tracer, which was then refused and left the tracee stuck:
	 * 2026-11-17-shield-applied-while-traced-keeps-tracer.md).  The test
	 * kernel keeps that behaviour, for starting Capsule or SwitchBoard
	 * under a debugger.
	 */
	want = test_kernel ? 0 : EBUSY;

	/* CP_OP_SHIELD by the traced process itself. */
	fixture_start(&f, "plain");
	agent_start(&tracer, -1);
	ATF_REQUIRE_EQ(agent_attach(&tracer, f.pid), 0);
	ATF_REQUIRE_EQ(agent_do(&tracer, "CONT", NULL, "cont %d", f.pid), 0);
	ATF_CHECK_EQ(fixture_shield(&f, CP_SF_PTRACE), want);
	if (test_kernel) {
		/* The tracer's later requests are refused, as before. */
		ATF_CHECK_EQ(agent_read(&tracer, f.pid, f.canary, &v),
		    EACCES);
		agent_stop(&tracer);
		status = fixture_stop(&f);
	} else {
		/* Unshielded: the tracer keeps its process and detaches. */
		ATF_REQUIRE(kill(f.pid, SIGSTOP) == 0);
		/* The tracer collects the stop before its PT_IO (P_WAITED). */
		ATF_CHECK_EQ(agent_do(&tracer, "WAITSTOP", NULL, "waitstop %d",
		    f.pid), 0);
		ATF_CHECK_EQ(agent_read(&tracer, f.pid, f.canary, &v), 0);
		ATF_CHECK_EQ(agent_detach(&tracer, f.pid), 0);
		agent_stop(&tracer);
		(void)kill(f.pid, SIGCONT);
		status = fixture_stop(&f);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "status %#x", status);
		/* Once the tracer is gone the process may shield itself. */
		fixture_start(&f, "plain");
		ATF_CHECK_EQ(fixture_shield(&f, CP_SF_PTRACE), 0);
		fixture_stop(&f);
	}

	/* CP_OP_PROTECT by the launcher of a traced process. */
	fixture_start_as(&f, "plain", (uid_t)-1, &pd, 0);
	agent_start(&tracer, -1);
	ATF_REQUIRE_EQ(agent_attach(&tracer, f.pid), 0);
	ATF_REQUIRE_EQ(agent_do(&tracer, "CONT", NULL, "cont %d", f.pid), 0);
	ATF_CHECK_EQ(protect_pd(pd, CP_SF_PTRACE, &cfd), want);
	ATF_CHECK_EQ(agent_read(&tracer, f.pid, f.canary, &v),
	    test_kernel ? EACCES : EBUSY);
	agent_stop(&tracer);
	close(f.sock);
	close(pd);
	close(cfd);
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
 * pdfork a child of the fixture; the parent's process descriptor for it
 * arrives in *pdp.
 */
static pid_t
fixture_pdfork(struct fx *f, int *pdp)
{
	char rest[64];

	send_line(f->sock, "pdfork");
	recv_line(f->sock, rest, sizeof(rest), pdp);
	ATF_REQUIRE_MSG(strcmp(rest, "PD 0") == 0 && *pdp >= 0,
	    "pdfork: \"%s\"", rest);
	expect_line(f->sock, "CHILD", rest, sizeof(rest));
	f->server = atoi(rest);
	ATF_REQUIRE(f->server > 0);
	return (f->server);
}

/* The agent protects the process behind pd with flags. */
static int
agent_protect_fd(struct agent *a, int pd, uint32_t flags)
{
	char line[64], rest[64];

	snprintf(line, sizeof(line), "protect %x", flags);
	send_line_fd(a->sock, line, pd);
	expect_line(a->sock, "PROTECT", rest, sizeof(rest));
	return (atoi(rest));
}

/* exec the serving child into "plain"; it keeps its pid. */
static void
fixture_exec(struct fx *f)
{
	char rest[256];

	send_line(f->sock, "exec");
	expect_line(f->sock, "READY", rest, sizeof(rest));
}

ATF_TC(pin_inherited_converts_on_protect);
ATF_TC_HEAD(pin_inherited_converts_on_protect, tc)
{
	atf_tc_set_md_var(tc, "descr", "CP_OP_PROTECT of a fork child of a "
	    "ptrace-shielded process makes the caller its protector; the "
	    "explicit shield survives exec");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_converts_on_protect, tc)
{
	struct agent protector, stranger;
	struct fx f;
	pid_t child;
	int pd;

	paths_init(tc);
	fixture_start(&f, "self");
	child = fixture_pdfork(&f, &pd);
	agent_start(&protector, -1);
	agent_start(&stranger, -1);
	/* Inherited: protector is the parent; the agent is not yet. */
	ATF_CHECK_EQ(agent_attach(&protector, child), EACCES);
	ATF_REQUIRE_EQ(agent_protect_fd(&protector, pd, CP_SF_PTRACE), 0);
	close(pd);
	ATF_CHECK_EQ(agent_attach(&protector, child), 0);
	ATF_CHECK_EQ(agent_detach(&protector, child), 0);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	fixture_exec(&f);
	/* The explicit shield and its protector survive the exec. */
	ATF_CHECK_EQ(agent_attach(&protector, child), 0);
	ATF_CHECK_EQ(agent_detach(&protector, child), 0);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	agent_stop(&stranger);
	agent_stop(&protector);
	fixture_join(&f, child);
	fixture_stop(&f);
}

ATF_TC(pin_inherited_dropped_at_exec);
ATF_TC_HEAD(pin_inherited_dropped_at_exec, tc)
{
	atf_tc_set_md_var(tc, "descr", "The ptrace shield a fork child "
	    "inherits drops when it execs an unprotected image");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_dropped_at_exec, tc)
{
	struct agent stranger;
	struct fx f;
	pid_t child;

	paths_init(tc);
	fixture_start(&f, "self");
	child = fixture_split(&f, "fork");
	agent_start(&stranger, -1);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	fixture_exec(&f);
	ATF_CHECK_EQ(agent_attach(&stranger, child), 0);
	ATF_CHECK_EQ(agent_detach(&stranger, child), 0);
	agent_stop(&stranger);
	fixture_join(&f, child);
	fixture_stop(&f);
}

ATF_TC(pin_inherited_parent_exit);
ATF_TC_HEAD(pin_inherited_parent_exit, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child whose ptrace-shielded "
	    "parent exits stays refused to every debugger until it execs");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_parent_exit, tc)
{
	struct agent stranger;
	struct fx f;
	pid_t child;
	int status;

	paths_init(tc);
	/* PTRACE only, so that the test may kill the parent. */
	fixture_start(&f, "flags=1");
	child = fixture_split(&f, "fork");
	ATF_REQUIRE(kill(f.pid, SIGKILL) == 0);
	ATF_REQUIRE(waitpid(f.pid, &status, 0) == f.pid);
	f.pid = 0;
	agent_start(&stranger, -1);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	fixture_exec(&f);
	ATF_CHECK_EQ(agent_attach(&stranger, child), 0);
	ATF_CHECK_EQ(agent_detach(&stranger, child), 0);
	agent_stop(&stranger);
	fixture_stop(&f);
}

ATF_TC(pin_unshielded_fork_unchanged);
ATF_TC_HEAD(pin_unshielded_fork_unchanged, tc)
{
	atf_tc_set_md_var(tc, "descr", "A fork child of an unshielded process "
	    "inherits no shield");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pin_unshielded_fork_unchanged, tc)
{
	struct agent stranger;
	struct fx f;
	pid_t child;

	paths_init(tc);
	fixture_start(&f, "plain");
	child = fixture_split(&f, "fork");
	agent_start(&stranger, -1);
	ATF_CHECK_EQ(agent_attach(&stranger, child), 0);
	ATF_CHECK_EQ(agent_detach(&stranger, child), 0);
	agent_stop(&stranger);
	fixture_join(&f, child);
	fixture_stop(&f);
	/* A signal-only shield is not inherited either. */
	fixture_start(&f, "self-signal-only");
	child = fixture_split(&f, "fork");
	agent_start(&stranger, -1);
	ATF_CHECK_EQ(agent_attach(&stranger, child), 0);
	ATF_CHECK_EQ(agent_detach(&stranger, child), 0);
	agent_stop(&stranger);
	fixture_join(&f, child);
	fixture_stop(&f);
}

ATF_TC(pin_inherited_protect_without_ptrace);
ATF_TC_HEAD(pin_inherited_protect_without_ptrace, tc)
{
	atf_tc_set_md_var(tc, "descr", "CP_OP_PROTECT without CP_SF_PTRACE of "
	    "a fork child of a ptrace-shielded process: ptrace-refused until "
	    "exec, debuggable after, signals refused throughout");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_protect_without_ptrace, tc)
{
	struct agent protector, stranger;
	struct fx f;
	pid_t child;
	int pd;

	paths_init(tc);
	fixture_start(&f, "self");
	child = fixture_pdfork(&f, &pd);
	agent_start(&protector, -1);
	agent_start(&stranger, -1);
	ATF_REQUIRE_EQ(agent_protect_fd(&protector, pd, CP_SF_SIGNAL), 0);
	close(pd);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	ATF_CHECK(kill(child, SIGUSR1) == -1 && errno == EACCES);
	fixture_exec(&f);
	/* After exec: exactly the explicit flags, SIGNAL. */
	ATF_CHECK_EQ(agent_attach(&stranger, child), 0);
	ATF_CHECK_EQ(agent_detach(&stranger, child), 0);
	ATF_CHECK(kill(child, SIGUSR1) == -1 && errno == EACCES);
	agent_stop(&stranger);
	agent_stop(&protector);
	fixture_join(&f, child);
	fixture_stop(&f);
}

ATF_TC(pin_inherited_parent_debugs);
ATF_TC_HEAD(pin_inherited_parent_debugs, tc)
{
	atf_tc_set_md_var(tc, "descr", "Q-B1: the parent, which owns the "
	    "memory, may debug its fork child before the child execs");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_parent_debugs, tc)
{
	struct agent stranger;
	struct fx f;
	char rest[64];
	int child;

	paths_init(tc);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	send_line(f.sock, "forkidle");
	expect_line(f.sock, "FORKIDLE", rest, sizeof(rest));
	child = atoi(rest);
	ATF_REQUIRE(child > 0);
	agent_start(&stranger, -1);
	ATF_CHECK_EQ(agent_attach(&stranger, child), EACCES);
	agent_stop(&stranger);
	send_line(f.sock, "pattach");
	expect_line(f.sock, "PATTACH", rest, sizeof(rest));
	ATF_CHECK_STREQ(rest, "0");
	send_line(f.sock, "pread");
	expect_line(f.sock, "PREAD", rest, sizeof(rest));
	ATF_CHECK_STREQ(rest, "0 0x1122334455667788");
	send_line(f.sock, "pdetach");
	expect_line(f.sock, "PDETACH", rest, sizeof(rest));
	fixture_stop(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pin_ptrace_vfork_child_shared_vmspace);
	ATF_TP_ADD_TC(tp, pin_ptrace_fork_child_copy);
	ATF_TP_ADD_TC(tp, pin_ptrace_unshare_copy);
	ATF_TP_ADD_TC(tp, pin_shield_while_traced);
	ATF_TP_ADD_TC(tp, pin_inherited_converts_on_protect);
	ATF_TP_ADD_TC(tp, pin_inherited_dropped_at_exec);
	ATF_TP_ADD_TC(tp, pin_inherited_parent_exit);
	ATF_TP_ADD_TC(tp, pin_unshielded_fork_unchanged);
	ATF_TP_ADD_TC(tp, pin_inherited_protect_without_ptrace);
	ATF_TP_ADD_TC(tp, pin_inherited_parent_debugs);

	return (atf_no_error());
}
