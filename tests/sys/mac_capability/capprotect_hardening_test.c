/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The capprotect ptrace shield and the children of a shielded process
 * (mac_capability_capprotect(4)).  The first cases fail on a kernel with
 * the defect they name:
 *
 *   - a child that shares a shielded process's memory (vfork, RFMEM,
 *     posix_spawn) was debuggable, and through it the shielded memory;
 *   - a fork or unshare copy of a shielded process's memory was debuggable
 *     until it executed a new image;
 *   - shielding a process that a debugger already traced left the tracer
 *     attached, refused at every request.
 *
 * The others pin the rules of the inherited shield, and what a fork of an
 * unshielded process and a debugger that follows forks keep seeing.
 *
 * The fixture is capprotect_share_helper, driven over a socket; ptrace and
 * the protector role are played by capprotect_protector_helper (the
 * "agent"), a separate process, because capprotect recognises the
 * protector and token holders by PID.  Run in a guest only.
 */

#include <sys/param.h>
#include <sys/cap_authority.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
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

/*
 * Start an agent; fixture_end, when not -1, becomes the agent's descriptors
 * 3 and 4, and token, when not -1, is installed before the agent's image is
 * executed, so that the agent runs under its software authority.
 */
static void
agent_start_token(struct agent *a, int fixture_end, int token)
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
		if (token >= 0 &&
		    syscall(SYS_cap_process, CAP_AUTH_INSTALL, token, 0,
		    NULL) != 0)
			_exit(123);
		closefrom(fixture_end >= 0 ? 5 : 3);
		execl(agent_path, AGENT_NAME, fixture_path, (char *)NULL);
		_exit(122);
	}
	close(sv[1]);
	a->pid = pid;
	a->sock = sv[0];
}

static void
agent_start(struct agent *a, int fixture_end)
{

	agent_start_token(a, fixture_end, -1);
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
 * An attach that the shield must refuse.  One that succeeds is detached
 * again, so that the case fails by its check and not by the timeout of a
 * child left stopped.
 */
static int
agent_attach_refused(struct agent *a, pid_t pid)
{
	int error;

	error = agent_attach(a, pid);
	if (error == 0)
		(void)agent_detach(a, pid);
	return (error);
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

/*
 * Watch the fixture for a fork (EVFILT_PROC with NOTE_TRACK) and for a
 * reply on its control socket.
 */
static int
fork_watch(struct fx *f)
{
	struct kevent kev[2];
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&kev[0], f->server, EVFILT_PROC, EV_ADD, NOTE_FORK | NOTE_TRACK,
	    0, NULL);
	EV_SET(&kev[1], f->sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_MSG(kevent(kq, kev, 2, NULL, 0, NULL) == 0, "kevent: %s",
	    strerror(errno));
	return (kq);
}

/*
 * The child the watched fixture forks next.  A reply that arrives first
 * says that the fixture did not fork; it fails the case.
 */
static pid_t
fork_watch_child(int kq, struct fx *f)
{
	struct kevent kev;
	char buf[256];

	for (;;) {
		if (kevent(kq, NULL, 0, &kev, 1, NULL) != 1) {
			ATF_REQUIRE_MSG(errno == EINTR, "kevent: %s",
			    strerror(errno));
			continue;
		}
		if (kev.filter == EVFILT_READ) {
			recv_line(f->sock, buf, sizeof(buf), NULL);
			atf_tc_fail("the fixture did not fork: \"%s\"", buf);
		}
		ATF_REQUIRE_MSG((kev.fflags & NOTE_TRACKERR) == 0,
		    "the kernel could not track the fork of %d",
		    (int)f->server);
		if ((kev.fflags & NOTE_CHILD) != 0) {
			ATF_REQUIRE_EQ((pid_t)kev.data, f->server);
			return ((pid_t)kev.ident);
		}
	}
}

/*
 * The vfork and RFMEM child of a shielded process shares its vmspace.  A
 * foreign debugger attached the unshielded child and read and wrote the
 * shielded parent's memory.
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
	/* The child inherits the parent's ptrace shield until it execs. */
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
	    "of a ptrace-shielded process does not give a foreign debugger, "
	    "or the parent's protector, the parent's memory");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "300");
}
ATF_TC_BODY(pin_ptrace_vfork_child_shared_vmspace, tc)
{
	struct agent prober, protector;
	struct fx f;
	char rest[128], cwd[MAXPATHLEN], fifo[MAXPATHLEN];
	pid_t child;
	int error, kq, wfd;

	paths_init(tc);
	shared_child_case("vfork");
	shared_child_case("rfmem");

	/*
	 * posix_spawn (RFSPAWN): the child's first file action opens a FIFO
	 * for reading.  It cannot finish that open, and so cannot exec,
	 * before this test opens the FIFO for writing: from its fork until
	 * then it shares the parent's memory.
	 */
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(fifo, sizeof(fifo), "%s/spawn.fifo", cwd);
	ATF_REQUIRE(mkfifo(fifo, 0600) == 0);
	fixture_start(&f, "self");
	fixture_set(&f, CANARY_SECRET);
	kq = fork_watch(&f);
	send_line(f.sock, "spawn %s", fifo);
	child = fork_watch_child(kq, &f);
	close(kq);
	agent_start(&prober, -1);
	error = probe_rw(&prober, child, f.canary, CANARY_SECRET,
	    CANARY_WRITTEN);
	agent_stop(&prober);
	/*
	 * Fatal: an attach that succeeded may have interrupted the child's
	 * open, and then no reader ever arrives.
	 */
	ATF_REQUIRE_EQ_MSG(error, EACCES, "probe of the posix_spawn child "
	    "%d: %d", (int)child, error);
	wfd = open(fifo, O_WRONLY);
	ATF_REQUIRE_MSG(wfd >= 0, "open %s: %s", fifo, strerror(errno));
	expect_line(f.sock, "SPAWNED", rest, sizeof(rest));
	ATF_CHECK_MSG(atoi(rest) == child, "SPAWNED %s, expected %d", rest,
	    (int)child);
	expect_line(f.sock, "RESUMED", rest, sizeof(rest));
	close(wfd);
	ATF_CHECK_EQ(fixture_canary(&f), CANARY_SECRET);
	fixture_stop(&f);

	/*
	 * The parent's protector is not the child's: the child's protector
	 * is its parent.
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
	/* The copy inherits the parent's ptrace shield until it execs. */
	ATF_CHECK_EQ(agent_attach_refused(&prober, child), EACCES);
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
	/* The shield inherited at the RFMEM fork stays. */
	ATF_CHECK_EQ(agent_attach_refused(&prober, child), EACCES);
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
	 * Release kernels refuse.  The shield used to be applied under the
	 * tracer, which was then refused at every request and could neither
	 * continue nor detach its process.  The test kernel keeps that, for
	 * starting Capsule or SwitchBoard under a debugger.
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
		(void)fixture_stop(&f);
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
	ATF_CHECK_EQ(agent_attach_refused(&protector, child), EACCES);
	ATF_REQUIRE_EQ(agent_protect_fd(&protector, pd, CP_SF_PTRACE), 0);
	close(pd);
	ATF_CHECK_EQ(agent_attach(&protector, child), 0);
	ATF_CHECK_EQ(agent_detach(&protector, child), 0);
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
	fixture_exec(&f);
	/* The explicit shield and its protector survive the exec. */
	ATF_CHECK_EQ(agent_attach(&protector, child), 0);
	ATF_CHECK_EQ(agent_detach(&protector, child), 0);
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
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
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
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
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
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
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
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
	atf_tc_set_md_var(tc, "descr", "The parent, which owns the memory, "
	    "may debug its fork child before the child execs");
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
	ATF_CHECK_EQ(agent_attach_refused(&stranger, child), EACCES);
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

/* The agent becomes the holder of a ptrace token of the shielded fixture. */
static void
agent_authorize(struct agent *a, struct fx *f)
{
	char rest[64];
	int token;

	send_line(f->sock, "mint %x", CP_SF_PTRACE);
	recv_line(f->sock, rest, sizeof(rest), &token);
	ATF_REQUIRE_MSG(strcmp(rest, "MINT 0") == 0 && token >= 0,
	    "mint: \"%s\"", rest);
	send_line_fd(a->sock, "authorize", token);
	close(token);
	expect_line(a->sock, "AUTHORIZE", rest, sizeof(rest));
	ATF_REQUIRE_STREQ(rest, "0");
}

ATF_TC(pin_inherited_token_holder_refused);
ATF_TC_HEAD(pin_inherited_token_holder_refused, tc)
{
	atf_tc_set_md_var(tc, "descr", "A ptrace token of a shielded process "
	    "does not admit its holder to the process's fork child");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_token_holder_refused, tc)
{
	struct agent holder;
	struct fx f;
	pid_t child;

	paths_init(tc);
	fixture_start(&f, "self");
	agent_start(&holder, -1);
	agent_authorize(&holder, &f);
	/* The token admits its holder to the shielded process itself. */
	ATF_REQUIRE_EQ(agent_attach(&holder, f.pid), 0);
	ATF_REQUIRE_EQ(agent_detach(&holder, f.pid), 0);
	child = fixture_split(&f, "fork");
	ATF_CHECK_EQ(agent_attach_refused(&holder, child), EACCES);
	agent_stop(&holder);
	fixture_join(&f, child);
	fixture_stop(&f);
}

/*
 * A debugger that the shield admits (here the protector) follows the forks
 * of the shielded process: the kernel attaches each child to it at the
 * fork, without asking.  The debugger must be able to work with that child
 * and to detach it; a refused debugger could do neither, and the child
 * would stay stopped (and a vfork parent with it).
 */
static void
follow_fork_case(const char *how)
{
	struct agent debugger;
	struct fx f;
	char rest[64];
	uint64_t v;
	pid_t parent, child;

	agent_spawn(&debugger, &f, 0, CP_SF_PTRACE, "plain");
	parent = f.server;
	fixture_set(&f, CANARY_SECRET);
	ATF_REQUIRE_EQ(agent_attach(&debugger, parent), 0);
	ATF_REQUIRE_EQ(agent_do(&debugger, "FOLLOWFORK", NULL, "followfork %d",
	    (int)parent), 0);
	ATF_REQUIRE_EQ(agent_do(&debugger, "CONT", NULL, "cont %d",
	    (int)parent), 0);
	send_line(f.sock, "%s", how);
	ATF_REQUIRE_EQ(agent_do(&debugger, "WAITFORK", &v, "waitfork %d",
	    (int)parent), 0);
	child = (pid_t)v;
	ATF_REQUIRE_EQ(agent_do(&debugger, "WAITSTOP", NULL, "waitstop %d",
	    (int)child), 0);
	v = 0;
	ATF_REQUIRE_EQ_MSG(agent_read(&debugger, child, f.canary, &v), 0,
	    "%s: the debugger cannot read the child it follows", how);
	ATF_CHECK_EQ(v, CANARY_SECRET);
	ATF_REQUIRE_EQ_MSG(agent_detach(&debugger, child), 0,
	    "%s: the debugger cannot detach the child it follows", how);
	ATF_REQUIRE_EQ(agent_detach(&debugger, parent), 0);
	expect_line(f.sock, "CHILD", rest, sizeof(rest));
	ATF_REQUIRE_EQ(atoi(rest), child);
	f.server = child;
	/* Detached, the parent's protector is a stranger to the child. */
	ATF_CHECK_EQ(agent_attach_refused(&debugger, child), EACCES);
	ATF_CHECK_EQ(fixture_join(&f, child), CANARY_SECRET);
	fixture_stop(&f);
	agent_stop(&debugger);
}

ATF_TC(pin_follow_fork_keeps_child);
ATF_TC_HEAD(pin_follow_fork_keeps_child, tc)
{
	atf_tc_set_md_var(tc, "descr", "A debugger of a ptrace-shielded "
	    "process that follows its forks can debug and detach the "
	    "children the kernel attaches to it");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_follow_fork_keeps_child, tc)
{

	paths_init(tc);
	follow_fork_case("fork");
	follow_fork_case("vfork");
}

/*
 * A managed software authority constrained to the agent's image, from the
 * test issuer of a GENERIC-TEST kernel booted with
 * kern.mac_capability.test_issuer=1 (the stack tier); skips elsewhere.
 */
static int
agent_token(int *issuerp)
{
	struct cap_authority_spec spec = {
		.version = CAP_AUTH_VERSION, .kind = CAP_AUTH_MANAGED,
	};
	struct cap_authority_constraint c;
	size_t len;
	int enabled, image, issuer, token;

	len = sizeof(enabled);
	if (sysctlbyname("kern.mac_capability.test_issuer", &enabled, &len,
	    NULL, 0) != 0 || enabled != 1 ||
	    (issuer = syscall(SYS_cap_process, CAP_AUTH_ISSUER_CREATE, -1, 0,
	    NULL)) < 0)
		atf_tc_skip("DEFERRED_STACK_TIER: no test issuer: needs "
		    "GENERIC-TEST with kern.mac_capability.test_issuer=1, boot "
		    "not anchored (vm-provider.sh STACK_TIER=1)");
	token = syscall(SYS_cap_process, CAP_AUTH_ISSUE, issuer, 0, &spec);
	ATF_REQUIRE_MSG(token >= 0, "issue: %s", strerror(errno));
	image = open(agent_path, O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(image >= 0);
	memset(&c, 0, sizeof(c));
	c.token_fd = token;
	c.nexec = 1;
	c.executable_fds[0] = image;
	ATF_REQUIRE_MSG(syscall(SYS_cap_process, CAP_AUTH_CONSTRAIN, issuer, 0,
	    &c) == 0, "constrain: %s", strerror(errno));
	close(image);
	*issuerp = issuer;
	return (token);
}

ATF_TC(pin_inherited_parent_exec_authority);
ATF_TC_HEAD(pin_inherited_parent_exec_authority, tc)
{
	atf_tc_set_md_var(tc, "descr", "The inherited ptrace shield does "
	    "not pass the authority debug check: once a ptrace-shielded "
	    "authority holder executes a new image, it is refused its "
	    "pre-exec fork child (EPERM), as for a child with no shield");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(pin_inherited_parent_exec_authority, tc)
{
	struct agent holder;
	uint64_t v;
	pid_t child;
	int issuer, token;

	paths_init(tc);
	token = agent_token(&issuer);
	agent_start_token(&holder, -1, token);
	close(token);
	ATF_REQUIRE_EQ(agent_do(&holder, "SHIELD", NULL, "shield %x",
	    CP_SF_PTRACE), 0);
	ATF_REQUIRE_EQ(agent_do(&holder, "FORK", &v, "fork"), 0);
	child = (pid_t)v;
	ATF_REQUIRE(child > 0);
	/* Control: sharing the child's execution, the parent debugs it. */
	ATF_CHECK_EQ(agent_attach(&holder, child), 0);
	ATF_CHECK_EQ(agent_detach(&holder, child), 0);
	/* A new image is a new execution of the authority, or none. */
	ATF_REQUIRE_EQ(agent_do(&holder, "PID", NULL, "reexec\npid"),
	    holder.pid);
	ATF_CHECK_EQ(agent_attach_refused(&holder, child), EPERM);
	ATF_CHECK(kill(child, SIGKILL) == 0);
	agent_stop(&holder);
	close(issuer);
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
	ATF_TP_ADD_TC(tp, pin_inherited_token_holder_refused);
	ATF_TP_ADD_TC(tp, pin_follow_fork_keeps_child);
	ATF_TP_ADD_TC(tp, pin_inherited_parent_exec_authority);

	return (atf_no_error());
}
