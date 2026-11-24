/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Agent for the capprotect debug and tracing pins
 * (capprotect_debug_pins_test.c, capprotect_hardening_test.c).  It is a
 * separate process, so that the test that drives it is never the protector
 * or the tracer by accident: the capprotect shield identifies the protector
 * and token holders by PID.
 *
 * usage: capprotect_protector_helper FIXTURE
 *
 * FIXTURE is the path of the program "spawn" executes (capprotect_usdt_helper
 * or capprotect_share_helper).  Descriptors 3 and 4, when
 * open, become the standard input and output of a fixture started with
 * "spawn".  Commands arrive one per line on standard input, which must be a
 * UNIX-domain socket for "authorize"; each gets a one-line reply on
 * standard output.  End of file ends the agent.
 *
 *   spawn PDFLAGS PROTECT MODE
 *                     pdfork(2) with PDFLAGS (hex), CP_OP_PROTECT the child
 *                     with PROTECT (hex; 0 means do not protect), then let
 *                     the child exec the fixture in MODE.
 *                     Reply: SPAWNED PID ERRNO (ERRNO of the protect)
 *   protect PROTECT   CP_OP_PROTECT the spawned child again, or the process
 *                     whose descriptor arrived with the command line.
 *                     PROTECT ERRNO
 *   attach PID        PT_ATTACH, then wait for the stop.  ATTACH ERRNO
 *   read PID ADDR     PT_IO PIOD_READ_D of 8 bytes.  READ ERRNO VALUE
 *   write PID ADDR V  PT_IO PIOD_WRITE_D of 8 bytes.  WRITE ERRNO
 *   getregs PID       PT_GETREGS.  GETREGS ERRNO
 *   cont PID          PT_CONTINUE.  CONT ERRNO
 *   waitstop PID      wait for the traced PID's next stop.  WAITSTOP ERRNO
 *   followfork PID    PT_FOLLOW_FORK: trace the children PID forks.
 *                     FOLLOWFORK ERRNO
 *   waitfork PID      wait for the stop that reports a fork by the traced
 *                     PID.  WAITFORK ERRNO CHILD (the new child, which the
 *                     kernel attached to this agent)
 *   detach PID        PT_DETACH.  DETACH ERRNO
 *   vmmap PID         sysctl kern.proc.vmmap.  VMMAP ERRNO
 *   proc OID PID      sysctl kern.proc.OID (a KERN_PROC_* number) for PID.
 *                     PROC ERRNO
 *   authorize         CP_OP_AUTHORIZE on the token descriptor that arrived
 *                     with the command line.  AUTHORIZE ERRNO
 *   pid               PID PID
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <machine/reg.h>

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

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"

static const char *fixture;
static int child_pd = -1;
static int protect_fd = -1;

static void __printflike(1, 2)
reply(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf) ||
	    write(STDOUT_FILENO, buf, n) != n)
		_exit(98);
}

/*
 * Read one command line; a descriptor sent with any byte of it is returned
 * in *fdp (or -1).  Returns false at end of file.
 */
static bool
read_command(char *buf, size_t len, int *fdp)
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

	*fdp = -1;
	n = 0;
	for (;;) {
		iov.iov_base = &c;
		iov.iov_len = 1;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);
		r = recvmsg(STDIN_FILENO, &msg, 0);
		if (r < 0 && errno == ENOTSOCK)
			r = read(STDIN_FILENO, &c, 1);
		else if (r > 0) {
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET &&
				    cmsg->cmsg_type == SCM_RIGHTS)
					memcpy(fdp, CMSG_DATA(cmsg),
					    sizeof(int));
			}
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return (false);
		if (c == '\n')
			break;
		if (n + 1 < len)
			buf[n++] = c;
	}
	buf[n] = '\0';
	return (true);
}

static int
cp_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "capprotect", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		saved = errno;
		close(ctl);
		errno = saved;
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

static int
cp_call(int fd, uint32_t op, uint32_t flags, int *reqfd)
{
	struct mac_capability_call_args ca;
	struct cp_request req;

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (reqfd != NULL) {
		ca.req_fds = reqfd;
		ca.req_nfds = 1;
	}
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0 ? 0 : errno);
}

static int
protect_child(uint32_t flags, int pd)
{
	int error, fd;

	if (pd < 0)
		pd = child_pd;
	if (pd < 0)
		return (EBADF);
	fd = cp_connect();
	if (fd < 0)
		return (errno);
	error = cp_call(fd, CP_OP_PROTECT, flags, &pd);
	if (error != 0) {
		close(fd);
		return (error);
	}
	/* The protector keeps its descriptor; replace any earlier one. */
	if (protect_fd >= 0)
		close(protect_fd);
	protect_fd = fd;
	return (0);
}

static void
spawn(int pdflags, uint32_t protect, const char *mode)
{
	int gate[2], pd, error;
	pid_t pid;
	char go;

	if (pipe(gate) != 0) {
		reply("SPAWNED -1 %d\n", errno);
		return;
	}
	pid = pdfork(&pd, pdflags);
	if (pid < 0) {
		reply("SPAWNED -1 %d\n", errno);
		close(gate[0]);
		close(gate[1]);
		return;
	}
	if (pid == 0) {
		close(gate[1]);
		/* Wait for the protection before the descriptors are reset. */
		if (read(gate[0], &go, 1) != 1)
			_exit(91);
		if (dup2(3, STDIN_FILENO) < 0 || dup2(4, STDOUT_FILENO) < 0)
			_exit(90);
		closefrom(3);
		execl(fixture, fixture, mode, (char *)NULL);
		_exit(92);
	}
	close(gate[0]);
	child_pd = pd;
	error = protect != 0 ? protect_child(protect, -1) : 0;
	(void)write(gate[1], "g", 1);
	close(gate[1]);
	reply("SPAWNED %d %d\n", (int)pid, error);
}

static int
pt_io(pid_t pid, int op, uintmax_t addr, uint64_t *val)
{
	struct ptrace_io_desc piod;

	piod.piod_op = op;
	piod.piod_offs = (void *)(uintptr_t)addr;
	piod.piod_addr = val;
	piod.piod_len = sizeof(*val);
	if (ptrace(PT_IO, pid, (caddr_t)&piod, 0) != 0)
		return (errno);
	return (piod.piod_len == sizeof(*val) ? 0 : EIO);
}

/* Wait for the next stop of a traced process (ptrace requests need it). */
static int
waitstop(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return (errno);
	}
	return (WIFSTOPPED(status) ? 0 : ECHILD);
}

/* Wait for the traced process to report a fork; *childp is the child. */
static int
waitfork(pid_t pid, pid_t *childp)
{
	struct ptrace_lwpinfo pl;
	int error;

	*childp = -1;
	error = waitstop(pid);
	if (error != 0)
		return (error);
	if (ptrace(PT_LWPINFO, pid, (caddr_t)&pl, sizeof(pl)) != 0)
		return (errno);
	if ((pl.pl_flags & PL_FLAG_FORKED) == 0)
		return (ENOMSG);
	*childp = pl.pl_child_pid;
	return (0);
}

static int
attach(pid_t pid)
{

	if (ptrace(PT_ATTACH, pid, NULL, 0) != 0)
		return (errno);
	return (waitstop(pid));
}

static int
proc_sysctl(int oid, pid_t pid)
{
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = oid;
	mib[3] = pid;
	len = 0;
	return (sysctl(mib, 4, NULL, &len, NULL, 0) == 0 ? 0 : errno);
}

int
main(int argc, char **argv)
{
	struct reg regs;
	char cmd[256], mode[64];
	uintmax_t addr;
	uint64_t val;
	unsigned int pdflags, protect;
	pid_t child;
	int pid, fd, error;

	if (argc != 2) {
		fprintf(stderr, "usage: capprotect_protector_helper FIXTURE\n");
		return (2);
	}
	fixture = argv[1];
	signal(SIGPIPE, SIG_IGN);
	alarm(600);
	while (read_command(cmd, sizeof(cmd), &fd)) {
		if (sscanf(cmd, "spawn %x %x %63s", &pdflags, &protect,
		    mode) == 3)
			spawn((int)pdflags, protect, mode);
		else if (sscanf(cmd, "protect %x", &protect) == 1)
			reply("PROTECT %d\n", protect_child(protect, fd));
		else if (sscanf(cmd, "attach %d", &pid) == 1)
			reply("ATTACH %d\n", attach(pid));
		else if (sscanf(cmd, "read %d %jx", &pid, &addr) == 2) {
			val = 0;
			error = pt_io(pid, PIOD_READ_D, addr, &val);
			reply("READ %d %#" PRIx64 "\n", error, val);
		} else if (sscanf(cmd, "write %d %jx %" SCNx64, &pid, &addr,
		    &val) == 3)
			reply("WRITE %d\n", pt_io(pid, PIOD_WRITE_D, addr, &val));
		else if (sscanf(cmd, "getregs %d", &pid) == 1)
			reply("GETREGS %d\n", ptrace(PT_GETREGS, pid,
			    (caddr_t)&regs, 0) == 0 ? 0 : errno);
		else if (sscanf(cmd, "cont %d", &pid) == 1)
			reply("CONT %d\n", ptrace(PT_CONTINUE, pid, (caddr_t)1,
			    0) == 0 ? 0 : errno);
		else if (sscanf(cmd, "waitstop %d", &pid) == 1)
			reply("WAITSTOP %d\n", waitstop(pid));
		else if (sscanf(cmd, "followfork %d", &pid) == 1)
			reply("FOLLOWFORK %d\n", ptrace(PT_FOLLOW_FORK, pid, NULL,
			    1) == 0 ? 0 : errno);
		else if (sscanf(cmd, "waitfork %d", &pid) == 1) {
			error = waitfork(pid, &child);
			reply("WAITFORK %d %#x\n", error, (unsigned int)child);
		} else if (sscanf(cmd, "detach %d", &pid) == 1)
			reply("DETACH %d\n", ptrace(PT_DETACH, pid, (caddr_t)1,
			    0) == 0 ? 0 : errno);
		else if (sscanf(cmd, "vmmap %d", &pid) == 1)
			reply("VMMAP %d\n", proc_sysctl(KERN_PROC_VMMAP, pid));
		else if (sscanf(cmd, "proc %u %d", &protect, &pid) == 2)
			reply("PROC %d\n", proc_sysctl((int)protect, pid));
		else if (strcmp(cmd, "authorize") == 0) {
			if (fd < 0)
				reply("AUTHORIZE %d\n", EBADF);
			else {
				/* The token stays open: it is the grant. */
				reply("AUTHORIZE %d\n",
				    cp_call(fd, CP_OP_AUTHORIZE, 0, NULL));
			}
			fd = -1;
		} else if (strcmp(cmd, "pid") == 0)
			reply("PID %d\n", (int)getpid());
		else
			reply("ERROR unknown command\n");
		if (fd >= 0)
			close(fd);
	}
	return (0);
}
