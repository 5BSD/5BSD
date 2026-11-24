/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Fixture for the capprotect shield-hardening pins
 * (capprotect_hardening_test.c, capprotect_hardening_dtrace_test.sh): a
 * process that shares (vfork, RFMEM, posix_spawn) or copies (fork,
 * unshare) its memory with a child, and runs aio and a pid-provider target.
 *
 * usage: capprotect_share_helper MODE
 *
 *   plain             no protection
 *   self              shields itself with CP_SF_PTRACE|SIGNAL|SIGKILL
 *   self-signal-only  shields itself with CP_SF_SIGNAL|SIGKILL (no PTRACE)
 *   flags=HEX         shields itself with exactly HEX
 *   execloop          executes itself in "execloop" mode, again and again
 *   capmode           enters capability mode and re-executes itself
 *                     (fexecve) in "plain" mode
 *
 * The fixture then prints one line
 *
 *   READY pid=PID canary=ADDR value=VALUE
 *
 * on standard output and serves commands, one per line, from standard input.
 * Standard output may be a socket, which "mint" needs.  Every reply is one
 * line.  The process that serves the commands is called the server below;
 * after "vfork", "rfmem", "fork" and "unshare" it is the new child until the
 * child exits, then again the parent, which first prints
 * "RESUMED child=PID status=STATUS canary=VALUE".
 *
 *   canary            CANARY VALUE (the server's view of the canary)
 *   set HEX           SET 0, after storing HEX in the canary
 *   shield HEX        SHIELD ERRNO (CP_OP_SHIELD with flags HEX)
 *   mint HEX          MINT ERRNO, with the token descriptor attached when
 *                     ERRNO is 0 (CP_OP_MINT on the shield descriptor)
 *   pid               PID PID
 *   sigcount          SIGCOUNT N (SIGUSR1 deliveries counted so far)
 *   vfork             CHILD PID from the vfork(2) child, which then serves
 *   rfmem             CHILD PID from an rfork(RFPROC|RFMEM) child
 *   fork              CHILD PID from a fork(2) child
 *   unshare           CHILD PID from an rfork(RFPROC|RFMEM) child that has
 *                     called rfork(0) (vmspace_unshare) first
 *   spawn FIFO        posix_spawn(3) of /usr/bin/true whose file actions
 *                     open FIFO for reading, so the child blocks in the
 *                     open sharing the parent's memory (RFSPAWN); the
 *                     parent, blocked in posix_spawn, then prints
 *                     SPAWNED PID ERRNO and waits for the child
 *   pdfork            as "fork", with pdfork(2): the parent first sends
 *                     PD 0 with the process descriptor attached (standard
 *                     output must be a socket)
 *   forkidle          FORKIDLE PID: a fork(2) child that only waits; the
 *                     parent keeps serving, and is the child's debugger
 *                     for the commands below
 *   pattach           PATTACH ERRNO: the parent attaches the idle child
 *   pread             PREAD ERRNO VALUE: PT_IO read of the child's canary
 *   pdetach           PDETACH ERRNO
 *   exec              re-executes this program in "plain" mode; the new
 *                     image prints a new READY line
 *   func              FUNC ADDR, the address of fixture_func(), which
 *                     SIGUSR1 calls (a pid-provider target)
 *   aio PATH          AIO ERRNO, after an aio_read(2) of PATH into a
 *                     buffer, so that an aio daemon runs on this vmspace
 *   exit              the server exits with status 0
 *
 * End of file on standard input makes the server exit.  An alarm ends
 * every process of the fixture after FIXTURE_TIMEOUT seconds.
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"


#define	FIXTURE_TIMEOUT	600

extern char **environ;

/*
 * The canary lives in .data, so a fork copy and a sharer see it at the same
 * address as the parent.  The tests read and write it through PT_IO.
 */
static volatile uint64_t cp_canary __used = 0x5ec2e75ec2e75ec2ULL;
static volatile sig_atomic_t cp_sigusr1;
static const char *cp_self;
/* The shield descriptor of the process that applied it; -1 if none. */
static int cp_shield_fd = -1;

static void
on_alarm(int sig __unused)
{

	_exit(99);
}

/* Called by the SIGUSR1 handler; the pid-provider pins probe its entry. */
void fixture_func(void);
void __noinline
fixture_func(void)
{

	cp_sigusr1++;
	__compiler_membar();
}

static void
on_usr1(int sig __unused)
{

	fixture_func();
}

static int
do_aio(const char *path)
{
	const struct aiocb *list[1];
	struct aiocb cb;
	char buf[4096];
	int error, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (errno);
	memset(&cb, 0, sizeof(cb));
	cb.aio_fildes = fd;
	cb.aio_buf = buf;
	cb.aio_nbytes = sizeof(buf);
	error = 0;
	if (aio_read(&cb) != 0)
		error = errno;
	else {
		list[0] = &cb;
		while (aio_error(&cb) == EINPROGRESS)
			(void)aio_suspend(list, 1, NULL);
		if (aio_return(&cb) < 0)
			error = aio_error(&cb);
	}
	close(fd);
	return (error);
}

/*
 * Replies are formatted on the stack and written with one write(2): the
 * server may be a vfork(2) child, which must not use the parent's stdio.
 */
static void __printflike(1, 2)
reply(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf))
		_exit(98);
	if (write(STDOUT_FILENO, buf, n) != n)
		_exit(97);
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

/* CP_OP_SHIELD on this process; returns 0 or an errno. */
static int
shield_self(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int error, fd;

	fd = cp_connect();
	if (fd < 0)
		return (errno);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		error = errno;
		close(fd);
		return (error);
	}
	if (cp_shield_fd >= 0)
		close(cp_shield_fd);
	cp_shield_fd = fd;
	return (0);
}

/* CP_OP_MINT on the shield descriptor; the token goes out with the reply. */
static void
mint_token(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char line[64];
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	int token;

	token = -1;
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = &token;
	ca.reply_nfds = 1;
	if (cp_shield_fd < 0) {
		reply("MINT %d\n", EBADF);
		return;
	}
	if (ioctl(cp_shield_fd, MAC_CAPABILITY_CALL, &ca) != 0 ||
	    ca.reply_nfds != 1 || token < 0) {
		reply("MINT %d\n", errno != 0 ? errno : EIO);
		return;
	}
	snprintf(line, sizeof(line), "MINT 0\n");
	iov.iov_base = line;
	iov.iov_len = strlen(line);
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
	memcpy(CMSG_DATA(cmsg), &token, sizeof(int));
	if (sendmsg(STDOUT_FILENO, &msg, 0) != (ssize_t)iov.iov_len)
		_exit(96);
	close(token);
}

/*
 * Read one command line.  Returns false at end of file.  Waits in poll(2),
 * which the destructive-action pins probe (syscall::poll:entry).
 */
static bool
read_command(char *buf, size_t len)
{
	struct pollfd pfd;
	size_t n;
	ssize_t r;
	char c;

	for (;;) {
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;
		pfd.revents = 0;
		r = poll(&pfd, 1, 100);
		if (r < 0 && errno != EINTR)
			_exit(95);
		if (r > 0)
			break;
	}
	n = 0;
	for (;;) {
		r = read(STDIN_FILENO, &c, 1);
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

static void serve(bool child) __dead2;

static void
report_resumed(pid_t pid)
{
	int status;

	status = -1;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	reply("RESUMED child=%d status=%d canary=%#" PRIx64 "\n", (int)pid,
	    status, (uint64_t)cp_canary);
}

/* rfork_thread(3) entry of the rfmem and unshare children. */
static int
rfmem_child(void *arg)
{

	if (arg != NULL && rfork(0) != 0)
		_exit(94);
	serve(true);
}

static void
split_rfmem(bool unshare)
{
	char *stack;
	size_t stacksz;
	pid_t pid;

	stacksz = 256 * 1024;
	stack = malloc(stacksz);
	if (stack == NULL)
		_exit(93);
	pid = rfork_thread(RFPROC | RFMEM, stack + stacksz, rfmem_child,
	    unshare ? (void *)1 : NULL);
	if (pid < 0) {
		reply("CHILD -%d\n", errno);
		free(stack);
		return;
	}
	report_resumed(pid);
	free(stack);
}

static void
split_vfork(void)
{
	pid_t pid;

	pid = vfork();
	if (pid == 0)
		serve(true);
	if (pid < 0) {
		reply("CHILD -%d\n", errno);
		return;
	}
	report_resumed(pid);
}

static void
split_fork(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0)
		serve(true);
	if (pid < 0) {
		reply("CHILD -%d\n", errno);
		return;
	}
	report_resumed(pid);
}

/* Send a reply line with a descriptor attached. */
static void
reply_fd(const char *line, int fd)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;

	iov.iov_base = __DECONST(char *, line);
	iov.iov_len = strlen(line);
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
	if (sendmsg(STDOUT_FILENO, &msg, 0) != (ssize_t)iov.iov_len)
		_exit(96);
}

static void
split_pdfork(void)
{
	int gate[2], pd;
	pid_t pid;
	char go;

	if (pipe(gate) != 0) {
		reply("CHILD -%d\n", errno);
		return;
	}
	pid = pdfork(&pd, 0);
	if (pid == 0) {
		close(gate[1]);
		/* The parent's PD line goes first. */
		if (read(gate[0], &go, 1) != 1)
			_exit(91);
		close(gate[0]);
		serve(true);
	}
	close(gate[0]);
	if (pid < 0) {
		close(gate[1]);
		reply("CHILD -%d\n", errno);
		return;
	}
	reply_fd("PD 0\n", pd);
	(void)write(gate[1], "g", 1);
	close(gate[1]);
	report_resumed(pid);
	close(pd);
}

/* The idle child of "forkidle" and the parent's debugging of it. */
static pid_t cp_idle_child = -1;

static void
split_forkidle(void)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		alarm(FIXTURE_TIMEOUT);
		for (;;)
			pause();
	}
	if (pid < 0) {
		reply("FORKIDLE -%d\n", errno);
		return;
	}
	cp_idle_child = pid;
	reply("FORKIDLE %d\n", (int)pid);
}

static int
parent_attach(void)
{
	int status;

	if (ptrace(PT_ATTACH, cp_idle_child, NULL, 0) != 0)
		return (errno);
	while (waitpid(cp_idle_child, &status, WUNTRACED) < 0) {
		if (errno != EINTR)
			return (errno);
	}
	return (WIFSTOPPED(status) ? 0 : ECHILD);
}

static void
parent_read(void)
{
	struct ptrace_io_desc piod;
	uint64_t v;

	v = 0;
	piod.piod_op = PIOD_READ_D;
	piod.piod_offs = __DEVOLATILE(uint64_t *, &cp_canary);
	piod.piod_addr = &v;
	piod.piod_len = sizeof(v);
	if (ptrace(PT_IO, cp_idle_child, (caddr_t)&piod, 0) != 0)
		reply("PREAD %d 0\n", errno);
	else
		reply("PREAD 0 %#" PRIx64 "\n", v);
}

static void
split_spawn(const char *fifo)
{
	posix_spawn_file_actions_t fa;
	char *argv[] = { __DECONST(char *, "true"), NULL };
	pid_t pid;
	int error;

	pid = -1;
	error = posix_spawn_file_actions_init(&fa);
	if (error == 0)
		error = posix_spawn_file_actions_addopen(&fa, 5, fifo,
		    O_RDONLY, 0);
	if (error == 0)
		error = posix_spawn(&pid, "/usr/bin/true", &fa, NULL, argv,
		    environ);
	posix_spawn_file_actions_destroy(&fa);
	reply("SPAWNED %d %d\n", (int)pid, error);
	if (error == 0)
		report_resumed(pid);
}

static void
serve(bool child)
{
	char cmd[128];
	unsigned long long v;

	if (child) {
		/* An alarm is not inherited; each process of the fixture sets one. */
		alarm(FIXTURE_TIMEOUT);
		reply("CHILD %d\n", (int)getpid());
	}
	while (read_command(cmd, sizeof(cmd))) {
		if (!child && cp_idle_child > 0 && strcmp(cmd, "exit") == 0)
			kill(cp_idle_child, SIGKILL);
		if (strcmp(cmd, "canary") == 0)
			reply("CANARY %#" PRIx64 "\n", (uint64_t)cp_canary);
		else if (sscanf(cmd, "set %llx", &v) == 1) {
			cp_canary = v;
			reply("SET 0\n");
		} else if (sscanf(cmd, "shield %llx", &v) == 1)
			reply("SHIELD %d\n", shield_self((uint32_t)v));
		else if (sscanf(cmd, "mint %llx", &v) == 1)
			mint_token((uint32_t)v);
		else if (strcmp(cmd, "pid") == 0)
			reply("PID %d\n", (int)getpid());
		else if (strcmp(cmd, "sigcount") == 0)
			reply("SIGCOUNT %d\n", (int)cp_sigusr1);
		else if (strcmp(cmd, "vfork") == 0)
			split_vfork();
		else if (strcmp(cmd, "rfmem") == 0)
			split_rfmem(false);
		else if (strcmp(cmd, "unshare") == 0)
			split_rfmem(true);
		else if (strcmp(cmd, "fork") == 0)
			split_fork();
		else if (strcmp(cmd, "pdfork") == 0)
			split_pdfork();
		else if (strcmp(cmd, "forkidle") == 0)
			split_forkidle();
		else if (strcmp(cmd, "pattach") == 0)
			reply("PATTACH %d\n", parent_attach());
		else if (strcmp(cmd, "pread") == 0)
			parent_read();
		else if (strcmp(cmd, "pdetach") == 0)
			reply("PDETACH %d\n", ptrace(PT_DETACH, cp_idle_child,
			    (caddr_t)1, 0) == 0 ? 0 : errno);
		else if (strncmp(cmd, "spawn ", 6) == 0)
			split_spawn(cmd + 6);
		else if (strcmp(cmd, "exec") == 0) {
			execl(cp_self, "capprotect_share_helper", "plain",
			    (char *)NULL);
			reply("EXEC %d\n", errno);
		} else if (strcmp(cmd, "func") == 0)
			reply("FUNC %p\n", (void *)(uintptr_t)fixture_func);
		else if (strncmp(cmd, "aio ", 4) == 0)
			reply("AIO %d\n", do_aio(cmd + 4));
		else if (strcmp(cmd, "exit") == 0)
			_exit(0);
		else
			reply("ERROR unknown command\n");
	}
	if (!child && cp_idle_child > 0)
		kill(cp_idle_child, SIGKILL);
	_exit(0);
}

int
main(int argc, char **argv)
{
	uint32_t flags;
	int error;

	if (argc != 2) {
		fprintf(stderr, "usage: capprotect_share_helper MODE\n");
		return (2);
	}
	/* "exec" re-executes argv[0]: the tests run the fixture by full path. */
	cp_self = argv[0];
	signal(SIGALRM, on_alarm);
	signal(SIGUSR1, on_usr1);
	signal(SIGPIPE, SIG_IGN);
	alarm(FIXTURE_TIMEOUT);

	if (strcmp(argv[1], "execloop") == 0) {
		/* Execute itself again and again (the MAKEPROBE exec race). */
		execl(argv[0], "capprotect_share_helper", "execloop",
		    (char *)NULL);
		return (1);
	}
	if (strcmp(argv[1], "plain") == 0)
		flags = 0;
	else if (strcmp(argv[1], "self") == 0)
		flags = CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_SIGKILL;
	else if (strcmp(argv[1], "self-signal-only") == 0)
		flags = CP_SF_SIGNAL | CP_SF_SIGKILL;
	else if (strcmp(argv[1], "capmode") == 0) {
		char *nargv[] = { argv[0], __DECONST(char *, "plain"),
		    NULL };
		int fd;

		fd = open(argv[0], O_RDONLY | O_EXEC);
		if (fd < 0 || cap_enter() != 0) {
			reply("FAILED capmode %d\n", errno);
			return (1);
		}
		fexecve(fd, nargv, environ);
		reply("FAILED fexecve %d\n", errno);
		return (1);
	} else if (strncmp(argv[1], "flags=", 6) == 0)
		flags = (uint32_t)strtoul(argv[1] + 6, NULL, 16);
	else {
		fprintf(stderr, "capprotect_share_helper: unknown mode %s\n",
		    argv[1]);
		return (2);
	}
	if (flags != 0 && (error = shield_self(flags)) != 0) {
		reply("FAILED shield %d\n", error);
		return (1);
	}
	reply("READY pid=%d canary=%p value=%#" PRIx64 "\n", (int)getpid(),
	    (void *)(uintptr_t)&cp_canary, (uint64_t)cp_canary);
	serve(false);
}
