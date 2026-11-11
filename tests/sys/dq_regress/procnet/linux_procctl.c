/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The Linux-ABI half of procnet_control_test: process creation,
 * signalling, waiting and exit as a Linux process that is NOT attached to
 * a dq(4) controller sees them.  One fixed workload; every return value,
 * errno and wait status is compared with a table.  The table is the
 * behaviour of the kernel before the supervisor-control series (commit
 * a9935859e88), recorded by running this program on it.
 *
 * Freestanding (no Linux libc): built at test time by
 * linux_procctl_test.sh, as fdops/linux_fdops.c is.  argv[1] is this
 * program's own path, for the execve rows; "exit7" as argv[1] is the image
 * those rows run.
 *
 * vfork(2) and thread creation are written in assembly: the child of
 * either must not return through a C frame it shares with (vfork) or was
 * never given by (clone with a new stack) its parent.
 */

#define	SYS_write		1
#define	SYS_close		3
#define	SYS_pause		34
#define	SYS_nanosleep		35
#define	SYS_getpid		39
#define	SYS_clone		56
#define	SYS_fork		57
#define	SYS_vfork		58
#define	SYS_execve		59
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_gettid		186
#define	SYS_exit_group		231
#define	SYS_tgkill		234
#define	SYS_waitid		247
#define	SYS_pidfd_send_signal	424
#define	SYS_pidfd_open		434

#define	ENOENT		2
#define	ESRCH		3
#define	EBADF		9
#define	ECHILD		10
#define	EACCES		13
#define	EFAULT		14
#define	EINVAL		22
#define	ENOSYS		38

#define	SIGKILL		9
#define	SIGTERM		15
#define	SIGCHLD		17
#define	SIGCONT		18
#define	SIGSTOP		19

#define	WNOHANG		1
#define	WUNTRACED	2
#define	WSTOPPED	2
#define	WEXITED		4
#define	WCONTINUED	8
#define	WNOWAIT		0x01000000

#define	P_ALL		0
#define	P_PID		1
#define	P_PIDFD		3

#define	CLD_EXITED	1
#define	CLD_KILLED	2
#define	CLD_STOPPED	5
#define	CLD_CONTINUED	6

#define	CLONE_VM		0x00000100
#define	CLONE_FS		0x00000200
#define	CLONE_FILES		0x00000400
#define	CLONE_SIGHAND		0x00000800
#define	CLONE_THREAD		0x00010000
#define	CLONE_SYSVSEM		0x00040000
#define	CLONE_PARENT_SETTID	0x00100000
#define	CLONE_CHILD_CLEARTID	0x00200000
#define	THREAD_FLAGS	(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | \
    CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)

/* A pid and a tid that name nothing. */
#define	NOPID		99999
#define	NOTID		0x3ffffffe

/* The wait statuses of the Linux ABI. */
#define	ST_EXIT(c)	((c) << 8)
#define	ST_SIG(s)	(s)
#define	ST_STOP(s)	(((s) << 8) | 0x7f)
#define	ST_CONT		0xffff

/* The SIGCHLD members of the Linux siginfo_t on amd64. */
struct lsiginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	pad;
	int	si_pid;
	int	si_uid;
	int	si_status;
	char	fill[128 - 28];
};

struct ltimespec {
	long	tv_sec;
	long	tv_nsec;
};

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

#define	S0(n)			call(n, 0, 0, 0, 0, 0, 0)
#define	S1(n, a)		call(n, (long)(a), 0, 0, 0, 0, 0)
#define	S2(n, a, b)		call(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define	S3(n, a, b, c)		call(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define	S4(n, a, b, c, d)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), 0, 0)
#define	S5(n, a, b, c, d, e)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), 0)

/*
 * long l_vfork_exit(long code): vfork; the child exits with the code at
 * once, without touching the stack; the parent gets vfork's result.
 */
long l_vfork_exit(long);
__asm__(
	".text\n"
	"l_vfork_exit:\n"
	"	mov $58, %eax\n"
	"	syscall\n"
	"	test %rax, %rax\n"
	"	jnz 1f\n"
	"	mov $60, %eax\n"
	"	syscall\n"
	"	hlt\n"
	"1:	ret\n");

/*
 * long l_thread(long flags, void *stack, int *ptid, int *ctid, long mode):
 * clone a thread.  The new thread, by mode: 0 exits (exit(2), the thread
 * alone); -1 sleeps for ever; anything else ends the whole process with
 * exit_group(mode).
 */
long l_thread(long, void *, int *, int *, long);
__asm__(
	".text\n"
	"l_thread:\n"
	"	mov %rcx, %r10\n"
	"	mov %r8, %r9\n"
	"	xor %r8, %r8\n"
	"	mov $56, %eax\n"
	"	syscall\n"
	"	test %rax, %rax\n"
	"	jnz 1f\n"
	"	cmp $-1, %r9\n"
	"	je 3f\n"
	"	test %r9, %r9\n"
	"	jz 2f\n"
	"	mov %r9, %rdi\n"
	"	mov $231, %eax\n"
	"	syscall\n"
	"2:	xor %edi, %edi\n"
	"	mov $60, %eax\n"
	"	syscall\n"
	"	hlt\n"
	"3:	mov $34, %eax\n"
	"	syscall\n"
	"	jmp 3b\n"
	"1:	ret\n");

/* The compiler may emit these for struct copies and zeroing. */
void *memset(void *, int, unsigned long);
void *memcpy(void *, const void *, unsigned long);
void *
memset(void *p, int v, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = (char)v;
	return (p);
}
void *
memcpy(void *d, const void *s, unsigned long n)
{
	volatile char *dc = d;
	const char *sc = s;

	while (n-- > 0)
		*dc++ = *sc++;
	return (d);
}

static unsigned long
slen(const char *s)
{
	unsigned long n = 0;

	while (s[n] != '\0')
		n++;
	return (n);
}

static int
seq(const char *a, const char *b)
{

	while (*a != '\0' && *a == *b) {
		a++;
		b++;
	}
	return (*a == *b);
}

static void
out(const char *s)
{

	(void)S3(SYS_write, 1, s, slen(s));
}

static void
outn(long v)
{
	char buf[24], *p = buf + sizeof(buf);
	unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;

	*--p = '\0';
	do {
		*--p = '0' + u % 10;
		u /= 10;
	} while (u != 0);
	if (v < 0)
		*--p = '-';
	out(p);
}

/* The number of rows recorded; test() fails on any other count. */
#define	NROWS	92

static int g_rows, g_fails;

/* One row of the table; every row is printed, so a run is a record. */
static void
row(const char *name, long got, long want)
{

	g_rows++;
	if (got != want) {
		g_fails++;
		out("FAIL ");
	} else
		out("ok   ");
	out(name);
	out(": ");
	outn(got);
	if (got != want) {
		out(", expected ");
		outn(want);
	}
	out("\n");
}

static void
nap(void)
{
	struct ltimespec ts = { 0, 10 * 1000 * 1000 };

	(void)S2(SYS_nanosleep, &ts, 0);
}

/* fork a child that exits with the code. */
static long
child_exits(int code)
{
	long pid;

	pid = S0(SYS_fork);
	if (pid == 0) {
		(void)S1(SYS_exit, code);
		__builtin_unreachable();
	}
	return (pid);
}

/* fork a child that sleeps until a signal ends it. */
static long
child_sleeps(void)
{
	long pid;

	pid = S0(SYS_fork);
	if (pid == 0) {
		for (;;)
			(void)S0(SYS_pause);
	}
	return (pid);
}

static char stack1[16384] __attribute__((aligned(16)));
static int g_ptid, g_ctid;

static int
test(int argc, char **argv)
{
	struct lsiginfo si;
	char *xargv[3], *xenvp[1];
	long pid, pfd, r, self;
	int i, status;

	if (argc < 2)
		return (2);
	if (seq(argv[1], "exit7"))
		return (7);
	self = S0(SYS_getpid);

	/* --- wait with nothing to wait for --- */
	row("wait4(-1) no children", S4(SYS_wait4, -1, &status, 0, 0),
	    -ECHILD);
	row("wait4(1)", S4(SYS_wait4, 1, &status, WNOHANG, 0), -ECHILD);
	row("wait4 bad options", S4(SYS_wait4, -1, &status, 0x100, 0),
	    -EINVAL);
	row("waitid bad idtype", S5(SYS_waitid, 99, 0, &si, WEXITED, 0),
	    -EINVAL);
	row("waitid bad options", S5(SYS_waitid, P_ALL, 0, &si, 0x100, 0),
	    -EINVAL);
	row("waitid(P_PID, 0)", S5(SYS_waitid, P_PID, 0, &si, WEXITED, 0),
	    -EINVAL);
	row("waitid(P_ALL) no children", S5(SYS_waitid, P_ALL, 0, &si,
	    WEXITED, 0), -ECHILD);

	/* --- fork, exit, wait4 --- */
	pid = child_exits(3);
	if (pid <= 0)
		return (3);
	status = -1;
	row("fork: wait4", S4(SYS_wait4, pid, &status, 0, 0) == pid, 1);
	row("fork: status", status, ST_EXIT(3));
	row("fork: second wait4", S4(SYS_wait4, pid, &status, 0, 0),
	    -ECHILD);
	row("fork: kill reaped", S2(SYS_kill, pid, 0), -ESRCH);

	/* --- vfork --- */
	pid = l_vfork_exit(4);
	if (pid <= 0)
		return (3);
	status = -1;
	row("vfork: wait4", S4(SYS_wait4, pid, &status, 0, 0) == pid, 1);
	row("vfork: status", status, ST_EXIT(4));

	/* --- clone as fork --- */
	pid = S5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
	if (pid == 0) {
		(void)S1(SYS_exit, 5);
		__builtin_unreachable();
	}
	if (pid < 0)
		return (3);
	status = -1;
	row("clone(SIGCHLD): wait4", S4(SYS_wait4, pid, &status, 0, 0) == pid,
	    1);
	row("clone(SIGCHLD): status", status, ST_EXIT(5));

	/* --- execve --- */
	xargv[0] = argv[1];
	xargv[1] = (char *)"exit7";
	xargv[2] = 0;
	xenvp[0] = 0;
	pid = S0(SYS_fork);
	if (pid == 0) {
		(void)S3(SYS_execve, argv[1], xargv, xenvp);
		(void)S1(SYS_exit, 99);
		__builtin_unreachable();
	}
	if (pid < 0)
		return (3);
	status = -1;
	row("execve: wait4", S4(SYS_wait4, pid, &status, 0, 0) == pid, 1);
	row("execve: status", status, ST_EXIT(7));
	row("execve ENOENT", S3(SYS_execve, "/nonexistent/x", xargv, xenvp),
	    -ENOENT);
	row("execve of a directory", S3(SYS_execve, "/", xargv, xenvp),
	    -EACCES);
	row("execve bad path", S3(SYS_execve, -1L, xargv, xenvp), -EFAULT);

	/* --- kill, waitid --- */
	pid = child_exits(6);
	if (pid <= 0)
		return (3);
	memset(&si, 0, sizeof(si));
	row("waitid(WNOWAIT)", S5(SYS_waitid, P_PID, pid, &si,
	    WEXITED | WNOWAIT, 0), 0);
	row("waitid(WNOWAIT): si_signo", si.si_signo, SIGCHLD);
	row("waitid(WNOWAIT): si_code", si.si_code, CLD_EXITED);
	row("waitid(WNOWAIT): si_status", si.si_status, 6);
	row("waitid(WNOWAIT): si_pid", si.si_pid == pid, 1);
	row("kill(zombie, SIGKILL)", S2(SYS_kill, pid, SIGKILL), 0);
	memset(&si, 0, sizeof(si));
	row("waitid reaps", S5(SYS_waitid, P_PID, pid, &si, WEXITED, 0), 0);
	row("waitid reaps: si_status", si.si_status, 6);
	row("waitid again", S5(SYS_waitid, P_PID, pid, &si, WEXITED, 0),
	    -ECHILD);

	pid = child_sleeps();
	if (pid <= 0)
		return (3);
	row("kill(child, 0)", S2(SYS_kill, pid, 0), 0);
	row("kill bad signal", S2(SYS_kill, pid, 65), -EINVAL);
	row("kill negative signal", S2(SYS_kill, pid, -1), -EINVAL);
	row("kill(NOPID)", S2(SYS_kill, NOPID, 0), -ESRCH);
	row("wait4(WNOHANG) live child", S4(SYS_wait4, pid, &status, WNOHANG,
	    0), 0);
	memset(&si, 0xff, sizeof(si));
	row("waitid(WNOHANG) live child", S5(SYS_waitid, P_PID, pid, &si,
	    WEXITED | WNOHANG, 0), 0);
	row("waitid(WNOHANG) live child: si_pid", si.si_pid, 0);
	row("waitid(WNOHANG) live child: si_signo", si.si_signo, 0);

	/* A stop and a continue are reported once each. */
	row("kill(child, SIGSTOP)", S2(SYS_kill, pid, SIGSTOP), 0);
	status = -1;
	row("wait4(WUNTRACED)", S4(SYS_wait4, pid, &status, WUNTRACED, 0) ==
	    pid, 1);
	row("stop status", status, ST_STOP(SIGSTOP));
	row("wait4(WUNTRACED) again", S4(SYS_wait4, pid, &status,
	    WUNTRACED | WNOHANG, 0), 0);
	row("kill(child, SIGCONT)", S2(SYS_kill, pid, SIGCONT), 0);
	status = -1;
	row("wait4(WCONTINUED)", S4(SYS_wait4, pid, &status, WCONTINUED, 0) ==
	    pid, 1);
	row("continue status", status, ST_CONT);
	row("wait4(WCONTINUED) again", S4(SYS_wait4, pid, &status,
	    WCONTINUED | WNOHANG, 0), 0);
	row("kill(child, SIGSTOP) 2", S2(SYS_kill, pid, SIGSTOP), 0);
	memset(&si, 0, sizeof(si));
	row("waitid(WSTOPPED)", S5(SYS_waitid, P_PID, pid, &si, WSTOPPED, 0),
	    0);
	row("waitid(WSTOPPED): si_code", si.si_code, CLD_STOPPED);
	row("waitid(WSTOPPED): si_status", si.si_status, SIGSTOP);
	row("kill(stopped child, SIGTERM)", S2(SYS_kill, pid, SIGTERM), 0);
	row("wait4(WNOHANG) stopped, SIGTERM pending", S4(SYS_wait4, pid,
	    &status, WNOHANG, 0), 0);
	row("kill(child, SIGCONT) 2", S2(SYS_kill, pid, SIGCONT), 0);
	status = -1;
	row("SIGTERM: wait4", S4(SYS_wait4, pid, &status, 0, 0) == pid, 1);
	row("SIGTERM: status", status, ST_SIG(SIGTERM));

	pid = child_sleeps();
	if (pid <= 0)
		return (3);
	row("kill(child, SIGKILL)", S2(SYS_kill, pid, SIGKILL), 0);
	memset(&si, 0, sizeof(si));
	row("SIGKILL: waitid", S5(SYS_waitid, P_PID, pid, &si, WEXITED, 0),
	    0);
	row("SIGKILL: si_code", si.si_code, CLD_KILLED);
	row("SIGKILL: si_status", si.si_status, SIGKILL);

	/* --- tgkill --- */
	row("tgkill(self, self, 0)", S3(SYS_tgkill, self, S0(SYS_gettid), 0),
	    0);
	row("tgkill bad signal", S3(SYS_tgkill, self, S0(SYS_gettid), 65),
	    -EINVAL);
	row("tgkill(self, NOTID)", S3(SYS_tgkill, self, NOTID, 0), -ESRCH);
	row("tgkill(0, 0)", S3(SYS_tgkill, 0, 0, 0), -EINVAL);

	/* --- pidfd --- */
	pid = child_sleeps();
	if (pid <= 0)
		return (3);
	pfd = S2(SYS_pidfd_open, pid, 0);
	if (pfd < 0) {
		/*
		 * Both kernels this was recorded on have pidfd_open; without
		 * it the pidfd rows cannot run, and that is a failure, also
		 * caught by the row count at the end.
		 */
		row("pidfd_open", pfd, 3);
		(void)S2(SYS_kill, pid, SIGKILL);
		(void)S4(SYS_wait4, pid, &status, 0, 0);
	} else {
		row("pidfd_open", pfd >= 0, 1);
		row("pidfd_open bad flags", S2(SYS_pidfd_open, pid, 0x40000000),
		    -EINVAL);
		row("pidfd_open(0)", S2(SYS_pidfd_open, 0, 0), -EINVAL);
		row("pidfd_open(NOPID)", S2(SYS_pidfd_open, NOPID, 0), -ESRCH);
		row("pidfd_send_signal(0)", S4(SYS_pidfd_send_signal, pfd, 0,
		    0, 0), 0);
		row("pidfd_send_signal bad signal", S4(SYS_pidfd_send_signal,
		    pfd, 65, 0, 0), -EINVAL);
		row("pidfd_send_signal bad flags", S4(SYS_pidfd_send_signal,
		    pfd, 0, 0, 0x40000000), -EINVAL);
		row("pidfd_send_signal(not a pidfd)",
		    S4(SYS_pidfd_send_signal, 1, 0, 0, 0), -EBADF);
		row("pidfd_send_signal(-1)", S4(SYS_pidfd_send_signal, -1, 0,
		    0, 0), -EBADF);
		row("waitid(P_PIDFD, not a pidfd)", S5(SYS_waitid, P_PIDFD, 1,
		    &si, WEXITED, 0), -EBADF);
		memset(&si, 0xff, sizeof(si));
		row("waitid(P_PIDFD, WNOHANG) live", S5(SYS_waitid, P_PIDFD,
		    pfd, &si, WEXITED | WNOHANG, 0), 0);
		row("waitid(P_PIDFD, WNOHANG) live: si_pid", si.si_pid, 0);
		row("pidfd_send_signal(SIGTERM)", S4(SYS_pidfd_send_signal,
		    pfd, SIGTERM, 0, 0), 0);
		memset(&si, 0, sizeof(si));
		row("waitid(P_PIDFD)", S5(SYS_waitid, P_PIDFD, pfd, &si,
		    WEXITED, 0), 0);
		row("waitid(P_PIDFD): si_code", si.si_code, CLD_KILLED);
		row("waitid(P_PIDFD): si_status", si.si_status, SIGTERM);
		row("waitid(P_PIDFD): si_pid", si.si_pid == pid, 1);
		row("pidfd_send_signal(reaped)", S4(SYS_pidfd_send_signal,
		    pfd, 0, 0, 0), -ESRCH);
		row("waitid(P_PIDFD) reaped", S5(SYS_waitid, P_PIDFD, pfd,
		    &si, WEXITED, 0), -ECHILD);
		row("close(pidfd)", S1(SYS_close, pfd), 0);
	}

	/* --- threads --- */
	g_ptid = 0;
	g_ctid = -1;
	r = l_thread(THREAD_FLAGS, stack1 + sizeof(stack1), &g_ptid, &g_ctid,
	    0);
	row("clone thread", r > 0, 1);
	if (r > 0) {
		row("clone thread: tid is not the pid", r != self, 1);
		row("clone thread: parent tid stored", g_ptid == r, 1);
		/* The thread's exit(2) clears the tid and ends only it. */
		for (i = 0; i < 1000 && *(volatile int *)&g_ctid != 0; i++)
			nap();
		row("clone thread: child tid cleared at exit",
		    *(volatile int *)&g_ctid, 0);
		row("getpid after thread exit", S0(SYS_getpid) == self, 1);
	}

	/* exit_group(2) from a second thread ends the process. */
	pid = S0(SYS_fork);
	if (pid == 0) {
		r = l_thread(THREAD_FLAGS, stack1 + sizeof(stack1), &g_ptid,
		    &g_ctid, 9);
		if (r <= 0)
			(void)S1(SYS_exit_group, 98);
		for (;;)
			(void)S0(SYS_pause);
	}
	if (pid < 0)
		return (3);
	status = -1;
	row("exit_group from a thread: wait4", S4(SYS_wait4, pid, &status, 0,
	    0) == pid, 1);
	row("exit_group from a thread: status", status, ST_EXIT(9));

	/* A signal ends a process whose other thread sleeps. */
	pid = S0(SYS_fork);
	if (pid == 0) {
		r = l_thread(THREAD_FLAGS, stack1 + sizeof(stack1), &g_ptid,
		    &g_ctid, -1);
		if (r <= 0)
			(void)S1(SYS_exit_group, 98);
		(void)S2(SYS_kill, S0(SYS_getpid), SIGTERM);
		(void)S1(SYS_exit_group, 97);
		__builtin_unreachable();
	}
	if (pid < 0)
		return (3);
	status = -1;
	row("threaded SIGTERM: wait4", S4(SYS_wait4, pid, &status, 0, 0) ==
	    pid, 1);
	row("threaded SIGTERM: status", status, ST_SIG(SIGTERM));

	row("wait4(-1) at the end", S4(SYS_wait4, -1, &status, WNOHANG, 0),
	    -ECHILD);

	/* Every row must have run: none is conditional. */
	if (g_rows != NROWS) {
		out("FAIL row count: expected ");
		outn(NROWS);
		out("\n");
		g_fails++;
	}
	out("linux_procctl: ");
	outn(g_rows);
	out(" rows, ");
	outn(g_fails);
	out(" not as recorded\n");
	return (g_fails == 0 ? 0 : 1);
}

void start_c(long *sp);
__attribute__((force_align_arg_pointer)) void
start_c(long *sp)
{
	(void)S1(SYS_exit_group, test((int)sp[0], (char **)&sp[1]));
	__builtin_unreachable();
}

__asm__(
	".globl _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call start_c\n"
	"	hlt\n");
