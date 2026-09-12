/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for pidfd_open(2),
 * pidfd_send_signal(2) and pidfd_getfd(2).  No Linux libc required.
 * Exit status identifies the failed check.
 */
struct pollfd { int fd; short events, revents; };
struct timespec { long sec, nsec; };
struct epoll_event { unsigned int events; unsigned long long data; }
    __attribute__((packed));
struct siginfo {
	int signo, errno_, code, pad;
	int pid, uid;
	int pad2[24];
};
struct stat { unsigned long buf[18]; };

#define	SYS_read		0
#define	SYS_write		1
#define	SYS_close		3
#define	SYS_fstat		5
#define	SYS_poll		7
#define	SYS_mmap		9
#define	SYS_munmap		11
#define	SYS_pipe		22
#define	SYS_pause		34
#define	SYS_nanosleep		35
#define	SYS_getpid		39
#define	SYS_clone		56
#define	SYS_fork		57
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_fcntl		72
#define	SYS_getppid		110
#define	SYS_epoll_wait		232
#define	SYS_epoll_ctl		233
#define	SYS_epoll_create1	291
#define	SYS_pidfd_send_signal	424
#define	SYS_pidfd_open		434
#define	SYS_pidfd_getfd		438

#define	EPERM	1
#define	ESRCH	3
#define	EBADF	9
#define	EINVAL	22

#define	POLLIN		1
#define	SIGUSR1		10
#define	SIGTERM		15
#define	WNOHANG		1
#define	O_NONBLOCK	04000
#define	F_GETFD		1
#define	F_GETFL		3
#define	FD_CLOEXEC	1
#define	PIDFD_NONBLOCK	O_NONBLOCK
#define	EPOLL_CTL_ADD	1
#define	EPOLLIN		1

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

static void
msleep(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000 };

	(void)call(SYS_nanosleep, (long)&ts, 0, 0, 0, 0, 0);
}

static long
pidfd_open(long pid, long flags)
{

	return (call(SYS_pidfd_open, pid, flags, 0, 0, 0, 0));
}

static long
pidfd_send_signal(long fd, long sig, void *info, long flags)
{

	return (call(SYS_pidfd_send_signal, fd, sig, (long)info, flags, 0, 0));
}

static long
poll1(long fd, long timeout)
{
	struct pollfd pfd = { (int)fd, POLLIN, 0 };
	long n;

	n = call(SYS_poll, (long)&pfd, 1, timeout, 0, 0, 0);
	if (n == 1 && (pfd.revents & POLLIN) == 0)
		return (-1000);
	return (n);
}

/*
 * Thread creation for the "tid is not a process" check: the child lands on
 * a fresh stack, so the clone is done in asm and the child just sleeps and
 * exits without touching C.
 */
static long
thread_sleep_exit(void *stack_top)
{
	long tid;

	/* CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID */
	__asm__ volatile(
	    "mov $56, %%eax\n\t"
	    "mov $0x10f00, %%edi\n\t"	/* flags: 0x100|0x200|0x400|0x800|0x10000 */
	    "orl $0x00100000, %%edi\n\t"	/* CLONE_PARENT_SETTID */
	    "syscall\n\t"
	    "test %%rax, %%rax\n\t"
	    "jnz 1f\n\t"
	    /* child: nanosleep(300ms) then exit(0) */
	    "mov $35, %%eax\n\t"
	    "lea 16(%%rsp), %%rdi\n\t"
	    "movq $0, (%%rdi)\n\t"
	    "movq $300000000, 8(%%rdi)\n\t"
	    "xor %%esi, %%esi\n\t"
	    "syscall\n\t"
	    "mov $60, %%eax\n\t"
	    "xor %%edi, %%edi\n\t"
	    "syscall\n\t"
	    "1:\n\t"
	    : "=a"(tid)
	    : "S"(stack_top), "d"(&tid)
	    : "rcx", "r11", "rdi", "memory");
	return (tid);
}

static int
test(void)
{
	struct siginfo si;
	struct epoll_event ev;
	struct stat sb;
	long fd, fd2, me, child, r, status, tid;
	int pipes[2];
	char c;
	void *stack;

	me = call(SYS_getpid, 0, 0, 0, 0, 0, 0);

	/* 1-4: pidfd_open on self; close-on-exec is always set. */
	fd = pidfd_open(me, 0);
	if (fd < 0) return (1);
	if (call(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0) != FD_CLOEXEC) return (2);
	if (call(SYS_fstat, fd, (long)&sb, 0, 0, 0, 0) != 0) return (3);
	/* A live process is not readable. */
	if (poll1(fd, 0) != 0) return (4);
	/* 5: a pidfd supports no I/O (EINVAL on Linux). */
	if (call(SYS_read, fd, (long)&c, 1, 0, 0, 0) != -EINVAL) return (5);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/* 6-7: PIDFD_NONBLOCK is honoured and visible through F_GETFL. */
	fd = pidfd_open(me, PIDFD_NONBLOCK);
	if (fd < 0) return (6);
	if ((call(SYS_fcntl, fd, F_GETFL, 0, 0, 0, 0) & O_NONBLOCK) == 0)
		return (7);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/* 8-10: argument validation. */
	if (pidfd_open(me, 1) != -EINVAL) return (8);
	if (pidfd_open(0, 0) != -EINVAL) return (9);
	if (pidfd_open(-1, 0) != -EINVAL) return (10);

	/*
	 * 11-19: exit readiness.  The child lives 100ms; the pidfd must
	 * not be readable before it exits (a naive "always ready" would
	 * fail 12), must become readable afterwards, and once it is
	 * readable wait4(WNOHANG) must reap it immediately (a
	 * notification delivered before the process is a zombie would
	 * fail 14).
	 */
	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child < 0) return (11);
	if (child == 0) {
		msleep(100);
		call(SYS_exit, 5, 0, 0, 0, 0, 0);
	}
	fd = pidfd_open(child, 0);
	if (fd < 0) return (11);
	if (poll1(fd, 0) != 0) return (12);
	if (poll1(fd, 5000) != 1) return (13);
	status = 0;
	if (call(SYS_wait4, child, (long)&status, WNOHANG, 0, 0, 0) != child)
		return (14);
	if (((status >> 8) & 0xff) != 5) return (15);
	/* Still readable after the reap; signalling a reaped pid is ESRCH. */
	if (poll1(fd, 0) != 1) return (16);
	if (pidfd_send_signal(fd, 0, 0, 0) != -ESRCH) return (17);
	if (pidfd_send_signal(fd, SIGTERM, 0, 0) != -ESRCH) return (18);
	/* The pid is gone: a fresh pidfd_open fails. */
	if (pidfd_open(child, 0) != -ESRCH) return (19);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/* 20-24: epoll (what Bun uses) sees the exit too. */
	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child < 0) return (20);
	if (child == 0) {
		msleep(50);
		call(SYS_exit, 0, 0, 0, 0, 0, 0);
	}
	fd = pidfd_open(child, 0);
	if (fd < 0) return (20);
	fd2 = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	if (fd2 < 0) return (21);
	ev.events = EPOLLIN;
	ev.data = 77;
	if (call(SYS_epoll_ctl, fd2, EPOLL_CTL_ADD, fd, (long)&ev, 0, 0) != 0)
		return (22);
	ev.data = 0;
	if (call(SYS_epoll_wait, fd2, (long)&ev, 1, 5000, 0, 0) != 1)
		return (23);
	if (ev.data != 77 || (ev.events & EPOLLIN) == 0) return (24);
	if (call(SYS_wait4, child, (long)&status, WNOHANG, 0, 0, 0) != child)
		return (25);
	(void)call(SYS_close, fd2, 0, 0, 0, 0, 0);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/*
	 * 26-36: pidfd_send_signal.  The child blocks in pause(); a
	 * signal 0 probe succeeds, bad arguments are rejected without
	 * touching the child, then SIGTERM kills it.
	 */
	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child < 0) return (26);
	if (child == 0) {
		for (;;)
			call(SYS_pause, 0, 0, 0, 0, 0, 0);
	}
	fd = pidfd_open(child, 0);
	if (fd < 0) return (26);
	if (pidfd_send_signal(fd, 0, 0, 0) != 0) return (27);
	if (pidfd_send_signal(fd, SIGTERM, 0, 8) != -EINVAL) return (28);
	if (pidfd_send_signal(fd, 999, 0, 0) != -EINVAL) return (29);
	if (pidfd_send_signal(3000, SIGTERM, 0, 0) != -EBADF) return (30);
	/* A non-pidfd descriptor is EBADF. */
	if (call(SYS_pipe, (long)pipes, 0, 0, 0, 0, 0) != 0) return (31);
	if (pidfd_send_signal(pipes[0], SIGTERM, 0, 0) != -EBADF) return (31);
	/* siginfo: si_signo must match sig. */
	for (r = 0; r < (long)(sizeof(si) / sizeof(long)); r++)
		((long *)&si)[r] = 0;
	si.signo = SIGUSR1;
	si.code = -1;
	if (pidfd_send_signal(fd, SIGTERM, &si, 0) != -EINVAL) return (32);
	/* Forging a kernel si_code (>= 0) at another process is EPERM. */
	si.signo = SIGTERM;
	si.code = 0;
	if (pidfd_send_signal(fd, SIGTERM, &si, 0) != -EPERM) return (33);
	if (poll1(fd, 0) != 0) return (34);
	/* SI_QUEUE info from userland is fine. */
	si.code = -1;
	if (pidfd_send_signal(fd, SIGTERM, &si, 0) != 0) return (35);
	if (poll1(fd, 5000) != 1) return (36);
	if (call(SYS_wait4, child, (long)&status, WNOHANG, 0, 0, 0) != child)
		return (37);
	if ((status & 0x7f) != SIGTERM) return (38);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/*
	 * 39-46: pidfd_getfd.  The child pulls the parent's pipe write end
	 * through a pidfd and writes through it; the copy is close-on-exec.
	 */
	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child < 0) return (39);
	if (child == 0) {
		long pfd, nfd;

		pfd = pidfd_open(call(SYS_getppid, 0, 0, 0, 0, 0, 0), 0);
		if (pfd < 0)
			call(SYS_exit, 1, 0, 0, 0, 0, 0);
		if (call(SYS_pidfd_getfd, pfd, pipes[1], 1, 0, 0, 0) != -EINVAL)
			call(SYS_exit, 2, 0, 0, 0, 0, 0);
		if (call(SYS_pidfd_getfd, pfd, 9999, 0, 0, 0, 0) != -EBADF)
			call(SYS_exit, 3, 0, 0, 0, 0, 0);
		if (call(SYS_pidfd_getfd, pfd, -1, 0, 0, 0, 0) != -EBADF)
			call(SYS_exit, 4, 0, 0, 0, 0, 0);
		nfd = call(SYS_pidfd_getfd, pfd, pipes[1], 0, 0, 0, 0);
		if (nfd < 0)
			call(SYS_exit, 5, 0, 0, 0, 0, 0);
		if (call(SYS_fcntl, nfd, F_GETFD, 0, 0, 0, 0) != FD_CLOEXEC)
			call(SYS_exit, 6, 0, 0, 0, 0, 0);
		if (call(SYS_write, nfd, (long)"k", 1, 0, 0, 0) != 1)
			call(SYS_exit, 7, 0, 0, 0, 0, 0);
		call(SYS_exit, 0, 0, 0, 0, 0, 0);
	}
	if (call(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
		return (40);
	if (((status >> 8) & 0xff) != 0) return (41);
	c = 0;
	if (call(SYS_read, pipes[0], (long)&c, 1, 0, 0, 0) != 1 || c != 'k')
		return (42);
	/* getfd from a reaped process is ESRCH; from self works. */
	fd = pidfd_open(me, 0);
	if (fd < 0) return (43);
	fd2 = call(SYS_pidfd_getfd, fd, pipes[0], 0, 0, 0, 0);
	if (fd2 < 0) return (44);
	if (call(SYS_write, pipes[1], (long)"q", 1, 0, 0, 0) != 1) return (45);
	if (call(SYS_read, fd2, (long)&c, 1, 0, 0, 0) != 1 || c != 'q')
		return (46);
	(void)call(SYS_close, fd2, 0, 0, 0, 0, 0);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/*
	 * 47-49: a thread id that is not a thread-group leader is not a
	 * process: Linux returns EINVAL, not ESRCH.
	 */
	stack = (void *)call(SYS_mmap, 0, 65536, 3, 0x22, -1, 0);
	if ((long)stack < 0) return (47);
	tid = thread_sleep_exit((char *)stack + 65536 - 256);
	if (tid <= 0) return (48);
	if (pidfd_open(tid, 0) != -EINVAL) return (49);
	msleep(400);

	/* 50: a zombie can still be opened and is immediately readable. */
	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child == 0)
		call(SYS_exit, 0, 0, 0, 0, 0, 0);
	msleep(100);
	fd = pidfd_open(child, 0);
	if (fd < 0 || poll1(fd, 0) != 1) return (50);
	if (pidfd_send_signal(fd, 0, 0, 0) != 0) return (51);
	(void)call(SYS_wait4, child, (long)&status, 0, 0, 0, 0);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	return (0);
}

void __attribute__((force_align_arg_pointer))
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
