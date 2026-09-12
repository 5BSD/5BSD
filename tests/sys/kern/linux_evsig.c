/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for epoll_ctl flag handling
 * (EPOLLEXCLUSIVE/EPOLLWAKEUP hints and the Linux EPOLLEXCLUSIVE rules),
 * rt_sigaction sa_flags masking (SA_UNSUPPORTED & co) and clone3 argument
 * validation (CLONE_INTO_CGROUP, CLONE_NEWTIME, set_tid, struct tails).
 * No Linux libc or sysroot required; exit status = failed check number.
 */
struct epoll_event {
	unsigned int events;
	unsigned long long data;
} __attribute__((packed));

struct kernel_sigaction {
	void *handler;
	unsigned long flags;
	void *restorer;
	unsigned long mask;
};

struct pollfd { int fd; short events, revents; };
struct clone_args {
	unsigned long long flags;
	unsigned long long pidfd;
	unsigned long long child_tid;
	unsigned long long parent_tid;
	unsigned long long exit_signal;
	unsigned long long stack;
	unsigned long long stack_size;
	unsigned long long tls;
	unsigned long long set_tid;
	unsigned long long set_tid_size;
	unsigned long long cgroup;
};

#define	EPOLLIN		0x001
#define	EPOLLMSG	0x400
#define	EPOLLRDHUP	0x2000
#define	EPOLLEXCLUSIVE	(1u << 28)
#define	EPOLLWAKEUP	(1u << 29)
#define	EPOLLONESHOT	(1u << 30)
#define	EPOLLET		(1u << 31)
#define	EPOLL_CTL_ADD	1
#define	EPOLL_CTL_DEL	2
#define	EPOLL_CTL_MOD	3

#define	SA_SIGINFO		0x00000004
#define	SA_UNSUPPORTED		0x00000400
#define	SA_EXPOSE_TAGBITS	0x00000800
#define	SA_RESTORER		0x04000000
#define	SA_RESTART		0x10000000
#define	SIGUSR1			10
#define	SIGCHLD			17

#define	CLONE_PIDFD		0x00001000ULL
#define	CLONE_NEWTIME		0x00000080ULL
#define	CLONE_INTO_CGROUP	0x200000000ULL

#define	SYS_write		1
#define	SYS_close		3
#define	SYS_poll		7
#define	SYS_clone		56
#define	SYS_rt_sigaction	13
#define	SYS_pipe		22
#define	SYS_getpid		39
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_epoll_wait		232
#define	SYS_epoll_ctl		233
#define	SYS_epoll_create1	291
#define	SYS_clone3		435

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

/* Linux x86_64 requires SA_RESTORER; the restorer is rt_sigreturn(2). */
void restorer(void);
__asm__(".text\n.globl restorer\nrestorer:\n\tmov $15, %eax\n\tsyscall\n");

static volatile int got_signal;

static void
handler(int sig, void *info, void *ctx)
{
	(void)info;
	(void)ctx;
	got_signal = sig;
}

static long
epoll_ctl(long epfd, long op, long fd, unsigned int events)
{
	struct epoll_event ev = { events, 0x1234 };

	return (call(SYS_epoll_ctl, epfd, op, fd, (long)&ev, 0, 0));
}

static long
clone3(struct clone_args *ca, long usize)
{
	return (call(SYS_clone3, (long)ca, usize, 0, 0, 0, 0));
}

static int
test(void)
{
	struct epoll_event evs[4];
	struct kernel_sigaction sa, old;
	struct clone_args ca;
	unsigned char cabuf[96];
	struct pollfd pfd;
	int pipes[2], tids[2], status, pidfd, i;
	long epfd, epfd2, pid, r;

	/* --- epoll --- */
	epfd = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	if (epfd < 0) return (1);
	if (call(SYS_pipe, (long)pipes, 0, 0, 0, 0, 0) != 0) return (2);
	/* 3: EXCLUSIVE and WAKEUP are hints; ADD with OK bits succeeds. */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipes[0],
	    EPOLLIN | EPOLLET | EPOLLEXCLUSIVE | EPOLLWAKEUP) != 0) return (3);
	/* 4: Linux: EPOLLEXCLUSIVE with EPOLL_CTL_MOD is EINVAL. */
	if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipes[0],
	    EPOLLIN | EPOLLEXCLUSIVE) != -22) return (4);
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, pipes[0], 0) != 0) return (5);
	/* 6: EPOLLONESHOT is not in EPOLLEXCLUSIVE_OK_BITS: EINVAL. */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipes[0],
	    EPOLLIN | EPOLLONESHOT | EPOLLEXCLUSIVE) != -22) return (6);
	/* 7: EPOLLRDHUP is not in EPOLLEXCLUSIVE_OK_BITS: EINVAL. */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipes[0],
	    EPOLLIN | EPOLLRDHUP | EPOLLEXCLUSIVE) != -22) return (7);
	/* 8: EPOLLEXCLUSIVE on a nested epoll instance: EINVAL. */
	epfd2 = call(SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
	if (epfd2 < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, epfd2,
	    EPOLLIN | EPOLLEXCLUSIVE) != -22) return (8);
	/* 9: ET|ONESHOT|WAKEUP (no EXCLUSIVE) registers fine. */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipes[0],
	    EPOLLIN | EPOLLET | EPOLLONESHOT | EPOLLWAKEUP) != 0) return (9);
	/* 10/11: a write wakes epoll_wait with EPOLLIN and our data. */
	if (call(SYS_write, pipes[1], (long)"x", 1, 0, 0, 0) != 1) return (10);
	r = call(SYS_epoll_wait, epfd, (long)evs, 4, 1000, 0, 0);
	if (r != 1 || (evs[0].events & EPOLLIN) == 0 || evs[0].data != 0x1234)
		return (11);
	/* 12: EPOLLONESHOT disarmed the entry: nothing more is reported. */
	if (call(SYS_epoll_wait, epfd, (long)evs, 4, 0, 0, 0) != 0)
		return (12);
	/* 13/14: EPOLL_CTL_MOD (no EXCLUSIVE) re-arms it; data still there. */
	if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipes[0], EPOLLIN) != 0) return (13);
	if (call(SYS_epoll_wait, epfd, (long)evs, 4, 0, 0, 0) != 1)
		return (14);
	/* 15: bits kqueue cannot honour (EPOLLMSG) are rejected with EINVAL. */
	if (epoll_ctl(epfd, EPOLL_CTL_MOD, pipes[0], EPOLLIN | EPOLLMSG) != -22)
		return (15);

	/* --- rt_sigaction --- */
	sa.handler = (void *)handler;
	sa.flags = SA_RESTORER | SA_SIGINFO | SA_RESTART | SA_UNSUPPORTED |
	    SA_EXPOSE_TAGBITS | 0x20;
	sa.restorer = (void *)restorer;
	sa.mask = 0;
	/* 16: unknown/probe flags are masked, not rejected. */
	if (call(SYS_rt_sigaction, SIGUSR1, (long)&sa, 0, 8, 0, 0) != 0)
		return (16);
	for (i = 0; i < (int)sizeof(old); i++)
		((char *)&old)[i] = 0;
	if (call(SYS_rt_sigaction, SIGUSR1, 0, (long)&old, 8, 0, 0) != 0)
		return (17);
	/* 18: SA_UNSUPPORTED is never reported back (Linux 5.11 probing). */
	if ((old.flags & SA_UNSUPPORTED) != 0) return (18);
	/* 19: undefined bits are cleared as well. */
	if ((old.flags & 0x20) != 0) return (19);
	/* 20: the mapped flags survive the round trip. */
	if ((old.flags & (SA_SIGINFO | SA_RESTART)) != (SA_SIGINFO | SA_RESTART))
		return (20);
	if (old.handler != (void *)handler) return (21);
	/* 22/23: the handler actually runs. */
	pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
	if (call(SYS_kill, pid, SIGUSR1, 0, 0, 0, 0) != 0) return (22);
	if (got_signal != SIGUSR1) return (23);

	/* --- clone3 --- */
	for (i = 0; i < (int)sizeof(ca); i++)
		((char *)&ca)[i] = 0;
	ca.exit_signal = SIGCHLD;
	/* 24: CLONE_INTO_CGROUP: no fd can be a cgroup2 directory: EBADF. */
	ca.flags = CLONE_INTO_CGROUP;
	ca.cgroup = 0;
	if (clone3(&ca, 88) != -9) return (24);
	/* 25: CLONE_INTO_CGROUP needs CLONE_ARGS_SIZE_VER2 (88): EINVAL. */
	if (clone3(&ca, 64) != -22) return (25);
	/* 26: CLONE_NEWTIME (no time namespaces): EINVAL. */
	ca.flags = CLONE_NEWTIME;
	if (clone3(&ca, 64) != -22) return (26);
	/* 27: bigger struct with a nonzero tail: E2BIG. */
	for (i = 0; i < (int)sizeof(cabuf); i++)
		cabuf[i] = 0;
	cabuf[32] = SIGCHLD;		/* exit_signal */
	cabuf[90] = 1;
	if (call(SYS_clone3, (long)cabuf, 96, 0, 0, 0, 0) != -7) return (27);
	/* 28: set_tid deeper than the pid namespace nesting: EINVAL. */
	ca.flags = 0;
	tids[0] = 12345;
	tids[1] = 12345;
	ca.set_tid = (unsigned long)tids;
	ca.set_tid_size = 2;
	if (clone3(&ca, 88) != -22) return (28);
	/* 29: set_tid with an invalid pid: EINVAL. */
	tids[0] = 0;
	ca.set_tid_size = 1;
	if (clone3(&ca, 88) != -22) return (29);
	/* 30: a valid set_tid: EPERM unprivileged (ENOSYS as root). */
	tids[0] = 12345;
	r = clone3(&ca, 88);
	if (r != -1 && r != -38) return (30);
	ca.set_tid = 0;
	ca.set_tid_size = 0;
	/* 31-33: plain clone3 forks; the child exits 7 and wait4 reaps it. */
	pid = clone3(&ca, 64);
	if (pid == 0)
		call(60, 7, 0, 0, 0, 0, 0);
	if (pid < 0) return (31);
	status = 0;
	if (call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid) return (32);
	if (((status >> 8) & 0xff) != 7) return (33);
	/*
	 * 34-38: CLONE_PIDFD delivers a pidfd for the child before it runs;
	 * the fd becomes readable when the child exits and the child can
	 * then be reaped at once.  Legacy clone() with CLONE_PIDFD and
	 * CLONE_PARENT_SETTID together is EINVAL.
	 */
	ca.flags = CLONE_PIDFD;
	pidfd = -1;
	ca.pidfd = (unsigned long)&pidfd;
	pid = clone3(&ca, 88);
	if (pid == 0)
		call(60, 3, 0, 0, 0, 0, 0);
	if (pid < 0 || pidfd < 0) return (34);
	pfd.fd = pidfd;
	pfd.events = 1;
	pfd.revents = 0;
	if (call(SYS_poll, (long)&pfd, 1, 5000, 0, 0, 0) != 1) return (35);
	if (call(SYS_wait4, pid, (long)&status, 1, 0, 0, 0) != pid) return (36);
	if (((status >> 8) & 0xff) != 3) return (37);
	call(SYS_close, pidfd, 0, 0, 0, 0, 0);
	if (call(SYS_clone, CLONE_PIDFD | 0x00100000 | SIGCHLD, 0, (long)&pidfd,
	    0, 0, 0) != -22)
		return (38);
	return (0);
}

/*
 * The process entry stack is 16-byte aligned, one slot off from what a
 * called function expects; realign so vectorised stores do not fault.
 */
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
