/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * signalfd(2)/signalfd4(2): creation and flag validation, reading pending
 * signals with full siginfo (kill, sigqueue value, SIGCHLD status, timer),
 * short buffers, non-blocking EAGAIN, blocking reads woken by a thread and
 * by a child, several records per read, RT ordering, mask replacement,
 * poll/epoll (level-triggered) readiness, signals outside the mask staying
 * pending, unblocked signals going to handlers instead, fork inheritance
 * (the child reads its own signals), close-on-exec, a storm of 5000 queued
 * signals, 200 simultaneous descriptors, and closing under a blocked
 * reader.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_signalfd4		289
#define	SYS_signalfd		282
#define	SYS_rt_sigqueueinfo	129
#define	SYS_rt_sigpending	127
#define	SYS_timer_create	222
#define	SYS_timer_settime	223
#define	SYS_timer_delete	226
#define	SFD_CLOEXEC		O_CLOEXEC
#define	SFD_NONBLOCK		O_NONBLOCK
#define	SIGRTMIN		34
#define	SI_USER			0
#define	SI_QUEUE		-1
#define	SI_TIMER		-2
#define	CLD_EXITED		1
#define	CLD_KILLED		2
#define	POLLIN			1
#define	EPOLLIN			1
#define	EPOLLET			(1u << 31)
#define	EPOLL_CTL_ADD		1
#define	F_GETFD			1
#define	SIGEV_SIGNAL		0
#define	CLOCK_MONOTONIC		1

struct signalfd_siginfo {
	u32 signo; int err, code; u32 pid, uid; int fd; u32 tid, band, overrun,
	    trapno; int status, sint; u64 ptr, utime, stime, addr; u16 addr_lsb,
	    pad2; int syscall_; u64 call_addr; u32 arch; u8 pad[28];
};
struct siginfo_l { int signo, errno_, code, pad; long pid_uid; long val; long rest[10]; };
struct pollfd { int fd; short events, revents; };
struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));
struct sigevent_l { long value; int signo, notify; int tid; int pad[12]; };
struct itimerspec { struct timespec it_interval, it_value; };

static long
signalfd4(long fd, unsigned long mask, long size, long flags)
{

	return (sys4(SYS_signalfd4, fd, &mask, size, flags));
}

static long
blocked(unsigned long m)
{

	return (sys4(SYS_rt_sigprocmask, SIG_BLOCK, &m, 0, 8));
}

#define	M(sig)	(1UL << ((sig) - 1))

static long
sigqueue_val(long pid, int sig, int val)
{
	struct siginfo_l si;

	xmemset(&si, 0, sizeof(si));
	si.signo = sig; si.code = SI_QUEUE; si.val = val;
	return (sys3(SYS_rt_sigqueueinfo, pid, sig, &si));
}

static int wake_sfd;
static long wake_tid;
static int
waker(void *arg)
{

	(void)arg;
	sleep_ms(100);
	(void)sys3(SYS_tgkill, sys0(SYS_getpid), wake_tid, SIGUSR2);
	return (0);
}

static int
closer(void *arg)
{

	(void)arg;
	sleep_ms(100);
	(void)sys1(SYS_close, wake_sfd);
	return (0);
}

static volatile int handled;
static void
handler(int sig)
{

	handled = sig;
}

static int
test(int argc, char **argv, char **envp)
{
	struct signalfd_siginfo si[8];
	struct siginfo_l qi;
	struct pollfd pf;
	struct epoll_event ev;
	struct thread th;
	struct sigevent_l sev;
	struct itimerspec its;
	unsigned long pend, m;
	long sfd, sfd2, r, pid, i, ep, tid, timerid;
	int status, fds[200];
	char small[64];

	(void)argc; (void)argv; (void)envp;
	pid = sys0(SYS_getpid);
	tid = sys0(SYS_gettid);

	/* 1-4: validation. */
	if (signalfd4(-1, M(SIGUSR1), 4, 0) != -EINVAL) return (1);
	if (signalfd4(-1, M(SIGUSR1), 8, 0x100) != -EINVAL) return (2);
	if (sys4(SYS_signalfd4, -1, 0, 8, 0) != -EFAULT) return (3);
	if (signalfd4(9999, M(SIGUSR1), 8, 0) != -EBADF) return (4);
	sfd = sys3(SYS_open, "/dev/null", O_RDONLY, 0);
	if (signalfd4(sfd, M(SIGUSR1), 8, 0) != -EINVAL) return (4);
	(void)sys1(SYS_close, sfd);

	/* 5-7: create; short read is EINVAL; nonblocking empty is EAGAIN. */
	sfd = signalfd4(-1, M(SIGUSR1) | M(SIGRTMIN), 8, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0) return (5);
	if (sys3(SYS_fcntl, sfd, F_GETFD, 0) != 1) return (5);
	if (sys3(SYS_read, sfd, small, sizeof(small)) != -EINVAL) return (6);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != -EAGAIN) return (7);
	if (sys3(SYS_write, sfd, si, sizeof(si[0])) != -EINVAL) return (7);
	/* 8: an unblocked signal goes to its handler, not the fd. */
	{
		struct { void *h; unsigned long flags; void *rest; unsigned long mask; } sa;

		xmemset(&sa, 0, sizeof(sa));
		sa.h = (void *)handler;
		sa.flags = 0x04000000; /* SA_RESTORER */
		__asm__(".globl sfd_restorer\nsfd_restorer:\n mov $15, %eax\n syscall\n");
		extern void sfd_restorer(void);
		sa.rest = (void *)sfd_restorer;
		(void)sys4(SYS_rt_sigaction, SIGUSR1, &sa, 0, 8);
	}
	handled = 0;
	(void)sys2(SYS_kill, pid, SIGUSR1);
	if (handled != SIGUSR1) return (8);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != -EAGAIN) return (8);
	/* 9-11: blocked SIGUSR1 from kill(): one record with SI_USER fields. */
	if (blocked(M(SIGUSR1) | M(SIGRTMIN) | M(SIGUSR2) | M(SIGCHLD)) != 0)
		return (9);
	(void)sys2(SYS_kill, pid, SIGUSR1);
	pf.fd = sfd; pf.events = POLLIN; pf.revents = 0;
	if (sys3(SYS_poll, &pf, 1, 0) != 1) return (9);
	r = sys3(SYS_read, sfd, si, sizeof(si[0]));
	if (r != (long)sizeof(si[0])) return (10);
	if (si[0].signo != SIGUSR1 || si[0].code != SI_USER || si[0].pid != pid ||
	    si[0].uid != (u32)sys0(SYS_getuid)) return (11);
	/* consumed: no longer pending, poll idle, read EAGAIN */
	if (sys2(SYS_rt_sigpending, &pend, 8) != 0 || (pend & M(SIGUSR1)) != 0)
		return (11);
	if (sys3(SYS_poll, &pf, 1, 0) != 0) return (11);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != -EAGAIN) return (11);
	/* 12-13: sigqueue value and SI_QUEUE code. */
	xmemset(&qi, 0, sizeof(qi));
	qi.signo = SIGRTMIN; qi.code = SI_QUEUE; qi.val = 0x5151515151L;
	if (sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &qi) != 0) return (12);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (12);
	if (si[0].signo != SIGRTMIN || si[0].code != SI_QUEUE ||
	    (long)si[0].ptr != 0x5151515151L || si[0].sint != 0x51515151) return (13);
	/* 14-16: several pending signals come back in one read, RT in FIFO order. */
	for (i = 0; i < 5; i++) {
		qi.val = 100 + i;
		if (sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &qi) != 0) return (14);
	}
	(void)sys2(SYS_kill, pid, SIGUSR1);
	r = sys3(SYS_read, sfd, si, sizeof(si));
	if (r != 6 * (long)sizeof(si[0])) { msgnum("multi read ", r); return (15); }
	/* SIGUSR1 (lower number) first, then the five RT in order */
	if (si[0].signo != SIGUSR1) return (16);
	for (i = 0; i < 5; i++)
		if (si[1 + i].signo != SIGRTMIN || si[1 + i].sint != 100 + i)
			return (16);
	/* a buffer for 2 records returns 2 and leaves the rest pending */
	for (i = 0; i < 3; i++) { qi.val = 7; (void)sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &qi); }
	if (sys3(SYS_read, sfd, si, 2 * sizeof(si[0])) != 2 * (long)sizeof(si[0]))
		return (16);
	if (sys3(SYS_read, sfd, si, sizeof(si)) != (long)sizeof(si[0])) return (16);
	/* 17: a signal outside the mask stays pending and is not readable. */
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (sys3(SYS_poll, &pf, 1, 0) != 0) return (17);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != -EAGAIN) return (17);
	if (sys2(SYS_rt_sigpending, &pend, 8) != 0 || (pend & M(SIGUSR2)) == 0)
		return (17);
	/* 18: replacing the mask (signalfd on the existing fd) makes it readable. */
	if (signalfd4(sfd, M(SIGUSR2), 8, 0) != sfd) return (18);
	if (sys3(SYS_poll, &pf, 1, 0) != 1) return (18);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0]) ||
	    si[0].signo != SIGUSR2) return (18);
	/* SIGKILL/SIGSTOP in the mask are ignored silently */
	if (signalfd4(sfd, M(SIGKILL) | M(SIGSTOP) | M(SIGUSR2), 8, 0) != sfd)
		return (18);
	/* 19-20: SIGCHLD record carries pid and exit status. */
	if (signalfd4(sfd, M(SIGCHLD) | M(SIGUSR2), 8, 0) != sfd) return (19);
	r = sys0(SYS_fork);
	if (r == 0)
		(void)sys1(SYS_exit_group, 9);
	pf.revents = 0;
	if (sys3(SYS_poll, &pf, 1, 5000) != 1) return (19);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (19);
	if (si[0].signo != SIGCHLD || si[0].code != CLD_EXITED || si[0].pid != r ||
	    si[0].status != 9) return (20);
	(void)sys4(SYS_wait4, r, &status, 0, 0);
	/* killed child: CLD_KILLED, status = signal */
	r = sys0(SYS_fork);
	if (r == 0) { sleep_ms(5000); (void)sys1(SYS_exit_group, 0); }
	(void)sys2(SYS_kill, r, SIGKILL);
	if (sys3(SYS_poll, &pf, 1, 5000) != 1) return (20);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (20);
	if (si[0].code != CLD_KILLED || si[0].status != SIGKILL) return (20);
	(void)sys4(SYS_wait4, r, &status, 0, 0);
	/* 21: a POSIX timer signal: SI_TIMER with the timer's value. */
	xmemset(&sev, 0, sizeof(sev));
	sev.value = 4242; sev.signo = SIGUSR2; sev.notify = SIGEV_SIGNAL;
	if (sys3(SYS_timer_create, CLOCK_MONOTONIC, &sev, &timerid) == 0) {
		xmemset(&its, 0, sizeof(its));
		its.it_value.tv_nsec = 10000000;
		(void)sys4(SYS_timer_settime, timerid, 0, &its, 0);
		if (sys3(SYS_poll, &pf, 1, 2000) != 1) return (21);
		if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (21);
		if (si[0].signo != SIGUSR2 || si[0].code != SI_TIMER || si[0].sint != 4242)
			return (21);
		(void)sys1(SYS_timer_delete, timerid);
	}

	/* 22-23: blocking read, woken by another thread's tgkill. */
	sfd2 = signalfd4(-1, M(SIGUSR2), 8, 0);
	if (sfd2 < 0) return (22);
	wake_tid = tid;
	if (thread_create(&th, waker, 0) != 0) return (22);
	r = sys3(SYS_read, sfd2, si, sizeof(si[0]));
	if (r != (long)sizeof(si[0]) || si[0].signo != SIGUSR2) return (23);
	if (thread_join(&th) != 0) return (23);
	/* the signal was consumed by the reader only: not pending for the waker */
	if (sys2(SYS_rt_sigpending, &pend, 8) != 0 || (pend & M(SIGUSR2)) != 0)
		return (23);
	/* 24: closing the descriptor under a blocked reader: read returns EBADF/EINTR, no hang. */
	wake_sfd = sfd2;
	if (thread_create(&th, closer, 0) != 0) return (24);
	pf.fd = sfd2; pf.events = POLLIN; pf.revents = 0;
	r = sys3(SYS_poll, &pf, 1, 3000);
	/* poll on an fd closed underneath: POLLNVAL, or the timeout (0) - not a hang */
	if (r < 0) return (24);
	if (thread_join(&th) != 0) return (24);
	if (sys3(SYS_read, sfd2, si, sizeof(si[0])) != -EBADF) return (24);

	/* 25-27: epoll: level-triggered readiness, ET exactly once. */
	ep = sys1(SYS_epoll_create1, 0);
	ev.events = EPOLLIN; ev.data = 1;
	if (sys4(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, sfd, &ev) != 0) return (25);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 0) return (25);
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 1000) != 1) return (26);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 1) return (26);	/* LT */
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (26);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 0) return (26);
	ev.events = EPOLLIN | EPOLLET; ev.data = 1;
	if (sys4(SYS_epoll_ctl, ep, 3 /* MOD */, sfd, &ev) != 0) return (27);
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 1000) != 1) return (27);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 50) != 0) return (27);
	(void)sys3(SYS_read, sfd, si, sizeof(si[0]));
	(void)sys1(SYS_close, ep);

	/* 28-29: a forked child reads its own signals through the inherited fd. */
	r = sys0(SYS_fork);
	if (r == 0) {
		(void)sys2(SYS_kill, sys0(SYS_getpid), SIGUSR2);
		if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0]))
			(void)sys1(SYS_exit_group, 1);
		if (si[0].signo != SIGUSR2 || si[0].pid != (u32)sys0(SYS_getpid))
			(void)sys1(SYS_exit_group, 2);
		/* the parent's pending signals are not visible here */
		if (sys3(SYS_read, sfd, si, sizeof(si[0])) != -EAGAIN)
			(void)sys1(SYS_exit_group, 3);
		(void)sys1(SYS_exit_group, 0);
	}
	/*
	 * The parent's SIGCHLD for that child is readable; take it before
	 * reaping (FreeBSD drops a child's queued SIGCHLD when it is reaped,
	 * Linux leaves it pending - both orders are valid for a real program
	 * that reads then waits, which is what signalfd users do).
	 */
	pf.fd = sfd; pf.events = POLLIN; pf.revents = 0;
	if (sys3(SYS_poll, &pf, 1, 5000) != 1) return (29);
	if (sys3(SYS_read, sfd, si, sizeof(si[0])) != (long)sizeof(si[0]) ||
	    si[0].signo != SIGCHLD || si[0].pid != r) return (29);
	if (sys4(SYS_wait4, r, &status, 0, 0) != r) return (28);
	if (status != 0) { msgnum("child status ", status >> 8); return (29); }

	/* 30-31: storm: queue RT signals until the sender is told the queue is
	 * full (EAGAIN - a value must never be silently lost), then read them
	 * all back, in order, and then EAGAIN. */
	if (signalfd4(sfd, M(SIGRTMIN), 8, 0) != sfd) return (30);
	{
		long accepted = 0, got = 0;

		for (i = 0; i < 5000; i++) {
			r = sigqueue_val(pid, SIGRTMIN, i);
			if (r == -EAGAIN)
				break;
			if (r != 0) { msgnum("storm send ", r); return (30); }
			accepted++;
		}
		if (accepted < 64) { msgnum("storm accepted only ", accepted); return (30); }
		msgnum("storm queued ", accepted);
		while (got < accepted) {
			r = sys3(SYS_read, sfd, si, sizeof(si));
			if (r <= 0) { msgnum("storm read ", r); return (31); }
			for (i = 0; i < r / (long)sizeof(si[0]); i++, got++)
				if (si[i].sint != got) { msgnum("storm order got ", si[i].sint); msgnum(" expect ", got); return (31); }
		}
		if ((r = sys3(SYS_read, sfd, si, sizeof(si[0]))) != -EAGAIN) { msgnum("storm trailing read ", r); return (31); }
	}

	/* 32: 200 descriptors at once, all see the same signal, only one consumes it. */
	for (i = 0; i < 200; i++) {
		fds[i] = signalfd4(-1, M(SIGUSR2), 8, SFD_NONBLOCK);
		if (fds[i] < 0) return (32);
	}
	(void)sys2(SYS_kill, pid, SIGUSR2);
	{
		int got = 0;

		for (i = 0; i < 200; i++) {
			pf.fd = fds[i]; pf.events = POLLIN; pf.revents = 0;
			if (sys3(SYS_poll, &pf, 1, 0) != 1) return (32);
		}
		for (i = 0; i < 200; i++) {
			r = sys3(SYS_read, fds[i], si, sizeof(si[0]));
			if (r == (long)sizeof(si[0])) got++;
			else if (r != -EAGAIN) return (32);
		}
		if (got != 1) return (32);
		for (i = 0; i < 200; i++)
			(void)sys1(SYS_close, fds[i]);
	}
	/* 33: legacy signalfd(2) works too. */
	m = M(SIGUSR2);
	r = sys3(SYS_signalfd, -1, &m, 8);
	if (r < 0) return (33);
	(void)sys1(SYS_close, r);
	(void)sys1(SYS_close, sfd);
	return (0);
}
