/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial signalfd(2): four readers draining one descriptor while four
 * senders queue value-carrying RT signals (every value read exactly once,
 * none lost, none duplicated); queue overflow must surface as EAGAIN to
 * the sender, never as a silently lost value; a thread-directed signal is
 * readable only by that thread; dup()ed descriptors share the queue;
 * pending signals are not inherited by fork; EPOLLET gives one edge per
 * arrival; close() under blocked readers is safe.  Exit status = failed
 * check number.
 */
#include "linux_test.h"

#define	SYS_signalfd4		289
#define	SYS_rt_sigqueueinfo	129
#define	SYS_rt_tgsigqueueinfo	297
#define	SIGRTMIN		34
#define	SI_QUEUE		-1
#define	POLLIN			1
#define	EPOLLIN			1
#define	EPOLLET			(1u << 31)
#define	EPOLL_CTL_ADD		1
#define	NREAD			4
#define	NSEND			4
#define	SYS_clock_gettime	228
#define	CLOCK_MONOTONIC		1
#define	PER_SENDER		60

static long
now_ms(void)
{
	struct { long sec, nsec; } ts;

	if (sys2(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return (ts.sec * 1000 + ts.nsec / 1000000);
}

struct sfd_si {
	unsigned int signo; int errno_; int code; unsigned int pid, uid;
	int fd; unsigned int tid, band, overrun, trapno; int status, sint;
	unsigned long ptr, utime, stime, addr; unsigned short addr_lsb, pad2;
	int syscall_; unsigned long call_addr; unsigned int arch;
	unsigned char pad[28];
};
struct siginfo_l { int signo, errno_, code, pad; long pid_uid; long val; long rest[10]; };
struct pollfd { int fd; short events, revents; };
struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));

static long
sigqueue_val(long pid, int sig, int val)
{
	struct siginfo_l si;

	xmemset(&si, 0, sizeof(si));
	si.signo = sig; si.code = SI_QUEUE; si.val = val;
	return (sys3(SYS_rt_sigqueueinfo, pid, sig, &si));
}

static long
tgsigqueue_val(long pid, long tid, int sig, int val)
{
	struct siginfo_l si;

	xmemset(&si, 0, sizeof(si));
	si.signo = sig; si.code = SI_QUEUE; si.val = val;
	return (sys4(SYS_rt_tgsigqueueinfo, pid, tid, sig, &si));
}

static void
block_sig(int sig)
{
	unsigned long set = 1UL << (sig - 1);

	(void)sys4(SYS_rt_sigprocmask, SIG_BLOCK, &set, 0, 8);
}

/* --- storm --- */
static int storm_fd;
static long storm_pid;
static volatile int storm_total, storm_stop;
static volatile unsigned char seen[NSEND * PER_SENDER];
static volatile long dup_or_oob, send_eagain;

static int
reader(void *arg __attribute__((unused)))
{
	struct sfd_si si[8];
	struct pollfd pf;
	long r, i;

	long idle = 0, deadline = now_ms() + 60000;

	for (;;) {
		if (storm_stop && __atomic_load_n(&storm_total, __ATOMIC_ACQUIRE) >=
		    NSEND * PER_SENDER)
			return (0);
		if (now_ms() > deadline)	/* never hang the suite */
			return (3);
		if (storm_stop && ++idle > 50)	/* 5 s with nothing: values lost */
			return (2);
		pf.fd = storm_fd; pf.events = POLLIN; pf.revents = 0;
		r = sys3(SYS_poll, &pf, 1, 100);
		if (r <= 0)
			continue;
		r = sys3(SYS_read, storm_fd, si, sizeof(si));
		if (r == -EAGAIN)
			continue;
		if (r <= 0)
			return (1);
		for (i = 0; i < r / (long)sizeof(si[0]); i++) {
			int v = si[i].sint;

			if (v < 0 || v >= NSEND * PER_SENDER ||
			    __atomic_fetch_add(&seen[v], 1, __ATOMIC_ACQ_REL) != 0)
				__atomic_fetch_add(&dup_or_oob, 1, __ATOMIC_ACQ_REL);
			__atomic_fetch_add(&storm_total, 1, __ATOMIC_ACQ_REL);
		}
	}
}

static int
sender(void *arg)
{
	long s = (long)arg, i, r;

	for (i = 0; i < PER_SENDER; i++) {
		/* retry on EAGAIN (queue full): the value must never be dropped */
		long deadline = now_ms() + 60000;

		for (;;) {
			r = sigqueue_val(storm_pid, SIGRTMIN, s * PER_SENDER + i);
			if (r == 0)
				break;
			if (r != -EAGAIN)
				return (1);
			if (now_ms() > deadline)	/* readers starved: bail, no hang */
				return (2);
			__atomic_fetch_add(&send_eagain, 1, __ATOMIC_ACQ_REL);
			(void)sys0(SYS_sched_yield);
		}
	}
	return (0);
}

/* --- thread-directed --- */
static int td_fd;
static volatile int td_tid, td_go, td_result;
static int
td_thread(void *arg __attribute__((unused)))
{
	struct sfd_si si;
	struct pollfd pf;
	long r;

	block_sig(SIGRTMIN + 1);
	__atomic_store_n(&td_tid, (int)sys0(SYS_gettid), __ATOMIC_RELEASE);
	while (!__atomic_load_n(&td_go, __ATOMIC_ACQUIRE))
		(void)sys0(SYS_sched_yield);
	pf.fd = td_fd; pf.events = POLLIN; pf.revents = 0;
	if (sys3(SYS_poll, &pf, 1, 5000) != 1) { td_result = 1; return (0); }
	r = sys3(SYS_read, td_fd, &si, sizeof(si));
	if (r != (long)sizeof(si) || si.signo != SIGRTMIN + 1 || si.sint != 4242)
		td_result = 2;
	else
		td_result = 3;	/* got it */
	return (0);
}

static int blocked_fd;
static int
blocked_reader(void *arg __attribute__((unused)))
{
	struct sfd_si si;
	struct pollfd pf;
	long r;

	/* Wait for the signal, but bounded: a poll timeout returns cleanly
	 * rather than blocking the suite forever if a wakeup is missed. */
	pf.fd = blocked_fd; pf.events = POLLIN; pf.revents = 0;
	r = sys3(SYS_poll, &pf, 1, 10000);
	if (r != 1)
		return (0);
	r = sys3(SYS_read, blocked_fd, &si, sizeof(si));
	return (r == (long)sizeof(si) ? 0 : 1);
}

static int
fork_child(void *arg)
{
	struct sfd_si si;
	int fd = (int)(long)arg;

	/* nothing pending was inherited: a non-blocking read is EAGAIN */
	if (sys3(SYS_read, fd, &si, sizeof(si)) != -EAGAIN) return (1);
	return (0);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	struct thread th[NREAD + NSEND];
	struct sfd_si si[4];
	struct epoll_event ev;
	unsigned long mask;
	long pid, fd, fd2, r, i, accepted, got, ep;

	pid = sys0(SYS_getpid);
	block_sig(SIGRTMIN);
	block_sig(SIGRTMIN + 1);
	block_sig(SIGRTMIN + 2);

	msg("bsfd: 1-3\n");
	/* 1-3: storm - 4 readers, 4 senders, exactly-once values. */
	mask = 1UL << (SIGRTMIN - 1);
	fd = sys4(SYS_signalfd4, -1, &mask, 8, O_NONBLOCK);
	if (fd < 0) return (1);
	storm_fd = fd; storm_pid = pid;
	for (i = 0; i < NREAD; i++)
		if (thread_create(&th[i], reader, 0) != 0) return (1);
	for (i = 0; i < NSEND; i++)
		if (thread_create(&th[NREAD + i], sender, (void *)i) != 0) return (1);
	for (i = 0; i < NSEND; i++)
		if (thread_join(&th[NREAD + i]) != 0) return (2);
	storm_stop = 1;
	for (i = 0; i < NREAD; i++)
		if (thread_join(&th[i]) != 0) return (2);
	if (storm_total != NSEND * PER_SENDER) { msgnum("storm total ", storm_total); return (3); }
	if (dup_or_oob != 0) { msgnum("storm dup/oob ", dup_or_oob); return (3); }
	for (i = 0; i < NSEND * PER_SENDER; i++)
		if (seen[i] != 1) { msgnum("storm missing value ", i); return (3); }
	msgnum("storm sender EAGAIN retries ", send_eagain);
	(void)sys1(SYS_close, fd);

	msg("bsfd: 4-5\n");
	/* 4-5: overflow is EAGAIN to the sender, never a lost value. */
	mask = 1UL << (SIGRTMIN + 2 - 1);
	fd = sys4(SYS_signalfd4, -1, &mask, 8, O_NONBLOCK);
	if (fd < 0) return (4);
	accepted = 0;
	for (i = 0; i < 100000; i++) {
		r = sigqueue_val(pid, SIGRTMIN + 2, i);
		if (r == -EAGAIN)
			break;
		if (r != 0) { msgnum("overflow send ", r); return (4); }
		accepted++;
	}
	if (accepted == 0) return (4);
	msgnum("queue accepted before EAGAIN ", accepted);
	got = 0;
	for (;;) {
		r = sys3(SYS_read, fd, si, sizeof(si));
		if (r == -EAGAIN)
			break;
		if (r <= 0) return (5);
		for (i = 0; i < r / (long)sizeof(si[0]); i++, got++)
			if (si[i].sint != got) { msgnum("overflow value at ", got); msgnum(" got ", si[i].sint); return (5); }
	}
	if (got != accepted) { msgnum("overflow read ", got); msgnum(" accepted ", accepted); return (5); }
	(void)sys1(SYS_close, fd);

	msg("bsfd: 6-7\n");
	/* 6-7: thread-directed signal only readable by that thread. */
	mask = 1UL << (SIGRTMIN + 1 - 1);
	td_fd = sys4(SYS_signalfd4, -1, &mask, 8, O_NONBLOCK);
	if (td_fd < 0) return (6);
	if (thread_create(&th[0], td_thread, 0) != 0) return (6);
	while (__atomic_load_n(&td_tid, __ATOMIC_ACQUIRE) == 0)
		(void)sys0(SYS_sched_yield);
	if (tgsigqueue_val(pid, td_tid, SIGRTMIN + 1, 4242) != 0) return (6);
	sleep_ms(20);
	/* the main thread must not see it */
	r = sys3(SYS_read, td_fd, si, sizeof(si[0]));
	if (r != -EAGAIN) { msgnum("main read thread-directed ", r); return (7); }
	__atomic_store_n(&td_go, 1, __ATOMIC_RELEASE);
	if (thread_join(&th[0]) != 0) return (7);
	if (td_result != 3) { msgnum("thread result ", td_result); return (7); }
	(void)sys1(SYS_close, td_fd);

	msg("bsfd: 8\n");
	/* 8: dup'ed descriptors share one queue. */
	mask = 1UL << (SIGRTMIN - 1);
	fd = sys4(SYS_signalfd4, -1, &mask, 8, O_NONBLOCK);
	fd2 = sys1(SYS_dup, fd);
	if (fd < 0 || fd2 < 0) return (8);
	if (sigqueue_val(pid, SIGRTMIN, 7) != 0) return (8);
	if (sys3(SYS_read, fd2, si, sizeof(si[0])) != (long)sizeof(si[0]) || si[0].sint != 7) return (8);
	if (sys3(SYS_read, fd, si, sizeof(si[0])) != -EAGAIN) return (8);

	msg("bsfd: 9\n");
	/* 9: pending signals are not inherited by fork. */
	for (i = 0; i < 10; i++)
		if (sigqueue_val(pid, SIGRTMIN, 100 + i) != 0) return (9);
	r = run_child(fork_child, (void *)fd);
	if (r != 0) { msgnum("fork child ", r); return (9); }
	for (i = 0; i < 10; i++) {
		if (sys3(SYS_read, fd, si, sizeof(si[0])) != (long)sizeof(si[0])) return (9);
		if (si[0].sint != 100 + i) return (9);
	}

	msg("bsfd: 10-11\n");
	/* 10-11: EPOLLET: one edge per arrival, none while drained. */
	ep = sys1(SYS_epoll_create1, 0);
	if (ep < 0) return (10);
	ev.events = EPOLLIN | EPOLLET; ev.data = 1;
	if (sys4(SYS_epoll_ctl, ep, EPOLL_CTL_ADD, fd, &ev) != 0) return (10);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 0) return (10);	/* drained */
	if (sigqueue_val(pid, SIGRTMIN, 1) != 0) return (10);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 1000) != 1) return (10);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 0) return (11);	/* edge consumed */
	if (sigqueue_val(pid, SIGRTMIN, 2) != 0) return (11);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 1000) != 1) return (11);	/* new edge */
	if (sys3(SYS_read, fd, si, sizeof(si)) != 2 * (long)sizeof(si[0])) return (11);
	if (sys4(SYS_epoll_wait, ep, &ev, 1, 0) != 0) return (11);

	msg("bsfd: 12\n");
	/* 12: close() under blocked readers: they keep their reference and
	 * finish when a signal arrives. */
	mask = 1UL << (SIGRTMIN - 1);
	blocked_fd = sys4(SYS_signalfd4, -1, &mask, 8, 0);
	if (blocked_fd < 0) return (12);
	for (i = 0; i < NREAD; i++)
		if (thread_create(&th[i], blocked_reader, 0) != 0) return (12);
	sleep_ms(50);
	(void)sys1(SYS_close, blocked_fd);
	for (i = 0; i < 2 * NREAD; i++)
		(void)sigqueue_val(pid, SIGRTMIN, 9);
	for (i = 0; i < NREAD; i++)
		if (thread_join(&th[i]) != 0) return (12);
	return (0);
}
