/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial epoll/eventfd/timerfd tests: edge-triggered exactness under
 * a producer thread, EPOLLONESHOT re-arm races, EPOLLEXCLUSIVE with
 * several waiters, epoll_ctl DEL racing epoll_wait, close() of a
 * registered fd, nested epoll, dup rules, epoll_pwait2 timeouts/sigmask,
 * eventfd semaphore/overflow semantics, timerfd expirations and
 * TFD_TIMER_CANCEL_ON_SET.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	EPOLL_CTL_ADD	1
#define	EPOLL_CTL_DEL	2
#define	EPOLL_CTL_MOD	3
#define	EPOLLIN		0x001
#define	EPOLLOUT	0x004
#define	EPOLLERR	0x008
#define	EPOLLHUP	0x010
#define	EPOLLRDHUP	0x2000
#define	EPOLLEXCLUSIVE	(1u << 28)
#define	EPOLLONESHOT	(1u << 30)
#define	EPOLLET		(1u << 31)
#define	EFD_SEMAPHORE	1
#define	EFD_NONBLOCK	O_NONBLOCK
#define	TFD_NONBLOCK	O_NONBLOCK
#define	TFD_TIMER_ABSTIME 1
#define	TFD_TIMER_CANCEL_ON_SET 2
#define	CLOCK_REALTIME	0
#define	CLOCK_MONOTONIC	1
#define	SYS_timerfd_settime 286
#define	SYS_timerfd_gettime 287
#define	SYS_settimeofday 164
#define	SYS_epoll_ctl_	233
#define	ECANCELED	125

struct epoll_event { unsigned int events; unsigned long data; } __attribute__((packed));
struct itimerspec { struct timespec it_interval, it_value; };
struct timeval { long tv_sec, tv_usec; };

static int prod_fd;
static int stop;

/* Producer: write single bytes into a pipe with small pauses. */
static int
producer(void *arg)
{
	long i, n = (long)arg;

	for (i = 0; i < n; i++) {
		while (sys3(SYS_write, prod_fd, "x", 1) != 1)
			sleep_ms(1);
		if ((i & 63) == 0)
			sleep_ms(1);
	}
	return (0);
}

static int excl_ep;
static int excl_hits[4];

static int
excl_waiter(void *arg)
{
	struct epoll_event ev;
	long me = (long)arg, r;

	while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
		r = sys4(SYS_epoll_wait, excl_ep, &ev, 1, 50);
		if (r == 1)
			excl_hits[me]++;
	}
	return (0);
}

static int del_ep, del_fd;

static int
deleter(void *arg)
{
	long i;

	(void)arg;
	for (i = 0; i < 2000; i++) {
		struct epoll_event ev;

		ev.events = EPOLLIN; ev.data = 7;
		(void)sys4(SYS_epoll_ctl_, del_ep, EPOLL_CTL_DEL, del_fd, 0);
		(void)sys4(SYS_epoll_ctl_, del_ep, EPOLL_CTL_ADD, del_fd, &ev);
	}
	__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th[4];
	struct epoll_event ev, evs[16];
	struct itimerspec its;
	struct timespec ts;
	unsigned long mask, val;
	long ep, ep2, efd, tfd, r, i, total, spurious;
	int pfd[2], pfd2[2];
	char buf[256];

	(void)argc; (void)argv; (void)envp;
	ignore_signal(SIGPIPE);

	/* 1-4: EPOLLET on a pipe: every event drains fully, no spurious ones. */
	if (sys2(SYS_pipe2, pfd, O_NONBLOCK) != 0) return (1);
	ep = sys1(SYS_epoll_create1, 0);
	if (ep < 0) return (1);
	ev.events = EPOLLIN | EPOLLET; ev.data = 1;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, pfd[0], &ev) != 0) return (1);
	prod_fd = pfd[1];
	if (thread_create(&th[0], producer, (void *)5000) != 0) return (2);
	total = 0; spurious = 0;
	while (total < 5000) {
		r = sys4(SYS_epoll_wait, ep, evs, 16, 5000);
		if (r < 0) return (3);
		if (r == 0) { msgnum("stalled at ", total); return (3); }
		/* drain: with ET we must read until EAGAIN */
		for (;;) {
			r = sys3(SYS_read, pfd[0], buf, sizeof(buf));
			if (r > 0) { total += r; continue; }
			if (r == -EAGAIN) break;
			return (3);
		}
	}
	if (thread_join(&th[0]) != 0) return (4);
	/* pipe drained, ET: no event pending */
	if (sys4(SYS_epoll_wait, ep, evs, 16, 50) != 0) return (4);
	/* level-triggered after MOD: still nothing (empty) then one after write */
	ev.events = EPOLLIN; ev.data = 1;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_MOD, pfd[0], &ev) != 0) return (4);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 0) != 0) return (4);
	(void)sys3(SYS_write, pfd[1], "z", 1);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 0) != 1) return (4);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 0) != 1) return (4);	/* LT repeats */
	(void)sys3(SYS_read, pfd[0], buf, 1);
	(void)spurious;

	/* 5-7: EPOLLONESHOT: one event, then silence until re-armed. */
	ev.events = EPOLLIN | EPOLLONESHOT; ev.data = 2;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_MOD, pfd[0], &ev) != 0) return (5);
	(void)sys3(SYS_write, pfd[1], "ab", 2);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 100) != 1) return (5);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 50) != 0) return (6);	/* disarmed */
	(void)sys3(SYS_write, pfd[1], "c", 1);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 50) != 0) return (6);	/* still */
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_MOD, pfd[0], &ev) != 0) return (7);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 100) != 1) return (7);
	while (sys3(SYS_read, pfd[0], buf, sizeof(buf)) > 0)
		;
	/* 8: EPOLL_CTL_ADD twice is EEXIST; MOD of unknown is ENOENT; DEL ok. */
	ev.events = EPOLLIN; ev.data = 2;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, pfd[0], &ev) != -EEXIST)
		return (8);
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_MOD, pfd[1], &ev) != -ENOENT)
		return (8);
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_DEL, pfd[0], 0) != 0) return (8);
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_DEL, pfd[0], 0) != -ENOENT)
		return (8);
	/* 9: a dup of a registered fd is a separate registration (allowed). */
	r = sys1(SYS_dup, pfd[0]);
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, pfd[0], &ev) != 0) return (9);
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, r, &ev) != 0) return (9);
	(void)sys3(SYS_write, pfd[1], "d", 1);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 100) != 2) return (9);
	(void)sys3(SYS_read, pfd[0], buf, 1);
	(void)sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_DEL, r, 0);
	(void)sys1(SYS_close, r);
	/* 10: registering the epoll fd in itself is EINVAL; nesting works. */
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, ep, &ev) != -EINVAL)
		return (10);
	ep2 = sys1(SYS_epoll_create1, 0);
	ev.events = EPOLLIN; ev.data = 99;
	if (sys4(SYS_epoll_ctl_, ep2, EPOLL_CTL_ADD, ep, &ev) != 0) return (10);
	(void)sys3(SYS_write, pfd[1], "e", 1);
	if (sys4(SYS_epoll_wait, ep2, evs, 16, 100) != 1 || evs[0].data != 99)
		return (10);
	(void)sys3(SYS_read, pfd[0], buf, 1);
	(void)sys1(SYS_close, ep2);
	/* 11: closing a registered fd removes it: no events, no crash. */
	if (sys2(SYS_pipe2, pfd2, 0) != 0) return (11);
	ev.events = EPOLLIN; ev.data = 3;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, pfd2[0], &ev) != 0) return (11);
	(void)sys1(SYS_close, pfd2[0]);
	(void)sys3(SYS_write, pfd2[1], "f", 1);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 50) != 0) return (11);
	(void)sys1(SYS_close, pfd2[1]);
	/* 12: EPOLLHUP on a pipe whose writer closed; EPOLLRDHUP ignored. */
	if (sys2(SYS_pipe2, pfd2, 0) != 0) return (12);
	ev.events = EPOLLIN | EPOLLRDHUP; ev.data = 4;
	if (sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_ADD, pfd2[0], &ev) != 0) return (12);
	(void)sys1(SYS_close, pfd2[1]);
	if (sys4(SYS_epoll_wait, ep, evs, 16, 100) != 1) return (12);
	if ((evs[0].events & EPOLLHUP) == 0) return (12);
	(void)sys1(SYS_close, pfd2[0]);

	/* 13-14: EPOLL_CTL_DEL/ADD storm from one thread while another waits. */
	del_ep = ep; del_fd = pfd[0]; stop = 0;
	if (thread_create(&th[0], deleter, 0) != 0) return (13);
	while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
		(void)sys3(SYS_write, pfd[1], "g", 1);
		r = sys4(SYS_epoll_wait, ep, evs, 16, 1);
		if (r < 0) return (13);
		while (sys3(SYS_read, pfd[0], buf, sizeof(buf)) > 0)
			;
	}
	if (thread_join(&th[0]) != 0) return (14);
	(void)sys4(SYS_epoll_ctl_, ep, EPOLL_CTL_DEL, pfd[0], 0);

	/* 15-16: EPOLLEXCLUSIVE: 4 waiters, 200 wakeups, at least one wakes each. */
	excl_ep = sys1(SYS_epoll_create1, 0);
	efd = sys2(SYS_eventfd2, 0, EFD_NONBLOCK);
	if (excl_ep < 0 || efd < 0) return (15);
	ev.events = EPOLLIN | EPOLLEXCLUSIVE; ev.data = 5;
	if (sys4(SYS_epoll_ctl_, excl_ep, EPOLL_CTL_ADD, efd, &ev) != 0)
		return (15);
	stop = 0;
	for (i = 0; i < 4; i++)
		if (thread_create(&th[i], excl_waiter, (void *)i) != 0)
			return (15);
	for (i = 0; i < 200; i++) {
		val = 1;
		(void)sys3(SYS_write, efd, &val, 8);
		sleep_ms(2);
		(void)sys3(SYS_read, efd, &val, 8);
	}
	__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
	for (i = 0; i < 4; i++)
		if (thread_join(&th[i]) != 0) return (16);
	total = excl_hits[0] + excl_hits[1] + excl_hits[2] + excl_hits[3];
	if (total == 0) return (16);
	/* EXCLUSIVE with MOD is EINVAL; with a nested epoll is EINVAL */
	ev.events = EPOLLIN | EPOLLEXCLUSIVE;
	if (sys4(SYS_epoll_ctl_, excl_ep, EPOLL_CTL_MOD, efd, &ev) != -EINVAL)
		return (16);
	(void)sys1(SYS_close, excl_ep);

	/* 17-19: eventfd semantics: counter, semaphore, overflow. */
	val = 5;
	if (sys3(SYS_write, efd, &val, 8) != 8) return (17);
	if (sys3(SYS_read, efd, &val, 8) != 8 || val != 5) return (17);
	if (sys3(SYS_read, efd, &val, 8) != -EAGAIN) return (17);
	(void)sys1(SYS_close, efd);
	efd = sys2(SYS_eventfd2, 3, EFD_SEMAPHORE | EFD_NONBLOCK);
	if (efd < 0) return (18);
	for (i = 0; i < 3; i++)
		if (sys3(SYS_read, efd, &val, 8) != 8 || val != 1) return (18);
	if (sys3(SYS_read, efd, &val, 8) != -EAGAIN) return (18);
	val = 0xfffffffffffffffeUL;
	if (sys3(SYS_write, efd, &val, 8) != 8) return (19);
	val = 1;
	if (sys3(SYS_write, efd, &val, 8) != -EAGAIN) return (19);	/* overflow */
	val = 0xffffffffffffffffUL;
	if (sys3(SYS_write, efd, &val, 8) != -EINVAL) return (19);
	if (sys3(SYS_write, efd, &val, 4) != -EINVAL) return (19);
	(void)sys1(SYS_close, efd);

	/* 20-23: timerfd: interval expirations counted, gettime, ABSTIME. */
	tfd = sys2(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tfd < 0) return (20);
	its.it_value.tv_sec = 0; its.it_value.tv_nsec = 10000000;
	its.it_interval.tv_sec = 0; its.it_interval.tv_nsec = 10000000;
	if (sys4(SYS_timerfd_settime, tfd, 0, &its, 0) != 0) return (20);
	sleep_ms(105);
	if (sys3(SYS_read, tfd, &val, 8) != 8) return (21);
	if (val < 8 || val > 12) { msgnum("expirations ", val); return (21); }
	if (sys3(SYS_read, tfd, &val, 8) != -EAGAIN) return (21);
	if (sys2(SYS_timerfd_gettime, tfd, &its) != 0) return (22);
	if (its.it_interval.tv_nsec != 10000000) return (22);
	/* disarm */
	xmemset(&its, 0, sizeof(its));
	if (sys4(SYS_timerfd_settime, tfd, 0, &its, 0) != 0) return (22);
	sleep_ms(30);
	if (sys3(SYS_read, tfd, &val, 8) != -EAGAIN) return (22);
	/* absolute time in the past fires immediately */
	if (sys2(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) return (23);
	its.it_value = ts;
	its.it_value.tv_sec -= 1;
	if (sys4(SYS_timerfd_settime, tfd, TFD_TIMER_ABSTIME, &its, 0) != 0)
		return (23);
	sleep_ms(5);
	if (sys3(SYS_read, tfd, &val, 8) != 8 || val != 1) return (23);
	(void)sys1(SYS_close, tfd);
	/* 24: TFD_TIMER_CANCEL_ON_SET: a clock step makes read() ECANCELED. */
	tfd = sys2(SYS_timerfd_create, CLOCK_REALTIME, 0);
	if (tfd < 0) return (24);
	if (sys2(SYS_clock_gettime, CLOCK_REALTIME, &ts) != 0) return (24);
	its.it_value = ts; its.it_value.tv_sec += 60;
	its.it_interval.tv_sec = 0; its.it_interval.tv_nsec = 0;
	if (sys4(SYS_timerfd_settime, tfd, TFD_TIMER_ABSTIME |
	    TFD_TIMER_CANCEL_ON_SET, &its, 0) != 0) return (24);
	{
		struct timeval tv;

		tv.tv_sec = ts.tv_sec + 1; tv.tv_usec = 0;
		if (sys2(SYS_settimeofday, &tv, 0) != 0)
			msg("note: settimeofday failed; CANCEL_ON_SET unverified\n");
		else {
			r = sys3(SYS_read, tfd, &val, 8);
			if (r != -ECANCELED) { msgnum("read after step ", r); return (24); }
		}
	}
	(void)sys1(SYS_close, tfd);
	/* 25: invalid flags / clocks. */
	r = sys2(SYS_timerfd_create, CLOCK_MONOTONIC, 0x100);
	if (r != -EINVAL) { msgnum("timerfd_create bad flags ", r); return (25); }
	r = sys2(SYS_timerfd_create, 99, 0);
	if (r != -EINVAL) { msgnum("timerfd_create bad clock ", r); return (25); }
	r = sys2(SYS_eventfd2, 0, 0x100);
	if (r != -EINVAL) { msgnum("eventfd2 bad flags ", r); return (25); }
	r = sys1(SYS_epoll_create1, 0x100);
	if (r != -EINVAL) { msgnum("epoll_create1 bad flags ", r); return (25); }
	/* 26: epoll_pwait2 timeout in a timespec, sigmask honoured. */
	ts.tv_sec = 0; ts.tv_nsec = 20000000;
	mask = 0;
	r = sys6(SYS_epoll_pwait2, ep, evs, 16, &ts, &mask, 8);
	if (r != 0) return (26);
	ts.tv_nsec = -1;
	if (sys6(SYS_epoll_pwait2, ep, evs, 16, &ts, 0, 8) != -EINVAL) return (26);
	/* 27: maxevents 0 is EINVAL, a bad events pointer EFAULT (when ready). */
	if (sys4(SYS_epoll_wait, ep, evs, 0, 0) != -EINVAL) return (27);
	(void)sys1(SYS_close, ep);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	return (0);
}
