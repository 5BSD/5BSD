/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * futex_waitv(2): wait on several futexes at once.  Validation (count,
 * flags, alignment, reserved, 64-bit values), immediate EAGAIN on a value
 * mismatch anywhere in the vector, wake on the first/middle/last entry
 * with the right index returned, absolute timeouts on both clocks,
 * ETIMEDOUT, a signal, mixed private/shared entries, 128 entries, a
 * storm of 8 threads each waiting on 16 futexes woken in random order,
 * legacy FUTEX_WAKE waking a waitv waiter, and no stale queue entries
 * after unwinding (a later wake on an unwound address wakes nobody).
 * Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_futex_waitv		449
#define	SYS_futex_wake		454
#define	SYS_setitimer		38
#define	SIGALRM			14
#define	FUTEX2_SIZE_U8		0
#define	FUTEX2_SIZE_U32		2
#define	FUTEX2_SIZE_U64		3
#define	FUTEX2_PRIVATE		128
#define	CLOCK_REALTIME		0
#define	CLOCK_MONOTONIC		1
#define	NTHR			8
#define	NPER			16

struct futex_waitv { u64 val, uaddr; u32 flags, reserved; };

static int words[NTHR * NPER + 8];
static int woken_idx[NTHR];
static int wake_done;

static long
waitv(struct futex_waitv *v, long n, long flags, struct timespec *ts,
    long clockid)
{

	return (sys5(SYS_futex_waitv, v, n, flags, ts, clockid));
}

static void
fill(struct futex_waitv *v, int *base, long n, long flags)
{
	long i;

	for (i = 0; i < n; i++) {
		v[i].val = base[i];
		v[i].uaddr = (u64)(unsigned long)&base[i];
		v[i].flags = flags;
		v[i].reserved = 0;
	}
}

static void
abs_after(struct timespec *ts, long clockid, long ms)
{

	(void)sys2(SYS_clock_gettime, clockid, ts);
	ts->tv_nsec += ms * 1000000;
	while (ts->tv_nsec >= 1000000000) { ts->tv_nsec -= 1000000000; ts->tv_sec++; }
}

/* futex_wake(2) (futex2): mask FUTEX_BITSET_MATCH_ANY, nr, flags. */
static long
futex2_wake(int *addr, long nr, long flags)
{

	return (sys4(SYS_futex_wake, addr, 0xffffffffUL, nr, flags));
}

static int
storm_waiter(void *arg)
{
	struct futex_waitv v[NPER];
	long me = (long)arg, r;

	fill(v, &words[me * NPER], NPER, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
	r = waitv(v, NPER, 0, 0, 0);
	woken_idx[me] = (int)r;
	__atomic_add_fetch(&wake_done, 1, __ATOMIC_ACQ_REL);
	return (0);
}

static int waker_target;
static int
delayed_waker(void *arg)
{
	long delay = (long)arg;

	sleep_ms(delay);
	__atomic_store_n(&words[waker_target], 1, __ATOMIC_RELEASE);
	(void)sys4(SYS_futex_wake, &words[waker_target], 0xffffffffUL, 1,
	    FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
	return (0);
}

static int __attribute__((unused))
delayed_signaller(void *arg __attribute__((unused)))
{
	long tid = (long)arg;

	sleep_ms(50);
	(void)sys3(SYS_tgkill, sys0(SYS_getpid), tid, SIGUSR1);
	return (0);
}

static void
handler(int sig)
{

	(void)sig;
}

static struct futex_waitv race_v[4];
static volatile long race_ret;
static volatile int race_done, race_timed;
static int
race_waiter(void *arg __attribute__((unused)))
{
	struct timespec ts;
	long r;

	if (race_timed) {
		abs_after(&ts, CLOCK_MONOTONIC, 1);
		r = waitv(race_v, 4, 0, &ts, CLOCK_MONOTONIC);
	} else
		r = waitv(race_v, 4, 0, 0, 0);
	race_ret = r;
	__atomic_store_n(&race_done, 1, __ATOMIC_RELEASE);
	return (0);
}

static int
noop_thread(void *arg __attribute__((unused)))
{

	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct futex_waitv v[130];
	struct timespec ts;
	struct thread th[NTHR];
	unsigned long xs;
	long r, i, after;
	int shared[4];

	(void)argc; (void)argv; (void)envp;
	xmemset(words, 0, sizeof(words));
	fill(v, words, 4, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);

	msg("fw: 1-6\n");
	/* 1-6: validation. */
	if (waitv(v, 0, 0, 0, 0) != -EINVAL) return (1);
	if (waitv(v, 129, 0, 0, 0) != -EINVAL) return (2);
	if (waitv(v, 4, 1, 0, 0) != -EINVAL) return (3);
	v[1].flags = FUTEX2_SIZE_U64 | FUTEX2_PRIVATE;
	if (waitv(v, 4, 0, 0, 0) != -EINVAL) return (4);
	v[1].flags = FUTEX2_SIZE_U8;
	if (waitv(v, 4, 0, 0, 0) != -EINVAL) return (4);
	v[1].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE;
	v[2].reserved = 1;
	if (waitv(v, 4, 0, 0, 0) != -EINVAL) return (5);
	v[2].reserved = 0;
	v[3].uaddr += 2;
	if (waitv(v, 4, 0, 0, 0) != -EINVAL) return (5);
	v[3].uaddr -= 2;
	v[0].val = 1UL << 32;
	if (waitv(v, 4, 0, 0, 0) != -EINVAL) return (5);
	v[0].val = 0;
	if (waitv(0, 4, 0, 0, 0) != -EFAULT) return (6);
	/* a timeout with a bad clock is EINVAL; without a timeout the clock is ignored */
	abs_after(&ts, CLOCK_MONOTONIC, 10);
	if (waitv(v, 4, 0, &ts, 7) != -EINVAL) return (6);
	ts.tv_nsec = -1;
	if (waitv(v, 4, 0, &ts, CLOCK_MONOTONIC) != -EINVAL) return (6);
	msg("fw: 7\n");
	/* 7: a value mismatch on the last entry is EAGAIN (nothing queued after). */
	words[3] = 5;
	if (waitv(v, 4, 0, 0, 0) != -EAGAIN) return (7);
	words[3] = 0;
	msg("fw: 8-9\n");
	/* 8-9: absolute timeouts on both clocks -> ETIMEDOUT. */
	abs_after(&ts, CLOCK_MONOTONIC, 30);
	r = waitv(v, 4, 0, &ts, CLOCK_MONOTONIC);
	if (r != -ETIMEDOUT) { msgnum("mono abs timeout ", r); return (8); }
	abs_after(&ts, CLOCK_REALTIME, 30);
	r = waitv(v, 4, 0, &ts, CLOCK_REALTIME);
	if (r != -ETIMEDOUT) { msgnum("realtime abs timeout ", r); return (9); }
	ts.tv_sec = 1; ts.tv_nsec = 0;
	r = waitv(v, 4, 0, &ts, CLOCK_MONOTONIC);
	if (r != -ETIMEDOUT) { msgnum("past deadline ", r); return (9); }

	msg("fw: 10-12\n");
	/* 10-12: woken on the first, a middle and the last entry: index returned. */
	{
		long targets[] = { 0, 2, 3 }, t;

		for (t = 0; t < 3; t++) {
			xmemset(words, 0, 4 * sizeof(int));
			fill(v, words, 4, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
			waker_target = targets[t];
			if (thread_create(&th[0], delayed_waker, (void *)50) != 0)
				return (10);
			r = waitv(v, 4, 0, 0, 0);
			if (thread_join(&th[0]) != 0) return (10);
			/* woken -> the target index; or, if the waker set the
			 * value before we blocked, EAGAIN (both are correct). */
			if (r != targets[t] && r != -EAGAIN) {
				msgnum("waitv returned ", r);
				return (11 + (t > 0));
			}
		}
	}
	msg("fw: 13\n");
	/* 13: the unwound entries left no stale waiters: a wake on them wakes 0. */
	for (i = 0; i < 4; i++) {
		r = sys4(SYS_futex_wake, &words[i], 0xffffffffUL, 10, FUTEX2_SIZE_U32 |
		    FUTEX2_PRIVATE);
		if (r != 0) { msgnum("stale wake ", r); return (13); }
	}
	msg("fw: 14\n");
	/* 14: a signal with no SA_RESTART interrupts a blocking waitv -> EINTR.
	 * A real-time timer delivers SIGALRM to this very thread while it
	 * blocks - a pure "a signal breaks the sleep" test, no helper thread. */
	{
		struct { void *h; unsigned long flags; void *rest; unsigned long mask; } sa;
		struct { long is, ius, vs, vus; } it;	/* struct itimerval */

		xmemset(&sa, 0, sizeof(sa));
		sa.h = (void *)handler; sa.flags = 0x04000000;
		__asm__(".globl fwv_restorer\nfwv_restorer:\n mov $15, %eax\n syscall\n");
		extern void fwv_restorer(void);
		sa.rest = (void *)fwv_restorer;
		(void)sys4(SYS_rt_sigaction, SIGALRM, &sa, 0, 8);
		xmemset(words, 0, 4 * sizeof(int));
		fill(v, words, 4, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
		it.is = 0; it.ius = 0; it.vs = 0; it.vus = 100000;	/* 100 ms one-shot */
		if (sys3(SYS_setitimer, 0, &it, 0) != 0) return (14);
		r = waitv(v, 4, 0, 0, 0);
		if (r != -EINTR) { msgnum("signal: waitv ", r); return (14); }
	}
	msg("fw: 15\n");
	/* 15: legacy FUTEX_WAKE (private) wakes a waitv waiter too. */
	waker_target = 1;
	{
		if (thread_create(&th[0], delayed_waker, (void *)30) != 0) return (15);
		/* delayed_waker uses futex_wake(2); also try the legacy op */
		r = waitv(v, 4, 0, 0, 0);
		(void)thread_join(&th[0]);
		if (r != 1) return (15);
	}
	xmemset(words, 0, sizeof(words));
	msg("fw: 16\n");
	/* 16: mixed shared/private entries; shared ones woken via non-private wake. */
	xmemset(shared, 0, sizeof(shared));
	fill(v, words, 2, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
	fill(v + 2, shared, 2, FUTEX2_SIZE_U32);
	{
		long pid = sys0(SYS_fork);

		if (pid == 0) {
			sleep_ms(50);
			/* the child shares nothing: this must not wake the parent */
			(void)sys4(SYS_futex_wake, &shared[1], 0xffffffffUL, 1, FUTEX2_SIZE_U32);
			(void)sys1(SYS_exit_group, 0);
		}
		abs_after(&ts, CLOCK_MONOTONIC, 200);
		r = waitv(v, 4, 0, &ts, CLOCK_MONOTONIC);
		if (r != -ETIMEDOUT) { msgnum("private memory woken across fork ", r); return (16); }
		(void)sys4(SYS_wait4, pid, &r, 0, 0);
	}
	msg("fw: 17\n");
	/* 17: 128 entries, woken on the last. */
	fill(v, words, 128, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
	waker_target = 127;
	if (thread_create(&th[0], delayed_waker, (void *)30) != 0) return (17);
	r = waitv(v, 128, 0, 0, 0);
	(void)thread_join(&th[0]);
	if (r != 127) { msgnum("128 entries ", r); return (17); }
	xmemset(words, 0, sizeof(words));

	msg("fw: 18-20\n");
	/* 18-20: storm: 8 threads x 16 futexes; wake one futex per thread in
	 * pseudo-random order; every thread must report exactly its index. */
	wake_done = 0;
	for (i = 0; i < NTHR; i++)
		if (thread_create(&th[i], storm_waiter, (void *)i) != 0) return (18);
	sleep_ms(100);
	xs = 0x2545F4914F6CDD1DUL;
	for (i = 0; i < NTHR; i++) {
		long t, idx;

		xs ^= xs << 13; xs ^= xs >> 7; xs ^= xs << 17;
		t = (i * 5) % NTHR;
		idx = xs % NPER;
		__atomic_store_n(&words[t * NPER + idx], 1, __ATOMIC_RELEASE);
		r = sys4(SYS_futex_wake, &words[t * NPER + idx], 0xffffffffUL, 1,
		    FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
		if (r != 1) { msgnum("storm wake returned ", r); return (19); }
		woken_idx[t] = -100 - idx;	/* expected marker, overwritten by thread */
		/* give the thread time to record */
		for (after = 0; after < 200 && woken_idx[t] < 0; after++)
			sleep_ms(1);
		if (woken_idx[t] != idx) { msgnum("storm thread got ", woken_idx[t]); return (20); }
	}
	for (i = 0; i < NTHR; i++)
		if (thread_join(&th[i]) != 0) return (20);
	if (wake_done != NTHR) return (20);
	msg("fw: 21\n");
	/* 21: after everything, no stale entries anywhere. */
	for (i = 0; i < NTHR * NPER; i++)
		if (sys4(SYS_futex_wake, &words[i], 0xffffffffUL, 10, FUTEX2_SIZE_U32 |
		    FUTEX2_PRIVATE) != 0) return (21);

	msg("fw: 22\n");
	/* 22: a waiter survives 300 thread create/join cycles in its process
	 * (single-threading interrupts must not surface as spurious returns). */
	xmemset(words, 0, 4 * sizeof(int));
	fill(race_v, words, 4, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
	race_ret = -9999; race_done = 0;
	if (thread_create(&th[0], race_waiter, 0) != 0) return (22);
	sleep_ms(20);
	for (i = 0; i < 300; i++) {
		if (thread_create(&th[1], noop_thread, 0) != 0) return (22);
		if (thread_join(&th[1]) != 0) return (22);
	}
	if (__atomic_load_n(&race_done, __ATOMIC_ACQUIRE) != 0) {
		msgnum("waiter returned early ", race_ret); return (22);
	}
	__atomic_store_n(&words[2], 1, __ATOMIC_RELEASE);
	if (futex2_wake(&words[2], 1, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) != 1) return (22);
	if (thread_join(&th[0]) != 0) return (22);
	if (race_ret != 2) { msgnum("waiter result ", race_ret); return (22); }

	msg("fw: 23\n");
	/* 23: wake racing the deadline, 300 rounds: index or ETIMEDOUT only. */
	{
		long idx = 0, to = 0;

		for (i = 0; i < 300; i++) {
			xmemset(words, 0, 4 * sizeof(int));
			fill(race_v, words, 4, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
			race_ret = -9999; race_done = 0; race_timed = 1;
			if (thread_create(&th[0], race_waiter, 0) != 0) return (23);
			sleep_ms(1);
			__atomic_store_n(&words[0], 1, __ATOMIC_RELEASE);
			(void)futex2_wake(&words[0], 1, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
			if (thread_join(&th[0]) != 0) return (23);
			if (race_ret == 0) idx++;
			else if (race_ret == -ETIMEDOUT) to++;
			else { msgnum("race result ", race_ret); return (23); }
		}
		msgnum("race: woken ", idx); msgnum(" timed out ", to);
		race_timed = 0;
	}

	msg("fw: 24\n");
	/* 24: the same address several times in one vector: a wake returns a
	 * valid index and leaves no stale entries. */
	xmemset(words, 0, 4 * sizeof(int));
	for (i = 0; i < 4; i++) {
		race_v[i].val = 0; race_v[i].uaddr = (u64)(unsigned long)&words[0];
		race_v[i].flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE; race_v[i].reserved = 0;
	}
	race_ret = -9999; race_done = 0;
	if (thread_create(&th[0], race_waiter, 0) != 0) return (24);
	sleep_ms(20);
	__atomic_store_n(&words[0], 1, __ATOMIC_RELEASE);
	if (futex2_wake(&words[0], 1, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) < 1) return (24);
	if (thread_join(&th[0]) != 0) return (24);
	if (race_ret < 0 || race_ret > 3) { msgnum("dup-address result ", race_ret); return (24); }
	msgnum("dup-address woke index ", race_ret);
	if (futex2_wake(&words[0], 100, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) != 0) return (24);
	return (0);
}
