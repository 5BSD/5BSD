/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial futex tests with real threads: contended ping-pong, requeue
 * storms, wake-all counting, timeouts racing wakes, robust lists (owner
 * death), PI locks, waits on unmapped/unaligned memory, and futex2.
 * Everything a libc mutex/condvar implementation does, done wrong on
 * purpose where Linux defines the outcome.  Exit status = failed check.
 */
#include "linux_test.h"

#define	FUTEX_REQUEUE		3
#define	FUTEX_CMP_REQUEUE	4
#define	FUTEX_WAKE_OP		5
#define	FUTEX_LOCK_PI		6
#define	FUTEX_UNLOCK_PI		7
#define	FUTEX_TRYLOCK_PI	8
#define	FUTEX_WAIT_BITSET	9
#define	FUTEX_WAKE_BITSET	10
#define	FUTEX_LOCK_PI2		13
#define	FUTEX_CLOCK_REALTIME	256
#define	FUTEX_WAITERS		0x80000000
#define	FUTEX_OWNER_DIED	0x40000000
#define	FUTEX_TID_MASK		0x3fffffff
#define	SYS_set_robust_list	273
#define	SYS_futex_wake		454
#define	SYS_futex_wait		455
#define	SYS_futex_requeue	456
#define	FUTEX2_SIZE_U32		0x02
#define	FUTEX2_PRIVATE		128
#define	NTHREADS		8
#define	ROUNDS			20000

static int ball;			/* whose turn: 0..NTHREADS-1 */
static int turns[NTHREADS];
static int gate;
static int woken;
static int qa, qb;			/* requeue source / destination */
static int qwoken;
static int pilock;
static int pi_acquired;
static int robust_lock;
struct robust_list_head { unsigned long list; long futex_offset;
    unsigned long list_op_pending; };

static long
futex(int *a, int op, int val, const void *t, int *a2, int val3)
{

	return (sys6(SYS_futex, a, op | FUTEX_PRIVATE_FLAG, val, t, a2, val3));
}

/* Token passing: thread i may run only when ball == i, then hands on. */
static int
pingpong(void *arg)
{
	int me = (int)(long)arg, i, next;

	for (i = 0; i < ROUNDS; i++) {
		int v;

		/* The value compared by futex_wait must be the one tested. */
		while ((v = __atomic_load_n(&ball, __ATOMIC_ACQUIRE)) != me)
			(void)futex_wait(&ball, v, 0);
		turns[me]++;
		next = (me + 1) % NTHREADS;
		__atomic_store_n(&ball, next, __ATOMIC_RELEASE);
		(void)futex_wake(&ball, NTHREADS);
	}
	return (0);
}

/* Wait on the gate, count the wakeup. */
static int
gate_waiter(void *arg)
{
	long r;

	(void)arg;
	while (__atomic_load_n(&gate, __ATOMIC_ACQUIRE) == 0) {
		r = futex_wait(&gate, 0, 0);
		if (r != 0 && r != -EAGAIN && r != -EINTR)
			return (1);
	}
	__atomic_add_fetch(&woken, 1, __ATOMIC_ACQ_REL);
	return (0);
}

/* Wait on qa; expect to be requeued to qb and woken from there. */
static int
requeue_waiter(void *arg)
{
	long r;

	(void)arg;
	r = futex_wait(&qa, 0, 0);
	if (r != 0 && r != -EAGAIN)
		return (1);
	__atomic_add_fetch(&qwoken, 1, __ATOMIC_ACQ_REL);
	return (0);
}

static int *robust_word;

static int
robust_dier2(void *arg)
{
	struct robust_list_head head;
	struct { unsigned long next; unsigned long pad; int lock; } node;
	int tid;

	(void)arg;
	tid = (int)sys0(SYS_gettid);
	head.list = (unsigned long)&node.next;
	head.futex_offset = (long)((char *)&node.lock - (char *)&node.next);
	head.list_op_pending = 0;
	node.next = (unsigned long)&head.list;	/* one entry, self-terminated */
	node.lock = tid;			/* held by us */
	robust_word = &node.lock;
	if (sys2(SYS_set_robust_list, &head, sizeof(head)) != 0)
		return (1);
	/*
	 * Exit with the lock held.  The node lives on this thread's stack,
	 * which stays mapped (the test never unmaps it before checking).
	 */
	(void)sys1(SYS_exit, 0);
	return (0);
}

static int
pi_taker(void *arg)
{
	long r;

	(void)arg;
	r = futex(&pilock, FUTEX_LOCK_PI, 0, 0, 0, 0);
	if (r != 0)
		return (1);
	__atomic_store_n(&pi_acquired, 1, __ATOMIC_RELEASE);
	sleep_ms(20);
	r = futex(&pilock, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
	return (r == 0 ? 0 : 2);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th[NTHREADS];
	struct timespec ts;
	long r, p, i, tid;
	int v;

	(void)argc; (void)argv; (void)envp;

	msg("futex: pingpong\n");
	/* 1-3: contended token passing across 8 threads, 20k rounds each. */
	ball = 0;
	for (i = 0; i < NTHREADS; i++)
		if (thread_create(&th[i], pingpong, (void *)i) != 0) return (1);
	for (i = 0; i < NTHREADS; i++)
		if (thread_join(&th[i]) != 0) return (2);
	for (i = 0; i < NTHREADS; i++)
		if (turns[i] != ROUNDS) return (3);

	msg("futex: wake-all\n");
	/* 4-6: FUTEX_WAKE with INT_MAX wakes every waiter exactly once. */
	gate = 0; woken = 0;
	for (i = 0; i < NTHREADS; i++)
		if (thread_create(&th[i], gate_waiter, 0) != 0) return (4);
	sleep_ms(100);
	__atomic_store_n(&gate, 1, __ATOMIC_RELEASE);
	r = futex_wake(&gate, 0x7fffffff);
	if (r < 0) return (5);
	for (i = 0; i < NTHREADS; i++)
		if (thread_join(&th[i]) != 0) return (5);
	if (woken != NTHREADS) return (6);
	/* a wake with nobody waiting returns 0 */
	if (futex_wake(&gate, 1) != 0) return (6);

	msg("futex: requeue\n");
	/* 7-10: requeue storm: 8 waiters on qa, move them to qb 1 by 1, wake qb. */
	qa = 0; qb = 0; qwoken = 0;
	for (i = 0; i < NTHREADS; i++)
		if (thread_create(&th[i], requeue_waiter, 0) != 0) return (7);
	sleep_ms(100);
	/* CMP_REQUEUE with the wrong expected value is EAGAIN */
	if (futex(&qa, FUTEX_CMP_REQUEUE, 0, (void *)1, &qb, 1) != -EAGAIN)
		return (8);
	/* move one at a time (nr_wake=0, nr_requeue=1): returns 1 each */
	for (i = 0; i < NTHREADS; i++) {
		r = futex(&qa, FUTEX_CMP_REQUEUE, 0, (void *)1, &qb, 0);
		if (r != 1) { msgnum("requeue returned ", r); return (9); }
	}
	/* nobody is left on qa */
	if (futex_wake(&qa, 100) != 0) return (9);
	/* wake them all on qb */
	sleep_ms(20);
	r = futex_wake(&qb, 100);
	if (r != NTHREADS) { msgnum("wake qb returned ", r); return (10); }
	for (i = 0; i < NTHREADS; i++)
		if (thread_join(&th[i]) != 0) return (10);
	if (qwoken != NTHREADS) return (10);

	msg("futex: timeouts\n");
	/* 11-13: timeouts. */
	v = 0;
	ts.tv_sec = 0; ts.tv_nsec = 50 * 1000000;
	if (futex_wait(&v, 0, &ts) != -ETIMEDOUT) return (11);
	/* value mismatch is EAGAIN, immediately */
	if (futex_wait(&v, 1, &ts) != -EAGAIN) return (12);
	/* an absolute deadline in the past (WAIT_BITSET|CLOCK_REALTIME) */
	ts.tv_sec = 1; ts.tv_nsec = 0;
	if (futex(&v, FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME, 0, &ts, 0,
	    0xffffffff) != -ETIMEDOUT) return (13);
	/* a negative timeout is EINVAL */
	ts.tv_sec = -1; ts.tv_nsec = 0;
	if (futex_wait(&v, 0, &ts) != -EINVAL) return (13);
	ts.tv_sec = 0; ts.tv_nsec = 1000000000;
	if (futex_wait(&v, 0, &ts) != -EINVAL) return (13);

	/* 14-16: bad addresses: unaligned EINVAL, unmapped EFAULT. */
	if (futex((int *)((char *)&v + 1), FUTEX_WAIT, 0, 0, 0, 0) != -EINVAL)
		return (14);
	p = call(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p < 0) return (15);
	(void)sys2(SYS_munmap, p, PAGE);
	if (futex((int *)p, FUTEX_WAIT, 0, 0, 0, 0) != -EFAULT) return (15);
	/* wake on unmapped memory is not an error on Linux (nobody there) */
	r = futex((int *)p, FUTEX_WAKE, 1, 0, 0, 0);
	if (r != 0 && r != -EFAULT) return (16);
	/* a read-only page: WAIT works (reads), value 0 */
	p = call(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1,
	    0);
	if (p < 0) return (16);
	if (futex((int *)p, FUTEX_WAIT, 1, 0, 0, 0) != -EAGAIN) return (16);
	(void)sys2(SYS_munmap, p, PAGE);

	/* 17-18: WAKE_OP: wake 1 on a, conditionally on b, atomic op on b. */
	{
		int a = 0, b = 5;
		/* op = FUTEX_OP(SET, 7, CMP_EQ, 5): set b=7, wake b if old==5 */
		int op = (0 << 28) | (7 << 12) | (0 << 24) | 5;

		r = futex(&a, FUTEX_WAKE_OP, 1, (void *)1, &b, op);
		if (r != 0) return (17);
		if (b != 7) return (18);
	}

	msg("futex: pi\n");
	/* 19-21: PI lock handoff between two threads. */
	pilock = 0; pi_acquired = 0;
	tid = sys0(SYS_gettid);
	if (futex(&pilock, FUTEX_TRYLOCK_PI, 0, 0, 0, 0) != 0) return (19);
	if ((pilock & FUTEX_TID_MASK) != tid) return (19);
	if (thread_create(&th[0], pi_taker, 0) != 0) return (20);
	sleep_ms(50);
	/* the waiter marked the lock contended */
	if ((pilock & FUTEX_WAITERS) == 0) return (20);
	if (futex(&pilock, FUTEX_UNLOCK_PI, 0, 0, 0, 0) != 0) return (20);
	if (thread_join(&th[0]) != 0) return (21);
	if (!pi_acquired || pilock != 0) return (21);
	/* unlocking a lock we do not own is EPERM */
	pilock = 12345;
	if (futex(&pilock, FUTEX_UNLOCK_PI, 0, 0, 0, 0) != -EPERM) return (21);
	pilock = 0;

	msg("futex: robust\n");
	/* 22-23: robust list: a thread dies holding a lock -> OWNER_DIED. */
	robust_lock = 0;
	if (thread_create(&th[0], robust_dier2, 0) != 0) return (22);
	/* do not join (that unmaps the stack): wait for the tid to clear */
	while (__atomic_load_n(&th[0].tid, __ATOMIC_ACQUIRE) != 0)
		sleep_ms(1);
	sleep_ms(10);
	if (robust_word == 0) return (22);
	if ((*robust_word & FUTEX_OWNER_DIED) == 0) {
		msgnum("robust lock word ", *robust_word);
		return (23);
	}
	(void)sys2(SYS_munmap, th[0].stack, th[0].stack_size);

	msg("futex: futex2\n");
	/* 24-26: futex2 basics against the same waiters. */
	gate = 0; woken = 0;
	for (i = 0; i < NTHREADS; i++)
		if (thread_create(&th[i], gate_waiter, 0) != 0) return (24);
	sleep_ms(100);
	__atomic_store_n(&gate, 1, __ATOMIC_RELEASE);
	r = sys4(SYS_futex_wake, &gate, 0xffffffffUL, 100, FUTEX2_SIZE_U32 |
	    FUTEX2_PRIVATE);
	if (r != NTHREADS) { msgnum("futex_wake returned ", r); return (25); }
	for (i = 0; i < NTHREADS; i++)
		if (thread_join(&th[i]) != 0) return (25);
	if (woken != NTHREADS) return (26);
	/* futex_wait with a mismatched value is EAGAIN; nr <= 0 wakes none */
	v = 3;
	if (sys6(SYS_futex_wait, &v, 4, 0xffffffffUL, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
	    0, 0) != -EAGAIN) return (26);
	if (sys4(SYS_futex_wake, &v, 0xffffffffUL, 0, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE)
	    != 0) return (26);
	return (0);
}
