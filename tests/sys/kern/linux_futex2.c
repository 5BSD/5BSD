/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for the futex2 interface
 * (futex_wait(2), futex_wake(2), futex_requeue(2)) and the requeue
 * operations of futex(2).  No Linux libc or sysroot required.
 * Exit status identifies the failed check.
 */
typedef unsigned int u32;
typedef unsigned long u64;

struct timespec { long tv_sec; long tv_nsec; };
struct futex_waitv { u64 val; u64 uaddr; u32 flags; u32 __reserved; };

#define	SYS_mmap		9
#define	SYS_nanosleep		35
#define	SYS_fork		57
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_futex		202
#define	SYS_futex_wake		454
#define	SYS_futex_wait		455
#define	SYS_futex_requeue	456

#define	EAGAIN		11
#define	EFAULT		14
#define	EINVAL		22
#define	ENOSYS		38
#define	ETIMEDOUT	110

#define	FUTEX_WAIT		0
#define	FUTEX_WAKE		1
#define	FUTEX_REQUEUE		3
#define	FUTEX_CMP_REQUEUE	4
#define	FUTEX_WAIT_BITSET	9
#define	FUTEX_CLOCK_REALTIME	256
#define	FUTEX_BITSET_MATCH_ANY	0xffffffffU

#define	FUTEX2_SIZE_U64		0x03
#define	FUTEX2_SIZE_U32		0x02
#define	FUTEX2_NUMA		0x04
#define	FUTEX2_PRIVATE		0x80

#define	CLOCK_REALTIME		0
#define	CLOCK_MONOTONIC		1
#define	CLOCK_BOOTTIME		7

#define	INT_MAX			0x7fffffff
#define	PRIVATE_U32		(FUTEX2_SIZE_U32 | FUTEX2_PRIVATE)

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

static long
futex_wait(u32 *uaddr, u64 val, u64 mask, u32 flags, struct timespec *ts,
    int clockid)
{
	return (call(SYS_futex_wait, (long)uaddr, val, mask, flags, (long)ts,
	    clockid));
}

static long
futex_wake(u32 *uaddr, u64 mask, int nr, u32 flags)
{
	return (call(SYS_futex_wake, (long)uaddr, mask, nr, flags, 0, 0));
}

static long
futex_requeue(struct futex_waitv *w, u32 flags, int nr_wake, int nr_requeue)
{
	return (call(SYS_futex_requeue, (long)w, flags, nr_wake, nr_requeue,
	    0, 0));
}

static long
futex(u32 *uaddr, int op, u32 val, long timeout_or_nr, u32 *uaddr2, u32 val3)
{
	return (call(SYS_futex, (long)uaddr, op, val, timeout_or_nr,
	    (long)uaddr2, val3));
}

static void
msleep(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000 };

	(void)call(SYS_nanosleep, (long)&ts, 0, 0, 0, 0, 0);
}

static void
child_exit(long r)
{
	(void)call(SYS_exit, r < 0 ? -r : r, 0, 0, 0, 0, 0);
	__builtin_unreachable();
}

/* Returns 0 if the child exited with status 0. */
static int
reap(long pid)
{
	int status = -1;

	if (call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid)
		return (-1);
	return (status);
}

/*
 * Fork a child that waits on *w with the given interface.  Cross-process
 * waits must not use the PRIVATE flag: as on Linux, private futexes are
 * keyed on the address space, not on the shared page.
 */
static long
fork_futex2_waiter(u32 *w, u64 mask)
{
	long pid;

	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid == 0)
		child_exit(futex_wait(w, 0, mask, FUTEX2_SIZE_U32, 0, 0));
	return (pid);
}

static long
fork_futex_waiter(u32 *w)
{
	long pid;

	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid == 0)
		child_exit(futex(w, FUTEX_WAIT, 0, 0, 0, 0));
	return (pid);
}

#define	MAX_POLLS	500		/* 500 x 10 ms = 5 s per wait */

static u32 *fa, *fb;

/*
 * Never leave a forked waiter stranded on a failure: wake everything on
 * both words first so the test cannot hang its runner.
 */
static int
fail(int n)
{
	(void)futex(fa, FUTEX_WAKE, INT_MAX, 0, 0, 0);
	(void)futex(fb, FUTEX_WAKE, INT_MAX, 0, 0, 0);
	return (n);
}

#define	FAIL(n)	return (fail(n))

static int
test(void)
{
	struct futex_waitv wv[2];
	struct timespec ts;
	u32 *page;
	long r, total, pid1, pid2;
	int i;

	page = (u32 *)call(SYS_mmap, 0, 4096, 3, 0x01 | 0x20, -1, 0);
	if ((long)page < 0) return (1);
	fa = &page[0];
	fb = &page[16];
	*fa = 0;
	*fb = 0;

	/*
	 * futex_wait(2) argument validation.
	 */
	/* 2: expected value differs from *uaddr -> EAGAIN. */
	if (futex_wait(fa, 1, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, 0, 0) !=
	    -EAGAIN) FAIL(2);
	/* 3: flags outside FUTEX2_VALID_MASK -> EINVAL. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32 | 0x100,
	    0, 0) != -EINVAL) FAIL(3);
	/* 4: only 32-bit futex words are supported: U64 -> EINVAL. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY,
	    FUTEX2_SIZE_U64 | FUTEX2_PRIVATE, 0, 0) != -EINVAL) FAIL(4);
	/* 5: U8 (size 0) -> EINVAL. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, FUTEX2_PRIVATE, 0, 0) !=
	    -EINVAL) FAIL(5);
	/* 6: NUMA-aware futexes are not implemented -> EINVAL. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32 | FUTEX2_NUMA,
	    0, 0) != -EINVAL) FAIL(6);
	/* 7: a zero mask -> EINVAL. */
	if (futex_wait(fa, 1, 0, PRIVATE_U32, 0, 0) != -EINVAL) FAIL(7);
	/* 8: val not representable in a 32-bit word -> EINVAL, not EAGAIN. */
	if (futex_wait(fa, 1UL << 32, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32,
	    0, 0) != -EINVAL) FAIL(8);
	/* 9: mask not representable in a 32-bit word -> EINVAL. */
	if (futex_wait(fa, 1, 1UL << 32, PRIVATE_U32, 0, 0) != -EINVAL)
		FAIL(9);
	/* 10: with a timeout the clock must be MONOTONIC or REALTIME. */
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, &ts,
	    CLOCK_BOOTTIME) != -EINVAL) FAIL(10);
	/* 11: without a timeout the clockid is not examined. */
	if (futex_wait(fa, 1, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, 0,
	    CLOCK_BOOTTIME) != -EAGAIN) FAIL(11);
	/* 12: timeout is ABSOLUTE: the monotonic epoch is long past. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, &ts,
	    CLOCK_MONOTONIC) != -ETIMEDOUT) FAIL(12);
	/* 13: absolute CLOCK_REALTIME timeout in the past -> ETIMEDOUT. */
	ts.tv_sec = 1;
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, &ts,
	    CLOCK_REALTIME) != -ETIMEDOUT) FAIL(13);
	/* 14: an invalid timespec -> EINVAL. */
	ts.tv_nsec = 1000000000L;
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32, &ts,
	    CLOCK_MONOTONIC) != -EINVAL) FAIL(14);
	/* 15: an unreadable timeout pointer -> EFAULT. */
	if (futex_wait(fa, 0, FUTEX_BITSET_MATCH_ANY, PRIVATE_U32,
	    (struct timespec *)8, CLOCK_MONOTONIC) != -EFAULT) FAIL(15);
	/* 16: the futex word must be 4-byte aligned -> EINVAL. */
	if (futex_wait((u32 *)((char *)fa + 1), 0, FUTEX_BITSET_MATCH_ANY,
	    PRIVATE_U32, 0, 0) != -EINVAL) FAIL(16);
	/* 17: shared (non-private) waits on the same page also work. */
	if (futex_wait(fa, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0, 0) !=
	    -EAGAIN) FAIL(17);

	/*
	 * futex_wake(2) argument validation.
	 */
	/* 18: no waiters -> 0. */
	if (futex_wake(fa, FUTEX_BITSET_MATCH_ANY, 1, PRIVATE_U32) != 0)
		FAIL(18);
	/* 19: a zero mask -> EINVAL. */
	if (futex_wake(fa, 0, 1, PRIVATE_U32) != -EINVAL) FAIL(19);
	/* 20: bad flags -> EINVAL. */
	if (futex_wake(fa, FUTEX_BITSET_MATCH_ANY, 1, 0x40) != -EINVAL)
		FAIL(20);
	/* 21: U16 -> EINVAL. */
	if (futex_wake(fa, FUTEX_BITSET_MATCH_ANY, 1, 0x01 | FUTEX2_PRIVATE) !=
	    -EINVAL) FAIL(21);
	/* 22: mask wider than the word -> EINVAL. */
	if (futex_wake(fa, 1UL << 32, 1, PRIVATE_U32) != -EINVAL) FAIL(22);
	/* 23: futex2 wake is strict: nr == 0 wakes nobody. */
	if (futex_wake(fa, FUTEX_BITSET_MATCH_ANY, 0, PRIVATE_U32) != 0)
		FAIL(23);
	/* 24: unaligned word -> EINVAL. */
	if (futex_wake((u32 *)((char *)fa + 2), FUTEX_BITSET_MATCH_ANY, 1,
	    PRIVATE_U32) != -EINVAL) FAIL(24);

	/*
	 * A real wake across processes with a bitset: the child waits with
	 * mask 0x2; a wake with a disjoint mask must not wake it, a wake
	 * with an intersecting mask returns 1.
	 */
	pid1 = fork_futex2_waiter(fa, 0x2);
	/* 25: fork(2) works. */
	if (pid1 < 0) FAIL(25);
	msleep(100);
	/* 26: a disjoint mask (0x1) must not wake a waiter on mask 0x2. */
	if (futex_wake(fa, 0x1, INT_MAX, FUTEX2_SIZE_U32) != 0) FAIL(26);
	for (i = 0; i < MAX_POLLS; i++) {
		r = futex_wake(fa, 0x2, INT_MAX, FUTEX2_SIZE_U32);
		if (r != 0)
			break;
		msleep(10);
	}
	/* 27: exactly one waiter is woken. */
	if (r != 1) FAIL(27);
	/* 28: the child's futex_wait() returned 0. */
	if (reap(pid1) != 0) FAIL(28);

	/*
	 * futex_requeue(2) argument validation.
	 */
	wv[0].val = 0;
	wv[0].uaddr = (u64)fa;
	wv[0].flags = FUTEX2_SIZE_U32;
	wv[0].__reserved = 0;
	wv[1] = wv[0];
	wv[1].uaddr = (u64)fb;
	/* 29: flags must be 0 -> EINVAL. */
	if (futex_requeue(wv, 1, 0, INT_MAX) != -EINVAL) FAIL(29);
	/* 30: a NULL waiters pointer -> EINVAL. */
	if (futex_requeue(0, 0, 0, INT_MAX) != -EINVAL) FAIL(30);
	/* 31: an unreadable waiters pointer -> EFAULT. */
	if (futex_requeue((struct futex_waitv *)8, 0, 0, INT_MAX) != -EFAULT)
		FAIL(31);
	/* 32: __reserved must be 0 -> EINVAL. */
	wv[1].__reserved = 1;
	if (futex_requeue(wv, 0, 0, INT_MAX) != -EINVAL) FAIL(32);
	wv[1].__reserved = 0;
	/* 33: per-entry flags are validated: U64 -> EINVAL. */
	wv[1].flags = FUTEX2_SIZE_U64;
	if (futex_requeue(wv, 0, 0, INT_MAX) != -EINVAL) FAIL(33);
	wv[1].flags = FUTEX2_SIZE_U32;
	/* 34: negative counts -> EINVAL (CVE-2018-6927). */
	if (futex_requeue(wv, 0, -1, INT_MAX) != -EINVAL) FAIL(34);
	if (futex_requeue(wv, 0, 0, -1) != -EINVAL) FAIL(34);
	/* 35: waiters[0].val is compared with *uaddr -> EAGAIN on mismatch. */
	wv[0].val = 5;
	if (futex_requeue(wv, 0, 0, INT_MAX) != -EAGAIN) FAIL(35);
	wv[0].val = 0;
	/* 36: no waiters -> 0. */
	if (futex_requeue(wv, 0, 0, INT_MAX) != 0) FAIL(36);

	/*
	 * futex_requeue(2) really moves waiters: two children wait on A,
	 * get requeued onto B, and can then only be woken there.
	 */
	pid1 = fork_futex2_waiter(fa, FUTEX_BITSET_MATCH_ANY);
	pid2 = fork_futex2_waiter(fa, FUTEX_BITSET_MATCH_ANY);
	if (pid1 < 0 || pid2 < 0) FAIL(37);
	for (total = 0, i = 0; i < MAX_POLLS && total < 2; i++) {
		r = futex_requeue(wv, 0, 0, INT_MAX);
		if (r < 0) FAIL(38);
		total += r;
		msleep(10);
	}
	/* 39: both waiters were requeued (return value counts them). */
	if (total != 2) FAIL(39);
	/* 40: nobody is left waiting on A. */
	if (futex_wake(fa, FUTEX_BITSET_MATCH_ANY, INT_MAX, FUTEX2_SIZE_U32) !=
	    0) FAIL(40);
	/* 41: both are woken on B (fails if requeue woke or dropped them). */
	if (futex_wake(fb, FUTEX_BITSET_MATCH_ANY, INT_MAX, FUTEX2_SIZE_U32) !=
	    2) FAIL(41);
	/* 42: both children's futex_wait() returned 0. */
	if (reap(pid1) != 0 || reap(pid2) != 0) FAIL(42);

	/*
	 * futex(2) FUTEX_CMP_REQUEUE / FUTEX_REQUEUE.
	 */
	/* 43: val3 mismatch -> EAGAIN. */
	if (futex(fa, FUTEX_CMP_REQUEUE, 1, 1, fb, 7) != -EAGAIN) FAIL(43);
	/* 44: FUTEX_REQUEUE (no comparison) is a legal operation: 0 waiters. */
	if (futex(fa, FUTEX_REQUEUE, 0, INT_MAX, fb, 0) != 0) FAIL(44);
	/* 45: negative nr_wake / nr_requeue -> EINVAL. */
	if (futex(fa, FUTEX_CMP_REQUEUE, (u32)-1, 1, fb, 0) != -EINVAL)
		FAIL(45);
	if (futex(fa, FUTEX_CMP_REQUEUE, 0, -1, fb, 0) != -EINVAL) FAIL(45);

	/* Broadcast-style CMP_REQUEUE that must move both waiters to B. */
	pid1 = fork_futex_waiter(fa);
	pid2 = fork_futex_waiter(fa);
	if (pid1 < 0 || pid2 < 0) FAIL(46);
	for (total = 0, i = 0; i < MAX_POLLS && total < 2; i++) {
		r = futex(fa, FUTEX_CMP_REQUEUE, 0, INT_MAX, fb, 0);
		if (r < 0) FAIL(47);
		total += r;
		msleep(10);
	}
	/* 48: FUTEX_CMP_REQUEUE returns woken + requeued. */
	if (total != 2) FAIL(48);
	/* 49: A is empty afterwards. */
	if (futex(fa, FUTEX_WAKE, INT_MAX, 0, 0, 0) != 0) FAIL(49);
	/* 50: both wake on B. */
	if (futex(fb, FUTEX_WAKE, INT_MAX, 0, 0, 0) != 2) FAIL(50);
	if (reap(pid1) != 0 || reap(pid2) != 0) FAIL(51);

	/*
	 * nr_requeue == 0 must wake nr_wake and requeue nobody: with both
	 * children asleep on A, CMP_REQUEUE(nr_wake=1, nr_requeue=0) wakes
	 * one and leaves the other on A, so nothing shows up on B.
	 */
	pid1 = fork_futex_waiter(fa);
	pid2 = fork_futex_waiter(fa);
	if (pid1 < 0 || pid2 < 0) FAIL(52);
	msleep(100);
	for (r = 0, i = 0; i < MAX_POLLS && r == 0; i++) {
		r = futex(fa, FUTEX_CMP_REQUEUE, 1, 0, fb, 0);
		if (r < 0) FAIL(53);
		if (r == 0)
			msleep(10);
	}
	/* 54: exactly one waiter is woken. */
	if (r != 1) FAIL(54);
	/* 55: the other waiter was not requeued onto B. */
	if (futex(fb, FUTEX_WAKE, INT_MAX, 0, 0, 0) != 0) FAIL(55);
	for (r = 0, i = 0; i < MAX_POLLS && r == 0; i++) {
		r = futex(fa, FUTEX_WAKE, INT_MAX, 0, 0, 0);
		if (r == 0)
			msleep(10);
	}
	/* 56: it is still waiting on A. */
	if (r != 1) FAIL(56);
	if (reap(pid1) != 0 || reap(pid2) != 0) FAIL(57);

	/*
	 * Legacy futex(2) corner cases fixed alongside.
	 */
	/* 58: FUTEX_WAIT_BITSET with an empty bitset -> EINVAL. */
	if (futex(fa, FUTEX_WAIT_BITSET, 1, 0, 0, 0) != -EINVAL) FAIL(58);
	/* 59: FUTEX_WAIT accepts FUTEX_CLOCK_REALTIME (relative timeout). */
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	if (futex(fa, FUTEX_WAIT | FUTEX_CLOCK_REALTIME, 0, (long)&ts, 0, 0) !=
	    -ETIMEDOUT) FAIL(59);
	/* 60: FUTEX_WAKE_OP still rejects FUTEX_CLOCK_REALTIME -> ENOSYS. */
	if (futex(fa, 5 | FUTEX_CLOCK_REALTIME, 1, 1, fb, 0) != -ENOSYS)
		FAIL(60);
	return (0);
}

void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
