/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test: no Linux libc or sysroot required.
 * Exit status identifies the failed check; each check's comment names the
 * Linux behaviour it asserts.  Where the emulator deliberately rejects a
 * mode it cannot honour exactly, the comment says so.
 *
 * Covers adjtimex(2) and clock_adjtime(2).
 */
struct timeval { long tv_sec; long tv_usec; };

/* <uapi/linux/timex.h>, x86_64 layout (208 bytes). */
struct timex {
	unsigned int modes;
	long offset;
	long freq;
	long maxerror;
	long esterror;
	int status;
	long constant;
	long precision;
	long tolerance;
	struct timeval time;
	long tick;
	long ppsfreq;
	long jitter;
	int shift;
	long stabil;
	long jitcnt;
	long calcnt;
	long errcnt;
	long stbcnt;
	int tai;
	int pad[11];
};

#define	SYS_exit		60
#define	SYS_getuid		102
#define	SYS_adjtimex		159
#define	SYS_clock_adjtime	305

#define	EPERM		1
#define	EFAULT		14
#define	EINVAL		22
#define	EOPNOTSUPP	95

#define	ADJ_OFFSET		0x0001
#define	ADJ_STATUS		0x0010
#define	ADJ_TAI			0x0080
#define	ADJ_SETOFFSET		0x0100
#define	ADJ_MICRO		0x1000
#define	ADJ_NANO		0x2000
#define	ADJ_TICK		0x4000
#define	ADJ_ADJTIME		0x8000
#define	ADJ_OFFSET_SINGLESHOT	0x8001
#define	ADJ_OFFSET_SS_READ	0xa001

#define	STA_NANO		0x2000

#define	CLOCK_REALTIME		0
#define	CLOCK_MONOTONIC		1
#define	CLOCK_PROCESS_CPUTIME_ID 2
#define	CLOCK_THREAD_CPUTIME_ID	3
#define	CLOCK_MONOTONIC_RAW	4
#define	CLOCK_REALTIME_COARSE	5
#define	CLOCK_MONOTONIC_COARSE	6
#define	CLOCK_BOOTTIME		7
#define	CLOCK_REALTIME_ALARM	8
#define	CLOCK_BOOTTIME_ALARM	9
#define	CLOCK_SGI_CYCLE		10
#define	CLOCK_TAI		11

/* Dynamic clock ids: fd-based (CLOCKFD = 3) and per-pid CPU clocks. */
#define	FD_TO_CLOCKID(fd)	((int)((~(unsigned int)(fd) << 3) | 3))
#define	PID_TO_CPUCLOCK(pid)	((int)((~(unsigned int)(pid) << 3) | 0))

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
zero(void *p, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = 0;
}

static long
adjtimex(struct timex *tx)
{
	return (call(SYS_adjtimex, (long)tx, 0, 0, 0, 0, 0));
}

static long
clock_adjtime(long which, struct timex *tx)
{
	return (call(SYS_clock_adjtime, which, (long)tx, 0, 0, 0, 0));
}

/* A clock state return value: TIME_OK (0) .. TIME_ERROR (5). */
static int
is_state(long ret)
{
	return (ret >= 0 && ret <= 5);
}

static int
test(void)
{
	struct timex tx, tx2;
	long ret, root, remaining;
	int status0;

	_Static_assert(sizeof(struct timex) == 208, "timex layout");
	root = call(SYS_getuid, 0, 0, 0, 0, 0, 0) == 0;

	/* 1: a read-only adjtimex returns the clock state, TIME_OK..TIME_ERROR. */
	zero(&tx, sizeof(tx));
	ret = adjtimex(&tx);
	if (!is_state(ret)) return (1);
	/* 2: the USER_HZ tick length is reported and positive. */
	if (tx.tick <= 0 || tx.tick > 1000000) return (2);
	/* 3: the current time is filled in (after 2001). */
	if (tx.time.tv_sec < 1000000000L) return (3);
	/* 4: tv_usec holds nanoseconds under STA_NANO, microseconds otherwise. */
	if ((tx.status & STA_NANO) != 0) {
		if (tx.time.tv_usec < 0 || tx.time.tv_usec >= 1000000000L)
			return (4);
	} else {
		if (tx.time.tv_usec < 0 || tx.time.tv_usec >= 1000000L)
			return (4);
	}
	/* 5: the frequency tolerance is a positive constant. */
	if (tx.tolerance <= 0) return (5);
	/* 6: the TAI offset is non-negative. */
	if (tx.tai < 0) return (6);
	/* 7: the padding is zeroed on the way out. */
	if (tx.pad[0] != 0 || tx.pad[10] != 0) return (7);
	/* 8: a NULL pointer is EFAULT. */
	if (adjtimex(0) != -EFAULT) return (8);
	status0 = tx.status;

	/* 9: clock_adjtime(CLOCK_REALTIME) is adjtimex. */
	zero(&tx2, sizeof(tx2));
	ret = clock_adjtime(CLOCK_REALTIME, &tx2);
	if (!is_state(ret)) return (9);
	/* 10-11: time did not go backwards between the two reads; same tick. */
	if (tx2.time.tv_sec < tx.time.tv_sec) return (10);
	if (tx2.tick != tx.tick) return (11);
	/* 12: clock_adjtime with a NULL pointer is EFAULT. */
	if (clock_adjtime(CLOCK_REALTIME, 0) != -EFAULT) return (12);
	/*
	 * 13-20: every other known clock has no clock_adj method on Linux:
	 * EOPNOTSUPP.
	 */
	zero(&tx2, sizeof(tx2));
	if (clock_adjtime(CLOCK_MONOTONIC, &tx2) != -EOPNOTSUPP) return (13);
	if (clock_adjtime(CLOCK_PROCESS_CPUTIME_ID, &tx2) != -EOPNOTSUPP)
		return (14);
	if (clock_adjtime(CLOCK_THREAD_CPUTIME_ID, &tx2) != -EOPNOTSUPP)
		return (15);
	if (clock_adjtime(CLOCK_MONOTONIC_RAW, &tx2) != -EOPNOTSUPP) return (16);
	if (clock_adjtime(CLOCK_REALTIME_COARSE, &tx2) != -EOPNOTSUPP)
		return (17);
	if (clock_adjtime(CLOCK_MONOTONIC_COARSE, &tx2) != -EOPNOTSUPP)
		return (17);
	if (clock_adjtime(CLOCK_BOOTTIME, &tx2) != -EOPNOTSUPP) return (18);
	if (clock_adjtime(CLOCK_REALTIME_ALARM, &tx2) != -EOPNOTSUPP)
		return (19);
	if (clock_adjtime(CLOCK_BOOTTIME_ALARM, &tx2) != -EOPNOTSUPP)
		return (19);
	if (clock_adjtime(CLOCK_TAI, &tx2) != -EOPNOTSUPP) return (20);
	/* 21-22: CLOCK_SGI_CYCLE (unused slot) and unknown ids are EINVAL. */
	if (clock_adjtime(CLOCK_SGI_CYCLE, &tx2) != -EINVAL) return (21);
	if (clock_adjtime(99, &tx2) != -EINVAL) return (22);
	/*
	 * 23: a dynamic (fd-based) clock id whose descriptor is no POSIX
	 * clock device is EINVAL.  (There are no PTP clock devices to
	 * offer, so every fd-based id ends up here.)
	 */
	if (clock_adjtime(FD_TO_CLOCKID(1), &tx2) != -EINVAL) return (23);
	/* 24: a per-process CPU clock id has no clock_adj: EOPNOTSUPP. */
	if (clock_adjtime(PID_TO_CPUCLOCK(1), &tx2) != -EOPNOTSUPP) return (24);
	/* 25: ...and a per-thread one (CPUCLOCK_PERTHREAD_MASK) too. */
	if (clock_adjtime(PID_TO_CPUCLOCK(1) | 4, &tx2) != -EOPNOTSUPP)
		return (25);

	/*
	 * 26: ADJ_TICK is refused.  Unprivileged callers see EPERM first,
	 * as on Linux (CAP_SYS_TIME is checked before the modes); root gets
	 * EINVAL because there is no adjustable user tick here (Linux would
	 * accept 900000/HZ..1100000/HZ).
	 */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_TICK;
	tx.tick = 10000;
	ret = adjtimex(&tx);
	if (ret != (root ? -EINVAL : -EPERM)) return (26);
	/*
	 * 27: ADJ_SETOFFSET likewise: stepping the clock atomically with
	 * the PLL update cannot be done here, so it is refused rather than
	 * approximated with a settimeofday.
	 */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_SETOFFSET;
	ret = adjtimex(&tx);
	if (ret != (root ? -EINVAL : -EPERM)) return (27);
	/*
	 * 28: a refused call copies the caller's structure back unchanged
	 * (Linux copies it out whatever do_adjtimex() returned).
	 */
	if (tx.modes != ADJ_SETOFFSET || tx.tick != 0 || tx.time.tv_sec != 0)
		return (28);
	/* 29-31: ADJ_TAI / ADJ_STATUS as non-root are EPERM (root would apply). */
	if (!root) {
		zero(&tx, sizeof(tx));
		tx.modes = ADJ_TAI;
		tx.constant = 37;
		if (adjtimex(&tx) != -EPERM) return (29);
		zero(&tx, sizeof(tx));
		tx.modes = ADJ_STATUS;
		if (adjtimex(&tx) != -EPERM) return (30);
		if (clock_adjtime(CLOCK_REALTIME, &tx) != -EPERM) return (31);
		/* 32: an unknown mode bit alone is EPERM too (privilege first). */
		zero(&tx, sizeof(tx));
		tx.modes = 0x0800;
		if (adjtimex(&tx) != -EPERM) return (32);
	} else {
		/*
		 * 33-36: ADJ_NANO / ADJ_MICRO switch the reported resolution
		 * (STA_NANO) and the time field follows; the original mode
		 * is restored afterwards.
		 */
		zero(&tx, sizeof(tx));
		tx.modes = ADJ_NANO;
		if (!is_state(adjtimex(&tx))) return (33);
		if ((tx.status & STA_NANO) == 0 ||
		    tx.time.tv_usec < 0 || tx.time.tv_usec >= 1000000000L)
			return (34);
		zero(&tx, sizeof(tx));
		tx.modes = ADJ_MICRO;
		if (!is_state(adjtimex(&tx))) return (35);
		if ((tx.status & STA_NANO) != 0 ||
		    tx.time.tv_usec < 0 || tx.time.tv_usec >= 1000000L)
			return (36);
		zero(&tx, sizeof(tx));
		tx.modes = (status0 & STA_NANO) != 0 ? ADJ_NANO : ADJ_MICRO;
		if (!is_state(adjtimex(&tx))) return (36);
		/* 37: an unknown mode bit is ignored, as on Linux. */
		zero(&tx, sizeof(tx));
		tx.modes = 0x0800;
		if (!is_state(adjtimex(&tx))) return (37);
	}
	/*
	 * 38: ADJ_ADJTIME without ADJ_OFFSET is EINVAL for everybody, the
	 * documented rule (adjtimex(2): ADJ_OFFSET_SINGLESHOT must be given
	 * in full) - Linux's own check happens to let the bare bit through
	 * because of how it masks it; the documented contract is asserted.
	 */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_ADJTIME;
	if (adjtimex(&tx) != -EINVAL) return (38);
	/* 39: ADJ_OFFSET_SS_READ reads the pending adjtime(2) delta, no privilege. */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_OFFSET_SS_READ;
	tx.offset = 123456789;
	ret = adjtimex(&tx);
	if (!is_state(ret)) return (39);
	/* 40: the input offset was replaced by the pending delta. */
	if (tx.offset == 123456789) return (40);
	remaining = tx.offset;
	/* 41: ADJ_OFFSET_SS_READ through clock_adjtime is the same call. */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_OFFSET_SS_READ;
	tx.offset = 123456789;
	if (!is_state(clock_adjtime(CLOCK_REALTIME, &tx))) return (41);
	if (tx.offset == 123456789) return (41);
	/* 42: ADJ_OFFSET_SINGLESHOT needs privilege ... */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_OFFSET_SINGLESHOT;
	tx.offset = remaining;
	ret = adjtimex(&tx);
	if (!root) {
		if (ret != -EPERM) return (42);
	} else {
		/*
		 * 43-44: ... re-arming the same delta returns the old delta
		 * (it may have been consumed by up to 5000us per second
		 * between the two calls).
		 */
		if (!is_state(ret)) return (43);
		if (tx.offset - remaining > 5000 || remaining - tx.offset > 5000)
			return (44);
	}
	/* 45-46: the structure is fully refilled after a read (tick again). */
	zero(&tx, sizeof(tx));
	tx.modes = ADJ_OFFSET_SS_READ;
	if (!is_state(adjtimex(&tx))) return (45);
	if (tx.tick <= 0 || tx.time.tv_sec < 1000000000L) return (46);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
