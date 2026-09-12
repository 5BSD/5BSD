/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test: no Linux libc or sysroot required.
 * Exit status identifies the failed check; each check's comment names the
 * Linux behaviour it asserts.  Where the emulator deliberately rejects an
 * option it cannot honour exactly, the comment says so.
 *
 * Covers setfsuid/setfsgid, sched_setattr/sched_getattr, process_madvise,
 * waitid(P_PIDFD), the prctl(2) options added alongside them, syslog(2)
 * action handling and mlock2(2).
 */
struct iovec { void *base; unsigned long len; };

struct sched_attr {
	unsigned int size;
	unsigned int sched_policy;
	unsigned long long sched_flags;
	int sched_nice;
	unsigned int sched_priority;
	unsigned long long sched_runtime;
	unsigned long long sched_deadline;
	unsigned long long sched_period;
	unsigned int sched_util_min;
	unsigned int sched_util_max;
};

/* Linux amd64 syscall numbers. */
#define	SYS_read		0
#define	SYS_write		1
#define	SYS_close		3
#define	SYS_mmap		9
#define	SYS_munmap		11
#define	SYS_getpid		39
#define	SYS_fork		57
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_getuid		102
#define	SYS_syslog		103
#define	SYS_geteuid		107
#define	SYS_getegid		108
#define	SYS_setfsuid		122
#define	SYS_setfsgid		123
#define	SYS_getpriority		140
#define	SYS_munlock		150
#define	SYS_prctl		157
#define	SYS_set_tid_address	218
#define	SYS_waitid		247
#define	SYS_pipe2		293
#define	SYS_sched_setattr	314
#define	SYS_sched_getattr	315
#define	SYS_mlock2		325
#define	SYS_pidfd_open		434
#define	SYS_process_madvise	440

#define	EPERM		1
#define	ESRCH		3
#define	E2BIG		7
#define	EBADF		9
#define	ECHILD		10
#define	EAGAIN		11
#define	ENOMEM		12
#define	EFAULT		14
#define	ENODEV		19
#define	EINVAL		22

#define	SIGKILL		9
#define	SIGCHLD		17
#define	CLD_EXITED	1
#define	CLD_KILLED	2

#define	P_PIDFD		3
#define	WNOHANG		1
#define	WEXITED		4

#define	MADV_WILLNEED	3
#define	MADV_DONTNEED	4
#define	MADV_COLD	20
#define	MADV_PAGEOUT	21

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

/* Write a one-line note on stderr and exit 0: the test cannot run here. */
static void
skip(const char *msg)
{
	unsigned long n;

	for (n = 0; msg[n] != '\0'; n++)
		;
	(void)call(SYS_write, 2, (long)msg, n, 0, 0, 0);
	call(SYS_exit, 0, 0, 0, 0, 0, 0);
}

static int
test_setfs(void)
{
	long euid, egid;

	euid = call(SYS_geteuid, 0, 0, 0, 0, 0, 0);
	egid = call(SYS_getegid, 0, 0, 0, 0, 0, 0);
	/* 1: setfsuid(-1) is the query idiom; returns the current fsuid. */
	if (call(SYS_setfsuid, -1, 0, 0, 0, 0, 0) != euid) return (1);
	/* 2: setfsuid(euid) returns the previous value, never an error. */
	if (call(SYS_setfsuid, euid, 0, 0, 0, 0, 0) != euid) return (2);
	/* 3/4: same for setfsgid. */
	if (call(SYS_setfsgid, -1, 0, 0, 0, 0, 0) != egid) return (3);
	if (call(SYS_setfsgid, egid, 0, 0, 0, 0, 0) != egid) return (4);
	/*
	 * 5: a value that is not honoured (the fs ids are not decoupled
	 * from the effective ids here) still yields the "previous" value,
	 * as Linux does for a uid the caller may not switch to.
	 */
	if (call(SYS_setfsuid, euid + 12345, 0, 0, 0, 0, 0) != euid)
		return (5);
	/* 6: ...and the effective uid was left alone. */
	if (call(SYS_geteuid, 0, 0, 0, 0, 0, 0) != euid) return (6);
	if (call(SYS_setfsgid, egid + 12345, 0, 0, 0, 0, 0) != egid)
		return (7);
	if (call(SYS_getegid, 0, 0, 0, 0, 0, 0) != egid) return (8);
	return (0);
}

static int
test_sched(int root)
{
	struct sched_attr attr;
	unsigned long long big[16];
	int nice0, nice1;

	zero(&attr, sizeof(attr));
	/* 10: sched_getattr of self with the full structure. */
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 0, 0, 0) != 0)
		return (10);
	/* 11: size reports what the kernel wrote (VER1 = 56). */
	if (attr.size != 56) return (11);
	/* 12: a fresh process is SCHED_OTHER with priority 0. */
	if (attr.sched_policy != 0)
		skip("skipping: test process is not SCHED_OTHER\n");
	if (attr.sched_priority != 0) return (12);
	/* 9: the inherited nice value agrees with getpriority (20 - nice). */
	nice0 = attr.sched_nice;
	if (call(SYS_getpriority, 0, 0, 0, 0, 0, 0) != 20 - nice0) return (9);
	/* 13: non-zero flags are EINVAL. */
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 1, 0, 0) != -EINVAL)
		return (13);
	/* 14: size below SCHED_ATTR_SIZE_VER0 is EINVAL. */
	if (call(SYS_sched_getattr, 0, (long)&attr, 40, 0, 0, 0) != -EINVAL)
		return (14);
	/* 15: size above PAGE_SIZE is EINVAL. */
	if (call(SYS_sched_getattr, 0, (long)&attr, 4097, 0, 0, 0) != -EINVAL)
		return (15);
	/* 16-17: VER0-sized buffer succeeds and reports size 48 (min rule). */
	zero(&attr, sizeof(attr));
	if (call(SYS_sched_getattr, 0, (long)&attr, 48, 0, 0, 0) != 0)
		return (16);
	if (attr.size != 48) return (17);
	/* 18-19: a larger user structure reports our size, 56. */
	zero(big, sizeof(big));
	if (call(SYS_sched_getattr, 0, (long)big, sizeof(big), 0, 0, 0) != 0)
		return (18);
	if (((struct sched_attr *)big)->size != 56) return (19);
	/* 20-21: nonexistent pid is ESRCH, negative pid is EINVAL. */
	if (call(SYS_sched_getattr, 0x7fffffff, (long)&attr, 56, 0, 0, 0) !=
	    -ESRCH)
		return (20);
	if (call(SYS_sched_getattr, -1, (long)&attr, 56, 0, 0, 0) != -EINVAL)
		return (21);
	/* 22: NULL attr is EINVAL. */
	if (call(SYS_sched_getattr, 0, 0, 56, 0, 0, 0) != -EINVAL) return (22);

	/*
	 * 23: SCHED_DEADLINE has no native scheduling class; mapping it to
	 * SCHED_OTHER would silently drop its guarantees, so it is
	 * deliberately EINVAL (what Linux gives for an unknown policy).
	 */
	zero(&attr, sizeof(attr));
	attr.size = 56;
	attr.sched_policy = 6;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (23);
	/* 24: flags argument must be 0. */
	attr.sched_policy = 0;
	if (call(SYS_sched_setattr, 0, (long)&attr, 1, 0, 0, 0) != -EINVAL)
		return (24);
	/* 25-26: size below VER0 is E2BIG and size is rewritten to 56. */
	attr.size = 40;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -E2BIG)
		return (25);
	if (attr.size != 56) return (26);
	/* 27: size above PAGE_SIZE is E2BIG too. */
	attr.size = 4097;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -E2BIG)
		return (27);
	/* 28: a larger struct with non-zero trailing bytes is E2BIG. */
	zero(big, sizeof(big));
	((struct sched_attr *)big)->size = sizeof(big);
	big[15] = 1;
	if (call(SYS_sched_setattr, 0, (long)big, 0, 0, 0, 0) != -E2BIG)
		return (28);
	/* 29: ... and with zero trailing bytes it is accepted. */
	big[15] = 0;
	((struct sched_attr *)big)->size = sizeof(big);
	((struct sched_attr *)big)->sched_nice = nice0;
	if (call(SYS_sched_setattr, 0, (long)big, 0, 0, 0, 0) != 0)
		return (29);
	/* 30: NULL attr is EINVAL. */
	if (call(SYS_sched_setattr, 0, 0, 0, 0, 0, 0) != -EINVAL) return (30);
	/*
	 * 31: SCHED_FLAG_RESET_ON_FORK has no native per-thread bit and
	 * would silently leave children real-time: deliberately EINVAL.
	 */
	zero(&attr, sizeof(attr));
	attr.size = 56;
	attr.sched_flags = 1;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (31);
	/* 32: SCHED_FLAG_RECLAIM / DL_OVERRUN are deadline-only: EINVAL. */
	attr.sched_flags = 0x02;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (32);
	attr.sched_flags = 0x04;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (32);
	/* 33: an unknown flag bit is EINVAL. */
	attr.sched_flags = 0x100;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (33);
	/*
	 * 34-35: SCHED_FLAG_UTIL_CLAMP_MIN is EINVAL with a VER0-sized
	 * struct (Linux) and otherwise too (no utilization clamping here).
	 */
	attr.sched_flags = 0x20;
	attr.size = 48;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (34);
	attr.size = 56;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (35);
	/* 36: SCHED_OTHER with a non-zero priority is EINVAL. */
	attr.sched_flags = 0;
	attr.sched_priority = 1;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (36);
	/* 37: SCHED_FIFO with priority 0 is EINVAL. */
	attr.sched_policy = 1;
	attr.sched_priority = 0;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (37);
	/* 38: SCHED_FIFO with priority 100 (above MAX_RT_PRIO-1) is EINVAL. */
	attr.sched_priority = 100;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (38);
	/* 39: SCHED_BATCH, SCHED_IDLE and SCHED_EXT are deliberately EINVAL. */
	attr.sched_priority = 0;
	attr.sched_policy = 3;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (39);
	attr.sched_policy = 5;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (39);
	attr.sched_policy = 7;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (39);
	/* 40: size 0 means VER0 (ABI quirk) and is accepted. */
	attr.sched_policy = 0;
	attr.sched_nice = nice0;
	attr.size = 0;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (40);
	/* 41-42: nonexistent pid is ESRCH, negative pid is EINVAL. */
	attr.size = 56;
	if (call(SYS_sched_setattr, 0x7fffffff, (long)&attr, 0, 0, 0, 0) !=
	    -ESRCH)
		return (41);
	if (call(SYS_sched_setattr, -1, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (42);
	/* 43: raising nice via sched_nice works unprivileged ... */
	nice1 = nice0 + 5 > 19 ? 19 : nice0 + 5;
	attr.sched_nice = nice1;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (43);
	/* 44: ... and is visible through getpriority (returns 20 - nice). */
	if (call(SYS_getpriority, 0, 0, 0, 0, 0, 0) != 20 - nice1) return (44);
	/* 45-46: ... and through sched_getattr. */
	zero(&attr, sizeof(attr));
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 0, 0, 0) != 0)
		return (45);
	if (attr.sched_nice != nice1) return (46);
	/* 47-48: Linux clamps sched_nice to [-20, 19] instead of rejecting. */
	attr.sched_nice = 200;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (47);
	if (call(SYS_getpriority, 0, 0, 0, 0, 0, 0) != 1) return (48);
	/* 49: lowering nice is EPERM without privilege (and works as root). */
	attr.sched_nice = 18;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) !=
	    (root ? 0 : -EPERM))
		return (49);
	if (root) {
		attr.sched_nice = 19;
		if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
			return (49);
	}
	/* 50-51: SCHED_FLAG_KEEP_PARAMS leaves nice alone. */
	attr.sched_flags = 0x10;
	attr.sched_nice = 0;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (50);
	if (call(SYS_getpriority, 0, 0, 0, 0, 0, 0) != 1) return (51);
	/* 52: SCHED_FLAG_KEEP_POLICY ignores an otherwise-bad policy. */
	attr.sched_flags = 0x08;
	attr.sched_policy = 6;
	attr.sched_nice = 19;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (52);
	/* 53: a negative policy is EINVAL even with KEEP_POLICY. */
	attr.sched_policy = (unsigned int)-1;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != -EINVAL)
		return (53);
	/* 54: KEEP_POLICY|KEEP_PARAMS together are accepted (no change). */
	attr.sched_flags = 0x18;
	attr.sched_policy = 6;
	attr.sched_priority = 77;
	attr.sched_nice = -20;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (54);
	if (call(SYS_getpriority, 0, 0, 0, 0, 0, 0) != 1) return (54);
	/* 55: SCHED_FIFO needs privilege: EPERM unprivileged. */
	zero(&attr, sizeof(attr));
	attr.size = 56;
	attr.sched_policy = 1;
	attr.sched_priority = 10;
	if (!root) {
		if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) !=
		    -EPERM)
			return (55);
		return (0);
	}
	/* 56-58 (root): SCHED_FIFO is set and read back as FIFO. */
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (56);
	zero(&attr, sizeof(attr));
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 0, 0, 0) != 0)
		return (57);
	/*
	 * The native RT range is coarser than Linux's 1..99, so the value
	 * read back may be rounded down (never up); nice is not reported
	 * for RT policies.
	 */
	if (attr.sched_policy != 1 || attr.sched_priority < 1 ||
	    attr.sched_priority > 10 || attr.sched_nice != 0)
		return (58);
	/* 59: SCHED_RR with KEEP_PARAMS keeps the RT priority. */
	attr.sched_policy = 2;
	attr.sched_flags = 0x10;
	attr.sched_priority = 0;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (59);
	zero(&attr, sizeof(attr));
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 0, 0, 0) != 0)
		return (59);
	if (attr.sched_policy != 2 || attr.sched_priority < 1) return (59);
	/* 60: back to SCHED_OTHER, restoring nice. */
	zero(&attr, sizeof(attr));
	attr.size = 56;
	attr.sched_nice = 19;
	if (call(SYS_sched_setattr, 0, (long)&attr, 0, 0, 0, 0) != 0)
		return (60);
	zero(&attr, sizeof(attr));
	if (call(SYS_sched_getattr, 0, (long)&attr, 56, 0, 0, 0) != 0)
		return (60);
	if (attr.sched_policy != 0 || attr.sched_priority != 0 ||
	    attr.sched_nice != 19)
		return (60);
	return (0);
}

/*
 * Fork a child that blocks reading a pipe until it is killed.  Should
 * the parent die first, the write end closes and the child exits on
 * EOF, so it cannot be stranded.  Returns the pid, keeps the write end
 * in *wfd.
 */
static long
fork_blocked_child(int *wfd)
{
	int pipes[2];
	char c;
	long pid;

	if (call(SYS_pipe2, (long)pipes, 0, 0, 0, 0, 0) != 0)
		return (-1);
	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		(void)call(SYS_close, pipes[1], 0, 0, 0, 0, 0);
		(void)call(SYS_read, pipes[0], (long)&c, 1, 0, 0, 0);
		call(SYS_exit, 0, 0, 0, 0, 0, 0);
	}
	(void)call(SYS_close, pipes[0], 0, 0, 0, 0, 0);
	*wfd = pipes[1];
	return (pid);
}

static void
reap(long pid, int wfd)
{
	int status;

	(void)call(SYS_kill, pid, SIGKILL, 0, 0, 0, 0);
	(void)call(SYS_close, wfd, 0, 0, 0, 0, 0);
	(void)call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
}

static int
test_process_madvise(void)
{
	struct iovec iov;
	long fd, pid, ret, child;
	volatile char *page;
	int wfd;

	/* 70: non-zero flags are EINVAL. */
	if (call(SYS_process_madvise, 0, 0, 0, MADV_COLD, 1, 0) != -EINVAL)
		return (70);
	/* 71: vlen above UIO_MAXIOV (1024) is EINVAL. */
	if (call(SYS_process_madvise, 0, 0, 1025, MADV_COLD, 0, 0) != -EINVAL)
		return (71);
	/* 72: a descriptor that is not a pidfd is EBADF. */
	if (call(SYS_process_madvise, 1, 0, 0, MADV_COLD, 0, 0) != -EBADF)
		return (72);
	/* 73: ...and so is a closed one. */
	if (call(SYS_process_madvise, 9999, 0, 0, MADV_COLD, 0, 0) != -EBADF)
		return (73);
	pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
	/* 74: pidfd_open(self). */
	fd = call(SYS_pidfd_open, pid, 0, 0, 0, 0, 0);
	if (fd < 0) return (74);
	page = (volatile char *)call(SYS_mmap, 0, 4096, 3, 0x22, -1, 0);
	if ((long)page < 0) return (75);
	page[0] = 0x5a;
	page[4095] = 0x5b;
	iov.base = (void *)page;
	iov.len = 4096;
	/* 76: MADV_COLD on self returns the number of bytes advised. */
	ret = call(SYS_process_madvise, fd, (long)&iov, 1, MADV_COLD, 0, 0);
	if (ret != 4096) return (76);
	/* 77: MADV_COLD is a hint: contents survive. */
	if (page[0] != 0x5a || page[4095] != 0x5b) return (77);
	/* 78-79: MADV_PAGEOUT likewise. */
	if (call(SYS_process_madvise, fd, (long)&iov, 1, MADV_PAGEOUT, 0, 0) !=
	    4096)
		return (78);
	if (page[0] != 0x5a || page[4095] != 0x5b) return (79);
	/* 80: MADV_WILLNEED works too. */
	if (call(SYS_process_madvise, fd, (long)&iov, 1, MADV_WILLNEED, 0, 0)
	    != 4096)
		return (80);
	/* 81: an empty vector advises nothing and returns 0. */
	if (call(SYS_process_madvise, fd, (long)&iov, 0, MADV_COLD, 0, 0) != 0)
		return (81);
	/* 82: a NULL vector with vlen > 0 is EFAULT. */
	if (call(SYS_process_madvise, fd, 0, 1, MADV_COLD, 0, 0) != -EFAULT)
		return (82);
	/* 83: an unaligned start address is EINVAL. */
	iov.base = (void *)(page + 1);
	if (call(SYS_process_madvise, fd, (long)&iov, 1, MADV_COLD, 0, 0) !=
	    -EINVAL)
		return (83);
	iov.base = (void *)page;
	/* 84: invalid advice is EINVAL. */
	if (call(SYS_process_madvise, fd, (long)&iov, 1, -1, 0, 0) != -EINVAL)
		return (84);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/*
	 * 85-88: another process.  Cross-process advice is not
	 * implemented (no remote vm_map access check); the caller sees the
	 * EPERM Linux gives an unauthorized caller for advice that is
	 * valid remotely, and EINVAL for advice Linux never allows
	 * remotely (MADV_DONTNEED), in that order of precedence.
	 */
	child = fork_blocked_child(&wfd);
	if (child < 0) return (85);
	fd = call(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
	if (fd < 0) {
		reap(child, wfd);
		return (86);
	}
	ret = call(SYS_process_madvise, fd, (long)&iov, 1, MADV_COLD, 0, 0);
	if (ret != -EPERM) {
		reap(child, wfd);
		return (87);
	}
	ret = call(SYS_process_madvise, fd, (long)&iov, 1, MADV_DONTNEED, 0, 0);
	reap(child, wfd);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	if (ret != -EINVAL) return (88);
	(void)call(SYS_munmap, (long)page, 4096, 0, 0, 0, 0);
	return (0);
}

static int
test_waitid_pidfd(void)
{
	int si[32];
	long child, fd, ret;
	int wfd;

	child = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (child < 0) return (90);
	if (child == 0)
		call(SYS_exit, 7, 0, 0, 0, 0, 0);
	/* 91: pidfd_open on the child (possibly already a zombie). */
	fd = call(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
	if (fd < 0) return (91);
	/* 92: waitid(P_PIDFD, fd, WEXITED) reaps it. */
	zero(si, sizeof(si));
	ret = call(SYS_waitid, P_PIDFD, fd, (long)si, WEXITED, 0, 0);
	if (ret != 0) return (92);
	/* 93-94: si_pid (offset 16) is the child, si_status (offset 24) is 7. */
	if (si[4] != child) return (93);
	if (si[6] != 7) return (94);
	/* 95: si_signo is SIGCHLD, si_code is CLD_EXITED. */
	if (si[0] != SIGCHLD || si[2] != CLD_EXITED) return (95);
	/* 96: a second wait finds no child: ECHILD. */
	if (call(SYS_waitid, P_PIDFD, fd, (long)si, WEXITED, 0, 0) != -ECHILD)
		return (96);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 97: a descriptor that is not a pidfd is EBADF. */
	if (call(SYS_waitid, P_PIDFD, 1, (long)si, WEXITED, 0, 0) != -EBADF)
		return (97);
	/* 98: a closed descriptor is EBADF. */
	if (call(SYS_waitid, P_PIDFD, 9999, (long)si, WEXITED, 0, 0) != -EBADF)
		return (98);

	/* 99-100: a running child with WNOHANG: 0, nothing reported. */
	child = fork_blocked_child(&wfd);
	if (child < 0) return (99);
	fd = call(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
	if (fd < 0) {
		reap(child, wfd);
		return (99);
	}
	zero(si, sizeof(si));
	ret = call(SYS_waitid, P_PIDFD, fd, (long)si, WEXITED | WNOHANG, 0, 0);
	if (ret != 0 || si[4] != 0) {
		reap(child, wfd);
		return (100);
	}
	/* 101: options without WEXITED/WSTOPPED/WCONTINUED are EINVAL. */
	ret = call(SYS_waitid, P_PIDFD, fd, (long)si, WNOHANG, 0, 0);
	if (ret != -EINVAL) {
		reap(child, wfd);
		return (101);
	}
	/* 102-103: after SIGKILL the wait reports CLD_KILLED / SIGKILL. */
	if (call(SYS_kill, child, SIGKILL, 0, 0, 0, 0) != 0) {
		reap(child, wfd);
		return (102);
	}
	zero(si, sizeof(si));
	ret = call(SYS_waitid, P_PIDFD, fd, (long)si, WEXITED, 0, 0);
	(void)call(SYS_close, wfd, 0, 0, 0, 0, 0);
	if (ret != 0) return (102);
	if (si[4] != child || si[2] != CLD_KILLED || si[6] != SIGKILL)
		return (103);
	/* 104: an invalid idtype is EINVAL. */
	if (call(SYS_waitid, 9, fd, (long)si, WEXITED, 0, 0) != -EINVAL)
		return (104);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	return (0);
}

static int
test_prctl(void)
{
	long tid, ret;
	unsigned long addr;
	int tidvar, v;

	/* 110-112: PR_GET_TIMING is statistical; PR_SET_TIMING only accepts it. */
	if (call(SYS_prctl, 13, 0, 0, 0, 0, 0) != 0) return (110);
	if (call(SYS_prctl, 14, 1, 0, 0, 0, 0) != -EINVAL) return (111);
	if (call(SYS_prctl, 14, 0, 0, 0, 0, 0) != 0) return (112);
	/*
	 * 113-116: PR_GET_TSC reports PR_TSC_ENABLE; PR_TSC_SIGSEGV would
	 * need a per-thread CR4.TSD, which does not exist here, so setting
	 * it is deliberately EINVAL rather than silently ignored.
	 */
	v = 0;
	if (call(SYS_prctl, 25, (long)&v, 0, 0, 0, 0) != 0) return (113);
	if (v != 1) return (114);
	if (call(SYS_prctl, 26, 2, 0, 0, 0, 0) != -EINVAL) return (115);
	if (call(SYS_prctl, 26, 1, 0, 0, 0, 0) != 0) return (116);
	/* 117: PR_GET_TSC with a bad pointer is EFAULT. */
	if (call(SYS_prctl, 25, 0, 0, 0, 0, 0) != -EFAULT) return (117);
	/* 118-119: securebits are the default (0); setting them needs CAP_SETPCAP. */
	if (call(SYS_prctl, 27, 0, 0, 0, 0, 0) != 0) return (118);
	if (call(SYS_prctl, 28, 0, 0, 0, 0, 0) != -EPERM) return (119);
	/*
	 * 120-121: timer slack is not offered at all (nothing to store it
	 * in, and a made-up GET value would be a lie): EINVAL.
	 */
	if (call(SYS_prctl, 29, 1000, 0, 0, 0, 0) != -EINVAL) return (120);
	if (call(SYS_prctl, 30, 0, 0, 0, 0, 0) != -EINVAL) return (121);
	/* 122-124: PR_GET_TID_ADDRESS returns what set_tid_address installed. */
	tid = call(SYS_set_tid_address, (long)&tidvar, 0, 0, 0, 0, 0);
	if (tid <= 0) return (122);
	addr = 0;
	if (call(SYS_prctl, 40, (long)&addr, 0, 0, 0, 0) != 0) return (123);
	if (addr != (unsigned long)&tidvar) return (124);
	/* 125: PR_GET_TID_ADDRESS with a bad pointer is EFAULT. */
	if (call(SYS_prctl, 40, 0, 0, 0, 0, 0) != -EFAULT) return (125);
	/*
	 * 126-129: THP cannot be disabled per process (deliberately EINVAL);
	 * the enabled state is settable and readable; extra args are EINVAL.
	 */
	if (call(SYS_prctl, 41, 0, 0, 0, 0, 0) != 0) return (126);
	if (call(SYS_prctl, 41, 1, 0, 0, 0, 0) != -EINVAL) return (127);
	if (call(SYS_prctl, 41, 0, 1, 0, 0, 0) != -EINVAL) return (127);
	if (call(SYS_prctl, 42, 0, 0, 0, 0, 0) != 0) return (128);
	if (call(SYS_prctl, 42, 1, 0, 0, 0, 0) != -EINVAL) return (129);
	/* 130-131: speculation control is ENODEV, as on an arch without it. */
	if (call(SYS_prctl, 52, 0, 0, 0, 0, 0) != -ENODEV) return (130);
	if (call(SYS_prctl, 53, 0, 0, 0, 0, 0) != -ENODEV) return (131);
	/* 132: still-unsupported options are EINVAL (PR_SET_MM). */
	ret = call(SYS_prctl, 35, 0, 0, 0, 0, 0);
	if (ret != -EINVAL) return (132);
	/* 133: PR_CAPBSET_DROP is EINVAL (no capability bounding set). */
	if (call(SYS_prctl, 24, 0, 0, 0, 0, 0) != -EINVAL) return (133);
	return (0);
}

static int
test_syslog(int root)
{
	char buf[64];
	long ret;

	/* 140-141: OPEN and CLOSE are historical no-ops. */
	if (call(SYS_syslog, 1, 0, 0, 0, 0, 0) != 0) return (140);
	if (call(SYS_syslog, 0, 0, 0, 0, 0, 0) != 0) return (141);
	/*
	 * 142: SIZE_BUFFER is the message buffer size, or EPERM when the
	 * buffer is hidden from unprivileged users
	 * (security.bsd.unprivileged_read_msgbuf=0).
	 */
	ret = call(SYS_syslog, 10, 0, 0, 0, 0, 0);
	if (ret <= 0 && ret != -EPERM) return (142);
	/* 143: READ_ALL with len 0 reads nothing. */
	if (call(SYS_syslog, 3, (long)buf, 0, 0, 0, 0) != 0) return (143);
	/* 144-145: a NULL buffer or negative length is EINVAL. */
	if (call(SYS_syslog, 3, 0, 10, 0, 0, 0) != -EINVAL) return (144);
	if (call(SYS_syslog, 3, (long)buf, -1, 0, 0, 0) != -EINVAL)
		return (145);
	/* 146: READ_ALL into a small buffer returns at most len bytes. */
	ret = call(SYS_syslog, 3, (long)buf, sizeof(buf), 0, 0, 0);
	if (ret != -EPERM && (ret < 0 || ret > (long)sizeof(buf))) return (146);
	/* 147: an unknown action is EINVAL for everybody. */
	if (call(SYS_syslog, 99, 0, 0, 0, 0, 0) != -EINVAL) return (147);
	/*
	 * 148-152: CONSOLE_OFF/ON/LEVEL, READ and SIZE_UNREAD need
	 * CAP_SYSLOG on Linux, so they are EPERM unprivileged; for root
	 * they are deliberately EINVAL because the native kernel has no
	 * console log level and no read cursor into the message buffer.
	 */
	ret = call(SYS_syslog, 6, 0, 0, 0, 0, 0);
	if (ret != (root ? -EINVAL : -EPERM)) return (148);
	ret = call(SYS_syslog, 7, 0, 0, 0, 0, 0);
	if (ret != (root ? -EINVAL : -EPERM)) return (149);
	ret = call(SYS_syslog, 8, 0, 0, 0, 0, 0);
	if (ret != (root ? -EINVAL : -EPERM)) return (150);
	ret = call(SYS_syslog, 9, 0, 0, 0, 0, 0);
	if (ret != (root ? -EINVAL : -EPERM)) return (151);
	ret = call(SYS_syslog, 2, (long)buf, sizeof(buf), 0, 0, 0);
	if (ret != (root ? -EINVAL : -EPERM)) return (152);
	/*
	 * 153-155: CLEAR / READ_CLEAR are EPERM unprivileged; READ_CLEAR
	 * validates its buffer first (EINVAL) like READ_ALL.  Not run as
	 * root: they would wipe the host's message buffer.
	 */
	if (!root) {
		if (call(SYS_syslog, 5, 0, 0, 0, 0, 0) != -EPERM) return (153);
		if (call(SYS_syslog, 4, (long)buf, sizeof(buf), 0, 0, 0) !=
		    -EPERM)
			return (154);
		if (call(SYS_syslog, 4, 0, 10, 0, 0, 0) != -EINVAL)
			return (155);
	}
	return (0);
}

static int
test_mlock2(void)
{
	long page, r0, r1;

	page = call(SYS_mmap, 0, 4096, 3, 0x22, -1, 0);
	if (page < 0) return (160);
	/* 161: unknown flags are EINVAL before anything else is looked at. */
	if (call(SYS_mlock2, 0, 0, 2, 0, 0, 0) != -EINVAL) return (161);
	/*
	 * 162: plain mlock2 succeeds, or fails only on the memlock limit
	 * (ENOMEM), the wired-page limit (EAGAIN) or privilege (EPERM).
	 */
	r0 = call(SYS_mlock2, page, 4096, 0, 0, 0, 0);
	if (r0 != 0 && r0 != -ENOMEM && r0 != -EPERM && r0 != -EAGAIN)
		return (162);
	/*
	 * 163: MLOCK_ONFAULT gives the same answer (wiring eagerly is a
	 * superset of locking on fault, so the flag is honoured).
	 */
	r1 = call(SYS_mlock2, page, 4096, 1, 0, 0, 0);
	if (r1 != r0) return (163);
	/* 164: any other flag is EINVAL. */
	if (call(SYS_mlock2, page, 4096, 2, 0, 0, 0) != -EINVAL) return (164);
	if (call(SYS_mlock2, page, 4096, 3, 0, 0, 0) != -EINVAL) return (164);
	/* 165: the range can be unlocked again. */
	if (r0 == 0 && call(SYS_munlock, page, 4096, 0, 0, 0, 0) != 0)
		return (165);
	(void)call(SYS_munmap, page, 4096, 0, 0, 0, 0);
	return (0);
}

static int
test(void)
{
	int r, root;

	root = call(SYS_getuid, 0, 0, 0, 0, 0, 0) == 0;
	if ((r = test_setfs()) != 0) return (r);
	if ((r = test_sched(root)) != 0) return (r);
	if ((r = test_process_madvise()) != 0) return (r);
	if ((r = test_waitid_pidfd()) != 0) return (r);
	if ((r = test_prctl()) != 0) return (r);
	if ((r = test_syslog(root)) != 0) return (r);
	if ((r = test_mlock2()) != 0) return (r);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
