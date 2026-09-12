/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for readahead(2),
 * restart_syscall(2) and the arch_prctl(2) feature-query codes: no Linux
 * libc or sysroot required.  Exit status identifies the failed check.
 */
typedef unsigned long u64;
typedef unsigned int u32;

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "cc", "memory");
	return (result);
}

static void
cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d)
{

	__asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) :
	    "a"(leaf), "c"(sub));
}

static u64
xgetbv0(void)
{
	u32 lo, hi;

	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	return ((u64)hi << 32 | lo);
}

#define	EPERM		1
#define	EBADF		9
#define	EEXIST		17
#define	ENODEV		19
#define	EINVAL		22
#define	EOPNOTSUPP	95
#define	EINTR		4

#define	ARCH_SET_FS		0x1002
#define	ARCH_GET_FS		0x1003
#define	ARCH_GET_CPUID		0x1011
#define	ARCH_SET_CPUID		0x1012
#define	ARCH_GET_XCOMP_SUPP	0x1021
#define	ARCH_GET_XCOMP_PERM	0x1022
#define	ARCH_REQ_XCOMP_PERM	0x1023
#define	ARCH_MAP_VDSO_X32	0x2001
#define	ARCH_MAP_VDSO_64	0x2003
#define	ARCH_GET_UNTAG_MASK	0x4001
#define	ARCH_ENABLE_TAGGED_ADDR	0x4002
#define	ARCH_GET_MAX_TAG_BITS	0x4003
#define	ARCH_SHSTK_ENABLE	0x5001
#define	ARCH_SHSTK_DISABLE	0x5002
#define	ARCH_SHSTK_LOCK		0x5003
#define	ARCH_SHSTK_UNLOCK	0x5004
#define	ARCH_SHSTK_STATUS	0x5005

static int
test(void)
{
	char path[] = "machdep2.data";
	char buf[] = "0123456789abcdef";
	u32 a, b, c, d;
	u64 val, xcr0, fsbase;
	long fd, rofd, dirfd;
	int pipes[2];

	fd = call(2, (long)path, 2 | 64 | 128, 0600, 0, 0, 0);
	if (fd < 0) return (1);
	if (call(1, fd, (long)buf, 16, 0, 0, 0) != 16) return (2);
	/* 3: readahead on a readable regular file succeeds. */
	if (call(187, fd, 0, 16, 0, 0, 0) != 0) return (3);
	/* 4: a range past EOF and a huge count are fine (hint). */
	if (call(187, fd, 1 << 20, 1 << 20, 0, 0, 0) != 0) return (4);
	if (call(187, fd, 8, -1L, 0, 0, 0) != 0) return (5);
	/* 6: a negative offset is a no-op hint on Linux (returns 0). */
	if (call(187, fd, -1, 16, 0, 0, 0) != 0) return (6);
	/* 7: write-only descriptor is EBADF (not open for reading). */
	rofd = call(2, (long)path, 1, 0, 0, 0, 0);
	if (rofd < 0) return (7);
	if (call(187, rofd, 0, 16, 0, 0, 0) != -EBADF) return (8);
	(void)call(3, rofd, 0, 0, 0, 0, 0);
	if (call(87, (long)path, 0, 0, 0, 0, 0) != 0) return (9);
	/* 10: bad descriptor is EBADF. */
	if (call(187, -1, 0, 16, 0, 0, 0) != -EBADF) return (10);
	if (call(187, fd + 100, 0, 16, 0, 0, 0) != -EBADF) return (11);
	(void)call(3, fd, 0, 0, 0, 0, 0);
	if (call(187, fd, 0, 16, 0, 0, 0) != -EBADF) return (12);
	/* 13: a pipe is EINVAL (Linux), not ESPIPE (FreeBSD fadvise). */
	if (call(22, (long)pipes, 0, 0, 0, 0, 0) != 0) return (13);
	if (call(187, pipes[0], 0, 16, 0, 0, 0) != -EINVAL) return (14);
	/* 15: a directory is not a regular file: EINVAL. */
	dirfd = call(2, (long)".", 0 | 0200000, 0, 0, 0, 0);
	if (dirfd < 0) return (15);
	if (call(187, dirfd, 0, 16, 0, 0, 0) != -EINVAL) return (16);

	/* 17: restart_syscall called directly fails with EINTR. */
	if (call(219, 0, 0, 0, 0, 0, 0) != -EINTR) return (17);

	/* 18: ARCH_GET_XCOMP_SUPP reports x87 and SSE at least. */
	val = 0;
	if (call(158, ARCH_GET_XCOMP_SUPP, (long)&val, 0, 0, 0, 0) != 0)
		return (18);
	if ((val & 3) != 3) return (19);
	/* 20: and matches XCR0 as enabled by the OS. */
	cpuid(1, 0, &a, &b, &c, &d);
	if ((c & (1 << 27)) != 0) {
		xcr0 = xgetbv0();
		if (val != xcr0) return (20);
		/* 21: AVX bit reported iff XCR0 has it. */
		if (((val >> 2) & 1) != ((xcr0 >> 2) & 1)) return (21);
	}
	/* 22: ARCH_GET_XCOMP_PERM is the same mask (no permission model). */
	xcr0 = val;
	val = 0;
	if (call(158, ARCH_GET_XCOMP_PERM, (long)&val, 0, 0, 0, 0) != 0)
		return (22);
	if (val != xcr0) return (23);
	/* 24: bad user pointer is EFAULT. */
	if (call(158, ARCH_GET_XCOMP_SUPP, 0, 0, 0, 0, 0) != -14) return (24);
	/*
	 * 25-27: REQ_XCOMP_PERM takes a component number, and only the
	 * dynamically enabled XTILEDATA (18) has a permission entry: x87,
	 * SSE and AVX are EOPNOTSUPP even though they are always enabled.
	 */
	if (call(158, ARCH_REQ_XCOMP_PERM, 0, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (25);
	if (call(158, ARCH_REQ_XCOMP_PERM, 1, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (26);
	if (call(158, ARCH_REQ_XCOMP_PERM, 2, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (27);
	/* 28: AMX tile data is permitted iff XCR0 has both tile components. */
	if ((xcr0 & (3UL << 17)) == (3UL << 17)) {
		if (call(158, ARCH_REQ_XCOMP_PERM, 18, 0, 0, 0, 0) != 0)
			return (28);
	} else {
		if (call(158, ARCH_REQ_XCOMP_PERM, 18, 0, 0, 0, 0) !=
		    -EOPNOTSUPP)
			return (28);
	}
	/* 29: an unknown component number is EINVAL. */
	if (call(158, ARCH_REQ_XCOMP_PERM, 63, 0, 0, 0, 0) != -EINVAL)
		return (29);
	if (call(158, ARCH_REQ_XCOMP_PERM, 1000, 0, 0, 0, 0) != -EINVAL)
		return (30);
	/* 31: CPUID faulting: GET reports enabled (1), SET is ENODEV. */
	if (call(158, ARCH_GET_CPUID, 0, 0, 0, 0, 0) != 1) return (31);
	if (call(158, ARCH_SET_CPUID, 0, 0, 0, 0, 0) != -ENODEV) return (32);
	if (call(158, ARCH_SET_CPUID, 1, 0, 0, 0, 0) != -ENODEV) return (33);
	/* 34: unknown code is EINVAL. */
	if (call(158, 0x9999, 0, 0, 0, 0, 0) != -EINVAL) return (34);
	/* 35: vDSO is already mapped: EEXIST; no x32 ABI: EINVAL. */
	if (call(158, ARCH_MAP_VDSO_64, 0, 0, 0, 0, 0) != -EEXIST) return (35);
	if (call(158, ARCH_MAP_VDSO_X32, 0, 0, 0, 0, 0) != -EINVAL) return (36);
	/* 37: LAM is off: untag mask is all ones, 0 tag bits, enable ENODEV. */
	val = 0;
	if (call(158, ARCH_GET_UNTAG_MASK, (long)&val, 0, 0, 0, 0) != 0)
		return (37);
	if (val != ~0UL) return (38);
	val = 1;
	if (call(158, ARCH_GET_MAX_TAG_BITS, (long)&val, 0, 0, 0, 0) != 0)
		return (39);
	if (val != 0) return (40);
	if (call(158, ARCH_ENABLE_TAGGED_ADDR, 6, 0, 0, 0, 0) != -ENODEV)
		return (41);
	/* 42: shadow stacks: status 0, enable/disable EOPNOTSUPP. */
	val = 1;
	if (call(158, ARCH_SHSTK_STATUS, (long)&val, 0, 0, 0, 0) != 0)
		return (42);
	if (val != 0) return (43);
	if (call(158, ARCH_SHSTK_ENABLE, 1, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (44);
	if (call(158, ARCH_SHSTK_DISABLE, 2, 0, 0, 0, 0) != -EOPNOTSUPP)
		return (45);
	/* 46: more than one feature at a time, or none, is EINVAL. */
	if (call(158, ARCH_SHSTK_ENABLE, 3, 0, 0, 0, 0) != -EINVAL) return (46);
	if (call(158, ARCH_SHSTK_ENABLE, 0, 0, 0, 0, 0) != -EINVAL) return (47);
	if (call(158, ARCH_SHSTK_ENABLE, 4, 0, 0, 0, 0) != -EINVAL) return (48);
	/* 49: LOCK succeeds, UNLOCK is only for ptrace. */
	if (call(158, ARCH_SHSTK_LOCK, 1, 0, 0, 0, 0) != 0) return (49);
	if (call(158, ARCH_SHSTK_UNLOCK, 1, 0, 0, 0, 0) != -EINVAL) return (50);
	/* 51: the existing FS base codes still work. */
	fsbase = 0;
	if (call(158, ARCH_GET_FS, (long)&fsbase, 0, 0, 0, 0) != 0) return (51);
	if (call(158, ARCH_SET_FS, (long)fsbase, 0, 0, 0, 0) != 0) return (52);
	if (call(158, ARCH_SET_FS, ~0UL, 0, 0, 0, 0) != -EPERM) return (53);
	return (0);
}

/* ELF entry has no return address; realign before calling C functions. */
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
