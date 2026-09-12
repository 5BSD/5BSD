/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for madvise(2) advice values.
 * Exit status identifies the failed check.
 */
#define	SYS_write	1
#define	SYS_open	2
#define	SYS_close	3
#define	SYS_mmap	9
#define	SYS_madvise	28
#define	SYS_exit	60
#define	SYS_ftruncate	77
#define	SYS_unlink	87
#define	SYS_getuid	102

#define	EPERM		1
#define	EINVAL		22
#define	EOPNOTSUPP	95

#define	MADV_DONTNEED	4
#define	MADV_REMOVE	9
#define	MADV_MERGEABLE	12
#define	MADV_UNMERGEABLE 13
#define	MADV_HUGEPAGE	14
#define	MADV_NOHUGEPAGE	15
#define	MADV_COLD	20
#define	MADV_PAGEOUT	21
#define	MADV_POPULATE_READ 22
#define	MADV_POPULATE_WRITE 23
#define	MADV_DONTNEED_LOCKED 24
#define	MADV_COLLAPSE	25
#define	MADV_HWPOISON	100
#define	MADV_SOFT_OFFLINE 101
#define	MADV_GUARD_INSTALL 102
#define	MADV_GUARD_REMOVE 103

#define	PAGE	4096
#define	NPAGES	4

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
madvise(void *p, long len, long advice)
{

	return (call(SYS_madvise, (long)p, len, advice, 0, 0, 0));
}

static void
fill(volatile char *p, char v)
{
	long i;

	for (i = 0; i < NPAGES * PAGE; i += 64)
		p[i] = (char)(v + i / PAGE);
}

static int
intact(volatile char *p, char v)
{
	long i;

	for (i = 0; i < NPAGES * PAGE; i += 64)
		if (p[i] != (char)(v + i / PAGE))
			return (0);
	return (1);
}

static int
test(void)
{
	char path[] = "madvise.data";
	volatile char *anon, *file;
	long fd, uid;

	uid = call(SYS_getuid, 0, 0, 0, 0, 0, 0);
	anon = (volatile char *)call(SYS_mmap, 0, NPAGES * PAGE, 3, 0x22, -1, 0);
	if ((long)anon < 0) return (1);
	fill(anon, 'a');

	/*
	 * 2-5: MADV_PAGEOUT and MADV_COLD are reclaim hints that must keep
	 * the data.  A mapping onto Linux MADV_DONTNEED (discard) or
	 * FreeBSD MADV_FREE would zero the pages and fail 3/5.
	 */
	if (madvise((void *)anon, NPAGES * PAGE, MADV_PAGEOUT) != 0) return (2);
	if (!intact(anon, 'a')) return (3);
	if (madvise((void *)anon, NPAGES * PAGE, MADV_COLD) != 0) return (4);
	if (!intact(anon, 'a')) return (5);

	/* 6-8: the same on a dirty MAP_SHARED file mapping. */
	fd = call(SYS_open, (long)path, 2 | 64 | 128, 0600, 0, 0, 0);
	if (fd < 0) return (6);
	(void)call(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
	if (call(SYS_ftruncate, fd, NPAGES * PAGE, 0, 0, 0, 0) != 0) return (6);
	file = (volatile char *)call(SYS_mmap, 0, NPAGES * PAGE, 3, 0x01, fd, 0);
	if ((long)file < 0) return (6);
	fill(file, 'f');
	if (madvise((void *)file, NPAGES * PAGE, MADV_PAGEOUT) != 0) return (7);
	if (!intact(file, 'f')) return (8);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);

	/* 9-12: KSM and THP hints. */
	if (madvise((void *)anon, PAGE, MADV_MERGEABLE) != 0) return (9);
	if (madvise((void *)anon, PAGE, MADV_UNMERGEABLE) != 0) return (10);
	if (madvise((void *)anon, PAGE, MADV_HUGEPAGE) != 0) return (11);
	/* NOHUGEPAGE cannot be honoured: EINVAL as on a Linux without THP. */
	if (madvise((void *)anon, PAGE, MADV_NOHUGEPAGE) != -EINVAL) return (12);
	if (!intact(anon, 'a')) return (13);

	/* 14-18: advice we cannot honour exactly is rejected, not weakened. */
	if (madvise((void *)anon, PAGE, MADV_POPULATE_READ) != -EINVAL) return (14);
	if (madvise((void *)anon, PAGE, MADV_POPULATE_WRITE) != -EINVAL) return (15);
	if (madvise((void *)anon, PAGE, MADV_COLLAPSE) != -EINVAL) return (16);
	if (madvise((void *)anon, PAGE, MADV_GUARD_INSTALL) != -EINVAL) return (17);
	if (madvise((void *)anon, PAGE, MADV_GUARD_REMOVE) != -EINVAL) return (18);
	if (madvise((void *)anon, PAGE, MADV_REMOVE) != -EOPNOTSUPP) return (19);
	/* 20-21: memory failure injection: EPERM unprivileged, EINVAL for root. */
	if (madvise((void *)anon, PAGE, MADV_HWPOISON) != (uid == 0 ? -EINVAL : -EPERM))
		return (20);
	if (madvise((void *)anon, PAGE, MADV_SOFT_OFFLINE) != (uid == 0 ? -EINVAL : -EPERM))
		return (21);
	/* 22: the BoringSSL stub-detection value is still EINVAL. */
	if (madvise((void *)anon, PAGE, -1) != -EINVAL) return (22);
	if (madvise((void *)anon, PAGE, 999) != -EINVAL) return (23);
	if (!intact(anon, 'a')) return (24);

	/* 25-26: DONTNEED_LOCKED discards like DONTNEED (zero-fill on read). */
	if (madvise((void *)anon, NPAGES * PAGE, MADV_DONTNEED_LOCKED) != 0)
		return (25);
	if (anon[0] != 0 || anon[PAGE] != 0) return (26);
	fill(anon, 'b');
	if (madvise((void *)anon, NPAGES * PAGE, MADV_DONTNEED) != 0) return (27);
	if (anon[0] != 0) return (28);
	/* 29: unaligned start is EINVAL. */
	if (madvise((void *)(anon + 1), PAGE, MADV_COLD) != -EINVAL) return (29);
	return (0);
}

void __attribute__((force_align_arg_pointer))
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
