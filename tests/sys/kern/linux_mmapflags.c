/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * mmap(2)/mprotect(2) flag semantics: MAP_FIXED_NOREPLACE, MAP_POPULATE,
 * MAP_LOCKED, MAP_HUGETLB, MAP_SYNC, MAP_SHARED_VALIDATE, the no-op hints,
 * argument validation, and PROT_GROWSUP/GROWSDOWN.  Exit status = failed
 * check number.
 */
#define	MINCORE_PAGES	16

static long
mmap6(unsigned long addr, unsigned long len, long prot, long flags, long fd,
    long off)
{

	return (call(9, addr, len, prot, flags, fd, off));
}

static int
test(int argc, char **argv, char **envp)
{
	unsigned char vec[MINCORE_PAGES];
	struct rlimit rl;
	long p, q, r, fd, wfd, i;
	volatile char *c;

	(void)argc; (void)argv; (void)envp;

	/* 1: a plain anonymous private mapping. */
	p = mmap6(0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p < 0) return (1);
	/* 2: MAP_FIXED_NOREPLACE on an occupied range is EEXIST... */
	r = mmap6(p, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED_NOREPLACE, -1, 0);
	if (r != -EEXIST) return (2);
	/* 3: ...also when only the tail overlaps. */
	r = mmap6(p + PAGE, 2 * PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED_NOREPLACE, -1, 0);
	if (r != -EEXIST) return (3);
	/* 4: ...and the existing mapping is untouched (still writable). */
	c = (volatile char *)p;
	c[0] = 'x';
	if (c[0] != 'x') return (4);
	/* 5: on a free range it maps exactly there. */
	q = mmap6(0, 4 * PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (q < 0) return (5);
	if (sys2(SYS_munmap, q, 4 * PAGE) != 0) return (5);
	r = mmap6(q, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (r != q) return (6);
	/* 7: a second NOREPLACE on the same range now fails. */
	r = mmap6(q, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED_NOREPLACE, -1, 0);
	if (r != -EEXIST) return (7);
	/* 8: MAP_FIXED together with NOREPLACE: MAP_FIXED wins, replaces. */
	r = mmap6(q, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED | MAP_FIXED_NOREPLACE, -1, 0);
	if (r != q) return (8);
	/* 9: unaligned address with NOREPLACE is EINVAL. */
	r = mmap6(q + 1, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED_NOREPLACE, -1, 0);
	if (r != -EINVAL) return (9);
	/* 10: after munmap the range is free for NOREPLACE again. */
	if (sys2(SYS_munmap, q, 4 * PAGE) != 0) return (10);
	r = mmap6(q, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED_NOREPLACE, -1, 0);
	if (r != q) return (10);
	(void)sys2(SYS_munmap, q, PAGE);

	/* 11: MAP_POPULATE pre-faults every page (mincore reports resident). */
	r = mmap6(0, MINCORE_PAGES * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (r < 0) return (11);
	xmemset(vec, 0, sizeof(vec));
	if (sys3(SYS_mincore, r, MINCORE_PAGES * PAGE, vec) != 0) return (12);
	for (i = 0; i < MINCORE_PAGES; i++)
		if ((vec[i] & 1) == 0) return (13);
	(void)sys2(SYS_munmap, r, MINCORE_PAGES * PAGE);
	/* 14: without POPULATE a fresh mapping is not resident. */
	r = mmap6(0, MINCORE_PAGES * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0) return (14);
	xmemset(vec, 0xff, sizeof(vec));
	if (sys3(SYS_mincore, r, MINCORE_PAGES * PAGE, vec) != 0) return (14);
	for (i = 0; i < MINCORE_PAGES; i++)
		if ((vec[i] & 1) != 0) return (15);
	(void)sys2(SYS_munmap, r, MINCORE_PAGES * PAGE);

	/* 16: MAP_LOCKED maps and wires; the pages are resident. */
	r = mmap6(0, 4 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	if (r < 0) return (16);
	xmemset(vec, 0, sizeof(vec));
	if (sys3(SYS_mincore, r, 4 * PAGE, vec) != 0) return (17);
	for (i = 0; i < 4; i++)
		if ((vec[i] & 1) == 0) return (17);
	/* 18: munlock of a MAP_LOCKED range works and the memory stays. */
	if (sys2(SYS_munlock, r, 4 * PAGE) != 0) return (18);
	c = (volatile char *)r;
	c[PAGE] = 'y';
	if (c[PAGE] != 'y') return (18);
	(void)sys2(SYS_munmap, r, 4 * PAGE);
	/*
	 * 19: Linux ignores a failed mlock for MAP_LOCKED: with
	 * RLIMIT_MEMLOCK = 0 the mapping is still created.
	 */
	if (sys2(SYS_getrlimit, 8 /* RLIMIT_MEMLOCK */, &rl) != 0) return (19);
	rl.rlim_cur = 0;
	if (sys2(SYS_setrlimit, 8, &rl) == 0) {
		r = mmap6(0, 64 * PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
		if (r < 0) return (19);
		(void)sys2(SYS_munmap, r, 64 * PAGE);
	}

	/* 20-22: MAP_HUGETLB has no pool behind it: ENOMEM, with any size. */
	if (mmap6(0, 2 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_HUGETLB, -1, 0) != -ENOMEM) return (20);
	if (mmap6(0, 2 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0) != -ENOMEM)
		return (21);
	if (mmap6(0, 2 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_1GB, -1, 0) != -ENOMEM)
		return (22);

	/* 23: a file for the shared-mapping cases. */
	fd = tmpfile_fd("mmapflags.tmp");
	if (fd < 0) return (23);
	if (sys2(SYS_ftruncate, fd, 4 * PAGE) != 0) return (23);
	/* 24: MAP_SYNC needs DAX: EOPNOTSUPP with MAP_SHARED_VALIDATE... */
	if (mmap6(0, PAGE, PROT_READ, MAP_SHARED_VALIDATE | MAP_SYNC, fd, 0) !=
	    -EOPNOTSUPP) return (24);
	/* 25: ...but is silently ignored with plain MAP_SHARED (as Linux). */
	r = mmap6(0, PAGE, PROT_READ, MAP_SHARED | MAP_SYNC, fd, 0);
	if (r < 0) return (25);
	(void)sys2(SYS_munmap, r, PAGE);
	/* 26: MAP_SHARED_VALIDATE alone is MAP_SHARED. */
	r = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
	if (r < 0) return (26);
	c = (volatile char *)r;
	c[0] = 'z';
	(void)sys2(SYS_munmap, r, PAGE);
	/* 27: and it rejects an unknown flag bit with EOPNOTSUPP... */
	if (mmap6(0, PAGE, PROT_READ, MAP_SHARED_VALIDATE | (1 << 25), fd, 0) !=
	    -EOPNOTSUPP) return (27);
	/* (1 << 27) lies inside the MAP_HUGE_* field, which the legacy mask
	 * covers, so Linux accepts it: not an "unknown" bit. */
	/* 28: ...whereas MAP_SHARED ignores unknown bits. */
	r = mmap6(0, PAGE, PROT_READ, MAP_SHARED | (1 << 25), fd, 0);
	if (r < 0) return (28);
	(void)sys2(SYS_munmap, r, PAGE);
	/* 29: MAP_SHARED|MAP_PRIVATE is MAP_SHARED_VALIDATE (0x03): valid. */
	r = mmap6(0, PAGE, PROT_READ, MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	if (r < 0) return (29);
	(void)sys2(SYS_munmap, r, PAGE);
	/* 30: neither MAP_SHARED nor MAP_PRIVATE is EINVAL. */
	if (mmap6(0, PAGE, PROT_READ, MAP_ANONYMOUS, -1, 0) != -EINVAL)
		return (30);

	/* 31-36: pure hints are accepted and the mapping is usable. */
	{
		long hints[] = { MAP_NORESERVE, MAP_NONBLOCK, MAP_STACK,
		    MAP_DENYWRITE, MAP_EXECUTABLE, MAP_UNINITIALIZED };
		for (i = 0; i < 6; i++) {
			r = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE |
			    MAP_ANONYMOUS | hints[i], -1, 0);
			if (r < 0) return (31 + i);
			c = (volatile char *)r;
			c[0] = 1;
			(void)sys2(SYS_munmap, r, PAGE);
		}
	}

	/* 37: length 0 is EINVAL. */
	if (mmap6(0, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) !=
	    -EINVAL) return (37);
	/* 38: the fd is ignored with MAP_ANONYMOUS. */
	r = mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 9999, 0);
	if (r < 0) return (38);
	(void)sys2(SYS_munmap, r, PAGE);
	/* 39: a bad fd without MAP_ANONYMOUS is EBADF. */
	if (mmap6(0, PAGE, PROT_READ, MAP_PRIVATE, 9999, 0) != -EBADF)
		return (39);
	/* 40: an unaligned file offset is EINVAL. */
	if (mmap6(0, PAGE, PROT_READ, MAP_PRIVATE, fd, 1) != -EINVAL)
		return (40);
	/* 41: an unaligned MAP_FIXED address is EINVAL. */
	if (mmap6(p + 1, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
	    MAP_FIXED, -1, 0) != -EINVAL) return (41);
	/* 42: an anonymous mapping with an unaligned offset is EINVAL. */
	if (mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 1) !=
	    -EINVAL) return (42);
	/* 43: a write-only file cannot be mapped at all (EACCES). */
	wfd = sys3(SYS_open, "mmapflags.tmp", O_WRONLY, 0);
	if (wfd < 0) return (43);
	if (mmap6(0, PAGE, PROT_READ, MAP_PRIVATE, wfd, 0) != -EACCES)
		return (43);
	(void)sys1(SYS_close, wfd);
	/* 44: PROT_WRITE|MAP_SHARED on a read-only descriptor is EACCES. */
	wfd = sys3(SYS_open, "mmapflags.tmp", O_RDONLY, 0);
	if (wfd < 0) return (44);
	if (mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, wfd, 0) !=
	    -EACCES) return (44);
	/* 45: ...but PROT_WRITE|MAP_PRIVATE (copy on write) is fine. */
	r = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, wfd, 0);
	if (r < 0) return (45);
	(void)sys2(SYS_munmap, r, PAGE);
	(void)sys1(SYS_close, wfd);
	/* 46: MAP_32BIT lands below 4 GiB. */
	r = mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
	    -1, 0);
	if (r < 0 || r >= (1L << 32)) return (46);
	(void)sys2(SYS_munmap, r, PAGE);
	/* 47: MAP_FIXED silently replaces an existing mapping. */
	r = mmap6(p, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
	    -1, 0);
	if (r != p) return (47);
	c = (volatile char *)p;
	if (c[0] != 0) return (47);	/* fresh zero page, not the old 'x' */

	/* 48: PROT_GROWSUP is EINVAL on x86-64. */
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_GROWSUP) != -EINVAL)
		return (48);
	/* 49: both GROWS flags together are EINVAL. */
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_GROWSDOWN |
	    PROT_GROWSUP) != -EINVAL) return (49);
	/* 50: an unknown protection bit is EINVAL. */
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | 0x8) != -EINVAL)
		return (50);
	/* 51: PROT_NONE and back again work. */
	if (sys3(SYS_mprotect, p, PAGE, 0) != 0) return (51);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_WRITE) != 0)
		return (51);
	/* 52: an unaligned mprotect address is EINVAL. */
	if (sys3(SYS_mprotect, p + 1, PAGE, PROT_READ) != -EINVAL) return (52);
	/* 53: mprotect of a freshly unmapped range is ENOMEM. */
	q = mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (q < 0) return (53);
	(void)sys2(SYS_munmap, q, PAGE);
	if (sys3(SYS_mprotect, q, PAGE, PROT_READ) != -ENOMEM) return (53);

	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "mmapflags.tmp");
	return (0);
}

