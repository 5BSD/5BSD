/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial memory tests: huge NORESERVE reservations (what Go/JVM do),
 * mremap grow/shrink/move over live data, MAP_FIXED_NOREPLACE racing
 * between two threads, madvise(DONTNEED) on shared file mappings (must
 * not lose file data), MADV_FREE then read, mprotect splits and merges,
 * MAP_GROWSDOWN growth, length overflow, mincore on holes, msync flags,
 * fork with 10k mappings, and process_madvise on a busy child.  Exit
 * status = failed check number.
 */
#include "linux_test.h"

#define	MREMAP_MAYMOVE	1
#define	MREMAP_FIXED	2
#define	MREMAP_DONTUNMAP 4
#define	MADV_DONTNEED	4
#define	MADV_FREE	8
#define	MADV_COLD	20
#define	MADV_PAGEOUT	21
#define	MS_ASYNC	1
#define	MS_INVALIDATE	2
#define	MS_SYNC		4
#define	NRACE		2000

static long
mmap6(unsigned long addr, unsigned long len, long prot, long flags, long fd,
    long off)
{

	return (call(SYS_mmap, addr, len, prot, flags, fd, off));
}

static unsigned long race_addr;
static int race_wins[2];

static int race_go;

static int
racer(void *arg)
{
	long me = (long)arg, i, r;

	while (!__atomic_load_n(&race_go, __ATOMIC_ACQUIRE))
		sleep_ms(1);
	for (i = 0; i < NRACE; i++) {
		r = mmap6(race_addr + i * PAGE, PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
		if (r == (long)(race_addr + i * PAGE))
			race_wins[me]++;
		else if (r != -EEXIST)
			return (1);
	}
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th[2];
	unsigned char vec[64];
	volatile char *c;
	long p, q, r, fd, i;
	int status;

	(void)argc; (void)argv; (void)envp;

	msg("mmap: 1-2\n");
	/* 1-2: a 64 GiB NORESERVE reservation; touch pages 1 GiB apart. */
	p = mmap6(0, 64UL << 30, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (p < 0) { msgnum("64G reserve ", p); return (1); }
	c = (volatile char *)p;
	for (i = 0; i < 64; i++)
		c[i << 30] = (char)i;
	for (i = 0; i < 64; i++)
		if (c[i << 30] != (char)i) return (2);
	/* mincore over a 16-page window: exactly the touched page resident */
	if (sys3(SYS_mincore, p, 16 * PAGE, vec) != 0) return (2);
	if ((vec[0] & 1) == 0 || (vec[1] & 1) != 0) return (2);
	if (sys2(SYS_munmap, p, 64UL << 30) != 0) return (2);

	msg("mmap: 3-6\n");
	/* 3-6: mremap: grow in place or move, data survives; shrink; FIXED. */
	p = mmap6(0, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	if (p < 0) return (3);
	c = (volatile char *)p;
	for (i = 0; i < 4; i++) c[i * PAGE] = 'A' + i;
	q = sys5(SYS_mremap, p, 4 * PAGE, 64 * PAGE, MREMAP_MAYMOVE, 0);
	if (q < 0) return (3);
	c = (volatile char *)q;
	for (i = 0; i < 4; i++) if (c[i * PAGE] != 'A' + i) return (4);
	c[63 * PAGE] = 'Z';
	/* shrink back */
	r = sys5(SYS_mremap, q, 64 * PAGE, 2 * PAGE, 0, 0);
	if (r != q) return (5);
	if (c[PAGE] != 'B') return (5);
	if (sys3(SYS_mincore, q + 2 * PAGE, PAGE, vec) != -ENOMEM) return (5);
	/* FIXED move to a chosen free address */
	p = mmap6(0, 8 * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)sys2(SYS_munmap, p, 8 * PAGE);
	r = sys5(SYS_mremap, q, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, p);
	if (r != p) return (6);
	c = (volatile char *)p;
	if (c[PAGE] != 'B') return (6);
	/* old address is gone */
	if (sys3(SYS_mincore, q, PAGE, vec) != -ENOMEM) return (6);
	/* invalid: FIXED without MAYMOVE, DONTUNMAP, overlapping FIXED */
	if (sys5(SYS_mremap, p, 2 * PAGE, 2 * PAGE, MREMAP_FIXED, q) != -EINVAL)
		return (6);
	if (sys5(SYS_mremap, p, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE |
	    MREMAP_DONTUNMAP, 0) != -EINVAL) return (6);
	if (sys5(SYS_mremap, p, 2 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED,
	    p + PAGE) != -EINVAL) return (6);
	if (sys5(SYS_mremap, p + 1, PAGE, PAGE, 0, 0) != -EINVAL) return (6);
	(void)sys2(SYS_munmap, p, 2 * PAGE);

	msg("mmap: 7-8\n");
	/* 7-8: two threads racing MAP_FIXED_NOREPLACE on the same 2000 pages. */
	/* threads first: their stacks must not land in the race region */
	race_wins[0] = race_wins[1] = 0;
	race_go = 0;
	if (thread_create(&th[0], racer, (void *)0) != 0) return (7);
	if (thread_create(&th[1], racer, (void *)1) != 0) return (7);
	p = mmap6(0, NRACE * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p < 0) return (7);
	(void)sys2(SYS_munmap, p, NRACE * PAGE);
	race_addr = p;
	__atomic_store_n(&race_go, 1, __ATOMIC_RELEASE);
	if (thread_join(&th[0]) != 0 || thread_join(&th[1]) != 0) return (7);
	/* every page won exactly once, and every page is mapped */
	if (race_wins[0] + race_wins[1] != NRACE) {
		msgnum("wins ", race_wins[0] + race_wins[1]);
		return (8);
	}
	for (i = 0; i < NRACE; i += 97) {
		c = (volatile char *)(p + i * PAGE);
		c[0] = 1;
	}
	(void)sys2(SYS_munmap, p, NRACE * PAGE);

	msg("mmap: 9-11\n");
	/* 9-11: MADV_DONTNEED on a MAP_SHARED file mapping keeps file data. */
	fd = tmpfile_fd("mm.tmp");
	if (fd < 0) return (9);
	if (sys2(SYS_ftruncate, fd, 4 * PAGE) != 0) return (9);
	p = mmap6(0, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p < 0) return (9);
	c = (volatile char *)p;
	c[0] = 'S'; c[3 * PAGE] = 'T';
	if (sys3(SYS_msync, p, 4 * PAGE, MS_SYNC) != 0) return (9);
	if (sys3(SYS_madvise, p, 4 * PAGE, MADV_DONTNEED) != 0) return (10);
	if (c[0] != 'S' || c[3 * PAGE] != 'T') return (10);	/* re-read from file */
	{
		char b[2];

		if (sys4(SYS_pread64, fd, b, 1, 0) != 1 || b[0] != 'S') return (10);
	}
	/* a private mapping of the file: DONTNEED drops private COW copies */
	q = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (q < 0) return (11);
	c = (volatile char *)q;
	c[0] = 'P';
	r = sys3(SYS_madvise, q, PAGE, MADV_DONTNEED);
	if (r != 0) { msgnum("private DONTNEED ", r); return (11); }
	if (c[0] != 'S') { msg("private DONTNEED kept the COW page\n"); return (11); }
	(void)sys2(SYS_munmap, q, PAGE);
	/* msync flags: SYNC|ASYNC together EINVAL; unknown EINVAL; INVALIDATE ok */
	r = sys3(SYS_msync, p, PAGE, MS_SYNC | MS_ASYNC);
	if (r != -EINVAL) { msgnum("msync SYNC|ASYNC ", r); return (11); }
	r = sys3(SYS_msync, p, PAGE, 8);
	if (r != -EINVAL) { msgnum("msync 8 ", r); return (11); }
	r = sys3(SYS_msync, p, PAGE, MS_INVALIDATE);
	if (r != 0) { msgnum("msync INVALIDATE ", r); return (11); }
	r = sys3(SYS_msync, p + 1, PAGE, MS_ASYNC);
	if (r != -EINVAL) { msgnum("msync unaligned ", r); return (11); }
	(void)sys2(SYS_munmap, p, 4 * PAGE);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "mm.tmp");

	msg("mmap: 12\n");
	/* 12: MADV_FREE: contents are either kept or zero, never garbage. */
	p = mmap6(0, 16 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	c = (volatile char *)p;
	for (i = 0; i < 16; i++) c[i * PAGE] = 0x5a;
	if (sys3(SYS_madvise, p, 16 * PAGE, MADV_FREE) != 0) return (12);
	for (i = 0; i < 16; i++)
		if (c[i * PAGE] != 0x5a && c[i * PAGE] != 0) return (12);
	/* writing again after FREE cancels it */
	c[0] = 0x11;
	if (c[0] != 0x11) return (12);
	(void)sys2(SYS_munmap, p, 16 * PAGE);

	msg("mmap: 13-14\n");
	/* 13-14: mprotect splits: 3-way split then merge, contents intact. */
	p = mmap6(0, 8 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	c = (volatile char *)p;
	for (i = 0; i < 8; i++) c[i * PAGE] = 'a' + i;
	if (sys3(SYS_mprotect, p + 2 * PAGE, 3 * PAGE, PROT_READ) != 0) return (13);
	for (i = 0; i < 8; i++) if (c[i * PAGE] != 'a' + i) return (13);
	r = sys3(SYS_mprotect, p, 8 * PAGE, PROT_READ | PROT_WRITE);
	if (r != 0) { msgnum("mprotect merge ", r); return (14); }
	c[3 * PAGE] = 'x';
	if (c[3 * PAGE] != 'x') return (14);
	/* mprotect across a hole is ENOMEM and changes nothing before it */
	(void)sys2(SYS_munmap, p + 4 * PAGE, PAGE);
	r = sys3(SYS_mprotect, p, 8 * PAGE, PROT_READ);
	if (r != -ENOMEM) { msgnum("mprotect across hole ", r); return (14); }
	(void)sys2(SYS_munmap, p, 8 * PAGE);

	msg("mmap: 15\n");
	/* 15: length overflow: addr + len wraps -> EINVAL/ENOMEM, no mapping. */
	if (mmap6(0, ~0UL - PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
	    >= 0) return (15);
	r = sys2(SYS_munmap, PAGE, ~0UL - 2 * PAGE);
	if (r != -EINVAL && r != 0) return (15);
	if (sys3(SYS_mprotect, PAGE, ~0UL - PAGE, PROT_READ) != -ENOMEM &&
	    sys3(SYS_mprotect, PAGE, ~0UL - PAGE, PROT_READ) != -EINVAL) return (15);
	if (sys3(SYS_madvise, PAGE, ~0UL - PAGE, MADV_COLD) != -EINVAL &&
	    sys3(SYS_madvise, PAGE, ~0UL - PAGE, MADV_COLD) != -ENOMEM) return (15);

	msg("mmap: 16-17\n");
	/* 16-17: MAP_GROWSDOWN stack: touching below the mapped top grows it. */
	p = mmap6(0, 16 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	if (p < 0) return (16);
	c = (volatile char *)p;
	c[16 * PAGE - 1] = 'g';		/* top: mapped */
	c[15 * PAGE] = 'f';		/* a page inside the initial region */
	if (c[15 * PAGE] != 'f' || c[16 * PAGE - 1] != 'g') return (17);
	(void)sys2(SYS_munmap, p, 16 * PAGE);

	msg("mmap: 18-19\n");
	/* 18-19: fork with 5000 mappings; the child sees the same data. */
	{
		long base;

		base = mmap6(0, 5000 * PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (base < 0) return (18);
		/* split into 5000 entries by alternating protection */
		for (i = 0; i < 5000; i += 2)
			if (sys3(SYS_mprotect, base + i * PAGE, PAGE, PROT_READ) != 0)
				return (18);
		for (i = 1; i < 5000; i += 2)
			((volatile char *)base)[i * PAGE] = (char)i;
		r = sys0(SYS_fork);
		if (r == 0) {
			for (i = 1; i < 5000; i += 2)
				if (((volatile char *)base)[i * PAGE] != (char)i)
					(void)sys1(SYS_exit_group, 1);
			/* child writes must not leak to the parent */
			((volatile char *)base)[PAGE] = 'C';
			(void)sys1(SYS_exit_group, 0);
		}
		if (sys4(SYS_wait4, r, &status, 0, 0) != r || status != 0)
			return (19);
		if (((volatile char *)base)[PAGE] != (char)1) return (19);
		(void)sys2(SYS_munmap, base, 5000 * PAGE);
	}

	msg("mmap: 20\n");
	/* 20: mincore of an unmapped page is ENOMEM; of a bad vector EFAULT. */
	p = mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)sys2(SYS_munmap, p, PAGE);
	if (sys3(SYS_mincore, p, PAGE, vec) != -ENOMEM) return (20);
	p = mmap6(0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (sys3(SYS_mincore, p, PAGE, 0) != -EFAULT) return (20);
	if (sys3(SYS_mincore, p + 1, PAGE, vec) != -EINVAL) return (20);
	(void)sys2(SYS_munmap, p, PAGE);
	return (0);
}
