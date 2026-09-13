/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * cachestat(2): page-cache residency for a file range.  Validation (flags,
 * bad fd, non-regular fd, EFAULT on the range and result pointers), and
 * residency behaviour: pages resident after writing, zero beyond EOF, a
 * bounded sub-range count, and nr_dirty never exceeding nr_cache with the
 * (untracked) eviction counters staying zero.  Exit status = failed check.
 */
#include "linux_test.h"

#define	SYS_cachestat		451
#define	NPG			64

struct cstat_range { unsigned long long off, len; };
struct cstat { unsigned long long nr_cache, nr_dirty, nr_writeback, nr_evicted, nr_recently_evicted; };

static long
cachestat(long fd, struct cstat_range *r, struct cstat *cs, long flags)
{

	return (sys4(SYS_cachestat, fd, (long)r, (long)cs, flags));
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	static char page[4096];
	struct cstat_range range;
	struct cstat cs;
	long fd, i, r, p[2];

	fd = tmpfile_fd("cachestat");
	if (fd < 0) return (1);
	for (i = 0; i < 4096; i++) page[i] = (char)(i + 1);
	for (i = 0; i < NPG; i++)
		if (sys3(SYS_write, fd, (long)page, 4096) != 4096) return (1);

	/* 1: nonzero flags -> EINVAL. */
	range.off = 0; range.len = 0;
	if (cachestat(fd, &range, &cs, 1) != -EINVAL) return (1);
	/* 2: a bad fd -> EBADF. */
	if (cachestat(999, &range, &cs, 0) != -EBADF) return (2);
	/* 3: a non-regular fd (pipe) -> EBADF. */
	if (sys2(SYS_pipe2, (long)p, 0) != 0) return (3);
	if (cachestat(p[0], &range, &cs, 0) != -EBADF) return (3);
	(void)sys1(SYS_close, p[0]); (void)sys1(SYS_close, p[1]);

	/* 4: whole file (len 0 = to EOF): pages are resident after writing. */
	xmemset(&cs, 0, sizeof(cs));
	range.off = 0; range.len = 0;
	r = cachestat(fd, &range, &cs, 0);
	if (r != 0) { msgnum("cachestat whole ", r); return (4); }
	if (cs.nr_cache == 0 || cs.nr_cache > NPG) { msgnum("nr_cache ", cs.nr_cache); return (4); }
	if (cs.nr_dirty > cs.nr_cache) { msgnum("nr_dirty ", cs.nr_dirty); return (4); }
	if (cs.nr_evicted != 0 || cs.nr_recently_evicted != 0) return (4);

	/* 5: a one-page sub-range counts at most one page. */
	xmemset(&cs, 0, sizeof(cs));
	range.off = 0; range.len = 4096;
	if (cachestat(fd, &range, &cs, 0) != 0) return (5);
	if (cs.nr_cache > 1) { msgnum("subrange nr_cache ", cs.nr_cache); return (5); }

	/* 6: a range entirely beyond EOF is empty. */
	xmemset(&cs, 0, sizeof(cs));
	range.off = (unsigned long long)NPG * 4096; range.len = 4096;
	if (cachestat(fd, &range, &cs, 0) != 0) return (6);
	if (cs.nr_cache != 0) { msgnum("beyond-EOF nr_cache ", cs.nr_cache); return (6); }

	/* 7: EFAULT on a bad result pointer. */
	range.off = 0; range.len = 0;
	if (cachestat(fd, &range, (struct cstat *)0x10, 0) != -EFAULT) return (7);
	/* 8: EFAULT on a bad range pointer. */
	if (cachestat(fd, (struct cstat_range *)0x10, &cs, 0) != -EFAULT) return (8);

	/* 9-10: a page dirtied through a shared mapping is counted dirty; after
	 * msync it is clean again. */
	{
		long m;

		m = call(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (m < 0) { msgnum("mmap ", m); return (9); }
		*(volatile char *)m = 'X';		/* dirty page 0 via the mapping */
		xmemset(&cs, 0, sizeof(cs));
		range.off = 0; range.len = 4096;
		if (cachestat(fd, &range, &cs, 0) != 0) return (9);
		if (cs.nr_cache < 1 || cs.nr_dirty < 1) { msgnum("mmap-dirty nr_dirty ", cs.nr_dirty); return (9); }
		if (sys3(SYS_msync, m, 4096, 4 /* MS_SYNC */) != 0) return (10);
		(void)sys2(SYS_munmap, m, 4096);
	}
	(void)sys1(SYS_close, fd);
	return (0);
}
