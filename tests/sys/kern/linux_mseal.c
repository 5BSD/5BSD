/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * mseal(2): a sealed mapping cannot be unmapped, remapped, re-protected,
 * replaced by MAP_FIXED, or destructively advised (EPERM, contents intact),
 * while non-destructive use and unsealed neighbours keep working; seals
 * are inherited across fork and dropped by exec; validation (flags,
 * alignment, unmapped ranges, length 0), overlapping/merged seals, and a
 * 3000-seal stress.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_mseal	462
#define	MADV_WILLNEED	3
#define	MADV_DONTNEED	4
#define	MADV_FREE	8
#define	MADV_COLD	20
#define	MREMAP_MAYMOVE	1

static long
mseal(unsigned long addr, unsigned long len, unsigned long flags)
{

	return (sys3(SYS_mseal, addr, len, flags));
}

static long
anon(unsigned long npages)
{

	return (call(SYS_mmap, 0, npages * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
}

static int
test(int argc, char **argv, char **envp)
{
	volatile char *c;
	long p, q, r, i;
	int status;

	if (argc >= 2 && argv[1][0] == 'c') {
		/* exec'd child: argv[2] is a sealed-in-parent address as hex */
		unsigned long a = 0;
		const char *s = argv[2];

		while (*s != '\0') {
			a = a * 16 + (*s >= 'a' ? *s - 'a' + 10 : *s - '0');
			s++;
		}
		/* after exec nothing is sealed: a fresh mapping there unmaps */
		r = call(SYS_mmap, a, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
		    MAP_FIXED, -1, 0);
		if (r != (long)a) return (90);
		if (sys2(SYS_munmap, a, PAGE) != 0) return (91);
		return (0);
	}

	/* 1-4: validation. */
	p = anon(8);
	if (p < 0) return (1);
	if (mseal(p, PAGE, 1) != -EINVAL) return (1);
	if (mseal(p + 1, PAGE, 0) != -EINVAL) return (2);
	if (mseal(p, 0, 0) != 0) return (3);			/* len 0: no-op */
	q = anon(4);
	(void)sys2(SYS_munmap, q, 4 * PAGE);
	if (mseal(q, 4 * PAGE, 0) != -ENOMEM) return (4);	/* unmapped */
	if (mseal(p + 6 * PAGE, 4 * PAGE, 0) != -ENOMEM &&
	    mseal(p + 6 * PAGE, 4 * PAGE, 0) != 0) return (4);
	if (mseal(p, ~0UL - PAGE, 0) != -EINVAL) return (4);	/* wrap */

	/* 5: seal pages 2..5 of the 8-page mapping; write to them first. */
	c = (volatile char *)p;
	for (i = 0; i < 8; i++) c[i * PAGE] = 'a' + i;
	if (mseal(p + 2 * PAGE, 4 * PAGE, 0) != 0) return (5);
	/* 6-9: munmap / mprotect / mremap / MAP_FIXED over it: EPERM, intact. */
	if (sys2(SYS_munmap, p + 3 * PAGE, PAGE) != -EPERM) return (6);
	if (sys2(SYS_munmap, p, 8 * PAGE) != -EPERM) return (6);		/* overlap */
	if (sys3(SYS_mprotect, p + 2 * PAGE, PAGE, PROT_READ) != -EPERM) return (7);
	if (sys3(SYS_mprotect, p, 8 * PAGE, PROT_READ) != -EPERM) return (7);
	if (sys5(SYS_mremap, p + 2 * PAGE, 4 * PAGE, 8 * PAGE, MREMAP_MAYMOVE, 0) !=
	    -EPERM) return (8);
	if (call(SYS_mmap, p + 4 * PAGE, PAGE, PROT_READ, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_FIXED, -1, 0) != -EPERM) return (9);
	for (i = 0; i < 8; i++) if (c[i * PAGE] != 'a' + i) return (9);
	c[3 * PAGE] = 'Z';	/* still writable */
	/* 10-11: destructive advice EPERM, hints fine. */
	if (sys3(SYS_madvise, p + 2 * PAGE, PAGE, MADV_DONTNEED) != -EPERM) return (10);
	if (sys3(SYS_madvise, p + 2 * PAGE, PAGE, MADV_FREE) != -EPERM) return (10);
	if (c[2 * PAGE] != 'c') return (10);
	if (sys3(SYS_madvise, p + 2 * PAGE, PAGE, MADV_WILLNEED) != 0) return (11);
	if (sys3(SYS_madvise, p + 2 * PAGE, PAGE, MADV_COLD) != 0) return (11);
	/* 12-13: unsealed neighbours are unaffected. */
	if (sys3(SYS_mprotect, p, 2 * PAGE, PROT_READ) != 0) return (12);
	if (sys2(SYS_munmap, p + 6 * PAGE, 2 * PAGE) != 0) return (12);
	if (sys3(SYS_madvise, p, PAGE, MADV_DONTNEED) != 0) return (13);
	if (c[0] != 0) return (13);	/* discarded */
	/* 14: sealing twice / overlapping merges silently. */
	if (mseal(p + 2 * PAGE, 4 * PAGE, 0) != 0) return (14);
	if (mseal(p + 3 * PAGE, PAGE, 0) != 0) return (14);
	if (sys2(SYS_munmap, p + 5 * PAGE, PAGE) != -EPERM) return (14);

	/* 15-16: fork inherits the seals. */
	r = sys0(SYS_fork);
	if (r == 0) {
		if (sys2(SYS_munmap, p + 3 * PAGE, PAGE) != -EPERM)
			(void)sys1(SYS_exit_group, 1);
		if (sys3(SYS_mprotect, p + 2 * PAGE, PAGE, PROT_READ) != -EPERM)
			(void)sys1(SYS_exit_group, 2);
		if (c[4 * PAGE] != 'e') (void)sys1(SYS_exit_group, 3);
		(void)sys1(SYS_exit_group, 0);
	}
	if (sys4(SYS_wait4, r, &status, 0, 0) != r) return (15);
	if (status != 0) { msgnum("child status ", status >> 8); return (16); }
	/* 17: exec drops them (the child maps and unmaps the same address). */
	{
		char hex[20], *args_[4];
		unsigned long a = p + 3 * PAGE;
		int n = 0, k;

		for (k = 15; k >= 0; k--) {
			int d = (a >> (k * 4)) & 0xf;
			if (n == 0 && d == 0 && k != 0) continue;
			hex[n++] = d < 10 ? '0' + d : 'a' + d - 10;
		}
		hex[n] = '\0';
		args_[0] = argv[0]; args_[1] = "child"; args_[2] = hex; args_[3] = 0;
		r = sys0(SYS_fork);
		if (r == 0) {
			(void)sys3(SYS_execve, argv[0], args_, envp);
			(void)sys1(SYS_exit_group, 99);
		}
		if (sys4(SYS_wait4, r, &status, 0, 0) != r) return (17);
		if (status != 0) { msgnum("exec child status ", status >> 8); return (17); }
	}

	/* 18-20: 3000 separate seals, then their enforcement and merging. */
	q = anon(6000);
	if (q < 0) return (18);
	for (i = 0; i < 3000; i++)
		if (mseal(q + 2 * i * PAGE, PAGE, 0) != 0) { msgnum("seal # ", i); return (18); }
	for (i = 0; i < 3000; i += 97)
		if (sys2(SYS_munmap, q + 2 * i * PAGE, PAGE) != -EPERM) return (19);
	/* the gaps between seals are still unsealed */
	if (sys2(SYS_munmap, q + PAGE, PAGE) != 0) return (19);
	/* one seal across everything merges the lot */
	if (mseal(q, 6000 * PAGE, 0) != -ENOMEM) return (20);	/* gap we unmapped */
	if (mseal(q + 2 * PAGE, 5998 * PAGE, 0) != 0) return (20);
	if (sys2(SYS_munmap, q + 3 * PAGE, PAGE) != -EPERM) return (20);
	/* 21: the process can still exit with everything sealed (no leak/hang). */
	return (0);
}
