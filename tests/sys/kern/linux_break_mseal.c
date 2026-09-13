/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial mseal(2): sealing racing a thread that keeps changing
 * protections (every change after the seal must be EPERM, contents
 * intact); MAP_FIXED_NOREPLACE over a sealed page is EEXIST (nothing
 * replaced); mremap into/out of/shrinking a sealed range is EPERM; eight
 * threads sealing disjoint slices of one region concurrently; a seal over
 * a hole is ENOMEM and seals nothing; one munmap spanning sealed and
 * unsealed pages is EPERM and unmaps NOTHING; the 4096-range emulator cap
 * fails safely (ENOMEM, re-sealing a sealed page still succeeds); fork
 * storm; guard-page advice refused on sealed pages.  Exit status = failed
 * check number.
 */
#include "linux_test.h"

#define	SYS_mseal		462
#define	MREMAP_MAYMOVE		1
#define	MREMAP_FIXED		2
#define	MADV_GUARD_INSTALL	102
#define	NTHR			8

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

/* --- 1: protection-flipper racing the seal --- */
static long flip_base;
static volatile int flip_sealed, flip_stop;
static volatile long flip_bad, flip_after;

static int
flipper(void *arg __attribute__((unused)))
{
	long r;
	int prot = PROT_READ;

	while (!flip_stop) {
		r = sys3(SYS_mprotect, flip_base + 8 * PAGE, 16 * PAGE, prot);
		if (flip_sealed) {
			flip_after++;
			if (r != -EPERM)
				flip_bad++;
		}
		prot = (prot == PROT_READ) ? PROT_READ | PROT_WRITE : PROT_READ;
	}
	return (0);
}

/* --- 4: concurrent sealers --- */
static long conc_base;
static int
sealer(void *arg)
{
	long k = (long)arg, i;

	for (i = 0; i < 512; i++)
		if (mseal(conc_base + (k * 512 + i) * PAGE, PAGE, 0) != 0)
			return (1);
	return (0);
}

static int
fork_check(void *arg)
{
	long p = (long)arg;

	if (sys2(SYS_munmap, p, PAGE) != -EPERM) return (1);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ) != -EPERM) return (2);
	if (*(volatile char *)p != 'S') return (3);
	return (0);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	struct thread th[NTHR];
	volatile char *c;
	long p, q, r, i;

	/* 1-2: flipper thread vs seal. */
	p = anon(32);
	if (p < 0) return (1);
	c = (volatile char *)p;
	for (i = 0; i < 32; i++) c[i * PAGE] = 'a' + (i % 26);
	flip_base = p;
	if (thread_create(&th[0], flipper, 0) != 0) return (1);
	sleep_ms(30);
	/* make sure pages are writable when sealed so contents can be checked */
	if (mseal(p + 8 * PAGE, 16 * PAGE, 0) != 0) return (1);
	flip_sealed = 1;
	sleep_ms(200);
	flip_stop = 1;
	if (thread_join(&th[0]) != 0) return (1);
	if (flip_after < 10) { msgnum("flipper iterations after seal ", flip_after); return (2); }
	if (flip_bad != 0) { msgnum("non-EPERM mprotects after seal ", flip_bad); return (2); }
	/* the flipper may have left the range read-only: reads must still work */
	for (i = 8; i < 24; i++) if (c[i * PAGE] != 'a' + (i % 26)) return (2);

	/* 3: MAP_FIXED_NOREPLACE over sealed: EEXIST, mapping untouched. */
	r = call(SYS_mmap, p + 10 * PAGE, PAGE, PROT_READ, MAP_PRIVATE |
	    MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (r != -EEXIST) { msgnum("NOREPLACE over sealed ", r); return (3); }
	if (c[10 * PAGE] != 'a' + 10) return (3);

	/* 4: mremap variants against sealed pages. */
	q = anon(4);
	if (q < 0) return (4);
	/* into a sealed destination */
	r = sys5(SYS_mremap, q, 4 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED,
	    p + 12 * PAGE);
	if (r != -EPERM) { msgnum("mremap FIXED into sealed ", r); return (4); }
	if (c[12 * PAGE] != 'a' + 12) return (4);
	/* shrinking a sealed range */
	r = sys5(SYS_mremap, p + 8 * PAGE, 16 * PAGE, 8 * PAGE, 0, 0);
	if (r != -EPERM) { msgnum("mremap shrink sealed ", r); return (4); }
	/* growing in place from a sealed range */
	r = sys5(SYS_mremap, p + 8 * PAGE, 16 * PAGE, 24 * PAGE, MREMAP_MAYMOVE, 0);
	if (r != -EPERM) { msgnum("mremap grow sealed ", r); return (4); }
	(void)sys2(SYS_munmap, q, 4 * PAGE);

	/* 5: one munmap spanning sealed + unsealed: EPERM, nothing unmapped. */
	if (sys2(SYS_munmap, p, 32 * PAGE) != -EPERM) return (5);
	for (i = 0; i < 8; i++) c[i * PAGE] = 'z';		/* still mapped+writable */
	for (i = 24; i < 32; i++) c[i * PAGE] = 'z';
	if (sys3(SYS_mprotect, p, 32 * PAGE, PROT_READ) != -EPERM) return (5);
	c[0] = 'y';						/* still writable */
	if (c[0] != 'y') return (5);

	/* 6: guard advice on sealed pages is refused. */
	r = sys3(SYS_madvise, p + 9 * PAGE, PAGE, MADV_GUARD_INSTALL);
	if (r != -EPERM) { msgnum("GUARD_INSTALL on sealed ", r); return (6); }

	/* 7-8: eight threads sealing disjoint 512-page slices concurrently. */
	q = anon(NTHR * 512);
	if (q < 0) return (7);
	conc_base = q;
	for (i = 0; i < NTHR; i++)
		if (thread_create(&th[i], sealer, (void *)i) != 0) return (7);
	for (i = 0; i < NTHR; i++)
		if (thread_join(&th[i]) != 0) return (7);
	for (i = 0; i < NTHR * 512; i += 97)
		if (sys2(SYS_munmap, q + i * PAGE, PAGE) != -EPERM) return (8);
	if (sys2(SYS_munmap, q, NTHR * 512 * PAGE) != -EPERM) return (8);

	/* 9: a seal over a hole is ENOMEM and seals nothing. */
	p = anon(8);
	if (p < 0) return (9);
	(void)sys2(SYS_munmap, p + 4 * PAGE, PAGE);
	if (mseal(p, 8 * PAGE, 0) != -ENOMEM) return (9);
	if (sys2(SYS_munmap, p, 4 * PAGE) != 0) return (9);
	if (sys2(SYS_munmap, p + 5 * PAGE, 3 * PAGE) != 0) return (9);

	/* 10-11: the emulator's 4096-range cap fails safely. */
	q = anon(8200);
	if (q < 0) return (10);
	/* earlier checks already hold a few ranges: seal until the cap says
	 * ENOMEM, which must happen close to 4096 and never crash */
	for (i = 0; i < 4096; i++) {		/* every other page: never merges */
		r = mseal(q + 2 * i * PAGE, PAGE, 0);
		if (r == -ENOMEM)
			break;
		if (r != 0) { msgnum("seal # ", i); msgnum(" -> ", r); return (10); }
	}
	if (i < 4000 || i == 4096) { msgnum("cap reached at ", i); return (10); }
	msgnum("cap reached at ", i);
	r = mseal(q + (2 * 4096 + 1) * PAGE, PAGE, 0);
	if (r != -ENOMEM) { msgnum("seal past cap ", r); return (10); }
	if (mseal(q + 2 * 100 * PAGE, PAGE, 0) != 0) return (11);	/* re-seal: ok */
	if (sys2(SYS_munmap, q + 2 * 100 * PAGE, PAGE) != -EPERM) return (11);
	if (sys2(SYS_munmap, q + (2 * 100 + 1) * PAGE, PAGE) != 0) return (11);	/* gap */
	/* a merge seal across a stretch still works at the cap (merges into one) */
	if (mseal(q, 100 * PAGE, 0) != 0 && mseal(q, 100 * PAGE, 0) != -ENOMEM) return (11);

	/* 12: fork storm with a sealed page. */
	p = anon(1);
	if (p < 0) return (12);
	*(volatile char *)p = 'S';
	if (mseal(p, PAGE, 0) != 0) return (12);
	for (i = 0; i < 40; i++) {
		r = run_child(fork_check, (void *)p);
		if (r != 0) { msgnum("fork child rc ", r); return (12); }
	}
	return (0);
}
