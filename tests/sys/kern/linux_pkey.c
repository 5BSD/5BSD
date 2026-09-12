/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for pkey_alloc(2), pkey_free(2) and
 * pkey_mprotect(2): no Linux libc or sysroot required.  Exit status
 * identifies the failed check.
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

static u32
rdpkru(void)
{
	u32 val;

	__asm__ volatile("rdpkru" : "=a"(val) : "c"(0) : "edx");
	return (val);
}

static void
wrpkru(u32 val)
{

	__asm__ volatile("wrpkru" : : "a"(val), "c"(0), "d"(0) : "memory");
}

static void
msg(const char *s)
{
	long n = 0;

	while (s[n] != '\0')
		n++;
	(void)call(1, 2, (long)s, n, 0, 0, 0);
}

/* Linux amd64 rt signal frame; only the fields we need to reach. */
struct l_sigcontext {
	u64	gregs[18];
	unsigned short cs, gs, fs, pad;
	u64	err, trapno, oldmask, cr2;
	u64	fpstate;	/* pointer to the XSAVE area */
	u64	reserved[8];
};
struct l_ucontext {
	u64	uc_flags;
	u64	uc_link;
	u64	ss_sp;
	int	ss_flags;
	int	ss_pad;
	u64	ss_size;
	struct l_sigcontext uc_mcontext;
	u64	uc_sigmask;
};
struct l_sigaction {
	void	(*handler)(int, void *, void *);
	u64	flags;
	void	(*restorer)(void);
	u64	mask;
};

#define	SA_SIGINFO	0x4
#define	SA_RESTORER	0x04000000
#define	PROT_READ	0x1
#define	PROT_WRITE	0x2
#define	MAP_PRIVATE	0x2
#define	MAP_ANONYMOUS	0x20
#define	PKEY_DISABLE_ACCESS	0x1
#define	PKEY_DISABLE_WRITE	0x2
#define	EINVAL	22
#define	ENOSPC	28
#define	EINTR	4

static volatile int faults;
static u32 pkru_offset;

/* rt_sigreturn(15) trampoline. */
__attribute__((naked)) static void
restorer(void)
{

	__asm__ volatile("mov $15, %eax\n\tsyscall");
}

/*
 * SIGSEGV handler: the faulting instruction is retried after sigreturn
 * with the PKRU value saved in the frame, so lift the restriction by
 * zeroing PKRU inside the frame's XSAVE area (as a Linux program must).
 */
__attribute__((force_align_arg_pointer)) static void
handler(int sig, void *si, void *ucp)
{
	struct l_ucontext *uc = ucp;
	u64 *xstate_bv;
	u32 *pkru;

	(void)sig;
	(void)si;
	faults++;
	xstate_bv = (u64 *)(uc->uc_mcontext.fpstate + 512);
	pkru = (u32 *)(uc->uc_mcontext.fpstate + pkru_offset);
	if ((*xstate_bv & (1UL << 9)) != 0)
		*pkru = 0;
}

static int
test(void)
{
	struct l_sigaction sa;
	volatile char *page;
	u32 a, b, c, d, val;
	long k, k2, r, pid, i, got;
	int status;

	cpuid(7, 0, &a, &b, &c, &d);
	if ((c & (1 << 3)) == 0 || (c & (1 << 4)) == 0) {
		/* 1: without PKU/OSPKE Linux fails pkey_alloc with ENOSPC. */
		if (call(330, 0, 0, 0, 0, 0, 0) != -ENOSPC) return (1);
		/* 2: and pkey_free/pkey_mprotect(pkey) with EINVAL. */
		if (call(331, 0, 0, 0, 0, 0, 0) != -EINVAL) return (2);
		msg("pku not available\n");
		return (0);
	}
	cpuid(0xd, 9, &a, &b, &c, &d);
	pkru_offset = b;

	/* 3: no flags are defined. */
	if (call(330, 1, 0, 0, 0, 0, 0) != -EINVAL) return (3);
	/* 4: access rights outside DISABLE_ACCESS|DISABLE_WRITE. */
	if (call(330, 0, 4, 0, 0, 0, 0) != -EINVAL) return (4);
	/* 5: first key allocated is 1..15 (key 0 is the default). */
	k = call(330, 0, 0, 0, 0, 0, 0);
	if (k < 1 || k > 15) return (5);
	/* 6: allocation cleared the key's PKRU bits on this thread. */
	if ((rdpkru() & (3U << (2 * k))) != 0) return (6);
	/* 7: init_val DISABLE_ACCESS sets AD for the new key on this thread. */
	k2 = call(330, 0, PKEY_DISABLE_ACCESS, 0, 0, 0, 0);
	if (k2 < 1 || k2 > 15 || k2 == k) return (7);
	val = rdpkru();
	if ((val & (3U << (2 * k2))) != (1U << (2 * k2))) return (8);
	/* 9: init_val DISABLE_WRITE sets WD only. */
	if (call(331, k2, 0, 0, 0, 0, 0) != 0) return (9);
	k2 = call(330, 0, PKEY_DISABLE_WRITE, 0, 0, 0, 0);
	if (k2 < 1 || k2 > 15) return (10);
	if ((rdpkru() & (3U << (2 * k2))) != (2U << (2 * k2))) return (11);
	if (call(331, k2, 0, 0, 0, 0, 0) != 0) return (12);

	page = (char *)call(9, 0, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((long)page < 0) return (13);
	page[0] = 'A';

	/* 14: unaligned start is EINVAL even with pkey -1. */
	if (call(329, (long)page + 1, 4095, PROT_READ, -1, 0, 0) != -EINVAL)
		return (14);
	/* 15: len 0 is a no-op success, even with an unallocated key. */
	if (call(329, (long)page, 0, PROT_READ, 14, 0, 0) != 0) return (15);
	/* 16: an unallocated key is EINVAL. */
	if (call(329, (long)page, 4096, PROT_READ | PROT_WRITE,
	    k == 14 ? 13 : 14, 0, 0) != -EINVAL) return (16);
	/* 17: keys outside 0..15 are EINVAL. */
	if (call(329, (long)page, 4096, PROT_READ, 16, 0, 0) != -EINVAL)
		return (17);
	if (call(329, (long)page, 4096, PROT_READ, -2, 0, 0) != -EINVAL)
		return (18);
	/* 19: assign the allocated key to the page. */
	if (call(329, (long)page, 4096, PROT_READ | PROT_WRITE, k, 0, 0) != 0)
		return (19);

	sa.handler = handler;
	sa.flags = SA_SIGINFO | SA_RESTORER;
	sa.restorer = restorer;
	sa.mask = 0;
	if (call(13, 11, (long)&sa, 0, 8, 0, 0) != 0) return (20);

	/* 21: disabling access for the key makes a read fault. */
	wrpkru(3U << (2 * k));
	got = page[0];
	wrpkru(0);
	if (faults != 1 || got != 'A') return (21);
	/* 22: write-disable faults a write but not a read. */
	faults = 0;
	wrpkru(2U << (2 * k));
	got = page[0];
	if (faults != 0 || got != 'A') return (22);
	page[0] = 'B';
	wrpkru(0);
	if (faults != 1 || page[0] != 'B') return (23);
	/* 24: with PKRU 0 no fault. */
	faults = 0;
	got = page[0];
	if (faults != 0) return (24);
	/* 25: key assignment is not disturbed by a plain mprotect. */
	if (call(329, (long)page, 4096, PROT_READ, -1, 0, 0) != 0) return (25);
	wrpkru(3U << (2 * k));
	got = page[0];
	wrpkru(0);
	if (faults != 1 || got != 'B') return (26);
	/* 27: key assignment survives fork (Linux copies VMAs and PKRU). */
	faults = 0;
	pid = call(57, 0, 0, 0, 0, 0, 0);
	if (pid < 0) return (27);
	if (pid == 0) {
		wrpkru(3U << (2 * k));
		got = page[0];
		wrpkru(0);
		call(60, faults == 1 && got == 'B' ? 0 : 1, 0, 0, 0, 0, 0);
	}
	if (call(61, pid, (long)&status, 0, 0, 0, 0) != pid) return (28);
	if (status != 0) return (29);
	/* 30: parent unaffected by the child. */
	if (faults != 0) return (30);
	/* 31: assigning key 0 (always allocated) removes the restriction. */
	if (call(329, (long)page, 4096, PROT_READ, 0, 0, 0) != 0) return (31);
	wrpkru(3U << (2 * k));
	got = page[0];
	wrpkru(0);
	if (faults != 0 || got != 'B') return (32);
	if (call(329, (long)page, 4096, PROT_READ, k, 0, 0) != 0) return (33);
	/* 34: freeing the key does not detach it from the page (pitfall). */
	if (call(331, k, 0, 0, 0, 0, 0) != 0) return (34);
	if (call(331, k, 0, 0, 0, 0, 0) != -EINVAL) return (35);
	wrpkru(3U << (2 * k));
	got = page[0];
	wrpkru(0);
	if (faults != 1 || got != 'B') return (36);
	/* 37: a freed key can no longer be used with pkey_mprotect. */
	if (call(329, (long)page, 4096, PROT_READ, k, 0, 0) != -EINVAL)
		return (37);
	/* 38: exactly 15 keys (1..15) can be allocated, then ENOSPC. */
	for (i = 0; i < 15; i++) {
		r = call(330, 0, 0, 0, 0, 0, 0);
		if (r < 1 || r > 15) return (38);
	}
	if (call(330, 0, 0, 0, 0, 0, 0) != -ENOSPC) return (39);
	/* 40: a new mapping at the same address starts with key 0. */
	if (call(11, (long)page, 4096, 0, 0, 0, 0) != 0) return (40);
	if ((long)call(9, (long)page, 4096, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | 0x10, -1, 0) != (long)page)
		return (41);
	faults = 0;
	wrpkru(3U << (2 * k));
	got = page[0];
	wrpkru(0);
	if (faults != 0 || got != 0) return (42);
	/* 43: pkey_mprotect rejects bad prot like mprotect. */
	if (call(329, (long)page, 4096, 0x100, 1, 0, 0) != -EINVAL) return (43);
	/* 44: free everything, including key 0 (allowed on Linux). */
	for (i = 0; i < 16; i++)
		if (call(331, i, 0, 0, 0, 0, 0) != 0) return (44);
	/* 45: with key 0 freed the allocator hands it out first (Linux quirk). */
	if (call(330, 0, 0, 0, 0, 0, 0) != 0) return (45);
	return (0);
}

/* ELF entry has no return address; realign before calling C functions. */
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
