/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial process_vm_readv(2)/process_vm_writev(2): the cross-process
 * memory bridge.  Self round-trips, real cross-process read AND write to a
 * forked child (same-VA static buffers), scatter/gather with mismatched
 * local/remote iovec shapes, partial transfers (min of the two totals),
 * multi-page transfers, and the full validation surface (flags, iovcnt
 * bounds, zero counts, ESRCH, EFAULT on bad local and remote addresses).
 * readahead(2) is checked at the end.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_process_vm_readv	310
#define	SYS_process_vm_writev	311
#define	SYS_readahead		187
#define	SYS_setuid		105
#define	SYS_setgid		106
#define	NOBODY			65534
#define	UIO_MAXIOV		1024
#define	BIG			(256 * 1024)

/* Same virtual address in parent and child after fork (COW). */
static volatile unsigned char rbuf[BIG];
static volatile unsigned char lbuf[BIG];

static long
vm_readv(long pid, const struct iovec *lv, unsigned long lc,
    const struct iovec *rv, unsigned long rc, unsigned long flags)
{

	return (call(SYS_process_vm_readv, pid, (long)lv, lc, (long)rv, rc, flags));
}

static long
vm_writev(long pid, const struct iovec *lv, unsigned long lc,
    const struct iovec *rv, unsigned long rc, unsigned long flags)
{

	return (call(SYS_process_vm_writev, pid, (long)lv, lc, (long)rv, rc, flags));
}

static void
fillpat(volatile unsigned char *p, long n, unsigned char seed)
{
	long i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char)(seed + i * 7);
}

static int
checkpat(volatile unsigned char *p, long n, unsigned char seed)
{
	long i;

	for (i = 0; i < n; i++)
		if (p[i] != (unsigned char)(seed + i * 7))
			return (0);
	return (1);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	struct iovec liov[4], riov[4];
	long pid, r, i, pfd[2];
	int ipc[2], status;

	pid = sys0(SYS_getpid);

	/* 1: self read round-trip: copy rbuf -> lbuf via our own pid. */
	fillpat(rbuf, 4096, 0x11);
	xmemset((void *)lbuf, 0, 4096);
	liov[0].iov_base = (void *)lbuf; liov[0].iov_len = 4096;
	riov[0].iov_base = (void *)rbuf; riov[0].iov_len = 4096;
	r = vm_readv(pid, liov, 1, riov, 1, 0);
	if (r != 4096) { msgnum("self readv ", r); return (1); }
	if (!checkpat(lbuf, 4096, 0x11)) return (1);

	/* 2: self write round-trip: lbuf -> rbuf. */
	fillpat(lbuf, 4096, 0x22);
	xmemset((void *)rbuf, 0, 4096);
	r = vm_writev(pid, liov, 1, riov, 1, 0);
	if (r != 4096) { msgnum("self writev ", r); return (2); }
	if (!checkpat(rbuf, 4096, 0x22)) return (2);

	/* 3: validation - nonzero flags. */
	if (vm_readv(pid, liov, 1, riov, 1, 1) != -EINVAL) return (3);
	if (vm_writev(pid, liov, 1, riov, 1, 1) != -EINVAL) return (3);
	/* 4: iovcnt over UIO_MAXIOV. */
	if (vm_readv(pid, liov, UIO_MAXIOV + 1, riov, 1, 0) != -EINVAL) return (4);
	if (vm_readv(pid, liov, 1, riov, UIO_MAXIOV + 1, 0) != -EINVAL) return (4);
	/* 5: zero counts transfer nothing. */
	if (vm_readv(pid, liov, 0, riov, 1, 0) != 0) return (5);
	if (vm_readv(pid, liov, 1, riov, 0, 0) != 0) return (5);

	/* 6: ESRCH for a pid that does not exist. */
	r = vm_readv(0x3fffffff, liov, 1, riov, 1, 0);
	if (r != -ESRCH) { msgnum("nonexistent pid ", r); return (6); }

	/* 7: EFAULT on a bad LOCAL address (import of local iovecs faults). */
	liov[0].iov_base = (void *)0x10; liov[0].iov_len = 4096;
	riov[0].iov_base = (void *)rbuf; riov[0].iov_len = 4096;
	r = vm_readv(pid, liov, 1, riov, 1, 0);
	if (r != -EFAULT) { msgnum("bad local addr ", r); return (7); }
	/* 8: a bad REMOTE address yields EFAULT (or a short count of 0). */
	liov[0].iov_base = (void *)lbuf; liov[0].iov_len = 4096;
	riov[0].iov_base = (void *)0x10; riov[0].iov_len = 4096;
	r = vm_readv(pid, liov, 1, riov, 1, 0);
	if (r != -EFAULT && r != 0) { msgnum("bad remote addr ", r); return (8); }

	/* 9: scatter/gather - three local pieces gather one remote block. */
	fillpat(rbuf, 300, 0x33);
	xmemset((void *)lbuf, 0, 300);
	liov[0].iov_base = (void *)lbuf;        liov[0].iov_len = 100;
	liov[1].iov_base = (void *)(lbuf + 100); liov[1].iov_len = 100;
	liov[2].iov_base = (void *)(lbuf + 200); liov[2].iov_len = 100;
	riov[0].iov_base = (void *)rbuf;         riov[0].iov_len = 300;
	r = vm_readv(pid, liov, 3, riov, 1, 0);
	if (r != 300) { msgnum("gather ", r); return (9); }
	if (!checkpat(lbuf, 300, 0x33)) return (9);

	/* 10: partial - remote offers more than local can take; only the
	 * local total is transferred. */
	fillpat(rbuf, 4096, 0x44);
	xmemset((void *)lbuf, 0, 4096);
	liov[0].iov_base = (void *)lbuf; liov[0].iov_len = 1000;
	riov[0].iov_base = (void *)rbuf; riov[0].iov_len = 4096;
	r = vm_readv(pid, liov, 1, riov, 1, 0);
	if (r != 1000) { msgnum("partial ", r); return (10); }
	if (!checkpat(lbuf, 1000, 0x44) || lbuf[1000] != 0) return (10);

	/* 11: a large multi-page self transfer. */
	fillpat(rbuf, BIG, 0x55);
	xmemset((void *)lbuf, 0, BIG);
	liov[0].iov_base = (void *)lbuf; liov[0].iov_len = BIG;
	riov[0].iov_base = (void *)rbuf; riov[0].iov_len = BIG;
	r = vm_readv(pid, liov, 1, riov, 1, 0);
	if (r != BIG) { msgnum("large ", r); return (11); }
	if (!checkpat(lbuf, BIG, 0x55)) return (11);

	/*
	 * 12-14: real cross-process transfer.  The child fills rbuf (same VA
	 * as ours after fork), tells us via a pipe, waits; we read its rbuf,
	 * verify, then write a new pattern into its rbuf; it verifies and
	 * exits 0.
	 */
	if (sys2(SYS_pipe2, (long)ipc, 0) != 0) return (12);
	{ int p2[2]; if (sys2(SYS_pipe2, (long)p2, 0) != 0) return (12); pfd[0]=p2[0]; pfd[1]=p2[1]; }
	pid = sys0(SYS_fork);
	if (pid == 0) {
		unsigned char one = 1;

		fillpat(rbuf, 8192, 0x66);		/* known payload for parent */
		(void)sys3(SYS_write, ipc[1], (long)&one, 1);	/* "ready" */
		(void)sys3(SYS_read, pfd[0], (long)&one, 1);	/* wait for parent write */
		if (!checkpat(rbuf, 8192, 0x77))
			(void)sys1(SYS_exit_group, 1);		/* parent's write missing */
		(void)sys1(SYS_exit_group, 0);
	}
	{
		unsigned char one = 0;

		if (sys3(SYS_read, ipc[0], (long)&one, 1) != 1) return (12);
		/* read the child's rbuf out of its address space */
		xmemset((void *)lbuf, 0, 8192);
		liov[0].iov_base = (void *)lbuf; liov[0].iov_len = 8192;
		riov[0].iov_base = (void *)rbuf; riov[0].iov_len = 8192;
		r = vm_readv(pid, liov, 1, riov, 1, 0);
		if (r != 8192) { msgnum("child readv ", r); return (13); }
		if (!checkpat(lbuf, 8192, 0x66)) return (13);
		/* write a new pattern into the child's rbuf */
		fillpat(lbuf, 8192, 0x77);
		r = vm_writev(pid, liov, 1, riov, 1, 0);
		if (r != 8192) { msgnum("child writev ", r); return (14); }
		one = 1;
		(void)sys3(SYS_write, pfd[1], (long)&one, 1);	/* release child */
		if (sys4(SYS_wait4, pid, &status, 0, 0) != pid) return (14);
		if (status != 0) { msgnum("child status ", (status >> 8) & 0xff); return (14); }
	}

	/*
	 * 17-18: cross-UID isolation.  A child that drops to an unprivileged
	 * uid must NOT be able to read this (root-owned) process's memory -
	 * the ptrace-mode permission check must deny it with EPERM.  (Run as
	 * root the earlier same-uid checks always pass; this is the only test
	 * that actually exercises the security boundary.)
	 */
	{
		long mypid = sys0(SYS_getpid), cpid;

		fillpat(rbuf, 256, 0x5a);
		cpid = sys0(SYS_fork);
		if (cpid == 0) {
			struct iovec lv, rv;
			static char b[256];

			(void)sys1(SYS_setgid, NOBODY);
			if (sys1(SYS_setuid, NOBODY) != 0)
				(void)sys1(SYS_exit_group, 40);
			/* still root? refuse to give a false pass */
			if (sys0(SYS_getuid) != NOBODY)
				(void)sys1(SYS_exit_group, 41);
			lv.iov_base = b; lv.iov_len = sizeof(b);
			rv.iov_base = (void *)rbuf; rv.iov_len = sizeof(b);
			r = vm_readv(mypid, &lv, 1, &rv, 1, 0);
			if (r != -EPERM)
				(void)sys1(SYS_exit_group, 42);
			/* a write into root's memory is likewise denied */
			r = vm_writev(mypid, &lv, 1, &rv, 1, 0);
			(void)sys1(SYS_exit_group, r == -EPERM ? 0 : 43);
		}
		if (sys4(SYS_wait4, cpid, &status, 0, 0) != cpid) return (17);
		if (status != 0) { msgnum("cross-uid child ", (status >> 8) & 0xff); return (18); }
		/* the root parent's rbuf is untouched by the denied access */
		if (!checkpat(rbuf, 256, 0x5a)) return (18);
	}

	/* 15-16: readahead - a hint that must at least validate the fd. */
	{
		long fd = tmpfile_fd("procvm_ra");

		if (fd < 0) return (15);
		for (i = 0; i < 64; i++)
			(void)sys3(SYS_write, fd, (long)rbuf, 4096);
		r = sys3(SYS_readahead, fd, 0, 65536);
		if (r != 0) { msgnum("readahead ", r); return (15); }
		(void)sys1(SYS_close, fd);
		if (sys3(SYS_readahead, 9999, 0, 4096) != -EBADF) return (16);
	}
	return (0);
}
