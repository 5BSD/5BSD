/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tracee for linux_trace_test: exercises each new Linuxulator syscall a
 * known number of times so truss/kdump/DTrace output can be asserted.
 * Usage: linux_tracee [count]  (default 1).  Exit status 0 on success,
 * otherwise the failing step number.
 */
#include "linux_test.h"

#define	T_pidfd_open	434
#define	T_futex_waitv	449
#define	T_signalfd4	289
#define	T_splice	275
#define	T_pipe2		293
#define	T_mseal		462
#define	T_getpid	39
#define	T_open		2
#define	T_munmap	11
#define	T_mmap		9
#define	T_write		1
#define	T_close		3
#define	T_mprotect	10
#define	T_read		0

struct waitv { unsigned long val; unsigned long uaddr; unsigned flags, resv; };

static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	long n = 1, i, r, pfd, sfd, p, pipes[2], nullfd;
	int pipefds[2];
	unsigned word = 5;
	struct waitv w;
	unsigned long mask;

	if (argc >= 2) {
		n = 0;
		for (const char *s = argv[1]; *s >= '0' && *s <= '9'; s++)
			n = n * 10 + (*s - '0');
		if (n <= 0) n = 1;
	}
	(void)pipes;
	for (i = 0; i < n; i++) {
		/* 1: pidfd_open(self) */
		pfd = call(T_pidfd_open, call(T_getpid, 0,0,0,0,0,0), 0, 0,0,0,0);
		if (pfd < 0) return (1);
		call(T_close, pfd, 0,0,0,0,0);
		/* 2: futex_waitv: value mismatch -> EAGAIN, no sleep */
		w.val = 6; w.uaddr = (unsigned long)&word; w.flags = 0x82; w.resv = 0;
		r = call(T_futex_waitv, (long)&w, 1, 0, 0, 0, 0);
		if (r != -EAGAIN) return (2);
		/* 3: signalfd4 for SIGUSR1 */
		mask = 1UL << (10 - 1);
		sfd = call(T_signalfd4, -1, (long)&mask, 8, 0, 0, 0);
		if (sfd < 0) return (3);
		call(T_close, sfd, 0,0,0,0,0);
		/* 4: mseal a page, then a refused munmap (denied probe) */
		p = call(T_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p < 0) return (4);
		if (call(T_mseal, p, PAGE, 0, 0,0,0) != 0) return (4);
		if (call(T_munmap, p, PAGE, 0,0,0,0) != -EPERM) return (4);
		/* 5: splice pipe -> /dev/null */
		if (call(T_pipe2, (long)pipefds, 0, 0,0,0,0) != 0) return (5);
		if (call(T_write, pipefds[1], (long)"tracee", 6, 0,0,0) != 6) return (5);
		nullfd = call(T_open, (long)"/dev/null", 1 /* O_WRONLY */, 0, 0,0,0);
		if (nullfd < 0) return (5);
		r = call(T_splice, pipefds[0], 0, nullfd, 0, 6, 0);
		if (r != 6) return (5);
		call(T_close, nullfd, 0,0,0,0,0);
		call(T_close, pipefds[0], 0,0,0,0,0);
		call(T_close, pipefds[1], 0,0,0,0,0);
	}
	return (0);
}
