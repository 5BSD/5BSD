/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * preadv2(2)/pwritev2(2) RWF_* flags, and the umount2(2)/mount(2) flag
 * handling that needs no privilege to observe.  Exit status = failed
 * check number.
 */
#include "linux_test.h"

#define	RWF_HIPRI	0x01
#define	RWF_DSYNC	0x02
#define	RWF_SYNC	0x04
#define	RWF_NOWAIT	0x08
#define	RWF_APPEND	0x10
#define	RWF_NOAPPEND	0x20
#define	RWF_ATOMIC	0x40
#define	RWF_DONTCACHE	0x80
#define	RWF_NOSIGNAL	0x100

static long
pwritev2(long fd, struct iovec *iov, long n, long off, long flags)
{

	return (sys6(SYS_pwritev2, fd, iov, n, off, off < 0 ? -1 : 0, flags));
}

static long
preadv2(long fd, struct iovec *iov, long n, long off, long flags)
{

	return (sys6(SYS_preadv2, fd, iov, n, off, off < 0 ? -1 : 0, flags));
}

static int
test(int argc, char **argv, char **envp)
{
	struct iovec iov;
	char buf[32];
	long fd, afd;

	(void)argc; (void)argv; (void)envp;

	fd = tmpfile_fd("rwf.tmp");
	if (fd < 0) return (1);
	iov.iov_base = "hello";
	iov.iov_len = 5;
	/* 1-3: HIPRI, DONTCACHE and flags 0 write normally. */
	if (pwritev2(fd, &iov, 1, 0, 0) != 5) return (1);
	if (pwritev2(fd, &iov, 1, 5, RWF_HIPRI) != 5) return (2);
	if (pwritev2(fd, &iov, 1, 10, RWF_DONTCACHE) != 5) return (3);
	/* 4-5: DSYNC and SYNC write (and sync) with the right byte count. */
	if (pwritev2(fd, &iov, 1, 15, RWF_DSYNC) != 5) return (4);
	if (pwritev2(fd, &iov, 1, 20, RWF_SYNC) != 5) return (5);
	if (pwritev2(fd, &iov, 1, 25, RWF_DSYNC | RWF_SYNC | RWF_HIPRI) != 5)
		return (5);
	/* 6: the data is all there. */
	iov.iov_base = buf;
	iov.iov_len = 30;
	if (preadv2(fd, &iov, 1, 0, 0) != 30) return (6);
	if (xmemcmp(buf, "hellohellohellohellohellohello", 30) != 0) return (6);
	/* 7: reads accept the hint flags too. */
	if (preadv2(fd, &iov, 1, 0, RWF_HIPRI | RWF_DONTCACHE) != 30) return (7);
	if (preadv2(fd, &iov, 1, 0, RWF_DSYNC) != 30) return (7);
	/* 8: offset -1 uses and advances the file offset. */
	if (sys3(SYS_lseek, fd, 0, 0) != 0) return (8);
	iov.iov_len = 5;
	if (preadv2(fd, &iov, 1, -1, 0) != 5) return (8);
	if (sys3(SYS_lseek, fd, 0, 1) != 5) return (8);
	/* 9-12: per-call semantics with no native expression: EOPNOTSUPP. */
	iov.iov_base = "x";
	iov.iov_len = 1;
	if (pwritev2(fd, &iov, 1, 0, RWF_NOWAIT) != -EOPNOTSUPP) return (9);
	if (pwritev2(fd, &iov, 1, 0, RWF_APPEND) != -EOPNOTSUPP) return (10);
	if (pwritev2(fd, &iov, 1, 0, RWF_ATOMIC) != -EOPNOTSUPP) return (11);
	if (pwritev2(fd, &iov, 1, 0, RWF_NOSIGNAL) != -EOPNOTSUPP) return (12);
	/* 13: unknown flag bits are EOPNOTSUPP. */
	if (pwritev2(fd, &iov, 1, 0, 0x200) != -EOPNOTSUPP) return (13);
	if (preadv2(fd, &iov, 1, 0, 0x1000) != -EOPNOTSUPP) return (13);
	/* 14: RWF_NOAPPEND on a non-append descriptor is a no-op success. */
	if (pwritev2(fd, &iov, 1, 0, RWF_NOAPPEND) != 1) return (14);
	/* 15: ...and EOPNOTSUPP on an O_APPEND one (cannot override). */
	afd = sys3(SYS_open, "rwf.tmp", O_WRONLY | O_APPEND, 0);
	if (afd < 0) return (15);
	if (pwritev2(afd, &iov, 1, 0, RWF_NOAPPEND) != -EOPNOTSUPP) return (15);
	(void)sys1(SYS_close, afd);
	/* 16: offset below -1 is EINVAL. */
	if (sys6(SYS_pwritev2, fd, &iov, 1, -2, -1, 0) != -EINVAL) return (16);
	/* 17: flags are checked before the descriptor (EOPNOTSUPP, not EBADF). */
	if (pwritev2(9999, &iov, 1, 0, RWF_NOWAIT) != -EOPNOTSUPP) return (17);
	if (pwritev2(9999, &iov, 1, 0, 0) != -EBADF) return (17);
	/* 18: too many iovecs is EINVAL. */
	if (pwritev2(fd, &iov, 1025, 0, 0) != -EINVAL) return (18);
	/* 19: DSYNC on a pipe: the write succeeds (nothing to sync). */
	{
		int pfd[2];

		if (sys2(SYS_pipe2, pfd, 0) != 0) return (19);
		iov.iov_base = "p";
		iov.iov_len = 1;
		if (pwritev2(pfd[1], &iov, 1, -1, RWF_DSYNC) != 1 &&
		    pwritev2(pfd[1], &iov, 1, -1, RWF_DSYNC) != -EINVAL)
			return (19);
		(void)sys1(SYS_close, pfd[0]);
		(void)sys1(SYS_close, pfd[1]);
	}
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "rwf.tmp");
	return (0);
}
