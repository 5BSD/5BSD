/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Direct Linux preadv2(2)/pwritev2(2) RWF_* regression checks.
 * Exit status = failed check number.
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
	/* HIPRI is a direct-I/O hint; unsupported drop-behind must reject. */
	if (pwritev2(fd, &iov, 1, 0, 0) != 5) return (1);
	if (pwritev2(fd, &iov, 1, 5, RWF_HIPRI) != 5) return (2);
	if (pwritev2(fd, &iov, 1, 10, RWF_DONTCACHE) != -EOPNOTSUPP) return (3);
	if (pwritev2(fd, &iov, 1, 10, 0) != 5) return (3);
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
	/* Reads validate hints too. */
	if (preadv2(fd, &iov, 1, 0, RWF_HIPRI) != 30) return (7);
	if (preadv2(fd, &iov, 1, 0, RWF_DSYNC) != 30) return (7);
	/* 8: offset -1 uses and advances the file offset. */
	if (sys3(SYS_lseek, fd, 0, 0) != 0) return (8);
	iov.iov_len = 5;
	if (preadv2(fd, &iov, 1, -1, 0) != 5) return (8);
	if (sys3(SYS_lseek, fd, 0, 1) != 5) return (8);
	/* APPEND and NOSIGNAL are implemented; other policies below reject. */
	iov.iov_base = "x";
	iov.iov_len = 1;
	if (pwritev2(fd, &iov, 1, 0, RWF_NOWAIT) != -EOPNOTSUPP) return (9);
	if (pwritev2(fd, &iov, 1, 0, RWF_APPEND) != 1) return (10);
	if (sys3(SYS_lseek, fd, 0, 2) != 31) return (10);
	if (pwritev2(fd, &iov, 1, 0, RWF_ATOMIC) != -EOPNOTSUPP) return (11);
	/* NOSIGNAL is accepted for ordinary files and is a no-op on reads. */
	if (pwritev2(fd, &iov, 1, 0, RWF_NOSIGNAL) != 1) return (12);
	iov.iov_base = buf;
	if (preadv2(fd, &iov, 1, 0, RWF_NOSIGNAL) != 1) return (12);
	/* 13: unknown flag bits are EOPNOTSUPP. */
	if (pwritev2(fd, &iov, 1, 0, 0x200) != -EOPNOTSUPP) return (13);
	if (preadv2(fd, &iov, 1, 0, 0x1000) != -EOPNOTSUPP) return (13);
	/* 14: RWF_NOAPPEND on a non-append descriptor is a no-op success. */
	if (pwritev2(fd, &iov, 1, 0, RWF_NOAPPEND) != 1) return (14);
	/* NOAPPEND overrides O_APPEND for this write, preserving file flags. */
	afd = sys4(SYS_openat, AT_FDCWD, "rwf.tmp", O_WRONLY | O_APPEND, 0);
	if (afd < 0) return (15);
	if (pwritev2(afd, &iov, 1, 0, RWF_NOAPPEND) != 1) return (15);
	if (sys3(SYS_lseek, afd, 0, 2) != 31) return (15);
	if ((sys3(SYS_fcntl, afd, 3 /* F_GETFL */, 0) & O_APPEND) == 0) return (15);
	(void)sys1(SYS_close, afd);
	/* 16: offset below -1 is EINVAL. */
	if (sys6(SYS_pwritev2, fd, &iov, 1, -2, -1, 0) != -EINVAL) return (16);
	/* 17: flags are checked before the descriptor (EOPNOTSUPP, not EBADF). */
	if (pwritev2(9999, &iov, 1, 0, RWF_NOWAIT) != -EOPNOTSUPP) return (17);
	if (pwritev2(9999, &iov, 1, 0, 0) != -EBADF) return (17);
	/* 18: too many iovecs is EINVAL. */
	if (pwritev2(fd, &iov, 1025, 0, 0) != -EINVAL) return (18);
	/* 19: NOSIGNAL validates before fd lookup, then reaches EBADF. */
	if (pwritev2(9999, &iov, 1, 0, RWF_NOSIGNAL) != -EBADF) return (19);
	/* 20: DSYNC on a pipe: the write succeeds (nothing to sync). */
	{
		int pfd[2];

		if (sys2(SYS_pipe2, pfd, 0) != 0) return (20);
		iov.iov_base = "p";
		iov.iov_len = 1;
		if (pwritev2(pfd[1], &iov, 1, -1, RWF_DSYNC) != 1)
			return (20);
		(void)sys1(SYS_close, pfd[0]);
		(void)sys1(SYS_close, pfd[1]);
	}
	/* 21-22: a closed pipe/socket raises SIGPIPE unless NOSIGNAL is set. */
	for (int kind = 0; kind < 2; kind++) {
		for (int suppress = 0; suppress < 2; suppress++) {
			long pid;
			int status = 0;

			pid = fork_process();
			if (pid < 0) return (21 + kind);
			if (pid == 0) {
				int fds[2];
				long r;

				if (kind == 0)
					r = sys2(SYS_pipe2, fds, 0);
				else
					r = sys4(SYS_socketpair, 1, 1, 0, fds);
				if (r != 0) (void)sys1(SYS_exit_group, 40);
				(void)sys1(SYS_close, kind == 0 ? fds[0] : fds[1]);
				iov.iov_base = "z"; iov.iov_len = 1;
				r = pwritev2(fds[kind == 0 ? 1 : 0], &iov, 1, -1,
				    suppress ? RWF_NOSIGNAL : 0);
				(void)sys1(SYS_exit_group,
				    suppress && r == -EPIPE ? 0 : 41);
			}
			if (sys4(SYS_wait4, pid, &status, 0, 0) != pid)
				return (21 + kind);
			if (suppress) {
				if (status != 0) return (21 + kind);
			} else if ((status & 0x7f) != SIGPIPE)
				return (21 + kind);
		}
	}
	(void)sys1(SYS_close, fd);
	(void)sys3(SYS_unlinkat, AT_FDCWD, "rwf.tmp", 0);
	return (0);
}
