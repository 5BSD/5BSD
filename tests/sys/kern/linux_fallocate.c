/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * fallocate(2) modes: plain preallocation, FALLOC_FL_PUNCH_HOLE|KEEP_SIZE
 * (hole punching that keeps the size), the modes with no VFS operation
 * here (EOPNOTSUPP) and Linux's argument/descriptor validation.  Exit
 * status = failed check number.
 */
#define	FALLOC_FL_KEEP_SIZE	0x01
#define	FALLOC_FL_PUNCH_HOLE	0x02
#define	FALLOC_FL_COLLAPSE_RANGE 0x08
#define	FALLOC_FL_ZERO_RANGE	0x10
#define	FALLOC_FL_INSERT_RANGE	0x20
#define	FALLOC_FL_UNSHARE_RANGE	0x40
#define	FALLOC_FL_WRITE_ZEROES	0x80

#define	FSZ	(1024 * 1024L)

static char buf[64 * 1024];

static long
fallocate(long fd, long mode, long off, long len)
{

	return (sys4(SYS_fallocate, fd, mode, off, len));
}

static int
test(int argc, char **argv, char **envp)
{
	struct stat st;
	long fd, rfd, i, before;
	int pfd[2];

	(void)argc; (void)argv; (void)envp;

	fd = tmpfile_fd("fallocate.tmp");
	if (fd < 0) return (1);
	/* 1-2: mode 0 preallocates and extends the size. */
	if (fallocate(fd, 0, 0, FSZ) != 0) return (1);
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != FSZ) return (2);
	/* 3: fill with a pattern so a hole is observable. */
	xmemset(buf, 'A', sizeof(buf));
	for (i = 0; i < FSZ; i += sizeof(buf))
		if (sys4(SYS_pwrite64, fd, buf, sizeof(buf), i) !=
		    (long)sizeof(buf)) return (3);
	if (sys1(SYS_fsync, fd) != 0) return (3);
	if (sys2(SYS_fstat, fd, &st) != 0) return (3);
	before = st.st_blocks;
	/* 4: PUNCH_HOLE without KEEP_SIZE is EOPNOTSUPP, nothing changes. */
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, 65536) != -EOPNOTSUPP)
		return (4);
	if (sys4(SYS_pread64, fd, buf, 16, 0) != 16 || buf[0] != 'A')
		return (4);
	/* 5: PUNCH_HOLE|KEEP_SIZE on the middle 512 KiB. */
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
	    FSZ / 4, FSZ / 2) != 0) return (5);
	/* 6: the size is unchanged... */
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != FSZ) return (6);
	/* 7: ...the hole reads as zeros... */
	if (sys4(SYS_pread64, fd, buf, sizeof(buf), FSZ / 4) !=
	    (long)sizeof(buf)) return (7);
	for (i = 0; i < (long)sizeof(buf); i++)
		if (buf[i] != 0) return (7);
	if (sys4(SYS_pread64, fd, buf, sizeof(buf), FSZ / 2) !=
	    (long)sizeof(buf)) return (7);
	for (i = 0; i < (long)sizeof(buf); i++)
		if (buf[i] != 0) return (7);
	/* 8: ...the data around it survives... */
	if (sys4(SYS_pread64, fd, buf, 16, FSZ / 4 - 16) != 16 || buf[0] != 'A')
		return (8);
	if (sys4(SYS_pread64, fd, buf, 16, 3 * FSZ / 4) != 16 || buf[0] != 'A')
		return (8);
	/*
	 * 9: ...and no blocks were added.  Whether they are freed is up to
	 * the file system (ZFS frees them, UFS zero-fills the range and
	 * keeps the allocation); Linux file systems differ the same way.
	 */
	if (sys1(SYS_fsync, fd) != 0) return (9);
	if (sys2(SYS_fstat, fd, &st) != 0) return (9);
	if (st.st_blocks > before) return (9);
	if (st.st_blocks == before)
		msg("note: hole punch kept the allocation (zero-fill fs)\n");
	/* 10: a hole entirely past EOF is a no-op success, size unchanged. */
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
	    2 * FSZ, FSZ) != 0) return (10);
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != FSZ) return (10);
	/* 11: a hole straddling EOF punches up to EOF, size unchanged. */
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
	    FSZ - 4096, 8192) != 0) return (11);
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != FSZ) return (11);
	if (sys4(SYS_pread64, fd, buf, 16, FSZ - 4096) != 16 || buf[0] != 0)
		return (11);
	/* 12: unaligned hole boundaries are accepted (partial blocks zeroed). */
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 100, 200)
	    != 0) return (12);
	if (sys4(SYS_pread64, fd, buf, 300, 50) != 300) return (12);
	if (buf[0] != 'A' || buf[49] != 'A' || buf[50] != 0 || buf[249] != 0 ||
	    buf[250] != 'A') return (12);
	/* 13: mode 0 past EOF extends again. */
	if (fallocate(fd, 0, FSZ, 4096) != 0) return (13);
	if (sys2(SYS_fstat, fd, &st) != 0 || st.st_size != FSZ + 4096)
		return (13);

	/* 14-19: modes without a VFS operation are EOPNOTSUPP. */
	if (fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 4096) != -EOPNOTSUPP)
		return (14);
	if (fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, 4096) != -EOPNOTSUPP)
		return (15);
	if (fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, 0, 4096) != -EOPNOTSUPP)
		return (16);
	if (fallocate(fd, FALLOC_FL_INSERT_RANGE, 0, 4096) != -EOPNOTSUPP)
		return (17);
	if (fallocate(fd, FALLOC_FL_UNSHARE_RANGE, 0, 4096) != -EOPNOTSUPP)
		return (18);
	if (fallocate(fd, FALLOC_FL_WRITE_ZEROES, 0, 4096) != -EOPNOTSUPP)
		return (19);
	/* 20: an unknown mode bit is EOPNOTSUPP too. */
	if (fallocate(fd, 0x100, 0, 4096) != -EOPNOTSUPP) return (20);
	/* 21-23: len <= 0 and a negative offset are EINVAL. */
	if (fallocate(fd, 0, 0, 0) != -EINVAL) return (21);
	if (fallocate(fd, 0, 0, -1) != -EINVAL) return (22);
	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, -1, 4096)
	    != -EINVAL) return (23);
	/* 24: a read-only descriptor is EBADF. */
	rfd = sys3(SYS_open, "fallocate.tmp", O_RDONLY, 0);
	if (rfd < 0) return (24);
	if (fallocate(rfd, 0, 0, 4096) != -EBADF) return (24);
	if (fallocate(rfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 4096)
	    != -EBADF) return (24);
	(void)sys1(SYS_close, rfd);
	/* 25: a closed descriptor is EBADF. */
	if (fallocate(rfd, 0, 0, 4096) != -EBADF) return (25);
	/* 26: a pipe is ESPIPE. */
	if (sys2(SYS_pipe2, pfd, 0) != 0) return (26);
	if (fallocate(pfd[1], 0, 0, 4096) != -ESPIPE) return (26);
	if (fallocate(pfd[1], FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0,
	    4096) != -ESPIPE) return (26);
	/* 27: a directory is EISDIR. */
	rfd = sys3(SYS_open, ".", O_RDONLY | O_DIRECTORY, 0);
	if (rfd < 0) return (27);
	if (fallocate(rfd, 0, 0, 4096) != -EISDIR) return (27);
	(void)sys1(SYS_close, rfd);
	/* 28: a socket is ENODEV. */
	rfd = sys3(SYS_socket, 1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0);
	if (rfd < 0) return (28);
	if (fallocate(rfd, 0, 0, 4096) != -ENODEV) return (28);
	(void)sys1(SYS_close, rfd);
	/* 29: an unknown mode bit is checked before the descriptor. */
	if (fallocate(9999, 0x100, 0, 4096) != -EOPNOTSUPP) return (29);
	/* 30: offset + len overflow is EFBIG on Linux (>= max file size). */
	if (fallocate(fd, 0, 0x7fffffffffffff00L, 0x1000) != -EFBIG &&
	    fallocate(fd, 0, 0x7fffffffffffff00L, 0x1000) != -EINVAL)
		return (30);

	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "fallocate.tmp");
	return (0);
}

