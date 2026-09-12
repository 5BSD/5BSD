/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * open(2)/openat(2) flag handling: every O_* flag is accepted where Linux
 * accepts it, O_DSYNC and O_SYNC are distinct and read back through
 * F_GETFL, F_SETFL only changes the flags Linux lets it change, and the
 * error cases.  Exit status = failed check number.
 */
#define	F_GETFD		1
#define	F_SETFD		2
#define	F_GETFL		3
#define	F_SETFL		4
#define	FD_CLOEXEC	1

static int
test(int argc, char **argv, char **envp)
{
	long fd, fd2, fl, i;
	int pfd[2];
	char buf[16];
	long flags[] = { O_APPEND, O_NONBLOCK, O_DSYNC, O_SYNC, O_ASYNC,
	    O_DIRECT, O_LARGEFILE, O_NOFOLLOW, O_NOATIME, O_CLOEXEC,
	    O_NOCTTY, O_TRUNC, O_EXCL | O_CREAT, 1L << 30 };

	(void)argc; (void)argv; (void)envp;

	(void)sys1(SYS_unlink, "openflags.tmp");
	(void)sys1(SYS_unlink, "openflags.lnk");
	fd = sys3(SYS_open, "openflags.tmp", O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0) return (1);
	if (sys3(SYS_write, fd, "hello", 5) != 5) return (1);
	(void)sys1(SYS_close, fd);

	/* 2-15: each flag opens (O_EXCL|O_CREAT on an existing file: EEXIST). */
	for (i = 0; i < 14; i++) {
		fd = sys3(SYS_open, "openflags.tmp", O_RDWR | flags[i], 0600);
		if (flags[i] == (O_EXCL | O_CREAT)) {
			if (fd != -EEXIST) return (2 + i);
			continue;
		}
		if (fd < 0) return (2 + i);
		(void)sys1(SYS_close, fd);
	}
	/* 16: O_TRUNC above emptied it; refill for the checks below. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDWR | O_TRUNC, 0);
	if (fd < 0) return (16);
	if (sys3(SYS_write, fd, "hello", 5) != 5) return (16);
	(void)sys1(SYS_close, fd);

	/* 17: O_DSYNC reads back as O_DSYNC only. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDWR | O_DSYNC, 0);
	if (fd < 0) return (17);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & O_SYNC) != O_DSYNC) return (17);
	(void)sys1(SYS_close, fd);
	/* 18: O_SYNC reads back as both bits. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDWR | O_SYNC, 0);
	if (fd < 0) return (18);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & O_SYNC) != O_SYNC) return (18);
	/* 19: F_SETFL cannot clear O_SYNC (Linux ignores it). */
	if (sys3(SYS_fcntl, fd, F_SETFL, 0) != 0) return (19);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & O_SYNC) != O_SYNC) return (19);
	(void)sys1(SYS_close, fd);
	/* 20: F_SETFL cannot add O_SYNC/O_DSYNC either. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDWR, 0);
	if (fd < 0) return (20);
	if (sys3(SYS_fcntl, fd, F_SETFL, O_SYNC) != 0) return (20);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & O_SYNC) != 0) return (20);
	/* 21: but O_APPEND|O_NONBLOCK round-trip. */
	if (sys3(SYS_fcntl, fd, F_SETFL, O_APPEND | O_NONBLOCK) != 0)
		return (21);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & (O_APPEND | O_NONBLOCK)) != (O_APPEND | O_NONBLOCK))
		return (21);
	/* 22: O_APPEND from F_SETFL really appends. */
	if (sys3(SYS_write, fd, "!", 1) != 1) return (22);
	if (sys4(SYS_pread64, fd, buf, 6, 0) != 6 || buf[5] != '!') return (22);
	/* 23: F_SETFL 0 clears them. */
	if (sys3(SYS_fcntl, fd, F_SETFL, 0) != 0) return (23);
	fl = sys3(SYS_fcntl, fd, F_GETFL, 0);
	if ((fl & (O_APPEND | O_NONBLOCK)) != 0) return (23);
	/* 24: the access mode is reported. */
	if ((fl & 3) != O_RDWR) return (24);
	(void)sys1(SYS_close, fd);

	/* 25: O_CLOEXEC sets FD_CLOEXEC; without it the flag is clear. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0 || sys3(SYS_fcntl, fd, F_GETFD, 0) != FD_CLOEXEC) return (25);
	(void)sys1(SYS_close, fd);
	fd = sys3(SYS_open, "openflags.tmp", O_RDONLY, 0);
	if (fd < 0 || sys3(SYS_fcntl, fd, F_GETFD, 0) != 0) return (25);
	(void)sys1(SYS_close, fd);

	/* 26: O_NOFOLLOW on a symlink is ELOOP. */
	if (sys2(SYS_symlink, "openflags.tmp", "openflags.lnk") != 0)
		return (26);
	if (sys3(SYS_open, "openflags.lnk", O_RDONLY | O_NOFOLLOW, 0) != -ELOOP)
		return (26);
	/* 27: O_PATH|O_NOFOLLOW opens the link itself; read on it is EBADF. */
	fd = sys3(SYS_open, "openflags.lnk", O_PATH | O_NOFOLLOW, 0);
	if (fd < 0) return (27);
	if (sys3(SYS_read, fd, buf, 1) != -EBADF) return (27);
	(void)sys1(SYS_close, fd);
	/* 28: O_PATH on a regular file: read EBADF, fstat works. */
	fd = sys3(SYS_open, "openflags.tmp", O_PATH, 0);
	if (fd < 0) return (28);
	if (sys3(SYS_read, fd, buf, 1) != -EBADF) return (28);
	{
		struct stat st;

		if (sys2(SYS_fstat, fd, &st) != 0 ||
		    (st.st_mode & S_IFMT) != S_IFREG) return (28);
	}
	(void)sys1(SYS_close, fd);
	/* 29: O_DIRECTORY on a file is ENOTDIR; on a directory it works. */
	if (sys3(SYS_open, "openflags.tmp", O_RDONLY | O_DIRECTORY, 0) !=
	    -ENOTDIR) return (29);
	fd = sys3(SYS_open, ".", O_RDONLY | O_DIRECTORY, 0);
	if (fd < 0) return (29);
	(void)sys1(SYS_close, fd);
	/* 30: O_TMPFILE is not implemented: EOPNOTSUPP (never a stray file). */
	if (sys3(SYS_open, ".", O_TMPFILE | O_RDWR, 0600) != -EOPNOTSUPP)
		return (30);
	/*
	 * 31: access mode 3 (O_WRONLY|O_RDWR) is Linux's "ioctl only" open:
	 * it succeeds and write() is EBADF (read is too on Linux; here the
	 * descriptor is read-only, the closest native mode).
	 */
	fd = sys3(SYS_open, "openflags.tmp", 3, 0);
	if (fd < 0) return (31);
	if (sys3(SYS_write, fd, "x", 1) != -EBADF) return (31);
	(void)sys1(SYS_close, fd);
	/* 32: O_CREAT on a read-only open still creates and reads. */
	(void)sys1(SYS_unlink, "openflags.new");
	fd = sys3(SYS_open, "openflags.new", O_RDONLY | O_CREAT, 0600);
	if (fd < 0) return (32);
	if (sys3(SYS_write, fd, "x", 1) != -EBADF) return (32);
	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "openflags.new");
	/* 33: O_NONBLOCK on a FIFO read end returns immediately. */
	(void)sys1(SYS_unlink, "openflags.fifo");
	if (sys3(SYS_open, "openflags.fifo", O_RDONLY, 0) != -ENOENT)
		return (33);
	if (sys2(SYS_pipe2, pfd, O_NONBLOCK) != 0) return (33);
	if (sys3(SYS_read, pfd[0], buf, 1) != -EAGAIN) return (33);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	/* 34: openat with a bad dirfd and a relative name is EBADF. */
	if (sys4(SYS_openat, 9999, "openflags.tmp", O_RDONLY, 0) != -EBADF)
		return (34);
	/* 35: ...and irrelevant for an absolute name. */
	fd2 = sys4(SYS_openat, 9999, "/", O_RDONLY | O_DIRECTORY, 0);
	if (fd2 < 0) return (35);
	(void)sys1(SYS_close, fd2);
	/* 36: a NULL path is EFAULT. */
	if (sys3(SYS_open, 0, O_RDONLY, 0) != -EFAULT) return (36);
	/* 37: an empty path is ENOENT. */
	if (sys3(SYS_open, "", O_RDONLY, 0) != -ENOENT) return (37);
	/* 38: O_EXCL without O_CREAT is ignored on a regular file. */
	fd = sys3(SYS_open, "openflags.tmp", O_RDONLY | O_EXCL, 0);
	if (fd < 0) return (38);
	(void)sys1(SYS_close, fd);

	(void)sys1(SYS_unlink, "openflags.lnk");
	(void)sys1(SYS_unlink, "openflags.tmp");
	return (0);
}

