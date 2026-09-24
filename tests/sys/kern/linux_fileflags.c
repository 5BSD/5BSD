/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for file-syscall option coverage:
 * renameat2(2) flags, fcntl(2) commands (OFD locks, seals, pipe size,
 * F_SETOWN_EX/F_GETOWN_EX, F_GETSIG/F_SETSIG), faccessat2(2), fchownat(2)
 * AT_EMPTY_PATH, copy_file_range(2) flags and inotify flags.  Exit status
 * identifies the failed check; each check's comment names the Linux
 * behaviour it asserts.  Where the emulator deliberately rejects an option
 * it cannot honour exactly, the comment says so.
 */
struct flock { short l_type, l_whence; long l_start, l_len; int l_pid; };
struct f_owner_ex { int type; int pid; };

#define	O_RDONLY	0
#define	O_WRONLY	1
#define	O_RDWR		2
#define	O_CREAT		0100
#define	O_EXCL		0200
#define	O_TRUNC		01000
#define	O_DIRECTORY	0200000
#define	O_CLOEXEC	02000000

#define	AT_FDCWD		-100
#define	AT_SYMLINK_NOFOLLOW	0x100
#define	AT_EACCESS		0x200
#define	AT_EMPTY_PATH		0x1000

#define	RENAME_NOREPLACE	1
#define	RENAME_EXCHANGE		2
#define	RENAME_WHITEOUT		4

#define	F_DUPFD		0
#define	F_GETFD		1
#define	F_SETLK		6
#define	F_SETOWN	8
#define	F_GETOWN	9
#define	F_SETSIG	10
#define	F_GETSIG	11
#define	F_SETOWN_EX	15
#define	F_GETOWN_EX	16
#define	F_OFD_GETLK	36
#define	F_OFD_SETLK	37
#define	F_OFD_SETLKW	38
#define	F_DUPFD_CLOEXEC	1030
#define	F_SETPIPE_SZ	1031
#define	F_GETPIPE_SZ	1032
#define	F_ADD_SEALS	1033
#define	F_GET_SEALS	1034

#define	F_OWNER_TID	0
#define	F_OWNER_PID	1
#define	F_OWNER_PGRP	2

#define	F_RDLCK		0
#define	F_WRLCK		1
#define	F_UNLCK		2

#define	F_SEAL_SEAL	0x01
#define	F_SEAL_SHRINK	0x02
#define	F_SEAL_GROW	0x04
#define	F_SEAL_WRITE	0x08
#define	F_SEAL_FUTURE_WRITE 0x10
#define	F_SEAL_EXEC	0x20

#define	MFD_CLOEXEC		1
#define	MFD_ALLOW_SEALING	2

#define	IN_MODIFY	0x02
#define	IN_CREATE	0x100
#define	IN_ONLYDIR	0x01000000
#define	IN_MASK_CREATE	0x10000000
#define	IN_MASK_ADD	0x20000000
#define	IN_ISDIR	0x40000000
#define	IN_NONBLOCK	0x800
#define	IN_CLOEXEC	0x80000

#define	AF_UNIX		1
#define	SOCK_STREAM	1

#define	FD_CLOEXEC	1
#define	SIGIO		29
#define	SIGURG		23
#define	F_OK		0
#define	R_OK		4

#define	EPERM	1
#define	ENOENT	2
#define	ESRCH	3
#define	EBADF	9
#define	EAGAIN	11
#define	EFAULT	14
#define	EEXIST	17
#define	ENOTDIR	20
#define	EINVAL	22
#define	ENOSYS	38

#define	SYS_read	0
#define	SYS_write	1
#define	SYS_close	3
#define	SYS_lseek	8
#define	SYS_socket	41
#define	SYS_exit	60
#define	SYS_getpid	39
#define	SYS_fcntl	72
#define	SYS_ftruncate	77
#define	SYS_mkdir	83
#define	SYS_rmdir	84
#define	SYS_unlink	87
#define	SYS_getuid	102
#define	SYS_getgid	104
#define	SYS_getpgid	121
#define	SYS_inotify_add_watch	254
#define	SYS_openat	257
#define	SYS_fchownat	260
#define	SYS_newfstatat	262
#define	SYS_pipe2	293
#define	SYS_inotify_init1	294
#define	SYS_renameat2	316
#define	SYS_memfd_create	319
#define	SYS_copy_file_range	326
#define	SYS_faccessat2	439

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

static long
fcntl(long fd, long cmd, long arg)
{
	return (call(SYS_fcntl, fd, cmd, arg, 0, 0, 0));
}

static long
renameat2(const char *from, const char *to, long flags)
{
	return (call(SYS_renameat2, AT_FDCWD, (long)from, AT_FDCWD, (long)to,
	    flags, 0));
}

static long
create(const char *path)
{
	return (call(SYS_openat, AT_FDCWD, (long)path,
	    O_RDWR | O_CREAT | O_TRUNC, 0644, 0, 0));
}

static long
exists(const char *path)
{
	return (call(SYS_faccessat2, AT_FDCWD, (long)path, F_OK, 0, 0, 0));
}

static int
test(void)
{
	struct flock fl;
	struct f_owner_ex oex;
	char a[] = "ff_a", b[] = "ff_b", c[] = "ff_c", dir[] = "ff_dir";
	char empty[] = "", name[] = "sealed";
	static char fill[4096];
	char buf[4];
	long fd, fd2, ifd, mfd, sfd, r, sz, pid, pgid;
	int pipes[2];

	(void)call(SYS_unlink, (long)a, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)b, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)c, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)dir, 0, 0, 0, 0, 0);

	/* renameat2 */
	fd = create(a);
	if (fd < 0) return (1);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	fd = create(b);
	if (fd < 0) return (1);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 2: RENAME_NOREPLACE onto an existing target is EEXIST. */
	if (renameat2(a, b, RENAME_NOREPLACE) != -EEXIST) return (2);
	/* 3: ...and neither name was touched by the failed attempt. */
	if (exists(a) != 0 || exists(b) != 0) return (3);
	/* 4-6: RENAME_NOREPLACE with no target renames. */
	if (renameat2(a, c, RENAME_NOREPLACE) != 0) return (4);
	if (exists(a) != -ENOENT) return (5);
	if (exists(c) != 0) return (6);
	/* 7: flags == 0 behaves like rename(2) (replaces). */
	if (renameat2(c, b, 0) != 0) return (7);
	if (exists(c) != -ENOENT || exists(b) != 0) return (7);
	/*
	 * 8-9: RENAME_EXCHANGE needs an atomic swap the native VOP_RENAME
	 * cannot do; it is deliberately rejected with the EINVAL Linux
	 * returns on a filesystem without it.
	 */
	fd = create(a);
	if (fd < 0) return (8);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	if (renameat2(a, b, RENAME_EXCHANGE) != -EINVAL) return (9);
	/* 10: RENAME_WHITEOUT (overlayfs) is EINVAL for the same reason. */
	if (renameat2(a, b, RENAME_WHITEOUT) != -EINVAL) return (10);
	/* 11: RENAME_NOREPLACE|RENAME_EXCHANGE is EINVAL (exclusive). */
	if (renameat2(a, b, RENAME_NOREPLACE | RENAME_EXCHANGE) != -EINVAL)
		return (11);
	/* 12: RENAME_EXCHANGE|RENAME_WHITEOUT is EINVAL (exclusive). */
	if (renameat2(a, b, RENAME_EXCHANGE | RENAME_WHITEOUT) != -EINVAL)
		return (12);
	/* 13: unknown flag bits are EINVAL. */
	if (renameat2(a, b, 8) != -EINVAL) return (13);
	/* 14: both names still exist after the rejected calls. */
	if (exists(a) != 0 || exists(b) != 0) return (14);
	/* 15: RENAME_NOREPLACE with a nonexistent source is ENOENT. */
	if (renameat2("ff_nope", c, RENAME_NOREPLACE) != -ENOENT) return (15);

	/* fcntl: OFD locks */
	fd = call(SYS_openat, AT_FDCWD, (long)a, O_RDWR, 0, 0, 0);
	if (fd < 0) return (16);
	fl.l_type = F_WRLCK;
	fl.l_whence = 0;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = 0;
	/* Same-description requests do not conflict. */
	if (fcntl(fd, F_OFD_SETLK, (long)&fl) != 0) return (17);
	if (fcntl(fd, F_OFD_SETLKW, (long)&fl) != 0) return (18);
	if (fcntl(fd, F_OFD_GETLK, (long)&fl) != 0 || fl.l_type != 2)
		return (19);
	/* Unlock OFD before taking a conflicting process-owned lock. */
	if (fcntl(fd, F_OFD_SETLK, (long)&fl) != 0) return (20);
	fl.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLK, (long)&fl) != 0) return (20);
	/* 21: F_SETLK on a bad descriptor is EBADF. */
	if (fcntl(9999, F_SETLK, (long)&fl) != -EBADF) return (21);

	/* fcntl: seals on memfd */
	mfd = call(SYS_memfd_create, (long)name, MFD_CLOEXEC | MFD_ALLOW_SEALING,
	    0, 0, 0, 0);
	if (mfd < 0) return (22);
	if (call(SYS_write, mfd, (long)"abcd", 4, 0, 0, 0) != 4) return (23);
	/* 24: no seals initially. */
	if (fcntl(mfd, F_GET_SEALS, 0) != 0) return (24);
	/* 25: FUTURE_WRITE is enforced by the shared-memory implementation. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) != 0) return (25);
	/* 26: F_SEAL_EXEC (Linux 6.3) likewise. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_EXEC) != -EINVAL) return (26);
	/* 27: an unknown seal bit is EINVAL, even alongside a valid one. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_GROW | 0x100) != -EINVAL) return (27);
	/* 28: ...and those rejected calls added nothing else. */
	if (fcntl(mfd, F_GET_SEALS, 0) != F_SEAL_FUTURE_WRITE) return (28);
	/* 29-30: F_SEAL_WRITE is added and reported back. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_WRITE) != 0) return (29);
	if (fcntl(mfd, F_GET_SEALS, 0) != (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) return (30);
	/* 31: the seal is real: writing now fails with EPERM. */
	if (call(SYS_write, mfd, (long)"e", 1, 0, 0, 0) != -EPERM) return (31);
	/* 32-33: F_SEAL_SHRINK makes ftruncate smaller fail with EPERM. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_SHRINK) != 0) return (32);
	if (call(SYS_ftruncate, mfd, 1, 0, 0, 0, 0) != -EPERM) return (33);
	/* 34: adding an already present seal is a no-op success. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_SHRINK) != 0) return (34);
	/* 35-37: F_SEAL_SEAL then blocks further seals with EPERM. */
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_SEAL) != 0) return (35);
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_GROW) != -EPERM) return (36);
	if (fcntl(mfd, F_GET_SEALS, 0) !=
	    (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK | F_SEAL_SEAL))
		return (37);
	(void)call(SYS_close, mfd, 0, 0, 0, 0, 0);
	/* 38-39: F_ADD_SEALS on a non-sealable memfd is EPERM. */
	mfd = call(SYS_memfd_create, (long)name, MFD_CLOEXEC, 0, 0, 0, 0);
	if (mfd < 0) return (38);
	if (fcntl(mfd, F_ADD_SEALS, F_SEAL_WRITE) != -EPERM) return (39);
	/* 40: ...and it reports F_SEAL_SEAL as the reason. */
	if (fcntl(mfd, F_GET_SEALS, 0) != F_SEAL_SEAL) return (40);
	(void)call(SYS_close, mfd, 0, 0, 0, 0, 0);
	/* 41-42: F_ADD_SEALS / F_GET_SEALS on a plain file are EINVAL. */
	if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) != -EINVAL) return (41);
	if (fcntl(fd, F_GET_SEALS, 0) != -EINVAL) return (42);

	/* fcntl: pipe size */
	if (call(SYS_pipe2, (long)pipes, 0, 0, 0, 0, 0) != 0) return (43);
	/* 44: F_GETPIPE_SZ reports a page-multiple power-of-two capacity... */
	sz = fcntl(pipes[0], F_GETPIPE_SZ, 0);
	if (sz < 4096 || (sz & (sz - 1)) != 0) return (44);
	/* 45: ...and the same value for the write end. */
	if (fcntl(pipes[1], F_GETPIPE_SZ, 0) != sz) return (45);
	/*
	 * 46: a PIPE_BUF-sized write fits.  (Do not assert that a full
	 * capacity write returns without a reader: native pipes hand
	 * writes >= PIPE_MINDIRECT to the reader directly and block.)
	 */
	if (call(SYS_write, pipes[1], (long)fill, 4096, 0, 0, 0) != 4096)
		return (46);
	if (call(SYS_read, pipes[0], (long)fill, 4096, 0, 0, 0) != 4096)
		return (46);
	/* 47: F_SETPIPE_SZ to the current size succeeds and returns it. */
	if (fcntl(pipes[1], F_SETPIPE_SZ, sz) != sz) return (47);
	/*
	 * 48: Linux rounds the request up to a power of two: a request just
	 * above half the current size rounds to the current size and
	 * succeeds, returning the rounded value.
	 */
	if (fcntl(pipes[0], F_SETPIPE_SZ, sz / 2 + 1) != sz) return (48);
	/*
	 * 49: the native buffer is sized by the kernel, so a request that
	 * rounds to a different size is deliberately rejected: EINVAL
	 * (Linux would resize).
	 */
	if (fcntl(pipes[1], F_SETPIPE_SZ, sz * 8) != -EINVAL) return (49);
	/*
	 * 50: 0 is a one-page request on Linux (rounded up to PAGE_SIZE):
	 * it succeeds only if the pipe already is one page.
	 */
	r = fcntl(pipes[1], F_SETPIPE_SZ, 0);
	if (r != (sz == 4096 ? 4096 : -EINVAL)) return (50);
	/* 51: a size above 2^31 cannot be rounded: EINVAL on Linux too. */
	if (fcntl(pipes[1], F_SETPIPE_SZ, 0x80000001L) != -EINVAL) return (51);
	/* 52-53: F_GETPIPE_SZ / F_SETPIPE_SZ on a non-pipe are EBADF. */
	if (fcntl(fd, F_GETPIPE_SZ, 0) != -EBADF) return (52);
	if (fcntl(fd, F_SETPIPE_SZ, sz) != -EBADF) return (53);
	/* 54: ...and on a closed descriptor too. */
	if (fcntl(9999, F_GETPIPE_SZ, 0) != -EBADF) return (54);

	/*
	 * fcntl: F_SETOWN_EX / F_GETOWN_EX.  A socket is used because the
	 * native kernel only keeps SIGIO owners for sockets, ttys and
	 * similar (F_GETOWN on a regular file is ENOTTY here, whereas
	 * Linux keeps an owner on any file).
	 */
	sfd = call(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
	if (sfd < 0) return (55);
	pid = call(SYS_getpid, 0, 0, 0, 0, 0, 0);
	pgid = call(SYS_getpgid, 0, 0, 0, 0, 0, 0);
	if (pid <= 0 || pgid <= 0) return (55);
	/* 56-57: F_GETOWN_EX on an unowned descriptor is type PID, pid 0. */
	oex.type = -1;
	oex.pid = -1;
	if (fcntl(sfd, F_GETOWN_EX, (long)&oex) != 0) return (56);
	if (oex.type != F_OWNER_PID || oex.pid != 0) return (57);
	/* 58: F_SETOWN_EX with F_OWNER_PID sets the owner... */
	oex.type = F_OWNER_PID;
	oex.pid = pid;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != 0) return (58);
	/* 59-60: ...visible through both F_GETOWN and F_GETOWN_EX. */
	if (fcntl(sfd, F_GETOWN, 0) != pid) return (59);
	oex.type = -1;
	oex.pid = -1;
	if (fcntl(sfd, F_GETOWN_EX, (long)&oex) != 0) return (60);
	if (oex.type != F_OWNER_PID || oex.pid != pid) return (60);
	/* 61-63: F_OWNER_PGRP sets the process group owner. */
	oex.type = F_OWNER_PGRP;
	oex.pid = pgid;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != 0) return (61);
	if (fcntl(sfd, F_GETOWN, 0) != -pgid) return (62);
	oex.type = -1;
	oex.pid = -1;
	if (fcntl(sfd, F_GETOWN_EX, (long)&oex) != 0) return (63);
	if (oex.type != F_OWNER_PGRP || oex.pid != pgid) return (63);
	/* 64-65: F_OWNER_PID with pid 0 clears the owner. */
	oex.type = F_OWNER_PID;
	oex.pid = 0;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != 0) return (64);
	if (fcntl(sfd, F_GETOWN, 0) != 0) return (65);
	/*
	 * 66: F_OWNER_TID (a single thread as owner) cannot be honoured:
	 * SIGIO ownership is per process here, so it is deliberately EINVAL
	 * rather than silently widened to the whole process.
	 */
	oex.type = F_OWNER_TID;
	oex.pid = pid;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != -EINVAL) return (66);
	/* 67: an unknown owner type is EINVAL. */
	oex.type = 7;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != -EINVAL) return (67);
	/* 68: a nonexistent pid is ESRCH. */
	oex.type = F_OWNER_PID;
	oex.pid = 0x7ffffff0;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != -ESRCH) return (68);
	/* 69: a negative pid finds no process either: ESRCH. */
	oex.pid = -5;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != -ESRCH) return (69);
	/* 70: a nonexistent process group is ESRCH. */
	oex.type = F_OWNER_PGRP;
	oex.pid = 0x7ffffff0;
	if (fcntl(sfd, F_SETOWN_EX, (long)&oex) != -ESRCH) return (70);
	/* 71: ...and the owner is still clear after the failed calls. */
	if (fcntl(sfd, F_GETOWN, 0) != 0) return (71);
	/* 72: Linux64 one-way pipes retain a per-open SIGIO owner. */
	oex.type = F_OWNER_PID;
	oex.pid = pid;
	if (fcntl(pipes[0], F_SETOWN_EX, (long)&oex) != 0) return (72);
	oex.type = -1;
	oex.pid = -1;
	if (fcntl(pipes[0], F_GETOWN_EX, (long)&oex) != 0 ||
	    oex.type != F_OWNER_PID || oex.pid != pid)
		return (72);
	/* 73-74: F_GETOWN_EX / F_SETOWN_EX with a bad pointer are EFAULT. */
	if (fcntl(sfd, F_GETOWN_EX, 0) != -EFAULT) return (73);
	if (fcntl(sfd, F_SETOWN_EX, 0) != -EFAULT) return (74);
	/* 75: F_GETOWN_EX on a bad descriptor is EBADF. */
	if (fcntl(9999, F_GETOWN_EX, (long)&oex) != -EBADF) return (75);

	/* fcntl: F_GETSIG / F_SETSIG */
	/* 76: F_GETSIG is 0, meaning the default SIGIO. */
	if (fcntl(sfd, F_GETSIG, 0) != 0) return (76);
	/* 77-78: F_SETSIG 0 and SIGIO are accepted (the only exact values). */
	if (fcntl(sfd, F_SETSIG, 0) != 0) return (77);
	if (fcntl(sfd, F_SETSIG, SIGIO) != 0) return (78);
	/*
	 * 79: any other valid signal cannot be honoured (SIGIO would be
	 * delivered instead): deliberately EINVAL, and F_GETSIG still 0.
	 */
	if (fcntl(sfd, F_SETSIG, SIGURG) != -EINVAL) return (79);
	if (fcntl(sfd, F_GETSIG, 0) != 0) return (80);
	/* 81: an invalid signal number is EINVAL on Linux too. */
	if (fcntl(sfd, F_SETSIG, 100) != -EINVAL) return (81);
	/* 82: F_GETSIG works on any descriptor, e.g. a regular file. */
	if (fcntl(fd, F_GETSIG, 0) != 0) return (82);
	/* 83-84: F_DUPFD_CLOEXEC dups with FD_CLOEXEC set. */
	fd2 = fcntl(fd, F_DUPFD_CLOEXEC, 10);
	if (fd2 < 10) return (83);
	if (fcntl(fd2, F_GETFD, 0) != FD_CLOEXEC) return (84);
	(void)call(SYS_close, fd2, 0, 0, 0, 0, 0);
	/* 85-86: F_GETSIG / F_SETSIG on a bad descriptor are EBADF. */
	if (fcntl(9999, F_GETSIG, 0) != -EBADF) return (85);
	if (fcntl(9999, F_SETSIG, 0) != -EBADF) return (86);
	(void)call(SYS_close, sfd, 0, 0, 0, 0, 0);

	/* faccessat2 */
	/* 87-88: AT_EACCESS and AT_SYMLINK_NOFOLLOW are accepted. */
	if (call(SYS_faccessat2, AT_FDCWD, (long)a, R_OK, AT_EACCESS, 0, 0)
	    != 0)
		return (87);
	if (call(SYS_faccessat2, AT_FDCWD, (long)a, R_OK, AT_SYMLINK_NOFOLLOW,
	    0, 0) != 0)
		return (88);
	/* 89: AT_EMPTY_PATH with "" checks the descriptor. */
	if (call(SYS_faccessat2, fd, (long)empty, R_OK, AT_EMPTY_PATH, 0, 0)
	    != 0)
		return (89);
	/* 90: "" without AT_EMPTY_PATH is ENOENT. */
	if (call(SYS_faccessat2, fd, (long)empty, R_OK, 0, 0, 0) != -ENOENT)
		return (90);
	/* 91: unknown flags are EINVAL. */
	if (call(SYS_faccessat2, AT_FDCWD, (long)a, R_OK, 0x400, 0, 0)
	    != -EINVAL)
		return (91);
	/* 92: an invalid mode is EINVAL. */
	if (call(SYS_faccessat2, AT_FDCWD, (long)a, 0x10, 0, 0, 0) != -EINVAL)
		return (92);
	/* 93: a bad dirfd with a relative name is EBADF. */
	if (call(SYS_faccessat2, 9999, (long)a, R_OK, 0, 0, 0) != -EBADF)
		return (93);

	/* fchownat */
	/* 94: AT_EMPTY_PATH with "" chowns the descriptor (to self: no-op). */
	if (call(SYS_fchownat, fd, (long)empty,
	    call(SYS_getuid, 0, 0, 0, 0, 0, 0), call(SYS_getgid, 0, 0, 0, 0, 0, 0),
	    AT_EMPTY_PATH, 0) != 0)
		return (94);
	/* 95: -1/-1 leaves ownership alone and succeeds. */
	if (call(SYS_fchownat, AT_FDCWD, (long)a, -1, -1, AT_SYMLINK_NOFOLLOW,
	    0) != 0)
		return (95);
	/* 96: unknown flags are EINVAL. */
	if (call(SYS_fchownat, AT_FDCWD, (long)a, -1, -1, 0x400, 0) != -EINVAL)
		return (96);
	/* 97: "" without AT_EMPTY_PATH is ENOENT. */
	if (call(SYS_fchownat, fd, (long)empty, -1, -1, 0, 0) != -ENOENT)
		return (97);
	/* 98: a bad dirfd with a relative name is EBADF. */
	if (call(SYS_fchownat, 9999, (long)a, -1, -1, 0, 0) != -EBADF)
		return (98);

	/* copy_file_range */
	fd2 = create(c);
	if (fd2 < 0) return (99);
	if (call(SYS_lseek, fd, 0, 0, 0, 0, 0) != 0) return (99);
	if (call(SYS_ftruncate, fd, 0, 0, 0, 0, 0) != 0) return (99);
	if (call(SYS_write, fd, (long)"wxyz", 4, 0, 0, 0) != 4) return (99);
	if (call(SYS_lseek, fd, 0, 0, 0, 0, 0) != 0) return (99);
	/* 100-101: flags == 0 copies. */
	if (call(SYS_copy_file_range, fd, 0, fd2, 0, 4, 0) != 4) return (100);
	if (call(SYS_lseek, fd2, 0, 0, 0, 0, 0) != 0) return (101);
	if (call(SYS_read, fd2, (long)buf, 4, 0, 0, 0) != 4) return (101);
	if (buf[0] != 'w' || buf[3] != 'z') return (101);
	/* 102-103: any nonzero flags value is EINVAL. */
	if (call(SYS_lseek, fd, 0, 0, 0, 0, 0) != 0) return (102);
	if (call(SYS_copy_file_range, fd, 0, fd2, 0, 4, 1) != -EINVAL)
		return (102);
	if (call(SYS_copy_file_range, fd, 0, fd2, 0, 4, 0x80000000L) != -EINVAL)
		return (103);
	/* 104: flags are validated before the descriptors (EINVAL, not EBADF). */
	if (call(SYS_copy_file_range, 9999, 0, 9998, 0, 4, 1) != -EINVAL)
		return (104);
	/* 105: ...and with flags 0 a bad descriptor is EBADF. */
	if (call(SYS_copy_file_range, 9999, 0, fd2, 0, 4, 0) != -EBADF)
		return (105);
	(void)call(SYS_close, fd2, 0, 0, 0, 0, 0);

	/* inotify */
	/* 106-107: IN_NONBLOCK|IN_CLOEXEC are accepted. */
	ifd = call(SYS_inotify_init1, IN_NONBLOCK | IN_CLOEXEC, 0, 0, 0, 0, 0);
	if (ifd < 0) return (106);
	if (fcntl(ifd, F_GETFD, 0) != FD_CLOEXEC) return (107);
	/* 108: unknown inotify_init1 flags are EINVAL, not ignored. */
	if (call(SYS_inotify_init1, 0x1, 0, 0, 0, 0, 0) != -EINVAL) return (108);
	if (call(SYS_mkdir, (long)dir, 0700, 0, 0, 0, 0) != 0) return (109);
	/* 110: an IN_ONLYDIR watch on a directory is added. */
	r = call(SYS_inotify_add_watch, ifd, (long)dir, IN_CREATE | IN_ONLYDIR,
	    0, 0, 0);
	if (r < 0) return (110);
	/* 111: the kernel-generated IN_ISDIR bit in a mask is tolerated. */
	if (call(SYS_inotify_add_watch, ifd, (long)dir,
	    IN_CREATE | IN_ISDIR | IN_MASK_ADD, 0, 0, 0) != r)
		return (111);
	/* 112: IN_MASK_ADD together with IN_MASK_CREATE is EINVAL. */
	if (call(SYS_inotify_add_watch, ifd, (long)dir,
	    IN_CREATE | IN_MASK_ADD | IN_MASK_CREATE, 0, 0, 0) != -EINVAL)
		return (112);
	/* 113: IN_MASK_CREATE on an existing watch is EEXIST. */
	if (call(SYS_inotify_add_watch, ifd, (long)dir,
	    IN_CREATE | IN_MASK_CREATE, 0, 0, 0) != -EEXIST)
		return (113);
	/* 114: a mask of 0 is EINVAL. */
	if (call(SYS_inotify_add_watch, ifd, (long)dir, 0, 0, 0, 0) != -EINVAL)
		return (114);
	/*
	 * 115: a mask with flags but no events is EINVAL: the native
	 * inotify insists on at least one event (Linux would add a watch
	 * that only ever reports IN_IGNORED/IN_UNMOUNT).
	 */
	if (call(SYS_inotify_add_watch, ifd, (long)dir, IN_ONLYDIR, 0, 0, 0)
	    != -EINVAL)
		return (115);
	/* 116: an unknown mask bit is EINVAL (not in ALL_INOTIFY_BITS). */
	if (call(SYS_inotify_add_watch, ifd, (long)dir, IN_CREATE | 0x1000,
	    0, 0, 0) != -EINVAL)
		return (116);
	/* 117: IN_ONLYDIR on a regular file is ENOTDIR. */
	if (call(SYS_inotify_add_watch, ifd, (long)a, IN_MODIFY | IN_ONLYDIR,
	    0, 0, 0) != -ENOTDIR)
		return (117);
	/* 118: inotify_add_watch on a non-inotify descriptor is EINVAL. */
	if (call(SYS_inotify_add_watch, fd, (long)dir, IN_CREATE, 0, 0, 0)
	    != -EINVAL)
		return (118);
	/* 119: ...and on a bad descriptor EBADF. */
	if (call(SYS_inotify_add_watch, 9999, (long)dir, IN_CREATE, 0, 0, 0)
	    != -EBADF)
		return (119);
	(void)call(SYS_close, ifd, 0, 0, 0, 0, 0);

	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	(void)call(SYS_close, pipes[0], 0, 0, 0, 0, 0);
	(void)call(SYS_close, pipes[1], 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)a, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)b, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)c, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)dir, 0, 0, 0, 0, 0);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
