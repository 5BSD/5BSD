/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for TIOCGPTPEER: no Linux libc or
 * sysroot required.  Exit status identifies the failed check.
 */
typedef unsigned long size_t;

#define	SYS_read	0
#define	SYS_write	1
#define	SYS_open	2
#define	SYS_close	3
#define	SYS_fstat	5
#define	SYS_ioctl	16
#define	SYS_pipe	22
#define	SYS_exit	60
#define	SYS_fcntl	72

#define	O_RDONLY	00
#define	O_WRONLY	01
#define	O_RDWR		02
#define	O_CREAT		0100
#define	O_NOCTTY	0400
#define	O_NONBLOCK	04000
#define	O_CLOEXEC	02000000

#define	EBADF		9
#define	EINVAL		22
#define	ENOTTY		25

#define	F_GETFD		1
#define	F_GETFL		3
#define	FD_CLOEXEC	1

#define	TIOCGPTN	0x80045430
#define	TIOCSPTLCK	0x40045431
#define	TIOCGPTPEER	0x5441

/* Linux x86_64 struct stat: st_rdev lives at byte offset 40. */
struct stat { unsigned long dev, ino, nlink; unsigned int mode, uid, gid,
	pad0; unsigned long rdev; long size, blksize, blocks;
	unsigned long atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
	long unused[3]; };

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

static int
test(void)
{
	struct stat st1, st2;
	char path[] = "/dev/pts/0000000000";
	char buf[8];
	long m, peer, ro, slave, r;
	unsigned int n;
	int zero = 0, pp[2], i;

	/* open("/dev/ptmx", O_RDWR|O_NOCTTY) yields a pty master. */
	m = call(SYS_open, (long)"/dev/ptmx", O_RDWR | O_NOCTTY, 0, 0, 0, 0);
	if (m < 0) return (1);
	/* TIOCSPTLCK(0x40045431) unlocks the slave. */
	if (call(SYS_ioctl, m, TIOCSPTLCK, (long)&zero, 0, 0, 0) != 0)
		return (2);
	/* TIOCGPTN(0x80045430) reports the unit number. */
	n = ~0u;
	if (call(SYS_ioctl, m, TIOCGPTN, (long)&n, 0, 0, 0) != 0) return (3);
	if (n == ~0u) return (4);

	/* TIOCGPTPEER(0x5441) with O_RDWR|O_NOCTTY returns a new fd. */
	peer = call(SYS_ioctl, m, TIOCGPTPEER, O_RDWR | O_NOCTTY, 0, 0, 0);
	if (peer < 0) return (5);
	if (peer == m) return (6);
	/* Data written to the master is read from the peer: it is the slave. */
	if (call(SYS_write, m, (long)"x\n", 2, 0, 0, 0) != 2) return (7);
	r = call(SYS_read, peer, (long)buf, sizeof(buf), 0, 0, 0);
	if (r < 1 || buf[0] != 'x') return (8);
	/* The peer is not close-on-exec and is blocking. */
	if (call(SYS_fcntl, peer, F_GETFD, 0, 0, 0, 0) != 0) return (9);
	if ((call(SYS_fcntl, peer, F_GETFL, 0, 0, 0, 0) & O_NONBLOCK) != 0)
		return (10);

	/* The peer's st_rdev is that of /dev/pts/N. */
	i = sizeof("/dev/pts/") - 1;
	if (n >= 10000)
		return (11);
	if (n >= 1000) path[i++] = '0' + n / 1000 % 10;
	if (n >= 100) path[i++] = '0' + n / 100 % 10;
	if (n >= 10) path[i++] = '0' + n / 10 % 10;
	path[i++] = '0' + n % 10;
	path[i] = '\0';
	slave = call(SYS_open, (long)path, O_RDWR | O_NOCTTY, 0, 0, 0, 0);
	if (slave < 0) return (12);
	if (call(SYS_fstat, peer, (long)&st1, 0, 0, 0, 0) != 0) return (13);
	if (call(SYS_fstat, slave, (long)&st2, 0, 0, 0, 0) != 0) return (14);
	if (st1.rdev != st2.rdev || st1.ino != st2.ino) return (15);
	/* And it is a character device (S_IFCHR). */
	if ((st1.mode & 0170000) != 0020000) return (16);
	/* Reading the slave through the fresh open also sees master data. */
	if (call(SYS_write, m, (long)"z\n", 2, 0, 0, 0) != 2) return (17);
	r = call(SYS_read, slave, (long)buf, sizeof(buf), 0, 0, 0);
	if (r < 1 || buf[0] != 'z') return (32);
	(void)call(SYS_close, slave, 0, 0, 0, 0, 0);

	/* O_CLOEXEC and O_NONBLOCK are honoured on the new descriptor. */
	r = call(SYS_ioctl, m, TIOCGPTPEER,
	    O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK, 0, 0, 0);
	if (r < 0) return (18);
	if (call(SYS_fcntl, r, F_GETFD, 0, 0, 0, 0) != FD_CLOEXEC) return (19);
	if ((call(SYS_fcntl, r, F_GETFL, 0, 0, 0, 0) & O_NONBLOCK) == 0)
		return (20);
	(void)call(SYS_close, r, 0, 0, 0, 0, 0);
	/* O_RDONLY gives a read-only descriptor: write() is EBADF. */
	ro = call(SYS_ioctl, m, TIOCGPTPEER, O_RDONLY, 0, 0, 0);
	if (ro < 0) return (21);
	if (call(SYS_write, ro, (long)"y", 1, 0, 0, 0) != -EBADF) return (22);
	if ((call(SYS_fcntl, ro, F_GETFL, 0, 0, 0, 0) & 3) != O_RDONLY)
		return (23);
	(void)call(SYS_close, ro, 0, 0, 0, 0, 0);
	/* O_WRONLY likewise: read() is EBADF. */
	ro = call(SYS_ioctl, m, TIOCGPTPEER, O_WRONLY, 0, 0, 0);
	if (ro < 0) return (24);
	if (call(SYS_read, ro, (long)buf, 1, 0, 0, 0) != -EBADF) return (25);
	(void)call(SYS_close, ro, 0, 0, 0, 0, 0);

	/* Flag bits other than the access mode/NOCTTY/NONBLOCK/CLOEXEC: EINVAL. */
	if (call(SYS_ioctl, m, TIOCGPTPEER, O_RDWR | O_CREAT, 0, 0, 0) !=
	    -EINVAL) return (26);
	/* An access mode of 3 is EINVAL. */
	if (call(SYS_ioctl, m, TIOCGPTPEER, 3, 0, 0, 0) != -EINVAL) return (27);
	/* TIOCGPTPEER on a pipe is ENOTTY. */
	if (call(SYS_pipe, (long)pp, 0, 0, 0, 0, 0) != 0) return (28);
	if (call(SYS_ioctl, pp[0], TIOCGPTPEER, O_RDWR, 0, 0, 0) != -ENOTTY)
		return (29);
	/* TIOCGPTPEER on the slave side is ENOTTY too (not a ptmx master). */
	if (call(SYS_ioctl, peer, TIOCGPTPEER, O_RDWR, 0, 0, 0) != -ENOTTY)
		return (30);
	/* EBADF. */
	if (call(SYS_ioctl, -1, TIOCGPTPEER, O_RDWR, 0, 0, 0) != -EBADF)
		return (31);

	(void)call(SYS_close, peer, 0, 0, 0, 0, 0);
	(void)call(SYS_close, m, 0, 0, 0, 0, 0);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
