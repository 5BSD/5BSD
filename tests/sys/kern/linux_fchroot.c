/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding amd64 Linux ABI test for fchroot(2), syscall 472. */
#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000
#define O_PATH 010000000
#define EPERM 1
#define ENOENT 2
#define EBADF 9
#define EACCES 13
#define ENOTDIR 20
#define EINVAL 22
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_pipe 22
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_mkdir 83
#define SYS_rmdir 84
#define SYS_unlink 87
#define SYS_chmod 90
#define SYS_setuid 105
#define SYS_openat 257
#define SYS_fchroot 472

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
openat(long dfd, const char *path, long flags, long mode)
{
	return (call(SYS_openat, dfd, (long)path, flags, mode, 0, 0));
}

static int
child_result(long dfd, unsigned int flags, int kind)
{
	char byte;
	long fd, r;

	r = call(SYS_fchroot, dfd, flags, 0, 0, 0, 0);
	if (kind == 1) {
		if (r != 0)
			return (1);
		fd = openat(AT_FDCWD, "/marker", O_RDONLY, 0);
		if (fd < 0)
			return (2);
		if (call(SYS_read, fd, (long)&byte, 1, 0, 0, 0) != 1 ||
		    byte != 'M')
			return (3);
		(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
		if (openat(AT_FDCWD, "/outside", O_RDONLY, 0) != -ENOENT)
			return (4);
		/* chroot/fchroot intentionally leave cwd unchanged. */
		fd = openat(AT_FDCWD, "outside", O_RDONLY, 0);
		if (fd < 0)
			return (5);
		(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
		return (0);
	}
	return ((int)-r);
}

static int
run_child(long fd, unsigned int flags, int kind, int drop_uid)
{
	long pid;
	int status;

	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		if (drop_uid && call(SYS_setuid, 65534, 0, 0, 0, 0, 0) != 0)
			call(SYS_exit, 250, 0, 0, 0, 0, 0);
		call(SYS_exit, child_result(fd, flags, kind), 0, 0, 0, 0, 0);
	}
	status = 0;
	if (call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid)
		return (-2);
	if ((status & 0x7f) != 0)
		return (-3);
	return ((status >> 8) & 0xff);
}

static int
test(void)
{
	char root[] = "fchroot.root", marker[] = "fchroot.root/marker";
	char outside[] = "outside";
	long dfd, filefd, pathfd, fd;
	int pipes[2];

	(void)call(SYS_unlink, (long)marker, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)root, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)outside, 0, 0, 0, 0, 0);
	if (call(SYS_mkdir, (long)root, 0755, 0, 0, 0, 0) != 0) return (1);
	fd = openat(AT_FDCWD, marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0 || call(SYS_write, fd, (long)"M", 1, 0, 0, 0) != 1)
		return (2);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	fd = openat(AT_FDCWD, outside, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return (3);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	dfd = openat(AT_FDCWD, root, O_RDONLY | O_DIRECTORY, 0);
	filefd = openat(AT_FDCWD, marker, O_RDONLY, 0);
	pathfd = openat(AT_FDCWD, root, O_PATH | O_DIRECTORY, 0);
	if (dfd < 0 || filefd < 0 || pathfd < 0) return (4);
	if (call(SYS_pipe, (long)pipes, 0, 0, 0, 0, 0) != 0) return (5);

	/* Validation precedes descriptor lookup. */
	if (call(SYS_fchroot, 9999, 1, 0, 0, 0, 0) != -EINVAL) return (6);
	if (call(SYS_fchroot, 9999, 0, 0, 0, 0, 0) != -EBADF) return (7);
	if (call(SYS_fchroot, filefd, 0, 0, 0, 0, 0) != -ENOTDIR) return (8);
	if (call(SYS_fchroot, pipes[0], 0, 0, 0, 0, 0) != -ENOTDIR) return (9);
	if (call(SYS_fchroot, pathfd, 0, 0, 0, 0, 0) != -EBADF) return (10);

	/* Root can install the descriptor root; absolute lookup is confined. */
	if (run_child(dfd, 0, 1, 0) != 0) return (11);
	/* Search permission is checked before CAP_SYS_CHROOT. */
	if (call(SYS_chmod, (long)root, 0000, 0, 0, 0, 0) != 0) return (12);
	if (run_child(dfd, 0, 0, 1) != EACCES) return (13);
	if (call(SYS_chmod, (long)root, 0755, 0, 0, 0, 0) != 0) return (14);
	/* An unprivileged caller with search permission gets EPERM. */
	if (run_child(dfd, 0, 0, 1) != EPERM) return (15);
	(void)call(SYS_close, filefd, 0, 0, 0, 0, 0);
	if (call(SYS_fchroot, filefd, 0, 0, 0, 0, 0) != -EBADF) return (16);

	(void)call(SYS_close, pipes[0], 0, 0, 0, 0, 0);
	(void)call(SYS_close, pipes[1], 0, 0, 0, 0, 0);
	(void)call(SYS_close, pathfd, 0, 0, 0, 0, 0);
	(void)call(SYS_close, dfd, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)marker, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)root, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)outside, 0, 0, 0, 0, 0);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
