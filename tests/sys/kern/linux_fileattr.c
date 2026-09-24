/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux ABI test for file_getattr(2) and
 * file_setattr(2), Linux syscall numbers 468 and 469.  It deliberately has
 * no Linux libc or sysroot dependency.  The exit status identifies the
 * failed assertion below.
 */
struct file_attr {
	unsigned long long fa_xflags;
	unsigned int fa_extsize;
	unsigned int fa_nextents;
	unsigned int fa_projid;
	unsigned int fa_cowextsize;
};

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_EMPTY_PATH 0x1000
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000
#define O_PATH 010000000
#define E2BIG 7
#define EBADF 9
#define EACCES 13
#define EFAULT 14
#define ENOENT 2
#define EPERM 1
#define EINVAL 22
#define EOPNOTSUPP 95
#define FS_XFLAG_PREALLOC 0x00000002
#define FS_XFLAG_IMMUTABLE 0x00000008
#define FS_XFLAG_APPEND 0x00000010
#define FS_XFLAG_SYNC 0x00000020
#define FS_XFLAG_NODUMP 0x00000080
#define FS_XFLAG_EXTSIZE 0x00000800
#define FS_XFLAG_VERITY 0x00020000
#define FS_XFLAG_HASATTR 0x80000000
#define FS_IMMUTABLE_FL 0x00000010
#define FS_APPEND_FL 0x00000020
#define FS_NODUMP_FL 0x00000040
#define FS_IOC_GETFLAGS 0x80086601
#define FS_IOC_SETFLAGS 0x40086602
#define SUPPORTED (FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND | FS_XFLAG_NODUMP)
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_pipe 22
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_mkdir 83
#define SYS_rmdir 84
#define SYS_unlink 87
#define SYS_symlink 88
#define SYS_setuid 105
#define SYS_openat 257
#define SYS_file_getattr 468
#define SYS_file_setattr 469

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
file_getattr(long dfd, const char *path, struct file_attr *fa,
    unsigned long size, unsigned int flags)
{
	return (call(SYS_file_getattr, dfd, (long)path, (long)fa, size,
	    flags, 0));
}

static long
file_setattr(long dfd, const char *path, struct file_attr *fa,
    unsigned long size, unsigned int flags)
{
	return (call(SYS_file_setattr, dfd, (long)path, (long)fa, size,
	    flags, 0));
}

static void
zero(void *p, unsigned long n)
{
	unsigned char *q = p;

	while (n-- != 0)
		*q++ = 0;
}

static int
test(void)
{
	struct file_attr fa;
	unsigned char big[32];
	char file[] = "fileattr.data", dir[] = "fileattr.dir";
	char link[] = "fileattr.link", empty[] = "", dot[] = ".";
	long fd, dfd, pfd, pid, r, lflags;
	int pipes[2], status, i;

	(void)call(SYS_unlink, (long)link, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)dir, 0, 0, 0, 0, 0);
	fd = call(SYS_openat, AT_FDCWD, (long)file,
	    O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
	if (fd < 0) return (1);

	/* Basic get returns a fully initialized version-zero structure. */
	for (i = 0; i < (int)sizeof(fa); i++) ((unsigned char *)&fa)[i] = 0xa5;
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0) return (2);
	if ((fa.fa_xflags & ~SUPPORTED) != 0 || fa.fa_extsize != 0 ||
	    fa.fa_nextents != 0 || fa.fa_projid != 0 || fa.fa_cowextsize != 0)
		return (3);
	/* A larger output structure is accepted and its unknown tail is zeroed. */
	for (i = 0; i < 32; i++) big[i] = 0xa5;
	if (file_getattr(AT_FDCWD, file, (struct file_attr *)big, 32, 0) != 0)
		return (4);
	for (i = 24; i < 32; i++) if (big[i] != 0) return (5);

	/* Size, pointer, flag, lookup, and descriptor failures. */
	if (file_getattr(AT_FDCWD, file, &fa, 23, 0) != -EINVAL) return (6);
	if (file_getattr(AT_FDCWD, file, &fa, 8192, 0) != -E2BIG) return (7);
	if (file_getattr(AT_FDCWD, file, 0, sizeof(fa), 0) != -EFAULT) return (8);
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 1) != -EINVAL)
		return (9);
	if (file_getattr(AT_FDCWD, "fileattr.missing", &fa, sizeof(fa), 0)
	    != -ENOENT) return (10);
	if (file_getattr(9999, file, &fa, sizeof(fa), 0) != -EBADF) return (11);
	if (file_getattr(fd, empty, &fa, sizeof(fa), 0) != -ENOENT) return (12);
	if (file_getattr(fd, 0, &fa, sizeof(fa), 0) != -EFAULT) return (13);
	if (file_getattr(9999, empty, &fa, sizeof(fa), AT_EMPTY_PATH) != -EBADF)
		return (14);

	zero(&fa, sizeof(fa));
	if (file_setattr(AT_FDCWD, file, &fa, 23, 0) != -EINVAL) return (15);
	if (file_setattr(AT_FDCWD, file, &fa, 8192, 0) != -E2BIG) return (16);
	if (file_setattr(AT_FDCWD, file, 0, sizeof(fa), 0) != -EFAULT)
		return (17);
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 2) != -EINVAL)
		return (18);
	fa.fa_xflags = 1ULL << 40;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != -EINVAL)
		return (19);
	fa.fa_xflags = FS_XFLAG_SYNC;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != -EOPNOTSUPP)
		return (20);
	zero(&fa, sizeof(fa)); fa.fa_extsize = 4096;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != -EOPNOTSUPP)
		return (21);
	zero(&fa, sizeof(fa)); fa.fa_projid = 7;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != -EOPNOTSUPP)
		return (22);
	zero(&fa, sizeof(fa)); fa.fa_cowextsize = 4096;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != -EOPNOTSUPP)
		return (23);

	/* copy_struct_from_user accepts a zero tail and rejects a nonzero tail. */
	zero(big, sizeof(big)); big[24] = 1;
	if (file_setattr(AT_FDCWD, file, (struct file_attr *)big, 32, 0)
	    != -E2BIG) return (24);
	big[24] = 0;
	if (file_setattr(AT_FDCWD, file, (struct file_attr *)big, 32, 0) != 0)
		return (25);

	/* Supported ZFS/native flags round-trip together and can be cleared. */
	zero(&fa, sizeof(fa)); fa.fa_xflags = SUPPORTED;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0) return (26);
	zero(&fa, sizeof(fa));
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0 ||
	    (fa.fa_xflags & SUPPORTED) != SUPPORTED) return (27);
	zero(&fa, sizeof(fa));
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0) return (28);
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0 ||
	    (fa.fa_xflags & SUPPORTED) != 0) return (29);
	/* The existing FS_IOC flags path uses the same ZFS-correct mapping. */
	lflags = 0;
	if (call(SYS_ioctl, fd, FS_IOC_GETFLAGS, (long)&lflags, 0, 0, 0) != 0)
		return (55);
	if ((lflags & (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL)) != 0)
		return (56);
	lflags = FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL;
	if (call(SYS_ioctl, fd, FS_IOC_SETFLAGS, (long)&lflags, 0, 0, 0) != 0)
		return (57);
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0 ||
	    (fa.fa_xflags & SUPPORTED) != SUPPORTED) return (58);
	lflags = 0x80000000;
	if (call(SYS_ioctl, fd, FS_IOC_SETFLAGS, (long)&lflags, 0, 0, 0)
	    != -EOPNOTSUPP) return (59);
	lflags = 0;
	if (call(SYS_ioctl, fd, FS_IOC_SETFLAGS, (long)&lflags, 0, 0, 0) != 0)
		return (60);
	/* Read-only flags and the get-only nextents field are ignored on set. */
	zero(&fa, sizeof(fa));
	fa.fa_xflags = FS_XFLAG_PREALLOC | FS_XFLAG_VERITY | FS_XFLAG_HASATTR;
	fa.fa_nextents = 123;
	if (file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0) return (30);
	if (file_getattr(AT_FDCWD, file, &fa, sizeof(fa), 0) != 0 ||
	    (fa.fa_xflags & SUPPORTED) != 0) return (31);

	/* Relative dirfd and AT_EMPTY_PATH (empty and NULL) name the same inode. */
	dfd = call(SYS_openat, AT_FDCWD, (long)dot, O_RDONLY | O_DIRECTORY,
	    0, 0, 0);
	if (dfd < 0) return (32);
	zero(&fa, sizeof(fa)); fa.fa_xflags = FS_XFLAG_NODUMP;
	if (file_setattr(dfd, file, &fa, sizeof(fa), 0) != 0) return (33);
	if (file_getattr(fd, empty, &fa, sizeof(fa), AT_EMPTY_PATH) != 0 ||
	    (fa.fa_xflags & FS_XFLAG_NODUMP) == 0) return (34);
	zero(&fa, sizeof(fa));
	if (file_setattr(fd, 0, &fa, sizeof(fa), AT_EMPTY_PATH) != 0) return (35);
	if (file_getattr(fd, 0, &fa, sizeof(fa), AT_EMPTY_PATH) != 0 ||
	    (fa.fa_xflags & SUPPORTED) != 0) return (36);

	/* Linux fd_empty() rejects O_PATH in the NULL descriptor form. */
	pfd = call(SYS_openat, AT_FDCWD, (long)file, O_PATH, 0, 0, 0);
	if (pfd < 0) return (37);
	zero(&fa, sizeof(fa)); fa.fa_xflags = FS_XFLAG_NODUMP;
	if (file_setattr(pfd, 0, &fa, sizeof(fa), AT_EMPTY_PATH) != -EBADF)
		return (38);
	if (file_getattr(pfd, 0, &fa, sizeof(fa), AT_EMPTY_PATH) != -EBADF)
		return (39);
	/* The empty string takes the same fd_empty() path. */
	zero(&fa, sizeof(fa));
	if (file_setattr(pfd, empty, &fa, sizeof(fa), AT_EMPTY_PATH) != -EBADF)
		return (40);

	/* Following a symlink reaches the file; NOFOLLOW reports unsupported. */
	if (call(SYS_symlink, (long)file, (long)link, 0, 0, 0, 0) != 0)
		return (41);
	if (file_getattr(AT_FDCWD, link, &fa, sizeof(fa), 0) != 0) return (42);
	if (file_getattr(AT_FDCWD, link, &fa, sizeof(fa),
	    AT_SYMLINK_NOFOLLOW) != -EOPNOTSUPP) return (43);
	if (file_setattr(AT_FDCWD, link, &fa, sizeof(fa),
	    AT_SYMLINK_NOFOLLOW) != -EOPNOTSUPP) return (44);

	/* Directories support the same flags; anonymous pipe objects do not. */
	if (call(SYS_mkdir, (long)dir, 0700, 0, 0, 0, 0) != 0) return (45);
	zero(&fa, sizeof(fa)); fa.fa_xflags = FS_XFLAG_NODUMP;
	if (file_setattr(AT_FDCWD, dir, &fa, sizeof(fa), 0) != 0) return (46);
	if (file_getattr(AT_FDCWD, dir, &fa, sizeof(fa), 0) != 0 ||
	    (fa.fa_xflags & FS_XFLAG_NODUMP) == 0) return (47);
	zero(&fa, sizeof(fa));
	if (file_setattr(AT_FDCWD, dir, &fa, sizeof(fa), 0) != 0) return (48);
	if (call(SYS_pipe, (long)pipes, 0, 0, 0, 0, 0) != 0) return (49);
	if (file_getattr(pipes[0], 0, &fa, sizeof(fa), AT_EMPTY_PATH)
	    != -EOPNOTSUPP) return (50);
	if (file_setattr(pipes[0], 0, &fa, sizeof(fa), AT_EMPTY_PATH)
	    != -EOPNOTSUPP) return (51);

	/* An unprivileged process cannot change a root-owned file. */
	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid < 0) return (52);
	if (pid == 0) {
		if (call(SYS_setuid, 65534, 0, 0, 0, 0, 0) != 0)
			call(SYS_exit, 2, 0, 0, 0, 0, 0);
		zero(&fa, sizeof(fa)); fa.fa_xflags = FS_XFLAG_NODUMP;
		r = file_setattr(AT_FDCWD, file, &fa, sizeof(fa), 0);
		call(SYS_exit, r == -EPERM || r == -EACCES ? 0 : 3,
		    0, 0, 0, 0, 0);
	}
	status = 0;
	if (call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid)
		return (53);
	if (status != 0) return (54);

	(void)call(SYS_close, pipes[0], 0, 0, 0, 0, 0);
	(void)call(SYS_close, pipes[1], 0, 0, 0, 0, 0);
	(void)call(SYS_close, pfd, 0, 0, 0, 0, 0);
	(void)call(SYS_close, dfd, 0, 0, 0, 0, 0);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)link, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)dir, 0, 0, 0, 0, 0);
	return (0);
}

__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(SYS_exit, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
