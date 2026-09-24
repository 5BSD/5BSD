/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for openat2(2), fchmodat2(2) and
 * execveat(2): no Linux libc or sysroot required.  Exit status identifies
 * the failed check; each check's comment names the Linux behaviour it
 * asserts.  Where the emulator deliberately rejects an option it cannot
 * honour exactly, the comment says so and the documented errno is
 * asserted.
 */
struct open_how { unsigned long flags, mode, resolve; };

#define	O_RDONLY	0
#define	O_WRONLY	1
#define	O_RDWR		2
#define	O_CREAT		0100
#define	O_EXCL		0200
#define	O_TRUNC		01000
#define	O_DIRECTORY	0200000
#define	O_NOFOLLOW	0400000
#define	O_CLOEXEC	02000000
#define	O_PATH		010000000
#define	__O_TMPFILE	020000000
#define	O_TMPFILE	(__O_TMPFILE | O_DIRECTORY)

#define	RESOLVE_NO_XDEV		0x01
#define	RESOLVE_NO_MAGICLINKS	0x02
#define	RESOLVE_NO_SYMLINKS	0x04
#define	RESOLVE_BENEATH		0x08
#define	RESOLVE_IN_ROOT		0x10
#define	RESOLVE_CACHED		0x20

#define	AT_FDCWD		-100
#define	AT_SYMLINK_NOFOLLOW	0x100
#define	AT_EMPTY_PATH		0x1000

#define	EPERM	1
#define	ENOENT	2
#define	E2BIG	7
#define	EBADF	9
#define	EAGAIN	11
#define	EACCES	13
#define	EFAULT	14
#define	EEXIST	17
#define	EXDEV	18
#define	ENOTDIR	20
#define	EINVAL	22
#define	ELOOP	40
#define	EOPNOTSUPP	95

#define	SYS_write	1
#define	SYS_close	3
#define	SYS_exit	60
#define	SYS_wait4	61
#define	SYS_fork	57
#define	SYS_mkdir	83
#define	SYS_rmdir	84
#define	SYS_unlink	87
#define	SYS_symlink	88
#define	SYS_openat	257
#define	SYS_newfstatat	262
#define	SYS_execveat	322
#define	SYS_openat2	437
#define	SYS_fchmodat2	452

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
openat2(long dfd, const char *path, struct open_how *how, long size)
{
	return (call(SYS_openat2, dfd, (long)path, (long)how, size, 0, 0));
}

static long
fchmodat2(long dfd, const char *path, long mode, long flags)
{
	return (call(SYS_fchmodat2, dfd, (long)path, mode, flags, 0, 0));
}

static long
execveat(long dfd, const char *path, char **argv, char **envp, long flags)
{
	return (call(SYS_execveat, dfd, (long)path, (long)argv, (long)envp,
	    flags, 0));
}

static void
how_set(struct open_how *how, unsigned long flags, unsigned long mode,
    unsigned long resolve)
{
	how->flags = flags;
	how->mode = mode;
	how->resolve = resolve;
}

/* x86_64 struct stat: st_mode is the 32-bit word at offset 24. */
static long
mode_of(long dfd, const char *path, long flags)
{
	unsigned char st[144];

	if (call(SYS_newfstatat, dfd, (long)path, (long)st, flags, 0, 0) != 0)
		return (-1);
	return (*(unsigned int *)&st[24] & 07777);
}

/*
 * Run the child: exec self through execveat with the given arguments
 * and report the child's exit status (or -1 on setup failure).  The
 * child either execs (and the re-executed image exits 0 at once) or
 * exits with the exec errno, so it can never be stranded.
 */
static long
exec_child(long dfd, const char *path, char **argv, char **envp, long flags)
{
	long pid, r;
	int status;

	pid = call(SYS_fork, 0, 0, 0, 0, 0, 0);
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		r = execveat(dfd, path, argv, envp, flags);
		/* Exec failed: report the negated errno, capped at 200. */
		r = -r;
		if (r > 200)
			r = 200;
		call(SYS_exit, r, 0, 0, 0, 0, 0);
	}
	status = 0;
	if (call(SYS_wait4, pid, (long)&status, 0, 0, 0, 0) != pid)
		return (-1);
	if ((status & 0x7f) != 0)
		return (-2);
	return ((status >> 8) & 0xff);
}

static int
test(char **argv, char **envp)
{
	struct open_how how;
	/* Larger buffer: struct open_how followed by trailing bytes. */
	unsigned long big[64];
	char dir[] = "o2dir", file[] = "o2dir/file", link[] = "o2dir/link";
	char sub[] = "o2dir/sub";
	char dirlink[] = "o2dir/dirlink", viadirlink[] = "o2dir/dirlink/file";
	char self_link[] = "o2self", dirself[] = "o2dir/self";
	char updir[256] = "../";
	const char *target;
	char child_arg[] = "child", empty[] = "";
	char *child_argv[3];
	long dfd, fd, r, i;
	int status;

	child_argv[0] = argv[0];
	child_argv[1] = child_arg;
	child_argv[2] = 0;

	(void)call(SYS_mkdir, (long)dir, 0700, 0, 0, 0, 0);
	(void)call(SYS_mkdir, (long)sub, 0700, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)link, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)dirlink, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)dirself, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)self_link, 0, 0, 0, 0, 0);

	/* 1: openat2 creates a file; O_CREAT permits a mode. */
	how_set(&how, O_WRONLY | O_CREAT | O_EXCL, 0640, 0);
	fd = openat2(AT_FDCWD, file, &how, sizeof(how));
	if (fd < 0) return (1);
	if (call(SYS_write, fd, (long)"hi", 2, 0, 0, 0) != 2) return (2);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 3: mode was honoured on creation (umask may clear group bits). */
	r = mode_of(AT_FDCWD, file, 0);
	if (r < 0 || (r & 0700) != 0600) return (3);
	/* 4: O_CREAT|O_EXCL on an existing file is EEXIST, like openat. */
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EEXIST) return (4);

	/* 5: size < OPEN_HOW_SIZE_VER0 (24) is EINVAL. */
	how_set(&how, O_RDONLY, 0, 0);
	if (openat2(AT_FDCWD, file, &how, 16) != -EINVAL) return (5);
	/* 6: size 0 is EINVAL too. */
	if (openat2(AT_FDCWD, file, &how, 0) != -EINVAL) return (6);
	/* 7: a NULL how pointer is EFAULT. */
	if (openat2(AT_FDCWD, file, 0, sizeof(how)) != -EFAULT) return (7);
	/* 8: a larger struct whose trailing bytes are zero is accepted. */
	for (i = 0; i < 64; i++)
		big[i] = 0;
	big[0] = O_RDONLY;
	fd = openat2(AT_FDCWD, file, (struct open_how *)big, 32);
	if (fd < 0) return (8);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 9: a larger struct with a nonzero trailing byte is E2BIG. */
	big[3] = 1;
	if (openat2(AT_FDCWD, file, (struct open_how *)big, 32) != -E2BIG)
		return (9);
	big[3] = 0;
	/* 10: size larger than a page is E2BIG regardless of contents. */
	if (openat2(AT_FDCWD, file, (struct open_how *)big, 8192) != -E2BIG)
		return (10);
	/* 11: unknown open flag bits are EINVAL (openat2 is strict). */
	how_set(&how, O_RDONLY | (1UL << 30), 0, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (11);
	/* 12: high 32 bits of flags are not silently truncated. */
	how_set(&how, O_RDONLY | (1UL << 40), 0, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (12);
	/* 13: unknown resolve bits are EINVAL. */
	how_set(&how, O_RDONLY, 0, 0x40);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (13);
	/* 14: mode without O_CREAT/O_TMPFILE is EINVAL. */
	how_set(&how, O_RDONLY, 0600, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (14);
	/* 15: O_CREAT mode outside 07777 is EINVAL. */
	how_set(&how, O_WRONLY | O_CREAT, 010000, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (15);
	/* 16: O_PATH with a flag outside O_PATH_FLAGS (O_RDWR) is EINVAL. */
	how_set(&how, O_PATH | O_RDWR, 0, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -EINVAL) return (16);
	/* 17: O_PATH|O_CLOEXEC is a valid combination. */
	how_set(&how, O_PATH | O_CLOEXEC, 0, 0);
	fd = openat2(AT_FDCWD, file, &how, sizeof(how));
	if (fd < 0) return (17);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 18: O_DIRECTORY|O_CREAT is EINVAL. */
	how_set(&how, O_DIRECTORY | O_CREAT, 0, 0);
	if (openat2(AT_FDCWD, dir, &how, sizeof(how)) != -EINVAL) return (18);
	/* 19: O_DIRECTORY on a regular file is ENOTDIR (plain errno). */
	how_set(&how, O_RDONLY | O_DIRECTORY, 0, 0);
	if (openat2(AT_FDCWD, file, &how, sizeof(how)) != -ENOTDIR) return (19);
	/* 20: __O_TMPFILE without O_DIRECTORY is EINVAL. */
	how_set(&how, __O_TMPFILE | O_RDWR, 0600, 0);
	if (openat2(AT_FDCWD, dir, &how, sizeof(how)) != -EINVAL) return (20);
	/* 21: O_TMPFILE without write access is EINVAL. */
	how_set(&how, O_TMPFILE | O_RDONLY, 0600, 0);
	if (openat2(AT_FDCWD, dir, &how, sizeof(how)) != -EINVAL) return (21);
	/*
	 * 22: O_TMPFILE|O_RDWR is not implemented (no unnamed files):
	 * EOPNOTSUPP, the errno Linux gives on a filesystem without it.
	 */
	how_set(&how, O_TMPFILE | O_RDWR, 0600, 0);
	if (openat2(AT_FDCWD, dir, &how, sizeof(how)) != -EOPNOTSUPP)
		return (22);

	/* 23-24: RESOLVE_BENEATH happy path: a relative name inside dirfd. */
	dfd = call(SYS_openat, AT_FDCWD, (long)dir, O_RDONLY | O_DIRECTORY,
	    0, 0, 0);
	if (dfd < 0) return (23);
	how_set(&how, O_RDONLY, 0, RESOLVE_BENEATH);
	fd = openat2(dfd, "file", &how, sizeof(how));
	if (fd < 0) return (24);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 25: RESOLVE_BENEATH permits ".." that never leaves dirfd. */
	fd = openat2(dfd, "sub/../file", &how, sizeof(how));
	if (fd < 0) return (25);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 26: RESOLVE_BENEATH relative to AT_FDCWD scopes to the cwd. */
	fd = openat2(AT_FDCWD, file, &how, sizeof(how));
	if (fd < 0) return (26);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 27: RESOLVE_BENEATH: ".." escaping dirfd is EXDEV. */
	if (openat2(dfd, "../o2dir/file", &how, sizeof(how)) != -EXDEV)
		return (27);
	/* 28: RESOLVE_BENEATH: absolute paths are EXDEV. */
	if (openat2(dfd, "/", &how, sizeof(how)) != -EXDEV) return (28);
	/* 29: ...also relative to AT_FDCWD. */
	if (openat2(AT_FDCWD, "/", &how, sizeof(how)) != -EXDEV) return (29);
	/* 30-31: RESOLVE_BENEATH: a symlink to an absolute path is EXDEV. */
	if (call(SYS_symlink, (long)"/", (long)link, 0, 0, 0, 0) != 0)
		return (30);
	if (openat2(dfd, "link", &how, sizeof(how)) != -EXDEV) return (31);
	/* 32: ...even as an intermediate component. */
	if (openat2(dfd, "link/etc", &how, sizeof(how)) != -EXDEV) return (32);
	/* 33-34: a relative symlink that stays inside dirfd is fine. */
	if (call(SYS_symlink, (long)".", (long)dirlink, 0, 0, 0, 0) != 0)
		return (33);
	fd = openat2(dfd, "dirlink/file", &how, sizeof(how));
	if (fd < 0) return (34);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 35: RESOLVE_BENEATH|RESOLVE_IN_ROOT is EINVAL (exclusive). */
	how_set(&how, O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT);
	if (openat2(dfd, "file", &how, sizeof(how)) != -EINVAL) return (35);
	/* 36: RESOLVE_IN_ROOT interprets an absolute path below dirfd. */
	how_set(&how, O_RDONLY, 0, RESOLVE_IN_ROOT);
	fd = openat2(dfd, "/file", &how, sizeof(how));
	if (fd < 0) return (36);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 37: Every traversed symlink is rejected, including parent components. */
	how_set(&how, O_RDONLY, 0, RESOLVE_NO_SYMLINKS);
	if (openat2(AT_FDCWD, viadirlink, &how, sizeof(how)) != -ELOOP)
		return (37);
	/* 38-39: Plain paths work under either link restriction. */
	fd = openat2(dfd, "file", &how, sizeof(how));
	if (fd < 0) return (38);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	how_set(&how, O_RDONLY, 0, RESOLVE_NO_MAGICLINKS);
	fd = openat2(dfd, "file", &how, sizeof(how));
	if (fd < 0) return (39);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 40: RESOLVE_NO_XDEV permits lookups staying on this mount. */
	how_set(&how, O_RDONLY, 0, RESOLVE_NO_XDEV);
	fd = openat2(dfd, "file", &how, sizeof(how));
	if (fd < 0) return (40);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 41: RESOLVE_CACHED is EAGAIN (documented: retry without it). */
	how_set(&how, O_RDONLY, 0, RESOLVE_CACHED);
	if (openat2(dfd, "file", &how, sizeof(how)) != -EAGAIN) return (41);
	/* 42: EBADF for a bad dirfd with a relative name. */
	how_set(&how, O_RDONLY, 0, 0);
	if (openat2(9999, "file", &how, sizeof(how)) != -EBADF) return (42);
	/* 43: a bad dirfd is irrelevant for an absolute name. */
	fd = openat2(9999, "/", &how, sizeof(how));
	if (fd < 0) return (43);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 44: O_NOFOLLOW on a symlink is ELOOP, like openat. */
	how_set(&how, O_RDONLY | O_NOFOLLOW, 0, 0);
	if (openat2(dfd, "link", &how, sizeof(how)) != -ELOOP) return (44);
	/* 45: O_PATH|O_NOFOLLOW opens the symlink itself. */
	how_set(&how, O_PATH | O_NOFOLLOW, 0, 0);
	fd = openat2(dfd, "link", &how, sizeof(how));
	if (fd < 0) return (45);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 46: a nonexistent name is ENOENT (plain errno passthrough). */
	how_set(&how, O_RDONLY, 0, 0);
	if (openat2(dfd, "nope", &how, sizeof(how)) != -ENOENT) return (46);

	/* 47-48: fchmodat2 happy path changes the mode. */
	if (fchmodat2(AT_FDCWD, file, 0604, 0) != 0) return (47);
	if (mode_of(AT_FDCWD, file, 0) != 0604) return (48);
	/* 49: fchmodat2 with unknown flags (AT_EACCESS here) is EINVAL. */
	if (fchmodat2(AT_FDCWD, file, 0600, 0x200) != -EINVAL) return (49);
	/* 50-52: AT_EMPTY_PATH with "" operates on dfd itself. */
	fd = call(SYS_openat, AT_FDCWD, (long)file, O_RDONLY, 0, 0, 0);
	if (fd < 0) return (50);
	if (fchmodat2(fd, empty, 0600, AT_EMPTY_PATH) != 0) return (51);
	if (mode_of(AT_FDCWD, file, 0) != 0600) return (52);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 53: AT_EMPTY_PATH with a non-empty name resolves the name. */
	if (fchmodat2(dfd, "file", 0640, AT_EMPTY_PATH) != 0) return (53);
	if (mode_of(AT_FDCWD, file, 0) != 0640) return (53);
	/* 54: "" without AT_EMPTY_PATH is ENOENT. */
	if (fchmodat2(dfd, empty, 0600, 0) != -ENOENT) return (54);
	/* 55-56: AT_SYMLINK_NOFOLLOW on a regular file works. */
	if (fchmodat2(dfd, "file", 0600, AT_SYMLINK_NOFOLLOW) != 0) return (55);
	if (mode_of(AT_FDCWD, file, 0) != 0600) return (56);
	/*
	 * 57: AT_SYMLINK_NOFOLLOW on a symlink is EOPNOTSUPP: Linux symlinks
	 * carry no mode, so the link itself is never changed.
	 */
	if (fchmodat2(dfd, "link", 0600, AT_SYMLINK_NOFOLLOW) != -EOPNOTSUPP)
		return (57);
	/* 58-60: without AT_SYMLINK_NOFOLLOW the symlink target is used. */
	if (call(SYS_unlink, (long)link, 0, 0, 0, 0, 0) != 0) return (58);
	if (call(SYS_symlink, (long)"file", (long)link, 0, 0, 0, 0) != 0)
		return (58);
	if (fchmodat2(dfd, "link", 0604, 0) != 0) return (59);
	if (mode_of(AT_FDCWD, file, 0) != 0604) return (60);
	/* 61: EBADF for a bad dirfd. */
	if (fchmodat2(9999, "file", 0600, 0) != -EBADF) return (61);
	/* 62: a nonexistent name is ENOENT. */
	if (fchmodat2(dfd, "nope", 0600, 0) != -ENOENT) return (62);

	/* 63: execveat with unknown flags is EINVAL. */
	if (execveat(AT_FDCWD, argv[0], child_argv, envp, 0x200) != -EINVAL)
		return (63);
	/* 64: "" without AT_EMPTY_PATH is ENOENT. */
	if (execveat(dfd, empty, child_argv, envp, 0) != -ENOENT) return (64);
	/* 65: EBADF for a bad descriptor with AT_EMPTY_PATH. */
	if (execveat(9999, empty, child_argv, envp, AT_EMPTY_PATH) != -EBADF)
		return (65);
	/* 66: EBADF for a bad dirfd with a relative name. */
	if (execveat(9999, "x", child_argv, envp, 0) != -EBADF) return (66);
	/* 67: a bad dirfd is irrelevant for an absolute name (ENOENT). */
	if (execveat(9999, "/nonexistent-o2", child_argv, envp, 0) != -ENOENT)
		return (67);
	/* 68-69: AT_SYMLINK_NOFOLLOW on a symlink to the binary is ELOOP. */
	if (call(SYS_symlink, (long)argv[0], (long)self_link, 0, 0, 0, 0) != 0)
		return (68);
	if (execveat(AT_FDCWD, self_link, child_argv, envp,
	    AT_SYMLINK_NOFOLLOW) != -ELOOP)
		return (69);
	/* 70: a directory descriptor with AT_EMPTY_PATH is EACCES. */
	if (execveat(dfd, empty, child_argv, envp, AT_EMPTY_PATH) != -EACCES)
		return (70);
	/* 71: AT_FDCWD with "" and AT_EMPTY_PATH "executes" the cwd: EACCES. */
	if (execveat(AT_FDCWD, empty, child_argv, envp, AT_EMPTY_PATH) !=
	    -EACCES)
		return (71);
	/* 72: a nonexistent relative name is ENOENT. */
	if (execveat(dfd, "nope", child_argv, envp, 0) != -ENOENT) return (72);
	/* 73-74: AT_EMPTY_PATH executes the descriptor (fexecve semantics). */
	fd = call(SYS_openat, AT_FDCWD, (long)argv[0], O_RDONLY | O_CLOEXEC,
	    0, 0, 0);
	if (fd < 0) return (73);
	status = exec_child(fd, empty, child_argv, envp, AT_EMPTY_PATH);
	if (status != 0) return (74);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	/* 75: a plain path relative to AT_FDCWD executes. */
	status = exec_child(AT_FDCWD, argv[0], child_argv, envp, 0);
	if (status != 0) return (75);
	/* 76: AT_SYMLINK_NOFOLLOW on the real binary executes. */
	status = exec_child(AT_FDCWD, argv[0], child_argv, envp,
	    AT_SYMLINK_NOFOLLOW);
	if (status != 0) return (76);
	/* 77: the symlink is followed without AT_SYMLINK_NOFOLLOW. */
	status = exec_child(AT_FDCWD, self_link, child_argv, envp, 0);
	if (status != 0) return (77);
	/* 78-79: a name relative to a directory descriptor executes. */
	if (call(SYS_unlink, (long)self_link, 0, 0, 0, 0, 0) != 0) return (78);
	/*
	 * The link lives one level down, so a relative argv[0] ("./openat2")
	 * must be re-rooted through ".." for the link to resolve.
	 */
	if (argv[0][0] == '/')
		target = argv[0];
	else {
		target = updir;
		for (i = 0; argv[0][i] != '\0' && i < (long)sizeof(updir) - 4;
		    i++)
			updir[3 + i] = argv[0][i];
		updir[3 + i] = '\0';
	}
	if (call(SYS_symlink, (long)target, (long)dirself, 0, 0, 0, 0) != 0)
		return (78);
	status = exec_child(dfd, "self", child_argv, envp, 0);
	if (status != 0) return (79);
	/* 80: ...and AT_SYMLINK_NOFOLLOW relative to dirfd is ELOOP too. */
	if (execveat(dfd, "self", child_argv, envp, AT_SYMLINK_NOFOLLOW) !=
	    -ELOOP)
		return (80);
	/* 81: a non-executable regular file relative to dirfd is EACCES. */
	if (execveat(dfd, "file", child_argv, envp, 0) != -EACCES) return (81);

	(void)call(SYS_close, dfd, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)dirself, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)dirlink, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)link, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)sub, 0, 0, 0, 0, 0);
	(void)call(SYS_rmdir, (long)dir, 0, 0, 0, 0, 0);
	return (0);
}

/* Entry with access to argv/envp: _start hands the initial stack to us. */
__attribute__((force_align_arg_pointer)) void
start_c(long *sp)
{
	long argc;
	char **argv, **envp;

	argc = sp[0];
	argv = (char **)&sp[1];
	envp = argv + argc + 1;
	/* Re-executed child: prove we ran and exit successfully. */
	if (argc >= 2 && argv[1][0] == 'c' && argv[1][1] == 'h')
		call(SYS_exit, 0, 0, 0, 0, 0, 0);
	call(SYS_exit, test(argv, envp), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}

__asm__(
	".globl _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call start_c\n"
	"	hlt\n");
