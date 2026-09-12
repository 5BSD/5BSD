/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Freestanding amd64 Linux syscall test for the *xattrat() family
 * (setxattrat 463, getxattrat 464, listxattrat 465, removexattrat 466).
 * No Linux libc or sysroot required; the exit status identifies the
 * failed check.  If the working directory's filesystem has no extended
 * attribute support the filesystem-touching checks are skipped (a note
 * goes to stderr) but the argument validation checks still run.
 */
struct xattr_args {
	unsigned long long value;
	unsigned int size;
	unsigned int flags;
};

#define	AT_FDCWD		-100
#define	AT_SYMLINK_NOFOLLOW	0x100
#define	AT_EMPTY_PATH		0x1000
#define	XATTR_CREATE		1
#define	XATTR_REPLACE		2

#define	SYS_write		1
#define	SYS_open		2
#define	SYS_close		3
#define	SYS_unlink		87
#define	SYS_symlink		88
#define	SYS_setxattr		188
#define	SYS_setxattrat		463
#define	SYS_getxattrat		464
#define	SYS_listxattrat		465
#define	SYS_removexattrat	466

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
setxattrat(long dfd, const char *path, long atf, const char *name,
    const void *val, unsigned int size, unsigned int flags, long usize)
{
	struct xattr_args xa = { (unsigned long)val, size, flags };

	return (call(SYS_setxattrat, dfd, (long)path, atf, (long)name,
	    (long)&xa, usize));
}

static long
getxattrat(long dfd, const char *path, long atf, const char *name,
    void *val, unsigned int size, unsigned int flags, long usize)
{
	struct xattr_args xa = { (unsigned long)val, size, flags };

	return (call(SYS_getxattrat, dfd, (long)path, atf, (long)name,
	    (long)&xa, usize));
}

static int
has_entry(const char *list, long len, const char *want)
{
	long i, j;

	for (i = 0; i < len; ) {
		for (j = 0; list[i + j] == want[j] && want[j] != '\0'; j++)
			;
		if (want[j] == '\0' && list[i + j] == '\0')
			return (1);
		while (i < len && list[i] != '\0')
			i++;
		i++;
	}
	return (0);
}

static int
test(void)
{
	static const char note[] = "note: no extattr support here, "
	    "filesystem checks skipped\n";
	char path[] = "xattrat.data", lnk[] = "xattrat.lnk", dot[] = ".";
	char name[] = "user.t", val[] = "xyz", buf[16], list[64];
	char big[24];
	long fd, dirfd, r;
	int nofs, i;

	fd = call(SYS_open, (long)path, 2 | 64 | 512, 0600, 0, 0, 0);
	if (fd < 0) return (1);
	/* Probe: plain setxattr(2) tells us whether the fs has extattr. */
	r = call(SYS_setxattr, (long)path, (long)name, (long)"abc", 3, 0, 0);
	nofs = (r == -95);
	if (r != 0 && !nofs) return (2);

	/* --- argument validation, never reaches the filesystem --- */
	/* 3: size below XATTR_ARGS_SIZE_VER0 (16) is EINVAL. */
	if (setxattrat(AT_FDCWD, path, 0, name, val, 3, 0, 15) != -22)
		return (3);
	/* 4: larger struct with a nonzero tail is E2BIG (copy_struct_from_user). */
	for (i = 0; i < 24; i++)
		big[i] = 0;
	*(unsigned long long *)big = (unsigned long)val;
	*(unsigned int *)(big + 8) = 3;
	big[20] = 1;
	if (call(SYS_setxattrat, AT_FDCWD, (long)path, 0, (long)name,
	    (long)big, 24) != -7) return (4);
	/* 5: size above a page is E2BIG. */
	if (setxattrat(AT_FDCWD, path, 0, name, val, 3, 0, 8192) != -7)
		return (5);
	/* 6: undefined at_flags bit is EINVAL (only NOFOLLOW/EMPTY_PATH ok). */
	if (setxattrat(AT_FDCWD, path, 0x1, name, val, 3, 0, 16) != -22)
		return (6);
	/* 7: getxattrat defines no args.flags; nonzero is EINVAL. */
	if (getxattrat(AT_FDCWD, path, 0, name, buf, 16, 1, 16) != -22)
		return (7);
	/* 8: getxattrat with bad size is EINVAL / E2BIG too. */
	if (getxattrat(AT_FDCWD, path, 0, name, buf, 16, 0, 8) != -22)
		return (8);
	/* 9: listxattrat rejects unknown at_flags. */
	if (call(SYS_listxattrat, AT_FDCWD, (long)path, 0x2, (long)list, 64,
	    0) != -22) return (9);
	/* 10: removexattrat rejects unknown at_flags. */
	if (call(SYS_removexattrat, AT_FDCWD, (long)path, 0x800, (long)name,
	    0, 0) != -22) return (10);
	/* 11: XATTR_CREATE|XATTR_REPLACE together is EINVAL. */
	if (setxattrat(AT_FDCWD, path, 0, name, val, 3,
	    XATTR_CREATE | XATTR_REPLACE, 16) != -22) return (11);
	/* 12: bad dfd with AT_EMPTY_PATH is EBADF. */
	if (getxattrat(9999, "", AT_EMPTY_PATH, name, buf, 16, 0, 16) != -9)
		return (12);
	/* 13: bad dfd with a relative path is EBADF. */
	if (getxattrat(9999, path, 0, name, buf, 16, 0, 16) != -9)
		return (13);

	if (nofs) {
		(void)call(SYS_write, 2, (long)note, sizeof(note) - 1, 0, 0, 0);
		(void)call(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
		return (0);
	}

	/* --- filesystem semantics --- */
	/* 14: larger struct with an all-zero tail is accepted. */
	big[20] = 0;
	if (call(SYS_setxattrat, AT_FDCWD, (long)path, 0, (long)name,
	    (long)big, 24) != 0) return (14);
	/* 15: plain set relative to AT_FDCWD. */
	if (setxattrat(AT_FDCWD, path, 0, name, val, 3, 0, 16) != 0)
		return (15);
	/* 16/17: get reads it back with the value length. */
	for (i = 0; i < 16; i++)
		buf[i] = 0;
	if (getxattrat(AT_FDCWD, path, 0, name, buf, 16, 0, 16) != 3)
		return (16);
	if (buf[0] != 'x' || buf[1] != 'y' || buf[2] != 'z') return (17);
	/* 18: list contains the attribute name. */
	r = call(SYS_listxattrat, AT_FDCWD, (long)path, 0, (long)list, 64, 0);
	if (r < 7 || !has_entry(list, r, name)) return (18);
	/* 19: AT_EMPTY_PATH with "" operates on dfd itself. */
	if (getxattrat(fd, "", AT_EMPTY_PATH, name, buf, 16, 0, 16) != 3)
		return (19);
	/* 20: AT_EMPTY_PATH with a NULL path names dfd as well (6.13). */
	if (getxattrat(fd, 0, AT_EMPTY_PATH, name, buf, 16, 0, 16) != 3)
		return (20);
	/* 21: "" without AT_EMPTY_PATH is a lookup failure, ENOENT. */
	if (getxattrat(fd, "", 0, name, buf, 16, 0, 16) != -2) return (21);
	/* 22/23: dfd-relative lookup through a directory descriptor. */
	dirfd = call(SYS_open, (long)dot, 0 | 0200000, 0, 0, 0, 0);
	if (dirfd < 0) return (22);
	if (getxattrat(dirfd, path, 0, name, buf, 16, 0, 16) != 3)
		return (23);
	/* 24: listxattrat dfd-relative. */
	r = call(SYS_listxattrat, dirfd, (long)path, 0, (long)list, 64, 0);
	if (r < 7 || !has_entry(list, r, name)) return (24);
	/* 25: XATTR_CREATE on an existing attribute is EEXIST. */
	if (setxattrat(dirfd, path, 0, name, val, 3, XATTR_CREATE, 16) != -17)
		return (25);
	/* 26: XATTR_REPLACE on a missing attribute is ENODATA. */
	if (setxattrat(dirfd, path, 0, "user.none", val, 3, XATTR_REPLACE,
	    16) != -61) return (26);
	/* 27/28: removexattrat dfd-relative, then the attribute is gone. */
	if (call(SYS_removexattrat, dirfd, (long)path, 0, (long)name, 0, 0)
	    != 0) return (27);
	if (getxattrat(AT_FDCWD, path, 0, name, buf, 16, 0, 16) != -61)
		return (28);
	/* 29: removing it again is ENODATA. */
	if (call(SYS_removexattrat, AT_FDCWD, (long)path, 0, (long)name, 0, 0)
	    != -61) return (29);
	/* 30-32: symlinks: default follows, AT_SYMLINK_NOFOLLOW does not. */
	if (call(SYS_symlink, (long)path, (long)lnk, 0, 0, 0, 0) != 0)
		return (30);
	if (setxattrat(AT_FDCWD, lnk, 0, name, val, 3, 0, 16) != 0)
		return (31);
	if (getxattrat(AT_FDCWD, path, 0, name, buf, 16, 0, 16) != 3)
		return (32);
	/*
	 * 33/34: NOFOLLOW must not see the target's value.  Whether a
	 * symlink can carry user attributes is filesystem specific (Linux:
	 * ENODATA; FreeBSD: ENODATA or EOPNOTSUPP), so only assert that.
	 */
	r = getxattrat(AT_FDCWD, lnk, AT_SYMLINK_NOFOLLOW, name, buf, 16, 0,
	    16);
	if (r != -61 && r != -95) return (33);
	r = getxattrat(dirfd, lnk, AT_SYMLINK_NOFOLLOW, name, buf, 16, 0, 16);
	if (r != -61 && r != -95) return (34);
	/* 35: dfd-relative with follow sees the target through the link. */
	if (getxattrat(dirfd, lnk, 0, name, buf, 16, 0, 16) != 3) return (35);
	/* 36: unknown namespace is ENOTSUP (95) like the non-at calls. */
	if (setxattrat(AT_FDCWD, path, 0, "bogus.t", val, 3, 0, 16) != -95)
		return (36);

	(void)call(SYS_close, dirfd, 0, 0, 0, 0, 0);
	(void)call(SYS_close, fd, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)lnk, 0, 0, 0, 0, 0);
	(void)call(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
	return (0);
}

/*
 * The process entry stack is 16-byte aligned, one slot off from what a
 * called function expects; realign so vectorised stores do not fault.
 */
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	(void)call(60, test(), 0, 0, 0, 0, 0);
	__builtin_unreachable();
}
