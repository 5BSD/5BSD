/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * mount(2)/umount2(2) flag handling (root): MS_BIND as a nullfs mount,
 * MS_MGC_VAL masking, the accepted no-op flags, propagation-only calls,
 * MS_MOVE/MS_MANDLOCK rejection, MS_RDONLY|MS_REMOUNT round trip, and
 * umount2 MNT_FORCE / MNT_DETACH / MNT_EXPIRE / UMOUNT_NOFOLLOW.  Exit
 * status = failed check number.
 */
#include "linux_test.h"

#define	MS_RDONLY	1
#define	MS_NOSUID	2
#define	MS_NODEV	4
#define	MS_NOEXEC	8
#define	MS_SYNCHRONOUS	16
#define	MS_REMOUNT	32
#define	MS_MANDLOCK	64
#define	MS_NOATIME	1024
#define	MS_NODIRATIME	2048
#define	MS_BIND		4096
#define	MS_MOVE		8192
#define	MS_REC		16384
#define	MS_SILENT	32768
#define	MS_PRIVATE	(1 << 18)
#define	MS_SLAVE	(1 << 19)
#define	MS_SHARED	(1 << 20)
#define	MS_RELATIME	(1 << 21)
#define	MS_STRICTATIME	(1 << 24)
#define	MS_LAZYTIME	(1 << 25)
#define	MS_MGC_VAL	0xC0ED0000
#define	MNT_FORCE	1
#define	MNT_DETACH	2
#define	MNT_EXPIRE	4
#define	UMOUNT_NOFOLLOW	8

static long
mount(const char *src, const char *tgt, const char *type, long flags,
    const char *data)
{

	return (sys5(SYS_mount, src, tgt, type, flags, data));
}

static int
exists(const char *path)
{
	struct stat st;

	return (sys4(SYS_newfstatat, AT_FDCWD, path, &st, 0) == 0);
}

static int
test(int argc, char **argv, char **envp)
{
	long fd, r;

	(void)argc; (void)argv; (void)envp;

	(void)sys1(SYS_rmdir, "mnt_src");
	(void)sys1(SYS_rmdir, "mnt_tgt");
	(void)sys1(SYS_unlink, "mnt_lnk");
	if (sys2(SYS_mkdir, "mnt_src", 0755) != 0) return (1);
	if (sys2(SYS_mkdir, "mnt_tgt", 0755) != 0) return (1);
	fd = sys3(SYS_open, "mnt_src/marker", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) return (1);
	(void)sys1(SYS_close, fd);

	/* 2-3: MS_BIND makes the source visible at the target (nullfs). */
	if (mount("mnt_src", "mnt_tgt", "ignored", MS_BIND, 0) != 0) return (2);
	if (!exists("mnt_tgt/marker")) return (3);
	/* 4: umount2 with an unknown flag is EINVAL and unmounts nothing. */
	if (sys2(SYS_umount2, "mnt_tgt", 0x100) != -EINVAL) return (4);
	if (!exists("mnt_tgt/marker")) return (4);
	/* 5-6: MNT_DETACH and MNT_EXPIRE are refused (no lazy unmount). */
	if (sys2(SYS_umount2, "mnt_tgt", MNT_DETACH) != -EINVAL) return (5);
	if (sys2(SYS_umount2, "mnt_tgt", MNT_EXPIRE) != -EINVAL) return (6);
	if (!exists("mnt_tgt/marker")) return (6);
	/* 7: UMOUNT_NOFOLLOW on a symlink to the mount point is EINVAL. */
	if (sys2(SYS_symlink, "mnt_tgt", "mnt_lnk") != 0) return (7);
	if (sys2(SYS_umount2, "mnt_lnk", UMOUNT_NOFOLLOW) != -EINVAL) return (7);
	if (!exists("mnt_tgt/marker")) return (7);
	/* 8: ...and works on the real path. */
	if (sys2(SYS_umount2, "mnt_tgt", UMOUNT_NOFOLLOW) != 0) return (8);
	if (exists("mnt_tgt/marker")) return (8);
	/* 9: the historical magic number is masked off. */
	if (mount("mnt_src", "mnt_tgt", "none", MS_MGC_VAL | MS_BIND, 0) != 0)
		return (9);
	if (!exists("mnt_tgt/marker")) return (9);
	/* 10: MNT_FORCE unmounts. */
	if (sys2(SYS_umount2, "mnt_tgt", MNT_FORCE) != 0) return (10);
	/* 11: bind with the no-op flags and NOATIME/NOSUID/NOEXEC/RDONLY. */
	if (mount("mnt_src", "mnt_tgt", "none", MS_BIND | MS_NODEV |
	    MS_NODIRATIME | MS_RELATIME | MS_SILENT | MS_NOATIME | MS_NOSUID |
	    MS_NOEXEC | MS_RDONLY, 0) != 0) return (11);
	/* 12: it really is read-only. */
	if (sys3(SYS_open, "mnt_tgt/new", O_WRONLY | O_CREAT, 0644) != -EROFS)
		return (12);
	/*
	 * 13: MS_REMOUNT|MS_BIND to read-write.  nullfs cannot change the
	 * flags of a live mount (mount -u is EOPNOTSUPP there), so either
	 * the remount works and a create succeeds, or it is EOPNOTSUPP and
	 * the mount is left as it was (still read-only).
	 */
	r = mount("mnt_src", "mnt_tgt", "none", MS_REMOUNT | MS_BIND, 0);
	if (r == 0) {
		fd = sys3(SYS_open, "mnt_tgt/new", O_WRONLY | O_CREAT, 0644);
		if (fd < 0) return (13);
		(void)sys1(SYS_close, fd);
		if (!exists("mnt_src/new")) return (13);
		(void)sys1(SYS_unlink, "mnt_src/new");
	} else if (r == -EOPNOTSUPP) {
		msg("note: nullfs bind mounts cannot be remounted (EOPNOTSUPP)\n");
		if (sys3(SYS_open, "mnt_tgt/new", O_WRONLY | O_CREAT, 0644) !=
		    -EROFS) return (13);
	} else
		return (13);
	/* 14: the mount point of a symlink target is followed without NOFOLLOW. */
	if (sys2(SYS_umount2, "mnt_lnk", 0) != 0) return (14);
	if (exists("mnt_tgt/marker")) return (14);
	/* 15-17: propagation-only calls succeed (no namespaces to propagate). */
	if (mount(0, "mnt_tgt", 0, MS_PRIVATE, 0) != 0) return (15);
	if (mount(0, "/", 0, MS_REC | MS_PRIVATE, 0) != 0) return (16);
	if (mount(0, "mnt_tgt", 0, MS_SHARED | MS_SILENT, 0) != 0) return (16);
	/* two propagation types at once, or with other flags: EINVAL */
	if (mount(0, "mnt_tgt", 0, MS_PRIVATE | MS_SHARED, 0) != -EINVAL)
		return (17);
	if (mount(0, "mnt_tgt", 0, MS_PRIVATE | MS_RDONLY, 0) != -EINVAL)
		return (17);
	/* 18: MS_MOVE is EINVAL, MS_MANDLOCK is EPERM. */
	if (mount("mnt_src", "mnt_tgt", 0, MS_MOVE, 0) != -EINVAL) return (18);
	if (mount("mnt_src", "mnt_tgt", "none", MS_BIND | MS_MANDLOCK, 0) !=
	    -EPERM) return (18);
	/* 19: STRICTATIME/LAZYTIME/SYNCHRONOUS are accepted on a bind. */
	if (mount("mnt_src", "mnt_tgt", "none", MS_BIND | MS_STRICTATIME |
	    MS_LAZYTIME | MS_SYNCHRONOUS, 0) != 0) return (19);
	if (sys2(SYS_umount2, "mnt_tgt", 0) != 0) return (19);
	/* 20: umount2 of a non-mount-point is EINVAL. */
	if (sys2(SYS_umount2, "mnt_src", 0) != -EINVAL) return (20);
	/* 21: a bad type string is EFAULT-free: NULL type without BIND ENODEV. */
	if (mount("mnt_src", "mnt_tgt", "nosuchfs", 0, 0) != -ENODEV) return (21);

	(void)sys1(SYS_unlink, "mnt_lnk");
	(void)sys1(SYS_unlink, "mnt_src/marker");
	(void)sys1(SYS_rmdir, "mnt_src");
	(void)sys1(SYS_rmdir, "mnt_tgt");
	return (0);
}
