/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * statx(2)/newfstatat(2) additions: AT_STATX_* sync hints accepted,
 * STATX_MNT_ID reported when asked for, STATX_ATTR_IMMUTABLE/APPEND/NODUMP
 * from the file flags (via FS_IOC_SETFLAGS), the reserved mask bit, and
 * the FS_IOC_GETFLAGS/SETFLAGS, FIGETBSZ, FIOQSIZE, RNDGETENTCNT ioctls.
 * Exit status = failed check number.
 */
#include "linux_test.h"

#define	AT_SYMLINK_NOFOLLOW	0x100
#define	AT_EMPTY_PATH		0x1000
#define	AT_STATX_FORCE_SYNC	0x2000
#define	AT_STATX_DONT_SYNC	0x4000
#define	STATX_BASIC_STATS	0x7ff
#define	STATX_BTIME		0x800
#define	STATX_MNT_ID		0x1000
#define	STATX_MNT_ID_UNIQUE	0x4000
#define	STATX__RESERVED		0x80000000U
#define	STATX_ATTR_IMMUTABLE	0x10
#define	STATX_ATTR_APPEND	0x20
#define	STATX_ATTR_NODUMP	0x40
#define	FS_IOC_GETFLAGS		0x80086601
#define	FS_IOC_SETFLAGS		0x40086602
#define	FS_IMMUTABLE_FL		0x10
#define	FS_APPEND_FL		0x20
#define	FS_NODUMP_FL		0x40
#define	FS_SYNC_FL		0x08
#define	FIGETBSZ		0x2
#define	FIOQSIZE		0x5460
#define	RNDGETENTCNT		0x80045200

struct statx_ts { long tv_sec; int tv_nsec; int pad; };
struct statx {
	u32 stx_mask, stx_blksize;
	u64 stx_attributes;
	u32 stx_nlink, stx_uid, stx_gid;
	u16 stx_mode, pad0;
	u64 stx_ino, stx_size, stx_blocks, stx_attributes_mask;
	struct statx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
	u32 stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
	u64 stx_mnt_id;
	u64 spare[13];
};

static long
statx(long dfd, const char *path, long flags, long mask, struct statx *sx)
{

	return (sys5(SYS_statx, dfd, path, flags, mask, sx));
}

static int
test(int argc, char **argv, char **envp)
{
	struct statx sx, sx2;
	struct stat st;
	long fd, rfd, fl, v;
	int pfd[2];
	int iv;

	(void)argc; (void)argv; (void)envp;

	fd = tmpfile_fd("statx2.tmp");
	if (fd < 0) return (1);
	if (sys3(SYS_write, fd, "0123456789", 10) != 10) return (1);

	/* 2: the sync hints are accepted. */
	if (statx(AT_FDCWD, "statx2.tmp", AT_STATX_FORCE_SYNC, STATX_BASIC_STATS,
	    &sx) != 0) return (2);
	if (statx(AT_FDCWD, "statx2.tmp", AT_STATX_DONT_SYNC, STATX_BASIC_STATS,
	    &sx) != 0) return (2);
	/* 3: both sync bits together are EINVAL on Linux. */
	if (statx(AT_FDCWD, "statx2.tmp", AT_STATX_FORCE_SYNC |
	    AT_STATX_DONT_SYNC, STATX_BASIC_STATS, &sx) != -EINVAL) return (3);
	/* 4: the reserved mask bit is EINVAL; unknown mask bits are ignored. */
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX__RESERVED, &sx) != -EINVAL)
		return (4);
	if (statx(AT_FDCWD, "statx2.tmp", 0, 1u << 20, &sx) != 0) return (4);
	/* 5: without STATX_MNT_ID in the mask the bit is not reported. */
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX_BASIC_STATS, &sx) != 0)
		return (5);
	if ((sx.stx_mask & STATX_MNT_ID) != 0) return (5);
	/* 6: with it, a mount id is reported, equal for two files on the fs. */
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX_BASIC_STATS | STATX_MNT_ID,
	    &sx) != 0) return (6);
	if ((sx.stx_mask & STATX_MNT_ID) == 0) return (6);
	if (statx(AT_FDCWD, ".", 0, STATX_MNT_ID, &sx2) != 0) return (6);
	if ((sx2.stx_mask & STATX_MNT_ID) == 0 || sx2.stx_mnt_id != sx.stx_mnt_id)
		return (6);
	/* 7: ...and different from the root's when / is another fs. */
	if (statx(AT_FDCWD, "/dev", 0, STATX_MNT_ID, &sx2) != 0) return (7);
	if ((sx2.stx_mask & STATX_MNT_ID) == 0 || sx2.stx_mnt_id == sx.stx_mnt_id)
		return (7);
	/* 8: MNT_ID_UNIQUE is not provided (bit absent), no error. */
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX_MNT_ID_UNIQUE, &sx) != 0)
		return (8);
	if ((sx.stx_mask & STATX_MNT_ID_UNIQUE) != 0) return (8);
	/* 9: basic stats and btime are always there. */
	if ((sx.stx_mask & (STATX_BASIC_STATS | STATX_BTIME)) !=
	    (STATX_BASIC_STATS | STATX_BTIME)) return (9);
	if (sx.stx_size != 10) return (9);
	/* 10: the attributes mask advertises the three mapped bits. */
	if ((sx.stx_attributes_mask & (STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND |
	    STATX_ATTR_NODUMP)) != (STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND |
	    STATX_ATTR_NODUMP)) return (10);
	if (sx.stx_attributes != 0) return (10);

	/* 11: FS_IOC_GETFLAGS starts empty. */
	fl = -1;
	if (sys3(SYS_ioctl, fd, FS_IOC_GETFLAGS, &fl) != 0) return (11);
	if (fl != 0) return (11);
	/* 12-13: FS_IOC_SETFLAGS NODUMP|APPEND, visible via GETFLAGS and statx. */
	fl = FS_NODUMP_FL | FS_APPEND_FL;
	if (sys3(SYS_ioctl, fd, FS_IOC_SETFLAGS, &fl) != 0) return (12);
	fl = 0;
	if (sys3(SYS_ioctl, fd, FS_IOC_GETFLAGS, &fl) != 0) return (12);
	if (fl != (FS_NODUMP_FL | FS_APPEND_FL)) return (12);
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX_BASIC_STATS, &sx) != 0)
		return (13);
	if (sx.stx_attributes != (STATX_ATTR_NODUMP | STATX_ATTR_APPEND))
		return (13);
	/* 14: append-only really is append-only: pwrite at 0 fails. */
	if (sys4(SYS_pwrite64, fd, "x", 1, 0) != -EPERM) return (14);
	/* 15: immutable, then a write is EPERM and unlink is EPERM. */
	fl = FS_IMMUTABLE_FL;
	if (sys3(SYS_ioctl, fd, FS_IOC_SETFLAGS, &fl) != 0) return (15);
	if (statx(AT_FDCWD, "statx2.tmp", 0, 0, &sx) != 0) return (15);
	if (sx.stx_attributes != STATX_ATTR_IMMUTABLE) return (15);
	/* a new writable open is refused; an fd opened earlier is fs-specific */
	if (sys3(SYS_open, "statx2.tmp", O_WRONLY, 0) != -EPERM) return (15);
	if (sys1(SYS_unlink, "statx2.tmp") != -EPERM) return (15);
	/* 16: clearing all flags restores normal behaviour. */
	fl = 0;
	if (sys3(SYS_ioctl, fd, FS_IOC_SETFLAGS, &fl) != 0) return (16);
	(void)sys3(SYS_lseek, fd, 0, 2);
	if (sys3(SYS_write, fd, "x", 1) != 1) return (16);
	/* 17: a flag with no chflags equivalent is EOPNOTSUPP. */
	fl = FS_SYNC_FL;
	if (sys3(SYS_ioctl, fd, FS_IOC_SETFLAGS, &fl) != -EOPNOTSUPP) return (17);
	/* 18: a bad pointer is EFAULT. */
	if (sys3(SYS_ioctl, fd, FS_IOC_SETFLAGS, 0) != -EFAULT) return (18);
	if (sys3(SYS_ioctl, fd, FS_IOC_GETFLAGS, 0) != -EFAULT) return (18);
	/* 19: GETFLAGS/SETFLAGS on a pipe is ENOTTY. */
	if (sys2(SYS_pipe2, pfd, 0) != 0) return (19);
	fl = 0;
	if (sys3(SYS_ioctl, pfd[0], FS_IOC_SETFLAGS, &fl) != -ENOTTY) return (19);

	/* 20: FIGETBSZ reports st_blksize. */
	if (sys2(SYS_fstat, fd, &st) != 0) return (20);
	iv = 0;
	if (sys3(SYS_ioctl, fd, FIGETBSZ, &iv) != 0) return (20);
	if (iv != st.st_blksize) return (20);
	/* 21-23: FIOQSIZE is the size for regular files and directories... */
	v = -1;
	if (sys3(SYS_ioctl, fd, FIOQSIZE, &v) != 0) return (21);
	if (v != 11) return (21);
	rfd = sys3(SYS_open, ".", O_RDONLY | O_DIRECTORY, 0);
	if (rfd < 0) return (22);
	if (sys3(SYS_ioctl, rfd, FIOQSIZE, &v) != 0) return (22);
	(void)sys1(SYS_close, rfd);
	/* ...and ENOTTY on a pipe. */
	if (sys3(SYS_ioctl, pfd[0], FIOQSIZE, &v) != -ENOTTY) return (23);
	(void)sys1(SYS_close, pfd[0]);
	(void)sys1(SYS_close, pfd[1]);
	/* 24: RNDGETENTCNT on /dev/random reports a positive count. */
	rfd = sys3(SYS_open, "/dev/random", O_RDONLY, 0);
	if (rfd < 0) return (24);
	iv = 0;
	if (sys3(SYS_ioctl, rfd, RNDGETENTCNT, &iv) != 0) return (24);
	if (iv <= 0) return (24);
	(void)sys1(SYS_close, rfd);
	/* 25: AT_EMPTY_PATH statx on the descriptor. */
	if (statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx) != 0) return (25);
	if (sx.stx_size != 11) return (25);
	/* 26: a bad statx buffer is EFAULT. */
	if (statx(AT_FDCWD, "statx2.tmp", 0, STATX_BASIC_STATS, 0) != -EFAULT)
		return (26);

	(void)sys1(SYS_close, fd);
	(void)sys1(SYS_unlink, "statx2.tmp");
	return (0);
}
