/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux/AArch64 checks for recently shared syscall paths. */
#define SYS_io_setup 0
#define SYS_io_destroy 1
#define SYS_quotactl_fd 443
#define SYS_remap_file_pages 234
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define STATX_MNT_ID 0x1000
#include "linux_test.h"

struct statx_ts { long sec; int nsec, pad; };
struct statx {
	u32 mask, blksize;
	u64 attributes;
	u32 nlink, uid, gid;
	u16 mode, pad0;
	u64 ino, size, blocks, attributes_mask;
	struct statx_ts atime, btime, ctime, mtime;
	u32 rdev_major, rdev_minor, dev_major, dev_minor;
	u64 mnt_id, spare[13];
};

static int
test(int argc, char **argv, char **envp)
{
	struct statx sx;
	u64 ctx;
	char name[16];

	(void)argc;
	(void)argv;
	(void)envp;
	if (sys2(SYS_prctl, PR_SET_NAME, "arm64-parity") != 0)
		return (1);
	xmemset(name, 0, sizeof(name));
	if (sys2(SYS_prctl, PR_GET_NAME, name) != 0 ||
	    !xstreq(name, "arm64-parity"))
		return (2);
	ctx = 0;
	if (sys2(SYS_io_setup, 0, &ctx) != -EINVAL)
		return (3);
	if (sys2(SYS_io_setup, 1, &ctx) != 0 || ctx == 0)
		return (4);
	if (sys1(SYS_io_destroy, ctx) != 0)
		return (5);
	if (sys4(SYS_quotactl_fd, -1, 0, 0, 0) != -EBADF)
		return (6);
	if (sys5(SYS_remap_file_pages, 0, 4096, 1, 0, 0) != -EINVAL)
		return (7);
	xmemset(&sx, 0, sizeof(sx));
	if (sys5(SYS_statx, -100, ".", 0, STATX_MNT_ID, &sx) != 0 ||
	    (sx.mask & STATX_MNT_ID) == 0 || sx.mnt_id == 0)
		return (8);
	return (0);
}
