/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable root guest only; cwd must be a dedicated quota-enabled filesystem. */
#include "linux_test.h"
#define SYS_quotactl 179
#define SYS_quotactl_fd 443
#define SYS_fchown 93
#define SYS_setuid 105
#define SYS_setgid 106
#define SYS_setgroups 116
#define Q_SYNC 0x800001U
#define Q_GETQUOTA 0x800007U
#define Q_SETQUOTA 0x800008U
#define QCMD(cmd, type) (((cmd) << 8) | (type))
#define TEST_ID 60001
#define EDQUOT 122
#define EOVERFLOW 75
#define EOPNOTSUPP 95
#define F_DUPFD_CLOEXEC 1030
struct dqblk {
	unsigned long bhard, bsoft, bytes, ihard, isoft, inodes, btime, itime;
	unsigned int valid, pad;
};
_Static_assert(sizeof(struct dqblk) == 72, "Linux64 quota layout");
static long dirfd;
static long quota(int cmd, int type, unsigned int id, struct dqblk *dq)
{
	return (sys4(SYS_quotactl_fd, dirfd, QCMD(cmd, type), id, dq));
}
static long setlimit(int type, unsigned long limit)
{
	struct dqblk dq = { .bhard = limit, .valid = 1 };
	return (quota(Q_SETQUOTA, type, TEST_ID, &dq));
}
static int roundtrip(void)
{
	struct dqblk dq;
	int type;
	for (type = 0; type < 2; type++) {
		if (setlimit(type, 8192 + type) != 0)
			return (1);
		if (quota(Q_GETQUOTA, type, TEST_ID, &dq) != 0 ||
		    dq.bhard != 8192UL + type || dq.bsoft != 0 ||
		    dq.btime != 0 || dq.valid != 63 || dq.pad != 0)
			return (2);
		if (setlimit(type, 0) != 0 ||
		    quota(Q_GETQUOTA, type, TEST_ID, &dq) != 0 || dq.bhard != 0)
			return (3);
	}
	return (0);
}
static int badargs(void)
{
	struct dqblk dq;
	if (sys4(SYS_quotactl_fd, -1, QCMD(Q_GETQUOTA, 255), 0, 0) != -EBADF)
		return (1);
	if (quota(Q_GETQUOTA, 255, 0, &dq) != -EINVAL)
		return (2);
	if (quota(Q_GETQUOTA, 0, (unsigned int)-1, &dq) != -EINVAL)
		return (3);
	if (quota(Q_GETQUOTA, 0, TEST_ID, 0) != -EFAULT ||
	    quota(Q_SETQUOTA, 0, TEST_ID, 0) != -EFAULT)
		return (4);
	return (0);
}
static int paths(void)
{
	struct dqblk dq;
	if (sys4(SYS_quotactl, QCMD(Q_GETQUOTA, 0), ".", 0, &dq) != -15)
		return (1);
	if (sys4(SYS_quotactl, QCMD(Q_GETQUOTA, 0), "/quota-no-such", 0, &dq) != -ENOENT)
		return (2);
	if (sys4(SYS_quotactl, QCMD(Q_GETQUOTA, 0), 0, 0, &dq) != -ENODEV)
		return (3);
	if (sys4(SYS_quotactl, QCMD(Q_GETQUOTA, 255), (void *)1, 0, &dq) != -EINVAL)
		return (4);
	return (0);
}
static int sync_quota(void)
{
	if (quota(Q_SYNC, 0, 0, 0) != 0 || quota(Q_SYNC, 1, 0, 0) != 0)
		return (1);
	return (sys4(SYS_quotactl, QCMD(Q_SYNC, 0), 0, 0, 0) == 0 ? 0 : 2);
}
static int permissions_child(void *unused)
{
	struct dqblk dq = { .bhard = 123, .valid = 1 };
	(void)unused;
	if (sys2(SYS_setgroups, 0, 0) != 0 || sys1(SYS_setgid, TEST_ID) != 0 ||
	    sys1(SYS_setuid, TEST_ID) != 0)
		return (1);
	if (quota(Q_GETQUOTA, 0, TEST_ID, &dq) != 0 ||
	    quota(Q_GETQUOTA, 1, TEST_ID, &dq) != 0)
		return (2);
	if (quota(Q_GETQUOTA, 0, TEST_ID + 1, 0) != -EPERM ||
	    quota(Q_GETQUOTA, 1, TEST_ID + 1, 0) != -EPERM ||
	    quota(Q_SETQUOTA, 0, TEST_ID, 0) != -EPERM)
		return (3);
	return (0);
}
static int permissions(void) { return (run_child(permissions_child, 0)); }
static int ignored_fields(void)
{
	struct dqblk dq = { .bhard = 1024, .bsoft = ~0UL, .valid = 0 };
	if (setlimit(0, 8192) != 0 || quota(Q_SETQUOTA, 0, TEST_ID, &dq) != 0 ||
	    quota(Q_GETQUOTA, 0, TEST_ID, &dq) != 0 || dq.bhard != 8192)
		return (1);
	return (setlimit(0, 0) == 0 ? 0 : 2);
}
static int descriptors(void)
{
	struct dqblk dq;
	long fd, saved = dirfd;
	fd = sys4(SYS_openat, dirfd, ".", O_PATH | O_DIRECTORY, 0);
	if (fd < 0)
		return (1);
	dirfd = fd;
	if (quota(Q_GETQUOTA, 0, TEST_ID, &dq) != 0)
		return (2);
	dirfd = sys1(SYS_dup, fd);
	(void)sys1(SYS_close, fd);
	if (dirfd < 0 || quota(Q_GETQUOTA, 0, TEST_ID, &dq) != 0)
		return (3);
	(void)sys1(SYS_close, dirfd);
	dirfd = saved;
	return (0);
}
static const char *self_path;
static int exec_child(void *unused)
{
	char *args[] = { (char *)self_path, "exec_fd_check", 0 };
	char *env[] = { 0 };
	(void)unused;
	if (sys2(SYS_dup2, dirfd, 77) != 77 || sys1(SYS_chdir, "/") != 0)
		return (1);
	(void)sys3(SYS_execve, self_path, args, env);
	return (2);
}
static int exec_lifetime(void)
{
	int rc;
	if (setlimit(0, 8193) != 0)
		return (1);
	rc = run_child(exec_child, 0);
	if (setlimit(0, 0) != 0)
		return (3);
	return (rc);
}
static unsigned char data[16384];
static int writer(void *unused)
{
	long fd, n;
	unsigned int seed = 1;
	int i;
	int type = (int)(long)unused;
	fd = sys4(SYS_openat, dirfd, "quota-data", O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0 || sys3(SYS_fchown, fd, TEST_ID, TEST_ID) != 0 ||
	    sys1(SYS_setgid, TEST_ID) != 0 || sys1(SYS_setuid, TEST_ID) != 0)
		return (1);
	for (i = 0; i < (int)sizeof(data); i++) {
		seed = seed * 1664525 + 1013904223;
		data[i] = seed >> 24;
	}
	for (i = 0; i < 128; i++) {
		n = sys3(SYS_write, fd, data, sizeof(data));
		if (n == -EDQUOT)
			return (0);
		if (n < 0)
			return (2);
		n = sys1(SYS_fsync, fd);
		if (n == -EDQUOT)
			return (0);
		if (n != 0 || quota(Q_SYNC, type, 0, 0) != 0)
			return (3);
	}
	return (4);
}
static int enforce_type(int type)
{
	struct dqblk dq;
	int rc;
	if (quota(Q_SYNC, type, 0, 0) != 0 || setlimit(type, 64) != 0)
		return (1);
	rc = run_child(writer, (void *)(long)type);
	if (quota(Q_SYNC, type, 0, 0) != 0 ||
	    quota(Q_GETQUOTA, type, TEST_ID, &dq) != 0 || dq.bytes == 0 || dq.inodes == 0)
		rc = 5;
	(void)sys3(SYS_unlinkat, dirfd, "quota-data", 0);
	if (setlimit(type, 0) != 0 || quota(Q_SYNC, type, 0, 0) != 0)
		rc = 6;
	return (rc);
}
static int enforcement(void) { return (enforce_type(0)); }
static int group_enforcement(void) { return (enforce_type(1)); }
#ifdef QUOTA_BSD_SUBSET
static int unsupported(void)
{
	struct dqblk dq = { .bhard = 512, .bsoft = 256, .valid = 1 };
	if (setlimit(0, 8192) != 0)
		return (1);
	if (quota(Q_SETQUOTA, 0, TEST_ID, &dq) != -EOPNOTSUPP)
		return (2);
	dq.bsoft = 0;
	dq.valid = 4;
	if (quota(Q_SETQUOTA, 0, TEST_ID, &dq) != -EOPNOTSUPP)
		return (3);
	dq.valid = 1;
	dq.bhard = 1UL << 54;
	if (quota(Q_SETQUOTA, 0, TEST_ID, &dq) != -EOVERFLOW)
		return (4);
	if (quota(Q_GETQUOTA, 0, TEST_ID, &dq) != 0 || dq.bhard != 8192)
		return (5);
	return (setlimit(0, 0) == 0 ? 0 : 6);
}
#endif
static int test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "hard_limit_roundtrip", roundtrip },
		{ "invalid_arguments", badargs },
		{ "device_path_validation", paths },
		{ "quota_sync", sync_quota },
		{ "permissions", permissions },
		{ "ignored_fields", ignored_fields },
		{ "descriptor_lifetime", descriptors },
		{ "fork_exec_lifetime", exec_lifetime },
		{ "enforcement_and_usage", enforcement },
		{ "group_enforcement_and_usage", group_enforcement },
#ifdef QUOTA_BSD_SUBSET
		{ "unsupported_updates_are_atomic", unsupported },
#endif
	};
	(void)envp;
	self_path = argv[0];
	dirfd = sys4(SYS_openat, AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, 0);
	if (dirfd < 0)
		return (99);
	if (argc == 2 && xstreq(argv[1], "readonly")) {
		struct dqblk dq;
		return (quota(Q_GETQUOTA, 0, TEST_ID, &dq) == -EROFS &&
		    setlimit(0, 123) == -EROFS ? 0 : 95);
	}
	if (argc == 2 && xstreq(argv[1], "unsupported_fs")) {
		struct dqblk dq;
		return (quota(Q_GETQUOTA, 0, TEST_ID, &dq) == -ENOSYS ? 0 : 94);
	}
	if (argc == 2 && xstreq(argv[1], "exec_fd_check"))
		dirfd = 77;
	if (argc == 2 && (xstreq(argv[1], "native_set_check") ||
	    xstreq(argv[1], "exec_fd_check"))) {
		struct dqblk dq;
		return (quota(Q_GETQUOTA, 0, TEST_ID, &dq) == 0 &&
		    dq.bhard == 8193 ? 0 : 98);
	}
	if (argc == 2 && xstreq(argv[1], "native_get_prepare"))
		return (setlimit(0, 8193) == 0 ? 0 : 97);
	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}
