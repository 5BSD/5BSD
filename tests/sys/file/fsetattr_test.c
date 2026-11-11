/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * futimens(2), futimes(2) and fchflags(2) are answered by the descriptor's
 * fileops (fo_setattr).  Descriptors that carry a vnode set their times and
 * flags through it; descriptors with no vnode return EINVAL, as getvnode()
 * did; an O_PATH descriptor returns EBADF from these system calls, as
 * getvnode() did, while utimensat(2) through /dev/fd/N still reaches it.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/linker.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct timespec times[2] = {
	{ .tv_sec = 1000000000, .tv_nsec = 123000000 },
	{ .tv_sec = 1100000000, .tv_nsec = 456000000 },
};

static void
check_times_set(int fd)
{
	struct stat sb;

	ATF_REQUIRE_EQ_MSG(0, futimens(fd, times), "futimens: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(times[0].tv_sec, sb.st_atim.tv_sec);
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
}

/*
 * The /dev/fd/N cases need fdescfs.  The guest may not mount it on /dev/fd,
 * so mount a private instance in the work directory; the cleanup unmounts.
 */
static void
mount_fdesc(const atf_tc_t *tc)
{
	struct iovec iov[4];

	ATF_REQUIRE_EQ(0, mkdir("fdesc", 0755));
	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "fdescfs");
	iov[1].iov_len = sizeof("fdescfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, "fdesc");
	iov[3].iov_len = sizeof("fdesc");
	if (nmount(iov, nitems(iov), 0) != 0)
		atf_tc_fail("mount fdescfs: %s", strerror(errno));
	(void)tc;
}

static void
umount_fdesc(void)
{
	(void)unmount("fdesc", MNT_FORCE);
}


/*
 * The mac_test_hooks policy counts the calls of each hook it implements
 * and, while a hook's deny toggle is set, returns the toggle's value from
 * it.  A toggle acts on every process, so the cases that set one are
 * exclusive, keep it set for one system call, and clear every toggle
 * again in their cleanup.  The cases skip on a kernel whose policy lacks
 * the hook (the pre-project module has none of the vnode setattr hooks).
 */
#define	MAC_HOOKS		"mac_test_hooks"
#define	MAC_HOOKS_LOADED	"mac_test_hooks.loaded"
#define	MAC_HOOKS_SYSCTL	"security.mac.test_hooks"

static const char *const mac_hooks_used[] = {
	"vnode_check_setmode",
	"vnode_check_setowner",
	"vnode_check_setutimes",
};

static void
mac_hooks_require(void)
{
	char name[128];
	size_t len;
	u_int i;
	int fd, v;

	if (kldfind(MAC_HOOKS) == -1) {
		/* The capability plane refuses a module load this late. */
		if (kldload(MAC_HOOKS) == -1)
			atf_tc_skip("%s is not loaded and cannot be loaded "
			    "now (%s); preload it", MAC_HOOKS, strerror(errno));
		/* Loaded here, so the cleanup unloads it. */
		fd = open(MAC_HOOKS_LOADED, O_CREAT | O_WRONLY, 0600);
		ATF_REQUIRE(fd >= 0);
		close(fd);
	}
	for (i = 0; i < nitems(mac_hooks_used); i++) {
		snprintf(name, sizeof(name), "%s.counter.%s",
		    MAC_HOOKS_SYSCTL, mac_hooks_used[i]);
		len = sizeof(v);
		if (sysctlbyname(name, &v, &len, NULL, 0) == 0)
			continue;
		if (errno == ENOENT)
			atf_tc_skip("this kernel's %s has no %s hook",
			    MAC_HOOKS, mac_hooks_used[i]);
		atf_tc_fail("%s: %s", name, strerror(errno));
	}
}

static void
mac_hooks_cleanup(void)
{
	char name[128];
	u_int i;
	int id, v;

	for (i = 0; i < nitems(mac_hooks_used); i++) {
		snprintf(name, sizeof(name), "%s.deny.%s", MAC_HOOKS_SYSCTL,
		    mac_hooks_used[i]);
		v = 0;
		(void)sysctlbyname(name, NULL, NULL, &v, sizeof(v));
	}
	if (access(MAC_HOOKS_LOADED, F_OK) == 0 &&
	    (id = kldfind(MAC_HOOKS)) != -1)
		(void)kldunload(id);
}

static int
mac_hook_count(const char *hook)
{
	char name[128];
	size_t len;
	int v;

	snprintf(name, sizeof(name), "%s.counter.%s", MAC_HOOKS_SYSCTL, hook);
	len = sizeof(v);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &v, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	return (v);
}

static void
mac_hook_deny(const char *hook, int error)
{
	char name[128];

	snprintf(name, sizeof(name), "%s.deny.%s", MAC_HOOKS_SYSCTL, hook);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &error,
	    sizeof(error)), "%s: %s", name, strerror(errno));
}

typedef int setattr_op(int fd);

static int
op_fchmod(int fd)
{
	return (fchmod(fd, 0600));
}

static int
op_fchown(int fd)
{
	return (fchown(fd, 0, 0));
}

/* Neither time is set: both seconds are the kernel's "no value". */
static int
op_futimens_none(int fd)
{
	static const struct timespec none[2] = {
		{ .tv_sec = -1, .tv_nsec = 0 },
		{ .tv_sec = -1, .tv_nsec = 0 },
	};

	return (futimens(fd, none));
}

static int
op_futimes_none(int fd)
{
	static const struct timeval none[2] = {
		{ .tv_sec = -1, .tv_usec = 0 },
		{ .tv_sec = -1, .tv_usec = 0 },
	};

	return (futimes(fd, none));
}

/* The errno of op(fd), 0 for success. */
static int
op_errno(setattr_op *op, int fd)
{
	return (op(fd) == 0 ? 0 : errno);
}

/* The same while the policy's hook denies with EACCES. */
static int
op_errno_denied(const char *hook, setattr_op *op, int fd)
{
	int error;

	mac_hook_deny(hook, EACCES);
	error = op_errno(op, fd);
	mac_hook_deny(hook, 0);
	return (error);
}

/*
 * /dev/ptmx as it was, for the cases that change the node: saved in the
 * work directory before the first change and put back by the cleanup,
 * whatever the body got to.
 */
#define	PTMX_SAVED	"ptmx.saved"

static void
ptmx_save(struct stat *sb)
{
	FILE *f;

	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", sb));
	f = fopen(PTMX_SAVED, "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "%o %ju %ju\n", (u_int)(sb->st_mode & ALLPERMS),
	    (uintmax_t)sb->st_uid, (uintmax_t)sb->st_gid);
	ATF_REQUIRE_EQ(0, fclose(f));
}

static void
ptmx_restore(void)
{
	uintmax_t gid, uid;
	FILE *f;
	u_int mode;

	f = fopen(PTMX_SAVED, "r");
	if (f == NULL)
		return;
	if (fscanf(f, "%o %ju %ju", &mode, &uid, &gid) == 3) {
		(void)chown("/dev/ptmx", uid, gid);
		(void)chmod("/dev/ptmx", mode);
	}
	fclose(f);
}

#define	UID_NOBODY	65534
#define	GID_NOBODY	65534

/*
 * Run fn(res) as an unprivileged user in a child; fn stores the errno of
 * each of its n steps (0 for success).
 */
static void
run_as_nobody(void (*fn)(int *), int *res, size_t n)
{
	gid_t gid;
	pid_t pid;
	ssize_t len;
	int pp[2], st;

	len = n * sizeof(*res);
	ATF_REQUIRE_EQ(0, pipe(pp));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		gid = GID_NOBODY;
		if (setgroups(1, &gid) != 0 || setgid(GID_NOBODY) != 0 ||
		    setuid(UID_NOBODY) != 0)
			_exit(3);
		fn(res);
		_exit(write(pp[1], res, len) == len ? 0 : 4);
	}
	close(pp[1]);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &st, 0));
	ATF_REQUIRE_MSG(WIFEXITED(st) && WEXITSTATUS(st) == 0,
	    "child status %#x", st);
	ATF_REQUIRE_EQ(len, read(pp[0], res, len));
	close(pp[0]);
}

static void
check_errno(int fd, int expected)
{
	errno = 0;
	ATF_CHECK_EQ(-1, futimens(fd, times));
	ATF_CHECK_EQ(expected, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, futimes(fd, NULL));
	ATF_CHECK_EQ(expected, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fchflags(fd, 0));
	ATF_CHECK_EQ(expected, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file_times);
ATF_TC_BODY(regular_file_times, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_times_set(fd);
	/* futimes(NULL) sets the current time, and must move mtime forward. */
	ATF_REQUIRE_EQ(0, futimes(fd, NULL));
	{
		struct stat sb;

		ATF_REQUIRE_EQ(0, fstat(fd, &sb));
		ATF_CHECK(sb.st_mtim.tv_sec > times[1].tv_sec);
	}
	close(fd);
}

/* The birth time follows a modification time set earlier than it. */
ATF_TC_WITHOUT_HEAD(regular_file_birthtime);
ATF_TC_BODY(regular_file_birthtime, tc)
{
	struct stat sb;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	if (sb.st_birthtim.tv_sec == -1)
		atf_tc_skip("filesystem has no birth time");
	ATF_REQUIRE_EQ(0, futimens(fd, times));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_birthtim.tv_sec);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(regular_file_flags);
ATF_TC_BODY(regular_file_flags, tc)
{
	struct stat sb;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	if (fchflags(fd, sb.st_flags | UF_NODUMP) != 0) {
		if (errno == EOPNOTSUPP)
			atf_tc_skip("filesystem has no file flags");
		atf_tc_fail("fchflags: %s", strerror(errno));
	}
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK(sb.st_flags & UF_NODUMP);
	ATF_REQUIRE_EQ(0, fchflags(fd, sb.st_flags & ~UF_NODUMP));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK((sb.st_flags & UF_NODUMP) == 0);
	close(fd);
}

/*
 * The VNOVAL flag value is refused after the descriptor is consulted:
 * EOPNOTSUPP on an open descriptor, EBADF on a closed one.
 */
ATF_TC_WITHOUT_HEAD(flags_vnoval);
ATF_TC_BODY(flags_vnoval, tc)
{
	int fd, fds[2];

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK_EQ(-1, fchflags(fd, (u_long)-1));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	close(fd);
	errno = 0;
	ATF_CHECK_EQ(-1, fchflags(fd, (u_long)-1));
	ATF_CHECK_EQ(EBADF, errno);
	/* A descriptor without a vnode is refused first, as getvnode() did. */
	ATF_REQUIRE_EQ(0, pipe(fds));
	errno = 0;
	ATF_CHECK_EQ(-1, fchflags(fds[0], (u_long)-1));
	ATF_CHECK_EQ(EINVAL, errno);
	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkdir("dir", 0755));
	fd = open("dir", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_times_set(fd);
	close(fd);
}

/* futimens/fchflags refuse O_PATH with EBADF. */
ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EBADF);
	close(fd);
}

/* fdescfs still reaches an O_PATH descriptor's file. */
ATF_TC_WITH_CLEANUP(fdescfs_opath);
ATF_TC_HEAD(fdescfs_opath, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_opath, tc)
{
	struct stat sb;
	char path[32];
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_REQUIRE_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	ATF_REQUIRE_EQ(0, stat("file", &sb));
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_opath, tc)
{
	umount_fdesc();
}

/*
 * Through fdescfs, a descriptor without a vnode (a socket, an anonymous
 * pipe, a posix_openpt(2) master) keeps the answers getvnode() gave it:
 * times and chmod silently dropped, chflags refused.
 */
static void
check_fdesc_dropped(const char *path)
{

	ATF_CHECK_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	errno = 0;
	ATF_CHECK_EQ(-1, chflags(path, UF_NODUMP));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	ATF_CHECK_EQ_MSG(0, chmod(path, 0600), "chmod(%s): %s", path,
	    strerror(errno));
}

ATF_TC_WITH_CLEANUP(fdescfs_no_attributes);
ATF_TC_HEAD(fdescfs_no_attributes, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_no_attributes, tc)
{
	char path[32];
	int fds[2], fd;

	mount_fdesc(tc);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	check_fdesc_dropped(path);
	close(fd);
	ATF_REQUIRE_EQ(0, pipe(fds));
	snprintf(path, sizeof(path), "fdesc/%d", fds[0]);
	check_fdesc_dropped(path);
	close(fds[0]);
	close(fds[1]);
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	check_fdesc_dropped(path);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_no_attributes, tc)
{
	umount_fdesc();
}

/*
 * A shared memory object has fo_truncate, fo_chmod and fo_chown but no
 * fo_setattr; fdescfs keeps getvnode()'s answer for such a type: every
 * change but chflags(2) is silently dropped, the object untouched.
 */
ATF_TC_WITH_CLEANUP(fdescfs_shm);
ATF_TC_HEAD(fdescfs_shm, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_shm, tc)
{
	struct stat sb;
	char path[32];
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_CHECK_EQ_MSG(0, truncate(path, 8192), "truncate(%s): %s", path,
	    strerror(errno));
	ATF_CHECK_EQ_MSG(0, chmod(path, 0640), "chmod(%s): %s", path,
	    strerror(errno));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(0, sb.st_size);
	ATF_CHECK_EQ(0600, sb.st_mode & ALLPERMS);
	ATF_CHECK_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	errno = 0;
	ATF_CHECK_EQ(-1, chflags(path, UF_NODUMP));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_shm, tc)
{
	umount_fdesc();
}

/*
 * A /dev/ptmx master carries the device vnode, so a change made through
 * fdescfs reaches the device node, as it always did: devfs checks the
 * owner and the privilege, takes a mode and an owner, and ignores a size.
 * The owner set is not the node's own, which devfs would take for no
 * change.  The mode and owner set here leave the node usable by everyone
 * meanwhile, and the cleanup puts it back whatever the body got to.
 */
ATF_TC_WITH_CLEANUP(fdescfs_ptmx_direct);
ATF_TC_HEAD(fdescfs_ptmx_direct, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(fdescfs_ptmx_direct, tc)
{
	struct stat before, after;
	char path[32];
	mode_t mode;
	int fd;

	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	ptmx_save(&before);
	ATF_REQUIRE(before.st_uid != UID_NOBODY);
	ATF_REQUIRE(before.st_gid != GID_NOBODY);
	mode = before.st_mode & ALLPERMS;
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_CHECK_EQ_MSG(0, chmod(path, mode ^ S_IXUSR), "chmod(%s): %s",
	    path, strerror(errno));
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &after));
	ATF_CHECK_EQ(mode ^ S_IXUSR, after.st_mode & ALLPERMS);
	ATF_CHECK_EQ_MSG(0, chown(path, UID_NOBODY, GID_NOBODY),
	    "chown(%s): %s", path, strerror(errno));
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &after));
	ATF_CHECK_EQ(UID_NOBODY, after.st_uid);
	ATF_CHECK_EQ(GID_NOBODY, after.st_gid);
	ATF_CHECK_EQ_MSG(0, truncate(path, 0), "truncate(%s): %s", path,
	    strerror(errno));
	ATF_CHECK_EQ_MSG(0, chown(path, before.st_uid, before.st_gid),
	    "chown(%s): %s", path, strerror(errno));
	ATF_CHECK_EQ_MSG(0, chmod(path, mode), "chmod(%s): %s", path,
	    strerror(errno));
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_ptmx_direct, tc)
{
	ptmx_restore();
	umount_fdesc();
}

/*
 * The same master's node through fdescfs as a user who does not own it:
 * devfs refuses the mode and the owner, as it always did.  Flags on a
 * device need the privilege chflags(2) and fchflags(2) ask for, checked
 * before the filesystem is asked (D235); the pre-project fdescfs handed
 * them to devfs unchecked, which takes no flags and refuses any other.
 */
static int nonowner_dfd;

static void
ptmx_nonowner(int *res)
{
	char name[16];
	int fd;

	res[0] = res[1] = res[2] = res[3] = -1;
	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (fd < 0)
		return;
	snprintf(name, sizeof(name), "%d", fd);
	res[0] = fchmodat(nonowner_dfd, name, 0666, 0) == 0 ? 0 : errno;
	res[1] = fchownat(nonowner_dfd, name, UID_NOBODY, GID_NOBODY, 0) == 0 ?
	    0 : errno;
	res[2] = chflagsat(nonowner_dfd, name, 0, 0) == 0 ? 0 : errno;
	res[3] = chflagsat(nonowner_dfd, name, UF_NODUMP, 0) == 0 ? 0 : errno;
}

ATF_TC_WITH_CLEANUP(fdescfs_ptmx_nonowner);
ATF_TC_HEAD(fdescfs_ptmx_nonowner, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(fdescfs_ptmx_nonowner, tc)
{
	struct stat before, after;
	int res[4];
	bool pre1c;

	pre1c = atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false);
	ptmx_save(&before);
	ATF_REQUIRE(before.st_uid != UID_NOBODY);
	mount_fdesc(tc);
	/* The work directory is the test user's alone; look up from here. */
	nonowner_dfd = open("fdesc", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(nonowner_dfd >= 0);
	run_as_nobody(ptmx_nonowner, res, nitems(res));
	ATF_CHECK_EQ_MSG(EPERM, res[0], "chmod: %d", res[0]);
	ATF_CHECK_EQ_MSG(EPERM, res[1], "chown: %d", res[1]);
	ATF_CHECK_EQ_MSG(pre1c ? 0 : EPERM, res[2], "chflags 0: %d", res[2]);
	ATF_CHECK_EQ_MSG(pre1c ? EINVAL : EPERM, res[3], "chflags: %d",
	    res[3]);
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);
	close(nonowner_dfd);
}
ATF_TC_CLEANUP(fdescfs_ptmx_nonowner, tc)
{
	ptmx_restore();
	umount_fdesc();
}

/* A FIFO through fdescfs reaches its vnode. */
ATF_TC_WITH_CLEANUP(fdescfs_fifo);
ATF_TC_HEAD(fdescfs_fifo, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_fifo, tc)
{
	struct stat sb;
	char path[32];
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_REQUIRE_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	ATF_REQUIRE_EQ(0, stat("fifo", &sb));
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_fifo, tc)
{
	umount_fdesc();
}

ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_times_set(fd);
	close(fd);
}

/* Setting attributes through fdescfs on a regular file reaches the file. */
ATF_TC_WITH_CLEANUP(fdescfs_regular_file);
ATF_TC_HEAD(fdescfs_regular_file, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_regular_file, tc)
{
	struct stat sb;
	char path[32];
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_REQUIRE_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
	ATF_REQUIRE_EQ(0, chmod(path, 0600));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(0600, sb.st_mode & ACCESSPERMS);
	ATF_REQUIRE_EQ(0, truncate(path, 7));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(7, sb.st_size);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_regular_file, tc)
{
	umount_fdesc();
}

/* On a descriptor with no settable attributes fdescfs drops changes. */
ATF_TC_WITH_CLEANUP(fdescfs_kqueue);
ATF_TC_HEAD(fdescfs_kqueue, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(fdescfs_kqueue, tc)
{
	char path[32];
	int fd;

	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	ATF_REQUIRE_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	errno = 0;
	ATF_CHECK_EQ(-1, chflags(path, UF_NODUMP));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_kqueue, tc)
{
	umount_fdesc();
}

/*
 * A posix_openpt(2) master has no vnode; a /dev/ptmx-opened one sets the
 * times of the ptmx node (fstat on the master reports the tty, so the
 * oracle is stat on the node).
 */
ATF_TC_WITHOUT_HEAD(pts_master_openpt);
ATF_TC_BODY(pts_master_openpt, tc)
{
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
}

ATF_TC(pts_master_ptmx);
ATF_TC_HEAD(pts_master_ptmx, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(pts_master_ptmx, tc)
{
	struct timespec saved[2];
	struct stat sb;
	int fd;

	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &sb));
	saved[0] = sb.st_atim;
	saved[1] = sb.st_mtim;
	ATF_REQUIRE_EQ_MSG(0, futimens(fd, times), "futimens: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &sb));
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
	/* Leave the node as it was. */
	ATF_CHECK_EQ(0, futimens(fd, saved));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(anonymous_pipe);
ATF_TC_BODY(anonymous_pipe, tc)
{
	int fds[2];

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_errno(fds[0], EINVAL);
	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(socket);
ATF_TC_BODY(socket, tc)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(shm_fd);
ATF_TC_BODY(shm_fd, tc)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	check_errno(fd, EBADF);
}

/*
 * A VOP_SETATTR on /dev/fd/N that names several attributes is checked for
 * all of them before any is set (D235): with the owner refused by a
 * policy the mode is not set, and the other way round.  No system call
 * builds such a request, so an INVARIANTS kernel has a sysctl that issues
 * one on an O_PATH descriptor of the /dev/fd/N node; it makes no check of
 * its own, so the refusal is the target vnode's.
 */
struct fdesc_setattr_test {
	int32_t		fst_fd;
	uint32_t	fst_mode;
	uint32_t	fst_uid;
	uint32_t	fst_gid;
};
#define	FDESC_SETATTR_SYSCTL	"debug.fdescfs_setattr"

static int
fdesc_setattr_both(int pfd, mode_t mode, uid_t uid, gid_t gid)
{
	struct fdesc_setattr_test fst = {
		.fst_fd = pfd,
		.fst_mode = mode,
		.fst_uid = uid,
		.fst_gid = gid,
	};

	return (sysctlbyname(FDESC_SETATTR_SYSCTL, NULL, NULL, &fst,
	    sizeof(fst)) == 0 ? 0 : errno);
}

static int
fdesc_setattr_both_denied(const char *hook, int pfd, mode_t mode, uid_t uid,
    gid_t gid)
{
	int error;

	mac_hook_deny(hook, EACCES);
	error = fdesc_setattr_both(pfd, mode, uid, gid);
	mac_hook_deny(hook, 0);
	return (error);
}

ATF_TC_WITH_CLEANUP(fdesc_setattr_atomic);
ATF_TC_HEAD(fdesc_setattr_atomic, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(fdesc_setattr_atomic, tc)
{
	struct stat before, after;
	char path[32];
	size_t miblen;
	int mib[CTL_MAXNAME];
	int fd, mode_calls, owner_calls, pfd;

	miblen = nitems(mib);
	if (sysctlnametomib(FDESC_SETATTR_SYSCTL, mib, &miblen) != 0)
		atf_tc_skip("no %s: a kernel without INVARIANTS, or the "
		    "pre-project one", FDESC_SETATTR_SYSCTL);
	mac_hooks_require();
	mount_fdesc(tc);

	fd = open("file", O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &before));
	ATF_REQUIRE(before.st_uid != UID_NOBODY);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	pfd = open(path, O_PATH);
	ATF_REQUIRE_MSG(pfd >= 0, "open(%s, O_PATH): %s", path,
	    strerror(errno));

	/* The owner is refused after the mode was allowed. */
	mode_calls = mac_hook_count("vnode_check_setmode");
	owner_calls = mac_hook_count("vnode_check_setowner");
	ATF_CHECK_EQ(EACCES, fdesc_setattr_both_denied("vnode_check_setowner",
	    pfd, 0640, UID_NOBODY, GID_NOBODY));
	ATF_CHECK(mac_hook_count("vnode_check_setmode") > mode_calls);
	ATF_CHECK(mac_hook_count("vnode_check_setowner") > owner_calls);
	ATF_REQUIRE_EQ(0, fstat(fd, &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);

	/* The mode is refused. */
	ATF_CHECK_EQ(EACCES, fdesc_setattr_both_denied("vnode_check_setmode",
	    pfd, 0640, UID_NOBODY, GID_NOBODY));
	ATF_REQUIRE_EQ(0, fstat(fd, &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);

	/* Neither is refused: the one call sets both. */
	ATF_CHECK_EQ(0, fdesc_setattr_both(pfd, 0640, UID_NOBODY,
	    GID_NOBODY));
	ATF_REQUIRE_EQ(0, fstat(fd, &after));
	ATF_CHECK_EQ(0640, after.st_mode & ALLPERMS);
	ATF_CHECK_EQ(UID_NOBODY, after.st_uid);
	ATF_CHECK_EQ(GID_NOBODY, after.st_gid);
	close(pfd);
	close(fd);

	/* The same refusal for a device node, a /dev/ptmx master's. */
	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	ptmx_save(&before);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	pfd = open(path, O_PATH);
	ATF_REQUIRE_MSG(pfd >= 0, "open(%s, O_PATH): %s", path,
	    strerror(errno));
	ATF_CHECK_EQ(EACCES, fdesc_setattr_both_denied("vnode_check_setowner",
	    pfd, (before.st_mode & ALLPERMS) ^ S_IXUSR, UID_NOBODY,
	    GID_NOBODY));
	ATF_REQUIRE_EQ(0, stat("/dev/ptmx", &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);
	ATF_CHECK_EQ(before.st_uid, after.st_uid);
	ATF_CHECK_EQ(before.st_gid, after.st_gid);
	close(pfd);
	close(fd);
}
ATF_TC_CLEANUP(fdesc_setattr_atomic, tc)
{
	mac_hooks_cleanup();
	ptmx_restore();
	umount_fdesc();
}

/*
 * chmod(2) of /dev/fd/N checks the /dev/fd/N vnode in the system call, as
 * it always did, and then the file's own vnode before that is changed
 * (D235); the pre-project kernel made the first check only.
 */
ATF_TC_WITH_CLEANUP(fdescfs_mac_target);
ATF_TC_HEAD(fdescfs_mac_target, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(fdescfs_mac_target, tc)
{
	struct stat sb;
	char path[32];
	int calls, fd, want;

	mac_hooks_require();
	want = atf_tc_get_config_var_as_bool_wd(tc, "pre1c", false) ? 1 : 2;
	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	mount_fdesc(tc);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	calls = mac_hook_count("vnode_check_setmode");
	ATF_REQUIRE_EQ_MSG(0, chmod(path, 0640), "chmod(%s): %s", path,
	    strerror(errno));
	calls = mac_hook_count("vnode_check_setmode") - calls;
	ATF_CHECK_MSG(calls >= want, "%d mode checks, expected %d", calls,
	    want);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(0640, sb.st_mode & ALLPERMS);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_mac_target, tc)
{
	mac_hooks_cleanup();
	umount_fdesc();
}

/*
 * fchmod(2) and fchown(2) check the vnode with the policies before the
 * descriptor's table is asked (D301), so for any descriptor that has a
 * vnode a policy's refusal comes before the table's own answer: EBADF for
 * O_PATH, EINVAL for a /dev/ptmx master.
 */
ATF_TC_WITH_CLEANUP(fchmod_fchown_mac_first);
ATF_TC_HEAD(fchmod_fchown_mac_first, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(fchmod_fchown_mac_first, tc)
{
	struct stat before, after;
	int calls, fd, fds[2], mfd, pfd;

	mac_hooks_require();
	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstat(fd, &before));
	pfd = open("file", O_PATH);
	ATF_REQUIRE(pfd >= 0);
	mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(mfd >= 0);
	ATF_REQUIRE_EQ(0, pipe(fds));

	/* The tables' own answers, each after the vnode was checked. */
	calls = mac_hook_count("vnode_check_setmode");
	ATF_CHECK_EQ(EBADF, op_errno(op_fchmod, pfd));
	ATF_CHECK(mac_hook_count("vnode_check_setmode") > calls);
	calls = mac_hook_count("vnode_check_setowner");
	ATF_CHECK_EQ(EBADF, op_errno(op_fchown, pfd));
	ATF_CHECK(mac_hook_count("vnode_check_setowner") > calls);
	calls = mac_hook_count("vnode_check_setmode");
	ATF_CHECK_EQ(EINVAL, op_errno(op_fchmod, mfd));
	ATF_CHECK(mac_hook_count("vnode_check_setmode") > calls);
	calls = mac_hook_count("vnode_check_setowner");
	ATF_CHECK_EQ(EINVAL, op_errno(op_fchown, mfd));
	ATF_CHECK(mac_hook_count("vnode_check_setowner") > calls);

	/* The policy's refusal comes first. */
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setmode", op_fchmod,
	    pfd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setowner",
	    op_fchown, pfd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setmode", op_fchmod,
	    mfd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setowner",
	    op_fchown, mfd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setmode", op_fchmod,
	    fd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setowner",
	    op_fchown, fd));
	ATF_REQUIRE_EQ(0, fstat(fd, &after));
	ATF_CHECK_EQ(before.st_mode, after.st_mode);

	/* A descriptor without a vnode has none to check. */
	ATF_CHECK_EQ(EINVAL, op_errno_denied("vnode_check_setmode", op_fchmod,
	    fds[0]));
	ATF_CHECK_EQ(EINVAL, op_errno_denied("vnode_check_setowner",
	    op_fchown, fds[0]));
	close(fds[0]);
	close(fds[1]);
	close(mfd);
	close(pfd);
	close(fd);
}
ATF_TC_CLEANUP(fchmod_fchown_mac_first, tc)
{
	mac_hooks_cleanup();
}

/*
 * futimens(2) and futimes(2) given no time to set (both seconds -1, the
 * kernel's "no value") still go to the filesystem, which changes nothing.
 */
ATF_TC_WITHOUT_HEAD(times_none);
ATF_TC_BODY(times_none, tc)
{
	struct stat sb;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, futimens(fd, times));
	ATF_CHECK_EQ(0, op_errno(op_futimens_none, fd));
	ATF_CHECK_EQ(0, op_errno(op_futimes_none, fd));
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_CHECK_EQ(times[0].tv_sec, sb.st_atim.tv_sec);
	ATF_CHECK_EQ(times[1].tv_sec, sb.st_mtim.tv_sec);
	close(fd);
}

/*
 * The filesystem is asked: UFS refuses any attribute change of an
 * immutable file, a request that names no attribute included.
 */
ATF_TC_WITH_CLEANUP(times_none_immutable);
ATF_TC_HEAD(times_none_immutable, tc)
{
}
ATF_TC_BODY(times_none_immutable, tc)
{
	struct statfs sfs;
	struct stat sb;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstatfs(fd, &sfs));
	if (strcmp(sfs.f_fstypename, "ufs") != 0)
		atf_tc_skip("%s is not UFS", sfs.f_fstypename);
	ATF_REQUIRE_EQ(0, fstat(fd, &sb));
	ATF_REQUIRE_EQ(0, fchflags(fd, sb.st_flags | UF_IMMUTABLE));
	ATF_CHECK_EQ(EPERM, op_errno(op_futimens_none, fd));
	ATF_CHECK_EQ(EPERM, op_errno(op_futimes_none, fd));
	ATF_REQUIRE_EQ(0, fchflags(fd, sb.st_flags));
	close(fd);
}
ATF_TC_CLEANUP(times_none_immutable, tc)
{
	(void)chflags("file", 0);
}

/* They are checked by the policies all the same, and can be refused. */
ATF_TC_WITH_CLEANUP(times_none_mac);
ATF_TC_HEAD(times_none_mac, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(times_none_mac, tc)
{
	int calls, fd;

	mac_hooks_require();
	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	calls = mac_hook_count("vnode_check_setutimes");
	ATF_CHECK_EQ(0, op_errno(op_futimens_none, fd));
	ATF_CHECK(mac_hook_count("vnode_check_setutimes") > calls);
	calls = mac_hook_count("vnode_check_setutimes");
	ATF_CHECK_EQ(0, op_errno(op_futimes_none, fd));
	ATF_CHECK(mac_hook_count("vnode_check_setutimes") > calls);
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setutimes",
	    op_futimens_none, fd));
	ATF_CHECK_EQ(EACCES, op_errno_denied("vnode_check_setutimes",
	    op_futimes_none, fd));
	close(fd);
}
ATF_TC_CLEANUP(times_none_mac, tc)
{
	mac_hooks_cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file_times);
	ATF_TP_ADD_TC(tp, regular_file_birthtime);
	ATF_TP_ADD_TC(tp, regular_file_flags);
	ATF_TP_ADD_TC(tp, flags_vnoval);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, fdescfs_opath);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, fdescfs_regular_file);
	ATF_TP_ADD_TC(tp, fdescfs_kqueue);
	ATF_TP_ADD_TC(tp, fdescfs_no_attributes);
	ATF_TP_ADD_TC(tp, fdescfs_shm);
	ATF_TP_ADD_TC(tp, fdescfs_ptmx_direct);
	ATF_TP_ADD_TC(tp, fdescfs_ptmx_nonowner);
	ATF_TP_ADD_TC(tp, fdesc_setattr_atomic);
	ATF_TP_ADD_TC(tp, fdescfs_mac_target);
	ATF_TP_ADD_TC(tp, fchmod_fchown_mac_first);
	ATF_TP_ADD_TC(tp, times_none);
	ATF_TP_ADD_TC(tp, times_none_immutable);
	ATF_TP_ADD_TC(tp, times_none_mac);
	ATF_TP_ADD_TC(tp, fdescfs_fifo);
	ATF_TP_ADD_TC(tp, pts_master_openpt);
	ATF_TP_ADD_TC(tp, pts_master_ptmx);
	ATF_TP_ADD_TC(tp, anonymous_pipe);
	ATF_TP_ADD_TC(tp, socket);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
