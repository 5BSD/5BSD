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
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
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
 * The VNOVAL flag value is refused after the descriptor is consulted, as
 * it always was: EOPNOTSUPP on a file, EINVAL on a type with no
 * attributes, EBADF on a closed descriptor.
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
 * Through fdescfs, a descriptor whose fileops have no attributes keeps the
 * old answers: times silently dropped, chflags refused, chmod applied by
 * the type that has one (a pipe) and dropped otherwise.
 */
static void
check_fdesc_dropped(const char *path, bool chmod_applies, int fd)
{
	struct stat sb;

	ATF_CHECK_EQ_MSG(0, utimensat(AT_FDCWD, path, times, 0),
	    "utimensat(%s): %s", path, strerror(errno));
	errno = 0;
	ATF_CHECK_EQ(-1, chflags(path, UF_NODUMP));
	ATF_CHECK_EQ(EOPNOTSUPP, errno);
	ATF_CHECK_EQ_MSG(0, chmod(path, 0600), "chmod(%s): %s", path,
	    strerror(errno));
	if (chmod_applies) {
		ATF_REQUIRE_EQ(0, fstat(fd, &sb));
		ATF_CHECK_EQ(0600, sb.st_mode & ACCESSPERMS);
	}
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
	/* A pipe has a chmod, but its fstat does not report the mode. */
	ATF_REQUIRE_EQ(0, pipe(fds));
	snprintf(path, sizeof(path), "fdesc/%d", fds[0]);
	check_fdesc_dropped(path, false, fds[0]);
	close(fds[0]);
	close(fds[1]);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	check_fdesc_dropped(path, false, fd);
	close(fd);
	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	snprintf(path, sizeof(path), "fdesc/%d", fd);
	check_fdesc_dropped(path, false, fd);
	close(fd);
}
ATF_TC_CLEANUP(fdescfs_no_attributes, tc)
{
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
	ATF_TP_ADD_TC(tp, fdescfs_fifo);
	ATF_TP_ADD_TC(tp, pts_master_openpt);
	ATF_TP_ADD_TC(tp, pts_master_ptmx);
	ATF_TP_ADD_TC(tp, anonymous_pipe);
	ATF_TP_ADD_TC(tp, socket);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
