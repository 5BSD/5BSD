/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fstatfs(2) is answered by the descriptor's fileops (fo_statfs).  Every
 * descriptor that carries a vnode must answer as statfs(2) on its path
 * does; descriptors with no vnode return EINVAL, as getvnode_path() did.
 * Only the fields that do not change between two calls are compared, so a
 * busy filesystem cannot make the oracle flaky.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
check_vnode_oracle(int fd, const char *path)
{
	struct statfs fs, ps;

	ATF_REQUIRE_EQ_MSG(0, statfs(path, &ps), "statfs(%s): %s", path,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, fstatfs(fd, &fs), "fstatfs: %s",
	    strerror(errno));
	ATF_CHECK_EQ(ps.f_version, fs.f_version);
	ATF_CHECK_EQ(ps.f_type, fs.f_type);
	ATF_CHECK_EQ(ps.f_flags, fs.f_flags);
	ATF_CHECK_EQ(ps.f_bsize, fs.f_bsize);
	ATF_CHECK_EQ(ps.f_iosize, fs.f_iosize);
	ATF_CHECK_EQ(ps.f_blocks, fs.f_blocks);
	ATF_CHECK_EQ(ps.f_files, fs.f_files);
	ATF_CHECK_EQ(ps.f_namemax, fs.f_namemax);
	ATF_CHECK_EQ(ps.f_owner, fs.f_owner);
	ATF_CHECK_EQ(ps.f_fsid.val[0], fs.f_fsid.val[0]);
	ATF_CHECK_EQ(ps.f_fsid.val[1], fs.f_fsid.val[1]);
	ATF_CHECK_STREQ(ps.f_fstypename, fs.f_fstypename);
	ATF_CHECK_STREQ(ps.f_mntfromname, fs.f_mntfromname);
	ATF_CHECK_STREQ(ps.f_mntonname, fs.f_mntonname);
}

static void
check_unsupported(int fd)
{
	struct statfs fs;

	errno = 0;
	ATF_CHECK_EQ(-1, fstatfs(fd, &fs));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, ".");
	close(fd);
}

/* getvnode_path() accepted O_PATH descriptors; fstatfs keeps working. */
ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "file");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "fifo");
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_vnode_oracle(fd, "/dev/null");
	close(fd);
}

/* A pty master carries a devfs vnode and reports devfs. */
ATF_TC_WITHOUT_HEAD(pts_master);
ATF_TC_BODY(pts_master, tc)
{
	struct statfs fs;
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, fstatfs(fd, &fs));
	ATF_CHECK_STREQ("devfs", fs.f_fstypename);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(anonymous_pipe);
ATF_TC_BODY(anonymous_pipe, tc)
{
	int fds[2];

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_unsupported(fds[0]);
	check_unsupported(fds[1]);
	close(fds[0]);
	close(fds[1]);
}

ATF_TC_WITHOUT_HEAD(socket);
ATF_TC_BODY(socket, tc)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_unsupported(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(kqueue_fd);
ATF_TC_BODY(kqueue_fd, tc)
{
	int fd;

	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_unsupported(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(shm_fd);
ATF_TC_BODY(shm_fd, tc)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_unsupported(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	struct statfs fs;
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	errno = 0;
	ATF_CHECK_EQ(-1, fstatfs(fd, &fs));
	ATF_CHECK_EQ(EBADF, errno);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, pts_master);
	ATF_TP_ADD_TC(tp, anonymous_pipe);
	ATF_TP_ADD_TC(tp, socket);
	ATF_TP_ADD_TC(tp, kqueue_fd);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
