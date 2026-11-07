/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fsync(2) and fdatasync(2) are answered by the descriptor's fileops
 * (fo_fsync).  Every descriptor that carries a vnode syncs through it;
 * descriptors with no vnode return EINVAL, as getvnode() did; an O_PATH
 * descriptor returns EBADF from the system calls, as getvnode() did.  The
 * FIFO case is the regression test for the MPASS(f_type == DTYPE_VNODE)
 * that fsync(fifo) used to hit under INVARIANTS; the answers it and the
 * pty cases check are the ones a non-INVARIANTS kernel gave.
 */

#include <sys/param.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
check_syncs(int fd)
{
	ATF_CHECK_EQ_MSG(0, fsync(fd), "fsync: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(0, fdatasync(fd), "fdatasync: %s", strerror(errno));
}

static void
check_errno(int fd, int expected)
{
	errno = 0;
	ATF_CHECK_EQ(-1, fsync(fd));
	ATF_CHECK_EQ(expected, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fdatasync(fd));
	ATF_CHECK_EQ(expected, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(5, write(fd, "hello", 5));
	check_syncs(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_syncs(fd);
	close(fd);
}

/* getvnode() refused O_PATH descriptors with EBADF; it still does. */
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

/* A FIFO carries a vnode and syncs through it; this used to assert. */
ATF_TC_WITHOUT_HEAD(fifo);
ATF_TC_BODY(fifo, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_syncs(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_syncs(fd);
	close(fd);
}

/* Only a /dev/ptmx-opened master has a vnode to sync. */
ATF_TC_WITHOUT_HEAD(pts_master_openpt);
ATF_TC_BODY(pts_master_openpt, tc)
{
	int fd;

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_errno(fd, EINVAL);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(pts_master_ptmx);
ATF_TC_BODY(pts_master_ptmx, tc)
{
	int fd;

	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_syncs(fd);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(anonymous_pipe);
ATF_TC_BODY(anonymous_pipe, tc)
{
	int fds[2];

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_errno(fds[0], EINVAL);
	check_errno(fds[1], EINVAL);
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

ATF_TC_WITHOUT_HEAD(kqueue_fd);
ATF_TC_BODY(kqueue_fd, tc)
{
	int fd;

	fd = kqueue();
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
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, fifo);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, pts_master_openpt);
	ATF_TP_ADD_TC(tp, pts_master_ptmx);
	ATF_TP_ADD_TC(tp, anonymous_pipe);
	ATF_TP_ADD_TC(tp, socket);
	ATF_TP_ADD_TC(tp, kqueue_fd);
	ATF_TP_ADD_TC(tp, shm_fd);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
