/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The fcntl(2) commands with per-type semantics, F_READAHEAD, F_RDAHEAD and
 * F_ISUNIONSTACK, are answered by the descriptor's fileops (fo_fcntl).
 * Regular files take read-ahead; other vnode files return ENOTTY for it;
 * every vnode file answers F_ISUNIONSTACK; descriptors with no vnode return
 * EBADF, as the type tests did; O_PATH keeps F_ISUNIONSTACK and refuses
 * read-ahead with EBADF.
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
check_readahead_errno(int fd, int expected)
{
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_READAHEAD, 65536));
	ATF_CHECK_EQ(expected, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_RDAHEAD, 1));
	ATF_CHECK_EQ(expected, errno);
}

ATF_TC_WITHOUT_HEAD(regular_file);
ATF_TC_BODY(regular_file, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(0, fcntl(fd, F_READAHEAD, 65536));
	ATF_CHECK_EQ(0, fcntl(fd, F_READAHEAD, 0));
	ATF_CHECK_EQ(0, fcntl(fd, F_READAHEAD, -1));
	ATF_CHECK_EQ(0, fcntl(fd, F_RDAHEAD, 1));
	ATF_CHECK_EQ(0, fcntl(fd, F_RDAHEAD, 0));
	/* A regular file in the test directory is not on a union stack. */
	ATF_CHECK_EQ(0, fcntl(fd, F_ISUNIONSTACK, 0));
	close(fd);
}

/* Directories and devices answer F_ISUNIONSTACK but take no read-ahead. */
ATF_TC_WITHOUT_HEAD(directory);
ATF_TC_BODY(directory, tc)
{
	int fd;

	fd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, ENOTTY);
	ATF_CHECK_EQ(0, fcntl(fd, F_ISUNIONSTACK, 0));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(devfs_node);
ATF_TC_BODY(devfs_node, tc)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, ENOTTY);
	ATF_CHECK_EQ(0, fcntl(fd, F_ISUNIONSTACK, 0));
	close(fd);
}

ATF_TC_WITHOUT_HEAD(opath_file);
ATF_TC_BODY(opath_file, tc)
{
	int fd;

	ATF_REQUIRE_EQ(0, close(open("file", O_RDWR | O_CREAT, 0644)));
	fd = open("file", O_PATH);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	ATF_CHECK_EQ(0, fcntl(fd, F_ISUNIONSTACK, 0));
	close(fd);
}

/* FIFOs, ptys and non-vnode descriptors were EBADF for both and still are. */
ATF_TC_WITHOUT_HEAD(no_vnode_ops);
ATF_TC_BODY(no_vnode_ops, tc)
{
	int fds[2], fd;

	ATF_REQUIRE_EQ(0, mkfifo("fifo", 0644));
	fd = open("fifo", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);

	fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);

	ATF_REQUIRE_EQ(0, pipe(fds));
	check_readahead_errno(fds[0], EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fds[0], F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fds[0]);
	close(fds[1]);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	close(fd);

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);

	fd = kqueue();
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);

	fd = posix_openpt(O_RDWR | O_NOCTTY);
	ATF_REQUIRE(fd >= 0);
	check_readahead_errno(fd, EBADF);
	errno = 0;
	ATF_CHECK_EQ(-1, fcntl(fd, F_ISUNIONSTACK, 0));
	ATF_CHECK_EQ(EBADF, errno);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(bad_fd);
ATF_TC_BODY(bad_fd, tc)
{
	int fd;

	fd = open("file", O_RDWR | O_CREAT, 0644);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	check_readahead_errno(fd, EBADF);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, regular_file);
	ATF_TP_ADD_TC(tp, directory);
	ATF_TP_ADD_TC(tp, devfs_node);
	ATF_TP_ADD_TC(tp, opath_file);
	ATF_TP_ADD_TC(tp, no_vnode_ops);
	ATF_TP_ADD_TC(tp, bad_fd);
	return (atf_no_error());
}
