/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the production limiter without an ioctl test double.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>
#include <trustedzfs.h>

static void
require_rejection(int fd)
{
	struct zfd_limit_args limit = { .zl_ops = TZFS_OP_INFO };
	int error;

	/* Preserve the actual kernel error, without assuming a descriptor type. */
	ATF_REQUIRE_EQ(-1, ioctl(fd, ZFD_LIMIT, &limit));
	error = errno;
	ATF_REQUIRE_ERRNO(error,
	    tzfs_limit_dataset_ioctls(fd, TZFS_OP_INFO) == -1);
	ATF_REQUIRE_ERRNO(error,
	    tzfs_limit_pool_ioctls(fd, TZFS_OP_INFO) == -1);
	ATF_REQUIRE_ERRNO(error,
	    tzfs_limit_dataset_ioctls_by_rights(fd, 0, 0) == -1);
	ATF_REQUIRE_ERRNO(error,
	    tzfs_limit_pool_ioctls_by_rights(fd, 0) == -1);
	if (fd >= 0)
		ATF_REQUIRE_EQ(CAP_IOCTLS_ALL, cap_ioctls_get(fd, NULL, 0));
}

ATF_TC(socket_rejected);
ATF_TC_HEAD(socket_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "sockets cannot bypass the required TrustedZFS kernel ceiling");
}
ATF_TC_BODY(socket_rejected, tc)
{
	int sv[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	require_rejection(sv[0]);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(file_rejected);
ATF_TC_HEAD(file_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ordinary files cannot be reported as confined TrustedZFS handles");
}
ATF_TC_BODY(file_rejected, tc)
{
	char path[] = "ordinary.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, unlink(path));
	require_rejection(fd);
	close(fd);
}

ATF_TC(invalid_fd_rejected);
ATF_TC_HEAD(invalid_fd_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr", "invalid descriptor errors propagate");
}
ATF_TC_BODY(invalid_fd_rejected, tc)
{
	require_rejection(-1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, socket_rejected);
	ATF_TP_ADD_TC(tp, file_rejected);
	ATF_TP_ADD_TC(tp, invalid_fd_rejected);
	return (atf_no_error());
}
