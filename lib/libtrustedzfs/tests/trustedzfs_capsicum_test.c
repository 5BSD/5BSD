/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test libtrustedzfs's typed Capsicum ioctl profiles without requiring ZFS.
 * cap_ioctls_limit(2) is descriptor-generic, so a socket is sufficient to
 * verify the exact command sets and monotonic behavior.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <trustedzfs.h>

static int
test_fd(void)
{
	int sv[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	(void)close(sv[1]);
	return (sv[0]);
}

static void
require_ioctl_set(int fd, const cap_ioctl_t *expected, size_t nexpected)
{
	cap_ioctl_t actual[64];
	ssize_t nactual;
	size_t i, j;
	bool found;

	nactual = cap_ioctls_get(fd, actual, nitems(actual));
	ATF_REQUIRE_MSG(nactual >= 0, "cap_ioctls_get: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(nexpected, (size_t)nactual,
	    "expected %zu commands, got %zd", nexpected, nactual);
	for (i = 0; i < nexpected; i++) {
		found = false;
		for (j = 0; j < (size_t)nactual; j++) {
			if (actual[j] == expected[i]) {
				found = true;
				break;
			}
		}
		ATF_REQUIRE_MSG(found, "missing ioctl %#lx",
		    (unsigned long)expected[i]);
	}
}

ATF_TC(dataset_exact);
ATF_TC_HEAD(dataset_exact, tc)
{
	atf_tc_set_md_var(tc, "descr", "dataset operation mask is exact");
}
ATF_TC_BODY(dataset_exact, tc)
{
	const cap_ioctl_t expected[] = {
		ZFD_INFO, ZFD_STAT, ZFD_SNAPSHOT, ZFD_WAIT,
	};
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_INFO | TZFS_OP_STAT | TZFS_OP_SNAPSHOT | TZFS_OP_WAIT));
	require_ioctl_set(fd, expected, nitems(expected));
	(void)close(fd);
}

ATF_TC(dataset_rights_profile);
ATF_TC_HEAD(dataset_rights_profile, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "dataset ZH rights and subtree flag map to the complete verb set");
}
ATF_TC_BODY(dataset_rights_profile, tc)
{
	const cap_ioctl_t expected[] = {
		ZFD_INFO, ZFD_DERIVE, ZFD_OPENAT, ZFD_STAT, ZFD_GET_PROPS,
		ZFD_GET_ONE_PROP, ZFD_LIST_CHILDREN, ZFD_LIST_SNAPS, ZFD_HOLDS,
		ZFD_LIST_BOOKMARKS, ZFD_SET_PROP, ZFD_INHERIT, ZFD_SNAPSHOT,
		ZFD_BOOKMARK, ZFD_CREATE, ZFD_CLONE, ZFD_PROMOTE, ZFD_DESTROY,
		ZFD_RENAME, ZFD_HOLD, ZFD_RELEASE, ZFD_WAIT,
	};
	const uint64_t rights = ZH_PROPS_WRITE | ZH_SNAPSHOT | ZH_CREATE |
	    ZH_DESTROY | ZH_HOLD;
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls_by_rights(fd, rights,
	    ZHF_SUBTREE));
	require_ioctl_set(fd, expected, nitems(expected));
	(void)close(fd);
}

ATF_TC(pool_rights_profile);
ATF_TC_HEAD(pool_rights_profile, tc)
{
	atf_tc_set_md_var(tc, "descr", "pool rights map only to pool verbs");
}
ATF_TC_BODY(pool_rights_profile, tc)
{
	const cap_ioctl_t expected[] = {
		ZFD_INFO, ZFD_DERIVE, ZPD_STAT, ZPD_GET_PROPS,
		ZPD_SET_PROP, ZPD_SCRUB, ZPD_ROOT_OPEN, ZPD_WAIT,
	};
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_pool_ioctls_by_rights(fd,
	    ZH_PROPS_WRITE | ZH_SCRUB));
	require_ioctl_set(fd, expected, nitems(expected));
	(void)close(fd);
}

ATF_TC(all_dataset_rights_profile);
ATF_TC_HEAD(all_dataset_rights_profile, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "all dataset rights and subtree scope cover every dataset ioctl");
}
ATF_TC_BODY(all_dataset_rights_profile, tc)
{
	const cap_ioctl_t expected[] = {
		ZFD_INFO, ZFD_DERIVE, ZFD_OPENAT, ZFD_STAT, ZFD_GET_PROPS,
		ZFD_GET_ONE_PROP, ZFD_LIST_CHILDREN, ZFD_LIST_SNAPS, ZFD_HOLDS,
		ZFD_LIST_BOOKMARKS, ZFD_SET_PROP, ZFD_INHERIT, ZFD_SNAPSHOT,
		ZFD_BOOKMARK, ZFD_SNAP_DESTROY, ZFD_DESTROY_BOOKMARK,
		ZFD_ROLLBACK, ZFD_CREATE, ZFD_DESTROY, ZFD_RENAME, ZFD_CLONE,
		ZFD_PROMOTE, ZFD_SEND, ZFD_RECV, ZFD_HOLD, ZFD_RELEASE,
		ZFD_BLKOPEN, ZFD_MOUNT, ZFD_UNMOUNT, ZFD_WAIT,
	};
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls_by_rights(fd,
	    ZH_ALL_RIGHTS, ZHF_SUBTREE));
	require_ioctl_set(fd, expected, nitems(expected));
	(void)close(fd);
}

ATF_TC(kind_and_mask_validation);
ATF_TC_HEAD(kind_and_mask_validation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cross-kind, unknown operation, rights, and flag bits are rejected");
}
ATF_TC_BODY(kind_and_mask_validation, tc)
{
	int fd;

	fd = test_fd();
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_POOL_STAT) == -1);
	ATF_REQUIRE_EQ(CAP_IOCTLS_ALL, cap_ioctls_get(fd, NULL, 0));
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_limit_pool_ioctls(fd,
	    TZFS_OP_STAT) == -1);
	ATF_REQUIRE_EQ(CAP_IOCTLS_ALL, cap_ioctls_get(fd, NULL, 0));
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_limit_dataset_ioctls(fd,
	    UINT64_C(1) << 63) == -1);
	ATF_REQUIRE_EQ(CAP_IOCTLS_ALL, cap_ioctls_get(fd, NULL, 0));
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_limit_dataset_ioctls_by_rights(fd,
	    ZH_ALL_RIGHTS + 1, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, tzfs_limit_dataset_ioctls_by_rights(fd,
	    0, ZHF_SUBTREE << 1) == -1);
	ATF_REQUIRE_EQ(CAP_IOCTLS_ALL, cap_ioctls_get(fd, NULL, 0));
	(void)close(fd);
}

ATF_TC(monotonic_narrowing);
ATF_TC_HEAD(monotonic_narrowing, tc)
{
	atf_tc_set_md_var(tc, "descr", "ioctl profiles narrow but never widen");
}
ATF_TC_BODY(monotonic_narrowing, tc)
{
	const cap_ioctl_t expected[] = { ZFD_INFO };
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_INFO | TZFS_OP_STAT));
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd, TZFS_OP_INFO));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, tzfs_limit_dataset_ioctls(fd,
	    TZFS_OP_INFO | TZFS_OP_STAT) == -1);
	require_ioctl_set(fd, expected, nitems(expected));
	(void)close(fd);
}

ATF_TC(empty_profile);
ATF_TC_HEAD(empty_profile, tc)
{
	atf_tc_set_md_var(tc, "descr", "an empty mask denies every ioctl");
}
ATF_TC_BODY(empty_profile, tc)
{
	int fd;

	fd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(fd, 0));
	require_ioctl_set(fd, NULL, 0);
	(void)close(fd);
}

ATF_TC(scm_rights_preserves_profile);
ATF_TC_HEAD(scm_rights_preserves_profile, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SCM_RIGHTS transfer preserves the ioctl command ceiling");
}
ATF_TC_BODY(scm_rights_preserves_profile, tc)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	const cap_ioctl_t expected[] = { ZFD_INFO, ZFD_STAT };
	struct cmsghdr *cm;
	struct iovec iov;
	struct msghdr msg;
	char byte;
	int capfd, received, sv[2];

	capfd = test_fd();
	ATF_REQUIRE_EQ(0, tzfs_limit_dataset_ioctls(capfd,
	    TZFS_OP_INFO | TZFS_OP_STAT));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	byte = 'x';
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &capfd, sizeof(capfd));
	ATF_REQUIRE_EQ(1, sendmsg(sv[0], &msg, 0));

	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	byte = 0;
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	ATF_REQUIRE_EQ(1, recvmsg(sv[1], &msg, 0));
	cm = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cm != NULL);
	ATF_REQUIRE_EQ(SOL_SOCKET, cm->cmsg_level);
	ATF_REQUIRE_EQ(SCM_RIGHTS, cm->cmsg_type);
	memcpy(&received, CMSG_DATA(cm), sizeof(received));
	require_ioctl_set(received, expected, nitems(expected));

	(void)close(received);
	(void)close(capfd);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, dataset_exact);
	ATF_TP_ADD_TC(tp, dataset_rights_profile);
	ATF_TP_ADD_TC(tp, pool_rights_profile);
	ATF_TP_ADD_TC(tp, all_dataset_rights_profile);
	ATF_TP_ADD_TC(tp, kind_and_mask_validation);
	ATF_TP_ADD_TC(tp, monotonic_narrowing);
	ATF_TP_ADD_TC(tp, empty_profile);
	ATF_TP_ADD_TC(tp, scm_rights_preserves_profile);
	return (atf_no_error());
}
