/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Tests for the cap_rt mount service.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "cap_rt_ioctl.h"
#include "cap_rt_mount_proto.h"

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static int
cap_rt_open(void)
{
	int fd;

	fd = open("/dev/cap_rt", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("cap_rt module not loaded");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/cap_rt: %s", strerror(errno));
	return (fd);
}

static int
mount_connect(void)
{
	struct cap_rt_connect_args ca;
	int ctl;

	ctl = cap_rt_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "mount", sizeof(ca.name));
	if (ioctl(ctl, CAP_RT_CONNECT, &ca) != 0) {
		if (errno == ENOENT)
			atf_tc_skip("mount service not loaded");
		ATF_REQUIRE_MSG(0, "connect mount: %s", strerror(errno));
	}
	close(ctl);
	return (ca.fd);
}

static int
mount_call_raw(int fd, const void *req, size_t reqlen,
    void *reply, size_t replylen)
{
	struct cap_rt_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, CAP_RT_CALL, &ca));
}

/* ----------------------------------------------------------------
 * Validation tests (don't require jail or root for most)
 * ---------------------------------------------------------------- */

ATF_TC(mount_rejects_bad_fstype);
ATF_TC_HEAD(mount_rejects_bad_fstype, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT rejects non-whitelisted filesystem type");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_rejects_bad_fstype, tc)
{
	struct mount_request req;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	memset(&req, 0, sizeof(req));
	req.op = MOUNT_OP_MOUNT;
	strlcpy(req.fstype, "zfs", sizeof(req.fstype));
	strlcpy(req.fspath, "/mnt", sizeof(req.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_EPERM);

	close(fd);
}

ATF_TC(mount_rejects_relative_path);
ATF_TC_HEAD(mount_rejects_relative_path, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT rejects relative mount path");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_rejects_relative_path, tc)
{
	struct mount_request req;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	memset(&req, 0, sizeof(req));
	req.op = MOUNT_OP_MOUNT;
	strlcpy(req.fstype, "tmpfs", sizeof(req.fstype));
	strlcpy(req.fspath, "tmp", sizeof(req.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_ERR);

	close(fd);
}

ATF_TC(mount_rejects_dotdot_path);
ATF_TC_HEAD(mount_rejects_dotdot_path, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT rejects paths containing ..");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_rejects_dotdot_path, tc)
{
	struct mount_request req;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	memset(&req, 0, sizeof(req));
	req.op = MOUNT_OP_MOUNT;
	strlcpy(req.fstype, "tmpfs", sizeof(req.fstype));
	strlcpy(req.fspath, "/tmp/../etc", sizeof(req.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_ERR);

	close(fd);
}

ATF_TC(mount_allows_dotdot_in_name);
ATF_TC_HEAD(mount_allows_dotdot_in_name, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT accepts paths with .. in directory names");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_allows_dotdot_in_name, tc)
{
	struct mount_request req;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	/*
	 * "/tmp/..hidden" has ".." in the directory name, not as a
	 * path traversal component.  This should NOT be rejected.
	 * The mount will likely fail with ENOENT (dir doesn't exist),
	 * but it should not be rejected by path validation.
	 */
	memset(&req, 0, sizeof(req));
	req.op = MOUNT_OP_MOUNT;
	strlcpy(req.fstype, "tmpfs", sizeof(req.fstype));
	strlcpy(req.fspath, "/tmp/..hidden", sizeof(req.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == 0);
	/* Should pass validation (not STATUS_ERR from path check).
	 * Will fail with ENOENT or EPERM, not the validation error. */
	ATF_CHECK(reply.status != MOUNT_STATUS_ERR ||
	    reply.status == MOUNT_STATUS_ENOENT ||
	    reply.status == MOUNT_STATUS_EPERM);

	close(fd);
}

ATF_TC(mount_rejects_bad_flags);
ATF_TC_HEAD(mount_rejects_bad_flags, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT rejects unknown flags");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_rejects_bad_flags, tc)
{
	struct mount_request req;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	memset(&req, 0, sizeof(req));
	req.op = MOUNT_OP_MOUNT;
	req.flags = 0xFFFF;
	strlcpy(req.fstype, "tmpfs", sizeof(req.fstype));
	strlcpy(req.fspath, "/tmp", sizeof(req.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &req, sizeof(req),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_ERR);

	close(fd);
}

ATF_TC(mount_bad_op);
ATF_TC_HEAD(mount_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown operation returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
}
ATF_TC_BODY(mount_bad_op, tc)
{
	uint32_t op = 99;
	struct mount_reply reply;
	int fd;

	fd = mount_connect();

	ATF_CHECK_ERRNO(EINVAL,
	    mount_call_raw(fd, &op, sizeof(op),
	    &reply, sizeof(reply)) == -1);

	close(fd);
}

ATF_TC(mount_tmpfs);
ATF_TC_HEAD(mount_tmpfs, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MOUNT_OP_MOUNT mounts tmpfs on a test directory");
	atf_tc_set_md_var(tc, "require.kmods", "cap_rt cap_rt_mount");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mount_tmpfs, tc)
{
	struct mount_request mreq;
	struct unmount_request ureq;
	struct mount_reply reply;
	char mntpath[MOUNT_MAXPATH];
	int fd;

	snprintf(mntpath, sizeof(mntpath),
	    "/tmp/cap_rt_mount_test.%d", (int)getpid());
	ATF_REQUIRE(mkdir(mntpath, 0755) == 0 || errno == EEXIST);

	fd = mount_connect();

	/* Mount tmpfs */
	memset(&mreq, 0, sizeof(mreq));
	mreq.op = MOUNT_OP_MOUNT;
	mreq.flags = MOUNT_F_NOSUID | MOUNT_F_NOEXEC;
	strlcpy(mreq.fstype, "tmpfs", sizeof(mreq.fstype));
	strlcpy(mreq.fspath, mntpath, sizeof(mreq.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &mreq, sizeof(mreq),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_OK);

	/* Verify we can create a file on it */
	if (reply.status == MOUNT_STATUS_OK) {
		char filepath[MOUNT_MAXPATH + 16];
		int tfd;

		snprintf(filepath, sizeof(filepath), "%s/testfile", mntpath);
		tfd = open(filepath, O_CREAT | O_RDWR, 0644);
		ATF_CHECK(tfd >= 0);
		if (tfd >= 0)
			close(tfd);
		unlink(filepath);
	}

	/* Unmount */
	memset(&ureq, 0, sizeof(ureq));
	ureq.op = MOUNT_OP_UNMOUNT;
	strlcpy(ureq.fspath, mntpath, sizeof(ureq.fspath));
	ATF_REQUIRE(mount_call_raw(fd, &ureq, sizeof(ureq),
	    &reply, sizeof(reply)) == 0);
	ATF_CHECK_EQ(reply.status, MOUNT_STATUS_OK);

	rmdir(mntpath);
	close(fd);
}

/* ----------------------------------------------------------------
 * Registration
 * ---------------------------------------------------------------- */

ATF_TP_ADD_TCS(tp)
{

	/* Validation */
	ATF_TP_ADD_TC(tp, mount_rejects_bad_fstype);
	ATF_TP_ADD_TC(tp, mount_rejects_relative_path);
	ATF_TP_ADD_TC(tp, mount_rejects_dotdot_path);
	ATF_TP_ADD_TC(tp, mount_allows_dotdot_in_name);
	ATF_TP_ADD_TC(tp, mount_rejects_bad_flags);
	ATF_TP_ADD_TC(tp, mount_bad_op);

	/* Functional */
	ATF_TP_ADD_TC(tp, mount_tmpfs);

	return (atf_no_error());
}
