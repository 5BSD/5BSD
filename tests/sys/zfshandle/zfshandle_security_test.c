/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TrustedZFS security-model tests: capability mode, per-command ioctl
 * allowlists, SCM_RIGHTS delegation, and the central asymmetry (handles
 * work sandboxed; minting does not).
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <trustedzfs.h>

#include "zfshandle_test_helpers.h"

static void
zht_setup(const atf_tc_t *tc, char *ds, size_t dslen)
{
	zht_require(tc);
	zht_pool_create(tc);
	snprintf(ds, dslen, "%s/data", zht_pool);
	ATF_REQUIRE_EQ(0, zht_systemf("zfs create %s", ds));
}

ATF_TC_WITH_CLEANUP(capsicum_asymmetry);
ATF_TC_HEAD(capsicum_asymmetry, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "post-cap_enter: handle verbs work, name-based minting fails");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(capsicum_asymmetry, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args st;
	char ds[256];
	pid_t pid;
	int status, zfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = zht_open_req(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY, ZHF_SUBTREE);

	/* Sandbox a child holding the handle. */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int sfd;

		if (cap_enter() != 0)
			_exit(10);
		/* Verbs through the handle: allowed. */
		if (zfd_info(zfd, &info) != 0 || info.zi_valid != 1)
			_exit(11);
		if (zfd_stat(zfd, &st) != 0)
			_exit(12);
		if (zfd_snapshot(zfd, "sandboxed") != 0)
			_exit(13);
		sfd = zfd_openat(zfd, "@sandboxed", 0, 0);
		if (sfd < 0)
			_exit(14);
		close(sfd);
		sfd = zfd_derive(zfd, 0);
		if (sfd < 0)
			_exit(15);
		close(sfd);
		/* Name-based minting: denied by capability mode. */
		if (zht_open(ds, 0, 0) != -1)
			_exit(16);
		if (errno != ECAPMODE && errno != ENOTCAPABLE)
			_exit(17);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "sandboxed child exited %d", WEXITSTATUS(status));

	/* The snapshot the sandboxed child took is real. */
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs list -H -t snapshot %s@sandboxed >/dev/null", ds));
	close(zfd);
}
ATF_TC_CLEANUP(capsicum_asymmetry, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(ioctl_allowlist);
ATF_TC_HEAD(ioctl_allowlist, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "cap_ioctls_limit narrows the verb set per-fd");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ioctl_allowlist, tc)
{
	struct zfd_info_args info;
	struct zfd_stat_args st;
	cap_rights_t rights;
	const cap_ioctl_t cmds[] = { ZFD_INFO, ZFD_STAT };
	char ds[256];
	int zfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = zht_open_req(ds, ZH_SNAPSHOT, 0);

	ATF_REQUIRE_EQ(0, cap_ioctls_limit(zfd, cmds, nitems(cmds)));
	ATF_REQUIRE_EQ(0, zfd_info(zfd, &info));
	ATF_REQUIRE_EQ(0, zfd_stat(zfd, &st));
	/* Allowed by the handle rights, blocked by the fd allowlist. */
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, zfd_snapshot(zfd, "no") == -1);

	/* Dropping CAP_IOCTL kills everything. */
	cap_rights_init(&rights, CAP_FSTAT);
	ATF_REQUIRE_EQ(0, cap_rights_limit(zfd, &rights));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, zfd_info(zfd, &info) == -1);

	close(zfd);
}
ATF_TC_CLEANUP(ioctl_allowlist, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(scm_rights_delegation);
ATF_TC_HEAD(scm_rights_delegation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a handle passed over a unix socket works in the receiver");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(scm_rights_delegation, tc)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsg;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	char ds[256], byte;
	pid_t pid;
	int sv[2], status, zfd, rfd;

	zht_setup(tc, ds, sizeof(ds));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Receiver: sandbox first, then accept the delegation. */
		close(sv[0]);
		if (cap_enter() != 0)
			_exit(20);
		memset(&msg, 0, sizeof(msg));
		byte = 0;
		iov.iov_base = &byte;
		iov.iov_len = 1;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cmsg.buf;
		msg.msg_controllen = sizeof(cmsg.buf);
		if (recvmsg(sv[1], &msg, 0) != 1)
			_exit(21);
		cm = CMSG_FIRSTHDR(&msg);
		if (cm == NULL || cm->cmsg_type != SCM_RIGHTS)
			_exit(22);
		memcpy(&rfd, CMSG_DATA(cm), sizeof(int));
		/* Use the delegated authority. */
		if (zfd_snapshot(rfd, "delegated") != 0)
			_exit(23);
		/* The delegation is narrow: destroy was not granted. */
		if (zfd_snap_destroy(rfd, "delegated") != -1 ||
		    errno != EPERM)
			_exit(24);
		_exit(0);
	}
	close(sv[1]);

	/* Grantor: mint broad, derive narrow, pass the narrow one. */
	zfd = zht_open_req(ds, ZH_SNAPSHOT | ZH_SNAP_DESTROY, 0);
	rfd = zfd_derive(zfd, ZH_SNAPSHOT);
	ATF_REQUIRE(rfd >= 0);

	memset(&msg, 0, sizeof(msg));
	byte = 'x';
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg.buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &rfd, sizeof(int));
	ATF_REQUIRE_EQ(1, sendmsg(sv[0], &msg, 0));

	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "receiver exited %d", WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0, zht_systemf(
	    "zfs list -H -t snapshot %s@delegated >/dev/null", ds));

	close(rfd);
	close(zfd);
	close(sv[0]);
}
ATF_TC_CLEANUP(scm_rights_delegation, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TC_WITH_CLEANUP(dup_and_fork);
ATF_TC_HEAD(dup_and_fork, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "handles survive dup and fork with standard fd semantics");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dup_and_fork, tc)
{
	struct zfd_stat_args st;
	char ds[256];
	pid_t pid;
	int status, zfd, dfd;

	zht_setup(tc, ds, sizeof(ds));
	zfd = zht_open_req(ds, ZH_SNAPSHOT, 0);
	dfd = dup(zfd);
	ATF_REQUIRE(dfd >= 0);
	ATF_REQUIRE_EQ(0, zfd_stat(dfd, &st));
	close(zfd);
	/* The dup keeps the handle alive. */
	ATF_REQUIRE_EQ(0, zfd_stat(dfd, &st));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		_exit(zfd_snapshot(dfd, "forked") == 0 ? 0 : 30);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "forked child exited %d", WEXITSTATUS(status));
	close(dfd);
}
ATF_TC_CLEANUP(dup_and_fork, tc)
{
	zht_pool_cleanup(tc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capsicum_asymmetry);
	ATF_TP_ADD_TC(tp, ioctl_allowlist);
	ATF_TP_ADD_TC(tp, scm_rights_delegation);
	ATF_TP_ADD_TC(tp, dup_and_fork);
	return (atf_no_error());
}
