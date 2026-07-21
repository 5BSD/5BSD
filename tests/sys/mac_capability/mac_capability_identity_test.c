/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for:
 *   - mac_capability_identity service (IDENTITY_OP_SELF, IDENTITY_OP_QUERY)
 *   - Capsicum ioctl allowlist enforcement
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_identity_proto.h"

static int
identity_call(int fd, const struct identity_request *req,
    const int *req_fds, int nfds,
    struct identity_reply *reply)
{
	struct mac_capability_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = sizeof(*req);
	ca.req_fds = req_fds;
	ca.req_nfds = nfds;
	ca.reply = reply;
	ca.reply_len = sizeof(*reply);
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

/* ----------------------------------------------------------------
 * Identity service tests
 * ---------------------------------------------------------------- */

ATF_TC(identity_self);
ATF_TC_HEAD(identity_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "IDENTITY_OP_SELF returns caller's nonce");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_self, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE_MSG(fd >= 0, "connect identity: %s", strerror(errno));

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &reply) == 0);
	ATF_CHECK_EQ(reply.status, IDENTITY_STATUS_OK);
	ATF_CHECK(reply.nonce != 0);

	close(fd);
}

ATF_TC(identity_self_stable);
ATF_TC_HEAD(identity_self_stable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple SELF calls return the same nonce");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_self_stable, tc)
{
	struct identity_request req;
	struct identity_reply r1, r2;
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &r1) == 0);
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &r2) == 0);
	ATF_CHECK_EQ(r1.nonce, r2.nonce);

	close(fd);
}

ATF_TC(identity_fork_inherits);
ATF_TC_HEAD(identity_fork_inherits, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Child inherits parent's nonce across fork");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_fork_inherits, tc)
{
	struct identity_request req;
	struct identity_reply parent_reply, child_reply;
	int fd, sv[2], status;
	pid_t pid;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &parent_reply) == 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(sv[0]);
		if (identity_call(fd, &req, NULL, 0, &child_reply) != 0)
			_exit(1);
		/* Send child nonce to parent */
		write(sv[1], &child_reply.nonce, sizeof(child_reply.nonce));
		close(sv[1]);
		close(fd);
		_exit(0);
	}
	close(sv[1]);

	uint64_t child_nonce;
	ATF_REQUIRE(read(sv[0], &child_nonce, sizeof(child_nonce)) ==
	    (ssize_t)sizeof(child_nonce));
	close(sv[0]);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK_EQ(parent_reply.nonce, child_nonce);

	close(fd);
}

ATF_TC(identity_query_dead_procdesc);
ATF_TC_HEAD(identity_query_dead_procdesc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "IDENTITY_OP_QUERY returns DEAD for an exited procdesc target");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_query_dead_procdesc, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0)
		_exit(0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_QUERY;
	ATF_REQUIRE(identity_call(fd, &req, &pd, 1, &reply) == 0);
	ATF_CHECK_EQ(reply.status, IDENTITY_STATUS_DEAD);
	ATF_CHECK_EQ(reply.nonce, 0);

	close(pd);
	close(fd);
}

ATF_TC(identity_query_procdesc);
ATF_TC_HEAD(identity_query_procdesc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "IDENTITY_OP_QUERY returns child nonce via procdesc");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_query_procdesc, tc)
{
	struct identity_request req;
	struct identity_reply self_reply, query_reply;
	int fd, pd, status;
	pid_t pid;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	/* Get parent nonce */
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &self_reply) == 0);

	/* Fork with procdesc */
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child: just sleep so parent can query */
		close(fd);
		sleep(10);
		_exit(0);
	}

	/* Query child nonce via procdesc fd */
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_QUERY;
	ATF_REQUIRE(identity_call(fd, &req, &pd, 1, &query_reply) == 0);
	ATF_CHECK_EQ(query_reply.status, IDENTITY_STATUS_OK);
	ATF_CHECK(query_reply.nonce != 0);

	/* Child is forked (no exec), so nonce should match parent */
	ATF_CHECK_EQ(self_reply.nonce, query_reply.nonce);

	/* Clean up child */
	pdkill(pd, SIGKILL);
	waitpid(pid, &status, 0);
	close(pd);
	close(fd);
}

ATF_TC(identity_query_no_fd);
ATF_TC_HEAD(identity_query_no_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "IDENTITY_OP_QUERY without an attached fd fails");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_query_no_fd, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_QUERY;
	ATF_CHECK_ERRNO(EINVAL,
	    identity_call(fd, &req, NULL, 0, &reply) == -1);

	close(fd);
}

ATF_TC(identity_query_wrong_fd_type);
ATF_TC_HEAD(identity_query_wrong_fd_type, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "IDENTITY_OP_QUERY with a non-procdesc fd fails");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_query_wrong_fd_type, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	int fd, pipefd[2];

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(pipefd) == 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_QUERY;
	ATF_CHECK_ERRNO(EINVAL,
	    identity_call(fd, &req, &pipefd[0], 1, &reply) == -1);

	close(pipefd[0]);
	close(pipefd[1]);
	close(fd);
}

ATF_TC(identity_bad_op);
ATF_TC_HEAD(identity_bad_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown operation code returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(identity_bad_op, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = 99;
	ATF_CHECK_ERRNO(EINVAL,
	    identity_call(fd, &req, NULL, 0, &reply) == -1);

	close(fd);
}

/* ----------------------------------------------------------------
 * Capsicum ioctl allowlist enforcement tests
 * ---------------------------------------------------------------- */

ATF_TC(capsicum_default_ioctls_unrestricted);
ATF_TC_HEAD(capsicum_default_ioctls_unrestricted, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Fresh mac_capability fds initially allow all ioctl commands");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(capsicum_default_ioctls_unrestricted, tc)
{
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	ATF_CHECK_EQ(cap_ioctls_get(fd, NULL, 0), CAP_IOCTLS_ALL);

	close(fd);
}

ATF_TC(capsicum_send_ioctl_limit);
ATF_TC_HEAD(capsicum_send_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SENDMSG is denied when absent from the fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_send_ioctl_limit, tc)
{
	struct mac_capability_sendmsg_args sa;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_RECVMSG };
	int fd;
	char buf[16];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = buf;
	sa.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(fd);
}

ATF_TC(capsicum_recv_ioctl_limit);
ATF_TC_HEAD(capsicum_recv_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG is denied when absent from the fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_test_keystore");
}
ATF_TC_BODY(capsicum_recv_ioctl_limit, tc)
{
	struct mac_capability_recvmsg_args ra;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_SENDMSG };
	int fd;
	char buf[128];

	fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra) == -1);

	close(fd);
}

ATF_TC(capsicum_call_ioctl_limit);
ATF_TC_HEAD(capsicum_call_ioctl_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CALL is denied when absent from the fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(capsicum_call_ioctl_limit, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);
	ATF_CHECK_ERRNO(ENOTCAPABLE,
	    identity_call(fd, &req, NULL, 0, &reply) == -1);

	close(fd);
}

ATF_TC(capsicum_call_ioctl_allowed);
ATF_TC_HEAD(capsicum_call_ioctl_allowed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CALL succeeds when present in the fd ioctl allowlist");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(capsicum_call_ioctl_allowed, tc)
{
	struct identity_request req;
	struct identity_reply reply;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_CALL };
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	ATF_REQUIRE(identity_call(fd, &req, NULL, 0, &reply) == 0);
	ATF_CHECK_EQ(reply.status, IDENTITY_STATUS_OK);
	ATF_CHECK(reply.nonce != 0);

	close(fd);
}

ATF_TC(capsicum_getinfo_ioctl_allowed);
ATF_TC_HEAD(capsicum_getinfo_ioctl_allowed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GETINFO works when it is the only allowed ioctl command");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(capsicum_getinfo_ioctl_allowed, tc)
{
	struct mac_capability_info_args info;
	cap_ioctl_t cmds[] = { MAC_CAPABILITY_GETINFO };
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_MSG(strcmp(info.name, "identity") == 0,
	    "expected 'identity', got '%s'", info.name);

	close(fd);
}

ATF_TC(capsicum_revoke_ioctls_allowed);
ATF_TC_HEAD(capsicum_revoke_ioctls_allowed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "REVOKE_SEND/RECV/CALL work when explicitly allowlisted");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_identity");
}
ATF_TC_BODY(capsicum_revoke_ioctls_allowed, tc)
{
	cap_ioctl_t cmds[] = {
		MAC_CAPABILITY_REVOKE_SEND,
		MAC_CAPABILITY_REVOKE_RECV,
		MAC_CAPABILITY_REVOKE_CALL,
	};
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(cap_ioctls_limit(fd, cmds, nitems(cmds)) == 0);

	/* Capability narrowing should always work */
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_REVOKE_SEND, NULL) == 0);
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_REVOKE_RECV, NULL) == 0);
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_REVOKE_CALL, NULL) == 0);

	close(fd);
}

/* ----------------------------------------------------------------
 * Test registration
 * ---------------------------------------------------------------- */

ATF_TP_ADD_TCS(tp)
{
	/* Identity service */
	ATF_TP_ADD_TC(tp, identity_self);
	ATF_TP_ADD_TC(tp, identity_self_stable);
	ATF_TP_ADD_TC(tp, identity_fork_inherits);
	ATF_TP_ADD_TC(tp, identity_query_dead_procdesc);
	ATF_TP_ADD_TC(tp, identity_query_procdesc);
	ATF_TP_ADD_TC(tp, identity_query_no_fd);
	ATF_TP_ADD_TC(tp, identity_query_wrong_fd_type);
	ATF_TP_ADD_TC(tp, identity_bad_op);

	/* Capsicum ioctl allowlist enforcement */
	ATF_TP_ADD_TC(tp, capsicum_default_ioctls_unrestricted);
	ATF_TP_ADD_TC(tp, capsicum_send_ioctl_limit);
	ATF_TP_ADD_TC(tp, capsicum_recv_ioctl_limit);
	ATF_TP_ADD_TC(tp, capsicum_call_ioctl_limit);
	ATF_TP_ADD_TC(tp, capsicum_call_ioctl_allowed);
	ATF_TP_ADD_TC(tp, capsicum_getinfo_ioctl_allowed);
	ATF_TP_ADD_TC(tp, capsicum_revoke_ioctls_allowed);

	return (atf_no_error());
}
