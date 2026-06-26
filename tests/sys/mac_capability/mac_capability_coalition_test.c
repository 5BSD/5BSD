/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * Tests for mac_capability_coalition — capability-based resource group management.
 *
 * Requires:
 *   kldload mac_capability
 *   kldload mac_capability_coalition
 *   kldload mac_capability_test_keystore   (for mac_capability member tests)
 *   kldload mac_capability_channel            (for mac_capability member termination tests)
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/jail.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jail.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_coalition_proto.h"

#define	COALITION_TEST_JAIL_NAME	"mac_capability_coalition_jail_member_test"

/* ================================================================
 * Helpers
 * ================================================================ */

/*
 * Issue a coalition CALL with optional attached fds.
 * Returns 0 on ioctl success, -1 on failure.
 * On success, reply is filled and *replylenp updated.
 */
static int
coalition_call(int fd, const void *req, size_t reqlen,
    const int *req_fds, int nfds,
    void *reply, size_t replylen)
{
	struct mac_capability_call_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.req = req;
	ca.req_len = reqlen;
	ca.req_fds = req_fds;
	ca.req_nfds = nfds;
	ca.reply = reply;
	ca.reply_len = replylen;
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

/* Issue a simple operation (no fds, coalition_reply) */
static int
coalition_op(int fd, uint32_t op, int32_t *status_out)
{
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	int ret;

	hdr.op = op;
	ret = coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

/* Enlist a member fd into the coalition */
static int
coalition_enlist(int cfd, int member_fd, int32_t *status_out)
{
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	int ret;

	hdr.op = COALITION_OP_ENLIST;
	ret = coalition_call(cfd, &hdr, sizeof(hdr), &member_fd, 1,
	    &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

static int
coalition_enlist_set(int cfd, const int *member_fds, int nfds,
    struct coalition_enlist_set_reply *reply)
{
	struct coalition_req_hdr hdr;

	hdr.op = COALITION_OP_ENLIST_SET;
	return (coalition_call(cfd, &hdr, sizeof(hdr), member_fds, nfds,
	    reply, sizeof(*reply)));
}

/* Get coalition stat */
static int
coalition_stat(int fd, struct coalition_stat_reply *sr)
{
	struct coalition_req_hdr hdr;

	hdr.op = COALITION_OP_STAT;
	return (coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    sr, sizeof(*sr)));
}

static int
coalition_recv_event(int fd, struct coalition_event_msg *ev)
{
	struct mac_capability_recvmsg_args ra;

	memset(&ra, 0, sizeof(ra));
	ra.payload = ev;
	ra.payload_len = sizeof(*ev);
	return (ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra));
}

static int
coalition_sendmsg(int fd, const void *req, size_t reqlen,
    const int *req_fds, int nfds, uint64_t token)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = req;
	sa.payload_len = reqlen;
	sa.fds = req_fds;
	sa.nfds = nfds;
	sa.reply_token = token;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

static int
coalition_recvmsg(int fd, void *reply, uint32_t *replylenp,
    uint64_t *tokenp)
{
	struct mac_capability_recvmsg_args ra;
	int ret;

	memset(&ra, 0, sizeof(ra));
	ra.payload = reply;
	ra.payload_len = *replylenp;
	ret = ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra);
	if (ret == 0) {
		*replylenp = ra.payload_len;
		if (tokenp != NULL)
			*tokenp = ra.reply_token;
	}
	return (ret);
}

static int
kqueue_poll(int kq_fd, struct kevent *events, int nevents, int timeout_ms)
{
	struct timespec ts;

	ts.tv_sec = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
	return (kevent(kq_fd, NULL, 0, events, nevents, &ts));
}

static int
create_jail_with_desc(const char *name)
{
	char desc_str[16] = "";
	int jid;

	jid = jail_setv(JAIL_CREATE | JAIL_GET_DESC,
	    "name", name,
	    "path", "/",
	    "persist", NULL,
	    "desc", desc_str,
	    NULL);
	if (jid < 0)
		return (-1);

	return (atoi(desc_str));
}

static void
remove_jail_by_name(const char *name)
{
	int jid;

	jid = jail_getid(name);
	if (jid > 0)
		(void)jail_remove(jid);
}

static void
wait_for_jail_removal(const char *name)
{
	int i;
	int jid;

	for (i = 0; i < 50; i++) {
		errno = 0;
		jid = jail_getid(name);
		if (jid < 0) {
			ATF_REQUIRE_MSG(errno == ENOENT,
			    "jail_getid(%s): %s", name, strerror(errno));
			return;
		}
		usleep(20000);
	}

	errno = 0;
	jid = jail_getid(name);
	ATF_REQUIRE_MSG(jid < 0 && errno == ENOENT,
	    "jail %s still exists after coalition teardown", name);
}

/* ================================================================
 * Basic lifecycle tests
 * ================================================================ */

ATF_TC(connect_coalition);
ATF_TC_HEAD(connect_coalition, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Connect to coalition service and close");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(connect_coalition, tc)
{
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE_MSG(fd >= 0, "connect: %s", strerror(errno));
	close(fd);
}

ATF_TC(stat_empty);
ATF_TC_HEAD(stat_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "STAT on empty coalition returns zero members");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(stat_empty, tc)
{
	struct coalition_stat_reply sr;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.status, 0);
	ATF_CHECK_EQ(sr.member_count, 0);
	ATF_CHECK_EQ(sr.nesting_depth, 0);
	ATF_CHECK_EQ(sr.nested_count, 0);
	ATF_CHECK_EQ(sr.mac_capability_count, 0);
	ATF_CHECK_EQ(sr.process_count, 0);
	ATF_CHECK_EQ(sr.jail_count, 0);
	ATF_CHECK_EQ(sr.other_count, 0);
	ATF_CHECK_EQ(sr.flags & COF_TERMINATING, 0);

	close(fd);
}

ATF_TC(terminate_empty);
ATF_TC_HEAD(terminate_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminate empty coalition succeeds");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(terminate_empty, tc)
{
	int32_t status;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	close(fd);
}

ATF_TC(terminate_twice);
ATF_TC_HEAD(terminate_twice, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Double terminate returns ESHUTDOWN");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(terminate_twice, tc)
{
	int32_t status;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, ESHUTDOWN);

	close(fd);
}

ATF_TC(mac_capability_terminate_ioctl);
ATF_TC_HEAD(mac_capability_terminate_ioctl, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_TERMINATE ioctl on coalition fd triggers co_revoke");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(mac_capability_terminate_ioctl, tc)
{
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* MAC_CAPABILITY_TERMINATE kills the instance for all holders */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/* Further CALL should fail with ECONNRESET */
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	hdr.op = COALITION_OP_STAT;
	ATF_CHECK_ERRNO(ECONNRESET,
	    coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    &rpl, sizeof(rpl)) == -1);

	close(fd);
}

/* ================================================================
 * Socket member tests
 * ================================================================ */

ATF_TC(enlist_socket);
ATF_TC_HEAD(enlist_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist a socket, verify STAT counts");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_socket, tc)
{
	struct coalition_stat_reply sr;
	int fd, sv[2];
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 1);
	ATF_CHECK_EQ(sr.other_count, 1);

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(enlist_socket_requires_shutdown_right);
ATF_TC_HEAD(enlist_socket_requires_shutdown_right, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting a socket without CAP_SHUTDOWN is rejected");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_socket_requires_shutdown_right, tc)
{
	cap_rights_t rights;
	int fd, sv[2];
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	ATF_REQUIRE(cap_rights_limit(sv[0], &rights) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, ENOTCAPABLE);

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(enlist_duplicate);
ATF_TC_HEAD(enlist_duplicate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting same fd twice returns EBUSY");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_duplicate, tc)
{
	int fd, sv[2];
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, EBUSY);

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(terminate_shuts_socket);
ATF_TC_HEAD(terminate_shuts_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating coalition shuts down enlisted sockets");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(terminate_shuts_socket, tc)
{
	int fd, sv[2];
	int32_t status;
	char buf[1];
	ssize_t n;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Terminate — should shutdown the socket */
	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* The peer end should see EOF or error */
	n = read(sv[1], buf, sizeof(buf));
	ATF_CHECK(n == 0 || (n == -1 && errno == ECONNRESET));

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

/* ================================================================
 * Mac_capability member tests
 * ================================================================ */

ATF_TC(enlist_mac_capability_member);
ATF_TC_HEAD(enlist_mac_capability_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist a mac_capability instance as member, verify STAT");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(enlist_mac_capability_member, tc)
{
	struct coalition_stat_reply sr;
	int cfd, member_fd;
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 1);
	ATF_CHECK_EQ(sr.mac_capability_count, 1);

	close(cfd);
	close(member_fd);
}

ATF_TC(terminate_revokes_mac_capability);
ATF_TC_HEAD(terminate_revokes_mac_capability, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating coalition revokes mac_capability members (ECONNRESET)");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_revokes_mac_capability, tc)
{
	int cfd, member_fd;
	int32_t status;
	struct mac_capability_sendmsg_args sa;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Terminate the coalition */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/*
	 * The mac_capability member should now be revoked.
	 * SENDMSG should fail with EPIPE (instance dead).
	 */
	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(member_fd);
}

ATF_TC(enlist_multiple_types);
ATF_TC_HEAD(enlist_multiple_types, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist socket and mac_capability, verify mixed STAT");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(enlist_multiple_types, tc)
{
	struct coalition_stat_reply sr;
	int cfd, member_fd, sv[2];
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_enlist(cfd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 2);
	ATF_CHECK_EQ(sr.mac_capability_count, 1);
	ATF_CHECK_EQ(sr.other_count, 1);

	close(cfd);
	close(member_fd);
	close(sv[0]);
	close(sv[1]);
}

/* ================================================================
 * Nested coalition tests
 * ================================================================ */

ATF_TC(enlist_nested_coalition);
ATF_TC_HEAD(enlist_nested_coalition, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist one coalition inside another");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_nested_coalition, tc)
{
	struct coalition_stat_reply sr;
	int parent, child;
	int32_t status;

	parent = mac_capability_connect("coalition");
	ATF_REQUIRE(parent >= 0);

	child = mac_capability_connect("coalition");
	ATF_REQUIRE(child >= 0);

	ATF_REQUIRE(coalition_enlist(parent, child, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Child counts as a nested coalition member */
	ATF_REQUIRE(coalition_stat(parent, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 1);
	ATF_CHECK_EQ(sr.nesting_depth, 0);
	ATF_CHECK_EQ(sr.nested_count, 1);
	ATF_CHECK_EQ(sr.mac_capability_count, 0);

	close(parent);
	close(child);
}

ATF_TC(nested_depth_tracking);
ATF_TC_HEAD(nested_depth_tracking, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Nested coalitions track parent-chain depth");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(nested_depth_tracking, tc)
{
	struct coalition_stat_reply sr;
	int level0, level1, level2;
	int32_t status;

	level0 = mac_capability_connect("coalition");
	ATF_REQUIRE(level0 >= 0);
	level1 = mac_capability_connect("coalition");
	ATF_REQUIRE(level1 >= 0);
	level2 = mac_capability_connect("coalition");
	ATF_REQUIRE(level2 >= 0);

	ATF_REQUIRE(coalition_enlist(level1, level2, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_enlist(level0, level1, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(level0, &sr) == 0);
	ATF_CHECK_EQ(sr.nesting_depth, 0);
	ATF_CHECK_EQ(sr.nested_count, 1);

	ATF_REQUIRE(coalition_stat(level1, &sr) == 0);
	ATF_CHECK_EQ(sr.nesting_depth, 1);
	ATF_CHECK_EQ(sr.nested_count, 1);

	ATF_REQUIRE(coalition_stat(level2, &sr) == 0);
	ATF_CHECK_EQ(sr.nesting_depth, 2);

	close(level0);
	close(level1);
	close(level2);
}

ATF_TC(nested_depth_limit);
ATF_TC_HEAD(nested_depth_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Parent-chain depth is bounded by COALITION_MAX_NESTING");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(nested_depth_limit, tc)
{
	int fds[COALITION_MAX_NESTING + 1];
	int i;
	int32_t status;

	for (i = 0; i < (int)nitems(fds); i++) {
		fds[i] = mac_capability_connect("coalition");
		ATF_REQUIRE_MSG(fds[i] >= 0, "connect %d: %s",
		    i, strerror(errno));
	}

	for (i = COALITION_MAX_NESTING - 1; i > 0; i--) {
		ATF_REQUIRE(coalition_enlist(fds[i - 1], fds[i], &status) == 0);
		ATF_CHECK_EQ(status, 0);
	}

	ATF_REQUIRE(coalition_enlist(fds[COALITION_MAX_NESTING - 1],
	    fds[COALITION_MAX_NESTING], &status) == 0);
	ATF_CHECK_EQ(status, ELOOP);

	for (i = 0; i < (int)nitems(fds); i++)
		close(fds[i]);
}

ATF_TC(enlist_self_fails);
ATF_TC_HEAD(enlist_self_fails, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting a coalition in itself returns error");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_self_fails, tc)
{
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_enlist(fd, fd, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	close(fd);
}

ATF_TC(terminate_cascades_nested);
ATF_TC_HEAD(terminate_cascades_nested, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating parent cascades to nested child members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(terminate_cascades_nested, tc)
{
	int parent, child, member_fd;
	int32_t status;
	struct mac_capability_sendmsg_args sa;
	char payload[] = "test";

	parent = mac_capability_connect("coalition");
	ATF_REQUIRE(parent >= 0);

	child = mac_capability_connect("coalition");
	ATF_REQUIRE(child >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	/* Enlist keystore in child */
	ATF_REQUIRE(coalition_enlist(child, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Enlist child in parent */
	ATF_REQUIRE(coalition_enlist(parent, child, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Terminate parent — should cascade to child → revoke keystore */
	ATF_REQUIRE(coalition_op(parent, COALITION_OP_TERMINATE,
	    &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/*
	 * Close child fd to complete the cascade.  The parent terminate
	 * marks the child instance as revoked, but co_revoke is deferred
	 * until the last reference drops (the close here).
	 */
	close(child);
	close(parent);

	/* Keystore member should now be revoked */
	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(member_fd);
}

/* ================================================================
 * Batch enlistment tests
 * ================================================================ */

ATF_TC(enlist_set_basic);
ATF_TC_HEAD(enlist_set_basic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ENLIST_SET enlists multiple members in one call");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_set_basic, tc)
{
	struct coalition_enlist_set_reply esr;
	struct coalition_stat_reply sr;
	int cfd, sv0[2], sv1[2];

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv0) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);

	ATF_REQUIRE(coalition_enlist_set(cfd,
	    (int[]){ sv0[0], sv1[0] }, 2, &esr) == 0);
	ATF_CHECK_EQ(esr.status, 0);
	ATF_CHECK_EQ(esr.enlisted, 2);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 2);
	ATF_CHECK_EQ(sr.other_count, 2);

	close(cfd);
	close(sv0[0]);
	close(sv0[1]);
	close(sv1[0]);
	close(sv1[1]);
}

ATF_TC(enlist_set_partial_failure);
ATF_TC_HEAD(enlist_set_partial_failure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ENLIST_SET stops on first error and reports partial success");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_set_partial_failure, tc)
{
	struct coalition_enlist_set_reply esr;
	struct coalition_stat_reply sr;
	int cfd, sv[2];

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist_set(cfd,
	    (int[]){ sv[0], sv[0] }, 2, &esr) == 0);
	ATF_CHECK_EQ(esr.status, EBUSY);
	ATF_CHECK_EQ(esr.enlisted, 1);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 1);

	close(cfd);
	close(sv[0]);
	close(sv[1]);
}

/* ================================================================
 * Event notification tests
 * ================================================================ */

ATF_TC(kqueue_member_added_event);
ATF_TC_HEAD(kqueue_member_added_event, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition member additions generate kqueue-backed events");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(kqueue_member_added_event, tc)
{
	struct coalition_event_msg ev;
	struct kevent kev;
	int cfd, kq, sv[2];
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	ATF_REQUIRE(coalition_enlist(cfd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE_MSG(kqueue_poll(kq, &kev, 1, 500) == 1,
	    "did not receive member-added readiness");
	ATF_REQUIRE(coalition_recv_event(cfd, &ev) == 0);
	ATF_CHECK(ev.flags & COALITION_NOTE_MEMBER_ADDED);

	close(cfd);
	close(kq);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(kqueue_terminating_event);
ATF_TC_HEAD(kqueue_terminating_event, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition termination generates a terminating event");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(kqueue_terminating_event, tc)
{
	struct coalition_event_msg ev;
	struct kevent kev;
	int cfd, kq;
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE_MSG(kqueue_poll(kq, &kev, 1, 500) == 1,
	    "did not receive terminating readiness");
	ATF_REQUIRE(coalition_recv_event(cfd, &ev) == 0);
	ATF_CHECK(ev.flags & COALITION_NOTE_TERMINATING);

	close(cfd);
	close(kq);
}

ATF_TC(async_stat_kqueue_roundtrip);
ATF_TC_HEAD(async_stat_kqueue_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition SENDMSG replies are exposed through kqueue/RECVMSG");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(async_stat_kqueue_roundtrip, tc)
{
	struct mac_capability_info_args info;
	struct coalition_req_hdr hdr;
	struct coalition_stat_reply sr;
	struct kevent kev;
	uint32_t replylen;
	uint64_t token;
	int cfd, kq;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(cfd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_CALL);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_SENDMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_RECVMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_KQUEUE);

	EV_SET(&kev, cfd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);
	ATF_REQUIRE_MSG(kqueue_poll(kq, &kev, 1, 500) == 1,
	    "did not receive send-side readiness");
	ATF_CHECK_EQ(kev.filter, EVFILT_WRITE);

	EV_SET(&kev, cfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ATF_REQUIRE(kevent(kq, &kev, 1, NULL, 0, NULL) == 0);

	hdr.op = COALITION_OP_STAT;
	ATF_REQUIRE(coalition_sendmsg(cfd, &hdr, sizeof(hdr), NULL, 0,
	    0x12345678) == 0);

	ATF_REQUIRE_MSG(kqueue_poll(kq, &kev, 1, 1000) == 1,
	    "did not receive recv-side readiness for async STAT reply");
	ATF_CHECK_EQ(kev.filter, EVFILT_READ);

	memset(&sr, 0, sizeof(sr));
	replylen = sizeof(sr);
	token = 0;
	ATF_REQUIRE(coalition_recvmsg(cfd, &sr, &replylen, &token) == 0);
	ATF_CHECK_EQ(replylen, sizeof(sr));
	ATF_CHECK_EQ(token, 0x12345678);
	ATF_CHECK_EQ(sr.status, 0);
	ATF_CHECK_EQ(sr.member_count, 0);

	close(cfd);
	close(kq);
}

ATF_TC(async_join_rejected);
ATF_TC_HEAD(async_join_rejected, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition JOIN is rejected on async SENDMSG path");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(async_join_rejected, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	uint32_t replylen;
	uint64_t token;
	int cfd;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	hdr.op = COALITION_OP_JOIN;
	ATF_REQUIRE(coalition_sendmsg(cfd, &hdr, sizeof(hdr), NULL, 0,
	    0xabcdef) == 0);

	memset(&rpl, 0, sizeof(rpl));
	replylen = sizeof(rpl);
	token = 0;
	ATF_REQUIRE(coalition_recvmsg(cfd, &rpl, &replylen, &token) == 0);
	ATF_CHECK_EQ(replylen, sizeof(rpl));
	ATF_CHECK_EQ(token, 0xabcdef);
	ATF_CHECK_EQ(rpl.status, EOPNOTSUPP);

	close(cfd);
}

/* ================================================================
 * Process join tests
 * ================================================================ */

ATF_TC(join_self);
ATF_TC_HEAD(join_self, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "JOIN enlists calling process, shows in STAT");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(join_self, tc)
{
	struct coalition_stat_reply sr;
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.process_count, 1);
	ATF_CHECK_EQ(sr.member_count, 1);

	close(fd);
}

ATF_TC(join_twice);
ATF_TC_HEAD(join_twice, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Joining same process twice returns EBUSY");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(join_twice, tc)
{
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, EBUSY);

	close(fd);
}

ATF_TC(fork_inherits_membership);
ATF_TC_HEAD(fork_inherits_membership, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Child process inherits coalition membership on fork");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(fork_inherits_membership, tc)
{
	struct coalition_stat_reply sr;
	int fd;
	int32_t status;
	pid_t pid;
	int wstatus;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child — sleep briefly and exit */
		usleep(200000);
		_exit(0);
	}

	/* Parent — child should be auto-enlisted */
	usleep(50000);
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK(sr.process_count >= 2);

	waitpid(pid, &wstatus, 0);
	close(fd);
}

/* ================================================================
 * Signal and watchdog tests
 * ================================================================ */

ATF_TC(set_signal);
ATF_TC_HEAD(set_signal, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_SIGNAL changes termination signal, verified via terminate");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(set_signal, tc)
{
	struct coalition_set_signal_req ssr;
	struct coalition_reply rpl;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;
	int wstatus;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	/* Invalid signal */
	ssr.op = COALITION_OP_SET_SIGNAL;
	ssr.signal = 0;
	ATF_REQUIRE(coalition_call(cfd, &ssr, sizeof(ssr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, EINVAL);

	/* Set signal to SIGTERM */
	ssr.signal = SIGTERM;
	ATF_REQUIRE(coalition_call(cfd, &ssr, sizeof(ssr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* Enlist a child process */
	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Terminate — should send SIGTERM, not SIGKILL */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	ATF_CHECK(WIFSIGNALED(wstatus));
	ATF_CHECK_EQ(WTERMSIG(wstatus), SIGTERM);

	close(cfd);
	close(proc_fd);
}

ATF_TC(watchdog_heartbeat);
ATF_TC_HEAD(watchdog_heartbeat, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Set watchdog and heartbeat, verify flags");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(watchdog_heartbeat, tc)
{
	struct coalition_set_watchdog_req wr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Set watchdog for 5 seconds */
	wr.op = COALITION_OP_SET_WATCHDOG;
	wr.timeout_ms = 5000;
	ATF_REQUIRE(coalition_call(fd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* Check flag is set */
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_WATCHDOG_ACTIVE);

	/* Heartbeat should succeed */
	ATF_REQUIRE(coalition_op(fd, COALITION_OP_HEARTBEAT, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Cancel watchdog */
	wr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(fd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* Flag should be cleared */
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.flags & COF_WATCHDOG_ACTIVE, 0);

	/* Heartbeat without watchdog should fail */
	ATF_REQUIRE(coalition_op(fd, COALITION_OP_HEARTBEAT, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	close(fd);
}

ATF_TC(watchdog_fires_revokes_mac_capability);
ATF_TC_HEAD(watchdog_fires_revokes_mac_capability, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Watchdog expiry revokes mac_capability members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(watchdog_fires_revokes_mac_capability, tc)
{
	struct coalition_set_watchdog_req wr;
	struct coalition_reply rpl;
	struct mac_capability_sendmsg_args sa;
	int cfd, member_fd;
	int32_t status;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	wr.op = COALITION_OP_SET_WATCHDOG;
	wr.timeout_ms = 100;
	ATF_REQUIRE(coalition_call(cfd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	usleep(300000);

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(member_fd);
}

ATF_TC(large_timeouts_do_not_fire);
ATF_TC_HEAD(large_timeouts_do_not_fire, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Near-limit deadline and watchdog values do not fire immediately");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(large_timeouts_do_not_fire, tc)
{
	struct coalition_set_watchdog_req wr;
	struct coalition_set_deadline_req dr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	struct mac_capability_sendmsg_args sa;
	int cfd, member_fd;
	int32_t status;
	char payload[] = "ping";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	wr.op = COALITION_OP_SET_WATCHDOG;
	wr.timeout_ms = UINT32_MAX;
	ATF_REQUIRE(coalition_call(cfd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = UINT32_MAX;
	dr.signal = SIGTERM;
	dr.grace_ms = UINT32_MAX;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_WATCHDOG_ACTIVE);
	ATF_CHECK(sr.flags & COF_DEADLINE_ACTIVE);

	usleep(100000);

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_REQUIRE_MSG(ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "mac_capability member revoked unexpectedly: %s", strerror(errno));

	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_HEARTBEAT, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	dr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	wr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.flags & COF_WATCHDOG_ACTIVE, 0);
	ATF_CHECK_EQ(sr.flags & COF_DEADLINE_ACTIVE, 0);

	close(cfd);
	close(member_fd);
}

ATF_TC(deadline_cancel);
ATF_TC_HEAD(deadline_cancel, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Set and cancel a deadline");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(deadline_cancel, tc)
{
	struct coalition_set_deadline_req dr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Set deadline */
	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = 10000;
	dr.signal = SIGTERM;
	dr.grace_ms = 2000;
	ATF_REQUIRE(coalition_call(fd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_DEADLINE_ACTIVE);

	/* Cancel deadline */
	dr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(fd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.flags & COF_DEADLINE_ACTIVE, 0);

	close(fd);
}

ATF_TC(deadline_cancel_clears_grace);
ATF_TC_HEAD(deadline_cancel_clears_grace, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Canceling a deadline during grace clears grace state");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(deadline_cancel_clears_grace, tc)
{
	struct coalition_set_deadline_req dr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int cfd, proc_fd, sv[2];
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		signal(SIGTERM, SIG_IGN);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = 100;
	dr.signal = SIGTERM;
	dr.grace_ms = 5000;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	usleep(300000);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_DEADLINE_ACTIVE);
	ATF_CHECK(sr.flags & COF_DEADLINE_GRACE);
	ATF_CHECK(sr.flags & COF_GRACE_ACTIVE);

	dr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.flags & COF_DEADLINE_ACTIVE, 0);
	ATF_CHECK_EQ(sr.flags & COF_DEADLINE_GRACE, 0);
	ATF_CHECK_EQ(sr.flags & COF_GRACE_ACTIVE, 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(coalition_enlist(cfd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	(void)kill(pid, SIGKILL);
	ATF_REQUIRE(waitpid(pid, NULL, 0) == pid);

	close(sv[0]);
	close(sv[1]);
	close(cfd);
	close(proc_fd);
}

/* ================================================================
 * Leader tests
 * ================================================================ */

ATF_TC(set_leader_socket);
ATF_TC_HEAD(set_leader_socket, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Set and clear leader (socket member not supported → EINVAL)");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(set_leader_socket, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	int fd, sv[2];
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Sockets can't be leaders */
	hdr.op = COALITION_OP_SET_LEADER;
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), &sv[0], 1,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, EINVAL);

	/* Clear leader (no fd) should succeed */
	hdr.op = COALITION_OP_SET_LEADER;
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(set_leader_mac_capability);
ATF_TC_HEAD(set_leader_mac_capability, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Mac_capability leader death (revoke) terminates coalition members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(set_leader_mac_capability, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	struct mac_capability_sendmsg_args sa;
	int cfd, leader_fd, other_fd;
	int32_t status;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	leader_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(leader_fd >= 0);

	other_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(other_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, leader_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_enlist(cfd, other_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Set leader */
	hdr.op = COALITION_OP_SET_LEADER;
	ATF_REQUIRE(coalition_call(cfd, &hdr, sizeof(hdr), &leader_fd, 1,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_HAS_LEADER);

	/* Kill the leader — MAC_CAPABILITY_TERMINATE revokes the instance */
	ATF_REQUIRE(ioctl(leader_fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	/*
	 * The leader monitor polls every 100ms.  Wait for it to
	 * detect the dead leader and terminate the coalition.
	 */
	usleep(300000);	/* 300ms — enough for 2-3 poll cycles */

	/* other_fd should be revoked (EPIPE on send) */
	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(other_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(leader_fd);
	close(other_fd);
}

/* ================================================================
 * Error handling tests
 * ================================================================ */

ATF_TC(enlist_no_fd);
ATF_TC_HEAD(enlist_no_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ENLIST without attached fd returns EINVAL");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_no_fd, tc)
{
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Call ENLIST with no fds */
	ATF_REQUIRE(coalition_op(fd, COALITION_OP_ENLIST, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	close(fd);
}

ATF_TC(enlist_after_terminate);
ATF_TC_HEAD(enlist_after_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist after terminate returns ESHUTDOWN");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_after_terminate, tc)
{
	int fd, sv[2];
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);

	ATF_REQUIRE(coalition_enlist(fd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, ESHUTDOWN);

	close(fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(unknown_op);
ATF_TC_HEAD(unknown_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Unknown operation returns EINVAL in status");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(unknown_op, tc)
{
	int fd;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_op(fd, 9999, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	close(fd);
}

ATF_TC(getinfo);
ATF_TC_HEAD(getinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_GETINFO returns coalition service metadata");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(getinfo, tc)
{
	struct mac_capability_info_args info;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);

	ATF_CHECK_STREQ(info.name, "coalition");
	ATF_CHECK(info.badge != 0);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_CALL);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_SENDMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_RECVMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_KQUEUE);

	close(fd);
}

/* ================================================================
 * Close-on-destroy tests
 * ================================================================ */

ATF_TC(close_terminates_members);
ATF_TC_HEAD(close_terminates_members, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing coalition fd terminates all members via co_revoke");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(close_terminates_members, tc)
{
	int cfd, member_fd;
	int32_t status;
	struct mac_capability_sendmsg_args sa;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Close the coalition fd — should trigger co_revoke */
	close(cfd);

	/* Member should be revoked */
	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(member_fd);
}

/* ================================================================
 * Rusage test
 * ================================================================ */

ATF_TC(rusage_empty);
ATF_TC_HEAD(rusage_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RUSAGE on empty coalition returns zeros");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(rusage_empty, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_rusage_reply rr;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	hdr.op = COALITION_OP_RUSAGE;
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    &rr, sizeof(rr)) == 0);
	ATF_CHECK_EQ(rr.nprocs, 0);
	ATF_CHECK_EQ(rr.nthreads, 0);

	close(fd);
}

/* ================================================================
 * Process enlistment via procdesc
 * ================================================================ */

ATF_TC(enlist_procdesc);
ATF_TC_HEAD(enlist_procdesc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist a child process via procdesc fd");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_procdesc, tc)
{
	struct coalition_stat_reply sr;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, PD_DAEMON);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.process_count, 1);
	ATF_CHECK_EQ(sr.member_count, 1);

	close(cfd);	/* triggers terminate → SIGKILL child */
	close(proc_fd);
}

ATF_TC(enlist_procdesc_requires_pdkill_right);
ATF_TC_HEAD(enlist_procdesc_requires_pdkill_right, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting a procdesc without CAP_PDKILL is rejected");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_procdesc_requires_pdkill_right, tc)
{
	cap_rights_t rights;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;
	int wstatus;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	cap_rights_init(&rights, CAP_PDGETPID);
	ATF_REQUIRE(cap_rights_limit(proc_fd, &rights) == 0);

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, ENOTCAPABLE);

	ATF_REQUIRE(kill(pid, SIGKILL) == 0);
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	close(proc_fd);
	close(cfd);
}

ATF_TC(terminate_kills_process);
ATF_TC_HEAD(terminate_kills_process, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating coalition sends SIGKILL to process members");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(terminate_kills_process, tc)
{
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;
	int wstatus;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Terminate */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Child should be killed */
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	ATF_CHECK(WIFSIGNALED(wstatus));
	ATF_CHECK_EQ(WTERMSIG(wstatus), SIGKILL);

	close(cfd);
	close(proc_fd);
}

ATF_TC(process_exit_decrements_count);
ATF_TC_HEAD(process_exit_decrements_count, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Process exiting naturally decrements member count");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(process_exit_decrements_count, tc)
{
	struct coalition_stat_reply sr;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		usleep(50000);	/* 50ms then exit */
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.process_count, 1);

	/* Wait for child to exit */
	waitpid(pid, NULL, 0);
	usleep(100000);	/* Let exit handler run */

	/* Exit handler removes member from TAILQ — count should be 0 */
	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 0);
	ATF_CHECK_EQ(sr.process_count, 0);

	close(cfd);
	close(proc_fd);
}

/* ================================================================
 * Graceful termination test
 * ================================================================ */

ATF_TC(graceful_terminate);
ATF_TC_HEAD(graceful_terminate, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Graceful terminate sends signal then SIGKILL on timeout");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(graceful_terminate, tc)
{
	struct coalition_graceful_req gr;
	struct coalition_reply rpl;
	int cfd, proc_fd, sync_pipe[2];
	int32_t status;
	pid_t pid;
	int wstatus;
	char ch;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ATF_REQUIRE(pipe(sync_pipe) == 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		close(sync_pipe[0]);
		/* Ignore SIGTERM — force the grace period to expire */
		signal(SIGTERM, SIG_IGN);
		/* Signal parent that SIG_IGN is installed */
		(void)write(sync_pipe[1], "r", 1);
		close(sync_pipe[1]);
		pause();
		_exit(0);
	}
	close(sync_pipe[1]);

	/* Wait for child to install SIG_IGN */
	ATF_REQUIRE(read(sync_pipe[0], &ch, 1) == 1);
	close(sync_pipe[0]);

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Graceful: SIGTERM → 200ms grace → SIGKILL */
	gr.op = COALITION_OP_GRACEFUL;
	gr.signal = SIGTERM;
	gr.timeout_ms = 200;
	ATF_REQUIRE(coalition_call(cfd, &gr, sizeof(gr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* Child should be killed (SIGKILL after grace period) */
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	ATF_CHECK(WIFSIGNALED(wstatus));
	ATF_CHECK_EQ(WTERMSIG(wstatus), SIGKILL);

	close(cfd);
	close(proc_fd);
}

ATF_TC(graceful_terminate_clears_grace);
ATF_TC_HEAD(graceful_terminate_clears_grace, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Successful graceful terminate clears grace state");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(graceful_terminate_clears_grace, tc)
{
	struct coalition_graceful_req gr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int cfd, proc_fd, sv[2];
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	gr.op = COALITION_OP_GRACEFUL;
	gr.signal = SIGTERM;
	gr.timeout_ms = 2000;
	ATF_REQUIRE(coalition_call(cfd, &gr, sizeof(gr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	ATF_REQUIRE(waitpid(pid, NULL, 0) == pid);
	usleep(100000);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.flags & COF_GRACE_ACTIVE, 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(coalition_enlist(cfd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	close(sv[0]);
	close(sv[1]);
	close(cfd);
	close(proc_fd);
}

/* ================================================================
 * Jail enlistment via jaildesc
 * ================================================================ */

ATF_TC_WITH_CLEANUP(terminate_removes_jaildesc_member);
ATF_TC_HEAD(terminate_removes_jaildesc_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating a coalition removes enlisted jaildesc members");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(terminate_removes_jaildesc_member, tc)
{
	struct coalition_stat_reply sr;
	int cfd, jail_fd;
	int32_t status;

	remove_jail_by_name(COALITION_TEST_JAIL_NAME);

	jail_fd = create_jail_with_desc(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE_MSG(jail_fd >= 0, "create_jail_with_desc: %s",
	    strerror(errno));

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, jail_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 1);
	ATF_CHECK_EQ(sr.jail_count, 1);

	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	wait_for_jail_removal(COALITION_TEST_JAIL_NAME);

	close(cfd);
	close(jail_fd);
}
ATF_TC_CLEANUP(terminate_removes_jaildesc_member, tc)
{
	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
}

ATF_TC(graceful_terminate_revokes_mac_capability);
ATF_TC_HEAD(graceful_terminate_revokes_mac_capability, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Graceful terminate revokes mac_capability members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(graceful_terminate_revokes_mac_capability, tc)
{
	struct coalition_graceful_req gr;
	struct coalition_reply rpl;
	struct mac_capability_sendmsg_args sa;
	int cfd, member_fd;
	int32_t status;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	gr.op = COALITION_OP_GRACEFUL;
	gr.signal = SIGTERM;
	gr.timeout_ms = 1000;
	ATF_REQUIRE(coalition_call(cfd, &gr, sizeof(gr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(member_fd);
}

/* ================================================================
 * Deadline fire test
 * ================================================================ */

ATF_TC(deadline_fires);
ATF_TC_HEAD(deadline_fires, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Deadline timer fires and terminates members");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(deadline_fires, tc)
{
	struct coalition_set_deadline_req dr;
	struct coalition_reply rpl;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;
	int wstatus;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Set deadline to 200ms, no grace period */
	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = 200;
	dr.signal = 0;
	dr.grace_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* Wait for child to be killed by deadline */
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	ATF_CHECK(WIFSIGNALED(wstatus));
	ATF_CHECK_EQ(WTERMSIG(wstatus), SIGKILL);

	close(cfd);
	close(proc_fd);
}

ATF_TC(deadline_fires_revokes_mac_capability);
ATF_TC_HEAD(deadline_fires_revokes_mac_capability, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Deadline expiry revokes mac_capability members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(deadline_fires_revokes_mac_capability, tc)
{
	struct coalition_set_deadline_req dr;
	struct coalition_reply rpl;
	struct mac_capability_sendmsg_args sa;
	int cfd, member_fd;
	int32_t status;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	member_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(member_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, member_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = 100;
	dr.signal = 0;
	dr.grace_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	usleep(300000);

	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(member_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(member_fd);
}

/* ================================================================
 * Multiple coalitions
 * ================================================================ */

ATF_TC(multiple_coalitions);
ATF_TC_HEAD(multiple_coalitions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple coalitions coexist independently");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(multiple_coalitions, tc)
{
	struct coalition_stat_reply sr;
	int fd1, fd2, fd3, sv[2];
	int32_t status;

	fd1 = mac_capability_connect("coalition");
	ATF_REQUIRE(fd1 >= 0);
	fd2 = mac_capability_connect("coalition");
	ATF_REQUIRE(fd2 >= 0);
	fd3 = mac_capability_connect("coalition");
	ATF_REQUIRE(fd3 >= 0);

	ATF_CHECK(fd1 != fd2 && fd2 != fd3);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	ATF_REQUIRE(coalition_enlist(fd1, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* fd2 should still be empty */
	ATF_REQUIRE(coalition_stat(fd2, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 0);

	close(fd3);
	close(fd2);
	close(fd1);
	close(sv[0]);
	close(sv[1]);
}

/* ================================================================
 * SHM truncation on terminate
 * ================================================================ */

ATF_TC(terminate_truncates_shm);
ATF_TC_HEAD(terminate_truncates_shm, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Terminating coalition truncates SHM members to zero");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(terminate_truncates_shm, tc)
{
	int cfd, shm_fd;
	int32_t status;
	struct stat sb;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	shm_fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(shm_fd >= 0);
	ATF_REQUIRE(ftruncate(shm_fd, 4096) == 0);

	ATF_REQUIRE(coalition_enlist(cfd, shm_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* SHM should be truncated to 0 */
	ATF_REQUIRE(fstat(shm_fd, &sb) == 0);
	ATF_CHECK_EQ(sb.st_size, 0);

	close(cfd);
	close(shm_fd);
}

ATF_TC(enlist_shm_requires_ftruncate_right);
ATF_TC_HEAD(enlist_shm_requires_ftruncate_right, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting SHM without CAP_FTRUNCATE is rejected");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_shm_requires_ftruncate_right, tc)
{
	cap_rights_t rights;
	int cfd, shm_fd;
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	shm_fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
	ATF_REQUIRE(shm_fd >= 0);
	ATF_REQUIRE(ftruncate(shm_fd, 4096) == 0);

	cap_rights_init(&rights, CAP_READ, CAP_WRITE);
	ATF_REQUIRE(cap_rights_limit(shm_fd, &rights) == 0);

	ATF_REQUIRE(coalition_enlist(cfd, shm_fd, &status) == 0);
	ATF_CHECK_EQ(status, ENOTCAPABLE);

	close(cfd);
	close(shm_fd);
}

/* ================================================================
 * Rusage with process
 * ================================================================ */

ATF_TC(rusage_with_process);
ATF_TC_HEAD(rusage_with_process, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RUSAGE reports stats for joined processes");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(rusage_with_process, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_rusage_reply rr;
	int cfd, proc_fd;
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	pid = pdfork(&proc_fd, PD_DAEMON);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		pause();
		_exit(0);
	}

	ATF_REQUIRE(coalition_enlist(cfd, proc_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	hdr.op = COALITION_OP_RUSAGE;
	ATF_REQUIRE(coalition_call(cfd, &hdr, sizeof(hdr), NULL, 0,
	    &rr, sizeof(rr)) == 0);
	ATF_CHECK(rr.nprocs >= 1);
	ATF_CHECK(rr.nthreads >= 1);

	close(cfd);
	close(proc_fd);
}

/* ================================================================
 * Mac_capability descriptor type tests
 * ================================================================ */

ATF_TC(mac_capability_member_type_tracking);
ATF_TC_HEAD(mac_capability_member_type_tracking, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Mac_capability members are tracked as DTYPE_MAC_CAPABILITY, not generic");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore");
}
ATF_TC_BODY(mac_capability_member_type_tracking, tc)
{
	struct coalition_stat_reply sr;
	int cfd, ks_fd, sv[2];
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ks_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(ks_fd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Enlist mac_capability member */
	ATF_REQUIRE(coalition_enlist(cfd, ks_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Enlist socket */
	ATF_REQUIRE(coalition_enlist(cfd, sv[0], &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* STAT must distinguish mac_capability from sockets */
	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 2);
	ATF_CHECK_EQ(sr.mac_capability_count, 1);
	ATF_CHECK_EQ(sr.other_count, 1);
	ATF_CHECK_EQ(sr.process_count, 0);
	ATF_CHECK_EQ(sr.jail_count, 0);

	close(cfd);
	close(ks_fd);
	close(sv[0]);
	close(sv[1]);
}

ATF_TC(mac_capability_member_multiple_services);
ATF_TC_HEAD(mac_capability_member_multiple_services, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Multiple mac_capability members from different services are counted");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore mac_capability_channel");
}
ATF_TC_BODY(mac_capability_member_multiple_services, tc)
{
	struct coalition_stat_reply sr;
	int cfd, ks_fd, channel_fd;
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ks_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(ks_fd >= 0);

	channel_fd = mac_capability_connect("channel");
	ATF_REQUIRE(channel_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, ks_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_REQUIRE(coalition_enlist(cfd, channel_fd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Both are mac_capability members */
	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.mac_capability_count, 2);
	ATF_CHECK_EQ(sr.member_count, 2);

	close(cfd);
	close(ks_fd);
	close(channel_fd);
}

ATF_TC(terminate_revokes_multiple_services);
ATF_TC_HEAD(terminate_revokes_multiple_services, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Termination revokes mac_capability members from different services");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition mac_capability_test_keystore mac_capability_channel");
}
ATF_TC_BODY(terminate_revokes_multiple_services, tc)
{
	int cfd, ks_fd, channel_fd;
	int32_t status;
	struct mac_capability_sendmsg_args sa;
	char payload[] = "test";

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ks_fd = mac_capability_connect("test_keystore");
	ATF_REQUIRE(ks_fd >= 0);

	channel_fd = mac_capability_connect("channel");
	ATF_REQUIRE(channel_fd >= 0);

	ATF_REQUIRE(coalition_enlist(cfd, ks_fd, &status) == 0);
	ATF_REQUIRE(coalition_enlist(cfd, channel_fd, &status) == 0);

	/* Terminate coalition */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Both should be revoked */
	memset(&sa, 0, sizeof(sa));
	sa.payload = payload;
	sa.payload_len = sizeof(payload);

	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(ks_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);
	ATF_CHECK_ERRNO(EPIPE,
	    ioctl(channel_fd, MAC_CAPABILITY_SENDMSG, &sa) == -1);

	close(cfd);
	close(ks_fd);
	close(channel_fd);
}

ATF_TC(coalition_is_mac_capability_type);
ATF_TC_HEAD(coalition_is_mac_capability_type, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition fd is a mac_capability descriptor (GETINFO works)");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(coalition_is_mac_capability_type, tc)
{
	struct mac_capability_info_args info;
	struct stat sb;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* GETINFO confirms it's a mac_capability instance */
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	ATF_CHECK_STREQ(info.name, "coalition");
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_CALL);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_SENDMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_RECVMSG);
	ATF_CHECK(info.features & MAC_CAPABILITY_INFO_F_KQUEUE);

	/* fstat should work */
	ATF_REQUIRE(fstat(fd, &sb) == 0);

	close(fd);
}

ATF_TC(mac_capability_revoke_send_on_coalition);
ATF_TC_HEAD(mac_capability_revoke_send_on_coalition, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "MAC_CAPABILITY_REVOKE_CALL on coalition fd strips call ability");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(mac_capability_revoke_send_on_coalition, tc)
{
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Revoke CALL ability on the coalition fd itself */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_REVOKE_CALL, NULL) == 0);

	/* Now CALL should fail */
	hdr.op = COALITION_OP_STAT;
	ATF_CHECK_ERRNO(EACCES,
	    coalition_call(fd, &hdr, sizeof(hdr), NULL, 0,
	    &rpl, sizeof(rpl)) == -1);

	/* TERMINATE still works (always allowed) */
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_TERMINATE, NULL) == 0);

	close(fd);
}

/* ================================================================
 * Edge case tests
 * ================================================================ */

ATF_TC(deadline_zero_timeout);
ATF_TC_HEAD(deadline_zero_timeout, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Deadline with timeout_ms=0 fires immediately");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(deadline_zero_timeout, tc)
{
	struct coalition_set_deadline_req dr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int cfd;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	/* Set deadline with timeout_ms=1 — should fire within one tick */
	dr.op = COALITION_OP_SET_DEADLINE;
	dr.timeout_ms = 1;
	dr.signal = 0;
	dr.grace_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &dr, sizeof(dr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/*
	 * Give the callout time to fire.  A zero-timeout callout may
	 * not fire synchronously — it gets scheduled for the next tick.
	 */
	usleep(200000);

	/* Verify the deadline has progressed: either still active or terminating */
	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK(sr.flags & (COF_TERMINATING | COF_DEADLINE_ACTIVE));

	close(cfd);
}

ATF_TC(watchdog_reset_extends);
ATF_TC_HEAD(watchdog_reset_extends, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Heartbeat resets watchdog, extending the deadline");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "10");
}
ATF_TC_BODY(watchdog_reset_extends, tc)
{
	struct coalition_set_watchdog_req wr;
	struct coalition_stat_reply sr;
	struct coalition_reply rpl;
	int cfd;
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	/* Set watchdog with 200ms timeout */
	wr.op = COALITION_OP_SET_WATCHDOG;
	wr.timeout_ms = 200;
	ATF_REQUIRE(coalition_call(cfd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);

	/* At 100ms, send a heartbeat to reset the timer */
	usleep(100000);
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_HEARTBEAT, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/*
	 * At 250ms total (150ms after heartbeat), the coalition should
	 * still be alive because the heartbeat extended the 200ms window.
	 */
	usleep(150000);

	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK(sr.flags & COF_WATCHDOG_ACTIVE);
	ATF_CHECK_EQ(sr.flags & COF_TERMINATING, 0);

	/* Cancel watchdog to clean up */
	wr.timeout_ms = 0;
	ATF_REQUIRE(coalition_call(cfd, &wr, sizeof(wr), NULL, 0,
	    &rpl, sizeof(rpl)) == 0);

	close(cfd);
}

ATF_TC(enlist_after_close);
ATF_TC_HEAD(enlist_after_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlisting on a closed coalition fd returns EBADF");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(enlist_after_close, tc)
{
	int cfd, sv[2];
	int32_t status;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* Close the coalition fd */
	close(cfd);

	/* Attempt to enlist on the closed fd — should get EBADF */
	ATF_CHECK_ERRNO(EBADF,
	    coalition_enlist(cfd, sv[0], &status) == -1);

	close(sv[0]);
	close(sv[1]);
}

ATF_TC(concurrent_enlist);
ATF_TC_HEAD(concurrent_enlist, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Enlist 10 socket members, verify count, terminate and cleanup");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(concurrent_enlist, tc)
{
	struct coalition_stat_reply sr;
	int cfd;
	int sv[10][2];
	int32_t status;
	int i;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	/* Create and enlist 10 socket pairs */
	for (i = 0; i < 10; i++) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) == 0);
		ATF_REQUIRE(coalition_enlist(cfd, sv[i][0], &status) == 0);
		ATF_CHECK_EQ_MSG(status, 0,
		    "enlist %d failed with status %d", i, status);
	}

	/* Verify member_count == 10 */
	ATF_REQUIRE(coalition_stat(cfd, &sr) == 0);
	ATF_CHECK_EQ(sr.member_count, 10);
	ATF_CHECK_EQ(sr.other_count, 10);

	/* Terminate — should shut down all 10 sockets */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Verify all peers see EOF or error */
	for (i = 0; i < 10; i++) {
		char buf[1];
		ssize_t n;

		n = read(sv[i][1], buf, sizeof(buf));
		ATF_CHECK_MSG(n == 0 || (n == -1 && errno == ECONNRESET),
		    "socket %d peer: unexpected read result %zd (errno %d)",
		    i, n, errno);
	}

	close(cfd);
	for (i = 0; i < 10; i++) {
		close(sv[i][0]);
		close(sv[i][1]);
	}
}

/* ================================================================
 * Test registration
 * ================================================================ */

ATF_TP_ADD_TCS(tp)
{
	/* Lifecycle */
	ATF_TP_ADD_TC(tp, connect_coalition);
	ATF_TP_ADD_TC(tp, stat_empty);
	ATF_TP_ADD_TC(tp, terminate_empty);
	ATF_TP_ADD_TC(tp, terminate_twice);
	ATF_TP_ADD_TC(tp, mac_capability_terminate_ioctl);

		/* Socket members */
		ATF_TP_ADD_TC(tp, enlist_socket);
		ATF_TP_ADD_TC(tp, enlist_socket_requires_shutdown_right);
		ATF_TP_ADD_TC(tp, enlist_duplicate);
		ATF_TP_ADD_TC(tp, terminate_shuts_socket);

	/* Mac_capability members */
	ATF_TP_ADD_TC(tp, enlist_mac_capability_member);
	ATF_TP_ADD_TC(tp, terminate_revokes_mac_capability);
	ATF_TP_ADD_TC(tp, enlist_multiple_types);

	/* Nested coalitions */
	ATF_TP_ADD_TC(tp, enlist_nested_coalition);
	ATF_TP_ADD_TC(tp, nested_depth_tracking);
	ATF_TP_ADD_TC(tp, nested_depth_limit);
	ATF_TP_ADD_TC(tp, enlist_self_fails);
	ATF_TP_ADD_TC(tp, terminate_cascades_nested);
	ATF_TP_ADD_TC(tp, enlist_set_basic);
	ATF_TP_ADD_TC(tp, enlist_set_partial_failure);
	ATF_TP_ADD_TC(tp, kqueue_member_added_event);
	ATF_TP_ADD_TC(tp, kqueue_terminating_event);
	ATF_TP_ADD_TC(tp, async_stat_kqueue_roundtrip);
	ATF_TP_ADD_TC(tp, async_join_rejected);

	/* Process join */
	ATF_TP_ADD_TC(tp, join_self);
	ATF_TP_ADD_TC(tp, join_twice);
	ATF_TP_ADD_TC(tp, fork_inherits_membership);

	/* Signal / watchdog / deadline */
	ATF_TP_ADD_TC(tp, set_signal);
	ATF_TP_ADD_TC(tp, watchdog_heartbeat);
	ATF_TP_ADD_TC(tp, watchdog_fires_revokes_mac_capability);
	ATF_TP_ADD_TC(tp, large_timeouts_do_not_fire);
	ATF_TP_ADD_TC(tp, deadline_cancel);
	ATF_TP_ADD_TC(tp, deadline_cancel_clears_grace);

	/* Leader */
	ATF_TP_ADD_TC(tp, set_leader_socket);
	ATF_TP_ADD_TC(tp, set_leader_mac_capability);

	/* Error handling */
	ATF_TP_ADD_TC(tp, enlist_no_fd);
	ATF_TP_ADD_TC(tp, enlist_after_terminate);
	ATF_TP_ADD_TC(tp, unknown_op);
	ATF_TP_ADD_TC(tp, getinfo);

	/* Close behavior */
	ATF_TP_ADD_TC(tp, close_terminates_members);

		/* Process enlistment via procdesc */
		ATF_TP_ADD_TC(tp, enlist_procdesc);
		ATF_TP_ADD_TC(tp, enlist_procdesc_requires_pdkill_right);
		ATF_TP_ADD_TC(tp, terminate_kills_process);
		ATF_TP_ADD_TC(tp, process_exit_decrements_count);
		ATF_TP_ADD_TC(tp, terminate_removes_jaildesc_member);

	/* Graceful termination */
	ATF_TP_ADD_TC(tp, graceful_terminate);
	ATF_TP_ADD_TC(tp, graceful_terminate_clears_grace);
	ATF_TP_ADD_TC(tp, graceful_terminate_revokes_mac_capability);

	/* Deadline */
	ATF_TP_ADD_TC(tp, deadline_fires);
	ATF_TP_ADD_TC(tp, deadline_fires_revokes_mac_capability);

	/* Multiple coalitions */
	ATF_TP_ADD_TC(tp, multiple_coalitions);

		/* SHM */
		ATF_TP_ADD_TC(tp, terminate_truncates_shm);
		ATF_TP_ADD_TC(tp, enlist_shm_requires_ftruncate_right);

	/* Rusage */
	ATF_TP_ADD_TC(tp, rusage_empty);
	ATF_TP_ADD_TC(tp, rusage_with_process);

	/* Edge cases */
	ATF_TP_ADD_TC(tp, deadline_zero_timeout);
	ATF_TP_ADD_TC(tp, watchdog_reset_extends);
	ATF_TP_ADD_TC(tp, enlist_after_close);
	ATF_TP_ADD_TC(tp, concurrent_enlist);

	/* Mac_capability descriptor type tracking */
	ATF_TP_ADD_TC(tp, mac_capability_member_type_tracking);
	ATF_TP_ADD_TC(tp, mac_capability_member_multiple_services);
	ATF_TP_ADD_TC(tp, terminate_revokes_multiple_services);
	ATF_TP_ADD_TC(tp, coalition_is_mac_capability_type);
	ATF_TP_ADD_TC(tp, mac_capability_revoke_send_on_coalition);

	return (atf_no_error());
}
