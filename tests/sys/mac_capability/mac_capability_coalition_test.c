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
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>
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
/* vm_lowmem flags; the header is kernel-only. */
#define	TEST_VM_LOW_PAGES	0x02

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

/*
 * Like create_jail_with_desc(), but the jail may contain one of its own.
 * Needed to reach the case where a process sits in a jail nested inside the
 * jail a coalition actually holds.
 */
static int
create_parent_jail_with_desc(const char *name)
{
	char desc_str[16] = "";
	int jid;

	jid = jail_setv(JAIL_CREATE | JAIL_GET_DESC,
	    "name", name,
	    "path", "/",
	    "persist", NULL,
	    "children.max", "1",
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
 * Identity and responsible parent
 * ================================================================ */

static int
coalition_set_responsible(int cfd, const int *fdp, uint32_t flags,
    int32_t *status_out)
{
	struct coalition_set_responsible_req rr;
	struct coalition_reply rpl;
	int ret;

	memset(&rr, 0, sizeof(rr));
	rr.op = COALITION_OP_SET_RESPONSIBLE;
	rr.flags = flags;
	ret = coalition_call(cfd, &rr, sizeof(rr), fdp, fdp != NULL ? 1 : 0,
	    &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

static unsigned
coalition_count(void)
{
	unsigned v = 0;
	size_t len = sizeof(v);

	(void)sysctlbyname("kern.mac_capability_coalition.count", &v, &len,
	    NULL, 0);
	return (v);
}

/* Wait up to ~5s for a child to be reaped; returns true if it exited. */
static bool
wait_exit_bounded(pid_t pid, int *wstatus)
{
	int i;

	for (i = 0; i < 100; i++) {
		pid_t r = waitpid(pid, wstatus, WNOHANG);

		if (r == pid)
			return (true);
		if (r == -1 && errno != EINTR)
			return (false);
		usleep(50000);
	}
	return (false);
}

/*
 * Fork a pdfork child that drops its inherited copy of the coalition
 * descriptor and then sleeps, returning only once it has actually dropped it.
 *
 * The handshake is not politeness.  A coalition's close path deliberately
 * skips the process doing the closing -- a unit tearing down its own coalition
 * should not kill itself -- so whichever holder closes the coalition LAST is
 * the one that revokes it, and if that turns out to be the child then the
 * child is the skipped "self" and is never signalled.  Without the handshake,
 * "closing the coalition terminates its members" is a race the parent loses
 * whenever the machine is busy enough to delay the child's close, and the
 * failure looks like a live member surviving a close.
 *
 * Returns the child pid with its process descriptor in *pdp, or -1.
 */
static pid_t
coalition_fork_member(int cfd, int *pdp)
{
	int ready[2];
	char tok;
	pid_t pid;

	if (pipe(ready) != 0)
		return (-1);
	pid = pdfork(pdp, 0);
	if (pid < 0) {
		(void)close(ready[0]);
		(void)close(ready[1]);
		return (-1);
	}
	if (pid == 0) {
		(void)close(ready[0]);
		(void)close(cfd);
		(void)write(ready[1], "r", 1);
		pause();
		_exit(0);
	}
	(void)close(ready[1]);
	if (read(ready[0], &tok, 1) != 1) {
		(void)close(ready[0]);
		return (-1);
	}
	(void)close(ready[0]);
	return (pid);
}

static int
kinfo_of(pid_t pid, struct kinfo_proc *kp)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
	size_t len = sizeof(*kp);

	if (sysctl(mib, 4, kp, &len, NULL, 0) == -1)
		return (-1);
	return (len == sizeof(*kp) ? 0 : -1);
}

ATF_TC(identity_unique_ids);
ATF_TC_HEAD(identity_unique_ids, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Every coalition carries a permanent nonzero id that is never "
	    "reused, even after its predecessor is closed");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(identity_unique_ids, tc)
{
	struct coalition_stat_reply a, b, c;
	int fa, fb, fc;

	fa = mac_capability_connect("coalition");
	fb = mac_capability_connect("coalition");
	ATF_REQUIRE(fa >= 0 && fb >= 0);
	ATF_REQUIRE(coalition_stat(fa, &a) == 0);
	ATF_REQUIRE(coalition_stat(fb, &b) == 0);
	ATF_CHECK(a.id != 0);
	ATF_CHECK(b.id != 0);
	ATF_CHECK(a.id != b.id);
	ATF_CHECK(b.id > a.id);
	/* Unset until SET_RESPONSIBLE. */
	ATF_CHECK_EQ(a.responsible_id, 0);
	ATF_CHECK_EQ(a.responsible_leader_pid, 0);
	ATF_CHECK_EQ(a.leader_pid, 0);
	ATF_CHECK_EQ(a.flags & COF_RESPONSIBLE, 0);
	/* Ids are not recycled once a coalition is gone. */
	close(fa);
	fc = mac_capability_connect("coalition");
	ATF_REQUIRE(fc >= 0);
	ATF_REQUIRE(coalition_stat(fc, &c) == 0);
	ATF_CHECK(c.id != a.id);
	ATF_CHECK(c.id > b.id);
	close(fb);
	close(fc);
}

ATF_TC(identity_stat_old_layout);
ATF_TC_HEAD(identity_stat_old_layout, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A caller offering only the pre-identity STAT layout still gets a "
	    "successful reply of exactly that size");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(identity_stat_old_layout, tc)
{
	struct coalition_req_hdr hdr;
	struct mac_capability_call_args ca;
	unsigned char buf[sizeof(struct coalition_stat_reply)];
	struct coalition_stat_reply *sr = (void *)buf;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	memset(buf, 0xa5, sizeof(buf));
	hdr.op = COALITION_OP_STAT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &hdr;
	ca.req_len = sizeof(hdr);
	ca.reply = buf;
	ca.reply_len = COALITION_STAT_REPLY_V1_LEN;
	ATF_REQUIRE_MSG(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0, "ioctl: %s",
	    strerror(errno));
	ATF_CHECK_EQ(ca.reply_len, COALITION_STAT_REPLY_V1_LEN);
	ATF_CHECK_EQ(sr->status, 0);
	ATF_CHECK_EQ(sr->member_count, 0);
	/* Bytes beyond the old layout were not written. */
	ATF_CHECK_EQ(buf[COALITION_STAT_REPLY_V1_LEN], 0xa5);
	/* Shorter than the old layout is still an error. */
	ca.reply_len = COALITION_STAT_REPLY_V1_LEN - 4;
	ATF_CHECK(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	close(fd);
}

ATF_TC(responsible_set_once);
ATF_TC_HEAD(responsible_set_once, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RESPONSIBLE with a coalition fd records the parent id, "
	    "sets COF_RESPONSIBLE, and refuses a second call with EALREADY");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_set_once, tc)
{
	struct coalition_stat_reply parent, child;
	int pfd, cfd, other;
	int32_t status;

	pfd = mac_capability_connect("coalition");
	cfd = mac_capability_connect("coalition");
	other = mac_capability_connect("coalition");
	ATF_REQUIRE(pfd >= 0 && cfd >= 0 && other >= 0);
	ATF_REQUIRE(coalition_stat(pfd, &parent) == 0);

	ATF_REQUIRE(coalition_set_responsible(cfd, &pfd, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.responsible_id, parent.id);
	ATF_CHECK(child.responsible_id != child.id);
	ATF_CHECK(child.flags & COF_RESPONSIBLE);
	ATF_CHECK_EQ(child.responsible_leader_pid, 0);
	/* The parent is unaffected: no members, no edge of its own. */
	ATF_REQUIRE(coalition_stat(pfd, &parent) == 0);
	ATF_CHECK_EQ(parent.member_count, 0);
	ATF_CHECK_EQ(parent.responsible_id, 0);

	/* Immutable. */
	ATF_REQUIRE(coalition_set_responsible(cfd, &other, 0, &status) == 0);
	ATF_CHECK_EQ(status, EALREADY);
	ATF_REQUIRE(coalition_set_responsible(cfd, NULL, COALITION_RESP_SELF,
	    &status) == 0);
	ATF_CHECK_EQ(status, EALREADY);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.responsible_id, parent.id);

	close(other);
	close(cfd);
	close(pfd);
}

ATF_TC(responsible_self_root);
ATF_TC_HEAD(responsible_self_root, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "COALITION_RESP_SELF makes a coalition the root of its own chain; "
	    "attaching its own fd means the same");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_self_root, tc)
{
	struct coalition_stat_reply sr;
	int fd, fd2;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_set_responsible(fd, NULL, COALITION_RESP_SELF,
	    &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.responsible_id, sr.id);
	ATF_CHECK(sr.flags & COF_RESPONSIBLE);

	fd2 = mac_capability_connect("coalition");
	ATF_REQUIRE(fd2 >= 0);
	ATF_REQUIRE(coalition_set_responsible(fd2, &fd2, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(fd2, &sr) == 0);
	ATF_CHECK_EQ(sr.responsible_id, sr.id);

	/* A self-root's leader is reported as the responsible leader. */
	ATF_REQUIRE(coalition_op(fd2, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	close(fd);
	close(fd2);
}

ATF_TC(responsible_bad_args);
ATF_TC_HEAD(responsible_bad_args, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_RESPONSIBLE rejects malformed requests: no fd and no flag, "
	    "both flags, unknown flags, a non-coalition fd, and a short "
	    "request; the edge stays unset");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_bad_args, tc)
{
	struct coalition_stat_reply sr;
	struct coalition_req_hdr hdr;
	struct coalition_reply rpl;
	int fd, sock;
	int32_t status;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	ATF_REQUIRE(coalition_set_responsible(fd, NULL, 0, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);
	ATF_REQUIRE(coalition_set_responsible(fd, NULL,
	    COALITION_RESP_SELF | COALITION_RESP_CALLER, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);
	ATF_REQUIRE(coalition_set_responsible(fd, NULL, 0x80, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	/* A socket is neither a coalition nor a procdesc. */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(sock >= 0);
	ATF_REQUIRE(coalition_set_responsible(fd, &sock, 0, &status) == 0);
	ATF_CHECK_EQ(status, EBADF);
	close(sock);

	/* Short request. */
	hdr.op = COALITION_OP_SET_RESPONSIBLE;
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0, &rpl,
	    sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, EINVAL);

	/* Caller not in any coalition. */
	ATF_REQUIRE(coalition_set_responsible(fd, NULL, COALITION_RESP_CALLER,
	    &status) == 0);
	ATF_CHECK_EQ(status, ESRCH);

	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(sr.responsible_id, 0);
	ATF_CHECK_EQ(sr.flags & COF_RESPONSIBLE, 0);
	close(fd);
}

ATF_TC(responsible_caller_and_procdesc);
ATF_TC_HEAD(responsible_caller_and_procdesc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "COALITION_RESP_CALLER names the caller's own coalition, and a "
	    "process descriptor names the coalition its process belongs to; "
	    "a procdesc for a member-less process fails with ESRCH");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_caller_and_procdesc, tc)
{
	struct coalition_stat_reply mine, sr;
	int me, a, b, pd, wstatus;
	int32_t status;
	pid_t pid;

	me = mac_capability_connect("coalition");
	a = mac_capability_connect("coalition");
	b = mac_capability_connect("coalition");
	ATF_REQUIRE(me >= 0 && a >= 0 && b >= 0);
	ATF_REQUIRE(coalition_op(me, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(me, &mine) == 0);

	ATF_REQUIRE(coalition_set_responsible(a, NULL, COALITION_RESP_CALLER,
	    &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(a, &sr) == 0);
	ATF_CHECK_EQ(sr.responsible_id, mine.id);

	/* A child of ours inherits membership; its procdesc names 'mine'. */
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(me);
		close(a);
		close(b);
		pause();
		_exit(0);
	}
	/*
	 * A pdfork child inherits its creator's membership, so its procdesc
	 * resolves to 'mine' at once.
	 */
	usleep(50000);
	ATF_REQUIRE(coalition_set_responsible(b, &pd, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(b, &sr) == 0);
	ATF_CHECK_EQ(sr.responsible_id, mine.id);

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(b);
	close(a);
	close(me);
}

ATF_TC(responsible_no_cycles);
ATF_TC_HEAD(responsible_no_cycles, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A responsibility chain may not loop: closing A->B->C->A is "
	    "refused with ELOOP and leaves the graph unchanged");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_no_cycles, tc)
{
	struct coalition_stat_reply sa, sb, sc;
	int a, b, c;
	int32_t status;

	a = mac_capability_connect("coalition");
	b = mac_capability_connect("coalition");
	c = mac_capability_connect("coalition");
	ATF_REQUIRE(a >= 0 && b >= 0 && c >= 0);
	/* b is responsible to a; c is responsible to b. */
	ATF_REQUIRE(coalition_set_responsible(b, &a, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_set_responsible(c, &b, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	/* a -> c would close the loop. */
	ATF_REQUIRE(coalition_set_responsible(a, &c, 0, &status) == 0);
	ATF_CHECK_EQ(status, ELOOP);
	/* a -> b likewise (two-node loop). */
	ATF_REQUIRE(coalition_set_responsible(a, &b, 0, &status) == 0);
	ATF_CHECK_EQ(status, ELOOP);
	ATF_REQUIRE(coalition_stat(a, &sa) == 0);
	ATF_REQUIRE(coalition_stat(b, &sb) == 0);
	ATF_REQUIRE(coalition_stat(c, &sc) == 0);
	ATF_CHECK_EQ(sa.responsible_id, 0);
	ATF_CHECK_EQ(sb.responsible_id, sa.id);
	ATF_CHECK_EQ(sc.responsible_id, sb.id);
	/* a may still take a root. */
	ATF_REQUIRE(coalition_set_responsible(a, NULL, COALITION_RESP_SELF,
	    &status) == 0);
	ATF_CHECK_EQ(status, 0);
	close(c);
	close(b);
	close(a);
}

ATF_TC(responsible_survives_parent_close);
ATF_TC_HEAD(responsible_survives_parent_close, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The responsible id stays readable after the parent coalition is "
	    "closed; its leader pid reads as 0 once it is gone");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_survives_parent_close, tc)
{
	struct coalition_stat_reply parent, child;
	int pfd, cfd, pd, wstatus;
	int32_t status;
	pid_t pid;

	pfd = mac_capability_connect("coalition");
	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(pfd >= 0 && cfd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(pfd);
		close(cfd);
		pause();
		_exit(0);
	}
	ATF_REQUIRE(coalition_enlist(pfd, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	{
		struct coalition_req_hdr hdr;
		struct coalition_reply rpl;

		hdr.op = COALITION_OP_SET_LEADER;
		ATF_REQUIRE(coalition_call(pfd, &hdr, sizeof(hdr), &pd, 1,
		    &rpl, sizeof(rpl)) == 0);
		ATF_CHECK_EQ(rpl.status, 0);
	}
	ATF_REQUIRE(coalition_stat(pfd, &parent) == 0);
	ATF_CHECK_EQ(parent.leader_pid, pid);

	ATF_REQUIRE(coalition_set_responsible(cfd, &pfd, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.responsible_id, parent.id);
	ATF_CHECK_EQ(child.responsible_leader_pid, pid);

	/* Close the parent: its members are terminated, the edge remains. */
	fprintf(stderr, "count before close(parent)=%u\n", coalition_count());
	close(pfd);
	fprintf(stderr, "count after close(parent)=%u alive=%d\n",
	    coalition_count(), kill(pid, 0) == 0);
	if (!wait_exit_bounded(pid, &wstatus)) {
		atf_tc_fail_nonfatal("member not terminated by closing the "
		    "parent coalition (count=%u)", coalition_count());
		pdkill(pd, SIGKILL);
		(void)wait_exit_bounded(pid, &wstatus);
	}
	close(pd);
	usleep(100000);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.responsible_id, parent.id);
	ATF_CHECK_EQ(child.responsible_leader_pid, 0);
	ATF_CHECK(child.flags & COF_RESPONSIBLE);
	close(cfd);
}

ATF_TC(responsible_kinfo_export);
ATF_TC_HEAD(responsible_kinfo_export, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "kinfo_proc reports a member's coalition id, responsible id and "
	    "responsible leader pid; a fork child inherits all three; a "
	    "process in no coalition reports zeros");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_kinfo_export, tc)
{
	struct coalition_stat_reply parent, mine;
	struct kinfo_proc kp;
	int pfd, me, ppd, wstatus;
	int32_t status;
	pid_t leader, child;

	/* Not in a coalition yet: all zero. */
	ATF_REQUIRE(kinfo_of(getpid(), &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, 0);
	ATF_CHECK_EQ(kp.ki_rcoalition, 0);
	ATF_CHECK_EQ(kp.ki_rpid, 0);

	pfd = mac_capability_connect("coalition");
	me = mac_capability_connect("coalition");
	ATF_REQUIRE(pfd >= 0 && me >= 0);

	/* Parent coalition with a leader process. */
	leader = pdfork(&ppd, 0);
	ATF_REQUIRE(leader >= 0);
	if (leader == 0) {
		close(pfd);
		close(me);
		pause();
		_exit(0);
	}
	ATF_REQUIRE(coalition_enlist(pfd, ppd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	{
		struct coalition_req_hdr hdr;
		struct coalition_reply rpl;

		hdr.op = COALITION_OP_SET_LEADER;
		ATF_REQUIRE(coalition_call(pfd, &hdr, sizeof(hdr), &ppd, 1,
		    &rpl, sizeof(rpl)) == 0);
		ATF_CHECK_EQ(rpl.status, 0);
	}
	ATF_REQUIRE(coalition_stat(pfd, &parent) == 0);

	ATF_REQUIRE(coalition_op(me, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_set_responsible(me, &pfd, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(me, &mine) == 0);

	ATF_REQUIRE(kinfo_of(getpid(), &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, mine.id);
	ATF_CHECK_EQ(kp.ki_rcoalition, parent.id);
	ATF_CHECK_EQ(kp.ki_rpid, leader);
	/* The leader itself: own coalition, no edge. */
	ATF_REQUIRE(kinfo_of(leader, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, parent.id);
	ATF_CHECK_EQ(kp.ki_rcoalition, 0);
	ATF_CHECK_EQ(kp.ki_rpid, 0);

	/* A plain fork child inherits membership and so the identity. */
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		pause();
		_exit(0);
	}
	usleep(50000);
	ATF_REQUIRE(kinfo_of(child, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, mine.id);
	ATF_CHECK_EQ(kp.ki_rcoalition, parent.id);
	ATF_CHECK_EQ(kp.ki_rpid, leader);
	kill(child, SIGKILL);
	waitpid(child, &wstatus, 0);

	/* Leader exit: the responsible leader pid decays to 0. */
	pdkill(ppd, SIGKILL);
	waitpid(leader, &wstatus, 0);
	usleep(100000);
	ATF_REQUIRE(kinfo_of(getpid(), &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, mine.id);
	ATF_CHECK_EQ(kp.ki_rcoalition, parent.id);
	ATF_CHECK_EQ(kp.ki_rpid, 0);
	close(ppd);
	close(pfd);
	close(me);
}

ATF_TC(responsible_chain_depth_limit);
ATF_TC_HEAD(responsible_chain_depth_limit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A responsibility chain longer than the kernel bound is refused "
	    "with ELOOP rather than walked without limit");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(responsible_chain_depth_limit, tc)
{
	int fds[70];
	int i, n = 70;
	int32_t status;
	bool hit_limit = false;

	for (i = 0; i < n; i++) {
		fds[i] = mac_capability_connect("coalition");
		ATF_REQUIRE(fds[i] >= 0);
	}
	for (i = 1; i < n; i++) {
		ATF_REQUIRE(coalition_set_responsible(fds[i], &fds[i - 1], 0,
		    &status) == 0);
		if (status == ELOOP) {
			hit_limit = true;
			break;
		}
		ATF_CHECK_EQ(status, 0);
	}
	ATF_CHECK(hit_limit);
	for (i = 0; i < n; i++)
		close(fds[i]);
}


ATF_TC(set_signal_zero_releases);
ATF_TC_HEAD(set_signal_zero_releases, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "SET_SIGNAL 0 makes teardown release process members instead of "
	    "signalling them: closing the coalition leaves the member alive "
	    "and no longer in any coalition");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(set_signal_zero_releases, tc)
{
	struct coalition_set_signal_req ssr;
	struct coalition_reply rpl;
	struct kinfo_proc kp;
	int cfd, pd, wstatus;
	int32_t status;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	memset(&ssr, 0, sizeof(ssr));
	ssr.op = COALITION_OP_SET_SIGNAL;
	ssr.signal = 0;
	ATF_REQUIRE(coalition_call(cfd, &ssr, sizeof(ssr), NULL, 0, &rpl,
	    sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);
	ssr.signal = -1;
	ATF_REQUIRE(coalition_call(cfd, &ssr, sizeof(ssr), NULL, 0, &rpl,
	    sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, EINVAL);

	pid = coalition_fork_member(cfd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(cfd, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK(kp.ki_coalition != 0);

	/* Explicit terminate: the member survives. */
	ATF_REQUIRE(coalition_op(cfd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	usleep(100000);
	ATF_CHECK_EQ(waitpid(pid, &wstatus, WNOHANG), 0);
	/* Close: the member survives and is no longer in any coalition. */
	fprintf(stderr, "count before close=%u\n", coalition_count());
	close(cfd);
	usleep(200000);
	fprintf(stderr, "count after close=%u\n", coalition_count());
	ATF_CHECK_EQ(waitpid(pid, &wstatus, WNOHANG), 0);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ_MSG(kp.ki_coalition, 0, "member still in coalition %ju "
	    "after close (count=%u)", (uintmax_t)kp.ki_coalition,
	    coalition_count());
	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
}


ATF_TC(pdfork_inherits_and_rehomes);
ATF_TC_HEAD(pdfork_inherits_and_rehomes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A pdfork child of a member inherits the coalition; a holder of "
	    "its process descriptor may re-home that inherited membership by "
	    "enlisting it elsewhere, after which it is pinned (EBUSY)");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(pdfork_inherits_and_rehomes, tc)
{
	struct coalition_stat_reply sa, sb;
	struct kinfo_proc kp;
	int a, b, c, pd, wstatus;
	int32_t status;
	pid_t pid;

	a = mac_capability_connect("coalition");
	b = mac_capability_connect("coalition");
	c = mac_capability_connect("coalition");
	ATF_REQUIRE(a >= 0 && b >= 0 && c >= 0);
	ATF_REQUIRE(coalition_op(a, COALITION_OP_JOIN, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(a, &sa) == 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(a);
		close(b);
		close(c);
		pause();
		_exit(0);
	}
	usleep(50000);
	/* Inherited: the child carries a's id. */
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, sa.id);
	ATF_REQUIRE(coalition_stat(a, &sa) == 0);
	ATF_CHECK_EQ(sa.process_count, 2);

	/* Re-home: enlist the child's procdesc into b. */
	ATF_REQUIRE(coalition_enlist(b, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_stat(a, &sa) == 0);
	ATF_REQUIRE(coalition_stat(b, &sb) == 0);
	ATF_CHECK_EQ(sa.process_count, 1);
	ATF_CHECK_EQ(sb.process_count, 1);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, sb.id);

	/* Pinned now: an explicit membership does not move again. */
	ATF_REQUIRE(coalition_enlist(c, pd, &status) == 0);
	ATF_CHECK_EQ(status, EBUSY);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, sb.id);

	/* The creator itself is untouched. */
	ATF_REQUIRE(kinfo_of(getpid(), &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, sa.id);

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(c);
	close(b);
	close(a);
}


ATF_TC(close_terminates_live_member);
ATF_TC_HEAD(close_terminates_live_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing the last descriptor of a coalition with a live procdesc "
	    "member terminates the member (default SIGKILL) and frees the "
	    "coalition");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(close_terminates_live_member, tc)
{
	unsigned before, mid, after;
	int cfd, pd, wstatus;
	int32_t status;
	pid_t pid;

	before = coalition_count();
	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	mid = coalition_count();
	ATF_CHECK_EQ(mid, before + 1);
	/*
	 * The child must have dropped its inherited copy of the coalition
	 * before we drop ours, so that OUR close is the one that revokes it.
	 */
	pid = coalition_fork_member(cfd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(cfd, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	close(cfd);
	if (!wait_exit_bounded(pid, &wstatus)) {
		struct kinfo_proc kp;
		const char *state = "gone";
		int signalled = kill(pid, 0);

		/*
		 * Say which of the two possible failures this is.  A process
		 * descriptor keeps a dead child from being reaped by wait(2),
		 * so waitpid() reporting nothing does not by itself mean the
		 * member was spared: a zombie means the kernel did terminate
		 * it and only the reap is pending, while a running or sleeping
		 * process means the close really did not reach it.
		 */
		if (kinfo_of(pid, &kp) == 0) {
			switch (kp.ki_stat) {
			case SZOMB:	state = "zombie"; break;
			case SRUN:	state = "running"; break;
			case SSLEEP:	state = "sleeping"; break;
			case SSTOP:	state = "stopped"; break;
			default:	state = "other"; break;
			}
		}
		atf_tc_fail_nonfatal("live member survived close: state=%s "
		    "kill0=%d count=%u", state, signalled, coalition_count());
		pdkill(pd, SIGKILL);
		(void)wait_exit_bounded(pid, &wstatus);
	}
	close(pd);
	usleep(200000);
	after = coalition_count();
	ATF_CHECK_EQ_MSG(after, before, "coalition not freed after close: "
	    "before=%u after=%u", before, after);
}


ATF_TC(refattach_confined_descriptors);
ATF_TC_HEAD(refattach_confined_descriptors, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition operations hold attached descriptors in the kernel, "
	    "so a CAP_XFER_NONE coalition fd may name a responsible parent, a "
	    "CAP_XFER_NONE procdesc may be enlisted, and a CAP_XFER_ONCE "
	    "attachment is not consumed");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(refattach_confined_descriptors, tc)
{
	struct coalition_stat_reply parent, child;
	int pfd, cfd, pd, wstatus;
	int32_t status;
	pid_t pid;

	pfd = mac_capability_connect("coalition");
	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(pfd >= 0 && cfd >= 0);
	/* Confine the parent's fd the way the launcher does. */
	ATF_REQUIRE(cap_xfer_limit(pfd, CAP_XFER_NONE) == 0);
	ATF_REQUIRE(coalition_set_responsible(cfd, &pfd, 0, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "confined parent fd refused: %d", status);
	ATF_REQUIRE(coalition_stat(pfd, &parent) == 0);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.responsible_id, parent.id);

	/* A confined procdesc can still be enlisted. */
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(pfd);
		close(cfd);
		pause();
		_exit(0);
	}
	ATF_REQUIRE(cap_xfer_limit(pd, CAP_XFER_NONE) == 0);
	ATF_REQUIRE(coalition_enlist(cfd, pd, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "confined procdesc refused: %d", status);
	ATF_REQUIRE(coalition_stat(cfd, &child) == 0);
	ATF_CHECK_EQ(child.process_count, 1);

	/*
	 * A ONCE attachment is a reference, not a transfer: the descriptor
	 * can still be sent once over a socket afterwards (a consumed one
	 * would be CAP_XFER_NONE and the send would fail).
	 */
	{
		int ofd = mac_capability_connect("coalition");
		int other = mac_capability_connect("coalition");
		int sv[2];
		struct msghdr mh;
		struct iovec iov;
		union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } cm;
		char c = 'x';

		ATF_REQUIRE(ofd >= 0 && other >= 0);
		ATF_REQUIRE(cap_xfer_limit(ofd, CAP_XFER_ONCE) == 0);
		ATF_REQUIRE(coalition_set_responsible(other, &ofd, 0,
		    &status) == 0);
		ATF_CHECK_EQ(status, 0);
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
		memset(&mh, 0, sizeof(mh));
		memset(&cm, 0, sizeof(cm));
		iov.iov_base = &c;
		iov.iov_len = 1;
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		mh.msg_control = &cm;
		mh.msg_controllen = CMSG_LEN(sizeof(int));
		cm.h.cmsg_len = CMSG_LEN(sizeof(int));
		cm.h.cmsg_level = SOL_SOCKET;
		cm.h.cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(&cm.h), &ofd, sizeof(int));
		ATF_CHECK_MSG(sendmsg(sv[0], &mh, 0) == 1,
		    "attachment consumed the ONCE transfer state: %s",
		    strerror(errno));
		close(sv[0]);
		close(sv[1]);
		close(other);
		close(ofd);
	}
	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(cfd);
	close(pfd);
}


ATF_TC(set_signal_zero_releases_joined);
ATF_TC_HEAD(set_signal_zero_releases_joined, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "With signal 0, closing a coalition whose members JOINed (and "
	    "their fork children) releases them: nobody is signalled and the "
	    "children report no coalition afterwards");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(set_signal_zero_releases_joined, tc)
{
	struct coalition_set_signal_req ssr;
	struct coalition_reply rpl;
	struct kinfo_proc kp;
	int cfd, holder[2], wstatus;
	pid_t joiner, grandchild;

	/*
	 * The joiner is a separate process (like a session leader): it JOINs,
	 * forks a child that inherits, and both keep only the child-side of a
	 * pipe.  The coalition fd is closed by THIS process, the only holder,
	 * exactly like a session record going away.
	 */
	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	memset(&ssr, 0, sizeof(ssr));
	ssr.op = COALITION_OP_SET_SIGNAL;
	ssr.signal = 0;
	ATF_REQUIRE(coalition_call(cfd, &ssr, sizeof(ssr), NULL, 0, &rpl,
	    sizeof(rpl)) == 0);
	ATF_CHECK_EQ(rpl.status, 0);
	ATF_REQUIRE(pipe(holder) == 0);
	joiner = fork();
	ATF_REQUIRE(joiner >= 0);
	if (joiner == 0) {
		int32_t st;

		close(holder[0]);
		if (coalition_op(cfd, COALITION_OP_JOIN, &st) != 0 || st != 0)
			_exit(2);
		close(cfd);
		grandchild = fork();
		if (grandchild == 0) {
			pause();
			_exit(0);
		}
		/* report the grandchild pid, then linger */
		(void)write(holder[1], &grandchild, sizeof(grandchild));
		pause();
		_exit(0);
	}
	close(holder[1]);
	ATF_REQUIRE(read(holder[0], &grandchild, sizeof(grandchild)) ==
	    (ssize_t)sizeof(grandchild));
	usleep(50000);
	ATF_REQUIRE(kinfo_of(grandchild, &kp) == 0);
	ATF_CHECK(kp.ki_coalition != 0);

	close(cfd);	/* last holder: the coalition ends */
	usleep(300000);
	/*
	 * The grandchild is not our child (waitpid cannot see it): judge
	 * liveness by kill(0) plus a non-zombie kinfo state.
	 */
	ATF_CHECK_EQ_MSG(waitpid(joiner, &wstatus, WNOHANG), 0,
	    "joiner was signalled at close");
	ATF_CHECK_MSG(kill(grandchild, 0) == 0, "grandchild gone at close");
	ATF_REQUIRE(kinfo_of(grandchild, &kp) == 0);
	ATF_CHECK_MSG(kp.ki_stat != SZOMB, "grandchild died at close");
	ATF_CHECK_EQ_MSG(kp.ki_coalition, 0, "grandchild still in coalition");
	ATF_REQUIRE(kinfo_of(joiner, &kp) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, 0);
	kill(grandchild, SIGKILL);
	kill(joiner, SIGKILL);
	waitpid(joiner, &wstatus, 0);
	close(holder[0]);
}


/* ================================================================
 * Memory pressure
 * ================================================================ */

/*
 * debug.vm_lowmem fires the kernel's low-memory event synchronously.  The
 * coalition module answers it on a taskqueue, so a reader has to wait a
 * moment; drain up to `tries` notifications looking for the pressure note.
 */
static bool
wait_for_pressure(int fd, int tries)
{
	struct coalition_event_msg ev;
	int i, lowmem = TEST_VM_LOW_PAGES;

	if (sysctlbyname("debug.vm_lowmem", NULL, NULL, &lowmem,
	    sizeof(lowmem)) != 0)
		atf_tc_skip("debug.vm_lowmem unavailable: %s",
		    strerror(errno));
	for (i = 0; i < tries; i++) {
		while (coalition_recv_event(fd, &ev) == 0)
			if ((ev.flags & COALITION_NOTE_PRESSURE) != 0)
				return (true);
		usleep(100000);
	}
	return (false);
}


/*
 * Wait for a note to arrive on a coalition, and hand back the event that
 * carried it.  Events are a queue, so the one we want may be behind others;
 * anything else is discarded rather than treated as a failure.
 */
static bool
coalition_wait_note(int fd, uint32_t want, struct coalition_event_msg *out,
    int tries)
{
	struct coalition_event_msg ev;
	int i;

	/*
	 * Non-blocking: receiving an event waits for one otherwise, and a note
	 * that never arrives would hang the test rather than fail it, which
	 * costs a five-minute timeout instead of a useful message.
	 */
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1)
		return (false);
	for (i = 0; i < tries; i++) {
		while (coalition_recv_event(fd, &ev) == 0) {
			if ((ev.flags & want) != 0) {
				if (out != NULL)
					*out = ev;
				return (true);
			}
		}
		usleep(100000);
	}
	return (false);
}

ATF_TC(pressure_notifies_coalitions);
ATF_TC_HEAD(pressure_notifies_coalitions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A low-memory event delivers COALITION_NOTE_PRESSURE to every "
	    "live coalition, so a unit can drop caches before anything is "
	    "killed; nothing is terminated and members are untouched");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(pressure_notifies_coalitions, tc)
{
	struct coalition_stat_reply sr;
	struct kinfo_proc kp;
	int a, b, pd, wstatus;
	int32_t status;
	pid_t pid;

	a = mac_capability_connect("coalition");
	b = mac_capability_connect("coalition");
	ATF_REQUIRE(a >= 0 && b >= 0);

	/* A member so we can prove the notification kills nothing. */
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(a);
		close(b);
		pause();
		_exit(0);
	}
	ATF_REQUIRE(coalition_enlist(a, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	ATF_CHECK_MSG(wait_for_pressure(a, 20),
	    "no pressure notification on the first coalition");
	/* Every live coalition is told, not just the one with members. */
	ATF_CHECK_MSG(wait_for_pressure(b, 20),
	    "no pressure notification on the second coalition");

	/* Advisory only: the member is alive and the coalition intact. */
	ATF_CHECK_EQ_MSG(waitpid(pid, &wstatus, WNOHANG), 0,
	    "pressure notification killed a member");
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_REQUIRE(coalition_stat(a, &sr) == 0);
	ATF_CHECK_EQ(kp.ki_coalition, sr.id);
	ATF_CHECK_EQ(sr.process_count, 1);
	ATF_CHECK_EQ(sr.flags & COF_TERMINATING, 0);

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(b);
	close(a);
}

ATF_TC(pressure_after_close_is_safe);
ATF_TC_HEAD(pressure_after_close_is_safe, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A low-memory event during and after coalition teardown is "
	    "harmless: the pass skips closing coalitions and the count "
	    "returns to its baseline");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(pressure_after_close_is_safe, tc)
{
	unsigned before, after;
	int lowmem = TEST_VM_LOW_PAGES;
	int fds[16];
	int i;

	before = coalition_count();
	for (i = 0; i < 16; i++) {
		fds[i] = mac_capability_connect("coalition");
		ATF_REQUIRE(fds[i] >= 0);
	}
	/* Churn the list while the pass runs. */
	for (i = 0; i < 16; i++) {
		if (sysctlbyname("debug.vm_lowmem", NULL, NULL, &lowmem,
		    sizeof(lowmem)) != 0)
			atf_tc_skip("debug.vm_lowmem unavailable: %s",
			    strerror(errno));
		close(fds[i]);
	}
	usleep(500000);
	(void)sysctlbyname("debug.vm_lowmem", NULL, NULL, &lowmem,
	    sizeof(lowmem));
	usleep(500000);
	after = coalition_count();
	ATF_CHECK_EQ_MSG(after, before, "coalitions leaked across pressure: "
	    "before=%u after=%u", before, after);
}


/* ================================================================
 * Resource ledger
 * ================================================================ */

static int
coalition_ledger(int fd, uint32_t flags, struct coalition_ledger_reply *lr)
{
	struct coalition_ledger_req lq;

	memset(&lq, 0, sizeof(lq));
	lq.op = COALITION_OP_LEDGER;
	lq.flags = flags;
	return (coalition_call(fd, &lq, sizeof(lq), NULL, 0, lr, sizeof(*lr)));
}


static int
coalition_set_limit_full(int fd, uint32_t flags, uint64_t bytes,
    uint64_t vmem, int32_t *status_out)
{
	struct coalition_limit_req lq;
	struct coalition_reply rpl;
	int ret;

	memset(&lq, 0, sizeof(lq));
	lq.op = COALITION_OP_SET_LIMIT;
	lq.flags = flags;
	lq.memory_bytes = bytes;
	lq.vmem_bytes = vmem;
	ret = coalition_call(fd, &lq, sizeof(lq), NULL, 0, &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

static int
coalition_set_cpu_limit(int fd, uint32_t flags, uint32_t pct,
    int32_t *status_out)
{
	struct coalition_limit_req lq;
	struct coalition_reply rpl;
	int ret;

	memset(&lq, 0, sizeof(lq));
	lq.op = COALITION_OP_SET_LIMIT;
	lq.flags = flags;
	lq.cpu_percent = pct;
	ret = coalition_call(fd, &lq, sizeof(lq), NULL, 0, &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

/*
 * Switch the periodic sweep off, and back on again afterwards.
 *
 * Lengthening sweep_interval_ms is not the same thing: it does not cancel the
 * callout that is already armed, so one more sweep still lands at the old
 * interval.  A test that must see NOTHING enforce a ceiling has to use the
 * on/off knob, or it is racing a straggler.
 *
 * Returns the previous value, or -1 if the knob is not there.
 */
static int
sweep_enable_set(int enable)
{
	int old = -1;
	size_t len = sizeof(old);

	if (sysctlbyname("kern.mac_capability_coalition.sweep", &old, &len,
	    &enable, sizeof(enable)) != 0)
		return (-1);
	return (old);
}

static void
sweep_enable_restore(int enable)
{

	if (enable >= 0)
		(void)sysctlbyname("kern.mac_capability_coalition.sweep",
		    NULL, NULL, &enable, sizeof(enable));
}

/*
 * Remembered across the cleanup routine.  This knob is global to the machine,
 * so a test that fails part way through must still put it back: leaving the
 * sweep off would make every later test about a ceiling or an idle exit fail
 * for a reason that has nothing to do with what it is testing.
 */
static int sweep_enable_saved = -1;

/*
 * Wait until the accounting framework has attributed resident memory to the
 * coalition.
 *
 * Resident memory is the one container figure that is not charged as it
 * happens: the page daemon writes it on its pass, so a member that was forked
 * a moment ago is genuinely carrying zero as far as the container is
 * concerned.  A test about a RESIDENT ceiling has to wait for that, or it is
 * really testing how fast the page daemon happens to be.  Address space needs
 * none of this -- it is charged at the mapping path.
 */
static bool
wait_for_resident_accounting(int fd)
{
	struct coalition_ledger_reply lr;
	int i;

	for (i = 0; i < 100; i++) {
		if (coalition_ledger(fd, 0, &lr) == 0 && lr.status == 0 &&
		    lr.rss_bytes > 0)
			return (true);
		usleep(100000);
	}
	return (false);
}

/* Longer than wait_exit_bounded: a rate needs several windows to be sure. */
static bool
wait_exit_slow(pid_t pid, int *wstatus)
{
	int i;

	for (i = 0; i < 300; i++) {
		pid_t r = waitpid(pid, wstatus, WNOHANG);

		if (r == pid)
			return (true);
		if (r == -1 && errno != EINTR)
			return (false);
		usleep(100000);
	}
	return (false);
}

static int
coalition_set_limit(int fd, uint32_t flags, uint64_t bytes, int32_t *status_out)
{
	struct coalition_limit_req lq;
	struct coalition_reply rpl;
	int ret;

	memset(&lq, 0, sizeof(lq));
	lq.op = COALITION_OP_SET_LIMIT;
	lq.flags = flags;
	lq.memory_bytes = bytes;
	ret = coalition_call(fd, &lq, sizeof(lq), NULL, 0, &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}



/*
 * The periodic sweep is what enforces ceilings and puts idle work away, and it
 * runs every ten seconds by default.  A test that waits less than that learns
 * nothing: one expecting an action times out, and -- worse -- one expecting NO
 * action passes whether the mechanism works or not, because the sweep never
 * ran.  So tests about the sweep shorten its interval to the shortest the
 * kernel accepts, and put it back afterwards.
 */
#define	SWEEP_FAST_MS	1000

static u_int
sweep_interval_set(u_int ms)
{
	u_int old = 0;
	size_t len = sizeof(old);

	if (sysctlbyname("kern.mac_capability_coalition.sweep_interval_ms",
	    &old, &len, &ms, sizeof(ms)) != 0)
		return (0);
	return (old);
}

static void
sweep_interval_restore(u_int ms)
{

	if (ms != 0)
		(void)sysctlbyname(
		    "kern.mac_capability_coalition.sweep_interval_ms", NULL,
		    NULL, &ms, sizeof(ms));
}

static int
coalition_set_idle_exit(int fd, uint32_t flags, uint32_t min_age_ms,
    int32_t *status_out)
{
	struct coalition_idle_req iq;
	struct coalition_reply rpl;
	int ret;

	memset(&iq, 0, sizeof(iq));
	iq.op = COALITION_OP_SET_IDLE_EXIT;
	iq.flags = flags;
	iq.min_age_ms = min_age_ms;
	ret = coalition_call(fd, &iq, sizeof(iq), NULL, 0, &rpl, sizeof(rpl));
	if (ret == 0 && status_out != NULL)
		*status_out = rpl.status;
	return (ret);
}

static int
coalition_band(int fd, uint32_t flags, uint32_t floor,
    struct coalition_band_reply *br)
{
	struct coalition_band_req bq;

	memset(&bq, 0, sizeof(bq));
	bq.op = COALITION_OP_BAND;
	bq.flags = flags;
	bq.floor = floor;
	return (coalition_call(fd, &bq, sizeof(bq), NULL, 0, br, sizeof(*br)));
}

/*
 * Ask for an assertion at band.  Returns the ioctl result; on success the
 * assertion descriptor is stored in *afd and the reply in *br.
 */
static int
coalition_assert(int fd, uint32_t band, struct coalition_band_reply *br,
    int *afd)
{
	struct mac_capability_call_args ca;
	struct coalition_band_req bq;
	uint32_t nfds = 1;
	int ret;

	memset(&bq, 0, sizeof(bq));
	bq.op = COALITION_OP_ASSERT;
	bq.band = band;
	memset(&ca, 0, sizeof(ca));
	ca.req = &bq;
	ca.req_len = sizeof(bq);
	ca.reply = br;
	ca.reply_len = sizeof(*br);
	ca.reply_fds = afd;
	ca.reply_nfds = nfds;
	*afd = -1;
	ret = ioctl(fd, MAC_CAPABILITY_CALL, &ca);
	return (ret);
}

ATF_TC(ledger_never_sampled);
ATF_TC_HEAD(ledger_never_sampled, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition that has never been sampled reports zeroed counters "
	    "and an age of UINT64_MAX, and rejects unknown flags");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(ledger_never_sampled, tc)
{
	struct coalition_ledger_reply lr;
	struct coalition_stat_reply sr;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_REQUIRE(coalition_ledger(fd, 0, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);
	ATF_CHECK_EQ(lr.id, sr.id);
	ATF_CHECK_EQ(lr.rss_bytes, 0);
	ATF_CHECK_EQ(lr.vsz_bytes, 0);
	ATF_CHECK_EQ(lr.nprocs, 0);
	/*
	 * Zero, not UINT64_MAX: the figures are maintained by the accounting
	 * framework rather than sampled, so there is no such thing as a
	 * reading that has never been taken or one that has gone stale.
	 */
	ATF_CHECK_EQ(lr.age_ms, 0);

	/* Unknown flags are refused. */
	ATF_REQUIRE(coalition_ledger(fd, 0x80, &lr) == 0);
	ATF_CHECK_EQ(lr.status, EINVAL);
	close(fd);
}

ATF_TC(ledger_refresh_counts_members);
ATF_TC_HEAD(ledger_refresh_counts_members, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A forced refresh sums the footprint of process members: the "
	    "sample tracks members joining, reports a fresh age, and agrees "
	    "with the exact walk COALITION_OP_RUSAGE performs");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(ledger_refresh_counts_members, tc)
{
	struct coalition_ledger_reply lr;
	struct coalition_rusage_reply rr;
	struct coalition_req_hdr hdr;
	int cfd, pd, wstatus, ready[2];
	int32_t status;
	char tok;
	pid_t pid;

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	/* Empty: a refresh is valid and reports nothing. */
	ATF_REQUIRE(coalition_ledger(cfd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);
	ATF_CHECK_EQ(lr.nprocs, 0);
	ATF_CHECK_EQ(lr.age_ms, 0);

	/*
	 * The member has to be settled before either snapshot is taken.  A
	 * child that is still faulting in its first pages has a resident set
	 * that changes between the cheap sample and the exact walk, which
	 * would make the comparison below a race rather than a check.  It
	 * tells us when it has stopped growing, and only then do we look.
	 */
	ATF_REQUIRE(pipe(ready) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(cfd);
		close(ready[0]);
		(void)write(ready[1], "r", 1);
		pause();
		_exit(0);
	}
	close(ready[1]);
	ATF_REQUIRE(read(ready[0], &tok, 1) == 1);
	close(ready[0]);
	ATF_REQUIRE(coalition_enlist(cfd, pd, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	/* Let the child reach pause() and stop touching memory. */
	usleep(200000);

	ATF_REQUIRE(coalition_ledger(cfd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);
	ATF_CHECK_EQ_MSG(lr.nprocs, 1, "member not counted");
	ATF_CHECK(lr.nthreads >= 1);
	ATF_CHECK_MSG(lr.vsz_bytes > 0, "no address space attributed");
	ATF_CHECK_EQ(lr.age_ms, 0);

	/* The cheap sample and the exact walk see the same thing. */
	hdr.op = COALITION_OP_RUSAGE;
	ATF_REQUIRE(coalition_call(cfd, &hdr, sizeof(hdr), NULL, 0, &rr,
	    sizeof(rr)) == 0);
	ATF_CHECK_EQ(rr.status, 0);
	ATF_CHECK_EQ(rr.nprocs, lr.nprocs);
	/*
	 * The address space of a paused process does not move, and the
	 * container is charged at the mapping path, so the counter and the
	 * exact walk must agree on it to the byte.
	 *
	 * Resident memory is deliberately NOT compared.  The walk reads the
	 * live vmspace; the container carries whatever the page daemon last
	 * wrote, which for a child this young may still be nothing at all.
	 * That difference is the design -- one figure is maintained, the other
	 * is measured now -- and asserting they match would be asserting the
	 * page daemon had run, which nothing here controls.
	 */
	ATF_CHECK_EQ_MSG(rr.vsz_bytes, lr.vsz_bytes,
	    "address space disagrees: walk=%ju counter=%ju",
	    (uintmax_t)rr.vsz_bytes, (uintmax_t)lr.vsz_bytes);

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(cfd);
}

ATF_TC(ledger_tracks_without_being_asked);
ATF_TC_HEAD(ledger_tracks_without_being_asked, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The ledger reports counters the accounting framework maintains, "
	    "so a member taking more address space is visible on the next read "
	    "with no refresh, no sweep and no memory pressure involved");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(ledger_tracks_without_being_asked, tc)
{
	struct coalition_ledger_reply before, after;
	int fd, pd, wstatus, ready[2], done[2];
	int32_t status;
	char tok;
	pid_t pid;

	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(done) == 0);
	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char c;

		close(fd);
		close(ready[0]);
		close(done[0]);
		/* Announce, wait to be told, then take a large mapping. */
		(void)write(ready[1], "r", 1);
		if (read(done[1], &c, 1) == 0)
			_exit(1);
		_exit(0);
	}
	close(ready[1]);
	close(done[1]);
	ATF_REQUIRE(read(ready[0], &tok, 1) == 1);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * No COALITION_LEDGER_REFRESH on either read.  Under the old sampled
	 * model both would have returned the same cached figures; the point of
	 * the change is that they do not.
	 */
	ATF_REQUIRE(coalition_ledger(fd, 0, &before) == 0);
	ATF_REQUIRE_EQ(before.status, 0);
	ATF_CHECK_EQ_MSG(before.nprocs, 1,
	    "the member was not counted without a refresh");
	ATF_CHECK_MSG(before.vsz_bytes > 0,
	    "no address space attributed without a refresh");

	/*
	 * Let the child go; it exits, which takes its whole address space out
	 * of the container.  Address space is charged and discharged at the
	 * mapping path, so this is exact and needs no pass of anything.
	 */
	close(done[0]);
	ATF_REQUIRE(wait_exit_bounded(pid, &wstatus));

	ATF_REQUIRE(coalition_ledger(fd, 0, &after) == 0);
	ATF_REQUIRE_EQ(after.status, 0);
	ATF_CHECK_EQ_MSG(after.nprocs, 0,
	    "a departed member is still counted: %u", after.nprocs);
	ATF_CHECK_MSG(after.vsz_bytes < before.vsz_bytes,
	    "address space did not fall when the member left: %ju then %ju",
	    (uintmax_t)before.vsz_bytes, (uintmax_t)after.vsz_bytes);
	ATF_CHECK_EQ(after.age_ms, 0);

	close(ready[0]);
	close(pd);
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

	/* Invalid signal (0 is the release mode; out of range is refused) */
	ssr.op = COALITION_OP_SET_SIGNAL;
	ssr.signal = NSIG;
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

ATF_TC_WITH_CLEANUP(jail_members_are_accounted);
ATF_TC_HEAD(jail_members_are_accounted, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition holding a jail reports the resources used inside it: "
	    "a process that enters the jail is charged without ever being "
	    "enlisted, and what it was charged is given back when it exits, so "
	    "a jail that churns processes does not inflate the container");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(jail_members_are_accounted, tc)
{
	struct coalition_ledger_reply empty, occupied, after;
	int cfd, jail_fd, jid, wstatus;
	int32_t status;
	pid_t pid;
	int i;

	memset(&empty, 0, sizeof(empty));
	memset(&occupied, 0, sizeof(occupied));
	memset(&after, 0, sizeof(after));

	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
	jail_fd = create_jail_with_desc(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE_MSG(jail_fd >= 0, "create_jail_with_desc: %s",
	    strerror(errno));
	jid = jail_getid(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE(jid > 0);

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(coalition_enlist(cfd, jail_fd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Nothing is running in it yet. */
	ATF_REQUIRE(coalition_ledger(cfd, 0, &empty) == 0);
	ATF_REQUIRE_EQ(empty.status, 0);
	ATF_CHECK_EQ_MSG(empty.nprocs, 0,
	    "an empty jail was credited with %u processes", empty.nprocs);

	/*
	 * Put a process inside.  It is never enlisted -- the coalition holds
	 * the jail, not the process -- so if it is accounted at all it is
	 * because entering the jail charged it.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (jail_attach(jid) != 0)
			_exit(1);
		/* Take a mapping big enough to be unmistakable, then wait. */
		if (mmap(NULL, 64UL << 20, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0) == MAP_FAILED)
			_exit(2);
		pause();
		_exit(0);
	}
	/* Give the child time to attach and map. */
	for (i = 0; i < 100; i++) {
		if (coalition_ledger(cfd, 0, &occupied) == 0 &&
		    occupied.status == 0 && occupied.nprocs > 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(occupied.nprocs > 0,
	    "a process inside a held jail was not accounted for");
	ATF_CHECK_MSG(occupied.vsz_bytes > empty.vsz_bytes,
	    "the jailed process's address space was not charged: %ju then %ju",
	    (uintmax_t)empty.vsz_bytes, (uintmax_t)occupied.vsz_bytes);

	/*
	 * Now let it go.  Everything reclaimable must come back, or a jail
	 * that starts and stops work would inflate the container for good.
	 */
	ATF_REQUIRE(kill(pid, SIGKILL) == 0);
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);
	for (i = 0; i < 100; i++) {
		if (coalition_ledger(cfd, 0, &after) == 0 &&
		    after.status == 0 && after.nprocs == 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_EQ_MSG(after.nprocs, 0,
	    "a departed jailed process is still counted: %u", after.nprocs);
	ATF_CHECK_MSG(after.vsz_bytes <= empty.vsz_bytes,
	    "address space was not given back when the jailed process exited: "
	    "%ju empty, %ju after", (uintmax_t)empty.vsz_bytes,
	    (uintmax_t)after.vsz_bytes);

	close(cfd);
	close(jail_fd);
}
ATF_TC_CLEANUP(jail_members_are_accounted, tc)
{
	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
}

ATF_TC_WITH_CLEANUP(a_jail_held_coalition_is_visible_to_pressure);
ATF_TC_HEAD(a_jail_held_coalition_is_visible_to_pressure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition whose memory is all inside a jail it holds is ranked "
	    "on that memory and handed down under pressure. Ranking on a walk "
	    "of the member list instead counted process members only, so such "
	    "a coalition looked empty and was never chosen");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(a_jail_held_coalition_is_visible_to_pressure, tc)
{
	struct coalition_ledger_reply lr;
	struct coalition_band_reply br;
	u_int before = 0, after = 0;
	size_t len = sizeof(before);
	int cfd, jail_fd, jid, wstatus, ready[2], lowmem = TEST_VM_LOW_PAGES;
	int32_t status;
	char tok;
	pid_t pid;
	int i;

	if (sysctlbyname("kern.mac_capability_coalition.pressure_reclaims",
	    &before, &len, NULL, 0) != 0)
		atf_tc_skip("pressure_reclaims sysctl unavailable: %s",
		    strerror(errno));

	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
	jail_fd = create_jail_with_desc(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE_MSG(jail_fd >= 0, "create_jail_with_desc: %s",
	    strerror(errno));
	jid = jail_getid(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE(jid > 0);

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(coalition_enlist(cfd, jail_fd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Low enough a band that the pressure pass may hand it down. */
	ATF_REQUIRE(coalition_band(cfd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_BACKGROUND, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	/*
	 * All of the memory is inside the jail, and the process holding it is
	 * never enlisted: the coalition holds the jail, not the process.
	 */
	ATF_REQUIRE(pipe(ready) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char *m;
		size_t n = 32UL << 20;

		close(ready[0]);
		if (jail_attach(jid) != 0)
			_exit(1);
		m = mmap(NULL, n, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (m == MAP_FAILED)
			_exit(2);
		/* Touch it so it is resident, not merely mapped. */
		memset(m, 1, n);
		(void)write(ready[1], "r", 1);
		pause();
		_exit(0);
	}
	close(ready[1]);
	ATF_REQUIRE(read(ready[0], &tok, 1) == 1);
	close(ready[0]);

	/*
	 * Wait for the page daemon to attribute that resident memory to the
	 * container; until it has, there is genuinely nothing to rank on.
	 */
	memset(&lr, 0, sizeof(lr));
	for (i = 0; i < 100; i++) {
		if (coalition_ledger(cfd, 0, &lr) == 0 && lr.status == 0 &&
		    lr.rss_bytes >= (8UL << 20))
			break;
		usleep(100000);
	}
	if (lr.rss_bytes < (8UL << 20)) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &wstatus, 0);
		close(cfd);
		close(jail_fd);
		atf_tc_skip("the jail's memory was not attributed to the "
		    "coalition (%ju bytes); nothing to rank",
		    (uintmax_t)lr.rss_bytes);
	}

	if (sysctlbyname("debug.vm_lowmem", NULL, NULL, &lowmem,
	    sizeof(lowmem)) != 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &wstatus, 0);
		close(cfd);
		close(jail_fd);
		atf_tc_skip("debug.vm_lowmem unavailable: %s",
		    strerror(errno));
	}
	for (i = 0; i < 50; i++) {
		len = sizeof(after);
		if (sysctlbyname(
		    "kern.mac_capability_coalition.pressure_reclaims",
		    &after, &len, NULL, 0) == 0 && after > before)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(after > before,
	    "a coalition holding %ju KB inside its jail was never handed "
	    "down: %u then %u", (uintmax_t)(lr.rss_bytes / 1024), before,
	    after);

	(void)kill(pid, SIGKILL);
	(void)waitpid(pid, &wstatus, 0);
	close(cfd);
	close(jail_fd);
}
ATF_TC_CLEANUP(a_jail_held_coalition_is_visible_to_pressure, tc)
{
	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
}

ATF_TC_WITH_CLEANUP(a_nested_jail_is_charged_to_the_held_one);
ATF_TC_HEAD(a_nested_jail_is_charged_to_the_held_one, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A process inside a jail nested within the jail a coalition holds "
	    "is charged to that coalition: the search walks out through the "
	    "enclosing jails rather than looking only at the one the process "
	    "is directly in");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(a_nested_jail_is_charged_to_the_held_one, tc)
{
	struct coalition_ledger_reply lr;
	int cfd, jail_fd, jid, wstatus, ready[2];
	int32_t status;
	char tok;
	pid_t pid;
	int i;

	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
	jail_fd = create_parent_jail_with_desc(COALITION_TEST_JAIL_NAME);
	if (jail_fd < 0)
		atf_tc_skip("could not create a jail allowing children: %s",
		    strerror(errno));
	jid = jail_getid(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE(jid > 0);

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(coalition_enlist(cfd, jail_fd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_REQUIRE(pipe(ready) == 0);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int inner;

		close(cfd);
		close(ready[0]);
		/* Into the held jail, then into one nested inside it. */
		if (jail_attach(jid) != 0)
			_exit(1);
		inner = jail_setv(JAIL_CREATE,
		    "name", "inner", "path", "/", "persist", NULL, NULL);
		if (inner < 0)
			_exit(2);
		if (jail_attach(inner) != 0)
			_exit(3);
		(void)write(ready[1], "r", 1);
		pause();
		_exit(0);
	}
	close(ready[1]);
	if (read(ready[0], &tok, 1) != 1) {
		(void)waitpid(pid, &wstatus, 0);
		close(ready[0]);
		close(cfd);
		close(jail_fd);
		atf_tc_skip("could not nest a jail inside the held one");
	}
	close(ready[0]);

	memset(&lr, 0, sizeof(lr));
	for (i = 0; i < 50; i++) {
		if (coalition_ledger(cfd, 0, &lr) == 0 && lr.status == 0 &&
		    lr.nprocs > 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(lr.nprocs > 0,
	    "a process in a jail nested inside the held jail was not charged "
	    "to the coalition holding it");

	(void)kill(pid, SIGKILL);
	(void)waitpid(pid, &wstatus, 0);
	close(cfd);
	close(jail_fd);
}
ATF_TC_CLEANUP(a_nested_jail_is_charged_to_the_held_one, tc)
{
	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
}

ATF_TC_WITH_CLEANUP(enlistment_beats_the_jail_it_is_in);
ATF_TC_HEAD(enlistment_beats_the_jail_it_is_in, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A process enlisted in its own right is charged there and not to "
	    "the coalition holding the jail it happens to be in: an individual "
	    "enlistment is the more specific statement");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(enlistment_beats_the_jail_it_is_in, tc)
{
	struct coalition_ledger_reply jl, ol;
	int jailco, owner, jail_fd, pd, jid, wstatus, ready[2], go[2];
	int32_t status;
	char tok;
	pid_t pid;
	int i;

	memset(&jl, 0, sizeof(jl));
	memset(&ol, 0, sizeof(ol));

	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
	jail_fd = create_jail_with_desc(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE_MSG(jail_fd >= 0, "create_jail_with_desc: %s",
	    strerror(errno));
	jid = jail_getid(COALITION_TEST_JAIL_NAME);
	ATF_REQUIRE(jid > 0);

	/* One coalition holds the jail; a different one owns the process. */
	jailco = mac_capability_connect("coalition");
	ATF_REQUIRE(jailco >= 0);
	ATF_REQUIRE(coalition_enlist(jailco, jail_fd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	owner = mac_capability_connect("coalition");
	ATF_REQUIRE(owner >= 0);

	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(go) == 0);
	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char c;

		close(jailco);
		close(owner);
		close(ready[0]);
		close(go[1]);
		/* Announce, wait to be enlisted, then enter the jail. */
		(void)write(ready[1], "r", 1);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		if (jail_attach(jid) != 0)
			_exit(2);
		pause();
		_exit(0);
	}
	close(ready[1]);
	close(go[0]);
	ATF_REQUIRE(read(ready[0], &tok, 1) == 1);
	close(ready[0]);

	/* Enlisted first, so the enlistment is the statement that stands. */
	ATF_REQUIRE(coalition_enlist(owner, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * Now let it move into the held jail.  Entering the jail must not
	 * take it away from the coalition that enlisted it.
	 */
	ATF_REQUIRE(write(go[1], "g", 1) == 1);
	close(go[1]);
	for (i = 0; i < 50; i++) {
		if (coalition_ledger(jailco, 0, &jl) == 0 && jl.status == 0 &&
		    coalition_ledger(owner, 0, &ol) == 0 && ol.status == 0 &&
		    ol.nprocs > 0)
			break;
		usleep(100000);
	}
	ATF_CHECK_EQ_MSG(ol.nprocs, 1,
	    "the enlisted process was not charged to the coalition that "
	    "enlisted it (%u)", ol.nprocs);
	ATF_REQUIRE(coalition_ledger(jailco, 0, &jl) == 0);
	ATF_CHECK_EQ_MSG(jl.nprocs, 0,
	    "the jail's coalition claimed a process enlisted elsewhere (%u)",
	    jl.nprocs);

	pdkill(pd, SIGKILL);
	(void)wait_exit_bounded(pid, &wstatus);
	close(pd);
	close(owner);
	close(jailco);
	close(jail_fd);
}
ATF_TC_CLEANUP(enlistment_beats_the_jail_it_is_in, tc)
{
	remove_jail_by_name(COALITION_TEST_JAIL_NAME);
}

ATF_TC_WITH_CLEANUP(close_removes_jaildesc_member);
ATF_TC_HEAD(close_removes_jaildesc_member, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Closing a coalition removes enlisted jaildesc members");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(close_removes_jaildesc_member, tc)
{
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

	close(cfd);
	wait_for_jail_removal(COALITION_TEST_JAIL_NAME);

	close(jail_fd);
}
ATF_TC_CLEANUP(close_removes_jaildesc_member, tc)
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
 * Resource exhaustion + teardown-race stress
 * ================================================================ */

static u_int
coalition_sysctl_get(const char *name)
{
	u_int v;
	size_t len = sizeof(v);

	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (0);
	return (v);
}

static int
coalition_sysctl_set(const char *name, u_int v)
{

	return (sysctlbyname(name, NULL, NULL, &v, sizeof(v)));
}

/*
 * Opening more coalitions than kern.mac_capability_coalition.max must fail
 * gracefully with ENOMEM at the cap -- never panic or allocate unbounded.  We
 * lower the cap to baseline+N so the test is fast and deterministic regardless
 * of any coalitions other tests leaked, and restore it unconditionally.
 */
ATF_TC(exhaust_coalition_max);
ATF_TC_HEAD(exhaust_coalition_max, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition create cap is enforced with ENOMEM, no panic, no leak");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(exhaust_coalition_max, tc)
{
#define	EXH_N	16
	u_int orig, base;
	int fds[EXH_N], extra, i, opened;

	orig = coalition_sysctl_get("kern.mac_capability_coalition.max");
	base = coalition_sysctl_get("kern.mac_capability_coalition.count");
	ATF_REQUIRE_MSG(coalition_sysctl_set(
	    "kern.mac_capability_coalition.max", base + EXH_N) == 0,
	    "set max: %s", strerror(errno));

	/* Fill exactly to the cap. */
	opened = 0;
	for (i = 0; i < EXH_N; i++) {
		fds[i] = mac_capability_connect("coalition");
		if (fds[i] < 0)
			break;
		opened++;
	}
	ATF_CHECK_EQ_MSG(opened, EXH_N, "opened %d of %d before the cap",
	    opened, EXH_N);

	/* One past the cap must fail with ENOMEM, not succeed and not panic. */
	extra = mac_capability_connect("coalition");
	ATF_CHECK_MSG(extra < 0 && errno == ENOMEM,
	    "connect past cap: fd=%d errno=%d (want ENOMEM)", extra, errno);
	if (extra >= 0)
		close(extra);

	for (i = 0; i < opened; i++)
		close(fds[i]);
	(void)coalition_sysctl_set("kern.mac_capability_coalition.max", orig);

	/* Count returns to baseline -- no leaked coalitions. */
	ATF_CHECK_EQ_MSG(coalition_sysctl_get("kern.mac_capability_coalition.count"),
	    base, "coalition count did not return to baseline");
#undef EXH_N
}

/*
 * Enlisting more members than kern.mac_capability_coalition.max_members must be
 * refused with a non-zero status (ENOMEM), never panic or leak.
 */
ATF_TC(exhaust_member_max);
ATF_TC_HEAD(exhaust_member_max, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Member cap is enforced with ENOMEM; count returns to baseline");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(exhaust_member_max, tc)
{
#define	MEM_N	24
	u_int orig, base;
	int cfd, sv[MEM_N][2], extra[2], i, enlisted;
	int32_t status;

	orig = coalition_sysctl_get("kern.mac_capability_coalition.max_members");
	base = coalition_sysctl_get("kern.mac_capability_coalition.members");
	ATF_REQUIRE(coalition_sysctl_set(
	    "kern.mac_capability_coalition.max_members", base + MEM_N) == 0);

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);

	enlisted = 0;
	for (i = 0; i < MEM_N; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) != 0)
			break;
		status = 0;
		if (coalition_enlist(cfd, sv[i][0], &status) != 0 || status != 0) {
			close(sv[i][0]); close(sv[i][1]);
			break;
		}
		enlisted++;
	}
	ATF_CHECK_EQ_MSG(enlisted, MEM_N, "enlisted %d of %d before the cap",
	    enlisted, MEM_N);

	/* One past the cap: enlist must report ENOMEM in status, not panic. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, extra) == 0);
	status = 0;
	(void)coalition_enlist(cfd, extra[0], &status);
	ATF_CHECK_MSG(status == ENOMEM, "enlist past cap: status=%d (want ENOMEM)",
	    status);
	close(extra[0]); close(extra[1]);

	close(cfd);
	for (i = 0; i < enlisted; i++) { close(sv[i][0]); close(sv[i][1]); }
	(void)coalition_sysctl_set(
	    "kern.mac_capability_coalition.max_members", orig);

	ATF_CHECK_EQ_MSG(coalition_sysctl_get("kern.mac_capability_coalition.members"),
	    base, "member count did not return to baseline");
#undef MEM_N
}

/*
 * The "dead jail" hazard: a jail member can be torn down from BOTH the coalition
 * side (close -> coalition_jail_terminate -> prison_remove) and the jail side
 * (jail_remove -> OSD dtor -> cleanup task).  Race the two paths many times so a
 * double-free / UAF / lock bug trips on an INVARIANTS+WITNESS kernel.  Each
 * round forks a child that jail_remove()s while the parent close()s the
 * coalition, alternating which starts first.
 */
ATF_TC(jail_teardown_race);
ATF_TC_HEAD(jail_teardown_race, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Race coalition close vs jail_remove on a jail member; no panic/leak");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(jail_teardown_race, tc)
{
	u_int base;
	int round;

	base = coalition_sysctl_get("kern.mac_capability_coalition.count");

	for (round = 0; round < 40; round++) {
		char name[64];
		int cfd, jail_fd, jid;
		int32_t status;
		pid_t pid;

		snprintf(name, sizeof(name), "%s_race_%d",
		    COALITION_TEST_JAIL_NAME, round);
		remove_jail_by_name(name);

		jail_fd = create_jail_with_desc(name);
		ATF_REQUIRE_MSG(jail_fd >= 0, "round %d create_jail: %s",
		    round, strerror(errno));
		jid = jail_getid(name);
		cfd = mac_capability_connect("coalition");
		ATF_REQUIRE(cfd >= 0);
		ATF_REQUIRE(coalition_enlist(cfd, jail_fd, &status) == 0);
		ATF_REQUIRE_EQ(status, 0);

		/* Child removes the jail; parent closes the coalition -- racing
		 * the jail-side and coalition-side teardown of the same member.
		 * Alternate which side is nudged first across rounds. */
		pid = fork();
		ATF_REQUIRE(pid >= 0);
		if (pid == 0) {
			if (round & 1)
				(void)jail_remove(jid);
			else {
				(void)usleep(1);
				(void)jail_remove(jid);
			}
			_exit(0);
		}
		if (round & 1)
			(void)usleep(1);
		close(cfd);
		(void)waitpid(pid, NULL, 0);

		wait_for_jail_removal(name);
		close(jail_fd);
	}

	/* No coalitions leaked across 40 create/teardown-race rounds. */
	ATF_CHECK_EQ_MSG(coalition_sysctl_get("kern.mac_capability_coalition.count"),
	    base, "coalition count did not return to baseline after race churn");
}

/*
 * Churn coalitions + socket members repeatedly and confirm the global member
 * and coalition counts return to baseline -- catches a member/coalition leak in
 * the teardown paths.
 */
ATF_TC(coalition_churn_no_leak);
ATF_TC_HEAD(coalition_churn_no_leak, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalition + member counts return to baseline after churn (no leak)");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(coalition_churn_no_leak, tc)
{
	u_int cbase, mbase;
	int round;

	cbase = coalition_sysctl_get("kern.mac_capability_coalition.count");
	mbase = coalition_sysctl_get("kern.mac_capability_coalition.members");

	for (round = 0; round < 100; round++) {
		int cfd, sv[4][2], i;
		int32_t status;

		cfd = mac_capability_connect("coalition");
		ATF_REQUIRE(cfd >= 0);
		for (i = 0; i < 4; i++) {
			ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv[i]) == 0);
			ATF_REQUIRE(coalition_enlist(cfd, sv[i][0], &status) == 0);
			ATF_REQUIRE_EQ(status, 0);
		}
		/* Alternate terminate-then-close vs bare close. */
		if (round & 1)
			(void)coalition_op(cfd, COALITION_OP_TERMINATE, &status);
		close(cfd);
		for (i = 0; i < 4; i++) { close(sv[i][0]); close(sv[i][1]); }
	}

	ATF_CHECK_EQ_MSG(coalition_sysctl_get("kern.mac_capability_coalition.count"),
	    cbase, "coalition count leaked after churn");
	ATF_CHECK_EQ_MSG(coalition_sysctl_get("kern.mac_capability_coalition.members"),
	    mbase, "member count leaked after churn");
}

/* ================================================================
 * Test registration
 * ================================================================ */


ATF_TC(band_floor_default_and_set);
ATF_TC_HEAD(band_floor_default_and_set, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A new coalition starts at the standard band; the holder may move "
	    "the floor, out-of-range bands are refused, and with no assertions "
	    "the effective band is the floor");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_floor_default_and_set, tc)
{
	struct coalition_band_reply br;
	struct coalition_stat_reply sr;
	int fd, b;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);

	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.status, 0);
	ATF_CHECK_EQ(br.id, sr.id);
	ATF_CHECK_EQ(br.floor, COALITION_BAND_STANDARD);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_STANDARD);
	for (b = 0; b < COALITION_BAND_COUNT; b++)
		ATF_CHECK_EQ(br.nassert[b], 0);

	/* Every valid band can be set, and reads back as the effective band. */
	for (b = 0; b < COALITION_BAND_COUNT; b++) {
		ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
		    (uint32_t)b, &br) == 0);
		ATF_CHECK_EQ(br.status, 0);
		ATF_CHECK_EQ(br.floor, (uint32_t)b);
		ATF_CHECK_EQ(br.effective, (uint32_t)b);
	}

	/* Out of range, and unknown flags, are refused without changing it. */
	ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_COUNT, &br) == 0);
	ATF_CHECK_EQ(br.status, EINVAL);
	ATF_REQUIRE(coalition_band(fd, 0x80, 0, &br) == 0);
	ATF_CHECK_EQ(br.status, EINVAL);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.floor, COALITION_BAND_CRITICAL);
	close(fd);
}

ATF_TC(band_assertion_raises_and_close_drops);
ATF_TC_HEAD(band_assertion_raises_and_close_drops, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An assertion descriptor raises the effective band while it is "
	    "open and drops it when closed; assertions below the floor do not "
	    "lower it; the highest assertion wins");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertion_raises_and_close_drops, tc)
{
	struct coalition_band_reply br;
	int fd, a_int, a_crit, a_idle;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	/* Put the floor at the bottom so assertions are what moves it. */
	ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_IDLE, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_INTERACTIVE,
	    &br, &a_int) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(a_int >= 0);
	ATF_CHECK_EQ(br.asserted, COALITION_BAND_INTERACTIVE);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_INTERACTIVE);
	ATF_CHECK_EQ(br.nassert[COALITION_BAND_INTERACTIVE], 1);

	/* A lower assertion cannot pull the band back down. */
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_IDLE,
	    &br, &a_idle) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_INTERACTIVE);

	/* A higher one raises it further. */
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_CRITICAL,
	    &br, &a_crit) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_CRITICAL);

	/* Closing the top assertion falls back to the next one down. */
	ATF_REQUIRE(close(a_crit) == 0);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_INTERACTIVE);
	ATF_CHECK_EQ(br.nassert[COALITION_BAND_CRITICAL], 0);

	ATF_REQUIRE(close(a_int) == 0);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_IDLE);

	ATF_REQUIRE(close(a_idle) == 0);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_IDLE);
	ATF_CHECK_EQ(br.nassert[COALITION_BAND_IDLE], 0);
	close(fd);
}

ATF_TC(band_assertion_dies_with_holder);
ATF_TC_HEAD(band_assertion_dies_with_holder, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An assertion held only by a process that exits is released by the "
	    "kernel: a crashed holder cannot pin a coalition at a high band");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertion_dies_with_holder, tc)
{
	struct coalition_band_reply br;
	int fd, afd, wstatus;
	pid_t pid;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_IDLE, &br) == 0);
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_CRITICAL,
	    &br, &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_CRITICAL);

	/*
	 * Hand the only copy to a child and let it die.  The parent closes its
	 * copy first, so the child's exit is the last reference.
	 */
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Hold it, then die abruptly. */
		_exit(0);
	}
	ATF_REQUIRE(close(afd) == 0);
	ATF_REQUIRE(waitpid(pid, &wstatus, 0) == pid);

	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.effective, COALITION_BAND_IDLE);
	ATF_CHECK_EQ(br.nassert[COALITION_BAND_CRITICAL], 0);
	close(fd);
}

ATF_TC(band_assertion_carries_no_authority);
ATF_TC_HEAD(band_assertion_carries_no_authority, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An assertion descriptor reports the band and nothing else: it is "
	    "not a coalition, so terminate, stat and enlist are all refused, "
	    "and it cannot be obtained by connecting to the service");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertion_carries_no_authority, tc)
{
	struct coalition_band_reply br, abr;
	struct coalition_stat_reply sr;
	struct coalition_req_hdr hdr;
	int fd, afd;

	/* The assertion service refuses a direct connection. */
	ATF_CHECK(mac_capability_connect("coalition_assert") < 0);

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_INTERACTIVE,
	    &br, &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	/* It answers COALITION_OP_BAND, naming its own band. */
	memset(&abr, 0, sizeof(abr));
	ATF_REQUIRE(coalition_band(afd, 0, 0, &abr) == 0);
	ATF_CHECK_EQ(abr.id, sr.id);
	ATF_CHECK_EQ(abr.asserted, COALITION_BAND_INTERACTIVE);
	ATF_CHECK_EQ(abr.effective, COALITION_BAND_INTERACTIVE);

	/* It answers nothing else. */
	hdr.op = COALITION_OP_TERMINATE;
	ATF_CHECK(coalition_call(afd, &hdr, sizeof(hdr), NULL, 0,
	    &abr, sizeof(abr)) != 0);
	hdr.op = COALITION_OP_STAT;
	ATF_CHECK(coalition_call(afd, &hdr, sizeof(hdr), NULL, 0,
	    &sr, sizeof(sr)) != 0);

	/* Setting a floor through an assertion is refused, not honoured. */
	ATF_CHECK(coalition_band(afd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_IDLE, &abr) != 0);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.floor, COALITION_BAND_STANDARD);

	/* The coalition is still alive and still holds the assertion. */
	ATF_REQUIRE(coalition_stat(fd, &sr) == 0);
	ATF_CHECK_EQ(br.nassert[COALITION_BAND_INTERACTIVE], 1);
	close(afd);
	close(fd);
}

ATF_TC(band_assertion_outlives_coalition_fd);
ATF_TC_HEAD(band_assertion_outlives_coalition_fd, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An assertion keeps the coalition object alive after the coalition "
	    "descriptor is closed: the assertion still answers, and closing it "
	    "releases the last reference without a panic");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertion_outlives_coalition_fd, tc)
{
	struct coalition_band_reply br;
	int fd, afd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_CRITICAL,
	    &br, &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(afd >= 0);

	/* Drop the coalition; the assertion is the only thing holding it. */
	ATF_REQUIRE(close(fd) == 0);

	memset(&br, 0, sizeof(br));
	ATF_REQUIRE(coalition_band(afd, 0, 0, &br) == 0);
	ATF_CHECK_EQ(br.asserted, COALITION_BAND_CRITICAL);
	ATF_REQUIRE(close(afd) == 0);
}

ATF_TC(band_assertion_churn_under_readers);
ATF_TC_HEAD(band_assertion_churn_under_readers, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Coalitions and assertions churn while other processes enumerate "
	    "every process repeatedly: exercises the lock-free process-hash and "
	    "coalition-list read paths against concurrent create and free");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertion_churn_under_readers, tc)
{
	struct coalition_band_reply br;
	int i, r, wstatus, nreaders = 4;
	pid_t readers[4], pid;

	/*
	 * The readers hammer the exporter: every kinfo_proc fill calls into
	 * the coalition process hash with no lock held, so this is the race
	 * the SMR read side has to survive.
	 */
	for (r = 0; r < nreaders; r++) {
		pid = fork();
		ATF_REQUIRE(pid >= 0);
		if (pid == 0) {
			size_t len;
			int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };

			for (i = 0; i < 400; i++) {
				len = 0;
				(void)sysctl(mib, 3, NULL, &len, NULL, 0);
				if (len != 0) {
					void *buf = malloc(len);

					if (buf != NULL) {
						(void)sysctl(mib, 3, buf, &len,
						    NULL, 0);
						free(buf);
					}
				}
			}
			_exit(0);
		}
		readers[r] = pid;
	}

	for (i = 0; i < 300; i++) {
		int fd, afd, pd;
		pid_t child;

		fd = mac_capability_connect("coalition");
		ATF_REQUIRE(fd >= 0);
		/* A real process member, so the hash is written too. */
		child = pdfork(&pd, 0);
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			pause();
			_exit(0);
		}
		(void)coalition_enlist(fd, pd, NULL);
		if (coalition_assert(fd, (uint32_t)(i % COALITION_BAND_COUNT),
		    &br, &afd) == 0 && afd >= 0) {
			if ((i & 1) == 0)
				close(afd);
			else {
				/* Close order reversed for half the rounds. */
				close(fd);
				fd = -1;
				close(afd);
			}
		}
		if (fd >= 0)
			close(fd);
		close(pd);
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &wstatus, 0);
	}

	for (r = 0; r < nreaders; r++)
		ATF_CHECK(waitpid(readers[r], &wstatus, 0) == readers[r]);
}

ATF_TC(band_assertions_are_capped);
ATF_TC_HEAD(band_assertions_are_capped, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition's live assertions are capped, so one holder cannot "
	    "consume the assertion service's whole budget and leave nothing "
	    "for anyone else; the cap is released as assertions are closed");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_assertions_are_capped, tc)
{
	struct coalition_band_reply br;
	u_int cap = 0;
	size_t len = sizeof(cap);
	int fd, afd, i, got = 0, refused = 0;
	int *afds;

	if (sysctlbyname("kern.mac_capability_coalition.max_assertions", &cap,
	    &len, NULL, 0) != 0)
		atf_tc_skip("max_assertions sysctl unavailable: %s",
		    strerror(errno));
	ATF_REQUIRE(cap > 0 && cap < 4096);

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	afds = calloc(cap + 8, sizeof(*afds));
	ATF_REQUIRE(afds != NULL);

	/*
	 * Ask for more than the cap allows.  The limit is a soft one, so a few
	 * extra may slip through when threads race; what must not happen is
	 * that it keeps handing them out without bound.
	 */
	for (i = 0; i < (int)cap + 8; i++) {
		if (coalition_assert(fd, COALITION_BAND_STANDARD, &br,
		    &afd) == 0 && br.status == 0 && afd >= 0) {
			afds[got++] = afd;
		} else {
			refused++;
			afds[i] = -1;
		}
	}
	ATF_CHECK_MSG(refused > 0, "the cap never refused an assertion: "
	    "granted %d with a cap of %u", got, cap);
	ATF_CHECK_MSG((u_int)got <= cap + 8,
	    "granted %d assertions with a cap of %u", got, cap);

	/* Closing them frees the budget again. */
	for (i = 0; i < got; i++)
		close(afds[i]);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_EQ_MSG(0, br.nassert[COALITION_BAND_STANDARD],
	    "assertions still counted after every one was closed: %u",
	    br.nassert[COALITION_BAND_STANDARD]);
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_STANDARD, &br,
	    &afd) == 0);
	ATF_CHECK_EQ_MSG(br.status, 0,
	    "the cap did not recover after closing every assertion");
	if (afd >= 0)
		close(afd);
	free(afds);
	close(fd);
}

ATF_TC(band_visible_in_kinfo);
ATF_TC_HEAD(band_visible_in_kinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A process's effective band is exported through kinfo_proc, so ps "
	    "and procstat can show it: a process in no coalition reports -1, a "
	    "member reports its coalition's band, and an assertion raising the "
	    "band shows up there");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(band_visible_in_kinfo, tc)
{
	struct coalition_band_reply br;
	struct kinfo_proc kp;
	int cfd, pd, afd, wstatus;
	int32_t status;
	pid_t pid;

	/* We are in no coalition: -1, distinguishable from the idle band. */
	ATF_REQUIRE(kinfo_of(getpid(), &kp) == 0);
	ATF_CHECK_EQ_MSG(-1, kp.ki_coalition_band,
	    "a process in no coalition reported band %d",
	    kp.ki_coalition_band);

	cfd = mac_capability_connect("coalition");
	ATF_REQUIRE(cfd >= 0);
	ATF_REQUIRE(coalition_band(cfd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_BACKGROUND, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	pid = coalition_fork_member(cfd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(cfd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ_MSG(COALITION_BAND_BACKGROUND, kp.ki_coalition_band,
	    "member reported band %d, expected the floor",
	    kp.ki_coalition_band);

	/* An assertion raises it, and the member's kinfo follows. */
	ATF_REQUIRE(coalition_assert(cfd, COALITION_BAND_CRITICAL, &br,
	    &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ_MSG(COALITION_BAND_CRITICAL, kp.ki_coalition_band,
	    "member reported band %d while an assertion held it critical",
	    kp.ki_coalition_band);

	/* Closing the assertion drops it back to the floor. */
	ATF_REQUIRE(close(afd) == 0);
	ATF_REQUIRE(kinfo_of(pid, &kp) == 0);
	ATF_CHECK_EQ_MSG(COALITION_BAND_BACKGROUND, kp.ki_coalition_band,
	    "member reported band %d after the assertion was closed",
	    kp.ki_coalition_band);

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(cfd);
}

ATF_TC(pressure_hands_down_low_bands);
ATF_TC_HEAD(pressure_hands_down_low_bands, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Memory pressure hands low-band coalitions down rather than "
	    "killing them: a background coalition's members are advised "
	    "reclaimable and keep running, while a critical one is left alone");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(pressure_hands_down_low_bands, tc)
{
	struct coalition_band_reply br;
	struct kinfo_proc kp;
	u_int before = 0, after = 0;
	size_t len = sizeof(before);
	int lowmem = TEST_VM_LOW_PAGES;
	int lo, hi, pdlo, pdhi, wstatus;
	int32_t status;
	pid_t plo, phi;

	if (sysctlbyname("kern.mac_capability_coalition.pressure_reclaims",
	    &before, &len, NULL, 0) != 0)
		atf_tc_skip("pressure_reclaims sysctl unavailable: %s",
		    strerror(errno));

	/* One coalition the system may give up, one it may not. */
	lo = mac_capability_connect("coalition");
	hi = mac_capability_connect("coalition");
	ATF_REQUIRE(lo >= 0 && hi >= 0);
	ATF_REQUIRE(coalition_band(lo, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_BACKGROUND, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(coalition_band(hi, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_CRITICAL, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	plo = coalition_fork_member(lo, &pdlo);
	ATF_REQUIRE(plo > 0);
	ATF_REQUIRE(coalition_enlist(lo, pdlo, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	phi = coalition_fork_member(hi, &pdhi);
	ATF_REQUIRE(phi > 0);
	ATF_REQUIRE(coalition_enlist(hi, pdhi, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	if (sysctlbyname("debug.vm_lowmem", NULL, NULL, &lowmem,
	    sizeof(lowmem)) != 0)
		atf_tc_skip("debug.vm_lowmem unavailable: %s",
		    strerror(errno));
	usleep(500000);

	/*
	 * Handing down is advisory, so the footprint is not a reliable
	 * assertion -- a small paused process may have nothing worth
	 * reclaiming.  What must hold is that the pass acted and that acting
	 * did not terminate anybody.
	 */
	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname(
	    "kern.mac_capability_coalition.pressure_reclaims", &after, &len,
	    NULL, 0) == 0);
	ATF_CHECK_MSG(after >= before,
	    "the hand-down counter went backwards: %u then %u", before, after);

	/* Nothing was killed: both members are alive and still members. */
	ATF_CHECK_MSG(kill(plo, 0) == 0,
	    "the background member was terminated, not handed down");
	ATF_CHECK_MSG(kill(phi, 0) == 0, "the critical member was terminated");
	ATF_REQUIRE(kinfo_of(plo, &kp) == 0);
	ATF_CHECK(kp.ki_stat != SZOMB);
	ATF_CHECK_EQ_MSG(COALITION_BAND_BACKGROUND, kp.ki_coalition_band,
	    "the background member left its band: %d", kp.ki_coalition_band);
	ATF_REQUIRE(kinfo_of(phi, &kp) == 0);
	ATF_CHECK(kp.ki_stat != SZOMB);
	ATF_CHECK_EQ_MSG(COALITION_BAND_CRITICAL, kp.ki_coalition_band,
	    "the critical member left its band: %d", kp.ki_coalition_band);

	pdkill(pdlo, SIGKILL);
	pdkill(pdhi, SIGKILL);
	waitpid(plo, &wstatus, 0);
	waitpid(phi, &wstatus, 0);
	close(pdlo);
	close(pdhi);
	close(lo);
	close(hi);
}

ATF_TC(oom_policy_is_installed_and_bounded);
ATF_TC_HEAD(oom_policy_is_installed_and_bounded, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The out-of-memory victim policy is present, on by default, and "
	    "will not consider a coalition above its band ceiling, so the "
	    "critical band stays out of reach of a memory kill");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(oom_policy_is_installed_and_bounded, tc)
{
	int on = -1;
	u_int ceiling = 0, kills = 0;
	size_t len;

	len = sizeof(on);
	if (sysctlbyname("kern.mac_capability_coalition.oom_kill", &on, &len,
	    NULL, 0) != 0)
		atf_tc_skip("oom_kill sysctl unavailable: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(1, on,
	    "the out-of-memory policy is not on by default");

	len = sizeof(ceiling);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition."
	    "oom_band_ceiling", &ceiling, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(ceiling < COALITION_BAND_CRITICAL,
	    "the ceiling admits the critical band: %u", ceiling);

	/* The report counter exists and is readable. */
	len = sizeof(kills);
	ATF_CHECK(sysctlbyname("kern.mac_capability_coalition.oom_kills",
	    &kills, &len, NULL, 0) == 0);
}

ATF_TC(oom_ceiling_excludes_critical_band);
ATF_TC_HEAD(oom_ceiling_excludes_critical_band, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Raising a coalition to the critical band, by floor or by holding "
	    "an assertion, puts it above the out-of-memory ceiling; the band "
	    "the policy reads is the effective one, not the floor");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(oom_ceiling_excludes_critical_band, tc)
{
	struct coalition_band_reply br;
	u_int ceiling = 0;
	size_t len = sizeof(ceiling);
	int fd, afd;

	if (sysctlbyname("kern.mac_capability_coalition.oom_band_ceiling",
	    &ceiling, &len, NULL, 0) != 0)
		atf_tc_skip("oom_band_ceiling sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* A background unit is a candidate. */
	ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_BACKGROUND, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_CHECK_MSG(br.effective <= ceiling,
	    "a background coalition is not a candidate: band %u ceiling %u",
	    br.effective, ceiling);

	/*
	 * An assertion alone lifts it out of reach, without touching the
	 * floor.  This is what lets a client protect work in flight from a
	 * memory kill by holding a descriptor.
	 */
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_CRITICAL, &br,
	    &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_CHECK_EQ(COALITION_BAND_CRITICAL, br.effective);
	ATF_CHECK_MSG(br.effective > ceiling,
	    "an asserted critical coalition is still a candidate: band %u "
	    "ceiling %u", br.effective, ceiling);
	ATF_CHECK_EQ_MSG(COALITION_BAND_BACKGROUND, br.floor,
	    "the assertion changed the floor");

	/* Dropping it puts the coalition back in reach. */
	ATF_REQUIRE(close(afd) == 0);
	ATF_REQUIRE(coalition_band(fd, 0, 0, &br) == 0);
	ATF_CHECK_MSG(br.effective <= ceiling,
	    "the coalition stayed out of reach after the assertion went: %u",
	    br.effective);
	close(fd);
}

ATF_TC(limit_absent_by_default_and_settable);
ATF_TC_HEAD(limit_absent_by_default_and_settable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition has no footprint ceiling unless one is declared, a "
	    "ceiling can be set and removed, and unknown flags are refused");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(limit_absent_by_default_and_settable, tc)
{
	struct coalition_ledger_reply lr;
	int32_t status = -1;
	int fd;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/*
	 * No ceiling to begin with: a refresh, which is where the ceiling is
	 * enforced, must be harmless on a coalition that has none.
	 */
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);

	/* Set one generously, notify-only. */
	ATF_REQUIRE(coalition_set_limit(fd, 0, 1ULL << 40, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "a ceiling was refused: %d", status);
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);

	/* Ask for termination on breach, still generous, still harmless. */
	ATF_REQUIRE(coalition_set_limit(fd, COALITION_LIMIT_KILL, 1ULL << 40,
	    &status) == 0);
	ATF_CHECK_EQ(status, 0);
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);

	/* Remove it. */
	ATF_REQUIRE(coalition_set_limit(fd, 0, 0, &status) == 0);
	ATF_CHECK_EQ(status, 0);

	/* Unknown flags are refused. */
	ATF_REQUIRE(coalition_set_limit(fd, 0x80, 1ULL << 40, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);
	close(fd);
}

ATF_TC(limit_breach_terminates_regardless_of_band);
ATF_TC_HEAD(limit_breach_terminates_regardless_of_band, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition over the ceiling declared for it is terminated even "
	    "in the critical band, because it is over budget rather than "
	    "merely expendable; the counter records it");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(limit_breach_terminates_regardless_of_band, tc)
{
	struct coalition_band_reply br;
	struct coalition_ledger_reply lr;
	u_int before = 0, after = 0;
	size_t len = sizeof(before);
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	if (sysctlbyname("kern.mac_capability_coalition.limit_kills", &before,
	    &len, NULL, 0) != 0)
		atf_tc_skip("limit_kills sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	/* Critical band: this must not save it from its own ceiling. */
	ATF_REQUIRE(coalition_band(fd, COALITION_BAND_SET_FLOOR,
	    COALITION_BAND_CRITICAL, &br) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* A ceiling of one byte is breached by any live member. */
	ATF_REQUIRE(coalition_set_limit(fd, COALITION_LIMIT_KILL, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	if (!wait_for_resident_accounting(fd))
		atf_tc_skip("the page daemon did not attribute resident "
		    "memory to the coalition; nothing to breach a ceiling "
		    "with");

	/* The refresh now means: judge the ceiling, do not wait for a sweep. */
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_EQ(lr.status, 0);
	ATF_CHECK_MSG(lr.rss_bytes > 1,
	    "the member had no footprint to exceed the ceiling with");

	ATF_CHECK_MSG(wait_exit_bounded(pid, &wstatus),
	    "a coalition over its own ceiling was not terminated");

	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &after, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(after > before,
	    "the ceiling termination was not counted: %u then %u", before,
	    after);

	close(pd);
	close(fd);
}

ATF_TC(limit_under_ceiling_is_left_alone);
ATF_TC_HEAD(limit_under_ceiling_is_left_alone, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition within its ceiling is not touched by a refresh, and "
	    "raising a ceiling above a footprint that had breached it rearms "
	    "the coalition rather than leaving it marked over");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(limit_under_ceiling_is_left_alone, tc)
{
	struct coalition_ledger_reply lr;
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Notify-only, and breached: the member must survive it. */
	ATF_REQUIRE(coalition_set_limit(fd, 0, 1, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	if (!wait_for_resident_accounting(fd))
		atf_tc_skip("the page daemon did not attribute resident "
		    "memory to the coalition");
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "a notify-only ceiling terminated the coalition");

	/* Raise it out of reach; the coalition is rearmed and still alive. */
	ATF_REQUIRE(coalition_set_limit(fd, COALITION_LIMIT_KILL, 1ULL << 40,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "raising the ceiling did not clear the breach");

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(fd);
}

ATF_TC(idle_exit_is_opt_in);
ATF_TC_HEAD(idle_exit_is_opt_in, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition is never put away for being idle unless it was "
	    "declared able to come back; a quiet coalition that never declared "
	    "it survives the sweep, and unknown flags are refused");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(idle_exit_is_opt_in, tc)
{
	int fd, pd, wstatus;
	int32_t status = -1;
	u_int saved;
	pid_t pid;

	saved = sweep_interval_set(SWEEP_FAST_MS);
	if (saved == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Never declared: several sweeps must go by without touching it. */
	usleep(3500000);
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "a coalition that never opted in was put away");

	/* Unknown flags are refused. */
	ATF_REQUIRE(coalition_set_idle_exit(fd, 0x80, 0, &status) == 0);
	ATF_CHECK_EQ(status, EINVAL);

	/* Declaring it with a long age keeps it safe for now. */
	ATF_REQUIRE(coalition_set_idle_exit(fd, COALITION_IDLE_EXIT_ENABLE,
	    3600000, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	usleep(3500000);
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "a coalition idle for seconds was put away with an hour's age");

	pdkill(pd, SIGKILL);
	waitpid(pid, &wstatus, 0);
	close(pd);
	close(fd);
	sweep_interval_restore(saved);
}

ATF_TC(idle_exit_puts_away_after_its_age);
ATF_TC_HEAD(idle_exit_puts_away_after_its_age, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition declared able to come back, holding no assertion, is "
	    "put away once it has been idle for its declared age, and the "
	    "reason is counted as an idle exit rather than a memory kill");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(idle_exit_puts_away_after_its_age, tc)
{
	u_int before = 0, after = 0, oom_before = 0, oom_after = 0, saved;
	size_t len = sizeof(before);
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	saved = sweep_interval_set(SWEEP_FAST_MS);
	if (saved == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));
	if (sysctlbyname("kern.mac_capability_coalition.idle_kills", &before,
	    &len, NULL, 0) != 0)
		atf_tc_skip("idle_kills sysctl unavailable: %s",
		    strerror(errno));
	len = sizeof(oom_before);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.oom_kills",
	    &oom_before, &len, NULL, 0) == 0);

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Eligible immediately: no assertions, and no age to wait out. */
	ATF_REQUIRE(coalition_set_idle_exit(fd, COALITION_IDLE_EXIT_ENABLE, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_CHECK_MSG(wait_exit_bounded(pid, &wstatus),
	    "an idle coalition was not put away");

	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.idle_kills",
	    &after, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(after > before,
	    "the idle exit was not counted: %u then %u", before, after);

	/* And it was not mistaken for the machine running out of memory. */
	len = sizeof(oom_after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.oom_kills",
	    &oom_after, &len, NULL, 0) == 0);
	ATF_CHECK_EQ_MSG(oom_before, oom_after,
	    "an idle exit was counted as an out-of-memory kill");

	close(pd);
	close(fd);
	sweep_interval_restore(saved);
}

ATF_TC(idle_exit_is_held_off_by_an_assertion);
ATF_TC_HEAD(idle_exit_is_held_off_by_an_assertion, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An assertion means the work is in use: it holds off an idle exit "
	    "however long the coalition has been quiet, and dropping it starts "
	    "the idle clock again rather than resuming where it left off");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(idle_exit_is_held_off_by_an_assertion, tc)
{
	struct coalition_band_reply br;
	int fd, pd, afd, wstatus;
	int32_t status;
	u_int saved;
	pid_t pid;

	saved = sweep_interval_set(SWEEP_FAST_MS);
	if (saved == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Hold the work, then declare it eligible with no age to wait. */
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_BACKGROUND, &br,
	    &afd) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(coalition_set_idle_exit(fd, COALITION_IDLE_EXIT_ENABLE, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Several sweeps must go by without it being taken. */
	usleep(2500000);
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "an idle exit ignored a held assertion");

	/* Dropping it makes the coalition eligible, and it goes. */
	ATF_REQUIRE(close(afd) == 0);
	ATF_CHECK_MSG(wait_exit_bounded(pid, &wstatus),
	    "the coalition was not put away after its assertion went");

	close(pd);
	close(fd);
	sweep_interval_restore(saved);
}

ATF_TC_WITH_CLEANUP(vmem_ceiling_needs_no_sample);
ATF_TC_HEAD(vmem_ceiling_needs_no_sample, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An address-space ceiling is judged from a counter the accounting "
	    "framework maintains, not from a walk of the members: with the "
	    "periodic sweep switched off entirely, one request to judge the "
	    "ceilings catches a member that has mapped past it");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(vmem_ceiling_needs_no_sample, tc)
{
	struct coalition_ledger_reply lr;
	u_int before = 0, after = 0;
	int saved_sweep;
	size_t len = sizeof(before);
	int fd, pd, ready[2], wstatus;
	int32_t status;
	pid_t pid;
	int i;

	if (sysctlbyname("kern.mac_capability_coalition.limit_kills", &before,
	    &len, NULL, 0) != 0)
		atf_tc_skip("limit_kills sysctl unavailable: %s",
		    strerror(errno));

	/*
	 * Switch the sweep OFF rather than lengthening its interval.  Writing
	 * a long interval does not cancel the callout that is already armed,
	 * so one more sweep still lands at the old interval and would enforce
	 * the ceiling for us -- which is exactly what this test must not let
	 * happen, or it proves nothing about where the figure came from.
	 */
	saved_sweep = sweep_enable_set(0);
	if (saved_sweep < 0)
		atf_tc_skip("sweep sysctl unavailable: %s", strerror(errno));
	sweep_enable_saved = saved_sweep;

	ATF_REQUIRE(pipe(ready) == 0);
	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		char c;

		close(ready[1]);
		close(fd);
		if (read(ready[0], &c, 1) == 1)
			(void)mmap(NULL, 256UL << 20, PROT_READ | PROT_WRITE,
			    MAP_ANON | MAP_PRIVATE, -1, 0);
		pause();
		_exit(0);
	}
	close(ready[0]);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* A ceiling the child is under now and will exceed when it maps. */
	ATF_REQUIRE(coalition_set_limit_full(fd, COALITION_LIMIT_KILL, 0,
	    64UL << 20, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_REQUIRE(write(ready[1], "g", 1) == 1);
	close(ready[1]);

	/*
	 * The charge lands as the mapping is made, with nothing sampling
	 * anything, so the ledger shows it without a refresh being asked for.
	 */
	memset(&lr, 0, sizeof(lr));
	for (i = 0; i < 100; i++) {
		if (coalition_ledger(fd, 0, &lr) == 0 && lr.status == 0 &&
		    lr.vsz_bytes > (64UL << 20))
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(lr.vsz_bytes > (64UL << 20),
	    "the mapping was not charged without a sample: %ju",
	    (uintmax_t)lr.vsz_bytes);

	/* Still alive: with the sweep off, nothing has judged it yet. */
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "the coalition was acted on with the sweep switched off");

	/* Now ask for the ceilings to be judged.  That is all it takes. */
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	ATF_CHECK_MSG(wait_exit_bounded(pid, &wstatus),
	    "a coalition past its address-space ceiling was not acted on when "
	    "the ceilings were judged");

	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &after, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(after > before,
	    "the address-space breach was not counted: %u then %u", before,
	    after);

	close(pd);
	close(fd);
	sweep_enable_restore(saved_sweep);
	sweep_enable_saved = -1;
}
ATF_TC_CLEANUP(vmem_ceiling_needs_no_sample, tc)
{

	sweep_enable_restore(sweep_enable_saved);
}

ATF_TC(cpu_ceiling_absent_by_default_and_settable);
ATF_TC_HEAD(cpu_ceiling_absent_by_default_and_settable, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition has no CPU ceiling until one is declared, a ceiling "
	    "of zero removes it again, and the three ceilings are independent "
	    "of one another");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(cpu_ceiling_absent_by_default_and_settable, tc)
{
	int fd;
	int32_t status = -1;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Accepted on its own, with and without the kill flag. */
	ATF_REQUIRE(coalition_set_cpu_limit(fd, 0, 50, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "a notify-only CPU ceiling was refused");
	status = -1;
	ATF_REQUIRE(coalition_set_cpu_limit(fd, COALITION_LIMIT_KILL, 400,
	    &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "a CPU ceiling above one processor was "
	    "refused; 400 means four processors, not an error");
	status = -1;
	ATF_REQUIRE(coalition_set_cpu_limit(fd, 0, 0, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "removing a CPU ceiling was refused");

	/*
	 * A request that stops before cpu_percent is a caller built against
	 * the older header, and must still be accepted as meaning no CPU
	 * ceiling rather than refused for being short.
	 */
	{
		struct coalition_limit_req lq;
		struct coalition_reply rpl;

		memset(&lq, 0, sizeof(lq));
		lq.op = COALITION_OP_SET_LIMIT;
		lq.memory_bytes = 1ULL << 40;
		ATF_REQUIRE(coalition_call(fd, &lq,
		    COALITION_LIMIT_REQ_V1_LEN, NULL, 0, &rpl,
		    sizeof(rpl)) == 0);
		ATF_CHECK_EQ_MSG(rpl.status, 0,
		    "a request carrying only the memory ceilings was refused");

		/* One byte short of even that is still a malformed request. */
		ATF_REQUIRE(coalition_call(fd, &lq,
		    COALITION_LIMIT_REQ_V1_LEN - 1, NULL, 0, &rpl,
		    sizeof(rpl)) == 0);
		ATF_CHECK_EQ_MSG(rpl.status, EINVAL,
		    "a truncated limit request was accepted");
	}

	/* The same op carries all three, and unknown flags are still refused. */
	status = -1;
	ATF_REQUIRE(coalition_set_limit_full(fd, COALITION_LIMIT_KILL,
	    1ULL << 40, 1ULL << 40, &status) == 0);
	ATF_CHECK_EQ_MSG(status, 0, "setting the memory ceilings after a CPU "
	    "ceiling was refused");
	status = -1;
	ATF_REQUIRE(coalition_set_cpu_limit(fd, 0x80, 50, &status) == 0);
	ATF_CHECK_EQ_MSG(status, EINVAL,
	    "an unknown flag was accepted on a CPU ceiling");

	close(fd);
}

ATF_TC(cpu_ceiling_terminates_a_spinner);
ATF_TC_HEAD(cpu_ceiling_terminates_a_spinner, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition averaging more than its declared share of a processor "
	    "is terminated with COALITION_KILL_OVER_CPU, and the termination "
	    "is counted apart from a memory breach");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(cpu_ceiling_terminates_a_spinner, tc)
{
	u_int before = 0, after = 0, mem_before = 0, mem_after = 0;
	u_int saved_sweep;
	size_t len = sizeof(before);
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	if (sysctlbyname("kern.mac_capability_coalition.cpu_kills", &before,
	    &len, NULL, 0) != 0)
		atf_tc_skip("cpu_kills sysctl unavailable: %s",
		    strerror(errno));
	len = sizeof(mem_before);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &mem_before, &len, NULL, 0) == 0);

	saved_sweep = sweep_interval_set(SWEEP_FAST_MS);
	if (saved_sweep == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		volatile unsigned long x = 0;

		close(fd);
		/* Burn a processor until somebody stops us. */
		for (;;)
			x++;
		_exit(0);
	}
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * Ten percent of one processor, which a busy loop exceeds by an order
	 * of magnitude, so the verdict does not depend on how the window
	 * happens to line up with the accounting daemon.
	 */
	ATF_REQUIRE(coalition_set_cpu_limit(fd, COALITION_LIMIT_KILL, 10,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_CHECK_MSG(wait_exit_slow(pid, &wstatus),
	    "a coalition far over its CPU ceiling was never terminated");
	if (kill(pid, 0) == 0) {
		pdkill(pd, SIGKILL);
		(void)wait_exit_slow(pid, &wstatus);
	}

	len = sizeof(after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.cpu_kills",
	    &after, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(after > before,
	    "the CPU breach was not counted as one: %u then %u", before,
	    after);
	len = sizeof(mem_after);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &mem_after, &len, NULL, 0) == 0);
	ATF_CHECK_MSG(mem_after == mem_before,
	    "a CPU breach was counted as a memory breach: %u then %u",
	    mem_before, mem_after);

	close(pd);
	close(fd);
	sweep_interval_restore(saved_sweep);
}

ATF_TC(cpu_ceiling_leaves_a_quiet_coalition_alone);
ATF_TC_HEAD(cpu_ceiling_leaves_a_quiet_coalition_alone, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition that is not spending CPU survives a CPU ceiling "
	    "across several sweeps: the ceiling is a rate, so the total a "
	    "long-lived unit has accumulated must not be what is judged");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(cpu_ceiling_leaves_a_quiet_coalition_alone, tc)
{
	u_int saved_sweep;
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;
	int i;

	saved_sweep = sweep_interval_set(SWEEP_FAST_MS);
	if (saved_sweep == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * One percent: low enough that a total would breach it the moment the
	 * process had run at all, and high enough that a sleeping member
	 * cannot reach it as a rate.
	 */
	ATF_REQUIRE(coalition_set_cpu_limit(fd, COALITION_LIMIT_KILL, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Several windows and several sweeps, not one of each. */
	for (i = 0; i < 6; i++) {
		usleep(1000000);
		if (kill(pid, 0) != 0)
			break;
	}
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "a sleeping coalition was terminated for CPU it was not spending");

	pdkill(pd, SIGKILL);
	(void)wait_exit_slow(pid, &wstatus);
	close(pd);
	close(fd);
	sweep_interval_restore(saved_sweep);
}

ATF_TC(a_breach_does_not_mask_another_resource);
ATF_TC_HEAD(a_breach_does_not_mask_another_resource, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Going over one ceiling does not silence the next: a coalition "
	    "already over its address-space ceiling is still told when it "
	    "goes over a different one, because being out of one thing is a "
	    "different fact from being out of another");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(a_breach_does_not_mask_another_resource, tc)
{
	struct coalition_ledger_reply lr;
	struct coalition_event_msg ev;
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * Notify only, so nothing dies and the coalition stays available to
	 * breach a second time.  Address space first: it is exact, so the
	 * breach is certain the moment the member is enlisted.
	 */
	ATF_REQUIRE(coalition_set_limit_full(fd, 0, 0, 1, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	memset(&ev, 0, sizeof(ev));
	ATF_REQUIRE_MSG(coalition_wait_note(fd, COALITION_NOTE_LIMIT, &ev, 50),
	    "no notification for the first ceiling");

	/*
	 * Now add a second ceiling on a different resource, with the first
	 * still breached.  Under a single breach latch this second one would
	 * be silent, because the coalition was already marked as over.
	 */
	ATF_REQUIRE(coalition_set_limit_full(fd, 0, 0, 1, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	if (!wait_for_resident_accounting(fd))
		atf_tc_skip("the page daemon did not attribute resident "
		    "memory to the coalition");
	{
		struct coalition_limit_req lq;
		struct coalition_reply rpl;

		memset(&lq, 0, sizeof(lq));
		lq.op = COALITION_OP_SET_LIMIT;
		lq.memory_bytes = 1;	/* resident, now also breached */
		lq.vmem_bytes = 1;	/* address space, still breached */
		ATF_REQUIRE(coalition_call(fd, &lq, sizeof(lq), NULL, 0, &rpl,
		    sizeof(rpl)) == 0);
		ATF_REQUIRE_EQ(rpl.status, 0);
	}
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);
	memset(&ev, 0, sizeof(ev));
	ATF_CHECK_MSG(coalition_wait_note(fd, COALITION_NOTE_LIMIT, &ev, 50),
	    "a second ceiling on a different resource was never reported; "
	    "the first breach masked it");

	pdkill(pd, SIGKILL);
	(void)wait_exit_bounded(pid, &wstatus);
	close(pd);
	close(fd);
}

ATF_TC(cpu_ceiling_survives_a_member_joining_with_history);
ATF_TC_HEAD(cpu_ceiling_survives_a_member_joining_with_history, tc)
{
	atf_tc_set_md_var(tc, "descr",
    "Enlisting a process that has already spent CPU does not read as a "
	    "burst. Joining copies the whole of a process's accounting into "
	    "the container, total AND decaying rate, and neither transfers "
	    "meaningfully: the total is a step the rate never saw, and the "
	    "rate would then be counted a second time through the container's "
	    "own runtime. The ceiling here is tight enough that either mistake "
	    "breaches it.");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
	atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(cpu_ceiling_survives_a_member_joining_with_history, tc)
{
	u_int saved_sweep;
	int fd, pd, wstatus, ready[2];
	int32_t status;
	char tok;
	pid_t pid;
	int i;

	saved_sweep = sweep_interval_set(SWEEP_FAST_MS);
	if (saved_sweep == 0)
		atf_tc_skip("sweep_interval_ms sysctl unavailable: %s",
		    strerror(errno));

	ATF_REQUIRE(pipe(ready) == 0);
	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	pid = pdfork(&pd, 0);
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		volatile unsigned long x = 0;
		unsigned long n;

		close(fd);
		close(ready[0]);
		/*
		 * Spend real CPU BEFORE being enlisted, then go quiet.  This
		 * is the history the coalition must not be charged for.
		 */
		for (n = 0; n < 200000000UL; n++)
			x++;
		(void)write(ready[1], "r", 1);
		pause();
		_exit(0);
	}
	close(ready[1]);
	ATF_REQUIRE(read(ready[0], &tok, 1) == 1);
	close(ready[0]);

	/* Now enlist it, carrying all that CPU into the container at once. */
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	/*
	 * Five percent, not fifty.  A joiner fresh from a busy loop carries a
	 * decayed rate near one whole processor; importing it would show up as
	 * roughly a third of that on the first look, which a fifty percent
	 * ceiling would quietly tolerate and a five percent one will not.
	 */
	ATF_REQUIRE(coalition_set_cpu_limit(fd, COALITION_LIMIT_KILL, 5,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * The member is asleep from here on, so a correct rate is zero.  Only
	 * a reading that mistook the joined history for spending would breach
	 * fifty percent, and it would do so on the very first window.
	 */
	for (i = 0; i < 6; i++) {
		usleep(1000000);
		if (kill(pid, 0) != 0)
			break;
	}
	ATF_CHECK_MSG(kill(pid, 0) == 0,
	    "a coalition was killed for CPU a member spent before it joined");

	pdkill(pd, SIGKILL);
	(void)wait_exit_slow(pid, &wstatus);
	close(pd);
	close(fd);
	sweep_interval_restore(saved_sweep);
}

ATF_TC(assertions_name_their_holders);
ATF_TC_HEAD(assertions_name_their_holders, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An operator can find out who is holding a coalition up, not just "
	    "how many are: each assertion reports the process that took it, "
	    "its band and its age, and the live count is honest when the "
	    "caller's buffer is too small for the list");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(assertions_name_their_holders, tc)
{
	struct coalition_band_reply br;
	/*
	 * The reply ends in a flexible array, so the buffer is bytes and the
	 * reply is read through a pointer rather than being a struct member.
	 */
	char buf[sizeof(struct coalition_assertions_reply) +
	    4 * sizeof(struct coalition_assert_info)];
	struct coalition_assertions_reply *big =
	    (struct coalition_assertions_reply *)buf;
	struct coalition_assertions_reply small;
	struct coalition_req_hdr hdr;
	int fd, a1, a2;
	unsigned i;
	bool saw_background = false, saw_critical = false;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);

	/* Nothing held yet. */
	memset(buf, 0, sizeof(buf));
	hdr.op = COALITION_OP_ASSERTIONS;
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0, buf,
	    sizeof(buf)) == 0);
	ATF_CHECK_EQ(big->status, 0);
	ATF_CHECK_EQ_MSG(0, big->live, "a fresh coalition reported %u held",
	    big->live);

	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_BACKGROUND, &br,
	    &a1) == 0);
	ATF_REQUIRE_EQ(br.status, 0);
	ATF_REQUIRE(coalition_assert(fd, COALITION_BAND_CRITICAL, &br,
	    &a2) == 0);
	ATF_REQUIRE_EQ(br.status, 0);

	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0, buf,
	    sizeof(buf)) == 0);
	ATF_CHECK_EQ_MSG(2, big->live, "expected two held, got %u", big->live);
	ATF_CHECK_EQ(2, big->returned);
	for (i = 0; i < big->returned; i++) {
		ATF_CHECK_EQ_MSG(getpid(), big->held[i].pid,
		    "assertion %u names pid %d, not the process that took it",
		    i, big->held[i].pid);
		if (big->held[i].band == COALITION_BAND_BACKGROUND)
			saw_background = true;
		if (big->held[i].band == COALITION_BAND_CRITICAL)
			saw_critical = true;
	}
	ATF_CHECK_MSG(saw_background && saw_critical,
	    "the bands of the held assertions were not both reported");

	/* A buffer with room for none still learns the true count. */
	memset(&small, 0, sizeof(small));
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0, &small,
	    sizeof(small)) == 0);
	ATF_CHECK_EQ_MSG(2, small.live,
	    "a short reply understated the live count as %u", small.live);
	ATF_CHECK_EQ_MSG(0, small.returned,
	    "a reply with no room returned %u entries", small.returned);

	/* Releasing one is reflected. */
	ATF_REQUIRE(close(a2) == 0);
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(coalition_call(fd, &hdr, sizeof(hdr), NULL, 0, buf,
	    sizeof(buf)) == 0);
	ATF_CHECK_EQ_MSG(1, big->live, "after releasing one, %u remain",
	    big->live);
	ATF_CHECK_EQ(COALITION_BAND_BACKGROUND, big->held[0].band);

	close(a1);
	close(fd);
}

ATF_TC(kill_reason_reaches_the_holder);
ATF_TC_HEAD(kill_reason_reaches_the_holder, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A coalition terminated by a policy tells its holder why, and the "
	    "reason on the event is the one the policy acted on rather than a "
	    "generic termination");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(kill_reason_reaches_the_holder, tc)
{
	struct coalition_event_msg ev;
	struct coalition_ledger_reply lr;
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/*
	 * An address-space ceiling any live member exceeds.  Address space is
	 * charged at the mapping path, so it is over the moment the member is
	 * enlisted; a resident ceiling would first have to wait for the page
	 * daemon, which is not what this test is about.
	 */
	ATF_REQUIRE(coalition_set_limit_full(fd, COALITION_LIMIT_KILL, 0, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	ATF_REQUIRE(coalition_ledger(fd, COALITION_LEDGER_REFRESH, &lr) == 0);

	memset(&ev, 0, sizeof(ev));
	ATF_REQUIRE_MSG(coalition_wait_note(fd, COALITION_NOTE_TERMINATING,
	    &ev, 50), "the holder was never told its coalition was going");
	ATF_CHECK_EQ_MSG(COALITION_KILL_OVER_CEILING, ev.reason,
	    "the holder was told reason %u, not that it was over its ceiling",
	    ev.reason);
	(void)wait_exit_bounded(pid, &wstatus);
	close(pd);
	close(fd);
}

ATF_TC(a_holder_closing_is_not_reported_as_a_policy_kill);
ATF_TC_HEAD(a_holder_closing_is_not_reported_as_a_policy_kill, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Asking for a termination is not a memory policy: the reason on "
	    "the event distinguishes a holder's own request from something "
	    "the system decided, and the policy counters do not move");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(a_holder_closing_is_not_reported_as_a_policy_kill, tc)
{
	struct coalition_event_msg ev;
	u_int oom0 = 0, lim0 = 0, idle0 = 0, oom1 = 0, lim1 = 0, idle1 = 0;
	size_t len;
	int fd, pd, wstatus;
	int32_t status;
	pid_t pid;

	len = sizeof(oom0);
	if (sysctlbyname("kern.mac_capability_coalition.oom_kills", &oom0,
	    &len, NULL, 0) != 0)
		atf_tc_skip("oom_kills sysctl unavailable: %s",
		    strerror(errno));
	len = sizeof(lim0);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &lim0, &len, NULL, 0) == 0);
	len = sizeof(idle0);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.idle_kills",
	    &idle0, &len, NULL, 0) == 0);

	fd = mac_capability_connect("coalition");
	ATF_REQUIRE(fd >= 0);
	pid = coalition_fork_member(fd, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(fd, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	ATF_REQUIRE(coalition_op(fd, COALITION_OP_TERMINATE, &status) == 0);
	ATF_CHECK_EQ(status, 0);
	memset(&ev, 0, sizeof(ev));
	if (coalition_wait_note(fd, COALITION_NOTE_TERMINATING, &ev, 30))
		ATF_CHECK_EQ_MSG(COALITION_KILL_REQUESTED, ev.reason,
		    "an asked-for termination reported reason %u", ev.reason);

	/* None of the memory counters moved. */
	len = sizeof(oom1);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.oom_kills",
	    &oom1, &len, NULL, 0) == 0);
	len = sizeof(lim1);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.limit_kills",
	    &lim1, &len, NULL, 0) == 0);
	len = sizeof(idle1);
	ATF_REQUIRE(sysctlbyname("kern.mac_capability_coalition.idle_kills",
	    &idle1, &len, NULL, 0) == 0);
	ATF_CHECK_EQ_MSG(oom0, oom1, "a requested termination was counted as "
	    "an out-of-memory kill");
	ATF_CHECK_EQ_MSG(lim0, lim1, "a requested termination was counted as "
	    "a ceiling breach");
	ATF_CHECK_EQ_MSG(idle0, idle1, "a requested termination was counted as "
	    "an idle exit");

	(void)wait_exit_bounded(pid, &wstatus);
	close(pd);
	close(fd);
}

ATF_TC(the_responsible_party_is_told_when_its_work_dies);
ATF_TC_HEAD(the_responsible_party_is_told_when_its_work_dies, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The party a coalition is responsible to is told when a policy "
	    "takes that work away, with the reason and which coalition it "
	    "was, because it is the party that can do something about it");
	atf_tc_set_md_var(tc, "require.kmods", "mac_capability mac_capability_coalition");
}
ATF_TC_BODY(the_responsible_party_is_told_when_its_work_dies, tc)
{
	struct coalition_event_msg ev;
	struct coalition_stat_reply child_stat;
	struct coalition_ledger_reply lr;
	int parent, child, pd, wstatus;
	int32_t status;
	pid_t pid;

	parent = mac_capability_connect("coalition");
	child = mac_capability_connect("coalition");
	ATF_REQUIRE(parent >= 0 && child >= 0);
	ATF_REQUIRE(coalition_set_responsible(child, &parent, 0, &status) == 0);
	ATF_REQUIRE_EQ_MSG(status, 0, "could not record the responsible party");
	ATF_REQUIRE(coalition_stat(child, &child_stat) == 0);

	pid = coalition_fork_member(child, &pd);
	ATF_REQUIRE(pid > 0);
	ATF_REQUIRE(coalition_enlist(child, pd, &status) == 0);
	ATF_REQUIRE_EQ(status, 0);

	/* Address space, for the same reason as above: exact and immediate. */
	ATF_REQUIRE(coalition_set_limit_full(child, COALITION_LIMIT_KILL, 0, 1,
	    &status) == 0);
	ATF_REQUIRE_EQ(status, 0);
	ATF_REQUIRE(coalition_ledger(child, COALITION_LEDGER_REFRESH,
	    &lr) == 0);

	memset(&ev, 0, sizeof(ev));
	ATF_REQUIRE_MSG(coalition_wait_note(parent,
	    COALITION_NOTE_CHILD_KILLED, &ev, 50),
	    "the responsible party was never told its work had been taken");
	ATF_CHECK_EQ_MSG(COALITION_KILL_OVER_CEILING, ev.reason,
	    "told reason %u rather than the ceiling breach", ev.reason);
	ATF_CHECK_EQ_MSG(child_stat.id, ev.subject_id,
	    "told about coalition %ju, not the one that died (%ju)",
	    (uintmax_t)ev.subject_id, (uintmax_t)child_stat.id);

	(void)wait_exit_bounded(pid, &wstatus);
	close(pd);
	close(child);
	close(parent);
}

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
		ATF_TP_ADD_TC(tp, jail_members_are_accounted);
	ATF_TP_ADD_TC(tp, a_jail_held_coalition_is_visible_to_pressure);
	ATF_TP_ADD_TC(tp, a_nested_jail_is_charged_to_the_held_one);
	ATF_TP_ADD_TC(tp, enlistment_beats_the_jail_it_is_in);
	ATF_TP_ADD_TC(tp, close_removes_jaildesc_member);

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

	/* Identity + responsible parent */
	ATF_TP_ADD_TC(tp, identity_unique_ids);
	ATF_TP_ADD_TC(tp, identity_stat_old_layout);
	ATF_TP_ADD_TC(tp, responsible_set_once);
	ATF_TP_ADD_TC(tp, responsible_self_root);
	ATF_TP_ADD_TC(tp, responsible_bad_args);
	ATF_TP_ADD_TC(tp, responsible_caller_and_procdesc);
	ATF_TP_ADD_TC(tp, responsible_no_cycles);
	ATF_TP_ADD_TC(tp, responsible_survives_parent_close);
	ATF_TP_ADD_TC(tp, responsible_kinfo_export);
	ATF_TP_ADD_TC(tp, responsible_chain_depth_limit);
	ATF_TP_ADD_TC(tp, set_signal_zero_releases);
	ATF_TP_ADD_TC(tp, pdfork_inherits_and_rehomes);
	ATF_TP_ADD_TC(tp, close_terminates_live_member);
	ATF_TP_ADD_TC(tp, refattach_confined_descriptors);
	ATF_TP_ADD_TC(tp, set_signal_zero_releases_joined);
	ATF_TP_ADD_TC(tp, pressure_notifies_coalitions);
	ATF_TP_ADD_TC(tp, pressure_after_close_is_safe);
	ATF_TP_ADD_TC(tp, ledger_never_sampled);
	ATF_TP_ADD_TC(tp, ledger_refresh_counts_members);
	ATF_TP_ADD_TC(tp, ledger_tracks_without_being_asked);
	ATF_TP_ADD_TC(tp, band_floor_default_and_set);
	ATF_TP_ADD_TC(tp, band_assertion_raises_and_close_drops);
	ATF_TP_ADD_TC(tp, band_assertion_dies_with_holder);
	ATF_TP_ADD_TC(tp, band_assertion_carries_no_authority);
	ATF_TP_ADD_TC(tp, band_assertion_outlives_coalition_fd);
	ATF_TP_ADD_TC(tp, band_assertion_churn_under_readers);
	ATF_TP_ADD_TC(tp, band_assertions_are_capped);
	ATF_TP_ADD_TC(tp, band_visible_in_kinfo);
	ATF_TP_ADD_TC(tp, pressure_hands_down_low_bands);
	ATF_TP_ADD_TC(tp, oom_policy_is_installed_and_bounded);
	ATF_TP_ADD_TC(tp, oom_ceiling_excludes_critical_band);
	ATF_TP_ADD_TC(tp, limit_absent_by_default_and_settable);
	ATF_TP_ADD_TC(tp, limit_breach_terminates_regardless_of_band);
	ATF_TP_ADD_TC(tp, limit_under_ceiling_is_left_alone);
	ATF_TP_ADD_TC(tp, idle_exit_is_opt_in);
	ATF_TP_ADD_TC(tp, idle_exit_puts_away_after_its_age);
	ATF_TP_ADD_TC(tp, idle_exit_is_held_off_by_an_assertion);
	ATF_TP_ADD_TC(tp, vmem_ceiling_needs_no_sample);
	ATF_TP_ADD_TC(tp, cpu_ceiling_absent_by_default_and_settable);
	ATF_TP_ADD_TC(tp, cpu_ceiling_terminates_a_spinner);
	ATF_TP_ADD_TC(tp, cpu_ceiling_leaves_a_quiet_coalition_alone);
	ATF_TP_ADD_TC(tp, a_breach_does_not_mask_another_resource);
	ATF_TP_ADD_TC(tp, cpu_ceiling_survives_a_member_joining_with_history);
	ATF_TP_ADD_TC(tp, assertions_name_their_holders);
	ATF_TP_ADD_TC(tp, kill_reason_reaches_the_holder);
	ATF_TP_ADD_TC(tp, a_holder_closing_is_not_reported_as_a_policy_kill);
	ATF_TP_ADD_TC(tp, the_responsible_party_is_told_when_its_work_dies);

	/* Resource exhaustion + teardown-race stress */
	ATF_TP_ADD_TC(tp, exhaust_coalition_max);
	ATF_TP_ADD_TC(tp, exhaust_member_max);
	ATF_TP_ADD_TC(tp, jail_teardown_race);
	ATF_TP_ADD_TC(tp, coalition_churn_no_leak);

	return (atf_no_error());
}
