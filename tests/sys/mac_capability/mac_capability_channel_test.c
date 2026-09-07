/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Tests for the ungated SYF_CAPENABLED channel-pair-create syscall
 * (mac_capability_channel_create), registered dynamically by the
 * mac_capability_channel module.
 *
 * These build unconditionally but only RUN under a harness where the
 * capability plane is inactive (CAPLANE_OFF) and the mac_capability +
 * mac_capability_channel + mac_capability_identity modules are loaded.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_test_helpers.h"
#include "mac_capability_identity_proto.h"
#include "mac_capability_channel_proto.h"

/* Descriptor transfer states (mirror of sys/capsicum.h enum). */
#ifndef CAP_XFER_UNLIMITED
#define	CAP_XFER_UNLIMITED	0
#define	CAP_XFER_ONCE		1
#define	CAP_XFER_NONE		2
#endif

/* Resolve the dynamic syscall number, or -1 if the module is not loaded. */
static int
chan_sysno(void)
{
	struct module_stat ms;
	int modid;

	modid = modfind("sys/mac_capability_channel_create");
	if (modid < 0)
		return (-1);
	ms.version = sizeof(ms);
	if (modstat(modid, &ms) != 0)
		return (-1);
	return (ms.data.intval);
}

static int
chan_create(int fds[2])
{
	int no;

	no = chan_sysno();
	if (no < 0) {
		errno = ENOSYS;
		return (-1);
	}
	return (syscall(no, fds));
}

/* Skip the test if the syscall/module isn't present. */
static int
chan_create_or_skip(int fds[2])
{
	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");
	return (chan_create(fds));
}

static int
chan_send(int fd, const void *buf, size_t len)
{
	struct mac_capability_sendmsg_args sa;

	memset(&sa, 0, sizeof(sa));
	sa.payload = buf;
	sa.payload_len = len;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG, &sa));
}

static int
chan_recv(int fd, void *buf, size_t len, uint32_t *outlen,
    struct mac_capability_cred_trailer *tr)
{
	struct mac_capability_recvmsg_args ra;
	int r;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = len;
	r = ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra);
	if (r == 0) {
		if (outlen != NULL)
			*outlen = ra.payload_len;
		if (tr != NULL)
			*tr = ra.trailer;
	}
	return (r);
}

/* Authoritative caller nonce via the identity service. */
static uint64_t
self_nonce(void)
{
	struct identity_request req;
	struct identity_reply reply;
	struct mac_capability_call_args ca;
	int fd;

	fd = mac_capability_connect("identity");
	ATF_REQUIRE_MSG(fd >= 0, "connect identity: %s", strerror(errno));
	memset(&req, 0, sizeof(req));
	req.op = IDENTITY_OP_SELF;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply = &reply;
	ca.reply_len = sizeof(reply);
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0);
	ATF_REQUIRE_EQ(reply.status, IDENTITY_STATUS_OK);
	close(fd);
	return (reply.nonce);
}

/* Nonblocking recv: returns 0, or -1 with errno (EAGAIN when empty). */
static int
chan_recv_nb(int fd, void *buf, size_t len, uint32_t *outlen,
    struct mac_capability_cred_trailer *tr)
{
	int fl, r;

	fl = fcntl(fd, F_GETFL);
	ATF_REQUIRE(fl >= 0);
	ATF_REQUIRE(fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0);
	r = chan_recv(fd, buf, len, outlen, tr);
	(void)fcntl(fd, F_SETFL, fl);
	return (r);
}

/* Lowest-free descriptor number — a leak pushes this up. */
static int
lowest_free_fd(void)
{
	int fd;

	fd = fcntl(0, F_DUPFD, 0);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	return (fd);
}

/* ----------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------- */

ATF_TC(create_pair);
ATF_TC_HEAD(create_pair, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Syscall returns two distinct, usable channel fds");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(create_pair, tc)
{
	int fds[2] = { -1, -1 };

	ATF_REQUIRE_MSG(chan_create_or_skip(fds) == 0,
	    "create: %s", strerror(errno));
	ATF_CHECK(fds[0] >= 0);
	ATF_CHECK(fds[1] >= 0);
	ATF_CHECK(fds[0] != fds[1]);

	close(fds[0]);
	close(fds[1]);
}

ATF_TC(bidirectional);
ATF_TC_HEAD(bidirectional, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Messages flow both A->B and B->A");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(bidirectional, tc)
{
	int fds[2];
	char rxbuf[64];
	uint32_t rxlen;
	static const char a2b[] = "ping-a-to-b";
	static const char b2a[] = "pong-b-to-a";

	ATF_REQUIRE(chan_create_or_skip(fds) == 0);

	/* A -> B */
	ATF_REQUIRE_MSG(chan_send(fds[0], a2b, sizeof(a2b)) == 0,
	    "send A->B: %s", strerror(errno));
	memset(rxbuf, 0, sizeof(rxbuf));
	rxlen = 0;
	ATF_REQUIRE_MSG(chan_recv(fds[1], rxbuf, sizeof(rxbuf), &rxlen, NULL) == 0,
	    "recv on B: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(a2b), rxlen);
	ATF_CHECK(memcmp(rxbuf, a2b, sizeof(a2b)) == 0);

	/* B -> A */
	ATF_REQUIRE_MSG(chan_send(fds[1], b2a, sizeof(b2a)) == 0,
	    "send B->A: %s", strerror(errno));
	memset(rxbuf, 0, sizeof(rxbuf));
	rxlen = 0;
	ATF_REQUIRE_MSG(chan_recv(fds[0], rxbuf, sizeof(rxbuf), &rxlen, NULL) == 0,
	    "recv on A: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(b2a), rxlen);
	ATF_CHECK(memcmp(rxbuf, b2a, sizeof(b2a)) == 0);

	close(fds[0]);
	close(fds[1]);
}

ATF_TC(carries_nonce);
ATF_TC_HEAD(carries_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A message received on the pair carries the caller's cred nonce");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel mac_capability_identity");
}
ATF_TC_BODY(carries_nonce, tc)
{
	struct mac_capability_cred_trailer tr;
	uint64_t mine;
	int fds[2];
	char rxbuf[32];
	static const char msg[] = "nonce-check";

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	mine = self_nonce();
	ATF_REQUIRE(mine != 0);

	ATF_REQUIRE(chan_create(fds) == 0);

	/* A -> B: B sees the sender's (our) nonce. */
	ATF_REQUIRE(chan_send(fds[0], msg, sizeof(msg)) == 0);
	memset(&tr, 0, sizeof(tr));
	ATF_REQUIRE(chan_recv(fds[1], rxbuf, sizeof(rxbuf), NULL, &tr) == 0);
	ATF_CHECK_EQ(mine, tr.nonce);

	/* B -> A: same nonce (same process holds both ends). */
	ATF_REQUIRE(chan_send(fds[1], msg, sizeof(msg)) == 0);
	memset(&tr, 0, sizeof(tr));
	ATF_REQUIRE(chan_recv(fds[0], rxbuf, sizeof(rxbuf), NULL, &tr) == 0);
	ATF_CHECK_EQ(mine, tr.nonce);

	close(fds[0]);
	close(fds[1]);
}

ATF_TC(child_exec_fresh_nonce);
ATF_TC_HEAD(child_exec_fresh_nonce, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A fork+exec'd child (fresh nonce) can create and use a pair");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel mac_capability_identity");
	atf_tc_set_md_var(tc, "require.progs", "mac_capability_channel_helper");
}
ATF_TC_BODY(child_exec_fresh_nonce, tc)
{
	char helper[PATH_MAX];
	int status;
	pid_t pid;

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	snprintf(helper, sizeof(helper), "%s/mac_capability_channel_helper",
	    atf_tc_get_config_var(tc, "srcdir"));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(helper, helper, "pair", (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "helper exited with status 0x%x", status);
}

ATF_TC(create_in_capmode);
ATF_TC_HEAD(create_in_capmode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The create syscall succeeds after cap_enter()");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(create_in_capmode, tc)
{
	int fds[2];
	int no, status;
	pid_t pid;

	no = chan_sysno();
	if (no < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Resolve happened above (pre-capmode); now sandbox. */
		if (cap_enter() != 0 && errno != ENOSYS)
			_exit(10);
		if (syscall(no, fds) != 0)
			_exit(11);
		if (fds[0] < 0 || fds[1] < 0)
			_exit(12);
		/* Prove the pair works inside the sandbox. */
		if (chan_send(fds[0], "x", 1) != 0)
			_exit(13);
		char b[4];
		if (chan_recv(fds[1], b, sizeof(b), NULL, NULL) != 0)
			_exit(14);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "capmode child exited with status 0x%x", status);
}

ATF_TC(create_efault);
ATF_TC_HEAD(create_efault, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A bad fds pointer fails with EFAULT and installs nothing");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(create_efault, tc)
{
	int no;

	no = chan_sysno();
	if (no < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	ATF_CHECK_ERRNO(EFAULT, syscall(no, (int *)(uintptr_t)0x1) == -1);
	ATF_CHECK_ERRNO(EFAULT, syscall(no, (int *)NULL) == -1);
}

/*
 * ADVERSARIAL — the keystone.  A created endpoint is the socketpair(2)
 * equivalent: it can ONLY forward to its peer.  It must not be usable to
 * reach a service, mint a service capability, obtain a gate/reply token, or
 * invoke a synchronous service call.  We attempt exactly those operations
 * and prove they yield nothing beyond peer messaging.
 */
ATF_TC(endpoint_grants_no_authority);
ATF_TC_HEAD(endpoint_grants_no_authority, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A pair endpoint grants no authority: forward-to-peer only, "
	    "no service reply, no minted capability, no CALL path");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(endpoint_grants_no_authority, tc)
{
	struct mac_capability_info_args info;
	struct mac_capability_call_args ca;
	int fds[2];
	uint32_t op, rxlen;
	int rfds[MAC_CAPABILITY_MAX_FDS];
	uint32_t rxop, replybuf;
	struct mac_capability_recvmsg_args ra;

	ATF_REQUIRE(chan_create_or_skip(fds) == 0);

	/*
	 * GETINFO must show this is the plain "channel" service with NO
	 * synchronous-call feature — it is not some authoritative service.
	 */
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE_MSG(ioctl(fds[0], MAC_CAPABILITY_GETINFO, &info) == 0,
	    "GETINFO: %s", strerror(errno));
	ATF_CHECK_STREQ("channel", info.name);
	ATF_CHECK((info.features & MAC_CAPABILITY_INFO_F_CALL) == 0);

	/*
	 * Send a *service* op (CHANNEL_OP_CREATE) on the endpoint.  On a real
	 * service connection this mints a peer capability and replies.  On a
	 * self-owned pair the endpoint is already linked, so this is just an
	 * opaque payload forwarded to the peer — NOT interpreted as a service
	 * request.
	 */
	op = CHANNEL_OP_CREATE;
	ATF_REQUIRE_MSG(chan_send(fds[0], &op, sizeof(op)) == 0,
	    "send op: %s", strerror(errno));

	/* The peer receives the raw bytes with NO attached fd/capability. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = &rxop;
	ra.payload_len = sizeof(rxop);
	ra.fds = rfds;
	ra.nfds = MAC_CAPABILITY_MAX_FDS;
	ATF_REQUIRE_MSG(ioctl(fds[1], MAC_CAPABILITY_RECVMSG, &ra) == 0,
	    "recv on peer: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(op), ra.payload_len);
	ATF_CHECK_EQ(CHANNEL_OP_CREATE, rxop);
	ATF_CHECK_EQ(0, ra.nfds);	/* no minted peer capability delivered */

	/*
	 * The SENDER got NO service reply: a self-owned pair never
	 * synthesizes one.  Nonblocking recv on the sending endpoint returns
	 * EAGAIN (empty), proving no gate token / reply capability came back.
	 */
	replybuf = 0;
	rxlen = 0;
	ATF_CHECK_ERRNO(EAGAIN,
	    chan_recv_nb(fds[0], &replybuf, sizeof(replybuf), &rxlen, NULL) == -1);

	/*
	 * The channel service registers no co_call, so the synchronous CALL
	 * path — the classic way to obtain a service reply capability — is
	 * unavailable on an endpoint.
	 */
	op = CHANNEL_OP_CREATE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &op;
	ca.req_len = sizeof(op);
	ca.reply = &replybuf;
	ca.reply_len = sizeof(replybuf);
	ATF_CHECK_ERRNO(EOPNOTSUPP,
	    ioctl(fds[0], MAC_CAPABILITY_CALL, &ca) == -1);

	close(fds[0]);
	close(fds[1]);
}

ATF_TC(create_null_ptr);
ATF_TC_HEAD(create_null_ptr, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A NULL fds pointer fails cleanly (EFAULT/EINVAL), no crash");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(create_null_ptr, tc)
{
	int no, r;

	no = chan_sysno();
	if (no < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	r = syscall(no, (int *)NULL);
	ATF_CHECK_MSG(r == -1, "NULL fds unexpectedly succeeded");
	ATF_CHECK_MSG(errno == EFAULT || errno == EINVAL,
	    "NULL fds errno = %d (%s), expected EFAULT/EINVAL", errno,
	    strerror(errno));
}

/*
 * Drive the process out of descriptors and confirm the create syscall fails
 * cleanly with EMFILE/ENFILE (no panic).  Then free descriptors and create
 * again — proving the finstall-fail path (second finstall fails, kernel
 * closes the first) leaks no descriptor or endpoint.
 */
ATF_TC(fd_exhaustion);
ATF_TC_HEAD(fd_exhaustion, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Descriptor exhaustion fails cleanly and leaves no fd/endpoint leak");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fd_exhaustion, tc)
{
	struct rlimit saved, rl;
	int store[1024];
	int fds[2];
	int no, n, r, i;

	no = chan_sysno();
	if (no < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &saved) == 0);
	rl = saved;
	/*
	 * Cap just above the current descriptor count (approximated by the
	 * lowest free fd) so a bounded number of pairs exhausts the limit
	 * regardless of how many descriptors the harness already holds.
	 */
	rl.rlim_cur = lowest_free_fd() + 24;
	ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &rl) == 0);

	n = 0;
	for (;;) {
		r = chan_create(fds);
		if (r != 0)
			break;
		ATF_REQUIRE(n + 2 <= (int)nitems(store));
		store[n++] = fds[0];
		store[n++] = fds[1];
	}

	/* It must FAIL (not hang/panic) and do so with a descriptor error. */
	ATF_CHECK_MSG(errno == EMFILE || errno == ENFILE,
	    "exhaustion errno = %d (%s), expected EMFILE/ENFILE", errno,
	    strerror(errno));
	ATF_REQUIRE_MSG(n >= 2, "no pairs created before exhaustion");

	/* Free four descriptors, then a fresh create must succeed again. */
	for (i = 0; i < 4 && n > 0; i++)
		close(store[--n]);
	ATF_CHECK_MSG(chan_create(fds) == 0,
	    "create after freeing fds failed: %s — descriptor/endpoint leak?",
	    strerror(errno));
	close(fds[0]);
	close(fds[1]);

	while (n > 0)
		close(store[--n]);
	ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &saved) == 0);
}

/*
 * Create and close many pairs; the lowest-free descriptor number must return
 * to baseline, proving no descriptor is leaked across create/close cycles.
 */
ATF_TC(many_pairs_no_leak);
ATF_TC_HEAD(many_pairs_no_leak, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Creating and closing many pairs leaks no descriptors");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(many_pairs_no_leak, tc)
{
	int fds[2];
	int base, after, i;

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	base = lowest_free_fd();
	for (i = 0; i < 1000; i++) {
		ATF_REQUIRE_MSG(chan_create(fds) == 0,
		    "create at iter %d: %s", i, strerror(errno));
		ATF_REQUIRE(close(fds[0]) == 0);
		ATF_REQUIRE(close(fds[1]) == 0);
	}
	after = lowest_free_fd();
	ATF_CHECK_EQ_MSG(base, after,
	    "lowest-free fd moved %d -> %d: descriptor leak", base, after);
}

/*
 * Closing one endpoint revokes the other regardless of close order.  Verify
 * both orders (a-then-b, b-then-a): after the peer closes, the survivor's
 * SENDMSG fails EPIPE and RECVMSG fails ECONNRESET — deterministic peer-death
 * signalling, no hang.
 */
ATF_TC(close_orders);
ATF_TC_HEAD(close_orders, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Peer-death is signalled to the survivor for both close orders");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(close_orders, tc)
{
	int fds[2];
	char rx[32];
	uint32_t rxlen;
	static const char msg[] = "queued";

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	/* Subcase 1: close A first; B is the survivor. */
	ATF_REQUIRE(chan_create(fds) == 0);
	/* Deliver and drain a message first (avoid the async-forward race). */
	ATF_REQUIRE(chan_send(fds[0], msg, sizeof(msg)) == 0);
	rxlen = 0;
	ATF_REQUIRE(chan_recv(fds[1], rx, sizeof(rx), &rxlen, NULL) == 0);
	ATF_CHECK_EQ(sizeof(msg), rxlen);

	ATF_REQUIRE(close(fds[0]) == 0);
	/* Survivor B: send -> EPIPE, recv (empty) -> ECONNRESET. */
	ATF_CHECK_ERRNO(EPIPE, chan_send(fds[1], msg, sizeof(msg)) == -1);
	ATF_CHECK_ERRNO(ECONNRESET,
	    chan_recv(fds[1], rx, sizeof(rx), NULL, NULL) == -1);
	ATF_REQUIRE(close(fds[1]) == 0);

	/* Subcase 2: close B first; A is the survivor. */
	ATF_REQUIRE(chan_create(fds) == 0);
	ATF_REQUIRE(chan_send(fds[1], msg, sizeof(msg)) == 0);
	rxlen = 0;
	ATF_REQUIRE(chan_recv(fds[0], rx, sizeof(rx), &rxlen, NULL) == 0);
	ATF_CHECK_EQ(sizeof(msg), rxlen);

	ATF_REQUIRE(close(fds[1]) == 0);
	ATF_CHECK_ERRNO(EPIPE, chan_send(fds[0], msg, sizeof(msg)) == -1);
	ATF_CHECK_ERRNO(ECONNRESET,
	    chan_recv(fds[0], rx, sizeof(rx), NULL, NULL) == -1);
	ATF_REQUIRE(close(fds[0]) == 0);
}

/*
 * Peer death: closing one end revokes the other.  Send on the survivor ->
 * EPIPE; recv on the survivor -> ECONNRESET.  All graceful, no hang.
 */
ATF_TC(peer_death);
ATF_TC_HEAD(peer_death, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "After a peer closes, the survivor sees EPIPE on send and "
	    "ECONNRESET on recv");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(peer_death, tc)
{
	int fds[2];
	char rx[16];

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	ATF_REQUIRE(chan_create(fds) == 0);
	ATF_REQUIRE(close(fds[0]) == 0);	/* kill the peer */

	/* Send on the survivor: peer is gone (SF_REVOKED => SF_DEAD mask). */
	ATF_CHECK_ERRNO(EPIPE, chan_send(fds[1], "x", 1) == -1);
	/* Recv on the survivor with an empty queue: ECONNRESET. */
	ATF_CHECK_ERRNO(ECONNRESET,
	    chan_recv(fds[1], rx, sizeof(rx), NULL, NULL) == -1);

	ATF_REQUIRE(close(fds[1]) == 0);
}

/*
 * fork(2) shares the underlying struct file (refcount bumped).  The child
 * uses the inherited endpoints, then exits; the parent must still be able to
 * use the surviving endpoints — proving the refcount is neither prematurely
 * dropped (no use-after-free / spurious revoke) nor leaked.
 */
ATF_TC(fork_inherit_refcount);
ATF_TC_HEAD(fork_inherit_refcount, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Endpoints survive across fork; parent still works after child exits");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fork_inherit_refcount, tc)
{
	int fds[2];
	char rx[32];
	uint32_t rxlen;
	int status;
	pid_t pid;
	static const char fromchild[] = "hello-from-child";
	static const char afterchild[] = "parent-still-alive";

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	ATF_REQUIRE(chan_create(fds) == 0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		/* Child shares both endpoints; send A->B, then exit. */
		if (chan_send(fds[0], fromchild, sizeof(fromchild)) != 0)
			_exit(1);
		_exit(0);
	}

	/* Parent receives the child's message on the inherited endpoint. */
	rxlen = 0;
	ATF_REQUIRE_MSG(chan_recv(fds[1], rx, sizeof(rx), &rxlen, NULL) == 0,
	    "parent recv from child: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(fromchild), rxlen);
	ATF_CHECK(memcmp(rx, fromchild, sizeof(fromchild)) == 0);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child exited 0x%x", status);

	/*
	 * The child's fd copies are gone, but the parent's references keep the
	 * endpoints alive.  A fresh roundtrip must still work.
	 */
	ATF_REQUIRE_MSG(chan_send(fds[0], afterchild, sizeof(afterchild)) == 0,
	    "parent send after child exit: %s", strerror(errno));
	rxlen = 0;
	ATF_REQUIRE_MSG(chan_recv(fds[1], rx, sizeof(rx), &rxlen, NULL) == 0,
	    "parent recv after child exit: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(afterchild), rxlen);
	ATF_CHECK(memcmp(rx, afterchild, sizeof(afterchild)) == 0);

	close(fds[0]);
	close(fds[1]);
}

/*
 * Endpoints are first-class capabilities: one endpoint of pair Q can be sent
 * as an attached fd over pair P, received on P's peer, and then used to
 * message Q's partner.  Proves the socketpair primitive composes.
 */
ATF_TC(fd_passing);
ATF_TC_HEAD(fd_passing, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A channel endpoint can be passed as a capability inside a message");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fd_passing, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	int P[2], Q[2];
	int rfds[MAC_CAPABILITY_MAX_FDS];
	char rx[32];
	uint32_t rxlen;
	int received;
	static const char note[] = "carrier";
	static const char thru[] = "through-passed-endpoint";

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	ATF_REQUIRE(chan_create(P) == 0);
	ATF_REQUIRE(chan_create(Q) == 0);

	/* Q[0] must be marked transferable to be attachable. */
	ATF_REQUIRE_MSG(cap_xfer_limit(Q[0], CAP_XFER_ONCE) == 0,
	    "cap_xfer_limit: %s", strerror(errno));

	/* Send Q[0] as an attached fd over P (P[0] -> P[1]). */
	memset(&sa, 0, sizeof(sa));
	sa.payload = note;
	sa.payload_len = sizeof(note);
	sa.fds = &Q[0];
	sa.nfds = 1;
	ATF_REQUIRE_MSG(ioctl(P[0], MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "send with attached endpoint: %s", strerror(errno));

	/* Receive it on P's peer. */
	memset(&ra, 0, sizeof(ra));
	ra.payload = rx;
	ra.payload_len = sizeof(rx);
	ra.fds = rfds;
	ra.nfds = MAC_CAPABILITY_MAX_FDS;
	ATF_REQUIRE_MSG(ioctl(P[1], MAC_CAPABILITY_RECVMSG, &ra) == 0,
	    "recv attached endpoint: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(1, ra.nfds, "expected exactly one passed fd");
	received = rfds[0];
	ATF_REQUIRE(received >= 0);

	/*
	 * The received endpoint is Q[0]'s identity: messaging it reaches Q[1],
	 * Q[0]'s original partner.
	 */
	ATF_REQUIRE_MSG(chan_send(received, thru, sizeof(thru)) == 0,
	    "send on received endpoint: %s", strerror(errno));
	rxlen = 0;
	ATF_REQUIRE_MSG(chan_recv(Q[1], rx, sizeof(rx), &rxlen, NULL) == 0,
	    "recv on Q partner: %s", strerror(errno));
	ATF_CHECK_EQ(sizeof(thru), rxlen);
	ATF_CHECK(memcmp(rx, thru, sizeof(thru)) == 0);

	close(received);
	close(P[0]);
	close(P[1]);
	/* The send duplicated the endpoint reference; the original fd remains. */
	close(Q[0]);
	close(Q[1]);
}

/*
 * Full capability-mode use: a fork+exec'd child (fresh nonce) enters cap
 * mode, then creates AND exercises a pair bidirectionally — all inside the
 * sandbox.  Helper-backed because it needs a fresh exec'd process.
 */
ATF_TC(capmode_full_roundtrip);
ATF_TC_HEAD(capmode_full_roundtrip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Create plus bidirectional send/recv all succeed after cap_enter()");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel mac_capability_identity");
	atf_tc_set_md_var(tc, "require.progs", "mac_capability_channel_helper");
}
ATF_TC_BODY(capmode_full_roundtrip, tc)
{
	char helper[PATH_MAX];
	int status;
	pid_t pid;

	if (chan_sysno() < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	snprintf(helper, sizeof(helper), "%s/mac_capability_channel_helper",
	    atf_tc_get_config_var(tc, "srcdir"));

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		execl(helper, helper, "capmode_roundtrip", (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "capmode roundtrip helper exited with status 0x%x", status);
}

/*
 * Stress the global atomic badge allocator and the create/close paths under
 * true concurrency: several children each create+close many pairs at once.
 * No corruption or panic — every child exits 0.
 */
ATF_TC(concurrent_creates);
ATF_TC_HEAD(concurrent_creates, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Concurrent create/close from many processes: no corruption/panic");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(concurrent_creates, tc)
{
	const int nchild = 8;
	const int per_child = 400;
	pid_t pids[8];
	int no, i, j, status;

	no = chan_sysno();
	if (no < 0)
		atf_tc_skip("mac_capability_channel module not loaded");

	for (i = 0; i < nchild; i++) {
		pids[i] = fork();
		ATF_REQUIRE(pids[i] >= 0);
		if (pids[i] == 0) {
			for (j = 0; j < per_child; j++) {
				int fds[2];

				if (syscall(no, fds) != 0)
					_exit(1);
				if (fds[0] < 0 || fds[1] < 0 ||
				    fds[0] == fds[1])
					_exit(2);
				/* Exercise the pair once, then tear down. */
				if (chan_send(fds[0], "z", 1) != 0)
					_exit(3);
				close(fds[0]);
				close(fds[1]);
			}
			_exit(0);
		}
	}

	for (i = 0; i < nchild; i++) {
		ATF_REQUIRE(waitpid(pids[i], &status, 0) == pids[i]);
		ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		    "child %d exited 0x%x", i, status);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_pair);
	ATF_TP_ADD_TC(tp, bidirectional);
	ATF_TP_ADD_TC(tp, carries_nonce);
	ATF_TP_ADD_TC(tp, child_exec_fresh_nonce);
	ATF_TP_ADD_TC(tp, create_in_capmode);
	ATF_TP_ADD_TC(tp, create_efault);
	ATF_TP_ADD_TC(tp, endpoint_grants_no_authority);
	ATF_TP_ADD_TC(tp, create_null_ptr);
	ATF_TP_ADD_TC(tp, fd_exhaustion);
	ATF_TP_ADD_TC(tp, many_pairs_no_leak);
	ATF_TP_ADD_TC(tp, close_orders);
	ATF_TP_ADD_TC(tp, peer_death);
	ATF_TP_ADD_TC(tp, fork_inherit_refcount);
	ATF_TP_ADD_TC(tp, fd_passing);
	ATF_TP_ADD_TC(tp, capmode_full_roundtrip);
	ATF_TP_ADD_TC(tp, concurrent_creates);

	return (atf_no_error());
}
