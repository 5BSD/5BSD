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
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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


/* ------------------------------------------------------------------
 * Delivery fast path, receive status and receive-with-wait.
 * ------------------------------------------------------------------ */

static void
seq_fill(unsigned char *buf, size_t len, uint32_t seq)
{
	size_t i;

	memcpy(buf, &seq, sizeof(seq));
	for (i = sizeof(seq); i < len; i++)
		buf[i] = (unsigned char)(seq * 37 + i);
}

static void
seq_check(const unsigned char *buf, size_t len, uint32_t want)
{
	uint32_t seq;
	size_t i;

	ATF_REQUIRE(len >= sizeof(seq));
	memcpy(&seq, buf, sizeof(seq));
	ATF_REQUIRE_EQ_MSG(want, seq, "message order");
	for (i = sizeof(seq); i < len; i++)
		if (buf[i] != (unsigned char)(seq * 37 + i))
			atf_tc_fail("payload of %u corrupt at %zu", seq, i);
}

/* Sizes crossing the small-zone boundary and reaching the maximum. */
static size_t
seq_len(uint32_t seq)
{
	static const size_t sizes[] = { 4, 100, 1023, 1024, 1025, 4096,
	    MAC_CAPABILITY_MAX_MSG - 1, MAC_CAPABILITY_MAX_MSG, 512 };

	return (sizes[seq % nitems(sizes)]);
}

/* Toggle direct delivery if permitted; returns the previous value or -1. */
static int
set_direct(int value)
{
	int old;
	size_t len = sizeof(old);

	if (sysctlbyname("kern.mac_capability.direct_delivery", &old, &len,
	    &value, sizeof(value)) != 0)
		return (-1);
	return (old);
}

ATF_TC(ordering_mixed_paths);
ATF_TC_HEAD(ordering_mixed_paths, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "messages keep order and content across direct and queued delivery");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "require.user", "root");
	/* Toggles the global kern.mac_capability.direct_delivery knob. */
	atf_tc_set_md_var(tc, "is_exclusive", "true");
}
ATF_TC_BODY(ordering_mixed_paths, tc)
{
	static unsigned char tx[MAC_CAPABILITY_MAX_MSG], rx[MAC_CAPABILITY_MAX_MSG];
	uint32_t seq = 0, want = 0, rxlen;
	int P[2], batch, i, saved;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	saved = set_direct(1);
	for (batch = 0; batch < 40; batch++) {
		/* Alternate paths between batches when the knob is available. */
		if (saved >= 0)
			(void)set_direct(batch % 2);
		for (i = 0; i < 25; i++, seq++) {
			seq_fill(tx, seq_len(seq), seq);
			ATF_REQUIRE_MSG(chan_send(P[0], tx, seq_len(seq)) == 0,
			    "send %u: %s", seq, strerror(errno));
		}
		for (i = 0; i < 25; i++, want++) {
			rxlen = 0;
			ATF_REQUIRE_MSG(chan_recv(P[1], rx, sizeof(rx), &rxlen,
			    NULL) == 0, "recv %u: %s", want, strerror(errno));
			ATF_REQUIRE_EQ(seq_len(want), rxlen);
			seq_check(rx, rxlen, want);
		}
	}
	if (saved >= 0)
		(void)set_direct(saved);
	close(P[0]);
	close(P[1]);
}

ATF_TC(burst_fallback_ordering);
ATF_TC_HEAD(burst_fallback_ordering, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a burst past the peer queue limit falls back without loss or reordering");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(burst_fallback_ordering, tc)
{
	static unsigned char tx[MAC_CAPABILITY_MAX_MSG], rx[MAC_CAPABILITY_MAX_MSG];
	uint32_t seq, want, rxlen;
	int P[2], fl, tries;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	fl = fcntl(P[0], F_GETFL);
	ATF_REQUIRE(fcntl(P[0], F_SETFL, fl | O_NONBLOCK) == 0);
	/* Fill until the transport pushes back with EAGAIN/ENOBUFS. */
	for (seq = 0; seq < 100000; seq++) {
		seq_fill(tx, seq_len(seq), seq);
		if (chan_send(P[0], tx, seq_len(seq)) != 0) {
			ATF_REQUIRE_MSG(errno == EAGAIN || errno == ENOBUFS,
			    "burst send: %s", strerror(errno));
			break;
		}
	}
	ATF_REQUIRE_MSG(seq > 0 && seq < 100000, "queue never pushed back");
	/* Queued messages drain through the service path after the peer reads. */
	for (want = 0; want < seq; want++) {
		for (tries = 0; tries < 2000; tries++) {
			rxlen = 0;
			if (chan_recv_nb(P[1], rx, sizeof(rx), &rxlen, NULL) == 0)
				break;
			ATF_REQUIRE_MSG(errno == EAGAIN, "drain: %s",
			    strerror(errno));
			usleep(1000);
		}
		ATF_REQUIRE_MSG(tries < 2000, "message %u never arrived", want);
		ATF_REQUIRE_EQ(seq_len(want), rxlen);
		seq_check(rx, rxlen, want);
	}
	ATF_REQUIRE(chan_recv_nb(P[1], rx, sizeof(rx), &rxlen, NULL) == -1);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	close(P[0]);
	close(P[1]);
}

static int
recv_flags(int fd, void *buf, size_t len, uint32_t flags, uint32_t wait_ms,
    uint32_t *outflags)
{
	struct mac_capability_recvmsg_args ra;
	int r;

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = len;
	ra.flags = flags;
	ra._reserved[0] = wait_ms;
	r = ioctl(fd, MAC_CAPABILITY_RECVMSG, &ra);
	if (r == 0 && outflags != NULL)
		*outflags = ra.flags;
	return (r);
}

ATF_TC(recv_status_flags);
ATF_TC_HEAD(recv_status_flags, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a receive reports whether further messages remained queued");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(recv_status_flags, tc)
{
	char buf[16];
	uint32_t flags;
	int P[2];

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	ATF_REQUIRE(chan_send(P[0], "one", 3) == 0);
	ATF_REQUIRE(chan_send(P[0], "two", 3) == 0);
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf), 0, 0, &flags) == 0);
	ATF_CHECK(flags & MAC_CAPABILITY_RECV_F_STATUS);
	ATF_CHECK((flags & MAC_CAPABILITY_RECV_F_EMPTY) == 0);
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf), 0, 0, &flags) == 0);
	ATF_CHECK(flags & MAC_CAPABILITY_RECV_F_STATUS);
	ATF_CHECK(flags & MAC_CAPABILITY_RECV_F_EMPTY);
	close(P[0]);
	close(P[1]);
}

ATF_TC(recv_wait_timeout_and_args);
ATF_TC_HEAD(recv_wait_timeout_and_args, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "receive-with-wait times out, polls, and validates its arguments");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(recv_wait_timeout_and_args, tc)
{
	struct timespec t0, t1;
	char buf[16];
	double ms;
	int P[2], fl;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	fl = fcntl(P[1], F_GETFL);
	ATF_REQUIRE(fcntl(P[1], F_SETFL, fl | O_NONBLOCK) == 0);
	/* A wait on a non-blocking descriptor still waits, then times out. */
	clock_gettime(CLOCK_MONOTONIC, &t0);
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf),
	    MAC_CAPABILITY_RECV_F_WAIT, 100, NULL) == -1);
	ATF_REQUIRE_EQ(ETIMEDOUT, errno);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	ms = (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
	ATF_CHECK_MSG(ms >= 80 && ms < 5000, "waited %.1f ms", ms);
	/* A zero wait polls. */
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf),
	    MAC_CAPABILITY_RECV_F_WAIT, 0, NULL) == -1);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	/* A timeout without the wait flag, or unknown flags, is invalid. */
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf), 0, 5, NULL) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf), 0x80, 0, NULL) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	/* A queued message returns at once. */
	ATF_REQUIRE(chan_send(P[0], "now", 3) == 0);
	ATF_REQUIRE(recv_flags(P[1], buf, sizeof(buf),
	    MAC_CAPABILITY_RECV_F_WAIT, MAC_CAPABILITY_RECV_WAIT_FOREVER,
	    NULL) == 0);
	ATF_CHECK(memcmp(buf, "now", 3) == 0);
	close(P[0]);
	close(P[1]);
}

ATF_TC(recv_wait_wakes);
ATF_TC_HEAD(recv_wait_wakes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a message from another process wakes a waiting receive");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(recv_wait_wakes, tc)
{
	char buf[16];
	pid_t child;
	int P[2], status;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(P[1]);
		usleep(150000);
		_exit(chan_send(P[0], "wake", 4) == 0 ? 0 : 1);
	}
	close(P[0]);
	ATF_REQUIRE_MSG(recv_flags(P[1], buf, sizeof(buf),
	    MAC_CAPABILITY_RECV_F_WAIT, 10000, NULL) == 0,
	    "waiting receive: %s", strerror(errno));
	ATF_CHECK(memcmp(buf, "wake", 4) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(P[1]);
}

ATF_TC(xfer_once_direct);
ATF_TC_HEAD(xfer_once_direct, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a one-hop descriptor is delivered once and then refused");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(xfer_once_direct, tc)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	int P[2], pipefd[2], rfds[MAC_CAPABILITY_MAX_FDS];
	char rx[16], byte;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(cap_xfer_limit(pipefd[1], CAP_XFER_ONCE) == 0);
	memset(&sa, 0, sizeof(sa));
	sa.payload = "fd";
	sa.payload_len = 2;
	sa.fds = &pipefd[1];
	sa.nfds = 1;
	ATF_REQUIRE_MSG(ioctl(P[0], MAC_CAPABILITY_SENDMSG, &sa) == 0,
	    "first send: %s", strerror(errno));
	/* Authority was consumed by the accepted send. */
	ATF_REQUIRE(ioctl(P[0], MAC_CAPABILITY_SENDMSG, &sa) == -1);
	ATF_REQUIRE_EQ(ENOTCAPABLE, errno);
	memset(&ra, 0, sizeof(ra));
	ra.payload = rx;
	ra.payload_len = sizeof(rx);
	ra.fds = rfds;
	ra.nfds = MAC_CAPABILITY_MAX_FDS;
	ATF_REQUIRE(ioctl(P[1], MAC_CAPABILITY_RECVMSG, &ra) == 0);
	ATF_REQUIRE_EQ(1, ra.nfds);
	ATF_REQUIRE(write(rfds[0], "x", 1) == 1);
	ATF_REQUIRE(read(pipefd[0], &byte, 1) == 1 && byte == 'x');
	close(rfds[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	close(P[0]);
	close(P[1]);
}

ATF_TC(fd_payload_sizes);
ATF_TC_HEAD(fd_payload_sizes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "descriptors travel intact with small and maximum payloads");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fd_payload_sizes, tc)
{
	static unsigned char tx[MAC_CAPABILITY_MAX_MSG], rx[MAC_CAPABILITY_MAX_MSG];
	static const size_t sizes[] = { 1, 1024, 1025, MAC_CAPABILITY_MAX_MSG };
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	int P[2], pipes[3][2], fds[3], rfds[MAC_CAPABILITY_MAX_FDS], base;
	unsigned i, j;
	char byte;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	base = lowest_free_fd();
	for (i = 0; i < nitems(sizes); i++) {
		for (j = 0; j < 3; j++) {
			ATF_REQUIRE(pipe(pipes[j]) == 0);
			fds[j] = pipes[j][1];
		}
		seq_fill(tx, sizes[i] < 4 ? 4 : sizes[i], i);
		memset(&sa, 0, sizeof(sa));
		sa.payload = tx;
		sa.payload_len = sizes[i] < 4 ? 4 : sizes[i];
		sa.fds = fds;
		sa.nfds = 3;
		ATF_REQUIRE_MSG(ioctl(P[0], MAC_CAPABILITY_SENDMSG, &sa) == 0,
		    "send %zu: %s", sizes[i], strerror(errno));
		memset(&ra, 0, sizeof(ra));
		ra.payload = rx;
		ra.payload_len = sizeof(rx);
		ra.fds = rfds;
		ra.nfds = MAC_CAPABILITY_MAX_FDS;
		ATF_REQUIRE(ioctl(P[1], MAC_CAPABILITY_RECVMSG, &ra) == 0);
		ATF_REQUIRE_EQ(3, ra.nfds);
		seq_check(rx, ra.payload_len, i);
		for (j = 0; j < 3; j++) {
			ATF_REQUIRE(write(rfds[j], "m", 1) == 1);
			ATF_REQUIRE(read(pipes[j][0], &byte, 1) == 1);
			close(rfds[j]);
			close(pipes[j][0]);
			close(pipes[j][1]);
		}
	}
	ATF_CHECK_EQ(base, lowest_free_fd());
	close(P[0]);
	close(P[1]);
}

/* ------------------------------------------------------------------
 * Descriptor expectations, move and lock in one send; receive info.
 * ------------------------------------------------------------------ */

static int
send_v2(int fd, int *fds, uint32_t nfds,
    const struct mac_capability_fd_spec *specs, uint32_t flags)
{
	struct mac_capability_sendmsg_v2_args a;

	memset(&a, 0, sizeof(a));
	a.message.payload = "v2";
	a.message.payload_len = 2;
	a.message.fds = fds;
	a.message.nfds = nfds;
	a.message.flags = flags;
	a.fd_specs = specs;
	return (ioctl(fd, MAC_CAPABILITY_SENDMSG_V2, &a));
}

static int
recv_v4(int fd, int *fds, struct mac_capability_fd_info *info,
    uint32_t *nfds)
{
	struct mac_capability_recvmsg_v4_args a;
	char rx[16];

	memset(&a, 0, sizeof(a));
	a.v3.message.payload = rx;
	a.v3.message.payload_len = sizeof(rx);
	a.v3.message.fds = fds;
	a.v3.message.nfds = MAC_CAPABILITY_MAX_FDS;
	a.fd_info = info;
	if (ioctl(fd, MAC_CAPABILITY_RECVMSG_V4, &a) != 0)
		return (-1);
	*nfds = a.v3.message.nfds;
	return (0);
}

/*
 * recv_v4 on a nonblocking endpoint for a message whose send was accepted.
 * Only direct delivery is synchronous; the queued path (direct delivery
 * off, or the sender not idle) forwards through the bearer taskqueue, so
 * retry EAGAIN for a bounded time.
 */
static int
recv_v4_accepted(int fd, int *fds, struct mac_capability_fd_info *info,
    uint32_t *nfds)
{
	int i;

	for (i = 0; i < 5000; i++) {
		if (recv_v4(fd, fds, info, nfds) == 0)
			return (0);
		if (errno != EAGAIN)
			return (-1);
		usleep(1000);
	}
	return (-1);
}

static bool
locked_inheritance(int fd)
{

	return (cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE &&
	    cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE);
}

ATF_TC(sendmsg_v2_atomic);
ATF_TC_HEAD(sendmsg_v2_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a failed descriptor expectation rejects the whole message and "
	    "consumes no transfer authority; malformed arguments are refused");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(sendmsg_v2_atomic, tc)
{
	struct mac_capability_sendmsg_v2_args a;
	struct mac_capability_fd_spec specs[2];
	int P[2], pipefd[2], fds[2], rfds[MAC_CAPABILITY_MAX_FDS];
	uint32_t nfds;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	/* Probe for "nothing queued" without blocking. */
	ATF_REQUIRE(fcntl(P[1], F_SETFL, O_NONBLOCK) == 0);
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(cap_xfer_limit(pipefd[1], CAP_XFER_ONCE) == 0);
	fds[0] = pipefd[1];
	fds[1] = pipefd[0];
	memset(specs, 0, sizeof(specs));
	specs[1].type = MAC_CAPABILITY_FD_TYPE_SOCKET;
	ATF_REQUIRE(send_v2(P[0], fds, 2, specs,
	    MAC_CAPABILITY_SEND_F_MOVE) == -1);
	ATF_REQUIRE_EQ(EFTYPE, errno);
	/* Nothing moved, nothing queued, one-hop authority intact. */
	ATF_REQUIRE(fcntl(pipefd[0], F_GETFD) != -1);
	ATF_REQUIRE(fcntl(pipefd[1], F_GETFD) != -1);
	ATF_REQUIRE(recv_v4(P[1], rfds, NULL, &nfds) == -1);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	specs[1].type = MAC_CAPABILITY_FD_TYPE_ANY;
	specs[1].rights = MAC_CAPABILITY_FD_RIGHT_WRITE;
	cap_rights_t r;
	cap_rights_init(&r, CAP_READ, CAP_EVENT);
	ATF_REQUIRE(cap_rights_limit(pipefd[0], &r) == 0);
	ATF_REQUIRE(send_v2(P[0], fds, 2, specs, 0) == -1);
	ATF_REQUIRE_EQ(ENOTCAPABLE, errno);
	ATF_REQUIRE(send_v2(P[0], fds, 1, NULL, 0) == 0);
	ATF_REQUIRE(recv_v4_accepted(P[1], rfds, NULL, &nfds) == 0);
	ATF_REQUIRE_EQ(1, nfds);
	close(rfds[0]);

	/* Argument errors. */
	memset(specs, 0, sizeof(specs));
	specs[0].type = 4;
	ATF_REQUIRE(send_v2(P[0], &pipefd[0], 1, specs, 0) == -1);
	ATF_REQUIRE_EQ(EOPNOTSUPP, errno);
	specs[0].type = MAC_CAPABILITY_FD_TYPE_CHANNEL;
	specs[0].rights = MAC_CAPABILITY_FD_RIGHT_READ;
	ATF_REQUIRE(send_v2(P[0], &pipefd[0], 1, specs, 0) == -1);
	ATF_REQUIRE_EQ(EOPNOTSUPP, errno);
	memset(specs, 0, sizeof(specs));
	specs[0].rights = MAC_CAPABILITY_FD_RIGHT_FSTAT;
	ATF_REQUIRE(send_v2(P[0], &pipefd[0], 1, specs, 0) == -1);
	ATF_REQUIRE_EQ(EOPNOTSUPP, errno);
	ATF_REQUIRE(send_v2(P[0], &pipefd[0], 1, NULL, 0x4) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	memset(&a, 0, sizeof(a));
	a.message.payload = "x";
	a.message.payload_len = 1;
	a._reserved2[1] = 1;
	ATF_REQUIRE(ioctl(P[0], MAC_CAPABILITY_SENDMSG_V2, &a) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	/* A message with no descriptors ignores fd_specs. */
	a._reserved2[1] = 0;
	a.fd_specs = (void *)(uintptr_t)1;
	ATF_REQUIRE(ioctl(P[0], MAC_CAPABILITY_SENDMSG_V2, &a) == 0);
	ATF_REQUIRE(recv_v4_accepted(P[1], rfds, NULL, &nfds) == 0);
	ATF_REQUIRE_EQ(0, nfds);
	/* An unreadable spec array faults without side effects. */
	ATF_REQUIRE(send_v2(P[0], &pipefd[0], 1,
	    (void *)(uintptr_t)1, MAC_CAPABILITY_SEND_F_MOVE) == -1);
	ATF_REQUIRE_EQ(EFAULT, errno);
	ATF_REQUIRE(fcntl(pipefd[0], F_GETFD) != -1);
	close(pipefd[0]);
	close(pipefd[1]);
	close(P[0]);
	close(P[1]);
}

ATF_TC(sendmsg_v2_move_lock_paths);
ATF_TC_HEAD(sendmsg_v2_move_lock_paths, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "move closes the sender's descriptors and lock-inherit locks the "
	    "delivered ones, on direct and queued delivery");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sendmsg_v2_move_lock_paths, tc)
{
	struct mac_capability_fd_spec specs[3];
	struct mac_capability_fd_info info[MAC_CAPABILITY_MAX_FDS];
	int P[2], pipefd[2], fds[3], rfds[MAC_CAPABILITY_MAX_FDS];
	int pass, saved, i;
	uint32_t nfds;
	char byte;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	saved = set_direct(1);
	for (pass = 0; pass < 2; pass++) {
		if (saved >= 0)
			(void)set_direct(pass == 0);
		ATF_REQUIRE(pipe(pipefd) == 0);
		fds[0] = pipefd[1];
		fds[1] = dup(pipefd[1]);
		fds[2] = dup(pipefd[1]);
		ATF_REQUIRE(fds[1] >= 0 && fds[2] >= 0);
		memset(specs, 0, sizeof(specs));
		specs[1].flags = MAC_CAPABILITY_FD_SPEC_LOCK_INHERIT;
		specs[2].rights = MAC_CAPABILITY_FD_RIGHT_WRITE;
		ATF_REQUIRE_MSG(send_v2(P[0], fds, 3, specs,
		    MAC_CAPABILITY_SEND_F_MOVE) == 0, "pass %d: %s", pass,
		    strerror(errno));
		for (i = 0; i < 3; i++) {
			errno = 0;
			ATF_REQUIRE(fcntl(fds[i], F_GETFD) == -1);
			ATF_REQUIRE_EQ(EBADF, errno);
		}
		ATF_REQUIRE(recv_v4(P[1], rfds, info, &nfds) == 0);
		ATF_REQUIRE_EQ(3, nfds);
		ATF_REQUIRE(!locked_inheritance(rfds[0]));
		ATF_REQUIRE(locked_inheritance(rfds[1]));
		ATF_REQUIRE(!locked_inheritance(rfds[2]));
		ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_TYPE_OTHER, info[2].type);
		ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_RIGHT_WRITE |
		    MAC_CAPABILITY_FD_RIGHTS_EXACT, info[2].rights);
		ATF_REQUIRE((info[0].rights &
		    MAC_CAPABILITY_FD_RIGHTS_EXACT) == 0);
		for (i = 0; i < 3; i++) {
			ATF_REQUIRE(write(rfds[i], "m", 1) == 1);
			close(rfds[i]);
		}
		for (i = 0; i < 3; i++)
			ATF_REQUIRE(read(pipefd[0], &byte, 1) == 1);
		/* The moved descriptors were the only writers left. */
		ATF_REQUIRE_EQ(0, read(pipefd[0], &byte, 1));
		close(pipefd[0]);

		/* Whole-message lock. */
		ATF_REQUIRE(pipe(pipefd) == 0);
		ATF_REQUIRE(send_v2(P[0], &pipefd[1], 1, NULL,
		    MAC_CAPABILITY_SEND_F_LOCK_INHERIT) == 0);
		ATF_REQUIRE(fcntl(pipefd[1], F_GETFD) != -1);
		ATF_REQUIRE(!locked_inheritance(pipefd[1]));
		ATF_REQUIRE(recv_v4(P[1], rfds, NULL, &nfds) == 0);
		ATF_REQUIRE_EQ(1, nfds);
		ATF_REQUIRE(locked_inheritance(rfds[0]));
		close(rfds[0]);
		close(pipefd[0]);
		close(pipefd[1]);
	}
	if (saved >= 0)
		(void)set_direct(saved);
	close(P[0]);
	close(P[1]);
}

ATF_TC(recvmsg_v4_info);
ATF_TC_HEAD(recvmsg_v4_info, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RECVMSG_V4 reports each received descriptor's type and rights");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(recvmsg_v4_info, tc)
{
	struct mac_capability_recvmsg_v4_args a;
	struct mac_capability_fd_spec specs[3];
	struct mac_capability_fd_info info[MAC_CAPABILITY_MAX_FDS];
	int P[2], Q[2], sv[2], fds[3], rfds[MAC_CAPABILITY_MAX_FDS];
	cap_rights_t rights;
	uint32_t nfds;
	int i;

	ATF_REQUIRE(chan_create_or_skip(P) == 0);
	ATF_REQUIRE(chan_create_or_skip(Q) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	fds[0] = sv[0];
	fds[1] = sv[1];
	fds[2] = Q[0];
	memset(specs, 0, sizeof(specs));
	specs[0].type = MAC_CAPABILITY_FD_TYPE_SOCKET;
	specs[0].rights = MAC_CAPABILITY_FD_RIGHT_READ |
	    MAC_CAPABILITY_FD_RIGHT_WRITE;
	specs[2].type = MAC_CAPABILITY_FD_TYPE_CHANNEL;
	ATF_REQUIRE(send_v2(P[0], fds, 3, specs, 0) == 0);
	memset(info, 0xff, sizeof(info));
	ATF_REQUIRE(recv_v4(P[1], rfds, info, &nfds) == 0);
	ATF_REQUIRE_EQ(3, nfds);
	ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_TYPE_SOCKET, info[0].type);
	ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_RIGHT_READ |
	    MAC_CAPABILITY_FD_RIGHT_WRITE | MAC_CAPABILITY_FD_RIGHT_FSTAT |
	    MAC_CAPABILITY_FD_RIGHTS_EXACT, info[0].rights);
	ATF_REQUIRE(cap_rights_get(rfds[0], &rights) == 0);
	ATF_REQUIRE(!cap_rights_is_set(&rights, CAP_IOCTL));
	ATF_REQUIRE(!cap_rights_is_set(&rights, CAP_SHUTDOWN));
	ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_TYPE_SOCKET, info[1].type);
	ATF_REQUIRE((info[1].rights & (MAC_CAPABILITY_FD_RIGHT_READ |
	    MAC_CAPABILITY_FD_RIGHT_WRITE | MAC_CAPABILITY_FD_RIGHT_FSTAT)) ==
	    (MAC_CAPABILITY_FD_RIGHT_READ | MAC_CAPABILITY_FD_RIGHT_WRITE |
	    MAC_CAPABILITY_FD_RIGHT_FSTAT));
	ATF_REQUIRE((info[1].rights & MAC_CAPABILITY_FD_RIGHTS_EXACT) == 0);
	ATF_REQUIRE_EQ(MAC_CAPABILITY_FD_TYPE_CHANNEL, info[2].type);
	/* Entries past nfds are left alone. */
	ATF_REQUIRE_EQ(0xffffffffu, info[3].type);
	for (i = 0; i < 3; i++)
		close(rfds[i]);
	/* The sender's socket kept its rights. */
	ATF_REQUIRE(cap_rights_get(sv[0], &rights) == 0);
	ATF_REQUIRE(cap_rights_is_set(&rights, CAP_SHUTDOWN));

	memset(&a, 0, sizeof(a));
	a._reserved2[0] = 1;
	ATF_REQUIRE(ioctl(P[1], MAC_CAPABILITY_RECVMSG_V4, &a) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	close(sv[0]);
	close(sv[1]);
	close(Q[0]);
	close(Q[1]);
	close(P[0]);
	close(P[1]);
}

ATF_TC(peer_close_race);
ATF_TC_HEAD(peer_close_race, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "peer lookups racing a closing peer neither revive nor touch it");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "600");
}
ATF_TC_BODY(peer_close_race, tc)
{
	char buf[64];
	int P[2], round, saved, status;
	pid_t child;

	saved = set_direct(1);
	for (round = 0; round < 400; round++) {
		if (saved >= 0)
			(void)set_direct(round % 2);
		ATF_REQUIRE(chan_create_or_skip(P) == 0);
		ATF_REQUIRE(fcntl(P[0], F_SETFL, O_NONBLOCK) == 0);
		ATF_REQUIRE(fcntl(P[1], F_SETFL, O_NONBLOCK) == 0);
		child = fork();
		ATF_REQUIRE(child >= 0);
		if (child == 0) {
			/* Send (direct lookup) and receive (drain lookup)
			 * until the peer is gone. */
			close(P[1]);
			for (;;) {
				if (chan_send(P[0], "r", 1) != 0 &&
				    errno != EAGAIN)
					_exit(0);
				(void)chan_recv(P[0], buf, sizeof(buf), NULL,
				    NULL);
			}
		}
		close(P[0]);
		/* Let the child run a varying amount, keep its queue moving,
		 * then close underneath it. */
		for (int i = 0; i < round % 37; i++) {
			(void)chan_recv(P[1], buf, sizeof(buf), NULL, NULL);
			(void)chan_send(P[1], "p", 1);
		}
		close(P[1]);
		ATF_REQUIRE(waitpid(child, &status, 0) == child);
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	if (saved >= 0)
		(void)set_direct(saved);
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
	ATF_TP_ADD_TC(tp, ordering_mixed_paths);
	ATF_TP_ADD_TC(tp, burst_fallback_ordering);
	ATF_TP_ADD_TC(tp, recv_status_flags);
	ATF_TP_ADD_TC(tp, recv_wait_timeout_and_args);
	ATF_TP_ADD_TC(tp, recv_wait_wakes);
	ATF_TP_ADD_TC(tp, xfer_once_direct);
	ATF_TP_ADD_TC(tp, fd_payload_sizes);
	ATF_TP_ADD_TC(tp, sendmsg_v2_atomic);
	ATF_TP_ADD_TC(tp, sendmsg_v2_move_lock_paths);
	ATF_TP_ADD_TC(tp, recvmsg_v4_info);
	ATF_TP_ADD_TC(tp, peer_close_race);

	return (atf_no_error());
}
