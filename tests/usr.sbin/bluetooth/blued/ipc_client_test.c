/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the libble side of the framed control protocol: the HELLO
 * handshake (version match and mismatch), structured error codes surfacing
 * through ble_errno()/ble_strerror(), and the finding-C8 event-routing fix
 * (an EVENT frame arriving while a command is in flight must not be misrouted
 * into the command's response stream).
 *
 * The "server" is the peer end of a socketpair: because AF_UNIX sockets are
 * buffered and bidirectional, staged response frames are written before the
 * client library reads them, so no server thread is required.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ble.h"
#include "ipc_proto.h"

static bool	g_short_sendmsg;
static int	g_sendmsg_calls;

extern ssize_t	__real_sendmsg(int, const struct msghdr *, int);
ssize_t		__wrap_sendmsg(int, const struct msghdr *, int);
ssize_t
__wrap_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct msghdr one;
	struct iovec iov;
	int i;

	if (!g_short_sendmsg)
		return (__real_sendmsg(fd, msg, flags));

	g_sendmsg_calls++;
	for (i = 0; i < msg->msg_iovlen; i++) {
		if (msg->msg_iov[i].iov_len == 0)
			continue;
		one = *msg;
		iov.iov_base = msg->msg_iov[i].iov_base;
		iov.iov_len = 1;
		one.msg_iov = &iov;
		one.msg_iovlen = 1;
		return (__real_sendmsg(fd, &one, flags));
	}
	errno = EINVAL;
	return (-1);
}

/* Stage one server->client frame on the server end of the pair. */
static void
stage_frame(int srv, uint16_t type, uint16_t arg, const char *pl)
{
	uint8_t hdr[IPC_HDR_SIZE];
	size_t plen = (pl != NULL) ? strlen(pl) : 0;

	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	ATF_REQUIRE(write(srv, hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr));
	if (plen > 0)
		ATF_REQUIRE(write(srv, pl, plen) == (ssize_t)plen);
}

static void stage_raw_frame(int, uint16_t, uint16_t, const void *, size_t);

static void
stage_hello(int srv, uint16_t version, uint32_t features)
{
	uint8_t payload[IPC_HELLO_FEATURES_SIZE];

	ipc_put_le32(payload, features);
	stage_raw_frame(srv, IPC_T_HELLO, version, payload, sizeof(payload));
}

static void
stage_raw_frame(int srv, uint16_t type, uint16_t arg, const void *pl,
    size_t plen)
{
	uint8_t hdr[IPC_HDR_SIZE];

	ipc_hdr_encode(hdr, (uint32_t)plen, type, arg);
	ATF_REQUIRE(write(srv, hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr));
	if (plen != 0)
		ATF_REQUIRE(write(srv, pl, plen) == (ssize_t)plen);
}

static void
read_exact(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < len) {
		ssize_t n;

		n = read(fd, p + got, len - got);
		ATF_REQUIRE(n > 0);
		got += (size_t)n;
	}
}

/* ================================================================
 * Test: HELLO handshake succeeds when the server version matches.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_handshake_match);
ATF_TC_BODY(client_handshake_match, tc)
{
	ble_ctx_t *ctx;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	/* Server accepts the current version and event capability. */
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);

	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_handshake(ctx), 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_NONE);

	ble_close(ctx);
	close(sp[1]);
}

/* ================================================================
 * Test: HELLO version MISMATCH fails cleanly (BLE_ERR_PROTO), no hang.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_handshake_version_mismatch);
ATF_TC_BODY(client_handshake_version_mismatch, tc)
{
	ble_ctx_t *ctx;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	/* Server advertises an incompatible version. */
	stage_hello(sp[1], IPC_PROTO_VERSION + 99, 0);

	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_handshake(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PROTO);

	ble_close(ctx);
	close(sp[1]);
}

/* ================================================================
 * Test: an IPC_T_ERROR reply from the server, indicating the handshake was
 * rejected, surfaces as a clean error (not a hang).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_handshake_rejected);
ATF_TC_BODY(client_handshake_rejected, tc)
{
	ble_ctx_t *ctx;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	stage_frame(sp[1], IPC_T_ERROR, IPC_ERR_PROTO,
	    "protocol version mismatch");

	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_handshake(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PROTO);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_handshake_short_sendmsg);
ATF_TC_BODY(client_handshake_short_sendmsg, tc)
{
	ble_ctx_t *ctx;
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[64];
	uint32_t plen;
	uint16_t type, arg;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);

	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);

	g_sendmsg_calls = 0;
	g_short_sendmsg = true;
	ATF_CHECK_EQ(ble_handshake(ctx), 0);
	g_short_sendmsg = false;
	ATF_CHECK_MSG(g_sendmsg_calls > 1,
	    "short-write wrapper was not exercised");

	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_CHECK_EQ(IPC_T_HELLO, type);
	ATF_CHECK_EQ(IPC_PROTO_VERSION, arg);
	ATF_REQUIRE_EQ(plen, IPC_HELLO_FEATURES_SIZE);
	read_exact(sp[1], payload, plen);
	ATF_CHECK((ipc_get_le32(payload) & IPC_FEATURE_EVENTS) != 0);
	ATF_CHECK((ipc_get_le32(payload) & IPC_FEATURE_FDPASS) != 0);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_correlated_control);
ATF_TC_BODY(client_correlated_control, tc)
{
	ble_ctx_t *ctx;
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t hello[128];
	uint8_t req[IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE];
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_CTL_REPLY_SIZE];
	uint32_t plen, request_id, arg0, arg1;
	uint16_t type, arg, status, flags, opcode, ctlflags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);

	/* Consume the client's HELLO before inspecting the operation frame. */
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_REQUIRE(plen <= sizeof(hello));
	read_exact(sp[1], hello, plen);

	ATF_REQUIRE_EQ(ble_set_preferred_mtu(ctx, 247), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(arg, IPC_OP_DOMAIN_CTL);
	ATF_REQUIRE_EQ(plen, sizeof(req));
	read_exact(sp[1], req, plen);
	ipc_op_prefix_decode(req, &request_id, &status, &flags);
	ATF_CHECK(request_id != 0);
	ATF_CHECK_EQ(status, 0);
	ATF_CHECK_EQ(flags, 0);
	ipc_ctl_req_decode(req + IPC_OP_PREFIX_SIZE, &opcode, &ctlflags,
	    &arg0, &arg1);
	ATF_CHECK_EQ(opcode, IPC_CTL_SET_MTU);
	ATF_CHECK_EQ(arg0, 247);

	ipc_op_prefix_encode(reply, request_id, IPC_ERR_NONE, 0);
	ipc_ctl_reply_encode(reply + IPC_OP_PREFIX_SIZE, opcode, 0, 247);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
	    sizeof(reply));
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_NONE);

	ATF_REQUIRE_EQ(ble_set_preferred_mtu(ctx, 185), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	ATF_REQUIRE_EQ(plen, sizeof(req));
	read_exact(sp[1], req, plen);
	ipc_op_prefix_decode(req, &request_id, &status, &flags);
	ipc_op_prefix_encode(reply, request_id + 1, IPC_ERR_NONE, 0);
	ipc_ctl_reply_encode(reply + IPC_OP_PREFIX_SIZE, IPC_CTL_SET_MTU, 0,
	    185);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
	    sizeof(reply));
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PROTO);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_correlated_status_and_adapter_caps);
ATF_TC_BODY(client_correlated_status_and_adapter_caps, tc)
{
	ble_adapter_caps_t caps;
	ble_ctx_t *ctx;
	ble_status_t snapshot;
	uint8_t hdr[IPC_HDR_SIZE], request[128];
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ADAPTER_CAPS_REPLY_SIZE];
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	char name[IPC_ADAPTER_NAME_SIZE] = "ubt2";
	uint32_t arg0, arg1, plen, request_id;
	uint16_t type, domain, status, flags, opcode, ctlflags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE(plen <= sizeof(request));
	read_exact(sp[1], request, plen);

	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_status_reply_encode(reply + IPC_OP_PREFIX_SIZE, 3, 4, 5,
	    IPC_STATUS_F_PERIPH_ACTIVE);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
	    IPC_OP_PREFIX_SIZE + IPC_STATUS_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_status(ctx, &snapshot), 0);
	ATF_CHECK_EQ(snapshot.adapters, 3);
	ATF_CHECK_EQ(snapshot.connections, 4);
	ATF_CHECK_EQ(snapshot.clients, 5);
	ATF_CHECK(snapshot.peripheral_active);

	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_CTL);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 1);
	ATF_CHECK_EQ(status, IPC_ERR_NONE);
	ATF_CHECK_EQ(flags, 0);
	ipc_ctl_req_decode(request + IPC_OP_PREFIX_SIZE, &opcode, &ctlflags,
	    &arg0, &arg1);
	ATF_CHECK_EQ(opcode, IPC_CTL_STATUS);
	ATF_CHECK_EQ(ctlflags, 0);
	ATF_CHECK_EQ(arg0, 0);
	ATF_CHECK_EQ(arg1, 0);

	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 2, IPC_ERR_NONE, 0);
	ipc_adapter_caps_reply_encode(reply + IPC_OP_PREFIX_SIZE, 2, name,
	    addr, 1, 1, 0x123456789abcdef0ULL);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
	    sizeof(reply));
	ATF_REQUIRE_EQ(ble_adapter_caps(ctx, 2, &caps), 0);
	ATF_CHECK_EQ(caps.index, 2);
	ATF_CHECK_STREQ(caps.name, "ubt2");
	ATF_CHECK_EQ(caps.addr.addr_type, 1);
	ATF_CHECK(memcmp(caps.addr.addr, addr, sizeof(addr)) == 0);
	ATF_CHECK_EQ(caps.addr.adapter_index, 2);
	ATF_CHECK(caps.powered);
	ATF_CHECK_EQ(caps.le_features, 0x123456789abcdef0ULL);

	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_CTL);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_CTL_REQ_SIZE);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 2);
	ipc_ctl_req_decode(request + IPC_OP_PREFIX_SIZE, &opcode, &ctlflags,
	    &arg0, &arg1);
	ATF_CHECK_EQ(opcode, IPC_CTL_ADAPTER_CAPS);
	ATF_CHECK_EQ(arg0, 2);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_sync_query_rejects_bad_replies);
ATF_TC_BODY(client_sync_query_rejects_bad_replies, tc)
{
	static const struct {
		uint32_t request_id;
		uint16_t domain;
		uint16_t status;
		uint16_t flags;
		size_t body_len;
		int error;
	} cases[] = {
		{ 2, IPC_OP_DOMAIN_CTL, IPC_ERR_NONE, 0,
		    IPC_STATUS_REPLY_SIZE, BLE_ERR_PROTO },
		{ 1, IPC_OP_DOMAIN_GAP, IPC_ERR_NONE, 0,
		    IPC_STATUS_REPLY_SIZE, BLE_ERR_PROTO },
		{ 1, IPC_OP_DOMAIN_CTL, IPC_ERR_NONE, 1,
		    IPC_STATUS_REPLY_SIZE, BLE_ERR_PROTO },
		{ 1, IPC_OP_DOMAIN_CTL, IPC_ERR_NONE, 0,
		    IPC_STATUS_REPLY_SIZE - 1, BLE_ERR_PROTO },
		{ 1, IPC_OP_DOMAIN_CTL, IPC_ERR_INVAL, 0, 3, BLE_ERR_INVAL },
	};
	ble_status_t snapshot;
	ble_ctx_t *ctx;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_STATUS_REPLY_SIZE];
	int sp[2];
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
		stage_hello(sp[1], IPC_PROTO_VERSION, 0);
		ctx = ble_open_fd(sp[0]);
		ATF_REQUIRE(ctx != NULL);
		ATF_REQUIRE_EQ(ble_handshake(ctx), 0);

		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, cases[i].request_id, cases[i].status,
		    cases[i].flags);
		if (cases[i].status == IPC_ERR_NONE)
			ipc_status_reply_encode(reply + IPC_OP_PREFIX_SIZE, 1, 2, 3, 0);
		else
			memcpy(reply + IPC_OP_PREFIX_SIZE, "bad", 3);
		stage_raw_frame(sp[1], IPC_T_OP_REPLY, cases[i].domain, reply,
		    IPC_OP_PREFIX_SIZE + cases[i].body_len);

		ATF_CHECK_EQ(ble_status(ctx, &snapshot), -1);
		ATF_CHECK_EQ(ble_errno(ctx), cases[i].error);
		ble_close(ctx);
		close(sp[1]);
	}
}

ATF_TC_WITHOUT_HEAD(client_adapter_caps_rejects_bad_results);
ATF_TC_BODY(client_adapter_caps_rejects_bad_results, tc)
{
	ble_adapter_caps_t caps;
	ble_ctx_t *ctx;
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_ADAPTER_CAPS_REPLY_SIZE];
	char name[IPC_ADAPTER_NAME_SIZE] = "ubt2";
	int sp[2];
	size_t i;

	for (i = 0; i < 3; i++) {
		ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
		stage_hello(sp[1], IPC_PROTO_VERSION, 0);
		ctx = ble_open_fd(sp[0]);
		ATF_REQUIRE(ctx != NULL);
		ATF_REQUIRE_EQ(ble_handshake(ctx), 0);

		memset(reply, 0, sizeof(reply));
		ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
		ipc_adapter_caps_reply_encode(reply + IPC_OP_PREFIX_SIZE,
		    i == 0 ? 3 : 2, name, addr, i == 1 ? 2 : 1,
		    i == 2 ? 2 : 1, 0);
		stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_CTL, reply,
		    sizeof(reply));

		ATF_CHECK_EQ(ble_adapter_caps(ctx, 2, &caps), -1);
		ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PROTO);
		ble_close(ctx);
		close(sp[1]);
	}
}

ATF_TC_WITHOUT_HEAD(client_unknown_accepted_capability_rejected);
ATF_TC_BODY(client_unknown_accepted_capability_rejected, tc)
{
	ble_ctx_t *ctx;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen;
	uint16_t type, arg;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0x80000000u);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_handshake(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PROTO);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &arg);
	read_exact(sp[1], payload, plen);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_disconnect);
ATF_TC_BODY(client_typed_disconnect, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1,
	    .adapter_index = 3 };
	uint8_t hdr[IPC_HDR_SIZE], payload[128], decoded[6], addr_type, reserved;
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags, opcode;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE(plen <= sizeof(payload));
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_disconnect(ctx, &addr), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK(request_id != 0);
	ipc_gap_req_decode(payload + IPC_OP_PREFIX_SIZE, &opcode, &flags,
	    &addr_type, decoded, &reserved);
	ATF_CHECK_EQ(opcode, IPC_GAP_DISCONNECT);
	ATF_CHECK_EQ(addr_type, 1);
	ATF_CHECK_EQ(reserved, 3);
	ATF_CHECK(memcmp(decoded, addr.addr, sizeof(decoded)) == 0);

	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NOT_FOUND, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, "device not found", 16);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + 16);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_NOTFOUND);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_connection_controls);
ATF_TC_BODY(client_typed_connection_controls, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 0 };
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags, opcode;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_set_phy(ctx, &addr, 3, 4), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_PHY_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	opcode = ipc_get_le16(payload + IPC_OP_PREFIX_SIZE);
	ATF_CHECK_EQ(opcode, IPC_GAP_SET_PHY);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 12], 3);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 13], 4);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_REQUIRE_EQ(ble_set_data_length(ctx, &addr, 0x00fb, 0x4290), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_DATA_LEN_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_SET_DATA_LEN);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 0x00fb);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 0x4290);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_REQUIRE_EQ(ble_conn_params_update(ctx, &addr, 6, 12, 3, 200), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_CONN_UPDATE_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_CONN_UPDATE);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 6);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 12);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 16), 3);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 18), 200);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ble_close(ctx);
	close(sp[1]);
}

struct connect_state {
	int calls;
	int error;
	ble_addr_t addr;
};

static void
record_connect(const ble_addr_t *addr, int error, void *arg)
{
	struct connect_state *state = arg;

	state->calls++;
	state->error = error;
	state->addr = *addr;
}

ATF_TC_WITHOUT_HEAD(client_typed_connect);
ATF_TC_BODY(client_typed_connect, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 6, 5, 4, 3, 2, 1 }, .addr_type = 1 };
	ble_conn_params_t params = { .interval_min = 6, .interval_max = 12,
	    .latency = 2, .timeout = 200, .tx_phys = 3, .rx_phys = 5 };
	struct connect_state state;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_connect_params(ctx, &addr, &params, record_connect,
	    &state), 0);
	ATF_CHECK_EQ(state.calls, 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECT_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_CONNECT);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 2),
	    IPC_GAP_F_CONN_PARAMS | IPC_GAP_F_PHY);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 6);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 18), 200);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 20], 3);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 21], 5);

	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.calls, 1);
	ATF_CHECK_EQ(state.error, 0);
	ATF_CHECK(memcmp(state.addr.addr, addr.addr, sizeof(addr.addr)) == 0);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_connect_name);
ATF_TC_BODY(client_typed_connect_name, tc)
{
	ble_ctx_t *ctx;
	struct connect_state state;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint8_t resolved[6] = { 1, 3, 5, 7, 9, 11 };
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_connect_name(ctx, 3, "SensorTag", record_connect,
	    &state), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECT_NAME_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_CONNECT_NAME);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 2),
	    (uint16_t)3 << IPC_OP_ADAPTER_SHIFT);
	ATF_CHECK(strcmp((char *)payload + IPC_OP_PREFIX_SIZE + 4,
	    "SensorTag") == 0);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	payload[IPC_OP_PREFIX_SIZE] = 1;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 1, resolved, sizeof(resolved));
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECT_NAME_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.calls, 1);
	ATF_CHECK_EQ(state.error, 0);
	ATF_CHECK_EQ(state.addr.adapter_index, 3);
	ATF_CHECK_EQ(state.addr.addr_type, 1);
	ATF_CHECK(memcmp(state.addr.addr, resolved, sizeof(resolved)) == 0);

	ble_close(ctx);
	close(sp[1]);
}

struct lifecycle_state {
	int connected_calls;
	int disconnected_calls;
	ble_addr_t addr;
	uint16_t handle;
	uint16_t mtu;
	uint16_t reason;
};

static void
record_connected(const ble_addr_t *addr, uint16_t handle, uint16_t mtu,
    void *arg)
{
	struct lifecycle_state *state = arg;

	state->connected_calls++;
	state->addr = *addr;
	state->handle = handle;
	state->mtu = mtu;
}

static void
record_disconnected(const ble_addr_t *addr, uint16_t reason, void *arg)
{
	struct lifecycle_state *state = arg;

	state->disconnected_calls++;
	state->addr = *addr;
	state->reason = reason;
}

ATF_TC_WITHOUT_HEAD(client_typed_connection_lifecycle);
ATF_TC_BODY(client_typed_connection_lifecycle, tc)
{
	ble_ctx_t *ctx;
	struct lifecycle_state state;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE];
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t addr2[6] = { 6, 5, 4, 3, 2, 1 };
	ble_addr_t peer1 = { .addr_type = 1, .adapter_index = 0 };
	ble_addr_t peer2 = { .addr_type = 0, .adapter_index = 2 };
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	ble_on_connected(ctx, record_connected, &state);
	ble_on_disconnected(ctx, record_disconnected, &state);

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GAP_EV_CONNECTED);
	payload[IPC_OP_PREFIX_SIZE + 2] = 1;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 3, addr, sizeof(addr));
	payload[IPC_OP_PREFIX_SIZE + 9] = 0;
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 10, 0x1234);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 12, 185);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.connected_calls, 1);
	ATF_CHECK_EQ(state.disconnected_calls, 0);
	ATF_CHECK_EQ(state.addr.addr_type, 1);
	ATF_CHECK(memcmp(state.addr.addr, addr, sizeof(addr)) == 0);
	ATF_CHECK_EQ(state.handle, 0x1234);
	ATF_CHECK_EQ(state.mtu, 185);
	memcpy(peer1.addr, addr, sizeof(addr));
	memcpy(peer2.addr, addr2, sizeof(addr2));
	ATF_CHECK(ble_is_connected(ctx));
	ATF_CHECK_EQ(ble_get_mtu(ctx), 185);
	ATF_CHECK(ble_is_peer_connected(ctx, &peer1));
	ATF_CHECK_EQ(ble_get_peer_mtu(ctx, &peer1), 185);
	ATF_CHECK(!ble_is_peer_connected(ctx, &peer2));

	/* A second peer is independently keyed by adapter, type, and address. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GAP_EV_CONNECTED);
	payload[IPC_OP_PREFIX_SIZE + 2] = 0;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 3, addr2, sizeof(addr2));
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 10, 0x5678);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 12, 247);
	payload[IPC_OP_PREFIX_SIZE + 14] = 2;
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    sizeof(payload));
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.connected_calls, 2);
	ATF_CHECK(ble_is_peer_connected(ctx, &peer1));
	ATF_CHECK(ble_is_peer_connected(ctx, &peer2));
	ATF_CHECK_EQ(ble_get_peer_mtu(ctx, &peer1), 185);
	ATF_CHECK_EQ(ble_get_peer_mtu(ctx, &peer2), 247);
	ATF_CHECK_EQ(ble_get_mtu(ctx), 0); /* ambiguous aggregate */

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GAP_EV_DISCONNECTED);
	payload[IPC_OP_PREFIX_SIZE + 2] = 1;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 3, addr, sizeof(addr));
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 9, 0x13);
	payload[IPC_OP_PREFIX_SIZE + 11] = 0;
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.connected_calls, 2);
	ATF_CHECK_EQ(state.disconnected_calls, 1);
	ATF_CHECK_EQ(state.reason, 0x13);
	ATF_CHECK(ble_is_connected(ctx));
	ATF_CHECK(!ble_is_peer_connected(ctx, &peer1));
	ATF_CHECK(ble_is_peer_connected(ctx, &peer2));
	ATF_CHECK_EQ(ble_get_mtu(ctx), 247);

	/* Disconnecting the remaining identity finally clears aggregate state. */
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GAP_EV_DISCONNECTED);
	payload[IPC_OP_PREFIX_SIZE + 2] = 0;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 3, addr2, sizeof(addr2));
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 9, 0x16);
	payload[IPC_OP_PREFIX_SIZE + 11] = 2;
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.disconnected_calls, 2);
	ATF_CHECK(!ble_is_connected(ctx));
	ATF_CHECK_EQ(ble_get_mtu(ctx), 0);

	ble_close(ctx);
	close(sp[1]);
}

struct scan_state {
	int calls;
	ble_scan_result_t result;
};

static void
record_scan(const ble_scan_result_t *result, void *arg)
{
	struct scan_state *state = arg;

	state->calls++;
	state->result = *result;
}

ATF_TC_WITHOUT_HEAD(client_typed_scan);
ATF_TC_BODY(client_typed_scan, tc)
{
	ble_ctx_t *ctx;
	ble_scan_params_t params;
	struct scan_state state;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint8_t addr[6] = { 6, 5, 4, 3, 2, 1 };
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	memset(&params, 0, sizeof(params));
	memset(&state, 0, sizeof(state));
	params.passive = true;
	params.interval = 200;
	params.window = 100;
	params.accept_list = true;
	params.no_dedup = true;
	params.uuid16 = 0x180f;
	params.rssi_min = -70;
	strlcpy(params.name_sub, "Tag", sizeof(params.name_sub));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_scan_filtered(ctx, &params, record_scan, &state), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE), IPC_GAP_SCAN);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 2),
	    IPC_GAP_SCAN_F_PASSIVE | IPC_GAP_SCAN_F_ACCEPT_LIST |
	    IPC_GAP_SCAN_F_NO_DEDUP);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 4), 200);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 6), 100);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 8), 0x180f);
	ATF_CHECK_EQ((int8_t)payload[IPC_OP_PREFIX_SIZE + 10], -70);
	ATF_CHECK(strcmp((char *)payload + IPC_OP_PREFIX_SIZE + 12, "Tag") == 0);

	memset(payload, 0,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GAP_EV_SCAN_RESULT);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 3);
	payload[IPC_OP_PREFIX_SIZE + 4] = 1;
	memcpy(payload + IPC_OP_PREFIX_SIZE + 5, addr, sizeof(addr));
	payload[IPC_OP_PREFIX_SIZE + 11] = (uint8_t)-42;
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 12, 0x1234);
	payload[IPC_OP_PREFIX_SIZE + 14] = 2;
	payload[IPC_OP_PREFIX_SIZE + 15] = 7;
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 16, 0x180f);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 18, 0x180a);
	memcpy(payload + IPC_OP_PREFIX_SIZE + 32, "TestTag", 7);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.calls, 1);
	ATF_CHECK_EQ(state.result.addr.addr_type, 1);
	ATF_CHECK(memcmp(state.result.addr.addr, addr, sizeof(addr)) == 0);
	ATF_CHECK_EQ(state.result.rssi, -42);
	ATF_CHECK_EQ(state.result.mfr_id, 0x1234);
	ATF_CHECK_EQ(state.result.num_svc_uuids, 2);
	ATF_CHECK_EQ(state.result.svc_uuids[0].uuid16, 0x180f);
	ATF_CHECK(strcmp(state.result.name, "TestTag") == 0);
	ATF_CHECK_EQ(ble_get_rssi(ctx, &state.result.addr), -42);

	ble_close(ctx);
	close(sp[1]);
}

struct read_state {
	int calls;
	int error;
	uint16_t handle;
	uint16_t len;
	uint8_t value[16];
};

static void
record_read(const ble_addr_t *addr, uint16_t handle, const uint8_t *value,
    uint16_t len, int error, void *arg)
{
	struct read_state *state = arg;

	(void)addr;
	state->calls++;
	state->error = error;
	state->handle = handle;
	state->len = len;
	if (value != NULL && len <= sizeof(state->value))
		memcpy(state->value, value, len);
}

ATF_TC_WITHOUT_HEAD(client_typed_gatt_io);
ATF_TC_BODY(client_typed_gatt_io, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	struct read_state state;
	const uint8_t write_value[] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_read(ctx, &addr, 0x0025, record_read, &state), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE), IPC_GATT_READ);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 4], 1);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + 5, addr.addr, 6) == 0);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 0x0025);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_READ);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0025);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 4, 3);
	memcpy(payload + IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE,
	    "abc", 3);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE + 3);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.calls, 1);
	ATF_CHECK_EQ(state.error, 0);
	ATF_CHECK_EQ(state.handle, 0x0025);
	ATF_CHECK_EQ(state.len, 3);
	ATF_CHECK(memcmp(state.value, "abc", 3) == 0);

	ATF_REQUIRE_EQ(ble_write(ctx, &addr, 0x0030, write_value,
	    sizeof(write_value)), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE), IPC_GATT_WRITE);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 0x0030);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 4);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_REQ_SIZE,
	    write_value, sizeof(write_value)) == 0);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_REQUIRE_EQ(ble_subscribe(ctx, &addr, 0x0030, NULL, NULL), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_SUBSCRIBE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_gatt_reads_out_of_order);
ATF_TC_BODY(client_gatt_reads_out_of_order, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	struct read_state first, second;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t ids[2], plen;
	uint16_t type, domain, status, flags;
	int i, sp[2];

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_read(ctx, &addr, 0x0021, record_read, &first), 0);
	ATF_REQUIRE_EQ(ble_read(ctx, &addr, 0x0022, record_read, &second), 0);
	for (i = 0; i < 2; i++) {
		read_exact(sp[1], hdr, sizeof(hdr));
		ipc_hdr_decode(hdr, &plen, &type, &domain);
		ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
		ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
		read_exact(sp[1], payload, plen);
		ipc_op_prefix_decode(payload, &ids[i], &status, &flags);
	}

	/* Complete the second request first; callbacks must follow request IDs. */
	ipc_op_prefix_encode(payload, ids[1], IPC_ERR_NONE, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_READ);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0022);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 4, 3);
	memcpy(payload + IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE,
	    "two", 3);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE + 3);
	ipc_op_prefix_encode(payload, ids[0], IPC_ERR_NONE, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_READ);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0021);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 4, 3);
	memcpy(payload + IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE,
	    "one", 3);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_REPLY_SIZE + 3);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_CHECK_EQ(first.calls, 1);
	ATF_CHECK_EQ(first.handle, 0x0021);
	ATF_CHECK(memcmp(first.value, "one", 3) == 0);
	ATF_CHECK_EQ(second.calls, 1);
	ATF_CHECK_EQ(second.handle, 0x0022);
	ATF_CHECK(memcmp(second.value, "two", 3) == 0);

	ble_close(ctx);
	close(sp[1]);
}

struct discover_state {
	int calls;
	int nservices;
	int nchars;
	ble_service_t service;
	ble_characteristic_t characteristic;
};

static void
record_discover(const ble_addr_t *addr, const ble_service_t *services,
    int nservices, const ble_characteristic_t *characteristics, int nchars,
    void *arg)
{
	struct discover_state *state = arg;

	(void)addr;
	state->calls++;
	state->nservices = nservices;
	state->nchars = nchars;
	if (nservices != 0)
		state->service = services[0];
	if (nchars != 0)
		state->characteristic = characteristics[0];
}

ATF_TC_WITHOUT_HEAD(client_typed_gatt_discover);
ATF_TC_BODY(client_typed_gatt_discover, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 0 };
	struct discover_state state;
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	ATF_REQUIRE_EQ(ble_discover(ctx, &addr, record_discover, &state), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_CHECK_EQ(ipc_get_le16(body), IPC_GATT_DISCOVER);

	memset(payload, 0, IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(body, IPC_GATT_EV_SERVICE);
	ipc_put_le16(body + 2, 0x180f);
	ipc_put_le16(body + 20, 1);
	ipc_put_le16(body + 22, 5);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE);
	memset(body, 0, IPC_GATT_DISCOVERY_EVENT_SIZE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(body, IPC_GATT_EV_CHARACTERISTIC);
	ipc_put_le16(body + 2, 0x2a19);
	ipc_put_le16(body + 20, 3);
	body[22] = BLE_PROP_READ | BLE_PROP_NOTIFY;
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.calls, 1);
	ATF_CHECK_EQ(state.nservices, 1);
	ATF_CHECK_EQ(state.nchars, 1);
	ATF_CHECK_EQ(state.service.uuid.uuid16, 0x180f);
	ATF_CHECK_EQ(state.service.start_handle, 1);
	ATF_CHECK_EQ(state.service.end_handle, 5);
	ATF_CHECK_EQ(state.characteristic.uuid.uuid16, 0x2a19);
	ATF_CHECK_EQ(state.characteristic.handle, 3);
	ATF_CHECK_EQ(state.characteristic.properties,
	    BLE_PROP_READ | BLE_PROP_NOTIFY);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_gatt_local_value_ops);
ATF_TC_BODY(client_typed_gatt_local_value_ops, tc)
{
	ble_ctx_t *ctx;
	const uint8_t value[] = { 0x00, 0x7f, 0xff };
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	const uint16_t opcodes[] = {
		IPC_GATT_SET_VALUE,
		IPC_GATT_NOTIFY,
		IPC_GATT_INDICATE,
		IPC_GATT_REMOVE_SERVICE,
	};
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	for (size_t i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); i++) {
		int error;

		switch (opcodes[i]) {
		case IPC_GATT_SET_VALUE:
			error = ble_set_value(ctx, 0x0042, value, sizeof(value));
			break;
		case IPC_GATT_NOTIFY:
			error = ble_notify(ctx, 0x0042, value, sizeof(value));
			break;
		case IPC_GATT_INDICATE:
			error = ble_indicate(ctx, 0x0042, value, sizeof(value));
			break;
		default:
			error = ble_remove_service(ctx, 0x0042);
			break;
		}
		ATF_REQUIRE_EQ(error, 0);
		read_exact(sp[1], hdr, sizeof(hdr));
		ipc_hdr_decode(hdr, &plen, &type, &domain);
		ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
		ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
		read_exact(sp[1], payload, plen);
		ipc_op_prefix_decode(payload, &request_id, &status, &flags);
		ATF_CHECK(request_id != 0);
		ATF_CHECK_EQ(status, 0);
		ATF_CHECK_EQ(flags, 0);
		ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
		    opcodes[i]);
		ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12),
		    0x0042);
		if (opcodes[i] == IPC_GATT_REMOVE_SERVICE) {
			ATF_CHECK_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE);
		} else {
			ATF_CHECK_EQ(plen, IPC_OP_PREFIX_SIZE +
			    IPC_GATT_VALUE_REQ_SIZE + sizeof(value));
			ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14),
			    sizeof(value));
			ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE +
			    IPC_GATT_VALUE_REQ_SIZE, value, sizeof(value)) == 0);
		}
		ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
		stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT,
		    payload, IPC_OP_PREFIX_SIZE);
		ATF_REQUIRE_EQ(ble_process(ctx), 0);
	}

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_gatt_database_ops);
ATF_TC_BODY(client_typed_gatt_database_ops, tc)
{
	ble_ctx_t *ctx;
	ble_uuid_t uuid16 = { .uuid16 = 0x180f };
	ble_uuid_t uuid128 = { .uuid128 = {
	    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } };
	const uint8_t value[] = { 0x12, 0x34 };
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags, handle;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	handle = 0xffff;
	ATF_REQUIRE_EQ(ble_add_service(ctx, &uuid16, &handle), 0);
	ATF_CHECK_EQ(handle, 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
	ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_GATT);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE +
	    IPC_GATT_ADD_SERVICE_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ADD_SERVICE);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 0x180f);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0040);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(handle, 0x0040);

	handle = 0xffff;
	ATF_REQUIRE_EQ(ble_add_char_ex(ctx, 0x0040, &uuid128,
	    BLE_PROP_READ | BLE_PROP_NOTIFY, BLE_PERM_READ, value,
	    sizeof(value), BLE_CHAR_F_DYNAMIC, &handle), 0);
	ATF_CHECK_EQ(handle, 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_CHAR_REQ_SIZE +
	    sizeof(value));
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ADD_CHARACTERISTIC);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 0x0040);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + 16, uuid128.uuid128,
	    sizeof(uuid128.uuid128)) == 0);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 32],
	    BLE_PROP_READ | BLE_PROP_NOTIFY);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 33], BLE_PERM_READ);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 34], BLE_CHAR_F_DYNAMIC);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 36), 2);
	ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE +
	    IPC_GATT_ADD_CHAR_REQ_SIZE, value, sizeof(value)) == 0);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_CHARACTERISTIC);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0042);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(handle, 0x0042);

	handle = 0xffff;
	ATF_REQUIRE_EQ(ble_add_include(ctx, 0x0040, 0x0020, 0x0025, 0x180a,
	    &handle), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_INCLUDE_REQ_SIZE);
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ADD_INCLUDE);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 0x0020);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 16), 0x0025);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 18), 0x180a);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_INCLUDE);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0043);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(handle, 0x0043);

	handle = 0xffff;
	ATF_REQUIRE_EQ(ble_add_descriptor(ctx, 0x0042, &uuid16,
	    BLE_PERM_READ, value, sizeof(value), &handle), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE_EQ(plen, IPC_OP_PREFIX_SIZE + IPC_GATT_ADD_DESC_REQ_SIZE +
	    sizeof(value));
	read_exact(sp[1], payload, plen);
	ipc_op_prefix_decode(payload, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ADD_DESCRIPTOR);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 12), 0x0042);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 14), 0x180f);
	ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 32], BLE_PERM_READ);
	ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE + 34), 2);
	ipc_op_prefix_encode(payload, request_id, 0, 0);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE, IPC_GATT_ADD_DESCRIPTOR);
	ipc_put_le16(payload + IPC_OP_PREFIX_SIZE + 2, 0x0044);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_HANDLE_REPLY_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(handle, 0x0044);

	ble_close(ctx);
	close(sp[1]);
}

struct server_event_state {
	int writes;
	int reads;
	int authorizes;
	uint16_t handle;
	uint16_t offset;
	bool is_write;
	ble_addr_t addr;
	uint8_t value[8];
	uint16_t value_len;
};

static void
record_server_write(uint16_t handle, const uint8_t *value, uint16_t len,
    void *arg)
{
	struct server_event_state *state = arg;

	state->writes++;
	state->handle = handle;
	state->value_len = len;
	memcpy(state->value, value, len);
}

static void
record_server_read(uint16_t handle, uint16_t offset, void *arg)
{
	struct server_event_state *state = arg;

	state->reads++;
	state->handle = handle;
	state->offset = offset;
}

static void
record_server_authorize(const ble_addr_t *addr, uint16_t handle,
    bool is_write, void *arg)
{
	struct server_event_state *state = arg;

	state->authorizes++;
	state->addr = *addr;
	state->handle = handle;
	state->is_write = is_write;
}

ATF_TC_WITHOUT_HEAD(client_typed_gatt_server_events);
ATF_TC_BODY(client_typed_gatt_server_events, tc)
{
	ble_ctx_t *ctx;
	struct server_event_state state;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE + 8];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	uint8_t addr[6] = { 2, 4, 6, 8, 10, 12 };
	int sp[2];

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	ble_on_write(ctx, record_server_write, &state);
	ble_on_read_request(ctx, record_server_read, &state);
	ble_on_authorize(ctx, record_server_authorize, &state);

	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(body, IPC_GATT_EV_WRITE);
	ipc_put_le16(body + 2, 0x0042);
	ipc_put_le16(body + 4, 3);
	memcpy(body + IPC_GATT_VALUE_EVENT_SIZE, "xyz", 3);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE + 3);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.writes, 1);
	ATF_CHECK_EQ(state.handle, 0x0042);
	ATF_CHECK_EQ(state.value_len, 3);
	ATF_CHECK(memcmp(state.value, "xyz", 3) == 0);

	memset(body, 0, IPC_GATT_READ_EVENT_SIZE);
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(body, IPC_GATT_EV_READ);
	ipc_put_le16(body + 2, 0x0043);
	ipc_put_le16(body + 4, 7);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_EVENT_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.reads, 1);
	ATF_CHECK_EQ(state.handle, 0x0043);
	ATF_CHECK_EQ(state.offset, 7);

	memset(body, 0, IPC_GATT_AUTHORIZE_EVENT_SIZE);
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(body, IPC_GATT_EV_AUTHORIZE);
	body[2] = 1;
	memcpy(body + 3, addr, sizeof(addr));
	ipc_put_le16(body + 9, 0x0044);
	body[11] = 1;
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_AUTHORIZE_EVENT_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(state.authorizes, 1);
	ATF_CHECK_EQ(state.addr.addr_type, 1);
	ATF_CHECK(memcmp(state.addr.addr, addr, sizeof(addr)) == 0);
	ATF_CHECK_EQ(state.handle, 0x0044);
	ATF_CHECK(state.is_write);

	ble_close(ctx);
	close(sp[1]);
}

/* ================================================================
 * Test: a peer that never answers HELLO makes ble_handshake() fail cleanly
 * with BLE_ERR_TIMEOUT (bounded wait, never an indefinite hang).  This locks
 * in the intended ble_open() failure mode going forward.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_handshake_timeout);
ATF_TC_BODY(client_handshake_timeout, tc)
{
	ble_ctx_t *ctx;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

	/* sp[1] is left silent: no HELLO reply is ever staged. */
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(ble_handshake(ctx), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_TIMEOUT);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_security_ops);
ATF_TC_BODY(client_typed_security_ops, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 3, 5, 7, 9, 11 }, .addr_type = 1 };
	const uint16_t opcodes[] = {
		IPC_SECURITY_PAIR,
		IPC_SECURITY_PASSKEY_REPLY,
		IPC_SECURITY_NUMCMP_REPLY,
		IPC_SECURITY_REGISTER_AGENT,
		IPC_SECURITY_UNREGISTER_AGENT,
		IPC_SECURITY_UNBOND,
		IPC_SECURITY_REKEY,
	};
	uint8_t hdr[IPC_HDR_SIZE], payload[128];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], payload, plen);

	for (size_t i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); i++) {
		int error;

		switch (opcodes[i]) {
		case IPC_SECURITY_PAIR:
			error = ble_pair(ctx, &addr);
			break;
		case IPC_SECURITY_PASSKEY_REPLY:
			error = ble_passkey_reply(ctx, &addr, 123456);
			break;
		case IPC_SECURITY_NUMCMP_REPLY:
			error = ble_numcmp_reply(ctx, &addr, true);
			break;
		case IPC_SECURITY_REGISTER_AGENT:
			error = ble_register_agent(ctx, BLE_IO_DISPLAY_YESNO);
			break;
		case IPC_SECURITY_UNREGISTER_AGENT:
			error = ble_unregister_agent(ctx);
			break;
		case IPC_SECURITY_UNBOND:
			error = ble_unbond(ctx, &addr);
			break;
		default:
			error = ble_rekey(ctx, &addr);
			break;
		}
		ATF_REQUIRE_EQ(error, 0);
		read_exact(sp[1], hdr, sizeof(hdr));
		ipc_hdr_decode(hdr, &plen, &type, &domain);
		ATF_REQUIRE_EQ(type, IPC_T_OP_REQ);
		ATF_REQUIRE_EQ(domain, IPC_OP_DOMAIN_SECURITY);
		read_exact(sp[1], payload, plen);
		ipc_op_prefix_decode(payload, &request_id, &status, &flags);
		if (opcodes[i] == IPC_SECURITY_PASSKEY_REPLY ||
		    opcodes[i] == IPC_SECURITY_NUMCMP_REPLY) {
			/*
			 * Findings 28/29 passkey/numcmp reply: the standard
			 * typed-security header [opcode u16][flags u16]
			 * [addr_type u8][addr[6]][adapter_index u8][value...].
			 */
			const uint8_t *b = payload + IPC_OP_PREFIX_SIZE;

			ATF_CHECK_EQ(ipc_get_le16(b), opcodes[i]);
			ATF_CHECK_EQ(b[4], addr.addr_type);
			ATF_CHECK(memcmp(b + 5, addr.addr,
			    sizeof(addr.addr)) == 0);
			ATF_CHECK_EQ(b[11], addr.adapter_index);
			if (opcodes[i] == IPC_SECURITY_PASSKEY_REPLY)
				ATF_CHECK_EQ(ipc_get_le32(b + 12), 123456);
			else
				ATF_CHECK_EQ(b[12], 1);
		} else {
			ATF_CHECK_EQ(ipc_get_le16(payload + IPC_OP_PREFIX_SIZE),
			    opcodes[i]);
			if (opcodes[i] != IPC_SECURITY_REGISTER_AGENT &&
			    opcodes[i] != IPC_SECURITY_UNREGISTER_AGENT)
				ATF_CHECK(memcmp(payload + IPC_OP_PREFIX_SIZE + 5,
				    addr.addr, sizeof(addr.addr)) == 0);
			if (opcodes[i] == IPC_SECURITY_REGISTER_AGENT)
				ATF_CHECK_EQ(payload[IPC_OP_PREFIX_SIZE + 12],
				    BLE_IO_DISPLAY_YESNO);
		}
		ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
		stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    payload, IPC_OP_PREFIX_SIZE);
		ATF_REQUIRE_EQ(ble_process(ctx), 0);
	}

	ble_close(ctx);
	close(sp[1]);
}

/*
 * Helper: open + handshake a framed context against the pair.
 */
static ble_ctx_t *
framed_ctx(int sp[2])
{
	ble_ctx_t *ctx;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	return (ctx);
}

/* ================================================================
 * Test: structured error codes map onto ble_errno()/ble_strerror().
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_error_taxonomy);
ATF_TC_BODY(client_error_taxonomy, tc)
{
	struct {
		uint16_t	ipc;
		int		ble;
		const char	*msg;
	} cases[] = {
		{ IPC_ERR_PERM,     BLE_ERR_PERM,    "permission denied" },
		{ IPC_ERR_NOT_CONN, BLE_ERR_NOTCONN, "device not connected" },
		{ IPC_ERR_NOT_FOUND,BLE_ERR_NOTFOUND,"device not found" },
		{ IPC_ERR_INVAL,    BLE_ERR_INVAL,   "invalid address" },
		{ IPC_ERR_BUSY,     BLE_ERR_BUSY,    "rate limited" },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ble_ctx_t *ctx;
		int sp[2];

		ctx = framed_ctx(sp);
		stage_frame(sp[1], IPC_T_ERROR, cases[i].ipc, cases[i].msg);
		ATF_CHECK_EQ(ble_process(ctx), 0);
		ATF_CHECK_EQ_MSG(ble_errno(ctx), cases[i].ble,
		    "ipc code %u", cases[i].ipc);
		ATF_CHECK_MSG(strstr(ble_strerror(ctx), cases[i].msg) != NULL,
		    "strerror '%s' missing '%s'",
		    ble_strerror(ctx), cases[i].msg);

		ble_close(ctx);
		close(sp[1]);
	}
}

/* C8 recording state. */
struct c8_state {
	int	numcmp_calls;
};

static void
c8_numcmp(const ble_addr_t *addr, uint32_t value, void *arg)
{
	struct c8_state *st = arg;

	(void)addr;
	(void)value;
	st->numcmp_calls++;
}

/* ================================================================
 * Test (finding C8): a typed security event is routed to its event callback.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(client_typed_security_event);
ATF_TC_BODY(client_typed_security_event, tc)
{
	ble_ctx_t *ctx;
	struct c8_state st;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE];
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	const uint8_t addr[] = { 1, 2, 3, 4, 5, 6 };
	int sp[2];

	memset(&st, 0, sizeof(st));
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, IPC_FEATURE_EVENTS);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	ble_on_numcmp(ctx, c8_numcmp, &st);
	memset(payload, 0, sizeof(payload));
	ipc_op_prefix_encode(payload, 0, 0, 0);
	ipc_put_le16(body, IPC_SECURITY_EV_NUMCMP);
	body[2] = 0;			/* adapter_index (findings 28/29 layout) */
	body[3] = 1;			/* addr_type */
	memcpy(body + 4, addr, sizeof(addr));
	ipc_put_le32(body + 10, 654321);
	stage_raw_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY,
	    payload, sizeof(payload));
	ATF_REQUIRE_EQ(ble_process(ctx), 0);
	ATF_CHECK_EQ(st.numcmp_calls, 1);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_security_policy);
ATF_TC_BODY(client_typed_security_policy, tc)
{
	ble_ctx_t *ctx;
	ble_security_policy_t policy;
	uint8_t frame[IPC_OP_PREFIX_SIZE + IPC_SECURITY_POLICY_REPLY_SIZE];
	uint8_t hdr[IPC_HDR_SIZE], request[128];
	uint8_t *body = frame + IPC_OP_PREFIX_SIZE;
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 1, 0, 0);
	ipc_put_le16(body, IPC_SECURITY_GET_POLICY);
	body[2] = 1;
	body[3] = 1;
	body[4] = BLE_SC_ONLY;
	body[5] = 1;
	body[6] = BLE_IO_KEYBOARD_DISPLAY;
	body[7] = BLE_SEC_SC;
	body[8] = 16;
	body[9] = BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID;
	ipc_put_le16(body + 10, 900);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    sizeof(frame));
	ATF_REQUIRE_EQ(ble_get_security_policy(ctx, &policy), 0);
	ATF_CHECK(policy.mitm);
	ATF_CHECK(policy.bonding);
	ATF_CHECK_EQ(policy.sc_mode, BLE_SC_ONLY);
	ATF_CHECK_EQ(policy.min_key_size, 16);
	ATF_CHECK_EQ(policy.rpa_timeout, 900);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 1);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_SECURITY);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_SECURITY_GET_POLICY);

	policy.min_key_size = 12;
	ATF_REQUIRE_EQ(ble_set_security_policy(ctx, &policy), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 2);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_SECURITY_SET_POLICY);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12),
	    IPC_SECURITY_POLICY_F_ALL);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 20], 12);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_security_oob_resolving);
ATF_TC_BODY(client_typed_security_oob_resolving, tc)
{
	ble_ctx_t *ctx;
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	ble_oob_sc_t oob;
	uint8_t confirm[16], random[16], pkx[32], irk[16];
	uint8_t frame[IPC_OP_PREFIX_SIZE + IPC_SECURITY_OOB_REPLY_SIZE];
	uint8_t hdr[IPC_HDR_SIZE], request[128];
	uint8_t *body = frame + IPC_OP_PREFIX_SIZE;
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2], error;

	for (size_t i = 0; i < sizeof(confirm); i++) {
		confirm[i] = (uint8_t)i;
		random[i] = (uint8_t)(0x20 + i);
		irk[i] = (uint8_t)(0x80 + i);
	}
	for (size_t i = 0; i < sizeof(pkx); i++)
		pkx[i] = (uint8_t)(0x40 + i);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_SECURITY_OOB_GENERATE);
	memcpy(body + 2, confirm, sizeof(confirm));
	memcpy(body + 18, random, sizeof(random));
	memcpy(body + 34, pkx, sizeof(pkx));
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    sizeof(frame));
	ATF_REQUIRE_EQ(ble_oob_sc_generate(ctx, &oob), 0);
	ATF_CHECK(memcmp(oob.confirm, confirm, sizeof(confirm)) == 0);
	ATF_CHECK(memcmp(oob.random, random, sizeof(random)) == 0);
	ATF_CHECK(memcmp(oob.pkx, pkx, sizeof(pkx)) == 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ATF_CHECK_EQ(type, IPC_T_OP_REQ);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_SECURITY);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_SECURITY_OOB_GENERATE);

	for (uint16_t opcode = IPC_SECURITY_OOB_INJECT_SC;
	    opcode <= IPC_SECURITY_RESOLV_CLEAR; opcode++) {
		switch (opcode) {
		case IPC_SECURITY_OOB_INJECT_SC:
			error = ble_oob_inject_sc(ctx, &addr, confirm, random);
			break;
		case IPC_SECURITY_OOB_INJECT_LEGACY:
			error = ble_oob_inject_legacy(ctx, &addr, confirm);
			break;
		case IPC_SECURITY_OOB_CLEAR:
			error = ble_oob_clear(ctx, NULL);
			break;
		case IPC_SECURITY_RESOLV_ADD:
			error = ble_resolv_add(ctx, &addr, irk);
			break;
		case IPC_SECURITY_RESOLV_REMOVE:
			error = ble_resolv_remove(ctx, &addr);
			break;
		default:
			error = ble_resolv_clear(ctx);
			break;
		}
		ATF_REQUIRE_EQ(error, 0);
		read_exact(sp[1], hdr, sizeof(hdr));
		ipc_hdr_decode(hdr, &plen, &type, &domain);
		read_exact(sp[1], request, plen);
		ipc_op_prefix_decode(request, &request_id, &status, &flags);
		ATF_CHECK_EQ(type, IPC_T_OP_REQ);
		ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_SECURITY);
		ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE), opcode);
		if (opcode == IPC_SECURITY_OOB_INJECT_SC) {
			ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE + 12,
			    confirm, 16) == 0);
			ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE + 28,
			    random, 16) == 0);
		} else if (opcode == IPC_SECURITY_OOB_CLEAR)
			ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 12],
			    IPC_SECURITY_OOB_CLEAR_F_ALL);
		else if (opcode == IPC_SECURITY_RESOLV_ADD) {
			ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 12],
			    IPC_SECURITY_RESOLV_F_IRK);
			ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE + 16,
			    irk, 16) == 0);
		}
		ipc_op_prefix_encode(frame, request_id, IPC_ERR_NONE, 0);
		stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY,
		    frame, IPC_OP_PREFIX_SIZE);
		ATF_REQUIRE_EQ(ble_process(ctx), 0);
	}

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_advertising_ops);
ATF_TC_BODY(client_typed_advertising_ops, tc)
{
	ble_ctx_t *ctx;
	ble_adv_set_t *set;
	ble_adv_params_t params = { .mode = BLE_ADV_MODE_AUTO,
	    .type = BLE_ADV_TYPE_CONN_UND, .tx_power = 127 };
	const uint8_t data[] = { 2, 1, 6 };
	uint8_t hdr[IPC_HDR_SIZE], request[128], reply[IPC_OP_PREFIX_SIZE + 4];
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	ATF_REQUIRE_EQ(ble_set_adv_params(ctx, &params), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_ADV);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_ADV_SET_PARAMS);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 6], 7);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 8], BLE_PHY_1M);
	ipc_op_prefix_encode(reply, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, reply,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_REQUIRE_EQ(ble_set_name(ctx, "typed-name"), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_ADV_SET_NAME);
	ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE +
	    IPC_ADV_NAME_REQ_HDR_SIZE, "typed-name", 10) == 0);
	ipc_op_prefix_encode(reply, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, reply,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	ATF_REQUIRE_EQ(ble_set_adv_data(ctx, data, sizeof(data)), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_ADV_SET_DATA);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 4),
	    sizeof(data));
	ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE +
	    IPC_ADV_DATA_REQ_HDR_SIZE, data, sizeof(data)) == 0);
	ipc_op_prefix_encode(reply, request_id, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, domain, reply,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_process(ctx), 0);

	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 4, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_ADV_SET_CREATE);
	reply[IPC_OP_PREFIX_SIZE + 2] = 7;
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_ADV, reply,
	    sizeof(reply));
	ATF_REQUIRE_EQ(ble_adv_set_create(ctx, &set), 0);
	ATF_CHECK_EQ(ble_adv_set_handle(set), 7);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_ADV_SET_CREATE);

	ipc_op_prefix_encode(reply, 5, IPC_ERR_NONE, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_ADV, reply,
	    IPC_OP_PREFIX_SIZE);
	ble_adv_set_close(set);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_ADV_SET_HANDLE_REMOVE);

	ble_close(ctx);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(client_typed_snapshots_and_bond_records);
ATF_TC_BODY(client_typed_snapshots_and_bond_records, tc)
{
	ble_ctx_t *ctx;
	ble_connection_info_t conn;
	ble_bond_t bond;
	ble_resolv_entry_t resolv;
	ble_bond_record_t *record;
	const uint8_t *record_data;
	size_t record_len;
	uint8_t hdr[IPC_HDR_SIZE], request[IPC_MAX_PAYLOAD];
	uint8_t frame[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint8_t *body = frame + IPC_OP_PREFIX_SIZE;
	uint8_t exported[] = { 0xde, 0xad, 0xbe, 0xef };
	uint32_t plen, request_id;
	uint16_t type, domain, status, flags;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	stage_hello(sp[1], IPC_PROTO_VERSION, 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 1, 0, 0);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, 1);
	body[4] = 1;
	memcpy(body + 5, (const uint8_t[]){ 1, 2, 3, 4, 5, 6 }, 6);
	body[11] = 2;
	body[12] = 1;
	body[13] = IPC_GAP_CONN_F_ENCRYPTED |
	    IPC_GAP_CONN_F_AUTHENTICATED | IPC_GAP_CONN_F_PHY_VALID;
	body[14] = 16;
	body[15] = 2;
	body[16] = 1;
	body[17] = 3;
	ipc_put_le16(body + 18, 0x1234);
	ipc_put_le16(body + 20, 247);
	ipc_put_le16(body + 22, 24);
	ipc_put_le16(body + 24, 1);
	ipc_put_le16(body + 26, 200);
	strlcpy((char *)body + 28, "typed-peer", 64);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GAP, frame,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
	    IPC_GAP_CONNECTION_RECORD_SIZE);
	ATF_REQUIRE_EQ(ble_connections(ctx, &conn, 1), 1);
	ATF_CHECK_EQ(conn.handle, 0x1234);
	ATF_CHECK_EQ(conn.mtu, 247);
	ATF_CHECK_EQ(conn.adapter_index, 3);
	ATF_CHECK_EQ(conn.addr.adapter_index, 3);
	ATF_CHECK(conn.encrypted && conn.authenticated && conn.phy_valid);
	ATF_CHECK_STREQ(conn.name, "typed-peer");
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_GAP);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_GET_CONNECTIONS);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 2, 0, 0);
	ipc_put_le16(body, IPC_SECURITY_BOND_LIST);
	ipc_put_le16(body + 2, 1);
	body[4] = 1;
	memcpy(body + 5, (const uint8_t[]){ 6, 5, 4, 3, 2, 1 }, 6);
	body[11] = IPC_SECURITY_BOND_F_LTK | IPC_SECURITY_BOND_F_IRK |
	    IPC_SECURITY_BOND_F_SC;
	strlcpy((char *)body + 12, "bonded-peer", 64);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_BOND_REPLY_HDR_SIZE +
	    IPC_SECURITY_BOND_RECORD_SIZE);
	ATF_REQUIRE_EQ(ble_bond_list(ctx, &bond, 1), 1);
	ATF_CHECK(bond.has_ltk && bond.has_irk && bond.is_sc);
	ATF_CHECK_STREQ(bond.name, "bonded-peer");
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 3, 0, 0);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_LIST);
	ipc_put_le16(body + 2, 1);
	body[4] = 0;
	memcpy(body + 5, (const uint8_t[]){ 9, 8, 7, 6, 5, 4 }, 6);
	body[11] = IPC_SECURITY_RESOLV_F_IN_LIST;
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
	    IPC_SECURITY_RESOLV_RECORD_SIZE);
	ATF_REQUIRE_EQ(ble_resolv_entries(ctx, &resolv, 1), 1);
	ATF_CHECK(resolv.in_controller);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	memset(frame, 0, sizeof(frame));
	ipc_op_prefix_encode(frame, 4, 0, 0);
	ipc_put_le16(body, IPC_SECURITY_BOND_EXPORT);
	ipc_put_le16(body + 2, sizeof(exported));
	memcpy(body + IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE, exported,
	    sizeof(exported));
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE +
	    sizeof(exported));
	record = ble_bond_export(ctx, &bond.addr);
	ATF_REQUIRE(record != NULL);
	record_data = ble_bond_record_data(record, &record_len);
	ATF_REQUIRE_EQ(record_len, sizeof(exported));
	ATF_CHECK(memcmp(record_data, exported, sizeof(exported)) == 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	read_exact(sp[1], request, plen);

	ipc_op_prefix_encode(frame, 5, 0, 0);
	stage_raw_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_SECURITY, frame,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(ble_bond_import(ctx, record), 0);
	read_exact(sp[1], hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &plen, &type, &domain);
	ATF_REQUIRE(plen <= sizeof(request));
	read_exact(sp[1], request, plen);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 5);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_SECURITY_BOND_IMPORT);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12),
	    sizeof(exported));
	ATF_CHECK(memcmp(request + IPC_OP_PREFIX_SIZE +
	    IPC_SECURITY_BOND_IMPORT_REQ_HDR_SIZE, exported,
	    sizeof(exported)) == 0);

	ble_bond_record_free(record);
	ble_close(ctx);
	close(sp[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, client_handshake_match);
	ATF_TP_ADD_TC(tp, client_handshake_version_mismatch);
	ATF_TP_ADD_TC(tp, client_handshake_rejected);
	ATF_TP_ADD_TC(tp, client_handshake_short_sendmsg);
	ATF_TP_ADD_TC(tp, client_correlated_control);
	ATF_TP_ADD_TC(tp, client_correlated_status_and_adapter_caps);
	ATF_TP_ADD_TC(tp, client_sync_query_rejects_bad_replies);
	ATF_TP_ADD_TC(tp, client_adapter_caps_rejects_bad_results);
	ATF_TP_ADD_TC(tp, client_unknown_accepted_capability_rejected);
	ATF_TP_ADD_TC(tp, client_typed_disconnect);
	ATF_TP_ADD_TC(tp, client_typed_connection_controls);
	ATF_TP_ADD_TC(tp, client_typed_connect);
	ATF_TP_ADD_TC(tp, client_typed_connect_name);
	ATF_TP_ADD_TC(tp, client_typed_connection_lifecycle);
	ATF_TP_ADD_TC(tp, client_typed_scan);
	ATF_TP_ADD_TC(tp, client_typed_gatt_io);
	ATF_TP_ADD_TC(tp, client_gatt_reads_out_of_order);
	ATF_TP_ADD_TC(tp, client_typed_gatt_discover);
	ATF_TP_ADD_TC(tp, client_typed_gatt_local_value_ops);
	ATF_TP_ADD_TC(tp, client_typed_gatt_database_ops);
	ATF_TP_ADD_TC(tp, client_typed_gatt_server_events);
	ATF_TP_ADD_TC(tp, client_typed_security_ops);
	ATF_TP_ADD_TC(tp, client_handshake_timeout);
	ATF_TP_ADD_TC(tp, client_error_taxonomy);
	ATF_TP_ADD_TC(tp, client_typed_security_event);
	ATF_TP_ADD_TC(tp, client_typed_security_policy);
	ATF_TP_ADD_TC(tp, client_typed_security_oob_resolving);
	ATF_TP_ADD_TC(tp, client_typed_advertising_ops);
	ATF_TP_ADD_TC(tp, client_typed_snapshots_and_bond_records);

	return (atf_no_error());
}
