/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/* Typed-only libble tests not duplicated by ipc_client_test. */

#include <sys/socket.h>

#include <atf-c.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "ble.h"
#include "ipc_proto.h"

static ble_ctx_t *
make_mock_ctx(int *daemon_fd)
{
	ble_ctx_t *ctx;
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	*daemon_fd = sp[1];
	return (ctx);
}

static void
send_frame(int fd, uint16_t type, uint16_t arg, const void *payload,
    size_t payload_len)
{
	uint8_t hdr[IPC_HDR_SIZE];

	ipc_hdr_encode(hdr, (uint32_t)payload_len, type, arg);
	ATF_REQUIRE_EQ(send(fd, hdr, sizeof(hdr), 0), (ssize_t)sizeof(hdr));
	if (payload_len != 0)
		ATF_REQUIRE_EQ(send(fd, payload, payload_len, 0),
		    (ssize_t)payload_len);
}

static void
read_exact(int fd, void *buf, size_t len)
{
	uint8_t *p;
	ssize_t n;

	p = buf;
	while (len != 0) {
		n = recv(fd, p, len, 0);
		ATF_REQUIRE(n > 0);
		p += n;
		len -= (size_t)n;
	}
}

static void
read_frame(int fd, uint16_t *type, uint16_t *arg, uint8_t *payload,
    size_t payload_size, size_t *payload_len)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t len;

	read_exact(fd, hdr, sizeof(hdr));
	ipc_hdr_decode(hdr, &len, type, arg);
	ATF_REQUIRE(len <= payload_size);
	read_exact(fd, payload, len);
	*payload_len = len;
}

static void
enable_features(ble_ctx_t *ctx, int daemon_fd, uint32_t feature_mask)
{
	uint8_t features[IPC_HELLO_FEATURES_SIZE];
	uint8_t payload[64];
	uint16_t type, arg;
	size_t payload_len;

	ipc_put_le32(features, feature_mask);
	send_frame(daemon_fd, IPC_T_HELLO, IPC_PROTO_VERSION,
	    features, sizeof(features));
	ATF_REQUIRE_EQ(ble_handshake(ctx), 0);
	read_frame(daemon_fd, &type, &arg, payload, sizeof(payload),
	    &payload_len);
	ATF_CHECK_EQ(type, IPC_T_HELLO);
	ATF_CHECK_EQ(arg, IPC_PROTO_VERSION);
	ATF_CHECK_EQ(payload_len, IPC_HELLO_FEATURES_SIZE);
	ATF_CHECK_EQ(ipc_get_le32(payload), IPC_FEATURE_EVENTS |
	    IPC_FEATURE_FDPASS);
}

static void
enable_fdpass(ble_ctx_t *ctx, int daemon_fd)
{

	enable_features(ctx, daemon_fd, IPC_FEATURE_FDPASS);
}

static void
send_fd(int fd, int passed_fd)
{
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char control[CMSG_SPACE(sizeof(int))];
	char byte;

	memset(&msg, 0, sizeof(msg));
	byte = 0;
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	memset(control, 0, sizeof(control));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &passed_fd, sizeof(passed_fd));
	ATF_REQUIRE_EQ(sendmsg(fd, &msg, 0), 1);
}

struct delayed_fds {
	int socket_fd;
	int passed_fd;
	unsigned count;
};

static void *
send_fds_delayed(void *arg)
{
	struct delayed_fds *fds = arg;

	/* Let the framed reply be consumed before its SCM_RIGHTS handout. */
	usleep(10000);
	for (unsigned i = 0; i < fds->count; i++)
		send_fd(fds->socket_fd, fds->passed_fd);
	return (NULL);
}

static void
send_sync_reply_id(int fd, uint32_t request_id, uint16_t domain,
    const void *body, size_t body_len)
{
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];

	ATF_REQUIRE(body_len <= IPC_MAX_PAYLOAD);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	if (body_len != 0)
		memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	send_frame(fd, IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE + body_len);
}

static void
send_sync_reply(int fd, uint16_t domain, const void *body, size_t body_len)
{

	send_sync_reply_id(fd, 1, domain, body, body_len);
}

ATF_TC_WITHOUT_HEAD(acquire_notify_typed);
ATF_TC_BODY(acquire_notify_typed, tc)
{
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	ble_ctx_t *ctx;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
	uint32_t request_id;
	uint16_t type, domain, status, flags, mtu;
	size_t request_len;
	int channel[2], daemon_fd, fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) == 0);
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_GATT_ACQUIRE_NOTIFY);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, 185);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, reply,
	    sizeof(reply));
	send_fd(daemon_fd, channel[1]);

	fd = -1;
	mtu = 0;
	ATF_REQUIRE_EQ(ble_acquire_notify(ctx, &addr, 0x0042, &fd, &mtu), 0);
	ATF_CHECK_EQ(mtu, 185);
	ATF_REQUIRE(fd >= 0);
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_REQUIRE_EQ(request_len, sizeof(request));
	ATF_CHECK_EQ(type, IPC_T_OP_REQ);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_GATT);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 1);
	ATF_CHECK_EQ(status, 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_GATT_ACQUIRE_NOTIFY);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12), 0x0042);

	close(fd);
	close(channel[0]);
	close(channel[1]);
	close(daemon_fd);
	ble_close(ctx);

}

ATF_TC_WITHOUT_HEAD(acquire_requires_fdpass);
ATF_TC_BODY(acquire_requires_fdpass, tc)
{
	ble_addr_t addr = { 0 };
	ble_ctx_t *ctx;
	uint16_t mtu;
	int daemon_fd, fd;

	ctx = make_mock_ctx(&daemon_fd);
	fd = -1;
	mtu = 0;
	ATF_CHECK_EQ(ble_acquire_notify(ctx, &addr, 1, &fd, &mtu), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PERM);
	ATF_CHECK_EQ(ble_acquire_write(ctx, &addr, 1, &fd), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_PERM);
	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(acquire_write_typed);
ATF_TC_BODY(acquire_write_typed, tc)
{
	ble_addr_t addr = { .addr = { 6, 5, 4, 3, 2, 1 }, .addr_type = 1 };
	ble_ctx_t *ctx;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_GATT_REQ_SIZE];
	uint16_t type, domain;
	size_t request_len;
	int channel[2], daemon_fd, fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) == 0);
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_GATT_ACQUIRE_WRITE);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, 0);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, reply,
	    sizeof(reply));
	send_fd(daemon_fd, channel[1]);

	fd = -1;
	ATF_REQUIRE_EQ(0, ble_acquire_write(ctx, &addr, 0x0043, &fd));
	ATF_REQUIRE(fd >= 0);
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_T_OP_REQ, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_GATT, domain);
	ATF_CHECK_EQ(IPC_GATT_ACQUIRE_WRITE,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ(0x0043,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12));

	close(fd);
	close(channel[0]);
	close(channel[1]);
	close(daemon_fd);
	ble_close(ctx);

}

ATF_TC_WITHOUT_HEAD(acquire_coc_and_ecbfc_typed);
ATF_TC_BODY(acquire_coc_and_ecbfc_typed, tc)
{
	ble_addr_t addr = {
	    .addr = { 1, 3, 5, 7, 9, 11 }, .addr_type = 1,
	    .adapter_index = 2
	};
	ble_ctx_t *ctx;
	ble_ecbfc_session_t *session;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_L2CAP_ACQUIRE_REPLY_SIZE];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_L2CAP_REQ_SIZE];
	uint16_t type, domain;
	size_t request_len;
	int channel[2], daemon_fd, fd, taken;
	pthread_t sender;
	struct delayed_fds fds;

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel));
	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_L2CAP_ACQUIRE_COC);
	reply[IPC_OP_PREFIX_SIZE + 2] = 1;
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4, 512);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_L2CAP, reply,
	    sizeof(reply));
	fds = (struct delayed_fds){ daemon_fd, channel[1], 1 };
	ATF_REQUIRE_EQ(0, pthread_create(&sender, NULL, send_fds_delayed, &fds));
	fd = -1;
	ATF_REQUIRE_EQ_MSG(0, ble_acquire_coc(ctx, &addr, 0x0081, &fd),
	    "ble error %d: %s", ble_errno(ctx), ble_strerror(ctx));
	ATF_REQUIRE_EQ(0, pthread_join(sender, NULL));
	ATF_REQUIRE(fd >= 0);
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_T_OP_REQ, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_L2CAP, domain);
	ATF_CHECK_EQ(IPC_L2CAP_ACQUIRE_COC,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ(0x0081,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12));
	ATF_CHECK_EQ(2, request[IPC_OP_PREFIX_SIZE + 16]);
	close(fd);
	close(channel[0]);
	close(channel[1]);
	close(daemon_fd);
	ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel));
	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_L2CAP_ACQUIRE_COC);
	reply[IPC_OP_PREFIX_SIZE + 2] = 3;
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 4, 100);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 6, 200);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 8, 300);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_L2CAP, reply,
	    sizeof(reply));
	fds = (struct delayed_fds){ daemon_fd, channel[1], 3 };
	ATF_REQUIRE_EQ(0, pthread_create(&sender, NULL, send_fds_delayed, &fds));
	session = NULL;
	ATF_REQUIRE_EQ_MSG(0, ble_ecbfc_session_open(ctx, &addr, 0x0083, 3,
	    &session), "ble error %d: %s", ble_errno(ctx),
	    ble_strerror(ctx));
	ATF_REQUIRE_EQ(0, pthread_join(sender, NULL));
	ATF_REQUIRE(session != NULL);
	ATF_CHECK_EQ(3, ble_ecbfc_session_count(session));
	ATF_CHECK_EQ(100, ble_ecbfc_session_omtu(session, 0));
	ATF_CHECK_EQ(200, ble_ecbfc_session_omtu(session, 1));
	ATF_CHECK_EQ(300, ble_ecbfc_session_omtu(session, 2));
	ATF_CHECK(ble_ecbfc_session_fd(session, 0) >= 0);
	taken = ble_ecbfc_session_take_fd(session, 1);
	ATF_REQUIRE(taken >= 0);
	ATF_CHECK_EQ(-1, ble_ecbfc_session_fd(session, 1));
	ATF_CHECK_EQ(0, ble_ecbfc_session_count(NULL));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_fd(NULL, 0));
	ATF_CHECK_EQ(0, ble_ecbfc_session_omtu(NULL, 0));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_take_fd(NULL, 0));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_reconfigure(ctx, NULL, 128, 64));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_reconfigure(ctx, session, 63, 64));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_reconfigure(ctx, session, 64, 63));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	/* AF_UNIX stand-ins reject the real SOL_L2CAP reconfiguration option. */
	ATF_CHECK_EQ(-1, ble_ecbfc_session_reconfigure(ctx, session, 256, 128));
	ATF_CHECK_EQ(BLE_ERR_SOCKET, ble_errno(ctx));
	/* Once ownership of every channel is transferred, no socket remains. */
	fd = ble_ecbfc_session_take_fd(session, 0);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	fd = ble_ecbfc_session_take_fd(session, 2);
	ATF_REQUIRE(fd >= 0);
	close(fd);
	ATF_CHECK_EQ(0, ble_ecbfc_session_reconfigure(ctx, session, 256, 128));
	close(taken);
	ble_ecbfc_session_close(session);
	ble_ecbfc_session_close(NULL);
	close(channel[0]);
	close(channel[1]);
	close(daemon_fd);
	ble_close(ctx);

	/* Public validation and malformed broker replies fail without fd leaks. */
	ctx = make_mock_ctx(&daemon_fd);
	session = NULL;
	fd = -1;
	ATF_CHECK_EQ(-1, ble_acquire_coc(ctx, NULL, 1, &fd));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_acquire_coc(ctx, &addr, 1, NULL));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_acquire_coc(ctx, &addr, 1, &fd));
	ATF_CHECK_EQ(BLE_ERR_PERM, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_open(ctx, &addr, 1, 0,
	    &session));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_open(ctx, &addr, 1, 6,
	    &session));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_open(ctx, &addr, 1, 1,
	    &session));
	ATF_CHECK_EQ(BLE_ERR_PERM, ble_errno(ctx));
	close(daemon_fd);
	ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	memset(reply, 0, sizeof(reply));
	ipc_op_prefix_encode(reply, 1, IPC_ERR_NONE, 0);
	ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, IPC_L2CAP_ACQUIRE_COC);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_L2CAP, reply,
	    sizeof(reply));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_open(ctx, &addr, 1, 2,
	    &session));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(scan_filter_validation_and_encoding);
ATF_TC_BODY(scan_filter_validation_and_encoding, tc)
{
	ble_ctx_t *ctx;
	ble_scan_params_t params;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_REQ_SIZE];
	uint16_t type, domain;
	size_t request_len;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	memset(&params, 0, sizeof(params));
	params.interval = 3;
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	params.interval = 0x4001;
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	params.interval = 0x10;
	params.window = 3;
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	params.window = 0x4001;
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	params.window = 0x11;
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	params.window = 0x10;
	strlcpy(params.name_sub, "bad name", sizeof(params.name_sub));
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));
	strlcpy(params.name_sub, "bad\177name", sizeof(params.name_sub));
	ATF_CHECK_EQ(-1, ble_scan_filtered(ctx, &params, NULL, NULL));

	/* An all-zero filter maps RSSI zero to the documented ANY sentinel. */
	memset(&params, 0, sizeof(params));
	ATF_REQUIRE_EQ(0, ble_scan_filtered(ctx, &params, NULL, NULL));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_T_OP_REQ, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_GAP, domain);
	ATF_CHECK_EQ(IPC_GAP_SCAN, ipc_get_le16(request + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ((uint8_t)BLE_RSSI_ANY, request[IPC_OP_PREFIX_SIZE + 10]);

	/* Every optional flag and filter is serialized into its fixed field. */
	memset(&params, 0, sizeof(params));
	params.interval = 0x20;
	params.window = 0x10;
	params.uuid16 = 0x180d;
	params.rssi_min = -70;
	params.passive = true;
	params.accept_list = true;
	params.no_dedup = true;
	strlcpy(params.name_sub, "Heart", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, ble_scan_filtered(ctx, &params, NULL, NULL));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_GAP_SCAN_F_PASSIVE | IPC_GAP_SCAN_F_ACCEPT_LIST |
	    IPC_GAP_SCAN_F_NO_DEDUP,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 2));
	ATF_CHECK_EQ(0x20, ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 4));
	ATF_CHECK_EQ(0x10, ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 6));
	ATF_CHECK_EQ(0x180d, ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 8));
	ATF_CHECK_EQ((uint8_t)-70, request[IPC_OP_PREFIX_SIZE + 10]);
	ATF_CHECK_STREQ((char *)request + IPC_OP_PREFIX_SIZE + 12, "Heart");

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(acquire_reply_errors);
ATF_TC_BODY(acquire_reply_errors, tc)
{
	static const struct {
		uint32_t request_id;
		uint16_t status;
		uint16_t opcode;
		int expected_error;
	} cases[] = {
		{ 1, IPC_ERR_NOT_FOUND, IPC_GATT_ACQUIRE_WRITE,
		    BLE_ERR_NOTFOUND },
		{ 2, IPC_ERR_NONE, IPC_GATT_ACQUIRE_WRITE, BLE_ERR_PROTO },
		{ 1, IPC_ERR_NONE, IPC_GATT_ACQUIRE_NOTIFY, BLE_ERR_PROTO },
	};
	ble_addr_t addr = { 0 };
	ble_ctx_t *ctx;
	uint8_t reply[IPC_OP_PREFIX_SIZE + IPC_GATT_ACQUIRE_REPLY_SIZE];
	size_t i;
	int daemon_fd, fd;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ctx = make_mock_ctx(&daemon_fd);
		enable_fdpass(ctx, daemon_fd);
		ipc_op_prefix_encode(reply, cases[i].request_id,
		    cases[i].status, 0);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE, cases[i].opcode);
		ipc_put_le16(reply + IPC_OP_PREFIX_SIZE + 2, 0);
		send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT,
		    reply, sizeof(reply));
		fd = -1;
		ATF_CHECK_EQ(-1, ble_acquire_write(ctx, &addr, 1, &fd));
		ATF_CHECK_EQ(cases[i].expected_error, ble_errno(ctx));
		ATF_CHECK_EQ(-1, fd);
		close(daemon_fd);
		ble_close(ctx);
	}

	/* Acquisition is exclusive with ordinary correlated operations. */
	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE_EQ(0, ble_advertise(ctx, true));
	fd = -1;
	ATF_CHECK_EQ(-1, ble_acquire_write(ctx, &addr, 1, &fd));
	ATF_CHECK_EQ(BLE_ERR_BUSY, ble_errno(ctx));
	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(addr_format);
ATF_TC_BODY(addr_format, tc)
{
	ble_addr_t addr = { .addr = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa } };
	char text[18];

	ATF_CHECK_STREQ(ble_addr_str(&addr, text), "aa:bb:cc:dd:ee:ff");
}

ATF_TC_WITHOUT_HEAD(path_loss_serialization);
ATF_TC_BODY(path_loss_serialization, tc)
{
	ble_addr_t addr = {
		.addr = { 1, 2, 3, 4, 5, 6 },
		.addr_type = 1,
		.adapter_index = 3,
	};
	ble_ctx_t *ctx;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_GAP_PATH_LOSS_REQ_SIZE];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	ATF_REQUIRE_EQ(ble_path_loss_reporting(ctx, &addr, 0x20, 0x02,
	    0x60, 0x04, 0x1234, true), 0);
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_REQUIRE_EQ(request_len, sizeof(request));
	ATF_CHECK_EQ(type, IPC_T_OP_REQ);
	ATF_CHECK_EQ(domain, IPC_OP_DOMAIN_GAP);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 1);
	ATF_CHECK_EQ(status, 0);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE),
	    IPC_GAP_PATH_LOSS);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 2), 0);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 4], addr.addr_type);
	ATF_CHECK_EQ(memcmp(request + IPC_OP_PREFIX_SIZE + 5, addr.addr,
	    sizeof(addr.addr)), 0);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 11], addr.adapter_index);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 12], 0x20);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 13], 0x02);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 14], 0x60);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 15], 0x04);
	ATF_CHECK_EQ(ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 16), 0x1234);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 18], 1);
	ATF_CHECK_EQ(request[IPC_OP_PREFIX_SIZE + 19], 0);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(path_loss_invalid_inputs);
ATF_TC_BODY(path_loss_invalid_inputs, tc)
{
	ble_addr_t addr = { 0 };
	ble_ctx_t *ctx;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(ble_path_loss_reporting(ctx, NULL, 0x20, 0, 0x60, 0,
	    1, true), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);
	ATF_CHECK_EQ(ble_path_loss_reporting(ctx, &addr, 0x61, 0, 0x60, 0,
	    1, false), -1);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(public_api_command_families);
ATF_TC_BODY(public_api_command_families, tc)
{
	ble_addr_t addr = { 0 };
	ble_ctx_t *ctx;
	uint8_t payload[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint8_t scan_rsp[] = { 2, 0x0a, 0xec };
	uint16_t type, domain;
	size_t payload_len;
	int daemon_fd, i;

	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(ble_gatt_begin(ctx), 0);
	ATF_CHECK_EQ(ble_gatt_commit(ctx), 0);
	ATF_CHECK_EQ(ble_gatt_rollback(ctx), 0);
	ATF_CHECK_EQ(ble_advertise(ctx, true), 0);
	ATF_CHECK_EQ(ble_adapter_power(ctx, 3, false), 0);
	ATF_CHECK_EQ(ble_set_discoverable(ctx, true, 60, true), 0);
	ATF_CHECK_EQ(ble_set_pairable(ctx, false), 0);
	ATF_CHECK_EQ(ble_set_scan_response(ctx, scan_rsp, sizeof(scan_rsp)), 0);
	ATF_CHECK_EQ(ble_set_privacy(ctx, true), 0);
	ATF_CHECK_EQ(ble_set_mitm(ctx, true), 0);
	ATF_CHECK_EQ(ble_set_bondable(ctx, true), 0);
	ATF_CHECK_EQ(ble_set_sc_mode(ctx, BLE_SC_ONLY), 0);
	ATF_CHECK_EQ(ble_set_keypress(ctx, true), 0);
	ATF_CHECK_EQ(ble_set_io_capability(ctx, BLE_IO_KEYBOARD_DISPLAY), 0);
	ATF_CHECK_EQ(ble_set_min_security(ctx, BLE_SEC_SC), 0);
	ATF_CHECK_EQ(ble_set_min_key_size(ctx, 16), 0);
	ATF_CHECK_EQ(ble_set_key_distribution(ctx,
	    BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID | BLE_KEY_DIST_SIGN), 0);
	ATF_CHECK_EQ(ble_set_rpa_timeout(ctx, 3600), 0);
	ATF_CHECK_EQ(ble_oob_clear(ctx, NULL), 0);
	ATF_CHECK_EQ(ble_resolv_add(ctx, &addr, NULL), 0);
	ATF_CHECK_EQ(ble_resolv_remove(ctx, &addr), 0);
	ATF_CHECK_EQ(ble_resolv_clear(ctx), 0);

	/* Every successful public call above must emit one typed operation. */
	for (i = 0; i < 22; i++) {
		read_frame(daemon_fd, &type, &domain, payload, sizeof(payload),
		    &payload_len);
		ATF_CHECK_EQ(type, IPC_T_OP_REQ);
		ATF_CHECK(domain == IPC_OP_DOMAIN_CTL ||
		    domain == IPC_OP_DOMAIN_ADV ||
		    domain == IPC_OP_DOMAIN_SECURITY);
		ATF_CHECK(payload_len >= IPC_OP_PREFIX_SIZE);
	}

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(public_api_validation_families);
ATF_TC_BODY(public_api_validation_families, tc)
{
	ble_addr_t addr = { 0 };
	ble_security_info_t security_info;
	ble_security_policy_t policy = {
		.io_cap = BLE_IO_NO_INPUT_NO_OUTPUT,
		.sc_mode = BLE_SC_ON,
		.min_security = BLE_SEC_ENC,
		.min_key_size = 7,
		.key_dist = BLE_KEY_DIST_ENC,
	};
	ble_resolv_entry_t entries[1];
	uint8_t oob[16] = { 0 };
	ble_ctx_t *ctx;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(ble_set_discoverable(ctx, true, 3601, false), -1);
	ATF_CHECK_EQ(ble_set_scan_response(ctx, NULL, 1), -1);
	ATF_CHECK_EQ(ble_set_sc_mode(ctx, (ble_sc_mode_t)99), -1);
	ATF_CHECK_EQ(ble_set_io_capability(ctx, (ble_io_cap_t)99), -1);
	ATF_CHECK_EQ(ble_set_min_security(ctx, (ble_sec_level_t)99), -1);
	ATF_CHECK_EQ(ble_set_min_key_size(ctx, 6), -1);
	ATF_CHECK_EQ(ble_set_min_key_size(ctx, 17), -1);
	ATF_CHECK_EQ(ble_set_key_distribution(ctx, 0x80), -1);
	ATF_CHECK_EQ(ble_set_rpa_timeout(ctx, 0), -1);
	ATF_CHECK_EQ(ble_set_rpa_timeout(ctx, 3601), -1);
	ATF_CHECK_EQ(ble_set_security_policy(ctx, NULL), -1);
	policy.io_cap = (ble_io_cap_t)99;
	ATF_CHECK_EQ(ble_set_security_policy(ctx, &policy), -1);
	policy.io_cap = BLE_IO_NO_INPUT_NO_OUTPUT;
	policy.sc_mode = (ble_sc_mode_t)99;
	ATF_CHECK_EQ(ble_set_security_policy(ctx, &policy), -1);
	policy.sc_mode = BLE_SC_ON;
	policy.min_security = (ble_sec_level_t)99;
	ATF_CHECK_EQ(ble_set_security_policy(ctx, &policy), -1);
	policy.min_security = BLE_SEC_ENC;
	policy.min_key_size = 6;
	ATF_CHECK_EQ(ble_set_security_policy(ctx, &policy), -1);
	policy.min_key_size = 7;
	policy.key_dist = 0x80;
	ATF_CHECK_EQ(ble_set_security_policy(ctx, &policy), -1);
	ATF_CHECK_EQ(ble_get_security_policy(ctx, NULL), -1);
	ATF_CHECK_EQ(ble_get_security_info(ctx, NULL, &security_info), -1);
	ATF_CHECK_EQ(ble_get_security_info(ctx, &addr, NULL), -1);
	ATF_CHECK_EQ(ble_oob_sc_generate(ctx, NULL), -1);
	ATF_CHECK_EQ(ble_oob_inject_sc(ctx, NULL, oob, oob), -1);
	ATF_CHECK_EQ(ble_oob_inject_sc(ctx, &addr, NULL, oob), -1);
	ATF_CHECK_EQ(ble_oob_inject_legacy(ctx, NULL, oob), -1);
	ATF_CHECK_EQ(ble_oob_inject_legacy(ctx, &addr, NULL), -1);
	ATF_CHECK_EQ(ble_resolv_add(ctx, NULL, oob), -1);
	ATF_CHECK_EQ(ble_resolv_remove(ctx, NULL), -1);
	ATF_CHECK_EQ(ble_resolv_entries(ctx, NULL, 1), -1);
	ATF_CHECK_EQ(ble_resolv_entries(ctx, entries, 0), -1);
	ATF_CHECK(ble_bond_export(ctx, NULL) == NULL);
	ATF_CHECK_EQ(ble_bond_import(ctx, NULL), -1);
	ATF_CHECK(ble_bond_record_data(NULL, NULL) == NULL);
	ATF_CHECK(ble_bond_record_from_data(NULL, 1) == NULL);
	ATF_CHECK(ble_bond_record_from_data(oob, 0) == NULL);
	ble_bond_record_free(NULL);
	ATF_CHECK_EQ(ble_errno(ctx), BLE_ERR_INVAL);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(public_api_utilities_and_callbacks);
ATF_TC_BODY(public_api_utilities_and_callbacks, tc)
{
	ble_addr_t addr;
	ble_bond_record_t *record;
	ble_ctx_t *ctx;
	const void *record_data;
	const uint8_t serialized[] = { 1, 2, 3, 4 };
	size_t record_len;
	int daemon_fd;

	ATF_CHECK_EQ(ble_addr_parse("11:22:33:44:55:66", 1, &addr), 0);
	ATF_CHECK_EQ(addr.addr_type, 1);
	ATF_CHECK_EQ(ble_addr_parse(NULL, 0, &addr), -1);
	ATF_CHECK_EQ(ble_addr_parse("bad", 0, &addr), -1);
	ATF_CHECK_EQ(ble_addr_parse("11:22:33:44:55:66", 2, &addr), -1);
	ATF_CHECK_EQ(ble_addr_parse("11:22:33:44:55:66", 0, NULL), -1);
	record = ble_bond_record_from_data(serialized, sizeof(serialized));
	ATF_REQUIRE(record != NULL);
	record_data = ble_bond_record_data(record, &record_len);
	ATF_CHECK_EQ(sizeof(serialized), record_len);
	ATF_CHECK_EQ(0, memcmp(serialized, record_data, record_len));
	ble_bond_record_free(record);

	ctx = make_mock_ctx(&daemon_fd);
	ble_on_write(ctx, NULL, &addr);
	ble_on_read_request(ctx, NULL, &addr);
	ble_on_authorize(ctx, NULL, &addr);
	ble_on_passkey_display(ctx, NULL, &addr);
	ble_on_passkey_input(ctx, NULL, &addr);
	ble_on_keypress(ctx, NULL, &addr);
	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(security_sync_query_matrix);
ATF_TC_BODY(security_sync_query_matrix, tc)
{
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	ble_bond_record_t *record;
	ble_ctx_t *ctx;
	ble_oob_sc_t oob;
	ble_resolv_entry_t entry;
	ble_security_info_t info;
	ble_security_policy_t policy;
	uint8_t body[IPC_SECURITY_OOB_REPLY_SIZE];
	const void *data;
	size_t len;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_POLICY_REPLY_SIZE);
	ipc_put_le16(body, IPC_SECURITY_GET_POLICY);
	body[2] = 1; body[3] = 1; body[4] = BLE_SC_ONLY;
	body[5] = 1; body[6] = BLE_IO_KEYBOARD_DISPLAY;
	body[7] = BLE_SEC_SC; body[8] = 16;
	body[9] = BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID;
	ipc_put_le16(body + 10, 900);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_POLICY_REPLY_SIZE);
	ATF_REQUIRE_EQ(0, ble_get_security_policy(ctx, &policy));
	ATF_CHECK(policy.mitm && policy.bonding && policy.keypress);
	ATF_CHECK_EQ(900, policy.rpa_timeout);
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_INFO_REPLY_SIZE);
	ipc_put_le16(body, IPC_SECURITY_GET_INFO);
	body[2] = addr.addr_type;
	memcpy(body + 3, addr.addr, sizeof(addr.addr));
	body[9] = 16; body[10] = 4;
	body[11] = IPC_SECURITY_INFO_F_ENCRYPTED |
	    IPC_SECURITY_INFO_F_AUTHENTICATED | IPC_SECURITY_INFO_F_SC |
	    IPC_SECURITY_INFO_F_BONDED;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_INFO_REPLY_SIZE);
	ATF_REQUIRE_EQ(0, ble_get_security_info(ctx, &addr, &info));
	ATF_CHECK(info.encrypted && info.authenticated &&
	    info.secure_connections && info.bonded);
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0x5a, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_OOB_GENERATE);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body, sizeof(body));
	ATF_REQUIRE_EQ(0, ble_oob_sc_generate(ctx, &oob));
	ATF_CHECK_EQ(0, memcmp(oob.confirm, body + 2, sizeof(oob.confirm)));
	ATF_CHECK_EQ(0, memcmp(oob.pkx, body + 34, sizeof(oob.pkx)));
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
	    IPC_SECURITY_RESOLV_RECORD_SIZE);
	ipc_put_le16(body, IPC_SECURITY_RESOLV_LIST);
	ipc_put_le16(body + 2, 1);
	body[4] = addr.addr_type;
	memcpy(body + 5, addr.addr, sizeof(addr.addr));
	body[11] = IPC_SECURITY_RESOLV_F_IN_LIST;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_RESOLV_REPLY_HDR_SIZE + IPC_SECURITY_RESOLV_RECORD_SIZE);
	ATF_REQUIRE_EQ(1, ble_resolv_entries(ctx, &entry, 1));
	ATF_CHECK(entry.in_controller);
	ATF_CHECK_EQ(0, memcmp(entry.addr.addr, addr.addr, sizeof(addr.addr)));
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, 8);
	ipc_put_le16(body, IPC_SECURITY_BOND_EXPORT);
	ipc_put_le16(body + 2, 4);
	memcpy(body + 4, "bond", 4);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body, 8);
	record = ble_bond_export(ctx, &addr);
	ATF_REQUIRE(record != NULL);
	data = ble_bond_record_data(record, &len);
	ATF_CHECK_EQ(4u, len);
	ATF_CHECK_EQ(0, memcmp(data, "bond", 4));
	ble_bond_record_free(record);
	close(daemon_fd); ble_close(ctx);
}

struct event_matrix_state {
	int notify_calls;
	int display_calls;
	int input_calls;
	int keypress_calls;
	int cis_request_calls;
	int iso_established_calls;
	uint16_t handle;
	uint16_t mtu;
	uint32_t passkey;
	uint8_t keypress;
	uint8_t cig_id;
	uint8_t cis_id;
	uint8_t adapter_index;
	uint8_t sec_adapter_index;
	uint8_t sec_addr_type;
	uint8_t value[4];
	uint16_t value_len;
};

static void
record_notification(const ble_addr_t *addr __unused, uint16_t handle,
    const uint8_t *value, uint16_t len, void *arg)
{
	struct event_matrix_state *state = arg;

	state->notify_calls++;
	state->handle = handle;
	state->value_len = len;
	memcpy(state->value, value, len);
}

static void
record_display(const ble_addr_t *addr, uint32_t passkey, void *arg)
{
	struct event_matrix_state *state = arg;

	state->display_calls++;
	state->passkey = passkey;
	state->sec_adapter_index = addr->adapter_index;
	state->sec_addr_type = addr->addr_type;
}

static void
record_input(const ble_addr_t *addr, void *arg)
{
	struct event_matrix_state *state = arg;

	state->input_calls++;
	state->sec_adapter_index = addr->adapter_index;
	state->sec_addr_type = addr->addr_type;
}

static void
record_keypress(const ble_addr_t *addr, uint8_t type, void *arg)
{
	struct event_matrix_state *state = arg;

	state->keypress_calls++;
	state->keypress = type;
	state->sec_adapter_index = addr->adapter_index;
	state->sec_addr_type = addr->addr_type;
}

static void
record_cis_request(const ble_addr_t *addr, uint16_t handle,
    uint8_t cig_id, uint8_t cis_id, void *arg)
{
	struct event_matrix_state *state = arg;

	state->cis_request_calls++;
	state->handle = handle;
	state->cig_id = cig_id;
	state->cis_id = cis_id;
	state->adapter_index = addr->adapter_index;
}

static void
record_iso_established(const ble_addr_t *addr, uint16_t handle,
    uint16_t mtu, void *arg)
{
	struct event_matrix_state *state = arg;

	state->iso_established_calls++;
	state->handle = handle;
	state->mtu = mtu;
	state->adapter_index = addr->adapter_index;
}

ATF_TC_WITHOUT_HEAD(typed_event_callback_matrix);
ATF_TC_BODY(typed_event_callback_matrix, tc)
{
	ble_addr_t addr = {
		.addr = { 1, 2, 3, 4, 5, 6 },
		.addr_type = 1,
		.adapter_index = 2,
	};
	ble_ctx_t *ctx;
	struct event_matrix_state state;
	uint8_t event[IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 4];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint8_t *body = event + IPC_OP_PREFIX_SIZE;
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;
	int daemon_fd;

	memset(&state, 0, sizeof(state));
	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);
	ble_on_passkey_display(ctx, record_display, &state);
	ble_on_passkey_input(ctx, record_input, &state);
	ble_on_keypress(ctx, record_keypress, &state);
	ble_on_iso_cis_request(ctx, record_cis_request, &state);
	ble_on_iso_established(ctx, record_iso_established, &state);

	/* Register a per-handle notification callback and acknowledge it. */
	ATF_REQUIRE_EQ(0, ble_subscribe(ctx, &addr, 0x0042,
	    record_notification, &state));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ipc_op_prefix_encode(request, request_id, IPC_ERR_NONE, 0);
	send_frame(daemon_fd, IPC_T_OP_REPLY, domain, request,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));

	memset(event, 0, sizeof(event));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	body[2] = addr.addr_type;
	memcpy(body + 3, addr.addr, sizeof(addr.addr));
	ipc_put_le16(body + 9, 0x0042);
	ipc_put_le16(body + 11, 3);
	body[13] = addr.adapter_index;
	ipc_put_le16(body + 14, 185);
	memcpy(body + IPC_GATT_NOTIFY_EVENT_SIZE, "ble", 3);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 3);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.notify_calls);
	ATF_CHECK_EQ(0x0042, state.handle);
	ATF_CHECK_EQ(3, state.value_len);
	ATF_CHECK_EQ(0, memcmp(state.value, "ble", 3));

	/*
	 * Exercise every security event callback with the finding 28/29
	 * coordinated body layout: [event u16][adapter_index u8][addr_type u8]
	 * [addr[6]][payload...].  Verify the decoded ble_addr_t carries the
	 * adapter_index and addr_type from their fixed offsets (finding 29:
	 * previously adapter_index was left uninitialized).
	 */
	memset(event, 0, sizeof(event));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_DISPLAY);
	body[2] = addr.adapter_index;
	body[3] = addr.addr_type;
	memcpy(body + 4, addr.addr, sizeof(addr.addr));
	ipc_put_le32(body + 10, 654321);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.display_calls);
	ATF_CHECK_EQ(654321, state.passkey);
	ATF_CHECK_EQ(addr.adapter_index, state.sec_adapter_index);
	ATF_CHECK_EQ(addr.addr_type, state.sec_addr_type);

	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_INPUT);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_INPUT_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.input_calls);
	ATF_CHECK_EQ(addr.adapter_index, state.sec_adapter_index);

	ipc_put_le16(body, IPC_SECURITY_EV_KEYPRESS);
	body[10] = 4;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_KEYPRESS_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.keypress_calls);
	ATF_CHECK_EQ(4, state.keypress);
	ATF_CHECK_EQ(addr.adapter_index, state.sec_adapter_index);

	/* Exercise both ISO asynchronous event variants. */
	memset(event, 0, sizeof(event));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_ISO_EV_CIS_REQUEST);
	body[2] = addr.addr_type;
	memcpy(body + 3, addr.addr, sizeof(addr.addr));
	ipc_put_le16(body + 9, 0x1234);
	body[11] = 5;
	body[12] = 6;
	body[13] = 7;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, event,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.cis_request_calls);
	ATF_CHECK_EQ(5, state.cig_id);
	ATF_CHECK_EQ(6, state.cis_id);
	ATF_CHECK_EQ(7, state.adapter_index);

	ipc_put_le16(body, IPC_ISO_EV_ESTABLISHED);
	ipc_put_le16(body + 11, 251);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, event,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(1, state.iso_established_calls);
	ATF_CHECK_EQ(0x1234, state.handle);
	ATF_CHECK_EQ(251, state.mtu);
	ATF_CHECK_EQ(7, state.adapter_index);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(typed_protocol_error_matrix);
ATF_TC_BODY(typed_protocol_error_matrix, tc)
{
	static const struct {
		uint16_t ipc_error;
		int ble_error;
	} error_cases[] = {
		{ IPC_ERR_NOMEM, BLE_ERR_NOMEM },
		{ IPC_ERR_PROTO, BLE_ERR_PROTO },
		{ IPC_ERR_GENERIC, BLE_ERR_DAEMON },
		{ IPC_ERR_UNKNOWN_CMD, BLE_ERR_DAEMON },
		{ IPC_ERR_IO, BLE_ERR_DAEMON },
	};
	ble_ctx_t *ctx;
	uint8_t payload[IPC_OP_PREFIX_SIZE + 4];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;
	size_t i;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);

	/* A short reply cannot be correlated to its pending request. */
	ATF_REQUIRE_EQ(0, ble_advertise(ctx, true));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	send_frame(daemon_fd, IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE - 1);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* Unknown reply flag bits are rejected after successful correlation. */
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0x8000);
	send_frame(daemon_fd, IPC_T_OP_REPLY, domain, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* Invalid event correlation and domains may not be dispatched. */
	ipc_op_prefix_encode(payload, 1, IPC_ERR_NONE, 0);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	send_frame(daemon_fd, IPC_T_OP_EVENT, 0xffff, payload,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	for (i = 0; i < sizeof(error_cases) / sizeof(error_cases[0]); i++) {
		send_frame(daemon_fd, IPC_T_ERROR, error_cases[i].ipc_error,
		    "daemon error", sizeof("daemon error") - 1);
		ATF_REQUIRE_EQ(0, ble_process(ctx));
		ATF_CHECK_EQ(error_cases[i].ble_error, ble_errno(ctx));
	}

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(typed_malformed_event_matrix);
ATF_TC_BODY(typed_malformed_event_matrix, tc)
{
	ble_ctx_t *ctx;
	uint8_t event[IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE];
	uint8_t *body = event + IPC_OP_PREFIX_SIZE;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);
	memset(event, 0, sizeof(event));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);

	/* Status and flag bits are forbidden on every asynchronous event. */
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	ipc_op_prefix_encode(event, 0, IPC_ERR_IO, 0);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 1);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);

	/* Invalid address types are rejected independently in each domain. */
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	body[2] = 2;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    sizeof(event));
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* Each GATT server event validates its fixed and variable payload. */
	memset(body, 0, IPC_GATT_VALUE_EVENT_SIZE + 1);
	ipc_put_le16(body, IPC_GATT_EV_WRITE);
	ipc_put_le16(body + 4, 1);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_GATT_READ_EVENT_SIZE);
	ipc_put_le16(body, IPC_GATT_EV_READ);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_EVENT_SIZE - 1);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_GATT_AUTHORIZE_EVENT_SIZE);
	ipc_put_le16(body, IPC_GATT_EV_AUTHORIZE);
	body[2] = 2;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_AUTHORIZE_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_GATT_NOTIFY_EVENT_SIZE);
	ipc_put_le16(body, IPC_GATT_EV_NOTIFY);
	body[2] = 1;
	ipc_put_le16(body + 11, 1);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* Invalid addr_type (body[3], findings 28/29 layout) fails closed. */
	memset(body, 0, IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_DISPLAY);
	body[3] = 2;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_INPUT);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ipc_put_le16(body, 0xffff);
	body[2] = 1;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* A syntactically valid passkey event still enforces the value range. */
	memset(body, 0, IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_DISPLAY);
	body[3] = 1;
	ipc_put_le32(body + 10, 1000000);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, event,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	/* ISO correlation, unknown domains, and GAP opcodes fail closed. */
	memset(body, 0, IPC_ISO_EVENT_SIZE);
	ipc_put_le16(body, IPC_ISO_EV_CIS_REQUEST);
	body[2] = 1;
	ipc_op_prefix_encode(event, 1, IPC_ERR_NONE, 0);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, event,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	ipc_op_prefix_encode(event, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, 0xffff);
	send_frame(daemon_fd, IPC_T_OP_EVENT, 0xfffe, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_GAP_CONNECTED_EVENT_SIZE);
	ipc_put_le16(body, IPC_GAP_EV_CONNECTED);
	body[2] = 2;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, event,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ipc_put_le16(body, IPC_GAP_EV_DISCONNECTED);
	body[2] = 2;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, event,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_ISO_EVENT_SIZE);
	ipc_put_le16(body, 0xffff);
	body[2] = 1;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, event,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	memset(body, 0, IPC_ISO_EVENT_SIZE);
	ipc_put_le16(body, IPC_ISO_EV_CIS_REQUEST);
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, event,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(pending_operation_capacity);
ATF_TC_BODY(pending_operation_capacity, tc)
{
	ble_ctx_t *ctx;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint16_t type, domain;
	size_t request_len;
	int daemon_fd, i;

	ctx = make_mock_ctx(&daemon_fd);
	for (i = 0; i < 64; i++)
		ATF_REQUIRE_EQ_MSG(0, ble_subscribe(ctx, NULL, (uint16_t)i,
		    NULL, NULL),
		    "operation %d unexpectedly rejected", i);
	ATF_CHECK_EQ(-1, ble_subscribe(ctx, NULL, 64, NULL, NULL));
	ATF_CHECK_EQ(BLE_ERR_BUSY, ble_errno(ctx));

	/* Confirm all accepted operations reached the mock daemon. */
	for (i = 0; i < 64; i++) {
		read_frame(daemon_fd, &type, &domain, request, sizeof(request),
		    &request_len);
		ATF_CHECK_EQ(IPC_T_OP_REQ, type);
		ATF_CHECK_EQ(IPC_OP_DOMAIN_GATT, domain);
	}

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(typed_adv_set_lifecycle);
ATF_TC_BODY(typed_adv_set_lifecycle, tc)
{
	ble_adv_set_t *set = NULL;
	ble_ctx_t *ctx;
	uint8_t create[IPC_ADV_SET_CREATE_REPLY_SIZE] = { 0 };
	uint8_t data[] = { 0x02, 0x01, 0x06 };
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	ipc_put_le16(create, IPC_ADV_SET_CREATE);
	create[2] = 0x23;
	send_sync_reply_id(daemon_fd, 1, IPC_OP_DOMAIN_ADV, create,
	    sizeof(create));
	ATF_REQUIRE_EQ(0, ble_adv_set_create(ctx, &set));
	ATF_REQUIRE(set != NULL);
	ATF_CHECK_EQ(0x23, ble_adv_set_handle(set));

	send_sync_reply_id(daemon_fd, 2, IPC_OP_DOMAIN_ADV, NULL, 0);
	ATF_CHECK_EQ(0, ble_adv_set_params(set, 0, 0x20, 0x40, 1, 2));
	send_sync_reply_id(daemon_fd, 3, IPC_OP_DOMAIN_ADV, NULL, 0);
	ATF_CHECK_EQ(0, ble_adv_set_data(set, data, sizeof(data)));
	send_sync_reply_id(daemon_fd, 4, IPC_OP_DOMAIN_ADV, NULL, 0);
	ATF_CHECK_EQ(0, ble_adv_set_data(set, NULL, 0));
	send_sync_reply_id(daemon_fd, 5, IPC_OP_DOMAIN_ADV, NULL, 0);
	ATF_CHECK_EQ(0, ble_adv_set_enable(set, true));
	send_sync_reply_id(daemon_fd, 6, IPC_OP_DOMAIN_ADV, NULL, 0);
	ble_adv_set_close(set);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(typed_structured_reply_rejections);
ATF_TC_BODY(typed_structured_reply_rejections, tc)
{
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 1 };
	ble_adv_set_t *set = NULL;
	ble_adapter_caps_t caps;
	ble_bond_t bond;
	ble_cig_params_t cig;
	ble_connection_info_t conn;
	ble_ctx_t *ctx;
	ble_security_info_t info;
	ble_security_policy_t policy;
	ble_status_t st;
	uint8_t body[IPC_SECURITY_BOND_REPLY_HDR_SIZE +
	    IPC_SECURITY_BOND_RECORD_SIZE];
	uint16_t handles[1];
	uint8_t size;
	int daemon_fd;

	/* CIG replies must carry a bounded count and reserved-zero byte. */
	memset(&cig, 0, sizeof(cig));
	cig.num_cis = 1;
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_ISO_CIG_REPLY_SIZE);
	ipc_put_le16(body, IPC_ISO_CIG_CREATE);
	body[2] = 9;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_ISO, body,
	    IPC_ISO_CIG_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_iso_cig_create(ctx, 0, &cig, handles, 1));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Owned advertising handle zero is reserved. */
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_ADV_SET_CREATE_REPLY_SIZE);
	ipc_put_le16(body, IPC_ADV_SET_CREATE);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_ADV, body,
	    IPC_ADV_SET_CREATE_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_adv_set_create(ctx, &set));
	ATF_CHECK(set == NULL);
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Periodic list replies reject nonzero reserved fields. */
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_PERIODIC_SIZE_REPLY_SIZE);
	ipc_put_le16(body, IPC_PERIODIC_LIST_SIZE);
	body[3] = 1;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_PERIODIC, body,
	    IPC_PERIODIC_SIZE_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_size(ctx, 0, &size));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Global status accepts only the documented flag bit. */
	ctx = make_mock_ctx(&daemon_fd);
	ipc_status_reply_encode(body, 1, 2, 3, 0x8000);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_CTL, body,
	    IPC_STATUS_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_status(ctx, &st));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Adapter identity in a reply must match the requested index. */
	ctx = make_mock_ctx(&daemon_fd);
	ipc_adapter_caps_reply_encode(body, 2, "mock", addr.addr, 0, 1, 0);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_CTL, body,
	    IPC_ADAPTER_CAPS_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_adapter_caps(ctx, 1, &caps));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Snapshot counts are bounded before record iteration. */
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_BOND_REPLY_HDR_SIZE);
	ipc_put_le16(body, IPC_SECURITY_BOND_LIST);
	ipc_put_le16(body + 2, BLE_MAX_BONDS + 1);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_BOND_REPLY_HDR_SIZE);
	ATF_CHECK_EQ(-1, ble_bond_list(ctx, &bond, 1));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_GAP_CONNECTION_REPLY_HDR_SIZE);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, IPC_GAP_CONNECTION_MAX + 1);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_GAP, body,
	    IPC_GAP_CONNECTION_REPLY_HDR_SIZE);
	ATF_CHECK_EQ(-1, ble_connections(ctx, &conn, 1));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Structured security replies reject impossible enums and levels. */
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_POLICY_REPLY_SIZE);
	ipc_put_le16(body, IPC_SECURITY_GET_POLICY);
	body[2] = 2;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_POLICY_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_get_security_policy(ctx, &policy));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, IPC_SECURITY_INFO_REPLY_SIZE);
	ipc_put_le16(body, IPC_SECURITY_GET_INFO);
	body[2] = 2;
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_SECURITY, body,
	    IPC_SECURITY_INFO_REPLY_SIZE);
	ATF_CHECK_EQ(-1, ble_get_security_info(ctx, &addr, &info));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(typed_iso_stream_lifecycle);

ATF_TC_WITHOUT_HEAD(connection_snapshot_record_matrix);
ATF_TC_BODY(connection_snapshot_record_matrix, tc)
{
	ble_connection_info_t connections[2];
	ble_addr_t first_addr, second_addr;
	ble_ctx_t *ctx;
	uint8_t body[IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
	    2 * IPC_GAP_CONNECTION_RECORD_SIZE];
	uint8_t *record;
	int daemon_fd, variant;

	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(-1, ble_connections(ctx, NULL, 1));
	close(daemon_fd); ble_close(ctx);
	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(-1, ble_connections(ctx, connections, 0));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(ctx));
	close(daemon_fd); ble_close(ctx);

	/* Two valid records are safely truncated to the caller's capacity. */
	ctx = make_mock_ctx(&daemon_fd);
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, 2);
	record = body + IPC_GAP_CONNECTION_REPLY_HDR_SIZE;
	record[0] = 1; record[7] = BLE_CONNECTION_ACTIVE; record[8] = 1;
	memset(record + 1, 0x11, 6); record[13] = 1;
	ipc_put_le16(record + 16, 185);
	record[9] = IPC_GAP_CONN_F_ENCRYPTED |
	    IPC_GAP_CONN_F_AUTHENTICATED | IPC_GAP_CONN_F_PHY_VALID;
	record[10] = 16; record[11] = 2; record[12] = 3;
	memcpy(record + 24, "first", 6);
	record += IPC_GAP_CONNECTION_RECORD_SIZE;
	record[0] = 0; record[7] = BLE_CONNECTION_ACTIVE; record[8] = 0;
	memset(record + 1, 0x22, 6); record[13] = 2;
	ipc_put_le16(record + 16, 247);
	memcpy(record + 24, "second", 7);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_GAP, body, sizeof(body));
	ATF_REQUIRE_EQ(1, ble_connections(ctx, connections, 1));
	ATF_CHECK_STREQ("first", connections[0].name);
	ATF_CHECK(connections[0].encrypted);
	ATF_CHECK(connections[0].authenticated);
	ATF_CHECK(connections[0].phy_valid);
	memset(&first_addr, 0, sizeof(first_addr));
	first_addr.addr_type = 1; first_addr.adapter_index = 1;
	memset(first_addr.addr, 0x11, sizeof(first_addr.addr));
	memset(&second_addr, 0, sizeof(second_addr));
	second_addr.addr_type = 0; second_addr.adapter_index = 2;
	memset(second_addr.addr, 0x22, sizeof(second_addr.addr));
	ATF_CHECK(ble_is_connected(ctx));
	ATF_CHECK(ble_is_peer_connected(ctx, &first_addr));
	ATF_CHECK(ble_is_peer_connected(ctx, &second_addr));
	ATF_CHECK_EQ(185, ble_get_peer_mtu(ctx, &first_addr));
	ATF_CHECK_EQ(247, ble_get_peer_mtu(ctx, &second_addr));
	ATF_CHECK_EQ(0, ble_get_mtu(ctx));

	/* A malformed replacement snapshot must preserve the last good cache. */
	memset(body, 0, IPC_GAP_CONNECTION_REPLY_HDR_SIZE);
	ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(body + 2, IPC_GAP_CONNECTION_MAX + 1);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_GAP, body,
	    IPC_GAP_CONNECTION_REPLY_HDR_SIZE);
	ATF_CHECK_EQ(-1, ble_connections(ctx, connections, 2));
	ATF_CHECK(ble_is_peer_connected(ctx, &first_addr));
	ATF_CHECK(ble_is_peer_connected(ctx, &second_addr));
	close(daemon_fd); ble_close(ctx);

	/* Every constrained field in a connection record is validated. */
	for (variant = 0; variant < 10; variant++) {
		ctx = make_mock_ctx(&daemon_fd);
		memset(body, 0, sizeof(body));
		ipc_put_le16(body, IPC_GAP_GET_CONNECTIONS);
		ipc_put_le16(body + 2, 1);
		record = body + IPC_GAP_CONNECTION_REPLY_HDR_SIZE;
		memcpy(record + 24, "peer", 5);
		switch (variant) {
		case 0: record[0] = 2; break;
		case 1: record[7] = 4; break;
		case 2: record[8] = 2; break;
		case 3: record[9] = 0x80; break;
		case 4: record[10] = 17; break;
		case 5:
			record[9] = IPC_GAP_CONN_F_ENCRYPTED;
			record[10] = 6;
			break;
		case 6:
			record[9] = IPC_GAP_CONN_F_AUTHENTICATED;
			break;
		case 7:
			record[9] = IPC_GAP_CONN_F_PHY_VALID;
			record[11] = 0; record[12] = 1;
			break;
		case 8: record[13] = 8; break;
		case 9: memset(record + 24, 'x', 64); break;
		}
		send_sync_reply(daemon_fd, IPC_OP_DOMAIN_GAP, body,
		    IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
		    IPC_GAP_CONNECTION_RECORD_SIZE);
		ATF_CHECK_EQ(-1, ble_connections(ctx, connections, 2));
		ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(ctx));
		close(daemon_fd); ble_close(ctx);
	}
}

ATF_TC_BODY(typed_iso_stream_lifecycle, tc)
{
	ble_iso_stream_t *stream = NULL;
	ble_ctx_t *ctx;
	struct delayed_fds fds;
	pthread_t sender;
	uint8_t body[IPC_ISO_ACQUIRE_REPLY_SIZE] = { 0 };
	uint8_t tx[] = { 1, 2, 3 }, rx[4] = { 0 };
	int channel[2], daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel));
	ipc_put_le16(body, IPC_ISO_ACQUIRE);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_ISO, body, sizeof(body));
	fds = (struct delayed_fds){ daemon_fd, channel[1], 1 };
	ATF_REQUIRE_EQ(0, pthread_create(&sender, NULL, send_fds_delayed, &fds));
	ATF_REQUIRE_EQ(0, ble_iso_acquire(ctx, 2, 0x123, &stream));
	ATF_REQUIRE_EQ(0, pthread_join(sender, NULL));
	ATF_REQUIRE(stream != NULL);
	ATF_CHECK(ble_iso_fd(stream) >= 0);
	ATF_CHECK_EQ((int)sizeof(tx), ble_iso_send(stream, tx, sizeof(tx)));
	ATF_REQUIRE_EQ((ssize_t)sizeof(tx), read(channel[0], rx, sizeof(rx)));
	ATF_CHECK_EQ(0, memcmp(tx, rx, sizeof(tx)));
	ATF_REQUIRE_EQ((ssize_t)sizeof(tx), write(channel[0], tx, sizeof(tx)));
	memset(rx, 0, sizeof(rx));
	ATF_CHECK_EQ((int)sizeof(tx), ble_iso_recv(stream, rx, sizeof(rx)));
	ATF_CHECK_EQ(0, memcmp(tx, rx, sizeof(tx)));
	ble_iso_close(stream);
	close(channel[0]); close(channel[1]); close(daemon_fd); ble_close(ctx);

	stream = NULL;
	ctx = make_mock_ctx(&daemon_fd);
	enable_fdpass(ctx, daemon_fd);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel));
	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_ISO_BIS_ACQUIRE);
	send_sync_reply(daemon_fd, IPC_OP_DOMAIN_ISO, body, sizeof(body));
	fds = (struct delayed_fds){ daemon_fd, channel[1], 1 };
	ATF_REQUIRE_EQ(0, pthread_create(&sender, NULL, send_fds_delayed, &fds));
	ATF_REQUIRE_EQ(0, ble_iso_bis_acquire(ctx, 1, 2, 3, &stream));
	ATF_REQUIRE_EQ(0, pthread_join(sender, NULL));
	ATF_REQUIRE(stream != NULL);
	ble_iso_close(stream);
	close(channel[0]); close(channel[1]); close(daemon_fd); ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(battery_discovery_chains_read);
ATF_TC_BODY(battery_discovery_chains_read, tc)
{
	ble_addr_t addr = {
	    .addr = { 2, 4, 6, 8, 10, 12 }, .addr_type = 1,
	    .adapter_index = 3
	};
	ble_ctx_t *ctx;
	uint8_t event[IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE];
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint8_t *body = event + IPC_OP_PREFIX_SIZE;
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;
	int daemon_fd;

	ATF_CHECK_EQ(-1, ble_read_battery(NULL, &addr, NULL, NULL));
	ctx = make_mock_ctx(&daemon_fd);
	ATF_CHECK_EQ(-1, ble_read_battery(ctx, NULL, NULL, NULL));
	ATF_REQUIRE_EQ(0, ble_read_battery(ctx, &addr, NULL, NULL));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	ATF_CHECK_EQ(IPC_GATT_DISCOVER,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE));

	memset(event, 0, sizeof(event));
	ipc_op_prefix_encode(event, request_id, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_GATT_EV_CHARACTERISTIC);
	ipc_put_le16(body + 2, BLE_CHR_BATTERY_LEVEL);
	ipc_put_le16(body + 20, 0x0025);
	body[22] = 0x02;
	send_frame(daemon_fd, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, event,
	    sizeof(event));
	ATF_REQUIRE_EQ(0, ble_process(ctx));

	ipc_op_prefix_encode(event, request_id, IPC_ERR_NONE, 0);
	send_frame(daemon_fd, IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, event,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_T_OP_REQ, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_GATT, domain);
	ATF_CHECK_EQ(IPC_GATT_READ,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE));
	ATF_CHECK_EQ(0x0025,
	    ipc_get_le16(request + IPC_OP_PREFIX_SIZE + 12));

	close(daemon_fd);
	ble_close(ctx);
}

/*
 * Finding 28/29: ble_passkey_reply()/ble_numcmp_reply() encode the coordinated
 * body layout [adapter_index u8][addr_type u8][addr[6]][value...] so the daemon
 * can route the reply by (adapter, addr, addr_type).
 */
ATF_TC_WITHOUT_HEAD(security_reply_encoding);
ATF_TC_BODY(security_reply_encoding, tc)
{
	ble_addr_t addr = {
		.addr = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
		.addr_type = 1,
		.adapter_index = 3,
	};
	ble_ctx_t *ctx;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	const uint8_t *b;
	uint16_t type, domain;
	size_t request_len;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);

	ATF_REQUIRE_EQ(0, ble_passkey_reply(ctx, &addr, 424242));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_T_OP_REQ, type);
	ATF_CHECK_EQ(IPC_OP_DOMAIN_SECURITY, domain);
	ATF_CHECK_EQ(IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_REQ_SIZE,
	    request_len);
	b = request + IPC_OP_PREFIX_SIZE;
	ATF_CHECK_EQ(IPC_SECURITY_PASSKEY_REPLY, ipc_get_le16(b));
	ATF_CHECK_EQ(addr.addr_type, b[4]);
	ATF_CHECK_EQ(0, memcmp(b + 5, addr.addr, sizeof(addr.addr)));
	ATF_CHECK_EQ(addr.adapter_index, b[11]);
	ATF_CHECK_EQ(424242u, ipc_get_le32(b + 12));

	ATF_REQUIRE_EQ(0, ble_numcmp_reply(ctx, &addr, true));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ATF_CHECK_EQ(IPC_OP_PREFIX_SIZE + IPC_SECURITY_DECISION_REQ_SIZE,
	    request_len);
	b = request + IPC_OP_PREFIX_SIZE;
	ATF_CHECK_EQ(IPC_SECURITY_NUMCMP_REPLY, ipc_get_le16(b));
	ATF_CHECK_EQ(addr.addr_type, b[4]);
	ATF_CHECK_EQ(0, memcmp(b + 5, addr.addr, sizeof(addr.addr)));
	ATF_CHECK_EQ(1, b[12]);

	close(daemon_fd);
	ble_close(ctx);
}

/*
 * Finding 34: ble_pending_count() lets a one-shot client await the correlated
 * OP_REPLY of a fire-and-forget operation and observe its error, instead of
 * exiting 0 unconditionally.
 */
ATF_TC_WITHOUT_HEAD(pending_count_drains_reply);
ATF_TC_BODY(pending_count_drains_reply, tc)
{
	ble_addr_t addr = { .addr = { 1, 2, 3, 4, 5, 6 }, .addr_type = 0 };
	ble_ctx_t *ctx;
	uint8_t request[IPC_OP_PREFIX_SIZE + IPC_MAX_PAYLOAD];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);

	/* A fire-and-forget disconnect leaves exactly one pending operation. */
	ATF_REQUIRE_EQ(0, ble_disconnect(ctx, &addr));
	ATF_CHECK_EQ(1u, ble_pending_count(ctx));
	read_frame(daemon_fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);

	/* A failing reply resolves the pending op and surfaces the error. */
	ipc_op_prefix_encode(request, request_id, IPC_ERR_NOT_CONN, 0);
	send_frame(daemon_fd, IPC_T_OP_REPLY, domain, request,
	    IPC_OP_PREFIX_SIZE);
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(0u, ble_pending_count(ctx));
	ATF_CHECK_EQ(BLE_ERR_NOTCONN, ble_errno(ctx));

	close(daemon_fd);
	ble_close(ctx);
}

struct passkey_capture {
	int calls;
	uint32_t value;
};

static void
drain_passkey_cb(const ble_addr_t *a __unused, uint32_t v, void *arg)
{
	struct passkey_capture *c = arg;

	c->calls++;
	c->value = v;
}

struct drain_daemon_args {
	int fd;
	const uint8_t *event_tail;
	size_t event_tail_len;
	uint16_t reply_domain;
};

static void *
drain_daemon_thread(void *arg)
{
	struct drain_daemon_args *a = arg;
	uint8_t request[256];
	uint32_t request_id;
	uint16_t type, domain, status, flags;
	size_t request_len;

	/* Read the synchronous request, then flush the partial event + reply. */
	read_frame(a->fd, &type, &domain, request, sizeof(request),
	    &request_len);
	ipc_op_prefix_decode(request, &request_id, &status, &flags);
	(void)send(a->fd, a->event_tail, a->event_tail_len, 0);
	ipc_op_prefix_encode(request, request_id, IPC_ERR_NONE, 0);
	send_frame(a->fd, IPC_T_OP_REPLY, a->reply_domain, request,
	    IPC_OP_PREFIX_SIZE);
	return (NULL);
}

/*
 * Finding 32: a synchronous libble operation must drain bytes already buffered
 * by a prior ble_process() before reading the socket.  Here ble_process()
 * leaves a partial security event in the rx buffer; the following synchronous
 * ble_eatt_open() must reassemble that event (firing its callback) and then
 * read its own reply, rather than starting mid-frame and desyncing.
 */
ATF_TC_WITHOUT_HEAD(sync_op_drains_partial_frame);
ATF_TC_BODY(sync_op_drains_partial_frame, tc)
{
	ble_addr_t addr = { .addr = { 9, 8, 7, 6, 5, 4 }, .addr_type = 0 };
	ble_ctx_t *ctx;
	struct passkey_capture cap = { 0, 0 };
	uint8_t frame[IPC_HDR_SIZE + IPC_OP_PREFIX_SIZE +
	    IPC_SECURITY_PASSKEY_EVENT_SIZE];
	uint8_t *payload = frame + IPC_HDR_SIZE;
	uint8_t *body = payload + IPC_OP_PREFIX_SIZE;
	const size_t split = 12;	/* header + partial payload: leaves a partial */
	struct drain_daemon_args args;
	pthread_t thr;
	int daemon_fd;

	ctx = make_mock_ctx(&daemon_fd);
	enable_features(ctx, daemon_fd, IPC_FEATURE_EVENTS);
	ble_on_passkey_display(ctx, drain_passkey_cb, &cap);

	/* Build a full PASSKEY_DISPLAY event frame (findings 28/29 layout). */
	memset(frame, 0, sizeof(frame));
	ipc_hdr_encode(frame, IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE,
	    IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY);
	ipc_op_prefix_encode(payload, 0, IPC_ERR_NONE, 0);
	ipc_put_le16(body, IPC_SECURITY_EV_PASSKEY_DISPLAY);
	body[2] = 0;			/* adapter_index */
	body[3] = 0;			/* addr_type */
	ipc_put_le32(body + 10, 246810);

	/* Deliver only the first `split` bytes; ble_process buffers a partial. */
	ATF_REQUIRE_EQ((ssize_t)split, send(daemon_fd, frame, split, 0));
	ATF_REQUIRE_EQ(0, ble_process(ctx));
	ATF_CHECK_EQ(0, cap.calls);	/* not yet complete */

	/* The daemon completes the event and answers the sync request. */
	args.fd = daemon_fd;
	args.event_tail = frame + split;
	args.event_tail_len = sizeof(frame) - split;
	args.reply_domain = IPC_OP_DOMAIN_L2CAP;
	ATF_REQUIRE_EQ(0, pthread_create(&thr, NULL, drain_daemon_thread,
	    &args));

	/* Synchronous op: must drain the buffered partial event first. */
	ATF_REQUIRE_EQ(0, ble_eatt_open(ctx, &addr, 1));
	ATF_REQUIRE_EQ(0, pthread_join(thr, NULL));

	/* The buffered event was reassembled and dispatched, not lost/desynced. */
	ATF_CHECK_EQ(1, cap.calls);
	ATF_CHECK_EQ(246810u, cap.value);

	close(daemon_fd);
	ble_close(ctx);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, security_reply_encoding);
	ATF_TP_ADD_TC(tp, pending_count_drains_reply);
	ATF_TP_ADD_TC(tp, sync_op_drains_partial_frame);
	ATF_TP_ADD_TC(tp, acquire_notify_typed);
	ATF_TP_ADD_TC(tp, acquire_requires_fdpass);
	ATF_TP_ADD_TC(tp, acquire_write_typed);
	ATF_TP_ADD_TC(tp, acquire_coc_and_ecbfc_typed);
	ATF_TP_ADD_TC(tp, scan_filter_validation_and_encoding);
	ATF_TP_ADD_TC(tp, acquire_reply_errors);
	ATF_TP_ADD_TC(tp, addr_format);
	ATF_TP_ADD_TC(tp, path_loss_serialization);
	ATF_TP_ADD_TC(tp, path_loss_invalid_inputs);
	ATF_TP_ADD_TC(tp, public_api_command_families);
	ATF_TP_ADD_TC(tp, public_api_validation_families);
	ATF_TP_ADD_TC(tp, public_api_utilities_and_callbacks);
	ATF_TP_ADD_TC(tp, security_sync_query_matrix);
	ATF_TP_ADD_TC(tp, typed_event_callback_matrix);
	ATF_TP_ADD_TC(tp, typed_protocol_error_matrix);
	ATF_TP_ADD_TC(tp, typed_malformed_event_matrix);
	ATF_TP_ADD_TC(tp, typed_adv_set_lifecycle);
	ATF_TP_ADD_TC(tp, typed_structured_reply_rejections);
	ATF_TP_ADD_TC(tp, connection_snapshot_record_matrix);
	ATF_TP_ADD_TC(tp, typed_iso_stream_lifecycle);
	ATF_TP_ADD_TC(tp, pending_operation_capacity);
	ATF_TP_ADD_TC(tp, battery_discovery_chains_read);
	return (atf_no_error());
}
