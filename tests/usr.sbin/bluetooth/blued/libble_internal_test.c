/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

/* White-box malformed-wire tests for the libble protocol engine. */
#include "ble.c"
#include <atf-c.h>

static unsigned callbacks;
static uint16_t callback_status;

static void
reply_cb(ble_ctx_t *ctx, uint16_t opcode, uint16_t status,
    const uint8_t *payload, size_t len, void *arg)
{
	(void)ctx; (void)opcode; (void)payload; (void)len; (void)arg;
	callback_status = status;
	callbacks++;
}

static void
notify_cb(const ble_addr_t *addr, uint16_t handle, const uint8_t *value,
    uint16_t len, void *arg)
{
	(void)addr; (void)handle; (void)value; (void)len; (void)arg;
	callbacks++;
}

static void write_cb(uint16_t h, const uint8_t *v, uint16_t n, void *arg)
{ (void)h; (void)v; (void)n; (void)arg; callbacks++; }
static void read_req_cb(uint16_t h, uint16_t off, void *arg)
{ (void)h; (void)off; (void)arg; callbacks++; }
static void authorize_cb(const ble_addr_t *a, uint16_t h, bool w, void *arg)
{ (void)a; (void)h; (void)w; (void)arg; callbacks++; }
static void addr_cb(const ble_addr_t *a, void *arg)
{ (void)a; (void)arg; callbacks++; }
static void value_cb(const ble_addr_t *a, uint32_t v, void *arg)
{ (void)a; (void)v; (void)arg; callbacks++; }
static void keypress_cb(const ble_addr_t *a, uint8_t v, void *arg)
{ (void)a; (void)v; (void)arg; callbacks++; }
static void conn_cb(const ble_addr_t *a, uint16_t h, uint16_t mtu, void *arg)
{ (void)a; (void)h; (void)mtu; (void)arg; callbacks++; }
static void disconn_cb(const ble_addr_t *a, uint16_t reason, void *arg)
{ (void)a; (void)reason; (void)arg; callbacks++; }
static void iso_req_cb(const ble_addr_t *a, uint16_t h, uint8_t cig,
    uint8_t cis, void *arg)
{ (void)a; (void)h; (void)cig; (void)cis; (void)arg; callbacks++; }
static void iso_est_cb(const ble_addr_t *a, uint16_t h, uint16_t mtu,
    void *arg)
{ (void)a; (void)h; (void)mtu; (void)arg; callbacks++; }
static void scan_cb(const ble_scan_result_t *r, void *arg)
{ (void)r; (void)arg; callbacks++; }
static void discover_cb(const ble_addr_t *a, const ble_service_t *s, int ns,
    const ble_characteristic_t *c, int nc, void *arg)
{ (void)a; (void)s; (void)ns; (void)c; (void)nc; (void)arg; callbacks++; }
static void gatt_read_cb(const ble_addr_t *a, uint16_t h, const uint8_t *v,
    uint16_t n, int error, void *arg)
{ (void)a; (void)h; (void)v; (void)n; (void)error; (void)arg; callbacks++; }

static void
init_ctx(ble_ctx_t *ctx, int fd)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = fd;
}

static void
prefix(uint8_t *p, uint32_t id, uint16_t status, uint16_t flags,
    uint16_t event)
{
	memset(p, 0, IPC_MAX_PAYLOAD + 32);
	ipc_op_prefix_encode(p, id, status, flags);
	ipc_put_le16(p + IPC_OP_PREFIX_SIZE, event);
}

static void
stage_sync_reply(int fd, uint32_t id, uint16_t domain, const void *body,
    size_t body_len)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_OP_PREFIX_SIZE + 512];

	ATF_REQUIRE(body_len <= sizeof(payload) - IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_encode(payload, id, IPC_ERR_NONE, 0);
	memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	ipc_hdr_encode(hdr, IPC_OP_PREFIX_SIZE + body_len, IPC_T_OP_REPLY,
	    domain);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), send(fd, hdr, sizeof(hdr), 0));
	ATF_REQUIRE_EQ((ssize_t)(IPC_OP_PREFIX_SIZE + body_len), send(fd,
	    payload, IPC_OP_PREFIX_SIZE + body_len, 0));
}

static void
stage_reply_frame(int fd, uint16_t type, uint16_t domain, uint32_t id,
    uint16_t status, uint16_t flags, const void *body, size_t body_len)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_OP_PREFIX_SIZE + 32];

	ATF_REQUIRE(body_len <= sizeof(payload) - IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_encode(payload, id, status, flags);
	if (body_len != 0)
		memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	ipc_hdr_encode(hdr, IPC_OP_PREFIX_SIZE + body_len, type, domain);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), send(fd, hdr, sizeof(hdr), 0));
	ATF_REQUIRE_EQ((ssize_t)(IPC_OP_PREFIX_SIZE + body_len), send(fd,
	    payload, IPC_OP_PREFIX_SIZE + body_len, 0));
}

ATF_TC_WITHOUT_HEAD(send_and_error_matrix);
ATF_TC_BODY(send_and_error_matrix, tc)
{
	ble_ctx_t ctx;
	uint8_t byte = 0;
	uint32_t id;
	int sp[2];
	int errors[] = { BLE_ERR_SOCKET, BLE_ERR_PROTO, BLE_ERR_BUSY,
	    BLE_ERR_NOTCONN, BLE_ERR_INVAL, BLE_ERR_DAEMON, BLE_ERR_NOMEM,
	    BLE_ERR_TIMEOUT, BLE_ERR_PERM, BLE_ERR_NOTFOUND, 999 };
	size_t i;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	init_ctx(&ctx, sp[0]);
	ATF_CHECK_EQ(ble_send_frame(&ctx, IPC_T_ERROR, 0, &byte,
	    IPC_MAX_PAYLOAD + 1), -1);
	ATF_CHECK_EQ(ble_send_operation(&ctx, 0, 0, &byte, 1, NULL, NULL,
	    NULL), -1);
	ctx.pending_count = BLE_MAX_PENDING_OPS;
	ATF_CHECK_EQ(ble_send_operation(&ctx, 1, 1, &byte, 1, NULL, NULL,
	    NULL), -1);
	ctx.pending_count = 0;
	ctx.next_request_id = UINT32_MAX;
	ATF_REQUIRE_EQ(ble_send_operation(&ctx, 1, 7, &byte, 1, NULL, NULL,
	    &id), 0);
	ATF_CHECK_EQ(id, 1);
	ctx.pending_count = 0;
	ATF_CHECK_EQ(ctl_send_typed(&ctx, IPC_CTL_STATUS, 0, 0, 0), 0);

	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_NONE), BLE_ERR_NONE);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_INVAL), BLE_ERR_INVAL);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_TOOBIG), BLE_ERR_INVAL);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_NOT_FOUND), BLE_ERR_NOTFOUND);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_NOT_CONN), BLE_ERR_NOTCONN);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_BUSY), BLE_ERR_BUSY);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_PERM), BLE_ERR_PERM);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_NOMEM), BLE_ERR_NOMEM);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_PROTO), BLE_ERR_PROTO);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_GENERIC), BLE_ERR_DAEMON);
	ATF_CHECK_EQ(ble_map_ipc_err(IPC_ERR_UNKNOWN_CMD), BLE_ERR_DAEMON);
	ATF_CHECK_EQ(ble_map_ipc_err(UINT16_MAX), BLE_ERR_DAEMON);
	memset(ctx.errmsg, 0, sizeof(ctx.errmsg));
	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		ctx.last_error = errors[i];
		ctx.errmsg[0] = '\0';
		ATF_CHECK(strlen(ble_strerror(&ctx)) != 0);
	}
	close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(discovery_and_scan_guard_matrix);
ATF_TC_BODY(discovery_and_scan_guard_matrix, tc)
{
	ble_ctx_t ctx;
	struct ble_discover_op discover;
	struct ble_scan_op scan;
	uint8_t p[IPC_MAX_PAYLOAD + 32];
	size_t plen;

	init_ctx(&ctx, -1);
	memset(&discover, 0, sizeof(discover));
	memset(&scan, 0, sizeof(scan));

	/* Correlated discovery records must have exact wire size and state. */
	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 44;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GATT;
	ctx.pending_ops[0].opcode = IPC_GATT_DISCOVER;
	ctx.pending_ops[0].arg = &discover;
	prefix(p, 44, 0, 0, IPC_GATT_EV_SERVICE);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + 2);
	plen = IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE;
	ctx.pending_ops[0].arg = NULL;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);
	ctx.pending_ops[0].arg = &discover;
	prefix(p, 44, 0, 0, UINT16_MAX);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);

	/* Scan events likewise require correlation, retained state and bounded
	 * address/count/name fields before any callback can run. */
	ctx.pending_ops[0].id = 55;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GAP;
	ctx.pending_ops[0].opcode = IPC_GAP_SCAN;
	ctx.pending_ops[0].arg = &scan;
	prefix(p, 55, 0, 0, UINT16_MAX);
	plen = IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	prefix(p, 55, 0, 0, IPC_GAP_EV_SCAN_RESULT);
	ctx.pending_ops[0].arg = NULL;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	ctx.pending_ops[0].arg = &scan;
	p[IPC_OP_PREFIX_SIZE + 4] = 2;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	p[IPC_OP_PREFIX_SIZE + 4] = 0;
	p[IPC_OP_PREFIX_SIZE + 14] = 9;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	p[IPC_OP_PREFIX_SIZE + 14] = 0;
	p[IPC_OP_PREFIX_SIZE + 15] = 33;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);

	ble_dispatch_frame(&ctx, IPC_T_HELLO, 0, p, 0);
	ble_dispatch_frame(&ctx, UINT16_MAX, 0, p, 0);
}

ATF_TC_WITHOUT_HEAD(iso_argument_guard_matrix);
ATF_TC_BODY(iso_argument_guard_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	ble_cig_params_t cig;
	ble_iso_stream_t *stream;
	uint16_t handles[8];
	uint8_t bis[9] = { 1 };
	int fd;

	init_ctx(&ctx, -1);
	memset(&addr, 0, sizeof(addr));
	memset(&cig, 0, sizeof(cig));
	ctx.fdpass_ok = true;
	ATF_CHECK_EQ(-1, ble_acquire_iso(&ctx, NULL, 1, &fd));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(&ctx));
	ATF_CHECK_EQ(-1, ble_acquire_iso(&ctx, &addr, 1, NULL));
	ATF_CHECK_EQ(-1, ble_iso_cig_create(&ctx, 0, NULL, handles, 8));
	ATF_CHECK_EQ(-1, ble_iso_cig_create(&ctx, 0, &cig, handles, 8));
	cig.num_cis = 9;
	ATF_CHECK_EQ(-1, ble_iso_cig_create(&ctx, 0, &cig, handles, 8));
	cig.num_cis = 1;
	ATF_CHECK_EQ(-1, ble_iso_cig_create(&ctx, 0, &cig, handles, -1));
	ATF_CHECK_EQ(-1, ble_iso_cig_create(&ctx, 0, &cig, NULL, 1));
	ATF_CHECK_EQ(-1, ble_iso_cis_create(&ctx, NULL, 1, 1));
	ATF_CHECK_EQ(BLE_ERR_INVAL, ble_errno(&ctx));
	ATF_CHECK_EQ(-1, ble_iso_big_create(&ctx, 0, NULL));
	ATF_CHECK_EQ(-1, ble_iso_big_create_sync(&ctx, 0, 1, 1, NULL, 1,
	    0, 10, NULL));
	ATF_CHECK_EQ(-1, ble_iso_big_create_sync(&ctx, 0, 1, 1, bis, 0,
	    0, 10, NULL));
	ATF_CHECK_EQ(-1, ble_iso_big_create_sync(&ctx, 0, 1, 1, bis, 9,
	    0, 10, NULL));
	ATF_CHECK_EQ(-1, ble_iso_acquire(&ctx, 0, 1, NULL));
	ATF_CHECK_EQ(-1, ble_iso_bis_acquire(&ctx, 0, 1, 1, NULL));
	ctx.fdpass_ok = false;
	ATF_CHECK_EQ(-1, ble_iso_acquire(&ctx, 0, 1, &stream));
	ATF_CHECK_EQ(BLE_ERR_PERM, ble_errno(&ctx));
	ATF_CHECK_EQ(-1, ble_iso_bis_acquire(&ctx, 0, 1, 1, &stream));
}

ATF_TC_WITHOUT_HEAD(sync_reply_success_matrix);
ATF_TC_BODY(sync_reply_success_matrix, tc)
{
	ble_ctx_t ctx;
	ble_cig_params_t cig;
	ble_bond_t bond;
	uint16_t handles[2];
	uint8_t cig_reply[IPC_ISO_CIG_REPLY_SIZE] = { 0 };
	uint8_t size_reply[IPC_PERIODIC_SIZE_REPLY_SIZE] = { 0 };
	uint8_t bonds[IPC_SECURITY_BOND_REPLY_HDR_SIZE +
	    2 * IPC_SECURITY_BOND_RECORD_SIZE] = { 0 };
	uint8_t list_size;
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	memset(&cig, 0, sizeof(cig));
	cig.num_cis = 1;
	cig_reply[0] = IPC_ISO_CIG_CREATE & 0xff;
	cig_reply[1] = IPC_ISO_CIG_CREATE >> 8;
	cig_reply[2] = 3;
	ipc_put_le16(cig_reply + 4, 0x100);
	ipc_put_le16(cig_reply + 6, 0x101);
	ipc_put_le16(cig_reply + 8, 0x102);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_ISO, cig_reply,
	    sizeof(cig_reply));
	ATF_CHECK_EQ(2, ble_iso_cig_create(&ctx, 0, &cig, handles,
	    sizeof(handles) / sizeof(handles[0])));
	ATF_CHECK_EQ(0x100, handles[0]);
	ATF_CHECK_EQ(0x101, handles[1]);

	ipc_put_le16(size_reply, IPC_PERIODIC_LIST_SIZE);
	size_reply[2] = 17;
	stage_sync_reply(sp[1], 2, IPC_OP_DOMAIN_PERIODIC, size_reply,
	    sizeof(size_reply));
	ATF_CHECK_EQ(0, ble_periodic_adv_list_size(&ctx, 0, &list_size));
	ATF_CHECK_EQ(17, list_size);

	ipc_put_le16(bonds, IPC_SECURITY_BOND_LIST);
	ipc_put_le16(bonds + 2, 2);
	bonds[IPC_SECURITY_BOND_REPLY_HDR_SIZE] = 0;
	bonds[IPC_SECURITY_BOND_REPLY_HDR_SIZE + IPC_SECURITY_BOND_RECORD_SIZE] = 1;
	stage_sync_reply(sp[1], 3, IPC_OP_DOMAIN_SECURITY, bonds,
	    sizeof(bonds));
	ATF_CHECK_EQ(1, ble_bond_list(&ctx, &bond, 1));
	close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(sync_operation_error_matrix);
ATF_TC_BODY(sync_operation_error_matrix, tc)
{
	ble_ctx_t ctx;
	uint8_t body[IPC_MAX_PAYLOAD] = { 0 };
	uint8_t byte = 0xa5;
	size_t result_len;
	int sp[2];

	init_ctx(&ctx, -1);
	ipc_put_le16(body, 7);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 0, 7, body, 2,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 8, body, 2,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, sizeof(body),
	    NULL, 0, NULL));
	ctx.pending_count = 1;
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	ctx.pending_count = 0;
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(BLE_ERR_SOCKET, ble_errno(&ctx));

	/* Wrong frame type/domain is rejected before correlation processing. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_reply_frame(sp[1], IPC_T_HELLO, 1, 1, 0, 0, NULL, 0);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(&ctx));
	close(sp[0]); close(sp[1]);

	/* Request-id mismatch and nonzero reply flags are correlation errors. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, 1, 2, 0, 0, NULL, 0);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, 1, 2, 0, 1, NULL, 0);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	close(sp[0]); close(sp[1]);

	/* Daemon status text is mapped; an unexpected success body is bounded. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, 1, 1, IPC_ERR_BUSY, 0,
	    "busy", 4);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, NULL));
	ATF_CHECK_EQ(BLE_ERR_BUSY, ble_errno(&ctx));
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, 1, 2, 0, 0, &byte, 1);
	ATF_CHECK_EQ(-1, ble_sync_operation(&ctx, 1, 7, body, 2,
	    NULL, 0, &result_len));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(&ctx));
	close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(reply_and_event_guards);
ATF_TC_BODY(reply_and_event_guards, tc)
{
	ble_ctx_t ctx;
	struct ble_discover_op discover;
	struct ble_scan_op scan;
	uint8_t p[IPC_MAX_PAYLOAD + 32];
	size_t plen;

	init_ctx(&ctx, -1);
	callbacks = 0;
	callback_status = 0;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, 0);
	prefix(p, 0, IPC_ERR_IO, 0, IPC_GATT_EV_NOTIFY);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + 2);
	prefix(p, 0, 0, 0, IPC_GATT_EV_NOTIFY);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + 2);
	ctx.pending_count = 1;
	ctx.pending_ops[0].opcode = 9;
	ctx.pending_ops[0].cb = reply_cb;
	ble_dispatch_frame(&ctx, IPC_T_ERROR, IPC_ERR_PERM, p, 0);
	ATF_CHECK_EQ(callbacks, 1);
	ATF_CHECK_EQ(IPC_ERR_PERM, callback_status);
	ATF_CHECK_EQ(BLE_ERR_PERM, ble_errno(&ctx));

	ble_dispatch_frame(&ctx, IPC_T_OP_REPLY, 0, p, 0);
	prefix(p, 22, 0, 0, 0);
	ble_dispatch_frame(&ctx, IPC_T_OP_REPLY, 1, p, IPC_OP_PREFIX_SIZE);
	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 22;
	ctx.pending_ops[0].domain = 1;
	ctx.pending_ops[0].opcode = 3;
	ctx.pending_ops[0].cb = reply_cb;
	prefix(p, 22, 0, 1, 0);
	ble_dispatch_frame(&ctx, IPC_T_OP_REPLY, 1, p, IPC_OP_PREFIX_SIZE);
	ATF_CHECK_EQ(callbacks, 2);

	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 23;
	ctx.pending_ops[0].domain = 1;
	ctx.pending_ops[0].opcode = 4;
	ctx.pending_ops[0].cb = reply_cb;
	prefix(p, 23, IPC_ERR_IO, 0, 0);
	memset(p + IPC_OP_PREFIX_SIZE, 'x', IPC_MAX_PAYLOAD + 16 -
	    IPC_OP_PREFIX_SIZE);
	ble_dispatch_frame(&ctx, IPC_T_OP_REPLY, 1, p, IPC_MAX_PAYLOAD + 16);
	ATF_CHECK_EQ(callbacks, 3);

	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 30;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GATT;
	ctx.pending_ops[0].opcode = IPC_GATT_DISCOVER;
	ctx.pending_ops[0].arg = &discover;
	prefix(p, 30, 0, 0, IPC_GATT_EV_SERVICE);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + 2);
	plen = IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE;
	ctx.pending_ops[0].arg = NULL;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);
	memset(&discover, 0, sizeof(discover));
	ctx.pending_ops[0].arg = &discover;
	ipc_put_le16(p + IPC_OP_PREFIX_SIZE, UINT16_MAX);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);

	prefix(p, 0, 0, 0, IPC_GATT_EV_NOTIFY);
	p[IPC_OP_PREFIX_SIZE + 2] = 0;
	ipc_put_le16(p + IPC_OP_PREFIX_SIZE + 9, 0x1234);
	ipc_put_le16(p + IPC_OP_PREFIX_SIZE + 11, 0);
	ipc_put_le16(p + IPC_OP_PREFIX_SIZE + 14, 23);
	ctx.notify_cb = notify_cb;
	ctx.num_notify_subs = 1;
	ctx.notify_subs[0].handle = 1;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE);
	ATF_CHECK_EQ(callbacks, 4);

	prefix(p, 40, 0, 0, IPC_GAP_EV_SCAN_RESULT);
	plen = IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE;
	ctx.pending_count = 0;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 40;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GAP;
	ctx.pending_ops[0].opcode = IPC_GAP_SCAN;
	ctx.pending_ops[0].arg = NULL;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	memset(&scan, 0, sizeof(scan));
	ctx.pending_ops[0].arg = &scan;
	p[IPC_OP_PREFIX_SIZE + 4] = 2;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p, plen);
	ble_dispatch_frame(&ctx, IPC_T_HELLO, 0, p, 0);
	ble_dispatch_frame(&ctx, UINT16_MAX, 0, p, 0);
}

ATF_TC_WITHOUT_HEAD(stream_guard_matrix);
ATF_TC_BODY(stream_guard_matrix, tc)
{
	ble_ctx_t ctx;
	uint8_t hdr[IPC_HDR_SIZE];
	int sp[2];

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	init_ctx(&ctx, sp[0]);
	ctx.rxlen = sizeof(ctx.rxbuf);
	ATF_REQUIRE_EQ(send(sp[1], "x", 1, 0), 1);
	ATF_CHECK_EQ(ble_process_framed(&ctx), 0);
	ATF_CHECK_EQ(ble_process_framed(&ctx), 0);
	ipc_hdr_encode(hdr, 4, IPC_T_ERROR, 0);
	ATF_REQUIRE_EQ(send(sp[1], hdr, sizeof(hdr), 0), (ssize_t)sizeof(hdr));
	ATF_CHECK_EQ(ble_process_framed(&ctx), 0);
	ctx.rxlen = 0;
	ipc_hdr_encode(hdr, IPC_MAX_PAYLOAD + 1, IPC_T_ERROR, 0);
	ATF_REQUIRE_EQ(send(sp[1], hdr, sizeof(hdr), 0), (ssize_t)sizeof(hdr));
	ATF_CHECK_EQ(ble_process_framed(&ctx), -1);
	ATF_CHECK_EQ(ctx.last_error, BLE_ERR_PROTO);
	close(sp[1]);
	ATF_CHECK_EQ(ble_process_framed(&ctx), -1);
	close(sp[0]);
}

ATF_TC_WITHOUT_HEAD(operation_event_decode_matrix);
ATF_TC_BODY(operation_event_decode_matrix, tc)
{
	ble_ctx_t ctx;
	struct ble_discover_op discover;
	struct ble_scan_op scan;
	uint8_t p[IPC_MAX_PAYLOAD + 32], *body;
	size_t plen;

	init_ctx(&ctx, -1);
	callbacks = 0;
	ctx.write_cb = write_cb;
	ctx.read_req_cb = read_req_cb;
	ctx.authorize_cb = authorize_cb;
	ctx.passkey_input_cb = addr_cb;
	ctx.passkey_display_cb = value_cb;
	ctx.numcmp_cb = value_cb;
	ctx.keypress_cb = keypress_cb;
	ctx.connected_cb = conn_cb;
	ctx.disconnected_cb = disconn_cb;
	ctx.iso_req_cb = iso_req_cb;
	ctx.iso_est_cb = iso_est_cb;

	memset(&discover, 0, sizeof(discover));
	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 10;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GATT;
	ctx.pending_ops[0].opcode = IPC_GATT_DISCOVER;
	ctx.pending_ops[0].arg = &discover;
	plen = IPC_OP_PREFIX_SIZE + IPC_GATT_DISCOVERY_EVENT_SIZE;
	prefix(p, 10, 0, 0, IPC_GATT_EV_SERVICE);
	body = p + IPC_OP_PREFIX_SIZE;
	ipc_put_le16(body + 2, 0x180f);
	ipc_put_le16(body + 20, 1);
	ipc_put_le16(body + 22, 5);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);
	ATF_CHECK_EQ(1, discover.nsvc);
	prefix(p, 10, 0, 0, IPC_GATT_EV_CHARACTERISTIC);
	body = p + IPC_OP_PREFIX_SIZE;
	ipc_put_le16(body + 2, 0x2a19);
	ipc_put_le16(body + 20, 2);
	body[22] = 0x02;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p, plen);
	ATF_CHECK_EQ(1, discover.nchar);

	prefix(p, 0, 0, 0, IPC_GATT_EV_WRITE);
	body = p + IPC_OP_PREFIX_SIZE;
	ipc_put_le16(body + 2, 3);
	ipc_put_le16(body + 4, 2);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE + 2);
	ipc_put_le16(body + 4, 3);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_VALUE_EVENT_SIZE + 2);
	prefix(p, 0, 0, 0, IPC_GATT_EV_READ);
	body = p + IPC_OP_PREFIX_SIZE;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_READ_EVENT_SIZE);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + 2);
	prefix(p, 0, 0, 0, IPC_GATT_EV_AUTHORIZE);
	body = p + IPC_OP_PREFIX_SIZE;
	body[2] = 1;
	body[11] = 1;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_AUTHORIZE_EVENT_SIZE);
	body[11] = 2;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_AUTHORIZE_EVENT_SIZE);
	prefix(p, 0, 0, 0, IPC_GATT_EV_NOTIFY);
	body = p + IPC_OP_PREFIX_SIZE;
	body[2] = 0;
	ipc_put_le16(body + 9, 7);
	ipc_put_le16(body + 11, 2);
	ipc_put_le16(body + 14, 23);
	ctx.num_notify_subs = 1;
	ctx.notify_subs[0].handle = 7;
	ctx.notify_subs[0].cb = notify_cb;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 2);
	ipc_put_le16(body + 11, 3);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, p,
	    IPC_OP_PREFIX_SIZE + IPC_GATT_NOTIFY_EVENT_SIZE + 2);

	prefix(p, 0, 0, 0, IPC_SECURITY_EV_PASSKEY_INPUT);
	body = p + IPC_OP_PREFIX_SIZE;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, p,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_INPUT_EVENT_SIZE);
	for (uint16_t event = IPC_SECURITY_EV_PASSKEY_DISPLAY;
	    event <= IPC_SECURITY_EV_NUMCMP; event++) {
		prefix(p, 0, 0, 0, event);
		body = p + IPC_OP_PREFIX_SIZE;
		ipc_put_le32(body + 9, 123456);
		ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, p,
		    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	}
	prefix(p, 0, 0, 0, IPC_SECURITY_EV_KEYPRESS);
	body = p + IPC_OP_PREFIX_SIZE;
	body[9] = BLE_KEYPRESS_COMPLETED;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, p,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_KEYPRESS_EVENT_SIZE);
	prefix(p, 0, 0, 0, IPC_SECURITY_EV_PASSKEY_DISPLAY);
	body = p + IPC_OP_PREFIX_SIZE;
	ipc_put_le32(body + 9, 1000000);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, p,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_PASSKEY_EVENT_SIZE);
	prefix(p, 1, 0, 0, IPC_SECURITY_EV_PASSKEY_INPUT);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_SECURITY, p,
	    IPC_OP_PREFIX_SIZE + IPC_SECURITY_INPUT_EVENT_SIZE);

	for (uint16_t event = IPC_ISO_EV_CIS_REQUEST;
	    event <= IPC_ISO_EV_ESTABLISHED; event++) {
		prefix(p, 0, 0, 0, event);
		body = p + IPC_OP_PREFIX_SIZE;
		ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, p,
		    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	}
	prefix(p, 0, 0, 0, UINT16_MAX);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, p,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);
	body = p + IPC_OP_PREFIX_SIZE;
	body[2] = 2;
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_ISO, p,
	    IPC_OP_PREFIX_SIZE + IPC_ISO_EVENT_SIZE);

	memset(&scan, 0, sizeof(scan));
	scan.cb = scan_cb;
	ctx.pending_count = 1;
	ctx.pending_ops[0].id = 20;
	ctx.pending_ops[0].domain = IPC_OP_DOMAIN_GAP;
	ctx.pending_ops[0].opcode = IPC_GAP_SCAN;
	ctx.pending_ops[0].arg = &scan;
	prefix(p, 20, 0, 0, IPC_GAP_EV_SCAN_RESULT);
	body = p + IPC_OP_PREFIX_SIZE;
	body[4] = 1;
	body[14] = 2;
	body[15] = 4;
	ipc_put_le16(body + 16, 0x180d);
	ipc_put_le16(body + 18, 0x180f);
	memcpy(body + 32, "name", 4);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_SCAN_RESULT_EVENT_SIZE);
	ATF_CHECK(ctx.rssi_valid);
	prefix(p, 0, 0, 0, IPC_GAP_EV_CONNECTED);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_CONNECTED_EVENT_SIZE);
	ATF_CHECK(ble_is_connected(&ctx));
	prefix(p, 0, 0, 0, IPC_GAP_EV_DISCONNECTED);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p,
	    IPC_OP_PREFIX_SIZE + IPC_GAP_DISCONNECTED_EVENT_SIZE);
	ATF_CHECK(!ble_is_connected(&ctx));
	prefix(p, 0, 0, 0, UINT16_MAX);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, IPC_OP_DOMAIN_GAP, p,
	    IPC_OP_PREFIX_SIZE + 2);
	ble_dispatch_frame(&ctx, IPC_T_OP_EVENT, UINT16_MAX, p,
	    IPC_OP_PREFIX_SIZE + 2);
	ATF_CHECK(callbacks >= 12);
}

ATF_TC_WITHOUT_HEAD(callback_and_encoder_matrix);
ATF_TC_BODY(callback_and_encoder_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	ble_characteristic_t chr;
	ble_security_policy_t policy;
	struct ble_battery_op *battery;
	struct ble_discover_op *discover;
	struct ble_read_op *readop;
	uint8_t payload[IPC_GATT_READ_REPLY_SIZE + 2] = { 0 };
	uint16_t handle = 0;

	init_ctx(&ctx, -1);
	memset(&addr, 0, sizeof(addr));
	callbacks = 0;

	for (int cap = BLE_IO_DISPLAY_ONLY; cap <= BLE_IO_KEYBOARD_DISPLAY; cap++)
		ATF_CHECK(ble_io_cap_str((ble_io_cap_t)cap) != NULL);
	ATF_CHECK(ble_io_cap_str((ble_io_cap_t)255) == NULL);
	ATF_CHECK(ble_past_params_valid(0, 0, 0x000a));
	ATF_CHECK(!ble_past_params_valid(4, 0, 0x000a));
	ATF_CHECK(ble_key_dist_valid(BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID));
	ATF_CHECK(!ble_key_dist_valid(0x80));

	memset(&policy, 0, sizeof(policy));
	policy.mitm = true;
	policy.bonding = true;
	policy.keypress = true;
	policy.io_cap = BLE_IO_KEYBOARD_DISPLAY;
	policy.key_dist = BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID;
	ATF_CHECK_EQ(-1, ble_send_security_policy(&ctx, UINT16_MAX, &policy));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_peer(&ctx, NULL, 0, true));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_peer(&ctx, &addr, 16, false));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_peer(&ctx, &addr, 1, true));
	ATF_CHECK_EQ(-1, ble_periodic_adv_list_peer(&ctx, &addr, 1, false));
	ATF_CHECK_EQ(-1, ble_past_params(&ctx, &addr, 1, 0, 0x000a, 0));
	ATF_CHECK_EQ(-1, ble_past_default_params(&ctx, 0, 1, 0, 0x000a, 0));

	ble_gatt_handle_reply(&ctx, IPC_GATT_ADD_SERVICE, IPC_ERR_IO, payload,
	    0, &handle);
	ble_gatt_handle_reply(&ctx, IPC_GATT_ADD_SERVICE, IPC_ERR_NONE, payload,
	    1, &handle);
	ipc_put_le16(payload, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(payload + 2, 0x1234);
	ble_gatt_handle_reply(&ctx, IPC_GATT_ADD_SERVICE, IPC_ERR_NONE, payload,
	    IPC_GATT_HANDLE_REPLY_SIZE, &handle);
	ATF_CHECK_EQ(0x1234, handle);

	discover = calloc(1, sizeof(*discover));
	ATF_REQUIRE(discover != NULL);
	discover->cb = discover_cb;
	discover->nsvc = 1;
	discover->nchar = 1;
	ble_discover_reply(&ctx, 0, IPC_ERR_NONE, NULL, 0, discover);
	ble_discover_reply(&ctx, 0, IPC_ERR_NONE, NULL, 0, NULL);

	readop = calloc(1, sizeof(*readop));
	ATF_REQUIRE(readop != NULL);
	readop->cb = gatt_read_cb;
	ble_read_reply(&ctx, IPC_GATT_READ, IPC_ERR_IO, payload, 0, readop);
	readop = calloc(1, sizeof(*readop));
	ATF_REQUIRE(readop != NULL);
	readop->cb = gatt_read_cb;
	ble_read_reply(&ctx, IPC_GATT_READ, IPC_ERR_NONE, payload, 1, readop);
	readop = calloc(1, sizeof(*readop));
	ATF_REQUIRE(readop != NULL);
	readop->cb = gatt_read_cb;
	ipc_put_le16(payload, IPC_GATT_READ);
	ipc_put_le16(payload + 2, 0x42);
	ipc_put_le16(payload + 4, 2);
	ble_read_reply(&ctx, IPC_GATT_READ, IPC_ERR_NONE, payload,
	    sizeof(payload), readop);
	ble_read_reply(&ctx, IPC_GATT_READ, IPC_ERR_NONE, payload,
	    sizeof(payload), NULL);

	memset(&chr, 0, sizeof(chr));
	chr.uuid.uuid16 = BLE_CHR_BATTERY_LEVEL;
	chr.handle = 0x44;
	battery = calloc(1, sizeof(*battery));
	ATF_REQUIRE(battery != NULL);
	battery->ctx = &ctx;
	battery->cb = gatt_read_cb;
	battery_discover_done(&addr, NULL, 0, &chr, 1, battery);
	battery = calloc(1, sizeof(*battery));
	ATF_REQUIRE(battery != NULL);
	battery->ctx = &ctx;
	battery->cb = gatt_read_cb;
	battery_discover_done(&addr, NULL, 0, &chr, 0, battery);
	ATF_CHECK(callbacks >= 6);
}

ATF_TC_WITHOUT_HEAD(subscription_state_send_failure_matrix);
ATF_TC_BODY(subscription_state_send_failure_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	int i;

	init_ctx(&ctx, -1);
	memset(&addr, 0, sizeof(addr));
	addr.addr_type = 1;

	ATF_CHECK_EQ(-1, ble_subscribe(&ctx, NULL, 0x0100, notify_cb, &ctx));
	ATF_CHECK(ctx.notify_cb == NULL);
	ATF_CHECK(ctx.notify_arg == NULL);
	ATF_CHECK_EQ(0, ctx.num_notify_subs);

	ATF_CHECK_EQ(-1, ble_subscribe(&ctx, &addr, 0x0101, notify_cb, &ctx));
	ATF_CHECK_EQ(0, ctx.num_notify_subs);

	ctx.num_notify_subs = 1;
	ctx.notify_subs[0].handle = 0x0102;
	ctx.notify_subs[0].cb = NULL;
	ctx.notify_subs[0].arg = NULL;
	ATF_CHECK_EQ(-1, ble_subscribe(&ctx, &addr, 0x0102, notify_cb, &ctx));
	ATF_CHECK_EQ(1, ctx.num_notify_subs);
	ATF_CHECK_EQ(0x0102, ctx.notify_subs[0].handle);
	ATF_CHECK(ctx.notify_subs[0].cb == NULL);
	ATF_CHECK(ctx.notify_subs[0].arg == NULL);

	ctx.num_notify_subs = MAX_NOTIFY_SUBS;
	for (i = 0; i < MAX_NOTIFY_SUBS; i++) {
		ctx.notify_subs[i].handle = 0x0200 + i;
		ctx.notify_subs[i].cb = NULL;
		ctx.notify_subs[i].arg = NULL;
	}
	ctx.notify_cb = NULL;
	ctx.notify_arg = NULL;
	ATF_CHECK_EQ(-1, ble_subscribe(&ctx, &addr, 0x0300, notify_cb, &ctx));
	ATF_CHECK_EQ(MAX_NOTIFY_SUBS, ctx.num_notify_subs);
	ATF_CHECK(ctx.notify_cb == NULL);
	ATF_CHECK(ctx.notify_arg == NULL);

	ctx.num_notify_subs = 1;
	ctx.notify_subs[0].handle = 0x0400;
	ctx.notify_subs[0].cb = notify_cb;
	ctx.notify_subs[0].arg = &ctx;
	ATF_CHECK_EQ(-1, ble_unsubscribe(&ctx, &addr, 0x0400));
	ATF_CHECK_EQ(1, ctx.num_notify_subs);
	ATF_CHECK_EQ(0x0400, ctx.notify_subs[0].handle);
	ATF_CHECK(ctx.notify_subs[0].cb == notify_cb);
	ATF_CHECK(ctx.notify_subs[0].arg == &ctx);
}

ATF_TC_WITHOUT_HEAD(fd_receive_matrix);
ATF_TC_BODY(fd_receive_matrix, tc)
{
	ble_ctx_t ctx;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	char control[CMSG_SPACE(sizeof(int))];
	char byte = 'x';
	int sp[2], pp[2], received = -1;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	ATF_REQUIRE_EQ(0, pipe(pp));
	init_ctx(&ctx, sp[0]);
	ATF_REQUIRE_EQ(1, send(sp[1], &byte, 1, 0));
	ATF_CHECK_EQ(-1, ble_recv_fd(&ctx, 100, &received));

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &pp[0], sizeof(int));
	ATF_REQUIRE_EQ(1, sendmsg(sp[1], &msg, 0));
	ATF_CHECK_EQ(0, ble_recv_fd(&ctx, 100, &received));
	ATF_CHECK(received >= 0);
	close(received);
	close(pp[0]); close(pp[1]); close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(gatt_acquire_protocol_matrix);
ATF_TC_BODY(gatt_acquire_protocol_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	uint8_t metadata[IPC_GATT_ACQUIRE_REPLY_SIZE] = { 0 };
	int sp[2], out = -1;
	uint16_t mtu = 0;

	memset(&addr, 0, sizeof(addr));
	init_ctx(&ctx, -1);
	ctx.pending_count = 1;
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
	ctx.pending_count = 0;
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));

	/* Malformed envelope. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_reply_frame(sp[1], IPC_T_HELLO, IPC_OP_DOMAIN_GATT, 1, 0, 0,
	    NULL, 0);
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
	close(sp[0]); close(sp[1]);

	/* Correlation identifier and flags are both strict. */
	for (int arm = 0; arm < 2; arm++) {
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
		init_ctx(&ctx, sp[0]);
		stage_reply_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT,
		    arm == 0 ? 2 : 1, 0, arm == 0 ? 0 : 1, NULL, 0);
		ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
		    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
		close(sp[0]); close(sp[1]);
	}

	/* A daemon error preserves its explanatory payload. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, 1,
	    IPC_ERR_BUSY, 0, "busy", 4);
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
	ATF_CHECK_EQ(BLE_ERR_BUSY, ble_errno(&ctx));
	close(sp[0]); close(sp[1]);

	/* The reply metadata must name the requested acquire operation. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ipc_put_le16(metadata, IPC_GATT_ACQUIRE_WRITE);
	ipc_put_le16(metadata + 2, 247);
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, 1, 0, 0,
	    metadata, sizeof(metadata));
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
	close(sp[0]); close(sp[1]);

	/* Events interleaved before a valid reply are dispatched and skipped;
	 * closing the peer then reaches the missing-SCM_RIGHTS failure. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ctx.next_request_id = UINT32_MAX;
	stage_reply_frame(sp[1], IPC_T_OP_EVENT, IPC_OP_DOMAIN_GATT, 0, 0, 0,
	    NULL, 0);
	ipc_put_le16(metadata, IPC_GATT_ACQUIRE_NOTIFY);
	stage_reply_frame(sp[1], IPC_T_OP_REPLY, IPC_OP_DOMAIN_GATT, 1, 0, 0,
	    metadata, sizeof(metadata));
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
	ATF_CHECK_EQ(-1, ble_acquire_typed_gatt(&ctx,
	    IPC_GATT_ACQUIRE_NOTIFY, &addr, 1, &out, &mtu));
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(&ctx));
	close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(public_guard_and_snapshot_matrix);
ATF_TC_BODY(public_guard_and_snapshot_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	ble_conn_params_t cp;
	ble_adv_params_t ap;
	ble_bond_t bond;
	ble_resolv_entry_t entry;
	ble_adapter_caps_t caps;
	ble_oob_sc_t oob;
	uint8_t body[IPC_SECURITY_BOND_REPLY_HDR_SIZE +
	    IPC_SECURITY_BOND_RECORD_SIZE];
	uint8_t rbody[IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
	    IPC_SECURITY_RESOLV_RECORD_SIZE];
	char long_name[40];
	int sp[2], out = -1;

	memset(&addr, 0, sizeof(addr));
	init_ctx(&ctx, -1);
	memset(&cp, 0, sizeof(cp));
	cp.interval_min = 20; cp.interval_max = 10;
	ATF_CHECK_EQ(-1, ble_connect_params(&ctx, &addr, &cp, NULL, NULL));
	memset(long_name, 'x', sizeof(long_name));
	long_name[sizeof(long_name) - 1] = '\0';
	ATF_CHECK_EQ(-1, ble_connect_name(&ctx, 0, long_name, NULL, NULL));
	ATF_CHECK_EQ(-1, ble_acquire_notify(&ctx, NULL, 1, &out, NULL));
	ctx.fdpass_ok = true;
	ATF_CHECK_EQ(-1, ble_acquire_iso(&ctx, &addr, 0x40, &out));

	/* A directed advertising request encodes its peer before the expected
	 * disconnected-socket failure. */
	memset(&ap, 0, sizeof(ap));
	ap.has_peer = true;
	ap.peer.addr_type = 1;
	ap.interval_min = ap.interval_max = 0x20;
	ATF_CHECK_EQ(-1, ble_set_adv_params(&ctx, &ap));

	/* Successful envelopes with malformed typed bodies reach each snapshot
	 * validator rather than the generic synchronous-operation guards. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_CTL, NULL, 0);
	ATF_CHECK_EQ(-1, ble_adapter_caps(&ctx, 0, &caps));
	close(sp[0]); close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, NULL, 0);
	ATF_CHECK_EQ(-1, ble_oob_sc_generate(&ctx, &oob));
	close(sp[0]); close(sp[1]);

	memset(body, 0, sizeof(body));
	ipc_put_le16(body, IPC_SECURITY_BOND_LIST);
	ipc_put_le16(body + 2, 1);
	body[IPC_SECURITY_BOND_REPLY_HDR_SIZE] = 2; /* invalid addr type */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, body, sizeof(body));
	ATF_CHECK_EQ(-1, ble_bond_list(&ctx, &bond, 1));
	close(sp[0]); close(sp[1]);

	memset(rbody, 0, sizeof(rbody));
	ipc_put_le16(rbody, IPC_SECURITY_RESOLV_LIST);
	ipc_put_le16(rbody + 2, 1);
	rbody[IPC_SECURITY_RESOLV_REPLY_HDR_SIZE] = 2;
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, rbody,
	    sizeof(rbody));
	ATF_CHECK_EQ(-1, ble_resolv_entries(&ctx, &entry, 1));
	close(sp[0]); close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, NULL, 0);
	ATF_CHECK(ble_bond_export(&ctx, &addr) == NULL);
	close(sp[0]); close(sp[1]);

	/* CoC validates the typed acquisition metadata after a valid exchange. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]); ctx.fdpass_ok = true;
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_L2CAP, NULL, 0);
	ATF_CHECK_EQ(-1, ble_acquire_coc(&ctx, &addr, 0x80, &out));
	close(sp[0]); close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(periodic_properties_spec_mask);
ATF_TC_BODY(periodic_properties_spec_mask, tc)
{
	ble_ctx_t ctx;
	int sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_PERIODIC, NULL, 0);
	ATF_CHECK_EQ(0, ble_periodic_adv_params(&ctx, 0, 0x0006, 0x0006,
	    BLE_PERIODIC_ADV_PROP_INCLUDE_TX_POWER));
	close(sp[0]);
	close(sp[1]);
}

ATF_TC_WITHOUT_HEAD(remaining_public_and_reply_matrix);
ATF_TC_BODY(remaining_public_and_reply_matrix, tc)
{
	ble_ctx_t ctx;
	ble_addr_t addr;
	ble_adv_set_t set;
	ble_adapter_caps_t caps;
	ble_security_policy_t policy;
	ble_security_info_t security;
	ble_oob_sc_t oob;
	ble_resolv_entry_t entries[2];
	ble_ecbfc_session_t *session;
	struct ble_connect_op *cop;
	struct ble_bond_record rec;
	uint8_t hdr[IPC_HDR_SIZE], request[16];
	uint8_t iso_reply[IPC_ISO_ACQUIRE_REPLY_SIZE];
	uint8_t resolv[IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
	    2 * IPC_SECURITY_RESOLV_RECORD_SIZE];
	uint8_t byte = 0;
	int sp[2], out;

	memset(&addr, 0, sizeof(addr));
	init_ctx(&ctx, -1);
	/* Public guards and send-failure cleanup paths. */
	ATF_CHECK_EQ(-1, ble_handshake(&ctx));
	ATF_CHECK_EQ(-1, ble_scan_filtered(&ctx, NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, ble_adapter_caps(&ctx, 70000, NULL));
	ATF_CHECK_EQ(-1, ble_set_rpa_timeout(&ctx, 30));
	ATF_CHECK_EQ(-1, ble_get_security_info(&ctx, NULL, NULL));
	ATF_CHECK_EQ(-1, ble_read_battery(&ctx, &addr, NULL, NULL));
	memset(&set, 0, sizeof(set));
	set.ctx = &ctx;
	ATF_CHECK_EQ(-1, ble_adv_set_params(&set, 0, 0x10, 0x20, 1, 1));
	ATF_CHECK_EQ(-1, ble_adv_set_data(&set, NULL, 1));
	memset(&rec, 0, sizeof(rec));
	rec.data = &byte;
	rec.len = UINT16_MAX;
	ATF_CHECK_EQ(-1, ble_bond_import(&ctx, &rec));
	ATF_CHECK_EQ(-1, ble_adapter_caps(&ctx, 0, &caps));
	ATF_CHECK_EQ(-1, ble_get_security_policy(&ctx, &policy));
	ATF_CHECK_EQ(-1, ble_get_security_info(&ctx, &addr, &security));
	ATF_CHECK_EQ(-1, ble_oob_sc_generate(&ctx, &oob));
	ctx.fdpass_ok = true;
	ATF_CHECK_EQ(-1, ble_acquire_coc(&ctx, &addr, 0x80, &out));
	ATF_CHECK_EQ(-1, ble_ecbfc_session_open(&ctx, &addr, 0x80, 1,
	    &session));

	/* CONNECT_NAME callback handling tolerates absent state and rejects a
	 * malformed successful address reply before invoking the callback. */
	ble_connect_reply(&ctx, IPC_GAP_CONNECT_NAME, IPC_ERR_NONE, &byte, 1,
	    NULL);
	cop = calloc(1, sizeof(*cop));
	ATF_REQUIRE(cop != NULL);
	ble_connect_reply(&ctx, IPC_GAP_CONNECT_NAME, IPC_ERR_NONE, &byte, 1,
	    cop);
	ATF_CHECK_EQ(BLE_ERR_PROTO, ble_errno(&ctx));

	/* A non-HELLO handshake reply is rejected after a successful send. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ipc_hdr_encode(hdr, 0, UINT16_MAX, 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr),
	    send(sp[1], hdr, sizeof(hdr), 0));
	ATF_CHECK_EQ(-1, ble_handshake(&ctx));
	close(sp[0]); close(sp[1]);

	/* Exact frame-reader EOF, oversize, payload-timeout and payload-EOF
	 * boundaries, plus the fd-reader timeout. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
	{
		uint16_t type, arg;
		size_t len;
		ATF_CHECK_EQ(-1, ble_read_one_frame(&ctx, &type, &arg, &byte,
		    &len, 0));
	}
	close(sp[0]); close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ipc_hdr_encode(hdr, IPC_MAX_PAYLOAD + 1, IPC_T_HELLO, 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), send(sp[1], hdr, sizeof(hdr), 0));
	{
		uint16_t type, arg;
		size_t len;
		ATF_CHECK_EQ(-1, ble_read_one_frame(&ctx, &type, &arg, &byte,
		    &len, 0));
	}
	close(sp[0]); close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ipc_hdr_encode(hdr, 1, IPC_T_HELLO, 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), send(sp[1], hdr, sizeof(hdr), 0));
	{
		uint16_t type, arg;
		size_t len;
		ATF_CHECK_EQ(-1, ble_read_one_frame(&ctx, &type, &arg, &byte,
		    &len, 0));
	}
	close(sp[0]); close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ipc_hdr_encode(hdr, 1, IPC_T_HELLO, 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), send(sp[1], hdr, sizeof(hdr), 0));
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
	{
		uint16_t type, arg;
		size_t len;
		ATF_CHECK_EQ(-1, ble_read_one_frame(&ctx, &type, &arg, &byte,
		    &len, 0));
		ATF_CHECK_EQ(-1, ble_recv_fd(&ctx, 0, &out));
	}
	close(sp[0]); close(sp[1]);

	/* A connected socket reaches WRITE_CMD's successful queueing path. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	ATF_CHECK_EQ(0, ble_write_no_response(&ctx, &addr, 1, NULL, 0));
	close(sp[0]); close(sp[1]);

	/* Correct CoC/ECBFC metadata followed by a missing descriptor reaches
	 * each fd-handoff cleanup path. */
	{
		uint8_t coc[IPC_L2CAP_ACQUIRE_REPLY_SIZE] = { 0 };
		ipc_put_le16(coc, IPC_L2CAP_ACQUIRE_COC);
		coc[2] = 1;
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
		init_ctx(&ctx, sp[0]); ctx.fdpass_ok = true;
		stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_L2CAP, coc,
		    sizeof(coc));
		ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
		ATF_CHECK_EQ(-1, ble_acquire_coc(&ctx, &addr, 0x80, &out));
		close(sp[0]); close(sp[1]);

		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
		init_ctx(&ctx, sp[0]); ctx.fdpass_ok = true;
		stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_L2CAP, coc,
		    sizeof(coc));
		ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
		ATF_CHECK_EQ(-1, ble_ecbfc_session_open(&ctx, &addr, 0x80, 1,
		    &session));
		close(sp[0]); close(sp[1]);
	}

	/* Session close closes every installed descriptor. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	session = calloc(1, sizeof(*session));
	ATF_REQUIRE(session != NULL);
	session->count = 1;
	session->fds[0] = sp[0];
	ble_ecbfc_session_close(session);
	close(sp[1]);

	/* ISO acquisition: validate metadata, then validate the mandatory
	 * SCM_RIGHTS handout after a correct reply. */
	memset(request, 0, sizeof(request));
	ipc_put_le16(request, IPC_ISO_ACQUIRE);
	memset(iso_reply, 0, sizeof(iso_reply));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_ISO, NULL, 0);
	ATF_CHECK_EQ(-1, ble_acquire_typed_iso_fd(&ctx, IPC_ISO_ACQUIRE,
	    request, sizeof(request), &out));
	close(sp[0]); close(sp[1]);

	ipc_put_le16(iso_reply, IPC_ISO_ACQUIRE);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_ISO, iso_reply,
	    sizeof(iso_reply));
	ATF_REQUIRE_EQ(0, shutdown(sp[1], SHUT_WR));
	ATF_CHECK_EQ(-1, ble_acquire_typed_iso_fd(&ctx, IPC_ISO_ACQUIRE,
	    request, sizeof(request), &out));
	close(sp[0]); close(sp[1]);

	/* Snapshot count truncation and over-capacity rejection. */
	memset(resolv, 0, sizeof(resolv));
	ipc_put_le16(resolv, IPC_SECURITY_RESOLV_LIST);
	ipc_put_le16(resolv + 2, 2);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, resolv,
	    sizeof(resolv));
	ATF_CHECK_EQ(1, ble_resolv_entries(&ctx, entries, 1));
	close(sp[0]); close(sp[1]);

	ipc_put_le16(resolv + 2, BLE_MAX_BONDS + 1);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	init_ctx(&ctx, sp[0]);
	stage_sync_reply(sp[1], 1, IPC_OP_DOMAIN_SECURITY, resolv,
	    IPC_SECURITY_RESOLV_REPLY_HDR_SIZE);
	ATF_CHECK_EQ(-1, ble_resolv_entries(&ctx, entries, 1));
	close(sp[0]); close(sp[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, send_and_error_matrix);
	ATF_TP_ADD_TC(tp, reply_and_event_guards);
	ATF_TP_ADD_TC(tp, discovery_and_scan_guard_matrix);
	ATF_TP_ADD_TC(tp, iso_argument_guard_matrix);
	ATF_TP_ADD_TC(tp, sync_reply_success_matrix);
	ATF_TP_ADD_TC(tp, sync_operation_error_matrix);
	ATF_TP_ADD_TC(tp, stream_guard_matrix);
	ATF_TP_ADD_TC(tp, operation_event_decode_matrix);
	ATF_TP_ADD_TC(tp, callback_and_encoder_matrix);
	ATF_TP_ADD_TC(tp, subscription_state_send_failure_matrix);
	ATF_TP_ADD_TC(tp, fd_receive_matrix);
	ATF_TP_ADD_TC(tp, gatt_acquire_protocol_matrix);
	ATF_TP_ADD_TC(tp, public_guard_and_snapshot_matrix);
	ATF_TP_ADD_TC(tp, periodic_properties_spec_mask);
	ATF_TP_ADD_TC(tp, remaining_public_and_reply_matrix);
	return (atf_no_error());
}
