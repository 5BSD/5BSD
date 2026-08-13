/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * App-platform completeness tests for the ATT server: dynamic reads and
 * per-access authorization for app-backed (owner_fd >= 0) characteristics.
 *
 * These close two gaps that let a third-party app back a characteristic with
 * live code over the ctl IPC:
 *
 *   1. DYNAMIC READ — a peer read of a characteristic flagged
 *      ATT_ATTR_F_DYNAMIC is withheld; the server asks the owning app for the
 *      value (blued_ctl_notify_read -> EVENT READ) and completes the ATT
 *      Read/Read-Blob response only when the app supplies bytes
 *      (att_server_complete_read) or declines (att_server_reject_read).
 *
 *   2. AUTHORIZATION — a read/write of a characteristic flagged
 *      ATT_ATTR_F_AUTHORIZE is withheld; the app allows or denies it
 *      (att_server_complete_authorize).  A denial yields ATT Insufficient
 *      Authorization (0x08).
 *
 * ORACLE: response opcodes, error codes and Read-Blob slicing are hand-derived
 * from the Bluetooth Core Specification (ATT = Vol 3 Part F §3.4; the 0x08
 * Insufficient Authorization code = Table 3.4 / Part G §8.2), never captured
 * from the implementation's own output.
 *
 * A SOCK_SEQPACKET socketpair stands in for the L2CAP ATT channel; the server
 * responses are drained with MSG_DONTWAIT.  The owning app is represented by
 * capturing stubs of the ctl notify emitters (TEST_CUSTOM_CTL_NOTIFY), so the
 * app-facing EVENT arguments are asserted directly and the app "reply" is the
 * matching att_server_* completion call.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "hci_log.h"

#define TEST_CUSTOM_CTL_NOTIFY
#include "test_common.h"

#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	1024
#define TEST_OWNER_FD		42

/* ================================================================
 * Captured app-facing EVENT emissions (the owning app's inbox).
 * ================================================================ */
static struct {
	int		read_calls;
	int		read_owner;
	uint16_t	read_handle;
	uint16_t	read_offset;

	int		auth_calls;
	int		auth_owner;
	uint16_t	auth_handle;
	bool		auth_write;

	int		write_calls;
	uint16_t	write_handle;
	uint8_t		write_val[512];
	uint16_t	write_len;
} cap;

static void
cap_reset(void)
{

	memset(&cap, 0, sizeof(cap));
}

void
blued_ctl_notify_value(struct blued_conn *conn __unused, uint16_t handle __unused,
    const uint8_t *value __unused, uint16_t len __unused,
    uint16_t bearer_mtu __unused)
{
}

void
blued_ctl_notify_write(int owner_fd __unused, uint16_t handle,
    const uint8_t *value, uint16_t len)
{

	cap.write_calls++;
	cap.write_handle = handle;
	cap.write_len = len > sizeof(cap.write_val) ?
	    (uint16_t)sizeof(cap.write_val) : len;
	memcpy(cap.write_val, value, cap.write_len);
}

void
blued_ctl_notify_read(int owner_fd, uint16_t handle, uint16_t offset)
{

	cap.read_calls++;
	cap.read_owner = owner_fd;
	cap.read_handle = handle;
	cap.read_offset = offset;
}

void
blued_ctl_notify_authorize(int owner_fd, uint16_t handle, bool is_write,
    const struct att_conn *ac __unused)
{

	cap.auth_calls++;
	cap.auth_owner = owner_fd;
	cap.auth_handle = handle;
	cap.auth_write = is_write;
}

/* ================================================================
 * Fixture: a small GATT database of app-backed characteristics.
 * ================================================================ */
struct fixture {
	struct att_conn		ac;
	int			peer_fd;
	struct att_db		db;
	struct att_attr		attrs[TEST_DB_MAX_ATTRS];
	uint8_t			valbuf[TEST_DB_VAL_SIZE];
	uint16_t		h_static;	/* stored-value read */
	uint16_t		h_dynamic;	/* dynamic read */
	uint16_t		h_auth_read;	/* authorize + stored value */
	uint16_t		h_auth_write;	/* authorize + writable */
	uint16_t		h_dyn_auth;	/* dynamic + authorize read */
};

static void
set_flags_owner(struct att_db *db, uint16_t handle, uint8_t flags)
{
	struct att_attr *a = attdb_find_by_handle(db, handle);

	ATF_REQUIRE(a != NULL);
	a->flags = flags;
	a->owner_fd = TEST_OWNER_FD;
}

static void
fx_setup(struct fixture *fx)
{
	static const uint8_t static_val[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
	static const uint8_t seed[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	int fds[2];

	cap_reset();
	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);

	memset(&fx->ac, 0, sizeof(fx->ac));
	fx->ac.fd = fds[0];
	fx->ac.bearer_fd = -1;
	fx->ac.mtu = ATT_PDU_BUF_SIZE;
	fx->ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(fx->ac.buf != NULL);
	fx->peer_fd = fds[1];

	attdb_init(&fx->db, fx->attrs, TEST_DB_MAX_ATTRS,
	    fx->valbuf, TEST_DB_VAL_SIZE);
	ATF_REQUIRE(attdb_add_service(&fx->db, 0x1800) != 0);

	fx->h_static = attdb_add_characteristic(&fx->db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, static_val, sizeof(static_val));
	ATF_REQUIRE(fx->h_static != 0);

	fx->h_dynamic = attdb_add_characteristic(&fx->db, 0x2A01,
	    GATT_PROP_READ, ATT_PERM_READ, NULL, 0);
	ATF_REQUIRE(fx->h_dynamic != 0);
	set_flags_owner(&fx->db, fx->h_dynamic, ATT_ATTR_F_DYNAMIC);

	fx->h_auth_read = attdb_add_characteristic(&fx->db, 0x2A02,
	    GATT_PROP_READ, ATT_PERM_READ, static_val, sizeof(static_val));
	ATF_REQUIRE(fx->h_auth_read != 0);
	set_flags_owner(&fx->db, fx->h_auth_read, ATT_ATTR_F_AUTHORIZE);

	/* Writable authorize char: reserve room via a 16-byte initial value. */
	fx->h_auth_write = attdb_add_characteristic(&fx->db, 0x2A03,
	    GATT_PROP_READ | GATT_PROP_WRITE, ATT_PERM_READ | ATT_PERM_WRITE,
	    seed, sizeof(seed));
	ATF_REQUIRE(fx->h_auth_write != 0);
	set_flags_owner(&fx->db, fx->h_auth_write, ATT_ATTR_F_AUTHORIZE);

	fx->h_dyn_auth = attdb_add_characteristic(&fx->db, 0x2A04,
	    GATT_PROP_READ, ATT_PERM_READ, NULL, 0);
	ATF_REQUIRE(fx->h_dyn_auth != 0);
	set_flags_owner(&fx->db, fx->h_dyn_auth,
	    ATT_ATTR_F_DYNAMIC | ATT_ATTR_F_AUTHORIZE);
}

static void
fx_teardown(struct fixture *fx)
{

	close(fx->peer_fd);
	close(fx->ac.fd);
	free(fx->ac.buf);
}

/* Feed a PDU into the server as if received on the primary bearer. */
static void
srv_recv(struct fixture *fx, const uint8_t *pdu, size_t len)
{

	att_server_handle(&fx->ac, &fx->db, pdu, len, -1, 0);
}

/* Drain one server response PDU; returns length (0 == none pending). */
static ssize_t
srv_drain(struct fixture *fx, uint8_t *out, size_t outsz)
{
	ssize_t n = recv(fx->peer_fd, out, outsz, MSG_DONTWAIT);

	if (n < 0)
		return (0);
	return (n);
}

static void
send_read(struct fixture *fx, uint16_t handle)
{
	uint8_t pdu[3];

	pdu[0] = ATT_OP_READ_REQ;
	put_le16(pdu + 1, handle);
	srv_recv(fx, pdu, sizeof(pdu));
}

static void
send_read_blob(struct fixture *fx, uint16_t handle, uint16_t offset)
{
	uint8_t pdu[5];

	pdu[0] = ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, handle);
	put_le16(pdu + 3, offset);
	srv_recv(fx, pdu, sizeof(pdu));
}

static void
send_write(struct fixture *fx, uint16_t handle, const uint8_t *val,
    uint16_t vlen, bool with_response)
{
	uint8_t pdu[3 + 64];

	ATF_REQUIRE(vlen <= 64);
	pdu[0] = with_response ? ATT_OP_WRITE_REQ : ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, val, vlen);
	srv_recv(fx, pdu, (size_t)3 + vlen);
}

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * Dynamic read round-trip: peer read -> EVENT READ -> app READ_REPLY -> peer
 * gets exactly the app-supplied bytes (Core Spec Vol 3 Part F §3.4.4.3-4).
 */
ATF_TC_WITHOUT_HEAD(dynamic_read_roundtrip);
ATF_TC_BODY(dynamic_read_roundtrip, tc)
{
	struct fixture fx;
	static const uint8_t app_val[5] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dynamic);

	/* No response yet; the read is deferred to the owning app. */
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.read_calls);
	ATF_CHECK_EQ(TEST_OWNER_FD, cap.read_owner);
	ATF_CHECK_EQ(fx.h_dynamic, cap.read_handle);
	ATF_CHECK_EQ(0, cap.read_offset);
	ATF_CHECK(att_server_pending_active(&fx.ac));
	ATF_CHECK(att_server_pending_is_read(&fx.ac));

	/* App supplies the live value. */
	ATF_REQUIRE_EQ(0,
	    att_server_complete_read(&fx.ac, app_val, sizeof(app_val)));

	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1 + (ssize_t)sizeof(app_val), n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, app_val, sizeof(app_val)));
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	fx_teardown(&fx);
}

/*
 * Dynamic Read-Blob: the app returns the full value and the server slices it
 * at the requested offset (Vol 3 Part F §3.4.4.5), tagging a Read Blob Rsp.
 */
ATF_TC_WITHOUT_HEAD(dynamic_read_blob_offset);
ATF_TC_BODY(dynamic_read_blob_offset, tc)
{
	struct fixture fx;
	static const uint8_t app_val[6] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read_blob(&fx, fx.h_dynamic, 2);
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.read_calls);
	ATF_CHECK_EQ(2, cap.read_offset);

	ATF_REQUIRE_EQ(0,
	    att_server_complete_read(&fx.ac, app_val, sizeof(app_val)));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1 + 4, n);	/* value[2..5], 4 bytes */
	ATF_CHECK_EQ(ATT_OP_READ_BLOB_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, app_val + 2, 4));

	/* Offset past the value -> Invalid Offset (0x07). */
	cap_reset();
	send_read_blob(&fx, fx.h_dynamic, 10);
	ATF_REQUIRE_EQ(0,
	    att_server_complete_read(&fx.ac, app_val, sizeof(app_val)));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_ERR_INVALID_OFFSET, rsp[4]);

	fx_teardown(&fx);
}

/*
 * The app declines a dynamic read: the peer receives the app-chosen ATT error.
 */
ATF_TC_WITHOUT_HEAD(dynamic_read_reject);
ATF_TC_BODY(dynamic_read_reject, tc)
{
	struct fixture fx;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dynamic);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));

	ATF_REQUIRE_EQ(0,
	    att_server_reject_read(&fx.ac, ATT_ERR_READ_NOT_PERMITTED));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_OP_READ_REQ, rsp[1]);
	ATF_CHECK_EQ(ATT_ERR_READ_NOT_PERMITTED, rsp[4]);
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	fx_teardown(&fx);
}

/*
 * The app never replies: the bounded timeout fails the request with Unlikely
 * Error (0x0E) and releases the bearer (Vol 3 Part F §3.3.3 transaction
 * timeout).
 */
ATF_TC_WITHOUT_HEAD(dynamic_read_timeout);
ATF_TC_BODY(dynamic_read_timeout, tc)
{
	struct fixture fx;
	struct timeval now;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dynamic);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));

	/* Before the deadline: no expiry. */
	gettimeofday(&now, NULL);
	ATF_CHECK_EQ(0, att_server_pending_expire(&fx.ac, &now));
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK(att_server_pending_active(&fx.ac));

	/* Past the deadline: the request fails and the bearer is released. */
	now.tv_sec += ATT_PENDING_TIMEOUT_SEC + 1;
	ATF_CHECK_EQ(1, att_server_pending_expire(&fx.ac, &now));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_ERR_UNLIKELY_ERROR, rsp[4]);
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	/* A late app reply after expiry is a harmless no-op (no PDU). */
	ATF_CHECK_EQ(0, att_server_complete_read(&fx.ac, rsp, 1));
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));

	fx_teardown(&fx);
}

/*
 * Disconnect while a read is pending: clearing the bearer's state sends no PDU,
 * leaks nothing, and the connection is reusable for a fresh read afterwards.
 */
ATF_TC_WITHOUT_HEAD(disconnect_while_pending);
ATF_TC_BODY(disconnect_while_pending, tc)
{
	struct fixture fx;
	static const uint8_t app_val[2] = { 0x77, 0x88 };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dynamic);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));

	/* Teardown path: release without answering. */
	att_server_pending_clear(&fx.ac);
	ATF_CHECK(!att_server_pending_active(&fx.ac));
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));

	/* A stale completion after clear does nothing. */
	ATF_CHECK_EQ(0, att_server_complete_read(&fx.ac, app_val,
	    sizeof(app_val)));
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));

	/* The bearer still serves a fresh dynamic read. */
	cap_reset();
	send_read(&fx, fx.h_dynamic);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));
	ATF_REQUIRE_EQ(0, att_server_complete_read(&fx.ac, app_val,
	    sizeof(app_val)));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, app_val, sizeof(app_val)));

	fx_teardown(&fx);
}

/*
 * A second request while one is deferred violates ATT sequencing and is
 * answered with Unlikely Error; the original pending survives.
 */
ATF_TC_WITHOUT_HEAD(second_request_while_pending);
ATF_TC_BODY(second_request_while_pending, tc)
{
	struct fixture fx;
	static const uint8_t app_val[1] = { 0x5A };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dynamic);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));
	ATF_CHECK_EQ(fx.h_dynamic, att_server_pending_handle(&fx.ac));

	/* Second deferred read arrives before the first is answered. */
	send_read(&fx, fx.h_dyn_auth);
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_ERR_UNLIKELY_ERROR, rsp[4]);
	/* Original pending is untouched. */
	ATF_CHECK_EQ(fx.h_dynamic, att_server_pending_handle(&fx.ac));

	ATF_REQUIRE_EQ(0, att_server_complete_read(&fx.ac, app_val, 1));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(2, n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);

	fx_teardown(&fx);
}

/*
 * Authorization allow (read): EVENT AUTHORIZE -> allow -> the stored value is
 * served.
 */
ATF_TC_WITHOUT_HEAD(authorize_read_allow);
ATF_TC_BODY(authorize_read_allow, tc)
{
	struct fixture fx;
	static const uint8_t expect[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_auth_read);
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.auth_calls);
	ATF_CHECK_EQ(fx.h_auth_read, cap.auth_handle);
	ATF_CHECK(!cap.auth_write);
	ATF_CHECK(att_server_pending_is_authorize(&fx.ac));

	ATF_REQUIRE_EQ(0,
	    att_server_complete_authorize(&fx.ac, &fx.db, true));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1 + (ssize_t)sizeof(expect), n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, expect, sizeof(expect)));
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	fx_teardown(&fx);
}

/*
 * Authorization deny (read): the peer receives Insufficient Authorization
 * (0x08), Core Spec Vol 3 Part F Table 3.4 / Part G §8.2.
 */
ATF_TC_WITHOUT_HEAD(authorize_read_deny);
ATF_TC_BODY(authorize_read_deny, tc)
{
	struct fixture fx;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_auth_read);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));

	ATF_REQUIRE_EQ(0,
	    att_server_complete_authorize(&fx.ac, &fx.db, false));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_OP_READ_REQ, rsp[1]);
	ATF_CHECK_EQ(ATT_ERR_INSUFF_AUTHOR, rsp[4]);
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	fx_teardown(&fx);
}

/*
 * Authorization allow (write): the write is applied to the stored value, the
 * owning app is notified, and a Write Response is returned.
 */
ATF_TC_WITHOUT_HEAD(authorize_write_allow);
ATF_TC_BODY(authorize_write_allow, tc)
{
	struct fixture fx;
	static const uint8_t wval[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
	struct att_attr *a;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_write(&fx, fx.h_auth_write, wval, sizeof(wval), true);
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.auth_calls);
	ATF_CHECK(cap.auth_write);
	ATF_CHECK_EQ(fx.h_auth_write, cap.auth_handle);

	ATF_REQUIRE_EQ(0,
	    att_server_complete_authorize(&fx.ac, &fx.db, true));

	/* Write Response returned. */
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ(ATT_OP_WRITE_RSP, rsp[0]);

	/* Value applied and app notified. */
	a = attdb_find_by_handle(&fx.db, fx.h_auth_write);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(sizeof(wval), a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, wval, sizeof(wval)));
	ATF_CHECK_EQ(1, cap.write_calls);
	ATF_CHECK_EQ(0, memcmp(cap.write_val, wval, sizeof(wval)));

	fx_teardown(&fx);
}

/*
 * Authorization deny (write): 0x08 to the peer, the stored value is unchanged,
 * and the app is NOT notified of a write.
 */
ATF_TC_WITHOUT_HEAD(authorize_write_deny);
ATF_TC_BODY(authorize_write_deny, tc)
{
	struct fixture fx;
	static const uint8_t wval[4] = { 0x01, 0x02, 0x03, 0x04 };
	struct att_attr *a;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	a = attdb_find_by_handle(&fx.db, fx.h_auth_write);
	ATF_REQUIRE(a != NULL);
	ATF_REQUIRE(a->value_len >= sizeof(wval));

	send_write(&fx, fx.h_auth_write, wval, sizeof(wval), true);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));

	ATF_REQUIRE_EQ(0,
	    att_server_complete_authorize(&fx.ac, &fx.db, false));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(5, n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_OP_WRITE_REQ, rsp[1]);
	ATF_CHECK_EQ(ATT_ERR_INSUFF_AUTHOR, rsp[4]);

	/* Value not written; no write notification. */
	ATF_CHECK(a->value[0] != 0x01 || a->value[1] != 0x02);
	ATF_CHECK_EQ(0, cap.write_calls);

	fx_teardown(&fx);
}

/*
 * Dynamic + authorize on the same characteristic: authorization is resolved
 * first, then an allow re-defers for the app to supply the live value.
 */
ATF_TC_WITHOUT_HEAD(authorize_then_dynamic_read);
ATF_TC_BODY(authorize_then_dynamic_read, tc)
{
	struct fixture fx;
	static const uint8_t app_val[3] = { 0x11, 0x22, 0x33 };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_dyn_auth);
	/* First: an authorization request, not a value request. */
	ATF_CHECK_EQ(1, cap.auth_calls);
	ATF_CHECK_EQ(0, cap.read_calls);
	ATF_CHECK(att_server_pending_is_authorize(&fx.ac));

	/* Allow -> now the app is asked for the value. */
	ATF_REQUIRE_EQ(0,
	    att_server_complete_authorize(&fx.ac, &fx.db, true));
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.read_calls);
	ATF_CHECK_EQ(fx.h_dyn_auth, cap.read_handle);
	ATF_CHECK(att_server_pending_is_read(&fx.ac));

	ATF_REQUIRE_EQ(0,
	    att_server_complete_read(&fx.ac, app_val, sizeof(app_val)));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1 + (ssize_t)sizeof(app_val), n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, app_val, sizeof(app_val)));

	fx_teardown(&fx);
}

/*
 * A static (non-app-backed) characteristic still serves its stored value
 * immediately, with no app round-trip and no pending state — unchanged.
 */
ATF_TC_WITHOUT_HEAD(static_read_unchanged);
ATF_TC_BODY(static_read_unchanged, tc)
{
	struct fixture fx;
	static const uint8_t expect[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	send_read(&fx, fx.h_static);
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1 + (ssize_t)sizeof(expect), n);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(0, memcmp(rsp + 1, expect, sizeof(expect)));
	ATF_CHECK_EQ(0, cap.read_calls);
	ATF_CHECK_EQ(0, cap.auth_calls);
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	fx_teardown(&fx);
}

/*
 * Finding 51: an authorize-gated Write Request longer than the deferred-write
 * holding buffer (ATT_PEND_WVAL_MAX == 512, the maximum ATT attribute value
 * length) must be REJECTED with Invalid Attribute Value Length, not silently
 * truncated to 512 and acked.  A characteristic can register value_maxlen above
 * 512 (up to 517), so a >512 write can pass the maxlen check yet not fit the
 * pending buffer.  The reject happens before any authorize event is emitted.
 */
ATF_TC_WITHOUT_HEAD(authorize_write_over_pend_max_rejected);
ATF_TC_BODY(authorize_write_over_pend_max_rejected, tc)
{
	struct fixture fx;
	uint8_t big_init[513];
	uint8_t wval[513];
	uint8_t pdu[3 + 513];
	uint16_t h;
	uint8_t rsp[64];
	ssize_t n;

	fx_setup(&fx);

	/*
	 * Register a writable, authorize-gated characteristic whose reserved
	 * capacity exceeds ATT_PEND_WVAL_MAX (value_maxlen == 513 via a 513-byte
	 * initial value).  The fixture MTU is ATT_PDU_BUF_SIZE (517) so a 513-B
	 * value fits in one Write Request.
	 */
	memset(big_init, 0x5A, sizeof(big_init));
	h = attdb_add_characteristic(&fx.db, 0x2B01,
	    GATT_PROP_READ | GATT_PROP_WRITE, ATT_PERM_READ | ATT_PERM_WRITE,
	    big_init, sizeof(big_init));
	ATF_REQUIRE(h != 0);
	set_flags_owner(&fx.db, h, ATT_ATTR_F_AUTHORIZE);

	/* Write 513 octets: passes value_maxlen (513) but exceeds 512. */
	memset(wval, 0xC3, sizeof(wval));
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, h);
	memcpy(pdu + 3, wval, sizeof(wval));
	srv_recv(&fx, pdu, sizeof(pdu));

	/* Rejected up front: an Error Response, no authorize event, no pending. */
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ_MSG(5, n, "expected 5-byte error response, got %zd", n);
	ATF_CHECK_EQ(ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(ATT_OP_WRITE_REQ, rsp[1]);
	ATF_CHECK_EQ_MSG(ATT_ERR_INVALID_ATTR_LEN, rsp[4],
	    "over-max authorize write must be rejected, not truncated");
	ATF_CHECK_EQ(0, cap.auth_calls);
	ATF_CHECK(!att_server_pending_active(&fx.ac));

	/* A ≤512 authorize write to the same char still defers normally. */
	pdu[0] = ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, h);
	srv_recv(&fx, pdu, (size_t)3 + 512);
	ATF_CHECK_EQ(0, srv_drain(&fx, rsp, sizeof(rsp)));
	ATF_CHECK_EQ(1, cap.auth_calls);
	ATF_REQUIRE(att_server_pending_active(&fx.ac));
	ATF_REQUIRE_EQ(0, att_server_complete_authorize(&fx.ac, &fx.db, true));
	n = srv_drain(&fx, rsp, sizeof(rsp));
	ATF_REQUIRE_EQ(1, n);
	ATF_CHECK_EQ(ATT_OP_WRITE_RSP, rsp[0]);
	{
		struct att_attr *a = attdb_find_by_handle(&fx.db, h);
		ATF_REQUIRE(a != NULL);
		ATF_CHECK_EQ(512, a->value_len);
	}

	fx_teardown(&fx);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, authorize_write_over_pend_max_rejected);

	ATF_TP_ADD_TC(tp, dynamic_read_roundtrip);
	ATF_TP_ADD_TC(tp, dynamic_read_blob_offset);
	ATF_TP_ADD_TC(tp, dynamic_read_reject);
	ATF_TP_ADD_TC(tp, dynamic_read_timeout);
	ATF_TP_ADD_TC(tp, disconnect_while_pending);
	ATF_TP_ADD_TC(tp, second_request_while_pending);
	ATF_TP_ADD_TC(tp, authorize_read_allow);
	ATF_TP_ADD_TC(tp, authorize_read_deny);
	ATF_TP_ADD_TC(tp, authorize_write_allow);
	ATF_TP_ADD_TC(tp, authorize_write_deny);
	ATF_TP_ADD_TC(tp, authorize_then_dynamic_read);
	ATF_TP_ADD_TC(tp, static_read_unchanged);

	return (atf_no_error());
}
