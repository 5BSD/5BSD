/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF negative / robustness tests for the ATT server request dispatcher
 * (att_server_handle() and its per-opcode handlers).
 *
 * Every ATT request opcode is fed malformed, truncated, out-of-range and
 * MTU-boundary PDUs.  The tests assert that the correct ATT Error Response
 * (opcode / requested-handle / error-code) is emitted where the spec calls
 * for one, that no response is sent where the spec calls for silent
 * discard (commands, signed writes), and that nothing crashes or over-reads
 * a short buffer.
 *
 * A SOCK_SEQPACKET socketpair stands in for the L2CAP ATT channel so no
 * real Bluetooth hardware is needed.  Responses are drained with
 * MSG_DONTWAIT so a "no response" case cannot block the test.
 *
 * Reference: Core Spec Vol 3 Part F (ATT), Part G (GATT / Robust Caching).
 */

#include <sys/types.h>
#include <sys/socket.h>

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
#include "hci_util.h"

#include "test_common.h"
#include "spec_att_server_negative_oracles.h"

static void
spec_put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
spec_get16(const uint8_t *p)
{
	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

/* ================================================================
 * Mock helpers (mirrors att_test.c / gatt_test.c)
 * ================================================================ */

static void
att_mock_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = BT_ASN_DEFAULT_MTU;
	ac->buf = malloc(BT_ASN_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
att_mock_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

/*
 * Standard test database.  Handle map:
 *   0x0001 Primary Service Decl (0x2800) value=0x1800      (READ)
 *   0x0002 Char Decl (0x2803) props=READ                   (READ)
 *   0x0003 Device Name value (0x2A00) "Test" (len 4)       (READ)
 *   0x0004 Primary Service Decl (0x2800) value=0xFFE0      (READ)
 *   0x0005 Char Decl (0x2803) props=READ|WRITE|NOTIFY      (READ)
 *   0x0006 Custom Char value (0xFFE1) 4 bytes, maxlen 4    (READ|WRITE)
 *   0x0007 CCCD (0x2902) 2 bytes, maxlen 2                 (READ|WRITE)
 */
#define TEST_DB_MAX_ATTRS	32
#define TEST_DB_VAL_SIZE	512

#define HANDLE_NAME_VALUE	0x0003	/* read-only value attr */
#define HANDLE_CUSTOM_VALUE	0x0006	/* read/write value attr, maxlen 4 */
#define HANDLE_CCCD		0x0007	/* read/write CCCD, maxlen 2 */

static void
build_test_db(struct att_db *db, struct att_attr *attrs, uint8_t *val_buf)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val_buf, TEST_DB_VAL_SIZE);

	attdb_add_service(db, BT_ASN_UUID_GAP_SERVICE);
	attdb_add_characteristic(db, BT_ASN_UUID_DEVICE_NAME,
	    BT_ASN_GATT_PROP_READ, ATT_PERM_READ, "Test", 4);

	attdb_add_service(db, 0xFFE0);
	attdb_add_characteristic(db, 0xFFE1,
	    BT_ASN_GATT_PROP_READ | BT_ASN_GATT_PROP_WRITE |
	    BT_ASN_GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\xAA\xBB\xCC\xDD", 4);
	attdb_add_cccd(db);
}

/* ================================================================
 * Response-checking helpers
 * ================================================================ */

/* Run one request through the dispatcher, return recv length (or <0). */
static ssize_t
srv_exchange(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t *rsp, size_t rsplen)
{

	att_server_handle(ac, db, pdu, len, -1, 0);
	return (recv(peer, rsp, rsplen, MSG_DONTWAIT));
}

/* Expect an ATT Error Response with the given request-op and error code. */
static void
expect_err(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op, uint8_t exp_code)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_exchange(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == BT_ASN_ERROR_RSP_LEN,
	    "req 0x%02x: expected 5-byte error response, got %zd",
	    (len > 0 ? pdu[0] : 0), n);
	ATF_CHECK_EQ_MSG(rsp[0], BT_ASN_OP_ERROR_RSP, "req 0x%02x", pdu[0]);
	ATF_CHECK_EQ_MSG(rsp[1], exp_op, "req 0x%02x: wrong echoed opcode",
	    pdu[0]);
	ATF_CHECK_EQ_MSG(rsp[4], exp_code,
	    "req 0x%02x: expected code 0x%02x got 0x%02x",
	    pdu[0], exp_code, rsp[4]);
}

/* Same, but also assert the error's attribute handle field. */
static void
expect_err_h(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op, uint16_t exp_handle,
    uint8_t exp_code)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_exchange(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == BT_ASN_ERROR_RSP_LEN,
	    "req 0x%02x: expected 5-byte error response, got %zd", pdu[0], n);
	ATF_CHECK_EQ(rsp[0], BT_ASN_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], exp_op);
	ATF_CHECK_EQ_MSG(spec_get16(rsp + 2), exp_handle,
	    "req 0x%02x: expected handle 0x%04x got 0x%04x",
	    pdu[0], exp_handle, spec_get16(rsp + 2));
	ATF_CHECK_EQ_MSG(rsp[4], exp_code,
	    "req 0x%02x: expected code 0x%02x got 0x%02x",
	    pdu[0], exp_code, rsp[4]);
}

/* Expect no PDU emitted at all (silent discard). */
static void
expect_none(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_exchange(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n < 0,
	    "expected no response, got %zd bytes (op 0x%02x)", n, rsp[0]);
}

/* Expect a response whose opcode is exp_op (success path). */
static void
expect_rsp_op(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_exchange(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n >= 1, "req 0x%02x: expected a response, got %zd",
	    pdu[0], n);
	ATF_CHECK_EQ_MSG(rsp[0], exp_op,
	    "req 0x%02x: expected rsp 0x%02x got 0x%02x", pdu[0], exp_op,
	    rsp[0]);
}

#define DB_SETUP(ac, peer, db, attrs, val)				\
	struct att_conn ac;						\
	int peer;							\
	struct att_db db;						\
	struct att_attr attrs[TEST_DB_MAX_ATTRS];			\
	uint8_t val[TEST_DB_VAL_SIZE];					\
	att_mock_pair(&ac, &peer);					\
	build_test_db(&db, attrs, val)

/* ================================================================
 * 0. Zero-length PDU — dispatcher must reject with no send
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_zero_length);
ATF_TC_BODY(test_neg_zero_length, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[1] = { 0 };
	int ret;

	ret = att_server_handle(&ac, &db, pdu, 0, -1, 0);
	ATF_CHECK_EQ_MSG(ret, -1, "zero-length PDU must return -1");

	/* Nothing must have been sent. */
	uint8_t rsp[8];
	ATF_CHECK(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 1. Exchange MTU (0x02)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_mtu);
ATF_TC_BODY(test_neg_mtu, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[3];

	/* 1-byte PDU: truncated -> INVALID_PDU */
	pdu[0] = BT_ASN_OP_MTU_REQ;
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_MTU_REQ, BT_ASN_ERR_INVALID_PDU);

	/* 2-byte PDU: still < 3 -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 2, BT_ASN_OP_MTU_REQ, BT_ASN_ERR_INVALID_PDU);

	/* Valid MTU exchange succeeds. */
	pdu[0] = BT_ASN_OP_MTU_REQ;
	spec_put16(pdu + 1, 100);
	expect_rsp_op(&ac, &db, peer, pdu, 3, BT_ASN_OP_MTU_RSP);

	/* Second MTU request after exchange -> REQ_NOT_SUPPORTED */
	expect_err(&ac, &db, peer, pdu, 3, BT_ASN_OP_MTU_REQ,
	    BT_ASN_ERR_REQUEST_NOT_SUPPORTED);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 2. Find Information (0x04)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_find_info);
ATF_TC_BODY(test_neg_find_info, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];

	pdu[0] = BT_ASN_OP_FIND_INFO_REQ;

	/* 1-byte and 4-byte truncated PDUs -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_FIND_INFO_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	spec_put16(pdu + 1, 0x0001);
	expect_err(&ac, &db, peer, pdu, 4, BT_ASN_OP_FIND_INFO_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* start handle 0x0000 -> INVALID_HANDLE (handle field = 0) */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_FIND_INFO_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* start > end -> INVALID_HANDLE (handle field = start) */
	spec_put16(pdu + 1, 0x0005);
	spec_put16(pdu + 3, 0x0001);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_FIND_INFO_REQ, 0x0005,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* Valid range with no attributes present -> ATTR_NOT_FOUND */
	spec_put16(pdu + 1, 0xFFFE);
	spec_put16(pdu + 3, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_FIND_INFO_REQ, 0xFFFE,
	    BT_ASN_ERR_ATTRIBUTE_NOT_FOUND);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 3. Find By Type Value (0x06)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_find_by_type_value);
ATF_TC_BODY(test_neg_find_by_type_value, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[9];

	pdu[0] = BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ;

	/* 1-byte and 6-byte truncated PDUs -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 6, BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* start 0x0000 -> INVALID_HANDLE.  Type 0x2800, zero-length value. */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_PRIMARY_SERVICE);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ,
	    0x0000, BT_ASN_ERR_INVALID_HANDLE);

	/* start > end -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0008);
	spec_put16(pdu + 3, 0x0002);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ,
	    0x0008, BT_ASN_ERR_INVALID_HANDLE);

	/* Valid range/type, value that matches nothing -> ATTR_NOT_FOUND */
	spec_put16(pdu + 1, 0x0001);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_PRIMARY_SERVICE);
	spec_put16(pdu + 7, 0x9999);
	expect_err_h(&ac, &db, peer, pdu, 9, BT_ASN_OP_FIND_BY_TYPE_VALUE_REQ,
	    0x0001, BT_ASN_ERR_ATTRIBUTE_NOT_FOUND);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 4. Read By Type (0x08)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_by_type);
ATF_TC_BODY(test_neg_read_by_type, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[22];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_READ_BY_TYPE_REQ;

	/* Lengths other than 7/9/21 are INVALID_PDU (1, 6, 8, 22). */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_READ_BY_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 6, BT_ASN_OP_READ_BY_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 8, BT_ASN_OP_READ_BY_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 22, BT_ASN_OP_READ_BY_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* start 0x0000 -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_CHARACTERISTIC);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_TYPE_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* start > end -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0009);
	spec_put16(pdu + 3, 0x0002);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_TYPE_REQ, 0x0009,
	    BT_ASN_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 5. Read By Group Type (0x10)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_by_group_type);
ATF_TC_BODY(test_neg_read_by_group_type, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[21];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_READ_BY_GROUP_TYPE_REQ;

	/* Bad lengths -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 8, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/*
	 * 128-bit group type that does not collapse to a 16-bit UUID
	 * -> UNSUPPORTED_GROUP_TYPE.
	 */
	spec_put16(pdu + 1, 0x0001);
	spec_put16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0xAB, 16);
	expect_err(&ac, &db, peer, pdu, 21, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_ASN_ERR_UNSUPPORTED_GROUP_TYPE);

	/* 16-bit non-service group type (Characteristic) -> UNSUPPORTED */
	spec_put16(pdu + 1, 0x0001);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_CHARACTERISTIC);
	expect_err(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_ASN_ERR_UNSUPPORTED_GROUP_TYPE);

	/* start 0x0000 with a valid service type -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_PRIMARY_SERVICE);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    0x0000, BT_ASN_ERR_INVALID_HANDLE);

	/* start > end with a valid service type -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0008);
	spec_put16(pdu + 3, 0x0002);
	expect_err_h(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_GROUP_TYPE_REQ,
	    0x0008, BT_ASN_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 6. Read Request (0x0A)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read);
ATF_TC_BODY(test_neg_read, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[3];

	pdu[0] = BT_ASN_OP_READ_REQ;

	/* 1-byte truncated -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_READ_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* handle 0x0000 -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0000);
	expect_err_h(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* handle 0xFFFF (absent) -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_REQ, 0xFFFF,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* Valid read of a readable value handle -> READ_RSP */
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_rsp_op(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_RSP);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 7. Read Blob (0x0C)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_blob);
ATF_TC_BODY(test_neg_read_blob, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];

	pdu[0] = BT_ASN_OP_READ_BLOB_REQ;

	/* 1-byte and 4-byte truncated -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_READ_BLOB_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_err(&ac, &db, peer, pdu, 4, BT_ASN_OP_READ_BLOB_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* handle 0x0000 -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0x0000);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_BLOB_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* handle 0xFFFF -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_BLOB_REQ, 0xFFFF,
	    BT_ASN_ERR_INVALID_HANDLE);

	/*
	 * Non-zero offset (still within the 4-octet "Test" value) into a short
	 * (non-long) attribute -> ATTR_NOT_LONG (0x0B, the optional "may"
	 * response for a fixed short attribute).  Core Spec Vol 3 Part F
	 * §3.4.4.5.
	 */
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	spec_put16(pdu + 3, 2);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_BLOB_REQ,
	    HANDLE_NAME_VALUE, BT_ASN_ERR_ATTRIBUTE_NOT_LONG);

	/*
	 * Offset past the end of the value (10 > len 4) -> Invalid Offset
	 * (0x07).  §3.4.4.5 makes this a "shall", so it takes precedence over
	 * the optional Attribute Not Long response even for a short attribute.
	 */
	spec_put16(pdu + 3, 10);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_BLOB_REQ,
	    HANDLE_NAME_VALUE, BT_ASN_ERR_INVALID_OFFSET);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 8. Read Multiple (0x0E)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_multiple);
ATF_TC_BODY(test_neg_read_multiple, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];

	pdu[0] = BT_ASN_OP_READ_MULTIPLE_REQ;

	/* 1-byte and 3-byte (< 2 handles) -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_READ_MULTIPLE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_err(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_MULTIPLE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* Odd handle-list length (6 bytes total) -> INVALID_PDU */
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_READ_MULTIPLE_REQ;
	{
		uint8_t big[6] = { BT_ASN_OP_READ_MULTIPLE_REQ,
		    0x03, 0x00, 0x06, 0x00, 0x00 };
		expect_err(&ac, &db, peer, big, sizeof(big),
		    BT_ASN_OP_READ_MULTIPLE_REQ, BT_ASN_ERR_INVALID_PDU);
	}

	/* First handle 0x0000 -> INVALID_HANDLE */
	pdu[0] = BT_ASN_OP_READ_MULTIPLE_REQ;
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, HANDLE_NAME_VALUE);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_MULTIPLE_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* Handle 0xFFFF (absent) -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_READ_MULTIPLE_REQ, 0xFFFF,
	    BT_ASN_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 9. Read Multiple Variable (0x20)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_multiple_variable);
ATF_TC_BODY(test_neg_read_multiple_variable, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];

	pdu[0] = BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ;

	/* < 2 handles -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1,
	    BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ, BT_ASN_ERR_INVALID_PDU);
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_err(&ac, &db, peer, pdu, 3,
	    BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ, BT_ASN_ERR_INVALID_PDU);

	/* Odd handle-list length -> INVALID_PDU */
	{
		uint8_t big[6] = { BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ,
		    0x03, 0x00, 0x06, 0x00, 0x00 };
		expect_err(&ac, &db, peer, big, sizeof(big),
		    BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ, BT_ASN_ERR_INVALID_PDU);
	}

	/* First handle 0x0000 -> INVALID_HANDLE */
	pdu[0] = BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ;
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, HANDLE_NAME_VALUE);
	expect_err_h(&ac, &db, peer, pdu, 5,
	    BT_ASN_OP_READ_MULTIPLE_VARIABLE_REQ, 0x0000, BT_ASN_ERR_INVALID_HANDLE);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 10. Write Request (0x12)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_write_req);
ATF_TC_BODY(test_neg_write_req, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[64];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_WRITE_REQ;

	/* 1-byte and 2-byte truncated -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 2, BT_ASN_OP_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* handle 0x0000 -> INVALID_HANDLE (zero-length value) */
	spec_put16(pdu + 1, 0x0000);
	expect_err_h(&ac, &db, peer, pdu, 3, BT_ASN_OP_WRITE_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* handle 0xFFFF -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 3, BT_ASN_OP_WRITE_REQ, 0xFFFF,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* Write to a read-only attribute -> WRITE_NOT_PERMITTED */
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	pdu[3] = 0x42;
	expect_err_h(&ac, &db, peer, pdu, 4, BT_ASN_OP_WRITE_REQ,
	    HANDLE_NAME_VALUE, BT_ASN_ERR_WRITE_NOT_PERMITTED);

	/* Oversized value beyond value_maxlen (4) -> INVALID_ATTR_LEN */
	spec_put16(pdu + 1, HANDLE_CUSTOM_VALUE);
	memset(pdu + 3, 0x55, 10);
	expect_err_h(&ac, &db, peer, pdu, 3 + 10, BT_ASN_OP_WRITE_REQ,
	    HANDLE_CUSTOM_VALUE, BT_ASN_ERR_INVALID_ATTRIBUTE_LENGTH);

	/* Boundary: exactly value_maxlen bytes -> WRITE_RSP */
	spec_put16(pdu + 1, HANDLE_CUSTOM_VALUE);
	memset(pdu + 3, 0x11, 4);
	expect_rsp_op(&ac, &db, peer, pdu, 3 + 4, BT_ASN_OP_WRITE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 11. Write Command (0x52) — no response even when malformed
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_write_cmd);
ATF_TC_BODY(test_neg_write_cmd, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[8];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_WRITE_CMD;

	/* Truncated command: silently dropped, no response. */
	expect_none(&ac, &db, peer, pdu, 1);
	expect_none(&ac, &db, peer, pdu, 2);

	/* Command to an absent handle: silently dropped. */
	spec_put16(pdu + 1, 0xFFFF);
	pdu[3] = 0x01;
	expect_none(&ac, &db, peer, pdu, 4);

	/* Command to a read-only handle: silently dropped (no error PDU). */
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_none(&ac, &db, peer, pdu, 4);

	/* Valid write command: applied, still no response. */
	spec_put16(pdu + 1, HANDLE_CUSTOM_VALUE);
	memset(pdu + 3, 0x22, 4);
	expect_none(&ac, &db, peer, pdu, 3 + 4);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 12. Prepare Write (0x16)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_prepare_write);
ATF_TC_BODY(test_neg_prepare_write, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[16];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_PREPARE_WRITE_REQ;

	/* 1-byte and 4-byte truncated -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_PREPARE_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);
	expect_err(&ac, &db, peer, pdu, 4, BT_ASN_OP_PREPARE_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* handle 0x0000 -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0x0000);
	spec_put16(pdu + 3, 0x0000);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_PREPARE_WRITE_REQ, 0x0000,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* handle 0xFFFF -> INVALID_HANDLE */
	spec_put16(pdu + 1, 0xFFFF);
	expect_err_h(&ac, &db, peer, pdu, 5, BT_ASN_OP_PREPARE_WRITE_REQ, 0xFFFF,
	    BT_ASN_ERR_INVALID_HANDLE);

	/* Prepare on a read-only handle -> WRITE_NOT_PERMITTED */
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	spec_put16(pdu + 3, 0x0000);
	pdu[5] = 0x01;
	expect_err_h(&ac, &db, peer, pdu, 6, BT_ASN_OP_PREPARE_WRITE_REQ,
	    HANDLE_NAME_VALUE, BT_ASN_ERR_WRITE_NOT_PERMITTED);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 13. Prepare Write queue overflow -> PREPARE_QUEUE_FULL
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_prepare_queue_overflow);
ATF_TC_BODY(test_neg_prepare_queue_overflow, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[6];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	int i;

	pdu[0] = BT_ASN_OP_PREPARE_WRITE_REQ;
	spec_put16(pdu + 1, HANDLE_CUSTOM_VALUE);
	spec_put16(pdu + 3, 0x0000);
	pdu[5] = 0xEE;

	/* Fill the queue (ATT_PREPARE_QUEUE_MAX entries all succeed). */
	for (i = 0; i < ATT_PREPARE_QUEUE_MAX; i++) {
		att_server_handle(&ac, &db, pdu, sizeof(pdu), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
		ATF_REQUIRE_MSG(n >= 1, "prepare %d: no response (%zd)", i, n);
		ATF_CHECK_EQ_MSG(rsp[0], BT_ASN_OP_PREPARE_WRITE_RSP,
		    "prepare %d: unexpected opcode 0x%02x", i, rsp[0]);
	}

	/* One more must overflow. */
	expect_err_h(&ac, &db, peer, pdu, sizeof(pdu),
	    BT_ASN_OP_PREPARE_WRITE_REQ, HANDLE_CUSTOM_VALUE,
	    BT_ASN_ERR_PREPARE_QUEUE_FULL);

	/* Cancel drains the queue and returns EXECUTE_WRITE_RSP. */
	{
		uint8_t exec[2] = { BT_ASN_OP_EXECUTE_WRITE_REQ,
		    BT_ASN_EXEC_CANCEL };
		expect_rsp_op(&ac, &db, peer, exec, sizeof(exec),
		    BT_ASN_OP_EXECUTE_WRITE_RSP);
	}

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 14. Execute Write (0x18) — truncation, bad flags, cancel
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_execute_write);
ATF_TC_BODY(test_neg_execute_write, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[2];

	pdu[0] = BT_ASN_OP_EXECUTE_WRITE_REQ;

	/* 1-byte truncated -> INVALID_PDU */
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OP_EXECUTE_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* Reserved flags value (0x02) -> INVALID_PDU */
	pdu[1] = BT_ASN_EXEC_COMMIT + 1;
	expect_err(&ac, &db, peer, pdu, 2, BT_ASN_OP_EXECUTE_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	/* Cancel with empty queue -> EXECUTE_WRITE_RSP */
	pdu[1] = BT_ASN_EXEC_CANCEL;
	expect_rsp_op(&ac, &db, peer, pdu, 2, BT_ASN_OP_EXECUTE_WRITE_RSP);

	/* Commit with empty queue -> EXECUTE_WRITE_RSP */
	pdu[1] = BT_ASN_EXEC_COMMIT;
	expect_rsp_op(&ac, &db, peer, pdu, 2, BT_ASN_OP_EXECUTE_WRITE_RSP);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 15. Signed Write Command (0xD2) — dropped, never answered
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_signed_write);
ATF_TC_BODY(test_neg_signed_write, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[32];

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_ASN_OP_SIGNED_WRITE_CMD;

	/* Too short for a signature (< 15 bytes): silently dropped. */
	expect_none(&ac, &db, peer, pdu, 1);
	expect_none(&ac, &db, peer, pdu, 14);

	/*
	 * Long enough but no peer CSRK configured (has_peer_csrk == false):
	 * signature cannot be verified -> silently dropped, no response.
	 */
	spec_put16(pdu + 1, HANDLE_CUSTOM_VALUE);
	pdu[3] = 0x77;
	expect_none(&ac, &db, peer, pdu, 20);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 16. Unknown opcode handling
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_unknown_opcode);
ATF_TC_BODY(test_neg_unknown_opcode, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[4];

	memset(pdu, 0, sizeof(pdu));

	/* Core Vol 3 Part F §3.3.1 Table 3.2: undefined Method, command clear. */
	pdu[0] = BT_ASN_OPCODE_METHOD_MASK;
	expect_err(&ac, &db, peer, pdu, 1, BT_ASN_OPCODE_METHOD_MASK,
	    BT_ASN_ERR_REQUEST_NOT_SUPPORTED);

	/* The same undefined Method with Table 3.2 Command Flag set is ignored. */
	pdu[0] = BT_ASN_OPCODE_METHOD_MASK | BT_ASN_OPCODE_COMMAND_FLAG;
	expect_none(&ac, &db, peer, pdu, 1);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * 17. Robust Caching gating for a change-unaware client
 *     (Core Spec Vol 3 Part G Section 2.5.2.1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_robust_caching_gating);
ATF_TC_BODY(test_neg_robust_caching_gating, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[7];

	ac.robust_caching = true;
	ac.change_aware = false;
	ac.out_of_sync_sent = false;

	/* First gated request: a plain Read is blocked -> DATABASE_OUT_OF_SYNC. */
	pdu[0] = BT_ASN_OP_READ_REQ;
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_err(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_REQ,
	    BT_ASN_ERR_DATABASE_OUT_OF_SYNC);

	/*
	 * Vol 3 Part G §2.5.2.1 Fig 2.7: the Database Out Of Sync error is
	 * sent only once per bearer.  Receiving another request transitions
	 * the client to change-aware and is processed normally -- the same
	 * Read now returns a Read Response.
	 */
	expect_rsp_op(&ac, &db, peer, pdu, 3, BT_ASN_OP_READ_RSP);
	ATF_CHECK(ac.change_aware);

	/*
	 * Back to change-unaware: Find Information (0x04) is NOT gated by Robust
	 * Caching.  Table 3.43 (Vol 3 Part F §3.4.9) does not list Database Out
	 * Of Sync (0x12) among the valid errors for ATT_FIND_INFORMATION_REQ, so
	 * a change-unaware client's Find Information must be processed normally
	 * and return a FIND_INFO_RSP, never 0x12.
	 */
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_ASN_OP_FIND_INFO_REQ;
	spec_put16(pdu + 1, 0x0001);
	spec_put16(pdu + 3, 0xFFFF);
	expect_rsp_op(&ac, &db, peer, pdu, 5, BT_ASN_OP_FIND_INFO_RSP);

	/* Reset to change-unaware for the always-allowed operations. */
	ac.change_aware = false;
	ac.out_of_sync_sent = false;

	/* MTU exchange is always permitted -> MTU_RSP. */
	pdu[0] = BT_ASN_OP_MTU_REQ;
	spec_put16(pdu + 1, 100);
	expect_rsp_op(&ac, &db, peer, pdu, 3, BT_ASN_OP_MTU_RSP);

	/*
	 * Read By Type of Characteristic (0x2803) over the full range is
	 * allowed for change-unaware clients (discovery must continue).
	 */
	pdu[0] = BT_ASN_OP_READ_BY_TYPE_REQ;
	spec_put16(pdu + 1, 0x0001);
	spec_put16(pdu + 3, 0xFFFF);
	spec_put16(pdu + 5, BT_ASN_UUID_CHARACTERISTIC);
	expect_rsp_op(&ac, &db, peer, pdu, 7, BT_ASN_OP_READ_BY_TYPE_RSP);

	/* A command from a change-unaware client is silently ignored. */
	{
		uint8_t cmd[7];
		cmd[0] = BT_ASN_OP_WRITE_CMD;
		spec_put16(cmd + 1, HANDLE_CUSTOM_VALUE);
		memset(cmd + 3, 0x33, 4);
		expect_none(&ac, &db, peer, cmd, 7);
	}

	att_mock_cleanup(&ac, peer);
}

/* Part F §§3.4.2-.6: fixed-size requests reject one trailing octet. */
ATF_TC_WITHOUT_HEAD(test_neg_fixed_request_overlong);
ATF_TC_BODY(test_neg_fixed_request_overlong, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[8] = { 0 };

	pdu[0] = BT_ASN_OP_MTU_REQ;
	spec_put16(pdu + 1, 100);
	expect_err(&ac, &db, peer, pdu, 4, BT_ASN_OP_MTU_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	pdu[0] = BT_ASN_OP_FIND_INFO_REQ;
	spec_put16(pdu + 1, 1);
	spec_put16(pdu + 3, 0xffff);
	expect_err(&ac, &db, peer, pdu, 6, BT_ASN_OP_FIND_INFO_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	pdu[0] = BT_ASN_OP_READ_REQ;
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	expect_err(&ac, &db, peer, pdu, 4, BT_ASN_OP_READ_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	pdu[0] = BT_ASN_OP_READ_BLOB_REQ;
	spec_put16(pdu + 1, HANDLE_NAME_VALUE);
	spec_put16(pdu + 3, 0);
	expect_err(&ac, &db, peer, pdu, 6, BT_ASN_OP_READ_BLOB_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	pdu[0] = BT_ASN_OP_EXECUTE_WRITE_REQ;
	pdu[1] = BT_ASN_EXEC_CANCEL;
	expect_err(&ac, &db, peer, pdu, 3, BT_ASN_OP_EXECUTE_WRITE_REQ,
	    BT_ASN_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * Finding 104: READ_BY_TYPE_REQ with a 2-octet Attribute Type of 0x0000
 * is malformed and must be rejected Invalid PDU — not treated as a 128-bit
 * type sentinel (which would compare against an uninitialised uuid128).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_read_by_type_zero_uuid16);
ATF_TC_BODY(test_neg_read_by_type_zero_uuid16, tc)
{
	DB_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[7];

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	spec_put16(pdu + 1, 0x0001);	/* start */
	spec_put16(pdu + 3, 0xFFFF);	/* end */
	spec_put16(pdu + 5, 0x0000);	/* 2-octet Attribute Type == 0x0000 */
	expect_err(&ac, &db, peer, pdu, 7, ATT_OP_READ_BY_TYPE_REQ,
	    ATT_ERR_INVALID_PDU);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * Finding 113: a writable characteristic declared with an EMPTY initial
 * value must still be writable (reserve capacity), not permanently rejected
 * with INVALID_ATTR_LEN against a NULL value / zero value_maxlen.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_empty_writable_char_is_writable);
ATF_TC_BODY(test_neg_empty_writable_char_is_writable, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	/* An empty writable char reserves the max ATT attribute value length
	 * (512); give the arena room for that plus the declarations. */
	uint8_t val[1024];
	uint8_t pdu[3 + 8];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	struct att_attr *a;
	uint16_t vh;
	ssize_t n;

	att_mock_pair(&ac, &peer);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, sizeof(val));
	attdb_add_service(&db, 0xFFF0);
	vh = attdb_add_characteristic(&db, 0xFFF1, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, NULL, 0);	/* empty initial value */
	ATF_REQUIRE(vh != 0);

	a = attdb_find_by_handle(&db, vh);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_MSG(a->value != NULL,
	    "empty writable char must reserve a value buffer");
	ATF_CHECK_MSG(a->value_maxlen > 0,
	    "empty writable char must have nonzero value_maxlen");

	pdu[0] = ATT_OP_WRITE_REQ;
	spec_put16(pdu + 1, vh);
	memset(pdu + 3, 0xAB, 8);
	n = srv_exchange(&ac, &db, peer, pdu, sizeof(pdu), rsp, sizeof(rsp));
	ATF_REQUIRE_EQ_MSG(1, n, "expected Write Response, got %zd", n);
	ATF_CHECK_EQ(ATT_OP_WRITE_RSP, rsp[0]);

	a = attdb_find_by_handle(&db, vh);
	ATF_CHECK_EQ(8, a->value_len);
	ATF_CHECK_EQ(0, memcmp(a->value, pdu + 3, 8));

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * Finding 114: att_send_indication self-arms its 30 s confirmation deadline
 * so a caller that never arms an external timer cannot wedge every future
 * indication at EBUSY.  A pending indication past its deadline is auto-cleared
 * before the next indication is sent.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_neg_indication_self_heals_timeout);
ATF_TC_BODY(test_neg_indication_self_heals_timeout, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	uint8_t v = 0x01;
	ssize_t n;

	att_mock_pair(&ac, &peer);

	/* First indication: sent, ind_pending set, deadline self-armed. */
	ATF_REQUIRE_EQ(0, att_send_indication(&ac, 0x0005, &v, 1));
	ATF_CHECK(ac.ind_pending);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_EQ(4, n);
	ATF_CHECK_EQ(ATT_OP_HANDLE_IND, rsp[0]);

	/* Second while still within the window: refused EBUSY (§3.3.2). */
	errno = 0;
	ATF_CHECK_EQ(-1, att_send_indication(&ac, 0x0005, &v, 1));
	ATF_CHECK_EQ(EBUSY, errno);

	/* Simulate the confirmation window elapsing with no confirmation. */
	ac.ind_deadline.tv_sec -= 60;
	ATF_REQUIRE_EQ_MSG(0, att_send_indication(&ac, 0x0006, &v, 1),
	    "stale pending indication must self-heal, not wedge (errno=%d)",
	    errno);
	ATF_CHECK(ac.ind_pending);
	ATF_CHECK_EQ(0x0006, ac.ind_handle);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_EQ(4, n);
	ATF_CHECK_EQ(ATT_OP_HANDLE_IND, rsp[0]);

	att_mock_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_neg_read_by_type_zero_uuid16);
	ATF_TP_ADD_TC(tp, test_neg_empty_writable_char_is_writable);
	ATF_TP_ADD_TC(tp, test_neg_indication_self_heals_timeout);
	ATF_TP_ADD_TC(tp, test_neg_zero_length);
	ATF_TP_ADD_TC(tp, test_neg_mtu);
	ATF_TP_ADD_TC(tp, test_neg_find_info);
	ATF_TP_ADD_TC(tp, test_neg_find_by_type_value);
	ATF_TP_ADD_TC(tp, test_neg_read_by_type);
	ATF_TP_ADD_TC(tp, test_neg_read_by_group_type);
	ATF_TP_ADD_TC(tp, test_neg_read);
	ATF_TP_ADD_TC(tp, test_neg_read_blob);
	ATF_TP_ADD_TC(tp, test_neg_read_multiple);
	ATF_TP_ADD_TC(tp, test_neg_read_multiple_variable);
	ATF_TP_ADD_TC(tp, test_neg_write_req);
	ATF_TP_ADD_TC(tp, test_neg_write_cmd);
	ATF_TP_ADD_TC(tp, test_neg_prepare_write);
	ATF_TP_ADD_TC(tp, test_neg_prepare_queue_overflow);
	ATF_TP_ADD_TC(tp, test_neg_execute_write);
	ATF_TP_ADD_TC(tp, test_neg_signed_write);
	ATF_TP_ADD_TC(tp, test_neg_unknown_opcode);
	ATF_TP_ADD_TC(tp, test_neg_robust_caching_gating);
	ATF_TP_ADD_TC(tp, test_neg_fixed_request_overlong);

	return (atf_no_error());
}
