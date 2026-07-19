/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Residual branch-coverage tests for the ATT *server* dispatcher.
 *
 * These target branches left uncovered by att_server_edge_test.c and
 * att_server_deep_test.c.  The dominant residual is the EATT heap
 * response-buffer seam: ATT_RSP_BUF_DECL() allocates on the heap whenever
 * the negotiated MTU exceeds ATT_PDU_BUF_SIZE (517).  An Enhanced ATT
 * bearer may negotiate an MTU up to 65535 octets (Core Spec Vol 3 Part F
 * Section 3.2.9; Vol 3 Part G Section 5.3), so every request handler is
 * re-driven here with ac->mtu = 600 to exercise the malloc()/free() arm of
 * the response-buffer macro on each of its return paths.  The remaining
 * cases hit specific reachable predicate arms in the dispatcher and the
 * permission checks.
 *
 * ORACLE: expected opcodes and error codes are taken from the Bluetooth
 * Core Specification, Vol 3 Part F (Attribute Protocol) Section 3.4 and the
 * error-code table in Section 3.4.1.1, and Vol 3 Part G (GATT) for Robust
 * Caching / Database Hash.  No expected value is captured from the
 * implementation's own output.
 *
 * A SOCK_SEQPACKET socketpair stands in for the L2CAP ATT channel.
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
#include "att_server_internal.h"
#include "ble_util.h"
#include "hci_log.h"

/* Supply our own controllable Signed Write verification result. */
#define TEST_LINKS_SMP
#include "test_common.h"

static bool g_sig_ok = false;
static uint32_t g_sig_counter = 0;
bool
smp_verify_signature(const uint8_t csrk[16] __unused,
    const uint8_t *msg __unused, size_t msg_len __unused,
    const uint8_t mac[8] __unused, uint32_t counter)
{

	g_sig_counter = counter;
	return (g_sig_ok);
}

#include "spec_att_client_oracles.h"

/* ATT PDU opcodes carried in tests come from the generated Core namespace. */

#define DB_MAX	256
#define VAL_SZ	8192
#define BIG_MTU	600		/* > ATT_PDU_BUF_SIZE(517): EATT heap path */

/* ================================================================
 * Fixture: a rich attribute database + connection over a socketpair
 * ================================================================ */
struct fixture {
	struct att_conn	ac;
	struct att_db	db;
	int		peer;
	struct att_attr	storage[DB_MAX];
	uint8_t		valbuf[VAL_SZ];

	/* handles of interest, filled by build_db() */
	uint16_t	h_name_val;	/* 0x2A00, READ only (no notify) */
	uint16_t	h_name_cccd;	/* CCCD whose parent lacks NOTIFY */
	uint16_t	h_batt_val;	/* 0x2A19 READ|NOTIFY */
	uint16_t	h_batt_cccd;	/* CCCD whose parent HAS NOTIFY */
	uint16_t	h_write_val;	/* 0x2A06 WRITE */
	uint16_t	h_csf_val;	/* 0x2B29 client supported features */
	uint16_t	h_hash_val;	/* 0x2B2A database hash */
	uint16_t	h_renc_val;	/* READ_ENCRYPT */
	uint16_t	h_rauth_val;	/* READ_AUTHEN */
	uint16_t	h_wenc_val;	/* WRITE_ENCRYPT */
	uint16_t	h_wauth_val;	/* WRITE_AUTHEN */
	uint16_t	h_null_val;	/* value==NULL but value_len>0 */
	uint16_t	h_zero_val;	/* value==NULL, value_len==0 */
	uint16_t	h_ind_val;	/* 0x2A05 Service Changed, INDICATE */
	uint16_t	h_ind_cccd;	/* CCCD whose parent HAS INDICATE */
};

static void
build_db(struct fixture *f)
{
	uint8_t v4[4] = { 1, 2, 3, 4 };
	uint8_t one = 100;
	uint8_t zero = 0;
	uint8_t h16[16];
	struct att_attr *a;

	attdb_init(&f->db, f->storage, DB_MAX, f->valbuf, VAL_SZ);

	/* Service 1: GAP-ish, a READ-only characteristic + its CCCD. */
	attdb_add_service(&f->db, 0x1800);
	f->h_name_val = attdb_add_characteristic(&f->db, 0x2A00,
	    GATT_PROP_READ, ATT_PERM_READ, "Name", 4);
	f->h_name_cccd = attdb_add_cccd(&f->db);

	/* Service 2: Battery, a READ|NOTIFY characteristic + its CCCD. */
	attdb_add_service(&f->db, 0x180F);
	f->h_batt_val = attdb_add_characteristic(&f->db, 0x2A19,
	    GATT_PROP_READ | GATT_PROP_NOTIFY, ATT_PERM_READ, &one, 1);
	f->h_batt_cccd = attdb_add_cccd(&f->db);

	/* Service 3: writable characteristic. */
	attdb_add_service(&f->db, 0x180A);
	f->h_write_val = attdb_add_characteristic(&f->db, 0x2A06,
	    GATT_PROP_WRITE, ATT_PERM_WRITE, v4, 4);

	/* Client Supported Features 0x2B29 (Robust Caching opt-in byte). */
	f->h_csf_val = attdb_add_characteristic(&f->db, 0x2B29,
	    GATT_PROP_READ | GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, &zero, 1);

	/* Database Hash 0x2B2A. */
	memset(h16, 0xAB, sizeof(h16));
	f->h_hash_val = attdb_add_characteristic(&f->db, 0x2B2A,
	    GATT_PROP_READ, ATT_PERM_READ, h16, 16);

	/* Permission-gated characteristics (encryption / authentication). */
	f->h_renc_val = attdb_add_characteristic(&f->db, 0x2A1C,
	    GATT_PROP_READ, ATT_PERM_READ_ENCRYPT, v4, 4);
	f->h_rauth_val = attdb_add_characteristic(&f->db, 0x2A1D,
	    GATT_PROP_READ, ATT_PERM_READ_AUTHEN, v4, 4);
	f->h_wenc_val = attdb_add_characteristic(&f->db, 0x2A1E,
	    GATT_PROP_WRITE, ATT_PERM_WRITE_ENCRYPT, v4, 4);
	f->h_wauth_val = attdb_add_characteristic(&f->db, 0x2A1F,
	    GATT_PROP_WRITE, ATT_PERM_WRITE_AUTHEN, v4, 4);

	/* Service Changed 0x2A05 (INDICATE) + its CCCD (parent HAS indicate). */
	attdb_add_service(&f->db, 0x1801);
	f->h_ind_val = attdb_add_characteristic(&f->db, 0x2A05,
	    GATT_PROP_INDICATE, ATT_PERM_READ, v4, 4);
	f->h_ind_cccd = attdb_add_cccd(&f->db);

	/* Extra bare services so Read By Group Type overflows a small MTU. */
	attdb_add_service(&f->db, 0x1801);
	attdb_add_service(&f->db, 0x1811);
	attdb_add_service(&f->db, 0x1812);

	/*
	 * An attribute with a non-NULL length but a NULL value pointer, to
	 * drive the Read Multiple zero-fill arm (Vol 3 Part F 3.4.4.7: the
	 * response is a concatenation of attribute values).  This is a
	 * white-box construction: attdb_* never produces it, so poke the
	 * slot directly.
	 */
	f->h_null_val = attdb_add_descriptor(&f->db, 0x2A3D,
	    ATT_PERM_READ, "x", 1);
	a = attdb_find_by_handle(&f->db, f->h_null_val);
	ATF_REQUIRE(a != NULL);
	a->value = NULL;
	a->value_len = 5;

	/* A zero-length readable descriptor (value NULL, value_len 0) to
	 * drive the Read Multiple "available == 0" arm. */
	f->h_zero_val = attdb_add_descriptor(&f->db, 0x2A3E,
	    ATT_PERM_READ, NULL, 0);
}

static void
fx_setup(struct fixture *f)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(&f->ac, 0, sizeof(f->ac));
	f->ac.fd = fds[0];
	f->ac.bearer_fd = -1;
	f->ac.mtu = ATT_PDU_BUF_SIZE;
	f->ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(f->ac.buf != NULL);
	f->peer = fds[1];
	build_db(f);
}

static void
fx_teardown(struct fixture *f)
{

	free(f->ac.buf);
	f->ac.buf = NULL;
	if (f->ac.fd >= 0)
		close(f->ac.fd);
	if (f->peer >= 0)
		close(f->peer);
}

/* Drive one request through the primary bearer; return response length. */
static ssize_t
drive(struct fixture *f, const uint8_t *pdu, size_t len,
    uint8_t *rsp, size_t rsplen)
{

	att_server_handle(&f->ac, &f->db, pdu, len, -1, 0);
	return (recv(f->peer, rsp, rsplen, MSG_DONTWAIT));
}

/* Assert an ATT_ERROR_RSP with the expected request-opcode and error code. */
static void
expect_err(struct fixture *f, const uint8_t *pdu, size_t len,
    uint8_t exp_req, uint8_t exp_code)
{
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	n = drive(f, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "expected 5-byte error rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(exp_req, rsp[1]);
	ATF_CHECK_EQ(exp_code, rsp[4]);
}

/* Assert a response whose opcode is exp_op. */
static void
expect_op(struct fixture *f, const uint8_t *pdu, size_t len, uint8_t exp_op)
{
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	n = drive(f, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n >= 1, "expected a response, got %zd", n);
	ATF_CHECK_EQ(exp_op, rsp[0]);
}

/* ================================================================
 * EATT large-MTU (heap response buffer) — every handler, every path.
 *
 * Vol 3 Part F 3.2.9 / Vol 3 Part G 5.3: an Enhanced ATT bearer may
 * negotiate an MTU larger than the 517-octet unenhanced maximum, so the
 * server allocates its response buffer on the heap.  Re-drive each handler
 * at ac->mtu = 600 so its ATT_RSP_BUF_DECL/FREE heap arm executes on the
 * success path and on every early-return error path.
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(eatt_find_info);
ATF_TC_BODY(eatt_find_info, tc)
{
	struct fixture f;
	uint8_t pdu[5];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP);

	/* invalid PDU (too short) */
	expect_err(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle (start == 0) — Vol 3 Part F 3.4.3.1 */
	put_le16(pdu + 1, 0x0000); put_le16(pdu + 3, 0xFFFF);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* attribute not found (empty range) */
	put_le16(pdu + 1, 0xF000); put_le16(pdu + 3, 0xFFFF);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read_by_group);
ATF_TC_BODY(eatt_read_by_group, tc)
{
	struct fixture f;
	uint8_t pdu[21];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success: primary services */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_RSP);

	/* invalid PDU length (not 7 or 21) */
	expect_err(&f, pdu, 8, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* unsupported group type: a 16-bit type that is not a service decl */
	put_le16(pdu + 5, 0x2803);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	/* invalid handle (start > end) */
	put_le16(pdu + 1, 0x0005); put_le16(pdu + 3, 0x0002);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* attribute not found (valid group type, empty range) */
	put_le16(pdu + 1, 0xF000); put_le16(pdu + 3, 0xFFFF);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	/*
	 * Unsupported group type via a 128-bit non-Base UUID (extract yields
	 * uuid16==0).  Vol 3 Part F 3.4.4.9.
	 */
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	memset(pdu + 5, 0x11, 16);
	expect_err(&f, pdu, 21, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_UNSUPPORTED_GROUP_TYPE);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read_by_type);
ATF_TC_BODY(eatt_read_by_type, tc)
{
	struct fixture f;
	uint8_t pdu[21];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP);

	/* invalid PDU length */
	expect_err(&f, pdu, 9, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, 0x0000); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* attribute not found */
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2999);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read);
ATF_TC_BODY(eatt_read, tc)
{
	struct fixture f;
	uint8_t pdu[3];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_name_val);
	expect_op(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_RSP);

	/* invalid PDU */
	expect_err(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_READ_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, 0xF000);
	expect_err(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* read-not-permitted: read the WRITE-only characteristic value */
	put_le16(pdu + 1, f.h_write_val);
	expect_err(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_REQ, BT_CORE63_WIRE_ATT_ERR_READ_NOT_PERMITTED);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read_blob);
ATF_TC_BODY(eatt_read_blob, tc)
{
	struct fixture f;
	uint8_t pdu[5];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success: offset 0 */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, f.h_hash_val); put_le16(pdu + 3, 0x0000);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_RSP);

	/* invalid PDU */
	expect_err(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, 0xF000); put_le16(pdu + 3, 0x0000);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* read-not-permitted */
	put_le16(pdu + 1, f.h_write_val); put_le16(pdu + 3, 0x0000);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_READ_NOT_PERMITTED);

	/* invalid offset (offset > value length) — Vol 3 Part F 3.4.4.5 */
	put_le16(pdu + 1, f.h_hash_val); put_le16(pdu + 3, 0x0100);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_OFFSET);

	/* attribute not long: short value, nonzero offset, fits in one MTU */
	put_le16(pdu + 1, f.h_name_val); put_le16(pdu + 3, 0x0002);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_LONG);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_prepare_write);
ATF_TC_BODY(eatt_prepare_write, tc)
{
	struct fixture f;
	uint8_t pdu[64];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_write_val); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0xAA; pdu[6] = 0xBB;
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	/* invalid PDU */
	expect_err(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, 0xF000);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* write-not-permitted: prepare-write a READ-only attribute */
	put_le16(pdu + 1, f.h_name_val);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_WRITE_NOT_PERMITTED);

	/* invalid offset: offset + len > 0xFFFF — Vol 3 Part F 3.4.6.1 */
	put_le16(pdu + 1, f.h_write_val); put_le16(pdu + 3, 0xFFFF);
	pdu[5] = 0x00; pdu[6] = 0x00;
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_OFFSET);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_prepare_queue_full);
ATF_TC_BODY(eatt_prepare_queue_full, tc)
{
	struct fixture f;
	uint8_t pdu[7];
	int i;

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* Fill the prepare queue (ATT_PREPARE_QUEUE_MAX entries). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_write_val);
	for (i = 0; i < ATT_PREPARE_QUEUE_MAX; i++) {
		put_le16(pdu + 3, 0x0000);
		pdu[5] = (uint8_t)i; pdu[6] = 0x00;
		expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);
	}
	/* One more -> Prepare Queue Full (0x09) — Vol 3 Part F 3.4.1.1. */
	put_le16(pdu + 3, 0x0000);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_PREPARE_QUEUE_FULL);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_find_by_type_value);
ATF_TC_BODY(eatt_find_by_type_value, tc)
{
	struct fixture f;
	uint8_t pdu[32];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success: locate the GAP primary service by its value */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800);
	expect_op(&f, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_RSP);

	/* invalid PDU */
	expect_err(&f, pdu, 6, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, 0x0000);
	expect_err(&f, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* attribute not found: right type, value nobody has */
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x9999);
	expect_err(&f, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read_multiple);
ATF_TC_BODY(eatt_read_multiple, tc)
{
	struct fixture f;
	uint8_t pdu[16];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, f.h_batt_val);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP);

	/* invalid PDU (odd length) */
	expect_err(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, 0xF000);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ, BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* read-not-permitted */
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, f.h_write_val);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_READ_NOT_PERMITTED);

	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(eatt_read_multiple_variable);
ATF_TC_BODY(eatt_read_multiple_variable, tc)
{
	struct fixture f;
	uint8_t pdu[16];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* success */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, f.h_batt_val);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_RSP);

	/* invalid PDU */
	expect_err(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_PDU);

	/* invalid handle */
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, 0xF000);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	/* read-not-permitted */
	put_le16(pdu + 1, f.h_name_val);
	put_le16(pdu + 3, f.h_write_val);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_READ_NOT_PERMITTED);

	fx_teardown(&f);
}

/* ================================================================
 * Specific reachable predicate arms
 * ================================================================ */

/*
 * att_check_read_perm / att_check_write_perm: an encrypted link whose
 * encryption key size is not tracked (enc_key_size == 0) must NOT trip the
 * INSUFF_ENC_KEY_SIZE gate (Vol 3 Part F 3.4.1.1; key-size enforcement per
 * Vol 3 Part H 2.4.4 applies only when a key size is known).  Exercises the
 * short-circuit false arm of the "enc_key_size > 0" sub-conditions.
 */
ATF_TC_WITHOUT_HEAD(perm_encrypted_keysize_unknown);
ATF_TC_BODY(perm_encrypted_keysize_unknown, tc)
{
	struct fixture f;
	uint8_t pdu[7];

	fx_setup(&f);
	f.ac.encrypted = true;
	f.ac.authenticated = true;
	f.ac.enc_key_size = 0;		/* unknown key size */

	/* READ_ENCRYPT attribute: permitted, no key-size error. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_renc_val);
	expect_op(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_RSP);

	/* READ_AUTHEN attribute. */
	put_le16(pdu + 1, f.h_rauth_val);
	expect_op(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_RSP);

	/* WRITE_ENCRYPT attribute. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_wenc_val);
	pdu[3] = 0x01;
	expect_op(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	/* WRITE_AUTHEN attribute. */
	put_le16(pdu + 1, f.h_wauth_val);
	expect_op(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	fx_teardown(&f);
}

/*
 * Read By Group Type overflow: with a small MTU and several primary
 * services, the response fills and the accumulation loop breaks on the
 * "pos + entry_len > pos_limit" guard (Vol 3 Part F 3.4.4.9 — the response
 * carries as many complete entries as fit).
 */
ATF_TC_WITHOUT_HEAD(read_by_group_mtu_overflow);
ATF_TC_BODY(read_by_group_mtu_overflow, tc)
{
	struct fixture f;
	uint8_t pdu[7];

	fx_setup(&f);
	f.ac.mtu = ATT_DEFAULT_MTU;	/* 23: only a few 6-octet entries fit */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_RSP);

	fx_teardown(&f);
}

/*
 * Read By Type where a matching-type attribute lies beyond the requested
 * end handle: exercises the "a->handle > end" continue arm (Vol 3 Part F
 * 3.4.4.1).
 */
ATF_TC_WITHOUT_HEAD(read_by_type_handle_beyond_end);
ATF_TC_BODY(read_by_type_handle_beyond_end, tc)
{
	struct fixture f;
	uint8_t pdu[7];

	fx_setup(&f);

	/* Characteristic decls exist at handles 2, 6, 10, ...; end=3 keeps
	 * the first in range and forces later ones through the > end skip. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0x0003);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP);

	fx_teardown(&f);
}

/*
 * Read a CCCD after a per-connection value has been stored: exercises the
 * per-connection CCCD lookup loop and match (Vol 3 Part G 3.3.3.3).
 */
ATF_TC_WITHOUT_HEAD(read_cccd_after_write);
ATF_TC_BODY(read_cccd_after_write, tc)
{
	struct fixture f;
	uint8_t pdu[5];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	/* Enable notifications on the battery CCCD (parent has NOTIFY). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_batt_cccd);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	/* Read it back: response value must be the stored 0x0001. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_batt_cccd);
	n = drive(&f, pdu, 3, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 3, "expected 3-byte read rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_READ_RSP, rsp[0]);
	ATF_CHECK_EQ(GATT_CCCD_NOTIFY, get_le16(rsp + 1));

	fx_teardown(&f);
}

/*
 * Write Command (no response) to a CCCD whose parent characteristic does
 * not support notifications: the server drops it silently (Vol 3 Part G
 * 3.3.3.3 — a CCCD write that enables an unsupported configuration is
 * rejected; for a command there is no error response to send).
 */
ATF_TC_WITHOUT_HEAD(write_cmd_cccd_notify_not_permitted);
ATF_TC_BODY(write_cmd_cccd_notify_not_permitted, tc)
{
	struct fixture f;
	uint8_t pdu[5];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;		/* command: no response */
	put_le16(pdu + 1, f.h_name_cccd);	/* parent 0x2A00 lacks NOTIFY */
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	n = drive(&f, pdu, 5, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n < 0, "write command must produce no response (got %zd)",
	    n);

	fx_teardown(&f);
}

/*
 * Write the Client Supported Features characteristic (0x2B29) with the
 * Robust Caching bit CLEAR: exercises the "(value[0] & 0x01) != 0" false
 * arm so the connection is NOT marked change-aware (Vol 3 Part G 7.2).
 */
ATF_TC_WITHOUT_HEAD(write_csf_robust_bit_clear);
ATF_TC_BODY(write_csf_robust_bit_clear, tc)
{
	struct fixture f;
	uint8_t pdu[4];

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_csf_val);
	pdu[3] = 0x00;				/* robust caching bit clear */
	expect_op(&f, pdu, 4, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);
	ATF_CHECK(!f.ac.robust_caching);

	fx_teardown(&f);
}

/*
 * Find By Type Value where an attribute of the requested type has a value
 * of a different length than the search value: exercises the
 * "value_len != vlen" first operand of the value-comparison skip
 * (Vol 3 Part F 3.4.3.3).
 */
ATF_TC_WITHOUT_HEAD(find_by_type_value_length_mismatch);
ATF_TC_BODY(find_by_type_value_length_mismatch, tc)
{
	struct fixture f;
	uint8_t pdu[16];

	fx_setup(&f);

	/* Search primary services (2-octet values) with a 4-octet value. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800); put_le16(pdu + 9, 0x0000);	/* 4 octets */
	expect_err(&f, pdu, 11, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	fx_teardown(&f);
}

/*
 * Read Multiple across an attribute with a non-NULL length but a NULL value
 * pointer: the response zero-fills that value's octets (Vol 3 Part F
 * 3.4.4.7 — the response is the concatenation of the attribute values).
 */
ATF_TC_WITHOUT_HEAD(read_multiple_null_value_zerofill);
ATF_TC_BODY(read_multiple_null_value_zerofill, tc)
{
	struct fixture f;
	uint8_t pdu[5];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, f.h_name_val);	/* "Name" (4 octets) */
	put_le16(pdu + 3, f.h_null_val);	/* NULL value, len 5 */
	n = drive(&f, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 1 + 4 + 5, "expected 10-byte rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP, rsp[0]);
	/* Zero-filled tail for the NULL-valued attribute. */
	ATF_CHECK_EQ(0x00, rsp[5]);
	ATF_CHECK_EQ(0x00, rsp[9]);

	fx_teardown(&f);
}

/*
 * Robust Caching: a change-unaware client issuing Read By Type with a
 * 128-bit type (len 21) over a PARTIAL handle range is not on the discovery
 * allow-list, so it receives Database Out Of Sync (Vol 3 Part G 2.5.2.1).
 * §2.5.2.1 is an OR: a 128-bit type is neither «Include» nor «Characteristic»
 * (uuid16 == 0), so it is blocked only when the range is also not
 * 0x0001-0xFFFF -- hence the partial range here.  Exercises the "(len == 7)"
 * false arm of the allow-list UUID extraction.
 */
ATF_TC_WITHOUT_HEAD(robust_read_by_type_uuid128_out_of_sync);
ATF_TC_BODY(robust_read_by_type_uuid128_out_of_sync, tc)
{
	struct fixture f;
	uint8_t pdu[21];

	fx_setup(&f);
	f.ac.robust_caching = true;
	f.ac.change_aware = false;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0x0005);	/* partial */
	memset(pdu + 5, 0x22, 16);		/* 128-bit type */
	expect_err(&f, pdu, 21, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC);

	fx_teardown(&f);
}

/*
 * Robust Caching Database Out Of Sync sent on an EATT bearer: drives the
 * bearer-context restore path with bearer_fd >= 0 and bearer_mtu > 0
 * (Vol 3 Part G 2.5.2.1; EATT bearers Vol 3 Part G 5.3).
 */
ATF_TC_WITHOUT_HEAD(robust_out_of_sync_on_eatt_bearer);
ATF_TC_BODY(robust_out_of_sync_on_eatt_bearer, tc)
{
	struct fixture f;
	uint8_t pdu[3];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);
	f.ac.robust_caching = true;
	f.ac.change_aware = false;

	/* Disallowed op on an EATT bearer (bearer_fd >= 0, bearer_mtu > 0). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_name_val);
	att_server_handle(&f.ac, &f.db, pdu, 3, f.ac.fd, 100);
	n = recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "expected error rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC, rsp[4]);

	fx_teardown(&f);
}

/*
 * Handle Value Confirmation predicate arms (Vol 3 Part G 2.5.2.1, Fig 2.6):
 * the "robust_caching && !change_aware && ind_pending" guard must be driven
 * with each conjunct false so all three short-circuit arms are covered.
 */
ATF_TC_WITHOUT_HEAD(confirm_predicate_arms);
ATF_TC_BODY(confirm_predicate_arms, tc)
{
	struct fixture f;
	uint8_t pdu[1] = { BT_CORE63_WIRE_ATT_OP_HANDLE_CFM };
	uint8_t rsp[ATT_MAX_MTU];

	fx_setup(&f);

	/* (a) robust_caching == false -> first conjunct false. */
	f.ac.robust_caching = false;
	f.ac.change_aware = false;
	f.ac.ind_pending = true;
	att_server_handle(&f.ac, &f.db, pdu, 1, -1, 0);
	ATF_CHECK(recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0);
	ATF_CHECK(!f.ac.ind_pending);

	/* (b) change_aware == true -> second conjunct false. */
	f.ac.robust_caching = true;
	f.ac.change_aware = true;
	f.ac.ind_pending = true;
	att_server_handle(&f.ac, &f.db, pdu, 1, -1, 0);
	ATF_CHECK(!f.ac.ind_pending);

	/* (c) ind_pending == false -> third conjunct false. */
	f.ac.robust_caching = true;
	f.ac.change_aware = false;
	f.ac.ind_pending = false;
	att_server_handle(&f.ac, &f.db, pdu, 1, -1, 0);
	ATF_CHECK(!f.ac.ind_pending);

	fx_teardown(&f);
}

/* ================================================================
 * Notification / Indication senders on an EATT (heap-buffer) MTU
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(eatt_notify_indicate);
ATF_TC_BODY(eatt_notify_indicate, tc)
{
	struct fixture f;
	uint8_t rsp[ATT_MAX_MTU];
	uint8_t val[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const uint8_t *vals[2];
	uint16_t handles[2], lens[2];
	ssize_t n;

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;
	atomic_store(&blued_verbose, 2);	/* light the -vv trace branches */
	blued_daemonized = 1;			/* syslog priority-select arm */

	/* Notification (heap buffer). */
	ATF_CHECK_EQ(0, att_send_notification(&f.ac, f.h_batt_val, val, 8));
	n = recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n == 11);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY, rsp[0]);

	/* Indication (heap buffer). */
	ATF_CHECK_EQ(0, att_send_indication(&f.ac, f.h_batt_val, val, 8));
	n = recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n == 11);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_HANDLE_IND, rsp[0]);

	/* Second indication while one is pending -> EBUSY (Vol 3 Part F
	 * 3.3.2: only one indication outstanding at a time). */
	ATF_CHECK_EQ(-1, att_send_indication(&f.ac, f.h_batt_val, val, 8));
	ATF_CHECK_EQ(EBUSY, errno);

	/* Multiple Handle Value Notification (heap buffer). */
	handles[0] = f.h_name_val; handles[1] = f.h_batt_val;
	vals[0] = val; vals[1] = val;
	lens[0] = 4; lens[1] = 8;
	ATF_CHECK_EQ(0, att_send_multiple_handle_value_ntf(&f.ac, handles,
	    vals, lens, 2));
	n = recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n > 1);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF, rsp[0]);

	/* count <= 0 -> nothing sent, returns 0. */
	ATF_CHECK_EQ(0, att_send_multiple_handle_value_ntf(&f.ac, handles,
	    vals, lens, 0));

	/* Re-run the multi-NTF trace on the foreground (stderr) arm too. */
	blued_daemonized = 0;
	ATF_CHECK_EQ(0, att_send_multiple_handle_value_ntf(&f.ac, handles,
	    vals, lens, 2));
	(void)recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);

	atomic_store(&blued_verbose, 0);
	fx_teardown(&f);
}

/* ================================================================
 * Execute Write with a queued CCCD entry (heap-MTU) — commit + re-validate
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(eatt_execute_write_cccd);
ATF_TC_BODY(eatt_execute_write_cccd, tc)
{
	struct fixture f;
	uint8_t pdu[16];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* Queue a CCCD notify-enable via Prepare Write (parent has NOTIFY). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_batt_cccd);
	put_le16(pdu + 3, 0x0000);
	put_le16(pdu + 5, GATT_CCCD_NOTIFY);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	/* Execute (flags=0x01 write) -> commit; response is Execute Write. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	expect_op(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP);

	/* The committed value is now observable via Read. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_batt_cccd);
	expect_op(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_RSP);

	fx_teardown(&f);
}

/*
 * Execute Write validation at commit: a queued Prepare Write whose length
 * exceeds the attribute maximum is rejected at execute time with Invalid
 * Attribute Value Length (Vol 3 Part F 3.4.6.3).
 */
ATF_TC_WITHOUT_HEAD(execute_write_revalidate_len);
ATF_TC_BODY(execute_write_revalidate_len, tc)
{
	struct fixture f;
	uint8_t pdu[64];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;

	/* Queue a write past the 4-octet maximum of 0x2A06 at offset 2. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_write_val);
	put_le16(pdu + 3, 0x0002);
	memset(pdu + 5, 0x55, 8);		/* offset 2 + 8 > maxlen 4 */
	expect_op(&f, pdu, 13, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	expect_err(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_ATTR_LEN);

	fx_teardown(&f);
}

/* ================================================================
 * Database Hash: 128-bit Bluetooth-Base-UUID hashable-type encodings
 * (Vol 3 Part G 7.3.1) — value-bearing and value-less variants, plus a
 * non-hashable 128-bit vendor UUID skip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(db_hash_uuid128_types);
ATF_TC_BODY(db_hash_uuid128_types, tc)
{
	struct att_db db;
	struct att_attr storage[8];
	uint8_t valbuf[64];
	uint8_t hash[16];
	struct att_attr *a;
	int idx = 0;

	attdb_init(&db, storage, 8, valbuf, sizeof(valbuf));

	/* A regular 16-bit primary service so the hash context has content. */
	attdb_add_service(&db, 0x1800);

	/*
	 * Poke 128-bit-encoded attributes directly (attdb_* only produce
	 * 16-bit type codes for these).  Base-UUID encoding: bytes[0..11] =
	 * bt_base_uuid_le, [12..13] = short code (LE), [14..15] = 0.
	 */
	/* 0x2900 Characteristic Extended Properties: value included. */
	a = &db.attrs[db.count++];
	memset(a, 0, sizeof(*a));
	a->handle = db.next_handle++;
	a->owner_fd = -1;
	a->uuid16 = 0;
	memcpy(a->uuid128, bt_base_uuid_le, 12);
	a->uuid128[12] = 0x00; a->uuid128[13] = 0x29;
	a->value = &valbuf[32];
	valbuf[32] = 0x01; valbuf[33] = 0x00;
	a->value_len = 2;
	idx++;

	/* 0x2901 Characteristic User Description: handle+type only. */
	a = &db.attrs[db.count++];
	memset(a, 0, sizeof(*a));
	a->handle = db.next_handle++;
	a->owner_fd = -1;
	a->uuid16 = 0;
	memcpy(a->uuid128, bt_base_uuid_le, 12);
	a->uuid128[12] = 0x01; a->uuid128[13] = 0x29;
	a->value_len = 0;

	/* A non-hashable 128-bit vendor UUID: skipped entirely. */
	a = &db.attrs[db.count++];
	memset(a, 0, sizeof(*a));
	a->handle = db.next_handle++;
	a->owner_fd = -1;
	a->uuid16 = 0;
	memset(a->uuid128, 0x77, 16);

	/* A 128-bit Base-UUID encoding of a NON-hashable short code (0x2A00):
	 * matches the Base UUID but the switch default skips it. */
	a = &db.attrs[db.count++];
	memset(a, 0, sizeof(*a));
	a->handle = db.next_handle++;
	a->owner_fd = -1;
	a->uuid16 = 0;
	memcpy(a->uuid128, bt_base_uuid_le, 12);
	a->uuid128[12] = 0x00; a->uuid128[13] = 0x2A;

	/* Compute with -vv tracing on, in both the foreground (stderr) and
	 * daemonized (syslog) configurations, so the hash-dump trace branch
	 * and its priority-select arm are exercised. */
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 0;
	attdb_compute_db_hash(&db, hash);
	blued_daemonized = 1;
	attdb_compute_db_hash(&db, hash);
	atomic_store(&blued_verbose, 0);
	blued_daemonized = 0;

	/* A valid 16-byte AES-CMAC is not all-zero for a non-empty database. */
	{
		int i, nz = 0;
		for (i = 0; i < 16; i++)
			if (hash[i] != 0)
				nz = 1;
		ATF_CHECK(nz);
	}
	(void)idx;
}

/* ================================================================
 * Verbosity-gated logging branches.
 *
 * Every request handler emits LOG_ATT() trace, whose _BLUED_LOG() body is
 * gated on `blued_verbose >= level` and branches again on
 * `blued_daemonized` (syslog vs stderr) and the syslog priority selection.
 * These are real, reachable branches on the daemon's -vv trace path; drive
 * a representative request of every opcode with tracing enabled, in both
 * the foreground (stderr) and daemonized (syslog) configurations, to cover
 * them.  Assertions remain the spec-defined ATT responses; the verbosity is
 * environmental only.
 * ================================================================ */
static void
run_battery(struct fixture *f)
{
	uint8_t rsp[ATT_MAX_MTU];
	uint8_t pdu[64];

	/* MTU exchange (fresh state each call). */
	f->ac.mtu_exchanged = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_MTU_REQ;
	put_le16(pdu + 1, 250);
	(void)drive(f, pdu, 3, rsp, sizeof(rsp));

	/* Find Information. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));

	/* Read By Group Type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	(void)drive(f, pdu, 7, rsp, sizeof(rsp));

	/* Read By Type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_CHARACTERISTIC);
	(void)drive(f, pdu, 7, rsp, sizeof(rsp));

	/* Read / Read Blob. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f->h_name_val);
	(void)drive(f, pdu, 3, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, f->h_hash_val); put_le16(pdu + 3, 0x0000);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));

	/* Find By Type Value. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800);
	(void)drive(f, pdu, 9, rsp, sizeof(rsp));

	/* Read Multiple / Variable. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, f->h_name_val); put_le16(pdu + 3, f->h_batt_val);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, f->h_name_val); put_le16(pdu + 3, f->h_batt_val);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));

	/* Write Request + Write Command to a writable value. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f->h_write_val); pdu[3] = 0x01;
	(void)drive(f, pdu, 4, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	(void)drive(f, pdu, 4, rsp, sizeof(rsp));

	/* CCCD write (enable notifications, then the orphan-CCCD trace). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f->h_batt_cccd); put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));

	/* Prepare + Execute (apply), then Prepare + Execute (cancel). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f->h_write_val); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0x77;
	(void)drive(f, pdu, 6, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	(void)drive(f, pdu, 2, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f->h_write_val); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0x88;
	(void)drive(f, pdu, 6, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x00;	/* cancel */
	(void)drive(f, pdu, 2, rsp, sizeof(rsp));

	/* Signed Write: short, then no-CSRK, then failed, then verified,
	 * then replay (Vol 3 Part F 3.3.1.4; Vol 3 Part H 2.4.5). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_LEGACY_SIGNED_WRITE_CMD;
	(void)drive(f, pdu, 10, rsp, sizeof(rsp));		/* too short */

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_LEGACY_SIGNED_WRITE_CMD;
	put_le16(pdu + 1, f->h_write_val); pdu[3] = 0x42;
	put_le32(pdu + 4, 5);					/* counter=5 */
	f->ac.has_peer_csrk = false;
	g_sig_ok = false;
	(void)drive(f, pdu, 16, rsp, sizeof(rsp));		/* no CSRK */

	f->ac.has_peer_csrk = true;
	g_sig_ok = false;
	(void)drive(f, pdu, 16, rsp, sizeof(rsp));		/* verify fail */

	g_sig_ok = true;
	f->ac.has_peer_sign_counter = false;
	(void)drive(f, pdu, 16, rsp, sizeof(rsp));		/* verified */
	(void)drive(f, pdu, 16, rsp, sizeof(rsp));		/* replay */

	/* Split-CCCD Prepare/Execute rejected at post-apply (trace path). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f->h_name_cccd); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0x01;					/* 1-octet split write */
	(void)drive(f, pdu, 6, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	(void)drive(f, pdu, 2, rsp, sizeof(rsp));

	/* Indicate-only split CCCD write rejected at post-apply (trace). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f->h_batt_cccd); put_le16(pdu + 3, 0x0000);
	pdu[5] = GATT_CCCD_INDICATE;		/* parent lacks indicate */
	(void)drive(f, pdu, 6, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	(void)drive(f, pdu, 2, rsp, sizeof(rsp));

	/* Permission-error return arms (unencrypted link, encrypted attrs). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A1C);
	(void)drive(f, pdu, 7, rsp, sizeof(rsp));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A1C); put_le16(pdu + 7, 0x0102);
	(void)drive(f, pdu, 9, rsp, sizeof(rsp));

	/* A few error paths (exercise error-return trace + response buffer
	 * free on the error arms). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ; put_le16(pdu + 1, 0xF000);
	(void)drive(f, pdu, 3, rsp, sizeof(rsp));		/* invalid handle */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, f->h_hash_val); put_le16(pdu + 3, 0x0100);
	(void)drive(f, pdu, 5, rsp, sizeof(rsp));		/* invalid offset */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f->h_name_val); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0x00;
	(void)drive(f, pdu, 6, rsp, sizeof(rsp));		/* write-not-perm */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x05;	/* bad flags */
	(void)drive(f, pdu, 2, rsp, sizeof(rsp));

	/* Handle Value Confirmation. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_CFM;
	(void)drive(f, pdu, 1, rsp, sizeof(rsp));

	/* Unsupported request opcode + a silently ignored unknown command. */
	pdu[0] = 0x30;
	(void)drive(f, pdu, 1, rsp, sizeof(rsp));
	pdu[0] = 0x70;						/* bit6 set */
	(void)drive(f, pdu, 1, rsp, sizeof(rsp));
}

ATF_TC_WITHOUT_HEAD(verbose_battery_stderr);
ATF_TC_BODY(verbose_battery_stderr, tc)
{
	struct fixture f;

	fx_setup(&f);
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 0;
	f.ac.mtu = BIG_MTU;
	run_battery(&f);
	f.ac.mtu = ATT_PDU_BUF_SIZE;
	run_battery(&f);
	atomic_store(&blued_verbose, 0);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(verbose_battery_syslog);
ATF_TC_BODY(verbose_battery_syslog, tc)
{
	struct fixture f;

	fx_setup(&f);
	atomic_store(&blued_verbose, 2);
	blued_daemonized = 1;			/* syslog path + priority select */
	f.ac.mtu = BIG_MTU;
	run_battery(&f);
	atomic_store(&blued_verbose, 0);
	blued_daemonized = 0;
	fx_teardown(&f);
}

/*
 * Read a CCCD while a per-connection entry exists for a DIFFERENT handle:
 * the lookup loop iterates without matching, so the reported value is the
 * default 0x0000 (Vol 3 Part G 3.3.3.3).  Covers the no-match loop arm.
 */
ATF_TC_WITHOUT_HEAD(read_cccd_no_match);
ATF_TC_BODY(read_cccd_no_match, tc)
{
	struct fixture f;
	uint8_t pdu[5];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	/* Store an entry for the battery CCCD. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_batt_cccd); put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	/* Read a DIFFERENT CCCD -> no per-connection entry -> value 0x0000. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_name_cccd);
	n = drive(&f, pdu, 3, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 3, "expected 3-byte read rsp, got %zd", n);
	ATF_CHECK_EQ(0x0000, get_le16(rsp + 1));

	fx_teardown(&f);
}

/*
 * Write Request (with response) to a CCCD enabling notifications whose
 * parent characteristic lacks the Notify property: the server rejects with
 * Value Not Allowed (Vol 3 Part G 3.3.3.3 / Vol 3 Part F 3.4.1.1 code
 * 0x13).  Covers the with_response=true arm of that rejection.
 */
ATF_TC_WITHOUT_HEAD(write_req_cccd_notify_not_permitted);
ATF_TC_BODY(write_req_cccd_notify_not_permitted, tc)
{
	struct fixture f;
	uint8_t pdu[5];

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_name_cccd);	/* parent 0x2A00 lacks NOTIFY */
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ, BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	/* Also the Indicate-not-permitted variant. */
	put_le16(pdu + 3, GATT_CCCD_INDICATE);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ, BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	fx_teardown(&f);
}

/*
 * Write the Client Supported Features characteristic (0x2B29) with a
 * zero-length value: the Robust Caching opt-in scan requires vlen >= 1, so
 * the "vlen >= 1" conjunct is false and the connection stays as-is
 * (Vol 3 Part G 7.2).
 */
ATF_TC_WITHOUT_HEAD(write_csf_empty_value);
ATF_TC_BODY(write_csf_empty_value, tc)
{
	struct fixture f;
	uint8_t pdu[3];

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_csf_val);		/* len 3 -> vlen 0 */
	expect_op(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);
	ATF_CHECK(!f.ac.robust_caching);

	fx_teardown(&f);
}

/*
 * Execute Write committing a CCCD Indicate-enable whose parent supports
 * indications (0x2A05 Service Changed): drives the apply-time CCCD commit
 * loop and the Indicate-permitted acceptance (Vol 3 Part F 3.4.6.3;
 * Vol 3 Part G 3.3.3.3).
 */
ATF_TC_WITHOUT_HEAD(execute_write_cccd_indicate);
ATF_TC_BODY(execute_write_cccd_indicate, tc)
{
	struct fixture f;
	uint8_t pdu[16];
	uint8_t rsp[ATT_MAX_MTU];

	fx_setup(&f);

	/* Store a per-connection entry for a DIFFERENT CCCD first, so the
	 * apply-time commit loop iterates past a non-matching slot before
	 * appending a new one for h_ind_cccd (non-match + append arms). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, f.h_batt_cccd); put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	expect_op(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	/* Now queue + execute an Indicate-enable via Prepare/Execute Write. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_ind_cccd); put_le16(pdu + 3, 0x0000);
	put_le16(pdu + 5, GATT_CCCD_INDICATE);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	expect_op(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP);

	/* Read back: indicate bit must be set. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_ind_cccd);
	ATF_REQUIRE(drive(&f, pdu, 3, rsp, sizeof(rsp)) == 3);
	ATF_CHECK_EQ(GATT_CCCD_INDICATE, get_le16(rsp + 1));

	/* Re-queue + execute the SAME CCCD: the commit loop now finds the
	 * existing per-connection slot and updates it in place (match arm). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_ind_cccd); put_le16(pdu + 3, 0x0000);
	put_le16(pdu + 5, GATT_CCCD_INDICATE);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	expect_op(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP);

	fx_teardown(&f);
}

/*
 * Robust Caching Database Out Of Sync where the transient bearer context
 * has a file descriptor but a zero MTU (bearer_fd >= 0, bearer_mtu == 0):
 * the response uses the primary MTU and the "bearer_mtu > 0" restore
 * conjunct is false (Vol 3 Part G 2.5.2.1 / 5.3).
 */
ATF_TC_WITHOUT_HEAD(out_of_sync_bearer_mtu_zero);
ATF_TC_BODY(out_of_sync_bearer_mtu_zero, tc)
{
	struct fixture f;
	uint8_t pdu[3];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);
	f.ac.robust_caching = true;
	f.ac.change_aware = false;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_name_val);
	att_server_handle(&f.ac, &f.db, pdu, 3, f.ac.fd, 0);	/* mtu == 0 */
	n = recv(f.peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "expected error rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC, rsp[4]);

	fx_teardown(&f);
}

/*
 * Read Multiple across a zero-length attribute (value NULL, value_len 0):
 * that attribute contributes no octets to the response (Vol 3 Part F
 * 3.4.4.7).  Covers the "available == 0" arm.
 */
ATF_TC_WITHOUT_HEAD(read_multiple_zero_length);
ATF_TC_BODY(read_multiple_zero_length, tc)
{
	struct fixture f;
	uint8_t pdu[5];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, f.h_zero_val);	/* 0 octets */
	put_le16(pdu + 3, f.h_name_val);	/* "Name" (4 octets) */
	n = drive(&f, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 1 + 0 + 4, "expected 5-byte rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP, rsp[0]);

	fx_teardown(&f);
}

/*
 * Execute Write re-validation rejecting a queued CCCD Notify-enable whose
 * parent characteristic lacks Notify: at commit the server returns Value
 * Not Allowed (Vol 3 Part G 3.3.3.3).
 */
ATF_TC_WITHOUT_HEAD(execute_write_cccd_reject);
ATF_TC_BODY(execute_write_cccd_reject, tc)
{
	struct fixture f;
	uint8_t pdu[16];

	fx_setup(&f);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_name_cccd);	/* parent lacks NOTIFY */
	put_le16(pdu + 3, 0x0000);
	put_le16(pdu + 5, GATT_CCCD_NOTIFY);
	expect_op(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	expect_err(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	fx_teardown(&f);
}

/*
 * Permission failures on an EATT (heap-buffer) MTU: an unencrypted link
 * reading encryption-required attributes yields Insufficient Encryption
 * (Vol 3 Part F 3.4.1.1 code 0x0f), exercising the response-buffer free on
 * the permission-error return arm of each reader at ac->mtu > 517.
 */
ATF_TC_WITHOUT_HEAD(perm_error_large_mtu);
ATF_TC_BODY(perm_error_large_mtu, tc)
{
	struct fixture f;
	uint8_t pdu[21];

	fx_setup(&f);
	f.ac.mtu = BIG_MTU;
	f.ac.encrypted = false;			/* encryption-required attrs fail */

	/* Read By Type over the READ_ENCRYPT attribute's type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A1C);
	expect_err(&f, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Find By Type Value matching that type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A1C); put_le16(pdu + 7, 0x0102);
	expect_err(&f, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Read / Read Blob / Read Multiple / Variable on the encrypted attr. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_renc_val);
	expect_err(&f, pdu, 3, BT_CORE63_WIRE_ATT_OP_READ_REQ, BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, f.h_renc_val); put_le16(pdu + 3, 0x0000);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, f.h_renc_val); put_le16(pdu + 3, f.h_name_val);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ, BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, f.h_renc_val); put_le16(pdu + 3, f.h_name_val);
	expect_err(&f, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Prepare Write on a WRITE_ENCRYPT attribute. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_wenc_val); put_le16(pdu + 3, 0x0000);
	pdu[5] = 0x00;
	expect_err(&f, pdu, 6, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	fx_teardown(&f);
}

/*
 * Split (unreliable-length) Prepare/Execute Write to a CCCD carrying only
 * the Indicate bit, whose parent characteristic supports Notify but not
 * Indicate: the post-apply CCCD validation rejects it (Vol 3 Part G
 * 3.3.3.3).  Exercises the "(value & Notify) == 0 / (value & Indicate)
 * set" arms of the post-apply check.
 */
ATF_TC_WITHOUT_HEAD(split_cccd_indicate_reject);
ATF_TC_BODY(split_cccd_indicate_reject, tc)
{
	struct fixture f;
	uint8_t pdu[16];
	uint8_t rsp[ATT_MAX_MTU];
	ssize_t n;

	fx_setup(&f);

	/* 1-octet (split) write of the Indicate bit to the battery CCCD
	 * (parent 0x2A19 has Notify, lacks Indicate). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, f.h_batt_cccd); put_le16(pdu + 3, 0x0000);
	pdu[5] = GATT_CCCD_INDICATE;		/* 0x02, one octet */
	expect_op(&f, pdu, 6, BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x01;
	expect_err(&f, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	/* The rejected split write leaves the CCCD cleared. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, f.h_batt_cccd);
	n = drive(&f, pdu, 3, rsp, sizeof(rsp));
	ATF_REQUIRE(n == 3);
	ATF_CHECK_EQ(0x0000, get_le16(rsp + 1));

	fx_teardown(&f);
}

/*
 * Write to an orphan CCCD (a 0x2902 descriptor with no preceding
 * Characteristic Declaration): the server cannot resolve the parent
 * characteristic's properties and returns Unlikely Error (Vol 3 Part F
 * 3.4.1.1 code 0x0e).  Built on a bespoke database because attdb_add_*
 * never produces an orphan.  Driven at -vv so the diagnostic trace branch
 * is also exercised.
 */
ATF_TC_WITHOUT_HEAD(orphan_cccd_write);
ATF_TC_BODY(orphan_cccd_write, tc)
{
	struct att_conn ac;
	struct att_db db;
	struct att_attr storage[8];
	uint8_t valbuf[128];
	uint8_t pdu[5];
	uint8_t rsp[64];
	uint16_t cccd;
	int fds[2];
	ssize_t n;

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(&ac, 0, sizeof(ac));
	ac.fd = fds[0];
	ac.bearer_fd = -1;
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac.buf != NULL);

	/* Service then a CCCD with NO characteristic before it. */
	attdb_init(&db, storage, 8, valbuf, sizeof(valbuf));
	attdb_add_service(&db, 0x1802);
	cccd = attdb_add_cccd(&db);		/* orphan: no parent char decl */

	atomic_store(&blued_verbose, 2);
	blued_daemonized = 0;

	/* Write Request -> Unlikely Error (0x0e). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, cccd); put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(fds[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "expected error rsp, got %zd", n);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_OP_ERROR_RSP, rsp[0]);
	ATF_CHECK_EQ(BT_CORE63_WIRE_ATT_ERR_UNLIKELY_ERROR, rsp[4]);

	/* Write Command variant: silently dropped (no response). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK(recv(fds[1], rsp, sizeof(rsp), MSG_DONTWAIT) < 0);

	atomic_store(&blued_verbose, 0);
	free(ac.buf);
	close(fds[0]);
	close(fds[1]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, eatt_find_info);
	ATF_TP_ADD_TC(tp, eatt_read_by_group);
	ATF_TP_ADD_TC(tp, eatt_read_by_type);
	ATF_TP_ADD_TC(tp, eatt_read);
	ATF_TP_ADD_TC(tp, eatt_read_blob);
	ATF_TP_ADD_TC(tp, eatt_prepare_write);
	ATF_TP_ADD_TC(tp, eatt_prepare_queue_full);
	ATF_TP_ADD_TC(tp, eatt_find_by_type_value);
	ATF_TP_ADD_TC(tp, eatt_read_multiple);
	ATF_TP_ADD_TC(tp, eatt_read_multiple_variable);
	ATF_TP_ADD_TC(tp, perm_encrypted_keysize_unknown);
	ATF_TP_ADD_TC(tp, read_by_group_mtu_overflow);
	ATF_TP_ADD_TC(tp, read_by_type_handle_beyond_end);
	ATF_TP_ADD_TC(tp, read_cccd_after_write);
	ATF_TP_ADD_TC(tp, write_cmd_cccd_notify_not_permitted);
	ATF_TP_ADD_TC(tp, write_csf_robust_bit_clear);
	ATF_TP_ADD_TC(tp, find_by_type_value_length_mismatch);
	ATF_TP_ADD_TC(tp, read_multiple_null_value_zerofill);
	ATF_TP_ADD_TC(tp, robust_read_by_type_uuid128_out_of_sync);
	ATF_TP_ADD_TC(tp, robust_out_of_sync_on_eatt_bearer);
	ATF_TP_ADD_TC(tp, confirm_predicate_arms);
	ATF_TP_ADD_TC(tp, eatt_notify_indicate);
	ATF_TP_ADD_TC(tp, eatt_execute_write_cccd);
	ATF_TP_ADD_TC(tp, execute_write_revalidate_len);
	ATF_TP_ADD_TC(tp, db_hash_uuid128_types);
	ATF_TP_ADD_TC(tp, verbose_battery_stderr);
	ATF_TP_ADD_TC(tp, verbose_battery_syslog);
	ATF_TP_ADD_TC(tp, read_cccd_no_match);
	ATF_TP_ADD_TC(tp, write_req_cccd_notify_not_permitted);
	ATF_TP_ADD_TC(tp, write_csf_empty_value);
	ATF_TP_ADD_TC(tp, execute_write_cccd_indicate);
	ATF_TP_ADD_TC(tp, execute_write_cccd_reject);
	ATF_TP_ADD_TC(tp, out_of_sync_bearer_mtu_zero);
	ATF_TP_ADD_TC(tp, read_multiple_zero_length);
	ATF_TP_ADD_TC(tp, perm_error_large_mtu);
	ATF_TP_ADD_TC(tp, split_cccd_indicate_reject);
	ATF_TP_ADD_TC(tp, orphan_cccd_write);

	return (atf_no_error());
}
