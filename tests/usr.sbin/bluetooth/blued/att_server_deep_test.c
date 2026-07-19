/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep branch-coverage tests for the ATT *server* subsystem:
 *   att_server.c, att_server_dispatch.c, att_server_notify.c,
 *   att_server_hash.c.
 *
 * This suite targets the residual UNIT-REACHABLE branches left uncovered
 * after att_server_edge_test.c: every attribute-database allocation-failure
 * path (attdb_alloc / val_alloc == NULL) in each add helper; the write-side
 * INSUFF_ENC_KEY_SIZE gates; att_opcode_name / att_extract_uuid corners;
 * the 128-bit Find Information branch; Find By Type Value permission /
 * group-end / clamp branches; Read By Group / Read By Type value-length
 * clamps and mixed-length breaks; Read (CCCD) tiny-MTU clamp; Read Multiple
 * NULL-value memset; Read Multiple Variable permission / clamp; Write Command
 * CCCD notify/indicate/orphan/table-full/owner-fd branches; Prepare/Execute
 * Write echo-clamp, execute-time re-validation, CCCD commit, value extension
 * and split-CCCD execute-time rejection; Robust Caching gating on an EATT
 * bearer; Signed Write signature-verified accept + replay; the
 * notification / indication / multiple-notification large-MTU and
 * send-failure branches; and the Database Hash 16-bit descriptor cases,
 * every 128-bit Bluetooth-Base-UUID hashable-type case, the vendor-UUID /
 * non-hashable skips, and the include-value-with-NULL-value skip.
 *
 * ORACLE: expected error codes / PDU bytes are taken from the Bluetooth
 * Core Specification (ATT = Vol 3 Part F; Robust Caching / DB hash = Vol 3
 * Part G), cited per group.  No expected value is captured from the
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

/* Suppress the default smp_verify_signature stub; we supply our own. */
#define TEST_LINKS_SMP
#include "test_common.h"
#include "spec_att_client_oracles.h"

/* Controllable Signed Write verification result. */
static bool g_sig_ok = false;
static int g_persist_error;

static int
persist_sign_counter(struct att_conn *ac __unused, uint32_t counter __unused)
{
	return (g_persist_error);
}

bool
smp_verify_signature(const uint8_t csrk[16] __unused,
    const uint8_t *msg __unused, size_t msg_len __unused,
    const uint8_t mac[8] __unused, uint32_t counter __unused)
{
	return (g_sig_ok);
}

#define DB_MAX	200
#define VAL_SZ	4096

/* ================================================================
 * Mock helpers
 * ================================================================ */
static void
srv_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = ATT_PDU_BUF_SIZE;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
srv_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

static ssize_t
srv_xchg(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t *rsp, size_t rsplen)
{

	att_server_handle(ac, db, pdu, len, -1, 0);
	return (recv(peer, rsp, rsplen, MSG_DONTWAIT));
}

static void
expect_err(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op, uint8_t exp_code)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_xchg(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "op 0x%02x: expected 5-byte error, got %zd",
	    pdu[0], n);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ_MSG(rsp[1], exp_op, "op 0x%02x wrong echoed opcode", pdu[0]);
	ATF_CHECK_EQ_MSG(rsp[4], exp_code,
	    "op 0x%02x expected code 0x%02x got 0x%02x", pdu[0], exp_code,
	    rsp[4]);
}

/* ================================================================
 * att_opcode_name — direct table walk (att_server.c 41-69)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_opcode_name);
ATF_TC_BODY(test_opcode_name, tc)
{
	struct { uint8_t op; const char *name; } tab[] = {
		{ BT_CORE63_WIRE_ATT_OP_MTU_REQ, "MTU_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_MTU_RSP, "MTU_RSP" },
		{ BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ, "FIND_INFO_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP, "FIND_INFO_RSP" },
		{ BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ, "FIND_BY_TYPE_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ, "READ_BY_TYPE_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP, "READ_BY_TYPE_RSP" },
		{ BT_CORE63_WIRE_ATT_OP_READ_REQ, "READ_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_RSP, "READ_RSP" },
		{ BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ, "READ_BLOB_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ, "READ_MULTI_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ, "READ_MULTI_VAR_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ, "READ_BY_GRP_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_WRITE_REQ, "WRITE_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_WRITE_CMD, "WRITE_CMD" },
		{ BT_CORE63_WIRE_ATT_OP_LEGACY_SIGNED_WRITE_CMD, "SIGNED_WRITE_CMD" },
		{ BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ, "PREP_WRITE_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ, "EXEC_WRITE_REQ" },
		{ BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY, "NOTIFY" },
		{ BT_CORE63_WIRE_ATT_OP_HANDLE_IND, "INDICATE" },
		{ BT_CORE63_WIRE_ATT_OP_HANDLE_CFM, "CONFIRM" },
		{ BT_CORE63_WIRE_ATT_OP_ERROR_RSP, "ERROR_RSP" },
		{ 0x00, "UNKNOWN" },
		{ 0xEE, "UNKNOWN" },
	};

	for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++)
		ATF_CHECK_STREQ_MSG(att_opcode_name(tab[i].op), tab[i].name,
		    "opcode 0x%02x", tab[i].op);
}

/* ================================================================
 * att_extract_uuid — corner branches (att_server.c 92-126)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_extract_uuid_corners);
ATF_TC_BODY(test_extract_uuid_corners, tc)
{
	uint16_t u16;
	uint8_t u128[16];
	uint8_t buf[16];

	/* Invalid length -> -1 (default case, att_server.c 123). */
	ATF_CHECK_EQ(att_extract_uuid(buf, 3, &u16, u128), -1);
	ATF_CHECK_EQ(att_extract_uuid(buf, 0, &u16, u128), -1);
	ATF_CHECK_EQ(att_extract_uuid(buf, 17, &u16, u128), -1);

	/*
	 * 16-byte UUID whose first 12 bytes match the Bluetooth Base UUID
	 * but with a non-zero byte 14 -> NOT a 16-bit alias, kept 128-bit
	 * (att_server.c 115-121, else arm).
	 */
	memcpy(buf, bt_base_uuid_le, 12);
	buf[12] = 0x34; buf[13] = 0x12; buf[14] = 0x01; buf[15] = 0x00;
	ATF_CHECK_EQ(att_extract_uuid(buf, 16, &u16, u128), 0);
	ATF_CHECK_EQ_MSG(u16, 0, "byte14!=0 must not collapse to 16-bit");
	ATF_CHECK(memcmp(u128, buf, 16) == 0);

	/* Same, non-zero byte 15. */
	memcpy(buf, bt_base_uuid_le, 12);
	buf[12] = 0x34; buf[13] = 0x12; buf[14] = 0x00; buf[15] = 0x02;
	ATF_CHECK_EQ(att_extract_uuid(buf, 16, &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0);

	/*
	 * A 4-octet (UUID32) Attribute Type is not a valid on-wire type
	 * field: Core Spec Vol 3 Part F §3.4.4.1 Table 3.15 constrains it to
	 * a 2- or 16-octet UUID, so att_extract_uuid must reject len 4 (the
	 * caller then returns Invalid PDU 0x04).
	 */
	buf[0] = 0x01; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x10;
	ATF_CHECK_EQ(att_extract_uuid(buf, 4, &u16, u128), -1);
	buf[0] = 0x04; buf[1] = 0xFF; buf[2] = 0x00; buf[3] = 0x00;
	ATF_CHECK_EQ_MSG(att_extract_uuid(buf, 4, &u16, u128), -1,
	    "4-octet UUID (even with zero high half) is an invalid type field");
}

/* ================================================================
 * attdb add-helper allocation-failure paths (att_server.c)
 *
 * Two failure modes per helper:
 *   attdb_alloc()==NULL  -> database slot table full (db->count>=db->max)
 *   val_alloc()==NULL    -> value backing store exhausted
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_attdb_slot_exhaustion);
ATF_TC_BODY(test_attdb_slot_exhaustion, tc)
{
	struct att_db db;
	struct att_attr attrs[4];
	uint8_t val[512];
	uint8_t u128[16] = { 0 };

	/* max=1: first alloc consumes the only slot. */
	attdb_init(&db, attrs, 1, val, sizeof(val));
	ATF_CHECK(attdb_add_service(&db, 0x1800) != 0);
	/* Now table is full: every alloc-first helper returns 0. */
	ATF_CHECK_EQ_MSG(attdb_add_service(&db, 0x1801), 0, "service slot full");
	ATF_CHECK_EQ(attdb_add_service128(&db, u128), 0);
	ATF_CHECK_EQ(attdb_add_characteristic(&db, 0x2A00, 0, ATT_PERM_READ,
	    "x", 1), 0);
	ATF_CHECK_EQ(attdb_add_characteristic128(&db, u128, 0, ATT_PERM_READ,
	    "x", 1), 0);
	ATF_CHECK_EQ(attdb_add_cccd(&db), 0);
	ATF_CHECK_EQ(attdb_add_include(&db, 1, 1, 2, 0x1801), 0);
	ATF_CHECK_EQ(attdb_add_descriptor(&db, 0x2901, ATT_PERM_READ, "x", 1),
	    0);

	/*
	 * max=3 with 2 slots used: a characteristic needs 2 slots (decl +
	 * value); with only 1 free the *second* attdb_alloc fails
	 * (att_server.c 242-246 / 287-291).
	 */
	attdb_init(&db, attrs, 3, val, sizeof(val));
	attdb_add_service(&db, 0x1800);		/* slot 0 */
	attdb_add_service(&db, 0x1801);		/* slot 1 */
	ATF_CHECK_EQ_MSG(attdb_add_characteristic(&db, 0x2A00, 0,
	    ATT_PERM_READ, "x", 1), 0, "char val_attr slot full");

	attdb_init(&db, attrs, 3, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_service(&db, 0x1801);
	ATF_CHECK_EQ(attdb_add_characteristic128(&db, u128, 0, ATT_PERM_READ,
	    "x", 1), 0);
}

ATF_TC_WITHOUT_HEAD(test_attdb_value_exhaustion);
ATF_TC_BODY(test_attdb_value_exhaustion, tc)
{
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t u128[16] = { 0 };

	/* val_size 0: the *first* val_alloc in each helper fails. */
	{
		uint8_t val[1];
		attdb_init(&db, attrs, DB_MAX, val, 0);
		ATF_CHECK_EQ_MSG(attdb_add_service(&db, 0x1800), 0,
		    "service value store empty");
		ATF_CHECK_EQ(attdb_add_service128(&db, u128), 0);
		ATF_CHECK_EQ(attdb_add_characteristic(&db, 0x2A00, 0,
		    ATT_PERM_READ, "x", 1), 0);
		ATF_CHECK_EQ(attdb_add_characteristic128(&db, u128, 0,
		    ATT_PERM_READ, "x", 1), 0);
		ATF_CHECK_EQ(attdb_add_cccd(&db), 0);
		/* include with uuid16!=0 needs 6 bytes; ==0 needs 4 bytes. */
		ATF_CHECK_EQ(attdb_add_include(&db, 1, 1, 2, 0x1801), 0);
		ATF_CHECK_EQ(attdb_add_include(&db, 1, 1, 2, 0), 0);
		ATF_CHECK_EQ(attdb_add_descriptor(&db, 0x2901, ATT_PERM_READ,
		    "x", 1), 0);
	}

	/*
	 * Characteristic: declaration value fits, but the characteristic
	 * *value* store is exhausted -> second val_alloc fails, count-=2
	 * (att_server.c 296-301 / 252-255).
	 */
	{
		uint8_t val[5];	/* exactly one 16-bit char declaration */
		attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
		ATF_CHECK_EQ_MSG(attdb_add_characteristic(&db, 0x2A00, 0,
		    ATT_PERM_READ, "value", 5), 0,
		    "char value store exhausted after decl");
	}
	{
		uint8_t val[19];	/* exactly one 128-bit char declaration */
		attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
		ATF_CHECK_EQ(attdb_add_characteristic128(&db, u128, 0,
		    ATT_PERM_READ, "value", 5), 0);
	}
	/* Include uuid16==0 branch, value store too small for 4 bytes. */
	{
		uint8_t val[2];
		attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
		ATF_CHECK_EQ(attdb_add_include(&db, 1, 1, 2, 0), 0);
	}
}

/* ================================================================
 * Write-side encryption-key-size gate (att_server.c 525-532)
 *   INSUFF_ENC_KEY_SIZE for WRITE_ENCRYPT and WRITE_AUTHEN attrs when the
 *   negotiated key is shorter than the required minimum.
 *   Core Spec Vol 3 Part F 3.4.1.1 (error 0x0C).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_write_enc_key_size);
ATF_TC_BODY(test_write_enc_key_size, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[8];
	uint16_t h_enc, h_auth;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	ac.encrypted = true;		/* link encrypted ... */
	ac.authenticated = true;
	ac.enc_key_size = 7;		/* ... but with a short key */
	ac.min_key_size = 16;

	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_enc = attdb_add_characteristic(&db, 0xFF01,
	    GATT_PROP_WRITE, ATT_PERM_WRITE_ENCRYPT, "\x00\x00", 2);
	h_auth = attdb_add_characteristic(&db, 0xFF02,
	    GATT_PROP_WRITE, ATT_PERM_WRITE_AUTHEN, "\x00\x00", 2);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 3, 0x1234);

	put_le16(pdu + 1, h_enc);
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENC_KEY_SIZE);

	put_le16(pdu + 1, h_auth);
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENC_KEY_SIZE);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Find Information — 128-bit UUID format branch and mixed-format break
 * (att_server.c 100-142).  Core Spec Vol 3 Part F 3.4.3.1/3.4.3.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_find_info_128bit);
ATF_TC_BODY(test_find_info_128bit, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t u128[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* 128-bit characteristic: its value attr has uuid16==0. */
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic128(&db, u128, GATT_PROP_READ,
	    ATT_PERM_READ, "\x00", 1);

	/* Find Info over the value attr (handle 0x0003) -> 128-bit format. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0003);
	put_le16(pdu + 3, 0x0003);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_FIND_INFO_RSP);
	ATF_CHECK_EQ_MSG(rsp[1], 0x02, "format must be 0x02 (128-bit)");
	ATF_CHECK_EQ(get_le16(rsp + 2), 0x0003);
	ATF_CHECK(memcmp(rsp + 4, u128, 16) == 0);

	/*
	 * Mixed formats in one range must stop at the format change
	 * (att_server.c 113 / 122).  Range covering the 16-bit char decl
	 * (0x0002) then the 128-bit value (0x0003): first entry sets format
	 * 1, the 128-bit attr then breaks -> only one entry.
	 */
	put_le16(pdu + 1, 0x0002);
	put_le16(pdu + 3, 0x0003);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 0x01, "first entry is 16-bit -> format 1");
	ATF_CHECK_EQ_MSG(n, 2 + 4, "128-bit attr must break the 16-bit list");

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_find_info_128bit_first);
ATF_TC_BODY(test_find_info_128bit_first, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t ua[16] = { 0xAA,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/*
	 * Craft two attributes directly: a 128-bit one first (handle 1),
	 * then a 16-bit one (handle 2).  A Find Info over both starts the
	 * list in 128-bit format, then the 16-bit attr triggers the
	 * "else if (format != 1) break" arm (att_server.c 113).
	 */
	db.count = 2;
	db.next_handle = 3;
	attrs[0].handle = 1; attrs[0].uuid16 = 0; memcpy(attrs[0].uuid128, ua, 16);
	attrs[0].value = NULL; attrs[0].value_len = 0; attrs[0].is_char_value = false;
	attrs[0].perms = ATT_PERM_READ; attrs[0].owner_fd = -1;
	attrs[1].handle = 2; attrs[1].uuid16 = 0x2902; attrs[1].value = NULL;
	attrs[1].value_len = 0; attrs[1].is_char_value = false;
	attrs[1].perms = ATT_PERM_READ; attrs[1].owner_fd = -1;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0002);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 0x02, "first entry is 128-bit -> format 2");
	ATF_CHECK_EQ_MSG(n, 2 + 18, "16-bit attr must break the 128-bit list");

	srv_cleanup(&ac, peer);
}

/* Fill the response with many 128-bit entries to force the pos+18 break. */
ATF_TC_WITHOUT_HEAD(test_find_info_128bit_full);
ATF_TC_BODY(test_find_info_128bit_full, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* small: fits only one 128-bit entry */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	db.count = 3;
	db.next_handle = 4;
	for (int i = 0; i < 3; i++) {
		attrs[i].handle = i + 1;
		attrs[i].uuid16 = 0;
		memset(attrs[i].uuid128, 0x20 + i, 16);
		attrs[i].value = NULL;
		attrs[i].value_len = 0;
		attrs[i].is_char_value = false;
		attrs[i].perms = ATT_PERM_READ;
		attrs[i].owner_fd = -1;
	}
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0003);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	/* mtu 23 -> 2 + 18 = 20 <= 23 for one entry; second (38) breaks. */
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(n, 2 + 18, "only one 128-bit entry fits in MTU 23");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Find By Type Value — permission / group-end / non-service / clamp
 * (att_server.c 945-1045).  Core Spec Vol 3 Part F 3.4.3.3/3.4.3.4.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_fbtv_perm_and_range);
ATF_TC_BODY(test_fbtv_perm_and_range, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* Two primary services; the second is encryption-gated by hand. */
	attdb_add_service(&db, 0x1800);		/* handle 1, value 00 18 */
	attdb_add_service(&db, 0x1801);		/* handle 2, value 01 18 */
	attrs[1].perms = ATT_PERM_READ_ENCRYPT;	/* gate handle 2 */
	ac.encrypted = false;

	/*
	 * Find By Type Value for Primary Service (0x2800) == 0x1801.
	 * The only matching attr (handle 2) is encryption-gated and is the
	 * first candidate, so the server returns INSUFF_ENCRYPTION
	 * (att_server.c 993-998).  Range starts at handle 2 so handle 1 is
	 * skipped by the range test first (att_server.c 985-986).
	 */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0002);	/* start after handle 1 */
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1801);
	expect_err(&ac, &db, peer, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_fbtv_nonservice_and_endgroup);
ATF_TC_BODY(test_fbtv_nonservice_and_endgroup, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));

	/* Primary service with an explicit end_group_handle set. */
	attdb_add_service(&db, 0x1800);		/* handle 1 */
	attrs[0].end_group_handle = 0x0005;	/* att_server.c 1009-1010 */
	/* A non-service attribute matching a custom type + value. */
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x64\x00", 2); /* h2 */

	/* Match the service by value -> grp_end from end_group_handle. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "one 4-byte pair expected, got %zd", n);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_RSP);
	ATF_CHECK_EQ(get_le16(rsp + 1), 0x0001);
	ATF_CHECK_EQ_MSG(get_le16(rsp + 3), 0x0005, "grp_end from end_group");

	/* Match the non-service attr by type+value -> grp_end == handle. */
	put_le16(pdu + 5, 0x2A19);
	put_le16(pdu + 7, 0x0064);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "non-service match expected, got %zd", n);
	ATF_CHECK_EQ_MSG(get_le16(rsp + 1), 0x0002, "found handle");
	ATF_CHECK_EQ_MSG(get_le16(rsp + 3), 0x0002, "grp_end == own handle");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Read By Group Type — perm break, end_group, value clamps, mixed len
 * (att_server.c 144-264).  Core Spec Vol 3 Part F 3.4.4.9/3.4.4.10.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_rbgt_perm_first);
ATF_TC_BODY(test_rbgt_perm_first, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[8];

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);		/* handle 1 */
	attrs[0].perms = ATT_PERM_READ_ENCRYPT;	/* gate it */
	ac.encrypted = false;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	/* First matching group is gated -> INSUFF_ENCRYPTION (209-213). */
	expect_err(&ac, &db, peer, pdu, 7, BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_rbgt_value_clamp_and_mixed);
ATF_TC_BODY(test_rbgt_value_clamp_and_mixed, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t big[300];
	uint8_t pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);

	/*
	 * Value length clamp to pos_limit-6 (att_server.c 235-236): a
	 * synthetic primary service value longer than the valid minimum MTU
	 * can carry.
	 */
	ac.mtu = ATT_DEFAULT_MTU;	/* pos_limit-6 = 17 */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	memset(big, 0xAB, sizeof(big));
	db.count = 1;
	db.next_handle = 2;
	attrs[0].handle = 1; attrs[0].uuid16 = GATT_UUID_PRIMARY_SERVICE;
	attrs[0].value = big; attrs[0].value_len = 32;
	attrs[0].end_group_handle = 0x0002; attrs[0].perms = ATT_PERM_READ;
	attrs[0].is_char_value = false; attrs[0].owner_fd = -1;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 4 + 17,
	    "entry length clamps value to ATT_DEFAULT_MTU-6");

	/*
	 * Value length clamp to 251 (att_server.c 237-238): a service attr
	 * whose value_len exceeds 251 (constructed by hand).
	 */
	srv_cleanup(&ac, peer);
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	memset(big, 0xAB, sizeof(big));
	db.count = 1;
	db.next_handle = 2;
	attrs[0].handle = 1; attrs[0].uuid16 = GATT_UUID_PRIMARY_SERVICE;
	attrs[0].value = big; attrs[0].value_len = 300;
	attrs[0].end_group_handle = 0x0001; attrs[0].perms = ATT_PERM_READ;
	attrs[0].is_char_value = false; attrs[0].owner_fd = -1;
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 4 + 251, "value clamped to 251 bytes");

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_rbgt_mixed_len_break);
ATF_TC_BODY(test_rbgt_mixed_len_break, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t u128[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* 16-bit primary service then a 128-bit primary service. */
	attdb_add_service(&db, 0x1800);		/* value 2 bytes */
	attdb_add_service128(&db, u128);	/* value 16 bytes */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	/* First entry sets entry_len = 4+2; the 16-byte one breaks (242-243). */
	ATF_CHECK_EQ_MSG(rsp[1], 4 + 2, "entry_len fixed by first group");
	ATF_CHECK_EQ_MSG(n, 2 + (4 + 2), "second differing-length group breaks");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Read By Type — perm break, value clamps, mixed len, fill break
 * (att_server.c 266-367).  Core Spec Vol 3 Part F 3.4.4.1/3.4.4.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_rbt_perm_break_and_mixed);
ATF_TC_BODY(test_rbt_perm_break_and_mixed, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* Three descriptors of the same type 0x2A19, second is gated. */
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x01", 1); /* h1 */
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ_ENCRYPT, "\x02", 1); /* h2 */
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x03\x03", 2); /* h3 */
	ac.encrypted = false;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A19);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	/*
	 * First entry (handle 1) succeeds; handle 2 is gated so the loop
	 * breaks with entry_len already set (att_server.c 327-334).
	 */
	ATF_CHECK_EQ_MSG(rsp[1], 2 + 1, "entry_len = 2 + 1-byte value");
	ATF_CHECK_EQ_MSG(n, 2 + (2 + 1), "gated 2nd attr breaks the response");

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_rbt_mixed_len_break);
ATF_TC_BODY(test_rbt_mixed_len_break, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x01", 1);	/* len 1 */
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x02\x02", 2);	/* len 2 */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A19);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 2 + 1, "entry_len fixed at 2+1");
	ATF_CHECK_EQ_MSG(n, 2 + (2 + 1), "differing-length attr breaks (347)");

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_rbt_value_clamp_253);
ATF_TC_BODY(test_rbt_value_clamp_253, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t big[300], pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	memset(big, 0xCD, sizeof(big));
	db.count = 1;
	db.next_handle = 2;
	attrs[0].handle = 1; attrs[0].uuid16 = 0x2A19; attrs[0].value = big;
	attrs[0].value_len = 300; attrs[0].perms = ATT_PERM_READ;
	attrs[0].is_char_value = false; attrs[0].owner_fd = -1;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A19);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(rsp[1], 2 + 253, "value clamped to 253 (att_server.c 342)");

	srv_cleanup(&ac, peer);
}

/* Fill the Read By Type response to force the pos+entry_len break (350). */
ATF_TC_WITHOUT_HEAD(test_rbt_fill_break);
ATF_TC_BODY(test_rbt_fill_break, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[8], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* 23: fits (23-2)/(2+16)=1 big entry */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ,
	    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ,
	    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2A19);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(n, 2 + (2 + 16), "second entry does not fit MTU 23");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Read (CCCD) tiny-MTU clamp (att_server.c 408-420).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_read_cccd_min_mtu);
ATF_TC_BODY(test_read_cccd_min_mtu, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x00", 1);
	h_cccd = attdb_add_cccd(&db);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, h_cccd);
	n = srv_xchg(&ac, &db, peer, pdu, 3, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_READ_RSP);
	ATF_CHECK_EQ_MSG(n, 3,
	    "minimum ATT MTU carries the full 2-byte CCCD value");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Read Multiple — NULL-value memset branch (att_server.c 1097-1100).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_read_multiple_null_value);
ATF_TC_BODY(test_read_multiple_null_value, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x11\x22", 2); /* h1 */
	attdb_add_descriptor(&db, 0x2A1A, ATT_PERM_READ, "\x33", 1);	/* h2 */
	/* Force handle 2 to have a length but a NULL backing pointer. */
	attrs[1].value = NULL;
	attrs[1].value_len = 3;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0002);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_RSP);
	/* 2 bytes (h1) + 3 zero bytes (h2 memset). */
	ATF_CHECK_EQ_MSG(n, 1 + 2 + 3, "NULL value contributes zero bytes");
	ATF_CHECK(rsp[3] == 0 && rsp[4] == 0 && rsp[5] == 0);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Read Multiple Variable — perm error + fill break
 * (att_server.c 1112-1175).  Core Spec Vol 3 Part F 3.4.4.8.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_read_multiple_var_perm);
ATF_TC_BODY(test_read_multiple_var_perm, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5];

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x11", 1);	/* h1 */
	attdb_add_descriptor(&db, 0x2A1A, ATT_PERM_READ_ENCRYPT, "\x22", 1); /* h2 */
	ac.encrypted = false;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0002);
	/* Second handle gated -> INSUFF_ENCRYPTION (att_server.c 1147-1152). */
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_ENCRYPTION);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_read_multiple_var_fill);
ATF_TC_BODY(test_read_multiple_var_fill, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t big[300], pdu[7], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	memset(big, 0x5A, sizeof(big));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, big, 40);	/* h1 */
	attdb_add_descriptor(&db, 0x2A1A, ATT_PERM_READ, big, 8);	/* h2 */
	attrs[0].value = big; attrs[0].value_len = 40;
	attrs[1].value = big; attrs[1].value_len = 8;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0002);
	put_le16(pdu + 5, 0x0002);	/* 3 handles -> len 7 */
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_RSP);
	/* First value truncates to fill MTU; subsequent break at pos>=limit. */
	ATF_CHECK_EQ_MSG(n, ATT_DEFAULT_MTU,
	    "response bounded by ATT_DEFAULT_MTU, got %zd", n);
	ATF_CHECK_EQ_MSG(get_le16(rsp + 1), 40,
	    "Length field carries the full attribute value length");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Write Command CCCD branches (att_server.c 498-631, with_response=false).
 * ================================================================ */
static uint16_t
build_notify_char(struct att_db *db)
{

	/* Service + NOTIFY-capable characteristic + CCCD. */
	attdb_add_service(db, 0x1800);
	attdb_add_characteristic(db, 0xFF01, GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x00", 1);
	return (attdb_add_cccd(db));
}

ATF_TC_WITHOUT_HEAD(test_write_cmd_cccd_branches);
ATF_TC_BODY(test_write_cmd_cccd_branches, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5], rsp[8];
	ssize_t n;
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	h_cccd = build_notify_char(&db);

	/* Write Command too short (len<3) -> silently accepted, no reply. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	att_server_handle(&ac, &db, pdu, 2, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n < 0, "short Write Command must be silent");

	/* Write Command enabling INDICATE on a NOTIFY-only char: silent. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, GATT_CCCD_INDICATE);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n < 0, "rejected Write Command must be silent (576)");

	/* Write Command enabling NOTIFY (allowed) then again -> updates entry. */
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_EQ_MSG(ac.cccd_count, 1, "first CCCD write adds an entry");
	att_server_handle(&ac, &db, pdu, 5, -1, 0);	/* update existing (589) */
	ATF_CHECK_EQ_MSG(ac.cccd_count, 1, "second write updates in place");
	(void)recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_write_cccd_orphan_cmd);
ATF_TC_BODY(test_write_cccd_orphan_cmd, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5], rsp[8];
	ssize_t n;
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* CCCD with no preceding characteristic declaration -> orphan. */
	attdb_add_service(&db, 0x1800);
	h_cccd = attdb_add_cccd(&db);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);	/* orphan cmd (584) */
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n < 0, "orphan CCCD Write Command must be silent");

	/* As a Write *Request* the same orphan yields UNLIKELY_ERROR (583). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_UNLIKELY_ERROR);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_write_cccd_table_full);
ATF_TC_BODY(test_write_cccd_table_full, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	h_cccd = build_notify_char(&db);

	/* Pre-fill the per-connection CCCD table with unrelated handles. */
	ac.cccd_count = ATT_MAX_CCCDS_PER_CONN;
	for (int i = 0; i < ATT_MAX_CCCDS_PER_CONN; i++) {
		ac.cccds[i].handle = 0x8000 + i;	/* != h_cccd */
		ac.cccds[i].value = 0;
	}

	/* A new distinct CCCD handle cannot be stored -> INSUFF_RESOURCES. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INSUFF_RESOURCES);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_write_owner_fd_notify);
ATF_TC_BODY(test_write_owner_fd_notify, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[6], rsp[8];
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00", 1);
	/* Registered by a ctl client -> owner_fd >= 0 triggers notify (612). */
	attrs[db.count - 1].owner_fd = 0;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, h_val);
	pdu[3] = 0x42;
	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	ATF_REQUIRE(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) == 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_WRITE_RSP);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Prepare Write echo-clamp (att_server.c 708-709).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_prepare_echo_clamp);
ATF_TC_BODY(test_prepare_echo_clamp, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[64], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;	/* 23 -> echo clamps at 5 + (23-5) */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, NULL, 0);
	attrs[db.count - 1].value = val + 400;	/* give it writable storage */
	attrs[db.count - 1].value_maxlen = 64;

	/* Prepare 30 bytes at offset 0: response echo clamps to MTU. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_val);
	put_le16(pdu + 3, 0);
	memset(pdu + 5, 0x77, 30);
	n = srv_xchg(&ac, &db, peer, pdu, 35, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 5);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_RSP);
	ATF_CHECK_EQ_MSG(n, ATT_DEFAULT_MTU, "echoed value clamped to MTU");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Execute Write — execute-time re-validation of a queued entry
 * (att_server.c 744-780): handle invalidated and permission revoked.
 * Core Spec Vol 3 Part F 3.4.6.3.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_execute_revalidate_handle);
ATF_TC_BODY(test_execute_revalidate_handle, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00\x00", 2);

	/* Queue a valid prepare write. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_val);
	put_le16(pdu + 3, 0);
	pdu[5] = 0xAA;
	(void)srv_xchg(&ac, &db, peer, pdu, 6, val + 3000, 32);

	/* Invalidate the handle by dropping the last attr from the table. */
	db.count--;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;	/* commit */
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_HANDLE);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_execute_revalidate_perm);
ATF_TC_BODY(test_execute_revalidate_perm, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00\x00", 2);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_val);
	put_le16(pdu + 3, 0);
	pdu[5] = 0xAA;
	(void)srv_xchg(&ac, &db, peer, pdu, 6, val + 3000, 32);

	/* Revoke write permission after queueing. */
	attrs[db.count - 1].perms = ATT_PERM_READ;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_WRITE_NOT_PERMITTED);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Execute Write — CCCD commit validation and value-length extension.
 * ================================================================ */
static uint16_t
build_notify_char_named(struct att_db *db, uint8_t props, uint16_t *h_char)
{
	uint16_t hc;

	attdb_add_service(db, 0x1800);
	hc = attdb_add_characteristic(db, 0xFF01, props, ATT_PERM_READ,
	    "\x00", 1);
	if (h_char != NULL)
		*h_char = hc;
	return (attdb_add_cccd(db));
}

ATF_TC_WITHOUT_HEAD(test_execute_cccd_notify_reject);
ATF_TC_BODY(test_execute_cccd_notify_reject, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* Characteristic supports neither NOTIFY nor INDICATE. */
	h_cccd = build_notify_char_named(&db, GATT_PROP_READ, NULL);

	/* Prepare a CCCD write enabling NOTIFY, then commit. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	put_le16(pdu + 5, GATT_CCCD_NOTIFY);
	(void)srv_xchg(&ac, &db, peer, pdu, 7, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	/* att_server.c 803-812 */
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_execute_cccd_indicate_reject);
ATF_TC_BODY(test_execute_cccd_indicate_reject, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	h_cccd = build_notify_char_named(&db, GATT_PROP_NOTIFY, NULL);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	put_le16(pdu + 5, GATT_CCCD_INDICATE);
	(void)srv_xchg(&ac, &db, peer, pdu, 7, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	/* att_server.c 813-822 */
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_execute_cccd_orphan_reject);
ATF_TC_BODY(test_execute_cccd_orphan_reject, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_cccd = attdb_add_cccd(&db);	/* no parent characteristic */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	put_le16(pdu + 5, GATT_CCCD_NOTIFY);
	(void)srv_xchg(&ac, &db, peer, pdu, 7, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	/* att_server.c 823-830 */
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_UNLIKELY_ERROR);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_execute_cccd_commit_update);
ATF_TC_BODY(test_execute_cccd_commit_update, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[8];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	h_cccd = build_notify_char_named(&db, GATT_PROP_NOTIFY, NULL);

	/* Seed an existing CCCD entry so the commit apply *updates* it (847). */
	ac.cccd_count = 1;
	ac.cccds[0].handle = h_cccd;
	ac.cccds[0].value = 0;

	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	put_le16(pdu + 5, GATT_CCCD_NOTIFY);
	(void)srv_xchg(&ac, &db, peer, pdu, 7, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	ATF_REQUIRE(srv_xchg(&ac, &db, peer, pdu, 2, rsp, sizeof(rsp)) == 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP);
	ATF_CHECK_EQ_MSG(ac.cccd_count, 1, "existing CCCD entry updated in place");
	ATF_CHECK_EQ(ac.cccds[0].value, GATT_CCCD_NOTIFY);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_execute_value_extend);
ATF_TC_BODY(test_execute_value_extend, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[32], rsp[8];
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00\x00", 2);	/* value_len 2 */
	attrs[db.count - 1].value_maxlen = 16;

	/* Prepare 8 bytes at offset 0 -> commit extends value_len to 8 (868). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_val);
	put_le16(pdu + 3, 0);
	memset(pdu + 5, 0x5A, 8);
	(void)srv_xchg(&ac, &db, peer, pdu, 13, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	ATF_REQUIRE(srv_xchg(&ac, &db, peer, pdu, 2, rsp, sizeof(rsp)) == 1);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value_len, 8,
	    "committed prepare extends value_len");

	srv_cleanup(&ac, peer);
}

/* Split CCCD prepare that composes unsupported INDICATE -> Execute rejects. */
ATF_TC_WITHOUT_HEAD(test_execute_cccd_split_indicate);
ATF_TC_BODY(test_execute_cccd_split_indicate, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* NOTIFY-only characteristic: INDICATE is not permitted. */
	h_cccd = build_notify_char_named(&db, GATT_PROP_NOTIFY, NULL);

	/*
	 * Partial CCCD prepare: offset 0, length 1, value 0x02 (INDICATE low
	 * byte).  Execute Write composes the full two-octet CCCD value from
	 * queued fragments and rejects unsupported INDICATE atomically.
	 */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	pdu[5] = 0x02;
	(void)srv_xchg(&ac, &db, peer, pdu, 6, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	expect_err(&ac, &db, peer, pdu, 2, BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_VALUE_NOT_ALLOWED);
	ATF_CHECK_EQ_MSG(ac.cccd_count, 0,
	    "illegal split INDICATE must not create a subscription");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Robust Caching gating dispatched on an EATT bearer (att_server.c 1270-1278).
 * Core Spec Vol 3 Part G 2.5.2.1: change-unaware client gets
 * DATABASE_OUT_OF_SYNC.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_robust_block_on_bearer);
ATF_TC_BODY(test_robust_block_on_bearer, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	int bfd[2];
	uint8_t pdu[3], rsp[8];
	ssize_t n;

	srv_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bfd) == 0);
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.robust_caching = true;
	ac.change_aware = false;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_READ, ATT_PERM_READ,
	    "\x00", 1);

	/* Read of a non-hash handle is not allowed for a change-unaware
	 * client; dispatch on the EATT bearer so bearer_fd >= 0. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0x0003);
	att_server_handle(&ac, &db, pdu, 3, bfd[0], 100);
	n = recv(bfd[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "error must be sent on the bearer fd, got %zd", n);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[4], BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC);

	close(bfd[0]);
	close(bfd[1]);
	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Signed Write with a verified signature: accept + replay
 * (att_server.c 1321-1358).  Core Spec Vol 3 Part F 3.4.5.4, Part H 2.4.5.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_signed_write_verified);
ATF_TC_BODY(test_signed_write_verified, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[32];
	uint16_t h_val;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.has_peer_csrk = true;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00", 1);

	/*
	 * Signed Write PDU = opcode | handle | value(1) | signature(12).
	 * The trailing 12 bytes are counter(4) + MAC(8).  msg_len = len-12.
	 * The signature body carries counter 10.
	 */
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = BT_CORE63_WIRE_ATT_OP_LEGACY_SIGNED_WRITE_CMD;
	put_le16(pdu + 1, h_val);
	pdu[3] = 0x99;			/* new value */
	put_le32(pdu + 4, 10);		/* sign counter within signature */

	g_sig_ok = true;		/* signature verifies */

	/* Accept: counter 10 > none -> value written, counter recorded. */
	att_server_handle(&ac, &db, pdu, 16, -1, 0);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value[0], 0x99,
	    "verified Signed Write applies the value");
	ATF_CHECK(ac.has_peer_sign_counter);
	ATF_CHECK_EQ(ac.peer_sign_counter, 10);

	/* Replay: a counter <= last is dropped without applying (1337-1346). */
	pdu[3] = 0x11;
	put_le32(pdu + 4, 5);		/* stale counter */
	att_server_handle(&ac, &db, pdu, 16, -1, 0);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value[0], 0x99,
	    "replayed Signed Write must not apply");

	/*
	 * Equal-counter replay boundary: a SignCounter *equal* to the last
	 * accepted value is a replay and MUST be discarded (Core Spec Vol 3
	 * Part C §10.4.2 / Part H §2.4.5 — the counter must be strictly
	 * greater than the last received).  Guards the `<=` -> `<` weakening.
	 */
	pdu[3] = 0x22;
	put_le32(pdu + 4, 10);		/* same counter as the accepted one */
	att_server_handle(&ac, &db, pdu, 16, -1, 0);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value[0], 0x99,
	    "a Signed Write replaying the same SignCounter must not apply");
	ATF_CHECK_EQ_MSG(ac.peer_sign_counter, 10,
	    "an equal-counter replay must not advance the stored counter");

	/* Second accept: counter 20 > last 10 -> applies (1338 false arm). */
	pdu[3] = 0x77;
	put_le32(pdu + 4, 20);
	att_server_handle(&ac, &db, pdu, 16, -1, 0);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value[0], 0x77,
	    "fresh higher-counter Signed Write applies");
	ATF_CHECK_EQ(ac.peer_sign_counter, 20);

	/* Persistence failure must reject the command before its side effect. */
	ac.persist_sign_counter = persist_sign_counter;
	g_persist_error = -1;
	pdu[3] = 0x88;
	put_le32(pdu + 4, 30);
	att_server_handle(&ac, &db, pdu, 16, -1, 0);
	ATF_CHECK_EQ_MSG(attrs[db.count - 1].value[0], 0x77,
	    "Signed Write must not apply when its replay floor cannot persist");
	ATF_CHECK_EQ_MSG(ac.peer_sign_counter, 20,
	    "failed persistence must not advance the in-session counter");
	g_persist_error = 0;

	g_sig_ok = false;
	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Notification / indication large-MTU (malloc) and length-clamp paths
 * (att_server_notify.c).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_notify_large_mtu_clamp);
ATF_TC_BODY(test_notify_large_mtu_clamp, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t big[900], rsp[1024];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = 800;	/* > ATT_PDU_BUF_SIZE -> malloc path + len clamp */
	memset(big, 0x5A, sizeof(big));

	/* len 900 > maxlen-3 (797) -> clamps; pdulen == mtu. */
	ATF_CHECK_EQ(att_send_notification(&ac, 0x0010, big, sizeof(big)), 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n >= 3);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ_MSG(n, 800, "notification clamped to MTU 800");

	/* Indication, same clamp. */
	ATF_CHECK_EQ(att_send_indication(&ac, 0x0010, big, sizeof(big)), 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n >= 3);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_HANDLE_IND);
	ATF_CHECK_EQ_MSG(n, 800, "indication clamped to MTU 800");
	ATF_CHECK(ac.ind_pending);

	/* Multiple Handle Value Notification, malloc path. */
	{
		uint16_t handles[1] = { 0x0010 };
		const uint8_t *values[1] = { big };
		uint16_t lengths[1] = { 100 };
		ATF_CHECK_EQ(att_send_multiple_handle_value_ntf(&ac, handles,
		    values, lengths, 1), 0);
		n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
		ATF_REQUIRE(n >= 5);
		ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);
	}

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_notify_send_failure);
ATF_TC_BODY(test_notify_send_failure, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t v[4] = { 1, 2, 3, 4 };
	uint16_t handles[1] = { 0x0010 };
	const uint8_t *values[1] = { v };
	uint16_t lengths[1] = { 4 };

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	close(peer);	/* peer gone -> every send fails */

	ATF_CHECK_EQ_MSG(att_send_notification(&ac, 0x0010, v, 4), -1,
	    "notification send failure -> -1 (att_server_notify.c 57)");
	ATF_CHECK_EQ_MSG(att_send_indication(&ac, 0x0010, v, 4), -1,
	    "indication send failure -> -1 (90) and ind_pending stays clear");
	ATF_CHECK_MSG(!ac.ind_pending, "failed indication must not set pending");
	ATF_CHECK_EQ_MSG(att_send_multiple_handle_value_ntf(&ac, handles,
	    values, lengths, 1), -1, "multi-ntf send failure -> -1 (143)");

	free(ac.buf);
	ac.buf = NULL;
	close(ac.fd);
}

/* ================================================================
 * Database Hash — 16-bit descriptor cases and 128-bit hashable types
 * (att_server_hash.c).  Core Spec Vol 3 Part G 7.3.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hash_16bit_descriptors);
ATF_TC_BODY(test_hash_16bit_descriptors, tc)
{
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t hash_a[16], hash_b[16];

	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_READ, ATT_PERM_READ,
	    "\x00", 1);
	/* The four value-excluded 16-bit descriptor types beyond CCCD. */
	attdb_add_descriptor(&db, 0x2901, ATT_PERM_READ, "desc", 4);	/* User Desc */
	attdb_add_descriptor(&db, 0x2903, ATT_PERM_READ, "\x00\x00", 2);/* SCCD */
	attdb_add_descriptor(&db, 0x2904, ATT_PERM_READ, "\x01\x00\x00\x00\x00\x00\x00", 7); /* Pres Fmt */
	attdb_add_descriptor(&db, 0x2905, ATT_PERM_READ, "\x03\x00\x04\x00", 4); /* Agg Fmt */

	attdb_compute_db_hash(&db, hash_a);

	/*
	 * Because 0x2901/0x2903/0x2904/0x2905 are hashed by handle+type only
	 * (value excluded), changing their *values* must not change the hash.
	 */
	memcpy(attdb_find_by_handle(&db, 0x0005)->value, "XXXX", 4);
	attdb_compute_db_hash(&db, hash_b);
	ATF_CHECK_MSG(memcmp(hash_a, hash_b, 16) == 0,
	    "descriptor values must be excluded from the DB hash");
}

ATF_TC_WITHOUT_HEAD(test_hash_128bit_types);
ATF_TC_BODY(test_hash_128bit_types, tc)
{
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t hash[16];
	static const uint16_t types[] = {
		0x2800, 0x2801, 0x2802, 0x2803, 0x2900,	/* value included */
		0x2901, 0x2902, 0x2903, 0x2904, 0x2905,	/* value excluded */
		0x2A00,					/* non-hashable base */
	};
	int n = (int)(sizeof(types) / sizeof(types[0]));
	int i;

	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	db.count = n + 3;
	db.next_handle = n + 4;

	/* Each hashable type encoded as its 128-bit Bluetooth Base UUID. */
	for (i = 0; i < n; i++) {
		struct att_attr *a = &attrs[i];
		memset(a, 0, sizeof(*a));
		a->handle = i + 1;
		a->uuid16 = 0;
		memcpy(a->uuid128, bt_base_uuid_le, 12);
		put_le16(a->uuid128 + 12, types[i]);
		a->uuid128[14] = 0;
		a->uuid128[15] = 0;
		a->value = val + i * 4;
		memset(a->value, i, 4);
		a->value_len = 4;
		a->is_char_value = false;
		a->owner_fd = -1;
	}
	/* A genuine vendor 128-bit UUID (not a Base UUID) -> skipped (119). */
	{
		struct att_attr *a = &attrs[n];
		memset(a, 0, sizeof(*a));
		a->handle = n + 1;
		a->uuid16 = 0;
		memset(a->uuid128, 0xAB, 16);	/* fails Base-UUID compare */
		a->value = NULL;
		a->is_char_value = false;
		a->owner_fd = -1;
	}
	/* Base-UUID-prefixed but with a non-zero byte 14 -> skipped (120:8). */
	{
		struct att_attr *a = &attrs[n + 1];
		memset(a, 0, sizeof(*a));
		a->handle = n + 2;
		a->uuid16 = 0;
		memcpy(a->uuid128, bt_base_uuid_le, 12);
		put_le16(a->uuid128 + 12, 0x2800);
		a->uuid128[14] = 0x07;		/* not a valid Base UUID */
		a->value = NULL;
		a->is_char_value = false;
		a->owner_fd = -1;
	}
	/* Base-UUID-prefixed, byte 14 zero but non-zero byte 15 -> skipped
	 * (att_server_hash.c 120:34). */
	{
		struct att_attr *a = &attrs[n + 2];
		memset(a, 0, sizeof(*a));
		a->handle = n + 3;
		a->uuid16 = 0;
		memcpy(a->uuid128, bt_base_uuid_le, 12);
		put_le16(a->uuid128 + 12, 0x2800);
		a->uuid128[14] = 0x00;
		a->uuid128[15] = 0x02;
		a->value = NULL;
		a->is_char_value = false;
		a->owner_fd = -1;
	}

	/* Must complete without crashing and produce a non-degenerate hash. */
	attdb_compute_db_hash(&db, hash);
	{
		uint8_t zero[16] = { 0 };
		ATF_CHECK_MSG(memcmp(hash, zero, 16) != 0,
		    "hash over 128-bit hashable types must be non-zero");
	}
}

/* Include-value type whose value pointer is NULL -> value update skipped
 * (att_server_hash.c 144). */
ATF_TC_WITHOUT_HEAD(test_hash_include_null_value);
ATF_TC_BODY(test_hash_include_null_value, tc)
{
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t hash[16];

	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	db.count = 1;
	db.next_handle = 2;
	memset(&attrs[0], 0, sizeof(attrs[0]));
	attrs[0].handle = 1;
	attrs[0].uuid16 = 0x2800;	/* value-included type ... */
	attrs[0].value = NULL;		/* ... but NULL value pointer */
	attrs[0].value_len = 0;
	attrs[0].is_char_value = false;
	attrs[0].owner_fd = -1;

	attdb_compute_db_hash(&db, hash);	/* must not dereference NULL */
	ATF_CHECK(true);			/* reached without crashing */
}

/* ================================================================
 * Residual dispatch break/fill and Write-Command validation branches.
 * ================================================================ */

/* MTU Response send failure (att_server_dispatch.c 60-61). */
ATF_TC_WITHOUT_HEAD(test_mtu_send_failure);
ATF_TC_BODY(test_mtu_send_failure, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t pdu[3];

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	close(peer);	/* the MTU response send() will fail */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_MTU_REQ;
	put_le16(pdu + 1, 100);
	ATF_CHECK_EQ_MSG(att_server_handle(&ac, NULL, pdu, 3, -1, 0), -1,
	    "MTU response send failure propagates -1");

	free(ac.buf);
	ac.buf = NULL;
	close(ac.fd);
}

/*
 * Find By Type Value / Read By Group Type: a readable match followed by a
 * permission-gated match breaks the response (att_server_dispatch.c 999 /
 * 215), and a small MTU forces the fill break (1029).
 */
ATF_TC_WITHOUT_HEAD(test_group_break_after_match);
ATF_TC_BODY(test_group_break_after_match, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* Two identical primary services; gate the second by hand. */
	attdb_add_service(&db, 0x1800);		/* handle 1, readable */
	attdb_add_service(&db, 0x1800);		/* handle 2 */
	attrs[1].perms = ATT_PERM_READ_ENCRYPT;
	ac.encrypted = false;

	/* Find By Type Value: first matches, second gated -> break (999). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ_MSG(n, 1 + 4, "only the first (readable) match returned");

	/* Read By Group Type: first matches, second gated -> break (215). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ_MSG(n, 2 + (4 + 2), "gated 2nd group breaks the response");

	srv_cleanup(&ac, peer);
}

/* Find By Type Value fill break at pos+4 > MTU (Vol 3 Part F 3.4.3.3). */
ATF_TC_WITHOUT_HEAD(test_fbtv_fill_break);
ATF_TC_BODY(test_fbtv_fill_break, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	for (int i = 0; i < 6; i++)
		attdb_add_service(&db, 0x1800);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ_MSG(n, 1 + (5 * 4),
	    "sixth 4-byte pair does not fit ATT_DEFAULT_MTU");

	srv_cleanup(&ac, peer);
}

/* Read Multiple Variable: break at pos+2 > pos_limit (1157). */
ATF_TC_WITHOUT_HEAD(test_rmv_len_prefix_break);
ATF_TC_BODY(test_rmv_len_prefix_break, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[7], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ,
	    "\x01\x02\x03\x04\x05\x06\x07\x08\x09", 9);
	attdb_add_descriptor(&db, 0x2A1A, ATT_PERM_READ,
	    "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11", 8);
	attdb_add_descriptor(&db, 0x2A1B, ATT_PERM_READ,
	    "\x12\x13\x14\x15\x16\x17", 6);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0002);
	put_le16(pdu + 5, 0x0003);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ_MSG(n, 1 + (2 + 9) + (2 + 8),
	    "third length-prefix does not fit ATT_DEFAULT_MTU");

	srv_cleanup(&ac, peer);
}

/* Write Command validation-fail (silent) branches: invalid length, NOTIFY
 * not permitted, and CCCD table full (att_server_dispatch.c 536/568/603). */
ATF_TC_WITHOUT_HEAD(test_write_cmd_silent_rejects);
ATF_TC_BODY(test_write_cmd_silent_rejects, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[8];
	uint16_t h_val, h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	h_val = attdb_add_characteristic(&db, 0xFF01,
	    GATT_PROP_WRITE | GATT_PROP_NOTIFY, ATT_PERM_WRITE, "\x00", 1);
	h_cccd = attdb_add_cccd(&db);

	/* Write Command with a value longer than value_maxlen -> silent (536). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, h_val);
	memset(pdu + 3, 0x11, 8);		/* 8 > maxlen(1) */
	att_server_handle(&ac, &db, pdu, 11, -1, 0);
	ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
	    "oversized Write Command is silently dropped");

	/*
	 * CCCD table already full: a Write Command to a new CCCD handle is
	 * dropped silently (603).  Char has NOTIFY so validation passes.
	 */
	ac.cccd_count = ATT_MAX_CCCDS_PER_CONN;
	for (int i = 0; i < ATT_MAX_CCCDS_PER_CONN; i++)
		ac.cccds[i].handle = 0x9000 + i;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
	    "CCCD-table-full Write Command dropped silently (603)");

	srv_cleanup(&ac, peer);
}

/* Write Command enabling NOTIFY on a non-NOTIFY characteristic -> silent
 * (att_server_dispatch.c 568). */
ATF_TC_WITHOUT_HEAD(test_write_cmd_notify_not_permitted);
ATF_TC_BODY(test_write_cmd_notify_not_permitted, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[5], rsp[8];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_READ, ATT_PERM_READ,
	    "\x00", 1);				/* no NOTIFY property */
	h_cccd = attdb_add_cccd(&db);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, GATT_CCCD_NOTIFY);
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
	    "NOTIFY-not-permitted Write Command dropped silently (568)");

	srv_cleanup(&ac, peer);
}

/* Post-apply CCCD sweep: a split write leaving value_len < 2 is skipped
 * (att_server_dispatch.c 887-888). */
ATF_TC_WITHOUT_HEAD(test_execute_cccd_split_shortval);
ATF_TC_BODY(test_execute_cccd_split_shortval, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[16], rsp[8];
	uint16_t h_cccd;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	h_cccd = build_notify_char_named(&db, GATT_PROP_NOTIFY, NULL);
	/* Shrink the CCCD backing length so the post-apply sweep skips it. */
	attdb_find_by_handle(&db, h_cccd)->value_len = 1;

	/* Partial prepare (offset 0, len 1) -> not the (0,2) CCCD fast path. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, h_cccd);
	put_le16(pdu + 3, 0);
	pdu[5] = 0x01;
	(void)srv_xchg(&ac, &db, peer, pdu, 6, val + 3000, 32);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ;
	pdu[1] = 0x01;
	ATF_REQUIRE(srv_xchg(&ac, &db, peer, pdu, 2, rsp, sizeof(rsp)) == 1);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_RSP);

	srv_cleanup(&ac, peer);
}

/*
 * Send-failure tail of every response-producing handler and of
 * att_send_error(): with the peer closed att_server_send() fails, so each
 * handler returns -1 (att_server.c 485; att_server_dispatch.c per-handler
 * "== len ? 0 : -1" arms).
 */
ATF_TC_WITHOUT_HEAD(test_send_failure_sweep);
ATF_TC_BODY(test_send_failure_sweep, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[32];
	uint16_t h_rd, h_wr;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);				/* h1 */
	h_rd = attdb_add_characteristic(&db, 0xFF01, GATT_PROP_READ,
	    ATT_PERM_READ, "\x10\x11", 2);			/* h3 */
	h_wr = attdb_add_characteristic(&db, 0xFF02, GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00\x00", 2);			/* h5 */
	attrs[db.count - 1].value_maxlen = 8;

	close(peer);	/* every att_server_send() now fails */

#define FIRE(len)	ATF_CHECK_EQ(att_server_handle(&ac, &db, pdu, (len), \
			    -1, 0), -1)

	/* att_send_error tail: invalid-handle Read -> error send fails (485). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ; put_le16(pdu + 1, 0xABCD); FIRE(3);

	/* Find Information response send failure. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_INFO_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF); FIRE(5);

	/* Find By Type Value (matches the primary service). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE);
	put_le16(pdu + 7, 0x1800); FIRE(9);

	/* Read By Group Type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_PRIMARY_SERVICE); FIRE(7);

	/* Read By Type. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0xFF01); FIRE(7);

	/* Read Request. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ; put_le16(pdu + 1, h_rd); FIRE(3);

	/* Read Blob Request. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ; put_le16(pdu + 1, h_rd);
	put_le16(pdu + 3, 0); FIRE(5);

	/* Read Multiple. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, h_rd); put_le16(pdu + 3, h_rd); FIRE(5);

	/* Read Multiple Variable. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, h_rd); put_le16(pdu + 3, h_rd); FIRE(5);

	/* Write Request (Write Response send fails). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ; put_le16(pdu + 1, h_wr);
	pdu[3] = 0x22; pdu[4] = 0x33; FIRE(5);

	/* Prepare Write (echo send fails). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_PREPARE_WRITE_REQ; put_le16(pdu + 1, h_wr);
	put_le16(pdu + 3, 0); pdu[5] = 0x44; FIRE(6);

	/* Execute Write (cancel: Execute Write Response send fails). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_EXECUTE_WRITE_REQ; pdu[1] = 0x00; FIRE(2);

#undef FIRE
	free(ac.buf);
	ac.buf = NULL;
	close(ac.fd);
}

/*
 * Residual dispatch branches: 128-bit Read By Type match; Find By Type
 * Value against a Secondary Service and with a non-matching value / an
 * out-of-range attribute; Read By Group out-of-range skip; and a
 * writable attribute with a NULL backing pointer.
 */
ATF_TC_WITHOUT_HEAD(test_dispatch_residual);
ATF_TC_BODY(test_dispatch_residual, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t u128[16] = { 0xDE,0xAD,0xBE,0xEF,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[32], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	/* --- 128-bit Read By Type match (att_server_dispatch.c 316-319). --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic128(&db, u128, GATT_PROP_READ, ATT_PERM_READ,
	    "\xAB", 1);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	memcpy(pdu + 5, u128, 16);		/* 21-byte 128-bit request */
	n = srv_xchg(&ac, &db, peer, pdu, 21, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 2);
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP);
	srv_cleanup(&ac, peer);

	/* --- Secondary Service group + value mismatch + range skip. --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	/* Build by hand: a Secondary Service (0x2801) then a later attr. */
	db.count = 3;
	db.next_handle = 4;
	memset(attrs, 0, sizeof(attrs[0]) * 3);
	attrs[0].handle = 1; attrs[0].uuid16 = GATT_UUID_SECONDARY_SERVICE;
	put_le16(val + 0, 0x1801); attrs[0].value = val; attrs[0].value_len = 2;
	attrs[0].perms = ATT_PERM_READ; attrs[0].owner_fd = -1;
	attrs[1].handle = 2; attrs[1].uuid16 = 0x2A19;
	val[8] = 0x77; attrs[1].value = val + 8; attrs[1].value_len = 1;
	attrs[1].perms = ATT_PERM_READ; attrs[1].owner_fd = -1;
	attrs[2].handle = 3; attrs[2].uuid16 = GATT_UUID_SECONDARY_SERVICE;
	put_le16(val + 16, 0x1802); attrs[2].value = val + 16;
	attrs[2].value_len = 2; attrs[2].perms = ATT_PERM_READ;
	attrs[2].owner_fd = -1;

	/* Find secondary service 0x1801 over the full range: dynamic grp_end
	 * boundary lands on the next secondary service (1007-1019). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, GATT_UUID_SECONDARY_SERVICE);
	put_le16(pdu + 7, 0x1801);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "one secondary-service group, got %zd", n);
	ATF_CHECK_EQ_MSG(get_le16(rsp + 3), 0x0002,
	    "grp_end is the handle before the next secondary service");

	/* Non-matching value for the same type -> value comparison continue
	 * (att_server_dispatch.c 1003). */
	put_le16(pdu + 7, 0x9999);
	expect_err(&ac, &db, peer, pdu, 9, BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);

	/* Narrow range so later handles are skipped by handle>end
	 * (att_server_dispatch.c 985 / 203). */
	put_le16(pdu + 3, 0x0001);	/* end = 1 */
	put_le16(pdu + 7, 0x1801);
	n = srv_xchg(&ac, &db, peer, pdu, 9, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n == 5, "match at handle 1, later handles out of range");

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(pdu + 3, 0x0001);
	put_le16(pdu + 5, GATT_UUID_SECONDARY_SERVICE);
	n = srv_xchg(&ac, &db, peer, pdu, 7, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n >= 2, "read-by-group secondary within narrow range");
	srv_cleanup(&ac, peer);

	/* --- Writable attribute with a NULL backing pointer. --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE, ATT_PERM_WRITE,
	    NULL, 0);
	attrs[db.count - 1].value = NULL;
	attrs[db.count - 1].value_maxlen = 4;	/* maxlen>0 but value==NULL */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	pdu[3] = 0x11; pdu[4] = 0x22;
	/* vlen(2) <= maxlen(4) so the NULL-pointer clause fires (532:32). */
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_WRITE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_ATTR_LEN);
	srv_cleanup(&ac, peer);
}

/*
 * More database-helper corners: zero-length characteristic/descriptor,
 * Secondary Service removal, and a write to an encryption-gated attribute
 * whose key size is "unset" (0) so the key-size floor does not apply.
 */
ATF_TC_WITHOUT_HEAD(test_attdb_helper_corners);
ATF_TC_BODY(test_attdb_helper_corners, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t u128[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[8], rsp[8];

	/* Zero-length 128-bit characteristic and zero-length descriptor:
	 * the value-store branch is skipped (att_server.c 296 / 386). */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	ATF_CHECK(attdb_add_characteristic128(&db, u128, GATT_PROP_READ,
	    ATT_PERM_READ, NULL, 0) != 0);
	ATF_CHECK(attdb_add_descriptor(&db, 0x2901, ATT_PERM_READ, NULL, 0)
	    != 0);

	/* Remove a Secondary Service (att_server.c 408-409, 420-421): two
	 * secondary services built by hand; removing the first finds the
	 * second as the group boundary. */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	db.count = 3;
	db.next_handle = 4;
	memset(attrs, 0, sizeof(attrs[0]) * 3);
	attrs[0].handle = 1; attrs[0].uuid16 = GATT_UUID_SECONDARY_SERVICE;
	attrs[0].owner_fd = -1;
	attrs[1].handle = 2; attrs[1].uuid16 = 0x2803; attrs[1].owner_fd = -1;
	attrs[2].handle = 3; attrs[2].uuid16 = GATT_UUID_SECONDARY_SERVICE;
	attrs[2].owner_fd = -1;
	ATF_CHECK_EQ_MSG(attdb_remove_service(&db, 1), 0,
	    "secondary service removed");
	ATF_CHECK_EQ_MSG(db.count, 1, "group [1..2] removed, secondary 3 kept");
	ATF_CHECK_EQ(db.attrs[0].handle, 3);

	/* Encryption-gated write with enc_key_size == 0 (unset): the key-size
	 * floor check is skipped, so the write succeeds (att_server.c 526). */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	ac.encrypted = true;
	ac.enc_key_size = 0;		/* not negotiated -> floor N/A */
	ac.min_key_size = 16;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_WRITE,
	    ATT_PERM_WRITE_ENCRYPT, "\x00\x00", 2);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	pdu[3] = 0x55; pdu[4] = 0x66;
	ATF_REQUIRE(srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp)) == 1);
	ATF_CHECK_EQ_MSG(rsp[0], BT_CORE63_WIRE_ATT_OP_WRITE_RSP,
	    "encrypted write with unset key size succeeds");
	srv_cleanup(&ac, peer);
}

/*
 * Second residual batch: NULL-value Read / Read Blob / Read Multiple
 * Variable memcpy-guard arms; Read Blob on a zero-length value; MTU
 * request whose client value exceeds the server's; a 1-byte CCCD write
 * (vlen != 2 -> normal write path); a Client Supported Features write
 * with the Robust Caching bit clear; a dispatch on a bearer with mtu 0;
 * and a 128-bit Read By Type whose UUID matches nothing.
 */
ATF_TC_WITHOUT_HEAD(test_dispatch_residual2);
ATF_TC_BODY(test_dispatch_residual2, tc)
{
	struct att_conn ac;
	int peer, bfd[2];
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t u128[16] = { 0xC0,0xDE,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t other128[16] = { 0xFF,0xEE,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	uint8_t pdu[32], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	/* --- NULL-value Read / Read Blob / Read Multiple Variable. --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A19, ATT_PERM_READ, "\x00", 1);	/* h1 */
	attrs[0].value = NULL; attrs[0].value_len = 4;	/* len>0, ptr NULL */

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ; put_le16(pdu + 1, 0x0001);
	n = srv_xchg(&ac, &db, peer, pdu, 3, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n >= 1 && rsp[0] == BT_CORE63_WIRE_ATT_OP_READ_RSP,
	    "NULL-value Read handled without deref, got %zd", n);

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ; put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n >= 1, "NULL-value Read Blob handled");

	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0x0001);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n >= 1, "NULL-value Read Multiple Variable handled");
	srv_cleanup(&ac, peer);

	/* --- Read Blob offset>0 on a zero-length value -> INVALID_OFFSET. --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_descriptor(&db, 0x2A1B, ATT_PERM_READ, NULL, 0);	/* len 0 */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ; put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 4);
	expect_err(&ac, &db, peer, pdu, 5, BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ,
	    BT_CORE63_WIRE_ATT_ERR_INVALID_OFFSET);
	srv_cleanup(&ac, peer);

	/* --- MTU request client value > server value (att_server_dispatch 63). */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_DEFAULT_MTU;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_MTU_REQ; put_le16(pdu + 1, 4000);
	n = srv_xchg(&ac, &db, peer, pdu, 3, rsp, sizeof(rsp));
	ATF_REQUIRE(n == 3);
	ATF_CHECK_EQ_MSG(ac.mtu, ATT_PDU_BUF_SIZE,
	    "negotiated MTU is the smaller server value");
	srv_cleanup(&ac, peer);

	/*
	 * 1-byte CCCD write: a CCCD (0x2902) is exactly two octets (Core Spec
	 * Vol 3 Part G §3.3.3.3), so vlen != 2 must be rejected with Invalid
	 * Attribute Value Length (0x0D) rather than corrupting the stored CCCD
	 * via the generic write path.
	 */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0xFF01, GATT_PROP_NOTIFY, ATT_PERM_READ,
	    "\x00", 1);
	attdb_add_cccd(&db);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ; put_le16(pdu + 1, 0x0004);
	pdu[3] = 0x01;				/* 1 byte -> vlen 1 */
	n = srv_xchg(&ac, &db, peer, pdu, 4, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n == 5 && rsp[0] == BT_CORE63_WIRE_ATT_OP_ERROR_RSP &&
	    rsp[4] == BT_CORE63_WIRE_ATT_ERR_INVALID_ATTR_LEN,
	    "1-byte CCCD write must be rejected with Invalid Attribute Value Length");
	srv_cleanup(&ac, peer);

	/* --- Client Supported Features (0x2B29) write, Robust Caching clear. */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic(&db, 0x2B29, GATT_PROP_WRITE, ATT_PERM_WRITE,
	    "\x00", 1);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_REQ; put_le16(pdu + 1, 0x0003);
	pdu[3] = 0x00;				/* bit 0 (robust caching) clear */
	n = srv_xchg(&ac, &db, peer, pdu, 4, rsp, sizeof(rsp));
	ATF_CHECK_MSG(n == 1 && rsp[0] == BT_CORE63_WIRE_ATT_OP_WRITE_RSP, "CSF write ok");
	ATF_CHECK_MSG(!ac.robust_caching,
	    "robust caching stays off when bit 0 is clear");
	srv_cleanup(&ac, peer);

	/* --- Dispatch on a bearer whose MTU is 0 (bearer_mtu>0 false arm). --- */
	srv_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bfd) == 0);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ; put_le16(pdu + 1, 0x0001);
	att_server_handle(&ac, &db, pdu, 3, bfd[0], 0);	/* bearer_mtu == 0 */
	ATF_CHECK_MSG(recv(bfd[1], rsp, sizeof(rsp), MSG_DONTWAIT) >= 1,
	    "response still sent on the bearer with mtu 0");
	close(bfd[0]); close(bfd[1]);
	srv_cleanup(&ac, peer);

	/* --- 128-bit Read By Type matching no attribute (memcmp != 0). --- */
	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	attdb_add_characteristic128(&db, u128, GATT_PROP_READ, ATT_PERM_READ,
	    "\x00", 1);
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	memcpy(pdu + 5, other128, 16);		/* different 128-bit UUID */
	expect_err(&ac, &db, peer, pdu, 21, BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ,
	    BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND);
	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Robust Caching gate: change-unaware request classification and the
 * change-aware transitions (att_server_dispatch.c ~1255-1330, ~1416-1421).
 * Core Spec Vol 3 Part G 2.5.2.1 (Fig 2.6/2.7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_robust_caching_gate);
ATF_TC_BODY(test_robust_caching_gate, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t pdu[32], rsp[16];
	uint16_t sc_val, hash_val, vendor_val;
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	/* Service Changed (0x2A05) INDICATE value attribute. */
	sc_val = attdb_add_characteristic(&db, 0x2A05, 0x20 /*INDICATE*/,
	    ATT_PERM_READ, "\x00\x00\x00\x00", 4);
	/* Database Hash (0x2B2A) READ value attribute. */
	hash_val = attdb_add_characteristic(&db, 0x2B2A, GATT_PROP_READ,
	    ATT_PERM_READ, "\x00", 1);
	vendor_val = attdb_add_characteristic(&db, 0xFF01,
	    GATT_PROP_READ | GATT_PROP_WRITE_NO_RSP,
	    ATT_PERM_READ | ATT_PERM_WRITE, "\x01", 1);

	/* Helper: drive a change-unaware request on the primary bearer and
	 * expect a DATABASE_OUT_OF_SYNC error (Vol 3 Part F 3.4.1.1 0x19). */
#define OOS(pdulen)							\
	do {								\
		ac.change_aware = false;				\
		ac.out_of_sync_sent = false;				\
		ac.robust_caching = true;				\
		att_server_handle(&ac, &db, pdu, (pdulen), -1, 0);	\
		n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);		\
		ATF_CHECK_EQ_MSG(n, 5, "out-of-sync is a 5-byte error");\
		ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_ERROR_RSP);			\
		ATF_CHECK_EQ(rsp[4], BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC);	\
	} while (0)

	/* READ_BY_TYPE too short to classify (len < 7): disallowed. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	OOS(5);

	/*
	 * §2.5.2.1: 0x12 is sent for READ_BY_TYPE only when the type is NOT
	 * «Include»/«Characteristic» AND the range is NOT 0x0001-0xFFFF.  The
	 * following three requests satisfy both (non-discovery type AND a
	 * partial range) and so are correctly disallowed.
	 */

	/* Non-discovery type (0x2800), partial range (start != 0x0001). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0005); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2800);
	OOS(7);

	/* Non-discovery type (0x2800), partial range (end != 0xFFFF). */
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0x00FF);
	put_le16(pdu + 5, 0x2800);
	OOS(7);

	/* Non-discovery type (0x2A00), partial range. */
	put_le16(pdu + 1, 0x0010); put_le16(pdu + 3, 0x0020);
	put_le16(pdu + 5, 0x2A00);
	OOS(7);

	/* READ too short to classify (len < 3): disallowed, handle 0 echoed. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	pdu[1] = 0x00;
	OOS(1);

	/* READ of a non-hash existing handle: disallowed. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, vendor_val);
	OOS(3);

	/* READ of a nonexistent handle (ra == NULL): disallowed. */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, 0x00FF);
	OOS(3);
#undef OOS

	/* ---- allowed change-unaware requests (not out-of-sync) ----
	 * Drain any queued datagram first so each recv sees only this
	 * request's response (consecutive handle() calls on one bearer
	 * otherwise leave the SEQPACKET queue ambiguous). */
#define DRAIN()	do { uint8_t d_[64]; while (recv(peer, d_, sizeof(d_),	\
		    MSG_DONTWAIT) > 0) continue; } while (0)

	/* READ_BY_TYPE Include (0x2802) discovery, full range: allowed. */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2802);
	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	/* Allowed => processed normally: with no Include attributes present the
	 * server legitimately answers ATTR_NOT_FOUND, NOT out-of-sync. */
	ATF_CHECK_MSG(n >= 1 && !(n == 5 &&
	    rsp[4] == BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC),
	    "Include discovery is allowed (not blocked) for a change-unaware client");

	/* READ_BY_TYPE Characteristic (0x2803) discovery, full range: allowed. */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2803);
	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n >= 1 && rsp[0] == BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_RSP,
	    "Characteristic discovery is allowed for a change-unaware client");

	/*
	 * §2.5.2.1 is an OR: Characteristic (0x2803) discovery over a *partial*
	 * range is allowed too (the type alone satisfies the exemption), and it
	 * must not be Database-Out-Of-Sync rejected.
	 */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0x0005);	/* partial */
	put_le16(pdu + 5, 0x2803);
	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n >= 1 && !(n == 5 &&
	    rsp[4] == BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC),
	    "Characteristic discovery over a partial range is allowed (OR)");

	/*
	 * The other OR arm: a non-discovery type (0x2800) over the FULL range
	 * 0x0001-0xFFFF is allowed because the range alone satisfies the
	 * exemption.
	 */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);	/* full range */
	put_le16(pdu + 5, 0x2800);
	att_server_handle(&ac, &db, pdu, 7, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n >= 1 && !(n == 5 &&
	    rsp[4] == BT_CORE63_WIRE_ATT_ERR_DATABASE_OUT_OF_SYNC),
	    "non-discovery type over the full range is allowed (OR)");

	/* §2.5.2.1: every command from a change-unaware client is ignored. */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, vendor_val);
	pdu[3] = 0xaa;
	att_server_handle(&ac, &db, pdu, 4, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n < 0, "ignored command must not produce a response");
	ATF_CHECK_EQ(0x01, attdb_find_by_handle(&db, vendor_val)->value[0]);
	ATF_CHECK(!ac.change_aware);

	/* Reading the Database Hash is allowed and makes the client aware
	 * (att_server_dispatch.c ~438). */
	DRAIN();
	ac.change_aware = false;
	ac.out_of_sync_sent = false;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, hash_val);
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_MSG(ac.change_aware,
	    "reading the Database Hash makes the client change-aware");
#undef DRAIN

	/* ---- change-aware transitions ---- */

	/* Second disallowed request after out-of-sync was already sent makes
	 * the client change-aware and is then processed (Fig 2.7). */
	ac.change_aware = false;
	ac.out_of_sync_sent = true;		/* already sent once */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, vendor_val);
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	ATF_CHECK_MSG(ac.change_aware,
	    "a request after out-of-sync transitions the client to aware");
	(void)recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);

	/* Confirming a Service Changed indication makes the client aware
	 * (Fig 2.6): robust_caching && !change_aware && ind_pending. */
	ac.change_aware = false;
	ac.robust_caching = true;
	ac.ind_pending = true;
	ac.ind_handle = sc_val;			/* Service Changed value handle */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_CFM;
	att_server_handle(&ac, &db, pdu, 1, -1, 0);
	ATF_CHECK_MSG(ac.change_aware,
	    "confirming a Service Changed indication makes the client aware");
	ATF_CHECK_EQ(ac.ind_pending, false);

	/* Confirming a NON-Service-Changed indication does NOT make aware. */
	ac.change_aware = false;
	ac.ind_pending = true;
	ac.ind_handle = vendor_val;		/* not 0x2A05 */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_HANDLE_CFM;
	att_server_handle(&ac, &db, pdu, 1, -1, 0);
	ATF_CHECK_MSG(!ac.change_aware,
	    "confirming an unrelated indication does not change awareness");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Permission checks: the ENCRYPT/AUTHEN *accept* paths where the link is
 * encrypted with a sufficient key size (att_server.c att_check_*_perm).
 * Core Spec Vol 3 Part F 3.2.5 / Part C 10.3.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_perm_encrypt_accept);
ATF_TC_BODY(test_perm_encrypt_accept, tc)
{
	struct att_conn ac;
	struct att_attr a;

	memset(&ac, 0, sizeof(ac));
	ac.encrypted = true;
	ac.authenticated = true;
	ac.min_key_size = 16;

	/* READ_ENCRYPT, sufficient key size (16 >= 16): accept. */
	memset(&a, 0, sizeof(a));
	a.perms = ATT_PERM_READ_ENCRYPT;
	ac.enc_key_size = 16;
	ATF_CHECK_EQ_MSG(att_check_read_perm(&a, &ac), 0,
	    "encrypted link, key size >= min: read permitted");

	/* READ_ENCRYPT, key size unknown (0): the size gate is skipped. */
	ac.enc_key_size = 0;
	ATF_CHECK_EQ(att_check_read_perm(&a, &ac), 0);

	/* READ_AUTHEN, encrypted+authenticated, sufficient key: accept. */
	a.perms = ATT_PERM_READ_AUTHEN;
	ac.enc_key_size = 16;
	ATF_CHECK_EQ(att_check_read_perm(&a, &ac), 0);

	/* WRITE_ENCRYPT, sufficient key size: accept. */
	a.perms = ATT_PERM_WRITE_ENCRYPT;
	ATF_CHECK_EQ(att_check_write_perm(&a, &ac), 0);

	/* WRITE_ENCRYPT, key size unknown (0): size gate skipped. */
	ac.enc_key_size = 0;
	ATF_CHECK_EQ(att_check_write_perm(&a, &ac), 0);

	/* WRITE_AUTHEN, encrypted+authenticated, sufficient key: accept. */
	a.perms = ATT_PERM_WRITE_AUTHEN;
	ac.enc_key_size = 16;
	ATF_CHECK_EQ(att_check_write_perm(&a, &ac), 0);
}

/* ================================================================
 * Dispatch edge arms: Read Blob of a genuinely long value (blob IS
 * appropriate), and Find By Type Value skipping a same-type attribute
 * whose value differs (att_server_dispatch.c ~500, ~1025).
 * Core Spec Vol 3 Part F 3.4.4.5 / 3.4.3.3.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_dispatch_blob_and_findvalue);
ATF_TC_BODY(test_dispatch_blob_and_findvalue, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[DB_MAX];
	uint8_t val[VAL_SZ];
	uint8_t longval[300];
	uint16_t h_long;
	uint8_t pdu[32], rsp[64];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = 100;				/* value_len 300 > mtu-1 */
	attdb_init(&db, attrs, DB_MAX, val, sizeof(val));
	attdb_add_service(&db, 0x1800);
	memset(longval, 0x5A, sizeof(longval));
	h_long = attdb_add_characteristic(&db, 0xFF10, GATT_PROP_READ,
	    ATT_PERM_READ, longval, sizeof(longval));

	/* Read Blob at offset>0 of a long value: NOT "attribute not long",
	 * the server returns the requested fragment (Read Blob Response). */
	pdu[0] = BT_CORE63_WIRE_ATT_OP_READ_BLOB_REQ;
	put_le16(pdu + 1, h_long);
	put_le16(pdu + 3, 50);			/* offset 50 (< value_len) */
	att_server_handle(&ac, &db, pdu, 5, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_CHECK_MSG(n >= 1 && rsp[0] == BT_CORE63_WIRE_ATT_OP_READ_BLOB_RSP,
	    "blob read of a long value returns a fragment, not an error");

	/* Find By Type Value where the 0x2800 attribute's value differs from
	 * the requested one: that attribute is skipped, yielding NOT FOUND. */
	while (recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) > 0)
		continue;
	pdu[0] = BT_CORE63_WIRE_ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(pdu + 1, 0x0001); put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0x2800);		/* Primary Service type */
	put_le16(pdu + 7, 0x1801);		/* requested UUID != stored 0x1800 */
	att_server_handle(&ac, &db, pdu, 9, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "value-mismatch yields a 5-byte error");
	ATF_CHECK_EQ(rsp[0], BT_CORE63_WIRE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ_MSG(rsp[4], BT_CORE63_WIRE_ATT_ERR_ATTR_NOT_FOUND,
	    "a same-type attribute with a different value is not a match");

	srv_cleanup(&ac, peer);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_dispatch_blob_and_findvalue);
	ATF_TP_ADD_TC(tp, test_perm_encrypt_accept);
	ATF_TP_ADD_TC(tp, test_robust_caching_gate);
	ATF_TP_ADD_TC(tp, test_dispatch_residual2);
	ATF_TP_ADD_TC(tp, test_attdb_helper_corners);
	ATF_TP_ADD_TC(tp, test_dispatch_residual);
	ATF_TP_ADD_TC(tp, test_send_failure_sweep);
	ATF_TP_ADD_TC(tp, test_mtu_send_failure);
	ATF_TP_ADD_TC(tp, test_group_break_after_match);
	ATF_TP_ADD_TC(tp, test_fbtv_fill_break);
	ATF_TP_ADD_TC(tp, test_rmv_len_prefix_break);
	ATF_TP_ADD_TC(tp, test_write_cmd_silent_rejects);
	ATF_TP_ADD_TC(tp, test_write_cmd_notify_not_permitted);
	ATF_TP_ADD_TC(tp, test_execute_cccd_split_shortval);
	ATF_TP_ADD_TC(tp, test_opcode_name);
	ATF_TP_ADD_TC(tp, test_extract_uuid_corners);
	ATF_TP_ADD_TC(tp, test_attdb_slot_exhaustion);
	ATF_TP_ADD_TC(tp, test_attdb_value_exhaustion);
	ATF_TP_ADD_TC(tp, test_write_enc_key_size);
	ATF_TP_ADD_TC(tp, test_find_info_128bit);
	ATF_TP_ADD_TC(tp, test_find_info_128bit_first);
	ATF_TP_ADD_TC(tp, test_find_info_128bit_full);
	ATF_TP_ADD_TC(tp, test_fbtv_perm_and_range);
	ATF_TP_ADD_TC(tp, test_fbtv_nonservice_and_endgroup);
	ATF_TP_ADD_TC(tp, test_rbgt_perm_first);
	ATF_TP_ADD_TC(tp, test_rbgt_value_clamp_and_mixed);
	ATF_TP_ADD_TC(tp, test_rbgt_mixed_len_break);
	ATF_TP_ADD_TC(tp, test_rbt_perm_break_and_mixed);
	ATF_TP_ADD_TC(tp, test_rbt_mixed_len_break);
	ATF_TP_ADD_TC(tp, test_rbt_value_clamp_253);
	ATF_TP_ADD_TC(tp, test_rbt_fill_break);
	ATF_TP_ADD_TC(tp, test_read_cccd_min_mtu);
	ATF_TP_ADD_TC(tp, test_read_multiple_null_value);
	ATF_TP_ADD_TC(tp, test_read_multiple_var_perm);
	ATF_TP_ADD_TC(tp, test_read_multiple_var_fill);
	ATF_TP_ADD_TC(tp, test_write_cmd_cccd_branches);
	ATF_TP_ADD_TC(tp, test_write_cccd_orphan_cmd);
	ATF_TP_ADD_TC(tp, test_write_cccd_table_full);
	ATF_TP_ADD_TC(tp, test_write_owner_fd_notify);
	ATF_TP_ADD_TC(tp, test_prepare_echo_clamp);
	ATF_TP_ADD_TC(tp, test_execute_revalidate_handle);
	ATF_TP_ADD_TC(tp, test_execute_revalidate_perm);
	ATF_TP_ADD_TC(tp, test_execute_cccd_notify_reject);
	ATF_TP_ADD_TC(tp, test_execute_cccd_indicate_reject);
	ATF_TP_ADD_TC(tp, test_execute_cccd_orphan_reject);
	ATF_TP_ADD_TC(tp, test_execute_cccd_commit_update);
	ATF_TP_ADD_TC(tp, test_execute_value_extend);
	ATF_TP_ADD_TC(tp, test_execute_cccd_split_indicate);
	ATF_TP_ADD_TC(tp, test_robust_block_on_bearer);
	ATF_TP_ADD_TC(tp, test_signed_write_verified);
	ATF_TP_ADD_TC(tp, test_notify_large_mtu_clamp);
	ATF_TP_ADD_TC(tp, test_notify_send_failure);
	ATF_TP_ADD_TC(tp, test_hash_16bit_descriptors);
	ATF_TP_ADD_TC(tp, test_hash_128bit_types);
	ATF_TP_ADD_TC(tp, test_hash_include_null_value);

	return (atf_no_error());
}
