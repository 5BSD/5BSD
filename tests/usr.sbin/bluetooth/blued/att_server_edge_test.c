/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case / negative tests for the ATT *server* (att_server.c,
 * att_server_dispatch.c, att_server_notify.c, att_server_hash.c) that the
 * existing att_test.c / att_negative_test.c suites do not reach:
 *
 *   - permission failures: READ/WRITE_NOT_PERMITTED, INSUFF_ENCRYPTION,
 *     INSUFF_ENC_KEY_SIZE, INSUFF_AUTHEN, exercised against a database of
 *     encryption- and authentication-gated attributes;
 *   - GATT Robust Caching gating for a change-unaware client across the
 *     allowed opcodes (MTU, Handle Value Confirmation, Read By Type of
 *     Include/Characteristic over the full range, and Read of the Database
 *     Hash which flips the client to change-aware);
 *   - Prepare/Execute Write: queue byte-budget overflow, oversized value,
 *     offset overflow, and Execute Write commit/validation branches;
 *   - Read Multiple (Variable) length-clamping and error branches;
 *   - the notification / indication / multiple-notification senders;
 *   - database construction helpers (includes, descriptors, 128-bit
 *     services/characteristics, service removal, value-store exhaustion);
 *   - the Database Hash (att_server_hash.c), verified byte-for-byte against
 *     the worked example in Core Spec Vol 3 Part G Appendix B.
 *
 * ORACLE: expected bytes / error codes / the Database Hash are hand-derived
 * from the Bluetooth Core Specification (ATT = Vol 3 Part F; robust caching
 * and the hash = Vol 3 Part G Section 2.5.2 / 7.3 / Appendix B), with a
 * citation per assertion group.  No expected value is captured from the
 * implementation's own output.
 *
 * A SOCK_SEQPACKET socketpair stands in for the L2CAP ATT channel; server
 * responses are drained with MSG_DONTWAIT.
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
#include "spec_oracles.h"

#define SEEDGE_ENUM(name, value) SEEDGE_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(SEEDGE_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(SEEDGE_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(SEEDGE_ENUM)
};
#undef SEEDGE_ENUM

enum {
	SEEDGE_HANDLE_MIN = 0x0001,
	SEEDGE_HANDLE_MAX = 0xffff,
	SEEDGE_EXECUTE_CANCEL = BT_CORE63_ATT_EXECUTE_CANCEL,
	SEEDGE_EXECUTE_COMMIT = BT_CORE63_ATT_EXECUTE_COMMIT,
	SEEDGE_FIXTURE_CHAR_1 = 0xff01,
	SEEDGE_FIXTURE_CHAR_2 = 0xff02,
	SEEDGE_FIXTURE_CHAR_3 = 0xff03,
	SEEDGE_FIXTURE_CHAR_4 = 0xff04,
	SEEDGE_FIXTURE_SERVICE_1 = 0xffe0,
	SEEDGE_FIXTURE_SERVICE_2 = 0xffe2,
	SEEDGE_FIXTURE_SERVICE_3 = 0xffe3,
};

/* Core 6.3 Vol 3 Part B §2.5.1, generated independently of blued. */
static const uint8_t seedge_base_uuid_le[12] =
    BT_CORE63_BLUETOOTH_BASE_UUID_LE12;

int att_test_eatt_mtu(int, uint16_t *, uint16_t *);
int
att_test_eatt_mtu(int fd __unused, uint16_t *imtu, uint16_t *omtu)
{

	*imtu = *omtu = BT_CORE63_EATT_MIN_MTU;
	return (0);
}

#include "test_common.h"

#define TEST_DB_MAX_ATTRS	48
#define TEST_DB_VAL_SIZE	1024

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
	ac->mtu = ATT_PDU_BUF_SIZE;	/* generous; individual tests override */
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

/* Pure-database tests use stack storage only; nothing to release. */
static void
srv_cleanup_nofd(struct att_db *db __unused)
{
}

/* Run one request through the dispatcher, return the reply length (or <0). */
static ssize_t
srv_xchg(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t *rsp, size_t rsplen)
{

	att_server_handle(ac, db, pdu, len, -1, 0);
	return (recv(peer, rsp, rsplen, MSG_DONTWAIT));
}

/* Assert an ATT Error Response (Core Spec Vol 3 Part F 3.4.1.1). */
static void
expect_err(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op, uint8_t exp_code)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_xchg(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n == 5, "op 0x%02x: expected 5-byte error, got %zd",
	    pdu[0], n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ_MSG(rsp[1], exp_op, "op 0x%02x: wrong echoed opcode",
	    pdu[0]);
	ATF_CHECK_EQ_MSG(rsp[4], exp_code,
	    "op 0x%02x: expected code 0x%02x got 0x%02x", pdu[0], exp_code,
	    rsp[4]);
}

static void
expect_rsp_op(struct att_conn *ac, struct att_db *db, int peer,
    const uint8_t *pdu, size_t len, uint8_t exp_op)
{
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	n = srv_xchg(ac, db, peer, pdu, len, rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n >= 1, "op 0x%02x: expected a response, got %zd",
	    pdu[0], n);
	ATF_CHECK_EQ_MSG(rsp[0], exp_op, "op 0x%02x: expected rsp 0x%02x got "
	    "0x%02x", pdu[0], exp_op, rsp[0]);
}

/* ================================================================
 * Permission-gated database
 *
 * Handle map:
 *  0x0001 Primary Service BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE                         (READ)
 *  0x0002 Char decl (READ)                               (READ)
 *  0x0003 "noread": value attr, perms = WRITE only       (write-only)
 *  0x0004 Char decl (READ|WRITE)                         (READ)
 *  0x0005 "encr": value attr, READ_ENCRYPT|WRITE_ENCRYPT (encryption-gated)
 *  0x0006 Char decl (READ|WRITE)                         (READ)
 *  0x0007 "auth": value attr, READ_AUTHEN|WRITE_AUTHEN   (authn-gated)
 *  0x0008 Char decl (READ)                               (READ)
 *  0x0009 "ro": value attr, READ only                    (read-only)
 * ================================================================ */
#define H_NOREAD	0x0003
#define H_ENCR		0x0005
#define H_AUTH		0x0007
#define H_RO		0x0009

static void
build_perm_db(struct att_db *db, struct att_attr *attrs, uint8_t *val)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);

	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(db, SEEDGE_FIXTURE_CHAR_1,
	    SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_WRITE, "\x00", 1);				/* 0x0003 */
	attdb_add_characteristic(db, SEEDGE_FIXTURE_CHAR_2,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ_ENCRYPT | ATT_PERM_WRITE_ENCRYPT,
	    "\x11\x22", 2);					/* 0x0005 */
	attdb_add_characteristic(db, SEEDGE_FIXTURE_CHAR_3,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ_AUTHEN | ATT_PERM_WRITE_AUTHEN,
	    "\x33\x44", 2);					/* 0x0007 */
	attdb_add_characteristic(db, SEEDGE_FIXTURE_CHAR_4,
	    SEEDGE_GATT_PROP_READ,
	    ATT_PERM_READ, "\x55\x66", 2);			/* 0x0009 */
}

#define PERM_SETUP(ac, peer, db, attrs, val)				\
	struct att_conn ac;						\
	int peer;							\
	struct att_db db;						\
	struct att_attr attrs[TEST_DB_MAX_ATTRS];			\
	uint8_t val[TEST_DB_VAL_SIZE];					\
	srv_pair(&ac, &peer);						\
	build_perm_db(&db, attrs, val)

static void
mk_read(uint8_t *pdu, uint16_t handle)
{

	pdu[0] = SEEDGE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, handle);
}

/* ---- READ_NOT_PERMITTED (Core Spec Vol 3 Part F 3.4.4.4) ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_not_permitted);
ATF_TC_BODY(test_se_read_not_permitted, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[3];

	mk_read(pdu, H_NOREAD);		/* write-only attribute */
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_READ_NOT_PERMITTED);

	srv_cleanup(&ac, peer);
}

/* ---- INSUFF_ENCRYPTION then INSUFF_ENC_KEY_SIZE then success ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_encryption_gate);
ATF_TC_BODY(test_se_read_encryption_gate, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[3];

	mk_read(pdu, H_ENCR);

	/* Unencrypted link -> Insufficient Encryption (3.4.4.4). */
	ac.encrypted = false;
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Encrypted but key shorter than the minimum -> Insufficient Key Size. */
	ac.encrypted = true;
	ac.enc_key_size = 7;
	ac.min_key_size = 16;
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENC_KEY_SIZE);

	/* Encrypted with an adequate key -> Read Response. */
	ac.enc_key_size = 16;
	expect_rsp_op(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_RSP);

	srv_cleanup(&ac, peer);
}

/* ---- AUTHEN: unencrypted, small key, and unauthenticated variants ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_authen_gate);
ATF_TC_BODY(test_se_read_authen_gate, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[3];

	mk_read(pdu, H_AUTH);

	/* Unencrypted -> Insufficient Encryption (encryption precedes authn). */
	ac.encrypted = false;
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Encrypted, small key -> Insufficient Encryption Key Size. */
	ac.encrypted = true;
	ac.enc_key_size = 7;
	ac.min_key_size = 16;
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENC_KEY_SIZE);

	/* Encrypted, adequate key, but not authenticated -> Insufficient
	 * Authentication (Core Spec Vol 3 Part F 3.4.4.4). */
	ac.enc_key_size = 16;
	ac.authenticated = false;
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_REQ,
	    SEEDGE_ATT_ERR_INSUFF_AUTHEN);

	/* Authenticated -> Read Response. */
	ac.authenticated = true;
	expect_rsp_op(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_READ_RSP);

	srv_cleanup(&ac, peer);
}

/* ---- WRITE_NOT_PERMITTED + write encryption/authn gating ---- */
ATF_TC_WITHOUT_HEAD(test_se_write_permission_gates);
ATF_TC_BODY(test_se_write_permission_gates, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[8];

	/* Write to a read-only attribute -> Write Not Permitted (3.4.5.2). */
	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, H_RO);
	pdu[3] = 0xAA; pdu[4] = 0xBB;
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_WRITE_NOT_PERMITTED);

	/* Encryption-gated write on an unencrypted link. */
	put_le16(pdu + 1, H_ENCR);
	ac.encrypted = false;
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENCRYPTION);

	/* Authn-gated write, encrypted but unauthenticated. */
	put_le16(pdu + 1, H_AUTH);
	ac.encrypted = true;
	ac.enc_key_size = 16;
	ac.min_key_size = 16;
	ac.authenticated = false;
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_INSUFF_AUTHEN);

	/* Authenticated write succeeds. */
	ac.authenticated = true;
	expect_rsp_op(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_RSP);

	srv_cleanup(&ac, peer);
}

/* ---- permission failure surfaces through Read By Type discovery ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_by_type_perm_first);
ATF_TC_BODY(test_se_read_by_type_perm_first, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[7];

	/*
	 * Read By Type for the encryption-gated custom UUID on an
	 * unencrypted link: the first (and only) match fails the read
	 * permission check, so the whole request errors (3.4.4.1).
	 */
	pdu[0] = SEEDGE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, 0xFF02);	/* the READ_ENCRYPT value attr */
	ac.encrypted = false;
	expect_err(&ac, &db, peer, pdu, 7, SEEDGE_ATT_OP_READ_BY_TYPE_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENCRYPTION);

	srv_cleanup(&ac, peer);
}

/* ---- Read By Type with a 4-byte (32-bit) UUID is a malformed PDU ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_by_type_uuid32);
ATF_TC_BODY(test_se_read_by_type_uuid32, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[9];

	/*
	 * Core Spec Vol 3 Part F §3.4.4.1 Table 3.15: the Attribute Type is a
	 * 2- or 16-octet UUID only.  A 9-octet request (4-octet UUID32 type)
	 * is malformed regardless of whether the high half is zero, so the
	 * server shall respond with Invalid PDU (0x04) and not attempt any
	 * UUID32->UUID16/UUID128 collapse/expansion.
	 */
	pdu[0] = SEEDGE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	pdu[5] = 0x04; pdu[6] = 0xFF; pdu[7] = 0x00; pdu[8] = 0x00;
	expect_err(&ac, &db, peer, pdu, 9, SEEDGE_ATT_OP_READ_BY_TYPE_REQ,
	    SEEDGE_ATT_ERR_INVALID_PDU);

	pdu[5] = 0x04; pdu[6] = 0xFF; pdu[7] = 0x01; pdu[8] = 0x00;
	expect_err(&ac, &db, peer, pdu, 9, SEEDGE_ATT_OP_READ_BY_TYPE_REQ,
	    SEEDGE_ATT_ERR_INVALID_PDU);

	srv_cleanup(&ac, peer);
}

/* ---- Read Multiple: invalid handle and permission error ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_multiple_errors);
ATF_TC_BODY(test_se_read_multiple_errors, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];

	/* A missing handle in the set -> Invalid Handle (3.4.4.7). */
	pdu[0] = SEEDGE_ATT_OP_READ_MULTIPLE_REQ;
	put_le16(pdu + 1, H_RO);
	put_le16(pdu + 3, 0xF000);
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_READ_MULTIPLE_REQ,
	    SEEDGE_ATT_ERR_INVALID_HANDLE);

	/* A permission-gated handle in the set -> the permission error. */
	put_le16(pdu + 3, H_ENCR);
	ac.encrypted = false;
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_READ_MULTIPLE_REQ,
	    SEEDGE_ATT_ERR_INSUFF_ENCRYPTION);

	srv_cleanup(&ac, peer);
}

/* ---- Read Multiple Variable: success + invalid handle ---- */
ATF_TC_WITHOUT_HEAD(test_se_read_multiple_variable);
ATF_TC_BODY(test_se_read_multiple_variable, tc)
{
	PERM_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	/*
	 * Two readable handles: 0x0009 ("ro", 2 bytes) twice.  Response is
	 * a sequence of {length(2) || value} tuples (3.4.4.11-.12).
	 */
	pdu[0] = SEEDGE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	put_le16(pdu + 1, H_RO);
	put_le16(pdu + 3, H_RO);
	n = srv_xchg(&ac, &db, peer, pdu, 5, rsp, sizeof(rsp));
	ATF_REQUIRE(n >= 1);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_READ_MULTIPLE_VARIABLE_RSP);
	/* opcode + [len=2, 2 bytes] + [len=2, 2 bytes] = 1 + 4 + 4 = 9 */
	ATF_CHECK_EQ_MSG(n, 9, "two 2-byte values with length prefixes");
	ATF_CHECK_EQ(get_le16(rsp + 1), 2);

	/* Invalid handle -> Invalid Handle error. */
	put_le16(pdu + 3, 0xF000);
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_READ_MULTIPLE_VARIABLE_REQ,
	    SEEDGE_ATT_ERR_INVALID_HANDLE);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * CCCD write validation (Core Spec Vol 3 Part G 3.3.3.3)
 * ================================================================ */

/* Char with NOTIFY only + a CCCD, and a stray CCCD with no parent decl. */
#define H_CCCD_NOTIFY	0x0003
#define H_CCCD_ORPHAN	0x0005

static void
build_cccd_db(struct att_db *db, struct att_attr *attrs, uint8_t *val)
{

	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);

	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	/* 0x0002 char decl (NOTIFY), 0x0003 value -> then CCCD... but the
	 * value attr occupies 0x0003; add_cccd lands at 0x0004. */
	attdb_add_characteristic(db, 0xAA01, SEEDGE_GATT_PROP_NOTIFY,
	    ATT_PERM_READ, "\x00", 1);
	attdb_add_cccd(db);				/* 0x0004, parent NOTIFY */
	/* An orphan CCCD directly under the service (no characteristic). */
	attdb_add_cccd(db);				/* 0x0005, no parent */
}

ATF_TC_WITHOUT_HEAD(test_se_cccd_indicate_not_allowed);
ATF_TC_BODY(test_se_cccd_indicate_not_allowed, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[5];

	srv_pair(&ac, &peer);
	build_cccd_db(&db, attrs, val);

	/* Enabling notifications on a NOTIFY-capable char succeeds. */
	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0004);
	put_le16(pdu + 3, BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	expect_rsp_op(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_RSP);

	/* Enabling indications when the char lacks INDICATE -> Value Not
	 * Allowed (Core Spec Vol 3 Part G 3.3.3.3). */
	put_le16(pdu + 3, BT_CORE63_GATT_CCCD_INDICATIONS_ENABLED);
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_VALUE_NOT_ALLOWED);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_se_cccd_orphan);
ATF_TC_BODY(test_se_cccd_orphan, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[5];

	srv_pair(&ac, &peer);
	/*
	 * A CCCD placed directly under a service with NO preceding
	 * characteristic declaration: 0x0001 service, 0x0002 CCCD.  A write
	 * cannot locate a parent characteristic to validate against ->
	 * Unlikely Error.
	 */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);		/* 0x0001 */
	attdb_add_cccd(&db);			/* 0x0002, no parent char */

	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0002);
	put_le16(pdu + 3, BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	expect_err(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_UNLIKELY_ERROR);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Prepare / Execute Write edge branches (Core Spec Vol 3 Part F 3.4.6)
 * ================================================================ */

/* Writable custom characteristic with a large maxlen for long writes. */
#define H_LONG	0x0003

static void
build_long_db(struct att_db *db, struct att_attr *attrs, uint8_t *val)
{
	uint8_t zeros[64];

	memset(zeros, 0, sizeof(zeros));
	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(db, SEEDGE_FIXTURE_SERVICE_1);
	attdb_add_characteristic(db, 0xBB01,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, zeros, sizeof(zeros)); /* 0x0003 */
}

#define LONG_SETUP(ac, peer, db, attrs, val)				\
	struct att_conn ac;						\
	int peer;							\
	struct att_db db;						\
	struct att_attr attrs[TEST_DB_MAX_ATTRS];			\
	uint8_t val[TEST_DB_VAL_SIZE];					\
	srv_pair(&ac, &peer);						\
	build_long_db(&db, attrs, val)

/* Offset + length overflowing the 16-bit space -> Invalid Offset. */
ATF_TC_WITHOUT_HEAD(test_se_prepare_offset_overflow);
ATF_TC_BODY(test_se_prepare_offset_overflow, tc)
{
	LONG_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5 + 4];

	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, H_LONG);
	put_le16(pdu + 3, 0xFFFF);	/* offset */
	memset(pdu + 5, 0xAA, 4);	/* 0xFFFF + 4 > 0xFFFF */
	expect_err(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_REQ, SEEDGE_ATT_ERR_INVALID_OFFSET);

	srv_cleanup(&ac, peer);
}

/* A single prepared value larger than the per-entry buffer -> Invalid Attr
 * Length (the entry value cap is ATT_PDU_BUF_SIZE - 5 = 512). */
ATF_TC_WITHOUT_HEAD(test_se_prepare_value_too_long);
ATF_TC_BODY(test_se_prepare_value_too_long, tc)
{
	LONG_SETUP(ac, peer, db, attrs, val);
	static uint8_t pdu[5 + 520];

	ac.mtu = ATT_MAX_MTU;		/* allow a jumbo PDU through the server */
	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, H_LONG);
	put_le16(pdu + 3, 0);
	memset(pdu + 5, 0xCD, 520);	/* vlen = 520 > 512 */
	expect_err(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_REQ, SEEDGE_ATT_ERR_INVALID_ATTR_LEN);

	srv_cleanup(&ac, peer);
}

/* Exhaust the queue byte budget -> Prepare Queue Full (3.4.6.1). */
ATF_TC_WITHOUT_HEAD(test_se_prepare_byte_budget);
ATF_TC_BODY(test_se_prepare_byte_budget, tc)
{
	LONG_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5 + 400];
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;
	int i;

	ac.mtu = ATT_MAX_MTU;
	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, H_LONG);
	memset(pdu + 5, 0x5A, 400);

	/*
	 * ATT_PREPARE_QUEUE_MAX_BYTES is 4096.  Ten 400-byte values = 4000
	 * bytes succeed; the eleventh would reach 4400 > 4096 and is rejected
	 * on the byte budget (not the entry count, which is 16).
	 */
	for (i = 0; i < 10; i++) {
		put_le16(pdu + 3, (uint16_t)(i * 400));
		att_server_handle(&ac, &db, pdu, sizeof(pdu), -1, 0);
		n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
		ATF_REQUIRE_MSG(n >= 1, "prepare %d: no response", i);
		ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_PREPARE_WRITE_RSP);
	}
	put_le16(pdu + 3, 4000);
	expect_err(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_REQ, SEEDGE_ATT_ERR_PREPARE_QUEUE_FULL);

	srv_cleanup(&ac, peer);
}

/* Execute Write commit applies queued values to the attribute. */
ATF_TC_WITHOUT_HEAD(test_se_execute_commit_applies);
ATF_TC_BODY(test_se_execute_commit_applies, tc)
{
	LONG_SETUP(ac, peer, db, attrs, val);
	uint8_t pdu[5 + 4], exec[2];
	struct att_attr *a;

	/* Queue a 4-byte write at offset 2. */
	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, H_LONG);
	put_le16(pdu + 3, 2);
	memcpy(pdu + 5, "\xDE\xAD\xBE\xEF", 4);
	expect_rsp_op(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_RSP);

	/* Commit (flags 0x01) -> Execute Write Response (3.4.6.3). */
	exec[0] = SEEDGE_ATT_OP_EXECUTE_WRITE_REQ;
	exec[1] = SEEDGE_EXECUTE_COMMIT;
	expect_rsp_op(&ac, &db, peer, exec, 2, SEEDGE_ATT_OP_EXECUTE_WRITE_RSP);

	/* The attribute bytes at offset 2..5 must now hold the committed value. */
	a = attdb_find_by_handle(&db, H_LONG);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ_MSG(memcmp(a->value + 2, "\xDE\xAD\xBE\xEF", 4), 0,
	    "committed prepared write must land at its offset");

	srv_cleanup(&ac, peer);
}

/* Execute Write commit whose queued offset exceeds the value length. */
ATF_TC_WITHOUT_HEAD(test_se_execute_commit_bad_offset);
ATF_TC_BODY(test_se_execute_commit_bad_offset, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[5 + 2], exec[2];

	srv_pair(&ac, &peer);
	/* Short (2-byte) writable value so a large offset is invalid. */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, SEEDGE_FIXTURE_SERVICE_2);
	attdb_add_characteristic(&db, 0xCC01,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, "\x01\x02", 2);	/* 0x0003 */

	/* Queue at offset 5 (> current length 2): accepted at prepare time. */
	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	put_le16(pdu + 3, 5);
	pdu[5] = 0xAA; pdu[6] = 0xBB;
	expect_rsp_op(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_RSP);

	/* Commit validation rejects offset 5 > value_len 2 -> Invalid Offset. */
	exec[0] = SEEDGE_ATT_OP_EXECUTE_WRITE_REQ;
	exec[1] = SEEDGE_EXECUTE_COMMIT;
	expect_err(&ac, &db, peer, exec, 2, SEEDGE_ATT_OP_EXECUTE_WRITE_REQ,
	    SEEDGE_ATT_ERR_INVALID_OFFSET);

	srv_cleanup(&ac, peer);
}

/* Execute Write commit whose queued value overruns the attribute maxlen. */
ATF_TC_WITHOUT_HEAD(test_se_execute_commit_bad_len);
ATF_TC_BODY(test_se_execute_commit_bad_len, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[5 + 4], exec[2];

	srv_pair(&ac, &peer);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, SEEDGE_FIXTURE_SERVICE_3);
	/* maxlen == 2 */
	attdb_add_characteristic(&db, 0xDD01,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, "\x01\x02", 2);	/* 0x0003 */

	/* Queue offset 0, len 4 -> 0 + 4 > maxlen 2. Accepted at prepare. */
	pdu[0] = SEEDGE_ATT_OP_PREPARE_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	put_le16(pdu + 3, 0);
	memcpy(pdu + 5, "\xAA\xBB\xCC\xDD", 4);
	expect_rsp_op(&ac, &db, peer, pdu, sizeof(pdu),
	    SEEDGE_ATT_OP_PREPARE_WRITE_RSP);

	exec[0] = SEEDGE_ATT_OP_EXECUTE_WRITE_REQ;
	exec[1] = SEEDGE_EXECUTE_COMMIT;
	expect_err(&ac, &db, peer, exec, 2, SEEDGE_ATT_OP_EXECUTE_WRITE_REQ,
	    SEEDGE_ATT_ERR_INVALID_ATTR_LEN);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Robust Caching: allowed opcodes for a change-unaware client
 * (Core Spec Vol 3 Part G 2.5.2.1)
 * ================================================================ */

/* Database that carries a Database Hash characteristic (BT_ASSIGNED_UUID_DATABASE_HASH). */
static void
build_rc_db(struct att_db *db, struct att_attr *attrs, uint8_t *val)
{
	uint8_t hash[16];

	memset(hash, 0, sizeof(hash));
	attdb_init(db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);

	attdb_add_service(db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);		/* GATT service */
	/* Database Hash characteristic: decl 0x0002, value 0x0003 (BT_ASSIGNED_UUID_DATABASE_HASH). */
	attdb_add_characteristic(db, BT_ASSIGNED_UUID_DATABASE_HASH, SEEDGE_GATT_PROP_READ,
	    ATT_PERM_READ, hash, sizeof(hash));
	/* An included service so BT_ASSIGNED_UUID_INCLUDE discovery has something to return. */
	attdb_add_include(db, 0x0001, 0x0001, 0x0003, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
}

ATF_TC_WITHOUT_HEAD(test_se_robust_allowed_ops);
ATF_TC_BODY(test_se_robust_allowed_ops, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[7];

	srv_pair(&ac, &peer);
	build_rc_db(&db, attrs, val);

	ac.robust_caching = true;
	ac.change_aware = false;

	/* Handle Value Confirmation is always allowed (no reply, clears
	 * ind_pending). */
	ac.ind_pending = true;
	{
		uint8_t cfm[1] = { SEEDGE_ATT_OP_HANDLE_CFM };
		uint8_t rsp[8];
		att_server_handle(&ac, &db, cfm, 1, -1, 0);
		ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
		    "Handle Value Confirmation must not be answered");
		ATF_CHECK_MSG(!ac.ind_pending,
		    "confirmation must clear the pending indication");
	}

	/* Read By Type of Include (BT_ASSIGNED_UUID_INCLUDE) over the full range is allowed. */
	pdu[0] = SEEDGE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0xFFFF);
	put_le16(pdu + 5, BT_ASSIGNED_UUID_INCLUDE);
	expect_rsp_op(&ac, &db, peer, pdu, 7, SEEDGE_ATT_OP_READ_BY_TYPE_RSP);

	/* Reading the Database Hash (BT_ASSIGNED_UUID_DATABASE_HASH) is allowed and makes the client
	 * change-aware (Core Spec Vol 3 Part G 2.5.2.1). */
	{
		uint8_t rd[3];
		mk_read(rd, 0x0003);	/* the BT_ASSIGNED_UUID_DATABASE_HASH value handle */
		expect_rsp_op(&ac, &db, peer, rd, 3, SEEDGE_ATT_OP_READ_RSP);
		ATF_CHECK_MSG(ac.change_aware,
		    "reading the Database Hash must set change_aware");
	}

	/* Now change-aware: a plain read that was previously blocked works. */
	{
		uint8_t rd[3];
		mk_read(rd, 0x0003);
		expect_rsp_op(&ac, &db, peer, rd, 3, SEEDGE_ATT_OP_READ_RSP);
	}

	srv_cleanup(&ac, peer);
}

/*
 * A change-unaware Read By Type is blocked only when BOTH exemptions fail
 * (Core Spec Vol 3 Part G §2.5.2.1): the type is neither «Include» nor
 * «Characteristic» AND the range is not 0x0001-0xFFFF.  Here a non-discovery
 * type (BT_ASSIGNED_UUID_PRIMARY_SERVICE) over a partial range satisfies both, so it is blocked with
 * Database Out Of Sync.
 */
ATF_TC_WITHOUT_HEAD(test_se_robust_partial_range_blocked);
ATF_TC_BODY(test_se_robust_partial_range_blocked, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[7];

	srv_pair(&ac, &peer);
	build_rc_db(&db, attrs, val);
	ac.robust_caching = true;
	ac.change_aware = false;

	/* Non-discovery type (BT_ASSIGNED_UUID_PRIMARY_SERVICE) over a partial range -> blocked. */
	pdu[0] = SEEDGE_ATT_OP_READ_BY_TYPE_REQ;
	put_le16(pdu + 1, 0x0001);
	put_le16(pdu + 3, 0x0005);	/* partial range */
	put_le16(pdu + 5, BT_ASSIGNED_UUID_PRIMARY_SERVICE);
	expect_err(&ac, &db, peer, pdu, 7, SEEDGE_ATT_OP_READ_BY_TYPE_REQ,
	    SEEDGE_ATT_ERR_DATABASE_OUT_OF_SYNC);

	srv_cleanup(&ac, peer);
}

/*
 * Writing the Client Supported Features (BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES) Robust Caching bit enables
 * the feature but MUST NOT alter change-awareness.  Core Spec Vol 3 Part G
 * §2.5.2.1: initial change-awareness is derived from the trusted relationship
 * and the Database Hash comparison at connection setup, not from the CSF
 * write.  A CSF write must therefore leave a change-aware client change-aware
 * and (critically) leave a change-unaware / stale-bonded client change-unaware
 * -- otherwise a stale client could skip mandatory rediscovery.
 */
ATF_TC_WITHOUT_HEAD(test_se_robust_enable_via_csf);
ATF_TC_BODY(test_se_robust_enable_via_csf, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint8_t pdu[5];

	srv_pair(&ac, &peer);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	/* Client Supported Features characteristic value (BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES), writable. */
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_WRITE,
	    ATT_PERM_READ | ATT_PERM_WRITE, "\x00", 1);	/* 0x0003 */

	/*
	 * Case A: a change-aware client (the default for a client without a
	 * stale trusted relationship) writes the Robust Caching bit.  Feature
	 * turns on; the client stays change-aware.
	 */
	ac.change_aware = true;
	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	pdu[3] = BT_CORE63_GATT_CSF_ROBUST_CACHING;
	expect_rsp_op(&ac, &db, peer, pdu, 4, SEEDGE_ATT_OP_WRITE_RSP);

	ATF_CHECK_MSG(ac.robust_caching,
	    "Robust Caching bit must enable robust caching");
	ATF_CHECK_MSG(ac.change_aware,
	    "CSF write must not clear an already change-aware client");

	/*
	 * Case B: a change-unaware client (e.g. a stale bonded device) writes
	 * the same bit.  The CSF write must NOT rescue it into change-aware --
	 * it stays change-unaware until it reads the Database Hash.
	 */
	ac.change_aware = false;
	ac.robust_caching = false;
	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, 0x0003);
	pdu[3] = BT_CORE63_GATT_CSF_ROBUST_CACHING;
	expect_rsp_op(&ac, &db, peer, pdu, 4, SEEDGE_ATT_OP_WRITE_RSP);

	ATF_CHECK_MSG(ac.robust_caching,
	    "Robust Caching bit must enable robust caching");
	ATF_CHECK_MSG(!ac.change_aware,
	    "CSF write must not force a change-unaware client change-aware");

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * EATT bearer dispatch: MTU_REQ is refused on an enhanced bearer
 * (Core Spec Vol 3 Part G 5.3.1 — MTU exchange only on the fixed bearer)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_se_mtu_req_on_eatt);
ATF_TC_BODY(test_se_mtu_req_on_eatt, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	int bearer[2];
	uint8_t pdu[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	build_perm_db(&db, attrs, val);

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bearer) == 0);

	/* Dispatch an MTU request on an EATT bearer (bearer_fd >= 0). */
	pdu[0] = SEEDGE_ATT_OP_MTU_REQ;
	put_le16(pdu + 1, 200);
	att_server_handle(&ac, &db, pdu, 3, bearer[0], 100);

	/* The response must go out on the EATT bearer, not the primary. */
	ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
	    "no reply expected on the primary bearer");
	n = recv(bearer[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE(n == 5);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ_MSG(rsp[4], SEEDGE_ATT_ERR_REQ_NOT_SUPPORTED,
	    "MTU exchange is not supported on an EATT bearer");

	close(bearer[0]);
	close(bearer[1]);
	srv_cleanup(&ac, peer);
}

/* ================================================================
 * L7 — a server-accepted EATT bearer carries ATT PDUs in parallel with
 * the fixed ATT channel (Core Spec Vol 3 Part G 5.3 / Part F 5.3.2).
 *
 * att_eatt_add_bearer() is the attach path the daemon's incoming-EATT
 * listener uses after accept4() to route a bearer to its connection.  Once
 * attached, a Read Request dispatched on the bearer must be answered on the
 * bearer, while the fixed bearer keeps working — the two bearers multiplex.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_se_eatt_bearer_carries_pdu);
ATF_TC_BODY(test_se_eatt_bearer_carries_pdu, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	int bearer[2];
	uint8_t pdu[3], rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	build_perm_db(&db, attrs, val);

	/* A connected L2CAP CoC socket stands in for the accepted bearer. */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bearer) == 0);

	ATF_CHECK_EQ(ac.eatt_count, 0);
	ATF_REQUIRE_EQ(att_eatt_add_bearer(&ac, bearer[0]), 0);
	ATF_CHECK_EQ(ac.eatt_count, 1);
	ATF_CHECK(ac.eatt[0].active);
	ATF_CHECK_EQ(ac.eatt[0].fd, bearer[0]);
	/* The fake CoC explicitly injects its negotiated 64-byte MTU. */
	ATF_CHECK_EQ(ac.eatt[0].mtu, BT_CORE63_EATT_MIN_MTU);

	/* Read on the ENHANCED bearer -> reply on the bearer, not the fixed. */
	mk_read(pdu, H_RO);
	att_server_handle(&ac, &db, pdu, 3, bearer[0], ac.eatt[0].mtu);
	ATF_CHECK_MSG(recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT) < 0,
	    "enhanced-bearer reply must not appear on the fixed channel");
	n = recv(bearer[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n >= 1, "expected a reply on the EATT bearer, got %zd", n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_READ_RSP);

	/* The fixed ATT channel still serves requests alongside the bearer. */
	mk_read(pdu, H_RO);
	att_server_handle(&ac, &db, pdu, 3, -1, 0);
	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n >= 1, "expected a reply on the fixed channel, got %zd",
	    n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_READ_RSP);

	/* Bearer teardown closes bearer[0] and compacts the set. */
	att_eatt_remove_bearer(&ac, bearer[0]);
	ATF_CHECK_EQ(ac.eatt_count, 0);

	close(bearer[1]);
	srv_cleanup(&ac, peer);
}

/* ================================================================
 * Notification / Indication senders (att_server_notify.c)
 * Core Spec Vol 3 Part F 3.4.7
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_se_notification_pdu);
ATF_TC_BODY(test_se_notification_pdu, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t got[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;	/* 23 -> value capped at 20 bytes */

	ret = att_send_notification(&ac, 0x0006, "\x01\x02\x03", 3);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE(n == 6);
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(got + 1), 0x0006);
	ATF_CHECK_EQ(memcmp(got + 3, "\x01\x02\x03", 3), 0);

	srv_cleanup(&ac, peer);
}

/* Oversized notification value is clamped to the MTU (3.4.7.1). */
ATF_TC_WITHOUT_HEAD(test_se_notification_clamped);
ATF_TC_BODY(test_se_notification_clamped, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t big[200], got[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;	/* 23 */
	memset(big, 0x5A, sizeof(big));

	ret = att_send_notification(&ac, 0x0006, big, sizeof(big));
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	/*
	 * ATT_HANDLE_VALUE_NTF = opcode(1) | handle(2, LE) | value.  The value
	 * is capped at ATT_MTU-3 octets, so the whole PDU is exactly ATT_MTU
	 * (Core Spec Vol 3 Part F 3.4.7.1: "The Attribute Value ... shall be
	 * ... ATT_MTU-3 octets in length").
	 */
	ATF_REQUIRE_MSG(n == BT_CORE63_ATT_DEFAULT_MTU,
	    "notification must be clamped to the ATT_MTU (23)");
	ATF_CHECK_EQ_MSG(got[0], SEEDGE_ATT_OP_HANDLE_NOTIFY,
	    "clamped PDU is still a Handle Value Notification");
	ATF_CHECK_EQ_MSG(get_le16(got + 1), 0x0006, "notified handle preserved");
	ATF_CHECK_EQ_MSG(n - 3, BT_CORE63_ATT_DEFAULT_MTU - 3,
	    "notified value payload is exactly ATT_MTU-3 octets");
	for (int i = 3; i < n; i++)
		ATF_CHECK_EQ_MSG(got[i], 0x5A, "clamped value byte %d", i);

	srv_cleanup(&ac, peer);
}

/* Only one indication may be outstanding at a time (3.3.2). */
ATF_TC_WITHOUT_HEAD(test_se_indication_flow_control);
ATF_TC_BODY(test_se_indication_flow_control, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t got[ATT_PDU_BUF_SIZE];

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;

	ret = att_send_indication(&ac, 0x0006, "\xAA\xBB", 2);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(ac.ind_pending, "sending an indication sets ind_pending");
	ATF_REQUIRE(recv(peer, got, sizeof(got), MSG_DONTWAIT) == 5);
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_HANDLE_IND);

	/* A second indication while one is pending -> EBUSY, nothing sent. */
	ret = att_send_indication(&ac, 0x0006, "\xCC\xDD", 2);
	ATF_CHECK_EQ_MSG(ret, -1, "second concurrent indication must fail");
	ATF_CHECK_EQ(errno, EBUSY);
	ATF_CHECK(recv(peer, got, sizeof(got), MSG_DONTWAIT) < 0);

	srv_cleanup(&ac, peer);
}

/* Multiple Handle Value Notification (Core Spec Vol 3 Part F 3.4.7.5). */
ATF_TC_WITHOUT_HEAD(test_se_multi_notification);
ATF_TC_BODY(test_se_multi_notification, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t got[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t handles[2] = { 0x0006, 0x0009 };
	const uint8_t v0[2] = { 0x11, 0x22 };
	const uint8_t v1[3] = { 0x33, 0x44, 0x55 };
	const uint8_t *values[2] = { v0, v1 };
	uint16_t lengths[2] = { 2, 3 };

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;

	ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 2);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	/* opcode + [h,len,val]{4+2} + [h,len,val]{4+3} = 1 + 6 + 7 = 14 */
	ATF_REQUIRE(n == 14);
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);
	ATF_CHECK_EQ(get_le16(got + 1), 0x0006);
	ATF_CHECK_EQ(get_le16(got + 3), 2);
	ATF_CHECK_EQ(get_le16(got + 7), 0x0009);
	ATF_CHECK_EQ(get_le16(got + 9), 3);

	/* count <= 0 sends nothing and returns 0. */
	ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 0);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK(recv(peer, got, sizeof(got), MSG_DONTWAIT) < 0);

	srv_cleanup(&ac, peer);
}

/* First multi-notification entry too large to fit -> nothing sent. */
ATF_TC_WITHOUT_HEAD(test_se_multi_notification_too_big);
ATF_TC_BODY(test_se_multi_notification_too_big, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t big[600], got[8];
	uint16_t handles[1] = { 0x0006 };
	const uint8_t *values[1];
	uint16_t lengths[1];

	srv_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;	/* 23 */
	memset(big, 0, sizeof(big));
	values[0] = big;
	lengths[0] = 600;		/* 4 + 600 > 23 */

	ret = att_send_multiple_handle_value_ntf(&ac, handles, values,
	    lengths, 1);
	ATF_CHECK_EQ_MSG(ret, 0, "an unsendable first entry yields no PDU");
	ATF_CHECK(recv(peer, got, sizeof(got), MSG_DONTWAIT) < 0);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * L6 — Multiple Handle Value Notification is gated on Client Supported
 * Features bit 2 (Core Spec Vol 3 Part G 7.2 / Part F 3.4.7.5).
 *
 * A client that set CSF bit 2 (ac.multi_notify) receives a single coalesced
 * Multiple HVN; a client that did not must instead receive one Handle Value
 * Notification per handle — a Multiple HVN would violate the client's
 * declared capability.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_se_multi_notify_csf_gate);
ATF_TC_BODY(test_se_multi_notify_csf_gate, tc)
{
	struct att_conn ac;
	int peer, ret;
	uint8_t got[ATT_PDU_BUF_SIZE];
	ssize_t n;
	uint16_t handles[2] = { 0x0006, 0x0009 };
	const uint8_t v0[2] = { 0x11, 0x22 };
	const uint8_t v1[3] = { 0x33, 0x44, 0x55 };
	const uint8_t *values[2] = { v0, v1 };
	uint16_t lengths[2] = { 2, 3 };

	srv_pair(&ac, &peer);
	ac.mtu = ATT_PDU_BUF_SIZE;

	/* CSF bit 2 set -> a single coalesced Multiple HVN PDU. */
	ac.multi_notify = true;
	ret = att_notify_multi_gated(&ac, handles, values, lengths, 2);
	ATF_CHECK_EQ(ret, 0);
	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 14, "coalesced Multiple HVN is 14 bytes, got %zd",
	    n);
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF);
	ATF_CHECK_MSG(recv(peer, got, sizeof(got), MSG_DONTWAIT) < 0,
	    "exactly one PDU when coalesced");

	/* CSF bit 2 clear -> one Handle Value Notification per handle. */
	ac.multi_notify = false;
	ret = att_notify_multi_gated(&ac, handles, values, lengths, 2);
	ATF_CHECK_EQ(ret, 0);

	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "first individual HVN = op+handle+2 bytes");
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(got + 1), 0x0006);

	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 6, "second individual HVN = op+handle+3 bytes");
	ATF_CHECK_EQ(got[0], SEEDGE_ATT_OP_HANDLE_NOTIFY);
	ATF_CHECK_EQ(get_le16(got + 1), 0x0009);

	ATF_CHECK_MSG(recv(peer, got, sizeof(got), MSG_DONTWAIT) < 0,
	    "no Multiple HVN when CSF bit 2 is clear");

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_se_notify_guard_completion);
ATF_TC_BODY(test_se_notify_guard_completion, tc)
{
	struct att_conn ac;
	uint16_t handles[2] = { 1, 2 }, lengths[2] = { 1, 1 };
	uint8_t byte = 1;
	const uint8_t *values[2] = { &byte, &byte };
	int peer;
	uint8_t got[ATT_PDU_BUF_SIZE];
	ssize_t n;

	ATF_CHECK_EQ(-1, att_send_notification(NULL, 1, &byte, 1));
	ATF_CHECK_EQ(-1, att_send_indication(NULL, 1, &byte, 1));
	ATF_CHECK_EQ(-1, att_send_multiple_handle_value_ntf(NULL, handles,
	    values, lengths, 2));
	ATF_CHECK_EQ(-1, att_notify_multi_gated(NULL, handles, values, lengths,
	    2));

	srv_pair(&ac, &peer);
	ac.mtu = 2;
	ATF_CHECK_EQ(-1, att_send_notification(&ac, 1, &byte, 1));
	ATF_CHECK_EQ(EMSGSIZE, errno);
	ATF_CHECK_EQ(-1, att_send_indication(&ac, 1, &byte, 1));
	ATF_CHECK_EQ(EMSGSIZE, errno);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;
	ATF_CHECK_EQ(-1, att_send_notification(&ac, 1, NULL, 1));
	ATF_CHECK_EQ(-1, att_send_indication(&ac, 1, NULL, 1));
	ATF_CHECK_EQ(0, att_send_notification(&ac, 1, NULL, 0));
	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(SEEDGE_ATT_OP_HANDLE_NOTIFY, got[0]);
	ATF_CHECK_EQ(0, att_send_indication(&ac, 1, NULL, 0));
	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(3, n);
	ATF_CHECK_EQ(SEEDGE_ATT_OP_HANDLE_IND, got[0]);
	ac.ind_pending = false;
	ATF_CHECK_EQ(-1, att_send_multiple_handle_value_ntf(&ac, NULL, values,
	    lengths, 2));
	values[0] = NULL;
	ATF_CHECK_EQ(-1, att_send_multiple_handle_value_ntf(&ac, handles,
	    values, lengths, 2));
	lengths[0] = 0;
	ATF_CHECK_EQ(0, att_send_multiple_handle_value_ntf(&ac, handles,
	    values, lengths, 2));
	n = recv(peer, got, sizeof(got), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(10, n);
	ATF_CHECK_EQ(SEEDGE_ATT_OP_MULTIPLE_HANDLE_VALUE_NTF, got[0]);
	lengths[0] = 1;
	values[0] = &byte;
	ATF_CHECK_EQ(-1, att_notify_multi_gated(&ac, NULL, values, lengths, 2));
	ATF_CHECK_EQ(-1, att_notify_multi_gated(&ac, handles, NULL, lengths, 2));
	ATF_CHECK_EQ(-1, att_notify_multi_gated(&ac, handles, values, NULL, 2));
	ATF_CHECK_EQ(0, att_notify_multi_gated(&ac, handles, values, lengths, 0));

	/* Individual fallback reports failure if any constituent send fails. */
	close(peer);
	ATF_CHECK_EQ(-1, att_notify_multi_gated(&ac, handles, values, lengths,
	    2));
	srv_cleanup(&ac, -1);
}

/* ================================================================
 * Database construction helpers (att_server.c)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_se_attdb_construction);
ATF_TC_BODY(test_se_attdb_construction, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint16_t svc, inc, desc, svc128, chr128;
	struct att_attr *a;
	static const uint8_t uuid128[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);

	svc = attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	ATF_CHECK_EQ(svc, 0x0001);

	/* Include with an inline 16-bit UUID -> 6-byte value (3.2). */
	inc = attdb_add_include(&db, svc, 0x0020, 0x0025, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	ATF_REQUIRE(inc != 0);
	a = attdb_find_by_handle(&db, inc);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(a->uuid16, BT_ASSIGNED_UUID_INCLUDE);
	ATF_CHECK_EQ_MSG(a->value_len, 6, "inline-UUID include value is 6 bytes");
	ATF_CHECK_EQ(get_le16(a->value), 0x0020);
	ATF_CHECK_EQ(get_le16(a->value + 4), BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);

	/* Include WITHOUT an inline UUID -> 4-byte value. */
	inc = attdb_add_include(&db, svc, 0x0030, 0x0035, 0x0000);
	a = attdb_find_by_handle(&db, inc);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ_MSG(a->value_len, 4, "no-UUID include value is 4 bytes");

	/* Descriptor (e.g. Characteristic User Description, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION). */
	desc = attdb_add_descriptor(&db, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION, ATT_PERM_READ, "hi", 2);
	a = attdb_find_by_handle(&db, desc);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(a->uuid16, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION);
	ATF_CHECK_EQ(a->value_len, 2);

	/* 128-bit service and characteristic declarations. */
	svc128 = attdb_add_service128(&db, uuid128);
	a = attdb_find_by_handle(&db, svc128);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ(a->uuid16, BT_ASSIGNED_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ_MSG(a->value_len, 16, "128-bit service value is the UUID");

	chr128 = attdb_add_characteristic128(&db, uuid128,
	    SEEDGE_GATT_PROP_READ, ATT_PERM_READ, "\x01\x02", 2);
	a = attdb_find_by_handle(&db, chr128);
	ATF_REQUIRE(a != NULL);
	ATF_CHECK_EQ_MSG(a->uuid16, 0, "128-bit char value has no 16-bit UUID");
	ATF_CHECK_EQ(memcmp(a->uuid128, uuid128, 16), 0);
	ATF_CHECK(a->is_char_value);

	srv_cleanup_nofd(&db);
}

/* attdb_remove_service and its rejection paths. */
ATF_TC_WITHOUT_HEAD(test_se_attdb_remove_service);
ATF_TC_BODY(test_se_attdb_remove_service, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint16_t s1, s2;
	int rc;

	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	s1 = attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_DEVICE_NAME, SEEDGE_GATT_PROP_READ, ATT_PERM_READ,
	    "ab", 2);
	s2 = attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	attdb_add_characteristic(&db, BT_ASSIGNED_UUID_SERVICE_CHANGED, SEEDGE_GATT_PROP_INDICATE,
	    ATT_PERM_READ, "cd", 2);

	/* Removing a non-service handle is rejected. */
	rc = attdb_remove_service(&db, s1 + 1);	/* a characteristic decl */
	ATF_CHECK_EQ_MSG(rc, -1, "only a service handle may be removed");

	/* Removing an unknown handle is rejected. */
	rc = attdb_remove_service(&db, 0xF000);
	ATF_CHECK_EQ(rc, -1);

	/* Removing the first service drops it and its characteristic. */
	rc = attdb_remove_service(&db, s1);
	ATF_CHECK_EQ(rc, 0);
	ATF_CHECK_MSG(attdb_find_by_handle(&db, s1) == NULL,
	    "removed service handle must be gone");
	ATF_CHECK_MSG(attdb_find_by_handle(&db, s2) != NULL,
	    "the second service must remain");

	/* Removing the last remaining service resets the handle counter. */
	rc = attdb_remove_service(&db, s2);
	ATF_CHECK_EQ(rc, 0);
	ATF_CHECK_EQ_MSG(db.count, 0, "database must be empty");

	srv_cleanup_nofd(&db);
}

/* Value-store exhaustion: attdb_add_* fails gracefully (returns 0). */
ATF_TC_WITHOUT_HEAD(test_se_attdb_val_exhaustion);
ATF_TC_BODY(test_se_attdb_val_exhaustion, tc)
{
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[8];			/* tiny value store */
	uint16_t h;

	/* Only 8 bytes of value storage. */
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, sizeof(val));

	h = attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);	/* consumes 2 bytes */
	ATF_CHECK(h != 0);

	/* A characteristic needs 5 (decl) + value bytes; storage runs out. */
	h = attdb_add_characteristic(&db, BT_ASSIGNED_UUID_DEVICE_NAME, SEEDGE_GATT_PROP_READ,
	    ATT_PERM_READ, "abcdefgh", 8);
	ATF_CHECK_EQ_MSG(h, 0, "characteristic add must fail when value store "
	    "is exhausted");

	srv_cleanup_nofd(&db);
}

/* ================================================================
 * Database Hash — verified against Core Spec Vol 3 Part G Appendix B
 * (Table B.1) which publishes both the example database and its hash.
 * ================================================================ */

/*
 * Append one attribute directly to the database, mirroring exactly the
 * fields att_server_hash.c consumes (handle, 16-bit type, is_char_value,
 * value bytes).  Used to reproduce the Appendix B database byte-for-byte.
 */
static void
hb_add(struct att_db *db, uint16_t handle, uint16_t uuid16,
    bool is_char_value, const uint8_t *value, uint16_t len)
{
	struct att_attr *a = &db->attrs[db->count++];

	memset(a, 0, sizeof(*a));
	a->handle = handle;
	a->uuid16 = uuid16;
	a->is_char_value = is_char_value;
	a->owner_fd = -1;
	if (len > 0) {
		a->value = db->val_store + db->val_used;
		memcpy(a->value, value, len);
		a->value_len = len;
		db->val_used += len;
	}
}

/* Append a 128-bit-typed attribute (uuid16 == 0). */
static void
hb_add128(struct att_db *db, uint16_t handle, const uint8_t uuid128[16],
    bool is_char_value, const uint8_t *value, uint16_t len)
{
	struct att_attr *a = &db->attrs[db->count++];

	memset(a, 0, sizeof(*a));
	a->handle = handle;
	a->uuid16 = 0;
	memcpy(a->uuid128, uuid128, 16);
	a->is_char_value = is_char_value;
	a->owner_fd = -1;
	if (len > 0) {
		a->value = db->val_store + db->val_used;
		memcpy(a->value, value, len);
		a->value_len = len;
		db->val_used += len;
	}
}

ATF_TC_WITHOUT_HEAD(test_se_hash_appendix_b);
ATF_TC_BODY(test_se_hash_appendix_b, tc)
{
	struct att_db db;
	struct att_attr attrs[32];
	uint8_t vbuf[512];
	uint8_t hash[16];
	/*
	 * Core Spec Vol 3 Part G Appendix B, Table B.1: the example database
	 * and its published Database Hash:
	 *   AES-CMAC(k=0, m) = F1 CA 2D 48 EC F5 8B AC 8A 88 30 BB B9 FB A9 90
	 * (most-significant octet first).  attdb_compute_db_hash returns the
	 * raw AES-CMAC output in that same most-significant-first order.
	 */
	static const uint8_t expect[16] = {
		BT_CORE63_GATT_DATABASE_HASH_KAT_BYTES
	};

	attdb_init(&db, attrs, 32, vbuf, sizeof(vbuf));

	/* 0x0001 Primary Service (GAP), value BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE. */
	hb_add(&db, 0x0001, BT_ASSIGNED_UUID_PRIMARY_SERVICE, false, (const uint8_t[]){0x00,0x18}, 2);
	/* 0x0002 Characteristic (Read,Write) Device Name: {0x0A,0x0003,BT_ASSIGNED_UUID_DEVICE_NAME} */
	hb_add(&db, 0x0002, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x0A,0x03,0x00,0x00,0x2A}, 5);
	/* 0x0003 Characteristic Value Device Name (excluded from hash). */
	hb_add(&db, 0x0003, BT_ASSIGNED_UUID_DEVICE_NAME, true, (const uint8_t[]){0xDE,0xAD}, 2);
	/* 0x0004 Characteristic (Read) Appearance: {0x02,0x0005,BT_ASSIGNED_UUID_APPEARANCE} */
	hb_add(&db, 0x0004, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x02,0x05,0x00,0x01,0x2A}, 5);
	/* 0x0005 Characteristic Value Appearance (excluded). */
	hb_add(&db, 0x0005, BT_ASSIGNED_UUID_APPEARANCE, true, (const uint8_t[]){0x00,0x00}, 2);
	/* 0x0006 Primary Service (GATT), value BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE. */
	hb_add(&db, 0x0006, BT_ASSIGNED_UUID_PRIMARY_SERVICE, false, (const uint8_t[]){0x01,0x18}, 2);
	/* 0x0007 Characteristic (Indicate) Service Changed: {0x20,0x0008,BT_ASSIGNED_UUID_SERVICE_CHANGED} */
	hb_add(&db, 0x0007, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x20,0x08,0x00,0x05,0x2A}, 5);
	/* 0x0008 Characteristic Value Service Changed (excluded). */
	hb_add(&db, 0x0008, BT_ASSIGNED_UUID_SERVICE_CHANGED, true, (const uint8_t[]){0x00,0x00}, 2);
	/* 0x0009 CCCD, value 0x0002 (type included, VALUE excluded -> HT). */
	hb_add(&db, 0x0009, BT_ASSIGNED_UUID_CCCD, false, (const uint8_t[]){0x02,0x00}, 2);
	/* 0x000A Characteristic (Read,Write) Client Supported Features. */
	hb_add(&db, 0x000A, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x0A,0x0B,0x00,0x29,0x2B}, 5);
	/* 0x000B Characteristic Value Client Supported Features (excluded). */
	hb_add(&db, 0x000B, BT_ASSIGNED_UUID_CLIENT_SUPPORTED_FEATURES, true, (const uint8_t[]){0x00}, 1);
	/* 0x000C Characteristic (Read) Database Hash: {0x02,0x000D,BT_ASSIGNED_UUID_DATABASE_HASH} */
	hb_add(&db, 0x000C, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x02,0x0D,0x00,0x2A,0x2B}, 5);
	/* 0x000D Characteristic Value Database Hash (excluded). */
	hb_add(&db, 0x000D, BT_ASSIGNED_UUID_DATABASE_HASH, true, (const uint8_t[]){0x00}, 1);
	/* 0x000E Primary Service (Glucose), value BT_ASSIGNED_UUID_GLUCOSE_SERVICE. */
	hb_add(&db, 0x000E, BT_ASSIGNED_UUID_PRIMARY_SERVICE, false, (const uint8_t[]){0x08,0x18}, 2);
	/* 0x000F Included Service (Battery): {0x0014,0x0016,BT_ASSIGNED_UUID_BATTERY_SERVICE} */
	hb_add(&db, 0x000F, BT_ASSIGNED_UUID_INCLUDE, false,
	    (const uint8_t[]){0x14,0x00,0x16,0x00,0x0F,0x18}, 6);
	/* 0x0010 Characteristic (Read,Indicate,ExtProps) Glucose Measurement. */
	hb_add(&db, 0x0010, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0xA2,0x11,0x00,0x18,0x2A}, 5);
	/* 0x0011 Characteristic Value Glucose Measurement (excluded). */
	hb_add(&db, 0x0011, BT_ASSIGNED_UUID_GLUCOSE_MEASUREMENT, true, (const uint8_t[]){0x00}, 1);
	/* 0x0012 CCCD, value 0x0002 (HT). */
	hb_add(&db, 0x0012, BT_ASSIGNED_UUID_CCCD, false, (const uint8_t[]){0x02,0x00}, 2);
	/* 0x0013 Characteristic Extended Properties, value 0x0000 (HTV). */
	hb_add(&db, 0x0013, BT_ASSIGNED_UUID_CHARACTERISTIC_EXTENDED_PROPERTIES, false, (const uint8_t[]){0x00,0x00}, 2);
	/* 0x0014 Secondary Service (Battery), value BT_ASSIGNED_UUID_BATTERY_SERVICE. */
	hb_add(&db, 0x0014, BT_ASSIGNED_UUID_SECONDARY_SERVICE, false, (const uint8_t[]){0x0F,0x18}, 2);
	/* 0x0015 Characteristic (Read) Battery Level: {0x02,0x0016,BT_ASSIGNED_UUID_BATTERY_LEVEL} */
	hb_add(&db, 0x0015, BT_ASSIGNED_UUID_CHARACTERISTIC, false,
	    (const uint8_t[]){0x02,0x16,0x00,0x19,0x2A}, 5);
	/* 0x0016 Characteristic Value Battery Level (excluded). */
	hb_add(&db, 0x0016, BT_ASSIGNED_UUID_BATTERY_LEVEL, true, (const uint8_t[]){0x00}, 1);

	attdb_compute_db_hash(&db, hash);

	ATF_CHECK_EQ_MSG(memcmp(hash, expect, 16), 0,
	    "Database Hash must equal the Core Spec Appendix B example");
}

/*
 * Hash structural / invariant coverage: the 128-bit-typed hashable-UUID
 * detection (Bluetooth Base UUID match and non-match) and the exclusion
 * rules from Core Spec Vol 3 Part G 7.3.1.
 */
ATF_TC_WITHOUT_HEAD(test_se_hash_invariants);
ATF_TC_BODY(test_se_hash_invariants, tc)
{
	struct att_db db;
	struct att_attr attrs[8];
	uint8_t vbuf[128];
	uint8_t h_base[16], h_again[16], h_charval[16], h_nonhash[16];
	/* Bluetooth Base UUID (LSB-first wire order): the 16-bit short form
	 * occupies bytes [12..13]; [0..11] and [14..15] identify the base. */
	uint8_t u_primary[16], u_cccd[16], u_random[16], u_nonhash[16];

	memcpy(u_primary, seedge_base_uuid_le, 12);
	u_primary[12] = 0x00; u_primary[13] = 0x28;	/* BT_ASSIGNED_UUID_PRIMARY_SERVICE */
	u_primary[14] = 0x00; u_primary[15] = 0x00;

	memcpy(u_cccd, seedge_base_uuid_le, 12);
	u_cccd[12] = 0x02; u_cccd[13] = 0x29;		/* BT_ASSIGNED_UUID_CCCD (HT only) */
	u_cccd[14] = 0x00; u_cccd[15] = 0x00;

	/* Not a Bluetooth Base UUID at all -> excluded (non-match path). */
	memset(u_random, 0xAB, 16);

	/* Base UUID but a non-hashable short form (0x1234) -> excluded. */
	memcpy(u_nonhash, seedge_base_uuid_le, 12);
	u_nonhash[12] = 0x34; u_nonhash[13] = 0x12;
	u_nonhash[14] = 0x00; u_nonhash[15] = 0x00;

	/* Baseline DB: a 128-bit-typed primary service + a 128-bit CCCD. */
	attdb_init(&db, attrs, 8, vbuf, sizeof(vbuf));
	hb_add128(&db, 0x0001, u_primary, false,
	    (const uint8_t[]){0x00,0x18}, 2);
	hb_add128(&db, 0x0002, u_cccd, false, (const uint8_t[]){0x02,0x00}, 2);
	attdb_compute_db_hash(&db, h_base);

	/* Determinism: same database -> identical hash. */
	attdb_compute_db_hash(&db, h_again);
	ATF_CHECK_EQ_MSG(memcmp(h_base, h_again, 16), 0,
	    "the Database Hash must be deterministic");

	/*
	 * Adding a Characteristic Value attribute (is_char_value) and a
	 * non-hashable 128-bit-typed attribute must NOT change the hash:
	 * both are excluded (Core Spec Vol 3 Part G 7.3.1).
	 */
	attdb_init(&db, attrs, 8, vbuf, sizeof(vbuf));
	hb_add128(&db, 0x0001, u_primary, false,
	    (const uint8_t[]){0x00,0x18}, 2);
	hb_add128(&db, 0x0002, u_cccd, false, (const uint8_t[]){0x02,0x00}, 2);
	hb_add(&db, 0x0003, BT_ASSIGNED_UUID_DEVICE_NAME, true, (const uint8_t[]){0xFF,0xEE}, 2);
	hb_add128(&db, 0x0004, u_random, false, (const uint8_t[]){0x99}, 1);
	hb_add128(&db, 0x0005, u_nonhash, false, (const uint8_t[]){0x77}, 1);
	attdb_compute_db_hash(&db, h_charval);
	ATF_CHECK_EQ_MSG(memcmp(h_base, h_charval, 16), 0,
	    "excluded attributes must not affect the Database Hash");

	/*
	 * Changing the CCCD *value* must NOT change the hash (its value is
	 * excluded — HT only), confirming the include_value == 0 path.
	 */
	attdb_init(&db, attrs, 8, vbuf, sizeof(vbuf));
	hb_add128(&db, 0x0001, u_primary, false,
	    (const uint8_t[]){0x00,0x18}, 2);
	hb_add128(&db, 0x0002, u_cccd, false, (const uint8_t[]){0x01,0x00}, 2);
	attdb_compute_db_hash(&db, h_nonhash);
	ATF_CHECK_EQ_MSG(memcmp(h_base, h_nonhash, 16), 0,
	    "a CCCD value change must not affect the hash (value excluded)");

	srv_cleanup_nofd(&db);
}

/* Empty database: the hash is AES-CMAC over an empty message. */
ATF_TC_WITHOUT_HEAD(test_se_hash_empty_db);
ATF_TC_BODY(test_se_hash_empty_db, tc)
{
	struct att_db db;
	struct att_attr attrs[4];
	uint8_t vbuf[16];
	uint8_t hash[16];
	/*
	 * AES-128-CMAC with an all-zero key over a zero-length message is a
	 * fixed cryptographic constant, verifiable by any reference AES-CMAC
	 * implementation (e.g. `openssl mac -macopt cipher:AES-128-CBC
	 * -macopt hexkey:00..00 CMAC` over empty input):
	 *   43 87 C1 4B 46 EF 7E 17 6D CE EF A8 62 D7 2F F9
	 * in most-significant-octet-first order, matching the hash function's
	 * raw AES-CMAC output order.
	 */
	static const uint8_t expect[16] = {
		BT_RFC4493_ZERO_KEY_EMPTY_MESSAGE_CMAC_BYTES
	};

	attdb_init(&db, attrs, 4, vbuf, sizeof(vbuf));
	attdb_compute_db_hash(&db, hash);

	ATF_CHECK_EQ_MSG(memcmp(hash, expect, 16), 0,
	    "empty-database hash must equal AES-CMAC(0, empty message)");
}

/*
 * K-low: a Write Request to a CCCD (BT_ASSIGNED_UUID_CCCD) with a value length other than 2
 * must be rejected with Invalid Attribute Value Length (0x0D).  A CCCD is
 * exactly two octets (Core Spec Vol 3 Part G §3.3.3.3); a 0- or 1-octet write
 * would otherwise slip past the two-octet CCCD path into the generic write
 * branch, corrupting the stored CCCD length and bypassing the notify/indicate
 * permission checks.
 */
ATF_TC_WITHOUT_HEAD(test_se_cccd_write_bad_length);
ATF_TC_BODY(test_se_cccd_write_bad_length, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint16_t cccd_h;
	uint8_t pdu[6];

	srv_pair(&ac, &peer);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	attdb_add_characteristic(&db, 0xFFE1,
	    SEEDGE_GATT_PROP_READ | SEEDGE_GATT_PROP_NOTIFY, ATT_PERM_READ, "\x00", 1);
	cccd_h = attdb_add_cccd(&db);

	/* vlen 1 -> Invalid Attribute Value Length (0x0D). */
	pdu[0] = SEEDGE_ATT_OP_WRITE_REQ;
	put_le16(pdu + 1, cccd_h);
	pdu[3] = 0x01;
	expect_err(&ac, &db, peer, pdu, 4, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_INVALID_ATTR_LEN);

	/* vlen 0 -> Invalid Attribute Value Length (0x0D). */
	expect_err(&ac, &db, peer, pdu, 3, SEEDGE_ATT_OP_WRITE_REQ,
	    SEEDGE_ATT_ERR_INVALID_ATTR_LEN);

	/* Control: a proper 2-octet CCCD write (Notify) succeeds. */
	put_le16(pdu + 3, BT_CORE63_GATT_CCCD_NOTIFICATIONS_ENABLED);
	expect_rsp_op(&ac, &db, peer, pdu, 5, SEEDGE_ATT_OP_WRITE_RSP);

	srv_cleanup(&ac, peer);
}

/*
 * K-low: a bearer advertising a sub-23 MTU must be clamped up to the minimum
 * ATT MTU (23), otherwise responses are malformed/undersized (Core Spec Vol 3
 * Part F §3.2.9).  Read a 20-octet value over a bearer whose MTU is 5: without
 * the clamp the response would be truncated to mtu-1 = 4 value octets; with the
 * clamp (mtu == 23) all 20 octets fit.
 */
ATF_TC_WITHOUT_HEAD(test_se_bearer_mtu_lower_clamp);
ATF_TC_BODY(test_se_bearer_mtu_lower_clamp, tc)
{
	struct att_conn ac;
	int peer;
	int bfd[2];
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint16_t vh;
	uint8_t pdu[3], rsp[64];
	ssize_t n;

	srv_pair(&ac, &peer);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, bfd) == 0);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	vh = attdb_add_characteristic(&db, 0xFFE1, SEEDGE_GATT_PROP_READ, ATT_PERM_READ,
	    "01234567890123456789", 20);

	pdu[0] = SEEDGE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, vh);
	/* Dispatch on a bearer whose advertised MTU (5) is below the minimum. */
	att_server_handle(&ac, &db, pdu, 3, bfd[0], 5);
	n = recv(bfd[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n >= 1, "expected a read response, got %zd", n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_READ_RSP);
	ATF_CHECK_EQ_MSG(n, 1 + 20,
	    "sub-23 bearer MTU must be clamped to 23, not truncate the value");

	close(bfd[0]);
	close(bfd[1]);
	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_se_primary_mtu_lower_clamp);
ATF_TC_BODY(test_se_primary_mtu_lower_clamp, tc)
{
	struct att_conn ac;
	int peer;
	struct att_db db;
	struct att_attr attrs[TEST_DB_MAX_ATTRS];
	uint8_t val[TEST_DB_VAL_SIZE];
	uint16_t vh;
	uint8_t pdu[3], rsp[64];
	ssize_t n;

	srv_pair(&ac, &peer);
	attdb_init(&db, attrs, TEST_DB_MAX_ATTRS, val, TEST_DB_VAL_SIZE);
	attdb_add_service(&db, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	vh = attdb_add_characteristic(&db, 0xFFE1, SEEDGE_GATT_PROP_READ,
	    ATT_PERM_READ, "01234567890123456789", 20);

	ac.mtu = 0;
	pdu[0] = SEEDGE_ATT_OP_READ_REQ;
	put_le16(pdu + 1, vh);
	n = srv_xchg(&ac, &db, peer, pdu, sizeof(pdu), rsp, sizeof(rsp));
	ATF_REQUIRE_MSG(n >= 1, "expected a read response, got %zd", n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_READ_RSP);
	ATF_CHECK_EQ_MSG(n, 1 + 20,
	    "primary ATT MTU below 23 must be clamped before response sizing");
	ATF_CHECK_EQ(ac.mtu, BT_CORE63_ATT_DEFAULT_MTU);

	srv_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(test_se_deferred_read_null_value_rejected);
ATF_TC_BODY(test_se_deferred_read_null_value_rejected, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t rsp[ATT_PDU_BUF_SIZE];
	ssize_t n;

	srv_pair(&ac, &peer);
	ac.mtu = BT_CORE63_ATT_DEFAULT_MTU;
	ac.pending.kind = ATT_PEND_READ;
	ac.pending.req_op = SEEDGE_ATT_OP_READ_REQ;
	ac.pending.handle = H_RO;
	ac.pending.bearer_fd = -1;
	ac.pending.bearer_mtu = ac.mtu;

	ATF_CHECK_EQ(0, att_server_complete_read(&ac, NULL, 1));
	ATF_CHECK(!att_server_pending_active(&ac));

	n = recv(peer, rsp, sizeof(rsp), MSG_DONTWAIT);
	ATF_REQUIRE_MSG(n == 5, "expected ATT Error Response, got %zd", n);
	ATF_CHECK_EQ(rsp[0], SEEDGE_ATT_OP_ERROR_RSP);
	ATF_CHECK_EQ(rsp[1], SEEDGE_ATT_OP_READ_REQ);
	ATF_CHECK_EQ(get_le16(rsp + 2), H_RO);
	ATF_CHECK_EQ(rsp[4], SEEDGE_ATT_ERR_UNLIKELY_ERROR);

	srv_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Permission gating */
	ATF_TP_ADD_TC(tp, test_se_read_not_permitted);
	ATF_TP_ADD_TC(tp, test_se_read_encryption_gate);
	ATF_TP_ADD_TC(tp, test_se_read_authen_gate);
	ATF_TP_ADD_TC(tp, test_se_write_permission_gates);
	ATF_TP_ADD_TC(tp, test_se_read_by_type_perm_first);
	ATF_TP_ADD_TC(tp, test_se_read_by_type_uuid32);
	ATF_TP_ADD_TC(tp, test_se_read_multiple_errors);
	ATF_TP_ADD_TC(tp, test_se_read_multiple_variable);

	/* CCCD validation */
	ATF_TP_ADD_TC(tp, test_se_cccd_indicate_not_allowed);
	ATF_TP_ADD_TC(tp, test_se_cccd_orphan);
	ATF_TP_ADD_TC(tp, test_se_cccd_write_bad_length);

	/* Bearer MTU clamping */
	ATF_TP_ADD_TC(tp, test_se_bearer_mtu_lower_clamp);
	ATF_TP_ADD_TC(tp, test_se_primary_mtu_lower_clamp);
	ATF_TP_ADD_TC(tp, test_se_deferred_read_null_value_rejected);

	/* Prepare / Execute Write */
	ATF_TP_ADD_TC(tp, test_se_prepare_offset_overflow);
	ATF_TP_ADD_TC(tp, test_se_prepare_value_too_long);
	ATF_TP_ADD_TC(tp, test_se_prepare_byte_budget);
	ATF_TP_ADD_TC(tp, test_se_execute_commit_applies);
	ATF_TP_ADD_TC(tp, test_se_execute_commit_bad_offset);
	ATF_TP_ADD_TC(tp, test_se_execute_commit_bad_len);

	/* Robust caching */
	ATF_TP_ADD_TC(tp, test_se_robust_allowed_ops);
	ATF_TP_ADD_TC(tp, test_se_robust_partial_range_blocked);
	ATF_TP_ADD_TC(tp, test_se_robust_enable_via_csf);

	/* EATT dispatch */
	ATF_TP_ADD_TC(tp, test_se_mtu_req_on_eatt);
	ATF_TP_ADD_TC(tp, test_se_eatt_bearer_carries_pdu);

	/* Notifications / indications */
	ATF_TP_ADD_TC(tp, test_se_notification_pdu);
	ATF_TP_ADD_TC(tp, test_se_notification_clamped);
	ATF_TP_ADD_TC(tp, test_se_indication_flow_control);
	ATF_TP_ADD_TC(tp, test_se_multi_notification);
	ATF_TP_ADD_TC(tp, test_se_multi_notify_csf_gate);
	ATF_TP_ADD_TC(tp, test_se_multi_notification_too_big);
	ATF_TP_ADD_TC(tp, test_se_notify_guard_completion);

	/* Database construction */
	ATF_TP_ADD_TC(tp, test_se_attdb_construction);
	ATF_TP_ADD_TC(tp, test_se_attdb_remove_service);
	ATF_TP_ADD_TC(tp, test_se_attdb_val_exhaustion);

	/* Database hash */
	ATF_TP_ADD_TC(tp, test_se_hash_appendix_b);
	ATF_TP_ADD_TC(tp, test_se_hash_invariants);
	ATF_TP_ADD_TC(tp, test_se_hash_empty_db);

	return (atf_no_error());
}
