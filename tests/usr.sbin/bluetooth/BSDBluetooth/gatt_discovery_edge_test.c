/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case tests for the GATT client discovery parsers in gatt.c.
 *
 * gatt_client_test.c covers the happy paths and a handful of malformed
 * responses.  This file targets the branches those tests leave uncovered:
 *
 *   - 32-bit UUID entries (entry_len 8 / 9) that either collapse to a
 *     16-bit UUID (high half zero) or expand against the Bluetooth Base
 *     UUID (high half non-zero) -- Core Spec Vol 3 Part B Sec 2.5.1.
 *   - 128-bit UUID entries (entry_len 20 / 21, Find Info format 2).
 *   - ATT Error Responses (non ATTR_NOT_FOUND) surfaced by every
 *     discover_* variant -- Core Spec Vol 3 Part F Sec 3.4.1.1.
 *   - count==0 termination when a well-formed header advertises an
 *     entry_len larger than the remaining payload.
 *   - non-advancing / wrapping handle ranges that must break the loop.
 *   - the by-uuid128 and include (128-bit) variants, plus the FreeBSD
 *     secondary-service scan extension (Core Part G §3.1 defines no
 *     standard procedure for discovering secondary services),
 *     plus database-hash short-buffer and error paths.
 *
 * Mechanics mirror gatt_client_test.c: a nonblocking SOCK_SEQPACKET
 * socketpair preloaded with one crafted ATT response datagram; once it is
 * consumed the daemon-side recv() returns EAGAIN and discovery unwinds, so
 * every case is single-shot, fork-free and hang-free.
 *
 * Oracle: Core Spec Vol 3 Part F (ATT PDUs) and Part G (GATT discovery
 * procedures).  Expected values are derived from the spec PDU layouts, not
 * captured from the implementation.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "gatt.h"
#include "hci_log.h"
#include "hci_util.h"
#include "spec_oracles.h"

#include "test_common.h"

#define GCEDGE_ENUM(name, value) GCEDGE_##name = value,
enum {
	BT_CORE63_ATT_ORACLES(GCEDGE_ENUM)
	BT_CORE63_ATT_ERROR_ORACLES(GCEDGE_ENUM)
	BT_CORE63_GATT_PROPERTY_ORACLES(GCEDGE_ENUM)
};
#undef GCEDGE_ENUM

static const uint8_t gcedge_base_uuid_le[12] =
    BT_CORE63_BLUETOOTH_BASE_UUID_LE12;

enum {
	GCEDGE_HANDLE_MIN = 0x0001,
	GCEDGE_HANDLE_MAX = 0xffff,
	/* Local buffer-sized fixture; not a normative ATT_MTU maximum claim. */
	GCEDGE_LOCAL_TEST_MTU = 517,
	/* Non-assigned local UUID used only to distinguish a second fixture. */
	GCEDGE_FIXTURE_SERVICE_B = 0x180b,
};

/*
 * Every other explicit handle in this file is a scripted local database
 * position.  The Core-derived oracle is its validity, ordering, width, or
 * advancement behavior—not the arbitrary fixture number itself.
 */

/* ================================================================
 * Mock helper: att_conn on a nonblocking socketpair.
 * ================================================================ */
static void
gc_pair(struct att_conn *ac, int *peer_fd)
{
	int fds[2];

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	memset(ac, 0, sizeof(*ac));
	ac->fd = fds[0];
	ac->bearer_fd = -1;
	ac->mtu = GCEDGE_LOCAL_TEST_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	ATF_REQUIRE(ac->buf != NULL);
	*peer_fd = fds[1];
}

static void
gc_cleanup(struct att_conn *ac, int peer_fd)
{

	free(ac->buf);
	ac->buf = NULL;
	if (ac->fd >= 0)
		close(ac->fd);
	if (peer_fd >= 0)
		close(peer_fd);
}

static void
gc_preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, 0) == (ssize_t)len);
}

/* Build an ATT Error Response datagram for req_op with err code. */
static size_t
gc_error_rsp(uint8_t *rsp, uint8_t req_op, uint16_t handle, uint8_t err)
{

	rsp[0] = GCEDGE_ATT_OP_ERROR_RSP;
	rsp[1] = req_op;
	put_le16(rsp + 2, handle);
	rsp[4] = err;
	return (5);
}

/* The Bluetooth Base UUID low 96 bits, LE, as gatt.c expands 32-bit UUIDs. */
static void
check_base_expanded(const uint8_t uuid128[16], const uint8_t tail4[4])
{

	ATF_CHECK_EQ(memcmp(uuid128, gcedge_base_uuid_le,
	    sizeof(gcedge_base_uuid_le)), 0);
	ATF_CHECK_EQ(memcmp(uuid128 + 12, tail4, 4), 0);
}

/* ================================================================
 * database hash: ATT error path (att_read_by_type returns non-zero)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_dbhash_error);
ATF_TC_BODY(edge_dbhash_error, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[16];
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	/* READ_NOT_PERMITTED is not ATTR_NOT_FOUND -> surfaced as failure. */
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_READ_BY_TYPE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_READ_NOT_PERMITTED));

	ATF_CHECK(gatt_read_database_hash(&ac, hash) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * database hash: short response (len < 19) -> failure
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_dbhash_short);
ATF_TC_BODY(edge_dbhash_short, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[16];

	gc_pair(&ac, &peer);
	/* attr_data_len=18 but only a handle follows: total payload < 19. */
	uint8_t rsp[1 + 1 + 2] = { GCEDGE_ATT_OP_READ_BY_TYPE_RSP, 18, 0x10, 0x00 };
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_read_database_hash(&ac, hash) != 0);
	gc_cleanup(&ac, peer);
}

/* Database Hash must resolve to one real attribute, not handle zero/list tail. */
ATF_TC_WITHOUT_HEAD(edge_dbhash_invalid_list);
ATF_TC_BODY(edge_dbhash_invalid_list, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[16];
	uint8_t rsp[1 + 1 + 2 * 18];

	gc_pair(&ac, &peer);
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 18;
	/* One otherwise well-framed entry with the prohibited handle 0x0000. */
	gc_preload(peer, rsp, 20);
	ATF_CHECK(gatt_read_database_hash(&ac, hash) != 0);
	gc_cleanup(&ac, peer);

	gc_pair(&ac, &peer);
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 18;
	put_le16(rsp + 2, 1);
	put_le16(rsp + 20, 2);
	gc_preload(peer, rsp, sizeof(rsp));
	ATF_CHECK(gatt_read_database_hash(&ac, hash) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: 32-bit UUID that collapses to 16-bit (high half 0)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_uuid32_collapse);
ATF_TC_BODY(edge_primary_uuid32_collapse, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* Read By Group Type Rsp, entry_len 8 (32-bit UUID 0x0000180F). */
	uint8_t rsp[1 + 1 + 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x0005);
	rsp[6] = 0x0F; rsp[7] = 0x18; rsp[8] = 0x00; rsp[9] = 0x00;
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: 32-bit UUID with non-zero high half -> Base UUID expand
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_uuid32_expand);
ATF_TC_BODY(edge_primary_uuid32_expand, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	const uint8_t tail4[4] = { 0x78, 0x56, 0x34, 0x12 };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x0005);
	memcpy(rsp + 6, tail4, 4);	/* 0x12345678: high half non-zero */
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	check_base_expanded(svcs[0].uuid128, tail4);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: 128-bit UUID (entry_len 20)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_uuid128);
ATF_TC_BODY(edge_primary_uuid128, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = {
		0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	};

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 20];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 20;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x000A);
	memcpy(rsp + 6, u128, 16);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(svcs[0].uuid128, u128, 16), 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: invalid entry_len (10) -> inner else break, count 0
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_bad_entry_len);
ATF_TC_BODY(edge_primary_bad_entry_len, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 10 is neither 6/8/20; header ok so inner loop runs then
	 * hits the else->break for an unrecognised UUID length. */
	uint8_t rsp[1 + 1 + 10];
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 10;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x0005);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: header advertises entry_len > payload -> count 0 break
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_short_payload);
ATF_TC_BODY(edge_primary_short_payload, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 6 but only 3 bytes of entry data follow. */
	uint8_t rsp[1 + 1 + 3] = {
		GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP, 6, 0x01, 0x00, 0x05
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: max-count truncation (more entries than maxsvcs)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_maxcount);
ATF_TC_BODY(edge_primary_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* Two advancing services but maxsvcs == 1: only the first is stored. */
	uint8_t rsp[1 + 1 + 2 * 6];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0001); put_le16(rsp + 4, 0x0005);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ACCESS_SERVICE);
	put_le16(rsp + 8, 0x0006); put_le16(rsp + 10, 0x0009);
	put_le16(rsp + 12, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0001);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary services: ATT error (non ATTR_NOT_FOUND) -> failure return
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_primary_error);
ATF_TC_BODY(edge_primary_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_UNSUPPORTED_GROUP_TYPE));

	ATF_CHECK(gatt_discover_primary_services(&ac, svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_primary_explicit_range);
ATF_TC_BODY(edge_primary_explicit_range, tc)
{
	struct att_conn ac;
	struct gatt_service svc;
	uint8_t rsp[1 + 1 + 6];
	int peer, n = -1;

	gc_pair(&ac, &peer);
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0100);
	put_le16(rsp + 4, 0x010f);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(0, gatt_discover_primary_services_range(&ac, 0x0100,
	    0x01ff, &svc, 1, &n));
	ATF_CHECK_EQ(1, n);
	ATF_CHECK_EQ(0x0100, svc.start_handle);
	ATF_CHECK_EQ(0x010f, svc.end_handle);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid: truncated response (shorter than one 4-byte pair).
 * Per att.c the Find By Type Value Rsp must carry >= 1 handle pair, so a
 * short PDU is rejected with EPROTO and surfaces as a discovery failure.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid_truncated);
ATF_TC_BODY(edge_by_uuid_truncated, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* Find By Type Value Rsp with only 2 bytes (< one handle pair). */
	uint8_t rsp[1 + 2] = { GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP, 0x04, 0x00 };
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_service_by_uuid(&ac, BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid: max-count truncation -- more pairs than max_services.
 * Only max_services entries are stored (Core Spec Vol 3 Part G Sec 4.4.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid_maxcount);
ATF_TC_BODY(edge_by_uuid_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 2 * 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0004); put_le16(rsp + 3, 0x0007);
	put_le16(rsp + 5, 0x0010); put_le16(rsp + 7, 0x0015);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_service_by_uuid(&ac, BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid: non-advancing group end -> loop guard breaks
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid_non_advancing);
ATF_TC_BODY(edge_by_uuid_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* group_end 0x0000 does not advance past start 0x0001. */
	uint8_t rsp[1 + 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0001);
	put_le16(rsp + 3, 0x0000);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_service_by_uuid(&ac, BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid: ATT error -> failure return
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid_error);
ATF_TC_BODY(edge_by_uuid_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_INVALID_HANDLE));

	ATF_CHECK(gatt_discover_primary_service_by_uuid(&ac, BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid128: positive multi-entry
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid128_multi);
ATF_TC_BODY(edge_by_uuid128_multi, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = {
		0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80,
		0x00, 0x10, 0x00, 0x00, 0x0F, 0x18, 0x00, 0x00
	};

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 2 * 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0004);
	put_le16(rsp + 3, 0x0007);
	put_le16(rsp + 5, 0x0010);
	put_le16(rsp + 7, 0x0015);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 2, &n), 0);
	ATF_CHECK_EQ(n, 2);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(svcs[0].uuid128, u128, 16), 0);
	ATF_CHECK_EQ(svcs[1].start_handle, 0x0010);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * primary-by-uuid128: n==0 break, non-advancing, and error paths
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_by_uuid128_truncated);
ATF_TC_BODY(edge_by_uuid128_truncated, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = { 0 };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 3] = { GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP, 0x04, 0x00, 0x07 };
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_by_uuid128_maxcount);
ATF_TC_BODY(edge_by_uuid128_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = { 0 };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 2 * 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0004); put_le16(rsp + 3, 0x0007);
	put_le16(rsp + 5, 0x0010); put_le16(rsp + 7, 0x0015);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_by_uuid128_non_advancing);
ATF_TC_BODY(edge_by_uuid128_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = { 0 };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0001);
	put_le16(rsp + 3, 0x0000);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_by_uuid128_error);
ATF_TC_BODY(edge_by_uuid128_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = { 0 };
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_FIND_BY_TYPE_VALUE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_INVALID_HANDLE));

	ATF_CHECK(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * FreeBSD secondary-service scan extension: 16/32/128-bit UUID decoding.
 * Core 6.3 Vol 3 Part G §3.1 explicitly defines no discovery procedure for
 * secondary services; these cases are implementation-contract coverage.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_secondary_uuid16);
ATF_TC_BODY(edge_secondary_uuid16, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 6];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0010);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_uuid32_collapse);
ATF_TC_BODY(edge_secondary_uuid32_collapse, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	rsp[6] = 0x01; rsp[7] = 0x18; rsp[8] = 0x00; rsp[9] = 0x00;
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_uuid32_expand);
ATF_TC_BODY(edge_secondary_uuid32_expand, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	const uint8_t tail4[4] = { 0xEF, 0xBE, 0xAD, 0xDE };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	memcpy(rsp + 6, tail4, 4);	/* 0xDEADBEEF */
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	check_base_expanded(svcs[0].uuid128, tail4);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_uuid128);
ATF_TC_BODY(edge_secondary_uuid128, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	static const uint8_t u128[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
	};

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 20];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 20;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	memcpy(rsp + 6, u128, 16);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(svcs[0].uuid128, u128, 16), 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_maxcount);
ATF_TC_BODY(edge_secondary_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 2 * 6];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0010); put_le16(rsp + 4, 0x0015);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	put_le16(rsp + 8, 0x0016); put_le16(rsp + 10, 0x0019);
	put_le16(rsp + 12, BT_ASSIGNED_UUID_IMMEDIATE_ALERT_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	gc_cleanup(&ac, peer);
}

/* entry_len neither 6/8/20 (and >= 6) -> inner else break. */
ATF_TC_WITHOUT_HEAD(edge_secondary_bad_entry_len);
ATF_TC_BODY(edge_secondary_bad_entry_len, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 10];
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 10;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_secondary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_entry_len_small);
ATF_TC_BODY(edge_secondary_entry_len_small, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 4 (< 6) -> immediate break, count 0. */
	uint8_t rsp[1 + 1 + 4] = {
		GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP, 4, 0x01, 0x00, 0x05, 0x00
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_secondary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_short_payload);
ATF_TC_BODY(edge_secondary_short_payload, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 3] = {
		GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP, 6, 0x10, 0x00, 0x15
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_secondary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_non_advancing);
ATF_TC_BODY(edge_secondary_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 6];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x0000);	/* non-advancing end */
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GENERIC_ATTRIBUTE_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_secondary_services(&ac, svcs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_secondary_error);
ATF_TC_BODY(edge_secondary_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_READ_BY_GROUP_TYPE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_UNSUPPORTED_GROUP_TYPE));

	ATF_CHECK(gatt_discover_secondary_services(&ac, svcs, 8, &n) != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * includes: 128-bit include (entry_len 6) with follow-up read failing
 * -> has_uuid stays false (Core Spec Vol 3 Part G Sec 4.5.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_includes_128bit_unresolved);
ATF_TC_BODY(edge_includes_128bit_unresolved, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 6: no inline UUID.  Only this datagram is preloaded, so
	 * the follow-up att_read() gets EAGAIN and the UUID is unresolved. */
	uint8_t rsp[1 + 1 + 6];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 6;
	put_le16(rsp + 2, 0x0004);	/* include declaration handle */
	put_le16(rsp + 4, 0x0020);	/* included service start */
	put_le16(rsp + 6, 0x0025);	/* included service end */
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 1, &n),
	    0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0004);
	ATF_CHECK_EQ(incs[0].start_handle, 0x0020);
	ATF_CHECK_EQ(incs[0].end_handle, 0x0025);
	ATF_CHECK(!incs[0].has_uuid);
	gc_cleanup(&ac, peer);
}

/* entry_len neither 6 nor 8 (and >= 6) -> inner else break. */
ATF_TC_WITHOUT_HEAD(edge_includes_bad_entry_len);
ATF_TC_BODY(edge_includes_bad_entry_len, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 10];
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 10;
	put_le16(rsp + 2, 0x0004);
	put_le16(rsp + 4, 0x0020);
	put_le16(rsp + 6, 0x0025);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 8, &n)
	    != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* max-count truncation: more include declarations than max_includes. */
ATF_TC_WITHOUT_HEAD(edge_includes_maxcount);
ATF_TC_BODY(edge_includes_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 2 * 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0004); put_le16(rsp + 4, 0x0020);
	put_le16(rsp + 6, 0x0025); put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	put_le16(rsp + 10, 0x0005); put_le16(rsp + 12, 0x0030);
	put_le16(rsp + 14, 0x0035); put_le16(rsp + 16, GCEDGE_FIXTURE_SERVICE_B);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 1, &n),
	    0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0004);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_includes_entry_len_small);
ATF_TC_BODY(edge_includes_entry_len_small, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 4 (< 6) -> break. */
	uint8_t rsp[1 + 1 + 4] = {
		GCEDGE_ATT_OP_READ_BY_TYPE_RSP, 4, 0x04, 0x00, 0x20, 0x00
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 8, &n)
	    != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_includes_short_payload);
ATF_TC_BODY(edge_includes_short_payload, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 8 but only 5 bytes of payload -> count 0 break. */
	uint8_t rsp[1 + 1 + 5] = {
		GCEDGE_ATT_OP_READ_BY_TYPE_RSP, 8, 0x04, 0x00, 0x20, 0x00, 0x25
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 8, &n)
	    != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_includes_non_advancing);
ATF_TC_BODY(edge_includes_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;

	gc_pair(&ac, &peer);
	/* Include declaration handle 0x0000 does not advance past start. */
	uint8_t rsp[1 + 1 + 8];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 8;
	put_le16(rsp + 2, 0x0000);	/* include handle -> non-advancing */
	put_le16(rsp + 4, 0x0020);
	put_le16(rsp + 6, 0x0025);
	put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 8, &n)
	    != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_includes_error);
ATF_TC_BODY(edge_includes_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_READ_BY_TYPE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_INVALID_HANDLE));

	ATF_CHECK(gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 8, &n)
	    != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * characteristics: 32-bit UUID collapse / expand, 128-bit, small entry_len
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_chars_uuid32_collapse);
ATF_TC_BODY(edge_chars_uuid32_collapse, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 9: decl(2)+prop(1)+val(2)+uuid32(4). */
	uint8_t rsp[1 + 1 + 9];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 9;
	put_le16(rsp + 2, 0x0002);
	rsp[4] = GCEDGE_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003);
	rsp[7] = 0x00; rsp[8] = 0x2A; rsp[9] = 0x00; rsp[10] = 0x00;
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(chars[0].uuid16, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_uuid32_expand);
ATF_TC_BODY(edge_chars_uuid32_expand, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	const uint8_t tail4[4] = { 0x01, 0x00, 0x00, 0x01 };

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 9];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 9;
	put_le16(rsp + 2, 0x0002);
	rsp[4] = GCEDGE_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003);
	memcpy(rsp + 7, tail4, 4);	/* 0x01000001: high half non-zero */
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(chars[0].uuid16, 0);
	check_base_expanded(chars[0].uuid128, tail4);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_uuid128);
ATF_TC_BODY(edge_chars_uuid128, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	static const uint8_t u128[16] = {
		0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
		0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
	};

	gc_pair(&ac, &peer);
	/* entry_len 21: decl(2)+prop(1)+val(2)+uuid128(16). */
	uint8_t rsp[1 + 1 + 21];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 21;
	put_le16(rsp + 2, 0x0002);
	rsp[4] = GCEDGE_GATT_PROP_NOTIFY;
	put_le16(rsp + 5, 0x0003);
	memcpy(rsp + 7, u128, 16);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(chars[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(chars[0].uuid128, u128, 16), 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_entry_len_small);
ATF_TC_BODY(edge_chars_entry_len_small, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 5 (< 7) -> break. */
	uint8_t rsp[1 + 1 + 5] = {
		GCEDGE_ATT_OP_READ_BY_TYPE_RSP, 5, 0x02, 0x00, 0x02, 0x03, 0x00
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_bad_entry_len);
ATF_TC_BODY(edge_chars_bad_entry_len, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* entry_len 11 is neither 7/9/21 -> inner else break. */
	uint8_t rsp[1 + 1 + 11];
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 11;
	put_le16(rsp + 2, 0x0002);
	rsp[4] = GCEDGE_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_maxcount);
ATF_TC_BODY(edge_chars_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;

	gc_pair(&ac, &peer);
	uint8_t rsp[1 + 1 + 2 * 7];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 7;
	put_le16(rsp + 2, 0x0002); rsp[4] = GCEDGE_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003); put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
	put_le16(rsp + 9, 0x0005); rsp[11] = GCEDGE_GATT_PROP_NOTIFY;
	put_le16(rsp + 12, 0x0006); put_le16(rsp + 14, BT_ASSIGNED_UUID_APPEARANCE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(chars[0].decl_handle, 0x0002);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_chars_non_advancing);
ATF_TC_BODY(edge_chars_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* decl_handle 0x0000 -> new_start does not advance past start. */
	uint8_t rsp[1 + 1 + 7];
	rsp[0] = GCEDGE_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 7;
	put_le16(rsp + 2, 0x0000);
	rsp[4] = GCEDGE_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003);
	put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* Only Attribute Not Found terminates successfully; other ATT errors escape. */
ATF_TC_WITHOUT_HEAD(edge_chars_error);
ATF_TC_BODY(edge_chars_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_READ_BY_TYPE_REQ, 0x0001,
	    GCEDGE_ATT_ERR_INVALID_HANDLE));

	ATF_CHECK(gatt_discover_characteristics(&ac, 0x0001, 0xFFFF,
	    chars, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * descriptors: invalid format, non-advancing, error path
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_descs_bad_format);
ATF_TC_BODY(edge_descs_bad_format, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* format 3 is neither 1 nor 2 -> break. */
	uint8_t rsp[1 + 1 + 4] = {
		GCEDGE_ATT_OP_FIND_INFO_RSP, 3, 0x07, 0x00, 0x02, 0x29
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_descriptors(&ac, 0x0001, 0xFFFF,
	    descs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_descs_non_advancing);
ATF_TC_BODY(edge_descs_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* handle 0x0000 -> new_start does not advance past start 0x0001. */
	uint8_t rsp[1 + 1 + 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_INFO_RSP;
	rsp[1] = 1;
	put_le16(rsp + 2, 0x0000);
	put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_descriptors(&ac, 0x0001, 0xFFFF,
	    descs, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_descs_maxcount);
ATF_TC_BODY(edge_descs_maxcount, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;

	gc_pair(&ac, &peer);
	/* Two format-1 descriptors, maxdescs == 1: only the first is stored. */
	uint8_t rsp[1 + 1 + 2 * 4];
	rsp[0] = GCEDGE_ATT_OP_FIND_INFO_RSP;
	rsp[1] = 1;
	put_le16(rsp + 2, 0x0007); put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	put_le16(rsp + 6, 0x0008); put_le16(rsp + 8, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESCRIPTION);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_descriptors(&ac, 0x0001, 0xFFFF,
	    descs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(descs[0].handle, 0x0007);
	gc_cleanup(&ac, peer);
}

ATF_TC_WITHOUT_HEAD(edge_descs_error);
ATF_TC_BODY(edge_descs_error, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;
	uint8_t rsp[5];

	gc_pair(&ac, &peer);
	gc_preload(peer, rsp,
	    gc_error_rsp(rsp, GCEDGE_ATT_OP_FIND_INFO_REQ, 0x0001,
	    GCEDGE_ATT_ERR_INVALID_HANDLE));

	ATF_CHECK(gatt_discover_descriptors(&ac, 0x0001, 0xFFFF, descs, 8, &n)
	    != 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, edge_dbhash_error);
	ATF_TP_ADD_TC(tp, edge_dbhash_short);
	ATF_TP_ADD_TC(tp, edge_dbhash_invalid_list);

	ATF_TP_ADD_TC(tp, edge_primary_uuid32_collapse);
	ATF_TP_ADD_TC(tp, edge_primary_uuid32_expand);
	ATF_TP_ADD_TC(tp, edge_primary_uuid128);
	ATF_TP_ADD_TC(tp, edge_primary_bad_entry_len);
	ATF_TP_ADD_TC(tp, edge_primary_short_payload);
	ATF_TP_ADD_TC(tp, edge_primary_maxcount);
	ATF_TP_ADD_TC(tp, edge_primary_error);
	ATF_TP_ADD_TC(tp, edge_primary_explicit_range);

	ATF_TP_ADD_TC(tp, edge_by_uuid_truncated);
	ATF_TP_ADD_TC(tp, edge_by_uuid_maxcount);
	ATF_TP_ADD_TC(tp, edge_by_uuid_non_advancing);
	ATF_TP_ADD_TC(tp, edge_by_uuid_error);

	ATF_TP_ADD_TC(tp, edge_by_uuid128_multi);
	ATF_TP_ADD_TC(tp, edge_by_uuid128_truncated);
	ATF_TP_ADD_TC(tp, edge_by_uuid128_maxcount);
	ATF_TP_ADD_TC(tp, edge_by_uuid128_non_advancing);
	ATF_TP_ADD_TC(tp, edge_by_uuid128_error);

	ATF_TP_ADD_TC(tp, edge_secondary_uuid16);
	ATF_TP_ADD_TC(tp, edge_secondary_uuid32_collapse);
	ATF_TP_ADD_TC(tp, edge_secondary_uuid32_expand);
	ATF_TP_ADD_TC(tp, edge_secondary_uuid128);
	ATF_TP_ADD_TC(tp, edge_secondary_maxcount);
	ATF_TP_ADD_TC(tp, edge_secondary_bad_entry_len);
	ATF_TP_ADD_TC(tp, edge_secondary_entry_len_small);
	ATF_TP_ADD_TC(tp, edge_secondary_short_payload);
	ATF_TP_ADD_TC(tp, edge_secondary_non_advancing);
	ATF_TP_ADD_TC(tp, edge_secondary_error);

	ATF_TP_ADD_TC(tp, edge_includes_128bit_unresolved);
	ATF_TP_ADD_TC(tp, edge_includes_bad_entry_len);
	ATF_TP_ADD_TC(tp, edge_includes_maxcount);
	ATF_TP_ADD_TC(tp, edge_includes_entry_len_small);
	ATF_TP_ADD_TC(tp, edge_includes_short_payload);
	ATF_TP_ADD_TC(tp, edge_includes_non_advancing);
	ATF_TP_ADD_TC(tp, edge_includes_error);

	ATF_TP_ADD_TC(tp, edge_chars_uuid32_collapse);
	ATF_TP_ADD_TC(tp, edge_chars_uuid32_expand);
	ATF_TP_ADD_TC(tp, edge_chars_uuid128);
	ATF_TP_ADD_TC(tp, edge_chars_entry_len_small);
	ATF_TP_ADD_TC(tp, edge_chars_bad_entry_len);
	ATF_TP_ADD_TC(tp, edge_chars_maxcount);
	ATF_TP_ADD_TC(tp, edge_chars_non_advancing);
	ATF_TP_ADD_TC(tp, edge_chars_error);

	ATF_TP_ADD_TC(tp, edge_descs_bad_format);
	ATF_TP_ADD_TC(tp, edge_descs_maxcount);
	ATF_TP_ADD_TC(tp, edge_descs_non_advancing);
	ATF_TP_ADD_TC(tp, edge_descs_error);

	return (atf_no_error());
}
