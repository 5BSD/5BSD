/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the GATT client discovery parsers in gatt.c.
 *
 * When blued acts as a central talking to an untrusted peripheral, the
 * peer's ATT responses drive service / characteristic / descriptor
 * discovery.  These tests feed crafted ATT response PDUs through a
 * SOCK_SEQPACKET socketpair (standing in for the L2CAP ATT channel) and
 * exercise the discovery routines directly.
 *
 * Socketpair mechanics follow fuzz/fuzz_gatt_client.c: the daemon-side fd
 * is O_NONBLOCK, so once the single preloaded response datagram is consumed
 * the next recv() returns EAGAIN and the discovery routine unwinds.  This
 * makes every test single-shot and deterministic with no fork and no hang.
 *
 * Positive cases assert parsed handles / UUIDs / counts from valid
 * multi-entry responses.  Negative cases feed malformed responses
 * (zero-length entries, entry lengths larger than the payload, UUID length
 * mismatches, non-advancing handle ranges, ATT Error Responses) and assert
 * the parser reports the correct count, never hangs, and never over-reads.
 *
 * Reference: Core Spec Vol 3 Part F (ATT), Part G (GATT discovery).
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

#include "spec_att_client_oracles.h"
#include "test_common.h"

/* Test-fixture encoder; expected wire bytes do not use production helpers. */
static void
gc_put_le16(uint8_t *p, uint16_t value)
{

	p[0] = (uint8_t)value;
	p[1] = (uint8_t)(value >> 8);
}

/* ================================================================
 * Mock helper: att_conn on a nonblocking socketpair, preloaded with
 * a single crafted ATT response datagram.
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
	ac->mtu = BT_CORE63_ATT_MAX_MTU;	/* Core Vol 3 Part F §3.2.9 */
	ac->buf = malloc(BT_CORE63_ATT_MAX_MTU);
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

/* Preload one response datagram to be delivered to the daemon-side fd. */
static void
gc_preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, 0) == (ssize_t)len);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.4.1; Part F §3.4.4.10:
 * primary service discovery, multi-entry response.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_primary_services_multi);
ATF_TC_BODY(test_gc_primary_services_multi, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/*
	 * Read By Group Type Response, entry_len = 6, three services.
	 * Passing maxsvcs == 3 terminates discovery after this one
	 * datagram (no second request is issued).
	 */
	uint8_t rsp[1 + 1 + 3 * BT_CORE63_ATT_GROUP16_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_GROUP16_ENTRY_SIZE;
	gc_put_le16(rsp + 2, 0x0001); gc_put_le16(rsp + 4, 0x0005);
	gc_put_le16(rsp + 6, BT_ASSIGNED_UUID_GAP_SERVICE);
	gc_put_le16(rsp + 8, 0x0006); gc_put_le16(rsp + 10, 0x0009);
	gc_put_le16(rsp + 12, 0xFFE0);
	gc_put_le16(rsp + 14, 0x000A); gc_put_le16(rsp + 16, 0x000F);
	gc_put_le16(rsp + 18, BT_ASSIGNED_UUID_BATTERY_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_primary_services(&ac, svcs, 3, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 3);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0001);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0005);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GAP_SERVICE);
	ATF_CHECK_EQ(svcs[1].start_handle, 0x0006);
	ATF_CHECK_EQ(svcs[1].uuid16, 0xFFE0);
	ATF_CHECK_EQ(svcs[2].start_handle, 0x000A);
	ATF_CHECK_EQ(svcs[2].uuid16, BT_ASSIGNED_UUID_BATTERY_SERVICE);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.6.1; Part F §3.4.4.1:
 * characteristic discovery, multi-entry response.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_characteristics_multi);
ATF_TC_BODY(test_gc_characteristics_multi, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Read By Type Response, entry_len = 7, two characteristics. */
	uint8_t rsp[1 + 1 + 2 * BT_CORE63_ATT_CHAR16_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_CHAR16_ENTRY_SIZE;
	gc_put_le16(rsp + 2, 0x0002); rsp[4] = BT_CORE63_GATT_PROP_READ;
	gc_put_le16(rsp + 5, 0x0003);
	gc_put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_put_le16(rsp + 9, 0x0005);
	rsp[11] = BT_CORE63_GATT_PROP_READ | BT_CORE63_GATT_PROP_WRITE | BT_CORE63_GATT_PROP_NOTIFY;
	gc_put_le16(rsp + 12, 0x0006); gc_put_le16(rsp + 14, 0xFFE1);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_characteristics(&ac, 0x0001, 0xFFFF, chars, 2, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 2);
	ATF_CHECK_EQ(chars[0].decl_handle, 0x0002);
	ATF_CHECK_EQ(chars[0].properties, BT_CORE63_GATT_PROP_READ);
	ATF_CHECK_EQ(chars[0].value_handle, 0x0003);
	ATF_CHECK_EQ(chars[0].uuid16, BT_ASSIGNED_UUID_DEVICE_NAME);
	ATF_CHECK_EQ(chars[1].decl_handle, 0x0005);
	ATF_CHECK_EQ(chars[1].value_handle, 0x0006);
	ATF_CHECK_EQ(chars[1].uuid16, 0xFFE1);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.7.1; Part F §3.4.3.1:
 * descriptor discovery, Find Information format 1 (16-bit).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_descriptors_multi);
ATF_TC_BODY(test_gc_descriptors_multi, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Find Information Response, format 1, two descriptors. */
	uint8_t rsp[1 + 1 +
	    2 * BT_CORE63_ATT_FIND_INFO_UUID16_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_FIND_INFO_RSP;
	rsp[1] = BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16;
	gc_put_le16(rsp + 2, 0x0007);
	gc_put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	gc_put_le16(rsp + 6, 0x0008);
	gc_put_le16(rsp + 8, BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESC);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_descriptors(&ac, 0x0001, 0xFFFF, descs, 2, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 2);
	ATF_CHECK_EQ(descs[0].handle, 0x0007);
	ATF_CHECK_EQ(descs[0].uuid16, BT_ASSIGNED_UUID_CCCD);
	ATF_CHECK_EQ(descs[1].handle, 0x0008);
	ATF_CHECK_EQ(descs[1].uuid16,
	    BT_ASSIGNED_UUID_CHARACTERISTIC_USER_DESC);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.7.1; Part F §3.4.3.1: descriptor discovery
 * whose last descriptor sits exactly on
 * the requested end handle.  new_start = end + 1 does not wrap and does
 * not fall back on start, so the loop is not broken by the advance
 * guard; instead the next `start <= end` test fails and the while loop
 * terminates naturally.  Drives the loop-condition-false exit arm of
 * gatt_discover_descriptors() (the non-0xFFFF end boundary), which the
 * end=0xFFFF descriptor tests never reach.
 * Oracle: Core Spec Vol 3 Part G Sec 4.7.1 — discovery over [start,end]
 * stops once the handle range is exhausted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_descriptors_end_boundary);
ATF_TC_BODY(test_gc_descriptors_end_boundary, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[4];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/*
	 * One descriptor at handle 0x0007 == end.  After storing it,
	 * new_start becomes 0x0008 (> end), so the while (start <= end)
	 * guard, not the advance guard, ends the loop.
	 */
	uint8_t rsp[1 + 1 + 4];
	rsp[0] = BT_CORE63_ATT_OP_FIND_INFO_RSP;
	rsp[1] = BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16;
	gc_put_le16(rsp + 2, 0x0007);
	gc_put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_descriptors(&ac, 0x0001, 0x0007, descs, 4, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(descs[0].handle, 0x0007);
	ATF_CHECK_EQ(descs[0].uuid16, BT_ASSIGNED_UUID_CCCD);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.7.1; Part F §3.4.3.1:
 * descriptor discovery, Find Information format 2 (128-bit).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_descriptors_128bit);
ATF_TC_BODY(test_gc_descriptors_128bit, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[4];
	int n = -1;
	int ret;
	static const uint8_t uuid128[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	};

	gc_pair(&ac, &peer);

	/* Find Information Response, format 2, one 128-bit descriptor. */
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_FIND_INFO_UUID128_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_FIND_INFO_RSP;
	rsp[1] = BT_CORE63_ATT_FIND_INFO_FORMAT_UUID128;
	gc_put_le16(rsp + 2, 0x0009);
	memcpy(rsp + 4, uuid128, 16);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_descriptors(&ac, 0x0001, 0xFFFF, descs, 1, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(descs[0].handle, 0x0009);
	ATF_CHECK_EQ(descs[0].uuid16, 0);
	ATF_CHECK_EQ(memcmp(descs[0].uuid128, uuid128, 16), 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.5.1; Part F §3.4.4.1:
 * include discovery with inline 16-bit UUID (entry length 8).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_includes_inline_uuid);
ATF_TC_BODY(test_gc_includes_inline_uuid, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Read By Type Response, entry_len = 8 (inline 16-bit UUID). */
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE;
	gc_put_le16(rsp + 2, 0x0004);	/* include declaration handle */
	gc_put_le16(rsp + 4, 0x0020);	/* included service start */
	gc_put_le16(rsp + 6, 0x0025);	/* included service end */
	gc_put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_includes(&ac, 0x0001, 0xFFFF, incs, 1, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0004);
	ATF_CHECK_EQ(incs[0].start_handle, 0x0020);
	ATF_CHECK_EQ(incs[0].end_handle, 0x0025);
	ATF_CHECK_EQ(incs[0].uuid16, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	ATF_CHECK(incs[0].has_uuid);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.4.2; Part F §3.4.3.3:
 * primary service by UUID (Find By Type Value), multi-entry.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_primary_by_uuid);
ATF_TC_BODY(test_gc_primary_by_uuid, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Find By Type Value Response: two [handle, group_end] pairs. */
	uint8_t rsp[1 + 2 * 4];
	rsp[0] = BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	gc_put_le16(rsp + 1, 0x0004); gc_put_le16(rsp + 3, 0x0007);
	gc_put_le16(rsp + 5, 0x0010); gc_put_le16(rsp + 7, 0x0015);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_primary_service_by_uuid(&ac, 0xFFE0, svcs, 2, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 2);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	ATF_CHECK_EQ(svcs[0].uuid16, 0xFFE0);
	ATF_CHECK_EQ(svcs[1].start_handle, 0x0010);
	ATF_CHECK_EQ(svcs[1].end_handle, 0x0015);
	ATF_CHECK_EQ(svcs[1].uuid16, 0xFFE0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §§2.5.2.1, 4.6.1, 7.3.1; Part F §3.4.4.1:
 * read the 16-octet Database Hash characteristic by type.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_read_database_hash);
ATF_TC_BODY(test_gc_read_database_hash, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[BT_CORE63_ATT_DB_HASH_SIZE];
	int ret;
	static const uint8_t expected[BT_CORE63_ATT_DB_HASH_SIZE] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};

	gc_pair(&ac, &peer);

	/* Read By Type Response: attr_data_len=18, [handle(2) + hash(16)] */
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_DB_HASH_ENTRY_SIZE];
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_DB_HASH_ENTRY_SIZE;
	gc_put_le16(rsp + 2, 0x0010);
	memcpy(rsp + 4, expected, BT_CORE63_ATT_DB_HASH_SIZE);
	gc_preload(peer, rsp, sizeof(rsp));

	memset(hash, 0, sizeof(hash));
	ret = gatt_read_database_hash(&ac, hash);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(memcmp(hash, expected, 16), 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §7.3.1; Part F §3.4.4.1: reject a Database Hash
 * entry whose Attribute Data length is not handle(2) + hash(16).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_read_database_hash_bad_len);
ATF_TC_BODY(test_gc_read_database_hash_bad_len, tc)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[BT_CORE63_ATT_DB_HASH_SIZE];
	int ret;

	gc_pair(&ac, &peer);

	/* attr_data_len advertised as 10, not the required 18. */
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_DB_HASH_ENTRY_SIZE];
	memset(rsp, 0, sizeof(rsp));
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_DB_HASH_ENTRY_SIZE - 8;
	gc_preload(peer, rsp, sizeof(rsp));

	memset(hash, 0xFF, sizeof(hash));
	ret = gatt_read_database_hash(&ac, hash);

	ATF_CHECK(ret != 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part F §3.4.4.10: reject a Read By Group Type Response
 * whose Attribute Data Length is zero.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_entry_len_zero);
ATF_TC_BODY(test_gc_entry_len_zero, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Read By Group Type Response with a zero attr_data_len. */
	uint8_t rsp[2] = { BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP, 0x00 };
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_primary_services(&ac, svcs, 8, &n);

	ATF_CHECK(ret != 0);
	ATF_CHECK_EQ(n, 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part F §3.4.4.1: reject a Read By Type Response whose
 * declared entry length exceeds the received payload.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_entry_len_overflow);
ATF_TC_BODY(test_gc_entry_len_overflow, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/*
	 * Read By Type Response claiming entry_len=7 but carrying only
	 * 3 bytes of entry data.  The parser must not read past the buffer.
	 */
	uint8_t rsp[1 + 1 + 3] = {
		BT_CORE63_ATT_OP_READ_BY_TYPE_RSP, 7, 0x02, 0x00, 0x03
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_characteristics(&ac, 0x0001, 0xFFFF, chars, 8, &n);

	ATF_CHECK(ret != 0);
	ATF_CHECK_EQ(n, 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part F §3.4.4.10; Part G §4.4.1: reject a primary-service
 * group whose end handle precedes its start handle.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_non_advancing);
ATF_TC_BODY(test_gc_non_advancing, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/*
	 * Single service whose end_handle (0x0000) does not advance past
	 * the current start (0x0001).  The loop guard must stop after this
	 * datagram rather than issuing another request (which would spin
	 * or, on this nonblocking socket, fail).  We assert it terminated
	 * cleanly with the one parsed entry.
	 */
	uint8_t rsp[1 + 1 + 6];
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_GROUP16_ENTRY_SIZE;
	gc_put_le16(rsp + 2, 0x0001);	/* start */
	gc_put_le16(rsp + 4, 0x0000);	/* end (non-advancing) */
	gc_put_le16(rsp + 6, 0x1800);
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_primary_services(&ac, svcs, 8, &n);

	ATF_CHECK(ret != 0);
	ATF_CHECK_EQ(n, 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part F §3.4.3.1: reject Find Information format 2 when
 * its payload cannot contain one handle plus 128-bit UUID entry.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_uuid_len_mismatch);
ATF_TC_BODY(test_gc_uuid_len_mismatch, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/*
	 * Find Information Response with format 2 (128-bit, 18-byte entries)
	 * but only a 16-bit-sized (4-byte) payload.  The parser must not
	 * consume an 18-byte entry from a 4-byte buffer.
	 */
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_FIND_INFO_UUID16_ENTRY_SIZE] = {
		BT_CORE63_ATT_OP_FIND_INFO_RSP,
		BT_CORE63_ATT_FIND_INFO_FORMAT_UUID128,
		0x07, 0x00, 0x02, 0x29
	};
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_descriptors(&ac, 0x0001, 0xFFFF, descs, 8, &n);

	ATF_CHECK(ret != 0);
	ATF_CHECK_EQ(n, 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part F §§3.4.1.1 and 3.4.4.1: Invalid Handle Error
 * Response is a discovery failure, not normal range exhaustion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_error_response);
ATF_TC_BODY(test_gc_error_response, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Error Response with INVALID_HANDLE -> discovery fails. */
	uint8_t rsp[5];
	rsp[0] = BT_CORE63_ATT_OP_ERROR_RSP;
	rsp[1] = BT_CORE63_ATT_OP_READ_BY_TYPE_REQ;
	gc_put_le16(rsp + 2, 0x0001);
	rsp[4] = BT_CORE63_ATT_ERR_INVALID_HANDLE;
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_characteristics(&ac, 0x0001, 0xFFFF, chars, 8, &n);

	ATF_CHECK_MSG(ret != 0, "expected non-zero return on ATT error");

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * Core 6.3 Vol 3 Part G §4.4.1; Part F §§3.4.1.1 and 3.4.4.10:
 * Attribute Not Found terminates primary-service discovery with no entries.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_gc_attr_not_found);
ATF_TC_BODY(test_gc_attr_not_found, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[8];
	int n = -1;
	int ret;

	gc_pair(&ac, &peer);

	/* Error Response with ATTR_NOT_FOUND == normal end of discovery. */
	uint8_t rsp[5];
	rsp[0] = BT_CORE63_ATT_OP_ERROR_RSP;
	rsp[1] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_REQ;
	gc_put_le16(rsp + 2, 0x0001);
	rsp[4] = BT_CORE63_ATT_ERR_ATTRIBUTE_NOT_FOUND;
	gc_preload(peer, rsp, sizeof(rsp));

	ret = gatt_discover_primary_services(&ac, svcs, 8, &n);

	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_EQ(n, 0);

	gc_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Positive discovery */
	ATF_TP_ADD_TC(tp, test_gc_primary_services_multi);
	ATF_TP_ADD_TC(tp, test_gc_characteristics_multi);
	ATF_TP_ADD_TC(tp, test_gc_descriptors_multi);
	ATF_TP_ADD_TC(tp, test_gc_descriptors_end_boundary);
	ATF_TP_ADD_TC(tp, test_gc_descriptors_128bit);
	ATF_TP_ADD_TC(tp, test_gc_includes_inline_uuid);
	ATF_TP_ADD_TC(tp, test_gc_primary_by_uuid);
	ATF_TP_ADD_TC(tp, test_gc_read_database_hash);

	/* Negative / robustness */
	ATF_TP_ADD_TC(tp, test_gc_read_database_hash_bad_len);
	ATF_TP_ADD_TC(tp, test_gc_entry_len_zero);
	ATF_TP_ADD_TC(tp, test_gc_entry_len_overflow);
	ATF_TP_ADD_TC(tp, test_gc_non_advancing);
	ATF_TP_ADD_TC(tp, test_gc_uuid_len_mismatch);
	ATF_TP_ADD_TC(tp, test_gc_error_response);
	ATF_TP_ADD_TC(tp, test_gc_attr_not_found);

	return (atf_no_error());
}
