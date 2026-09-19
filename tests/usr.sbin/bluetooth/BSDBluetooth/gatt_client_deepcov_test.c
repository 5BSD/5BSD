/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep branch-coverage tests for the GATT client discovery parsers in
 * gatt.c.  gatt_client_test.c and gatt_discovery_edge_test.c already
 * exercise the malformed-response and UUID-length matrix; this file closes
 * the remaining UNIT-REACHABLE branches those two leave uncovered:
 *
 *   1. The verbose-logging path in every routine.  Each gatt_discover_*
 *      and gatt_read_database_hash ends in a LOG_GATT(1, ...) call which
 *      expands (ble_util.h _BLUED_LOG) to
 *          if (blued_verbose >= lvl) {
 *              if (blued_daemonized) syslog(...); else fprintf(...);
 *          }
 *      With the default blued_verbose == 0 only the outer False arm is
 *      taken, leaving three arms per call uncovered (verbose True, and
 *      both daemonized arms).  Driving each routine to its trailing log
 *      with blued_verbose == 1 under both blued_daemonized == 0 (stderr)
 *      and blued_daemonized == 1 (syslog) covers all three.
 *
 *   2. The outer while-guard False arm of the two range-bounded routines
 *      gatt_discover_includes (start <= end_handle) and
 *      gatt_discover_characteristics (start <= end).  A response whose
 *      last handle sits at the top of the caller's range advances `start`
 *      past `end`, so the loop re-evaluates its guard and exits through
 *      the range check rather than the att-layer end-of-discovery.  The
 *      unbounded 0xFFFF routines cannot take this arm (start is uint16_t
 *      so start <= 0xFFFF is a tautology -- see the report for that dead
 *      branch); only the parameter-bounded routines can.
 *
 *   3. The rdlen != 16 arm of gatt_discover_includes' 128-bit resolution
 *      read: a 128-bit include (entry_len 6) whose follow-up ATT Read
 *      Request succeeds (ret == 0) but returns a value whose length is
 *      not the 16 bytes of a service UUID.  Per Core Spec Vol 3 Part G
 *      Sec 4.5.1 the UUID stays unresolved (has_uuid == false).
 *
 * Mechanics mirror gatt_client_test.c: a nonblocking SOCK_SEQPACKET
 * socketpair preloaded with crafted ATT response datagram(s) via MSG_EOR
 * (which preserves record boundaries on this platform, so a multi-PDU
 * lockstep exchange -- Read By Type Response then Read Response -- is
 * delivered one datagram per recv()).  Once the preloaded datagrams are
 * consumed the daemon-side recv() returns EAGAIN and discovery unwinds,
 * so every case is single-shot, fork-free and hang-free.
 *
 * Oracle: Core Spec Vol 3 Part F (ATT PDUs) and Part G (GATT discovery).
 * Expected values are derived from the spec PDU layouts, never captured
 * from the implementation.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
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

static void
assert_gatt_client_wire_contract(void)
{

	ATF_CHECK_EQ(ATT_OP_FIND_INFO_RSP, BT_CORE63_ATT_OP_FIND_INFO_RSP);
	ATF_CHECK_EQ(ATT_OP_FIND_BY_TYPE_VALUE_RSP,
	    BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP);
	ATF_CHECK_EQ(ATT_OP_READ_BY_TYPE_RSP,
	    BT_CORE63_ATT_OP_READ_BY_TYPE_RSP);
	ATF_CHECK_EQ(ATT_OP_READ_RSP, BT_CORE63_ATT_OP_READ_RSP);
	ATF_CHECK_EQ(ATT_OP_READ_BY_GROUP_TYPE_RSP,
	    BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP);
	ATF_CHECK_EQ(GATT_UUID_PRIMARY_SERVICE,
	    BT_ASSIGNED_UUID_PRIMARY_SERVICE);
	ATF_CHECK_EQ(GATT_UUID_SECONDARY_SERVICE,
	    BT_ASSIGNED_UUID_SECONDARY_SERVICE);
	ATF_CHECK_EQ(GATT_UUID_INCLUDE, BT_ASSIGNED_UUID_INCLUDE);
	ATF_CHECK_EQ(GATT_UUID_CHARACTERISTIC,
	    BT_ASSIGNED_UUID_CHARACTERISTIC);
	ATF_CHECK_EQ(GATT_UUID_CCCD, BT_ASSIGNED_UUID_CCCD);
	ATF_CHECK_EQ(GATT_PROP_READ, BT_CORE63_GATT_PROP_READ);
}

/* ================================================================
 * Mock helper: att_conn on a nonblocking SOCK_SEQPACKET socketpair.
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
	ac->mtu = BT_CORE63_ATT_MAX_MTU;
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

/* MSG_EOR keeps SEQPACKET record boundaries so multiple datagrams queue. */
static void
gc_preload(int peer_fd, const uint8_t *pdu, size_t len)
{

	ATF_REQUIRE(send(peer_fd, pdu, len, MSG_EOR) == (ssize_t)len);
}

/* ----------------------------------------------------------------
 * Per-routine "one valid response" drivers.  Each preloads a minimal
 * well-formed response, runs the routine to its trailing LOG_GATT(1,...),
 * and checks the parse.  Used by the logging-path cases below under
 * different blued_verbose / blued_daemonized settings.
 * ---------------------------------------------------------------- */

static void
drive_dbhash(void)
{
	struct att_conn ac;
	int peer;
	uint8_t hash[BT_CORE63_ATT_DB_HASH_SIZE];
	/* Non-normative recognizable 128-bit Database Hash test value. */
	static const uint8_t expected[BT_CORE63_ATT_DB_HASH_SIZE] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	uint8_t rsp[1 + 1 + 2 + BT_CORE63_ATT_DB_HASH_SIZE];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = 2 + BT_CORE63_ATT_DB_HASH_SIZE;
	put_le16(rsp + 2, 0x0010);
	memcpy(rsp + 4, expected, sizeof(expected));
	gc_preload(peer, rsp, sizeof(rsp));

	memset(hash, 0, sizeof(hash));
	ATF_CHECK_EQ(gatt_read_database_hash(&ac, hash), 0);
	ATF_CHECK_EQ(memcmp(hash, expected, sizeof(expected)), 0);
	gc_cleanup(&ac, peer);
}

static void
drive_primary(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[4];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_GROUP16_ENTRY_SIZE];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_GROUP16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0001);
	put_le16(rsp + 4, 0x0005);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GAP_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0001);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0005);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GAP_SERVICE);
	gc_cleanup(&ac, peer);
}

static void
drive_primary_by_uuid(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[4];
	int n = -1;
	uint8_t rsp[1 + 4];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0004);
	put_le16(rsp + 3, 0x0007);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_service_by_uuid(&ac,
	    BT_ASSIGNED_UUID_BATTERY_SERVICE,
	    svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	gc_cleanup(&ac, peer);
}

static void
drive_primary_by_uuid128(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[4];
	int n = -1;
	/* Non-normative custom UUID request sentinel, distinct from SIG UUIDs. */
	static const uint8_t u128[BT_CORE63_ATT_UUID128_SIZE] = {
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
	};
	uint8_t rsp[1 + 4];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_FIND_BY_TYPE_VALUE_RSP;
	put_le16(rsp + 1, 0x0004);
	put_le16(rsp + 3, 0x0007);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_primary_service_by_uuid128(&ac, u128,
	    svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0004);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0007);
	gc_cleanup(&ac, peer);
}

static void
drive_secondary(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_service svcs[4];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_GROUP16_ENTRY_SIZE];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_GROUP_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_GROUP16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0010);
	put_le16(rsp + 4, 0x0015);
	put_le16(rsp + 6, BT_ASSIGNED_UUID_GATT_SERVICE);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_secondary_services(&ac, svcs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(svcs[0].start_handle, 0x0010);
	ATF_CHECK_EQ(svcs[0].end_handle, 0x0015);
	ATF_CHECK_EQ(svcs[0].uuid16, BT_ASSIGNED_UUID_GATT_SERVICE);
	gc_cleanup(&ac, peer);
}

static void
drive_includes(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0004);
	put_le16(rsp + 4, 0x0020);
	put_le16(rsp + 6, 0x0025);
	put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_includes(&ac, 0x0001,
	    BT_CORE63_ATT_HANDLE_MAX, incs, 1, &n),
	    0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0004);
	ATF_CHECK_EQ(incs[0].uuid16, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	gc_cleanup(&ac, peer);
}

static void
drive_characteristics(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[4];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_CHAR16_ENTRY_SIZE];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_CHAR16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0002);
	rsp[4] = BT_CORE63_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0003);
	put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_characteristics(&ac, 0x0001,
	    BT_CORE63_ATT_HANDLE_MAX,
	    chars, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(chars[0].decl_handle, 0x0002);
	ATF_CHECK_EQ(chars[0].value_handle, 0x0003);
	ATF_CHECK_EQ(chars[0].properties, BT_CORE63_GATT_PROP_READ);
	ATF_CHECK_EQ(chars[0].uuid16, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_cleanup(&ac, peer);
}

static void
drive_descriptors(void)
{
	struct att_conn ac;
	int peer;
	struct gatt_desc descs[4];
	int n = -1;
	uint8_t rsp[1 + 1 + 4];

	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_FIND_INFO_RSP;
	rsp[1] = BT_CORE63_ATT_FIND_INFO_FORMAT_UUID16;
	put_le16(rsp + 2, 0x0007);
	put_le16(rsp + 4, BT_ASSIGNED_UUID_CCCD);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK_EQ(gatt_discover_descriptors(&ac, 0x0001,
	    BT_CORE63_ATT_HANDLE_MAX,
	    descs, 1, &n), 0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(descs[0].handle, 0x0007);
	ATF_CHECK_EQ(descs[0].uuid16, BT_ASSIGNED_UUID_CCCD);
	gc_cleanup(&ac, peer);
}

static void
drive_all(void)
{

	drive_dbhash();
	drive_primary();
	drive_primary_by_uuid();
	drive_primary_by_uuid128();
	drive_secondary();
	drive_includes();
	drive_characteristics();
	drive_descriptors();
}

/* ================================================================
 * LOGGING: verbose enabled, non-daemonized -> the fprintf(stderr) arm of
 * every trailing LOG_GATT(1, ...) (blued_verbose >= 1 True, daemonized
 * False).  ble_util.h _BLUED_LOG expansion.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_log_verbose_stderr);
ATF_TC_BODY(deep_log_verbose_stderr, tc)
{

	assert_gatt_client_wire_contract();
	blued_verbose = 1;
	blued_daemonized = 0;
	drive_all();
	blued_verbose = 0;
}

/* ================================================================
 * LOGGING: verbose enabled, daemonized -> the syslog() arm of every
 * trailing LOG_GATT(1, ...) (blued_verbose >= 1 True, daemonized True).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_log_verbose_syslog);
ATF_TC_BODY(deep_log_verbose_syslog, tc)
{

	assert_gatt_client_wire_contract();
	blued_verbose = 1;
	blued_daemonized = 1;
	drive_all();
	blued_verbose = 0;
	blued_daemonized = 0;
}

/* ================================================================
 * gatt_discover_includes: caller's range is exhausted by the response.
 * With end_handle == 0x0025 and an include declaration AT 0x0025, the
 * next start (0x0026) exceeds end_handle, so the outer while re-evaluates
 * `start <= end_handle` and exits through its False arm rather than via a
 * second ATT request.  Core Spec Vol 3 Part G Sec 4.5.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_includes_range_exhausted);
ATF_TC_BODY(deep_includes_range_exhausted, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[8];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE];

	assert_gatt_client_wire_contract();
	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_INCLUDE16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0025);	/* include decl handle == end_handle */
	put_le16(rsp + 4, 0x0030);	/* included service start */
	put_le16(rsp + 6, 0x0035);	/* included service end */
	put_le16(rsp + 8, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	gc_preload(peer, rsp, sizeof(rsp));

	/* max_includes 8 keeps the count guard true so the range guard is
	 * the arm that terminates the loop. */
	ATF_CHECK_EQ(gatt_discover_includes(&ac, 0x0001, 0x0025, incs, 8, &n),
	    0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0025);
	ATF_CHECK_EQ(incs[0].start_handle, 0x0030);
	ATF_CHECK_EQ(incs[0].end_handle, 0x0035);
	ATF_CHECK_EQ(incs[0].uuid16, BT_ASSIGNED_UUID_DEVICE_INFORMATION);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * A declaration at the final handle whose value handle lies beyond the
 * requested service range is malformed.  Reject it without publishing a
 * partial characteristic.  Core Spec Vol 3 Part G Sec 3.3.1 and 4.6.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_chars_range_exhausted);
ATF_TC_BODY(deep_chars_range_exhausted, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_char chars[8];
	int n = -1;
	uint8_t rsp[1 + 1 + BT_CORE63_ATT_CHAR16_ENTRY_SIZE];

	assert_gatt_client_wire_contract();
	gc_pair(&ac, &peer);
	rsp[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rsp[1] = BT_CORE63_ATT_CHAR16_ENTRY_SIZE;
	put_le16(rsp + 2, 0x0003);	/* decl handle == end */
	rsp[4] = BT_CORE63_GATT_PROP_READ;
	put_le16(rsp + 5, 0x0004);	/* value handle */
	put_le16(rsp + 7, BT_ASSIGNED_UUID_DEVICE_NAME);
	gc_preload(peer, rsp, sizeof(rsp));

	ATF_CHECK(gatt_discover_characteristics(&ac, 0x0001, 0x0003,
	    chars, 8, &n) != 0);
	ATF_CHECK_EQ(n, 0);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * gatt_discover_includes: 128-bit include whose follow-up ATT Read
 * Request succeeds but returns a value that is not 16 bytes long.  The
 * resolution guard `ret == 0 && rdlen == 16` must take its rdlen != 16
 * False arm and leave the UUID unresolved (has_uuid == false).
 *
 * Two datagrams are queued in lockstep: the Read By Type Response
 * (entry_len 6, no inline UUID) and, for the subsequent att_read() on the
 * included service's start handle, a Read Response carrying an 8-byte
 * value.  Core Spec Vol 3 Part G Sec 4.5.1 / Part F Sec 3.4.4.4.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(deep_includes_read_wrong_len);
ATF_TC_BODY(deep_includes_read_wrong_len, tc)
{
	struct att_conn ac;
	int peer;
	struct gatt_include incs[4];
	int n = -1;
	uint8_t rbt[1 + 1 + BT_CORE63_ATT_INCLUDE128_ENTRY_SIZE];
	uint8_t rdr[1 + BT_CORE63_ATT_UUID128_TRUNCATED_SIZE];

	assert_gatt_client_wire_contract();
	gc_pair(&ac, &peer);

	/* Read By Type Response: one include, entry_len 6 (128-bit form). */
	rbt[0] = BT_CORE63_ATT_OP_READ_BY_TYPE_RSP;
	rbt[1] = BT_CORE63_ATT_INCLUDE128_ENTRY_SIZE;
	put_le16(rbt + 2, 0x0004);	/* include declaration handle */
	put_le16(rbt + 4, 0x0020);	/* included service start */
	put_le16(rbt + 6, 0x0025);	/* included service end */
	gc_preload(peer, rbt, sizeof(rbt));

	/* Adjacent-short 15-octet value cannot be a 128-bit service UUID. */
	rdr[0] = BT_CORE63_ATT_OP_READ_RSP;
	memset(rdr + 1, 0xA5, BT_CORE63_ATT_UUID128_TRUNCATED_SIZE);
	gc_preload(peer, rdr, sizeof(rdr));

	ATF_CHECK_EQ(gatt_discover_includes(&ac, 0x0001,
	    BT_CORE63_ATT_HANDLE_MAX, incs, 1, &n),
	    0);
	ATF_CHECK_EQ(n, 1);
	ATF_CHECK_EQ(incs[0].handle, 0x0004);
	ATF_CHECK_EQ(incs[0].start_handle, 0x0020);
	ATF_CHECK_EQ(incs[0].end_handle, 0x0025);
	ATF_CHECK(!incs[0].has_uuid);
	gc_cleanup(&ac, peer);
}

/* ================================================================
 * ATF TEST PLAN
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, deep_log_verbose_stderr);
	ATF_TP_ADD_TC(tp, deep_log_verbose_syslog);
	ATF_TP_ADD_TC(tp, deep_includes_range_exhausted);
	ATF_TP_ADD_TC(tp, deep_chars_range_exhausted);
	ATF_TP_ADD_TC(tp, deep_includes_read_wrong_len);

	return (atf_no_error());
}
