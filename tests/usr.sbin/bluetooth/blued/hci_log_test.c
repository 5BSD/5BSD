/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for the HCI BTSnoop packet logger (hci_log.c).
 *
 * These tests link directly against hci_log.c (not the stubs in
 * test_common.h) so that the real open/close/write paths are exercised.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hci_log.h"
#include "spec_hci_log_oracles.h"

/* ble_util.h globals required by hci_log.c (via warn()) */
#include <stdatomic.h>
#include "ble_util.h"
extern atomic_int blued_verbose;
extern int blued_daemonized;
atomic_int blued_verbose;
int blued_daemonized;

static void
assert_hci_log_wire_contract(void)
{

	ATF_CHECK_EQ(HCI_LOG_CMD, BT_CORE63_H4_COMMAND_PACKET);
	ATF_CHECK_EQ(HCI_LOG_ACL, BT_CORE63_H4_ACL_PACKET);
}

/* Helper to read big-endian uint32 */
static uint32_t
read_be32(const uint8_t *p)
{

	return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

/* Helper to read big-endian uint64 */
static uint64_t
read_be64(const uint8_t *p)
{

	return ((uint64_t)read_be32(p) << 32 | (uint64_t)read_be32(p + 4));
}

/* ================================================================
 * Test 1: open/close lifecycle and header verification
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_log_open_close);
ATF_TC_BODY(test_hci_log_open_close, tc)
{
	char path[] = "/tmp/blued_hci_log_test.XXXXXX";
	int fd;
	uint8_t hdr[BT_BTSNOOP_FILE_HEADER_SIZE];
	ssize_t n;

	assert_hci_log_wire_contract();
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	/* Before open, logging must be disabled */
	ATF_CHECK(!hci_log_enabled());

	hci_log_open(path);
	ATF_CHECK(hci_log_enabled());

	hci_log_close();
	ATF_CHECK(!hci_log_enabled());

	/* Verify the BTSnoop file header */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);

	n = read(fd, hdr, sizeof(hdr));
	ATF_CHECK_EQ(n, BT_BTSNOOP_FILE_HEADER_SIZE);

	/* Magic: "btsnoop\0" */
	ATF_CHECK(memcmp(hdr, bt_btsnoop_magic,
	    sizeof(bt_btsnoop_magic)) == 0);

	/* Version: 1 (big-endian) */
	ATF_CHECK_EQ(read_be32(hdr + 8), BT_BTSNOOP_VERSION);

	/* Datalink type: 1002 (H4) */
	ATF_CHECK_EQ(read_be32(hdr + 12), BT_BTSNOOP_DATALINK_H4);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 2: log a packet and verify the record format
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_log_packet);
ATF_TC_BODY(test_hci_log_packet, tc)
{
	char path[] = "/tmp/blued_hci_log_pkt.XXXXXX";
	int fd;
	uint8_t file_buf[256];
	ssize_t n;
	/* Core Vol 4 Part E §7.3.2 command header; H4 type is supplied apart. */
	uint8_t test_data[BT_CORE63_HCI_COMMAND_HEADER_SIZE] = {
	    BT_CORE63_HCI_RESET_OPCODE_LE0, BT_CORE63_HCI_RESET_OPCODE_LE1,
	    BT_CORE63_HCI_RESET_PARAM_LEN };
	uint32_t orig_len, incl_len, flags, drops;
	uint64_t timestamp;

	assert_hci_log_wire_contract();
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* Log an HCI command (sent to controller) */
	hci_log_packet(HCI_LOG_CMD, test_data, sizeof(test_data), false);

	hci_log_close();

	/* Read the file: 16-byte header + record */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	n = read(fd, file_buf, sizeof(file_buf));
	ATF_REQUIRE_EQ(n, BT_BTSNOOP_FILE_HEADER_SIZE +
	    BT_BTSNOOP_RECORD_HEADER_SIZE + 1 + sizeof(test_data));

	/* Skip the 16-byte file header, parse the record header (24 bytes) */
	const uint8_t *rec = file_buf + BT_BTSNOOP_FILE_HEADER_SIZE;

	orig_len = read_be32(rec + 0);
	incl_len = read_be32(rec + 4);
	flags = read_be32(rec + 8);
	drops = read_be32(rec + 12);
	timestamp = read_be64(rec + 16);

	/* Total = H4 type byte (1) + data (4) = 5 */
	ATF_CHECK_EQ(orig_len, sizeof(test_data) + 1);
	ATF_CHECK_EQ(incl_len, sizeof(test_data) + 1);

	/* Direction=sent (0), type=command (bit 1 set) => flags=2 */
	ATF_CHECK_EQ(flags, BT_BTSNOOP_FLAG_SENT_COMMAND);

	/* Drops should be 0 */
	ATF_CHECK_EQ(drops, BT_BTSNOOP_DROPS_NONE);

	/* Timestamp should be nonzero (BTSnoop epoch offset) */
	ATF_CHECK(timestamp > 0);

	/* Verify data: H4 type byte + payload */
	const uint8_t *pkt = rec + BT_BTSNOOP_RECORD_HEADER_SIZE;
	ATF_CHECK_EQ(pkt[0], BT_CORE63_H4_COMMAND_PACKET);
	ATF_CHECK(memcmp(pkt + 1, test_data, sizeof(test_data)) == 0);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 3: log an incoming ACL packet and verify direction flag
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_log_packet_incoming);
ATF_TC_BODY(test_hci_log_packet_incoming, tc)
{
	char path[] = "/tmp/blued_hci_log_in.XXXXXX";
	int fd;
	uint8_t file_buf[256];
	ssize_t n;
	uint8_t acl_data[] = { 0x40, 0x20, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
	uint32_t flags;

	assert_hci_log_wire_contract();
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* Log an incoming ACL packet */
	hci_log_packet(HCI_LOG_ACL, acl_data, sizeof(acl_data), true);

	hci_log_close();

	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	n = read(fd, file_buf, sizeof(file_buf));
	ATF_REQUIRE_EQ(n, BT_BTSNOOP_FILE_HEADER_SIZE +
	    BT_BTSNOOP_RECORD_HEADER_SIZE + 1 + sizeof(acl_data));

	/* Parse flags from the record */
	flags = read_be32(file_buf + BT_BTSNOOP_FILE_HEADER_SIZE + 8);

	/* Direction=received (bit 0), type=data (bit 1 clear) => flags=1 */
	ATF_CHECK_EQ(flags, BT_BTSNOOP_FLAG_RECEIVED_DATA);

	/*
	 * First payload byte is the H4 packet type indicator prepended by the
	 * logger.  For ACL data it must be 0x02 per Core Spec Vol 4 Part A
	 * Section 2, Table 2.1 (HCI packet indicators).
	 */
	ATF_CHECK_EQ(file_buf[BT_BTSNOOP_FILE_HEADER_SIZE +
	    BT_BTSNOOP_RECORD_HEADER_SIZE], BT_CORE63_H4_ACL_PACKET);
	ATF_CHECK(memcmp(file_buf + BT_BTSNOOP_FILE_HEADER_SIZE +
	    BT_BTSNOOP_RECORD_HEADER_SIZE + 1, acl_data,
	    sizeof(acl_data)) == 0);

	close(fd);
	unlink(path);
}

/* ================================================================
 * Test 4: hci_log_enabled() returns correct state
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_log_disabled);
ATF_TC_BODY(test_hci_log_disabled, tc)
{
	char path[] = "/tmp/blued_hci_log_dis.XXXXXX";
	int fd;

	assert_hci_log_wire_contract();
	/* Initially disabled */
	ATF_CHECK(!hci_log_enabled());

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	/* After open, enabled */
	hci_log_open(path);
	ATF_CHECK(hci_log_enabled());

	/* After close, disabled again */
	hci_log_close();
	ATF_CHECK(!hci_log_enabled());

	/* Logging a packet when disabled should be a no-op (no crash) */
	{
		uint8_t dummy = 0x00;
		hci_log_packet(HCI_LOG_CMD, &dummy, 1, false);
	}

	unlink(path);
}

/* ================================================================
 * Finding 49: an oversized L2CAP PDU is truncated into a record, not
 * silently dropped.  The BTSnoop L2CAP length is a uint16_t that must
 * also hold the 4-byte basic header, so the payload is capped at
 * UINT16_MAX-4 and a record is still emitted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_hci_log_l2cap_oversized_truncated);
ATF_TC_BODY(test_hci_log_l2cap_oversized_truncated, tc)
{
	char path[] = "/tmp/blued_hci_log_big.XXXXXX";
	int fd;
	uint8_t *big;
	struct stat sb;
	size_t expect_payload = (size_t)UINT16_MAX - 4;
	off_t expect_size;

	assert_hci_log_wire_contract();
	big = malloc(UINT16_MAX);
	ATF_REQUIRE(big != NULL);
	memset(big, 0xA5, UINT16_MAX);

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	close(fd);

	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* 65535-byte PDU: previously dropped, now truncated + written. */
	hci_log_l2cap(0x0040, 0x0004, big, UINT16_MAX, false);
	hci_log_close();

	ATF_REQUIRE_EQ(0, stat(path, &sb));
	/*
	 * file header + record header + H4 type(1) + ACL(4) + L2CAP(4)
	 * + truncated payload.
	 */
	expect_size = (off_t)(BT_BTSNOOP_FILE_HEADER_SIZE +
	    BT_BTSNOOP_RECORD_HEADER_SIZE + 1 + 8 + expect_payload);
	ATF_CHECK_MSG(sb.st_size == expect_size,
	    "record must be truncated+written (size=%jd, expected %jd)",
	    (intmax_t)sb.st_size, (intmax_t)expect_size);
	ATF_CHECK_MSG(sb.st_size > (off_t)BT_BTSNOOP_FILE_HEADER_SIZE,
	    "record must not be dropped");

	free(big);
	unlink(path);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test_hci_log_l2cap_oversized_truncated);

	ATF_TP_ADD_TC(tp, test_hci_log_open_close);
	ATF_TP_ADD_TC(tp, test_hci_log_packet);
	ATF_TP_ADD_TC(tp, test_hci_log_packet_incoming);
	ATF_TP_ADD_TC(tp, test_hci_log_disabled);

	/*
	 * Larger writes, reopen behavior, and timestamp monotonicity are covered
	 * by hci_log_deep_test; this file keeps the basic format/lifecycle cases.
	 */

	return (atf_no_error());
}
