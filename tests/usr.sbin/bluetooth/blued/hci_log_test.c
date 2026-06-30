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

/* ble_util.h globals required by hci_log.c (via warn()) */
#include <stdatomic.h>
#include "ble_util.h"
extern atomic_int blued_verbose;
extern int blued_daemonized;
atomic_int blued_verbose;
int blued_daemonized;

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
	uint8_t hdr[16];
	ssize_t n;

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
	ATF_CHECK_EQ(n, 16);

	/* Magic: "btsnoop\0" */
	ATF_CHECK(memcmp(hdr, "btsnoop\0", 8) == 0);

	/* Version: 1 (big-endian) */
	ATF_CHECK_EQ(read_be32(hdr + 8), 1);

	/* Datalink type: 1002 (H4) */
	ATF_CHECK_EQ(read_be32(hdr + 12), 1002);

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
	uint8_t test_data[] = { 0x01, 0x03, 0x0C, 0x00 }; /* HCI Reset cmd */
	uint32_t orig_len, incl_len, flags, drops;
	uint64_t timestamp;

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
	ATF_REQUIRE(n > 16);

	/* Skip the 16-byte file header, parse the record header (24 bytes) */
	const uint8_t *rec = file_buf + 16;
	ATF_REQUIRE(n >= 16 + 24);

	orig_len = read_be32(rec + 0);
	incl_len = read_be32(rec + 4);
	flags = read_be32(rec + 8);
	drops = read_be32(rec + 12);
	timestamp = read_be64(rec + 16);

	/* Total = H4 type byte (1) + data (4) = 5 */
	ATF_CHECK_EQ(orig_len, sizeof(test_data) + 1);
	ATF_CHECK_EQ(incl_len, sizeof(test_data) + 1);

	/* Direction=sent (0), type=command (bit 1 set) => flags=2 */
	ATF_CHECK_EQ(flags, 2);

	/* Drops should be 0 */
	ATF_CHECK_EQ(drops, 0);

	/* Timestamp should be nonzero (BTSnoop epoch offset) */
	ATF_CHECK(timestamp > 0);

	/* Verify data: H4 type byte + payload */
	const uint8_t *pkt = rec + 24;
	ATF_REQUIRE(n >= 16 + 24 + 1 + (ssize_t)sizeof(test_data));
	ATF_CHECK_EQ(pkt[0], HCI_LOG_CMD);
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
	ATF_REQUIRE(n >= 16 + 24);

	/* Parse flags from the record */
	flags = read_be32(file_buf + 16 + 8);

	/* Direction=received (bit 0), type=data (bit 1 clear) => flags=1 */
	ATF_CHECK_EQ(flags, 1);

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
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_hci_log_open_close);
	ATF_TP_ADD_TC(tp, test_hci_log_packet);
	ATF_TP_ADD_TC(tp, test_hci_log_packet_incoming);
	ATF_TP_ADD_TC(tp, test_hci_log_disabled);

	return (atf_no_error());
}
