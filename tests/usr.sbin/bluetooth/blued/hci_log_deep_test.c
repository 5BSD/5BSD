/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * BTSnoop packet-logger coverage (hci_log.c).
 *
 * hci_log.c is a pure byte-formatter with no controller dependency, yet the
 * existing HCI test suite never opens a capture, so the entire logger sits at
 * ~3% branch coverage.  These cases drive every unit-reachable branch:
 *
 *   - hci_log_open success (writes and verifies the BTSnoop file header) and
 *     failure (unopenable path leaves the logger disabled)
 *   - hci_log_enabled before/after open and after close
 *   - hci_log_packet for each H4 type (CMD / EVT command-or-event flag=2 set;
 *     ACL data flag clear) in both directions (direction flag bit 0)
 *   - hci_log_l2cap normal path plus the two length-overflow guards
 *     (len > UINT16_MAX truncation, len > UINT16_MAX-4 early return)
 *   - the early "log disabled" return of hci_log_packet / hci_log_l2cap
 *
 * Oracle: the BTSnoop file format (8-byte "btsnoop\0" magic, big-endian
 * version = 1, big-endian datalink = 1002 for H4-with-type) and the per-record
 * header (orig_len / incl_len / flags / drops big-endian) documented in the
 * BTSnoop specification and mirrored in the hci_log.c file comment.  The
 * flag encoding (bit0 = direction 0=host->ctrl / 1=ctrl->host, bit1 = 1 for
 * command/event) is asserted from that spec, never captured from the code.
 *
 * The writev-failure and short-write branches need a descriptor whose write
 * fails after a successful open; that is fault injection (category C) and is
 * not attempted here.
 *
 * Link set: hci_log_deep_test.c hci_util.c hci_adv.c hci_scan.c hci_conn.c
 * hci_privacy.c hci_misc.c hci_log.c   (+ libbluetooth, libcrypto).
 */

#include <sys/stat.h>

#include <atf-c.h>

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hci_log.h"
#include "ble_util.h"	/* extern decls for blued_verbose / blued_daemonized */
#include "spec_hci_log_oracles.h"

/* Stub globals referenced by the hci_*.c logging macros pulled in at link. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

static void
assert_hci_log_deep_contract(void)
{

	ATF_CHECK_EQ(HCI_LOG_CMD, BT_CORE63_H4_COMMAND_PACKET);
	ATF_CHECK_EQ(HCI_LOG_ACL, BT_CORE63_H4_ACL_PACKET);
	ATF_CHECK_EQ(HCI_LOG_EVT, BT_CORE63_H4_EVENT_PACKET);
}

static uint32_t
be32(const uint8_t *p)
{

	return (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | p[3]);
}

/* Make a unique temp path in the test's working directory. */
static void
tmp_path(char *buf, size_t len)
{

	snprintf(buf, len, "hci_log_deep.%d.btsnoop", (int)getpid());
}

/* ================================================================
 * hci_log_open writes a well-formed BTSnoop header and enables the log.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(log_open_header_and_enabled);
ATF_TC_BODY(log_open_header_and_enabled, tc)
{
	char path[64];
	uint8_t hdr[BT_BTSNOOP_FILE_HEADER_SIZE];
	int fd;
	ssize_t n;

	assert_hci_log_deep_contract();
	ATF_CHECK(!hci_log_enabled());		/* disabled before open */

	tmp_path(path, sizeof(path));
	hci_log_open(path);
	ATF_CHECK(hci_log_enabled());

	hci_log_close();
	ATF_CHECK(!hci_log_enabled());		/* disabled again after close */

	/* Verify the 16-byte BTSnoop header the open wrote. */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	n = read(fd, hdr, sizeof(hdr));
	close(fd);
	(void)unlink(path);

	ATF_REQUIRE_EQ(n, BT_BTSNOOP_FILE_HEADER_SIZE);
	ATF_CHECK_EQ(memcmp(hdr, bt_btsnoop_magic,
	    sizeof(bt_btsnoop_magic)), 0);
	ATF_CHECK_EQ(be32(hdr + 8), BT_BTSNOOP_VERSION);
	ATF_CHECK_EQ(be32(hdr + 12), BT_BTSNOOP_DATALINK_H4);
}

/* ================================================================
 * hci_log_open on an unopenable path leaves the logger disabled and the
 * packet/l2cap writers become no-ops (their early "log_fd < 0" return).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(log_open_failure_disabled);
ATF_TC_BODY(log_open_failure_disabled, tc)
{
	const uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

	assert_hci_log_deep_contract();
	/* A path under a nonexistent directory cannot be created. */
	hci_log_open("/nonexistent-dir-hci/deep/capture.btsnoop");
	ATF_CHECK(!hci_log_enabled());

	/* With no log open these must return immediately without crashing. */
	hci_log_packet(HCI_LOG_CMD, data, sizeof(data), false);
	hci_log_l2cap(0x0040, 0x0004, data, sizeof(data), true);
	ATF_CHECK(!hci_log_enabled());
}

/* ================================================================
 * hci_log_packet: one record per H4 type / direction, with the BTSnoop
 * record header and flags checked against the format.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(log_packet_types_and_flags);
ATF_TC_BODY(log_packet_types_and_flags, tc)
{
	char path[64];
	const uint8_t acl[] = {
	    0x40, 0x20, 0x01, 0x00, 0xaa
	};
	uint8_t rec[BT_BTSNOOP_RECORD_HEADER_SIZE + 1];
	int fd;
	off_t off;

	assert_hci_log_deep_contract();
	tmp_path(path, sizeof(path));
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* CMD, host->controller: flags bit1 (cmd/evt) set, bit0 (dir) clear. */
	hci_log_packet(HCI_LOG_CMD, bt_core63_hci_reset_command,
	    sizeof(bt_core63_hci_reset_command), false);
	/* EVT, controller->host: flags bits 0 and 1 both set. */
	hci_log_packet(HCI_LOG_EVT, bt_core63_hci_reset_complete_event,
	    sizeof(bt_core63_hci_reset_complete_event), true);
	/* ACL data, controller->host: bit1 clear (not cmd/evt), bit0 set. */
	hci_log_packet(HCI_LOG_ACL, acl, sizeof(acl), true);
	/* ACL data, host->controller: both bits clear. */
	hci_log_packet(HCI_LOG_ACL, acl, sizeof(acl), false);

	hci_log_close();

	/* Re-read the four records and check flags / length accounting. */
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	off = BT_BTSNOOP_FILE_HEADER_SIZE;

	/*
	 * Each record is followed by the H4 packet type indicator byte that the
	 * logger prepends to the payload; that byte is spec-defined in
	 * Core Spec Vol 4 Part A Section 2, Table 2.1 (HCI Command = 0x01,
	 * HCI ACL Data = 0x02, HCI Event = 0x04), so rec[24] is asserted against
	 * the mandated indicator, not just the BTSnoop flags.
	 */
	/* Record 1: CMD sent -> flags 2, incl_len = len + 1 (H4 type byte). */
	ATF_REQUIRE_EQ(pread(fd, rec, sizeof(rec), off), (ssize_t)sizeof(rec));
	ATF_CHECK_EQ(be32(rec + 0), sizeof(bt_core63_hci_reset_command) + 1);
	ATF_CHECK_EQ(be32(rec + 4), sizeof(bt_core63_hci_reset_command) + 1);
	ATF_CHECK_EQ(be32(rec + 8), BT_BTSNOOP_FLAG_SENT_COMMAND);
	ATF_CHECK_EQ(be32(rec + 12), BT_BTSNOOP_DROPS_NONE);
	ATF_CHECK_EQ(rec[BT_BTSNOOP_RECORD_HEADER_SIZE],
	    BT_CORE63_H4_COMMAND_PACKET);
	off += BT_BTSNOOP_RECORD_HEADER_SIZE + 1 +
	    sizeof(bt_core63_hci_reset_command);

	/* Record 2: EVT received -> flags 3. */
	ATF_REQUIRE_EQ(pread(fd, rec, sizeof(rec), off), (ssize_t)sizeof(rec));
	ATF_CHECK_EQ(be32(rec + 8), BT_BTSNOOP_FLAG_RECEIVED_EVENT);
	ATF_CHECK_EQ(rec[BT_BTSNOOP_RECORD_HEADER_SIZE],
	    BT_CORE63_H4_EVENT_PACKET);
	off += BT_BTSNOOP_RECORD_HEADER_SIZE + 1 +
	    sizeof(bt_core63_hci_reset_complete_event);

	/* Record 3: ACL received -> flags 1 (direction only). */
	ATF_REQUIRE_EQ(pread(fd, rec, sizeof(rec), off), (ssize_t)sizeof(rec));
	ATF_CHECK_EQ(be32(rec + 8), BT_BTSNOOP_FLAG_RECEIVED_DATA);
	ATF_CHECK_EQ(rec[BT_BTSNOOP_RECORD_HEADER_SIZE],
	    BT_CORE63_H4_ACL_PACKET);
	off += BT_BTSNOOP_RECORD_HEADER_SIZE + 1 + sizeof(acl);

	/* Record 4: ACL sent -> flags 0. */
	ATF_REQUIRE_EQ(pread(fd, rec, sizeof(rec), off), (ssize_t)sizeof(rec));
	ATF_CHECK_EQ(be32(rec + 8), BT_BTSNOOP_FLAG_SENT_DATA);
	ATF_CHECK_EQ(rec[BT_BTSNOOP_RECORD_HEADER_SIZE],
	    BT_CORE63_H4_ACL_PACKET);

	close(fd);
	(void)unlink(path);
}

/* ================================================================
 * hci_log_l2cap: a normal PDU is wrapped with an HCI ACL header (PB=0b10,
 * first automatically flushable) and an L2CAP basic header (length + CID).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(log_l2cap_wraps_headers);
ATF_TC_BODY(log_l2cap_wraps_headers, tc)
{
	char path[64];
	uint8_t buf[BT_BTSNOOP_RECORD_HEADER_SIZE + 1 +
	    BT_CORE63_ACL_HEADER_SIZE + BT_CORE63_L2CAP_BASIC_HEADER_SIZE +
	    sizeof(bt_core63_att_exchange_mtu_23)];
	int fd;
	ssize_t n;

	assert_hci_log_deep_contract();
	tmp_path(path, sizeof(path));
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	hci_log_l2cap(BT_TEST_ACL_CONNECTION_HANDLE, BT_CORE63_L2CAP_CID_ATT,
	    bt_core63_att_exchange_mtu_23,
	    sizeof(bt_core63_att_exchange_mtu_23), true);
	hci_log_close();

	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	n = pread(fd, buf, sizeof(buf), BT_BTSNOOP_FILE_HEADER_SIZE);
	close(fd);
	(void)unlink(path);

	ATF_REQUIRE_EQ(n, (ssize_t)sizeof(buf));

	ATF_CHECK_EQ(be32(buf + 0), 1 + BT_CORE63_ACL_HEADER_SIZE +
	    BT_CORE63_L2CAP_BASIC_HEADER_SIZE +
	    sizeof(bt_core63_att_exchange_mtu_23));
	ATF_CHECK_EQ(be32(buf + 8), BT_BTSNOOP_FLAG_RECEIVED_DATA);

	/* buf[24] = H4 ACL type indicator (0x02). */
	ATF_CHECK_EQ(buf[BT_BTSNOOP_RECORD_HEADER_SIZE],
	    BT_CORE63_H4_ACL_PACKET);
	/* ACL header: handle 0x0040 with PB=0b10 -> byte1 = 0x20. */
	ATF_CHECK_EQ(buf[25], BT_TEST_ACL_CONNECTION_HANDLE & 0xff);
	ATF_CHECK_EQ(buf[26],
	    ((BT_TEST_ACL_CONNECTION_HANDLE >> 8) & 0x0f) |
	    (BT_CORE63_ACL_PB_FIRST_AUTO_FLUSH << 4));
	/* ACL total length = L2CAP header(4) + three-octet ATT request = 7. */
	ATF_CHECK_EQ(buf[27], 7);
	ATF_CHECK_EQ(buf[28], 0);
	/* L2CAP basic header: length = payload(3), CID = ATT (0x0004). */
	ATF_CHECK_EQ(buf[29], sizeof(bt_core63_att_exchange_mtu_23));
	ATF_CHECK_EQ(buf[30], 0);
	ATF_CHECK_EQ(buf[31], BT_CORE63_L2CAP_CID_ATT & 0xff);
	ATF_CHECK_EQ(buf[32], BT_CORE63_L2CAP_CID_ATT >> 8);
	ATF_CHECK(memcmp(buf + 33, bt_core63_att_exchange_mtu_23,
	    sizeof(bt_core63_att_exchange_mtu_23)) == 0);
}

/* ================================================================
 * hci_log_l2cap length-overflow guards.
 *   len > UINT16_MAX          -> warn + clamp to UINT16_MAX, then
 *   len > UINT16_MAX - 4      -> early return (no record written)
 * A length in (UINT16_MAX-4, UINT16_MAX] hits only the second guard.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(log_l2cap_length_guards);
ATF_TC_BODY(log_l2cap_length_guards, tc)
{
	char path[64];
	uint8_t *big;
	struct stat st;
	size_t bigsz = 70000;		/* > UINT16_MAX */

	assert_hci_log_deep_contract();
	big = malloc(bigsz);
	ATF_REQUIRE(big != NULL);
	memset(big, 0x5A, bigsz);

	tmp_path(path, sizeof(path));
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* len 70000 > 65535: truncate branch, then 65535 > 65531: early ret. */
	hci_log_l2cap(BT_TEST_ACL_CONNECTION_HANDLE, BT_CORE63_L2CAP_CID_ATT,
	    big, bigsz, false);
	/* len 65532 in (65531, 65535]: first guard false, second true. */
	hci_log_l2cap(BT_TEST_ACL_CONNECTION_HANDLE, BT_CORE63_L2CAP_CID_ATT,
	    big, (size_t)(UINT16_MAX - 3), false);

	hci_log_close();

	/* No record should have been written past the 16-byte file header. */
	ATF_REQUIRE_EQ(stat(path, &st), 0);
	ATF_CHECK_EQ(st.st_size, BT_BTSNOOP_FILE_HEADER_SIZE);

	(void)unlink(path);
	free(big);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, log_open_header_and_enabled);
	ATF_TP_ADD_TC(tp, log_open_failure_disabled);
	ATF_TP_ADD_TC(tp, log_packet_types_and_flags);
	ATF_TP_ADD_TC(tp, log_l2cap_wraps_headers);
	ATF_TP_ADD_TC(tp, log_l2cap_length_guards);

	return (atf_no_error());
}
