/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Periodic Advertising (BT 5.0), Periodic Advertising Sync Transfer /
 * PAST (BT 5.1) and Direction Finding / CTE (BT 5.1) conformance tests.
 *
 * Two seams, both driven against the Core Spec as oracle:
 *
 *   Command byte layout — the encoders in hci_adv.c are exercised through
 *   the bt_devreq() link-time wrap (-Wl,--wrap=bt_devreq), and the captured
 *   command parameters are asserted against the §7.8 wire layout:
 *     periodic adv params/data/enable (§7.8.61-63), create/terminate sync
 *     (§7.8.67-69), PAST transfer + parameters (§7.8.89-92), and the CTE
 *     transmit-parameter commands with an antenna switching pattern
 *     (§7.8.80/84/85/87).
 *
 *   Event decode — crafted LE Meta event packets are fed through the
 *   production decode seam (blued_parse_le_meta_event) and the extracted
 *   fields are asserted against the §7.7.65 event layout: Periodic Adv Sync
 *   Established/Report/Sync Lost, Connectionless/Connection IQ Report, CTE
 *   Request Failed, and PAST Received, plus a truncated and a not-owned case.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/endian.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "blued_le_meta.h"
#include "spec_hci_periodic_df_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

/* ================================================================
 * bt_devreq --wrap seam: capture the outbound command parameters and
 * synthesise a Command Complete with status 0x00.  The Read Antenna
 * Information reply is filled with known values so the read decoder
 * can be checked.
 * ================================================================ */
static struct {
	int		called;
	uint16_t	opcode;
	uint8_t		cparam[128];
	size_t		clen;
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	W.called++;
	W.opcode = r->opcode;
	W.clen = r->clen;
	memset(W.cparam, 0, sizeof(W.cparam));
	if (r->cparam != NULL && r->clen > 0) {
		size_t n = r->clen < sizeof(W.cparam) ? r->clen :
		    sizeof(W.cparam);
		memcpy(W.cparam, r->cparam, n);
	}

	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);

	/* Read Antenna Information (§7.8.87): status + 4 capability octets. */
	if (r->opcode == BT_PDF_OP_READ_ANTENNA_INFO &&
	    r->rparam != NULL &&
	    r->rlen >= sizeof(ng_hci_le_read_antenna_information_rp)) {
		ng_hci_le_read_antenna_information_rp *rp = r->rparam;

		rp->status = BT_PDF_STATUS_SUCCESS;
		rp->supported_switching_sampling_rates = 0x03;
		rp->num_antennae = 4;
		rp->max_switching_pattern_length = 8;
		rp->max_cte_length = 20;
	}

	return (0);
}

static void
mock_reset(void)
{

	memset(&W, 0, sizeof(W));
}

#define CHECK_OPCODE(expected_opcode) \
	ATF_CHECK_EQ_MSG((expected_opcode), W.opcode, \
	    "exact HCI opcode 0x%04x", (expected_opcode))

/* ================================================================
 * Periodic Advertising broadcaster commands (§7.8.61-63)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(periodic_adv_params_layout);
ATF_TC_BODY(periodic_adv_params_layout, tc)
{
	int rc;

	mock_reset();
	/* handle=1, min=0x0006, max=0x0C80, properties=0x0040 (Include TxPwr). */
	rc = hci_le_set_periodic_adv_params(FD, 1,
	    BT_PDF_PERIODIC_INTERVAL_MIN, 0x0c80,
	    BT_PDF_PERIODIC_PROP_INCLUDE_TX_POWER);
	ATF_CHECK_EQ(0, rc);
	ATF_CHECK_EQ(1, W.called);
	CHECK_OPCODE(BT_PDF_OP_SET_PERIODIC_ADV_PARAMS);
	ATF_CHECK_EQ_MSG(7, W.clen, "params command is 7 octets");
	ATF_CHECK_EQ(0x01, W.cparam[0]);		/* Advertising_Handle */
	ATF_CHECK_EQ(0x06, W.cparam[1]);		/* Interval_Min LSB */
	ATF_CHECK_EQ(0x00, W.cparam[2]);		/* Interval_Min MSB */
	ATF_CHECK_EQ(0x80, W.cparam[3]);		/* Interval_Max LSB */
	ATF_CHECK_EQ(0x0C, W.cparam[4]);		/* Interval_Max MSB */
	ATF_CHECK_EQ(0x40, W.cparam[5]);		/* Properties LSB */
	ATF_CHECK_EQ(0x00, W.cparam[6]);		/* Properties MSB */

	/* Reserved properties, including the formerly accepted bit 0, fail. */
	mock_reset();
	rc = hci_le_set_periodic_adv_params(FD, 1,
	    BT_PDF_PERIODIC_INTERVAL_MIN, 0x0c80,
	    BT_PDF_PERIODIC_PROP_FIRST_RESERVED);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ_MSG(0, W.called, "reserved property must not reach devreq");

	/* Interval below 0x0006 is rejected before any command is issued. */
	mock_reset();
	rc = hci_le_set_periodic_adv_params(FD, 1,
	    BT_PDF_PERIODIC_INTERVAL_MIN - 1, 0x0c80, 0);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ_MSG(0, W.called, "invalid interval must not reach devreq");
}

ATF_TC_WITHOUT_HEAD(periodic_adv_data_layout);
ATF_TC_BODY(periodic_adv_data_layout, tc)
{
	const uint8_t data[] = { 0x03, 0xAA, 0xBB, 0xCC };
	int rc;

	mock_reset();
	rc = hci_le_set_periodic_adv_data(FD, 2, data, sizeof(data));
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_PERIODIC_ADV_DATA);
	/* handle(1) operation(1) data_length(1) + data; only data sent. */
	ATF_CHECK_EQ_MSG(3 + sizeof(data), W.clen, "data command trims buffer");
	ATF_CHECK_EQ(0x02, W.cparam[0]);		/* Advertising_Handle */
	ATF_CHECK_EQ_MSG(BT_PDF_DATA_OPERATION_COMPLETE, W.cparam[1],
	    "operation is Complete Data");
	ATF_CHECK_EQ(sizeof(data), W.cparam[2]);	/* Data_Length */
	ATF_CHECK_EQ(0xAA, W.cparam[4]);
	ATF_CHECK_EQ(0xCC, W.cparam[6]);
}

ATF_TC_WITHOUT_HEAD(periodic_adv_enable_layout);
ATF_TC_BODY(periodic_adv_enable_layout, tc)
{
	int rc;

	mock_reset();
	rc = hci_le_set_periodic_adv_enable(FD, 1, 3);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_PERIODIC_ADV_ENABLE);
	ATF_CHECK_EQ_MSG(2, W.clen, "enable command is 2 octets");
	ATF_CHECK_EQ(0x01, W.cparam[0]);		/* Enable */
	ATF_CHECK_EQ(0x03, W.cparam[1]);		/* Advertising_Handle */
}

/* ================================================================
 * Periodic Advertising observer/sync commands (§7.8.67-69)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(periodic_adv_create_sync_layout);
ATF_TC_BODY(periodic_adv_create_sync_layout, tc)
{
	const uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	int rc;

	mock_reset();
	/* options=0, sid=5, addr_type=1 (random), skip=2, timeout=0x0100. */
	rc = hci_le_periodic_adv_create_sync(FD, 0x00, 5,
	    BT_PDF_ADDR_RANDOM, addr,
	    0x0002, 0x0100);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_PERIODIC_CREATE_SYNC);
	/* options(1) sid(1) addr_type(1) addr(6) skip(2) timeout(2) cte(1). */
	ATF_CHECK_EQ_MSG(14, W.clen, "create sync command is 14 octets");
	ATF_CHECK_EQ(0x00, W.cparam[0]);		/* Options */
	ATF_CHECK_EQ(0x05, W.cparam[1]);		/* Advertising_SID */
	ATF_CHECK_EQ(0x01, W.cparam[2]);		/* Advertiser_Address_Type */
	ATF_CHECK_EQ(0x11, W.cparam[3]);		/* Advertiser_Address[0] */
	ATF_CHECK_EQ(0x66, W.cparam[8]);		/* Advertiser_Address[5] */
	ATF_CHECK_EQ(0x02, W.cparam[9]);		/* Skip LSB */
	ATF_CHECK_EQ(0x00, W.cparam[10]);		/* Skip MSB */
	ATF_CHECK_EQ(0x00, W.cparam[11]);		/* Sync_Timeout LSB */
	ATF_CHECK_EQ(0x01, W.cparam[12]);		/* Sync_Timeout MSB */
	ATF_CHECK_EQ(0x00, W.cparam[13]);		/* Sync_CTE_Type */

	/* Cancel carries no parameters (§7.8.68). */
	mock_reset();
	rc = hci_le_periodic_adv_create_sync_cancel(FD);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_PERIODIC_CREATE_SYNC_CANCEL);
	ATF_CHECK_EQ_MSG(0, W.clen, "cancel has no parameters");

	/* Terminate Sync carries the 2-octet sync handle (§7.8.69). */
	mock_reset();
	rc = hci_le_periodic_adv_terminate_sync(FD, 0x0007);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_PERIODIC_TERMINATE_SYNC);
	ATF_CHECK_EQ(2, W.clen);
	ATF_CHECK_EQ(0x07, W.cparam[0]);		/* Sync_Handle LSB */
	ATF_CHECK_EQ(0x00, W.cparam[1]);		/* Sync_Handle MSB */
}

/* ================================================================
 * PAST commands (§7.8.89-92)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(past_transfer_layout);
ATF_TC_BODY(past_transfer_layout, tc)
{
	int rc;

	/* LE Periodic Advertising Sync Transfer (§7.8.89). */
	mock_reset();
	rc = hci_le_periodic_adv_sync_transfer(FD, 0x0040, 0x1234, 0x0002);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_PERIODIC_SYNC_TRANSFER);
	ATF_CHECK_EQ_MSG(6, W.clen, "sync transfer is 6 octets");
	ATF_CHECK_EQ(0x40, W.cparam[0]);		/* Connection_Handle LSB */
	ATF_CHECK_EQ(0x00, W.cparam[1]);		/* Connection_Handle MSB */
	ATF_CHECK_EQ(0x34, W.cparam[2]);		/* Service_Data LSB */
	ATF_CHECK_EQ(0x12, W.cparam[3]);		/* Service_Data MSB */
	ATF_CHECK_EQ(0x02, W.cparam[4]);		/* Sync_Handle LSB */
	ATF_CHECK_EQ(0x00, W.cparam[5]);		/* Sync_Handle MSB */

	/* LE Periodic Advertising Set Info Transfer (§7.8.90). */
	mock_reset();
	rc = hci_le_periodic_adv_set_info_transfer(FD, 0x0040, 0x1234, 3);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_PERIODIC_SET_INFO_TRANSFER);
	ATF_CHECK_EQ_MSG(5, W.clen, "set info transfer is 5 octets");
	ATF_CHECK_EQ(0x40, W.cparam[0]);		/* Connection_Handle LSB */
	ATF_CHECK_EQ(0x34, W.cparam[2]);		/* Service_Data LSB */
	ATF_CHECK_EQ(0x03, W.cparam[4]);		/* Advertising_Handle */
}

ATF_TC_WITHOUT_HEAD(past_params_layout);
ATF_TC_BODY(past_params_layout, tc)
{
	int rc;

	/* LE Set PAST Parameters (§7.8.91): per-connection. */
	mock_reset();
	/* con=0x0040, mode=2, skip=1, timeout=0x0100, cte_type=0. */
	rc = hci_le_set_past_params(FD, 0x0040, 2, 0x0001, 0x0100, 0);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_PAST_PARAMS);
	ATF_CHECK_EQ_MSG(8, W.clen, "PAST params is 8 octets");
	ATF_CHECK_EQ(0x40, W.cparam[0]);		/* Connection_Handle LSB */
	ATF_CHECK_EQ(0x00, W.cparam[1]);		/* Connection_Handle MSB */
	ATF_CHECK_EQ(0x02, W.cparam[2]);		/* Mode */
	ATF_CHECK_EQ(0x01, W.cparam[3]);		/* Skip LSB */
	ATF_CHECK_EQ(0x00, W.cparam[4]);		/* Skip MSB */
	ATF_CHECK_EQ(0x00, W.cparam[5]);		/* Sync_Timeout LSB */
	ATF_CHECK_EQ(0x01, W.cparam[6]);		/* Sync_Timeout MSB */
	ATF_CHECK_EQ(0x00, W.cparam[7]);		/* CTE_Type */

	/* LE Set Default PAST Parameters (§7.8.92): no connection handle. */
	mock_reset();
	rc = hci_le_set_default_past_params(FD, 1, 0x0002, 0x00C8, 0);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_DEFAULT_PAST_PARAMS);
	ATF_CHECK_EQ_MSG(6, W.clen, "default PAST params is 6 octets");
	ATF_CHECK_EQ(0x01, W.cparam[0]);		/* Mode */
	ATF_CHECK_EQ(0x02, W.cparam[1]);		/* Skip LSB */
	ATF_CHECK_EQ(0xC8, W.cparam[3]);		/* Sync_Timeout LSB */
	ATF_CHECK_EQ(0x00, W.cparam[5]);		/* CTE_Type */
}

/* ================================================================
 * Direction Finding commands with antenna switching pattern
 * (§7.8.80/84/85/87)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cte_connless_tx_params_layout);
ATF_TC_BODY(cte_connless_tx_params_layout, tc)
{
	const uint8_t antenna_ids[] = { 0x00, 0x01, 0x02 };
	int rc;

	mock_reset();
	/* adv_handle=1, cte_length=20, cte_type=1 (AoD 1us), cte_count=2. */
	rc = hci_le_set_connless_cte_tx_params(FD, 1, 20, 1, 2,
	    sizeof(antenna_ids), antenna_ids);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_CONNLESS_CTE_TX_PARAMS);
	/* handle(1) len(1) type(1) count(1) pattern_len(1) + antenna_ids. */
	ATF_CHECK_EQ_MSG(5 + sizeof(antenna_ids), W.clen,
	    "connless CTE TX params trails the antenna pattern");
	ATF_CHECK_EQ(0x01, W.cparam[0]);		/* Advertising_Handle */
	ATF_CHECK_EQ(20, W.cparam[1]);			/* CTE_Length */
	ATF_CHECK_EQ(0x01, W.cparam[2]);		/* CTE_Type */
	ATF_CHECK_EQ(0x02, W.cparam[3]);		/* CTE_Count */
	ATF_CHECK_EQ_MSG(3, W.cparam[4],
	    "Switching_Pattern_Length octet precedes the ids");
	ATF_CHECK_EQ(0x00, W.cparam[5]);		/* Antenna_IDs[0] */
	ATF_CHECK_EQ(0x01, W.cparam[6]);		/* Antenna_IDs[1] */
	ATF_CHECK_EQ(0x02, W.cparam[7]);		/* Antenna_IDs[2] */

	/* A pattern longer than the 75-id maximum is rejected (§7.8.80). */
	mock_reset();
	rc = hci_le_set_connless_cte_tx_params(FD, 1, 20, 1, 2,
	    BT_PDF_CTE_PATTERN_MAX + 1,
	    antenna_ids);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_EQ(0, W.called);
}

ATF_TC_WITHOUT_HEAD(cte_conn_tx_params_layout);
ATF_TC_BODY(cte_conn_tx_params_layout, tc)
{
	const uint8_t antenna_ids[] = { 0x02, 0x03 };
	int rc;

	mock_reset();
	/* con=0x0040, cte_types=0x04 (AoA), pattern {2,3}. */
	rc = hci_le_set_conn_cte_tx_params(FD, 0x0040, 0x04,
	    sizeof(antenna_ids), antenna_ids);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_SET_CONN_CTE_TX_PARAMS);
	/* connection_handle(2) cte_types(1) pattern_len(1) + antenna_ids. */
	ATF_CHECK_EQ_MSG(4 + sizeof(antenna_ids), W.clen,
	    "conn CTE TX params trails the antenna pattern");
	ATF_CHECK_EQ(0x40, W.cparam[0]);		/* Connection_Handle LSB */
	ATF_CHECK_EQ(0x00, W.cparam[1]);		/* Connection_Handle MSB */
	ATF_CHECK_EQ(0x04, W.cparam[2]);		/* CTE_Types */
	ATF_CHECK_EQ_MSG(2, W.cparam[3], "Switching_Pattern_Length");
	ATF_CHECK_EQ(0x02, W.cparam[4]);		/* Antenna_IDs[0] */
	ATF_CHECK_EQ(0x03, W.cparam[5]);		/* Antenna_IDs[1] */
}

ATF_TC_WITHOUT_HEAD(conn_cte_req_enable_layout);
ATF_TC_BODY(conn_cte_req_enable_layout, tc)
{
	int rc;

	mock_reset();
	/* con=0x0040, enable=1, interval=0x0005, length=16, type=0 (AoA). */
	rc = hci_le_conn_cte_req_enable(FD, 0x0040, 1, 0x0005, 16, 0);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_CONN_CTE_REQ_ENABLE);
	/* handle(2) enable(1) interval(2) length(1) type(1). */
	ATF_CHECK_EQ_MSG(7, W.clen, "conn CTE request enable is 7 octets");
	ATF_CHECK_EQ(0x40, W.cparam[0]);		/* Connection_Handle LSB */
	ATF_CHECK_EQ(0x01, W.cparam[2]);		/* Enable */
	ATF_CHECK_EQ(0x05, W.cparam[3]);		/* CTE_Request_Interval LSB */
	ATF_CHECK_EQ(0x00, W.cparam[4]);		/* CTE_Request_Interval MSB */
	ATF_CHECK_EQ(16, W.cparam[5]);			/* Requested_CTE_Length */
	ATF_CHECK_EQ(0x00, W.cparam[6]);		/* Requested_CTE_Type */
}

ATF_TC_WITHOUT_HEAD(read_antenna_info_decode);
ATF_TC_BODY(read_antenna_info_decode, tc)
{
	uint8_t rates, antennae, max_pattern, max_cte;
	int rc;

	mock_reset();
	rc = hci_le_read_antenna_info(FD, &rates, &antennae, &max_pattern,
	    &max_cte);
	ATF_CHECK_EQ(0, rc);
	CHECK_OPCODE(BT_PDF_OP_READ_ANTENNA_INFO);
	ATF_CHECK_EQ_MSG(0, W.clen, "read antenna info has no parameters");
	/* Values injected by the wrap reply. */
	ATF_CHECK_EQ(0x03, rates);
	ATF_CHECK_EQ(4, antennae);
	ATF_CHECK_EQ(8, max_pattern);
	ATF_CHECK_EQ(20, max_cte);
}

/* ================================================================
 * Event decode through blued_parse_le_meta_event (§7.7.65)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(decode_periodic_adv_sync_established);
ATF_TC_BODY(decode_periodic_adv_sync_established, tc)
{
	/* §7.7.65.14, subevent 0x0E. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 16, BT_PDF_SUBEVENT_SYNC_ESTABLISHED,
		0x00,			/* status */
		0x02, 0x00,		/* sync_handle = 0x0002 */
		0x05,			/* advertising_sid */
		0x01,			/* advertiser_addr_type = random */
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* advertiser_addr */
		0x01,			/* advertiser_phy = 1M */
		0x80, 0x0C,		/* periodic_adv_interval = 0x0C80 */
		0x00,			/* advertiser_clock_accuracy */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_SYNC_ESTABLISHED, rep.subevent);
	ATF_CHECK(rep.has_status);
	ATF_CHECK_EQ(0x00, rep.status);
	ATF_CHECK_EQ(0x0002, rep.sync_handle);
	ATF_CHECK_EQ(0x05, rep.advertising_sid);
	ATF_CHECK_EQ(0x01, rep.advertiser_addr_type);
	ATF_CHECK_EQ(0x11, rep.advertiser_addr[0]);
	ATF_CHECK_EQ(0x66, rep.advertiser_addr[5]);
	ATF_CHECK_EQ(0x01, rep.advertiser_phy);
	ATF_CHECK_EQ(0x0C80, rep.periodic_adv_interval);
	ATF_CHECK_EQ(0x00, rep.advertiser_clock_accuracy);

	/* Truncated: one octet short must be flagged malformed. */
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt) - 1, &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_SYNC_ESTABLISHED, rep.subevent);
}

ATF_TC_WITHOUT_HEAD(decode_periodic_adv_report);
ATF_TC_BODY(decode_periodic_adv_report, tc)
{
	/* §7.7.65.15, subevent 0x0F, with 3 data octets. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 11, BT_PDF_SUBEVENT_PERIODIC_REPORT,
		0x02, 0x00,		/* sync_handle = 0x0002 */
		0xF6,			/* tx_power = -10 dBm */
		0xCE,			/* rssi = -50 dBm */
		0x00,			/* cte_type */
		BT_PDF_DATA_STATUS_MORE,
		0x03,			/* data_length */
		0xDE, 0xAD, 0xBE,	/* data */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_PERIODIC_REPORT, rep.subevent);
	ATF_CHECK_EQ(0x0002, rep.sync_handle);
	ATF_CHECK_EQ(-10, (int)rep.tx_power);
	ATF_CHECK_EQ(-50, (int)rep.rssi);
	ATF_CHECK_EQ(0x01, rep.data_status);
	ATF_CHECK_EQ(3, rep.data_length);
	ATF_CHECK(rep.data != NULL);
	ATF_CHECK_EQ(0xDE, rep.data[0]);
	ATF_CHECK_EQ(0xBE, rep.data[2]);

	/* data_length exceeding the packet is malformed (field at pkt[10]). */
	pkt[10] = 0x40;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	pkt[10] = 0x03;
	pkt[9] = BT_PDF_DATA_STATUS_RESERVED;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
}

ATF_TC_WITHOUT_HEAD(decode_periodic_adv_sync_lost);
ATF_TC_BODY(decode_periodic_adv_sync_lost, tc)
{
	/* §7.7.65.16, subevent 0x10. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 3, BT_PDF_SUBEVENT_SYNC_LOST,
		0x07, 0x00,		/* sync_handle = 0x0007 */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_SYNC_LOST, rep.subevent);
	ATF_CHECK_EQ(0x0007, rep.sync_handle);
}

ATF_TC_WITHOUT_HEAD(decode_connectionless_iq_report);
ATF_TC_BODY(decode_connectionless_iq_report, tc)
{
	/* §7.7.65.21, subevent 0x15, 2 IQ sample pairs. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 17, BT_PDF_SUBEVENT_CONNLESS_IQ,
		0x02, 0x00,		/* sync_handle = 0x0002 */
		0x25,			/* channel_index = 37 */
		0x60, 0xFF,		/* rssi = -160 (0.1 dBm units) */
		0x01,			/* rssi_antenna_id */
		0x00,			/* cte_type = AoA */
		0x01,			/* slot_durations = 1us */
		0x00,			/* packet_status */
		0x34, 0x12,		/* periodic_event_counter = 0x1234 */
		0x02,			/* sample_count */
		0x0A, 0x0B, 0x0C, 0x0D,	/* 2 * {I, Q} */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_CONNLESS_IQ, rep.subevent);
	ATF_CHECK_EQ(0x0002, rep.sync_handle);
	ATF_CHECK_EQ(37, rep.channel_index);
	ATF_CHECK_EQ(-160, (int)rep.iq_rssi);
	ATF_CHECK_EQ(0x01, rep.rssi_antenna_id);
	ATF_CHECK_EQ(0x00, rep.cte_type);
	ATF_CHECK_EQ(0x01, rep.slot_durations);
	ATF_CHECK_EQ(0x1234, rep.event_counter);
	ATF_CHECK_EQ(2, rep.sample_count);
	ATF_CHECK(rep.iq_samples != NULL);
	ATF_CHECK_EQ(0x0A, rep.iq_samples[0]);
	ATF_CHECK_EQ(0x0D, rep.iq_samples[3]);

	/* sample_count that overruns the packet is malformed. */
	pkt[15] = 0x20;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
}

ATF_TC_WITHOUT_HEAD(decode_connection_iq_report);
ATF_TC_BODY(decode_connection_iq_report, tc)
{
	/* §7.7.65.22, subevent 0x16, 1 IQ sample pair. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 16, BT_PDF_SUBEVENT_CONN_IQ,
		0x40, 0x00,		/* connection_handle = 0x0040 */
		0x02,			/* rx_phy = 2M */
		0x0A,			/* data_channel_index = 10 */
		0x60, 0xFF,		/* rssi = -160 */
		0x03,			/* rssi_antenna_id */
		0x00,			/* cte_type = AoA */
		0x02,			/* slot_durations = 2us */
		0x00,			/* packet_status */
		0x21, 0x43,		/* connection_event_counter = 0x4321 */
		0x01,			/* sample_count */
		0x7F, 0x80,		/* {I, Q} */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_CONN_IQ, rep.subevent);
	ATF_CHECK_EQ(0x0040, rep.connection_handle);
	ATF_CHECK_EQ(0x02, rep.rx_phy);
	ATF_CHECK_EQ(10, rep.data_channel_index);
	ATF_CHECK_EQ(-160, (int)rep.iq_rssi);
	ATF_CHECK_EQ(0x03, rep.rssi_antenna_id);
	ATF_CHECK_EQ(0x00, rep.cte_type);
	ATF_CHECK_EQ(0x02, rep.slot_durations);
	ATF_CHECK_EQ(0x4321, rep.event_counter);
	ATF_CHECK_EQ(1, rep.sample_count);
	ATF_CHECK(rep.iq_samples != NULL);
	ATF_CHECK_EQ(0x7F, rep.iq_samples[0]);
	ATF_CHECK_EQ(0x80, rep.iq_samples[1]);

	pkt[11] = 0x03;		/* reserved CTE_Type */
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
}

ATF_TC_WITHOUT_HEAD(decode_cte_request_failed);
ATF_TC_BODY(decode_cte_request_failed, tc)
{
	/* §7.7.65.23, subevent 0x17. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 4, BT_PDF_SUBEVENT_CTE_FAILED,
		0x1A,			/* status = failure code */
		0x40, 0x00,		/* connection_handle = 0x0040 */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_CTE_FAILED, rep.subevent);
	ATF_CHECK(rep.has_status);
	ATF_CHECK_EQ(0x1A, rep.status);
	ATF_CHECK_EQ(0x0040, rep.connection_handle);
}

ATF_TC_WITHOUT_HEAD(decode_past_received);
ATF_TC_BODY(decode_past_received, tc)
{
	/* §7.7.65.24, subevent 0x18. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 20, BT_PDF_SUBEVENT_PAST_RECEIVED,
		0x00,			/* status */
		0x40, 0x00,		/* connection_handle = 0x0040 */
		0x34, 0x12,		/* service_data = 0x1234 */
		0x05, 0x00,		/* sync_handle = 0x0005 */
		0x03,			/* advertising_sid */
		0x00,			/* advertiser_addr_type = public */
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,	/* advertiser_addr */
		0x01,			/* advertiser_phy = 1M */
		0x80, 0x0C,		/* periodic_adv_interval = 0x0C80 */
		0x00,			/* advertiser_clock_accuracy */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_PAST_RECEIVED, rep.subevent);
	ATF_CHECK(rep.has_status);
	ATF_CHECK_EQ(0x00, rep.status);
	ATF_CHECK_EQ(0x0040, rep.connection_handle);
	ATF_CHECK_EQ(0x1234, rep.service_data);
	ATF_CHECK_EQ(0x0005, rep.sync_handle);
	ATF_CHECK_EQ(0x03, rep.advertising_sid);
	ATF_CHECK_EQ(0x00, rep.advertiser_addr_type);
	ATF_CHECK_EQ(0xAA, rep.advertiser_addr[0]);
	ATF_CHECK_EQ(0xFF, rep.advertiser_addr[5]);
	ATF_CHECK_EQ(0x01, rep.advertiser_phy);
	ATF_CHECK_EQ(0x0C80, rep.periodic_adv_interval);
}

/*
 * Finding 124: Advertiser_PHY = LE 2M (0x02) is valid (0x01=1M, 0x02=2M,
 * 0x03=Coded) and a genuine sync/PAST on a 2M periodic train must decode,
 * not be rejected as malformed.
 */
ATF_TC_WITHOUT_HEAD(decode_sync_established_2m_phy);
ATF_TC_BODY(decode_sync_established_2m_phy, tc)
{
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 16, BT_PDF_SUBEVENT_SYNC_ESTABLISHED,
		0x00,			/* status = success */
		0x02, 0x00,		/* sync_handle */
		0x05,			/* advertising_sid */
		0x01,			/* advertiser_addr_type */
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x02,			/* advertiser_phy = 2M (finding 124) */
		0x80, 0x0C,		/* periodic_adv_interval */
		0x00,			/* clock accuracy */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep),
	    "a 2M periodic-adv sync must not be rejected");
	ATF_CHECK_EQ(0x02, rep.advertiser_phy);
}

ATF_TC_WITHOUT_HEAD(decode_past_received_2m_phy);
ATF_TC_BODY(decode_past_received_2m_phy, tc)
{
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 20, BT_PDF_SUBEVENT_PAST_RECEIVED,
		0x00,			/* status = success */
		0x40, 0x00,		/* connection_handle */
		0x34, 0x12,		/* service_data */
		0x05, 0x00,		/* sync_handle */
		0x03,			/* advertising_sid */
		0x00,			/* advertiser_addr_type */
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x02,			/* advertiser_phy = 2M (finding 124) */
		0x80, 0x0C,		/* periodic_adv_interval */
		0x00,			/* clock accuracy */
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ_MSG(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep),
	    "a 2M PAST must not be rejected");
	ATF_CHECK_EQ(0x02, rep.advertiser_phy);
}

ATF_TC_WITHOUT_HEAD(decode_not_owned_subevent);
ATF_TC_BODY(decode_not_owned_subevent, tc)
{
	/* A connection-management subevent is decoded elsewhere: seam yields 1. */
	uint8_t pkt[] = {
		0x04, BT_PDF_EVENT_LE_META, 3, BT_PDF_SUBEVENT_CONN_COMPLETE, 0x00, 0x00,
	};
	struct blued_le_meta_report rep;

	ATF_CHECK_EQ_MSG(1, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep),
	    "non-owned subevent must return 1 for the caller to handle");
	ATF_CHECK_EQ(BT_PDF_SUBEVENT_CONN_COMPLETE, rep.subevent);
}

/*
 * Keep one decoder instantiation complete.  The production decoder is inline
 * and also used by the power-control and ISO programs; this matrix verifies
 * every owned subevent's fixed-size boundary in one translation unit.
 */
ATF_TC_WITHOUT_HEAD(decode_all_owned_boundary_matrix);
ATF_TC_BODY(decode_all_owned_boundary_matrix, tc)
{
	static const struct {
		uint8_t subevent;
		size_t params_len;
	} cases[] = {
		{ BT_PDF_SUBEVENT_SYNC_ESTABLISHED,
		    BT_PDF_LEN_SYNC_ESTABLISHED },
		{ BT_PDF_SUBEVENT_PERIODIC_REPORT,
		    BT_PDF_LEN_PERIODIC_REPORT_FIXED },
		{ BT_PDF_SUBEVENT_SYNC_LOST,
		    BT_PDF_LEN_SYNC_LOST },
		{ BT_PDF_SUBEVENT_CONNLESS_IQ,
		    BT_PDF_LEN_CONNLESS_IQ_FIXED },
		{ BT_PDF_SUBEVENT_CONN_IQ,
		    BT_PDF_LEN_CONN_IQ_FIXED },
		{ BT_PDF_SUBEVENT_CTE_FAILED,
		    BT_PDF_LEN_CTE_FAILED },
		{ BT_PDF_SUBEVENT_PAST_RECEIVED,
		    BT_PDF_LEN_PAST_RECEIVED },
		{ BT_PDF_SUBEVENT_PATH_LOSS,
		    BT_PDF_LEN_PATH_LOSS },
		{ BT_PDF_SUBEVENT_TX_POWER_REPORTING,
		    BT_PDF_LEN_TX_POWER_REPORTING },
		{ BT_PDF_SUBEVENT_CIS_ESTABLISHED,
		    BT_PDF_LEN_CIS_ESTABLISHED },
		{ BT_PDF_SUBEVENT_CIS_REQUEST, BT_PDF_LEN_CIS_REQUEST },
		{ BT_PDF_SUBEVENT_CREATE_BIG_COMPLETE,
		    BT_PDF_LEN_CREATE_BIG_FIXED },
		{ BT_PDF_SUBEVENT_TERMINATE_BIG_COMPLETE,
		    BT_PDF_LEN_TERMINATE_BIG },
		{ BT_PDF_SUBEVENT_BIG_SYNC_ESTABLISHED,
		    BT_PDF_LEN_BIG_SYNC_FIXED },
		{ BT_PDF_SUBEVENT_BIG_SYNC_LOST,
		    BT_PDF_LEN_BIG_SYNC_LOST },
	};
	struct blued_le_meta_report rep;
	uint8_t pkt[64];
	size_t i, len;

	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(NULL, 0, &rep));
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt, sizeof(pkt), NULL));
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_PDF_H4_EVENT_PACKET;
	pkt[1] = BT_PDF_EVENT_LE_META;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF - 1, &rep));
	pkt[0] = BT_PDF_H4_EVENT_PACKET;
	pkt[1] = 0xff;
	ATF_CHECK_EQ(1, blued_parse_le_meta_event(pkt, 3, &rep));

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(pkt, 0, sizeof(pkt));
		pkt[0] = 0x04;
		pkt[1] = BT_PDF_EVENT_LE_META;
		pkt[2] = (uint8_t)(cases[i].params_len + 1);
		pkt[3] = cases[i].subevent;
		/* Supply the minimum defined values for closed fields; an all-zero
		 * envelope is not a valid PHY/slot tuple for several subevents. */
		switch (cases[i].subevent) {
		case BT_PDF_SUBEVENT_SYNC_ESTABLISHED:
			pkt[BLUED_LE_META_PARAM_OFF + 11] = 0x01;
			pkt[BLUED_LE_META_PARAM_OFF + 12] = 0x06;
			break;
		case BT_PDF_SUBEVENT_CONNLESS_IQ:
			pkt[BLUED_LE_META_PARAM_OFF + 7] = 0x01;
			break;
		case BT_PDF_SUBEVENT_CONN_IQ:
			pkt[BLUED_LE_META_PARAM_OFF + 2] = 0x01;
			pkt[BLUED_LE_META_PARAM_OFF + 8] = 0x01;
			break;
		case BT_PDF_SUBEVENT_PAST_RECEIVED:
			pkt[BLUED_LE_META_PARAM_OFF + 15] = 0x01;
			pkt[BLUED_LE_META_PARAM_OFF + 16] = 0x06;
			break;
		case BT_PDF_SUBEVENT_TX_POWER_REPORTING:
			pkt[BLUED_LE_META_PARAM_OFF + 4] = 0x01;
			break;
		default:
			break;
		}
		len = BLUED_LE_META_PARAM_OFF + cases[i].params_len;
		ATF_REQUIRE_MSG(len <= sizeof(pkt), "subevent 0x%02x",
		    cases[i].subevent);
		ATF_CHECK_MSG(blued_parse_le_meta_event(pkt, len, &rep) == 0,
		    "subevent 0x%02x exact fixed length", cases[i].subevent);
		ATF_CHECK_EQ(cases[i].subevent, rep.subevent);
		ATF_CHECK_MSG(blued_parse_le_meta_event(pkt, len - 1, &rep) == -1,
		    "subevent 0x%02x truncated", cases[i].subevent);
	}

	/* Zero-length variable payloads are represented by NULL views. */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_PDF_H4_EVENT_PACKET;
	pkt[1] = BT_PDF_EVENT_LE_META;
	pkt[2] = 1 + BT_PDF_LEN_PERIODIC_REPORT_FIXED;
	pkt[3] = BT_PDF_SUBEVENT_PERIODIC_REPORT;
	ATF_REQUIRE_EQ(0, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF + BT_PDF_LEN_PERIODIC_REPORT_FIXED,
	    &rep));
	ATF_CHECK(rep.data == NULL);
	pkt[2] = 1 + BT_PDF_LEN_CREATE_BIG_FIXED;
	pkt[3] = BT_PDF_SUBEVENT_CREATE_BIG_COMPLETE;
	ATF_REQUIRE_EQ(0, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF + BT_PDF_LEN_CREATE_BIG_FIXED,
	    &rep));
	ATF_CHECK(rep.bis_handles == NULL);

	/* Variable tails must fit the bytes following their fixed headers. */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_PDF_H4_EVENT_PACKET;
	pkt[1] = BT_PDF_EVENT_LE_META;
	pkt[2] = 1 + BT_PDF_LEN_CONN_IQ_FIXED;
	pkt[3] = BT_PDF_SUBEVENT_CONN_IQ;
	pkt[BLUED_LE_META_PARAM_OFF + 12] = 1;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF + BT_PDF_LEN_CONN_IQ_FIXED,
	    &rep));
	pkt[2] = 1 + BT_PDF_LEN_CREATE_BIG_FIXED;
	pkt[3] = BT_PDF_SUBEVENT_CREATE_BIG_COMPLETE;
	pkt[BLUED_LE_META_PARAM_OFF + 17] = 1;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF + BT_PDF_LEN_CREATE_BIG_FIXED,
	    &rep));
	pkt[2] = 1 + BT_PDF_LEN_BIG_SYNC_FIXED;
	pkt[3] = BT_PDF_SUBEVENT_BIG_SYNC_ESTABLISHED;
	pkt[BLUED_LE_META_PARAM_OFF + 13] = 1;
	ATF_CHECK_EQ(-1, blued_parse_le_meta_event(pkt,
	    BLUED_LE_META_PARAM_OFF + BT_PDF_LEN_BIG_SYNC_FIXED, &rep));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, periodic_adv_params_layout);
	ATF_TP_ADD_TC(tp, periodic_adv_data_layout);
	ATF_TP_ADD_TC(tp, periodic_adv_enable_layout);
	ATF_TP_ADD_TC(tp, periodic_adv_create_sync_layout);
	ATF_TP_ADD_TC(tp, past_transfer_layout);
	ATF_TP_ADD_TC(tp, past_params_layout);
	ATF_TP_ADD_TC(tp, cte_connless_tx_params_layout);
	ATF_TP_ADD_TC(tp, cte_conn_tx_params_layout);
	ATF_TP_ADD_TC(tp, conn_cte_req_enable_layout);
	ATF_TP_ADD_TC(tp, read_antenna_info_decode);
	ATF_TP_ADD_TC(tp, decode_periodic_adv_sync_established);
	ATF_TP_ADD_TC(tp, decode_periodic_adv_report);
	ATF_TP_ADD_TC(tp, decode_periodic_adv_sync_lost);
	ATF_TP_ADD_TC(tp, decode_connectionless_iq_report);
	ATF_TP_ADD_TC(tp, decode_connection_iq_report);
	ATF_TP_ADD_TC(tp, decode_cte_request_failed);
	ATF_TP_ADD_TC(tp, decode_past_received);
	ATF_TP_ADD_TC(tp, decode_sync_established_2m_phy);
	ATF_TP_ADD_TC(tp, decode_past_received_2m_phy);
	ATF_TP_ADD_TC(tp, decode_not_owned_subevent);
	ATF_TP_ADD_TC(tp, decode_all_owned_boundary_matrix);

	return (atf_no_error());
}
