/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * hci_emulator_test.c - spec-anchored unit tests for the userspace HCI
 * controller emulator (hci_emulator.c).
 *
 * The oracle is the Bluetooth Core Spec Vol 4 Part E (HCI).  Each case
 * asserts the exact emitted event bytes and cites the spec section.
 * No daemon globals, no kernel, no netgraph -- the emulator is fed typed
 * command packets and its typed event output is captured via a callback.
 */

#include <atf-c.h>

#include <sys/types.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include <stdint.h>
#include <string.h>

#include "hci_emulator.h"
#include "spec_hci_emulator_oracles.h"

/* ================================================================
 * Output capture
 * ================================================================ */
static uint8_t	g_pkt[512];
static size_t	g_len;
static int	g_count;

static void
cap_out(void *ctx, const uint8_t *pkt, size_t len)
{

	(void)ctx;
	if (len > sizeof(g_pkt))
		len = sizeof(g_pkt);
	memcpy(g_pkt, pkt, len);
	g_len = len;
	g_count++;
}

static void
cap_reset(void)
{

	memset(g_pkt, 0, sizeof(g_pkt));
	g_len = 0;
	g_count = 0;
}

/* Feed one typed command packet: 0x01 | opcode(2,LE) | plen | params. */
static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params,
    uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = HCI_EMU_SPEC_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/*
 * Assert the captured event is a Command Complete (§7.7.14) for opcode
 * with the given status and return-parameter length (rplen includes the
 * leading status byte).
 */
static void
check_cc(uint16_t opcode, uint8_t status, uint8_t rplen)
{

	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_COMMAND_COMPLETE, g_pkt[1]);
	ATF_CHECK_EQ((uint8_t)(HCI_EMU_SPEC_CC_FIXED_PARAM_LEN + rplen),
	    g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_NUM_COMMAND_PACKETS, g_pkt[3]);
	ATF_CHECK_EQ(opcode, le16dec(&g_pkt[4]));		/* echoed opcode */
	ATF_CHECK_EQ(status, g_pkt[6]);				/* status first */
	ATF_CHECK_EQ((size_t)HCI_EMU_SPEC_CC_TYPED_HEADER_LEN + rplen, g_len);
}

/* ================================================================
 * Full blued init sequence -> Command Complete bytes per command
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_init_sequence);
ATF_TC_BODY(test_init_sequence, tc)
{
	struct hci_emu *e;
	const uint8_t bd[6] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 };
	const uint8_t lmp[8] = { 0xff, 0xfe, 0x8f, 0xfe, 0xdb, 0xff, 0x7b, 0x87 };
	const uint8_t lef[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	uint8_t cmds[64];
	uint8_t p[64];
	int i;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	/* Pin deterministic controller identity. */
	hci_emu_set_bd_addr(e, bd);
	hci_emu_set_local_version(e, 0x0c, 0x1234, 0x0c, 0x000f, 0x5678);
	hci_emu_set_buffer_size(e, 1021, 96, 8, 0);
	hci_emu_set_le_buffer_size(e, 251, 12, 512, 4);
	hci_emu_set_lmp_features(e, lmp);
	hci_emu_set_le_features(e, lef);
	hci_emu_set_num_adv_sets(e, 5);
	for (i = 0; i < 64; i++)
		cmds[i] = (uint8_t)i;
	hci_emu_set_supported_commands(e, cmds);

	/* Reset (§7.3.2): status only. */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_RESET, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_RESET, HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	/* Read_BD_ADDR (§7.4.6): status + BD_ADDR(6). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_READ_BD_ADDR, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_READ_BD_ADDR, HCI_EMU_SPEC_STATUS_SUCCESS, 7);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[7], bd, 6));

	/* Read_Local_Version_Information (§7.4.1). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_READ_LOCAL_VERSION, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_READ_LOCAL_VERSION,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 9);
	ATF_CHECK_EQ(0x0c, g_pkt[7]);			/* hci_version */
	ATF_CHECK_EQ(0x1234, le16dec(&g_pkt[8]));	/* hci_revision */
	ATF_CHECK_EQ(0x0c, g_pkt[10]);			/* lmp_version */
	ATF_CHECK_EQ(0x000f, le16dec(&g_pkt[11]));	/* manufacturer */
	ATF_CHECK_EQ(0x5678, le16dec(&g_pkt[13]));	/* lmp_subversion */

	/* Read_Buffer_Size (§7.4.5). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_READ_BUFFER_SIZE, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_READ_BUFFER_SIZE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 8);
	ATF_CHECK_EQ(1021, le16dec(&g_pkt[7]));		/* max_acl_size */
	ATF_CHECK_EQ(96, g_pkt[9]);			/* max_sco_size */
	ATF_CHECK_EQ(8, le16dec(&g_pkt[10]));		/* num_acl_pkt */
	ATF_CHECK_EQ(0, le16dec(&g_pkt[12]));		/* num_sco_pkt */

	/* Read_Local_Supported_Commands (§7.4.2): status + 64 bytes. */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_READ_LOCAL_COMMANDS, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_READ_LOCAL_COMMANDS,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 65);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[7], cmds, 64));

	/* Read_Local_Supported_Features (§7.4.3): status + LMP features(8). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_READ_LOCAL_FEATURES, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_READ_LOCAL_FEATURES,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 9);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[7], lmp, 8));

	/* Write_LE_Host_Supported (§7.3.79): status only. */
	cap_reset();
	p[0] = 0x01;	/* LE_Supported_Host */
	p[1] = 0x00;	/* Simultaneous_LE_Host */
	feed_cmd(e, HCI_EMU_SPEC_OP_WRITE_LE_HOST_SUPPORTED, p, 2);
	check_cc(HCI_EMU_SPEC_OP_WRITE_LE_HOST_SUPPORTED,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	/* Set_Event_Mask (§7.3.1): status only; state stored. */
	cap_reset();
	le64enc(p, 0x2000800002008090ULL);
	feed_cmd(e, HCI_EMU_SPEC_OP_SET_EVENT_MASK, p, 8);
	check_cc(HCI_EMU_SPEC_OP_SET_EVENT_MASK,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(0x2000800002008090ULL, hci_emu_get_event_mask(e));

	/* LE_Set_Event_Mask (§7.8.1): status only; state stored. */
	cap_reset();
	le64enc(p, 0x000000000000001fULL);
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_EVENT_MASK, p, 8);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_EVENT_MASK,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(0x000000000000001fULL, hci_emu_get_le_event_mask(e));

	/* LE_Read_Buffer_Size v1 (§7.8.2). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_READ_BUFFER_SIZE, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_LE_READ_BUFFER_SIZE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 4);
	ATF_CHECK_EQ(251, le16dec(&g_pkt[7]));	/* hc_le_data_packet_length */
	ATF_CHECK_EQ(12, g_pkt[9]);		/* hc_total_num_le_data_pkts */

	/* LE_Read_Buffer_Size v2 (§7.8.2). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_READ_BUFFER_SIZE_V2, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_LE_READ_BUFFER_SIZE_V2,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 7);
	ATF_CHECK_EQ(251, le16dec(&g_pkt[7]));	/* le_data_packet_length */
	ATF_CHECK_EQ(12, g_pkt[9]);		/* le_num_data_packets */
	ATF_CHECK_EQ(512, le16dec(&g_pkt[10]));	/* iso_data_packet_length */
	ATF_CHECK_EQ(4, g_pkt[12]);		/* iso_num_data_packets */

	/* LE_Read_Local_Supported_Features (§7.8.3): status + LE features(8). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_READ_LOCAL_FEATURES, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_LE_READ_LOCAL_FEATURES,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 9);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[7], lef, 8));

	/* LE_Read_Number_of_Supported_Advertising_Sets (§7.8.58). */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_READ_NUM_ADV_SETS, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_LE_READ_NUM_ADV_SETS,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 2);
	ATF_CHECK_EQ(5, g_pkt[7]);		/* num_supported_adv_sets */

	/* LE_Set_Random_Address (§7.8.4): status only; state stored. */
	cap_reset();
	{
		const uint8_t ra[6] = { 0xc0, 0xff, 0xee, 0x00, 0x11, 0x22 };
		uint8_t got[6];

		feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_RANDOM_ADDRESS, ra, 6);
		check_cc(HCI_EMU_SPEC_OP_LE_SET_RANDOM_ADDRESS,
		    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
		hci_emu_get_random_addr(e, got);
		ATF_CHECK_EQ(0, memcmp(got, ra, 6));
	}

	/* LE_Set_Advertising_Parameters (§7.8.5): status only. */
	cap_reset();
	memset(p, 0, sizeof(p));
	le16enc(&p[0], 0x0020);		/* interval_min */
	le16enc(&p[2], 0x0040);		/* interval_max */
	p[4] = 0x00;			/* ADV_IND */
	p[5] = 0x00;			/* own_address_type */
	p[6] = 0x00;			/* direct_address_type */
	/* p[7..12] direct_address = 0 */
	p[13] = 0x07;			/* channel map: all 3 */
	p[14] = 0x00;			/* filter policy */
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_ADV_PARAMS, p, 15);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_ADV_PARAMS,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	/* LE_Set_Advertising_Data (§7.8.7): status only. */
	cap_reset();
	memset(p, 0, sizeof(p));
	p[0] = 3;			/* significant length */
	p[1] = 2;			/* AD element length */
	p[2] = 0x01;			/* Flags */
	p[3] = 0x06;
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_ADV_DATA, p, 32);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_ADV_DATA,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	/* LE_Set_Scan_Response_Data (§7.8.8): status only. */
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_SCAN_RSP_DATA, p, 32);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_SCAN_RSP_DATA,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	/* LE_Set_Scan_Parameters (§7.8.10): status only. */
	cap_reset();
	memset(p, 0, sizeof(p));
	p[0] = 0x01;			/* active scan */
	le16enc(&p[1], 0x0060);		/* interval */
	le16enc(&p[3], 0x0030);		/* window */
	p[5] = 0x00;			/* own address type */
	p[6] = 0x00;			/* filter policy */
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_SCAN_PARAMS, p, 7);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_SCAN_PARAMS,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	hci_emu_free(e);
}

/* ================================================================
 * Unknown opcode -> Command Complete carrying Unknown HCI Command 0x01
 * (Vol 4 Part E §7.7.14 + §1.3 error-code table).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_unknown_opcode);
ATF_TC_BODY(test_unknown_opcode, tc)
{
	struct hci_emu *e;
	uint16_t bogus = HCI_EMU_SPEC_UNKNOWN_VENDOR_OPCODE;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	cap_reset();
	feed_cmd(e, bogus, NULL, 0);
	ATF_CHECK_EQ(1, g_count);
	check_cc(bogus, HCI_EMU_SPEC_ERR_UNKNOWN_HCI_COMMAND, 1);

	hci_emu_free(e);
}

/* ================================================================
 * LE_Set_Advertise_Enable(1) then (0): state flips, each status 0x00.
 * (Vol 4 Part E §7.8.9)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_adv_enable_toggle);
ATF_TC_BODY(test_adv_enable_toggle, tc)
{
	struct hci_emu *e;
	uint8_t on = HCI_EMU_SPEC_ENABLED, off = HCI_EMU_SPEC_DISABLED;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	ATF_CHECK_EQ(0, hci_emu_get_adv_enable(e));

	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_ADV_ENABLE, &on, 1);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_ADV_ENABLE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(1, hci_emu_get_adv_enable(e));

	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_ADV_ENABLE, &off, 1);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_ADV_ENABLE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(0, hci_emu_get_adv_enable(e));

	hci_emu_free(e);
}

/* ================================================================
 * LE_Set_Scan_Enable / LE_Add_Device_To_Resolving_List /
 * LE_Set_Address_Resolution_Enable: status 0x00 and state updated.
 * (Vol 4 Part E §7.8.11, §7.8.38, §7.8.44)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_scan_and_resolving_state);
ATF_TC_BODY(test_scan_and_resolving_state, tc)
{
	struct hci_emu *e;
	uint8_t p[64];

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	/* LE_Set_Scan_Enable(enable=1, filter_dups=1). */
	cap_reset();
	p[0] = HCI_EMU_SPEC_ENABLED;
	p[1] = HCI_EMU_SPEC_ENABLED;
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_SCAN_ENABLE, p, 2);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_SCAN_ENABLE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(1, hci_emu_get_scan_enable(e));

	/* LE_Add_Device_To_Resolving_List: addr_type + addr(6) + 2*IRK(16). */
	cap_reset();
	ATF_CHECK_EQ(0, hci_emu_get_resolving_list_count(e));
	memset(p, 0, sizeof(p));
	p[0] = HCI_EMU_SPEC_ADDR_PUBLIC;
	p[1] = 0xaa; p[2] = 0xbb; p[3] = 0xcc;
	p[4] = 0xdd; p[5] = 0xee; p[6] = 0xff;		/* identity addr */
	/* p[7..22] peer IRK, p[23..38] local IRK (all zero is fine) */
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_ADD_RESOLVING_LIST, p, 1 + 6 + 16 + 16);
	check_cc(HCI_EMU_SPEC_OP_LE_ADD_RESOLVING_LIST,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(1, hci_emu_get_resolving_list_count(e));

	/* LE_Set_Address_Resolution_Enable(1). */
	cap_reset();
	ATF_CHECK_EQ(0, hci_emu_get_addr_resolution_enable(e));
	p[0] = HCI_EMU_SPEC_ENABLED;
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_ADDR_RES_ENABLE, p, 1);
	check_cc(HCI_EMU_SPEC_OP_LE_SET_ADDR_RES_ENABLE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(1, hci_emu_get_addr_resolution_enable(e));

	hci_emu_free(e);
}

/* ================================================================
 * Inject LE Connection Complete: LE Meta (0x3E) subevent 0x01.
 * Vol 4 Part E §7.7.65.1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_inject_le_connection_complete);
ATF_TC_BODY(test_inject_le_connection_complete, tc)
{
	struct hci_emu *e;
	const uint8_t peer[6] = { 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	cap_reset();
	hci_emu_inject_le_connection_complete(e,
	    HCI_EMU_SPEC_STATUS_SUCCESS,
	    0x0040,		/* connection handle */
	    HCI_EMU_SPEC_ROLE_PERIPHERAL,
	    HCI_EMU_SPEC_ADDR_PUBLIC,
	    peer,
	    0x0028,		/* connection interval */
	    0x0000,		/* peripheral latency */
	    0x00c8,		/* supervision timeout */
	    0x00);		/* central clock accuracy */

	ATF_CHECK_EQ(1, g_count);
	/* Typed header: 0x04 | 0x3E | param_len(19). */
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_LE_META, g_pkt[1]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_CONN_COMPLETE_PARAM_LEN, g_pkt[2]);
	ATF_CHECK_EQ((size_t)3 + HCI_EMU_SPEC_CONN_COMPLETE_PARAM_LEN, g_len);
	/* Params. */
	ATF_CHECK_EQ(HCI_EMU_SPEC_SUBEVENT_LE_CONN_COMPLETE, g_pkt[3]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_STATUS_SUCCESS, g_pkt[4]);
	ATF_CHECK_EQ(0x0040, le16dec(&g_pkt[5]));	/* handle */
	ATF_CHECK_EQ(HCI_EMU_SPEC_ROLE_PERIPHERAL, g_pkt[7]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_ADDR_PUBLIC, g_pkt[8]);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[9], peer, 6));	/* peer addr */
	ATF_CHECK_EQ(0x0028, le16dec(&g_pkt[15]));	/* interval */
	ATF_CHECK_EQ(0x0000, le16dec(&g_pkt[17]));	/* latency */
	ATF_CHECK_EQ(0x00c8, le16dec(&g_pkt[19]));	/* supervision timeout */
	ATF_CHECK_EQ(0x00, g_pkt[21]);			/* clock accuracy */

	hci_emu_free(e);
}

/* ================================================================
 * Inject LE Advertising Report: LE Meta (0x3E) subevent 0x02.
 * Vol 4 Part E §7.7.65.2.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_inject_le_adv_report);
ATF_TC_BODY(test_inject_le_adv_report, tc)
{
	struct hci_emu *e;
	const uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	const uint8_t ad[] = { 0x02, 0x01, 0x06, 0x03, 0x03, 0x0f, 0x18 };
	uint8_t adlen = (uint8_t)sizeof(ad);

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	cap_reset();
	hci_emu_inject_le_adv_report(e,
	    HCI_EMU_SPEC_ADV_IND,
	    HCI_EMU_SPEC_ADDR_RANDOM,
	    addr,
	    ad, adlen,
	    (int8_t)-60);	/* RSSI */

	ATF_CHECK_EQ(1, g_count);
	/* Typed header: 0x04 | 0x3E | param_len. */
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_LE_META, g_pkt[1]);
	/* Params: subevent(1)+num(1)+etype(1)+atype(1)+addr(6)+dlen(1)+
	 * data(adlen)+rssi(1). */
	ATF_CHECK_EQ((uint8_t)(HCI_EMU_SPEC_ADV_REPORT_FIXED_PARAM_LEN + adlen),
	    g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_SUBEVENT_LE_ADV_REPORT, g_pkt[3]);
	ATF_CHECK_EQ(1, g_pkt[4]);			/* num_reports */
	ATF_CHECK_EQ(HCI_EMU_SPEC_ADV_IND, g_pkt[5]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_ADDR_RANDOM, g_pkt[6]);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[7], addr, 6));	/* address */
	ATF_CHECK_EQ(adlen, g_pkt[13]);			/* data length */
	ATF_CHECK_EQ(0, memcmp(&g_pkt[14], ad, adlen));	/* AD data */
	ATF_CHECK_EQ((uint8_t)-60, g_pkt[14 + adlen]);	/* RSSI */

	hci_emu_free(e);
}

ATF_TC_WITHOUT_HEAD(test_periodic_adv_and_sync_events);
ATF_TC_BODY(test_periodic_adv_and_sync_events, tc)
{
	struct hci_emu *e;
	const uint8_t params[] = { 0, 0x06, 0, 0x10, 0, 0, 0 };
	const uint8_t enable[] = { 1, 0 };
	const uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	const uint8_t data[] = { 0x02, 0x01, 0x06 };

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_PARAMS, params,
	    sizeof(params));
	check_cc(HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_PARAMS,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_ENABLE, enable,
	    sizeof(enable));
	check_cc(HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_ENABLE,
	    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	ATF_CHECK_EQ(1, hci_emu_get_periodic_adv_enable(e));
	/* PAST receiver accepts an established synchronization handle. */
	{
		const uint8_t rcv_enable[] = { 0x23, 0x01, 0x01 };
		feed_cmd(e, HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_RCV_ENABLE,
		    rcv_enable,
		    sizeof(rcv_enable));
		check_cc(HCI_EMU_SPEC_OP_LE_SET_PERIODIC_ADV_RCV_ENABLE,
		    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
		const uint8_t transfer[] = { 0x40, 0x00, 0x34, 0x12, 0x23, 0x01 };
		feed_cmd(e, HCI_EMU_SPEC_OP_LE_PERIODIC_ADV_SYNC_TRANSFER,
		    transfer,
		    sizeof(transfer));
		check_cc(HCI_EMU_SPEC_OP_LE_PERIODIC_ADV_SYNC_TRANSFER,
		    HCI_EMU_SPEC_STATUS_SUCCESS, 1);
	}

	cap_reset();
	hci_emu_inject_periodic_sync_established(e, 0, 0x123, 4, 0, addr, 1,
	    0x100);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_LE_META, g_pkt[1]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_PERIODIC_SYNC_EST_PARAM_LEN, g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_SUBEVENT_PERIODIC_SYNC_ESTABLISHED, g_pkt[3]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_STATUS_SUCCESS, g_pkt[4]);
	ATF_CHECK_EQ(0x123, le16dec(&g_pkt[5]));
	ATF_CHECK_EQ(4, g_pkt[7]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_ADDR_PUBLIC, g_pkt[8]);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[9], addr, sizeof(addr)));
	ATF_CHECK_EQ(1, g_pkt[15]);
	ATF_CHECK_EQ(0x100, le16dec(&g_pkt[16]));
	ATF_CHECK_EQ(0, g_pkt[18]);
	ATF_CHECK_EQ((size_t)3 + HCI_EMU_SPEC_PERIODIC_SYNC_EST_PARAM_LEN,
	    g_len);
	hci_emu_inject_periodic_adv_report(e, 0x123, -4, -60, 0, 0, data,
	    sizeof(data));
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_LE_META, g_pkt[1]);
	ATF_CHECK_EQ((uint8_t)(HCI_EMU_SPEC_PERIODIC_REPORT_FIXED_PARAM_LEN +
	    sizeof(data)), g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_SUBEVENT_PERIODIC_ADV_REPORT, g_pkt[3]);
	ATF_CHECK_EQ(0x123, le16dec(&g_pkt[4]));
	ATF_CHECK_EQ((uint8_t)-4, g_pkt[6]);
	ATF_CHECK_EQ((uint8_t)-60, g_pkt[7]);
	ATF_CHECK_EQ(0, g_pkt[8]);
	ATF_CHECK_EQ(0, g_pkt[9]);
	ATF_CHECK_EQ(sizeof(data), g_pkt[10]);
	ATF_CHECK_EQ(0, memcmp(&g_pkt[11], data, sizeof(data)));
	hci_emu_inject_periodic_sync_lost(e, 0x123);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_LE_META, g_pkt[1]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_PERIODIC_SYNC_LOST_PARAM_LEN, g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_SUBEVENT_PERIODIC_SYNC_LOST, g_pkt[3]);
	ATF_CHECK_EQ(0x123, le16dec(&g_pkt[4]));

	hci_emu_free(e);
}

/* ================================================================
 * Inject Disconnection Complete (0x05), Vol 4 Part E §7.7.5.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_inject_disconnection_complete);
ATF_TC_BODY(test_inject_disconnection_complete, tc)
{
	struct hci_emu *e;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	cap_reset();
	hci_emu_inject_disconnection_complete(e, 0x0040,
	    HCI_EMU_SPEC_REASON_REMOTE_USER_TERM);

	ATF_CHECK_EQ(1, g_count);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_PKT, g_pkt[0]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_EVENT_DISCON_COMPLETE, g_pkt[1]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_DISCON_COMPLETE_PARAM_LEN, g_pkt[2]);
	ATF_CHECK_EQ(HCI_EMU_SPEC_STATUS_SUCCESS, g_pkt[3]);
	ATF_CHECK_EQ(0x0040, le16dec(&g_pkt[4]));		/* handle */
	ATF_CHECK_EQ(HCI_EMU_SPEC_REASON_REMOTE_USER_TERM, g_pkt[6]);

	hci_emu_free(e);
}

/* ================================================================
 * Fault injection: force Reset to complete with Command Disallowed
 * (0x0C).  Vol 4 Part E §1.3 error-code table.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_fault_injection);
ATF_TC_BODY(test_fault_injection, tc)
{
	struct hci_emu *e;

	e = hci_emu_new();
	ATF_REQUIRE(e != NULL);
	hci_emu_set_output(e, cap_out, NULL);

	/* Force Reset to fail. */
	hci_emu_force_status(e, HCI_EMU_SPEC_OP_RESET,
	    HCI_EMU_SPEC_ERR_COMMAND_DISALLOWED);

	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_RESET, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_RESET, HCI_EMU_SPEC_ERR_COMMAND_DISALLOWED, 1);

	/* Clearing the override restores normal behavior (status 0x00). */
	hci_emu_clear_forced_status(e);
	cap_reset();
	feed_cmd(e, HCI_EMU_SPEC_OP_RESET, NULL, 0);
	check_cc(HCI_EMU_SPEC_OP_RESET, HCI_EMU_SPEC_STATUS_SUCCESS, 1);

	hci_emu_free(e);
}

/* ================================================================
 * ATF entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_init_sequence);
	ATF_TP_ADD_TC(tp, test_unknown_opcode);
	ATF_TP_ADD_TC(tp, test_adv_enable_toggle);
	ATF_TP_ADD_TC(tp, test_scan_and_resolving_state);
	ATF_TP_ADD_TC(tp, test_inject_le_connection_complete);
	ATF_TP_ADD_TC(tp, test_inject_le_adv_report);
	ATF_TP_ADD_TC(tp, test_periodic_adv_and_sync_events);
	ATF_TP_ADD_TC(tp, test_inject_disconnection_complete);
	ATF_TP_ADD_TC(tp, test_fault_injection);

	return (atf_no_error());
}
