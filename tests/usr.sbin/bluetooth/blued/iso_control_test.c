/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Conformance tests for the LE Isochronous (ISO) CONTROL-PLANE callers
 * that wire the ISO command encoders into a working data path: CIG
 * provisioning (LE Set CIG Parameters), per-direction ISO data-path setup
 * (LE Setup ISO Data Path), and the established-stream orchestration the
 * daemon runs when an LE CIS Established / Create BIG Complete / BIG Sync
 * Established event arrives.  Scope is the isochronous TRANSPORT only; the
 * LE Audio profiles that would consume the SDUs are out of scope.
 *
 * Oracle.  Every command byte offset and field asserted here is
 * hand-encoded from the Core Spec Vol 4 Part E (§7.8.97 LE Set CIG
 * Parameters, §7.8.109 LE Setup ISO Data Path; event formats §7.7.65.25,
 * .27, .29), cited per assertion — never captured from the code's output.
 *
 * Method.  The callers reach the controller through the ISO encoders in
 * hci_misc.c -> hci_devreq_logged() -> bt_devreq() (libbluetooth).  We
 * interpose bt_devreq at link time (-Wl,--wrap=bt_devreq).  Unlike the
 * single-command capture in iso_transport_test.c, __wrap_bt_devreq here
 * records a SEQUENCE of commands, so a caller that issues several Setup
 * ISO Data Path commands (both CIS directions, one per BIS) can be checked
 * command by command.  The established-stream tests build a real HCI LE
 * meta event, decode it through the production seam
 * (blued_parse_le_meta_event) and then drive the same per-handle loop the
 * daemon's event handler runs, so the event->data-path wiring is covered
 * end to end at the seam.
 */

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "ble_util.h"
#include "blued_le_meta.h"
#include "spec_iso_control_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

/* ================================================================
 * The --wrap seam: capture a SEQUENCE of built commands + responses.
 * ================================================================ */
#define CAP_MAX		8
struct captured_cmd {
	uint16_t	opcode;		/* r->opcode (host order) */
	uint8_t		event;		/* r->event expected completion */
	uint8_t		cmd[320];	/* r->cparam bytes */
	size_t		clen;		/* r->clen */
};

static struct {
	int			fail;		/* nonzero -> bt_devreq fails */
	int			fail_errno;
	uint8_t			payload[320];	/* return params, status first */
	size_t			payload_len;

	int			calls;		/* number of invocations */
	struct captured_cmd	c[CAP_MAX];	/* per-call capture */
} W;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	(void)s;
	(void)to;

	if (W.calls < CAP_MAX) {
		struct captured_cmd *cc = &W.c[W.calls];

		cc->opcode = r->opcode;
		cc->event = r->event;
		cc->clen = r->clen;
		memset(cc->cmd, 0, sizeof(cc->cmd));
		if (r->cparam != NULL && r->clen > 0) {
			size_t n = r->clen < sizeof(cc->cmd) ?
			    r->clen : sizeof(cc->cmd);
			memcpy(cc->cmd, r->cparam, n);
		}
	}
	W.calls++;

	if (W.fail) {
		errno = W.fail_errno;
		return (-1);
	}
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = W.payload_len < r->rlen ? W.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, W.payload, n);
	}
	return (0);
}

static void
reset(void)
{

	memset(&W, 0, sizeof(W));
}

static void
mock_ok_bytes(const void *p, size_t n)
{

	W.fail = 0;
	if (n > sizeof(W.payload))
		n = sizeof(W.payload);
	memcpy(W.payload, p, n);
	W.payload_len = n;
}

static void
mock_ok(void)
{
	uint8_t st = BT_ISO_SPEC_STATUS_SUCCESS;

	mock_ok_bytes(&st, 1);
}

/* Little-endian readers over a captured command buffer. */
static uint16_t
c_le16(const struct captured_cmd *cc, size_t off)
{

	return ((uint16_t)cc->cmd[off] | ((uint16_t)cc->cmd[off + 1] << 8));
}

static uint32_t
c_le24(const struct captured_cmd *cc, size_t off)
{

	return ((uint32_t)cc->cmd[off] | ((uint32_t)cc->cmd[off + 1] << 8) |
	    ((uint32_t)cc->cmd[off + 2] << 16));
}

/* ================================================================
 * §7.8.97  LE Set CIG Parameters — provisioning caller layout.
 *
 * CP header (15 octets): CIG_ID(1) | SDU_Interval_C_To_P(3 LE) |
 *   SDU_Interval_P_To_C(3 LE) | Worst_Case_SCA(1) | Packing(1) |
 *   Framing(1) | Max_Transport_Latency_C_To_P(2 LE) |
 *   Max_Transport_Latency_P_To_C(2 LE) | CIS_Count(1)
 * then CIS_Count * 9-octet records:
 *   CIS_ID(1) | Max_SDU_C_To_P(2 LE) | Max_SDU_P_To_C(2 LE) |
 *   PHY_C_To_P(1) | PHY_P_To_C(1) | RTN_C_To_P(1) | RTN_P_To_C(1)
 * RP: Status(1) | CIG_ID(1) | CIS_Count(1) | Connection_Handle[i](2 LE)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(setup_cig_layout);
ATF_TC_BODY(setup_cig_layout, tc)
{
	struct hci_cis_param cises[2] = {
		{ .cis_id = 0x01, .max_sdu_c_to_p = 0x00F0,
		  .max_sdu_p_to_c = 0x0000, .phy_c_to_p = 0x02,
		  .phy_p_to_c = 0x01, .rtn_c_to_p = 0x03, .rtn_p_to_c = 0x00 },
		{ .cis_id = 0x02, .max_sdu_c_to_p = 0x0000,
		  .max_sdu_p_to_c = 0x0064, .phy_c_to_p = 0x01,
		  .phy_p_to_c = 0x02, .rtn_c_to_p = 0x00, .rtn_p_to_c = 0x05 },
	};
	/* RP: status, cig_id, cis_count=2, handles 0x0100 and 0x0101. */
	uint8_t rp[] = { 0x00, 0x0A, 0x02, 0x00, 0x01, 0x01, 0x01 };
	uint8_t got_cig = 0, got_count = 0;
	uint16_t handles[2] = { 0, 0 };
	const struct captured_cmd *cc;

	reset();
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_setup_cig(FD, /*cig_id*/0x0A,
	    /*sdu_c*/0x0004E2, /*sdu_p*/0x002710, /*sca*/0x00,
	    /*packing*/0x00, /*framing*/0x00, /*lat_c*/0x000A,
	    /*lat_p*/0x0014, 2, cises, &got_cig, &got_count, handles));

	ATF_CHECK_EQ(1, W.calls);
	cc = &W.c[0];
	ATF_CHECK_EQ(BT_ISO_SPEC_OP_LE_SET_CIG_PARAMS, cc->opcode);
	ATF_CHECK_EQ(BT_ISO_SPEC_EVENT_COMMAND_COMPLETE, cc->event);
	/* 15-octet header + 2 * 9-octet records = 33. */
	ATF_CHECK_EQ((size_t)(BT_ISO_SPEC_CIG_HEADER_LEN +
	    2 * BT_ISO_SPEC_CIS_RECORD_LEN), cc->clen);

	/* Header (§7.8.97). */
	ATF_CHECK_EQ(0x0A, cc->cmd[0]);			/* CIG_ID */
	ATF_CHECK_EQ((uint32_t)0x0004E2, c_le24(cc, 1));	/* SDU_Interval_C */
	ATF_CHECK_EQ((uint32_t)0x002710, c_le24(cc, 4));	/* SDU_Interval_P */
	ATF_CHECK_EQ(0x00, cc->cmd[7]);			/* Worst_Case_SCA */
	ATF_CHECK_EQ(0x00, cc->cmd[8]);			/* Packing */
	ATF_CHECK_EQ(0x00, cc->cmd[9]);			/* Framing */
	ATF_CHECK_EQ(0x000A, c_le16(cc, 10));		/* Max_Latency_C */
	ATF_CHECK_EQ(0x0014, c_le16(cc, 12));		/* Max_Latency_P */
	ATF_CHECK_EQ(0x02, cc->cmd[14]);		/* CIS_Count */

	/* Record 0 at offset 15. */
	ATF_CHECK_EQ(0x01, cc->cmd[15]);		/* CIS_ID */
	ATF_CHECK_EQ(0x00F0, c_le16(cc, 16));		/* Max_SDU_C_To_P */
	ATF_CHECK_EQ(0x0000, c_le16(cc, 18));		/* Max_SDU_P_To_C */
	ATF_CHECK_EQ(0x02, cc->cmd[20]);		/* PHY_C_To_P */
	ATF_CHECK_EQ(0x01, cc->cmd[21]);		/* PHY_P_To_C */
	ATF_CHECK_EQ(0x03, cc->cmd[22]);		/* RTN_C_To_P */
	ATF_CHECK_EQ(0x00, cc->cmd[23]);		/* RTN_P_To_C */

	/* Record 1 at offset 24. */
	ATF_CHECK_EQ(0x02, cc->cmd[24]);		/* CIS_ID */
	ATF_CHECK_EQ(0x0000, c_le16(cc, 25));		/* Max_SDU_C_To_P */
	ATF_CHECK_EQ(0x0064, c_le16(cc, 27));		/* Max_SDU_P_To_C */
	ATF_CHECK_EQ(0x01, cc->cmd[29]);		/* PHY_C_To_P */
	ATF_CHECK_EQ(0x02, cc->cmd[30]);		/* PHY_P_To_C */
	ATF_CHECK_EQ(0x00, cc->cmd[31]);		/* RTN_C_To_P */
	ATF_CHECK_EQ(0x05, cc->cmd[32]);		/* RTN_P_To_C */

	/* Return-parameter extraction. */
	ATF_CHECK_EQ(0x0A, got_cig);
	ATF_CHECK_EQ(0x02, got_count);
	ATF_CHECK_EQ(0x0100, handles[0]);
	ATF_CHECK_EQ(0x0101, handles[1]);
}

/* Host-side rejection before any I/O: count > 31, or NULL records. */
ATF_TC_WITHOUT_HEAD(setup_cig_reject_before_io);
ATF_TC_BODY(setup_cig_reject_before_io, tc)
{
	struct hci_cis_param one = { .cis_id = 0 };

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_cig(FD, 0, 0, 0, 0, 0, 0, 0, 0,
	    BT_ISO_SPEC_CIS_COUNT_MAX + 1, &one, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);	/* no I/O */

	reset();
	mock_ok();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_setup_cig(FD, 0, 0, 0, 0, 0, 0, 0, 0,
	    1, NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(0, W.calls);
}

/* ================================================================
 * §7.8.109  LE Setup ISO Data Path — per-direction HCI-transport caller.
 *
 * CP: Connection_Handle(2 LE) | Data_Path_Direction(1) | Data_Path_ID(1) |
 *     Codec_ID(5) | Controller_Delay(3 LE) | Codec_Configuration_Length(1) |
 *     Codec_Configuration(len)
 * The HCI-transport caller pins Data_Path_ID=0x00 (HCI), the Transparent
 * coding format Codec_ID {0x03,0,0,0,0}, zero delay and no config.
 * ================================================================ */
static void
check_iso_hci_path_cmd(const struct captured_cmd *cc, uint16_t handle,
    uint8_t dir)
{

	ATF_CHECK_EQ(BT_ISO_SPEC_OP_LE_SETUP_DATA_PATH, cc->opcode);
	ATF_CHECK_EQ(BT_ISO_SPEC_EVENT_COMMAND_COMPLETE, cc->event);
	ATF_CHECK_EQ((size_t)BT_ISO_SPEC_SETUP_PATH_HEADER_LEN, cc->clen);
	ATF_CHECK_EQ(handle, c_le16(cc, 0));	/* Connection_Handle */
	ATF_CHECK_EQ(dir, cc->cmd[2]);		/* Data_Path_Direction */
	ATF_CHECK_EQ(BT_ISO_SPEC_DATA_PATH_HCI, cc->cmd[3]);
	ATF_CHECK_EQ(BT_ISO_SPEC_CODEC_TRANSPARENT, cc->cmd[4]);
	ATF_CHECK_EQ(0x00, cc->cmd[5]);		/* Company_ID lo */
	ATF_CHECK_EQ(0x00, cc->cmd[6]);		/* Company_ID hi */
	ATF_CHECK_EQ(0x00, cc->cmd[7]);		/* Vendor_Codec_ID lo */
	ATF_CHECK_EQ(0x00, cc->cmd[8]);		/* Vendor_Codec_ID hi */
	ATF_CHECK_EQ((uint32_t)0, c_le24(cc, 9));	/* Controller_Delay */
	ATF_CHECK_EQ(0x00, cc->cmd[12]);	/* Codec_Configuration_Length */
}

ATF_TC_WITHOUT_HEAD(setup_iso_hci_path_layout);
ATF_TC_BODY(setup_iso_hci_path_layout, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_setup_iso_hci_path(FD, 0x0100,
	    HCI_ISO_DIR_INPUT));
	ATF_CHECK_EQ(1, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0100, BT_ISO_SPEC_DIR_INPUT);

	reset();
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_setup_iso_hci_path(FD, 0x0101,
	    HCI_ISO_DIR_OUTPUT));
	ATF_CHECK_EQ(1, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0101, BT_ISO_SPEC_DIR_OUTPUT);
}

/* ================================================================
 * Established-stream orchestration: correct direction(s) per stream kind.
 *  - CIS is bidirectional -> Input then Output.
 *  - BIS the device broadcasts -> Input only.
 *  - BIS the device is synchronized to -> Output only.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cis_sets_both_directions);
ATF_TC_BODY(cis_sets_both_directions, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(2, hci_le_setup_iso_stream_paths(FD, 0x0100,
	    HCI_ISO_STREAM_CIS));
	ATF_CHECK_EQ(2, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0100, BT_ISO_SPEC_DIR_INPUT);
	check_iso_hci_path_cmd(&W.c[1], 0x0100, BT_ISO_SPEC_DIR_OUTPUT);
}

ATF_TC_WITHOUT_HEAD(bis_source_sets_input_only);
ATF_TC_BODY(bis_source_sets_input_only, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(1, hci_le_setup_iso_stream_paths(FD, 0x0200,
	    HCI_ISO_STREAM_BIS_SOURCE));
	ATF_CHECK_EQ(1, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0200, BT_ISO_SPEC_DIR_INPUT);
}

ATF_TC_WITHOUT_HEAD(bis_sink_sets_output_only);
ATF_TC_BODY(bis_sink_sets_output_only, tc)
{

	reset();
	mock_ok();
	ATF_CHECK_EQ(1, hci_le_setup_iso_stream_paths(FD, 0x0201,
	    HCI_ISO_STREAM_BIS_SINK));
	ATF_CHECK_EQ(1, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0201, BT_ISO_SPEC_DIR_OUTPUT);
}

/* ================================================================
 * Event -> data-path wiring, driven through the production decode seam.
 *
 * Build a real LE meta event, decode it with blued_parse_le_meta_event()
 * (the exact call the daemon's HCI event handler makes), then run the same
 * per-handle Setup ISO Data Path loop the handler runs and assert the
 * commands that reach the controller.  This is the regression guard for
 * the "encoders had zero callers" gap.
 *
 * Raw HCI event framing: pkt[0]=0x04 type, pkt[1]=0x3E LE Meta,
 * pkt[2]=param_len, pkt[3]=subevent, pkt[4..]=subevent params.
 * ================================================================ */

/* LE CIS Established (subevent 0x19): Status(1) Conn_Handle(2 LE) then a
 * 25-octet tail the parser reads fields out of (28-octet ep total). */
ATF_TC_WITHOUT_HEAD(cis_established_event_wires_paths);
ATF_TC_BODY(cis_established_event_wires_paths, tc)
{
	uint8_t pkt[4 + BT_ISO_SPEC_CIS_ESTABLISHED_PARAM_LEN];
	struct blued_le_meta_report rep;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_ISO_SPEC_EVENT_PACKET;
	pkt[1] = BT_ISO_SPEC_EVENT_LE_META;
	pkt[2] = (uint8_t)(1 + BT_ISO_SPEC_CIS_ESTABLISHED_PARAM_LEN);
	pkt[3] = BT_ISO_SPEC_SUBEVENT_CIS_ESTABLISHED;
	/* params: status=0x00, connection_handle=0x0100 LE. */
	pkt[4] = BT_ISO_SPEC_STATUS_SUCCESS;
	pkt[5] = 0x00;
	pkt[6] = 0x01;

	ATF_REQUIRE_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_REQUIRE_EQ(BT_ISO_SPEC_SUBEVENT_CIS_ESTABLISHED, rep.subevent);
	ATF_REQUIRE_EQ(BT_ISO_SPEC_STATUS_SUCCESS, rep.status);
	ATF_REQUIRE_EQ(0x0100, rep.connection_handle);

	/* The daemon acts only on status==0; a CIS gets both directions. */
	reset();
	mock_ok();
	if (rep.status == BT_ISO_SPEC_STATUS_SUCCESS)
		(void)hci_le_setup_iso_stream_paths(FD, rep.connection_handle,
		    HCI_ISO_STREAM_CIS);
	ATF_CHECK_EQ(2, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0100, BT_ISO_SPEC_DIR_INPUT);
	check_iso_hci_path_cmd(&W.c[1], 0x0100, BT_ISO_SPEC_DIR_OUTPUT);
}

/* LE Create BIG Complete (subevent 0x1b): 18-octet fixed header with
 * num_bis at offset 17, followed by num_bis 2-octet BIS handles.  The
 * broadcaster sets up one Input data path per BIS. */
ATF_TC_WITHOUT_HEAD(create_big_event_wires_input_paths);
ATF_TC_BODY(create_big_event_wires_input_paths, tc)
{
	uint8_t pkt[4 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN + 2 * 2];
	struct blued_le_meta_report rep;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_ISO_SPEC_EVENT_PACKET;
	pkt[1] = BT_ISO_SPEC_EVENT_LE_META;
	pkt[2] = (uint8_t)(1 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN + 2 * 2);
	pkt[3] = BT_ISO_SPEC_SUBEVENT_CREATE_BIG_COMPLETE;
	/* params start at pkt[4]: status=0 at +0, big_handle=1 at +1. */
	pkt[4 + 0] = BT_ISO_SPEC_STATUS_SUCCESS;
	pkt[4 + 1] = 0x01;	/* big_handle */
	pkt[4 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN - 1] = 0x02;
	/* BIS handles at +18: 0x0100, 0x0101 (LE). */
	pkt[4 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN] = 0x00;
	pkt[5 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN] = 0x01;
	pkt[6 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN] = 0x01;
	pkt[7 + BT_ISO_SPEC_CREATE_BIG_FIXED_LEN] = 0x01;

	ATF_REQUIRE_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_REQUIRE_EQ(BT_ISO_SPEC_SUBEVENT_CREATE_BIG_COMPLETE, rep.subevent);
	ATF_REQUIRE_EQ(BT_ISO_SPEC_STATUS_SUCCESS, rep.status);
	ATF_REQUIRE_EQ(2, rep.num_bis);
	ATF_REQUIRE(rep.bis_handles != NULL);

	reset();
	mock_ok();
	if (rep.status == BT_ISO_SPEC_STATUS_SUCCESS &&
	    rep.bis_handles != NULL) {
		for (uint8_t i = 0; i < rep.num_bis; i++)
			(void)hci_le_setup_iso_stream_paths(FD,
			    blued_le_meta_le16(rep.bis_handles + i * 2),
			    HCI_ISO_STREAM_BIS_SOURCE);
	}
	ATF_CHECK_EQ(2, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0100, BT_ISO_SPEC_DIR_INPUT);
	check_iso_hci_path_cmd(&W.c[1], 0x0101, BT_ISO_SPEC_DIR_INPUT);
}

/* LE BIG Sync Established (subevent 0x1d): 14-octet fixed header with
 * num_bis at offset 13, followed by num_bis 2-octet BIS handles.  The
 * synchronized receiver sets up one Output data path per BIS. */
ATF_TC_WITHOUT_HEAD(big_sync_event_wires_output_paths);
ATF_TC_BODY(big_sync_event_wires_output_paths, tc)
{
	uint8_t pkt[4 + BT_ISO_SPEC_BIG_SYNC_FIXED_LEN + 2];
	struct blued_le_meta_report rep;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = BT_ISO_SPEC_EVENT_PACKET;
	pkt[1] = BT_ISO_SPEC_EVENT_LE_META;
	pkt[2] = (uint8_t)(1 + BT_ISO_SPEC_BIG_SYNC_FIXED_LEN + 2);
	pkt[3] = BT_ISO_SPEC_SUBEVENT_BIG_SYNC_ESTABLISHED;
	pkt[4 + 0] = BT_ISO_SPEC_STATUS_SUCCESS;
	pkt[4 + 1] = 0x01;	/* big_handle */
	pkt[4 + BT_ISO_SPEC_BIG_SYNC_FIXED_LEN - 1] = 0x01;
	pkt[4 + BT_ISO_SPEC_BIG_SYNC_FIXED_LEN] = 0x05;
	pkt[5 + BT_ISO_SPEC_BIG_SYNC_FIXED_LEN] = 0x01;

	ATF_REQUIRE_EQ(0, blued_parse_le_meta_event(pkt, sizeof(pkt), &rep));
	ATF_REQUIRE_EQ(BT_ISO_SPEC_SUBEVENT_BIG_SYNC_ESTABLISHED, rep.subevent);
	ATF_REQUIRE_EQ(BT_ISO_SPEC_STATUS_SUCCESS, rep.status);
	ATF_REQUIRE_EQ(1, rep.num_bis);
	ATF_REQUIRE(rep.bis_handles != NULL);

	reset();
	mock_ok();
	if (rep.status == BT_ISO_SPEC_STATUS_SUCCESS &&
	    rep.bis_handles != NULL) {
		for (uint8_t i = 0; i < rep.num_bis; i++)
			(void)hci_le_setup_iso_stream_paths(FD,
			    blued_le_meta_le16(rep.bis_handles + i * 2),
			    HCI_ISO_STREAM_BIS_SINK);
	}
	ATF_CHECK_EQ(1, W.calls);
	check_iso_hci_path_cmd(&W.c[0], 0x0105, BT_ISO_SPEC_DIR_OUTPUT);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, setup_cig_layout);
	ATF_TP_ADD_TC(tp, setup_cig_reject_before_io);
	ATF_TP_ADD_TC(tp, setup_iso_hci_path_layout);
	ATF_TP_ADD_TC(tp, cis_sets_both_directions);
	ATF_TP_ADD_TC(tp, bis_source_sets_input_only);
	ATF_TP_ADD_TC(tp, bis_sink_sets_output_only);
	ATF_TP_ADD_TC(tp, cis_established_event_wires_paths);
	ATF_TP_ADD_TC(tp, create_big_event_wires_input_paths);
	ATF_TP_ADD_TC(tp, big_sync_event_wires_output_paths);

	return (atf_no_error());
}
