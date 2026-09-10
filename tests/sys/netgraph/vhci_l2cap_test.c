/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Byte-level conformance cases for the L2CAP layer of the in-kernel
 * Bluetooth stack, driven through the virtual HCI controller.
 *
 * Every case here injects a raw controller-to-host frame and asserts on the
 * exact octets the kernel emits in reply (or on the exact octets it delivers
 * to the upper layer).  The assertions are written against what the Core
 * Specification requires, NOT against what the code currently does: a
 * failure here is a defect report, not a case to be relaxed.
 *
 * These cases need root and a running kernel whose ng_hci/ng_l2cap match
 * this source tree; they skip cleanly otherwise (see vh_require()).
 */

#include <sys/types.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vhci_harness.h"

#define	LE_HANDLE	0x0021

/* We are the Central; the peer is the Peripheral. */
#define	ROLE_CENTRAL	0x00
#define	ROLE_PERIPHERAL	0x01

static void	put16(uint8_t *p, uint16_t v);
static uint16_t	get16(const uint8_t *p);

static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
get16(const uint8_t *p)
{

	return ((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/*
 * Everything the kernel emits in reply to one
 * L2CAP_CONNECTION_PARAMETER_UPDATE_REQ.
 *
 * The reply is not a single frame: an accepted request produces both an
 * L2CAP response on the LE signalling channel and an HCI
 * LE_Connection_Update command, and the two travel down independent paths
 * (the connection's ACL queue and the unit's command queue), so their
 * relative order at the controller endpoint is not fixed.  Collecting the
 * whole burst and classifying it is both order-independent and exactly the
 * assertion the case wants to make: whether a connection-update command
 * followed the request at all.
 */
struct urq_reply {
	int		responses;	/* parameter update responses seen */
	uint16_t	result;		/* Result of the last one */
	int		rejects;	/* command rejects seen */
	uint16_t	reject_reason;	/* Reason of the last one */
	uint8_t		reject_ident;
	int		updates;	/* LE_Connection_Update commands */
};

/*
 * Complete an HCI command with a Command_Status event.  ng_hci allows one
 * outstanding command, so an LE_Connection_Update left dangling would block
 * every later command in the same rig.
 */
static void
answer_command_status(struct vhci_rig *r, uint16_t opcode)
{
	uint8_t evt[7];

	evt[0] = NG_HCI_EVENT_PKT;
	evt[1] = NG_HCI_EVENT_COMMAND_STATUS;
	evt[2] = 4;
	evt[3] = 0x00;			/* status: pending */
	evt[4] = 1;			/* num_cmd_pkts */
	evt[5] = (uint8_t)(opcode & 0xff);
	evt[6] = (uint8_t)(opcode >> 8);
	vh_inject(r, evt, sizeof(evt));
}

/*
 * Send one L2CAP_CONNECTION_PARAMETER_UPDATE_REQ (Vol 3 Part A 4.20) up the
 * LE signalling channel and collect everything the kernel emits in reply,
 * until the controller endpoint has been quiet for VH_QUIET_MS.
 */
static void
param_update(struct vhci_rig *r, struct urq_reply *out, uint8_t ident,
    uint16_t imin, uint16_t imax, uint16_t latency, uint16_t timeout)
{
	uint8_t req[12], pkt[VH_BUFSZ];
	uint16_t opcode, l2len, cid;
	ssize_t n;

	memset(out, 0, sizeof(*out));

	req[0] = NG_L2CAP_CMD_PARAM_UPDATE_REQUEST;
	req[1] = ident;
	put16(&req[2], 8);
	put16(&req[4], imin);
	put16(&req[6], imax);
	put16(&req[8], latency);
	put16(&req[10], timeout);
	vh_send_bframe(r, NG_L2CAP_LESIGNAL_CID, req, sizeof(req));

	for (;;) {
		n = vh_capture(r, pkt, sizeof(pkt), VH_QUIET_MS);
		if (n < 0)
			break;
		ATF_REQUIRE_MSG(n > 0, "zero-length packet from the "
		    "controller endpoint");

		if (pkt[0] == NG_HCI_CMD_PKT) {
			ATF_REQUIRE_MSG(n >= 4, "runt HCI command, %zd "
			    "octets", n);
			opcode = get16(&pkt[1]);
			ATF_REQUIRE_EQ_MSG(NG_HCI_OPCODE(NG_HCI_OGF_LE,
			    NG_HCI_OCF_LE_CONNECTION_UPDATE), opcode,
			    "unexpected HCI command opcode %#x in reply to a "
			    "parameter update request", opcode);
			out->updates++;
			answer_command_status(r, opcode);
			continue;
		}

		ATF_REQUIRE_EQ_MSG(NG_HCI_ACL_DATA_PKT, pkt[0],
		    "unexpected packet type %#x", pkt[0]);
		ATF_REQUIRE_MSG(n >= 9, "runt ACL frame, %zd octets", n);
		l2len = get16(&pkt[5]);
		cid = get16(&pkt[7]);
		ATF_REQUIRE_EQ_MSG(NG_L2CAP_LESIGNAL_CID, cid,
		    "reply arrived on CID %#x, expected the LE signalling "
		    "CID", cid);
		ATF_REQUIRE_EQ_MSG((size_t)n, (size_t)l2len + 9,
		    "L2CAP length %u does not match frame length %zd",
		    l2len, n);

		switch (pkt[9]) {
		case NG_L2CAP_CMD_PARAM_UPDATE_RESPONSE:
			ATF_REQUIRE_EQ_MSG(6, l2len, "parameter update "
			    "response is %u octets, expected 6", l2len);
			ATF_CHECK_EQ_MSG(ident, pkt[10], "response "
			    "Identifier is %u, expected %u", pkt[10], ident);
			ATF_CHECK_EQ_MSG(2, get16(&pkt[11]), "response "
			    "Length is %u, expected 2", get16(&pkt[11]));
			out->result = get16(&pkt[13]);
			out->responses++;
			break;

		case NG_L2CAP_CMD_REJ:
			out->reject_ident = pkt[10];
			out->reject_reason = get16(&pkt[13]);
			out->rejects++;
			break;

		default:
			atf_tc_fail("unexpected L2CAP signalling code %#x in "
			    "reply to a parameter update request", pkt[9]);
		}
	}
}

/*
 * The request was answered with the given Result and, if it was rejected,
 * no LE_Connection_Update command followed it.
 */
static void
check_param_update(struct vhci_rig *r, uint8_t ident, uint16_t imin,
    uint16_t imax, uint16_t latency, uint16_t timeout, uint16_t want,
    const char *why)
{
	struct urq_reply rep;

	param_update(r, &rep, ident, imin, imax, latency, timeout);

	ATF_REQUIRE_EQ_MSG(1, rep.responses, "expected exactly one "
	    "L2CAP_CONNECTION_PARAMETER_UPDATE_RSP, got %d (%s)",
	    rep.responses, why);
	ATF_CHECK_EQ_MSG(0, rep.rejects, "the request drew an "
	    "L2CAP_COMMAND_REJECT_RSP, which is only correct when we are the "
	    "Peripheral (%s)", why);
	ATF_CHECK_EQ_MSG(want, rep.result, "Result is %#x, expected %#x: %s",
	    rep.result, want, why);

	if (want == NG_L2CAP_UPDATE_PARAM_REJECT)
		ATF_CHECK_EQ_MSG(0, rep.updates, "a rejected request must not "
		    "be acted on, but %d LE_Connection_Update command(s) "
		    "followed it: %s", rep.updates, why);
	else
		ATF_CHECK_EQ_MSG(1, rep.updates, "an accepted request must "
		    "produce exactly one LE_Connection_Update command, got "
		    "%d: %s", rep.updates, why);
}

/*
 * ---------------------------------------------------------------------
 * The supervision timeout bound.
 *
 * Core Spec Vol 6 Part B 4.5.2 requires
 *
 *     connSupervisionTimeout > (1 + connPeripheralLatency) *
 *                              connIntervalMax * 2
 *
 * in milliseconds.  On the wire (Vol 6 Part B 2.4.2.16) Timeout is in
 * 10 ms steps and Interval_Max in 1.25 ms steps, so
 *
 *     timeout * 10 > (1 + latency) * interval_max * 1.25 * 2
 *  => timeout *  4 > (1 + latency) * interval_max
 *
 * With latency 0 and Interval_Max 400 the right-hand side is 400, so the
 * smallest legal Timeout is 101 and 100 must be rejected.  The kernel
 * previously compared timeout * 8, which accepted everything from 51 up:
 * a supervision timeout of half the legal minimum, which a conformant peer
 * would drop the link over.
 * ---------------------------------------------------------------------
 */
ATF_TC(param_update_supervision_bound);
ATF_TC_HEAD(param_update_supervision_bound, tc)
{

	atf_tc_set_md_var(tc, "descr", "The connection-parameter supervision "
	    "timeout bound is enforced at the value Vol 6 Part B 4.5.2 "
	    "requires, not at half of it");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(param_update_supervision_bound, tc)
{
	struct vhci_rig rig;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	/* Timeout 100: exactly at the bound, which is not "greater than". */
	check_param_update(&rig, 1, 6, 400, 0, 100,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "timeout=100 with interval_max=400 and latency=0 satisfies "
	    "timeout*4 > (1+latency)*interval_max only as equality, so it "
	    "must be rejected");

	/* Timeout 101: the smallest legal value. */
	check_param_update(&rig, 2, 6, 400, 0, 101,
	    NG_L2CAP_UPDATE_PARAM_ACCEPT,
	    "timeout=101 is the smallest value satisfying the bound");

	/*
	 * The value the superseded factor-of-eight comparison accepted.  If
	 * this is accepted, the old bound is still in the tree.
	 */
	check_param_update(&rig, 3, 6, 400, 0, 51,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "timeout=51 is half the legal minimum; accepting it means the "
	    "superseded timeout*8 comparison is still in place");

	/* The bound scales with latency: latency 1 doubles the requirement. */
	check_param_update(&rig, 4, 6, 400, 1, 200,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "latency=1 requires timeout*4 > 800, so timeout=200 must be "
	    "rejected");

	check_param_update(&rig, 5, 6, 400, 1, 201,
	    NG_L2CAP_UPDATE_PARAM_ACCEPT,
	    "latency=1 with timeout=201 satisfies the bound");

	vh_down(&rig);
}

/*
 * The interval, latency and timeout range edges (Vol 6 Part B 2.4.2.16).
 * Each case moves exactly one field out of range and keeps the supervision
 * relation comfortably satisfied, so a rejection can only be the range
 * check firing.
 */
ATF_TC(param_update_range_edges);
ATF_TC_HEAD(param_update_range_edges, tc)
{

	atf_tc_set_md_var(tc, "descr", "Connection-parameter interval, "
	    "latency and timeout range edges");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(param_update_range_edges, tc)
{
	struct vhci_rig rig;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	check_param_update(&rig, 10, 5, 6, 0, 100,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "interval_min=5 is below the 6 (7.5 ms) minimum");

	check_param_update(&rig, 11, 6, 6, 0, 100,
	    NG_L2CAP_UPDATE_PARAM_ACCEPT,
	    "interval_min=6 is the minimum legal interval");

	check_param_update(&rig, 12, 6, 3201, 0, 3200,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "interval_max=3201 is above the 3200 (4 s) maximum");

	check_param_update(&rig, 13, 400, 100, 0, 3200,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "interval_min must not exceed interval_max");

	check_param_update(&rig, 14, 6, 6, 500, 3200,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "latency=500 is above the 499 maximum");

	check_param_update(&rig, 15, 6, 6, 499, 751,
	    NG_L2CAP_UPDATE_PARAM_ACCEPT,
	    "latency=499 with interval_max=6 requires timeout*4 > 3000, so "
	    "timeout=751 is legal");

	check_param_update(&rig, 16, 6, 6, 0, 9,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "timeout=9 is below the 10 (100 ms) minimum");

	check_param_update(&rig, 17, 6, 6, 0, 10,
	    NG_L2CAP_UPDATE_PARAM_ACCEPT,
	    "timeout=10 is the minimum legal supervision timeout and "
	    "4*10 > 6 satisfies the bound");

	check_param_update(&rig, 18, 6, 6, 0, 3201,
	    NG_L2CAP_UPDATE_PARAM_REJECT,
	    "timeout=3201 is above the 3200 (32 s) maximum");

	vh_down(&rig);
}

/*
 * Vol 3 Part A 4.20: only a Peripheral may send the request.  When we are
 * the Peripheral the request must draw an L2CAP_COMMAND_REJECT_RSP with
 * reason 0x0000, not a parameter update response.
 */
ATF_TC(param_update_role_gate);
ATF_TC_HEAD(param_update_role_gate, tc)
{

	atf_tc_set_md_var(tc, "descr", "A Peripheral rejects a connection "
	    "parameter update request as not understood");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(param_update_role_gate, tc)
{
	struct vhci_rig rig;
	struct urq_reply rep;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_PERIPHERAL);

	param_update(&rig, &rep, 20, 6, 400, 0, 101);

	ATF_CHECK_EQ_MSG(0, rep.responses, "a Peripheral must not answer "
	    "with a parameter update response");
	ATF_REQUIRE_EQ_MSG(1, rep.rejects, "expected exactly one "
	    "L2CAP_COMMAND_REJECT_RSP, got %d", rep.rejects);
	ATF_CHECK_EQ_MSG(20, rep.reject_ident, "reject Identifier is %u, "
	    "expected 20", rep.reject_ident);
	ATF_CHECK_EQ_MSG(NG_L2CAP_REJ_NOT_UNDERSTOOD, rep.reject_reason,
	    "expected reason 0x0000 (command not understood), got %#x",
	    rep.reject_reason);
	ATF_CHECK_EQ_MSG(0, rep.updates, "a rejected request must not be "
	    "acted on, but %d LE_Connection_Update command(s) followed it",
	    rep.updates);

	vh_down(&rig);
}

/*
 * ---------------------------------------------------------------------
 * The fixed-channel size cap.
 *
 * ng_l2cap gives the ATT (CID 0x0004) and SMP (CID 0x0006) fixed channels
 * an incoming MTU of NG_L2CAP_MTU_LE_MINIMUM (23) and drops any B-frame
 * longer than that in ng_l2cap_l2ca_receive().
 *
 * For SMP that is not merely conservative, it is disabling: Vol 3 Part H
 * 3.2 requires the SMP fixed channel to carry 65 octets whenever LE Secure
 * Connections is supported, because the Pairing Public Key PDU is a 1-octet
 * opcode plus a 64-octet key.  With the cap at 23 the key never reaches the
 * upper layer, so Secure Connections pairing cannot complete against any
 * real peer.
 *
 * The assertion is delivery: the 65 octets must arrive intact at the top of
 * L2CAP, on the SMP id-type, with the frame's dcid rewritten to the
 * connection handle as ng_l2cap does for fixed channels.
 * ---------------------------------------------------------------------
 */
ATF_TC(smp_public_key_survives);
ATF_TC_HEAD(smp_public_key_survives, tc)
{

	atf_tc_set_md_var(tc, "descr", "A 65-octet SMP Pairing Public Key "
	    "survives the fixed-channel receive path");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(smp_public_key_survives, tc)
{
	struct vhci_rig rig;
	uint8_t pdu[65], up[VH_BUFSZ];
	uint16_t idtype;
	ssize_t n;
	int i;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	/* SMP Pairing Public Key (Vol 3 Part H 3.5.6): opcode 0x0c + 64. */
	pdu[0] = 0x0c;
	for (i = 1; i < 65; i++)
		pdu[i] = (uint8_t)i;

	vh_send_bframe(&rig, NG_L2CAP_SMP_CID, pdu, sizeof(pdu));

	n = vh_recv_l2c(&rig, &idtype, up, sizeof(up), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "the 65-octet SMP PDU never reached the "
	    "upper layer: the fixed-channel MTU cap dropped it, which makes "
	    "LE Secure Connections pairing impossible (Vol 3 Part H 3.2)");
	ATF_CHECK_EQ_MSG(NG_L2CAP_L2CA_IDTYPE_SMP, idtype,
	    "delivered on id-type %u, expected SMP (%u)", idtype,
	    NG_L2CAP_L2CA_IDTYPE_SMP);
	ATF_REQUIRE_EQ_MSG(4 + 65, n, "delivered %zd octets, expected the "
	    "4-octet L2CAP header plus 65", n);
	ATF_CHECK_EQ_MSG(65, get16(&up[0]), "L2CAP Length is %u, expected 65",
	    get16(&up[0]));
	ATF_CHECK_EQ_MSG(LE_HANDLE, get16(&up[2]), "fixed-channel frames are "
	    "delivered with dcid rewritten to the connection handle");
	ATF_CHECK_EQ(0, memcmp(&up[4], pdu, sizeof(pdu)));

	vh_down(&rig);
}

/*
 * The same cap on the ATT fixed channel (CID 0x0004).
 *
 * L2CAP has no visibility of the ATT_MTU exchange (Vol 3 Part F 3.4.2), so
 * it cannot know the negotiated ATT_MTU and must not impose the 23-octet
 * default as a receive cap: a peer that has agreed a larger ATT_MTU sends
 * larger PDUs and every one of them is dropped.  This case asserts that a
 * 65-octet ATT PDU is delivered rather than silently discarded.
 */
ATF_TC(att_pdu_above_default_mtu_survives);
ATF_TC_HEAD(att_pdu_above_default_mtu_survives, tc)
{

	atf_tc_set_md_var(tc, "descr", "An ATT PDU larger than the default "
	    "ATT_MTU is delivered rather than dropped by L2CAP");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(att_pdu_above_default_mtu_survives, tc)
{
	struct vhci_rig rig;
	uint8_t pdu[65], up[VH_BUFSZ];
	uint16_t idtype;
	ssize_t n;
	int i;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	/* ATT Handle Value Notification (0x1b) with a long value. */
	pdu[0] = 0x1b;
	for (i = 1; i < 65; i++)
		pdu[i] = (uint8_t)(0x80 + i);

	vh_send_bframe(&rig, NG_L2CAP_ATT_CID, pdu, sizeof(pdu));

	n = vh_recv_l2c(&rig, &idtype, up, sizeof(up), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "the 65-octet ATT PDU never reached the "
	    "upper layer: L2CAP is enforcing the 23-octet default ATT_MTU "
	    "as a receive cap, which it cannot know is still in force");
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ATT, idtype);
	ATF_REQUIRE_EQ(4 + 65, n);
	ATF_CHECK_EQ(65, get16(&up[0]));
	ATF_CHECK_EQ(0, memcmp(&up[4], pdu, sizeof(pdu)));

	vh_down(&rig);
}

/*
 * A 23-octet frame on the same channel, which even the capped code path
 * accepts.  It is here so a failure of the two cases above can be read as
 * "the size cap" rather than "fixed channels never deliver anything".
 */
ATF_TC(smp_minimum_size_survives);
ATF_TC_HEAD(smp_minimum_size_survives, tc)
{

	atf_tc_set_md_var(tc, "descr", "A minimum-size SMP PDU is delivered "
	    "(control for the fixed-channel size cases)");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(smp_minimum_size_survives, tc)
{
	struct vhci_rig rig;
	uint8_t pdu[7], up[VH_BUFSZ];
	uint16_t idtype;
	ssize_t n;
	int i;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	/* SMP Pairing Request (Vol 3 Part H 3.5.1): opcode 0x01 + 6. */
	pdu[0] = 0x01;
	for (i = 1; i < 7; i++)
		pdu[i] = (uint8_t)i;

	vh_send_bframe(&rig, NG_L2CAP_SMP_CID, pdu, sizeof(pdu));

	n = vh_recv_l2c(&rig, &idtype, up, sizeof(up), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "even a 7-octet SMP PDU was not delivered; "
	    "the rig is not bringing the SMP fixed channel up at all");
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_SMP, idtype);
	ATF_REQUIRE_EQ(4 + 7, n);
	ATF_CHECK_EQ(0, memcmp(&up[4], pdu, sizeof(pdu)));

	vh_down(&rig);
}

/*
 * ---------------------------------------------------------------------
 * Outbound Enhanced Credit Based connection (Vol 3 Part A 4.25) and
 * per-K-frame credit return (Vol 3 Part A 4.24, 10.1).
 * ---------------------------------------------------------------------
 */

/*
 * Ask ng_l2cap to open an outbound ECBFC channel over the existing LE link
 * and return the emitted L2CAP_CREDIT_BASED_CONNECTION_REQ, with *scid set
 * to the Source CID it allocated and *ident to the Identifier it chose.
 */
static void
ecbfc_connect_req(struct vhci_rig *r, uint16_t psm, uint8_t *ident,
    uint16_t *scid)
{
	ng_l2cap_l2ca_con_ip ip;
	uint8_t req[VH_BUFSZ];
	uint16_t cid;
	ssize_t n;

	memset(&ip, 0, sizeof(ip));
	ip.psm = psm;
	memcpy(&ip.bdaddr, r->bdaddr, sizeof(r->bdaddr));
	ip.linktype = NG_HCI_LINK_LE_PUBLIC;
	ip.idtype = NG_L2CAP_L2CA_IDTYPE_ECBFC;
	ip.own_address_type = 0;

	/*
	 * ng_l2cap only accepts L2CA_* requests arriving through its upper
	 * hooks (ng_l2cap_upper_rcvmsg); the node's default receiver rejects
	 * them.  ".:l2c" is our own socket node followed by our "l2c" hook,
	 * so the message lands on ng_l2cap with the right lasthook.
	 */
	ATF_REQUIRE_MSG(NgSendMsg(r->cs, ".:l2c", NGM_L2CAP_COOKIE,
	    NGM_L2CAP_L2CA_CON, &ip, sizeof(ip)) >= 0,
	    "L2CA_Connect: %s", strerror(errno));

	n = vh_recv_bframe(r, &cid, req, sizeof(req), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "L2CA_Connect for an ECBFC channel emitted "
	    "nothing on the wire");
	ATF_CHECK_EQ_MSG(NG_L2CAP_LESIGNAL_CID, cid, "the request went out "
	    "on CID %#x, expected the LE signalling CID", cid);
	ATF_REQUIRE_EQ_MSG(NG_L2CAP_CREDIT_CON_REQ, req[0],
	    "expected an Enhanced Credit Based Connection Request (%#x), "
	    "got code %#x", NG_L2CAP_CREDIT_CON_REQ, req[0]);
	/* SPSM + MTU + MPS + Initial Credits + one Source CID. */
	ATF_REQUIRE_EQ_MSG(10, get16(&req[2]), "request Length is %u, "
	    "expected 10 for a single-channel request", get16(&req[2]));
	ATF_REQUIRE_EQ(4 + 10, n);
	ATF_CHECK_EQ_MSG(psm, get16(&req[4]), "SPSM is %#x, expected %#x",
	    get16(&req[4]), psm);
	ATF_CHECK_MSG(get16(&req[6]) >= NG_L2CAP_MTU_ECBFC_MINIMUM,
	    "MTU %u is below the 64-octet ECBFC minimum", get16(&req[6]));
	ATF_CHECK_MSG(get16(&req[8]) >= NG_L2CAP_MTU_ECBFC_MINIMUM,
	    "MPS %u is below the 64-octet ECBFC minimum", get16(&req[8]));
	ATF_CHECK_MSG(get16(&req[10]) > 0, "Initial Credits must be non-zero");

	*ident = req[1];
	*scid = get16(&req[12]);
	ATF_CHECK_MSG(*scid >= NG_L2CAP_FIRST_CID && *scid <=
	    NG_L2CAP_LELAST_CID, "Source CID %#x is outside the LE dynamic "
	    "range", *scid);
}

/*
 * Wait for the L2CA_Connect confirmation, ignoring the L2CA_ConnectInd and
 * hook-info messages ng_l2cap also raises on the upper hooks.
 */
static struct ng_mesg *
wait_l2ca_con(struct vhci_rig *r, int ms)
{
	struct ng_mesg *msg;

	while ((msg = vh_recv_msg(r, ms)) != NULL) {
		if (msg->header.typecookie == NGM_L2CAP_COOKIE &&
		    msg->header.cmd == NGM_L2CAP_L2CA_CON)
			return (msg);
		free(msg);
	}

	return (NULL);
}

/*
 * Central-role ATT and SMP fixed channels must open.
 *
 * The fixed channels exist as soon as the LE link does, so
 * ng_l2cap_l2ca_con_req() does not negotiate with the peer: it synthesises an
 * L2CAP_ConnectRsp, flags it M_PROTO2, and lets ng_l2cap_lp_send_pending()
 * loop it straight back into the receive path, where completing the command
 * raises the L2CA_ConnectCfm the socket layer is blocked on.
 *
 * That synthesised frame is in the classic ConnectRsp format and therefore
 * travels on the BR/EDR signalling CID, which [Vol 3] Part A, Table 2.1
 * forbids a PEER from using on an LE-U link.  A link-type guard that does not
 * distinguish our own looped-back frame from peer traffic drops it, the
 * confirmation never arrives, and the channel sits in W4_L2CAP_CON_RSP until
 * the RTX timeout -- taking every GATT client procedure, all of HOGP and
 * SMP-as-central with it.  Nothing else in this suite drives the outbound
 * path: vh_le_connect() exercises inbound channel creation only.
 */
ATF_TC(att_central_fixed_channel_opens);
ATF_TC_HEAD(att_central_fixed_channel_opens, tc)
{

	atf_tc_set_md_var(tc, "descr", "A central-role L2CA_Connect for the "
	    "ATT fixed channel completes and opens the channel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(att_central_fixed_channel_opens, tc)
{
	struct vhci_rig rig;
	struct ng_mesg *msg;
	ng_l2cap_l2ca_con_ip ip;
	ng_l2cap_l2ca_con_op op;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	memset(&ip, 0, sizeof(ip));
	ip.psm = 0;			/* fixed channel: no PSM */
	memcpy(&ip.bdaddr, rig.bdaddr, sizeof(rig.bdaddr));
	ip.linktype = NG_HCI_LINK_LE_PUBLIC;
	ip.idtype = NG_L2CAP_L2CA_IDTYPE_ATT;
	ip.own_address_type = 0;

	ATF_REQUIRE_MSG(NgSendMsg(rig.cs, ".:l2c", NGM_L2CAP_COOKIE,
	    NGM_L2CAP_L2CA_CON, &ip, sizeof(ip)) >= 0,
	    "L2CA_Connect: %s", strerror(errno));

	msg = wait_l2ca_con(&rig, VH_TIMEO_MS);
	ATF_REQUIRE_MSG(msg != NULL, "a central-role L2CA_Connect for the ATT "
	    "fixed channel produced no confirmation: the synthesised "
	    "ConnectRsp never reached the signalling decoder, so the channel "
	    "is stuck in W4_L2CAP_CON_RSP and central-role ATT cannot open");
	ATF_REQUIRE_EQ(sizeof(op), msg->header.arglen);

	memcpy(&op, msg->data, sizeof(op));
	ATF_CHECK_EQ_MSG(NG_L2CAP_SUCCESS, op.result,
	    "the ATT channel did not open: result %#x", op.result);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ATT, op.idtype);
	ATF_CHECK_EQ_MSG(NG_L2CAP_ATT_CID, op.lcid,
	    "confirmation names lcid %#x, expected the ATT CID %#x",
	    op.lcid, NG_L2CAP_ATT_CID);
	free(msg);

	vh_down(&rig);
}

ATF_TC(ecbfc_outbound_connect_completes);
ATF_TC_HEAD(ecbfc_outbound_connect_completes, tc)
{

	atf_tc_set_md_var(tc, "descr", "An outbound Enhanced Credit Based "
	    "connection completes and opens the channel");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ecbfc_outbound_connect_completes, tc)
{
	struct vhci_rig rig;
	struct ng_mesg *msg;
	ng_l2cap_l2ca_con_op op;
	uint8_t rsp[14];
	uint8_t ident;
	uint16_t scid;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	ecbfc_connect_req(&rig, NG_L2CAP_PSM_EATT, &ident, &scid);

	/*
	 * L2CAP_CREDIT_BASED_CONNECTION_RSP (Vol 3 Part A 4.26): MTU, MPS,
	 * Initial Credits, Result, then one Destination CID per Source CID
	 * in the request.
	 */
	rsp[0] = NG_L2CAP_CREDIT_CON_RSP;
	rsp[1] = ident;
	put16(&rsp[2], 10);
	put16(&rsp[4], 512);		/* MTU */
	put16(&rsp[6], 247);		/* MPS */
	put16(&rsp[8], 10);		/* Initial Credits */
	put16(&rsp[10], NG_L2CAP_LE_COC_SUCCESS);
	put16(&rsp[12], 0x0041);	/* Destination CID */
	vh_send_bframe(&rig, NG_L2CAP_LESIGNAL_CID, rsp, sizeof(rsp));

	msg = wait_l2ca_con(&rig, VH_TIMEO_MS);
	ATF_REQUIRE_MSG(msg != NULL, "a successful ECBFC connection response "
	    "produced no L2CA_Connect confirmation: the outbound path never "
	    "completes");
	ATF_REQUIRE_EQ(sizeof(op), msg->header.arglen);

	memcpy(&op, msg->data, sizeof(op));
	ATF_CHECK_EQ_MSG(NG_L2CAP_SUCCESS, op.result,
	    "the channel did not open: result %#x", op.result);
	ATF_CHECK_EQ(NG_L2CAP_L2CA_IDTYPE_ECBFC, op.idtype);
	ATF_CHECK_EQ_MSG(scid, op.lcid, "confirmation names lcid %#x, "
	    "expected the requested Source CID %#x", op.lcid, scid);
	ATF_CHECK_EQ_MSG(512, op.omtu, "outgoing MTU is %u, expected the "
	    "peer's 512", op.omtu);
	free(msg);

	vh_down(&rig);
}

/*
 * Vol 3 Part A 4.24 and 10.1: a receiver spends one credit per K-frame and
 * must return credits as the frames are consumed.  Withholding them until
 * a whole SDU has been reassembled deadlocks any peer whose credit window
 * is smaller than the SDU.  This case sends a two-K-frame SDU and asserts
 * an L2CAP_FLOW_CONTROL_CREDIT_IND after the first frame -- before the SDU
 * is complete -- and another after the second.
 */
ATF_TC(ecbfc_per_frame_credit_return);
ATF_TC_HEAD(ecbfc_per_frame_credit_return, tc)
{

	atf_tc_set_md_var(tc, "descr", "Credits are returned per K-frame, "
	    "not only when an SDU completes");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ecbfc_per_frame_credit_return, tc)
{
	struct vhci_rig rig;
	struct ng_mesg *msg;
	uint8_t rsp[14], kf[VH_BUFSZ], cred[VH_BUFSZ];
	uint8_t ident;
	uint16_t scid, cid;
	ssize_t n;
	int i;

	vh_require();
	vh_up(&rig);
	vh_le_connect(&rig, LE_HANDLE, ROLE_CENTRAL);

	ecbfc_connect_req(&rig, NG_L2CAP_PSM_EATT, &ident, &scid);

	rsp[0] = NG_L2CAP_CREDIT_CON_RSP;
	rsp[1] = ident;
	put16(&rsp[2], 10);
	put16(&rsp[4], 512);
	put16(&rsp[6], 247);
	put16(&rsp[8], 10);
	put16(&rsp[10], NG_L2CAP_LE_COC_SUCCESS);
	put16(&rsp[12], 0x0041);
	vh_send_bframe(&rig, NG_L2CAP_LESIGNAL_CID, rsp, sizeof(rsp));

	msg = wait_l2ca_con(&rig, VH_TIMEO_MS);
	ATF_REQUIRE_MSG(msg != NULL, "the ECBFC channel never opened, so "
	    "credit return cannot be exercised");
	free(msg);

	/*
	 * First K-frame: 2-octet SDU Length (300) plus 200 octets of the
	 * SDU.  The SDU is incomplete, so nothing may go up yet -- but the
	 * credit must come back.
	 */
	put16(&kf[0], 300);
	for (i = 0; i < 200; i++)
		kf[2 + i] = (uint8_t)i;
	vh_send_bframe(&rig, scid, kf, 202);

	n = vh_recv_bframe(&rig, &cid, cred, sizeof(cred), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "no credit was returned after the first "
	    "K-frame of a multi-frame SDU; a peer with a small credit "
	    "window deadlocks here");
	ATF_CHECK_EQ(NG_L2CAP_LESIGNAL_CID, cid);
	ATF_REQUIRE_EQ_MSG(NG_L2CAP_FLOW_CONTROL_CREDIT, cred[0],
	    "expected L2CAP_FLOW_CONTROL_CREDIT_IND (%#x), got code %#x",
	    NG_L2CAP_FLOW_CONTROL_CREDIT, cred[0]);
	ATF_REQUIRE_EQ(4, get16(&cred[2]));
	ATF_CHECK_EQ_MSG(scid, get16(&cred[4]), "the credit names CID %#x, "
	    "expected our Source CID %#x", get16(&cred[4]), scid);
	ATF_CHECK_EQ_MSG(1, get16(&cred[6]), "expected exactly one credit "
	    "for one consumed K-frame, got %u", get16(&cred[6]));

	/* Second K-frame completes the SDU: 100 more octets. */
	for (i = 0; i < 100; i++)
		kf[i] = (uint8_t)(0x40 + i);
	vh_send_bframe(&rig, scid, kf, 100);

	n = vh_recv_bframe(&rig, &cid, cred, sizeof(cred), VH_TIMEO_MS);
	ATF_REQUIRE_MSG(n >= 0, "no credit was returned after the K-frame "
	    "that completed the SDU");
	ATF_CHECK_EQ(NG_L2CAP_LESIGNAL_CID, cid);
	ATF_CHECK_EQ(NG_L2CAP_FLOW_CONTROL_CREDIT, cred[0]);
	ATF_CHECK_EQ(scid, get16(&cred[4]));
	ATF_CHECK_EQ_MSG(1, get16(&cred[6]), "expected exactly one credit "
	    "for the second consumed K-frame, got %u", get16(&cred[6]));

	vh_down(&rig);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, param_update_supervision_bound);
	ATF_TP_ADD_TC(tp, param_update_range_edges);
	ATF_TP_ADD_TC(tp, param_update_role_gate);
	ATF_TP_ADD_TC(tp, smp_minimum_size_survives);
	ATF_TP_ADD_TC(tp, smp_public_key_survives);
	ATF_TP_ADD_TC(tp, att_pdu_above_default_mtu_survives);
	ATF_TP_ADD_TC(tp, att_central_fixed_channel_opens);
	ATF_TP_ADD_TC(tp, ecbfc_outbound_connect_completes);
	ATF_TP_ADD_TC(tp, ecbfc_per_frame_credit_return);

	return (atf_no_error());
}
