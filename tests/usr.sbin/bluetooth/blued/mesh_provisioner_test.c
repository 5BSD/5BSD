/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the driven provisioning roles (mesh_provisioner.[ch],
 * MshPRT_v1.1 Section 5).
 *
 * PROVISIONING RUN.  A Provisioner session and a Device session are driven
 * against each other, PDU by PDU, using the Section 8.7 private keys and
 * provisioning data, fixed 256-bit Provisioning Randoms, and No-OOB
 * authentication.  The exchange must reproduce fixed expected HMAC
 * provisioning results, and both sides must end
 * holding the same DevKey with the device holding the handed-over NetKey /
 * IV Index / unicast address.  This exercises the whole Section 5.4 sequence -
 * Invite, Capabilities, Start, Public Key, Confirmation, Random, Data, Complete
 * - as a running protocol.
 *
 * LINK / TRANSACTION.  The PB-ADV link layer is driven through Link Open / Ack,
 * a multi-segment transaction with a simulated first-attempt loss and a timed
 * retransmission, the Transaction Acknowledgment, and the retransmission-budget
 * failure - all on an injected millisecond clock.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_provision.h"
#include "mesh_provisioner.h"
#include "spec_mesh_provision_oracles.h"

static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

#define	HEX(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

static void
assert_provisioning_wire_contract(void)
{
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_INVITE, MESH_PROV_INVITE);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_CAPABILITIES, MESH_PROV_CAPABILITIES);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_START, MESH_PROV_START);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_PUBLIC_KEY, MESH_PROV_PUBLIC_KEY);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_CONFIRMATION, MESH_PROV_CONFIRMATION);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_RANDOM, MESH_PROV_RANDOM);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_DATA, MESH_PROV_DATA);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_COMPLETE, MESH_PROV_COMPLETE);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_FAILED, MESH_PROV_FAILED);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_ALGO_P256_CMAC,
	    MESH_PROV_ALGO_P256_CMAC);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_ALGO_P256_HMAC,
	    MESH_PROV_ALGO_P256_HMAC);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_ALGO_BIT_CMAC,
	    MESH_PROV_ALGO_BIT_P256_CMAC);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_ALGO_BIT_HMAC,
	    MESH_PROV_ALGO_BIT_P256_HMAC);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_INVITE_VALUE_SIZE,
	    MESH_PROV_INVITE_VAL_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_CAPS_VALUE_SIZE,
	    MESH_PROV_CAPS_VAL_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_START_VALUE_SIZE,
	    MESH_PROV_START_VAL_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_P256_PUBLIC_SIZE,
	    MESH_PROV_PUBKEY_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_CMAC_CONFIRM_SIZE,
	    MESH_PROV_CONFIRM_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_CMAC_RANDOM_SIZE,
	    MESH_PROV_RANDOM_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_PDU_MAX_SIZE, MESH_PROV_PDU_MAX);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_DATA_SIZE, MESH_PROV_DATA_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PROV_DATA_ENC_SIZE, MESH_PROV_DATA_ENC_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_GP_START_DATA_MAX, MESH_GP_START_MAX);
	ATF_CHECK_EQ(BT_MSHPRT11_GP_CONT_DATA_MAX, MESH_GP_CONT_MAX);
	ATF_CHECK_EQ(BT_MSHPRT11_GPCF_START, MESH_GPCF_START);
	ATF_CHECK_EQ(BT_MSHPRT11_GPCF_ACK, MESH_GPCF_ACK);
	ATF_CHECK_EQ(BT_MSHPRT11_GPCF_CONTINUATION, MESH_GPCF_CONTINUATION);
	ATF_CHECK_EQ(BT_MSHPRT11_GPCF_CONTROL, MESH_GPCF_CONTROL);
	ATF_CHECK_EQ(BT_MSHPRT11_GP_PDU_MAX_SIZE, MESH_GP_PDU_MAX);
	ATF_CHECK_EQ(BT_MSHPRT11_PBADV_HEADER_SIZE, MESH_PBADV_HDR_LEN);
	ATF_CHECK_EQ(BT_MSHPRT11_PBADV_PACKET_MAX_SIZE, MESH_PBADV_PKT_MAX);
}

/* Move every queued outbound PDU of one session into the other. */
static void
deliver(struct mesh_prov_session *from, struct mesh_prov_session *to)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	while (mesh_prov_session_poll(from, pdu, &len) == 1)
		(void)mesh_prov_session_recv(to, pdu, len);
}

/* ================================================================
 * Full Provisioner <-> Device HMAC-SHA-256 run with deterministic inputs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provisioning_run);
ATF_TC_BODY(provisioning_run, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata, got;
	HEX(ppriv, BT_MSHPRT11_PROV_SAMPLE_PRIVATE_HEX, 32);
	HEX(dpriv, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PRIVATE_HEX, 32);
	HEX(rprov, BT_MSHPRT11_PROV_SAMPLE_PROVISIONER_RANDOM_HEX, 32);
	HEX(rdev, BT_MSHPRT11_PROV_SAMPLE_DEVICE_RANDOM_HEX, 32);
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	HEX(exp_devkey, BT_MSHPRT11_PROV_SAMPLE_DEVICE_KEY_HEX, 16);
	HEX(exp_skey, BT_MSHPRT11_PROV_SAMPLE_SESSION_KEY_HEX, 16);
	HEX(exp_snonce, BT_MSHPRT11_PROV_SAMPLE_SESSION_NONCE_HEX, 13);
	HEX(exp_confp, BT_MSHPRT11_PROV_SAMPLE_PROVISIONER_CONFIRM_HEX, 32);
	HEX(exp_confd, BT_MSHPRT11_PROV_SAMPLE_DEVICE_CONFIRM_HEX, 32);
	HEX(exp_netkey, BT_MSHPRT11_PROV_SAMPLE_NETKEY_HEX, 16);
	int i;

	assert_provisioning_wire_contract();
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* Device init must add the mandatory Mesh 1.1 HMAC capability bit. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, ppriv, rprov, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, dpriv, rdev, &caps));
	ATF_CHECK((dev.caps.algorithms & MESH_PROV_ALGO_BIT_P256_HMAC) != 0);

	/* Provisioner emits the Invite; then pump both sides to quiescence. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	for (i = 0; i < 16; i++) {
		deliver(&prov, &dev);
		deliver(&dev, &prov);
		if (mesh_prov_session_done(&prov) && mesh_prov_session_done(&dev))
			break;
	}

	ATF_CHECK(mesh_prov_session_done(&prov));
	ATF_CHECK(mesh_prov_session_done(&dev));
	ATF_CHECK(!mesh_prov_session_failed(&prov));
	ATF_CHECK(!mesh_prov_session_failed(&dev));
	ATF_CHECK_EQ(MESH_PROV_ALGO_P256_HMAC, prov.algorithm);
	ATF_CHECK_EQ(MESH_PROV_ALGO_P256_HMAC, dev.algorithm);

	/* Both sides derived the same expected DevKey. */
	ATF_CHECK_EQ_MSG(0, memcmp(mesh_prov_session_devkey(&prov), exp_devkey,
	    16), "provisioner DevKey (8.7.12)");
	ATF_CHECK_EQ_MSG(0, memcmp(mesh_prov_session_devkey(&dev), exp_devkey,
	    16), "device DevKey (8.7.12)");

	/* The negotiated HMAC session material matches the regression vectors. */
	ATF_CHECK_EQ_MSG(0, memcmp(prov.session_key, exp_skey, 16),
	    "SessionKey (8.7.12)");
	ATF_CHECK_EQ_MSG(0, memcmp(prov.session_nonce, exp_snonce, 13),
	    "SessionNonce (8.7.12)");

	/* Both 256-bit Confirmation values match the regression vectors. */
	ATF_CHECK_EQ_MSG(0, memcmp(prov.peer_confirm, exp_confd, 32),
	    "device Confirmation (8.7.9)");
	ATF_CHECK_EQ_MSG(0, memcmp(dev.peer_confirm, exp_confp, 32),
	    "provisioner Confirmation (8.7.8)");

	/* The device installed the handed-over provisioning data. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_get_data(&dev, &got));
	ATF_CHECK_EQ_MSG(0, memcmp(got.netkey, exp_netkey, 16), "installed NetKey");
	ATF_CHECK_EQ(0x0567, got.netkey_index);
	ATF_CHECK_EQ(0x01020304, got.iv_index);
	ATF_CHECK_EQ(0x0b0c, got.unicast_addr);

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/* ================================================================
 * A device with the wrong AuthValue produces a mismatching Confirmation, so
 * the provisioner aborts with a Failed PDU (Section 5.4.2.4).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(provisioning_confirmation_mismatch);
ATF_TC_BODY(provisioning_confirmation_mismatch, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(ppriv, BT_MSHPRT11_PROV_SAMPLE_PRIVATE_HEX, 32);
	HEX(dpriv, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PRIVATE_HEX, 32);
	HEX(rprov, BT_MSHPRT11_PROV_SAMPLE_PROVISIONER_RANDOM_HEX, 32);
	HEX(rdev, BT_MSHPRT11_PROV_SAMPLE_DEVICE_RANDOM_HEX, 32);
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	static const uint8_t oob_a[4] = { 0x12, 0x34, 0x56, 0x78 };
	static const uint8_t oob_b[4] = { 0x12, 0x34, 0x56, 0x79 };
	int i;

	assert_provisioning_wire_contract();
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	/* Advertise Static OOB so the Provisioner selects method 0x01. */
	caps.static_oob_type = MESH_PROV_OOB_TYPE_STATIC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, ppriv, rprov, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, dpriv, rdev, &caps));

	/*
	 * Give the two roles DIFFERENT Static OOB values: the operator typed
	 * the wrong number off the label.  Both compute an AuthValue, they do
	 * not match, and the Confirmation must fail (MshPRT_v1.1.1 Section
	 * 5.4.2.4.1 / 5.4.2.5).
	 *
	 * Corrupting session->auth directly no longer works, and that is the
	 * point of the fix: the AuthValue is now (re)computed from the
	 * selected authentication method when Provisioning Start fixes the
	 * algorithm, instead of being frozen at No-OOB in the role init.
	 */
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_static_oob(&prov, oob_a,
	    sizeof(oob_a)));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_static_oob(&dev, oob_b,
	    sizeof(oob_b)));

	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	for (i = 0; i < 16; i++) {
		deliver(&prov, &dev);
		deliver(&dev, &prov);
		if (mesh_prov_session_failed(&prov) ||
		    mesh_prov_session_failed(&dev))
			break;
	}
	ATF_CHECK(mesh_prov_session_failed(&prov));
	ATF_CHECK(!mesh_prov_session_done(&prov));

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/* ================================================================
 * PB-ADV link: Link Open/Ack, a lost multi-segment transaction retransmitted
 * on the timer, and the Transaction Ack (Section 5.3.1).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(link_open_and_retransmit);
ATF_TC_BODY(link_open_and_retransmit, tc)
{
	struct mesh_prov_link pl, dl;
	uint8_t uuid[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	uint8_t seg0[MESH_PBADV_PKT_MAX], seg1[MESH_PBADV_PKT_MAX];
	uint8_t ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	uint8_t payload[40];
	size_t pktlen, s0, s1, acklen, rlen;
	int have_pdu, have_ack;
	uint64_t now;
	size_t i;

	assert_provisioning_wire_contract();
	memset(uuid, 0xAB, sizeof(uuid));
	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)i;

	mesh_prov_link_init_provisioner(&pl, 0x12345678, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);

	/* Link Open -> Link Ack. */
	now = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK(have_ack);
	ATF_CHECK(mesh_prov_link_is_open(&dl));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(mesh_prov_link_is_open(&pl));

	/* Queue a 40-octet PDU: it segments into a Start + one Continuation. */
	now = 100;
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&pl, payload, sizeof(payload), now));

	/* First attempt: capture both segments but DROP them (simulated loss). */
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg0, &s0));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg1, &s1));
	ATF_CHECK_EQ(0, mesh_prov_link_poll(&pl, now, pkt, &pktlen));

	/* Before the retransmission timeout nothing is due. */
	now = 500;
	ATF_CHECK_EQ(0, mesh_prov_link_poll(&pl, now, pkt, &pktlen));

	/* After the timeout the whole transaction is retransmitted. */
	now = 1200;
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg0, &s0));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg1, &s1));

	/* The device reassembles and acknowledges. */
	have_pdu = have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg0, s0, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ(0, have_pdu);
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg1, s1, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK(have_pdu);
	ATF_CHECK(have_ack);
	ATF_CHECK_EQ(sizeof(payload), rlen);
	ATF_CHECK_EQ_MSG(0, memcmp(rpdu, payload, sizeof(payload)),
	    "reassembled Provisioning PDU");

	/* The provisioner clears the transaction on the Ack. */
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(0, pl.awaiting_ack);
	ATF_CHECK_EQ(0, mesh_prov_link_poll(&pl, now + 5000, pkt, &pktlen));
}

/* ================================================================
 * The retransmission budget is finite: with no Ack the link fails.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(link_retransmit_budget);
ATF_TC_BODY(link_retransmit_budget, tc)
{
	struct mesh_prov_link pl, dl;
	uint8_t uuid[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	uint8_t payload[40];
	size_t pktlen, acklen;
	int have_ack, rc;
	uint64_t now;
	int i;

	assert_provisioning_wire_contract();
	memset(uuid, 0x11, sizeof(uuid));
	memset(payload, 0x5a, sizeof(payload));

	mesh_prov_link_init_provisioner(&pl, 0x1, uuid, 1000, 1);
	mesh_prov_link_init_device(&dl, uuid, 1000, 1);

	now = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));

	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&pl, payload, sizeof(payload), now));

	/* Drain all output, never acknowledging; the link must eventually fail. */
	rc = 0;
	for (i = 0; i < 100; i++) {
		now += 1;
		rc = mesh_prov_link_poll(&pl, now, pkt, &pktlen);
		if (rc == -1)
			break;
		if (rc == 0)
			now += 1000;	/* jump past the retransmission timeout */
	}
	ATF_CHECK_EQ(-1, rc);
}

/* ================================================================
 * PB-ADV duplicate transaction: after a lost Transaction Ack the sender
 * retransmits the whole (already-completed) transaction.  The receiver must
 * re-emit the Transaction Ack but deliver the Provisioning PDU only once
 * (Section 5.3.1), so the session is never fed the same PDU twice.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(link_duplicate_transaction);
ATF_TC_BODY(link_duplicate_transaction, tc)
{
	struct mesh_prov_link pl, dl;
	uint8_t uuid[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX];
	uint8_t seg0[MESH_PBADV_PKT_MAX], seg1[MESH_PBADV_PKT_MAX];
	uint8_t ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	uint8_t payload[40];
	size_t pktlen, s0, s1, acklen, rlen;
	int have_pdu, have_ack;
	uint64_t now = 0;
	size_t i;

	assert_provisioning_wire_contract();
	memset(uuid, 0xCD, sizeof(uuid));
	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(0x40 + i);

	mesh_prov_link_init_provisioner(&pl, 0x0badf00d, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);

	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));

	/* Send a two-segment transaction; capture both segments. */
	now = 100;
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&pl, payload, sizeof(payload), now));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg0, &s0));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg1, &s1));

	/* First delivery: reassemble and acknowledge exactly once. */
	have_pdu = have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg0, s0, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ(0, have_pdu);
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg1, s1, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK(have_pdu);
	ATF_CHECK(have_ack);
	ATF_CHECK_EQ(sizeof(payload), rlen);

	/*
	 * The Ack was "lost": the provisioner retransmits the whole transaction.
	 * The device must re-Ack on the retransmitted Transaction Start but must
	 * NOT re-deliver the PDU (a second delivery would abort the session).
	 */
	have_pdu = have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg0, s0, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ_MSG(0, have_pdu, "retransmitted Start must not re-deliver");
	ATF_CHECK_MSG(have_ack, "retransmitted Start must be re-acknowledged");

	have_pdu = have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg1, s1, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ_MSG(0, have_pdu, "retransmitted Continuation must not re-deliver");

	/* A genuinely new transaction (next txn) is still delivered normally. */
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	now = 200;
	payload[0] = 0xFF;
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&pl, payload, sizeof(payload), now));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg0, &s0));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&pl, now, seg1, &s1));
	have_pdu = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg0, s0, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, seg1, s1, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_MSG(have_pdu, "a new transaction is delivered");
	ATF_CHECK_EQ(0xFF, rpdu[0]);
}

ATF_TC_WITHOUT_HEAD(api_and_state_guard_matrix);
ATF_TC_BODY(api_and_state_guard_matrix, tc)
{
	struct mesh_prov_session s;
	struct mesh_prov_link l;
	struct mesh_prov_data data;
	struct mesh_prov_caps caps;
	uint8_t uuid[16] = { 0 }, buf[MESH_PBADV_PKT_MAX], byte = 0;
	size_t len;

	assert_provisioning_wire_contract();
	memset(&s, 0, sizeof(s));
	memset(&data, 0, sizeof(data));
	memset(&caps, 0, sizeof(caps));
	ATF_CHECK_EQ(-1, mesh_prov_provisioner_init(NULL, NULL, NULL, 0,
	    &data));
	ATF_CHECK_EQ(-1, mesh_prov_provisioner_init(&s, NULL, NULL, 0, NULL));
	ATF_CHECK_EQ(-1, mesh_prov_device_init(NULL, NULL, NULL, &caps));
	ATF_CHECK_EQ(-1, mesh_prov_device_init(&s, NULL, NULL, NULL));
	mesh_prov_session_free(NULL);
	ATF_CHECK_EQ(-1, mesh_prov_session_start(NULL));
	s.role = MESH_PROV_ROLE_DEVICE; s.state = MPS_D_WAIT_INVITE;
	ATF_CHECK_EQ(-1, mesh_prov_session_start(&s));
	s.role = MESH_PROV_ROLE_PROVISIONER; s.state = MPS_P_WAIT_CAPS;
	ATF_CHECK_EQ(-1, mesh_prov_session_start(&s));
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(NULL, &byte, 1));
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, NULL, 1));
	s.state = MPS_DONE;
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, &byte, 1));
	s.state = MPS_P_WAIT_CAPS;
	byte = 0xff;
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, &byte, 1));
	ATF_CHECK(mesh_prov_session_failed(&s));
	ATF_CHECK(!mesh_prov_session_done(NULL));
	ATF_CHECK(!mesh_prov_session_failed(NULL));
	ATF_CHECK(mesh_prov_session_devkey(NULL) == NULL);
	ATF_CHECK_EQ(-1, mesh_prov_session_get_data(NULL, &data));
	ATF_CHECK_EQ(-1, mesh_prov_session_get_data(&s, NULL));
	ATF_CHECK_EQ(-1, mesh_prov_session_get_data(&s, &data));
	ATF_CHECK_EQ(-1, mesh_prov_session_poll(NULL, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_session_poll(&s, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_prov_session_poll(&s, buf, NULL));
	/* The malformed PDU queued a Failed response, then the FIFO empties. */
	ATF_CHECK_EQ(1, mesh_prov_session_poll(&s, buf, &len));
	ATF_CHECK_EQ(0, mesh_prov_session_poll(&s, buf, &len));

	mesh_prov_link_init_provisioner(NULL, 1, uuid, 10, 1);
	mesh_prov_link_init_device(NULL, uuid, 10, 1);
	mesh_prov_link_init_device(&l, uuid, 10, 1);
	ATF_CHECK_EQ(-1, mesh_prov_link_open(NULL, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_open(&l, 0, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_open(&l, 0, buf, NULL));
	ATF_CHECK_EQ(-1, mesh_prov_link_open(&l, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_close(NULL, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_close(&l, 0, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_close(&l, 0, buf, NULL));
	ATF_CHECK_EQ(0, mesh_prov_link_close(&l, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_send(NULL, &byte, 1, 0));
	ATF_CHECK_EQ(-1, mesh_prov_link_send(&l, NULL, 1, 0));
	ATF_CHECK_EQ(-1, mesh_prov_link_send(&l, &byte, 1, 0));
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(NULL, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&l, 0, NULL, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&l, 0, buf, NULL));
	l.state = MESH_LINK_FAILED;
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&l, 0, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_recv(NULL, buf, len, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, mesh_prov_link_recv(&l, NULL, 0, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(!mesh_prov_link_is_open(NULL));

	/* Opening retransmission: not due, one retry, then bounded failure. */
	mesh_prov_link_init_provisioner(&l, 1, uuid, 10, 1);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&l, 0, buf, &len));
	ATF_CHECK_EQ(0, mesh_prov_link_poll(&l, 9, buf, &len));
	ATF_CHECK_EQ(1, mesh_prov_link_poll(&l, 10, buf, &len));
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&l, 20, buf, &len));
	ATF_CHECK_EQ(MESH_LINK_FAILED, l.state);
}

ATF_TC_WITHOUT_HEAD(session_unexpected_pdu_matrix);
ATF_TC_BODY(session_unexpected_pdu_matrix, tc)
{
	struct mesh_prov_session s;
	struct mesh_prov_link tx, rx;
	uint8_t pdu[MESH_PROV_PDU_MAX] = { 0 };
	uint8_t pkt[MESH_PBADV_PKT_MAX], gp[MESH_GP_PDU_MAX];
	size_t pktlen, gplen;
	static const struct {
		uint8_t type;
		size_t len;
	} prov_pdus[] = {
		{ MESH_PROV_CAPABILITIES, 1 + MESH_PROV_CAPS_VAL_LEN },
		{ MESH_PROV_PUBLIC_KEY, 1 + MESH_PROV_PUBKEY_LEN },
		{ MESH_PROV_CONFIRMATION, 1 + MESH_PROV_CONFIRM_LEN },
		{ MESH_PROV_RANDOM, 1 + MESH_PROV_RANDOM_LEN },
		{ MESH_PROV_COMPLETE, 1 },
		{ MESH_PROV_INVITE, 1 + MESH_PROV_INVITE_VAL_LEN },
	}, dev_pdus[] = {
		{ MESH_PROV_INVITE, 1 + MESH_PROV_INVITE_VAL_LEN },
		{ MESH_PROV_START, 1 + MESH_PROV_START_VAL_LEN },
		{ MESH_PROV_PUBLIC_KEY, 1 + MESH_PROV_PUBKEY_LEN },
		{ MESH_PROV_CONFIRMATION, 1 + MESH_PROV_CONFIRM_LEN },
		{ MESH_PROV_RANDOM, 1 + MESH_PROV_RANDOM_LEN },
		{ MESH_PROV_DATA, 1 + MESH_PROV_DATA_ENC_LEN },
		{ MESH_PROV_COMPLETE, 1 },
	};
	size_t i;

	assert_provisioning_wire_contract();
	/* Every recognized PDU has an explicit out-of-state failure arm. */
	for (i = 0; i < nitems(prov_pdus); i++) {
		memset(&s, 0, sizeof(s));
		s.role = MESH_PROV_ROLE_PROVISIONER;
		s.state = MPS_P_IDLE;
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = prov_pdus[i].type;
		ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu,
		    prov_pdus[i].len));
		ATF_CHECK_EQ(MPS_FAILED, s.state);
	}
	for (i = 0; i < nitems(dev_pdus); i++) {
		memset(&s, 0, sizeof(s));
		s.role = MESH_PROV_ROLE_DEVICE;
		s.state = dev_pdus[i].type == MESH_PROV_INVITE ?
		    MPS_D_WAIT_START : MPS_D_WAIT_INVITE;
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = dev_pdus[i].type;
		ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu,
		    dev_pdus[i].len));
		ATF_CHECK_EQ(MPS_FAILED, s.state);
	}

	/*
	 * A Provisionee may advertise only BTM_ECDH_P256_CMAC (Table 5.21):
	 * the provisioner accepts CMAC-only Capabilities and negotiates CMAC.
	 */
	memset(&s, 0, sizeof(s));
	s.role = MESH_PROV_ROLE_PROVISIONER;
	s.state = MPS_P_WAIT_CAPS;
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = MESH_PROV_CAPABILITIES;
	pdu[1] = 1;
	pdu[3] = MESH_PROV_ALGO_BIT_P256_CMAC;
	ATF_CHECK_EQ(0, mesh_prov_session_recv(&s, pdu,
	    1 + MESH_PROV_CAPS_VAL_LEN));
	ATF_CHECK_EQ(MPS_P_WAIT_PUBKEY, s.state);
	ATF_CHECK_EQ(MESH_PROV_ALGO_P256_CMAC, s.algorithm);

	/* A device rejects an unsupported/ill-formed Start selection. */
	memset(&s, 0, sizeof(s));
	s.role = MESH_PROV_ROLE_DEVICE;
	s.state = MPS_D_WAIT_START;
	s.caps.algorithms = MESH_PROV_ALGO_BIT_P256_HMAC;
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = MESH_PROV_START;
	pdu[1] = MESH_PROV_ALGO_P256_HMAC;
	pdu[3] = 2;		/* Output OOB, but no output capability. */
	pdu[4] = 0;
	pdu[5] = 1;
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu,
	    1 + MESH_PROV_START_VAL_LEN));
	ATF_CHECK_EQ(0x01, s.error);	/* Invalid PDU */

	/* Peer Failed PDUs preserve their specified error on both roles. */
	for (i = 0; i < 2; i++) {
		memset(&s, 0, sizeof(s));
		s.role = i == 0 ? MESH_PROV_ROLE_PROVISIONER :
		    MESH_PROV_ROLE_DEVICE;
		s.state = i == 0 ? MPS_P_WAIT_CAPS : MPS_D_WAIT_INVITE;
		pdu[0] = MESH_PROV_FAILED; pdu[1] = 0x08;
		ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu, 2));
		ATF_CHECK_EQ(0x08, s.error);
	}

	/* A failure still transitions state if its outbound queue is full. */
	memset(&s, 0, sizeof(s));
	s.role = MESH_PROV_ROLE_PROVISIONER; s.state = MPS_P_IDLE;
	s.txq_tail = MESH_PROV_SESS_TXQ - 1;
	pdu[0] = MESH_PROV_INVITE; pdu[1] = 0;
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu, 2));
	ATF_CHECK_EQ(MPS_FAILED, s.state);

	/* Link Close is accepted on receive; malformed envelope/body is not. */
	mesh_prov_link_init_provisioner(&tx, 7, NULL, 10, 1);
	mesh_prov_link_init_device(&rx, NULL, 10, 1);
	ATF_REQUIRE_EQ(0, mesh_prov_link_close(&tx, 0, pkt, &pktlen));
	rx.state = MESH_LINK_OPEN;
	rx.link_id = 7;		/* the link the Close (and packets) belong to */
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&rx, pkt, pktlen, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK_EQ(MESH_LINK_CLOSED, rx.state);
	ATF_CHECK_EQ(-1, mesh_prov_link_recv(&rx, pkt, 1, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	gp[0] = 0xff; gplen = 1;
	ATF_REQUIRE_EQ(0, mesh_pbadv_build(7, 0, gp, gplen, pkt, &pktlen));
	ATF_CHECK_EQ(-1, mesh_prov_link_recv(&rx, pkt, pktlen, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
}

/* ================================================================
 * A device supports only the No-OOB AuthValue, so a Start selecting Static /
 * Output / Input OOB (auth_method 1-3) must be rejected at Start with Invalid
 * PDU rather than dying with Confirmation Failed later (finding 26,
 * Section 5.4.1.3).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(device_rejects_unsupported_oob_start);
ATF_TC_BODY(device_rejects_unsupported_oob_start, tc)
{
	struct mesh_prov_session s;
	struct mesh_prov_caps caps;
	uint8_t pdu[MESH_PROV_PDU_MAX];

	assert_provisioning_wire_contract();

	/* Advertise Static OOB so the OLD code would have accepted method 1. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.static_oob_type = 0x01;
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&s, NULL, NULL, &caps));
	s.state = MPS_D_WAIT_START;

	memset(pdu, 0, sizeof(pdu));
	pdu[0] = MESH_PROV_START;
	pdu[1] = MESH_PROV_ALGO_P256_CMAC;	/* algorithm 0x00 */
	pdu[2] = 0;				/* No OOB public key */
	pdu[3] = 1;				/* auth_method = Static OOB */
	pdu[4] = 0;				/* auth_action */
	pdu[5] = 0;				/* auth_size */
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&s, pdu,
	    1 + MESH_PROV_START_VAL_LEN));
	ATF_CHECK(mesh_prov_session_failed(&s));
	ATF_CHECK_EQ(0x01, s.error);		/* Invalid PDU, not later 0x04 */

	mesh_prov_session_free(&s);
}

/* ================================================================
 * PB-ADV Link ID / Device UUID filtering (finding 20, Section 5.2.2 /
 * 5.3.1.4.1).  A Link Close bearing a foreign Link ID must NOT tear down an
 * established link, and a Link Open whose Device UUID is not ours must NOT be
 * adopted.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(link_foreign_link_id_ignored);
ATF_TC_BODY(link_foreign_link_id_ignored, tc)
{
	struct mesh_prov_link pl, dl, foreign, closer, dl2, opener;
	uint8_t uuid[16], other[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	size_t pktlen, acklen;
	int have_ack;
	uint64_t now = 0;

	assert_provisioning_wire_contract();
	memset(uuid, 0xAB, sizeof(uuid));
	memset(other, 0x99, sizeof(other));

	/* Establish a link: link_id 0x11112222, our UUID. */
	mesh_prov_link_init_provisioner(&pl, 0x11112222, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK(have_ack);
	ATF_CHECK(mesh_prov_link_is_open(&dl));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(mesh_prov_link_is_open(&pl));

	/* An active device must ignore another provisioner's Link Open. */
	mesh_prov_link_init_provisioner(&opener, 0x55556666, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&opener, now + 1, pkt, &pktlen));
	have_ack = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now + 1, NULL,
	    NULL, NULL, ack, &acklen, &have_ack));
	ATF_CHECK_EQ(0, have_ack);
	ATF_CHECK_EQ(0x11112222, dl.link_id);
	ATF_CHECK(mesh_prov_link_is_open(&dl));

	/* A retransmitted Open for the active Link ID is Acked but not reset. */
	mesh_prov_link_init_provisioner(&opener, 0x11112222, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&opener, now + 2, pkt, &pktlen));
	have_ack = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now + 2, NULL,
	    NULL, NULL, ack, &acklen, &have_ack));
	ATF_CHECK(have_ack);
	ATF_CHECK_EQ(0x11112222, dl.link_id);
	ATF_CHECK(mesh_prov_link_is_open(&dl));

	/* A Link Close on a DIFFERENT Link ID must be ignored by both ends. */
	mesh_prov_link_init_provisioner(&foreign, 0x33334444, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_close(&foreign, 0, pkt, &pktlen));
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(mesh_prov_link_is_open(&dl));		/* still open */
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&pl, pkt, pktlen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(mesh_prov_link_is_open(&pl));		/* still open */

	/* A Link Close on the MATCHING Link ID does tear the link down. */
	mesh_prov_link_init_provisioner(&closer, 0x11112222, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_close(&closer, 0, pkt, &pktlen));
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_CHECK(!mesh_prov_link_is_open(&dl));

	/* A Link Open whose Device UUID is not ours must NOT be adopted. */
	mesh_prov_link_init_device(&dl2, uuid, 1000, 3);
	mesh_prov_link_init_provisioner(&opener, 0x55556666, other, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&opener, now, pkt, &pktlen));
	have_ack = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl2, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK_EQ(0, have_ack);			/* no Ack for a foreign UUID */
	ATF_CHECK(!mesh_prov_link_is_open(&dl2));

	/* A Link Open with our UUID is adopted and Acked. */
	mesh_prov_link_init_provisioner(&opener, 0x55556666, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&opener, now, pkt, &pktlen));
	have_ack = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&dl2, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK(have_ack);
	ATF_CHECK(mesh_prov_link_is_open(&dl2));
	ATF_CHECK_EQ(0x55556666, dl2.link_id);
}

/* ================================================================
 * Mandatory 60 s provisioning timers (finding 72, Section 5.3.1.4.1 / 5.4.4).
 * A peer that goes silent must cause the link to time out and FAIL instead of
 * hanging forever - both the link timer on an open link and the
 * link-establishment timer while awaiting the Link Ack.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(link_silent_peer_times_out);
ATF_TC_BODY(link_silent_peer_times_out, tc)
{
	struct mesh_prov_link pl, dl, po;
	uint8_t uuid[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	size_t pktlen, acklen;
	int have_ack;

	assert_provisioning_wire_contract();
	memset(uuid, 0x5A, sizeof(uuid));

	/* Open link timer: silence on an established link closes it at 60 s. */
	mesh_prov_link_init_provisioner(&pl, 0x0abcdef0, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, 0, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, 0, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, 0, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_REQUIRE(mesh_prov_link_is_open(&pl));

	/* Before 60 s of silence nothing is due and the link stays open. */
	ATF_CHECK_EQ(0, mesh_prov_link_poll(&pl, 59999, pkt, &pktlen));
	ATF_CHECK(mesh_prov_link_is_open(&pl));
	/* At 60 s with no received PDU the link times out. */
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&pl, 60000, pkt, &pktlen));
	ATF_CHECK(!mesh_prov_link_is_open(&pl));
	ATF_CHECK_EQ(MESH_LINK_FAILED, pl.state);

	/* Link-establishment timer: a Link Open that is never Acked fails at 60 s. */
	mesh_prov_link_init_provisioner(&po, 0x0fedcba0, uuid, 1000, 100000);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&po, 0, pkt, &pktlen));
	ATF_CHECK_EQ(1, mesh_prov_link_poll(&po, 1000, pkt, &pktlen));	/* retx */
	ATF_CHECK_EQ(MESH_LINK_OPENING, po.state);
	ATF_CHECK_EQ(-1, mesh_prov_link_poll(&po, 60000, pkt, &pktlen));
	ATF_CHECK_EQ(MESH_LINK_FAILED, po.state);
}

/*
 * Round-3 finding 12: transaction segments were reassembled, delivered to the
 * session and ACKED with no link-state check, so Provisioning PDUs were
 * processed on a CLOSED / FAILED / still-OPENING link.  A close must also
 * discard the in-flight transaction state so a reopened link does not inherit
 * a half-built inbound PDU or a pending outbound retransmission.
 */
ATF_TC_WITHOUT_HEAD(link_transactions_require_open_link);
ATF_TC_BODY(link_transactions_require_open_link, tc)
{
	struct mesh_prov_link pl, dl;
	uint8_t uuid[16];
	uint8_t pkt[MESH_PBADV_PKT_MAX], ack[MESH_PBADV_PKT_MAX];
	uint8_t rpdu[MESH_PROV_PDU_MAX];
	uint8_t prov[8];
	size_t pktlen, acklen, rlen;
	int have_ack, have_pdu;
	uint64_t now = 0;

	(void)tc;
	memset(uuid, 0xAB, sizeof(uuid));
	memset(prov, 0x00, sizeof(prov));
	prov[0] = 0x00;				/* Provisioning Invite */

	mesh_prov_link_init_provisioner(&pl, 0x11112222, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);

	/* Still OPENING on the provisioner side: no transaction may be run. */
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	ATF_CHECK(!mesh_prov_link_is_open(&pl));
	have_ack = have_pdu = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK(have_ack);
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&dl, prov, 2, now));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&dl, now, pkt, &pktlen));
	have_ack = have_pdu = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&pl, pkt, pktlen, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ_MSG(0, have_pdu,
	    "no Provisioning PDU is delivered on a link that is not OPEN");
	ATF_CHECK_EQ_MSG(0, have_ack,
	    "no Transaction Ack is emitted on a link that is not OPEN");

	/* Open the link properly. */
	mesh_prov_link_init_provisioner(&pl, 0x11112222, uuid, 1000, 3);
	mesh_prov_link_init_device(&dl, uuid, 1000, 3);
	ATF_REQUIRE_EQ(0, mesh_prov_link_open(&pl, now, pkt, &pktlen));
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_REQUIRE(have_ack);
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&pl, ack, acklen, now, NULL, NULL,
	    NULL, NULL, NULL, NULL));
	ATF_REQUIRE(mesh_prov_link_is_open(&pl));

	/* On an OPEN link the very same transaction IS delivered and acked. */
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&dl, prov, 2, now));
	ATF_REQUIRE_EQ(1, mesh_prov_link_poll(&dl, now, pkt, &pktlen));
	have_ack = have_pdu = 0;
	ATF_CHECK_EQ(0, mesh_prov_link_recv(&pl, pkt, pktlen, now, rpdu, &rlen,
	    &have_pdu, ack, &acklen, &have_ack));
	ATF_CHECK_EQ(1, have_pdu);
	ATF_CHECK_EQ(1, have_ack);

	/* A local close discards the in-flight transaction state. */
	ATF_REQUIRE_EQ(0, mesh_prov_link_send(&pl, prov, 2, now));
	ATF_REQUIRE(pl.nseg != 0);
	ATF_REQUIRE_EQ(0, mesh_prov_link_close(&pl, 0x00, pkt, &pktlen));
	ATF_CHECK_EQ(0u, (unsigned)pl.nseg);
	ATF_CHECK_EQ(0u, (unsigned)pl.seg_cursor);
	ATF_CHECK_EQ(0, pl.awaiting_ack);
	ATF_CHECK_EQ(0, pl.rx_have);

	/* A peer Link Close does the same on the receiving side. */
	ATF_REQUIRE(dl.rx_have == 0 || dl.rx_have == 1);
	have_ack = 0;
	ATF_REQUIRE_EQ(0, mesh_prov_link_recv(&dl, pkt, pktlen, now, NULL, NULL,
	    NULL, ack, &acklen, &have_ack));
	ATF_CHECK(!mesh_prov_link_is_open(&dl));
	ATF_CHECK_EQ(0u, (unsigned)dl.nseg);
	ATF_CHECK_EQ(0, dl.awaiting_ack);
	ATF_CHECK_EQ(0, dl.rx_have);
}


/* ================================================================
 * Operator-driven OOB authentication (MshPRT_v1.1.1 Sections 5.4.1.3,
 * 5.4.2.4.3 and 5.4.2.4.4).
 *
 * The direction of each method is what these cases pin, because getting it
 * backwards is the easy mistake: with OUTPUT OOB the Provisionee generates and
 * outputs the value and the PROVISIONER's user types it, and with INPUT OOB
 * the Provisioner generates and displays it and the PROVISIONEE's user types
 * it, answering with a Provisioning Input Complete PDU.
 * ================================================================ */

/* Pump both sessions, recording every Provisioning PDU type that crosses. */
#define	OOB_TRACE_MAX	32
struct oob_trace {
	uint8_t	type[OOB_TRACE_MAX];
	size_t	n;
};

static void
oob_deliver(struct mesh_prov_session *from, struct mesh_prov_session *to,
    struct oob_trace *tr)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	while (mesh_prov_session_poll(from, pdu, &len) == 1) {
		if (tr != NULL && tr->n < OOB_TRACE_MAX)
			tr->type[tr->n++] = pdu[0];
		(void)mesh_prov_session_recv(to, pdu, len);
	}
}

static size_t
oob_trace_count(const struct oob_trace *tr, uint8_t type)
{
	size_t i, n = 0;

	for (i = 0; i < tr->n; i++)
		if (tr->type[i] == type)
			n++;
	return (n);
}

static void
oob_pump(struct mesh_prov_session *prov, struct mesh_prov_session *dev,
    struct oob_trace *tr)
{
	int i;

	for (i = 0; i < 16; i++) {
		oob_deliver(prov, dev, tr);
		oob_deliver(dev, prov, tr);
		if (mesh_prov_session_done(prov) && mesh_prov_session_done(dev))
			return;
	}
}

/*
 * Output OOB: the DEVICE displays, the PROVISIONER collects.  The Provisioner
 * stalls after the public key exchange until the operator supplies the value,
 * and the exchange is authenticated with it (a wrong value would fail at
 * Confirmation, which is what the "wrong value" leg checks).
 */
ATF_TC_WITHOUT_HEAD(oob_output_direction_and_run);
ATF_TC_BODY(oob_output_direction_and_run, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_oob_prompt pp, dp;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct oob_trace tr;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	size_t i;

	assert_provisioning_wire_contract();
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* The device can show six digits with the Output Numeric action. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 6;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));

	memset(&tr, 0, sizeof(tr));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, &tr);

	/* Provisioning Start selected Output OOB with the Action and Size. */
	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_OUTPUT, prov.start_val[2],
	    "Start must select Output OOB");
	ATF_CHECK_EQ(MESH_PROV_OUT_ACT_NUMERIC, prov.start_val[3]);
	ATF_CHECK_EQ(6, prov.start_val[4]);

	/* The device displays; the provisioner waits for the operator. */
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&dev, &dp));
	ATF_CHECK_EQ(MESH_PROV_OOB_PROMPT_DISPLAY, dp.kind);
	ATF_CHECK_EQ(6, dp.size);
	ATF_CHECK_EQ(0, dp.alphanumeric);
	ATF_CHECK_EQ_MSG(6u, (unsigned)strlen(dp.value), "%s", dp.value);
	for (i = 0; i < strlen(dp.value); i++)
		ATF_CHECK(dp.value[i] >= '0' && dp.value[i] <= '9');
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&prov, &pp));
	ATF_CHECK_EQ_MSG(MESH_PROV_OOB_PROMPT_INPUT, pp.kind,
	    "Output OOB: the Provisioner collects what the device showed");
	ATF_CHECK_EQ(MESH_PROV_AUTH_METHOD_OUTPUT, pp.method);
	ATF_CHECK_EQ(6, pp.size);
	ATF_CHECK_EQ_MSG(MPS_P_WAIT_OOB_INPUT, prov.state,
	    "the exchange must stall, not proceed unauthenticated");
	ATF_CHECK_EQ_MSG(0u, oob_trace_count(&tr, MESH_PROV_CONFIRMATION),
	    "no Confirmation before the AuthValue is known");
	/* No Input Complete anywhere: that PDU belongs to Input OOB only. */
	ATF_CHECK_EQ(0u, oob_trace_count(&tr, MESH_PROV_INPUT_COMPLETE));

	/* The operator reads the value off the device and types it in. */
	ATF_REQUIRE_EQ(0, mesh_prov_session_oob_input(&prov, dp.value));
	ATF_CHECK_EQ(0, mesh_prov_session_oob_prompt(&prov, &pp));
	oob_pump(&prov, &dev, &tr);

	ATF_CHECK(mesh_prov_session_done(&prov));
	ATF_CHECK(mesh_prov_session_done(&dev));
	ATF_CHECK_EQ_MSG(0, memcmp(mesh_prov_session_devkey(&prov),
	    mesh_prov_session_devkey(&dev), 16), "same DevKey");
	/*
	 * The AuthValue is the displayed number as a big-endian integer, not
	 * zero (Section 5.4.2.4.1).  mesh_prov_device_init() always advertises
	 * the mandatory HMAC-SHA-256 algorithm, so the negotiated AuthValue is
	 * 256 bits wide and the number sits in its last four octets.
	 */
	ATF_REQUIRE_EQ(MESH_PROV_ALGO_P256_HMAC, prov.algorithm);
	ATF_CHECK_EQ(0, memcmp(prov.auth, dev.auth, MESH_PROV_AUTH_LEN_256));
	ATF_CHECK_EQ((uint32_t)strtoul(dp.value, NULL, 10),
	    ((uint32_t)prov.auth[28] << 24) | ((uint32_t)prov.auth[29] << 16) |
	    ((uint32_t)prov.auth[30] << 8) | (uint32_t)prov.auth[31]);
	ATF_CHECK_EQ(0u, oob_trace_count(&tr, MESH_PROV_INPUT_COMPLETE));

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/*
 * Output OOB with the wrong number typed: the AuthValues differ, so the
 * exchange must die at the Confirmation check rather than complete.
 */
ATF_TC_WITHOUT_HEAD(oob_output_wrong_value_fails_confirmation);
ATF_TC_BODY(oob_output_wrong_value_fails_confirmation, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_oob_prompt dp;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	char wrong[MESH_PROV_OOB_VALUE_MAX];

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);

	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&dev, &dp));
	snprintf(wrong, sizeof(wrong), "%04u",
	    (unsigned)((strtoul(dp.value, NULL, 10) + 1) % 10000));
	ATF_REQUIRE_EQ(0, mesh_prov_session_oob_input(&prov, wrong));
	oob_pump(&prov, &dev, NULL);

	ATF_CHECK(!mesh_prov_session_done(&prov));
	ATF_CHECK(!mesh_prov_session_done(&dev));
	ATF_CHECK(mesh_prov_session_failed(&prov) ||
	    mesh_prov_session_failed(&dev));

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/*
 * Input OOB: the PROVISIONER displays, the PROVISIONEE collects and answers
 * with a Provisioning Input Complete PDU, which is what releases the
 * Provisioner's Confirmation (Figure 5.20).  Run under the HMAC-SHA-256
 * algorithm as well, where the ConfirmationKey itself is a function of the
 * AuthValue and so cannot be derived before the value exists.
 */
ATF_TC_WITHOUT_HEAD(oob_input_direction_and_run);
ATF_TC_BODY(oob_input_direction_and_run, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_oob_prompt pp, dp;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	struct oob_trace tr;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	char shown[MESH_PROV_OOB_VALUE_MAX];
	size_t i;

	assert_provisioning_wire_contract();
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* The device has an alphanumeric keypad of eight characters. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_HMAC;
	caps.input_oob_size = 8;
	caps.input_oob_action = 1u << MESH_PROV_IN_ACT_ALPHANUMERIC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_INPUT));

	memset(&tr, 0, sizeof(tr));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, &tr);

	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_INPUT, prov.start_val[2],
	    "Start must select Input OOB");
	ATF_CHECK_EQ(MESH_PROV_IN_ACT_ALPHANUMERIC, prov.start_val[3]);
	ATF_CHECK_EQ(8, prov.start_val[4]);

	/* We display; the device's user types. */
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&prov, &pp));
	ATF_CHECK_EQ_MSG(MESH_PROV_OOB_PROMPT_DISPLAY, pp.kind,
	    "Input OOB: the Provisioner shows the value");
	ATF_CHECK_EQ(1, pp.alphanumeric);
	ATF_CHECK_EQ_MSG(8u, (unsigned)strlen(pp.value), "%s", pp.value);
	for (i = 0; i < strlen(pp.value); i++)
		ATF_CHECK_MSG((pp.value[i] >= '0' && pp.value[i] <= '9') ||
		    (pp.value[i] >= 'A' && pp.value[i] <= 'Z'),
		    "ASCII digits and uppercase only: %s", pp.value);
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&dev, &dp));
	ATF_CHECK_EQ(MESH_PROV_OOB_PROMPT_INPUT, dp.kind);
	ATF_CHECK_EQ(MESH_PROV_AUTH_METHOD_INPUT, dp.method);

	/* Both sides are parked, and nothing was confirmed yet. */
	ATF_CHECK_EQ_MSG(MPS_P_WAIT_INPUT_COMPLETE, prov.state,
	    "the Provisioner holds its Confirmation for Input Complete");
	ATF_CHECK_EQ(MPS_D_WAIT_OOB_INPUT, dev.state);
	ATF_CHECK_EQ(0u, oob_trace_count(&tr, MESH_PROV_CONFIRMATION));
	ATF_CHECK_EQ(0u, oob_trace_count(&tr, MESH_PROV_INPUT_COMPLETE));
	/* The public key exchange completed first (Figure 5.20). */
	ATF_CHECK_EQ(2u, oob_trace_count(&tr, MESH_PROV_PUBLIC_KEY));

	strlcpy(shown, pp.value, sizeof(shown));
	ATF_REQUIRE_EQ(0, mesh_prov_session_oob_input(&dev, shown));
	oob_pump(&prov, &dev, &tr);

	ATF_CHECK_EQ_MSG(1u, oob_trace_count(&tr, MESH_PROV_INPUT_COMPLETE),
	    "the Provisionee announces the completed entry exactly once");
	ATF_CHECK(mesh_prov_session_done(&prov));
	ATF_CHECK(mesh_prov_session_done(&dev));
	ATF_CHECK_EQ_MSG(0, memcmp(mesh_prov_session_devkey(&prov),
	    mesh_prov_session_devkey(&dev), 16), "same DevKey");
	ATF_CHECK_EQ(0, memcmp(prov.auth, shown, strlen(shown)));

	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/*
 * A Provisionee refuses a Start selecting an Output / Input OOB Action or Size
 * it never advertised, and refuses one for a method it advertised no
 * capability for at all - it does not silently accept and then fail at
 * Confirmation with a misleading error.
 */
ATF_TC_WITHOUT_HEAD(oob_device_refuses_unsatisfiable_start);
ATF_TC_BODY(oob_device_refuses_unsatisfiable_start, tc)
{
	static const struct {
		uint8_t	method;
		uint8_t	action;
		uint8_t	size;
		const char *why;
	} bad[] = {
		{ MESH_PROV_AUTH_METHOD_OUTPUT,
		  MESH_PROV_OUT_ACT_ALPHANUMERIC, 4, "Action not advertised" },
		{ MESH_PROV_AUTH_METHOD_OUTPUT, MESH_PROV_OUT_ACT_NUMERIC, 6,
		  "Size larger than advertised" },
		{ MESH_PROV_AUTH_METHOD_OUTPUT, MESH_PROV_OUT_ACT_BLINK, 4,
		  "Blink not advertised" },
		{ MESH_PROV_AUTH_METHOD_INPUT, MESH_PROV_IN_ACT_NUMERIC, 4,
		  "no Input OOB capability at all" },
	};
	struct mesh_prov_session s;
	struct mesh_prov_caps caps;
	struct mesh_prov_oob_prompt pr;
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t i;

	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;

	for (i = 0; i < nitems(bad); i++) {
		ATF_REQUIRE_EQ(0, mesh_prov_device_init(&s, NULL, NULL, &caps));
		s.state = MPS_D_WAIT_START;
		memset(pdu, 0, sizeof(pdu));
		pdu[0] = MESH_PROV_START;
		pdu[1] = MESH_PROV_ALGO_P256_CMAC;
		pdu[2] = 0;
		pdu[3] = bad[i].method;
		pdu[4] = bad[i].action;
		pdu[5] = bad[i].size;
		ATF_CHECK_EQ_MSG(-1, mesh_prov_session_recv(&s, pdu,
		    1 + MESH_PROV_START_VAL_LEN), "%s", bad[i].why);
		ATF_CHECK_MSG(mesh_prov_session_failed(&s), "%s", bad[i].why);
		ATF_CHECK_EQ_MSG(0x01, s.error, "%s", bad[i].why);
		ATF_CHECK_EQ(0, mesh_prov_session_oob_prompt(&s, &pr));
		mesh_prov_session_free(&s);
	}

	/* The advertised combination is accepted, raising a prompt. */
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&s, NULL, NULL, &caps));
	s.state = MPS_D_WAIT_START;
	memset(pdu, 0, sizeof(pdu));
	pdu[0] = MESH_PROV_START;
	pdu[1] = MESH_PROV_ALGO_P256_CMAC;
	pdu[3] = MESH_PROV_AUTH_METHOD_OUTPUT;
	pdu[4] = MESH_PROV_OUT_ACT_NUMERIC;
	pdu[5] = 4;
	ATF_CHECK_EQ(0, mesh_prov_session_recv(&s, pdu,
	    1 + MESH_PROV_START_VAL_LEN));
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&s, &pr));
	ATF_CHECK_EQ(MESH_PROV_OOB_PROMPT_DISPLAY, pr.kind);
	ATF_CHECK_EQ(4u, (unsigned)strlen(pr.value));
	mesh_prov_session_free(&s);
}

/*
 * A Provisioner that has not been opted in to the operator-driven methods must
 * not select them - and must refuse an "only OOB authenticated" device it
 * therefore cannot authenticate, instead of downgrading to No OOB.
 */
ATF_TC_WITHOUT_HEAD(oob_provisioner_opt_in_required);
ATF_TC_BODY(oob_provisioner_opt_in_required, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* Output-capable but not "only OOB": the run falls back to No OOB. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_CHECK_EQ_MSG(MESH_PROV_AUTH_METHOD_NONE, prov.start_val[2],
	    "no opt-in, no operator-driven method");
	ATF_CHECK(mesh_prov_session_done(&prov));
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);

	/*
	 * The same device demanding an OOB-authenticated exchange: with the
	 * operator opted in to INPUT only and the device offering OUTPUT only,
	 * nothing can be selected and the Provisioner must refuse.
	 */
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_HMAC;
	caps.static_oob_type = MESH_PROV_OOB_TYPE_ONLY_OOB;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_INPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_CHECK_MSG(mesh_prov_session_failed(&prov),
	    "an unsatisfiable OOB-only device must be refused, not downgraded");
	ATF_CHECK(!mesh_prov_session_done(&prov));
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);

	/* Opting in to OUTPUT instead makes the very same device work. */
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_CHECK_EQ(MESH_PROV_AUTH_METHOD_OUTPUT, prov.start_val[2]);
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/*
 * The Input Complete / operator timeout (Section 5.4.4).  Every stalled state
 * of both roles is covered: the timer starts on the first tick spent stalled,
 * does not fire early, and on expiry fails the session with a Provisioning
 * Failed PDU instead of waiting for a human forever.
 */
ATF_TC_WITHOUT_HEAD(oob_input_complete_timeout);
ATF_TC_BODY(oob_input_complete_timeout, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* Output OOB: the Provisioner waits for the operator. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_REQUIRE_EQ(MPS_P_WAIT_OOB_INPUT, prov.state);

	/* A tick before the stall started is the clock's zero point. */
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&prov, 5000));
	ATF_CHECK_EQ_MSG(0, mesh_prov_session_tick(&prov,
	    5000 + MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS - 1), "not yet due");
	ATF_CHECK(!mesh_prov_session_failed(&prov));
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_tick(&prov,
	    5000 + MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS), "deadline reached");
	ATF_CHECK(mesh_prov_session_failed(&prov));
	ATF_CHECK_EQ(0x07, prov.error);
	ATF_REQUIRE_EQ(1, mesh_prov_session_poll(&prov, pdu, &len));
	ATF_CHECK_EQ(MESH_PROV_FAILED, pdu[0]);
	ATF_CHECK_EQ(0x07, pdu[1]);
	/* And the operator can no longer answer a dead session. */
	ATF_CHECK_EQ(-1, mesh_prov_session_oob_input(&prov, "1234"));
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);

	/*
	 * Input OOB: the Provisioner waits for Input Complete
	 * (MPS_P_WAIT_INPUT_COMPLETE) and the device waits for its user
	 * (MPS_D_WAIT_OOB_INPUT).  Both must time out.
	 */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.input_oob_size = 4;
	caps.input_oob_action = 1u << MESH_PROV_IN_ACT_NUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_INPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_REQUIRE_EQ(MPS_P_WAIT_INPUT_COMPLETE, prov.state);
	ATF_REQUIRE_EQ(MPS_D_WAIT_OOB_INPUT, dev.state);

	ATF_CHECK_EQ(0, mesh_prov_session_tick(&prov, 0));
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&dev, 0));
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&prov,
	    MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS - 1));
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&dev,
	    MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS - 1));
	ATF_CHECK(!mesh_prov_session_failed(&prov));
	ATF_CHECK(!mesh_prov_session_failed(&dev));
	ATF_CHECK_EQ(-1, mesh_prov_session_tick(&prov,
	    MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS));
	ATF_CHECK_EQ(-1, mesh_prov_session_tick(&dev,
	    MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS));
	ATF_CHECK(mesh_prov_session_failed(&prov));
	ATF_CHECK(mesh_prov_session_failed(&dev));
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);

	/* A session that is not stalled never times out. */
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&prov, 0));
	ATF_CHECK_EQ(0, mesh_prov_session_tick(&prov, 10u * 60u * 1000u));
	ATF_CHECK(!mesh_prov_session_failed(&prov));
	ATF_CHECK_EQ(-1, mesh_prov_session_tick(NULL, 0));
	mesh_prov_session_free(&prov);
}

/*
 * Value validation and the API guards around the prompt interface.  A value
 * that does not match the negotiated Action and Size is refused WITHOUT
 * disturbing the session, so the operator can simply retype it.
 */
ATF_TC_WITHOUT_HEAD(oob_input_value_validation);
ATF_TC_BODY(oob_input_value_validation, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_oob_prompt pr;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));

	/* Guards before any session exists. */
	ATF_CHECK_EQ(-1, mesh_prov_session_set_oob_methods(NULL, 0));
	ATF_CHECK_EQ(-1, mesh_prov_session_oob_prompt(NULL, &pr));
	ATF_CHECK_EQ(-1, mesh_prov_session_oob_input(NULL, "1"));

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_set_oob_methods(&prov, 0x04),
	    "unknown method bits are rejected");
	ATF_CHECK_EQ(-1, mesh_prov_session_oob_prompt(&prov, NULL));
	ATF_CHECK_EQ(0, mesh_prov_session_oob_prompt(&prov, &pr));
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "1234"),
	    "no prompt, no input");
	ATF_CHECK_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_INPUT), "too late once the exchange started");

	/* Numeric, size 4, Push: 1..9999, leading zeros optional. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_BLINK;
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	oob_pump(&prov, &dev, NULL);
	ATF_REQUIRE_EQ(MPS_P_WAIT_OOB_INPUT, prov.state);
	ATF_REQUIRE_EQ(1, mesh_prov_session_oob_prompt(&prov, &pr));
	ATF_CHECK_EQ(MESH_PROV_OUT_ACT_BLINK, pr.action);

	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "12345"),
	    "more digits than the Authentication Size");
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "12a4"),
	    "not a decimal digit");
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, ""),
	    "empty value");
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "0"),
	    "Blink counts events: zero cannot be signalled");
	/* None of that disturbed the session. */
	ATF_CHECK_EQ(MPS_P_WAIT_OOB_INPUT, prov.state);
	ATF_CHECK_EQ(1, mesh_prov_session_oob_prompt(&prov, &pr));
	ATF_CHECK_EQ_MSG(0, mesh_prov_session_oob_input(&prov, "42"),
	    "leading zeros need not be typed");
	ATF_CHECK_EQ(MPS_P_WAIT_CONFIRM, prov.state);
	/* The AuthValue is the NUMBER 42 (Section 5.4.2.4.1 Numeric). */
	ATF_REQUIRE_EQ(MESH_PROV_ALGO_P256_HMAC, prov.algorithm);
	ATF_CHECK_EQ(42, prov.auth[31]);
	ATF_CHECK_EQ(0, prov.auth[30]);
	ATF_CHECK_EQ(0, prov.auth[0]);
	ATF_CHECK_EQ(0, mesh_prov_session_oob_prompt(&prov, &pr));
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);

	/* Alphanumeric, size 8: exactly eight characters of [0-9A-Z]. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 8;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_ALPHANUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_REQUIRE_EQ(MPS_P_WAIT_OOB_INPUT, prov.state);
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "ABC123"),
	    "shorter than the Authentication Size");
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "abc12345"),
	    "lowercase is outside the alphabet");
	ATF_CHECK_EQ_MSG(-1, mesh_prov_session_oob_input(&prov, "ABC-1234"),
	    "punctuation is outside the alphabet");
	ATF_CHECK_EQ(0, mesh_prov_session_oob_input(&prov, "AB12CD34"));
	ATF_CHECK_EQ_MSG(0, memcmp(prov.auth, "AB12CD34", 8),
	    "AuthValue is the ASCII string, left-aligned");
	ATF_CHECK_EQ(0, prov.auth[8]);
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

/*
 * The Provisioning Input Complete PDU is one-directional (Section 5.4.1.5):
 * only a Provisioner in an Input OOB exchange that is waiting for it accepts
 * one.  A Provisionee that receives one, and a Provisioner that receives one
 * out of turn, must answer Unexpected PDU.
 */
ATF_TC_WITHOUT_HEAD(oob_input_complete_direction);
ATF_TC_BODY(oob_input_complete_direction, tc)
{
	struct mesh_prov_session prov, dev;
	struct mesh_prov_caps caps;
	struct mesh_prov_data pdata;
	HEX(raw, BT_MSHPRT11_PROV_SAMPLE_DATA_HEX, 25);
	uint8_t ic[MESH_PROV_PDU_MAX];
	size_t iclen;

	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_no_param_build(MESH_PROV_INPUT_COMPLETE, ic,
	    &iclen));

	/* A device never receives one. */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.input_oob_size = 4;
	caps.input_oob_action = 1u << MESH_PROV_IN_ACT_NUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&dev, ic, iclen));
	ATF_CHECK(mesh_prov_session_failed(&dev));
	ATF_CHECK_EQ(0x03, dev.error);
	mesh_prov_session_free(&dev);

	/* Nor does a Provisioner outside the Input OOB wait state. */
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&prov, ic, iclen));
	ATF_CHECK(mesh_prov_session_failed(&prov));
	ATF_CHECK_EQ(0x03, prov.error);
	mesh_prov_session_free(&prov);

	/*
	 * And an Input Complete during an OUTPUT OOB stall - where no input is
	 * happening on the peer at all - is equally unexpected.
	 */
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;
	caps.output_oob_size = 4;
	caps.output_oob_action = 1u << MESH_PROV_OUT_ACT_NUMERIC;
	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, NULL, NULL, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, NULL, NULL, &caps));
	ATF_REQUIRE_EQ(0, mesh_prov_session_set_oob_methods(&prov,
	    MESH_PROV_OOB_ALLOW_OUTPUT));
	ATF_REQUIRE_EQ(0, mesh_prov_session_start(&prov));
	oob_pump(&prov, &dev, NULL);
	ATF_REQUIRE_EQ(MPS_P_WAIT_OOB_INPUT, prov.state);
	ATF_CHECK_EQ(-1, mesh_prov_session_recv(&prov, ic, iclen));
	ATF_CHECK(mesh_prov_session_failed(&prov));
	ATF_CHECK_EQ(0x03, prov.error);
	mesh_prov_session_free(&prov);
	mesh_prov_session_free(&dev);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, provisioning_run);
	ATF_TP_ADD_TC(tp, provisioning_confirmation_mismatch);
	ATF_TP_ADD_TC(tp, link_open_and_retransmit);
	ATF_TP_ADD_TC(tp, link_retransmit_budget);
	ATF_TP_ADD_TC(tp, link_duplicate_transaction);
	ATF_TP_ADD_TC(tp, api_and_state_guard_matrix);
	ATF_TP_ADD_TC(tp, session_unexpected_pdu_matrix);
	ATF_TP_ADD_TC(tp, device_rejects_unsupported_oob_start);
	ATF_TP_ADD_TC(tp, oob_output_direction_and_run);
	ATF_TP_ADD_TC(tp, oob_output_wrong_value_fails_confirmation);
	ATF_TP_ADD_TC(tp, oob_input_direction_and_run);
	ATF_TP_ADD_TC(tp, oob_device_refuses_unsatisfiable_start);
	ATF_TP_ADD_TC(tp, oob_provisioner_opt_in_required);
	ATF_TP_ADD_TC(tp, oob_input_complete_timeout);
	ATF_TP_ADD_TC(tp, oob_input_value_validation);
	ATF_TP_ADD_TC(tp, oob_input_complete_direction);
	ATF_TP_ADD_TC(tp, link_foreign_link_id_ignored);
	ATF_TP_ADD_TC(tp, link_silent_peer_times_out);
	ATF_TP_ADD_TC(tp, link_transactions_require_open_link);

	return (atf_no_error());
}
