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
	int i;

	assert_provisioning_wire_contract();
	ATF_REQUIRE_EQ(0, mesh_prov_data_unpack(raw, &pdata));
	memset(&caps, 0, sizeof(caps));
	caps.num_elements = 1;
	caps.algorithms = MESH_PROV_ALGO_BIT_P256_CMAC;

	ATF_REQUIRE_EQ(0, mesh_prov_provisioner_init(&prov, ppriv, rprov, 0x00,
	    &pdata));
	ATF_REQUIRE_EQ(0, mesh_prov_device_init(&dev, dpriv, rdev, &caps));

	/* Corrupt the device's AuthValue so its Confirmation will not verify. */
	dev.auth[0] ^= 0xff;

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
	ATF_TP_ADD_TC(tp, link_foreign_link_id_ignored);
	ATF_TP_ADD_TC(tp, link_silent_peer_times_out);

	return (atf_no_error());
}
