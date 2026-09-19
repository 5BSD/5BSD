/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the Bluetooth Mesh Replay Protection List
 * (mesh_rpl.[ch], MshPRT_v1.1 Section 3.9.8).
 *
 * The RPL rules are behavioural (accept newer, reject replays, higher IV
 * Index resets acceptance, bounded list rejects unknown SRC when full).  The
 * integration test drives mesh_rpl_net_receive(), which decrypts a real
 * Section 8.3 Network PDU with mesh_net_decrypt() and only then enforces the
 * RPL, showing that a replay of an authentic PDU is rejected.
 *
 * The Section 8.2.2 network security material (NetKey 7dd7364c..., IV Index
 * 0x12345678) is:
 *   NID = 0x68, EncryptionKey = 0953fa93e7caac9638f58820220a398e,
 *   PrivacyKey = 8b84eedec100067d670971dd2aa700cf.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_net.h"
#include "mesh_rpl.h"
#include "spec_mesh_network_oracles.h"
#include "spec_oracles.h"

static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		ATF_REQUIRE_EQ(1, sscanf(hex + 2 * i, "%02x", &b));
		out[i] = (uint8_t)b;
	}
}

#define	HEX(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

/* ================================================================
 * Core RPL semantics: accept-new, reject-replay, reject-equal,
 * accept-higher-IV, and higher-IV resets the SEQ window.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_semantics);
ATF_TC_BODY(mesh_rpl_semantics, tc)
{
	struct mesh_rpl_entry storage[4];
	struct mesh_rpl rpl;

	mesh_rpl_init(&rpl, storage, 4);

	/* Start at the exact §8.3.6 Message #6 source, IV Index, and SEQ. */
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_MSG6_SEQ));
	/* Equal (IV,SEQ): replay -> reject. */
	ATF_CHECK_EQ_MSG(0, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_MSG6_SEQ),
	    "equal (IV,SEQ) must be rejected as a replay");
	/* Lower SEQ, same IV: replay -> reject. */
	ATF_CHECK_EQ_MSG(0, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_MSG6_SEQ - 1),
	    "lower SEQ in the same IV Index must be rejected");
	/* Higher SEQ, same IV: accept. */
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_MSG6_SEQ + 1));
	/* Lower IV Index: reject even with a huge SEQ. */
	ATF_CHECK_EQ_MSG(0, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX - 1, BT_MSHPRT11_SEQ_MAX),
	    "a lower IV Index must be rejected regardless of SEQ");
	/* Higher IV Index resets acceptance: a small SEQ is accepted. */
	ATF_CHECK_EQ_MSG(1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX + 1, 0),
	    "a higher IV Index must reset the SEQ window");
	/* Within the new (higher) IV, the old large SEQ is now allowed. */
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX + 1, 1));
	/* But replaying SEQ 1 in the new IV epoch is now a replay. */
	ATF_CHECK_EQ(0, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_IV_INDEX + 1, 1));
}

/* ================================================================
 * Exact wire-field boundaries: §3.9.8 keys entries by the source element's
 * unicast address and 7-octet IVISeq; §3.4.3 defines SEQ as 24 bits.
 * Impossible field values must not consume or poison an RPL slot.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_field_bounds);
ATF_TC_BODY(mesh_rpl_field_bounds, tc)
{
	struct mesh_rpl_entry storage[2];
	struct mesh_rpl rpl;

	mesh_rpl_init(&rpl, storage, 2);
	ATF_CHECK_EQ(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNASSIGNED,
	    BT_MSHPRT11_MSG6_IV_INDEX, 0));
	ATF_CHECK_EQ(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_VIRTUAL_MIN,
	    BT_MSHPRT11_MSG6_IV_INDEX, 0));
	ATF_CHECK_EQ(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_GROUP_MIN,
	    BT_MSHPRT11_MSG6_IV_INDEX, 0));
	ATF_CHECK_EQ(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MIN,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_SEQ_MAX + 1));
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MIN,
	    BT_MSHPRT11_MSG6_IV_INDEX, BT_MSHPRT11_SEQ_MAX));
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MAX,
	    BT_MSHPRT11_MSG6_IV_INDEX, 0));
}

/* ================================================================
 * Bounded list: when full, a known SRC still works but an unknown SRC is
 * rejected (-1) because it cannot be replay-protected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_full);
ATF_TC_BODY(mesh_rpl_full, tc)
{
	struct mesh_rpl_entry storage[2];
	struct mesh_rpl rpl;

	/* Capacity 2 is a non-normative implementation-boundary sentinel. */
	mesh_rpl_init(&rpl, storage, 2);

	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MIN,
	    0, 1));
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl,
	    BT_MSHPRT11_ADDR_UNICAST_MIN + 1, 0, 1));
	/* List full, unknown SRC: cannot record -> reject. */
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_check(&rpl,
	    BT_MSHPRT11_ADDR_UNICAST_MIN + 2, 0, 1),
	    "a full list must reject an unknown SRC");
	/* Known SRCs continue to advance normally. */
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MIN,
	    0, 2));
	ATF_CHECK_EQ(0, mesh_rpl_check(&rpl, BT_MSHPRT11_ADDR_UNICAST_MIN,
	    0, 2));

	/* Reset empties the list; the previously-rejected SRC now fits. */
	mesh_rpl_reset(&rpl);
	ATF_CHECK_EQ(1, mesh_rpl_check(&rpl,
	    BT_MSHPRT11_ADDR_UNICAST_MIN + 2, 0, 1));
}

/* ================================================================
 * Integration with a real decrypt call: an authentic Section 8.3.6 Network
 * PDU is accepted once, then rejected as a replay on the second delivery.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_net_receive_replay);
ATF_TC_BODY(mesh_rpl_net_receive_replay, tc)
{
	HEX(enckey, BT_MSHPRT11_MSG6_ENCKEY_HEX, BT_AES128_KEY_BLOCK_SIZE);
	HEX(privkey, BT_MSHPRT11_MSG6_PRIVKEY_HEX, BT_AES128_KEY_BLOCK_SIZE);
	HEX(pdu, BT_MSHPRT11_MSG6_NETWORK_PDU_HEX,
	    BT_MSHPRT11_MSG6_NETWORK_PDU_SIZE);
	struct mesh_rpl_entry storage[4];
	struct mesh_rpl rpl;
	struct mesh_net_pdu out;

	mesh_rpl_init(&rpl, storage, 4);

	/* First delivery: authenticates and passes the RPL. */
	ATF_CHECK_EQ_MSG(1, mesh_rpl_net_receive(&rpl, enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, pdu,
	    sizeof(pdu), &out),
	    "first authentic delivery must be accepted");
	ATF_CHECK_EQ(out.src, BT_MSHPRT11_MSG6_SRC);
	ATF_CHECK_EQ(out.seq, BT_MSHPRT11_MSG6_SEQ);

	/* Second, identical delivery: authenticates but is a replay. */
	ATF_CHECK_EQ_MSG(0, mesh_rpl_net_receive(&rpl, enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, pdu,
	    sizeof(pdu), &out),
	    "replayed authentic PDU must be rejected by the RPL");

	/* A forged/corrupt PDU fails decryption and never reaches the RPL. */
	pdu[BT_MSHPRT11_MSG6_NETWORK_PDU_SIZE - 1] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_net_receive(&rpl, enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, pdu,
	    sizeof(pdu), &out),
	    "a PDU that fails the NetMIC must return -1, not touch the RPL");
}

/* ================================================================
 * Degenerate/NULL bindings must fail closed: an RPL with no backing
 * storage (or size 0) cannot replay-protect anything, so mesh_rpl_check
 * must return -1 (reject) rather than silently accept.  The init/reset
 * NULL guards must not dereference anything.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_degenerate);
ATF_TC_BODY(mesh_rpl_degenerate, tc)
{
	struct mesh_rpl_entry storage[2];
	struct mesh_rpl rpl;

	/* init/reset/check must tolerate a NULL rpl. */
	mesh_rpl_init(NULL, storage, 2);		/* must not crash */
	mesh_rpl_reset(NULL);				/* must not crash */
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_check(NULL, BT_MSHPRT11_MSG6_SRC, 1, 1),
	    "a NULL RPL must be rejected");

	/* NULL storage: size clamps to 0 and entries stays NULL. */
	mesh_rpl_init(&rpl, NULL, 5);
	ATF_CHECK_EQ(0u, (unsigned)rpl.size);
	ATF_CHECK(rpl.entries == NULL);
	/* reset on a NULL-backed list is a no-op, not a crash. */
	mesh_rpl_reset(&rpl);
	/* check must reject: nothing can be recorded. */
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC, 1, 1),
	    "an RPL with no storage must reject (cannot replay-protect)");

	/* Non-NULL storage but size 0: same, must reject. */
	mesh_rpl_init(&rpl, storage, 0);
	ATF_CHECK_EQ(0u, (unsigned)rpl.size);
	ATF_CHECK(rpl.entries != NULL);
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_check(&rpl, BT_MSHPRT11_MSG6_SRC, 1, 1),
	    "a zero-size RPL must reject");
}

/* ================================================================
 * mesh_rpl_net_receive must reject a NULL out pointer up front (before
 * any decryption), returning -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_rpl_net_receive_null_out);
ATF_TC_BODY(mesh_rpl_net_receive_null_out, tc)
{
	HEX(enckey, BT_MSHPRT11_MSG6_ENCKEY_HEX, BT_AES128_KEY_BLOCK_SIZE);
	HEX(privkey, BT_MSHPRT11_MSG6_PRIVKEY_HEX, BT_AES128_KEY_BLOCK_SIZE);
	HEX(pdu, BT_MSHPRT11_MSG6_NETWORK_PDU_HEX,
	    BT_MSHPRT11_MSG6_NETWORK_PDU_SIZE);
	struct mesh_rpl_entry storage[4];
	struct mesh_rpl rpl;

	mesh_rpl_init(&rpl, storage, 4);
	ATF_CHECK_EQ_MSG(-1, mesh_rpl_net_receive(&rpl, enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, pdu,
	    sizeof(pdu), NULL),
	    "a NULL out pointer must be rejected before decryption");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_rpl_semantics);
	ATF_TP_ADD_TC(tp, mesh_rpl_field_bounds);
	ATF_TP_ADD_TC(tp, mesh_rpl_full);
	ATF_TP_ADD_TC(tp, mesh_rpl_net_receive_replay);
	ATF_TP_ADD_TC(tp, mesh_rpl_degenerate);
	ATF_TP_ADD_TC(tp, mesh_rpl_net_receive_null_out);

	return (atf_no_error());
}
