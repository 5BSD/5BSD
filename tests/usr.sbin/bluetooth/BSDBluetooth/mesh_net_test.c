/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh network layer
 * (mesh_net.[ch], MshPRT_v1.1 Section 3.4).
 *
 * The end-to-end network-PDU vectors are the worked examples of
 * MshPRT_v1.1 Section 8.3 "Mesh message sample data".  They reuse the
 * Section 8.2.2 network security material derived by mesh_k2() from the
 * canonical NetKey 7dd7364cd842ad18c17c2b820c84c3d6 with IV Index
 * 0x12345678:
 *
 *   NID           = 0x68
 *   EncryptionKey = 0953fa93e7caac9638f58820220a398e
 *   PrivacyKey    = 8b84eedec100067d670971dd2aa700cf
 *
 * The encrypted payloads (EncDST||EncTransportPDU + NetMIC) are exactly
 * the Section 8.3.1 / 8.3.6 AES-CCM outputs already asserted by
 * mesh_crypto_test.c.  What is new here is the header obfuscation
 * (Section 3.4.5.2, PECB) and the resulting complete Network PDU.
 *
 * The Message #1 (Section 8.3.1) complete Network PDU
 *   68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df
 * is the canonical published value.  Both complete PDUs were reproduced
 * independently with the Python "cryptography" package (AES-ECB PECB +
 * XOR over the Section 8 inputs) before being committed here, so a
 * passing test confirms the module against the published/derived spec
 * bytes rather than against itself.
 *
 * Mesh operates in network (big-endian) byte order; no byte reversal is
 * applied.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_net.h"
#include "spec_mesh_net_oracles.h"
#include "spec_mesh_relay_oracles.h"

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

/* Section 8.2.2 network security material, shared by the vectors. */
#define	ENCKEY_HEX	BT_MESH_SPEC_NET_ENCKEY_HEX
#define	PRIVKEY_HEX	BT_MESH_SPEC_NET_PRIVKEY_HEX
#define	NET_NID		BT_MESH_SPEC_NET_NID
#define	NET_IVINDEX	BT_MESH_SPEC_NET_IV_INDEX

/* ================================================================
 * Message #1 (Section 8.3.1): a control message (CTL=1, 64-bit NetMIC).
 *   CTL=1 TTL=0 SEQ=000001 SRC=1201 DST=fffd
 *   TransportPDU = 034b50057e400000010000
 *   Complete Network PDU (canonical published value):
 *     68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_encrypt_message1);
ATF_TC_BODY(mesh_net_encrypt_message1, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(transport, "034b50057e400000010000", 11);
	HEX(exp, "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df", 28);
	struct mesh_net_pdu pdu;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;

	memset(&pdu, 0, sizeof(pdu));
	pdu.nid = NET_NID;
	pdu.ctl = 1;
	pdu.ttl = 0;
	pdu.seq = 0x000001;
	pdu.src = 0x1201;
	pdu.dst = 0xfffd;
	memcpy(pdu.transport, transport, 11);
	pdu.transport_len = 11;

	ATF_REQUIRE_EQ(0, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &pdu, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 28,
	    "Message #1 Network PDU length %zu != 28", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 28), 0,
	    "Message #1 obfuscated+encrypted Network PDU mismatch (8.3.1)");
}

ATF_TC_WITHOUT_HEAD(mesh_net_decrypt_message1);
ATF_TC_BODY(mesh_net_decrypt_message1, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(pdu_bytes,
	    "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df", 28);
	HEX(transport, "034b50057e400000010000", 11);
	struct mesh_net_pdu out;

	ATF_REQUIRE_EQ(0, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, pdu_bytes, 28, &out));
	ATF_CHECK_EQ(out.nid, NET_NID);
	ATF_CHECK_EQ(out.ivi, 0);
	ATF_CHECK_EQ(out.ctl, 1);
	ATF_CHECK_EQ(out.ttl, 0);
	ATF_CHECK_EQ(out.seq, 0x000001u);
	ATF_CHECK_EQ(out.src, 0x1201);
	ATF_CHECK_EQ(out.dst, 0xfffd);
	ATF_CHECK_EQ_MSG(out.transport_len, 11,
	    "Message #1 recovered TransportPDU length %zu != 11",
	    out.transport_len);
	ATF_CHECK_EQ_MSG(memcmp(out.transport, transport, 11), 0,
	    "Message #1 decrypt did not recover the TransportPDU (8.3.1)");
}

/* ================================================================
 * Message #6, segment #0 (Section 8.3.6): a segmented access message
 * (CTL=0, 32-bit NetMIC).
 *   CTL=0 TTL=04 SEQ=3129ab SRC=0003 DST=1201
 *   TransportPDU = 8026ac01ee9dddfd2169326d23f3afdf
 *   Complete Network PDU (Section 8 inputs, PECB obfuscation):
 *     68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_encrypt_message6);
ATF_TC_BODY(mesh_net_encrypt_message6, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(transport, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	HEX(exp,
	    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e", 29);
	struct mesh_net_pdu pdu;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;

	memset(&pdu, 0, sizeof(pdu));
	pdu.nid = NET_NID;
	pdu.ctl = 0;
	pdu.ttl = 0x04;
	pdu.seq = 0x3129ab;
	pdu.src = 0x0003;
	pdu.dst = 0x1201;
	memcpy(pdu.transport, transport, 16);
	pdu.transport_len = 16;

	ATF_REQUIRE_EQ(0, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &pdu, out, &outlen));
	ATF_CHECK_EQ_MSG(outlen, 29,
	    "Message #6 Network PDU length %zu != 29", outlen);
	ATF_CHECK_EQ_MSG(memcmp(out, exp, 29), 0,
	    "Message #6 obfuscated+encrypted Network PDU mismatch (8.3.6)");
}

ATF_TC_WITHOUT_HEAD(mesh_net_decrypt_message6);
ATF_TC_BODY(mesh_net_decrypt_message6, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(pdu_bytes,
	    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e", 29);
	HEX(transport, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	struct mesh_net_pdu out;

	ATF_REQUIRE_EQ(0, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, pdu_bytes, 29, &out));
	ATF_CHECK_EQ(out.nid, NET_NID);
	ATF_CHECK_EQ(out.ivi, 0);
	ATF_CHECK_EQ(out.ctl, 0);
	ATF_CHECK_EQ(out.ttl, 0x04);
	ATF_CHECK_EQ(out.seq, 0x3129abu);
	ATF_CHECK_EQ(out.src, 0x0003);
	ATF_CHECK_EQ(out.dst, 0x1201);
	ATF_CHECK_EQ_MSG(out.transport_len, 16,
	    "Message #6 recovered TransportPDU length %zu != 16",
	    out.transport_len);
	ATF_CHECK_EQ_MSG(memcmp(out.transport, transport, 16), 0,
	    "Message #6 decrypt did not recover the TransportPDU (8.3.6)");
}

/* ================================================================
 * NID matching (Section 3.4.6.3): the predicate, plus decrypt rejection
 * when the local key's NID does not match the received PDU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_nid_mismatch);
ATF_TC_BODY(mesh_net_nid_mismatch, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(pdu_bytes,
	    "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df", 28);
	struct mesh_net_pdu out;

	/* Octet 0 low 7 bits = 0x68; IVI bit is ignored by the match. */
	ATF_CHECK(mesh_net_nid_match(0x68, 0x68));
	ATF_CHECK(mesh_net_nid_match(0x68, 0xe8));	/* IVI=1, NID=0x68 */
	ATF_CHECK(!mesh_net_nid_match(0x69, 0x68));
	ATF_CHECK(!mesh_net_nid_match(0x00, 0x68));

	/* A key whose NID is 0x69 must not decode a 0x68 PDU. */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, 0x69,
	    NET_IVINDEX, pdu_bytes, 28, &out),
	    "decrypt accepted a PDU whose NID did not match the key");

	/* IVI is bound to the IV Index, not merely ignored by NID matching. */
	pdu_bytes[0] ^= 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, pdu_bytes, 28, &out),
	    "decrypt accepted a PDU whose IVI did not match the IV Index");
}

/* ================================================================
 * NetMIC / ciphertext tamper rejection: a single flipped bit anywhere in
 * the encrypted region must make decrypt fail (both MIC sizes).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_netmic_tamper);
ATF_TC_BODY(mesh_net_netmic_tamper, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(msg1, "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df",
	    28);
	HEX(msg6,
	    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e", 29);
	struct mesh_net_pdu out;

	/* Flip the last NetMIC octet of the 64-bit-MIC control message. */
	msg1[27] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, msg1, 28, &out),
	    "decrypt accepted a corrupted 64-bit NetMIC (Message #1)");
	msg1[27] ^= 0x01;
	/* Now corrupt a ciphertext octet instead; deobfuscation of the
	 * header still succeeds but the NetMIC check must fail. */
	msg1[10] ^= 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, msg1, 28, &out),
	    "decrypt accepted a corrupted ciphertext (Message #1)");

	/* Flip the last NetMIC octet of the 32-bit-MIC access message. */
	msg6[28] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, msg6, 29, &out),
	    "decrypt accepted a corrupted 32-bit NetMIC (Message #6)");
}

/* ================================================================
 * Relay decision predicate (Section 3.4.6.3): TTL boundaries 0,1,2,127.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_relay_boundaries);
ATF_TC_BODY(mesh_net_relay_boundaries, tc)
{
	uint8_t new_ttl;

	ATF_CHECK_EQ_MSG(0, mesh_net_relay(0, NULL),
	    "TTL 0 must not be relayable");
	ATF_CHECK_EQ_MSG(0, mesh_net_relay(BT_MESH_SPEC_TTL_NO_RELAY_MAX, NULL),
	    "TTL 1 must not be relayable");

	new_ttl = 0xff;
	ATF_CHECK_EQ_MSG(1, mesh_net_relay(BT_MESH_SPEC_TTL_RELAY_MIN,
	    &new_ttl),
	    "TTL 2 must be relayable");
	ATF_CHECK_EQ_MSG(new_ttl, 1,
	    "TTL 2 must relay with decremented TTL 1");

	new_ttl = 0xff;
	ATF_CHECK_EQ_MSG(1, mesh_net_relay(BT_MESH_SPEC_TTL_MAX, &new_ttl),
	    "TTL 127 must be relayable");
	ATF_CHECK_EQ_MSG(new_ttl, 126,
	    "TTL 127 must relay with decremented TTL 126");

	new_ttl = 0x55;
	ATF_CHECK_EQ_MSG(0, mesh_net_relay(
	    BT_MESH_SPEC_TTL_FIRST_RESERVED, &new_ttl),
	    "the first reserved TTL must not be relayed");
	ATF_CHECK_EQ_MSG(0x55, new_ttl,
	    "reserved TTL rejection must leave output untouched");
}

/* ================================================================
 * Round-trip properties: cleartext build->parse, and the full
 * encrypt->decrypt inverse over both a control and an access PDU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_roundtrip);
ATF_TC_BODY(mesh_net_roundtrip, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(transport, "8026ac01ee9dddfd2169326d23f3afdf", 16);
	struct mesh_net_pdu in, mid, back;
	uint8_t wire[MESH_NET_MAX_PDU], sec[MESH_NET_MAX_PDU];
	size_t wirelen, seclen;

	memset(&in, 0, sizeof(in));
	in.ivi = 0;
	in.nid = NET_NID;
	in.ctl = 0;
	in.ttl = 0x04;
	in.seq = 0x3129ab;
	in.src = 0x0003;
	in.dst = 0x1201;
	memcpy(in.transport, transport, 16);
	in.transport_len = 16;

	/* Cleartext codec round trip (field layout, Section 3.4.4). */
	ATF_REQUIRE_EQ(0, mesh_net_pdu_build(&in, wire, &wirelen));
	ATF_REQUIRE_EQ(0, mesh_net_pdu_parse(wire, wirelen, &mid));
	ATF_CHECK_EQ(mid.ivi, in.ivi);
	ATF_CHECK_EQ(mid.nid, in.nid);
	ATF_CHECK_EQ(mid.ctl, in.ctl);
	ATF_CHECK_EQ(mid.ttl, in.ttl);
	ATF_CHECK_EQ(mid.seq, in.seq);
	ATF_CHECK_EQ(mid.src, in.src);
	ATF_CHECK_EQ(mid.dst, in.dst);
	ATF_CHECK_EQ(mid.transport_len, in.transport_len);
	ATF_CHECK_EQ(0, memcmp(mid.transport, in.transport, 16));

	/* Secured round trip: encrypt then decrypt recovers every field. */
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &in, sec, &seclen));
	ATF_REQUIRE_EQ(0, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, sec, seclen, &back));
	ATF_CHECK_EQ(back.ctl, in.ctl);
	ATF_CHECK_EQ(back.ttl, in.ttl);
	ATF_CHECK_EQ(back.seq, in.seq);
	ATF_CHECK_EQ(back.src, in.src);
	ATF_CHECK_EQ(back.dst, in.dst);
	ATF_CHECK_EQ(back.transport_len, in.transport_len);
	ATF_CHECK_EQ(0, memcmp(back.transport, in.transport, 16));
}

/* ================================================================
 * Minimal replay-protection primitive (a Phase-6 building block).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_rpl_primitive);
ATF_TC_BODY(mesh_net_rpl_primitive, tc)
{
	struct mesh_net_rpl tbl[2];

	memset(tbl, 0, sizeof(tbl));

	/* First sighting of a SRC is accepted and recorded. */
	ATF_CHECK_EQ(1, mesh_net_rpl_check(tbl, 2, 0x0001, 5));
	/* Same SEQ is a replay. */
	ATF_CHECK_EQ(0, mesh_net_rpl_check(tbl, 2, 0x0001, 5));
	/* A lower SEQ is a replay. */
	ATF_CHECK_EQ(0, mesh_net_rpl_check(tbl, 2, 0x0001, 4));
	/* A strictly higher SEQ advances the window. */
	ATF_CHECK_EQ(1, mesh_net_rpl_check(tbl, 2, 0x0001, 6));
	/* A different SRC uses the second slot. */
	ATF_CHECK_EQ(1, mesh_net_rpl_check(tbl, 2, 0x0002, 1));
	/* Table full and SRC unknown: cannot record. */
	ATF_CHECK_EQ(-1, mesh_net_rpl_check(tbl, 2, 0x0003, 1));
	/* Known SRCs still work when the table is full. */
	ATF_CHECK_EQ(1, mesh_net_rpl_check(tbl, 2, 0x0002, 2));
	ATF_CHECK_EQ(0, mesh_net_rpl_check(tbl, 2, 0x0002, 2));
}

/* ================================================================
 * Field-range validation (mesh_net_valid, Section 3.4.4): each out-of-range
 * field must make the cleartext build fail, as must a NULL PDU.  Exercised
 * through mesh_net_pdu_build(), which shares mesh_net_valid() with encrypt.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_valid_field_arms);
ATF_TC_BODY(mesh_net_valid_field_arms, tc)
{
	struct mesh_net_pdu p;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;

	/* A NULL PDU is rejected. */
	ATF_CHECK_EQ(-1, mesh_net_pdu_build(NULL, out, &outlen));

	/* A fully valid baseline that must build. */
	memset(&p, 0, sizeof(p));
	p.ivi = 0;
	p.nid = NET_NID;
	p.ctl = 0;
	p.ttl = 0x04;
	p.seq = 0x000001;
	p.src = 0x0003;
	p.dst = 0x1201;
	p.transport[0] = 0xaa;
	p.transport_len = 1;
	ATF_REQUIRE_EQ(0, mesh_net_pdu_build(&p, out, &outlen));

	/* Each out-of-range field independently fails validation. */
#define	BAD(field, val, msg) do {					\
	struct mesh_net_pdu q = p;					\
	q.field = (val);						\
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_build(&q, out, &outlen), msg);	\
} while (0)
	BAD(ivi, BT_MESH_SPEC_NET_FLAG_MAX + 1, "IVI > 1 must be rejected");
	BAD(nid, BT_MESH_SPEC_NET_NID_MAX + 1, "NID > 0x7f must be rejected");
	BAD(ctl, BT_MESH_SPEC_NET_FLAG_MAX + 1, "CTL > 1 must be rejected");
	BAD(ttl, BT_MESH_SPEC_NET_TTL_MAX + 1, "TTL > 0x7f must be rejected");
	BAD(seq, BT_MESH_SPEC_NET_SEQ_MAX + 1, "SEQ > 0xffffff rejected");
	BAD(transport_len, 0, "an empty Transport PDU must be rejected");
	BAD(transport_len, MESH_NET_MAX_TRANSPORT_PDU + 1,
	    "an oversized Transport PDU must be rejected");
#undef	BAD
}

/* ================================================================
 * mesh_net_pdu_build / _parse NULL-argument and length guards.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_codec_guards);
ATF_TC_BODY(mesh_net_codec_guards, tc)
{
	struct mesh_net_pdu p, out;
	uint8_t wire[MESH_NET_MAX_PDU + 4];
	size_t outlen;

	memset(&p, 0, sizeof(p));
	p.nid = NET_NID;
	p.ttl = 1;
	p.seq = 1;
	p.src = 0x0003;
	p.dst = 0x1201;
	p.transport[0] = 0xaa;
	p.transport_len = 1;

	/* build: NULL out / NULL outlen. */
	ATF_CHECK_EQ(-1, mesh_net_pdu_build(&p, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_net_pdu_build(&p, wire, NULL));

	/* parse: NULL in / NULL out. */
	ATF_CHECK_EQ(-1, mesh_net_pdu_parse(NULL, 10, &out));
	ATF_CHECK_EQ(-1, mesh_net_pdu_parse(wire, 10, NULL));

	/* parse: a PDU with no Transport octets (inlen <= header). */
	memset(wire, 0, sizeof(wire));
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_parse(wire, MESH_NET_HDR_LEN, &out),
	    "a header-only PDU (no Transport) must be rejected");

	/* parse: a Transport PDU longer than the maximum. */
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_parse(wire,
	    MESH_NET_HDR_LEN + MESH_NET_MAX_TRANSPORT_PDU + 1, &out),
	    "an oversized Transport PDU must be rejected on parse");
}

/* ================================================================
 * mesh_net_encrypt / _decrypt NULL-argument, NID-range and short-PDU guards.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_secure_guards);
ATF_TC_BODY(mesh_net_secure_guards, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(pdu_bytes,
	    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e", 29);
	struct mesh_net_pdu p, out;
	uint8_t buf[MESH_NET_MAX_PDU];
	size_t outlen;

	memset(&p, 0, sizeof(p));
	p.nid = NET_NID;
	p.ttl = 1;
	p.seq = 1;
	p.src = 0x0003;
	p.dst = 0x1201;
	p.transport[0] = 0xaa;
	p.transport_len = 1;

	/* encrypt: each NULL pointer argument. */
	ATF_CHECK_EQ(-1, mesh_net_encrypt(NULL, privkey, NET_NID, NET_IVINDEX,
	    &p, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_net_encrypt(enckey, NULL, NET_NID, NET_IVINDEX,
	    &p, buf, &outlen));
	ATF_CHECK_EQ(-1, mesh_net_encrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    &p, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_net_encrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    &p, buf, NULL));
	/* encrypt: NID out of range and an invalid PDU. */
	ATF_CHECK_EQ(-1, mesh_net_encrypt(enckey, privkey, 0x80, NET_IVINDEX,
	    &p, buf, &outlen));
	p.transport_len = 0;
	ATF_CHECK_EQ(-1, mesh_net_encrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    &p, buf, &outlen));

	/* decrypt: each NULL pointer argument. */
	ATF_CHECK_EQ(-1, mesh_net_decrypt(NULL, privkey, NET_NID, NET_IVINDEX,
	    pdu_bytes, 29, &out));
	ATF_CHECK_EQ(-1, mesh_net_decrypt(enckey, NULL, NET_NID, NET_IVINDEX,
	    pdu_bytes, 29, &out));
	ATF_CHECK_EQ(-1, mesh_net_decrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    NULL, 29, &out));
	ATF_CHECK_EQ(-1, mesh_net_decrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    pdu_bytes, 29, NULL));
	/* decrypt: NID out of range. */
	ATF_CHECK_EQ(-1, mesh_net_decrypt(enckey, privkey, 0x80, NET_IVINDEX,
	    pdu_bytes, 29, &out));
	/* decrypt: below the absolute minimum PDU length (1+6+2+1+4 = 14). */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, pdu_bytes, 13, &out),
	    "a PDU shorter than the 14-octet minimum must be rejected");
}

/* ================================================================
 * Deobfuscated-header length arms (Section 3.4.5): once the header is
 * recovered the effective NetMIC/ciphertext lengths are re-validated.
 * Truncating/extending an authentic PDU (its first 7 encrypted octets,
 * hence the PECB and the recovered CTL, are preserved) drives these arms
 * deterministically:
 *   - a control PDU (CTL=1, 64-bit NetMIC) truncated to 16 octets is
 *     shorter than 1+6+8+2, so it is rejected before decryption;
 *   - the same PDU at 17 octets yields a zero-length Transport PDU;
 *   - an access PDU (CTL=0, 32-bit NetMIC) extended to 30 octets yields a
 *     Transport PDU longer than the 16-octet maximum.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_decrypt_length_arms);
ATF_TC_BODY(mesh_net_decrypt_length_arms, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	HEX(ctlpdu, "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df",
	    28);					/* Message #1, CTL=1 */
	HEX(accpdu,
	    "68cab5c5348a230afba8c63d4e686364979deaf4fd40961145939cda0e", 29);
	uint8_t ext[MESH_NET_MAX_PDU + 1];
	struct mesh_net_pdu out;

	/* CTL=1 PDU truncated to 16: shorter than 1+6+miclen(8)+2 = 17. */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, ctlpdu, 16, &out),
	    "a control PDU too short for its 64-bit NetMIC must be rejected");

	/* CTL=1 PDU at 17: EncDST||EncTransport is exactly 2, Transport = 0. */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, ctlpdu, 17, &out),
	    "a control PDU with an empty Transport PDU must be rejected");

	/* CTL=0 PDU extended to 30: recovered Transport length 17 > max 16. */
	memcpy(ext, accpdu, 29);
	ext[29] = 0x00;
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, ext, 30, &out),
	    "an access PDU whose Transport PDU exceeds the maximum must fail");
}

/* ================================================================
 * mesh_net_relay with a NULL new_ttl output at a relayable TTL: the
 * decision is still 1 (relayable) and the NULL output is simply skipped.
 * mesh_net_rpl_check with a NULL table returns -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_relay_rpl_null);
ATF_TC_BODY(mesh_net_relay_rpl_null, tc)
{

	ATF_CHECK_EQ_MSG(1, mesh_net_relay(2, NULL),
	    "TTL 2 must be relayable even with a NULL new_ttl");
	ATF_CHECK_EQ_MSG(-1, mesh_net_rpl_check(NULL, 4, 0x0001, 1),
	    "a NULL RPL table must be rejected");
}

/* ================================================================
 * Control-message NetMIC bound (MshPRT_v1.1 Section 3.4.4): a control PDU
 * (CTL=1) carries an 8-octet NetMIC, so its Transport PDU is bounded at 12
 * octets, not 16.  Encrypting a control PDU with a 13..16-octet Transport
 * PDU would write 7 + 2 + transport_len + 8 = 30..33 octets into the
 * MESH_NET_MAX_PDU (29) output buffer -- an overflow -- so mesh_net_encrypt
 * MUST reject it.  The legitimate maxima (12 control, 16 access) must still
 * be accepted and must yield a complete Network PDU of at most 29 octets.
 * A canary region past octet 29 catches any stray write.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_ctl_netmic_bound);
ATF_TC_BODY(mesh_net_ctl_netmic_bound, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	struct mesh_net_pdu p;
	uint8_t out[MESH_NET_MAX_PDU + 8];
	size_t outlen, tl;

	/* MESH_NET_MAX_PDU is the 29-octet advertising-bearer Network PDU. */
	ATF_REQUIRE_EQ_MSG(BT_MESH_SPEC_NET_MAX_PDU_SIZE, MESH_NET_MAX_PDU,
	    "MshPRT Section 3.4.4: a Network PDU is at most 29 octets");

	memset(&p, 0, sizeof(p));
	p.nid = NET_NID;
	p.ctl = 1;			/* control message: 64-bit NetMIC */
	p.ttl = 0;
	p.seq = 0x000001;
	p.src = 0x1201;
	p.dst = 0xfffd;
	memset(p.transport, 0xa5, sizeof(p.transport));

	/*
	 * Over-long control Transport PDUs (13..16) must be REJECTED before any
	 * ciphertext is written, and the output buffer (canary included) must be
	 * left entirely untouched: 7 + 2 + tl + 8 would exceed 29.
	 */
	for (tl = 13; tl <= MESH_NET_MAX_TRANSPORT_PDU; tl++) {
		memset(out, 0xcc, sizeof(out));
		outlen = 12345;
		p.transport_len = tl;
		ATF_CHECK_EQ_MSG(-1, mesh_net_encrypt(enckey, privkey, NET_NID,
		    NET_IVINDEX, &p, out, &outlen),
		    "control Transport PDU > 12 octets must be rejected");
		for (size_t i = 0; i < sizeof(out); i++)
			ATF_CHECK_EQ_MSG(0xcc, out[i],
			    "rejected control encrypt wrote octet %zu", i);
	}

	/* The legitimate control maximum (12) is accepted; PDU is exactly 29. */
	memset(out, 0xcc, sizeof(out));
	p.transport_len = MESH_NET_MAX_CONTROL_TRANSPORT_PDU;
	ATF_REQUIRE_EQ_MSG(0, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &p, out, &outlen),
	    "a 12-octet control Transport PDU must be accepted");
	ATF_CHECK_EQ_MSG(outlen, 29,
	    "control max PDU length %zu != 29 (7+2+12+8)", outlen);
	ATF_CHECK(outlen <= MESH_NET_MAX_PDU);
	/* Nothing was written past octet 29. */
	for (size_t i = outlen; i < sizeof(out); i++)
		ATF_CHECK_EQ_MSG(0xcc, out[i],
		    "control encrypt wrote past the PDU at octet %zu", i);

	/* The legitimate access maximum (16) is accepted; PDU is exactly 29. */
	memset(out, 0xcc, sizeof(out));
	p.ctl = 0;			/* access message: 32-bit NetMIC */
	p.transport_len = MESH_NET_MAX_TRANSPORT_PDU;
	ATF_REQUIRE_EQ_MSG(0, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &p, out, &outlen),
	    "a 16-octet access Transport PDU must be accepted");
	ATF_CHECK_EQ_MSG(outlen, 29,
	    "access max PDU length %zu != 29 (7+2+16+4)", outlen);
	ATF_CHECK(outlen <= MESH_NET_MAX_PDU);
	for (size_t i = outlen; i < sizeof(out); i++)
		ATF_CHECK_EQ_MSG(0xcc, out[i],
		    "access encrypt wrote past the PDU at octet %zu", i);
}

/* ================================================================
 * Empty-PDU guard: mesh_net_decrypt with inlen == 0 must reject cleanly
 * without reading in[0] (the IVI|NID gate octet).  The input points at a
 * 1-octet buffer so a spurious in[0] read would still be in bounds for the
 * tools, but the contract is a guarded error return with no field recovered.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_decrypt_empty);
ATF_TC_BODY(mesh_net_decrypt_empty, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	uint8_t in[1] = { 0x68 };
	struct mesh_net_pdu out;

	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, in, 0, &out),
	    "an empty (inlen==0) PDU must be rejected without reading in[0]");
}

/* ================================================================
 * SRC must be a unicast address (MshPRT_v1.1 Section 3.4.3): a Network PDU
 * whose Source is a group, virtual or unassigned address is malformed and
 * must be rejected by both the cleartext codec and the secure encrypt.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mesh_net_src_unicast);
ATF_TC_BODY(mesh_net_src_unicast, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	struct mesh_net_pdu pdu;
	uint8_t out[MESH_NET_MAX_PDU];
	size_t outlen;
	static const uint16_t bad_src[] = {
		0x0000,		/* unassigned */
		0xc000,		/* group */
		0xffff,		/* all-nodes group */
		0x8000,		/* virtual */
		0xbfff,		/* virtual */
	};
	size_t i;

	memset(&pdu, 0, sizeof(pdu));
	pdu.nid = NET_NID;
	pdu.ctl = 0;
	pdu.ttl = 5;
	pdu.seq = 0x000007;
	pdu.dst = 0xc105;			/* group destination is fine */
	pdu.transport[0] = 0x11;
	pdu.transport_len = 10;

	/* A unicast SRC is accepted. */
	pdu.src = 0x1201;
	ATF_CHECK_EQ_MSG(0, mesh_net_pdu_build(&pdu, out, &outlen),
	    "unicast SRC builds");
	ATF_CHECK_EQ(0, mesh_net_encrypt(enckey, privkey, NET_NID, NET_IVINDEX,
	    &pdu, out, &outlen));

	/* Every non-unicast SRC is rejected by build and by encrypt. */
	for (i = 0; i < nitems(bad_src); i++) {
		pdu.src = bad_src[i];
		ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_build(&pdu, out, &outlen),
		    "non-unicast SRC 0x%04x rejected by build", bad_src[i]);
		ATF_CHECK_EQ_MSG(-1, mesh_net_encrypt(enckey, privkey, NET_NID,
		    NET_IVINDEX, &pdu, out, &outlen),
		    "non-unicast SRC 0x%04x rejected by encrypt", bad_src[i]);
	}

	/* The cleartext decoder applies the same address validity rules. */
	memset(out, 0, sizeof(out));
	out[5] = 0xc0;			/* group SRC 0xc000 */
	out[7] = 0x00; out[8] = 0x01;
	out[MESH_NET_HDR_LEN] = 0x11;
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_parse(out, MESH_NET_HDR_LEN + 1,
	    &pdu), "cleartext parse accepted a non-unicast SRC");

	/* Unassigned is prohibited as DST on every Network PDU path. */
	pdu.src = 0x1201;
	pdu.dst = 0x0000;
	pdu.transport_len = 10;
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_build(&pdu, out, &outlen),
	    "build accepted unassigned DST");
	ATF_CHECK_EQ_MSG(-1, mesh_net_encrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, &pdu, out, &outlen), "encrypt accepted unassigned DST");
	memset(out, 0, MESH_NET_HDR_LEN + 1);
	out[5] = 0x12; out[6] = 0x01;
	out[MESH_NET_HDR_LEN] = 0x11;
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_parse(out, MESH_NET_HDR_LEN + 1,
	    &pdu), "cleartext parse accepted unassigned DST");

	/* CTL=1 permits at most 12 transport octets in a Network PDU. */
	memset(out, 0, MESH_NET_HDR_LEN + 13);
	out[1] = 0x80;
	out[5] = 0x12; out[6] = 0x01;
	out[7] = 0x00; out[8] = 0x02;
	ATF_CHECK_EQ_MSG(-1, mesh_net_pdu_parse(out, MESH_NET_HDR_LEN + 13,
	    &pdu), "cleartext parse accepted an oversized control transport PDU");
}

/*
 * Finding 3 regression: mesh_net_decrypt() must reject any input longer than
 * MESH_NET_MAX_PDU (29 octets) up front (MshPRT Section 3.4.4).  This also
 * bounds the recovered control Transport PDU at 12 octets: a control PDU with a
 * 13..16-octet Transport PDU is 30..33 octets total and is now rejected, where
 * the previous code (capping only at the 16-octet access maximum with no total
 * check) would have let an authenticated 33-octet control PDU through.
 */
ATF_TC_WITHOUT_HEAD(mesh_net_decrypt_overlong);
ATF_TC_BODY(mesh_net_decrypt_overlong, tc)
{
	HEX(enckey, ENCKEY_HEX, 16);
	HEX(privkey, PRIVKEY_HEX, 16);
	/* Message #1 is a valid 28-octet control (CTL=1) PDU. */
	HEX(ctlpdu, "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df",
	    28);
	uint8_t ext[MESH_NET_MAX_PDU + 8];
	struct mesh_net_pdu out;
	size_t n;

	/* The canonical 28-octet control PDU still decrypts. */
	ATF_CHECK_EQ_MSG(0, mesh_net_decrypt(enckey, privkey, NET_NID,
	    NET_IVINDEX, ctlpdu, 28, &out),
	    "a valid 28-octet control PDU must still decrypt");

	/* Any length 30..33 (control tlen 13..16) must be rejected. */
	memcpy(ext, ctlpdu, 28);
	memset(ext + 28, 0x00, sizeof(ext) - 28);
	for (n = MESH_NET_MAX_PDU + 1; n <= MESH_NET_MAX_PDU + 4; n++)
		ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey, NET_NID,
		    NET_IVINDEX, ext, n, &out),
		    "a Network PDU longer than 29 octets must be rejected");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mesh_net_decrypt_overlong);
	ATF_TP_ADD_TC(tp, mesh_net_encrypt_message1);
	ATF_TP_ADD_TC(tp, mesh_net_decrypt_message1);
	ATF_TP_ADD_TC(tp, mesh_net_encrypt_message6);
	ATF_TP_ADD_TC(tp, mesh_net_decrypt_message6);
	ATF_TP_ADD_TC(tp, mesh_net_nid_mismatch);
	ATF_TP_ADD_TC(tp, mesh_net_netmic_tamper);
	ATF_TP_ADD_TC(tp, mesh_net_relay_boundaries);
	ATF_TP_ADD_TC(tp, mesh_net_roundtrip);
	ATF_TP_ADD_TC(tp, mesh_net_rpl_primitive);
	ATF_TP_ADD_TC(tp, mesh_net_valid_field_arms);
	ATF_TP_ADD_TC(tp, mesh_net_codec_guards);
	ATF_TP_ADD_TC(tp, mesh_net_secure_guards);
	ATF_TP_ADD_TC(tp, mesh_net_decrypt_length_arms);
	ATF_TP_ADD_TC(tp, mesh_net_relay_rpl_null);
	ATF_TP_ADD_TC(tp, mesh_net_ctl_netmic_bound);
	ATF_TP_ADD_TC(tp, mesh_net_decrypt_empty);
	ATF_TP_ADD_TC(tp, mesh_net_src_unicast);

	return (atf_no_error());
}
