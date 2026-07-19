/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF known-answer tests for the Bluetooth Mesh Proxy protocol
 * (mesh_proxy.[ch], MshPRT_v1.1 Section 6, the GATT bearer).
 *
 * The end-to-end secured vector is the worked example of MshPRT_v1.1
 * Section 8.9.1 "Set Filter Type" proxy configuration message sample data,
 * which secures a Set Filter Type message (Opcode 0x00, FilterType 0x00 =
 * accept list) as a Network PDU with CTL=1, TTL=0, DST=0x0000 under the
 * proxy nonce (Section 3.9.5.4):
 *
 *   NetKey        7dd7... (subnet); managed-flooding material:
 *   NID           = 0x10
 *   EncryptionKey = 3a4fe84a6cc2c6a766ea93f1084d4039
 *   PrivacyKey    = f695fcce709ccface4d8b7a1e6e39d25
 *   IV Index      = 0x12345678, SEQ = 0x000001, SRC = 0x0001
 *   Proxy nonce   = 03000000010001000012345678
 *   TransportPDU  = 0000
 *   EncDST||EncTransportPDU = 8b8c2851, NetMIC = 2e792d3711f4b526
 *   PECB          = b86bd60ffbba6ca41e7109226f247a16
 *   ProxyMessage (Network PDU) = 10386bd60efbbb8b8c28512e792d3711f4b526
 *   ProxyPDU                   = 0210386bd60efbbb8b8c28512e792d3711f4b526
 *
 * Every one of those bytes was reproduced independently with the Python
 * "cryptography" package (AES-CCM for the NetMIC, AES-ECB PECB + XOR for
 * the obfuscation) over the Section 8.9.1 inputs before being committed
 * here, so a passing test confirms the module against the published spec
 * bytes rather than against itself.
 *
 * The SAR segmentation vector (proxy_sar_segment_reassemble) is hand-derived
 * from that same Section 8.9.1 Network PDU: at a Proxy PDU size of 8 octets
 * the 19-octet message splits (Section 6.3.2.1) into a 7-octet first, a
 * 7-octet continuation and a 5-octet last segment, each with its SAR|type
 * header octet; the exact segment bytes are asserted.
 *
 * Mesh operates in network (big-endian) byte order; no byte reversal is
 * applied.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_proxy.h"
#include "spec_mesh_proxy_oracles.h"

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

/* Section 8.9.1 secured proxy configuration material. */
#define	CFG_ENCKEY_HEX	BT_MSHPRT11_PROXY_SAMPLE_ENCKEY_HEX
#define	CFG_PRIVKEY_HEX	BT_MSHPRT11_PROXY_SAMPLE_PRIVKEY_HEX
#define	CFG_NID		BT_MSHPRT11_PROXY_SAMPLE_NID
#define	CFG_IVINDEX	BT_MSHPRT11_PROXY_SAMPLE_IV_INDEX
#define	CFG_SEQ		BT_MSHPRT11_PROXY_SAMPLE_SEQ
#define	CFG_SRC		BT_MSHPRT11_PROXY_SAMPLE_SRC
/* ProxyMessage = the secured Network PDU (19 octets). */
#define	CFG_PROXYMSG_HEX	BT_MSHPRT11_PROXY_SAMPLE_MESSAGE_HEX
/* ProxyPDU = 0x02 (complete | Proxy Configuration) || ProxyMessage. */
#define	CFG_PROXYPDU_HEX	BT_MSHPRT11_PROXY_SAMPLE_PDU_HEX

/* ================================================================
 * Proxy PDU codec (Section 6.3.1): the SAR|MessageType header octet for
 * every MessageType, plus the Section 8.9.1 complete-config PDU byte.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_pdu_build_parse);
ATF_TC_BODY(proxy_pdu_build_parse, tc)
{
	static const uint8_t types[] = {
		BT_MSHPRT11_PROXY_TYPE_NETWORK, BT_MSHPRT11_PROXY_TYPE_BEACON,
		BT_MSHPRT11_PROXY_TYPE_CONFIG,
		BT_MSHPRT11_PROXY_TYPE_PROVISIONING
	};
	static const uint8_t sars[] = {
		BT_MSHPRT11_PROXY_SAR_COMPLETE, BT_MSHPRT11_PROXY_SAR_FIRST,
		BT_MSHPRT11_PROXY_SAR_CONTINUATION,
		BT_MSHPRT11_PROXY_SAR_LAST
	};
	uint8_t payload[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
	size_t ti, si;

	for (ti = 0; ti < sizeof(types); ti++) {
		for (si = 0; si < sizeof(sars); si++) {
			uint8_t out[8];
			size_t outlen;
			uint8_t sar, type;
			const uint8_t *data;
			size_t datalen;

			ATF_REQUIRE_EQ(0, mesh_proxy_pdu_build(sars[si],
			    types[ti], payload, sizeof(payload), out,
			    sizeof(out), &outlen));
			ATF_CHECK_EQ(outlen, 1 + sizeof(payload));
			/* Header octet = SAR (bits 7..6) | MessageType (5..0). */
			ATF_CHECK_EQ_MSG(out[0],
			    (uint8_t)((sars[si] << 6) | types[ti]),
			    "SAR|MessageType header octet mismatch");

			ATF_REQUIRE_EQ(0, mesh_proxy_pdu_parse(out, outlen,
			    &sar, &type, &data, &datalen));
			ATF_CHECK_EQ(sar, sars[si]);
			ATF_CHECK_EQ(type, types[ti]);
			ATF_CHECK_EQ(datalen, sizeof(payload));
			ATF_CHECK_EQ(0, memcmp(data, payload, sizeof(payload)));
		}
	}
}

/* The Section 8.9.1 ProxyPDU begins with 0x02 = SAR complete | Config. */
ATF_TC_WITHOUT_HEAD(proxy_pdu_config_header_kat);
ATF_TC_BODY(proxy_pdu_config_header_kat, tc)
{
	HEX(proxypdu, CFG_PROXYPDU_HEX, BT_MSHPRT11_PROXY_SAMPLE_PDU_SIZE);
	HEX(proxymsg, CFG_PROXYMSG_HEX,
	    BT_MSHPRT11_PROXY_SAMPLE_MESSAGE_SIZE);
	uint8_t sar, type;
	const uint8_t *data;
	size_t datalen;

	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_parse(proxypdu, sizeof(proxypdu),
	    &sar, &type, &data, &datalen));
	ATF_CHECK_EQ_MSG(sar, BT_MSHPRT11_PROXY_SAR_COMPLETE,
	    "8.9.1 SAR != complete");
	ATF_CHECK_EQ_MSG(type, BT_MSHPRT11_PROXY_TYPE_CONFIG,
	    "8.9.1 MessageType != Proxy Configuration");
	ATF_CHECK_EQ(datalen, 19);
	ATF_CHECK_EQ_MSG(0, memcmp(data, proxymsg, 19),
	    "8.9.1 Proxy PDU Data field != ProxyMessage");
}

/* ================================================================
 * Negative Proxy PDU parses: truncated, and Reserved-for-Future-Use type.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_pdu_negative);
ATF_TC_BODY(proxy_pdu_negative, tc)
{
	uint8_t buf[4] = { 0x02, 0x00, 0x00, 0x00 };
	uint8_t out[8];
	size_t outlen;
	uint8_t sar, type;
	struct mesh_proxy_reasm reasm;
	int complete;
	const uint8_t *data;
	size_t datalen;

	/* Truncated: a Proxy PDU needs at least the 1-octet header. */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_pdu_parse(buf, 0, &sar, &type, &data,
	    &datalen), "parse accepted a 0-length Proxy PDU");

	/* MessageType 0x04..0x3f are RFU and must be rejected on parse. */
	buf[0] = 0x04;			/* SAR complete, MessageType 0x04 (RFU) */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_pdu_parse(buf, sizeof(buf), &sar, &type,
	    &data, &datalen), "parse accepted an RFU MessageType");
	buf[0] = 0xff;			/* SAR last, MessageType 0x3f (RFU) */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_pdu_parse(buf, sizeof(buf), &sar, &type,
	    &data, &datalen), "parse accepted an RFU MessageType");
	/* The inbound reassembler ignores RFU PDUs without a link error. */
	mesh_proxy_reasm_init(&reasm);
	ATF_CHECK_EQ(MESH_PROXY_REASM_IGNORED,
	    mesh_proxy_reasm_feed(&reasm, buf, sizeof(buf), &complete, &type,
	    out, sizeof(out), &outlen));
	ATF_CHECK_EQ(0, complete);

	/* Build rejects an RFU MessageType too. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(BT_MSHPRT11_PROXY_SAR_COMPLETE,
	    BT_MSHPRT11_PROXY_TYPE_FIRST_RFU,
	    buf, 1, out, sizeof(out), &outlen));
	/* Build rejects an undersized output buffer. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(BT_MSHPRT11_PROXY_SAR_COMPLETE,
	    BT_MSHPRT11_PROXY_TYPE_NETWORK, buf, 4, out, 3, &outlen));
}

/* ================================================================
 * SAR segmentation + reassembly (Section 6.3.2), exact segment bytes
 * hand-derived from the Section 8.9.1 Network PDU at a Proxy PDU size of 8.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_sar_segment_reassemble);
ATF_TC_BODY(proxy_sar_segment_reassemble, tc)
{
	HEX(msg, CFG_PROXYMSG_HEX, 19);
	/* SAR|type header 0x42/0x82/0xc2 = first/continuation/last | Config. */
	HEX(seg0, "4210386bd60efbbb", 8);
	HEX(seg1, "828b8c28512e792d", 8);
	HEX(seg2, "c23711f4b526", 6);
	struct mesh_proxy_seg segs[8];
	size_t nseg;
	struct mesh_proxy_reasm r;
	size_t i;
	int complete = 0;
	uint8_t got_type = 0xff, got[MESH_PROXY_MAX_MSG];
	size_t gotlen = 0;

	ATF_REQUIRE_EQ(0, mesh_proxy_segment(BT_MSHPRT11_PROXY_TYPE_CONFIG, msg,
	    sizeof(msg), 8, segs, 8, &nseg));
	ATF_REQUIRE_EQ_MSG(nseg, 3, "19-octet message at MTU 8 must be 3 segs");

	ATF_CHECK_EQ(segs[0].len, 8);
	ATF_CHECK_EQ_MSG(0, memcmp(segs[0].bytes, seg0, 8), "first segment");
	ATF_CHECK_EQ(segs[1].len, 8);
	ATF_CHECK_EQ_MSG(0, memcmp(segs[1].bytes, seg1, 8),
	    "continuation segment");
	ATF_CHECK_EQ(segs[2].len, 6);
	ATF_CHECK_EQ_MSG(0, memcmp(segs[2].bytes, seg2, 6), "last segment");

	/* Reassembly reconstructs the original message exactly. */
	mesh_proxy_reasm_init(&r);
	for (i = 0; i < nseg; i++) {
		int c;
		uint8_t ty;
		uint8_t m[MESH_PROXY_MAX_MSG];
		size_t ml;

		ATF_REQUIRE_EQ_MSG(0, mesh_proxy_reasm_feed(&r, segs[i].bytes,
		    segs[i].len, &c, &ty, m, sizeof(m), &ml),
		    "legal segment rejected by reassembler");
		/* Only the last segment completes the message. */
		ATF_CHECK_EQ(c, (i == nseg - 1) ? 1 : 0);
		if (c) {
			complete = 1;
			got_type = ty;
			gotlen = ml;
			memcpy(got, m, ml);
		}
	}
	ATF_REQUIRE(complete);
	ATF_CHECK_EQ(got_type, BT_MSHPRT11_PROXY_TYPE_CONFIG);
	ATF_CHECK_EQ(gotlen, sizeof(msg));
	ATF_CHECK_EQ_MSG(0, memcmp(got, msg, sizeof(msg)),
	    "reassembled message != original");
}

/* A message that fits a single Proxy PDU is emitted as one complete seg. */
ATF_TC_WITHOUT_HEAD(proxy_sar_single_segment);
ATF_TC_BODY(proxy_sar_single_segment, tc)
{
	uint8_t msg[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	struct mesh_proxy_seg segs[4];
	size_t nseg;

	ATF_REQUIRE_EQ(0, mesh_proxy_segment(BT_MSHPRT11_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), 32, segs, 4, &nseg));
	ATF_CHECK_EQ_MSG(nseg, 1, "message fitting one PDU must be 1 segment");
	ATF_CHECK_EQ(segs[0].len, 1 + sizeof(msg));
	/* SAR complete (0b00) | MessageType Network (0x00) = 0x00. */
	ATF_CHECK_EQ(segs[0].bytes[0], 0x00);
	ATF_CHECK_EQ(0, memcmp(segs[0].bytes + 1, msg, sizeof(msg)));
}

/* ================================================================
 * Illegal SAR sequences must be rejected (Section 6.3.2.2: the receiver
 * disconnects).  Each starts from a fresh reassembler.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_sar_illegal_sequences);
ATF_TC_BODY(proxy_sar_illegal_sequences, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t first[4]  = { 0x42, 0x11, 0x22, 0x33 };	/* first | Config */
	uint8_t cont[4]   = { 0x82, 0x44, 0x55, 0x66 };	/* continuation */
	uint8_t last[4]   = { 0xc2, 0x77, 0x88, 0x99 };	/* last | Config */
	uint8_t cpl[4]    = { 0x02, 0xaa, 0xbb, 0xcc };	/* complete | Config */
	uint8_t last_net[4] = { 0xc0, 0x77, 0x88, 0x99 }; /* last | Network */
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	/* Continuation without a preceding first. */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, cont, sizeof(cont), &c,
	    &ty, m, sizeof(m), &ml), "continuation-without-first accepted");

	/* Last without a preceding first. */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, last, sizeof(last), &c,
	    &ty, m, sizeof(m), &ml), "last-without-first accepted");

	/* First then another first (first-after-first). */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first, sizeof(first), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, first, sizeof(first), &c,
	    &ty, m, sizeof(m), &ml), "first-after-first accepted");

	/* First then a complete (complete mid-reassembly). */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first, sizeof(first), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c,
	    &ty, m, sizeof(m), &ml), "complete-after-first accepted");

	/* First (Config) then a last of a DIFFERENT MessageType (Network). */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first, sizeof(first), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, last_net,
	    sizeof(last_net), &c, &ty, m, sizeof(m), &ml),
	    "MessageType change mid-reassembly accepted");
}

/* Reassembling a Network PDU longer than 29 octets must be rejected. */
ATF_TC_WITHOUT_HEAD(proxy_sar_oversized_network);
ATF_TC_BODY(proxy_sar_oversized_network, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t big[1 + 20];
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	memset(big, 0, sizeof(big));
	big[0] = 0x40;			/* first | Network PDU */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, big, sizeof(big), &c, &ty,
	    m, sizeof(m), &ml));	/* 20 octets so far, legal */
	big[0] = 0xc0;			/* last | Network PDU, +20 => 40 > 29 */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, big, sizeof(big), &c,
	    &ty, m, sizeof(m), &ml),
	    "reassembled Network PDU > 29 octets accepted");
}

/* Section 6.3.2.2 requires disconnect on a message exceeding its type's
 * maximum.  Exercise both complete and segmented boundary crossings. */
ATF_TC_WITHOUT_HEAD(proxy_sar_message_type_limits);
ATF_TC_BODY(proxy_sar_message_type_limits, tc)
{
	static const struct {
		uint8_t type;
		size_t max;
	} limits[] = {
		{ BT_MSHPRT11_PROXY_TYPE_NETWORK, BT_MSHPRT11_NETWORK_PDU_MAX },
		{ BT_MSHPRT11_PROXY_TYPE_BEACON,
		    BT_MSHPRT11_PROXY_BEACON_PDU_MAX },
		{ BT_MSHPRT11_PROXY_TYPE_CONFIG,
		    BT_MSHPRT11_PROXY_CONFIG_PDU_MAX },
		{ BT_MSHPRT11_PROXY_TYPE_PROVISIONING,
		    BT_MSHPRT11_PROXY_PROVISIONING_PDU_MAX },
	};
	struct mesh_proxy_reasm r;
	struct mesh_proxy_seg segs[8];
	uint8_t wire[MESH_PROXY_HDR_LEN + MESH_PROXY_MAX_MSG + 1];
	uint8_t msg[MESH_PROXY_MAX_MSG + 1], out[MESH_PROXY_MAX_MSG];
	size_t i, msglen, nseg;
	uint8_t out_type;
	int complete;

	ATF_CHECK_EQ(MESH_PROXY_MAX_UNPROV_BEACON,
	    BT_MSHPRT11_PROXY_UNPROV_BEACON_MAX);
	ATF_CHECK_EQ(MESH_PROXY_MAX_SECURE_BEACON,
	    BT_MSHPRT11_PROXY_SECURE_BEACON_MAX);
	ATF_CHECK_EQ(MESH_PROXY_MAX_PRIVATE_BEACON,
	    BT_MSHPRT11_PROXY_PRIVATE_BEACON_MAX);
	ATF_CHECK_EQ(MESH_PROXY_MAX_BEACON_PDU,
	    BT_MSHPRT11_PROXY_BEACON_PDU_MAX);
	ATF_CHECK_EQ(MESH_PROXY_MAX_PROVISIONING_PDU,
	    BT_MSHPRT11_PROXY_PROVISIONING_PDU_MAX);
	ATF_CHECK_EQ(MESH_PROXY_MAX_PDU, BT_MSHPRT11_PROXY_PDU_MAX);

	memset(msg, 0xa5, sizeof(msg));
	for (i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
		/* The exact maximum is accepted as a complete Proxy message. */
		wire[0] = limits[i].type;
		memcpy(wire + 1, msg, limits[i].max);
		mesh_proxy_reasm_init(&r);
		ATF_REQUIRE_EQ_MSG(MESH_PROXY_REASM_OK,
		    mesh_proxy_reasm_feed(&r, wire, 1 + limits[i].max,
		    &complete, &out_type, out, sizeof(out), &msglen),
		    "type %u maximum rejected", limits[i].type);
		ATF_CHECK_EQ(complete, 1);
		ATF_CHECK_EQ(msglen, limits[i].max);

		/* One octet beyond it is a SAR error (caller disconnects). */
		mesh_proxy_reasm_init(&r);
		ATF_CHECK_EQ_MSG(MESH_PROXY_REASM_ERROR,
		    mesh_proxy_reasm_feed(&r, wire, 2 + limits[i].max,
		    &complete, &out_type, out, sizeof(out), &msglen),
		    "type %u maximum + 1 accepted", limits[i].type);

		/* Outbound segmentation applies the same per-type boundary. */
		ATF_REQUIRE_EQ(0, mesh_proxy_segment(limits[i].type, msg,
		    limits[i].max, 20, segs, sizeof(segs) / sizeof(segs[0]),
		    &nseg));
		ATF_CHECK_EQ(-1, mesh_proxy_segment(limits[i].type, msg,
		    limits[i].max + 1, 20, segs,
		    sizeof(segs) / sizeof(segs[0]), &nseg));
	}

	/* A segmented beacon crossing 27 octets fails as soon as accumulated
	 * data exceeds the maximum, rather than waiting for a Last segment. */
	memset(wire, 0, sizeof(wire));
	wire[0] = (MESH_PROXY_SAR_FIRST << 6) | MESH_PROXY_TYPE_BEACON;
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(MESH_PROXY_REASM_OK, mesh_proxy_reasm_feed(&r, wire, 21,
	    &complete, &out_type, out, sizeof(out), &msglen));
	wire[0] = (MESH_PROXY_SAR_CONTINUATION << 6) |
	    MESH_PROXY_TYPE_BEACON;
	ATF_CHECK_EQ(MESH_PROXY_REASM_ERROR, mesh_proxy_reasm_feed(&r, wire, 9,
	    &complete, &out_type, out, sizeof(out), &msglen));
}

/* ================================================================
 * Proxy configuration message codecs (Section 6.6).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_cfg_set_filter_type);
ATF_TC_BODY(proxy_cfg_set_filter_type, tc)
{
	uint8_t out[4];
	size_t outlen;
	struct mesh_proxy_cfg cfg;

	/* Accept list: opcode 0x00, FilterType 0x00 (= the 8.9.1 message). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_set_filter_build(
	    BT_MSHPRT11_PROXY_FILTER_ACCEPT, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(outlen, 2);
	ATF_CHECK_EQ(out[0], BT_MSHPRT11_PROXY_OP_SET_FILTER_TYPE);
	ATF_CHECK_EQ(out[1], BT_MSHPRT11_PROXY_FILTER_ACCEPT);

	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(out, outlen, &cfg));
	ATF_CHECK_EQ(cfg.opcode, BT_MSHPRT11_PROXY_OP_SET_FILTER_TYPE);
	ATF_CHECK_EQ(cfg.filter_type, BT_MSHPRT11_PROXY_FILTER_ACCEPT);

	/* Reject list variant. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_set_filter_build(
	    BT_MSHPRT11_PROXY_FILTER_REJECT, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(out[1], BT_MSHPRT11_PROXY_FILTER_REJECT);

	/* Prohibited FilterType 0x02..0xff must be rejected. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_set_filter_build(
	    BT_MSHPRT11_PROXY_FILTER_FIRST_PROHIBITED, out, sizeof(out),
	    &outlen));
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_add_remove);
ATF_TC_BODY(proxy_cfg_add_remove, tc)
{
	uint16_t addrs[3] = { 0x0001, 0x1201, 0xc000 };
	uint8_t out[16];
	size_t outlen;
	struct mesh_proxy_cfg cfg;
	size_t i;

	/* Add Addresses (opcode 0x01): AddressArray = 2*N big-endian. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    addrs, 3, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(outlen, 1 + 2 * 3);
	ATF_CHECK_EQ(out[0], MESH_PROXY_OP_ADD_ADDR);
	ATF_CHECK_EQ(out[1], 0x00);	/* 0x0001 big-endian */
	ATF_CHECK_EQ(out[2], 0x01);
	ATF_CHECK_EQ(out[3], 0x12);	/* 0x1201 */
	ATF_CHECK_EQ(out[4], 0x01);

	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(out, outlen, &cfg));
	ATF_CHECK_EQ(cfg.opcode, MESH_PROXY_OP_ADD_ADDR);
	ATF_CHECK_EQ(cfg.naddr, 3);
	for (i = 0; i < 3; i++)
		ATF_CHECK_EQ(cfg.addrs[i], addrs[i]);

	/* Remove Addresses (opcode 0x02). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_REMOVE_ADDR,
	    addrs, 2, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(out[0], MESH_PROXY_OP_REMOVE_ADDR);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(out, outlen, &cfg));
	ATF_CHECK_EQ(cfg.opcode, MESH_PROXY_OP_REMOVE_ADDR);
	ATF_CHECK_EQ(cfg.naddr, 2);

	/* N=0 (opcode only) is a legal Add/Remove message. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    NULL, 0, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(outlen, 1);
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(out, outlen, &cfg));
	ATF_CHECK_EQ(cfg.naddr, 0);

	/* N > 5 must be rejected on build. */
	{
		uint16_t six[6] = { 1, 2, 3, 4, 5, 6 };

		ATF_CHECK_EQ(-1, mesh_proxy_cfg_addr_build(
		    MESH_PROXY_OP_ADD_ADDR, six, 6, out, sizeof(out), &outlen));
	}
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_filter_status);
ATF_TC_BODY(proxy_cfg_filter_status, tc)
{
	uint8_t out[8];
	size_t outlen;
	struct mesh_proxy_cfg cfg;

	/* Filter Status (opcode 0x03): FilterType (1) || ListSize (2). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_REJECT, 0x0102, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(outlen, 4);
	ATF_CHECK_EQ(out[0], MESH_PROXY_OP_FILTER_STATUS);
	ATF_CHECK_EQ(out[1], MESH_PROXY_FILTER_REJECT);
	ATF_CHECK_EQ(out[2], 0x01);	/* ListSize big-endian */
	ATF_CHECK_EQ(out[3], 0x02);

	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(out, outlen, &cfg));
	ATF_CHECK_EQ(cfg.opcode, MESH_PROXY_OP_FILTER_STATUS);
	ATF_CHECK_EQ(cfg.filter_type, MESH_PROXY_FILTER_REJECT);
	ATF_CHECK_EQ(cfg.list_size, 0x0102);
}

/* Negative config parses: truncation, wrong length, prohibited/RFU values. */
ATF_TC_WITHOUT_HEAD(proxy_cfg_parse_negative);
ATF_TC_BODY(proxy_cfg_parse_negative, tc)
{
	struct mesh_proxy_cfg cfg;
	uint8_t buf[16];

	/* Empty input. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 0, &cfg));

	/* Set Filter Type with a missing/oversized parameter. */
	buf[0] = MESH_PROXY_OP_SET_FILTER_TYPE;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 1, &cfg));	/* no param */
	buf[1] = 0x00;
	buf[2] = 0x00;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 3, &cfg));	/* too long */
	buf[1] = 0x02;					/* prohibited FilterType */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 2, &cfg));

	/* Add Addresses with an odd (non-2*N) AddressArray. */
	buf[0] = MESH_PROXY_OP_ADD_ADDR;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 2, &cfg));	/* 1 param octet */

	/* Add Addresses with N > 5 (13 octets => N=6). */
	memset(buf, 0, sizeof(buf));
	buf[0] = MESH_PROXY_OP_ADD_ADDR;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 1 + 2 * 6, &cfg));

	/* Filter Status with the wrong length. */
	buf[0] = MESH_PROXY_OP_FILTER_STATUS;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 3, &cfg));

	/* Directed-Proxy opcode 0x05 and an RFU opcode are rejected. */
	buf[0] = 0x05;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 3, &cfg));
	buf[0] = 0x80;
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 2, &cfg));
}

/* ================================================================
 * Proxy filter accept/reject predicate + list mutation (Sections 6.4, 6.7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_filter_predicate);
ATF_TC_BODY(proxy_filter_predicate, tc)
{
	struct mesh_proxy_filter f;
	uint16_t addrs[2] = { 0x1201, 0xc000 };

	/* Default is an accept-list filter with an empty list: passes nothing. */
	mesh_proxy_filter_init(&f);
	ATF_CHECK_EQ(f.type, MESH_PROXY_FILTER_ACCEPT);
	ATF_CHECK_EQ(f.count, 0);
	ATF_CHECK_EQ_MSG(0, mesh_proxy_filter_accepts(&f, 0x1201),
	    "empty accept list must pass nothing");

	/* Accept list: passes listed DSTs, blocks the rest. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_add(&f, addrs, 2));
	ATF_CHECK_EQ(f.count, 2);
	ATF_CHECK_EQ_MSG(1, mesh_proxy_filter_accepts(&f, 0x1201),
	    "accept list must pass a listed address");
	ATF_CHECK_EQ_MSG(1, mesh_proxy_filter_accepts(&f, 0xc000),
	    "accept list must pass a listed address");
	ATF_CHECK_EQ_MSG(0, mesh_proxy_filter_accepts(&f, 0x0002),
	    "accept list must block an unlisted address");

	/* Adding a duplicate does not grow the list. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_add(&f, addrs, 1));
	ATF_CHECK_EQ(f.count, 2);

	/* Remove drops a listed address; it is then blocked again. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_remove(&f, &addrs[0], 1));
	ATF_CHECK_EQ(f.count, 1);
	ATF_CHECK_EQ_MSG(0, mesh_proxy_filter_accepts(&f, 0x1201),
	    "removed address must be blocked by the accept list");
	ATF_CHECK_EQ(1, mesh_proxy_filter_accepts(&f, 0xc000));

	/* Switch to a reject list: setting the type clears the list. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_set_type(&f,
	    MESH_PROXY_FILTER_REJECT));
	ATF_CHECK_EQ(f.type, MESH_PROXY_FILTER_REJECT);
	ATF_CHECK_EQ_MSG(f.count, 0, "set_type must clear the list");
	/* Empty reject list passes everything. */
	ATF_CHECK_EQ(1, mesh_proxy_filter_accepts(&f, 0x1201));

	/* Reject list: blocks listed DSTs, passes the rest. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_add(&f, addrs, 2));
	ATF_CHECK_EQ_MSG(0, mesh_proxy_filter_accepts(&f, 0x1201),
	    "reject list must block a listed address");
	ATF_CHECK_EQ_MSG(1, mesh_proxy_filter_accepts(&f, 0x0002),
	    "reject list must pass an unlisted address");

	/* Prohibited FilterType is rejected and leaves the filter unchanged. */
	ATF_CHECK_EQ(-1, mesh_proxy_filter_set_type(&f, 0x02));
	ATF_CHECK_EQ(f.type, MESH_PROXY_FILTER_REJECT);
}

/* The bounded filter list rejects an overflowing Add. */
ATF_TC_WITHOUT_HEAD(proxy_filter_bounded);
ATF_TC_BODY(proxy_filter_bounded, tc)
{
	struct mesh_proxy_filter f;
	uint16_t a[1];
	size_t i;

	mesh_proxy_filter_init(&f);
	for (i = 0; i < MESH_PROXY_FILTER_MAX; i++) {
		a[0] = (uint16_t)(0x100 + i);
		ATF_REQUIRE_EQ(0, mesh_proxy_filter_add(&f, a, 1));
	}
	ATF_CHECK_EQ(f.count, MESH_PROXY_FILTER_MAX);
	/* One more distinct address overflows the bounded list. */
	a[0] = 0xffff;
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_filter_add(&f, a, 1),
	    "add past the bounded list size must fail");
}

/* ================================================================
 * Secured proxy configuration PDU, Section 8.9.1 known-answer test.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_cfg_secure_kat);
ATF_TC_BODY(proxy_cfg_secure_kat, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	HEX(cfgmsg, "0000", 2);			/* Set Filter Type, accept */
	HEX(exp_msg, CFG_PROXYMSG_HEX, 19);
	HEX(exp_pdu, CFG_PROXYPDU_HEX, 20);
	uint8_t net[MESH_PROXY_MAX_NETWORK_PDU];
	size_t netlen;
	uint8_t pdu[MESH_PROXY_MAX_PDU];
	size_t pdulen;

	/* Encrypt the config message into the secured Network PDU. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, cfgmsg, sizeof(cfgmsg), net,
	    &netlen));
	ATF_CHECK_EQ_MSG(netlen, 19, "ProxyMessage length %zu != 19", netlen);
	ATF_CHECK_EQ_MSG(0, memcmp(net, exp_msg, 19),
	    "Section 8.9.1 ProxyMessage (secured Network PDU) mismatch");

	/* Wrap it in a complete Proxy Configuration Proxy PDU. */
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_CONFIG, net, netlen, pdu, sizeof(pdu), &pdulen));
	ATF_CHECK_EQ_MSG(pdulen, 20, "ProxyPDU length %zu != 20", pdulen);
	ATF_CHECK_EQ_MSG(0, memcmp(pdu, exp_pdu, 20),
	    "Section 8.9.1 ProxyPDU mismatch");
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_secure_roundtrip);
ATF_TC_BODY(proxy_cfg_secure_roundtrip, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	HEX(msgbytes, CFG_PROXYMSG_HEX, 19);
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	uint32_t seq;
	uint16_t src;

	/* Decrypt the Section 8.9.1 Network PDU back to the config message. */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, msgbytes, sizeof(msgbytes), &seq, &src, msg,
	    sizeof(msg), &msglen));
	ATF_CHECK_EQ(seq, CFG_SEQ);
	ATF_CHECK_EQ(src, CFG_SRC);
	ATF_CHECK_EQ_MSG(msglen, 2, "recovered config message length != 2");
	ATF_CHECK_EQ(msg[0], MESH_PROXY_OP_SET_FILTER_TYPE);
	ATF_CHECK_EQ(msg[1], MESH_PROXY_FILTER_ACCEPT);

	/* A parsed round trip yields the Set Filter Type message. */
	{
		struct mesh_proxy_cfg cfg;

		ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(msg, msglen, &cfg));
		ATF_CHECK_EQ(cfg.opcode, MESH_PROXY_OP_SET_FILTER_TYPE);
		ATF_CHECK_EQ(cfg.filter_type, MESH_PROXY_FILTER_ACCEPT);
	}
}

/* NetMIC tamper and NID-mismatch rejection on the secured config PDU. */
ATF_TC_WITHOUT_HEAD(proxy_cfg_secure_reject);
ATF_TC_BODY(proxy_cfg_secure_reject, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	HEX(good, CFG_PROXYMSG_HEX, 19);
	uint8_t bad[19];
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen;
	uint32_t seq;
	uint16_t src;

	/* A key whose NID does not match the PDU is rejected up front. */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, 0x11,
	    CFG_IVINDEX, good, sizeof(good), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted a PDU whose NID != key");

	/* Flipping the last NetMIC octet must fail the 64-bit MIC check. */
	memcpy(bad, good, sizeof(bad));
	bad[18] ^= 0x01;
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, bad, sizeof(bad), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted a corrupted NetMIC");

	/* Flipping a ciphertext octet must also fail. */
	memcpy(bad, good, sizeof(bad));
	bad[7] ^= 0x80;			/* an EncDST octet */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, bad, sizeof(bad), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted corrupted ciphertext");

	/* A truncated PDU is rejected. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, good, 10, &seq, &src, msg, sizeof(msg), &msglen));
}

/* ================================================================
 * Argument-guard and boundary arms of the Proxy PDU codec (Section 6.3.1).
 * Oracle: the header contract in mesh_proxy.h (NULL out/outlen rejected;
 * sar in 0..3; RFU/oversized rejected; a zero-length Data field is legal).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_pdu_build_guards);
ATF_TC_BODY(proxy_pdu_build_guards, tc)
{
	uint8_t data[4] = { 1, 2, 3, 4 };
	uint8_t big[MESH_PROXY_MAX_MSG + 1];
	uint8_t out[MESH_PROXY_MAX_PDU];
	size_t outlen;

	memset(big, 0, sizeof(big));

	/* NULL output pointers. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_NETWORK, data, sizeof(data), NULL, sizeof(out),
	    &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_NETWORK, data, sizeof(data), out, sizeof(out),
	    NULL));

	/* SAR value out of range (0..3): 0x04 is not a defined SAR. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(0x04, MESH_PROXY_TYPE_NETWORK,
	    data, sizeof(data), out, sizeof(out), &outlen));

	/* datalen != 0 with a NULL data pointer. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_NETWORK, NULL, 4, out, sizeof(out), &outlen));

	/* Data field longer than the overall message maximum. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_NETWORK, big, sizeof(big), out, sizeof(big) + 1,
	    &outlen));

	/* A zero-length Data field is a legal PDU (header octet only). */
	ATF_REQUIRE_EQ(0, mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE,
	    MESH_PROXY_TYPE_BEACON, NULL, 0, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(outlen, MESH_PROXY_HDR_LEN);
	ATF_CHECK_EQ(out[0], MESH_PROXY_TYPE_BEACON);
}

ATF_TC_WITHOUT_HEAD(proxy_pdu_parse_guards);
ATF_TC_BODY(proxy_pdu_parse_guards, tc)
{
	uint8_t in[4] = { 0x02, 0x11, 0x22, 0x33 };
	uint8_t sar, type;
	const uint8_t *data;
	size_t datalen;

	/* Every output pointer and the input pointer must be non-NULL. */
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_parse(NULL, sizeof(in), &sar, &type,
	    &data, &datalen));
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_parse(in, sizeof(in), NULL, &type,
	    &data, &datalen));
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_parse(in, sizeof(in), &sar, NULL,
	    &data, &datalen));
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_parse(in, sizeof(in), &sar, &type,
	    NULL, &datalen));
	ATF_CHECK_EQ(-1, mesh_proxy_pdu_parse(in, sizeof(in), &sar, &type,
	    &data, NULL));
}

/* ================================================================
 * Argument-guard and boundary arms of SAR segmentation (Section 6.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_segment_guards);
ATF_TC_BODY(proxy_segment_guards, tc)
{
	uint8_t msg[40];
	uint8_t toobig[MESH_PROXY_MAX_MSG + 1];
	struct mesh_proxy_seg segs[8];
	size_t nseg;

	memset(msg, 0xa5, sizeof(msg));
	memset(toobig, 0, sizeof(toobig));

	/* NULL msg / segs / nseg. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, NULL,
	    sizeof(msg), 16, segs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), 16, NULL, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), 16, segs, 8, NULL));

	/* RFU MessageType. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(0x04, msg, sizeof(msg), 16, segs,
	    8, &nseg));

	/* pdu_max below the 2-octet minimum, and above MESH_PROXY_MAX_PDU. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), MESH_PROXY_HDR_LEN, segs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), MESH_PROXY_MAX_PDU + 1, segs, 8, &nseg));

	/* Empty message and oversized message. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg, 0, 16,
	    segs, 8, &nseg));
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, toobig,
	    sizeof(toobig), 16, segs, 8, &nseg));

	/* A single-segment message with maxsegs 0 has nowhere to land. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg, 4, 16,
	    segs, 0, &nseg));

	/* A multi-segment message that needs more than maxsegs descriptors.
	 * 40 octets at pdu_max 8 (datacap 7) needs 6 segments; cap at 2. */
	ATF_CHECK_EQ(-1, mesh_proxy_segment(MESH_PROXY_TYPE_NETWORK, msg,
	    sizeof(msg), 8, segs, 2, &nseg));
}

/* ================================================================
 * Reassembler argument guards and the remaining SAR error arms
 * (Section 6.3.2.2): the receiver rejects (disconnects on) each.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_reasm_guards);
ATF_TC_BODY(proxy_reasm_guards, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t cpl[4] = { 0x02, 0xaa, 0xbb, 0xcc };	/* complete | Config */
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	mesh_proxy_reasm_init(NULL);			/* must not crash */
	mesh_proxy_reasm_init(&r);

	/* complete == NULL is rejected (and no dereference occurs). */
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), NULL, &ty,
	    m, sizeof(m), &ml));
	/* Each remaining pointer argument must be non-NULL. */
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(NULL, cpl, sizeof(cpl), &c, &ty,
	    m, sizeof(m), &ml));
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, NULL, sizeof(cpl), &c, &ty,
	    m, sizeof(m), &ml));
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c, NULL,
	    m, sizeof(m), &ml));
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c, &ty,
	    NULL, sizeof(m), &ml));
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c, &ty,
	    m, sizeof(m), NULL));

	/* An unparseable PDU (zero length) is rejected. */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ(-1, mesh_proxy_reasm_feed(&r, cpl, 0, &c, &ty, m,
	    sizeof(m), &ml));
}

ATF_TC_WITHOUT_HEAD(proxy_reasm_complete_arms);
ATF_TC_BODY(proxy_reasm_complete_arms, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t cpl[3] = { 0x02, 0x00, 0x01 };	/* complete | Config, 2 data */
	uint8_t netbig[1 + 30];			/* complete | Network, 30 data */
	uint8_t beaconbig[1 + 67];		/* complete | Beacon, 67 data */
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	/* A fresh (not mid-reassembly) complete message is delivered as-is. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c, &ty,
	    m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 1);
	ATF_CHECK_EQ(ty, MESH_PROXY_TYPE_CONFIG);
	ATF_CHECK_EQ(ml, 2);
	ATF_CHECK_EQ(m[0], 0x00);
	ATF_CHECK_EQ(m[1], 0x01);

	/* A complete Network PDU with a Data field > 29 octets is rejected. */
	memset(netbig, 0, sizeof(netbig));
	netbig[0] = MESH_PROXY_TYPE_NETWORK;	/* SAR complete */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, netbig, sizeof(netbig),
	    &c, &ty, m, sizeof(m), &ml), "complete Network > 29 accepted");

	/* A complete non-Network/Config message > MESH_PROXY_MAX_MSG (default
	 * data-length arm) is rejected. */
	memset(beaconbig, 0, sizeof(beaconbig));
	beaconbig[0] = MESH_PROXY_TYPE_BEACON;	/* SAR complete */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, beaconbig,
	    sizeof(beaconbig), &c, &ty, m, sizeof(m), &ml),
	    "complete oversized non-Network message accepted");

	/* A complete message that will not fit the caller's output buffer. */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, cpl, sizeof(cpl), &c, &ty,
	    m, 1, &ml), "complete message overflowing outcap accepted");
}

ATF_TC_WITHOUT_HEAD(proxy_reasm_segment_error_arms);
ATF_TC_BODY(proxy_reasm_segment_error_arms, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t firstbig[1 + MESH_PROXY_MAX_MSG + 1];
	uint8_t first_full[1 + MESH_PROXY_MAX_MSG];
	uint8_t first10[1 + 10];	/* first | Config, 10 data */
	uint8_t cont1[1 + 1];		/* continuation | Config, 1 data */
	uint8_t cont_net[1 + 1];	/* continuation | Network, 1 data */
	uint8_t last1[1 + 1];		/* last | Config, 1 data */
	uint8_t last5[1 + 5];		/* last | Config, 5 data */
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	memset(firstbig, 0, sizeof(firstbig));
	firstbig[0] = (uint8_t)((MESH_PROXY_SAR_FIRST << 6) |
	    MESH_PROXY_TYPE_PROVISIONING);
	memset(first_full, 0, sizeof(first_full));
	first_full[0] = firstbig[0];
	memset(first10, 0, sizeof(first10));
	first10[0] = firstbig[0];
	memset(cont1, 0, sizeof(cont1));
	cont1[0] = (uint8_t)((MESH_PROXY_SAR_CONTINUATION << 6) |
	    MESH_PROXY_TYPE_PROVISIONING);
	memset(cont_net, 0, sizeof(cont_net));
	cont_net[0] = (uint8_t)((MESH_PROXY_SAR_CONTINUATION << 6) |
	    MESH_PROXY_TYPE_NETWORK);
	memset(last1, 0, sizeof(last1));
	last1[0] = (uint8_t)((MESH_PROXY_SAR_LAST << 6) |
	    MESH_PROXY_TYPE_PROVISIONING);
	memset(last5, 0, sizeof(last5));
	last5[0] = last1[0];

	/* A first segment whose Data exceeds the reassembly buffer. */
	mesh_proxy_reasm_init(&r);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, firstbig,
	    sizeof(firstbig), &c, &ty, m, sizeof(m), &ml),
	    "oversized first segment accepted");

	/* Continuation whose MessageType differs from the first. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first10, sizeof(first10),
	    &c, &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, cont_net,
	    sizeof(cont_net), &c, &ty, m, sizeof(m), &ml),
	    "continuation MessageType change accepted");

	/* Continuation overflowing a full buffer. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first_full,
	    sizeof(first_full), &c, &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, cont1, sizeof(cont1),
	    &c, &ty, m, sizeof(m), &ml),
	    "continuation overflowing the buffer accepted");

	/* Last overflowing a full buffer. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first_full,
	    sizeof(first_full), &c, &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, last1, sizeof(last1),
	    &c, &ty, m, sizeof(m), &ml),
	    "last overflowing the buffer accepted");

	/* Last completing a message that will not fit the caller's outcap. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first10, sizeof(first10),
	    &c, &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_reasm_feed(&r, last5, sizeof(last5),
	    &c, &ty, m, 10, &ml),
	    "reassembled message overflowing outcap accepted");
}

/* ================================================================
 * Filter API argument guards and the untaken predicate/mutation arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_filter_guards);
ATF_TC_BODY(proxy_filter_guards, tc)
{
	struct mesh_proxy_filter f;
	uint16_t a[2] = { 0x0001, 0x0002 };

	/* NULL-safe entry points. */
	mesh_proxy_filter_init(NULL);			/* must not crash */
	ATF_CHECK_EQ(-1, mesh_proxy_filter_set_type(NULL,
	    MESH_PROXY_FILTER_ACCEPT));
	ATF_CHECK_EQ(-1, mesh_proxy_filter_add(NULL, a, 2));
	ATF_CHECK_EQ(-1, mesh_proxy_filter_remove(NULL, a, 2));
	ATF_CHECK_EQ_MSG(0, mesh_proxy_filter_accepts(NULL, 0x0001),
	    "NULL filter must accept nothing");

	mesh_proxy_filter_init(&f);
	/* set_type ACCEPT (the not-yet-exercised valid-type arm). */
	ATF_CHECK_EQ(0, mesh_proxy_filter_set_type(&f, MESH_PROXY_FILTER_ACCEPT));
	ATF_CHECK_EQ(f.type, MESH_PROXY_FILTER_ACCEPT);

	/* Non-zero count with a NULL address array is rejected. */
	ATF_CHECK_EQ(-1, mesh_proxy_filter_add(&f, NULL, 2));
	ATF_CHECK_EQ(-1, mesh_proxy_filter_remove(&f, NULL, 2));

	/* An empty add/remove (n == 0) is a legal no-op. */
	ATF_CHECK_EQ(0, mesh_proxy_filter_add(&f, NULL, 0));
	ATF_CHECK_EQ(0, mesh_proxy_filter_remove(&f, NULL, 0));

	/* Removing an address that is not on the list is a no-op success. */
	ATF_REQUIRE_EQ(0, mesh_proxy_filter_add(&f, a, 1));	/* only 0x0001 */
	ATF_CHECK_EQ(0, mesh_proxy_filter_remove(&f, &a[1], 1));	/* 0x0002 absent */
	ATF_CHECK_EQ(f.count, 1);
}

/* ================================================================
 * Empty-Data-field arms of the reassembler: an empty Data field is
 * structurally permitted in each SAR position, so the "datalen != 0"
 * copy guards and the "r->len != 0" completion guard must all be exercised.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_reasm_empty_data_arms);
ATF_TC_BODY(proxy_reasm_empty_data_arms, tc)
{
	struct mesh_proxy_reasm r;
	uint8_t cpl0[1];	/* complete | Config, no Data */
	uint8_t first0[1];	/* first | Config, no Data */
	uint8_t last0[1];	/* last | Config, no Data */
	uint8_t first2[3];	/* first | Config, 2 Data */
	uint8_t cont0[1];	/* continuation | Config, no Data */
	uint8_t last2[3];	/* last | Config, 2 Data */
	int c;
	uint8_t ty, m[MESH_PROXY_MAX_MSG];
	size_t ml;

	cpl0[0] = (uint8_t)((MESH_PROXY_SAR_COMPLETE << 6) |
	    MESH_PROXY_TYPE_CONFIG);
	first0[0] = (uint8_t)((MESH_PROXY_SAR_FIRST << 6) |
	    MESH_PROXY_TYPE_CONFIG);
	last0[0] = (uint8_t)((MESH_PROXY_SAR_LAST << 6) | MESH_PROXY_TYPE_CONFIG);
	first2[0] = first0[0]; first2[1] = 0xaa; first2[2] = 0xbb;
	cont0[0] = (uint8_t)((MESH_PROXY_SAR_CONTINUATION << 6) |
	    MESH_PROXY_TYPE_CONFIG);
	last2[0] = last0[0]; last2[1] = 0xcc; last2[2] = 0xdd;

	/* A complete message with an empty Data field. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, cpl0, sizeof(cpl0), &c, &ty,
	    m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 1);
	ATF_CHECK_EQ(ml, 0);

	/* first(empty) + last(empty): the message reassembles to length 0. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first0, sizeof(first0), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 0);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, last0, sizeof(last0), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 1);
	ATF_CHECK_EQ(ml, 0);

	/* first(data) + continuation(empty) + last(data): the empty middle
	 * segment is legal and contributes nothing. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first2, sizeof(first2), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, cont0, sizeof(cont0), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 0);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, last2, sizeof(last2), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 1);
	ATF_CHECK_EQ(ml, 4);
	ATF_CHECK_EQ(m[0], 0xaa);
	ATF_CHECK_EQ(m[3], 0xdd);

	/* first(data) + last(empty): the last segment contributes no octets. */
	mesh_proxy_reasm_init(&r);
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, first2, sizeof(first2), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_REQUIRE_EQ(0, mesh_proxy_reasm_feed(&r, last0, sizeof(last0), &c,
	    &ty, m, sizeof(m), &ml));
	ATF_CHECK_EQ(c, 1);
	ATF_CHECK_EQ(ml, 2);
}

/* ================================================================
 * Config-message build/parse argument guards and boundary arms.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_cfg_build_guards);
ATF_TC_BODY(proxy_cfg_build_guards, tc)
{
	uint16_t addrs[3] = { 0x0001, 0x0002, 0x0003 };
	uint8_t out[16];
	size_t outlen;

	/* Set Filter Type: NULL outputs, valid ACCEPT type, tiny buffer. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_set_filter_build(MESH_PROXY_FILTER_ACCEPT,
	    NULL, sizeof(out), &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_set_filter_build(MESH_PROXY_FILTER_ACCEPT,
	    out, sizeof(out), NULL));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_set_filter_build(MESH_PROXY_FILTER_ACCEPT,
	    out, 1, &outlen));				/* outcap < 2 */

	/* Add/Remove: NULL outputs, NULL addrs with n != 0, bad opcode,
	 * output buffer too small. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    addrs, 3, NULL, sizeof(out), &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    addrs, 3, out, sizeof(out), NULL));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    NULL, 3, out, sizeof(out), &outlen));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_FILTER_STATUS,
	    addrs, 3, out, sizeof(out), &outlen), "addr_build took a bad opcode");
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_addr_build(MESH_PROXY_OP_ADD_ADDR,
	    addrs, 3, out, 5, &outlen), "addr_build ignored a small out buffer");

	/* Filter Status: NULL outputs, valid ACCEPT type, prohibited type,
	 * tiny buffer. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_ACCEPT, 0, NULL, sizeof(out), &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_ACCEPT, 0, out, sizeof(out), NULL));
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_ACCEPT, 0x0203, out, sizeof(out), &outlen));
	ATF_CHECK_EQ(out[1], MESH_PROXY_FILTER_ACCEPT);
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_filter_status_build(0x02, 0, out,
	    sizeof(out), &outlen));			/* prohibited type */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_filter_status_build(
	    MESH_PROXY_FILTER_ACCEPT, 0, out, 3, &outlen));	/* outcap < 4 */
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_parse_guards);
ATF_TC_BODY(proxy_cfg_parse_guards, tc)
{
	struct mesh_proxy_cfg cfg;
	uint8_t buf[8];

	buf[0] = MESH_PROXY_OP_SET_FILTER_TYPE;
	buf[1] = MESH_PROXY_FILTER_REJECT;

	/* NULL input / output. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(NULL, 2, &cfg));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 2, NULL));

	/* Set Filter Type with the REJECT value (the not-yet-parsed arm). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(buf, 2, &cfg));
	ATF_CHECK_EQ(cfg.opcode, MESH_PROXY_OP_SET_FILTER_TYPE);
	ATF_CHECK_EQ(cfg.filter_type, MESH_PROXY_FILTER_REJECT);

	/* Filter Status with the ACCEPT value, then a prohibited value. */
	buf[0] = MESH_PROXY_OP_FILTER_STATUS;
	buf[1] = MESH_PROXY_FILTER_ACCEPT;
	buf[2] = 0x00;
	buf[3] = 0x05;
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_parse(buf, 4, &cfg));
	ATF_CHECK_EQ(cfg.filter_type, MESH_PROXY_FILTER_ACCEPT);
	ATF_CHECK_EQ(cfg.list_size, 0x0005);
	buf[1] = 0x02;					/* prohibited FilterType */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_parse(buf, 4, &cfg));
}

/* ================================================================
 * Secured proxy configuration PDU: argument guards, parameter bounds, and
 * the CTL/DST enforcement and length arms of the decrypt path.  Oracle: a
 * proxy configuration message is a Network PDU with CTL=1, TTL=0 and
 * DST=0x0000 (Section 6.6), and the transport PDU is at most 12 octets.
 * ================================================================ */

/*
 * Hand-build a secured proxy configuration Network PDU with a CHOSEN DST,
 * replicating mesh_proxy_cfg_encrypt (Section 3.4.5 + proxy nonce 3.9.5.4):
 * CCM over DST||TransportPDU with a 64-bit NetMIC, then PECB obfuscation of
 * the six header octets.  Used to reach arms unreachable via the public
 * encrypt (which always forces DST=0x0000).
 */
static void
proxy_secure_with_dst(const uint8_t enckey[16], const uint8_t privkey[16],
    uint8_t nid, uint32_t iv_index, uint32_t seq, uint16_t src, uint16_t dst,
    const uint8_t *msg, size_t msglen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[13];
	uint8_t plain[2 + 12];
	uint8_t pplain[16], pecb[16];
	size_t plen, i;
	uint8_t ivi = (uint8_t)(iv_index & 0x01);

	plain[0] = (uint8_t)(dst >> 8);
	plain[1] = (uint8_t)dst;
	memcpy(plain + 2, msg, msglen);
	plen = 2 + msglen;

	out[0] = (uint8_t)((ivi & 0x01) << 7) | (uint8_t)(nid & 0x7f);
	out[1] = 0x80;					/* CTL=1, TTL=0 */
	out[2] = (uint8_t)(seq >> 16);
	out[3] = (uint8_t)(seq >> 8);
	out[4] = (uint8_t)seq;
	out[5] = (uint8_t)(src >> 8);
	out[6] = (uint8_t)src;

	mesh_proxy_nonce(nonce, seq, src, iv_index);
	ATF_REQUIRE_EQ(0, mesh_aes_ccm_encrypt(enckey, nonce, NULL, 0, plain,
	    plen, out + 7, out + 7 + plen, 8));

	memset(pplain, 0, 5);
	pplain[5] = (uint8_t)(iv_index >> 24);
	pplain[6] = (uint8_t)(iv_index >> 16);
	pplain[7] = (uint8_t)(iv_index >> 8);
	pplain[8] = (uint8_t)iv_index;
	memcpy(pplain + 9, out + 7, 7);
	ATF_REQUIRE_EQ(0, mesh_aes128_e(privkey, pplain, pecb));
	for (i = 0; i < 6; i++)
		out[1 + i] ^= pecb[i];
	*outlen = 7 + plen + 8;
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_encrypt_guards);
ATF_TC_BODY(proxy_cfg_encrypt_guards, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	uint8_t msg[13] = { 0 };
	uint8_t out[MESH_PROXY_MAX_NETWORK_PDU];
	size_t outlen;

	/* NULL argument guards. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(NULL, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, NULL, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, NULL, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 2, NULL, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 2, out, NULL));

	/* NID, SEQ, and the primary-element unicast SRC are range checked. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, 0x80,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, 0x1000000u, CFG_SRC, msg, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, 0x0000, msg, 2, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, 0x8000, msg, 2, out, &outlen));

	/* Transport length 0 and > 12 are both rejected. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 0, out, &outlen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_encrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, CFG_SEQ, CFG_SRC, msg, 13, out, &outlen));
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_decrypt_guards);
ATF_TC_BODY(proxy_cfg_decrypt_guards, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	HEX(good, CFG_PROXYMSG_HEX, 19);
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen;

	/* NULL argument guards. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(NULL, privkey, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, NULL, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, NULL, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, NULL, sizeof(msg),
	    &msglen));
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    NULL));

	/* NID out of the 7-bit range. */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, 0x80,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));

	/* Success with NULL seq/src out pointers (the optional-output arms). */
	ATF_REQUIRE_EQ(0, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));
	ATF_CHECK_EQ(msglen, 2);

	/* A wrong IV Index fails the MIC and runs the cleanup with NULL
	 * seq and src pointers (no store back to them). */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    0x12345679u, good, sizeof(good), NULL, NULL, msg, sizeof(msg),
	    &msglen));

	/* Recovered transport longer than the caller's msgcap is rejected
	 * (msgcap 1 < 2). */
	ATF_CHECK_EQ(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, good, sizeof(good), NULL, NULL, msg, 1, &msglen));
}

ATF_TC_WITHOUT_HEAD(proxy_cfg_decrypt_ctl_dst_len);
ATF_TC_BODY(proxy_cfg_decrypt_ctl_dst_len, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	HEX(good, CFG_PROXYMSG_HEX, 19);
	HEX(cfgmsg, "0000", 2);
	uint8_t crafted[19];
	uint8_t sane[MESH_PROXY_MAX_NETWORK_PDU];
	uint8_t big[19 + 12];
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen, sanelen;
	uint32_t seq;
	uint16_t src;

	/*
	 * Sanity: the hand crafter reproduces the module's own encrypt for the
	 * DST=0 Section 8.9.1 case, so its DST!=0 output is trustworthy.
	 */
	proxy_secure_with_dst(enckey, privkey, CFG_NID, CFG_IVINDEX, CFG_SEQ,
	    CFG_SRC, 0x0000, cfgmsg, sizeof(cfgmsg), sane, &sanelen);
	ATF_REQUIRE_EQ(sanelen, sizeof(good));
	ATF_REQUIRE_EQ_MSG(0, memcmp(sane, good, sizeof(good)),
	    "hand crafter must reproduce mesh_proxy_cfg_encrypt for DST=0");

	/* CTL=0 after deobfuscation (flip header bit 7) violates CTL=1. */
	memcpy(crafted, good, sizeof(crafted));
	crafted[1] ^= 0x80;
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, crafted, sizeof(crafted), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted a CTL=0 proxy configuration PDU");

	/* CTL=1 with a nonzero TTL is also prohibited for proxy config. */
	memcpy(crafted, good, sizeof(crafted));
	crafted[1] ^= 0x01;		/* deobfuscated CTL|TTL becomes 0x81 */
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, crafted, sizeof(crafted), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted a proxy configuration PDU with TTL != 0");

	/* SRC is the primary element address and therefore must be unicast. */
	proxy_secure_with_dst(enckey, privkey, CFG_NID, CFG_IVINDEX, CFG_SEQ,
	    0x0000, 0x0000, cfgmsg, sizeof(cfgmsg), sane, &sanelen);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, sane, sanelen, &seq, &src, msg, sizeof(msg), &msglen),
	    "decrypt accepted an unassigned proxy configuration SRC");
	proxy_secure_with_dst(enckey, privkey, CFG_NID, CFG_IVINDEX, CFG_SEQ,
	    0x8000, 0x0000, cfgmsg, sizeof(cfgmsg), sane, &sanelen);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, sane, sanelen, &seq, &src, msg, sizeof(msg), &msglen),
	    "decrypt accepted a group proxy configuration SRC");

	/* A validly secured PDU whose DST != 0x0000 is rejected. */
	proxy_secure_with_dst(enckey, privkey, CFG_NID, CFG_IVINDEX, CFG_SEQ,
	    CFG_SRC, 0x0001, cfgmsg, sizeof(cfgmsg), sane, &sanelen);
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, sane, sanelen, &seq, &src, msg, sizeof(msg), &msglen),
	    "decrypt accepted a proxy configuration PDU with DST != 0");

	/*
	 * A transport PDU longer than 12 octets is rejected before the MIC
	 * check.  Appending octets grows clen/tlen but leaves the header and
	 * the 7-octet Privacy Random untouched, so CTL stays 1 and the tlen
	 * bound arm fires (tlen = 14 > 12).
	 */
	memset(big, 0, sizeof(big));
	memcpy(big, good, sizeof(good));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, big, sizeof(big), &seq, &src, msg, sizeof(msg),
	    &msglen), "decrypt accepted an oversized transport PDU");
}

/* ================================================================
 * Empty-PDU guard: mesh_proxy_cfg_decrypt with inlen == 0 must reject
 * cleanly without reading in[0] (the NID-gate octet).  The input points at a
 * 1-octet buffer; the contract is a guarded error return with msglen 0 and
 * no seq/src stored.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(proxy_cfg_decrypt_empty);
ATF_TC_BODY(proxy_cfg_decrypt_empty, tc)
{
	HEX(enckey, CFG_ENCKEY_HEX, 16);
	HEX(privkey, CFG_PRIVKEY_HEX, 16);
	uint8_t in[1] = { CFG_NID };
	uint8_t msg[MESH_PROXY_MAX_MSG];
	size_t msglen = 12345;
	uint32_t seq = 0xdead;
	uint16_t src = 0xbeef;

	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey, CFG_NID,
	    CFG_IVINDEX, in, 0, &seq, &src, msg, sizeof(msg), &msglen),
	    "an empty (inlen==0) proxy config PDU must be rejected");
	ATF_CHECK_EQ_MSG(msglen, 0, "empty-PDU reject must leave msglen 0");
	ATF_CHECK_EQ_MSG(seq, 0, "empty-PDU reject must leave seq 0");
	ATF_CHECK_EQ_MSG(src, 0, "empty-PDU reject must leave src 0");
}

/* ================================================================
 * Proxy connectable advertising (Section 7.2.2.2).
 * ================================================================ */

/*
 * Network ID advertising: the carried Network ID must equal k3(NetKey).  The
 * NetKey 7dd7364c... / NetworkID 3ecaff672f673370 is the published k3 worked
 * example (also used in mesh_beacon_test / MshPRT_v1.1 Section 8).
 */
ATF_TC_WITHOUT_HEAD(proxy_adv_network_id);
ATF_TC_BODY(proxy_adv_network_id, tc)
{
	HEX(netkey, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	HEX(netid, "3ecaff672f673370", 8);
	uint8_t adv[MESH_PROXY_ADV_NETWORK_ID_LEN];
	size_t advlen;

	ATF_REQUIRE_EQ(0, mesh_proxy_adv_network_id_build(netkey, adv, &advlen));
	ATF_CHECK_EQ(MESH_PROXY_ADV_NETWORK_ID_LEN, advlen);
	/* AD structure: length, Service Data-16 type, UUID (LE), id type. */
	ATF_CHECK_EQ(MESH_PROXY_ADV_NETWORK_ID_LEN - 1, adv[0]);
	ATF_CHECK_EQ(MESH_AD_TYPE_SERVICE_DATA_16, adv[1]);
	ATF_CHECK_EQ((uint8_t)(MESH_PROXY_SERVICE_UUID & 0xff), adv[2]);
	ATF_CHECK_EQ((uint8_t)(MESH_PROXY_SERVICE_UUID >> 8), adv[3]);
	ATF_CHECK_EQ(MESH_PROXY_ADV_NETWORK_ID, adv[4]);
	ATF_CHECK_EQ_MSG(0, memcmp(adv + 5, netid, 8),
	    "Network ID adv must carry k3(NetKey)");
}

/*
 * Node Identity advertising: the embedded Hash must verify against the
 * IdentityKey/Address/Random derivation (Section 7.2.2.2.2), and depend on
 * the Random.
 */
ATF_TC_WITHOUT_HEAD(proxy_adv_node_identity);
ATF_TC_BODY(proxy_adv_node_identity, tc)
{
	HEX(netkey, "7dd7364cd842ad18c17c2b820c84c3d6", 16);
	HEX(random, "34ae608fbbc1f2c6", 8);
	HEX(random2, "34ae608fbbc1f2c7", 8);
	uint16_t addr = 0x1201;
	uint8_t idkey[16], hash[MESH_PROXY_ID_HASH_LEN];
	uint8_t adv[MESH_PROXY_ADV_NODE_IDENTITY_LEN];
	uint8_t adv2[MESH_PROXY_ADV_NODE_IDENTITY_LEN];
	size_t advlen;

	ATF_REQUIRE_EQ(0, mesh_proxy_identity_key(netkey, idkey));
	ATF_REQUIRE_EQ(0, mesh_proxy_identity_hash(idkey, addr, random, hash));

	ATF_REQUIRE_EQ(0, mesh_proxy_adv_node_identity_build(idkey, addr,
	    random, adv, &advlen));
	ATF_CHECK_EQ(MESH_PROXY_ADV_NODE_IDENTITY_LEN, advlen);
	ATF_CHECK_EQ(MESH_PROXY_ADV_NODE_IDENTITY, adv[4]);
	/* Embedded Hash matches the standalone derivation. */
	ATF_CHECK_EQ_MSG(0, memcmp(adv + 5, hash, MESH_PROXY_ID_HASH_LEN),
	    "Node Identity adv Hash must match the derivation");
	/* Random is carried after the Hash. */
	ATF_CHECK_EQ(0, memcmp(adv + 5 + MESH_PROXY_ID_HASH_LEN, random, 8));

	/* A different Random yields a different Hash. */
	ATF_REQUIRE_EQ(0, mesh_proxy_adv_node_identity_build(idkey, addr,
	    random2, adv2, &advlen));
	ATF_CHECK_MSG(memcmp(adv + 5, adv2 + 5, MESH_PROXY_ID_HASH_LEN) != 0,
	    "a different Random must change the Node Identity Hash");

	/* IdentityKey ("nkik") depends on the NetKey and is 16 octets. */
	{
		HEX(other, "00112233445566778899aabbccddeeff", 16);
		uint8_t idkey2[16];

		ATF_REQUIRE_EQ(0, mesh_proxy_identity_key(other, idkey2));
		ATF_CHECK(memcmp(idkey, idkey2, 16) != 0);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proxy_adv_network_id);
	ATF_TP_ADD_TC(tp, proxy_adv_node_identity);
	ATF_TP_ADD_TC(tp, proxy_pdu_build_parse);
	ATF_TP_ADD_TC(tp, proxy_pdu_config_header_kat);
	ATF_TP_ADD_TC(tp, proxy_pdu_negative);
	ATF_TP_ADD_TC(tp, proxy_sar_segment_reassemble);
	ATF_TP_ADD_TC(tp, proxy_sar_single_segment);
	ATF_TP_ADD_TC(tp, proxy_sar_illegal_sequences);
	ATF_TP_ADD_TC(tp, proxy_sar_oversized_network);
	ATF_TP_ADD_TC(tp, proxy_sar_message_type_limits);
	ATF_TP_ADD_TC(tp, proxy_cfg_set_filter_type);
	ATF_TP_ADD_TC(tp, proxy_cfg_add_remove);
	ATF_TP_ADD_TC(tp, proxy_cfg_filter_status);
	ATF_TP_ADD_TC(tp, proxy_cfg_parse_negative);
	ATF_TP_ADD_TC(tp, proxy_filter_predicate);
	ATF_TP_ADD_TC(tp, proxy_filter_bounded);
	ATF_TP_ADD_TC(tp, proxy_cfg_secure_kat);
	ATF_TP_ADD_TC(tp, proxy_cfg_secure_roundtrip);
	ATF_TP_ADD_TC(tp, proxy_cfg_secure_reject);
	ATF_TP_ADD_TC(tp, proxy_pdu_build_guards);
	ATF_TP_ADD_TC(tp, proxy_pdu_parse_guards);
	ATF_TP_ADD_TC(tp, proxy_segment_guards);
	ATF_TP_ADD_TC(tp, proxy_reasm_guards);
	ATF_TP_ADD_TC(tp, proxy_reasm_complete_arms);
	ATF_TP_ADD_TC(tp, proxy_reasm_segment_error_arms);
	ATF_TP_ADD_TC(tp, proxy_filter_guards);
	ATF_TP_ADD_TC(tp, proxy_reasm_empty_data_arms);
	ATF_TP_ADD_TC(tp, proxy_cfg_build_guards);
	ATF_TP_ADD_TC(tp, proxy_cfg_parse_guards);
	ATF_TP_ADD_TC(tp, proxy_cfg_encrypt_guards);
	ATF_TP_ADD_TC(tp, proxy_cfg_decrypt_guards);
	ATF_TP_ADD_TC(tp, proxy_cfg_decrypt_ctl_dst_len);
	ATF_TP_ADD_TC(tp, proxy_cfg_decrypt_empty);

	return (atf_no_error());
}
