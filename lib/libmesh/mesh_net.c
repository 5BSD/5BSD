/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh network layer (MshPRT_v1.1 Section 3.4), built on the
 * mesh_crypto.[ch] security toolbox (Section 3.8).
 *
 * The Network PDU wire format (Section 3.4.4) is:
 *
 *   octet 0     IVI (1 bit) | NID (7 bits)              -- cleartext
 *   octets 1-6  CTL (1) | TTL (7) | SEQ (24) | SRC (16) -- obfuscated
 *   octets 7..  EncDST (16) | EncTransportPDU | NetMIC  -- encrypted
 *
 * Encryption (Section 3.4.5.1) runs AES-CCM over DST||TransportPDU with
 * the network nonce to yield EncDST||EncTransportPDU and a NetMIC that is
 * 32 bits for an access message (CTL=0) or 64 bits for a control message
 * (CTL=1).  Obfuscation (Section 3.4.5.2) hides the header:
 *
 *   Privacy Random = (EncDST || EncTransportPDU || NetMIC)[0..6]  (7 octets)
 *   PECB           = e(PrivacyKey, 0x0000000000 || IVindex || Privacy Random)
 *   ObfuscatedData = (CTL/TTL/SEQ/SRC) XOR PECB[0..5]
 *
 * Deobfuscation is the same XOR (PECB depends only on the encrypted
 * payload, which survives obfuscation), so a receiver recovers the header
 * before decrypting.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_net.h"
#include "mesh_probes.h"

/*
 * Compute the Privacy ECB block used to obfuscate/deobfuscate the header.
 * MshPRT_v1.1 Section 3.4.5.2.  enc_payload must point at the first 7
 * octets of EncDST||EncTransportPDU||NetMIC (the Privacy Random).
 */
static int
mesh_net_pecb(const uint8_t privkey[16], uint32_t iv_index,
    const uint8_t enc_payload[7], uint8_t pecb[16])
{
	uint8_t pplain[16];
	int rc;

	memset(pplain, 0, 5);			/* 0x0000000000 pad */
	pplain[5] = (uint8_t)(iv_index >> 24);
	pplain[6] = (uint8_t)(iv_index >> 16);
	pplain[7] = (uint8_t)(iv_index >> 8);
	pplain[8] = (uint8_t)iv_index;
	memcpy(pplain + 9, enc_payload, 7);	/* Privacy Random */

	rc = mesh_aes128_e(privkey, pplain, pecb);
	explicit_bzero(pplain, sizeof(pplain));
	if (rc != 0)
		memset(pecb, 0, 16);
	return (rc);
}

/*
 * XOR the 6-octet obfuscated header region in place with PECB[0..5].
 * The transform is its own inverse, so this serves both obfuscation
 * (plaintext header -> wire) and deobfuscation (wire -> plaintext header).
 */
static void
mesh_net_xor_header(uint8_t hdr[6], const uint8_t pecb[16])
{
	size_t i;

	for (i = 0; i < 6; i++)
		hdr[i] ^= pecb[i];
}

/*
 * Validate the caller-supplied field ranges shared by build and encrypt.
 */
static int
mesh_net_valid(const struct mesh_net_pdu *p)
{
	size_t maxtransport, miclen;

	if (p == NULL)
		return (-1);
	if (p->ivi > 1 || p->nid > 0x7f || p->ctl > 1 || p->ttl > 0x7f)
		return (-1);
	if (p->seq > 0xffffff)
		return (-1);
	/*
	 * The Source Address field shall be a unicast address (MshPRT_v1.1
	 * Section 3.4.3): a group, virtual or unassigned address as SRC is
	 * malformed and the PDU must not be built or transmitted.
	 */
	if (p->src < 0x0001 || p->src > 0x7fff)
		return (-1);
	/* Unassigned is never a valid Network Destination Address. */
	if (p->dst == 0x0000)
		return (-1);
	/*
	 * The NetMIC is 8 octets for a control message (CTL=1) and 4 for an
	 * access message (CTL=0); MshPRT_v1.1 Section 3.4.4.  The complete
	 * Network PDU is IVI/NID (1) + obfuscated header (6) + EncDST (2) +
	 * EncTransportPDU + NetMIC and must fit in MESH_NET_MAX_PDU (29)
	 * octets, which bounds the Transport PDU at 12 octets for a control
	 * message and 16 for an access message.  Capping at
	 * MESH_NET_MAX_TRANSPORT_PDU (16) regardless of CTL would let a control
	 * PDU overflow the fixed-size mesh_net_encrypt output buffer, so the
	 * bound must depend on CTL and the total length is re-checked below.
	 */
	miclen = p->ctl ? MESH_NET_NETMIC_CONTROL : MESH_NET_NETMIC_ACCESS;
	maxtransport = p->ctl ? MESH_NET_MAX_CONTROL_TRANSPORT_PDU :
	    MESH_NET_MAX_TRANSPORT_PDU;
	if (p->transport_len == 0 || p->transport_len > maxtransport)
		return (-1);
	if (7 + 2 + p->transport_len + miclen > MESH_NET_MAX_PDU)
		return (-1);
	return (0);
}

/*
 * Pack the cleartext header (octets 0..8) into out.  Shared by
 * mesh_net_pdu_build() and mesh_net_encrypt().
 */
static void
mesh_net_pack_hdr(const struct mesh_net_pdu *p, uint8_t nid, uint8_t ivi,
    uint8_t out[MESH_NET_HDR_LEN])
{

	out[0] = (uint8_t)((ivi & 0x01) << 7) | (uint8_t)(nid & 0x7f);
	out[1] = (uint8_t)((p->ctl & 0x01) << 7) | (uint8_t)(p->ttl & 0x7f);
	out[2] = (uint8_t)(p->seq >> 16);
	out[3] = (uint8_t)(p->seq >> 8);
	out[4] = (uint8_t)p->seq;
	out[5] = (uint8_t)(p->src >> 8);
	out[6] = (uint8_t)p->src;
	out[7] = (uint8_t)(p->dst >> 8);
	out[8] = (uint8_t)p->dst;
}

/*
 * Cleartext Network PDU codec.  MshPRT_v1.1 Section 3.4.4.
 */
int
mesh_net_pdu_build(const struct mesh_net_pdu *in, uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL || mesh_net_valid(in) != 0)
		return (-1);

	mesh_net_pack_hdr(in, in->nid, in->ivi, out);
	memcpy(out + MESH_NET_HDR_LEN, in->transport, in->transport_len);
	*outlen = MESH_NET_HDR_LEN + in->transport_len;
	return (0);
}

int
mesh_net_pdu_parse(const uint8_t *in, size_t inlen, struct mesh_net_pdu *out)
{
	size_t tlen;

	if (in == NULL || out == NULL)
		return (-1);
	if (inlen <= MESH_NET_HDR_LEN ||
	    inlen - MESH_NET_HDR_LEN > MESH_NET_MAX_TRANSPORT_PDU) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}

	memset(out, 0, sizeof(*out));
	out->ivi = (uint8_t)(in[0] >> 7);
	out->nid = (uint8_t)(in[0] & 0x7f);
	out->ctl = (uint8_t)(in[1] >> 7);
	out->ttl = (uint8_t)(in[1] & 0x7f);
	out->seq = ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 8) |
	    (uint32_t)in[4];
	out->src = (uint16_t)((in[5] << 8) | in[6]);
	out->dst = (uint16_t)((in[7] << 8) | in[8]);
	tlen = inlen - MESH_NET_HDR_LEN;
	memcpy(out->transport, in + MESH_NET_HDR_LEN, tlen);
	out->transport_len = tlen;
	/* Apply the same semantic and CTL-dependent bounds as build/encrypt. */
	if (mesh_net_valid(out) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/*
 * Network encryption + obfuscation.  MshPRT_v1.1 Section 3.4.5.
 */
int
mesh_net_encrypt(const uint8_t enckey[16], const uint8_t privkey[16],
    uint8_t nid, uint32_t iv_index, const struct mesh_net_pdu *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t nonce[13];
	uint8_t plain[2 + MESH_NET_MAX_TRANSPORT_PDU];
	uint8_t pecb[16];
	size_t plen, clen, miclen;
	uint8_t ivi;
	int rc = -1;

	if (enckey == NULL || privkey == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (nid > 0x7f || mesh_net_valid(in) != 0)
		return (-1);

	miclen = in->ctl ? MESH_NET_NETMIC_CONTROL : MESH_NET_NETMIC_ACCESS;
	ivi = (uint8_t)(iv_index & 0x01);

	/* Cleartext CCM input: DST (big-endian) || TransportPDU. */
	plain[0] = (uint8_t)(in->dst >> 8);
	plain[1] = (uint8_t)in->dst;
	memcpy(plain + 2, in->transport, in->transport_len);
	plen = 2 + in->transport_len;
	clen = plen;			/* CCM ciphertext matches plaintext */

	/* Header octet 0 (cleartext) and octets 1..8 packed for reference. */
	mesh_net_pack_hdr(in, nid, ivi, out);

	mesh_network_nonce(nonce, in->ctl, in->ttl, in->seq, in->src, iv_index);

	/*
	 * Encrypt DST||TransportPDU into out[7..], NetMIC directly after.
	 * out[7] onward overwrites the packed EncDST/EncTransportPDU region.
	 */
	if (mesh_aes_ccm_encrypt(enckey, nonce, NULL, 0, plain, plen,
	    out + 7, out + 7 + clen, miclen) != 0)
		goto out;

	/* Obfuscate header octets 1..6 with the Privacy Key. */
	if (mesh_net_pecb(privkey, iv_index, out + 7, pecb) != 0)
		goto out;
	mesh_net_xor_header(out + 1, pecb);

	*outlen = 7 + clen + miclen;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	explicit_bzero(plain, sizeof(plain));
	explicit_bzero(pecb, sizeof(pecb));
	if (rc != 0) {
		memset(out, 0, MESH_NET_MAX_PDU);
		*outlen = 0;
	}
	/* Network-layer encrypt boundary: src/dst/seq/ttl only, never keys. */
	MESH_PROBE_NET_ENCRYPT(in->src, in->dst, in->seq, in->ttl);
	return (rc);
}

int
mesh_net_decrypt(const uint8_t enckey[16], const uint8_t privkey[16],
    uint8_t nid, uint32_t iv_index, const uint8_t *in, size_t inlen,
    struct mesh_net_pdu *out)
{
	uint8_t nonce[13];
	uint8_t hdr[6];
	uint8_t pecb[16];
	uint8_t plain[2 + MESH_NET_MAX_TRANSPORT_PDU];
	size_t miclen, clen, tlen;
	uint8_t ctl, ttl;
	uint32_t seq;
	uint16_t src, dst;
	int rc = -1;

	if (enckey == NULL || privkey == NULL || in == NULL || out == NULL)
		return (-1);
	if (nid > 0x7f)
		return (-1);
	memset(out, 0, sizeof(*out));

	/*
	 * Guard the in[0] (IVI|NID gate) read below: an empty PDU has no
	 * octet 0 to inspect.  (The full minimum-length check follows once the
	 * NID has matched.)
	 */
	if (inlen == 0)
		return (-1);

	/*
	 * Reject the PDU up front unless the received NID matches this
	 * network key.  The same NID may match several keys; the caller
	 * iterates over candidates using mesh_net_nid_match().
	 */
	if (!mesh_net_nid_match(nid, in[0])) {
		MESH_PROBE_NET_NID_MATCH(nid, in[0] & 0x7f, 0);
		return (-1);
	}
	MESH_PROBE_NET_NID_MATCH(nid, in[0] & 0x7f, 1);

	/*
	 * Minimum PDU: IVI/NID (1) + header (6) + EncDST (2) + at least one
	 * octet of EncTransportPDU + smallest NetMIC (4).  The 7-octet
	 * Privacy Random also requires 7 octets from in[7], which the
	 * minimum-length control PDU always satisfies.
	 */
	if (inlen < 1 + 6 + 2 + 1 + MESH_NET_NETMIC_ACCESS)
		return (-1);

	/* Deobfuscate the header using the encrypted payload at in[7..]. */
	if (mesh_net_pecb(privkey, iv_index, in + 7, pecb) != 0)
		goto out;
	memcpy(hdr, in + 1, 6);
	mesh_net_xor_header(hdr, pecb);

	ctl = (uint8_t)(hdr[0] >> 7);
	ttl = (uint8_t)(hdr[0] & 0x7f);
	seq = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) |
	    (uint32_t)hdr[3];
	src = (uint16_t)((hdr[4] << 8) | hdr[5]);

	miclen = ctl ? MESH_NET_NETMIC_CONTROL : MESH_NET_NETMIC_ACCESS;

	/* Encrypted region = EncDST||EncTransportPDU (>= 2, includes DST). */
	if (inlen < 1 + 6 + miclen + 2)
		goto out;
	clen = inlen - 7 - miclen;
	tlen = clen - 2;
	if (tlen == 0 || tlen > MESH_NET_MAX_TRANSPORT_PDU)
		goto out;

	mesh_network_nonce(nonce, ctl, ttl, seq, src, iv_index);

	if (mesh_aes_ccm_decrypt(enckey, nonce, NULL, 0, in + 7, clen,
	    plain, in + 7 + clen, miclen) != 0)
		goto out;

	dst = (uint16_t)((plain[0] << 8) | plain[1]);
	/*
	 * Network authentication proves only that the sender knows the NetKey;
	 * it does not make reserved address values valid.  A Network PDU source
	 * shall be unicast and the destination shall not be Unassigned.  Reject
	 * malformed authenticated PDUs before they can enter the RPL, message
	 * cache, Friend queue, proxy filter, or relay path.
	 */
	if (src < 0x0001 || src > 0x7fff || dst == 0x0000)
		goto out;

	out->ivi = (uint8_t)(in[0] >> 7);
	out->nid = (uint8_t)(in[0] & 0x7f);
	out->ctl = ctl;
	out->ttl = ttl;
	out->seq = seq;
	out->src = src;
	out->dst = dst;
	memcpy(out->transport, plain + 2, tlen);
	out->transport_len = tlen;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	explicit_bzero(hdr, sizeof(hdr));
	explicit_bzero(pecb, sizeof(pecb));
	explicit_bzero(plain, sizeof(plain));
	if (rc != 0)
		memset(out, 0, sizeof(*out));
	/*
	 * Network-layer decrypt verdict: nid, src (0 if auth failed before the
	 * header was recovered) and result (0 == accepted, -1 == MIC/parse
	 * failure).  No key material or transport payload is emitted.
	 */
	MESH_PROBE_NET_DECRYPT(nid, rc == 0 ? out->src : 0, rc);
	return (rc);
}

/*
 * NID match on receive.  MshPRT_v1.1 Section 3.4.6.3.
 */
int
mesh_net_nid_match(uint8_t local_nid, uint8_t pdu_octet0)
{

	return ((pdu_octet0 & 0x7f) == (local_nid & 0x7f));
}

/*
 * Relay decision predicate.  MshPRT_v1.1 Section 3.4.6.3.
 */
int
mesh_net_relay(uint8_t ttl, uint8_t *new_ttl)
{

	if (ttl < 2 || ttl > 0x7f) {
		/* TTL 0/1 and reserved non-7-bit values are not relayed. */
		MESH_PROBE_NET_RELAY(0, ttl, ttl, 0);
		return (0);
	}
	if (new_ttl != NULL)
		*new_ttl = (uint8_t)(ttl - 1);
	MESH_PROBE_NET_RELAY(0, ttl, (uint8_t)(ttl - 1), 1);
	return (1);
}

/*
 * Minimal replay-protection primitive (Phase 6 provides the full RPL).
 */
int
mesh_net_rpl_check(struct mesh_net_rpl *tbl, size_t n, uint16_t src,
    uint32_t seq)
{
	size_t i, free_slot = n;

	if (tbl == NULL)
		return (-1);

	for (i = 0; i < n; i++) {
		if (!tbl[i].valid) {
			if (free_slot == n)
				free_slot = i;
			continue;
		}
		if (tbl[i].src == src) {
			if (seq <= tbl[i].seq)
				return (0);	/* replay */
			tbl[i].seq = seq;
			return (1);		/* new, table updated */
		}
	}

	if (free_slot == n)
		return (-1);			/* table full, SRC unknown */
	tbl[free_slot].src = src;
	tbl[free_slot].seq = seq;
	tbl[free_slot].valid = 1;
	return (1);
}
