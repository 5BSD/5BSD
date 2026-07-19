/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh network layer.
 *
 * Implements the network layer of the Bluetooth Mesh Protocol
 * specification (MshPRT_v1.1) Section 3.4 "Network layer", built on the
 * cryptographic toolbox in mesh_crypto.[ch] (Section 3.8).
 *
 * The module is pure and hardware-free: every function operates on
 * values in network (big-endian) byte order, performs no I/O, keeps no
 * global state, and clears intermediate secrets with explicit_bzero().
 * Each function returns 0 on success and -1 on failure; on failure the
 * output buffers/structures are left zeroed.  The pure predicates
 * (mesh_net_nid_match, mesh_net_relay, mesh_net_rpl_check) return their
 * result directly as documented.
 *
 * The network security material (NID, EncryptionKey, PrivacyKey) is
 * produced by mesh_k2() from a NetKey; the SEQ and IV Index are supplied
 * by the caller at the layer boundary (no persistence here).
 */

#ifndef _MESH_NET_H_
#define _MESH_NET_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Network PDU size limits.  MshPRT_v1.1 Section 3.4.4.
 *
 * The obfuscated/cleartext header is 9 octets:
 *   IVI/NID (1) | CTL/TTL (1) | SEQ (3) | SRC (2) | DST (2)
 * followed by the Transport PDU and a 32-bit (CTL=0) or 64-bit (CTL=1)
 * NetMIC.  A Network PDU carried on the advertising bearer is at most 29
 * octets, which bounds the Transport PDU at 16 octets (CTL=0, NetMIC 4)
 * or 12 octets (CTL=1, NetMIC 8).
 */
#define	MESH_NET_HDR_LEN		9
#define	MESH_NET_MAX_TRANSPORT_PDU	16	/* access (CTL=0), 32-bit NetMIC */
#define	MESH_NET_MAX_CONTROL_TRANSPORT_PDU 12	/* control (CTL=1), 64-bit NetMIC */
#define	MESH_NET_MAX_PDU		29

/* NetMIC sizes: 32-bit for access (CTL=0), 64-bit for control (CTL=1). */
#define	MESH_NET_NETMIC_ACCESS		4
#define	MESH_NET_NETMIC_CONTROL		8

/*
 * Parsed / cleartext Network PDU.  Section 3.4.4.
 * All fields are held in host order; the wire codecs handle the
 * big-endian packing of SEQ (24-bit), SRC and DST (16-bit).
 */
struct mesh_net_pdu {
	uint8_t		ivi;		/* IV Index LSB, 0 or 1 */
	uint8_t		nid;		/* 7-bit network identifier */
	uint8_t		ctl;		/* 0 = access, 1 = control */
	uint8_t		ttl;		/* 7-bit time to live */
	uint32_t	seq;		/* 24-bit sequence number */
	uint16_t	src;		/* unicast source address */
	uint16_t	dst;		/* destination address */
	uint8_t		transport[MESH_NET_MAX_TRANSPORT_PDU];
	size_t		transport_len;
};

/*
 * Cleartext Network PDU codec (no encryption, no obfuscation, no
 * NetMIC).  mesh_net_pdu_build() packs the fields into wire order
 * (IVI/NID | CTL/TTL | SEQ | SRC | DST | TransportPDU); mesh_net_pdu_parse()
 * is its exact inverse.  These exist for the field-layout round trip and
 * for callers that want the plaintext representation.
 */
int	mesh_net_pdu_build(const struct mesh_net_pdu *in, uint8_t *out,
	    size_t *outlen);
int	mesh_net_pdu_parse(const uint8_t *in, size_t inlen,
	    struct mesh_net_pdu *out);

/*
 * Network encryption + obfuscation.  Section 3.4.5.
 *
 * mesh_net_encrypt() takes a cleartext PDU plus the network security
 * material and produces the fully secured Network PDU on the wire:
 *   - the network nonce is built from CTL/TTL/SEQ/SRC/IV Index;
 *   - DST||TransportPDU is AES-CCM encrypted under EncryptionKey to
 *     EncDST||EncTransportPDU plus a 4- or 8-octet NetMIC (per CTL);
 *   - the 6-octet header (CTL/TTL/SEQ/SRC) is obfuscated with the
 *     Privacy Key using the PECB construction of Section 3.4.5.2.
 * The IVI/NID octet is written from (iv_index & 1) and nid.
 *
 * mesh_net_decrypt() is the exact inverse: it checks the NID, deobfuscates
 * the header, decrypts and verifies the NetMIC, and fills *out.  It
 * returns -1 on a NID mismatch, a truncated PDU, or a NetMIC failure.
 */
int	mesh_net_encrypt(const uint8_t enckey[16], const uint8_t privkey[16],
	    uint8_t nid, uint32_t iv_index, const struct mesh_net_pdu *in,
	    uint8_t *out, size_t *outlen);
int	mesh_net_decrypt(const uint8_t enckey[16], const uint8_t privkey[16],
	    uint8_t nid, uint32_t iv_index, const uint8_t *in, size_t inlen,
	    struct mesh_net_pdu *out);

/*
 * NID match on receive.  Section 3.4.6.3.  A received PDU's NID (the low
 * 7 bits of octet 0) may match more than one network key, so reception
 * tries each candidate key.  Returns 1 on a match, 0 otherwise.  Never
 * fails.
 */
int	mesh_net_nid_match(uint8_t local_nid, uint8_t pdu_octet0);

/*
 * Relay decision predicate.  Section 3.4.6.3.  A PDU is relayable only if
 * its TTL is >= 2, in which case it is retransmitted with TTL - 1.
 * Returns 1 and (if new_ttl != NULL) writes the decremented TTL when the
 * PDU is relayable; returns 0 otherwise.  This is the pure predicate; the
 * full relay feature (network interface selection, cache) is Phase 8.
 *
 * Directed forwarding hook: this predicate is the managed-flooding relay
 * decision point.  A DF-capable node routes a received PDU through
 * mesh_df_forward_decide() (mesh_df.[ch], MshPRT_v1.1 Section 3.6.6), which
 * consults the Forwarding Table for a directed path and otherwise falls back
 * to this predicate for the managed-flooding path.  The directed forwarding
 * engine layers above the network layer and calls mesh_net_relay() directly;
 * the network layer keeps no dependency on it.
 */
int	mesh_net_relay(uint8_t ttl, uint8_t *new_ttl);

/*
 * Minimal network message cache / replay-protection primitive.
 *
 * This is a small, testable building block, NOT the full replay
 * protection list: the complete RPL (with IV Index handling and
 * persistence) is Phase 6.  Each slot records the highest SEQ seen from a
 * SRC.  mesh_net_rpl_check() returns 1 and updates the table when (src,seq)
 * is new (SRC unseen, or seq strictly greater than the stored value),
 * i.e. the PDU should be accepted; it returns 0 without modifying the
 * table when (src,seq) is a replay (seq <= stored).  If the table is full
 * and the SRC is unknown it returns -1 (cannot record).
 */
struct mesh_net_rpl {
	uint16_t	src;
	uint32_t	seq;
	int		valid;
};
int	mesh_net_rpl_check(struct mesh_net_rpl *tbl, size_t n, uint16_t src,
	    uint32_t seq);

#endif /* _MESH_NET_H_ */
