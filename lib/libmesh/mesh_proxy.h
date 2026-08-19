/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Proxy protocol (the GATT bearer).
 *
 * Implements the Proxy protocol of the Bluetooth Mesh Protocol
 * specification (MshPRT_v1.1) Section 6, which lets a phone or other
 * legacy-GATT device talk to a mesh network over a GATT connection:
 *
 *   - the Proxy PDU and its SAR segmentation/reassembly (Section 6.3),
 *   - the proxy filter accept/reject-list state machine (Sections 6.4,
 *     6.7),
 *   - the proxy configuration messages (Section 6.6): Set Filter Type,
 *     Add/Remove Addresses To/From Filter, Filter Status, both as the
 *     plaintext opcode/parameter codec and as the fully secured Network
 *     PDU (CTL=1, TTL=0, DST=unassigned) carried in a Proxy
 *     Configuration Proxy PDU and secured with the managed-flooding
 *     credentials under the proxy nonce (Section 3.9.5.4),
 *   - the Mesh Proxy Service GATT identifiers (Section 7.2.3).
 *
 * The module is pure and hardware-free: every function operates on
 * values in network (big-endian) byte order, performs no I/O, keeps no
 * global state, and clears intermediate secrets with explicit_bzero().
 * Each codec/crypto function returns 0 on success and -1 on failure; on
 * failure the output buffers/structures are left zeroed.  The pure
 * predicates return their result directly as documented.
 *
 * The module is used by meshd's ATT Mesh Proxy client; it remains independent
 * of ATT I/O so the protocol state and cryptography are testable in isolation.
 */

#ifndef _MESH_PROXY_H_
#define _MESH_PROXY_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Mesh Proxy Service GATT identifiers.  MshPRT_v1.1 Section 7.2 and the
 * Assigned Numbers document.  Data In is written by the client with a
 * GATT Write Without Response; Data Out is sent by the server with a GATT
 * Notification.
 */
#define	MESH_PROXY_SERVICE_UUID		0x1828	/* Mesh Proxy Service */
#define	MESH_PROXY_DATA_IN_UUID		0x2ADD	/* Mesh Proxy Data In  (WWR) */
#define	MESH_PROXY_DATA_OUT_UUID	0x2ADE	/* Mesh Proxy Data Out (Notify) */

/* ================================================================
 * Proxy connectable advertising (Section 7.2.2.2).  The Mesh Proxy Service is
 * advertised in a Service Data - 16-bit UUID AD structure whose Identification
 * Type selects between the Network ID and Node Identity forms.
 * ================================================================ */
#define	MESH_AD_TYPE_SERVICE_DATA_16	0x16	/* Service Data - 16-bit UUID */
#define	MESH_PROXY_ADV_NETWORK_ID	0x00	/* Identification Type */
#define	MESH_PROXY_ADV_NODE_IDENTITY	0x01
#define	MESH_PROXY_ADV_PRIVATE_NETWORK_ID	0x02	/* Section 7.2.2.2.4 */
#define	MESH_PROXY_ADV_PRIVATE_NODE_IDENTITY	0x03	/* Section 7.2.2.2.5 */

#define	MESH_NETWORK_ID_ADV_LEN		8	/* Network ID = k3(NetKey) */
#define	MESH_PROXY_ID_HASH_LEN		8
#define	MESH_PROXY_ID_RANDOM_LEN	8

/* Full AD structures: length(1) + AD type(1) + service data value. */
#define	MESH_PROXY_ADV_NETWORK_ID_LEN	13	/* + UUID(2)+type(1)+netid(8) */
#define	MESH_PROXY_ADV_NODE_IDENTITY_LEN 21	/* + UUID(2)+type(1)+hash(8)+rand(8) */
/* Private Network/Node Identity AD structures: type(1)+hash(8)+rand(8) value. */
#define	MESH_PROXY_ADV_PRIVATE_NETWORK_ID_LEN	21
#define	MESH_PROXY_ADV_PRIVATE_NODE_IDENTITY_LEN 21

/*
 * IdentityKey = k1(NetKey, s1("nkik"), "id128" || 0x01) (Section 3.9.6.3.4);
 * the key underlying the Node Identity Hash.
 */
int	mesh_proxy_identity_key(const uint8_t netkey[16], uint8_t out[16]);

/*
 * Node Identity Hash (Section 7.2.2.2.2):
 *   Hash = e(IdentityKey, 0x000000000000 || Random(8) || Address(2))[8..15]
 */
int	mesh_proxy_identity_hash(const uint8_t identity_key[16], uint16_t addr,
	    const uint8_t random[MESH_PROXY_ID_RANDOM_LEN],
	    uint8_t hash[MESH_PROXY_ID_HASH_LEN]);

/*
 * Build the Network ID (Section 7.2.2.2.1) and Node Identity (Section
 * 7.2.2.2.2) connectable-advertising Service Data AD structures.  Each writes
 * the full AD structure (length || 0x16 || UUID || type || value) and its
 * length; -1 (output zeroed) on a derivation failure or NULL argument.
 */
int	mesh_proxy_adv_network_id_build(const uint8_t netkey[16], uint8_t *out,
	    size_t *outlen);
int	mesh_proxy_adv_node_identity_build(const uint8_t identity_key[16],
	    uint16_t addr, const uint8_t random[MESH_PROXY_ID_RANDOM_LEN],
	    uint8_t *out, size_t *outlen);

/*
 * Build the Private Network Identity (Section 7.2.2.2.4) and Private Node
 * Identity (Section 7.2.2.2.5) connectable-advertising Service Data AD
 * structures (Mesh Protocol 1.1).  The 8-octet Hash obscures the identity:
 *
 *   Private Network Identity (type 0x02):
 *       Hash = e(IdentityKey, NetworkID(8) || Random(8))[8..15]
 *   Private Node Identity (type 0x03):
 *       Hash = e(IdentityKey, 0x00_00_00_00_00 || 0x03 || Random(8) ||
 *                Address(2))[8..15]
 *
 * The network-id variant derives NetworkID (k3) and the IdentityKey from the
 * NetKey; the node variant takes the IdentityKey and unicast Address.  Each
 * writes the full AD structure and its length; -1 (output zeroed) on a
 * derivation failure or NULL argument.
 */
int	mesh_proxy_adv_private_network_id_build(const uint8_t netkey[16],
	    const uint8_t random[MESH_PROXY_ID_RANDOM_LEN], uint8_t *out,
	    size_t *outlen);
int	mesh_proxy_adv_private_node_identity_build(const uint8_t identity_key[16],
	    uint16_t addr, const uint8_t random[MESH_PROXY_ID_RANDOM_LEN],
	    uint8_t *out, size_t *outlen);

/*
 * Proxy PDU header (Section 6.3.1, Table 6.1): one octet carrying the
 * 2-bit SAR field (bits 7..6) followed by the 6-bit MessageType field
 * (bits 5..0), then the variable Data field.
 */
#define	MESH_PROXY_HDR_LEN		1

/* SAR field values (Section 6.3.1, Table 6.2). */
#define	MESH_PROXY_SAR_COMPLETE		0x00	/* complete message */
#define	MESH_PROXY_SAR_FIRST		0x01	/* first segment */
#define	MESH_PROXY_SAR_CONTINUATION	0x02	/* continuation segment */
#define	MESH_PROXY_SAR_LAST		0x03	/* last segment */

/* MessageType field values (Section 6.3.1, Table 6.3). */
#define	MESH_PROXY_TYPE_NETWORK		0x00	/* Network PDU (Section 3.4.4) */
#define	MESH_PROXY_TYPE_BEACON		0x01	/* mesh beacon (Section 3.10) */
#define	MESH_PROXY_TYPE_CONFIG		0x02	/* proxy config (Section 6.6) */
#define	MESH_PROXY_TYPE_PROVISIONING	0x03	/* Provisioning PDU (Sec 5.4.1) */
#define	MESH_PROXY_TYPE_MAX		0x03	/* 0x04..0x3f are RFU */

/*
 * Per-message maxima used to bound reassembly state and reject oversized
 * Data fields (Section 6.3.2.2).  The beacon component sizes come from
 * Sections 3.10.2--3.10.4: an Unprovisioned Device beacon is 19 octets, or
 * 23 with its optional URI Hash; a Secure Network beacon is 22 octets; and
 * a Mesh Private beacon is 27 octets.  The longest Provisioning PDU is the
 * 65-octet Public Key PDU (Section 5.4.1); the 66-octet GATT characteristic
 * value includes the one-octet Proxy PDU header (Section 7.1.2).
 */
#define	MESH_PROXY_MAX_NETWORK_PDU	29
#define	MESH_PROXY_MAX_UNPROV_BEACON	23
#define	MESH_PROXY_MAX_SECURE_BEACON	22
#define	MESH_PROXY_MAX_PRIVATE_BEACON	27
#define	MESH_PROXY_MAX_BEACON_PDU	MESH_PROXY_MAX_PRIVATE_BEACON
#define	MESH_PROXY_MAX_CONFIG_PDU	29
#define	MESH_PROXY_MAX_PROVISIONING_PDU	65
#define	MESH_PROXY_MAX_MSG		MESH_PROXY_MAX_PROVISIONING_PDU
#define	MESH_PROXY_MAX_PDU		(MESH_PROXY_HDR_LEN + MESH_PROXY_MAX_MSG)

/*
 * Proxy configuration message opcodes (Section 6.6, Table 6.5).  0x04
 * (DIRECTED_PROXY_CAPABILITIES_STATUS) and 0x05 (DIRECTED_PROXY_CONTROL) belong
 * to the Directed Proxy feature (Sections 6.6.5/6.6.6); 0x06..0xff are RFU.
 */
#define	MESH_PROXY_OP_SET_FILTER_TYPE	0x00
#define	MESH_PROXY_OP_ADD_ADDR		0x01
#define	MESH_PROXY_OP_REMOVE_ADDR	0x02
#define	MESH_PROXY_OP_FILTER_STATUS	0x03
#define	MESH_PROXY_OP_DIRECTED_PROXY_CAP_STATUS	0x04
#define	MESH_PROXY_OP_DIRECTED_PROXY_CONTROL	0x05

/* Use_Directed field values (Tables 6.12 / 6.14).  0x02..0xff prohibited. */
#define	MESH_PROXY_USE_DIRECTED_DISABLE	0x00
#define	MESH_PROXY_USE_DIRECTED_ENABLE	0x01

/* FilterType values (Section 6.6.1, Table 6.7).  0x02..0xff are prohibited. */
#define	MESH_PROXY_FILTER_ACCEPT	0x00	/* accept (white) list filter */
#define	MESH_PROXY_FILTER_REJECT	0x01	/* reject (black) list filter */

/*
 * An Add/Remove Addresses message carries an AddressArray of 2*N octets
 * with N in 0..5 (Section 6.6.2/6.6.3).
 */
#define	MESH_PROXY_MAX_ADDR_PER_MSG	5

/* Bound on the number of addresses held in one proxy filter list. */
#define	MESH_PROXY_FILTER_MAX		32

/* ================================================================
 * Proxy PDU codec (Section 6.3.1).
 * ================================================================ */

/*
 * Build one Proxy PDU: header octet (sar<<6 | type) followed by the
 * datalen-octet Data field.  sar must be one of MESH_PROXY_SAR_*; type
 * must be a defined MessageType (0x00..0x03); RFU types are rejected.
 * Fails if the result would not fit in outcap.
 */
int	mesh_proxy_pdu_build(uint8_t sar, uint8_t type, const uint8_t *data,
	    size_t datalen, uint8_t *out, size_t outcap, size_t *outlen);

/*
 * Parse one Proxy PDU.  Recovers the SAR and MessageType fields and
 * returns a borrowed pointer into the input for the Data field (valid for
 * the lifetime of *in).  Rejects a truncated PDU (inlen < 1) or a
 * Reserved-for-Future-Use MessageType.
 */
int	mesh_proxy_pdu_parse(const uint8_t *in, size_t inlen, uint8_t *sar,
	    uint8_t *type, const uint8_t **data, size_t *datalen);

/* ================================================================
 * SAR segmentation and reassembly (Section 6.3.2).
 * ================================================================ */

/* One emitted Proxy PDU segment (full PDU including the header octet). */
struct mesh_proxy_seg {
	uint8_t	bytes[MESH_PROXY_MAX_PDU];
	size_t	len;
};

/*
 * Segment a full message of MessageType type into Proxy PDUs, each at
 * most pdu_max octets on the wire (including the 1-octet header), so each
 * segment's Data field is at most pdu_max-1 octets.  pdu_max must be in
 * [2, MESH_PROXY_MAX_PDU].  A message that fits in one PDU is emitted as a
 * single SAR=complete segment; otherwise the segments are first / (zero or
 * more) continuation / last, in order (Section 6.3.2.1).  Writes up to
 * maxsegs descriptors and the count to *nseg; fails if more than maxsegs
 * segments would be required.
 */
int	mesh_proxy_segment(uint8_t type, const uint8_t *msg, size_t msglen,
	    size_t pdu_max, struct mesh_proxy_seg *segs, size_t maxsegs,
	    size_t *nseg);

/*
 * Bounded per-connection reassembly state (Section 6.3.2.2).  Zeroed by
 * mesh_proxy_reasm_init(); each connection needs one instance.
 */
struct mesh_proxy_reasm {
	uint8_t		buf[MESH_PROXY_MAX_MSG];
	size_t		len;		/* octets accumulated so far */
	uint8_t		type;		/* MessageType of the message in flight */
	int		in_progress;	/* 1 between a first and its last segment */
	uint64_t	start_ms;	/* clock stamped when the timeout clock ran */
	int		timing;		/* start_ms valid (timeout clock running) */
};

/*
 * SAR reassembly timeout (Section 6.3.2.2): a partially reassembled message is
 * discarded if a segment is not received within 20 seconds.
 */
#define	MESH_PROXY_REASM_TIMEOUT_MS	20000u

void	mesh_proxy_reasm_init(struct mesh_proxy_reasm *r);

/*
 * Advance the reassembly timeout against the caller's clock (ms).  While a
 * message is partially reassembled the timeout clock runs from the most recent
 * segment; if MESH_PROXY_REASM_TIMEOUT_MS elapses with no further segment, the
 * partial message is discarded and 1 is returned (in the specification the
 * receiver disconnects).  Returns 0 when nothing is discarded.  Call it on a
 * timer between feeds; feeding a segment restarts the clock.
 */
int	mesh_proxy_reasm_tick(struct mesh_proxy_reasm *r, uint64_t now);

/*
 * Feed one received Proxy PDU (header + Data) into the reassembler.
 *
 * Returns MESH_PROXY_REASM_OK when the segment is legal (whether or not it
 * completes a message), MESH_PROXY_REASM_IGNORED for an RFU MessageType, and
 * MESH_PROXY_REASM_ERROR when the SAR sequence is illegal, the MessageType
 * changes mid-message, the Data field is oversized, or the reassembly
 * buffer would overflow -- in the specification the receiver disconnects
 * on any of these.  When a complete message has been assembled, *complete
 * is set to 1 and the message is copied to out_msg (out_type/out_msglen
 * filled) and the state is reset for the next message; otherwise *complete
 * is 0.  On the -1 path the state is reset and *complete is 0.
 */
#define MESH_PROXY_REASM_ERROR		(-1)
#define MESH_PROXY_REASM_OK		0
#define MESH_PROXY_REASM_IGNORED	1
int	mesh_proxy_reasm_feed(struct mesh_proxy_reasm *r, const uint8_t *pdu,
	    size_t pdulen, int *complete, uint8_t *out_type, uint8_t *out_msg,
	    size_t outcap, size_t *out_msglen);

/* ================================================================
 * Proxy filter state machine (Sections 6.4, 6.7).
 * ================================================================ */

struct mesh_proxy_filter {
	uint8_t		type;			/* MESH_PROXY_FILTER_* */
	size_t		count;
	uint16_t	list[MESH_PROXY_FILTER_MAX];
};

/*
 * Initialise a filter to its default state: an accept-list filter with an
 * empty list (Section 6.4.1).
 */
void	mesh_proxy_filter_init(struct mesh_proxy_filter *f);

/*
 * Set the filter type, which also clears the filter list (Section 6.6.1).
 * type must be MESH_PROXY_FILTER_ACCEPT or MESH_PROXY_FILTER_REJECT;
 * prohibited values are rejected with -1.
 */
int	mesh_proxy_filter_set_type(struct mesh_proxy_filter *f, uint8_t type);

/*
 * Add / remove a list of destination addresses (Section 6.6.2/6.6.3).
 * Add skips duplicates and returns -1 if the bounded list would overflow;
 * remove drops each listed address that is present.  Both leave the filter
 * unchanged and return -1 on a NULL argument.
 */
int	mesh_proxy_filter_add(struct mesh_proxy_filter *f,
	    const uint16_t *addrs, size_t n);
int	mesh_proxy_filter_remove(struct mesh_proxy_filter *f,
	    const uint16_t *addrs, size_t n);

/*
 * Accept/reject predicate (Section 6.4.1): for an accept-list filter,
 * returns 1 iff dst is on the list; for a reject-list filter, returns 1
 * iff dst is NOT on the list.  Never fails.
 */
int	mesh_proxy_filter_accepts(const struct mesh_proxy_filter *f,
	    uint16_t dst);

/* ================================================================
 * Proxy configuration message codec (Section 6.6): the plaintext
 * TransportPDU = Opcode (1) || Parameters (0..11).
 * ================================================================ */

/* Parsed proxy configuration message. */
struct mesh_proxy_cfg {
	uint8_t		opcode;			/* MESH_PROXY_OP_* */
	uint8_t		filter_type;		/* set-filter-type / filter-status */
	uint16_t	list_size;		/* filter-status */
	size_t		naddr;			/* add / remove */
	uint16_t	addrs[MESH_PROXY_MAX_ADDR_PER_MSG];

	/* Directed Proxy messages (Sections 6.6.5 / 6.6.6). */
	uint8_t		directed_proxy;		/* cap-status: Directed Proxy state */
	uint8_t		use_directed;		/* cap-status / control: Use_Directed */
	int		have_range;		/* control: address range present */
	uint16_t	range_start;		/* control: range start unicast */
	uint8_t		range_length;		/* control: range length (0 => single) */
};

/* Set Filter Type (opcode 0x00): FilterType (1). */
int	mesh_proxy_cfg_set_filter_build(uint8_t filter_type, uint8_t *out,
	    size_t outcap, size_t *outlen);

/*
 * Add / Remove Addresses (opcode 0x01 / 0x02): AddressArray (2*N), N in
 * 0..5.  opcode must be MESH_PROXY_OP_ADD_ADDR or MESH_PROXY_OP_REMOVE_ADDR.
 */
int	mesh_proxy_cfg_addr_build(uint8_t opcode, const uint16_t *addrs,
	    size_t n, uint8_t *out, size_t outcap, size_t *outlen);

/* Filter Status (opcode 0x03): FilterType (1) || ListSize (2). */
int	mesh_proxy_cfg_filter_status_build(uint8_t filter_type,
	    uint16_t list_size, uint8_t *out, size_t outcap, size_t *outlen);

/*
 * Parse a proxy configuration message, validating the opcode and its parameter
 * length: the four filter messages (0x00..0x03) plus the two Directed Proxy
 * messages (0x04 DIRECTED_PROXY_CAPABILITIES_STATUS, 0x05 DIRECTED_PROXY_CONTROL,
 * whose optional address range sets out->have_range).  RFU opcodes and
 * prohibited field values are rejected with -1.
 */
int	mesh_proxy_cfg_parse(const uint8_t *in, size_t inlen,
	    struct mesh_proxy_cfg *out);

/* ================================================================
 * Secured Proxy Configuration PDU (Section 6.6).  A proxy configuration
 * message is a Network PDU with CTL=1, TTL=0 and DST set to the unassigned
 * address (0x0000), secured with the managed-flooding EncryptionKey /
 * PrivacyKey under the proxy nonce (Section 3.9.5.4).  These functions
 * produce/consume that Network PDU (the "ProxyMessage"); wrap it in a
 * Proxy Configuration Proxy PDU with mesh_proxy_pdu_build/parse.
 * ================================================================ */

/*
 * Encrypt+obfuscate a proxy configuration message (the plaintext
 * Opcode||Parameters, msg/msglen) into the secured Network PDU.  nid is
 * the 7-bit network identifier; seq/src are the network SEQ and source
 * address that feed the proxy nonce.  On success *out holds the Network
 * PDU and *outlen its length (7 + 2 + msglen + 8).
 */
int	mesh_proxy_cfg_encrypt(const uint8_t enckey[16],
	    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index,
	    uint32_t seq, uint16_t src, const uint8_t *msg, size_t msglen,
	    uint8_t *out, size_t *outlen);

/*
 * Inverse of mesh_proxy_cfg_encrypt(): deobfuscate the header, verify the
 * NID and the 64-bit NetMIC under the proxy nonce, and recover the
 * plaintext configuration message.  Enforces CTL=1 and DST=0x0000 as
 * required for a proxy configuration message.  Writes the SEQ/SRC (if the
 * pointers are non-NULL) and the message to msg/msglen.  Returns -1 (with
 * outputs zeroed) on a NID mismatch, a malformed or oversized PDU, a
 * DST/CTL violation, or a NetMIC failure.
 */
int	mesh_proxy_cfg_decrypt(const uint8_t enckey[16],
	    const uint8_t privkey[16], uint8_t nid, uint32_t iv_index,
	    const uint8_t *in, size_t inlen, uint32_t *seq, uint16_t *src,
	    uint8_t *msg, size_t msgcap, size_t *msglen);

#endif /* _MESH_PROXY_H_ */
