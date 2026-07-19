/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh provisioning.
 *
 * Implements the provisioning protocol of the Bluetooth Mesh Protocol
 * specification (MshPRT_v1.1) Section 5 - the procedure that securely
 * admits an unprovisioned device into a mesh network and hands it the
 * NetKey and its device key (DevKey).  Four responsibilities:
 *
 *   - Provisioning PDU codec (Section 5.4.1): the Type octet + per-type
 *     field layouts for the Invite, Capabilities, Start, Public Key,
 *     Input Complete, Confirmation, Random, Data, Complete and Failed
 *     PDUs, with reserved-bit and length validation.
 *   - ECDH P-256 (Section 5.4.2.3): key-pair generation and the
 *     shared-secret (ECDHSecret = X coordinate) computation, built on the
 *     same OpenSSL EVP_PKEY idiom used by the LE SMP Secure Connections
 *     code (usr.sbin/bluetooth/blued/smp_sc.c).  Unlike SMP, Mesh keeps
 *     public keys and the shared secret in network (big-endian) byte
 *     order, so no byte reversal is performed.
 *   - Security functions (Section 5.4.2.4 / 3.8): ConfirmationInputs,
 *     ConfirmationSalt, ConfirmationKey, the Confirmation value, the
 *     ProvisioningSalt, SessionKey, SessionNonce and DevKey, plus the
 *     AuthValue packing for the OOB authentication methods.
 *   - Provisioning-data encryption (Section 5.4.2.5): AES-CCM of the
 *     25-octet provisioning data under the SessionKey/SessionNonce with an
 *     8-octet MIC.
 *   - Bearer framing: the PB-ADV Generic Provisioning PDU (Section 5.3.1)
 *     - Transaction Start / Continuation / Acknowledgment / Bearer Control
 *     with the 2-bit GPCF, the 3GPP TS 27.010 FCS and transaction
 *     reassembly - and the PB-GATT Proxy PDU wrap (Section 6.3).
 *
 * The security and codec functions are pure and hardware-free: they take
 * and return values in network (big-endian) byte order, perform no I/O,
 * keep no global state, and clear intermediate secrets with
 * explicit_bzero().  Each returns 0 on success and -1 on failure with the
 * output left zeroed; the reassembly primitives return their tri-state
 * result (-1 error / 0 incomplete / 1 complete).  The ECDH helpers wrap an
 * OpenSSL EVP_PKEY handle and so allocate; mesh_prov_keypair_free()
 * releases it.
 */

#ifndef _MESH_PROVISION_H_
#define _MESH_PROVISION_H_

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Provisioning PDU codec.  MshPRT_v1.1 Section 5.4.1.
 * ================================================================ */

/* Provisioning PDU types (Type octet, bits 0..5; bits 6..7 are RFU=0). */
#define	MESH_PROV_INVITE		0x00
#define	MESH_PROV_CAPABILITIES		0x01
#define	MESH_PROV_START			0x02
#define	MESH_PROV_PUBLIC_KEY		0x03
#define	MESH_PROV_INPUT_COMPLETE	0x04
#define	MESH_PROV_CONFIRMATION		0x05
#define	MESH_PROV_RANDOM		0x06
#define	MESH_PROV_DATA			0x07
#define	MESH_PROV_COMPLETE		0x08
#define	MESH_PROV_FAILED		0x09
#define	MESH_PROV_TYPE_MAX		0x09

/*
 * Provisioning algorithms (Provisioning Start "Algorithm" octet, and the
 * Capabilities "Algorithms" bitmask).  MshPRT_v1.1 Section 5.4.1.2.
 *   0x00 BTM_ECDH_P256_CMAC_AES128_AES_CCM  (16-octet Confirmation/Random)
 *   0x01 BTM_ECDH_P256_HMAC_SHA256_AES_CCM  (32-octet Confirmation/Random)
 */
#define	MESH_PROV_ALGO_P256_CMAC	0x00
#define	MESH_PROV_ALGO_P256_HMAC	0x01
#define	MESH_PROV_ALGO_BIT_P256_CMAC	0x0001	/* Algorithms bitmask bit 0 */
#define	MESH_PROV_ALGO_BIT_P256_HMAC	0x0002	/* Algorithms bitmask bit 1 */

/* Fixed field sizes shared across the protocol (AES-CMAC-128 algorithm). */
#define	MESH_PROV_PUBKEY_LEN		64	/* X(32) || Y(32) */
#define	MESH_PROV_COORD_LEN		32
#define	MESH_PROV_CONFIRM_LEN		16
#define	MESH_PROV_RANDOM_LEN		16
#define	MESH_PROV_AUTH_LEN		16
/* HMAC-SHA-256 algorithm (0x01): 32-octet Confirmation/Random/AuthValue. */
#define	MESH_PROV_CONFIRM_LEN_256	32
#define	MESH_PROV_RANDOM_LEN_256	32
#define	MESH_PROV_AUTH_LEN_256		32
#define	MESH_PROV_SALT_LEN		16
#define	MESH_PROV_KEY_LEN		16
#define	MESH_PROV_NONCE_LEN		13
#define	MESH_PROV_ECDH_LEN		32
#define	MESH_PROV_DATA_LEN		25	/* NetKey||idx||flags||iv||addr */
#define	MESH_PROV_DATA_MIC_LEN		8
#define	MESH_PROV_DATA_ENC_LEN		(MESH_PROV_DATA_LEN + MESH_PROV_DATA_MIC_LEN)

/* ConfirmationInputs length: Invite(1)||Caps(11)||Start(5)||PKp(64)||PKd(64). */
#define	MESH_PROV_CONF_INPUTS_LEN	145
#define	MESH_PROV_INVITE_VAL_LEN	1
#define	MESH_PROV_CAPS_VAL_LEN		11
#define	MESH_PROV_START_VAL_LEN		5

/* Largest on-wire Provisioning PDU (Public Key = Type + 64). */
#define	MESH_PROV_PDU_MAX		65

/*
 * Generic parsed Provisioning PDU.  mesh_prov_pdu_parse() validates the
 * Type octet (reserved bits 6..7 clear, type <= 0x09) and that the total
 * length equals the fixed length mandated for that type, then copies the
 * parameters (the octets after the Type octet).
 */
struct mesh_prov_pdu {
	uint8_t		type;
	uint8_t		params[MESH_PROV_PDU_MAX - 1];
	size_t		params_len;
};
int	mesh_prov_pdu_parse(const uint8_t *in, size_t len,
	    struct mesh_prov_pdu *out);
int	mesh_prov_pdu_build(uint8_t type, const uint8_t *params, size_t plen,
	    uint8_t *out, size_t *outlen);

/*
 * Algorithm-aware codec.  Identical to the above but the Confirmation and
 * Random field lengths follow the negotiated algorithm (16 octets for
 * BTM_ECDH_P256_CMAC, 32 for BTM_ECDH_P256_HMAC_SHA256).  The provisioner
 * and device both select on the Algorithm from Provisioning Start.
 */
int	mesh_prov_pdu_parse_alg(uint8_t algorithm, const uint8_t *in, size_t len,
	    struct mesh_prov_pdu *out);
int	mesh_prov_pdu_build_alg(uint8_t algorithm, uint8_t type,
	    const uint8_t *params, size_t plen, uint8_t *out, size_t *outlen);

/* Confirmation/Random field length for the negotiated algorithm (16 or 32). */
size_t	mesh_prov_auth_field_len(uint8_t algorithm);

/*
 * Structured per-type codecs.  Each *_build() writes the full on-wire PDU
 * (Type octet + fields) and its length; each *_parse() validates and
 * unpacks.  Multi-octet fields are big-endian.
 */

/* Invite (0x00): Attention Duration (1). */
int	mesh_prov_invite_build(uint8_t attention, uint8_t *out, size_t *outlen);
int	mesh_prov_invite_parse(const uint8_t *in, size_t len,
	    uint8_t *attention);

/* Capabilities (0x01): NumElements(1), Algorithms(2), PublicKeyType(1),
 * StaticOOBType(1), OutputOOBSize(1), OutputOOBAction(2), InputOOBSize(1),
 * InputOOBAction(2). */
struct mesh_prov_caps {
	uint8_t		num_elements;
	uint16_t	algorithms;
	uint8_t		public_key_type;
	uint8_t		static_oob_type;
	uint8_t		output_oob_size;
	uint16_t	output_oob_action;
	uint8_t		input_oob_size;
	uint16_t	input_oob_action;
};
int	mesh_prov_caps_build(const struct mesh_prov_caps *in, uint8_t *out,
	    size_t *outlen);
int	mesh_prov_caps_parse(const uint8_t *in, size_t len,
	    struct mesh_prov_caps *out);

/* Start (0x02): Algorithm(1), PublicKey(1), AuthMethod(1), AuthAction(1),
 * AuthSize(1). */
struct mesh_prov_start {
	uint8_t		algorithm;
	uint8_t		public_key;
	uint8_t		auth_method;
	uint8_t		auth_action;
	uint8_t		auth_size;
};
int	mesh_prov_start_build(const struct mesh_prov_start *in, uint8_t *out,
	    size_t *outlen);
int	mesh_prov_start_parse(const uint8_t *in, size_t len,
	    struct mesh_prov_start *out);

/* Public Key (0x03): PublicKeyX(32) || PublicKeyY(32). */
int	mesh_prov_public_key_build(const uint8_t x[32], const uint8_t y[32],
	    uint8_t *out, size_t *outlen);
int	mesh_prov_public_key_parse(const uint8_t *in, size_t len,
	    uint8_t x[32], uint8_t y[32]);

/* Confirmation (0x05): Confirmation(16). */
int	mesh_prov_confirmation_build(const uint8_t conf[16], uint8_t *out,
	    size_t *outlen);
int	mesh_prov_confirmation_parse(const uint8_t *in, size_t len,
	    uint8_t conf[16]);

/* Random (0x06): Random(16). */
int	mesh_prov_random_build(const uint8_t random[16], uint8_t *out,
	    size_t *outlen);
int	mesh_prov_random_parse(const uint8_t *in, size_t len,
	    uint8_t random[16]);

/*
 * Algorithm-aware Confirmation (0x05) / Random (0x06) codecs: the field is 16
 * octets under algorithm 0x00 and 32 octets under algorithm 0x01.  The conf /
 * random buffers must hold mesh_prov_auth_field_len(algorithm) octets.
 */
int	mesh_prov_confirmation_build_alg(uint8_t algorithm, const uint8_t *conf,
	    uint8_t *out, size_t *outlen);
int	mesh_prov_confirmation_parse_alg(uint8_t algorithm, const uint8_t *in,
	    size_t len, uint8_t *conf);
int	mesh_prov_random_build_alg(uint8_t algorithm, const uint8_t *random,
	    uint8_t *out, size_t *outlen);
int	mesh_prov_random_parse_alg(uint8_t algorithm, const uint8_t *in,
	    size_t len, uint8_t *random);

/* Data (0x07): EncryptedProvisioningData(25) || ProvisioningDataMIC(8). */
int	mesh_prov_data_pdu_build(const uint8_t enc[25], const uint8_t mic[8],
	    uint8_t *out, size_t *outlen);
int	mesh_prov_data_pdu_parse(const uint8_t *in, size_t len,
	    uint8_t enc[25], uint8_t mic[8]);

/* Failed (0x09): ErrorCode(1). */
int	mesh_prov_failed_build(uint8_t error_code, uint8_t *out, size_t *outlen);
int	mesh_prov_failed_parse(const uint8_t *in, size_t len,
	    uint8_t *error_code);

/* Input Complete (0x04) and Complete (0x08): no parameters. */
int	mesh_prov_no_param_build(uint8_t type, uint8_t *out, size_t *outlen);

/* ================================================================
 * ECDH P-256.  MshPRT_v1.1 Section 5.4.2.3.
 * ================================================================ */

/*
 * A provisioning key pair.  The public key coordinates are cached in
 * network (big-endian) byte order for direct inclusion in a Public Key
 * PDU.  pkey is an opaque OpenSSL handle; mesh_prov_keypair_free() releases
 * it (and is a no-op on a zeroed struct).
 */
struct mesh_prov_keypair {
	void		*pkey;			/* EVP_PKEY * */
	uint8_t		pub_x[32];
	uint8_t		pub_y[32];
};
int	mesh_prov_keypair_generate(struct mesh_prov_keypair *kp);
int	mesh_prov_keypair_from_private(const uint8_t priv[32],
	    struct mesh_prov_keypair *kp);
void	mesh_prov_keypair_free(struct mesh_prov_keypair *kp);

/* Validate that (x, y) is a point on the P-256 curve. */
int	mesh_prov_validate_public_key(const uint8_t x[32], const uint8_t y[32]);

/*
 * ECDHSecret = P256(local private key, peer public key), taken as the
 * X coordinate of the shared point (32 octets, big-endian).
 */
int	mesh_prov_ecdh_secret(const struct mesh_prov_keypair *local,
	    const uint8_t peer_x[32], const uint8_t peer_y[32],
	    uint8_t secret[32]);

/* ================================================================
 * Provisioning security functions.  MshPRT_v1.1 Sections 5.4.2.4, 3.8.
 * ================================================================ */

/*
 * ConfirmationInputs = ProvisioningInvitePDUValue ||
 *   ProvisioningCapabilitiesPDUValue || ProvisioningStartPDUValue ||
 *   PublicKeyProvisioner || PublicKeyDevice.  The PDU "values" are the
 *   parameter octets (no Type octet): Invite(1), Capabilities(11),
 *   Start(5).  Output is 145 octets.
 */
int	mesh_prov_confirmation_inputs(const uint8_t *invite_val,
	    const uint8_t *caps_val, const uint8_t *start_val,
	    const uint8_t prov_pub[64], const uint8_t dev_pub[64],
	    uint8_t out[145]);

/* ConfirmationSalt = s1(ConfirmationInputs). */
int	mesh_prov_confirmation_salt(const uint8_t *inputs, size_t inputs_len,
	    uint8_t salt[16]);

/* ConfirmationKey = k1(ECDHSecret, ConfirmationSalt, "prck"). */
int	mesh_prov_confirmation_key(const uint8_t ecdh[32],
	    const uint8_t conf_salt[16], uint8_t key[16]);

/* Confirmation = AES-CMAC(ConfirmationKey, Random || AuthValue). */
int	mesh_prov_confirmation(const uint8_t conf_key[16],
	    const uint8_t random[16], const uint8_t auth[16], uint8_t conf[16]);

/*
 * HMAC-SHA-256 provisioning algorithm (0x01) confirmation derivations
 * (Section 5.4.2.4).  All values are 32 octets.  Unlike algorithm 0x00, the
 * AuthValue is folded into the ConfirmationKey (via k5's P input), not into
 * the Confirmation:
 *   ConfirmationSalt = s2(ConfirmationInputs)
 *   ConfirmationKey  = k5(ECDHSecret || AuthValue, ConfirmationSalt, "prck256")
 *   Confirmation     = HMAC-SHA-256(ConfirmationKey, Random)
 */
int	mesh_prov_confirmation_salt_s2(const uint8_t *inputs, size_t inputs_len,
	    uint8_t salt[32]);
int	mesh_prov_confirmation_key_hmac(const uint8_t ecdh[32],
	    const uint8_t auth[32], const uint8_t conf_salt[32], uint8_t key[32]);
int	mesh_prov_confirmation_hmac(const uint8_t conf_key[32],
	    const uint8_t random[32], uint8_t conf[32]);

/*
 * 256-bit AuthValue packing for the HMAC-SHA-256 algorithm (Section 5.4.2.4).
 *   - No-OOB    : all zeros.
 *   - Static-OOB: the static value left-aligned, zero-padded right (<=32).
 *   - Numeric   : the number as a 256-bit big-endian integer (right-aligned).
 */
void	mesh_prov_auth256_no_oob(uint8_t auth[32]);
void	mesh_prov_auth256_static_oob(const uint8_t *value, size_t len,
	    uint8_t auth[32]);
void	mesh_prov_auth256_numeric(uint32_t number, uint8_t auth[32]);

/* ProvisioningSalt = s1(ConfirmationSalt || RandomProvisioner || RandomDevice). */
int	mesh_prov_provisioning_salt(const uint8_t conf_salt[16],
	    const uint8_t rand_prov[16], const uint8_t rand_dev[16],
	    uint8_t salt[16]);

/* SessionKey = k1(ECDHSecret, ProvisioningSalt, "prsk"). */
int	mesh_prov_session_key(const uint8_t ecdh[32], const uint8_t prov_salt[16],
	    uint8_t key[16]);

/*
 * SessionNonce = k1(ECDHSecret, ProvisioningSalt, "prsn"), taking the 13
 * least significant octets (indexes 3..15 of the 16-octet k1 output).
 */
int	mesh_prov_session_nonce(const uint8_t ecdh[32],
	    const uint8_t prov_salt[16], uint8_t nonce[13]);

/* DevKey = k1(ECDHSecret, ProvisioningSalt, "prdk"). */
int	mesh_prov_device_key(const uint8_t ecdh[32], const uint8_t prov_salt[16],
	    uint8_t devkey[16]);

/*
 * AuthValue packing.  MshPRT_v1.1 Section 5.4.2.4 (AES-CMAC-128 algorithm,
 * 16-octet AuthValue).
 *   - No-OOB    : all zeros.
 *   - Static-OOB: the static value copied left-aligned, zero-padded right,
 *                 trimmed to 16 octets.
 *   - Numeric   : the unsigned number as a 128-bit big-endian integer
 *                 (right-aligned, zero-padded on the left).
 *   - Alphanumeric: the ASCII string copied left-aligned, zero-padded right.
 */
void	mesh_prov_auth_no_oob(uint8_t auth[16]);
void	mesh_prov_auth_static_oob(const uint8_t *value, size_t len,
	    uint8_t auth[16]);
void	mesh_prov_auth_numeric(uint32_t number, uint8_t auth[16]);
void	mesh_prov_auth_alphanumeric(const char *str, size_t len,
	    uint8_t auth[16]);

/* ================================================================
 * Provisioning-data encryption.  MshPRT_v1.1 Section 5.4.2.5.
 * ================================================================ */

/*
 * The 25-octet provisioning data: NetKey(16) || NetKeyIndex(2) || Flags(1)
 * || IVIndex(4) || UnicastAddress(2), all big-endian.
 */
struct mesh_prov_data {
	uint8_t		netkey[16];
	uint16_t	netkey_index;	/* 12-bit key index */
	uint8_t		flags;
	uint32_t	iv_index;
	uint16_t	unicast_addr;
};
int	mesh_prov_data_pack(const struct mesh_prov_data *in, uint8_t out[25]);
int	mesh_prov_data_unpack(const uint8_t in[25], struct mesh_prov_data *out);

/*
 * AES-CCM (SessionKey, SessionNonce) over the 25-octet provisioning data,
 * producing the 25-octet encrypted data and the 8-octet MIC.  No AAD.
 * mesh_prov_data_decrypt() verifies the MIC and returns -1 (data zeroed) on
 * any mismatch.
 */
int	mesh_prov_data_encrypt(const uint8_t session_key[16],
	    const uint8_t session_nonce[13], const uint8_t data[25],
	    uint8_t enc[25], uint8_t mic[8]);
int	mesh_prov_data_decrypt(const uint8_t session_key[16],
	    const uint8_t session_nonce[13], const uint8_t enc[25],
	    const uint8_t mic[8], uint8_t data[25]);

/* ================================================================
 * PB-ADV Generic Provisioning bearer.  MshPRT_v1.1 Section 5.3.1.
 * ================================================================ */

/* Generic Provisioning Control Format (2-bit GPCF, octet-0 bits 0..1). */
#define	MESH_GPCF_START			0x00	/* Transaction Start */
#define	MESH_GPCF_ACK			0x01	/* Transaction Acknowledgment */
#define	MESH_GPCF_CONTINUATION		0x02	/* Transaction Continuation */
#define	MESH_GPCF_CONTROL		0x03	/* Bearer Control */

/* Bearer Control opcodes (octet-0 bits 2..7 when GPCF = Control). */
#define	MESH_BEARER_LINK_OPEN		0x00	/* + Device UUID (16) */
#define	MESH_BEARER_LINK_ACK		0x01	/* no parameters */
#define	MESH_BEARER_LINK_CLOSE		0x02	/* + Reason (1) */

/*
 * PB-ADV segment payload limits (Section 5.3.1): the first (Start) segment
 * carries at most 20 octets after its 4-octet header, each Continuation at
 * most 23 octets after its 1-octet header.  A Provisioning PDU is at most 65
 * octets, spanning at most 3 PB-ADV segments.
 */
#define	MESH_GP_START_MAX		20
#define	MESH_GP_CONT_MAX		23
#define	MESH_GP_SEG_MAX			8	/* SegN is 6-bit; cap for us */
#define	MESH_GP_PDU_MAX			24	/* header + max segment */

/* 3GPP TS 27.010 FCS over a Provisioning PDU (Section 5.3.1.1). */
uint8_t	mesh_prov_fcs(const uint8_t *pdu, size_t len);

/* A single built Generic Provisioning PDU. */
struct mesh_gp_pdu {
	uint8_t		bytes[MESH_GP_PDU_MAX];
	size_t		len;
};

/*
 * mesh_gp_segment() splits a Provisioning PDU into Generic Provisioning
 * PDUs: one Transaction Start (SegN, TotalLength, FCS, first data) followed
 * by Transaction Continuation PDUs.  *nseg receives the count.
 */
int	mesh_gp_segment(const uint8_t *prov_pdu, size_t len,
	    struct mesh_gp_pdu *out, size_t max, size_t *nseg);

/* Bearer Control and Transaction Acknowledgment PDU builders. */
int	mesh_gp_ack_build(uint8_t *out, size_t *outlen);
int	mesh_gp_link_open_build(const uint8_t device_uuid[16], uint8_t *out,
	    size_t *outlen);
int	mesh_gp_link_ack_build(uint8_t *out, size_t *outlen);
int	mesh_gp_link_close_build(uint8_t reason, uint8_t *out, size_t *outlen);

/* Parsed Generic Provisioning PDU. */
struct mesh_gp_parsed {
	uint8_t		gpcf;		/* MESH_GPCF_* */
	/* GPCF_START */
	uint8_t		segn;		/* last segment number */
	uint16_t	total_len;	/* reassembled Provisioning PDU length */
	uint8_t		fcs;
	/* GPCF_CONTINUATION */
	uint8_t		seg_index;
	/* GPCF_CONTROL */
	uint8_t		opcode;		/* MESH_BEARER_* */
	/* payload: segment data (START/CONTINUATION) or bearer params (CONTROL) */
	const uint8_t  *payload;
	size_t		payload_len;
};
int	mesh_gp_parse(const uint8_t *in, size_t len, struct mesh_gp_parsed *out);

/*
 * Transaction reassembly.  A struct mesh_gp_reasm tracks one reassembly
 * session.  mesh_gp_reasm_init() clears it.  mesh_gp_reasm_input() feeds one
 * Generic Provisioning PDU: a Transaction Start opens the session (SegN,
 * TotalLength, FCS), each Transaction Continuation fills a later segment.
 * Returns 1 when every segment has arrived and the assembled PDU's FCS
 * matches, 0 when accepted but still incomplete, -1 on error (malformed
 * segment, index past SegN, inconsistent Start, overflow, or - on the final
 * segment - an FCS mismatch).  mesh_gp_reasm_get() copies the reassembled
 * Provisioning PDU out once complete.
 */
struct mesh_gp_reasm {
	int		active;
	uint8_t		segn;
	uint16_t	total_len;
	uint8_t		fcs;
	uint32_t	seg_recv;	/* bit i set => segment i received */
	uint8_t		buf[MESH_PROV_PDU_MAX];
	size_t		seg_off[MESH_GP_SEG_MAX];	/* start offset of segment i */
};
void	mesh_gp_reasm_init(struct mesh_gp_reasm *r);
int	mesh_gp_reasm_input(struct mesh_gp_reasm *r, const uint8_t *gp_pdu,
	    size_t gp_len);
int	mesh_gp_reasm_complete(const struct mesh_gp_reasm *r);
int	mesh_gp_reasm_get(const struct mesh_gp_reasm *r, uint8_t *pdu,
	    size_t *pdu_len);

/*
 * PB-ADV packet framing: LinkID(4) || TransactionNumber(1) || Generic
 * Provisioning PDU.  Section 5.2.1.
 */
#define	MESH_PBADV_HDR_LEN		5
#define	MESH_PBADV_PKT_MAX		(MESH_PBADV_HDR_LEN + MESH_GP_PDU_MAX)
int	mesh_pbadv_build(uint32_t link_id, uint8_t transaction,
	    const uint8_t *gp_pdu, size_t gp_len, uint8_t *out, size_t *outlen);
int	mesh_pbadv_parse(const uint8_t *in, size_t len, uint32_t *link_id,
	    uint8_t *transaction, const uint8_t **gp_pdu, size_t *gp_len);

/* ================================================================
 * PB-GATT Proxy PDU.  MshPRT_v1.1 Section 6.3.
 * ================================================================ */

/* Proxy PDU message types (octet-0 bits 0..5). */
#define	MESH_PROXY_TYPE_NETWORK		0x00
#define	MESH_PROXY_TYPE_MESH_BEACON	0x01
#define	MESH_PROXY_TYPE_PROXY_CONFIG	0x02
#define	MESH_PROXY_TYPE_PROVISIONING	0x03

/* Proxy PDU SAR field (octet-0 bits 6..7). */
#define	MESH_PROXY_SAR_COMPLETE		0x00
#define	MESH_PROXY_SAR_FIRST		0x01
#define	MESH_PROXY_SAR_CONTINUATION	0x02
#define	MESH_PROXY_SAR_LAST		0x03

/*
 * mesh_pbgatt_wrap() prepends the 1-octet Proxy header (SAR<<6 | type) to a
 * (segment of a) Provisioning PDU; mesh_pbgatt_parse() splits the header off.
 */
int	mesh_pbgatt_wrap(uint8_t sar, uint8_t type, const uint8_t *payload,
	    size_t plen, uint8_t *out, size_t *outlen);
int	mesh_pbgatt_parse(const uint8_t *in, size_t len, uint8_t *sar,
	    uint8_t *type, const uint8_t **payload, size_t *plen);

/*
 * mesh_pbgatt_segment() splits a Provisioning PDU into Proxy PDUs of at most
 * seg_max payload octets each, tagging the SAR field (complete / first /
 * continuation / last).  *nseg receives the count.
 */
struct mesh_proxy_pdu {
	uint8_t		bytes[64];
	size_t		len;
};
int	mesh_pbgatt_segment(uint8_t type, const uint8_t *prov_pdu, size_t len,
	    size_t seg_max, struct mesh_proxy_pdu *out, size_t max, size_t *nseg);

/*
 * Inbound PB-GATT Proxy PDU SAR reassembly (Section 5.3.3).  A struct
 * mesh_pbgatt_reasm tracks one reassembly session.  mesh_pbgatt_reasm_init()
 * clears it.  mesh_pbgatt_reasm_input() feeds one received Proxy PDU (the
 * SAR|MessageType header octet followed by the segment payload):
 *
 *   1  a complete Provisioning PDU has been assembled and copied to
 *      out/outlen (the session is reset for the next PDU),
 *   0  the segment was accepted but the PDU is still incomplete,
 *  -1  the segment is malformed (empty), the SAR sequence is illegal, the
 *      MessageType changed mid-message, or the reassembled PDU would exceed
 *      MESH_PROV_PDU_MAX / outcap (the session is reset).
 */
struct mesh_pbgatt_reasm {
	int		active;			/* between a first and its last */
	uint8_t		type;			/* MessageType of the PDU in flight */
	uint8_t		buf[MESH_PROV_PDU_MAX];
	size_t		len;			/* octets accumulated so far */
};
void	mesh_pbgatt_reasm_init(struct mesh_pbgatt_reasm *r);
int	mesh_pbgatt_reasm_input(struct mesh_pbgatt_reasm *r, const uint8_t *pdu,
	    size_t len, uint8_t *out, size_t outcap, size_t *outlen);

#endif /* _MESH_PROVISION_H_ */
