/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh transport layer.
 *
 * Implements the upper transport layer (MshPRT_v1.1 Section 3.6) and the
 * lower transport layer (Section 3.5) on top of the mesh_crypto.[ch]
 * security toolbox (Section 3.8).  The output of this layer is the Lower
 * Transport PDU carried by the network layer (mesh_net.[ch], Section 3.4)
 * as the "transport" field of struct mesh_net_pdu.
 *
 * The module is pure and hardware-free: every function operates on values
 * in network (big-endian) byte order, performs no I/O, keeps no global
 * state, and clears intermediate secrets with explicit_bzero().  Each
 * function returns 0 on success and -1 on failure; on failure the output
 * buffers/structures are left zeroed.  The reassembly primitives return
 * their tri-state result (-1 error / 0 incomplete / 1 complete) directly
 * as documented, and the block-ack helpers return the bitmap value.
 *
 * Two layers, two responsibilities:
 *   - Upper transport (Section 3.6.5.1): AES-CCM encrypt the Access
 *     Payload under the AppKey (AKF=1, application nonce) or DevKey
 *     (AKF=0, device nonce), producing the Upper Transport Access PDU =
 *     Encrypted Access Payload || TransMIC.  The TransMIC is 32 bits,
 *     except a segmented message with SZMIC=1 uses a 64-bit TransMIC.
 *     When the destination is a virtual address, the 16-octet Label UUID
 *     is supplied as the CCM additional authenticated data (AAD).
 *   - Lower transport (Section 3.5.2/3.5.3): frame the Upper Transport
 *     PDU as an (un)segmented access or control Lower Transport PDU, and
 *     provide segmentation, reassembly (SAR) and the Segment
 *     Acknowledgement (block-ack) message.
 */

#ifndef _MESH_TRANSPORT_H_
#define _MESH_TRANSPORT_H_

#include <stddef.h>
#include <stdint.h>

/* TransMIC sizes.  Section 3.6.5.1. */
#define	MESH_TRANS_MIC32		4
#define	MESH_TRANS_MIC64		8

/* Label UUID length used as CCM AAD for virtual addresses.  Section 3.6.5.1. */
#define	MESH_LABEL_UUID_LEN		16

/*
 * Segmentation limits.  Section 3.5.3.1.  SegO and SegN are 5-bit fields,
 * so a message spans at most 32 segments (numbers 0..31).  Each access
 * segment carries at most 12 octets, bounding the Upper Transport Access
 * PDU (Encrypted Access Payload + TransMIC) at 32 * 12 = 384 octets and
 * the Access Payload at 384 - 4 = 380 octets (or 376 with a 64-bit MIC).
 */
#define	MESH_SEG_ACCESS_LEN		12
#define	MESH_SEG_CONTROL_LEN		8
#define	MESH_SEG_MAX			32
#define	MESH_UPPER_MAX			(MESH_SEG_MAX * MESH_SEG_ACCESS_LEN)
#define	MESH_ACCESS_MAX			(MESH_UPPER_MAX - MESH_TRANS_MIC32)

/*
 * Storage capacity for a parsed/built Lower Transport PDU.  The format-
 * specific limits below are smaller and are enforced by the codec.
 */
#define	MESH_LOWER_DATA_MAX		88

/*
 * Unsegmented Access message limit.  Section 3.5.2.1: an unsegmented access
 * Lower Transport PDU carries an Upper Transport Access PDU of at most 15
 * octets (a 11-octet Access Payload plus the 4-octet TransMIC).  A larger
 * Upper Transport Access PDU must be segmented; mesh_lower_build() rejects an
 * oversize unsegmented access PDU rather than emit an out-of-spec frame.
 */
#define	MESH_UNSEG_ACCESS_MAX		15

/* CTL NetMIC leaves 12 transport octets: opcode plus 11 parameters. */
#define	MESH_UNSEG_CONTROL_MAX		11

/* Segment Acknowledgement Lower Transport PDU length.  Section 3.5.3.3. */
#define	MESH_SEG_ACK_LEN		7

/*
 * Upper Transport Access PDU codec.  MshPRT_v1.1 Section 3.6.5.1.
 *
 * mesh_upper_encrypt() encrypts access[0..access_len) under key using the
 * AES-CCM construction of Section 3.8.2.3.  akf selects the nonce: AKF=1
 * uses the application nonce (mesh_application_nonce), AKF=0 uses the
 * device nonce (mesh_device_nonce).  szmic selects the TransMIC size (0 =>
 * 32-bit, 1 => 64-bit); unsegmented messages must pass szmic=0 because
 * their TransMIC is always 32-bit.  When label_uuid is non-NULL the
 * destination is a virtual address and the 16-octet Label UUID is the CCM
 * AAD; when NULL there is no AAD.  The output is the Upper Transport Access
 * PDU (Encrypted Access Payload || TransMIC) and its length.
 *
 * mesh_upper_decrypt() is the exact inverse: it decrypts and verifies the
 * TransMIC, returning -1 (output zeroed) on any MIC failure.  The recovered
 * Access Payload and its length are written to access/access_len.
 */
int	mesh_upper_encrypt(const uint8_t key[16], int akf, int szmic,
	    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index,
	    const uint8_t *label_uuid, const uint8_t *access, size_t access_len,
	    uint8_t *out, size_t *outlen);
int	mesh_upper_decrypt(const uint8_t key[16], int akf, int szmic,
	    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index,
	    const uint8_t *label_uuid, const uint8_t *upper, size_t upper_len,
	    uint8_t *access, size_t *access_len);

/*
 * Parsed / cleartext Lower Transport PDU.  MshPRT_v1.1 Section 3.5.2.
 *
 * The four Lower Transport PDU formats share this structure:
 *   - unsegmented access  (SEG=0, CTL=0): AKF|AID           | data
 *   - segmented access    (SEG=1, CTL=0): AKF|AID, SZMIC,
 *                                         SeqZero,SegO,SegN  | segment
 *   - unsegmented control (SEG=0, CTL=1): Opcode            | data
 *   - segmented control   (SEG=1, CTL=1): Opcode, SeqZero,
 *                                         SegO,SegN          | segment
 * ctl selects access vs control; seg selects the (un)segmented form.  For
 * access PDUs akf/aid (and, when segmented, szmic) are used; for control
 * PDUs opcode is used.  When seg=1 the seqzero/sego/segn fields frame the
 * segment carried in data[0..data_len).  data holds the Upper Transport
 * PDU (unsegmented) or one segment (segmented).
 */
struct mesh_lower {
	int		seg;		/* 0 unsegmented, 1 segmented */
	int		ctl;		/* 0 access, 1 control */
	int		akf;		/* access: application key flag */
	uint8_t		aid;		/* access: 6-bit application id */
	int		szmic;		/* segmented access: TransMIC size flag */
	uint8_t		opcode;		/* control: 7-bit opcode */
	uint16_t	seqzero;	/* segmented: 13-bit SeqZero */
	uint8_t		sego;		/* segmented: 5-bit segment offset */
	uint8_t		segn;		/* segmented: 5-bit last segment number */
	uint8_t		data[MESH_LOWER_DATA_MAX];
	size_t		data_len;
};

/*
 * Lower Transport PDU codec.  MshPRT_v1.1 Section 3.5.2.
 *
 * mesh_lower_build() packs *in into the on-wire Lower Transport PDU.
 * mesh_lower_parse() is its inverse; because the octet-0 layout of an
 * access PDU (AKF|AID) and a control PDU (Opcode) is indistinguishable
 * without the network CTL bit, the caller supplies ctl (0 access, 1
 * control) from the enclosing Network PDU.
 */
int	mesh_lower_build(const struct mesh_lower *in, uint8_t *out,
	    size_t *outlen);
int	mesh_lower_parse(int ctl, const uint8_t *in, size_t inlen,
	    struct mesh_lower *out);

/*
 * Segmentation (SAR).  MshPRT_v1.1 Section 3.5.3.1.
 *
 * mesh_sar_segment() splits an Upper Transport Access PDU into
 * ceil(upper_len / 12) segmented-access Lower Transport PDUs, each built
 * with SegO = index, SegN = count - 1 and the shared akf/aid/szmic/seqzero.
 * Each output slot is a fully built Lower Transport PDU (struct mesh_seg).
 * max is the number of slots available; *nseg receives the count.  A single
 * (short) Upper PDU still produces one segment (SegO=SegN=0).
 */
struct mesh_seg {
	uint8_t		bytes[4 + MESH_SEG_ACCESS_LEN];
	size_t		len;
};
int	mesh_sar_segment(int akf, uint8_t aid, int szmic, uint16_t seqzero,
	    const uint8_t *upper, size_t upper_len, struct mesh_seg *out,
	    size_t max, size_t *nseg);

/*
 * Reassembly (SAR).  MshPRT_v1.1 Section 3.5.3.2.
 *
 * A struct mesh_reasm tracks a single reassembly session keyed by
 * (SRC, SeqZero).  mesh_reasm_init() clears it.  mesh_reasm_input() feeds
 * one received segmented-access Lower Transport PDU (lt_pdu/lt_len) tagged
 * with its network SRC.  A segment whose (src, seqzero) differs from the
 * active session starts a fresh session.  Duplicate segments (a SegO whose
 * block-ack bit is already set) are accepted idempotently without
 * disturbing the buffer.
 *
 * Returns 1 when the message is complete (every segment 0..SegN received),
 * 0 when the segment was accepted but the message is still incomplete, and
 * -1 on error (malformed segment, SEG=0, inconsistent SegN/SeqZero, a
 * non-final segment not exactly 12 octets, or overflow).
 *
 * mesh_reasm_complete() reports whether all segments have arrived.
 * mesh_reasm_get() copies the reassembled Upper Transport PDU out once
 * complete (returns -1 otherwise).
 */
struct mesh_reasm {
	int		active;
	int		ctl;
	uint16_t	src;
	uint16_t	seqzero;	/* 13-bit */
	uint8_t		segn;		/* 5-bit last segment number */
	int		akf;
	uint8_t		aid;
	int		szmic;
	uint8_t		opcode;
	uint8_t		seg_size;
	uint32_t	blockack;	/* bit i set => segment i received */
	uint8_t		buf[MESH_UPPER_MAX];
	size_t		seg_len[MESH_SEG_MAX];
};
void	mesh_reasm_init(struct mesh_reasm *r);
int	mesh_reasm_input(struct mesh_reasm *r, uint16_t src,
	    const uint8_t *lt_pdu, size_t lt_len);
int	mesh_reasm_input_ctl(struct mesh_reasm *r, uint16_t src, int ctl,
	    const uint8_t *lt_pdu, size_t lt_len);
int	mesh_reasm_complete(const struct mesh_reasm *r);
int	mesh_reasm_get(const struct mesh_reasm *r, uint8_t *upper,
	    size_t *upper_len);

/*
 * Segment Acknowledgement message.  MshPRT_v1.1 Section 3.5.3.3.
 *
 * The Segment Acknowledgement is an unsegmented Transport Control PDU with
 * Opcode 0x00.  Its parameters are OBO (1 bit), SeqZero (13 bits), 2 RFU
 * bits and a 32-bit BlockAck bitmap (bit i set => segment i received).
 * mesh_seg_ack_build() emits the 7-octet Lower Transport PDU
 * (0x00 || OBO/SeqZero/RFU || BlockAck); mesh_seg_ack_parse() is its
 * inverse.
 */
struct mesh_seg_ack {
	int		obo;		/* On-Behalf-Of a Low Power node */
	uint16_t	seqzero;	/* 13-bit */
	uint32_t	blockack;	/* 32-bit block acknowledgement bitmap */
};
int	mesh_seg_ack_build(const struct mesh_seg_ack *in, uint8_t *out,
	    size_t *outlen);
int	mesh_seg_ack_parse(const uint8_t *in, size_t inlen,
	    struct mesh_seg_ack *out);

/*
 * BlockAck helpers.  MshPRT_v1.1 Section 3.5.3.3.
 *
 * mesh_blockack_from_segs() computes the BlockAck bitmap from an array of
 * received SegO values (bit SegO set for each).  mesh_blockack_full()
 * returns the "all received" bitmap for a message with the given SegN
 * (bits 0..SegN set).
 */
uint32_t	mesh_blockack_from_segs(const uint8_t *segos, size_t n);
uint32_t	mesh_blockack_full(uint8_t segn);

#endif /* _MESH_TRANSPORT_H_ */
