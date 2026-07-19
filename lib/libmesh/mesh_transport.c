/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh transport layer (MshPRT_v1.1 Sections 3.5 and 3.6), built
 * on the mesh_crypto.[ch] security toolbox (Section 3.8).
 *
 * Upper transport (Section 3.6.5.1) AES-CCM encrypts the Access Payload:
 *
 *   nonce  = application nonce (AKF=1) or device nonce (AKF=0)
 *   AAD    = 16-octet Label UUID when DST is a virtual address, else none
 *   output = Encrypted Access Payload || TransMIC   (the Upper Transport
 *            Access PDU); TransMIC is 32 bits, or 64 bits when the message
 *            is segmented with SZMIC=1.
 *
 * Lower transport (Section 3.5.2) frames the Upper Transport PDU:
 *
 *   unsegmented access  : SEG(0)|AKF(1)|AID(6) | UpperTransportAccessPDU
 *   segmented access    : SEG(1)|AKF(1)|AID(6) |
 *                         SZMIC(1)|SeqZero(13)|SegO(5)|SegN(5) | segment
 *   unsegmented control : SEG(0)|Opcode(7) | parameters
 *   segmented control   : SEG(1)|Opcode(7) |
 *                         RFU(1)|SeqZero(13)|SegO(5)|SegN(5) | segment
 *
 * SAR (Section 3.5.3) splits a large Upper Transport PDU into 12-octet
 * access segments and reassembles them, keyed by (SRC, SeqZero).  The
 * Segment Acknowledgement (Section 3.5.3.3) is an unsegmented control PDU
 * (Opcode 0x00) carrying OBO|SeqZero|RFU|BlockAck.
 *
 * All multi-octet fields are big-endian on the wire; secrets are cleared
 * with explicit_bzero(); outputs are zeroed on failure.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_probes.h"
#include "mesh_transport.h"

/* ================================================================
 * Upper Transport Access PDU (Section 3.6.5.1).
 * ================================================================ */

int
mesh_upper_encrypt(const uint8_t key[16], int akf, int szmic,
    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index,
    const uint8_t *label_uuid, const uint8_t *access, size_t access_len,
    uint8_t *out, size_t *outlen)
{
	uint8_t nonce[13];
	size_t miclen;
	int rc = -1;

	if (key == NULL || access == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (access_len == 0 || access_len > MESH_ACCESS_MAX)
		return (-1);
	if (seq > 0xffffff)
		return (-1);

	miclen = szmic ? MESH_TRANS_MIC64 : MESH_TRANS_MIC32;

	if (akf)
		mesh_application_nonce(nonce, (uint8_t)(szmic ? 1 : 0), seq,
		    src, dst, iv_index);
	else
		mesh_device_nonce(nonce, (uint8_t)(szmic ? 1 : 0), seq, src,
		    dst, iv_index);

	if (mesh_aes_ccm_encrypt(key, nonce, label_uuid,
	    label_uuid != NULL ? MESH_LABEL_UUID_LEN : 0, access, access_len,
	    out, out + access_len, miclen) != 0)
		goto out;

	*outlen = access_len + miclen;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	if (rc != 0) {
		memset(out, 0, access_len + miclen);
		*outlen = 0;
	}
	/* Upper-transport encrypt boundary: akf/szmic/len, never key/payload. */
	MESH_PROBE_TRANSPORT_ENC(akf ? 1 : 0, szmic ? 1 : 0, (int)access_len);
	return (rc);
}

int
mesh_upper_decrypt(const uint8_t key[16], int akf, int szmic,
    uint32_t seq, uint16_t src, uint16_t dst, uint32_t iv_index,
    const uint8_t *label_uuid, const uint8_t *upper, size_t upper_len,
    uint8_t *access, size_t *access_len)
{
	uint8_t nonce[13];
	size_t miclen, clen;
	int rc = -1;

	if (key == NULL || upper == NULL || access == NULL ||
	    access_len == NULL)
		return (-1);
	if (seq > 0xffffff)
		return (-1);

	miclen = szmic ? MESH_TRANS_MIC64 : MESH_TRANS_MIC32;
	if (upper_len <= miclen || upper_len - miclen > MESH_ACCESS_MAX)
		return (-1);
	clen = upper_len - miclen;

	if (akf)
		mesh_application_nonce(nonce, (uint8_t)(szmic ? 1 : 0), seq,
		    src, dst, iv_index);
	else
		mesh_device_nonce(nonce, (uint8_t)(szmic ? 1 : 0), seq, src,
		    dst, iv_index);

	if (mesh_aes_ccm_decrypt(key, nonce, label_uuid,
	    label_uuid != NULL ? MESH_LABEL_UUID_LEN : 0, upper, clen,
	    access, upper + clen, miclen) != 0)
		goto out;

	*access_len = clen;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	if (rc != 0) {
		memset(access, 0, clen);
		*access_len = 0;
	}
	/* Upper-transport decrypt verdict: akf + result (0 ok, -1 MIC fail). */
	MESH_PROBE_TRANSPORT_DEC(akf ? 1 : 0, rc);
	return (rc);
}

/* ================================================================
 * Lower Transport PDU codec (Section 3.5.2).
 * ================================================================ */

/*
 * Pack the 3-octet SZMIC/RFU | SeqZero | SegO | SegN word shared by the
 * segmented access and segmented control headers.  bit23 carries SZMIC
 * (access) or RFU (control); the caller supplies it in hi.
 */
static void
mesh_pack_seghdr(uint8_t out[3], int hi, uint16_t seqzero, uint8_t sego,
    uint8_t segn)
{
	uint32_t w;

	w = ((uint32_t)(hi & 0x01) << 23) |
	    ((uint32_t)(seqzero & 0x1fff) << 10) |
	    ((uint32_t)(sego & 0x1f) << 5) |
	    (uint32_t)(segn & 0x1f);
	out[0] = (uint8_t)(w >> 16);
	out[1] = (uint8_t)(w >> 8);
	out[2] = (uint8_t)w;
}

static void
mesh_unpack_seghdr(const uint8_t in[3], int *hi, uint16_t *seqzero,
    uint8_t *sego, uint8_t *segn)
{
	uint32_t w;

	w = ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | (uint32_t)in[2];
	*hi = (int)((w >> 23) & 0x01);
	*seqzero = (uint16_t)((w >> 10) & 0x1fff);
	*sego = (uint8_t)((w >> 5) & 0x1f);
	*segn = (uint8_t)(w & 0x1f);
}

int
mesh_lower_build(const struct mesh_lower *in, uint8_t *out, size_t *outlen)
{
	size_t off;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->data_len > MESH_LOWER_DATA_MAX)
		return (-1);
	if (in->seg) {
		size_t segmax = in->ctl ? MESH_SEG_CONTROL_LEN :
		    MESH_SEG_ACCESS_LEN;

		if (in->data_len == 0 || in->data_len > segmax)
			return (-1);
		if (in->sego > 0x1f || in->segn > 0x1f || in->sego > in->segn ||
		    in->seqzero > 0x1fff)
			return (-1);
	} else if (!in->ctl) {
		/*
		 * Unsegmented access (Section 3.5.2.1): the Upper Transport
		 * Access PDU is at most 15 octets; anything larger must be
		 * segmented.  Reject rather than emit an out-of-spec frame.
		 */
		if (in->data_len > MESH_UNSEG_ACCESS_MAX)
			return (-1);
	} else if (in->data_len > MESH_UNSEG_CONTROL_MAX) {
		return (-1);
	}

	if (in->ctl) {
		if (in->opcode > 0x7f)
			return (-1);
		out[0] = (uint8_t)((in->seg & 0x01) << 7) |
		    (uint8_t)(in->opcode & 0x7f);
	} else {
		if (in->aid > 0x3f)
			return (-1);
		out[0] = (uint8_t)((in->seg & 0x01) << 7) |
		    (uint8_t)((in->akf ? 1 : 0) << 6) |
		    (uint8_t)(in->aid & 0x3f);
	}
	off = 1;

	if (in->seg) {
		/* SZMIC bit for access, RFU (0) for control. */
		mesh_pack_seghdr(out + off, in->ctl ? 0 : (in->szmic ? 1 : 0),
		    in->seqzero, in->sego, in->segn);
		off += 3;
	}

	memcpy(out + off, in->data, in->data_len);
	*outlen = off + in->data_len;
	return (0);
}

int
mesh_lower_parse(int ctl, const uint8_t *in, size_t inlen, struct mesh_lower *out)
{
	size_t off;
	int hi;

	if (in == NULL || out == NULL || inlen == 0)
		return (-1);
	memset(out, 0, sizeof(*out));

	out->ctl = ctl ? 1 : 0;
	out->seg = (int)(in[0] >> 7);

	if (ctl)
		out->opcode = (uint8_t)(in[0] & 0x7f);
	else {
		out->akf = (int)((in[0] >> 6) & 0x01);
		out->aid = (uint8_t)(in[0] & 0x3f);
	}
	off = 1;

	if (out->seg) {
		if (inlen < 4) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
		mesh_unpack_seghdr(in + 1, &hi, &out->seqzero, &out->sego,
		    &out->segn);
		if (!ctl)
			out->szmic = hi;
		if (out->sego > out->segn) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
		off = 4;
	}

	if (inlen - off > MESH_LOWER_DATA_MAX ||
	    (out->seg && inlen - off >
	    (ctl ? MESH_SEG_CONTROL_LEN : MESH_SEG_ACCESS_LEN)) ||
	    (out->seg && inlen - off == 0) ||
	    (!out->seg && !ctl && inlen - off > MESH_UNSEG_ACCESS_MAX) ||
	    (!out->seg && ctl && inlen - off > MESH_UNSEG_CONTROL_MAX)) {
		/* Section 3.5.2.1: unsegmented access is at most 15 octets. */
		memset(out, 0, sizeof(*out));
		return (-1);
	}

	out->data_len = inlen - off;
	memcpy(out->data, in + off, out->data_len);
	return (0);
}

/* ================================================================
 * Segmentation (SAR, Section 3.5.3.1).
 * ================================================================ */

int
mesh_sar_segment(int akf, uint8_t aid, int szmic, uint16_t seqzero,
    const uint8_t *upper, size_t upper_len, struct mesh_seg *out, size_t max,
    size_t *nseg)
{
	struct mesh_lower lo;
	size_t nseg_l, i, off, chunk;
	uint8_t segn;

	if (upper == NULL || out == NULL || nseg == NULL)
		return (-1);
	if (upper_len == 0 || upper_len > MESH_UPPER_MAX)
		return (-1);
	if (aid > 0x3f || seqzero > 0x1fff)
		return (-1);

	nseg_l = (upper_len + MESH_SEG_ACCESS_LEN - 1) / MESH_SEG_ACCESS_LEN;
	if (nseg_l == 0 || nseg_l > MESH_SEG_MAX || nseg_l > max)
		return (-1);
	segn = (uint8_t)(nseg_l - 1);

	for (i = 0; i < nseg_l; i++) {
		size_t olen;

		off = i * MESH_SEG_ACCESS_LEN;
		chunk = upper_len - off;
		if (chunk > MESH_SEG_ACCESS_LEN)
			chunk = MESH_SEG_ACCESS_LEN;

		memset(&lo, 0, sizeof(lo));
		lo.seg = 1;
		lo.ctl = 0;
		lo.akf = akf ? 1 : 0;
		lo.aid = aid;
		lo.szmic = szmic ? 1 : 0;
		lo.seqzero = seqzero;
		lo.sego = (uint8_t)i;
		lo.segn = segn;
		memcpy(lo.data, upper + off, chunk);
		lo.data_len = chunk;

		if (mesh_lower_build(&lo, out[i].bytes, &olen) != 0) {
			explicit_bzero(&lo, sizeof(lo));
			memset(out, 0, sizeof(*out) * nseg_l);
			return (-1);
		}
		out[i].len = olen;
	}
	explicit_bzero(&lo, sizeof(lo));

	*nseg = nseg_l;
	/* SAR: message segmented into nseg_l segments (SegN = nseg_l - 1). */
	MESH_PROBE_TRANSPORT_SEG(seqzero, 0, segn);
	return (0);
}

/* ================================================================
 * Reassembly (SAR, Section 3.5.3.2).
 * ================================================================ */

void
mesh_reasm_init(struct mesh_reasm *r)
{

	if (r != NULL)
		memset(r, 0, sizeof(*r));
}

int
mesh_reasm_complete(const struct mesh_reasm *r)
{

	if (r == NULL || !r->active)
		return (0);
	return (r->blockack == mesh_blockack_full(r->segn));
}

int
mesh_reasm_input(struct mesh_reasm *r, uint16_t src, const uint8_t *lt_pdu,
    size_t lt_len)
{

	return (mesh_reasm_input_ctl(r, src, 0, lt_pdu, lt_len));
}

int
mesh_reasm_input_ctl(struct mesh_reasm *r, uint16_t src, int ctl,
    const uint8_t *lt_pdu, size_t lt_len)
{
	struct mesh_lower lo;
	uint32_t bit;
	size_t seg_size;

	if (r == NULL || lt_pdu == NULL)
		return (-1);
	if (mesh_lower_parse(ctl, lt_pdu, lt_len, &lo) != 0)
		return (-1);
	if (!lo.seg)
		return (-1);
	seg_size = ctl ? MESH_SEG_CONTROL_LEN : MESH_SEG_ACCESS_LEN;
	/* Every non-final segment is the full access/control segment size. */
	if (lo.sego != lo.segn && lo.data_len != seg_size)
		return (-1);
	if (lo.segn >= MESH_SEG_MAX)
		return (-1);

	/* Start a fresh session on first use or a new (SRC, SeqZero). */
	if (!r->active || r->src != src || r->seqzero != lo.seqzero) {
		memset(r, 0, sizeof(*r));
		r->active = 1;
		r->ctl = ctl ? 1 : 0;
		r->src = src;
		r->seqzero = lo.seqzero;
		r->segn = lo.segn;
		r->akf = lo.akf;
		r->aid = lo.aid;
		r->szmic = lo.szmic;
		r->opcode = lo.opcode;
		r->seg_size = (uint8_t)seg_size;
	} else if (r->ctl != (ctl ? 1 : 0) || r->segn != lo.segn ||
	    r->akf != lo.akf || r->aid != lo.aid ||
	    r->szmic != lo.szmic || r->opcode != lo.opcode) {
		/* All segmentation-header fields are invariant in a session. */
		return (-1);
	}

	bit = (uint32_t)1 << lo.sego;
	if (r->blockack & bit) {	/* duplicate: accept idempotently */
		int done = mesh_reasm_complete(r) ? 1 : 0;

		MESH_PROBE_TRANSPORT_REASM(src, lo.sego, done);
		return (done);
	}

	memcpy(r->buf + (size_t)lo.sego * seg_size, lo.data,
	    lo.data_len);
	r->seg_len[lo.sego] = lo.data_len;
	r->blockack |= bit;

	{
		int done = mesh_reasm_complete(r) ? 1 : 0;

		/* SAR reassembly: this segment ingested; complete==1 at the last. */
		MESH_PROBE_TRANSPORT_REASM(src, lo.sego, done);
		return (done);
	}
}

int
mesh_reasm_get(const struct mesh_reasm *r, uint8_t *upper, size_t *upper_len)
{
	size_t total, i;

	if (r == NULL || upper == NULL || upper_len == NULL)
		return (-1);
	if (!mesh_reasm_complete(r))
		return (-1);

	total = 0;
	for (i = 0; i <= r->segn; i++)
		total += r->seg_len[i];
	if (total == 0 || total > MESH_UPPER_MAX)
		return (-1);

	memcpy(upper, r->buf, total);
	*upper_len = total;
	return (0);
}

/* ================================================================
 * Segment Acknowledgement message (Section 3.5.3.3).
 * ================================================================ */

int
mesh_seg_ack_build(const struct mesh_seg_ack *in, uint8_t *out, size_t *outlen)
{
	uint16_t w;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->seqzero > 0x1fff)
		return (-1);

	out[0] = 0x00;			/* SEG=0, Opcode=0x00 (Segment Ack) */
	w = (uint16_t)((in->obo ? 1 : 0) << 15) |
	    (uint16_t)((in->seqzero & 0x1fff) << 2);	/* 2 RFU bits = 0 */
	out[1] = (uint8_t)(w >> 8);
	out[2] = (uint8_t)w;
	out[3] = (uint8_t)(in->blockack >> 24);
	out[4] = (uint8_t)(in->blockack >> 16);
	out[5] = (uint8_t)(in->blockack >> 8);
	out[6] = (uint8_t)in->blockack;
	*outlen = MESH_SEG_ACK_LEN;
	return (0);
}

int
mesh_seg_ack_parse(const uint8_t *in, size_t inlen, struct mesh_seg_ack *out)
{
	uint16_t w;

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen != MESH_SEG_ACK_LEN)
		return (-1);
	/* Must be an unsegmented control PDU with Opcode 0x00. */
	if (in[0] != 0x00)
		return (-1);

	w = (uint16_t)((in[1] << 8) | in[2]);
	out->obo = (int)((w >> 15) & 0x01);
	out->seqzero = (uint16_t)((w >> 2) & 0x1fff);
	out->blockack = ((uint32_t)in[3] << 24) | ((uint32_t)in[4] << 16) |
	    ((uint32_t)in[5] << 8) | (uint32_t)in[6];
	return (0);
}

/* ================================================================
 * BlockAck helpers (Section 3.5.3.3).
 * ================================================================ */

uint32_t
mesh_blockack_from_segs(const uint8_t *segos, size_t n)
{
	uint32_t ack = 0;
	size_t i;

	if (segos == NULL)
		return (0);
	for (i = 0; i < n; i++) {
		if (segos[i] < MESH_SEG_MAX)
			ack |= (uint32_t)1 << segos[i];
	}
	return (ack);
}

uint32_t
mesh_blockack_full(uint8_t segn)
{

	if (segn >= MESH_SEG_MAX - 1)
		return (0xffffffffu);
	return (((uint32_t)1 << (segn + 1)) - 1);
}
