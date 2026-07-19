/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Proxy protocol (MshPRT_v1.1 Section 6), the GATT bearer,
 * built on the mesh_crypto.[ch] security toolbox (Section 3.8).
 *
 * Proxy PDU wire format (Section 6.3.1, Table 6.1):
 *
 *   octet 0     SAR (2 bits, bits 7..6) | MessageType (6 bits, bits 5..0)
 *   octets 1..  Data (a full message or one segment of one)
 *
 * A proxy configuration message (Section 6.6) is a Network PDU with CTL=1,
 * TTL=0 and DST=0x0000, secured with the managed-flooding EncryptionKey /
 * PrivacyKey under the proxy nonce (Section 3.9.5.4) instead of the network
 * nonce.  The encryption/obfuscation is otherwise identical to the network
 * layer (Section 3.4.5): AES-CCM over DST||TransportPDU with a 64-bit
 * NetMIC, and PECB obfuscation of the CTL/TTL/SEQ/SRC header octets.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "mesh_crypto.h"
#include "mesh_proxy.h"

/* A proxy configuration message is a control PDU: 64-bit NetMIC. */
#define	MESH_PROXY_NETMIC		8
/* Max proxy config TransportPDU: Opcode (1) + Parameters (0..11). */
#define	MESH_PROXY_MAX_CFG_TRANSPORT	12

/* ================================================================
 * Proxy PDU codec (Section 6.3.1).
 * ================================================================ */

static int
mesh_proxy_type_valid(uint8_t type)
{

	return (type <= MESH_PROXY_TYPE_MAX);
}

/*
 * Per-MessageType maximum Data length used to reject oversized reassembled
 * messages (Section 6.3.2.2).  Returns 1 when len exceeds the maximum for
 * the type.
 */
static size_t
mesh_proxy_data_max(uint8_t type)
{

	switch (type) {
	case MESH_PROXY_TYPE_NETWORK:
		return (MESH_PROXY_MAX_NETWORK_PDU);
	case MESH_PROXY_TYPE_BEACON:
		return (MESH_PROXY_MAX_BEACON_PDU);
	case MESH_PROXY_TYPE_CONFIG:
		return (MESH_PROXY_MAX_CONFIG_PDU);
	case MESH_PROXY_TYPE_PROVISIONING:
		return (MESH_PROXY_MAX_PROVISIONING_PDU);
	}
	return (0);
}

static int
mesh_proxy_data_too_long(uint8_t type, size_t len)
{

	return (len > mesh_proxy_data_max(type));
}

int
mesh_proxy_pdu_build(uint8_t sar, uint8_t type, const uint8_t *data,
    size_t datalen, uint8_t *out, size_t outcap, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	if (sar > MESH_PROXY_SAR_LAST || !mesh_proxy_type_valid(type))
		return (-1);
	if (datalen != 0 && data == NULL)
		return (-1);
	if (datalen > MESH_PROXY_MAX_MSG ||
	    outcap < MESH_PROXY_HDR_LEN + datalen)
		return (-1);
	if (sar == MESH_PROXY_SAR_COMPLETE &&
	    mesh_proxy_data_too_long(type, datalen))
		return (-1);

	out[0] = (uint8_t)((sar & 0x03) << 6) | (uint8_t)(type & 0x3f);
	if (datalen != 0)
		memcpy(out + MESH_PROXY_HDR_LEN, data, datalen);
	*outlen = MESH_PROXY_HDR_LEN + datalen;
	return (0);
}

int
mesh_proxy_pdu_parse(const uint8_t *in, size_t inlen, uint8_t *sar,
    uint8_t *type, const uint8_t **data, size_t *datalen)
{
	uint8_t t;

	if (in == NULL || sar == NULL || type == NULL || data == NULL ||
	    datalen == NULL)
		return (-1);
	if (inlen < MESH_PROXY_HDR_LEN)
		return (-1);

	t = (uint8_t)(in[0] & 0x3f);
	if (!mesh_proxy_type_valid(t))		/* RFU MessageType: reject */
		return (-1);

	*sar = (uint8_t)((in[0] >> 6) & 0x03);
	*type = t;
	*data = in + MESH_PROXY_HDR_LEN;
	*datalen = inlen - MESH_PROXY_HDR_LEN;
	return (0);
}

/* ================================================================
 * SAR segmentation and reassembly (Section 6.3.2).
 * ================================================================ */

int
mesh_proxy_segment(uint8_t type, const uint8_t *msg, size_t msglen,
    size_t pdu_max, struct mesh_proxy_seg *segs, size_t maxsegs, size_t *nseg)
{
	size_t datacap, off, i;

	if (msg == NULL || segs == NULL || nseg == NULL)
		return (-1);
	if (!mesh_proxy_type_valid(type))
		return (-1);
	if (pdu_max < MESH_PROXY_HDR_LEN + 1 || pdu_max > MESH_PROXY_MAX_PDU)
		return (-1);
	if (msglen == 0 || mesh_proxy_data_too_long(type, msglen))
		return (-1);

	datacap = pdu_max - MESH_PROXY_HDR_LEN;

	/* A message that fits in one Proxy PDU: a single complete segment. */
	if (msglen <= datacap) {
		if (maxsegs < 1)
			return (-1);
		if (mesh_proxy_pdu_build(MESH_PROXY_SAR_COMPLETE, type, msg,
		    msglen, segs[0].bytes, sizeof(segs[0].bytes),
		    &segs[0].len) != 0)
			return (-1);
		*nseg = 1;
		return (0);
	}

	/* Otherwise first / continuation... / last, in order. */
	off = 0;
	i = 0;
	while (off < msglen) {
		size_t chunk = msglen - off;
		uint8_t sar;

		if (chunk > datacap)
			chunk = datacap;
		if (off == 0)
			sar = MESH_PROXY_SAR_FIRST;
		else if (off + chunk >= msglen)
			sar = MESH_PROXY_SAR_LAST;
		else
			sar = MESH_PROXY_SAR_CONTINUATION;

		if (i >= maxsegs)
			return (-1);
		if (mesh_proxy_pdu_build(sar, type, msg + off, chunk,
		    segs[i].bytes, sizeof(segs[i].bytes), &segs[i].len) != 0)
			return (-1);
		off += chunk;
		i++;
	}
	*nseg = i;
	return (0);
}

void
mesh_proxy_reasm_init(struct mesh_proxy_reasm *r)
{

	if (r != NULL)
		memset(r, 0, sizeof(*r));
}

static void
mesh_proxy_reasm_reset(struct mesh_proxy_reasm *r)
{

	memset(r->buf, 0, sizeof(r->buf));
	r->len = 0;
	r->type = 0;
	r->in_progress = 0;
}

int
mesh_proxy_reasm_feed(struct mesh_proxy_reasm *r, const uint8_t *pdu,
    size_t pdulen, int *complete, uint8_t *out_type, uint8_t *out_msg,
    size_t outcap, size_t *out_msglen)
{
	const uint8_t *data;
	size_t datalen;
	uint8_t sar, type;

	if (complete != NULL)
		*complete = 0;
	if (r == NULL || pdu == NULL || complete == NULL || out_type == NULL ||
	    out_msg == NULL || out_msglen == NULL)
		return (MESH_PROXY_REASM_ERROR);
	*out_msglen = 0;

	/* RFU MessageTypes are ignored and do not disturb an active message. */
	if (pdulen >= MESH_PROXY_HDR_LEN &&
	    (pdu[0] & 0x3f) > MESH_PROXY_TYPE_MAX)
		return (MESH_PROXY_REASM_IGNORED);

	if (mesh_proxy_pdu_parse(pdu, pdulen, &sar, &type, &data, &datalen) != 0)
		goto fail;

	switch (sar) {
	case MESH_PROXY_SAR_COMPLETE:
		/* A complete message is illegal mid-reassembly. */
		if (r->in_progress)
			goto fail;
		if (mesh_proxy_data_too_long(type, datalen))
			goto fail;
		if (datalen > outcap)
			goto fail;
		if (datalen != 0)
			memcpy(out_msg, data, datalen);
		*out_type = type;
		*out_msglen = datalen;
		*complete = 1;
		mesh_proxy_reasm_reset(r);
		return (0);

	case MESH_PROXY_SAR_FIRST:
		/* A first segment is illegal mid-reassembly. */
		if (r->in_progress)
			goto fail;
		if (mesh_proxy_data_too_long(type, datalen))
			goto fail;
		mesh_proxy_reasm_reset(r);
		r->type = type;
		if (datalen != 0)
			memcpy(r->buf, data, datalen);
		r->len = datalen;
		r->in_progress = 1;
		return (0);

	case MESH_PROXY_SAR_CONTINUATION:
		/* A continuation requires a first, with a stable MessageType. */
		if (!r->in_progress || type != r->type)
			goto fail;
		if (datalen > mesh_proxy_data_max(type) - r->len)
			goto fail;
		if (datalen != 0)
			memcpy(r->buf + r->len, data, datalen);
		r->len += datalen;
		return (0);

	case MESH_PROXY_SAR_LAST:
		/* A last segment requires a first, with a stable MessageType. */
		if (!r->in_progress || type != r->type)
			goto fail;
		if (datalen > mesh_proxy_data_max(type) - r->len)
			goto fail;
		if (datalen != 0)
			memcpy(r->buf + r->len, data, datalen);
		r->len += datalen;
		if (mesh_proxy_data_too_long(type, r->len))
			goto fail;
		if (r->len > outcap)
			goto fail;
		if (r->len != 0)
			memcpy(out_msg, r->buf, r->len);
		*out_type = type;
		*out_msglen = r->len;
		*complete = 1;
		mesh_proxy_reasm_reset(r);
		return (0);
	}

fail:
	mesh_proxy_reasm_reset(r);
	return (MESH_PROXY_REASM_ERROR);
}

/* ================================================================
 * Proxy filter state machine (Sections 6.4, 6.7).
 * ================================================================ */

static int
mesh_proxy_filter_find(const struct mesh_proxy_filter *f, uint16_t dst,
    size_t *idx)
{
	size_t i;

	for (i = 0; i < f->count; i++) {
		if (f->list[i] == dst) {
			if (idx != NULL)
				*idx = i;
			return (1);
		}
	}
	return (0);
}

void
mesh_proxy_filter_init(struct mesh_proxy_filter *f)
{

	if (f == NULL)
		return;
	memset(f, 0, sizeof(*f));
	f->type = MESH_PROXY_FILTER_ACCEPT;	/* default: accept, empty list */
}

int
mesh_proxy_filter_set_type(struct mesh_proxy_filter *f, uint8_t type)
{

	if (f == NULL)
		return (-1);
	if (type != MESH_PROXY_FILTER_ACCEPT && type != MESH_PROXY_FILTER_REJECT)
		return (-1);
	/* Setting the filter type clears the list (Section 6.6.1). */
	memset(f->list, 0, sizeof(f->list));
	f->count = 0;
	f->type = type;
	return (0);
}

int
mesh_proxy_filter_add(struct mesh_proxy_filter *f, const uint16_t *addrs,
    size_t n)
{
	size_t i;

	if (f == NULL || (n != 0 && addrs == NULL))
		return (-1);
	for (i = 0; i < n; i++) {
		if (mesh_proxy_filter_find(f, addrs[i], NULL))
			continue;		/* skip duplicates */
		if (f->count >= MESH_PROXY_FILTER_MAX)
			return (-1);		/* bounded list full */
		f->list[f->count++] = addrs[i];
	}
	return (0);
}

int
mesh_proxy_filter_remove(struct mesh_proxy_filter *f, const uint16_t *addrs,
    size_t n)
{
	size_t i, idx;

	if (f == NULL || (n != 0 && addrs == NULL))
		return (-1);
	for (i = 0; i < n; i++) {
		if (!mesh_proxy_filter_find(f, addrs[i], &idx))
			continue;
		/* Compact the list over the removed entry. */
		memmove(&f->list[idx], &f->list[idx + 1],
		    (f->count - idx - 1) * sizeof(f->list[0]));
		f->count--;
		f->list[f->count] = 0;
	}
	return (0);
}

int
mesh_proxy_filter_accepts(const struct mesh_proxy_filter *f, uint16_t dst)
{
	int listed;

	if (f == NULL)
		return (0);
	listed = mesh_proxy_filter_find(f, dst, NULL);
	if (f->type == MESH_PROXY_FILTER_ACCEPT)
		return (listed ? 1 : 0);	/* accept list: pass only listed */
	return (listed ? 0 : 1);		/* reject list: block only listed */
}

/* ================================================================
 * Proxy configuration message codec (Section 6.6).
 * ================================================================ */

int
mesh_proxy_cfg_set_filter_build(uint8_t filter_type, uint8_t *out,
    size_t outcap, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	if (filter_type != MESH_PROXY_FILTER_ACCEPT &&
	    filter_type != MESH_PROXY_FILTER_REJECT)
		return (-1);
	if (outcap < 2)
		return (-1);
	out[0] = MESH_PROXY_OP_SET_FILTER_TYPE;
	out[1] = filter_type;
	*outlen = 2;
	return (0);
}

int
mesh_proxy_cfg_addr_build(uint8_t opcode, const uint16_t *addrs, size_t n,
    uint8_t *out, size_t outcap, size_t *outlen)
{
	size_t i;

	if (out == NULL || outlen == NULL || (n != 0 && addrs == NULL))
		return (-1);
	if (opcode != MESH_PROXY_OP_ADD_ADDR &&
	    opcode != MESH_PROXY_OP_REMOVE_ADDR)
		return (-1);
	if (n > MESH_PROXY_MAX_ADDR_PER_MSG)
		return (-1);
	if (outcap < 1 + 2 * n)
		return (-1);
	out[0] = opcode;
	for (i = 0; i < n; i++) {
		out[1 + 2 * i] = (uint8_t)(addrs[i] >> 8);
		out[2 + 2 * i] = (uint8_t)addrs[i];
	}
	*outlen = 1 + 2 * n;
	return (0);
}

int
mesh_proxy_cfg_filter_status_build(uint8_t filter_type, uint16_t list_size,
    uint8_t *out, size_t outcap, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	if (filter_type != MESH_PROXY_FILTER_ACCEPT &&
	    filter_type != MESH_PROXY_FILTER_REJECT)
		return (-1);
	if (outcap < 4)
		return (-1);
	out[0] = MESH_PROXY_OP_FILTER_STATUS;
	out[1] = filter_type;
	out[2] = (uint8_t)(list_size >> 8);
	out[3] = (uint8_t)list_size;
	*outlen = 4;
	return (0);
}

int
mesh_proxy_cfg_parse(const uint8_t *in, size_t inlen, struct mesh_proxy_cfg *out)
{
	size_t i, n;

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (inlen < 1)
		return (-1);

	out->opcode = in[0];
	switch (in[0]) {
	case MESH_PROXY_OP_SET_FILTER_TYPE:
		if (inlen != 2)
			goto bad;
		if (in[1] != MESH_PROXY_FILTER_ACCEPT &&
		    in[1] != MESH_PROXY_FILTER_REJECT)
			goto bad;
		out->filter_type = in[1];
		return (0);

	case MESH_PROXY_OP_ADD_ADDR:
	case MESH_PROXY_OP_REMOVE_ADDR:
		if (((inlen - 1) & 0x01) != 0)		/* AddressArray = 2*N */
			goto bad;
		n = (inlen - 1) / 2;
		if (n > MESH_PROXY_MAX_ADDR_PER_MSG)
			goto bad;
		for (i = 0; i < n; i++)
			out->addrs[i] = (uint16_t)((in[1 + 2 * i] << 8) |
			    in[2 + 2 * i]);
		out->naddr = n;
		return (0);

	case MESH_PROXY_OP_FILTER_STATUS:
		if (inlen != 4)
			goto bad;
		if (in[1] != MESH_PROXY_FILTER_ACCEPT &&
		    in[1] != MESH_PROXY_FILTER_REJECT)
			goto bad;
		out->filter_type = in[1];
		out->list_size = (uint16_t)((in[2] << 8) | in[3]);
		return (0);

	default:
		goto bad;
	}

bad:
	memset(out, 0, sizeof(*out));
	return (-1);
}

/* ================================================================
 * Secured Proxy Configuration PDU (Section 6.6 + proxy nonce 3.9.5.4).
 * Mirrors the network encryption/obfuscation (Section 3.4.5) but uses the
 * proxy nonce and forces CTL=1, TTL=0, DST=0x0000.
 * ================================================================ */

/*
 * Privacy ECB block for header obfuscation (Section 3.4.5.2).  enc_payload
 * points at the first 7 octets of EncDST||EncTransportPDU||NetMIC.
 */
static int
mesh_proxy_pecb(const uint8_t privkey[16], uint32_t iv_index,
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

int
mesh_proxy_cfg_encrypt(const uint8_t enckey[16], const uint8_t privkey[16],
    uint8_t nid, uint32_t iv_index, uint32_t seq, uint16_t src,
    const uint8_t *msg, size_t msglen, uint8_t *out, size_t *outlen)
{
	uint8_t nonce[13];
	uint8_t plain[2 + MESH_PROXY_MAX_CFG_TRANSPORT];
	uint8_t pecb[16];
	size_t plen, i;
	uint8_t ivi;
	int rc = -1;

	if (enckey == NULL || privkey == NULL || msg == NULL || out == NULL ||
	    outlen == NULL)
		return (-1);
	if (nid > 0x7f || seq > 0xffffff || src < 0x0001 || src > 0x7fff)
		return (-1);
	if (msglen == 0 || msglen > MESH_PROXY_MAX_CFG_TRANSPORT)
		return (-1);

	ivi = (uint8_t)(iv_index & 0x01);

	/* CCM plaintext: DST (unassigned) || TransportPDU. */
	plain[0] = 0x00;
	plain[1] = 0x00;
	memcpy(plain + 2, msg, msglen);
	plen = 2 + msglen;

	/* Cleartext header: IVI/NID, then CTL=1/TTL=0 | SEQ | SRC. */
	out[0] = (uint8_t)((ivi & 0x01) << 7) | (uint8_t)(nid & 0x7f);
	out[1] = 0x80;				/* CTL=1, TTL=0 */
	out[2] = (uint8_t)(seq >> 16);
	out[3] = (uint8_t)(seq >> 8);
	out[4] = (uint8_t)seq;
	out[5] = (uint8_t)(src >> 8);
	out[6] = (uint8_t)src;

	mesh_proxy_nonce(nonce, seq, src, iv_index);

	if (mesh_aes_ccm_encrypt(enckey, nonce, NULL, 0, plain, plen,
	    out + 7, out + 7 + plen, MESH_PROXY_NETMIC) != 0)
		goto out;

	if (mesh_proxy_pecb(privkey, iv_index, out + 7, pecb) != 0)
		goto out;
	for (i = 0; i < 6; i++)
		out[1 + i] ^= pecb[i];

	*outlen = 7 + plen + MESH_PROXY_NETMIC;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	explicit_bzero(plain, sizeof(plain));
	explicit_bzero(pecb, sizeof(pecb));
	if (rc != 0) {
		memset(out, 0, MESH_PROXY_MAX_NETWORK_PDU);
		*outlen = 0;
	}
	return (rc);
}

int
mesh_proxy_cfg_decrypt(const uint8_t enckey[16], const uint8_t privkey[16],
    uint8_t nid, uint32_t iv_index, const uint8_t *in, size_t inlen,
    uint32_t *seq, uint16_t *src, uint8_t *msg, size_t msgcap, size_t *msglen)
{
	uint8_t nonce[13];
	uint8_t hdr[6];
	uint8_t pecb[16];
	uint8_t plain[2 + MESH_PROXY_MAX_CFG_TRANSPORT];
	size_t clen, tlen;
	uint32_t seq_;
	uint16_t src_, dst;
	int rc = -1;

	if (seq != NULL)
		*seq = 0;
	if (src != NULL)
		*src = 0;
	if (msg != NULL && msgcap != 0)
		memset(msg, 0, msgcap);
	if (enckey == NULL || privkey == NULL || in == NULL || msg == NULL ||
	    msglen == NULL)
		return (-1);
	*msglen = 0;
	if (nid > 0x7f)
		return (-1);

	/*
	 * Guard the in[0] read of the NID gate below: an empty PDU has no
	 * octet 0 to inspect.  (The full minimum-length check follows.)
	 */
	if (inlen == 0)
		return (-1);

	/* NID gate: the received octet-0 NID must match this key. */
	if ((in[0] & 0x7f) != (nid & 0x7f))
		return (-1);

	/*
	 * Minimum: IVI/NID (1) + header (6) + EncDST (2) + at least one octet
	 * of EncTransportPDU + 64-bit NetMIC (8).  The 7-octet Privacy Random
	 * is also available at in[7] for this minimum.
	 */
	if (inlen < 1 + 6 + 2 + 1 + MESH_PROXY_NETMIC)
		return (-1);

	if (mesh_proxy_pecb(privkey, iv_index, in + 7, pecb) != 0)
		goto out;
	memcpy(hdr, in + 1, 6);
	{
		size_t i;

		for (i = 0; i < 6; i++)
			hdr[i] ^= pecb[i];
	}

	if (hdr[0] != 0x80)			/* proxy config is CTL=1, TTL=0 */
		goto out;
	seq_ = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) |
	    (uint32_t)hdr[3];
	src_ = (uint16_t)((hdr[4] << 8) | hdr[5]);
	if (src_ < 0x0001 || src_ > 0x7fff)
		goto out;

	clen = inlen - 7 - MESH_PROXY_NETMIC;
	if (clen < 2 + 1)			/* EncDST (2) + >=1 transport */
		goto out;
	tlen = clen - 2;
	if (tlen > MESH_PROXY_MAX_CFG_TRANSPORT || tlen > msgcap)
		goto out;

	mesh_proxy_nonce(nonce, seq_, src_, iv_index);

	if (mesh_aes_ccm_decrypt(enckey, nonce, NULL, 0, in + 7, clen,
	    plain, in + 7 + clen, MESH_PROXY_NETMIC) != 0)
		goto out;

	dst = (uint16_t)((plain[0] << 8) | plain[1]);
	if (dst != 0x0000)			/* proxy config DST = unassigned */
		goto out;

	if (seq != NULL)
		*seq = seq_;
	if (src != NULL)
		*src = src_;
	memcpy(msg, plain + 2, tlen);
	*msglen = tlen;
	rc = 0;
out:
	explicit_bzero(nonce, sizeof(nonce));
	explicit_bzero(hdr, sizeof(hdr));
	explicit_bzero(pecb, sizeof(pecb));
	explicit_bzero(plain, sizeof(plain));
	if (rc != 0) {
		if (seq != NULL)
			*seq = 0;
		if (src != NULL)
			*src = 0;
		*msglen = 0;
	}
	return (rc);
}

/* ================================================================
 * Proxy connectable advertising (Section 7).  The Mesh Proxy Service is
 * advertised in a Service Data - 16-bit UUID AD structure carrying either
 * the Network ID (Section 7.2.2.2.1) or the Node Identity (Section
 * 7.2.2.2.2).
 * ================================================================ */

/*
 * IdentityKey = k1(NetKey, s1("nkik"), "id128" || 0x01).
 * MshPRT_v1.1 Section 3.9.6.3.4.
 */
int
mesh_proxy_identity_key(const uint8_t netkey[16], uint8_t out[16])
{
	static const char nkik[] = "nkik";
	static const uint8_t id128[] = { 'i', 'd', '1', '2', '8', 0x01 };
	uint8_t salt[16];
	int rc;

	if (netkey == NULL || out == NULL)
		return (-1);
	if (mesh_s1((const uint8_t *)nkik, sizeof(nkik) - 1, salt) != 0) {
		memset(out, 0, 16);
		return (-1);
	}
	rc = mesh_k1(netkey, 16, salt, id128, sizeof(id128), out);
	explicit_bzero(salt, sizeof(salt));
	if (rc != 0)
		memset(out, 0, 16);
	return (rc);
}

/*
 * Node Identity Hash (Section 7.2.2.2.2):
 *   Hash = e(IdentityKey, Padding(6 x 0x00) || Random(8) || Address(2))
 * taking the 64 least significant bits (rightmost 8 octets) of the result.
 */
int
mesh_proxy_identity_hash(const uint8_t identity_key[16], uint16_t addr,
    const uint8_t random[MESH_PROXY_ID_RANDOM_LEN],
    uint8_t hash[MESH_PROXY_ID_HASH_LEN])
{
	uint8_t in[16], out[16];
	int rc;

	if (identity_key == NULL || random == NULL || hash == NULL)
		return (-1);
	memset(in, 0, 6);				/* 48-bit padding */
	memcpy(in + 6, random, MESH_PROXY_ID_RANDOM_LEN);
	in[14] = (uint8_t)(addr >> 8);
	in[15] = (uint8_t)addr;

	rc = mesh_aes128_e(identity_key, in, out);
	if (rc == 0)
		memcpy(hash, out + 8, MESH_PROXY_ID_HASH_LEN);
	else
		memset(hash, 0, MESH_PROXY_ID_HASH_LEN);
	explicit_bzero(out, sizeof(out));
	return (rc);
}

/*
 * Build the Network ID connectable-advertising AD structure (Section
 * 7.2.2.2.1): a Service Data - 16-bit UUID structure whose value is the Mesh
 * Proxy Service UUID (0x1828), the Network ID identification type (0x00), and
 * the 8-octet Network ID (k3 of the NetKey).
 */
int
mesh_proxy_adv_network_id_build(const uint8_t netkey[16], uint8_t *out,
    size_t *outlen)
{
	uint8_t netid[MESH_NETWORK_ID_ADV_LEN];
	int rc = -1;

	if (netkey == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (mesh_k3(netkey, netid) != 0)
		goto out;

	out[0] = (uint8_t)(MESH_PROXY_ADV_NETWORK_ID_LEN - 1);	/* AD length */
	out[1] = MESH_AD_TYPE_SERVICE_DATA_16;
	out[2] = (uint8_t)(MESH_PROXY_SERVICE_UUID & 0xff);	/* UUID, LE */
	out[3] = (uint8_t)(MESH_PROXY_SERVICE_UUID >> 8);
	out[4] = MESH_PROXY_ADV_NETWORK_ID;
	memcpy(out + 5, netid, MESH_NETWORK_ID_ADV_LEN);
	*outlen = MESH_PROXY_ADV_NETWORK_ID_LEN;
	rc = 0;
out:
	explicit_bzero(netid, sizeof(netid));
	if (rc != 0) {
		memset(out, 0, MESH_PROXY_ADV_NETWORK_ID_LEN);
		*outlen = 0;
	}
	return (rc);
}

/*
 * Build the Node Identity connectable-advertising AD structure (Section
 * 7.2.2.2.2): a Service Data - 16-bit UUID structure whose value is the Mesh
 * Proxy Service UUID (0x1828), the Node Identity identification type (0x01),
 * the 8-octet Hash derived from the IdentityKey/Address/Random, and the
 * 8-octet Random.
 */
int
mesh_proxy_adv_node_identity_build(const uint8_t identity_key[16],
    uint16_t addr, const uint8_t random[MESH_PROXY_ID_RANDOM_LEN],
    uint8_t *out, size_t *outlen)
{
	uint8_t hash[MESH_PROXY_ID_HASH_LEN];

	if (identity_key == NULL || random == NULL || out == NULL ||
	    outlen == NULL)
		return (-1);
	if (mesh_proxy_identity_hash(identity_key, addr, random, hash) != 0) {
		memset(out, 0, MESH_PROXY_ADV_NODE_IDENTITY_LEN);
		*outlen = 0;
		return (-1);
	}

	out[0] = (uint8_t)(MESH_PROXY_ADV_NODE_IDENTITY_LEN - 1);
	out[1] = MESH_AD_TYPE_SERVICE_DATA_16;
	out[2] = (uint8_t)(MESH_PROXY_SERVICE_UUID & 0xff);
	out[3] = (uint8_t)(MESH_PROXY_SERVICE_UUID >> 8);
	out[4] = MESH_PROXY_ADV_NODE_IDENTITY;
	memcpy(out + 5, hash, MESH_PROXY_ID_HASH_LEN);
	memcpy(out + 5 + MESH_PROXY_ID_HASH_LEN, random,
	    MESH_PROXY_ID_RANDOM_LEN);
	*outlen = MESH_PROXY_ADV_NODE_IDENTITY_LEN;
	return (0);
}
