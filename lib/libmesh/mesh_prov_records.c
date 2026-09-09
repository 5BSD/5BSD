/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh provisioning records: codec, store and the two role halves.
 * MshPRT_v1.1.1 Sections 5.4.1.11 - 5.4.1.14 and 5.4.2.6.  See
 * mesh_prov_records.h for the model.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mesh_prov_records.h"

static void
put_be16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
get_be16(const uint8_t *p)
{

	return ((uint16_t)((uint16_t)p[0] << 8 | p[1]));
}

/* Is this one of the Record IDs defined by Table 5.52? */
static int
record_id_valid(uint16_t id)
{

	return (id <= MESH_PROV_RECORD_ID_MAX);
}

/* ================================================================
 * Record store.
 * ================================================================ */

void
mesh_prov_record_store_clear(struct mesh_prov_record_store *st)
{

	if (st == NULL)
		return;
	memset(st, 0, sizeof(*st));
}

/* Index of the slot holding `id`, or -1. */
static int
store_find(const struct mesh_prov_record_store *st, uint16_t id)
{
	size_t i;

	for (i = 0; i < st->n; i++)
		if (st->slot[i].valid && st->slot[i].id == id)
			return ((int)i);
	return (-1);
}

/* Drop slot i, compacting the pool so the freed octets are reusable. */
static void
store_drop(struct mesh_prov_record_store *st, size_t i)
{
	uint16_t off, len;
	size_t j;

	off = st->slot[i].off;
	len = st->slot[i].len;
	memmove(st->pool + off, st->pool + off + len, st->used - off - len);
	st->used -= len;
	for (j = 0; j < st->n; j++)
		if (st->slot[j].valid && st->slot[j].off > off)
			st->slot[j].off = (uint16_t)(st->slot[j].off - len);
	for (j = i; j + 1 < st->n; j++)
		st->slot[j] = st->slot[j + 1];
	st->n--;
	memset(&st->slot[st->n], 0, sizeof(st->slot[st->n]));
}

int
mesh_prov_record_store_set(struct mesh_prov_record_store *st, uint16_t id,
    const uint8_t *data, size_t len)
{
	int i;

	if (st == NULL || data == NULL || len == 0 ||
	    len > MESH_PROV_RECORD_DATA_MAX || !record_id_valid(id))
		return (-1);
	i = store_find(st, id);
	if (i >= 0)
		store_drop(st, (size_t)i);
	if (st->n == MESH_PROV_RECORD_SLOTS ||
	    len > MESH_PROV_RECORD_POOL_MAX - st->used)
		return (-1);
	memcpy(st->pool + st->used, data, len);
	st->slot[st->n].id = id;
	st->slot[st->n].off = (uint16_t)st->used;
	st->slot[st->n].len = (uint16_t)len;
	st->slot[st->n].valid = 1;
	st->n++;
	st->used += len;
	return (0);
}

const uint8_t *
mesh_prov_record_store_get(const struct mesh_prov_record_store *st, uint16_t id,
    size_t *len)
{
	int i;

	if (st == NULL)
		return (NULL);
	i = store_find(st, id);
	if (i < 0)
		return (NULL);
	if (len != NULL)
		*len = st->slot[i].len;
	return (st->pool + st->slot[i].off);
}

size_t
mesh_prov_record_store_ids(const struct mesh_prov_record_store *st,
    uint16_t *ids, size_t max)
{
	size_t i, j, n;
	uint16_t t;

	if (st == NULL || ids == NULL)
		return (0);
	n = 0;
	for (i = 0; i < st->n && n < max; i++)
		if (st->slot[i].valid)
			ids[n++] = st->slot[i].id;
	/* Ascending order; n is at most eighteen, so an insertion sort. */
	for (i = 1; i < n; i++) {
		t = ids[i];
		for (j = i; j > 0 && ids[j - 1] > t; j--)
			ids[j] = ids[j - 1];
		ids[j] = t;
	}
	return (n);
}

/* ================================================================
 * PDU codec.
 * ================================================================ */

int
mesh_prov_records_get_build(uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	out[0] = MESH_PROV_RECORDS_GET;
	*outlen = 1;
	return (0);
}

int
mesh_prov_records_list_build(uint16_t extensions, const uint16_t *ids, size_t n,
    uint8_t *out, size_t cap, size_t *outlen)
{
	size_t i, need;

	if (outlen != NULL)
		*outlen = 0;
	if (out == NULL || outlen == NULL || (n != 0 && ids == NULL))
		return (-1);
	need = 3 + 2 * n;
	if (need > cap)
		return (-1);
	for (i = 0; i < n; i++)
		if (!record_id_valid(ids[i]))
			return (-1);
	out[0] = MESH_PROV_RECORDS_LIST;
	put_be16(out + 1, extensions);
	for (i = 0; i < n; i++)
		put_be16(out + 3 + 2 * i, ids[i]);
	*outlen = need;
	return (0);
}

int
mesh_prov_records_list_parse(const uint8_t *in, size_t len, uint16_t *extensions,
    uint16_t *ids, size_t max, size_t *n)
{
	size_t count, i;

	if (n != NULL)
		*n = 0;
	if (extensions != NULL)
		*extensions = 0;
	if (in == NULL || n == NULL || len < 3)
		return (-1);
	if (in[0] != MESH_PROV_RECORDS_LIST)
		return (-1);
	/* Records List is a whole number of 16-bit Record IDs (Table 5.45). */
	if (((len - 3) & 1) != 0)
		return (-1);
	count = (len - 3) / 2;
	if (ids != NULL && count > max)
		return (-1);
	if (extensions != NULL)
		*extensions = get_be16(in + 1);
	for (i = 0; i < count && ids != NULL; i++)
		ids[i] = get_be16(in + 3 + 2 * i);
	*n = count;
	return (0);
}

/*
 * Build a Provisioning Record Request.  Static: the only caller is the
 * retrieval assembler below, which is what the Provisioner drives; a request
 * built outside it would have no fetch state to answer into.
 */
static int
mesh_prov_record_request_build(const struct mesh_prov_record_req *in,
    uint8_t *out, size_t *outlen)
{

	if (outlen != NULL)
		*outlen = 0;
	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	/* Fragment Maximum Size 0x0000 is Prohibited (Section 5.4.1.11). */
	if (in->frag_max == 0 || !record_id_valid(in->record_id))
		return (-1);
	out[0] = MESH_PROV_RECORD_REQUEST;
	put_be16(out + 1, in->record_id);
	put_be16(out + 3, in->frag_offset);
	put_be16(out + 5, in->frag_max);
	*outlen = 7;
	return (0);
}

int
mesh_prov_record_request_parse(const uint8_t *in, size_t len,
    struct mesh_prov_record_req *out)
{

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || len != 7 || in[0] != MESH_PROV_RECORD_REQUEST)
		return (-1);
	out->record_id = get_be16(in + 1);
	out->frag_offset = get_be16(in + 3);
	out->frag_max = get_be16(in + 5);
	/*
	 * A Prohibited Fragment Maximum Size is an error in the provisioning
	 * protocol for the Provisionee that receives it (Section 5.4.4); the
	 * Record ID is NOT range-checked here, because an unassigned ID is
	 * simply a record that is not present and Table 5.50 answers it with a
	 * status, not with a failure.
	 */
	if (out->frag_max == 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/*
 * Build a Provisioning Record Response.  Static for the mirror-image reason:
 * a Provisionee answers through mesh_prov_record_answer(), which is where the
 * Table 5.50 validation conditions that decide the Status live, and a response
 * built around them would not be one the specification allows.
 */
static int
mesh_prov_record_response_build(const struct mesh_prov_record_rsp *in,
    uint8_t *out, size_t cap, size_t *outlen)
{
	size_t need;

	if (outlen != NULL)
		*outlen = 0;
	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->status > MESH_PROV_REC_OFFSET_OOB)
		return (-1);
	if (in->data_len != 0 && in->data == NULL)
		return (-1);
	/* "If the value of the Status field ... is not Success, the Data field
	 * shall be empty" (Section 5.4.1.12). */
	if (in->status != MESH_PROV_REC_SUCCESS && in->data_len != 0)
		return (-1);
	/* Requested Record Is Not Present reports Total Length 0x0000. */
	if (in->status == MESH_PROV_REC_NOT_PRESENT && in->total_len != 0)
		return (-1);
	need = MESH_PROV_RECORD_RSP_HDR + in->data_len;
	if (need > cap || in->data_len > MESH_PROV_RECORD_FRAG_MAX)
		return (-1);
	out[0] = MESH_PROV_RECORD_RESPONSE;
	out[1] = in->status;
	put_be16(out + 2, in->record_id);
	put_be16(out + 4, in->frag_offset);
	put_be16(out + 6, in->total_len);
	if (in->data_len != 0)
		memcpy(out + MESH_PROV_RECORD_RSP_HDR, in->data, in->data_len);
	*outlen = need;
	return (0);
}

int
mesh_prov_record_response_parse(const uint8_t *in, size_t len,
    struct mesh_prov_record_rsp *out)
{

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || len < MESH_PROV_RECORD_RSP_HDR ||
	    in[0] != MESH_PROV_RECORD_RESPONSE)
		return (-1);
	out->status = in[1];
	out->record_id = get_be16(in + 2);
	out->frag_offset = get_be16(in + 4);
	out->total_len = get_be16(in + 6);
	out->data = in + MESH_PROV_RECORD_RSP_HDR;
	out->data_len = len - MESH_PROV_RECORD_RSP_HDR;
	/*
	 * Status codes 0x03-0xFF are Reserved for Future Use (Table 5.44) and
	 * a non-Success response carries no Data.  Both are refused here: the
	 * Provisioner cannot assemble a record from a response it does not
	 * understand, and a status it cannot classify must not be read as
	 * Success.
	 */
	if (out->status > MESH_PROV_REC_OFFSET_OOB ||
	    (out->status != MESH_PROV_REC_SUCCESS && out->data_len != 0)) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/* ================================================================
 * Provisionee half.
 * ================================================================ */

int
mesh_prov_record_answer(const struct mesh_prov_record_store *st,
    const struct mesh_prov_record_req *req, uint8_t *out, size_t cap,
    size_t *outlen)
{
	struct mesh_prov_record_rsp rsp;
	const uint8_t *data;
	size_t len, avail, frag;

	if (outlen != NULL)
		*outlen = 0;
	if (st == NULL || req == NULL || out == NULL || outlen == NULL ||
	    req->frag_max == 0)
		return (-1);

	memset(&rsp, 0, sizeof(rsp));
	rsp.record_id = req->record_id;
	rsp.frag_offset = req->frag_offset;

	len = 0;
	data = mesh_prov_record_store_get(st, req->record_id, &len);
	if (data == NULL) {
		/* Table 5.50: record absent, Total Length 0x0000, no Data. */
		rsp.status = MESH_PROV_REC_NOT_PRESENT;
		return (mesh_prov_record_response_build(&rsp, out, cap, outlen));
	}
	rsp.total_len = (uint16_t)len;
	if (req->frag_offset >= len) {
		/*
		 * Table 5.50: the condition is "the Fragment Offset field value
		 * is smaller than Total Length"; when it is not met the status
		 * is Requested Offset Is Out Of Bounds, and Section 5.4.1.12
		 * still reports the Total Length for that status.
		 */
		rsp.status = MESH_PROV_REC_OFFSET_OOB;
		return (mesh_prov_record_response_build(&rsp, out, cap, outlen));
	}

	avail = len - req->frag_offset;
	frag = req->frag_max < avail ? req->frag_max : avail;
	/*
	 * Section 5.4.1.12 permits a shorter fragment "if less data is
	 * available or if the Provisionee cannot create a message of the
	 * requested size", which is what a Fragment Maximum Size larger than
	 * this bearer's transaction, or than the caller's buffer, amounts to.
	 */
	if (frag > MESH_PROV_RECORD_FRAG_MAX)
		frag = MESH_PROV_RECORD_FRAG_MAX;
	if (cap > MESH_PROV_RECORD_RSP_HDR &&
	    frag > cap - MESH_PROV_RECORD_RSP_HDR)
		frag = cap - MESH_PROV_RECORD_RSP_HDR;
	rsp.status = MESH_PROV_REC_SUCCESS;
	rsp.data = data + req->frag_offset;
	rsp.data_len = frag;
	return (mesh_prov_record_response_build(&rsp, out, cap, outlen));
}

/* ================================================================
 * Provisioner half.
 * ================================================================ */

void
mesh_prov_record_fetch_init(struct mesh_prov_record_fetch *f, uint16_t record_id,
    uint16_t frag_max)
{

	if (f == NULL)
		return;
	memset(f, 0, sizeof(*f));
	f->active = 1;
	f->record_id = record_id;
	f->frag_max = frag_max != 0 && frag_max <= MESH_PROV_RECORD_FRAG_MAX ?
	    frag_max : MESH_PROV_RECORD_FRAG_MAX;
}

int
mesh_prov_record_fetch_request(const struct mesh_prov_record_fetch *f,
    uint8_t *out, size_t *outlen)
{
	struct mesh_prov_record_req req;

	if (f == NULL || !f->active)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.record_id = f->record_id;
	req.frag_offset = (uint16_t)f->len;
	req.frag_max = f->frag_max;
	return (mesh_prov_record_request_build(&req, out, outlen));
}

int
mesh_prov_record_fetch_input(struct mesh_prov_record_fetch *f,
    const struct mesh_prov_record_rsp *rsp)
{

	if (f == NULL || rsp == NULL || !f->active)
		return (-1);
	/*
	 * Section 5.4.1.12: the Record ID and the Fragment Offset of a Response
	 * "shall be set to the value of the ... corresponding Provisioning
	 * Record Request PDU".  A Response that does not match is not the
	 * answer to the Request in flight and is never assembled into it.
	 */
	if (rsp->record_id != f->record_id || rsp->frag_offset != f->len)
		return (-1);
	if (rsp->status != MESH_PROV_REC_SUCCESS) {
		f->status = rsp->status;
		f->total_len = rsp->total_len;
		f->have_total = 1;
		f->active = 0;
		return (-1);
	}
	if (rsp->total_len > MESH_PROV_RECORD_DATA_MAX)
		return (-1);
	/* The Total Length is a property of the record, so it cannot move. */
	if (f->have_total && rsp->total_len != f->total_len)
		return (-1);
	f->total_len = rsp->total_len;
	f->have_total = 1;
	/* A Success response with no Data would never terminate the loop. */
	if (rsp->data_len == 0)
		return (-1);
	if (rsp->data_len > (size_t)f->total_len - f->len)
		return (-1);
	memcpy(f->buf + f->len, rsp->data, rsp->data_len);
	f->len += rsp->data_len;
	if (f->len == f->total_len) {
		f->active = 0;
		return (1);
	}
	return (0);
}
