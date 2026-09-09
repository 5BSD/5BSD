/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh provisioning records (MshPRT_v1.1.1 Sections 5.4.1.11 -
 * 5.4.1.14 and 5.4.2.6).
 *
 * Provisioning records are read-only data items a Provisioner may retrieve
 * from a Provisionee over an established provisioning bearer BEFORE it sends
 * the Provisioning Invite PDU (Sections 5.4.2.6.1 and 5.4.2.6.2).  Each is
 * identified by a 16-bit Record ID from Table 5.52; the interesting ones carry
 * the device's X.509 Device Certificate and the intermediate certificates that
 * chain it to a root, which is how certificate-based provisioning (Section
 * 5.5) delivers the device's OOB Public Key.
 *
 * Four PDUs, all outside the provisioning session proper:
 *
 *   Provisioning Records Get    (0x0C) no parameters
 *   Provisioning Records List   (0x0D) Provisioning Extensions(2) || IDs(2N)
 *   Provisioning Record Request (0x0A) RecordID(2) Offset(2) FragmentMax(2)
 *   Provisioning Record Response(0x0B) Status(1) RecordID(2) Offset(2)
 *                                      TotalLength(2) Data(N)
 *
 * This module is the pure codec plus the two role halves that are pure
 * functions of it: the Provisionee's record store and the answer it owes a
 * Record Request (the Table 5.50 validation conditions), and the Provisioner's
 * fragment assembler.  No crypto, no I/O, no globals; every codec returns 0 on
 * success and -1 on failure with its output zeroed.
 *
 * Sizing.  A Record Response is far longer than any PDU of the provisioning
 * protocol itself, so it is bounded by what the bearer can carry in one
 * transaction rather than by MESH_PROV_PDU_MAX: MESH_PROV_BEARER_PDU_MAX
 * (mesh_provision.h) is the PB-ADV Transaction Start plus MESH_GP_SEG_MAX - 1
 * Continuations, and MESH_PROV_RECORD_FRAG_MAX is what is left of it after the
 * Response header.  The Fragment Maximum Size field of a Request is chosen by
 * the Provisioner "affected by the provisioning bearer that is being used"
 * (Section 5.4.1.11), and a Provisionee "may [respond] shorter than the value
 * of the Fragment Maximum Size field if less data is available or if the
 * Provisionee cannot create a message of the requested size" (Section
 * 5.4.1.12) -- so a peer asking for more than this bearer can carry is
 * answered with a shorter fragment, not refused.
 */

#ifndef _MESH_PROV_RECORDS_H_
#define _MESH_PROV_RECORDS_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_provision.h"

/* ----------------------------------------------------------------
 * Record IDs.  MshPRT_v1.1.1 Table 5.52.
 * ---------------------------------------------------------------- */
#define	MESH_PROV_RECORD_BASE_URI	0x0000	/* Cert-Based Prov Base URI */
#define	MESH_PROV_RECORD_DEVICE_CERT	0x0001	/* Device Certificate */
#define	MESH_PROV_RECORD_INTERMEDIATE1	0x0002	/* Intermediate Certificate 1 */
#define	MESH_PROV_RECORD_INTERMEDIATE15	0x0010	/* Intermediate Certificate 15 */
#define	MESH_PROV_RECORD_LOCAL_NAME	0x0011	/* Complete Local Name */
#define	MESH_PROV_RECORD_APPEARANCE	0x0012	/* Appearance */
#define	MESH_PROV_RECORD_ID_MAX		0x0012
/* Intermediate Certificate M (1..15), Section 5.4.2.6.3.3. */
#define	MESH_PROV_RECORD_INTERMEDIATE(m) \
	((uint16_t)(MESH_PROV_RECORD_INTERMEDIATE1 + (m) - 1))
#define	MESH_PROV_RECORD_INTERMEDIATE_COUNT	15

/* Provisioning Record Response status codes.  Table 5.44. */
#define	MESH_PROV_REC_SUCCESS		0x00
#define	MESH_PROV_REC_NOT_PRESENT	0x01	/* Requested Record Is Not Present */
#define	MESH_PROV_REC_OFFSET_OOB	0x02	/* Requested Offset Is Out Of Bounds */

/*
 * Fragment sizing.  The Response header is Type(1) + Status(1) + RecordID(2) +
 * FragmentOffset(2) + TotalLength(2).
 */
#define	MESH_PROV_RECORD_RSP_HDR	8
#define	MESH_PROV_RECORD_FRAG_MAX \
	(MESH_PROV_BEARER_PDU_MAX - MESH_PROV_RECORD_RSP_HDR)

/*
 * Record store.  Up to MESH_PROV_RECORD_SLOTS records share one pool, so a
 * store costs the pool and not eighteen worst-case certificates.  Used by both
 * roles: a Provisionee serves records from one, a Provisioner assembles
 * retrieved records into one.
 */
#define	MESH_PROV_RECORD_SLOTS		19	/* Table 5.52 defines 19 IDs */
#define	MESH_PROV_RECORD_POOL_MAX	4096
#define	MESH_PROV_RECORD_DATA_MAX	2048	/* one record */

struct mesh_prov_record_store {
	struct {
		uint16_t	id;
		uint16_t	off;		/* offset in pool */
		uint16_t	len;
		int		valid;
	}		slot[MESH_PROV_RECORD_SLOTS];
	size_t		n;
	size_t		used;			/* octets of pool in use */
	uint8_t		pool[MESH_PROV_RECORD_POOL_MAX];
};

void	mesh_prov_record_store_clear(struct mesh_prov_record_store *st);
/*
 * Install (or replace) one record.  id must be a Table 5.52 Record ID; len
 * must be 1..MESH_PROV_RECORD_DATA_MAX and must fit the free pool.  Returns 0,
 * -1 on a bad argument or a full store.
 */
int	mesh_prov_record_store_set(struct mesh_prov_record_store *st,
	    uint16_t id, const uint8_t *data, size_t len);
/* Look one up.  Returns the data (and *len) or NULL when not present. */
const uint8_t *mesh_prov_record_store_get(
	    const struct mesh_prov_record_store *st, uint16_t id, size_t *len);
/*
 * List the stored Record IDs in ascending order, as the Records List PDU
 * requires them to be reported.  Returns the count written (<= max).
 */
size_t	mesh_prov_record_store_ids(const struct mesh_prov_record_store *st,
	    uint16_t *ids, size_t max);

/* ----------------------------------------------------------------
 * PDU codec.  Sections 5.4.1.11 - 5.4.1.14.
 * ---------------------------------------------------------------- */

/* Provisioning Records Get (0x0C): no parameters. */
int	mesh_prov_records_get_build(uint8_t *out, size_t *outlen);

/*
 * Provisioning Records List (0x0D).  The Provisioning Extensions field is a
 * bitmask whose bits 0-15 are all Reserved for Future Use in this version
 * (Table 5.46).  A Provisioner does NOT fail on a non-zero value: Section
 * 5.4.4 makes RFU handling asymmetric -- only the Provisionee is required to
 * treat an RFU bit as an error -- so the parser surfaces the field and lets
 * the caller ignore bits it does not understand.
 */
int	mesh_prov_records_list_build(uint16_t extensions, const uint16_t *ids,
	    size_t n, uint8_t *out, size_t cap, size_t *outlen);
int	mesh_prov_records_list_parse(const uint8_t *in, size_t len,
	    uint16_t *extensions, uint16_t *ids, size_t max, size_t *n);

/*
 * Provisioning Record Request (0x0A).  Fragment Maximum Size 0x0000 is
 * Prohibited (Section 5.4.1.11), so neither role builds nor accepts one.  Only
 * the parser is exported: a Provisioner builds its requests through the
 * retrieval assembler at the end of this file, which owns the offset.
 */
struct mesh_prov_record_req {
	uint16_t	record_id;
	uint16_t	frag_offset;
	uint16_t	frag_max;
};
int	mesh_prov_record_request_parse(const uint8_t *in, size_t len,
	    struct mesh_prov_record_req *out);

/*
 * Provisioning Record Response (0x0B).  On parse, `data` points into the
 * caller's input buffer and is valid for as long as it is.  Only the parser is
 * exported; a Provisionee answers through mesh_prov_record_answer(), which
 * applies the Table 5.50 validation conditions.
 */
struct mesh_prov_record_rsp {
	uint8_t		status;
	uint16_t	record_id;
	uint16_t	frag_offset;
	uint16_t	total_len;
	const uint8_t  *data;
	size_t		data_len;
};
int	mesh_prov_record_response_parse(const uint8_t *in, size_t len,
	    struct mesh_prov_record_rsp *out);

/* ----------------------------------------------------------------
 * Provisionee half: answering a Provisioning Record Request.
 * ---------------------------------------------------------------- */

/*
 * Build the Provisioning Record Response owed to `req` from `st`, applying the
 * Table 5.50 request validation conditions:
 *
 *   record absent			-> Requested Record Is Not Present,
 *					   Total Length 0x0000, no Data
 *   Fragment Offset >= Total Length	-> Requested Offset Is Out Of Bounds,
 *					   Total Length reported, no Data
 *   otherwise				-> Success, a fragment starting at
 *					   Fragment Offset of at most Fragment
 *					   Maximum Size octets
 *
 * The fragment is additionally clamped to what one bearer transaction can
 * carry (MESH_PROV_RECORD_FRAG_MAX) and to `cap`, which Section 5.4.1.12
 * explicitly permits.  Returns 0, -1 on a bad argument.
 */
int	mesh_prov_record_answer(const struct mesh_prov_record_store *st,
	    const struct mesh_prov_record_req *req, uint8_t *out, size_t cap,
	    size_t *outlen);

/* ----------------------------------------------------------------
 * Provisioner half: assembling a record from its fragments.
 * ---------------------------------------------------------------- */

/*
 * One in-flight record retrieval.  mesh_prov_record_fetch_init() starts it,
 * mesh_prov_record_fetch_request() builds the next Provisioning Record Request
 * (the first at offset 0, each later one at the offset already assembled), and
 * mesh_prov_record_fetch_input() consumes the matching Response.
 *
 * Section 5.4.1.12 requires the Record ID and Fragment Offset of a Response to
 * equal those of the Request it answers; a Response that does not is not the
 * answer to our Request and is rejected rather than assembled.
 */
struct mesh_prov_record_fetch {
	int		active;
	uint16_t	record_id;
	uint16_t	frag_max;
	uint16_t	total_len;
	int		have_total;
	uint8_t		status;		/* last non-Success status seen */
	size_t		len;		/* octets assembled so far */
	uint8_t		buf[MESH_PROV_RECORD_DATA_MAX];
};
void	mesh_prov_record_fetch_init(struct mesh_prov_record_fetch *f,
	    uint16_t record_id, uint16_t frag_max);
int	mesh_prov_record_fetch_request(const struct mesh_prov_record_fetch *f,
	    uint8_t *out, size_t *outlen);
/*
 * Feed the Response.  Returns 1 when the record is complete (buf/len hold it),
 * 0 when more fragments are needed, and -1 when the exchange cannot continue:
 * a mismatched Record ID or Fragment Offset, a Total Length larger than this
 * assembler can hold, a Success response carrying no data (which would never
 * terminate), or a non-Success status (recorded in f->status, which the caller
 * renders -- an absent record is a legitimate answer, not a protocol error).
 */
int	mesh_prov_record_fetch_input(struct mesh_prov_record_fetch *f,
	    const struct mesh_prov_record_rsp *rsp);

#endif /* _MESH_PROV_RECORDS_H_ */
