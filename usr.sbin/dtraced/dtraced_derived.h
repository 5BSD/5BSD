/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DTRACED_DERIVED_H_
#define _DTRACED_DERIVED_H_

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include "dtraced.h"
#include "dtraced_wire.h"

/* Since protocol 36, the installed-event slot identifies derived ELF frames. */
typedef struct dtraced_derived_parent {
	uint8_t consumer_session[16];
	uint64_t delivery_id;
	uint16_t vmid;
	uint64_t epoch;
	uint8_t program_id[16];
	uint8_t source_id[16];
} dtraced_derived_parent_t;

static inline int
dtraced_derived_parent_valid(const dtraced_derived_parent_t *parent)
{
	static const uint8_t zero[16] = { 0 };
	return (parent != NULL && parent->delivery_id != 0 &&
	    parent->vmid != 0 && parent->epoch != 0 &&
	    memcmp(parent->consumer_session, zero, sizeof(zero)) != 0 &&
	    memcmp(parent->program_id, zero, sizeof(zero)) != 0 &&
	    memcmp(parent->source_id, zero, sizeof(zero)) != 0);
}

static inline int
dtraced_derived_parent_to_header(dtraced_hdr_t *header,
    const dtraced_derived_parent_t *parent)
{
	if (header == NULL || !dtraced_derived_parent_valid(parent)) {
		errno = EINVAL;
		return (-1);
	}
	header->installed.delivery_id = parent->delivery_id;
	header->installed.vmid = parent->vmid;
	header->installed.epoch = parent->epoch;
	memcpy(header->installed.program_id, parent->program_id, 16);
	memcpy(header->installed.source_id, parent->source_id, 16);
	memset(header->installed.name, 0, sizeof(header->installed.name));
	memcpy(header->installed.name, parent->consumer_session, 16);
	return (0);
}

static inline int
dtraced_derived_parent_from_header(dtraced_derived_parent_t *parent,
    const dtraced_hdr_t *header)
{
	static const char zero[DTRACED_FDIDENTLEN - 16] = { 0 };
	if (parent == NULL || header == NULL ||
	    memcmp(header->installed.name + 16, zero, sizeof(zero)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	parent->delivery_id = header->installed.delivery_id;
	memcpy(parent->consumer_session, header->installed.name, 16);
	parent->vmid = header->installed.vmid;
	parent->epoch = header->installed.epoch;
	memcpy(parent->program_id, header->installed.program_id, 16);
	memcpy(parent->source_id, header->installed.source_id, 16);
	if (!dtraced_derived_parent_valid(parent)) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

/* The payload digest includes the target envelope. Keeping this form lets
 * restart recovery resolve a retained spool without loading it into RAM. */
static inline int
dtraced_derived_program_id_from_digest(
    const dtraced_derived_parent_t *parent,
    const uint8_t payload_digest[SHA256_DIGEST_LENGTH],
    uint8_t program_id[16])
{
	uint8_t preimage[8 + 16 + 8 + 2 + 8 + 16 + 16 +
	    SHA256_DIGEST_LENGTH] = {
	    'H', 'D', 'E', 'R', 'I', 'V', '1', 0
	};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	if (!dtraced_derived_parent_valid(parent) ||
	    payload_digest == NULL || program_id == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(preimage + 8, parent->consumer_session, 16);
	dtraced_wire_put_u64(preimage + 24, parent->delivery_id);
	dtraced_wire_put_u16(preimage + 32, parent->vmid);
	dtraced_wire_put_u64(preimage + 34, parent->epoch);
	memcpy(preimage + 42, parent->program_id, 16);
	memcpy(preimage + 58, parent->source_id, 16);
	memcpy(preimage + 74, payload_digest, SHA256_DIGEST_LENGTH);
	if (SHA256(preimage, sizeof(preimage), digest) == NULL) {
		errno = EIO;
		return (-1);
	}
	memcpy(program_id, digest, 16);
	return (0);
}

/* An exact retry names the same spool artifact and binds its bytes to the
 * parent recipient and ingress delivery. */
static inline int
dtraced_derived_program_id(const dtraced_derived_parent_t *parent,
    const void *payload, size_t payload_size, uint8_t program_id[16])
{
	uint8_t payload_digest[SHA256_DIGEST_LENGTH];
	if (payload == NULL || payload_size == 0 ||
	    SHA256((const unsigned char *)payload, payload_size,
	    payload_digest) == NULL) {
		errno = EINVAL;
		return (-1);
	}
	return (dtraced_derived_program_id_from_digest(parent,
	    payload_digest, program_id));
}

#endif
