/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_COMMIT_H_
#define _BHYVE_MIGRATION_COMMIT_H_
#include <sys/endian.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define MIGRATION_FRESH_COMMIT_SIZE 80U
struct migration_commit_binding {
	uint16_t destination_vmid;
	uint64_t destination_epoch;
	uint8_t challenge[32];
	uint8_t state_digest[32]; /* digest of the complete DEV_STATE blob */
};

static inline int
migration_commit_encode(const struct migration_commit_binding *b,
    uint8_t wire[MIGRATION_FRESH_COMMIT_SIZE])
{
	if (b == NULL || wire == NULL || b->destination_vmid == 0 ||
	    b->destination_epoch == 0 ||
	    memcmp(b->challenge, (const uint8_t[32]){0}, 32) == 0 ||
	    memcmp(b->state_digest, (const uint8_t[32]){0}, 32) == 0)
		return (EINVAL);
	memset(wire, 0, MIGRATION_FRESH_COMMIT_SIZE);
	memcpy(wire, "FMC1", 4);
	le16enc(wire + 4, b->destination_vmid);
	le64enc(wire + 8, b->destination_epoch);
	memcpy(wire + 16, b->challenge, 32);
	memcpy(wire + 48, b->state_digest, 32);
	return (0);
}

static inline int
migration_commit_decode(const void *bytes, size_t length,
    struct migration_commit_binding *binding)
{
	const uint8_t *wire = bytes;
	struct migration_commit_binding b = {0};
	uint8_t canonical[MIGRATION_FRESH_COMMIT_SIZE];
	if (wire == NULL || binding == NULL || length != sizeof(canonical))
		return (EINVAL);
	b.destination_vmid = le16dec(wire + 4);
	b.destination_epoch = le64dec(wire + 8);
	memcpy(b.challenge, wire + 16, 32);
	memcpy(b.state_digest, wire + 48, 32);
	if (migration_commit_encode(&b, canonical) != 0 ||
	    memcmp(wire, canonical, sizeof(canonical)) != 0)
		return (EPROTO);
	*binding = b;
	return (0);
}
#endif
