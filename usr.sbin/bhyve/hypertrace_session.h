/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_HYPERTRACE_SESSION_H_
#define _BHYVE_HYPERTRACE_SESSION_H_
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/hypertrace.h>
#include <dev/virtio/dtrace/virtio_dtrace_wire.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define HYPERTRACE_SESSION_RECORD_SIZE 40U
#define HYPERTRACE_SESSION_RECORD_MAGIC 0x31535346U /* FSS1 */
#define HYPERTRACE_SESSION_FEATURES (VTDTR_WIRE_F_SESSION_REQUIRED | \
    VTDTR_WIRE_F_SESSION_STOP_V1 | VTDTR_WIRE_F_SESSION_FRESH_V1)
struct hypertrace_session_record {
	uint16_t vmid;
	uint64_t epoch;
	uint64_t stop_token;
	uint64_t features;
};

static inline int
hypertrace_session_record_valid(const struct hypertrace_session_record *record)
{
	return (record != NULL && record->vmid != 0 &&
	    record->vmid < HYPERTRACE_MAX_VMS && record->epoch != 0 &&
	    record->stop_token != 0 &&
	    record->features == HYPERTRACE_SESSION_FEATURES);
}

static inline int
hypertrace_session_record_encode(void *buffer, size_t length,
    const struct hypertrace_session_record *record)
{
	uint8_t *wire = buffer;
	if (buffer == NULL || length != HYPERTRACE_SESSION_RECORD_SIZE ||
	    !hypertrace_session_record_valid(record))
		return (EINVAL);
	memset(wire, 0, length);
	le32enc(wire, HYPERTRACE_SESSION_RECORD_MAGIC);
	le16enc(wire + 4, 1);
	le16enc(wire + 6, HYPERTRACE_SESSION_RECORD_SIZE);
	le16enc(wire + 8, record->vmid);
	le64enc(wire + 16, record->epoch);
	le64enc(wire + 24, record->stop_token);
	le64enc(wire + 32, record->features);
	return (0);
}

static inline int
hypertrace_session_record_decode(const void *buffer, size_t length,
    struct hypertrace_session_record *record)
{
	const uint8_t *wire = buffer;
	struct hypertrace_session_record candidate;
	if (buffer == NULL || record == NULL ||
	    length != HYPERTRACE_SESSION_RECORD_SIZE)
		return (EINVAL);
	if (le32dec(wire) != HYPERTRACE_SESSION_RECORD_MAGIC ||
	    le16dec(wire + 4) != 1 ||
	    le16dec(wire + 6) != HYPERTRACE_SESSION_RECORD_SIZE ||
	    le16dec(wire + 10) != 0 || le32dec(wire + 12) != 0)
		return (EPROTO);
	candidate.vmid = le16dec(wire + 8);
	candidate.epoch = le64dec(wire + 16);
	candidate.stop_token = le64dec(wire + 24);
	candidate.features = le64dec(wire + 32);
	if (!hypertrace_session_record_valid(&candidate))
		return (EPROTO);
	*record = candidate;
	return (0);
}
#endif
