/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_SNAPSHOT_H_
#define _BHYVE_MIGRATION_SNAPSHOT_H_

#include <stdbool.h>
#include "hypertrace_session.h"

#define MIGRATE_BLOB_HDR 16U

struct migration_snapshot_view {
	const uint8_t *metadata;
	size_t metadata_length;
	const uint8_t *kernel;
	size_t kernel_length;
	const uint8_t *fresh_record;
};

/* The caller supplies the negotiated tracing mode. Never infer consent to
 * fresh tracing from an unsolicited trailing record. Views borrow the blob;
 * no member is published until every length and the FSS1 record is valid.
 * FSS1 is not evidence of retirement and cannot authorize guest execution. */
static inline int
migration_snapshot_decode(const void *buffer, size_t length, bool fresh,
    struct migration_snapshot_view *view)
{
	const uint8_t *wire = buffer;
	struct migration_snapshot_view candidate = {0};
	struct hypertrace_session_record record;
	uint64_t metadata, kernel;
	size_t available, trace_length;
	int error;

	if (buffer == NULL || view == NULL)
		return (EINVAL);
	if (length < MIGRATE_BLOB_HDR)
		return (EBADMSG);
	available = length - MIGRATE_BLOB_HDR;
	metadata = le64dec(wire);
	kernel = le64dec(wire + 8);
	if (metadata > available || kernel > available - metadata)
		return (EBADMSG);
	trace_length = fresh ? HYPERTRACE_SESSION_RECORD_SIZE : 0;
	if (available - metadata - kernel != trace_length)
		return (EBADMSG);
	candidate.metadata = wire + MIGRATE_BLOB_HDR;
	candidate.metadata_length = (size_t)metadata;
	candidate.kernel = candidate.metadata + candidate.metadata_length;
	candidate.kernel_length = (size_t)kernel;
	if (fresh) {
		candidate.fresh_record = candidate.kernel + candidate.kernel_length;
		error = hypertrace_session_record_decode(candidate.fresh_record,
		    trace_length, &record);
		if (error != 0)
			return (error);
	}
	*view = candidate;
	return (0);
}
#endif
