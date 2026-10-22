/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_RECONCILE_H_
#define _BHYVE_MIGRATION_RECONCILE_H_

#include "migration_recovery.h"

/* Observation of the exact destination incarnation, not a PID or VM name.
 * PAUSED requires the committed RAM/device image and fresh-session startup
 * fence to remain intact. Missing state cannot be reconstructed from HMR2. */
enum migration_recovery_destination {
	MIGRATION_REC_VM_UNAVAILABLE,
	MIGRATION_REC_VM_PAUSED,
	MIGRATION_REC_VM_RUNNING,
};

enum migration_recovery_action {
	MIGRATION_REC_HOLD,
	MIGRATION_REC_FINISH_RETIREMENT,
	MIGRATION_REC_REISSUE_RELEASE,
	MIGRATION_REC_CONFIRM_RUNNING,
	MIGRATION_REC_COMPLETE,
};

/* Plan only: the executor must hold the attempt/VM ownership locks throughout
 * observation and action. Both records must be durably loaded, the peer record
 * obtained on the authenticated connection whose leaf pins are supplied here.
 * Never use a record checksum as authentication. Every successful action still
 * requires the normal monotonic persistence hooks; none permits source rollback
 * or authorizes tracing directly. Missing/contradictory evidence leaves HOLD. */
static inline int
migration_recovery_reconcile(const struct migration_recovery_record *source,
    const struct migration_recovery_record *destination,
    const uint8_t source_certificate[32],
    const uint8_t destination_certificate[32],
    enum migration_recovery_destination observed,
    enum migration_recovery_action *action)
{
	uint8_t swire[MIGRATION_RECOVERY_SIZE], dwire[MIGRATION_RECOVERY_SIZE];
	int error;

	if (action == NULL)
		return (EINVAL);
	*action = MIGRATION_REC_HOLD;
	if (source == NULL || destination == NULL || source_certificate == NULL ||
	    destination_certificate == NULL)
		return (EINVAL);
	error = migration_recovery_encode(source, swire);
	if (error == 0)
		error = migration_recovery_encode(destination, dwire);
	if (error != 0)
		return (error);
	if (source->phase < MIGRATION_REC_SOURCE_INTENT ||
	    source->phase > MIGRATION_REC_SOURCE_CONFIRMED ||
	    destination->phase < MIGRATION_REC_DEST_STAGED ||
	    destination->phase > MIGRATION_REC_DEST_RUNNING)
		return (EPROTO);
	/* Bytes 8..191 contain the complete attempt and certificate binding;
	 * the phase and its dependent checksum intentionally differ by role. */
	if (memcmp(swire + 8, dwire + 8, 184) != 0)
		return (ESTALE);
	if (memcmp(source->source_certificate_sha256, source_certificate, 32) != 0 ||
	    memcmp(source->destination_certificate_sha256,
	    destination_certificate, 32) != 0)
		return (EACCES);
	if (observed == MIGRATION_REC_VM_UNAVAILABLE)
		return (ENXIO);
	if (observed != MIGRATION_REC_VM_PAUSED && observed != MIGRATION_REC_VM_RUNNING)
		return (EINVAL);

	/* RELEASED is persisted at the source before transmission. A destination
	 * beyond STAGED with only source INTENT/RETIRED indicates stale evidence
	 * or a violated protocol, never permission to infer missing transitions. */
	if (source->phase < MIGRATION_REC_SOURCE_RELEASED) {
		if (destination->phase != MIGRATION_REC_DEST_STAGED ||
		    observed != MIGRATION_REC_VM_PAUSED)
			return (EPROTO);
		*action = source->phase == MIGRATION_REC_SOURCE_INTENT ?
		    MIGRATION_REC_FINISH_RETIREMENT : MIGRATION_REC_REISSUE_RELEASE;
		return (0);
	}
	if (source->phase == MIGRATION_REC_SOURCE_CONFIRMED) {
		if (destination->phase != MIGRATION_REC_DEST_RUNNING ||
		    observed != MIGRATION_REC_VM_RUNNING)
			return (EPROTO);
		*action = MIGRATION_REC_COMPLETE;
		return (0);
	}
	if (observed == MIGRATION_REC_VM_RUNNING) {
		/* A failed destination RUNNING write leaves RELEASED durable. The
		 * executor must finish that write before acknowledging the source. */
		if (destination->phase == MIGRATION_REC_DEST_STAGED)
			return (EPROTO);
		*action = MIGRATION_REC_CONFIRM_RUNNING;
	} else {
		if (destination->phase == MIGRATION_REC_DEST_RUNNING)
			return (EPROTO);
		*action = MIGRATION_REC_REISSUE_RELEASE;
	}
	return (0);
}
#endif
