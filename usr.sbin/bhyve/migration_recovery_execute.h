/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_RECOVERY_EXECUTE_H_
#define _BHYVE_MIGRATION_RECOVERY_EXECUTE_H_
#include "migration_recovery_exchange.h"
#include "migration_reconcile.h"

struct migration_recovery_run_state {
	enum migration_recovery_destination observed;
	bool resume_uncertain;
	bool ack_sent; /* Most recent attempt only; never a cumulative success bit. */
};
struct migration_recovery_run_ops {
	/* Verify the exact incarnation, retained image, and startup fence.
	 * Never report PAUSED after a partially failed resume. */
	int (*observe)(void *, enum migration_recovery_destination *);
	int (*resume)(void *);
};

static inline void
migration_recovery_command(uint8_t wire[40], bool ack, const uint8_t challenge[32])
{
	memset(wire, 0, 40);
	memcpy(wire, "HXR1", 4);
	wire[4] = 1;
	wire[5] = ack ? 2 : 1;
	memcpy(wire + 8, challenge, 32);
}

/* The owner must serialize calls and preserve run_state across reconnects.
 * Resume uncertainty quarantines the owner; a retry cannot simply rerun it.
 * Durable RUNNING precedes ACK. A failed ACK never discards a running VM. */
static inline int
migration_recovery_destination_run(struct migration_channel *channel,
    const struct migration_transport *xp, int dirfd,
    const struct migration_recovery_record *expected,
    const struct migration_recovery_run_ops *ops, void *arg,
    struct migration_recovery_run_state *run_state)
{
	struct migration_recovery_record local, peer;
	enum migration_recovery_action action;
	uint8_t command[40], received[40];
	int error;

	if (run_state == NULL)
		return (EINVAL);
	run_state->ack_sent = false;
	if (ops == NULL || ops->observe == NULL || ops->resume == NULL)
		return (EINVAL);
	if (run_state->resume_uncertain)
		return (EBUSY);
	error = migration_recovery_exchange(channel, xp, dirfd, false, expected, &local, &peer);
	if (error != 0)
		return (error);
	/* An authenticated fact alone is not an execution request. */
	migration_recovery_command(command, false, local.challenge);
	error = xp->xp_recv(xp->xp_cookie, received, sizeof(received));
	if (error != 0)
		return (error);
	if (memcmp(command, received, sizeof(command)) != 0 ||
	    peer.phase < MIGRATION_REC_SOURCE_RELEASED)
		return (EPROTO);
	run_state->observed = MIGRATION_REC_VM_UNAVAILABLE;
	error = ops->observe(arg, &run_state->observed);
	if (error == 0)
		error = migration_recovery_reconcile(&peer, &local,
		    local.source_certificate_sha256, local.destination_certificate_sha256,
		    run_state->observed, &action);
	if (error != 0)
		return (error);
	if (action != MIGRATION_REC_REISSUE_RELEASE &&
	    action != MIGRATION_REC_CONFIRM_RUNNING && action != MIGRATION_REC_COMPLETE)
		return (EPROTO);
	if (local.phase == MIGRATION_REC_DEST_STAGED) {
		local.phase = MIGRATION_REC_DEST_RELEASED;
		error = migration_recovery_store_at(dirfd, &local);
		if (error != 0)
			return (error);
	}
	if (run_state->observed == MIGRATION_REC_VM_PAUSED) {
		run_state->resume_uncertain = true;
		error = ops->resume(arg);
		if (error != 0)
			return (error);
		run_state->observed = MIGRATION_REC_VM_UNAVAILABLE;
		error = ops->observe(arg, &run_state->observed);
		if (error != 0)
			return (error);
		if (run_state->observed != MIGRATION_REC_VM_RUNNING)
			return (EBUSY);
		run_state->resume_uncertain = false;
	}
	if (local.phase != MIGRATION_REC_DEST_RUNNING) {
		local.phase = MIGRATION_REC_DEST_RUNNING;
		error = migration_recovery_store_at(dirfd, &local);
		if (error != 0)
			return (error);
	}
	migration_recovery_command(command, true, local.challenge);
	error = xp->xp_send(xp->xp_cookie, command, sizeof(command));
	run_state->ack_sent = error == 0;
	return (error);
}

/* Retry release only after checked retirement is already durable. INTENT is
 * insufficient: its recovery driver must complete checked destruction first.
 * This function never recreates or resumes a source VM. */
static inline int
migration_recovery_source_run(struct migration_channel *channel,
    const struct migration_transport *xp, int dirfd,
    const struct migration_recovery_record *expected)
{
	struct migration_recovery_record local, peer;
	uint8_t source_certificate[32], destination_certificate[32];
	uint8_t command[40], received[40];
	uint16_t phase;
	int error;

	if (expected == NULL || channel == NULL || xp == NULL ||
	    xp->xp_send == NULL || xp->xp_recv == NULL)
		return (EINVAL);
	error = migration_channel_binding(channel, true, source_certificate, destination_certificate);
	if (error != 0)
		return (error);
#ifndef NO_OPENSSL
	if (xp->xp_cookie != &channel->tls)
		return (EACCES);
#endif
	if (memcmp(source_certificate, expected->source_certificate_sha256, 32) != 0 ||
	    memcmp(destination_certificate, expected->destination_certificate_sha256, 32) != 0)
		return (EACCES);
	error = migration_recovery_load_at(dirfd, expected, &phase);
	if (error != 0)
		return (error);
	if (phase < MIGRATION_REC_SOURCE_RETIRED || phase > MIGRATION_REC_SOURCE_CONFIRMED)
		return (EBUSY);
	local = *expected;
	local.phase = phase;
	if (phase == MIGRATION_REC_SOURCE_RETIRED) {
		local.phase = MIGRATION_REC_SOURCE_RELEASED;
		error = migration_recovery_store_at(dirfd, &local);
		if (error != 0)
			return (error);
	}
	error = migration_recovery_exchange(channel, xp, dirfd, true, &local, &local, &peer);
	if (error != 0)
		return (error);
	if (local.phase == MIGRATION_REC_SOURCE_CONFIRMED && peer.phase != MIGRATION_REC_DEST_RUNNING)
		return (EPROTO);
	migration_recovery_command(command, false, local.challenge);
	error = xp->xp_send(xp->xp_cookie, command, sizeof(command));
	if (error == 0)
		error = xp->xp_recv(xp->xp_cookie, received, sizeof(received));
	if (error != 0)
		return (error);
	migration_recovery_command(command, true, local.challenge);
	if (memcmp(received, command, sizeof(command)) != 0)
		return (EPROTO);
	local.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	return (migration_recovery_store_at(dirfd, &local));
}
#endif
