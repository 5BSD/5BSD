/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_RECOVERY_EXCHANGE_H_
#define _BHYVE_MIGRATION_RECOVERY_EXCHANGE_H_

#include "migration_channel.h"
#include "migration_recovery.h"

/* A dedicated recovery connection exchanges one fixed-size HMX1 message per
 * endpoint. HMR2 binds the attempt; HMX1 binds direction and protocol. This
 * connection must never be interpreted as a normal RAM migration stream. */
#define MIGRATION_RECOVERY_EXCHANGE_SIZE (8U + MIGRATION_RECOVERY_SIZE)

static inline int
migration_recovery_peer_decode(const uint8_t *wire, size_t length,
    const struct migration_recovery_record *expected, bool peer_is_source,
    struct migration_recovery_record *peer)
{
	struct migration_recovery_record candidate;
	uint8_t canonical[MIGRATION_RECOVERY_SIZE];
	int error;

	if (wire == NULL || expected == NULL || peer == NULL)
		return (EINVAL);
	if (length != MIGRATION_RECOVERY_EXCHANGE_SIZE ||
	    memcmp(wire, "HMX1", 4) != 0 || wire[4] != 1 ||
	    wire[5] != (peer_is_source ? 1 : 2) || wire[6] != 0 || wire[7] != 0)
		return (EPROTO);
	candidate = *expected;
	candidate.phase = le16dec(wire + 8 + 6);
	if (peer_is_source ?
	    (candidate.phase < MIGRATION_REC_SOURCE_INTENT ||
	    candidate.phase > MIGRATION_REC_SOURCE_CONFIRMED) :
	    (candidate.phase < MIGRATION_REC_DEST_STAGED ||
	    candidate.phase > MIGRATION_REC_DEST_RUNNING))
		return (EPROTO);
	error = migration_recovery_encode(&candidate, canonical);
	if (error != 0)
		return (error);
	/* Canonical reconstruction checks all attempt fields, both certificate
	 * pins, reserved bytes and checksum, not merely the peer's phase. */
	if (memcmp(wire + 8, canonical, sizeof(canonical)) != 0)
		return (ESTALE);
	*peer = candidate;
	return (0);
}

/* Obtain durable snapshots, not authorization to execute. The recovery owner
 * must serialize reconciliation/actions and revalidate its VM incarnation.
 * Output is published only after a complete authenticated exchange. No state
 * transitions, source rollback, or destination resume occur here. */
static inline int
migration_recovery_exchange(struct migration_channel *channel,
    const struct migration_transport *xp, int dirfd, bool source,
    const struct migration_recovery_record *expected,
    struct migration_recovery_record *local_out,
    struct migration_recovery_record *peer_out)
{
	struct migration_recovery_record local, peer;
	uint8_t send_wire[MIGRATION_RECOVERY_EXCHANGE_SIZE] = {0};
	uint8_t recv_wire[MIGRATION_RECOVERY_EXCHANGE_SIZE];
	uint8_t source_certificate[32], destination_certificate[32];
	uint16_t phase;
	int error;

	if (channel == NULL || xp == NULL || xp->xp_send == NULL ||
	    xp->xp_recv == NULL || expected == NULL || local_out == NULL ||
	    peer_out == NULL || local_out == peer_out)
		return (EINVAL);
	local = *expected;
	if (source ? (local.phase < MIGRATION_REC_SOURCE_INTENT ||
	    local.phase > MIGRATION_REC_SOURCE_CONFIRMED) :
	    (local.phase < MIGRATION_REC_DEST_STAGED || local.phase > MIGRATION_REC_DEST_RUNNING))
		return (EPROTO);
	error = migration_channel_binding(channel, source, source_certificate,
	    destination_certificate);
	if (error != 0)
		return (error);
#ifndef NO_OPENSSL
	if (xp->xp_cookie != &channel->tls)
		return (EACCES);
#endif
	if (memcmp(source_certificate, local.source_certificate_sha256, 32) != 0 ||
	    memcmp(destination_certificate, local.destination_certificate_sha256, 32) != 0)
		return (EACCES);
	error = migration_recovery_load_at(dirfd, &local, &phase);
	if (error != 0)
		return (error);
	local.phase = phase;
	memcpy(send_wire, "HMX1", 4);
	send_wire[4] = 1;
	send_wire[5] = source ? 1 : 2;
	error = migration_recovery_encode(&local, send_wire + 8);
	if (error != 0)
		return (error);
	/* Source speaks first; destination validates before responding. */
	if (source) {
		error = xp->xp_send(xp->xp_cookie, send_wire, sizeof(send_wire));
		if (error != 0)
			return (error);
	}
	error = xp->xp_recv(xp->xp_cookie, recv_wire, sizeof(recv_wire));
	if (error == 0)
		error = migration_recovery_peer_decode(recv_wire, sizeof(recv_wire),
		    &local, !source, &peer);
	if (error != 0)
		return (error);
	if (!source) {
		error = xp->xp_send(xp->xp_cookie, send_wire, sizeof(send_wire));
		if (error != 0)
			return (error);
	}
	*local_out = local;
	*peer_out = peer;
	return (0);
}
#endif
