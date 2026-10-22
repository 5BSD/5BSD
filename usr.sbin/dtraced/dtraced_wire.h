/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_WIRE_H
#define DTRACED_WIRE_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "dtraced.h"
#include "dtraced_io.h"

/* Fixed wire offsets are independent of C ABI alignment. */
static inline void
dtraced_wire_put_u16(unsigned char *p, uint16_t value)
{
	p[0] = (unsigned char)value;
	p[1] = (unsigned char)(value >> 8);
}

static inline uint16_t
dtraced_wire_get_u16(const unsigned char *p)
{
	return ((uint16_t)p[0] | (uint16_t)p[1] << 8);
}

static inline void
dtraced_wire_put_u32(unsigned char *p, uint32_t value)
{
	for (unsigned i = 0; i != 4; ++i)
		p[i] = (unsigned char)(value >> (i * 8));
}

static inline uint32_t
dtraced_wire_get_u32(const unsigned char *p)
{
	uint32_t value = 0;
	for (unsigned i = 0; i != 4; ++i)
		value |= (uint32_t)p[i] << (i * 8);
	return (value);
}

static inline int
dtraced_wire_canonical_name(const unsigned char *name, size_t length)
{
	const unsigned char *end = (const unsigned char *)memchr(name, '\0',
	    length);
	if (end == NULL)
		return (0);
	for (const unsigned char *p = end + 1; p < name + length; ++p)
		if (*p != 0)
			return (0);
	return (1);
}

static inline void
dtraced_wire_encode_init(unsigned char wire[DTRACED_INIT_WIRE_SIZE],
    const dtd_initmsg_t *msg)
{
	dtraced_wire_put_u32(wire, (uint32_t)msg->kind);
	dtraced_wire_put_u32(wire + 4, msg->protocol_version);
	dtraced_wire_put_u64(wire + 8, msg->subs);
	memcpy(wire + 16, msg->ident, DTRACED_FDIDENTLEN);
	memcpy(wire + 144, msg->session_id, 16);
}

static inline void
dtraced_wire_decode_init(dtd_initmsg_t *msg,
    const unsigned char wire[DTRACED_INIT_WIRE_SIZE])
{
	memset(msg, 0, sizeof(*msg));
	msg->kind = (int32_t)dtraced_wire_get_u32(wire);
	msg->protocol_version = dtraced_wire_get_u32(wire + 4);
	msg->subs = dtraced_wire_get_u64(wire + 8);
	memcpy(msg->ident, wire + 16, DTRACED_FDIDENTLEN);
	memcpy(msg->session_id, wire + 144, 16);
}

/* The daemon's first message advertises only its kind and wire version.
 * Require its remaining fields to be zero so all clients agree on one
 * canonical server hello before sending credentials or control messages. */
static inline int
dtraced_wire_valid_server_init(const dtd_initmsg_t *msg)
{
	const unsigned char zero_ident[DTRACED_FDIDENTLEN] = { 0 };
	const unsigned char zero_session[16] = { 0 };

	return (msg != NULL && msg->kind == DTRACED_KIND_DTRACED &&
	    msg->protocol_version == DTRACED_PROTOCOL_VERSION &&
	    msg->subs == 0 &&
	    memcmp(msg->ident, zero_ident, sizeof(zero_ident)) == 0 &&
	    memcmp(msg->session_id, zero_session, sizeof(zero_session)) == 0);
}

static inline int
dtraced_wire_read_init(int fd, dtd_initmsg_t *msg, int64_t deadline,
    size_t *transferred)
{
	unsigned char wire[DTRACED_INIT_WIRE_SIZE];
	if (dtraced_io_transfer(fd, wire, sizeof(wire), false,
	    deadline, transferred) != 0)
		return (-1);
	dtraced_wire_decode_init(msg, wire);
	return (0);
}

static inline int
dtraced_wire_write_init(int fd, const dtd_initmsg_t *msg, int64_t deadline,
    size_t *transferred)
{
	unsigned char wire[DTRACED_INIT_WIRE_SIZE];
	dtraced_wire_encode_init(wire, msg);
	return (dtraced_io_transfer(fd, wire, sizeof(wire), true,
	    deadline, transferred));
}

/* Admission replay follows the one-byte ACK only for the restore-specific
 * forwarder subscription. Count and entries are fixed little-endian data. */
static inline void
dtraced_wire_encode_replay_kill(
    unsigned char wire[DTRACED_REPLAY_KILL_WIRE_SIZE],
    const dtraced_replay_kill_t *kill)
{
	dtraced_wire_put_u32(wire, (uint32_t)kill->pid);
	dtraced_wire_put_u16(wire + 4, kill->vmid);
	wire[6] = wire[7] = 0;
	dtraced_wire_put_u64(wire + 8, kill->epoch);
	memcpy(wire + 16, kill->source_id, 16);
}

static inline int
dtraced_wire_decode_replay_kill(dtraced_replay_kill_t *kill,
    const unsigned char wire[DTRACED_REPLAY_KILL_WIRE_SIZE])
{
	const unsigned char zero[16] = { 0 };
	if (wire[6] != 0 || wire[7] != 0 ||
	    (int32_t)dtraced_wire_get_u32(wire) <= 1 ||
	    dtraced_wire_get_u16(wire + 4) == 0 ||
	    dtraced_wire_get_u16(wire + 4) >= DTRACED_WIRE_MAX_VMS ||
	    dtraced_wire_get_u64(wire + 8) == 0 ||
	    memcmp(wire + 16, zero, 16) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(kill, 0, sizeof(*kill));
	kill->pid = (int32_t)dtraced_wire_get_u32(wire);
	kill->vmid = dtraced_wire_get_u16(wire + 4);
	kill->epoch = dtraced_wire_get_u64(wire + 8);
	memcpy(kill->source_id, wire + 16, 16);
	return (0);
}

static inline void
dtraced_wire_encode_status(unsigned char wire[DTRACED_STATUS_WIRE_SIZE],
    const dtraced_delivery_status_t *status)
{
	dtraced_wire_put_u64(wire, status->delivery_id);
	wire[8] = status->phase;
	wire[9] = status->revoked;
	wire[10] = status->replay;
	memset(wire + 11, 0, 5);
	memcpy(wire + 16, status->digest, 32);
}

static inline int
dtraced_wire_decode_status(dtraced_delivery_status_t *status,
    const unsigned char wire[DTRACED_STATUS_WIRE_SIZE])
{
	static const unsigned char zero[5] = {0};
	switch (wire[8]) {
	case 0:
	case 'a':	/* accepted delivery or applied KILL */
	case 'c':	/* committed handoff */
	case 'g':	/* guest-applied cleanup */
	case 'i':	/* installed delivery */
	case 'm':	/* mutating handoff */
	case 'p':	/* pending delivery or prepared handoff */
	case 'r':	/* claimed handoff */
	case 't':	/* terminal delivery */
	case 'u':	/* unavailable source binding */
	case 'v':	/* reserved handoff */
	case 'x':	/* exited delivery */
		break;
	default:
		errno = EPROTO;
		return (-1);
	}
	if (wire[9] > 1 || wire[10] > 1 ||
	    memcmp(wire + 11, zero, 5) != 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(status, 0, sizeof(*status));
	status->delivery_id = dtraced_wire_get_u64(wire);
	status->phase = wire[8];
	status->revoked = wire[9];
	status->replay = wire[10];
	memcpy(status->digest, wire + 16, 32);
	return (0);
}

static inline int
dtraced_wire_read_status(int fd, dtraced_delivery_status_t *status,
    int64_t deadline, size_t *transferred)
{
	unsigned char wire[DTRACED_STATUS_WIRE_SIZE];
	if (dtraced_io_transfer(fd, wire, sizeof(wire), false,
	    deadline, transferred) != 0)
		return (-1);
	return (dtraced_wire_decode_status(status, wire));
}

static inline void
dtraced_wire_encode_stats(unsigned char wire[DTRACED_STATS_WIRE_SIZE],
    const dtraced_stats_t *stats)
{
	dtraced_wire_put_u64(wire, stats->forwarder_channels);
	dtraced_wire_put_u64(wire + 8, stats->outbound_deliveries);
	dtraced_wire_put_u64(wire + 16, stats->installed_deliveries);
	dtraced_wire_put_u64(wire + 24, stats->revoked_deliveries);
}

static inline void
dtraced_wire_decode_stats(dtraced_stats_t *stats,
    const unsigned char wire[DTRACED_STATS_WIRE_SIZE])
{
	stats->forwarder_channels = dtraced_wire_get_u64(wire);
	stats->outbound_deliveries = dtraced_wire_get_u64(wire + 8);
	stats->installed_deliveries = dtraced_wire_get_u64(wire + 16);
	stats->revoked_deliveries = dtraced_wire_get_u64(wire + 24);
}

static inline int
dtraced_wire_read_stats(int fd, dtraced_stats_t *stats,
    int64_t deadline, size_t *transferred)
{
	unsigned char wire[DTRACED_STATS_WIRE_SIZE];
	if (dtraced_io_transfer(fd, wire, sizeof(wire), false,
	    deadline, transferred) != 0)
		return (-1);
	dtraced_wire_decode_stats(stats, wire);
	return (0);
}

static inline void
dtraced_wire_encode_ack(unsigned char wire[DTRACED_ACK_WIRE_SIZE],
    const dtraced_delivery_ack_t *ack)
{
	dtraced_wire_put_u64(wire, ack->delivery_id);
}

static inline void
dtraced_wire_decode_ack(dtraced_delivery_ack_t *ack,
    const unsigned char wire[DTRACED_ACK_WIRE_SIZE])
{
	ack->delivery_id = dtraced_wire_get_u64(wire);
}

static inline int
dtraced_wire_write_ack(int fd, const dtraced_delivery_ack_t *ack,
    int64_t deadline, size_t *transferred)
{
	unsigned char wire[DTRACED_ACK_WIRE_SIZE];
	dtraced_wire_encode_ack(wire, ack);
	return (dtraced_io_transfer(fd, wire, sizeof(wire), true,
	    deadline, transferred));
}

static inline void
dtraced_wire_encode_consumer_ack(
    unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE],
    const dtraced_consumer_ack_t *ack)
{
	memset(wire, 0, DTRACED_CONSUMER_ACK_WIRE_SIZE);
	dtraced_wire_put_u64(wire, ack->delivery_id);
	memcpy(wire + 8, ack->program_id, 16);
	memcpy(wire + 24, ack->source_id, 16);
	dtraced_wire_put_u16(wire + 40, ack->vmid);
	wire[42] = ack->outcome;
	dtraced_wire_put_u64(wire + 48, ack->epoch);
}

static inline int
dtraced_wire_decode_consumer_ack(dtraced_consumer_ack_t *ack,
    const unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE])
{
	static const unsigned char zero[5] = {0};
	static const unsigned char zero_id[16] = {0};
	if (memcmp(wire + 43, zero, sizeof(zero)) != 0 ||
	    dtraced_wire_get_u64(wire) == 0 ||
	    memcmp(wire + 8, zero_id, sizeof(zero_id)) == 0 ||
	    memcmp(wire + 24, zero_id, sizeof(zero_id)) == 0 ||
	    dtraced_wire_get_u16(wire + 40) == 0 ||
	    dtraced_wire_get_u16(wire + 40) >= DTRACED_WIRE_MAX_VMS ||
	    wire[42] < DTRACED_CONSUMER_ACK_NO_DERIVED ||
	    wire[42] > DTRACED_CONSUMER_ACK_DERIVED ||
	    dtraced_wire_get_u64(wire + 48) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(ack, 0, sizeof(*ack));
	ack->delivery_id = dtraced_wire_get_u64(wire);
	memcpy(ack->program_id, wire + 8, 16);
	memcpy(ack->source_id, wire + 24, 16);
	ack->vmid = dtraced_wire_get_u16(wire + 40);
	ack->outcome = wire[42];
	ack->epoch = dtraced_wire_get_u64(wire + 48);
	return (0);
}

static inline void
dtraced_wire_encode_consumer_execution(
    unsigned char wire[DTRACED_CONSUMER_EXECUTION_WIRE_SIZE],
    const dtraced_consumer_ack_t *result)
{
	dtraced_wire_encode_consumer_ack(wire, result);
	memcpy(wire + DTRACED_CONSUMER_ACK_WIRE_SIZE,
	    result->ingress_session, 16);
}

static inline int
dtraced_wire_decode_consumer_execution(dtraced_consumer_ack_t *result,
    const unsigned char wire[DTRACED_CONSUMER_EXECUTION_WIRE_SIZE])
{
	static const unsigned char zero[16] = {0};
	if (memcmp(wire + DTRACED_CONSUMER_ACK_WIRE_SIZE, zero, 16) == 0 ||
	    dtraced_wire_decode_consumer_ack(result, wire) != 0) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(result->ingress_session,
	    wire + DTRACED_CONSUMER_ACK_WIRE_SIZE, 16);
	return (0);
}

static inline void
dtraced_wire_encode_consumer_drain(
    unsigned char wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE],
    const dtraced_consumer_drain_t *drain)
{
	memset(wire, 0, DTRACED_CONSUMER_DRAIN_WIRE_SIZE);
	memcpy(wire, drain->token, 16);
	memcpy(wire + 16, drain->source_session, 16);
	memcpy(wire + 32, drain->consumer_session, 16);
	memcpy(wire + 48, drain->program_digest, 32);
	dtraced_wire_put_u16(wire + 80, drain->vmid);
	dtraced_wire_put_u64(wire + 88, drain->epoch);
}

static inline int
dtraced_wire_decode_consumer_drain(dtraced_consumer_drain_t *drain,
    const unsigned char wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE])
{
	static const unsigned char zero[16] = {0};
	static const unsigned char pad[6] = {0};
	if (memcmp(wire, zero, 16) == 0 ||
	    memcmp(wire + 16, zero, 16) == 0 ||
	    memcmp(wire + 32, zero, 16) == 0 ||
	    (memcmp(wire + 48, zero, 16) == 0 &&
	    memcmp(wire + 64, zero, 16) == 0) ||
	    dtraced_wire_get_u16(wire + 80) == 0 ||
	    dtraced_wire_get_u16(wire + 80) >= DTRACED_WIRE_MAX_VMS ||
	    memcmp(wire + 82, pad, sizeof(pad)) != 0 ||
	    dtraced_wire_get_u64(wire + 88) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(drain, 0, sizeof(*drain));
	memcpy(drain->token, wire, 16);
	memcpy(drain->source_session, wire + 16, 16);
	memcpy(drain->consumer_session, wire + 32, 16);
	memcpy(drain->program_digest, wire + 48, 32);
	drain->vmid = dtraced_wire_get_u16(wire + 80);
	drain->epoch = dtraced_wire_get_u64(wire + 88);
	return (0);
}

static inline void
dtraced_wire_encode_consumer_drain_ack(
    unsigned char wire[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE],
    const dtraced_consumer_drain_t *drain)
{
	dtraced_wire_encode_consumer_drain(wire, drain);
	memset(wire + DTRACED_CONSUMER_DRAIN_WIRE_SIZE, 0,
	    DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE - DTRACED_CONSUMER_DRAIN_WIRE_SIZE);
	wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE] = drain->result;
}

static inline int
dtraced_wire_decode_consumer_drain_ack(dtraced_consumer_drain_t *drain,
    const unsigned char wire[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE])
{
	static const unsigned char pad[7] = {0};
	dtraced_consumer_drain_t decoded;
	if (wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE] > 1 ||
	    memcmp(wire + DTRACED_CONSUMER_DRAIN_WIRE_SIZE + 1, pad,
	    sizeof(pad)) != 0 ||
	    dtraced_wire_decode_consumer_drain(&decoded, wire) != 0) {
		errno = EPROTO;
		return (-1);
	}
	decoded.result = wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
	*drain = decoded;
	return (0);
}

#define DTRACED_CONSUMER_STOP_WIRE_SIZE (8 + DTRACED_CONSUMER_DRAIN_WIRE_SIZE)
#define DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE (8 + DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE)

static inline void
dtraced_wire_encode_consumer_stop(
    unsigned char wire[DTRACED_CONSUMER_STOP_WIRE_SIZE],
    const dtraced_consumer_stop_t *stop)
{
	memcpy(wire, "HST1\0\0\0\0", 8);
	dtraced_wire_encode_consumer_drain(wire + 8, stop);
}

static inline int
dtraced_wire_decode_consumer_stop(dtraced_consumer_stop_t *stop,
    const unsigned char wire[DTRACED_CONSUMER_STOP_WIRE_SIZE])
{
	if (memcmp(wire, "HST1\0\0\0\0", 8) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (dtraced_wire_decode_consumer_drain(stop, wire + 8));
}

static inline void
dtraced_wire_encode_consumer_stop_ack(
    unsigned char wire[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE],
    const dtraced_consumer_stop_t *stop)
{
	memcpy(wire, "HSA1\0\0\0\0", 8);
	dtraced_wire_encode_consumer_drain_ack(wire + 8, stop);
}

static inline int
dtraced_wire_decode_consumer_stop_ack(dtraced_consumer_stop_t *stop,
    const unsigned char wire[DTRACED_CONSUMER_STOP_ACK_WIRE_SIZE])
{
	if (memcmp(wire, "HSA1\0\0\0\0", 8) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (dtraced_wire_decode_consumer_drain_ack(stop, wire + 8));
}

static inline void
dtraced_wire_encode_info(unsigned char wire[DTRACED_INFO_WIRE_SIZE],
    const dtraced_infomsg_t *info)
{
	dtraced_wire_put_u32(wire, (uint32_t)info->client_kind);
	memcpy(wire + 4, info->client_name, DTRACED_FDIDENTLEN);
}

static inline int
dtraced_wire_decode_info(dtraced_infomsg_t *info,
    const unsigned char wire[DTRACED_INFO_WIRE_SIZE])
{
	uint32_t kind = dtraced_wire_get_u32(wire);
	const unsigned char *name = wire + 4;
	if ((kind != DTRACED_KIND_CONSUMER &&
	    kind != DTRACED_KIND_FORWARDER &&
	    kind != DTRACED_KIND_DTRACED) ||
	    !dtraced_wire_canonical_name(name, DTRACED_FDIDENTLEN)) {
		errno = EPROTO;
		return (-1);
	}
	memset(info, 0, sizeof(*info));
	info->client_kind = (int32_t)kind;
	memcpy(info->client_name, wire + 4, DTRACED_FDIDENTLEN);
	return (0);
}

/* Fresh stop is independent of the experimental continuity protocol.
 * VM and source session identities come exclusively from the attested peer. */
static inline void
dtraced_wire_encode_session_stop(unsigned char wire[DTRACED_SESSION_STOP_WIRE_SIZE],
    const uint8_t token[16])
{
	memcpy(wire, "FST1\0\0\0\0", 8);
	memcpy(wire + 8, token, 16);
}

static inline int
dtraced_wire_decode_session_stop(uint8_t token[16],
    const unsigned char wire[DTRACED_SESSION_STOP_WIRE_SIZE])
{
	static const uint8_t zero[16] = {0};
	if (memcmp(wire, "FST1\0\0\0\0", 8) != 0 ||
	    memcmp(wire + 8, zero, 16) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(token, wire + 8, 16);
	return (0);
}

static inline void
dtraced_wire_encode_session_release(unsigned char wire[DTRACED_SESSION_STOP_WIRE_SIZE],
    const uint8_t token[16])
{
	memcpy(wire, "FRE1\0\0\0\0", 8);
	memcpy(wire + 8, token, 16);
}

static inline int
dtraced_wire_decode_session_release(uint8_t token[16],
    const unsigned char wire[DTRACED_SESSION_STOP_WIRE_SIZE])
{
	static const uint8_t zero[16] = {0};
	if (memcmp(wire, "FRE1\0\0\0\0", 8) != 0 ||
	    memcmp(wire + 8, zero, 16) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(token, wire + 8, 16);
	return (0);
}

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static inline void
dtraced_wire_encode_handoff(unsigned char wire[DTRACED_HANDOFF_WIRE_SIZE],
    const dtraced_handoff_request_t *request)
{
	wire[0] = request->op;
	memcpy(wire + 1, request->token, 16);
	memcpy(wire + 17, request->digest, 32);
}

static inline int
dtraced_wire_decode_handoff(dtraced_handoff_request_t *request,
    const unsigned char wire[DTRACED_HANDOFF_WIRE_SIZE])
{
	static const unsigned char zero16[16] = {0};
	static const unsigned char zero32[32] = {0};
	bool source_without_digest;
	uint8_t op = wire[0];

	switch (op) {
	case DTRACED_HANDOFF_ABORT:
	case DTRACED_HANDOFF_SOURCE_STATUS:
	case DTRACED_HANDOFF_EXPORT:
	case DTRACED_HANDOFF_SOURCE_GATE_BEGIN:
	case DTRACED_HANDOFF_SOURCE_GATE_ABORT:
		source_without_digest = true;
		break;
	case DTRACED_HANDOFF_COMMIT:
	case DTRACED_HANDOFF_PREPARE:
	case DTRACED_HANDOFF_RESERVE:
	case DTRACED_HANDOFF_CANCEL:
	case DTRACED_HANDOFF_MUTATE:
	case DTRACED_HANDOFF_CLAIM:
	case DTRACED_HANDOFF_DESTINATION_STATUS:
	case DTRACED_HANDOFF_BIND_KILLS_ALL:
	case DTRACED_HANDOFF_REKEY_APPLIED:
	case DTRACED_HANDOFF_PROMOTE_IMPORT:
	case DTRACED_HANDOFF_ACTIVATE_IMPORT:
	case DTRACED_HANDOFF_SOURCE_RELEASE:
	case DTRACED_HANDOFF_SOURCE_DRAIN_STEP:
	case DTRACED_HANDOFF_RELEASE_RECOVER:
	case DTRACED_HANDOFF_REPLAY_READY:
	case DTRACED_HANDOFF_EXECUTION_START:
	case DTRACED_HANDOFF_REBIND_BEGIN:
	case DTRACED_HANDOFF_REBIND_STAGE:
	case DTRACED_HANDOFF_REBIND_PENDING:
	case DTRACED_HANDOFF_REBIND_CANCEL_PENDING:
	case DTRACED_HANDOFF_REBIND_COMMIT_EMPTY:
	case DTRACED_HANDOFF_REBIND_EMPTY_READY:
	case DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT:
	case DTRACED_HANDOFF_RESET_MUTATION:
		source_without_digest = false;
		break;
	default:
		errno = EPROTO;
		return (-1);
	}
	if (memcmp(wire + 1, zero16, sizeof(zero16)) == 0 ||
	    (memcmp(wire + 17, zero32, sizeof(zero32)) == 0) !=
	    source_without_digest) {
		errno = EPROTO;
		return (-1);
	}
	request->op = wire[0];
	memcpy(request->token, wire + 1, 16);
	memcpy(request->digest, wire + 17, 32);
	return (0);
}

static inline void
dtraced_wire_encode_handoff_delivery(
    unsigned char wire[DTRACED_HANDOFF_DELIVERY_WIRE_SIZE],
    const dtraced_handoff_delivery_request_t *request)
{
	memcpy(wire, request->token, 16);
	memcpy(wire + 16, request->digest, 32);
	dtraced_wire_put_u64(wire + 48, request->delivery_id);
	memcpy(wire + 56, request->program_id, 16);
	memcpy(wire + 72, request->source_id, 16);
	wire[88] = request->scope;
	memset(wire + 89, 0, 7);
}

static inline int
dtraced_wire_decode_handoff_delivery(
    dtraced_handoff_delivery_request_t *request,
    const unsigned char wire[DTRACED_HANDOFF_DELIVERY_WIRE_SIZE])
{
	static const unsigned char zero[7] = {0};
	static const unsigned char zero16[16] = {0};
	static const unsigned char zero32[32] = {0};
	if (memcmp(wire + 89, zero, sizeof(zero)) != 0 ||
	    (wire[88] != 0 && wire[88] != 3) ||
	    dtraced_wire_get_u64(wire + 48) == 0 ||
	    memcmp(wire, zero16, sizeof(zero16)) == 0 ||
	    memcmp(wire + 16, zero32, sizeof(zero32)) == 0 ||
	    memcmp(wire + 56, zero16, sizeof(zero16)) == 0 ||
	    memcmp(wire + 72, zero16, sizeof(zero16)) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(request, 0, sizeof(*request));
	memcpy(request->token, wire, 16);
	memcpy(request->digest, wire + 16, 32);
	request->delivery_id = dtraced_wire_get_u64(wire + 48);
	memcpy(request->program_id, wire + 56, 16);
	memcpy(request->source_id, wire + 72, 16);
	request->scope = wire[88];
	return (0);
}

static inline void
dtraced_wire_encode_handoff_bind_delivery(
    unsigned char wire[DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE],
    const dtraced_handoff_bind_delivery_request_t *request)
{
	dtraced_wire_encode_handoff_delivery(wire, &request->delivery);
	memcpy(wire + DTRACED_HANDOFF_DELIVERY_WIRE_SIZE,
	    request->payload_digest, sizeof(request->payload_digest));
}

static inline int
dtraced_wire_decode_handoff_bind_delivery(
    dtraced_handoff_bind_delivery_request_t *request,
    const unsigned char wire[DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE])
{
	static const unsigned char zero32[32] = {0};
	dtraced_handoff_bind_delivery_request_t candidate;
	memset(&candidate, 0, sizeof(candidate));
	if (dtraced_wire_decode_handoff_delivery(&candidate.delivery,
	    wire) != 0)
		return (-1);
	if (candidate.delivery.scope != 0 ||
	    memcmp(wire + DTRACED_HANDOFF_DELIVERY_WIRE_SIZE, zero32,
	    sizeof(zero32)) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(candidate.payload_digest,
	    wire + DTRACED_HANDOFF_DELIVERY_WIRE_SIZE, 32);
	*request = candidate;
	return (0);
}

static inline void
dtraced_wire_encode_handoff_kill(
    unsigned char wire[DTRACED_HANDOFF_KILL_WIRE_SIZE],
    const dtraced_handoff_kill_request_t *request)
{
	memcpy(wire, request->token, 16);
	memcpy(wire + 16, request->digest, 32);
	dtraced_wire_put_u32(wire + 48, (uint32_t)request->pid);
	memcpy(wire + 52, request->source_id, 16);
	memset(wire + 68, 0, 4);
}

static inline int
dtraced_wire_decode_handoff_kill(dtraced_handoff_kill_request_t *request,
    const unsigned char wire[DTRACED_HANDOFF_KILL_WIRE_SIZE])
{
	static const unsigned char zero[4] = {0};
	static const unsigned char zero16[16] = {0};
	static const unsigned char zero32[32] = {0};
	if (memcmp(wire + 68, zero, sizeof(zero)) != 0 ||
	    (int32_t)dtraced_wire_get_u32(wire + 48) <= 1 ||
	    memcmp(wire, zero16, sizeof(zero16)) == 0 ||
	    memcmp(wire + 16, zero32, sizeof(zero32)) == 0 ||
	    memcmp(wire + 52, zero16, sizeof(zero16)) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(request, 0, sizeof(*request));
	memcpy(request->token, wire, 16);
	memcpy(request->digest, wire + 16, 32);
	request->pid = (int32_t)dtraced_wire_get_u32(wire + 48);
	memcpy(request->source_id, wire + 52, 16);
	return (0);
}

static inline void
dtraced_wire_encode_handoff_cleanup(
    unsigned char wire[DTRACED_HANDOFF_CLEANUP_WIRE_SIZE],
    const dtraced_handoff_cleanup_request_t *request)
{
	memcpy(wire, request->token, 16);
	memcpy(wire + 16, request->digest, 32);
	dtraced_wire_put_u64(wire + 48, request->delivery_id);
}

static inline int
dtraced_wire_decode_handoff_cleanup(
    dtraced_handoff_cleanup_request_t *request,
    const unsigned char wire[DTRACED_HANDOFF_CLEANUP_WIRE_SIZE])
{
	static const unsigned char zero16[16] = {}, zero32[32] = {};
	if (memcmp(wire, zero16, 16) == 0 ||
	    memcmp(wire + 16, zero32, 32) == 0 ||
	    dtraced_wire_get_u64(wire + 48) == 0) {
		errno = EPROTO;
		return (-1);
	}
	memset(request, 0, sizeof(*request));
	memcpy(request->token, wire, 16);
	memcpy(request->digest, wire + 16, 32);
	request->delivery_id = dtraced_wire_get_u64(wire + 48);
	return (0);
}
/* HT-C END */

static inline void
dtraced_wire_encode_launch(unsigned char wire[DTRACED_LAUNCH_WIRE_SIZE],
    const dtraced_launch_result_t *result)
{
	dtraced_wire_put_u64(wire, result->magic);
	wire[8] = result->installed;
	memset(wire + 9, 0, 7);
	memcpy(wire + 16, result->source_ident, DTRACED_PROGIDENTLEN);
}

static inline int
dtraced_wire_decode_launch(dtraced_launch_result_t *result,
    const unsigned char wire[DTRACED_LAUNCH_WIRE_SIZE])
{
	static const unsigned char zero[7] = {0};
	if (dtraced_wire_get_u64(wire) != DTRACED_LAUNCH_MAGIC) {
		errno = EPROTO;
		return (-1);
	}
	if (memcmp(wire + 9, zero, sizeof(zero)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (wire[8] > 1) {
		errno = EPROTO;
		return (-1);
	}
	memset(result, 0, sizeof(*result));
	result->magic = dtraced_wire_get_u64(wire);
	result->installed = wire[8];
	memcpy(result->source_ident, wire + 16, DTRACED_PROGIDENTLEN);
	return (0);
}

static inline void
dtraced_wire_encode_header(unsigned char wire[DTRACED_MSGHDRSIZE],
    const dtraced_hdr_t *h)
{
	memset(wire, 0, DTRACED_MSGHDRSIZE);
	dtraced_wire_put_u64(wire, h->msg_type);
	dtraced_wire_put_u64(wire + 8, h->elf.len);
	dtraced_wire_put_u64(wire + 16, h->elf.delivery_id);
	memcpy(wire + 24, h->elf.program_id, 16);
	memcpy(wire + 40, h->elf.source_id, 16);
	dtraced_wire_put_u32(wire + 56, (uint32_t)h->elf.ident_present);
	dtraced_wire_put_u32(wire + 60, (uint32_t)h->elf.filter_by_vmid);
	dtraced_wire_put_u16(wire + 64, h->elf.vmid);
	dtraced_wire_put_u64(wire + 72, h->elf.epoch);
	memcpy(wire + 80, h->elf.location, DTRACED_LOCSIZE);
	memcpy(wire + 144, h->elf.ident, DTRACED_PROGIDENTLEN);
	dtraced_wire_put_u32(wire + 272, (uint32_t)h->kill.pid);
	dtraced_wire_put_u16(wire + 276, h->kill.vmid);
	dtraced_wire_put_u64(wire + 280, h->kill.epoch);
	memcpy(wire + 288, h->kill.source_id, 16);
	dtraced_wire_put_u64(wire + 304, h->cleanup.num_entries);
	dtraced_wire_put_u16(wire + 312, h->cleanup.vmid);
	dtraced_wire_put_u64(wire + 320, h->cleanup.epoch);
	dtraced_wire_put_u64(wire + 328, h->info.count);
	dtraced_wire_put_u64(wire + 336, h->installed.delivery_id);
	dtraced_wire_put_u16(wire + 344, h->installed.vmid);
	dtraced_wire_put_u64(wire + 352, h->installed.epoch);
	memcpy(wire + 360, h->installed.program_id, 16);
	memcpy(wire + 376, h->installed.source_id, 16);
	memcpy(wire + 392, h->installed.name, DTRACED_FDIDENTLEN);
}

static inline int
dtraced_wire_decode_header(dtraced_hdr_t *h,
    const unsigned char wire[DTRACED_MSGHDRSIZE])
{
	static const unsigned char zero[264] = {0};
	enum {
		ELF_FIELDS = 1U << 0, KILL_FIELDS = 1U << 1,
		CLEANUP_FIELDS = 1U << 2, INFO_FIELDS = 1U << 3,
		INSTALLED_FIELDS = 1U << 4
	};
	uint64_t type = dtraced_wire_get_u64(wire);
	unsigned fields;

	switch (type) {
	case DTRACED_MSG_ELF:
		fields = ELF_FIELDS | INSTALLED_FIELDS;
		break;
	case DTRACED_MSG_CONSUMER_EXECUTION:
		/* Only elf.len is used to size the fixed execution body. */
		fields = ELF_FIELDS;
		break;
	case DTRACED_MSG_CONSUMER_PROGRAM:
		/* Only elf.len sizes the fixed HPI1 digest body. */
		fields = ELF_FIELDS;
		break;
	case DTRACED_MSG_CONSUMER_DRAIN:
	case DTRACED_MSG_CONSUMER_STOP:
		/* Only elf.len sizes the fixed quiescence challenge body. */
		fields = ELF_FIELDS;
		break;
	case DTRACED_MSG_KILL:
	case DTRACED_MSG_KILL_APPLIED:
		fields = KILL_FIELDS;
		break;
	case DTRACED_MSG_CLEANUP:
	case DTRACED_MSG_CLEANUP_APPLIED:
	case DTRACED_MSG_STATS:
		fields = CLEANUP_FIELDS;
		break;
	case DTRACED_MSG_INFO:
		fields = INFO_FIELDS;
		break;
	case DTRACED_MSG_INSTALLED:
	case DTRACED_MSG_UNINSTALLED:
	case DTRACED_MSG_STATUS:
	case DTRACED_MSG_INGRESS_STATUS:
		fields = INSTALLED_FIELDS;
		break;
	case DTRACED_MSG_HANDOFF:
	case DTRACED_MSG_HANDOFF_DELIVERY:
	case DTRACED_MSG_HANDOFF_KILL:
	case DTRACED_MSG_HANDOFF_BIND_DELIVERY:
	case DTRACED_MSG_HANDOFF_BIND_KILL:
	case DTRACED_MSG_HANDOFF_CLEANUP:
	case DTRACED_MSG_HANDOFF_IMPORT:
	case DTRACED_MSG_HANDOFF_RELEASE_IMPORT:
	case DTRACED_MSG_SESSION_STOP:
	case DTRACED_MSG_SESSION_RELEASE:
	case DTRACED_MSG_CONSUMER_STOP_COMMIT:
		fields = 0;
		break;
	default:
		errno = EPROTO;
		return (-1);
	}
	if (memcmp(wire + 66, zero, 6) != 0 ||
	    ((fields & ELF_FIELDS) != 0 &&
	    dtraced_wire_get_u16(wire + 64) >= DTRACED_WIRE_MAX_VMS) ||
	    ((fields & KILL_FIELDS) != 0 &&
	    ((int32_t)dtraced_wire_get_u32(wire + 272) <= 1 ||
	    dtraced_wire_get_u16(wire + 276) == 0 ||
	    dtraced_wire_get_u16(wire + 276) >= DTRACED_WIRE_MAX_VMS ||
	    dtraced_wire_get_u64(wire + 280) == 0 ||
	    memcmp(wire + 288, zero, 16) == 0)) ||
	    ((fields & CLEANUP_FIELDS) != 0 &&
	    dtraced_wire_get_u16(wire + 312) >= DTRACED_WIRE_MAX_VMS) ||
	    ((fields & INSTALLED_FIELDS) != 0 &&
	    dtraced_wire_get_u16(wire + 344) >= DTRACED_WIRE_MAX_VMS) ||
	    (type == DTRACED_MSG_CONSUMER_EXECUTION &&
	    (dtraced_wire_get_u64(wire + 8) !=
	    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE ||
	    memcmp(wire + 16, zero, 256) != 0)) ||
	    (type == DTRACED_MSG_CONSUMER_PROGRAM &&
	    ((dtraced_wire_get_u64(wire + 8) != 32 &&
	    dtraced_wire_get_u64(wire + 8) != 64) ||
	    memcmp(wire + 16, zero, 256) != 0)) ||
	    (type == DTRACED_MSG_CONSUMER_DRAIN &&
	    (dtraced_wire_get_u64(wire + 8) !=
	    DTRACED_CONSUMER_DRAIN_WIRE_SIZE ||
	    memcmp(wire + 16, zero, 256) != 0)) ||
	    (type == DTRACED_MSG_CONSUMER_STOP &&
	    (dtraced_wire_get_u64(wire + 8) !=
	    DTRACED_CONSUMER_STOP_WIRE_SIZE ||
	    memcmp(wire + 16, zero, 256) != 0)) ||
	    memcmp(wire + 278, zero, 2) != 0 ||
	    memcmp(wire + 314, zero, 6) != 0 ||
	    memcmp(wire + 346, zero, 6) != 0 ||
	    (type == DTRACED_MSG_STATS &&
	    (dtraced_wire_get_u16(wire + 312) != 0 ||
	    dtraced_wire_get_u64(wire + 320) != 0 ||
	    dtraced_wire_get_u64(wire + 328) != 0)) ||
	    (type == DTRACED_MSG_CLEANUP &&
	    (dtraced_wire_get_u16(wire + 312) == 0) !=
	    (dtraced_wire_get_u64(wire + 320) == 0)) ||
	    (type == DTRACED_MSG_CLEANUP &&
	    (dtraced_wire_get_u16(wire + 312) == 0) !=
	    (dtraced_wire_get_u64(wire + 328) == 0)) ||
	    (type == DTRACED_MSG_CLEANUP_APPLIED &&
	    (dtraced_wire_get_u64(wire + 304) != 0 ||
	    dtraced_wire_get_u16(wire + 312) == 0 ||
	    dtraced_wire_get_u64(wire + 320) == 0 ||
	    dtraced_wire_get_u64(wire + 328) == 0)) ||
	    ((fields & ELF_FIELDS) == 0 &&
	    memcmp(wire + 8, zero, 264) != 0) ||
	    ((fields & KILL_FIELDS) == 0 &&
	    memcmp(wire + 272, zero, 32) != 0) ||
	    ((fields & CLEANUP_FIELDS) == 0 &&
	    memcmp(wire + 304, zero, 24) != 0) ||
	    ((fields & (INFO_FIELDS | CLEANUP_FIELDS)) == 0 &&
	    memcmp(wire + 328, zero, 8) != 0) ||
	    ((fields & INSTALLED_FIELDS) == 0 &&
	    memcmp(wire + 336, zero, 184) != 0)) {
		errno = EPROTO;
		return (-1);
	}
	/* The ELF parent slot can carry a binary consumer session, and the
	 * program identity is 128 opaque bytes (libdtrace fills dp_ident with
	 * arc4random_buf), so it is compared only with memcmp and never parsed
	 * as a string. An absent identity must be all zero. All other names and
	 * the ELF location are canonical NUL-terminated strings. */
	if (((fields & ELF_FIELDS) != 0 &&
	    !dtraced_wire_canonical_name(wire + 80, DTRACED_LOCSIZE)) ||
	    ((fields & ELF_FIELDS) != 0 &&
	    (dtraced_wire_get_u32(wire + 56) > 1 ||
	    dtraced_wire_get_u32(wire + 60) > 1 ||
	    (dtraced_wire_get_u32(wire + 56) == 0 &&
	    memcmp(wire + 144, zero, DTRACED_PROGIDENTLEN) != 0))) ||
	    (type != DTRACED_MSG_ELF &&
	    (fields & INSTALLED_FIELDS) != 0 &&
	    !dtraced_wire_canonical_name(wire + 392,
	    DTRACED_FDIDENTLEN)) ||
	    (type == DTRACED_MSG_ELF &&
	    memcmp(wire + 336, zero, 184) != 0 &&
	    (dtraced_wire_get_u64(wire + 336) == 0 ||
	    dtraced_wire_get_u16(wire + 344) == 0 ||
	    dtraced_wire_get_u64(wire + 352) == 0 ||
	    memcmp(wire + 360, zero, 16) == 0 ||
	    memcmp(wire + 376, zero, 16) == 0 ||
	    memcmp(wire + 392, zero, 16) == 0 ||
	    memcmp(wire + 408, zero, DTRACED_FDIDENTLEN - 16) != 0))) {
		errno = EPROTO;
		return (-1);
	}
	memset(h, 0, sizeof(*h));
	h->msg_type = type;
	h->elf.len = dtraced_wire_get_u64(wire + 8);
	h->elf.delivery_id = dtraced_wire_get_u64(wire + 16);
	memcpy(h->elf.program_id, wire + 24, 16);
	memcpy(h->elf.source_id, wire + 40, 16);
	h->elf.ident_present = (int32_t)dtraced_wire_get_u32(wire + 56);
	h->elf.filter_by_vmid = (int32_t)dtraced_wire_get_u32(wire + 60);
	h->elf.vmid = dtraced_wire_get_u16(wire + 64);
	h->elf.epoch = dtraced_wire_get_u64(wire + 72);
	memcpy(h->elf.location, wire + 80, DTRACED_LOCSIZE);
	memcpy(h->elf.ident, wire + 144, DTRACED_PROGIDENTLEN);
	h->kill.pid = (int32_t)dtraced_wire_get_u32(wire + 272);
	h->kill.vmid = dtraced_wire_get_u16(wire + 276);
	h->kill.epoch = dtraced_wire_get_u64(wire + 280);
	memcpy(h->kill.source_id, wire + 288, 16);
	h->cleanup.num_entries = dtraced_wire_get_u64(wire + 304);
	h->cleanup.vmid = dtraced_wire_get_u16(wire + 312);
	h->cleanup.epoch = dtraced_wire_get_u64(wire + 320);
	h->info.count = dtraced_wire_get_u64(wire + 328);
	h->installed.delivery_id = dtraced_wire_get_u64(wire + 336);
	h->installed.vmid = dtraced_wire_get_u16(wire + 344);
	h->installed.epoch = dtraced_wire_get_u64(wire + 352);
	memcpy(h->installed.program_id, wire + 360, 16);
	memcpy(h->installed.source_id, wire + 376, 16);
	memcpy(h->installed.name, wire + 392, DTRACED_FDIDENTLEN);
	return (0);
}

/* HPI2 binds a compiled program to one kernel DTrace state lifetime.
 * Legacy 32-byte program registrations carry no kernel retirement evidence. */
#define DTRACED_CONSUMER_PROGRAM_V2_SIZE 64U
static inline int
dtraced_wire_decode_consumer_program_v2(const unsigned char *wire, size_t length,
    uint8_t digest[32], uint8_t lifetime[24])
{
	static const unsigned char zero[32] = {0};
	if (wire == NULL || digest == NULL || lifetime == NULL || length != 64 ||
	    memcmp(wire, "HPI2", 4) != 0 || memcmp(wire + 4, zero, 4) != 0 ||
	    memcmp(wire + 8, zero, 32) == 0 ||
	    memcmp(wire + 40, zero, 16) == 0 || dtraced_wire_get_u64(wire + 56) == 0)
		return (EPROTO);
	memcpy(digest, wire + 8, 32);
	memcpy(lifetime, wire + 40, 24);
	return (0);
}
#endif

