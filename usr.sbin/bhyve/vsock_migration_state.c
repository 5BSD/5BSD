/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <string.h>

#include "vsock_migration_state.h"

#define VSOCK_MIGRATION_CONN_MAGIC 0x31435356U /* "VSC1" */
#define VSOCK_MIGRATION_CONN_VERSION 1U
#define VSOCK_MIGRATION_TABLE_MAGIC 0x31545356U /* "VST1" */
#define VSOCK_MIGRATION_TABLE_VERSION 1U
#define VSOCK_MIGRATION_CONN_FLAGS (VSOCK_MIGRATION_CONN_HOST_EOF | \
    VSOCK_MIGRATION_CONN_TX_EOR | VSOCK_MIGRATION_CONN_RESID_SEQ | \
    VSOCK_MIGRATION_CONN_RESID_EOR | VSOCK_MIGRATION_CONN_CLOSE_TIMER | \
    VSOCK_MIGRATION_CONN_STALL_TIMER)

static int
vsock_migration_conn_valid(const struct vsock_migration_conn_state *state,
    size_t *size)
{
	size_t total;

	/* Both guest shutdown bits close immediately; a retained close has EOF. */
	if (state == NULL || size == NULL || state->local_port < 1024 ||
	    (state->type != VSOCK_MIGRATION_TYPE_STREAM &&
	    state->type != VSOCK_MIGRATION_TYPE_SEQPACKET) ||
	    (state->state != VSOCK_MIGRATION_CONN_ESTABLISHED &&
	    state->state != VSOCK_MIGRATION_CONN_CLOSING) ||
	    (state->flags & ~VSOCK_MIGRATION_CONN_FLAGS) != 0 ||
	    (state->peer_shutdown & ~(VSOCK_MIGRATION_PEER_SHUTDOWN_RCV |
	    VSOCK_MIGRATION_PEER_SHUTDOWN_SEND)) != 0 ||
	    state->peer_shutdown == (VSOCK_MIGRATION_PEER_SHUTDOWN_RCV |
	    VSOCK_MIGRATION_PEER_SHUTDOWN_SEND) ||
	    (state->state == VSOCK_MIGRATION_CONN_CLOSING) !=
	    (((state->flags & VSOCK_MIGRATION_CONN_HOST_EOF) != 0) &&
	    ((state->peer_shutdown & VSOCK_MIGRATION_PEER_SHUTDOWN_SEND) != 0)) ||
	    state->buf_alloc == 0 ||
	    state->buf_alloc > VSOCK_MIGRATION_MAX_BUFFER ||
	    state->peer_buf_alloc > VSOCK_MIGRATION_MAX_PEER_BUFFER ||
	    /* Peer credit may shrink, but outstanding data cannot exceed its cap. */
	    state->tx_cnt - state->peer_fwd_cnt >
	    VSOCK_MIGRATION_MAX_PEER_BUFFER ||
	    state->rx_reasm_len > state->buf_alloc ||
	    state->tx_buf_len > state->buf_alloc ||
	    state->rx_resid_len > VSOCK_MIGRATION_MAX_PEER_BUFFER ||
	    (state->rx_resid_len != 0 &&
	    state->rx_resid_off >= state->rx_resid_len) ||
	    (state->rx_resid_len == 0 && state->rx_resid_off != 0) ||
	    (state->type == VSOCK_MIGRATION_TYPE_STREAM &&
	    state->rx_resid_len > VSOCK_MIGRATION_MAX_STREAM_RESID) ||
	    (state->type == VSOCK_MIGRATION_TYPE_SEQPACKET &&
	    state->rx_resid_len != 0 &&
	    (state->flags & VSOCK_MIGRATION_CONN_RESID_SEQ) == 0) ||
	    ((state->flags & VSOCK_MIGRATION_CONN_TX_EOR) != 0 &&
	    state->tx_buf_len == 0) ||
	    (state->close_age_seconds != 0 &&
	    (state->flags & VSOCK_MIGRATION_CONN_CLOSE_TIMER) == 0) ||
	    (state->state == VSOCK_MIGRATION_CONN_CLOSING &&
	    (state->flags & VSOCK_MIGRATION_CONN_CLOSE_TIMER) == 0) ||
	    (state->state == VSOCK_MIGRATION_CONN_ESTABLISHED &&
	    (state->flags & VSOCK_MIGRATION_CONN_CLOSE_TIMER) != 0) ||
	    (state->stall_age_seconds != 0 &&
	    (state->flags & VSOCK_MIGRATION_CONN_STALL_TIMER) == 0) ||
	    (state->rx_reasm_len != 0 && state->rx_reasm == NULL) ||
	    (state->tx_buf_len != 0 && state->tx_buf == NULL) ||
	    (state->rx_resid_len != 0 && state->rx_resid == NULL) ||
	    (state->type == VSOCK_MIGRATION_TYPE_STREAM &&
	    (state->rx_reasm_len != 0 ||
	    (state->flags & (VSOCK_MIGRATION_CONN_TX_EOR |
	    VSOCK_MIGRATION_CONN_RESID_SEQ |
	    VSOCK_MIGRATION_CONN_RESID_EOR)) != 0)) ||
	    ((state->flags & VSOCK_MIGRATION_CONN_RESID_EOR) != 0 &&
	    (state->flags & VSOCK_MIGRATION_CONN_RESID_SEQ) == 0) ||
	    (state->rx_resid_len == 0 &&
	    (state->rx_resid_off != 0 ||
	    (state->flags & (VSOCK_MIGRATION_CONN_RESID_SEQ |
	    VSOCK_MIGRATION_CONN_RESID_EOR)) != 0)))
		return (EINVAL);
	total = VSOCK_MIGRATION_CONN_HEADER_SIZE + state->rx_reasm_len +
	    state->tx_buf_len + state->rx_resid_len;
	*size = total;
	return (0);
}

int
vsock_migration_conn_state_size(const struct vsock_migration_conn_state *state,
    size_t *size)
{

	return (vsock_migration_conn_valid(state, size));
}

int
vsock_migration_conn_state_encode(const struct vsock_migration_conn_state *state,
    uint8_t *wire, size_t wire_size)
{
	size_t offset, size;
	int error;

	if (wire == NULL)
		return (EINVAL);
	error = vsock_migration_conn_valid(state, &size);
	if (error != 0)
		return (error);
	if (wire_size < size)
		return (EMSGSIZE);
	le32enc(wire, VSOCK_MIGRATION_CONN_MAGIC);
	le32enc(wire + 4, VSOCK_MIGRATION_CONN_VERSION);
	le32enc(wire + 8, (uint32_t)size);
	le32enc(wire + 12, state->local_port);
	le32enc(wire + 16, state->guest_port);
	le32enc(wire + 20, state->type);
	le32enc(wire + 24, state->state);
	le32enc(wire + 28, state->flags);
	le32enc(wire + 32, state->peer_shutdown);
	le32enc(wire + 36, state->buf_alloc);
	le32enc(wire + 40, state->fwd_cnt);
	le32enc(wire + 44, state->last_fwd_cnt);
	le32enc(wire + 48, state->tx_cnt);
	le32enc(wire + 52, state->peer_buf_alloc);
	le32enc(wire + 56, state->peer_fwd_cnt);
	le32enc(wire + 60, state->rx_reasm_len);
	le32enc(wire + 64, state->tx_buf_len);
	le32enc(wire + 68, state->rx_resid_len);
	le32enc(wire + 72, state->rx_resid_off);
	le32enc(wire + 76, state->close_age_seconds);
	le32enc(wire + 80, state->stall_age_seconds);
	le32enc(wire + 84, 0);
	offset = VSOCK_MIGRATION_CONN_HEADER_SIZE;
	if (state->rx_reasm_len != 0) {
		memcpy(wire + offset, state->rx_reasm, state->rx_reasm_len);
		offset += state->rx_reasm_len;
	}
	if (state->tx_buf_len != 0) {
		memcpy(wire + offset, state->tx_buf, state->tx_buf_len);
		offset += state->tx_buf_len;
	}
	if (state->rx_resid_len != 0)
		memcpy(wire + offset, state->rx_resid, state->rx_resid_len);
	return (0);
}

int
vsock_migration_conn_state_decode(const uint8_t *wire, size_t wire_size,
    struct vsock_migration_conn_state *state)
{
	struct vsock_migration_conn_state candidate;
	size_t size, offset;
	int error;

	if (wire == NULL || state == NULL ||
	    wire_size < VSOCK_MIGRATION_CONN_HEADER_SIZE)
		return (EINVAL);
	if (le32dec(wire) != VSOCK_MIGRATION_CONN_MAGIC ||
	    le32dec(wire + 4) != VSOCK_MIGRATION_CONN_VERSION ||
	    le32dec(wire + 8) != wire_size || le32dec(wire + 84) != 0)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.local_port = le32dec(wire + 12);
	candidate.guest_port = le32dec(wire + 16);
	candidate.type = le32dec(wire + 20);
	candidate.state = le32dec(wire + 24);
	candidate.flags = le32dec(wire + 28);
	candidate.peer_shutdown = le32dec(wire + 32);
	candidate.buf_alloc = le32dec(wire + 36);
	candidate.fwd_cnt = le32dec(wire + 40);
	candidate.last_fwd_cnt = le32dec(wire + 44);
	candidate.tx_cnt = le32dec(wire + 48);
	candidate.peer_buf_alloc = le32dec(wire + 52);
	candidate.peer_fwd_cnt = le32dec(wire + 56);
	candidate.rx_reasm_len = le32dec(wire + 60);
	candidate.tx_buf_len = le32dec(wire + 64);
	candidate.rx_resid_len = le32dec(wire + 68);
	candidate.rx_resid_off = le32dec(wire + 72);
	candidate.close_age_seconds = le32dec(wire + 76);
	candidate.stall_age_seconds = le32dec(wire + 80);
	/* Validate lengths before forming any pointer beyond the record. */
	if (candidate.rx_reasm_len > wire_size -
	    VSOCK_MIGRATION_CONN_HEADER_SIZE ||
	    candidate.tx_buf_len > wire_size -
	    VSOCK_MIGRATION_CONN_HEADER_SIZE - candidate.rx_reasm_len ||
	    candidate.rx_resid_len > wire_size -
	    VSOCK_MIGRATION_CONN_HEADER_SIZE - candidate.rx_reasm_len -
	    candidate.tx_buf_len)
		return (EINVAL);
	offset = VSOCK_MIGRATION_CONN_HEADER_SIZE;
	candidate.rx_reasm = candidate.rx_reasm_len == 0 ? NULL : wire + offset;
	offset += candidate.rx_reasm_len;
	candidate.tx_buf = candidate.tx_buf_len == 0 ? NULL : wire + offset;
	offset += candidate.tx_buf_len;
	candidate.rx_resid = candidate.rx_resid_len == 0 ? NULL : wire + offset;
	error = vsock_migration_conn_valid(&candidate, &size);
	if (error != 0 || size != wire_size)
		return (EINVAL);
	*state = candidate;
	return (0);
}

/* A table is the unit restored atomically by the device snapshot callback. */
int
vsock_migration_table_size(const struct vsock_migration_conn_state *states,
    uint32_t count, size_t *size)
{
	size_t record_size, total;
	uint64_t reasm_total, tx_total;
	uint32_t i, j;
	int error;

	if (size == NULL || count > VSOCK_MIGRATION_MAX_CONNS ||
	    (count != 0 && states == NULL))
		return (EINVAL);
	total = VSOCK_MIGRATION_TABLE_HEADER_SIZE;
	reasm_total = tx_total = 0;
	for (i = 0; i < count; i++) {
		error = vsock_migration_conn_valid(&states[i], &record_size);
		if (error != 0)
			return (error);
		if (record_size > VSOCK_MIGRATION_MAX_TABLE_SIZE - total)
			return (EFBIG);
		total += record_size;
		reasm_total += states[i].rx_reasm_len;
		tx_total += states[i].tx_buf_len;
		if (reasm_total > VSOCK_MIGRATION_MAX_REASM_TOTAL ||
		    tx_total > VSOCK_MIGRATION_MAX_TX_TOTAL)
			return (EFBIG);
		for (j = 0; j < i; j++) {
			if (states[i].local_port == states[j].local_port)
				return (EINVAL);
		}
	}
	*size = total;
	return (0);
}

int
vsock_migration_table_encode(const struct vsock_migration_conn_state *states,
    uint32_t count, uint8_t *wire, size_t wire_size)
{
	size_t offset, record_size, size;
	uint32_t i;
	int error;

	if (wire == NULL)
		return (EINVAL);
	error = vsock_migration_table_size(states, count, &size);
	if (error != 0)
		return (error);
	if (wire_size < size)
		return (EMSGSIZE);
	le32enc(wire, VSOCK_MIGRATION_TABLE_MAGIC);
	le32enc(wire + 4, VSOCK_MIGRATION_TABLE_VERSION);
	le32enc(wire + 8, (uint32_t)size);
	le32enc(wire + 12, count);
	le32enc(wire + 16, 0);
	offset = VSOCK_MIGRATION_TABLE_HEADER_SIZE;
	for (i = 0; i < count; i++) {
		/* Validation above already proved every record and the total. */
		(void)vsock_migration_conn_valid(&states[i], &record_size);
		(void)vsock_migration_conn_state_encode(&states[i], wire + offset,
		    record_size);
		offset += record_size;
	}
	return (0);
}

int
vsock_migration_table_decode(const uint8_t *wire, size_t wire_size,
    struct vsock_migration_conn_state *states, uint32_t capacity,
    uint32_t *count_out)
{
	struct vsock_migration_conn_state candidate[VSOCK_MIGRATION_MAX_CONNS];
	size_t offset, record_size;
	uint64_t reasm_total, tx_total;
	uint32_t count, i, j;
	int error;

	if (wire == NULL || count_out == NULL ||
	    wire_size < VSOCK_MIGRATION_TABLE_HEADER_SIZE ||
	    wire_size > VSOCK_MIGRATION_MAX_TABLE_SIZE ||
	    le32dec(wire) != VSOCK_MIGRATION_TABLE_MAGIC ||
	    le32dec(wire + 4) != VSOCK_MIGRATION_TABLE_VERSION ||
	    le32dec(wire + 8) != wire_size || le32dec(wire + 16) != 0)
		return (EINVAL);
	count = le32dec(wire + 12);
	if (count > VSOCK_MIGRATION_MAX_CONNS || count > capacity ||
	    (count != 0 && states == NULL))
		return (EINVAL);
	offset = VSOCK_MIGRATION_TABLE_HEADER_SIZE;
	reasm_total = tx_total = 0;
	for (i = 0; i < count; i++) {
		if (wire_size - offset < VSOCK_MIGRATION_CONN_HEADER_SIZE)
			return (EINVAL);
		record_size = le32dec(wire + offset + 8);
		if (record_size < VSOCK_MIGRATION_CONN_HEADER_SIZE ||
		    record_size > wire_size - offset)
			return (EINVAL);
		error = vsock_migration_conn_state_decode(wire + offset,
		    record_size, &candidate[i]);
		if (error != 0)
			return (error);
		reasm_total += candidate[i].rx_reasm_len;
		tx_total += candidate[i].tx_buf_len;
		if (reasm_total > VSOCK_MIGRATION_MAX_REASM_TOTAL ||
		    tx_total > VSOCK_MIGRATION_MAX_TX_TOTAL)
			return (EFBIG);
		for (j = 0; j < i; j++) {
			if (candidate[i].local_port == candidate[j].local_port)
				return (EINVAL);
		}
		offset += record_size;
	}
	if (offset != wire_size)
		return (EINVAL);
	if (count != 0)
		memcpy(states, candidate, count * sizeof(candidate[0]));
	*count_out = count;
	return (0);
}
