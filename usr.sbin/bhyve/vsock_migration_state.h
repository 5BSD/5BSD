/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VSOCK_MIGRATION_STATE_H_
#define _BHYVE_VSOCK_MIGRATION_STATE_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#define VSOCK_MIGRATION_CONN_HEADER_SIZE 88U
#define VSOCK_MIGRATION_MAX_BUFFER (256U * 1024U)
#define VSOCK_MIGRATION_MAX_PEER_BUFFER (4U * 1024U * 1024U)
#define VSOCK_MIGRATION_MAX_STREAM_RESID (64U * 1024U)
#define VSOCK_MIGRATION_MAX_CONNS 256U
#define VSOCK_MIGRATION_TABLE_HEADER_SIZE 20U
#define VSOCK_MIGRATION_MAX_REASM_TOTAL (64U * 1024U * 1024U)
#define VSOCK_MIGRATION_MAX_TX_TOTAL (64U * 1024U * 1024U)
#define VSOCK_MIGRATION_MAX_TABLE_SIZE (512U * 1024U * 1024U)

#define VSOCK_MIGRATION_TYPE_STREAM 1U
#define VSOCK_MIGRATION_TYPE_SEQPACKET 2U
#define VSOCK_MIGRATION_CONN_CONNECTING 0U
#define VSOCK_MIGRATION_CONN_ESTABLISHED 1U
#define VSOCK_MIGRATION_CONN_CLOSING 2U

#define VSOCK_MIGRATION_CONN_HOST_EOF 0x01U
#define VSOCK_MIGRATION_CONN_TX_EOR 0x02U
#define VSOCK_MIGRATION_CONN_RESID_SEQ 0x04U
#define VSOCK_MIGRATION_CONN_RESID_EOR 0x08U
#define VSOCK_MIGRATION_CONN_CLOSE_TIMER 0x10U
#define VSOCK_MIGRATION_CONN_STALL_TIMER 0x20U
#define VSOCK_MIGRATION_PEER_SHUTDOWN_RCV 1U
#define VSOCK_MIGRATION_PEER_SHUTDOWN_SEND 2U

/*
 * Protocol state only.  A live migration must separately retain the source
 * Unix sockets and attach destination relay sockets before guest release.
 * Pointers refer to caller-owned memory; decoded pointers refer to wire.
 */
struct vsock_migration_conn_state {
	uint32_t local_port;
	uint32_t guest_port;
	uint32_t type;
	uint32_t state;
	uint32_t flags;
	uint32_t peer_shutdown;
	uint32_t buf_alloc;
	uint32_t fwd_cnt;
	uint32_t last_fwd_cnt;
	uint32_t tx_cnt;
	uint32_t peer_buf_alloc;
	uint32_t peer_fwd_cnt;
	uint32_t rx_reasm_len;
	uint32_t tx_buf_len;
	uint32_t rx_resid_len;
	uint32_t rx_resid_off;
	uint32_t close_age_seconds;
	uint32_t stall_age_seconds;
	const uint8_t *rx_reasm;
	const uint8_t *tx_buf;
	const uint8_t *rx_resid;
};

int vsock_migration_conn_state_size(
    const struct vsock_migration_conn_state *, size_t *);
int vsock_migration_conn_state_encode(
    const struct vsock_migration_conn_state *, uint8_t *, size_t);
int vsock_migration_conn_state_decode(const uint8_t *, size_t,
    struct vsock_migration_conn_state *);
int vsock_migration_table_size(const struct vsock_migration_conn_state *,
    uint32_t, size_t *);
int vsock_migration_table_encode(const struct vsock_migration_conn_state *,
    uint32_t, uint8_t *, size_t);
int vsock_migration_table_decode(const uint8_t *, size_t,
    struct vsock_migration_conn_state *, uint32_t, uint32_t *);

#endif
