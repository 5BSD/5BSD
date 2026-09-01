/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd's radio bearer, realised as a privileged client of blued.
 *
 * meshd never opens an HCI socket itself: blued is the sole HCI owner, and
 * meshd reaches the radio only through blued's control socket using the
 * mesh bearer API.  This module is a small,
 * mesh-scoped client of blued's length-prefixed control protocol:
 *
 *   - HELLO negotiates the mesh and asynchronous-event capability bits,
 *     then MESH_ADV_SUBSCRIBE registers meshd as a mesh-adv subscriber.
 *   - Outbound: meshd_blued_tx() is the struct meshd_bearer sink; it maps the
 *     PDU class to an AD type and emits a typed mesh operation.
 *   - Inbound: meshd_blued_pump_rx() drains typed MESH_ADV events and
 *     dispatches each to the matching meshd RX seam by AD type.
 *
 * Only opaque mesh PDUs cross this boundary; all mesh crypto/relay stays in
 * meshd.  The daemons share ipc_proto.h so this boundary has one wire contract.
 */

#ifndef _MESHD_BEARER_BLUED_H_
#define _MESHD_BEARER_BLUED_H_

#include <stddef.h>
#include <stdint.h>

#include "meshd.h"		/* enum meshd_pdu_class, struct meshd_node */

struct meshd_persist;

/* Reassembly buffer: one maximum control frame plus header slack. */
#define	MESHD_BLUED_RXBUF	(8u + 4096u)
#define	MESHD_BLUED_TXBUF	(16u * 1024u)
#define	MESHD_BLUED_MAX_PEERS	32
#define	MESHD_BLUED_MAX_WRITES	128
#define	MESHD_GATT_NONE		0
#define	MESHD_GATT_PROVISIONING	1

#define	MESHD_BLUED_WRITE_PROXY	1
#define	MESHD_BLUED_WRITE_PBGATT	2

#define	MESHD_BLUED_DOWN	0
#define	MESHD_BLUED_CONNECTING	1
#define	MESHD_BLUED_HELLO	2
#define	MESHD_BLUED_SUBSCRIBING	3
#define	MESHD_BLUED_READY	4

struct meshd_blued_write {
	uint32_t	request_id;
	uint64_t	generation;
	uint8_t		kind;
	uint8_t		proxy_index;
	uint8_t		terminal;
};

struct meshd_blued_proxy_link {
	char		addr[18];
	uint8_t		addr_type;	/* IPC address type: 0 public, 1 random */
	uint8_t		adapter_index;
	uint8_t		session_adapter_index; /* selector supplied by meshd */
	uint16_t	mtu;
	uint32_t	discover_request_id;
	uint32_t	subscribe_request_id;
	uint16_t	data_in;
	uint16_t	data_out;
	int		discovering;
	int		subscribing;
	int		subscribed;
	int		in_service;
	int		active;
};

struct meshd_blued_peer {
	uint8_t		addr[6];
	uint8_t		addr_type;
	uint8_t		adapter_index;
	uint16_t	mtu;
	int		active;
};

/*
 * The blued client state.  fd < 0 means the bearer is down (blued absent
 * or the connection dropped); the daemon keeps running on the sim and the tick
 * loop retries meshd_blued_maintain() with backoff.  All buffers are inline so
 * the object can live on the caller's stack.
 */
struct meshd_blued {
	int		fd;		/* connected control socket, -1 = down */
	uint8_t		state;		/* nonblocking connection/handshake phase */
	uint64_t	generation;	/* changes whenever a new fd is adopted */
	uint64_t	handshake_deadline; /* absolute monotonic milliseconds */
	uint32_t	handshake_request_id;
	struct meshd_node *node;		/* owner used for transport-failure teardown */
	char		sockpath[104];	/* remembered for reconnect */
	uint64_t	retry_at;	/* monotonic msecs: next reconnect due */
	unsigned	backoff;	/* current reconnect backoff, secs */
	uint32_t	next_request_id;
	uint64_t	pbgatt_generation;
	uint32_t	discover_request_id;
	uint32_t	subscribe_request_id;
	uint8_t		rx[MESHD_BLUED_RXBUF];	/* frame reassembly buffer */
	size_t		rxn;		/* bytes buffered in rx[] */
	uint8_t		tx[MESHD_BLUED_TXBUF];	/* complete queued frames */
	size_t		txoff;		/* first unsent byte in tx[] */
	size_t		txlen;		/* end of queued data in tx[] */
	char		gatt_addr[18];
	uint8_t		gatt_addr_type;
	uint8_t		gatt_adapter_index;
	uint16_t	gatt_mtu;
	uint16_t	gatt_data_in;
	uint16_t	gatt_data_out;
	int		gatt_discovering;
	int		gatt_subscribing;
	int		gatt_subscribed;
	int		gatt_in_service;
	uint8_t		gatt_mesh_type;	/* provisioning or network proxy */
	struct meshd_blued_proxy_link proxy[MESHD_MAX_PROXY_GATT];
	struct meshd_blued_peer peers[MESHD_BLUED_MAX_PEERS];
	/* Correlates every accepted GATT Write Command with its mesh link. */
	struct meshd_blued_write writes[MESHD_BLUED_MAX_WRITES];
	int		pbgatt_pending;	/* retry output after transient pressure */
	int		pbgatt_draining;
};

/* Initialise the client as down and remember the blued socket path. */
void	meshd_blued_init(struct meshd_blued *bc, const char *sockpath);
void	meshd_blued_bind_node(struct meshd_blued *bc, struct meshd_node *nd);

/*
 * Start a nonblocking blued connection.  The writable and receive pumps
 * advance connect, HELLO, and MESH_ADV_SUBSCRIBE under one absolute deadline;
 * interleaved events are dispatched as complete frames arrive.  Returns 0 once
 * the attempt has started (the fd is immediately available to kqueue), or -1
 * when no attempt could be started.
 */
int	meshd_blued_connect(struct meshd_blued *bc);

/*
 * Adopt an already-connected fd and synchronously run the same handshake.  This
 * compatibility seam is used by socketpair tests; production uses the fully
 * nonblocking meshd_blued_connect() state machine.  Takes ownership of fd.
 */
int	meshd_blued_attach(struct meshd_blued *bc, int fd);

/* The poll fd, or -1 when the bearer is down (poll() ignores a negative fd). */
int	meshd_blued_fd(const struct meshd_blued *bc);
uint64_t meshd_blued_generation(const struct meshd_blued *bc);
int	meshd_blued_wants_write(const struct meshd_blued *bc);
int	meshd_blued_flush(struct meshd_blued *bc);

/*
 * Reconnect maintenance for the tick loop.  If ready, returns 1 and also retries
 * provisioning output deferred by queue pressure.  If down, starts a reconnect
 * only once its backoff window has elapsed; handshaking and down both return 0.
 */
int	meshd_blued_maintain(struct meshd_blued *bc, uint64_t now);

/*
 * Drain all buffered EVENT MESH_ADV frames and dispatch by AD type to the node:
 * 0x2A -> meshd_bearer_rx, 0x2B -> meshd_beacon_rx, 0x29 ->
 * meshd_provisioner_recv (whose outbound is then drained back to the bearer).
 * now is the monotonic clock fed to the provisioner.  On a socket error/EOF the
 * bearer is marked down.  Returns the number of events dispatched (>= 0), -1 on
 * a bad argument.
 */
int	meshd_blued_pump_rx(struct meshd_blued *bc, struct meshd_node *nd,
	    struct meshd_persist *ps, uint64_t now);

/*
 * The struct meshd_bearer transmit sink (arg is the struct meshd_blued *).
 * Maps cls to its AD type and emits MESH_ADV_SEND.  Returns 0 on success, -1 if
 * the bearer is down, the PDU is too large, or the write fails (a write failure
 * marks the bearer down for the reconnect loop).
 */
int	meshd_blued_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu,
	    size_t len);

/* Bind a discovered Mesh Provisioning Service and move PB-GATT Proxy PDUs. */
int	meshd_blued_pbgatt_bind(struct meshd_blued *bc, const char *addr,
	    uint8_t addr_type, uint16_t data_in, uint16_t data_out);
int	meshd_blued_pbgatt_discover(struct meshd_blued *bc, const char *addr,
	    uint8_t addr_type);
int	meshd_blued_pbgatt_open(void *arg, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
int	meshd_blued_proxy_open(void *arg, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
int	meshd_blued_proxy_close(void *arg, const char *addr,
	    uint8_t addr_type, uint8_t adapter_index);
int	meshd_blued_pbgatt_close(void *arg);
int	meshd_blued_pbgatt_timeout(void *arg);
int	meshd_blued_proxy_tx(void *arg, const char *addr, uint8_t addr_type,
	    uint8_t adapter_index, uint8_t type, const uint8_t *pdu, size_t len);
int	meshd_blued_pbgatt_drain(struct meshd_blued *bc,
	    struct meshd_node *nd);

/* Close the socket and mark the bearer down (idempotent). */
void	meshd_blued_close(struct meshd_blued *bc);

#endif /* _MESHD_BEARER_BLUED_H_ */
