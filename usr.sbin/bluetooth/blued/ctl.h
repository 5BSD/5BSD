/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_CTL_H_
#define _BLUED_CTL_H_

#include <stdbool.h>
#include <stdint.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

struct blued_ctl_client;
struct blued_conn;
struct blued_adapter;

#include <pthread.h>

/*
 * Initialize ctl_clients_lock as a recursive mutex.  The ctl dispatch path
 * holds this lock across the whole verb handler and several handlers re-enter
 * it through connection-teardown / status helpers; recursion keeps the
 * outermost critical section intact (lock-reacquisition class, findings 30/88).
 */
void	blued_ctl_clients_lock_init(pthread_mutex_t *m);

int	blued_ctl_init(const char *path);
void	blued_ctl_accept(void);
int	blued_ctl_dispatch(struct blued_ctl_client *client);
int	blued_ctl_flush(struct blued_ctl_client *client);
void	blued_ctl_client_fini(struct blued_ctl_client *client);
void	blued_ctl_send_fd(int client_fd, uint64_t client_gen, int fd);
void	blued_ctl_cleanup(void);

/*
 * Quiesce and join the GATT worker pool.  Call before freeing per-connection
 * hogp/att state at shutdown so no worker dereferences a freed hogp (finding
 * 93).  Idempotent; blued_ctl_cleanup() also calls it.
 */
void	blued_ctl_gatt_workers_stop(void);

/* Push notification: send characteristic value changes to subscribed clients */
void	blued_ctl_notify_value(struct blued_conn *conn, uint16_t handle,
	    const uint8_t *value, uint16_t len, uint16_t bearer_mtu);

/*
 * Connection lifecycle push events (findings C1/C2/C5).  Broadcast a framed
 * EVENT CONNECTED / EVENT DISCONNECTED to every push-events client.  Called
 * from the event loop when a connection becomes ACTIVE (up=true, carrying the
 * connection handle, role and negotiated ATT MTU) and when it is torn down
 * (up=false, carrying the disconnect reason code).  Safe to call with no
 * clients connected (a no-op).
 */
void	blued_ctl_broadcast_conn_event(const bdaddr_t *addr, int role,
	    uint8_t addr_type, uint8_t adapter_index, uint16_t handle,
	    uint16_t mtu, bool up, uint8_t reason);

void	blued_ctl_iso_cis_request(struct blued_adapter *adp,
	    const bdaddr_t *addr, uint8_t addr_type,
	    uint16_t cis_handle, uint8_t cig_id, uint8_t cis_id);
void	blued_ctl_iso_established(struct blued_adapter *adp,
	    const bdaddr_t *addr, uint8_t addr_type,
	    uint16_t cis_handle, uint16_t mtu);
void	blued_ctl_iso_failed(struct blued_adapter *adp,
	    const bdaddr_t *addr, uint8_t addr_type,
	    uint16_t cis_handle, uint8_t status);

/* Push notification: forward GATT write to the ctl client that owns the attr */
void	blued_ctl_notify_write(int owner_fd, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/*
 * Deferred-access push events for app-backed characteristics.
 *
 * blued_ctl_notify_read: a peer is reading a dynamic characteristic — ask the
 * owning app for the value (EVENT READ <handle> [offset]).  The app answers
 * with READ_REPLY/READ_REJECT.
 *
 * blued_ctl_notify_authorize: a peer is reading or writing an authorize-gated
 * characteristic — ask the owning app to allow or deny it (EVENT AUTHORIZE
 * <handle> <read|write> <addr>).  The app answers with AUTHORIZE_REPLY.  The
 * peer address is taken from the connection that owns the att_conn.
 */
void	blued_ctl_notify_read(int owner_fd, uint16_t handle, uint16_t offset);
struct att_conn;
void	blued_ctl_notify_authorize(int owner_fd, uint16_t handle,
	    bool is_write, const struct att_conn *ac);

/* Reset owner_fd for attributes owned by a disconnected ctl client */
void	blued_ctl_reset_owner(int client_fd);

/*
 * Per-characteristic AcquireNotify/AcquireWrite lifecycle (the common
 * GATT-characteristic acquire pattern; Core Spec Vol 3 Part G notify/write).
 *
 * ctl_acquire_dispatch: pump a daemon-side acquire fd that became readable in
 * the main kqueue loop — a WRITE acquire's datagrams become ATT writes; EV_EOF
 * / client close tears the acquire down.
 * ctl_acquire_client_gone: release every acquire owned by a departing client.
 * ctl_acquire_conn_gone: release every acquire bound to a disconnected peer.
 */
struct kevent;
void	ctl_acquire_dispatch(struct kevent *ev);
void	ctl_acquire_client_gone(struct blued_ctl_client *client);
void	ctl_acquire_conn_gone(const struct blued_conn *conn);

/* Drop connection-scoped local GATT routes after a physical link ends. */
void	ctl_gatt_conn_gone(const struct blued_conn *conn);

/*
 * Runtime-added local GATT server-DB persistence (finding 137).
 *
 * CTL_GATT_OWNER_PERSISTED marks an attribute restored from a previous run: it
 * has no live client owner (served as a static attribute, like a built-in) but
 * is still re-serialized so it survives repeated restarts.
 *
 * ctl_gatt_persist_runtime: serialize every runtime attribute of the live
 * periph_gatt_db (owner_fd >= 0 or CTL_GATT_OWNER_PERSISTED) to the gattsrv
 * artifact; called under gatt_db_lock after each structural change.
 * ctl_gatt_load_persisted_services: replay that artifact into periph_gatt_db
 * after the peripheral build; called once at startup.
 */
#define CTL_GATT_OWNER_PERSISTED	(-2)
void	ctl_gatt_set_base_count(void);
void	ctl_gatt_persist_runtime(void);
void	ctl_gatt_load_persisted_services(int dirfd);

/*
 * Release a departing control client's remote GATT subscriptions.  Shared
 * CCCDs remain enabled; last-owner CCCDs are disabled asynchronously on the
 * per-connection GATT worker queue.  The client must already have been
 * removed from blued_g.ctl_clients, but must remain valid for this call.
 */
void	ctl_gatt_client_gone(struct blued_ctl_client *client);

/*
 * Mesh bearer (broker step C).
 *
 * The three mesh AD types blued acts as a dumb bearer for (Bluetooth Mesh
 * Profile / Core spec assigned numbers).  These are the ONLY AD types the
 * MESH_ADV_SEND verb accepts and the ONLY ones the receive demux forwards;
 * everything else is rejected/dropped (the leak filter).
 */
#define AD_TYPE_MESH_PB_ADV	0x29	/* PB-ADV provisioning bearer */
#define AD_TYPE_MESH_MESSAGE	0x2A	/* Mesh Message (network PDU) */
#define AD_TYPE_MESH_BEACON	0x2B	/* Mesh Beacon */

/*
 * Largest mesh PDU that fits a single legacy advertising AD structure:
 * 31-byte AD budget minus the [len][adtype] 2-byte header.
 */
#define MESH_ADV_PDU_MAX	29

/* True for one of the three mesh AD types above. */
static inline bool
blued_mesh_adtype_valid(uint8_t adtype)
{

	return (adtype == AD_TYPE_MESH_PB_ADV ||
	    adtype == AD_TYPE_MESH_MESSAGE ||
	    adtype == AD_TYPE_MESH_BEACON);
}

/*
 * Broadcast one received mesh AD field to every mesh subscriber as
 * EVENT MESH_ADV <adtype> <pdu-hex>.  Non-subscribers receive nothing.
 * adtype is assumed already validated by the caller (the demux only forwards
 * the three mesh AD types).  Safe with no subscribers (a no-op).
 */
void	blued_ctl_broadcast_mesh_adv(uint8_t adtype, const uint8_t *pdu,
	    size_t len);

/*
 * Walk the AD structures of a received advertising report's data and, for
 * each field whose AD type is a mesh type, emit one EVENT MESH_ADV to mesh
 * subscribers.  This IS the receive-side leak filter: NON-mesh AD structures
 * are dropped and never reach any client.  A malformed AD length terminates
 * the walk without over-reading.  Called from the LE adv-report path.
 */
void	blued_mesh_demux_report(const uint8_t *ad, size_t adlen);

/*
 * Re-assert the always-on mesh passive scan on every adapter that should be
 * running it.  Called after a synchronous SCAN burst (which reprograms and
 * then disables the controller scanner) so a mesh subscription is never left
 * stuck-off by an unrelated client SCAN.  A no-op when no mesh subscriber
 * exists.
 */
void	blued_mesh_scan_resume(void);
void	blued_mesh_scan_reassert(void);
void	blued_mesh_adv_reset(void);

/*
 * Release a departing client's mesh subscription (implicit unsubscribe on
 * disconnect) so an orphaned subscriber can never leave the mesh scanner
 * stuck-on.  Safe for a client that never subscribed (a no-op).
 */
void	blued_ctl_client_mesh_gone(struct blued_ctl_client *client);

/* SMP passkey/numcmp reply handling */
void	blued_ctl_passkey_reply(const char *args);
void	blued_ctl_numcmp_reply(const char *args);

void	blued_ctl_passkey_display(const bdaddr_t *addr, uint32_t passkey);
void	blued_ctl_passkey_input(const bdaddr_t *addr);
void	blued_ctl_numcmp_request(const bdaddr_t *addr, uint32_t value);
void	blued_ctl_keypress(const bdaddr_t *addr, uint8_t type);

/* Registered-agent IO capability, or the supplied static default. */
uint8_t	blued_ctl_effective_io_cap(uint8_t static_default);

#endif /* _BLUED_CTL_H_ */
