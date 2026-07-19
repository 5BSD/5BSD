/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Connection lifecycle management for blued.
 *
 * Provides allocation, kqueue registration, and cleanup for
 * blued_conn instances used by both central and peripheral modes.
 */

#ifndef _CONN_H_
#define _CONN_H_

#include "blued.h"

/*
 * Allocate a blued_conn and insert into blued_g.conns.
 * Returns NULL on allocation failure.
 */
struct blued_conn	*blued_conn_alloc(void);

/*
 * Detach conn from blued_g.conns, delete its conn-owned kqueue timers,
 * and release the list's reference.  The backing memory is freed once
 * the final reference is dropped (see blued_conn_unref), so a teardown
 * that races a running setup thread is safe.
 * For peripheral connections (att_owned != NULL), closes the ATT fd.
 * For central connections, does NOT close the ATT fd — caller must do that.
 */
void			 blued_conn_free(struct blued_conn *conn);

/*
 * Acquire/release a reference on conn.  A detached setup thread takes
 * a reference before it starts and drops it when it exits; the heap
 * object is freed when the last reference is released.
 */
void			 blued_conn_ref(struct blued_conn *conn);
void			 blued_conn_unref(struct blued_conn *conn);

/*
 * Register conn's ATT fd with the global kqueue for EVFILT_READ.
 * Uses conn as the udata tag.  Returns 0 on success, -1 on failure.
 */
int			 blued_conn_register(struct blued_conn *conn);
int			 blued_conn_register_bearer(struct blued_conn *conn,
			    int fd);
void			 blued_conn_unregister_bearer(int fd);

/* Enable/disable EVFILT_READ on every ATT bearer owned by conn. */
void			 blued_conn_set_att_events(struct blued_conn *conn,
				    bool enabled);

/* True only while the event loop owns receive() on this connection's ATT fds. */
bool			 blued_conn_att_event_ready(const struct blued_conn *conn);

/* Delete every ATT bearer registration before transport teardown. */
void			 blued_conn_unregister_att(struct blued_conn *conn);

/*
 * Change connection state with logging.
 */
void			 blued_conn_set_state(struct blued_conn *conn,
				    int new_state);

/* Capture the local address used on air for SMP address-dependent crypto. */
void			 blued_conn_local_from_socket(struct blued_conn *conn,
				    int fd);
bool			 blued_conn_get_local(struct blued_conn *conn,
				    uint8_t addr[6], uint8_t *type);
void			 blued_conn_reset_local(struct blued_conn *conn);
void			 blued_conn_apply_cached_local(struct blued_conn *conn);
void			 blued_conn_note_enhanced(struct blued_adapter *adapter,
				    uint16_t handle, const uint8_t peer[6],
				    uint8_t peer_type, const uint8_t local_rpa[6],
				    const uint8_t peer_rpa[6]);

/* Find an exact peer on one controller, including its LE address type. */
struct blued_conn	*blued_conn_by_peer(const struct blued_adapter *adapter,
			    const bdaddr_t *addr, uint8_t addr_type);

/* Find a controller-local HCI handle on its owning adapter. */
struct blued_conn	*blued_conn_by_handle(const struct blued_adapter *adapter,
			    uint16_t handle);

/*
 * Resolve an adapter by its stable index (0 == primary).  Returns NULL
 * for an out-of-range index or when no adapter carries that index.  Used
 * to route a client's per-adapter command to the addressed adapter.
 */
struct blued_adapter	*blued_adapter_by_index(int idx);
struct blued_adapter	*blued_adapter_by_index_powered(int idx);

/*
 * Resolve the adapter that owns an HCI socket fd.  Returns NULL if no
 * active adapter holds that descriptor.  Mirrors the key the event loop
 * uses to demux an incoming HCI event to its owning adapter.
 */
struct blued_adapter	*blued_adapter_by_fd(int fd);

/*
 * Assign each adapter a stable index by list position, primary first.
 * Called once after enumeration so a client can address an adapter by a
 * consistent number.
 */
void			 blued_index_adapters(void);

#endif /* _CONN_H_ */
