/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued connection lifecycle management.
 */

#include <sys/event.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "ble_util.h"
#include "blued.h"
#include "conn.h"

static const char *
blued_conn_state_name(int state)
{

	switch (state) {
	case BLUED_CONN_IDLE:		return ("IDLE");
	case BLUED_CONN_CONNECTING:	return ("CONNECTING");
	case BLUED_CONN_ACTIVE:		return ("ACTIVE");
	case BLUED_CONN_RECONNECTING:	return ("RECONNECTING");
	default:			return ("UNKNOWN");
	}
}

static bool
blued_addr_nonzero(const uint8_t addr[6])
{
	static const uint8_t zero[6];

	return (memcmp(addr, zero, sizeof(zero)) != 0);
}

static void
blued_conn_set_local(struct blued_conn *conn, const uint8_t addr[6],
    uint8_t type, bool from_hci)
{

	memcpy(&conn->local_addr, addr, sizeof(conn->local_addr));
	conn->local_addr_type = type;
	conn->local_addr_from_hci = from_hci;
	conn->local_addr_resolved = true;
}

void
blued_conn_local_from_socket(struct blued_conn *conn, int fd)
{
	struct sockaddr_l2cap sa;
	socklen_t len;
	bool socket_valid;

	if (conn == NULL || conn->adapter == NULL)
		return;
	memset(&sa, 0, sizeof(sa));
	len = sizeof(sa);
	socket_valid = fd >= 0 &&
	    getsockname(fd, (struct sockaddr *)&sa, &len) == 0 &&
	    len >= sizeof(sa) &&
	    (sa.l2cap_bdaddr_type == BDADDR_LE_PUBLIC ||
	    sa.l2cap_bdaddr_type == BDADDR_LE_RANDOM) &&
	    blued_addr_nonzero(sa.l2cap_bdaddr.b);
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	if (conn->local_addr_from_hci) {
		pthread_rwlock_unlock(&blued_g.conns_lock);
		return;
	}
	/* A public getsockname under 0x03 is the bind identity, not on-air proof. */
	if (socket_valid && (conn->local_own_addr_type != 0x03 ||
	    sa.l2cap_bdaddr_type == BDADDR_LE_RANDOM))
		blued_conn_set_local(conn, sa.l2cap_bdaddr.b,
		    sa.l2cap_bdaddr_type, false);
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

bool
blued_conn_get_local(struct blued_conn *conn, uint8_t addr[6], uint8_t *type)
{
	bool resolved;

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	memcpy(addr, &conn->local_addr, 6);
	if (type != NULL)
		*type = conn->local_addr_type;
	resolved = conn->local_addr_resolved;
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (resolved);
}

void
blued_conn_reset_local(struct blued_conn *conn)
{
	struct blued_local_identity *id;
	unsigned int i;

	if (conn == NULL || conn->adapter == NULL)
		return;
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	conn->con_handle = 0;
	conn->con_handle_valid = false;
	conn->controller_epoch = conn->adapter->controller_epoch;
	if (conn->local_own_addr_type == 0x03) {
		if (conn->adapter->random_addr_valid)
			blued_conn_set_local(conn,
			    (const uint8_t *)&conn->adapter->random_addr,
			    BDADDR_LE_RANDOM, false);
		else {
			memset(&conn->local_addr, 0, sizeof(conn->local_addr));
			conn->local_addr_type = BDADDR_LE_RANDOM;
			conn->local_addr_from_hci = false;
			conn->local_addr_resolved = false;
		}
	} else
		blued_conn_set_local(conn, (const uint8_t *)&conn->adapter->addr,
		    BDADDR_LE_PUBLIC, false);
	/* Do not let an Enhanced Complete cached for the prior link leak forward. */
	for (i = 0; i < BLUED_LOCAL_ID_CACHE; i++) {
		id = &conn->adapter->local_ids[i];
		if (id->valid && ((id->peer_type == conn->addr_type &&
		    memcmp(&id->peer, &conn->dst, 6) == 0) ||
		    (conn->addr_type == BDADDR_LE_RANDOM &&
		    blued_addr_nonzero((const uint8_t *)&id->peer_rpa) &&
		    memcmp(&id->peer_rpa, &conn->dst, 6) == 0)))
			id->valid = false;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

void
blued_conn_apply_cached_local(struct blued_conn *conn)
{
	struct blued_local_identity *id;
	unsigned int i;

	if (conn == NULL || conn->adapter == NULL)
		return;
	if (conn->controller_epoch == 0)
		conn->controller_epoch = conn->adapter->controller_epoch;
	blued_conn_local_from_socket(conn, -1);
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	for (i = 0; i < BLUED_LOCAL_ID_CACHE; i++) {
		id = &conn->adapter->local_ids[i];
		if (!id->valid || id->controller_epoch != conn->controller_epoch ||
		    conn->controller_epoch != conn->adapter->controller_epoch)
			continue;
		if (!((id->peer_type == conn->addr_type &&
		    memcmp(&id->peer, &conn->dst, 6) == 0) ||
		    (conn->addr_type == BDADDR_LE_RANDOM &&
		    blued_addr_nonzero((const uint8_t *)&id->peer_rpa) &&
		    memcmp(&id->peer_rpa, &conn->dst, 6) == 0)))
			continue;
		conn->con_handle = id->handle;
		conn->con_handle_valid = true;
		if (id->local_valid)
			blued_conn_set_local(conn, (const uint8_t *)&id->local,
			    id->local_type, true);
		id->valid = false;
		pthread_rwlock_unlock(&blued_g.conns_lock);
		return;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

void
blued_conn_note_enhanced(struct blued_adapter *adapter, uint16_t handle,
    const uint8_t peer[6], uint8_t peer_type, const uint8_t local_rpa[6],
    const uint8_t peer_rpa[6])
{
	struct blued_conn *conn;
	struct blued_local_identity *id;
	uint8_t local[6], local_type;
	bool local_valid;

	if (adapter == NULL)
		return;
	/* HCI 0x00/0x02 are public; 0x01/0x03 are random identities. */
	peer_type = (peer_type & 0x01) != 0 ?
	    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
	if (blued_addr_nonzero(local_rpa)) {
		memcpy(local, local_rpa, sizeof(local));
		local_type = BDADDR_LE_RANDOM;
		local_valid = true;
	} else {
		memcpy(local, &adapter->addr, sizeof(local));
		local_type = BDADDR_LE_PUBLIC;
		local_valid = true;
	}

	pthread_rwlock_wrlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter != adapter)
			continue;
		if (conn->controller_epoch != adapter->controller_epoch)
			continue;
		if ((conn->con_handle_valid && conn->con_handle == handle) ||
		    (conn->addr_type == peer_type && memcmp(&conn->dst, peer, 6) == 0) ||
		    (conn->addr_type == BDADDR_LE_RANDOM &&
		    blued_addr_nonzero(peer_rpa) && memcmp(&conn->dst, peer_rpa, 6) == 0)) {
			conn->con_handle = handle;
			conn->con_handle_valid = true;
			/* Under 0x03, zero Local_RPA does not identify the fallback. */
			if (blued_addr_nonzero(local_rpa))
				blued_conn_set_local(conn, local, local_type, true);
			else if (conn->local_own_addr_type != 0x03)
				blued_conn_set_local(conn, local, local_type, true);
			pthread_rwlock_unlock(&blued_g.conns_lock);
			return;
		}
	}
	id = &adapter->local_ids[adapter->local_id_next++ % BLUED_LOCAL_ID_CACHE];
	memcpy(&id->peer, peer, 6);
	memcpy(&id->peer_rpa, peer_rpa, 6);
	memcpy(&id->local, local, 6);
	id->handle = handle;
	id->controller_epoch = adapter->controller_epoch;
	id->peer_type = peer_type;
	id->local_type = local_type;
	/* A pre-accept privacy link likewise cannot infer public from zero. */
	id->local_valid = local_valid &&
	    (blued_addr_nonzero(local_rpa) || !adapter->privacy);
	id->valid = true;
	pthread_rwlock_unlock(&blued_g.conns_lock);
}

/*
 * Note: concurrent callers on the same conn may lose intermediate
 * state transitions (load+store is not CAS).  In the current
 * architecture this is acceptable because state writes for a given
 * connection are serialised by the setup thread -> main thread handoff.
 */
void
blued_conn_set_state(struct blued_conn *conn, int new_state)
{
	int old_state;

	old_state = atomic_load_explicit(&conn->state, memory_order_acquire);
	if (old_state == new_state)
		return;
	LOG_HOGP(1, "conn %04x: %s -> %s",
	    conn->con_handle,
	    blued_conn_state_name(old_state),
	    blued_conn_state_name(new_state));
	atomic_store_explicit(&conn->state, new_state, memory_order_release);
}

struct blued_conn *
blued_conn_alloc(void)
{
	struct blued_conn *conn, *cc;
	int nconn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return (NULL);

	conn->att_fd = -1;
	conn->state = BLUED_CONN_IDLE;
	conn->reconnect_timer = 0;
	conn->idle_timer = 0;
	/* The global connection list holds the initial reference. */
	atomic_init(&conn->refcount, 1);
	pthread_mutex_init(&conn->pairing_lock, NULL);
	pthread_cond_init(&conn->pairing_cond, NULL);
	conn->passkey_reply_status = -1;
	conn->numcmp_reply_status = -1;

	pthread_rwlock_wrlock(&blued_g.conns_lock);

	/* Enforce connection limit atomically with insertion */
	nconn = 0;
	LIST_FOREACH(cc, &blued_g.conns, entries)
		nconn++;
	if (nconn >= BLUED_MAX_CONNS) {
		pthread_rwlock_unlock(&blued_g.conns_lock);
		pthread_cond_destroy(&conn->pairing_cond);
		pthread_mutex_destroy(&conn->pairing_lock);
		free(conn);
		errno = ENOSPC;
		return (NULL);
	}

	LIST_INSERT_HEAD(&blued_g.conns, conn, entries);
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (conn);
}

/*
 * Release the backing memory once the final reference is dropped.
 * Runs from blued_conn_unref; by this point the connection is off the
 * global list and no thread holds a reference to it.
 */
static void
blued_conn_destroy(struct blued_conn *conn)
{

	if (conn->att_owned != NULL) {
		/*
		 * Close any Enhanced ATT (EATT) bearers first (Core Spec Vol 3
		 * Part G §5.3): these are extra L2CAP CoC sockets attached to
		 * the connection; closing them removes their kqueue
		 * registrations and prevents an fd leak on teardown.  Closed
		 * inline (rather than via att_close_eatt) so this TU does not
		 * pull in the ATT transport object.
		 */
		for (int i = 0; i < conn->att_owned->eatt_count; i++) {
			if (conn->att_owned->eatt[i].fd >= 0)
				close(conn->att_owned->eatt[i].fd);
			conn->att_owned->eatt[i].fd = -1;
			conn->att_owned->eatt[i].active = false;
		}
		conn->att_owned->eatt_count = 0;
		if (conn->att_owned->fd >= 0)
			close(conn->att_owned->fd);
		if (conn->att_owned->buf != NULL)
			explicit_bzero(conn->att_owned->buf, ATT_MAX_MTU);
		free(conn->att_owned->buf);
		free(conn->att_owned);
	}
	pthread_cond_destroy(&conn->pairing_cond);
	pthread_mutex_destroy(&conn->pairing_lock);
	explicit_bzero(conn, sizeof(*conn));
	free(conn);
}

void
blued_conn_ref(struct blued_conn *conn)
{

	if (conn == NULL)
		return;
	atomic_fetch_add_explicit(&conn->refcount, 1, memory_order_relaxed);
}

void
blued_conn_unref(struct blued_conn *conn)
{

	if (conn == NULL)
		return;
	if (atomic_fetch_sub_explicit(&conn->refcount, 1,
	    memory_order_acq_rel) == 1)
		blued_conn_destroy(conn);
}

void
blued_conn_free(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn == NULL)
		return;

	pthread_rwlock_wrlock(&blued_g.conns_lock);
	/*
	 * Detach from the global list exactly once.  LIST_REMOVE on an
	 * already-removed node is undefined behavior; le_prev is a
	 * sentinel — it is non-NULL while the entry is on a list.
	 */
	if (conn->entries.le_prev != NULL) {
		LIST_REMOVE(conn, entries);
		conn->entries.le_prev = NULL;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	/*
	 * The reconnect and idle timers carry this conn as their kevent
	 * udata.  Delete them from the kqueue before the connection can be
	 * freed, otherwise a timer that fires after the free would hand a
	 * dangling udata to the event loop.
	 */
	if (conn->reconnect_timer != 0) {
		EV_SET(&kev, conn->reconnect_timer, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		conn->reconnect_timer = 0;
	}
	if (conn->idle_timer != 0) {
		EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		conn->idle_timer = 0;
	}

	/* Drop the list's reference; frees when the last owner releases. */
	blued_conn_unref(conn);
}

int
blued_conn_register(struct blued_conn *conn)
{
	struct kevent kev[1 + ATT_MAX_EATT_BEARERS];
	int i, n;

	if (conn->att_fd < 0)
		return (-1);

	n = 0;
	EV_SET(&kev[n++], conn->att_fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, conn);
	if (conn->att != NULL) {
		for (i = 0; i < conn->att->eatt_count; i++) {
			if (!conn->att->eatt[i].active ||
			    conn->att->eatt[i].fd < 0)
				continue;
			EV_SET(&kev[n++], conn->att->eatt[i].fd, EVFILT_READ,
			    EV_ADD | EV_ENABLE, 0, 0, conn);
		}
	}
	if (kevent(blued_g.kq, kev, n, NULL, 0, NULL) < 0) {
		/* A partial changelist must not leave stale conn udata behind. */
		for (i = 0; i < n; i++) {
			EV_SET(&kev[i], kev[i].ident, EVFILT_READ, EV_DELETE,
			    0, 0, NULL);
			(void)kevent(blued_g.kq, &kev[i], 1, NULL, 0, NULL);
		}
		return (-1);
	}

	return (0);
}

int
blued_conn_register_bearer(struct blued_conn *conn, int fd)
{
	struct kevent kev;

	if (fd < 0 || blued_g.kq < 0) {
		errno = EINVAL;
		return (-1);
	}
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, conn);
	return (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL));
}

void
blued_conn_unregister_bearer(int fd)
{
	struct kevent kev;

	if (fd < 0 || blued_g.kq < 0)
		return;
	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

void
blued_conn_set_att_events(struct blued_conn *conn, bool enabled)
{
	struct kevent kev;
	uint16_t flags;
	int i;

	if (blued_g.kq < 0)
		return;
	flags = enabled ? EV_ENABLE : EV_DISABLE;
	if (conn->att_fd >= 0) {
		EV_SET(&kev, conn->att_fd, EVFILT_READ, flags, 0, 0, conn);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
	if (conn->att == NULL)
		return;
	for (i = 0; i < conn->att->eatt_count; i++) {
		if (!conn->att->eatt[i].active || conn->att->eatt[i].fd < 0)
			continue;
		EV_SET(&kev, conn->att->eatt[i].fd, EVFILT_READ, flags,
		    0, 0, conn);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
}

bool
blued_conn_att_event_ready(const struct blued_conn *conn)
{

	/*
	 * EV_DISABLE prevents future delivery but cannot retract an event already
	 * returned in the current kevent batch.  The blocking GATT worker is the
	 * sole recv() owner while any transaction is active, across fixed ATT and
	 * every EATT bearer.
	 */
	return (conn != NULL && atomic_load_explicit(&conn->att_ops_active,
	    memory_order_acquire) == 0);
}

void
blued_conn_unregister_att(struct blued_conn *conn)
{
	struct kevent kev;
	int i;

	if (blued_g.kq < 0)
		return;
	if (conn->att_fd >= 0) {
		EV_SET(&kev, conn->att_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
	if (conn->att == NULL)
		return;
	for (i = 0; i < conn->att->eatt_count; i++) {
		if (conn->att->eatt[i].fd < 0)
			continue;
		EV_SET(&kev, conn->att->eatt[i].fd, EVFILT_READ, EV_DELETE,
		    0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
}

struct blued_conn *
blued_conn_by_peer(const struct blued_adapter *adapter, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct blued_conn *conn;

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter == adapter && conn->addr_type == addr_type &&
		    memcmp(&conn->dst, addr, sizeof(*addr)) == 0) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			return (conn);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (NULL);
}

/*
 * Command-facing peer resolver.  Operator tools (bluedctl) identify a peer by
 * address but usually cannot supply its address type (a one-shot CLI cannot
 * remember what `connect` used), so they pass public (0) by default.  Try the
 * exact (address, type) match first; if that misses, fall back to a match on
 * address alone -- but only when it is UNAMBIGUOUS, i.e. exactly one connection
 * on this adapter carries that address.  This keeps internal exact-type callers
 * (event handling) using blued_conn_by_peer(), while letting operator commands
 * reach a peer that connected with a random/RPA address.
 */
struct blued_conn *
blued_conn_by_peer_cmd(const struct blued_adapter *adapter, const bdaddr_t *addr,
    uint8_t addr_type)
{
	struct blued_conn *conn, *uniq = NULL;
	int naddr = 0;

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter != adapter ||
		    memcmp(&conn->dst, addr, sizeof(*addr)) != 0)
			continue;
		if (conn->addr_type == addr_type) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			return (conn);		/* exact match wins */
		}
		naddr++;
		uniq = conn;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	/* No exact match: accept the address-only match only if unique. */
	return (naddr == 1 ? uniq : NULL);
}

bool
blued_conn_addr_context(const bdaddr_t *addr, uint8_t *adapter_index,
    uint8_t *addr_type)
{
	struct blued_conn *conn;
	bool found = false;

	if (addr == NULL)
		return (false);
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter != NULL &&
		    memcmp(&conn->dst, addr, sizeof(*addr)) == 0) {
			if (adapter_index != NULL)
				*adapter_index =
				    (uint8_t)conn->adapter->index;
			if (addr_type != NULL)
				*addr_type = conn->addr_type;
			found = true;
			break;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (found);
}

struct blued_conn *
blued_conn_by_handle(const struct blued_adapter *adapter, uint16_t handle)
{
	struct blued_conn *conn;

	if (adapter == NULL || handle > 0x0eff)
		return (NULL);
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (conn->adapter == adapter && conn->con_handle_valid &&
		    conn->con_handle == handle) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			return (conn);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (NULL);
}

struct blued_adapter *
blued_adapter_by_index(int idx)
{
	struct blued_adapter *adp;

	if (idx < 0 || idx >= BLUED_MAX_ADAPTERS)
		return (NULL);

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (adp->index == idx)
			return (adp);
	}
	return (NULL);
}

struct blued_adapter *
blued_adapter_by_index_powered(int idx)
{
	struct blued_adapter *adp;

	adp = blued_adapter_by_index(idx);
	return (adp != NULL && adp->active && adp->powered &&
	    !adp->power_quiescing ? adp : NULL);
}

struct blued_adapter *
blued_adapter_by_fd(int fd)
{
	struct blued_adapter *adp;

	if (fd < 0)
		return (NULL);

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (adp->hci_fd == fd)
			return (adp);
	}
	return (NULL);
}

void
blued_index_adapters(void)
{
	struct blued_adapter *adp;
	int idx = 0;

	/*
	 * Walk the list front-to-back so LIST_FIRST — the adapter every
	 * legacy default path already uses — receives index 0.  This keeps
	 * "adapter 0" identical to the pre-existing primary adapter.
	 */
	LIST_FOREACH(adp, &blued_g.adapters, entries)
		adp->index = idx++;
}
