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

#include <assert.h>

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

	pthread_rwlock_wrlock(&blued_g.conns_lock);

	/* Enforce connection limit atomically with insertion */
	nconn = 0;
	LIST_FOREACH(cc, &blued_g.conns, entries)
		nconn++;
	if (nconn >= BLUED_MAX_CONNS) {
		pthread_rwlock_unlock(&blued_g.conns_lock);
		free(conn);
		errno = ENOSPC;
		return (NULL);
	}

	LIST_INSERT_HEAD(&blued_g.conns, conn, entries);
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (conn);
}

void
blued_conn_free(struct blued_conn *conn)
{

	if (conn == NULL)
		return;

	if (conn->att_owned != NULL) {
		if (conn->att_owned->fd >= 0)
			close(conn->att_owned->fd);
		if (conn->att_owned->buf != NULL)
			explicit_bzero(conn->att_owned->buf, ATT_MAX_MTU);
		free(conn->att_owned->buf);
		free(conn->att_owned);
	}
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	/*
	 * Guard against double-free: LIST_REMOVE on an already-removed
	 * node is undefined behavior.  Use le_prev as a sentinel —
	 * it is non-NULL while the entry is on a list.
	 */
	if (conn->entries.le_prev != NULL) {
		LIST_REMOVE(conn, entries);
		conn->entries.le_prev = NULL;
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	explicit_bzero(conn, sizeof(*conn));
	free(conn);
}

int
blued_conn_register(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn->att_fd < 0)
		return (-1);

	EV_SET(&kev, conn->att_fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, conn);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0)
		return (-1);

	return (0);
}

/*
 * Look up a connection by destination address.
 *
 * SAFETY: the returned pointer is valid only as long as the
 * connection remains in the list.  Connection cleanup
 * (blued_conn_free) only occurs in the main event loop thread
 * via the setup_pipe signal path.  This function must only be
 * called from the main thread or from control socket handlers
 * (which also run in the main thread).  Calling from a setup
 * thread would create a use-after-free race.
 *
 * The assertion below catches misuse from non-main threads
 * during development.
 */
struct blued_conn *
blued_conn_by_addr(const bdaddr_t *addr)
{
	struct blued_conn *conn;

	/*
	 * In debug builds, verify we're on the main thread.
	 * blued_g.main_thread is set once at startup.
	 */
	assert(blued_g.main_thread == 0 ||
	    pthread_equal(pthread_self(), blued_g.main_thread));

	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (memcmp(&conn->dst, addr, sizeof(*addr)) == 0) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			return (conn);
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	return (NULL);
}
