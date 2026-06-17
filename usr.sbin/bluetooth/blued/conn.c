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

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "blued.h"
#include "conn.h"

struct blued_conn *
blued_conn_alloc(void)
{
	struct blued_conn *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		return (NULL);

	conn->att_fd = -1;
	conn->state = BLUED_CONN_IDLE;
	conn->reconnect_timer = -1;

	LIST_INSERT_HEAD(&blued_g.conns, conn, entries);
	return (conn);
}

void
blued_conn_free(struct blued_conn *conn)
{

	if (conn->att_owned != NULL) {
		if (conn->att_owned->fd >= 0)
			close(conn->att_owned->fd);
		free(conn->att_owned->buf);
		free(conn->att_owned);
	}
	LIST_REMOVE(conn, entries);
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

struct blued_conn *
blued_conn_by_addr(const bdaddr_t *addr)
{
	struct blued_conn *conn;

	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (memcmp(&conn->dst, addr, sizeof(*addr)) == 0)
			return (conn);
	}
	return (NULL);
}
