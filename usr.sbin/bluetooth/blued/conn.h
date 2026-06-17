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
 * Remove conn from blued_g.conns and free it.
 * Does NOT close the ATT fd — caller must do that.
 */
void			 blued_conn_free(struct blued_conn *conn);

/*
 * Register conn's ATT fd with the global kqueue for EVFILT_READ.
 * Uses conn as the udata tag.  Returns 0 on success, -1 on failure.
 */
int			 blued_conn_register(struct blued_conn *conn);

/*
 * Find a connection by destination address.
 * Returns NULL if not found.
 */
struct blued_conn	*blued_conn_by_addr(const bdaddr_t *addr);

#endif /* _CONN_H_ */
