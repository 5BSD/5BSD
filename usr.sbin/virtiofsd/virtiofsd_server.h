/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIOFSD_SERVER_H_
#define	_VIRTIOFSD_SERVER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"

struct virtiofsd_server;
struct virtiofsd_session;

int	virtiofsd_server_create(struct virtiofsd_session *, uint32_t,
	    uint32_t, uint32_t, unsigned int, struct virtiofsd_server **);
void	virtiofsd_server_destroy(struct virtiofsd_server *);
int	virtiofsd_server_handle(struct virtiofsd_server *,
	    const struct virtio_fs_backend_header *, const void *, size_t);
int	virtiofsd_server_flush_one(struct virtiofsd_server *, int);
int	virtiofsd_server_wakeup_fd(const struct virtiofsd_server *);
void	virtiofsd_server_drain_wakeup(struct virtiofsd_server *);
bool	virtiofsd_server_wants_write(struct virtiofsd_server *);
bool	virtiofsd_server_closed(struct virtiofsd_server *);
int	virtiofsd_server_error(struct virtiofsd_server *);

#endif
