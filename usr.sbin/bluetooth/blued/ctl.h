/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_CTL_H_
#define _BLUED_CTL_H_

#include <stdint.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

struct blued_ctl_client;

int	blued_ctl_init(const char *path);
void	blued_ctl_accept(void);
int	blued_ctl_dispatch(struct blued_ctl_client *client);
void	blued_ctl_send_fd(int client_fd, int fd);
void	blued_ctl_cleanup(void);

/* Push notification: send characteristic value changes to subscribed clients */
void	blued_ctl_notify_value(const bdaddr_t *addr, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Push notification: forward GATT write to the ctl client that owns the attr */
void	blued_ctl_notify_write(int owner_fd, uint16_t handle,
	    const uint8_t *value, uint16_t len);

/* Reset owner_fd for attributes owned by a disconnected ctl client */
void	blued_ctl_reset_owner(int client_fd);

/* SMP passkey/numcmp reply handling */
void	blued_ctl_passkey_reply(const char *args);
void	blued_ctl_numcmp_reply(const char *args);

#endif /* _BLUED_CTL_H_ */
