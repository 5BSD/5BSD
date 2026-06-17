/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_CTL_H_
#define _BLUED_CTL_H_

struct blued_ctl_client;

int	blued_ctl_init(const char *path);
void	blued_ctl_accept(void);
int	blued_ctl_dispatch(struct blued_ctl_client *client);
void	blued_ctl_send_fd(int client_fd, int fd);
void	blued_ctl_cleanup(void);

#endif /* _BLUED_CTL_H_ */
