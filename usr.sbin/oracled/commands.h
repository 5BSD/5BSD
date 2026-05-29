/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include <sys/types.h>

struct ctl_reply;

void	cmd_status(uint64_t uptime, struct ctl_reply *reply);
int	cmd_shutdown(uid_t euid, struct ctl_reply *reply);
void	cmd_reload(uid_t euid, int kq, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
void	cmd_check(uid_t euid, const char *filename, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
void	cmd_load(uid_t euid, const char *filename, int kq,
	    struct ctl_reply *reply, char *summary, size_t sumlen);
void	cmd_services(struct ctl_reply *reply, char *summary, size_t sumlen);
void	cmd_kldload(uid_t euid, const char *name, struct ctl_reply *reply);
void	cmd_kldunload(uid_t euid, const char *name, struct ctl_reply *reply);
void	cmd_reboot(uid_t euid, uint32_t howto, struct ctl_reply *reply);

#endif /* COMMANDS_H */
