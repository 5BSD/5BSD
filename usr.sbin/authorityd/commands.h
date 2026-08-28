/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include <sys/types.h>

struct ctl_reply;

void	config_apply_claims(const struct authorityd_config *newcfg);
void	cmd_status(uint64_t uptime, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
int	cmd_shutdown(uid_t euid, struct ctl_reply *reply);
int	cmd_lifecycle(uid_t euid, uint32_t op, struct ctl_reply *reply);
void	cmd_reload(uid_t euid, struct ctl_reply *reply,
	    char *summary, size_t sumlen);

#endif /* COMMANDS_H */
