/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include <sys/types.h>

struct ctl_reply;

void	config_apply_claims(const struct oracled_config *newcfg);
void	cmd_status(uint64_t uptime, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
int	cmd_shutdown(uid_t euid, struct ctl_reply *reply);
void	cmd_reload(uid_t euid, int kq, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
void	cmd_check(uid_t euid, const char *filename, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
void	cmd_load(uid_t euid, const char *filename, int kq,
	    struct ctl_reply *reply, char *summary, size_t sumlen);
void	cmd_services(uid_t euid, uint32_t flags, struct ctl_reply *reply,
	    char *summary, size_t sumlen);
void	cmd_verify(struct ctl_reply *reply, char *summary, size_t sumlen);

#endif /* COMMANDS_H */
