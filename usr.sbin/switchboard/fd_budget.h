/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SWITCHBOARD_FD_BUDGET_H
#define SWITCHBOARD_FD_BUDGET_H

#include <sys/types.h>
#include <sys/resource.h>

#include <stddef.h>
#include <stdint.h>

#define SWITCHBOARD_FD_EMERGENCY_RESERVE 8

struct switchboard_fd_budget_stats {
	rlim_t		soft_limit;
	rlim_t		hard_limit;
	size_t		reserve_count;
	uint64_t	admission_denied;
	uint64_t	control_shed;
	size_t		last_required;
};

int	switchboard_fd_budget_raise_limit(void);
int	switchboard_fd_budget_init(void);
void	switchboard_fd_budget_fini(void);
int	switchboard_fd_budget_check(size_t, const char *);
void	switchboard_fd_budget_shed_control(int);
void	switchboard_fd_budget_get_stats(struct switchboard_fd_budget_stats *);

#endif /* SWITCHBOARD_FD_BUDGET_H */
