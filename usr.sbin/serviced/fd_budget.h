/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SERVICED_FD_BUDGET_H
#define SERVICED_FD_BUDGET_H

#include <sys/types.h>
#include <sys/resource.h>

#include <stddef.h>
#include <stdint.h>

#define SERVICED_FD_EMERGENCY_RESERVE 8

struct serviced_fd_budget_stats {
	rlim_t		soft_limit;
	rlim_t		hard_limit;
	size_t		reserve_count;
	uint64_t	admission_denied;
	uint64_t	control_shed;
	size_t		last_required;
};

int	serviced_fd_budget_raise_limit(void);
int	serviced_fd_budget_init(void);
void	serviced_fd_budget_fini(void);
int	serviced_fd_budget_check(size_t, const char *);
void	serviced_fd_budget_shed_control(int);
void	serviced_fd_budget_get_stats(struct serviced_fd_budget_stats *);

#endif /* SERVICED_FD_BUDGET_H */
