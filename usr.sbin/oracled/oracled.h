/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef ORACLED_H
#define ORACLED_H

#include <sys/types.h>

#include <libutil.h>
#include <stdbool.h>

#include "config.h"

/*
 * Daemon state.
 *
 * Set by main() during initialization, read by all modules.
 * Shutdown is coordinated through the 'running' flag and the
 * teardown functions.
 *
 * Module-private state (cap_rt fds, control socket fd) is kept
 * in static variables within each module.
 */
struct oracled_state {
	struct pidfh		*pidfh;
	struct oracled_config	 cfg;
	bool			 foreground;
	bool			 test_mode;
	bool			 running;
};

extern struct oracled_state od;

/* cap_rt.c — capability runtime lifecycle */
int	cap_rt_setup(void);
void	cap_rt_teardown(void);

/* control.c — control socket lifecycle */
#define	CTL_ACTION_NONE		0
#define	CTL_ACTION_SHUTDOWN	0x01
#define	CTL_ACTION_REBOOT	0x02

int	ctl_setup(void);
void	ctl_teardown(void);
int	ctl_fd(void);
int	ctl_handle(int *reboot_howto);

/* event.c — main event loop */
void	event_loop(void);

/* proc.c — process management */
void	reap_children(void);
void	kill_subtree(void);
void	apply_procctl_self_policy(void);

#endif /* ORACLED_H */
