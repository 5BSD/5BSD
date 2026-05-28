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

/*
 * Daemon state.
 *
 * Set by main() during initialization, read by all modules.
 * Shutdown is coordinated through the 'running' flag and the
 * teardown functions.
 */
struct oracled_state {
	struct pidfh	*pidfh;
	int		 control_fd;
	bool		 foreground;
	bool		 test_mode;
	bool		 running;
};

extern struct oracled_state od;

/* Return values from handle_control_connection(). */
#define	CTL_ACTION_SHUTDOWN	0x01
#define	CTL_ACTION_REBOOT	0x02

/* Reboot flags set by control.c, read by event.c. */
extern int		 reboot_howto;

/* cap_rt.c — capability runtime lifecycle */
int	cap_rt_setup(void);
void	cap_rt_teardown(void);

/* control.c — control socket lifecycle */
int	setup_control_socket(void);
void	teardown_control_socket(void);
int	handle_control_connection(void);

/* event.c — main event loop */
void	event_loop(void);

/* proc.c — process management */
void	reap_children(void);
void	kill_subtree(void);
void	apply_procctl_self_policy(void);

#endif /* ORACLED_H */
