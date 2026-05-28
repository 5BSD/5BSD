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

/* Globals (defined in oracled.c). */
extern struct pidfh	*pidfh;
extern int		 cap_rt_fd;
extern int		 isolation_fd;
extern int		 capprotect_fd;
extern bool		 foreground;
extern bool		 test_mode;
extern bool		 running;

/* event.c */
void	event_loop(void);

/* proc.c */
void	reap_children(void);
void	kill_subtree(void);
void	apply_procctl_self_policy(void);

/* isolation.c */
int	isolate_cap_rt_device(void);
int	shield_self(void);

#endif /* ORACLED_H */
