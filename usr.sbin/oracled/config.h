/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/param.h>

#include <stdbool.h>

#define	ORACLED_DEFAULT_CONFFILE	"/etc/oracled.conf"
#define	ORACLED_DEFAULT_PIDFILE	"/var/run/oracled.pid"
#define	ORACLED_DEFAULT_CTLMODE	0700

struct oracled_config {
	/* Paths */
	char		pidfile[PATH_MAX];
	char		control_socket[PATH_MAX];
	mode_t		control_socket_mode;

	/* Shield flags */
	bool		shield_ptrace;
	bool		shield_signal;
	bool		shield_visible;
	bool		shield_wait;
	bool		shield_sched;
	bool		shield_core;
	bool		shield_ktrace;

	/* Isolation */
	bool		isolate_cap_rt;

	/* Set by config_load if a file was actually parsed. */
	bool		loaded_from_file;
};

void	config_init_defaults(struct oracled_config *cfg);
int	config_load(struct oracled_config *cfg, const char *path);
void	config_log(const struct oracled_config *cfg);

#endif /* CONFIG_H */
