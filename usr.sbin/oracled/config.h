/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>

#define	ORACLED_DEFAULT_CONFFILE	"/etc/oracled.conf"
#define	ORACLED_DEFAULT_PIDFILE	"/var/run/oracled.pid"
#define	ORACLED_DEFAULT_CTLMODE	0700
#define	ORACLED_DEFAULT_MANIFEST_DIR	"/etc/oracled.d"

#define	ORACLED_MAX_PATH_CLAIMS		64
#define	ORACLED_MAX_NET_CLAIMS		32

struct oracled_net_claim {
	int		domain;		/* AF_INET, AF_INET6, 0=any */
	int		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port;		/* host byte order */
	uint8_t		direction;	/* FI_NET_BIND/CONNECT/ANY */
};

struct oracled_config {
	/* Paths */
	char		pidfile[PATH_MAX];
	char		control_socket[PATH_MAX];
	mode_t		control_socket_mode;

	/* Integrity — capprotect flags for oracled itself */
	bool		integrity_ptrace;
	bool		integrity_signal;
	bool		integrity_visible;
	bool		integrity_wait;
	bool		integrity_sched;
	bool		integrity_core;
	bool		integrity_ktrace;

	/* Claims — resources under oracle control */
	char		claim_paths[ORACLED_MAX_PATH_CLAIMS][PATH_MAX];
	unsigned int	nclaim_paths;
	struct oracled_net_claim claim_net[ORACLED_MAX_NET_CLAIMS];
	unsigned int	nclaim_net;
	uint32_t	claim_system;	/* SYS_GATE_* bitmask */

	/* Service manifest directory */
	char		manifest_dir[PATH_MAX];

	/* Set by config_load if a file was actually parsed. */
	bool		loaded_from_file;
};

void	config_init_defaults(struct oracled_config *cfg);
int	config_load(struct oracled_config *cfg, const char *path);
void	config_log(const struct oracled_config *cfg);

#endif /* CONFIG_H */
