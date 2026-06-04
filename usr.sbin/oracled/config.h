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
#define	ORACLED_DEFAULT_SVC_MANAGER	"/usr/libexec/oracled/serviced"

#define	ORACLED_MAX_PATH_CLAIMS		64
#define	ORACLED_MAX_NET_CLAIMS		32

/* Network claim direction flags (match cap_rt_isolation_proto.h). */
#define	ORACLED_NET_DIR_BIND	0x01
#define	ORACLED_NET_DIR_CONNECT	0x02
#define	ORACLED_NET_DIR_ANY	0x03

struct oracled_net_claim {
	int		domain;		/* AF_INET, AF_INET6, 0=any */
	int		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port;		/* host byte order */
	uint8_t		direction;	/* ORACLED_NET_DIR_* */
};

struct oracled_config {
	/* Paths */
	char		pidfile[PATH_MAX];
	char		control_socket[PATH_MAX];
	mode_t		control_socket_mode;

	/* Integrity — capprotect shield bitmask (CP_SF_* flags) */
	uint32_t	integrity_flags;

	/* Claims — resources under oracle control */
	char		claim_paths[ORACLED_MAX_PATH_CLAIMS][PATH_MAX];
	unsigned int	nclaim_paths;
	struct oracled_net_claim claim_net[ORACLED_MAX_NET_CLAIMS];
	unsigned int	nclaim_net;
	uint32_t	claim_system;	/* SYS_GATE_* bitmask */

	/* Service manifest directory (passed to serviced) */
	char		manifest_dir[PATH_MAX];

	/* Service manager binary (started by bootstrap) */
	char		service_manager[PATH_MAX];

	/* Serviced control socket path (passed to serviced) */
	char		serviced_control_socket[PATH_MAX];

	/* Set by config_load if a file was actually parsed. */
	bool		loaded_from_file;
};

void	config_init_defaults(struct oracled_config *cfg);
int	config_load(struct oracled_config *cfg, const char *path);
void	config_log(const struct oracled_config *cfg);

/* Shared UCL parser for network claim objects (used by config.c and manifest.c). */
struct ucl_object_s;	/* forward decl to avoid ucl.h dependency in header */
int	parse_ucl_net_claim(const struct ucl_object_s *elem,
	    struct oracled_net_claim *nc, const char *label);

#endif /* CONFIG_H */
