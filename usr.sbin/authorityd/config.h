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

#include <dev/mac_capability/mac_capability_capprotect_proto.h>

#include <authorityrt.h>

#define	AUTHORITYD_DEFAULT_CONFFILE	"/etc/authorityd.conf"
#define	AUTHORITYD_DEFAULT_PIDFILE	"/var/run/authorityd.pid"
#define	AUTHORITYD_DEFAULT_CTLMODE	0700
#define	AUTHORITYD_DEFAULT_SVC_MANAGER	"/usr/libexec/serviced"

#define	AUTHORITYD_MAX_PATH_CLAIMS		64
#define	AUTHORITYD_MAX_NET_CLAIMS		32
#define	AUTHORITYD_MAX_JAIL_CLAIMS		32
#define	AUTHORITYD_MAX_VSOCK_CLAIMS	32
#define	AUTHORITYD_SYSTEM_GATE_NBITS	32	/* bits in uint32_t gate bitmask */
#define	AUTHORITYD_JAIL_DESC_MAX		96	/* jail_claim_string() output */

/* Foreign-nonce ambient PID signalling is never an Authority authority. */
#define	AUTHORITYD_REQUIRED_INTEGRITY_FLAGS	\
	(CP_SF_SIGNAL | CP_SF_SIGKILL | CP_SF_SIGCONT)

/* Claim provenance — where a claim originated. */
#define	CLAIM_SOURCE_POLICY	0x01	/* from authorityd.conf policy section */
#define	CLAIM_SOURCE_SERVICE	0x02	/* auto-registered from service request */

struct authorityd_jail_claim {
	int32_t		jid;		/* 0=not specified */
	uint32_t	actions;	/* FI_JAIL_* mask */
	char		name[64];	/* empty=not specified */
	char		path[PATH_MAX];	/* allowed root prefix, empty=any */
};

struct authorityd_config {
	/* Paths */
	char		pidfile[PATH_MAX];
	char		control_socket[PATH_MAX];
	mode_t		control_socket_mode;

	/* Integrity — capprotect shield bitmask (CP_SF_* flags) */
	uint32_t	integrity_flags;

	/* Claims — resources under authority control */
	char		claim_paths[AUTHORITYD_MAX_PATH_CLAIMS][PATH_MAX];
	uint8_t		claim_path_source[AUTHORITYD_MAX_PATH_CLAIMS];
	uint32_t	claim_path_refcount[AUTHORITYD_MAX_PATH_CLAIMS];
	unsigned int	nclaim_paths;
	struct ort_net_claim claim_net[AUTHORITYD_MAX_NET_CLAIMS];
	uint8_t		claim_net_source[AUTHORITYD_MAX_NET_CLAIMS];
	uint32_t	claim_net_refcount[AUTHORITYD_MAX_NET_CLAIMS];
	unsigned int	nclaim_net;
	struct authorityd_jail_claim claim_jail[AUTHORITYD_MAX_JAIL_CLAIMS];
	uint8_t		claim_jail_source[AUTHORITYD_MAX_JAIL_CLAIMS];
	uint32_t	claim_jail_refcount[AUTHORITYD_MAX_JAIL_CLAIMS];
	unsigned int	nclaim_jail;
	struct ort_vsock_claim claim_vsock[AUTHORITYD_MAX_VSOCK_CLAIMS];
	uint8_t		claim_vsock_source[AUTHORITYD_MAX_VSOCK_CLAIMS];
	uint32_t	claim_vsock_refcount[AUTHORITYD_MAX_VSOCK_CLAIMS];
	unsigned int	nclaim_vsock;
	uint32_t	claim_system;		/* SYS_GATE_* bitmask (all) */
	uint32_t	claim_system_policy;	/* policy-originated bits */
	uint32_t	claim_system_service;	/* service-originated bits */
	uint32_t	claim_system_refcount[AUTHORITYD_SYSTEM_GATE_NBITS];

	/* Service manager binary (started by bootstrap) */
	char		service_manager[PATH_MAX];

	/* Serviced control socket path (passed to serviced) */
	char		serviced_control_socket[PATH_MAX];

	/* Set by config_load if a file was actually parsed. */
	bool		loaded_from_file;
};

void	config_init_defaults(struct authorityd_config *cfg);
int	config_load(struct authorityd_config *cfg, const char *path);
void	config_log(const struct authorityd_config *cfg);

/* Shared UCL parsers (used by config.c, manifest.c, commands.c). */
struct ucl_object_s;	/* forward decl to avoid ucl.h dependency in header */
int	parse_ucl_net_claim(const struct ucl_object_s *elem,
	    struct ort_net_claim *nc, const char *label);
int	parse_ucl_jail_claim(const struct ucl_object_s *elem,
	    struct authorityd_jail_claim *jc, const char *label);

#endif /* CONFIG_H */
