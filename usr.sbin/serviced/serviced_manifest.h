/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service manifest types — shared between serviced and libappbundle.
 *
 * This header defines the manifest struct and claim types used by both
 * the legacy manifest parser (manifest.c) and the bundle parser
 * (libappbundle).  It deliberately has no daemon-internal state so that
 * libraries can include it without pulling in kqueue, runtime structs,
 * or function prototypes.
 */

#ifndef SERVICED_MANIFEST_H
#define SERVICED_MANIFEST_H

#include <sys/types.h>
#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>

/*
 * Limits.
 */
#define	SERVICED_MAX_SERVICES		64
#define	SERVICED_MAX_PROVIDES		8
#define	SERVICED_MAX_REQUIRES		8
#define	SERVICED_MAX_CAP_PATHS		16
#define	SERVICED_MAX_CAP_FILES		16
#define	SERVICED_MAX_CAP_NET		16
#define	SERVICED_MAX_CAP_JAIL		16
#define	SERVICED_LABEL_MAX		64

/* Restart policy */
#define	SVC_RESTART_NEVER		0
#define	SVC_RESTART_ALWAYS		1
#define	SVC_RESTART_ON_FAILURE		2

/* Network claim direction flags (match cap_rt_isolation_proto.h). */
#define	SERVICED_NET_DIR_BIND		0x01
#define	SERVICED_NET_DIR_CONNECT	0x02
#define	SERVICED_NET_DIR_ANY		0x03

struct serviced_file_cap {
	char		path[PATH_MAX];
	uint64_t	actions;	/* FI_FS_* mask */
};

struct serviced_net_claim {
	int		domain;		/* AF_INET, AF_INET6, 0=any */
	int		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port_min;	/* host byte order */
	uint16_t	port_max;	/* host byte order */
	uint8_t		direction;	/* SERVICED_NET_DIR_* */
	uint8_t		prefix;		/* CIDR prefix len, 0=exact/any */
	uint8_t		addr[16];	/* IPv6 or v4-mapped, all-zero=any */
};

struct serviced_jail_claim {
	int32_t		jid;		/* 0=not specified */
	uint32_t	actions;	/* FI_JAIL_* mask */
	char		name[64];	/* empty=not specified */
};

/*
 * Parsed service manifest.
 *
 * Produced by manifest_load_file() (legacy UCL) or
 * appbundle_svc_fill_manifest() (bundle).  Immutable after loading.
 */
struct svc_manifest {
	char		label[SERVICED_LABEL_MAX];
	char		description[256];
	char		program[PATH_MAX];
	char		user[64];
	char		group[64];

	/* Dependency graph edges */
	char		provides[SERVICED_MAX_PROVIDES][SERVICED_LABEL_MAX];
	unsigned	nprovides;
	char		requires[SERVICED_MAX_REQUIRES][SERVICED_LABEL_MAX];
	unsigned	nrequires;

	/* Capabilities to delegate */
	char		cap_paths[SERVICED_MAX_CAP_PATHS][PATH_MAX];
	unsigned	ncap_paths;
	struct serviced_file_cap cap_files[SERVICED_MAX_CAP_FILES];
	unsigned	ncap_files;
	struct serviced_net_claim cap_net[SERVICED_MAX_CAP_NET];
	unsigned	ncap_net;
	struct serviced_jail_claim cap_jail[SERVICED_MAX_CAP_JAIL];
	unsigned	ncap_jail;
	uint32_t	cap_system;	/* SYS_GATE_* bitmask */

	/* Jail to create and attach child into (optional). */
	bool		has_jail;
	char		jail_name[64];
	char		jail_path[PATH_MAX];
	char		jail_hostname[64];
	char		jail_ip4_addr[64];

	int		restart;	/* SVC_RESTART_* */
	int		stop_timeout;	/* seconds before SIGKILL (default 5) */
	unsigned	max_failures;	/* circuit breaker threshold (default 10) */
	bool		on_demand;	/* true = launch on first lookup */
};

#endif /* SERVICED_MANIFEST_H */
