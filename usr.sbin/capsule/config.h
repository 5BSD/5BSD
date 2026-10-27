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


#include <capsulert.h>
#include <capsule_svc_proto.h>

#define	CAPSULE_DEFAULT_CONFFILE	"/etc/capsule.conf"
#define	CAPSULE_DEFAULT_PIDFILE	"/var/run/capsule.pid"
#define	CAPSULE_DEFAULT_CTLMODE	0700
#define	CAPSULE_DEFAULT_SVC_MANAGER	"/usr/libexec/switchboard"

#define	CAPSULE_MAX_NET_CLAIMS		32
#define	CAPSULE_MAX_VSOCK_CLAIMS	32
#define	CAPSULE_SYSTEM_GATE_NBITS	32	/* bits in uint32_t gate bitmask */

/* Foreign-nonce ambient PID signalling can never control Capsule. */
#define	CAPSULE_REQUIRED_INTEGRITY_FLAGS	\
	(CP_SF_SIGNAL | CP_SF_SIGKILL | CP_SF_SIGCONT)

/* Claim provenance — where a claim originated. */
#define	CLAIM_SOURCE_POLICY	0x01	/* from capsule.conf policy section */
#define	CLAIM_SOURCE_SERVICE	0x02	/* auto-registered from service request */

#define CAPSULE_STORAGE_MEMORY_MAX (16U * 1024U * 1024U)
#define CAPSULE_STORAGE_DEVICES_MAX 8
#define CAPSULE_STORAGE_RECIPIENT_MAX CAPSULE_BOOT_STORAGE_LABEL_MAX
struct capsule_storage {
	char recipient[CAPSULE_STORAGE_RECIPIENT_MAX];
	char pool[256];
	char dataset[256];
	uint64_t pool_guid, dataset_guid, rights;
	unsigned ndevices;
	char devices[CAPSULE_STORAGE_DEVICES_MAX][PATH_MAX];
};

/* Bound expanded policy memory independently of filesystem layout. */
#define CAPSULE_STORAGE_MAX (CAPSULE_STORAGE_MEMORY_MAX / sizeof(struct capsule_storage))

struct capsule_config {
	/* Paths */
	char		pidfile[PATH_MAX];
	char		control_socket[PATH_MAX];
	mode_t		control_socket_mode;

	/* Integrity — capprotect shield bitmask (CP_SF_* flags) */
	uint32_t	integrity_flags;

	/* Claims — resources under Capsule control */
	struct ort_net_claim claim_net[CAPSULE_MAX_NET_CLAIMS];
	uint8_t		claim_net_source[CAPSULE_MAX_NET_CLAIMS];
	uint32_t	claim_net_refcount[CAPSULE_MAX_NET_CLAIMS];
	unsigned int	nclaim_net;
	struct ort_vsock_claim claim_vsock[CAPSULE_MAX_VSOCK_CLAIMS];
	uint8_t		claim_vsock_source[CAPSULE_MAX_VSOCK_CLAIMS];
	uint32_t	claim_vsock_refcount[CAPSULE_MAX_VSOCK_CLAIMS];
	unsigned int	nclaim_vsock;
	uint32_t	claim_system;		/* SYS_GATE_* bitmask (all) */
	uint32_t	claim_system_policy;	/* policy-originated bits */
	uint32_t	claim_system_service;	/* service-originated bits */
	uint32_t	claim_system_refcount[CAPSULE_SYSTEM_GATE_NBITS];

	/* Authenticated boot identity and storage assignments; not reloadable. */
	char hostuuid[37];
	char crypto_recipient[CAPSULE_BOOT_STORAGE_LABEL_MAX];
	unsigned nstorage;
	struct capsule_storage *storage; /* Owned; use config_copy, not value copies. */

	/* Service manager binary (started by bootstrap) */
	char		service_manager[PATH_MAX];

	/* Set by config_load if a file was actually parsed. */
	bool		loaded_from_file;
};

void	config_init_defaults(struct capsule_config *cfg);
/* Destination must be initialized or zeroed. Failure leaves it unchanged. */
int	config_copy(struct capsule_config *, const struct capsule_config *);
void	config_free(struct capsule_config *);
int	config_load(struct capsule_config *cfg, const char *path);
/* Consumes fd, including on failure. */
int	config_load_fd(struct capsule_config *cfg, int fd);
/* Canonical UUID to the standard rc host ID; not an authentication token. */
bool	config_hostid(const char *, unsigned long *);
bool	config_boot_policy_equal(const struct capsule_config *, const struct capsule_config *);
void	config_log(const struct capsule_config *cfg);
/* Shared validation report for the daemon and native builder. */
void	config_validation_report(const struct capsule_config *cfg);

/* Shared UCL parsers (used by config.c, manifest.c, commands.c). */
struct ucl_object_s;	/* forward decl to avoid ucl.h dependency in header */
int	parse_ucl_net_claim(const struct ucl_object_s *elem,
	    struct ort_net_claim *nc, const char *label);

#endif /* CONFIG_H */
