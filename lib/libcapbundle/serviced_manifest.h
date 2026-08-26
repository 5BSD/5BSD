/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service manifest types — shared between serviced and libcapbundle.
 *
 * This header defines the manifest struct and claim types used by both
 * the legacy manifest parser (manifest.c) and the bundle parser
 * (libcapbundle).  It deliberately has no daemon-internal state so that
 * libraries can include it without pulling in kqueue, runtime structs,
 * or function prototypes.
 */

#ifndef SERVICED_MANIFEST_H
#define SERVICED_MANIFEST_H

#include <sys/types.h>
#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>

#include <oraclert.h>

/*
 * Limits.
 */
#define	SERVICED_MAX_SERVICES		256
#define	SERVICED_MAX_PROVIDES		8
#define	SERVICED_MAX_CAP_PATHS		16
#define	SERVICED_MAX_CAP_FILES		16
#define	SERVICED_MAX_CAP_NET		16
#define	SERVICED_MAX_CAP_JAIL		16
#define	SERVICED_MAX_CAP_VSOCK		16
#define	SERVICED_MAX_CAP_SERVICES	4
#define	SERVICED_MAX_CAP_STORAGE	8
#define	SERVICED_CAP_SERVICE_NAME_MAX	16
#define	SERVICED_LABEL_MAX		64
#define	SERVICED_MAX_KMOD_REQUIRES	8
#define	SERVICED_KMOD_NAME_MAX		128
#define	SERVICED_MAX_ARGUMENTS		32
#define	SERVICED_ARGUMENT_MAX		256
#define	SERVICED_MAX_ENVIRONMENT	32
#define	SERVICED_ENVIRONMENT_MAX	1024
#define	SERVICED_MAX_COMPONENTS		8
#define	SERVICED_COMPONENT_NAME_MAX	64
#define	SERVICED_DEFAULT_USER		"capability"
#define	SERVICED_DEFAULT_GROUP		"capability"

/* Restart policy */
#define	SVC_RESTART_NEVER		0
#define	SVC_RESTART_ALWAYS		1
#define	SVC_RESTART_ON_FAILURE		2

struct serviced_file_cap {
	char		path[PATH_MAX];
	uint64_t	actions;	/* FI_FS_* mask */
};

struct serviced_jail_claim {
	int32_t		jid;		/* 0=not specified */
	uint32_t	actions;	/* FI_JAIL_* mask */
	char		name[64];	/* empty=not specified */
};

struct serviced_component {
	char		name[SERVICED_COMPONENT_NAME_MAX];
	/* Filesystem descriptor backing; empty for other descriptor kinds. */
	char		storage[ORT_STORAGE_NAME_MAX];
};

/*
 * Parsed service manifest.
 *
 * Produced by manifest_load_file() (legacy UCL) or
 * capbundle_svc_fill_manifest() (bundle).  Immutable after loading.
 */
struct svc_manifest {
	char		label[SERVICED_LABEL_MAX];
	char		description[256];
	char		program[PATH_MAX];
	char		arguments[SERVICED_MAX_ARGUMENTS][SERVICED_ARGUMENT_MAX];
	unsigned	narguments;
	char		environment[SERVICED_MAX_ENVIRONMENT][SERVICED_ENVIRONMENT_MAX];
	unsigned	nenvironment;
	char		user[64];
	char		group[64];

	/* Publication and internal component-startup edges. */
	char		provides[SERVICED_MAX_PROVIDES][SERVICED_LABEL_MAX];
	unsigned	nprovides;
	char		startup_after[SERVICED_MAX_COMPONENTS][SERVICED_LABEL_MAX];
	unsigned	nstartup_after;

	/* Local authority-replacement components consumed by this service. */
	struct serviced_component components[SERVICED_MAX_COMPONENTS];
	unsigned	ncomponents;

	/* Capabilities to delegate */
	char		cap_paths[SERVICED_MAX_CAP_PATHS][PATH_MAX];
	unsigned	ncap_paths;
	struct serviced_file_cap cap_files[SERVICED_MAX_CAP_FILES];
	unsigned	ncap_files;
	struct ort_net_claim cap_net[SERVICED_MAX_CAP_NET];
	unsigned	ncap_net;
	struct serviced_jail_claim cap_jail[SERVICED_MAX_CAP_JAIL];
	unsigned	ncap_jail;
	struct ort_vsock_claim cap_vsock[SERVICED_MAX_CAP_VSOCK];
	unsigned	ncap_vsock;
	struct ort_storage_claim cap_storage[SERVICED_MAX_CAP_STORAGE];
	unsigned	ncap_storage;
	char		cap_services[SERVICED_MAX_CAP_SERVICES]
		    [SERVICED_CAP_SERVICE_NAME_MAX];
	unsigned	ncap_services;
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
	/* Required kernel modules (ensured by oracled before launch) */
	char		kmod_requires[SERVICED_MAX_KMOD_REQUIRES][SERVICED_KMOD_NAME_MAX];
	unsigned	nkmod_requires;

	/*
	 * Launcher-applied protection policy (capprotect CP_SF_* bitmask).  When
	 * non-zero serviced shields the launched process by its process
	 * descriptor immediately after pdfork(2), so the protection is in force
	 * from the moment the process exists — before its program image runs and
	 * regardless of what that image does.  Zero leaves the process to apply
	 * its own shield (or none).
	 */
	uint32_t	protect_flags;
};

#endif /* SERVICED_MANIFEST_H */
