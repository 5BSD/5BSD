/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle internal definitions — shared across compilation units.
 */

#ifndef LIBCAPBUNDLE_INTERNAL_H
#define LIBCAPBUNDLE_INTERNAL_H

#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>

#include <oraclert.h>

#include "libcapbundle.h"
#include "serviced_manifest.h"

/* Limits matching serviced.h */
#define	CAPBUNDLE_MAX_CAP_PATHS		16
#define	CAPBUNDLE_MAX_CAP_FILES		16
#define	CAPBUNDLE_MAX_CAP_NET		16
#define	CAPBUNDLE_MAX_CAP_JAIL		16
#define	CAPBUNDLE_MAX_CAP_VSOCK		16
#define	CAPBUNDLE_MAX_CAP_STORAGE	SERVICED_MAX_CAP_STORAGE
#define	CAPBUNDLE_MAX_CAP_SERVICES	SERVICED_MAX_CAP_SERVICES
#define	CAPBUNDLE_MAX_KMOD_REQUIRES	8
/* Internal service representation. */
struct capbundle_service {
	char	program[PATH_MAX];	/* absolute resolved path */
	char	arguments[SERVICED_MAX_ARGUMENTS][SERVICED_ARGUMENT_MAX];
	unsigned narguments;
	char	environment[SERVICED_MAX_ENVIRONMENT][SERVICED_ENVIRONMENT_MAX];
	unsigned nenvironment;
	char	label[CAPBUNDLE_NAME_MAX + 1];
	char	provides[CAPBUNDLE_MAX_PROVIDES][CAPBUNDLE_NAME_MAX + 1];
	unsigned nprovides;
	char	startup_after[SERVICED_MAX_COMPONENTS][CAPBUNDLE_NAME_MAX + 1];
	unsigned nstartup_after;
	struct serviced_component components[SERVICED_MAX_COMPONENTS];
	unsigned ncomponents;
	int	restart;
	uint32_t cap_system;		/* SYS_GATE_* bitmask */

	/* Path capabilities */
	char	cap_paths[CAPBUNDLE_MAX_CAP_PATHS][PATH_MAX];
	unsigned ncap_paths;

	/* File capabilities (fine-grained, with actions) */
	struct {
		char	path[PATH_MAX];
		uint64_t actions;	/* FI_FS_* mask */
	} cap_files[CAPBUNDLE_MAX_CAP_FILES];
	unsigned ncap_files;

	/* Network capabilities (full: domain, address, prefix, port range) */
	struct ort_net_claim cap_net[CAPBUNDLE_MAX_CAP_NET];
	unsigned ncap_net;

	/* Jail capabilities */
	struct serviced_jail_claim cap_jail[CAPBUNDLE_MAX_CAP_JAIL];
	unsigned ncap_jail;
	struct ort_vsock_claim cap_vsock[CAPBUNDLE_MAX_CAP_VSOCK];
	unsigned ncap_vsock;
	struct ort_storage_claim cap_storage[CAPBUNDLE_MAX_CAP_STORAGE];
	unsigned ncap_storage;
	char	cap_services[CAPBUNDLE_MAX_CAP_SERVICES]
		    [SERVICED_CAP_SERVICE_NAME_MAX];
	unsigned ncap_services;

	/* User/group for privilege drop */
	char	user[64];
	char	group[64];

	/* Named persistent jail used as the service execution container. */
	bool	has_jail;
	char	jail_name[64];
	char	jail_path[PATH_MAX];
	char	jail_hostname[64];
	char	jail_ip4_addr[64];

	/* Required kernel modules */
	char	kmod_requires[CAPBUNDLE_MAX_KMOD_REQUIRES][128];
	unsigned nkmod_requires;

	/* Stop timeout */
	int	stop_timeout;
	unsigned max_failures;
};

/* Internal bundle representation. */
struct capbundle {
	char	path[PATH_MAX];		/* bundle directory */
	char	name[256];		/* basename of path (e.g. "Mail.cap") */
	char	bundle_id[CAPBUNDLE_ID_MAX];
	char	version[CAPBUNDLE_VERSION_MAX];
	char	author[CAPBUNDLE_AUTHOR_MAX];
	struct capbundle_service services[CAPBUNDLE_MAX_SERVICES];
	unsigned nservices;
};

/* Maximum Service.ucl file size (1 MB).  Protects against OOM. */
#define	CAPBUNDLE_MAX_UCL_SIZE	(1024 * 1024)

/*
 * Parse a single Service.ucl file within a bundle.
 * Defined in libcapbundle_parse.c, called from capbundle_open().
 */
int	capbundle_parse_service_ucl(const char *path, const char *bundle_path,
	    struct capbundle_service *svc, char *bundle_id, size_t bundle_id_sz,
	    char *version, size_t version_sz, char *author, size_t author_sz,
	    char *errbuf, size_t errlen);

#endif /* LIBCAPBUNDLE_INTERNAL_H */
