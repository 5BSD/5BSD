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

#include <authorityrt.h>

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
#define	CAPBUNDLE_MAX_CAP_OPEN		SERVICED_MAX_CAP_OPEN
#define	CAPBUNDLE_MAX_KMOD_REQUIRES	8
/*
 * Upper bound on a monotonic activation.timer interval: 366 days in seconds.
 * A period longer than a year is far past the point where a monotonic timer is
 * the right mechanism (that is calendar/persistent territory, deferred in v1).
 */
#define	CAPBUNDLE_MAX_TIMER_INTERVAL	(366 * 24 * 3600)

struct capbundle_shared_storage {
	char	name[ORT_STORAGE_NAME_MAX];
	char	flavor[ORT_STORAGE_FLAVOR_MAX];
	uint8_t	lifetime;
};
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
	bool	activation_boot;
	bool	is_helper;		/* private helper: launched on request only */
	/*
	 * Activation sources (Phase 5).  timer_interval_sec is the monotonic
	 * period in seconds (0 = none); activation_path is an absolute path
	 * watched via kqueue vnode events (empty = none).  Both name this unit
	 * in its own bundle and create demand for it, without dependency order.
	 */
	unsigned timer_interval_sec;
	char	activation_path[PATH_MAX];
	/*
	 * Socket activation sources (Phase 4).  serviced binds and holds each
	 * listening socket and delivers it to this unit by logical name; the
	 * first inbound connection is the demand that launches the unit.
	 * nactivation_sockets == 0 = no socket source.
	 */
	struct svc_activation_socket
		activation_sockets[SERVICED_MAX_ACTIVATION_SOCKETS];
	unsigned nactivation_sockets;
	int	restart;
	int	management;		/* SVC_MGMT_* (default SVC_MGMT_SYSTEM) */
	uint32_t cap_system;		/* SYS_GATE_* bitmask */
	uint32_t protect_flags;		/* capprotect CP_SF_* bitmask */

	/* Path capabilities */
	char	cap_paths[CAPBUNDLE_MAX_CAP_PATHS][PATH_MAX];
	unsigned ncap_paths;

	/* File capabilities (fine-grained, with actions) */
	struct {
		char	path[PATH_MAX];
		uint64_t actions;	/* FI_FS_* mask */
	} cap_files[CAPBUNDLE_MAX_CAP_FILES];
	unsigned ncap_files;

	/* Files/dirs serviced opens and delivers as named descriptors */
	struct serviced_open_cap cap_open[CAPBUNDLE_MAX_CAP_OPEN];
	unsigned ncap_open;

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

	/* Pre-exec process policy (setrlimit / scheduling band / umask). */
	struct svc_limits limits;
	int	band;			/* SVC_BAND_* (default SVC_BAND_STANDARD) */
	int	umask_val;		/* mask, or -1 for the plane default */

	/* Calendar activation source (launchd StartCalendarInterval). */
	bool	has_calendar;
	struct svc_calendar calendar;
	bool	calendar_persistent;

	/* Queue-directory / mount activation sources. */
	char	queue_directory[PATH_MAX];
	bool	activation_on_mount;
};

/* Internal bundle representation. */
struct capbundle {
	char	path[PATH_MAX];		/* bundle directory */
	char	name[256];		/* basename of path (e.g. "Mail.cap") */
	char	bundle_id[CAPBUNDLE_ID_MAX];
	char	version[CAPBUNDLE_VERSION_MAX];
	char	author[CAPBUNDLE_AUTHOR_MAX];
	char	publisher[CAPBUNDLE_PUBLISHER_MAX];
	uint64_t sequence;
	char	unit_names[CAPBUNDLE_MAX_SERVICES][CAPBUNDLE_NAME_MAX + 1];
	unsigned nunit_names;
	struct capbundle_shared_storage shared_storage[CAPBUNDLE_MAX_CAP_STORAGE];
	unsigned nshared_storage;
	struct capbundle_service services[CAPBUNDLE_MAX_SERVICES];
	unsigned nservices;
};

/* Maximum UCL file size (1 MB).  Protects against OOM. */
#define	CAPBUNDLE_MAX_UCL_SIZE	(1024 * 1024)
#define	CAPBUNDLE_MAX_TREE_ENTRIES	4096U
#define	CAPBUNDLE_MAX_FILE_SIZE		(512ULL * 1024 * 1024)
#define	CAPBUNDLE_MAX_TREE_SIZE		(2ULL * 1024 * 1024 * 1024)

/*
 * Parse the bundle metadata and exact unit inventory.
 * Defined in libcapbundle_parse.c, called from capbundle_open().
 */
int	capbundle_parse_bundle_ucl(const char *path, struct capbundle *bundle,
	    char *errbuf, size_t errlen);

/* Parse one Units/<name>.unit/Unit.ucl declared by Bundle.ucl. */
int	capbundle_parse_unit_ucl(const char *path, const char *unit_path,
	    const struct capbundle *bundle, const char *unit_name,
	    struct capbundle_service *svc,
	    char *errbuf, size_t errlen);

/* Stable opaque ZFS leaf key; public to the parser tests, not installed ABI. */
int	capbundle_storage_dataset_key(char out[ORT_STORAGE_DATASET_MAX],
	    const char *bundle_id, const char *unit_name, const char *name,
	    uint8_t scope);

/*
 * Path-parameterized principal-policy core; public to the tests, not installed
 * ABI.  capbundle_principal_is_admin() pins the real policy path.
 */
struct passwd;
bool	capbundle_principal_is_admin_at(const struct passwd *pwd,
	    const char *policy_path);

#endif /* LIBCAPBUNDLE_INTERNAL_H */
