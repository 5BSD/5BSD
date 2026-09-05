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

/*
 * Upper bound on a monotonic activation.timer interval: 366 days in seconds.
 * A period longer than a year is far past the point where a monotonic timer is
 * the right mechanism (that is calendar/persistent territory, deferred in v1).
 */
#define	CAPBUNDLE_MAX_TIMER_INTERVAL	(366 * 24 * 3600)

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
	 * USER-domain visibility (§22).  When set, this unit's provides names are
	 * resolvable through a narrowed USER-domain lookup channel; when clear
	 * (the default) the names are SYSTEM-domain only and a user session never
	 * discovers them.  Set from the manifest `resolvable_by = ["user"]` list.
	 * This replaces serviced's former hardcoded user-allow-list: which system
	 * providers a user session may reach is now a per-provider manifest policy.
	 */
	bool	user_resolvable;
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

	/* User/group for privilege drop */
	char	user[64];
	char	group[64];

	/* Stop timeout */
	int	stop_timeout;
	unsigned max_failures;

	/* Privileged (non-sandboxed) provider — see svc_manifest.privileged. */
	bool	privileged;

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

/*
 * Path-parameterized principal-policy core; public to the tests, not installed
 * ABI.  capbundle_principal_is_admin() pins the real policy path.
 */
struct passwd;
bool	capbundle_principal_is_admin_at(const struct passwd *pwd,
	    const char *policy_path);

#endif /* LIBCAPBUNDLE_INTERNAL_H */
