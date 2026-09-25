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

#include <capsulert.h>

#include "libcapbundle.h"
#include "switchboard_manifest.h"

/*
 * Upper bound on a monotonic activation.timer interval: 366 days in seconds.
 * A period longer than a year is far past the point where a monotonic timer is
 * the right mechanism (that is calendar/persistent territory, deferred in v1).
 */
#define	CAPBUNDLE_MAX_TIMER_INTERVAL	(366 * 24 * 3600)

/*
 * Upper bound on the liveness-watchdog interval (seconds).  A watchdog is a
 * heartbeat deadline, not a scheduling source, so it is capped far tighter
 * than an activation timer: one day is already generous for the slowest
 * batch-style provider.
 */
#define	CAPBUNDLE_MAX_WATCHDOG_INTERVAL	(24 * 3600)

/* The public and switchboard views of the same limits must agree. */
_Static_assert(CAPBUNDLE_LABEL_MAX == SWITCHBOARD_LABEL_MAX,
    "CAPBUNDLE_LABEL_MAX must equal SWITCHBOARD_LABEL_MAX");
_Static_assert(CAPBUNDLE_MAX_REQUIRES == SWITCHBOARD_MAX_REQUIRES,
    "CAPBUNDLE_MAX_REQUIRES must equal SWITCHBOARD_MAX_REQUIRES");
_Static_assert(CAPBUNDLE_MAX_ANOINTMENTS == SWITCHBOARD_MAX_ANOINTMENTS,
    "CAPBUNDLE_MAX_ANOINTMENTS must equal SWITCHBOARD_MAX_ANOINTMENTS");
_Static_assert(CAPBUNDLE_MAX_PROVIDES == SWITCHBOARD_MAX_PROVIDES,
    "CAPBUNDLE_MAX_PROVIDES must equal SWITCHBOARD_MAX_PROVIDES");

/* Internal service representation. */
struct capbundle_service {
	char	program[PATH_MAX];	/* absolute resolved path */
	char	arguments[SWITCHBOARD_MAX_ARGUMENTS][SWITCHBOARD_ARGUMENT_MAX];
	unsigned narguments;
	char	environment[SWITCHBOARD_MAX_ENVIRONMENT][SWITCHBOARD_ENVIRONMENT_MAX];
	unsigned nenvironment;
	char	label[CAPBUNDLE_NAME_MAX + 1];
	char	provides[CAPBUNDLE_MAX_PROVIDES][CAPBUNDLE_NAME_MAX + 1];
	unsigned nprovides;
	/*
	 * IPC anointments (docs/ipc-anointments-design.md).  requires[i] is the
	 * set of names a connecting program must hold (all of them) to resolve
	 * provides[i]; nrequires[i] == 0 leaves that endpoint open.  anointments
	 * is the set this unit declares it holds.  Names are bounded at parse
	 * to SWITCHBOARD_LABEL_MAX - 1 bytes.
	 */
	char	requires[CAPBUNDLE_MAX_PROVIDES][CAPBUNDLE_MAX_REQUIRES]
		    [SWITCHBOARD_LABEL_MAX];
	unsigned nrequires[CAPBUNDLE_MAX_PROVIDES];
	char	anointments[CAPBUNDLE_MAX_ANOINTMENTS][SWITCHBOARD_LABEL_MAX];
	unsigned nanointments;
	/* Resource directories delivered as descriptors (born-in-capmode). */
	char	resource_dirs[SWITCHBOARD_MAX_RESOURCE_DIRS][PATH_MAX];
	unsigned nresource_dirs;
	bool	activation_boot;
	bool	is_helper;		/* private helper: launched on request only */
	/*
	 * USER-domain visibility (§22).  When set, this unit's provides names are
	 * resolvable through a narrowed USER-domain lookup channel; when clear
	 * (the default) the names are SYSTEM-domain only and a user session never
	 * discovers them.  Set from the manifest `visible = ["user"]` list.
	 * This replaces switchboard's former hardcoded user-allow-list: which system
	 * providers a user session may reach is now a per-provider manifest policy.
	 */
	bool	user_resolvable;
	/*
	 * Operating-domain preference (SVC_MANIFEST_DOMAIN_*) from the manifest
	 * `domain` key.  DEFAULT (0) means the bundle-class default; switchboard
	 * resolves it to a concrete domain kind at launch.
	 */
	int	domain;
	/*
	 * Activation sources (Phase 5).  timer_interval_sec is the monotonic
	 * period in seconds (0 = none); activation_path is an absolute path
	 * watched via kqueue vnode events (empty = none).  Both name this unit
	 * in its own bundle and create demand for it, without dependency order.
	 */
	unsigned timer_interval_sec;
	char	activation_path[PATH_MAX];
	/*
	 * Socket activation sources (Phase 4).  switchboard binds and holds each
	 * listening socket and delivers it to this unit by logical name; the
	 * first inbound connection is the demand that launches the unit.
	 * nactivation_sockets == 0 = no socket source.
	 */
	struct svc_activation_socket
		activation_sockets[SWITCHBOARD_MAX_ACTIVATION_SOCKETS];
	unsigned nactivation_sockets;
	int	restart;
	int	management;		/* SVC_MGMT_* (default SVC_MGMT_SYSTEM) */
	uint32_t cap_system;		/* SYS_GATE_* bitmask */
	/*
	 * Per-OID sysctl isolation set (docs/capability-sysctl-isolation.md,
	 * Phase 2).  Dotted sysctl OID names; only meaningful with the "sysctl"
	 * gate.  Copied verbatim into svc_manifest by fill_manifest.
	 */
	char	sysctl_isolate[SWITCHBOARD_MAX_SYSCTL_ISOLATE]
		    [SWITCHBOARD_SYSCTL_NAME_MAX];
	unsigned n_sysctl_isolate;
	uint32_t protect_flags;		/* capprotect CP_SF_* bitmask */

	/* User/group for privilege drop */
	char	user[64];
	char	group[64];

	/* Stop timeout */
	int	stop_timeout;
	unsigned max_failures;

	/* Liveness watchdog interval in seconds (0 = disabled). */
	unsigned watchdog_interval;

	/* Ambient-authority (non-sandboxed) provider — see svc_manifest.ambient. */
	bool	ambient;

	/* Mint-authority role — see svc_manifest.mint_authority. */
	bool	mint_authority;

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
	/* Group containers (Data/Shared/<group>/) this bundle is a member of. */
	char	groups[CAPBUNDLE_MAX_GROUPS][CAPBUNDLE_GROUP_MAX];
	unsigned ngroups;
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

/* Reverse-domain name check shared by the parser and the principal policy. */
bool	capbundle_valid_service_name(const char *name, size_t maxlen);

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
