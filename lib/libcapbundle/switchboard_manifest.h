/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service manifest types — shared between switchboard and libcapbundle.
 *
 * This header defines the manifest struct and claim types used by both
 * switchboard and the bundle parser (libcapbundle).  It deliberately has no
 * daemon-internal state so that libraries can include it without pulling in
 * kqueue, runtime structs, or function prototypes.
 */

#ifndef SWITCHBOARD_MANIFEST_H
#define SWITCHBOARD_MANIFEST_H

#include <sys/types.h>
#include <sys/param.h>

#include <stdbool.h>
#include <stdint.h>

#include <capsulert.h>

/*
 * Limits.
 */
#define	SWITCHBOARD_MAX_SERVICES		256
#define	SWITCHBOARD_MAX_PROVIDES		8
#define	SWITCHBOARD_LABEL_MAX		64
/*
 * IPC anointments (docs/ipc-anointments-design.md): per-endpoint required
 * names and per-unit held names.  Mirror CAPBUNDLE_MAX_REQUIRES /
 * CAPBUNDLE_MAX_ANOINTMENTS in libcapbundle.h.
 */
#define	SWITCHBOARD_MAX_REQUIRES		8
#define	SWITCHBOARD_MAX_ANOINTMENTS	32
#define	SWITCHBOARD_MAX_ARGUMENTS		32
#define	SWITCHBOARD_ARGUMENT_MAX		256
#define	SWITCHBOARD_MAX_ENVIRONMENT	32
#define	SWITCHBOARD_ENVIRONMENT_MAX	1024
#define	SWITCHBOARD_MAX_ACTIVATION_SOCKETS	4
#define	SWITCHBOARD_MAX_RESOURCE_DIRS	8
/*
 * Per-OID sysctl isolation set (docs/capability-sysctl-isolation.md, Phase 2).
 * A "sysctl"-gated provider (bsdsysctl) may declare an `isolate` list of
 * sysctl OID names; switchboard resolves each name to a MIB and asks Capsule
 * to mint a SYSCTL token scoped to exactly those OIDs.  The count cap mirrors
 * the kernel's SYS_SYSCTL_MAXOIDS (per-claim isolated-OID cap) so a manifest
 * can never overflow a single scoped claim; SWITCHBOARD_SYSCTL_NAME_MAX bounds one
 * OID name (dotted sysctl path).
 */
#define	SWITCHBOARD_MAX_SYSCTL_ISOLATE	64	/* == SYS_SYSCTL_MAXOIDS */
#define	SWITCHBOARD_SYSCTL_NAME_MAX	128
#define	SWITCHBOARD_DEFAULT_USER		"capability"
#define	SWITCHBOARD_DEFAULT_GROUP		"capability"

/* Restart policy */
#define	SVC_RESTART_NEVER		0
#define	SVC_RESTART_ALWAYS		1
#define	SVC_RESTART_ON_FAILURE		2

/*
 * Service management class (§5 of the service-discovery model).  Governs who
 * may load/unload/start/stop the unit at runtime — orthogonal to discovery and
 * to the launcher process shield (protect_flags).  Values are chosen so that a
 * zero-initialised manifest (calloc / memset) is SVC_MGMT_SYSTEM, preserving
 * today's all-system behaviour for the base bundles and any manifest that omits
 * the key.
 *
 *   SYSTEM  root only (default).  Base daemons and adopted rc.d services.
 *   CORE    nobody — not even root — may stop/unload it at runtime; only the
 *           boot/shutdown lifecycle and reload-on-manifest-change touch it.
 *   USER    the owning uid (and root).  Per-user agents.
 *
 * Only the absolute CORE rule is enforced today; the SYSTEM=root-only and
 * USER=owning-uid rules need the channel principal and land in a later step.
 */
#define	SVC_MGMT_SYSTEM			0
#define	SVC_MGMT_CORE			1
#define	SVC_MGMT_USER			2

/*
 * Operating domain a launched unit's OWN service lookups run in (§22).  This is
 * the scope switchboard applies to names the unit itself resolves over its
 * bootstrap channel — distinct from resolvable_by, which controls who may
 * resolve the unit.  A zero-initialised manifest is SVC_MANIFEST_DOMAIN_DEFAULT,
 * so an omitted "domain" key defers to the sensible default: a base-system
 * bundle (under /Capabilities/System) operates in the SYSTEM domain (resolves
 * every registered name, as today), and an application bundle operates in the
 * USER domain (least privilege — resolves only user-visible names).  An explicit
 * "system" or "user" overrides that default.
 */
#define	SVC_MANIFEST_DOMAIN_DEFAULT	0
#define	SVC_MANIFEST_DOMAIN_SYSTEM	1
#define	SVC_MANIFEST_DOMAIN_USER	2

/*
 * Scheduling band (launchd ProcessType analogue).  Governs the CPU/IO priority
 * switchboard applies to the launched process.  A zero-initialised manifest is
 * SVC_BAND_STANDARD, so an omitted "band" key keeps today's neutral behaviour.
 *
 *   STANDARD     default; no special scheduling treatment.
 *   BACKGROUND   throttled CPU/IO — batch, periodic, and drain work that must
 *                not starve interactive units (positive nice + low-prio IO).
 *   INTERACTIVE  latency-sensitive; no imposed throttle (slight nice boost).
 */
#define	SVC_BAND_STANDARD		0
#define	SVC_BAND_BACKGROUND		1
#define	SVC_BAND_INTERACTIVE		2

/*
 * Pre-exec resource limits (setrlimit, launchd Hard/SoftResourceLimits).  Each
 * field is a byte/second/count ceiling, or SVC_LIMIT_UNSET to leave the
 * inherited limit in place.  switchboard applies these in the child after pdfork
 * and before exec, so the ceilings are in force from the first instruction of
 * the program image.  core defaults to 0 (no core dumps) unless overridden.
 */
#define	SVC_LIMIT_UNSET			((int64_t)-1)
struct svc_limits {
	int64_t		mem;		/* RLIMIT_AS, bytes */
	int64_t		cpu;		/* RLIMIT_CPU, seconds */
	int64_t		nproc;		/* RLIMIT_NPROC, processes */
	int64_t		nofile;		/* RLIMIT_NOFILE, descriptors */
	int64_t		stack;		/* RLIMIT_STACK, bytes */
	int64_t		fsize;		/* RLIMIT_FSIZE, bytes */
	int64_t		core;		/* RLIMIT_CORE, bytes (default 0) */
};

/*
 * Calendar activation (launchd StartCalendarInterval).  Each field holds the
 * matched value, or SVC_CAL_ANY for a wildcard.  A fire is due when every set
 * field matches wall-clock local time; omitted fields match anything.  This is
 * the cron/periodic replacement — one supervisor owns timers, so cron need not
 * run as a separate adopted rc unit.
 */
#define	SVC_CAL_ANY			(-1)
struct svc_calendar {
	int		minute;		/* 0-59  or SVC_CAL_ANY */
	int		hour;		/* 0-23  or SVC_CAL_ANY */
	int		mday;		/* 1-31  or SVC_CAL_ANY */
	int		month;		/* 1-12  or SVC_CAL_ANY */
	int		wday;		/* 0-6, Sun=0, or SVC_CAL_ANY */
};

/*
 * Socket activation source (Phase 4).  switchboard binds and holds a
 * listening socket; the first inbound connection is the demand that
 * launches this unit, and the listener is delivered to it by logical
 * name.  The listener outlives the unit's start/stop cycles, so a
 * provider restart never drops a queued connection.  domain and socktype are
 * stored as their AF_ and SOCK_ integer values (assigned by the parser, so
 * this header needs no sys/socket.h).
 */
struct svc_activation_socket {
	char		name[SWITCHBOARD_LABEL_MAX];  /* logical name delivered */
	int		domain;			/* AF_INET / AF_INET6 / AF_UNIX */
	int		socktype;		/* SOCK_STREAM / SOCK_DGRAM */
	uint8_t		addr[16];		/* v4/v6 address, 0 = any */
	uint16_t	port;			/* host order; 0 for AF_UNIX */
	char		unixpath[104];		/* AF_UNIX path; empty otherwise */
	int		backlog;		/* listen(2) backlog; default 128 */
};

/*
 * Parsed service manifest.
 *
 * Produced by capbundle_svc_fill_manifest() from a parsed bundle.  Immutable
 * after loading.
 */
struct svc_manifest {
	char		label[SWITCHBOARD_LABEL_MAX];
	char		program[PATH_MAX];
	char		arguments[SWITCHBOARD_MAX_ARGUMENTS][SWITCHBOARD_ARGUMENT_MAX];
	unsigned	narguments;
	char		environment[SWITCHBOARD_MAX_ENVIRONMENT][SWITCHBOARD_ENVIRONMENT_MAX];
	unsigned	nenvironment;
	char		user[64];
	char		group[64];

	/* Capability endpoints this service publishes. */
	char		provides[SWITCHBOARD_MAX_PROVIDES][SWITCHBOARD_LABEL_MAX];
	unsigned	nprovides;
	/*
	 * IPC anointments.  requires[i] lists the names a program must hold
	 * (all of them) to resolve provides[i]; nrequires[i] == 0 means the
	 * endpoint is open.  anointments lists the names this unit holds when it
	 * looks names up.  Indexed in parallel with provides[].
	 */
	char		requires[SWITCHBOARD_MAX_PROVIDES][SWITCHBOARD_MAX_REQUIRES]
			    [SWITCHBOARD_LABEL_MAX];
	unsigned	nrequires[SWITCHBOARD_MAX_PROVIDES];
	char		anointments[SWITCHBOARD_MAX_ANOINTMENTS][SWITCHBOARD_LABEL_MAX];
	unsigned	nanointments;

	/*
	 * Resource directories the daemon needs delivered as descriptors (§
	 * born-in-capability-mode).  switchboard opens each absolute directory
	 * O_DIRECTORY before the child enters capability mode and hands it down as
	 * an inherited fd (advertised in CAPABILITY_DIR_FDS), so a born-in-capmode
	 * daemon reaches e.g. /dev by openat(2) under the delivered fd instead of
	 * opening a global path.  A read-only directory capability; the daemon
	 * never names the path itself.
	 */
	char		resource_dirs[SWITCHBOARD_MAX_RESOURCE_DIRS][PATH_MAX];
	unsigned	nresource_dirs;

	/*
	 * Private helper (XPC-style): launched on request by a bundle sibling via
	 * service_helper_open(), never published under a system.* name and never
	 * boot-activated.  Resolved bundle-locally and scoped to the requesting
	 * parent's coalition.
	 */
	bool		is_helper;

	/*
	 * USER-domain visibility (§22).  When set, this unit's provides names are
	 * resolvable through a narrowed USER-domain lookup channel; when clear (the
	 * default) they are SYSTEM-domain only and a user session never discovers
	 * them.  Set from the manifest `resolvable_by = ["user"]`.  This is the
	 * per-provider replacement for switchboard's former hardcoded user-allow-list.
	 */
	bool		user_resolvable;

	/*
	 * Operating domain preference (§22): SVC_MANIFEST_DOMAIN_* from the
	 * manifest `domain` key.  DEFAULT (absent) defers to the bundle-class
	 * default; switchboard resolves it to a concrete domain kind at launch.
	 */
	int		domain;

	/* Capabilities to delegate */
	uint32_t	cap_system;	/* SYS_GATE_* bitmask */

	/*
	 * Per-OID sysctl isolation set (docs/capability-sysctl-isolation.md,
	 * Phase 2).  Only meaningful when cap_system carries SYS_GATE_SYSCTL.
	 * Each entry is a dotted sysctl OID name (e.g. "kern.maxfiles"); switchboard
	 * resolves them to MIBs at launch and asks Capsule to mint a SYSCTL
	 * token scoped to exactly this set.  An empty list with the sysctl gate
	 * declared is refused at launch (a bare, coarse sysctl gate is not
	 * delegatable — see execute.c).
	 */
	char		sysctl_isolate[SWITCHBOARD_MAX_SYSCTL_ISOLATE]
			    [SWITCHBOARD_SYSCTL_NAME_MAX];
	unsigned	n_sysctl_isolate;

	int		restart;	/* SVC_RESTART_* */
	int		management;	/* SVC_MGMT_* (default SVC_MGMT_SYSTEM) */
	int		stop_timeout;	/* seconds before SIGKILL (default 5) */
	unsigned	max_failures;	/* circuit breaker threshold (default 10) */

	/*
	 * Pre-exec process policy (applied in the child before exec).
	 *   limits:  setrlimit ceilings; SVC_LIMIT_UNSET fields are inherited.
	 *   band:    SVC_BAND_* scheduling class (default SVC_BAND_STANDARD).
	 *   umask:   file-creation mask, or -1 for the plane default (0077).
	 */
	struct svc_limits limits;
	int		band;
	int		umask_val;

	/*
	 * An ambient-authority provider legitimately runs OUTSIDE capability mode: its
	 * authority is a held system capability, not the capsicum sandbox, and its
	 * work needs the global namespace and classic privilege (the canonical
	 * case is bsdextension's kldload).  switchboard therefore treats the application's
	 * SVC_OP_READY as the readiness boundary instead of kernel-observed
	 * capability-mode entry.  Only honored for SYSTEM-domain bundles.
	 */
	bool		ambient;

	/*
	 * Mint-authority role (§6).  The mint boundary — the single unit permitted
	 * to translate an authenticated identity into a session lookup channel via
	 * SVC_OP_MINT_DOMAIN — is recognized by THIS declared role, not by matching
	 * a hardcoded principal label.  A minted channel's lookups carry
	 * requester == NULL and so obtain the ADMIN bypass, so the authority to
	 * mint is TCB-critical: switchboard honors this flag ONLY for a base-system
	 * bundle (bundle_registry_is_system), exactly as it does `ambient`, so an
	 * application bundle that self-declares it is ignored.  Set on BSDAuth's
	 * authagentd unit alone; see usr.sbin/switchboard/svc_proto.c and
	 * docs/auth-agent-design.md.
	 */
	bool		mint_authority;

	/*
	 * Activation sources (Phase 5).  These describe how THIS unit is
	 * activated on demand while it is stopped; they are not dependency
	 * ordering.  A timer or path source names the unit in its own bundle and
	 * creates demand for it when it fires (§13).
	 *
	 * timer_interval_sec: monotonic period in seconds; 0 = no timer source.
	 *   v1 supports monotonic intervals only — calendar/cron expressions are
	 *   rejected at parse time.
	 * activation_path: absolute path watched via kqueue vnode events; empty =
	 *   no path source.  Events are hints, never proof the path is unchanged.
	 */
	unsigned	timer_interval_sec;
	char		activation_path[PATH_MAX];

	/*
	 * Calendar activation source (launchd StartCalendarInterval).  When
	 * has_calendar is set, switchboard computes the next wall-clock match of
	 * `calendar` and arms a one-shot timer; on fire it re-arms for the
	 * following match.  calendar_persistent requests anacron-style catch-up:
	 * if a due fire was missed while switchboard (or the machine) was down, run
	 * once at startup.  This supersedes timer_interval_sec for wall-clock work.
	 */
	bool		has_calendar;
	struct svc_calendar calendar;
	bool		calendar_persistent;

	/*
	 * Queue-directory activation (launchd QueueDirectories).  While
	 * queue_directory is non-empty (holds any non-dot entry), switchboard keeps
	 * the unit started, relaunching it after each exit until the directory
	 * drains — the spool-drain pattern, layered on the same EVFILT_VNODE
	 * watch as activation_path.  Empty string = no queue source.
	 *
	 * activation_on_mount (launchd StartOnMount): (re)start the unit whenever
	 * a filesystem is mounted.
	 */
	char		queue_directory[PATH_MAX];
	bool		activation_on_mount;

	/*
	 * Socket activation source (Phase 4).  switchboard binds and holds a
	 * listening socket; the first inbound connection is the demand that
	 * launches this unit, and the listener is delivered to it by logical
	 * name.  The listener outlives the unit's start/stop cycles, so a
	 * provider restart never drops a queued connection.  nactivation_sockets
	 * == 0 = no socket source.
	 */
	struct svc_activation_socket
			activation_sockets[SWITCHBOARD_MAX_ACTIVATION_SOCKETS];
	unsigned	nactivation_sockets;

	/*
	 * Launcher-applied protection policy (capprotect CP_SF_* bitmask).  When
	 * non-zero switchboard shields the launched process by its process
	 * descriptor immediately after pdfork(2), so the protection is in force
	 * from the moment the process exists — before its program image runs and
	 * regardless of what that image does.  Zero leaves the process to apply
	 * its own shield (or none).
	 */
	uint32_t	protect_flags;
};

#endif /* SWITCHBOARD_MANIFEST_H */
