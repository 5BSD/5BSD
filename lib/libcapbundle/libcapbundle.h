/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libcapbundle — parse and validate 5BSD .cap bundles.
 *
 * A bundle is a self-contained application directory:
 *   Name.cap/Bundle.ucl
 *   Name.cap/Shared/{Config,Resources,Libraries,Executables}/
 *   Name.cap/Units/name.unit/Unit.ucl
 *   Name.cap/Units/name.unit/bin/name
 *
 * Bundle.ucl is the sole source of bundle identity and declares the exact
 * unit inventory.  Unit identity comes from its .unit directory name.
 */

#ifndef LIBCAPBUNDLE_H
#define LIBCAPBUNDLE_H

#include <sys/types.h>
#include <stdbool.h>

/* Limits */
#define	CAPBUNDLE_SCHEMA		"org.5bsd.capability-bundle"
#define	CAPBUNDLE_SCHEMA_VERSION	1
#define	CAPBUNDLE_MAX_SERVICES		32
#define	CAPBUNDLE_MAX_PROVIDES		8
#define	CAPBUNDLE_ID_MAX		128
#define	CAPBUNDLE_VERSION_MAX		32
#define	CAPBUNDLE_AUTHOR_MAX		128
#define	CAPBUNDLE_PUBLISHER_MAX		128
#define	CAPBUNDLE_NAME_MAX		255

struct capbundle;
struct capbundle_service;

/*
 * Open and parse a .cap bundle directory.  path and bp are required; *bp is
 * cleared before any parsing is attempted.  Returns 0 on success, -1 on
 * error with errno set (details in errbuf if non-NULL).
 */
int	capbundle_open(const char *path, struct capbundle **bp,
	    char *errbuf, size_t errlen);
void	capbundle_close(struct capbundle *b);

/* Bundle-level accessors return NULL when passed NULL. */
const char	*capbundle_id(const struct capbundle *b);
const char	*capbundle_version(const struct capbundle *b);
const char	*capbundle_author(const struct capbundle *b);
const char	*capbundle_publisher(const struct capbundle *b);
uint64_t	 capbundle_sequence(const struct capbundle *b);
const char	*capbundle_path(const struct capbundle *b);
const char	*capbundle_name(const struct capbundle *b);  /* dir basename */

/* Service enumeration returns zero/NULL for a NULL bundle or bad index. */
unsigned	 capbundle_nservices(const struct capbundle *b);
struct capbundle_service *capbundle_service(const struct capbundle *b,
		    unsigned idx);

/* Service accessors return zero/NULL for a NULL service or bad index. */
const char	*capbundle_svc_program(const struct capbundle_service *s);
const char	*capbundle_svc_label(const struct capbundle_service *s);
bool		 capbundle_svc_activates_at_boot(
		    const struct capbundle_service *s);
unsigned	 capbundle_svc_nprovides(const struct capbundle_service *s);
/*
 * Management class (§5): one of CAPBUNDLE_MGMT_* below, governing who may
 * stop/unload the unit at runtime.  Returns CAPBUNDLE_MGMT_SYSTEM (0) for a
 * NULL service, matching the absent-key default.
 */
int		 capbundle_svc_management_class(const struct capbundle_service *s);
/*
 * Activation sources (Phase 5).  timer interval is a monotonic period in
 * seconds (0 = no timer source); activation path is an absolute path watched
 * via kqueue vnode events ("" = no path source).  Both return zero/"" for a
 * NULL service.
 */
unsigned	 capbundle_svc_timer_interval(const struct capbundle_service *s);
const char	*capbundle_svc_activation_path(
		    const struct capbundle_service *s);
/*
 * Socket activation sources (Phase 4).  serviced binds and holds each listening
 * socket and delivers it to the unit by logical name.  Returns 0/NULL for a
 * NULL service or out-of-range index.
 */
struct svc_activation_socket;
unsigned	 capbundle_svc_nactivation_sockets(
		    const struct capbundle_service *s);
const struct svc_activation_socket *capbundle_svc_activation_socket(
		    const struct capbundle_service *s, unsigned i);
const char	*capbundle_svc_provides(const struct capbundle_service *s,
		    unsigned idx);
unsigned	 capbundle_svc_narguments(const struct capbundle_service *s);
const char	*capbundle_svc_argument(const struct capbundle_service *s,
		    unsigned idx);
unsigned	 capbundle_svc_nenvironment(const struct capbundle_service *s);
const char	*capbundle_svc_environment(const struct capbundle_service *s,
		    unsigned idx);

/*
 * Fill a svc_manifest struct from a bundle service.
 * This is the preferred way to get a complete manifest — handles all
 * capability fields, not just system gates.
 * Caller provides the struct; function fills all fields.
 * s and m are required.  Returns 0 on success, -1 with errno set on error.
 */
struct svc_manifest;
int	capbundle_svc_fill_manifest(const struct capbundle_service *s,
	    struct svc_manifest *m);

/*
 * Validate bundle integrity.
 * Checks structure, required fields, binary existence, internal consistency.
 * b is required.  Returns 0 if valid, -1 with errno set and details in
 * errbuf.
 */
int	capbundle_verify(const struct capbundle *b, char *errbuf, size_t errlen);

/*
 * Scan a directory for .cap bundles.
 * Calls cb for each successfully opened bundle.
 * If cb returns non-zero, scanning stops and that value is returned.
 * dirpath and cb are required.  Returns 0 on success, -1 with errno set on a
 * directory, argument, or malformed-bundle error.
 * Invalid bundles stop the scan; declarations are never silently skipped.
 */
typedef int (*capbundle_scan_cb)(struct capbundle *b, void *ctx);
int	capbundle_scan_dir(const char *dirpath, capbundle_scan_cb cb, void *ctx);

/* Restart policy constants (matches serviced). */
#define	CAPBUNDLE_RESTART_NEVER		0
#define	CAPBUNDLE_RESTART_ALWAYS	1
#define	CAPBUNDLE_RESTART_ON_FAILURE	2

/* Management class constants (matches serviced SVC_MGMT_*, §5). */
#define	CAPBUNDLE_MGMT_SYSTEM		0
#define	CAPBUNDLE_MGMT_CORE		1
#define	CAPBUNDLE_MGMT_USER		2

/*
 * The principal->bundle admin policy (docs/capability-authority-model.md, P1).
 * Whether a principal is entitled to an admin (full-discovery) session, per the
 * UCL policy at /Capabilities/Config/principal-policy.ucl, defaulting to the
 * historical rule (root or a member of "wheel") when no policy is configured.
 */
struct passwd;
bool	capbundle_principal_is_admin(const struct passwd *pwd);

/*
 * As above, but read the policy from an already-open read-only descriptor
 * rather than by path — the capsicum-clean form for a sandboxed auth-agent that
 * obtains principal-policy.ucl from the filesystem daemon (tzfsd) via
 * service_open_isolated(3).  A bad or absent fd fails safe to the historical
 * default.
 */
bool	capbundle_principal_is_admin_fd(const struct passwd *pwd, int policy_fd);

/*
 * A group-name -> gid resolver, returning (gid_t)-1 for an unknown name.  It
 * lets the decision core run without any group-database access of its own: a
 * capsicum-sandboxed auth-agent backs it with Casper cap_grp; an ordinary
 * caller backs it with getgrnam(3).
 */
typedef gid_t (*capbundle_group_gid_fn)(void *ctx, const char *group_name);

/*
 * The data-only decision core.  Decide admin-ness for a principal already
 * resolved to a uid and its set of member group ids, against the policy on
 * `policy_fd` (or the historical default when the fd is absent/unreadable),
 * using `name2gid` to resolve any group names the policy references.  This is
 * the entry point a sandboxed auth-agent uses after resolving the principal
 * itself (never trusting caller-supplied attributes).
 */
bool	capbundle_principal_is_admin_resolved(int policy_fd, uid_t uid,
	    const gid_t *member_gids, unsigned nmember,
	    capbundle_group_gid_fn name2gid, void *ctx);

#endif /* LIBCAPBUNDLE_H */
