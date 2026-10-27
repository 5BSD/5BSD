/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard management-class enforcement (§5 of the service-discovery model).
 *
 * A unit's management class governs who may stop/unload it at runtime.  This
 * module rejects runtime management of Core units, requires operator authority
 * for System units, and permits an authorized owner to manage User units.
 * In protected mode the dispatcher derives roles and ownership from a live
 * authenticated session, independently of the caller's UNIX credentials.
 */

#ifndef SWITCHBOARD_MANAGEMENT_H
#define SWITCHBOARD_MANAGEMENT_H

#include "switchboard_manifest.h"

struct svc_runtime;

void	svc_user_manifest_confine(struct svc_runtime *svc);
int	svc_user_manifest_credentials(struct svc_runtime *svc);
int	svc_user_credentials_match(uid_t owner, uid_t selected, bool have_creds);

/*
 * Management-class gate for a runtime management op (stop, start, restart,
 * unload, disable).  "op" is a verb used only for the diagnostic.  Returns 0 if
 * the op is permitted, else EPERM (logged at LOG_WARNING).  The three classes:
 *   CORE   -- refused absolutely, for everyone (escalation-proof); caller
 *             principal is never consulted.
 *   SYSTEM -- permitted only for an operator (is_operator true).
 *   USER   -- permitted for an operator, or for the owning uid itself
 *             (caller_uid == owner_uid): per-user-agent self-service.
 * In protected mode caller_uid is the authenticated session UID after the
 * dispatcher checks software eligibility and manage_self/manage_system rights;
 * (uid_t)-1 means no authorized owner. is_operator additionally requires a live
 * manage_system role. Development mode retains connection-UID ownership checks.
 */
int	svc_management_check_class(int management, const char *label,
	    const char *op, uid_t caller_uid, bool is_operator, uid_t owner_uid);

/* Convenience wrapper for a live unit; NULL svc is permitted (returns 0). */
int	svc_management_check_op(const struct svc_runtime *svc, const char *op,
	    uid_t caller_uid, bool is_operator);

/* Human-readable class name ("core"/"system"/"user"/"unknown"). */
const char *svc_management_name(int management);

/* Effective scheduling band: an INTERACTIVE boost is honoured only for a trusted
 * (system) bundle; a non-system unit is clamped to STANDARD. */
int	svc_effective_band(int band, bool is_system);

#endif /* SWITCHBOARD_MANAGEMENT_H */
