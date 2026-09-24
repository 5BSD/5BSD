/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard management-class enforcement (§5 of the service-discovery model).
 *
 * A unit's management class governs who may stop/unload it at runtime.  This
 * module implements the single absolute rule that needs no caller principal:
 * a "core" unit can never be stopped, restarted, unloaded, or disabled at
 * runtime — not even by root.  The principal-scoped system=root-only and
 * user=owning-uid rules are deferred to a later step (they require the minting
 * channel's recorded uid); see the hook comment in svc_management_check_class().
 */

#ifndef SWITCHBOARD_MANAGEMENT_H
#define SWITCHBOARD_MANAGEMENT_H

#include "switchboard_manifest.h"

struct svc_runtime;

/*
 * Management-class gate for a runtime management op (stop, start, restart,
 * unload, disable).  "op" is a verb used only for the diagnostic.  Returns 0 if
 * the op is permitted, else EPERM (logged at LOG_WARNING).  The three classes:
 *   CORE   -- refused absolutely, for everyone (escalation-proof); caller
 *             principal is never consulted.
 *   SYSTEM -- permitted only for an operator (is_operator true).
 *   USER   -- permitted for an operator, or for the owning uid itself
 *             (caller_uid == owner_uid): per-user-agent self-service.
 * caller_uid is the control channel's minted-channel principal ((uid_t)-1 if
 * none); is_operator is whether the caller holds management authority.
 */
int	svc_management_check_class(int management, const char *label,
	    const char *op, uid_t caller_uid, bool is_operator, uid_t owner_uid);

/* Convenience wrapper for a live unit; NULL svc is permitted (returns 0). */
int	svc_management_check_op(const struct svc_runtime *svc, const char *op,
	    uid_t caller_uid, bool is_operator);

/* Human-readable class name ("core"/"system"/"user"/"unknown"). */
const char *svc_management_name(int management);

#endif /* SWITCHBOARD_MANAGEMENT_H */
