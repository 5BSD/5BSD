/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced management-class enforcement (§5 of the service-discovery model).
 *
 * A unit's management class governs who may stop/unload it at runtime.  This
 * module implements the single absolute rule that needs no caller principal:
 * a "core" unit can never be stopped, restarted, unloaded, or disabled at
 * runtime — not even by root.  The principal-scoped system=root-only and
 * user=owning-uid rules are deferred to a later step (they require the minting
 * channel's recorded uid); see the hook comment in svc_management_check_class().
 */

#ifndef SERVICED_MANAGEMENT_H
#define SERVICED_MANAGEMENT_H

#include "serviced_manifest.h"

struct svc_runtime;

/*
 * Absolute management-class gate for an operator/runtime management op
 * (stop, restart, unload, disable).  "op" is a past-tense verb used only for
 * the diagnostic ("... cannot be <op> at runtime").  Returns 0 if the op is
 * permitted for a unit of this class, or EPERM (and logs at LOG_WARNING) if the
 * class is SVC_MGMT_CORE.  Never consults a caller principal — the CORE refusal
 * is absolute.
 */
int	svc_management_check_class(int management, const char *label,
	    const char *op);

/* Convenience wrapper for a live unit; NULL svc is permitted (returns 0). */
int	svc_management_check_op(const struct svc_runtime *svc, const char *op);

/* Human-readable class name ("core"/"system"/"user"/"unknown"). */
const char *svc_management_name(int management);

#endif /* SERVICED_MANAGEMENT_H */
