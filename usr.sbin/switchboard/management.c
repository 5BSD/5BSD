/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard management-class enforcement (§5 of the service-discovery model).
 */

#include <sys/types.h>

#include <errno.h>
#include <stddef.h>
#include <syslog.h>

#include "switchboard.h"
#include "management.h"

const char *
svc_management_name(int management)
{

	switch (management) {
	case SVC_MGMT_CORE:
		return ("core");
	case SVC_MGMT_SYSTEM:
		return ("system");
	case SVC_MGMT_USER:
		return ("user");
	default:
		return ("unknown");
	}
}

int
svc_effective_band(int band, bool is_system)
{

	/*
	 * A scheduling BOOST is a privilege: an INTERACTIVE band is honoured only
	 * for a trusted system bundle (whose verified manifest is the
	 * declaration).  A non-system unit's boost is clamped to STANDARD.
	 * STANDARD and BACKGROUND (throttle down) need no privilege and pass
	 * through for any unit.
	 */
	if (band == SVC_BAND_INTERACTIVE && !is_system)
		return (SVC_BAND_STANDARD);
	return (band);
}

int
svc_management_check_class(int management, const char *label, const char *op,
    uid_t caller_uid, bool is_operator, uid_t owner_uid)
{
	const char *l = label != NULL ? label : "(unknown)";
	const char *o = op != NULL ? op : "managed";

	switch (management) {
	case SVC_MGMT_CORE:
		/*
		 * Absolute, escalation-proof: a core unit (the base TCB plane)
		 * cannot be managed at runtime by anyone -- not an operator, not
		 * uid 0, not any held right or anointment.  Only switchboard's own
		 * boot/shutdown/restart lifecycle touches it.
		 */
		syslog(LOG_WARNING,
		    "management class core: %s cannot be %s at runtime", l, o);
		return (EPERM);
	case SVC_MGMT_USER:
		/*
		 * A per-user agent: manageable by an operator, or by the owning
		 * uid itself (the uid whose agent directory it was loaded from --
		 * self-service, no operator authority required).  No other
		 * principal, whatever it holds.
		 */
		if (is_operator)
			return (0);
		if (owner_uid != (uid_t)-1 && caller_uid != (uid_t)-1 &&
		    caller_uid == owner_uid)
			return (0);
		syslog(LOG_WARNING, "management class user: %s: %s denied for "
		    "uid %u (owner %u)", l, o, (unsigned)caller_uid,
		    (unsigned)owner_uid);
		return (EPERM);
	case SVC_MGMT_SYSTEM:
	default:
		/*
		 * System-wide services (base non-core daemons and operator-added
		 * software): manageable only by an operator (a session holding the
		 * management authority), never by a uid alone.
		 */
		if (is_operator)
			return (0);
		syslog(LOG_WARNING, "management class system: %s: %s requires "
		    "operator authority (uid %u)", l, o, (unsigned)caller_uid);
		return (EPERM);
	}
}

int
svc_management_check_op(const struct svc_runtime *svc, const char *op,
    uid_t caller_uid, bool is_operator)
{

	if (svc == NULL)
		return (0);
	return (svc_management_check_class(svc->manifest.management,
	    svc->manifest.label, op, caller_uid, is_operator, svc->owner_uid));
}
