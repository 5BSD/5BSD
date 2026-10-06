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
#include <pwd.h>
#include <string.h>
#include <syslog.h>

#include "switchboard.h"
#include "management.h"

/* User-writable bundle declarations cannot grant protected service access. */
void
svc_user_manifest_confine(struct svc_runtime *svc)
{
	struct svc_manifest *m = &svc->manifest;

	if (svc->owner_uid == (uid_t)-1)
		return;
	m->management = SVC_MGMT_USER;
	m->domain = SVC_MANIFEST_DOMAIN_USER;
	m->user_resolvable = false;
	m->ambient = false;
	m->cap_system = 0;
	m->n_sysctl_isolate = 0;
	/* Root-created listeners are reserved for trusted installation policy. */
	m->nactivation_sockets = 0;
	memset(m->activation_sockets, 0, sizeof(m->activation_sockets));
	m->nanointments = 0;
	memset(m->anointments, 0, sizeof(m->anointments));
}

/* Resolve the account from registry ownership, never from writable policy. */
int
svc_user_manifest_credentials(struct svc_runtime *svc)
{
	struct passwd *pw;

	if (svc->owner_uid == (uid_t)-1)
		return (0);
	pw = getpwuid(svc->owner_uid);
	if (pw == NULL)
		return (errno = ENOENT, -1);
	if (strlcpy(svc->manifest.user, pw->pw_name,
	    sizeof(svc->manifest.user)) >= sizeof(svc->manifest.user))
		return (errno = ENAMETOOLONG, -1);
	svc->manifest.group[0] = '\0';
	return (0);
}

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
		 * uid 0, not any held right or attribute.  Only switchboard's own
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
		 * software): require software management authority, never a UID alone.
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
