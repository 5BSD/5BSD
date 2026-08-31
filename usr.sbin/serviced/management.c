/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced management-class enforcement (§5 of the service-discovery model).
 */

#include <sys/types.h>

#include <errno.h>
#include <stddef.h>
#include <syslog.h>

#include "serviced.h"
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
svc_management_check_class(int management, const char *label, const char *op)
{

	if (management == SVC_MGMT_CORE) {
		syslog(LOG_WARNING,
		    "management class core: %s cannot be %s at runtime",
		    label != NULL ? label : "(unknown)",
		    op != NULL ? op : "managed");
		return (EPERM);
	}

	/*
	 * PRINCIPAL HOOK (§6, later step): the SVC_MGMT_SYSTEM=root-only and
	 * SVC_MGMT_USER=owning-uid decisions belong here, once each request
	 * carries the minting channel's recorded (uid, rights).  They are NOT
	 * implemented yet — the CORE rule above is the only class rule that is
	 * absolute and principal-independent.  Until then the per-operation
	 * SVC_RIGHTS_ADMIN check on the capability control channel (sctl.c
	 * sctl_cap_request: every state-changing op requires the ADMIN right held
	 * on its grant) is the sole authority for system/user classes, so every
	 * non-core op is permitted from here.
	 */
	return (0);
}

int
svc_management_check_op(const struct svc_runtime *svc, const char *op)
{

	if (svc == NULL)
		return (0);
	return (svc_management_check_class(svc->manifest.management,
	    svc->manifest.label, op));
}
