/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <bsm/audit_kevents.h>
#include <string.h>

#include "auditcmp_policy.h"

struct auditcmp_identity_event {
	const char	*identity;
	int		 event;
};

static const struct auditcmp_identity_event events[] = {
	{ "system.Filesystem", AUE_FILESYSTEMCMP_POLICY },
	{ "system.Log", AUE_LOGCMP_POLICY },
	{ "system.Network", AUE_NETWORKCMP_POLICY },
	{ "system.Notify", AUE_BSDNOTIFY_POLICY },
};

int
auditcmp_policy_event(const char *identity)
{
	const char *slash;
	size_t i, idlen;

	if (identity == NULL)
		return (0);
	/*
	 * The policy is keyed by a provider's bundle id, but a connecting
	 * client presents its full unit label "<bundle-id>/<unit>".  Match
	 * only the bundle-id component so any unit of a recognized provider
	 * is granted its audit event class.
	 */
	slash = strchr(identity, '/');
	idlen = slash != NULL ? (size_t)(slash - identity) : strlen(identity);
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++)
		if (strlen(events[i].identity) == idlen &&
		    strncmp(events[i].identity, identity, idlen) == 0)
			return (events[i].event);
	return (0);
}
