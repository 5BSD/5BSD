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
	{ "org.5bsd.FileSystemCmp", AUE_FILESYSTEMCMP_POLICY },
	{ "org.5bsd.LogCmp", AUE_LOGCMP_POLICY },
	{ "org.5bsd.NetworkCmp", AUE_NETWORKCMP_POLICY },
	{ "org.5bsd.NotifyCmp", AUE_NOTIFYCMP_POLICY },
};

int
auditcmp_policy_event(const char *identity)
{
	size_t i;

	if (identity == NULL)
		return (0);
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++)
		if (strcmp(events[i].identity, identity) == 0)
			return (events[i].event);
	return (0);
}
