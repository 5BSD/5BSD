/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <bsm/audit_kevents.h>
#include <stdbool.h>
#include <string.h>

#include "auditcmp_policy.h"

struct auditcmp_identity_event {
	const char	*identity;
	/*
	 * Optional: the event applies only to operations that begin with this
	 * prefix (up to the first '/').  NULL means every operation; the first
	 * entry for an identity is also the session's admission event.
	 */
	const char	*operation;
	int		 event;
};

static const struct auditcmp_identity_event events[] = {
	{ "system.Log", NULL, AUE_LOGCMP_POLICY },
	{ "system.Network", NULL, AUE_NETWORKCMP_POLICY },
	{ "system.Notify", NULL, AUE_BSDNOTIFY_POLICY },
	{ "system.Crypto", NULL, AUE_CRYPTOCMP_POLICY },
	/*
	 * The auth agent (docs/ipc-anointments-design.md "Elevation") submits
	 * "elevate/<stage>/<name>" for anoint(1) and "mint/<kind>/..." for
	 * session mints; each is its own event class.
	 */
	{ "system.Auth", "elevate", AUE_AUTHAGENT_ELEVATE },
	{ "system.Auth", "mint", AUE_AUTHAGENT_MINT },
};

static bool
identity_matches(const struct auditcmp_identity_event *e,
    const char *identity)
{
	const char *slash;
	size_t idlen;

	/*
	 * The policy is keyed by a provider's bundle id, but a connecting
	 * client presents its full unit label "<bundle-id>/<unit>".  Match
	 * only the bundle-id component so any unit of a recognized provider
	 * is granted its audit event class.
	 */
	slash = strchr(identity, '/');
	idlen = slash != NULL ? (size_t)(slash - identity) : strlen(identity);
	return (strlen(e->identity) == idlen &&
	    strncmp(e->identity, identity, idlen) == 0);
}

int
auditcmp_policy_event(const char *identity)
{
	size_t i;

	if (identity == NULL)
		return (0);
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++)
		if (identity_matches(&events[i], identity))
			return (events[i].event);
	return (0);
}

/*
 * Refine a session's admission event by the submitted operation: a provider
 * with per-operation entries gets the event whose prefix matches the
 * operation's first path component; anything else keeps `fallback`.  An
 * unknown operation from a per-operation provider also keeps `fallback`, so
 * a record is never dropped for its operation text.
 */
int
auditcmp_policy_operation_event(const char *identity, const char *operation,
    int fallback)
{
	const char *slash;
	size_t i, oplen;

	if (identity == NULL || operation == NULL)
		return (fallback);
	slash = strchr(operation, '/');
	oplen = slash != NULL ? (size_t)(slash - operation) : strlen(operation);
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		if (events[i].operation == NULL ||
		    !identity_matches(&events[i], identity))
			continue;
		if (strlen(events[i].operation) == oplen &&
		    strncmp(events[i].operation, operation, oplen) == 0)
			return (events[i].event);
	}
	return (fallback);
}
