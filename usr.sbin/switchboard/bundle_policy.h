/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_BUNDLE_POLICY_H
#define SWITCHBOARD_BUNDLE_POLICY_H

#include <sys/types.h>
#include <stdbool.h>
#include "switchboard_manifest.h"

/* Installation provenance, not signer identity, authorizes platform grants.
 * Personal units are handled by svc_user_manifest_confine at launch; keep
 * that policy independent of whether the owner signs their bundle.
 * Ambient UNIX execution and endpoint requirements do not assert grants.
 * System provenance is currently an operator-controlled installation scope,
 * not an authenticated boot-time trust anchor against malicious root.
 */
static inline bool
bundle_manifest_platform_allowed(const struct svc_manifest *m, bool system,
    uid_t owner_uid)
{
	return (system || owner_uid != (uid_t)-1 ||
	    (m->cap_system == 0 && m->nanointments == 0 &&
	    m->n_sysctl_isolate == 0));
}
#endif
