/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ensures required kernel modules are loaded before a service is launched.
 * The operation is delegated to authorityd so serviced never needs ambient
 * KLDSTAT/KLDLOAD authority.  Authority owns both pre-exec and runtime module
 * requests.
 */

#include <sys/types.h>
#include <syslog.h>

#include "serviced.h"

/*
 * Ensure all kernel modules required by manifest m are loaded.
 * Authorityd checks whether each module is already present and loads it if not.
 *
 * Returns 0 if all modules are loaded, -1 on failure.
 */
int
kldmgr_ensure_loaded(const struct svc_manifest *m, bool system_bundle,
    int kq __unused)
{
	unsigned i;

	/*
	 * Only system bundles may load kernel modules.  User bundles
	 * with kmod_requires are rejected here to prevent untrusted
	 * manifests from loading arbitrary kernel code.
	 */
	if (!system_bundle) {
		syslog(LOG_ERR,
		    "kldmgr: refusing kmod_requires for non-system "
		    "bundle service '%s'", m->label);
		return (-1);
	}

	for (i = 0; i < m->nkmod_requires; i++) {
		const char *name = m->kmod_requires[i];

		if (authority_ensure_kmod(sd.authority_channel_fd, name) == -1) {
			syslog(LOG_ERR, "kldmgr: failed to load %s: %m",
			    name);
			return (-1);
		}

		syslog(LOG_INFO, "kldmgr: ensured module %s", name);
	}

	return (0);
}
