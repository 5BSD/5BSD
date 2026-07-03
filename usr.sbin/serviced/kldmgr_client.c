/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Client for kldmgrd -- ensures required kernel modules are loaded
 * before a service is launched.
 *
 * Uses modfind() to skip already-loaded modules, then kldload() for
 * any that need loading.  serviced runs as root so kldload() works
 * directly; if it ever runs capability-mode the call will need to
 * go through kldmgrd via the naming system instead.
 */

#include <sys/types.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "serviced.h"

/*
 * Ensure all kernel modules required by manifest m are loaded.
 * Uses modfind() to skip already-loaded modules, then kldload()
 * for any that need loading.
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

		/* Check if the module is already loaded. */
		if (modfind(name) != -1) {
			syslog(LOG_DEBUG, "kldmgr: %s already loaded", name);
			continue;
		}

		/*
		 * Module not loaded -- try kldload() directly.
		 * serviced runs as root, so this should succeed
		 * unless the module does not exist on disk.
		 */
		if (kldload(name) == -1) {
			syslog(LOG_ERR, "kldmgr: failed to load %s: %m",
			    name);
			return (-1);
		}

		syslog(LOG_INFO, "kldmgr: loaded module %s", name);
	}

	return (0);
}
