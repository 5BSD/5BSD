/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SERVICED_LAUNCH_LIMITS_H
#define SERVICED_LAUNCH_LIMITS_H

#include <stdbool.h>

#include <service_bootstrap.h>

#include "serviced_manifest.h"

#define	SVC_LAUNCH_MAX_TOKENS	(SERVICED_MAX_CAP_PATHS + \
	SERVICED_MAX_CAP_NET + \
	SERVICED_MAX_CAP_VSOCK + 1)
/* Storage is not a delivered descriptor: consumers self-mint via tzfsd. */
#define	SVC_LAUNCH_MAX_NAMED_FDS	(SERVICED_MAX_CAP_SERVICES)

static inline bool
svc_launch_counts_valid(const struct svc_manifest *m)
{

	return (m->ncap_paths <= SERVICED_MAX_CAP_PATHS &&
	    m->ncap_net <= SERVICED_MAX_CAP_NET &&
	    m->ncap_vsock <= SERVICED_MAX_CAP_VSOCK &&
	    m->ncap_services <= SERVICED_MAX_CAP_SERVICES &&
	    m->ncap_services <= SERVICE_BOOTSTRAP_CAPABILITY_MAX);
}

static inline unsigned
svc_launch_token_count(const struct svc_manifest *m)
{

	return (m->ncap_paths + m->ncap_net +
	    m->ncap_vsock +
	    (m->cap_system != 0 ? 1u : 0u));
}

static inline unsigned
svc_launch_named_fd_count(const struct svc_manifest *m)
{

	return (m->ncap_services);
}

#endif /* SERVICED_LAUNCH_LIMITS_H */
