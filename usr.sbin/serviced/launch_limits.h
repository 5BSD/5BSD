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
	SERVICED_MAX_CAP_NET + 1)

static inline bool
svc_launch_counts_valid(const struct svc_manifest *m)
{

	return (m->ncap_paths <= SERVICED_MAX_CAP_PATHS &&
	    m->ncap_net <= SERVICED_MAX_CAP_NET);
}

static inline unsigned
svc_launch_token_count(const struct svc_manifest *m)
{

	return (m->ncap_paths + m->ncap_net +
	    (m->cap_system != 0 ? 1u : 0u));
}

#endif /* SERVICED_LAUNCH_LIMITS_H */
