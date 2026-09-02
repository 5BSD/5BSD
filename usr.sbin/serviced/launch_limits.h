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

#define	SVC_LAUNCH_MAX_TOKENS	1	/* the single combined system token */

static inline bool
svc_launch_counts_valid(const struct svc_manifest *m __unused)
{

	return (true);
}

static inline unsigned
svc_launch_token_count(const struct svc_manifest *m)
{

	return (m->cap_system != 0 ? 1u : 0u);
}

#endif /* SERVICED_LAUNCH_LIMITS_H */
