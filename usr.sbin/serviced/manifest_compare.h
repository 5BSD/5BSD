/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SERVICED_MANIFEST_COMPARE_H
#define SERVICED_MANIFEST_COMPARE_H

#include <stdbool.h>

#include "serviced_manifest.h"

bool	serviced_manifest_equal(const struct svc_manifest *,
	    const struct svc_manifest *);

#endif /* SERVICED_MANIFEST_COMPARE_H */
