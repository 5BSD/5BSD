/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SWITCHBOARD_MANIFEST_COMPARE_H
#define SWITCHBOARD_MANIFEST_COMPARE_H

#include <stdbool.h>

#include "switchboard_manifest.h"

bool	switchboard_manifest_equal(const struct svc_manifest *,
	    const struct svc_manifest *);

#endif /* SWITCHBOARD_MANIFEST_COMPARE_H */
