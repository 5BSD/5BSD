/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SERVICED_BUNDLE_SELECTION_H
#define SERVICED_BUNDLE_SELECTION_H

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

enum bundle_selection_result {
	BUNDLE_SELECTION_DISTINCT = 0,
	BUNDLE_SELECTION_KEEP_CURRENT,
	BUNDLE_SELECTION_REPLACE_CURRENT,
	BUNDLE_SELECTION_ORIGIN_CONFLICT,
	BUNDLE_SELECTION_SEQUENCE_CONFLICT,
	BUNDLE_SELECTION_INVALID
};

enum bundle_selection_result bundle_selection_compare(const char *, uint64_t,
	    bool, const char *, uint64_t, bool);

#endif
