/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "bundle_selection.h"

enum bundle_selection_result
bundle_selection_compare(const char *current_id, uint64_t current_sequence,
    bool current_system, const char *candidate_id, uint64_t candidate_sequence,
    bool candidate_system)
{

	if (current_id == NULL || candidate_id == NULL || current_id[0] == '\0' ||
	    candidate_id[0] == '\0' || current_sequence == 0 ||
	    candidate_sequence == 0)
		return (BUNDLE_SELECTION_INVALID);
	if (strcmp(current_id, candidate_id) != 0)
		return (BUNDLE_SELECTION_DISTINCT);
	if (current_system != candidate_system)
		return (BUNDLE_SELECTION_ORIGIN_CONFLICT);
	if (current_sequence == candidate_sequence)
		return (BUNDLE_SELECTION_SEQUENCE_CONFLICT);
	if (candidate_sequence < current_sequence)
		return (BUNDLE_SELECTION_KEEP_CURRENT);
	return (BUNDLE_SELECTION_REPLACE_CURRENT);
}
