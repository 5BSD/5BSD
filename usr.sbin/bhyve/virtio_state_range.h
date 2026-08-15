/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_STATE_RANGE_H_
#define	_BHYVE_VIRTIO_STATE_RANGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Portable-state encoders must not overwrite the object graph they are
 * serializing.  Treat a wrapping extent as overlapping so a malformed caller
 * is rejected before either range is dereferenced.
 */
static inline bool
virtio_state_ranges_overlap(const void *first, size_t first_length,
    const void *second, size_t second_length)
{
	uintptr_t first_start, second_start;

	if (first_length == 0 || second_length == 0)
		return (false);
	/* A non-empty null extent is not a usable range.  Fail closed. */
	if (first == NULL || second == NULL)
		return (true);
	first_start = (uintptr_t)first;
	second_start = (uintptr_t)second;
	if (first_start > UINTPTR_MAX - (first_length - 1) ||
	    second_start > UINTPTR_MAX - (second_length - 1))
		return (true);
	return (first_start <= second_start + second_length - 1 &&
	    second_start <= first_start + first_length - 1);
}

#endif /* !_BHYVE_VIRTIO_STATE_RANGE_H_ */
