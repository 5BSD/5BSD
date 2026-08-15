/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_RANDOM_VIRTIO_RANDOM_VAR_H_
#define _DEV_VIRTIO_RANDOM_VIRTIO_RANDOM_VAR_H_

#include <sys/types.h>

static inline bool
virtio_random_used_len_valid(uint32_t used_len, size_t buffer_len)
{

	return ((size_t)used_len <= buffer_len);
}

#endif /* _DEV_VIRTIO_RANDOM_VIRTIO_RANDOM_VAR_H_ */
