/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_BALLOON_VIRTIO_BALLOON_VAR_H_
#define _DEV_VIRTIO_BALLOON_VIRTIO_BALLOON_VAR_H_

#include <sys/errno.h>
#include <sys/limits.h>
#include <sys/types.h>

static inline int
virtio_balloon_encode_pfn(uint64_t paddr, uint32_t units_per_page,
    uint32_t *pfn)
{
	uint64_t first;

	if (pfn == NULL || units_per_page == 0 ||
	    (paddr & ((UINT64_C(1) << 12) - 1)) != 0)
		return (EINVAL);
	first = paddr >> 12;
	if (first > UINT32_MAX || units_per_page - 1 > UINT32_MAX - first)
		return (ERANGE);
	*pfn = (uint32_t)first;
	return (0);
}

static inline uint32_t
virtio_balloon_align_target(uint32_t target, uint32_t units_per_page)
{
	uint32_t maximum;

	if (units_per_page == 0)
		return (0);
	maximum = UINT32_MAX - UINT32_MAX % units_per_page;
	if (target > maximum - (units_per_page - 1))
		return (maximum);
	return (((target + units_per_page - 1) / units_per_page) *
	    units_per_page);
}

static inline int
virtio_balloon_request_result(bool completed, bool expected_cookie,
    int wait_error)
{

	if (completed)
		return (expected_cookie ? 0 : EPROTO);
	if (wait_error == EWOULDBLOCK)
		return (ETIMEDOUT);
	if (wait_error != 0)
		return (wait_error);
	return (EIO);
}

static inline uint32_t
virtio_balloon_lowmem_target(uint32_t current, uint32_t request_limit)
{

	if (request_limit == 0 || current <= request_limit)
		return (0);
	return (current - request_limit);
}

#endif /* _DEV_VIRTIO_BALLOON_VIRTIO_BALLOON_VAR_H_ */
