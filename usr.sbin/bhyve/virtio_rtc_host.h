/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_RTC_HOST_H_
#define	_BHYVE_VIRTIO_RTC_HOST_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_RTC_MAX_REQUEST	24
#define	BHYVE_VIRTIO_RTC_MAX_RESPONSE	24

typedef int (*virtio_rtc_read_clock_cb)(void *, uint64_t *);

struct virtio_rtc_alarm;

int	virtio_rtc_process_request(const void *, size_t, void *, size_t,
	    virtio_rtc_read_clock_cb, void *, size_t *);
int	virtio_rtc_process_request_alarm(const void *, size_t, void *, size_t,
	    virtio_rtc_read_clock_cb, void *, struct virtio_rtc_alarm *, bool,
	    size_t *);

#endif
