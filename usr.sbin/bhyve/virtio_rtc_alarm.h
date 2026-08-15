/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_RTC_ALARM_H_
#define	_BHYVE_VIRTIO_RTC_ALARM_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_RTC_ALARM_NOTIFICATION_SIZE	16U

struct virtio_rtc_alarm;

int	virtio_rtc_alarm_create(struct virtio_rtc_alarm **);
void	virtio_rtc_alarm_destroy(struct virtio_rtc_alarm *);
int	virtio_rtc_alarm_read(struct virtio_rtc_alarm *, uint64_t *, bool *);
int	virtio_rtc_alarm_set(struct virtio_rtc_alarm *, uint64_t, bool,
	    uint64_t);
int	virtio_rtc_alarm_set_enabled(struct virtio_rtc_alarm *, bool,
	    uint64_t);
int	virtio_rtc_alarm_observe(struct virtio_rtc_alarm *, uint64_t);
bool	virtio_rtc_alarm_pending(struct virtio_rtc_alarm *);
bool	virtio_rtc_alarm_owns_range(struct virtio_rtc_alarm *, const void *,
	    size_t);
int	virtio_rtc_alarm_notify(struct virtio_rtc_alarm *, void *, size_t,
	    size_t *);
int	virtio_rtc_alarm_reset(struct virtio_rtc_alarm *);
int	virtio_rtc_alarm_snapshot(struct virtio_rtc_alarm *, void *, size_t);
int	virtio_rtc_alarm_restore_validate(const void *, size_t);
int	virtio_rtc_alarm_restore(struct virtio_rtc_alarm *, const void *,
	    size_t, uint64_t);

#endif
