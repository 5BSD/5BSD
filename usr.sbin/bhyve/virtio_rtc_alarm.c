/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <dev/virtio/rtc/virtio_rtc.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_rtc_alarm.h"
#include "virtio_state_range.h"

#define	VTRTCA_STATE_MAGIC	0x31414c41U	/* "ALA1" */
#define	VTRTCA_STATE_VERSION	1U
#define	VTRTCA_STATE_SIZE	40U
#define	VTRTCA_DIGEST_OFFSET	32U

struct virtio_rtc_alarm {
	pthread_mutex_t mutex;
	uint64_t alarm_time;
	uint64_t last_reading;
	bool enabled;
	bool pending;
	bool have_reading;
};

static uint64_t
vtrtca_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VTRTCA_DIGEST_OFFSET &&
		    i < VTRTCA_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static void
vtrtca_observe_locked(struct virtio_rtc_alarm *alarm, uint64_t reading)
{

	if (alarm->enabled) {
		if ((!alarm->have_reading && reading >= alarm->alarm_time) ||
		    (alarm->have_reading &&
		    alarm->last_reading < alarm->alarm_time &&
		    reading >= alarm->alarm_time))
			alarm->pending = true;
	}
	alarm->last_reading = reading;
	alarm->have_reading = true;
}

int
virtio_rtc_alarm_create(struct virtio_rtc_alarm **result)
{
	struct virtio_rtc_alarm *alarm;

	if (result == NULL)
		return (EINVAL);
	alarm = calloc(1, sizeof(*alarm));
	if (alarm == NULL)
		return (ENOMEM);
	if (pthread_mutex_init(&alarm->mutex, NULL) != 0) {
		free(alarm);
		return (ENOMEM);
	}
	*result = alarm;
	return (0);
}

void
virtio_rtc_alarm_destroy(struct virtio_rtc_alarm *alarm)
{

	if (alarm == NULL)
		return;
	pthread_mutex_destroy(&alarm->mutex);
	free(alarm);
}

int
virtio_rtc_alarm_read(struct virtio_rtc_alarm *alarm, uint64_t *alarm_time,
    bool *enabled)
{

	if (alarm == NULL || alarm_time == NULL || enabled == NULL)
		return (EINVAL);
	pthread_mutex_lock(&alarm->mutex);
	*alarm_time = alarm->alarm_time;
	*enabled = alarm->enabled;
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_set(struct virtio_rtc_alarm *alarm, uint64_t alarm_time,
    bool enabled, uint64_t reading)
{

	if (alarm == NULL)
		return (EINVAL);
	pthread_mutex_lock(&alarm->mutex);
	alarm->alarm_time = alarm_time;
	alarm->enabled = enabled;
	alarm->pending = enabled && reading >= alarm_time;
	alarm->last_reading = reading;
	alarm->have_reading = true;
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_set_enabled(struct virtio_rtc_alarm *alarm, bool enabled,
    uint64_t reading)
{

	if (alarm == NULL)
		return (EINVAL);
	pthread_mutex_lock(&alarm->mutex);
	alarm->enabled = enabled;
	if (!enabled)
		alarm->pending = false;
	else {
		alarm->pending = reading >= alarm->alarm_time;
		alarm->last_reading = reading;
		alarm->have_reading = true;
	}
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_observe(struct virtio_rtc_alarm *alarm, uint64_t reading)
{

	if (alarm == NULL)
		return (EINVAL);
	pthread_mutex_lock(&alarm->mutex);
	vtrtca_observe_locked(alarm, reading);
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

bool
virtio_rtc_alarm_pending(struct virtio_rtc_alarm *alarm)
{
	bool pending;

	if (alarm == NULL)
		return (false);
	pthread_mutex_lock(&alarm->mutex);
	pending = alarm->pending;
	pthread_mutex_unlock(&alarm->mutex);
	return (pending);
}

bool
virtio_rtc_alarm_owns_range(struct virtio_rtc_alarm *alarm,
    const void *range, size_t length)
{

	if (alarm == NULL)
		return (false);
	return (virtio_state_ranges_overlap(range, length, alarm,
	    sizeof(*alarm)));
}

int
virtio_rtc_alarm_notify(struct virtio_rtc_alarm *alarm, void *output,
    size_t capacity, size_t *written)
{
	uint8_t *bytes;

	if (alarm == NULL || output == NULL || written == NULL)
		return (EINVAL);
	/*
	 * Treat notification publication as a disjoint multi-output
	 * transaction.  In particular, never clear the live object (and its
	 * mutex) through an aliased guest/output buffer while that mutex is
	 * held.  Rejection precedes both the length store and pending-state
	 * consumption so a corrected caller can retry the notification.
	 */
	if (virtio_rtc_alarm_owns_range(alarm, output, capacity) ||
	    virtio_rtc_alarm_owns_range(alarm, written, sizeof(*written)) ||
	    virtio_state_ranges_overlap(output, capacity, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	pthread_mutex_lock(&alarm->mutex);
	if (!alarm->pending) {
		pthread_mutex_unlock(&alarm->mutex);
		return (EAGAIN);
	}
	if (capacity < BHYVE_VIRTIO_RTC_ALARM_NOTIFICATION_SIZE) {
		pthread_mutex_unlock(&alarm->mutex);
		return (EMSGSIZE);
	}
	bytes = output;
	memset(bytes, 0, BHYVE_VIRTIO_RTC_ALARM_NOTIFICATION_SIZE);
	le16enc(bytes, VIRTIO_RTC_NOTIF_ALARM);
	/* The sole supported clock has clock_id zero. */
	le16enc(bytes + 8, 0);
	alarm->pending = false;
	*written = BHYVE_VIRTIO_RTC_ALARM_NOTIFICATION_SIZE;
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_reset(struct virtio_rtc_alarm *alarm)
{

	if (alarm == NULL)
		return (EINVAL);
	pthread_mutex_lock(&alarm->mutex);
	alarm->alarm_time = 0;
	alarm->last_reading = 0;
	alarm->enabled = false;
	alarm->pending = false;
	alarm->have_reading = false;
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_snapshot(struct virtio_rtc_alarm *alarm, void *buffer,
    size_t length)
{
	uint8_t *bytes;

	if (alarm == NULL || buffer == NULL)
		return (EINVAL);
	if (length != VTRTCA_STATE_SIZE)
		return (EMSGSIZE);
	if (virtio_state_ranges_overlap(buffer, length, alarm,
	    sizeof(*alarm)))
		return (EINVAL);
	bytes = buffer;
	pthread_mutex_lock(&alarm->mutex);
	memset(bytes, 0, length);
	le32enc(bytes + 0, VTRTCA_STATE_MAGIC);
	le16enc(bytes + 4, VTRTCA_STATE_VERSION);
	le16enc(bytes + 6, VTRTCA_STATE_SIZE);
	le64enc(bytes + 8, alarm->alarm_time);
	le64enc(bytes + 16, alarm->last_reading);
	bytes[24] = alarm->enabled;
	bytes[25] = alarm->pending;
	bytes[26] = alarm->have_reading;
	le64enc(bytes + VTRTCA_DIGEST_OFFSET, vtrtca_digest(bytes, length));
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}

int
virtio_rtc_alarm_restore_validate(const void *buffer, size_t length)
{
	const uint8_t *bytes;

	if (buffer == NULL)
		return (EINVAL);
	bytes = buffer;
	if (length != VTRTCA_STATE_SIZE ||
	    le32dec(bytes + 0) != VTRTCA_STATE_MAGIC ||
	    le16dec(bytes + 4) != VTRTCA_STATE_VERSION ||
	    le16dec(bytes + 6) != VTRTCA_STATE_SIZE ||
	    bytes[24] > 1 || bytes[25] > 1 || bytes[26] > 1 ||
	    (bytes[25] != 0 && bytes[24] == 0) ||
	    (bytes[26] == 0 &&
	    (bytes[24] != 0 || bytes[25] != 0 ||
	    le64dec(bytes + 16) != 0)) ||
	    bytes[27] != 0 || bytes[28] != 0 || bytes[29] != 0 ||
	    bytes[30] != 0 || bytes[31] != 0 ||
	    le64dec(bytes + VTRTCA_DIGEST_OFFSET) !=
	    vtrtca_digest(bytes, length))
		return (EPROTO);
	return (0);
}

int
virtio_rtc_alarm_restore(struct virtio_rtc_alarm *alarm, const void *buffer,
    size_t length, uint64_t current_reading)
{
	const uint8_t *bytes;
	int error;

	if (alarm == NULL)
		return (EINVAL);
	if (virtio_state_ranges_overlap(buffer, length, alarm,
	    sizeof(*alarm)))
		return (EINVAL);
	error = virtio_rtc_alarm_restore_validate(buffer, length);
	if (error != 0)
		return (error);
	bytes = buffer;
	pthread_mutex_lock(&alarm->mutex);
	alarm->alarm_time = le64dec(bytes + 8);
	alarm->last_reading = le64dec(bytes + 16);
	alarm->enabled = bytes[24] != 0;
	alarm->pending = bytes[25] != 0;
	alarm->have_reading = bytes[26] != 0;
	vtrtca_observe_locked(alarm, current_reading);
	pthread_mutex_unlock(&alarm->mutex);
	return (0);
}
