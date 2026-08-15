/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/types.h>

#include <dev/virtio/rtc/virtio_rtc.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_rtc_host.h"
#include "virtio_rtc_alarm.h"
#include "virtio_state_range.h"

static bool
virtio_rtc_zeros(const uint8_t *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (bytes[i] != 0)
			return (false);
	}
	return (true);
}

static size_t
virtio_rtc_status(void *response, size_t response_capacity, uint8_t status)
{
	struct virtio_rtc_resp_head head;
	size_t written;

	if (response_capacity == 0)
		return (0);
	memset(&head, 0, sizeof(head));
	head.status = status;
	written = MIN(response_capacity, sizeof(head));
	memcpy(response, &head, written);
	return (written);
}

static bool
virtio_rtc_counter_known(uint8_t counter)
{

	return (counter == VIRTIO_RTC_COUNTER_ARM_VCT ||
	    counter == VIRTIO_RTC_COUNTER_X86_TSC);
}

int
virtio_rtc_process_request(const void *request, size_t request_len,
    void *response, size_t response_capacity,
    virtio_rtc_read_clock_cb read_clock, void *clock_arg, size_t *written)
{

	return (virtio_rtc_process_request_alarm(request, request_len, response,
	    response_capacity, read_clock, clock_arg, NULL, false, written));
}

int
virtio_rtc_process_request_alarm(const void *request, size_t request_len,
    void *response, size_t response_capacity,
    virtio_rtc_read_clock_cb read_clock, void *clock_arg,
    struct virtio_rtc_alarm *alarm, bool alarm_negotiated, size_t *written)
{
	struct virtio_rtc_resp_clock_cap clock_cap;
	struct virtio_rtc_resp_cross_cap cross_cap;
	struct virtio_rtc_resp_cfg cfg;
	struct virtio_rtc_resp_read read_resp;
	struct virtio_rtc_resp_read_alarm read_alarm_resp;
	const struct virtio_rtc_req_clock_cap *clock_req;
	const struct virtio_rtc_req_cross_cap *cross_req;
	const struct virtio_rtc_req_head *head;
	const struct virtio_rtc_req_read *read_req;
	const struct virtio_rtc_req_read_alarm *read_alarm_req;
	const struct virtio_rtc_req_set_alarm *set_alarm_req;
	const struct virtio_rtc_req_set_alarm_enabled *set_enabled_req;
	const uint8_t *bytes;
	uint64_t alarm_time, reading;
	uint16_t clock_id, msg_type;
	size_t expected_request, expected_response;
	uint8_t flags, status;
	bool alarm_enabled;
	int error;

	if (written == NULL || (request == NULL && request_len != 0) ||
	    (response == NULL && response_capacity != 0) ||
	    read_clock == NULL || (alarm_negotiated && alarm == NULL))
		return (EINVAL);
	/*
	 * Decode and publication storage belongs to the caller, while the alarm
	 * object and length word are separate owners.  Reject aliases before the
	 * first length store or alarm transition.  This keeps malformed direct
	 * callers from overwriting a live mutex or changing the request while it
	 * is still being decoded, and leaves every rejected request retryable.
	 */
	if (virtio_state_ranges_overlap(written, sizeof(*written), request,
	    request_len) ||
	    virtio_state_ranges_overlap(written, sizeof(*written), response,
	    response_capacity) ||
	    virtio_state_ranges_overlap(request, request_len, response,
	    response_capacity) ||
	    (alarm != NULL &&
	    (virtio_rtc_alarm_owns_range(alarm, request, request_len) ||
	    virtio_rtc_alarm_owns_range(alarm, response, response_capacity) ||
	    virtio_rtc_alarm_owns_range(alarm, written, sizeof(*written)))))
		return (EINVAL);
	*written = 0;
	if (request_len < sizeof(*head)) {
		*written = virtio_rtc_status(response, response_capacity,
		    VIRTIO_RTC_S_EINVAL);
		return (0);
	}
	head = request;
	msg_type = le16toh(head->msg_type);
	status = VIRTIO_RTC_S_OK;
	expected_request = sizeof(*head);
	expected_response = sizeof(struct virtio_rtc_resp_head);

	switch (msg_type) {
	case VIRTIO_RTC_REQ_CFG:
		expected_response = sizeof(cfg);
		break;
	case VIRTIO_RTC_REQ_CLOCK_CAP:
		expected_request = sizeof(*clock_req);
		expected_response = sizeof(clock_cap);
		break;
	case VIRTIO_RTC_REQ_CROSS_CAP:
		expected_request = sizeof(*cross_req);
		expected_response = sizeof(cross_cap);
		break;
	case VIRTIO_RTC_REQ_READ:
		expected_request = sizeof(*read_req);
		expected_response = sizeof(read_resp);
		break;
	case VIRTIO_RTC_REQ_READ_CROSS:
		status = VIRTIO_RTC_S_EOPNOTSUPP;
		break;
	case VIRTIO_RTC_REQ_READ_ALARM:
		if (!alarm_negotiated) {
			status = VIRTIO_RTC_S_ENODEV;
			break;
		}
		expected_request = sizeof(*read_alarm_req);
		expected_response = sizeof(read_alarm_resp);
		break;
	case VIRTIO_RTC_REQ_SET_ALARM:
		if (!alarm_negotiated) {
			status = VIRTIO_RTC_S_ENODEV;
			break;
		}
		expected_request = sizeof(*set_alarm_req);
		break;
	case VIRTIO_RTC_REQ_SET_ALARM_ENABLED:
		if (!alarm_negotiated) {
			/*
			 * Section 5.23.6.6.2.2 requires ENODEV, rather than
			 * the generic unsupported-operation status.
			 */
			status = VIRTIO_RTC_S_ENODEV;
			break;
		}
		expected_request = sizeof(*set_enabled_req);
		break;
	default:
		status = VIRTIO_RTC_S_EOPNOTSUPP;
		break;
	}
	if (status == VIRTIO_RTC_S_OK && request_len < expected_request)
		status = VIRTIO_RTC_S_EINVAL;
	bytes = request;
	if (status == VIRTIO_RTC_S_OK) {
		/*
		 * Preserve the status precedence in section 5.23.6.2:
		 * unknown counters first, then nonexistent clocks, then
		 * otherwise-invalid request values and response sizing.
		 */
		switch (msg_type) {
		case VIRTIO_RTC_REQ_CFG:
			break;
		case VIRTIO_RTC_REQ_CLOCK_CAP:
			clock_req = request;
			clock_id = le16toh(clock_req->clock_id);
			if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if (!virtio_rtc_zeros(bytes +
			    sizeof(clock_req->head) +
			    sizeof(clock_req->clock_id),
			    sizeof(clock_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		case VIRTIO_RTC_REQ_CROSS_CAP:
			cross_req = request;
			clock_id = le16toh(cross_req->clock_id);
			if (!virtio_rtc_counter_known(cross_req->hw_counter))
				status = VIRTIO_RTC_S_EOPNOTSUPP;
			else if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if (!virtio_rtc_zeros(bytes +
			    sizeof(cross_req->head) +
			    sizeof(cross_req->clock_id) +
			    sizeof(cross_req->hw_counter),
			    sizeof(cross_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		case VIRTIO_RTC_REQ_READ:
			read_req = request;
			clock_id = le16toh(read_req->clock_id);
			if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if (!virtio_rtc_zeros(bytes +
			    sizeof(read_req->head) +
			    sizeof(read_req->clock_id),
			    sizeof(read_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		case VIRTIO_RTC_REQ_READ_ALARM:
			read_alarm_req = request;
			clock_id = le16toh(read_alarm_req->clock_id);
			if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if (!virtio_rtc_zeros(read_alarm_req->reserved,
			    sizeof(read_alarm_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		case VIRTIO_RTC_REQ_SET_ALARM:
			set_alarm_req = request;
			clock_id = le16toh(set_alarm_req->clock_id);
			if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if ((set_alarm_req->flags &
			    ~VIRTIO_RTC_FLAG_ALARM_ENABLED) != 0 ||
			    !virtio_rtc_zeros(set_alarm_req->reserved,
			    sizeof(set_alarm_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		case VIRTIO_RTC_REQ_SET_ALARM_ENABLED:
			set_enabled_req = request;
			clock_id = le16toh(set_enabled_req->clock_id);
			if (clock_id != 0)
				status = VIRTIO_RTC_S_ENODEV;
			else if ((set_enabled_req->flags &
			    ~VIRTIO_RTC_FLAG_ALARM_ENABLED) != 0 ||
			    !virtio_rtc_zeros(set_enabled_req->reserved,
			    sizeof(set_enabled_req->reserved)))
				status = VIRTIO_RTC_S_EINVAL;
			break;
		default:
			break;
		}
	}
	if (status == VIRTIO_RTC_S_OK &&
	    !virtio_rtc_zeros(head->reserved, sizeof(head->reserved)))
		status = VIRTIO_RTC_S_EINVAL;
	if (status == VIRTIO_RTC_S_OK &&
	    response_capacity < expected_response)
		status = VIRTIO_RTC_S_EINVAL;
	if (status != VIRTIO_RTC_S_OK) {
		*written = virtio_rtc_status(response, response_capacity, status);
		return (0);
	}

	switch (msg_type) {
	case VIRTIO_RTC_REQ_CFG:
		memset(&cfg, 0, sizeof(cfg));
		cfg.num_clocks = htole16(1);
		memcpy(response, &cfg, sizeof(cfg));
		*written = sizeof(cfg);
		break;
	case VIRTIO_RTC_REQ_CLOCK_CAP:
		memset(&clock_cap, 0, sizeof(clock_cap));
		/*
		 * CLOCK_REALTIME may either step at a leap second or be
		 * disciplined with a smear by host policy.  Advertise that
		 * uncertainty instead of promising unsmeared UTC.
		 */
		clock_cap.type = VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED;
		clock_cap.leap_second_smearing =
		    VIRTIO_RTC_SMEAR_UNSPECIFIED;
		if (alarm_negotiated)
			clock_cap.flags |= VIRTIO_RTC_FLAG_ALARM_CAP;
		memcpy(response, &clock_cap, sizeof(clock_cap));
		*written = sizeof(clock_cap);
		break;
	case VIRTIO_RTC_REQ_CROSS_CAP:
		memset(&cross_cap, 0, sizeof(cross_cap));
		memcpy(response, &cross_cap, sizeof(cross_cap));
		*written = sizeof(cross_cap);
		break;
	case VIRTIO_RTC_REQ_READ:
		memset(&read_resp, 0, sizeof(read_resp));
		error = read_clock(clock_arg, &reading);
		if (error == 0) {
			read_resp.clock_reading = htole64(reading);
			memcpy(response, &read_resp, sizeof(read_resp));
			*written = sizeof(read_resp);
			break;
		}
		status = VIRTIO_RTC_S_EIO;
		*written = virtio_rtc_status(response, response_capacity,
		    status);
		break;
	case VIRTIO_RTC_REQ_READ_ALARM:
		memset(&read_alarm_resp, 0, sizeof(read_alarm_resp));
		error = virtio_rtc_alarm_read(alarm, &alarm_time,
		    &alarm_enabled);
		if (error != 0)
			return (error);
		read_alarm_resp.alarm_time = htole64(alarm_time);
		if (alarm_enabled)
			read_alarm_resp.flags |=
			    VIRTIO_RTC_FLAG_ALARM_ENABLED;
		memcpy(response, &read_alarm_resp, sizeof(read_alarm_resp));
		*written = sizeof(read_alarm_resp);
		break;
	case VIRTIO_RTC_REQ_SET_ALARM:
		set_alarm_req = request;
		error = read_clock(clock_arg, &reading);
		if (error == 0)
			error = virtio_rtc_alarm_set(alarm,
			    le64toh(set_alarm_req->alarm_time),
			    (set_alarm_req->flags &
			    VIRTIO_RTC_FLAG_ALARM_ENABLED) != 0, reading);
		if (error != 0) {
			*written = virtio_rtc_status(response,
			    response_capacity, VIRTIO_RTC_S_EIO);
			break;
		}
		*written = virtio_rtc_status(response, response_capacity,
		    VIRTIO_RTC_S_OK);
		break;
	case VIRTIO_RTC_REQ_SET_ALARM_ENABLED:
		set_enabled_req = request;
		flags = set_enabled_req->flags;
		error = read_clock(clock_arg, &reading);
		if (error == 0)
			error = virtio_rtc_alarm_set_enabled(alarm,
			    (flags & VIRTIO_RTC_FLAG_ALARM_ENABLED) != 0,
			    reading);
		if (error != 0) {
			*written = virtio_rtc_status(response,
			    response_capacity, VIRTIO_RTC_S_EIO);
			break;
		}
		*written = virtio_rtc_status(response, response_capacity,
		    VIRTIO_RTC_S_OK);
		break;
	default:
		/* The unsupported cases returned above. */
		return (EINVAL);
	}
	return (0);
}
