/*
 * Independent VirtIO 1.4 section 5.23.6.6 RTC alarm-state tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_rtc_alarm.c"
#include "virtio_rtc_host.c"

#include "virtio_1_4_spec.h"

#define	DOC_NOTIF_ALARM	0x2000U

static int
fixed_clock(void *arg, uint64_t *reading)
{

	*reading = *(const uint64_t *)arg;
	return (0);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK(sizeof(struct virtio_rtc_req_read_alarm) ==
	    VIRTIO14_RTC_REQ_READ_ALARM_SIZE);
	ATF_CHECK(sizeof(struct virtio_rtc_resp_read_alarm) ==
	    VIRTIO14_RTC_RESP_READ_ALARM_SIZE);
	ATF_CHECK(sizeof(struct virtio_rtc_req_set_alarm) ==
	    VIRTIO14_RTC_REQ_SET_ALARM_SIZE);
	ATF_CHECK(sizeof(struct virtio_rtc_req_set_alarm_enabled) ==
	    VIRTIO14_RTC_REQ_SET_ALARM_ENABLED_SIZE);
	ATF_CHECK(sizeof(struct virtio_rtc_notif_head) ==
	    VIRTIO14_RTC_NOTIF_HEAD_SIZE);
	ATF_CHECK(sizeof(struct virtio_rtc_notif_alarm) ==
	    VIRTIO14_RTC_NOTIF_ALARM_SIZE);
	ATF_CHECK((VIRTIO_RTC_NOTIF_ALARM) == (VIRTIO14_RTC_NOTIF_ALARM));
}

ATF_TC_WITHOUT_HEAD(expiration_and_notification);
ATF_TC_BODY(expiration_and_notification, tc)
{
	struct virtio_rtc_alarm *alarm;
	uint8_t notification[16];
	size_t written;

	ATF_REQUIRE((virtio_rtc_alarm_create(&alarm)) == (0));
	ATF_REQUIRE((virtio_rtc_alarm_set(alarm, 100, true, 90)) == (0));
	ATF_CHECK(!virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_observe(alarm, 100)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_CHECK(virtio_rtc_alarm_notify(alarm, notification, 15,
	    &written) == EMSGSIZE);
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), &written) == 0);
	ATF_CHECK((written) == (sizeof(notification)));
	ATF_CHECK((le16dec(notification)) == (DOC_NOTIF_ALARM));
	ATF_CHECK((le16dec(notification + 8)) == (0));
	for (size_t i = 2; i < sizeof(notification); i++) {
		if (i == 8 || i == 9)
			continue;
		ATF_CHECK((notification[i]) == (0));
	}
	ATF_CHECK(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), &written) == EAGAIN);
	virtio_rtc_alarm_destroy(alarm);
}

ATF_TC_WITHOUT_HEAD(control_protocol);
ATF_TC_BODY(control_protocol, tc)
{
	struct virtio_rtc_alarm *alarm;
	struct virtio_rtc_req_clock_cap cap_req;
	struct virtio_rtc_req_read_alarm read_req;
	struct virtio_rtc_req_set_alarm set_req;
	struct virtio_rtc_req_set_alarm_enabled enabled_req;
	struct virtio_rtc_resp_clock_cap cap_resp;
	struct virtio_rtc_resp_read_alarm read_resp;
	uint8_t status[8];
	uint64_t now;
	size_t written;

	now = 100;
	ATF_REQUIRE(virtio_rtc_alarm_create(&alarm) == 0);
	memset(&cap_req, 0, sizeof(cap_req));
	cap_req.head.msg_type = htole16(VIRTIO14_RTC_REQ_CLOCK_CAP);
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&cap_req,
	    sizeof(cap_req), &cap_resp, sizeof(cap_resp), fixed_clock, &now,
	    alarm, true, &written) == 0);
	ATF_CHECK(written == sizeof(cap_resp));
	ATF_CHECK((cap_resp.flags & VIRTIO_RTC_FLAG_ALARM_CAP) != 0);

	memset(&set_req, 0, sizeof(set_req));
	set_req.head.msg_type = htole16(VIRTIO14_RTC_REQ_SET_ALARM);
	set_req.alarm_time = htole64(150);
	set_req.flags = VIRTIO14_RTC_FLAG_ALARM_ENABLED;
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&set_req,
	    sizeof(set_req), status, sizeof(status), fixed_clock, &now, alarm,
	    true, &written) == 0);
	ATF_CHECK(written == sizeof(status));
	ATF_CHECK(status[0] == VIRTIO14_RTC_STATUS_OK);

	memset(&read_req, 0, sizeof(read_req));
	read_req.head.msg_type = htole16(VIRTIO14_RTC_REQ_READ_ALARM);
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&read_req,
	    sizeof(read_req), &read_resp, sizeof(read_resp), fixed_clock, &now,
	    alarm, true, &written) == 0);
	ATF_CHECK(written == sizeof(read_resp));
	ATF_CHECK(le64toh(read_resp.alarm_time) == 150);
	ATF_CHECK((read_resp.flags & VIRTIO_RTC_FLAG_ALARM_ENABLED) != 0);

	memset(&enabled_req, 0, sizeof(enabled_req));
	enabled_req.head.msg_type =
	    htole16(VIRTIO14_RTC_REQ_SET_ALARM_ENABLED);
	now = 200;
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&enabled_req,
	    sizeof(enabled_req), status, sizeof(status), fixed_clock, &now,
	    alarm, true, &written) == 0);
	ATF_CHECK(status[0] == VIRTIO14_RTC_STATUS_OK);
	ATF_CHECK(!virtio_rtc_alarm_pending(alarm));

	enabled_req.flags = VIRTIO14_RTC_FLAG_ALARM_ENABLED;
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&enabled_req,
	    sizeof(enabled_req), status, sizeof(status), fixed_clock, &now,
	    alarm, true, &written) == 0);
	ATF_CHECK(status[0] == VIRTIO14_RTC_STATUS_OK);
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));

	enabled_req.flags = 0x80;
	ATF_REQUIRE(virtio_rtc_process_request_alarm(&enabled_req,
	    sizeof(enabled_req), status, sizeof(status), fixed_clock, &now,
	    alarm, true, &written) == 0);
	ATF_CHECK(status[0] == VIRTIO14_RTC_STATUS_EINVAL);

	ATF_REQUIRE(virtio_rtc_process_request(&read_req, sizeof(read_req),
	    status, sizeof(status), fixed_clock, &now, &written) == 0);
	ATF_CHECK(status[0] == VIRTIO14_RTC_STATUS_ENODEV);
	virtio_rtc_alarm_destroy(alarm);
}

ATF_TC_WITHOUT_HEAD(control_reset_and_backward_step);
ATF_TC_BODY(control_reset_and_backward_step, tc)
{
	struct virtio_rtc_alarm *alarm;
	uint8_t notification[VIRTIO14_RTC_NOTIF_ALARM_SIZE];
	uint64_t alarm_time;
	bool enabled;
	size_t written;

	ATF_REQUIRE((virtio_rtc_alarm_create(&alarm)) == (0));
	ATF_REQUIRE((virtio_rtc_alarm_set(alarm, 100, true, 100)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_set_enabled(alarm, false, 101)) == (0));
	ATF_CHECK(!virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_set_enabled(alarm, true, 101)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_set(alarm, 80, true, 101)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_observe(alarm, 50)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), &written) == 0);
	ATF_CHECK_EQ(written, sizeof(notification));
	ATF_CHECK(!virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_observe(alarm, 80)) == (0));
	ATF_CHECK(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE((virtio_rtc_alarm_read(alarm, &alarm_time, &enabled)) == (0));
	ATF_CHECK((alarm_time) == (80));
	ATF_CHECK(enabled);
	ATF_REQUIRE((virtio_rtc_alarm_reset(alarm)) == (0));
	ATF_REQUIRE((virtio_rtc_alarm_read(alarm, &alarm_time, &enabled)) == (0));
	ATF_CHECK((alarm_time) == (0));
	ATF_CHECK(!enabled);
	virtio_rtc_alarm_destroy(alarm);
}

ATF_TC_WITHOUT_HEAD(portable_restore_and_elapsed_alarm);
ATF_TC_BODY(portable_restore_and_elapsed_alarm, tc)
{
	struct virtio_rtc_alarm *source, *target;
	uint8_t state[40], corrupt[40];
	uint64_t alarm_time;
	bool enabled;

	ATF_REQUIRE((virtio_rtc_alarm_create(&source)) == (0));
	ATF_REQUIRE((virtio_rtc_alarm_create(&target)) == (0));
	ATF_REQUIRE((virtio_rtc_alarm_set(source, 200, true, 100)) == (0));
	ATF_REQUIRE(virtio_rtc_alarm_snapshot(source, state,
	    sizeof(state)) == 0);
	ATF_CHECK((le32dec(state)) == (UINT32_C(0x31414c41)));
	ATF_CHECK((le16dec(state + 4)) == (1));
	ATF_CHECK((le16dec(state + 6)) == (sizeof(state)));
	memcpy(corrupt, state, sizeof(state));
	corrupt[27] = 1;
	ATF_CHECK(virtio_rtc_alarm_restore_validate(corrupt,
	    sizeof(corrupt)) == EPROTO);
	ATF_CHECK(virtio_rtc_alarm_restore(target, corrupt,
	    sizeof(corrupt), 150) == EPROTO);
	memcpy(corrupt, state, sizeof(state));
	corrupt[24] = 0;
	corrupt[25] = 1;
	le64enc(corrupt + VTRTCA_DIGEST_OFFSET,
	    vtrtca_digest(corrupt, sizeof(corrupt)));
	ATF_CHECK(virtio_rtc_alarm_restore(target, corrupt,
	    sizeof(corrupt), 150) == EPROTO);

	/*
	 * A state that claims no clock observation cannot carry an enabled
	 * alarm or a last reading.  Recompute the integrity field so this
	 * exercises semantic validation rather than corruption detection.
	 */
	memcpy(corrupt, state, sizeof(state));
	corrupt[26] = 0;
	le64enc(corrupt + VTRTCA_DIGEST_OFFSET,
	    vtrtca_digest(corrupt, sizeof(corrupt)));
	ATF_CHECK(virtio_rtc_alarm_restore(target, corrupt,
	    sizeof(corrupt), 150) == EPROTO);

	/*
	 * Every rejected image must leave the destination alarm intact.
	 */
	ATF_REQUIRE((virtio_rtc_alarm_set(target, 175, true, 160)) == (0));
	memcpy(corrupt, state, sizeof(state));
	corrupt[27] = 1;
	ATF_CHECK(virtio_rtc_alarm_restore(target, corrupt,
	    sizeof(corrupt), 250) == EPROTO);
	ATF_REQUIRE((virtio_rtc_alarm_read(target, &alarm_time, &enabled)) ==
	    (0));
	ATF_CHECK((alarm_time) == (175));
	ATF_CHECK(enabled);
	ATF_CHECK(!virtio_rtc_alarm_pending(target));

	ATF_REQUIRE(virtio_rtc_alarm_restore_validate(state,
	    sizeof(state)) == 0);
	ATF_REQUIRE((virtio_rtc_alarm_read(target, &alarm_time, &enabled)) ==
	    (0));
	ATF_CHECK((alarm_time) == (175));
	ATF_CHECK(enabled);
	ATF_CHECK(!virtio_rtc_alarm_pending(target));
	ATF_REQUIRE(virtio_rtc_alarm_restore(target, state,
	    sizeof(state), 250) == 0);
	ATF_CHECK(virtio_rtc_alarm_pending(target));
	ATF_REQUIRE((virtio_rtc_alarm_read(target, &alarm_time, &enabled)) == (0));
	ATF_CHECK((alarm_time) == (200));
	ATF_CHECK(enabled);
	virtio_rtc_alarm_destroy(target);
	virtio_rtc_alarm_destroy(source);
}

ATF_TC_WITHOUT_HEAD(portable_state_alias_is_rejected);
ATF_TC_BODY(portable_state_alias_is_rejected, tc)
{
	struct virtio_rtc_alarm *alarm;
	uint8_t state[VTRTCA_STATE_SIZE];
	uint64_t alarm_time;
	bool enabled;

	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(alarm, 200, true, 100), 0);

	/*
	 * Neither direction may treat the live object (including its mutex)
	 * as portable-state storage.  Rejection must precede all writes and
	 * decoding so the object remains usable.
	 */
	ATF_CHECK_EQ(virtio_rtc_alarm_snapshot(alarm, alarm,
	    VTRTCA_STATE_SIZE), EINVAL);
	ATF_CHECK_EQ(virtio_rtc_alarm_restore(alarm, alarm,
	    VTRTCA_STATE_SIZE, 150), EINVAL);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_read(alarm, &alarm_time, &enabled), 0);
	ATF_CHECK_EQ(alarm_time, 200);
	ATF_CHECK(enabled);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_snapshot(alarm, state,
	    sizeof(state)), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_restore_validate(state,
	    sizeof(state)), 0);
	virtio_rtc_alarm_destroy(alarm);
}

ATF_TC_WITHOUT_HEAD(notification_and_control_aliases_are_rejected);
ATF_TC_BODY(notification_and_control_aliases_are_rejected, tc)
{
	struct virtio_rtc_alarm *alarm;
	struct virtio_rtc_req_set_alarm request;
	uint8_t notification[VIRTIO14_RTC_NOTIF_ALARM_SIZE];
	uint8_t response[VIRTIO14_RTC_RESP_HEAD_SIZE];
	uint64_t alarm_time, now;
	bool enabled;
	size_t written;

	now = 100;
	written = SIZE_MAX;
	ATF_REQUIRE_EQ(virtio_rtc_alarm_create(&alarm), 0);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_set(alarm, 100, true, now), 0);
	ATF_REQUIRE(virtio_rtc_alarm_pending(alarm));

	ATF_CHECK_EQ(virtio_rtc_alarm_notify(alarm, alarm,
	    sizeof(notification), &written), EINVAL);
	ATF_CHECK_EQ(written, SIZE_MAX);
	ATF_REQUIRE(virtio_rtc_alarm_pending(alarm));
	ATF_CHECK_EQ(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), (size_t *)(void *)&alarm->alarm_time),
	    EINVAL);
	ATF_REQUIRE(virtio_rtc_alarm_pending(alarm));
	ATF_CHECK_EQ(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), (size_t *)(void *)notification), EINVAL);
	ATF_REQUIRE(virtio_rtc_alarm_pending(alarm));
	ATF_REQUIRE_EQ(virtio_rtc_alarm_notify(alarm, notification,
	    sizeof(notification), &written), 0);
	ATF_CHECK_EQ(written, sizeof(notification));

	memset(&request, 0, sizeof(request));
	request.head.msg_type = htole16(VIRTIO14_RTC_REQ_SET_ALARM);
	request.alarm_time = htole64(200);
	request.flags = VIRTIO14_RTC_FLAG_ALARM_ENABLED;
	written = SIZE_MAX;
	ATF_CHECK_EQ(virtio_rtc_process_request_alarm(&request,
	    sizeof(request), alarm, sizeof(response), fixed_clock, &now, alarm,
	    true, &written), EINVAL);
	ATF_CHECK_EQ(written, SIZE_MAX);
	ATF_CHECK_EQ(virtio_rtc_process_request_alarm(&request,
	    sizeof(request), response, sizeof(response), fixed_clock, &now,
	    alarm, true, (size_t *)(void *)&request), EINVAL);
	ATF_CHECK_EQ(virtio_rtc_process_request_alarm(&request,
	    sizeof(request), response, sizeof(response), fixed_clock, &now,
	    alarm, true, (size_t *)(void *)response), EINVAL);
	ATF_REQUIRE_EQ(virtio_rtc_alarm_read(alarm, &alarm_time, &enabled), 0);
	ATF_CHECK_EQ(alarm_time, 100);
	ATF_CHECK(enabled);
	ATF_REQUIRE_EQ(virtio_rtc_process_request_alarm(&request,
	    sizeof(request), response, sizeof(response), fixed_clock, &now,
	    alarm, true, &written), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_REQUIRE_EQ(virtio_rtc_alarm_read(alarm, &alarm_time, &enabled), 0);
	ATF_CHECK_EQ(alarm_time, 200);
	ATF_CHECK(enabled);
	virtio_rtc_alarm_destroy(alarm);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, expiration_and_notification);
	ATF_TP_ADD_TC(tp, control_protocol);
	ATF_TP_ADD_TC(tp, control_reset_and_backward_step);
	ATF_TP_ADD_TC(tp, portable_restore_and_elapsed_alarm);
	ATF_TP_ADD_TC(tp, portable_state_alias_is_rejected);
	ATF_TP_ADD_TC(tp, notification_and_control_aliases_are_rejected);
	return (atf_no_error());
}
