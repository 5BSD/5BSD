/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>

#include "rebootctl.h"
#include "rebootctl_server.h"

static struct rebootctl_msg
message(uint16_t opcode, int32_t status)
{
	struct rebootctl_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.magic = REBOOTCTL_MAGIC;
	msg.version = REBOOTCTL_ABI_VERSION;
	msg.opcode = opcode;
	msg.status = status;
	return (msg);
}

ATF_TC_WITHOUT_HEAD(validation);
ATF_TC_BODY(validation, tc)
{
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_request request;
	} request;
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_status_reply status;
	} reply;

	memset(&request, 0, sizeof(request));
	request.msg = message(REBOOTCTL_OP_REBOOT, 0);
	ATF_CHECK_EQ(0,
	    rebootctl_validate_request(&request.msg, sizeof(request)));
	request.request.delay_ms = REBOOTCTL_MAX_DELAY_MS + 1;
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_request(&request.msg, sizeof(request)) == -1);
	memset(&reply, 0, sizeof(reply));
	reply.msg = message(REBOOTCTL_OP_STATUS, 0);
	reply.status.pending = 1;
	reply.status.request_id = 1;
	reply.status.requested_at_ns = 10;
	reply.status.execute_at_ns = 20;
	ATF_CHECK_EQ(0, rebootctl_validate_reply(&reply.msg, sizeof(reply)));
	reply.status.pending = 2;
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_reply(&reply.msg, sizeof(reply)) == -1);
}

ATF_TC_WITHOUT_HEAD(errors_and_api);
ATF_TC_BODY(errors_and_api, tc)
{
	struct rebootctl_msg msg;

	msg = message(REBOOTCTL_OP_REBOOT, -EACCES);
	ATF_CHECK_EQ(0, rebootctl_validate_reply(&msg, sizeof(msg)));
	msg.magic = 0;
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_reply(&msg, sizeof(msg)) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_status(NULL, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    rebootctl_reboot(NULL, UINT32_C(0x80000000)) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    rebootctl_reboot_after(NULL, 0, REBOOTCTL_MAX_DELAY_MS + 1) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_cancel(NULL) == -1);
	rebootctl_client_close(NULL);
}

ATF_TC_WITHOUT_HEAD(all_operations_and_lengths);
ATF_TC_BODY(all_operations_and_lengths, tc)
{
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_request request;
	} wire;
	size_t length;

	for (uint16_t opcode = REBOOTCTL_OP_REBOOT;
	    opcode <= REBOOTCTL_OP_CANCEL; opcode++) {
		memset(&wire, 0, sizeof(wire));
		wire.msg = message(opcode, 0);
		length = sizeof(wire.msg) +
		    (opcode == REBOOTCTL_OP_STATUS ||
		    opcode == REBOOTCTL_OP_CANCEL ? 0 : sizeof(wire.request));
		ATF_CHECK_EQ(0,
		    rebootctl_validate_request(&wire.msg, length));
		ATF_CHECK_ERRNO(EPROTO,
		    rebootctl_validate_request(&wire.msg, length + 1) == -1);
	}
	memset(&wire, 0, sizeof(wire));
	wire.msg = message(REBOOTCTL_OP_REBOOT, 0);
	wire.request.howto = REBOOTCTL_ALLOWED_FLAGS;
	ATF_CHECK_EQ(0, rebootctl_validate_request(&wire.msg, sizeof(wire)));
}

ATF_TC_WITHOUT_HEAD(header_boundaries);
ATF_TC_BODY(header_boundaries, tc)
{
	struct rebootctl_msg msg;
	size_t length;

	msg = message(REBOOTCTL_OP_STATUS, 0);
	for (length = 0; length < sizeof(msg); length++)
		ATF_CHECK_ERRNO(EPROTO,
		    rebootctl_validate_request(&msg, length) == -1);
	msg.flags = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_request(&msg, sizeof(msg)) == -1);
	msg = message(REBOOTCTL_OP_STATUS, 0);
	msg.version++;
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_request(&msg, sizeof(msg)) == -1);
	msg = message(REBOOTCTL_OP_STATUS, -ELAST - 1);
	ATF_CHECK_ERRNO(EPROTO,
	    rebootctl_validate_reply(&msg, sizeof(msg)) == -1);
}

static struct rebootctl_notification
notification(uint32_t state)
{
	struct rebootctl_notification event;

	memset(&event, 0, sizeof(event));
	event.version = REBOOTCTL_ABI_VERSION;
	event.state = state;
	event.request_id = 7;
	event.requested_at_ns = 100;
	event.execute_at_ns = 200;
	event.remaining_ms = 1;
	event.howto = RB_REROOT;
	event.error = state == REBOOTCTL_NOTIFICATION_CANCELLED ? ECANCELED : 0;
	event.requester_length = sizeof("org.test") - 1;
	memcpy(event.requester, "org.test", event.requester_length);
	return (event);
}

#define CHECK_BAD_NOTIFICATION(_event, _topic) do {                         \
	errno = 0;                                                            \
	ATF_CHECK_ERRNO(EPROTO, rebootctl_notification_decode((_topic),       \
	    &(_event), sizeof(_event), &decoded) == -1);                       \
} while (0)

ATF_TC_WITHOUT_HEAD(notification_validation);
ATF_TC_BODY(notification_validation, tc)
{
	static const char *const topics[] = {
		REBOOTCTL_NOTIFY_REQUESTED,
		REBOOTCTL_NOTIFY_SCHEDULED,
		REBOOTCTL_NOTIFY_IMMINENT,
		REBOOTCTL_NOTIFY_CANCELLED,
	};
	struct rebootctl_notification decoded, event;
	size_t i;

	(void)tc;
	for (i = 0; i < nitems(topics); i++) {
		event = notification((uint32_t)i + 1);
		ATF_REQUIRE_EQ(0, rebootctl_notification_decode(topics[i],
		    &event, sizeof(event), &decoded));
		ATF_CHECK_EQ(0, memcmp(&event, &decoded, sizeof(event)));
	}
	event = notification(REBOOTCTL_NOTIFICATION_SCHEDULED);
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_notification_decode(NULL, &event,
	    sizeof(event), &decoded) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_notification_decode(
	    REBOOTCTL_NOTIFY_SCHEDULED, NULL, sizeof(event), &decoded) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootctl_notification_decode(
	    REBOOTCTL_NOTIFY_SCHEDULED, &event, sizeof(event), NULL) == -1);
	ATF_CHECK_ERRNO(EPROTO, rebootctl_notification_decode(
	    REBOOTCTL_NOTIFY_SCHEDULED, &event, sizeof(event) - 1,
	    &decoded) == -1);

	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.version++;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.state = 0;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.request_id = 0;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.requested_at_ns = 0;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.execute_at_ns = event.requested_at_ns - 1;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.remaining_ms = REBOOTCTL_MAX_DELAY_MS + 1;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.howto = UINT32_C(0x80000000);
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.error = EIO;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_CANCELLED);
	event.error = 0;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_CANCELLED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.requester_length = 0;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.requester_length = sizeof(event.requester);
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.reserved16 = 1;
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.requester[event.requester_length] = 'x';
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
	event = notification(REBOOTCTL_NOTIFICATION_REQUESTED);
	event.requester[sizeof(event.requester) - 1] = 'x';
	CHECK_BAD_NOTIFICATION(event, REBOOTCTL_NOTIFY_REQUESTED);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, errors_and_api);
	ATF_TP_ADD_TC(tp, all_operations_and_lengths);
	ATF_TP_ADD_TC(tp, header_boundaries);
	ATF_TP_ADD_TC(tp, notification_validation);
	return (atf_no_error());
}
