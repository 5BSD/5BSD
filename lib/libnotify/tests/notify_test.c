/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "notify.h"
#include "notify_server.h"
#include "notify_internal.h"

static struct notify_msg
message(uint16_t opcode)
{
	struct notify_msg msg;

	memset(&msg, 0, sizeof(msg));
	ATF_REQUIRE_EQ(notify_message_init(&msg, opcode, 0), 0);
	return (msg);
}

ATF_TC_WITHOUT_HEAD(abi);
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(sizeof(struct notify_msg), 16);
	ATF_CHECK_EQ(offsetof(struct notify_event, data), 72);
	ATF_CHECK_EQ(sizeof(struct notify_topic_request), 136);
	ATF_CHECK(NOTIFY_MAX_MESSAGE >= sizeof(struct notify_msg) +
	    sizeof(struct notify_publish_request) + NOTIFY_MAX_PAYLOAD);
}

ATF_TC_WITHOUT_HEAD(topics);
ATF_TC_BODY(topics, tc)
{

	ATF_CHECK_EQ(notify_validate_topic("system.ready", 12), 0);
	ATF_CHECK_EQ(notify_validate_topic("service_1-state", 15), 0);
	ATF_CHECK_EQ(notify_validate_topic("org.5bsd.test", 13), 0);
	ATF_CHECK_EQ(notify_validate_topic("", 0), -1);
	ATF_CHECK_EQ(notify_validate_topic(".bad", 4), -1);
	ATF_CHECK_EQ(notify_validate_topic("bad..topic", 10), -1);
	ATF_CHECK_EQ(notify_validate_topic("bad/topic", 9), -1);
	ATF_CHECK_EQ(notify_validate_topic("9bad", 4), -1);
}

ATF_TC_WITHOUT_HEAD(validation);
ATF_TC_BODY(validation, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFY_MAX_MESSAGE];
	} storage;
	struct notify_msg *msg;
	struct notify_topic_request *topic;
	struct notify_publish_request *publish;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_SUBSCRIBE);
	topic = (void *)(msg + 1);
	topic->topic_length = 12;
	memcpy(topic->topic, "system.ready", 12);
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFY_MESSAGE_REQUEST), 0);

	topic->topic[12] = 'x';
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFY_MESSAGE_REQUEST), -1);
	topic->topic[12] = '\0';
	msg->status = -EINVAL;
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFY_MESSAGE_REQUEST), -1);

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_PUBLISH);
	publish = (void *)(msg + 1);
	publish->topic_length = 5;
	publish->payload_length = 3;
	memcpy(publish->topic, "event", 5);
	memcpy(publish + 1, "abc", 3);
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*publish) + 3,
	    NOTIFY_MESSAGE_REQUEST), 0);
	for (size_t length = 0;
	    length < sizeof(*msg) + sizeof(*publish) + 3; length++)
		ATF_CHECK_EQ(notify_validate_message(msg, length,
		    NOTIFY_MESSAGE_REQUEST), -1);
	publish->payload_length = NOTIFY_MAX_PAYLOAD + 1;
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*publish) + 3,
	    NOTIFY_MESSAGE_REQUEST), -1);
}

ATF_TC_WITHOUT_HEAD(events);
ATF_TC_BODY(events, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFY_MAX_MESSAGE];
	} storage;
	struct notify_event *event;
	struct notify_msg *msg;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_NEXT);
	event = (void *)(msg + 1);
	event->type = NOTIFY_EVENT_PUBLISH;
	event->router_epoch = 1;
	event->sequence = 1;
	event->publisher_length = 3;
	event->topic_length = 5;
	event->payload_length = 2;
	memcpy(event->data, "svc", 3);
	memcpy(event->data + 3, "event", 5);
	memcpy(event->data + 8, "ok", 2);
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*event) + 3 + 5 + 2,
	    NOTIFY_MESSAGE_REPLY), 0);
	for (size_t length = 0;
	    length < sizeof(*msg) + sizeof(*event) + 3 + 5 + 2; length++)
		ATF_CHECK_EQ(notify_validate_message(msg, length,
		    NOTIFY_MESSAGE_REPLY), -1);
	event->timer_id = 1;
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*event) + 3 + 5 + 2,
	    NOTIFY_MESSAGE_REPLY), -1);

	memset(event, 0, sizeof(*event));
	event->type = NOTIFY_EVENT_GAP;
	event->flags = NOTIFY_EVENT_F_GAP;
	event->router_epoch = 1;
	event->lost_count = 9;
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*event), NOTIFY_MESSAGE_REPLY), 0);
	event->lost_count = 0;
	ATF_CHECK_EQ(notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*event), NOTIFY_MESSAGE_REPLY), -1);
}

ATF_TC_WITHOUT_HEAD(timeout_saturation);
ATF_TC_BODY(timeout_saturation, tc)
{

	ATF_CHECK_EQ(notify_rpc_timeout(0), 1000);
	ATF_CHECK_EQ(notify_rpc_timeout(1), 1001);
	ATF_CHECK_EQ(notify_rpc_timeout(UINT32_MAX - 1001),
	    UINT32_MAX - 1);
	ATF_CHECK_EQ(notify_rpc_timeout(UINT32_MAX - 1000),
	    UINT32_MAX - 1);
	ATF_CHECK_EQ(notify_rpc_timeout(UINT32_MAX - 1),
	    UINT32_MAX - 1);
	ATF_CHECK_EQ(notify_rpc_timeout(NOTIFY_TIMEOUT_INFINITE),
	    NOTIFY_TIMEOUT_INFINITE);
}

ATF_TC_WITHOUT_HEAD(api_arguments);
ATF_TC_BODY(api_arguments, tc)
{
	struct notify_event event;
	struct notify_state_reply state;
	struct notify_stats stats;

	ATF_CHECK_ERRNO(EINVAL, notify_client_open(NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_subscribe(NULL, "system.ready") == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_unsubscribe(NULL, "system.ready") == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_publish(NULL, "system.ready", NULL, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_state_set(NULL, "system.ready", 1) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_state_get(NULL, "system.ready", &state) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_next(NULL, &event, sizeof(event), 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_timer_add(NULL, 1, 1, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    notify_timer_cancel(NULL, 1) == -1);
	ATF_CHECK_ERRNO(EINVAL, notify_stats(NULL, &stats) == -1);
	notify_client_close(NULL);
}

ATF_TC_WITHOUT_HEAD(reply_validation);
ATF_TC_BODY(reply_validation, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFY_MAX_MESSAGE];
	} storage;
	struct notify_hello_reply *hello;
	struct notify_msg *msg;
	struct notify_state_reply *state;
	size_t length;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_HELLO);
	hello = (void *)(msg + 1);
	hello->version = NOTIFY_ABI_VERSION;
	hello->features = NOTIFY_FEATURE_PUBSUB |
	    NOTIFY_FEATURE_TIMERS | NOTIFY_FEATURE_BOUNDED_QUEUE |
	    NOTIFY_FEATURE_STATE | NOTIFY_FEATURE_LOSS_REPORTING;
	hello->max_topic = NOTIFY_MAX_TOPIC;
	hello->max_payload = NOTIFY_MAX_PAYLOAD;
	hello->max_subscriptions = NOTIFY_MAX_SUBSCRIPTIONS;
	hello->queue_depth = NOTIFY_DEFAULT_QUEUE;
	hello->max_timers = NOTIFY_MAX_TIMERS;
	hello->max_states = NOTIFY_MAX_STATES;
	hello->router_epoch = 1;
	length = sizeof(*msg) + sizeof(*hello);
	ATF_CHECK_EQ(0, notify_validate_message(msg, length,
	    NOTIFY_MESSAGE_REPLY));
	hello->router_epoch = 0;
	ATF_CHECK_EQ(-1, notify_validate_message(msg, length,
	    NOTIFY_MESSAGE_REPLY));
	hello->router_epoch = 1;
	hello->features &= ~NOTIFY_FEATURE_STATE;
	ATF_CHECK_EQ(-1, notify_validate_message(msg, length,
	    NOTIFY_MESSAGE_REPLY));

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_STATE_GET);
	state = (void *)(msg + 1);
	state->router_epoch = 1;
	state->generation = 1;
	ATF_CHECK_EQ(0, notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*state), NOTIFY_MESSAGE_REPLY));
	ATF_CHECK_EQ(-1, notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*state) - 1, NOTIFY_MESSAGE_REPLY));
	msg->status = -ENOENT;
	ATF_CHECK_EQ(0, notify_validate_message(msg, sizeof(*msg),
	    NOTIFY_MESSAGE_REPLY));
	ATF_CHECK_EQ(-1, notify_validate_message(msg,
	    sizeof(*msg) + sizeof(*state), NOTIFY_MESSAGE_REPLY));
}

ATF_TC_WITHOUT_HEAD(event_classes);
ATF_TC_BODY(event_classes, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFY_MAX_MESSAGE];
	} storage;
	struct notify_event *event;
	struct notify_msg *msg;
	size_t base;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFY_OP_NEXT);
	event = (void *)(msg + 1);
	event->router_epoch = 9;
	event->sequence = 1;
	base = sizeof(*msg) + sizeof(*event);

	event->type = NOTIFY_EVENT_RESET;
	ATF_CHECK_EQ(0, notify_validate_message(msg, base,
	    NOTIFY_MESSAGE_REPLY));
	event->flags = NOTIFY_EVENT_F_GAP;
	ATF_CHECK_EQ(-1, notify_validate_message(msg, base,
	    NOTIFY_MESSAGE_REPLY));

	memset(event, 0, sizeof(*event));
	event->type = NOTIFY_EVENT_TIMER;
	event->router_epoch = 9;
	event->sequence = 2;
	event->timer_id = 4;
	event->publisher_length = 3;
	memcpy(event->data, "svc", 3);
	ATF_CHECK_EQ(0, notify_validate_message(msg, base + 3,
	    NOTIFY_MESSAGE_REPLY));

	memset(event, 0, sizeof(*event));
	event->type = NOTIFY_EVENT_STATE;
	event->router_epoch = 9;
	event->sequence = 3;
	event->generation = 7;
	event->state = 42;
	event->publisher_length = 3;
	event->topic_length = 5;
	memcpy(event->data, "svcevent", 8);
	ATF_CHECK_EQ(0, notify_validate_message(msg, base + 8,
	    NOTIFY_MESSAGE_REPLY));
	event->generation = 0;
	ATF_CHECK_EQ(-1, notify_validate_message(msg, base + 8,
	    NOTIFY_MESSAGE_REPLY));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, topics);
	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, events);
	ATF_TP_ADD_TC(tp, timeout_saturation);
	ATF_TP_ADD_TC(tp, api_arguments);
	ATF_TP_ADD_TC(tp, reply_validation);
	ATF_TP_ADD_TC(tp, event_classes);
	return (atf_no_error());
}
