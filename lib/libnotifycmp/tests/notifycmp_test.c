/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "notifycmp.h"

static struct notifycmp_msg
message(uint16_t opcode)
{
	struct notifycmp_msg msg;

	memset(&msg, 0, sizeof(msg));
	ATF_REQUIRE_EQ(notifycmp_message_init(&msg, opcode, 0), 0);
	return (msg);
}

ATF_TC_WITHOUT_HEAD(abi);
ATF_TC_BODY(abi, tc)
{

	ATF_CHECK_EQ(sizeof(struct notifycmp_msg), 16);
	ATF_CHECK_EQ(offsetof(struct notifycmp_event, data), 40);
	ATF_CHECK_EQ(sizeof(struct notifycmp_topic_request), 136);
	ATF_CHECK(NOTIFYCMP_MAX_MESSAGE >= sizeof(struct notifycmp_msg) +
	    sizeof(struct notifycmp_publish_request) + NOTIFYCMP_MAX_PAYLOAD);
}

ATF_TC_WITHOUT_HEAD(topics);
ATF_TC_BODY(topics, tc)
{

	ATF_CHECK_EQ(notifycmp_validate_topic("system.ready", 12), 0);
	ATF_CHECK_EQ(notifycmp_validate_topic("service_1-state", 15), 0);
	ATF_CHECK_EQ(notifycmp_validate_topic("", 0), -1);
	ATF_CHECK_EQ(notifycmp_validate_topic(".bad", 4), -1);
	ATF_CHECK_EQ(notifycmp_validate_topic("bad..topic", 10), -1);
	ATF_CHECK_EQ(notifycmp_validate_topic("bad/topic", 9), -1);
	ATF_CHECK_EQ(notifycmp_validate_topic("9bad", 4), -1);
}

ATF_TC_WITHOUT_HEAD(validation);
ATF_TC_BODY(validation, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
	} storage;
	struct notifycmp_msg *msg;
	struct notifycmp_topic_request *topic;
	struct notifycmp_publish_request *publish;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFYCMP_OP_SUBSCRIBE);
	topic = (void *)(msg + 1);
	topic->topic_length = 12;
	memcpy(topic->topic, "system.ready", 12);
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFYCMP_MESSAGE_REQUEST), 0);

	topic->topic[12] = 'x';
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFYCMP_MESSAGE_REQUEST), -1);
	topic->topic[12] = '\0';
	msg->status = -EINVAL;
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*topic), NOTIFYCMP_MESSAGE_REQUEST), -1);

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFYCMP_OP_PUBLISH);
	publish = (void *)(msg + 1);
	publish->topic_length = 5;
	publish->payload_length = 3;
	memcpy(publish->topic, "event", 5);
	memcpy(publish + 1, "abc", 3);
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*publish) + 3,
	    NOTIFYCMP_MESSAGE_REQUEST), 0);
	for (size_t length = 0;
	    length < sizeof(*msg) + sizeof(*publish) + 3; length++)
		ATF_CHECK_EQ(notifycmp_validate_message(msg, length,
		    NOTIFYCMP_MESSAGE_REQUEST), -1);
	publish->payload_length = NOTIFYCMP_MAX_PAYLOAD + 1;
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*publish) + 3,
	    NOTIFYCMP_MESSAGE_REQUEST), -1);
}

ATF_TC_WITHOUT_HEAD(events);
ATF_TC_BODY(events, tc)
{
	union {
		max_align_t align;
		uint8_t bytes[NOTIFYCMP_MAX_MESSAGE];
	} storage;
	struct notifycmp_event *event;
	struct notifycmp_msg *msg;

	memset(&storage, 0, sizeof(storage));
	msg = (void *)storage.bytes;
	*msg = message(NOTIFYCMP_OP_NEXT);
	event = (void *)(msg + 1);
	event->type = NOTIFYCMP_EVENT_PUBLISH;
	event->sequence = 1;
	event->publisher_length = 3;
	event->topic_length = 5;
	event->payload_length = 2;
	memcpy(event->data, "svc", 3);
	memcpy(event->data + 3, "event", 5);
	memcpy(event->data + 8, "ok", 2);
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*event) + 3 + 5 + 2,
	    NOTIFYCMP_MESSAGE_REPLY), 0);
	for (size_t length = 0;
	    length < sizeof(*msg) + sizeof(*event) + 3 + 5 + 2; length++)
		ATF_CHECK_EQ(notifycmp_validate_message(msg, length,
		    NOTIFYCMP_MESSAGE_REPLY), -1);
	event->timer_id = 1;
	ATF_CHECK_EQ(notifycmp_validate_message(msg,
	    sizeof(*msg) + sizeof(*event) + 3 + 5 + 2,
	    NOTIFYCMP_MESSAGE_REPLY), -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, abi);
	ATF_TP_ADD_TC(tp, topics);
	ATF_TP_ADD_TC(tp, validation);
	ATF_TP_ADD_TC(tp, events);
	return (atf_no_error());
}
