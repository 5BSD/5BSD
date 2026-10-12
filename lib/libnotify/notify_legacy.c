/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The pre-FIDL NTFC record validators (notify_server.h), kept for ABI
 * compatibility, and the event rules both formats share.  The provider and
 * libnotify speak bsd.notify.v1 (notify.fidl).
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "notify.h"
#include "notify_server.h"
#include "notify_internal.h"
#include "notify_probes.h"

int
notify_validate_event(const struct notify_event *event, size_t length)
{
	size_t expected, i;

	if (length < sizeof(*event) ||
	    (event->type < NOTIFY_EVENT_PUBLISH ||
	    event->type > NOTIFY_EVENT_RESET) ||
	    (event->flags & ~NOTIFY_EVENT_F_MASK) != 0 ||
	    event->router_epoch == 0 ||
	    event->publisher_length > NOTIFY_MAX_PUBLISHER ||
	    event->topic_length > NOTIFY_MAX_TOPIC ||
	    event->payload_length > NOTIFY_MAX_PAYLOAD)
		goto invalid;
	expected = sizeof(*event) + event->publisher_length +
	    event->topic_length + event->payload_length;
	if (expected != length ||
	    (event->publisher_length != 0 &&
	    memchr(event->data, '\0', event->publisher_length) != NULL) ||
	    (event->topic_length != 0 &&
	    notify_validate_topic((const char *)event->data +
	    event->publisher_length, event->topic_length) == -1))
		goto invalid;
	for (i = 0; i < event->publisher_length; i++)
		if (event->data[i] < 0x20 || event->data[i] == 0x7f)
			goto invalid;
	if ((event->type == NOTIFY_EVENT_PUBLISH ||
	    event->type == NOTIFY_EVENT_TIMER ||
	    event->type == NOTIFY_EVENT_STATE) &&
	    event->publisher_length == 0)
		goto invalid;
	if (event->type == NOTIFY_EVENT_TIMER &&
	    (event->timer_id == 0 || event->topic_length != 0 ||
	    event->payload_length != 0 || event->generation != 0 ||
	    event->lost_count != 0))
		goto invalid;
	if (event->type == NOTIFY_EVENT_PUBLISH &&
	    (event->timer_id != 0 || event->topic_length == 0 ||
	    event->generation != 0 || event->lost_count != 0))
		goto invalid;
	if (event->type == NOTIFY_EVENT_STATE &&
	    (event->timer_id != 0 || event->topic_length == 0 ||
	    event->payload_length != 0 || event->generation == 0 ||
	    event->lost_count != 0))
		goto invalid;
	if ((event->type == NOTIFY_EVENT_GAP ||
	    event->type == NOTIFY_EVENT_RESET) &&
	    (event->publisher_length != 0 || event->topic_length != 0 ||
	    event->payload_length != 0 || event->timer_id != 0 ||
	    event->generation != 0 || event->state != 0 ||
	    (event->type == NOTIFY_EVENT_GAP &&
	    (event->lost_count == 0 ||
	    (event->flags & NOTIFY_EVENT_F_GAP) == 0)) ||
	    (event->type == NOTIFY_EVENT_RESET &&
	    (event->lost_count != 0 || event->flags != 0))))
		goto invalid;
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

/*
 * Validate a LIST_SUBSCRIPTIONS / LIST_TIMERS reply body.  Shared by the
 * client (checking an incoming reply) and the daemon (checking a reply before
 * it is sent), so both ends agree on the exact wire shape.  The entry kind is
 * selected by opcode and the payload length must match the advertised count
 * exactly; each entry is validated in full so a caller may trust the contents.
 */
static int
validate_list_reply(uint16_t opcode, const void *body, size_t payload)
{
	const struct notify_list_reply *list;
	const struct notify_subscription_entry *subs;
	const struct notify_timer_entry *timers;
	size_t entry_size, i;

	if (payload < sizeof(*list))
		return (-1);
	list = body;
	/*
	 * next_cursor is an absolute resume offset, so it must not point past
	 * the reported total; per-call loop-safety (that it strictly advances
	 * the requested cursor) is enforced by the caller, which knows the
	 * cursor it sent.
	 */
	if (list->reserved != 0 || list->count > NOTIFY_LIST_MAX_ENTRIES ||
	    list->count > list->total || list->next_cursor > list->total)
		return (-1);
	entry_size = opcode == NOTIFY_OP_LIST_SUBSCRIPTIONS ?
	    sizeof(*subs) : sizeof(*timers);
	if (payload != sizeof(*list) + (size_t)list->count * entry_size)
		return (-1);
	if (opcode == NOTIFY_OP_LIST_SUBSCRIPTIONS) {
		subs = (const void *)(list + 1);
		for (i = 0; i < list->count; i++) {
			if (subs[i].reserved16 != 0 || subs[i].reserved32 != 0 ||
			    subs[i].topic_length == 0 ||
			    subs[i].topic_length > sizeof(subs[i].topic) ||
			    notify_validate_topic(subs[i].topic,
			    subs[i].topic_length) == -1 ||
			    memchr(subs[i].topic, '\0',
			    subs[i].topic_length) != NULL ||
			    memcmp(subs[i].topic + subs[i].topic_length,
			    (char[NOTIFY_MAX_TOPIC]){}, sizeof(subs[i].topic) -
			    subs[i].topic_length) != 0)
				return (-1);
		}
	} else {
		timers = (const void *)(list + 1);
		for (i = 0; i < list->count; i++) {
			if (timers[i].timer_id == 0 ||
			    timers[i].interval_ms == 0 ||
			    timers[i].interval_ms >
			    NOTIFY_MAX_TIMER_INTERVAL_MS ||
			    (timers[i].flags & ~NOTIFY_TIMER_F_MASK) != 0)
				return (-1);
		}
	}
	return (0);
}

static int
notify_header_validate(const struct notify_msg *msg, size_t length,
    enum notify_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > NOTIFY_MAX_MESSAGE ||
	    (role != NOTIFY_MESSAGE_REQUEST &&
	    role != NOTIFY_MESSAGE_REPLY &&
	    role != NOTIFY_MESSAGE_EVENT) ||
	    msg->magic != NOTIFY_MAGIC ||
	    msg->opcode < NOTIFY_OP_HELLO ||
	    msg->opcode > NOTIFY_OP_MAX ||
	    (msg->flags & ~NOTIFY_MSG_F_MASK) != 0 ||
	    (role != NOTIFY_MESSAGE_REPLY && msg->status != 0) ||
	    (role == NOTIFY_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
notify_message_init(struct notify_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < NOTIFY_OP_HELLO ||
	    opcode > NOTIFY_OP_MAX ||
	    (flags & ~NOTIFY_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = NOTIFY_MAGIC;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
notify_message_init_reply(struct notify_msg *reply,
    const struct notify_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    notify_header_validate(request, sizeof(*request),
	    NOTIFY_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = NOTIFY_MAGIC;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
notify_validate_message(const struct notify_msg *msg, size_t length,
    enum notify_message_role role)
{
	const struct notify_publish_request *publish;
	const struct notify_timer_request *timer;
	const struct notify_topic_request *topic;
	const struct notify_hello_reply *hello;
	const struct notify_state_set_request *state_set;
	size_t payload;

	if (notify_header_validate(msg, length, role) == -1)
		goto invalid;
	payload = length - sizeof(*msg);
	if (role == NOTIFY_MESSAGE_REPLY) {
		if (msg->status != 0 && payload != 0)
			goto invalid;
		if (msg->status != 0)
			return (0);
		switch (msg->opcode) {
		case NOTIFY_OP_HELLO:
			if (payload != sizeof(*hello))
				goto invalid;
			hello = (const void *)(msg + 1);
			if ((hello->features & ~NOTIFY_FEATURE_STATE_WATCH) !=
			    (NOTIFY_FEATURE_PUBSUB |
			    NOTIFY_FEATURE_TIMERS |
			    NOTIFY_FEATURE_BOUNDED_QUEUE |
			    NOTIFY_FEATURE_STATE |
			    NOTIFY_FEATURE_LOSS_REPORTING) ||
			    hello->max_topic != NOTIFY_MAX_TOPIC ||
			    hello->max_payload != NOTIFY_MAX_PAYLOAD ||
			    hello->max_subscriptions !=
			    NOTIFY_MAX_SUBSCRIPTIONS ||
			    hello->queue_depth == 0 ||
			    hello->queue_depth > NOTIFY_DEFAULT_QUEUE ||
			    hello->max_timers != NOTIFY_MAX_TIMERS ||
			    hello->max_states != NOTIFY_MAX_STATES ||
			    hello->router_epoch == 0)
				goto invalid;
			break;
		case NOTIFY_OP_NEXT:
			if (notify_validate_event((const void *)(msg + 1), payload) == -1)
				goto invalid;
			break;
		case NOTIFY_OP_STATS:
			if (payload != sizeof(struct notify_stats))
				goto invalid;
			break;
		case NOTIFY_OP_STATE_WATCH: {
			const struct notify_state_watch_reply *state;

			if (payload != sizeof(*state))
				goto invalid;
			state = (const void *)(msg + 1);
			if (state->watch_epoch == 0 || state->generation == 0 ||
			    state->present > 1 || state->reserved != 0 ||
			    (state->present == 0 && state->state != 0))
				goto invalid;
			break;
		}
		case NOTIFY_OP_STATE_SET:
		case NOTIFY_OP_STATE_GET:
			if (payload != sizeof(struct notify_state_reply))
				goto invalid;
			break;
		case NOTIFY_OP_LIST_SUBSCRIPTIONS:
		case NOTIFY_OP_LIST_TIMERS:
			if (validate_list_reply(msg->opcode, msg + 1,
			    payload) == -1)
				goto invalid;
			break;
		default:
			if (payload != 0)
				goto invalid;
		}
		return (0);
	}
	if (msg->status != 0)
		goto invalid;
	switch (msg->opcode) {
	case NOTIFY_OP_HELLO:
		if (payload != 0) {
			const struct notify_hello_request *hello_request;

			if (payload != sizeof(*hello_request))
				goto invalid;
			hello_request = (const void *)(msg + 1);
			if (hello_request->reserved != 0 ||
			    (hello_request->features & ~NOTIFY_FEATURE_STATE_WATCH) != 0)
				goto invalid;
		}
		break;
	case NOTIFY_OP_STATS:
		if (payload != 0)
			goto invalid;
		break;
	case NOTIFY_OP_SUBSCRIBE:
	case NOTIFY_OP_UNSUBSCRIBE:
	case NOTIFY_OP_STATE_GET:
	case NOTIFY_OP_STATE_CLEAR:
		if (payload != sizeof(*topic))
			goto invalid;
		topic = (const void *)(msg + 1);
		if (topic->reserved16 != 0 || topic->reserved32 != 0 ||
		    topic->topic_length == 0 ||
		    topic->topic_length > sizeof(topic->topic) ||
		    notify_validate_topic(topic->topic,
		    topic->topic_length) == -1 ||
		    memchr(topic->topic, '\0', topic->topic_length) != NULL ||
		    memcmp(topic->topic + topic->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(topic->topic) -
		    topic->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_STATE_WATCH: {
		const struct notify_state_watch_request *watch;

		if (payload != sizeof(*watch))
			goto invalid;
		watch = (const void *)(msg + 1);
		topic = &watch->topic;
		if (watch->reserved != 0 || topic->reserved16 != 0 ||
		    topic->reserved32 != 0 ||
		    notify_validate_topic(topic->topic, topic->topic_length) == -1 ||
		    memcmp(topic->topic + topic->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(topic->topic) -
		    topic->topic_length) != 0)
			goto invalid;
		break;
	}
	case NOTIFY_OP_STATE_SET:
		if (payload != sizeof(*state_set))
			goto invalid;
		state_set = (const void *)(msg + 1);
		if (state_set->reserved16 != 0 || state_set->reserved32 != 0 ||
		    state_set->topic_length == 0 ||
		    state_set->topic_length > sizeof(state_set->topic) ||
		    notify_validate_topic(state_set->topic,
		    state_set->topic_length) == -1 ||
		    memchr(state_set->topic, '\0', state_set->topic_length) != NULL ||
		    memcmp(state_set->topic + state_set->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(state_set->topic) -
		    state_set->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_PUBLISH:
		if (payload < sizeof(*publish))
			goto invalid;
		publish = (const void *)(msg + 1);
		if (publish->reserved16 != 0 || publish->topic_length == 0 ||
		    publish->topic_length > sizeof(publish->topic) ||
		    publish->payload_length > NOTIFY_MAX_PAYLOAD ||
		    payload != sizeof(*publish) + publish->payload_length ||
		    notify_validate_topic(publish->topic,
		    publish->topic_length) == -1 ||
		    memchr(publish->topic, '\0', publish->topic_length) != NULL ||
		    memcmp(publish->topic + publish->topic_length,
		    (char[NOTIFY_MAX_TOPIC]){}, sizeof(publish->topic) -
		    publish->topic_length) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_NEXT: {
		const struct notify_next_request *next;

		if (payload != sizeof(*next))
			goto invalid;
		next = (const void *)(msg + 1);
		if (next->reserved != 0)
			goto invalid;
		break;
	}
	case NOTIFY_OP_TIMER_ADD:
		if (payload != sizeof(*timer))
			goto invalid;
		timer = (const void *)(msg + 1);
		if (timer->timer_id == 0 || timer->interval_ms == 0 ||
		    timer->interval_ms > 86400000 ||
		    (timer->flags & ~NOTIFY_TIMER_F_MASK) != 0)
			goto invalid;
		break;
	case NOTIFY_OP_TIMER_CANCEL: {
		const struct notify_timer_cancel_request *cancel;

		if (payload != sizeof(*cancel))
			goto invalid;
		cancel = (const void *)(msg + 1);
		if (cancel->timer_id == 0 || cancel->reserved != 0)
			goto invalid;
		break;
	}
	case NOTIFY_OP_LIST_SUBSCRIPTIONS:
	case NOTIFY_OP_LIST_TIMERS: {
		const struct notify_list_request *list;

		if (payload != sizeof(*list))
			goto invalid;
		list = (const void *)(msg + 1);
		if (list->reserved != 0)
			goto invalid;
		break;
	}
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

