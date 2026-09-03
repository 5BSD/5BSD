/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_PROTOCOL_H_
#define	_NOTIFY_PROTOCOL_H_

#include <stdint.h>

#define	NOTIFY_INTERFACE		"system.Notify"
#define	NOTIFY_INTERFACE_VERSION	"2.0.0"
#define	NOTIFY_MAGIC			0x4e544643U	/* "NTFC" */
#define	NOTIFY_ABI_VERSION		2

#define	NOTIFY_MAX_TOPIC		128
#define	NOTIFY_MAX_PAYLOAD		2048
#define	NOTIFY_MAX_PUBLISHER		64
#define	NOTIFY_MAX_MESSAGE		4096
#define	NOTIFY_MAX_SUBSCRIPTIONS	64
#define	NOTIFY_DEFAULT_QUEUE		256
#define	NOTIFY_MAX_TIMERS		64
#define	NOTIFY_MAX_TIMER_INTERVAL_MS	86400000U
#define	NOTIFY_MAX_STATES		4096
#define	NOTIFY_TIMEOUT_INFINITE	UINT32_MAX

#define	NOTIFY_FEATURE_PUBSUB		0x00000001U
#define	NOTIFY_FEATURE_TIMERS		0x00000002U
#define	NOTIFY_FEATURE_BOUNDED_QUEUE	0x00000004U
#define	NOTIFY_FEATURE_STATE		0x00000008U
#define	NOTIFY_FEATURE_LOSS_REPORTING	0x00000010U

#define	NOTIFY_MSG_F_MASK		0U

#define	NOTIFY_TIMER_F_PERIODIC	0x00000001U
#define	NOTIFY_TIMER_F_MASK		NOTIFY_TIMER_F_PERIODIC

enum notify_opcode {
	NOTIFY_OP_HELLO = 1,
	NOTIFY_OP_SUBSCRIBE,
	NOTIFY_OP_UNSUBSCRIBE,
	NOTIFY_OP_PUBLISH,
	NOTIFY_OP_NEXT,
	NOTIFY_OP_TIMER_ADD,
	NOTIFY_OP_TIMER_CANCEL,
	NOTIFY_OP_STATS,
	NOTIFY_OP_STATE_SET,
	NOTIFY_OP_STATE_GET,
	NOTIFY_OP_STATE_CLEAR
};

enum notify_event_type {
	NOTIFY_EVENT_PUBLISH = 1,
	NOTIFY_EVENT_TIMER,
	NOTIFY_EVENT_STATE,
	NOTIFY_EVENT_GAP,
	NOTIFY_EVENT_RESET
};

#define	NOTIFY_EVENT_F_GAP		0x00000001U
#define	NOTIFY_EVENT_F_MASK		NOTIFY_EVENT_F_GAP

enum notify_message_role {
	NOTIFY_MESSAGE_REQUEST = 1,
	NOTIFY_MESSAGE_REPLY,
	NOTIFY_MESSAGE_EVENT
};

struct notify_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct notify_msg) == 16,
    "notify message header ABI");

struct notify_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint32_t	max_topic;
	uint32_t	max_payload;
	uint32_t	max_subscriptions;
	uint32_t	queue_depth;
	uint32_t	max_timers;
	uint32_t	max_states;
	uint64_t	router_epoch;
};

struct notify_topic_request {
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	reserved32;
	char		topic[NOTIFY_MAX_TOPIC];
};

struct notify_publish_request {
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	payload_length;
	char		topic[NOTIFY_MAX_TOPIC];
	uint8_t		payload[];
};

struct notify_next_request {
	uint32_t	timeout_ms;
	uint32_t	reserved;
};

struct notify_timer_request {
	uint64_t	timer_id;
	uint32_t	interval_ms;
	uint32_t	flags;
};

struct notify_timer_cancel_request {
	uint64_t	timer_id;
	uint64_t	reserved;
};

struct notify_state_set_request {
	uint64_t	state;
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	reserved32;
	char		topic[NOTIFY_MAX_TOPIC];
};

struct notify_state_reply {
	uint64_t	router_epoch;
	uint64_t	generation;
	uint64_t	state;
};

struct notify_event {
	uint32_t	type;
	uint32_t	flags;
	uint64_t	router_epoch;
	uint64_t	sequence;
	uint64_t	timestamp_ns;
	uint64_t	timer_id;
	uint64_t	generation;
	uint64_t	state;
	uint64_t	lost_count;
	uint16_t	publisher_length;
	uint16_t	topic_length;
	uint32_t	payload_length;
	uint8_t		data[];
};

struct notify_stats {
	uint64_t	published;
	uint64_t	delivered;
	uint64_t	dropped;
	uint64_t	rejected;
	uint64_t	timer_events;
	uint64_t	reserved[3];
};

#endif
