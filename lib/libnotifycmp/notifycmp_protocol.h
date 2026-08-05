/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_PROTOCOL_H_
#define	_NOTIFYCMP_PROTOCOL_H_

#include <stdint.h>

#define	NOTIFYCMP_INTERFACE		"org.5bsd.notify"
#define	NOTIFYCMP_INTERFACE_VERSION	"2.0.0"
#define	NOTIFYCMP_MAGIC			0x4e544643U	/* "NTFC" */
#define	NOTIFYCMP_ABI_VERSION		2

#define	NOTIFYCMP_MAX_TOPIC		128
#define	NOTIFYCMP_MAX_PAYLOAD		2048
#define	NOTIFYCMP_MAX_PUBLISHER		64
#define	NOTIFYCMP_MAX_MESSAGE		4096
#define	NOTIFYCMP_MAX_SUBSCRIPTIONS	64
#define	NOTIFYCMP_DEFAULT_QUEUE		256
#define	NOTIFYCMP_MAX_TIMERS		64
#define	NOTIFYCMP_MAX_STATES		4096
#define	NOTIFYCMP_TIMEOUT_INFINITE	UINT32_MAX

#define	NOTIFYCMP_FEATURE_PUBSUB		0x00000001U
#define	NOTIFYCMP_FEATURE_TIMERS		0x00000002U
#define	NOTIFYCMP_FEATURE_BOUNDED_QUEUE	0x00000004U
#define	NOTIFYCMP_FEATURE_STATE		0x00000008U
#define	NOTIFYCMP_FEATURE_LOSS_REPORTING	0x00000010U

#define	NOTIFYCMP_MSG_F_MASK		0U

#define	NOTIFYCMP_TIMER_F_PERIODIC	0x00000001U
#define	NOTIFYCMP_TIMER_F_MASK		NOTIFYCMP_TIMER_F_PERIODIC

enum notifycmp_opcode {
	NOTIFYCMP_OP_HELLO = 1,
	NOTIFYCMP_OP_SUBSCRIBE,
	NOTIFYCMP_OP_UNSUBSCRIBE,
	NOTIFYCMP_OP_PUBLISH,
	NOTIFYCMP_OP_NEXT,
	NOTIFYCMP_OP_TIMER_ADD,
	NOTIFYCMP_OP_TIMER_CANCEL,
	NOTIFYCMP_OP_STATS,
	NOTIFYCMP_OP_STATE_SET,
	NOTIFYCMP_OP_STATE_GET
};

enum notifycmp_event_type {
	NOTIFYCMP_EVENT_PUBLISH = 1,
	NOTIFYCMP_EVENT_TIMER,
	NOTIFYCMP_EVENT_STATE,
	NOTIFYCMP_EVENT_GAP,
	NOTIFYCMP_EVENT_RESET
};

#define	NOTIFYCMP_EVENT_F_GAP		0x00000001U
#define	NOTIFYCMP_EVENT_F_MASK		NOTIFYCMP_EVENT_F_GAP

enum notifycmp_message_role {
	NOTIFYCMP_MESSAGE_REQUEST = 1,
	NOTIFYCMP_MESSAGE_REPLY,
	NOTIFYCMP_MESSAGE_EVENT
};

struct notifycmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
};

_Static_assert(sizeof(struct notifycmp_msg) == 16,
    "notifycmp message header ABI");

struct notifycmp_hello_reply {
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

struct notifycmp_topic_request {
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	reserved32;
	char		topic[NOTIFYCMP_MAX_TOPIC];
};

struct notifycmp_publish_request {
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	payload_length;
	char		topic[NOTIFYCMP_MAX_TOPIC];
	uint8_t		payload[];
};

struct notifycmp_next_request {
	uint32_t	timeout_ms;
	uint32_t	reserved;
};

struct notifycmp_timer_request {
	uint64_t	timer_id;
	uint32_t	interval_ms;
	uint32_t	flags;
};

struct notifycmp_timer_cancel_request {
	uint64_t	timer_id;
	uint64_t	reserved;
};

struct notifycmp_state_set_request {
	uint64_t	state;
	uint16_t	topic_length;
	uint16_t	reserved16;
	uint32_t	reserved32;
	char		topic[NOTIFYCMP_MAX_TOPIC];
};

struct notifycmp_state_reply {
	uint64_t	router_epoch;
	uint64_t	generation;
	uint64_t	state;
};

struct notifycmp_event {
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

struct notifycmp_stats {
	uint64_t	published;
	uint64_t	delivered;
	uint64_t	dropped;
	uint64_t	rejected;
	uint64_t	timer_events;
	uint64_t	reserved[3];
};

#endif
