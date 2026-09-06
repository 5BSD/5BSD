/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NOTIFY_ROUTER_TEST
#include "../bsdnotify.c"

struct fixture {
	struct router router;
	struct router_session session;
	struct notify_broker_client *publisher;
	int peer;
};

static void
fixture_open(struct fixture *fixture)
{
	int pair[2];

	memset(fixture, 0, sizeof(*fixture));
	fixture->router.kq = kqueue();
	ATF_REQUIRE(fixture->router.kq >= 0);
	fixture->router.broker = notify_broker_create();
	ATF_REQUIRE(fixture->router.broker != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	fixture->peer = pair[0];
	fixture->session.fd = pair[1];
	strlcpy(fixture->session.label, "tests.subscriber",
	    sizeof(fixture->session.label));
	fixture->session.client = notify_broker_add(fixture->router.broker,
	    fixture->session.label, NOTIFY_DEFAULT_QUEUE);
	ATF_REQUIRE(fixture->session.client != NULL);
	fixture->session.source.type = ROUTER_EVENT_SESSION;
	fixture->router.sessions = &fixture->session;
	fixture->publisher = notify_broker_add(fixture->router.broker,
	    "tests.publisher", NOTIFY_DEFAULT_QUEUE);
	ATF_REQUIRE(fixture->publisher != NULL);
}

static void
fixture_close(struct fixture *fixture)
{

	if (fixture->session.next_timer != NULL)
		router_delete_timer(&fixture->router, fixture->session.next_timer);
	while (fixture->session.timers != NULL)
		router_delete_timer(&fixture->router, fixture->session.timers);
	router_collect_garbage(&fixture->router);
	notify_broker_remove(fixture->router.broker, fixture->publisher);
	notify_broker_remove(fixture->router.broker, fixture->session.client);
	notify_broker_destroy(fixture->router.broker);
	close(fixture->peer);
	close(fixture->session.fd);
	close(fixture->router.kq);
}

static size_t
request(void *storage, uint16_t opcode, const void *payload, size_t length)
{
	struct notify_msg *message;

	memset(storage, 0, NOTIFY_MAX_MESSAGE);
	message = storage;
	ATF_REQUIRE_EQ(0, notify_message_init(message, opcode, 0));
	if (length != 0)
		memcpy(message + 1, payload, length);
	ATF_REQUIRE_EQ(0, notify_validate_message(message,
	    sizeof(*message) + length, NOTIFY_MESSAGE_REQUEST));
	return (sizeof(*message) + length);
}

static ssize_t
roundtrip(struct fixture *fixture, void *request_data, size_t request_length,
    void *reply, size_t reply_capacity)
{

	ATF_REQUIRE_EQ(0, internal_send(fixture->peer, request_data,
	    request_length, NOTIFY_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0,
	    router_handle_request(&fixture->router, &fixture->session, NULL));
	return (internal_receive(fixture->peer, reply, reply_capacity,
	    NOTIFY_MESSAGE_REPLY));
}

static void
subscribe_topic(struct fixture *fixture, const char *name)
{
	union notify_buffer outgoing, incoming;
	struct notify_topic_request topic;
	struct notify_msg *reply;
	size_t length;

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = strlen(name);
	memcpy(topic.topic, name, topic.topic_length);
	length = request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, &topic,
	    sizeof(topic));
	ATF_REQUIRE_EQ(sizeof(struct notify_msg), roundtrip(fixture,
	    outgoing.bytes, length, incoming.bytes, sizeof(incoming)));
	reply = (void *)incoming.bytes;
	ATF_REQUIRE_EQ(0, reply->status);
}

static void
unsubscribe_topic(struct fixture *fixture, const char *name)
{
	union notify_buffer outgoing, incoming;
	struct notify_topic_request topic;
	struct notify_msg *reply;
	size_t length;

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = strlen(name);
	memcpy(topic.topic, name, topic.topic_length);
	length = request(outgoing.bytes, NOTIFY_OP_UNSUBSCRIBE, &topic,
	    sizeof(topic));
	ATF_REQUIRE_EQ(sizeof(struct notify_msg), roundtrip(fixture,
	    outgoing.bytes, length, incoming.bytes, sizeof(incoming)));
	reply = (void *)incoming.bytes;
	ATF_REQUIRE_EQ(0, reply->status);
}

/* Enumerate the fixture session's subscriptions, reassembling all pages. */
static size_t
collect_subscriptions(struct fixture *fixture,
    char topics[][NOTIFY_MAX_TOPIC + 1], size_t max)
{
	union notify_buffer outgoing, incoming;
	struct notify_list_request req;
	const struct notify_msg *reply;
	const struct notify_list_reply *hdr;
	const struct notify_subscription_entry *ent;
	size_t total, length, i;
	uint32_t cursor;
	ssize_t received;

	total = 0;
	cursor = 0;
	for (;;) {
		memset(&req, 0, sizeof(req));
		req.cursor = cursor;
		length = request(outgoing.bytes, NOTIFY_OP_LIST_SUBSCRIPTIONS,
		    &req, sizeof(req));
		received = roundtrip(fixture, outgoing.bytes, length,
		    incoming.bytes, sizeof(incoming));
		reply = (const void *)incoming.bytes;
		ATF_REQUIRE_EQ(0, reply->status);
		ATF_REQUIRE_EQ(NOTIFY_OP_LIST_SUBSCRIPTIONS, reply->opcode);
		hdr = (const void *)(reply + 1);
		ent = (const void *)(hdr + 1);
		ATF_REQUIRE(hdr->count <= NOTIFY_LIST_MAX_ENTRIES);
		ATF_REQUIRE_EQ((size_t)received, sizeof(*reply) + sizeof(*hdr) +
		    (size_t)hdr->count * sizeof(*ent));
		for (i = 0; i < hdr->count; i++) {
			ATF_REQUIRE(total < max);
			ATF_REQUIRE(ent[i].topic_length > 0 &&
			    ent[i].topic_length <= NOTIFY_MAX_TOPIC);
			memcpy(topics[total], ent[i].topic, ent[i].topic_length);
			topics[total][ent[i].topic_length] = '\0';
			total++;
		}
		cursor = hdr->next_cursor;
		if (cursor == 0)
			break;
	}
	return (total);
}

static bool
topics_contain(char topics[][NOTIFY_MAX_TOPIC + 1], size_t count,
    const char *name)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (strcmp(topics[i], name) == 0)
			return (true);
	return (false);
}

ATF_TC_WITHOUT_HEAD(list_subscriptions_reflects_membership);
ATF_TC_BODY(list_subscriptions_reflects_membership, tc)
{
	static const char *const names[] = {
		"list.alpha", "list.beta", "list.gamma"
	};
	struct fixture fixture;
	char topics[8][NOTIFY_MAX_TOPIC + 1];
	size_t i, count;

	fixture_open(&fixture);
	count = collect_subscriptions(&fixture, topics, nitems(topics));
	ATF_CHECK_EQ(0, count);
	for (i = 0; i < nitems(names); i++)
		subscribe_topic(&fixture, names[i]);
	count = collect_subscriptions(&fixture, topics, nitems(topics));
	ATF_CHECK_EQ(nitems(names), count);
	for (i = 0; i < nitems(names); i++)
		ATF_CHECK(topics_contain(topics, count, names[i]));
	/* Unsubscription is reflected. */
	unsubscribe_topic(&fixture, "list.beta");
	count = collect_subscriptions(&fixture, topics, nitems(topics));
	ATF_CHECK_EQ(2, count);
	ATF_CHECK(topics_contain(topics, count, "list.alpha"));
	ATF_CHECK(!topics_contain(topics, count, "list.beta"));
	ATF_CHECK(topics_contain(topics, count, "list.gamma"));
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(list_subscriptions_paginates);
ATF_TC_BODY(list_subscriptions_paginates, tc)
{
	enum { COUNT = NOTIFY_LIST_MAX_ENTRIES + 6 };
	struct fixture fixture;
	char topics[COUNT][NOTIFY_MAX_TOPIC + 1];
	char name[NOTIFY_MAX_TOPIC + 1];
	size_t i, got;

	fixture_open(&fixture);
	for (i = 0; i < COUNT; i++) {
		(void)snprintf(name, sizeof(name), "page.t%02zu", i);
		subscribe_topic(&fixture, name);
	}
	got = collect_subscriptions(&fixture, topics, COUNT);
	ATF_CHECK_EQ((size_t)COUNT, got);
	/* Every distinct topic came back exactly once across the pages. */
	for (i = 0; i < COUNT; i++) {
		(void)snprintf(name, sizeof(name), "page.t%02zu", i);
		ATF_CHECK(topics_contain(topics, got, name));
	}
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(list_timers_reflects_membership);
ATF_TC_BODY(list_timers_reflects_membership, tc)
{
	union notify_buffer outgoing, incoming;
	struct notify_timer_request timer;
	struct notify_timer_cancel_request cancel;
	struct notify_list_request req;
	const struct notify_msg *reply;
	const struct notify_list_reply *hdr;
	const struct notify_timer_entry *ent;
	struct fixture fixture;
	size_t length, i;
	ssize_t received;
	bool saw_periodic, saw_oneshot;

	fixture_open(&fixture);
	timer = (struct notify_timer_request){ .timer_id = 11,
	    .interval_ms = 1000, .flags = NOTIFY_TIMER_F_PERIODIC };
	length = request(outgoing.bytes, NOTIFY_OP_TIMER_ADD, &timer,
	    sizeof(timer));
	ATF_REQUIRE_EQ(sizeof(struct notify_msg), roundtrip(&fixture,
	    outgoing.bytes, length, incoming.bytes, sizeof(incoming)));
	timer = (struct notify_timer_request){ .timer_id = 22,
	    .interval_ms = 5000 };
	length = request(outgoing.bytes, NOTIFY_OP_TIMER_ADD, &timer,
	    sizeof(timer));
	ATF_REQUIRE_EQ(sizeof(struct notify_msg), roundtrip(&fixture,
	    outgoing.bytes, length, incoming.bytes, sizeof(incoming)));

	memset(&req, 0, sizeof(req));
	length = request(outgoing.bytes, NOTIFY_OP_LIST_TIMERS, &req,
	    sizeof(req));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	reply = (const void *)incoming.bytes;
	ATF_REQUIRE_EQ(0, reply->status);
	hdr = (const void *)(reply + 1);
	ent = (const void *)(hdr + 1);
	ATF_CHECK_EQ(2, hdr->count);
	ATF_CHECK_EQ(2, hdr->total);
	ATF_CHECK_EQ(0, hdr->next_cursor);
	ATF_REQUIRE_EQ((size_t)received, sizeof(*reply) + sizeof(*hdr) +
	    2 * sizeof(*ent));
	saw_periodic = saw_oneshot = false;
	for (i = 0; i < hdr->count; i++) {
		if (ent[i].timer_id == 11) {
			ATF_CHECK_EQ(1000, ent[i].interval_ms);
			ATF_CHECK_EQ(NOTIFY_TIMER_F_PERIODIC, ent[i].flags);
			ATF_CHECK(ent[i].next_fire_ms <= 1000);
			saw_periodic = true;
		} else if (ent[i].timer_id == 22) {
			ATF_CHECK_EQ(5000, ent[i].interval_ms);
			ATF_CHECK_EQ(0, ent[i].flags);
			ATF_CHECK(ent[i].next_fire_ms <= 5000);
			saw_oneshot = true;
		}
	}
	ATF_CHECK(saw_periodic && saw_oneshot);

	/* Cancellation is reflected. */
	cancel = (struct notify_timer_cancel_request){ .timer_id = 11 };
	length = request(outgoing.bytes, NOTIFY_OP_TIMER_CANCEL, &cancel,
	    sizeof(cancel));
	ATF_REQUIRE_EQ(sizeof(struct notify_msg), roundtrip(&fixture,
	    outgoing.bytes, length, incoming.bytes, sizeof(incoming)));
	memset(&req, 0, sizeof(req));
	length = request(outgoing.bytes, NOTIFY_OP_LIST_TIMERS, &req,
	    sizeof(req));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	reply = (const void *)incoming.bytes;
	hdr = (const void *)(reply + 1);
	ent = (const void *)(hdr + 1);
	ATF_CHECK_EQ(1, hdr->count);
	ATF_CHECK_EQ(22, ent[0].timer_id);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(list_is_scoped_to_own_session);
ATF_TC_BODY(list_is_scoped_to_own_session, tc)
{
	struct fixture fixture;
	struct router_session other;
	char topics[8][NOTIFY_MAX_TOPIC + 1];
	int pair[2];
	size_t count;

	fixture_open(&fixture);
	/* A second, independent session with its own broker client. */
	memset(&other, 0, sizeof(other));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	other.fd = pair[1];
	other.source.type = ROUTER_EVENT_SESSION;
	other.router = &fixture.router;
	strlcpy(other.label, "tests.other", sizeof(other.label));
	other.client = notify_broker_add(fixture.router.broker, other.label,
	    NOTIFY_DEFAULT_QUEUE);
	ATF_REQUIRE(other.client != NULL);
	ATF_REQUIRE_EQ(0, notify_broker_subscribe(fixture.router.broker,
	    other.client, "other.secret", 12));

	subscribe_topic(&fixture, "mine.topic");
	count = collect_subscriptions(&fixture, topics, nitems(topics));
	/* The other session's subscription must never appear here. */
	ATF_CHECK_EQ(1, count);
	ATF_CHECK(topics_contain(topics, count, "mine.topic"));
	ATF_CHECK(!topics_contain(topics, count, "other.secret"));

	notify_broker_remove(fixture.router.broker, other.client);
	close(pair[0]);
	close(other.fd);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(hello_stats_and_errors);
ATF_TC_BODY(hello_stats_and_errors, tc)
{
	union notify_buffer outgoing, incoming;
	struct notify_msg *reply;
	struct fixture fixture;
	ssize_t received;
	size_t length;

	fixture_open(&fixture);
	length = request(outgoing.bytes, NOTIFY_OP_HELLO, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	ATF_CHECK_EQ(NOTIFY_OP_HELLO, reply->opcode);

	length = request(outgoing.bytes, NOTIFY_OP_STATS, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notify_stats), received);

	/* A malformed frame is fatal to this internal router session. */
	memset(outgoing.bytes, 0, sizeof(struct notify_msg));
	ATF_REQUIRE(send(fixture.peer, outgoing.bytes,
	    sizeof(struct notify_msg), 0) > 0);
	ATF_CHECK_ERRNO(EPROTO,
	    router_handle_request(&fixture.router, &fixture.session, NULL) == -1);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(pubsub_state_and_next);
ATF_TC_BODY(pubsub_state_and_next, tc)
{
	union notify_buffer outgoing, incoming;
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct notify_publish_request) + 32];
	} publish_storage;
	struct notify_publish_request *publish;
	struct notify_topic_request topic;
	struct notify_state_set_request state;
	struct notify_next_request next;
	struct notify_event *event;
	struct notify_msg *reply;
	struct fixture fixture;
	static const char name[] = "org.5bsd.tests.changed";
	uint8_t expected[32];
	ssize_t received;
	size_t i, length;

	fixture_open(&fixture);
	memset(&topic, 0, sizeof(topic));
	topic.topic_length = sizeof(name) - 1;
	memcpy(topic.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, &topic,
	    sizeof(topic));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);

	for (i = 0; i < sizeof(expected); i++)
		expected[i] = (uint8_t)(i * 29U);
	memset(&publish_storage, 0, sizeof(publish_storage));
	publish = (void *)publish_storage.bytes;
	publish->topic_length = sizeof(name) - 1;
	publish->payload_length = sizeof(expected);
	memcpy(publish->topic, name, sizeof(name) - 1);
	memcpy(publish + 1, expected, sizeof(expected));
	length = request(outgoing.bytes, NOTIFY_OP_PUBLISH, publish,
	    sizeof(*publish) + sizeof(expected));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	memset(&next, 0, sizeof(next));
	length = request(outgoing.bytes, NOTIFY_OP_NEXT, &next, sizeof(next));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	event = (void *)(reply + 1);
	ATF_CHECK_EQ(NOTIFY_EVENT_PUBLISH, event->type);
	ATF_CHECK_EQ(strlen(fixture.session.label), event->publisher_length);
	ATF_CHECK_EQ(0, memcmp(event->data, fixture.session.label,
	    event->publisher_length));
	ATF_CHECK_EQ(sizeof(expected), event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event->data + event->publisher_length +
	    event->topic_length, expected, sizeof(expected)));

	length = request(outgoing.bytes, NOTIFY_OP_UNSUBSCRIBE, &topic,
	    sizeof(topic));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	/* An unsubscribed client must not receive later publications. */
	ATF_REQUIRE_EQ(0, notify_broker_publish(fixture.router.broker,
	    fixture.publisher, name, sizeof(name) - 1, "ignored", 7));
	memset(&next, 0, sizeof(next));
	length = request(outgoing.bytes, NOTIFY_OP_NEXT, &next, sizeof(next));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EAGAIN, reply->status);

	memset(&state, 0, sizeof(state));
	state.state = 42;
	state.topic_length = sizeof(name) - 1;
	memcpy(state.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFY_OP_STATE_SET, &state,
	    sizeof(state));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notify_state_reply),
	    received);

	length = request(outgoing.bytes, NOTIFY_OP_STATE_GET, &topic,
	    sizeof(topic));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notify_state_reply),
	    received);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(timers_and_pending_request);
ATF_TC_BODY(timers_and_pending_request, tc)
{
	union notify_buffer outgoing, incoming;
	struct notify_timer_cancel_request cancel;
	struct notify_timer_request timer;
	struct notify_topic_request topic;
	struct notify_next_request next;
	struct notify_msg *reply;
	struct fixture fixture;
	static const char name[] = "org.5bsd.tests.pending";
	ssize_t received;
	size_t length;

	fixture_open(&fixture);
	timer = (struct notify_timer_request){
	    .timer_id = 7, .interval_ms = 1000 };
	length = request(outgoing.bytes, NOTIFY_OP_TIMER_ADD, &timer,
	    sizeof(timer));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));
	/* Duplicate timer IDs are rejected without corrupting the original. */
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EEXIST, reply->status);
	cancel = (struct notify_timer_cancel_request){ .timer_id = 7 };
	length = request(outgoing.bytes, NOTIFY_OP_TIMER_CANCEL, &cancel,
	    sizeof(cancel));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = sizeof(name) - 1;
	memcpy(topic.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, &topic,
	    sizeof(topic));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));

	next = (struct notify_next_request){
	    .timeout_ms = NOTIFY_TIMEOUT_INFINITE };
	length = request(outgoing.bytes, NOTIFY_OP_NEXT, &next, sizeof(next));
	ATF_REQUIRE_EQ(0, internal_send(fixture.peer, outgoing.bytes, length,
	    NOTIFY_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0,
	    router_handle_request(&fixture.router, &fixture.session, NULL));
	ATF_REQUIRE(fixture.session.pending_active);
	length = request(outgoing.bytes, NOTIFY_OP_HELLO, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EBUSY, reply->status);
	ATF_CHECK(fixture.session.pending_active);
	ATF_REQUIRE_EQ(0, notify_broker_publish(fixture.router.broker,
	    fixture.publisher, name, sizeof(name) - 1, NULL, 0));
	ATF_REQUIRE_EQ(0, router_deliver(&fixture.router, &fixture.session));
	received = internal_receive(fixture.peer, incoming.bytes, sizeof(incoming),
	    NOTIFY_MESSAGE_REPLY);
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	ATF_CHECK(!fixture.session.pending_active);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(admission_failure_classes);
ATF_TC_BODY(admission_failure_classes, tc)
{
	int error;

	errno = ETIMEDOUT;
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL,
	    router_admission_classify(-1, 0, 0, EPROTO, &error));
	ATF_CHECK_EQ(ETIMEDOUT, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL,
	    router_admission_classify(0, 0, 0, 0, &error));
	ATF_CHECK_EQ(EPROTO, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL,
	    router_admission_classify(0, sizeof(struct router_control_reply), 1,
	    0, &error));
	ATF_CHECK_EQ(EPROTO, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL,
	    router_admission_classify(0, sizeof(struct router_control_reply), 0,
	    EPROTO, &error));
	ATF_CHECK_EQ(EPROTO, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_REJECTED,
	    router_admission_classify(0, sizeof(struct router_control_reply), 0,
	    ENOSPC, &error));
	ATF_CHECK_EQ(ENOSPC, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_ACCEPTED,
	    router_admission_classify(0, sizeof(struct router_control_reply), 0,
	    0, &error));
	ATF_CHECK_EQ(0, error);
}

ATF_TC_WITHOUT_HEAD(timer_identifier_wrap_and_label_bounds);
ATF_TC_BODY(timer_identifier_wrap_and_label_bounds, tc)
{
	struct fixture fixture;
	char overlong[NOTIFY_MAX_PUBLISHER + 2];
	uint64_t first;

	fixture_open(&fixture);
	fixture.router.next_ident = UINT64_MAX;
	ATF_REQUIRE_EQ(0, router_add_timer(&fixture.router, &fixture.session,
	    1, 60000, 0, ROUTER_EVENT_USER_TIMER));
	first = fixture.session.timers->ident;
	ATF_CHECK_EQ(1, first);
	fixture.router.next_ident = UINT64_MAX;
	ATF_REQUIRE_EQ(0, router_add_timer(&fixture.router, &fixture.session,
	    2, 60000, 0, ROUTER_EVENT_USER_TIMER));
	ATF_CHECK_EQ(2, fixture.session.timers->ident);
	ATF_CHECK(fixture.session.timers->ident != first);
	ATF_CHECK(!router_label_valid(NULL));
	ATF_CHECK(!router_label_valid(""));
	memset(overlong, 'x', sizeof(overlong));
	overlong[sizeof(overlong) - 1] = '\0';
	ATF_CHECK(!router_label_valid(overlong));
	ATF_CHECK(router_label_valid("service.valid"));
	fixture_close(&fixture);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hello_stats_and_errors);
	ATF_TP_ADD_TC(tp, pubsub_state_and_next);
	ATF_TP_ADD_TC(tp, timers_and_pending_request);
	ATF_TP_ADD_TC(tp, admission_failure_classes);
	ATF_TP_ADD_TC(tp, timer_identifier_wrap_and_label_bounds);
	ATF_TP_ADD_TC(tp, list_subscriptions_reflects_membership);
	ATF_TP_ADD_TC(tp, list_subscriptions_paginates);
	ATF_TP_ADD_TC(tp, list_timers_reflects_membership);
	ATF_TP_ADD_TC(tp, list_is_scoped_to_own_session);
	return (atf_no_error());
}
