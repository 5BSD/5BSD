/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/*
 * Tier authorization (docs/book/src/plane/anointments.md rows B1-B6).  The
 * decision point is router_session_authorized(): the session's tier picked
 * its policy at admission via notify_policy_db_select(), and ADMIN rights
 * bypass policy on either tier.  Positive rows are also pushed through
 * router_handle_request() to prove the request itself succeeds.
 */
static size_t
publish_request(void *storage, const char *name)
{
	struct notify_publish_request publish;

	memset(&publish, 0, sizeof(publish));
	publish.topic_length = strlen(name);
	memcpy(publish.topic, name, publish.topic_length);
	return (request(storage, NOTIFY_OP_PUBLISH, &publish, sizeof(publish)));
}

static size_t
topic_request(void *storage, uint16_t opcode, const char *name)
{
	struct notify_topic_request topic;

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = strlen(name);
	memcpy(topic.topic, name, topic.topic_length);
	return (request(storage, opcode, &topic, sizeof(topic)));
}

static size_t
state_set_request(void *storage, const char *name)
{
	struct notify_state_set_request state;

	memset(&state, 0, sizeof(state));
	state.state = 1;
	state.topic_length = strlen(name);
	memcpy(state.topic, name, state.topic_length);
	return (request(storage, NOTIFY_OP_STATE_SET, &state, sizeof(state)));
}

static size_t
timer_request(void *storage)
{
	struct notify_timer_request timer;

	timer = (struct notify_timer_request){ .timer_id = 5,
	    .interval_ms = 1000 };
	return (request(storage, NOTIFY_OP_TIMER_ADD, &timer, sizeof(timer)));
}

static bool
authorized(const struct router_session *session, const void *storage,
    const char *expected_operation)
{
	const char *operation;
	bool result;

	operation = NULL;
	result = router_session_authorized(session, storage, &operation);
	ATF_REQUIRE(operation != NULL);
	ATF_CHECK_STREQ(expected_operation, operation);
	return (result);
}

/* Admit the fixture session on a tier with the given label and rights. */
static void
fixture_tier(struct fixture *fixture, const struct notify_policy_db *db,
    uint32_t tier, const char *label, service_rights_t rights)
{

	fixture->session.tier = tier;
	fixture->session.rights = rights;
	strlcpy(fixture->session.label, label, sizeof(fixture->session.label));
	fixture->session.policy = notify_policy_db_select(db, tier, label);
	ATF_REQUIRE(fixture->session.policy != NULL);
}

/* Round-trip a request through the router and return its status. */
static int32_t
request_status(struct fixture *fixture, void *storage, size_t length)
{
	union notify_buffer incoming;
	const struct notify_msg *reply;

	ATF_REQUIRE(roundtrip(fixture, storage, length, incoming.bytes,
	    sizeof(incoming)) >= (ssize_t)sizeof(*reply));
	reply = (const void *)incoming.bytes;
	return (reply->status);
}

ATF_TC_WITHOUT_HEAD(tier_open_default_user);
ATF_TC_BODY(tier_open_default_user, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* Shipped default: no conf blocks at all -> builtins. */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("clients {};", db));
	fixture_open(&fixture);
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "org.5bsd.user-session", 0);

	/* B1: subscribe system.shutdown.x -> ok (and really succeeds). */
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE,
	    "system.shutdown.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET,
	    "system.shutdown.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-get"));

	/* B2: publish user.me.x -> ok (and really succeeds). */
	length = publish_request(outgoing.bytes, "user.me.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = publish_request(outgoing.bytes, "user.me");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	length = state_set_request(outgoing.bytes, "user.me.state");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-set"));

	/* B3: publish system.x / state under system.* / timers -> EACCES. */
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "user");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "users.me.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_CLEAR,
	    "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-clear"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

ATF_TC_WITHOUT_HEAD(tier_system_default_unit);
ATF_TC_BODY(tier_system_default_unit, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("clients {};", db));
	fixture_open(&fixture);
	/* B4: com.example.pub on the system tier, no clients{} entry. */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example.pub", 0);
	ATF_CHECK(fixture.session.policy == &db->system_default);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "timer-add"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-set"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "any.thing");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	fixture_close(&fixture);
	free(db);
}

ATF_TC_WITHOUT_HEAD(tier_system_clients_narrow);
ATF_TC_BODY(tier_system_clients_narrow, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	/* B5: clients { "com.example.pub" { publish = ["system.shutdown.*"] } } */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"com.example/pub\" { publish = [\"system.shutdown.*\"]; } }",
	    db));
	fixture_open(&fixture);
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/pub", 0);
	ATF_CHECK(fixture.session.policy != &db->system_default);
	length = publish_request(outgoing.bytes, "system.shutdown.now");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = publish_request(outgoing.bytes, "system.other");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "system.shutdown");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	/* The entry REPLACES system_default: nothing else was granted. */
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE,
	    "system.shutdown.now");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));

	/* Another label on the same tier is untouched by that entry. */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/other", 0);
	ATF_CHECK(fixture.session.policy == &db->system_default);
	length = publish_request(outgoing.bytes, "system.other");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));

	/*
	 * The same label on the OPEN tier never sees clients{}: it gets the
	 * open default, so system.shutdown.now is denied and user.* allowed.
	 */
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "com.example/pub", 0);
	ATF_CHECK(fixture.session.policy == &db->open_default);
	length = publish_request(outgoing.bytes, "system.shutdown.now");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "user.pub.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE,
	    "system.shutdown.now");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

ATF_TC_WITHOUT_HEAD(tier_open_admin_bypass);
ATF_TC_BODY(tier_open_admin_bypass, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"org.5bsd/narrow\" { publish = [\"a.b\"]; } }", db));
	fixture_open(&fixture);
	/* B6: root on system.Notify (open tier) with ADMIN publishes system.x. */
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "org.5bsd.user-session",
	    SERVICE_RIGHTS_ADMIN);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	/* Without ADMIN the very same session is bound by the open policy. */
	fixture.session.rights = 0;
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	/* ADMIN also bypasses a narrowing clients{} entry on the system tier. */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "org.5bsd/narrow",
	    SERVICE_RIGHTS_ADMIN);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	fixture.session.rights = 0;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

ATF_TC_WITHOUT_HEAD(admission_control_tier_validation);
ATF_TC_BODY(admission_control_tier_validation, tc)
{
	struct router_control control;

	memset(&control, 0, sizeof(control));
	control.magic = ROUTER_CONTROL_MAGIC;
	control.queue_depth = NOTIFY_DEFAULT_QUEUE;
	strlcpy(control.label, "org.5bsd/unit", sizeof(control.label));
	control.tier = NOTIFY_TIER_OPEN;
	ATF_CHECK(router_control_valid(&control));
	control.tier = NOTIFY_TIER_SYSTEM;
	ATF_CHECK(router_control_valid(&control));
	/* Only the two known tiers admit; anything else is a protocol error. */
	control.tier = 2;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = UINT32_MAX;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = NOTIFY_TIER_OPEN;
	control.magic = 0;
	ATF_CHECK(!router_control_valid(&control));
	control.magic = ROUTER_CONTROL_MAGIC;
	control.queue_depth = 0;
	ATF_CHECK(!router_control_valid(&control));
	control.queue_depth = NOTIFY_DEFAULT_QUEUE + 1;
	ATF_CHECK(!router_control_valid(&control));
	control.queue_depth = NOTIFY_DEFAULT_QUEUE;
	control.label[0] = '\0';
	ATF_CHECK(!router_control_valid(&control));
	ATF_CHECK(!router_control_valid(NULL));
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

/*
 * ---------------------------------------------------------------------------
 * Edge-case and negative tier coverage.  A request that fails the wire
 * validator never reaches router_session_authorized() in the daemon (the
 * channel path validates first, see router_channel_request), so malformed
 * topics are checked against both: the validator must refuse them, and the
 * policy verdict is recorded so the ordering stays visible.
 * ---------------------------------------------------------------------------
 */

/* Like request() but without the validity requirement. */
static size_t
raw_request(void *storage, uint16_t opcode, const void *payload,
    size_t length)
{
	struct notify_msg *message;

	memset(storage, 0, NOTIFY_MAX_MESSAGE);
	message = storage;
	ATF_REQUIRE_EQ(0, notify_message_init(message, opcode, 0));
	if (length != 0)
		memcpy(message + 1, payload, length);
	return (sizeof(*message) + length);
}

static size_t
raw_publish_request(void *storage, const char *name, size_t name_length)
{
	struct notify_publish_request publish;

	memset(&publish, 0, sizeof(publish));
	publish.topic_length = name_length;
	memcpy(publish.topic, name, name_length);
	return (raw_request(storage, NOTIFY_OP_PUBLISH, &publish,
	    sizeof(publish)));
}

static size_t
raw_topic_request(void *storage, uint16_t opcode, const char *name,
    size_t name_length)
{
	struct notify_topic_request topic;

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = name_length;
	memcpy(topic.topic, name, name_length);
	return (raw_request(storage, opcode, &topic, sizeof(topic)));
}

static size_t
timer_cancel_request(void *storage, uint64_t id)
{
	struct notify_timer_cancel_request cancel;

	cancel = (struct notify_timer_cancel_request){ .timer_id = id };
	return (request(storage, NOTIFY_OP_TIMER_CANCEL, &cancel,
	    sizeof(cancel)));
}

static size_t
list_request(void *storage, uint16_t opcode)
{
	struct notify_list_request list;

	memset(&list, 0, sizeof(list));
	return (request(storage, opcode, &list, sizeof(list)));
}

static bool
wire_valid(const void *storage, size_t length)
{

	return (notify_validate_message(storage, length,
	    NOTIFY_MESSAGE_REQUEST) == 0);
}

/*
 * Open tier, builtin policy: every opcode's verdict, plus the malformed
 * topics that must die at the validator before policy is asked.
 */
ATF_TC_WITHOUT_HEAD(tier_open_every_opcode);
ATF_TC_BODY(tier_open_every_opcode, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("", db));
	fixture_open(&fixture);
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "org.5bsd.user-session", 0);

	/* publish: only user.<something> */
	length = publish_request(outgoing.bytes, "user");
	ATF_CHECK(wire_valid(outgoing.bytes, length));
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "userx.y");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "users");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "system.user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "User.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	/* "user." is not a topic: refused on the wire; policy would deny too */
	length = raw_publish_request(outgoing.bytes, "user.", 5);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	/* "user..x" is not a topic either; here the validator is the guard */
	length = raw_publish_request(outgoing.bytes, "user..x", 7);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	/* an empty topic: refused on the wire */
	length = raw_publish_request(outgoing.bytes, "", 0);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	/* a topic with an embedded NUL inside a claimed length */
	length = raw_publish_request(outgoing.bytes, "user.\0x", 7);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	/* a length beyond the field */
	length = raw_publish_request(outgoing.bytes, "user.x", 6);
	((struct notify_publish_request *)(void *)
	    ((struct notify_msg *)(void *)outgoing.bytes + 1))->topic_length =
	    NOTIFY_MAX_TOPIC + 1;
	ATF_CHECK(!wire_valid(outgoing.bytes, length));

	/* subscribe: anything; the empty topic dies on the wire */
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "a");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = raw_topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "", 0);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	/*
	 * subscribe_all makes the matcher say yes even to an empty topic:
	 * recorded here so nobody moves authorization ahead of validation.
	 */
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = raw_topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE,
	    "bad topic", 9);
	ATF_CHECK(!wire_valid(outgoing.bytes, length));
	/* unsubscribe follows the subscribe rule */
	length = topic_request(outgoing.bytes, NOTIFY_OP_UNSUBSCRIBE,
	    "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "unsubscribe"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));

	/* state-set / state-clear follow the publish rule */
	length = state_set_request(outgoing.bytes, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-set"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	length = state_set_request(outgoing.bytes, "user");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_CLEAR, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-clear"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_CLEAR,
	    "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-clear"));
	/* state-get follows the subscribe rule (read side) */
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-get"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-get"));

	/* timers: both add and cancel denied */
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	length = timer_cancel_request(outgoing.bytes, 5);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-cancel"));

	/* introspection: always allowed, and really succeeds */
	length = list_request(outgoing.bytes, NOTIFY_OP_LIST_SUBSCRIPTIONS);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes,
	    "list-subscriptions"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = list_request(outgoing.bytes, NOTIFY_OP_LIST_TIMERS);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "list-timers"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = request(outgoing.bytes, NOTIFY_OP_HELLO, NULL, 0);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "request"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = request(outgoing.bytes, NOTIFY_OP_STATS, NULL, 0);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "request"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

/* An explicit empty list in a clients{} entry denies that operation. */
ATF_TC_WITHOUT_HEAD(tier_system_clients_explicit_empty_lists);
ATF_TC_BODY(tier_system_clients_explicit_empty_lists, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients {"
	    " \"com.example/reader\" { publish = []; subscribe = [\"system.a\"]; }"
	    " \"com.example/listener\" { subscribe = [\"*\"]; }"
	    " \"com.example/nothing\" { }"
	    " \"com.example/timers\" { timers = true; }"
	    "}", db));
	fixture_open(&fixture);

	/* publish = [] : no publishing at all; subscribe as listed */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/reader", 0);
	length = publish_request(outgoing.bytes, "system.a");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = state_set_request(outgoing.bytes, "system.a");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.a");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET, "system.a");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-get"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.b");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE,
	    "system.a.b");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));

	/* subscribe = ["*"] only : read everything, write nothing */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/listener",
	    0);
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "any.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET, "any.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-get"));
	length = publish_request(outgoing.bytes, "any.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = state_set_request(outgoing.bytes, "any.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_CLEAR, "any.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-clear"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));

	/* {} : listed but granted nothing, only introspection survives */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/nothing",
	    0);
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "any.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = publish_request(outgoing.bytes, "any.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	length = list_request(outgoing.bytes, NOTIFY_OP_LIST_SUBSCRIPTIONS);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes,
	    "list-subscriptions"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = request(outgoing.bytes, NOTIFY_OP_STATS, NULL, 0);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "request"));

	/* timers only : add and cancel, nothing topic-shaped */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "com.example/timers", 0);
	length = timer_request(outgoing.bytes);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "timer-add"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_cancel_request(outgoing.bytes, 5);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "timer-cancel"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

/*
 * ADMIN on the system tier beats a narrowing clients{} entry and an
 * explicit deny-all system_default; any other rights bit does not.
 */
ATF_TC_WITHOUT_HEAD(tier_system_admin_bypasses_narrowing);
ATF_TC_BODY(tier_system_admin_bypasses_narrowing, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "system_default {}"
	    "clients { \"org.5bsd/narrow\" { publish = [\"a.b\"]; } }", db));
	fixture_open(&fixture);
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "org.5bsd/narrow",
	    SERVICE_RIGHTS_ADMIN);
	ATF_CHECK(fixture.session.policy == notify_policy_db_lookup(db,
	    "org.5bsd/narrow"));
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_cancel_request(outgoing.bytes, 5);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	/* ADMIN inside a wider mask still counts */
	fixture.session.rights = SERVICE_RIGHTS_ALL;
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	/* every non-ADMIN bit pattern is bound by the narrow entry */
	fixture.session.rights = SERVICE_RIGHTS_ALL & ~SERVICE_RIGHTS_ADMIN;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	fixture.session.rights = (service_rights_t)1;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	fixture.session.rights = SERVICE_RIGHTS_ADMIN >> 1;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	fixture.session.rights = SERVICE_RIGHTS_NONE;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "a.b");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	/* and ADMIN over an explicit deny-all system_default (unlisted label) */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "org.5bsd/unlisted",
	    SERVICE_RIGHTS_ADMIN);
	ATF_CHECK(fixture.session.policy == &db->system_default);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	fixture.session.rights = 0;
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

/*
 * The admission record.  Everything router_add_session() refuses with
 * EPROTO is decided by router_control_valid(); the record-level rules are
 * pinned here field by field.  (router_add_session itself is compiled out
 * of the router test build, so the EPROTO mapping is asserted through the
 * classifier the parent uses on the reply.)
 */
ATF_TC_WITHOUT_HEAD(admission_control_field_by_field);
ATF_TC_BODY(admission_control_field_by_field, tc)
{
	struct router_control control, good;
	int error;

	memset(&good, 0, sizeof(good));
	good.magic = ROUTER_CONTROL_MAGIC;
	good.queue_depth = NOTIFY_DEFAULT_QUEUE;
	good.tier = NOTIFY_TIER_SYSTEM;
	strlcpy(good.label, "org.5bsd/unit", sizeof(good.label));
	ATF_REQUIRE(router_control_valid(&good));

	/* label: empty, over-long, unterminated */
	control = good;
	control.label[0] = '\0';
	ATF_CHECK(!router_control_valid(&control));
	control = good;
	memset(control.label, 'l', sizeof(control.label));
	ATF_CHECK(!router_control_valid(&control));
	control = good;
	memset(control.label, 'l', NOTIFY_MAX_PUBLISHER);
	control.label[NOTIFY_MAX_PUBLISHER] = '\0';
	ATF_CHECK(router_control_valid(&control));
	control = good;
	control.label[0] = 'x';
	control.label[1] = '\0';
	ATF_CHECK(router_control_valid(&control));
	/* the record does not care about the label's shape; policy does */
	control = good;
	strlcpy(control.label, "no separator here", sizeof(control.label));
	ATF_CHECK(router_control_valid(&control));

	/* queue depth: 0, over the maximum; 1 and the maximum admit */
	control = good;
	control.queue_depth = 0;
	ATF_CHECK(!router_control_valid(&control));
	control.queue_depth = NOTIFY_DEFAULT_QUEUE + 1;
	ATF_CHECK(!router_control_valid(&control));
	control.queue_depth = UINT32_MAX;
	ATF_CHECK(!router_control_valid(&control));
	control.queue_depth = 1;
	ATF_CHECK(router_control_valid(&control));
	control.queue_depth = NOTIFY_DEFAULT_QUEUE;
	ATF_CHECK(router_control_valid(&control));

	/* tier: only 0 and 1 */
	control = good;
	control.tier = 2;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = 255;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = (uint32_t)-1;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = 0x10000U | NOTIFY_TIER_SYSTEM;
	ATF_CHECK(!router_control_valid(&control));
	control.tier = NOTIFY_TIER_OPEN;
	ATF_CHECK(router_control_valid(&control));

	/* magic: zero, off by one, byte-swapped */
	control = good;
	control.magic = 0;
	ATF_CHECK(!router_control_valid(&control));
	control.magic = ROUTER_CONTROL_MAGIC + 1;
	ATF_CHECK(!router_control_valid(&control));
	control.magic = ROUTER_CONTROL_MAGIC - 1;
	ATF_CHECK(!router_control_valid(&control));
	control.magic = __builtin_bswap32(ROUTER_CONTROL_MAGIC);
	ATF_CHECK(!router_control_valid(&control));
	control.magic = ROUTER_CONTROL_MAGIC;
	ATF_CHECK(router_control_valid(&control));

	/* rights are opaque to admission: any value admits */
	control = good;
	control.rights = SERVICE_RIGHTS_ALL;
	ATF_CHECK(router_control_valid(&control));
	control.rights = SERVICE_RIGHTS_NONE;
	ATF_CHECK(router_control_valid(&control));

	/* the parent maps a refused record to a fatal EPROTO */
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply), 0, EPROTO, &error));
	ATF_CHECK_EQ(EPROTO, error);
	/* a reply status that is not an errno is also a protocol error */
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply), 0, ELAST + 1, &error));
	ATF_CHECK_EQ(EPROTO, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply), 0, -1, &error));
	ATF_CHECK_EQ(EPROTO, error);
	/* a short or long reply */
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply) - 1, 0, 0, &error));
	ATF_CHECK_EQ(EPROTO, error);
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply) + 1, 0, 0, &error));
	ATF_CHECK_EQ(EPROTO, error);
	/* no error slot: fatal, nothing dereferenced */
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL, router_admission_classify(0,
	    sizeof(struct router_control_reply), 0, 0, NULL));
	/* a -1 call result with errno 0 is reported as EIO, never 0 */
	errno = 0;
	ATF_CHECK_EQ(ROUTER_ADMISSION_FATAL,
	    router_admission_classify(-1, 0, 0, 0, &error));
	ATF_CHECK_EQ(EIO, error);
}

/* Round-trip one request on an arbitrary session/peer pair. */
static int32_t
session_status(struct fixture *fixture, struct router_session *session,
    int peer, void *storage, size_t length)
{
	union notify_buffer incoming;
	const struct notify_msg *reply;

	ATF_REQUIRE_EQ(0, internal_send(peer, storage, length,
	    NOTIFY_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0, router_handle_request(&fixture->router, session,
	    NULL));
	ATF_REQUIRE(internal_receive(peer, incoming.bytes, sizeof(incoming),
	    NOTIFY_MESSAGE_REPLY) >= (ssize_t)sizeof(*reply));
	reply = (const void *)incoming.bytes;
	return (reply->status);
}

/*
 * The same label admitted twice, once per tier: each session carries its
 * own tier policy and both are served by the one broker, so a program can
 * hold an open-tier and a system-tier handle at the same time and neither
 * leaks into the other.
 */
ATF_TC_WITHOUT_HEAD(same_label_two_tiers_coexist);
ATF_TC_BODY(same_label_two_tiers_coexist, tc)
{
	union notify_buffer outgoing, incoming;
	struct notify_policy_db *db;
	struct fixture fixture;
	struct router_session other;
	struct notify_next_request next;
	const struct notify_msg *reply;
	const struct notify_event *event;
	int pair[2];
	size_t length;
	ssize_t received;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"com.example/pub\" { publish = [\"system.shutdown.*\"];"
	    " subscribe = [\"user.*\"]; } }", db));
	fixture_open(&fixture);
	/* session 1: open tier (re-register its broker client under the label) */
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "com.example/pub", 0);
	notify_broker_remove(fixture.router.broker, fixture.session.client);
	fixture.session.client = notify_broker_add(fixture.router.broker,
	    fixture.session.label, NOTIFY_DEFAULT_QUEUE);
	ATF_REQUIRE(fixture.session.client != NULL);
	/* session 2: system tier, same label, own socket and broker client */
	memset(&other, 0, sizeof(other));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	other.fd = pair[1];
	other.source.type = ROUTER_EVENT_SESSION;
	other.router = &fixture.router;
	other.tier = NOTIFY_TIER_SYSTEM;
	strlcpy(other.label, "com.example/pub", sizeof(other.label));
	other.client = notify_broker_add(fixture.router.broker, other.label,
	    NOTIFY_DEFAULT_QUEUE);
	ATF_REQUIRE(other.client != NULL);
	other.policy = notify_policy_db_select(db, other.tier, other.label);
	ATF_REQUIRE(other.policy != NULL);
	other.next = fixture.router.sessions;
	fixture.router.sessions = &other;

	ATF_CHECK(fixture.session.policy == &db->open_default);
	ATF_CHECK(other.policy == notify_policy_db_lookup(db, "com.example/pub"));
	ATF_CHECK(fixture.session.policy != other.policy);
	ATF_CHECK(fixture.session.client != other.client);

	/* verdicts differ per session for the very same request bytes */
	length = publish_request(outgoing.bytes, "system.shutdown.now");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK(authorized(&other, outgoing.bytes, "publish"));
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK(!authorized(&other, outgoing.bytes, "publish"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "subscribe"));
	ATF_CHECK(!authorized(&other, outgoing.bytes, "subscribe"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	ATF_CHECK(!authorized(&other, outgoing.bytes, "timer-add"));

	/* both sessions are live on the broker: a publish on one reaches the other */
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "user.x");
	ATF_CHECK_EQ(0, session_status(&fixture, &other, pair[0],
	    outgoing.bytes, length));
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK_EQ(0, session_status(&fixture, &fixture.session,
	    fixture.peer, outgoing.bytes, length));
	memset(&next, 0, sizeof(next));
	length = request(outgoing.bytes, NOTIFY_OP_NEXT, &next, sizeof(next));
	ATF_REQUIRE_EQ(0, internal_send(pair[0], outgoing.bytes, length,
	    NOTIFY_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0, router_handle_request(&fixture.router, &other, NULL));
	received = internal_receive(pair[0], incoming.bytes, sizeof(incoming),
	    NOTIFY_MESSAGE_REPLY);
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	reply = (const void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	event = (const void *)(reply + 1);
	ATF_CHECK_EQ(NOTIFY_EVENT_PUBLISH, event->type);
	/* the publisher label is the shared one */
	ATF_CHECK_EQ(strlen("com.example/pub"), event->publisher_length);
	ATF_CHECK_EQ(0, memcmp(event->data, "com.example/pub",
	    event->publisher_length));
	/* the open session did not subscribe: nothing queued for it */
	length = request(outgoing.bytes, NOTIFY_OP_NEXT, &next, sizeof(next));
	ATF_CHECK_EQ(-EAGAIN, session_status(&fixture, &fixture.session,
	    fixture.peer, outgoing.bytes, length));
	/* subscriptions are per session, not per label */
	length = list_request(outgoing.bytes, NOTIFY_OP_LIST_SUBSCRIPTIONS);
	ATF_REQUIRE_EQ(0, internal_send(fixture.peer, outgoing.bytes, length,
	    NOTIFY_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0, router_handle_request(&fixture.router,
	    &fixture.session, NULL));
	received = internal_receive(fixture.peer, incoming.bytes,
	    sizeof(incoming), NOTIFY_MESSAGE_REPLY);
	ATF_REQUIRE(received >= (ssize_t)(sizeof(*reply) +
	    sizeof(struct notify_list_reply)));
	reply = (const void *)incoming.bytes;
	ATF_CHECK_EQ(0, ((const struct notify_list_reply *)(const void *)
	    (reply + 1))->total);

	fixture.router.sessions = other.next;
	notify_broker_remove(fixture.router.broker, other.client);
	close(pair[0]);
	close(other.fd);
	fixture_close(&fixture);
	free(db);
}

/*
 * The login-session label the auth agent mints ("org.5bsd.user-session")
 * is nothing special to bsdnotify: on the system tier it takes
 * system_default like any unlisted label, and a clients{} entry can narrow
 * it like any other.  (It has no '/', so it can only be listed if the label
 * grammar allowed it; it does not, which is the point: it can never be
 * narrowed, only tier-selected.)
 */
ATF_TC_WITHOUT_HEAD(user_session_label_not_special);
ATF_TC_BODY(user_session_label_not_special, tc)
{
	union notify_buffer outgoing;
	struct notify_policy_db *db;
	struct fixture fixture;
	size_t length;

	db = calloc(1, sizeof(*db));
	ATF_REQUIRE(db != NULL);
	ATF_REQUIRE_EQ(0, notify_policy_db_parse(
	    "clients { \"com.example/pub\" { publish = [\"a.b\"]; } }", db));
	fixture_open(&fixture);
	/* system tier, no entry: full system_default including timers */
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "org.5bsd.user-session",
	    0);
	ATF_CHECK(fixture.session.policy == &db->system_default);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "publish"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "timer-add"));
	ATF_CHECK_EQ(0, request_status(&fixture, outgoing.bytes, length));
	length = state_set_request(outgoing.bytes, "system.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "state-set"));
	/* open tier: the plain open default, as for every label */
	fixture_tier(&fixture, db, NOTIFY_TIER_OPEN, "org.5bsd.user-session", 0);
	ATF_CHECK(fixture.session.policy == &db->open_default);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = timer_cancel_request(outgoing.bytes, 5);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-cancel"));
	/* the label cannot appear in clients{} (no separator) */
	ATF_CHECK_ERRNO(EINVAL, notify_policy_db_parse(
	    "clients { \"org.5bsd.user-session\" { publish = []; } }", db) == -1);
	/* an explicit system_default {} narrows it like everyone else */
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("system_default {}", db));
	fixture_tier(&fixture, db, NOTIFY_TIER_SYSTEM, "org.5bsd.user-session",
	    0);
	length = publish_request(outgoing.bytes, "system.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = timer_request(outgoing.bytes);
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "timer-add"));
	(void)length;
	fixture_close(&fixture);
	free(db);
}

/*
 * A session with no policy (what router_add_session refuses at admission)
 * is denied everything topic-shaped by the relay check itself; ADMIN is
 * the only way through.  Guards against a future "policy == NULL means
 * unrestricted" regression.
 */
ATF_TC_WITHOUT_HEAD(null_policy_fails_closed);
ATF_TC_BODY(null_policy_fails_closed, tc)
{
	union notify_buffer outgoing;
	struct fixture fixture;
	size_t length;

	fixture_open(&fixture);
	fixture.session.policy = NULL;
	fixture.session.rights = 0;
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "publish"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_SUBSCRIBE, "user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "subscribe"));
	length = topic_request(outgoing.bytes, NOTIFY_OP_STATE_GET, "user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-get"));
	length = state_set_request(outgoing.bytes, "user.x");
	ATF_CHECK(!authorized(&fixture.session, outgoing.bytes, "state-set"));
	fixture.session.rights = SERVICE_RIGHTS_ADMIN;
	length = publish_request(outgoing.bytes, "user.x");
	ATF_CHECK(authorized(&fixture.session, outgoing.bytes, "admin"));
	(void)length;
	fixture_close(&fixture);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hello_stats_and_errors);
	ATF_TP_ADD_TC(tp, pubsub_state_and_next);
	ATF_TP_ADD_TC(tp, timers_and_pending_request);
	ATF_TP_ADD_TC(tp, admission_failure_classes);
	ATF_TP_ADD_TC(tp, admission_control_tier_validation);
	ATF_TP_ADD_TC(tp, tier_open_default_user);
	ATF_TP_ADD_TC(tp, tier_system_default_unit);
	ATF_TP_ADD_TC(tp, tier_system_clients_narrow);
	ATF_TP_ADD_TC(tp, tier_open_admin_bypass);
	ATF_TP_ADD_TC(tp, timer_identifier_wrap_and_label_bounds);
	ATF_TP_ADD_TC(tp, list_subscriptions_reflects_membership);
	ATF_TP_ADD_TC(tp, list_subscriptions_paginates);
	ATF_TP_ADD_TC(tp, list_timers_reflects_membership);
	ATF_TP_ADD_TC(tp, list_is_scoped_to_own_session);
	ATF_TP_ADD_TC(tp, tier_open_every_opcode);
	ATF_TP_ADD_TC(tp, tier_system_clients_explicit_empty_lists);
	ATF_TP_ADD_TC(tp, tier_system_admin_bypasses_narrowing);
	ATF_TP_ADD_TC(tp, admission_control_field_by_field);
	ATF_TP_ADD_TC(tp, same_label_two_tiers_coexist);
	ATF_TP_ADD_TC(tp, user_session_label_not_special);
	ATF_TP_ADD_TC(tp, null_policy_fails_closed);
	return (atf_no_error());
}
