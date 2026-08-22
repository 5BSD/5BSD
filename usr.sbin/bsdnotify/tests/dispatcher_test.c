/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define NOTIFYCMP_ROUTER_TEST
#include "../notifycmp.c"

struct fixture {
	struct router router;
	struct router_session session;
	struct notifycmp_broker_client *publisher;
	int peer;
};

static void
fixture_open(struct fixture *fixture)
{
	int pair[2];

	memset(fixture, 0, sizeof(*fixture));
	fixture->router.kq = kqueue();
	ATF_REQUIRE(fixture->router.kq >= 0);
	fixture->router.broker = notifycmp_broker_create();
	ATF_REQUIRE(fixture->router.broker != NULL);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	fixture->peer = pair[0];
	fixture->session.fd = pair[1];
	strlcpy(fixture->session.label, "tests.subscriber",
	    sizeof(fixture->session.label));
	fixture->session.client = notifycmp_broker_add(fixture->router.broker,
	    fixture->session.label, NOTIFYCMP_DEFAULT_QUEUE);
	ATF_REQUIRE(fixture->session.client != NULL);
	fixture->session.source.type = ROUTER_EVENT_SESSION;
	fixture->router.sessions = &fixture->session;
	fixture->publisher = notifycmp_broker_add(fixture->router.broker,
	    "tests.publisher", NOTIFYCMP_DEFAULT_QUEUE);
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
	notifycmp_broker_remove(fixture->router.broker, fixture->publisher);
	notifycmp_broker_remove(fixture->router.broker, fixture->session.client);
	notifycmp_broker_destroy(fixture->router.broker);
	close(fixture->peer);
	close(fixture->session.fd);
	close(fixture->router.kq);
}

static size_t
request(void *storage, uint16_t opcode, const void *payload, size_t length)
{
	struct notifycmp_msg *message;

	memset(storage, 0, NOTIFYCMP_MAX_MESSAGE);
	message = storage;
	ATF_REQUIRE_EQ(0, notifycmp_message_init(message, opcode, 0));
	if (length != 0)
		memcpy(message + 1, payload, length);
	ATF_REQUIRE_EQ(0, notifycmp_validate_message(message,
	    sizeof(*message) + length, NOTIFYCMP_MESSAGE_REQUEST));
	return (sizeof(*message) + length);
}

static ssize_t
roundtrip(struct fixture *fixture, void *request_data, size_t request_length,
    void *reply, size_t reply_capacity)
{

	ATF_REQUIRE_EQ(0, internal_send(fixture->peer, request_data,
	    request_length, NOTIFYCMP_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0,
	    router_handle_request(&fixture->router, &fixture->session, NULL));
	return (internal_receive(fixture->peer, reply, reply_capacity,
	    NOTIFYCMP_MESSAGE_REPLY));
}

ATF_TC_WITHOUT_HEAD(hello_stats_and_errors);
ATF_TC_BODY(hello_stats_and_errors, tc)
{
	union notifycmp_buffer outgoing, incoming;
	struct notifycmp_msg *reply;
	struct fixture fixture;
	ssize_t received;
	size_t length;

	fixture_open(&fixture);
	length = request(outgoing.bytes, NOTIFYCMP_OP_HELLO, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	ATF_CHECK_EQ(NOTIFYCMP_OP_HELLO, reply->opcode);

	length = request(outgoing.bytes, NOTIFYCMP_OP_STATS, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notifycmp_stats), received);

	/* A malformed frame is fatal to this internal router session. */
	memset(outgoing.bytes, 0, sizeof(struct notifycmp_msg));
	ATF_REQUIRE(send(fixture.peer, outgoing.bytes,
	    sizeof(struct notifycmp_msg), 0) > 0);
	ATF_CHECK_ERRNO(EPROTO,
	    router_handle_request(&fixture.router, &fixture.session, NULL) == -1);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(pubsub_state_and_next);
ATF_TC_BODY(pubsub_state_and_next, tc)
{
	union notifycmp_buffer outgoing, incoming;
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct notifycmp_publish_request) + 32];
	} publish_storage;
	struct notifycmp_publish_request *publish;
	struct notifycmp_topic_request topic;
	struct notifycmp_state_set_request state;
	struct notifycmp_next_request next;
	struct notifycmp_event *event;
	struct notifycmp_msg *reply;
	struct fixture fixture;
	static const char name[] = "org.5bsd.tests.changed";
	uint8_t expected[32];
	ssize_t received;
	size_t i, length;

	fixture_open(&fixture);
	memset(&topic, 0, sizeof(topic));
	topic.topic_length = sizeof(name) - 1;
	memcpy(topic.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFYCMP_OP_SUBSCRIBE, &topic,
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
	length = request(outgoing.bytes, NOTIFYCMP_OP_PUBLISH, publish,
	    sizeof(*publish) + sizeof(expected));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	memset(&next, 0, sizeof(next));
	length = request(outgoing.bytes, NOTIFYCMP_OP_NEXT, &next, sizeof(next));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE(received > (ssize_t)sizeof(*reply));
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	event = (void *)(reply + 1);
	ATF_CHECK_EQ(NOTIFYCMP_EVENT_PUBLISH, event->type);
	ATF_CHECK_EQ(strlen(fixture.session.label), event->publisher_length);
	ATF_CHECK_EQ(0, memcmp(event->data, fixture.session.label,
	    event->publisher_length));
	ATF_CHECK_EQ(sizeof(expected), event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event->data + event->publisher_length +
	    event->topic_length, expected, sizeof(expected)));

	length = request(outgoing.bytes, NOTIFYCMP_OP_UNSUBSCRIBE, &topic,
	    sizeof(topic));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(0, reply->status);
	/* An unsubscribed client must not receive later publications. */
	ATF_REQUIRE_EQ(0, notifycmp_broker_publish(fixture.router.broker,
	    fixture.publisher, name, sizeof(name) - 1, "ignored", 7));
	memset(&next, 0, sizeof(next));
	length = request(outgoing.bytes, NOTIFYCMP_OP_NEXT, &next, sizeof(next));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EAGAIN, reply->status);

	memset(&state, 0, sizeof(state));
	state.state = 42;
	state.topic_length = sizeof(name) - 1;
	memcpy(state.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFYCMP_OP_STATE_SET, &state,
	    sizeof(state));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notifycmp_state_reply),
	    received);

	length = request(outgoing.bytes, NOTIFYCMP_OP_STATE_GET, &topic,
	    sizeof(topic));
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply) + sizeof(struct notifycmp_state_reply),
	    received);
	fixture_close(&fixture);
}

ATF_TC_WITHOUT_HEAD(timers_and_pending_request);
ATF_TC_BODY(timers_and_pending_request, tc)
{
	union notifycmp_buffer outgoing, incoming;
	struct notifycmp_timer_cancel_request cancel;
	struct notifycmp_timer_request timer;
	struct notifycmp_topic_request topic;
	struct notifycmp_next_request next;
	struct notifycmp_msg *reply;
	struct fixture fixture;
	static const char name[] = "org.5bsd.tests.pending";
	ssize_t received;
	size_t length;

	fixture_open(&fixture);
	timer = (struct notifycmp_timer_request){
	    .timer_id = 7, .interval_ms = 1000 };
	length = request(outgoing.bytes, NOTIFYCMP_OP_TIMER_ADD, &timer,
	    sizeof(timer));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));
	/* Duplicate timer IDs are rejected without corrupting the original. */
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EEXIST, reply->status);
	cancel = (struct notifycmp_timer_cancel_request){ .timer_id = 7 };
	length = request(outgoing.bytes, NOTIFYCMP_OP_TIMER_CANCEL, &cancel,
	    sizeof(cancel));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));

	memset(&topic, 0, sizeof(topic));
	topic.topic_length = sizeof(name) - 1;
	memcpy(topic.topic, name, sizeof(name) - 1);
	length = request(outgoing.bytes, NOTIFYCMP_OP_SUBSCRIBE, &topic,
	    sizeof(topic));
	ATF_REQUIRE_EQ(sizeof(*reply), roundtrip(&fixture, outgoing.bytes, length,
	    incoming.bytes, sizeof(incoming)));

	next = (struct notifycmp_next_request){
	    .timeout_ms = NOTIFYCMP_TIMEOUT_INFINITE };
	length = request(outgoing.bytes, NOTIFYCMP_OP_NEXT, &next, sizeof(next));
	ATF_REQUIRE_EQ(0, internal_send(fixture.peer, outgoing.bytes, length,
	    NOTIFYCMP_MESSAGE_REQUEST));
	ATF_REQUIRE_EQ(0,
	    router_handle_request(&fixture.router, &fixture.session, NULL));
	ATF_REQUIRE(fixture.session.pending_active);
	length = request(outgoing.bytes, NOTIFYCMP_OP_HELLO, NULL, 0);
	received = roundtrip(&fixture, outgoing.bytes, length, incoming.bytes,
	    sizeof(incoming));
	ATF_REQUIRE_EQ(sizeof(*reply), received);
	reply = (void *)incoming.bytes;
	ATF_CHECK_EQ(-EBUSY, reply->status);
	ATF_CHECK(fixture.session.pending_active);
	ATF_REQUIRE_EQ(0, notifycmp_broker_publish(fixture.router.broker,
	    fixture.publisher, name, sizeof(name) - 1, NULL, 0));
	ATF_REQUIRE_EQ(0, router_deliver(&fixture.router, &fixture.session));
	received = internal_receive(fixture.peer, incoming.bytes, sizeof(incoming),
	    NOTIFYCMP_MESSAGE_REPLY);
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
	char overlong[NOTIFYCMP_MAX_PUBLISHER + 2];
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
	return (atf_no_error());
}
