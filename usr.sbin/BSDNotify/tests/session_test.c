/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The BSDNotify router (bsdnotify.c) serving bsd.notify.v1 sessions over
 * real capability channels to the real libnotify client, in process: a
 * router thread runs router_event() for the session and timer events, as
 * router_main() does.  Plane-on tier: without /dev/mac_capability the cases
 * skip.  Also the schema-evolution pairing with next_peer (bsd:2).
 */
#include <sys/param.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int bsdnotify_main(void);
#define main bsdnotify_main
#include "../bsdnotify.c"
#undef main

struct fixture {
	struct router router;
	struct notify_policy_db db;
	pthread_t thread;
	pthread_mutex_t lock;
	atomic_bool stop;
};

static void *
router_thread(void *argument)
{
	struct fixture *f = argument;
	struct timespec timeout = { 0, 20000000 };
	struct kevent events[16];
	int count;

	while (!atomic_load(&f->stop)) {
		count = kevent(f->router.kq, NULL, 0, events, nitems(events),
		    &timeout);
		pthread_mutex_lock(&f->lock);
		for (int i = 0; i < count; i++) {
			struct event_source *source = events[i].udata;

			if (source != NULL && source->type != 0)
				router_event(&f->router, source, &events[i]);
		}
		(void)router_deliver_pending(&f->router);
		router_collect_garbage(&f->router);
		pthread_mutex_unlock(&f->lock);
	}
	return (NULL);
}

static void
require_plane(void)
{
	int fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: %s",
		    strerror(errno));
	close(fd);
}

static void
fixture_start(struct fixture *f)
{
	require_plane();
	memset(f, 0, sizeof(*f));
	ATF_REQUIRE_EQ(0, notify_policy_db_parse("{}", &f->db));
	f->router.policy_db = &f->db;
	f->router.broker = notify_broker_create();
	f->router.kq = kqueue();
	ATF_REQUIRE(f->router.broker != NULL && f->router.kq >= 0);
	ATF_REQUIRE_EQ(0, pthread_mutex_init(&f->lock, NULL));
	ATF_REQUIRE_EQ(0, pthread_create(&f->thread, NULL, router_thread, f));
}

static void
fixture_stop(struct fixture *f)
{
	struct router_session *session;

	atomic_store(&f->stop, true);
	ATF_REQUIRE_EQ(0, pthread_join(f->thread, NULL));
	while ((session = f->router.sessions) != NULL)
		router_remove_session(&f->router, session);
	router_collect_garbage(&f->router);
	notify_broker_destroy(f->router.broker);
	close(f->router.kq);
}

/* Admit a session and return the client end of its channel. */
static int
admit(struct fixture *f, const char *label, uint32_t tier, uint64_t rights)
{
	struct router_control control = {
		.magic = ROUTER_CONTROL_MAGIC,
		.queue_depth = NOTIFY_DEFAULT_QUEUE,
		.tier = tier,
		.rights = rights
	};
	int ends[2];

	strlcpy(control.label, label, sizeof(control.label));
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	pthread_mutex_lock(&f->lock);
	ATF_REQUIRE_EQ(0, router_add_session(&f->router, &control, ends[1]));
	pthread_mutex_unlock(&f->lock);
	return (ends[0]);
}

static size_t
sessions(struct fixture *f)
{
	size_t n;

	/* Give the router a moment to notice a closed session. */
	usleep(100000);
	pthread_mutex_lock(&f->lock);
	n = f->router.nsessions;
	pthread_mutex_unlock(&f->lock);
	return (n);
}

ATF_TC(open_tier_round_trip);
ATF_TC_HEAD(open_tier_round_trip, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "The real client and router: subscribe, "
	    "publish, deliver, state and listing, with open-tier policy "
	    "refusals as EACCES that keep the session");
}
ATF_TC_BODY(open_tier_round_trip, tc)
{
	union notify_buffer buffer;
	struct notify_event *event = (void *)buffer.bytes;
	struct notify_subscription_info subs[4];
	struct notify_state_reply state;
	struct notify_client *client;
	struct notify_stats stats;
	struct fixture f;
	ssize_t length;

	fixture_start(&f);
	ATF_REQUIRE_EQ(0, notify_client_adopt(admit(&f, "org.test.notify",
	    NOTIFY_TIER_OPEN, SERVICE_RIGHTS_NONE), &client));
	ATF_REQUIRE_EQ(0, notify_subscribe(client, "user.alpha"));
	ATF_REQUIRE_EQ(0, notify_publish(client, "user.alpha", "x", 1));
	length = notify_next(client, event, sizeof(buffer), 2000);
	ATF_REQUIRE(length > 0);
	ATF_CHECK_EQ(NOTIFY_EVENT_PUBLISH, event->type);
	ATF_CHECK_EQ(strlen("org.test.notify"), event->publisher_length);
	ATF_CHECK_EQ(strlen("user.alpha"), event->topic_length);
	ATF_CHECK_EQ(1, event->payload_length);
	ATF_CHECK_EQ(0, memcmp(event->data, "org.test.notify",
	    event->publisher_length));
	/* Nothing more: a poll returns EAGAIN. */
	ATF_CHECK_ERRNO(EAGAIN, notify_next(client, event, sizeof(buffer),
	    0) == -1);
	ATF_REQUIRE_EQ(0, notify_state_set(client, "user.alpha", 7));
	ATF_REQUIRE_EQ(0, notify_state_get(client, "user.alpha", &state));
	ATF_CHECK_EQ(7, state.state);
	ATF_CHECK_EQ(1, notify_list_subscriptions(client, subs, nitems(subs)));
	ATF_CHECK_STREQ("user.alpha", subs[0].topic);
	/* Policy refusals are application errors. */
	ATF_CHECK_ERRNO(EACCES, notify_publish(client, "system.alpha", "x",
	    1) == -1);
	ATF_CHECK_ERRNO(EACCES, notify_timer_add(client, 1, 1000, 0) == -1);
	ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
	/* The broker counts the publish and the state change. */
	ATF_CHECK_EQ(2, stats.published);
	ATF_CHECK_EQ(1, sessions(&f));
	notify_client_close(client);
	ATF_CHECK_EQ(0, sessions(&f));
	fixture_stop(&f);
}

ATF_TC(admin_rights_and_timers);
ATF_TC_HEAD(admin_rights_and_timers, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "SERVICE_RIGHTS_ADMIN bypasses tier "
	    "policy; a timer fires through the router's kqueue");
}
ATF_TC_BODY(admin_rights_and_timers, tc)
{
	union notify_buffer buffer;
	struct notify_event *event = (void *)buffer.bytes;
	struct notify_client *client;
	struct fixture f;

	fixture_start(&f);
	ATF_REQUIRE_EQ(0, notify_client_adopt(admit(&f, "org.test.admin",
	    NOTIFY_TIER_OPEN, SERVICE_RIGHTS_ADMIN), &client));
	ATF_REQUIRE_EQ(0, notify_publish(client, "system.alpha", "x", 1));
	ATF_REQUIRE_EQ(0, notify_timer_add(client, 9, 50, 0));
	ATF_REQUIRE(notify_next(client, event, sizeof(buffer), 2000) > 0);
	ATF_CHECK_EQ(NOTIFY_EVENT_TIMER, event->type);
	ATF_CHECK_EQ(9, event->timer_id);
	notify_client_close(client);
	fixture_stop(&f);
}

/* A raw bsd.notify.v1 client, for what libnotify would never send. */
struct raw {
	struct fidl_bsd_connection *connection;
	bool done;
	int error;
	uint64_t tag;
	uint32_t err;
};

static void
raw_info(void *context, int error, struct bsd_notify_v1_ProtocolInfo *value)
{
	struct raw *r = context;
	(void)value;
	r->done = true;
	r->error = error;
}

#define	RAW_RESULT(name, type)						\
static void								\
name(void *context, int error, struct type *value)			\
{									\
	struct raw *r = context;					\
	r->done = true;							\
	r->error = error;						\
	if (error == 0) {						\
		r->tag = value->tag;					\
		r->err = value->tag == type##_err_tag ? value->value.err : 0; \
	}								\
}
RAW_RESULT(raw_next, bsd_notify_v1_Notify_Next_Result)
RAW_RESULT(raw_stats, bsd_notify_v1_Notify_GetStats_Result)
RAW_RESULT(raw_subscribe, bsd_notify_v1_Notify_Subscribe_Result)
RAW_RESULT(raw_hello, bsd_notify_v1_Notify_Hello_Result)

static void
raw_wait(struct raw *r)
{
	for (int i = 0; i < 300 && !r->done; i++)
		if (fidl_bsd_connection_poll(r->connection, 10) != 0 &&
		    !r->done) {
			r->done = true;
			r->error = fidl_bsd_connection_error(r->connection);
		}
	ATF_REQUIRE(r->done);
}

static void
raw_open(struct fixture *f, struct raw *r, bool negotiate)
{
	struct fidl_bsd_empty empty = { 0 };
	uint32_t txid;

	memset(r, 0, sizeof(*r));
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(admit(f, "org.test.raw",
	    NOTIFY_TIER_OPEN, SERVICE_RIGHTS_NONE), FIDL_BSD_CLIENT,
	    &r->connection));
	if (!negotiate)
		return;
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_GetProtocolInfo(r->connection,
	    &empty, raw_info, r, &txid));
	raw_wait(r);
	ATF_REQUIRE_EQ(0, r->error);
	r->done = false;
}

ATF_TC(long_poll_is_exclusive);
ATF_TC_HEAD(long_poll_is_exclusive, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "While a Next is pending every other "
	    "request on the session fails with EBUSY; the long poll then "
	    "times out with EAGAIN");
}
ATF_TC_BODY(long_poll_is_exclusive, tc)
{
	struct bsd_notify_v1_NextRequest next = { 300 };
	struct fidl_bsd_empty empty = { 0 };
	struct raw r, stats;
	struct fixture f;
	uint32_t txid;

	fixture_start(&f);
	raw_open(&f, &r, true);
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_Next(r.connection, &next,
	    raw_next, &r, &txid));
	(void)fidl_bsd_connection_poll(r.connection, 50);
	stats = r;
	stats.done = false;
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_GetStats(r.connection, &empty,
	    raw_stats, &stats, &txid));
	raw_wait(&stats);
	ATF_CHECK_EQ(0, stats.error);
	ATF_CHECK_EQ(EBUSY, stats.err);
	raw_wait(&r);
	ATF_CHECK_EQ(0, r.error);
	ATF_CHECK_EQ(EAGAIN, r.err);
	fidl_bsd_connection_destroy(r.connection);
	fixture_stop(&f);
}

ATF_TC(protocol_violations_end_the_session);
ATF_TC_HEAD(protocol_violations_end_the_session, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "A request before negotiation, a topic "
	    "outside the record rules, an unknown feature bit and a pre-FIDL "
	    "record each end only that session");
}
ATF_TC_BODY(protocol_violations_end_the_session, tc)
{
	struct bsd_notify_v1_TopicRequest bad_topic = { "9bad", 4 };
	struct bsd_notify_v1_TopicRequest good_topic = { "user.ok", 7 };
	struct bsd_notify_v1_HelloRequest hello = { 0x80000000u };
	struct notify_msg legacy;
	struct service_session *session;
	struct service_message message = { .size = sizeof(message),
		.data = &legacy, .length = sizeof(legacy) };
	uint8_t reply[64];
	struct service_reply response = { .size = sizeof(response),
		.data = reply, .capacity = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct notify_client *healthy;
	struct fixture f;
	struct raw r;
	uint32_t txid;

	fixture_start(&f);
	ATF_REQUIRE_EQ(0, notify_client_adopt(admit(&f, "org.test.healthy",
	    NOTIFY_TIER_OPEN, SERVICE_RIGHTS_NONE), &healthy));
	ATF_REQUIRE_EQ(1, sessions(&f));

	raw_open(&f, &r, false);
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_Subscribe(r.connection,
	    &good_topic, raw_subscribe, &r, &txid));
	raw_wait(&r);
	ATF_CHECK(r.error != 0);
	fidl_bsd_connection_destroy(r.connection);

	raw_open(&f, &r, true);
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_Subscribe(r.connection,
	    &bad_topic, raw_subscribe, &r, &txid));
	raw_wait(&r);
	ATF_CHECK(r.error != 0);
	fidl_bsd_connection_destroy(r.connection);

	raw_open(&f, &r, true);
	ATF_REQUIRE_EQ(0, bsd_notify_v1_Notify_Hello(r.connection, &hello,
	    raw_hello, &r, &txid));
	raw_wait(&r);
	ATF_CHECK(r.error != 0);
	fidl_bsd_connection_destroy(r.connection);

	ATF_REQUIRE_EQ(0, notify_message_init(&legacy, NOTIFY_OP_STATS, 0));
	ATF_REQUIRE_EQ(0, service_session_create(admit(&f, "org.test.legacy",
	    NOTIFY_TIER_OPEN, SERVICE_RIGHTS_NONE), &session));
	options.timeout_ms = 2000;
	ATF_CHECK_EQ(-1, service_session_call(session, &message, &response,
	    &options));
	service_session_close(session);

	/* Only the healthy session remains, and it still works. */
	ATF_CHECK_EQ(1, sessions(&f));
	ATF_CHECK_EQ(0, notify_subscribe(healthy, "user.ok"));
	notify_client_close(healthy);
	fixture_stop(&f);
}

static pid_t
launch_peer(const atf_tc_t *tc, const char *role, int fd)
{
	char path[PATH_MAX];
	pid_t child;

	snprintf(path, sizeof(path), "%s/next_peer",
	    atf_tc_get_config_var(tc, "srcdir"));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		/*
		 * The peer must hold only its own end: an inherited copy of the
		 * test's end would keep the channel open after the test closes it.
		 */
		if (fd == 3 ? fcntl(3, F_SETFD, 0) < 0 : dup2(fd, 3) < 0)
			_exit(126);
		closefrom(4);
		execl(path, path, role, "3", (char *)NULL);
		_exit(127);
	}
	close(fd);
	return (child);
}

static int
reap(pid_t child)
{
	int status;
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC(evolution_v1_client_with_v2_provider);
ATF_TC_HEAD(evolution_v1_client_with_v2_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(evolution_v1_client_with_v2_provider, tc)
{
	struct notify_client *client;
	struct notify_stats stats;
	int ends[2];
	pid_t peer;

	require_plane();
	ATF_REQUIRE_EQ(0, mac_capability_channel_create(ends));
	peer = launch_peer(tc, "serve", ends[1]);
	ATF_REQUIRE_EQ(0, notify_client_adopt(ends[0], &client));
	ATF_REQUIRE_EQ(0, notify_stats(client, &stats));
	ATF_CHECK_EQ(5, stats.published);
	notify_client_close(client);
	ATF_CHECK_EQ(0, reap(peer));
}

ATF_TC(evolution_v2_client_with_v1_provider);
ATF_TC_HEAD(evolution_v2_client_with_v1_provider, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(evolution_v2_client_with_v1_provider, tc)
{
	struct fixture f;

	fixture_start(&f);
	ATF_CHECK_EQ(0, reap(launch_peer(tc, "call", admit(&f,
	    "org.test.evolve", NOTIFY_TIER_OPEN, SERVICE_RIGHTS_NONE))));
	/* The unknown strict method ended that session. */
	ATF_CHECK_EQ(0, sessions(&f));
	fixture_stop(&f);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, open_tier_round_trip);
	ATF_TP_ADD_TC(tp, admin_rights_and_timers);
	ATF_TP_ADD_TC(tp, long_poll_is_exclusive);
	ATF_TP_ADD_TC(tp, protocol_violations_end_the_session);
	ATF_TP_ADD_TC(tp, evolution_v1_client_with_v2_provider);
	ATF_TP_ADD_TC(tp, evolution_v2_client_with_v1_provider);
	return (atf_no_error());
}
