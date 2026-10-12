/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Scripted system.Trace provider for the libtracecmp client tests.  It
 * replaces libservice's service_open(): each call creates a real capability
 * channel and serves the provider end with a bsd.trace.v1 server on its own
 * thread (one dispatch thread per connection), so the client library is
 * exercised over the native transport.
 */
#include <sys/types.h>

#include <assert.h>
#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.trace.v1/c/bsd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tracecmp.h>
#include "fake_service.h"

int service_open(const char *, int *);
int service_budget_timeout(uint32_t *);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t threads[64];
static unsigned created, closed, joined, concurrent, maximum;
static int connect_error, call_error;
static enum fake_reply_mode mode;

struct session {
	int fd;
	enum fake_reply_mode mode;
	int call_error;
};

static void
join_all(void)
{
	pthread_mutex_lock(&lock);
	while (joined < created) {
		pthread_t thread = threads[joined++];
		pthread_mutex_unlock(&lock);
		(void)pthread_join(thread, NULL);
		pthread_mutex_lock(&lock);
	}
	pthread_mutex_unlock(&lock);
}

void
fake_service_reset(void)
{
	join_all();
	pthread_mutex_lock(&lock);
	created = closed = joined = concurrent = maximum = 0;
	connect_error = call_error = 0;
	mode = FAKE_REPLY_NORMAL;
	pthread_mutex_unlock(&lock);
}

void fake_service_fail_connect(int error) { connect_error = error; }
void fake_service_fail_call(int error) { call_error = error; }
void fake_service_reply_mode(enum fake_reply_mode value) { mode = value; }

unsigned
fake_service_created(void)
{
	unsigned result;
	pthread_mutex_lock(&lock);
	result = created;
	pthread_mutex_unlock(&lock);
	return (result);
}

/* Sessions whose server saw the connection end (waits for them). */
unsigned
fake_service_closed(void)
{
	unsigned result;
	join_all();
	pthread_mutex_lock(&lock);
	result = closed;
	pthread_mutex_unlock(&lock);
	return (result);
}

unsigned
fake_service_max_concurrent(void)
{
	unsigned result;
	join_all();
	pthread_mutex_lock(&lock);
	result = maximum;
	pthread_mutex_unlock(&lock);
	return (result);
}

/* Callers' RPC budgets are not under test here. */
int
service_budget_timeout(uint32_t *ms)
{
	return (ms == NULL ? (errno = EINVAL, -1) : 0);
}

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct session *s = x;
	struct bsd_trace_v1_ProtocolInfo v = { TRACECMP_WIRE_VERSION,
		TRACECMP_FEATURE_RAW_DTRACE_FD };
	(void)e;
	if (s->call_error != 0) {
		fidl_bsd_connection_close(c, s->call_error);
		return;
	}
	/* Let concurrent sessions overlap. */
	usleep(20000);
	if (s->mode == FAKE_REPLY_NO_FEATURE)
		v.features = 0;
	else if (s->mode == FAKE_REPLY_BAD_FEATURES)
		v.features |= 0x80000000U;
	else if (s->mode == FAKE_REPLY_FUTURE_VERSION)
		v.wire_version++;
	assert(bsd_trace_v1_Trace_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
open_handler(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct session *s = x;
	struct bsd_trace_v1_Trace_Open_Result v = {
		.tag = bsd_trace_v1_Trace_Open_Result_response_tag
	};
	int fd;
	(void)e;
	if (s->mode == FAKE_REPLY_CLOSE_ON_OPEN) {
		fidl_bsd_connection_close(c, EPIPE);
		return;
	}
	if (s->mode == FAKE_REPLY_BAD_ERRNO) {
		v.tag = bsd_trace_v1_Trace_Open_Result_err_tag;
		v.value.err = 0;
		assert(bsd_trace_v1_Trace_Open_reply(c, r, &v) == 0);
		return;
	}
	fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	assert(fd >= 0);
	v.value.response.dtrace = fd;
	assert(bsd_trace_v1_Trace_Open_reply(c, r, &v) == 0);
	close(fd);
}

static void
stats_handler(void *x, struct fidl_bsd_connection *c,
    struct fidl_bsd_request *r, struct fidl_bsd_empty *e)
{
	struct bsd_trace_v1_TraceStats v = { FAKE_STATS_OPENED,
		FAKE_STATS_REJECTED };
	(void)x;
	(void)e;
	assert(bsd_trace_v1_Trace_Stats_reply(c, r, &v) == 0);
}

static void
legacy_request(struct channel *channel, struct channel_message *message,
    void *context)
{
	struct tracecmp_msg reply = { .magic = TRACECMP_MAGIC,
		.opcode = TRACECMP_OP_HELLO };
	struct channel_outgoing outgoing = CHANNEL_OUTGOING_INITIALIZER(&reply,
	    sizeof(reply));
	(void)channel;
	(void)channel_send_reply(message, &outgoing);
	channel_message_free(message);
	*(bool *)context = true;
}

static void *
serve(void *argument)
{
	struct session *s = argument;

	if (s->mode == FAKE_REPLY_LEGACY) {
		struct channel_options options =
		    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
		struct channel *channel;
		bool done = false;
		assert(channel_create(s->fd, &options, &channel) == 0);
		assert(channel_set_request_handler(channel, legacy_request,
		    &done) == 0);
		while (!done && channel_wait(channel, false, 5000) > 0)
			(void)channel_dispatch(channel);
		/* Wait for the client to give up. */
		while (channel_wait(channel, false, 5000) > 0 &&
		    channel_dispatch(channel) == 0)
			;
		channel_destroy(channel);
	} else {
		struct bsd_trace_v1_Trace_server handlers = {
			.GetProtocolInfo = info,
			.Open = open_handler,
			.Stats = stats_handler
		};
		struct fidl_bsd_connection *connection;
		assert(fidl_bsd_connection_create(s->fd, FIDL_BSD_SERVER,
		    &connection) == 0);
		assert(bsd_trace_v1_Trace_bind(connection, &handlers, s) == 0);
		while (fidl_bsd_connection_poll(connection, 10000) == 0)
			;
		fidl_bsd_connection_destroy(connection);
	}
	free(s);
	pthread_mutex_lock(&lock);
	closed++;
	concurrent--;
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fdp)
{
	struct session *s;
	int ends[2], error;

	if (name == NULL || strcmp(name, TRACECMP_INTERFACE) != 0 ||
	    fdp == NULL)
		return (errno = EINVAL, -1);
	pthread_mutex_lock(&lock);
	error = connect_error;
	connect_error = 0;
	pthread_mutex_unlock(&lock);
	if (error != 0)
		return (errno = error, -1);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	s = calloc(1, sizeof(*s));
	assert(s != NULL);
	s->fd = ends[1];
	pthread_mutex_lock(&lock);
	s->mode = mode;
	s->call_error = call_error;
	call_error = 0;
	assert(created < sizeof(threads) / sizeof(threads[0]));
	if (++concurrent > maximum)
		maximum = concurrent;
	error = pthread_create(&threads[created], NULL, serve, s);
	assert(error == 0);
	created++;
	pthread_mutex_unlock(&lock);
	*fdp = ends[0];
	return (0);
}
