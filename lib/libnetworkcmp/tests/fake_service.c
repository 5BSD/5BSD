/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Scripted system.Network provider for the libnetworkcmp client tests.  It
 * replaces libservice's service_open(): each call creates a real capability
 * channel served by a bsd.network.v1 server on its own thread.  GetLimits
 * replies are held for 20 ms so that calls from several client threads
 * overlap; the highest number held at once is reported.
 */
#include <sys/types.h>

#include <assert.h>
#include <channel.h>
#include <errno.h>
#include <fidl/bsd.network.v1/c/bsd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <networkcmp.h>
#include "fake_service.h"

int service_open(const char *, int *);
int service_harden_fd(int, unsigned);
int service_budget_timeout(uint32_t *);

/* The client's descriptor hardening and call budget, without libservice. */
int
service_harden_fd(int fd, unsigned flags)
{
	(void)flags;
	return (fd < 0 ? (errno = EBADF, -1) : 0);
}

int
service_budget_timeout(uint32_t *ms)
{
	return (ms == NULL ? (errno = EINVAL, -1) : 0);
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned created, closed, calls, maximum;
static int next_error;
static bool next_malformed;

#define HELD_MAX 64
struct session {
	struct fidl_bsd_connection *connection;
	struct fidl_bsd_request *held[HELD_MAX];
	unsigned nheld;
	bool malformed[HELD_MAX];
};

void
fake_service_reset(void)
{
	pthread_mutex_lock(&lock);
	created = closed = calls = maximum = 0;
	next_error = 0;
	next_malformed = false;
	pthread_mutex_unlock(&lock);
}

void
fake_service_malformed_reply(void)
{
	pthread_mutex_lock(&lock);
	next_malformed = true;
	pthread_mutex_unlock(&lock);
}

void
fake_service_fail(int error)
{
	pthread_mutex_lock(&lock);
	next_error = error;
	pthread_mutex_unlock(&lock);
}

#define COUNTER(name, value) \
	unsigned name(void) { unsigned result; pthread_mutex_lock(&lock); \
	result = value; pthread_mutex_unlock(&lock); return (result); }
COUNTER(fake_service_created, created)
COUNTER(fake_service_closed, closed)
COUNTER(fake_service_calls, calls)
COUNTER(fake_service_max_concurrent, maximum)

static void
info(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct bsd_network_v1_ProtocolInfo v = { NETWORKCMP_WIRE_VERSION };
	(void)x;
	(void)e;
	assert(bsd_network_v1_Network_GetProtocolInfo_reply(c, r, &v) == 0);
}

static void
limits(void *x, struct fidl_bsd_connection *c, struct fidl_bsd_request *r,
    struct fidl_bsd_empty *e)
{
	struct session *s = x;
	int error;
	bool malformed;
	(void)e;
	pthread_mutex_lock(&lock);
	calls++;
	error = next_error;
	next_error = 0;
	malformed = next_malformed;
	next_malformed = false;
	pthread_mutex_unlock(&lock);
	if (error != 0) {
		fidl_bsd_connection_close(c, error);
		return;
	}
	assert(s->nheld < HELD_MAX);
	fidl_bsd_request_retain(r);
	s->malformed[s->nheld] = malformed;
	s->held[s->nheld++] = r;
	pthread_mutex_lock(&lock);
	if (s->nheld > maximum)
		maximum = s->nheld;
	pthread_mutex_unlock(&lock);
}

/* Answer every held GetLimits. */
static void
release_held(struct session *s)
{
	struct bsd_network_v1_Limits v = {
		NETWORKCMP_FEATURE_TCP | NETWORKCMP_FEATURE_UDP |
		NETWORKCMP_FEATURE_IPV6 | NETWORKCMP_FEATURE_DNS,
		NETWORKCMP_RESOLVE_MAX_RESULTS
	};
	for (unsigned i = 0; i < s->nheld; i++) {
		struct bsd_network_v1_Limits reply = v;
		/* An unknown feature bit is a malformed reply. */
		if (s->malformed[i])
			reply.features |= 0x80000000u;
		if (fidl_bsd_connection_error(s->connection) == 0)
			(void)bsd_network_v1_Network_GetLimits_reply(
			    s->connection, s->held[i], &reply);
		fidl_bsd_request_release(s->held[i]);
	}
	s->nheld = 0;
}

static void *
serve(void *argument)
{
	struct bsd_network_v1_Network_server handlers = {
		.GetProtocolInfo = info,
		.GetLimits = limits
	};
	struct session s = { 0 };
	int fd = (int)(intptr_t)argument, error;

	assert(fidl_bsd_connection_create(fd, FIDL_BSD_SERVER,
	    &s.connection) == 0);
	assert(bsd_network_v1_Network_bind(s.connection, &handlers, &s) == 0);
	for (;;) {
		error = fidl_bsd_connection_poll(s.connection,
		    s.nheld != 0 ? 20 : 10000);
		if (error != 0)
			break;
		if (s.nheld != 0) {
			/* Collect whatever else arrives within the window. */
			(void)fidl_bsd_connection_poll(s.connection, 20);
			release_held(&s);
		}
	}
	release_held(&s);
	fidl_bsd_connection_destroy(s.connection);
	pthread_mutex_lock(&lock);
	closed++;
	pthread_mutex_unlock(&lock);
	return (NULL);
}

int
service_open(const char *name, int *fdp)
{
	pthread_t thread;
	int ends[2];

	if (name == NULL || strcmp(name, NETWORKCMP_INTERFACE) != 0 ||
	    fdp == NULL)
		return (errno = EINVAL, -1);
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	assert(pthread_create(&thread, NULL, serve,
	    (void *)(intptr_t)ends[1]) == 0);
	assert(pthread_detach(thread) == 0);
	pthread_mutex_lock(&lock);
	created++;
	pthread_mutex_unlock(&lock);
	*fdp = ends[0];
	return (0);
}
