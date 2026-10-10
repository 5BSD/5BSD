/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDTime -- the system.Time capability provider.  A client holds a system.Time
 * channel and asks the broker to read the wall clock (unprivileged, any holder)
 * or, when the per-label policy permits, to STEP it (clock_settime) or SLEW it
 * (adjtime).  Setting the clock needs PRIV_SETTIMEOFDAY, which a sandboxed
 * caller lacks; BSDTime is BORN IN CAPABILITY MODE (like BSDSysctl) and holds a
 * "system" SYS_GATE_SETTIME token delivered by switchboard, stepping/slewing
 * the clock THROUGH that token in kernel context -- the raw settimeofday(2)
 * stays refused in the cage, so the sandbox is never loosened.  The per-label
 * policy (time.conf) gates it on top.  Default-deny: no label may move the
 * clock unless time.conf grants it.
 */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/time.h>

#include <channel.h>
#include <errno.h>
#include <fidl/bsd.time.v1/c/bsd.h>
#include <libservice.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "BSDTime_probes.h"
#include "config.h"
#include "timecmp.h"

/* Multiplex bounded sessions in the process holding the locked gate token. */
#define BSDTIME_SESSION_IDLE_SEC 30

/* g_config is consumed only by main()'s accept loop (guarded out under
 * TESTING). */
static struct timecmp_config g_config __unused;
/* Held by the single provider process; locked against fork inheritance. */
static int g_time_token = -1;

struct session {
	char label[sizeof(((struct service_identity *)0)->client_label)];
	struct fidl_bsd_connection *connection;
	int fd;
	const struct timecmp_config *config;
	struct timespec last;
	bool negotiated, write_enabled;
};
static bool
ready(struct session *session, struct fidl_bsd_connection *connection)
{
	if (!session->negotiated) {
		fidl_bsd_connection_close(connection, EPROTO);
		return (false);
	}
	return (true);
}
static void
completed(struct session *session, struct fidl_bsd_connection *connection,
    unsigned opcode, int status, int error)
{
	BSDTIME_PROBE_REQUEST(session->label, opcode, status);
	if (error)
		fidl_bsd_connection_close(connection, error);
	else if (clock_gettime(CLOCK_MONOTONIC, &session->last) == -1)
		fidl_bsd_connection_close(connection, errno);
}
static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_time_v1_ProtocolInfo info = { TIMECMP_WIRE_VERSION };
	int error = bsd_time_v1_Time_GetProtocolInfo_reply(connection, request,
	    &info);
	session->negotiated = error == 0;
	completed(session, connection, 0, 0, error);
}
static void
get_time(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_time_v1_Time_Get_Result reply = { 0 };
	struct timespec now;
	int status = 0;
	if (!ready(session, connection))
		return;
	if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
		status = errno;
		reply.tag = bsd_time_v1_Time_Get_Result_err_tag;
		reply.value.err = status;
	} else {
		reply.tag = bsd_time_v1_Time_Get_Result_response_tag;
		reply.value.response.seconds = now.tv_sec;
		reply.value.response.nanoseconds = now.tv_nsec;
	}
	completed(session, connection, TIMECMP_OP_GET, status,
	    bsd_time_v1_Time_Get_reply(connection, request, &reply));
}
static void
set_time(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_time_v1_Timestamp *value)
{
	struct session *session = argument;
	struct bsd_time_v1_Time_Set_Result reply = { 0 };
	struct timespec time;
	int status = 0;
	if (!ready(session, connection))
		return;
	if (!timecmp_config_permits_set(session->config, session->label))
		status = EPERM;
	else if (value->nanoseconds < 0 || value->nanoseconds > 999999999 ||
	    (int64_t)(time_t)value->seconds != value->seconds)
		status = EINVAL;
	else {
		time.tv_sec = (time_t)value->seconds;
		time.tv_nsec = value->nanoseconds;
		if (service_system_settime(g_time_token, &time) == -1)
			status = errno;
		else {
			BSDTIME_PROBE_CLOCK_SET(session->label, value->seconds,
			    value->nanoseconds);
			syslog(LOG_NOTICE, "clock stepped by %s to %jd.%09d",
			    session->label, (intmax_t)value->seconds,
			    value->nanoseconds);
		}
	}
	reply.tag = status ? bsd_time_v1_Time_Set_Result_err_tag :
			     bsd_time_v1_Time_Set_Result_response_tag;
	if (status)
		reply.value.err = status;
	completed(session, connection, TIMECMP_OP_SET, status,
	    bsd_time_v1_Time_Set_reply(connection, request, &reply));
}
// Saturate only the tracing value; the gate receives the exact timeval.
static int64_t
trace_delta(const struct bsd_time_v1_Delta *value)
{
	int64_t seconds, fraction, sum;
	fraction = (int64_t)value->microseconds * 1000;
	if (__builtin_mul_overflow(value->seconds, INT64_C(1000000000),
		&seconds) ||
	    __builtin_add_overflow(seconds, fraction, &sum))
		return (value->seconds < 0 ? INT64_MIN : INT64_MAX);
	return (sum);
}
static void
adjust_time(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_time_v1_Delta *value)
{
	struct session *session = argument;
	struct bsd_time_v1_Time_Adjust_Result reply = { 0 };
	struct timeval delta, old = { 0 };
	int status = 0;
	if (!ready(session, connection))
		return;
	if (!timecmp_config_permits_set(session->config, session->label))
		status = EPERM;
	else if (value->microseconds < -999999 ||
	    value->microseconds > 999999 ||
	    (int64_t)(time_t)value->seconds != value->seconds)
		status = EINVAL;
	else {
		delta.tv_sec = (time_t)value->seconds;
		delta.tv_usec = value->microseconds;
		if (service_system_adjtime(g_time_token, &delta, &old) == -1)
			status = errno;
		else {
			BSDTIME_PROBE_CLOCK_ADJUST(session->label,
			    trace_delta(value));
			syslog(LOG_NOTICE,
			    "clock slewed by %s by %jd seconds and %ld microseconds",
			    session->label, (intmax_t)delta.tv_sec,
			    (long)delta.tv_usec);
		}
	}
	reply.tag = status ? bsd_time_v1_Time_Adjust_Result_err_tag :
			     bsd_time_v1_Time_Adjust_Result_response_tag;
	if (status)
		reply.value.err = status;
	else {
		reply.value.response.seconds = old.tv_sec;
		reply.value.response.microseconds = old.tv_usec;
	}
	completed(session, connection, TIMECMP_OP_ADJUST, status,
	    bsd_time_v1_Time_Adjust_reply(connection, request, &reply));
}
#define BSDTIME_MAX_SESSIONS	   32
#define BSDTIME_MAX_LABEL_SESSIONS 8
struct bsdtime_server {
	int queue;
	unsigned count, cursor;
	int idle_ms;
	struct session sessions[BSDTIME_MAX_SESSIONS];
};
static void
server_drop(struct bsdtime_server *server, struct session *session)
{
	struct kevent changes[2];
	if (session->connection == NULL)
		return;
	EV_SET(&changes[0], session->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&changes[1], session->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	(void)kevent(server->queue, changes, 2, NULL, 0, NULL);
	fidl_bsd_connection_destroy(session->connection);
	memset(session, 0, sizeof(*session));
	server->count--;
}
static void
server_destroy(struct bsdtime_server *server)
{
	for (unsigned i = 0; i < BSDTIME_MAX_SESSIONS; ++i)
		server_drop(server, &server->sessions[i]);
	if (server->queue >= 0)
		close(server->queue);
	server->queue = -1;
}
static int
server_init(struct bsdtime_server *server, int listener, int idle_ms)
{
	struct kevent event;
	memset(server, 0, sizeof(*server));
	server->queue = -1;
	server->idle_ms = idle_ms;
	if (idle_ms <= 0)
		return (EINVAL);
	server->queue = kqueuex(KQUEUE_CLOEXEC);
	if (server->queue < 0)
		return (errno);
	if (listener >= 0) {
		EV_SET(&event, listener, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(server->queue, &event, 1, NULL, 0, NULL) == -1) {
			int error = errno;
			server_destroy(server);
			return (error);
		}
	}
	return (0);
}
/* Consume the accepted descriptor on every path. No heap session list. */
static int
server_add(struct bsdtime_server *server, int fd, const char *label,
    const struct timecmp_config *config)
{
	const struct bsd_time_v1_Time_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Get = get_time,
		.Set = set_time,
		.Adjust = adjust_time
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct session *session = NULL;
	struct kevent changes[2];
	int error = EINVAL;
	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		goto rejected;
	if (strlen(label) >= sizeof(server->sessions[0].label)) {
		error = ENAMETOOLONG;
		goto rejected;
	}
	unsigned same_label = 0;
	for (unsigned i = 0; i < BSDTIME_MAX_SESSIONS; ++i)
		if (server->sessions[i].connection &&
		    strcmp(server->sessions[i].label, label) == 0)
			same_label++;
	if (same_label >= BSDTIME_MAX_LABEL_SESSIONS) {
		error = ENOBUFS;
		goto rejected;
	}
	for (unsigned i = 0; i < BSDTIME_MAX_SESSIONS; ++i) {
		if (server->sessions[i].connection == NULL) {
			session = &server->sessions[i];
			break;
		}
	}
	if (session == NULL) {
		error = ENOBUFS;
		goto rejected;
	}
	memset(session, 0, sizeof(*session));
	strlcpy(session->label, label, sizeof(session->label));
	session->config = config;
	if (clock_gettime(CLOCK_MONOTONIC, &session->last) == -1) {
		error = errno;
		goto rejected;
	}
	options.max_pending_requests = 1;
	options.max_queued_messages = 16;
	options.max_queued_bytes = 4096;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &session->connection);
	if (error)
		goto rejected;
	server->count++;
	session->fd = fidl_bsd_connection_fd(session->connection);
	error = bsd_time_v1_Time_bind(session->connection, &handlers, session);
	if (!error) {
		EV_SET(&changes[0], session->fd, EVFILT_READ, EV_ADD, 0, 0,
		    session);
		EV_SET(&changes[1], session->fd, EVFILT_WRITE,
		    EV_ADD | EV_DISABLE, 0, 0, session);
		if (kevent(server->queue, changes, 2, NULL, 0, NULL) == -1)
			error = errno;
	}
	if (error)
		server_drop(server, session);
	return (error);
rejected:
	if (fd >= 0)
		close(fd);
	return (error);
}
static int64_t
session_remaining(const struct bsdtime_server *server,
    const struct session *session, const struct timespec *now)
{
	return (server->idle_ms -
	    ((now->tv_sec - session->last.tv_sec) * INT64_C(1000) +
		(now->tv_nsec - session->last.tv_nsec) / 1000000));
}
static int
server_step(struct bsdtime_server *server, int timeout_ms, bool *accept_ready)
{
	struct kevent events[BSDTIME_MAX_SESSIONS * 2 + 1];
	bool ready[BSDTIME_MAX_SESSIONS] = { false };
	struct timespec now, wait;
	int count;
	*accept_ready = false;
	if (timeout_ms < 0)
		return (EINVAL);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (errno);
	for (unsigned i = 0; i < BSDTIME_MAX_SESSIONS; ++i) {
		struct session *session = &server->sessions[i];
		if (!session->connection)
			continue;
		int64_t remaining = session_remaining(server, session, &now);
		if (remaining <= 0)
			server_drop(server, session);
		else if (remaining < timeout_ms)
			timeout_ms = (int)remaining;
	}
	wait = (struct timespec) { timeout_ms / 1000,
		(timeout_ms % 1000) * 1000000L };
	count = kevent(server->queue, NULL, 0, events, nitems(events), &wait);
	if (count < 0)
		return (errno == EINTR ? 0 : errno);
	for (int i = 0; i < count; ++i) {
		if (events[i].udata == NULL) {
			*accept_ready = true;
			continue;
		}
		struct session *session = events[i].udata;
		if (session->connection &&
		    events[i].ident == (uintptr_t)session->fd)
			ready[session - server->sessions] = true;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (errno);
	/* One bounded libchannel batch per ready peer, rotating the first peer.
	 */
	for (unsigned n = 0; n < BSDTIME_MAX_SESSIONS; ++n) {
		unsigned i = (server->cursor + n) % BSDTIME_MAX_SESSIONS;
		struct session *session = &server->sessions[i];
		if (!session->connection)
			continue;
		if (session_remaining(server, session, &now) <= 0) {
			server_drop(server, session);
			continue;
		}
		if (!ready[i])
			continue;
		if (fidl_bsd_connection_dispatch(session->connection)) {
			server_drop(server, session);
			continue;
		}
		struct kevent change;
		bool write = fidl_bsd_connection_wants_write(
		    session->connection);
		if (write == session->write_enabled)
			continue;
		EV_SET(&change, session->fd, EVFILT_WRITE,
		    write ? EV_ENABLE : EV_DISABLE, 0, 0, session);
		if (kevent(server->queue, &change, 1, NULL, 0, NULL) == -1)
			server_drop(server, session);
		else
			session->write_enabled = write;
	}
	server->cursor = (server->cursor + 1) % BSDTIME_MAX_SESSIONS;
	return (0);
}
#ifdef BSDTIME_TESTING
static int
serve_session(int fd, const char *label, const struct timecmp_config *config)
{
	struct bsdtime_server server;
	bool ready;
	int error = server_init(&server, -1, BSDTIME_SESSION_IDLE_SEC * 1000);
	if (error) {
		close(fd);
		return (1);
	}
	error = server_add(&server, fd, label, config);
	while (!error && server.count)
		error = server_step(&server, 1000, &ready);
	server_destroy(&server);
	return (error ? 1 : 0);
}
#endif

#ifdef BSDTIME_TESTING
/*
 * Test entrypoints. Expose the session reactor and the gate-token
 * slot to the ATF suite so a test can drive the real request handler
 * (policy enforcement, protocol validation, GET/SET/ADJUST dispatch) over a
 * connected provider channel without the switchboard launch path.  The daemon
 * build (no -DBSDTIME_TESTING) compiles main() below instead and never these.
 */
#include "BSDTime_test.h"

int
bsdtime_test_serve_session(int fd, const char *label,
    const struct timecmp_config *config)
{
	return (serve_session(fd, label, config));
}

int
bsdtime_test_server_create(int idle_ms, struct bsdtime_server **out)
{
	struct bsdtime_server *server = calloc(1, sizeof(*server));
	if (!server)
		return (ENOMEM);
	int error = server_init(server, -1, idle_ms);
	if (error) {
		free(server);
		return (error);
	}
	*out = server;
	return (0);
}
int
bsdtime_test_server_add(struct bsdtime_server *server, int fd,
    const char *label, const struct timecmp_config *config)
{
	return (server_add(server, fd, label, config));
}
int
bsdtime_test_server_step(struct bsdtime_server *server, int timeout_ms)
{
	bool ready;
	return (server_step(server, timeout_ms, &ready));
}
unsigned
bsdtime_test_server_count(struct bsdtime_server *server)
{
	return (server->count);
}
void
bsdtime_test_server_destroy(struct bsdtime_server *server)
{
	server_destroy(server);
	free(server);
}

void
bsdtime_test_set_token(int fd)
{
	g_time_token = fd;
}
#endif /* BSDTIME_TESTING */

#ifndef BSDTIME_TESTING
int
main(void)
{
	struct service_identity identity;
	struct bsdtime_server server;
	bool accept_ready;
	struct service_listener *listener;
	struct service_provider *provider;
	int error, fd, cfgfd;

	openlog("BSDTime", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	/*
	 * Per-label policy, via the switchboard-delivered Config directory
	 * descriptor.  Fail-soft: a missing/malformed config keeps the built-in
	 * default (no label may set the clock).
	 */
	timecmp_config_defaults(&g_config);
	if (service_config_open(TIMECMP_CONFIG_NAME, &cfgfd) == -1) {
		if (errno != ENOENT)
			syslog(LOG_WARNING,
			    "policy config unavailable; using "
			    "built-in default (deny all clock writes): %m");
	} else if (timecmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING,
		    "policy config rejected; using built-in "
		    "default (deny all clock writes): %m");
	}
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) ==
		-1 ||
	    service_provider_expose(provider, TIMECMP_INTERFACE, &listener) ==
		-1)
		goto fail;
	/*
	 * Retain the delegated SYS_GATE_SETTIME token in this process, then
	 * enter capability mode.  Fail-soft: without the token, SET/ADJUST
	 * return the CALL error (ENOTCAPABLE) to the client; GET still works.
	 */
	if (service_system_token_dup(&g_time_token) == -1) {
		syslog(LOG_WARNING,
		    "no settime capability; SET/ADJUST "
		    "disabled: %m");
		g_time_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	error = server_init(&server, service_listener_fd(listener),
	    BSDTIME_SESSION_IDLE_SEC * 1000);
	if (error) {
		errno = error;
		goto fail;
	}
	for (;;) {
		if (service_provider_quiescing(provider) == 1) {
			server_destroy(&server);
			int status = service_provider_quiesce_complete(provider,
			    0);
			closelog();
			return (status == 0 ? 0 : 1);
		}
		error = server_step(&server, 1000, &accept_ready);
		if (error)
			break;
		if (!accept_ready)
			continue;
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (error == EINTR || error == ENOBUFS ||
			    service_provider_quiescing(provider) == 1)
				continue;
			break;
		}
		/* Admission failures close just this peer; existing peers
		 * continue. */
		(void)server_add(&server, fd, identity.client_label, &g_config);
	}
	server_destroy(&server);
	errno = error;
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif /* !BSDTIME_TESTING */
