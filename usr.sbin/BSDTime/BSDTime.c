/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * BSDTime -- the system.Time capability provider.  A client holds a system.Time
 * channel and asks the broker to read the wall clock (unprivileged, any holder)
 * or, when the per-label policy permits, to STEP it (clock_settime) or SLEW it
 * (adjtime).  Setting the clock needs PRIV_SETTIMEOFDAY, which a sandboxed
 * caller lacks; BSDTime is an ambient-authority provider (like BSDSysctl): it
 * runs OUTSIDE capability mode as the trusted concentration point, and the
 * per-label policy (time.conf) is the security boundary, not a Capsicum sandbox.
 * Default-deny: no label may move the clock unless time.conf grants it.
 */
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/time.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "timecmp_protocol.h"
#include "config.h"
#include "BSDTime_probes.h"

/*
 * Per-session idle deadline.  BSDTime holds a close-on-fork-locked gate token,
 * so it serves each client INLINE and sequentially in the single token-holding
 * process rather than pdforking.  A client that connects and then never sends a
 * complete request would otherwise pin serve_session on an infinite channel_wait
 * and wedge the accept loop -- denying clock step/slew to every other client.
 * Bound each session by idle time; the client reconnects for its next call.
 */
#define	BSDTIME_SESSION_IDLE_SEC	30

/* g_config is consumed only by main()'s accept loop (guarded out under TESTING). */
static struct timecmp_config g_config __unused;
static int g_time_token = -1;	/* SYS_GATE_SETTIME token, dup'd before workers fork */

struct session {
	const char			*label;
	const struct timecmp_config	*config;
	int				 error;
};

static void
init_reply(struct timecmp_msg *reply, const struct timecmp_msg *request,
    int status)
{

	memset(reply, 0, sizeof(*reply));
	reply->magic = TIMECMP_MAGIC;
	reply->version = TIMECMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;		/* 0 or -errno */
}

/* Reply carrying only a header (HELLO, SET, or an error). */
static int
send_status(struct channel_message *request_message,
    const struct timecmp_msg *request, int status)
{
	struct timecmp_msg reply;

	init_reply(&reply, request, status);
	if (timecmp_validate_message(&reply, sizeof(reply),
	    TIMECMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, sizeof(reply))));
}

/* Reply carrying a header plus one timecmp_time body (GET, ADJUST). */
static int
send_time(struct channel_message *request_message,
    const struct timecmp_msg *request, const struct timecmp_time *value)
{
	uint8_t buffer[TIMECMP_MAX_MESSAGE];
	struct timecmp_msg *reply;
	struct timecmp_time *body;
	size_t length;

	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	init_reply(reply, request, 0);
	body = (void *)(reply + 1);
	*body = *value;
	length = sizeof(*reply) + sizeof(*body);
	if (timecmp_validate_message(reply, length, TIMECMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct timecmp_msg *request;
	const struct timecmp_time *body;
	struct session *session;
	struct timecmp_time out;
	size_t message_len;
	uint16_t opcode;
	int result, status;

	session = argument;
	request = channel_message_data(message);
	message_len = channel_message_length(message);
	opcode = UINT16_MAX;
	result = 0;
	status = 0;
	if (request != NULL && message_len >= sizeof(*request))
		opcode = request->opcode;

	if (channel_message_fd_count(message) != 0 ||
	    timecmp_validate_message(request, message_len,
	    TIMECMP_MESSAGE_REQUEST) == -1) {
		status = EPROTO;
		session->error = status;
		(void)send_status(message, request, -status);
		goto out;
	}
	body = (const void *)(request + 1);

	switch (request->opcode) {
	case TIMECMP_OP_HELLO:
		result = send_status(message, request, 0);
		break;
	case TIMECMP_OP_GET: {
		struct timespec ts;

		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		memset(&out, 0, sizeof(out));
		out.sec = (int64_t)ts.tv_sec;
		out.nsec = (int32_t)ts.tv_nsec;
		out.present = 1;
		result = send_time(message, request, &out);
		break;
	}
	case TIMECMP_OP_SET: {
		struct timespec ts;

		if (message_len != sizeof(*request) + sizeof(*body)) {
			status = EPROTO;
			result = send_status(message, request, -status);
			break;
		}
		if (!timecmp_config_permits_set(session->config,
		    session->label)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		if (body->nsec < 0 || body->nsec > 999999999) {
			status = EINVAL;
			result = send_status(message, request, -status);
			break;
		}
		ts.tv_sec = (time_t)body->sec;
		ts.tv_nsec = body->nsec;
		if (service_system_settime(g_time_token, &ts) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		BSDTIME_PROBE_CLOCK_SET(session->label, body->sec, body->nsec);
		syslog(LOG_NOTICE, "clock stepped by %s to %jd.%09d",
		    session->label, (intmax_t)body->sec, body->nsec);
		result = send_status(message, request, 0);
		break;
	}
	case TIMECMP_OP_ADJUST: {
		struct timeval delta, old;

		if (message_len != sizeof(*request) + sizeof(*body)) {
			status = EPROTO;
			result = send_status(message, request, -status);
			break;
		}
		if (!timecmp_config_permits_set(session->config,
		    session->label)) {
			status = EPERM;
			result = send_status(message, request, -status);
			break;
		}
		/* Same sub-second range check SET applies: nsec is a magnitude in
		 * [0, 1e9); the sign lives in sec.  Reject out-of-range rather than
		 * feed adjtime a malformed tv_usec. */
		if (body->nsec < 0 || body->nsec > 999999999) {
			status = EINVAL;
			result = send_status(message, request, -status);
			break;
		}
		memset(&delta, 0, sizeof(delta));
		delta.tv_sec = (time_t)body->sec;
		delta.tv_usec = body->nsec / 1000;
		memset(&old, 0, sizeof(old));
		if (service_system_adjtime(g_time_token, &delta, &old) == -1) {
			status = errno;
			result = send_status(message, request, -status);
			break;
		}
		BSDTIME_PROBE_CLOCK_ADJUST(session->label,
		    (int64_t)body->sec * 1000000000 + body->nsec);
		syslog(LOG_NOTICE, "clock slewed by %s by %jd.%06ld",
		    session->label, (intmax_t)body->sec, (long)delta.tv_usec);
		memset(&out, 0, sizeof(out));
		out.sec = (int64_t)old.tv_sec;
		out.nsec = (int32_t)old.tv_usec * 1000;
		out.present = (old.tv_sec != 0 || old.tv_usec != 0) ? 1 : 0;
		result = send_time(message, request, &out);
		break;
	}
	default:
		status = EOPNOTSUPP;
		result = send_status(message, request, -status);
		break;
	}
	if (result == -1)
		session->error = errno;
out:
	BSDTIME_PROBE_REQUEST(session->label, opcode, status);
	channel_message_free(message);
}

static int
serve_session(int fd, const char *label, const struct timecmp_config *config)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct session session;
	struct timespec now, last;
	int ready, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || config == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.config = config;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		(void)close(fd);
		return (1);
	}
	if (channel_create(fd, &options, &channel) == -1) {
		(void)close(fd);	/* channel_create consumes fd only on success */
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request,
	    &session) == -1) {
		channel_destroy(channel);
		return (1);
	}
	last = now;
	for (;;) {
		long elapsed_ms, remaining_ms;

		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			break;
		elapsed_ms = (now.tv_sec - last.tv_sec) * 1000 +
		    (now.tv_nsec - last.tv_nsec) / 1000000;
		remaining_ms = (long)BSDTIME_SESSION_IDLE_SEC * 1000 - elapsed_ms;
		if (remaining_ms <= 0)
			break;			/* idle too long: drop the session */
		ready = channel_wait(channel, wants_write,
		    remaining_ms > INT_MAX ? INT_MAX : (int)remaining_ms);
		if (ready < 0)
			break;
		if (ready == 0)
			break;			/* idle deadline elapsed */
		last = now;			/* activity: re-arm the deadline */
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (session.error != 0)
			break;
	}
	channel_destroy(channel);
	return (0);
}

#ifdef BSDTIME_TESTING
/*
 * Test entrypoints.  Expose the per-session channel worker and the gate-token
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
			syslog(LOG_WARNING, "policy config unavailable; using "
			    "built-in default (deny all clock writes): %m");
	} else if (timecmp_config_load_fd(&g_config, cfgfd) == -1) {
		syslog(LOG_WARNING, "policy config rejected; using built-in "
		    "default (deny all clock writes): %m");
	}
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, TIMECMP_INTERFACE,
	    &listener) == -1)
		goto fail;
	/*
	 * Dup the delegated SYS_GATE_SETTIME token into a plain descriptor that
	 * survives the per-client worker's authority drop, then enter capability
	 * mode.  Fail-soft: without the token, SET/ADJUST return the CALL error
	 * (ENOTCAPABLE) to the client; GET still works.
	 */
	if (service_system_token_dup(&g_time_token) == -1) {
		syslog(LOG_WARNING, "no settime capability; SET/ADJUST "
		    "disabled: %m");
		g_time_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	/*
	 * Serve each client inline in this single process.  Unlike the sealed
	 * providers, BSDTime does NOT pdfork a per-client worker: the delivered
	 * SYS_GATE_SETTIME token is close-on-fork-locked (the plane keeps
	 * privileged tokens out of per-client workers by design), so the clock
	 * step/slew must be performed by the token holder itself.  The requests
	 * are trivial and stateless, so inline sequential serving is sufficient;
	 * the per-label policy in handle_request is the authorization boundary.
	 */
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int status;

				status = service_provider_quiesce_complete(
				    provider, 0);
				closelog();
				return (status == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		(void)serve_session(fd, identity.client_label, &g_config);
	}
fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif /* !BSDTIME_TESTING */
