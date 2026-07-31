/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <libcasper.h>
#include <casper/cap_syslog.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <logcmp.h>
#include <shmring.h>

#include "logcmp_probes.h"
#include "session.h"

#define	LOGCMP_PROVIDER_NAME	LOGCMP_INTERFACE
#define	LOGCMP_RING_SIZE		(256U * 1024)
#define	LOGCMP_DRAIN_INTERVAL_MS	10
#define	LOGCMP_DRAIN_TIMER_IDENT	1

union provider_buffer {
	max_align_t align;
	struct {
		struct logcmp_msg msg;
		uint8_t payload[LOGCMP_MAX_MESSAGE - sizeof(struct logcmp_msg)];
	} wire;
};

struct sink_context {
	cap_channel_t	*syslog;
	const char	*label;
	uint64_t	 instance;
};

struct worker_state {
	struct logcmp_session	 session;
	struct sink_context	 sink;
	int			 terminal_error;
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_LOGCMP_POLICY, getuid(), (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

static int
harden_factory_channel(cap_channel_t *channel)
{
	int fd;

	fd = cap_sock(channel);
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
harden_worker_channel(cap_channel_t *channel)
{
	int fd;

	fd = cap_sock(channel);
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
harden_worker_fd(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
syslog_sink(void *arg, const struct logcmp_record *record,
    const char *message, const char *fields)
{
	struct sink_context *context;
	char sanitized[LOGCMP_MAX_FIELDS + 1];
	size_t i;

	context = arg;
	if (record->fields_length == 0)
		cap_syslog(context->syslog, (int)record->severity,
		    "[service=%s instance=%ju sequence=%ju] %.*s",
		    context->label, (uintmax_t)context->instance,
		    (uintmax_t)record->sequence, (int)record->message_length,
		    message);
	else {
		memcpy(sanitized, fields, record->fields_length);
		for (i = 0; i < record->fields_length; i++)
			if (sanitized[i] == '\n')
				sanitized[i] = ' ';
		sanitized[record->fields_length] = '\0';
		cap_syslog(context->syslog, (int)record->severity,
		    "[service=%s instance=%ju sequence=%ju] %.*s {%.*s}",
		    context->label, (uintmax_t)context->instance,
		    (uintmax_t)record->sequence, (int)record->message_length,
		    message, (int)record->fields_length, sanitized);
	}
	LOGCMPD_PROBE_RECORD(context->label, record->severity,
	    record->message_length, 0);
	return (0);
}

static int
send_reply(struct channel_message *request_message,
    const struct logcmp_msg *request, int error, const void *payload,
    size_t payload_length)
{
	union provider_buffer buffer;
	struct logcmp_msg *reply;
	size_t length;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	if (logcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (logcmp_validate_message(reply, length, LOGCMP_MESSAGE_REPLY) == -1 ||
	    logcmp_validate_fds(reply, 0, LOGCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(reply, length)));
}

static int
drain_session(struct worker_state *state, const char *operation)
{
	int error;

	if (logcmp_session_drain(&state->session, syslog_sink,
	    &state->sink) == 0)
		return (0);
	error = errno != 0 ? errno : EPROTO;
	audit_policy(state->sink.label, operation, error);
	LOGCMPD_PROBE_DROP(state->sink.label,
	    state->session.stats.last_sequence, error);
	errno = error;
	return (-1);
}

static void
handle_event(struct channel *channel __unused,
    struct channel_message *event_message, void *argument)
{
	struct worker_state *state;
	const struct logcmp_msg *message;
	size_t length;

	state = argument;
	message = channel_message_data(event_message);
	length = channel_message_length(event_message);
	if (logcmp_validate_message(message, length, LOGCMP_MESSAGE_EVENT) ==
	    -1 || logcmp_validate_fds(message,
	    channel_message_fd_count(event_message), LOGCMP_MESSAGE_EVENT) ==
	    -1) {
		state->terminal_error = EPROTO;
	} else if (drain_session(state, "batch-notify") == -1) {
		/*
		 * A wake received before ATTACH is a protocol violation.  Sink
		 * failures are session-local and also terminate this producer.
		 */
		state->terminal_error = errno;
	}
	channel_message_free(event_message);
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct logcmp_hello_reply hello;
	struct shmring_fds ringfds;
	struct worker_state *state;
	const struct logcmp_msg *message;
	uint64_t rejected_before;
	size_t length;
	int error;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (logcmp_validate_message(message, length,
	    LOGCMP_MESSAGE_REQUEST) == -1 ||
	    logcmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    LOGCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}

	error = 0;
	rejected_before = state->session.stats.rejected;
	switch (message->opcode) {
	case LOGCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = LOGCMP_ABI_VERSION;
		hello.features = LOGCMP_FEATURE_INLINE |
		    LOGCMP_FEATURE_SHM_RING | LOGCMP_FEATURE_SYSLOG;
		hello.ring_size = LOGCMP_RING_SIZE;
		hello.max_record = LOGCMP_MAX_RECORD;
		hello.max_text = LOGCMP_MAX_TEXT;
		hello.max_fields = LOGCMP_MAX_FIELDS;
		if (send_reply(request_message, message, 0, &hello,
		    sizeof(hello)) == -1)
			state->terminal_error = errno;
		channel_message_free(request_message);
		return;
	case LOGCMP_OP_ATTACH:
		ringfds.config_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_CONFIG);
		ringfds.data_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_DATA);
		ringfds.head_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_HEAD);
		ringfds.tail_fd = channel_message_borrow_fd(request_message,
		    LOGCMP_ATTACH_FD_TAIL);
		if (ringfds.config_fd == -1 || ringfds.data_fd == -1 ||
		    ringfds.head_fd == -1 || ringfds.tail_fd == -1 ||
		    logcmp_session_attach(&state->session,
		    (const void *)(message + 1), &ringfds) == -1)
			error = errno != 0 ? errno : EPROTO;
		break;
	case LOGCMP_OP_WRITE:
		if (logcmp_session_submit(&state->session,
		    (const void *)(message + 1), length - sizeof(*message),
		    syslog_sink, &state->sink) == -1)
			error = errno != 0 ? errno : EPROTO;
		break;
	case LOGCMP_OP_FLUSH:
		if (drain_session(state, "explicit-flush") == -1)
			error = errno;
		break;
	case LOGCMP_OP_STATS:
		if (send_reply(request_message, message, 0,
		    &state->session.stats, sizeof(state->session.stats)) == -1)
			state->terminal_error = errno;
		channel_message_free(request_message);
		return;
	case LOGCMP_OP_DETACH:
		if (logcmp_session_detach(&state->session) == -1)
			error = errno != 0 ? errno : EPROTO;
		break;
	default:
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}
	if (error != 0) {
		if (state->session.stats.rejected == rejected_before)
			state->session.stats.rejected++;
		audit_policy(state->sink.label, "request-denied", error);
		LOGCMPD_PROBE_DROP(state->sink.label,
		    state->session.stats.last_sequence, error);
	}
	if (send_reply(request_message, message, error, NULL, 0) == -1)
		state->terminal_error = errno;
	channel_message_free(request_message);
}

static int
worker(int fd, int barrier, cap_channel_t *capsyslog,
    const char *client_label, uint64_t instance_id)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct kevent changes[3], event;
	struct worker_state state;
	struct channel *channel;
	char byte;
	int channel_descriptor, error, kq, wants_write;

	memset(&state, 0, sizeof(state));
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	if (channel_create(fd, &options, &channel) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request, &state) == -1 ||
	    channel_set_event_handler(channel, handle_event, &state) == -1) {
		error = errno;
		channel_destroy(channel);
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	channel_descriptor = channel_fd(channel);
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1 || harden_worker_fd(kq) == -1) {
		error = errno;
		if (kq >= 0)
			close(kq);
		channel_destroy(channel);
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	EV_SET(&changes[0], channel_descriptor, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(&changes[1], channel_descriptor, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, 0, 0, NULL);
	EV_SET(&changes[2], LOGCMP_DRAIN_TIMER_IDENT, EVFILT_TIMER,
	    EV_ADD | EV_ENABLE, NOTE_MSECONDS, LOGCMP_DRAIN_INTERVAL_MS, NULL);
	if (kevent(kq, changes, nitems(changes), NULL, 0, NULL) == -1) {
		error = errno;
		close(kq);
		channel_destroy(channel);
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	logcmp_session_init(&state.session, LOGCMP_MAX_RECORD);
	state.sink.syslog = capsyslog;
	state.sink.label = client_label;
	state.sink.instance = instance_id;
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1) {
		logcmp_session_destroy(&state.session);
		channel_destroy(channel);
		close(kq);
		return (1);
	}
	close(barrier);

	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		EV_SET(&changes[0], channel_descriptor, EVFILT_WRITE,
		    wants_write ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
		if (kevent(kq, changes, 1, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if ((event.flags & EV_ERROR) != 0) {
			errno = event.data != 0 ? (int)event.data : EIO;
			break;
		}
		if (event.filter == EVFILT_TIMER) {
			if (state.session.ring != NULL)
				(void)drain_session(&state, "timer-drain");
			continue;
		}
		if (event.ident != (uintptr_t)channel_descriptor)
			continue;
		if (event.filter == EVFILT_WRITE &&
		    channel_flush(channel) == -1)
			break;
		if (event.filter == EVFILT_READ &&
		    channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}

	logcmp_session_destroy(&state.session);
	cap_close(capsyslog);
	close(kq);
	channel_destroy(channel);
	return (0);
}

static int
start_session(int fd, cap_channel_t *casper, const char *peer_label)
{
	cap_channel_t *capsyslog;
	static uint64_t next_instance;
	uint64_t instance_id;
	char byte;
	int syncfd[2], pd, child_error, error;
	ssize_t n;
	pid_t pid;

	instance_id = ++next_instance;
	capsyslog = cap_service_open(casper, "system.syslog");
	if (capsyslog == NULL) {
		error = errno;
		goto reject;
	}
	cap_openlog(capsyslog, "logcmp", LOG_PID | LOG_NDELAY, LOG_USER);
	if (harden_worker_channel(capsyslog) == -1 ||
	    harden_worker_fd(fd) == -1 ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		cap_close(capsyslog);
		goto reject;
	}
	if (harden_worker_fd(syncfd[1]) == -1 ||
	    cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capsyslog);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capsyslog);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		cap_close(casper);
		_exit(worker(fd, syncfd[1], capsyslog, peer_label,
		    instance_id));
	}
	cap_close(capsyslog);
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	LOGCMPD_PROBE_SESSION(peer_label, instance_id, 0);
	return (0);

reject:
	audit_policy(peer_label, "session-bootstrap", error);
	LOGCMPD_PROBE_SESSION(peer_label, instance_id, error);
	errno = error;
	return (-1);
}

int
main(void)
{
	cap_channel_t *casper;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	openlog("logcmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	casper = cap_init();
	if (casper == NULL || harden_factory_channel(casper) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, LOGCMP_PROVIDER_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (start_session(fd, casper, identity.client_label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
