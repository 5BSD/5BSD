/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/procdesc.h>
#include <sys/reboot.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <notifycmp.h>
#include <rebootctl.h>
#include <rebootctl_server.h>

#include "rebootd_policy.h"
#include "rebootd_ops.h"
#include "rebootd_probes.h"
#include "rebootd_store.h"
#ifndef REBOOTD_TESTING
#include "rebootd_state.h"
#endif
#ifdef REBOOTD_TESTING
#include "rebootd_test.h"

static int rebootd_test_persist_error;
static unsigned rebootd_test_sequence;
static unsigned rebootd_test_persist_order;
#endif

#define	REBOOT_CLIENT_TIMEOUT_MS	30000

struct session {
	const char	*label;
	const struct rebootd_backend *backend;
	_Atomic bool	*pending;
	struct rebootd_schedule *schedule;
	struct notifycmp_client *notify;
	uint64_t	 execute_mono_ns;
	bool		 scheduled;
	bool		 imminent_sent;
	bool		 allowed;
	int		 error;
};

struct rebootd_schedule {
	_Atomic uint32_t phase;	/* 0 idle, 1 initializing, 2 scheduled */
	_Atomic uint64_t next_request_id;
	_Atomic uint64_t request_id;
	_Atomic uint64_t requested_at_ns;
	_Atomic uint64_t execute_at_ns;
	_Atomic uint32_t howto;
	_Atomic uint32_t opcode;
	_Atomic uint64_t execute_mono_ns;
	_Atomic bool imminent_sent;
	char requester[64];
};

#ifndef REBOOTD_TESTING
static _Atomic bool *shutdown_pending;
static struct rebootd_schedule *shutdown_schedule;
static struct rebootd_store *shutdown_store;
#endif

static int
persist_schedule(const struct rebootd_schedule *schedule, bool active,
    enum rebootd_store_commit *commitp)
{
#ifdef REBOOTD_TESTING
	(void)schedule;
	(void)active;
	rebootd_test_persist_order = ++rebootd_test_sequence;
	if (rebootd_test_persist_error != 0)
		return (errno = rebootd_test_persist_error, -1);
	if (commitp != NULL)
		*commitp = REBOOTD_STORE_DURABLE;
	return (0);
#else
	struct rebootd_state_record record;

	memset(&record, 0, sizeof(record));
	record.active = active;
	record.next_request_id = atomic_load_explicit(
	    &schedule->next_request_id, memory_order_acquire);
	if (active) {
		record.request_id = atomic_load_explicit(&schedule->request_id,
		    memory_order_acquire);
		record.requested_at_ns = atomic_load_explicit(
		    &schedule->requested_at_ns, memory_order_acquire);
		record.execute_at_ns = atomic_load_explicit(
		    &schedule->execute_at_ns, memory_order_acquire);
		record.howto = atomic_load_explicit(&schedule->howto,
		    memory_order_acquire);
		record.opcode = (uint16_t)atomic_load_explicit(&schedule->opcode,
		    memory_order_acquire);
		record.requester_length = (uint16_t)strnlen(schedule->requester,
		    sizeof(record.requester));
		memcpy(record.requester, schedule->requester,
		    record.requester_length);
	}
	rebootd_state_seal(&record);
	return (rebootd_store_save(shutdown_store, &record, commitp));
#endif
}

static uint64_t
clock_ns(clockid_t clock)
{
	struct timespec now;

	if (clock_gettime(clock, &now) == -1)
		return (0);
	return ((uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec);
}

static int
publish_shutdown(struct session *session, uint32_t state, const char *topic,
    int error)
{
	struct rebootctl_notification event;
	size_t length;
	uint64_t now, execute;

	if (session->notify == NULL)
		return (0);
	memset(&event, 0, sizeof(event));
	event.version = REBOOTCTL_ABI_VERSION;
	event.state = state;
	event.request_id = atomic_load_explicit(&session->schedule->request_id,
	    memory_order_acquire);
	event.requested_at_ns = atomic_load_explicit(
	    &session->schedule->requested_at_ns, memory_order_acquire);
	execute = atomic_load_explicit(&session->schedule->execute_at_ns,
	    memory_order_acquire);
	event.execute_at_ns = execute;
	event.howto = atomic_load_explicit(&session->schedule->howto,
	    memory_order_acquire);
	event.error = error;
	now = clock_ns(CLOCK_REALTIME);
	if (execute > now)
		event.remaining_ms = (uint32_t)MIN((execute - now) / 1000000,
		    UINT32_MAX);
	length = strnlen(session->label, sizeof(event.requester));
	event.requester_length = (uint16_t)length;
	memcpy(event.requester, session->label, length);
	return (notifycmp_publish(session->notify, topic, &event, sizeof(event)));
}

static void
clear_schedule(struct session *session)
{

	atomic_store_explicit(session->pending, false, memory_order_release);
	atomic_store_explicit(&session->schedule->request_id, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->requested_at_ns, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->execute_at_ns, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->howto, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->opcode, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->execute_mono_ns, 0,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->imminent_sent, false,
	    memory_order_relaxed);
	explicit_bzero(session->schedule->requester,
	    sizeof(session->schedule->requester));
	atomic_store_explicit(&session->schedule->phase, 0, memory_order_release);
}

static int
schedule_shutdown(struct session *session, uint16_t opcode,
    const struct rebootctl_request *request)
{
	uint32_t expected;
	uint64_t requested, execute;
	enum rebootd_store_commit commit;
	int error, howto;

	error = rebootd_validate(opcode, request, session->allowed, &howto);
	if (error != 0)
		return (error);
	expected = 0;
	if (!atomic_compare_exchange_strong_explicit(&session->schedule->phase,
	    &expected, 1, memory_order_acq_rel, memory_order_acquire))
		return (EALREADY);
	requested = clock_ns(CLOCK_REALTIME);
	if (requested == 0) {
		clear_schedule(session);
		return (EIO);
	}
	execute = requested + (uint64_t)request->delay_ms * 1000000;
	atomic_store_explicit(&session->schedule->request_id,
	    atomic_fetch_add_explicit(&session->schedule->next_request_id, 1,
	    memory_order_relaxed) + 1, memory_order_relaxed);
	atomic_store_explicit(&session->schedule->requested_at_ns, requested,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->execute_at_ns, execute,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->howto, (uint32_t)howto,
	    memory_order_relaxed);
	atomic_store_explicit(&session->schedule->opcode, opcode,
	    memory_order_relaxed);
	session->execute_mono_ns = clock_ns(CLOCK_MONOTONIC) +
	    (uint64_t)request->delay_ms * 1000000;
	atomic_store_explicit(&session->schedule->execute_mono_ns,
	    session->execute_mono_ns, memory_order_relaxed);
	strlcpy(session->schedule->requester, session->label,
	    sizeof(session->schedule->requester));
	if (session->execute_mono_ns == 0 ||
	    publish_shutdown(session, REBOOTCTL_NOTIFICATION_REQUESTED,
	    REBOOTCTL_NOTIFY_REQUESTED, 0) == -1) {
		error = errno != 0 ? errno : EIO;
		(void)publish_shutdown(session, REBOOTCTL_NOTIFICATION_CANCELLED,
		    REBOOTCTL_NOTIFY_CANCELLED, error);
		clear_schedule(session);
		return (error);
	}
	commit = REBOOTD_STORE_NOT_COMMITTED;
	if (persist_schedule(session->schedule, true, &commit) == -1) {
		error = errno != 0 ? errno : EIO;
		if (commit == REBOOTD_STORE_NOT_COMMITTED) {
			(void)publish_shutdown(session,
			    REBOOTCTL_NOTIFICATION_CANCELLED,
			    REBOOTCTL_NOTIFY_CANCELLED, error);
			clear_schedule(session);
		} else {
			/*
			 * The rename is visible but its directory durability is
			 * uncertain.  Preserve the pending operation so STATUS can
			 * reconcile the ambiguous acknowledgement.  Execution still
			 * requires a durable inactive checkpoint in coordinator_tick().
			 */
			atomic_store_explicit(session->pending, true,
			    memory_order_release);
			atomic_store_explicit(&session->schedule->phase, 2,
			    memory_order_release);
			session->scheduled = true;
		}
		return (error);
	}
	if (publish_shutdown(session, REBOOTCTL_NOTIFICATION_SCHEDULED,
	    REBOOTCTL_NOTIFY_SCHEDULED, 0) == -1)
		syslog(LOG_WARNING, "scheduled notification for %s: %m",
		    session->label);
	atomic_store_explicit(session->pending, true, memory_order_release);
	atomic_store_explicit(&session->schedule->phase, 2, memory_order_release);
	REBOOTD_PROBE_SCHEDULE(__DECONST(char *, session->label),
	    atomic_load_explicit(&session->schedule->request_id,
	    memory_order_acquire), execute, (uint32_t)howto);
	session->scheduled = true;
	return (0);
}

#ifdef REBOOTD_TESTING
static void
audit_request(const char *label __unused, uint32_t opcode __unused,
    int error __unused)
{
}
#else
static void
audit_request(const char *label, uint32_t opcode, int error)
{

	(void)audit_submit((short)AUE_REBOOT, AU_DEFAUDITID, (char)error,
	    error != 0, "client=%s opcode=%u result=%d", label, opcode,
	    error);
}

static int
backend_reboot(int howto, void *context __unused)
{

	return (reboot(howto));
}

static const struct rebootd_backend system_backend = {
	.reboot = backend_reboot,
	.context = NULL
};
#endif /* REBOOTD_TESTING */

static int
scheduler_tick(struct rebootd_schedule *schedule, _Atomic bool *pending,
    struct notifycmp_client *notify, const struct rebootd_backend *backend)
{
	struct session session;
	uint64_t execute, now;
	enum rebootd_store_commit commit;
	bool disarmed;
	int error;

	if (atomic_load_explicit(&schedule->phase, memory_order_acquire) != 2)
		return (0);
	execute = atomic_load_explicit(&schedule->execute_mono_ns,
	    memory_order_acquire);
	now = clock_ns(CLOCK_MONOTONIC);
	if (now == 0)
		return (-1);
	memset(&session, 0, sizeof(session));
	session.label = schedule->requester;
	session.backend = backend;
	session.pending = pending;
	session.schedule = schedule;
	session.notify = notify;
	disarmed = false;
	if (!atomic_load_explicit(&schedule->imminent_sent,
	    memory_order_acquire) && now +
	    (uint64_t)REBOOTCTL_IMMINENT_MS * 1000000 >= execute) {
		if (publish_shutdown(&session, REBOOTCTL_NOTIFICATION_IMMINENT,
		    REBOOTCTL_NOTIFY_IMMINENT, 0) == -1)
			goto cancel;
		atomic_store_explicit(&schedule->imminent_sent, true,
		    memory_order_release);
		REBOOTD_PROBE_IMMINENT(atomic_load_explicit(&schedule->request_id,
		    memory_order_acquire), REBOOTCTL_IMMINENT_MS);
	}
	if (now < execute)
		return (0);
	/* Never replay a non-idempotent reboot after a coordinator crash. */
	commit = REBOOTD_STORE_NOT_COMMITTED;
	if (persist_schedule(schedule, false, &commit) == -1)
		return (-1);
	disarmed = true;
	error = backend->reboot((int)atomic_load_explicit(&schedule->howto,
	    memory_order_acquire), backend->context);
	REBOOTD_PROBE_EXECUTE(atomic_load_explicit(&schedule->request_id,
	    memory_order_acquire), atomic_load_explicit(&schedule->howto,
	    memory_order_acquire), error == -1 ? errno : EIO);
	if (error == -1)
		goto cancel;
	errno = EIO;
cancel:
	error = errno != 0 ? errno : EIO;
	if (!disarmed) {
		commit = REBOOTD_STORE_NOT_COMMITTED;
		if (persist_schedule(schedule, false, &commit) == -1)
			return (-1);
	}
	audit_request(schedule->requester,
	    atomic_load_explicit(&schedule->opcode, memory_order_acquire), error);
	REBOOTD_PROBE_CANCEL(atomic_load_explicit(&schedule->request_id,
	    memory_order_acquire), error);
	if (publish_shutdown(&session, REBOOTCTL_NOTIFICATION_CANCELLED,
	    REBOOTCTL_NOTIFY_CANCELLED, error) == -1)
		syslog(LOG_WARNING, "failure notification for %s: %m",
		    session.label);
	clear_schedule(&session);
	return (errno = error, -1);
}

static int
send_reply(struct channel_message *message, const struct session *session,
    uint16_t opcode, int error, bool include_status)
{
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_status_reply status;
	} reply;
	size_t length;

	memset(&reply, 0, sizeof(reply));
	reply.msg.magic = REBOOTCTL_MAGIC;
	reply.msg.version = REBOOTCTL_ABI_VERSION;
	reply.msg.opcode = opcode;
	reply.msg.status = error == 0 ? 0 : -error;
	reply.status.pending = atomic_load_explicit(session->pending,
	    memory_order_acquire);
	if (reply.status.pending != 0) {
		if (session->schedule != NULL) {
			reply.status.howto = atomic_load_explicit(
			    &session->schedule->howto, memory_order_acquire);
			reply.status.request_id = atomic_load_explicit(
			    &session->schedule->request_id, memory_order_acquire);
			reply.status.requested_at_ns = atomic_load_explicit(
			    &session->schedule->requested_at_ns,
			    memory_order_acquire);
			reply.status.execute_at_ns = atomic_load_explicit(
			    &session->schedule->execute_at_ns, memory_order_acquire);
		} else {
			/* Unit-test/immediate backend compatibility state. */
			reply.status.request_id = 1;
			reply.status.requested_at_ns = 1;
			reply.status.execute_at_ns = 1;
		}
	}
	length = sizeof(reply.msg) +
	    (error == 0 && include_status ? sizeof(reply.status) : 0);
	if (rebootctl_validate_reply(&reply.msg, length) == -1)
		return (-1);
	return (channel_send_reply(message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, length)));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct rebootctl_msg *request;
	const struct rebootctl_request *operation;
	struct session *session;
	int error;

	session = argument;
	request = NULL;
	if (channel_message_fd_count(message) != 0 ||
	    rebootctl_validate_request(channel_message_data(message),
	    channel_message_length(message)) == -1) {
		REBOOTD_PROBE_MALFORMED(
		    __DECONST(char *, session->label), EPROTO);
		session->error = EPROTO;
		goto out;
	}
	request = channel_message_data(message);
	operation = (const void *)(request + 1);
	error = 0;
	switch (request->opcode) {
	case REBOOTCTL_OP_REBOOT:
	case REBOOTCTL_OP_SHUTDOWN:
	case REBOOTCTL_OP_STATUS:
	case REBOOTCTL_OP_CANCEL:
		if (request->opcode == REBOOTCTL_OP_CANCEL &&
		    session->schedule != NULL) {
			enum rebootd_store_commit commit;

			error = rebootd_validate(request->opcode, NULL,
			    session->allowed, &(int){ 0 });
			if (error == 0 && atomic_load_explicit(
			    &session->schedule->phase, memory_order_acquire) != 2)
				error = ENOENT;
			if (error == 0) {
				commit = REBOOTD_STORE_NOT_COMMITTED;
				if (persist_schedule(session->schedule, false,
				    &commit) == -1) {
					error = errno != 0 ? errno : EIO;
					if (commit == REBOOTD_STORE_VISIBLE) {
						(void)publish_shutdown(session,
						    REBOOTCTL_NOTIFICATION_CANCELLED,
						    REBOOTCTL_NOTIFY_CANCELLED, error);
						REBOOTD_PROBE_CANCEL(atomic_load_explicit(
						    &session->schedule->request_id,
						    memory_order_acquire), error);
						clear_schedule(session);
					}
					break;
				}
				if (publish_shutdown(session,
				    REBOOTCTL_NOTIFICATION_CANCELLED,
				    REBOOTCTL_NOTIFY_CANCELLED, ECANCELED) == -1)
					syslog(LOG_WARNING,
					    "cancel notification for %s: %m",
					    session->label);
				REBOOTD_PROBE_CANCEL(atomic_load_explicit(
				    &session->schedule->request_id,
				    memory_order_acquire), ECANCELED);
				clear_schedule(session);
			}
			break;
		}
		if (session->schedule != NULL &&
		    request->opcode != REBOOTCTL_OP_STATUS &&
		    request->opcode != REBOOTCTL_OP_CANCEL)
			error = schedule_shutdown(session, request->opcode, operation);
		else
			error = rebootd_execute(request->opcode, operation,
			    session->allowed, session->pending, session->backend);
		if (error != 0)
			syslog(LOG_WARNING, "operation %u for %s denied or failed: %s",
			    request->opcode, session->label, strerror(error));
		else if (request->opcode != REBOOTCTL_OP_STATUS)
			syslog(LOG_NOTICE, "operation %u requested by %s",
			    request->opcode, session->label);
		break;
	default:
		error = rebootd_execute(request->opcode, operation,
		    session->allowed, session->pending, session->backend);
		break;
	}
	if (request != NULL) {
		if (request->opcode == REBOOTCTL_OP_REBOOT ||
		    request->opcode == REBOOTCTL_OP_SHUTDOWN ||
		    request->opcode == REBOOTCTL_OP_CANCEL)
			audit_request(session->label, request->opcode, error);
		REBOOTD_PROBE_REQUEST(__DECONST(char *, session->label),
		    request->opcode, error);
	}
	if (send_reply(message, session, request->opcode, error,
	    request->opcode == REBOOTCTL_OP_STATUS) == -1)
		session->error = errno;
out:
	channel_message_free(message);
}

#ifndef REBOOTD_TESTING
static int serve_session(int, const char *, bool, _Atomic bool *,
    const struct rebootd_backend *, struct rebootd_schedule *,
    struct notifycmp_client *, bool) __unused;
#endif

static int
serve_session(int fd, const char *label, bool allowed,
    _Atomic bool *pending, const struct rebootd_backend *backend,
    struct rebootd_schedule *schedule, struct notifycmp_client *notify,
    bool protect)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct pollfd descriptor;
	struct session session;
	int loop_error, result, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || pending == NULL ||
	    backend == NULL || backend->reboot == NULL)
		return (errno = EINVAL, -1);
	if (protect && service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC |
	    SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (protect)
		service_worker_drop_inherited_authority();
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.backend = backend;
	session.pending = pending;
	session.schedule = schedule;
	session.notify = notify;
	session.allowed = allowed;
	loop_error = 0;
	REBOOTD_PROBE_SESSION_START(__DECONST(char *, label));
	if (channel_create(fd, &options, &channel) == -1) {
		REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request, &session) ==
	    -1) {
		result = errno;
		channel_destroy(channel);
		REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), result);
		return (1);
	}
	for (;;) {
		wants_write = channel != NULL ? channel_wants_write(channel) : 0;
		if (wants_write == -1) {
			loop_error = errno;
			break;
		}
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel != NULL ? channel_fd(channel) : -1;
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		if (session.scheduled) {
			uint64_t now, wake;

			now = clock_ns(CLOCK_MONOTONIC);
			wake = session.execute_mono_ns;
			if (!session.imminent_sent &&
			    wake > (uint64_t)REBOOTCTL_IMMINENT_MS * 1000000)
				wake -= (uint64_t)REBOOTCTL_IMMINENT_MS * 1000000;
			if (now >= wake)
				result = 0;
			else
				result = (int)MIN((wake - now + 999999) / 1000000,
				    INT_MAX);
		} else
			result = REBOOT_CLIENT_TIMEOUT_MS;
		do {
			result = poll(&descriptor, 1, result);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			if (!session.scheduled) {
				loop_error = ETIMEDOUT;
				break;
			}
			if (!session.imminent_sent && clock_ns(CLOCK_MONOTONIC) <
			    session.execute_mono_ns) {
				if (publish_shutdown(&session,
				    REBOOTCTL_NOTIFICATION_IMMINENT,
				    REBOOTCTL_NOTIFY_IMMINENT, 0) == -1) {
					loop_error = errno;
					(void)publish_shutdown(&session,
					    REBOOTCTL_NOTIFICATION_CANCELLED,
					    REBOOTCTL_NOTIFY_CANCELLED, loop_error);
					clear_schedule(&session);
					break;
				}
				session.imminent_sent = true;
				continue;
			}
			if (backend->reboot((int)atomic_load_explicit(
			    &schedule->howto, memory_order_acquire),
			    backend->context) == -1) {
				loop_error = errno != 0 ? errno : EIO;
				(void)publish_shutdown(&session,
				    REBOOTCTL_NOTIFICATION_CANCELLED,
				    REBOOTCTL_NOTIFY_CANCELLED, loop_error);
				clear_schedule(&session);
				break;
			}
			break;
		}
		if (result == -1) {
			loop_error = errno;
			break;
		}
		if (channel != NULL && (descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1) {
			loop_error = errno;
			break;
		}
		if (channel != NULL && (descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1) {
			loop_error = errno;
			if (!session.scheduled)
				break;
			channel_destroy(channel);
			channel = NULL;
			loop_error = 0;
		}
		if (session.error != 0) {
			loop_error = session.error;
			break;
		}
	}
	if (channel != NULL)
		channel_destroy(channel);
	notifycmp_client_close(notify);
	REBOOTD_PROBE_SESSION_END(__DECONST(char *, label), loop_error);
	return (loop_error == 0 ? 0 : 1);
}

#ifdef REBOOTD_TESTING
struct rebootd_test_backend_context {
	int error;
	unsigned order;
};

static int
rebootd_test_backend_reboot(int howto __unused, void *argument)
{
	struct rebootd_test_backend_context *context;

	context = argument;
	context->order = ++rebootd_test_sequence;
	return (context->error == 0 ? 0 : (errno = context->error, -1));
}

int
rebootd_test_scheduler_tick(int persist_error, int reboot_error,
    unsigned *persist_order, unsigned *reboot_order, bool *pending_after)
{
	struct rebootd_test_backend_context backend_context;
	struct rebootd_backend backend;
	struct rebootd_schedule schedule;
	_Atomic bool pending;
	int result;

	memset(&schedule, 0, sizeof(schedule));
	atomic_init(&schedule.phase, 2);
	atomic_init(&schedule.request_id, 1);
	atomic_init(&schedule.howto, RB_REROOT);
	atomic_init(&schedule.opcode, REBOOTCTL_OP_REBOOT);
	atomic_init(&schedule.execute_mono_ns, 1);
	strlcpy(schedule.requester, "org.test.scheduler",
	    sizeof(schedule.requester));
	atomic_init(&pending, true);
	backend_context = (struct rebootd_test_backend_context){
		.error = reboot_error,
	};
	backend = (struct rebootd_backend){
		.reboot = rebootd_test_backend_reboot,
		.context = &backend_context,
	};
	rebootd_test_persist_error = persist_error;
	rebootd_test_sequence = 0;
	rebootd_test_persist_order = 0;
	result = scheduler_tick(&schedule, &pending, NULL, &backend);
	*persist_order = rebootd_test_persist_order;
	*reboot_order = backend_context.order;
	*pending_after = atomic_load_explicit(&pending, memory_order_acquire);
	rebootd_test_persist_error = 0;
	return (result);
}

int
rebootd_test_serve(int fd, const char *label, bool allowed,
    _Atomic bool *pending, const struct rebootd_backend *backend)
{

	return (serve_session(fd, label, allowed, pending, backend, NULL, NULL,
	    false));
}
#else

#define	REBOOTD_MAX_SESSIONS	65536U
#define	REBOOTD_MAX_EVENTS	128

struct coordinator_client {
	struct coordinator_client *next;
	struct channel	*channel;
	struct session	 session;
	int		 fd;
};

static int
coordinator_change(int kq, uintptr_t ident, int16_t filter, uint16_t flags,
    void *udata)
{
	struct kevent change;

	EV_SET(&change, ident, filter, flags, 0, 0, udata);
	return (kevent(kq, &change, 1, NULL, 0, NULL));
}

static void
coordinator_remove(int kq, struct coordinator_client **clients,
    struct coordinator_client *client, size_t *count)
{
	struct coordinator_client **cursor;
	char *label;

	cursor = clients;
	while (*cursor != NULL && *cursor != client)
		cursor = &(*cursor)->next;
	if (*cursor == client)
		*cursor = client->next;
	(void)coordinator_change(kq, client->fd, EVFILT_READ, EV_DELETE, NULL);
	channel_destroy(client->channel);
	if (*count != 0)
		(*count)--;
	REBOOTD_PROBE_SESSION_END(__DECONST(char *, client->session.label),
	    client->session.error);
	label = __DECONST(char *, client->session.label);
	explicit_bzero(client, sizeof(*client));
	free(label);
	free(client);
}

static int
coordinator_add(int kq, struct coordinator_client **clients, size_t *count,
    int fd, const char *label, bool allowed, struct rebootd_schedule *schedule,
    _Atomic bool *pending, struct notifycmp_client *notify)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct coordinator_client *client;
	int error;

	if (*count >= REBOOTD_MAX_SESSIONS)
		return (errno = ENOSPC, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return (-1);
	client->fd = -1;
	client->session.label = strdup(label);
	client->session.backend = &system_backend;
	client->session.pending = pending;
	client->session.schedule = schedule;
	client->session.notify = notify;
	client->session.allowed = allowed;
	if (client->session.label == NULL ||
	    cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    channel_create(fd, &options, &client->channel) == -1 ||
	    channel_set_request_handler(client->channel, handle_request,
	    &client->session) == -1) {
		error = errno != 0 ? errno : EIO;
		if (client->channel != NULL)
			channel_destroy(client->channel);
		else
			close(fd);
		free(__DECONST(char *, client->session.label));
		free(client);
		return (errno = error, -1);
	}
	client->fd = channel_fd(client->channel);
	if (coordinator_change(kq, client->fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, client) == -1 ||
	    coordinator_change(kq, client->fd, EVFILT_WRITE,
	    EV_ADD | EV_DISABLE, client) == -1) {
		error = errno;
		channel_destroy(client->channel);
		free(__DECONST(char *, client->session.label));
		free(client);
		return (errno = error, -1);
	}
	client->next = *clients;
	*clients = client;
	(*count)++;
	REBOOTD_PROBE_SESSION_START(__DECONST(char *, client->session.label));
	return (0);
}

static int
coordinator_tick(struct rebootd_schedule *schedule, _Atomic bool *pending,
    struct notifycmp_client *notify)
{

	return (scheduler_tick(schedule, pending, notify, &system_backend));
}

static int
restore_schedule(struct rebootd_store *store, struct rebootd_schedule *schedule,
    _Atomic bool *pending)
{
	struct rebootd_state_record record;
	uint64_t mono, realtime, remaining;

	if (rebootd_store_load(store, &record) == -1)
		return (-1);
	atomic_store_explicit(&schedule->next_request_id,
	    record.next_request_id, memory_order_relaxed);
	if (record.active == 0)
		return (0);
	realtime = clock_ns(CLOCK_REALTIME);
	mono = clock_ns(CLOCK_MONOTONIC);
	if (realtime == 0 || mono == 0)
		return (errno = EIO, -1);
	remaining = record.execute_at_ns > realtime ?
	    record.execute_at_ns - realtime : 0;
	atomic_store_explicit(&schedule->request_id, record.request_id,
	    memory_order_relaxed);
	atomic_store_explicit(&schedule->requested_at_ns,
	    record.requested_at_ns, memory_order_relaxed);
	atomic_store_explicit(&schedule->execute_at_ns, record.execute_at_ns,
	    memory_order_relaxed);
	atomic_store_explicit(&schedule->howto, record.howto,
	    memory_order_relaxed);
	atomic_store_explicit(&schedule->opcode, record.opcode,
	    memory_order_relaxed);
	atomic_store_explicit(&schedule->execute_mono_ns, mono + remaining,
	    memory_order_relaxed);
	atomic_store_explicit(&schedule->imminent_sent, false,
	    memory_order_relaxed);
	memcpy(schedule->requester, record.requester,
	    sizeof(schedule->requester));
	atomic_store_explicit(pending, true, memory_order_release);
	atomic_store_explicit(&schedule->phase, 2, memory_order_release);
	return (0);
}

static void
coordinator_timeout(const struct rebootd_schedule *schedule,
    struct timespec *timeout)
{
	uint64_t execute, now, wake;

	timeout->tv_sec = 1;
	timeout->tv_nsec = 0;
	if (atomic_load_explicit(&schedule->phase, memory_order_acquire) != 2)
		return;
	execute = atomic_load_explicit(&schedule->execute_mono_ns,
	    memory_order_acquire);
	wake = execute;
	if (!atomic_load_explicit(&schedule->imminent_sent,
	    memory_order_acquire) && execute >
	    (uint64_t)REBOOTCTL_IMMINENT_MS * 1000000)
		wake = execute - (uint64_t)REBOOTCTL_IMMINENT_MS * 1000000;
	now = clock_ns(CLOCK_MONOTONIC);
	if (wake <= now) {
		timeout->tv_sec = 0;
		timeout->tv_nsec = 0;
	} else {
		timeout->tv_sec = (time_t)((wake - now) / 1000000000);
		timeout->tv_nsec = (long)((wake - now) % 1000000000);
	}
}

int
main(void)
{
	struct coordinator_client *clients, *client, *next;
	struct kevent events[REBOOTD_MAX_EVENTS];
	struct timespec timeout;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct service_context *context;
	struct notifycmp_client *notify;
	struct rebootd_policy policy;
	size_t nclients;
	int count, fd, i, kq, notify_fd, shutdown_error, wants_write;

	openlog("rebootd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	clients = NULL;
	nclients = 0;
	notify_fd = -1;
	notify = NULL;
	kq = -1;
	shutdown_pending = mmap(NULL, sizeof(*shutdown_pending),
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (shutdown_pending == MAP_FAILED)
		goto fail;
	atomic_init(shutdown_pending, false);
	shutdown_schedule = mmap(NULL, sizeof(*shutdown_schedule),
	    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (shutdown_schedule == MAP_FAILED)
		goto fail;
	memset(shutdown_schedule, 0, sizeof(*shutdown_schedule));
	atomic_init(&shutdown_schedule->phase, 0);
	atomic_init(&shutdown_schedule->next_request_id, 0);
	atomic_init(&shutdown_schedule->request_id, 0);
	atomic_init(&shutdown_schedule->requested_at_ns, 0);
	atomic_init(&shutdown_schedule->execute_at_ns, 0);
	atomic_init(&shutdown_schedule->howto, 0);
	atomic_init(&shutdown_schedule->opcode, 0);
	atomic_init(&shutdown_schedule->execute_mono_ns, 0);
	atomic_init(&shutdown_schedule->imminent_sent, false);
	if (rebootd_store_open(&shutdown_store) == -1 ||
	    restore_schedule(shutdown_store, shutdown_schedule,
	    shutdown_pending) == -1 ||
	    rebootd_policy_load(REBOOTD_POLICY_PATH, &policy) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_acquire(&context) == -1 ||
	    service_connect(context, NOTIFYCMP_INTERFACE, &notify_fd) == -1 ||
	    cap_xfer_limit(notify_fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(notify_fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(notify_fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    notifycmp_client_adopt(notify_fd, &notify) == -1 ||
	    (kq = kqueuex(KQUEUE_CLOEXEC)) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1 ||
	    service_provider_expose(provider, REBOOTCTL_INTERFACE,
	    &listener) == -1 ||
	    coordinator_change(kq, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	if (atomic_load_explicit(&shutdown_schedule->phase,
	    memory_order_acquire) == 2) {
		struct session restored;

		memset(&restored, 0, sizeof(restored));
		restored.label = shutdown_schedule->requester;
		restored.pending = shutdown_pending;
		restored.schedule = shutdown_schedule;
		restored.notify = notify;
		if (publish_shutdown(&restored,
		    REBOOTCTL_NOTIFICATION_SCHEDULED,
		    REBOOTCTL_NOTIFY_SCHEDULED, 0) == -1)
			goto fail;
	}
	for (;;) {
		if (coordinator_tick(shutdown_schedule, shutdown_pending,
		    notify) == -1)
			goto fail;
		coordinator_timeout(shutdown_schedule, &timeout);
		count = kevent(kq, NULL, 0, events, nitems(events), &timeout);
		if (count == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		for (i = 0; i < count; i++) {
			if (events[i].udata == listener) {
				memset(&identity, 0, sizeof(identity));
				identity.size = sizeof(identity);
				if (service_listener_accept(listener, &identity, &fd) == -1) {
					if (service_provider_quiescing(provider) == 1)
						goto shutdown;
					if (errno != EINTR)
						goto fail;
					continue;
				}
				if (coordinator_add(kq, &clients, &nclients, fd,
				    identity.client_label,
				    rebootd_policy_allows(&policy,
				    identity.client_label), shutdown_schedule,
				    shutdown_pending, notify) == -1) {
					syslog(LOG_WARNING, "client %s rejected: %m",
					    identity.client_label);
				}
				continue;
			}
			client = events[i].udata;
			if ((events[i].flags & EV_EOF) != 0) {
				coordinator_remove(kq, &clients, client, &nclients);
				continue;
			}
			if (events[i].filter == EVFILT_WRITE &&
			    channel_flush(client->channel) == -1)
				client->session.error = errno;
			else if (events[i].filter == EVFILT_READ &&
			    channel_dispatch(client->channel) == -1)
				client->session.error = errno;
			if (client->session.error != 0) {
				coordinator_remove(kq, &clients, client, &nclients);
				continue;
			}
			wants_write = channel_wants_write(client->channel);
			if (wants_write == -1 || coordinator_change(kq, client->fd,
			    EVFILT_WRITE, wants_write ? EV_ENABLE : EV_DISABLE,
			    client) == -1) {
				client->session.error = errno != 0 ? errno : EIO;
				coordinator_remove(kq, &clients, client, &nclients);
			}
		}
	}

shutdown:
	shutdown_error = 0;
	if (atomic_load_explicit(&shutdown_schedule->phase,
	    memory_order_acquire) == 2) {
		struct session session;
		enum rebootd_store_commit commit;

		memset(&session, 0, sizeof(session));
		session.label = shutdown_schedule->requester;
		session.pending = shutdown_pending;
		session.schedule = shutdown_schedule;
		session.notify = notify;
		commit = REBOOTD_STORE_NOT_COMMITTED;
		if (persist_schedule(shutdown_schedule, false, &commit) == -1)
			shutdown_error = errno != 0 ? errno : EIO;
		else if (publish_shutdown(&session,
		    REBOOTCTL_NOTIFICATION_CANCELLED,
		    REBOOTCTL_NOTIFY_CANCELLED, ESHUTDOWN) == -1)
			shutdown_error = errno != 0 ? errno : EIO;
		REBOOTD_PROBE_CANCEL(atomic_load_explicit(
		    &shutdown_schedule->request_id, memory_order_acquire),
		    ESHUTDOWN);
		if (shutdown_error == 0 || commit == REBOOTD_STORE_VISIBLE)
			clear_schedule(&session);
	}
	for (client = clients; client != NULL; client = next) {
		next = client->next;
		coordinator_remove(kq, &clients, client, &nclients);
	}
	if (service_provider_quiesce_complete(provider, shutdown_error) == -1)
		return (1);
	notifycmp_client_close(notify);
	rebootd_store_close(shutdown_store);
	close(kq);
	return (shutdown_error == 0 ? 0 : 1);

fail:
	if (notify != NULL)
		notifycmp_client_close(notify);
	else if (notify_fd >= 0)
		close(notify_fd);
	if (kq >= 0)
		close(kq);
	rebootd_store_close(shutdown_store);
	syslog(LOG_ERR, "initialization or service loop: %m");
	closelog();
	return (1);
}
#endif /* !REBOOTD_TESTING */
