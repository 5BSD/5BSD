/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <kldmgr.h>
#include <kldmgr_server.h>
#include <libservice.h>

#include "kldmgrd_policy.h"
#include "kldmgrd_ops.h"
#include "kldmgrd_probes.h"
#ifdef KLDMGRD_TESTING
#include "kldmgrd_test.h"
#endif

#define	KLDMGR_CLIENT_TIMEOUT_MS	30000

static int
prepare_worker_channel(int fd)
{

	/* The session belongs to exactly one worker process. */
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

#ifdef KLDMGRD_TESTING
int
kldmgrd_test_prepare_worker_fd(int fd)
{

	return (prepare_worker_channel(fd));
}
#endif

struct session {
	const char	*label;
	const struct kldmgrd_backend *backend;
	bool		 allowed;
	int		 error;
};

#ifdef KLDMGRD_TESTING
static void
audit_request(const char *label __unused, uint32_t opcode __unused,
    int error __unused)
{
}
#else
static void
audit_request(const char *label, uint32_t opcode, int error)
{
	short event;

	event = opcode == KLDMGR_OP_UNLOAD ? AUE_MODUNLOAD : AUE_MODLOAD;
	(void)audit_submit(event, AU_DEFAUDITID, (char)error, error != 0,
	    "client=%s opcode=%u result=%d", label, opcode, error);
}

static int
backend_load(const char *name, void *context __unused)
{

	return (kldload(name));
}

static int
backend_find(const char *name, void *context __unused)
{

	return (kldfind(name));
}

static int
backend_unload(int id, void *context __unused)
{

	return (kldunload(id));
}

static int
backend_next(int id, void *context __unused)
{

	return (kldnext(id));
}

static int
backend_stat(int id, struct kld_file_stat *status, void *context __unused)
{

	return (kldstat(id, status));
}

static const struct kldmgrd_backend system_backend = {
	.load = backend_load,
	.find = backend_find,
	.unload = backend_unload,
	.next = backend_next,
	.stat = backend_stat,
	.context = NULL
};
#endif /* KLDMGRD_TESTING */

static int
send_reply(struct channel_message *message, uint16_t opcode, int error,
    const void *payload, size_t payload_length)
{
	uint8_t buffer[KLDMGR_MAX_MESSAGE];
	struct kldmgr_msg *reply;
	size_t length;

	if (payload_length > sizeof(buffer) - sizeof(*reply))
		return (errno = EOVERFLOW, -1);
	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	reply->magic = KLDMGR_MAGIC;
	reply->version = KLDMGR_ABI_VERSION;
	reply->opcode = opcode;
	reply->status = error == 0 ? 0 : -error;
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (kldmgr_validate_reply(reply, length) == -1)
		return (-1);
	return (channel_send_reply(message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

static int
respond_list(struct channel_message *message, bool allowed,
	const struct kldmgrd_backend *backend, int *operation_error)
{
	char buffer[sizeof(struct kldmgr_list_reply) +
	    KLDMGR_LIST_MAX * sizeof(struct kldmgr_list_entry)];
	struct kldmgr_list_reply *reply;
	size_t count;
	int error;

	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	error = kldmgrd_list(allowed, backend, reply->entries,
	    KLDMGR_LIST_MAX, &count);
	*operation_error = error;
	if (error != 0)
		return (send_reply(message, KLDMGR_OP_LIST, error, NULL, 0));
	reply->count = (uint32_t)count;
	return (send_reply(message, KLDMGR_OP_LIST, 0, buffer,
	    sizeof(*reply) + count * sizeof(struct kldmgr_list_entry)));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct kldmgr_msg *request;
	const struct kldmgr_module_request *module;
	struct kldmgr_id_reply reply;
	struct session *session;
	int error, result;

	session = argument;
	request = NULL;
	error = 0;
	result = 0;
	memset(&reply, 0, sizeof(reply));
	reply.id = -1;
	if (channel_message_fd_count(message) != 0 ||
	    kldmgr_validate_request(channel_message_data(message),
	    channel_message_length(message)) == -1) {
		KLDMGRD_PROBE_MALFORMED(
		    __DECONST(char *, session->label), EPROTO);
		session->error = EPROTO;
		goto out;
	}
	request = channel_message_data(message);
	module = (const void *)(request + 1);
	error = 0;
	switch (request->opcode) {
	case KLDMGR_OP_LOAD:
	case KLDMGR_OP_UNLOAD:
		error = kldmgrd_execute_module(request->opcode, module,
		    session->allowed, session->backend, &reply.id);
		if (error != 0)
			syslog(LOG_WARNING, "module operation %u for %s: %s",
			    request->opcode, module->name, strerror(error));
		else
			syslog(LOG_INFO, "module operation %u for %s (id %d)",
			    request->opcode, module->name, reply.id);
		result = send_reply(message, request->opcode, error, &reply,
		    sizeof(reply));
		break;
	case KLDMGR_OP_LIST:
		result = respond_list(message, session->allowed, session->backend,
		    &error);
		break;
	default:
		error = EOPNOTSUPP;
		result = send_reply(message, request->opcode, error, NULL, 0);
		break;
	}
out:
	if (request != NULL) {
		if (request->opcode == KLDMGR_OP_LOAD ||
		    request->opcode == KLDMGR_OP_UNLOAD)
			audit_request(session->label, request->opcode, error);
		KLDMGRD_PROBE_REQUEST(__DECONST(char *, session->label),
		    request->opcode, error);
	}
	if (result == -1)
		session->error = errno;
	channel_message_free(message);
}

static int
serve_session(int fd, const char *label, bool allowed,
    const struct kldmgrd_backend *backend, bool protect)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct pollfd descriptor;
	struct session session;
	int loop_error, result, wants_write;

	if (fd < 0 || label == NULL || label[0] == '\0' || backend == NULL ||
	    backend->load == NULL || backend->find == NULL ||
	    backend->unload == NULL || backend->next == NULL ||
	    backend->stat == NULL)
		return (errno = EINVAL, -1);
	if (protect && service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC |
	    SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (protect)
		service_worker_drop_inherited_authority();
	memset(&session, 0, sizeof(session));
	session.label = label;
	session.backend = backend;
	session.allowed = allowed;
	loop_error = 0;
	KLDMGRD_PROBE_SESSION_START(__DECONST(char *, label));
	if (channel_create(fd, &options, &channel) == -1) {
		KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), errno);
		return (1);
	}
	if (channel_set_request_handler(channel, handle_request, &session) ==
	    -1) {
		result = errno;
		channel_destroy(channel);
		KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), result);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			loop_error = errno;
			break;
		}
		memset(&descriptor, 0, sizeof(descriptor));
		descriptor.fd = channel_fd(channel);
		descriptor.events = POLLIN | (wants_write ? POLLOUT : 0);
		do {
			result = poll(&descriptor, 1, KLDMGR_CLIENT_TIMEOUT_MS);
		} while (result == -1 && errno == EINTR);
		if (result == 0) {
			loop_error = ETIMEDOUT;
			break;
		}
		if (result == -1) {
			loop_error = errno;
			break;
		}
		if ((descriptor.revents & POLLOUT) != 0 &&
		    channel_flush(channel) == -1) {
			loop_error = errno;
			break;
		}
		if ((descriptor.revents &
		    (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0 &&
		    channel_dispatch(channel) == -1) {
			loop_error = errno;
			break;
		}
		if (session.error != 0) {
			loop_error = session.error;
			break;
		}
	}
	channel_destroy(channel);
	KLDMGRD_PROBE_SESSION_END(__DECONST(char *, label), loop_error);
	return (loop_error == 0 ? 0 : 1);
}

#ifdef KLDMGRD_TESTING
int
kldmgrd_test_serve(int fd, const char *label, bool allowed,
    const struct kldmgrd_backend *backend)
{

	return (serve_session(fd, label, allowed, backend, false));
}
#else

static int
serve_client(int fd, const char *label, bool allowed)
{

	return (serve_session(fd, label, allowed, &system_backend, true));
}

#define	KLDMGRD_MAX_WORKERS	256U

struct kld_worker {
	struct kld_worker *next;
	int pd;
	pid_t pid;
};

static void
worker_remove(struct kld_worker **workers, struct kld_worker *worker,
    size_t *count)
{
	struct kld_worker **cursor;
	int status;

	for (cursor = workers; *cursor != NULL && *cursor != worker;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == worker)
		*cursor = worker->next;
	(void)pdwait(worker->pd, &status, WNOHANG, NULL, NULL);
	close(worker->pd);
	free(worker);
	if (*count != 0)
		(*count)--;
}

static void
workers_shutdown(int kq, struct kld_worker **workers, size_t *count)
{
	struct kld_worker *worker, *next;
	struct kevent event;
	struct timespec deadline, now, timeout;
	int result, status;

	for (worker = *workers; worker != NULL; worker = worker->next)
		(void)pdkill(worker->pd, SIGTERM);
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == 0)
		deadline.tv_sec += 5;
	while (*workers != NULL &&
	    clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		    now.tv_nsec >= deadline.tv_nsec))
			break;
		timeout.tv_sec = deadline.tv_sec - now.tv_sec;
		timeout.tv_nsec = deadline.tv_nsec - now.tv_nsec;
		if (timeout.tv_nsec < 0) {
			timeout.tv_sec--;
			timeout.tv_nsec += 1000000000L;
		}
		result = kevent(kq, NULL, 0, &event, 1, &timeout);
		if (result == 0)
			break;
		if (result == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (event.filter == EVFILT_PROCDESC)
			worker_remove(workers, event.udata, count);
	}
	for (worker = *workers; worker != NULL; worker = worker->next)
		(void)pdkill(worker->pd, SIGKILL);
	for (worker = *workers; worker != NULL; worker = next) {
		next = worker->next;
		(void)pdwait(worker->pd, &status, 0, NULL, NULL);
		close(worker->pd);
		free(worker);
	}
	*workers = NULL;
	*count = 0;
}

int
main(void)
{
	struct kld_worker *worker, *workers;
	struct kevent event, change;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct kldmgrd_policy policy;
	char label[sizeof(identity.client_label)];
	size_t nworkers;
	int client, error, kq, status;
	pid_t pid;

	openlog("kldmgrd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	workers = NULL;
	nworkers = 0;
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1 ||
	    kldmgrd_policy_load(KLDMGRD_POLICY_PATH, &policy) == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, KLDMGR_INTERFACE,
	    &listener) == -1)
		goto fail;
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (event.filter == EVFILT_PROCDESC) {
			worker_remove(&workers, event.udata, &nworkers);
			continue;
		}
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &client) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1)
				break;
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (nworkers >= KLDMGRD_MAX_WORKERS) {
			syslog(LOG_WARNING, "session limit for %s",
			    identity.client_label);
			close(client);
			continue;
		}
		strlcpy(label, identity.client_label, sizeof(label));
		worker = calloc(1, sizeof(*worker));
		if (worker == NULL || prepare_worker_channel(client) == -1) {
			syslog(LOG_WARNING, "protect session for %s: %m", label);
			close(client);
			free(worker);
			continue;
		}
		pid = pdfork(&worker->pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_WARNING, "fork client %s: %m", label);
			close(client);
			free(worker);
			continue;
		}
		if (pid == 0)
			_exit(serve_client(client, label,
		    kldmgrd_policy_allows(&policy, label)));
		close(client);
		worker->pid = pid;
		EV_SET(&change, worker->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, worker);
		if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			(void)pdkill(worker->pd, SIGKILL);
			(void)pdwait(worker->pd, &status, 0, NULL, NULL);
			close(worker->pd);
			free(worker);
			continue;
		}
		worker->next = workers;
		workers = worker;
		nworkers++;
	}
	workers_shutdown(kq, &workers, &nworkers);
	status = service_provider_quiesce_complete(provider, 0);
	close(kq);
	closelog();
	return (status == 0 ? 0 : 1);

fail:
	error = errno != 0 ? errno : EIO;
	if (workers != NULL)
		workers_shutdown(kq, &workers, &nworkers);
	if (kq >= 0)
		close(kq);
	errno = error;
	syslog(LOG_ERR, "initialization or service loop: %m");
	closelog();
	return (1);
}
#endif /* !KLDMGRD_TESTING */
