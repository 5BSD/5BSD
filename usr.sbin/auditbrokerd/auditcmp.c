/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <bsm/libbsm.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <auditcmp.h>
#include <auditcmp_server.h>
#include <channel.h>
#include <libservice.h>

#include "auditcmp_policy.h"
#include "auditbrokerd_probes.h"
#include "auditcmp_rate.h"
#include "auditcmp_submit.h"
#ifdef AUDITCMP_TESTING
#include "auditcmp_test.h"
#endif

#define	AUDITCMP_RATE_PER_SECOND	100
#define	AUDITCMP_RATE_BURST		200

struct session {
	const char		*provider;
	int			 event;
	int			 error;
	struct auditcmp_stats	 stats;
	struct auditcmp_rate	 rate;
	const struct auditcmp_backend *backend;
};

static bool
rate_allow(struct session *session)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (false);
	return (auditcmp_rate_allow_at(&session->rate, &now));
}

static int
send_reply(struct channel_message *request_message,
    const struct auditcmp_msg *request, int error, const void *payload,
    size_t payload_length)
{
	uint8_t buffer[AUDITCMP_MAX_MESSAGE];
	struct auditcmp_msg *reply;
	size_t length;

	if (payload_length > sizeof(buffer) - sizeof(*reply))
		return (errno = EOVERFLOW, -1);
	memset(buffer, 0, sizeof(buffer));
	reply = (void *)buffer;
	if (auditcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (auditcmp_validate_message(reply, length,
	    AUDITCMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(buffer, length)));
}

#ifndef AUDITCMP_TESTING
static int
backend_submit(int event, int result_error, const char *provider,
    const char *subject, const char *operation, void *context __unused)
{

	return (audit_submit((short)event, AU_DEFAUDITID,
	    (char)result_error, result_error != 0,
	    "provider=%s client=%s operation=%s result=%d",
	    provider, subject, operation, result_error));
}

static const struct auditcmp_backend system_backend = {
	.submit = backend_submit,
	.context = NULL
};
#endif

static void
handle_request(struct channel *channel __unused,
    struct channel_message *message, void *argument)
{
	const struct auditcmp_submit_request *submit;
	const struct auditcmp_msg *request;
	struct auditcmp_hello_reply hello;
	struct session *session;
	int error, result;

	session = argument;
	request = channel_message_data(message);
	error = 0;
	result = 0;
	if (channel_message_fd_count(message) != 0 ||
	    auditcmp_validate_message(request,
	    channel_message_length(message),
	    AUDITCMP_MESSAGE_REQUEST) == -1) {
		session->stats.rejected++;
		AUDITBROKERD_PROBE_REJECT(
		    __DECONST(char *, session->provider), EPROTO);
		session->error = EPROTO;
		goto out;
	}
	switch (request->opcode) {
	case AUDITCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = AUDITCMP_ABI_VERSION;
		result = send_reply(message, request, 0, &hello, sizeof(hello));
		break;
	case AUDITCMP_OP_SUBMIT:
		submit = (const void *)(request + 1);
		error = auditcmp_submit_record(session->provider, session->event,
		    submit, rate_allow(session), session->backend);
		if (error == 0)
			session->stats.submitted++;
		else
			session->stats.rejected++;
		AUDITBROKERD_PROBE_SUBMIT(
		    __DECONST(char *, session->provider), session->event,
		    submit->error, error);
		result = send_reply(message, request, error, NULL, 0);
		break;
	case AUDITCMP_OP_STATS:
		result = send_reply(message, request, 0, &session->stats,
		    sizeof(session->stats));
		break;
	default:
		error = EOPNOTSUPP;
		result = send_reply(message, request, error, NULL, 0);
		break;
	}
	if (result == -1)
		session->error = errno;
out:
	channel_message_free(message);
}

static int
serve_session(int fd, const char *provider, int event,
    const struct auditcmp_backend *backend)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel;
	struct session session;
	struct timespec now;
	int ready, wants_write;

	if (fd < 0 || provider == NULL || provider[0] == '\0' || event == 0 ||
	    backend == NULL || backend->submit == NULL)
		return (errno = EINVAL, -1);
	memset(&session, 0, sizeof(session));
	session.provider = provider;
	session.event = event;
	session.backend = backend;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 ||
	    auditcmp_rate_init(&session.rate, AUDITCMP_RATE_PER_SECOND,
	    AUDITCMP_RATE_BURST, &now) == -1)
		return (-1);
	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, handle_request, &session) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		ready = channel_wait(channel, wants_write, -1);
		if (ready <= 0)
			break;
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
	return (session.error == 0 ? 0 : 1);
}

#ifdef AUDITCMP_TESTING
int
auditcmp_test_serve(int fd, const char *provider, int event,
    const struct auditcmp_backend *backend)
{

	return (serve_session(fd, provider, event, backend));
}
#endif

#ifndef AUDITCMP_TESTING
static int
worker(int fd, int barrier, const char *provider, int event)
{
	char byte;
	int error;

	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC |
	    SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1)
		error = errno;
	else {
		service_worker_drop_inherited_authority();
		error = cap_enter() == -1 ? errno : 0;
	}
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    error != 0)
		return (1);
	if (read(barrier, &byte, 1) != 1)
		return (1);
	close(barrier);
	return (serve_session(fd, provider, event, &system_backend));
}

static int
start_session(int fd, const char *provider, int *pdp, pid_t *pidp)
{
	int event, pd, syncfd[2], error, status;
	pid_t pid;

	event = auditcmp_policy_event(provider);
	if (event == 0)
		return (errno = EACCES, -1);
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1)
		return (-1);
	if (cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    cap_xfer_limit(syncfd[1], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[1], CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(syncfd[1], CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		return (errno = error, -1);
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		return (errno = error, -1);
	}
	if (pid == 0) {
		close(syncfd[0]);
		_exit(worker(fd, syncfd[1], provider, event));
	}
	close(syncfd[1]);
	if (read(syncfd[0], &status, sizeof(status)) != sizeof(status))
		status = EIO;
	if (status == 0 && write(syncfd[0], "", 1) != 1)
		status = EIO;
	close(syncfd[0]);
	if (status != 0)
		return (close(pd), errno = status, -1);
	*pdp = pd;
	*pidp = pid;
	AUDITBROKERD_PROBE_SESSION(__DECONST(char *, provider),
	    event);
	return (0);
}

#endif /* !AUDITCMP_TESTING */

/*
 * Per-connection rate buckets are re-created for every worker (a fresh burst
 * on every accept), so a caller could churn connections to bypass the limit.
 * The parent authenticates every connection's provider label, so it enforces a
 * second, reconnect-proof bucket keyed by that label: new connections for a
 * label are throttled here regardless of how the caller opens and drops them.
 * The per-session limiter (serve_session) remains as a secondary bound.
 *
 * The bucket table is bounded; on overflow the least-recently-active label is
 * reclaimed.  A flooding label is by definition the most-recently-active one,
 * so its depleted bucket is never the reclaim victim.
 *
 * This accounting is compiled in both the daemon and the AUDITCMP_TESTING
 * builds so the reconnect-survival invariant can be unit-tested (see the test
 * hooks below); the daemon's behaviour is unchanged.
 */
#define	AUDITCMP_ACCEPT_RATE_PER_SECOND	8
#define	AUDITCMP_ACCEPT_RATE_BURST	16
#define	AUDITCMP_RATE_LABELS		1024U

struct label_rate {
	bool			used;
	char			label[sizeof(((struct service_identity *)0)->client_label)];
	struct auditcmp_rate	rate;
};

static bool
timespec_before(const struct timespec *a, const struct timespec *b)
{

	return (a->tv_sec < b->tv_sec ||
	    (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec));
}

static struct auditcmp_rate *
accept_rate_for(struct label_rate *table, size_t capacity, const char *label,
    const struct timespec *now)
{
	size_t i, free_idx, victim;

	free_idx = capacity;
	victim = capacity;
	for (i = 0; i < capacity; i++) {
		if (!table[i].used) {
			if (free_idx == capacity)
				free_idx = i;
			continue;
		}
		if (strcmp(table[i].label, label) == 0)
			return (&table[i].rate);
		if (victim == capacity ||
		    timespec_before(&table[i].rate.refill,
		    &table[victim].rate.refill))
			victim = i;
	}
	if (free_idx == capacity)
		free_idx = victim;
	if (free_idx == capacity ||
	    strlcpy(table[free_idx].label, label,
	    sizeof(table[free_idx].label)) >= sizeof(table[free_idx].label) ||
	    auditcmp_rate_init(&table[free_idx].rate,
	    AUDITCMP_ACCEPT_RATE_PER_SECOND, AUDITCMP_ACCEPT_RATE_BURST,
	    now) == -1) {
		if (free_idx != capacity)
			table[free_idx].used = false;
		return (NULL);
	}
	table[free_idx].used = true;
	return (&table[free_idx].rate);
}

#ifdef AUDITCMP_TESTING
/*
 * Test hooks (no runtime path uses these): expose the parent per-label bucket
 * table so the reconnect-survival accounting can be driven directly.  The table
 * is opaque to callers; auditcmp_test_accept_table() allocates one sized exactly
 * as the accept loop's, and auditcmp_test_accept_lookup() resolves a label to
 * its persistent bucket exactly as accept_rate_for() does in main().
 */
struct label_rate *
auditcmp_test_accept_table(void)
{

	return (calloc(AUDITCMP_RATE_LABELS, sizeof(struct label_rate)));
}

struct auditcmp_rate *
auditcmp_test_accept_lookup(struct label_rate *table, const char *label,
    const struct timespec *now)
{

	return (accept_rate_for(table, AUDITCMP_RATE_LABELS, label, now));
}
#endif /* AUDITCMP_TESTING */

#ifndef AUDITCMP_TESTING
#define	AUDITCMP_MAX_WORKERS	4096U

struct audit_worker {
	struct audit_worker *next;
	int pd;
	pid_t pid;
};

static void
worker_remove(struct audit_worker **workers, struct audit_worker *worker,
    size_t *count)
{
	struct audit_worker **cursor;
	int status;

	for (cursor = workers; *cursor != NULL && *cursor != worker;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == worker)
		*cursor = worker->next;
	(void)pdwait(worker->pd, &status, WEXITED | WNOHANG, NULL, NULL);
	close(worker->pd);
	free(worker);
	if (*count != 0)
		(*count)--;
}

static void
workers_shutdown(int kq, struct audit_worker **workers, size_t *count)
{
	struct audit_worker *worker, *next;
	struct kevent event;
	struct timespec deadline, now, timeout;
	int status;

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
		status = kevent(kq, NULL, 0, &event, 1, &timeout);
		if (status == 0)
			break;
		if (status == -1) {
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
		(void)pdwait(worker->pd, &status, WEXITED, NULL, NULL);
		close(worker->pd);
		free(worker);
	}
	*workers = NULL;
	*count = 0;
}

int
main(void)
{
	struct audit_worker *worker, *workers;
	struct kevent event, change;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct label_rate *rate_table;
	struct auditcmp_rate *rate;
	struct timespec now;
	size_t nworkers;
	int error, fd, kq, status;

	openlog("auditbrokerd", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
	workers = NULL;
	nworkers = 0;
	rate_table = calloc(AUDITCMP_RATE_LABELS, sizeof(*rate_table));
	if (rate_table == NULL)
		err(1, "initialize");
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1 || service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, AUDITCMP_INTERFACE,
	    &listener) == -1)
		err(1, "initialize");
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		err(1, "initialize");
	for (;;) {
		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}
		if (event.filter == EVFILT_PROCDESC) {
			worker_remove(&workers, event.udata, &nworkers);
			continue;
		}
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1)
				break;
			errno = error;
			if (errno == EINTR)
				continue;
			err(1, "accept");
		}
		if (nworkers >= AUDITCMP_MAX_WORKERS) {
			errno = ENOSPC;
			syslog(LOG_WARNING, "session limit for %s",
			    identity.client_label);
			close(fd);
			continue;
		}
		/*
		 * Reconnect-proof per-label admission throttle: the bucket
		 * survives this connection, so churning connections cannot reset
		 * the burst.
		 */
		rate = clock_gettime(CLOCK_MONOTONIC, &now) == -1 ? NULL :
		    accept_rate_for(rate_table, AUDITCMP_RATE_LABELS,
		    identity.client_label, &now);
		if (rate == NULL || !auditcmp_rate_allow_at(rate, &now)) {
			AUDITBROKERD_PROBE_REJECT(
			    __DECONST(char *, identity.client_label), EAGAIN);
			syslog(LOG_WARNING, "accept rate limit for %s",
			    identity.client_label);
			close(fd);
			continue;
		}
		worker = calloc(1, sizeof(*worker));
		if (worker == NULL || start_session(fd, identity.client_label,
		    &worker->pd, &worker->pid) == -1) {
			syslog(LOG_WARNING, "session for %s: %m",
			    identity.client_label);
			free(worker);
			close(fd);
			continue;
		}
		close(fd);
		EV_SET(&change, worker->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, worker);
		if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			(void)pdkill(worker->pd, SIGKILL);
			(void)pdwait(worker->pd, &status, WEXITED, NULL, NULL);
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
	free(rate_table);
	closelog();
	return (status == 0 ? 0 : 1);
}
#endif
