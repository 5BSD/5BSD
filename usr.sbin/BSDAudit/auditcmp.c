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
#include <limits.h>
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
#include <fidl/bsd.audit.v1/c/bsd.h>
#include <libservice.h>
#include <service_runtime.h>
#include <logcmp.h>

#include "auditcmp_policy.h"
#include "bsdaudit_probes.h"
#include "auditcmp_rate.h"
#include "auditcmp_submit.h"
#ifdef AUDITCMP_TESTING
#include "auditcmp_test.h"
#endif

#define	AUDITCMP_RATE_PER_SECOND	100
#define	AUDITCMP_RATE_BURST		200
/*
 * Per-session idle deadline: a worker whose client neither submits nor closes
 * for this long is reaped so stalled connections cannot permanently exhaust the
 * worker pool.  Generous, since a quiet consumer legitimately submits nothing
 * between audit events and simply reconnects for the next one.
 */
#define	AUDITCMP_SESSION_IDLE_SEC	300

struct session {
	const char		*provider;
	int			 event;
	int			 error;
	bool			 negotiated;
	bool			 activity;
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

#ifndef AUDITCMP_TESTING
static int
backend_submit(int event, int result_error, const char *provider,
    const char *subject, const char *operation, void *context __unused)
{

	/* A provider with per-operation event classes (the auth agent). */
	event = auditcmp_policy_operation_event(provider, operation, event);
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

/*
 * A protocol violation is terminal for the session, counted as a rejection
 * and visible to the reject and request-done probes (opcode UINT32_MAX when
 * the bindings refused the frame before any handler ran).
 */
static void
protocol_violation(struct session *session,
    struct fidl_bsd_connection *connection, uint32_t opcode)
{

	session->stats.rejected++;
	BSDAUDIT_PROBE_REJECT(__DECONST(char *, session->provider), EPROTO);
	session->error = EPROTO;
	BSDAUDIT_PROBE_REQUEST_DONE(opcode, EPROTO, 0);
	if (connection != NULL)
		fidl_bsd_connection_close(connection, EPROTO);
}

static void
request_done(struct session *session, struct fidl_bsd_connection *connection,
    uint32_t opcode, int error, int reply_error)
{

	if (reply_error != 0) {
		session->error = reply_error;
		fidl_bsd_connection_close(connection, reply_error);
	}
	BSDAUDIT_PROBE_REQUEST_DONE(opcode, error, reply_error);
}

static void
protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_audit_v1_ProtocolInfo info = { AUDITCMP_WIRE_VERSION };
	int error;

	session->activity = true;
	error = bsd_audit_v1_Audit_GetProtocolInfo_reply(connection, request,
	    &info);
	session->negotiated = error == 0;
	request_done(session, connection, 0, 0, error);
}

static void
submit(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_audit_v1_SubmitRequest *in)
{
	struct session *session = argument;
	struct bsd_audit_v1_Audit_Submit_Result reply = { 0 };
	struct {
		struct auditcmp_msg msg;
		struct auditcmp_submit_request submit;
	} record;
	int error;

	session->activity = true;
	if (!session->negotiated) {
		protocol_violation(session, connection, AUDITCMP_OP_SUBMIT);
		return;
	}
	/*
	 * Apply the record rules every release has enforced (lengths,
	 * character set, NUL padding, error range) to the decoded fields; a
	 * record that breaks them is a protocol violation, as before.
	 */
	memset(&record, 0, sizeof(record));
	(void)auditcmp_message_init(&record.msg, AUDITCMP_OP_SUBMIT, 0);
	record.submit.error = in->error;
	record.submit.subject_length = (uint16_t)in->subject_size;
	record.submit.operation_length = (uint16_t)in->operation_size;
	memcpy(record.submit.subject, in->subject, in->subject_size);
	memcpy(record.submit.operation, in->operation, in->operation_size);
	if (auditcmp_validate_message(&record.msg, sizeof(record),
	    AUDITCMP_MESSAGE_REQUEST) == -1) {
		protocol_violation(session, connection, AUDITCMP_OP_SUBMIT);
		return;
	}
	error = auditcmp_submit_record(session->provider, session->event,
	    &record.submit, rate_allow(session), session->backend);
	if (error == 0)
		session->stats.submitted++;
	else
		session->stats.rejected++;
	BSDAUDIT_PROBE_SUBMIT(__DECONST(char *, session->provider),
	    session->event, record.submit.error, error);
	reply.tag = error ? bsd_audit_v1_Audit_Submit_Result_err_tag :
	    bsd_audit_v1_Audit_Submit_Result_response_tag;
	if (error)
		reply.value.err = (uint32_t)error;
	request_done(session, connection, AUDITCMP_OP_SUBMIT, error,
	    bsd_audit_v1_Audit_Submit_reply(connection, request, &reply));
}

static void
stats(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct session *session = argument;
	struct bsd_audit_v1_AuditStats value;

	session->activity = true;
	if (!session->negotiated) {
		protocol_violation(session, connection, AUDITCMP_OP_STATS);
		return;
	}
	value.submitted = session->stats.submitted;
	value.rejected = session->stats.rejected;
	request_done(session, connection, AUDITCMP_OP_STATS, 0,
	    bsd_audit_v1_Audit_Stats_reply(connection, request, &value));
}

/* A connection the bindings closed for a malformed or unknown frame. */
static bool
protocol_rejection(int error)
{

	return (error != 0 && error != EPIPE && error != ECONNRESET &&
	    error != ECANCELED && error != ETIMEDOUT && error != ENOTCONN);
}

static int
serve_session(int fd, const char *provider, int event,
    const struct auditcmp_backend *backend)
{
	static const struct bsd_audit_v1_Audit_server handlers = {
		.GetProtocolInfo = protocol_info,
		.Submit = submit,
		.Stats = stats
	};
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct fidl_bsd_connection *connection;
	struct session session;
	struct timespec now, last;
	int error;

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
	/* One request at a time; requests carry no descriptors. */
	options.max_pending_requests = 1;
	options.max_queued_messages = 8;
	options.max_queued_bytes = 4096;
	options.max_queued_fds = 0;
	if (fidl_bsd_connection_create_with_options(fd, FIDL_BSD_SERVER,
	    &options, &connection) != 0)
		return (1);
	if (bsd_audit_v1_Audit_bind(connection, &handlers, &session) != 0) {
		fidl_bsd_connection_destroy(connection);
		return (1);
	}
	/*
	 * Bound each worker's lifetime by an idle deadline so a client that
	 * connects and then never sends (nor closes) cannot pin its pdfork'd
	 * worker forever: the per-label accept throttle limits the connection
	 * RATE, not the concurrent COUNT, so without this a slow drip of stalled
	 * connections would fill all AUDITCMP_MAX_WORKERS slots permanently.  A
	 * request re-arms the deadline; only genuine inactivity for
	 * AUDITCMP_SESSION_IDLE_SEC drops the session (the consumer reconnects to
	 * submit its next record).
	 */
	last = now;
	error = 0;
	for (;;) {
		long elapsed_ms, remaining_ms;

		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			break;
		elapsed_ms = (now.tv_sec - last.tv_sec) * 1000 +
		    (now.tv_nsec - last.tv_nsec) / 1000000;
		remaining_ms = (long)AUDITCMP_SESSION_IDLE_SEC * 1000 - elapsed_ms;
		if (remaining_ms <= 0)
			break;			/* idle too long: reap the slot */
		session.activity = false;
		error = fidl_bsd_connection_poll(connection,
		    remaining_ms > INT_MAX ? INT_MAX : (int)remaining_ms);
		if (error != 0 || session.error != 0)
			break;
		if (session.activity)
			last = now;		/* activity: re-arm the deadline */
	}
	if (session.error == 0 && protocol_rejection(error))
		protocol_violation(&session, NULL, UINT32_MAX);
	fidl_bsd_connection_destroy(connection);
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

	setproctitle("-BSDAudit: %s", provider);
	error = service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC |
	    SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1 ? errno : 0;
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
	if (service_harden_fd(fd, SERVICE_HARDEN_CLOFORK_ONCE) == -1 ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1)
		return (-1);
	if (service_harden_fd(syncfd[0], 0) == -1 ||
	    service_harden_fd(syncfd[1], SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		return (errno = error, -1);
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
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
	*pdp = pd;
	*pidp = pid;
	status = service_bootstrap_parent(syncfd[0], 5000) == -1 ? errno : 0;
	close(syncfd[0]);
	if (status != 0)
		return (errno = status, -1);
	BSDAUDIT_PROBE_SESSION(__DECONST(char *, provider),
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

/* Own the worker before installing its watch, including on failure. */
static int
worker_track(int kq, struct audit_worker **workers, struct audit_worker *worker,
    size_t *count)
{
	struct kevent change;

	worker->next = *workers;
	*workers = worker;
	(*count)++;
	EV_SET(&change, worker->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
	    NOTE_EXIT, 0, worker);
	if (service_harden_fd(worker->pd, 0) == -1)
		return (-1);
	return (kevent(kq, &change, 1, NULL, 0, NULL));
}

static int
worker_remove(struct audit_worker **workers, struct audit_worker *worker,
    size_t *count)
{
	struct audit_worker **cursor;
	int status, result, error;

	for (cursor = workers; *cursor != NULL && *cursor != worker;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == worker)
		*cursor = worker->next;
	do {
		result = pdwait(worker->pd, &status, WEXITED | WNOHANG,
		    NULL, NULL);
	} while (result == -1 && errno == EINTR);
	error = result == -1 && errno != ECHILD && errno != ESRCH ? errno : 0;
	close(worker->pd);
	free(worker);
	if (*count != 0)
		(*count)--;
	return (error != 0 ? (errno = error, -1) : 0);
}

static int
workers_shutdown(int kq, struct audit_worker **workers, size_t *count)
{
	struct audit_worker *worker, *next;
	struct kevent event;
	struct timespec deadline, now, timeout;
	int status, result, error = 0;

	for (worker = *workers; worker != NULL; worker = worker->next)
		(void)pdkill(worker->pd, SIGTERM);
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		goto force;
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
		if (event.filter == EVFILT_PROCDESC &&
		    worker_remove(workers, event.udata, count) == -1 && error == 0)
			error = errno;
	}
force:
	for (worker = *workers; worker != NULL; worker = worker->next) {
		if (pdkill(worker->pd, SIGKILL) == -1 && errno != ESRCH &&
		    error == 0)
			error = errno;
	}
	for (worker = *workers; worker != NULL; worker = next) {
		next = worker->next;
		do {
			result = pdwait(worker->pd, &status,
			    WEXITED | (error != 0 ? WNOHANG : 0), NULL, NULL);
		} while (result == -1 && errno == EINTR);
		if (result == -1 && errno != ECHILD && errno != ESRCH && error == 0)
			error = errno;
		close(worker->pd);
		free(worker);
	}
	*workers = NULL;
	*count = 0;
	return (error != 0 ? (errno = error, -1) : 0);
}

int
main(void)
{
	struct audit_worker *worker, *workers;
	struct kevent event, change;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider = NULL;
	struct label_rate *rate_table;
	struct auditcmp_rate *rate;
	struct timespec now;
	size_t nworkers;
	int error, fd, kq = -1, result = 1;

	openlog("bsdaudit", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
	/* ps(1) shows the unit name, not the ld-elf.so.1 launcher. */
	service_set_proctitle();
	/*
	 * Prime the timezone before entering capability mode.  audit_submit(3)
	 * timestamps each record via localtime(3), which opens /etc/localtime by
	 * path — denied (ECAPMODE) once sandboxed, so every record failed to
	 * commit.  tzset(3) plus a warm-up localtime(3) caches the zone in memory;
	 * workers pdfork(2)ed later inherit it, and audit(2) itself is already
	 * capability-mode enabled, so the record then commits with no path open.
	 */
	{
		time_t now_t = 0;

		tzset();
		(void)localtime(&now_t);
	}
	workers = NULL;
	nworkers = 0;
	rate_table = calloc(AUDITCMP_RATE_LABELS, sizeof(*rate_table));
	if (rate_table == NULL)
		goto initialize_failed;
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1 || service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, AUDITCMP_INTERFACE,
	    &listener) == -1)
		goto initialize_failed;
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto initialize_failed;
	for (;;) {
		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			warn("kevent");
			goto out;
		}
		if (event.filter == EVFILT_PROCDESC) {
			if (worker_remove(&workers, event.udata, &nworkers) == -1) {
				warn("worker reap");
				goto out;
			}
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
			warn("accept");
			goto out;
		}
		if (nworkers >= AUDITCMP_MAX_WORKERS) {
			errno = ENOSPC;
			logcmp_log(LOG_WARNING, "session limit for %s",
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
			BSDAUDIT_PROBE_REJECT(
			    __DECONST(char *, identity.client_label), EAGAIN);
			logcmp_log(LOG_WARNING, "accept rate limit for %s",
			    identity.client_label);
			close(fd);
			continue;
		}
		worker = calloc(1, sizeof(*worker));
		if (worker != NULL)
			worker->pd = -1;
		if (worker == NULL || start_session(fd, identity.client_label,
		    &worker->pd, &worker->pid) == -1) {
			logcmp_log(LOG_WARNING, "session for %s: %m",
			    identity.client_label);
			close(fd);
			if (worker != NULL && worker->pd >= 0) {
				worker->next = workers;
				workers = worker;
				nworkers++;
				goto out;
			}
			free(worker);
			continue;
		}
		close(fd);
		if (worker_track(kq, &workers, worker, &nworkers) == -1) {
			warn("worker watch");
			goto out;
		}
	}
	result = 0;
	goto out;
initialize_failed:
	warn("initialize");
out:
	if (workers_shutdown(kq, &workers, &nworkers) == -1) {
		warn("worker shutdown");
		result = 1;
	}
	if (kq != -1)
		close(kq);
	free(rate_table);
	if (result == 0 && service_provider_quiesce_complete(provider, 0) == -1)
		result = 1;
	if (provider != NULL)
		service_provider_destroy(provider);
	closelog();
	return (result);
}
#endif
