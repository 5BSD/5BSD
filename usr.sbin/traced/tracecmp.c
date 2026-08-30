/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/ioccom.h>
#include <sys/dtrace.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "tracecmp.h"
#include <tracecmp_server.h>
#include "tracecmp_policy.h"
#include "traced_probes.h"
#ifdef TRACECMP_TESTING
#include "tracecmp_test.h"
#endif

#define	TRACECMP_PROVIDER_NAME	TRACECMP_INTERFACE
#define	TRACECMP_CLIENT_TIMEOUT_MS	30000

union tracecmp_buffer {
	max_align_t align;
	uint8_t bytes[TRACECMP_MAX_MESSAGE];
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_TRACECMP_POLICY, AU_DEFAUDITID,
	    (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

static int
harden_worker_descriptor(int fd, int xfer)
{

	/*
	 * The provider deliberately hands this descriptor to exactly one
	 * pdfork() child.  CAP_CLOFORK_ONCE atomically consumes that authority
	 * and locks both resulting entries against any later fork.
	 */
	return (cap_xfer_limit(fd, xfer) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

#ifdef TRACECMP_TESTING
int
tracecmp_test_prepare_worker_fd(int fd)
{

	return (harden_worker_descriptor(fd, CAP_XFER_NONE));
}
#endif

struct worker_state {
	struct tracecmp_stats	stats;
	const char		*client_label;
	uint64_t		 instance_id;
	int			 dtrace_fd;
	bool			 authorized;
	int			 device_error;
	int			 terminal_error;
};

#ifndef TRACECMP_TESTING
static int
open_dtrace_directory(void)
{
	cap_rights_t rights;
	int fd;

	fd = open("/dev/dtrace", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
	    O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_FSTAT,
	    CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_fcntls_limit(fd, 0) == -1 ||
	    cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (fd);
}

static int
open_dtrace_consumer(int directory)
{
	static const unsigned long ioctls[] = {
		DTRACEIOC_PROVIDER, DTRACEIOC_PROBES, DTRACEIOC_BUFSNAP,
		DTRACEIOC_PROBEMATCH, DTRACEIOC_ENABLE, DTRACEIOC_AGGSNAP,
		DTRACEIOC_EPROBE, DTRACEIOC_PROBEARG, DTRACEIOC_CONF,
		DTRACEIOC_STATUS, DTRACEIOC_GO, DTRACEIOC_STOP,
		DTRACEIOC_AGGDESC, DTRACEIOC_FORMAT, DTRACEIOC_DOFGET
	};
	cap_rights_t rights;
	int fd, error;

	if (directory < 0)
		return (errno = ENXIO, -1);
	fd = openat(directory, "dtrace", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, ioctls, nitems(ioctls)) == -1 ||
	    cap_fcntls_limit(fd, 0) == -1 ||
	    harden_worker_descriptor(fd, CAP_XFER_ONCE) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (fd);
}
#endif

static int
send_reply(struct channel_message *request_message,
    const struct tracecmp_msg *request, int error, const void *payload,
    size_t payload_length, int attached_fd)
{
	union tracecmp_buffer buffer;
	struct tracecmp_msg *reply;
	const int *fds;
	size_t nfds;

	memset(&buffer, 0, sizeof(buffer));
	reply = (void *)buffer.bytes;
	if (tracecmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	fds = attached_fd >= 0 ? &attached_fd : NULL;
	nfds = attached_fd >= 0 ? 1 : 0;
	if (tracecmp_validate_message(reply,
	    sizeof(*reply) + (error == 0 ? payload_length : 0),
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    tracecmp_validate_fds(reply, nfds, TRACECMP_MESSAGE_REPLY) == -1)
		return (-1);
	return (channel_send_reply(request_message,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = reply,
		.length = sizeof(*reply) +
		    (error == 0 ? payload_length : 0),
		.fds = fds,
		.nfds = nfds
	    }));
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct worker_state *state;
	struct tracecmp_hello_reply hello;
	const struct tracecmp_msg *message;
	const struct channel_sender *sender;
	size_t length;
	bool caller_root;
	int error;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (tracecmp_validate_message(message, length,
	    TRACECMP_MESSAGE_REQUEST) == -1 ||
	    tracecmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    TRACECMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		channel_message_free(request_message);
		return;
	}

	/*
	 * MIGRATION (docs/capability-authority-model.md, phase P5): this uid gate
	 * is transitional; the end state authorizes OPEN by a presented trace:raw
	 * capability, not by the caller's uid or a label allowlist.
	 *
	 * Until then, authorization gates on the caller's authenticated uid: root
	 * (uid 0) may obtain the raw DTrace consumer fd regardless of the label
	 * allowlist, matching the plane-wide "root may do anything" rule; a
	 * non-root caller is delegated the fd only if its client label is in
	 * the traced allowlist (the mechanism that lets specific unprivileged
	 * labels drive DTrace).  The uid is the kernel-stamped per-request
	 * sender credential, not a session-time cache, so it cannot be spoofed.
	 */
	sender = channel_message_sender(request_message);
	caller_root = (sender != NULL && sender->uid == 0);

	error = 0;
	switch (message->opcode) {
	case TRACECMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = TRACECMP_ABI_VERSION;
		hello.features = (caller_root || state->authorized) &&
		    state->dtrace_fd >= 0 ? TRACECMP_FEATURE_RAW_DTRACE_FD : 0;
		if (send_reply(request_message, message, 0, &hello,
		    sizeof(hello), -1) == -1)
			state->terminal_error = errno;
		break;
	case TRACECMP_OP_OPEN:
		if (!(caller_root || state->authorized))
			error = EACCES;
		else if (state->dtrace_fd < 0)
			error = state->device_error != 0 ?
			    state->device_error : EALREADY;
		else if (send_reply(request_message, message, 0, NULL, 0,
		    state->dtrace_fd) == -1)
			state->terminal_error = errno;
		else {
			close(state->dtrace_fd);
			state->dtrace_fd = -1;
			state->stats.opened++;
			TRACED_PROBE_DELEGATE(
			    __DECONST(char *, state->client_label),
			    state->instance_id, 0);
			audit_policy(state->client_label,
			    "raw-dtrace-fd-delegated", 0);
		}
		break;
	case TRACECMP_OP_STATS:
		if (send_reply(request_message, message, 0, &state->stats,
		    sizeof(state->stats), -1) == -1)
			state->terminal_error = errno;
		break;
	default:
		state->terminal_error = EPROTO;
		break;
	}
	if (error != 0) {
		if (message->opcode == TRACECMP_OP_OPEN)
			TRACED_PROBE_DELEGATE(
			    __DECONST(char *, state->client_label),
			    state->instance_id, error);
		state->stats.rejected++;
		audit_policy(state->client_label, "request-denied", error);
		TRACED_PROBE_REJECT(
		    __DECONST(char *, state->client_label),
		    message->opcode, error);
		if (send_reply(request_message, message, error, NULL, 0, -1) ==
		    -1)
			state->terminal_error = errno;
	}
	channel_message_free(request_message);
}

static int
serve_session(int fd, int dtrace_fd, bool authorized, int device_error,
    const char *client_label, uint64_t instance_id)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct worker_state state;
	struct channel *channel;
	int ready;
	int loop_error, wants_write;

	memset(&state, 0, sizeof(state));
	state.client_label = client_label;
	state.instance_id = instance_id;
	state.dtrace_fd = dtrace_fd;
	state.authorized = authorized;
	state.device_error = device_error;
	loop_error = 0;
	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, handle_request, &state) ==
	    -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1) {
			loop_error = errno;
			break;
		}
		ready = channel_wait(channel, wants_write,
		    TRACECMP_CLIENT_TIMEOUT_MS);
		if (ready == 0) {
			loop_error = ETIMEDOUT;
			break;
		}
		if (ready == -1) {
			loop_error = errno;
			break;
		}
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) {
			loop_error = errno;
			break;
		}
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1) {
			loop_error = errno;
			break;
		}
		if (state.terminal_error != 0) {
			loop_error = state.terminal_error;
			errno = loop_error;
			break;
		}
	}
	channel_destroy(channel);
	if (state.dtrace_fd >= 0)
		close(state.dtrace_fd);
	TRACED_PROBE_SESSION_END(__DECONST(char *, client_label),
	    instance_id, loop_error);
	return (0);
}

#ifdef TRACECMP_TESTING
int
tracecmp_test_serve(int fd, int dtrace_fd, bool authorized, int device_error,
    const char *client_label)
{

	if (fd < 0 || dtrace_fd < -1 || device_error < 0 ||
	    client_label == NULL || client_label[0] == '\0')
		return (errno = EINVAL, -1);
	return (serve_session(fd, dtrace_fd, authorized, device_error,
	    client_label, 0));
}
#else
static int
worker(int fd, int barrier, int dtrace_fd, bool authorized,
    int device_error, const char *client_label,
    uint64_t instance_id __unused)
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
	return (serve_session(fd, dtrace_fd, authorized, device_error,
	    client_label, instance_id));
}

static int
start_session(int fd, int dtrace_directory, bool authorized,
    const char *peer_label, int *pdp, pid_t *pidp)
{
	static uint64_t next_instance;
	char byte;
	int syncfd[2], pd, child_error, dtrace_fd, device_error, error;
	ssize_t n;
	pid_t pid;
	uint64_t instance_id;

	instance_id = ++next_instance;
	device_error = 0;
	/*
	 * Open the DTrace consumer fd whenever the device is available, not
	 * only for allowlisted labels: the per-request authorization (root, or
	 * an allowlisted label) is enforced in the worker's handle_request(),
	 * which cannot open the sandboxed device itself.  The fd is held by the
	 * worker and delegated only on an authorized OPEN, so an unprivileged
	 * session merely holds an undelegated fd (bounded by the worker cap)
	 * until it disconnects.
	 */
	dtrace_fd = open_dtrace_consumer(dtrace_directory);
	if (dtrace_fd == -1)
		device_error = errno;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		if (dtrace_fd >= 0)
			close(dtrace_fd);
		goto reject;
	}
	if (harden_worker_descriptor(fd, CAP_XFER_NONE) == -1 ||
	    cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    harden_worker_descriptor(syncfd[1], CAP_XFER_NONE) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		if (dtrace_fd >= 0)
			close(dtrace_fd);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		if (dtrace_fd >= 0)
			close(dtrace_fd);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		_exit(worker(fd, syncfd[1], dtrace_fd, authorized, device_error,
		    peer_label, instance_id));
	}
	if (dtrace_fd >= 0)
		close(dtrace_fd);
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	*pdp = pd;
	*pidp = pid;
	audit_policy(peer_label, "session-bootstrap", 0);
	TRACED_PROBE_SESSION_START(__DECONST(char *, peer_label),
	    instance_id, 0);
	return (0);

reject:
	audit_policy(peer_label, "session-bootstrap", error);
	TRACED_PROBE_SESSION_START(__DECONST(char *, peer_label),
	    instance_id, error);
	errno = error;
	return (-1);
}

#define	TRACECMP_MAX_WORKERS	256U

struct trace_worker {
	struct trace_worker *next;
	int pd;
	pid_t pid;
};

static void
worker_remove(struct trace_worker **workers, struct trace_worker *worker,
    size_t *count)
{
	struct trace_worker **cursor;
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
workers_shutdown(int kq, struct trace_worker **workers, size_t *count)
{
	struct trace_worker *worker, *next;
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
	struct trace_worker *worker, *workers;
	struct kevent event, change;
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	struct tracecmp_policy policy;
	size_t nworkers;
	int dtrace_directory, error, fd, kq, status;

	openlog("traced", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	workers = NULL;
	nworkers = 0;
	dtrace_directory = -1;
	kq = -1;
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1)
		goto fail;
	if (tracecmp_policy_load(TRACECMP_POLICY_PATH, &policy) == -1)
		goto fail;
	dtrace_directory = open_dtrace_directory();
	if (dtrace_directory == -1 && errno != ENOENT && errno != ENXIO)
		goto fail;
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, TRACECMP_PROVIDER_NAME,
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
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1)
				break;
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (nworkers >= TRACECMP_MAX_WORKERS) {
			syslog(LOG_WARNING, "session limit for %s",
			    identity.client_label);
			close(fd);
			continue;
		}
		worker = calloc(1, sizeof(*worker));
		if (worker == NULL || start_session(fd, dtrace_directory,
		    tracecmp_policy_allows(&policy, identity.client_label),
		    identity.client_label, &worker->pd, &worker->pid) == -1) {
			syslog(LOG_WARNING, "session for %s rejected: %m",
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
	if (dtrace_directory >= 0)
		close(dtrace_directory);
	closelog();
	return (status == 0 ? 0 : 1);

fail:
	error = errno != 0 ? errno : EIO;
	if (workers != NULL && kq >= 0)
		workers_shutdown(kq, &workers, &nworkers);
	if (dtrace_directory >= 0)
		close(dtrace_directory);
	if (kq >= 0)
		close(kq);
	errno = error;
	syslog(LOG_ERR, "initialization or service loop: %m");
	closelog();
	return (1);
}
#endif
