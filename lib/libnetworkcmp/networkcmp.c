/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libnetworkcmp: the system.Network client over the generated bsd.network.v1
 * bindings (networkcmp.fidl) on a native capability channel.
 *
 * One process client is shared by every caller, as before, and calls from
 * several threads proceed concurrently: one waiting thread at a time reads
 * the channel (outside the client lock) and dispatches every completion,
 * the others sleep on a condition variable.  A call that reaches its
 * deadline (30 seconds, shortened by service_budget_begin()) is cancelled
 * and fails with ETIMEDOUT; the session survives.  A malformed reply makes
 * the client terminal (EPROTO); a lost provider makes it terminal with the
 * transport error.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <fidl/bsd.network.v1/c/bsd.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>
#include <service_runtime.h>

#include "networkcmp.h"
#include "networkcmp_server.h"
#include "networkcmp_probes.h"

/*
 * Retained in static consumers and available in the shared object so
 * switchboardctl deps can suggest, but never authorize, manifest requirements.
 */
#define NETWORKCMP_DEPENDENCY_TEXT \
    "interface=system.Network\n" \
    "local-name=network\n" \
    "required=true\n"
/* ELF notes have a native-endian header and four-byte padded owner/payload.
 * Raw text in a .note section is not a valid note and prevents bounded ELF
 * consumers from walking subsequent records. This is not a signature note. */
static const struct {
	uint32_t namesz, descsz, type;
	char owner[8];
	char description[(sizeof(NETWORKCMP_DEPENDENCY_TEXT) + 3) & ~3U];
} networkcmp_dependency_note
    __attribute__((section(".note.5bsd.descriptors"), used, aligned(4))) = {
	5, sizeof(NETWORKCMP_DEPENDENCY_TEXT), 0x35424450,
	"5BSD", NETWORKCMP_DEPENDENCY_TEXT
};
#undef NETWORKCMP_DEPENDENCY_TEXT

#define	NETWORKCMP_CALL_TIMEOUT_MS	30000U

struct networkcmp_client {
	struct fidl_bsd_connection	*connection;
	struct networkcmp_hello_reply	 limits;
	pid_t				 owner;
	uint32_t			 references;
	_Atomic int			 terminal_error;
	pthread_mutex_t			 lock;
	pthread_cond_t			 completed;
	int				 kq;
	bool				 polling;
	bool				 write_armed;
	bool				 initialized;
};

/* One call's completion, filled by the generated callback. */
struct completion {
	bool		 done;
	bool		 malformed;
	int		 error;		/* transport or application errno */
	uint32_t	 txid;
	int		 fd;		/* received descriptor, owned here */
	union {
		struct bsd_network_v1_Limits limits;
		struct {
			uint16_t port;
		} listen;
		struct {
			struct networkcmp_resolve_result *results;
			size_t capacity;
			size_t count;
			char *canonname;
			size_t canonname_size;
			uint32_t ttl_seconds;
		} resolve;
	} u;
};

static pthread_mutex_t networkcmp_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t networkcmp_registry_ready = PTHREAD_COND_INITIALIZER;
static pthread_once_t networkcmp_atfork_once = PTHREAD_ONCE_INIT;
static struct networkcmp_client *networkcmp_process_client;
static const char *networkcmp_process_iface;	/* interface it was opened on */
static int networkcmp_atfork_error;
static bool networkcmp_initializing;

static void networkcmp_atfork_prepare(void) __no_lock_analysis;
static void networkcmp_atfork_parent(void) __no_lock_analysis;
static void networkcmp_atfork_child(void) __no_lock_analysis;

static void
networkcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_parent(void)
{

	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_child(void)
{

	networkcmp_process_client = NULL;
	networkcmp_process_iface = NULL;
	networkcmp_initializing = false;
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static void
networkcmp_atfork_init(void)
{

	networkcmp_atfork_error = pthread_atfork(networkcmp_atfork_prepare,
	    networkcmp_atfork_parent, networkcmp_atfork_child);
}

static int
client_init(struct networkcmp_client *client)
{
	pthread_condattr_t attributes;
	int error;

	client->kq = -1;
	client->connection = NULL;
	error = pthread_mutex_init(&client->lock, NULL);
	if (error != 0)
		return (errno = error, -1);
	error = pthread_condattr_init(&attributes);
	if (error == 0) {
		error = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
		if (error == 0)
			error = pthread_cond_init(&client->completed,
			    &attributes);
		(void)pthread_condattr_destroy(&attributes);
	}
	if (error != 0) {
		(void)pthread_mutex_destroy(&client->lock);
		return (errno = error, -1);
	}
	client->initialized = true;
	return (0);
}

/* Adopt fd (consumed on success and failure) as the client's connection. */
static int
client_connect(struct networkcmp_client *client, int fd)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct kevent changes[3];
	int cfd, error;

	if (service_harden_fd(fd, 0) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	/* Up to 64 calls in flight, as many replies, one descriptor each. */
	options.max_pending_requests = 64;
	options.max_queued_messages = 128;
	options.max_queued_fds = 64;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_CLIENT,
	    &options, &client->connection);
	if (error != 0) {
		(void)close(fd);
		return (errno = error, -1);
	}
	client->kq = kqueuex(KQUEUE_CLOEXEC);
	cfd = fidl_bsd_connection_fd(client->connection);
	if (client->kq == -1 || cfd < 0)
		return (-1);
	EV_SET(&changes[0], cfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(&changes[1], cfd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0,
	    NULL);
	EV_SET(&changes[2], 0, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
	return (kevent(client->kq, changes, nitems(changes), NULL, 0, NULL));
}

static void
client_destroy(struct networkcmp_client *client)
{

	if (client->connection != NULL)
		fidl_bsd_connection_destroy(client->connection);
	if (client->kq >= 0)
		(void)close(client->kq);
	if (client->initialized) {
		(void)pthread_cond_destroy(&client->completed);
		(void)pthread_mutex_destroy(&client->lock);
	}
	free(client);
}

/* Record a terminal error; later calls fail with it. */
static int
client_fail_locked(struct networkcmp_client *client, int error)
{
	int expected = 0;

	if (error == 0)
		error = EIO;
	(void)atomic_compare_exchange_strong(&client->terminal_error,
	    &expected, error);
	fidl_bsd_connection_close(client->connection, error);
	(void)pthread_cond_broadcast(&client->completed);
	return (atomic_load(&client->terminal_error));
}

static void
wake_poller(struct networkcmp_client *client)
{
	struct kevent trigger;

	if (!client->polling)
		return;
	EV_SET(&trigger, 0, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
	(void)kevent(client->kq, &trigger, 1, NULL, 0, NULL);
}

static int64_t
remaining_ms(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (0);
	return ((deadline->tv_sec - now.tv_sec) * INT64_C(1000) +
	    (deadline->tv_nsec - now.tv_nsec) / 1000000);
}

/*
 * Wait, with client->lock held, until the call completes, the connection
 * fails or the deadline passes.  Returns 0 or an errno value; a timeout
 * cancels only this call.
 */
static int
call_wait(struct networkcmp_client *client, struct completion *call,
    const struct timespec *deadline) __no_lock_analysis
{
	struct kevent change, events[4];
	struct timespec timeout;
	int64_t ms;
	int cfd, error, ready, wants_write;

	while (!call->done) {
		error = fidl_bsd_connection_error(client->connection);
		if (error != 0)
			return (client_fail_locked(client, error));
		ms = remaining_ms(deadline);
		if (ms <= 0) {
			if (fidl_bsd_connection_cancel(client->connection,
			    call->txid) != 0 || !call->done)
				return (client_fail_locked(client, ETIMEDOUT));
			return (ETIMEDOUT);
		}
		if (client->polling) {
			(void)pthread_cond_timedwait(&client->completed,
			    &client->lock, deadline);
			continue;
		}
		client->polling = true;
		cfd = fidl_bsd_connection_fd(client->connection);
		wants_write = fidl_bsd_connection_wants_write(client->connection);
		if (wants_write != client->write_armed) {
			EV_SET(&change, cfd, EVFILT_WRITE,
			    wants_write ? EV_ENABLE : EV_DISABLE, 0, 0, NULL);
			if (kevent(client->kq, &change, 1, NULL, 0, NULL) == -1) {
				client->polling = false;
				return (client_fail_locked(client, errno));
			}
			client->write_armed = wants_write;
		}
		timeout.tv_sec = ms / 1000;
		timeout.tv_nsec = (long)(ms % 1000) * 1000000L;
		(void)pthread_mutex_unlock(&client->lock);
		ready = kevent(client->kq, NULL, 0, events, nitems(events),
		    &timeout);
		error = ready == -1 ? errno : 0;
		(void)pthread_mutex_lock(&client->lock);
		client->polling = false;
		if (ready == -1 && error != EINTR) {
			(void)client_fail_locked(client, error);
			continue;
		}
		if (ready > 0) {
			error = fidl_bsd_connection_dispatch(client->connection);
			if (error != 0)
				(void)client_fail_locked(client, error);
		}
		/* Completions for other threads, or a new poller. */
		(void)pthread_cond_broadcast(&client->completed);
	}
	return (0);
}

/*
 * Common entry: validate the handle and compute the call's deadline.  On
 * success the client lock is held.
 */
static int
call_begin(struct networkcmp_client *client, struct timespec *deadline)
    __no_lock_analysis
{
	uint32_t timeout_ms = NETWORKCMP_CALL_TIMEOUT_MS;
	int error;

	if (client == NULL || client->owner != getpid() ||
	    client->connection == NULL)
		return (errno = EINVAL, -1);
	error = atomic_load(&client->terminal_error);
	if (error != 0)
		return (errno = error, -1);
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (-1);
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	error = pthread_mutex_lock(&client->lock);
	if (error != 0)
		return (errno = error, -1);
	return (0);
}

/*
 * Finish a call issued under the lock: wait for it, then classify.  A
 * malformed reply is terminal; an application error keeps the session.
 * Releases the lock.  Any descriptor in call->fd is closed on failure.
 */
static int
call_finish(struct networkcmp_client *client, uint16_t opcode, int issue_error,
    struct completion *call, const struct timespec *deadline) __no_lock_analysis
{
	int error;

	if (issue_error == 0) {
		NETWORKCMP_PROBE_SEND(opcode, 0, 0, 0);
		wake_poller(client);
		error = call_wait(client, call, deadline);
	} else
		error = issue_error;
	if (error == 0 && call->malformed) {
		NETWORKCMP_PROBE_REJECT(opcode, 0, call->error);
		error = client_fail_locked(client, call->error);
	} else if (error == 0)
		error = call->error;
	/* A transport failure is terminal; application errors are not. */
	if (fidl_bsd_connection_error(client->connection) != 0)
		error = client_fail_locked(client,
		    fidl_bsd_connection_error(client->connection));
	if (error == 0) {
		NETWORKCMP_PROBE_RECEIVE(opcode, 0, call->fd >= 0 ? 1 : 0, 0);
	} else if (!call->malformed) {
		NETWORKCMP_PROBE_REJECT(opcode, 0, error);
	}
	(void)pthread_mutex_unlock(&client->lock);
	if (error != 0) {
		if (call->fd >= 0)
			(void)close(call->fd);
		call->fd = -1;
		return (errno = error, -1);
	}
	return (0);
}

static void
malformed(struct completion *call)
{

	call->malformed = true;
	call->error = EPROTO;
}

/* A result union's error: an errno in 1..ELAST, anything else malformed. */
static void
domain_error(struct completion *call, uint32_t error)
{

	if (error == 0 || error > ELAST)
		malformed(call);
	else
		call->error = (int)error;
}

static void
info_reply(void *context, int error, struct bsd_network_v1_ProtocolInfo *value)
{
	struct completion *call = context;

	call->done = true;
	call->error = error;
	if (error == 0 && (value == NULL ||
	    value->wire_version != NETWORKCMP_WIRE_VERSION)) {
		call->malformed = true;
		call->error = EPROTONOSUPPORT;
	}
}

static void
limits_reply(void *context, int error, struct bsd_network_v1_Limits *value)
{
	struct completion *call = context;

	call->done = true;
	call->error = error;
	if (error != 0)
		return;
	/*
	 * The resolve ceiling tracks the DNS feature: 0 without it, 1..MAX
	 * with it.  Unknown feature bits or an inconsistent ceiling are a
	 * malformed reply, as before.
	 */
	if (value == NULL || (value->features & ~(NETWORKCMP_FEATURE_TCP |
	    NETWORKCMP_FEATURE_UDP | NETWORKCMP_FEATURE_IPV6 |
	    NETWORKCMP_FEATURE_DNS | NETWORKCMP_FEATURE_LISTEN)) != 0 ||
	    ((value->features & NETWORKCMP_FEATURE_DNS) != 0 ?
	    (value->max_resolve_results == 0 || value->max_resolve_results >
	    NETWORKCMP_RESOLVE_MAX_RESULTS) : value->max_resolve_results != 0)) {
		malformed(call);
		return;
	}
	call->u.limits = *value;
}

static void
take_socket(struct completion *call, int *fd)
{
	int taken = fidl_bsd_take_fd(fd);

	if (taken < 0)
		malformed(call);
	else
		call->fd = taken;
}

#define	CONNECTED_REPLY(name, type)					\
static void								\
name(void *context, int error, struct type *value)			\
{									\
	struct completion *call = context;				\
									\
	call->done = true;						\
	call->error = error;						\
	if (error != 0)							\
		return;							\
	if (value == NULL)						\
		malformed(call);					\
	else if (value->tag == type##_err_tag)				\
		domain_error(call, value->value.err);			\
	else if (value->tag == type##_response_tag)			\
		take_socket(call, &value->value.response.socket);	\
	else								\
		malformed(call);					\
}
CONNECTED_REPLY(connect_reply, bsd_network_v1_Network_Connect_Result)
CONNECTED_REPLY(udp_reply, bsd_network_v1_Network_Udp_Result)

static void
listen_reply(void *context, int error,
    struct bsd_network_v1_Network_Listen_Result *value)
{
	struct completion *call = context;

	call->done = true;
	call->error = error;
	if (error != 0)
		return;
	if (value == NULL)
		malformed(call);
	else if (value->tag == bsd_network_v1_Network_Listen_Result_err_tag)
		domain_error(call, value->value.err);
	else if (value->tag ==
	    bsd_network_v1_Network_Listen_Result_response_tag) {
		take_socket(call, &value->value.response.socket);
		call->u.listen.port = value->value.response.port;
	} else
		malformed(call);
}

static bool
endpoint_valid(const struct bsd_network_v1_Endpoint *endpoint)
{
	static const uint8_t zero[12];

	if (endpoint->prefix != 0)
		return (false);
	switch (endpoint->family) {
	case NETWORKCMP_AF_INET4:
		return (endpoint->scope_id == 0 &&
		    memcmp(endpoint->address + 4, zero, sizeof(zero)) == 0);
	case NETWORKCMP_AF_INET6:
		return (true);
	default:
		return (false);
	}
}

static void
resolve_reply(void *context, int error,
    struct bsd_network_v1_Network_Resolve_Result *value)
{
	struct completion *call = context;
	const struct bsd_network_v1_Resolved *resolved;
	size_t i;

	call->done = true;
	call->error = error;
	if (error != 0)
		return;
	if (value == NULL) {
		malformed(call);
		return;
	}
	if (value->tag == bsd_network_v1_Network_Resolve_Result_err_tag) {
		domain_error(call, value->value.err);
		return;
	}
	if (value->tag != bsd_network_v1_Network_Resolve_Result_response_tag) {
		malformed(call);
		return;
	}
	resolved = &value->value.response;
	if (resolved->results_size > NETWORKCMP_RESOLVE_MAX_RESULTS ||
	    resolved->canonname_size > NETWORKCMP_CANONNAME_MAX ||
	    memchr(resolved->canonname, '\0', resolved->canonname_size) !=
	    NULL) {
		malformed(call);
		return;
	}
	for (i = 0; i < resolved->results_size; i++)
		if (!endpoint_valid(&resolved->results[i].endpoint) ||
		    resolved->results[i].socket_type > NETWORKCMP_SOCK_DGRAM) {
			malformed(call);
			return;
		}
	/* Capacity errors are the caller's, not the provider's. */
	if (resolved->results_size > call->u.resolve.capacity) {
		call->error = EOVERFLOW;
		return;
	}
	if (call->u.resolve.canonname != NULL &&
	    resolved->canonname_size + 1 > call->u.resolve.canonname_size) {
		call->error = ERANGE;
		return;
	}
	for (i = 0; i < resolved->results_size; i++) {
		struct networkcmp_resolve_result *out =
		    &call->u.resolve.results[i];
		const struct bsd_network_v1_ResolveResult *in =
		    &resolved->results[i];

		memset(out, 0, sizeof(*out));
		out->endpoint.family = in->endpoint.family;
		out->endpoint.prefix = in->endpoint.prefix;
		out->endpoint.port = in->endpoint.port;
		out->endpoint.scope_id = in->endpoint.scope_id;
		memcpy(out->endpoint.address, in->endpoint.address,
		    sizeof(out->endpoint.address));
		out->socket_type = in->socket_type;
		out->protocol = in->protocol;
	}
	if (call->u.resolve.canonname != NULL) {
		memcpy(call->u.resolve.canonname, resolved->canonname,
		    resolved->canonname_size);
		call->u.resolve.canonname[resolved->canonname_size] = '\0';
	}
	call->u.resolve.count = resolved->results_size;
	call->u.resolve.ttl_seconds = resolved->ttl_seconds;
}

/* The wire version, checked once when the process client is created. */
static int
negotiate(struct networkcmp_client *client)
{
	struct completion call = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;

	if (call_begin(client, &deadline) == -1)
		return (-1);
	return (call_finish(client, NETWORKCMP_OP_HELLO,
	    bsd_network_v1_Network_GetProtocolInfo(client->connection, &empty,
	    info_reply, &call, &call.txid), &call, &deadline));
}

int
networkcmp_hello(struct networkcmp_client *client,
    struct networkcmp_hello_reply *reply_value)
{
	struct completion call = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;

	if (client == NULL || reply_value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (call_begin(client, &deadline) == -1)
		return (-1);
	if (call_finish(client, NETWORKCMP_OP_HELLO,
	    bsd_network_v1_Network_GetLimits(client->connection, &empty,
	    limits_reply, &call, &call.txid), &call, &deadline) == -1)
		return (-1);
	memset(reply_value, 0, sizeof(*reply_value));
	reply_value->features = call.u.limits.features;
	reply_value->max_resolve_results = call.u.limits.max_resolve_results;
	return (0);
}

/*
 * Open the process client on `iface`.  The process shares one client; a
 * process that opened one interface cannot also open the other.
 */
static int
networkcmp_client_open_iface(const char *iface,
    struct networkcmp_client **clientp) __no_lock_analysis
{
	struct networkcmp_client *client;
	int error, fd;

	if (clientp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	error = pthread_once(&networkcmp_atfork_once, networkcmp_atfork_init);
	if (error == 0)
		error = networkcmp_atfork_error;
	if (error == 0)
		error = pthread_mutex_lock(&networkcmp_registry_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	while (networkcmp_initializing) {
		error = pthread_cond_wait(&networkcmp_registry_ready,
		    &networkcmp_registry_lock);
		if (error != 0) {
			(void)pthread_mutex_unlock(&networkcmp_registry_lock);
			errno = error;
			return (-1);
		}
	}
	if (networkcmp_process_client != NULL) {
		if (strcmp(networkcmp_process_iface, iface) != 0) {
			(void)pthread_mutex_unlock(&networkcmp_registry_lock);
			errno = EBUSY;
			return (-1);
		}
		networkcmp_process_client->references++;
		*clientp = networkcmp_process_client;
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return (0);
	}
	networkcmp_initializing = true;
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto fail;
	if (client_init(client) == -1) {
		free(client);
		client = NULL;
		goto fail;
	}
	if (service_open(iface, &fd) == -1)
		goto fail;
	if (client_connect(client, fd) == -1)
		goto fail;
	client->owner = getpid();
	if (negotiate(client) == -1 ||
	    networkcmp_hello(client, &client->limits) == -1)
		goto fail;
	client->references = 1;
	error = pthread_mutex_lock(&networkcmp_registry_lock);
	if (error != 0) {
		errno = error;
		goto fail;
	}
	networkcmp_process_client = client;
	networkcmp_process_iface = iface;
	networkcmp_initializing = false;
	*clientp = client;
	(void)pthread_cond_broadcast(&networkcmp_registry_ready);
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	NETWORKCMP_PROBE_OPEN(__DECONST(char *, iface), 0);
	return (0);

fail:
	error = errno;
	if (client != NULL)
		client_destroy(client);
	if (pthread_mutex_lock(&networkcmp_registry_lock) == 0) {
		networkcmp_initializing = false;
		(void)pthread_cond_broadcast(&networkcmp_registry_ready);
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
	}
	NETWORKCMP_PROBE_OPEN(__DECONST(char *, iface), error);
	errno = error;
	return (-1);
}

int
networkcmp_client_open(struct networkcmp_client **clientp)
{

	return (networkcmp_client_open_iface(NETWORKCMP_INTERFACE, clientp));
}

/*
 * The administrative interface: the same protocol, published under a name
 * that requires the system.network.admin software attribute, so only
 * approved programs (networkcmpctl) resolve it -- from a login session too.
 */
int
networkcmp_client_open_admin(struct networkcmp_client **clientp)
{

	return (networkcmp_client_open_iface(NETWORKCMP_ADMIN_INTERFACE,
	    clientp));
}

const struct networkcmp_hello_reply *
networkcmp_client_limits(const struct networkcmp_client *client)
{

	if (client == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (&client->limits);
}

void
networkcmp_client_close(struct networkcmp_client *client) __no_lock_analysis
{
	if (client == NULL)
		return;
	if (pthread_mutex_lock(&networkcmp_registry_lock) != 0)
		return;
	if (client != networkcmp_process_client ||
	    client->owner != getpid() || client->references == 0) {
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return;
	}
	if (--client->references != 0) {
		(void)pthread_mutex_unlock(&networkcmp_registry_lock);
		return;
	}
	/*
	 * Keep the one injected process session alive with no public borrows.
	 * Reopening then reuses the existing managed reader rather than
	 * duplicating a channel receive queue or attempting global discovery.
	 */
	(void)pthread_mutex_unlock(&networkcmp_registry_lock);
}

static int
networkcmp_sockaddr_endpoint(const struct sockaddr *sa, socklen_t salen,
    struct networkcmp_endpoint *endpoint)
{

	if (sa == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(endpoint, 0, sizeof(*endpoint));
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const void *)sa;

		if (salen < (socklen_t)sizeof(*sin)) {
			errno = EINVAL;
			return (-1);
		}
		endpoint->family = NETWORKCMP_AF_INET4;
		endpoint->port = ntohs(sin->sin_port);
		memcpy(endpoint->address, &sin->sin_addr,
		    sizeof(sin->sin_addr));
		return (0);
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const void *)sa;

		if (salen < (socklen_t)sizeof(*sin6)) {
			errno = EINVAL;
			return (-1);
		}
		endpoint->family = NETWORKCMP_AF_INET6;
		endpoint->port = ntohs(sin6->sin6_port);
		endpoint->scope_id = sin6->sin6_scope_id;
		memcpy(endpoint->address, &sin6->sin6_addr,
		    sizeof(sin6->sin6_addr));
		return (0);
	}
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}
}

static void
endpoint_to_wire(const struct networkcmp_endpoint *in,
    struct bsd_network_v1_Endpoint *out)
{

	out->family = in->family;
	out->prefix = in->prefix;
	out->port = in->port;
	out->scope_id = in->scope_id;
	memcpy(out->address, in->address, sizeof(out->address));
}

static int
networkcmp_endpoint_op(struct networkcmp_client *client, uint16_t opcode,
    const struct sockaddr *sa, socklen_t salen, uint32_t timeout_ms, int *out_fd)
{
	struct completion call = { .fd = -1 };
	struct networkcmp_endpoint endpoint;
	struct timespec deadline;
	int error;

	if (out_fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*out_fd = -1;
	if (networkcmp_sockaddr_endpoint(sa, salen, &endpoint) == -1)
		return (-1);
	if (call_begin(client, &deadline) == -1)
		return (-1);
	if (opcode == NETWORKCMP_OP_UDP) {
		struct bsd_network_v1_UdpRequest request;

		endpoint_to_wire(&endpoint, &request.endpoint);
		error = bsd_network_v1_Network_Udp(client->connection, &request,
		    udp_reply, &call, &call.txid);
	} else {
		struct bsd_network_v1_ConnectRequest request;

		endpoint_to_wire(&endpoint, &request.endpoint);
		request.timeout_ms = timeout_ms;
		error = bsd_network_v1_Network_Connect(client->connection,
		    &request, connect_reply, &call, &call.txid);
	}
	if (call_finish(client, opcode, error, &call, &deadline) == -1)
		return (-1);
	*out_fd = call.fd;
	return (0);
}

int
networkcmp_connect(struct networkcmp_client *client,
    const struct sockaddr *address, socklen_t address_length, int *out_fd)
{

	return (networkcmp_endpoint_op(client, NETWORKCMP_OP_CONNECT, address,
	    address_length, 0, out_fd));
}

int
networkcmp_connect_ex(struct networkcmp_client *client,
    const struct sockaddr *address, socklen_t address_length,
    uint32_t timeout_ms, int *out_fd)
{

	return (networkcmp_endpoint_op(client, NETWORKCMP_OP_CONNECT, address,
	    address_length, timeout_ms, out_fd));
}

int
networkcmp_listen(struct networkcmp_client *client, uint16_t backlog,
    uint16_t *port_out, int *out_fd)
{
	struct completion call = { .fd = -1 };
	struct bsd_network_v1_ListenRequest request = { backlog };
	struct timespec deadline;

	if (out_fd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*out_fd = -1;
	if (call_begin(client, &deadline) == -1)
		return (-1);
	if (call_finish(client, NETWORKCMP_OP_LISTEN,
	    bsd_network_v1_Network_Listen(client->connection, &request,
	    listen_reply, &call, &call.txid), &call, &deadline) == -1)
		return (-1);
	if (port_out != NULL)
		*port_out = call.u.listen.port;
	*out_fd = call.fd;
	return (0);
}

int
networkcmp_udp(struct networkcmp_client *client, const struct sockaddr *peer,
    socklen_t peer_length, int *out_fd)
{

	return (networkcmp_endpoint_op(client, NETWORKCMP_OP_UDP, peer,
	    peer_length, 0, out_fd));
}

int
networkcmp_resolve(struct networkcmp_client *client, const char *host,
    const char *service,
    uint32_t family, uint32_t socket_type, uint32_t flags,
    struct networkcmp_resolve_result *results, size_t *nresults,
    char *canonname, size_t canonname_size, uint32_t *ttl_seconds)
{
	struct completion call = { .fd = -1 };
	struct bsd_network_v1_ResolveRequest request;
	struct timespec deadline;
	size_t host_length, service_length;

	host_length = host != NULL ? strlen(host) : 0;
	service_length = service != NULL ? strlen(service) : 0;
	if (nresults == NULL || (results == NULL && *nresults != 0) ||
	    host_length > NETWORKCMP_NAME_MAX ||
	    service_length > NETWORKCMP_SERVICE_MAX ||
	    (host_length == 0 && service_length == 0) ||
	    family > NETWORKCMP_AF_INET6 ||
	    socket_type > NETWORKCMP_SOCK_DGRAM ||
	    (flags & ~NETWORKCMP_RESOLVE_F_MASK) != 0 ||
	    *nresults == 0 || *nresults > NETWORKCMP_RESOLVE_MAX_RESULTS ||
	    (canonname == NULL && canonname_size != 0)) {
		errno = EINVAL;
		return (-1);
	}
	if ((flags & NETWORKCMP_RESOLVE_F_ADDRCONFIG) != 0) {
		errno = EOPNOTSUPP;
		return (-1);
	}
	request = (struct bsd_network_v1_ResolveRequest){
		.host = host_length != 0 ? host : "",
		.host_size = host_length,
		.service = service_length != 0 ? service : "",
		.service_size = service_length,
		.family = family,
		.socket_type = socket_type,
		.flags = flags,
		.max_results = (uint32_t)*nresults
	};
	/*
	 * The callback validates every capacity before writing any output, so
	 * a failed call leaves results, counts, TTL and canonname untouched.
	 */
	call.u.resolve.results = results;
	call.u.resolve.capacity = *nresults;
	call.u.resolve.canonname = canonname;
	call.u.resolve.canonname_size = canonname_size;
	if (call_begin(client, &deadline) == -1)
		return (-1);
	if (call_finish(client, NETWORKCMP_OP_RESOLVE,
	    bsd_network_v1_Network_Resolve(client->connection, &request,
	    resolve_reply, &call, &call.txid), &call, &deadline) == -1)
		return (-1);
	*nresults = call.u.resolve.count;
	if (ttl_seconds != NULL)
		*ttl_seconds = call.u.resolve.ttl_seconds;
	return (0);
}

struct networkcmp_addrinfo {
	struct addrinfo ai;
	struct sockaddr_storage address;
	char canonical[NETWORKCMP_CANONNAME_MAX + 1];
};

void
networkcmp_freeaddrinfo(struct addrinfo *result)
{
	struct addrinfo *next;

	while (result != NULL) {
		next = result->ai_next;
		free(result);
		result = next;
	}
}

static int
networkcmp_gai_error(int error)
{

	switch (error) {
	case EAGAIN:
		return (EAI_AGAIN);
	case ENOMEM:
		return (EAI_MEMORY);
	case ENOENT:
		return (EAI_NONAME);
	case EAFNOSUPPORT:
		return (EAI_FAMILY);
	case EPROTONOSUPPORT:
	case EPROTOTYPE:
		return (EAI_SERVICE);
	default:
		return (EAI_SYSTEM);
	}
}

int
networkcmp_getaddrinfo(struct networkcmp_client *client, const char *host,
    const char *service,
    const struct addrinfo *hints, struct addrinfo **result)
{
	struct networkcmp_resolve_result resolved[NETWORKCMP_RESOLVE_MAX_RESULTS];
	struct networkcmp_addrinfo *entry;
	struct addrinfo **tail;
	char canonical[NETWORKCMP_CANONNAME_MAX + 1];
	uint32_t family, socket_type, flags;
	size_t count, i;
	int saved_errno;

	if (result == NULL)
		return (EAI_FAIL);
	*result = NULL;
	family = NETWORKCMP_AF_UNSPEC;
	socket_type = NETWORKCMP_SOCK_ANY;
	flags = 0;
	if (hints != NULL) {
		switch (hints->ai_family) {
		case AF_UNSPEC:
			break;
		case AF_INET:
			family = NETWORKCMP_AF_INET4;
			break;
		case AF_INET6:
			family = NETWORKCMP_AF_INET6;
			break;
		default:
			return (EAI_FAMILY);
		}
		switch (hints->ai_socktype) {
		case 0:
			break;
		case SOCK_STREAM:
			socket_type = NETWORKCMP_SOCK_STREAM;
			break;
		case SOCK_DGRAM:
			socket_type = NETWORKCMP_SOCK_DGRAM;
			break;
		default:
			return (EAI_SOCKTYPE);
		}
		switch (hints->ai_protocol) {
		case 0:
			break;
		case IPPROTO_TCP:
			if (socket_type == NETWORKCMP_SOCK_DGRAM)
				return (EAI_SOCKTYPE);
			socket_type = NETWORKCMP_SOCK_STREAM;
			break;
		case IPPROTO_UDP:
			if (socket_type == NETWORKCMP_SOCK_STREAM)
				return (EAI_SOCKTYPE);
			socket_type = NETWORKCMP_SOCK_DGRAM;
			break;
		default:
			return (EAI_SERVICE);
		}
		if ((hints->ai_flags & ~(AI_PASSIVE | AI_CANONNAME |
		    AI_NUMERICHOST | AI_NUMERICSERV |
		    AI_V4MAPPED | AI_ALL)) != 0)
			return (EAI_BADFLAGS);
		if ((hints->ai_flags & AI_PASSIVE) != 0)
			flags |= NETWORKCMP_RESOLVE_F_PASSIVE;
		if ((hints->ai_flags & AI_CANONNAME) != 0)
			flags |= NETWORKCMP_RESOLVE_F_CANONNAME;
		if ((hints->ai_flags & AI_NUMERICHOST) != 0)
			flags |= NETWORKCMP_RESOLVE_F_NUMERIC_HOST;
		if ((hints->ai_flags & AI_NUMERICSERV) != 0)
			flags |= NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE;
		if ((hints->ai_flags & AI_V4MAPPED) != 0)
			flags |= NETWORKCMP_RESOLVE_F_V4MAPPED;
		if ((hints->ai_flags & AI_ALL) != 0)
			flags |= NETWORKCMP_RESOLVE_F_ALL;
	}
	count = nitems(resolved);
	if (networkcmp_resolve(client, host, service, family, socket_type,
	    flags,
	    resolved, &count, canonical, sizeof(canonical), NULL) == -1)
		return (networkcmp_gai_error(errno));
	tail = result;
	for (i = 0; i < count; i++) {
		entry = calloc(1, sizeof(*entry));
		if (entry == NULL) {
			saved_errno = errno;
			networkcmp_freeaddrinfo(*result);
			*result = NULL;
			errno = saved_errno;
			return (EAI_MEMORY);
		}
		entry->ai.ai_family =
		    resolved[i].endpoint.family == NETWORKCMP_AF_INET4 ?
		    AF_INET : AF_INET6;
		entry->ai.ai_socktype =
		    resolved[i].socket_type == NETWORKCMP_SOCK_STREAM ?
		    SOCK_STREAM : resolved[i].socket_type ==
		    NETWORKCMP_SOCK_DGRAM ? SOCK_DGRAM : 0;
		entry->ai.ai_protocol = (int)resolved[i].protocol;
		if (entry->ai.ai_family == AF_INET) {
			struct sockaddr_in *sin = (void *)&entry->address;

			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			sin->sin_port = htons(resolved[i].endpoint.port);
			memcpy(&sin->sin_addr, resolved[i].endpoint.address,
			    sizeof(sin->sin_addr));
			entry->ai.ai_addrlen = sizeof(*sin);
		} else {
			struct sockaddr_in6 *sin6 = (void *)&entry->address;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			sin6->sin6_port = htons(resolved[i].endpoint.port);
			sin6->sin6_scope_id = resolved[i].endpoint.scope_id;
			memcpy(&sin6->sin6_addr, resolved[i].endpoint.address,
			    sizeof(sin6->sin6_addr));
			entry->ai.ai_addrlen = sizeof(*sin6);
		}
		entry->ai.ai_addr = (void *)&entry->address;
		if (i == 0 && canonical[0] != '\0') {
			strlcpy(entry->canonical, canonical,
			    sizeof(entry->canonical));
			entry->ai.ai_canonname = entry->canonical;
		}
		*tail = &entry->ai;
		tail = &entry->ai.ai_next;
	}
	if (*result == NULL)
		return (EAI_NONAME);
	return (0);
}
