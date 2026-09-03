/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/filio.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <libcasper.h>
#include <casper/cap_net.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <auditcmp.h>
#include <auditcmp_server.h>
#include <libservice.h>
#include <networkcmp.h>
#include <networkcmp_server.h>

#include "localnetwork_probes.h"
#include "policy.h"
#ifdef NETWORKCMP_TESTING
#include "networkcmp_test.h"
#endif

#define	LOCALNETWORK_NAME	"system.Network"
#define	NETWORKCMP_RESOLVER_TIMEOUT_MS	30000U

union provider_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

struct resolver_job {
	struct channel_message		*request_message;
	cap_channel_t			*capnet;
	const char			*label;
	struct networkcmp_policy	 policy;
	struct networkcmp_msg		 request_header;
	struct networkcmp_resolve_request request;
	char				 host[NETWORKCMP_NAME_MAX + 1];
	char				 service[NETWORKCMP_SERVICE_MAX + 1];
	uint8_t			 payload[NETWORKCMP_MAX_MESSAGE -
					 sizeof(struct networkcmp_msg)];
	size_t				 payload_length;
	int				 notify_fd;
	int				 error;
	pthread_t			 thread;
	_Atomic bool			 complete;
#ifdef NETWORKCMP_TESTING
	int				 test_ready_fd;
	int				 test_release_fd;
#endif
};

struct session_state {
	cap_channel_t		*capnet;
	cap_channel_t		*resolver_capnet;
	struct auditcmp_client	*audit;
	/* Immutable session policy; set once at session creation. */
	struct networkcmp_policy policy;
	const char		*label;
	struct resolver_job	*resolver;
	int			 resolver_pipe[2];
	uint64_t		 resolver_deadline_ns;
	uint32_t		 resolver_timeout_ms;
	int			 terminal_error;
#ifdef NETWORKCMP_TESTING
	int			 test_ready_fd;
	int			 test_release_fd;
#endif
};

static uint64_t
monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (0);
	return ((uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec);
}

static int
endpoint_sockaddr(const struct networkcmp_endpoint *endpoint,
    struct sockaddr_storage *storage, socklen_t *length)
{

	memset(storage, 0, sizeof(*storage));
	if (endpoint->family == NETWORKCMP_AF_INET4) {
		struct sockaddr_in *sin;

		sin = (void *)storage;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(endpoint->port);
		memcpy(&sin->sin_addr, endpoint->address, sizeof(sin->sin_addr));
		*length = sizeof(*sin);
		return (0);
	}
	if (endpoint->family == NETWORKCMP_AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (void *)storage;
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(endpoint->port);
		sin6->sin6_scope_id = endpoint->scope_id;
		memcpy(&sin6->sin6_addr, endpoint->address,
		    sizeof(sin6->sin6_addr));
		*length = sizeof(*sin6);
		return (0);
	}
	errno = EAFNOSUPPORT;
	return (-1);
}

/*
 * Destination constraint (N2 / SSRF defense).  A session that does not hold the
 * internal-reach authority (NETWORKCMP_RIGHT_INTERNAL, or ADMIN) must not be
 * able to have the broker connect to loopback, link-local, or the private
 * RFC1918/ULA ranges — those reach other local capability endpoints and
 * management planes.  The casper CAPNET_CONNECT limit only fixes the mode and
 * cannot express "everything except the internal ranges" (its address limits are
 * an allow-list, and destinations are client-supplied and dynamic), so the
 * constraint is enforced here, fail-closed, BEFORE any connect() is issued.
 *
 * Returns true iff the endpoint names an internal destination.
 */
static bool
endpoint_is_internal(const struct networkcmp_endpoint *endpoint)
{
	const uint8_t *a = endpoint->address;

	if (endpoint->family == NETWORKCMP_AF_INET4) {
		/* 0.0.0.0/8 (this host), 127/8 loopback, 169.254/16 link-local. */
		if (a[0] == 0 || a[0] == 127)
			return (true);
		if (a[0] == 169 && a[1] == 254)
			return (true);
		/* RFC1918: 10/8, 172.16/12, 192.168/16. */
		if (a[0] == 10)
			return (true);
		if (a[0] == 172 && (a[1] & 0xf0) == 16)
			return (true);
		if (a[0] == 192 && a[1] == 168)
			return (true);
		return (false);
	}
	if (endpoint->family == NETWORKCMP_AF_INET6) {
		static const uint8_t loopback[16] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
		static const uint8_t v4mapped[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

		if (memcmp(a, loopback, sizeof(loopback)) == 0)
			return (true);
		/* fe80::/10 link-local, fec0::/10 site-local, fc00::/7 ULA. */
		if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
			return (true);
		if (a[0] == 0xfe && (a[1] & 0xc0) == 0xc0)
			return (true);
		if ((a[0] & 0xfe) == 0xfc)
			return (true);
		/* Unspecified ::/128. */
		{
			static const uint8_t unspecified[16] = { 0 };

			if (memcmp(a, unspecified, sizeof(unspecified)) == 0)
				return (true);
		}
		/* IPv4-mapped ::ffff:0:0/96 — apply the v4 rules to the mapping. */
		if (memcmp(a, v4mapped, sizeof(v4mapped)) == 0) {
			struct networkcmp_endpoint mapped;

			memset(&mapped, 0, sizeof(mapped));
			mapped.family = NETWORKCMP_AF_INET4;
			memcpy(mapped.address, a + 12, 4);
			return (endpoint_is_internal(&mapped));
		}
		return (false);
	}
	return (false);
}

/*
 * Limit a connected socket to exactly the rights a data-transfer client needs
 * before it is handed off via SCM_RIGHTS.  The client may read/write, receive
 * events, shut down, get/set socket options, query and toggle O_NONBLOCK, and
 * fstat.  It may not bind, connect, listen, accept, or peel off, and the
 * descriptor may be transferred exactly once (this delivery) and no further.
 * CAP_RECV/CAP_SEND are aliases of CAP_READ/CAP_WRITE.  CAP_IOCTL is present
 * only so the FIONREAD/FIONBIO/FIOASYNC allow-list below has effect.
 */
static int
harden_delivered_socket(int fd)
{
	static const unsigned long ioctls[] = { FIONREAD, FIONBIO, FIOASYNC };
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SHUTDOWN,
	    CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_FSTAT, CAP_IOCTL);
	return (cap_rights_limit(fd, &rights) == -1 ||
	    cap_ioctls_limit(fd, ioctls, nitems(ioctls)) == -1 ||
	    cap_fcntls_limit(fd, CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) == -1 ||
	    cap_xfer_limit(fd, CAP_XFER_ONCE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
broker_perform_connect(struct session_state *state, int fd,
    const struct sockaddr *sa, socklen_t length)
{

#ifdef NETWORKCMP_TESTING
	(void)state;
	return (connect(fd, sa, length));
#else
	return (cap_connect(state->capnet, fd, sa, length));
#endif
}

/*
 * Create and connect a socket to the requested endpoint under the immutable
 * session policy, then rights-limit it for delivery.  On success *out_fd holds
 * a connected, transfer-limited descriptor owned by the caller.
 */
static int
broker_connect(struct session_state *state, uint16_t opcode,
    const struct networkcmp_endpoint *endpoint, int *out_fd)
{
	struct sockaddr_storage storage;
	socklen_t length;
	int fd, domain, type, error;
	bool udp;

	*out_fd = -1;
	udp = opcode == NETWORKCMP_OP_UDP;
	if ((endpoint->family == NETWORKCMP_AF_INET4 && !state->policy.ipv4) ||
	    (endpoint->family == NETWORKCMP_AF_INET6 && !state->policy.ipv6)) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	/*
	 * Default-deny internal destinations unless this session's authority
	 * explicitly permits them (N2).  Fail closed before touching the network.
	 */
	if (!state->policy.allow_internal && endpoint_is_internal(endpoint)) {
		errno = EACCES;
		return (-1);
	}
	if (endpoint_sockaddr(endpoint, &storage, &length) == -1)
		return (-1);
	domain = endpoint->family == NETWORKCMP_AF_INET4 ? AF_INET : AF_INET6;
	type = udp ? SOCK_DGRAM : SOCK_STREAM;
	fd = socket(domain, type | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	if (broker_perform_connect(state, fd, (const void *)&storage,
	    length) == -1 || harden_delivered_socket(fd) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	*out_fd = fd;
	return (0);
}

static void
audit_policy(struct auditcmp_client *audit, const char *label,
    const char *operation, int error)
{

	if (audit == NULL)
		return;
	if (auditcmp_submit(audit, label, operation, error) == -1)
		syslog(LOG_WARNING, "audit %s for %s failed: %m", operation,
		    label);
}

/*
 * Casper's master channel is factory authority.  It must remain in the
 * provider and must never cross either a fork or exec boundary.
 */
#ifndef NETWORKCMP_TESTING
static int
harden_factory_channel(cap_channel_t *channel)
{
	int fd;

	fd = cap_sock(channel);
	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

/*
 * A limited per-session channel crosses exactly the worker pdfork.  The
 * CAP_CLOFORK_ONCE transition locks it in both processes after that fork.
 */
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
#endif

static int
send_reply(struct channel_message *request_message,
    const char *label __unused, const struct networkcmp_msg *request, int error,
    const void *payload, size_t payload_length, int attached_fd)
{
	union provider_buffer buffer;
	struct networkcmp_msg *reply;
	const int *fds;
	size_t length, nfds;
	int result, saved_error;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	if (networkcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1) {
		LOCALNETWORK_REQUEST_DONE(__DECONST(char *, label),
		    request->opcode, errno);
		return (-1);
	}
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	fds = (error == 0 && attached_fd >= 0) ? &attached_fd : NULL;
	nfds = (error == 0 && attached_fd >= 0) ? 1 : 0;
	if (networkcmp_validate_message(reply, length,
	    NETWORKCMP_MESSAGE_REPLY) == -1 ||
	    networkcmp_validate_fds(reply, nfds,
	    NETWORKCMP_MESSAGE_REPLY) == -1) {
		LOCALNETWORK_REQUEST_DONE(__DECONST(char *, label),
		    request->opcode, errno);
		return (-1);
	}
	result = channel_send_reply(request_message,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = reply,
		.length = length,
		.fds = fds,
		.nfds = nfds
	    });
	saved_error = result == -1 ? errno : error;
	LOCALNETWORK_REQUEST_DONE(__DECONST(char *, label),
	    request->opcode, saved_error);
	if (result == -1)
		errno = saved_error;
	return (result);
}

#ifndef NETWORKCMP_TESTING
static int
gai_to_errno(int error)
{

	switch (error) {
	case 0:
		return (0);
	case EAI_AGAIN:
		return (EAGAIN);
	case EAI_MEMORY:
		return (ENOMEM);
	case EAI_NONAME:
		return (ENOENT);
	case EAI_SERVICE:
	case EAI_SOCKTYPE:
		return (EPROTONOSUPPORT);
	case EAI_SYSTEM:
		return (errno != 0 ? errno : EIO);
	default:
		return (EIO);
	}
}

static int
resolve_perform(struct resolver_job *job)
{
	const struct networkcmp_resolve_request *request;
	struct networkcmp_resolve_reply *reply;
	struct networkcmp_resolve_result *results;
	struct addrinfo hints, *addresses, *ai;
	char *canonical;
	size_t canonical_length, payload_length;
	uint32_t count, maximum;
	int error;

	request = &job->request;
	if ((request->family == NETWORKCMP_AF_INET4 && !job->policy.ipv4) ||
	    (request->family == NETWORKCMP_AF_INET6 && !job->policy.ipv6)) {
		error = EAFNOSUPPORT;
		goto reject;
	}
	memset(&hints, 0, sizeof(hints));
	switch (request->family) {
	case NETWORKCMP_AF_UNSPEC:
		hints.ai_family = AF_UNSPEC;
		break;
	case NETWORKCMP_AF_INET4:
		hints.ai_family = AF_INET;
		break;
	case NETWORKCMP_AF_INET6:
		hints.ai_family = AF_INET6;
		break;
	default:
		error = EAFNOSUPPORT;
		goto reject;
	}
	switch (request->socket_type) {
	case NETWORKCMP_SOCK_ANY:
		hints.ai_socktype = 0;
		break;
	case NETWORKCMP_SOCK_STREAM:
		hints.ai_socktype = SOCK_STREAM;
		break;
	case NETWORKCMP_SOCK_DGRAM:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	default:
		error = EPROTOTYPE;
		goto reject;
	}
	if ((request->flags & NETWORKCMP_RESOLVE_F_PASSIVE) != 0)
		hints.ai_flags |= AI_PASSIVE;
	if ((request->flags & NETWORKCMP_RESOLVE_F_CANONNAME) != 0)
		hints.ai_flags |= AI_CANONNAME;
	if ((request->flags & NETWORKCMP_RESOLVE_F_NUMERIC_HOST) != 0)
		hints.ai_flags |= AI_NUMERICHOST;
	if ((request->flags & NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE) != 0)
		hints.ai_flags |= AI_NUMERICSERV;

	LOCALNETWORK_RESOLVE_START(__DECONST(char *, job->label), job->host);
	addresses = NULL;
	error = cap_getaddrinfo(job->capnet,
	    request->host_length != 0 ? job->host : NULL,
	    request->service_length != 0 ? job->service : NULL, &hints,
	    &addresses);
	if (error != 0) {
		error = gai_to_errno(error);
		goto reject_probe;
	}
	memset(job->payload, 0, sizeof(job->payload));
	reply = (void *)job->payload;
	results = (void *)(reply + 1);
	maximum = MIN(request->max_results, job->policy.max_results);
	canonical = NULL;
	count = 0;
	for (ai = addresses; ai != NULL && count < maximum; ai = ai->ai_next) {
		struct networkcmp_resolve_result *result;

		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		result = &results[count];
		result->endpoint.family = ai->ai_family == AF_INET ?
		    NETWORKCMP_AF_INET4 : NETWORKCMP_AF_INET6;
		result->socket_type = ai->ai_socktype == SOCK_STREAM ?
		    NETWORKCMP_SOCK_STREAM : ai->ai_socktype == SOCK_DGRAM ?
		    NETWORKCMP_SOCK_DGRAM : NETWORKCMP_SOCK_ANY;
		result->protocol = (uint32_t)ai->ai_protocol;
		if (ai->ai_family == AF_INET) {
			const struct sockaddr_in *sin = (const void *)ai->ai_addr;

			result->endpoint.port = ntohs(sin->sin_port);
			memcpy(result->endpoint.address, &sin->sin_addr,
			    sizeof(sin->sin_addr));
		} else {
			const struct sockaddr_in6 *sin6 = (const void *)ai->ai_addr;

			result->endpoint.port = ntohs(sin6->sin6_port);
			result->endpoint.scope_id = sin6->sin6_scope_id;
			memcpy(result->endpoint.address, &sin6->sin6_addr,
			    sizeof(sin6->sin6_addr));
		}
		if (canonical == NULL && ai->ai_canonname != NULL)
			canonical = ai->ai_canonname;
		count++;
	}
	canonical_length = canonical != NULL ? strlen(canonical) : 0;
	if (canonical_length > NETWORKCMP_CANONNAME_MAX)
		canonical_length = NETWORKCMP_CANONNAME_MAX;
	reply->result_count = count;
	reply->canonname_length = (uint32_t)canonical_length;
	/* cap_net/getaddrinfo does not expose DNS TTLs; zero means unknown. */
	reply->ttl_seconds = 0;
	if (canonical_length != 0)
		memcpy(results + count, canonical, canonical_length);
	payload_length = sizeof(*reply) + count * sizeof(*results) +
	    canonical_length;
	freeaddrinfo(addresses);
	LOCALNETWORK_RESOLVE_DONE(__DECONST(char *, job->label), count, 0);
	job->payload_length = payload_length;
	return (0);

reject_probe:
	LOCALNETWORK_RESOLVE_DONE(__DECONST(char *, job->label), 0, error);
reject:
	errno = error;
	return (-1);
}
#else
static int
resolve_perform(struct resolver_job *job)
{
	uint8_t byte;
	ssize_t amount;

	if (job->test_ready_fd >= 0) {
		byte = 1;
		do {
			amount = write(job->test_ready_fd, &byte, sizeof(byte));
		} while (amount == -1 && errno == EINTR);
		if (amount != sizeof(byte))
			return (-1);
		do {
			amount = read(job->test_release_fd, &byte, sizeof(byte));
		} while (amount == -1 && errno == EINTR);
		if (amount != sizeof(byte))
			return (-1);
	}
	errno = EOPNOTSUPP;
	return (-1);
}
#endif

#define	NETWORKCMP_DISPATCH_ASYNC	1

static void *
resolver_thread(void *argument)
{
	struct resolver_job *job;
	uint8_t byte;

	job = argument;
	job->error = resolve_perform(job) == -1 ?
	    (errno != 0 ? errno : EIO) : 0;
	atomic_store_explicit(&job->complete, true, memory_order_release);
	byte = 1;
	(void)write(job->notify_fd, &byte, sizeof(byte));
	return (NULL);
}

static int
start_resolve(struct session_state *state,
    struct channel_message *request_message,
    const struct networkcmp_msg *message)
{
	const struct networkcmp_resolve_request *request;
	const char *wire;
	struct resolver_job *job;
	int error;

	if (state->resolver != NULL)
		return (errno = EBUSY, -1);
	request = (const void *)(message + 1);
	wire = (const void *)(request + 1);
	job = calloc(1, sizeof(*job));
	if (job == NULL)
		return (-1);
	job->request_message = request_message;
	job->capnet = state->resolver_capnet;
	job->label = state->label;
	job->policy = state->policy;
	job->request_header = *message;
	job->request = *request;
	memcpy(job->host, wire, request->host_length);
	job->host[request->host_length] = '\0';
	memcpy(job->service, wire + request->host_length,
	    request->service_length);
	job->service[request->service_length] = '\0';
	job->notify_fd = state->resolver_pipe[1];
	atomic_init(&job->complete, false);
#ifdef NETWORKCMP_TESTING
	job->test_ready_fd = state->test_ready_fd;
	job->test_release_fd = state->test_release_fd;
#endif
	state->resolver = job;
	state->resolver_deadline_ns = monotonic_ns();
	if (state->resolver_deadline_ns == 0) {
		state->resolver = NULL;
		free(job);
		return (errno = EIO, -1);
	}
	state->resolver_deadline_ns +=
	    (uint64_t)state->resolver_timeout_ms * 1000000;
	error = pthread_create(&job->thread, NULL, resolver_thread, job);
	if (error != 0) {
		state->resolver = NULL;
		free(job);
		errno = error;
		return (-1);
	}
	return (0);
}

static int
finish_resolve(struct session_state *state)
{
	struct resolver_job *job;
	uint8_t bytes[32];
	ssize_t amount;
	int error, result;

	for (;;) {
		amount = read(state->resolver_pipe[0], bytes, sizeof(bytes));
		if (amount > 0)
			continue;
		if (amount == -1 && errno == EINTR)
			continue;
		if (amount == -1 && errno == EAGAIN)
			break;
		if (amount == 0)
			break;
		return (-1);
	}
	job = state->resolver;
	if (job == NULL || !atomic_load_explicit(&job->complete,
	    memory_order_acquire))
		return (0);
	error = pthread_join(job->thread, NULL);
	if (error != 0)
		return (errno = error, -1);
	audit_policy(state->audit, state->label, "resolve", job->error);
	result = send_reply(job->request_message, state->label,
	    &job->request_header, job->error,
	    job->error == 0 ? job->payload : NULL,
	    job->error == 0 ? job->payload_length : 0, -1);
	error = result == -1 ? errno : 0;
	channel_message_free(job->request_message);
	state->resolver = NULL;
	state->resolver_deadline_ns = 0;
	free(job);
	errno = error;
	return (result);
}

static int
dispatch(struct channel_message *request_message,
    struct session_state *state, const struct networkcmp_msg *message,
    const char *label)
{
	const struct networkcmp_connect_request *connect_request;
	struct networkcmp_hello_reply hello;
	int fd, error, result;
	bool udp;

	switch (message->opcode) {
	case NETWORKCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = NETWORKCMP_ABI_VERSION;
		hello.features = NETWORKCMP_FEATURE_DNS |
		    (state->policy.allow_connect ? NETWORKCMP_FEATURE_TCP : 0) |
		    (state->policy.allow_udp ? NETWORKCMP_FEATURE_UDP : 0) |
		    (state->policy.ipv6 ? NETWORKCMP_FEATURE_IPV6 : 0);
		hello.max_resolve_results = state->policy.max_results;
		return (send_reply(request_message, label, message, 0, &hello,
		    sizeof(hello), -1));
	case NETWORKCMP_OP_CONNECT:
	case NETWORKCMP_OP_UDP:
		connect_request = (const void *)(message + 1);
		udp = message->opcode == NETWORKCMP_OP_UDP;
		fd = -1;
		if ((udp && !state->policy.allow_udp) ||
		    (!udp && !state->policy.allow_connect))
			error = EACCES;
		else
			error = broker_connect(state, message->opcode,
			    &connect_request->endpoint, &fd) == -1 ? errno : 0;
		audit_policy(state->audit, label, udp ? "udp" : "connect",
		    error);
		result = send_reply(request_message, label, message, error,
		    NULL, 0, error == 0 ? fd : -1);
		if (fd >= 0)
			close(fd);
		return (result);
	case NETWORKCMP_OP_RESOLVE:
		if (!state->policy.resolve) {
			audit_policy(state->audit, label, "resolve", EACCES);
			return (send_reply(request_message, label, message, EACCES,
			    NULL, 0, -1));
		}
		if (start_resolve(state, request_message, message) == -1) {
			error = errno;
			audit_policy(state->audit, label, "resolve", error);
			return (send_reply(request_message, label, message, error,
			    NULL, 0, -1));
		}
		return (NETWORKCMP_DISPATCH_ASYNC);
	default:
		audit_policy(state->audit, label, "unsupported", EOPNOTSUPP);
		return (send_reply(request_message, label, message, EOPNOTSUPP,
		    NULL, 0, -1));
	}
}

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct session_state *state;
	const struct networkcmp_msg *message;
	size_t length;
	int result;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (networkcmp_validate_message(message, length,
	    NETWORKCMP_MESSAGE_REQUEST) == -1 ||
	    networkcmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    NETWORKCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		LOCALNETWORK_REJECT(__DECONST(char *, state->label),
		    EPROTO);
		audit_policy(state->audit, state->label, "malformed-request",
		    EPROTO);
		channel_message_free(request_message);
		return;
	}
	result = dispatch(request_message, state, message, state->label);
	if (result == -1)
		state->terminal_error = errno;
	if (result != NETWORKCMP_DISPATCH_ASYNC)
		channel_message_free(request_message);
}

static int
serve_session(int fd, cap_channel_t *capnet, cap_channel_t *resolver_capnet,
    const struct networkcmp_policy *policy, struct auditcmp_client *audit,
    const char *label, const int resolver_pipe[2], uint32_t resolver_timeout_ms
#ifdef NETWORKCMP_TESTING
    , int test_ready_fd, int test_release_fd
#endif
    )
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct session_state state;
	struct channel *channel;
	struct kevent kev, kout[3];
	struct timespec ts, *tsp;
	int kq, nev, i, poll_timeout, result, wants_write;
	bool chan_read, chan_write, pipe_read;
	uint64_t now, remaining;

	if (fd < 0 || policy == NULL || label == NULL || label[0] == '\0' ||
	    resolver_pipe == NULL || resolver_pipe[0] < 0 || resolver_pipe[1] < 0)
		return (errno = EINVAL, -1);
	channel = NULL;
	memset(&state, 0, sizeof(state));
	state.label = label;
	state.audit = audit;
	LOCALNETWORK_SESSION_START(__DECONST(char *, label),
	    policy->max_results);
	state.capnet = capnet;
	state.resolver_capnet = resolver_capnet;
	state.resolver_pipe[0] = resolver_pipe[0];
	state.resolver_pipe[1] = resolver_pipe[1];
	state.resolver_timeout_ms = resolver_timeout_ms;
#ifdef NETWORKCMP_TESTING
	state.test_ready_fd = test_ready_fd;
	state.test_release_fd = test_release_fd;
#endif
	state.policy = *policy;
	if (channel_create(fd, &options, &channel) == -1 ||
	    channel_set_request_handler(channel, handle_request, &state) ==
	    -1) {
		if (channel != NULL)
			channel_destroy(channel);
		goto fail;
	}
	/*
	 * Channels are kqueue-only, and this session also waits on the resolver
	 * pipe, so watch both fds on one kqueue.  Read interest on the channel
	 * and pipe is registered once; the channel write filter is toggled per
	 * iteration to match pending outbound data.
	 */
	kq = kqueue();
	if (kq == -1)
		state.terminal_error = errno;
	else {
		EV_SET(&kev, channel_fd(channel), EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
			state.terminal_error = errno;
		EV_SET(&kev, state.resolver_pipe[0], EVFILT_READ, EV_ADD, 0, 0,
		    NULL);
		if (state.terminal_error == 0 &&
		    kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
			state.terminal_error = errno;
	}
	while (state.terminal_error == 0) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		EV_SET(&kev, channel_fd(channel), EVFILT_WRITE,
		    wants_write ? EV_ADD : EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		poll_timeout = -1;
		if (state.resolver != NULL) {
			now = monotonic_ns();
			if (now == 0 || now >= state.resolver_deadline_ns) {
				state.terminal_error = now == 0 ? EIO : ETIMEDOUT;
				break;
			}
			remaining = state.resolver_deadline_ns - now;
			poll_timeout = (int)MIN((remaining + 999999) / 1000000,
			    INT_MAX);
		}
		if (poll_timeout < 0) {
			tsp = NULL;
		} else {
			ts.tv_sec = poll_timeout / 1000;
			ts.tv_nsec = (long)(poll_timeout % 1000) * 1000000L;
			tsp = &ts;
		}
		do {
			nev = kevent(kq, NULL, 0, kout, nitems(kout), tsp);
		} while (nev == -1 && errno == EINTR);
		if (nev == -1)
			break;
		if (nev == 0) {
			state.terminal_error = ETIMEDOUT;
			break;
		}
		chan_read = chan_write = pipe_read = false;
		for (i = 0; i < nev; i++) {
			if ((int)kout[i].ident == state.resolver_pipe[0] &&
			    kout[i].filter == EVFILT_READ)
				pipe_read = true;
			else if (kout[i].filter == EVFILT_READ)
				chan_read = true;
			else if (kout[i].filter == EVFILT_WRITE)
				chan_write = true;
		}
		if (pipe_read && finish_resolve(&state) == -1)
			break;
		if (chan_write && channel_flush(channel) == -1)
			break;
		if (chan_read && channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}
	if (kq != -1)
		close(kq);
	channel_destroy(channel);
	if (state.resolver == NULL) {
		close(state.resolver_pipe[0]);
		close(state.resolver_pipe[1]);
	}
	result = state.terminal_error == 0 ? 0 : 1;
	LOCALNETWORK_SESSION_END(__DECONST(char *, label),
	    state.terminal_error);
	return (result);

fail:
	result = errno;
	LOCALNETWORK_SESSION_END(__DECONST(char *, label), result);
	errno = result;
	return (1);
}

#ifdef NETWORKCMP_TESTING
bool
networkcmp_test_endpoint_is_internal(const struct networkcmp_endpoint *endpoint)
{

	return (endpoint_is_internal(endpoint));
}

int
networkcmp_test_serve(int fd, cap_channel_t *capnet,
    const struct networkcmp_policy *policy, const char *label)
{
	int resolver_pipe[2];

	if (fd < 0 || policy == NULL || label == NULL || label[0] == '\0')
		return (errno = EINVAL, -1);
	if (pipe2(resolver_pipe, O_CLOEXEC | O_NONBLOCK) == -1)
		return (-1);
	return (serve_session(fd, capnet, capnet, policy, NULL, label,
	    resolver_pipe, NETWORKCMP_RESOLVER_TIMEOUT_MS, -1, -1));
}

int
networkcmp_test_serve_blocked_resolver(int fd, cap_channel_t *capnet,
    const struct networkcmp_policy *policy, const char *label, int ready_fd,
    int release_fd)
{
	int resolver_pipe[2];

	if (fd < 0 || policy == NULL || label == NULL || label[0] == '\0' ||
	    ready_fd < 0 || release_fd < 0)
		return (errno = EINVAL, -1);
	if (pipe2(resolver_pipe, O_CLOEXEC | O_NONBLOCK) == -1)
		return (-1);
	return (serve_session(fd, capnet, capnet, policy, NULL, label,
	    resolver_pipe, NETWORKCMP_RESOLVER_TIMEOUT_MS, ready_fd, release_fd));
}

int
networkcmp_test_serve_blocked_resolver_timeout(int fd, cap_channel_t *capnet,
    const struct networkcmp_policy *policy, const char *label, int ready_fd,
    int release_fd, uint32_t timeout_ms)
{
	int resolver_pipe[2];

	if (fd < 0 || policy == NULL || label == NULL || label[0] == '\0' ||
	    ready_fd < 0 || release_fd < 0 || timeout_ms == 0)
		return (errno = EINVAL, -1);
	if (pipe2(resolver_pipe, O_CLOEXEC | O_NONBLOCK) == -1)
		return (-1);
	return (serve_session(fd, capnet, capnet, policy, NULL, label,
	    resolver_pipe, timeout_ms, ready_fd, release_fd));
}
#endif

#ifndef NETWORKCMP_TESTING
static int
worker(int fd, int barrier, cap_channel_t *capnet,
    cap_channel_t *resolver_capnet, const int resolver_pipe[2],
    const struct networkcmp_policy *policy, int audit_fd, const char *label)
{
	struct auditcmp_client *audit;
	char byte;
	int error, result;

	audit = NULL;
	if (auditcmp_client_adopt(audit_fd, &audit) == -1)
		goto fail;
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC) == -1)
		goto fail;
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1)
		goto fail;
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1) {
		result = 1;
		goto out;
	}
	close(barrier);
	barrier = -1;
	result = serve_session(fd, capnet, resolver_capnet, policy, audit, label,
	    resolver_pipe, NETWORKCMP_RESOLVER_TIMEOUT_MS);
out:
	if (barrier >= 0)
		close(barrier);
	cap_close(capnet);
	/* resolver_capnet and an active resolver job die atomically with _exit(). */
	auditcmp_client_close(audit);
	return (result);
fail:
	error = errno;
	(void)write(barrier, &error, sizeof(error));
	result = 1;
	goto out;
}

static int
start_session(int fd, cap_channel_t *casper, const char *peer_label,
    service_rights_t rights)
{
	struct networkcmp_policy policy;
	cap_channel_t *capnet, *resolver_capnet;
	cap_net_limit_t *limit;
	int families[2];
	size_t nfamilies;
	int syncfd[2], resolver_pipe[2], pd, audit_fd, child_error, error;
	pid_t pid;
	char byte;
	ssize_t n;

	audit_fd = -1;
	capnet = NULL;
	resolver_capnet = NULL;
	resolver_pipe[0] = resolver_pipe[1] = -1;
	if (harden_worker_fd(fd) == -1) {
		error = errno;
		goto reject;
	}
	/*
	 * Authority is the rights serviced stamped onto this session's channel,
	 * not a hardcoded default (N1).  Derive the immutable policy from them and
	 * fail closed: a session that carries no network rights permits nothing,
	 * so refuse it outright rather than brokering with an empty policy.
	 */
	if (networkcmp_policy_from_rights(&policy, rights) == -1) {
		error = errno;
		goto reject;
	}
	if (!networkcmp_policy_permits_any(&policy)) {
		error = EACCES;
		goto reject;
	}
	nfamilies = 0;
	if (policy.ipv4)
		families[nfamilies++] = AF_INET;
	if (policy.ipv6)
		families[nfamilies++] = AF_INET6;
	capnet = cap_service_open(casper, "system.net");
	if (capnet == NULL) {
		error = errno;
		goto reject;
	}
	/*
	 * The broker performs connect on the client's behalf; bind, listen and
	 * accept are not part of the version-1 client API.
	 */
	limit = cap_net_limit_init(capnet, CAPNET_CONNECT);
	if (limit == NULL || cap_net_limit(limit) == -1) {
		error = errno;
		cap_close(capnet);
		capnet = NULL;
		goto reject;
	}
	if (harden_worker_channel(capnet) == -1) {
		error = errno;
		cap_close(capnet);
		capnet = NULL;
		goto reject;
	}
	resolver_capnet = cap_service_open(casper, "system.net");
	if (resolver_capnet == NULL) {
		error = errno;
		goto reject;
	}
	limit = cap_net_limit_init(resolver_capnet, CAPNET_NAME2ADDR);
	if (limit == NULL || cap_net_limit_name2addr_family(limit, families,
	    nfamilies) == NULL || cap_net_limit(limit) == -1 ||
	    harden_worker_channel(resolver_capnet) == -1) {
		error = errno;
		goto reject;
	}
	if (auditcmp_client_prepare(&audit_fd) == -1) {
		error = errno;
		goto reject;
	}
	if (pipe2(resolver_pipe, O_CLOEXEC | O_NONBLOCK) == -1 ||
	    harden_worker_fd(resolver_pipe[0]) == -1 ||
	    harden_worker_fd(resolver_pipe[1]) == -1) {
		error = errno;
		goto reject;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		goto reject;
	}
	if (cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    harden_worker_fd(syncfd[1]) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		cap_close(casper);
		_exit(worker(fd, syncfd[1], capnet, resolver_capnet,
		    resolver_pipe, &policy, audit_fd, peer_label));
	}
	close(audit_fd);
	audit_fd = -1;
	cap_close(capnet);
	capnet = NULL;
	cap_close(resolver_capnet);
	resolver_capnet = NULL;
	close(resolver_pipe[0]);
	close(resolver_pipe[1]);
	resolver_pipe[0] = resolver_pipe[1] = -1;
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
	return (0);

reject:
	if (audit_fd >= 0)
		close(audit_fd);
	if (resolver_pipe[0] >= 0)
		close(resolver_pipe[0]);
	if (resolver_pipe[1] >= 0)
		close(resolver_pipe[1]);
	if (resolver_capnet != NULL)
		cap_close(resolver_capnet);
	if (capnet != NULL)
		cap_close(capnet);
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
	int error, fd;

	openlog("localnetwork", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	casper = cap_init();
	if (casper == NULL)
		goto fail;
	if (harden_factory_channel(casper) == -1)
		goto fail;
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, LOCALNETWORK_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		goto fail;
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				int status;

				status = service_provider_quiesce_complete(provider, 0);
				cap_close(casper);
				closelog();
				return (status == 0 ? 0 : 1);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (start_session(fd, casper, identity.client_label,
		    identity.rights) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
#endif
