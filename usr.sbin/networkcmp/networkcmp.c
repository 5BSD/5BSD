/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <libcasper.h>
#include <casper/cap_net.h>
#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libservice.h>
#include <networkcmp.h>

#include "networkcmp_probes.h"

#define	NETWORKCMP_PROVIDER_NAME	"org.5bsd.NetworkCmp.resolver"

union provider_buffer {
	max_align_t align;
	struct {
		struct networkcmp_msg msg;
		uint8_t payload[NETWORKCMP_MAX_MESSAGE -
		    sizeof(struct networkcmp_msg)];
	} wire;
};

struct resolver_policy {
	bool ipv4;
	bool ipv6;
	uint32_t max_results;
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_NETWORKCMP_POLICY, getuid(), (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

/*
 * Casper's master channel is factory authority.  It must remain in the
 * provider and must never cross either a fork or exec boundary.
 */
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

static int
send_reply(int fd, const struct networkcmp_msg *request, int error,
    const void *payload, size_t payload_length)
{
	union provider_buffer buffer;
	struct networkcmp_msg *reply;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	reply->magic = NETWORKCMP_MAGIC;
	reply->version = NETWORKCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->flags = NETWORKCMP_MSG_F_REPLY;
	reply->length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	reply->request_id = request->request_id;
	reply->status = error == 0 ? 0 : -error;
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	return (networkcmp_send_message(fd, reply, reply->length, NULL, 0));
}

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
resolve_request(int fd, cap_channel_t *capnet,
    const struct resolver_policy *policy, const struct networkcmp_msg *message,
    const char *label)
{
	union provider_buffer reply_buffer;
	const struct networkcmp_resolve_request *request;
	struct networkcmp_resolve_reply *reply;
	struct networkcmp_resolve_result *results;
	struct addrinfo hints, *addresses, *ai;
	const char *wire;
	char host[NETWORKCMP_NAME_MAX + 1];
	char service[NETWORKCMP_SERVICE_MAX + 1];
	char *canonical;
	size_t canonical_length, payload_length;
	uint32_t count, maximum;
	int error;

	request = (const void *)(message + 1);
	wire = (const char *)(request + 1);
	memcpy(host, wire, request->host_length);
	host[request->host_length] = '\0';
	memcpy(service, wire + request->host_length, request->service_length);
	service[request->service_length] = '\0';
	if ((request->family == NETWORKCMP_AF_INET4 && !policy->ipv4) ||
	    (request->family == NETWORKCMP_AF_INET6 && !policy->ipv6)) {
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

	NETWORKCMP_PROVIDER_RESOLVE_START(__DECONST(char *, label), host);
	addresses = NULL;
	error = cap_getaddrinfo(capnet, request->host_length != 0 ? host : NULL,
	    request->service_length != 0 ? service : NULL, &hints, &addresses);
	if (error != 0) {
		error = gai_to_errno(error);
		goto reject_probe;
	}
	memset(&reply_buffer, 0, sizeof(reply_buffer));
	reply = (void *)reply_buffer.wire.payload;
	results = (void *)(reply + 1);
	maximum = MIN(request->max_results, policy->max_results);
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
	NETWORKCMP_PROVIDER_RESOLVE_DONE(__DECONST(char *, label), count, 0);
	audit_policy(label, "resolve", 0);
	return (send_reply(fd, message, 0, reply, payload_length));

reject_probe:
	NETWORKCMP_PROVIDER_RESOLVE_DONE(__DECONST(char *, label), 0, error);
reject:
	audit_policy(label, "resolve", error);
	return (send_reply(fd, message, error, NULL, 0));
}

static int
dispatch(int fd, cap_channel_t *capnet, const struct resolver_policy *policy,
    const struct networkcmp_msg *message, const char *label)
{
	struct networkcmp_hello_reply hello;

	switch (message->opcode) {
	case NETWORKCMP_OP_HELLO:
		memset(&hello, 0, sizeof(hello));
		hello.version = NETWORKCMP_ABI_VERSION;
		hello.features = NETWORKCMP_FEATURE_DNS |
		    (policy->ipv6 ? NETWORKCMP_FEATURE_IPV6 : 0);
		hello.max_sockets = 0;
		hello.max_ring_size = 0;
		return (send_reply(fd, message, 0, &hello, sizeof(hello)));
	case NETWORKCMP_OP_RESOLVE:
		return (resolve_request(fd, capnet, policy, message, label));
	default:
		audit_policy(label, "unsupported", EOPNOTSUPP);
		return (send_reply(fd, message, EOPNOTSUPP, NULL, 0));
	}
}

static int
worker(int fd, int barrier, cap_channel_t *capnet,
    const struct resolver_policy *policy, const char *label)
{
	union provider_buffer buffer;
	size_t nfds;
	ssize_t received;
	char byte;
	int error;

	if (service_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	service_drop_inherited_authority();
	if (cap_enter() == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1)
		return (1);
	close(barrier);
	NETWORKCMP_PROVIDER_SESSION_START(__DECONST(char *, label),
	    policy->max_results);
	for (;;) {
		nfds = 0;
		received = networkcmp_receive_message(fd, &buffer, sizeof(buffer),
		    NULL, &nfds);
		if (received == -1) {
			if (errno != ECONNRESET && errno != EPIPE) {
				NETWORKCMP_PROVIDER_REJECT(
				    __DECONST(char *, label), errno);
				audit_policy(label, "malformed-request", errno);
			}
			break;
		}
		if ((buffer.wire.msg.flags & NETWORKCMP_MSG_F_REPLY) != 0 ||
		    dispatch(fd, capnet, policy, &buffer.wire.msg, label) == -1)
			break;
	}
	close(fd);
	cap_close(capnet);
	return (0);
}

static int
start_session(int fd, cap_channel_t *casper, const char *peer_label)
{
	struct component_session_bootstrap bootstrap;
	struct resolver_policy policy;
	cap_channel_t *capnet;
	cap_net_limit_t *limit;
	char options[COMPONENT_SESSION_OPTIONS_MAX];
	int families[] = { AF_INET, AF_INET6 };
	int syncfd[2], pd, child_error, error;
	pid_t pid;
	char byte;
	ssize_t n;

	if (service_component_recv_bootstrap(fd, &bootstrap, options,
	    sizeof(options)) == -1)
		return (-1);
	if (strcmp(bootstrap.interface, NETWORKCMP_INTERFACE) != 0 ||
	    strcmp(bootstrap.interface_version,
	    NETWORKCMP_INTERFACE_VERSION) != 0 ||
	    bootstrap.scope != COMPONENT_SESSION_SCOPE_PRIVATE) {
		error = EOPNOTSUPP;
		goto reject;
	}
	if (harden_worker_fd(fd) == -1) {
		error = errno;
		goto reject;
	}
	/*
	 * The first provider is deliberately DNS-only.  Its feature set makes
	 * that explicit; the future netmap/lwIP provider shares this exact ABI.
	 */
	policy.ipv4 = true;
	policy.ipv6 = true;
	policy.max_results = NETWORKCMP_RESOLVE_MAX_RESULTS;
	if (strcmp(options, "{}") != 0) {
		error = EINVAL;
		goto reject;
	}
	capnet = cap_service_open(casper, "system.net");
	if (capnet == NULL) {
		error = errno;
		goto reject;
	}
	limit = cap_net_limit_init(capnet, CAPNET_NAME2ADDR);
	if (limit == NULL ||
	    cap_net_limit_name2addr_family(limit, families,
	    nitems(families)) == NULL ||
	    cap_net_limit(limit) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (harden_worker_channel(capnet) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		cap_close(capnet);
		goto reject;
	}
	if (cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    harden_worker_fd(syncfd[1]) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capnet);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		cap_close(capnet);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		cap_close(casper);
		_exit(worker(fd, syncfd[1], capnet, &policy, peer_label));
	}
	cap_close(capnet);
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	if (service_component_send_reply(fd, bootstrap.instance_id, 0,
	    COMPONENT_SESSION_MEMBER_PROCDESC, pd) == -1) {
		error = errno;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		return (-1);
	}
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	return (0);

reject:
	(void)service_component_send_reply(fd, bootstrap.instance_id, error, 0,
	    -1);
	audit_policy(peer_label, "session-bootstrap", error);
	errno = error;
	return (-1);
}

int
main(void)
{
	cap_channel_t *casper;
	char label[COMPONENT_SESSION_LABEL_MAX];
	int fd;

	openlog("networkcmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	casper = cap_init();
	if (casper == NULL)
		goto fail;
	if (harden_factory_channel(casper) == -1)
		goto fail;
	if (service_init() == -1 ||
	    service_authorize_capabilities() == -1 ||
	    service_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_register(NETWORKCMP_PROVIDER_NAME) == -1 ||
	    service_ready() == -1)
		goto fail;
	for (;;) {
		fd = service_accept(label, sizeof(label));
		if (fd == -1) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (start_session(fd, casper, label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m", label);
		close(fd);
	}

fail:
	syslog(LOG_ERR, "initialization or service loop: %m");
	return (1);
}
