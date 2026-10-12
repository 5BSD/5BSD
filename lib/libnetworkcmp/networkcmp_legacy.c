/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The pre-FIDL NCMP record validators (networkcmp_server.h), kept for ABI
 * compatibility.  Nothing in the tree speaks this format any more: the
 * provider and libnetworkcmp use bsd.network.v1 (networkcmp.fidl).
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "networkcmp.h"
#include "networkcmp_server.h"
#include "networkcmp_probes.h"

static bool
networkcmp_endpoint_valid(const struct networkcmp_endpoint *endpoint)
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

static int
networkcmp_header_validate(const struct networkcmp_msg *msg, size_t received,
    enum networkcmp_message_role role)
{

	if (msg == NULL || received < sizeof(*msg) ||
	    received > NETWORKCMP_MAX_MESSAGE ||
	    (role != NETWORKCMP_MESSAGE_REQUEST &&
	    role != NETWORKCMP_MESSAGE_REPLY &&
	    role != NETWORKCMP_MESSAGE_EVENT) ||
	    msg->magic != NETWORKCMP_MAGIC ||
	    msg->opcode < NETWORKCMP_OP_HELLO ||
	    msg->opcode > NETWORKCMP_OP_LISTEN ||
	    (msg->flags & ~NETWORKCMP_MSG_F_MASK) != 0 ||
	    (role != NETWORKCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == NETWORKCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
networkcmp_message_init(struct networkcmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < NETWORKCMP_OP_HELLO ||
	    opcode > NETWORKCMP_OP_LISTEN ||
	    (flags & ~NETWORKCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = NETWORKCMP_MAGIC;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
networkcmp_message_init_reply(struct networkcmp_msg *reply,
    const struct networkcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    networkcmp_header_validate(request, sizeof(*request),
	    NETWORKCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = NETWORKCMP_MAGIC;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
networkcmp_validate_message(const struct networkcmp_msg *msg,
    size_t received, enum networkcmp_message_role role)
{
	size_t payload, expected;
	uint16_t probe_opcode;

	probe_opcode = msg != NULL ? msg->opcode : 0;
	if (networkcmp_header_validate(msg, received, role) == -1)
		goto reject;
	payload = received - sizeof(*msg);
	if (role == NETWORKCMP_MESSAGE_EVENT)
		goto reject;
	if (role == NETWORKCMP_MESSAGE_REPLY && msg->status != 0)
		expected = 0;
	else if (role == NETWORKCMP_MESSAGE_REPLY) {
		switch (msg->opcode) {
		case NETWORKCMP_OP_HELLO: {
			const struct networkcmp_hello_reply *hello;

			expected = sizeof(struct networkcmp_hello_reply);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->reserved != 0 ||
				    (hello->features &
				    ~(NETWORKCMP_FEATURE_TCP |
				    NETWORKCMP_FEATURE_UDP |
				    NETWORKCMP_FEATURE_IPV6 |
				    NETWORKCMP_FEATURE_DNS |
				    NETWORKCMP_FEATURE_LISTEN)) != 0)
					goto reject;
				/*
				 * The resolve ceiling tracks the DNS feature: a
				 * label without resolve advertises 0 results, one
				 * with it a bounded 1..MAX.  Anything else is an
				 * inconsistent reply.
				 */
				if ((hello->features & NETWORKCMP_FEATURE_DNS) != 0) {
					if (hello->max_resolve_results == 0 ||
					    hello->max_resolve_results >
					    NETWORKCMP_RESOLVE_MAX_RESULTS)
						goto reject;
				} else if (hello->max_resolve_results != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_CONNECT:
		case NETWORKCMP_OP_UDP:
			/* The connected descriptor arrives out of band. */
			expected = 0;
			break;
		case NETWORKCMP_OP_LISTEN:
			/* Carries listen_reply + the listening socket (OOB). */
			expected = sizeof(struct networkcmp_listen_reply);
			if (payload == expected) {
				const struct networkcmp_listen_reply *l =
				    (const void *)(msg + 1);

				if (l->reserved0 != 0 || l->reserved1 != 0)
					goto reject;
			}
			break;
		case NETWORKCMP_OP_RESOLVE: {
			const struct networkcmp_resolve_reply *resolve;
			const struct networkcmp_resolve_result *results;
			const char *canonname;
			size_t entries;
			uint32_t i;

			if (payload < sizeof(*resolve))
				goto reject;
			resolve = (const void *)(msg + 1);
			if (resolve->reserved != 0 ||
			    resolve->result_count >
			    NETWORKCMP_RESOLVE_MAX_RESULTS ||
			    resolve->canonname_length >
			    NETWORKCMP_CANONNAME_MAX)
				goto reject;
			entries = (size_t)resolve->result_count *
			    sizeof(struct networkcmp_resolve_result);
			expected = sizeof(*resolve) + entries +
			    resolve->canonname_length;
			if (payload != expected)
				goto reject;
			results = (const void *)(resolve + 1);
			for (i = 0; i < resolve->result_count; i++)
				if (!networkcmp_endpoint_valid(
				    &results[i].endpoint) ||
				    results[i].socket_type >
				    NETWORKCMP_SOCK_DGRAM)
					goto reject;
			canonname = (const char *)(results +
			    resolve->result_count);
			if (memchr(canonname, '\0',
			    resolve->canonname_length) != NULL)
				goto reject;
			break;
		}
		default:
			expected = 0;
			break;
		}
	} else {
		switch (msg->opcode) {
		case NETWORKCMP_OP_HELLO: {
			const struct networkcmp_hello *hello;

			expected = sizeof(struct networkcmp_hello);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->reserved != 0 ||
				    (hello->features &
				    ~(NETWORKCMP_FEATURE_TCP |
				    NETWORKCMP_FEATURE_UDP |
				    NETWORKCMP_FEATURE_IPV6 |
				    NETWORKCMP_FEATURE_DNS)) != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_CONNECT:
		case NETWORKCMP_OP_UDP: {
			const struct networkcmp_connect_request *connect;

			expected = sizeof(struct networkcmp_connect_request);
			if (payload == expected) {
				connect = (const void *)(msg + 1);
				if (!networkcmp_endpoint_valid(
				    &connect->endpoint) ||
				    connect->reserved != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_LISTEN: {
			const struct networkcmp_listen_request *l;

			expected = sizeof(struct networkcmp_listen_request);
			if (payload == expected) {
				l = (const void *)(msg + 1);
				if (l->reserved0 != 0 || l->reserved1 != 0)
					goto reject;
			}
			break;
		}
		case NETWORKCMP_OP_RESOLVE: {
			const struct networkcmp_resolve_request *resolve;

			if (payload < sizeof(*resolve))
				goto reject;
			resolve = (const void *)(msg + 1);
			if (resolve->host_length > NETWORKCMP_NAME_MAX ||
			    resolve->service_length > NETWORKCMP_SERVICE_MAX ||
			    (resolve->host_length == 0 &&
			    resolve->service_length == 0) ||
			    resolve->family > NETWORKCMP_AF_INET6 ||
			    resolve->socket_type > NETWORKCMP_SOCK_DGRAM ||
			    (resolve->flags & ~NETWORKCMP_RESOLVE_F_MASK) != 0 ||
			    resolve->max_results == 0 ||
			    resolve->max_results >
			    NETWORKCMP_RESOLVE_MAX_RESULTS)
				goto reject;
			expected = sizeof(*resolve) + resolve->host_length +
			    resolve->service_length;
			if (payload != expected ||
			    memchr(resolve + 1, '\0',
			    resolve->host_length + resolve->service_length) !=
			    NULL)
				goto reject;
			break;
		}
		default:
			goto reject;
		}
	}
	if (expected > NETWORKCMP_MAX_MESSAGE - sizeof(*msg) ||
	    payload != expected)
		goto reject;
	return (0);

reject:
	errno = EPROTO;
	NETWORKCMP_PROBE_REJECT(probe_opcode, (uint32_t)received, EPROTO);
	return (-1);
}

int
networkcmp_validate_fds(const struct networkcmp_msg *msg, size_t nfds,
    enum networkcmp_message_role role)
{
	size_t expected;

	if (msg == NULL || (role != NETWORKCMP_MESSAGE_REQUEST &&
	    role != NETWORKCMP_MESSAGE_REPLY &&
	    role != NETWORKCMP_MESSAGE_EVENT)) {
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Only a successful CONNECT or UDP reply carries exactly one
	 * descriptor: the connected socket.  Every other message carries none.
	 */
	expected = role == NETWORKCMP_MESSAGE_REPLY && msg->status == 0 &&
	    (msg->opcode == NETWORKCMP_OP_CONNECT ||
	    msg->opcode == NETWORKCMP_OP_UDP ||
	    msg->opcode == NETWORKCMP_OP_LISTEN) ? 1 : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

