/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETWORKCMP_PROTOCOL_H_
#define	_NETWORKCMP_PROTOCOL_H_

#include <sys/types.h>

#include <stdint.h>

#define	NETWORKCMP_MAGIC		0x4e434d50U	/* "NCMP" */
#define	NETWORKCMP_ABI_VERSION		1
#define	NETWORKCMP_INTERFACE		"system.Network"
#define	NETWORKCMP_INTERFACE_VERSION	"1.0.0"
#define	NETWORKCMP_MAX_MESSAGE		2048
#define	NETWORKCMP_NAME_MAX		253
#define	NETWORKCMP_SERVICE_MAX		32
#define	NETWORKCMP_CANONNAME_MAX	253
#define	NETWORKCMP_RESOLVE_MAX_RESULTS	32

#define	NETWORKCMP_MSG_F_MASK		0U

#define	NETWORKCMP_FEATURE_TCP		0x00000001U
#define	NETWORKCMP_FEATURE_UDP		0x00000002U
#define	NETWORKCMP_FEATURE_IPV6		0x00000004U
#define	NETWORKCMP_FEATURE_DNS		0x00000008U

#define	NETWORKCMP_RESOLVE_F_PASSIVE		0x00000001U
#define	NETWORKCMP_RESOLVE_F_CANONNAME		0x00000002U
#define	NETWORKCMP_RESOLVE_F_NUMERIC_HOST	0x00000004U
#define	NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE	0x00000008U
#define	NETWORKCMP_RESOLVE_F_MASK		0x0000000fU

/*
 * Protocol version 1 is a connection broker.  RESOLVE performs a bounded
 * getaddrinfo under policy and returns address results as data; CONNECT and
 * UDP perform a real socket()+connect() under policy and hand the connected,
 * rights-limited descriptor back over the session channel via SCM_RIGHTS.
 * The client owns all subsequent I/O on that descriptor.  There is no data
 * proxying and no emulated socket handle.
 *
 * Protocol space is deliberately reserved for future userspace networking
 * (listeners, protocol stacks, virtual interfaces); none of it is implemented
 * by version 1 and any such behavior requires a negotiated protocol version.
 */
enum networkcmp_opcode {
	NETWORKCMP_OP_HELLO = 1,
	NETWORKCMP_OP_RESOLVE,
	NETWORKCMP_OP_CONNECT,
	NETWORKCMP_OP_UDP
};

enum networkcmp_family {
	NETWORKCMP_AF_UNSPEC = 0,
	NETWORKCMP_AF_INET4 = 1,
	NETWORKCMP_AF_INET6 = 2
};

enum networkcmp_socket_type {
	NETWORKCMP_SOCK_ANY = 0,
	NETWORKCMP_SOCK_STREAM = 1,
	NETWORKCMP_SOCK_DGRAM = 2
};

enum networkcmp_message_role {
	NETWORKCMP_MESSAGE_REQUEST = 1,
	NETWORKCMP_MESSAGE_REPLY,
	NETWORKCMP_MESSAGE_EVENT
};

struct networkcmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	int32_t		status;
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct networkcmp_msg) == 16,
    "networkcmp message header ABI");

struct networkcmp_endpoint {
	uint8_t		family;
	uint8_t		prefix;
	uint16_t	port;		/* host byte order */
	uint32_t	scope_id;
	uint8_t		address[16];
};

struct networkcmp_hello {
	uint32_t	min_version;
	uint32_t	max_version;
	uint32_t	features;
	uint32_t	reserved;
};

struct networkcmp_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint32_t	max_resolve_results;
	uint32_t	reserved;
};

/*
 * CONNECT and UDP carry a single fully-specified destination endpoint.  A
 * successful reply carries no payload; the connected descriptor is delivered
 * out of band via SCM_RIGHTS and the status field conveys the connect result.
 */
struct networkcmp_connect_request {
	struct networkcmp_endpoint endpoint;
};

/*
 * The host and service strings follow this structure, without terminators.
 * Either string may be empty, but not both.  Results are bounded by both the
 * request and NETWORKCMP_RESOLVE_MAX_RESULTS.
 */
struct networkcmp_resolve_request {
	uint32_t	host_length;
	uint32_t	service_length;
	uint32_t	family;
	uint32_t	socket_type;
	uint32_t	flags;
	uint32_t	max_results;
};

struct networkcmp_resolve_reply {
	uint32_t	result_count;
	uint32_t	canonname_length;
	uint32_t	ttl_seconds;
	uint32_t	reserved;
	/* result_count entries, then canonname_length bytes, follow. */
};

struct networkcmp_resolve_result {
	struct networkcmp_endpoint endpoint;
	uint32_t	socket_type;
	uint32_t	protocol;
};

#endif /* !_NETWORKCMP_PROTOCOL_H_ */
