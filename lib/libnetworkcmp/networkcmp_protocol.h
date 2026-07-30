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
#define	NETWORKCMP_INTERFACE		"org.5bsd.cmp.network"
#define	NETWORKCMP_INTERFACE_VERSION	"1.0.0"
#define	NETWORKCMP_MAX_MESSAGE		14336
#define	NETWORKCMP_RING_FDS		8
#define	NETWORKCMP_NAME_MAX		253
#define	NETWORKCMP_SERVICE_MAX		32
#define	NETWORKCMP_CANONNAME_MAX	253
#define	NETWORKCMP_RESOLVE_MAX_RESULTS	32
#define	NETWORKCMP_RING_MIN_SIZE		4096U
#define	NETWORKCMP_RING_MAX_SIZE		(1U << 30)
#define	NETWORKCMP_RING_DEFAULT_SIZE	(256U * 1024)
#define	NETWORKCMP_DATAGRAM_DEFAULT_MAX	65535U

#define	NETWORKCMP_MSG_F_REPLY		0x00000001U
#define	NETWORKCMP_MSG_F_MASK		NETWORKCMP_MSG_F_REPLY

#define	NETWORKCMP_FEATURE_TCP		0x00000001U
#define	NETWORKCMP_FEATURE_UDP		0x00000002U
#define	NETWORKCMP_FEATURE_IPV6		0x00000004U
#define	NETWORKCMP_FEATURE_SHM_RINGS	0x00000008U
#define	NETWORKCMP_FEATURE_QUIC_DATAGRAM	0x00000010U
#define	NETWORKCMP_FEATURE_DNS		0x00000020U

#define	NETWORKCMP_RESOLVE_F_PASSIVE		0x00000001U
#define	NETWORKCMP_RESOLVE_F_CANONNAME		0x00000002U
#define	NETWORKCMP_RESOLVE_F_NUMERIC_HOST	0x00000004U
#define	NETWORKCMP_RESOLVE_F_NUMERIC_SERVICE	0x00000008U
#define	NETWORKCMP_RESOLVE_F_MASK		0x0000000fU

enum networkcmp_opcode {
	NETWORKCMP_OP_HELLO = 1,
	NETWORKCMP_OP_SOCKET,
	NETWORKCMP_OP_BIND,
	NETWORKCMP_OP_CONNECT,
	NETWORKCMP_OP_LISTEN,
	NETWORKCMP_OP_ACCEPT,
	NETWORKCMP_OP_SETOPT,
	NETWORKCMP_OP_SHUTDOWN,
	NETWORKCMP_OP_CLOSE,
	NETWORKCMP_OP_RESOLVE,
	NETWORKCMP_OP_ATTACH_RINGS,
	NETWORKCMP_OP_NOTIFY
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

struct networkcmp_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	uint32_t	length;
	uint64_t	request_id;
	int32_t		status;
	uint32_t	reserved;
};

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
	uint32_t	preferred_tx_ring_size;
	uint32_t	preferred_rx_ring_size;
	uint32_t	preferred_max_datagram;
	uint32_t	reserved2;
};

struct networkcmp_hello_reply {
	uint32_t	version;
	uint32_t	features;
	uint32_t	max_sockets;
	uint32_t	max_ring_size;
	uint32_t	tx_ring_size;
	uint32_t	rx_ring_size;
	uint32_t	max_datagram;
	uint32_t	reserved;
};

struct networkcmp_handle {
	uint64_t	handle;
	uint64_t	generation;
};

struct networkcmp_socket_request {
	uint32_t	family;
	uint32_t	type;
	uint32_t	protocol;
	uint32_t	flags;
};

struct networkcmp_handle_reply {
	struct networkcmp_handle socket;
};

struct networkcmp_endpoint_request {
	struct networkcmp_handle socket;
	struct networkcmp_endpoint endpoint;
};

struct networkcmp_listen_request {
	struct networkcmp_handle socket;
	uint32_t	backlog;
	uint32_t	reserved;
};

struct networkcmp_close_request {
	struct networkcmp_handle socket;
};

struct networkcmp_setopt_request {
	struct networkcmp_handle socket;
	uint32_t	level;
	uint32_t	option;
	uint32_t	value_length;
	uint32_t	reserved;
	/* value_length bytes follow. */
};

struct networkcmp_shutdown_request {
	struct networkcmp_handle socket;
	uint32_t	how;
	uint32_t	reserved;
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

struct networkcmp_ring_request {
	struct networkcmp_handle socket;
	uint32_t	tx_mode;
	uint32_t	rx_mode;
};

#endif /* !_NETWORKCMP_PROTOCOL_H_ */
