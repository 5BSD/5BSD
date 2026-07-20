/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * liboraclert — shared types, constants, and helpers for the oracle
 * MAC capability.  Used by oracled, serviced, libcapbundle, and
 * client tools.
 */

#ifndef _ORACLERT_H_
#define	_ORACLERT_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdint.h>

/* Network claim direction flags (match mac_capability_isolation_proto.h). */
#define	ORT_NET_DIR_BIND	0x01
#define	ORT_NET_DIR_CONNECT	0x02
#define	ORT_NET_DIR_ANY		0x03

/* Stable AF_BLUETOOTH socket protocol numbers. */
#define	ORT_BTPROTO_HCI		134
#define	ORT_BTPROTO_L2CAP	135
#define	ORT_BTPROTO_RFCOMM	136
#define	ORT_BTPROTO_SCO		137
#define	ORT_BTPROTO_ISO		138

/*
 * Canonical network claim descriptor.  Used by oracled configuration,
 * serviced manifests, and the oracle IPC protocol.  Field layout
 * matches the kernel-side mac_capability_isolation_proto.h.
 */
struct ort_net_claim {
	int		domain;		/* AF_INET, AF_INET6, 0=any */
	int		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port_min;	/* host byte order */
	uint16_t	port_max;	/* host byte order */
	uint8_t		direction;	/* ORT_NET_DIR_* */
	uint8_t		prefix;		/* CIDR prefix len, 0=exact/any */
	uint8_t		addr[16];	/* IPv6 or v4-mapped, all-zero=any */
};

struct ort_vsock_claim {
	uint64_t	cid;		/* VSOCK_CID_ANY or a specific CID */
	uint32_t	port_min;
	uint32_t	port_max;
	uint8_t		direction;	/* ORT_NET_DIR_* */
};

static inline const char *
ort_net_domain_name(int domain)
{

	switch (domain) {
	case AF_INET:
		return ("inet");
	case AF_INET6:
		return ("inet6");
	case AF_BLUETOOTH:
		return ("bluetooth");
	default:
		return ("any");
	}
}

static inline const char *
ort_net_direction_name(int dir)
{

	switch (dir) {
	case ORT_NET_DIR_BIND:
		return ("bind");
	case ORT_NET_DIR_CONNECT:
		return ("connect");
	default:
		return ("any");
	}
}

static inline const char *
ort_net_protocol_name(int proto)
{

	switch (proto) {
	case IPPROTO_TCP:
		return ("tcp");
	case IPPROTO_UDP:
		return ("udp");
	case ORT_BTPROTO_HCI:
		return ("hci");
	case ORT_BTPROTO_L2CAP:
		return ("l2cap");
	case ORT_BTPROTO_RFCOMM:
		return ("rfcomm");
	case ORT_BTPROTO_SCO:
		return ("sco");
	case ORT_BTPROTO_ISO:
		return ("iso");
	default:
		return ("any");
	}
}

#endif /* !_ORACLERT_H_ */
