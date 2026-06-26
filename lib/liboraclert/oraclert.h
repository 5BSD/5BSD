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

#include <netinet/in.h>

#include <stdint.h>

/* Network claim direction flags (match mac_capability_isolation_proto.h). */
#define	ORT_NET_DIR_BIND	0x01
#define	ORT_NET_DIR_CONNECT	0x02
#define	ORT_NET_DIR_ANY		0x03

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
	default:
		return ("any");
	}
}

#endif /* !_ORACLERT_H_ */
