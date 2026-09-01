/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libauthorityrt — shared types, constants, and helpers for the authority
 * MAC capability.  Used by authorityd, serviced, libcapbundle, and
 * client tools.
 */

#ifndef _AUTHORITYRT_H_
#define	_AUTHORITYRT_H_

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
 * Canonical network claim descriptor.  Used by authorityd configuration,
 * serviced manifests, and the authority IPC protocol.  Field layout
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

/*
 * TrustedZFS storage claim: storage the service is granted a capability
 * handle to, obtained from tzfsd(8) under /Capabilities.  name is the logical
 * descriptor role visible to the service.  dataset is an opaque, stable key
 * derived from the bundle identity and storage scope; it is the only value
 * sent to the storage authority.  rights is a ZH_* mask (see
 * <sys/zfshandle.h>); lifetime is the storage lifecycle.  POD, embedded by
 * value like the other claim arrays.
 */
#define	ORT_STORAGE_NAME_MAX	64	/* == TZFSD_NAME_MAX */
#define	ORT_STORAGE_DATASET_MAX	64	/* opaque ZFS leaf key */
#define	ORT_STORAGE_PERSISTENT	0
#define	ORT_STORAGE_CACHE	1
#define	ORT_STORAGE_BOOT	2
#define	ORT_STORAGE_LEASE	3
#define	ORT_STORAGE_SCOPE_UNIT	0
#define	ORT_STORAGE_SCOPE_SHARED	1

struct ort_storage_claim {
	char		name[ORT_STORAGE_NAME_MAX];
	char		dataset[ORT_STORAGE_DATASET_MAX];
	uint64_t	rights;		/* ZH_* mask */
	uint8_t		lifetime;	/* ORT_STORAGE_* */
	uint8_t		scope;		/* ORT_STORAGE_SCOPE_* */
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

#endif /* !_AUTHORITYRT_H_ */
