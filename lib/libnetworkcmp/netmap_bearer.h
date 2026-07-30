/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _NETMAP_BEARER_H_
#define	_NETMAP_BEARER_H_

#include <net/if.h>
#include <stdint.h>

#define	NETMAP_BEARER_MAGIC	0x4e4d4252U	/* "NMBR" */
#define	NETMAP_BEARER_VERSION	1
#define	NETMAPD_PROVIDER	"org.5bsd.netmapd"
#define	NETMAP_BEARER_MAX_MESSAGE	4096
#define	NETMAP_BEARER_MSG_F_REPLY	0x00000001U

enum netmap_bearer_opcode {
	NETMAP_BEARER_OP_HELLO = 1,
	NETMAP_BEARER_OP_CREATE,
	NETMAP_BEARER_OP_DESTROY,
	NETMAP_BEARER_OP_GET_INFO,
	NETMAP_BEARER_OP_GET_STATS,
	NETMAP_BEARER_OP_REPLACE_POLICY
};

enum netmap_bearer_type {
	NETMAP_BEARER_VALE = 1,
	NETMAP_BEARER_PIPE,
	NETMAP_BEARER_HOST,
	NETMAP_BEARER_PHYSICAL_QUEUE
};

#define	NETMAP_BEARER_F_RX		0x00000001U
#define	NETMAP_BEARER_F_TX		0x00000002U
#define	NETMAP_BEARER_F_TRUSTED_PHYSICAL	0x80000000U

struct netmap_bearer_msg {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	opcode;
	uint32_t	flags;
	uint32_t	length;
	uint64_t	request_id;
	int32_t		status;
	uint32_t	reserved;
};

struct netmap_bearer_create {
	uint64_t	realm_id;
	uint64_t	policy_generation;
	uint32_t	type;
	uint32_t	queue_first;
	uint32_t	queue_count;
	uint32_t	slots;
	uint32_t	buffer_size;
	uint32_t	flags;
	char		interface[IFNAMSIZ];
};

struct netmap_bearer_reply {
	uint64_t	bearer_id;
	uint64_t	generation;
	uint64_t	mapping_offset;
	uint64_t	mapping_size;
	uint32_t	queue_count;
	uint32_t	slot_count;
	uint32_t	buffer_size;
	uint32_t	features;
	uint16_t	first_tx_ring;
	uint16_t	last_tx_ring;
	uint16_t	first_rx_ring;
	uint16_t	last_rx_ring;
	uint32_t	reserved;
};

/*
 * Minimum authoritative policy enforced below replaceable NetworkCmp
 * providers.  The first implementation may support only exact/range matches;
 * the ABI leaves room for an atomically replaced compiled flow table.
 */
struct netmap_bearer_flow {
	uint64_t	service_identity;
	uint32_t	direction;
	uint32_t	protocol;
	uint8_t		source[16];
	uint8_t		destination[16];
	uint8_t		source_prefix;
	uint8_t		destination_prefix;
	uint16_t	source_port_first;
	uint16_t	source_port_last;
	uint16_t	destination_port_first;
	uint16_t	destination_port_last;
	uint32_t	action;
	uint32_t	rate_limit;
};

#endif /* !_NETMAP_BEARER_H_ */
