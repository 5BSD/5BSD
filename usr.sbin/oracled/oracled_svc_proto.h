/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled service manager pair channel protocol.
 *
 * Shared between oracled(8) and serviced(8).  Messages are exchanged
 * over a cap_rt NOXFER pair channel using CAP_RT_SENDMSG/CAP_RT_RECVMSG
 * with reply_token correlation.
 *
 * serviced inherits one end of the pair as fd 3 (ORACLED_PAIR_FD).
 * oracled holds the other end and dispatches requests from its event
 * loop.  All requests are initiated by serviced; oracled only replies.
 *
 * File descriptors (tokens, pairs, coalitions) are returned as
 * attached fds in the SENDMSG reply, not as integers in the payload.
 */

#ifndef ORACLED_SVC_PROTO_H
#define ORACLED_SVC_PROTO_H

#include <sys/types.h>
#include <sys/param.h>		/* PATH_MAX */

#define	ORACLE_PROTO_VERSION	1

/*
 * Operation codes — first 4 bytes of every request payload.
 */
#define	ORACLE_OP_MINT_PATH		1	/* mint path isolation token */
#define	ORACLE_OP_MINT_NET		2	/* mint network isolation token */
#define	ORACLE_OP_MINT_SYSTEM		3	/* mint system gate token */
#define	ORACLE_OP_CREATE_PAIR		4	/* create a new pair channel */
#define	ORACLE_OP_CREATE_COALITION	5	/* create a new coalition */
#define	ORACLE_OP_READY			6	/* serviced initialization complete */
#define	ORACLE_OP_PING			7	/* liveness check */

/*
 * Common request header — used for operations with no extra parameters
 * (CREATE_PAIR, CREATE_COALITION, READY, PING).
 */
struct oracle_req_hdr {
	uint32_t	op;
};

/*
 * ORACLE_OP_MINT_PATH
 *   req:  oracle_mint_path_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = isolation token fd (on success)
 *
 * Requests a path isolation token.  oracled validates that path
 * is within its claimed set before minting.
 */
struct oracle_mint_path_req {
	uint32_t	op;		/* ORACLE_OP_MINT_PATH */
	uint32_t	_pad;
	char		path[PATH_MAX];
};

/*
 * ORACLE_OP_MINT_NET
 *   req:  oracle_mint_net_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = network isolation token fd (on success)
 *
 * Mints a network isolation token for the requested endpoint.  oracled
 * validates that the endpoint is covered by one of its claimed network
 * endpoints before minting.
 */
struct oracle_mint_net_req {
	uint32_t	op;		/* ORACLE_OP_MINT_NET */
	uint32_t	_pad;
	int32_t		domain;		/* AF_INET, AF_INET6, 0=any */
	int32_t		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port;		/* host byte order, 0=any */
	uint8_t		direction;	/* FI_NET_* compatible bitmask */
	uint8_t		_reserved[5];
};

/*
 * ORACLE_OP_MINT_SYSTEM
 *   req:  oracle_mint_system_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = system gate token fd (on success)
 *
 * Mints a system gate token.  oracled validates that gates is a
 * subset of its claimed gates before minting.
 */
struct oracle_mint_system_req {
	uint32_t	op;		/* ORACLE_OP_MINT_SYSTEM */
	uint32_t	gates;		/* SYS_GATE_* bitmask */
};

/*
 * ORACLE_OP_CREATE_PAIR
 *   req:  oracle_req_hdr { .op = ORACLE_OP_CREATE_PAIR }
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = endpoint A, reply_fds[1] = endpoint B
 *
 * Creates a new NOXFER pair channel for serviced to pass to a
 * launched service.  serviced keeps one end, gives the other
 * to the child via pdfork.
 */

/*
 * ORACLE_OP_CREATE_COALITION
 *   req:  oracle_req_hdr { .op = ORACLE_OP_CREATE_COALITION }
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = coalition instance fd
 *
 * Creates a new coalition for process group management.
 */

/*
 * ORACLE_OP_READY
 *   req:  oracle_req_hdr { .op = ORACLE_OP_READY }
 *   reply: oracle_reply { .status = 0 }
 *
 * Sent by serviced after initialization is complete.
 * oracled logs the transition and may gate status reporting.
 */

/*
 * ORACLE_OP_PING
 *   req:  oracle_req_hdr { .op = ORACLE_OP_PING }
 *   reply: oracle_reply { .status = 0 }
 *
 * Liveness check.  Either side may send.
 */

/*
 * Generic reply — returned for all operations.
 * Status is 0 on success, errno on failure.
 * File descriptors (if any) are attached to the reply message.
 */
struct oracle_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

/*
 * Maximum number of reply fds per operation.
 * CREATE_PAIR returns 2, everything else returns 0 or 1.
 */
#define	ORACLE_MAX_REPLY_FDS	2

#endif /* ORACLED_SVC_PROTO_H */
