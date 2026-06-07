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

#define	ORACLE_PROTO_VERSION_MAJOR	0
#define	ORACLE_PROTO_VERSION_MINOR	0
#define	ORACLE_PROTO_VERSION_PATCH	1
#define	ORACLE_PROTO_VERSION		1

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
#define	ORACLE_OP_MINT_FILE		8	/* mint narrowed file token */
#define	ORACLE_OP_MINT_JAIL		9	/* mint jail isolation token */

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
 * ORACLE_OP_MINT_FILE
 *   req:  oracle_mint_file_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = isolation token fd (on success)
 *
 * Requests a narrowed file isolation token.  oracled validates that
 * path is within its claimed set before minting and asks
 * cap_rt_isolation to constrain authorization to the given FI_FS_*
 * action mask.
 */
struct oracle_mint_file_req {
	uint32_t	op;		/* ORACLE_OP_MINT_FILE */
	uint32_t	_pad;
	uint64_t	actions;	/* FI_FS_* compatible mask */
	char		path[PATH_MAX];
};

/*
 * ORACLE_OP_MINT_NET
 *   req:  oracle_mint_net_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = network isolation token fd (on success)
 *
 * Mints a network isolation token for the requested endpoint or range.
 * oracled validates that the endpoint is covered by one of its claimed
 * network endpoints before minting.  Ports are in host byte order;
 * 0..65535 means any port.
 */
struct oracle_mint_net_req {
	uint32_t	op;		/* ORACLE_OP_MINT_NET */
	uint32_t	_pad;
	int32_t		domain;		/* AF_INET, AF_INET6, 0=any */
	int32_t		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port_min;	/* host byte order */
	uint16_t	port_max;	/* host byte order */
	uint8_t		direction;	/* FI_NET_* compatible bitmask */
	uint8_t		prefix;		/* CIDR prefix len, 0=exact/any */
	uint8_t		_reserved[2];
	uint8_t		addr[16];	/* IPv6 or v4-mapped, all-zero=any */
};

/*
 * ORACLE_OP_MINT_JAIL
 *   req:  oracle_mint_jail_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = jail isolation token fd (on success)
 *
 * Mints a jail isolation token for the requested JID/name and action
 * mask.  JID 0 means no JID key.  Empty name means no name key.
 */
struct oracle_mint_jail_req {
	uint32_t	op;		/* ORACLE_OP_MINT_JAIL */
	uint32_t	actions;	/* FI_JAIL_* compatible mask */
	int32_t		jid;		/* 0=not specified */
	uint32_t	_pad;
	char		name[64];	/* empty=not specified */
};

/*
 * ORACLE_OP_CREATE_JAIL
 *   req:  oracle_create_jail_req
 *   reply: oracle_reply { .status }
 *   reply_fds[0] = jail descriptor fd (on success)
 *
 * Creates a persist jail with the given name and path, returning a
 * jail descriptor fd.  oracled validates that the jail name is within
 * its claimed set before creating.  The jail is created by oracled
 * (which holds the cap_rt claim) and the descriptor is passed to
 * serviced for jail_attach_jd / jail_remove_jd.
 */
#define	ORACLE_OP_CREATE_JAIL		10

/*
 * Dynamic claim/release operations.
 *
 * These allow serviced to dynamically extend the oracle's claimed
 * resource set at runtime.  The oracle maintains a global reference
 * count per dynamic claim.  Manifest claims (CLAIM_SOURCE_POLICY)
 * are immortal and cannot be released via this channel.
 *
 * Request structs are shared with the corresponding MINT operations
 * (same payload, different op).  Claims return oracle_reply with no
 * attached fds.  Releases return oracle_reply with no attached fds.
 *
 * Mint handlers (MINT_PATH, MINT_NET, etc.) implicitly auto-claim
 * resources not already in the oracle's claimed set.  Services do
 * not need to send explicit CLAIM before MINT — the oracle handles
 * it in one trip.  The refcount is bumped on each mint/claim, even
 * for resources already claimed dynamically.
 *
 * Error returns:
 *   CLAIM:   ENOSPC (array full), EIO (kernel claim failed)
 *   RELEASE: ENOENT (not found), EPERM (manifest/internal claim)
 */
#define	ORACLE_OP_CLAIM_PATH		11	/* dynamically claim a path */
#define	ORACLE_OP_CLAIM_NET		12	/* dynamically claim a network endpoint */
#define	ORACLE_OP_CLAIM_JAIL		13	/* dynamically claim a jail */
#define	ORACLE_OP_CLAIM_SYSTEM		14	/* dynamically claim system gates */
#define	ORACLE_OP_RELEASE_PATH		15	/* release a dynamic path claim */
#define	ORACLE_OP_RELEASE_NET		16	/* release a dynamic network claim */
#define	ORACLE_OP_RELEASE_JAIL		17	/* release a dynamic jail claim */
#define	ORACLE_OP_RELEASE_SYSTEM	18	/* release dynamic system gates */

struct oracle_create_jail_req {
	uint32_t	op;		/* ORACLE_OP_CREATE_JAIL */
	uint32_t	_pad;
	char		name[64];	/* jail name (required) */
	char		path[PATH_MAX];	/* jail root path (required) */
	char		hostname[64];	/* host.hostname (empty=use name) */
	char		ip4_addr[64];	/* ip4.addr (empty=inherit) */
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

/*
 * Safe snprintf accumulator.  Appends formatted text to buf at
 * offset *offp, clamping to prevent overflow.
 *
 * Shared between oracled and serviced for status formatting.
 */
#ifndef BUF_APPEND
#define	BUF_APPEND(buf, bufsz, offp, ...)	do {			\
	size_t _rem = (*(offp) < (bufsz)) ? (bufsz) - *(offp) : 0;	\
	int _n = snprintf((buf) + *(offp), _rem, __VA_ARGS__);		\
	if (_n > 0) *(offp) += (size_t)_n;				\
	if (*(offp) >= (bufsz)) *(offp) = (bufsz) - 1;			\
} while (0)
#endif /* BUF_APPEND */

#endif /* ORACLED_SVC_PROTO_H */
