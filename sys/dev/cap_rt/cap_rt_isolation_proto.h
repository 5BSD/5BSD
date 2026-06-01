/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_isolation — wire protocol for the isolation service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CAP_RT_CALL requests for the "isolation" service.
 *
 * PURPOSE
 *
 * Allow a supervisor (e.g. init) to fully isolate vnodes so that
 * only processes sharing the claimer's CAP_RT nonce can interact
 * with them.  Isolated vnodes are protected against:
 *
 *   - open / exec                (content access)
 *   - unlink / link / rename     (namespace mutation)
 *   - chmod / chown / chflags / utimes / truncate (metadata mutation)
 *   - stat / access / readlink   (information disclosure)
 *   - connect (AF_UNIX)          (socket access)
 *
 * The claimer may still dup/pass an already-open fd to other
 * processes; only new vnode operations are gated.
 *
 * Isolation works for any vnode type: device nodes (character and
 * block), regular files, FIFOs, and Unix domain sockets (connect
 * is gated; bind creates a new vnode so cannot be gated).  Claims
 * are keyed by vnode identity (held via vref), not by pathname or
 * dev_t.
 *
 * OPERATIONS
 *
 *   FI_OP_CLAIM
 *     Claim isolation over a vnode.  The caller passes an open fd
 *     to the target in the CAP_RT_CALL message (cm_nfds=1).  The
 *     service identifies the vnode from the fd internally.
 *     The caller's nonce becomes the owner.  Fails with EBUSY if
 *     already claimed by a different nonce.  Re-claiming the same
 *     vnode from the same nonce transfers ownership to the calling
 *     instance (the claim's lifetime tracks the most recent claimer).
 *
 *   FI_OP_RELEASE
 *     Release a previously isolated vnode.  Only the owning nonce
 *     may release.  Passes any fd referring to the same vnode to
 *     identify the target.
 *
 *   FI_OP_QUERY
 *     Check whether a vnode is currently isolated.  Returns the
 *     status in fi_reply.flags:
 *       FI_QF_CLAIMED  — vnode is isolated
 *       FI_QF_MINE     — isolated by the caller's nonce
 *
 * ACCESS TOKENS
 *
 *   FI_OP_MINT
 *     Create an access token fd for a specific claim.  The token
 *     is returned as a reply fd.  Only the claim owner (same nonce)
 *     can mint tokens.  Pass the target vnode fd to identify which
 *     claim.  For network claims, use FI_OP_MINT_NET with the
 *     endpoint description in the payload.
 *
 *   FI_OP_AUTHORIZE
 *     Called on a token fd by the process that received it.  Adds
 *     the caller's nonce to the claim's authorized set.  The
 *     authorization persists as long as the token fd is open.
 *     Closing the token fd revokes the authorization.
 *
 * ENFORCEMENT
 *
 *   The service registers MACF hooks for all vnode check operations
 *   listed above.  Each hook looks up the vnode in the isolation
 *   table:
 *     - No entry          → allow (default-open)
 *     - Entry, nonce match → allow
 *     - Entry, authorized nonce → allow
 *     - Entry, nonce mismatch and not authorized → EACCES
 *
 * LIFECYCLE
 *
 *   Claims are held by the CAP_RT instance fd.  When the claimer's
 *   CAP_RT connection closes (instance revoke), all claims owned by
 *   that instance are automatically released.  This prevents stale
 *   claims from orphaned supervisors.
 *
 *   If the claimer exec()s, its nonce rotates and it loses the
 *   ability to release via a new connection — but the original
 *   instance fd (if kept open across exec) still holds the claim
 *   until closed.
 */

#ifndef _DEV_CAP_RT_CAP_RT_ISOLATION_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_ISOLATION_PROTO_H_

#include <sys/types.h>

/* --- Vnode operations (existing) --- */

#define	FI_OP_CLAIM		1	/* claim vnode (file or dir) */
#define	FI_OP_RELEASE		2	/* release vnode claim */
#define	FI_OP_QUERY		3	/* query vnode claim status */

/* --- Network operations (new) --- */

#define	FI_OP_CLAIM_NET		4	/* claim network endpoint */
#define	FI_OP_RELEASE_NET	5	/* release network claim */
/* FI_OP_QUERY_NET (6) reserved — not yet implemented */

/* --- Access token operations --- */

#define	FI_OP_MINT		10	/* mint vnode access token (reply fd) */
#define	FI_OP_AUTHORIZE		11	/* activate token (add caller nonce) */
#define	FI_OP_MINT_NET		12	/* mint network access token (reply fd) */

/* Query reply flags */
#define	FI_QF_CLAIMED		0x01	/* resource is isolated by someone */
#define	FI_QF_MINE		0x02	/* isolated by caller's nonce */
#define	FI_QF_AUTHORIZED	0x04	/* caller is authorized via token */

/* Vnode request (ops 1-3): pass target fd via req_fds[0] */
struct fi_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
} __packed;

struct fi_reply {
	uint32_t	flags;		/* FI_QF_* for QUERY; 0 otherwise */
	uint32_t	_pad;
} __packed;

/* Network claim direction flags */
#define	FI_NET_BIND		0x01	/* gate bind() */
#define	FI_NET_CONNECT		0x02	/* gate connect() */
#define	FI_NET_ANY		0x03	/* bind + connect */
/* Note: listen is not separately enforced — bind is the gate.
 * socket create is enforced only for fully-wildcard (domain-wide) claims. */

/*
 * Network request (ops 4-6 and FI_OP_MINT_NET): no fd needed, endpoint
 * in payload.
 * Fields set to 0 match any value (wildcards).
 */
struct fi_net_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
	int32_t		domain;		/* AF_INET, AF_INET6, 0=any */
	int32_t		protocol;	/* IPPROTO_TCP, IPPROTO_UDP, 0=any */
	uint16_t	port;		/* network byte order, 0=any */
	uint8_t		direction;	/* FI_NET_* bitmask */
	uint8_t		prefix;		/* CIDR prefix len, 0=exact/any */
	uint8_t		addr[16];	/* IPv6 or v4-mapped, all-zero=any */
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_ISOLATION_PROTO_H_ */
