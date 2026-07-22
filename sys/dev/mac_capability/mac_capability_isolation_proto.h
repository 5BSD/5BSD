/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * mac_capability_isolation — wire protocol for the isolation service.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct MAC_CAPABILITY_CALL requests for the "isolation" service.
 *
 * PURPOSE
 *
 * Allow a supervisor (e.g. init) to fully isolate vnodes so that
 * only processes sharing the claimer's MAC_CAPABILITY nonce can interact
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
 *     to the target in the MAC_CAPABILITY_CALL message (cm_nfds=1).  The
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
 *     Check whether a vnode is currently isolated.  The caller must
 *     supply a valid FI_FS_* actions mask.  Returns the status in
 *     fi_reply.flags:
 *       FI_QF_CLAIMED  — vnode is isolated
 *       FI_QF_MINE     — isolated by the caller's nonce
 *
 * ACCESS TOKENS
 *
 *   FI_OP_MINT
 *     Create an access token fd for a specific claim.  The caller
 *     must supply a valid FI_FS_* actions mask to narrow the token.
 *     The token is returned as a reply fd.  Only the claim owner
 *     (same nonce) can mint tokens.  Pass the target vnode fd to
 *     identify which claim.  For network claims, use FI_OP_MINT_NET
 *     with the endpoint description in the payload.
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
 *   Claims are held by the MAC_CAPABILITY instance fd.  When the claimer's
 *   MAC_CAPABILITY connection closes (instance revoke), all claims owned by
 *   that instance are automatically released.  This prevents stale
 *   claims from orphaned supervisors.
 *
 *   If the claimer exec()s, its nonce rotates and it loses the
 *   ability to release via a new connection — but the original
 *   instance fd (if kept open across exec) still holds the claim
 *   until closed.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_ISOLATION_PROTO_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_ISOLATION_PROTO_H_

#include <sys/types.h>

/* --- Vnode operations (existing) --- */

#define	FI_OP_CLAIM		1	/* claim vnode (file or dir) */
#define	FI_OP_RELEASE		2	/* release vnode claim */
#define	FI_OP_QUERY		3	/* query vnode claim status */

/* --- Network operations (new) --- */

#define	FI_OP_CLAIM_NET		4	/* claim network endpoint */
#define	FI_OP_RELEASE_NET	5	/* release network claim */
#define	FI_OP_QUERY_NET		6	/* query network claim status */

/* --- Jail operations --- */

#define	FI_OP_CLAIM_JAIL	7	/* claim jail JID/name */
#define	FI_OP_RELEASE_JAIL	8	/* release jail claim */
#define	FI_OP_QUERY_JAIL	9	/* query jail claim status */

/* --- Access token operations --- */

#define	FI_OP_MINT		10	/* mint vnode access token (reply fd) */
#define	FI_OP_AUTHORIZE		11	/* activate token (add caller nonce) */
#define	FI_OP_MINT_NET		12	/* mint network access token (reply fd) */
#define	FI_OP_MINT_JAIL		13	/* mint jail access token (reply fd) */

/* --- vsock operations --- */

#define	FI_OP_CLAIM_VSOCK	14	/* claim vsock endpoint */
#define	FI_OP_RELEASE_VSOCK	15	/* release vsock claim */
#define	FI_OP_QUERY_VSOCK	16	/* query vsock claim status */
#define	FI_OP_MINT_VSOCK	17	/* mint vsock access token (reply fd) */

/* Query reply flags */
#define	FI_QF_CLAIMED		0x01	/* resource is isolated by someone */
#define	FI_QF_MINE		0x02	/* isolated by caller's nonce */
#define	FI_QF_AUTHORIZED	0x04	/* caller is authorized via token */

/*
 * Vnode request (ops 1-3, 10): pass target fd via req_fds[0].
 * For CLAIM and RELEASE the actions field is ignored.
 * For QUERY and MINT a valid FI_FS_* mask is required (0 → EINVAL).
 */
struct fi_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
	uint64_t	actions;	/* FI_FS_* mask */
} __packed;

struct fi_reply {
	uint32_t	flags;		/* FI_QF_* for QUERY; 0 otherwise */
	uint32_t	_pad;
} __packed;

/* Filesystem action flags for FI_OP_MINT / FI_OP_QUERY. */
#define	FI_FS_LOOKUP		0x0000000000000001ull
#define	FI_FS_STAT		0x0000000000000002ull
#define	FI_FS_READ		0x0000000000000004ull
#define	FI_FS_WRITE		0x0000000000000008ull
#define	FI_FS_APPEND		0x0000000000000010ull
#define	FI_FS_CREATE		0x0000000000000020ull
#define	FI_FS_DELETE		0x0000000000000040ull
#define	FI_FS_RENAME_FROM	0x0000000000000080ull
#define	FI_FS_RENAME_TO		0x0000000000000100ull
#define	FI_FS_LINK		0x0000000000000200ull
#define	FI_FS_EXEC		0x0000000000000400ull
#define	FI_FS_SETATTR		0x0000000000000800ull
#define	FI_FS_TRUNCATE		0x0000000000001000ull
#define	FI_FS_UIPC_CONNECT	0x0000000000002000ull

#define	FI_FS_ALL		(FI_FS_LOOKUP | FI_FS_STAT | FI_FS_READ | \
				    FI_FS_WRITE | FI_FS_APPEND | FI_FS_CREATE | \
				    FI_FS_DELETE | FI_FS_RENAME_FROM | \
				    FI_FS_RENAME_TO | FI_FS_LINK | FI_FS_EXEC | \
				    FI_FS_SETATTR | FI_FS_TRUNCATE | \
				    FI_FS_UIPC_CONNECT)

/* Network claim direction flags */
#define	FI_NET_BIND		0x01	/* gate bind() */
#define	FI_NET_CONNECT		0x02	/* gate connect() */
#define	FI_NET_ANY		0x03	/* bind + connect */
/* Note: listen is not separately enforced — bind is the gate.
 * socket create is enforced only for fully-wildcard (domain-wide) claims. */

/*
 * Network request (ops 4-6 and FI_OP_MINT_NET): no fd needed.
 * port_min/port_max are network byte order.  A full range of
 * 0..65535 means any port.  Domain/protocol 0 and an all-zero address
 * remain wildcards.
 *
 * Bluetooth (AF_BLUETOOTH):  domain=AF_BLUETOOTH, protocol is one of
 * BLUETOOTH_PROTO_L2CAP, BLUETOOTH_PROTO_RFCOMM, BLUETOOTH_PROTO_SCO,
 * or BLUETOOTH_PROTO_ISO (0=any).  addr[0..5] holds the BD_ADDR (6
 * bytes, all-zero=any).  port_min/port_max carry the PSM (L2CAP) or
 * channel (RFCOMM) in network byte order.  prefix must be 0 (any
 * address) or 48 (exact BD_ADDR match).
 */
struct fi_net_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
	int32_t		domain;		/* AF_INET, AF_INET6, AF_BLUETOOTH, 0=any */
	int32_t		protocol;	/* IPPROTO_TCP/UDP, BLUETOOTH_PROTO_*, 0=any */
	uint16_t	port_min;	/* network byte order */
	uint16_t	port_max;	/* network byte order */
	uint8_t		direction;	/* FI_NET_* bitmask */
	uint8_t		prefix;		/* CIDR/BD_ADDR prefix len, 0=exact/any */
	uint8_t		addr[16];	/* IPv6/v4-mapped/BD_ADDR, all-zero=any */
} __packed;

/* Jail action flags for FI_OP_MINT_JAIL. */
#define	FI_JAIL_CREATE		0x00000001u
#define	FI_JAIL_GET		0x00000002u
#define	FI_JAIL_SET		0x00000004u
#define	FI_JAIL_REMOVE		0x00000008u
#define	FI_JAIL_ATTACH		0x00000010u
#define	FI_JAIL_ALL		(FI_JAIL_CREATE | FI_JAIL_GET | \
				    FI_JAIL_SET | FI_JAIL_REMOVE | \
				    FI_JAIL_ATTACH)

/*
 * Jail request (ops 7-9 and FI_OP_MINT_JAIL): no fd needed.
 * jid == 0 means no JID key.  name[0] == '\0' means no name key.
 * Claim and mint requests must name at least one key.  A claim with
 * both keys protects either identifier for the same jail.
 */
struct fi_jail_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
	int32_t		jid;		/* host byte order; 0=not specified */
	uint32_t	actions;	/* FI_JAIL_* mask */
	char		name[64];	/* NUL-terminated jail name */
} __packed;

/*
 * vsock request (ops 14-17): no fd needed.
 * port_min/port_max are host byte order (32-bit vsock ports).
 * cid is the 32-bit VM context ID widened on the wire
 * (VSOCK_CID_ANY=any, else specific).  Values above UINT32_MAX are invalid.
 * Reuses FI_NET_BIND/FI_NET_CONNECT direction flags.
 * Socket type is intentionally not part of the key: claims cover both
 * SOCK_STREAM and SOCK_SEQPACKET endpoints.
 */
struct fi_vsock_request {
	uint32_t	op;
	uint32_t	flags;		/* reserved, must be 0 */
	uint64_t	cid;		/* VSOCK_CID_ANY or specific CID */
	uint32_t	port_min;	/* host byte order */
	uint32_t	port_max;	/* host byte order */
	uint8_t		direction;	/* FI_NET_* bitmask */
	uint8_t		_pad[3];
} __packed;

#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_ISOLATION_PROTO_H_ */
