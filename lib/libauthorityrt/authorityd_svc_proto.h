/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityd service manager channel protocol.
 *
 * Shared between authorityd(8) and serviced(8).  Messages are exchanged
 * over a restricted mac_capability channel using MAC_CAPABILITY_SENDMSG/MAC_CAPABILITY_RECVMSG
 * with reply_token correlation.
 *
 * serviced inherits one end of the channel as fd 3 (AUTHORITYD_CHANNEL_FD).
 * authorityd holds the other end and dispatches requests from its event
 * loop.  All requests are initiated by serviced; authorityd only replies.
 *
 * File descriptors (activation tokens, channels, coalitions, and named
 * capability-service instances) are returned as attached fds in the SENDMSG
 * reply, not as integers in the payload.
 */

#ifndef AUTHORITYD_SVC_PROTO_H
#define AUTHORITYD_SVC_PROTO_H

#include <sys/types.h>
#include <sys/param.h>		/* PATH_MAX */

#define	AUTHORITY_PROTO_VERSION_MAJOR	0
#define	AUTHORITY_PROTO_VERSION_MINOR	0
#define	AUTHORITY_PROTO_VERSION_PATCH	3
#define	AUTHORITY_PROTO_VERSION		1

/*
 * Operation codes — first 4 bytes of every request payload.
 */
/* Opcode 1 (MINT_PATH) is retired: tzfsd(8) brokers filesystem paths and
 * hands rights-limited fds directly; authorityd mints no path tokens. */
#define	AUTHORITY_OP_MINT_NET		2	/* mint network isolation token */
#define	AUTHORITY_OP_MINT_SYSTEM		3	/* mint system gate token */
#define	AUTHORITY_OP_CREATE_CHANNEL	4	/* create a new channel */
#define	AUTHORITY_OP_CREATE_COALITION	5	/* create a new coalition */
#define	AUTHORITY_OP_READY			6	/* serviced initialization complete */
#define	AUTHORITY_OP_PING			7	/* liveness check */
/* Opcode 8 (MINT_FILE) is retired: file access is tzfsd(8) self-service via
 * service_open_isolated(3); serviced no longer mints file tokens. */
/* Opcode 9 (MINT_JAIL) is retired: warden(8) owns jail self-service. */
#define	AUTHORITY_OP_MINT_VSOCK		19	/* mint VSOCK isolation token */
/* 24, 25 retired: storage moved to serviced<->tzfsd direct (was MINT/DESTROY_STORAGE) */
#define	AUTHORITY_OP_SET_AMBIENT_LOOKUP	26	/* install ambient lookup fd in capsule */
#define	AUTHORITY_OP_LIFECYCLE		27	/* apply a system lifecycle transition (P4b) */
#define	AUTHORITY_OP_RELOAD		28	/* reload authority config claims (P4b) */

/*
 * AUTHORITY_OP_RELOAD (docs/lifecycle-capability-design.md, P4b): the reloadable
 * half of the authorityd control surface, re-homed onto the authority channel so
 * authorityctl(8) reaches it through serviced's ADMIN-gated system.lifecycle
 * capability and the getpeereid socket can be deleted.  Status-only:
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_RELOAD }
 *   reply: authority_reply { .status }
 * (authorityctl's `status` is synthesized by serviced from the authority
 * reachability/readiness it already tracks, so it needs no channel op.)
 */

/*
 * AUTHORITY_OP_LIFECYCLE
 *   req:  authority_lifecycle_req
 *   reply: authority_reply { .status }  (0 = accepted; the transition runs
 *          after the reply is queued, so the caller's ack precedes the death
 *          sweep — same ordering as the legacy control-socket path)
 *
 * serviced relays a lifecycle request it received over its ADMIN-gated
 * system.lifecycle capability (docs/lifecycle-capability-design.md, P4b).
 * authorityd, which is PID 1, translates lifecycle_op into a state transition
 * via oi_lifecycle_apply() exactly as the control-socket path does.  lifecycle_op
 * is a CTL_OP_* lifecycle opcode (authorityd_ctl.h): REBOOT/HALT/POWEROFF/
 * POWERCYCLE/SINGLE/REROOT/RESCAN/CATATONIA.
 */
struct authority_lifecycle_req {
	uint32_t	op;		/* AUTHORITY_OP_LIFECYCLE */
	uint32_t	lifecycle_op;	/* CTL_OP_* lifecycle opcode */
};

/*
 * Common request header — used for operations with no extra parameters
 * (CREATE_CHANNEL, CREATE_COALITION, READY, PING).
 */
struct authority_req_hdr {
	uint32_t	op;
};

/*
 * Path isolation tokens are NOT an authorityd op.  tzfsd(8) brokers filesystem
 * paths end to end: service_open_isolated(3) opens the path and hands back a
 * rights-limited fd, so nothing mints isolation PATH tokens from authorityd.
 * Opcodes 1 (MINT_PATH), 11 (CLAIM_PATH), and 15 (RELEASE_PATH), and the
 * former struct authority_path_req, are retired.
 */

/*
 * AUTHORITY_OP_MINT_NET
 *   req:  authority_net_req
 *   reply: authority_reply { .status }
 *   reply_fds[0] = network isolation token fd (on success)
 *
 * Mints a network isolation token for the requested endpoint or range.
 * authorityd ensures the endpoint is held (creating a reference-counted service
 * claim when necessary) before minting.  Ports are in host byte order;
 * 0..65535 means any port.
 */
struct authority_net_req {
	uint32_t	op;		/* AUTHORITY_OP_MINT_NET / CLAIM / RELEASE */
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
 * Jail delegation is NOT an authorityd op.  warden(8) owns jails end to end:
 * a consumer self-attaches via libservice service_enter_namespace(3), scoped by
 * an unforgeable label, and warden does the jail_set(2)/jail_attach(2).  PID 1
 * neither claims jail names nor mints jail tokens.  Opcodes 9 (MINT_JAIL),
 * 10 (CREATE_JAIL), 13 (CLAIM_JAIL), and 17 (RELEASE_JAIL) are retired.
 */

/*
 * Dynamic claim/release operations.
 *
 * These allow serviced to dynamically extend the authority's claimed
 * resource set at runtime.  The authority maintains a global reference
 * count per dynamic claim.  Manifest claims (CLAIM_SOURCE_POLICY)
 * are immortal and cannot be released via this channel.
 *
 * Request structs are shared with the corresponding MINT operations
 * (same payload, different op).  Claims return authority_reply with no
 * attached fds.  Releases return authority_reply with no attached fds.
 *
 * Mint handlers (MINT_NET, MINT_VSOCK, MINT_SYSTEM) implicitly auto-claim
 * resources not already in the authority's claimed set.  Services do
 * not need to send explicit CLAIM before MINT — the authority handles
 * it in one trip.  The refcount is bumped on each mint/claim, even
 * for resources already claimed dynamically.
 *
 * Error returns:
 *   CLAIM:   ENOSPC (array full), EIO (kernel claim failed)
 *   RELEASE: ENOENT (not found), EPERM (manifest/internal claim)
 */
/* Opcode 11 (CLAIM_PATH) is retired: tzfsd(8) brokers filesystem paths. */
#define	AUTHORITY_OP_CLAIM_NET		12	/* dynamically claim a network endpoint */
/* Opcode 13 (CLAIM_JAIL) is retired: warden(8) owns jail self-service. */
#define	AUTHORITY_OP_CLAIM_SYSTEM		14	/* dynamically claim system gates */
/* Opcode 15 (RELEASE_PATH) is retired: tzfsd(8) brokers filesystem paths. */
#define	AUTHORITY_OP_RELEASE_NET		16	/* release a dynamic network claim */
/* Opcode 17 (RELEASE_JAIL) is retired: warden(8) owns jail self-service. */
#define	AUTHORITY_OP_RELEASE_SYSTEM	18	/* release dynamic system gates */
#define	AUTHORITY_OP_CLAIM_VSOCK		20
#define	AUTHORITY_OP_RELEASE_VSOCK	21
/* Opcode 22 (ENSURE_KMOD) is retired: sysextd(8) owns kernel-module loading. */
#define	AUTHORITY_OP_DELEGATE_SERVICE	23	/* delegate named service fd */

struct authority_vsock_req {
	uint32_t	op;
	uint32_t	_pad;
	uint64_t	cid;
	uint32_t	port_min;
	uint32_t	port_max;
	uint8_t		direction;
	uint8_t		_reserved[7];
};

/*
 * Storage is NOT an authorityd op.  tzfsd(8) owns storage; serviced talks to
 * tzfsd directly (see usr.sbin/serviced/storage_client.c).  Storage never
 * transits the init process.  Opcodes 24/25 are retired and left unused.
 */

/*
 * Kernel-module loading is NOT an authorityd op.  sysextd(8) owns it: it holds
 * the kldload system-capability gate and exposes system.SystemExtension
 * as a socket-free provider, so a service self-serves a module by name via
 * service_ensure_extension(3).  PID 1 no longer loads kernel code.
 */

#define	AUTHORITY_SERVICE_NAME_MAX	16
struct authority_service_req {
	uint32_t	op;
	uint32_t	_pad;
	char		name[AUTHORITY_SERVICE_NAME_MAX];
};

/*
 * AUTHORITY_OP_MINT_SYSTEM
 *   req:  authority_system_req
 *   reply: authority_reply { .status }
 *   reply_fds[0] = system gate token fd (on success)
 *
 * Mints a system gate token.  authorityd dynamically claims gates not already
 * held and reference-counts service ownership before minting.
 */
struct authority_system_req {
	uint32_t	op;		/* AUTHORITY_OP_MINT_SYSTEM / CLAIM / RELEASE */
	uint32_t	gates;		/* SYS_GATE_* bitmask */
};

/*
 * AUTHORITY_OP_CREATE_CHANNEL
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_CREATE_CHANNEL }
 *   reply: authority_reply { .status }
 *   reply_fds[0] = endpoint A, reply_fds[1] = endpoint B
 *
 * Creates a new restricted channel for serviced to pass to a
 * launched service.  serviced keeps one end, gives the other
 * to the child via pdfork.
 */

/*
 * AUTHORITY_OP_CREATE_COALITION
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_CREATE_COALITION }
 *   reply: authority_reply { .status }
 *   reply_fds[0] = coalition instance fd
 *
 * Creates a new coalition for process group management.
 */

/*
 * AUTHORITY_OP_READY
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_READY }
 *   reply: authority_reply { .status = 0 }
 *
 * Sent by serviced only after inherited descriptors are irreversibly
 * confined and its capprotect shield is active.  Receipt therefore means
 * "protected and operational", not merely that exec succeeded.
 * authorityd logs the transition and may gate status reporting.
 */

/*
 * AUTHORITY_OP_PING
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_PING }
 *   reply: authority_reply { .status = 0 }
 *
 * Liveness request sent by serviced; authorityd replies.
 */

/*
 * AUTHORITY_OP_SET_AMBIENT_LOOKUP
 *   req:  authority_req_hdr { .op = AUTHORITY_OP_SET_AMBIENT_LOOKUP }
 *   req_fds[0] = ambient lookup channel client end (SCM_RIGHTS)
 *   reply: authority_reply { .status }
 *
 * serviced sends a dup of its retained SYSTEM ambient lookup channel client end
 * so capsule (PID 1) can carry it into interactive logins.  capsule is
 * the parent of the getty/login sessions spawned from /etc/ttys; those are
 * siblings of /etc/rc and never inherit serviced's SERVICE_LOOKUP_FD
 * environment.  capsule stores the fd, makes it fork/exec-durable, and
 * dup2()s it to SERVICE_LOOKUP_FIXED_FD just before exec'ing each getty so
 * login inherits the discovery channel at the fixed number.
 *
 * Strictly best-effort: the rc path already carries the channel by environment
 * inheritance, so any failure here (send, receive, or install) is logged and
 * ignored on both ends and never disrupts boot, the authority event loop, or a
 * login.  The reply is status-only with no attached fds.
 */

/*
 * Generic reply — returned for all operations.
 * Status is 0 on success, errno on failure.
 * File descriptors (if any) are attached to the reply message.
 */
struct authority_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

/*
 * Maximum number of reply fds per operation.
 * CREATE_CHANNEL returns 2, everything else returns 0 or 1.
 */
#define	AUTHORITY_MAX_REPLY_FDS	2

/*
 * Safe snprintf accumulator.  Appends formatted text to buf at
 * offset *offp, clamping to prevent overflow.
 *
 * Shared between authorityd and serviced for status formatting.
 */
#ifndef BUF_APPEND
#define	BUF_APPEND(buf, bufsz, offp, ...)	do {			\
	size_t _rem = (*(offp) < (bufsz)) ? (bufsz) - *(offp) : 0;	\
	int _n = snprintf((buf) + *(offp), _rem, __VA_ARGS__);		\
	if (_n > 0) *(offp) += (size_t)_n;				\
	if (*(offp) >= (bufsz)) *(offp) = (bufsz) - 1;			\
} while (0)
#endif /* BUF_APPEND */

#endif /* AUTHORITYD_SVC_PROTO_H */
