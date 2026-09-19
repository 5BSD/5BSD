/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * capsule service manager channel protocol.
 *
 * Shared between capsule(8) and switchboard(8).  Messages are exchanged
 * over a restricted mac_capability channel using MAC_CAPABILITY_SENDMSG/MAC_CAPABILITY_RECVMSG
 * with reply_token correlation.
 *
 * switchboard inherits one end of the channel as fd 3 (CAPSULE_CHANNEL_FD).
 * capsule holds the other end and dispatches requests from its event
 * loop.  All requests are initiated by switchboard; capsule only replies.
 *
 * File descriptors (activation tokens, channels, coalitions, and named
 * capability-service instances) are returned as attached fds in the SENDMSG
 * reply, not as integers in the payload.
 */

#ifndef CAPSULE_SVC_PROTO_H
#define CAPSULE_SVC_PROTO_H

#include <sys/types.h>
#include <sys/param.h>		/* PATH_MAX */

#define	CAPSULE_PROTO_VERSION_MAJOR	0
#define	CAPSULE_PROTO_VERSION_MINOR	0
#define	CAPSULE_PROTO_VERSION_PATCH	3
#define	CAPSULE_PROTO_VERSION		1

/*
 * Operation codes — first 4 bytes of every request payload.
 */
/* Opcode 1 (MINT_PATH) is retired: bsdfilesystem(8) brokers filesystem paths and
 * hands rights-limited fds directly; capsule mints no path tokens. */
#define	CAPSULE_OP_MINT_NET		2	/* mint network isolation token */
#define	CAPSULE_OP_MINT_SYSTEM		3	/* mint system gate token */
#define	CAPSULE_OP_CREATE_CHANNEL	4	/* create a new channel */
#define	CAPSULE_OP_CREATE_COALITION	5	/* create a new coalition */
#define	CAPSULE_OP_READY			6	/* switchboard initialization complete */
#define	CAPSULE_OP_PING			7	/* liveness check */
/* Opcode 8 (MINT_FILE) is retired: file access is bsdfilesystem(8) self-service via
 * service_open_isolated(3); switchboard no longer mints file tokens. */
/* Opcode 9 (MINT_JAIL) is retired: bsdnamespace(8) owns jail self-service. */
#define	CAPSULE_OP_MINT_VSOCK		19	/* mint VSOCK isolation token */
/* 24, 25 retired: storage moved to switchboard<->bsdfilesystem direct (was MINT/DESTROY_STORAGE) */
#define	CAPSULE_OP_SET_AMBIENT_LOOKUP	26	/* install ambient lookup fd in capsule */
#define	CAPSULE_OP_LIFECYCLE		27	/* apply a system lifecycle transition (P4b) */
#define	CAPSULE_OP_RELOAD		28	/* reload Capsule configuration claims (P4b) */

/*
 * CAPSULE_OP_RELOAD (docs/lifecycle-capability-design.md, P4b): the reloadable
 * half of the capsule control surface, re-homed onto the Capsule channel so
 * capsulectl(8) reaches it through switchboard's ADMIN-gated system.lifecycle
 * capability and the getpeereid socket can be deleted.  Status-only:
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_RELOAD }
 *   reply: capsule_reply { .status }
 * (capsulectl's `status` is synthesized by switchboard from Capsule
 * reachability/readiness it already tracks, so it needs no channel op.)
 */

/*
 * CAPSULE_OP_LIFECYCLE
 *   req:  capsule_lifecycle_req
 *   reply: capsule_reply { .status }  (0 = accepted; the transition runs
 *          after the reply is queued, so the caller's ack precedes the death
 *          sweep — same ordering as the legacy control-socket path)
 *
 * switchboard relays a lifecycle request it received over its ADMIN-gated
 * system.lifecycle capability (docs/lifecycle-capability-design.md, P4b).
 * Capsule, which is PID 1, translates lifecycle_op into a state transition
 * via oi_lifecycle_apply() exactly as the control-socket path does.  lifecycle_op
 * is a CTL_OP_* lifecycle opcode (capsule_ctl.h): REBOOT/HALT/POWEROFF/
 * POWERCYCLE/SINGLE/REROOT/RESCAN/CATATONIA.
 */
struct capsule_lifecycle_req {
	uint32_t	op;		/* CAPSULE_OP_LIFECYCLE */
	uint32_t	lifecycle_op;	/* CTL_OP_* lifecycle opcode */
};

/*
 * Common request header — used for operations with no extra parameters
 * (CREATE_CHANNEL, CREATE_COALITION, READY, PING).
 */
struct capsule_req_hdr {
	uint32_t	op;
};

/*
 * Path isolation tokens are NOT a Capsule operation.  bsdfilesystem(8) brokers filesystem
 * paths end to end: service_open_isolated(3) opens the path and hands back a
 * rights-limited fd, so nothing mints isolation PATH tokens from Capsule.
 * Opcodes 1 (MINT_PATH), 11 (CLAIM_PATH), and 15 (RELEASE_PATH), and the
 * former struct capsule_path_req, are retired.
 */

/*
 * CAPSULE_OP_MINT_NET
 *   req:  capsule_net_req
 *   reply: capsule_reply { .status }
 *   reply_fds[0] = network isolation token fd (on success)
 *
 * Mints a network isolation token for the requested endpoint or range.
 * Capsule ensures the endpoint is held (creating a reference-counted service
 * claim when necessary) before minting.  Ports are in host byte order;
 * 0..65535 means any port.
 */
struct capsule_net_req {
	uint32_t	op;		/* CAPSULE_OP_MINT_NET / CLAIM / RELEASE */
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
 * Jail delegation is NOT a Capsule operation.  bsdnamespace(8) owns jails end to end:
 * a consumer self-attaches via libservice service_enter_namespace(3), scoped by
 * an unforgeable label, and bsdnamespace does the jail_set(2)/jail_attach(2).  PID 1
 * neither claims jail names nor mints jail tokens.  Opcodes 9 (MINT_JAIL),
 * 10 (CREATE_JAIL), 13 (CLAIM_JAIL), and 17 (RELEASE_JAIL) are retired.
 */

/*
 * Dynamic claim/release operations.
 *
 * These allow switchboard to dynamically extend Capsule's claimed
 * resource set at runtime.  Capsule maintains a global reference
 * count per dynamic claim.  Manifest claims (CLAIM_SOURCE_POLICY)
 * are immortal and cannot be released via this channel.
 *
 * Request structs are shared with the corresponding MINT operations
 * (same payload, different op).  Claims return capsule_reply with no
 * attached fds.  Releases return capsule_reply with no attached fds.
 *
 * Mint handlers (MINT_NET, MINT_VSOCK, MINT_SYSTEM) implicitly auto-claim
 * resources not already in Capsule's claimed set.  Services do
 * not need to send explicit CLAIM before MINT — Capsule handles
 * it in one trip.  The refcount is bumped on each mint/claim, even
 * for resources already claimed dynamically.
 *
 * Error returns:
 *   CLAIM:   ENOSPC (array full), EIO (kernel claim failed)
 *   RELEASE: ENOENT (not found), EPERM (manifest/internal claim)
 */
/* Opcode 11 (CLAIM_PATH) is retired: bsdfilesystem(8) brokers filesystem paths. */
#define	CAPSULE_OP_CLAIM_NET		12	/* dynamically claim a network endpoint */
/* Opcode 13 (CLAIM_JAIL) is retired: bsdnamespace(8) owns jail self-service. */
#define	CAPSULE_OP_CLAIM_SYSTEM		14	/* dynamically claim system gates */
/* Opcode 15 (RELEASE_PATH) is retired: bsdfilesystem(8) brokers filesystem paths. */
#define	CAPSULE_OP_RELEASE_NET		16	/* release a dynamic network claim */
/* Opcode 17 (RELEASE_JAIL) is retired: bsdnamespace(8) owns jail self-service. */
#define	CAPSULE_OP_RELEASE_SYSTEM	18	/* release dynamic system gates */
#define	CAPSULE_OP_CLAIM_VSOCK		20
#define	CAPSULE_OP_RELEASE_VSOCK	21
/* Opcode 22 (ENSURE_KMOD) is retired: bsdextension(8) owns kernel-module loading. */
#define	CAPSULE_OP_DELEGATE_SERVICE	23	/* delegate named service fd */

struct capsule_vsock_req {
	uint32_t	op;
	uint32_t	_pad;
	uint64_t	cid;
	uint32_t	port_min;
	uint32_t	port_max;
	uint8_t		direction;
	uint8_t		_reserved[7];
};

/*
 * Storage is NOT a Capsule operation.  bsdfilesystem(8) owns storage; switchboard talks to
 * bsdfilesystem directly (see usr.sbin/switchboard/storage_client.c).  Storage never
 * transits the init process.  Opcodes 24/25 are retired and left unused.
 */

/*
 * Kernel-module loading is NOT a Capsule operation.  bsdextension(8) owns it: it holds
 * the kldload system-capability gate and exposes system.SystemExtension
 * as a socket-free provider, so a service self-serves a module by name via
 * service_ensure_extension(3).  PID 1 no longer loads kernel code.
 */

#define	CAPSULE_SERVICE_NAME_MAX	16
struct capsule_service_req {
	uint32_t	op;
	uint32_t	_pad;
	char		name[CAPSULE_SERVICE_NAME_MAX];
};

/*
 * CAPSULE_OP_MINT_SYSTEM
 *   req:  capsule_system_req
 *   reply: capsule_reply { .status }
 *   reply_fds[0] = system gate token fd (on success)
 *
 * Mints a system gate token.  Capsule dynamically claims gates not already
 * held and reference-counts service ownership before minting.
 *
 * OPTIONAL TRAILING PAYLOAD (per-OID sysctl isolation, Phase 2 —
 * docs/capability-sysctl-isolation.md).  A CAPSULE_OP_MINT_SYSTEM request
 * MAY carry an opaque byte payload immediately after the fixed
 * capsule_system_req header; Capsule detects it by
 *     req_len > sizeof(struct capsule_system_req)
 * exactly as the kernel detects the SYSCTL OID-set on SYS_OP_CLAIM.  The fixed
 * header is unchanged (compatibility floor): a request with no trailing bytes
 * is the historical coarse mint.
 *
 * The payload is a marshalled struct sys_sysctl_oidset (see
 * <dev/mac_capability/mac_capability_system_proto.h>): switchboard resolves the
 * manifest `isolate` OID names to MIBs and builds it.  Capsule treats the
 * bytes as OPAQUE — it bounds-checks the length and relays them verbatim into
 * the kernel SYS_OP_CLAIM's OID-set trailer under its own nonce (a scoped
 * claim), never interpreting sysctl specifics.  This keeps the same generic
 * relay usable for future scoped namespaces.  A trailing payload is only valid
 * when gates == SYS_GATE_SYSCTL; any other gates alongside a payload are
 * rejected EINVAL.
 */
struct capsule_system_req {
	uint32_t	op;		/* CAPSULE_OP_MINT_SYSTEM / CLAIM / RELEASE */
	uint32_t	gates;		/* SYS_GATE_* bitmask */
	/* optional opaque sys_sysctl_oidset payload follows (MINT_SYSTEM only) */
};

/*
 * Upper bound on the opaque MINT_SYSTEM payload (a sys_sysctl_oidset with up to
 * SYS_SYSCTL_MAXOIDS entries).  Defined in terms of the kernel wire struct so
 * Capsule's receive buffer and bounds check track the kernel cap.  Only
 * compilation units that include the kernel system proto header (which defines
 * SYS_SYSCTL_MAXOIDS / struct sys_sysctl_oid) can use this.
 */
#ifdef SYS_SYSCTL_MAXOIDS
#define	CAPSULE_MINT_SYSTEM_PAYLOAD_MAX				\
	(sizeof(uint32_t) + (size_t)SYS_SYSCTL_MAXOIDS *		\
	    sizeof(struct sys_sysctl_oid))
#define	CAPSULE_MINT_SYSTEM_REQ_MAX					\
	(sizeof(struct capsule_system_req) +				\
	    CAPSULE_MINT_SYSTEM_PAYLOAD_MAX)
#endif

/*
 * CAPSULE_OP_CREATE_CHANNEL
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_CREATE_CHANNEL }
 *   reply: capsule_reply { .status }
 *   reply_fds[0] = endpoint A, reply_fds[1] = endpoint B
 *
 * Creates a new restricted channel for switchboard to pass to a
 * launched service.  switchboard keeps one end, gives the other
 * to the child via pdfork.
 */

/*
 * CAPSULE_OP_CREATE_COALITION
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_CREATE_COALITION }
 *   reply: capsule_reply { .status }
 *   reply_fds[0] = coalition instance fd
 *
 * Creates a new coalition for process group management.
 */

/*
 * CAPSULE_OP_READY
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_READY }
 *   reply: capsule_reply { .status = 0 }
 *
 * Sent by switchboard only after inherited descriptors are irreversibly
 * confined and its capprotect shield is active.  Receipt therefore means
 * "protected and operational", not merely that exec succeeded.
 * Capsule logs the transition and may gate status reporting.
 */

/*
 * CAPSULE_OP_PING
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_PING }
 *   reply: capsule_reply { .status = 0 }
 *
 * Liveness request sent by switchboard; capsule replies.
 */

/*
 * CAPSULE_OP_SET_AMBIENT_LOOKUP
 *   req:  capsule_req_hdr { .op = CAPSULE_OP_SET_AMBIENT_LOOKUP }
 *   req_fds[0] = ambient lookup channel client end (SCM_RIGHTS)
 *   reply: capsule_reply { .status }
 *
 * switchboard sends a dup of its retained SYSTEM ambient lookup channel client end
 * so Capsule (PID 1) can carry it into interactive logins.  Capsule is
 * the parent of the getty/login sessions spawned from /etc/ttys; those are
 * siblings of /etc/rc and never inherit switchboard's SERVICE_LOOKUP_FD
 * environment.  capsule stores the fd, makes it fork/exec-durable, and
 * dup2()s it to SERVICE_LOOKUP_FIXED_FD just before exec'ing each getty so
 * login inherits the discovery channel at the fixed number.
 *
 * Strictly best-effort: the rc path already carries the channel by environment
 * inheritance, so any failure here (send, receive, or install) is logged and
 * ignored on both ends and never disrupts boot, Capsule event loop, or a
 * login.  The reply is status-only with no attached fds.
 */

/*
 * Generic reply — returned for all operations.
 * Status is 0 on success, errno on failure.
 * File descriptors (if any) are attached to the reply message.
 */
struct capsule_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

/*
 * Maximum number of reply fds per operation.
 * CREATE_CHANNEL returns 2, everything else returns 0 or 1.
 */
#define	CAPSULE_MAX_REPLY_FDS	2

/*
 * Safe snprintf accumulator.  Appends formatted text to buf at
 * offset *offp, clamping to prevent overflow.
 *
 * Shared between capsule and switchboard for status formatting.
 */
#ifndef BUF_APPEND
#define	BUF_APPEND(buf, bufsz, offp, ...)	do {			\
	size_t _rem = (*(offp) < (bufsz)) ? (bufsz) - *(offp) : 0;	\
	int _n = snprintf((buf) + *(offp), _rem, __VA_ARGS__);		\
	if (_n > 0) *(offp) += (size_t)_n;				\
	if (*(offp) >= (bufsz)) *(offp) = (bufsz) - 1;			\
} while (0)
#endif /* BUF_APPEND */

#endif /* CAPSULE_SVC_PROTO_H */
