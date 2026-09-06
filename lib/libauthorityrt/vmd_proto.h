/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for vmd(8) — the virtual-machine component.
 *
 * vmd is the VM authority.  For now it brokers vsock (VM socket) endpoints; it
 * will grow to run full virtual machines under bhyve.  It is a socket-free
 * service_provider: a Component reaches it over a held mac_capability channel
 * obtained by name (system.VM) and asks it to set up a vsock endpoint and hand
 * back the channel.  The discovery domain layer resolves system.VM only for
 * SYSTEM clients.
 *
 * Authority is the connecting channel's unforgeable label, never a wire
 * argument: vmd scopes each Component's vsock port namespace to a window it
 * exclusively owns.  A hash of the label picks the window's home slot, but vmd
 * keeps a registry keyed by the *full* label and relocates on hash collision, so
 * a given concrete port range belongs to exactly one label and one Component can
 * never bind another's port.  vmd owns the vsock transport (the /dev/vsock provider
 * authority delegated from authorityd), opens the socket on the Component's
 * behalf, binds it in the Component's scoped range, listens, and returns the
 * listening socket as the reply's single SCM fd — the same broker-holds-a-
 * capability, re-delivers-by-label shape tzfsd uses for filesystem paths.
 *
 * vmd runs as a root, non-capability-mode privileged provider: managing bhyve
 * and the vsock transport needs device access and a global-namespace lookup
 * (loadat/openat of the bhyve tool and its libraries), which capsicum forbids.
 *
 * vmd also brokers the peer side: VSOCK_CONNECT dials a concrete (cid,port) a
 * peer advertised from its own VSOCK_BIND reply and returns the connected
 * socket.  Connecting owns and scopes nothing — there is no registry
 * involvement, no port window — it just reaches the peer's advertised address;
 * the listener authorizes its own clients, exactly the client/server model.
 * A Component in capability mode cannot connect an AF_VSOCK address itself (a
 * global namespace), so vmd opens the socket and connect(2)s on its behalf.
 */

#ifndef VMD_PROTO_H
#define VMD_PROTO_H

#include <sys/types.h>

#include <stdint.h>

#define	VMD_SERVICE_NAME	"system.Waspnest"

#define	VMD_OP_VSOCK_BIND	1	/* bind+listen a vsock endpoint for me */
#define	VMD_OP_VSOCK_CONNECT	2	/* dial a peer's advertised (cid,port) */
#define	VMD_OP_VSOCK_LIST	3	/* report MY own port window (base+range) */

/*
 * The per-Component vsock port window vmd hands out.  vmd hashes the caller's
 * unforgeable label to a home window and, via a full-label registry, assigns it
 * a window it exclusively owns (relocating on hash collision); the caller's
 * window is
 *
 *   [VMD_PORT_BASE + offset*VMD_PORTS_PER_LABEL,
 *    VMD_PORT_BASE + (offset+1)*VMD_PORTS_PER_LABEL)
 *
 * on the host-local CID (VMADDR_CID_LOCAL).  The wire "port" is only an index
 * within that window, so a Component can never name another Component's port.
 * The base sits high in the 32-bit vsock port space, clear of the low ports a
 * VMM assigns to guest transports.
 */
#define	VMD_PORT_BASE		0x40000000u
#define	VMD_LABEL_WINDOWS	4096u
#define	VMD_PORTS_PER_LABEL	16u

/*
 * Request.  The 16-byte layout is shared by both operations; each reads only
 * its own fields and the unused ones MUST be zero (fail closed on stray bits).
 *
 * VMD_OP_VSOCK_BIND:
 *   op      = VMD_OP_VSOCK_BIND
 *   port    = INDEX within the caller's own window (0 .. VMD_PORTS_PER_LABEL-1);
 *             vmd maps it into the label-scoped range so the wire value can
 *             never name another Component's port.
 *   backlog = listen(2) backlog (0 = default).
 *   cid     = MUST be 0.
 *
 * VMD_OP_VSOCK_CONNECT:
 *   op      = VMD_OP_VSOCK_CONNECT
 *   port    = CONCRETE target port, as advertised by a peer's BIND reply (not a
 *             window index — connect owns/scopes nothing, so no window bound).
 *   backlog = MUST be 0 (unused).
 *   cid     = target CID (e.g. VMADDR_CID_LOCAL for host-local); MUST NOT be
 *             VMADDR_CID_ANY (0xffffffff).
 *
 * VMD_OP_VSOCK_LIST:
 *   Reports the caller's OWN scoped port window (so a Component can discover the
 *   concrete port range it may bind within, and the base to advertise, without
 *   guessing).  It owns and scopes nothing new: port/backlog/cid MUST all be 0
 *   (fail closed on stray bits).  The answer is derived entirely from the
 *   connecting channel's unforgeable label — vmd reports only the window that
 *   label exclusively owns and can never reveal another label's window.
 */
struct vmd_request {
	uint32_t	op;		/* VMD_OP_VSOCK_* */
	uint32_t	port;		/* BIND: window index; CONNECT: target port; LIST: 0 */
	uint32_t	backlog;	/* BIND: listen backlog; CONNECT/LIST: 0 */
	uint32_t	cid;		/* BIND/LIST: 0; CONNECT: target CID */
};

/*
 * Reply.  On status==0 the message carries one SCM descriptor:
 *   - VSOCK_BIND: the bound, listening AF_VSOCK socket the Component accept(2)s
 *     on; cid/port report the concrete (host-local) address vmd bound, for the
 *     Component to advertise.
 *   - VSOCK_CONNECT: the connected AF_VSOCK socket; cid/port echo the concrete
 *     target that was reached, for symmetry.
 */
struct vmd_reply {
	int32_t		status;		/* 0, or errno */
	uint32_t	cid;		/* the host-local CID bound */
	uint32_t	port;		/* the concrete port bound */
	uint32_t	_reserved;
};

/*
 * Reply to VMD_OP_VSOCK_LIST.  Data-only (no descriptor): it reports the
 * caller's OWN exclusively-owned port window, derived from the connecting
 * label, so a Component learns the concrete range it may bind within and the
 * base to advertise.  The reported range is
 *
 *   [port_base, port_limit)  ==  [port_base, port_base + port_count)
 *
 * on the host-local CID.  port_count is VMD_PORTS_PER_LABEL and a window index i
 * (as passed to VSOCK_BIND) maps to concrete port (port_base + i).  This reply's
 * wire size is deliberately distinct from vmd_reply.  _reserved MUST be 0.
 */
struct vmd_list_reply {
	int32_t		status;		/* 0, or errno */
	uint32_t	cid;		/* VMADDR_CID_LOCAL — the window's CID */
	uint32_t	port_base;	/* first concrete port owned (inclusive) */
	uint32_t	port_limit;	/* one past the last owned port (exclusive) */
	uint32_t	port_count;	/* window width == VMD_PORTS_PER_LABEL */
	uint32_t	_reserved;	/* MUST be 0 */
};

#endif /* VMD_PROTO_H */
