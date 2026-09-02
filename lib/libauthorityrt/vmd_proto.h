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
 * argument: vmd scopes each Component's vsock port namespace by a hash of its
 * label (VMD_PORT_BASE + a per-label offset), so one Component can never bind
 * another's port.  vmd owns the vsock transport (the /dev/vsock provider
 * authority delegated from authorityd), opens the socket on the Component's
 * behalf, binds it in the Component's scoped range, listens, and returns the
 * listening socket as the reply's single SCM fd — the same broker-holds-a-
 * capability, re-delivers-by-label shape tzfsd uses for filesystem paths.
 *
 * vmd runs as a root, non-capability-mode privileged provider: managing bhyve
 * and the vsock transport needs device access and a global-namespace lookup
 * (loadat/openat of the bhyve tool and its libraries), which capsicum forbids.
 */

#ifndef VMD_PROTO_H
#define VMD_PROTO_H

#include <sys/types.h>

#include <stdint.h>

#define	VMD_SERVICE_NAME	"system.VM"

#define	VMD_OP_VSOCK_BIND	1	/* bind+listen a vsock endpoint for me */

/*
 * The per-Component vsock port window vmd hands out.  vmd derives a window
 * offset from a hash of the caller's unforgeable label; the caller's window is
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
 * Bind request.  port is the index within the caller's own window (0 ..
 * VMD_PORTS_PER_LABEL-1); vmd maps it into the label-scoped range so the wire
 * value can never name another Component's port.  backlog is the listen(2)
 * backlog (0 = default).
 */
struct vmd_request {
	uint32_t	op;		/* VMD_OP_VSOCK_BIND */
	uint32_t	port;		/* index within the caller's window */
	uint32_t	backlog;	/* listen backlog, 0 = default */
	uint32_t	_reserved;
};

/*
 * Reply.  On status==0 the message carries one SCM descriptor: the bound,
 * listening AF_VSOCK socket the Component accept(2)s on.  cid/port report the
 * concrete (host-local) address vmd bound, for the Component to advertise.
 */
struct vmd_reply {
	int32_t		status;		/* 0, or errno */
	uint32_t	cid;		/* the host-local CID bound */
	uint32_t	port;		/* the concrete port bound */
	uint32_t	_reserved;
};

#endif /* VMD_PROTO_H */
