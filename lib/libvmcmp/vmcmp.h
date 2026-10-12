/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _VMCMP_H_
#define _VMCMP_H_

/* The system.VM client (formerly part of libservice). */
#include <libservice.h>

__BEGIN_DECLS
/*
 * Obtain a host-local vsock (VM socket) listener from vmd (system.VM).  Consumer
 * self-service: libservice resolves vmd by name (pulling it up on demand) and
 * has it bind a listening AF_VSOCK socket on the caller's behalf — a capability-
 * mode process cannot bind a vsock address itself.  `port` is an index within
 * the caller's own label-scoped window (0 .. VMD_PORTS_PER_LABEL-1), so it can
 * never name another Component's port; `backlog` is the listen backlog (0 =
 * default).  On success fdp receives the close-on-exec listening descriptor to
 * accept(2) on, and cidp/portp (when non-NULL) the concrete host-local CID and
 * port bound.  Returns 0, or -1 with errno.
 */
int	service_vsock_listen(struct service_context *, unsigned port,
	    unsigned backlog, unsigned *cidp, unsigned *portp, int *fdp);

/*
 * Dial a peer's advertised vsock (cid,port) via vmd (system.VM) and return the
 * connected AF_VSOCK socket — a capability-mode process cannot connect a vsock
 * address itself.  `port` is the concrete port the peer advertised from its own
 * service_vsock_listen reply (not a window index); `cid` is the target CID and
 * must not be VMADDR_CID_ANY (0xffffffff).  On success *fdp receives the close-
 * on-exec connected descriptor.  Returns 0, or -1 with errno.
 */
int	service_vsock_connect(struct service_context *, unsigned cid,
	    unsigned port, int *fdp);

/*
 * Report the caller's OWN vsock port window from vmd (VMD_OP_VSOCK_LIST), so a
 * Component can discover the concrete port range it may service_vsock_listen(3)
 * within (and the base to advertise) without guessing.  Data-only: no descriptor.
 * The answer is derived entirely from the caller's unforgeable channel label, so
 * it can only ever be the caller's own window and never another Component's.  On
 * success stores (when non-NULL) the host-local CID in *cidp, the first concrete
 * port of the window in *port_basep, and the window width (VMD_PORTS_PER_LABEL)
 * in *port_countp; a window index i passed to service_vsock_listen(3) maps to
 * concrete port (*port_basep + i).  Returns 0, or -1 with errno.
 */
int	service_vsock_list(struct service_context *, unsigned *cidp,
	    unsigned *port_basep, unsigned *port_countp);
__END_DECLS

#endif
