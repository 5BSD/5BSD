/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.VM client, moved out of libservice: service_vsock_listen(3), service_vsock_connect(3) and service_vsock_list(3).
 * The record protocol and behaviour are unchanged.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/vsock.h>

#include <libservice.h>
#include <libservice_session.h>
#include <bsdvm_proto.h>
#include "vmcmp.h"

/*
 * Bound for the system.VM control calls.  Without a finite
 * timeout a provider that is up-but-wedged (accepted the connection but never
 * replies) would block the calling daemon thread forever.  A crashed provider is
 * already handled -- the channel reset delivers ECONNRESET -- so this only
 * covers the wedged case; 30s is generous for a vsock setup.
 */
#define	SERVICE_CONTROL_CALL_TIMEOUT_MS	30000

static struct service_session *service_vm_session;
#define SESSIONS_FORGET() do { service_vm_session = NULL; } while (0)
static bool
service_provider_status_valid(int32_t status)
{

	return (status >= 0 && status <= ELAST);
}

static int
service_provider_protocol_error(struct service_session *session, int fd)
{

	if (fd >= 0)
		(void)close(fd);
	(void)service_session_fail(session, EPROTO);
	errno = EPROTO;
	return (-1);
}


/*
 * One process-wide provider session, opened by name on first use.  A
 * session that failed terminally (the provider died or was relaunched) is
 * replaced; a session inherited across fork or pdfork belongs to the parent
 * and is abandoned (libservice's fork handling severs its channel).
 */
static pthread_mutex_t service_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t service_session_owner;

static int
service_cached_session_get(const char *name, struct service_session **slot)
    __no_lock_analysis
{
	struct service_session *candidate;
	int error, fd;

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0)
		return (errno = error, -1);
	if (service_session_owner != getpid()) {
		/* Never close an inherited session: it is the parent's. */
		SESSIONS_FORGET();
		service_session_owner = getpid();
	}
	if (*slot != NULL) {
		struct service_session *dead = NULL;

		if (service_session_is_dead(*slot)) {
			dead = *slot;
			*slot = NULL;
		}
		(void)pthread_mutex_unlock(&service_state_lock);
		if (dead == NULL)
			return (0);
		service_session_close(dead);
	} else
		(void)pthread_mutex_unlock(&service_state_lock);

	if (service_open(name, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &candidate) == -1) {
		error = errno;
		(void)close(fd);
		errno = error;
		return (-1);
	}

	error = pthread_mutex_lock(&service_state_lock);
	if (error != 0) {
		service_session_close(candidate);
		errno = error;
		return (-1);
	}
	if (*slot == NULL) {
		*slot = candidate;
		candidate = NULL;
	}
	(void)pthread_mutex_unlock(&service_state_lock);
	if (candidate != NULL)
		service_session_close(candidate);
	return (0);
}

/*
 * Obtain a host-local vsock (VM socket) listener from vmd(8).  Consumer self-
 * service, uniform with storage/jails/modules: libservice opens a system.VM
 * channel by name (pulling vmd up on demand) and asks it to bind a listening
 * AF_VSOCK socket.  A process in capability mode cannot bind a vsock address
 * itself (it names a global namespace); vmd binds one on the caller's behalf in
 * a port window scoped to the caller's unforgeable channel label and returns the
 * listening descriptor, which the caller accept(2)s on.
 *
 * `port` is an index within the caller's own window (0 .. VMD_PORTS_PER_LABEL-1);
 * vmd maps it into the label-scoped range, so the value can never name another
 * Component's port.  `backlog` is the listen(2) backlog (0 = a sensible default).
 * On success fdp receives the close-on-exec listening descriptor and, when
 * non-NULL, cidp/portp receive the concrete host-local CID and port bound (for
 * the caller to advertise to a peer).  Returns 0, or -1 with errno.
 */
int
service_vsock_listen(struct service_context *context, unsigned port,
    unsigned backlog, unsigned *cidp, unsigned *portp, int *fdp)
{
	struct vmd_request rq;
	struct vmd_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;
	int fd = -1;

	if (fdp == NULL || port >= VMD_PORTS_PER_LABEL) {
		errno = EINVAL;
		return (-1);
	}
	*fdp = -1;
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.VM channel. */
	if (service_cached_session_get(VMD_SERVICE_NAME,
	    &service_vm_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_BIND;
	rq.port = port;
	rq.backlog = backlog;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	if (service_session_call(service_vm_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_vm_session, -1));
		return (-1);
	}
	if (incoming.length != sizeof(rp) || rp._reserved != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    (rp.status == 0 && (incoming.nfds != 1 ||
	    rp.cid != VMADDR_CID_LOCAL || rp.port < VMD_PORT_BASE ||
	    rp.port >= VMD_PORT_BASE + VMD_LABEL_WINDOWS *
	    VMD_PORTS_PER_LABEL ||
	    (rp.port - VMD_PORT_BASE) % VMD_PORTS_PER_LABEL != rq.port)) ||
	    (rp.status != 0 && (incoming.nfds != 0 || rp.cid != 0 ||
	    rp.port != 0)))
		return (service_provider_protocol_error(service_vm_session,
		    incoming.nfds != 0 ? fd : -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	if (cidp != NULL)
		*cidp = rp.cid;
	if (portp != NULL)
		*portp = rp.port;
	*fdp = fd;
	return (0);
}

/*
 * Dial a peer's advertised vsock (cid,port) via vmd (VMD_OP_VSOCK_CONNECT) and
 * return the connected AF_VSOCK socket.  Consumer self-service, symmetric with
 * service_vsock_listen: a capability-mode process cannot connect a vsock address
 * itself (a global namespace), so vmd opens the socket and connect(2)s on its
 * behalf.  Connecting owns and scopes nothing — `port` is the concrete target
 * port the peer advertised from its own listen reply (not a window index) and
 * `cid` is the target CID (e.g. VMADDR_CID_LOCAL).  cid must not be
 * VMADDR_CID_ANY (0xffffffff).  On success *fdp receives the close-on-exec
 * connected descriptor.  The delivered socket is the client's own; the daemon
 * set CAP_XFER_ONCE, consumed to NONE at this client by the reply-send, so it is
 * not re-delegable and no extra attenuation is applied.  Returns 0, or -1 with
 * errno.
 */
int
service_vsock_connect(struct service_context *context, unsigned cid,
    unsigned port, int *fdp)
{
	struct vmd_request rq;
	struct vmd_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;
	int fd = -1;

	/* 0xffffffff == VMADDR_CID_ANY: never a valid connect target. */
	if (fdp == NULL || cid == 0xffffffffu) {
		errno = EINVAL;
		return (-1);
	}
	*fdp = -1;
	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.VM channel. */
	if (service_cached_session_get(VMD_SERVICE_NAME,
	    &service_vm_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_CONNECT;
	rq.port = port;			/* concrete target port; backlog stays 0 */
	rq.cid = cid;			/* target CID */
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	if (service_session_call(service_vm_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_vm_session, -1));
		return (-1);
	}
	if (incoming.length != sizeof(rp) || rp._reserved != 0 ||
	    !service_provider_status_valid(rp.status) ||
	    (rp.status == 0 && (incoming.nfds != 1 || rp.cid != rq.cid ||
	    rp.port != rq.port)) ||
	    (rp.status != 0 && (incoming.nfds != 0 || rp.cid != 0 ||
	    rp.port != 0)))
		return (service_provider_protocol_error(service_vm_session,
		    incoming.nfds != 0 ? fd : -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	*fdp = fd;
	return (0);
}

/*
 * Report the caller's OWN vsock port window from vmd (VMD_OP_VSOCK_LIST).  Data-
 * only, symmetric with service_vsock_listen but taking and returning no
 * descriptor: vmd answers entirely from the connecting label's exclusively-owned
 * window, so this can only ever be the caller's own window.  Shares the cached
 * system.VM session with listen/connect.  On success stores the host-local CID,
 * the window's first concrete port, and its width into the non-NULL out params.
 */
int
service_vsock_list(struct service_context *context, unsigned *cidp,
    unsigned *port_basep, unsigned *port_countp)
{
	struct vmd_request rq;
	struct vmd_list_reply rp;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	options.timeout_ms = SERVICE_CONTROL_CALL_TIMEOUT_MS;

	if (service_context_check(context) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Reuse the process-wide system.VM channel. */
	if (service_cached_session_get(VMD_SERVICE_NAME,
	    &service_vm_session) == -1)
		return (-1);

	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_LIST;		/* port/backlog/cid stay zero */
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &rq;
	outgoing.length = sizeof(rq);
	memset(&rp, 0, sizeof(rp));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &rp;
	incoming.capacity = sizeof(rp);
	if (service_session_call(service_vm_session, &outgoing, &incoming,
	    &options) == -1) {
		if (errno == EMSGSIZE)
			return (service_provider_protocol_error(
			    service_vm_session, -1));
		return (-1);
	}
	/* Strict reply validation: framing, errno, and an owned window. */
	if (incoming.length != sizeof(rp) || incoming.nfds != 0 ||
	    rp._reserved != 0 || !service_provider_status_valid(rp.status) ||
	    (rp.status == 0 && (rp.cid != VMADDR_CID_LOCAL ||
	    rp.port_count != VMD_PORTS_PER_LABEL ||
	    rp.port_base < VMD_PORT_BASE ||
	    rp.port_base >= VMD_PORT_BASE + VMD_LABEL_WINDOWS *
	    VMD_PORTS_PER_LABEL ||
	    (rp.port_base - VMD_PORT_BASE) % VMD_PORTS_PER_LABEL != 0 ||
	    rp.port_limit != rp.port_base + rp.port_count)) ||
	    (rp.status != 0 && (rp.cid != 0 || rp.port_base != 0 ||
	    rp.port_limit != 0 || rp.port_count != 0)))
		return (service_provider_protocol_error(service_vm_session, -1));
	if (rp.status != 0) {
		errno = rp.status;
		return (-1);
	}
	if (cidp != NULL)
		*cidp = rp.cid;
	if (port_basep != NULL)
		*port_basep = rp.port_base;
	if (port_countp != NULL)
		*port_countp = rp.port_count;
	return (0);
}
