/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * vmd(8) — the virtual-machine component.
 *
 * vmd is the VM authority.  Its eventual job is to run full virtual machines
 * under bhyve; today it brokers vsock (VM socket) endpoints, taking that out of
 * switchboard and the manifest.  vmd is a socket-free service_provider exposing
 * system.VM; the discovery domain layer resolves that name only for SYSTEM
 * clients.
 *
 * This is consumer self-service, uniform with warden (jails) and tzfsd
 * (filesystem): a program's library (service_vsock_listen(3)) — never switchboard —
 * resolves vmd and asks it to set up a vsock endpoint.  A Component in
 * capability mode cannot itself bind a vsock address (a global namespace); vmd,
 * which owns the vsock transport, binds one on the Component's behalf inside a
 * port window scoped to the Component's unforgeable channel label and returns
 * the listening socket as a descriptor.  One Component can never name or bind
 * another's port.  This is the same broker-holds-a-capability, re-deliver-by-
 * label shape tzfsd uses for filesystem paths and warden for jails — vmd is a
 * broker, not a second isolation authority.
 *
 * vmd runs as root and NOT in capability mode: managing bhyve and the vsock
 * transport needs device access and a global-namespace lookup (loadat/openat of
 * the bhyve tool and its libraries), both of which capsicum forbids.  It is
 * launched on demand by switchboard (the first consumer that asks for a vsock
 * resolves system.VM and pulls vmd up).
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/vsock.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <fidl/bsd.vm.v1/c/bsd.h>
#include <libservice.h>

#include "bsdvm_proto.h"
#include "bsdvm_probes.h"
#ifdef VMD_TESTING
#include "bsdvm_test.h"
#endif

/* The default listen(2) backlog when the request leaves it unspecified. */
#define	VMD_DEFAULT_BACKLOG	8

#ifndef VMD_TESTING
/*
 * Guarantee fds 0/1/2 are open before any capability handle is created.  vmd is
 * launched by switchboard without a controlling terminal.
 */
static void
reserve_stdio(void)
{
	int fd, nfd;

	for (fd = 0; fd <= 2; fd++) {
		if (fcntl(fd, F_GETFD) != -1)
			continue;
		nfd = open("/dev/null", O_RDWR);
		if (nfd == -1)
			continue;
		if (nfd != fd) {
			(void)dup2(nfd, fd);
			(void)close(nfd);
		}
	}
}
#endif /* !VMD_TESTING */

/* FNV-1a over the label — the home slot for a label's window in the registry. */
static uint32_t
label_hash(const char *label)
{
	uint32_t hash = 2166136261u;
	size_t i;

	for (i = 0; label[i] != '\0'; i++) {
		hash ^= (unsigned char)label[i];
		hash *= 16777619u;
	}
	return (hash);
}

/*
 * Window-ownership registry, private to the single-process accept loop (each
 * client is then served by a pdfork'd worker that only ever binds within the
 * window the parent already resolved for it).  Slot i owns the concrete port
 * range [VMD_PORT_BASE + i*PORTS, +PORTS); g_windows[i].label is the exactly-one
 * full label that owns it.
 *
 * A bare hash (the old label_window_base) let distinct, mutually-untrusting
 * labels that collide onto one of only 4096 windows share the same 16 concrete
 * ports — so one Component could bind, squat, or intercept the exact (cid,port)
 * another advertised (first-bind wins VMADDR_CID_LOCAL:port).  Keying the
 * registry by the FULL label closes that: resolve_window hashes to a home slot
 * then linear-probes, reusing the slot already owned by this exact label
 * (deterministic across reconnects) or claiming the first free slot otherwise.
 * Two distinct labels therefore never share a window, so no label can ever bind
 * a concrete port another label's window maps to.
 */
/*
 * refs counts the live pdfork'd workers currently serving this label.  A slot is
 * claimed on a label's first contact and RECLAIMED (used=false) when its last
 * worker exits, so the 4096-slot registry is bounded by concurrent activity, not
 * by the number of distinct labels ever seen — while a label with live workers
 * keeps its slot (and thus its stable port window) across those workers.  refs
 * also caps a single label to VMD_MAX_WORKERS_PER_LABEL concurrent sessions so
 * one label cannot monopolize the whole worker pool.
 */
struct window_owner {
	bool		used;
	unsigned	refs;
	char		label[64];
};
static struct window_owner g_windows[VMD_LABEL_WINDOWS];

#define	VMD_MAX_WORKERS			4096u	/* fleet-wide live-worker ceiling */
#define	VMD_MAX_WORKERS_PER_LABEL	128u	/* per-label concurrent sessions */

/*
 * g_windows lives entirely in the parent: the accept loop assigns slots in
 * resolve_window, and a mutex serializes every access to it.  Forked workers
 * never touch g_windows (they only bind within the base the parent already
 * resolved), so the lock lives entirely in the parent.
 */
static pthread_mutex_t g_windows_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Resolve the caller's label to the base of the window it exclusively owns,
 * assigning one on first contact and taking a worker reference on it.  Returns 0
 * on success (filling *base_out and *idx_out); -1 with errno ENOSPC when the
 * registry is full (VMD_LABEL_WINDOWS labels currently active) or EBUSY when this
 * label already holds VMD_MAX_WORKERS_PER_LABEL concurrent sessions.  Every 0
 * return must be balanced by a window_release(*idx_out) when the worker exits.
 */
static int
resolve_window(const char *label, uint32_t *base_out, uint32_t *idx_out)
{
	uint32_t home, i, idx, freeidx = VMD_LABEL_WINDOWS;
	int rc = -1, err = ENOSPC;

	/*
	 * The registry stores the label in a fixed 64-byte field and matches it
	 * with strcmp.  A label that would be truncated on store could never
	 * match its own entry, so it would claim a fresh slot on every reconnect
	 * (losing its stable window and slowly exhausting the registry).  Reject
	 * it rather than silently truncate.
	 */
	if (strlen(label) >= sizeof(g_windows[0].label)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	home = label_hash(label) % VMD_LABEL_WINDOWS;

	(void)pthread_mutex_lock(&g_windows_lock);
	for (i = 0; i < VMD_LABEL_WINDOWS; i++) {
		idx = (home + i) % VMD_LABEL_WINDOWS;
		if (!g_windows[idx].used) {
			if (freeidx == VMD_LABEL_WINDOWS)
				freeidx = idx;
			continue;
		}
		if (strcmp(g_windows[idx].label, label) == 0) {
			if (g_windows[idx].refs >= VMD_MAX_WORKERS_PER_LABEL) {
				err = EBUSY;
				goto out;
			}
			g_windows[idx].refs++;
			*base_out = VMD_PORT_BASE + idx * VMD_PORTS_PER_LABEL;
			*idx_out = idx;
			rc = 0;
			goto out;
		}
	}
	if (freeidx == VMD_LABEL_WINDOWS)
		goto out;
	g_windows[freeidx].used = true;
	g_windows[freeidx].refs = 1;
	(void)strlcpy(g_windows[freeidx].label, label,
	    sizeof(g_windows[freeidx].label));
	*base_out = VMD_PORT_BASE + freeidx * VMD_PORTS_PER_LABEL;
	*idx_out = freeidx;
	rc = 0;
out:
	(void)pthread_mutex_unlock(&g_windows_lock);
	if (rc != 0)
		errno = err;
	return (rc);
}

/*
 * Drop one worker's reference to a window and reclaim the slot when the last
 * worker for the label exits, so the registry is bounded by concurrent activity
 * rather than by every label ever seen.
 */
static void
window_release(uint32_t idx)
{

	(void)pthread_mutex_lock(&g_windows_lock);
	if (idx < VMD_LABEL_WINDOWS && g_windows[idx].used &&
	    g_windows[idx].refs > 0 && --g_windows[idx].refs == 0)
		g_windows[idx].used = false;
	(void)pthread_mutex_unlock(&g_windows_lock);
}

/*
 * Validate a wire request, failing closed on any stray bit.  Each op reads only
 * its own fields and the fields it does not use must be zero:
 *
 *   VSOCK_BIND: cid must be 0 (unused) and the port INDEX must fall inside the
 *   caller's window.
 *
 *   VSOCK_CONNECT: backlog must be 0 (unused), cid must not be the wildcard
 *   VMADDR_CID_ANY (you dial a concrete peer, never a wildcard), and port is a
 *   concrete target with no window bound (connect owns/scopes nothing).
 *
 * An unknown op is rejected.
 */
static bool
valid_request(const struct vmd_request *rq)
{

	switch (rq->op) {
	case VMD_OP_VSOCK_BIND:
		if (rq->cid != 0)
			return (false);
		if (rq->port >= VMD_PORTS_PER_LABEL)
			return (false);
		return (true);
	case VMD_OP_VSOCK_CONNECT:
		if (rq->backlog != 0)
			return (false);
		if (rq->cid == VMADDR_CID_ANY)
			return (false);
		return (true);
	case VMD_OP_VSOCK_LIST:
		/*
		 * LIST reports the caller's own window, derived entirely from the
		 * connecting label; it names/owns/scopes nothing, so every wire
		 * field must be zero (fail closed on stray bits).
		 */
		if (rq->port != 0 || rq->backlog != 0 || rq->cid != 0)
			return (false);
		return (true);
	default:
		return (false);
	}
}

/*
 * Clamp the caller-supplied listen(2) backlog to a sane range: 0 means
 * "default", and an out-of-range uint32 must not sign-flip to a negative int.
 */
static int
clamp_backlog(uint32_t backlog)
{

	if (backlog == 0)
		return (VMD_DEFAULT_BACKLOG);
	if (backlog > (uint32_t)SOMAXCONN)
		return (SOMAXCONN);
	return ((int)backlog);
}

/*
 * Bind and listen a host-local (VMADDR_CID_LOCAL) AF_VSOCK socket at the
 * concrete port the caller's window maps its requested index to, and return the
 * listening descriptor.  On success *out_port receives that concrete port.
 * Returns the fd, or -1 with errno set.
 */
static int
bind_vsock(uint32_t window_base, uint32_t index, uint32_t backlog,
    uint32_t *out_port)
{
	struct sockaddr_vm sa;
	uint32_t port = window_base + index;
	int s, saved, bl, on = 1;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s == -1)
		return (-1);

	/*
	 * Allow a restarted Component to rebind its own concrete port
	 * deterministically instead of tripping EADDRINUSE on a listener still
	 * lingering from the previous incarnation.
	 */
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sa, 0, sizeof(sa));
	sa.svm_len = sizeof(sa);
	sa.svm_family = AF_VSOCK;
	sa.svm_cid = VMADDR_CID_LOCAL;
	sa.svm_port = port;
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		goto fail;
	bl = clamp_backlog(backlog);
	if (listen(s, bl) == -1)
		goto fail;

	*out_port = port;
	return (s);

fail:
	saved = errno;
	(void)close(s);
	errno = saved;
	return (-1);
}

/*
 * Dial a concrete peer AF_VSOCK endpoint (cid,port) — the address a peer
 * advertised from its own VSOCK_BIND reply — and hand back the connected
 * descriptor.  Connecting owns and scopes nothing: there is no window, no
 * registry involvement; vmd merely opens the socket and connect(2)s on the
 * Component's behalf (a capability-mode Component cannot name the global vsock
 * namespace itself).  On success stores the fd in *fdp and returns 0; on
 * failure returns -1 with errno set.
 */
static int
connect_vsock(uint32_t cid, uint32_t port, int *fdp)
{
	struct sockaddr_vm sa;
	int s, saved;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s == -1)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.svm_len = sizeof(sa);
	sa.svm_family = AF_VSOCK;
	sa.svm_cid = cid;
	sa.svm_port = port;
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		saved = errno;
		(void)close(s);
		errno = saved;
		return (-1);
	}

	*fdp = s;
	return (0);
}

/*
 * Per-client worker context: the connecting client's unforgeable label (for
 * logging), the concrete port window the parent's registry resolved for it, and
 * whether the session has negotiated.  The worker only ever binds within
 * window_base, so a Component can bind only inside the window its label
 * exclusively owns.
 */
struct vmd_client_ctx {
	char		label[64];
	uint32_t	window_base;
	bool		negotiated;
};

/*
 * bsd.vm.v1 method handlers.  Every method but GetProtocolInfo requires a
 * negotiated session; a failed reply closes the connection.  The request-done
 * probe keeps the historical VMD_OP_* codes (0 is protocol negotiation).
 */
static bool
vmd_ready(struct vmd_client_ctx *ctx, struct fidl_bsd_connection *connection,
    uint32_t opcode)
{

	if (ctx->negotiated)
		return (true);
	BSDVM_PROBE_REQUEST_DONE(opcode, EPROTO, EPROTO);
	fidl_bsd_connection_close(connection, EPROTO);
	return (false);
}

static void
vmd_completed(struct fidl_bsd_connection *connection, uint32_t opcode,
    int status, int transport_error)
{

	BSDVM_PROBE_REQUEST_DONE(opcode, status, transport_error);
	if (transport_error != 0)
		fidl_bsd_connection_close(connection, transport_error);
}

static void
vmd_protocol_info(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct vmd_client_ctx *ctx = argument;
	struct bsd_vm_v1_ProtocolInfo info = { VMD_WIRE_VERSION };
	int error;

	error = bsd_vm_v1_VM_GetProtocolInfo_reply(connection, request, &info);
	ctx->negotiated = error == 0;
	vmd_completed(connection, 0, 0, error);
}

/*
 * Bind: the reply carries the bound, listening vsock descriptor on success --
 * rights-limited and made non-re-delegable.
 */
static void
vmd_bind(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_vm_v1_BindRequest *value)
{
	struct vmd_client_ctx *ctx = argument;
	const char *client = ctx->label;
	struct bsd_vm_v1_VM_Bind_Result reply;
	struct vmd_request rq;
	cap_rights_t rights;
	uint32_t port = 0;
	int s = -1, status = 0;

	if (!vmd_ready(ctx, connection, VMD_OP_VSOCK_BIND))
		return;
	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_BIND;
	rq.port = value->index;
	rq.backlog = value->backlog;
	if (!valid_request(&rq)) {
		status = EINVAL;
		goto reply;
	}

	s = bind_vsock(ctx->window_base, rq.port, rq.backlog, &port);
	if (s < 0) {
		status = errno;
		syslog(LOG_ERR, "VSOCK_BIND idx=%u (client %s) -> bind %u: %s",
		    rq.port, client, ctx->window_base + rq.port,
		    strerror(status));
		goto reply;
	}

	/*
	 * Harden the delivered listener.  accept(2) hands the accepted socket
	 * the LISTENER's capability rights (kern_accept4 -> falloc_caps with the
	 * listener's filecaps), so the listener must carry the data-plane rights
	 * (read/write/shutdown/{get,set}sockopt) the accepted connections need to
	 * be usable, in addition to accept/event/fstat for the listener itself.
	 * We still withhold CAP_BIND/CAP_CONNECT/CAP_LISTEN so the Component can
	 * neither rebind nor repurpose the socket, and attenuate transfer to
	 * CAP_XFER_ONCE so the reply's own SCM_RIGHTS send consumes it to
	 * CAP_XFER_NONE at the Component (it cannot re-delegate the listener).
	 */
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_FSTAT, CAP_READ,
	    CAP_WRITE, CAP_SHUTDOWN, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
	if (cap_rights_limit(s, &rights) == -1 ||
	    cap_xfer_limit(s, CAP_XFER_ONCE) == -1) {
		status = errno != 0 ? errno : EIO;
		syslog(LOG_ERR, "VSOCK_BIND idx=%u (client %s) -> rights limit: "
		    "%s", rq.port, client, strerror(status));
		(void)close(s);
		s = -1;
		goto reply;
	}
	syslog(LOG_INFO, "VSOCK_BIND idx=%u (client %s) -> cid=%u port=%u",
	    rq.port, client, VMADDR_CID_LOCAL, port);

reply:
	memset(&reply, 0, sizeof(reply));
	if (status == 0) {
		reply.tag = bsd_vm_v1_VM_Bind_Result_response_tag;
		reply.value.response.listener = s;
		reply.value.response.cid = VMADDR_CID_LOCAL;
		reply.value.response.port = port;
	} else {
		reply.tag = bsd_vm_v1_VM_Bind_Result_err_tag;
		reply.value.err = (uint32_t)status;
	}
	/* The bindings send a private duplicate; ours is closed either way. */
	vmd_completed(connection, VMD_OP_VSOCK_BIND, status,
	    bsd_vm_v1_VM_Bind_reply(connection, request, &reply));
	if (s >= 0)
		(void)close(s);
}

static void
vmd_connect(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_vm_v1_ConnectRequest *value)
{
	struct vmd_client_ctx *ctx = argument;
	const char *client = ctx->label;
	struct bsd_vm_v1_VM_Connect_Result reply;
	struct vmd_request rq;
	cap_rights_t rights;
	int s = -1, status = 0;

	if (!vmd_ready(ctx, connection, VMD_OP_VSOCK_CONNECT))
		return;
	memset(&rq, 0, sizeof(rq));
	rq.op = VMD_OP_VSOCK_CONNECT;
	rq.port = value->port;
	rq.cid = value->cid;
	if (!valid_request(&rq)) {
		status = EINVAL;
		goto reply;
	}
	if (connect_vsock(rq.cid, rq.port, &s) == -1) {
		status = errno;
		syslog(LOG_ERR, "VSOCK_CONNECT cid=%u port=%u (client %s): %s",
		    rq.cid, rq.port, client, strerror(status));
		goto reply;
	}

	/*
	 * Harden the delivered connected socket: the Component reads, writes,
	 * polls, shuts down, and (get/set)sockopts it -- but must never
	 * accept/bind/connect/listen on it -- so limit its rights to that
	 * data-plane set, and attenuate transfer to CAP_XFER_ONCE so the reply's
	 * own SCM_RIGHTS send exhausts it (no re-delegation).
	 */
	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SHUTDOWN,
	    CAP_FSTAT, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
	if (cap_rights_limit(s, &rights) == -1 ||
	    cap_xfer_limit(s, CAP_XFER_ONCE) == -1) {
		status = errno != 0 ? errno : EIO;
		syslog(LOG_ERR, "VSOCK_CONNECT cid=%u port=%u (client %s) -> "
		    "rights limit: %s", rq.cid, rq.port, client,
		    strerror(status));
		(void)close(s);
		s = -1;
		goto reply;
	}
	syslog(LOG_INFO, "VSOCK_CONNECT (client %s) -> cid=%u port=%u", client,
	    rq.cid, rq.port);

reply:
	memset(&reply, 0, sizeof(reply));
	if (status == 0) {
		reply.tag = bsd_vm_v1_VM_Connect_Result_response_tag;
		reply.value.response.socket = s;
	} else {
		reply.tag = bsd_vm_v1_VM_Connect_Result_err_tag;
		reply.value.err = (uint32_t)status;
	}
	vmd_completed(connection, VMD_OP_VSOCK_CONNECT, status,
	    bsd_vm_v1_VM_Connect_reply(connection, request, &reply));
	if (s >= 0)
		(void)close(s);
}

/*
 * List answers strictly from ctx->window_base -- the window the parent's
 * registry resolved for THIS connecting label and handed the worker at fork.
 * A worker only ever knows its own label's base, so List can only ever report
 * the caller's own window and never another label's.  Data-only: no
 * descriptor rides the reply.
 */
static void
vmd_list(void *argument, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct fidl_bsd_empty *empty __unused)
{
	struct vmd_client_ctx *ctx = argument;
	struct bsd_vm_v1_VM_List_Result reply;
	struct bsd_vm_v1_Window *window = &reply.value.response;

	if (!vmd_ready(ctx, connection, VMD_OP_VSOCK_LIST))
		return;
	memset(&reply, 0, sizeof(reply));
	reply.tag = bsd_vm_v1_VM_List_Result_response_tag;
	window->cid = VMADDR_CID_LOCAL;
	window->port_base = ctx->window_base;
	window->port_limit = ctx->window_base + VMD_PORTS_PER_LABEL;
	window->port_count = VMD_PORTS_PER_LABEL;
	BSDVM_PROBE_VSOCK_LIST(ctx->label, window->port_base, window->port_limit,
	    0);
	syslog(LOG_INFO, "VSOCK_LIST (client %s) -> base=%u range=[%u,%u)",
	    ctx->label, window->port_base, window->port_base, window->port_limit);
	vmd_completed(connection, VMD_OP_VSOCK_LIST, 0,
	    bsd_vm_v1_VM_List_reply(connection, request, &reply));
}

/* Serve one client on its own worker channel until it closes. */
static int
vmd_worker(int fd, const char *client, uint32_t window_base)
{
	static const struct bsd_vm_v1_VM_server handlers = {
		.GetProtocolInfo = vmd_protocol_info,
		.Bind = vmd_bind,
		.Connect = vmd_connect,
		.List = vmd_list
	};
	struct fidl_bsd_connection *connection;
	struct vmd_client_ctx ctx;

	/* Discard parent authority before serving the worker channel. */
	service_worker_drop_inherited_authority();

	memset(&ctx, 0, sizeof(ctx));
	(void)strlcpy(ctx.label, client, sizeof(ctx.label));
	ctx.window_base = window_base;

	if (fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &connection) != 0)
		return (1);
	/*
	 * Each delivered socket is hardened above (CAP_XFER_ONCE); keep that
	 * state on the duplicate the bindings send.
	 */
	fidl_bsd_connection_preserve_sent_inheritance(connection);
	if (bsd_vm_v1_VM_bind(connection, &handlers, &ctx) != 0) {
		fidl_bsd_connection_destroy(connection);
		return (1);
	}
	/* Peer close or a protocol violation ends the session. */
	while (fidl_bsd_connection_poll(connection, -1) == 0)
		;
	fidl_bsd_connection_destroy(connection);
	return (0);
}

#ifdef VMD_TESTING
/*
 * Test entrypoints (VMD_TESTING builds only).  They wrap the exact production
 * statics so a unit test can drive the file-scope window-ownership registry and
 * request validation deterministically, and run the per-client request handler
 * over a caller-supplied channel descriptor.  main()/reserve_stdio()/vmd_serve()
 * — the pieces that need a live service_provider transport and a controlling
 * process — are compiled out; nothing else changes.
 */
void
vmd_test_registry_reset(void)
{

	memset(g_windows, 0, sizeof(g_windows));
}

uint32_t
vmd_test_label_hash(const char *label)
{

	return (label_hash(label));
}

bool
vmd_test_resolve_window(const char *label, uint32_t *base_out)
{
	uint32_t idx;

	return (resolve_window(label, base_out, &idx) == 0);
}

void
vmd_test_window_release_label(const char *label)
{
	uint32_t home = label_hash(label) % VMD_LABEL_WINDOWS, i, idx;

	for (i = 0; i < VMD_LABEL_WINDOWS; i++) {
		idx = (home + i) % VMD_LABEL_WINDOWS;
		if (g_windows[idx].used &&
		    strcmp(g_windows[idx].label, label) == 0) {
			window_release(idx);
			return;
		}
	}
}

bool
vmd_test_valid_request(const struct vmd_request *rq)
{

	return (valid_request(rq));
}

int
vmd_test_clamp_backlog(uint32_t backlog)
{

	return (clamp_backlog(backlog));
}

int
vmd_test_worker(int fd, const char *label, uint32_t window_base)
{

	return (vmd_worker(fd, label, window_base));
}
#endif /* VMD_TESTING */

#ifndef VMD_TESTING
/*
 * One live pdfork'd worker and the window slot it holds a reference on.  Tracked
 * in the parent so a worker's exit (delivered as EVFILT_PROCDESC) can release its
 * window reference and free the pool slot.
 */
struct vmd_worker_ent {
	struct vmd_worker_ent	*next;
	int			 pd;
	uint32_t		 widx;
};

/* Reap an exited worker: drop its window reference and account the slot. */
static int
vmd_worker_remove(struct vmd_worker_ent **head, struct vmd_worker_ent *w,
    size_t *count)
{
	struct vmd_worker_ent **cursor;
	int status, result, error;

	for (cursor = head; *cursor != NULL && *cursor != w;
	    cursor = &(*cursor)->next)
		;
	if (*cursor == w)
		*cursor = w->next;
	do {
		result = pdwait(w->pd, &status, WEXITED | WNOHANG, NULL, NULL);
	} while (result == -1 && errno == EINTR);
	error = result == -1 && errno != ECHILD && errno != ESRCH ? errno : 0;
	if (error == 0)
		window_release(w->widx);
	(void)close(w->pd);
	free(w);
	if (*count != 0)
		(*count)--;
	return (error != 0 ? (errno = error, -1) : 0);
}

/* Release a window only after its worker has been confirmed reaped. */
static int
vmd_workers_stop(struct vmd_worker_ent **head, size_t *count)
{
	struct vmd_worker_ent *w;
	int error = 0, result, status, killed;

	while ((w = *head) != NULL) {
		*head = w->next;
		killed = pdkill(w->pd, SIGKILL);
		if (killed == 0 || errno == ESRCH) {
			do {
				result = pdwait(w->pd, &status, WEXITED, NULL, NULL);
			} while (result == -1 && errno == EINTR);
			if (result != -1 || errno == ECHILD || errno == ESRCH)
				window_release(w->widx);
			else if (error == 0)
				error = errno;
		} else if (error == 0)
			error = errno;
		close(w->pd);
		free(w);
	}
	*count = 0;
	return (error != 0 ? (errno = error, -1) : 0);
}

/*
 * Expose system.VM and dispatch each accepted client on its own pdfork'd
 * worker.  vmd is an ambient provider: it does NOT enter capability mode (the
 * vsock transport and bhyve management need device access and a global-namespace
 * lookup, both capsicum-forbidden).  A kqueue drives the accept loop AND watches
 * each worker's process descriptor, so the live-worker count (capped at
 * VMD_MAX_WORKERS) and the per-label window references are both bounded — a
 * client cannot fork-bomb the broker by churning connections, and window slots
 * are reclaimed as their last worker exits.  Returns 0 on completed quiescence,
 * or -1 on setup, loop, or cleanup failure.
 */
static int
vmd_serve(void)
{
	struct vmd_worker_ent *workers = NULL, *w;
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider = NULL;
	struct kevent event, change;
	size_t nworkers = 0;
	int fd, kq = -1, result = -1, error;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL) == -1 ||
	    service_provider_expose(provider, VMD_SERVICE_NAME,
	    &listener) == -1 ||
	    service_provider_enter_ambient(provider) == -1)
		goto out;
	kq = kqueuex(KQUEUE_CLOEXEC);
	if (kq == -1)
		goto out;
	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_ready(provider) == -1) {
		goto out;
	}

	for (;;) {
		pid_t pid;
		uint32_t base, widx;

		if (kevent(kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (event.filter == EVFILT_PROCDESC) {
			if (vmd_worker_remove(&workers, event.udata, &nworkers) == -1)
				goto out;
			continue;
		}
		/* Listener readable: accept exactly one connection. */
		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			/*
			 * Fail soft: a signal-interrupted accept must not tear
			 * the whole broker down.  Retry on EINTR, exit cleanly
			 * when the provider is quiescing, and only a genuine,
			 * non-transient listener failure is fatal.
			 */
			if (errno == EINTR)
				continue;
			if (service_provider_quiescing(provider) == 1) {
				if (nworkers != 0) {
					if (service_provider_quiesce_complete(provider,
					    EBUSY) == 0)
						continue;
					if (errno != EINVAL)
						goto out;
				}
				result = 0;
				goto out;
			}
			goto out;
		}
		if (nworkers >= VMD_MAX_WORKERS) {
			syslog(LOG_WARNING, "worker limit reached; dropping %s",
			    id.resource_owner);
			(void)close(fd);
			continue;
		}
		/*
		 * Resolve (and, on first contact, exclusively assign) this
		 * label's window here in the single-process accept loop, where
		 * the registry is authoritative, before handing the worker a
		 * window it alone may bind within.  The reference taken here is
		 * dropped by vmd_worker_remove when the worker exits.
		 */
		if (resolve_window(id.resource_owner, &base, &widx) == -1) {
			syslog(LOG_WARNING, errno == EBUSY ?
			    "session limit for %s" :
			    "no free vsock window for %s", id.resource_owner);
			(void)close(fd);
			continue;
		}
		w = calloc(1, sizeof(*w));
		if (w == NULL) {
			syslog(LOG_WARNING, "worker alloc: %m");
			window_release(widx);
			(void)close(fd);
			continue;
		}
		w->widx = widx;
		pid = pdfork(&w->pd, PD_CLOEXEC | PD_DAEMON | PD_NOWAITPID);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			free(w);
			window_release(widx);
			(void)close(fd);
			continue;
		}
		if (pid == 0) {
			setproctitle("-BSDVM: %s", id.client_label);
			(void)close(kq);
			/* Protect before dropping the inherited bootstrap authority. */
			if (service_worker_protect(SERVICE_PROTECT_EXTERNAL) == -1) {
				syslog(LOG_ERR, "worker protection: %m");
				_exit(1);
			}
			_exit(vmd_worker(fd, id.resource_owner, base));
		}
		(void)close(fd);
		EV_SET(&change, w->pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE,
		    NOTE_EXIT, 0, w);
		if (service_harden_fd(w->pd, 0) == -1 ||
		    kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			size_t rejected = 1;

			syslog(LOG_WARNING, "procdesc watch %s: %m",
			    id.resource_owner);
			/* This uncounted worker owns its window until reaped. */
			if (vmd_workers_stop(&w, &rejected) == -1)
				goto out;
			continue;
		}
		w->next = workers;
		workers = w;
		nworkers++;
	}
out:
	error = errno;
	if (vmd_workers_stop(&workers, &nworkers) == -1) {
		error = errno;
		result = -1;
	}
	if (kq != -1)
		close(kq);
	if (result == 0 && service_provider_quiesce_complete(provider, 0) == -1) {
		error = errno;
		result = -1;
	}
	if (provider != NULL)
		service_provider_destroy(provider);
	errno = error;
	return (result);
}

int
main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			(void)fprintf(stderr, "usage: vmd\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: vmd\n");
		return (1);
	}

	openlog("bsdvm", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	reserve_stdio();

	setproctitle("-VM");
	syslog(LOG_NOTICE, "vmd virtual-machine component (vsock broker)");

	if (vmd_serve() == -1)
		errx(1, "VM provider failed");

	return (0);
}
#endif /* !VMD_TESTING */
