/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * vmd(8) — the virtual-machine component.
 *
 * vmd is the VM authority.  Its eventual job is to run full virtual machines
 * under bhyve; today it brokers vsock (VM socket) endpoints, taking that out of
 * serviced and the manifest.  vmd is a socket-free service_provider exposing
 * system.VM; the discovery domain layer resolves that name only for SYSTEM
 * clients.
 *
 * This is consumer self-service, uniform with warden (jails) and tzfsd
 * (filesystem): a program's library (service_vsock_listen(3)) — never serviced —
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
 * launched on demand by serviced (the first consumer that asks for a vsock
 * resolves system.VM and pulls vmd up).
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/vsock.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "vmd_proto.h"
#include "waspnest_probes.h"
#ifdef VMD_TESTING
#include "waspnest_test.h"
#endif

/* The default listen(2) backlog when the request leaves it unspecified. */
#define	VMD_DEFAULT_BACKLOG	8

#ifndef VMD_TESTING
/*
 * Guarantee fds 0/1/2 are open before any capability handle is created.  vmd is
 * launched by serviced without a controlling terminal.
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
struct window_owner {
	bool	used;
	char	label[64];
};
static struct window_owner g_windows[VMD_LABEL_WINDOWS];

/*
 * Resolve the caller's label to the base of the window it exclusively owns,
 * assigning one on first contact.  Returns false only when the registry is full
 * (more than VMD_LABEL_WINDOWS distinct labels have ever been seen).
 */
static bool
resolve_window(const char *label, uint32_t *base_out)
{
	uint32_t home = label_hash(label) % VMD_LABEL_WINDOWS;
	uint32_t i, idx, freeidx = VMD_LABEL_WINDOWS;

	for (i = 0; i < VMD_LABEL_WINDOWS; i++) {
		idx = (home + i) % VMD_LABEL_WINDOWS;
		if (!g_windows[idx].used) {
			if (freeidx == VMD_LABEL_WINDOWS)
				freeidx = idx;
			continue;
		}
		if (strcmp(g_windows[idx].label, label) == 0) {
			*base_out = VMD_PORT_BASE + idx * VMD_PORTS_PER_LABEL;
			return (true);
		}
	}
	if (freeidx == VMD_LABEL_WINDOWS)
		return (false);
	g_windows[freeidx].used = true;
	(void)strlcpy(g_windows[freeidx].label, label,
	    sizeof(g_windows[freeidx].label));
	*base_out = VMD_PORT_BASE + freeidx * VMD_PORTS_PER_LABEL;
	return (true);
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
 * logging) and the concrete port window the parent's registry resolved for it.
 * The worker only ever binds within window_base, so a Component can bind only
 * inside the window its label exclusively owns.
 */
struct vmd_client_ctx {
	char		label[64];
	uint32_t	window_base;
};

/*
 * Per-client channel request handler.  arg is this worker's context (label +
 * resolved window).  The reply carries the bound, listening vsock descriptor on
 * success — rights-limited to accept-only and made non-re-delegable.
 */
static void
vmd_request_handler(struct channel *ch __unused, struct channel_message *m,
    void *arg)
{
	const struct vmd_client_ctx *ctx = arg;
	const char *client = ctx->label;
	const struct vmd_request *rq;
	struct vmd_reply rp;
	struct channel_outgoing out;
	cap_rights_t rights;
	uint32_t port = 0;
	int s = -1;

	memset(&rp, 0, sizeof(rp));

	if (channel_message_length(m) != sizeof(*rq) ||
	    channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if (!valid_request(rq)) {
		rp.status = EINVAL;
		goto reply;
	}

	if (rq->op == VMD_OP_VSOCK_LIST) {
		struct vmd_list_reply lrp;
		struct channel_outgoing lout;

		/*
		 * Answer strictly from ctx->window_base — the window the parent's
		 * registry resolved for THIS connecting label and handed the worker
		 * at fork.  A worker only ever knows its own label's base, so LIST
		 * can only ever report the caller's own window and never another
		 * label's.  Data-only: no descriptor rides the reply.
		 */
		memset(&lrp, 0, sizeof(lrp));
		lrp.status = 0;
		lrp.cid = VMADDR_CID_LOCAL;
		lrp.port_base = ctx->window_base;
		lrp.port_limit = ctx->window_base + VMD_PORTS_PER_LABEL;
		lrp.port_count = VMD_PORTS_PER_LABEL;
		WASPNEST_PROBE_VSOCK_LIST(client, lrp.port_base, lrp.port_limit, 0);
		syslog(LOG_INFO, "VSOCK_LIST (client %s) -> base=%u range=[%u,%u)",
		    client, lrp.port_base, lrp.port_base, lrp.port_limit);
		memset(&lout, 0, sizeof(lout));
		lout.size = sizeof(lout);
		lout.data = &lrp;
		lout.length = sizeof(lrp);
		(void)channel_send_reply(m, &lout);
		channel_message_free(m);
		return;
	}

	if (rq->op == VMD_OP_VSOCK_CONNECT) {
		if (connect_vsock(rq->cid, rq->port, &s) == -1) {
			rp.status = errno;
			syslog(LOG_ERR, "VSOCK_CONNECT cid=%u port=%u (client "
			    "%s): %s", rq->cid, rq->port, client,
			    strerror(rp.status));
			goto reply;
		}

		/*
		 * Harden the delivered connected socket: the Component reads,
		 * writes, polls, shuts down, and (get/set)sockopts it — but must
		 * never accept/bind/connect/listen on it — so limit its rights to
		 * that data-plane set, and attenuate transfer to CAP_XFER_ONCE so
		 * the reply's own SCM_RIGHTS send exhausts it (no re-delegation).
		 */
		cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT,
		    CAP_SHUTDOWN, CAP_FSTAT, CAP_GETSOCKOPT, CAP_SETSOCKOPT);
		if (cap_rights_limit(s, &rights) == -1 ||
		    cap_xfer_limit(s, CAP_XFER_ONCE) == -1) {
			rp.status = errno != 0 ? errno : EIO;
			syslog(LOG_ERR, "VSOCK_CONNECT cid=%u port=%u (client "
			    "%s) -> rights limit: %s", rq->cid, rq->port, client,
			    strerror(rp.status));
			(void)close(s);
			s = -1;
			goto reply;
		}

		rp.status = 0;
		rp.cid = rq->cid;
		rp.port = rq->port;
		syslog(LOG_INFO, "VSOCK_CONNECT (client %s) -> cid=%u port=%u",
		    client, rp.cid, rp.port);
		goto reply;
	}

	s = bind_vsock(ctx->window_base, rq->port, rq->backlog, &port);
	if (s < 0) {
		rp.status = errno;
		syslog(LOG_ERR, "VSOCK_BIND idx=%u (client %s) -> bind %u: %s",
		    rq->port, client, ctx->window_base + rq->port,
		    strerror(rp.status));
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
		rp.status = errno != 0 ? errno : EIO;
		syslog(LOG_ERR, "VSOCK_BIND idx=%u (client %s) -> rights limit: "
		    "%s", rq->port, client, strerror(rp.status));
		(void)close(s);
		s = -1;
		goto reply;
	}

	rp.status = 0;
	rp.cid = VMADDR_CID_LOCAL;
	rp.port = port;
	syslog(LOG_INFO, "VSOCK_BIND idx=%u (client %s) -> cid=%u port=%u",
	    rq->port, client, rp.cid, rp.port);

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (s >= 0 && rp.status == 0) {
		out.fds = &s;
		out.nfds = 1;
	}
	(void)channel_send_reply(m, &out);
	if (s >= 0)
		(void)close(s);
	channel_message_free(m);
}

/* Serve one client on its own worker channel until it closes. */
static int
vmd_worker(int fd, const char *client, uint32_t window_base)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	struct vmd_client_ctx ctx;
	int ready, wants_write;

	memset(&ctx, 0, sizeof(ctx));
	(void)strlcpy(ctx.label, client, sizeof(ctx.label));
	ctx.window_base = window_base;

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, vmd_request_handler,
	    &ctx) == -1) {
		channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1 ||
		    (ready = channel_wait(channel, wants_write, -1)) == -1 ||
		    ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1) ||
		    ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1))
			break;
	}
	channel_destroy(channel);
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

	return (resolve_window(label, base_out));
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
 * Expose system.VM and dispatch each accepted client on its own pdfork'd
 * worker.  vmd is a privileged provider: it does NOT enter capability mode (the
 * vsock transport and bhyve management need device access and a global-namespace
 * lookup, both capsicum-forbidden).  Returns -1 only on setup failure.
 */
static int
vmd_serve(void)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, VMD_SERVICE_NAME,
	    &listener) == -1 ||
	    service_provider_enter_privileged(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	for (;;) {
		pid_t pid;
		uint32_t base;
		int pd;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		/*
		 * Resolve (and, on first contact, exclusively assign) this
		 * label's window here in the single-process accept loop, where
		 * the registry is authoritative, before handing the worker a
		 * window it alone may bind within.
		 */
		if (!resolve_window(id.client_label, &base)) {
			syslog(LOG_ERR, "no free vsock window for client %s",
			    id.client_label);
			(void)close(fd);
			continue;
		}
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0)
			_exit(vmd_worker(fd, id.client_label, base));
		(void)close(fd);
		(void)close(pd);
	}
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

	openlog("vmd", LOG_PID | LOG_PERROR, LOG_DAEMON);
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
