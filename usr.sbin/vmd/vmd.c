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

/* The default listen(2) backlog when the request leaves it unspecified. */
#define	VMD_DEFAULT_BACKLOG	8

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

/*
 * Map the caller's unforgeable channel label to a stable vsock port window.
 * FNV-1a over the label, reduced into VMD_LABEL_WINDOWS windows; the caller may
 * then bind any of the VMD_PORTS_PER_LABEL ports in its own window and no other.
 * Distinct labels can collide onto the same window (a hash, not a registry), but
 * a collision only means two Components share a port range they must coordinate
 * within — it never lets one bind outside the shared window or reach a third
 * Component's window.
 */
static uint32_t
label_window_base(const char *label)
{
	uint32_t hash = 2166136261u;
	size_t i;

	for (i = 0; label[i] != '\0'; i++) {
		hash ^= (unsigned char)label[i];
		hash *= 16777619u;
	}
	return (VMD_PORT_BASE +
	    (hash % VMD_LABEL_WINDOWS) * VMD_PORTS_PER_LABEL);
}

/* op must be known and the port index must fall inside the caller's window. */
static bool
valid_request(const struct vmd_request *rq)
{

	if (rq->op != VMD_OP_VSOCK_BIND)
		return (false);
	if (rq->port >= VMD_PORTS_PER_LABEL)
		return (false);
	return (true);
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
	int s, saved;

	s = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (s == -1)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.svm_len = sizeof(sa);
	sa.svm_family = AF_VSOCK;
	sa.svm_cid = VMADDR_CID_LOCAL;
	sa.svm_port = port;
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		goto fail;
	if (listen(s, backlog != 0 ? (int)backlog : VMD_DEFAULT_BACKLOG) == -1)
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
 * Per-client channel request handler.  arg is the connecting client's
 * unforgeable label, which scopes the port window (the domain layer already
 * restricted reachability to SYSTEM clients).  The reply carries the bound,
 * listening vsock descriptor on success.
 */
static void
vmd_request_handler(struct channel *ch __unused, struct channel_message *m,
    void *arg)
{
	const char *client = arg;
	const struct vmd_request *rq;
	struct vmd_reply rp;
	struct channel_outgoing out;
	uint32_t base, port = 0;
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

	base = label_window_base(client);
	s = bind_vsock(base, rq->port, rq->backlog, &port);
	if (s < 0) {
		rp.status = errno;
		syslog(LOG_ERR, "VSOCK_BIND idx=%u (client %s) -> bind %u: %s",
		    rq->port, client, base + rq->port, strerror(rp.status));
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
vmd_worker(int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	char label[64];
	int ready, wants_write;

	(void)strlcpy(label, client, sizeof(label));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, vmd_request_handler,
	    label) == -1) {
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
		int pd;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1)
			return (-1);
		pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
		if (pid == -1) {
			syslog(LOG_ERR, "pdfork: %m");
			(void)close(fd);
			continue;
		}
		if (pid == 0)
			_exit(vmd_worker(fd, id.client_label));
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
