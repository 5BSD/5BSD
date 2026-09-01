/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * sysextd(8) — the system-extension broker.
 *
 * Owns kernel-module ("system extension") loading, taking it out of PID 1.
 * sysextd is a socket-free service_provider: it exposes the well-known name
 * system.SystemExtension and serves each client on its own mac_capability
 * worker channel.  A client asks it to ensure a named extension is loaded; the
 * domain layer restricts system.SystemExtension to SYSTEM-domain clients, so a
 * user service can never reach it and therefore can never load kernel code.
 *
 * sysextd holds no /dev/mac_capability handle of its own — PID 1 owns that
 * device.  It declares the kldload/kldstat system-capability gates in its
 * manifest; serviced mints the matching system token (authorityd claims the
 * gates under its nonce) and delivers it as a bootstrap capability.
 * service_provider_authorize_capabilities() authorizes that token, adding
 * sysextd's process nonce to the gate's authorized set.  Because the pdfork'd
 * workers share sysextd's fork-family nonce, each worker's kldload(2) passes the
 * gate — no token is minted here, no device is opened, and no socket appears
 * anywhere in the path.
 *
 * sysextd runs as root and NOT in capability mode.  kldload(2) needs the classic
 * PRIV_KLD_LOAD privilege (checked before the gate) and resolves a bare module
 * name against the global kernel module path, which capsicum forbids; module
 * loading is inherently privileged and unsandboxable.  The mac_capability system
 * gate is what actually authorizes the load — even root is denied without the
 * held token — so root only satisfies the classical privilege underneath it.
 * modfind(2) is avoided: a kldload whose module is already present returns
 * EEXIST, which sysextd reports as success.
 */

#include <sys/types.h>
#include <sys/linker.h>
#include <sys/procdesc.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>

#include "sysext_proto.h"

/*
 * Guarantee fds 0/1/2 are open before any capability handle is created, so a
 * held service instance can never occupy a stdio slot and be clobbered by a
 * later /dev/null redirect.  sysextd is launched by serviced without a
 * controlling terminal.
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

/* A module name must be a single, safe filename component (no path, no dots). */
static bool
valid_module_name(const char *name)
{

	if (memchr(name, '\0', SYSEXT_NAME_MAX) == NULL)
		return (false);
	if (name[0] == '\0' || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (false);
	if (strchr(name, '/') != NULL)
		return (false);
	return (true);
}

/*
 * Ensure the named kernel extension is loaded.  Returns 0 on success (including
 * "already loaded") or an errno.  kldload(2) is CAPENABLED; a name that is
 * already present returns EEXIST, which is success for an ensure.
 */
static int
ensure_extension(const char *name)
{

	if (kldload(name) != -1)
		return (0);
	if (errno == EEXIST)
		return (0);
	return (errno);
}

/*
 * Per-client channel request handler.  arg is the connecting client's
 * unforgeable label (for the audit log only; the domain layer already gated
 * reachability).  The reply is a fixed sysext_reply.
 */
static void
sysext_request(struct channel *ch __unused, struct channel_message *m, void *arg)
{
	const char *client = arg;
	const struct sysext_request *rq;
	struct sysext_reply rp;
	struct channel_outgoing out;

	memset(&rp, 0, sizeof(rp));

	if (channel_message_length(m) != sizeof(*rq) ||
	    channel_message_fd_count(m) != 0) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if (rq->op != SYSEXT_OP_ENSURE || !valid_module_name(rq->name)) {
		rp.status = EINVAL;
		goto reply;
	}

	rp.status = ensure_extension(rq->name);
	if (rp.status == 0)
		syslog(LOG_INFO, "ENSURE %s (client %s) -> loaded", rq->name,
		    client);
	else
		syslog(LOG_NOTICE, "ENSURE %s (client %s) -> %s", rq->name,
		    client, strerror(rp.status));

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	(void)channel_send_reply(m, &out);
	channel_message_free(m);
}

/*
 * Serve one client on its own worker channel until it closes.  Runs in a
 * pdfork'd worker; it shares sysextd's fork-family nonce, so its kldload passes
 * the gate under the authorization granted at startup.
 */
static int
sysext_worker(int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	char label[SYSEXT_NAME_MAX];
	int ready, wants_write;

	(void)strlcpy(label, client, sizeof(label));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, sysext_request, label) == -1) {
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
 * Expose system.SystemExtension and dispatch each accepted client on its own
 * pdfork'd worker.  service_provider_authorize_capabilities() authorizes the
 * delivered kldload/kldstat system token before serving.
 *
 * Unlike other capability-plane providers, sysextd does NOT enter capability
 * mode: kldload(2) resolves a bare module name against the global kernel module
 * path (a namei over kern.module_path), which capsicum forbids — in capability
 * mode the load fails ENOENT before the gate is ever consulted.  Module loading
 * is inherently privileged and unsandboxable, so sysextd stays a root,
 * non-capability-mode broker (exactly as PID 1 was before this split), gated
 * only by the held system capability.  Returns -1 only on setup failure.
 */
static int
sysext_serve(void)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, SYSEXT_SERVICE_NAME,
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
			_exit(sysext_worker(fd, id.client_label));
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
			(void)fprintf(stderr, "usage: sysextd\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: sysextd\n");
		return (1);
	}

	/*
	 * LOG_PERROR unconditionally: serviced captures the copies on the
	 * launching side; there is no controlling terminal in production.
	 */
	openlog("sysextd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	/* Before opening any capability handle (see reserve_stdio). */
	reserve_stdio();

	setproctitle("-SystemExtension");
	syslog(LOG_NOTICE, "sysextd system-extension broker");

	/*
	 * Serve as a socket-free service_provider: authorize the delivered
	 * kldload/kldstat system token, expose system.SystemExtension, enter
	 * capability mode, and dispatch each client on its own worker channel.
	 * sysext_serve() owns the provider lifecycle and does not return on
	 * success.
	 */
	if (sysext_serve() == -1)
		errx(1, "system-extension provider failed");

	return (0);
}
