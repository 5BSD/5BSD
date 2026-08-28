/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Lookup domains (§22) and minted user-domain channels (§21).
 *
 * A domain is a scope over the reverse-DNS naming layer: it selects which
 * registered names a lookup channel may resolve.  Domains only ever NARROW.
 * The system domain (the default every serviced-launched unit holds) resolves
 * every registered name; a user domain resolves only an explicit allow-list of
 * system names plus (in future) user-scoped services, and reports every other
 * name as ENOENT — indistinguishable from an unregistered name.
 *
 * This file also owns the serviced-held end of minted user-domain lookup
 * channels.  SVC_OP_MINT_DOMAIN hands the caller a narrowed channel; serviced
 * keeps the other end here, dispatches SVC_OP_LOOKUP arriving on it, and scopes
 * each lookup to the channel's domain.  The channel carries no backing process,
 * so it serves lookups only — never name registration or readiness.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"
#include "fd_budget.h"
#include "serviced_svc_proto.h"

/*
 * USER-domain system allow-list.
 *
 * The small, explicit set of system reverse-DNS names a user session may
 * resolve.  A privileged system-only provider (storage broker, module
 * management, identity minting, ...) is deliberately absent: a user domain
 * never sees it.  Extend this set consciously — every entry widens what an
 * unprivileged session can discover.
 */
static const char *const user_system_allow[] = {
	"org.5bsd.Log",		/* logging */
	"org.5bsd.Notify",	/* notifications */
};

/*
 * The serviced-held ends of minted user-domain lookup channels.  Each entry is
 * a channel whose peer was handed to a session; requests on it are scoped to
 * its domain.  Kept in a simple list — the population is one channel per login
 * session, not per process.
 */
struct svc_lookup_channel {
	struct svc_lookup_channel	*next;
	struct channel			*channel;
	int				 fd;	/* channel_fd(), registered on kq */
	struct svc_domain		 domain;
};

static struct svc_lookup_channel *lookup_channels;

/*
 * Decide whether a domain may resolve a name.  Checked before the registry is
 * consulted, so an out-of-scope name is reported exactly as an unregistered
 * one.  A NULL or SYSTEM domain resolves everything (the default authority);
 * a USER domain resolves only its allow-list (user-scoped services do not yet
 * exist).  Domains only narrow, so this only ever removes names.
 */
bool
svc_domain_resolves(const struct svc_domain *domain, const char *name)
{
	size_t i;

	if (domain == NULL || domain->kind == SVC_DOMAIN_SYSTEM)
		return (true);
	/* SVC_DOMAIN_USER: allow-listed system names only. */
	for (i = 0; i < nitems(user_system_allow); i++) {
		if (strcmp(user_system_allow[i], name) == 0)
			return (true);
	}
	return (false);
}

/*
 * Whether a domain may mint a narrower one.  Only a SYSTEM domain (the default)
 * may: domains only ever narrow, so a request arriving on an already-narrowed
 * channel is refused.  A NULL domain is treated as SYSTEM.
 */
bool
svc_domain_may_mint(const struct svc_domain *domain)
{

	return (domain == NULL || domain->kind == SVC_DOMAIN_SYSTEM);
}

/*
 * Mark a descriptor ambient (§21.1): it survives every fork
 * (CAP_CLOFORK_UNLOCKED), survives exec (close-on-exec cleared), and — being a
 * mac_capability channel endpoint — remains usable in capability mode.  A
 * session leader can then inherit it exactly the way it inherits standard I/O.
 * Returns 0 on success, -1 with errno set on failure.
 */
int
svc_fd_make_ambient(int fd)
{

	if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1)
		return (-1);
	if (fcntl(fd, F_SETFD, 0) == -1)
		return (-1);
	return (0);
}

static struct svc_lookup_channel *
lookup_channel_find(uintptr_t ident)
{
	struct svc_lookup_channel *lc;

	for (lc = lookup_channels; lc != NULL; lc = lc->next) {
		if ((uintptr_t)lc->fd == ident)
			return (lc);
	}
	return (NULL);
}

static void
lookup_channel_close(struct svc_lookup_channel *lc)
{
	struct svc_lookup_channel **pp;

	for (pp = &lookup_channels; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == lc) {
			*pp = lc->next;
			break;
		}
	}
	if (lc->channel != NULL)
		channel_destroy(lc->channel);
	else if (lc->fd >= 0)
		close(lc->fd);
	free(lc);
}

static void
lookup_channel_sync_events(struct svc_lookup_channel *lc, int kq)
{
	struct kevent change;
	int wants;

	if (lc->channel == NULL || lc->fd < 0)
		return;
	wants = channel_wants_write(lc->channel);
	if (wants == -1)
		return;
	EV_SET(&change, lc->fd, EVFILT_WRITE,
	    EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0, 0, lc);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1)
		syslog(LOG_WARNING, "domain: update channel write event: %m");
}

static void
lookup_channel_reply(struct channel_message *request, int status, int *fds,
    size_t nfds)
{
	struct svc_reply reply;
	size_t i;

	reply.status = status;
	for (i = 0; i < nfds; i++) {
		if (cap_xfer_limit(fds[i], CAP_XFER_ONCE) == -1) {
			reply.status = errno;
			fds = NULL;
			nfds = 0;
			break;
		}
	}
	if (channel_send_reply(request,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &reply,
		.length = sizeof(reply),
		.fds = fds,
		.nfds = nfds
	    }) == -1)
		syslog(LOG_WARNING, "domain: channel reply: %m");
}

/*
 * Request handler for a minted user-domain channel.  It serves only
 * SVC_OP_LOOKUP, scoped to the channel's domain; every other operation is
 * refused.  There is no backing unit, so the lookup carries a NULL requester.
 */
static void
lookup_channel_request(struct channel *channel,
    struct channel_message *request, void *context)
{
	struct svc_lookup_channel *lc;
	const struct svc_lookup_req *req;
	const uint32_t *opp;
	uint32_t op;
	int client_fd, error;

	(void)channel;
	lc = context;
	if (channel_message_fd_count(request) != 0 ||
	    channel_message_length(request) < sizeof(op)) {
		lookup_channel_reply(request, EINVAL, NULL, 0);
		goto out;
	}
	opp = channel_message_data(request);
	memcpy(&op, opp, sizeof(op));
	if (op != SVC_OP_LOOKUP) {
		/* A user-domain channel is a discovery channel only. */
		lookup_channel_reply(request, ENOTSUP, NULL, 0);
		goto out;
	}
	if (channel_message_length(request) != sizeof(*req)) {
		lookup_channel_reply(request, EINVAL, NULL, 0);
		goto out;
	}
	req = channel_message_data(request);
	if (req->flags != 0) {
		lookup_channel_reply(request, EINVAL, NULL, 0);
		goto out;
	}
	if (strnlen(req->name, sizeof(req->name)) >= sizeof(req->name)) {
		lookup_channel_reply(request, ENAMETOOLONG, NULL, 0);
		goto out;
	}
	client_fd = naming_lookup(req->name, NULL, &lc->domain, &error);
	if (client_fd < 0) {
		lookup_channel_reply(request, error, NULL, 0);
		goto out;
	}
	lookup_channel_reply(request, 0, &client_fd, 1);
	close(client_fd);
out:
	channel_message_free(request);
	lookup_channel_sync_events(lc, serviced_kq);
}

/*
 * Mint a fresh lookup channel bound to (kind, uid).  serviced keeps one end
 * (dispatched here, scoped to the channel's domain) and returns the other in
 * *out_fd as an ambient descriptor:
 *
 *   - CAP_CLOFORK_UNLOCKED: survives every fork;
 *   - FD_CLOEXEC cleared: survives exec;
 *   - usable in capability mode (it is a mac_capability channel endpoint).
 *
 * These properties let the boot/login path install it as a session leader's
 * inherited lookup channel so every descendant shares the same domain.  A
 * SYSTEM channel resolves every registered name (the channel serviced installs
 * before running /etc/rc); a USER channel resolves only the allow-list.
 * Returns 0 on success, -1 with errno set on failure.
 */
static int
domain_mint_channel(enum svc_domain_kind kind, uid_t uid, int *out_fd, int kq)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct svc_lookup_channel *lc;
	struct kevent change;
	int serviced_end, client_end, error;

	*out_fd = -1;
	/* Two endpoints plus one queued attachment on each. */
	if (serviced_fd_budget_check(4, "user-domain lookup channel") == -1)
		return (-1);
	lc = calloc(1, sizeof(*lc));
	if (lc == NULL)
		return (-1);
	lc->fd = -1;

	if (mac_cap_create_channel(&serviced_end, &client_end) != 0) {
		error = errno != 0 ? errno : EIO;
		free(lc);
		errno = error;
		return (-1);
	}

	options.max_pending_requests = 64;
	options.max_queued_messages = 256;
	options.max_queued_bytes = 1024 * 1024;
	options.max_queued_fds = 256;
	if (channel_create(serviced_end, &options, &lc->channel) == -1) {
		error = errno;
		close(serviced_end);
		close(client_end);
		free(lc);
		errno = error;
		return (-1);
	}
	lc->fd = channel_fd(lc->channel);
	lc->domain.kind = kind;
	lc->domain.uid = uid;
	if (channel_set_request_handler(lc->channel, lookup_channel_request,
	    lc) == -1) {
		error = errno;
		channel_destroy(lc->channel);
		close(client_end);
		free(lc);
		errno = error;
		return (-1);
	}

	EV_SET(&change, lc->fd, EVFILT_READ, EV_ADD, 0, 0, lc);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
		error = errno;
		channel_destroy(lc->channel);
		close(client_end);
		free(lc);
		errno = error;
		return (-1);
	}

	/*
	 * Make the caller's endpoint ambient: survive every fork, survive exec,
	 * remain usable in capability mode.  mac_cap_create_channel returns both
	 * ends close-on-exec; relax the caller's end while keeping serviced's own
	 * end confined.
	 */
	if (svc_fd_make_ambient(client_end) == -1) {
		error = errno;
		EV_SET(&change, lc->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &change, 1, NULL, 0, NULL);
		lookup_channel_close(lc);
		close(client_end);
		errno = error;
		return (-1);
	}

	lc->next = lookup_channels;
	lookup_channels = lc;

	if (kind == SVC_DOMAIN_USER)
		syslog(LOG_INFO,
		    "domain: minted user-domain lookup channel for uid %u",
		    (unsigned)uid);
	else
		syslog(LOG_INFO, "domain: minted system-domain lookup channel");
	*out_fd = client_end;
	return (0);
}

/*
 * Mint a USER-domain (per-uid) lookup channel — the narrowed channel a login
 * session is handed (§22.1).
 */
int
domain_mint_user_channel(uid_t uid, int *out_fd, int kq)
{

	return (domain_mint_channel(SVC_DOMAIN_USER, uid, out_fd, kq));
}

/*
 * Mint a SYSTEM-domain lookup channel — the ambient channel serviced installs
 * before exec'ing /etc/rc so rc, getty, login, and every other boot descendant
 * inherits system-wide service discovery (§21.1).  It resolves every registered
 * name; the login path narrows it per uid.
 */
int
domain_mint_system_channel(int *out_fd, int kq)
{

	return (domain_mint_channel(SVC_DOMAIN_SYSTEM, 0, out_fd, kq));
}

bool
domain_channel_owns_event(uintptr_t ident)
{

	return (lookup_channel_find(ident) != NULL);
}

void
domain_channel_event(struct kevent *kev, int kq)
{
	struct svc_lookup_channel *lc;

	lc = lookup_channel_find(kev->ident);
	if (lc == NULL)
		return;
	if (kev->flags & EV_EOF) {
		errno = ECONNRESET;
		goto dead;
	}
	if (kev->filter == EVFILT_WRITE) {
		if (channel_flush(lc->channel) == -1)
			goto dead;
	} else if (kev->filter == EVFILT_READ) {
		if (channel_dispatch(lc->channel) == -1)
			goto dead;
	}
	lookup_channel_sync_events(lc, kq);
	return;
dead:
	syslog(LOG_INFO, "domain: user-domain channel (uid %u) closed: %s",
	    (unsigned)lc->domain.uid, strerror(errno != 0 ? errno : ECONNRESET));
	lookup_channel_close(lc);
}

void
domain_channel_teardown(void)
{

	while (lookup_channels != NULL)
		lookup_channel_close(lookup_channels);
}
