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
 * every registered name; a user domain resolves only names whose provider
 * opted into user visibility (manifest resolvable_by = ["user"]) plus (in
 * future) user-scoped services, and reports every other name as ENOENT —
 * indistinguishable from an unregistered name.
 *
 * This file also owns the serviced-held end of minted user-domain lookup
 * channels.  SVC_OP_MINT_DOMAIN hands the caller a narrowed channel; serviced
 * keeps the other end here, dispatches SVC_OP_LOOKUP arriving on it, and scopes
 * each lookup to the channel's domain.  The channel carries no backing process,
 * so it serves lookups only — never name registration or readiness.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "fd_budget.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"
#include "register_lookup_gate.h"

/*
 * Whether a name's provider opts into USER-domain visibility.
 *
 * The set of system names a user session may resolve is no longer a list baked
 * into serviced: it is a per-provider manifest policy.  A unit declares
 * `resolvable_by = ["user"]` to expose its provides names to narrowed
 * USER-domain lookup channels; every other name stays SYSTEM-only and a user
 * session never discovers it (reported as ENOENT, indistinguishable from an
 * unregistered name).
 *
 * The decision is read from the bundle registry, which indexes every provides
 * name to its unit manifest whether or not the provider is currently running —
 * so this answers correctly on both the resolve path (provider up) and the
 * on-demand path (provider still stopped).  An unknown name is not
 * user-resolvable.
 */
static bool
svc_name_user_resolvable(const char *name)
{
	unsigned bi, si;
	struct capbundle *b;
	const struct capbundle_service *s;

	if (name == NULL || bundle_registry_lookup(name, &bi, &si) != 0)
		return (false);
	b = bundle_registry_get(bi);
	if (b == NULL)
		return (false);
	s = capbundle_service(b, si);
	return (capbundle_svc_user_resolvable(s));
}

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

static void lookup_channel_request(struct channel *channel,
    struct channel_message *request, void *context);
static struct svc_lookup_channel *lookup_channel_adopt(int serviced_end,
    enum svc_domain_kind kind, uid_t uid, int kq);

/*
 * Decide whether a domain may resolve a name.  Checked before the registry is
 * consulted, so an out-of-scope name is reported exactly as an unregistered
 * one.  A NULL or SYSTEM domain resolves everything (the default authority);
 * a USER domain resolves only names whose provider opted into user visibility
 * (user-scoped services do not yet exist).  Domains only narrow, so this only
 * ever removes names.
 */
bool
svc_domain_resolves(const struct svc_domain *domain, const char *name)
{

	if (domain == NULL || domain->kind == SVC_DOMAIN_SYSTEM)
		return (true);
	/* SVC_DOMAIN_USER: only names whose provider opts into user visibility. */
	return (svc_name_user_resolvable(name));
}

/*
 * A control name is one whose final dot-component is "Control"
 * (service.Control, storage.Control, lifecycle.Control).  Like the reserved
 * "helper." prefix, this namespace is structural: a control name is registered
 * in SVC_DOMAIN_CONTROL and is invisible to SYSTEM/USER lookups, and a CONTROL
 * channel resolves nothing else.  This keeps the admin control plane a set of
 * ordinary capability names reachable only by a held CONTROL channel — no
 * getpeereid, no socket path.
 */
bool
name_is_control(const char *name)
{
	const char *dot;

	if (name == NULL)
		return (false);
	/*
	 * The "helper." namespace is already reserved (bundle-private helpers);
	 * a helper unit named "Control" must not be reinterpreted as a control
	 * name.  The two reserved namespaces are disjoint.
	 */
	if (strncmp(name, "helper.", 7) == 0)
		return (false);
	dot = strrchr(name, '.');
	return (dot != NULL && strcmp(dot + 1, "Control") == 0);
}

/*
 * Whether a channel of domain `chan` may resolve a *registered* name whose own
 * registered domain is `name_domain`.  This is the structural separation: a
 * control name resolves ONLY through a CONTROL channel; a CONTROL channel
 * resolves ONLY control names; SYSTEM/USER behave as before for non-control
 * names (SYSTEM resolves all, USER by per-provider manifest visibility).
 */
bool
svc_domain_permits(const struct svc_domain *chan,
    enum svc_domain_kind name_domain, const char *name)
{

	if (name_domain == SVC_DOMAIN_CONTROL)
		return (chan != NULL && chan->kind == SVC_DOMAIN_CONTROL);
	/* Non-control (SYSTEM) name. */
	if (chan != NULL && chan->kind == SVC_DOMAIN_CONTROL)
		return (false);
	return (svc_domain_resolves(chan, name));
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
 * Resolve a SVC_OP_MINT_DOMAIN request's wire `domain` field to the domain kind
 * to mint, enforcing the SYSTEM-mint escalation guard (§6): minting a SYSTEM
 * (full-discovery admin) channel is a privilege, so it is permitted only when
 * the REQUESTING channel is itself SYSTEM.  A USER channel that asks for SYSTEM
 * is refused with EPERM — it can never widen its own scope.  A USER mint is
 * always in-policy for a caller that may mint at all (svc_domain_may_mint()
 * already gates that a USER channel cannot mint anything).
 *
 * Returns 0 with *kind set on success; -1 with errno set on failure: EPERM for
 * a non-SYSTEM channel requesting SYSTEM, EINVAL for an unknown domain value.
 * A NULL requester is treated as SYSTEM (the default authority).
 */
int
svc_mint_domain_kind(const struct svc_domain *requester, uint32_t wire_domain,
    enum svc_domain_kind *kind)
{

	switch (wire_domain) {
	case SVC_MINT_DOMAIN_USER:
		*kind = SVC_DOMAIN_USER;
		return (0);
	case SVC_MINT_DOMAIN_SYSTEM:
		if (requester != NULL && requester->kind != SVC_DOMAIN_SYSTEM) {
			errno = EPERM;
			return (-1);
		}
		*kind = SVC_DOMAIN_SYSTEM;
		return (0);
	case SVC_MINT_DOMAIN_CONTROL:
		/*
		 * A CONTROL channel is a sibling of SYSTEM, not a widening of it:
		 * only an admin session (which holds a SYSTEM channel) may mint
		 * one, and login/su gate that request on the principal being
		 * root/wheel.  A USER channel may mint neither.
		 */
		if (requester != NULL && requester->kind != SVC_DOMAIN_SYSTEM) {
			errno = EPERM;
			return (-1);
		}
		*kind = SVC_DOMAIN_CONTROL;
		return (0);
	default:
		errno = EINVAL;
		return (-1);
	}
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

	/*
	 * Drop any on-demand lookups still parked on this channel before the
	 * channel (and the retained request tokens that reference it) go away,
	 * or the deferred reply would touch freed channel state.
	 */
	on_demand_lookup_channel_gone(lc, serviced_kq);
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

/*
 * Whether `lc` is still a live, registered lookup channel.  on_demand uses this
 * to confirm an ambient requester survived the async activation gap before
 * replying over its channel.
 */
bool
lookup_channel_is_live(const struct svc_lookup_channel *lc)
{
	const struct svc_lookup_channel *p;

	for (p = lookup_channels; p != NULL; p = p->next) {
		if (p == lc)
			return (true);
	}
	return (false);
}

void
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
lookup_channel_reply_ex(struct channel_message *request, int status, int *fds,
    size_t nfds, bool cap_xfer)
{
	struct svc_reply reply;
	size_t i;

	reply.status = status;
	for (i = 0; cap_xfer && i < nfds; i++) {
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

static void
lookup_channel_reply(struct channel_message *request, int status, int *fds,
    size_t nfds)
{

	lookup_channel_reply_ex(request, status, fds, nfds, true);
}

/*
 * Whether a descriptor is an open mac_capability channel.  A cheap GETINFO gate
 * used before adopting a client-supplied endpoint as a private lookup channel:
 * a non-channel fd (a pipe, a socket, a regular file) fails GETINFO and is
 * rejected.  It does not — and need not — prove the fd is one end of a pair the
 * caller made: adoption grants no authority beyond the arriving channel's own
 * domain, so a self-connected or unrelated channel would only ever serve the
 * caller its own scope.
 */
static bool
fd_is_mac_capability_channel(int fd)
{
	struct mac_capability_info_args info;

	if (fd < 0)
		return (false);
	memset(&info, 0, sizeof(info));
	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
}

/*
 * Handle SVC_OP_REGISTER_LOOKUP arriving on the lookup channel `lc`
 * (docs/capability-ambient-lookup-per-process.md, P2).  The request carries
 * exactly one descriptor: an endpoint of a channel pair the client created for
 * itself.  serviced adopts it as a private per-client lookup channel scoped to
 * `lc`'s domain — the domain of the channel the request ARRIVED on, never a
 * wire value — so the client gets its current discovery scope privately, never
 * a wider one.  On success serviced pushes an ACK on the ADOPTED (private)
 * channel; nothing is ever replied on the arriving shared channel, so the
 * client never receives on the shared queue and cannot hit the reply-discard
 * race.  A malformed or non-channel request is rejected silently (the fd is
 * closed, no adoption); the client falls back on its own lookup timeout.
 *
 * Does NOT free `request` (the caller's out: path does) but consumes every
 * attached descriptor.
 */
static void
lookup_channel_register(struct svc_lookup_channel *lc,
    struct channel_message *request)
{
	const struct svc_register_lookup_req *req;
	struct svc_lookup_channel *adopted;
	struct svc_register_lookup_ack ack;
	enum svc_domain_kind adopt_kind;
	size_t nfds, i;
	uint32_t flags;
	int fd, extra, error;

	nfds = channel_message_fd_count(request);
	flags = 0;
	if (channel_message_length(request) == sizeof(*req)) {
		req = channel_message_data(request);
		flags = req->flags;
	}

	/*
	 * Take the (expected single) descriptor first so every rejection path
	 * closes it, and drain any extras a malformed request over-attached so
	 * none leak.  The shape check below rejects any count other than one.
	 */
	fd = nfds >= 1 ? channel_message_take_fd(request, 0) : -1;
	for (i = 1; i < nfds; i++) {
		extra = channel_message_take_fd(request, i);
		if (extra >= 0)
			(void)close(extra);
	}

	error = svc_register_lookup_check(channel_message_length(request), nfds,
	    fd_is_mac_capability_channel(fd), flags, lc->domain.kind,
	    &adopt_kind);
	if (error != 0)
		goto reject;

	/* Two endpoints of accounting: the adopted fd and the channel's dup. */
	if (serviced_fd_budget_check(2, "registered lookup channel") == -1) {
		error = errno != 0 ? errno : ENFILE;
		goto reject;
	}

	adopted = lookup_channel_adopt(fd, adopt_kind, lc->domain.uid,
	    serviced_kq);
	if (adopted == NULL) {
		/* adopt closed/owns fd on both success and failure. */
		syslog(LOG_WARNING,
		    "domain: adopt registered lookup channel: %m");
		return;
	}

	ack.op = SVC_OP_REGISTER_LOOKUP;
	ack.status = 0;
	ack.magic = SVC_REGISTER_LOOKUP_MAGIC;
	if (channel_send_event(adopted->channel,
	    &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &ack,
		.length = sizeof(ack),
		.fds = NULL,
		.nfds = 0
	    }) == -1)
		syslog(LOG_WARNING, "domain: register-lookup ack: %m");
	lookup_channel_sync_events(adopted, serviced_kq);
	syslog(LOG_INFO, "domain: adopted private %s lookup channel",
	    adopt_kind == SVC_DOMAIN_SYSTEM ? "system" :
	    adopt_kind == SVC_DOMAIN_CONTROL ? "control" : "user");
	return;

reject:
	if (fd >= 0)
		(void)close(fd);
	syslog(LOG_NOTICE, "domain: reject register-lookup: %s",
	    strerror(error));
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
	const char *kindstr;
	uint32_t op;
	bool sendable;
	int client_fd, error;

	(void)channel;
	lc = context;
	kindstr = lc->domain.kind == SVC_DOMAIN_SYSTEM ? "system" :
	    lc->domain.kind == SVC_DOMAIN_CONTROL ? "control" : "user";
	if (channel_message_length(request) < sizeof(op)) {
		lookup_channel_reply(request, EINVAL, NULL, 0);
		goto out;
	}
	opp = channel_message_data(request);
	memcpy(&op, opp, sizeof(op));
	if (op == SVC_OP_REGISTER_LOOKUP) {
		/*
		 * The only op that carries a descriptor.  It adopts that
		 * descriptor as a private per-client lookup channel and ACKs on
		 * the ADOPTED channel — never here on the arriving (shared)
		 * channel, which is exactly what keeps the client off the shared
		 * receive queue (the reply-discard race).  Consumes the attached
		 * fd; out: frees the request message.
		 */
		lookup_channel_register(lc, request);
		goto out;
	}
	/* Every other op carries no descriptor. */
	if (channel_message_fd_count(request) != 0) {
		lookup_channel_reply(request, EINVAL, NULL, 0);
		goto out;
	}
	if (op == SVC_OP_MINT_DOMAIN) {
		/*
		 * Direct minting over an ambient lookup channel is RETIRED (P1c).
		 * The auth-agent (system.authagent) is the single mint boundary:
		 * it mints session channels over its own unit bootstrap channel
		 * (handle_mint_domain() in svc_proto.c), and a session leader
		 * reaches it by LOOKUP over this channel.  login/su/sshd therefore
		 * can no longer mint their own session channel here — even the
		 * SYSTEM ambient carry serviced hands getty is now lookup-only for
		 * this op.  Refused unconditionally; the primitives
		 * (svc_domain_may_mint / svc_mint_domain_kind) remain for the
		 * bootstrap-channel path that still uses them.
		 */
		lookup_channel_reply(request, EPERM, NULL, 0);
		goto out;
	}
	if (op == SVC_OP_AMBIENT_HELLO) {
		/*
		 * Behavioral handshake (§11a D1): confirm to a probing inheritor
		 * that this really is a serviced ambient LOOKUP channel.  Only a
		 * lookup channel answers with the magic ack; a unit control
		 * channel's dispatcher (svc_proto.c) has no case for this op and
		 * returns ENOTSUP from its default, which is exactly how the
		 * probe tells the two fd-3 channels apart.  Served on BOTH SYSTEM
		 * and USER lookup channels — either is a valid ambient carrier.
		 */
		struct svc_ambient_hello_reply hello;

		if (channel_message_length(request) !=
		    sizeof(struct svc_ambient_hello_req)) {
			lookup_channel_reply(request, EINVAL, NULL, 0);
			goto out;
		}
		hello.status = 0;
		hello.magic = SVC_AMBIENT_HELLO_MAGIC;
		if (channel_send_reply(request,
		    &(struct channel_outgoing){
			.size = sizeof(struct channel_outgoing),
			.data = &hello,
			.length = sizeof(hello),
			.fds = NULL,
			.nfds = 0
		    }) == -1)
			syslog(LOG_WARNING, "domain: hello reply: %m");
		goto out;
	}
	if (op != SVC_OP_LOOKUP) {
		/* Any other op on a lookup channel is unsupported. */
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
	/*
	 * The reserved "helper." namespace is private to a bundle and reachable
	 * only through SVC_OP_HELPER_OPEN, never global lookup.  handle_lookup()
	 * enforces this on the per-provider channel; the ambient lookup channel
	 * (which resolves everything on a SYSTEM domain) must enforce it too, or
	 * a SYSTEM-domain holder could reach another bundle's private helper.
	 */
	if (strncmp(req->name, "helper.", 7) == 0) {
		lookup_channel_reply(request, EACCES, NULL, 0);
		goto out;
	}
	client_fd = naming_lookup(req->name, NULL, &lc->domain, &error,
	    &sendable);
	if (client_fd < 0) {
		/*
		 * A miss on an on-demand name activates its provider, exactly as
		 * a service-to-service lookup does (svc_proto.c handle_lookup).
		 * on_demand_launch_ambient() takes ownership of `request` and
		 * replies over this lookup channel once the provider checks in;
		 * return without freeing so the reply token survives.  Domain
		 * scope is carried by value so activation stays scoped to this
		 * channel's authority.
		 */
		if (error == ENOENT &&
		    on_demand_launch_ambient(req->name, lc, &lc->domain,
		    request, serviced_kq) == 0)
			return;
		/*
		 * EACCES means out-of-scope for this channel's domain: fail fast
		 * (no on-demand) and report ENOENT so the client cannot tell an
		 * out-of-scope name from an unregistered one.  The probe records
		 * the TRUE error (EACCES) the wire masks, so tracing can see the
		 * out-of-scope refusal the client is deliberately not told about.
		 */
		SERVICED_PROBE_DOMAIN_LOOKUP_DENY(req->name, kindstr, error);
		lookup_channel_reply(request, error == EACCES ? ENOENT : error,
		    NULL, 0);
		goto out;
	}
	SERVICED_PROBE_DOMAIN_LOOKUP(req->name, kindstr, lc->domain.uid);
	lookup_channel_reply_ex(request, 0, &client_fd, 1, !sendable);
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
 * before running /etc/rc); a USER channel resolves only user-visible names.
 * Returns 0 on success, -1 with errno set on failure.
 */
/*
 * Adopt a serviced-held channel endpoint as a lookup channel scoped to
 * (kind, uid): wrap it, dispatch its requests through lookup_channel_request(),
 * register it for read readiness on the event loop, and link it into the
 * lookup_channels list.  This is the shared core of BOTH the mint path
 * (domain_mint_channel(), which creates the pair itself) and the
 * adopt-received-fd path (lookup_channel_register(), which is handed a
 * client-made endpoint over SVC_OP_REGISTER_LOOKUP).
 *
 * Takes ownership of serviced_end: on success it is owned by the returned lc
 * (channel_create() holds its own duplicate); on failure it is closed and NULL
 * is returned with errno set.  The caller owns fd-budget accounting and (mint
 * path) the peer endpoint.
 */
static struct svc_lookup_channel *
lookup_channel_adopt(int serviced_end, enum svc_domain_kind kind, uid_t uid,
    int kq)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct svc_lookup_channel *lc;
	struct kevent change;
	int error;

	lc = calloc(1, sizeof(*lc));
	if (lc == NULL) {
		error = errno;
		(void)close(serviced_end);
		errno = error;
		return (NULL);
	}
	lc->fd = -1;
	lc->domain.kind = kind;
	lc->domain.uid = uid;

	options.max_pending_requests = 64;
	options.max_queued_messages = 256;
	options.max_queued_bytes = 1024 * 1024;
	options.max_queued_fds = 256;
	if (channel_create(serviced_end, &options, &lc->channel) == -1) {
		error = errno;
		(void)close(serviced_end);
		free(lc);
		errno = error;
		return (NULL);
	}
	/* channel_create() consumed serviced_end (owns its own duplicate). */
	lc->fd = channel_fd(lc->channel);
	if (channel_set_request_handler(lc->channel, lookup_channel_request,
	    lc) == -1) {
		error = errno;
		channel_destroy(lc->channel);
		free(lc);
		errno = error;
		return (NULL);
	}

	EV_SET(&change, lc->fd, EVFILT_READ, EV_ADD, 0, 0, lc);
	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
		error = errno;
		channel_destroy(lc->channel);
		free(lc);
		errno = error;
		return (NULL);
	}

	lc->next = lookup_channels;
	lookup_channels = lc;
	return (lc);
}

static int
domain_mint_channel(enum svc_domain_kind kind, uid_t uid, int *out_fd, int kq)
{
	struct svc_lookup_channel *lc;
	int serviced_end, client_end, error;

	*out_fd = -1;
	/* Two endpoints plus one queued attachment on each. */
	if (serviced_fd_budget_check(4, "user-domain lookup channel") == -1)
		return (-1);

	if (mac_cap_create_channel(&serviced_end, &client_end) != 0) {
		error = errno != 0 ? errno : EIO;
		errno = error;
		return (-1);
	}

	lc = lookup_channel_adopt(serviced_end, kind, uid, kq);
	if (lc == NULL) {
		error = errno;
		/* adopt consumed/closed serviced_end; close the peer. */
		(void)close(client_end);
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
		lookup_channel_close(lc);
		(void)close(client_end);
		errno = error;
		return (-1);
	}

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

/*
 * Mint the session channel a mint request selected (§6): SVC_DOMAIN_USER binds
 * the recorded uid, SVC_DOMAIN_SYSTEM ignores it (a SYSTEM channel resolves
 * every name, so uid is meaningless and recorded as 0).  The caller has already
 * run svc_mint_domain_kind() to authorize the requested kind.
 */
int
domain_mint_session_channel(enum svc_domain_kind kind, uid_t uid, int *out_fd,
    int kq)
{

	return (domain_mint_channel(kind,
	    kind == SVC_DOMAIN_USER ? uid : 0, out_fd, kq));
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
