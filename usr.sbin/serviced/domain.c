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
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
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
	"system.Log",		/* logging */
	"system.Notify",	/* notifications */
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
	if (op == SVC_OP_MINT_DOMAIN) {
		/*
		 * A session leader provisions its session's ambient channel
		 * (§21.3, §6): a login or su holding the SYSTEM channel mints the
		 * channel appropriate to the target principal — a per-uid USER
		 * channel for a regular user, or a SYSTEM (admin) channel for a
		 * root/wheel session.  Only a SYSTEM-domain channel may mint —
		 * domains only ever narrow, so a request arriving on an
		 * already-narrowed USER channel is refused; and a SYSTEM mint is
		 * refused unless this channel is itself SYSTEM.  This is the same
		 * operation handle_mint_domain() serves on a unit control channel;
		 * the ambient lookup channel has no backing unit, so it is served
		 * here.
		 */
		const struct svc_mint_domain_req *mreq;
		enum svc_domain_kind mkind;
		int minted_fd, merror;

		if (!svc_domain_may_mint(&lc->domain)) {
			lookup_channel_reply(request, EPERM, NULL, 0);
			goto out;
		}
		if (channel_message_length(request) != sizeof(*mreq)) {
			lookup_channel_reply(request, EINVAL, NULL, 0);
			goto out;
		}
		mreq = channel_message_data(request);
		if (mreq->flags != 0) {
			lookup_channel_reply(request, EINVAL, NULL, 0);
			goto out;
		}
		/*
		 * Escalation guard (§6): a SYSTEM mint is allowed only when this
		 * channel is itself SYSTEM.  svc_domain_may_mint() above already
		 * confirms that, so a USER channel is refused for both kinds; the
		 * explicit re-check here is the security boundary that must hold
		 * even if minting policy widens later.
		 */
		if (svc_mint_domain_kind(&lc->domain, mreq->domain,
		    &mkind) == -1) {
			lookup_channel_reply(request,
			    errno != 0 ? errno : EPERM, NULL, 0);
			goto out;
		}
		minted_fd = -1;
		if (domain_mint_session_channel(mkind, (uid_t)mreq->uid,
		    &minted_fd, serviced_kq) == -1)
			merror = errno != 0 ? errno : EIO;
		else
			merror = 0;
		lookup_channel_reply(request, merror,
		    merror == 0 ? &minted_fd : NULL, merror == 0 ? 1 : 0);
		if (merror == 0)
			close(minted_fd);
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

/*
 * Whether the target principal is an administrator (§6): root, or a member of
 * the "wheel" group.  Computed from the passwd/group database for the target
 * uid — getpwuid resolves its name and getgrouplist its full group set —
 * entirely independent of the requesting process's credentials, because
 * provisioning scopes by the TARGET uid, never the requester.  Mirrors the
 * principal_is_admin() helper login(1)/su(1) apply on the getty-inheritance
 * path.  Best-effort: any lookup failure fails safe to "not admin", i.e. the
 * narrower USER scope.
 */
static bool
domain_uid_is_admin(uid_t uid)
{
	gid_t groups[NGROUPS_MAX];
	struct passwd *pw;
	struct group *wheel;
	int ngroups, i;

	if (uid == 0)
		return (true);
	pw = getpwuid(uid);
	if (pw == NULL)
		return (false);
	if ((wheel = getgrnam("wheel")) == NULL)
		return (false);
	ngroups = nitems(groups);
	if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) == -1)
		ngroups = nitems(groups);	/* truncated: scan what fit */
	for (i = 0; i < ngroups && i < (int)nitems(groups); i++) {
		if (groups[i] == wheel->gr_gid)
			return (true);
	}
	return (false);
}

/*
 * Socket-authenticated session provisioning (§21/§22, item 4).  serviced's
 * control socket authenticates its peer with getpeereid(3) — a kernel-attested
 * euid — and the caller passes that euid here as requester_euid.  This is the
 * userspace analogue of the getty-inheritance mint that login(1)/su(1) perform
 * over an inherited SYSTEM channel, for the one login path that cannot inherit
 * one: an ssh network session, whose sshd fills fds 0-4 with /dev/null and
 * closefrom()s the rest at startup, destroying any inherited channel.
 *
 * AUTH (the security boundary): provisioning mints a channel that speaks for an
 * ARBITRARY target uid, so only root may request it.  A non-root requester is
 * refused with EPERM and no descriptor — the kernel-attested peer euid is the
 * whole gate.  (The over-channel mint path in lookup_channel_request() keeps
 * its own escalation guard: a USER session channel can never widen to SYSTEM.
 * This socket path is disjoint from that and does not weaken it.)
 *
 * SCOPE is chosen by the TARGET uid, never the requester: uid 0 or a wheel
 * member gets a SYSTEM (full-discovery admin) channel; every other uid gets a
 * per-uid USER channel that resolves only the user-domain allow-list.  So even
 * a root requester provisioning for a regular uid hands out a narrowed channel.
 *
 * DELIVERY: the endpoint is handed over with full transfer authority; serviced
 * does not pre-limit it.  Each sender closes its own copy after the SCM_RIGHTS
 * send (the control-socket handler; sshd's monitor relay), and the session leaf
 * simply holds it — the single-transfer model.
 *
 * Non-fatal: every failure returns -1 with errno set, leaving serviced running.
 */
int
domain_provision_session(uid_t requester_euid, uid_t target_uid, int *out_fd,
    int kq)
{
	enum svc_domain_kind kind;

	*out_fd = -1;

	/* AUTH: only the root peer may provision for an arbitrary uid. */
	if (requester_euid != 0) {
		errno = EPERM;
		return (-1);
	}

	/* SCOPE by target uid: admin (SYSTEM) for root/wheel, else USER. */
	kind = domain_uid_is_admin(target_uid) ? SVC_DOMAIN_SYSTEM :
	    SVC_DOMAIN_USER;

	if (domain_mint_session_channel(kind, target_uid, out_fd, kq) == -1)
		return (-1);

	/* Handed over with full authority; see the delivery note above. */
	return (0);
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
