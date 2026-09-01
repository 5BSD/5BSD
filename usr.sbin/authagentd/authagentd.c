/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authagentd — the identity->capability mint boundary (system.authagent).
 *
 * A capsicum-sandboxed capability service.  A login program (login/su/sshd),
 * after authenticating a principal, connects to system.authagent and asks for
 * that session's capability bundle.  authagentd applies the principal->bundle
 * policy (capbundle_principal_is_admin) and mints the scoped session lookup
 * channel over its OWN bootstrap channel to serviced, then forwards it to the
 * login program.  The login program never holds mint authority itself.  See
 * docs/auth-agent-design.md.
 */

#include <sys/types.h>
#include <sys/capsicum.h>	/* cap_xfer_limit, CAP_XFER_ONCE */
#include <sys/event.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcasper.h>
#include <casper/cap_grp.h>
#include <casper/cap_pwd.h>

#include <channel.h>
#include <libservice.h>
#include <libcapbundle.h>

#include <authagent_proto.h>

/* Our own consumer handle on the bootstrap channel, used to mint. */
static struct service_context	*g_context;
static int			 g_kq = -1;
/*
 * The admin policy, delivered as a read-only descriptor (capabilities.open) so
 * the daemon never opens a path in capability mode.  -1 when absent, in which
 * case capbundle_principal_is_admin_fd applies the historical root-or-wheel
 * default.
 */
static int			 g_policy_fd = -1;
/*
 * Casper channels for authoritative passwd/group resolution inside the sandbox.
 * The agent NEVER trusts principal attributes from the wire — it resolves the
 * uid to its passwd and group membership itself, so a compromised login client
 * cannot claim admin membership it does not have.
 */
static cap_channel_t		*g_cappwd;
static cap_channel_t		*g_capgrp;

/* Group-name -> gid for the policy engine, backed by Casper cap_grp. */
static gid_t
agent_name2gid(void *ctx, const char *name)
{
	cap_channel_t *grp = ctx;
	struct group *gr;

	if (grp == NULL || (gr = cap_getgrnam(grp, name)) == NULL)
		return ((gid_t)-1);
	return (gr->gr_gid);
}

/*
 * Resolve a principal's group membership authoritatively via Casper: its
 * primary gid plus every group whose member list names it.  cap_grp exposes no
 * getgrouplist, so scan the group database (a mint is infrequent).
 */
static unsigned
agent_member_gids(const struct passwd *pw, gid_t *out, unsigned max)
{
	struct group *gr;
	unsigned n = 0;

	if (max == 0)
		return (0);
	out[n++] = pw->pw_gid;
	if (g_capgrp == NULL)
		return (n);
	(void)cap_setgrent(g_capgrp);	/* rewind; a bad rewind just yields none */
	while (n < max && (gr = cap_getgrent(g_capgrp)) != NULL) {
		char **m;

		if (gr->gr_gid == pw->pw_gid)
			continue;
		for (m = gr->gr_mem; m != NULL && *m != NULL; m++)
			if (strcmp(*m, pw->pw_name) == 0) {
				out[n++] = gr->gr_gid;
				break;
			}
	}
	return (n);
}

/*
 * One connected login program.  The channel's fd is the kqueue key; udata
 * distinguishes it from the listener (whose udata is the listener pointer).
 */
struct client {
	TAILQ_ENTRY(client)	entry;
	int			fd;
	struct channel		*chan;
};
static TAILQ_HEAD(, client) clients = TAILQ_HEAD_INITIALIZER(clients);

static void
client_destroy(struct client *c)
{
	struct kevent kev;

	EV_SET(&kev, c->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
	EV_SET(&kev, c->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
	if (c->chan != NULL)
		channel_destroy(c->chan);
	TAILQ_REMOVE(&clients, c, entry);
	free(c);
}

/* Track the channel's queued-output state in the kqueue write filter. */
static void
client_sync_events(struct client *c)
{
	struct kevent kev;
	int wants;

	wants = channel_wants_write(c->chan);
	if (wants == -1)
		return;
	EV_SET(&kev, c->fd, EVFILT_WRITE,
	    EV_ADD | (wants ? EV_ENABLE : EV_DISABLE), 0, 0, c);
	(void)kevent(g_kq, &kev, 1, NULL, 0, NULL);
}

/*
 * Serve one AUTHAGENT_OP_MINT_SESSION request.  No credential is trusted from
 * the wire: the scope is derived from policy applied to the named principal.
 * The minted fd is delivered transferable by serviced (RESEND) and re-attenuated
 * here to CAP_XFER_ONCE, so the single reply send consumes it to CAP_XFER_NONE
 * at the login program — the session leaf cannot re-delegate its lookup channel.
 */
static void
handle_request(struct channel *ch __unused, struct channel_message *request,
    void *arg)
{
	struct client *c = arg;
	const struct authagent_mint_req *req;
	struct authagent_mint_reply reply;
	struct passwd *pw;
	const void *data;
	size_t len;
	int fd = -1;

	memset(&reply, 0, sizeof(reply));
	data = channel_message_data(request);
	len = channel_message_length(request);

	if (channel_message_fd_count(request) != 0 || data == NULL ||
	    len != sizeof(*req)) {
		reply.status = EINVAL;
	} else {
		req = data;
		if (req->version != AUTHAGENTD_PROTO_VERSION ||
		    req->op != AUTHAGENT_OP_MINT_SESSION ||
		    (req->flags & ~AUTHAGENT_FLAG_FORWARDABLE) != 0) {
			reply.status = EINVAL;
		} else if ((pw = cap_getpwuid(g_cappwd,
		    (uid_t)req->uid)) == NULL) {
			reply.status = ENOENT;
		} else {
			gid_t members[NGROUPS_MAX];
			unsigned nmember = agent_member_gids(pw, members,
			    nitems(members));
			bool forwardable =
			    (req->flags & AUTHAGENT_FLAG_FORWARDABLE) != 0;
			enum service_mint_kind kind =
			    capbundle_principal_is_admin_resolved(g_policy_fd,
			    (uid_t)req->uid, members, nmember, agent_name2gid,
			    g_capgrp) ? SERVICE_MINT_SYSTEM : SERVICE_MINT_USER;

			/*
			 * A session leaf (login/su) receives the channel
			 * non-transferable: attenuate to CAP_XFER_ONCE so the
			 * reply's own SCM_RIGHTS send consumes it to
			 * CAP_XFER_NONE at the caller.  A forwarding caller
			 * (sshd monitor) receives it still-transferable and
			 * re-attenuates before its own single forward.
			 */
			if (service_context_mint_domain(g_context, kind,
			    (uid_t)req->uid, &fd) == 0 && fd >= 0 &&
			    (forwardable ||
			    cap_xfer_limit(fd, CAP_XFER_ONCE) == 0)) {
				reply.status = 0;
			} else {
				reply.status = errno != 0 ? errno : EIO;
				if (fd >= 0) {
					close(fd);
					fd = -1;
				}
			}
			syslog(LOG_INFO, "mint %s uid=%u -> %d",
			    kind == SERVICE_MINT_SYSTEM ? "system" : "user",
			    (unsigned)req->uid, reply.status);
		}
	}

	if (channel_send_reply(request, &(struct channel_outgoing){
		.size = sizeof(struct channel_outgoing),
		.data = &reply,
		.length = sizeof(reply),
		.fds = reply.status == 0 ? &fd : NULL,
		.nfds = reply.status == 0 ? 1 : 0,
	    }) == -1)
		syslog(LOG_WARNING, "reply: %m");
	if (fd >= 0)
		close(fd);
	client_sync_events(c);
}

static int
client_adopt(int client_fd)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct client *c;
	struct kevent kev;
	int error;

	options.max_pending_requests = 8;
	options.max_queued_messages = 32;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 4;

	c = calloc(1, sizeof(*c));
	if (c == NULL) {
		close(client_fd);
		return (-1);
	}
	if (channel_create(client_fd, &options, &c->chan) == -1) {
		error = errno;
		free(c);
		close(client_fd);
		errno = error;
		return (-1);
	}
	c->fd = channel_fd(c->chan);
	if (channel_set_request_handler(c->chan, handle_request, c) == -1) {
		error = errno;
		channel_destroy(c->chan);
		free(c);
		errno = error;
		return (-1);
	}
	TAILQ_INSERT_TAIL(&clients, c, entry);
	EV_SET(&kev, c->fd, EVFILT_READ, EV_ADD, 0, 0, c);
	if (kevent(g_kq, &kev, 1, NULL, 0, NULL) == -1) {
		client_destroy(c);
		return (-1);
	}
	return (0);
}

int
main(void)
{
	struct service_provider *provider;
	struct service_listener *listener;
	struct service_identity identity;
	struct kevent event, change;
	int fd;

	openlog("authagentd", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);

	g_kq = kqueuex(KQUEUE_CLOEXEC);
	if (g_kq == -1 ||
	    service_provider_create(&provider) == -1 ||
	    service_acquire(&g_context) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, AUTHAGENTD_NAME, &listener) == -1)
		err(1, "initialize");

	/*
	 * Adopt the admin policy file from the filesystem daemon (tzfsd): ask it
	 * to open /Capabilities/Config/principal-policy.ucl on our behalf and hand
	 * back a read-only descriptor.  Nothing is declared in the manifest;
	 * tzfsd's own per-label policy decides whether this service may read it.
	 * It is optional: an unreadable or ungranted policy leaves g_policy_fd ==
	 * -1 and the mint path falls back to the historical root-or-wheel default.
	 * Done before cap_enter so no path is ever consulted at request time.
	 */
	if (service_open_isolated(g_context,
	    "/Capabilities/Config/principal-policy.ucl", SERVICE_OPEN_READ, 0,
	    &g_policy_fd) == -1)
		g_policy_fd = -1;

	/*
	 * Bring up Casper before entering the sandbox so the agent can resolve
	 * a uid to its passwd and group membership authoritatively after
	 * cap_enter — the security basis for not trusting the login client's
	 * claims.  Limited to exactly the lookups the mint decision needs.
	 */
	{
		static const char *const pwdcmds[] = { "getpwuid" };
		static const char *const grpcmds[] = { "getgrnam",
		    "setgrent", "getgrent" };
		cap_channel_t *capcas = cap_init();

		if (capcas == NULL ||
		    (g_cappwd = cap_service_open(capcas, "system.pwd")) ==
		    NULL ||
		    (g_capgrp = cap_service_open(capcas, "system.grp")) == NULL)
			err(1, "casper");
		cap_close(capcas);
		if (cap_pwd_limit_cmds(g_cappwd, pwdcmds, nitems(pwdcmds)) < 0 ||
		    cap_grp_limit_cmds(g_capgrp, grpcmds, nitems(grpcmds)) < 0)
			err(1, "casper limit");
	}

	EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, listener);
	if (kevent(g_kq, &change, 1, NULL, 0, NULL) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		err(1, "initialize");

	for (;;) {
		if (kevent(g_kq, NULL, 0, &event, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}
		if (event.udata == listener) {
			memset(&identity, 0, sizeof(identity));
			identity.size = sizeof(identity);
			if (service_listener_accept(listener, &identity,
			    &fd) == -1) {
				if (errno == EINTR)
					continue;
				if (service_provider_quiescing(provider) == 1)
					break;
				syslog(LOG_WARNING, "accept: %m");
				continue;
			}
			if (client_adopt(fd) == -1)
				syslog(LOG_WARNING, "adopt client: %m");
			continue;
		}
		/* A connected login program's channel. */
		{
			struct client *c = event.udata;

			if (event.flags & EV_EOF) {
				client_destroy(c);
				continue;
			}
			if (event.filter == EVFILT_WRITE) {
				if (channel_flush(c->chan) == -1) {
					client_destroy(c);
					continue;
				}
			} else if (event.filter == EVFILT_READ) {
				if (channel_dispatch(c->chan) == -1) {
					client_destroy(c);
					continue;
				}
			}
			client_sync_events(c);
		}
	}

	return (service_provider_quiesce_complete(provider, 0) == 0 ? 0 : 1);
}
