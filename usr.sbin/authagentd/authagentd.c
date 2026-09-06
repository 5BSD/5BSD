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
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>
#include <libservice.h>
#include <libcapbundle.h>

#include <authagent_proto.h>

#include "authagentd_test.h"

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
 * In-process NSS for authoritative passwd/group resolution inside the sandbox.
 * The agent NEVER trusts principal attributes from the wire — it resolves the
 * uid to its passwd and group membership itself, so a compromised login client
 * cannot claim admin membership it does not have.
 *
 * The Identity fold: rather than a Casper zygote (system.pwd/system.grp), the
 * agent retains read-only descriptors on /etc/passwd and /etc/group, opened
 * before it enters capability mode.  Capability mode forbids opening a path,
 * but lseek+read on an already-open descriptor is legal, so each lookup reads a
 * fresh snapshot from the top and parses it — authoritative, Casper-free, and
 * live (a user added to a group takes effect with no restart; unbuffered raw
 * reads, unlike a cached stdio stream).  We only need uid/name/gid (fields
 * 0,2,3 of passwd; 0,2,3 plus the member list of group), at the same offsets in
 * the 7-field public passwd and 10-field master.passwd, so the parse is
 * format-agnostic.
 */
static int			 g_pwfd = -1;	/* /etc/passwd, read-only */
static int			 g_grfd = -1;	/* /etc/group, read-only */

/*
 * Bounded per-lookup snapshots.  Two independent buffers (passwd, group), never
 * used concurrently: the provider serves requests serially from one kqueue
 * loop, so file-scope statics are safe and avoid large stack frames.
 */
#define	ID_SNAP_MAX	(128 * 1024)
static char			 g_pwbuf[ID_SNAP_MAX];
static char			 g_grbuf[ID_SNAP_MAX];

#ifndef AUTHAGENTD_TESTING
/*
 * Open the identity databases.  authagentd is born in capability mode, so it
 * cannot open a path itself; it obtains read-only, seekable (CAP_READ|CAP_SEEK,
 * for the per-lookup pread snapshots) descriptors on demand through the
 * filesystem provider (service_open_isolated(3)), authorized by tzfsd's
 * per-label open policy.  Returns 0, or -1 with the descriptor(s) left -1 (a
 * resolution then fails closed -> the mint is denied).  Only main() calls this.
 */
static int
id_open_databases(void)
{

	if (service_open_isolated(g_context, "/etc/passwd", SERVICE_OPEN_READ,
	    0, &g_pwfd) == -1 ||
	    service_open_isolated(g_context, "/etc/group", SERVICE_OPEN_READ,
	    0, &g_grfd) == -1) {
		g_pwfd = g_grfd = -1;
		return (-1);
	}
	return (0);
}
#endif /* !AUTHAGENTD_TESTING */

/*
 * Read the retained descriptor from the top into buf as a fresh, NUL-terminated
 * snapshot.  Returns its length, or -1.  A file larger than the buffer is
 * truncated: a uid/group past the cap simply fails to resolve (fail-closed),
 * never a spurious grant.
 */
static ssize_t
id_snapshot(int fd, char *buf, size_t bufsz)
{
	size_t off = 0;
	ssize_t n;

	if (fd == -1 || lseek(fd, 0, SEEK_SET) == -1)
		return (-1);
	while (off < bufsz - 1) {
		n = read(fd, buf + off, bufsz - 1 - off);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
	return ((ssize_t)off);
}

/* uid -> passwd (name/uid/gid only), from /etc/passwd.  NULL if not found. */
static struct passwd *
id_getpwuid(uid_t uid)
{
	static struct passwd pw;
	static char namebuf[MAXLOGNAME + 1];
	char *cursor, *line, *p, *f_name, *f_uid, *f_gid;

	if (id_snapshot(g_pwfd, g_pwbuf, sizeof(g_pwbuf)) == -1)
		return (NULL);
	cursor = g_pwbuf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		(void)strsep(&p, ":");		/* password field, ignored */
		f_uid = strsep(&p, ":");
		f_gid = strsep(&p, ":");
		if (f_name == NULL || f_name[0] == '\0' ||
		    f_uid == NULL || f_gid == NULL)
			continue;
		if ((uid_t)strtoul(f_uid, NULL, 10) != uid)
			continue;
		(void)strlcpy(namebuf, f_name, sizeof(namebuf));
		memset(&pw, 0, sizeof(pw));
		pw.pw_name = namebuf;
		pw.pw_uid = uid;
		pw.pw_gid = (gid_t)strtoul(f_gid, NULL, 10);
		return (&pw);
	}
	return (NULL);
}

/* Group-name -> gid for the policy engine, from /etc/group.  -1 if absent. */
static gid_t
agent_name2gid(void *ctx __unused, const char *name)
{
	char *cursor, *line, *p, *f_name, *f_gid;

	if (name == NULL ||
	    id_snapshot(g_grfd, g_grbuf, sizeof(g_grbuf)) == -1)
		return ((gid_t)-1);
	cursor = g_grbuf;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		f_name = strsep(&p, ":");
		(void)strsep(&p, ":");		/* password field, ignored */
		f_gid = strsep(&p, ":");
		if (f_name == NULL || f_gid == NULL)
			continue;
		if (strcmp(f_name, name) == 0)
			return ((gid_t)strtoul(f_gid, NULL, 10));
	}
	return ((gid_t)-1);
}

/*
 * Resolve a principal's group membership authoritatively: its primary gid plus
 * every group whose member list names it.  Scan /etc/group (a mint is
 * infrequent), same as the former cap_grp enumeration.
 */
static unsigned
agent_member_gids(const struct passwd *pw, gid_t *out, unsigned max)
{
	char *cursor, *line, *p, *f_gid, *members, *m, *save;
	gid_t gid;
	unsigned n = 0;

	if (max == 0)
		return (0);
	out[n++] = pw->pw_gid;
	if (id_snapshot(g_grfd, g_grbuf, sizeof(g_grbuf)) == -1)
		return (n);
	cursor = g_grbuf;
	while (n < max && (line = strsep(&cursor, "\n")) != NULL) {
		if (line[0] == '\0' || line[0] == '#')
			continue;
		p = line;
		(void)strsep(&p, ":");		/* group name, ignored */
		(void)strsep(&p, ":");		/* password field, ignored */
		f_gid = strsep(&p, ":");
		members = p;			/* remainder: comma-separated */
		if (f_gid == NULL || members == NULL)
			continue;
		gid = (gid_t)strtoul(f_gid, NULL, 10);
		if (gid == pw->pw_gid)		/* primary already recorded */
			continue;
		for (m = strtok_r(members, ",", &save); m != NULL;
		    m = strtok_r(NULL, ",", &save)) {
			if (strcmp(m, pw->pw_name) == 0) {
				out[n++] = gid;
				break;
			}
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
	/*
	 * The connecting caller's identity, as stamped by serviced when it
	 * brokered this connection (naming.c) and delivered by
	 * service_listener_accept().  The mint gate in handle_request()
	 * consults `rights`; `client_label` is retained for audit logging.
	 */
	service_rights_t	rights;
	char			client_label[64];
};
static TAILQ_HEAD(, client) clients = TAILQ_HEAD_INITIALIZER(clients);

/*
 * The mint caller-gate predicate (docs/auth-agent-design.md, P1c), factored out
 * of handle_request() so the privilege-escalation regression is unit-testable
 * without a live plane.  A caller may ask us to mint iff serviced stamped
 * SERVICE_RIGHTS_ADMIN on its brokered session — the bit serviced (naming.c)
 * grants only to an ambient login-session lookup (requester==NULL) on a
 * full-discovery (root/wheel) channel, i.e. exactly and only the login family
 * (login/su/sshd).  Every ordinary unit, including a compromised SYSTEM unit
 * that looks us up over its own bootstrap channel, is stamped without the admin
 * bit and refused.  Fail closed: an unknown or empty identity (no rights) is
 * denied.  The gate logic is identical to its former inline form.
 */
bool
authagent_caller_allowed(service_rights_t rights)
{

	return (service_rights_allow(rights, SERVICE_RIGHTS_ADMIN));
}

/*
 * The SYSTEM-vs-USER mint decision, factored for unit testing.  A principal
 * that policy resolves as an administrator mints a full-discovery SYSTEM
 * channel; every other principal mints a per-uid USER channel.  Pure: the
 * caller supplies the resolved member gids and a group-name resolver, exactly
 * as handle_request() does from Casper.
 */
enum service_mint_kind
authagent_mint_kind(int policy_fd, uid_t uid, const gid_t *member_gids,
    unsigned nmember, capbundle_group_gid_fn name2gid, void *ctx)
{

	return (capbundle_principal_is_admin_resolved(policy_fd, uid,
	    member_gids, nmember, name2gid, ctx) ? SERVICE_MINT_SYSTEM :
	    SERVICE_MINT_USER);
}

#ifndef AUTHAGENTD_TESTING
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
#endif /* !AUTHAGENTD_TESTING */

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

	/*
	 * Caller gate — the mint boundary (docs/auth-agent-design.md, P1c).
	 * authagentd gates the MINTER (only its own whitelisted bootstrap
	 * channel can call serviced's SVC_OP_MINT_DOMAIN), but that says nothing
	 * about WHO may ask us to mint.  system.authagent is a plain SYSTEM name,
	 * so any serviced-managed SYSTEM unit could otherwise connect, send
	 * MINT_SESSION{uid=0}, and be handed a SYSTEM admin channel — the exact
	 * proxy escalation the serviced mint-gate was written to close.
	 *
	 * In this OS authority is a held right, not a name string.  serviced
	 * (naming.c) stamps SERVICE_RIGHTS_ADMIN on a brokered session only for
	 * an ambient login-session lookup (requester==NULL) on a SYSTEM
	 * (full-discovery, i.e. root/wheel) channel — which is exactly, and only,
	 * the channel the login family (login, su, sshd) reaches us over.  Every
	 * ordinary unit — including a compromised SYSTEM unit that looks us up
	 * over its own bootstrap channel — is stamped requester!=NULL and thus
	 * WITHOUT the admin bit.  Gate on that right and fail closed: any caller
	 * that does not hold SERVICE_RIGHTS_ADMIN (unknown/empty identity
	 * included) is refused before we mint or even parse the request.
	 */
	if (!authagent_caller_allowed(c->rights)) {
		syslog(LOG_AUTHPRIV | LOG_WARNING,
		    "mint denied: caller '%.*s' lacks authenticator authority",
		    (int)sizeof(c->client_label), c->client_label);
		reply.status = EPERM;
		goto send_reply;
	}

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
		} else if ((pw = id_getpwuid((uid_t)req->uid)) == NULL) {
			reply.status = ENOENT;
		} else {
			gid_t members[NGROUPS_MAX];
			unsigned nmember = agent_member_gids(pw, members,
			    nitems(members));
			bool forwardable =
			    (req->flags & AUTHAGENT_FLAG_FORWARDABLE) != 0;
			enum service_mint_kind kind =
			    authagent_mint_kind(g_policy_fd, (uid_t)req->uid,
			    members, nmember, agent_name2gid, NULL);

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

 send_reply:
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

#ifndef AUTHAGENTD_TESTING
static int
client_adopt(int client_fd, const struct service_identity *identity)
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
	/*
	 * Retain the caller's serviced-stamped identity for the mint gate in
	 * handle_request().  The rights bitmask carries the authenticator
	 * authority; the label is kept for audit logging only.
	 */
	c->rights = identity->rights;
	(void)strlcpy(c->client_label, identity->client_label,
	    sizeof(c->client_label));
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
	/* ps(1) shows the unit name, not the ld-elf.so.1 launcher. */
	service_set_proctitle();

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
	{
		/*
		 * tzfsd may not be serving yet this early in boot: its manifest
		 * might not be registered when we ask, which fails fast rather
		 * than blocking on on-demand launch (a registered-but-not-running
		 * provider would instead block until it checks in).  A one-shot
		 * open would then leave g_policy_fd == -1 for the life of the
		 * process and every mint would silently fall back to the
		 * root-or-wheel default even when the operator configured admin
		 * uids/groups.  Retry a bounded number of times with a short
		 * backoff (~1s worst case) to let tzfsd come up; a definitive
		 * answer (EACCES/EPERM — not granted) stops us at once, and so
		 * does success.  This runs before cap_enter, so consulting the
		 * path is still permitted.  Never fatal, and never an unbounded
		 * block: if the policy is genuinely unavailable we log a warning
		 * (so the fallback is observable, not silent) and proceed on the
		 * default.
		 */
		unsigned attempt;
		int last_errno = 0;

		g_policy_fd = -1;
		for (attempt = 0; attempt < 8; attempt++) {
			if (service_open_isolated(g_context,
			    "/Capabilities/Config/principal-policy.ucl",
			    SERVICE_OPEN_READ, 0, &g_policy_fd) == 0)
				break;
			last_errno = errno;
			g_policy_fd = -1;
			if (errno == EACCES || errno == EPERM)
				break;	/* definitive: not granted */
			(void)nanosleep(&(struct timespec){
			    .tv_sec = 0, .tv_nsec = 125 * 1000 * 1000 }, NULL);
		}
		/*
		 * Make the fallback observable.  A missing policy file (ENOENT)
		 * is the normal optional case — note it at INFO.  Anything else
		 * (denied, or tzfsd never came up) is unexpected: warn, because
		 * an operator-configured policy is then silently not in effect.
		 */
		if (g_policy_fd == -1) {
			errno = last_errno;
			syslog(last_errno == ENOENT ?
			    (LOG_AUTHPRIV | LOG_INFO) :
			    (LOG_AUTHPRIV | LOG_WARNING),
			    "principal policy unavailable (%m); "
			    "mint uses the root-or-wheel default");
		}
	}

	/*
	 * Open the identity databases (/etc/passwd, /etc/group) before entering
	 * the sandbox, so the agent can resolve a uid to its passwd and group
	 * membership authoritatively after cap_enter — the security basis for not
	 * trusting the login client's claims.  Reading the retained descriptors is
	 * capability-mode-legal; opening the paths would not be.  This is the
	 * Identity fold: in-process NSS, no Casper zygote.
	 */
	{
		if (id_open_databases() == -1) {
			syslog(LOG_ERR, "identity databases unavailable: %m");
			return (1);
		}
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
			if (client_adopt(fd, &identity) == -1)
				syslog(LOG_WARNING, "adopt client: %m");
			continue;
		}
		/* A connected login program's channel. */
		{
			struct client *c = event.udata;

			if (event.flags & EV_EOF) {
				/*
				 * A caller that half-closes its write end
				 * (shutdown(SHUT_WR)) right after sending its
				 * request shows up as EV_EOF while the request
				 * bytes are still buffered and its read end is
				 * still open for the reply.  Drain one dispatch
				 * pass so the reply is produced, then flush it
				 * best-effort before tearing the client down —
				 * do not destroy it out from under an unanswered
				 * request.  Only the read side can carry pending
				 * input; a write-side EOF has nothing to drain.
				 */
				if (event.filter == EVFILT_READ &&
				    channel_dispatch(c->chan) == 0)
					(void)channel_flush(c->chan);
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
#endif /* !AUTHAGENTD_TESTING */

#ifdef AUTHAGENTD_TESTING
/*
 * Test seam.  These entry points let an ATF provider test drive the real
 * handle_request() over a channel without standing up main()'s kqueue accept
 * loop.  They change no runtime behaviour: the daemon binary is built without
 * AUTHAGENTD_TESTING and never sees them.
 */
void
authagentd_test_configure(struct service_context *context, int policy_fd)
{

	g_context = context;
	g_policy_fd = policy_fd;
	/*
	 * Identity streams (g_pwf/g_grf) are left NULL in the test seam: the
	 * provider tests drive the caller-gate and protocol paths, not live
	 * uid resolution (which id_getpwuid then fails closed, ENOENT).
	 */
}

int
authagentd_test_serve(int fd, const struct service_identity *identity)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct client c;
	int ready, wants;

	options.max_pending_requests = 8;
	options.max_queued_messages = 32;
	options.max_queued_bytes = 64 * 1024;
	options.max_queued_fds = 4;

	memset(&c, 0, sizeof(c));
	c.rights = identity->rights;
	(void)strlcpy(c.client_label, identity->client_label,
	    sizeof(c.client_label));
	if (channel_create(fd, &options, &c.chan) == -1)
		return (-1);
	c.fd = channel_fd(c.chan);
	if (channel_set_request_handler(c.chan, handle_request, &c) == -1) {
		channel_destroy(c.chan);
		return (-1);
	}
	for (;;) {
		wants = channel_wants_write(c.chan);
		if (wants == -1)
			break;
		ready = channel_wait(c.chan, wants, -1);
		if (ready <= 0)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(c.chan) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(c.chan) == -1)
			break;
	}
	channel_destroy(c.chan);
	return (0);
}
#endif /* AUTHAGENTD_TESTING */
