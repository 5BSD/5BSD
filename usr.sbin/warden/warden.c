/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * warden(8) — the namespace (jail) broker.
 *
 * Owns jail construction (jail_set(2)), taking it out of PID 1.  warden is a
 * socket-free service_provider exposing system.Namespace; the discovery domain
 * layer resolves that name only for SYSTEM-domain clients.
 *
 * This is consumer self-service, uniform with storage and module loading:
 * a program's library (service_enter_namespace(3)) — never serviced — resolves
 * warden and confines the process.  warden creates the jail rooted at the
 * requested path with JAIL_OWN_DESC and returns the owning descriptor; the
 * credential stored in that descriptor (root, from warden) authorizes
 * jail_attach_jd(2), so the non-root consumer attaches itself.  Self-jailing is
 * self-confinement, so warden needs no per-caller token — it scopes each jail
 * by the caller's unforgeable channel label, so one consumer can never name or
 * reuse another's jail.
 *
 * warden runs as root and NOT in capability mode: jail_set(2) needs
 * PRIV_JAIL_SET and a global-namespace path lookup, both of which capsicum
 * forbids.  It is launched on demand by serviced (the first consumer that
 * self-jails resolves system.Namespace and pulls it up).
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <jail.h>
#include <sha256.h>

#include <channel.h>
#include <libservice.h>

#include "warden_proto.h"

/* A jail name derived from a channel label: alnum plus '.', '_', '-'. */
#define	WARDEN_JAIL_NAME_MAX	64

#ifndef WARDEN_TESTING
/*
 * Guarantee fds 0/1/2 are open before any capability handle is created.  warden
 * is launched by serviced without a controlling terminal.
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
#endif /* !WARDEN_TESTING */

/*
 * Derive a stable, safe, FLAT jail name from the caller's unforgeable channel
 * label.  The name MUST be an injective function of the full label: two distinct
 * labels must never map to the same jail name, or one consumer could land on —
 * and reuse — another consumer's jail, defeating the "one consumer can never
 * name or reuse another's jail" isolation invariant.
 *
 * A lossy sanitise-and-truncate is NOT injective: folding every non-[A-Za-z0-9_-]
 * character to '_' collapses "a.b" and "a_b" onto one name, and truncating at
 * WARDEN_JAIL_NAME_MAX-1 collapses every label sharing a 63-char prefix.  Both
 * are collisions an attacker can steer.  So we derive the name from a
 * collision-resistant hash of the *entire* label instead: "wj_" followed by the
 * hex of the first 30 bytes (240 bits) of SHA-256(label).  That is 63 characters
 * — within WARDEN_JAIL_NAME_MAX — uses only the jail-safe alphabet (no '.', so no
 * accidental hierarchy), and is deterministic (same label -> same name), so a
 * relaunched consumer still reattaches to its own jail.  Returns false only for
 * an empty label or a buffer too small to hold a meaningful name.
 */
static bool
jail_name_from_label(const char *label, char *out, size_t outsz)
{
	static const char hex[] = "0123456789abcdef";
	static const char prefix[] = "wj_";
	const size_t plen = sizeof(prefix) - 1;
	SHA256_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	size_t nbytes, i;

	if (label == NULL || label[0] == '\0')
		return (false);
	/* Need room for the prefix, at least 128 bits of hash, and the NUL. */
	if (outsz < plen + 2 * 16 + 1)
		return (false);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, label, strlen(label));
	SHA256_Final(digest, &ctx);

	/* As many digest bytes as fit after the prefix, capped at the digest. */
	nbytes = (outsz - 1 - plen) / 2;
	if (nbytes > sizeof(digest))
		nbytes = sizeof(digest);

	memcpy(out, prefix, plen);
	for (i = 0; i < nbytes; i++) {
		out[plen + 2 * i] = hex[digest[i] >> 4];
		out[plen + 2 * i + 1] = hex[digest[i] & 0x0f];
	}
	out[plen + 2 * nbytes] = '\0';
	return (true);
}

/* Every string field must be NUL-terminated; path must be absolute. */
static bool
valid_request(const struct warden_request *rq)
{

	if (rq->op != WARDEN_OP_ENTER_JAIL ||
	    (rq->flags & ~(WARDEN_F_EPHEMERAL | WARDEN_F_VNET)) != 0)
		return (false);
	if (memchr(rq->path, '\0', sizeof(rq->path)) == NULL ||
	    memchr(rq->hostname, '\0', sizeof(rq->hostname)) == NULL ||
	    memchr(rq->ip4_addr, '\0', sizeof(rq->ip4_addr)) == NULL ||
	    memchr(rq->ip6_addr, '\0', sizeof(rq->ip6_addr)) == NULL)
		return (false);
	if (rq->path[0] != '/')
		return (false);
	return (true);
}

/*
 * Parse a jail "desc" parameter — a decimal descriptor number the kernel writes
 * as a string — into an int fd.  A malformed or empty desc must be rejected, not
 * silently coerced to fd 0: strtol("", ...) yields 0 with end==desc, and a
 * trailing-junk string yields a partial value, either of which would hand back a
 * bogus descriptor.  Returns true and stores the fd only for a fully-consumed,
 * in-range non-negative number.
 */
static bool
parse_desc_fd(const char *desc, int *out_fd)
{
	char *end;
	long fd;

	errno = 0;
	fd = strtol(desc, &end, 10);
	if (errno != 0 || end == desc || *end != '\0' || fd < 0 || fd > INT_MAX)
		return (false);
	*out_fd = (int)fd;
	return (true);
}

/*
 * Fetch an existing jail's ip4.addr into out (empty string if the jail has no
 * address).  Returns 0 on success, or an errno.  This is a separate get with no
 * descriptor: jailparam_get(3) reports a requested-but-absent parameter as
 * ENOENT, so asking for ip4.addr in the main JAIL_GET_DESC call would be misread
 * as "jail absent".  Here ENOENT unambiguously means "this jail has no ip4
 * address", which the caller compares against whether the request asked for one.
 */
static int
jail_get_ip4(const char *name, char *out, size_t outsz)
{

	if (outsz == 0)
		return (EINVAL);
	out[0] = '\0';
	if (jail_getv(0, "name", __DECONST(char *, name),
	    "ip4.addr", out, NULL) < 0)
		return (errno);
	return (0);
}

/*
 * Fetch an existing jail's ip6.addr into out (empty string if the jail has no
 * address).  Mirrors jail_get_ip4: a separate get with no descriptor, so an
 * absent ip6.addr surfaces as ENOENT ("this jail has no ip6 address") rather
 * than being misread as "jail absent".  Returns 0 on success, or an errno.
 */
static int
jail_get_ip6(const char *name, char *out, size_t outsz)
{

	if (outsz == 0)
		return (EINVAL);
	out[0] = '\0';
	if (jail_getv(0, "name", __DECONST(char *, name),
	    "ip6.addr", out, NULL) < 0)
		return (errno);
	return (0);
}

/*
 * Fetch an existing jail's "vnet" setting into *out (JAIL_SYS_DISABLE,
 * JAIL_SYS_NEW, or JAIL_SYS_INHERIT).  Returns 0 on success, or an errno; a
 * kernel built without VIMAGE has no "vnet" parameter at all, which surfaces as
 * ENOENT — the caller treats that as "not a vnet jail", the same as disabled.
 */
static int
jail_get_vnet(const char *name, int *out)
{
	char buf[16];

	*out = JAIL_SYS_DISABLE;
	buf[0] = '\0';
	if (jail_getv(0, "name", __DECONST(char *, name),
	    "vnet", buf, NULL) < 0)
		return (errno);
	/*
	 * A jailsys parameter exports as the string "disable"/"new"/"inherit",
	 * not a number -- map it back rather than strtol() (which would read 0
	 * for every one of them).
	 */
	if (strcmp(buf, "new") == 0)
		*out = JAIL_SYS_NEW;
	else if (strcmp(buf, "inherit") == 0)
		*out = JAIL_SYS_INHERIT;
	else
		*out = JAIL_SYS_DISABLE;
	return (0);
}

/*
 * Return a non-owning descriptor for an existing jail with this name when its
 * immutable definition matches the request; -1/errno otherwise (ENOENT when
 * absent).  Lets a relaunched consumer reattach to its persistent jail.  The
 * descriptor is always non-owning: it authorizes the consumer's attach (its
 * stored credential is warden's root) but closing it never removes the jail.
 * An ephemeral jail's lifetime is instead anchored by the per-client worker
 * process holding a separate owning descriptor (see warden_request_handler).
 *
 * Reuse is safe ONLY when the *entire* requested definition matches the existing
 * jail: path, hostname, ip4 address, ip6 address, AND vnet setting.  A consumer
 * that reconnects must get back the jail it defined, never silently attach into a
 * differently-shaped one (which would discard its isolation request — e.g. a
 * requested ip6.addr or its own vnet — with no error).  Any mismatch is a hard
 * EEXIST, enforcing the immutable definition the reuse contract promises.
 */
static int
existing_jail_descriptor(const char *name, const struct warden_request *rq)
{
	char desc[32], path[PATH_MAX], host[MAXHOSTNAMELEN], ip4[256], ip6[256];
	const char *want_host = rq->hostname[0] != '\0' ? rq->hostname : name;
	bool want_vnet = (rq->flags & WARDEN_F_VNET) != 0;
	int jid, iperr, fd, saved_errno, vnet, verr;

	memset(desc, 0, sizeof(desc));
	memset(path, 0, sizeof(path));
	memset(host, 0, sizeof(host));
	jid = jail_getv(JAIL_GET_DESC,
	    "name", __DECONST(char *, name),
	    "path", path,
	    "host.hostname", host,
	    "desc", desc,
	    NULL);
	if (jid < 0)
		return (-1);			/* errno == ENOENT when absent */

	/* Root path and hostname must match the request exactly. */
	if (strcmp(path, rq->path) != 0 || strcmp(host, want_host) != 0) {
		errno = EEXIST;
		goto fail;
	}

	/*
	 * The ip4 address must match too: a request asking for a specific
	 * address must not silently attach into an address-less (or
	 * differently-addressed) jail, and a request asking for none must not
	 * land in an addressed one.
	 */
	memset(ip4, 0, sizeof(ip4));
	iperr = jail_get_ip4(name, ip4, sizeof(ip4));
	if (iperr != 0 && iperr != ENOENT) {
		errno = iperr;
		goto fail;
	}
	if (rq->ip4_addr[0] != '\0') {
		if (iperr == ENOENT || strcmp(ip4, rq->ip4_addr) != 0) {
			errno = EEXIST;
			goto fail;
		}
	} else if (iperr != ENOENT) {
		errno = EEXIST;
		goto fail;
	}

	/* Same rule for ip6.addr: a requested/absent address must match. */
	memset(ip6, 0, sizeof(ip6));
	iperr = jail_get_ip6(name, ip6, sizeof(ip6));
	if (iperr != 0 && iperr != ENOENT) {
		errno = iperr;
		goto fail;
	}
	if (rq->ip6_addr[0] != '\0') {
		if (iperr == ENOENT || strcmp(ip6, rq->ip6_addr) != 0) {
			errno = EEXIST;
			goto fail;
		}
	} else if (iperr != ENOENT) {
		errno = EEXIST;
		goto fail;
	}

	/*
	 * The vnet setting is part of the immutable definition too: a request
	 * for an own-vnet jail must not attach into a shared-stack one, nor the
	 * reverse.  A kernel without VIMAGE reports the "vnet" parameter as
	 * ENOENT, which reads as "not a vnet jail" (== disabled).
	 */
	verr = jail_get_vnet(name, &vnet);
	if (verr != 0 && verr != ENOENT) {
		errno = verr;
		goto fail;
	}
	if (want_vnet != (verr == 0 && vnet == JAIL_SYS_NEW)) {
		errno = EEXIST;
		goto fail;
	}

	if (!parse_desc_fd(desc, &fd)) {
		errno = EPROTO;
		goto fail;
	}
	return (fd);

fail:
	/*
	 * Preserve the mismatch errno (EEXIST, or an ip4/ip6/vnet lookup error)
	 * across the descriptor cleanup: parse_desc_fd() does "errno = 0" before its
	 * strtol(), which would otherwise clobber the reason to 0 and make the
	 * caller mistake a definition conflict for a successful reuse.
	 */
	saved_errno = errno;
	if (parse_desc_fd(desc, &fd))
		(void)close(fd);
	errno = saved_errno;
	return (-1);
}

/*
 * Create the named jail and return a descriptor whose stored credential (root,
 * from warden) authorizes the consumer's jail_attach_jd(2), or -1/errno.  Uses
 * jailparam(3) — the exact encoding jail(8) uses — so string params (path,
 * host.hostname, ip4.addr, ip6.addr) and the boolean flags (persist, vnet) are
 * marshalled correctly; note "persist" and "vnet" are boolean parameters and
 * must be given the value "1" (a NULL value is a no-op in jailparam_import(3),
 * which for "persist" would silently leave the jail non-persistent).
 *
 * The parameter list is assembled dynamically rather than through a fixed
 * jail_setv() call because the optional fields (ip4.addr, ip6.addr, vnet) are
 * independent, giving too many combinations to spell out.  This mirrors
 * jail_setv(3) internally: jailparam_init/import each name/value pair,
 * jailparam_set() the batch, then read the descriptor fd back out of the "desc"
 * parameter's value (which JAIL_GET_DESC populated) as a decimal string.
 *
 * The jail is always created persist=1 so it is alive during the create->attach
 * handoff window and while it is reused: a descriptor (owning or not) only
 * structurally holds the prison, it does not keep it alive (no user reference),
 * so without persist the prison is already dying when the consumer attaches and
 * the kernel SIGKILLs it.  The returned descriptor is non-owning: closing it
 * never removes the jail.  An ephemeral jail is torn down not by this descriptor
 * but by the per-client worker holding a separate owning descriptor, which
 * closes when the consumer disconnects (see warden_request_handler).
 */
static int
create_jail(const char *name, const struct warden_request *rq, int *out_jid)
{
	const char *host = rq->hostname[0] != '\0' ? rq->hostname : name;
	const char *pn[8];
	char *pv[8];
	struct jailparam jp[8];
	char desc[32];
	unsigned n, ninit;
	int jid, fd;

	memset(desc, 0, sizeof(desc));
	n = 0;
	pn[n] = "name";			pv[n++] = __DECONST(char *, name);
	pn[n] = "path";			pv[n++] = __DECONST(char *, rq->path);
	pn[n] = "persist";		pv[n++] = __DECONST(char *, "1");
	pn[n] = "host.hostname";	pv[n++] = __DECONST(char *, host);
	if (rq->ip4_addr[0] != '\0') {
		pn[n] = "ip4.addr";
		pv[n++] = __DECONST(char *, rq->ip4_addr);
	}
	if (rq->ip6_addr[0] != '\0') {
		pn[n] = "ip6.addr";
		pv[n++] = __DECONST(char *, rq->ip6_addr);
	}
	if ((rq->flags & WARDEN_F_VNET) != 0) {
		pn[n] = "vnet";
		/*
		 * "vnet" is a jailsys parameter: its value is the string
		 * "new"/"inherit"/"disable" (jailparam_import maps it to
		 * JAIL_SYS_*), NOT a numeric "1".
		 */
		pv[n++] = __DECONST(char *, "new");
	}
	pn[n] = "desc";			pv[n++] = desc;	/* filled on success */

	for (ninit = 0; ninit < n; ninit++) {
		if (jailparam_init(&jp[ninit], pn[ninit]) < 0)
			break;
		if (jailparam_import(&jp[ninit], pv[ninit]) < 0) {
			ninit++;		/* this one needs freeing too */
			break;
		}
	}
	if (ninit < n) {
		jailparam_free(jp, ninit);
		return (-1);
	}
	jid = jailparam_set(jp, n, JAIL_CREATE | JAIL_GET_DESC);
	if (jid > 0)
		(void)snprintf(desc, sizeof(desc), "%d",
		    *(int *)jp[n - 1].jp_value);
	jailparam_free(jp, n);
	if (jid < 0)
		return (-1);
	/*
	 * Validate the descriptor exactly as the get paths do — a malformed or
	 * empty "desc" must error, not silently yield fd 0.  The jail is already
	 * created persist=1, so on a parse failure remove it rather than leak a
	 * permanent jail with no descriptor to anchor it.
	 */
	if (!parse_desc_fd(desc, &fd)) {
		(void)jail_remove(jid);
		errno = EPROTO;
		return (-1);
	}
	if (out_jid != NULL)
		*out_jid = jid;
	return (fd);
}

/*
 * Acquire an owning descriptor (JAIL_OWN_DESC) for the existing named jail.  The
 * per-client worker holds this for the life of the client connection; when the
 * consumer disconnects the worker exits, the descriptor closes, and the prison
 * is removed (prison_remove overrides persist).  This is how an ephemeral jail's
 * lifetime is bound to its consumer without warden watching for the exit.
 * Returns the fd, or -1/errno.
 */
static int
owning_jail_descriptor(const char *name)
{
	char desc[32];
	int jid, fd;

	memset(desc, 0, sizeof(desc));
	jid = jail_getv(JAIL_GET_DESC | JAIL_OWN_DESC,
	    "name", __DECONST(char *, name), "desc", desc, NULL);
	if (jid < 0)
		return (-1);
	if (!parse_desc_fd(desc, &fd)) {
		errno = EPROTO;
		return (-1);
	}
	return (fd);
}

/*
 * An ephemeral jail's owning descriptor, held for the life of this worker
 * process (== the life of the client connection).  Each client is served by its
 * own pdfork'd worker, so this file-scope handle is private to one consumer;
 * when the consumer disconnects the worker exits, this fd closes, and the prison
 * is removed.  -1 when no ephemeral jail is held.
 */
static int worker_owning_fd = -1;

/* Send a status-only reply (no SCM fd): ENTER errors, DESTROY, dispatch. */
static void
send_status(struct channel_message *m, int32_t status)
{
	struct warden_reply rp;
	struct channel_outgoing out;

	memset(&rp, 0, sizeof(rp));
	rp.status = status;
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	(void)channel_send_reply(m, &out);
}

/*
 * ENTER_JAIL: create or reuse the caller's label-scoped jail and reply with its
 * non-owning descriptor.  arg is the connecting client's unforgeable label,
 * which both scopes the jail name and gates reachability (the domain layer
 * already restricted it to SYSTEM clients).  For an ephemeral request the worker
 * additionally retains the jail's owning descriptor so the jail is torn down
 * when the consumer exits.  This is the original handler body, unchanged.
 */
static void
handle_enter_jail(struct channel_message *m, const char *client)
{
	const struct warden_request *rq;
	struct warden_reply rp;
	struct channel_outgoing out;
	char name[WARDEN_JAIL_NAME_MAX];
	int jd = -1, created_jid = -1;

	memset(&rp, 0, sizeof(rp));

	if (channel_message_length(m) != sizeof(*rq)) {
		rp.status = EPROTO;
		goto reply;
	}
	rq = channel_message_data(m);
	if (!valid_request(rq) || !jail_name_from_label(client, name,
	    sizeof(name))) {
		rp.status = EINVAL;
		goto reply;
	}

	/*
	 * worker_owning_fd is a single file-scope slot private to this worker.
	 * If it is already set, this channel has already anchored an ephemeral
	 * jail; a second ENTER would overwrite the slot and close the first
	 * owning fd, tearing that jail down while the consumer is still using
	 * it.  Reject the second ENTER instead of clobbering.
	 */
	if (worker_owning_fd >= 0) {
		rp.status = EALREADY;
		syslog(LOG_NOTICE, "ENTER (client %s) -> refused: channel "
		    "already holds an ephemeral jail", client);
		goto reply;
	}

	jd = existing_jail_descriptor(name, rq);
	if (jd >= 0) {
		syslog(LOG_INFO, "ENTER %s (client %s) -> reused jd", name,
		    client);
	} else if (errno != ENOENT) {
		rp.status = errno;
		syslog(LOG_NOTICE, "ENTER %s (client %s) -> conflict: %s", name,
		    client, strerror(rp.status));
		goto reply;
	} else {
		jd = create_jail(name, rq, &created_jid);
		if (jd < 0) {
			rp.status = errno;
			syslog(LOG_ERR, "ENTER %s path=%s (client %s) -> "
			    "jail_set: %s", name, rq->path, client,
			    strerror(rp.status));
			goto reply;
		}
		syslog(LOG_INFO, "ENTER %s path=%s (client %s) -> created", name,
		    rq->path, client);
	}

	/*
	 * For an ephemeral jail, retain its owning descriptor in this worker so
	 * the jail is removed when the consumer disconnects (this worker exits).
	 * The consumer still attaches with the non-owning descriptor sent below.
	 * If acquiring the owning descriptor fails we must FAIL the request, not
	 * silently degrade to a permanent persist=1 jail nothing reclaims: fail
	 * closed in the safe direction (no leak).  Tear down a jail we created
	 * here; a reused persistent jail is left as it was.
	 */
	if (jd >= 0 && (rq->flags & WARDEN_F_EPHEMERAL)) {
		worker_owning_fd = owning_jail_descriptor(name);
		if (worker_owning_fd < 0) {
			rp.status = errno != 0 ? errno : EIO;
			syslog(LOG_ERR, "ENTER %s (client %s) -> owning "
			    "descriptor failed, failing request: %m", name,
			    client);
			if (created_jid >= 0)
				(void)jail_remove(created_jid);
			(void)close(jd);
			jd = -1;
			goto reply;
		}
	}

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (jd >= 0 && rp.status == 0) {
		out.fds = &jd;
		out.nfds = 1;
	}
	(void)channel_send_reply(m, &out);
	if (jd >= 0)
		(void)close(jd);
}

/*
 * DESTROY_JAIL: remove the caller's label-scoped jail.  Owner-scoped by
 * construction — jail_name_from_label(client) names only the caller's own jail,
 * never another label's — so this can never remove a jail warden created for a
 * different consumer.  Replies ENOENT if the caller has no jail, status 0 once
 * removed, or the failure errno.
 *
 * The target is normally a persistent jail (the only kind that leaks).  If it
 * happens to be an ephemeral jail whose lifetime another worker anchors with an
 * owning descriptor, jail_remove() still tears it down: prison_remove overrides
 * both persist and any structural descriptor reference.
 */
static void
handle_destroy_jail(struct channel_message *m, const char *client)
{
	char name[WARDEN_JAIL_NAME_MAX];
	int jid;

	if (channel_message_length(m) != sizeof(struct warden_control_request)) {
		send_status(m, EPROTO);
		return;
	}
	if (!jail_name_from_label(client, name, sizeof(name))) {
		send_status(m, EINVAL);
		return;
	}
	jid = jail_getid(name);
	if (jid < 0) {
		syslog(LOG_INFO, "DESTROY %s (client %s) -> no such jail", name,
		    client);
		send_status(m, ENOENT);
		return;
	}
	if (jail_remove(jid) < 0) {
		int status = errno != 0 ? errno : EIO;

		syslog(LOG_ERR, "DESTROY %s (client %s) -> jail_remove: %s", name,
		    client, strerror(status));
		send_status(m, status);
		return;
	}
	syslog(LOG_INFO, "DESTROY %s (client %s) -> removed", name, client);
	send_status(m, 0);
}

/*
 * LIST_JAILS: report the caller's label-scoped jail.  Owner-scoped by the same
 * construction as DESTROY: it can only ever describe the caller's own jail.  A
 * label owns at most one jail, so the answer is present==1 (with the definition)
 * or present==0 (none); status is 0 for both, or an errno on a real lookup
 * failure.
 *
 * This reads the definition back with jail_getv()/jail_get_ip4() — the same
 * primitives existing_jail_descriptor() uses — but does NOT go through the
 * descriptor ("desc") path, so it never calls parse_desc_fd() and thus never
 * hits that helper's "errno = 0" clobber; the errno seen after a failed
 * jail_getv() here is therefore the real lookup errno.
 */
static void
handle_list_jails(struct channel_message *m, const char *client)
{
	struct warden_list_reply lr;
	struct channel_outgoing out;
	char name[WARDEN_JAIL_NAME_MAX];
	char path[PATH_MAX], host[MAXHOSTNAMELEN], ip4[256], ip6[256];
	int jid, iperr, iperr6;

	memset(&lr, 0, sizeof(lr));
	lr.jid = -1;

	/*
	 * A framing error is answered with the minimal status reply, not the
	 * large warden_list_reply: an error carries no jail definition, and a
	 * caller that sent a malformed LIST has no reason to size its receive
	 * buffer for the full reply.
	 */
	if (channel_message_length(m) != sizeof(struct warden_control_request)) {
		send_status(m, EPROTO);
		return;
	}
	if (!jail_name_from_label(client, name, sizeof(name))) {
		lr.status = EINVAL;
		goto reply;
	}

	memset(path, 0, sizeof(path));
	memset(host, 0, sizeof(host));
	jid = jail_getv(0, "name", __DECONST(char *, name),
	    "path", path, "host.hostname", host, NULL);
	if (jid < 0) {
		/* ENOENT is the ordinary "caller has no jail" answer. */
		if (errno == ENOENT) {
			lr.present = 0;
			lr.status = 0;
		} else {
			lr.status = errno;
			syslog(LOG_NOTICE, "LIST %s (client %s) -> jail_getv: %s",
			    name, client, strerror(lr.status));
		}
		goto reply;
	}

	memset(ip4, 0, sizeof(ip4));
	iperr = jail_get_ip4(name, ip4, sizeof(ip4));
	if (iperr != 0 && iperr != ENOENT) {
		lr.status = iperr;
		syslog(LOG_NOTICE, "LIST %s (client %s) -> ip4: %s", name, client,
		    strerror(iperr));
		goto reply;
	}

	memset(ip6, 0, sizeof(ip6));
	iperr6 = jail_get_ip6(name, ip6, sizeof(ip6));
	if (iperr6 != 0 && iperr6 != ENOENT) {
		lr.status = iperr6;
		syslog(LOG_NOTICE, "LIST %s (client %s) -> ip6: %s", name, client,
		    strerror(iperr6));
		goto reply;
	}

	lr.status = 0;
	lr.present = 1;
	lr.jid = jid;
	(void)strlcpy(lr.path, path, sizeof(lr.path));
	(void)strlcpy(lr.hostname, host, sizeof(lr.hostname));
	if (iperr == 0)
		(void)strlcpy(lr.ip4_addr, ip4, sizeof(lr.ip4_addr));
	if (iperr6 == 0)
		(void)strlcpy(lr.ip6_addr, ip6, sizeof(lr.ip6_addr));
	syslog(LOG_INFO, "LIST %s (client %s) -> present jid=%d", name, client,
	    jid);

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &lr;
	out.length = sizeof(lr);
	(void)channel_send_reply(m, &out);
}

/*
 * Per-client channel request handler.  arg is the connecting client's
 * unforgeable label.  Every op is validated fail-closed: the channel accepts no
 * SCM fds (an attached descriptor is already a terminal transport rejection, so
 * fd_count is never > 0 here in practice, but reject defensively), and the
 * message must be long enough to hold at least the opcode word before it is
 * dispatched.  ENTER requires the full warden_request; DESTROY and LIST require
 * a warden_control_request; an unknown op is EINVAL.
 */
static void
warden_request_handler(struct channel *ch __unused, struct channel_message *m,
    void *arg)
{
	const char *client = arg;
	uint32_t op;

	if (channel_message_fd_count(m) != 0 ||
	    channel_message_length(m) < sizeof(uint32_t)) {
		send_status(m, EPROTO);
		goto done;
	}
	memcpy(&op, channel_message_data(m), sizeof(op));
	switch (op) {
	case WARDEN_OP_ENTER_JAIL:
		handle_enter_jail(m, client);
		break;
	case WARDEN_OP_DESTROY_JAIL:
		handle_destroy_jail(m, client);
		break;
	case WARDEN_OP_LIST_JAILS:
		handle_list_jails(m, client);
		break;
	default:
		send_status(m, EINVAL);
		break;
	}
done:
	channel_message_free(m);
}

/* Serve one client on its own worker channel until it closes. */
static int
warden_worker(int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	char label[64];
	int ready, wants_write;

	(void)strlcpy(label, client, sizeof(label));

	if (channel_create(fd, &options, &channel) == -1)
		return (1);
	if (channel_set_request_handler(channel, warden_request_handler,
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

#ifdef WARDEN_TESTING
/*
 * Test entrypoints.  These expose the pure decision logic (name derivation,
 * request validation, descriptor parsing) and the per-client channel worker to
 * the ATF suite without duplicating any of it.  The daemon build never compiles
 * this block; behavior of the shipped binary is unchanged.
 */
#include "warden_test.h"

bool
warden_test_jail_name(const char *label, char *out, size_t outsz)
{

	return (jail_name_from_label(label, out, outsz));
}

bool
warden_test_valid_request(const struct warden_request *rq)
{

	return (valid_request(rq));
}

bool
warden_test_parse_desc(const char *desc, int *out_fd)
{

	return (parse_desc_fd(desc, out_fd));
}

int
warden_test_worker(int fd, const char *client)
{

	return (warden_worker(fd, client));
}
#endif /* WARDEN_TESTING */

#ifndef WARDEN_TESTING
/*
 * Expose system.Namespace and dispatch each accepted client on its own pdfork'd
 * worker.  warden is a privileged provider: it does NOT enter capability mode
 * (jail_set needs PRIV_JAIL_SET and a global-namespace path lookup, both
 * capsicum-forbidden).  Returns -1 only on setup failure.
 */
static int
warden_serve(void)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, WARDEN_SERVICE_NAME,
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
			_exit(warden_worker(fd, id.client_label));
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
			(void)fprintf(stderr, "usage: warden\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: warden\n");
		return (1);
	}

	openlog("warden", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	reserve_stdio();

	setproctitle("-Namespace");
	syslog(LOG_NOTICE, "warden namespace (jail) broker");

	if (warden_serve() == -1)
		errx(1, "namespace provider failed");

	return (0);
}
#endif /* !WARDEN_TESTING */
