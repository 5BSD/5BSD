/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdnamespace(8) — the namespace (jail) broker.
 *
 * Owns jail construction (jail_set(2)), taking it out of PID 1.  bsdnamespace is a
 * socket-free service_provider exposing system.Namespace; the discovery domain
 * layer resolves that name only for SYSTEM-domain clients.
 *
 * This is consumer self-service, uniform with storage and module loading:
 * a program's library (service_enter_namespace(3)) — never switchboard — resolves
 * bsdnamespace and confines the process.  bsdnamespace creates the jail rooted at the
 * requested path with JAIL_OWN_DESC and returns the owning descriptor; the
 * credential stored in that descriptor (root, from bsdnamespace) authorizes
 * jail_attach_jd(2), so the non-root consumer attaches itself.  Self-jailing is
 * self-confinement, so bsdnamespace needs no per-caller token — it scopes each jail
 * by the caller's unforgeable channel label, so one consumer can never name or
 * reuse another's jail.
 *
 * bsdnamespace is BORN IN CAPABILITY MODE.  jail_set(2)/jail_get(2) are not
 * capsicum-enabled (a global jail namespace is exactly what the sandbox hides),
 * and jail_set needs PRIV_JAIL_SET plus a global-namespace path lookup.  So the
 * broker performs jail construction and inspection THROUGH a held mac_capability
 * "system" token covering SYS_GATE_JAIL: service_system_jail_set/get(3) reach
 * kern_jail_set_gated()/kern_jail_get() in kernel context, where the held claim
 * replaces PRIV_JAIL_SET and the jail-root namei runs UIO_SYSSPACE (exempt from
 * the capmode userspace-path restriction).  The token is minted by switchboard
 * from the capabilities.system=["jail"] manifest declaration and delivered at
 * launch; root is not required and grants nothing the token does not.  Launched
 * on demand (the first consumer that self-jails resolves system.Namespace).
 */

#include <sys/param.h>
#include <sys/procdesc.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <pthread.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
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

#include "bsdnamespace_proto.h"
#include "bsdnamespace_reclaim.h"
#include "bsdnamespace_probes.h"

/* A jail name derived from a channel label: alnum plus '.', '_', '-'. */
#define	BSDNAMESPACE_JAIL_NAME_MAX	64

/*
 * The held mac_capability "system" token covering SYS_GATE_JAIL.  Dup'd from the
 * switchboard-delivered token before entering capability mode, so it outlives the
 * bootstrap authority drop and survives the one reclaim fork (the dup is not
 * close-on-fork).  Every jail create/get/remove goes THROUGH this token; -1 when
 * none is held (a unit test, or a plane that delivered no jail capability), in
 * which case the gated calls fail ENOTCAPABLE rather than silently falling back
 * to a privileged syscall the sandbox would refuse anyway.  reclaim.c performs
 * its gated removals through the bsdnamespace_jail_remove()/_next() wrappers below,
 * which read this token, so it stays file-local.
 */
static int bsdnamespace_jail_token = -1;

#ifndef BSDNAMESPACE_TESTING
/*
 * Guarantee fds 0/1/2 are open before any capability handle is created.  bsdnamespace
 * is launched by switchboard without a controlling terminal.
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
#endif /* !BSDNAMESPACE_TESTING */

/*
 * Derive a stable, safe, FLAT jail name from the caller's unforgeable channel
 * label.  The name MUST be an injective function of the full label: two distinct
 * labels must never map to the same jail name, or one consumer could land on —
 * and reuse — another consumer's jail, defeating the "one consumer can never
 * name or reuse another's jail" isolation invariant.
 *
 * A lossy sanitise-and-truncate is NOT injective: folding every non-[A-Za-z0-9_-]
 * character to '_' collapses "a.b" and "a_b" onto one name, and truncating at
 * BSDNAMESPACE_JAIL_NAME_MAX-1 collapses every label sharing a 63-char prefix.  Both
 * are collisions an attacker can steer.  So we derive the name from a
 * collision-resistant hash of the *entire* label instead: "wj_" followed by the
 * hex of the first 30 bytes (240 bits) of SHA-256(label).  That is 63 characters
 * — within BSDNAMESPACE_JAIL_NAME_MAX — uses only the jail-safe alphabet (no '.', so no
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
valid_request(const struct bsdnamespace_request *rq)
{

	if (rq->op != BSDNAMESPACE_OP_ENTER_JAIL ||
	    (rq->flags & ~(BSDNAMESPACE_F_EPHEMERAL | BSDNAMESPACE_F_VNET)) != 0)
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

/* Largest jailparam vector this broker builds (name/path/persist/host/ip4/ip6/vnet/desc). */
#define	GATE_JAIL_MAXPARAMS	8

/*
 * Marshal an imported jailparam array into the mac_capability jail gate's option
 * vector and run kern_jail_set_gated() through the held SYS_GATE_JAIL token.
 * Mirrors jailparam_set(3)'s iovec construction exactly -- a value-less boolean,
 * a NUL-counted string, a fixed-width binary value otherwise -- but reaches jail
 * creation from capability mode, where jail_set(2) is forbidden.  On success the
 * jid is stored in *jid_out and, when a "desc" param is present, the installed
 * descriptor fd in *desc_out.  This broker never sets a boolean to false, so the
 * "no<name>" inversion jailparam_set performs for a zero value is unreachable
 * here and intentionally omitted.
 */
static int
gate_jail_set(struct jailparam *jp, unsigned njp, int flags, int *jid_out,
    int *desc_out)
{
	struct iovec jiov[2 * GATE_JAIL_MAXPARAMS];
	unsigned i, j;

	if (bsdnamespace_jail_token < 0) {
		errno = ENOTCAPABLE;
		return (-1);
	}
	if (njp > GATE_JAIL_MAXPARAMS) {
		errno = E2BIG;
		return (-1);
	}
	for (i = j = 0; j < njp; j++) {
		jiov[i].iov_base = jp[j].jp_name;
		jiov[i].iov_len = strlen(jp[j].jp_name) + 1;
		i++;
		if (jp[j].jp_flags & (JP_BOOL | JP_NOBOOL)) {
			/* A boolean is set by presence; this broker never clears one. */
			jiov[i].iov_base = NULL;
			jiov[i].iov_len = 0;
		} else {
			/* Fill a missing value with an empty string, as jailparam_set does. */
			if (jp[j].jp_value == NULL && jp[j].jp_valuelen > 0 &&
			    jailparam_import(&jp[j], "") < 0)
				return (-1);
			jiov[i].iov_base = jp[j].jp_value;
			jiov[i].iov_len =
			    (jp[j].jp_ctltype & CTLTYPE) == CTLTYPE_STRING
			    ? strlen(jp[j].jp_value) + 1 : jp[j].jp_valuelen;
		}
		i++;
	}
	return (service_system_jail_set(bsdnamespace_jail_token, jiov, i, flags,
	    jid_out, desc_out));
}

/*
 * Run kern_jail_get() through the held token, reading an existing jail's
 * parameters.  A param whose jp_value the caller already imported (e.g. "name")
 * is the lookup key; a param left uninitialised by jailparam_init() is an output
 * slot, given a generously-sized zeroed buffer here so a single round trip
 * suffices -- this broker only ever creates jails with one address, so an
 * address array never overflows a 512-byte slot (jailparam_get(3) instead
 * re-probes sizes in a retry loop, which the gate does not expose).  On success
 * each output param's jp_valuelen is set to the actual length the kernel wrote,
 * so jailparam_export(3) decodes it; *jid_out gets the jid and, when a "desc"
 * param is present, *desc_out gets the installed descriptor fd.
 */
static int
gate_jail_get(struct jailparam *jp, unsigned njp, int flags, int *jid_out,
    int *desc_out)
{
	struct iovec jiov[2 * GATE_JAIL_MAXPARAMS];
	unsigned i, j;
	int rc, saved;

	if (bsdnamespace_jail_token < 0) {
		errno = ENOTCAPABLE;
		return (-1);
	}
	if (njp > GATE_JAIL_MAXPARAMS) {
		errno = E2BIG;
		return (-1);
	}
	for (i = j = 0; j < njp; j++) {
		jiov[i].iov_base = jp[j].jp_name;
		jiov[i].iov_len = strlen(jp[j].jp_name) + 1;
		i++;
		if (jp[j].jp_value != NULL) {
			/* An imported input/key param (e.g. "name"). */
			jiov[i].iov_base = jp[j].jp_value;
			jiov[i].iov_len =
			    (jp[j].jp_ctltype & CTLTYPE) == CTLTYPE_STRING
			    ? strlen(jp[j].jp_value) + 1 : jp[j].jp_valuelen;
		} else {
			size_t len = jp[j].jp_valuelen;

			if (jp[j].jp_elemlen != 0 && len < 512)
				len = 512;	/* room for an address array */
			if (len == 0)
				len = 256;	/* a string with no fixed max */
			jp[j].jp_value = malloc(len);
			if (jp[j].jp_value == NULL)
				return (-1);
			memset(jp[j].jp_value, 0, len);
			jp[j].jp_valuelen = len;
			jiov[i].iov_base = jp[j].jp_value;
			jiov[i].iov_len = len;
		}
		i++;
	}
	rc = service_system_jail_get(bsdnamespace_jail_token, jiov, i, flags,
	    jid_out, desc_out);
	if (rc == -1)
		return (-1);
	/* Fold the true value lengths back so jailparam_export() can decode. */
	saved = errno;
	for (i = j = 0; j < njp; j++) {
		i++;				/* name iov */
		jp[j].jp_valuelen = jiov[i].iov_len;
		i++;
	}
	errno = saved;
	return (rc);
}

/*
 * Read one parameter of an existing jail into a text buffer, THROUGH the gate --
 * the capmode-safe replacement for jail_getv(0, "name", name, param, out, NULL).
 * Returns 0 on success (out holds the value, "" when the jail has the parameter
 * but no value, e.g. an address-less ip4.addr), or an errno (ENOENT when the
 * jail or the parameter is absent).  jailparam_export() renders arrays and
 * jailsys/boolean ints exactly as libjail would.
 */
static int
gate_jail_get_param(const char *name, const char *param, char *out, size_t outsz)
{
	struct jailparam jp[2];
	char *value;
	int rc, saved;

	if (outsz == 0)
		return (EINVAL);
	out[0] = '\0';
	if (jailparam_init(&jp[0], "name") < 0)
		return (errno != 0 ? errno : EINVAL);
	if (jailparam_import(&jp[0], name) < 0) {
		saved = errno;
		jailparam_free(jp, 1);
		return (saved != 0 ? saved : EINVAL);
	}
	if (jailparam_init(&jp[1], param) < 0) {
		saved = errno;
		jailparam_free(jp, 1);
		return (saved != 0 ? saved : EINVAL);
	}
	rc = gate_jail_get(jp, 2, 0, NULL, NULL);
	if (rc == -1) {
		saved = errno;
		jailparam_free(jp, 2);
		return (saved != 0 ? saved : EIO);
	}
	value = jailparam_export(&jp[1]);
	if (value != NULL) {
		(void)strlcpy(out, value, outsz);
		free(value);
	}
	jailparam_free(jp, 2);
	return (0);
}

/*
 * Acquire an owning descriptor (JAIL_OWN_DESC) for the named jail THROUGH the
 * gate.  The descriptor's stored credential (bsdnamespace's) authorizes a
 * consumer's jail_attach_jd(2); held for the connection's life it anchors an
 * ephemeral jail, since closing an owning descriptor removes the prison.
 * Returns the fd, or -1/errno (ENOENT when the jail is absent).
 */
static int
gate_owning_descriptor(const char *name)
{
	struct jailparam jp[2];
	static const char *pn[2] = { "name", "desc" };
	unsigned ninit;
	int jid, fd = -1, saved;

	for (ninit = 0; ninit < 2; ninit++)
		if (jailparam_init(&jp[ninit], pn[ninit]) < 0)
			break;
	if (ninit < 2) {
		saved = errno;
		jailparam_free(jp, ninit);
		errno = saved != 0 ? saved : EINVAL;
		return (-1);
	}
	if (jailparam_import(&jp[0], name) < 0) {
		saved = errno;
		jailparam_free(jp, 2);
		errno = saved != 0 ? saved : EINVAL;
		return (-1);
	}
	jid = gate_jail_get(jp, 2, JAIL_GET_DESC | JAIL_OWN_DESC, NULL, &fd);
	saved = errno;
	jailparam_free(jp, 2);
	if (jid < 0) {
		errno = saved;
		return (-1);
	}
	if (fd < 0) {
		errno = EPROTO;
		return (-1);
	}
	return (fd);
}

/*
 * Remove the named jail THROUGH the gate: acquire an owning descriptor and close
 * it, which triggers prison_remove (overriding persist and any other structural
 * reference) -- the capmode-safe equivalent of jail_remove(2), which is not
 * capsicum-enabled.  Returns 0 on removal, or -1/errno (ENOENT when already gone).
 */
static int
gate_jail_remove(const char *name)
{
	int fd;

	fd = gate_owning_descriptor(name);
	if (fd < 0)
		return (-1);
	(void)close(fd);		/* owning-descriptor close -> prison_remove */
	return (0);
}

/*
 * Cross-file removal entry for the forked reclaim child (reclaim.c), which shares
 * the dup'd SYS_GATE_JAIL token.  A thin non-static wrapper over gate_jail_remove
 * so reclaim reaps stale jails through the same gate as the live broker.
 */
int
bsdnamespace_jail_remove(const char *name)
{

	return (gate_jail_remove(name));
}

/*
 * Enumerate jails THROUGH the gate for the reclaim child.  Given the previous
 * jid (0 to start), fill *name with the next jail's name and return its jid; 0
 * at the end of the list; -1/errno on failure.  This is a lastjid walk (the
 * capmode-safe form of jail_get(2) iteration), used only to count wj_ jails that
 * predate the owner map -- it never removes anything.
 */
int
bsdnamespace_jail_next(int lastjid, char *name, size_t namesz)
{
	struct jailparam jp[2];
	char *value;
	int jid, saved;

	if (name == NULL || namesz == 0) {
		errno = EINVAL;
		return (-1);
	}
	name[0] = '\0';
	if (jailparam_init(&jp[0], "lastjid") < 0)
		return (-1);
	if (jailparam_import_raw(&jp[0], &lastjid, sizeof(lastjid)) < 0) {
		saved = errno;
		jailparam_free(jp, 1);
		errno = saved;
		return (-1);
	}
	if (jailparam_init(&jp[1], "name") < 0) {
		saved = errno;
		jailparam_free(jp, 1);
		errno = saved;
		return (-1);
	}
	jid = -1;
	if (gate_jail_get(jp, 2, 0, &jid, NULL) < 0) {
		saved = errno;
		jailparam_free(jp, 2);
		if (saved == ENOENT) {		/* end of the list */
			errno = 0;
			return (0);
		}
		errno = saved;
		return (-1);
	}
	value = jailparam_export(&jp[1]);
	if (value != NULL) {
		(void)strlcpy(name, value, namesz);
		free(value);
	}
	jailparam_free(jp, 2);
	return (jid);
}

/*
 * Fetch an existing jail's ip4.addr into out (empty string if the jail has no
 * address).  Returns 0 on success, or an errno.  This is a separate get with no
 * descriptor: jailparam_get(3) reports a requested-but-absent parameter as
 * ENOENT, so asking for ip4.addr in the main JAIL_GET_DESC call would be misread
 * as "jail absent". The caller accepts either ENOENT or a successful empty
 * list as an absent address, and compares nonempty lists exactly.
 */
static int
jail_get_ip4(const char *name, char *out, size_t outsz)
{

	return (gate_jail_get_param(name, "ip4.addr", out, outsz));
}

/*
 * Fetch an existing jail's ip6.addr into out (empty string if the jail has no
 * address).  Mirrors jail_get_ip4: a separate get with no descriptor, so an
 * absent parameter can report ENOENT separately from the descriptor lookup.
 * A successful empty list also means no address. Returns 0 or an errno.
 */
static int
jail_get_ip6(const char *name, char *out, size_t outsz)
{

	return (gate_jail_get_param(name, "ip6.addr", out, outsz));
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
	int error;

	*out = JAIL_SYS_DISABLE;
	buf[0] = '\0';
	error = gate_jail_get_param(name, "vnet", buf, sizeof(buf));
	if (error != 0)
		return (error);
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
 * stored credential is bsdnamespace's root) but closing it never removes the jail.
 * An ephemeral jail's lifetime is instead anchored by the per-client worker
 * process holding a separate owning descriptor (see bsdnamespace_request_handler).
 *
 * Reuse is safe ONLY when the *entire* requested definition matches the existing
 * jail: path, hostname, ip4 address, ip6 address, AND vnet setting.  A consumer
 * that reconnects must get back the jail it defined, never silently attach into a
 * differently-shaped one (which would discard its isolation request — e.g. a
 * requested ip6.addr or its own vnet — with no error).  Any mismatch is a hard
 * EEXIST, enforcing the immutable definition the reuse contract promises.
 */
static int
existing_jail_descriptor(const char *name, const struct bsdnamespace_request *rq)
{
	struct jailparam jp[4];
	static const char *pn[4] = { "name", "path", "host.hostname", "desc" };
	char path[PATH_MAX], host[MAXHOSTNAMELEN], ip4[256], ip6[256];
	const char *want_host = rq->hostname[0] != '\0' ? rq->hostname : name;
	bool want_vnet = (rq->flags & BSDNAMESPACE_F_VNET) != 0;
	char *pv, *hv;
	int jid, iperr, fd = -1, saved_errno, vnet, verr;
	unsigned ninit;

	/*
	 * name(key)/path/host.hostname/desc through the gate.  desc yields the
	 * jail descriptor fd directly (no decimal-string parse), the credential
	 * of which authorizes the consumer's attach; path/host.hostname are read
	 * back to enforce the immutable-definition reuse contract below.
	 */
	for (ninit = 0; ninit < 4; ninit++)
		if (jailparam_init(&jp[ninit], pn[ninit]) < 0)
			break;
	if (ninit < 4) {
		saved_errno = errno;
		jailparam_free(jp, ninit);
		errno = saved_errno != 0 ? saved_errno : EINVAL;
		return (-1);
	}
	if (jailparam_import(&jp[0], name) < 0) {
		saved_errno = errno;
		jailparam_free(jp, 4);
		errno = saved_errno != 0 ? saved_errno : EINVAL;
		return (-1);
	}
	jid = gate_jail_get(jp, 4, JAIL_GET_DESC, NULL, &fd);
	if (jid < 0) {
		saved_errno = errno;		/* ENOENT when absent */
		jailparam_free(jp, 4);
		errno = saved_errno;
		return (-1);
	}
	pv = jailparam_export(&jp[1]);
	hv = jailparam_export(&jp[2]);
	(void)strlcpy(path, pv != NULL ? pv : "", sizeof(path));
	(void)strlcpy(host, hv != NULL ? hv : "", sizeof(host));
	free(pv);
	free(hv);
	jailparam_free(jp, 4);

	/* Root path and hostname must match the request exactly. */
	if (strcmp(path, rq->path) != 0 || strcmp(host, want_host) != 0) {
		errno = EEXIST;
		goto fail;
	}

	/*
	 * The ip4 address must match too: a request asking for a specific
	 * address must not silently attach into an address-less (or
	 * differently-addressed) jail, and a request asking for none must not
	 * land in an addressed one. An empty address list may be returned
	 * successfully, rather than as ENOENT.
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
	} else if (iperr == 0 && ip4[0] != '\0') {
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
	} else if (iperr == 0 && ip6[0] != '\0') {
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

	if (fd < 0) {
		errno = EPROTO;
		goto fail;
	}
	return (fd);

fail:
	/*
	 * Preserve the mismatch errno (EEXIST, or an ip4/ip6/vnet lookup error)
	 * across the descriptor cleanup: close(2) can overwrite errno, which would
	 * make the caller mistake a definition conflict for a successful reuse.
	 */
	saved_errno = errno;
	if (fd >= 0)
		(void)close(fd);
	errno = saved_errno;
	return (-1);
}

/*
 * Create the named jail and return a descriptor whose stored credential (root,
 * from bsdnamespace) authorizes the consumer's jail_attach_jd(2), or -1/errno.  Uses
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
 * closes when the consumer disconnects (see bsdnamespace_request_handler).
 */
static int
create_jail(const char *name, const struct bsdnamespace_request *rq, int *out_jid)
{
	const char *host = rq->hostname[0] != '\0' ? rq->hostname : name;
	const char *pn[8];
	char *pv[8];
	struct jailparam jp[8];
	unsigned n, ninit;
	int jid, fd, saved_errno;

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
	if ((rq->flags & BSDNAMESPACE_F_VNET) != 0) {
		pn[n] = "vnet";
		/*
		 * "vnet" is a jailsys parameter: its value is the string
		 * "new"/"inherit"/"disable" (jailparam_import maps it to
		 * JAIL_SYS_*), NOT a numeric "1".
		 */
		pv[n++] = __DECONST(char *, "new");
	}
	pn[n] = "desc";			pv[n++] = __DECONST(char *, "");	/* fd filled on success */

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
	/*
	 * Create THROUGH the gate: kern_jail_set_gated() runs with the held
	 * SYS_GATE_JAIL claim standing in for PRIV_JAIL_SET and does the jail-root
	 * namei in kernel context, so a born-in-capmode broker builds a jail the
	 * raw capmode syscall could not.  The installed descriptor fd comes back
	 * directly (no decimal-string parse), so a malformed desc can no longer
	 * masquerade as fd 0.
	 */
	fd = -1;
	jid = -1;
	if (gate_jail_set(jp, n, JAIL_CREATE | JAIL_GET_DESC, &jid, &fd) == -1) {
		saved_errno = errno;
		jailparam_free(jp, n);
		errno = saved_errno;
		return (-1);
	}
	jailparam_free(jp, n);
	if (fd < 0) {
		/*
		 * The jail was created persist=1 but no descriptor came back to
		 * anchor it; remove it rather than leak a permanent jail.  Removal
		 * is itself gated (get an owning descriptor and close it).
		 */
		if (jid >= 0)
			(void)gate_jail_remove(name);
		errno = EPROTO;
		return (-1);
	}
	if (out_jid != NULL)
		*out_jid = jid;
	return (fd);
}

/*
 * Per-client connection state, private to one worker thread (== one consumer
 * connection).  bsdnamespace serves each accepted client on its own thread, not a
 * pdfork worker: the held SYS_GATE_JAIL token is close-on-fork, but threads share
 * it, so a born-in-capmode broker can perform gated jail ops for every client.
 *
 * owning_fd is an ephemeral jail's owning descriptor, held for the life of this
 * connection: when the consumer disconnects the worker thread returns and closes
 * it, and closing an owning descriptor removes the prison.  This is per-thread
 * (not file-scope) precisely because threads share one address space -- a global
 * would conflate distinct consumers' ephemeral jails.  -1 when none is held.
 */
struct bsdnamespace_conn {
	char	label[64];		/* the client's unforgeable channel label */
	int	owning_fd;		/* ephemeral-jail anchor, or -1 */
};

/* Send a status-only reply (no SCM fd): ENTER errors, DESTROY, dispatch. */
static void
send_status(struct channel_message *m, int32_t status)
{
	struct bsdnamespace_reply rp;
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
 * when the consumer exits.
 */
static void
handle_enter_jail(struct channel_message *m, struct bsdnamespace_conn *conn)
{
	const char *client = conn->label;
	const struct bsdnamespace_request *rq;
	struct bsdnamespace_reply rp;
	struct channel_outgoing out;
	char name[BSDNAMESPACE_JAIL_NAME_MAX];
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
	 * conn->owning_fd is a single slot private to this connection's thread.
	 * If it is already set, this channel has already anchored an ephemeral
	 * jail; a second ENTER would overwrite the slot and close the first
	 * owning fd, tearing that jail down while the consumer is still using
	 * it.  Reject the second ENTER instead of clobbering.
	 */
	if (conn->owning_fd >= 0) {
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
	 * For an ephemeral jail THIS request just CREATED, retain its owning
	 * descriptor in this worker so the jail is removed when the consumer
	 * disconnects (this worker exits).  Only anchor a freshly-created jail
	 * (created_jid >= 0), never a REUSED one: an ephemeral request that reused
	 * an existing jail must not convert that jail's lifetime -- a persistent
	 * jail reused with F_EPHEMERAL would otherwise be silently torn down on this
	 * disconnect, destroying the consumer's durable namespace.  (Reuse only ever
	 * matches a persistent jail anyway: an ephemeral jail is gone once its
	 * creator disconnects, so a relaunched consumer re-creates it here.)
	 * The consumer still attaches with the non-owning descriptor sent below.
	 * If acquiring the owning descriptor fails we FAIL the request rather than
	 * leak a permanent persist=1 jail nothing reclaims (fail closed).
	 */
	if (created_jid >= 0 && (rq->flags & BSDNAMESPACE_F_EPHEMERAL)) {
		conn->owning_fd = gate_owning_descriptor(name);
		if (conn->owning_fd < 0) {
			rp.status = errno != 0 ? errno : EIO;
			syslog(LOG_ERR, "ENTER %s (client %s) -> owning "
			    "descriptor failed, failing request: %m", name,
			    client);
			if (created_jid >= 0)
				(void)gate_jail_remove(name);
			(void)close(jd);
			jd = -1;
			goto reply;
		}
	}

reply:
	BSDNAMESPACE_PROBE_ENTER(client, created_jid, rp.status);
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &rp;
	out.length = sizeof(rp);
	if (jd >= 0 && rp.status == 0) {
		/*
		 * Single-hop delivery of the jail attach descriptor: this SCM send is
		 * the one-and-only delegation (CAP_XFER_ONCE -> the consumer's copy is
		 * non-re-delegable), close-on-fork, close-on-exec.  Jail attach is not
		 * label-gated in the kernel -- any holder of the descriptor can
		 * jail_attach_jd(2) -- so a re-delegable descriptor would let a
		 * differently-labelled component attach into a jail it was never
		 * scoped to, undercutting the per-label jail scoping.
		 */
		if (service_harden_fd(jd, SERVICE_HARDEN_XFER_ONCE |
		    SERVICE_HARDEN_CLOFORK_ONCE) == -1) {
			/*
			 * Could not make the descriptor non-re-delegable: fail
			 * CLOSED rather than hand out an attenuation-less jail
			 * attach capability.  Drop the fd and report the error.
			 */
			rp.status = EPERM;
			out.length = sizeof(rp);
		} else {
			out.fds = &jd;
			out.nfds = 1;
		}
	}
	(void)channel_send_reply(m, &out);
	if (jd >= 0)
		(void)close(jd);
}

/*
 * DESTROY_JAIL: remove the caller's label-scoped jail.  Owner-scoped by
 * construction — jail_name_from_label(client) names only the caller's own jail,
 * never another label's — so this can never remove a jail bsdnamespace created for a
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
	char name[BSDNAMESPACE_JAIL_NAME_MAX];

	if (channel_message_length(m) != sizeof(struct bsdnamespace_control_request)) {
		send_status(m, EPROTO);
		return;
	}
	if (!jail_name_from_label(client, name, sizeof(name))) {
		send_status(m, EINVAL);
		return;
	}
	/*
	 * Remove THROUGH the gate (acquire an owning descriptor and close it ->
	 * prison_remove), the capmode-safe equivalent of jail_remove(2).  ENOENT
	 * is the ordinary "caller has no jail" answer.
	 */
	if (gate_jail_remove(name) < 0) {
		int status = errno != 0 ? errno : EIO;

		if (status == ENOENT)
			syslog(LOG_INFO, "DESTROY %s (client %s) -> no such jail",
			    name, client);
		else
			syslog(LOG_ERR, "DESTROY %s (client %s) -> remove: %s",
			    name, client, strerror(status));
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
 * This reads the definition back through the gate (gate_jail_get()/
 * jail_get_ip4()) — the same primitives existing_jail_descriptor() uses — but
 * does NOT request the descriptor ("desc") path, so it neither installs a fd nor
 * anchors anything; the errno seen after a failed gate get here is the real
 * lookup errno (ENOENT == the caller has no jail).
 */
static void
handle_list_jails(struct channel_message *m, struct bsdnamespace_conn *conn)
{
	const char *client = conn->label;
	struct bsdnamespace_list_reply lr;
	struct channel_outgoing out;
	struct jailparam jp[3];
	static const char *lpn[3] = { "name", "path", "host.hostname" };
	char name[BSDNAMESPACE_JAIL_NAME_MAX];
	char path[PATH_MAX], host[MAXHOSTNAMELEN], ip4[256], ip6[256];
	char *pv, *hv;
	int jid, iperr, iperr6, vnet, verr, gerr;
	unsigned ninit;

	memset(&lr, 0, sizeof(lr));
	lr.jid = -1;

	/*
	 * A framing error is answered with the minimal status reply, not the
	 * large bsdnamespace_list_reply: an error carries no jail definition, and a
	 * caller that sent a malformed LIST has no reason to size its receive
	 * buffer for the full reply.
	 */
	if (channel_message_length(m) != sizeof(struct bsdnamespace_control_request)) {
		send_status(m, EPROTO);
		return;
	}
	if (!jail_name_from_label(client, name, sizeof(name))) {
		lr.status = EINVAL;
		goto reply;
	}

	for (ninit = 0; ninit < 3; ninit++)
		if (jailparam_init(&jp[ninit], lpn[ninit]) < 0)
			break;
	if (ninit < 3) {
		lr.status = errno != 0 ? errno : EINVAL;
		jailparam_free(jp, ninit);
		goto reply;
	}
	if (jailparam_import(&jp[0], name) < 0) {
		lr.status = errno != 0 ? errno : EINVAL;
		jailparam_free(jp, 3);
		goto reply;
	}
	jid = -1;
	if (gate_jail_get(jp, 3, 0, &jid, NULL) < 0) {
		gerr = errno;
		jailparam_free(jp, 3);
		/* ENOENT is the ordinary "caller has no jail" answer. */
		if (gerr == ENOENT) {
			lr.present = 0;
			lr.status = 0;
		} else {
			lr.status = gerr;
			syslog(LOG_NOTICE, "LIST %s (client %s) -> jail_get: %s",
			    name, client, strerror(lr.status));
		}
		goto reply;
	}
	/* gate_jail_get() returns 0 on success; the jid travels via jid_out. */
	pv = jailparam_export(&jp[1]);
	hv = jailparam_export(&jp[2]);
	(void)strlcpy(path, pv != NULL ? pv : "", sizeof(path));
	(void)strlcpy(host, hv != NULL ? hv : "", sizeof(host));
	free(pv);
	free(hv);
	jailparam_free(jp, 3);

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

	/*
	 * Report the jail's vnet setting so a consumer can reconstruct a matching
	 * ENTER after a restart.  jail_get_vnet() reads the same "vnet" jailsys
	 * parameter existing_jail_descriptor() enforces on reuse; a real lookup
	 * error is fatal, but ENOENT means "no vnet parameter" (a kernel without
	 * VIMAGE, or a non-vnet jail) and reads as "not a vnet jail".
	 */
	verr = jail_get_vnet(name, &vnet);
	if (verr != 0 && verr != ENOENT) {
		lr.status = verr;
		syslog(LOG_NOTICE, "LIST %s (client %s) -> vnet: %s", name, client,
		    strerror(verr));
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
	/*
	 * Report the jail's shape as BSDNAMESPACE_F_* bits.  BSDNAMESPACE_F_VNET when the jail
	 * owns its network stack.  BSDNAMESPACE_F_EPHEMERAL when THIS connection anchors
	 * the jail's lifetime with an owning descriptor (conn->owning_fd >= 0): that
	 * is a jail this same channel created ephemerally.  A persistent jail
	 * reused by a relaunched consumer has no such anchor and reports the flag
	 * clear -- exactly the persist/ephemeral distinction the consumer needs.
	 */
	lr.flags = 0;
	if (verr == 0 && vnet == JAIL_SYS_NEW)
		lr.flags |= BSDNAMESPACE_F_VNET;
	if (conn->owning_fd >= 0)
		lr.flags |= BSDNAMESPACE_F_EPHEMERAL;
	syslog(LOG_INFO, "LIST %s (client %s) -> present jid=%d flags=0x%x", name,
	    client, jid, lr.flags);

reply:
	memset(&out, 0, sizeof(out));
	out.size = sizeof(out);
	out.data = &lr;
	out.length = sizeof(lr);
	(void)channel_send_reply(m, &out);
}

/*
 * Per-client channel request handler.  arg is this connection's state (its
 * unforgeable label plus any ephemeral-jail anchor).  Every op is validated
 * fail-closed: the channel accepts no SCM fds (an attached descriptor is already
 * a terminal transport rejection, so fd_count is never > 0 here in practice, but
 * reject defensively), and the message must be long enough to hold at least the
 * opcode word before it is dispatched.  ENTER requires the full
 * bsdnamespace_request; DESTROY and LIST require a bsdnamespace_control_request;
 * an unknown op is EINVAL.
 */
static void
bsdnamespace_request_handler(struct channel *ch __unused, struct channel_message *m,
    void *arg)
{
	struct bsdnamespace_conn *conn = arg;
	uint32_t op;

	if (channel_message_fd_count(m) != 0 ||
	    channel_message_length(m) < sizeof(uint32_t)) {
		send_status(m, EPROTO);
		goto done;
	}
	memcpy(&op, channel_message_data(m), sizeof(op));
	switch (op) {
	case BSDNAMESPACE_OP_ENTER_JAIL:
		handle_enter_jail(m, conn);
		break;
	case BSDNAMESPACE_OP_DESTROY_JAIL:
		handle_destroy_jail(m, conn->label);
		break;
	case BSDNAMESPACE_OP_LIST_JAILS:
		handle_list_jails(m, conn);
		break;
	default:
		send_status(m, EINVAL);
		break;
	}
done:
	channel_message_free(m);
}

/*
 * Serve one client on its own worker channel until it closes.  The connection
 * state (label + ephemeral-jail anchor) is stack-local, so distinct client
 * threads never share an anchor.  When the session ends, closing conn.owning_fd
 * removes any ephemeral jail this connection anchored (owning-descriptor close ->
 * prison_remove) -- the capmode analogue of the old pdfork worker exiting.
 */
static int
bsdnamespace_worker(int fd, const char *client)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct channel *channel = NULL;
	struct bsdnamespace_conn conn;
	int ready, wants_write;

	memset(&conn, 0, sizeof(conn));
	conn.owning_fd = -1;
	(void)strlcpy(conn.label, client, sizeof(conn.label));

	/*
	 * channel_create() consumes (closes) fd on success and leaves it on
	 * failure -- so close it here only on failure, and NEVER after return.
	 * The caller (bsdnamespace_client_thread) must not close it again: doing
	 * so closes an fd number channel_create already returned to the pool,
	 * which a concurrent accept on another thread may have re-used (a
	 * double-close race that silently tears down a co-connecting client).
	 */
	if (channel_create(fd, &options, &channel) == -1) {
		(void)close(fd);
		return (1);
	}
	if (channel_set_request_handler(channel, bsdnamespace_request_handler,
	    &conn) == -1) {
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
	if (conn.owning_fd >= 0)
		(void)close(conn.owning_fd);	/* tears down the ephemeral jail */
	return (0);
}

#ifdef BSDNAMESPACE_TESTING
/*
 * Test entrypoints.  These expose the pure decision logic (name derivation,
 * request validation) and the per-client channel worker to the ATF suite without
 * duplicating any of it.  The daemon build never compiles this block; behavior of
 * the shipped binary is unchanged.
 */
#include "bsdnamespace_test.h"

bool
bsdnamespace_test_jail_name(const char *label, char *out, size_t outsz)
{

	return (jail_name_from_label(label, out, outsz));
}

bool
bsdnamespace_test_valid_request(const struct bsdnamespace_request *rq)
{

	return (valid_request(rq));
}

int
bsdnamespace_test_worker(int fd, const char *client)
{

	return (bsdnamespace_worker(fd, client));
}

/*
 * Install a held SYS_GATE_JAIL token for the worker (production dups the
 * switchboard-delivered one via service_system_token_dup; a test mints and
 * authorizes its own, then hands it here before running the worker).
 */
void
bsdnamespace_test_set_jail_token(int fd)
{

	bsdnamespace_jail_token = fd;
}
#endif /* BSDNAMESPACE_TESTING */

#ifndef BSDNAMESPACE_TESTING
/* One accepted client handed to its worker thread; freed when the thread ends. */
struct bsdnamespace_client {
	int	fd;
	char	label[64];		/* the client's resource-owner label */
};

/*
 * Per-client worker thread: run the channel session to completion, then close
 * the client fd and release the argument.  Threads (unlike pdfork workers) share
 * the daemon's SYS_GATE_JAIL token, so each can perform gated jail ops.
 */
/*
 * Bound concurrent client threads so a switchboard-authorized label cannot
 * exhaust threads/fds/address space on the jail broker with long-lived
 * connections.  A thread carries a stack (unlike a pdfork worker's separate
 * address space), so the ceiling is lower than the *_MAX_WORKERS = 4096 the
 * process-per-client daemons use; 256 concurrent jail sessions is far above any
 * legitimate need, and a refused client simply retries.
 */
#define	BSDNAMESPACE_MAX_CLIENTS	256
static _Atomic unsigned bsdnamespace_nthreads;

static void *
bsdnamespace_client_thread(void *arg)
{
	struct bsdnamespace_client *c = arg;

	/* bsdnamespace_worker() owns c->fd (channel_create consumes it, or it
	 * closes it on failure) -- do NOT close it again here (double-close race). */
	(void)bsdnamespace_worker(c->fd, c->label);
	free(c);
	(void)atomic_fetch_sub_explicit(&bsdnamespace_nthreads, 1,
	    memory_order_relaxed);
	return (NULL);
}

/*
 * Expose system.Namespace and dispatch each accepted client on its own thread.
 * bsdnamespace is BORN IN CAPABILITY MODE: it dups the switchboard-delivered
 * SYS_GATE_JAIL token (so it outlives the bootstrap authority drop), enters
 * capability mode, and performs every jail create/get/remove THROUGH that token
 * (service_system_jail_set/get -> kern_jail_set_gated/kern_jail_get), where the
 * held claim replaces PRIV_JAIL_SET and the jail-root namei runs in kernel
 * context.  Returns -1 only on setup failure.
 */
static int
bsdnamespace_serve(void)
{
	struct service_identity id;
	struct service_listener *listener;
	struct service_provider *provider;
	int fd, owners_fd;

	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_expose(provider, BSDNAMESPACE_SERVICE_NAME,
	    &listener) == -1)
		return (-1);
	/*
	 * Dup the delivered jail token before entering capmode.  Fail-soft: with
	 * no token every gated op returns ENOTCAPABLE (rather than silently
	 * attempting a privileged syscall the sandbox would refuse anyway), so a
	 * misprovisioned plane fails closed and visibly.
	 */
	if (service_system_token_dup(&bsdnamespace_jail_token) == -1) {
		syslog(LOG_WARNING, "no jail capability delivered; jail operations "
		    "will fail until one is provisioned: %m");
		bsdnamespace_jail_token = -1;
	}
	if (service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1)
		return (-1);

	/*
	 * Jail reclaim (container model): the owner map lives in bsdnamespace's own
	 * storage, the reconcile runs in a forked child that inherits the dup'd
	 * token (which is not close-on-fork) and removes stale jails through it.
	 * Soft: without storage or delivered roots bsdnamespace serves without reclaim.
	 */
	owners_fd = bsdnamespace_reclaim_start();

	for (;;) {
		struct bsdnamespace_client *c;
		pthread_t tid;
		int error;

		memset(&id, 0, sizeof(id));
		id.size = sizeof(id);
		if (service_listener_accept(listener, &id, &fd) == -1) {
			error = errno;
			/* A clean quiesce is the only reason to leave the loop. */
			if (service_provider_quiescing(provider) == 1) {
				int qst = service_provider_quiesce_complete(
				    provider, 0);
				return (qst == 0 ? 0 : 1);
			}
			/*
			 * Otherwise never exit: this broker's death closes every
			 * ephemeral jail's owning descriptor and drops live
			 * consumers' jails.  Log and keep serving; back off on fd
			 * exhaustion so the loop does not spin.
			 */
			if (error == EMFILE || error == ENFILE)
				(void)usleep(100000);
			if (error != EINTR)
				syslog(LOG_ERR, "accept: %s", strerror(error));
			continue;
		}
		/*
		 * Attribute the client's (future) jail to its bundle so the
		 * reconcile can reap it once the bundle is gone: the jail name
		 * is a one-way hash of the resource owner, and the bundle comes
		 * from the stamped container, never the wire.  Units without a
		 * bundle (sessions, rc units) are not noted.
		 */
		if (owners_fd >= 0 && id.container[0] != '\0') {
			char jname[BSDNAMESPACE_JAIL_NAME_MAX], bundle[64];

			if (jail_name_from_label(id.resource_owner, jname,
			    sizeof(jname)) &&
			    bsdnamespace_bundle_of(id.container, bundle,
			    sizeof(bundle)) == 0 &&
			    bsdnamespace_owner_note(owners_fd, jname, bundle) == -1)
				syslog(LOG_WARNING, "reclaim: cannot note jail %s "
				    "for bundle %s: %m", jname, bundle);
		}
		/*
		 * Serve each client on its own THREAD, not a pdfork worker: the
		 * dup'd SYS_GATE_JAIL token is shared by threads but would be lost
		 * by a fork boundary's close-on-fork consumption, and consumers
		 * hold long-lived connections that must not head-of-line block.
		 */
		if (atomic_load_explicit(&bsdnamespace_nthreads,
		    memory_order_relaxed) >= BSDNAMESPACE_MAX_CLIENTS) {
			syslog(LOG_WARNING, "client from %s refused: %u sessions "
			    "already active", id.resource_owner,
			    BSDNAMESPACE_MAX_CLIENTS);
			(void)close(fd);
			continue;
		}
		c = malloc(sizeof(*c));
		if (c == NULL) {
			syslog(LOG_WARNING, "client alloc: %m");
			(void)close(fd);
			continue;
		}
		c->fd = fd;
		(void)strlcpy(c->label, id.resource_owner, sizeof(c->label));
		/*
		 * Count the thread before creating it (the single-threaded accept
		 * loop is the only incrementer; workers only decrement); undo on
		 * failure.
		 */
		(void)atomic_fetch_add_explicit(&bsdnamespace_nthreads, 1,
		    memory_order_relaxed);
		error = pthread_create(&tid, NULL, bsdnamespace_client_thread, c);
		if (error != 0) {
			(void)atomic_fetch_sub_explicit(&bsdnamespace_nthreads, 1,
			    memory_order_relaxed);
			syslog(LOG_ERR, "pthread_create: %s", strerror(error));
			(void)close(fd);
			free(c);
			continue;
		}
		(void)pthread_detach(tid);
	}
}

int
main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			(void)fprintf(stderr, "usage: bsdnamespace\n");
			return (1);
		}
	}
	if (argc != optind) {
		(void)fprintf(stderr, "usage: bsdnamespace\n");
		return (1);
	}

	openlog("bsdnamespace", LOG_PID | LOG_PERROR, LOG_DAEMON);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGCHLD, SIG_IGN);

	reserve_stdio();

	setproctitle("-Namespace");
	syslog(LOG_NOTICE, "bsdnamespace namespace (jail) broker");

	if (bsdnamespace_serve() == -1)
		errx(1, "namespace provider failed");

	return (0);
}
#endif /* !BSDNAMESPACE_TESTING */
