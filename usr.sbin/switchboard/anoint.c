/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * IPC anointments, v1 (docs/ipc-anointments-design.md).
 *
 * An endpoint may declare, in its bundle's policy file, the anointment names a
 * connecting program must hold (all of them).  A unit declares what it holds
 * in its own policy file; a login session holds what the auth agent's
 * principal policy gave it at mint.  This file owns the set representation,
 * the match, and the refusal record.  Matching is by exact, case-sensitive
 * string comparison; the names are opaque here — the parser already validated
 * their form.
 *
 * Every refusal is audited (AUE_SWITCHBOARD_ANOINT, with the requester label,
 * the endpoint and the missing names) and traced (anoint-deny) in one place,
 * svc_anoint_deny(), so the resolve path (naming.c) and the on-demand pre-check
 * (on_demand.c) report identically.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "switchboard.h"
#include "switchboard_audit.h"
#include "switchboard_probes.h"
#include "switchboard_svc_proto.h"

/*
 * A unit's set is exactly its policy-file `anointments` list.  Units never
 * hold "*" (libcapbundle refuses it) and never carry the ADMIN rights bit —
 * a unit is not an admin principal, whatever its uid or bundle class.
 */
void
svc_anoint_set_from_manifest(struct svc_anoint_set *set,
    const struct svc_manifest *m)
{
	unsigned i, n;

	memset(set, 0, sizeof(*set));
	if (m == NULL)
		return;
	n = m->nanointments;
	if (n > SVC_ANOINT_MAX)
		n = SVC_ANOINT_MAX;
	for (i = 0; i < n; i++) {
		if (m->anointments[i][0] == '\0')
			continue;
		strlcpy(set->names[set->n], m->anointments[i],
		    sizeof(set->names[set->n]));
		set->n++;
	}
	set->all = false;
	set->admin_rights = false;
}

/*
 * Validate a SVC_OP_MINT_DOMAIN request's anointment fields and build the set
 * the minted session channel will carry.  Returns 0 with *set filled, or
 * EINVAL: an unknown flag, a count over the bound, a nonzero reserved word, or
 * a name that is empty, unterminated, or the wildcard ("*" travels as
 * SVC_MINT_FLAG_ANOINT_ALL, never as a name, so a payload cannot smuggle it
 * past a caller that meant a literal list).  Entries past nanointments are
 * ignored.  Pure: no channel or registry state, so it is unit-testable.
 */
int
svc_anoint_set_from_mint(const struct svc_mint_domain_req *req,
    struct svc_anoint_set *set)
{
	unsigned i;
	size_t len;

	memset(set, 0, sizeof(*set));
	if (req == NULL)
		return (EINVAL);
	if ((req->flags & ~(SVC_MINT_FLAG_RESEND | SVC_MINT_FLAG_ANOINT_ALL |
	    SVC_MINT_FLAG_ADMIN_RIGHTS)) != 0)
		return (EINVAL);
	if (req->reserved != 0)
		return (EINVAL);
	if (req->nanointments > SVC_ANOINT_MAX)
		return (EINVAL);
	for (i = 0; i < req->nanointments; i++) {
		len = strnlen(req->anointments[i], SVC_ANOINT_NAME_MAX);
		if (len == 0 || len >= SVC_ANOINT_NAME_MAX)
			return (EINVAL);
		if (strcmp(req->anointments[i], "*") == 0)
			return (EINVAL);
		memcpy(set->names[i], req->anointments[i], len + 1);
	}
	set->n = req->nanointments;
	set->all = (req->flags & SVC_MINT_FLAG_ANOINT_ALL) != 0;
	set->admin_rights = (req->flags & SVC_MINT_FLAG_ADMIN_RIGHTS) != 0;
	return (0);
}

/* Whether the set holds one name.  A NULL set holds nothing. */
bool
svc_anoint_holds(const struct svc_anoint_set *set, const char *name)
{
	unsigned i, n;

	if (set == NULL || name == NULL)
		return (false);
	if (set->all)
		return (true);
	n = set->n;
	if (n > SVC_ANOINT_MAX)
		n = SVC_ANOINT_MAX;
	for (i = 0; i < n; i++) {
		if (strcmp(set->names[i], name) == 0)
			return (true);
	}
	return (false);
}

/*
 * The match: does the set cover an endpoint's requires?  All-of semantics; an
 * open endpoint (nrequires == 0) is covered by every set, including NULL, and
 * `all` covers everything.
 */
bool
svc_anoint_covers(const struct svc_anoint_set *set,
    const char (*requires)[SWITCHBOARD_LABEL_MAX], unsigned nrequires)
{
	unsigned j;

	if (nrequires == 0)
		return (true);
	if (set == NULL)
		return (false);
	if (set->all)
		return (true);
	if (requires == NULL)
		return (false);
	if (nrequires > SWITCHBOARD_MAX_REQUIRES)
		nrequires = SWITCHBOARD_MAX_REQUIRES;
	for (j = 0; j < nrequires; j++) {
		if (!svc_anoint_holds(set, requires[j]))
			return (false);
	}
	return (true);
}

/*
 * The requires list of `name` as published by a running unit's own manifest
 * (the policy it was launched with).  Returns 0 with *requires pointing into
 * the manifest (and *nrequires, possibly 0 = open), or -1 when the manifest
 * does not publish `name` at all (a synthetic helper name, for instance).
 */
int
svc_anoint_unit_requires(const struct svc_manifest *m, const char *name,
    const char (**requires)[SWITCHBOARD_LABEL_MAX], unsigned *nrequires)
{
	unsigned i, n;

	*requires = NULL;
	*nrequires = 0;
	if (m == NULL || name == NULL)
		return (-1);
	n = m->nprovides;
	if (n > SWITCHBOARD_MAX_PROVIDES)
		n = SWITCHBOARD_MAX_PROVIDES;
	for (i = 0; i < n; i++) {
		if (strcmp(m->provides[i], name) != 0)
			continue;
		*requires = m->requires[i];
		*nrequires = m->nrequires[i] > SWITCHBOARD_MAX_REQUIRES ?
		    SWITCHBOARD_MAX_REQUIRES : m->nrequires[i];
		return (0);
	}
	return (-1);
}

/*
 * The requires list of `name` from the bundle registry, which indexes every
 * provides name to its unit whether or not the provider is running — so this
 * answers on the on-demand path (provider stopped) as well as the resolve
 * path.  Copies at most SWITCHBOARD_MAX_REQUIRES names into the caller's
 * buffer.  Returns 0 (with *nrequires possibly 0 = open) or -1 when the
 * registry does not know the name; the caller treats unknown as open, since
 * a name nobody publishes gates nothing and will fail as unregistered anyway.
 */
int
svc_anoint_endpoint_requires(const char *name,
    char (*requires)[SWITCHBOARD_LABEL_MAX], unsigned *nrequires)
{
	const struct capbundle_service *s;
	struct capbundle *b;
	const char *r;
	unsigned bi, si, j, n;
	int idx;

	*nrequires = 0;
	if (name == NULL || bundle_registry_lookup(name, &bi, &si) != 0)
		return (-1);
	b = bundle_registry_get(bi);
	if (b == NULL)
		return (-1);
	s = capbundle_service(b, si);
	if (s == NULL)
		return (-1);
	idx = capbundle_svc_provides_index(s, name);
	if (idx < 0)
		return (-1);
	n = capbundle_svc_nrequires(s, (unsigned)idx);
	if (n > SWITCHBOARD_MAX_REQUIRES)
		n = SWITCHBOARD_MAX_REQUIRES;
	for (j = 0; j < n; j++) {
		r = capbundle_svc_requires(s, (unsigned)idx, j);
		if (r == NULL)
			break;
		strlcpy(requires[j], r, SWITCHBOARD_LABEL_MAX);
	}
	*nrequires = j;
	return (0);
}

/*
 * Whether the registry publishes `name` as a gated endpoint (non-empty
 * requires).  A gated endpoint is visible to whoever covers it regardless of
 * the provider's resolvable_by: the provider gated it, so it said who may
 * reach it.  Unknown names are not gated.
 */
bool
svc_anoint_name_gated(const char *name)
{
	char requires[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	unsigned n;

	if (svc_anoint_endpoint_requires(name, requires, &n) != 0)
		return (false);
	return (n > 0);
}

/*
 * Render the names in requires[] the set does not hold, comma-separated, for
 * the audit record and the log line.  Returns the number of missing names.
 */
size_t
svc_anoint_missing(const struct svc_anoint_set *set,
    const char (*requires)[SWITCHBOARD_LABEL_MAX], unsigned nrequires,
    char *buf, size_t buflen)
{
	size_t missing, used;
	unsigned j;
	int w;

	missing = 0;
	used = 0;
	if (buflen > 0)
		buf[0] = '\0';
	if (requires == NULL)
		return (0);
	if (nrequires > SWITCHBOARD_MAX_REQUIRES)
		nrequires = SWITCHBOARD_MAX_REQUIRES;
	for (j = 0; j < nrequires; j++) {
		if (svc_anoint_holds(set, requires[j]))
			continue;
		if (buflen > used) {
			w = snprintf(buf + used, buflen - used, "%s%s",
			    missing > 0 ? "," : "", requires[j]);
			if (w > 0)
				used += (size_t)w < buflen - used ? (size_t)w :
				    buflen - used - 1;
		}
		missing++;
	}
	return (missing);
}

/*
 * Record one refusal: audit trail, DTrace probe, and a syslog line.  `label`
 * is the requester's identity (a unit's policy-file label, or the reserved
 * org.5bsd.user-session for a login session); `uid` is the requester's uid
 * from the kernel sender stamp when the caller had one.
 */
void
svc_anoint_deny(const char *name, const char *label, uid_t uid,
    const char *missing)
{

	if (label == NULL)
		label = "org.5bsd.user-session";
	if (missing == NULL)
		missing = "";
	(void)uid;	/* consumed only by the audit record when built in */
	switchboard_audit(AUE_SWITCHBOARD_ANOINT, uid, EACCES,
	    "anointment refused: %s -> %s missing %s", label, name, missing);
	SWITCHBOARD_PROBE_ANOINT_DENY(name, label, missing);
	syslog(LOG_NOTICE, "anoint: '%s' refused '%s': missing %s",
	    label, name, missing);
}

/*
 * The on-demand pre-check: before switchboard activates a stopped provider on
 * a requester's behalf, confirm the requester could reach the endpoint once
 * it is up.  A program that cannot reach a provider must not be able to start
 * it (an existence/side-effect leak).  Reads the registry, since the provider
 * is by definition not running.  Returns 0 (covered, or the registry does not
 * gate the name), or -1 with errno = EACCES after recording the refusal.
 */
int
od_anoint_precheck(const char *name, const struct svc_anoint_set *set,
    const char *label, uid_t uid)
{
	char requires[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	char missing[SWITCHBOARD_MAX_REQUIRES * SWITCHBOARD_LABEL_MAX];
	unsigned n;

	if (svc_anoint_endpoint_requires(name, requires, &n) != 0 || n == 0)
		return (0);
	if (svc_anoint_covers(set, requires, n))
		return (0);
	(void)svc_anoint_missing(set, requires, n, missing, sizeof(missing));
	svc_anoint_deny(name, label, uid, missing);
	errno = EACCES;
	return (-1);
}
