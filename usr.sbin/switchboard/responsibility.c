/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * responsibility.c — who a launched unit exists on behalf of.
 *
 * Every native unit runs in its own kernel coalition; the coalition carries a
 * permanent id and a set-once "responsible parent" edge
 * (COALITION_OP_SET_RESPONSIBLE).  This file decides the parent from the
 * launch context and records it, following the management model:
 *
 *   - a private helper, or a per-user unit requested by a unit of the same
 *     owner, is responsible to the REQUESTING UNIT's coalition;
 *   - a per-user unit activated from a login session of its owner is
 *     responsible to that SESSION's coalition;
 *   - a shared SYSTEM/CORE provider activated on demand by an arbitrary
 *     client answers for ITSELF (a client that happened to touch
 *     system.Crypto first does not own it; per-request attribution is the
 *     badge's job);
 *   - a boot-launched, operator-started, or adopted unit is responsible to
 *     SWITCHBOARD's own root coalition, so the chain ends at the system.
 *
 * The edge is attribution only: it never changes membership, signals, or
 * lifetime, and it is walkable from any process (ps -o coal,rcoal,rpid,
 * procstat coalition, OES events) back to a session or the system.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <dev/mac_capability/mac_capability_coalition_proto.h>

#include "switchboard.h"

/*
 * Does `requester` manage `unit`, in the sense that a launch it caused is
 * its own doing rather than a shared service?  Mirrors
 * svc_management_check_class: a per-user unit belongs to its owner, a
 * helper belongs to whoever opened it, and SYSTEM/CORE providers belong to
 * no requester.
 */
static bool
requester_manages(const struct svc_runtime *unit,
    const struct svc_runtime *requester)
{

	if (unit->manifest.is_helper)
		return (true);
	if (unit->manifest.management == SVC_MGMT_USER)
		return (unit->owner_uid != (uid_t)-1 &&
		    requester->owner_uid == unit->owner_uid);
	return (false);
}

static int
dup_parent(int fd)
{

	if (fd < 0)
		return (-1);
	return (fcntl(fd, F_DUPFD_CLOEXEC, 0));
}

void
svc_responsibility_clear(struct svc_runtime *svc)
{

	if (svc->responsible.parent_fd >= 0)
		(void)close(svc->responsible.parent_fd);
	memset(&svc->responsible, 0, sizeof(svc->responsible));
	svc->responsible.parent_fd = -1;
}

void
svc_responsibility_decide(struct svc_runtime *unit,
    const struct svc_runtime *requester,
    const struct svc_lookup_channel *session)
{
	struct svc_responsible *r = &unit->responsible;

	svc_responsibility_clear(unit);
	if (requester != NULL) {
		if (requester_manages(unit, requester) &&
		    requester->coalition_fd >= 0) {
			r->parent_fd = dup_parent(requester->coalition_fd);
			if (r->parent_fd >= 0) {
				r->kind = SVC_RESP_UNIT;
				strlcpy(r->label, requester->manifest.label,
				    sizeof(r->label));
				r->parent_id = requester->coalition_id;
				return;
			}
			syslog(LOG_NOTICE, "responsibility: %s: cannot hold "
			    "%s's coalition (%m); rooting the unit itself",
			    unit->manifest.label, requester->manifest.label);
		}
		r->kind = SVC_RESP_SELF;
		return;
	}
	if (session != NULL) {
		if (unit->manifest.management == SVC_MGMT_USER &&
		    unit->owner_uid != (uid_t)-1 &&
		    unit->owner_uid == lookup_channel_uid(session) &&
		    lookup_channel_coalition_fd(session) >= 0) {
			r->parent_fd =
			    dup_parent(lookup_channel_coalition_fd(session));
			if (r->parent_fd >= 0) {
				r->kind = SVC_RESP_SESSION;
				r->uid = lookup_channel_uid(session);
				r->parent_id =
				    lookup_channel_coalition_id(session);
				return;
			}
			syslog(LOG_NOTICE, "responsibility: %s: cannot hold "
			    "the session coalition (%m); rooting the unit itself",
			    unit->manifest.label);
		}
		r->kind = SVC_RESP_SELF;
		return;
	}
	/* Boot, operator start, adoption: the system (id 0 = no root minted). */
	if (sd.root_coalition_fd >= 0 && sd.root_coalition_id != 0) {
		r->parent_fd = dup_parent(sd.root_coalition_fd);
		if (r->parent_fd >= 0) {
			r->kind = SVC_RESP_SWITCHBOARD;
			r->parent_id = sd.root_coalition_id;
			return;
		}
	}
	r->kind = SVC_RESP_SELF;
}

/*
 * Does this unit's launch constraint allow the party that is about to be
 * recorded as responsible for it?  An empty constraint allows anyone.  The
 * token vocabulary is the one svc_responsibility_name() prints and
 * libcapbundle validates: self, switchboard, session, session:uid=<n>,
 * bundle (any unit of this unit's own bundle), or a full unit label.
 */
bool
svc_responsible_allowed(const struct svc_manifest *m,
    const struct svc_responsible *r)
{
	char uidtok[32];
	unsigned i;

	if (m->nlaunch_responsible == 0)
		return (true);
	(void)snprintf(uidtok, sizeof(uidtok), "session:uid=%u",
	    (unsigned)r->uid);
	for (i = 0; i < m->nlaunch_responsible; i++) {
		const char *t = m->launch_responsible[i];

		switch (r->kind) {
		case SVC_RESP_SELF:
			if (strcmp(t, "self") == 0)
				return (true);
			break;
		case SVC_RESP_SWITCHBOARD:
			if (strcmp(t, "switchboard") == 0)
				return (true);
			break;
		case SVC_RESP_SESSION:
			if (strcmp(t, "session") == 0 ||
			    strcmp(t, uidtok) == 0)
				return (true);
			break;
		case SVC_RESP_UNIT:
			if (strcmp(t, r->label) == 0)
				return (true);
			if (strcmp(t, "bundle") == 0) {
				const char *a = strchr(m->label, '/');
				const char *b = strchr(r->label, '/');
				size_t la = a != NULL ?
				    (size_t)(a - m->label) : strlen(m->label);
				size_t lb = b != NULL ?
				    (size_t)(b - r->label) : strlen(r->label);

				if (la != 0 && la == lb &&
				    strncmp(m->label, r->label, la) == 0)
					return (true);
			}
			break;
		case SVC_RESP_UNSET:
		default:
			break;
		}
	}
	return (false);
}

const char *
svc_responsibility_name(const struct svc_responsible *r, char *buf,
    size_t len)
{

	switch (r->kind) {
	case SVC_RESP_SELF:
		return ("self");
	case SVC_RESP_SWITCHBOARD:
		return ("switchboard");
	case SVC_RESP_UNIT:
		return (r->label);
	case SVC_RESP_SESSION:
		(void)snprintf(buf, len, "session:uid=%u", (unsigned)r->uid);
		return (buf);
	default:
		return ("unset");
	}
}

/*
 * Record the decided parent on a freshly minted coalition and learn both
 * ids.  Best-effort: attribution must never fail a launch.  A parent whose
 * coalition is gone (EBADF/ESRCH) degrades to a self-root, logged.
 */
void
svc_responsibility_apply(struct svc_runtime *svc, int coalition_fd)
{
	struct coalition_stat_reply sr;
	struct svc_responsible *r = &svc->responsible;
	char nbuf[64];
	int rc;

	svc->coalition_id = 0;
	if (coalition_fd < 0)
		return;
	if (r->kind == SVC_RESP_UNSET)
		svc_responsibility_decide(svc, NULL, NULL);
	if (r->kind == SVC_RESP_SELF || r->parent_fd < 0)
		rc = mac_cap_coalition_set_responsible(coalition_fd, -1,
		    COALITION_RESP_SELF);
	else {
		rc = mac_cap_coalition_set_responsible(coalition_fd,
		    r->parent_fd, 0);
		if (rc != 0) {
			syslog(LOG_NOTICE, "responsibility: %s: parent %s "
			    "unavailable (%m); rooting the unit itself",
			    svc->manifest.label,
			    svc_responsibility_name(r, nbuf, sizeof(nbuf)));
			svc_responsibility_clear(svc);
			r->kind = SVC_RESP_SELF;
			rc = mac_cap_coalition_set_responsible(coalition_fd,
			    -1, COALITION_RESP_SELF);
		}
	}
	if (rc != 0)
		syslog(LOG_WARNING, "responsibility: %s: set_responsible: %m",
		    svc->manifest.label);
	if (mac_cap_coalition_stat(coalition_fd, &sr) != 0) {
		syslog(LOG_WARNING, "responsibility: %s: coalition stat: %m",
		    svc->manifest.label);
		return;
	}
	svc->coalition_id = sr.id;
	r->parent_id = sr.responsible_id;
	syslog(LOG_INFO, "service %s: coalition %ju responsible to %s (%ju)",
	    svc->manifest.label, (uintmax_t)sr.id,
	    svc_responsibility_name(r, nbuf, sizeof(nbuf)),
	    (uintmax_t)sr.responsible_id);
}

/*
 * Coalition ids are unique for one boot only (a kernel counter).  Pair them
 * with the kernel's boot id so a record from one boot can never be confused
 * with the same number from another.  Hex, 32 chars; "unknown" if the
 * sysctl is unavailable.
 */
const char *
svc_boot_id(char *buf, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char id[16];
	size_t n = sizeof(id), i;

	if (len < 2 * sizeof(id) + 1 ||
	    sysctlbyname("kern.boot_id", id, &n, NULL, 0) == -1 ||
	    n != sizeof(id)) {
		(void)strlcpy(buf, "unknown", len);
		return (buf);
	}
	for (i = 0; i < sizeof(id); i++) {
		buf[2 * i] = hex[id[i] >> 4];
		buf[2 * i + 1] = hex[id[i] & 0xf];
	}
	buf[2 * sizeof(id)] = '\0';
	return (buf);
}

/*
 * The system's attribution root: a member-less, self-rooted coalition with
 * no termination signal, held for switchboard's lifetime.
 */
int
svc_responsibility_root_init(void)
{
	struct coalition_stat_reply sr;
	int fd, error;

	sd.root_coalition_fd = -1;
	sd.root_coalition_id = 0;
	fd = mac_cap_create_coalition();
	if (fd == -1)
		return (-1);
	if (cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ||
	    mac_cap_coalition_set_signal(fd, 0) != 0 ||
	    mac_cap_coalition_set_responsible(fd, -1, COALITION_RESP_SELF) != 0 ||
	    mac_cap_coalition_stat(fd, &sr) != 0) {
		error = errno;
		(void)close(fd);
		errno = error;
		return (-1);
	}
	sd.root_coalition_fd = fd;
	sd.root_coalition_id = sr.id;
	{
		char bid[40];

		syslog(LOG_NOTICE, "responsibility: boot %s root coalition %ju",
		    svc_boot_id(bid, sizeof(bid)), (uintmax_t)sr.id);
	}
	return (0);
}
