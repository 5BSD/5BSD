/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reverse-domain-name service registry.
 *
 * Services register names (e.g., "org.5bsd.sshd") via their channel
 * to switchboard.  Clients look up names and receive a channel
 * endpoint to the named service.  switchboard brokers the connection
 * by minting a new channel from its delegated channel service and pushing
 * one end to each
 * party.
 *
 * The registry is a simple hash table keyed by name.  Entries are
 * auto-removed when the owning service exits.
 */

#include <sys/types.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <channel.h>

#include "switchboard.h"
#include "switchboard_ctl.h"
#include "fd_budget.h"
#include "switchboard_probes.h"
#include "switchboard_svc_proto.h"

/* The requester identity a login session carries (no policy file). */
#define	NAMING_SESSION_LABEL	SVC_SESSION_LABEL

#define	NAMING_HASH_SIZE	64
#define	NAMING_MAX_PER_SERVICE	32

struct naming_entry {
	struct naming_entry	*next;
	char			 name[SWITCHBOARD_NAME_MAX + 1];
	struct svc_runtime	*owner;		/* owning service */
	bool			 sendable;	/* provider allows session forwarding */
	enum svc_domain_kind	 domain;	/* SYSTEM (default) or CONTROL */
};

static struct naming_entry *naming_hash[NAMING_HASH_SIZE];
static unsigned naming_total;

static unsigned
name_hash(const char *name)
{

	return (switchboard_hash_djb2(name) % NAMING_HASH_SIZE);
}

/*
 * Validate reverse-domain name format.
 * Must have at least one dot, only alphanumerics/dots/hyphens/underscores,
 * no leading/trailing dots, no consecutive dots.
 */
static bool
name_valid(const char *name)
{
	size_t len;
	bool has_dot;
	const char *p;

	len = strlen(name);
	if (len == 0 || len > SWITCHBOARD_NAME_MAX)
		return (false);
	if (name[0] == '.' || name[len - 1] == '.')
		return (false);

	has_dot = false;
	for (p = name; *p != '\0'; p++) {
		if (*p == '.') {
			if (p > name && *(p - 1) == '.')
				return (false);	/* consecutive dots */
			has_dot = true;
		} else if (!((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '-' || *p == '_')) {
			return (false);
		}
	}
	return (has_dot);
}

static struct naming_entry *
naming_find(const char *name)
{
	struct naming_entry *e;
	unsigned h;

	h = name_hash(name);
	for (e = naming_hash[h]; e != NULL; e = e->next) {
		if (strcmp(e->name, name) == 0)
			return (e);
	}
	return (NULL);
}

/*
 * Report whether a name is currently registered, without creating a
 * session.  Used to decide launch deferral for lazy peer consumers.
 */
bool
naming_exists(const char *name)
{

	return (name != NULL && naming_find(name) != NULL);
}

/*
 * Count names owned by a service.
 */
static unsigned
naming_count_owner(struct svc_runtime *owner)
{
	struct naming_entry *e;
	unsigned i, count;

	count = 0;
	for (i = 0; i < NAMING_HASH_SIZE; i++) {
		for (e = naming_hash[i]; e != NULL; e = e->next) {
			if (e->owner == owner)
				count++;
		}
	}
	return (count);
}

int
naming_register(const char *name, struct svc_runtime *owner, bool sendable)
{
	struct naming_entry *e;
	unsigned h;

	if (!name_valid(name)) {
		syslog(LOG_WARNING, "naming: invalid name '%s' from '%s'",
		    name, owner->manifest.label);
		SWITCHBOARD_PROBE_NAMING_DENY(name, EINVAL);
		return (EINVAL);
	}

	/*
	 * Authorization is exact: runtime identity never implies a public
	 * endpoint.  Every exposed name must appear in provides[].
	 */
	{
		unsigned j;
		bool found;

		found = false;
		for (j = 0; j < owner->manifest.nprovides; j++) {
			if (strcmp(owner->manifest.provides[j], name) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			syslog(LOG_WARNING,
			    "naming: '%s' denied: not in provides[] "
			    "for '%s'", name, owner->manifest.label);
			SWITCHBOARD_PROBE_NAMING_DENY(name, EACCES);
			return (EACCES);
		}
	}

	/*
	 * Per-service limit prevents resource exhaustion.
	 */
	if (naming_count_owner(owner) >= NAMING_MAX_PER_SERVICE) {
		syslog(LOG_WARNING,
		    "naming: '%s' hit registration limit (%d)",
		    owner->manifest.label, NAMING_MAX_PER_SERVICE);
		return (ENOSPC);
	}

	e = naming_find(name);
	if (e != NULL && e->owner == owner)
		return (0);
	if (e != NULL) {
		syslog(LOG_WARNING,
		    "naming: '%s' already registered (requested by '%s')",
		    name, owner->manifest.label);
		return (EEXIST);
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL) {
		SWITCHBOARD_PROBE_ERROR("naming", "register alloc failed");
		return (ENOMEM);
	}

	strlcpy(e->name, name, sizeof(e->name));
	e->owner = owner;
	e->sendable = sendable;
	/*
	 * A name in the reserved ".Control" namespace registers in the CONTROL
	 * domain: it is invisible to SYSTEM/USER lookups and resolvable only by
	 * a held CONTROL channel.  Everything else is a SYSTEM name.
	 */
	e->domain = name_is_control(name) ? SVC_DOMAIN_CONTROL : SVC_DOMAIN_SYSTEM;

	h = name_hash(name);
	e->next = naming_hash[h];
	naming_hash[h] = e;

	naming_total++;
	syslog(LOG_INFO, "naming: '%s' registered by '%s'",
	    name, owner->manifest.label);
	SWITCHBOARD_PROBE_NAMING_REGISTER(name, owner->manifest.label);
	SWITCHBOARD_PROBE_NAMING_COUNT(naming_total);
	return (0);
}

int
naming_unregister(const char *name, struct svc_runtime *owner)
{
	struct naming_entry **pp, *e;
	unsigned h;

	h = name_hash(name);
	for (pp = &naming_hash[h]; (e = *pp) != NULL; pp = &e->next) {
		if (strcmp(e->name, name) == 0) {
			if (e->owner != owner) {
				syslog(LOG_WARNING,
				    "naming: '%s' unregister denied: "
				    "owned by '%s', requested by '%s'",
				    name, e->owner->manifest.label,
				    owner->manifest.label);
				return (EPERM);
			}
			*pp = e->next;
			free(e);
			naming_total--;
			syslog(LOG_INFO, "naming: '%s' unregistered", name);
			SWITCHBOARD_PROBE_NAMING_UNREGISTER(name);
			SWITCHBOARD_PROBE_NAMING_COUNT(naming_total);
			return (0);
		}
	}
	return (ENOENT);
}

/*
 * Remove all names owned by a service.
 * Called when a service exits.
 */
void
naming_remove_owner(struct svc_runtime *owner)
{
	struct naming_entry **pp, *e;
	unsigned i;

	for (i = 0; i < NAMING_HASH_SIZE; i++) {
		pp = &naming_hash[i];
		while ((e = *pp) != NULL) {
			if (e->owner == owner) {
				syslog(LOG_INFO,
				    "naming: '%s' auto-unregistered "
				    "(owner '%s' exited)",
				    e->name, owner->manifest.label);
				*pp = e->next;
				free(e);
				naming_total--;
			} else {
				pp = &e->next;
			}
		}
	}
	SWITCHBOARD_PROBE_NAMING_COUNT(naming_total);
}

/*
 * Rebind registry ownership after sd.services[] compaction.
 */
void
naming_rebind_owner(struct svc_runtime *old_owner,
    struct svc_runtime *new_owner)
{
	struct naming_entry *e;
	unsigned i;

	if (old_owner == new_owner)
		return;

	for (i = 0; i < NAMING_HASH_SIZE; i++) {
		for (e = naming_hash[i]; e != NULL; e = e->next) {
			if (e->owner == old_owner)
				e->owner = new_owner;
		}
	}
}

/*
 * Look up a name and broker a connection.
 *
 * Creates a new channel through switchboard's delegated channel factory, pushes
 * one end to the provider
 * service (SVC_OP_NEW_CLIENT notification), and returns the other
 * end to the caller.
 *
 * Returns the client's fd on success, -1 on failure (sets *errp).
 *
 * domain scopes the requesting channel (§22): SVC_DOMAIN_SYSTEM resolves every
 * registered name, while a narrowed domain resolves only names in its scope.
 * The scope check runs FIRST, before the registry is consulted, so a name that
 * is out of scope is reported as ENOENT indistinguishably from a name that was
 * never registered — the requester learns nothing about names it may not see.
 * requester is the owning unit for a unit control channel and NULL for a
 * minted domain channel that has no backing process; the self-connection guard
 * applies only when there is a requester.  Per-name authorization in the
 * provider is unchanged: domain scoping narrows discovery, it never grants
 * access.
 */
/*
 * Resolve SWITCHBOARD_CONTROL_NAME (docs/capability-authority-model.md, P3):
 * switchboard self-serves its own control plane, so this name has no provider
 * process and forks off the general registry path.  It is reachable only for an
 * ambient login session (requester == NULL), never a service, and only for a
 * session holding the SVC_ANOINT_SWITCHBOARD_ADMIN anointment (see the P6 note
 * below).  Per P6 the DOMAIN KIND no longer gates this: a USER-domain channel
 * does reach the anointment check, so authorization rests on the anointment
 * alone -- a root admin shell (USER kind) carrying the anointment resolves it,
 * a wheel session without it does not.  The grant always carries
 * SVC_RIGHTS_ADMIN; switchboard adopts the provider end in-process as an
 * ADMIN-gated control connection.  Returns the client fd, or -1 with *errp.
 */
static int
naming_lookup_self_control(const char *name, struct svc_runtime *requester,
    const struct svc_domain *domain, const struct channel_sender *sender,
    bool capsule_relay, int *errp)
{
	int provider_end, client_end;

	if (requester != NULL) {
		/* A service is not an operator; it may not open control. */
		*errp = EACCES;
		return (-1);
	}
	/*
	 * The control plane is a gated endpoint (docs/ipc-anointments-design.md):
	 * the session must hold SVC_ANOINT_SWITCHBOARD_ADMIN (or "*").  The boot
	 * carry holds "*", so getty/login/rc behave as before; a session whose
	 * principal policy left it out is refused exactly like any other
	 * anointment miss -- EACCES internally (masked to ENOENT on the wire, no
	 * on-demand), audited with the missing name.  Domain kind no longer
	 * decides this: a root shell with admin_rights = false but the admin
	 * anointment reaches it; a wheel session without it does not (P6).
	 */
	if (domain == NULL ||
	    !svc_anoint_holds(&domain->anoint, SVC_ANOINT_SWITCHBOARD_ADMIN)) {
		svc_anoint_deny(name, NAMING_SESSION_LABEL,
		    sender != NULL ? (uid_t)sender->uid : getuid(),
		    SVC_ANOINT_SWITCHBOARD_ADMIN);
		*errp = EACCES;
		return (-1);
	}
	SWITCHBOARD_PROBE_ANOINT_ALLOW(name, NAMING_SESSION_LABEL, 1U);
	if (switchboard_fd_budget_check(2, "capability control connection") == -1) {
		*errp = errno;
		return (-1);
	}
	if (mac_cap_create_channel(&provider_end, &client_end) != 0) {
		*errp = errno != 0 ? errno : EIO;
		return (-1);
	}
	/* Control channel is non-forwardable: single delivery, no re-send. */
	if (cap_xfer_limit(client_end, CAP_XFER_ONCE) == -1) {
		close(provider_end);
		close(client_end);
		*errp = ENOTCAPABLE;
		return (-1);
	}
	if (sctl_adopt_channel(provider_end, SVC_RIGHTS_ALL,
	    capsule_relay) == -1) {
		/* adopt() took ownership of provider_end (closed on failure). */
		close(client_end);
		*errp = errno != 0 ? errno : EIO;
		return (-1);
	}
	return (client_end);
}

int
naming_lookup(const char *name, struct svc_runtime *requester,
    const struct svc_domain *domain, const struct channel_sender *sender,
    int *errp, bool *sendablep)
{
	struct naming_entry *e;
	struct svc_runtime *provider;
	struct svc_new_client_msg notify;
	const char (*requires)[SWITCHBOARD_LABEL_MAX];
	char registry_requires[SWITCHBOARD_MAX_REQUIRES][SWITCHBOARD_LABEL_MAX];
	unsigned nrequires;
	int provider_end, client_end;

	if (sendablep != NULL)
		*sendablep = false;

	/*
	 * switchboard self-serves two spine control names with no provider process:
	 * its own control plane (P3, handled in-process) and the system lifecycle
	 * plane (P4b, relayed to capsule).  Both are gated on the switchboard admin
	 * anointment and always carry ADMIN rights.
	 */
	if (strcmp(name, SWITCHBOARD_CONTROL_NAME) == 0)
		return (naming_lookup_self_control(name, requester, domain,
		    sender, false, errp));
	if (strcmp(name, SWITCHBOARD_LIFECYCLE_NAME) == 0)
		return (naming_lookup_self_control(name, requester, domain,
		    sender, true, errp));

	e = naming_find(name);
	/* A name becomes visible only after its independent activation succeeds. */
	if (e == NULL || !e->owner->protocol_ready ||
	    e->owner->state != SVC_STATE_RUNNING) {
		/*
		 * Not registered.  Decide whether this channel may on-demand the
		 * name (ENOENT, on-demand-eligible) or is out of scope (EACCES,
		 * fail fast -- the caller maps EACCES to ENOENT on the wire, so a
		 * client still cannot tell out-of-scope from unregistered).
		 *
		 * The control plane and the service plane never cross: a control
		 * name may be on-demanded only by a CONTROL channel, and a CONTROL
		 * channel may on-demand only control names.  Crossing that line is
		 * out of scope and must NOT trigger a launch -- otherwise a plain
		 * SYSTEM channel could force-launch a control provider it can
		 * never reach (an existence/side-effect leak).  Within the service
		 * plane, USER visibility (manifest resolvable_by) still gates
		 * on-demand as before.
		 */
		{
			bool ctrl_name = name_is_control(name);
			bool ctrl_chan = (domain != NULL &&
			    domain->kind == SVC_DOMAIN_CONTROL);

			if (ctrl_name != ctrl_chan)
				*errp = EACCES;		/* cross-plane */
			else if (ctrl_name)
				*errp = ENOENT;		/* control<->control */
			else
				*errp = svc_domain_resolves(domain, name) ?
				    ENOENT : EACCES;	/* service plane */
		}
		return (-1);
	}

	/*
	 * Registered: enforce the channel's domain against the NAME's registered
	 * domain.  This is the structural separation between the SYSTEM/USER
	 * service plane and the CONTROL admin plane -- a control name resolves
	 * only through a CONTROL channel, and a CONTROL channel resolves only
	 * control names.  An out-of-scope hit returns EACCES internally (the
	 * caller maps it to ENOENT on the wire and does NOT on-demand it): the
	 * name exists but this channel may never reach it.
	 */
	if (!svc_domain_permits(domain, e->domain, name)) {
		*errp = EACCES;
		return (-1);
	}

	/*
	 * IPC anointments (docs/ipc-anointments-design.md): the endpoint's
	 * `requires` -- from the running provider's own policy (the manifest it
	 * was launched with), falling back to the registry for a name the unit
	 * manifest does not list -- must be covered by the requester's set: a
	 * unit's policy-file anointments, or the set the auth agent put on a
	 * session channel at mint.  A miss is EACCES internally (the wire masks
	 * it to ENOENT, and no on-demand) and is audited with the missing names.
	 * An open endpoint (no requires) is unaffected.
	 */
	/*
	 * The bundle registry is the on-disk policy and is refreshed by reload,
	 * so it is consulted FIRST; the running provider's manifest copy is only
	 * the fallback for a name the registry does not know (e.g. a dynamic
	 * claim).  The reverse order let a stale runtime copy keep an endpoint
	 * open after its policy file gained a requirement (VM-found).
	 */
	if (svc_anoint_endpoint_requires(name, registry_requires,
	    &nrequires) == 0) {
		requires = (const char (*)[SWITCHBOARD_LABEL_MAX])
		    registry_requires;
	} else if (svc_anoint_unit_requires(&e->owner->manifest, name,
	    &requires, &nrequires) != 0) {
		nrequires = 0;
	}
	if (nrequires > 0 && !svc_anoint_covers(domain != NULL ?
	    &domain->anoint : NULL, requires, nrequires)) {
		char missing[SWITCHBOARD_MAX_REQUIRES * SWITCHBOARD_LABEL_MAX];

		(void)svc_anoint_missing(domain != NULL ? &domain->anoint : NULL,
		    requires, nrequires, missing, sizeof(missing));
		svc_anoint_deny(name, requester != NULL ?
		    requester->manifest.label : NAMING_SESSION_LABEL,
		    sender != NULL ? (uid_t)sender->uid : getuid(), missing);
		*errp = EACCES;
		return (-1);
	}
	if (nrequires > 0)
		SWITCHBOARD_PROBE_ANOINT_ALLOW(name, (requester != NULL ?
		    requester->manifest.label : NAMING_SESSION_LABEL), nrequires);

	provider = e->owner;

	/* Don't let a service connect to itself (unit channels only). */
	if (requester != NULL && provider == requester) {
		*errp = ELOOP;
		return (-1);
	}

	/* Two endpoints plus one queued attachment on each direct channel. */
	if (switchboard_fd_budget_check(4, "global service connection") == -1) {
		*errp = errno;
		SWITCHBOARD_PROBE_NAMING_DENY(name, *errp);
		return (-1);
	}

	/* Create a channel for the connection. */
	if (mac_cap_create_channel(&provider_end, &client_end) != 0) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': failed to create channel", name);
		SWITCHBOARD_PROBE_ERROR("naming", "lookup channel creation failed");
		*errp = errno != 0 ? errno : EIO;
		return (-1);
	}
	/*
	 * The provider endpoint stays transfer-unlimited: it is the provider's
	 * own end, and a provider that hands each session to a worker attenuates
	 * it to CAP_XFER_ONCE itself right before the SCM_RIGHTS forward (so the
	 * worker lands at CAP_XFER_NONE) — multi-hop delegation is built from
	 * explicit per-hop attenuation, not a kernel-baked budget.
	 *
	 * The client endpoint's transfer policy is the provider's own contract,
	 * declared when it exposed this name.  By default it is limited to
	 * CAP_XFER_ONCE, which the single delivery send to the consumer consumes
	 * to CAP_XFER_NONE: the consumer cannot delegate it further.  If the
	 * provider marked the name sendable, the client endpoint is left
	 * CAP_XFER_UNLIMITED so the consumer may re-send it (attenuating per hop
	 * as it chooses); it can only ever tighten from there.
	 */
	if (!e->sendable &&
	    cap_xfer_limit(client_end, CAP_XFER_ONCE) == -1) {
		close(provider_end);
		close(client_end);
		*errp = ENOTCAPABLE;
		return (-1);
	}

	/* Check provider is still alive before sending. */
	if (provider->channel_fd < 0) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': provider '%s' channel closed",
		    name, provider->manifest.label);
		close(provider_end);
		close(client_end);
		*errp = ECONNRESET;
		return (-1);
	}

	/* Push the provider's end to the owning service. */
	memset(&notify, 0, sizeof(notify));
	notify.op = SVC_OP_NEW_CLIENT;
	strlcpy(notify.service_name, name, sizeof(notify.service_name));
	strlcpy(notify.client_label,
	    requester != NULL ? requester->manifest.label :
	    NAMING_SESSION_LABEL, sizeof(notify.client_label));
	/*
	 * Identity of the running instance (v13): the kernel's per-exec program
	 * nonce and the sender ABI, both from the stamp on the lookup request.
	 * The label above is the persistent identity; the nonce tells one
	 * incarnation from the next (U10).  ABI is information for the provider
	 * and never gates reach.  Both are 0 when no stamp is available.
	 */
	notify.client_nonce = sender != NULL ? sender->nonce : 0;
	notify.client_abi = sender != NULL ? sender->abi : SVC_CLIENT_ABI_UNKNOWN;
	if (svc_lifecycle_client(requester, provider, &notify) == -1) {
		*errp = errno;
		close(provider_end);
		close(client_end);
		return (-1);
	}

	/*
	 * Rights granted to this session (capability-authority-model.md).  The
	 * administrative right -- the capability replacement for the old "root
	 * may do anything" bypass -- is a separate knob from reach: the holder's
	 * admin_rights flag, set by the auth agent's principal policy at mint
	 * (and by the boot carry, which holds everything).  A unit's set never
	 * carries it (a service is not an admin principal, whatever its domain
	 * kind), so a session with admin_rights = false gets no bypass even on a
	 * SYSTEM channel (P8).  All non-admin rights are still granted in full
	 * until a policy scopes them, so a provider that ignores rights, or
	 * checks them, behaves exactly as before.
	 */
	if (domain != NULL && domain->anoint.admin_rights)
		notify.rights = SVC_RIGHTS_ALL;
	else
		notify.rights = SVC_RIGHTS_ALL & ~SVC_RIGHTS_ADMIN;

	if (svc_channel_send_event(provider, &notify, sizeof(notify),
	    &provider_end, 1, switchboard_kq) == -1) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': failed to notify provider '%s': %m",
		    name, provider->manifest.label);
		close(provider_end);
		close(client_end);
		*errp = EIO;
		return (-1);
	}

	close(provider_end);	/* kernel copied it into the message */

	syslog(LOG_DEBUG, "naming: '%s' connected '%s' to '%s'",
	    name, notify.client_label, provider->manifest.label);
	SWITCHBOARD_PROBE_NAMING_LOOKUP(name, notify.client_label);
	/*
	 * Count at the one common broker point.  Both immediately published
	 * and on-demand names pass through here, and the count belongs to the
	 * provider that received the new-session endpoint, not the requester.
	 */
	provider->connection_count++;

	/*
	 * New client demand means the provider is no longer idle; drop any
	 * pending idle-shutdown timer.  The provider re-arms it via SVC_OP_IDLE
	 * once it next goes idle.
	 */
	cancel_idle_timer(provider, switchboard_kq);

	if (sendablep != NULL)
		*sendablep = e->sendable;
	*errp = 0;
	return (client_end);
}
