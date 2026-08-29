/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reverse-domain-name service registry.
 *
 * Services register names (e.g., "org.5bsd.sshd") via their channel
 * to serviced.  Clients look up names and receive a channel
 * endpoint to the named service.  serviced brokers the connection
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

#include "serviced.h"
#include "fd_budget.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"

#define	NAMING_HASH_SIZE	64
#define	NAMING_MAX_PER_SERVICE	32

struct naming_entry {
	struct naming_entry	*next;
	char			 name[SERVICED_NAME_MAX + 1];
	struct svc_runtime	*owner;		/* owning service */
	bool			 sendable;	/* provider allows session forwarding */
};

static struct naming_entry *naming_hash[NAMING_HASH_SIZE];
static unsigned naming_total;

static unsigned
name_hash(const char *name)
{

	return (serviced_hash_djb2(name) % NAMING_HASH_SIZE);
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
	if (len == 0 || len > SERVICED_NAME_MAX)
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
		SERVICED_PROBE_NAMING_DENY(name, EINVAL);
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
			SERVICED_PROBE_NAMING_DENY(name, EACCES);
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
		SERVICED_PROBE_ERROR("naming", "register alloc failed");
		return (ENOMEM);
	}

	strlcpy(e->name, name, sizeof(e->name));
	e->owner = owner;
	e->sendable = sendable;

	h = name_hash(name);
	e->next = naming_hash[h];
	naming_hash[h] = e;

	naming_total++;
	syslog(LOG_INFO, "naming: '%s' registered by '%s'",
	    name, owner->manifest.label);
	SERVICED_PROBE_NAMING_REGISTER(name, owner->manifest.label);
	SERVICED_PROBE_NAMING_COUNT(naming_total);
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
			SERVICED_PROBE_NAMING_UNREGISTER(name);
			SERVICED_PROBE_NAMING_COUNT(naming_total);
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
	SERVICED_PROBE_NAMING_COUNT(naming_total);
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
 * Creates a new channel through serviced's delegated channel factory, pushes
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
int
naming_lookup(const char *name, struct svc_runtime *requester,
    const struct svc_domain *domain, int *errp, bool *sendablep)
{
	struct naming_entry *e;
	struct svc_runtime *provider;
	struct svc_new_client_msg notify;
	int provider_end, client_end;

	if (sendablep != NULL)
		*sendablep = false;
	/*
	 * Domain scope is layered on top of the registry and checked first: an
	 * out-of-scope name is indistinguishable from an unregistered one.
	 */
	if (!svc_domain_resolves(domain, name)) {
		*errp = ENOENT;
		return (-1);
	}

	e = naming_find(name);
	/* A name becomes visible only after its independent activation succeeds. */
	if (e == NULL || !e->owner->protocol_ready ||
	    e->owner->state != SVC_STATE_RUNNING) {
		*errp = ENOENT;
		return (-1);
	}

	provider = e->owner;

	/* Don't let a service connect to itself (unit channels only). */
	if (requester != NULL && provider == requester) {
		*errp = ELOOP;
		return (-1);
	}

	/* Two endpoints plus one queued attachment on each direct channel. */
	if (serviced_fd_budget_check(4, "global service connection") == -1) {
		*errp = errno;
		SERVICED_PROBE_NAMING_DENY(name, *errp);
		return (-1);
	}

	/* Create a channel for the connection. */
	if (mac_cap_create_channel(&provider_end, &client_end) != 0) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': failed to create channel", name);
		SERVICED_PROBE_ERROR("naming", "lookup channel creation failed");
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
	    "org.5bsd.user-session", sizeof(notify.client_label));

	if (svc_channel_send_event(provider, &notify, sizeof(notify),
	    &provider_end, 1, serviced_kq) == -1) {
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
	SERVICED_PROBE_NAMING_LOOKUP(name, notify.client_label);
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
	cancel_idle_timer(provider, serviced_kq);

	if (sendablep != NULL)
		*sendablep = e->sendable;
	*errp = 0;
	return (client_end);
}
