/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reverse-domain-name service registry.
 *
 * Services register names (e.g., "org.freebsd.sshd") via their pair
 * channel to serviced.  Clients look up names and receive a pair
 * endpoint to the named service.  serviced brokers the connection
 * by creating a new pair (via oracled) and pushing one end to each
 * party.
 *
 * The registry is a simple hash table keyed by name.  Entries are
 * auto-removed when the owning service exits.
 */

#include <sys/types.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "serviced.h"
#include "serviced_svc_proto.h"

#define	NAMING_HASH_SIZE	64
#define	NAMING_MAX_PER_SERVICE	32

struct naming_entry {
	struct naming_entry	*next;
	char			 name[SERVICED_NAME_MAX + 1];
	struct svc_runtime	*owner;		/* owning service */
};

static struct naming_entry *naming_hash[NAMING_HASH_SIZE];

static unsigned
name_hash(const char *name)
{
	unsigned h;
	const unsigned char *p;

	h = 5381;
	for (p = (const unsigned char *)name; *p != '\0'; p++)
		h = h * 33 + *p;
	return (h % NAMING_HASH_SIZE);
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
naming_register(const char *name, struct svc_runtime *owner)
{
	struct naming_entry *e;
	unsigned h;

	if (!name_valid(name)) {
		syslog(LOG_WARNING, "naming: invalid name '%s' from '%s'",
		    name, owner->manifest.label);
		return (EINVAL);
	}

	/*
	 * Authorization: the name must match the service's own label
	 * or be declared in the manifest's provides[] array.  This
	 * prevents a service from squatting on arbitrary names.
	 */
	{
		unsigned j;
		bool found;

		found = (strcmp(owner->manifest.label, name) == 0);
		if (!found) {
			for (j = 0; j < owner->manifest.nprovides; j++) {
				if (strcmp(owner->manifest.provides[j],
				    name) == 0) {
					found = true;
					break;
				}
			}
		}
		if (!found) {
			syslog(LOG_WARNING,
			    "naming: '%s' denied: not in label or provides[] "
			    "for '%s'", name, owner->manifest.label);
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

	if (naming_find(name) != NULL) {
		syslog(LOG_WARNING,
		    "naming: '%s' already registered (requested by '%s')",
		    name, owner->manifest.label);
		return (EEXIST);
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return (ENOMEM);

	strlcpy(e->name, name, sizeof(e->name));
	e->owner = owner;

	h = name_hash(name);
	e->next = naming_hash[h];
	naming_hash[h] = e;

	syslog(LOG_INFO, "naming: '%s' registered by '%s'",
	    name, owner->manifest.label);
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
			syslog(LOG_INFO, "naming: '%s' unregistered", name);
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
			} else {
				pp = &e->next;
			}
		}
	}
}

/*
 * Look up a name and broker a connection.
 *
 * Creates a new pair via oracled, pushes one end to the provider
 * service (SVC_OP_NEW_CLIENT notification), and returns the other
 * end to the caller.
 *
 * Returns the client's fd on success, -1 on failure (sets *errp).
 */
int
naming_lookup(const char *name, struct svc_runtime *requester, int *errp)
{
	struct naming_entry *e;
	struct svc_runtime *provider;
	struct svc_new_client_msg notify;
	struct cap_rt_sendmsg_args sa;
	int provider_end, client_end;

	e = naming_find(name);
	if (e == NULL) {
		*errp = ENOENT;
		return (-1);
	}

	provider = e->owner;

	/* Don't let a service connect to itself. */
	if (provider == requester) {
		*errp = ELOOP;
		return (-1);
	}

	/* Create a pair for the connection. */
	if (oracle_create_pair(sd.oracle_pair_fd,
	    &provider_end, &client_end) != 0) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': failed to create pair", name);
		*errp = EIO;
		return (-1);
	}

	/* Check provider is still alive before sending. */
	if (provider->pair_fd < 0) {
		syslog(LOG_WARNING,
		    "naming: lookup '%s': provider '%s' pair closed",
		    name, provider->manifest.label);
		close(provider_end);
		close(client_end);
		*errp = ECONNRESET;
		return (-1);
	}

	/* Push the provider's end to the owning service. */
	memset(&notify, 0, sizeof(notify));
	notify.op = SVC_OP_NEW_CLIENT;
	strlcpy(notify.client_label, requester->manifest.label,
	    sizeof(notify.client_label));

	memset(&sa, 0, sizeof(sa));
	sa.payload = &notify;
	sa.payload_len = sizeof(notify);
	sa.fds = &provider_end;
	sa.nfds = 1;

	if (ioctl(provider->pair_fd, CAP_RT_SENDMSG, &sa) == -1) {
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
	    name, requester->manifest.label, provider->manifest.label);

	*errp = 0;
	return (client_end);
}
