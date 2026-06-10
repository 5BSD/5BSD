/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * On-demand service launch for serviced.
 *
 * When a service_lookup() arrives for an unregistered name that exists
 * in the bundle registry, we launch the service from its bundle, wait
 * for it to report ready, then broker the connection.
 *
 * Multiple concurrent lookups for the same service are coalesced:
 * only one launch occurs, all waiters are drained when ready.
 * Each waiter gets its own unique pair channel (never shared).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <dev/cap_rt/cap_rt_ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libcapbundle.h>

#include "serviced.h"
#include "serviced_probes.h"

#define	ON_DEMAND_TIMEOUT_SEC	10
#define	ON_DEMAND_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 2))
#define	ON_DEMAND_MAX_PENDING	64

static uintptr_t od_timer_next = ON_DEMAND_TIMER_BIT | 1;

struct pending_lookup {
	struct pending_lookup	*next;
	char			 name[CAPBUNDLE_NAME_MAX + 1];
	char			 requester_label[SERVICED_LABEL_MAX];
	int			 requester_pair_fd; /* snapshot — not owned */
	uint64_t		 reply_token;
	uintptr_t		 timeout_ident;
};

static struct pending_lookup *pending_list;
static unsigned npending;

static bool
pending_for_name(const char *name)
{
	struct pending_lookup *p;

	for (p = pending_list; p != NULL; p = p->next) {
		if (strcmp(p->name, name) == 0)
			return (true);
	}
	return (false);
}

/*
 * Find an active service that provides 'name'.
 *
 * Searches sd.services[] directly by provides name, catching both
 * on-demand launches with pending lookups AND boot/reload services
 * that are already STARTING but have no pending lookup yet.
 */
static struct svc_runtime *
find_launching_service(const char *name)
{
	unsigned i, j;

	for (i = 0; i < sd.nservices; i++) {
		if (sd.services[i].state != SVC_STATE_STARTING &&
		    sd.services[i].state != SVC_STATE_RUNNING)
			continue;
		/* Check by provides name. */
		for (j = 0; j < sd.services[i].manifest.nprovides; j++) {
			if (strcmp(sd.services[i].manifest.provides[j],
			    name) == 0)
				return (&sd.services[i]);
		}
		/* Check by label. */
		if (strcmp(sd.services[i].manifest.label, name) == 0)
			return (&sd.services[i]);
	}
	return (NULL);
}

/*
 * Detect circular on-demand dependencies.
 *
 * Returns true if launching 'name' on behalf of 'requester' would
 * create a deadlock.  This happens when there is already a pending
 * lookup waiting on a name that the requester provides — meaning
 * the requester can't become ready until that lookup completes, but
 * that lookup is waiting for the requester.
 */
static bool
would_deadlock(const char *name, struct svc_runtime *requester)
{
	struct pending_lookup *p;
	unsigned i;

	if (requester == NULL)
		return (false);

	/*
	 * Check: is anyone waiting on a name the requester provides?
	 * If so, and the requester is still STARTING, completing that
	 * wait requires the requester to become ready first — but the
	 * requester is blocked on us.  Deadlock.
	 */
	if (requester->state != SVC_STATE_STARTING)
		return (false);

	for (p = pending_list; p != NULL; p = p->next) {
		/* Is this pending lookup waiting on a name requester provides? */
		for (i = 0; i < requester->manifest.nprovides; i++) {
			if (strcmp(p->name, requester->manifest.provides[i]) == 0) {
				syslog(LOG_WARNING,
				    "on_demand: circular dependency detected: "
				    "'%s' needs '%s' which needs '%s'",
				    requester->manifest.label, name,
				    p->name);
				return (true);
			}
		}
	}
	return (false);
}

/*
 * Launch a service on demand.
 *
 * Called from svc_proto.c when naming_lookup() returns ENOENT but the
 * provides registry has a match.
 *
 * Returns 0 if launch initiated (reply deferred), -1 on immediate failure.
 * Sets errno to EDEADLK if circular dependency detected.
 */
int
on_demand_launch(const char *name, struct svc_runtime *requester,
    uint64_t reply_token, int kq)
{
	unsigned bundle_idx, service_idx;
	struct capbundle *b;
	struct capbundle_service *asvc;
	struct svc_runtime *target;
	struct pending_lookup *pl;
	struct kevent kev;

	/* Look up in the provides registry. */
	if (bundle_registry_lookup(name, &bundle_idx, &service_idx) == -1)
		return (-1);  /* not found — caller should return ENOENT */

	/* Circular dependency detection. */
	if (would_deadlock(name, requester)) {
		errno = EDEADLK;
		return (-1);
	}

	/* Check if this service is already running or being launched. */
	target = find_launching_service(name);
	if (target == NULL) {
		/* Need to actually launch. */
		b = bundle_registry_get(bundle_idx);
		if (b == NULL)
			return (-1);
		asvc = capbundle_service(b, service_idx);
		if (asvc == NULL)
			return (-1);

		/* Find a free slot in sd.services[]. */
		if (sd.nservices >= SERVICED_MAX_SERVICES) {
			syslog(LOG_ERR,
			    "on_demand: service limit reached, cannot launch '%s'",
			    name);
			return (-1);
		}

		target = &sd.services[sd.nservices];
		memset(target, 0, sizeof(*target));
		target->pd_fd = -1;
		target->pair_fd = -1;
		target->coalition_fd = -1;
		target->jail_fd = -1;
		target->state = SVC_STATE_STOPPED;
		target->bundle_idx = bundle_idx;
		target->bundle_svc_idx = service_idx;

		/* Fill manifest from bundle (includes all capabilities). */
		if (capbundle_svc_fill_manifest(asvc,
		    &target->manifest) == -1) {
			syslog(LOG_ERR,
			    "on_demand: invalid bundle service '%s'",
			    capbundle_svc_label(asvc));
			return (-1);
		}
		target->manifest.on_demand = true;

		/* Attribution. */
		if (requester != NULL)
			strlcpy(target->launched_by, requester->manifest.label,
			    sizeof(target->launched_by));
		else
			strlcpy(target->launched_by, "unknown",
			    sizeof(target->launched_by));
		clock_gettime(CLOCK_MONOTONIC, &target->launch_time);

		sd.nservices++;

		/* Launch the service. */
		if (svc_exec(target, kq) == -1) {
			syslog(LOG_ERR,
			    "on_demand: failed to launch '%s'", name);
			sd.nservices--;
			memset(target, 0, sizeof(*target));
			target->pd_fd = -1;
			target->pair_fd = -1;
			target->coalition_fd = -1;
			target->jail_fd = -1;
			return (-1);
		}

		syslog(LOG_INFO,
		    "on_demand: launching '%s' (requested by '%s')",
		    target->manifest.label, target->launched_by);
		SERVICED_PROBE_ON_DEMAND_LAUNCH(name, target->launched_by);
	} else {
		SERVICED_PROBE_ON_DEMAND_COALESCE(name);
	}

	/* Queue the waiter. */
	if (npending >= ON_DEMAND_MAX_PENDING) {
		syslog(LOG_WARNING,
		    "on_demand: too many pending lookups");
		return (-1);
	}

	pl = calloc(1, sizeof(*pl));
	if (pl == NULL) {
		syslog(LOG_ERR, "on_demand: calloc pending: %m");
		return (-1);
	}

	strlcpy(pl->name, name, sizeof(pl->name));
	if (requester != NULL) {
		strlcpy(pl->requester_label, requester->manifest.label,
		    sizeof(pl->requester_label));
		pl->requester_pair_fd = requester->pair_fd;
	} else {
		strlcpy(pl->requester_label, "unknown",
		    sizeof(pl->requester_label));
		pl->requester_pair_fd = -1;
	}
	pl->reply_token = reply_token;

	/* Arm timeout timer. */
	pl->timeout_ident = od_timer_next++;
	EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, ON_DEMAND_TIMEOUT_SEC, pl);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		syslog(LOG_WARNING, "on_demand: kevent timer: %m");

	pl->next = pending_list;
	pending_list = pl;
	npending++;

	return (0);
}

/*
 * Called when a service reports SVC_OP_READY.
 * Drain all pending lookups waiting on names this service provides.
 */
void
on_demand_check_ready(struct svc_runtime *svc, int kq)
{
	struct pending_lookup **pp, *pl;
	struct kevent kev;
	unsigned i;
	bool match;

	unsigned nwaiters = 0;

	pp = &pending_list;
	while (*pp != NULL) {
		pl = *pp;
		match = false;

		/* Match by provides name. */
		for (i = 0; i < svc->manifest.nprovides; i++) {
			if (strcmp(pl->name,
			    svc->manifest.provides[i]) == 0) {
				match = true;
				break;
			}
		}

		if (!match) {
			pp = &(*pp)->next;
			continue;
		}

		/*
		 * Service is ready — broker the connection.
		 * Resolve the requester from sd.services[] by label
		 * to avoid stale pointers after svc_remove().
		 */
		{
			struct svc_runtime *req_svc;
			int client_fd, error, pair_fd;

			req_svc = svc_by_label(pl->requester_label);
			pair_fd = (req_svc != NULL) ?
			    req_svc->pair_fd : pl->requester_pair_fd;

			client_fd = (req_svc != NULL) ?
			    naming_lookup(pl->name, req_svc, &error) : -1;
			if (req_svc == NULL)
				error = ECONNRESET;

			if (client_fd >= 0) {
				struct cap_rt_sendmsg_args sa;
				int32_t status = 0;

				memset(&sa, 0, sizeof(sa));
				sa.payload = &status;
				sa.payload_len = sizeof(status);
				sa.fds = &client_fd;
				sa.nfds = 1;
				sa.reply_token = pl->reply_token;

				if (pair_fd >= 0)
					(void)ioctl(pair_fd,
					    CAP_RT_SENDMSG, &sa);

				close(client_fd);
				svc->connection_count++;
			} else {
				struct cap_rt_sendmsg_args sa;
				int32_t status = error;

				memset(&sa, 0, sizeof(sa));
				sa.payload = &status;
				sa.payload_len = sizeof(status);
				sa.reply_token = pl->reply_token;

				if (pair_fd >= 0)
					(void)ioctl(pair_fd,
					    CAP_RT_SENDMSG, &sa);
			}
		}

		/* Cancel timeout timer. */
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);

		/* Remove from list. */
		*pp = pl->next;
		free(pl);
		npending--;
		nwaiters++;
	}

	if (nwaiters > 0)
		SERVICED_PROBE_ON_DEMAND_READY(svc->manifest.label, nwaiters);
}

/*
 * Handle on-demand timeout.
 * Reply ETIMEDOUT to all waiters for the timed-out service.
 */
void
on_demand_timeout(uintptr_t ident, int kq)
{
	struct pending_lookup **pp, *pl;
	char expired_name[CAPBUNDLE_NAME_MAX + 1];

	pp = &pending_list;
	while (*pp != NULL) {
		pl = *pp;
		if (pl->timeout_ident != ident) {
			pp = &(*pp)->next;
			continue;
		}

		syslog(LOG_WARNING,
		    "on_demand: timeout waiting for '%s' (requested by '%s')",
		    pl->name, pl->requester_label);
		SERVICED_PROBE_ON_DEMAND_TIMEOUT(pl->name);
		strlcpy(expired_name, pl->name, sizeof(expired_name));

		/* Send ETIMEDOUT reply.  Re-resolve the requester by
		 * label — the original pair_fd may be stale if the
		 * requester was restarted since the lookup. */
		{
			struct cap_rt_sendmsg_args sa;
			struct svc_runtime *req;
			int reply_fd;
			int32_t status = ETIMEDOUT;

			reply_fd = -1;
			req = svc_by_label(pl->requester_label);
			if (req != NULL && req->pair_fd >= 0)
				reply_fd = req->pair_fd;

			memset(&sa, 0, sizeof(sa));
			sa.payload = &status;
			sa.payload_len = sizeof(status);
			sa.reply_token = pl->reply_token;

			if (reply_fd >= 0)
				(void)ioctl(reply_fd,
				    CAP_RT_SENDMSG, &sa);
		}

		/* Remove from list. */
		*pp = pl->next;
		free(pl);
		npending--;
		if (!pending_for_name(expired_name)) {
			struct svc_runtime *target;

			target = find_launching_service(expired_name);
			if (target != NULL && target->manifest.on_demand &&
			    target->state == SVC_STATE_STARTING) {
				syslog(LOG_WARNING,
				    "on_demand: stopping unready '%s'",
				    target->manifest.label);
				target->remove_pending = true;
				svc_graceful_stop(target, kq);
			}
		}
		return;  /* timer is per-entry, so just one match */
	}
}

/*
 * Check if a kevent is an on-demand timer.
 */
bool
on_demand_is_timer(uintptr_t ident)
{

	return ((ident & ON_DEMAND_TIMER_BIT) != 0);
}

/*
 * Tear down on-demand state: reply ESHUTDOWN to all pending waiters
 * and cancel their timers.
 */
void
on_demand_teardown(int kq)
{
	struct pending_lookup *pl, *next;
	struct kevent kev;

	for (pl = pending_list; pl != NULL; pl = next) {
		next = pl->next;

		/* Send error reply. */
		if (pl->requester_pair_fd >= 0) {
			struct cap_rt_sendmsg_args sa;
			int32_t status = ESHUTDOWN;

			memset(&sa, 0, sizeof(sa));
			sa.payload = &status;
			sa.payload_len = sizeof(status);
			sa.reply_token = pl->reply_token;
			(void)ioctl(pl->requester_pair_fd,
			    CAP_RT_SENDMSG, &sa);
		}

		/* Cancel timeout timer. */
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);

		free(pl);
	}
	pending_list = NULL;
	npending = 0;
}
