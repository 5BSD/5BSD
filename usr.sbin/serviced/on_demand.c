/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * On-demand service launch for serviced.
 *
 * When a service lookup arrives for a reserved name without a published
 * endpoint, launch its bundle if necessary, wait for the provider to check in
 * and activate that exact name, then broker a direct connection.
 *
 * Multiple concurrent lookups for the same service are coalesced:
 * only one launch occurs, all waiters are drained when ready.
 * Each waiter gets its own unique channel (never shared).
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <libcapbundle.h>
#include <channel.h>

#include "serviced.h"
#include "serviced_audit.h"
#include "serviced_probes.h"
#include "serviced_svc_proto.h"

#define	ON_DEMAND_TIMEOUT_SEC	10
#define	ON_DEMAND_TIMER_BIT	((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 2))
#define	ON_DEMAND_MAX_PENDING	64

static uintptr_t od_timer_next = ON_DEMAND_TIMER_BIT | 1;

struct pending_lookup {
	struct pending_lookup	*next;
	char			 name[CAPBUNDLE_NAME_MAX + 1];
	char			 provider_label[SERVICED_LABEL_MAX];
	pid_t			 provider_pid;
	uint64_t		 provider_launch_id;
	char			 requester_label[SERVICED_LABEL_MAX];
	pid_t			 requester_pid;
	uint64_t		 requester_launch_id;
	struct channel_message	*request;
	uintptr_t		 timeout_ident;
};

static struct pending_lookup *pending_list;
static unsigned npending;

static bool
pending_provider_matches(const struct pending_lookup *pending,
    const struct svc_runtime *provider)
{

	if (pending == NULL || provider == NULL ||
	    strcmp(pending->provider_label, provider->manifest.label) != 0)
		return (false);
	/*
	 * A waiter registered while the provider's own launch was still
	 * deferred has no pid/launch generation to pin; the label alone
	 * identifies whichever launch eventually satisfies it.
	 */
	if (pending->provider_pid <= 0)
		return (true);
	return (pending->provider_pid == provider->pid &&
	    pending->provider_launch_id == provider->launch_id);
}

static struct svc_runtime *
pending_requester(const struct pending_lookup *pending)
{
	struct svc_runtime *requester;

	requester = svc_by_label(pending->requester_label);
	if (requester == NULL || requester->pid != pending->requester_pid ||
	    requester->launch_id != pending->requester_launch_id ||
	    requester->channel_fd < 0)
		return (NULL);
	return (requester);
}

/*
 * Resolve the unit whose deferred launch a request==NULL pending entry
 * represents.  The unit was never launched, so only the label identifies
 * it; a slot that moved on to another state no longer wants the launch.
 */
static struct svc_runtime *
pending_launch_waiter(const struct pending_lookup *pending)
{
	struct svc_runtime *waiter;

	waiter = svc_by_label(pending->requester_label);
	if (waiter == NULL || waiter->state != SVC_STATE_STOPPED)
		return (NULL);
	return (waiter);
}

static bool
pending_for_provider_name(const struct svc_runtime *provider, const char *name)
{
	struct pending_lookup *p;

	for (p = pending_list; p != NULL; p = p->next) {
		if (strcmp(p->name, name) == 0 &&
		    pending_provider_matches(p, provider))
			return (true);
	}
	return (false);
}

static uintptr_t
next_timeout_ident(void)
{
	struct pending_lookup *p;
	uintptr_t ident;
	unsigned attempt;
	bool collision;

	/*
	 * Keep every identifier in the dedicated on-demand range and avoid
	 * reusing an identifier that is still present in the pending list.
	 * With at most ON_DEMAND_MAX_PENDING live timers, one more candidate
	 * than that is sufficient to find a free identifier.
	 */
	for (attempt = 0; attempt <= ON_DEMAND_MAX_PENDING; attempt++) {
		ident = od_timer_next;
		od_timer_next = ON_DEMAND_TIMER_BIT |
		    ((od_timer_next + 1) & (ON_DEMAND_TIMER_BIT - 1));
		if (od_timer_next == ON_DEMAND_TIMER_BIT)
			od_timer_next++;
		collision = false;
		for (p = pending_list; p != NULL; p = p->next) {
			if (p->timeout_ident == ident) {
				collision = true;
				break;
			}
		}
		if (!collision)
			return (ident);
	}
	errno = EAGAIN;
	return (0);
}

static int
arm_timeout(int kq, struct pending_lookup *pending)
{
	struct kevent kev;

	if (pending == NULL) {
		errno = EINVAL;
		return (-1);
	}
	pending->timeout_ident = next_timeout_ident();
	if (pending->timeout_ident == 0)
		return (-1);
	EV_SET(&kev, pending->timeout_ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, ON_DEMAND_TIMEOUT_SEC, pending);
	return (kevent(kq, &kev, 1, NULL, 0, NULL));
}

static int
provided_name_index(const struct svc_runtime *svc, const char *name)
{
	unsigned i;

	for (i = 0; i < svc->manifest.nprovides; i++)
		if (strcmp(svc->manifest.provides[i], name) == 0)
			return ((int)i);
	return (-1);
}

int
on_demand_name_claim(struct svc_runtime *svc, const char *name, bool sendable)
{
	int index;

	if (svc == NULL || name == NULL)
		return (EINVAL);
	index = provided_name_index(svc, name);
	if (index < 0)
		return (EACCES);
	if (svc->name_state[index] != SVC_NAME_UNCLAIMED)
		return (EALREADY);
	svc->name_state[index] = SVC_NAME_INACTIVE;
	svc->name_sendable[index] = sendable;
	return (0);
}

/*
 * The provider's declared transfer policy for a claimed name (see
 * name_sendable): true if delivered sessions may be forwarded.  Read when the
 * name activates and its naming entry is registered.
 */
bool
on_demand_name_sendable(const struct svc_runtime *svc, const char *name)
{
	int index;

	if (svc == NULL || name == NULL)
		return (false);
	index = provided_name_index(svc, name);
	return (index >= 0 && svc->name_sendable[index]);
}

bool
on_demand_all_names_claimed(const struct svc_runtime *svc)
{
	unsigned i;

	if (svc == NULL)
		return (false);
	for (i = 0; i < svc->manifest.nprovides; i++)
		if (svc->name_state[i] == SVC_NAME_UNCLAIMED)
			return (false);
	return (true);
}

int
on_demand_name_withdraw(struct svc_runtime *svc, const char *name, int kq)
{
	int error, index;

	if (svc == NULL || name == NULL)
		return (EINVAL);
	index = provided_name_index(svc, name);
	if (index < 0)
		return (EACCES);
	switch (svc->name_state[index]) {
	case SVC_NAME_UNCLAIMED:
		return (ENOENT);
	case SVC_NAME_ACTIVATING:
		/*
		 * Withdrawal is authoritative cancellation.  The activation
		 * event may already be queued on the provider channel; changing
		 * the state first makes any late NAME_RESULT stale, while
		 * failing retained requests gives every caller a terminal result
		 * instead of leaving an orphaned claim.
		 */
		on_demand_name_failed(svc, name, ECANCELED, kq);
		break;
	case SVC_NAME_READY:
		error = naming_unregister(name, svc);
		if (error != 0)
			return (error);
		break;
	case SVC_NAME_INACTIVE:
		break;
	default:
		return (EPROTO);
	}
	svc->name_state[index] = SVC_NAME_UNCLAIMED;
	return (0);
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
		struct svc_runtime *waiter;
		unsigned j;

		/* Is this pending lookup waiting on a name requester provides? */
		for (i = 0; i < requester->manifest.nprovides; i++) {
			if (strcmp(p->name, requester->manifest.provides[i]) != 0 ||
			    !pending_provider_matches(p, requester))
				continue;
			/*
			 * The waiter is blocked on the requester.  That alone is
			 * not a deadlock: the requester becomes ready once its own
			 * dependency 'name' resolves, and the waiter's lookup then
			 * completes.  It is a cycle only if 'name' is itself
			 * provided by that blocked waiter — requester needs 'name'
			 * (= the waiter) which cannot become ready because it is
			 * waiting on the requester.  A starting provider that pulls
			 * in an unrelated on-demand service (e.g. the audit broker)
			 * is not circular.
			 */
			waiter = svc_by_label(p->requester_label);
			if (waiter == NULL)
				continue;
			for (j = 0; j < waiter->manifest.nprovides; j++) {
				if (strcmp(waiter->manifest.provides[j],
				    name) != 0)
					continue;
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
 * Broker a resolved lookup to a waiting requester.
 *
 * Resolves 'name' on behalf of req_svc and sends the reply on the
 * requester's *current* channel — never a cached fd, which may have been
 * recycled once the requester exited.  If the requester is gone (req_svc
 * NULL) or has no channel, there is nobody to answer, so nothing is sent.
 *
 * Returns true if a client fd was delivered.
 */
static bool
on_demand_broker(const char *name, struct svc_runtime *req_svc,
    struct channel_message *request)
{
	bool sendable;
	int client_fd, error;
	int32_t status;

	if (req_svc == NULL || req_svc->channel_fd < 0) {
		channel_message_free(request);
		return (false);
	}

	client_fd = naming_lookup(name, req_svc, &req_svc->domain, &error,
	    &sendable);
	if (client_fd >= 0) {
		status = 0;
		/*
		 * A sendable session is delivered at the CAP_XFER_UNLIMITED
		 * state naming_lookup() left it (the consumer may re-send it);
		 * every other session is attenuated to CAP_XFER_ONCE so the
		 * single delivery send consumes it to CAP_XFER_NONE.
		 */
		if (!sendable && cap_xfer_limit(client_fd, CAP_XFER_ONCE) == -1)
			status = errno;
		if (status == 0) {
			if (channel_send_reply(request,
			    &(struct channel_outgoing){
				.size = sizeof(struct channel_outgoing),
				.data = &status,
				.length = sizeof(status),
				.fds = &client_fd,
				.nfds = 1
			    }) == -1)
				syslog(LOG_WARNING,
				    "on_demand: lookup reply with endpoint "
				    "failed: %m");
		} else if (channel_send_reply(request,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(&status,
		    sizeof(status))) == -1) {
			syslog(LOG_WARNING,
			    "on_demand: lookup status reply failed: %m");
		}
		close(client_fd);
		channel_message_free(request);
		svc_channel_sync_events(req_svc, serviced_kq);
		return (status == 0);
	}
	status = error;
	(void)channel_send_reply(request, &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&status, sizeof(status)));
	channel_message_free(request);
	svc_channel_sync_events(req_svc, serviced_kq);
	return (false);
}

static int
send_activation(struct svc_runtime *provider, const char *name)
{
	struct svc_activate_name_msg message;

	if (provider == NULL || provider->channel_fd < 0) {
		errno = ECONNRESET;
		return (-1);
	}
	memset(&message, 0, sizeof(message));
	message.op = SVC_OP_ACTIVATE_NAME;
	strlcpy(message.name, name, sizeof(message.name));
	return (svc_channel_send_event(provider, &message, sizeof(message),
	    NULL, 0, serviced_kq));
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
/*
 * Launch a unit.  Every capability service a unit depends on is now reached
 * lazily at runtime (service_connect), so there is no pre-exec provider to
 * await; the launch proceeds immediately.
 */
int
svc_launch_or_await(struct svc_runtime *svc, int kq)
{

	return (svc_exec(svc, kq));
}

int
on_demand_launch(const char *name, struct svc_runtime *requester,
    struct channel_message *request, int kq)
{
	unsigned bundle_idx, service_idx;
	struct capbundle *b;
	struct capbundle_service *asvc;
	struct svc_runtime *target;
	struct pending_lookup *pl;
	struct kevent kev;
	int saved_errno;

	/* Look up in the provides registry. */
	if (bundle_registry_lookup(name, &bundle_idx, &service_idx) == -1)
		return (-1);  /* not found — caller should return ENOENT */

	/* Circular dependency detection. */
	if (would_deadlock(name, requester)) {
		errno = EDEADLK;
		return (-1);
	}

	/*
	 * Reserve the bounded waiter and its timer before changing process
	 * state.  A timer-registration failure must be terminal for this
	 * lookup; otherwise the retained reply token could wait forever.
	 */
	if (npending >= ON_DEMAND_MAX_PENDING) {
		syslog(LOG_WARNING,
		    "on_demand: too many pending lookups");
		errno = EAGAIN;
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
		pl->requester_pid = requester->pid;
		pl->requester_launch_id = requester->launch_id;
	} else {
		strlcpy(pl->requester_label, "unknown",
		    sizeof(pl->requester_label));
		pl->requester_pid = -1;
	}
	pl->request = request;
	if (arm_timeout(kq, pl) == -1) {
		syslog(LOG_WARNING, "on_demand: kevent timer: %m");
		goto fail_waiter;
	}

	/* Check if this service is already running or being launched. */
	target = find_launching_service(name);
	if (target == NULL) {
		/* Need to actually launch. */
		b = bundle_registry_get(bundle_idx);
		if (b == NULL)
			goto fail_timer;
		asvc = capbundle_service(b, service_idx);
		if (asvc == NULL)
			goto fail_timer;

		/*
		 * A boot-activated unit may already own a runtime slot that
		 * has not launched yet (or is between states).  Appending a
		 * second runtime under the same label would race the boot
		 * launch with this activation and leave one instance losing
		 * its name claims.  Launch through the existing slot instead.
		 */
		target = svc_by_label(capbundle_svc_label(asvc));
		if (target != NULL) {
			if (target->state == SVC_STATE_STOPPED) {
				if (svc_launch_or_await(target, kq) == -1) {
					syslog(LOG_ERR,
				    "on_demand: failed to launch '%s': %m", name);
					goto fail_timer;
				}
				syslog(LOG_INFO,
				    "on_demand: launching existing unit '%s' "
				    "(requested by '%s')",
				    target->manifest.label,
				    pl->requester_label);
			} else {
				SERVICED_PROBE_ON_DEMAND_COALESCE(name);
			}
			goto have_target;
		}

		/* Find a free slot in sd.services[]. */
		if (sd.services == NULL) {
			/* Service array was never allocated (startup OOM). */
			errno = ENOMEM;
			goto fail_timer;
		}
		if (sd.nservices >= SERVICED_MAX_SERVICES) {
			syslog(LOG_ERR,
			    "on_demand: service limit reached, cannot launch '%s'",
			    name);
			errno = ENOSPC;
			goto fail_timer;
		}

		target = &sd.services[sd.nservices];
		memset(target, 0, sizeof(*target));
		svc_runtime_init_fds(target);
		target->state = SVC_STATE_STOPPED;
		target->bundle_idx = bundle_idx;
		target->bundle_svc_idx = service_idx;

		/* Fill manifest from bundle (includes all capabilities). */
		if (capbundle_svc_fill_manifest(asvc,
		    &target->manifest) == -1) {
			syslog(LOG_ERR,
			    "on_demand: invalid bundle service '%s'",
			    capbundle_svc_label(asvc));
			goto fail_timer;
		}
		target->lookup_activated = true;

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
		if (svc_launch_or_await(target, kq) == -1) {
			syslog(LOG_ERR,
				    "on_demand: failed to launch '%s': %m", name);
			sd.nservices--;
			memset(target, 0, sizeof(*target));
			svc_runtime_init_fds(target);
			goto fail_timer;
		}

		syslog(LOG_INFO,
		    "on_demand: launching '%s' (requested by '%s')",
		    target->manifest.label, target->launched_by);
		SERVICED_PROBE_ON_DEMAND_LAUNCH(name, target->launched_by);
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), 0,
		    "on-demand launch svc=%s requested_by=%s",
		    target->manifest.label, target->launched_by);
	} else {
		SERVICED_PROBE_ON_DEMAND_COALESCE(name);
	}

have_target:
	strlcpy(pl->provider_label, target->manifest.label,
	    sizeof(pl->provider_label));
	pl->provider_pid = target->pid;
	pl->provider_launch_id = target->launch_id;
	pl->next = pending_list;
	pending_list = pl;
	npending++;
	if (target->state == SVC_STATE_RUNNING && target->protocol_ready)
		on_demand_check_ready(target, kq);

	return (0);

fail_timer:
	saved_errno = errno != 0 ? errno : EIO;
	EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
	    EV_DELETE, 0, 0, NULL);
	(void)kevent(kq, &kev, 1, NULL, 0, NULL);
	errno = saved_errno;
fail_waiter:
	saved_errno = errno != 0 ? errno : EIO;
	free(pl);
	errno = saved_errno;
	return (-1);
}

/*
 * Request activation of each pending name once the process itself is ready.
 */
void
on_demand_check_ready(struct svc_runtime *svc, int kq)
{
	struct pending_lookup *pl;
	unsigned i;
	bool pending;

	if (svc->state != SVC_STATE_RUNNING || !svc->protocol_ready)
		return;
	for (i = 0; i < svc->manifest.nprovides; i++) {
		pending = false;
		for (pl = pending_list; pl != NULL; pl = pl->next) {
			if (strcmp(pl->name, svc->manifest.provides[i]) != 0)
				continue;
			if (!pending_provider_matches(pl, svc))
				continue;
			pending = true;
		}
		if (!pending || svc->name_state[i] != SVC_NAME_INACTIVE)
			continue;
		if (send_activation(svc, svc->manifest.provides[i]) == -1) {
			on_demand_name_failed(svc, svc->manifest.provides[i],
			    errno != 0 ? errno : EIO, kq);
			continue;
		}
		svc->name_state[i] = SVC_NAME_ACTIVATING;
		SERVICED_PROBE_ENDPOINT_ACTIVATE(svc->manifest.label,
		    svc->manifest.provides[i]);
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), 0,
		    "endpoint activation requested svc=%s name=%s",
		    svc->manifest.label, svc->manifest.provides[i]);
		syslog(LOG_INFO,
		    "on_demand: activation of endpoint '%s' requested from "
		    "provider '%s'", svc->manifest.provides[i],
		    svc->manifest.label);
	}
}

bool
on_demand_name_activating(struct svc_runtime *svc, const char *name)
{
	int index;

	index = provided_name_index(svc, name);
	return (index >= 0 &&
	    svc->name_state[index] == SVC_NAME_ACTIVATING);
}

void
on_demand_name_ready(struct svc_runtime *svc, const char *name, int kq)
{
	struct pending_lookup **pp, *pl;
	struct kevent kev;
	unsigned nwaiters;
	int index;

	index = provided_name_index(svc, name);
	if (index < 0)
		return;
	svc->name_state[index] = SVC_NAME_READY;
	nwaiters = 0;
	pp = &pending_list;
	while ((pl = *pp) != NULL) {
		if (strcmp(pl->name, name) != 0 ||
		    !pending_provider_matches(pl, svc)) {
			pp = &pl->next;
			continue;
		}
		if (pl->request == NULL) {
			struct svc_runtime *waiter;

			/* Deferred launch: the provider this unit's
			 * components need is now ready. */
			waiter = pending_launch_waiter(pl);
			if (waiter != NULL) {
				syslog(LOG_INFO,
				    "on_demand: provider '%s' ready; launching "
				    "deferred unit '%s'", name,
				    waiter->manifest.label);
				if (svc_launch_or_await(waiter, kq) == -1)
					syslog(LOG_ERR,
					    "on_demand: deferred launch of "
					    "'%s' failed: %m",
					    waiter->manifest.label);
			}
		} else
			(void)on_demand_broker(name, pending_requester(pl),
			    pl->request);
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		*pp = pl->next;
		free(pl);
		npending--;
		nwaiters++;
	}
	if (nwaiters != 0)
		SERVICED_PROBE_ON_DEMAND_READY(name, nwaiters);
	if (nwaiters != 0) {
		syslog(LOG_INFO,
		    "on_demand: activation of endpoint '%s' by provider '%s' "
		    "ready; releasing %u waiter%s", name,
		    svc->manifest.label, nwaiters, nwaiters == 1 ? "" : "s");
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), 0,
		    "endpoint activation ready svc=%s name=%s waiters=%u",
		    svc->manifest.label, name, nwaiters);
	}
}

void
on_demand_name_failed(struct svc_runtime *svc, const char *name, int error,
    int kq)
{
	struct pending_lookup **pp, *pl;
	struct svc_runtime *requester;
	struct kevent kev;
	unsigned failed;
	int index;
	int32_t status;

	index = provided_name_index(svc, name);
	if (index >= 0)
		svc->name_state[index] = SVC_NAME_INACTIVE;
	if (error <= 0)
		error = EIO;
	status = error;
	failed = 0;
	pp = &pending_list;
	while ((pl = *pp) != NULL) {
		if (strcmp(pl->name, name) != 0 ||
		    !pending_provider_matches(pl, svc)) {
			pp = &pl->next;
			continue;
		}
		requester = pending_requester(pl);
		if (requester != NULL) {
			(void)channel_send_reply(pl->request,
			    &(struct channel_outgoing)
			    CHANNEL_OUTGOING_INITIALIZER(&status,
			    sizeof(status)));
			svc_channel_sync_events(requester, kq);
		}
		channel_message_free(pl->request);
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		*pp = pl->next;
		free(pl);
		npending--;
		failed++;
	}
	if (failed != 0) {
		syslog(LOG_WARNING,
		    "on_demand: activation of endpoint '%s' by provider '%s' "
		    "failed: %s; failing %u waiter%s", name,
		    svc->manifest.label, strerror(error), failed,
		    failed == 1 ? "" : "s");
		SERVICED_PROBE_ON_DEMAND_FAIL(name, error, failed);
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), error,
		    "endpoint activation failed svc=%s name=%s waiters=%u",
		    svc->manifest.label, name, failed);
	}
}

/*
 * Fail lookups immediately when their provider exits before publication.
 * Waiting for each independent timeout would hide the crash from clients and
 * retain reply tokens after the failed runtime is already gone.
 */
void
on_demand_provider_failed(struct svc_runtime *svc, int error, int kq)
{
	struct pending_lookup **pp, *pl;
	struct svc_runtime *requester;
	struct kevent kev;
	unsigned failed;
	int32_t status;

	if (error <= 0)
		error = ECONNRESET;
	status = error;
	failed = 0;
	pp = &pending_list;
	while (*pp != NULL) {
		pl = *pp;
		if (!pending_provider_matches(pl, svc)) {
			pp = &pl->next;
			continue;
		}

		requester = pending_requester(pl);
		if (requester != NULL) {
			(void)channel_send_reply(pl->request,
			    &(struct channel_outgoing)
			    CHANNEL_OUTGOING_INITIALIZER(&status,
			    sizeof(status)));
			svc_channel_sync_events(requester, kq);
		}
		channel_message_free(pl->request);
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		syslog(LOG_WARNING,
		    "on_demand: provider '%s' failed before endpoint '%s' "
		    "became ready", svc->manifest.label, pl->name);
		*pp = pl->next;
		free(pl);
		npending--;
		failed++;
	}
	if (failed != 0) {
		SERVICED_PROBE_ON_DEMAND_FAIL(svc->manifest.label, error,
		    failed);
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), error,
		    "on-demand provider failed svc=%s waiters=%u",
		    svc->manifest.label, failed);
	}
}

/*
 * A reply token belongs to one control-channel instance, not to a persistent
 * service label.  Drop its outstanding requests when that exact process
 * exits so a restarted process can never consume a stale reply.
 */
void
on_demand_requester_gone(struct svc_runtime *svc, int kq)
{
	struct pending_lookup **pp, *pl;
	struct kevent kev;
	unsigned canceled;

	canceled = 0;
	pp = &pending_list;
	while (*pp != NULL) {
		pl = *pp;
		if (pl->requester_pid != svc->pid ||
		    pl->requester_launch_id != svc->launch_id ||
		    strcmp(pl->requester_label, svc->manifest.label) != 0) {
			pp = &pl->next;
			continue;
		}
		EV_SET(&kev, pl->timeout_ident, EVFILT_TIMER,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(kq, &kev, 1, NULL, 0, NULL);
		channel_message_free(pl->request);
		*pp = pl->next;
		free(pl);
		npending--;
		canceled++;
	}
	if (canceled != 0) {
		syslog(LOG_INFO,
		    "on_demand: canceled %u pending lookup%s for exited "
		    "requester '%s' (pid %jd, launch %ju)",
		    canceled, canceled == 1 ? "" : "s", svc->manifest.label,
		    (intmax_t)svc->pid, (uintmax_t)svc->launch_id);
		SERVICED_PROBE_ON_DEMAND_CANCEL(svc->manifest.label,
		    svc->pid, svc->launch_id, canceled);
		serviced_audit(AUE_SERVICED_ONDEMAND, getuid(), ECANCELED,
		    "on-demand requester gone svc=%s pid=%jd launch=%ju "
		    "waiters=%u", svc->manifest.label, (intmax_t)svc->pid,
		    (uintmax_t)svc->launch_id, canceled);
	}
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
	char expired_provider[SERVICED_LABEL_MAX];
	pid_t expired_pid;
	uint64_t expired_launch_id;

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
		strlcpy(expired_provider, pl->provider_label,
		    sizeof(expired_provider));
		expired_pid = pl->provider_pid;
		expired_launch_id = pl->provider_launch_id;

		/* Send ETIMEDOUT reply.  Re-resolve the requester by
		 * label — the original channel_fd may be stale if the
		 * requester was restarted since the lookup.  Deferred
		 * launches carry no request; the unit simply stays
		 * stopped and a later demand may retry it. */
		if (pl->request != NULL) {
			struct svc_runtime *req;
			int32_t status = ETIMEDOUT;

			req = pending_requester(pl);
			if (req != NULL) {
				(void)channel_send_reply(pl->request,
				    &(struct channel_outgoing)
				    CHANNEL_OUTGOING_INITIALIZER(&status,
				    sizeof(status)));
				svc_channel_sync_events(req, kq);
			}
			channel_message_free(pl->request);
		}

		/* Remove from list. */
		*pp = pl->next;
		free(pl);
		npending--;
		{
			struct svc_runtime *target;

			target = svc_by_label(expired_provider);
			if (target != NULL && target->lookup_activated &&
			    target->state == SVC_STATE_STARTING &&
			    target->pid == expired_pid &&
			    target->launch_id == expired_launch_id &&
			    !pending_for_provider_name(target, expired_name)) {
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

		/* Send error reply.  Re-resolve the requester by label and use
		 * only its current channel fd; if it is gone there is nobody to
		 * answer, so do not write to a possibly-recycled fd. */
		{
			struct svc_runtime *req;

			req = pending_requester(pl);
			if (req != NULL) {
				int32_t status = ESHUTDOWN;

				(void)channel_send_reply(pl->request,
				    &(struct channel_outgoing)
				    CHANNEL_OUTGOING_INITIALIZER(&status,
				    sizeof(status)));
				svc_channel_sync_events(req, kq);
			}
			channel_message_free(pl->request);
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
