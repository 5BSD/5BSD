/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Client Management
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/selinfo.h>
#include <sys/jail.h>
#include <sys/loginclass.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/tty.h>
#include <sys/resourcevar.h>
#include <sys/time.h>
#include <sys/sysent.h>
#include <security/audit/audit.h>

#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

MALLOC_DECLARE(M_OES);

/* proctree_lock protects p_pptr, p_pgrp, and related tree fields */
extern struct sx proctree_lock;

/*
 * Get process generation ID (start time as microseconds).
 * Requires: PROC_LOCK(p) held by caller.
 */
static uint64_t
oes_proc_genid(struct proc *p)
{
	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (p->p_stats != NULL) {
		/*
		 * Combine seconds and microseconds to distinguish
		 * processes that start within the same second.
		 */
		return ((uint64_t)p->p_stats->p_start.tv_sec * 1000000ULL +
		    (uint64_t)p->p_stats->p_start.tv_usec);
	}
	return (0);
}

bool
oes_client_observes_token(const struct oes_client *ec,
	const oes_proc_token_t *token)
{
	struct proc *p, *q;
	bool locked_here, observed;

	if (ec->ec_scope == OES_SCOPE_GLOBAL)
		return (true);
	if (token == NULL || token->ept_id == 0 || token->ept_id > PID_MAX)
		return (false);

	observed = false;
	locked_here = !sx_xlocked(&proctree_lock);
	if (locked_here)
		sx_slock(&proctree_lock);
	p = pfind((pid_t)token->ept_id);
	if (p == NULL)
		goto out;
	if (token->ept_genid != 0 && token->ept_genid != oes_proc_genid(p)) {
		PROC_UNLOCK(p);
		goto out;
	}
	for (q = p; q != NULL; q = proc_realparent(q)) {
		if (q->p_pid == ec->ec_owner_pid) {
			observed = true;
			break;
		}
		if (q == &proc0)
			break;
	}
	PROC_UNLOCK(p);
out:
	if (locked_here)
		sx_sunlock(&proctree_lock);
	return (observed);
}

static int
oes_client_validate_token(struct oes_client *ec,
	const oes_proc_token_t *token)
{
	struct proc *p;
	uint64_t genid;
	pid_t pid;

	if (token == NULL)
		return (EINVAL);
	if (token->ept_id == 0 || token->ept_id > PID_MAX)
		return (EINVAL);

	pid = (pid_t)token->ept_id;
	p = pfind(pid);
	if (p == NULL)
		return (ESRCH);

	if ((p->p_flag & P_WEXIT) != 0) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}

	genid = oes_proc_genid(p);
	PROC_UNLOCK(p);

	if (token->ept_genid != 0 && token->ept_genid != genid)
		return (ESRCH);
	if (!oes_client_observes_token(ec, token))
		return (EPERM);

	return (0);
}

struct oes_client *
oes_client_alloc(void)
{
	struct oes_client *ec;
	int queue_max;
	int deadline_ms;

	ec = malloc(sizeof(*ec), M_OES, M_WAITOK | M_ZERO);

	mtx_init(&ec->ec_mtx, "oes_client", NULL, MTX_DEF);
	ec->ec_owner_pid = -1;
	ec->ec_scope = OES_SCOPE_GLOBAL;
	ec->ec_mode = OES_MODE_NOTIFY;
	deadline_ms = oes_default_deadline;
	if (deadline_ms < OES_MIN_DEADLINE_MS)
		deadline_ms = OES_MIN_DEADLINE_MS;
	if (deadline_ms > OES_MAX_DEADLINE_MS)
		deadline_ms = OES_MAX_DEADLINE_MS;
	ec->ec_default_deadline_ms = (uint32_t)deadline_ms;
	if (oes_default_deadline_miss_mode == OES_DEADLINE_MISS_FAIL_OPEN ||
	    oes_default_deadline_miss_mode == OES_DEADLINE_MISS_FAIL_CLOSED)
		ec->ec_deadline_miss_mode = oes_default_deadline_miss_mode;
	else
		ec->ec_deadline_miss_mode = OES_DEADLINE_MISS_FAIL_OPEN;
	queue_max = oes_default_queue_size;
	if (queue_max <= 0)
		queue_max = OES_DEFAULT_QUEUE_SIZE;
	if (queue_max > 65536)
		queue_max = 65536;
	ec->ec_queue_max = (uint32_t)queue_max;

	TAILQ_INIT(&ec->ec_pending);
	TAILQ_INIT(&ec->ec_delivered);
	for (int i = 0; i < OES_MUTE_PROC_BUCKETS; i++)
		LIST_INIT(&ec->ec_muted[i]);
	LIST_INIT(&ec->ec_muted_paths);
	LIST_INIT(&ec->ec_muted_targets);
	LIST_INIT(&ec->ec_muted_uids);
	LIST_INIT(&ec->ec_muted_gids);
	oes_cache_init(ec);

	knlist_init_mtx(&ec->ec_selinfo.si_note, &ec->ec_mtx);

	return (ec);
}

void
oes_client_free(struct oes_client *ec)
{
	struct oes_pending *ep, *ep_tmp;
	struct oes_mute_entry *em, *em_tmp;
	struct oes_mute_path_entry *epm, *epm_tmp;

	EC_LOCK(ec);

	/* Wake any AUTH waiters with default response */
	TAILQ_FOREACH_SAFE(ep, &ec->ec_pending, ep_link, ep_tmp) {
		TAILQ_REMOVE(&ec->ec_pending, ep, ep_link);
		ec->ec_queue_count--;
		if (ec->ec_queue_bytes >= ep->ep_msg.em_size)
			ec->ec_queue_bytes -= ep->ep_msg.em_size;
		else
			ec->ec_queue_bytes = 0;

		if (ep->ep_flags & EP_FLAG_AUTH) {
			mtx_lock(&ep->ep_mtx);
			if (!ep->ep_responded) {
				oes_auth_result_t close_action;

				close_action = (oes_auth_fail_closed ||
				    oes_require_auth_clients || ec->ec_deadline_miss_mode ==
				    OES_DEADLINE_MISS_FAIL_CLOSED) ? OES_AUTH_DENY :
				    OES_AUTH_ALLOW;
				ep->ep_responded = true;
				ep->ep_result = close_action;
				if (ep->ep_group != NULL)
					oes_auth_group_mark_response(
					    ep->ep_group, close_action);
				cv_broadcast(&ep->ep_cv);
			}
			mtx_unlock(&ep->ep_mtx);
		}
		oes_pending_rele(ep);
	}

	/* Wake any delivered AUTH events */
	TAILQ_FOREACH_SAFE(ep, &ec->ec_delivered, ep_link, ep_tmp) {
		TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);

		if (ep->ep_flags & EP_FLAG_AUTH) {
			mtx_lock(&ep->ep_mtx);
			if (!ep->ep_responded) {
				oes_auth_result_t close_action;

				close_action = (oes_auth_fail_closed ||
				    oes_require_auth_clients || ec->ec_deadline_miss_mode ==
				    OES_DEADLINE_MISS_FAIL_CLOSED) ? OES_AUTH_DENY :
				    OES_AUTH_ALLOW;
				ep->ep_responded = true;
				ep->ep_result = close_action;
				if (ep->ep_group != NULL)
					oes_auth_group_mark_response(
					    ep->ep_group, close_action);
				cv_broadcast(&ep->ep_cv);
			}
			mtx_unlock(&ep->ep_mtx);
		}
		oes_pending_rele(ep);
	}

	for (int i = 0; i < OES_MUTE_PROC_BUCKETS; i++) {
		LIST_FOREACH_SAFE(em, &ec->ec_muted[i], em_link, em_tmp) {
			LIST_REMOVE(em, em_link);
			free(em, M_OES);
		}
	}
	LIST_FOREACH_SAFE(epm, &ec->ec_muted_paths, emp_link, epm_tmp) {
		LIST_REMOVE(epm, emp_link);
		free(epm, M_OES);
	}
	LIST_FOREACH_SAFE(epm, &ec->ec_muted_targets, emp_link, epm_tmp) {
		LIST_REMOVE(epm, emp_link);
		free(epm, M_OES);
	}
	{
		struct oes_mute_uid_entry *emu, *emu_tmp;
		struct oes_mute_gid_entry *emg, *emg_tmp;

		LIST_FOREACH_SAFE(emu, &ec->ec_muted_uids, emu_link, emu_tmp) {
			LIST_REMOVE(emu, emu_link);
			free(emu, M_OES);
		}
		LIST_FOREACH_SAFE(emg, &ec->ec_muted_gids, emg_link, emg_tmp) {
			LIST_REMOVE(emg, emg_link);
			free(emg, M_OES);
		}
	}

	oes_cache_destroy(ec);

	EC_UNLOCK(ec);

	/*
	 * Drain any knotes still attached to this client's knlist before
	 * destroying it.  A kqueue registration (oes_kqfilter) attaches a knote
	 * whose kn_hook is this client; if such a knote outlived the fd-close
	 * knote_fdclose() drop, destroying (and freeing) the client underneath
	 * it would leave a dangling kn_knlist and fault in oes_kqdetach().
	 * knlist_clear() removes and detaches any remaining knotes first; it is
	 * a no-op in the common case where the fd close already dropped them.
	 */
	knlist_clear(&ec->ec_selinfo.si_note, 0);

	/* Destroy knlist (must be done without lock) */
	knlist_destroy(&ec->ec_selinfo.si_note);

	mtx_destroy(&ec->ec_mtx);
	free(ec, M_OES);
}

int
oes_client_subscribe_events(struct oes_client *ec, oes_event_type_t *events,
    size_t count, uint32_t flags)
{
	size_t i;

	if (flags != OES_SUB_ADD && flags != OES_SUB_REPLACE &&
	    flags != OES_SUB_REMOVE)
		return (EINVAL);

	/*
	 * Validate all events BEFORE modifying state to ensure atomicity.
	 * Without this, OES_SUB_REPLACE could clear subscriptions and then
	 * fail partway through, leaving the client with partial subscriptions.
	 */
	EC_LOCK(ec);
	if ((ec->ec_flags & EC_FLAG_SCOPE_SETTING) != 0) {
		EC_UNLOCK(ec);
		return (EBUSY);
	}

	for (i = 0; i < count; i++) {
		oes_event_type_t ev = events[i];
		int bit = ev & 0x0FFF;

		/* Validate event type is a defined enum value */
		if (!oes_event_is_valid(ev)) {
			EC_UNLOCK(ec);
			return (EINVAL);
		}

		/* Validate bit position is within supported range */
		if (bit >= 128) {
			EC_UNLOCK(ec);
			return (EINVAL);
		}

		/* AUTH events require AUTH mode (PASSIVE gets them as NOTIFY). */
		if (flags != OES_SUB_REMOVE && OES_EVENT_IS_AUTH(ev) &&
		    ec->ec_mode != OES_MODE_AUTH) {
			if (ec->ec_mode == OES_MODE_PASSIVE) {
				if (oes_auth_to_notify(ev) == 0) {
					EC_UNLOCK(ec);
					return (EPERM);
				}
			} else {
				/* NOTIFY mode can't subscribe to AUTH */
				EC_UNLOCK(ec);
				return (EPERM);
			}
		}
	}

	/* All events validated - now apply changes atomically */
	if (flags & OES_SUB_REPLACE)
		oes_client_unsubscribe_all(ec);

	for (i = 0; i < count; i++) {
		if (flags == OES_SUB_REMOVE)
			oes_client_unsubscribe(ec, events[i]);
		else
			oes_client_subscribe(ec, events[i]);
	}

	EC_UNLOCK(ec);

	OES_DEBUG("client %p subscribed to %zu events", ec, count);

	return (0);
}

/*
 * Validate AUTH bitmap for PASSIVE mode.
 * All set bits must have corresponding NOTIFY mappings.
 */
static bool
oes_validate_auth_bitmap_for_passive(const uint64_t auth_bitmap[2])
{
	int i, j;

	for (j = 0; j < 2; j++) {
		uint64_t mask = auth_bitmap[j];
		for (i = 0; i < 64; i++) {
			if (mask & (1ULL << i)) {
				oes_event_type_t ev = (j * 64) + i;
				if (oes_auth_to_notify(ev) == 0)
					return (false);
			}
		}
	}
	return (true);
}

int
oes_client_subscribe_bitmap(struct oes_client *ec,
    const uint64_t auth_bitmap[2], const uint64_t notify_bitmap[2],
    uint32_t flags)
{
	if (flags != OES_SUB_ADD && flags != OES_SUB_REPLACE &&
	    flags != OES_SUB_REMOVE)
		return (EINVAL);

	EC_LOCK(ec);
	if ((ec->ec_flags & EC_FLAG_SCOPE_SETTING) != 0) {
		EC_UNLOCK(ec);
		return (EBUSY);
	}

	/* AUTH subscriptions require AUTH mode (or PASSIVE) */
	if (flags != OES_SUB_REMOVE &&
	    (auth_bitmap[0] != 0 || auth_bitmap[1] != 0)) {
		if (ec->ec_mode != OES_MODE_AUTH &&
		    ec->ec_mode != OES_MODE_PASSIVE) {
			EC_UNLOCK(ec);
			return (EPERM);
		}
		/* PASSIVE: validate all AUTH bits have NOTIFY mappings */
		if (ec->ec_mode == OES_MODE_PASSIVE) {
			if (!oes_validate_auth_bitmap_for_passive(auth_bitmap)) {
				EC_UNLOCK(ec);
				return (EPERM);
			}
		}
	}

	/* Replace mode: clear existing subscriptions */
	if (flags & OES_SUB_REPLACE)
		oes_client_unsubscribe_all(ec);

	if (flags == OES_SUB_REMOVE) {
		ec->ec_subscriptions[0] &= ~(auth_bitmap[0] & OES_VALID_AUTH_LO);
		ec->ec_subscriptions[1] &= ~(auth_bitmap[1] & OES_VALID_AUTH_HI);
		ec->ec_subscriptions[2] &= ~(notify_bitmap[0] & OES_VALID_NOTIFY_LO);
		ec->ec_subscriptions[3] &= ~(notify_bitmap[1] & OES_VALID_NOTIFY_HI);
	} else {
		ec->ec_subscriptions[0] |= auth_bitmap[0] & OES_VALID_AUTH_LO;
		ec->ec_subscriptions[1] |= auth_bitmap[1] & OES_VALID_AUTH_HI;
		ec->ec_subscriptions[2] |= notify_bitmap[0] & OES_VALID_NOTIFY_LO;
		ec->ec_subscriptions[3] |= notify_bitmap[1] & OES_VALID_NOTIFY_HI;
	}

	EC_UNLOCK(ec);

	OES_DEBUG("client %p subscribed via ext bitmap", ec);

	return (0);
}

void
oes_client_get_subscriptions(struct oes_client *ec, uint64_t auth_bitmap[2],
    uint64_t notify_bitmap[2])
{
	EC_LOCK(ec);
	auth_bitmap[0] = ec->ec_subscriptions[0];
	auth_bitmap[1] = ec->ec_subscriptions[1];
	notify_bitmap[0] = ec->ec_subscriptions[2];
	notify_bitmap[1] = ec->ec_subscriptions[3];
	EC_UNLOCK(ec);
}

int
oes_client_set_scope(struct oes_client *ec, uint32_t scope)
{
	uint64_t marker;
	pid_t owner_pid;
	int error;

	if (scope != OES_SCOPE_DESCENDANTS)
		return (EINVAL);

	EC_LOCK(ec);
	if ((ec->ec_flags & (EC_FLAG_MODE_SET | EC_FLAG_SCOPE_SETTING)) != 0 ||
	    ec->ec_subscriptions[0] != 0 || ec->ec_subscriptions[1] != 0 ||
	    ec->ec_subscriptions[2] != 0 || ec->ec_subscriptions[3] != 0 ||
	    !TAILQ_EMPTY(&ec->ec_pending) || !TAILQ_EMPTY(&ec->ec_delivered)) {
		error = EBUSY;
	} else if (ec->ec_scope == OES_SCOPE_GLOBAL) {
		ec->ec_flags |= EC_FLAG_SCOPE_SETTING;
		owner_pid = ec->ec_owner_pid;
		EC_UNLOCK(ec);
		error = oes_scope_mark_current(owner_pid, &marker);
		EC_LOCK(ec);
		ec->ec_flags &= ~EC_FLAG_SCOPE_SETTING;
		if (error == 0) {
			ec->ec_scope_marker = marker;
			ec->ec_scope = scope;
		}
	} else {
		error = (ec->ec_scope == scope) ? 0 : EPERM;
	}
	EC_UNLOCK(ec);
	return (error);
}

void
oes_client_get_scope(struct oes_client *ec, uint32_t *scope)
{

	EC_LOCK(ec);
	*scope = ec->ec_scope;
	EC_UNLOCK(ec);
}

/*
 * Apply default mutes from sysctl configuration
 * Called when client first sets mode.
 */
static void
oes_client_apply_default_mutes(struct oes_client *ec)
{
	char pathbuf[MAXPATHLEN];
	const char *start, *end;
	size_t len;

	/* Apply default self-mute (add entry to list for query consistency) */
	if (oes_default_self_mute && ec->ec_scope != OES_SCOPE_DESCENDANTS &&
	    !(ec->ec_flags & EC_FLAG_MUTED_SELF)) {
		struct oes_mute_entry *em;

		em = malloc(sizeof(*em), M_OES, M_NOWAIT | M_ZERO);

		EC_LOCK(ec);
		ec->ec_flags |= EC_FLAG_MUTED_SELF;
		if (em != NULL) {
			em->em_pid = ec->ec_owner_pid;
			em->em_genid = ec->ec_owner_genid;
			/* em_events stays 0 = mute all */
			LIST_INSERT_HEAD(
			    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
			    em, em_link);
			ec->ec_muted_proc_count++;
		}
		EC_UNLOCK(ec);
		OES_DEBUG("client %p: applied default self-mute", ec);
	}

	/* Apply default prefix path mutes */
	if (oes_default_muted_paths[0] != '\0') {
		start = oes_default_muted_paths;
		while (*start != '\0') {
			/* Find end of this path (colon or end of string) */
			end = start;
			while (*end != '\0' && *end != ':')
				end++;
			len = end - start;
			if (len > 0 && len < MAXPATHLEN) {
				memcpy(pathbuf, start, len);
				pathbuf[len] = '\0';
				(void)oes_client_mute_path(ec, pathbuf,
				    OES_MUTE_PATH_PREFIX, false);
				OES_DEBUG("client %p: muted prefix path %s",
				    ec, pathbuf);
			}
			/* Skip to next path */
			start = (*end == ':') ? end + 1 : end;
		}
	}

	/* Apply default literal path mutes */
	if (oes_default_muted_paths_literal[0] != '\0') {
		start = oes_default_muted_paths_literal;
		while (*start != '\0') {
			end = start;
			while (*end != '\0' && *end != ':')
				end++;
			len = end - start;
			if (len > 0 && len < MAXPATHLEN) {
				memcpy(pathbuf, start, len);
				pathbuf[len] = '\0';
				(void)oes_client_mute_path(ec, pathbuf,
				    OES_MUTE_PATH_LITERAL, false);
				OES_DEBUG("client %p: muted literal path %s",
				    ec, pathbuf);
			}
			start = (*end == ':') ? end + 1 : end;
		}
	}
}

int
oes_client_set_mode(struct oes_client *ec, uint32_t mode,
    uint32_t default_deadline_ms,
    uint32_t queue_size)
{
	bool first_mode_set;

	EC_LOCK(ec);
	if ((ec->ec_flags & EC_FLAG_SCOPE_SETTING) != 0) {
		EC_UNLOCK(ec);
		return (EBUSY);
	}

	/* Track if this is the first mode set (for default mutes) */
	first_mode_set = !(ec->ec_flags & EC_FLAG_MODE_SET);

	/* Validate mode */
	if (mode != OES_MODE_NOTIFY && mode != OES_MODE_AUTH &&
	    mode != OES_MODE_PASSIVE) {
		EC_UNLOCK(ec);
		return (EINVAL);
	}

	ec->ec_mode = mode;
	ec->ec_flags |= EC_FLAG_MODE_SET;

	if (default_deadline_ms != 0) {
		if (default_deadline_ms < OES_MIN_DEADLINE_MS)
			default_deadline_ms = OES_MIN_DEADLINE_MS;
		if (default_deadline_ms > OES_MAX_DEADLINE_MS)
			default_deadline_ms = OES_MAX_DEADLINE_MS;
		ec->ec_default_deadline_ms = default_deadline_ms;
	}

	if (queue_size != 0) {
		if (queue_size > 65536)
			queue_size = 65536;
		ec->ec_queue_max = queue_size;
	}

	EC_UNLOCK(ec);

	/* Apply default mutes on first mode set */
	if (first_mode_set)
		oes_client_apply_default_mutes(ec);

	OES_DEBUG("client %p mode=%u deadline=%u queue=%u",
	    ec, mode, ec->ec_default_deadline_ms, ec->ec_queue_max);

	return (0);
}

void
oes_client_get_mode(struct oes_client *ec, uint32_t *mode,
    uint32_t *default_deadline_ms, uint32_t *queue_size)
{
	EC_LOCK(ec);
	if (mode != NULL)
		*mode = ec->ec_mode;
	if (default_deadline_ms != NULL)
		*default_deadline_ms = ec->ec_default_deadline_ms;
	if (queue_size != NULL)
		*queue_size = ec->ec_queue_max;
	EC_UNLOCK(ec);
}

static int
oes_deadline_event_index(oes_event_type_t event, uint32_t *index)
{
	uint32_t bit;

	if (!oes_event_is_valid(event) || !OES_EVENT_IS_AUTH(event))
		return (EINVAL);
	bit = (uint32_t)event & 0x0fff;
	if (bit >= nitems(((struct oes_client *)0)->ec_deadline_min_ms))
		return (EINVAL);
	*index = bit;
	return (0);
}

int
oes_client_set_deadline_bound(struct oes_client *ec, oes_event_type_t event,
    uint32_t milliseconds, bool minimum)
{
	uint32_t index;
	int error;

	error = oes_deadline_event_index(event, &index);
	if (error != 0)
		return (error);
	if (milliseconds != 0) {
		if (milliseconds < OES_MIN_DEADLINE_MS)
			milliseconds = OES_MIN_DEADLINE_MS;
		if (milliseconds > OES_MAX_DEADLINE_MS)
			milliseconds = OES_MAX_DEADLINE_MS;
	}

	EC_LOCK(ec);
	if (minimum && ec->ec_scope != OES_SCOPE_DESCENDANTS) {
		EC_UNLOCK(ec);
		return (EPERM);
	}
	if (minimum) {
		ec->ec_deadline_min_ms[index] = milliseconds;
		if (milliseconds != 0) {
			uint32_t maximum = ec->ec_deadline_max_ms[index];

			if (maximum == 0)
				maximum = ec->ec_default_deadline_ms;
			if (maximum < milliseconds)
				ec->ec_deadline_max_ms[index] = milliseconds;
		}
	} else {
		ec->ec_deadline_max_ms[index] = milliseconds;
		if (milliseconds != 0 &&
		    ec->ec_deadline_min_ms[index] > milliseconds)
			ec->ec_deadline_min_ms[index] = milliseconds;
	}
	EC_UNLOCK(ec);
	return (0);
}

int
oes_client_get_deadline_bound(struct oes_client *ec, oes_event_type_t event,
    uint32_t *milliseconds, bool minimum)
{
	uint32_t index, value;
	int error;

	if (milliseconds == NULL)
		return (EINVAL);
	error = oes_deadline_event_index(event, &index);
	if (error != 0)
		return (error);

	EC_LOCK(ec);
	if (minimum && ec->ec_scope != OES_SCOPE_DESCENDANTS) {
		EC_UNLOCK(ec);
		return (EPERM);
	}
	if (minimum) {
		value = ec->ec_deadline_min_ms[index];
	} else {
		value = ec->ec_deadline_max_ms[index];
		if (value == 0)
			value = ec->ec_default_deadline_ms;
		if (value < ec->ec_deadline_min_ms[index])
			value = ec->ec_deadline_min_ms[index];
	}
	EC_UNLOCK(ec);
	*milliseconds = value;
	return (0);
}

uint32_t
oes_client_effective_deadline_locked(struct oes_client *ec,
    oes_event_type_t event)
{
	uint32_t index, maximum, minimum, timeout;

	EC_LOCK_ASSERT(ec);
	if (oes_deadline_event_index(event, &index) != 0)
		return (ec->ec_default_deadline_ms);
	minimum = ec->ec_deadline_min_ms[index];
	maximum = ec->ec_deadline_max_ms[index];
	if (maximum == 0)
		maximum = ec->ec_default_deadline_ms;
	if (maximum < minimum)
		maximum = minimum;
	timeout = ec->ec_default_deadline_ms;
	if (timeout < minimum)
		timeout = minimum;
	if (timeout > maximum)
		timeout = maximum;
	return (timeout);
}

static bool
oes_event_in_bitmap(oes_event_type_t event, const uint64_t bitmap[4])
{
	int base = OES_EVENT_IS_NOTIFY(event) ? 2 : 0;
	int bit = event & 0x0FFF;
	int word = bit / 64;
	int shift = bit % 64;

	if (bit >= 128)
		return (false);
	return ((bitmap[base + word] & (1ULL << shift)) != 0);
}

static bool
oes_mute_entry_matches_event(const struct oes_mute_entry *em,
    oes_event_type_t event)
{

	if (em->em_events[0] == 0 && em->em_events[1] == 0 &&
	    em->em_events[2] == 0 && em->em_events[3] == 0)
		return (true);
	if (event == 0)
		return (true);
	return (oes_event_in_bitmap(event, em->em_events));
}

static bool
oes_client_self_entry_muted(struct oes_client *ec, pid_t pid, uint64_t genid,
    oes_event_type_t event, bool *found)
{
	struct oes_mute_entry *em;

	if (found != NULL)
		*found = false;

	if (pid != ec->ec_owner_pid ||
	    (ec->ec_owner_genid != 0 && ec->ec_owner_genid != genid))
		return (false);

	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(pid)], em_link) {
		if (em->em_pid != pid)
			continue;
		if (em->em_genid != 0 && em->em_genid != genid)
			continue;
		if (found != NULL)
			*found = true;
		return (oes_mute_entry_matches_event(em, event));
	}

	return (false);
}

/*
 * Check if a process is muted for this client for a specific event
 *
 * If event is 0, checks whether the process is muted for all events.
 * Otherwise, checks if the specific event is muted for this process.
 */
bool
oes_client_is_muted(struct oes_client *ec, struct proc *p, oes_event_type_t event)
{
	struct oes_mute_entry *em;
	bool in_list = false;
	bool self_entry_found = false;
	uint64_t genid;
	bool inverted;

	EC_LOCK_ASSERT(ec);

	if (p == NULL)
		return (false);

	/*
	 * Read process genid for mute matching.
	 *
	 * Use mtx_trylock to avoid lock order reversal: the dispatch
	 * path holds oes -> oes_client -> (need process lock), but MAC
	 * hooks like proc_check_debug enter with process lock already
	 * held. If we can't get the lock, skip the mute check (the
	 * event will be delivered rather than suppressed).
	 */
	{
		bool owned = mtx_owned(&p->p_mtx);
		bool locked = owned;

		if (!owned)
			locked = mtx_trylock(&p->p_mtx);
		if (!locked)
			return (false);  /* Can't check, don't mute */
		if ((p->p_flag & P_WEXIT) != 0) {
			if (!owned)
				PROC_UNLOCK(p);
			return (false);
		}
		genid = oes_proc_genid(p);
		if (!owned)
			PROC_UNLOCK(p);
	}

	in_list = oes_client_self_entry_muted(ec, p->p_pid, genid, event,
	    &self_entry_found);
	if (self_entry_found)
		goto apply_inversion;

	/* If the self-mute list entry could not be allocated, the flag still
	 * represents a mute-all self entry. */
	if ((ec->ec_flags & EC_FLAG_MUTED_SELF) &&
	    p->p_pid == ec->ec_owner_pid &&
	    (ec->ec_owner_genid == 0 || ec->ec_owner_genid == genid)) {
		in_list = true;
		goto apply_inversion;
	}

	/* Check mute list - use hash bucket for O(1) average lookup */
	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(p->p_pid)], em_link) {
		if (em->em_pid != p->p_pid)
			continue;
		if (em->em_genid != 0 && em->em_genid != genid)
			continue;

		/*
		 * Found matching process entry.
		 * If all bitmaps are 0, all events are muted.
		 * Otherwise, check if specific event is in bitmap.
		 */
		in_list = oes_mute_entry_matches_event(em, event);
		break;
	}

apply_inversion:
	inverted = (ec->ec_mute_invert & EC_MUTE_INVERT_PROCESS) != 0;
	return (inverted ? !in_list : in_list);
}

/*
 * NOSLEEP-safe variant: Check if a process is muted using pre-captured token.
 *
 * Uses pid/genid from the message's process token instead of PROC_LOCK.
 * Safe to call from NOSLEEP context (fork/exit/signal handlers).
 */
bool
oes_client_is_muted_by_token(struct oes_client *ec, const oes_proc_token_t *token,
    oes_event_type_t event)
{
	struct oes_mute_entry *em;
	bool in_list = false;
	bool self_entry_found = false;
	pid_t pid;
	uint64_t genid;
	bool inverted;

	EC_LOCK_ASSERT(ec);

	if (token == NULL)
		return (false);

	pid = (pid_t)token->ept_id;
	genid = token->ept_genid;

	in_list = oes_client_self_entry_muted(ec, pid, genid, event,
	    &self_entry_found);
	if (self_entry_found)
		goto apply_inversion;

	if ((ec->ec_flags & EC_FLAG_MUTED_SELF) &&
	    pid == ec->ec_owner_pid &&
	    (ec->ec_owner_genid == 0 || ec->ec_owner_genid == genid)) {
		in_list = true;
		goto apply_inversion;
	}

	/* Check mute list - use hash bucket for O(1) average lookup */
	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(pid)], em_link) {
		if (em->em_pid != pid)
			continue;
		if (em->em_genid != 0 && em->em_genid != genid)
			continue;

		/*
		 * Found matching process entry.
		 * If all bitmaps are 0, all events are muted.
		 * Otherwise, check if specific event is in bitmap.
		 */
		in_list = oes_mute_entry_matches_event(em, event);
		break;
	}

apply_inversion:
	inverted = (ec->ec_mute_invert & EC_MUTE_INVERT_PROCESS) != 0;
	return (inverted ? !in_list : in_list);
}

static bool
oes_path_match(const struct oes_mute_path_entry *emp, const char *path)
{
	size_t path_len;

	if (emp == NULL || path == NULL)
		return (false);

	path_len = strlen(path);
	if (emp->emp_type == OES_MUTE_PATH_LITERAL)
		return (path_len == emp->emp_len &&
		    memcmp(emp->emp_path, path, emp->emp_len) == 0);
	if (emp->emp_type == OES_MUTE_PATH_PREFIX) {
		if (path_len < emp->emp_len ||
		    memcmp(emp->emp_path, path, emp->emp_len) != 0)
			return (false);
		if (emp->emp_len == 1 && emp->emp_path[0] == '/')
			return (true);
		if (emp->emp_path[emp->emp_len - 1] == '/')
			return (true);
		return (path_len == emp->emp_len || path[emp->emp_len] == '/');
	}
	return (false);
}

/*
 * Check if a path is muted for this client for a specific event
 *
 * If event is 0, checks whether the path is muted for all events.
 * Otherwise, checks if the specific event is muted for this path.
 */
bool
oes_client_is_path_muted(struct oes_client *ec, const char *path, bool target,
    oes_event_type_t event)
{
	struct oes_mute_path_entry *emp;
	bool in_list = false;
	bool inverted;

	EC_LOCK_ASSERT(ec);

	inverted = target ?
	    ((ec->ec_mute_invert & EC_MUTE_INVERT_TARGET) != 0) :
	    ((ec->ec_mute_invert & EC_MUTE_INVERT_PATH) != 0);

	if (path == NULL || path[0] == '\0')
		return (false);

	LIST_FOREACH(emp, target ? &ec->ec_muted_targets
	    : &ec->ec_muted_paths, emp_link) {
		if (!oes_path_match(emp, path))
			continue;

		/*
		 * Found matching path entry.
		 * If all bitmaps are 0, all events are muted.
		 * Otherwise, check if specific event is in bitmap.
		 */
		if (emp->emp_events[0] == 0 && emp->emp_events[1] == 0 &&
		    emp->emp_events[2] == 0 && emp->emp_events[3] == 0) {
			in_list = true;  /* All events muted */
		} else if (event != 0 && oes_event_in_bitmap(event, emp->emp_events)) {
			in_list = true;  /* Specific event muted */
		} else if (event == 0) {
			in_list = true;  /* Legacy: any mute entry counts */
		}
		break;
	}

	return (inverted ? !in_list : in_list);
}

/*
 * Check if a file is muted by its inode/device token.
 *
 * This is used as a fallback when path resolution fails (e.g., locked vnodes).
 * If the mute entry has a token (from resolving the path at mute time), and
 * the event's file has matching ino/dev, the file is considered muted.
 */
bool
oes_client_is_token_muted(struct oes_client *ec, uint64_t ino, uint64_t dev,
    bool target, oes_event_type_t event)
{
	struct oes_mute_path_entry *emp;
	bool in_list = false;
	bool inverted;

	EC_LOCK_ASSERT(ec);

	inverted = target ?
	    ((ec->ec_mute_invert & EC_MUTE_INVERT_TARGET) != 0) :
	    ((ec->ec_mute_invert & EC_MUTE_INVERT_PATH) != 0);

	if (ino == 0 && dev == 0)
		return (false);

	LIST_FOREACH(emp, target ? &ec->ec_muted_targets
	    : &ec->ec_muted_paths, emp_link) {
		if (!emp->emp_has_token)
			continue;
		if (emp->emp_ino != ino || emp->emp_dev != dev)
			continue;

		/*
		 * Found matching token entry.
		 * If all bitmaps are 0, all events are muted.
		 * Otherwise, check if specific event is in bitmap.
		 */
		if (emp->emp_events[0] == 0 && emp->emp_events[1] == 0 &&
		    emp->emp_events[2] == 0 && emp->emp_events[3] == 0) {
			in_list = true;  /* All events muted */
		} else if (event != 0 && oes_event_in_bitmap(event, emp->emp_events)) {
			in_list = true;  /* Specific event muted */
		} else if (event == 0) {
			in_list = true;  /* Legacy: any mute entry counts */
		}
		break;
	}

	return (inverted ? !in_list : in_list);
}

int
oes_client_mute(struct oes_client *ec, oes_proc_token_t *token, uint32_t flags)
{
	struct oes_mute_entry *em;
	int error;

	/* Self-mute: set flag AND add entry to list for query consistency */
	if (flags & OES_MUTE_SELF) {
		EC_LOCK(ec);

		/* Check if already in list (use owner_pid to match enforcement) */
		LIST_FOREACH(em,
		    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
		    em_link) {
			if (em->em_pid == ec->ec_owner_pid) {
				/*
				 * Already in list. Upgrade per-event mute
				 * to mute-all by clearing the event bitmap.
				 */
				memset(em->em_events, 0, sizeof(em->em_events));
				ec->ec_flags |= EC_FLAG_MUTED_SELF;
				EC_UNLOCK(ec);
				return (0);
			}
		}

		/* Check limit */
		if (ec->ec_muted_proc_count >= OES_MUTE_PROC_MAX) {
			/* Still set flag even if can't add to list */
			ec->ec_flags |= EC_FLAG_MUTED_SELF;
			EC_UNLOCK(ec);
			return (0);
		}

		/* Add entry for self so GET_MUTED_PROCESSES returns it */
		em = malloc(sizeof(*em), M_OES, M_NOWAIT | M_ZERO);
		if (em == NULL) {
			/* Still set flag even if can't add to list */
			ec->ec_flags |= EC_FLAG_MUTED_SELF;
			EC_UNLOCK(ec);
			return (0);
		}

		em->em_pid = ec->ec_owner_pid;
		em->em_genid = ec->ec_owner_genid;
		/* em_events[] stays zeroed = mute all events */
		LIST_INSERT_HEAD(
		    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
		    em, em_link);
		ec->ec_muted_proc_count++;
		ec->ec_flags |= EC_FLAG_MUTED_SELF;

		EC_UNLOCK(ec);
		OES_DEBUG("client %p self-muted", ec);
		return (0);
	}

	error = oes_client_validate_token(ec, token);
	if (error != 0)
		return (error);

	EC_LOCK(ec);

	/* Check limit */
	if (ec->ec_muted_proc_count >= OES_MUTE_PROC_MAX) {
		EC_UNLOCK(ec);
		return (ENOSPC);
	}

	/* Check if already muted, handling PID reuse */
	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em_link) {
		if (em->em_pid == (pid_t)token->ept_id) {
			if (em->em_genid == token->ept_genid) {
				/*
				 * Same process already muted.  Upgrade
				 * per-event mute to mute-all by clearing
				 * the event bitmap (all-zeros = all events).
				 */
				memset(em->em_events, 0, sizeof(em->em_events));
				EC_UNLOCK(ec);
				return (0);
			}
			/*
			 * PID reused by different process - update entry
			 * with new genid and reset event mask.
			 */
			em->em_genid = token->ept_genid;
			memset(em->em_events, 0, sizeof(em->em_events));
			EC_UNLOCK(ec);
			OES_DEBUG("client %p updated muted pid %d (genid %ju)",
			    ec, em->em_pid, (uintmax_t)em->em_genid);
			return (0);
		}
	}

	/* Add to mute list */
	em = malloc(sizeof(*em), M_OES, M_NOWAIT | M_ZERO);
	if (em == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	em->em_pid = (pid_t)token->ept_id;
	em->em_genid = token->ept_genid;
	/* em_events[] is zeroed by M_ZERO, meaning mute all events */
	LIST_INSERT_HEAD(&ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em, em_link);
	ec->ec_muted_proc_count++;

	EC_UNLOCK(ec);

	OES_DEBUG("client %p muted pid %d", ec, em->em_pid);

	return (0);
}

int
oes_client_mute_path(struct oes_client *ec, const char *path, uint32_t type,
    bool target)
{
	struct oes_mute_path_entry *emp;
	struct oes_mute_path_list *list;
	struct nameidata nd;
	struct vattr va;
	size_t len;
	uint64_t ino = 0, dev = 0;
	bool has_token = false;

	if (path == NULL)
		return (EINVAL);

	len = strnlen(path, MAXPATHLEN);
	if (len == 0 || len >= MAXPATHLEN)
		return (EINVAL);

	if (type != OES_MUTE_PATH_LITERAL && type != OES_MUTE_PATH_PREFIX)
		return (EINVAL);

	/*
	 * Try to resolve the path to get inode/device for token-based
	 * matching. This allows path muting to work even when vnode
	 * path resolution fails (e.g., locked vnodes).
	 * Only attempt for literal full paths (starting with /).
	 */
	if (type == OES_MUTE_PATH_LITERAL && path[0] == '/') {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, path);
		if (namei(&nd) == 0) {
			if (VOP_GETATTR(nd.ni_vp, &va,
			    curthread->td_ucred) == 0) {
				ino = va.va_fileid;
				dev = va.va_fsid;
				has_token = true;
			}
			vput(nd.ni_vp);
			NDFREE_PNBUF(&nd);
		}
	}

	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	/* Check limit */
	if (target) {
		if (ec->ec_muted_target_count >= OES_MUTE_PATH_MAX) {
			EC_UNLOCK(ec);
			return (ENOSPC);
		}
	} else {
		if (ec->ec_muted_path_count >= OES_MUTE_PATH_MAX) {
			EC_UNLOCK(ec);
			return (ENOSPC);
		}
	}

	LIST_FOREACH(emp, list, emp_link) {
		if (emp->emp_type == type && emp->emp_len == len &&
		    memcmp(emp->emp_path, path, len) == 0) {
			/*
			 * Path already muted.  Upgrade per-event mute
			 * to mute-all by clearing the event bitmap.
			 */
			memset(emp->emp_events, 0, sizeof(emp->emp_events));
			EC_UNLOCK(ec);
			return (0);
		}
	}

	emp = malloc(sizeof(*emp), M_OES, M_NOWAIT | M_ZERO);
	if (emp == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	memcpy(emp->emp_path, path, len);
	emp->emp_path[len] = '\0';
	emp->emp_len = len;
	emp->emp_type = type;
	emp->emp_ino = ino;
	emp->emp_dev = dev;
	emp->emp_has_token = has_token;
	LIST_INSERT_HEAD(list, emp, emp_link);
	if (target)
		ec->ec_muted_target_count++;
	else
		ec->ec_muted_path_count++;

	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_unmute_path(struct oes_client *ec, const char *path, uint32_t type,
    bool target)
{
	struct oes_mute_path_entry *emp, *emp_tmp;
	struct oes_mute_path_list *list;
	size_t len;
	int error = ESRCH;

	if (path == NULL)
		return (EINVAL);

	len = strnlen(path, MAXPATHLEN);
	if (len == 0 || len >= MAXPATHLEN)
		return (EINVAL);

	if (type != OES_MUTE_PATH_LITERAL && type != OES_MUTE_PATH_PREFIX)
		return (EINVAL);

	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	LIST_FOREACH_SAFE(emp, list, emp_link, emp_tmp) {
		if (emp->emp_type == type && emp->emp_len == len &&
		    memcmp(emp->emp_path, path, len) == 0) {
			LIST_REMOVE(emp, emp_link);
			free(emp, M_OES);
			if (target)
				ec->ec_muted_target_count--;
			else
				ec->ec_muted_path_count--;
			error = 0;
			break;
		}
	}

	EC_UNLOCK(ec);

	return (error);
}

int
oes_client_unmute(struct oes_client *ec, oes_proc_token_t *token)
{
	struct oes_mute_entry *em, *em_tmp;
	int error;

	if (token == NULL)
		return (EINVAL);
	error = oes_client_validate_token(ec, token);
	if (error != 0)
		return (error);
	error = ESRCH;

	EC_LOCK(ec);

	LIST_FOREACH_SAFE(em, &ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em_link, em_tmp) {
		if (em->em_pid == (pid_t)token->ept_id &&
		    (em->em_genid == 0 || em->em_genid == token->ept_genid)) {
			LIST_REMOVE(em, em_link);
			free(em, M_OES);
			ec->ec_muted_proc_count--;
			error = 0;
			break;
		}
	}

	EC_UNLOCK(ec);

	return (error);
}

int
oes_client_set_mute_invert(struct oes_client *ec, uint32_t type, bool invert)
{
	uint32_t mask;

	switch (type) {
	case OES_MUTE_INVERT_PROCESS:
		mask = EC_MUTE_INVERT_PROCESS;
		break;
	case OES_MUTE_INVERT_PATH:
		mask = EC_MUTE_INVERT_PATH;
		break;
	case OES_MUTE_INVERT_TARGET_PATH:
		mask = EC_MUTE_INVERT_TARGET;
		break;
	default:
		return (EINVAL);
	}

	EC_LOCK(ec);
	if (invert)
		ec->ec_mute_invert |= mask;
	else
		ec->ec_mute_invert &= ~mask;
	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_get_mute_invert(struct oes_client *ec, uint32_t type,
    uint32_t *invert)
{
	uint32_t mask;

	if (invert == NULL)
		return (EINVAL);

	switch (type) {
	case OES_MUTE_INVERT_PROCESS:
		mask = EC_MUTE_INVERT_PROCESS;
		break;
	case OES_MUTE_INVERT_PATH:
		mask = EC_MUTE_INVERT_PATH;
		break;
	case OES_MUTE_INVERT_TARGET_PATH:
		mask = EC_MUTE_INVERT_TARGET;
		break;
	default:
		return (EINVAL);
	}

	EC_LOCK(ec);
	*invert = (ec->ec_mute_invert & mask) != 0;
	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_set_deadline_miss_mode(struct oes_client *ec, uint32_t mode)
{
	if (mode != OES_DEADLINE_MISS_FAIL_OPEN &&
	    mode != OES_DEADLINE_MISS_FAIL_CLOSED)
		return (EINVAL);

	EC_LOCK(ec);
	ec->ec_deadline_miss_mode = mode;
	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_get_deadline_miss_mode(struct oes_client *ec, uint32_t *mode)
{
	if (mode == NULL)
		return (EINVAL);

	EC_LOCK(ec);
	*mode = ec->ec_deadline_miss_mode;
	EC_UNLOCK(ec);

	return (0);
}

void
oes_client_get_stats(struct oes_client *ec, struct oes_stats *stats)
{
	EC_LOCK(ec);

	/* Counters */
	stats->es_events_received = ec->ec_events_received;
	stats->es_events_dropped = ec->ec_events_dropped;
	stats->es_auth_timeouts = ec->ec_auth_timeouts;
	stats->es_auth_allowed = ec->ec_auth_allowed;
	stats->es_auth_denied = ec->ec_auth_denied;
	stats->es_cache_hits = ec->ec_cache_hits;
	stats->es_cache_misses = ec->ec_cache_misses;
	stats->es_cache_evictions = ec->ec_cache_evictions;
	stats->es_cache_expired = ec->ec_cache_expired;

	/* Cache state */
	stats->es_cache_entries = ec->ec_cache_entries;
	stats->es_cache_max = ec->ec_cache_max;

	/* Queue state */
	stats->es_queue_current = ec->ec_queue_count;
	stats->es_queue_max = ec->ec_queue_max;
	stats->es_queue_bytes = ec->ec_queue_bytes;
	stats->es_queue_highwater = ec->ec_queue_highwater;

	/* Global counters */
	stats->es_nosleep_drops = oes_softc.sc_nosleep_drops;
	stats->es_alloc_failures = oes_softc.sc_alloc_failures;

	/* Current configuration */
	stats->es_mode = ec->ec_mode;
	stats->es_default_deadline_ms = ec->ec_default_deadline_ms;
	stats->es_deadline_miss_mode = ec->ec_deadline_miss_mode;
	stats->es_reserved = 0;

	EC_UNLOCK(ec);
}

/* Returns false if any events are invalid (out of range or not AUTH/NOTIFY) */
static bool
oes_events_to_bitmap(const oes_event_type_t *events, size_t count,
    uint64_t bitmap[4])
{
	size_t i;
	bool valid = true;

	bitmap[0] = 0;
	bitmap[1] = 0;
	bitmap[2] = 0;
	bitmap[3] = 0;

	for (i = 0; i < count; i++) {
		oes_event_type_t ev = events[i];
		int bit = ev & 0x0FFF;
		int base, word, shift;

		/* Validate event is a defined enum value */
		if (!oes_event_is_valid(ev)) {
			OES_DEBUG("event type 0x%x is not a defined event",
			    ev);
			valid = false;
			continue;
		}

		/* Validate bit position */
		if (bit >= 128) {
			OES_WARN("event type 0x%x has bit %d >= 128", ev, bit);
			valid = false;
			continue;
		}

		base = OES_EVENT_IS_NOTIFY(ev) ? 2 : 0;
		word = bit / 64;
		shift = bit % 64;
		bitmap[base + word] |= (1ULL << shift);
	}
	return (valid);
}

/* bitmap[0,1]=AUTH, bitmap[2,3]=NOTIFY */
static size_t
oes_bitmap_to_events(const uint64_t bitmap[4], oes_event_type_t *events,
    size_t maxcount)
{
	size_t count = 0;
	int i, j;

	for (j = 0; j < 2 && count < maxcount; j++) {
		uint64_t mask = bitmap[j];
		for (i = 0; i < 64 && count < maxcount; i++) {
			if (mask & (1ULL << i)) {
				events[count++] = (j * 64) + i;
			}
		}
	}

	/* NOTIFY events: bitmap[2,3] -> event types 0x1000-0x107F */
	for (j = 2; j < 4 && count < maxcount; j++) {
		uint64_t mask = bitmap[j];
		for (i = 0; i < 64 && count < maxcount; i++) {
			if (mask & (1ULL << i)) {
				events[count++] = 0x1000 | ((j - 2) * 64) + i;
			}
		}
	}
	return (count);
}

int
oes_client_mute_events(struct oes_client *ec, oes_proc_token_t *token,
    uint32_t flags, const oes_event_type_t *events, size_t count)
{
	struct oes_mute_entry *em;
	uint64_t bitmap[4];
	int error;

	if (count == 0 || count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	if (!oes_events_to_bitmap(events, count, bitmap))
		return (EINVAL);  /* Invalid event type in list */

	/* Self-mute with specific events */
	if (flags & OES_MUTE_SELF) {
		EC_LOCK(ec);

		/* Find existing entry for self (use owner_pid to match enforcement) */
		LIST_FOREACH(em,
		    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
		    em_link) {
			if (em->em_pid == ec->ec_owner_pid) {
				/*
				 * If already mute-all (all zeros), adding
				 * specific events is a no-op.
				 */
				if (em->em_events[0] != 0 ||
				    em->em_events[1] != 0 ||
				    em->em_events[2] != 0 ||
				    em->em_events[3] != 0) {
					/* Add events to existing entry */
					em->em_events[0] |= bitmap[0];
					em->em_events[1] |= bitmap[1];
					em->em_events[2] |= bitmap[2];
					em->em_events[3] |= bitmap[3];
				}
				EC_UNLOCK(ec);
				return (0);
			}
		}

		/* Create new entry for self - check limit first */
		if (ec->ec_muted_proc_count >= OES_MUTE_PROC_MAX) {
			EC_UNLOCK(ec);
			return (ENOSPC);
		}

		em = malloc(sizeof(*em), M_OES, M_NOWAIT | M_ZERO);
		if (em == NULL) {
			EC_UNLOCK(ec);
			return (ENOMEM);
		}

		em->em_pid = ec->ec_owner_pid;
		em->em_genid = ec->ec_owner_genid;
		memcpy(em->em_events, bitmap, sizeof(em->em_events));
		LIST_INSERT_HEAD(
		    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
		    em, em_link);
		ec->ec_muted_proc_count++;

		EC_UNLOCK(ec);
		return (0);
	}

	error = oes_client_validate_token(ec, token);
	if (error != 0)
		return (error);

	EC_LOCK(ec);

	/* Find existing entry or create new one, handling PID reuse */
	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em_link) {
		if (em->em_pid == (pid_t)token->ept_id) {
			if (em->em_genid != token->ept_genid) {
				/*
				 * PID reused by different process - reset
				 * the entry with new genid and bitmap.
				 */
				em->em_genid = token->ept_genid;
				memcpy(em->em_events, bitmap,
				    sizeof(em->em_events));
			} else {
				/*
				 * Same process - add events to existing.
				 * If already mute-all, this is a no-op.
				 */
				if (em->em_events[0] != 0 ||
				    em->em_events[1] != 0 ||
				    em->em_events[2] != 0 ||
				    em->em_events[3] != 0) {
					em->em_events[0] |= bitmap[0];
					em->em_events[1] |= bitmap[1];
					em->em_events[2] |= bitmap[2];
					em->em_events[3] |= bitmap[3];
				}
			}
			EC_UNLOCK(ec);
			return (0);
		}
	}

	/* Create new entry - check limit first */
	if (ec->ec_muted_proc_count >= OES_MUTE_PROC_MAX) {
		EC_UNLOCK(ec);
		return (ENOSPC);
	}

	em = malloc(sizeof(*em), M_OES, M_NOWAIT | M_ZERO);
	if (em == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	em->em_pid = (pid_t)token->ept_id;
	em->em_genid = token->ept_genid;
	memcpy(em->em_events, bitmap, sizeof(em->em_events));
	LIST_INSERT_HEAD(&ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em, em_link);
	ec->ec_muted_proc_count++;

	EC_UNLOCK(ec);
	return (0);
}

int
oes_client_unmute_events(struct oes_client *ec, oes_proc_token_t *token,
    uint32_t flags, const oes_event_type_t *events, size_t count)
{
	struct oes_mute_entry *em;
	uint64_t bitmap[4];
	int error;

	if (count == 0 || count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	if (!oes_events_to_bitmap(events, count, bitmap))
		return (EINVAL);  /* Invalid event type in list */

	/* Self-unmute: clear events from list entry */
	if (flags & OES_MUTE_SELF) {
		struct oes_mute_entry *em_tmp;

		EC_LOCK(ec);

		/* Use owner_pid to match enforcement check */
		LIST_FOREACH_SAFE(em,
		    &ec->ec_muted[oes_mute_proc_bucket(ec->ec_owner_pid)],
		    em_link, em_tmp) {
			if (em->em_pid == ec->ec_owner_pid) {
				/*
				 * If this is a "mute all" entry (all zeros),
				 * convert to explicit all-events first.
				 */
				if (em->em_events[0] == 0 &&
				    em->em_events[1] == 0 &&
				    em->em_events[2] == 0 &&
				    em->em_events[3] == 0) {
					em->em_events[0] = OES_VALID_AUTH_LO;
					em->em_events[1] = OES_VALID_AUTH_HI;
					em->em_events[2] = OES_VALID_NOTIFY_LO;
					em->em_events[3] = OES_VALID_NOTIFY_HI;
				}

				/* Remove events from entry */
				em->em_events[0] &= ~bitmap[0];
				em->em_events[1] &= ~bitmap[1];
				em->em_events[2] &= ~bitmap[2];
				em->em_events[3] &= ~bitmap[3];

				/* If no events left, remove entry and clear flag */
				if (em->em_events[0] == 0 && em->em_events[1] == 0 &&
				    em->em_events[2] == 0 && em->em_events[3] == 0) {
					LIST_REMOVE(em, em_link);
					free(em, M_OES);
					ec->ec_muted_proc_count--;
					ec->ec_flags &= ~EC_FLAG_MUTED_SELF;
				}
				EC_UNLOCK(ec);
				return (0);
			}
		}

		EC_UNLOCK(ec);
		return (ESRCH);  /* No self entry found */
	}

	if (token == NULL)
		return (EINVAL);
	error = oes_client_validate_token(ec, token);
	if (error != 0)
		return (error);

	/* bitmap was already populated at function start */

	EC_LOCK(ec);

	LIST_FOREACH(em, &ec->ec_muted[oes_mute_proc_bucket(token->ept_id)],
	    em_link) {
		if (em->em_pid == (pid_t)token->ept_id &&
		    (em->em_genid == 0 || em->em_genid == token->ept_genid)) {
			/*
			 * If this is a "mute all" entry (all zeros),
			 * convert to explicit all-events first.
			 */
			if (em->em_events[0] == 0 && em->em_events[1] == 0 &&
			    em->em_events[2] == 0 && em->em_events[3] == 0) {
				em->em_events[0] = OES_VALID_AUTH_LO;
				em->em_events[1] = OES_VALID_AUTH_HI;
				em->em_events[2] = OES_VALID_NOTIFY_LO;
				em->em_events[3] = OES_VALID_NOTIFY_HI;
			}

			/* Remove events from entry */
			em->em_events[0] &= ~bitmap[0];
			em->em_events[1] &= ~bitmap[1];
			em->em_events[2] &= ~bitmap[2];
			em->em_events[3] &= ~bitmap[3];

			/* If no events left, remove entry */
			if (em->em_events[0] == 0 && em->em_events[1] == 0 &&
			    em->em_events[2] == 0 && em->em_events[3] == 0) {
				LIST_REMOVE(em, em_link);
				free(em, M_OES);
				ec->ec_muted_proc_count--;
			}
			EC_UNLOCK(ec);
			return (0);
		}
	}

	EC_UNLOCK(ec);
	return (ESRCH);
}

int
oes_client_mute_path_events(struct oes_client *ec, const char *path,
    uint32_t type, bool target, const oes_event_type_t *events, size_t count)
{
	struct oes_mute_path_entry *emp;
	struct oes_mute_path_list *list;
	struct nameidata nd;
	struct vattr va;
	uint64_t bitmap[4];
	uint64_t ino = 0, dev = 0;
	bool has_token = false;
	size_t len;

	if (path == NULL || count == 0 || count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	len = strnlen(path, MAXPATHLEN);
	if (len == 0 || len >= MAXPATHLEN)
		return (EINVAL);

	if (type != OES_MUTE_PATH_LITERAL && type != OES_MUTE_PATH_PREFIX)
		return (EINVAL);

	if (!oes_events_to_bitmap(events, count, bitmap))
		return (EINVAL);  /* Invalid event type in list */

	/*
	 * Try to resolve the path to get inode/device for token-based
	 * matching. This allows path muting to work even when vnode
	 * path resolution fails (e.g., locked vnodes).
	 * Only attempt for literal full paths (starting with /).
	 */
	if (type == OES_MUTE_PATH_LITERAL && path[0] == '/') {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, path);
		if (namei(&nd) == 0) {
			if (VOP_GETATTR(nd.ni_vp, &va,
			    curthread->td_ucred) == 0) {
				ino = va.va_fileid;
				dev = va.va_fsid;
				has_token = true;
			}
			vput(nd.ni_vp);
			NDFREE_PNBUF(&nd);
		}
	}

	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	/* Find existing entry or create new one */
	LIST_FOREACH(emp, list, emp_link) {
		if (emp->emp_type == type && emp->emp_len == len &&
		    memcmp(emp->emp_path, path, len) == 0) {
			/*
			 * If already mute-all (all zeros), adding
			 * specific events is a no-op.
			 */
			if (emp->emp_events[0] != 0 ||
			    emp->emp_events[1] != 0 ||
			    emp->emp_events[2] != 0 ||
			    emp->emp_events[3] != 0) {
				/* Add events to existing entry */
				emp->emp_events[0] |= bitmap[0];
				emp->emp_events[1] |= bitmap[1];
				emp->emp_events[2] |= bitmap[2];
				emp->emp_events[3] |= bitmap[3];
			}
			EC_UNLOCK(ec);
			return (0);
		}
	}

	/* Create new entry - check limit first */
	if (target) {
		if (ec->ec_muted_target_count >= OES_MUTE_PATH_MAX) {
			EC_UNLOCK(ec);
			return (ENOSPC);
		}
	} else {
		if (ec->ec_muted_path_count >= OES_MUTE_PATH_MAX) {
			EC_UNLOCK(ec);
			return (ENOSPC);
		}
	}

	emp = malloc(sizeof(*emp), M_OES, M_NOWAIT | M_ZERO);
	if (emp == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	memcpy(emp->emp_path, path, len);
	emp->emp_path[len] = '\0';
	emp->emp_len = len;
	emp->emp_type = type;
	memcpy(emp->emp_events, bitmap, sizeof(emp->emp_events));
	emp->emp_ino = ino;
	emp->emp_dev = dev;
	emp->emp_has_token = has_token;
	LIST_INSERT_HEAD(list, emp, emp_link);
	if (target)
		ec->ec_muted_target_count++;
	else
		ec->ec_muted_path_count++;

	EC_UNLOCK(ec);
	return (0);
}

int
oes_client_unmute_path_events(struct oes_client *ec, const char *path,
    uint32_t type, bool target, const oes_event_type_t *events, size_t count)
{
	struct oes_mute_path_entry *emp;
	struct oes_mute_path_list *list;
	uint64_t bitmap[4];
	size_t len;

	if (path == NULL || count == 0 || count > OES_MAX_MUTE_EVENTS)
		return (EINVAL);

	len = strnlen(path, MAXPATHLEN);
	if (len == 0 || len >= MAXPATHLEN)
		return (EINVAL);

	if (type != OES_MUTE_PATH_LITERAL && type != OES_MUTE_PATH_PREFIX)
		return (EINVAL);

	if (!oes_events_to_bitmap(events, count, bitmap))
		return (EINVAL);  /* Invalid event type in list */
	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	LIST_FOREACH(emp, list, emp_link) {
		if (emp->emp_type == type && emp->emp_len == len &&
		    memcmp(emp->emp_path, path, len) == 0) {
			/*
			 * If this is a "mute all" entry (all zeros), convert
			 * to explicit all-events before clearing specific ones.
			 */
			if (emp->emp_events[0] == 0 && emp->emp_events[1] == 0 &&
			    emp->emp_events[2] == 0 && emp->emp_events[3] == 0) {
				emp->emp_events[0] = OES_VALID_AUTH_LO;
				emp->emp_events[1] = OES_VALID_AUTH_HI;
				emp->emp_events[2] = OES_VALID_NOTIFY_LO;
				emp->emp_events[3] = OES_VALID_NOTIFY_HI;
			}

			/* Remove events from entry */
			emp->emp_events[0] &= ~bitmap[0];
			emp->emp_events[1] &= ~bitmap[1];
			emp->emp_events[2] &= ~bitmap[2];
			emp->emp_events[3] &= ~bitmap[3];

			/* If no events left, remove entry */
			if (emp->emp_events[0] == 0 && emp->emp_events[1] == 0 &&
			    emp->emp_events[2] == 0 && emp->emp_events[3] == 0) {
				LIST_REMOVE(emp, emp_link);
				free(emp, M_OES);
				if (target)
					ec->ec_muted_target_count--;
				else
					ec->ec_muted_path_count--;
			}
			EC_UNLOCK(ec);
			return (0);
		}
	}

	EC_UNLOCK(ec);
	return (ESRCH);
}

int
oes_client_get_muted_processes(struct oes_client *ec,
    struct oes_muted_process_entry *entries, size_t count, size_t *actual)
{
	struct oes_mute_entry *em;
	size_t i = 0;
	int bucket;

	EC_LOCK(ec);

	/* Iterate all hash buckets to collect all muted processes */
	for (bucket = 0; bucket < OES_MUTE_PROC_BUCKETS; bucket++) {
		LIST_FOREACH(em, &ec->ec_muted[bucket], em_link) {
			if (i < count && entries != NULL) {
				entries[i].emp_token.ept_id = em->em_pid;
				entries[i].emp_token.ept_genid = em->em_genid;

				/* Check if all events muted (all bitmaps zero means all) */
				if (em->em_events[0] == 0 && em->em_events[1] == 0 &&
				    em->em_events[2] == 0 && em->em_events[3] == 0) {
					entries[i].emp_event_count = 0;
				} else {
					entries[i].emp_event_count = oes_bitmap_to_events(
					    em->em_events, entries[i].emp_events,
					    OES_MAX_MUTE_EVENTS);
				}
			}
			i++;
		}
	}

	if (actual != NULL)
		*actual = i;
	EC_UNLOCK(ec);
	return (0);
}

int
oes_client_get_muted_paths(struct oes_client *ec,
    struct oes_muted_path_entry *entries, size_t count, size_t *actual,
    bool target)
{
	struct oes_mute_path_entry *emp;
	struct oes_mute_path_list *list;
	size_t i = 0;

	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	LIST_FOREACH(emp, list, emp_link) {
		if (i < count && entries != NULL) {
			strlcpy(entries[i].emp_path, emp->emp_path,
			    sizeof(entries[i].emp_path));
			entries[i].emp_type = emp->emp_type;
			entries[i].emp_flags = target ? OES_MUTE_PATH_FLAG_TARGET : 0;

			/* Check if all events muted */
			if (emp->emp_events[0] == 0 && emp->emp_events[1] == 0 &&
			    emp->emp_events[2] == 0 && emp->emp_events[3] == 0) {
				entries[i].emp_event_count = 0;
			} else {
				entries[i].emp_event_count = oes_bitmap_to_events(
				    emp->emp_events, entries[i].emp_events,
				    OES_MAX_MUTE_EVENTS);
			}
		}
		i++;
	}

	if (actual != NULL)
		*actual = i;
	EC_UNLOCK(ec);
	return (0);
}

void
oes_client_unmute_all_processes(struct oes_client *ec)
{
	struct oes_mute_entry *em, *em_tmp;
	int i;

	EC_LOCK(ec);

	/* Clear self-mute flag */
	ec->ec_flags &= ~EC_FLAG_MUTED_SELF;

	/* Free all muted process entries from all hash buckets */
	for (i = 0; i < OES_MUTE_PROC_BUCKETS; i++) {
		LIST_FOREACH_SAFE(em, &ec->ec_muted[i], em_link, em_tmp) {
			LIST_REMOVE(em, em_link);
			free(em, M_OES);
		}
	}
	ec->ec_muted_proc_count = 0;

	EC_UNLOCK(ec);
}

void
oes_client_unmute_all_paths(struct oes_client *ec, bool target)
{
	struct oes_mute_path_entry *emp, *emp_tmp;
	struct oes_mute_path_list *list;

	list = target ? &ec->ec_muted_targets : &ec->ec_muted_paths;

	EC_LOCK(ec);

	LIST_FOREACH_SAFE(emp, list, emp_link, emp_tmp) {
		LIST_REMOVE(emp, emp_link);
		free(emp, M_OES);
	}
	if (target)
		ec->ec_muted_target_count = 0;
	else
		ec->ec_muted_path_count = 0;

	EC_UNLOCK(ec);
}

int
oes_client_mute_uid(struct oes_client *ec, uid_t uid)
{
	struct oes_mute_uid_entry *emu;

	EC_LOCK(ec);

	/* Check if already muted */
	LIST_FOREACH(emu, &ec->ec_muted_uids, emu_link) {
		if (emu->emu_uid == uid) {
			EC_UNLOCK(ec);
			return (0);
		}
	}

	/* Check limit */
	if (ec->ec_muted_uid_count >= OES_MUTE_UID_MAX) {
		EC_UNLOCK(ec);
		return (ENOSPC);
	}

	/* Allocate new entry */
	emu = malloc(sizeof(*emu), M_OES, M_NOWAIT | M_ZERO);
	if (emu == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	emu->emu_uid = uid;
	LIST_INSERT_HEAD(&ec->ec_muted_uids, emu, emu_link);
	ec->ec_muted_uid_count++;
	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_unmute_uid(struct oes_client *ec, uid_t uid)
{
	struct oes_mute_uid_entry *emu, *emu_tmp;

	EC_LOCK(ec);

	LIST_FOREACH_SAFE(emu, &ec->ec_muted_uids, emu_link, emu_tmp) {
		if (emu->emu_uid == uid) {
			LIST_REMOVE(emu, emu_link);
			free(emu, M_OES);
			ec->ec_muted_uid_count--;
			EC_UNLOCK(ec);
			return (0);
		}
	}

	EC_UNLOCK(ec);
	return (ESRCH);
}

int
oes_client_mute_gid(struct oes_client *ec, gid_t gid)
{
	struct oes_mute_gid_entry *emg;

	EC_LOCK(ec);

	/* Check if already muted */
	LIST_FOREACH(emg, &ec->ec_muted_gids, emg_link) {
		if (emg->emg_gid == gid) {
			EC_UNLOCK(ec);
			return (0);
		}
	}

	/* Check limit */
	if (ec->ec_muted_gid_count >= OES_MUTE_GID_MAX) {
		EC_UNLOCK(ec);
		return (ENOSPC);
	}

	/* Allocate new entry */
	emg = malloc(sizeof(*emg), M_OES, M_NOWAIT | M_ZERO);
	if (emg == NULL) {
		EC_UNLOCK(ec);
		return (ENOMEM);
	}

	emg->emg_gid = gid;
	LIST_INSERT_HEAD(&ec->ec_muted_gids, emg, emg_link);
	ec->ec_muted_gid_count++;
	EC_UNLOCK(ec);

	return (0);
}

int
oes_client_unmute_gid(struct oes_client *ec, gid_t gid)
{
	struct oes_mute_gid_entry *emg, *emg_tmp;

	EC_LOCK(ec);

	LIST_FOREACH_SAFE(emg, &ec->ec_muted_gids, emg_link, emg_tmp) {
		if (emg->emg_gid == gid) {
			LIST_REMOVE(emg, emg_link);
			free(emg, M_OES);
			ec->ec_muted_gid_count--;
			EC_UNLOCK(ec);
			return (0);
		}
	}

	EC_UNLOCK(ec);
	return (ESRCH);
}

void
oes_client_unmute_all_uids(struct oes_client *ec)
{
	struct oes_mute_uid_entry *emu, *emu_tmp;

	EC_LOCK(ec);
	LIST_FOREACH_SAFE(emu, &ec->ec_muted_uids, emu_link, emu_tmp) {
		LIST_REMOVE(emu, emu_link);
		free(emu, M_OES);
	}
	ec->ec_muted_uid_count = 0;
	EC_UNLOCK(ec);
}

void
oes_client_unmute_all_gids(struct oes_client *ec)
{
	struct oes_mute_gid_entry *emg, *emg_tmp;

	EC_LOCK(ec);
	LIST_FOREACH_SAFE(emg, &ec->ec_muted_gids, emg_link, emg_tmp) {
		LIST_REMOVE(emg, emg_link);
		free(emg, M_OES);
	}
	ec->ec_muted_gid_count = 0;
	EC_UNLOCK(ec);
}

/* Caller must hold EC_LOCK */
bool
oes_client_is_uid_muted(struct oes_client *ec, uid_t uid)
{
	struct oes_mute_uid_entry *emu;

	EC_LOCK_ASSERT(ec);

	LIST_FOREACH(emu, &ec->ec_muted_uids, emu_link) {
		if (emu->emu_uid == uid)
			return (true);
	}
	return (false);
}

/* Caller must hold EC_LOCK */
bool
oes_client_is_gid_muted(struct oes_client *ec, gid_t gid)
{
	struct oes_mute_gid_entry *emg;

	EC_LOCK_ASSERT(ec);

	LIST_FOREACH(emg, &ec->ec_muted_gids, emg_link) {
		if (emg->emg_gid == gid)
			return (true);
	}
	return (false);
}

void
oes_fill_process(oes_process_t *ep, struct proc *p, struct ucred *cred_override,
    struct oes_strtab *st, void *msg_base)
{
	struct ucred *cred;
	struct session *sess;
	struct proc *pptr;
	struct pgrp *pgrp;
	const char *exec_path;
	uint32_t exec_meta_flags;
	int i, ngroups;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	bzero(ep, sizeof(*ep));

	/* Process token: pid + start time for unique identity */
	ep->ep_token.ept_id = p->p_pid;
	ep->ep_token.ept_genid = oes_proc_genid(p);
	if (p->p_stats != NULL) {
		ep->ep_start_sec = p->p_stats->p_start.tv_sec;
		ep->ep_start_usec = p->p_stats->p_start.tv_usec;
	}

	/* Execution ID: same across fork, changes on exec */
	ep->ep_exec_id = oes_proc_get_exec_id(p);

	/* Basic process IDs */
	ep->ep_pid = p->p_pid;
	ep->ep_original_ppid = p->p_oppid;
	ep->ep_num_threads = p->p_numthreads;
	ep->ep_nice = p->p_nice;
	ep->ep_osrel = p->p_osrel;
	ep->ep_fibnum = p->p_fibnum;
	ep->ep_state = (uint32_t)p->p_state + 1;
	ep->ep_meta_flags |= OES_PROC_META_CWD_UNAVAILABLE;

	/*
	 * Parent and pgrp info require proctree_lock. Use sx_try_slock to
	 * avoid lock order violation (proctree_lock > PROC_LOCK). If busy
	 * (rare), fall back to p_oppid for ppid (others stay zeroed).
	 */
	if (sx_try_slock(&proctree_lock)) {
		pptr = p->p_pptr;
		if (pptr != NULL) {
			ep->ep_ppid = pptr->p_pid;
			strlcpy(ep->ep_pcomm, pptr->p_comm,
			    sizeof(ep->ep_pcomm));
		} else
			ep->ep_meta_flags |= OES_PROC_META_PARENT_UNAVAILABLE;
		if (p->p_reaper != NULL)
			ep->ep_reaper_pid = p->p_reaper->p_pid;

		pgrp = p->p_pgrp;
		ep->ep_pgid = (pgrp != NULL) ? pgrp->pg_id : 0;
		sess = (pgrp != NULL) ? pgrp->pg_session : NULL;
		if (sess != NULL) {
			struct tty *tp;
			bool has_ttyvp;

			ep->ep_sid = sess->s_sid;
			SESS_LOCK(sess);
			tp = sess->s_ttyp;
			has_ttyvp = sess->s_ttyvp != NULL;
			if (sess->s_login[0] != '\0')
				strlcpy(ep->ep_login, sess->s_login,
				    sizeof(ep->ep_login));
			SESS_UNLOCK(sess);
			if (tp != NULL && has_ttyvp) {
				ep->ep_flags |= EP_FLAG_CONTROLT;
				strlcpy(ep->ep_tty, tty_devname(tp),
				    sizeof(ep->ep_tty));
			}
		} else
			ep->ep_meta_flags |= OES_PROC_META_SESSION_UNAVAILABLE;
		sx_sunlock(&proctree_lock);
	} else {
		ep->ep_ppid = p->p_oppid;
		ep->ep_meta_flags |= OES_PROC_META_PARENT_UNAVAILABLE |
		    OES_PROC_META_SESSION_UNAVAILABLE;
	}

	/* Credential information */
	cred = (cred_override != NULL) ? cred_override : p->p_ucred;
	if (cred != NULL) {
		ep->ep_uid = cred->cr_uid;
		ep->ep_ruid = cred->cr_ruid;
		ep->ep_suid = cred->cr_svuid;
		ep->ep_gid = cred->cr_gid;
		ep->ep_rgid = cred->cr_rgid;
		ep->ep_sgid = cred->cr_svgid;

		ep->ep_ngroups = cred->cr_ngroups;
		if (cred->cr_ngroups > 16)
			ep->ep_meta_flags |= OES_PROC_META_GROUPS_TRUNCATED;
		ngroups = MIN(cred->cr_ngroups, 16);
		for (i = 0; i < ngroups; i++)
			ep->ep_groups[i] = cred->cr_groups[i];

		/* Jail info - name goes to string table */
		if (jailed(cred)) {
			ep->ep_jid = cred->cr_prison->pr_id;
			ep->ep_flags |= EP_FLAG_JAILED;
			if (st != NULL && msg_base != NULL)
				ep->ep_jailname_off = oes_strtab_add(st,
				    msg_base,
				    cred->cr_prison->pr_hostname);
		}

		if (cred->cr_flags & CRED_FLAG_CAPMODE) {
			ep->ep_flags |= EP_FLAG_CAPMODE;
			ep->ep_cred_flags |= OES_CRED_FLAG_CAPMODE;
		}
		if (cred->cr_loginclass != NULL)
			strlcpy(ep->ep_loginclass, cred->cr_loginclass->lc_name,
			    sizeof(ep->ep_loginclass));

		ep->ep_auid = cred->cr_audit.ai_auid;
		ep->ep_asid = cred->cr_audit.ai_asid;
		ep->ep_audit_mask_success = cred->cr_audit.ai_mask.am_success;
		ep->ep_audit_mask_failure = cred->cr_audit.ai_mask.am_failure;
		ep->ep_audit_term_port = cred->cr_audit.ai_termid.at_port;
		ep->ep_audit_term_type = cred->cr_audit.ai_termid.at_type;
		bcopy(cred->cr_audit.ai_termid.at_addr,
		    ep->ep_audit_term_addr, sizeof(ep->ep_audit_term_addr));
		ep->ep_audit_flags = cred->cr_audit.ai_flags;
	} else
		ep->ep_meta_flags |= OES_PROC_META_CREDENTIALS_UNAVAILABLE;

	/* Command name (inline - always populated, small) */
	strlcpy(ep->ep_comm, p->p_comm, sizeof(ep->ep_comm));

	/* Executable path is cached at successful exec; no VFS lookup is needed. */
	exec_path = oes_proc_get_exec_path(p, &exec_meta_flags);
	if (exec_path != NULL && st != NULL && msg_base != NULL) {
		ep->ep_path_off = oes_strtab_add(st, msg_base, exec_path);
		ep->ep_meta_flags |= exec_meta_flags;
		if (ep->ep_path_off == 0)
			ep->ep_meta_flags |= OES_PROC_META_PATH_TRUNCATED;
	} else if (msg_base != NULL)
		oes_process_mark_path_unavailable(msg_base, ep);

	/* Process flags */
	if (p->p_flag & P_SUGID)
		ep->ep_flags |= (EP_FLAG_SETUID | EP_FLAG_SETGID);
	if (p->p_flag & P_TRACED)
		ep->ep_flags |= EP_FLAG_TRACED;
	if (p->p_flag & P_SYSTEM)
		ep->ep_flags |= EP_FLAG_SYSTEM;
	if (p->p_flag & P_WEXIT)
		ep->ep_flags |= EP_FLAG_WEXIT;
	if (p->p_flag & P_EXEC)
		ep->ep_flags |= EP_FLAG_EXEC;

	/* ABI/Binary type */
	if (p->p_sysent != NULL) {
		ep->ep_abi = p->p_sysent->sv_flags & SV_ABI_MASK;
		if (ep->ep_abi == SV_ABI_LINUX)
			ep->ep_flags |= EP_FLAG_LINUX;
	} else {
		ep->ep_abi = SV_ABI_UNDEF;
	}
}


/*
 * Fill file information structure
 *
 * The cred parameter should be the credential from the MAC hook,
 * not curthread->td_ucred, to ensure correct behavior under
 * credential changes or delegated operations.
 */
void
oes_fill_file(oes_file_t *ef, struct vnode *vp, struct ucred *cred,
    struct oes_strtab *st, void *msg_base)
{
	struct vattr va;
	struct mount *mp;
	int error;

	bzero(ef, sizeof(*ef));

	if (vp == NULL)
		return;

	/* File type from vnode */
	ef->ef_type = oes_vtype_to_eftype(vp->v_type);

	ef->ef_token.eft_id = 0;
	ef->ef_token.eft_dev = 0;

	/* Get vnode attributes using provided credential */
	if (cred != NULL)
		error = VOP_GETATTR(vp, &va, cred);
	else
		error = VOP_GETATTR(vp, &va, curthread->td_ucred);
	if (error == 0) {
		ef->ef_ino = va.va_fileid;
		ef->ef_dev = va.va_fsid;
		ef->ef_size = va.va_size;
		ef->ef_blocks = va.va_bytes / 512;
		ef->ef_allocated_bytes = va.va_bytes;
		ef->ef_block_size = va.va_blocksize;
		ef->ef_generation = va.va_gen;
		ef->ef_rdev = va.va_rdev;
		ef->ef_filerev = va.va_filerev;
		ef->ef_mode = va.va_mode;
		ef->ef_uid = va.va_uid;
		ef->ef_gid = va.va_gid;
		ef->ef_flags = va.va_flags;
		ef->ef_nlink = va.va_nlink;

		ef->ef_atime = va.va_atime.tv_sec;
		ef->ef_mtime = va.va_mtime.tv_sec;
		ef->ef_ctime = va.va_ctime.tv_sec;
		ef->ef_birthtime = va.va_birthtime.tv_sec;
		ef->ef_atime_nsec = va.va_atime.tv_nsec;
		ef->ef_mtime_nsec = va.va_mtime.tv_nsec;
		ef->ef_ctime_nsec = va.va_ctime.tv_nsec;
		ef->ef_birthtime_nsec = va.va_birthtime.tv_nsec;
		ef->ef_vaflags = va.va_vaflags;

		ef->ef_token.eft_id = va.va_fileid;
		ef->ef_token.eft_dev = va.va_fsid;
	} else
		ef->ef_meta_flags |= OES_FILE_META_ATTR_UNAVAILABLE;

	/* Filesystem type (inline - always populated, 16 bytes) */
	mp = vp->v_mount;
	if (mp != NULL && mp->mnt_vfc != NULL)
		strlcpy(ef->ef_fstype, mp->mnt_vfc->vfc_name,
		    sizeof(ef->ef_fstype));
	else
		ef->ef_meta_flags |= OES_FILE_META_FSTYPE_UNAVAILABLE;

	/*
	 * Path lookup: vn_fullpath() can deadlock when called from MAC
	 * hooks that already hold VFS locks. Attempt only when vnode
	 * is not locked; otherwise caller sets ef_path_off via strtab.
	 */
	if (st != NULL && msg_base != NULL && VOP_ISLOCKED(vp) == 0) {
		char *fullpath = NULL;
		char *freepath = NULL;

		if (vn_fullpath(vp, &fullpath, &freepath) == 0 &&
		    fullpath != NULL) {
			ef->ef_path_off = oes_strtab_add(st, msg_base,
			    fullpath);
			if (ef->ef_path_off == 0)
				ef->ef_meta_flags |= OES_FILE_META_PATH_TRUNCATED;
		} else {
			oes_file_mark_path_unavailable(msg_base, ef);
		}
		if (freepath != NULL)
			free(freepath, M_TEMP);
	} else if (st != NULL && msg_base != NULL) {
		oes_file_mark_path_unavailable(msg_base, ef);
	}
}
