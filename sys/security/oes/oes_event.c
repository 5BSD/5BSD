/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Event Generation and Dispatch
 */

#include "opt_mac_capability.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/jail.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/sdt.h>
#include <machine/atomic.h>
#include <vm/uma.h>

#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

#ifdef MAC_CAPABILITY_TEST_PERMISSIVE
/* Test kernels only: mac_capability_testissuer.c. */
extern volatile u_int mac_capability_test_issuer_oes_trylock_fail;

/* Is p the subject a test asked to fill without its lock? */
static bool
oes_test_trylock_fail(struct proc *p)
{
	u_int pid;

	pid = atomic_load_int(&mac_capability_test_issuer_oes_trylock_fail);
	return (pid != 0 && (pid_t)pid == p->p_pid);
}
#endif

MALLOC_DECLARE(M_OES);

/*
 * Provision once at client open; signal hooks may not ask VM for memory.
 * OES cannot unload, so keep this bounded reserve for the rest of the boot.
 * No reserve pages or recurring refill work are needed before the first open.
 */
#define OES_SIGNAL_RESERVE 128
static uma_zone_t oes_signal_zone;
static struct sx oes_signal_init_lock;
SX_SYSINIT(oes_signal_init, &oes_signal_init_lock, "oes signal reserve");

void
oes_signal_reserve_prepare(void)
{
	uma_zone_t zone;

	if (atomic_load_acq_ptr((uintptr_t *)&oes_signal_zone) != 0)
		return;
	sx_xlock(&oes_signal_init_lock);
	if (oes_signal_zone == NULL) {
		zone = uma_zcreate("oes signal", offsetof(struct oes_pending,
		    ep_msg) + OES_MSG_MAX_SIZE, NULL, NULL, NULL, NULL,
		    UMA_ALIGN_PTR, UMA_ZONE_NOFREE | UMA_ZONE_NOBUCKET);
		uma_zone_set_max(zone, OES_SIGNAL_RESERVE);
		/* set_max() recalculates caches, overriding UMA_ZONE_NOBUCKET. */
		uma_zone_set_maxcache(zone, 0);
		uma_prealloc(zone, OES_SIGNAL_RESERVE);
		atomic_store_rel_ptr((uintptr_t *)&oes_signal_zone,
		    (uintptr_t)zone);
	}
	sx_xunlock(&oes_signal_init_lock);
}

static struct oes_pending *oes_pending_init(struct oes_pending *,
    oes_event_type_t, struct proc *);

/* proctree_lock stabilizes proc_realparent() while ancestry is captured. */
extern struct sx proctree_lock;

/*
 * DTrace SDT provider for OES
 *
 * Probes:
 *   oes:::auth-allow(event, pid, path)     - AUTH event allowed
 *   oes:::auth-deny(event, pid, path)      - AUTH event denied
 *   oes:::auth-timeout(event, pid, action) - AUTH event timed out
 *   oes:::event-enqueue(event, pid, client_id) - Event queued for client
 *   oes:::event-drop(event, pid, client_id) - Event dropped (queue full)
 *   oes:::cache-hit(event, pid, result)    - Decision cache hit
 *   oes:::cache-miss(event, pid)           - Decision cache miss
 *
 * Example usage:
 *   dtrace -n 'oes:::auth-deny { printf("%s pid=%d", execname, arg1); }'
 */
SDT_PROVIDER_DEFINE(oes);
SDT_PROBE_DEFINE2(oes, , , wait__start, "uintptr_t", "size_t");
SDT_PROBE_DEFINE2(oes, , , wait__done, "uintptr_t", "int");

SDT_PROBE_DEFINE3(oes, , , auth__allow,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(oes, , , auth__deny,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "const char *");		/* path (if applicable) */

SDT_PROBE_DEFINE3(oes, , , auth__timeout,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "oes_auth_result_t");	/* default action taken */

SDT_PROBE_DEFINE3(oes, , , event__enqueue,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(oes, , , event__drop,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "uint64_t");		/* client ID */

SDT_PROBE_DEFINE3(oes, , , cache__hit,
    "oes_event_type_t",		/* event type */
    "pid_t",			/* process ID */
    "oes_auth_result_t");	/* cached result */

SDT_PROBE_DEFINE2(oes, , , cache__miss,
    "oes_event_type_t",		/* event type */
    "pid_t");			/* process ID */

/*
 * oes_event_is_valid - Validate that an event type is a defined enum value.
 * Moved out of header to avoid duplicating 100+ lines per translation unit.
 */
bool
oes_event_is_valid(oes_event_type_t ev)
{
	if (OES_EVENT_IS_AUTH(ev)) {
#define OES_EVENT_CASE(name, value) case name:
		switch (ev) {
		OES_AUTH_EVENT_LIST(OES_EVENT_CASE)
			return (true);
		default:
			return (false);
		}
#undef OES_EVENT_CASE
	}

	switch (ev) {
#define OES_EVENT_CASE(name, value) case name:
		OES_NOTIFY_EVENT_LIST(OES_EVENT_CASE)
			return (true);
		default:
			return (false);
		}
#undef OES_EVENT_CASE
}

/*
 * AUTH → NOTIFY event mapping table.
 */
static const oes_event_type_t oes_auth_notify_map[] = {
#define OES_AUTH_NOTIFY_ENTRY(auth_event, notify_event) \
	[auth_event] = notify_event,
	OES_AUTH_NOTIFY_EVENT_LIST(OES_AUTH_NOTIFY_ENTRY)
#undef OES_AUTH_NOTIFY_ENTRY
};

oes_event_type_t
oes_auth_to_notify(oes_event_type_t auth_event)
{
	u_int idx = (u_int)auth_event;

	if (idx < nitems(oes_auth_notify_map))
		return (oes_auth_notify_map[idx]);
	return (0);
}

/*
 * String table helpers.
 *
 * The string table lives immediately after sizeof(oes_message_t) in the
 * same allocation as oes_pending.  Offsets are relative to the start
 * of oes_message_t so userspace can use oes_msg_string(msg, off).
 */
void
oes_strtab_init(struct oes_strtab *st)
{
	st->st_off = sizeof(oes_message_t);
	st->st_max = OES_MSG_MAX_SIZE;
}

uint32_t
oes_strtab_add(struct oes_strtab *st, void *msg_base, const char *str)
{
	size_t len;
	uint32_t off;

	if (str == NULL || str[0] == '\0')
		return (0);

	len = strlen(str) + 1;
	if (st->st_off + len > st->st_max) {
		if (msg_base != NULL)
			((oes_message_t *)msg_base)->em_flags |=
			    OES_MSG_FLAG_STRINGS_TRUNCATED;
		return (0);
	}

	off = st->st_off;
	memcpy((char *)msg_base + off, str, len);
	st->st_off += len;
	return (off);
}

/*
 * Add raw data (e.g., NUL-separated argv) to the string table.
 * Returns offset or 0 on overflow.
 */
uint32_t
oes_strtab_add_buf(struct oes_strtab *st, void *msg_base,
    const void *data, size_t len)
{
	uint32_t off;

	if (data == NULL || len == 0)
		return (0);

	if (st->st_off + len > st->st_max) {
		if (msg_base != NULL)
			((oes_message_t *)msg_base)->em_flags |=
			    OES_MSG_FLAG_STRINGS_TRUNCATED;
		return (0);
	}

	off = st->st_off;
	memcpy((char *)msg_base + off, data, len);
	st->st_off += len;
	return (off);
}

struct oes_auth_group {
	struct mtx	ag_mtx;
	struct cv	ag_cv;
	uint32_t	ag_pending;
	bool		ag_denied;
	int		ag_refcount;
};

struct oes_auth_group *
oes_auth_group_alloc(int mflags)
{
	struct oes_auth_group *ag;

	ag = malloc(sizeof(*ag), M_OES, mflags | M_ZERO);
	if (ag == NULL)
		return (NULL);

	mtx_init(&ag->ag_mtx, "oes_auth_group", NULL, MTX_DEF);
	cv_init(&ag->ag_cv, "oes_auth_group");
	ag->ag_refcount = 1;

	return (ag);
}

void
oes_auth_group_hold(struct oes_auth_group *ag)
{
	if (ag == NULL)
		return;
	atomic_add_int(&ag->ag_refcount, 1);
}

void
oes_auth_group_rele(struct oes_auth_group *ag)
{
	if (ag == NULL)
		return;
	if (atomic_fetchadd_int(&ag->ag_refcount, -1) == 1) {
		cv_destroy(&ag->ag_cv);
		mtx_destroy(&ag->ag_mtx);
		free(ag, M_OES);
	}
}

void
oes_auth_group_add_pending(struct oes_auth_group *ag)
{
	mtx_lock(&ag->ag_mtx);
	ag->ag_pending++;
	mtx_unlock(&ag->ag_mtx);
}

void
oes_auth_group_cancel_pending(struct oes_auth_group *ag)
{
	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

void
oes_auth_group_mark_response(struct oes_auth_group *ag,
    oes_auth_result_t result)
{
	mtx_lock(&ag->ag_mtx);
	if (ag->ag_pending > 0)
		ag->ag_pending--;
	if (result == OES_AUTH_DENY)
		ag->ag_denied = true;
	cv_broadcast(&ag->ag_cv);
	mtx_unlock(&ag->ag_mtx);
}

static void
oes_auth_group_update_timeouts(struct oes_auth_group *ag,
    struct oes_pending **eps, size_t count)
{
	struct timespec now;
	size_t i;

	nanouptime(&now);

	for (i = 0; i < count; i++) {
		struct oes_pending *ep = eps[i];
		oes_auth_result_t action;
		bool responded;

		if (ep == NULL)
			continue;

		mtx_lock(&ep->ep_mtx);
		responded = ep->ep_responded;
		action = ep->ep_deadline_miss_mode ==
		    OES_DEADLINE_MISS_FAIL_CLOSED ? OES_AUTH_DENY :
		    OES_AUTH_ALLOW;
		if (!responded &&
		    timespeccmp(&now, &ep->ep_deadline, >=)) {
			ep->ep_responded = true;
			ep->ep_result = action;
			ep->ep_flags |= EP_FLAG_EXPIRED;
			mtx_unlock(&ep->ep_mtx);

			SDT_PROBE3(oes, , , auth__timeout,
			    ep->ep_msg.em_event,
			    ep->ep_msg.em_process.ep_pid,
			    action);

			oes_auth_group_mark_response(ag, action);
			oes_event_handle_timeout(ep);
			continue;
		}
		mtx_unlock(&ep->ep_mtx);
	}
}

int
oes_auth_group_wait(struct oes_auth_group *ag, struct oes_pending **eps,
    size_t count)
{
	struct timespec next_deadline;
	bool have_deadline;
	size_t i;
	bool denied = false;

	SDT_PROBE2(oes, , , wait__start, (uintptr_t)ag, count);
	for (;;) {
		oes_auth_group_update_timeouts(ag, eps, count);

		mtx_lock(&ag->ag_mtx);
		if (ag->ag_pending == 0) {
			denied = ag->ag_denied;
			mtx_unlock(&ag->ag_mtx);
			break;
		}
		mtx_unlock(&ag->ag_mtx);

		have_deadline = false;
		for (i = 0; i < count; i++) {
			struct oes_pending *ep = eps[i];
			bool responded;

			if (ep == NULL)
				continue;

			mtx_lock(&ep->ep_mtx);
			responded = ep->ep_responded;
			if (!responded) {
				if (!have_deadline ||
				    timespeccmp(&ep->ep_deadline,
				    &next_deadline, <)) {
					next_deadline = ep->ep_deadline;
					have_deadline = true;
				}
			}
			mtx_unlock(&ep->ep_mtx);
		}

		if (!have_deadline)
			continue;

		mtx_lock(&ag->ag_mtx);
		if (ag->ag_pending == 0) {
			denied = ag->ag_denied;
			mtx_unlock(&ag->ag_mtx);
			break;
		}
		cv_timedwait_sbt(&ag->ag_cv, &ag->ag_mtx,
		    tstosbt(next_deadline), SBT_1MS, C_ABSOLUTE);
		mtx_unlock(&ag->ag_mtx);
	}

	SDT_PROBE2(oes, , , wait__done, (uintptr_t)ag,
	    (denied ? EACCES : 0));
	return (denied ? EACCES : 0);
}

void
oes_set_auth_deadline(struct oes_pending *ep, uint32_t deadline_ms)
{
	struct timespec ts;
	struct timespec deadline;

	if (deadline_ms == 0)
		deadline_ms = OES_DEFAULT_DEADLINE_MS;

	nanouptime(&deadline);
	ts.tv_sec = deadline_ms / 1000;
	ts.tv_nsec = (deadline_ms % 1000) * 1000000;
	timespecadd(&deadline, &ts, &deadline);

	ep->ep_deadline = deadline;
	ep->ep_msg.em_deadline.tv_sec = deadline.tv_sec;
	ep->ep_msg.em_deadline.tv_nsec = deadline.tv_nsec;
}

/*
 * Allocate a pending event with room for the string table.
 *
 * The allocation extends past ep_msg by (OES_MSG_MAX_SIZE - sizeof(oes_message_t))
 * bytes.  The caller fills event data and appends strings via the strtab,
 * then calls oes_pending_seal() to finalize em_size.
 */
struct oes_pending *
oes_pending_alloc(oes_event_type_t event, struct proc *p)
{
	struct oes_pending *ep;
	size_t alloc_size;

	/*
	 * Allocate the fixed pending metadata + max message size.
	 * The string table area extends past sizeof(oes_message_t).
	 */
	alloc_size = offsetof(struct oes_pending, ep_msg) + OES_MSG_MAX_SIZE;
	ep = malloc(alloc_size, M_OES, M_NOWAIT | M_ZERO);
	if (ep == NULL) {
		/*
		 * An excluded subject allocates only to invalidate cached
		 * decisions and is never reported (base exclusion).
		 */
		if (!oes_proc_excluded(p))
			oes_event_lost_unsent(event);
		return (NULL);
	}
	return (oes_pending_init(ep, event, p));
}

/*
 * The exit event of p, filled under p's process lock: oes_pending_init()
 * only tries for the lock and without it leaves the credential fields zero.
 * The buffer is allocated and zeroed before the lock is taken.  *xexitp
 * gets p_xexit, read under the same hold.
 */
struct oes_pending *
oes_pending_alloc_exit(struct proc *p, int *xexitp)
{
	struct oes_pending *ep;
	size_t alloc_size;

	alloc_size = offsetof(struct oes_pending, ep_msg) + OES_MSG_MAX_SIZE;
	ep = malloc(alloc_size, M_OES, M_NOWAIT | M_ZERO);
	if (ep == NULL) {
		oes_event_lost_unsent(OES_EVENT_NOTIFY_EXIT);
		return (NULL);
	}
	PROC_LOCK(p);
	*xexitp = p->p_xexit;
	ep = oes_pending_init(ep, OES_EVENT_NOTIFY_EXIT, p);
	PROC_UNLOCK(p);
	return (ep);
}

struct oes_pending *
oes_pending_alloc_signal(struct proc *p)
{
	struct oes_pending *ep;
	uma_zone_t zone;

	zone = (uma_zone_t)atomic_load_acq_ptr((uintptr_t *)&oes_signal_zone);
	/* The bounded reserve is shared across all memory domains. */
	ep = zone != NULL ? uma_zalloc(zone,
	    M_NOWAIT | M_NOVM | M_USE_RESERVE | M_ZERO) : NULL;
	if (ep == NULL) {
		atomic_add_64(&oes_softc.sc_alloc_failures, 1);
		oes_event_lost_unsent(OES_EVENT_NOTIFY_SIGNAL);
		return (NULL);
	}
	ep->ep_flags = EP_FLAG_SIGNAL_RESERVE;
	return (oes_pending_init(ep, OES_EVENT_NOTIFY_SIGNAL, p));
}

static struct oes_pending *
oes_pending_init(struct oes_pending *ep, oes_event_type_t event, struct proc *p)
{
	struct oes_strtab st;

	ep->ep_refcount = 1;
	ep->ep_msg.em_version = OES_MESSAGE_VERSION;
	ep->ep_msg.em_size = sizeof(oes_message_t); /* minimum, grown by strtab */
	ep->ep_msg.em_struct_size = sizeof(oes_message_t);

	/* Assign unique message ID */
	ep->ep_msg.em_id = atomic_fetchadd_64(&oes_softc.sc_next_msg_id, 1);

	ep->ep_msg.em_event = event;

	if (OES_EVENT_IS_AUTH(event)) {
		ep->ep_msg.em_action = OES_ACTION_AUTH;
		ep->ep_flags |= EP_FLAG_AUTH;
		mtx_init(&ep->ep_mtx, "oes_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "oes_auth");
		ep->ep_responded = false;
		ep->ep_result = OES_AUTH_ALLOW;
	} else {
		ep->ep_msg.em_action = OES_ACTION_NOTIFY;
	}

	ep->ep_group = NULL;
	oes_scope_snapshot(ep);
	if (__predict_false(atomic_load_int(&oes_softc.sc_njail) != 0)) {
		/*
		 * The subject is the thread running the hook.  Its credential
		 * keeps the prison in place now; the event may be delivered
		 * after the thread is gone, so it takes its own reference.
		 */
		ep->ep_subject_pr = curthread->td_ucred->cr_prison;
		if (ep->ep_subject_pr != &prison0)
			prison_hold(ep->ep_subject_pr);
	}
	{
		struct timespec now, wall_now;

		nanouptime(&now);
		nanotime(&wall_now);
		ep->ep_msg.em_time.tv_sec = now.tv_sec;
		ep->ep_msg.em_time.tv_nsec = now.tv_nsec;
		ep->ep_msg.em_wall_time.tv_sec = wall_now.tv_sec;
		ep->ep_msg.em_wall_time.tv_nsec = wall_now.tv_nsec;
	}
	if (p != NULL && curthread != NULL && curthread->td_proc == p) {
		ep->ep_msg.em_thread.et_id = curthread->td_tid;
		ep->ep_msg.em_thread.et_flags = OES_THREAD_META_PRESENT;
		strlcpy(ep->ep_msg.em_thread.et_name, curthread->td_name,
		    sizeof(ep->ep_msg.em_thread.et_name));
	}

	/* Fill process info, appending paths to string table */
	oes_strtab_init(&st);
	if (p != NULL) {
		bool owned = mtx_owned(&p->p_mtx);
		bool locked = owned;

		if (!owned)
			locked = mtx_trylock(&p->p_mtx);
#ifdef MAC_CAPABILITY_TEST_PERMISSIVE
		if (locked && !owned && oes_test_trylock_fail(p)) {
			PROC_UNLOCK(p);
			locked = false;
		}
#endif
		if (locked) {
			oes_fill_process(&ep->ep_msg.em_process, p, NULL,
			    &st, &ep->ep_msg);
			if (!owned)
				PROC_UNLOCK(p);
		} else {
			/* Best-effort: fill what we can without the lock */
			ep->ep_msg.em_process.ep_pid = p->p_pid;
			ep->ep_msg.em_process.ep_token.ept_id = p->p_pid;
			/*
			 * The identity a client's reader set matches on
			 * (oes_client_is_reader()) must not depend on the
			 * trylock: genid needs no lock, and the subject's
			 * execution is its thread's own credential.
			 */
			ep->ep_msg.em_process.ep_token.ept_genid =
			    oes_proc_genid_unlocked(p);
			if (curthread->td_proc == p)
				ep->ep_msg.em_process.ep_exec_id =
				    oes_cred_get_exec_id(curthread->td_ucred);
			strlcpy(ep->ep_msg.em_process.ep_comm, p->p_comm,
			    sizeof(ep->ep_msg.em_process.ep_comm));
			oes_process_mark_path_unavailable(&ep->ep_msg,
			    &ep->ep_msg.em_process);
		}
	}
	ep->ep_msg.em_size = OES_MSG_ALIGNED(st.st_off);

	return (ep);
}

/*
 * Record the jail of a NOTIFY event's target process, for clients that
 * asked for inbound events.  The hook must hold the target's process lock;
 * if it does not, the target is simply not recorded.  AUTH events never
 * record a target: only the subject of an operation may be made to wait.
 */
void
oes_pending_set_target_prison(struct oes_pending *ep, struct proc *target)
{
	struct prison *pr;

	if (ep->ep_subject_pr == NULL || ep->ep_target_pr != NULL ||
	    target == NULL || OES_EVENT_IS_AUTH(ep->ep_msg.em_event) ||
	    !mtx_owned(&target->p_mtx) || target->p_ucred == NULL)
		return;
	pr = target->p_ucred->cr_prison;
	if (pr == ep->ep_subject_pr)
		return;
	if (pr != &prison0)
		prison_hold(pr);
	ep->ep_target_pr = pr;
}

/*
 * The event for the deferred queue, in an allocation of its actual size:
 * built events take OES_MSG_MAX_SIZE of message space whatever they
 * hold.  The copy takes over ep's prison references, which deferred jail
 * matching needs (oes_pending_clone() leaves them behind); ep keeps the
 * rest and is released by its owner as before.  A signal-reserve event
 * is copied without asking VM for memory (M_NOVM, its hook's rule), so
 * its reserve item returns to the reserve as soon as the hook is done
 * rather than staying queued.  NULL, and ep untouched, for a message
 * that fills OES_MSG_MAX_SIZE or when no memory is free at once.
 */
struct oes_pending *
oes_pending_compact(struct oes_pending *ep)
{
	struct oes_pending *cep;
	size_t msg_size, alloc_size;
	int mflags;

	KASSERT((ep->ep_flags & EP_FLAG_AUTH) == 0,
	    ("oes_pending_compact: AUTH event %#x", ep->ep_msg.em_event));
	KASSERT(ep->ep_refcount == 1,
	    ("oes_pending_compact: shared event, refcount %d",
	    ep->ep_refcount));
	KASSERT(ep->ep_group == NULL,
	    ("oes_pending_compact: NOTIFY event with an AUTH group"));
	msg_size = MAX(ep->ep_msg.em_size, sizeof(oes_message_t));
	if (msg_size >= OES_MSG_MAX_SIZE)
		return (NULL);
	alloc_size = offsetof(struct oes_pending, ep_msg) + msg_size;
	mflags = M_NOWAIT;
	if ((ep->ep_flags & EP_FLAG_SIGNAL_RESERVE) != 0)
		mflags |= M_NOVM;
	cep = malloc(alloc_size, M_OES, mflags);
	if (cep == NULL)
		return (NULL);
	/* A NOTIFY event: no lock, condition variable or group to carry. */
	memcpy(cep, ep, alloc_size);
	cep->ep_refcount = 1;
	cep->ep_flags &= ~EP_FLAG_SIGNAL_RESERVE;
	ep->ep_subject_pr = NULL;
	ep->ep_target_pr = NULL;
	return (cep);
}

/*
 * The memory a queued event holds: what the allocator gave it, or the
 * signal reserve's item.
 */
u_long
oes_pending_charge(const struct oes_pending *ep)
{

	if ((ep->ep_flags & EP_FLAG_SIGNAL_RESERVE) != 0)
		return (offsetof(struct oes_pending, ep_msg) +
		    OES_MSG_MAX_SIZE);
	return (malloc_usable_size(ep));
}

struct oes_pending *
oes_pending_clone(const struct oes_pending *src, int mflags)
{
	struct oes_pending *ep;
	size_t msg_size, alloc_size;

	if (src == NULL)
		return (NULL);

	/* Only allocate enough for the actual message (header + strings) */
	msg_size = src->ep_msg.em_size;
	if (msg_size < sizeof(oes_message_t))
		msg_size = sizeof(oes_message_t);
	alloc_size = offsetof(struct oes_pending, ep_msg) + msg_size;

	ep = malloc(alloc_size, M_OES, mflags | M_ZERO);
	if (ep == NULL)
		return (NULL);

	ep->ep_refcount = 1;
	ep->ep_flags = src->ep_flags & (EP_FLAG_AUTH | EP_FLAG_FAIL_OPEN);
	bcopy(&src->ep_msg, &ep->ep_msg, msg_size);
	ep->ep_msg.em_deadline = (oes_timespec_t){ 0 };
	ep->ep_deadline = (struct timespec){ 0 };
	ep->ep_group = NULL;
	ep->ep_scope_count = src->ep_scope_count;
	memcpy(ep->ep_scope_markers, src->ep_scope_markers,
	    sizeof(ep->ep_scope_markers));
	/* ep_subject_pr and ep_target_pr stay NULL: clones hold no prison. */

	if (ep->ep_flags & EP_FLAG_AUTH) {
		mtx_init(&ep->ep_mtx, "oes_pending", NULL, MTX_DEF);
		cv_init(&ep->ep_cv, "oes_auth");
		ep->ep_responded = false;
		ep->ep_result = OES_AUTH_ALLOW;
	}

	return (ep);
}

void
oes_pending_free(struct oes_pending *ep)
{
	if (ep->ep_flags & EP_FLAG_AUTH) {
		cv_destroy(&ep->ep_cv);
		mtx_destroy(&ep->ep_mtx);
	}

	if (ep->ep_subject_pr != NULL && ep->ep_subject_pr != &prison0)
		prison_free(ep->ep_subject_pr);
	if (ep->ep_target_pr != NULL && ep->ep_target_pr != &prison0)
		prison_free(ep->ep_target_pr);

	if (ep->ep_group != NULL)
		oes_auth_group_rele(ep->ep_group);

	if ((ep->ep_flags & EP_FLAG_SIGNAL_RESERVE) != 0)
		uma_zfree(oes_signal_zone, ep);
	else
		free(ep, M_OES);
}

void
oes_pending_hold(struct oes_pending *ep)
{
	atomic_add_int(&ep->ep_refcount, 1);
}

void
oes_pending_rele(struct oes_pending *ep)
{
	if (atomic_fetchadd_int(&ep->ep_refcount, -1) == 1)
		oes_pending_free(ep);
}

static void
oes_event_advance_sequences(struct oes_client *ec, oes_event_type_t event,
    uint64_t *seq_num, uint64_t *global_seq_num)
{
	uint32_t event_class, event_index;

	EC_LOCK_ASSERT(ec);
	event_index = event & 0x0fff;
	event_class = OES_EVENT_IS_NOTIFY(event) ? 1 : 0;
	*global_seq_num = ++ec->ec_global_seq_num;
	*seq_num = 0;
	if (event_index < nitems(ec->ec_event_seq[event_class]))
		*seq_num = ++ec->ec_event_seq[event_class][event_index];
}

void
oes_event_note_drop(struct oes_client *ec, oes_event_type_t event)
{
	uint64_t seq_num, global_seq_num;

	EC_LOCK_ASSERT(ec);
	oes_event_advance_sequences(ec, event, &seq_num, &global_seq_num);
	ec->ec_events_dropped++;
	/* The queue may be empty: wake readers for the marker. */
	ec->ec_lost_queue++;
	selwakeup(&ec->ec_selinfo);
	KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
	wakeup(&ec->ec_pending);
}

/*
 * An event no client was sent: refused at the deferred-delivery bound
 * (oes_mac.c oes_deliver_notify_nosleep()) or not allocated.  The code
 * that loses it may not be able to take the locks that matching it to
 * clients needs (a NOSLEEP hook cannot), so it is counted by its type,
 * and each client credits itself (oes_client_lost_fold()).  The delivery
 * task wakes the clients (oes_lost_announce()); sc_lost_kick enqueues it
 * once per announcement rather than once per loss.  The kick is read
 * after the total is advanced and the task clears it before it reads
 * the total, each with a full fence between, so either the task sees
 * this loss or this loss sees the kick clear and enqueues the task.
 */
void
oes_event_lost_unsent(oes_event_type_t event)
{
	u_int idx;

	idx = event & 0x0fff;
	if (idx < OES_EVENT_INDEX_COUNT)
		atomic_add_64(&oes_softc.sc_lost[OES_EVENT_IS_NOTIFY(event) ?
		    1 : 0][idx], 1);
	atomic_add_rel_64(&oes_softc.sc_lost_total, 1);
	atomic_thread_fence_seq_cst();
	if (oes_softc.sc_defer_tq != NULL &&
	    atomic_load_int(&oes_softc.sc_lost_kick) == 0 &&
	    atomic_cmpset_int(&oes_softc.sc_lost_kick, 0, 1))
		taskqueue_enqueue(oes_softc.sc_defer_tq,
		    &oes_softc.sc_defer_task);
}

/* Is ec subscribed to an event of class cls and index idx, as delivered? */
static bool
oes_client_lost_subscribed(struct oes_client *ec, u_int cls, u_int idx)
{
	oes_event_type_t notify;

	if (cls == 1)
		return (oes_client_subscribed(ec,
		    (oes_event_type_t)(0x1000 | idx)));
	/* An AUTH event reaches subscribers of its NOTIFY form as well. */
	if (oes_client_subscribed(ec, (oes_event_type_t)idx))
		return (true);
	notify = oes_auth_to_notify((oes_event_type_t)idx);
	return (notify != 0 && oes_client_subscribed(ec, notify));
}

/*
 * Credit ec with the events no client was sent since its snapshots, for
 * the types it is subscribed to now, and take new snapshots of every
 * type.  Called when the client looks for a marker and, with all, before
 * each subscription change, so a type counts only while subscribed.
 * Matching is by type alone: mutes and scopes are not applied, so a
 * client may be told of an event it would not have received.  The loser
 * advances the per-type count before the total (release), so a total read
 * here (acquire) covers the per-type counts read after it, and a total
 * already seen lets a reader skip the scan.  A subscription change must
 * not skip it: a per-type count advanced before its total would be
 * credited only after the type might have been unsubscribed.
 */
void
oes_client_lost_fold(struct oes_client *ec, bool all)
{
	uint64_t total, n, lost;
	u_int cls, i;

	EC_LOCK_ASSERT(ec);
	total = atomic_load_acq_64(&oes_softc.sc_lost_total);
	if (!all && total == ec->ec_lost_seen_total)
		return;
	lost = 0;
	for (cls = 0; cls < 2; cls++) {
		for (i = 0; i < OES_EVENT_INDEX_COUNT; i++) {
			n = atomic_load_64(&oes_softc.sc_lost[cls][i]);
			if (n == ec->ec_lost_seen[cls][i])
				continue;
			if (oes_client_lost_subscribed(ec, cls, i))
				lost += n - ec->ec_lost_seen[cls][i];
			ec->ec_lost_seen[cls][i] = n;
		}
	}
	ec->ec_lost_seen_total = total;
	ec->ec_lost_unsent += lost;
}

/* Whether a read now returns an OES_EVENT_NOTIFY_LOST marker. */
bool
oes_client_lost_pending(struct oes_client *ec)
{

	EC_LOCK_ASSERT(ec);
	oes_client_lost_fold(ec, false);
	return (ec->ec_lost_queue != 0 || ec->ec_lost_unsent != 0);
}

int
oes_event_enqueue(struct oes_client *ec, struct oes_pending *ep)
{

	EC_LOCK_ASSERT(ec);

	/* Stamp before checking capacity so a queue drop creates a visible gap. */
	oes_event_advance_sequences(ec, ep->ep_msg.em_event,
	    &ep->ep_msg.em_seq_num, &ep->ep_msg.em_global_seq_num);

	if (ec->ec_queue_count >= ec->ec_queue_max) {
		ec->ec_events_dropped++;
		/* Read with the marker first; the full queue is readable. */
		ec->ec_lost_queue++;
		SDT_PROBE3(oes, , , event__drop,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    ec->ec_id);
		return (ENOSPC);
	}

	oes_pending_hold(ep);
	TAILQ_INSERT_TAIL(&ec->ec_pending, ep, ep_link);
	ec->ec_queue_count++;
	ec->ec_queue_bytes += ep->ep_msg.em_size;
	if (ec->ec_queue_count > ec->ec_queue_highwater)
		ec->ec_queue_highwater = ec->ec_queue_count;
	ec->ec_events_received++;

	SDT_PROBE3(oes, , , event__enqueue,
	    ep->ep_msg.em_event,
	    ep->ep_msg.em_process.ep_pid,
	    ec->ec_id);

	selwakeup(&ec->ec_selinfo);
	KNOTE_LOCKED(&ec->ec_selinfo.si_note, 0);
	wakeup(&ec->ec_pending);

	return (0);
}

struct oes_pending *
oes_event_dequeue(struct oes_client *ec)
{
	struct oes_pending *ep;

	EC_LOCK_ASSERT(ec);

	ep = TAILQ_FIRST(&ec->ec_pending);
	if (ep != NULL) {
		TAILQ_REMOVE(&ec->ec_pending, ep, ep_link);
		ec->ec_queue_count--;
		if (ec->ec_queue_bytes >= ep->ep_msg.em_size)
			ec->ec_queue_bytes -= ep->ep_msg.em_size;
		else
			ec->ec_queue_bytes = 0;
		ep->ep_flags |= EP_FLAG_DELIVERED;
	}

	return (ep);
}

/*
 * Internal helper: Respond to an AUTH event
 *
 * If has_flags is true, allowed_flags and denied_flags are stored
 * for flags-based partial authorization.
 */
static int
oes_event_respond_internal(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags,
    bool has_flags)
{
	struct oes_pending *ep;
	int error = ESRCH;
	bool in_delivered = false;

	EC_LOCK(ec);

	/* Find the pending event by message ID */
	TAILQ_FOREACH(ep, &ec->ec_pending, ep_link) {
		if (ep->ep_msg.em_id == msg_id)
			break;
	}

	/* Also check delivered queue */
	if (ep == NULL) {
		TAILQ_FOREACH(ep, &ec->ec_delivered, ep_link) {
			if (ep->ep_msg.em_id == msg_id) {
				in_delivered = true;
				break;
			}
		}
	}

	if (ep != NULL && (ep->ep_flags & EP_FLAG_AUTH)) {
		mtx_lock(&ep->ep_mtx);
		if (has_flags && ep->ep_msg.em_event != OES_EVENT_AUTH_OPEN &&
		    ep->ep_msg.em_event != OES_EVENT_AUTH_MMAP &&
		    ep->ep_msg.em_event != OES_EVENT_AUTH_MPROTECT) {
			mtx_unlock(&ep->ep_mtx);
			EC_UNLOCK(ec);
			if (!cold)
				DTRACE_PROBE3(oes__response__rejected,
				    int, EINVAL, int, has_flags, int, result);
			return (EINVAL);
		}

		if (!ep->ep_responded) {
			ep->ep_responded = true;
			ep->ep_result = result;
			if (has_flags) {
				ep->ep_allowed_flags = allowed_flags;
				ep->ep_denied_flags = denied_flags;
				ep->ep_has_flag_response = true;
				if (!cold)
					DTRACE_PROBE4(oes__auth__flags,
					    int, ep->ep_msg.em_event, int, result,
					    uint32_t, allowed_flags, uint32_t, denied_flags);
			}

			/* Update stats and fire DTrace probes */
			if (result == OES_AUTH_ALLOW) {
				ec->ec_auth_allowed++;
				SDT_PROBE3(oes, , , auth__allow,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    oes_msg_string(&ep->ep_msg,
				    ep->ep_msg.em_process.ep_path_off));
			} else {
				ec->ec_auth_denied++;
				SDT_PROBE3(oes, , , auth__deny,
				    ep->ep_msg.em_event,
				    ep->ep_msg.em_process.ep_pid,
				    oes_msg_string(&ep->ep_msg,
				    ep->ep_msg.em_process.ep_path_off));
			}

			if (ep->ep_group != NULL)
				oes_auth_group_mark_response(ep->ep_group,
				    result);

			cv_broadcast(&ep->ep_cv);
			error = 0;
		} else {
			/* Already responded (timeout or duplicate) */
			error = EALREADY;
		}

		mtx_unlock(&ep->ep_mtx);

		/* Remove from delivered queue and release */
		if (in_delivered && error == 0) {
			TAILQ_REMOVE(&ec->ec_delivered, ep, ep_link);
			oes_pending_rele(ep);
		}
	}

	EC_UNLOCK(ec);

	if (!cold && error != 0)
		DTRACE_PROBE3(oes__response__rejected,
		    int, error, int, has_flags, int, result);
	return (error);
}

int
oes_event_respond(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result)
{
	return (oes_event_respond_internal(ec, msg_id, result, 0, 0, false));
}

/*
 * Respond with flags for partial authorization (e.g., AUTH_OPEN).
 */
int
oes_event_respond_flags(struct oes_client *ec, uint64_t msg_id,
    oes_auth_result_t result, uint32_t allowed_flags, uint32_t denied_flags)
{
	return (oes_event_respond_internal(ec, msg_id, result, allowed_flags,
	    denied_flags, true));
}

void
oes_event_handle_timeout(struct oes_pending *ep)
{
	struct oes_client *ec;
	bool need_rele = false;

	if (ep == NULL || ep->ep_client_id == 0)
		return;

	OES_LOCK();
	LIST_FOREACH(ec, &oes_softc.sc_clients, ec_link) {
		if (ec->ec_id != ep->ep_client_id)
			continue;

		EC_LOCK(ec);
		ec->ec_auth_timeouts++;

		if (ep->ep_flags & EP_FLAG_DELIVERED) {
			/* Remove from delivered queue */
			struct oes_pending *cur;

			TAILQ_FOREACH(cur, &ec->ec_delivered, ep_link) {
				if (cur == ep) {
					TAILQ_REMOVE(&ec->ec_delivered, ep,
					    ep_link);
					need_rele = true;
					break;
				}
			}
		} else {
			/* Remove from pending queue */
			struct oes_pending *cur;

			TAILQ_FOREACH(cur, &ec->ec_pending, ep_link) {
				if (cur == ep) {
					TAILQ_REMOVE(&ec->ec_pending, ep,
					    ep_link);
					ec->ec_queue_count--;
					if (ec->ec_queue_bytes >=
					    ep->ep_msg.em_size)
						ec->ec_queue_bytes -=
						    ep->ep_msg.em_size;
					else
						ec->ec_queue_bytes = 0;
					need_rele = true;
					break;
				}
			}
		}
		EC_UNLOCK(ec);
		break;
	}
	OES_UNLOCK();

	if (need_rele)
		oes_pending_rele(ep);
}
