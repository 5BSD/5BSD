/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability: generic capability interface for kernel modules.
 * Kernel API — exported for other modules.
 * Taskqueue dispatch, service lifecycle, reply/notify/revoke.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <vm/uma.h>

#include <sys/procdesc.h>

#include "mac_capability_internal.h"
#include "mac_capability_label.h"

extern struct sx proctree_lock;

MALLOC_DECLARE(M_MAC_CAPABILITY);

SDT_PROVIDER_DECLARE(mac_capability);
SDT_PROBE_DECLARE(mac_capability, , , dispatch);
SDT_PROBE_DECLARE(mac_capability, , , dispatch__done);
SDT_PROBE_DECLARE(mac_capability, , , reply);
SDT_PROBE_DECLARE(mac_capability, , , reply__done);
SDT_PROBE_DECLARE(mac_capability, , , notify);
SDT_PROBE_DECLARE(mac_capability, , , notify__done);
SDT_PROBE_DECLARE(mac_capability, , , forward);
SDT_PROBE_DECLARE(mac_capability, , , forward__done);
SDT_PROBE_DECLARE(mac_capability, , , revoke);
SDT_PROBE_DECLARE(mac_capability, , , revoke__done);
SDT_PROBE_DECLARE(mac_capability, , , instance__finalize);
SDT_PROBE_DECLARE(mac_capability, , , state);
SDT_PROBE_DECLARE(mac_capability, , , service__create);
SDT_PROBE_DECLARE(mac_capability, , , service__destroy);
SDT_PROBE_DECLARE(mac_capability, , , queue__pressure);

/*
 * Resolve target process: attached procdesc or self.
 * On success, returns with PROC_LOCK held and _PHOLD active.
 * Caller must PROC_UNLOCK and _PRELE.
 */
int
mac_capability_resolve_proc(struct file **fds, int nfds, struct proc **pp)
{
	struct procdesc *pd;
	struct proc *p;

	if (nfds == 0 || fds == NULL || fds[0] == NULL) {
		/* Self */
		p = curthread->td_proc;
		PROC_LOCK(p);
		_PHOLD(p);
		*pp = p;
		return (0);
	}

	if (fds[0]->f_type != DTYPE_PROCDESC)
		return (EINVAL);

	pd = fds[0]->f_data;

	sx_slock(&proctree_lock);
	p = pd->pd_proc;
	if (p == NULL) {
		sx_sunlock(&proctree_lock);
		return (ESRCH);
	}
	PROC_LOCK(p);
	if (p->p_flag & P_WEXIT) {
		PROC_UNLOCK(p);
		sx_sunlock(&proctree_lock);
		return (ESRCH);
	}
	_PHOLD(p);
	sx_sunlock(&proctree_lock);

	*pp = p;
	return (0);
}

void
mac_capability_instance_drain_txq(struct mac_capability_instance *s)
{
	struct mac_capability_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_txq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_txq, cm_link);
		s->ci_txqlen--;
		mac_capability_msg_free(msg);
	}
}

void
mac_capability_instance_drain_rxq(struct mac_capability_instance *s)
{
	struct mac_capability_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_rxq, cm_link);
		s->ci_rxqlen--;
		mac_capability_msg_free(msg);
	}
}

/*
 * Enqueue a message on an instance's TX queue.  Caller must hold ci_mtx.
 *
 * If 'force' is true the message bypasses the soft limit (used by
 * mac_capability_reply) but is still subject to the hard limit.  If false,
 * the enqueue is rejected with EAGAIN when the queue exceeds the
 * soft limit (used by mac_capability_notify).
 *
 * Hard limit: prevents a client that never reads from growing
 * kernel memory without bound.  Set to 4× queue_depth.
 */
static int
mac_capability_instance_enqueue_tx(struct mac_capability_instance *s, struct mac_capability_msg *msg,
    bool force)
{
	int hard_limit;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	if ((s->ci_flags & MAC_CAPABILITY_SF_DEAD) || s->ci_service == NULL) {
		mac_capability_msg_free(msg);
		return (ECONNRESET);
	}
	hard_limit = (int)s->ci_service->csvc_queue_depth * MAC_CAPABILITY_TX_HARD_MULT;
	if (!force && s->ci_txqlen >= (int)s->ci_service->csvc_tx_limit) {
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    s->ci_service->csvc_name, s->ci_badge, "tx-soft",
		    s->ci_txqlen, (int)s->ci_service->csvc_tx_limit);
		mac_capability_msg_free(msg);
		return (EAGAIN);
	}
	if (s->ci_txqlen >= hard_limit) {
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    s->ci_service->csvc_name, s->ci_badge, "tx-hard",
		    s->ci_txqlen, hard_limit);
		mac_capability_msg_free(msg);
		return (ENOBUFS);
	}
	STAILQ_INSERT_TAIL(&s->ci_txq, msg, cm_link);
	s->ci_txqlen++;
	KNOTE_LOCKED(&s->ci_rknotes, 0);
	wakeup(&s->ci_txq);
	return (0);
}

/*
 * Allocate a TX message with data, optional fds, and optional fcaps.
 * Called from mac_capability_reply() and mac_capability_notify() in sleeping context (M_WAITOK).
 * If fcaps is non-NULL, each entry is copied so the receiver gets the
 * sender's Capsicum rights.  NULL = full rights (kernel-minted fds).
 * Returns NULL if fhold() fails on a racing close.
 */
static struct mac_capability_msg *
mac_capability_msg_alloc_full(const void *data, size_t datalen,
    struct file * const *fds, const struct filecaps *fcaps,
    const uint8_t *xfer_state, int nfds,
    uint64_t badge, uint64_t reply_token, struct ucred *cred)
{
	struct mac_capability_msg *msg;
	int i;

	if (datalen > MAC_CAPABILITY_MSG_PAYLOAD_SIZE)
		return (NULL);
	KASSERT(nfds <= MAC_CAPABILITY_MAX_FDS,
	    ("%s: nfds %d > MAC_CAPABILITY_MAX_FDS", __func__, nfds));

	msg = uma_zalloc(mac_capability_msg_zone, M_WAITOK | M_ZERO);

	if (datalen > 0 && data != NULL) {
		memcpy(msg->cm_data, data, datalen);
		msg->cm_datalen = datalen;
	}

	if (nfds > 0 && fds != NULL) {
		for (i = 0; i < nfds; i++) {
			if (!fhold(fds[i])) {
				SDT_PROBE5(mac_capability, , , queue__pressure,
				    "<msg>", (uint64_t)0, "fhold-failed",
				    i, nfds);
				while (--i >= 0)
					fdrop(msg->cm_fds[i], curthread);
				msg->cm_nfds = 0;
				uma_zfree(mac_capability_msg_zone, msg);
				return (NULL);
			}
			msg->cm_fds[i] = fds[i];
		}
		msg->cm_nfds = nfds;

		if (fcaps != NULL) {
			for (i = 0; i < nfds; i++)
				filecaps_copy(&fcaps[i],
				    &msg->cm_fcaps[i], true);
		}
		if (xfer_state != NULL)
			memcpy(msg->cm_xfer_state, xfer_state,
			    nfds * sizeof(uint8_t));
	}

	msg->cm_badge = badge;
	msg->cm_reply_token = reply_token;
	if (cred != NULL)
		msg->cm_cred = crhold(cred);

	return (msg);
}

static struct mac_capability_msg *
mac_capability_msg_alloc(const void *data, size_t datalen,
    struct file * const *fds, const struct filecaps *fcaps, int nfds)
{

	return (mac_capability_msg_alloc_full(data, datalen, fds, fcaps, NULL, nfds,
	    0, 0, NULL));
}

/*
 * Auto-reply: enqueue an error when handler returns nonzero.
 * Runs in taskqueue context (may sleep).
 */
static void
mac_capability_auto_reply(struct mac_capability_instance *s, uint64_t reply_token, int error)
{
	struct mac_capability_msg *msg;
	uint32_t err32;
	int tx_error;

	msg = uma_zalloc(mac_capability_msg_zone, M_WAITOK | M_ZERO);
	err32 = (uint32_t)(error != 0 ? error : EIO);
	memcpy(msg->cm_data, &err32, sizeof(err32));
	msg->cm_datalen = sizeof(err32);
	msg->cm_reply_token = reply_token;

	mtx_lock(&s->ci_mtx);
	tx_error = mac_capability_instance_enqueue_tx(s, msg, true);
	mtx_unlock(&s->ci_mtx);
	if (tx_error != 0 && s->ci_service != NULL)
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    s->ci_service->csvc_name, s->ci_badge, "auto-reply-drop",
		    s->ci_txqlen, 0);
}

/*
 * Taskqueue dispatch — dequeue from RX, call handler.
 *
 * Each service has a taskqueue with up to min(ncpus, 4) threads.  Each
 * instance has its own struct task and ci_dispatching latch.  FreeBSD's
 * taskqueue permits a running task to be enqueued and picked up by another
 * worker, so the latch -- not the taskqueue itself -- provides per-instance
 * handler serialization while retaining cross-instance parallelism.
 */
void
mac_capability_dispatch_task(void *context, int pending __unused)
{
	struct mac_capability_instance *s = context;
	struct mac_capability_service *svc;
	struct mac_capability_msg *msg;
	sbintime_t start __unused;
	int error;

	svc = s->ci_service;
	if (svc == NULL)
		return;

	/*
	 * Hold a reference for the duration of this task.  Close waits
	 * for refcount to reach 1 after taskqueue_drain, so this
	 * guarantees the instance isn't freed while we're running — even
	 * if ci_inflight drops to 0 during self-revoke finalization.
	 */
	mac_capability_instance_hold(s);

	mtx_lock(&s->ci_mtx);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		if (s->ci_flags & MAC_CAPABILITY_SF_DEAD)
			break;

		STAILQ_REMOVE_HEAD(&s->ci_rxq, cm_link);
		s->ci_rxqlen--;
		s->ci_inflight++;

		/* Notify EVFILT_WRITE — SENDMSG can retry. */
		KNOTE_LOCKED(&s->ci_wknotes, 0);
		s->ci_handler_td = curthread;
		mtx_unlock(&s->ci_mtx);

		/*
		 * Call handler — no locks held, may sleep.
		 * Return 0: message consumed.  If the handler called
		 *     mac_capability_reply(), the client gets a response.  If not,
		 *     there is no reply — the client's next read blocks
		 *     until something else arrives (e.g. a notification).
		 * Return nonzero: automatic error reply sent to client.
		 */
		SDT_PROBE2(mac_capability, , , dispatch,
		    svc->csvc_name, msg->cm_badge);
		start = getsbinuptime();
		error = svc->csvc_ops->co_handler(s, msg, svc->csvc_arg);
		SDT_PROBE4(mac_capability, , , dispatch__done,
		    svc->csvc_name, msg->cm_badge, error,
		    getsbinuptime() - start);

		if (error != 0)
			mac_capability_auto_reply(s, msg->cm_reply_token, error);

		mac_capability_msg_free(msg);

		mtx_lock(&s->ci_mtx);
		s->ci_handler_td = NULL;
		s->ci_inflight--;
		if (s->ci_inflight == 0 && (s->ci_flags & MAC_CAPABILITY_SF_DEAD)) {
			wakeup(&s->ci_inflight);
			/* Wake service destroy loop waiting on svc. */
			wakeup(svc);
			/*
			 * If self-revoke set REVOKED during this handler,
			 * fire co_revoke now that the handler is done.
			 */
			if ((s->ci_flags & MAC_CAPABILITY_SF_REVOKED) &&
			    !(s->ci_flags & MAC_CAPABILITY_SF_FINALIZED)) {
				/*
				 * Wait for deferred work first.  Our own
				 * hold adds 1, so wait for refcnt <= 2.
				 */
				while (refcount_load(&s->ci_refcnt) > 2) {
					mtx_unlock(&s->ci_mtx);
					tsleep(s, 0, "mac_capabilitysr", MAC_CAPABILITY_POLL_TICKS);
					mtx_lock(&s->ci_mtx);
				}
				s->ci_flags |= MAC_CAPABILITY_SF_FINALIZED;
				mtx_unlock(&s->ci_mtx);
				if (svc->csvc_ops->co_revoke != NULL)
					svc->csvc_ops->co_revoke(s,
					    s->ci_badge,
					    MAC_CAPABILITY_REVOKE_BY_SERVICE,
					    svc->csvc_arg);
				mtx_lock(&s->ci_mtx);
			}
		}
	}

	/* If dead, drain any remaining RX messages. */
	if (s->ci_flags & MAC_CAPABILITY_SF_DEAD)
		mac_capability_instance_drain_rxq(s);
	s->ci_dispatching = false;

	mtx_unlock(&s->ci_mtx);
	mac_capability_instance_rele(s);
}

int
mac_capability_service_create(const struct mac_capability_service_params *p,
    struct mac_capability_service **svcp)
{
	struct mac_capability_service *svc;
	uint32_t queue_depth, instance_limit;

	if (p == NULL || p->name == NULL || p->name[0] == '\0')
		return (EINVAL);
	if (strlen(p->name) >= MAC_CAPABILITY_MAXNAME)
		return (ENAMETOOLONG);
	if (p->ops == NULL)
		return (EINVAL);
	if (p->ops->co_handler == NULL && p->ops->co_call == NULL)
		return (EINVAL);

	queue_depth = p->queue_depth > 0 ? p->queue_depth :
	    MAC_CAPABILITY_MAX_QUEUED;
	if (queue_depth > MAC_CAPABILITY_MAX_QUEUE_DEPTH)
		return (EINVAL);
	instance_limit = p->instance_limit > 0 ? p->instance_limit :
	    MAC_CAPABILITY_DEF_INSTANCE_LIMIT;
	if (instance_limit > MAC_CAPABILITY_MAX_INSTANCES)
		return (EINVAL);

	svc = malloc(sizeof(*svc), M_MAC_CAPABILITY, M_WAITOK | M_ZERO);
	strlcpy(svc->csvc_name, p->name, sizeof(svc->csvc_name));
	svc->csvc_ops = p->ops;
	svc->csvc_arg = p->arg;
	svc->csvc_instance_limit = instance_limit;
	svc->csvc_tx_limit = p->tx_limit > 0 ? p->tx_limit :
	    MAC_CAPABILITY_MAX_QUEUED;
	if (svc->csvc_tx_limit > MAC_CAPABILITY_MAX_TX_LIMIT)
		svc->csvc_tx_limit = MAC_CAPABILITY_MAX_TX_LIMIT;
	svc->csvc_queue_depth = queue_depth;
	svc->csvc_svc_flags = p->flags;
	LIST_INIT(&svc->csvc_instances);
	refcount_init(&svc->csvc_refcnt, 1);

	/* Only create a taskqueue if the service accepts async SENDMSG. */
	if (p->ops->co_handler != NULL) {
		svc->csvc_taskq = taskqueue_create("mac_capability_svc", M_WAITOK,
		    taskqueue_thread_enqueue, &svc->csvc_taskq);
		taskqueue_start_threads(&svc->csvc_taskq,
		    MIN(mp_ncpus, MAC_CAPABILITY_MAX_SVC_THREADS), PWAIT,
		    "mac_capability_%s", p->name);
	}

	sx_xlock(&mac_capability_registry_lock);
	if (mac_capability_service_lookup(p->name) != NULL) {
		SDT_PROBE5(mac_capability, , , queue__pressure,
		    p->name, (uint64_t)0, "service-duplicate",
		    0, 0);
		sx_xunlock(&mac_capability_registry_lock);
		if (svc->csvc_taskq != NULL)
			taskqueue_free(svc->csvc_taskq);
		free(svc, M_MAC_CAPABILITY);
		return (EEXIST);
	}
	LIST_INSERT_HEAD(&mac_capability_services, svc, csvc_link);
	counter_u64_add(mac_capability_stat_services, 1);
	sx_xunlock(&mac_capability_registry_lock);

	*svcp = svc;
	SDT_PROBE5(mac_capability, , , service__create, svc->csvc_name,
	    svc->csvc_svc_flags, svc->csvc_queue_depth, svc->csvc_tx_limit,
	    svc->csvc_instance_limit);
	return (0);
}

/*
 * Internal revoke with reason — shared by mac_capability_instance_revoke()
 * and mac_capability_service_destroy().
 */
static void
mac_capability_instance_revoke_reason(struct mac_capability_instance *s,
    enum mac_capability_revoke_reason reason)
{
	struct mac_capability_service *svc = s->ci_service;
	sbintime_t start __unused;

	start = getsbinuptime();
	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & MAC_CAPABILITY_SF_DEAD) {
		mtx_unlock(&s->ci_mtx);
		goto out;
	}
	s->ci_flags |= MAC_CAPABILITY_SF_REVOKED;
	mac_capability_instance_drain_rxq(s);
	/* Do NOT drain the TX queue here — let the receiver read
	 * already-queued messages before seeing ECONNRESET. */

	wakeup(&s->ci_txq);
	KNOTE_LOCKED(&s->ci_rknotes, 0);
	KNOTE_LOCKED(&s->ci_wknotes, 0);

	/*
	 * If the current thread IS the handler (self-revoke from
	 * co_handler), don't wait — the handler is still on the stack.
	 * The dispatch loop or close path fires co_revoke later.
	 */
	if (s->ci_handler_td == curthread) {
		mtx_unlock(&s->ci_mtx);
		goto out;
	}

	/* Wait for in-flight handlers and calls. */
	while (s->ci_inflight > 0)
		msleep(&s->ci_inflight, &s->ci_mtx, 0, "mac_capabilityrev", 0);

	/*
	 * If the refcount is > 1, someone else still holds the instance
	 * (e.g., the terminate collection loop or userspace).  Defer
	 * co_revoke to the close path — it will fire after the last
	 * holder releases.
	 */
	if (refcount_load(&s->ci_refcnt) > 1) {
		mtx_unlock(&s->ci_mtx);
		goto out;
	}

	/* Guard: co_revoke fires exactly once. */
	if (s->ci_flags & MAC_CAPABILITY_SF_FINALIZED) {
		mtx_unlock(&s->ci_mtx);
		goto out;
	}
	s->ci_flags |= MAC_CAPABILITY_SF_FINALIZED;
	mtx_unlock(&s->ci_mtx);

	if (svc != NULL) {
		SDT_PROBE6(mac_capability, , , instance__finalize,
		    svc->csvc_name, s->ci_badge, reason,
		    curthread->td_proc->p_pid, curthread->td_ucred,
		    mac_capability_proc_nonce(curthread->td_ucred));
		SDT_PROBE6(mac_capability, , , state, svc->csvc_name, s->ci_badge,
		    s->ci_flags, s->ci_restricted, curthread->td_proc->p_pid,
		    mac_capability_proc_nonce(curthread->td_ucred));
	}
	if (svc != NULL && svc->csvc_ops->co_revoke != NULL)
		svc->csvc_ops->co_revoke(s, s->ci_badge, reason,
		    svc->csvc_arg);

out:
	if (svc != NULL) {
		SDT_PROBE4(mac_capability, , , revoke__done, svc->csvc_name,
		    s->ci_badge, reason, getsbinuptime() - start);
	}
}

/*
 * Free a service struct.  Called when the last reference drops —
 * either from destroy (if no instances remain) or from the last
 * instance's close.
 */
void
mac_capability_service_free(struct mac_capability_service *svc)
{

	if (svc->csvc_taskq != NULL)
		taskqueue_free(svc->csvc_taskq);
	free(svc, M_MAC_CAPABILITY);
}

void
mac_capability_service_destroy(struct mac_capability_service *svc)
{
	struct mac_capability_instance *s;
	bool need_revoke;

	SDT_PROBE2(mac_capability, , , service__destroy, svc->csvc_name,
	    svc->csvc_svc_flags);

	/*
	 * Mark destroying and revoke all instances under xlock.
	 * We do NOT call co_revoke here yet — the force-finalize
	 * pass below handles that after handlers have drained.
	 * We just set REVOKED, drain queues, and wake blocked
	 * readers so userspace sees ECONNRESET.
	 *
	 * Holding xlock prevents concurrent close from removing a
	 * instance out from under us.
	 */
	sx_xlock(&mac_capability_registry_lock);
	svc->csvc_flags |= MAC_CAPABILITY_SVCF_DESTROYING;
	LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
		mtx_lock(&s->ci_mtx);
		if (!(s->ci_flags & MAC_CAPABILITY_SF_DEAD)) {
			s->ci_flags |= MAC_CAPABILITY_SF_REVOKED;
			mac_capability_instance_drain_rxq(s);
			mac_capability_instance_drain_txq(s);
			wakeup(&s->ci_txq);
			KNOTE_LOCKED(&s->ci_rknotes, 0);
			KNOTE_LOCKED(&s->ci_wknotes, 0);
		}
		mtx_unlock(&s->ci_mtx);
	}
	sx_xunlock(&mac_capability_registry_lock);

	/* Wait for all in-flight async handlers to complete. */
	if (svc->csvc_taskq != NULL)
		taskqueue_drain_all(svc->csvc_taskq);

	/*
	 * Wait for in-flight sync calls to complete.  co_call runs in
	 * the caller's thread, not the taskqueue.  ci_inflight tracks
	 * both handlers and calls.  After taskqueue drain, any remaining
	 * inflight count is from concurrent co_call invocations.
	 */
	{
		bool busy;
		do {
			busy = false;
			sx_slock(&mac_capability_registry_lock);
			LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
				mtx_lock(&s->ci_mtx);
				if (s->ci_inflight > 0)
					busy = true;
				mtx_unlock(&s->ci_mtx);
				if (busy)
					break;
			}
			sx_sunlock(&mac_capability_registry_lock);
			if (busy)
				tsleep(svc, 0, "mac_capabilitysyn", MAC_CAPABILITY_POLL_TICKS);
		} while (busy);
	}

	/* Remove from registry. */
	sx_xlock(&mac_capability_registry_lock);
	LIST_REMOVE(svc, csvc_link);
	counter_u64_add(mac_capability_stat_services, -1);
	sx_xunlock(&mac_capability_registry_lock);

	/*
	 * Force-finalize all instances still on the service list.
	 * After taskqueue_drain_all, no handlers are running.
	 * For each instance: set FINALIZED and fire co_revoke.
	 * This must happen before destroy returns because the
	 * consumer module is about to unload — co_revoke's
	 * function pointer will become stale.
	 *
	 * We do NOT unlink instances or release reservation refs
	 * here.  Close handles that.  If close races, it checks
	 * FINALIZED under ci_mtx and skips co_revoke.
	 *
	 * Scan from the list head each time: find the first
	 * instance that isn't FINALIZED, mark it, hold a ref,
	 * drop xlock, fire co_revoke, release ref, repeat.
	 * O(N²) worst case, but N is small and this only runs
	 * during module unload.
	 */
	for (;;) {
		sx_xlock(&mac_capability_registry_lock);
		LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
			mtx_lock(&s->ci_mtx);
			need_revoke =
			    !(s->ci_flags & MAC_CAPABILITY_SF_FINALIZED);
			if (need_revoke) {
				s->ci_flags |= MAC_CAPABILITY_SF_FINALIZED;
				mac_capability_instance_hold(s);
				mtx_unlock(&s->ci_mtx);
				break;
			}
			mtx_unlock(&s->ci_mtx);
		}
		sx_xunlock(&mac_capability_registry_lock);

		if (s == NULL)
			break;

		SDT_PROBE6(mac_capability, , , instance__finalize,
		    svc->csvc_name, s->ci_badge, MAC_CAPABILITY_REVOKE_UNLOAD,
		    curthread->td_proc->p_pid, curthread->td_ucred,
		    mac_capability_proc_nonce(curthread->td_ucred));
		SDT_PROBE6(mac_capability, , , state, svc->csvc_name, s->ci_badge,
		    s->ci_flags, s->ci_restricted, curthread->td_proc->p_pid,
		    mac_capability_proc_nonce(curthread->td_ucred));
		if (svc->csvc_ops->co_revoke != NULL)
			svc->csvc_ops->co_revoke(s, s->ci_badge,
			    MAC_CAPABILITY_REVOKE_UNLOAD, svc->csvc_arg);
		mac_capability_instance_rele(s);
	}

	/*
	 * Release our initial refcount (from service_create).
	 * Each instance still holds a reservation ref, and close
	 * acquires an additional ref — so the service struct
	 * stays alive until the last close frees it.  If all
	 * instances already closed, we are the last ref.
	 */
	if (refcount_release(&svc->csvc_refcnt))
		mac_capability_service_free(svc);
}

int
mac_capability_reply(struct mac_capability_instance *s, uint64_t reply_token,
    const void *out, size_t outlen,
    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds)
{
	struct mac_capability_msg *msg;
	sbintime_t start;
	int error;

	start = getsbinuptime();
	if (outlen > MAC_CAPABILITY_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (out_nfds < 0 || out_nfds > MAC_CAPABILITY_MAX_FDS)
		return (EINVAL);
	if (outlen > 0 && out == NULL)
		return (EINVAL);
	if (out_nfds > 0 && out_fds == NULL)
		return (EINVAL);

	msg = mac_capability_msg_alloc(out, outlen, out_fds, out_fcaps, out_nfds);
	if (msg == NULL) {
		error = out_nfds > 0 ? EBADF : ENOMEM;
		goto done;
	}

	msg->cm_reply_token = reply_token;
	/* cm_badge, cm_cred intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = mac_capability_instance_enqueue_tx(s, msg, true);
	mtx_unlock(&s->ci_mtx);

done:
	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(mac_capability, , , reply,
		    s->ci_service->csvc_name, s->ci_badge, outlen);
	if (s->ci_service != NULL) {
		SDT_PROBE5(mac_capability, , , reply__done, s->ci_service->csvc_name,
		    s->ci_badge, outlen, error, getsbinuptime() - start);
	}

	return (error);
}

int
mac_capability_notify(struct mac_capability_instance *s, const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds)
{
	struct mac_capability_msg *msg;
	sbintime_t start;
	int error;

	start = getsbinuptime();
	if (datalen > MAC_CAPABILITY_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (nfds < 0 || nfds > MAC_CAPABILITY_MAX_FDS)
		return (EINVAL);
	if (datalen > 0 && data == NULL)
		return (EINVAL);
	if (nfds > 0 && fds == NULL)
		return (EINVAL);

	msg = mac_capability_msg_alloc(data, datalen, fds, fcaps, nfds);
	if (msg == NULL) {
		error = nfds > 0 ? EBADF : ENOMEM;
		goto done;
	}
	/* cm_badge, cm_cred intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = mac_capability_instance_enqueue_tx(s, msg, false);
	mtx_unlock(&s->ci_mtx);

done:
	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(mac_capability, , , notify,
		    s->ci_service->csvc_name, s->ci_badge, datalen);
	if (s->ci_service != NULL) {
		SDT_PROBE5(mac_capability, , , notify__done, s->ci_service->csvc_name,
		    s->ci_badge, datalen, error, getsbinuptime() - start);
	}

	return (error);
}

int
mac_capability_forward(struct mac_capability_instance *s, const struct mac_capability_msg *src)
{
	struct mac_capability_msg *msg;
	sbintime_t start __unused;
	int error;

	start = getsbinuptime();
	if (s->ci_service != NULL)
		SDT_PROBE3(mac_capability, , , forward,
		    s->ci_service->csvc_name, s->ci_badge, src->cm_datalen);

	msg = mac_capability_msg_alloc_full(src->cm_data, src->cm_datalen,
	    src->cm_fds, src->cm_fcaps, src->cm_xfer_state, src->cm_nfds,
	    src->cm_badge, src->cm_reply_token, src->cm_cred);
	if (msg == NULL)
		return (src->cm_nfds > 0 ? EBADF : ENOMEM);
	if (src->cm_nfds > 0) {
		memcpy(msg->cm_cloexec_state, src->cm_cloexec_state,
		    src->cm_nfds * sizeof(uint8_t));
		memcpy(msg->cm_clofork_state, src->cm_clofork_state,
		    src->cm_nfds * sizeof(uint8_t));
	}

	mtx_lock(&s->ci_mtx);
	error = mac_capability_instance_enqueue_tx(s, msg, false);
	mtx_unlock(&s->ci_mtx);

	if (s->ci_service != NULL)
		SDT_PROBE5(mac_capability, , , forward__done,
		    s->ci_service->csvc_name, s->ci_badge,
		    src->cm_datalen, error, getsbinuptime() - start);

	return (error);
}

void
mac_capability_instance_revoke(struct mac_capability_instance *s)
{

	if (s->ci_service != NULL)
		SDT_PROBE3(mac_capability, , , revoke,
		    s->ci_service->csvc_name, s->ci_badge,
		    MAC_CAPABILITY_REVOKE_BY_SERVICE);
	mac_capability_instance_revoke_reason(s, MAC_CAPABILITY_REVOKE_BY_SERVICE);
}

void
mac_capability_instance_hold(struct mac_capability_instance *s)
{

	refcount_acquire(&s->ci_refcnt);
}

void
mac_capability_instance_rele(struct mac_capability_instance *s)
{
	bool last;

	last = refcount_release(&s->ci_refcnt);
	/* Wake close/revoke only when refcnt might have reached their threshold. */
	if (!last && refcount_load(&s->ci_refcnt) <= 2)
		wakeup(s);
}

void
mac_capability_instance_set_priv(struct mac_capability_instance *s, void *priv)
{

	s->ci_priv = priv;
}

void *
mac_capability_instance_get_priv(struct mac_capability_instance *s)
{

	return (s->ci_priv);
}

uint64_t
mac_capability_instance_get_badge(struct mac_capability_instance *s)
{

	return (s->ci_badge);
}


const void *
mac_capability_msg_data(const struct mac_capability_msg *msg)
{
	return (msg->cm_data);
}

size_t
mac_capability_msg_datalen(const struct mac_capability_msg *msg)
{
	return (msg->cm_datalen);
}

struct file **
mac_capability_msg_fds(const struct mac_capability_msg *msg)
{
	return (__DECONST(struct file **, msg->cm_fds));
}

struct filecaps *
mac_capability_msg_fcaps(const struct mac_capability_msg *msg)
{
	return (__DECONST(struct filecaps *, msg->cm_fcaps));
}

int
mac_capability_msg_nfds(const struct mac_capability_msg *msg)
{
	return (msg->cm_nfds);
}

uint64_t
mac_capability_msg_badge(const struct mac_capability_msg *msg)
{
	return (msg->cm_badge);
}

uint64_t
mac_capability_msg_token(const struct mac_capability_msg *msg)
{
	return (msg->cm_reply_token);
}

struct ucred *
mac_capability_msg_cred(const struct mac_capability_msg *msg)
{
	return (msg->cm_cred);
}
