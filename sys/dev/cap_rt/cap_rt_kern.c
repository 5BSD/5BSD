/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt: generic capability interface for kernel modules.
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

#include "cap_rt_internal.h"

MALLOC_DECLARE(M_CAP_RT);

SDT_PROVIDER_DECLARE(cap_rt);
SDT_PROBE_DECLARE(cap_rt, , , dispatch);
SDT_PROBE_DECLARE(cap_rt, , , dispatch__done);
SDT_PROBE_DECLARE(cap_rt, , , reply);
SDT_PROBE_DECLARE(cap_rt, , , reply__done);
SDT_PROBE_DECLARE(cap_rt, , , notify);
SDT_PROBE_DECLARE(cap_rt, , , notify__done);
SDT_PROBE_DECLARE(cap_rt, , , revoke);
SDT_PROBE_DECLARE(cap_rt, , , revoke__done);
SDT_PROBE_DECLARE(cap_rt, , , queue__pressure);

/* ----------------------------------------------------------------
 * Queue helpers
 * ---------------------------------------------------------------- */

void
cap_rt_instance_drain_txq(struct cap_rt_instance *s)
{
	struct cap_rt_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_txq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_txq, cm_link);
		s->ci_txqlen--;
		cap_rt_msg_free(msg);
	}
}

void
cap_rt_instance_drain_rxq(struct cap_rt_instance *s)
{
	struct cap_rt_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_rxq, cm_link);
		s->ci_rxqlen--;
		cap_rt_msg_free(msg);
	}
}

/*
 * Enqueue a message on an instance's TX queue.  Caller must hold ci_mtx.
 *
 * If 'force' is true the message bypasses the soft limit (used by
 * cap_rt_reply) but is still subject to the hard limit.  If false,
 * the enqueue is rejected with EAGAIN when the queue exceeds the
 * soft limit (used by cap_rt_notify).
 *
 * Hard limit: prevents a client that never reads from growing
 * kernel memory without bound.  Set to 4× queue_depth.
 */
static int
cap_rt_instance_enqueue_tx(struct cap_rt_instance *s, struct cap_rt_msg *msg,
    bool force)
{
	int hard_limit;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	if ((s->ci_flags & CAP_RT_SF_DEAD) || s->ci_service == NULL) {
		cap_rt_msg_free(msg);
		return (ECONNRESET);
	}
	hard_limit = (int)s->ci_service->csvc_queue_depth * CAP_RT_TX_HARD_MULT;
	if (!force && s->ci_txqlen >= (int)s->ci_service->csvc_tx_limit) {
		SDT_PROBE5(cap_rt, , , queue__pressure,
		    s->ci_service->csvc_name, s->ci_badge, "tx-soft",
		    s->ci_txqlen, (int)s->ci_service->csvc_tx_limit);
		cap_rt_msg_free(msg);
		return (EAGAIN);
	}
	if (s->ci_txqlen >= hard_limit) {
		SDT_PROBE5(cap_rt, , , queue__pressure,
		    s->ci_service->csvc_name, s->ci_badge, "tx-hard",
		    s->ci_txqlen, hard_limit);
		cap_rt_msg_free(msg);
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
 * Called from cap_rt_reply() and cap_rt_notify() in sleeping context (M_WAITOK).
 * If fcaps is non-NULL, each entry is copied so the receiver gets the
 * sender's Capsicum rights.  NULL = full rights (kernel-minted fds).
 * Returns NULL if fhold() fails on a racing close.
 */
static struct cap_rt_msg *
cap_rt_msg_alloc_full(const void *data, size_t datalen,
    struct file * const *fds, const struct filecaps *fcaps, int nfds,
    uint64_t badge, uint64_t reply_token, struct ucred *cred)
{
	struct cap_rt_msg *msg;
	int i;

	if (datalen > CAP_RT_MSG_PAYLOAD_SIZE)
		return (NULL);

	msg = uma_zalloc(cap_rt_msg_zone, M_WAITOK | M_ZERO);

	if (datalen > 0 && data != NULL) {
		memcpy(msg->cm_data, data, datalen);
		msg->cm_datalen = datalen;
	}

	if (nfds > 0 && fds != NULL) {
		for (i = 0; i < nfds; i++) {
			if (!fhold(fds[i])) {
				while (--i >= 0)
					fdrop(msg->cm_fds[i], curthread);
				msg->cm_nfds = 0;
				uma_zfree(cap_rt_msg_zone, msg);
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
	}

	msg->cm_badge = badge;
	msg->cm_reply_token = reply_token;
	if (cred != NULL)
		msg->cm_cred = crhold(cred);

	return (msg);
}

static struct cap_rt_msg *
cap_rt_msg_alloc(const void *data, size_t datalen,
    struct file * const *fds, const struct filecaps *fcaps, int nfds)
{

	return (cap_rt_msg_alloc_full(data, datalen, fds, fcaps, nfds,
	    0, 0, NULL));
}

/*
 * Auto-reply: enqueue an error when handler returns nonzero.
 * Runs in taskqueue context (may sleep).
 */
static void
cap_rt_auto_reply(struct cap_rt_instance *s, uint64_t reply_token, int error)
{
	struct cap_rt_msg *msg;
	uint32_t err32;

	msg = uma_zalloc(cap_rt_msg_zone, M_WAITOK | M_ZERO);
	err32 = (uint32_t)(error != 0 ? error : EIO);
	memcpy(msg->cm_data, &err32, sizeof(err32));
	msg->cm_datalen = sizeof(err32);
	msg->cm_reply_token = reply_token;

	mtx_lock(&s->ci_mtx);
	cap_rt_instance_enqueue_tx(s, msg, true);
	mtx_unlock(&s->ci_mtx);
}

/* ----------------------------------------------------------------
 * Taskqueue dispatch — dequeue from RX, call handler
 *
 * Each service has a taskqueue with up to min(ncpus, 4) threads.
 * Each instance has its own struct task.  The taskqueue guarantees
 * that the same task is never run concurrently on two threads,
 * giving per-instance handler serialization with cross-instance
 * parallelism.
 * ---------------------------------------------------------------- */

void
cap_rt_dispatch_task(void *context, int pending __unused)
{
	struct cap_rt_instance *s = context;
	struct cap_rt_service *svc;
	struct cap_rt_msg *msg;
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
	cap_rt_instance_hold(s);

	mtx_lock(&s->ci_mtx);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		if (s->ci_flags & CAP_RT_SF_DEAD)
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
		 *     cap_rt_reply(), the client gets a response.  If not,
		 *     there is no reply — the client's next read blocks
		 *     until something else arrives (e.g. a notification).
		 * Return nonzero: automatic error reply sent to client.
		 */
		SDT_PROBE2(cap_rt, , , dispatch,
		    svc->csvc_name, msg->cm_badge);
		start = getsbinuptime();
		error = svc->csvc_ops->co_handler(s, msg, svc->csvc_arg);
		SDT_PROBE4(cap_rt, , , dispatch__done,
		    svc->csvc_name, msg->cm_badge, error,
		    getsbinuptime() - start);

		if (error != 0)
			cap_rt_auto_reply(s, msg->cm_reply_token, error);

		cap_rt_msg_free(msg);

		mtx_lock(&s->ci_mtx);
		s->ci_handler_td = NULL;
		s->ci_inflight--;
		if (s->ci_inflight == 0 && (s->ci_flags & CAP_RT_SF_DEAD)) {
			wakeup(&s->ci_inflight);
			/*
			 * If self-revoke set REVOKED during this handler,
			 * fire co_revoke now that the handler is done.
			 */
			if ((s->ci_flags & CAP_RT_SF_REVOKED) &&
			    !(s->ci_flags & CAP_RT_SF_FINALIZED)) {
				/*
				 * Wait for deferred work first.  Our own
				 * hold adds 1, so wait for refcnt <= 2.
				 */
				while (refcount_load(&s->ci_refcnt) > 2) {
					mtx_unlock(&s->ci_mtx);
					tsleep(s, 0, "cap_rtsr", CAP_RT_POLL_TICKS);
					mtx_lock(&s->ci_mtx);
				}
				s->ci_flags |= CAP_RT_SF_FINALIZED;
				mtx_unlock(&s->ci_mtx);
				if (svc->csvc_ops->co_revoke != NULL)
					svc->csvc_ops->co_revoke(s,
					    s->ci_badge,
					    CAP_RT_REVOKE_BY_SERVICE,
					    svc->csvc_arg);
				mtx_lock(&s->ci_mtx);
			}
		}
	}

	/* If dead, drain any remaining RX messages. */
	if (s->ci_flags & CAP_RT_SF_DEAD)
		cap_rt_instance_drain_rxq(s);

	mtx_unlock(&s->ci_mtx);
	cap_rt_instance_rele(s);
}

/* ----------------------------------------------------------------
 * Service lifecycle
 * ---------------------------------------------------------------- */

int
cap_rt_service_create(const struct cap_rt_service_params *p,
    struct cap_rt_service **svcp)
{
	struct cap_rt_service *svc;
	uint32_t queue_depth, instance_limit;

	if (p == NULL || p->name == NULL || p->name[0] == '\0')
		return (EINVAL);
	if (strlen(p->name) >= CAP_RT_MAXNAME)
		return (ENAMETOOLONG);
	if (p->ops == NULL)
		return (EINVAL);
	if (p->ops->co_handler == NULL && p->ops->co_call == NULL)
		return (EINVAL);

	queue_depth = p->queue_depth > 0 ? p->queue_depth :
	    CAP_RT_MAX_QUEUED;
	if (queue_depth > CAP_RT_MAX_QUEUE_DEPTH)
		return (EINVAL);
	instance_limit = p->instance_limit > 0 ? p->instance_limit :
	    CAP_RT_DEF_INSTANCE_LIMIT;
	if (instance_limit > CAP_RT_MAX_INSTANCES)
		return (EINVAL);

	svc = malloc(sizeof(*svc), M_CAP_RT, M_WAITOK | M_ZERO);
	strlcpy(svc->csvc_name, p->name, sizeof(svc->csvc_name));
	svc->csvc_ops = p->ops;
	svc->csvc_arg = p->arg;
	svc->csvc_instance_limit = instance_limit;
	svc->csvc_tx_limit = p->tx_limit > 0 ? p->tx_limit :
	    CAP_RT_MAX_QUEUED;
	if (svc->csvc_tx_limit > CAP_RT_MAX_TX_LIMIT)
		svc->csvc_tx_limit = CAP_RT_MAX_TX_LIMIT;
	svc->csvc_queue_depth = queue_depth;
	svc->csvc_svc_flags = p->flags;
	LIST_INIT(&svc->csvc_instances);
	refcount_init(&svc->csvc_refcnt, 1);

	/* Only create a taskqueue if the service accepts async SENDMSG. */
	if (p->ops->co_handler != NULL) {
		svc->csvc_taskq = taskqueue_create("cap_rt_svc", M_WAITOK,
		    taskqueue_thread_enqueue, &svc->csvc_taskq);
		taskqueue_start_threads(&svc->csvc_taskq,
		    MIN(mp_ncpus, CAP_RT_MAX_SVC_THREADS), PWAIT,
		    "cap_rt_%s", p->name);
	}

	sx_xlock(&cap_rt_registry_lock);
	if (cap_rt_service_lookup(p->name) != NULL) {
		sx_xunlock(&cap_rt_registry_lock);
		if (svc->csvc_taskq != NULL)
			taskqueue_free(svc->csvc_taskq);
		free(svc, M_CAP_RT);
		return (EEXIST);
	}
	LIST_INSERT_HEAD(&cap_rt_services, svc, csvc_link);
	counter_u64_add(cap_rt_stat_services, 1);
	sx_xunlock(&cap_rt_registry_lock);

	*svcp = svc;
	return (0);
}

/*
 * Internal revoke with reason — shared by cap_rt_instance_revoke()
 * and cap_rt_service_destroy().
 */
static void
cap_rt_instance_revoke_reason(struct cap_rt_instance *s,
    enum cap_rt_revoke_reason reason)
{
	struct cap_rt_service *svc = s->ci_service;
	sbintime_t start __unused;

	start = getsbinuptime();
	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & CAP_RT_SF_DEAD) {
		mtx_unlock(&s->ci_mtx);
		if (svc != NULL) {
			SDT_PROBE4(cap_rt, , , revoke__done,
			    svc->csvc_name, s->ci_badge, reason,
			    getsbinuptime() - start);
		}
		return;
	}
	s->ci_flags |= CAP_RT_SF_REVOKED;
	cap_rt_instance_drain_rxq(s);
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
		if (svc != NULL) {
			SDT_PROBE4(cap_rt, , , revoke__done,
			    svc->csvc_name, s->ci_badge, reason,
			    getsbinuptime() - start);
		}
		return;
	}

	/* Wait for in-flight handlers and calls. */
	while (s->ci_inflight > 0)
		msleep(&s->ci_inflight, &s->ci_mtx, 0, "cap_rtrev", 0);

	/*
	 * If the refcount is > 1, someone else still holds the instance
	 * (e.g., the terminate collection loop or userspace).  Defer
	 * co_revoke to the close path — it will fire after the last
	 * holder releases.
	 */
	if (refcount_load(&s->ci_refcnt) > 1) {
		mtx_unlock(&s->ci_mtx);
		if (svc != NULL) {
			SDT_PROBE4(cap_rt, , , revoke__done,
			    svc->csvc_name, s->ci_badge, reason,
			    getsbinuptime() - start);
		}
		return;
	}

	/* Guard: co_revoke fires exactly once. */
	if (s->ci_flags & CAP_RT_SF_FINALIZED) {
		mtx_unlock(&s->ci_mtx);
		if (svc != NULL) {
			SDT_PROBE4(cap_rt, , , revoke__done,
			    svc->csvc_name, s->ci_badge, reason,
			    getsbinuptime() - start);
		}
		return;
	}
	s->ci_flags |= CAP_RT_SF_FINALIZED;
	mtx_unlock(&s->ci_mtx);

	if (svc != NULL && svc->csvc_ops->co_revoke != NULL)
		svc->csvc_ops->co_revoke(s, s->ci_badge, reason,
		    svc->csvc_arg);
	if (svc != NULL) {
		SDT_PROBE4(cap_rt, , , revoke__done, svc->csvc_name,
		    s->ci_badge, reason, getsbinuptime() - start);
	}
}

/*
 * Free a service struct.  Called when the last reference drops —
 * either from destroy (if no instances remain) or from the last
 * instance's close.
 */
void
cap_rt_service_free(struct cap_rt_service *svc)
{

	if (svc->csvc_taskq != NULL)
		taskqueue_free(svc->csvc_taskq);
	free(svc, M_CAP_RT);
}

void
cap_rt_service_destroy(struct cap_rt_service *svc)
{
	struct cap_rt_instance *s;
	bool need_revoke;

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
	sx_xlock(&cap_rt_registry_lock);
	svc->csvc_flags |= CAP_RT_SVCF_DESTROYING;
	LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
		mtx_lock(&s->ci_mtx);
		if (!(s->ci_flags & CAP_RT_SF_DEAD)) {
			s->ci_flags |= CAP_RT_SF_REVOKED;
			cap_rt_instance_drain_rxq(s);
			cap_rt_instance_drain_txq(s);
			wakeup(&s->ci_txq);
			KNOTE_LOCKED(&s->ci_rknotes, 0);
			KNOTE_LOCKED(&s->ci_wknotes, 0);
		}
		mtx_unlock(&s->ci_mtx);
	}
	sx_xunlock(&cap_rt_registry_lock);

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
			sx_slock(&cap_rt_registry_lock);
			LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
				mtx_lock(&s->ci_mtx);
				if (s->ci_inflight > 0)
					busy = true;
				mtx_unlock(&s->ci_mtx);
				if (busy)
					break;
			}
			sx_sunlock(&cap_rt_registry_lock);
			if (busy)
				tsleep(svc, 0, "cap_rtsyn", CAP_RT_POLL_TICKS);
		} while (busy);
	}

	/* Remove from registry. */
	sx_xlock(&cap_rt_registry_lock);
	LIST_REMOVE(svc, csvc_link);
	counter_u64_add(cap_rt_stat_services, -1);
	sx_xunlock(&cap_rt_registry_lock);

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
		sx_xlock(&cap_rt_registry_lock);
		LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
			mtx_lock(&s->ci_mtx);
			need_revoke =
			    !(s->ci_flags & CAP_RT_SF_FINALIZED);
			if (need_revoke) {
				s->ci_flags |= CAP_RT_SF_FINALIZED;
				cap_rt_instance_hold(s);
				mtx_unlock(&s->ci_mtx);
				break;
			}
			mtx_unlock(&s->ci_mtx);
		}
		sx_xunlock(&cap_rt_registry_lock);

		if (s == NULL)
			break;

		if (svc->csvc_ops->co_revoke != NULL)
			svc->csvc_ops->co_revoke(s, s->ci_badge,
			    CAP_RT_REVOKE_UNLOAD, svc->csvc_arg);
		cap_rt_instance_rele(s);
	}

	/*
	 * Release our initial refcount (from service_create).
	 * Each instance still holds a reservation ref, and close
	 * acquires an additional ref — so the service struct
	 * stays alive until the last close frees it.  If all
	 * instances already closed, we are the last ref.
	 */
	if (refcount_release(&svc->csvc_refcnt))
		cap_rt_service_free(svc);
}

/* ----------------------------------------------------------------
 * Reply and notify
 * ---------------------------------------------------------------- */

int
cap_rt_reply(struct cap_rt_instance *s, uint64_t reply_token,
    const void *out, size_t outlen,
    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds)
{
	struct cap_rt_msg *msg;
	sbintime_t start __unused;
	int error;

	start = getsbinuptime();
	if (outlen > CAP_RT_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (out_nfds < 0 || out_nfds > CAP_RT_MAX_FDS)
		return (EINVAL);
	if (outlen > 0 && out == NULL)
		return (EINVAL);
	if (out_nfds > 0 && out_fds == NULL)
		return (EINVAL);

	msg = cap_rt_msg_alloc(out, outlen, out_fds, out_fcaps, out_nfds);
	if (msg == NULL)
		return (out_nfds > 0 ? EBADF : ENOMEM);

	msg->cm_reply_token = reply_token;
	/* cm_badge, cm_cred intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = cap_rt_instance_enqueue_tx(s, msg, true);
	mtx_unlock(&s->ci_mtx);

	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , reply,
		    s->ci_service->csvc_name, s->ci_badge, outlen);
	if (s->ci_service != NULL) {
		SDT_PROBE5(cap_rt, , , reply__done, s->ci_service->csvc_name,
		    s->ci_badge, outlen, error, getsbinuptime() - start);
	}

	return (error);
}

int
cap_rt_notify(struct cap_rt_instance *s, const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds)
{
	struct cap_rt_msg *msg;
	sbintime_t start __unused;
	int error;

	start = getsbinuptime();
	if (datalen > CAP_RT_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (nfds < 0 || nfds > CAP_RT_MAX_FDS)
		return (EINVAL);
	if (datalen > 0 && data == NULL)
		return (EINVAL);
	if (nfds > 0 && fds == NULL)
		return (EINVAL);

	msg = cap_rt_msg_alloc(data, datalen, fds, fcaps, nfds);
	if (msg == NULL)
		return (nfds > 0 ? EBADF : ENOMEM);
	/* cm_badge, cm_cred intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = cap_rt_instance_enqueue_tx(s, msg, false);
	mtx_unlock(&s->ci_mtx);

	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , notify,
		    s->ci_service->csvc_name, s->ci_badge, datalen);
	if (s->ci_service != NULL) {
		SDT_PROBE5(cap_rt, , , notify__done, s->ci_service->csvc_name,
		    s->ci_badge, datalen, error, getsbinuptime() - start);
	}

	return (error);
}

int
cap_rt_forward(struct cap_rt_instance *s, const struct cap_rt_msg *src)
{
	struct cap_rt_msg *msg;
	int error;

	if (src == NULL)
		return (EINVAL);
	if (src->cm_datalen > CAP_RT_MSG_PAYLOAD_SIZE)
		return (EMSGSIZE);
	if (src->cm_nfds > CAP_RT_MAX_FDS)
		return (EINVAL);

	msg = cap_rt_msg_alloc_full(src->cm_data, src->cm_datalen,
	    src->cm_fds, src->cm_fcaps, src->cm_nfds,
	    src->cm_badge, src->cm_reply_token, src->cm_cred);
	if (msg == NULL)
		return (src->cm_nfds > 0 ? EBADF : ENOMEM);

	mtx_lock(&s->ci_mtx);
	error = cap_rt_instance_enqueue_tx(s, msg, false);
	mtx_unlock(&s->ci_mtx);

	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , notify,
		    s->ci_service->csvc_name, s->ci_badge, src->cm_datalen);

	return (error);
}

/* ----------------------------------------------------------------
 * Revocation
 * ---------------------------------------------------------------- */

void
cap_rt_instance_revoke(struct cap_rt_instance *s)
{

	if (s->ci_service != NULL)
		SDT_PROBE3(cap_rt, , , revoke,
		    s->ci_service->csvc_name, s->ci_badge,
		    CAP_RT_REVOKE_BY_SERVICE);
	cap_rt_instance_revoke_reason(s, CAP_RT_REVOKE_BY_SERVICE);
}

/* ----------------------------------------------------------------
 * Instance private data and badge
 * ---------------------------------------------------------------- */

/*
 * Instance hold/release for deferred work.  The handler calls hold()
 * before stashing the instance pointer, and the deferred task calls
 * rele() when done.  Close waits for the refcount to reach 1 before
 * freeing.
 */
void
cap_rt_instance_hold(struct cap_rt_instance *s)
{

	refcount_acquire(&s->ci_refcnt);
}

void
cap_rt_instance_rele(struct cap_rt_instance *s)
{

	refcount_release(&s->ci_refcnt);
	/* Wake close/revoke only when refcnt might have reached their threshold. */
	if (refcount_load(&s->ci_refcnt) <= 2)
		wakeup(s);
}

void
cap_rt_instance_set_priv(struct cap_rt_instance *s, void *priv)
{

	s->ci_priv = priv;
}

void *
cap_rt_instance_get_priv(struct cap_rt_instance *s)
{

	return (s->ci_priv);
}

uint64_t
cap_rt_instance_get_badge(struct cap_rt_instance *s)
{

	return (s->ci_badge);
}


/* ----------------------------------------------------------------
 * Message accessors — for co_handler.
 * ---------------------------------------------------------------- */

const void *
cap_rt_msg_data(const struct cap_rt_msg *msg)
{
	return (msg->cm_data);
}

size_t
cap_rt_msg_datalen(const struct cap_rt_msg *msg)
{
	return (msg->cm_datalen);
}

struct file **
cap_rt_msg_fds(const struct cap_rt_msg *msg)
{
	return (__DECONST(struct file **, msg->cm_fds));
}

struct filecaps *
cap_rt_msg_fcaps(const struct cap_rt_msg *msg)
{
	return (__DECONST(struct filecaps *, msg->cm_fcaps));
}

int
cap_rt_msg_nfds(const struct cap_rt_msg *msg)
{
	return (msg->cm_nfds);
}

uint64_t
cap_rt_msg_badge(const struct cap_rt_msg *msg)
{
	return (msg->cm_badge);
}

uint64_t
cap_rt_msg_token(const struct cap_rt_msg *msg)
{
	return (msg->cm_reply_token);
}

struct ucred *
cap_rt_msg_cred(const struct cap_rt_msg *msg)
{
	return (msg->cm_cred);
}


/* ----------------------------------------------------------------
 * Minting — service creates an instance and returns a struct file *.
 * Safe to call from handler (taskqueue) context.  The caller holds
 * one reference on the returned fp and must fdrop() after passing
 * it as an attached descriptor in cap_rt_reply() or cap_rt_notify().
 * ---------------------------------------------------------------- */
int
cap_rt_mint_fp(struct cap_rt_service *svc, uint64_t badge,
    struct file **fpp)
{
	struct cap_rt_instance *s;
	struct file *fp;
	int error;

	error = cap_rt_service_reserve(svc);
	if (error != 0)
		return (error);

	s = cap_rt_instance_init(svc, badge);

	error = falloc_noinstall(curthread, &fp);
	if (error != 0) {
		cap_rt_instance_free(s);
		cap_rt_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_CAP_RT, s,
	    (svc->csvc_svc_flags & CAP_RT_SVC_NOXFER) ?
	    &cap_rt_instance_noxfer_ops : &cap_rt_instance_ops);

	if (svc->csvc_ops->co_init != NULL) {
		error = svc->csvc_ops->co_init(s, svc->csvc_arg);
		if (error != 0) {
			mtx_lock(&s->ci_mtx);
			s->ci_flags |= CAP_RT_SF_FINALIZED;
			mtx_unlock(&s->ci_mtx);
			fdrop(fp, curthread);
			cap_rt_service_unreserve(svc);
			return (error);
		}
	}

	/* Link before returning — see cap_rt_instance_create for rationale. */
	error = cap_rt_instance_link(svc, s);
	if (error != 0) {
		fdrop(fp, curthread);
		cap_rt_service_unreserve(svc);
		return (error);
	}

	*fpp = fp;
	return (0);
}
