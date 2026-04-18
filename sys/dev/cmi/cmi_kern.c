/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi: generic capability interface for kernel modules.
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

#include "cmi_internal.h"

MALLOC_DECLARE(M_CMI);

SDT_PROVIDER_DECLARE(cmi);
SDT_PROBE_DECLARE(cmi, , , dispatch);
SDT_PROBE_DECLARE(cmi, , , reply);
SDT_PROBE_DECLARE(cmi, , , notify);
SDT_PROBE_DECLARE(cmi, , , revoke);

/* ----------------------------------------------------------------
 * Queue helpers
 * ---------------------------------------------------------------- */

void
cmi_instance_drain_txq(struct cmi_instance *s)
{
	struct cmi_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_txq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_txq, cm_link);
		s->ci_txqlen--;
		cmi_msg_free(msg);
	}
}

void
cmi_instance_drain_rxq(struct cmi_instance *s)
{
	struct cmi_msg *msg;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		STAILQ_REMOVE_HEAD(&s->ci_rxq, cm_link);
		s->ci_rxqlen--;
		cmi_msg_free(msg);
	}
}

/*
 * Enqueue a message on an instance's TX queue.  Caller must hold ci_mtx.
 *
 * If 'force' is true the message bypasses the soft limit (used by
 * cmi_reply) but is still subject to the hard limit.  If false,
 * the enqueue is rejected with EAGAIN when the queue exceeds the
 * soft limit (used by cmi_notify).
 *
 * Hard limit: prevents a client that never reads from growing
 * kernel memory without bound.  Set to 4× queue_depth.
 */
static int
cmi_instance_enqueue_tx(struct cmi_instance *s, struct cmi_msg *msg,
    bool force)
{
	int hard_limit;

	mtx_assert(&s->ci_mtx, MA_OWNED);
	if ((s->ci_flags & CMI_SF_DEAD) || s->ci_service == NULL) {
		cmi_msg_free(msg);
		return (ECONNRESET);
	}
	hard_limit = (int)s->ci_service->csvc_queue_depth * CMI_TX_HARD_MULT;
	if (!force && s->ci_txqlen >= (int)s->ci_service->csvc_tx_limit) {
		cmi_msg_free(msg);
		return (EAGAIN);
	}
	if (s->ci_txqlen >= hard_limit) {
		cmi_msg_free(msg);
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
 * Called from cmi_reply() and cmi_notify() in sleeping context (M_WAITOK).
 * If fcaps is non-NULL, each entry is copied so the receiver gets the
 * sender's Capsicum rights.  NULL = full rights (kernel-minted fds).
 * Returns NULL if fhold() fails on a racing close.
 */
static struct cmi_msg *
cmi_msg_alloc(const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds)
{
	struct cmi_msg *msg;
	int i;

	msg = uma_zalloc(cmi_msg_zone, M_WAITOK | M_ZERO);

	if (datalen > 0 && data != NULL) {
		msg->cm_data = malloc(datalen, M_CMI, M_WAITOK);
		memcpy(msg->cm_data, data, datalen);
		msg->cm_datalen = datalen;
	}

	if (nfds > 0 && fds != NULL) {
		msg->cm_fds = malloc(nfds * sizeof(struct file *),
		    M_CMI, M_WAITOK | M_ZERO);
		for (i = 0; i < nfds; i++) {
			if (!fhold(fds[i])) {
				while (--i >= 0)
					fdrop(msg->cm_fds[i], curthread);
				free(msg->cm_fds, M_CMI);
				free(msg->cm_data, M_CMI);
				uma_zfree(cmi_msg_zone, msg);
				return (NULL);
			}
			msg->cm_fds[i] = fds[i];
		}
		msg->cm_nfds = nfds;

		/* Copy Capsicum rights if provided. */
		if (fcaps != NULL) {
			msg->cm_fcaps = malloc(nfds * sizeof(struct filecaps),
			    M_CMI, M_WAITOK | M_ZERO);
			for (i = 0; i < nfds; i++)
				filecaps_copy(&fcaps[i],
				    &msg->cm_fcaps[i], true);
		}
	}

	return (msg);
}

/*
 * Auto-reply: enqueue an error when handler returns nonzero.
 * Runs in taskqueue context (may sleep).
 */
static void
cmi_auto_reply(struct cmi_instance *s, uint64_t reply_token, int error)
{
	struct cmi_msg *msg;
	uint32_t err32;

	msg = uma_zalloc(cmi_msg_zone, M_WAITOK | M_ZERO);
	err32 = (uint32_t)(error != 0 ? error : EIO);
	msg->cm_data = malloc(sizeof(err32), M_CMI, M_WAITOK);
	memcpy(msg->cm_data, &err32, sizeof(err32));
	msg->cm_datalen = sizeof(err32);
	msg->cm_reply_token = reply_token;

	mtx_lock(&s->ci_mtx);
	cmi_instance_enqueue_tx(s, msg, true);
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
cmi_dispatch_task(void *context, int pending __unused)
{
	struct cmi_instance *s = context;
	struct cmi_service *svc;
	struct cmi_msg *msg;
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
	cmi_instance_hold(s);

	mtx_lock(&s->ci_mtx);
	while ((msg = STAILQ_FIRST(&s->ci_rxq)) != NULL) {
		if (s->ci_flags & CMI_SF_DEAD)
			break;

		STAILQ_REMOVE_HEAD(&s->ci_rxq, cm_link);
		s->ci_rxqlen--;
		s->ci_inflight++;

		/* Notify EVFILT_WRITE — space freed in RX. */
		KNOTE_LOCKED(&s->ci_wknotes, 0);
		s->ci_handler_td = curthread;
		mtx_unlock(&s->ci_mtx);

		/*
		 * Call handler — no locks held, may sleep.
		 * Return 0: message consumed.  If the handler called
		 *     cmi_reply(), the client gets a response.  If not,
		 *     there is no reply — the client's next read blocks
		 *     until something else arrives (e.g. a notification).
		 * Return nonzero: automatic error reply sent to client.
		 */
		SDT_PROBE2(cmi, , , dispatch,
		    svc->csvc_name, msg->cm_badge);
		error = svc->csvc_ops->co_handler(s, msg, svc->csvc_arg);

		if (error != 0)
			cmi_auto_reply(s, msg->cm_reply_token, error);

		cmi_msg_free(msg);

		mtx_lock(&s->ci_mtx);
		s->ci_handler_td = NULL;
		s->ci_inflight--;
		if (s->ci_inflight == 0 && (s->ci_flags & CMI_SF_DEAD)) {
			wakeup(&s->ci_inflight);
			/*
			 * If self-revoke set REVOKED during this handler,
			 * fire co_revoke now that the handler is done.
			 */
			if ((s->ci_flags & CMI_SF_REVOKED) &&
			    !(s->ci_flags & CMI_SF_FINALIZED)) {
				/*
				 * Wait for deferred work first.  Our own
				 * hold adds 1, so wait for refcnt <= 2.
				 */
				while (refcount_load(&s->ci_refcnt) > 2) {
					mtx_unlock(&s->ci_mtx);
					tsleep(s, 0, "cmisr", CMI_POLL_TICKS);
					mtx_lock(&s->ci_mtx);
				}
				s->ci_flags |= CMI_SF_FINALIZED;
				mtx_unlock(&s->ci_mtx);
				if (svc->csvc_ops->co_revoke != NULL)
					svc->csvc_ops->co_revoke(s,
					    s->ci_badge,
					    CMI_REVOKE_BY_SERVICE,
					    svc->csvc_arg);
				mtx_lock(&s->ci_mtx);
			}
		}
	}

	/* If dead, drain any remaining RX messages. */
	if (s->ci_flags & CMI_SF_DEAD)
		cmi_instance_drain_rxq(s);

	mtx_unlock(&s->ci_mtx);
	cmi_instance_rele(s);
}

/* ----------------------------------------------------------------
 * Service lifecycle
 * ---------------------------------------------------------------- */

int
cmi_service_create(const struct cmi_service_params *p,
    struct cmi_service **svcp)
{
	struct cmi_service *svc;
	uint32_t msg_size, queue_depth, instance_limit;

	if (p == NULL || p->name == NULL || p->name[0] == '\0')
		return (EINVAL);
	if (strlen(p->name) >= CMI_MAXNAME)
		return (ENAMETOOLONG);
	if (p->ops == NULL)
		return (EINVAL);
	if (p->ops->co_handler == NULL && p->ops->co_call == NULL)
		return (EINVAL);
	/* A service must be async (co_handler) or sync (co_call), not both. */
	if (p->ops->co_handler != NULL && p->ops->co_call != NULL)
		return (EINVAL);

	msg_size = p->msg_size > 0 ? p->msg_size : CMI_MAX_MSG;
	if (msg_size > CMI_MSG_SIZE_LIMIT)
		return (EINVAL);
	queue_depth = p->queue_depth > 0 ? p->queue_depth :
	    CMI_MAX_QUEUED;
	if (queue_depth > CMI_MAX_QUEUE_DEPTH)
		return (EINVAL);
	instance_limit = p->instance_limit > 0 ? p->instance_limit :
	    CMI_DEF_INSTANCE_LIMIT;
	if (instance_limit > CMI_MAX_INSTANCES)
		return (EINVAL);

	svc = malloc(sizeof(*svc), M_CMI, M_WAITOK | M_ZERO);
	strlcpy(svc->csvc_name, p->name, sizeof(svc->csvc_name));
	svc->csvc_ops = p->ops;
	svc->csvc_arg = p->arg;
	svc->csvc_instance_limit = instance_limit;
	svc->csvc_msg_size = msg_size;
	svc->csvc_tx_limit = p->tx_limit > 0 ? p->tx_limit :
	    CMI_MAX_QUEUED;
	if (svc->csvc_tx_limit > CMI_MAX_TX_LIMIT)
		svc->csvc_tx_limit = CMI_MAX_TX_LIMIT;
	svc->csvc_queue_depth = queue_depth;
	svc->csvc_svc_flags = p->flags;
	LIST_INIT(&svc->csvc_instances);
	refcount_init(&svc->csvc_refcnt, 1);

	svc->csvc_taskq = taskqueue_create("cmi_svc", M_WAITOK,
	    taskqueue_thread_enqueue, &svc->csvc_taskq);
	taskqueue_start_threads(&svc->csvc_taskq,
	    MIN(mp_ncpus, CMI_MAX_SVC_THREADS), PWAIT, "cmi_%s", p->name);

	sx_xlock(&cmi_registry_lock);
	if (cmi_service_lookup(p->name) != NULL) {
		sx_xunlock(&cmi_registry_lock);
		taskqueue_free(svc->csvc_taskq);
		free(svc, M_CMI);
		return (EEXIST);
	}
	LIST_INSERT_HEAD(&cmi_services, svc, csvc_link);
	counter_u64_add(cmi_stat_services, 1);
	sx_xunlock(&cmi_registry_lock);

	*svcp = svc;
	return (0);
}

/*
 * Internal revoke with reason — shared by cmi_instance_revoke()
 * and cmi_service_destroy().
 */
static void
cmi_instance_revoke_reason(struct cmi_instance *s,
    enum cmi_revoke_reason reason)
{
	struct cmi_service *svc = s->ci_service;

	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & CMI_SF_DEAD) {
		mtx_unlock(&s->ci_mtx);
		return;
	}
	s->ci_flags |= CMI_SF_REVOKED;
	cmi_instance_drain_rxq(s);
	cmi_instance_drain_txq(s);

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
		return;
	}

	/* Wait for in-flight handlers and calls. */
	while (s->ci_inflight > 0)
		msleep(&s->ci_inflight, &s->ci_mtx, 0, "cmirev", 0);

	/*
	 * Try to finalize now.  If the refcount is already 1,
	 * we can fire co_revoke immediately.  If not (instance
	 * still held by userspace or deferred work), skip —
	 * close will fire co_revoke after the refcount drains.
	 */
	if (refcount_load(&s->ci_refcnt) > 1) {
		mtx_unlock(&s->ci_mtx);
		return;
	}

	/* Guard: co_revoke fires exactly once. */
	if (s->ci_flags & CMI_SF_FINALIZED) {
		mtx_unlock(&s->ci_mtx);
		return;
	}
	s->ci_flags |= CMI_SF_FINALIZED;
	mtx_unlock(&s->ci_mtx);

	if (svc != NULL && svc->csvc_ops->co_revoke != NULL)
		svc->csvc_ops->co_revoke(s, s->ci_badge, reason,
		    svc->csvc_arg);
}

/*
 * Free a service struct.  Called when the last reference drops —
 * either from destroy (if no instances remain) or from the last
 * instance's close.
 */
void
cmi_service_free(struct cmi_service *svc)
{

	taskqueue_free(svc->csvc_taskq);
	free(svc, M_CMI);
}

void
cmi_service_destroy(struct cmi_service *svc)
{
	struct cmi_instance *s;
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
	sx_xlock(&cmi_registry_lock);
	svc->csvc_flags |= CMI_SVCF_DESTROYING;
	LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
		mtx_lock(&s->ci_mtx);
		if (!(s->ci_flags & CMI_SF_DEAD)) {
			s->ci_flags |= CMI_SF_REVOKED;
			cmi_instance_drain_rxq(s);
			cmi_instance_drain_txq(s);
			wakeup(&s->ci_txq);
			KNOTE_LOCKED(&s->ci_rknotes, 0);
			KNOTE_LOCKED(&s->ci_wknotes, 0);
		}
		mtx_unlock(&s->ci_mtx);
	}
	sx_xunlock(&cmi_registry_lock);

	/* Wait for all in-flight handlers and calls to complete. */
	taskqueue_drain_all(svc->csvc_taskq);

	/* Remove from registry. */
	sx_xlock(&cmi_registry_lock);
	LIST_REMOVE(svc, csvc_link);
	counter_u64_add(cmi_stat_services, -1);
	sx_xunlock(&cmi_registry_lock);

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
		sx_xlock(&cmi_registry_lock);
		LIST_FOREACH(s, &svc->csvc_instances, ci_svc_link) {
			mtx_lock(&s->ci_mtx);
			need_revoke =
			    !(s->ci_flags & CMI_SF_FINALIZED);
			if (need_revoke) {
				s->ci_flags |= CMI_SF_FINALIZED;
				cmi_instance_hold(s);
				mtx_unlock(&s->ci_mtx);
				break;
			}
			mtx_unlock(&s->ci_mtx);
		}
		sx_xunlock(&cmi_registry_lock);

		if (s == NULL)
			break;

		if (svc->csvc_ops->co_revoke != NULL)
			svc->csvc_ops->co_revoke(s, s->ci_badge,
			    CMI_REVOKE_UNLOAD, svc->csvc_arg);
		cmi_instance_rele(s);
	}

	/*
	 * Release our initial refcount (from service_create).
	 * Each instance still holds a reservation ref, and close
	 * acquires an additional ref — so the service struct
	 * stays alive until the last close frees it.  If all
	 * instances already closed, we are the last ref.
	 */
	if (refcount_release(&svc->csvc_refcnt))
		cmi_service_free(svc);
}

/* ----------------------------------------------------------------
 * Reply and notify
 * ---------------------------------------------------------------- */

int
cmi_reply(struct cmi_instance *s, uint64_t reply_token,
    const void *out, size_t outlen,
    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds)
{
	struct cmi_msg *msg;
	uint32_t limit;
	int error;

	limit = s->ci_service != NULL ? s->ci_service->csvc_msg_size :
	    CMI_MAX_MSG;
	if (outlen > limit)
		return (EMSGSIZE);
	if (out_nfds < 0 || out_nfds > CMI_MAX_FDS)
		return (EINVAL);
	if (outlen > 0 && out == NULL)
		return (EINVAL);
	if (out_nfds > 0 && out_fds == NULL)
		return (EINVAL);

	msg = cmi_msg_alloc(out, outlen, out_fds, out_fcaps, out_nfds);
	if (msg == NULL)
		return (out_nfds > 0 ? EBADF : ENOMEM);

	msg->cm_reply_token = reply_token;
	/* cm_badge, cm_cred, cm_pid intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = cmi_instance_enqueue_tx(s, msg, true);
	mtx_unlock(&s->ci_mtx);

	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(cmi, , , reply,
		    s->ci_service->csvc_name, s->ci_badge, outlen);

	return (error);
}

int
cmi_notify(struct cmi_instance *s, const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds)
{
	struct cmi_msg *msg;
	uint32_t limit;
	int error;

	limit = s->ci_service != NULL ? s->ci_service->csvc_msg_size :
	    CMI_MAX_MSG;
	if (datalen > limit)
		return (EMSGSIZE);
	if (nfds < 0 || nfds > CMI_MAX_FDS)
		return (EINVAL);
	if (datalen > 0 && data == NULL)
		return (EINVAL);
	if (nfds > 0 && fds == NULL)
		return (EINVAL);

	msg = cmi_msg_alloc(data, datalen, fds, fcaps, nfds);
	if (msg == NULL)
		return (nfds > 0 ? EBADF : ENOMEM);
	/* cm_badge, cm_cred, cm_pid intentionally zero for service→client. */

	mtx_lock(&s->ci_mtx);
	error = cmi_instance_enqueue_tx(s, msg, false);
	mtx_unlock(&s->ci_mtx);

	if (error == 0 && s->ci_service != NULL)
		SDT_PROBE3(cmi, , , notify,
		    s->ci_service->csvc_name, s->ci_badge, datalen);

	return (error);
}

/* ----------------------------------------------------------------
 * Revocation
 * ---------------------------------------------------------------- */

void
cmi_instance_revoke(struct cmi_instance *s)
{

	if (s->ci_service != NULL)
		SDT_PROBE3(cmi, , , revoke,
		    s->ci_service->csvc_name, s->ci_badge,
		    CMI_REVOKE_BY_SERVICE);
	cmi_instance_revoke_reason(s, CMI_REVOKE_BY_SERVICE);
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
cmi_instance_hold(struct cmi_instance *s)
{

	refcount_acquire(&s->ci_refcnt);
}

void
cmi_instance_rele(struct cmi_instance *s)
{

	refcount_release(&s->ci_refcnt);
	/*
	 * Always wake — close/revoke wait for refcnt to reach 1
	 * (not 0), so a conditional wakeup on refcount_release's
	 * "reached zero" return would never fire for them.
	 */
	wakeup(s);
}

void
cmi_instance_set_priv(struct cmi_instance *s, void *priv)
{

	s->ci_priv = priv;
}

void *
cmi_instance_get_priv(struct cmi_instance *s)
{

	return (s->ci_priv);
}

uint64_t
cmi_instance_get_badge(struct cmi_instance *s)
{

	return (s->ci_badge);
}

uint64_t
cmi_instance_get_id(struct cmi_instance *s)
{

	return (s->ci_id);
}

/* ----------------------------------------------------------------
 * Message accessors — for co_handler.
 * ---------------------------------------------------------------- */

const void *
cmi_msg_data(const struct cmi_msg *msg)
{
	return (msg->cm_data);
}

size_t
cmi_msg_datalen(const struct cmi_msg *msg)
{
	return (msg->cm_datalen);
}

struct file **
cmi_msg_fds(const struct cmi_msg *msg)
{
	return (msg->cm_fds);
}

struct filecaps *
cmi_msg_fcaps(const struct cmi_msg *msg)
{
	return (msg->cm_fcaps);
}

int
cmi_msg_nfds(const struct cmi_msg *msg)
{
	return (msg->cm_nfds);
}

uint64_t
cmi_msg_badge(const struct cmi_msg *msg)
{
	return (msg->cm_badge);
}

uint64_t
cmi_msg_token(const struct cmi_msg *msg)
{
	return (msg->cm_reply_token);
}

struct ucred *
cmi_msg_cred(const struct cmi_msg *msg)
{
	return (msg->cm_cred);
}

pid_t
cmi_msg_pid(const struct cmi_msg *msg)
{
	return (msg->cm_pid);
}

/* ----------------------------------------------------------------
 * Minting — service creates an instance and returns a struct file *.
 * Safe to call from handler (taskqueue) context.  The caller holds
 * one reference on the returned fp and must fdrop() after passing
 * it as an attached descriptor in cmi_reply() or cmi_notify().
 * ---------------------------------------------------------------- */
int
cmi_mint_fp(struct cmi_service *svc, uint64_t badge,
    struct file **fpp)
{
	struct cmi_instance *s;
	struct file *fp;
	int error;

	error = cmi_service_reserve(svc);
	if (error != 0)
		return (error);

	s = cmi_instance_init(svc, badge);

	error = falloc_noinstall(curthread, &fp);
	if (error != 0) {
		cmi_instance_free(s);
		cmi_service_unreserve(svc);
		return (error);
	}

	finit(fp, FREAD | FWRITE, DTYPE_CMI, s,
	    (svc->csvc_svc_flags & CMI_SVC_NOXFER) ?
	    &cmi_instance_noxfer_ops : &cmi_instance_ops);

	if (svc->csvc_ops->co_init != NULL) {
		error = svc->csvc_ops->co_init(s, svc->csvc_arg);
		if (error != 0) {
			mtx_lock(&s->ci_mtx);
			s->ci_flags |= CMI_SF_FINALIZED;
			mtx_unlock(&s->ci_mtx);
			fdrop(fp, curthread);
			cmi_service_unreserve(svc);
			return (error);
		}
	}

	/* Link before returning — see cmi_instance_create for rationale. */
	error = cmi_instance_link(svc, s);
	if (error != 0) {
		fdrop(fp, curthread);
		cmi_service_unreserve(svc);
		return (error);
	}

	*fpp = fp;
	return (0);
}

/* ----------------------------------------------------------------
 * Kernel-side send — enqueue on a capability's RX queue from
 * kernel context.  Same effect as userspace CMI_SENDMSG but
 * without copyin.  The message flows through the normal
 * RX → taskqueue → co_handler path.
 *
 * fp must be a DTYPE_CMI file.  The caller provides kernel
 * pointers directly — no user/kernel boundary crossing.
 * Credentials are stamped as curthread's ucred.
 * ---------------------------------------------------------------- */
int
cmi_send(struct file *fp, const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds,
    uint64_t reply_token)
{
	struct cmi_instance *s;
	struct cmi_service *svc;
	struct cmi_msg *msg;
	int i;

	if (fp->f_type != DTYPE_CMI)
		return (EBADF);
	s = fp->f_data;
	if (s == NULL)
		return (EBADF);
	svc = s->ci_service;
	if (svc == NULL || svc->csvc_ops->co_handler == NULL)
		return (EOPNOTSUPP);
	if (datalen > svc->csvc_msg_size)
		return (EMSGSIZE);
	if (nfds < 0 || nfds > CMI_MAX_FDS)
		return (EINVAL);

	msg = uma_zalloc(cmi_msg_zone, M_WAITOK | M_ZERO);

	if (datalen > 0 && data != NULL) {
		msg->cm_data = malloc(datalen, M_CMI, M_WAITOK);
		memcpy(msg->cm_data, data, datalen);
		msg->cm_datalen = datalen;
	}

	if (nfds > 0 && fds != NULL) {
		msg->cm_fds = malloc(nfds * sizeof(struct file *),
		    M_CMI, M_WAITOK | M_ZERO);
		for (i = 0; i < nfds; i++) {
			if (!fhold(fds[i])) {
				while (--i >= 0)
					fdrop(msg->cm_fds[i], curthread);
				free(msg->cm_fds, M_CMI);
				msg->cm_fds = NULL;
				free(msg->cm_data, M_CMI);
				uma_zfree(cmi_msg_zone, msg);
				return (EBADF);
			}
			msg->cm_fds[i] = fds[i];
		}
		msg->cm_nfds = nfds;

		if (fcaps != NULL) {
			msg->cm_fcaps = malloc(nfds * sizeof(struct filecaps),
			    M_CMI, M_WAITOK | M_ZERO);
			for (i = 0; i < nfds; i++)
				filecaps_copy(&fcaps[i],
				    &msg->cm_fcaps[i], true);
		}
	}

	msg->cm_badge = s->ci_badge;
	msg->cm_reply_token = reply_token;
	msg->cm_cred = crhold(curthread->td_ucred);
	msg->cm_pid = curthread->td_proc->p_pid;

	mtx_lock(&s->ci_mtx);
	if (s->ci_flags & CMI_SF_DEAD) {
		mtx_unlock(&s->ci_mtx);
		cmi_msg_free(msg);
		return (ECONNRESET);
	}
	if (s->ci_rxqlen >= s->ci_rxqlimit) {
		mtx_unlock(&s->ci_mtx);
		cmi_msg_free(msg);
		return (EAGAIN);
	}
	STAILQ_INSERT_TAIL(&s->ci_rxq, msg, cm_link);
	s->ci_rxqlen++;
	if (svc->csvc_taskq != NULL)
		taskqueue_enqueue(svc->csvc_taskq, &s->ci_task);
	mtx_unlock(&s->ci_mtx);

	return (0);
}
