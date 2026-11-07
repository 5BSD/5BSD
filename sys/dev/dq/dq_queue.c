/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: queues, objects and events.
 *
 * A queue is one open of /dev/dq.  The kernel turns operations on the
 * queue's objects into events, the controller reads them and answers by
 * id, in any order, from any thread.  The requesting thread waits on its
 * event with only the serialization the operation already took
 * (foffset, rangelock) and never with a lock the controller needs.
 * Everything that can fail closed does: a revoked object, a closing queue,
 * a full queue and a missed deadline all answer EIO at once (design 15).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/sx.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/ucred.h>
#include <sys/uio.h>

#include <security/mac/mac_framework.h>
#include <dev/mac_capability/mac_capability_label.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

int
dq_event_cmp(const struct dq_event_k *a, const struct dq_event_k *b)
{

	return (a->ev_hdr.de_id < b->ev_hdr.de_id ? -1 :
	    a->ev_hdr.de_id > b->ev_hdr.de_id);
}
RB_GENERATE(dq_inflight_tree, dq_event_k, ev_tree, dq_event_cmp);

int
dq_object_cmp(const struct dq_object *a, const struct dq_object *b)
{

	return (a->o_id < b->o_id ? -1 : a->o_id > b->o_id);
}
RB_GENERATE(dq_object_tree, dq_object, o_tree, dq_object_cmp);

TAILQ_HEAD(dq_event_list, dq_event_k);

static void	dq_event_hold(struct dq_event_k *ev);
static void	dq_event_rele(struct dq_event_k *ev);
static void	dq_event_fail_locked(struct dq_queue *q, struct dq_event_k *ev,
		    int error, struct dq_event_list *freed);
static void	dq_object_revoke_locked(struct dq_queue *q, struct dq_object *o,
		    int why, struct dq_event_list *freed);

/*
 * Queues
 */

struct dq_queue *
dq_queue_create(struct thread *td, struct file *fp)
{
	struct dq_queue *q;
	int i;

	q = malloc(sizeof(*q), M_DQ, M_WAITOK | M_ZERO);
	mtx_init(&q->q_mtx, "dq queue", NULL, MTX_DEF);
	sx_init(&q->q_rdsx, "dq read");
	refcount_init(&q->q_refs, 1);
	q->q_file = fp;
	q->q_cred = crhold(td->td_ucred);
	q->q_pid = td->td_proc->p_pid;
	TAILQ_INIT(&q->q_pending);
	RB_INIT(&q->q_inflight);
	RB_INIT(&q->q_objects);
	LIST_INIT(&q->q_observers);
	for (i = 0; i < DQ_REQUESTER_HASH; i++)
		LIST_INIT(&q->q_requesters[i]);
	knlist_init_mtx(&q->q_sel.si_note, &q->q_mtx);
	q->q_depth = dq_queue_depth;
	q->q_stats.ds_version = DQ_API_VERSION;

	mtx_lock(&dq_mtx);
	q->q_gid = ++dq_next_gid;
	LIST_INSERT_HEAD(&dq_queues, q, q_all);
	dq_nqueues++;
	mtx_unlock(&dq_mtx);

	SDT_PROBE1(dq, , , queue__open, q);
	return (q);
}

void
dq_queue_hold(struct dq_queue *q)
{

	refcount_acquire(&q->q_refs);
}

void
dq_queue_rele(struct dq_queue *q)
{

	if (!refcount_release(&q->q_refs))
		return;
	KASSERT((q->q_flags & DQ_Q_CLOSING) != 0, ("dq: freeing an open queue"));
	KASSERT(TAILQ_EMPTY(&q->q_pending) && RB_EMPTY(&q->q_inflight),
	    ("dq: freeing a queue with events"));
	KASSERT(RB_EMPTY(&q->q_objects), ("dq: freeing a queue with objects"));
	knlist_clear(&q->q_sel.si_note, 0);
	knlist_destroy(&q->q_sel.si_note);
	seldrain(&q->q_sel);
	crfree(q->q_cred);
	sx_destroy(&q->q_rdsx);
	mtx_destroy(&q->q_mtx);
	free(q, M_DQ);
}

/*
 * The controller closed its last descriptor to the queue: fail closed.
 * Every object is revoked, every waiter woken with EIO, every reader and
 * observer told; nothing here waits for anyone (I11).  The memory stays
 * until the last object and observer drop their references, so an object
 * fileop that runs afterwards finds DQ_Q_CLOSING and answers EIO.
 */
void
dq_queue_close(struct dq_queue *q)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	struct dq_object *o;

	TAILQ_INIT(&freed);
	DQ_LOCK(q);
	q->q_flags |= DQ_Q_CLOSING;
	RB_FOREACH(o, dq_object_tree, &q->q_objects)
		dq_object_revoke_locked(q, o, 1, &freed);
	/* Queue-level records (CLOSE, INTERRUPT) left unread. */
	TAILQ_FOREACH_SAFE(ev, &q->q_pending, ev_link, evtmp)
		dq_event_fail_locked(q, ev, EIO, &freed);
	wakeup(&q->q_pending);
	wakeup(&q->q_requesters);
	selwakeup(&q->q_sel);
	KNOTE_LOCKED(&q->q_sel.si_note, 0);
	dq_observer_unlink_all(q);
	DQ_UNLOCK(q);

	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);

	mtx_lock(&dq_mtx);
	LIST_REMOVE(q, q_all);
	dq_nqueues--;
	mtx_unlock(&dq_mtx);

	SDT_PROBE1(dq, , , queue__close, q);
	dq_queue_rele(q);
}

/*
 * 15.4: a process that holds the queue may not operate on its objects
 * (EDEADLK); the test is by the queue's struct file in the caller's table,
 * so dup, fork and a pdfork'ed helper are covered.  FILEDESC_SLOCK comes
 * before q_mtx in the lock order; the caller holds no dq lock.
 */
bool
dq_caller_holds_queue(struct dq_queue *q, struct thread *td)
{
	struct filedesc *fdp;
	struct fdescenttbl *fdt;
	struct file *qfp;
	bool held;
	int i;

	if (td == NULL || td->td_proc == NULL)
		return (false);
	fdp = td->td_proc->p_fd;
	if (fdp == NULL)
		return (false);
	held = false;
	FILEDESC_SLOCK(fdp);
	DQ_LOCK(q);
	qfp = (q->q_flags & DQ_Q_CLOSING) != 0 ? NULL : q->q_file;
	DQ_UNLOCK(q);
	if (qfp != NULL) {
		fdt = fdp->fd_files;
		for (i = 0; i < fdt->fdt_nfiles; i++) {
			if (fdt->fdt_ofiles[i].fde_file == qfp) {
				held = true;
				break;
			}
		}
	}
	FILEDESC_SUNLOCK(fdp);
	return (held);
}

/*
 * Objects
 */

void
dq_object_hold(struct dq_object *o)
{

	refcount_acquire(&o->o_refs);
}

void
dq_object_rele(struct dq_object *o)
{
	struct dq_queue *q;

	if (!refcount_release(&o->o_refs))
		return;
	KASSERT(o->o_retired, ("dq: freeing an object still on its queue"));
	q = o->o_queue;
	mtx_destroy(&o->o_mtx);
	free(o, M_DQ);
	dq_queue_rele(q);
}

/* Fail one event: unlink it, wake its waiter, hand the list reference back. */
static void
dq_event_fail_locked(struct dq_queue *q, struct dq_event_k *ev, int error,
    struct dq_event_list *freed)
{

	DQ_LOCK_ASSERT(q);
	if (!ev->ev_linked)
		return;
	if (ev->ev_state == DQ_EV_PENDING) {
		TAILQ_REMOVE(&q->q_pending, ev, ev_link);
		q->q_count--;
		q->q_bytes -= ev->ev_size;
	} else {
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds_inflight--;
	}
	ev->ev_linked = false;
	ev->ev_state = DQ_EV_FAILED;
	ev->ev_errno = error;
	cv_broadcast(&ev->ev_cv);
	TAILQ_INSERT_TAIL(freed, ev, ev_link);
}

static void
dq_object_revoke_locked(struct dq_queue *q, struct dq_object *o, int why,
    struct dq_event_list *freed)
{
	struct dq_event_k *ev, *evtmp;

	DQ_LOCK_ASSERT(q);
	DQO_LOCK(o);
	if (o->o_state == DQ_OBJ_REVOKED) {
		DQO_UNLOCK(o);
		return;
	}
	o->o_state = DQ_OBJ_REVOKED;
	dq_file_knote(o, NOTE_REVOKE);
	DQO_UNLOCK(o);
	TAILQ_FOREACH_SAFE(ev, &q->q_pending, ev_link, evtmp) {
		if (ev->ev_object == o)
			dq_event_fail_locked(q, ev, EIO, freed);
	}
	RB_FOREACH_SAFE(ev, dq_inflight_tree, &q->q_inflight, evtmp) {
		if (ev->ev_object == o)
			dq_event_fail_locked(q, ev, EIO, freed);
	}
	wakeup(&o->o_inflight);
	wakeup(&q->q_requesters);
	q->q_stats.ds_objects_revoked++;
	SDT_PROBE3(dq, , , revoke, q, o, why);
}

int
dq_queue_revoke(struct dq_queue *q, uint64_t object)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	struct dq_object key, *o;

	TAILQ_INIT(&freed);
	key.o_id = object;
	DQ_LOCK(q);
	o = RB_FIND(dq_object_tree, &q->q_objects, &key);
	if (o == NULL) {
		DQ_UNLOCK(q);
		return (ESRCH);
	}
	dq_object_revoke_locked(q, o, 0, &freed);
	DQ_UNLOCK(q);
	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);
	return (0);
}

/*
 * The object's last file reference is gone (dq_close, which may run with
 * td == NULL from a socket's garbage collector).  Retire the id, post
 * CLOSE if the controller asked for it, never wait.
 */
void
dq_object_retire(struct dq_object *o, struct thread *td)
{
	struct dq_queue *q;
	bool post_close;

	q = o->o_queue;
	DQO_LOCK(o);
	o->o_fp = NULL;
	DQO_UNLOCK(o);

	/* May sleep in KQ_FLUX_SLEEP: no dq lock held. */
	knlist_clear(&o->o_sel.si_note, 0);
	knlist_destroy(&o->o_sel.si_note);
	seldrain(&o->o_sel);
	rangelock_destroy(&o->o_rl);

	DQ_LOCK(q);
	KASSERT(o->o_inflight == 0, ("dq: closing an object with events"));
	post_close = (q->q_flags & DQ_Q_CLOSING) == 0 &&
	    (o->o_policy.dp_events & DQ_EVENTS_CLOSE) != 0;
	if (!o->o_retired) {
		RB_REMOVE(dq_object_tree, &q->q_objects, o);
		o->o_retired = true;
		q->q_nobjects--;
		q->q_stats.ds_objects_live--;
	}
	DQ_UNLOCK(q);

	if (post_close)
		dq_event_post_nowait(q, o, DQ_OP_CLOSE, NULL, 0, td);
	SDT_PROBE2(dq, , , object__close, q, o);
}

/*
 * Events
 */

static void
dq_event_hold(struct dq_event_k *ev)
{

	refcount_acquire(&ev->ev_refs);
}

static void
dq_event_rele(struct dq_event_k *ev)
{

	if (!refcount_release(&ev->ev_refs))
		return;
	KASSERT(!ev->ev_linked, ("dq: freeing a linked event"));
	cv_destroy(&ev->ev_cv);
	if (ev->ev_reply != NULL)
		free(ev->ev_reply, M_DQ);
	if (ev->ev_object != NULL)
		dq_object_rele(ev->ev_object);
	free(ev, M_DQ);
}

void
dq_reply_free(void *reply)
{

	free(reply, M_DQ);
}

/*
 * D24, as refined by D91: the caller is the posting thread's credential and
 * process, which in the aio daemons is the requester's (aio_process_rw
 * swaps td_ucred); a kernel process or no thread at all is flagged
 * DQ_CALLER_F_KERNEL with pid 0.  Never the file's credential, which in
 * stage 1a is the controller's.
 */
static void
dq_caller_fill(struct dq_caller *dc, struct thread *td)
{
	struct ucred *cred;
	struct proc *p;
	bool nothread;

	bzero(dc, sizeof(*dc));
	nothread = td == NULL;
	if (nothread)
		td = curthread;
	cred = td->td_ucred;
	p = td->td_proc;
	if (nothread || p == NULL || (p->p_flag & P_KPROC) != 0) {
		dc->dc_flags |= DQ_CALLER_F_KERNEL;
	} else {
		dc->dc_pid = p->p_pid;
		PROC_LOCK(p);
		dc->dc_ppid = p->p_pptr != NULL ? p->p_pptr->p_pid : 0;
		PROC_UNLOCK(p);
		dc->dc_tid = td->td_tid;
	}
	dc->dc_uid = cred->cr_ruid;
	dc->dc_euid = cred->cr_uid;
	dc->dc_gid = cred->cr_rgid;
	dc->dc_egid = cred->cr_gid;
	dc->dc_jid = cred->cr_prison->pr_id;
	dc->dc_nonce = mac_capability_proc_nonce(cred);
}

static struct dq_event_k *
dq_event_alloc(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td)
{
	struct dq_event_k *ev;
	struct timespec ts;

	ev = malloc(offsetof(struct dq_event_k, ev_hdr) +
	    sizeof(struct dq_event) + bodylen, M_DQ, M_WAITOK | M_ZERO);
	refcount_init(&ev->ev_refs, 1);
	ev->ev_state = DQ_EV_PENDING;
	cv_init(&ev->ev_cv, "dqwait");
	ev->ev_size = sizeof(struct dq_event) + bodylen;
	ev->ev_hdr.de_version = DQ_API_VERSION;
	ev->ev_hdr.de_size = ev->ev_size;
	ev->ev_hdr.de_op = op;
	if (o != NULL) {
		dq_object_hold(o);
		ev->ev_object = o;
		ev->ev_hdr.de_object = o->o_id;
	}
	dq_caller_fill(&ev->ev_hdr.de_caller, td);
	ev->ev_requester = ev->ev_hdr.de_caller.dc_nonce != 0 ?
	    ev->ev_hdr.de_caller.dc_nonce :
	    ((uint64_t)1 << 63) | (uint64_t)ev->ev_hdr.de_caller.dc_pid;
	nanouptime(&ts);
	ev->ev_hdr.de_time.tv_sec = ts.tv_sec;
	ev->ev_hdr.de_time.tv_nsec = ts.tv_nsec;
	if (bodylen != 0)
		memcpy((char *)&ev->ev_hdr + sizeof(struct dq_event), body,
		    bodylen);
	return (ev);
}

/*
 * Append to the pending list.  The sequence number is taken before the
 * depth test so a drop leaves a visible gap (design 8.6).  Returns EIO on
 * a full queue; the list reference is taken on success.
 */
static int
dq_event_enqueue_locked(struct dq_queue *q, struct dq_event_k *ev)
{

	DQ_LOCK_ASSERT(q);
	ev->ev_hdr.de_seq = ++q->q_seq;
	if (q->q_count >= q->q_depth) {
		q->q_stats.ds_events_dropped++;
		SDT_PROBE2(dq, , , event__drop, q, ev->ev_hdr.de_op);
		return (EIO);
	}
	if (ev->ev_waited)
		ev->ev_hdr.de_id = ++q->q_next_id;
	dq_event_hold(ev);
	ev->ev_linked = true;
	TAILQ_INSERT_TAIL(&q->q_pending, ev, ev_link);
	q->q_count++;
	q->q_bytes += ev->ev_size;
	if (q->q_count > q->q_highwater)
		q->q_highwater = q->q_count;
	q->q_stats.ds_events_posted++;
	SDT_PROBE2(dq, , , event__post, q, ev);
	selwakeup(&q->q_sel);
	KNOTE_LOCKED(&q->q_sel.si_note, 0);
	wakeup(&q->q_pending);
	dq_observer_fanout_event(q, ev);
	return (0);
}

static struct dq_requester *
dq_requester_find_locked(struct dq_queue *q, uint64_t key)
{
	struct dq_requester *rq;

	LIST_FOREACH(rq, &q->q_requesters[key % DQ_REQUESTER_HASH], rq_link) {
		if (rq->rq_key == key)
			return (rq);
	}
	return (NULL);
}

static void
dq_requester_release_locked(struct dq_queue *q, uint64_t key)
{
	struct dq_requester *rq;

	rq = dq_requester_find_locked(q, key);
	KASSERT(rq != NULL && rq->rq_inflight > 0, ("dq: requester count"));
	if (--rq->rq_inflight == 0) {
		LIST_REMOVE(rq, rq_link);
		free(rq, M_DQ);
	}
	wakeup(&q->q_requesters);
}

static sbintime_t
dq_deadline(const struct dq_policy *pol)
{
	int ms;

	ms = pol->dp_deadline_ms;
	if (ms == DQ_DEADLINE_DEFAULT)
		ms = dq_default_deadline_ms;
	if (ms <= 0)
		return (0);
	return (sbinuptime() + (sbintime_t)ms * SBT_1MS);
}

int
dq_event_post_wait(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, void **replyp, size_t *replylenp,
    int *errnop)
{
	struct dq_queue *q;
	struct dq_event_k *ev;
	struct dq_requester *rq, *newrq;
	struct dq_interrupt_body ib;
	sbintime_t deadline;
	int error;
	bool interrupt, drop_list_ref;

	q = o->o_queue;
	*replyp = NULL;
	*replylenp = 0;
	*errnop = 0;
	interrupt = drop_list_ref = false;

	if (dq_caller_holds_queue(q, td))
		return (EDEADLK);

	ev = dq_event_alloc(o, op, body, bodylen, td);
	ev->ev_waited = true;
	newrq = malloc(sizeof(*newrq), M_DQ, M_WAITOK | M_ZERO);

	DQO_LOCK(o);
	deadline = dq_deadline(&o->o_policy);
	DQO_UNLOCK(o);
	ev->ev_deadline = deadline;
	rq = NULL;

	DQ_LOCK(q);
	for (;;) {
		if ((q->q_flags & DQ_Q_CLOSING) != 0) {
			error = EIO;
			goto out_locked;
		}
		DQO_LOCK(o);
		if (o->o_state == DQ_OBJ_REVOKED) {
			DQO_UNLOCK(o);
			error = EIO;
			goto out_locked;
		}
		DQO_UNLOCK(o);
		if (o->o_inflight >= dq_max_inflight_per_object) {
			error = msleep(&o->o_inflight, &q->q_mtx, PCATCH,
			    "dqinfl", 0);
			if (error != 0)
				goto out_locked;
			continue;
		}
		rq = dq_requester_find_locked(q, ev->ev_requester);
		if (rq != NULL && rq->rq_inflight >= dq_max_inflight_per_requester) {
			error = msleep(&q->q_requesters, &q->q_mtx, PCATCH,
			    "dqreq", 0);
			if (error != 0)
				goto out_locked;
			continue;
		}
		break;
	}
	error = dq_event_enqueue_locked(q, ev);
	if (error != 0)
		goto out_locked;
	if (rq == NULL) {
		rq = newrq;
		newrq = NULL;
		rq->rq_key = ev->ev_requester;
		LIST_INSERT_HEAD(&q->q_requesters[rq->rq_key % DQ_REQUESTER_HASH],
		    rq, rq_link);
	}
	rq->rq_inflight++;
	o->o_inflight++;

	error = 0;
	while (ev->ev_state == DQ_EV_PENDING || ev->ev_state == DQ_EV_DELIVERED) {
		if (deadline == 0)
			error = cv_wait_sig(&ev->ev_cv, &q->q_mtx);
		else
			error = cv_timedwait_sig_sbt(&ev->ev_cv, &q->q_mtx,
			    deadline, 0, C_ABSOLUTE);
		if (error != 0)
			break;
	}

	/*
	 * The state decides first: a reply or a failure that landed just
	 * before a signal or the deadline is the answer (D91 item 7).
	 */
	switch (ev->ev_state) {
	case DQ_EV_REPLIED:
		*replyp = ev->ev_reply;
		*replylenp = ev->ev_replylen;
		*errnop = ev->ev_errno;
		ev->ev_reply = NULL;
		error = 0;
		break;
	case DQ_EV_FAILED:
		error = EIO;
		break;
	case DQ_EV_PENDING:
		/* Unread by the controller: withdraw it silently. */
		KASSERT(error != 0, ("dq: pending event with no error"));
		TAILQ_REMOVE(&q->q_pending, ev, ev_link);
		q->q_count--;
		q->q_bytes -= ev->ev_size;
		ev->ev_linked = false;
		drop_list_ref = true;
		if (error == EWOULDBLOCK) {
			ev->ev_state = DQ_EV_FAILED;
			q->q_stats.ds_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else {
			ev->ev_state = DQ_EV_INTERRUPTED;
		}
		break;
	case DQ_EV_DELIVERED:
		KASSERT(error != 0, ("dq: delivered event with no error"));
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds_inflight--;
		ev->ev_linked = false;
		drop_list_ref = true;
		/*
		 * The controller has it: whichever way the waiter gives up,
		 * tell the controller the answer is no longer wanted.
		 */
		interrupt = true;
		if (error == EWOULDBLOCK) {
			ev->ev_state = DQ_EV_FAILED;
			q->q_stats.ds_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else {
			ev->ev_state = DQ_EV_INTERRUPTED;
			q->q_stats.ds_interrupts++;
			SDT_PROBE2(dq, , , event__interrupt, q, ev);
		}
		break;
	default:
		panic("dq: event %p in state %d", ev, ev->ev_state);
	}
	o->o_inflight--;
	wakeup(&o->o_inflight);
	dq_requester_release_locked(q, ev->ev_requester);
out_locked:
	DQ_UNLOCK(q);
	if (newrq != NULL)
		free(newrq, M_DQ);
	if (interrupt) {
		ib.din_id = ev->ev_hdr.de_id;
		dq_event_post_nowait(q, o, DQ_OP_INTERRUPT, &ib, sizeof(ib), td);
	}
	if (drop_list_ref)
		dq_event_rele(ev);
	dq_event_rele(ev);
	return (error);
}

/*
 * Post a record that needs no answer (CLOSE, INTERRUPT).  It carries no
 * id, is never waited for and is dropped on a closing or full queue.
 */
void
dq_event_post_nowait(struct dq_queue *q, struct dq_object *o, uint32_t op,
    const void *body, size_t bodylen, struct thread *td)
{
	struct dq_event_k *ev;

	ev = dq_event_alloc(o, op, body, bodylen, td);
	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) == 0)
		(void)dq_event_enqueue_locked(q, ev);
	DQ_UNLOCK(q);
	dq_event_rele(ev);
}

/*
 * read(2) on the queue: whole records, as many as fit, in order.  One
 * reader at a time; an event is dequeued only after its copy succeeded, so
 * a fault in the controller's buffer loses nothing: the read returns
 * short with the rest still queued and the next read reports the fault.
 */
int
dq_queue_read(struct dq_queue *q, struct uio *uio, int ioflag)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	struct iovec *iovsave, *iovbase;
	ssize_t resid;
	off_t offset;
	int error, iovcnt;
	bool copied;

	if (uio->uio_resid < (ssize_t)sizeof(struct dq_event))
		return (EINVAL);
	TAILQ_INIT(&freed);
	copied = false;
	error = 0;
	/*
	 * uiomove advances the iovecs it crosses before a later one faults;
	 * the controller must see whole records only, so the uio is restored
	 * to the start of a record whose copy failed.
	 */
	iovsave = malloc((size_t)uio->uio_iovcnt * sizeof(*iovsave), M_DQ,
	    M_WAITOK);

	/*
	 * Wait for events without the reader lock, so a non-blocking reader
	 * gets its EAGAIN while another one sleeps; then serialize the copy.
	 * The sx is taken before q_mtx (lock order), so the queue is looked
	 * at again once it is held.
	 */
	for (;;) {
		DQ_LOCK(q);
		while (TAILQ_EMPTY(&q->q_pending)) {
			if ((q->q_flags & DQ_Q_CLOSING) != 0) {
				DQ_UNLOCK(q);
				free(iovsave, M_DQ);
				return (ENXIO);
			}
			if ((ioflag & O_NONBLOCK) != 0) {
				DQ_UNLOCK(q);
				free(iovsave, M_DQ);
				return (EAGAIN);
			}
			error = msleep(&q->q_pending, &q->q_mtx, PCATCH, "dqrd",
			    0);
			if (error != 0) {
				DQ_UNLOCK(q);
				free(iovsave, M_DQ);
				return (error);
			}
		}
		DQ_UNLOCK(q);
		sx_xlock(&q->q_rdsx);
		DQ_LOCK(q);
		if (!TAILQ_EMPTY(&q->q_pending))
			break;
		DQ_UNLOCK(q);
		sx_xunlock(&q->q_rdsx);
	}
	for (;;) {
		ev = TAILQ_FIRST(&q->q_pending);
		if (ev == NULL)
			break;
		if (uio->uio_resid < (ssize_t)ev->ev_size) {
			if (!copied)
				error = ENOBUFS;
			break;
		}
		dq_event_hold(ev);
		DQ_UNLOCK(q);
		iovbase = uio->uio_iov;
		iovcnt = uio->uio_iovcnt;
		resid = uio->uio_resid;
		offset = uio->uio_offset;
		memcpy(iovsave, iovbase, (size_t)iovcnt * sizeof(*iovsave));
		error = uiomove(&ev->ev_hdr, ev->ev_size, uio);
		if (error != 0) {
			memcpy(iovbase, iovsave, (size_t)iovcnt * sizeof(*iovsave));
			uio->uio_iov = iovbase;
			uio->uio_iovcnt = iovcnt;
			uio->uio_resid = resid;
			uio->uio_offset = offset;
		}
		DQ_LOCK(q);
		if (error != 0) {
			dq_event_rele(ev);
			if (copied)
				error = 0;
			break;
		}
		/*
		 * Revoke or close may have failed and unlinked it while
		 * the copy ran: then this was a dead delivery and a late
		 * reply gets ESRCH.
		 */
		if (ev->ev_linked && ev->ev_state == DQ_EV_PENDING &&
		    TAILQ_FIRST(&q->q_pending) == ev) {
			TAILQ_REMOVE(&q->q_pending, ev, ev_link);
			q->q_count--;
			q->q_bytes -= ev->ev_size;
			ev->ev_state = DQ_EV_DELIVERED;
			q->q_stats.ds_events_delivered++;
			SDT_PROBE2(dq, , , event__deliver, q, ev);
			if (ev->ev_waited) {
				RB_INSERT(dq_inflight_tree, &q->q_inflight, ev);
				q->q_stats.ds_inflight++;
			} else {
				ev->ev_linked = false;
				TAILQ_INSERT_TAIL(&freed, ev, ev_link);
			}
		}
		dq_event_rele(ev);
		copied = true;
	}
	DQ_UNLOCK(q);
	sx_xunlock(&q->q_rdsx);
	free(iovsave, M_DQ);
	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);
	return (error);
}

int
dq_queue_poll(struct dq_queue *q, int events, struct thread *td)
{
	int revents;

	revents = 0;
	DQ_LOCK(q);
	if ((events & (POLLIN | POLLRDNORM)) != 0) {
		if (!TAILQ_EMPTY(&q->q_pending))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &q->q_sel);
	}
	if ((events & (POLLOUT | POLLWRNORM)) != 0)
		revents |= events & (POLLOUT | POLLWRNORM);
	if ((q->q_flags & DQ_Q_CLOSING) != 0)
		revents |= POLLHUP;
	DQ_UNLOCK(q);
	return (revents);
}

static void
dq_queue_kqdetach(struct knote *kn)
{
	struct dq_queue *q = kn->kn_hook;

	knlist_remove(&q->q_sel.si_note, kn, 0);
}

static int
dq_queue_kqread(struct knote *kn, long hint __unused)
{
	struct dq_queue *q = kn->kn_hook;

	DQ_LOCK_ASSERT(q);
	kn->kn_data = q->q_bytes;
	if ((q->q_flags & DQ_Q_CLOSING) != 0) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (!TAILQ_EMPTY(&q->q_pending));
}

static const struct filterops dq_queue_rfiltops = {
	.f_isfd = 1,
	.f_detach = dq_queue_kqdetach,
	.f_event = dq_queue_kqread,
};

int
dq_queue_kqfilter(struct dq_queue *q, struct knote *kn)
{

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	kn->kn_fop = &dq_queue_rfiltops;
	kn->kn_hook = q;
	knlist_add(&q->q_sel.si_note, kn, 0);
	return (0);
}

/*
 * Controller ioctls
 */

static int
dq_mint_reason(struct dq_mint_args *args, int reason, int error)
{
	int32_t r;

	if (args->dm_reasonp != NULL) {
		r = reason;
		if (copyout(&r, args->dm_reasonp, sizeof(r)) != 0 && error == 0)
			error = EFAULT;
	}
	return (error);
}

int
dq_queue_mint(struct dq_queue *q, struct dq_mint_args *args, struct thread *td)
{
	struct dq_object *o;
	int error, reason;

	args->dm_object = 0;
	args->dm_fd = -1;
	if (args->dm_version != DQ_API_VERSION || args->dm_pad0 != 0)
		return (dq_mint_reason(args, DQ_REASON_VERSION, EINVAL));
	if (args->dm_kind != DQ_KIND_FILE)
		return (dq_mint_reason(args, DQ_REASON_KIND, EINVAL));
	error = dq_ident_validate(args->dm_kind, &args->dm_ident, &reason);
	if (error == 0)
		error = dq_policy_validate(&args->dm_policy, &reason);
	if (error != 0)
		return (dq_mint_reason(args, reason, error));

	o = malloc(sizeof(*o), M_DQ, M_WAITOK | M_ZERO);
	mtx_init(&o->o_mtx, "dq object", NULL, MTX_DEF);
	refcount_init(&o->o_refs, 1);	/* the mint's reference, dropped below */
	dq_queue_hold(q);
	o->o_queue = q;
	o->o_kind = args->dm_kind;
	o->o_state = DQ_OBJ_LIVE;
	o->o_ident = args->dm_ident;
	o->o_policy = args->dm_policy;
	rangelock_init(&o->o_rl);
	knlist_init_mtx(&o->o_sel.si_note, &o->o_mtx);

	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0 || q->q_nobjects >= dq_max_objects) {
		error = (q->q_flags & DQ_Q_CLOSING) != 0 ? ENXIO : ENOSPC;
		DQ_UNLOCK(q);
		o->o_retired = true;
		knlist_destroy(&o->o_sel.si_note);
		rangelock_destroy(&o->o_rl);
		dq_object_rele(o);
		return (dq_mint_reason(args, DQ_REASON_NONE, error));
	}
	o->o_id = ++q->q_next_object;
	RB_INSERT(dq_object_tree, &q->q_objects, o);
	q->q_nobjects++;
	q->q_stats.ds_objects_live++;
	q->q_stats.ds_objects_total++;
	DQ_UNLOCK(q);

	error = dq_file_install(td, o, &args->dm_policy, &args->dm_fd);
	if (error == 0) {
		args->dm_object = o->o_id;
		SDT_PROBE2(dq, , , mint, q, o);
	}
	/* The mint's own reference; the file holds its own, or retired it. */
	dq_object_rele(o);
	return (dq_mint_reason(args, DQ_REASON_NONE, error));
}

int
dq_queue_mint_observer(struct dq_queue *q, struct dq_observer_args *args,
    struct thread *td)
{
	struct dq_observer *ob;
	int error;

	args->do_fd = -1;
	if (args->do_version != DQ_API_VERSION ||
	    (args->do_flags & ~DQ_OBS_F_DATA) != 0 || args->do_pad0 != 0)
		return (EINVAL);
	ob = dq_observer_create(q, args->do_flags);
	if (ob == NULL)
		return (ENXIO);
	error = dq_observer_install(td, ob, &args->do_fd);
	return (error);
}

/*
 * A reply: copy the data in before any lock, find the event among those
 * delivered, check the body against the operation, hand it to the waiter.
 */
int
dq_queue_reply(struct dq_queue *q, const struct dq_reply *r, struct thread *td)
{
	struct dq_event_k key, *ev;
	struct dq_object *o;
	struct dq_read_body *rb;
	struct file *fp;
	void *buf;
	size_t len;
	uint32_t op;
	int error, reason;

	if (r->dr_version != DQ_API_VERSION || r->dr_pad0 != 0 ||
	    r->dr_errno < 0 || r->dr_errno > ELAST || r->dr_len > dq_max_io)
		return (EINVAL);
	len = r->dr_len;
	buf = NULL;
	if (len != 0) {
		buf = malloc(len, M_DQ, M_WAITOK);
		error = copyin(r->dr_data, buf, len);
		if (error != 0) {
			free(buf, M_DQ);
			return (error);
		}
	}

	key.ev_hdr.de_id = r->dr_id;
	DQ_LOCK(q);
	ev = RB_FIND(dq_inflight_tree, &q->q_inflight, &key);
	if (ev == NULL) {
		q->q_stats.ds_late_replies++;
		SDT_PROBE2(dq, , , reply__late, q, r->dr_id);
		DQ_UNLOCK(q);
		if (buf != NULL)
			free(buf, M_DQ);
		return (ESRCH);
	}
	KASSERT(ev->ev_state == DQ_EV_DELIVERED, ("dq: inflight event state"));
	op = ev->ev_hdr.de_op;
	o = ev->ev_object;
	error = 0;
	switch (op) {
	case DQ_OP_READ:
		rb = (struct dq_read_body *)((char *)&ev->ev_hdr +
		    sizeof(struct dq_event));
		if (len > rb->dr_len || (r->dr_errno != 0 && len != 0))
			error = EINVAL;
		break;
	case DQ_OP_GETATTR:
		if (r->dr_errno == 0) {
			if (len != sizeof(struct dq_ident_file) ||
			    dq_ident_validate(o->o_kind, buf, &reason) != 0)
				error = EINVAL;
		} else if (len != 0)
			error = EINVAL;
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error != 0) {
		DQ_UNLOCK(q);
		if (buf != NULL)
			free(buf, M_DQ);
		return (error);
	}
	RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
	q->q_stats.ds_inflight--;
	q->q_stats.ds_replies++;
	ev->ev_linked = false;
	ev->ev_reply = buf;
	ev->ev_replylen = len;
	ev->ev_errno = r->dr_errno;
	ev->ev_state = DQ_EV_REPLIED;
	cv_signal(&ev->ev_cv);
	SDT_PROBE4(dq, , , event__reply, q, ev, r->dr_errno, len);
	dq_observer_fanout_reply(q, r->dr_id, r->dr_errno, len);

	/* D89: tell the policies, with the object's file held, no lock. */
	fp = NULL;
	if (o != NULL) {
		DQO_LOCK(o);
		fp = o->o_fp;
		if (fp != NULL && !fhold(fp))
			fp = NULL;
		DQO_UNLOCK(o);
	}
	DQ_UNLOCK(q);
	dq_event_rele(ev);	/* the list reference */
	if (fp != NULL) {
		mac_file_notify_reply(q->q_cred, fp, op, r->dr_errno, len);
		fdrop(fp, td);
	}
	return (0);
}

int
dq_queue_setident(struct dq_queue *q, struct dq_setident_args *args)
{
	struct dq_object key, *o;
	int error, reason;

	if (args->dsi_version != DQ_API_VERSION || args->dsi_pad0 != 0)
		return (EINVAL);
	key.o_id = args->dsi_object;
	DQ_LOCK(q);
	o = RB_FIND(dq_object_tree, &q->q_objects, &key);
	if (o == NULL) {
		DQ_UNLOCK(q);
		return (ESRCH);
	}
	error = dq_ident_validate(o->o_kind, &args->dsi_ident, &reason);
	if (error != 0) {
		DQ_UNLOCK(q);
		return (error);
	}
	DQO_LOCK(o);
	o->o_ident = args->dsi_ident;
	dq_file_knote(o, NOTE_ATTRIB);
	DQO_UNLOCK(o);
	DQ_UNLOCK(q);
	return (0);
}

/*
 * After the mint only what the descriptor's installed state does not fix
 * may change: the deadline, the optional events and the cache mode.
 */
int
dq_queue_setpolicy(struct dq_queue *q, struct dq_setpolicy_args *args)
{
	struct dq_object key, *o;
	struct dq_policy *cur, *new;
	int error, reason;

	if (args->dsp_version != DQ_API_VERSION || args->dsp_pad0 != 0)
		return (EINVAL);
	new = &args->dsp_policy;
	error = dq_policy_validate(new, &reason);
	if (error != 0)
		return (error);
	key.o_id = args->dsp_object;
	DQ_LOCK(q);
	o = RB_FIND(dq_object_tree, &q->q_objects, &key);
	if (o == NULL) {
		DQ_UNLOCK(q);
		return (ESRCH);
	}
	DQO_LOCK(o);
	cur = &o->o_policy;
	if (new->dp_write != cur->dp_write || new->dp_exec != cur->dp_exec ||
	    new->dp_mmap_shared_write != cur->dp_mmap_shared_write ||
	    new->dp_lock != cur->dp_lock || new->dp_ioctl != cur->dp_ioctl ||
	    memcmp(&new->dp_rights, &cur->dp_rights, sizeof(cap_rights_t)) != 0) {
		DQO_UNLOCK(o);
		DQ_UNLOCK(q);
		return (EINVAL);
	}
	cur->dp_cache = new->dp_cache;
	cur->dp_deadline_ms = new->dp_deadline_ms;
	cur->dp_events = new->dp_events;
	DQO_UNLOCK(o);
	DQ_UNLOCK(q);
	return (0);
}

void
dq_queue_stats(struct dq_queue *q, struct dq_stats *st)
{

	DQ_LOCK(q);
	*st = q->q_stats;
	st->ds_version = DQ_API_VERSION;
	st->ds_queue_id = q->q_gid;
	st->ds_queue_depth = q->q_depth;
	st->ds_queue_current = q->q_count;
	st->ds_queue_highwater = q->q_highwater;
	st->ds_queue_bytes = q->q_bytes;
	st->ds_observers = q->q_nobservers;
	DQ_UNLOCK(q);
}

/* A controller may lower its depth below the system bound, never raise it. */
int
dq_queue_set_depth(struct dq_queue *q, uint32_t depth)
{

	if (depth == 0 || depth > dq_queue_depth)
		return (EINVAL);
	DQ_LOCK(q);
	q->q_depth = depth;
	DQ_UNLOCK(q);
	return (0);
}
