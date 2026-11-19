/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: asynchronous page operations and the pager object's
 * lifecycle (D102 as amended by D105 B1-B3, B10).
 *
 * READ_ASYNC (sendfile filling busy pages) and WRITE_ASYNC (writeback of
 * share-busied dirty pages) have no waiting requester.  The queue owns
 * them: each is on q_async with a deadline the queue enforces through one
 * callout armed to the earliest; a reply, the deadline, a revoke or a close
 * unlinks the event under q_mtx and hands it to dq_taskq, whose completion
 * takes the VM object write lock with no dq lock held and finishes the
 * pages: a written page is undirtied and deactivated, a refused one stays
 * dirty and is reactivated, a read page is filled and validated, a failed
 * read reaches sendfile through iodone.  One completion path, one lock
 * order (q_mtx, released, then the VM object lock).
 *
 * The pager object's teardown (B2): o_closing is set under the VM object
 * write lock first, so no new page I/O starts; the pending operations are
 * then completed with an error and waited for (dq's own work only), the
 * pages removed, and at close the dq object's VM reference dropped.  The
 * controller is never waited for (I11).
 */

#include "opt_dq.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_radix.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

static void	dq_async_task(void *arg, int pending);

void
dq_async_queue_init(struct dq_queue *q)
{

	TAILQ_INIT(&q->q_async);
	TAILQ_INIT(&q->q_roomq);
	callout_init_mtx(&q->q_callout, &q->q_mtx, 0);
}

/*
 * A room event (q_mtx held): a slot of the queue or async bytes or an
 * object's async count was freed, or memory with it, or the queue died.
 * An async post refused AGAIN may now go: msync's wait (dq_async_wait)
 * wakes, and the destroy tasks parked on q_roomq are enqueued.  No
 * polling looks for room (owner, 2026-11-19); this is the only way out.
 */
void
dq_queue_room_locked(struct dq_queue *q)
{
	struct dq_object *o;

	DQ_LOCK_ASSERT(q);
	q->q_roomgen++;
	if (!DQ_WAKE(DQ_WAKE_ASYNC_ROOM))
		return;
	wakeup(&q->q_roomgen);
	while ((o = TAILQ_FIRST(&q->q_roomq)) != NULL) {
		TAILQ_REMOVE(&q->q_roomq, o, o_roomlink);
		o->o_onroomq = false;
		DQO_LOCK(o);
		dq_object_destroy_kick_locked(o);
		DQO_UNLOCK(o);
	}
}

/*
 * An event the destroy task waits for (o_mtx held): queue it, or, while
 * a pass runs, have that pass run again.
 */
void
dq_object_destroy_kick_locked(struct dq_object *o)
{

	DQO_LOCK_ASSERT(o);
	switch (o->o_destroy_state) {
	case DQ_DESTROY_IDLE:
		o->o_destroy_state = DQ_DESTROY_QUEUED;
		taskqueue_enqueue(dq_taskq, &o->o_destroy);
		break;
	case DQ_DESTROY_RUNNING:
		o->o_destroy_state = DQ_DESTROY_AGAIN;
		break;
	default:
		break;
	}
}

/* The page deadline (o_mtx held, callout_init_mtx). */
static void
dq_object_destroy_deadline(void *arg)
{

	dq_object_destroy_kick_locked(arg);
}

/* A pass that did not finish (no lock held): idle, or run again. */
static void
dq_object_destroy_pass_end(struct dq_object *o)
{

	DQO_LOCK(o);
	if (o->o_destroy_state == DQ_DESTROY_AGAIN) {
		o->o_destroy_state = DQ_DESTROY_QUEUED;
		taskqueue_enqueue(dq_taskq, &o->o_destroy);
	} else
		o->o_destroy_state = DQ_DESTROY_IDLE;
	DQO_UNLOCK(o);
}

/* Record that o's async post found no room (q_mtx held). */
static void
dq_async_noroom_locked(struct dq_queue *q, struct dq_object *o)
{

	DQ_LOCK_ASSERT(q);
	o->o_roomgen = q->q_roomgen;
}

/*
 * A page never waits forever (B1): the policy's deadline, else the default,
 * else DQ_PAGE_DEADLINE_MS.
 */
sbintime_t
dq_page_deadline(struct dq_object *o)
{
	int ms;

	DQO_LOCK(o);
	ms = o->o_policy.dp_deadline_ms;
	DQO_UNLOCK(o);
	if (ms == DQ_DEADLINE_DEFAULT || ms == 0)
		ms = dq_default_deadline_ms;
	if (ms <= 0)
		ms = DQ_PAGE_DEADLINE_MS;
	return (sbinuptime() + (sbintime_t)ms * SBT_1MS);
}

static void
dq_async_arm_locked(struct dq_queue *q, sbintime_t deadline)
{

	DQ_LOCK_ASSERT(q);
	if (q->q_callout_at != 0 && q->q_callout_at <= deadline)
		return;
	q->q_callout_at = deadline;
	callout_reset_sbt(&q->q_callout, deadline, 0, dq_async_timeout, q,
	    C_ABSOLUTE);
}

static void
dq_async_handoff_locked(struct dq_queue *q, struct dq_async *da)
{

	DQ_LOCK_ASSERT(q);
	KASSERT(da->da_posted, ("dq: async %p handed off twice", da));
	TAILQ_REMOVE(&q->q_async, da, da_link);
	da->da_posted = false;
	taskqueue_enqueue(dq_taskq, &da->da_task);
}

/*
 * The controller answered (dq_queue_reply did the unlinking and attached
 * the reply).  The completion runs in the task, never in the ioctl.
 */
void
dq_async_replied_locked(struct dq_queue *q, struct dq_async *da)
{

	da->da_listref = true;
	dq_async_handoff_locked(q, da);
}

/*
 * Fail a posted async operation: deadline, revoke, close or queue close.
 * interrupt: tell the controller, if it already read the event, that the
 * answer is no longer wanted (as a waiter that gives up does).
 */
static void
dq_async_fail_locked1(struct dq_queue *q, struct dq_async *da, bool interrupt)
{
	struct dq_event_k *ev;

	DQ_LOCK_ASSERT(q);
	if (!da->da_posted)
		return;
	ev = da->da_ev;
	if (ev->ev_linked) {
		if (ev->ev_state == DQ_EV_PENDING) {
			TAILQ_REMOVE(&q->q_pending, ev, ev_link);
			q->q_count--;
			q->q_bytes -= ev->ev_size;
			dq_queue_slots_freed(q, 1);
		} else {
			RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
			q->q_stats.ds2_inflight--;
			if (interrupt && (q->q_flags & DQ_Q_CLOSING) == 0)
				da->da_interrupt = true;
		}
		ev->ev_linked = false;
		da->da_listref = true;
	}
	ev->ev_state = DQ_EV_FAILED;
	ev->ev_errno = EIO;
	dq_async_handoff_locked(q, da);
}

/* Revoke and queue close (dq_event_fail_locked): no INTERRUPT. */
void
dq_async_fail_locked(struct dq_queue *q, struct dq_async *da)
{

	dq_async_fail_locked1(q, da, false);
}

/*
 * The queue's deadline callout (B1), with q_mtx held: every expired
 * operation goes to the task; the callout is re-armed to the next.
 */
void
dq_async_timeout(void *arg)
{
	struct dq_queue *q;
	struct dq_async *da, *datmp;
	sbintime_t now, next;

	q = arg;
	DQ_LOCK_ASSERT(q);
	q->q_callout_at = 0;
	now = sbinuptime();
	next = 0;
	TAILQ_FOREACH_SAFE(da, &q->q_async, da_link, datmp) {
		if (da->da_deadline <= now) {
			q->q_stats.ds2_async_deadlines++;
			SDT_PROBE2(dq, , , event__deadline, q, da->da_ev);
			dq_async_fail_locked1(q, da, true);
		} else if (next == 0 || da->da_deadline < next)
			next = da->da_deadline;
	}
	if (next != 0)
		dq_async_arm_locked(q, next);
}

/*
 * Post a READ_ASYNC (write false: the pages are exclusive-busy, the object
 * unlocked) or a WRITE_ASYNC (write true: share-busied pages, called from
 * putpages with the object write-locked) for the run ma[0..count), which
 * covers [offset, offset + len) of the file (B3).  M_NOWAIT throughout, no
 * EDEADLK scan (the page daemon owns no queue), no quota sleeps: an
 * allocation failure, a full queue or a bound answers VM_PAGER_AGAIN, a
 * closing or revoked object or queue VM_PAGER_ERROR, a posted operation
 * VM_PAGER_PEND.  The page data is copied with the object lock dropped
 * (the pages are busy and paging is in progress, as the swap and vnode
 * pagers rely on), through pmap_quick_enter_page.  A WRITE_ASYNC's caller
 * is the kernel: the write-back is the kernel's, not a requester's, and
 * no process lock is taken under the VM object lock.
 */
int
dq_async_post(struct dq_object *o, vm_object_t obj, vm_page_t *ma, int count,
    off_t offset, size_t len, bool write,
    void (*iodone)(void *, vm_page_t *, int, int), void *arg)
{
	struct dq_queue *q;
	struct dq_event_k *ev;
	struct dq_async *da;
	struct dq_write_body *wb;
	struct dq_read_body *rb;
	void *va;
	size_t bodylen, n, off;
	char *body;
	int error __diagused, i, rv;

	q = o->o_queue;
	if (write)
		VM_OBJECT_ASSERT_WLOCKED(obj);
	bodylen = write ? roundup2(sizeof(*wb) + len, 8) : sizeof(*rb);
	ev = dq_event_alloc_flags(o, write ? DQ_OP_WRITE_ASYNC :
	    DQ_OP_READ_ASYNC, NULL, bodylen, curthread, write, M_NOWAIT);
	da = ev == NULL ? NULL : malloc(sizeof(*da) +
	    (size_t)count * sizeof(vm_page_t), M_DQ, M_NOWAIT | M_ZERO);
	if (da == NULL) {
		/* Memory: a completion frees what this would have taken. */
		if (ev != NULL)
			dq_event_rele(ev);
		DQ_LOCK(q);
		dq_async_noroom_locked(q, o);
		DQ_UNLOCK(q);
		return (VM_PAGER_AGAIN);
	}
	body = (char *)&ev->ev_hdr + sizeof(struct dq_event);
	if (write) {
		wb = (struct dq_write_body *)body;
		wb->dw_offset = offset;
		wb->dw_len = len;
		wb->dw_flags = 0;
		VM_OBJECT_WUNLOCK(obj);
		for (i = 0, off = 0; i < count && off < len; i++,
		    off += PAGE_SIZE) {
			n = MIN(PAGE_SIZE, len - off);
			va = pmap_quick_enter_page(ma[i]);
			memcpy((char *)(wb + 1) + off, va, n);
			pmap_quick_remove_page(va);
		}
		VM_OBJECT_WLOCK(obj);
	} else {
		rb = (struct dq_read_body *)body;
		rb->dr_offset = offset;
		rb->dr_len = len;
		rb->dr_pad0 = 0;
	}
	ev->ev_waited = true;
	ev->ev_async = da;
	da->da_ev = ev;
	da->da_obj = obj;
	da->da_offset = offset;
	da->da_invalgen = dq_object_invalgen(o);
	da->da_len = len;
	da->da_write = write;
	da->da_iodone = iodone;
	da->da_arg = arg;
	da->da_count = count;
	memcpy(da->da_pages, ma, (size_t)count * sizeof(vm_page_t));
	TASK_INIT(&da->da_task, 0, dq_async_task, da);
	da->da_deadline = ev->ev_deadline = dq_page_deadline(o);
	if (!write)
		vm_object_pip_add(obj, count);

	rv = VM_PAGER_PEND;
	DQ_LOCK(q);
	DQO_LOCK(o);
	/*
	 * After the last close only write-back is posted (the deferred
	 * close flushes); nothing reaches past the pager's size, which a
	 * shrink moves before it fails what already does (dq_object_cut).
	 */
	if ((q->q_flags & DQ_Q_CLOSING) != 0 || o->o_state != DQ_OBJ_LIVE ||
	    o->o_closing || (!write && o->o_closed) ||
	    offset + (off_t)len > o->o_vmsize)
		rv = VM_PAGER_ERROR;
	else if (q->q_count >= q->q_depth ||
	    q->q_async_bytes + len > dq_max_inflight_bytes ||
	    o->o_async >= dq_max_inflight_per_object) {
		rv = VM_PAGER_AGAIN;
		dq_async_noroom_locked(q, o);
	}
	else {
		o->o_async++;
		if (write)
			o->o_awrites++;
	}
	DQO_UNLOCK(o);
	if (rv == VM_PAGER_PEND) {
		error = dq_event_enqueue_locked(q, ev);
		KASSERT(error == 0, ("dq: async post past the depth"));
		q->q_async_bytes += len;
		q->q_nasync++;
		da->da_posted = true;
		TAILQ_INSERT_TAIL(&q->q_async, da, da_link);
		dq_async_arm_locked(q, da->da_deadline);
	}
	DQ_UNLOCK(q);
	if (rv != VM_PAGER_PEND) {
		if (!write)
			vm_object_pip_wakeupn(obj, count);
		ev->ev_async = NULL;
		dq_event_rele(ev);
		free(da, M_DQ);
	}
	return (rv);
}

/*
 * The completion, in dq_taskq with no dq lock held: finish the pages under
 * the VM object write lock, then account.  A written page is clean only
 * for the bytes the controller took; a partial write leaves the pages it
 * did not cover dirty and active (they are written again later).
 */
static void
dq_async_complete(struct dq_async *da)
{
	struct dq_event_k *ev;
	struct dq_object *o;
	struct dq_queue *q;
	struct dq_data *reply;
	struct dq_interrupt_body ib;
	struct dq_event_k *iev;
	vm_object_t obj;
	vm_page_t m;
	uint64_t written;
	size_t rlen;
	int error, i, ndone;
	struct dq_errrec *er;

	ev = da->da_ev;
	o = ev->ev_object;
	q = o->o_queue;
	obj = da->da_obj;
	reply = ev->ev_reply;
	error = ev->ev_state == DQ_EV_REPLIED ? ev->ev_errno : EIO;
	ndone = 0;
	if (da->da_write) {
		written = 0;
		if (error == 0 && reply != NULL)
			written = ((const struct dq_write_reply *)
			    reply->dd_bytes)->dwr_written;
		ndone = written >= da->da_len ? da->da_count :
		    (int)(written / PAGE_SIZE);
		VM_OBJECT_WLOCK(obj);
		for (i = 0; i < da->da_count; i++) {
			m = da->da_pages[i];
			if (i < ndone) {
				vm_page_undirty(m);
				vm_page_deactivate_noreuse(m);
			} else
				vm_page_activate(m);
			vm_page_sunbusy(m);
		}
		/*
		 * vm_object_page_clean counted these pages written when it
		 * posted them (PEND) and moved cleangeneration on; pages left
		 * dirty by a failure would then be skipped by the next msync,
		 * which would report success without writing them.  Mark the
		 * object possibly dirty again.
		 */
		if (ndone < da->da_count)
			vm_object_set_writeable_dirty(obj);
		vm_object_pip_wakeupn(obj, da->da_count);
		VM_OBJECT_WUNLOCK(obj);
		if (written != 0) {
			/* Vnode writeback raises it too (B7). */
			DQO_LOCK(o);
			dq_file_knote(o, NOTE_WRITE);
			DQO_UNLOCK(o);
		}
	} else {
		/*
		 * As getpages: a short reply inside the pager's size is an
		 * error, not cached zeros; an INVALIDATE while the event was
		 * out (it skipped these busy pages) makes the data suspect,
		 * so nothing is validated and sendfile gets EIO; the bytes
		 * past the size are zeros.  dd_len is all data: the reply
		 * path refuses DQ_REPLY_F_POSTOP for READ_ASYNC (only READ,
		 * WRITE, FALLOCATE and FSPACECTL carry a block), so dd_len
		 * equals dd_plen here.
		 */
		rlen = reply != NULL ? reply->dd_len : 0;
		if (error == 0 && rlen < da->da_len &&
		    da->da_offset + (off_t)rlen < dq_object_vmsize(o))
			error = EIO;
		if (error == 0 && dq_object_invalgen(o) != da->da_invalgen)
			error = EIO;
		if (error == 0) {
			dq_pager_fill_run(da->da_pages, da->da_count,
			    reply != NULL ? reply->dd_bytes : NULL, rlen);
			dq_pager_zero_past(o, da->da_pages, da->da_count,
			    da->da_offset);
			for (i = 0; i < da->da_count; i++) {
				if (da->da_pages[i] != bogus_page)
					vm_page_valid(da->da_pages[i]);
			}
		}
		/* The requested pages stay busy for iodone (N8). */
		da->da_iodone(da->da_arg, da->da_pages, da->da_count,
		    error != 0 ? EIO : 0);
		vm_object_pip_wakeupn(obj, da->da_count);
	}
	/*
	 * A task never sleeps for memory: the INTERRUPT is M_NOWAIT, and a
	 * failed allocation is counted (the controller's late reply gets
	 * ESRCH, which tells it the same).
	 */
	iev = NULL;
	if (da->da_interrupt) {
		ib.din_id = ev->ev_hdr.de_id;
		iev = dq_event_alloc_flags(o, DQ_OP_INTERRUPT, &ib, sizeof(ib),
		    NULL, true, M_NOWAIT);
	}
	DQ_LOCK(q);
	if (da->da_interrupt) {
		if (iev == NULL)
			q->q_stats.ds2_task_drops++;
		else if ((q->q_flags & DQ_Q_CLOSING) == 0)
			(void)dq_event_enqueue_locked(q, iev);
	}
	q->q_async_bytes -= da->da_len;
	q->q_nasync--;
	/*
	 * The object's count drops under q_mtx too, so the room event below
	 * follows every bound an AGAIN looked at (dq_async_post).
	 */
	DQO_LOCK(o);
	KASSERT(o->o_async > 0, ("dq: async count"));
	o->o_async--;
	if (da->da_write) {
		o->o_awrites--;
		if (ndone < da->da_count) {
			o->o_async_errs++;
			er = &o->o_errring[o->o_async_errs % DQ_ERRRING];
			er->er_gen = o->o_async_errs;
			er->er_start = da->da_offset + (off_t)ndone * PAGE_SIZE;
			er->er_end = da->da_offset + (off_t)da->da_len;
		}
	}
	if (da->da_shrink) {
		KASSERT(o->o_shrinkwait > 0, ("dq: shrink wait count"));
		o->o_shrinkwait--;
	}
	o->o_async_done++;
	cv_broadcast(&o->o_async_cv);
	/* The destroy task waits for the last of them. */
	if (o->o_async == 0 && DQ_WAKE(DQ_WAKE_DESTROY))
		dq_object_destroy_kick_locked(o);
	DQO_UNLOCK(o);
	dq_queue_room_locked(q);
	DQ_UNLOCK(q);
	if (iev != NULL)
		dq_event_rele(iev);
	if (da->da_listref)
		dq_event_rele(ev);
	ev->ev_async = NULL;
	dq_event_rele(ev);		/* the allocation's; frees the reply */
	free(da, M_DQ);
}

static void
dq_async_task(void *arg, int pending __unused)
{

	dq_async_complete(arg);
}

/*
 * Wait for dq's own events with the VM object unlocked, event-driven: the
 * deadline (the caller's, a page deadline) is the only timeout.  all:
 * until no WRITE_ASYNC of the object is pending (msync(MS_SYNC), fsync),
 * woken by each completion.  Otherwise, after the async bounds answered
 * AGAIN, until the room event that frees what the post lacked (a slot, async
 * bytes, the object's async count, memory; dq_queue_room_locked) or the
 * queue's death.  Non-interruptible, as a disk wait; false once the
 * deadline has passed.
 */
bool
dq_async_wait(struct dq_object *o, sbintime_t deadline, bool all)
{
	struct dq_queue *q;
	int error;
	bool ok;

	ok = true;
	if (!all) {
		q = o->o_queue;
		DQ_LOCK(q);
		while (q->q_roomgen == o->o_roomgen &&
		    (q->q_flags & DQ_Q_CLOSING) == 0) {
			error = msleep_sbt(&q->q_roomgen, &q->q_mtx, PVM,
			    "dqroom", deadline, 0, C_ABSOLUTE);
			if (error == EWOULDBLOCK) {
				ok = false;
				break;
			}
		}
		DQ_UNLOCK(q);
		return (ok);
	}
	DQO_LOCK(o);
	while (o->o_awrites > 0) {
		error = cv_timedwait_sbt(&o->o_async_cv, &o->o_mtx, deadline,
		    0, C_ABSOLUTE);
		if (error == EWOULDBLOCK && o->o_awrites > 0) {
			ok = false;
			break;
		}
	}
	DQO_UNLOCK(o);
	return (ok);
}

/*
 * A shrink (dq_object_cut, q_mtx held): the async operations of o that
 * reach past newsize are failed and counted in o_shrinkwait, which the
 * shrink waits on.  A failed write-back leaves its pages dirty; one inside
 * the new size is posted again later, clipped.
 */
void
dq_async_cut_locked(struct dq_queue *q, struct dq_object *o, off_t newsize)
{
	struct dq_async *da, *datmp;

	DQ_LOCK_ASSERT(q);
	TAILQ_FOREACH_SAFE(da, &q->q_async, da_link, datmp) {
		if (da->da_ev->ev_object != o ||
		    da->da_offset + (off_t)da->da_len <= newsize)
			continue;
		DQO_LOCK(o);
		o->o_shrinkwait++;
		DQO_UNLOCK(o);
		da->da_shrink = true;
		dq_async_fail_locked1(q, da, true);
	}
}

/* Complete every posted async operation of the object with an error. */
void
dq_object_cancel_async(struct dq_object *o)
{
	struct dq_queue *q;
	struct dq_async *da, *datmp;

	q = o->o_queue;
	DQ_LOCK(q);
	TAILQ_FOREACH_SAFE(da, &q->q_async, da_link, datmp) {
		if (da->da_ev->ev_object == o)
			dq_async_fail_locked1(q, da, true);
	}
	DQ_UNLOCK(q);
}

/*
 * The controller-side users of the pager object (revoke, queue close,
 * INVALIDATE, SETIDENT) may run while the descriptor closes; they count
 * themselves so dq_close drops the dq object's VM reference only after
 * them.  False once it has been dropped.
 */
bool
dq_object_vm_hold(struct dq_object *o, vm_object_t *objp)
{

	DQO_LOCK(o);
	if (o->o_vmdropped || o->o_object == NULL) {
		DQO_UNLOCK(o);
		return (false);
	}
	o->o_vmusers++;
	*objp = o->o_object;
	DQO_UNLOCK(o);
	return (true);
}

void
dq_object_vm_drop(struct dq_object *o)
{

	DQO_LOCK(o);
	KASSERT(o->o_vmusers > 0, ("dq: vm users"));
	if (--o->o_vmusers == 0) {
		wakeup(&o->o_vmusers);
		if (DQ_WAKE(DQ_WAKE_DESTROY))
			dq_object_destroy_kick_locked(o);
	}
	DQO_UNLOCK(o);
}

/*
 * B2, in this order: o_closing under the VM object write lock (no new page
 * I/O: putpages and getpages answer VM_PAGER_ERROR), the pending async
 * operations completed with an error and waited for (dq's own work; td may
 * be NULL here), every page removed with pmap_remove_all (a mapping sees
 * the change on its next access; wired pages are handled by
 * vm_object_page_remove), and for a close the dq object's VM reference
 * dropped once no controller-side user holds it.  Revoke and queue close
 * use it without close: the VM object lives on with its mappings, which
 * now fault SIGBUS.
 */
void
dq_object_vm_teardown(struct dq_object *o, bool close)
{
	vm_object_t obj;

	if (close) {
		obj = o->o_object;
		if (obj == NULL)
			return;
	} else if (!dq_object_vm_hold(o, &obj))
		return;
	VM_OBJECT_WLOCK(obj);
	DQO_LOCK(o);
	o->o_closing = true;
	DQO_UNLOCK(o);
	VM_OBJECT_WUNLOCK(obj);
	dq_object_cancel_async(o);
	DQO_LOCK(o);
	while (o->o_async > 0)
		cv_wait(&o->o_async_cv, &o->o_mtx);
	DQO_UNLOCK(o);
	VM_OBJECT_WLOCK(obj);
	vm_object_page_remove(obj, 0, 0, 0);
	VM_OBJECT_WUNLOCK(obj);
	if (!close) {
		dq_object_vm_drop(o);
		return;
	}
	DQO_LOCK(o);
	o->o_vmdropped = true;
	while (o->o_vmusers > 0)
		msleep(&o->o_vmusers, &o->o_mtx, PVM, "dqvmu", 0);
	DQO_UNLOCK(o);
	vm_object_deallocate(obj);
}

/*
 * B10: the VM object's size follows the presented size, in the shape of
 * vnode_pager_setsize and shm_dotruncate_locked: a shrink removes the
 * pages past the new end and zeroes the tail of the new last page, after
 * failing the page operations that hold pages past it (dq_object_cut), so
 * it never sleeps on a page only the controller's reply would free; a
 * growth sets the size and drops the old last page if it is partial, clean
 * and idle, since its zeroed tail is now inside the file and only the
 * controller knows what is there.  Called after SETIDENT, a GETATTR reply,
 * an extending WRITE, FALLOCATE, SETATTR{size} and a post-operation size,
 * never with a dq lock held.
 *
 * The target is the presented size as it is now, read under the VM object
 * lock (review 1 H1), never a size the caller saw: two callers that race
 * each sync to the latest di_size, whichever runs last, so the VM object
 * cannot end smaller than the presented size because a stale caller ran
 * second.
 */
void
dq_object_sync_vmsize(struct dq_object *o)
{
	vm_object_t obj;
	vm_pindex_t nobjsize;
	vm_page_t m;
	off_t newsize;
	int base, start;
	bool busy;

	if (!dq_object_vm_hold(o, &obj))
		return;
	VM_OBJECT_WLOCK(obj);
	DQO_LOCK(o);
	newsize = (off_t)o->o_ident.di_size;
	DQO_UNLOCK(o);
	nobjsize = OFF_TO_IDX((uint64_t)newsize + PAGE_MASK);
	if (newsize == o->o_vmsize) {
		VM_OBJECT_WUNLOCK(obj);
		dq_object_vm_drop(o);
		return;
	}
	if (newsize > o->o_vmsize) {
		if ((o->o_vmsize & PAGE_MASK) != 0) {
			m = vm_page_lookup(obj, OFF_TO_IDX(o->o_vmsize));
			if (m != NULL && vm_page_tryxbusy(m) != 0) {
				/* Write-protect first: it harvests the
				   modified bit into m->dirty. */
				if (!vm_page_wired(m) &&
				    vm_page_try_remove_write(m) &&
				    m->dirty == 0 && vm_page_try_remove_all(m))
					vm_page_free(m);
				else
					vm_page_xunbusy(m);
			}
		}
		DQO_LOCK(o);
		o->o_vmsize = newsize;
		DQO_UNLOCK(o);
		obj->size = nobjsize;
		VM_OBJECT_WUNLOCK(obj);
		dq_object_vm_drop(o);
		return;
	}

	/*
	 * A shrink.  The pager's size moves first, so no new page-in or
	 * write-back reaches past it (the posts test it under q_mtx and
	 * o_mtx); then the operations already holding pages past it are
	 * failed through their normal completion and the async ones waited
	 * for (dq's own work, never the controller's); then the pages go.
	 */
	DQO_LOCK(o);
	o->o_vmsize = newsize;
	DQO_UNLOCK(o);
	VM_OBJECT_WUNLOCK(obj);
	dq_object_cut(o, newsize, IDX_TO_OFF(nobjsize));
	DQO_LOCK(o);
	while (o->o_shrinkwait > 0)
		cv_wait(&o->o_async_cv, &o->o_mtx);
	DQO_UNLOCK(o);
	VM_OBJECT_WLOCK(obj);
	if (o->o_vmsize == newsize) {
		/*
		 * A busy page left here belongs to a fault whose READ was
		 * failed and which is unwinding, or to the page daemon for a
		 * moment: vm_object_page_remove's sleep on it is not a wait
		 * for the controller.
		 */
		if (nobjsize < obj->size)
			vm_object_page_remove(obj, nobjsize, obj->size, 0);
		base = newsize & PAGE_MASK;
		m = base != 0 ? vm_page_lookup(obj, OFF_TO_IDX(newsize)) : NULL;
		if (m != NULL) {
			/*
			 * The new last page.  Busy (a page-in in flight, which
			 * zeroes past the size itself; a write-back inside the
			 * new size): zero the tail without sleeping.
			 */
			busy = vm_page_tryxbusy(m) == 0;
			if (!busy && !vm_page_none_valid(m)) {
				pmap_zero_page_area(m, base, PAGE_SIZE - base);
				vm_page_set_valid_range(m, base,
				    PAGE_SIZE - base);
				start = roundup2(base, DEV_BSIZE);
				if (start < PAGE_SIZE)
					vm_page_clear_dirty(m, start,
					    PAGE_SIZE - start);
			} else if (busy && vm_page_all_valid(m))
				pmap_zero_page_area(m, base, PAGE_SIZE - base);
			if (!busy)
				vm_page_xunbusy(m);
		}
	}
	obj->size = OFF_TO_IDX((uint64_t)o->o_vmsize + PAGE_MASK);
	VM_OBJECT_WUNLOCK(obj);
	dq_object_vm_drop(o);
}

/*
 * INVALIDATE (B2): the clean cached pages of [offset, offset + len), rounded
 * out to pages, are dropped and unmapped, so the next access faults or
 * reads them again; a dirty page of a shared mapping is kept and written
 * back.  This is vm_object_page_remove(OBJPR_CLEANONLY) except that a busy
 * page is skipped instead of slept on: it is being read from the
 * controller (and will hold what the controller answers) or written back
 * to it (dirty, so kept anyway), and the controller issuing the push must
 * never sleep on a page only its own reply can unbusy.  len 0 is to the
 * end.
 */
void
dq_object_invalidate(struct dq_object *o, off_t offset, off_t len)
{
	struct pctrie_iter pages;
	vm_object_t obj;
	vm_pindex_t start, end;
	vm_page_t p;

	if (!dq_object_vm_hold(o, &obj))
		return;
	start = OFF_TO_IDX(offset);
	end = len == 0 ? 0 : OFF_TO_IDX((uint64_t)offset + len + PAGE_MASK);
	VM_OBJECT_WLOCK(obj);
	/*
	 * Before the walk: a page-in already out (its page busy, skipped
	 * below) sees the generation move and reads again, so no byte from
	 * before the change is cached.
	 */
	DQO_LOCK(o);
	o->o_invalgen++;
	DQO_UNLOCK(o);
	if (obj->resident_page_count == 0)
		goto out;
	vm_page_iter_limit_init(&pages, obj, end);
	for (p = vm_radix_iter_lookup_ge(&pages, start); p != NULL;
	    p = vm_radix_iter_step(&pages)) {
		if (vm_page_tryxbusy(p) == 0)
			continue;
		if (vm_page_wired(p)) {
			/* sendfile in flight or a wired mapping: unmap only. */
			pmap_remove_all(p);
			vm_page_xunbusy(p);
			continue;
		}
		if (!vm_page_none_valid(p)) {
			if (!vm_page_try_remove_write(p)) {
				pmap_remove_all(p);
				vm_page_xunbusy(p);
				continue;
			}
			if (p->dirty != 0) {
				vm_page_xunbusy(p);
				continue;
			}
		}
		if (!vm_page_try_remove_all(p)) {
			pmap_remove_all(p);
			vm_page_xunbusy(p);
			continue;
		}
		vm_page_iter_free(&pages, p);
	}
out:
	VM_OBJECT_WUNLOCK(obj);
	dq_object_vm_drop(o);
}

/*
 * The deferred close (A).  The last reference to a served object (a
 * mapping holds one, so this is after the last munmap) must not lose what a
 * program wrote through MAP_SHARED, as a real file does not: dq_close stops
 * new page-ins (o_closed) and returns at once; this task, on dq_taskq,
 * posts WRITE_ASYNC for every dirty page run until no async operation of
 * the object is pending (a pending sendfile READ_ASYNC keeps its pages
 * until its own completion) and no dirty page is left unposted, or until
 * the page deadline; then pages are removed (a page whose write-back
 * failed or expired is dropped and counted in ds2_close_dropped), the dq
 * object's VM reference dropped, the object retired (its CLOSE record, if
 * asked for, follows the write-backs) and the file's reference released.
 * A pass never sleeps for dq's own work: the completions it waits for run
 * on the same task queue (two threads).  When the object has not settled
 * the pass returns, and the event it waits for kicks it again, with no
 * polling (owner, 2026-11-19): the completion that drops o_async to 0 or
 * the release that drops o_vmusers to 0, or a room event for a write-back
 * refused AGAIN, a busy page skipped, or a CLOSE record short of memory
 * (q_roomq, dq_queue_room_locked).  The page deadline, the caller's, is
 * armed as the one timeout (o_destroy_co): then the task settles with
 * what is left.  A kick never queues the task while a pass runs
 * (o_destroy_state): dq_taskq's second thread would run it at the same
 * time.
 */

/*
 * Post write-back for the dirty runs nobody is writing yet, without
 * sleeping: a busy page is skipped (its write-back is pending, or it is
 * busy for a moment) and looked at again next time.  The VM object is
 * write-locked; vm_pageout_flush may drop it.  True when a run was
 * refused for the bounds (AGAIN) and must be retried.
 */
static bool
dq_pager_flush_nowait(struct dq_object *o, vm_object_t obj, bool *skipped)
{
	struct pctrie_iter pages;
	vm_page_t ma[32], p;
	vm_pindex_t idx;
	int count, maxc;
	bool again;

	VM_OBJECT_ASSERT_WLOCKED(obj);
	maxc = MIN((int)nitems(ma), vm_pageout_page_count);
	again = *skipped = false;
	idx = 0;
	for (;;) {
		vm_page_iter_init(&pages, obj);
		p = vm_radix_iter_lookup_ge(&pages, idx);
		if (p == NULL)
			break;
		idx = p->pindex + 1;
		if (!vm_page_all_valid(p))
			continue;
		if (vm_page_tryxbusy(p) == 0) {
			*skipped = true;
			continue;
		}
		pmap_remove_write(p);
		if (p->dirty == 0) {
			vm_page_xunbusy(p);
			continue;
		}
		ma[0] = p;
		for (count = 1; count < maxc; count++) {
			p = vm_page_lookup(obj, ma[0]->pindex + count);
			if (p == NULL || !vm_page_all_valid(p) ||
			    vm_page_tryxbusy(p) == 0)
				break;
			pmap_remove_write(p);
			if (p->dirty == 0) {
				vm_page_xunbusy(p);
				break;
			}
			ma[count] = p;
		}
		idx = ma[0]->pindex + count;
		o->o_again = false;
		(void)vm_pageout_flush(ma, count, 0, NULL);
		if (o->o_again)
			again = true;
	}
	return (again);
}

/*
 * Park the destroy task until a room event (q_roomq), unless one came
 * since the pass began (roomgen), and arm the page deadline as its one
 * timeout.
 */
static void
dq_object_destroy_park(struct dq_object *o, uint64_t roomgen)
{
	struct dq_queue *q;
	sbintime_t now;

	q = o->o_queue;
	DQ_LOCK(q);
	DQO_LOCK(o);
	if (q->q_roomgen != roomgen || (q->q_flags & DQ_Q_CLOSING) != 0) {
		/* Room came meanwhile: run again at once. */
		o->o_destroy_state = DQ_DESTROY_AGAIN;
	} else if (!o->o_onroomq) {
		TAILQ_INSERT_TAIL(&q->q_roomq, o, o_roomlink);
		o->o_onroomq = true;
	}
	now = sbinuptime();
	if (o->o_destroy_deadline > now)
		callout_reset_sbt(&o->o_destroy_co, o->o_destroy_deadline, 0,
		    dq_object_destroy_deadline, o, C_ABSOLUTE);
	else
		o->o_destroy_state = DQ_DESTROY_AGAIN;
	DQO_UNLOCK(o);
	DQ_UNLOCK(q);
	dq_object_destroy_pass_end(o);
}

static void
dq_object_destroy_task(void *arg, int pending __unused)
{
	struct pctrie_iter pages;
	struct dq_object *o;
	struct dq_queue *q;
	struct dq_event_k *closeev;
	vm_object_t obj;
	vm_page_t p;
	uint64_t dropped, roomgen;
	bool again, flush, skipped, wantclose;

	o = arg;
	q = o->o_queue;
	obj = o->o_object;
	DQO_LOCK(o);
	KASSERT(o->o_destroy_state == DQ_DESTROY_QUEUED,
	    ("dq: destroy task state %d", o->o_destroy_state));
	o->o_destroy_state = DQ_DESTROY_RUNNING;
	DQO_UNLOCK(o);
	DQ_LOCK(q);
	if (o->o_onroomq) {
		TAILQ_REMOVE(&q->q_roomq, o, o_roomlink);
		o->o_onroomq = false;
	}
	roomgen = q->q_roomgen;
	DQ_UNLOCK(q);
	if (o->o_destroy_deadline == 0)
		o->o_destroy_deadline = dq_page_deadline(o);
	DQO_LOCK(o);
	flush = o->o_state == DQ_OBJ_LIVE && !o->o_closing &&
	    (q->q_flags & DQ_Q_CLOSING) == 0 &&
	    sbinuptime() < o->o_destroy_deadline;
	DQO_UNLOCK(o);
	again = skipped = false;
	VM_OBJECT_WLOCK(obj);
	if (flush)
		again = dq_pager_flush_nowait(o, obj, &skipped);
	DQO_LOCK(o);
	if (o->o_async != 0 || o->o_vmusers != 0) {
		/* The completion or release that ends them kicks us. */
		DQO_UNLOCK(o);
		VM_OBJECT_WUNLOCK(obj);
		dq_object_destroy_pass_end(o);
		return;
	}
	if (flush && (again || skipped)) {
		DQO_UNLOCK(o);
		VM_OBJECT_WUNLOCK(obj);
		dq_object_destroy_park(o, roomgen);
		return;
	}
	/*
	 * Settled: nothing pending, so the dirty pages left were refused or
	 * expired.  From here no page I/O starts (o_closing) and no
	 * controller-side user can take the object (o_vmdropped).
	 */
	o->o_closing = true;
	o->o_vmdropped = true;
	wantclose = (o->o_policy.dp_events & DQ_EVENTS_CLOSE) != 0;
	DQO_UNLOCK(o);
	/*
	 * The CLOSE record is allocated first, M_NOWAIT (a task never sleeps
	 * for memory): without it nothing irreversible is done yet, and the
	 * task comes back.
	 */
	if (wantclose && o->o_closeev == NULL) {
		o->o_closeev = dq_event_alloc_flags(o, DQ_OP_CLOSE, NULL, 0,
		    NULL, true, M_NOWAIT);
		if (o->o_closeev == NULL) {
			VM_OBJECT_WUNLOCK(obj);
			dq_object_destroy_park(o, roomgen);
			return;
		}
	}
	/*
	 * The pages go.  None of dq's own I/O can hold one busy now
	 * (o_async is 0, and o_closing makes the pager refuse new I/O at
	 * once), so a busy page is someone's for a moment (the page daemon)
	 * whose release needs nothing of this task queue: sleep until it is
	 * released and look again; what was already removed stays removed.
	 */
	dropped = 0;
restart:
	vm_page_iter_init(&pages, obj);
	for (p = vm_radix_iter_lookup_ge(&pages, 0); p != NULL;
	    p = vm_radix_iter_step(&pages)) {
		if (vm_page_tryxbusy(p) == 0) {
			if (vm_page_busy_sleep(p, "dqdbsy", 0))
				VM_OBJECT_WLOCK(obj);
			goto restart;
		}
		if (p->dirty != 0)
			dropped++;
		if (vm_page_wired(p) || !vm_page_try_remove_all(p)) {
			/* sendfile still holds it: unmap and invalidate. */
			pmap_remove_all(p);
			vm_page_invalid(p);
			vm_page_undirty(p);
			vm_page_xunbusy(p);
			continue;
		}
		vm_page_iter_free(&pages, p);
	}
	if (dropped != 0) {
		DQ_LOCK(q);
		q->q_stats.ds2_close_dropped += dropped;
		DQ_UNLOCK(q);
	}
	VM_OBJECT_WUNLOCK(obj);
	/*
	 * This pass is the last: no kick may queue the task again (the state
	 * is DONE), and the page deadline an earlier park armed is stopped
	 * under its lock, so it cannot fire after the object is gone.
	 */
	DQO_LOCK(o);
	o->o_destroy_state = DQ_DESTROY_DONE;
	callout_stop(&o->o_destroy_co);	/* o_mtx: it cannot run after */
	DQO_UNLOCK(o);
	/*
	 * The bounded sleeps left (dq_var.h): the terminate's pip wait when
	 * this was the last VM reference, knlist_clear in the retire.
	 */
	vm_object_deallocate(obj);
	closeev = o->o_closeev;
	o->o_closeev = NULL;
	dq_object_retire_ev(o, NULL, closeev);
	dq_object_rele(o);		/* the file's reference */
}

/*
 * The last reference is gone (dq_close).  Page-ins stop now; the
 * write-back and the teardown are the task's.  The file's reference on o
 * passes to the task.
 */
void
dq_object_close_deferred(struct dq_object *o)
{
	vm_object_t obj;

	obj = o->o_object;
	VM_OBJECT_WLOCK(obj);
	DQO_LOCK(o);
	o->o_closed = true;
	o->o_fp = NULL;		/* already (dq_object_close_begin) */
	DQO_UNLOCK(o);
	VM_OBJECT_WUNLOCK(obj);
	o->o_destroy_deadline = 0;
	TASK_INIT(&o->o_destroy, 0, dq_object_destroy_task, o);
	callout_init_mtx(&o->o_destroy_co, &o->o_mtx, 0);
	DQO_LOCK(o);
	o->o_destroy_state = DQ_DESTROY_QUEUED;	/* events kick it now */
	taskqueue_enqueue(dq_taskq, &o->o_destroy);
	DQO_UNLOCK(o);
}
