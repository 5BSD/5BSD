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
#include <sys/callout.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/ioccom.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/limits.h>
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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>

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
	for (i = 0; i < DQ_IDHASH; i++)
		LIST_INIT(&q->q_idhash[i]);
	knlist_init_mtx(&q->q_sel.si_note, &q->q_mtx);
	dq_async_queue_init(q);
	q->q_depth = dq_queue_depth;
	q->q_stats.ds2_size = sizeof(struct dq_stats2);

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
	KASSERT(TAILQ_EMPTY(&q->q_async) && q->q_nasync == 0,
	    ("dq: freeing a queue with page operations"));
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
 * observer told; the controller is waited for by nothing (I11).  Pending
 * page operations are completed with an error by dq_taskq, the deadline
 * callout is drained without q_mtx, and each object's pages are removed
 * after its own completions (B2): dq's own work, the only wait here.  The
 * memory stays until the last object and observer drop their references,
 * so an object fileop that runs afterwards finds DQ_Q_CLOSING and answers
 * EIO.
 */
void
dq_queue_close(struct dq_queue *q)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	struct dq_object *o, **objs;
	struct dq_async *da;
	u_int i, n, nobjs;

	TAILQ_INIT(&freed);
	DQ_LOCK(q);
	q->q_flags |= DQ_Q_CLOSING;	/* no mint from here on */
	nobjs = q->q_nobjects;
	DQ_UNLOCK(q);
	objs = nobjs != 0 ? malloc(nobjs * sizeof(*objs), M_DQ, M_WAITOK) :
	    NULL;
	n = 0;
	DQ_LOCK(q);
	RB_FOREACH(o, dq_object_tree, &q->q_objects) {
		dq_object_revoke_locked(q, o, 1, &freed);
		if (n < nobjs) {
			dq_object_hold(o);
			objs[n++] = o;
		}
	}
	/* Anything left (an object mid-close): its completion is the task's. */
	while ((da = TAILQ_FIRST(&q->q_async)) != NULL)
		dq_async_fail_locked(q, da);
	callout_stop(&q->q_callout);
	q->q_callout_at = 0;
	/* Queue-level records (CLOSE, INTERRUPT) left unread. */
	TAILQ_FOREACH_SAFE(ev, &q->q_pending, ev_link, evtmp)
		dq_event_fail_locked(q, ev, EIO, &freed);
	/*
	 * Queue-level events the controller read and never answered
	 * (RESOLVE): their requesters fail closed (D136).
	 */
	RB_FOREACH_SAFE(ev, dq_inflight_tree, &q->q_inflight, evtmp) {
		if (ev->ev_object == NULL)
			dq_event_fail_locked(q, ev, EIO, &freed);
	}
	wakeup(&q->q_pending);
	wakeup(&q->q_requesters);
	selwakeup(&q->q_sel);
	KNOTE_LOCKED(&q->q_sel.si_note, 0);
	dq_observer_unlink_all(q);
	DQ_UNLOCK(q);

	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);
	callout_drain(&q->q_callout);
	for (i = 0; i < n; i++) {
		dq_object_vm_teardown(objs[i], false);
		dq_object_rele(objs[i]);
	}
	free(objs, M_DQ);

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

/*
 * The identity index (N6): one bucket per (di_dev, di_ino) hash, under
 * q_mtx, maintained at mint, at an identity change (SETIDENT, a GETATTR
 * reply) and at retire.
 */
static struct dq_object_idlist *
dq_idbucket(struct dq_queue *q, uint64_t dev, uint64_t ino)
{
	uint64_t h;

	h = (dev * 0x9e3779b97f4a7c15ULL) ^ ino;
	h ^= h >> 32;
	return (&q->q_idhash[h % DQ_IDHASH]);
}

static void
dq_object_unhash_locked(struct dq_queue *q, struct dq_object *o)
{

	DQ_LOCK_ASSERT(q);
	if (o->o_hashed) {
		LIST_REMOVE(o, o_idlink);
		o->o_hashed = false;
	}
}

static void
dq_object_hash_locked(struct dq_queue *q, struct dq_object *o, uint64_t dev,
    uint64_t ino)
{

	DQ_LOCK_ASSERT(q);
	dq_object_unhash_locked(q, o);
	o->o_hdev = dev;
	o->o_hino = ino;
	LIST_INSERT_HEAD(dq_idbucket(q, dev, ino), o, o_idlink);
	o->o_hashed = true;
}

#define	DQ_SIBLINGS_FOREACH(s, q, o)					\
	LIST_FOREACH((s), dq_idbucket((q), (o)->o_hdev, (o)->o_hino),	\
	    o_idlink)							\
		if ((s)->o_hdev == (o)->o_hdev && (s)->o_hino == (o)->o_hino)

/*
 * Replace an object's identity (SETIDENT, a GETATTR reply) and keep the
 * index in step when the key changed.  hint, when non-zero, is raised on
 * the object's knotes.
 */
static void
dq_object_set_ident_locked(struct dq_queue *q, struct dq_object *o,
    const struct dq_ident_file *di, long hint)
{

	DQ_LOCK_ASSERT(q);
	DQO_LOCK(o);
	o->o_ident = *di;
	if (hint != 0)
		dq_file_knote(o, hint);
	DQO_UNLOCK(o);
	if (o->o_hashed && (o->o_hdev != di->di_dev || o->o_hino != di->di_ino))
		dq_object_hash_locked(q, o, di->di_dev, di->di_ino);
}

void
dq_object_set_ident(struct dq_object *o, const struct dq_ident_file *di,
    long hint)
{
	struct dq_queue *q;

	q = o->o_queue;
	DQ_LOCK(q);
	dq_object_set_ident_locked(q, o, di, hint);
	DQ_UNLOCK(q);
	dq_object_setsize(o, di->di_size);	/* B10 */
}

/*
 * Record that a LOCK of this kind was posted (D14), so the close-time
 * UNLOCK_ALL is posted.  B4: a POSIX owner is the process, and a process's
 * POSIX locks on a file are released by its close of any descriptor of
 * that file, so the bit goes on every object of the same identity on the
 * queue; the controller shares POSIX owners per identity and releases them
 * whichever sibling closes.  flock and OFD locks belong to one open file
 * and stay on the object.
 */
void
dq_object_mark_locked(struct dq_object *o, u_int bit)
{
	struct dq_queue *q;
	struct dq_object *s;

	q = o->o_queue;
	DQ_LOCK(q);
	if (bit == DQ_LOCKED_POSIX && o->o_hashed) {
		DQ_SIBLINGS_FOREACH(s, q, o) {
			DQO_LOCK(s);
			s->o_locked |= bit;
			DQO_UNLOCK(s);
		}
	} else {
		DQO_LOCK(o);
		o->o_locked |= bit;
		DQO_UNLOCK(o);
	}
	DQ_UNLOCK(q);
}

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
	KASSERT(o->o_async == 0 && o->o_vmusers == 0,
	    ("dq: freeing an object with page operations"));
	q = o->o_queue;
	cv_destroy(&o->o_async_cv);
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
	/* A page operation has no waiter: its completion is the task's. */
	if (ev->ev_async != NULL) {
		dq_async_fail_locked(q, ev->ev_async);
		return;
	}
	if (ev->ev_state == DQ_EV_PENDING) {
		TAILQ_REMOVE(&q->q_pending, ev, ev_link);
		q->q_count--;
		q->q_bytes -= ev->ev_size;
	} else {
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds2_inflight--;
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
	q->q_stats.ds2_objects_revoked++;
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
	dq_object_hold(o);
	DQ_UNLOCK(q);
	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);
	/* The pages go too (D11): a mapping now faults SIGBUS. */
	dq_object_vm_teardown(o, false);
	dq_object_rele(o);
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

	dq_object_retire_ev(o, td, NULL);
}

/*
 * As dq_object_retire, with the CLOSE record already allocated (closeev,
 * consumed; NULL to allocate here, which may sleep).  The deferred close
 * on dq_taskq allocates it M_NOWAIT beforehand.
 */
void
dq_object_retire_ev(struct dq_object *o, struct thread *td,
    struct dq_event_k *closeev)
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
	KASSERT(o->o_inflight == 0 && o->o_locks == 0,
	    ("dq: closing an object with events"));
	post_close = (q->q_flags & DQ_Q_CLOSING) == 0 &&
	    (o->o_policy.dp_events & DQ_EVENTS_CLOSE) != 0;
	if (!o->o_retired) {
		RB_REMOVE(dq_object_tree, &q->q_objects, o);
		dq_object_unhash_locked(q, o);
		o->o_retired = true;
		q->q_nobjects--;
		q->q_stats.ds2_objects_live--;
	}
	DQ_UNLOCK(q);

	if (post_close && closeev == NULL)
		dq_event_post_nowait(q, o, DQ_OP_CLOSE, NULL, 0, td);
	else if (post_close) {
		DQ_LOCK(q);
		if ((q->q_flags & DQ_Q_CLOSING) == 0)
			(void)dq_event_enqueue_locked(q, closeev);
		DQ_UNLOCK(q);
	}
	if (closeev != NULL)
		dq_event_rele(closeev);
	SDT_PROBE2(dq, , , object__close, q, o);
}

/*
 * A shrink (B10 as amended): the controller said the bytes past newsize
 * are gone, so every page operation that would hold a page the shrink
 * removes or zeroes is completed with EIO through the normal paths instead
 * of being slept on: async operations reaching past newsize (their
 * completion is waited for by the shrink: dq's own work), and pager READs
 * (a fault's or a DATA miss's waited event) whose run reaches a page at or
 * past pagecut, the first page the shrink removes.  A fault so failed sees
 * the new size and answers VM_PAGER_BAD (SIGBUS), as a real truncate
 * gives.  The caller (SETIDENT, SETATTR) never waits for the controller.
 */
void
dq_object_cut(struct dq_object *o, off_t newsize, off_t pagecut)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	const struct dq_read_body *rb;
	struct dq_queue *q;

	q = o->o_queue;
	TAILQ_INIT(&freed);
	DQ_LOCK(q);
	dq_async_cut_locked(q, o, newsize);
	TAILQ_FOREACH_SAFE(ev, &q->q_pending, ev_link, evtmp) {
		if (ev->ev_object != o || !ev->ev_pagein)
			continue;
		rb = (const struct dq_read_body *)((const char *)&ev->ev_hdr +
		    sizeof(struct dq_event));
		if (rb->dr_offset + rb->dr_len > (uint64_t)pagecut)
			dq_event_fail_locked(q, ev, EIO, &freed);
	}
	RB_FOREACH_SAFE(ev, dq_inflight_tree, &q->q_inflight, evtmp) {
		if (ev->ev_object != o || !ev->ev_pagein)
			continue;
		rb = (const struct dq_read_body *)((const char *)&ev->ev_hdr +
		    sizeof(struct dq_event));
		if (rb->dr_offset + rb->dr_len > (uint64_t)pagecut)
			dq_event_fail_locked(q, ev, EIO, &freed);
	}
	DQ_UNLOCK(q);
	TAILQ_FOREACH_SAFE(ev, &freed, ev_link, evtmp)
		dq_event_rele(ev);
}

/*
 * B7: an object has one struct file, so NOTE_OPEN at install and
 * NOTE_CLOSE at close can reach no knote on the object itself; they are
 * raised on the other objects of the same identity (di_dev, di_ino) on the
 * queue, which is how a vnode's other opens see them.  Only the identity's
 * index bucket is walked; q_mtx, then each sibling's o_mtx in turn.
 */
void
dq_object_knote_siblings(struct dq_object *o, long hint)
{
	struct dq_queue *q;
	struct dq_object *s;

	q = o->o_queue;
	DQ_LOCK(q);
	if (o->o_hashed) {
		DQ_SIBLINGS_FOREACH(s, q, o) {
			if (s == o)
				continue;
			DQO_LOCK(s);
			if (s->o_state == DQ_OBJ_LIVE)
				dq_file_knote(s, hint);
			DQO_UNLOCK(s);
		}
	}
	DQ_UNLOCK(q);
}

/*
 * Events
 */

void
dq_event_hold(struct dq_event_k *ev)
{

	refcount_acquire(&ev->ev_refs);
}

void
dq_event_rele(struct dq_event_k *ev)
{

	if (!refcount_release(&ev->ev_refs))
		return;
	KASSERT(!ev->ev_linked, ("dq: freeing a linked event"));
	cv_destroy(&ev->ev_cv);
	dq_data_rele(ev->ev_reply);
	if (ev->ev_object != NULL)
		dq_object_rele(ev->ev_object);
	free(ev, M_DQ);
}

/*
 * Reply data (D101).  The waiter, dq_event_rele (a reply nobody took), the
 * observer read and the observer drain at close are the releases.
 */
static struct dq_data *
dq_data_alloc(size_t len)
{
	struct dq_data *dd;
	size_t alloc;

	alloc = roundup2(len, 8);
	dd = malloc(sizeof(*dd) + alloc, M_DQ, M_WAITOK);
	refcount_init(&dd->dd_refs, 1);
	dd->dd_len = len;
	if (alloc != len)
		bzero(dd->dd_bytes + len, alloc - len);
	return (dd);
}

void
dq_data_hold(struct dq_data *dd)
{

	refcount_acquire(&dd->dd_refs);
}

void
dq_data_rele(struct dq_data *dd)
{

	if (dd == NULL || !refcount_release(&dd->dd_refs))
		return;
	free(dd, M_DQ);
}

void
dq_reply_free(struct dq_data *reply)
{

	dq_data_rele(reply);
}

/*
 * D24, as refined by D91: the caller is the posting thread's credential and
 * process, which in the aio daemons is the requester's (aio_process_rw
 * swaps td_ucred); a kernel process or no thread at all is flagged
 * DQ_CALLER_F_KERNEL with pid 0.  Never the file's credential, which in
 * stage 1a is the controller's.
 */
static void
dq_caller_fill(struct dq_caller *dc, struct thread *td, bool kcaller)
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
	/*
	 * kcaller: a page write-back, which is the kernel's (the page daemon,
	 * msync, fsync), posted under the VM object lock where no process
	 * lock may be taken; the credential's ids are still reported.
	 */
	if (kcaller) {
		dc->dc_flags |= DQ_CALLER_F_KERNEL;
		dc->dc_uid = cred->cr_ruid;
		dc->dc_euid = cred->cr_uid;
		dc->dc_gid = cred->cr_rgid;
		dc->dc_egid = cred->cr_gid;
		dc->dc_jid = cred->cr_prison->pr_id;
		return;
	}
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

/*
 * An event with its body (copied from body unless NULL: the caller fills
 * it).  mflags M_NOWAIT for the page write-back path, which may return NULL.
 */
struct dq_event_k *
dq_event_alloc_flags(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, bool kcaller, int mflags)
{
	struct dq_event_k *ev;
	struct timespec ts;

	KASSERT((bodylen & 7) == 0, ("dq: unpadded body %zu", bodylen));
	ev = malloc(offsetof(struct dq_event_k, ev_hdr) +
	    sizeof(struct dq_event) + bodylen, M_DQ, mflags | M_ZERO);
	if (ev == NULL)
		return (NULL);
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
	dq_caller_fill(&ev->ev_hdr.de_caller, td, kcaller);
	ev->ev_requester = ev->ev_hdr.de_caller.dc_nonce != 0 ?
	    ev->ev_hdr.de_caller.dc_nonce :
	    ((uint64_t)1 << 63) | (uint64_t)ev->ev_hdr.de_caller.dc_pid;
	nanouptime(&ts);
	ev->ev_hdr.de_time.tv_sec = ts.tv_sec;
	ev->ev_hdr.de_time.tv_nsec = ts.tv_nsec;
	if (bodylen != 0 && body != NULL)
		memcpy((char *)&ev->ev_hdr + sizeof(struct dq_event), body,
		    bodylen);
	return (ev);
}

static struct dq_event_k *
dq_event_alloc(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td)
{

	return (dq_event_alloc_flags(o, op, body, bodylen, td, false,
	    M_WAITOK));
}

/*
 * Append to the pending list.  The sequence number is taken before the
 * depth test so a drop leaves a visible gap (design 8.6).  Returns EIO on
 * a full queue; the list reference is taken on success.
 *
 * UNLOCK_ALL and INTERRUPT are exempt from the depth: losing one would
 * leave a lock held for a closed file or a cancelled request running at
 * the controller.  Both are bounded by events that already happened (one
 * per close of a locking owner, one per abandoned waiter), so the overrun
 * is bounded too; it is counted in ds2_overdepth.
 */
int
dq_event_enqueue_locked(struct dq_queue *q, struct dq_event_k *ev)
{
	uint32_t op;

	DQ_LOCK_ASSERT(q);
	ev->ev_hdr.de_seq = ++q->q_seq;
	if (q->q_count >= q->q_depth) {
		op = ev->ev_hdr.de_op;
		if (op != DQ_OP_UNLOCK_ALL && op != DQ_OP_INTERRUPT) {
			q->q_stats.ds2_events_dropped++;
			SDT_PROBE2(dq, , , event__drop, q, op);
			return (EIO);
		}
		q->q_stats.ds2_overdepth++;
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
	q->q_stats.ds2_events_posted++;
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

/*
 * B4: a page fault abandons its wait only when the process is being killed
 * or is exiting.  Called with no dq lock held.
 */
static bool
dq_fault_abandon(struct thread *td)
{
	struct proc *p;
	bool dying;

	if (curproc_sigkilled())
		return (true);
	p = td->td_proc;
	PROC_LOCK(p);
	dying = (p->p_flag & P_WEXIT) != 0;
	PROC_UNLOCK(p);
	return (dying);
}

#define	DQ_FAULT_SLICE	(100 * SBT_1MS)

/*
 * A quota sleep before the post.  A syscall's is interruptible; a fault's
 * (DQ_POST_FAULT) is a non-catching slice bounded by the deadline: 0 to
 * look again, EIO at the deadline, EINTR when the process is dying.
 * Called and returns with q_mtx held.
 */
static int
dq_post_quota_sleep(struct dq_queue *q, void *chan, const char *wmesg,
    struct thread *td, int flags, sbintime_t deadline)
{
	sbintime_t now;
	bool dying;

	if ((flags & DQ_POST_FAULT) == 0)
		return (msleep(chan, &q->q_mtx, PCATCH, wmesg, 0));
	now = sbinuptime();
	if (now >= deadline)
		return (EIO);
	(void)msleep_sbt(chan, &q->q_mtx, 0, wmesg,
	    MIN(deadline, now + DQ_FAULT_SLICE), 0, C_ABSOLUTE);
	DQ_UNLOCK(q);
	dying = dq_fault_abandon(td);
	DQ_LOCK(q);
	return (dying ? EINTR : 0);
}

int
dq_event_post_wait(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, int flags, struct dq_data **replyp,
    int *errnop)
{
	struct dq_queue *q;
	struct dq_event_k *ev;
	struct dq_requester *rq, *newrq;
	struct dq_interrupt_body ib;
	sbintime_t deadline, now;
	int error;
	bool interrupt, drop_list_ref, lock, fault, catching, dying;

	q = o->o_queue;
	*replyp = NULL;
	*errnop = 0;
	interrupt = drop_list_ref = false;
	lock = (flags & DQ_POST_LOCK) != 0;
	fault = (flags & DQ_POST_FAULT) != 0;
	KASSERT(!fault || (td == curthread && !lock),
	    ("dq: fault wait flags %#x", flags));

	/*
	 * A fault takes no FILEDESC lock: it may run under a filesystem's
	 * vnode lock (a write(2) whose buffer maps a served file), and
	 * vnode -> filedesc would invert the order kinfo export takes.  A
	 * controller faulting on its own served object waits out the page
	 * deadline and gets SIGBUS instead of EDEADLK.
	 */
	if (!fault && dq_caller_holds_queue(q, td))
		return (EDEADLK);

	ev = dq_event_alloc(o, op, body, bodylen, td);
	ev->ev_waited = true;
	ev->ev_lock = lock;
	ev->ev_pagein = fault && op == DQ_OP_READ;
	newrq = lock ? NULL : malloc(sizeof(*newrq), M_DQ, M_WAITOK | M_ZERO);

	if (fault) {
		/* A page never waits forever (B1, B4). */
		deadline = dq_page_deadline(o);
	} else if ((flags & DQ_POST_NODEADLINE) != 0) {
		deadline = 0;
	} else {
		DQO_LOCK(o);
		deadline = dq_deadline(&o->o_policy);
		DQO_UNLOCK(o);
	}
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
		/*
		 * A page-in past the pager's size is refused here, under the
		 * locks a shrink fails page-ins under (dq_object_cut), so one
		 * that read the old size cannot slip in after it.
		 */
		if (ev->ev_pagein) {
			const struct dq_read_body *prb = body;

			if (prb->dr_offset + prb->dr_len >
			    (uint64_t)round_page(o->o_vmsize)) {
				DQO_UNLOCK(o);
				error = EIO;
				goto out_locked;
			}
		}
		DQO_UNLOCK(o);
		/*
		 * B6: a LOCK is bounded by the queue depth alone.  A blocked
		 * SETLKW is a legitimate long wait on a real file; counting
		 * it against the in-flight quotas would let lockers starve
		 * readers.
		 */
		if (lock)
			break;
		if (o->o_inflight >= dq_max_inflight_per_object) {
			error = dq_post_quota_sleep(q, &o->o_inflight, "dqinfl",
			    td, flags, deadline);
			if (error != 0)
				goto out_locked;
			continue;
		}
		rq = dq_requester_find_locked(q, ev->ev_requester);
		if (rq != NULL && rq->rq_inflight >= dq_max_inflight_per_requester) {
			error = dq_post_quota_sleep(q, &q->q_requesters, "dqreq",
			    td, flags, deadline);
			if (error != 0)
				goto out_locked;
			continue;
		}
		break;
	}
	error = dq_event_enqueue_locked(q, ev);
	if (error != 0)
		goto out_locked;
	if (lock) {
		o->o_locks++;
		q->q_stats.ds2_locks++;
	} else {
		if (rq == NULL) {
			rq = newrq;
			newrq = NULL;
			rq->rq_key = ev->ev_requester;
			LIST_INSERT_HEAD(
			    &q->q_requesters[rq->rq_key % DQ_REQUESTER_HASH],
			    rq, rq_link);
		}
		rq->rq_inflight++;
		o->o_inflight++;
	}

	error = 0;
	catching = true;
	while (ev->ev_state == DQ_EV_PENDING || ev->ev_state == DQ_EV_DELIVERED) {
		if (fault && !catching) {
			/*
			 * B4: a caught signal is pending, so every catching
			 * sleep would return at once; sleep without catching,
			 * in slices, and look at the process on each wake.
			 */
			now = sbinuptime();
			if (now >= deadline) {
				error = EWOULDBLOCK;
				break;
			}
			(void)cv_timedwait_sbt(&ev->ev_cv, &q->q_mtx,
			    MIN(deadline, now + DQ_FAULT_SLICE), 0, C_ABSOLUTE);
			if (ev->ev_state != DQ_EV_PENDING &&
			    ev->ev_state != DQ_EV_DELIVERED)
				break;
			DQ_UNLOCK(q);
			dying = dq_fault_abandon(td);
			DQ_LOCK(q);
			if (dying) {
				error = EINTR;
				break;
			}
			continue;
		}
		if (deadline == 0)
			error = cv_wait_sig(&ev->ev_cv, &q->q_mtx);
		else
			error = cv_timedwait_sig_sbt(&ev->ev_cv, &q->q_mtx,
			    deadline, 0, C_ABSOLUTE);
		if (fault && (error == EINTR || error == ERESTART)) {
			DQ_UNLOCK(q);
			dying = dq_fault_abandon(td);
			DQ_LOCK(q);
			if (dying)
				break;
			catching = false;
			error = 0;
			continue;
		}
		if (error != 0)
			break;
	}

	/*
	 * The state decides first: a reply or a failure that landed just
	 * before a signal or the deadline is the answer (D91 item 7).
	 */
	switch (ev->ev_state) {
	case DQ_EV_REPLIED:
		*replyp = ev->ev_reply;	/* the reply's own reference */
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
			q->q_stats.ds2_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else {
			ev->ev_state = DQ_EV_INTERRUPTED;
		}
		break;
	case DQ_EV_DELIVERED:
		KASSERT(error != 0, ("dq: delivered event with no error"));
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds2_inflight--;
		ev->ev_linked = false;
		drop_list_ref = true;
		/*
		 * The controller has it: whichever way the waiter gives up,
		 * tell the controller the answer is no longer wanted.
		 */
		interrupt = true;
		if (error == EWOULDBLOCK) {
			ev->ev_state = DQ_EV_FAILED;
			q->q_stats.ds2_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else {
			ev->ev_state = DQ_EV_INTERRUPTED;
			q->q_stats.ds2_interrupts++;
			SDT_PROBE2(dq, , , event__interrupt, q, ev);
		}
		break;
	default:
		panic("dq: event %p in state %d", ev, ev->ev_state);
	}
	if (lock) {
		o->o_locks--;
	} else {
		o->o_inflight--;
		wakeup(&o->o_inflight);
		dq_requester_release_locked(q, ev->ev_requester);
	}
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
 * Post a record that needs no answer (CLOSE, INTERRUPT, UNLOCK_ALL).  It
 * carries no id and is never waited for.  The allocation sleeps (M_WAITOK;
 * every caller holds no dq lock, fo_close included), so a record is lost
 * only on a closing queue, where the controller is gone, or, for CLOSE
 * alone, on a full one (documented); INTERRUPT and UNLOCK_ALL bypass the
 * depth (dq_event_enqueue_locked).
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
 * A queue-level event a requester waits for (RESOLVE, stage 1c): as
 * dq_event_post_wait without an object, so no per-object quota and no
 * revoke; the queue closing fails it.  The caller is flagged ATTACHED.
 */
int
dq_event_post_wait_q(struct dq_queue *q, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, sbintime_t deadline,
    struct dq_data **replyp, int *errnop)
{
	struct dq_event_k *ev;
	struct dq_requester *rq, *newrq;
	struct dq_interrupt_body ib;
	int error;
	bool interrupt, drop_list_ref;

	*replyp = NULL;
	*errnop = 0;
	interrupt = drop_list_ref = false;
	if (dq_caller_holds_queue(q, td))
		return (EDEADLK);
	ev = dq_event_alloc(NULL, op, body, bodylen, td);
	ev->ev_waited = true;
	ev->ev_deadline = deadline;
	ev->ev_hdr.de_caller.dc_flags |= DQ_CALLER_F_ATTACHED;
	newrq = malloc(sizeof(*newrq), M_DQ, M_WAITOK | M_ZERO);
	rq = NULL;

	DQ_LOCK(q);
	for (;;) {
		if ((q->q_flags & DQ_Q_CLOSING) != 0) {
			error = EIO;
			goto out_locked;
		}
		rq = dq_requester_find_locked(q, ev->ev_requester);
		if (rq != NULL && rq->rq_inflight >= dq_max_inflight_per_requester) {
			/* The quota wait is bounded by the same deadline. */
			if (deadline != 0)
				error = msleep_sbt(&q->q_requesters, &q->q_mtx,
				    PCATCH, "dqreq", deadline, 0, C_ABSOLUTE);
			else
				error = msleep(&q->q_requesters, &q->q_mtx,
				    PCATCH, "dqreq", 0);
			if (error == EWOULDBLOCK)
				error = EIO;
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
	SDT_PROBE2(dq, , , resolve__post, q, ev);

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
	switch (ev->ev_state) {
	case DQ_EV_REPLIED:
		*replyp = ev->ev_reply;
		*errnop = ev->ev_errno;
		ev->ev_reply = NULL;
		error = 0;
		break;
	case DQ_EV_FAILED:
		error = EIO;
		break;
	case DQ_EV_PENDING:
		TAILQ_REMOVE(&q->q_pending, ev, ev_link);
		q->q_count--;
		q->q_bytes -= ev->ev_size;
		ev->ev_linked = false;
		drop_list_ref = true;
		if (error == EWOULDBLOCK) {
			ev->ev_state = DQ_EV_FAILED;
			q->q_stats.ds2_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else
			ev->ev_state = DQ_EV_INTERRUPTED;
		break;
	case DQ_EV_DELIVERED:
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds2_inflight--;
		ev->ev_linked = false;
		drop_list_ref = true;
		interrupt = true;
		if (error == EWOULDBLOCK) {
			ev->ev_state = DQ_EV_FAILED;
			q->q_stats.ds2_deadline_misses++;
			SDT_PROBE2(dq, , , event__deadline, q, ev);
			error = EIO;
		} else {
			ev->ev_state = DQ_EV_INTERRUPTED;
			q->q_stats.ds2_interrupts++;
			SDT_PROBE2(dq, , , event__interrupt, q, ev);
		}
		break;
	default:
		panic("dq: event %p in state %d", ev, ev->ev_state);
	}
	dq_requester_release_locked(q, ev->ev_requester);
out_locked:
	DQ_UNLOCK(q);
	if (newrq != NULL)
		free(newrq, M_DQ);
	if (interrupt) {
		ib.din_id = ev->ev_hdr.de_id;
		dq_event_post_nowait(q, NULL, DQ_OP_INTERRUPT, &ib, sizeof(ib),
		    td);
	}
	if (drop_list_ref)
		dq_event_rele(ev);
	dq_event_rele(ev);
	return (error);
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
			q->q_stats.ds2_events_delivered++;
			SDT_PROBE2(dq, , , event__deliver, q, ev);
			if (ev->ev_waited) {
				RB_INSERT(dq_inflight_tree, &q->q_inflight, ev);
				q->q_stats.ds2_inflight++;
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
	struct dq_object *o, *s;
	int error, reason;

	args->dm_object = 0;
	args->dm_fd = -1;
	if (args->dm_version != DQ_API_VERSION)
		return (dq_mint_reason(args, DQ_REASON_VERSION, EINVAL));
	if (args->dm_kind != DQ_KIND_FILE)
		return (dq_mint_reason(args, DQ_REASON_KIND, EINVAL));
	error = dq_ident_validate(args->dm_kind, &args->dm_ident, &reason);
	if (error == 0)
		error = dq_policy_validate(&args->dm_policy, &reason);
	if (error != 0)
		return (dq_mint_reason(args, reason, error));
	/*
	 * D95: the access mode is fixed at mint as open(2) fixes it; a
	 * writable descriptor needs a policy that serves writes.
	 */
	if ((args->dm_flags & ~DQ_MINT_F_WRITE) != 0 ||
	    ((args->dm_flags & DQ_MINT_F_WRITE) != 0 &&
	    args->dm_policy.dp_write != DQ_EVENT))
		return (dq_mint_reason(args, DQ_REASON_FLAGS, EINVAL));

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
	cv_init(&o->o_async_cv, "dqasync");
	/*
	 * The pager object (D102), in every cache mode: pages exist while
	 * mapped, wired or cached.  Created before the object is visible so
	 * a revoke always finds it.
	 */
	error = dq_object_vm_create(o);
	if (error != 0) {
		o->o_retired = true;
		knlist_destroy(&o->o_sel.si_note);
		rangelock_destroy(&o->o_rl);
		dq_object_rele(o);
		return (dq_mint_reason(args, DQ_REASON_NONE, error));
	}

	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0 || q->q_nobjects >= dq_max_objects) {
		error = (q->q_flags & DQ_Q_CLOSING) != 0 ? ENXIO : ENOSPC;
		DQ_UNLOCK(q);
		o->o_retired = true;
		knlist_destroy(&o->o_sel.si_note);
		rangelock_destroy(&o->o_rl);
		/* Its release reaches o through pgo_dealloc and dq_taskq. */
		o->o_vmdropped = true;
		vm_object_deallocate(o->o_object);
		dq_object_rele(o);
		return (dq_mint_reason(args, DQ_REASON_NONE, error));
	}
	o->o_id = ++q->q_next_object;
	RB_INSERT(dq_object_tree, &q->q_objects, o);
	dq_object_hash_locked(q, o, o->o_ident.di_dev, o->o_ident.di_ino);
	/*
	 * B4: a sibling's POSIX locks are the process's on this file too, so
	 * a close through this new object owes their UNLOCK_ALL.  o is not
	 * yet visible to anyone else; o_mtx is not needed for it.
	 */
	DQ_SIBLINGS_FOREACH(s, q, o) {
		if (s != o && (s->o_locked & DQ_LOCKED_POSIX) != 0) {
			o->o_locked |= DQ_LOCKED_POSIX;
			break;
		}
	}
	q->q_nobjects++;
	q->q_stats.ds2_objects_live++;
	q->q_stats.ds2_objects_total++;
	DQ_UNLOCK(q);

	error = dq_file_install(td, o, &args->dm_policy, args->dm_flags,
	    &args->dm_fd);
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
 * N5: the errnos a controller may answer, per operation.  A regular file
 * never answers EPIPE to write(2), so dofilewrite must never raise SIGPIPE
 * on a controller's word; anything outside the list reaches the requester
 * as EIO and is counted.  READ and GETATTR keep their 1a behaviour (no
 * list).
 */
static bool
dq_reply_errno_allowed(uint32_t op, int error)
{

	switch (op) {
	case DQ_OP_WRITE:
	case DQ_OP_WRITE_ASYNC:
		return (error == EIO || error == ENOSPC || error == EDQUOT ||
		    error == EFBIG || error == EACCES || error == EPERM ||
		    error == EROFS || error == EINTR || error == EAGAIN ||
		    error == ENXIO || error == EINVAL || error == ESTALE);
	case DQ_OP_SETATTR:
		return (error == EPERM || error == EROFS || error == EINVAL ||
		    error == EOPNOTSUPP || error == EIO || error == EFBIG ||
		    error == EDQUOT || error == ENOSPC || error == EACCES ||
		    error == ESTALE);
	case DQ_OP_FSYNC:
		return (error == EIO || error == EINVAL || error == ENOSPC ||
		    error == EDQUOT || error == ESTALE);
	case DQ_OP_FALLOCATE:
		return (error == ENOSPC || error == EFBIG || error == EINVAL ||
		    error == EIO || error == EOPNOTSUPP || error == EDQUOT);
	case DQ_OP_FSPACECTL:
		return (error == ENOSPC || error == EFBIG || error == EINVAL ||
		    error == EIO || error == EOPNOTSUPP || error == ENODEV);
	case DQ_OP_LOCK:
		return (error == EAGAIN || error == EDEADLK || error == ENOLCK ||
		    error == EINVAL || error == EIO || error == EINTR);
	case DQ_OP_IOCTL:
		return (error == ENOTTY || error == EINVAL || error == EIO ||
		    error == EPERM || error == EACCES || error == ENXIO);
	default:
		/* RESOLVE: per resolve op, dq_resolve_errno_allowed. */
		return (true);
	}
}

/*
 * The reply body against the operation (design 8.2): a wrong size or an
 * impossible value is EINVAL to the controller and the event stays in
 * flight.  An errno carries no body except where the row says so.
 */
static int
dq_reply_validate(const struct dq_event_k *ev, int rerrno, const void *buf,
    size_t len)
{
	const char *body;
	const struct dq_read_body *rb;
	const struct dq_write_body *wb;
	const struct dq_write_reply *wr;
	const struct dq_fspacectl_body *sb;
	const struct dq_fspacectl_reply *sr;
	const struct dq_lock_body *lb;
	const struct dq_lock_reply *lr;
	const struct dq_ioctl_body *ib;
	uint64_t end;
	int reason;

	body = (const char *)&ev->ev_hdr + sizeof(struct dq_event);
	switch (ev->ev_hdr.de_op) {
	case DQ_OP_READ:
	case DQ_OP_READ_ASYNC:
		rb = (const struct dq_read_body *)body;
		if (len > rb->dr_len || (rerrno != 0 && len != 0))
			return (EINVAL);
		return (0);
	case DQ_OP_GETATTR:
		if (rerrno != 0)
			return (len == 0 ? 0 : EINVAL);
		if (len != sizeof(struct dq_ident_file) ||
		    dq_ident_validate(ev->ev_object->o_kind, buf, &reason) != 0)
			return (EINVAL);
		return (0);
	case DQ_OP_WRITE:
	case DQ_OP_WRITE_ASYNC:		/* never APPEND: the offset echoes */
		if (rerrno != 0)
			return (len == 0 ? 0 : EINVAL);
		if (len != sizeof(*wr))
			return (EINVAL);
		wb = (const struct dq_write_body *)body;
		wr = buf;
		/* N2: the count fits the request and the offset the file. */
		if (wr->dwr_written > wb->dw_len || wr->dwr_offset > OFF_MAX ||
		    wr->dwr_written > (uint64_t)OFF_MAX - wr->dwr_offset)
			return (EINVAL);
		/* Only an append lets the controller choose where. */
		if ((wb->dw_flags & DQ_WRITE_F_APPEND) == 0 &&
		    wr->dwr_offset != wb->dw_offset)
			return (EINVAL);
		return (0);
	case DQ_OP_SETATTR:
	case DQ_OP_FSYNC:
	case DQ_OP_FALLOCATE:
		return (len == 0 ? 0 : EINVAL);
	case DQ_OP_FSPACECTL:
		if (rerrno != 0)
			return (len == 0 ? 0 : EINVAL);
		if (len != sizeof(*sr))
			return (EINVAL);
		sb = (const struct dq_fspacectl_body *)body;
		sr = buf;
		/*
		 * The invariant vn_fallocate panics on: the remaining range
		 * ends where the request ended and starts no earlier.  The
		 * kernel validated offset + len <= OFF_MAX before posting.
		 */
		end = sb->dsc_offset + sb->dsc_len;
		if (sr->dscr_offset < sb->dsc_offset || sr->dscr_offset > end ||
		    sr->dscr_len != end - sr->dscr_offset)
			return (EINVAL);
		return (0);
	case DQ_OP_LOCK:
		lb = (const struct dq_lock_body *)body;
		if (rerrno != 0 || lb->dl_op != DQ_LOCK_GETLK)
			return (len == 0 ? 0 : EINVAL);
		if (len != sizeof(*lr))
			return (EINVAL);
		lr = buf;
		/* As fusefs validates a server's lock before copying it out. */
		if (lr->dlr_type == F_UNLCK)
			return (0);
		if ((lr->dlr_type != F_RDLCK && lr->dlr_type != F_WRLCK) ||
		    lr->dlr_start < 0 || lr->dlr_len < 0 ||
		    (lr->dlr_len != 0 && lr->dlr_len - 1 > OFF_MAX - lr->dlr_start) ||
		    lr->dlr_pid < -1)
			return (EINVAL);
		return (0);
	case DQ_OP_IOCTL:
		ib = (const struct dq_ioctl_body *)body;
		/* N6: out[] only for an IOC_OUT command that succeeded. */
		if (rerrno == 0 && (ib->dio_cmd & IOC_OUT) != 0)
			return (len == IOCPARM_LEN(ib->dio_cmd) ? 0 : EINVAL);
		return (len == 0 ? 0 : EINVAL);
	case DQ_OP_RESOLVE:
		return (dq_resolve_reply_validate(rerrno, buf, len));
	default:
		return (EINVAL);
	}
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
	struct dq_data *dd;
	struct file *fp;
	size_t len;
	uint32_t op;
	int error, rerrno;
	bool async;

	if (r->dr_version != DQ_API_VERSION || r->dr_pad0 != 0 ||
	    r->dr_errno < 0 || r->dr_errno > ELAST || r->dr_len > dq_max_io)
		return (EINVAL);
	len = r->dr_len;
	dd = NULL;
	if (len != 0) {
		dd = dq_data_alloc(len);
		error = copyin(r->dr_data, dd->dd_bytes, len);
		if (error != 0) {
			dq_data_rele(dd);
			return (error);
		}
	}

	key.ev_hdr.de_id = r->dr_id;
	DQ_LOCK(q);
	ev = RB_FIND(dq_inflight_tree, &q->q_inflight, &key);
	if (ev == NULL) {
		q->q_stats.ds2_late_replies++;
		SDT_PROBE2(dq, , , reply__late, q, r->dr_id);
		DQ_UNLOCK(q);
		dq_data_rele(dd);
		return (ESRCH);
	}
	KASSERT(ev->ev_state == DQ_EV_DELIVERED, ("dq: inflight event state"));
	op = ev->ev_hdr.de_op;
	o = ev->ev_object;
	error = dq_reply_validate(ev, r->dr_errno,
	    dd != NULL ? dd->dd_bytes : NULL, len);
	if (error != 0) {
		DQ_UNLOCK(q);
		dq_data_rele(dd);
		return (error);
	}
	rerrno = r->dr_errno;
	if (rerrno != 0 && !(op == DQ_OP_RESOLVE ?
	    dq_resolve_errno_allowed(((const struct dq_resolve_body *)
	    ((const char *)&ev->ev_hdr + sizeof(struct dq_event)))->drs_op,
	    rerrno) : dq_reply_errno_allowed(op, rerrno))) {
		rerrno = EIO;
		q->q_stats.ds2_bad_replies++;
	}
	/*
	 * A regular file never accepts zero bytes of a non-empty write
	 * without an error; dofilewrite would report a 0-byte write, which
	 * callers loop on.  It is EIO to the requester.
	 */
	if ((op == DQ_OP_WRITE || op == DQ_OP_WRITE_ASYNC) && rerrno == 0 &&
	    ((const struct dq_write_reply *)dd->dd_bytes)->dwr_written == 0 &&
	    ((const struct dq_write_body *)((const char *)&ev->ev_hdr +
	    sizeof(struct dq_event)))->dw_len != 0) {
		rerrno = EIO;
		q->q_stats.ds2_bad_replies++;
	}
	RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
	q->q_stats.ds2_inflight--;
	q->q_stats.ds2_replies++;
	ev->ev_linked = false;
	ev->ev_reply = dd;	/* the waiter takes this reference */
	ev->ev_errno = rerrno;
	ev->ev_state = DQ_EV_REPLIED;
	async = ev->ev_async != NULL;
	if (async) {
		/*
		 * A page operation completes in dq_taskq, which takes the VM
		 * object lock; this ioctl takes none.  The task holds the
		 * list reference from here.
		 */
		dq_async_replied_locked(q, ev->ev_async);
	} else
		cv_signal(&ev->ev_cv);
	SDT_PROBE4(dq, , , event__reply, q, ev, r->dr_errno, len);
	/* Observers and the policies see what the controller said. */
	dq_observer_fanout_reply(q, r->dr_id, r->dr_errno, dd);

	/* D89: tell the policies, with the object's file held, no lock. */
	fp = NULL;
	if (o != NULL) {
		DQO_LOCK(o);
		/*
		 * o_fp is cleared under o_mtx inside fo_close, so the struct
		 * file is valid here, but its count may already be 0 (the
		 * close is running): fhold would raise it to 1 and the fdrop
		 * below would close the file a second time.
		 */
		fp = o->o_fp;
		if (fp != NULL && !refcount_acquire_if_not_zero(&fp->f_count))
			fp = NULL;
		DQO_UNLOCK(o);
	}
	DQ_UNLOCK(q);
	if (!async)
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
	dq_object_set_ident_locked(q, o, &args->dsi_ident, NOTE_ATTRIB);
	dq_object_hold(o);
	DQ_UNLOCK(q);
	/* B10: the pager object's size follows, with no dq lock held. */
	dq_object_setsize(o, args->dsi_ident.di_size);
	dq_object_rele(o);
	return (0);
}

/*
 * After the mint only what the descriptor's installed state does not fix
 * may change: the deadline, the optional events, the cache mode and
 * dp_ioctl (no installed state depends on it; dp_write fixed FWRITE and
 * dp_mmap_shared_write depends on dp_write).
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
	    new->dp_lock != cur->dp_lock ||
	    memcmp(&new->dp_rights, &cur->dp_rights, sizeof(cap_rights_t)) != 0) {
		DQO_UNLOCK(o);
		DQ_UNLOCK(q);
		return (EINVAL);
	}
	cur->dp_cache = new->dp_cache;
	cur->dp_ioctl = new->dp_ioctl;
	cur->dp_deadline_ms = new->dp_deadline_ms;
	cur->dp_events = new->dp_events;
	DQO_UNLOCK(o);
	DQ_UNLOCK(q);
	return (0);
}

void
dq_queue_stats2(struct dq_queue *q, struct dq_stats2 *st)
{

	DQ_LOCK(q);
	*st = q->q_stats;
	st->ds2_size = sizeof(*st);
	st->ds2_queue_id = q->q_gid;
	st->ds2_queue_depth = q->q_depth;
	st->ds2_queue_current = q->q_count;
	st->ds2_queue_highwater = q->q_highwater;
	st->ds2_queue_bytes = q->q_bytes;
	st->ds2_observers = q->q_nobservers;
	st->ds2_async_pending = q->q_nasync;
	st->ds2_async_bytes = q->q_async_bytes;
	DQ_UNLOCK(q);
}

/* The frozen 1a struct (B8): a projection of the full counters. */
void
dq_queue_stats(struct dq_queue *q, struct dq_stats *st)
{
	struct dq_stats2 st2;

	dq_queue_stats2(q, &st2);
	bzero(st, sizeof(*st));
	st->ds_version = DQ_API_VERSION;
	st->ds_queue_id = st2.ds2_queue_id;
	st->ds_events_posted = st2.ds2_events_posted;
	st->ds_events_delivered = st2.ds2_events_delivered;
	st->ds_events_dropped = st2.ds2_events_dropped;
	st->ds_replies = st2.ds2_replies;
	st->ds_late_replies = st2.ds2_late_replies;
	st->ds_interrupts = st2.ds2_interrupts;
	st->ds_deadline_misses = st2.ds2_deadline_misses;
	st->ds_objects_live = st2.ds2_objects_live;
	st->ds_objects_total = st2.ds2_objects_total;
	st->ds_objects_revoked = st2.ds2_objects_revoked;
	st->ds_inflight = st2.ds2_inflight;
	st->ds_queue_depth = st2.ds2_queue_depth;
	st->ds_queue_current = st2.ds2_queue_current;
	st->ds_queue_highwater = st2.ds2_queue_highwater;
	st->ds_queue_bytes = st2.ds2_queue_bytes;
	st->ds_observers = st2.ds2_observers;
}

/*
 * PUSH (D100): the controller raises an EVFILT_VNODE note for what happened
 * elsewhere.  Only the notes the filter knows are accepted; NOTE_REVOKE is
 * the REVOKE ioctl's (a pushed one would end the knotes of a live object).
 * A revoked object's knotes already report EOF; the raise is harmless.
 */
#define	DQ_PUSH_NOTES	(NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | \
	NOTE_LINK | NOTE_RENAME | NOTE_OPEN | NOTE_CLOSE | NOTE_CLOSE_WRITE | \
	NOTE_READ)
/*
 * INVALIDATE (B2): the clean cached pages of the range are dropped and
 * unmapped, outside q_mtx (the VM object lock comes first); a revoked
 * object has no pages left and the push is a no-op.
 */
int
dq_queue_push(struct dq_queue *q, const struct dq_push_args *args)
{
	struct dq_object key, *o;

	if (args->dp_version != DQ_API_VERSION || args->dp_pad0 != 0)
		return (EINVAL);
	switch (args->dp_op) {
	case DQ_PUSH_NOTIFY_VNODE:
		if (args->dp_note == 0 || (args->dp_note & ~DQ_PUSH_NOTES) != 0 ||
		    args->dp_offset != 0 || args->dp_len != 0)
			return (EINVAL);
		break;
	case DQ_PUSH_INVALIDATE:
		if (args->dp_note != 0 || args->dp_offset > OFF_MAX ||
		    args->dp_len > (uint64_t)OFF_MAX - args->dp_offset)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	key.o_id = args->dp_object;
	DQ_LOCK(q);
	o = RB_FIND(dq_object_tree, &q->q_objects, &key);
	if (o == NULL) {
		DQ_UNLOCK(q);
		return (ESRCH);
	}
	q->q_stats.ds2_pushes++;
	if (args->dp_op == DQ_PUSH_NOTIFY_VNODE) {
		DQO_LOCK(o);
		dq_file_knote(o, args->dp_note);
		DQO_UNLOCK(o);
		DQ_UNLOCK(q);
		return (0);
	}
	dq_object_hold(o);
	DQ_UNLOCK(q);
	dq_object_invalidate(o, args->dp_offset, args->dp_len);
	dq_object_rele(o);
	return (0);
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
