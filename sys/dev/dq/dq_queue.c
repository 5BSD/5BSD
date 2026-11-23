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
 * Everything that can fail closed does: a revoked object, a closing queue
 * and a missed deadline answer EIO (design 15); a waited post that finds
 * the queue full waits for a slot within its deadline (D205).
 */

#include "opt_dq.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/event.h>
#include <sys/eventhandler.h>
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
#include <sys/dqres.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
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
static void	dq_mutwait_wake_locked(struct dq_event_k *ev);

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
	/* Unreachable until listed below: the one store of q_owner. */
	q->q_owner = td->td_proc;
	q->q_flags = DQ_Q_PINNED;
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
	dq_standing_init(q);

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
	KASSERT((q->q_flags & DQ_Q_DIED) != 0, ("dq: freeing a live queue"));
	KASSERT(TAILQ_EMPTY(&q->q_pending) && RB_EMPTY(&q->q_inflight),
	    ("dq: freeing a queue with events"));
	KASSERT(RB_EMPTY(&q->q_objects), ("dq: freeing a queue with objects"));
	KASSERT(TAILQ_EMPTY(&q->q_async) && q->q_nasync == 0,
	    ("dq: freeing a queue with page operations"));
	knlist_clear(&q->q_sel.si_note, 0);
	knlist_destroy(&q->q_sel.si_note);
	seldrain(&q->q_sel);
	dq_standing_fini(q);
	crfree(q->q_cred);
	sx_destroy(&q->q_rdsx);
	mtx_destroy(&q->q_mtx);
	free(q, M_DQ);
}

/*
 * The queue dies: its controller is gone, fail closed.  Every object is
 * revoked, every waiter woken with EIO, every reader and observer told; the
 * controller is waited for by nothing (I11).  Pending page operations are
 * completed with an error by dq_taskq, the deadline callout is drained
 * without q_mtx, and each object's pages are removed after its own
 * completions (B2): dq's own work, the only wait here.  The memory stays
 * until the last object and observer drop their references, so an object
 * fileop that runs afterwards finds DQ_Q_CLOSING and answers EIO.
 *
 * A queue dies once.  The die is run by whoever comes first: the owner
 * where it exits, execs or leaves a shared table (dq_queue_owner_gone), or
 * the cdevpriv destructor at the last close of the file.  Everyone else
 * waits here until the teardown is finished, so that on return the queue
 * has died whichever thread did the work; the wait is for dq's own work
 * only, as the close's always was, and is not interruptible.  The runner
 * never waits for itself: nothing in the teardown drops a reference to
 * the queue's own file, so it cannot re-enter through the destructor.
 *
 * The queue stays on dq_queues, counted and listed (flagged closing), until
 * dq_queue_close.
 */
void
dq_queue_die(struct dq_queue *q)
{
	struct dq_event_list freed;
	struct dq_event_k *ev, *evtmp;
	struct dq_object *o, **objs;
	struct dq_async *da;
	u_int i, n, nobjs;

	TAILQ_INIT(&freed);
	mtx_lock(&dq_mtx);
	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_DEAD) != 0) {
		mtx_unlock(&dq_mtx);
		/*
		 * Died already, or dying in another thread.  The owner that
		 * ran the die at its exit comes here again from the last
		 * close of its own table and finds the teardown finished.
		 */
		while ((q->q_flags & DQ_Q_DIED) == 0) {
			KASSERT(q->q_dier != curthread,
			    ("dq: the die of queue %p waits for itself", q));
			msleep(&q->q_dier, &q->q_mtx, 0, "dqdie", 0);
		}
		DQ_UNLOCK(q);
		return;
	}
	/* No owner and no mint from here on: one section (dq_queue_enter). */
	q->q_flags |= DQ_Q_DEAD | DQ_Q_CLOSING;
	q->q_owner = NULL;
	q->q_dier = curthread;
	nobjs = q->q_nobjects;
	DQ_UNLOCK(q);
	mtx_unlock(&dq_mtx);
	/*
	 * The standing rules end with the controller.  Consultations test
	 * CLOSING before the rules; one that saw it clear finishes before
	 * the flush's write lock is granted, as a reply sent before the
	 * death would.
	 */
	dq_standing_flush(q, DQ_STANDING_CHANGE_DIE);
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
	/*
	 * Every post waiting for a slot ends here: the failures above freed
	 * no slots one by one (dq_queue_slots_freed on a closing queue).
	 */
	if (DQ_WAKE(DQ_WAKE_DIE_SPACE))
		wakeup(&q->q_space);
	dq_queue_room_locked(q);	/* msync's room wait, parked tasks */
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

	DQ_LOCK(q);
	q->q_flags |= DQ_Q_DIED;
	wakeup(&q->q_dier);
	DQ_UNLOCK(q);
}

/*
 * The last close of the queue's file (the cdevpriv destructor), or an open
 * that failed after the queue was made: the queue dies if it has not, then
 * leaves dq_queues and drops the reference it was created with.
 */
void
dq_queue_close(struct dq_queue *q)
{

	dq_queue_die(q);

	mtx_lock(&dq_mtx);
	LIST_REMOVE(q, q_all);
	dq_nqueues--;
	mtx_unlock(&dq_mtx);

	/* Per-queue state kept elsewhere (Linux served mount ids). */
	EVENTHANDLER_INVOKE(dq_queue_closed, q->q_gid);
	SDT_PROBE1(dq, , , queue__close, q);
	dq_queue_rele(q);
}

/*
 * The owner is gone (DQRES_OWNER_GONE): the process exits, execs or leaves
 * a descriptor table it shares.  Every queue it owns dies now, whoever
 * else still holds the queue's file; a holder is answered ENXIO from then
 * on and the last close only unlists the queue.  The process is
 * single-threaded here, so it has no queue call in flight and can open no
 * queue meanwhile; each queue found is dead, hence disowned, when
 * dq_queue_die returns, which ends the loop.  q_owner is compared, never
 * dereferenced.
 *
 * This function and its four call sites are the whole of "the queue dies
 * with its owner"; without them a queue dies at the last close alone.
 */
void
dq_queue_owner_gone(struct proc *p)
{
	struct dq_queue *q;

	for (;;) {
		mtx_lock(&dq_mtx);
		LIST_FOREACH(q, &dq_queues, q_all) {
			if (q->q_owner == p)
				break;
		}
		if (q == NULL) {
			mtx_unlock(&dq_mtx);
			return;
		}
		dq_queue_hold(q);
		mtx_unlock(&dq_mtx);
		dq_queue_die(q);
		dq_queue_rele(q);
	}
}

/*
 * Entry to the queue's device operations (read, ioctl, poll, kqfilter):
 * only the process that opened the queue operates it.  One q_mtx section,
 * in this order: the calling file is the pinned one (it always is; fail
 * closed if not), EPERM; the queue has died, ENXIO for every caller; the
 * caller is not the owner (a process sharing the owner's table, an aio
 * daemon reading for anyone), EPERM.  The owner's own answers follow
 * unchanged.  "The owner" is the opening process and anything that can run
 * system calls in it: this makes no claim against its debugger.
 */
int
dq_queue_enter(struct dq_queue *q, struct thread *td)
{
	struct file *fp;
	int error;

	fp = td->td_fpop;
	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_PINNED) != 0 &&
	    (fp == NULL || (fp->f_flag & FPINNED) == 0))
		error = EPERM;
	else if ((q->q_flags & DQ_Q_DEAD) != 0)
		error = ENXIO;
	else if (q->q_owner != td->td_proc)
		error = EPERM;
	else
		error = 0;
	DQ_UNLOCK(q);
	return (error);
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
 * Replace an object's identity (SETIDENT) and keep the
 * index in step when the key changed.  hint, when non-zero, is raised on
 * the object's knotes.
 */
static void
dq_object_set_ident_locked(struct dq_queue *q, struct dq_object *o,
    const struct dq_ident_file *di, long hint)
{
	int i;

	DQ_LOCK_ASSERT(q);
	DQO_LOCK(o);
	o->o_ident = *di;
	/* Every attribute is now as of the newest reply so far. */
	for (i = 0; i < DQ_GEN_N; i++)
		o->o_gen[i] = o->o_agen;
	dq_object_proofs_prune(o, o->o_agen);
	if (hint != 0)
		dq_file_knote(o, hint);
	DQO_UNLOCK(o);
	if (o->o_hashed && (o->o_hdev != di->di_dev || o->o_hino != di->di_ino))
		dq_object_hash_locked(q, o, di->di_dev, di->di_ino);
}

/*
 * A GETATTR answer (agen: its reply's generation).  Its size, block count,
 * times and attributes (mode, owner, flags, link count, birth time)
 * follow the generation rule, so an answer older than a newer reply
 * already applied does not take them back (review 2 #6, review 3: an old
 * answer must not revert a chmod or chown).  The rest (identity, path,
 * statfs, pathconf) is the answer's.  SETIDENT, the controller's own
 * statement, sets everything (dq_object_set_ident_locked).
 */
void
dq_object_set_ident_agen(struct dq_object *o, const struct dq_ident_file *di,
    uint64_t agen)
{
	struct dq_timespec atime, ctime, mtime, btime;
	struct dq_queue *q;
	uint64_t blocks, size;
	uint32_t flags, gid, mode, nlink, uid;

	q = o->o_queue;
	DQ_LOCK(q);
	DQO_LOCK(o);
	size = o->o_ident.di_size;
	blocks = o->o_ident.di_blocks;
	atime = o->o_ident.di_atime;
	mtime = o->o_ident.di_mtime;
	ctime = o->o_ident.di_ctime;
	btime = o->o_ident.di_birthtime;
	mode = o->o_ident.di_mode;
	uid = o->o_ident.di_uid;
	gid = o->o_ident.di_gid;
	flags = o->o_ident.di_flags;
	nlink = o->o_ident.di_nlink;
	o->o_ident = *di;
	o->o_ident.di_size = size;
	if (!dq_object_gen_newer(o, DQ_GEN_BLOCKS, agen))
		o->o_ident.di_blocks = blocks;
	if (!dq_object_gen_newer(o, DQ_GEN_MTIME, agen))
		o->o_ident.di_mtime = mtime;
	if (!dq_object_gen_newer(o, DQ_GEN_CTIME, agen))
		o->o_ident.di_ctime = ctime;
	if (!dq_object_gen_newer(o, DQ_GEN_ATIME, agen))
		o->o_ident.di_atime = atime;
	/* Each by its own generation: an older chown and a newer chmod. */
	if (!dq_object_gen_newer(o, DQ_GEN_MODE, agen))
		o->o_ident.di_mode = mode;
	if (!dq_object_gen_newer(o, DQ_GEN_UID, agen))
		o->o_ident.di_uid = uid;
	if (!dq_object_gen_newer(o, DQ_GEN_GID, agen))
		o->o_ident.di_gid = gid;
	if (!dq_object_gen_newer(o, DQ_GEN_FLAGS, agen))
		o->o_ident.di_flags = flags;
	if (!dq_object_gen_newer(o, DQ_GEN_NLINK, agen))
		o->o_ident.di_nlink = nlink;
	if (!dq_object_gen_newer(o, DQ_GEN_BIRTHTIME, agen))
		o->o_ident.di_birthtime = btime;
	(void)dq_object_postop_size(o, di->di_size, agen);
	DQO_UNLOCK(o);
	if (o->o_hashed && (o->o_hdev != di->di_dev || o->o_hino != di->di_ino))
		dq_object_hash_locked(q, o, di->di_dev, di->di_ino);
	DQ_UNLOCK(q);
	dq_object_sync_vmsize(o);	/* B10 */
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
	KASSERT(o->o_notify == 0,
	    ("dq: freeing an object a reply is telling the policies about"));
	q = o->o_queue;
	dq_object_proofs_prune(o, UINT64_MAX);
	cv_destroy(&o->o_async_cv);
	mtx_destroy(&o->o_mtx);
	free(o->o_target, M_DQ);
	free(o, M_DQ);
	dq_queue_rele(q);
}

/*
 * Take a linked event off the queue: off the pending list, whose slot then
 * goes to a post waiting on a full queue (D205), or out of the in-flight
 * tree.  The list reference stays with the caller.
 */
static void
dq_event_unlink_locked(struct dq_queue *q, struct dq_event_k *ev)
{

	DQ_LOCK_ASSERT(q);
	KASSERT(ev->ev_linked, ("dq: unlinking event %p twice", ev));
	if (ev->ev_state == DQ_EV_PENDING) {
		TAILQ_REMOVE(&q->q_pending, ev, ev_link);
		q->q_count--;
		q->q_bytes -= ev->ev_size;
		dq_queue_slots_freed(q, 1);
	} else {
		KASSERT(ev->ev_state == DQ_EV_DELIVERED,
		    ("dq: event %p linked in state %d", ev, ev->ev_state));
		RB_REMOVE(dq_inflight_tree, &q->q_inflight, ev);
		q->q_stats.ds2_inflight--;
	}
	ev->ev_linked = false;
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
	dq_event_unlink_locked(q, ev);
	ev->ev_state = DQ_EV_FAILED;
	ev->ev_errno = error;
	if (DQ_WAKE(DQ_WAKE_FAIL)) {
		cv_broadcast(&ev->ev_cv);
		dq_mutwait_wake_locked(ev);
	}
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
	if (DQ_WAKE(DQ_WAKE_REVOKE_QUOTA)) {
		wakeup(&o->o_inflight);
		wakeup(&q->q_requesters);
	}
	/*
	 * A post of this object waiting for a slot of a full queue fails
	 * now: no slot need come.  The others look again and sleep on.  A
	 * dying queue's revokes (why 1) leave it to the death, which wakes
	 * every slot waiter once (dq_queue_die).
	 */
	if (why == 0 && DQ_WAKE(DQ_WAKE_REVOKE_SPACE))
		wakeup(&q->q_space);
	/*
	 * The object's msync waiting for room and its parked destroy task
	 * end now too (a dying queue does this once itself).
	 */
	if (why == 0)
		dq_queue_room_locked(q);
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
	/* A RESOLVE FD answer nobody took (D171): its id ends here. */
	if (ev->ev_robj != NULL)
		dq_object_retire_unbound(ev->ev_robj, NULL);
	/*
	 * A RESOLVE SWAP answer nobody took.  The waiter of a REPLIED event
	 * always takes it (dq_event_post_wait_ev), so this is the event whose
	 * waiter is gone; the drop can be a last close, which may sleep.
	 */
	if (ev->ev_rswap.fs_fp != NULL) {
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
		    "dq: releasing a swapped file");
		fdswap_release(&ev->ev_rswap, curthread);
	}
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
	dd->dd_plen = len;
	dd->dd_postop = false;
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
	if (DQ_WAKE(DQ_WAKE_REQUESTER))
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
 * Event-driven waits (owner, 2026-11-19: no polling;
 * dq-served-wait-model.md).  A data or attribute wait that catches no
 * signal (DQ_WAIT_UNINTR, DQ_WAIT_FAULT) sleeps with PCATCH and every
 * signal but SIGKILL blocked, stops deferred, as fusefs's
 * fticket_wait_answer does: a caught signal neither wakes nor ends it and
 * is delivered once the operation returns, as after a disk wait (D192),
 * while SIGKILL wakes it and thread_single() aborts it (weed_inhib aborts
 * only catching sleeps).  Its only timeout is the caller's deadline; every
 * other end is a wakeup from the state change itself (section 3 of the
 * design).  The mask is set around the whole post, with no dq lock held,
 * because the process lock may not be taken under q_mtx.
 */
struct dq_wait_mask {
	sigset_t	wm_old;
	int		wm_stops;
	bool		wm_on;
};

static void
dq_wait_mask_enter(struct thread *td, int mode, struct dq_wait_mask *wm)
{
	sigset_t all;

	wm->wm_on = mode != DQ_WAIT_CATCH;
	if (!wm->wm_on)
		return;
	wm->wm_stops = sigdeferstop(SIGDEFERSTOP_SILENT);
	SIGFILLSET(all);	/* SIGKILL and SIGSTOP cannot be blocked */
	(void)kern_sigprocmask(td, SIG_BLOCK, &all, &wm->wm_old, 0);
}

static void
dq_wait_mask_leave(struct thread *td, struct dq_wait_mask *wm)
{

	if (!wm->wm_on)
		return;
	(void)kern_sigprocmask(td, SIG_SETMASK, &wm->wm_old, NULL, 0);
	sigallowstop(wm->wm_stops);
}

/*
 * Whether a wait that catches no signal ends because its process is
 * being taken down (D192), checked after every wake, never on a timer:
 * - SIGKILL (it wakes the PCATCH sleep);
 * - exit1, its own or a sibling's _exit: P_WEXIT, or SINGLE_EXIT, which
 *   exit1 starts before it sets P_WEXIT;
 * - sigexit, a fatal signal, one that dumps core included: P2_WEXIT; the
 *   dump single-threads with SINGLE_NO_EXIT (even with RLIMIT_CORE 0),
 *   which sets no P_SINGLE_EXIT, and after P2_WEXIT no SIGKILL comes;
 * - another thread single-threading the process to the user boundary
 *   (SINGLE_BOUNDARY): an execve, also one that then fails, an rfork
 *   without RFPROC, a fork under pg_killsx, jail_attach.  The process is
 *   not dying: thread_single aborts a catching sleep each time it looks,
 *   and the thread must reach the boundary.  A data or attribute wait
 *   gives up its operation (INTERRUPT to the controller) and returns
 *   ERESTART, so the system call is restarted once the single-threading
 *   is over, as fusefs's wait does (design 2.4); a page fault cannot be
 *   restarted that way and waits instead, without catching, for its
 *   answer or the page deadline (dq_wait_event, dq_wait_room).
 * The thread taking the process down (p_singlethread) keeps waiting, so a
 * core it writes to a served file is still answered.  Returns 0, EINTR
 * (dying) or ERESTART (boundary).  Called with no dq lock held.
 */
/*
 * A SIGKILL sent and not yet acted on (process lock held): queued on the
 * process, or on whichever thread tdsendsignal chose, which may be the
 * single-threading thread that cannot act on it before this one returns.
 */
static bool
dq_proc_sigkill_pending(struct proc *p)
{
	struct thread *td;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (SIGISMEMBER(p->p_sigqueue.sq_signals, SIGKILL))
		return (true);
	FOREACH_THREAD_IN_PROC(p, td) {
		if (SIGISMEMBER(td->td_sigqueue.sq_signals, SIGKILL))
			return (true);
	}
	return (false);
}

static int
dq_wait_abandon(struct thread *td)
{
	struct proc *p;
	int error;

	if (curproc_sigkilled())
		return (EINTR);
	p = td->td_proc;
	error = 0;
	PROC_LOCK(p);
	if ((p->p_flag & (P_WEXIT | P_WKILLED)) != 0 ||
	    dq_proc_sigkill_pending(p) ||
	    (((p->p_flag & P_SINGLE_EXIT) != 0 ||
	    (p->p_flag2 & P2_WEXIT) != 0) && p->p_singlethread != td))
		error = EINTR;
	else if ((p->p_flag & P_SINGLE_BOUNDARY) != 0 &&
	    p->p_singlethread != td)
		error = ERESTART;
	PROC_UNLOCK(p);
	return (error);
}

/*
 * Whether the controller changes state applying an operation, so that
 * one given up after it was delivered and then restarted would be
 * applied twice (owner, 2026-11-20).  An explicit table: an operation not
 * listed here as reading or idempotent counts as a mutation.
 */
static bool
dq_op_mutates(uint32_t op, const void *body, size_t bodylen)
{
	const struct dq_resolve_body *rb;

	switch (op) {
	case DQ_OP_READ:
	case DQ_OP_GETATTR:
	case DQ_OP_READDIR:
	case DQ_OP_FSYNC:	/* writing back twice is writing back */
	case DQ_OP_LOCK:	/* the same owner's same range again */
		return (false);
	case DQ_OP_RESOLVE:
		if (body == NULL || bodylen < sizeof(*rb))
			return (true);
		rb = body;
		switch (rb->drs_op) {
		case DQ_ROP_OPEN:
			return ((rb->drs_mode & (O_CREAT | O_TRUNC)) != 0);
		case DQ_ROP_STAT:
		case DQ_ROP_ACCESS:
		case DQ_ROP_READLINK:
		case DQ_ROP_REALPATH:
		case DQ_ROP_GETFH:
		case DQ_ROP_EXEC:
		case DQ_ROP_EXEC_INTERP:
		case DQ_ROP_CONNECT:
		case DQ_ROP_CHDIR:
		case DQ_ROP_CHROOT:
		case DQ_ROP_INOTIFY:
		/* Asked before anything is done, answered PASS or errno. */
		case DQ_ROP_SOCKET:
		case DQ_ROP_SOCKETPAIR:
			return (false);
		default:	/* unlink, rename, mkdir, bind, setattr, ... */
			return (true);
		}
	default:	/* WRITE, SETATTR, FALLOCATE, FSPACECTL, IOCTL, ... */
		return (true);
	}
}

/*
 * The wait of a delivered mutation or a fault while the process is
 * single-threaded to the user boundary (dq_wait_event): it catches no
 * signal, so thread_single cannot abort it, and ends with the answer
 * (or the event's failure), the deadline, or the process starting to
 * die.  The last has no wakeup of its own for a sleep that catches no
 * signal: the thread is on dq_mutwaits, and proc_dying_hook
 * (dq_proc_dying) wakes it.  Lock order: q_mtx, then dq_mutwait_mtx;
 * the process lock, then dq_mutwait_mtx.
 */
struct dq_mutwait {
	LIST_ENTRY(dq_mutwait)	 mw_link;
	struct proc		*mw_proc;
	bool			 mw_wake;	/* dq_mutwait_mtx */
};

static struct mtx dq_mutwait_mtx;
static LIST_HEAD(, dq_mutwait) dq_mutwaits =
    LIST_HEAD_INITIALIZER(dq_mutwaits);
/*
 * The waiters on dq_mutwaits, read without the lock by the hook, so that
 * a process dying with none (every exit) takes no global lock.  A waiter
 * counts itself (a locked add, a full barrier) before it looks at the
 * process's state; the hook runs after that state changed and looks at
 * the count after a full barrier: either the waiter sees the death, or
 * the hook sees the waiter.
 */
static u_int dq_mutwait_count;

static void
dq_mutwait_wake(struct dq_mutwait *mw)
{

	mtx_assert(&dq_mutwait_mtx, MA_OWNED);
	mw->mw_wake = true;
	wakeup(mw);
}

/* The process lock is held. */
static void
dq_proc_dying(struct proc *p)
{
	struct dq_mutwait *mw;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	atomic_thread_fence_seq_cst();
	if (atomic_load_int(&dq_mutwait_count) == 0)
		return;
	mtx_lock(&dq_mutwait_mtx);
	LIST_FOREACH(mw, &dq_mutwaits, mw_link) {
		if (mw->mw_proc == p)
			dq_mutwait_wake(mw);
	}
	mtx_unlock(&dq_mutwait_mtx);
}

void
dq_mutwait_init(void)
{

	mtx_init(&dq_mutwait_mtx, "dq mutwait", NULL, MTX_DEF);
	KASSERT(proc_dying_hook == NULL, ("dq: proc_dying_hook has an owner"));
	atomic_store_ptr(&proc_dying_hook, dq_proc_dying);
}

/* An answer or a failure of ev (q_mtx held): wake its boundary wait. */
static void
dq_mutwait_wake_locked(struct dq_event_k *ev)
{

	if (ev->ev_mutwait == NULL)
		return;
	mtx_lock(&dq_mutwait_mtx);
	dq_mutwait_wake(ev->ev_mutwait);
	mtx_unlock(&dq_mutwait_mtx);
}

/*
 * q_mtx is held and kept.  Returns 0 (answered or failed: the caller
 * reads the state), EWOULDBLOCK (the deadline), or EINTR (the process is
 * dying; dq:::wait-abandon).
 */
static int
dq_wait_delivered(struct dq_queue *q, struct dq_event_k *ev,
    struct thread *td, sbintime_t deadline)
{
	struct dq_mutwait mw;
	int error;

	DQ_LOCK_ASSERT(q);
	mw.mw_proc = td->td_proc;
	mw.mw_wake = false;
	mtx_lock(&dq_mutwait_mtx);
	LIST_INSERT_HEAD(&dq_mutwaits, &mw, mw_link);
	mtx_unlock(&dq_mutwait_mtx);
	atomic_add_int(&dq_mutwait_count, 1);
	atomic_thread_fence_seq_cst();
	ev->ev_mutwait = &mw;
	error = 0;
	while (ev->ev_state == DQ_EV_PENDING ||
	    ev->ev_state == DQ_EV_DELIVERED) {
		/*
		 * Registered first, so a death that begins after this look
		 * finds the thread on the list and wakes it.
		 */
		DQ_UNLOCK(q);
		if (dq_wait_abandon(td) == EINTR) {
			DQ_LOCK(q);
			SDT_PROBE2(dq, , , wait__abandon, q, ev);
			error = EINTR;
			break;
		}
		mtx_lock(&dq_mutwait_mtx);
		if (!mw.mw_wake)
			error = msleep_sbt(&mw, &dq_mutwait_mtx, PVFS,
			    "dqbndy", deadline, 0, C_ABSOLUTE);
		mw.mw_wake = false;
		mtx_unlock(&dq_mutwait_mtx);
		DQ_LOCK(q);
		if (error == EWOULDBLOCK) {
			if (ev->ev_state == DQ_EV_PENDING ||
			    ev->ev_state == DQ_EV_DELIVERED)
				break;
			error = 0;
		}
	}
	ev->ev_mutwait = NULL;
	mtx_lock(&dq_mutwait_mtx);
	LIST_REMOVE(&mw, mw_link);
	mtx_unlock(&dq_mutwait_mtx);
	atomic_subtract_int(&dq_mutwait_count, 1);
	return (error);
}

/*
 * After a wake of a wait that catches no signal: EINTR (dq:::wait-abandon)
 * when the process is being taken down, ERESTART when it is single-
 * threaded to the user boundary, else 0.  q_mtx is held and kept.
 */
static int
dq_wait_woken(struct dq_queue *q, struct dq_event_k *ev, struct thread *td)
{
	int error;

	DQ_UNLOCK(q);
	error = dq_wait_abandon(td);
	DQ_LOCK(q);
	if (error != 0)
		SDT_PROBE2(dq, , , wait__abandon, q, ev);
	return (error);
}

/*
 * A sleep for room before a waited post: a quota (the object's in-flight
 * bound, the requester's) or the queue's depth.  q_mtx is held and kept.
 * Returns 0 to look again; EIO when the deadline passed (the event was
 * never posted: the controller sees nothing of it); a caught signal's
 * EINTR or ERESTART (DQ_WAIT_CATCH); EINTR in the other modes when the
 * process is being taken down (dq:::wait-abandon).
 */
static int
dq_wait_room(struct dq_queue *q, struct dq_event_k *ev, void *chan,
    const char *wmesg, struct thread *td, int mode, sbintime_t deadline)
{
	int error;

	DQ_LOCK_ASSERT(q);
	if (deadline != 0 && sbinuptime() >= deadline)
		return (EIO);
	if (deadline == 0)
		error = msleep(chan, &q->q_mtx, PCATCH, wmesg, 0);
	else
		error = msleep_sbt(chan, &q->q_mtx, PCATCH, wmesg, deadline,
		    0, C_ABSOLUTE);
	if (error == EWOULDBLOCK)
		return (EIO);
	if (mode == DQ_WAIT_CATCH)
		return (error);
	error = dq_wait_woken(q, ev, td);
	if (error == ERESTART && mode == DQ_WAIT_FAULT) {
		/*
		 * A fault cannot be restarted: wait for a wakeup without
		 * catching, bounded by the page deadline (always set).
		 */
		error = msleep_sbt(chan, &q->q_mtx, 0, wmesg, deadline, 0,
		    C_ABSOLUTE);
		return (error == EWOULDBLOCK ? EIO : 0);
	}
	return (error);
}

/*
 * What one waited post waited for before it was posted: the quota it
 * waited on last (DQ_QUOTA_*, 0 for none), whether it waited for a slot of
 * a full queue, and whether it may hold a slot's wakeup it did not use.
 * dq:::quota-wait and dq:::wait-full fire once when the wait ends: with
 * the errno that ended the post, or 0 when the post went on.
 */
struct dq_post_waits {
	int	pw_quota;
	bool	pw_full;
	bool	pw_pass;
};

static void
dq_post_waits_done(struct dq_queue *q, struct dq_event_k *ev,
    struct dq_post_waits *pw, int error)
{

	DQ_LOCK_ASSERT(q);
	if (pw->pw_quota != 0)
		SDT_PROBE4(dq, , , quota__wait, q, ev, pw->pw_quota, error);
	if (pw->pw_full)
		SDT_PROBE3(dq, , , wait__full, q, ev, error);
	/* A slot this waiter was woken for and did not take goes on. */
	if (pw->pw_pass)
		dq_queue_slot_passed(q);
	pw->pw_quota = 0;
	pw->pw_full = pw->pw_pass = false;
}

/*
 * The quota sleeps of a waited post, bounded by the event's own deadline
 * (absolute, taken before the first sleep), so the wait for room and the
 * wait for the answer together never pass it (T-R03).
 */
static int
dq_post_quota_sleep(struct dq_queue *q, struct dq_event_k *ev, void *chan,
    const char *wmesg, struct thread *td, int mode, sbintime_t deadline,
    struct dq_post_waits *pw)
{
	int error;

	/* A slot this waiter was woken for goes on before it sleeps here. */
	if (pw->pw_pass) {
		dq_queue_slot_passed(q);
		pw->pw_pass = false;
	}
	pw->pw_quota = chan == (void *)&q->q_requesters ? DQ_QUOTA_REQUESTER :
	    DQ_QUOTA_OBJECT;
	error = dq_wait_room(q, ev, chan, wmesg, td, mode, deadline);
	if (error == EIO)
		q->q_stats.ds2_deadline_misses++;
	return (error);
}

/*
 * A full queue (D205): a waited post waits for a slot instead of failing,
 * in its own mode and bounded by its deadline, counted once per post in
 * ds2_full_waits.  dq_queue_slots_freed wakes one waiter per slot read off
 * the queue (or withdrawn).  A waiter that finds room on waking may hold
 * that slot's wakeup; if it goes on to sleep on a quota or fails, the
 * wakeup is passed on (pw_pass).  A waiter woken with the queue still full
 * (a spurious wake, a broadcast) holds none.  On a dying queue no slot is
 * passed on: the death wakes every waiter once.
 */
static int
dq_post_space_sleep(struct dq_queue *q, struct dq_event_k *ev,
    struct thread *td, int mode, sbintime_t deadline,
    struct dq_post_waits *pw)
{
	int error;

	if (!pw->pw_full) {
		pw->pw_full = true;
		q->q_stats.ds2_full_waits++;
	}
	error = dq_wait_room(q, ev, &q->q_space, "dqfull", td, mode,
	    deadline);
	if (error == EIO)
		q->q_stats.ds2_deadline_misses++;
	pw->pw_pass = error == 0 && q->q_count < q->q_depth;
	return (error);
}

void
dq_queue_slots_freed(struct dq_queue *q, u_int n)
{

	DQ_LOCK_ASSERT(q);
	/* A dying queue wakes every slot waiter once (dq_queue_die). */
	if ((q->q_flags & DQ_Q_CLOSING) != 0 || n == 0)
		return;
	dq_queue_room_locked(q);	/* an async post may go too */
	if (!DQ_WAKE(DQ_WAKE_SLOT))
		return;
	while (n-- > 0)
		wakeup_one(&q->q_space);
}

/*
 * A slot waiter woken for a slot it does not take (it sleeps on a quota
 * or fails) passes the wakeup on to the next (dq_post_space_sleep), its
 * own drop point (DQ_WAKE_PASS) so a test can prove the next waiter
 * depends on it.
 */
void
dq_queue_slot_passed(struct dq_queue *q)
{

	DQ_LOCK_ASSERT(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0)
		return;
	dq_queue_room_locked(q);
	if (DQ_WAKE(DQ_WAKE_PASS))
		wakeup_one(&q->q_space);
}

/*
 * Wait for ev's answer, q_mtx held and kept (D192).  DQ_WAIT_CATCH: a
 * signal ends the wait (EINTR or ERESTART), as an NFS intr mount's does;
 * for a mutation marked delivered, always EINTR, and a boundary
 * single-threading does not end that wait at all.
 * DQ_WAIT_UNINTR and DQ_WAIT_FAULT: no signal does, as a local file
 * system's disk wait: with the signals blocked (dq_wait_mask_enter) the
 * wait ends with the answer, the deadline (EWOULDBLOCK) or the process
 * being taken down (EINTR, dq_wait_abandon), each seen when it wakes the
 * sleep.  The caller reads the event's state first.
 */
static int
dq_wait_event(struct dq_queue *q, struct dq_event_k *ev, struct thread *td,
    int mode, sbintime_t deadline)
{
	int error;

	DQ_LOCK_ASSERT(q);
	KASSERT(td == curthread, ("dq: waiting for another thread"));
	error = 0;
	while (ev->ev_state == DQ_EV_PENDING ||
	    ev->ev_state == DQ_EV_DELIVERED) {
		if (deadline == 0)
			error = cv_wait_sig(&ev->ev_cv, &q->q_mtx);
		else
			error = cv_timedwait_sig_sbt(&ev->ev_cv, &q->q_mtx,
			    deadline, 0, C_ABSOLUTE);
		if (ev->ev_state != DQ_EV_PENDING &&
		    ev->ev_state != DQ_EV_DELIVERED) {
			error = 0;
			break;
		}
		if (error == EWOULDBLOCK)
			break;
		if (mode == DQ_WAIT_CATCH) {
			if (error == 0)
				continue;
			if (error != ERESTART || !ev->ev_mutates ||
			    ev->ev_state != DQ_EV_DELIVERED)
				break;
			/*
			 * A delivered mutation is not restarted (owner,
			 * 2026-11-23): posted again, the controller would
			 * apply it twice.  ERESTART is a signal or the
			 * process stopped at the user boundary (a single-
			 * threading, or stop_all_proc()'s abort of this
			 * sleep).  At the boundary the thread received no
			 * signal the call could fail with, so it waits as
			 * the other modes do; a signal pending as well is
			 * delivered when the call returns with its answer.
			 * Otherwise the signal ends the wait with EINTR.
			 */
			if (dq_wait_woken(q, ev, td) == ERESTART ||
			    (td->td_flags & TDF_ALLPROCSUSP) != 0)
				error = dq_wait_delivered(q, ev, td,
				    deadline);
			else
				error = EINTR;
			break;
		}
		/* A wake (or an abort) with no answer: dying, or sleep on. */
		error = dq_wait_woken(q, ev, td);
		if (error == ERESTART && (mode == DQ_WAIT_FAULT ||
		    (ev->ev_mutates && ev->ev_state == DQ_EV_DELIVERED))) {
			/*
			 * Not given up at the boundary (owner, 2026-11-20):
			 * a fault cannot be restarted (vm_fault has no retry
			 * answer from a pager: VM_PAGER_FAIL would zero-fill
			 * the page, VM_PAGER_ERROR is SIGBUS), and a
			 * delivered mutation restarted would be applied
			 * twice (an O_APPEND write lands twice, an O_EXCL
			 * create fails EEXIST).  Wait for the answer, the
			 * deadline or the process dying; the single-
			 * threading waits as it waits for a disk.
			 */
			error = dq_wait_delivered(q, ev, td, deadline);
			break;
		}
		if (error != 0)
			break;
	}
	return (error);
}

/*
 * What a waited post's answer carries to its caller: the reply data (its
 * own reference), the controller's errno, an object event's reply
 * generation (dq_object_gen_newer), and for a RESOLVE an FD answer's
 * object and a SWAP answer's file, each moved out of the event under
 * q_mtx (D91: the state before the wake reason).
 */
struct dq_post_answer {
	struct dq_data	*pa_reply;
	int		 pa_errno;
	uint64_t	 pa_agen;
	struct dq_object *pa_robj;
	struct fdswap	 pa_rswap;
};

/*
 * Give up a waited event its waiter stopped waiting for (H4): the wait
 * ended with error (the deadline's EWOULDBLOCK, a caught signal, or
 * dq_wait_abandon's EINTR or ERESTART) and no answer came.  Pending, the controller
 * never read it: it is withdrawn with no record.  Delivered, the
 * controller has it: *interruptp asks the caller to post the INTERRUPT
 * that says the answer is no longer wanted, once q_mtx is dropped.
 * Returns the waiter's errno, EIO at the deadline.  The caller drops the
 * list reference.
 */
static int
dq_event_withdraw_locked(struct dq_queue *q, struct dq_event_k *ev, int error,
    bool *interruptp)
{
	bool delivered;

	DQ_LOCK_ASSERT(q);
	KASSERT(error != 0, ("dq: withdrawing event %p with no error", ev));
	delivered = ev->ev_state == DQ_EV_DELIVERED;
	dq_event_unlink_locked(q, ev);
	*interruptp = delivered;
	if (error == EWOULDBLOCK) {
		ev->ev_state = DQ_EV_FAILED;
		q->q_stats.ds2_deadline_misses++;
		SDT_PROBE2(dq, , , event__deadline, q, ev);
		return (EIO);
	}
	ev->ev_state = DQ_EV_INTERRUPTED;
	if (delivered) {
		q->q_stats.ds2_interrupts++;
		SDT_PROBE2(dq, , , event__interrupt, q, ev);
	}
	return (error);
}

/*
 * The waited post (H4), for an object's event (o) or a queue-level one (o
 * NULL: no per-object quota, revoke or page bound; the queue closing
 * fails it).  ev is the caller's: allocated, filled, and its reference
 * kept.  The wait for room before the post (the quotas, a full queue) and
 * the wait for the answer after it are both in mode and bounded by the
 * one deadline (0: none).  Returns 0 with the answer in *pa; otherwise ev
 * was never posted, failed, or was withdrawn, and *pa is empty.
 */
static int
dq_event_post_wait_ev(struct dq_queue *q, struct dq_object *o,
    struct dq_event_k *ev, struct thread *td, int mode, sbintime_t deadline,
    struct dq_post_answer *pa)
{
	struct dq_requester *rq, *newrq;
	struct dq_interrupt_body ib;
	struct dq_wait_mask wm;
	struct dq_post_waits pw;
	int error;
	bool interrupt, drop_list_ref, lock;

	memset(pa, 0, sizeof(*pa));
	memset(&pw, 0, sizeof(pw));
	interrupt = drop_list_ref = false;
	lock = ev->ev_lock;
	KASSERT(o != NULL || (!lock && !ev->ev_pagein),
	    ("dq: queue-level event %p with object flags", ev));
	ev->ev_waited = true;
	ev->ev_deadline = deadline;
	newrq = lock ? NULL : malloc(sizeof(*newrq), M_DQ, M_WAITOK | M_ZERO);
	rq = NULL;

	dq_wait_mask_enter(td, mode, &wm);
	DQ_LOCK(q);
	for (;;) {
		if ((q->q_flags & DQ_Q_CLOSING) != 0) {
			error = EIO;
			goto out_locked;
		}
		if (o != NULL) {
			DQO_LOCK(o);
			if (o->o_state == DQ_OBJ_REVOKED) {
				DQO_UNLOCK(o);
				error = EIO;
				goto out_locked;
			}
			/*
			 * A page-in past the pager's size is refused here,
			 * under the locks a shrink fails page-ins under
			 * (dq_object_cut), so one that read the old size
			 * cannot slip in after it.
			 */
			if (ev->ev_pagein) {
				const struct dq_read_body *prb;

				prb = (const struct dq_read_body *)
				    ((const char *)&ev->ev_hdr +
				    sizeof(struct dq_event));
				if (prb->dr_offset + prb->dr_len >
				    (uint64_t)round_page(o->o_vmsize)) {
					DQO_UNLOCK(o);
					error = EIO;
					goto out_locked;
				}
			}
			DQO_UNLOCK(o);
		}
		/*
		 * B6: a LOCK is bounded by the queue depth alone.  A blocked
		 * SETLKW is a legitimate long wait on a real file; counting
		 * it against the in-flight quotas would let lockers starve
		 * readers.
		 */
		if (o != NULL && !lock &&
		    o->o_inflight >= dq_max_inflight_per_object) {
			error = dq_post_quota_sleep(q, ev, &o->o_inflight,
			    "dqinfl", td, mode, deadline, &pw);
			if (error != 0)
				goto out_locked;
			continue;
		}
		rq = lock ? NULL : dq_requester_find_locked(q, ev->ev_requester);
		if (rq != NULL && rq->rq_inflight >= dq_max_inflight_per_requester) {
			error = dq_post_quota_sleep(q, ev, &q->q_requesters,
			    "dqreq", td, mode, deadline, &pw);
			if (error != 0)
				goto out_locked;
			continue;
		}
		if (q->q_count >= q->q_depth) {
			error = dq_post_space_sleep(q, ev, td, mode, deadline,
			    &pw);
			if (error != 0)
				goto out_locked;
			continue;
		}
		break;
	}
	pw.pw_pass = false;		/* the slot is this post's */
	dq_post_waits_done(q, ev, &pw, 0);
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
		if (o != NULL)
			o->o_inflight++;
	}
	if (o == NULL)
		SDT_PROBE2(dq, , , resolve__post, q, ev);

	error = dq_wait_event(q, ev, td, mode, deadline);

	/*
	 * The state decides first: a reply or a failure that landed just
	 * before a signal or the deadline is the answer (D91 item 7).
	 */
	switch (ev->ev_state) {
	case DQ_EV_REPLIED:
		pa->pa_reply = ev->ev_reply;	/* the reply's own reference */
		pa->pa_errno = ev->ev_errno;
		pa->pa_agen = ev->ev_agen;
		pa->pa_robj = ev->ev_robj;
		pa->pa_rswap = ev->ev_rswap;	/* SWAP: the reference moves */
		ev->ev_reply = NULL;
		ev->ev_robj = NULL;
		bzero(&ev->ev_rswap, sizeof(ev->ev_rswap));
		error = 0;
		break;
	case DQ_EV_FAILED:
		error = EIO;
		break;
	case DQ_EV_PENDING:
	case DQ_EV_DELIVERED:
		error = dq_event_withdraw_locked(q, ev, error, &interrupt);
		drop_list_ref = true;
		break;
	default:
		panic("dq: event %p in state %d", ev, ev->ev_state);
	}
	if (lock) {
		o->o_locks--;
	} else {
		if (o != NULL) {
			o->o_inflight--;
			if (DQ_WAKE(DQ_WAKE_INFLIGHT))
				wakeup(&o->o_inflight);
		}
		dq_requester_release_locked(q, ev->ev_requester);
	}
out_locked:
	dq_post_waits_done(q, ev, &pw, error);
	DQ_UNLOCK(q);
	dq_wait_mask_leave(td, &wm);
	if (newrq != NULL)
		free(newrq, M_DQ);
	if (interrupt) {
		ib.din_id = ev->ev_hdr.de_id;
		dq_event_post_nowait(q, o, DQ_OP_INTERRUPT, &ib, sizeof(ib), td);
	}
	if (drop_list_ref)
		dq_event_rele(ev);
	return (error);
}

int
dq_event_post_wait(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, int flags, struct dq_data **replyp,
    int *errnop)
{

	return (dq_event_post_wait_agen(o, op, body, bodylen, td, flags,
	    replyp, errnop, NULL));
}

/*
 * dq_event_post_wait, and the reply's generation in *agenp (0 when no
 * reply came): the order the replies reached the kernel (DQ_IOC_REPLY),
 * for dq_object_gen_newer.
 */
int
dq_event_post_wait_agen(struct dq_object *o, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, int flags, struct dq_data **replyp,
    int *errnop, uint64_t *agenp)
{
	struct dq_queue *q;
	struct dq_event_k *ev;
	struct dq_post_answer pa;
	sbintime_t deadline;
	int error, mode;
	bool lock, fault;

	q = o->o_queue;
	*replyp = NULL;
	*errnop = 0;
	if (agenp != NULL)
		*agenp = 0;
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
	ev->ev_lock = lock;
	ev->ev_pagein = fault && op == DQ_OP_READ;
	ev->ev_mutates = dq_op_mutates(op, body, bodylen);

	/*
	 * The wait's mode (D192): a fault never catches a signal; a lock
	 * catches them, as lf_advlock's sleep does; the data and attribute
	 * waits catch them only under DQ_PF_INTR (an NFS intr mount), and
	 * otherwise wait as a local file system's I/O does.
	 */
	if (fault) {
		/* A page never waits forever (B1, B4). */
		deadline = dq_page_deadline(o);
		mode = DQ_WAIT_FAULT;
	} else {
		DQO_LOCK(o);
		deadline = (flags & DQ_POST_NODEADLINE) != 0 ? 0 :
		    dq_deadline(&o->o_policy);
		mode = lock || (o->o_policy.dp_flags & DQ_PF_INTR) != 0 ?
		    DQ_WAIT_CATCH : DQ_WAIT_UNINTR;
		DQO_UNLOCK(o);
	}
	error = dq_event_post_wait_ev(q, o, ev, td, mode, deadline, &pa);
	if (error == 0) {
		/*
		 * Only a queue-level RESOLVE carries an FD or SWAP answer
		 * (dq_resolve_reply_commit_locked).  Should an object event
		 * ever get one, it is released as an untaken answer is
		 * (dq_event_rele), not leaked.
		 */
		KASSERT(pa.pa_robj == NULL && pa.pa_rswap.fs_fp == NULL,
		    ("dq: object event %p answered with a RESOLVE kind", ev));
		if (__predict_false(pa.pa_robj != NULL))
			dq_object_retire_unbound(pa.pa_robj, NULL);
		if (__predict_false(pa.pa_rswap.fs_fp != NULL))
			fdswap_release(&pa.pa_rswap, curthread);
		*replyp = pa.pa_reply;
		*errnop = pa.pa_errno;
		if (agenp != NULL)
			*agenp = pa.pa_agen;
	}
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
 * catching: the queue's DQ_QF_INTR for the requester's own lookups (the
 * wait catches signals); every other wait does not (D192).
 */
int
dq_event_post_wait_q(struct dq_queue *q, uint32_t op, const void *body,
    size_t bodylen, struct thread *td, sbintime_t deadline, bool catching,
    struct dq_data **replyp, int *errnop, struct dq_object **robjp,
    struct fdswap *rswapp)
{
	struct dq_event_k *ev;
	struct dq_post_answer pa;
	int error;

	*replyp = NULL;
	*errnop = 0;
	*robjp = NULL;
	bzero(rswapp, sizeof(*rswapp));
	if (dq_caller_holds_queue(q, td))
		return (EDEADLK);
	ev = dq_event_alloc(NULL, op, body, bodylen, td);
	ev->ev_mutates = dq_op_mutates(op, body, bodylen);
	ev->ev_hdr.de_caller.dc_flags |= DQ_CALLER_F_ATTACHED;
	error = dq_event_post_wait_ev(q, NULL, ev, td,
	    catching ? DQ_WAIT_CATCH : DQ_WAIT_UNINTR, deadline, &pa);
	if (error == 0) {
		*replyp = pa.pa_reply;
		*errnop = pa.pa_errno;
		*robjp = pa.pa_robj;
		*rswapp = pa.pa_rswap;
	}
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
			/* A slot for a post waiting on a full queue (D205). */
			dq_queue_slots_freed(q, 1);
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

/*
 * Fault injection for the RESOLVE FD reply's ENOMEM row (debug.dq.
 * fail_vm_create: the next N object creations fail as if the pager object
 * could not be allocated).
 */
SYSCTL_NODE(_debug, OID_AUTO, dq, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "DescriptorQueue fault injection");
static u_int dq_fail_vm_create;
SYSCTL_UINT(_debug_dq, OID_AUTO, fail_vm_create, CTLFLAG_RW,
    &dq_fail_vm_create, 0, "Fail the next N object creations with ENOMEM");
static u_int dq_fail_link_closing;
SYSCTL_UINT(_debug_dq, OID_AUTO, fail_link_closing, CTLFLAG_RW,
    &dq_fail_link_closing, 0,
    "The next N RESOLVE FD links see the queue closing (ENXIO)");
u_int dq_fail_bind_enfile;
SYSCTL_UINT(_debug_dq, OID_AUTO, fail_bind_enfile, CTLFLAG_RW,
    &dq_fail_bind_enfile, 0,
    "The next N binds of a RESOLVE FD answer fail as falloc would (ENFILE)");
/*
 * The window in which a reply ioctl has released its requester and is
 * still telling the policies about the requester's file, made wide enough
 * for a test to close the file in it.
 */
static u_int dq_delay_reply_notify;
SYSCTL_UINT(_debug_dq, OID_AUTO, delay_reply_notify, CTLFLAG_RW,
    &dq_delay_reply_notify, 0,
    "The next N replies about an open file sleep one second after the "
    "requester is released, before the policies are told");

bool
dq_fault_inject(u_int *counter)
{
	u_int n;

	do {
		n = atomic_load_int(counter);
		if (n == 0)
			return (false);
	} while (!atomic_cmpset_int(counter, n, n - 1));
	return (true);
}

/*
 * Create an object, not yet visible: the creation reference, its pager
 * object (D102, in every cache mode, created before the object is visible
 * so a revoke always finds it) and its id, taken now (under q_mtx) so a
 * RESOLVE FD reply can hand it to the controller before linking.
 */
int
dq_object_create(struct dq_queue *q, u_int kind,
    const struct dq_ident_file *ident, const struct dq_policy *pol,
    struct dq_object **op)
{
	struct dq_object *o;
	int error;

	*op = NULL;
	o = malloc(sizeof(*o), M_DQ, M_WAITOK | M_ZERO);
	mtx_init(&o->o_mtx, "dq object", NULL, MTX_DEF);
	refcount_init(&o->o_refs, 1);	/* the creation reference */
	dq_queue_hold(q);
	o->o_queue = q;
	o->o_kind = kind;
	o->o_state = DQ_OBJ_LIVE;
	o->o_ident = *ident;
	o->o_policy = *pol;
	rangelock_init(&o->o_rl);
	knlist_init_mtx(&o->o_sel.si_note, &o->o_mtx);
	cv_init(&o->o_async_cv, "dqasync");
	TAILQ_INIT(&o->o_proofs);
	error = dq_fault_inject(&dq_fail_vm_create) ? ENOMEM : dq_object_vm_create(o);
	if (error != 0) {
		o->o_retired = true;
		knlist_destroy(&o->o_sel.si_note);
		rangelock_destroy(&o->o_rl);
		dq_object_rele(o);
		return (error);
	}
	/* q_mtx, not a 64-bit atomic: dq is MI (32-bit powerpc has none). */
	DQ_LOCK(q);
	o->o_id = ++q->q_next_object;
	DQ_UNLOCK(q);
	*op = o;
	return (0);
}

/* An object created and never linked: its id is never used. */
void
dq_object_destroy_unlinked(struct dq_object *o)
{

	o->o_retired = true;
	knlist_destroy(&o->o_sel.si_note);
	rangelock_destroy(&o->o_rl);
	/* Its release reaches o through pgo_dealloc and dq_taskq. */
	o->o_vmdropped = true;
	vm_object_deallocate(o->o_object);
	dq_object_rele(o);
}

/* Make o visible on q; the caller checked DQ_Q_CLOSING and the limit. */
void
dq_object_link_locked(struct dq_queue *q, struct dq_object *o)
{
	struct dq_object *s;

	DQ_LOCK_ASSERT(q);
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
}

/*
 * Link an object a reply minted (dq_resolve_mint_prepare) under q_mtx, as
 * dq_queue_mint links one: ENXIO on a closing queue, ENOSPC past
 * kern.dq.max_objects.
 */
int
dq_object_link_minted_locked(struct dq_queue *q, struct dq_object *o)
{

	DQ_LOCK_ASSERT(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0 ||
	    dq_fault_inject(&dq_fail_link_closing))
		return (ENXIO);
	if (q->q_nobjects >= dq_max_objects)
		return (ENOSPC);
	dq_object_link_locked(q, o);
	return (0);
}

/*
 * A linked object no file ever referenced (D171): a RESOLVE FD answer that
 * was refused after the reply, never taken, or whose file could not be
 * allocated.  Its pager object goes as dq_close's would, the id retires
 * with its CLOSE when the policy subscribes (every id a REPLY returned 0
 * for ends exactly once), and the creation reference is dropped.  td may
 * be NULL.  No dq lock held.
 */
void
dq_object_retire_unbound(struct dq_object *o, struct thread *td)
{
	struct dq_queue *q;

	q = o->o_queue;
	dq_object_vm_teardown(o, true);
	dq_object_retire(o, td);
	DQ_LOCK(q);
	q->q_stats.ds2_resolve_retired++;
	DQ_UNLOCK(q);
	SDT_PROBE2(dq, , , resolve__retire, q, o);
	dq_object_rele(o);
}

int
dq_queue_mint(struct dq_queue *q, struct dq_mint_args *args, struct thread *td)
{
	struct dq_object *o;
	int error, reason;

	args->dm_object = 0;
	args->dm_fd = -1;
	if (args->dm_version != DQ_API_VERSION)
		return (dq_mint_reason(args, DQ_REASON_VERSION, EINVAL));
	/* A directory may be minted too (1c-iii-b); a symlink only by FD. */
	if (args->dm_kind != DQ_KIND_FILE && args->dm_kind != DQ_KIND_DIR)
		return (dq_mint_reason(args, DQ_REASON_KIND, EINVAL));
	error = dq_ident_validate(args->dm_kind, &args->dm_ident, &reason);
	if (error == 0)
		error = dq_policy_validate_kind(args->dm_kind,
		    &args->dm_policy, &reason);
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

	error = dq_object_create(q, args->dm_kind, &args->dm_ident,
	    &args->dm_policy, &o);
	if (error != 0)
		return (dq_mint_reason(args, DQ_REASON_NONE, error));
	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0 || q->q_nobjects >= dq_max_objects) {
		error = (q->q_flags & DQ_Q_CLOSING) != 0 ? ENXIO : ENOSPC;
		DQ_UNLOCK(q);
		dq_object_destroy_unlinked(o);
		return (dq_mint_reason(args, DQ_REASON_NONE, error));
	}
	dq_object_link_locked(q, o);
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
 * list).  EINTR is the kernel's alone (D193): only a wait that catches a
 * signal gives it, never a controller's answer.
 */
static bool
dq_reply_errno_allowed(uint32_t op, int error)
{

	if (error == EINTR)
		return (false);
	switch (op) {
	case DQ_OP_WRITE:
	case DQ_OP_WRITE_ASYNC:
		return (error == EIO || error == ENOSPC || error == EDQUOT ||
		    error == EFBIG || error == EACCES || error == EPERM ||
		    error == EROFS || error == EAGAIN ||
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
		    error == EINVAL || error == EIO);
	case DQ_OP_IOCTL:
		return (error == ENOTTY || error == EINVAL || error == EIO ||
		    error == EPERM || error == EACCES || error == ENXIO);
	case DQ_OP_READDIR:
		return (dq_readdir_errno_allowed(error));
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
		    dq_object_ident_check(ev->ev_object, buf) != 0)
			return (EINVAL);
		return (0);
	case DQ_OP_READDIR:
		return (dq_readdir_reply_validate(ev, rerrno, buf, len));
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
		 * The remaining range, as vn_deallocate's contract has it:
		 * it starts no earlier than the request and no later than its
		 * end, and either ends where the request ended (progress) or
		 * is empty (done, or stopped at the end of the file, as
		 * vop_stddeallocate answers past EOF: {EOF, 0} or {offset,
		 * 0}).  The kernel validated offset + len <= OFF_MAX before
		 * posting, and passes the reply to the caller as it is.
		 */
		end = sb->dsc_offset + sb->dsc_len;
		if (sr->dscr_offset < sb->dsc_offset || sr->dscr_offset > end ||
		    sr->dscr_len > end - sr->dscr_offset ||
		    (sr->dscr_len != 0 && sr->dscr_offset + sr->dscr_len != end))
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
		return (dq_resolve_reply_validate(ev, rerrno, buf, len));
	default:
		return (EINVAL);
	}
}

/* The policies have been told about o_fp: let its close go on. */
static void
dq_object_notify_done(struct dq_object *o)
{

	DQO_LOCK(o);
	KASSERT(o->o_notify > 0, ("dq: object %p not being notified", o));
	if (--o->o_notify == 0)
		wakeup(&o->o_notify);
	DQO_UNLOCK(o);
}

/*
 * The first thing the last close does (dq_close): no reply finds the file
 * from here on, and those that found it are done with it on return.
 */
void
dq_object_close_begin(struct dq_object *o)
{

	DQO_LOCK(o);
	o->o_fp = NULL;
	while (o->o_notify > 0)
		msleep(&o->o_notify, &o->o_mtx, PVFS, "dqntfy", 0);
	DQO_UNLOCK(o);
}

/*
 * A reply: copy the data in before any lock, find the event among those
 * delivered, check the body against the operation, hand it to the waiter.
 * A RESOLVE reply may be larger than kern.dq.max_io, up to
 * DQ_RESOLVE_REPLY_MAX (D129).  Its FD and SWAP answers have work of their
 * own (M11), in dq_resolve.c: before the lock (the mint, the take of the
 * file), under it once the reply is valid (the link), and the undoing of
 * both when the reply is refused or its event has gone.
 */
int
dq_queue_reply(struct dq_queue *q, const struct dq_reply *r, struct thread *td)
{
	struct dq_event_k key, *ev;
	struct dq_object *o;
	struct dq_data *dd;
	struct file *fp;
	struct dq_resolve_rctx rc;
	size_t len;
	uint32_t op;
	int error, rerrno, stopdefer, undone __diagused;
	bool async, postop;

	postop = (r->dr_flags & DQ_REPLY_F_POSTOP) != 0;
	if (r->dr_version != DQ_API_VERSION ||
	    (r->dr_flags & ~DQ_REPLY_F_VALID) != 0 ||
	    r->dr_errno < 0 || r->dr_errno > ELAST ||
	    r->dr_len > MAX(dq_max_io, DQ_RESOLVE_REPLY_MAX) +
	    (postop ? sizeof(struct dq_postop_attr) : 0) ||
	    (postop && (r->dr_errno != 0 ||
	    r->dr_len < sizeof(struct dq_postop_attr))))
		return (EINVAL);
#ifdef DQ_FAULT_INJECTION
	if (postop && dq_faultinj_postop_refuse())
		return (EINVAL);
#endif
	len = r->dr_len;
	dd = NULL;
	if (len != 0) {
		dd = dq_data_alloc(len);
		error = copyin(r->dr_data, dd->dd_bytes, len);
		if (error != 0) {
			dq_data_rele(dd);
			return (error);
		}
		if (postop) {
			/* The block ends the data; the reply is the rest. */
			dd->dd_postop = true;
			dd->dd_plen = len - sizeof(struct dq_postop_attr);
			len = dd->dd_plen;
		}
	}
	error = dq_resolve_reply_pre(q, r, dd, len, postop, td, &rc);
	if (error != 0) {
		dq_data_rele(dd);
		return (error);
	}

	key.ev_hdr.de_id = r->dr_id;
	DQ_LOCK(q);
	ev = RB_FIND(dq_inflight_tree, &q->q_inflight, &key);
	if (ev == NULL) {
		q->q_stats.ds2_late_replies++;
		SDT_PROBE2(dq, , , reply__late, q, r->dr_id);
		DQ_UNLOCK(q);
		dq_data_rele(dd);
		/* ESRCH, or ECANCELED when a SWAP answer's take ran. */
		return (dq_resolve_reply_abort(&rc, td));
	}
	KASSERT(ev->ev_state == DQ_EV_DELIVERED, ("dq: inflight event state"));
	op = ev->ev_hdr.de_op;
	o = ev->ev_object;
	if (op != DQ_OP_RESOLVE && len > dq_max_io)
		error = EINVAL;
	else if (postop && op != DQ_OP_READ && op != DQ_OP_WRITE &&
	    op != DQ_OP_FALLOCATE && op != DQ_OP_FSPACECTL)
		error = EINVAL;		/* not an operation that has one */
	else
		error = dq_reply_validate(ev, r->dr_errno,
		    dd != NULL ? dd->dd_bytes : NULL, len);
	if (error == 0)
		error = dq_resolve_reply_commit_locked(q, ev, r->dr_errno, dd,
		    &rc);
	if (error != 0) {
		DQ_UNLOCK(q);
		dq_data_rele(dd);
		/*
		 * dq_resolve_swap_prepare refused everything the validation
		 * refuses before it took a file, and the raced-prepare case
		 * took none: a taken file is never refused here.
		 */
		undone = dq_resolve_reply_abort(&rc, td);
		KASSERT(undone == ESRCH,
		    ("dq: reply %d refused after its take", error));
		return (error);
	}
	/* Nothing fails from here: the event owns the taken file. */
	rerrno = r->dr_errno;
	if (rerrno != 0 && !(op == DQ_OP_RESOLVE ?
	    dq_resolve_reply_errno_allowed(ev, rerrno) :
	    dq_reply_errno_allowed(op, rerrno))) {
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
	/* The order the controller answered in (dq_object_gen_newer). */
	if (o != NULL)
		ev->ev_agen = ++o->o_agen;
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
		if (DQ_WAKE(DQ_WAKE_ANSWER)) {
			cv_signal(&ev->ev_cv);
			dq_mutwait_wake_locked(ev);
		}
	SDT_PROBE4(dq, , , event__reply, q, ev, r->dr_errno, len);
	/* Observers and the policies see what the controller said. */
	dq_observer_fanout_reply(q, r->dr_id, r->dr_errno, dd);

	/*
	 * D89: tell the policies, with no lock held.  The requester is
	 * running again and may close the file before the policies return.
	 * A reference taken here would then be the file's last, and the
	 * close the program made would release nothing: the UNLOCK_ALL of
	 * its flock and OFD locks would be posted from this ioctl, after
	 * whatever the program did next.  So the file is not referenced.
	 * It is kept by o_notify: dq_close clears o_fp and waits for the
	 * count under o_mtx before it does anything else, so a file found
	 * here stays whole, and the object with it (the file's reference
	 * on the object goes after dq_close), until dq_object_notify_done.
	 * Its count may be 0 by then (that close is waiting); the policies
	 * must not take a reference on it.
	 */
	fp = NULL;
	if (o != NULL) {
		DQO_LOCK(o);
		fp = o->o_fp;
		if (fp != NULL)
			o->o_notify++;
		DQO_UNLOCK(o);
	}
	DQ_UNLOCK(q);
	/*
	 * The list reference.  Not the event's last unless it has no file
	 * to release: a delivered event has a waiter, which takes a SWAP
	 * answer's file (ev_rswap) under q_mtx before it lets go.
	 */
	if (!async)
		dq_event_rele(ev);
	if (fp != NULL) {
		if (dq_fault_inject(&dq_delay_reply_notify))
			pause_sbt("dqdely", SBT_1S, 0, 0);
		/*
		 * A stop must not suspend this thread in a sleep a policy
		 * makes: the file's last close, and with it its process's
		 * exit, waits for the hook and no signal ends that wait.
		 */
		stopdefer = sigdeferstop(SIGDEFERSTOP_SILENT);
		mac_file_notify_reply(q->q_cred, fp, op, r->dr_errno, len);
		sigallowstop(stopdefer);
		dq_object_notify_done(o);
	}
	return (0);
}

int
dq_queue_setident(struct dq_queue *q, struct dq_setident_args *args)
{
	struct dq_object key, *o;
	int error;

	if (args->dsi_version != DQ_API_VERSION || args->dsi_pad0 != 0)
		return (EINVAL);
	key.o_id = args->dsi_object;
	DQ_LOCK(q);
	o = RB_FIND(dq_object_tree, &q->q_objects, &key);
	if (o == NULL) {
		DQ_UNLOCK(q);
		return (ESRCH);
	}
	error = dq_object_ident_check(o, &args->dsi_ident);
	if (error != 0) {
		DQ_UNLOCK(q);
		return (error);
	}
	dq_object_set_ident_locked(q, o, &args->dsi_ident, NOTE_ATTRIB);
	dq_object_hold(o);
	DQ_UNLOCK(q);
	/* B10: the pager object's size follows, with no dq lock held. */
	dq_object_sync_vmsize(o);
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
	cur->dp_flags = new->dp_flags;
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
	st->ds2_standing_pass = dq_standing_count(q, false);
	st->ds2_standing_deny = dq_standing_count(q, true);
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

int
dq_queue_flags(struct dq_queue *q, struct dq_queue_flags *qf)
{

	if (((qf->dqf_set | qf->dqf_clear) & ~DQ_QF_VALID) != 0 ||
	    (qf->dqf_set & qf->dqf_clear) != 0 || qf->dqf_pad0 != 0)
		return (EINVAL);
	DQ_LOCK(q);
	qf->dqf_old = q->q_qflags;
	q->q_qflags = (q->q_qflags & ~qf->dqf_clear) | qf->dqf_set;
	DQ_UNLOCK(q);
	return (0);
}

/* A controller may lower its depth below the system bound, never raise it. */
int
dq_queue_set_depth(struct dq_queue *q, uint32_t depth)
{

	if (depth == 0 || depth > dq_queue_depth)
		return (EINVAL);
	DQ_LOCK(q);
	/*
	 * Posts waiting for a slot look again at the new depth, and an
	 * async post refused for the depth may go (msync, a parked destroy).
	 */
	if (depth > q->q_depth) {
		q->q_depth = depth;
		wakeup(&q->q_space);
		dq_queue_room_locked(q);
	} else
		q->q_depth = depth;
	DQ_UNLOCK(q);
	return (0);
}
