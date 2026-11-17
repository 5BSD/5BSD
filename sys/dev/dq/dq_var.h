/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: kernel-private structures.
 *
 * Lock order, outermost first:
 *   FILEDESC_SLOCK (the EDEADLK scan) -> foffset -> rangelock -> q_rdsx ->
 *   dq_mtx -> q_mtx -> o_mtx.
 * The EDEADLK scan (dq_caller_holds_queue) runs at the top of every fileop
 * that serializes before posting, before foffset_lock_uio or any
 * rangelock, and again inside dq_event_post_wait: a controller touching
 * its own served descriptor must get EDEADLK, never sleep uninterruptibly
 * in rangelock_*lock behind a requester whose event only it can answer.
 * foffset and the rangelock are not witness locks; the scan is taken with
 * no dq mutex held.  q_file is compared by address while the queue is not
 * CLOSING.  CLOSING is set by the die (dq_queue_die): at the owner's exit,
 * exec or leaving of a shared table, while the file may still be held, or
 * from the cdevpriv destructor after the file's count hit zero; in that
 * last case a reused address can give one false EDEADLK in the window
 * (accepted).
 * q_owner is written with dq_mtx and q_mtx both held and read with either;
 * it is cleared in the q_mtx section that sets DQ_Q_DEAD, so an owned queue
 * is never dead.  The flags obey DIED => CLOSING => DEAD; a queue leaves
 * dq_queues, and is freed, only once DIED.
 * Nothing sleeps under q_mtx or o_mtx except the waits that release q_mtx
 * (the ev_cv waits and the msleeps on o_inflight, q_requesters and
 * q_pending) and one that releases o_mtx: dq_close's wait for o_notify
 * (below).  copyin, copyout, uiomove and M_WAITOK allocations happen
 * with neither held; observer records are M_NOWAIT and a failure is a
 * counted drop.  Knote filters run under the knlist's mutex (o_mtx for an
 * object, q_mtx for a queue or an observer) and never take the other.
 * The identity index (q_idhash) is under q_mtx; the sibling walks
 * (dq_object_knote_siblings, dq_object_mark_locked) take q_mtx then each
 * sibling's o_mtx in turn, never two o_mtx at once.  Reply data (struct dq_data) and WRITE events
 * are refcounted and shared between the waiter and the observer records
 * that hold them; the last release happens with no dq lock held.
 *
 * Pages (stage 1b-ii).  The VM object write lock of an object's pager
 * object (o_object) comes before q_mtx and o_mtx: vm_pageout_flush enters
 * dq_pager_putpages with it held, and the async post takes q_mtx (and
 * o_mtx inside it) under it.  So the VM object lock is never taken with
 * q_mtx or o_mtx held: an async completion (controller reply, deadline,
 * revoke, close) unlinks its event under q_mtx, hands it to dq_taskq, and
 * the task takes the VM object lock with no dq lock held.  The reply ioctl
 * never takes a VM object lock.  o_closing is written with the VM object
 * write lock and o_mtx both held (read under either).  Waits for dq's own
 * completions (o_async_cv on o_mtx) and for the VM-object users count
 * (o_vmusers) are the only sleeps close, revoke and queue close add; the
 * task never waits for anything but the VM object lock and page busy, so
 * nothing in fo_close, pgo_dealloc, the page daemon or
 * vm_object_terminate waits for the controller (I11).  fo_close also
 * waits for o_notify: a reply ioctl that is telling the MAC policies about
 * the object's file (mac_file_notify_reply) does so without a reference
 * on the file, which would make the reply ioctl, not the program's close,
 * the last close whenever the program closed first, and the release of
 * its flock and OFD locks late.  It counts itself in o_notify instead,
 * while o_fp is set, and dq_close clears o_fp and waits for the count
 * before anything else.  That wait is for kernel code in the hook, not
 * for anything the controller does: it ends without the controller's
 * help.  The per-queue
 * callout runs with q_mtx held (callout_init_mtx) and only hands expired
 * events to the task.  The task queue's own mutex ("dq_taskq") is a leaf:
 * taskqueue_enqueue runs under q_mtx (reply, deadline, revoke, close) and
 * under the VM object lock (pgo_dealloc), and nothing dq owns is taken
 * with it held (tasks run without it; the deferred close's timeout callout
 * only re-enqueues).  So: dq_mtx -> q_mtx -> o_mtx, VM object -> q_mtx,
 * and q_mtx or VM object -> dq_taskq's mutex, with no cycle.
 *
 * What a dq_taskq task may sleep on (two threads serve every queue's
 * completions, so a task never waits for dq_taskq work, for the controller
 * or for memory).  The completion (dq_async_complete) takes the VM object
 * write lock (its holders never wait while holding it: putpages posts
 * without waiting, msync, a shrink and vm_page_busy_sleep drop it before
 * they sleep) and q_mtx/o_mtx; its INTERRUPT is M_NOWAIT and counted in
 * ds2_task_drops when it fails.  The deferred close (dq_object_destroy_task)
 * re-arms itself instead of waiting, allocates its CLOSE M_NOWAIT (re-arming
 * on failure) and frees pages with vm_page_tryxbusy (re-arming on a busy
 * page).  The sleeps that remain are bounded and wait on nothing dq queues:
 * vm_object_deallocate's terminate waits for paging in progress when the
 * creation reference was the last, and by then o_async is 0 and o_closing
 * refuses new posts, so only the page daemon's momentary pip can remain;
 * knlist_clear (in the retire and the final queue release, also reached
 * from the pgo_dealloc release task) sleeps while a kevent scan has one of
 * the object's knotes in flux, which ends without dq; seldrain only wakes.
 */

#ifndef _DEV_DQ_DQ_VAR_H_
#define	_DEV_DQ_DQ_VAR_H_

#include <sys/param.h>
#include <sys/_task.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/counter.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/rangelock.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/sx.h>
#include <sys/tree.h>
#include <sys/fdswap.h>

#include <dev/dq/dq.h>

MALLOC_DECLARE(M_DQ);

SDT_PROVIDER_DECLARE(dq);
SDT_PROBE_DECLARE(dq, , , queue__open);
SDT_PROBE_DECLARE(dq, , , queue__close);
SDT_PROBE_DECLARE(dq, , , mint);
SDT_PROBE_DECLARE(dq, , , revoke);
SDT_PROBE_DECLARE(dq, , , swap__refused);
SDT_PROBE_DECLARE(dq, , , object__close);
SDT_PROBE_DECLARE(dq, , , event__post);
SDT_PROBE_DECLARE(dq, , , event__deliver);
SDT_PROBE_DECLARE(dq, , , event__reply);
SDT_PROBE_DECLARE(dq, , , event__drop);
SDT_PROBE_DECLARE(dq, , , event__interrupt);
SDT_PROBE_DECLARE(dq, , , event__deadline);
SDT_PROBE_DECLARE(dq, , , reply__late);
SDT_PROBE_DECLARE(dq, , , attach);
SDT_PROBE_DECLARE(dq, , , resolve__post);
SDT_PROBE_DECLARE(dq, , , resolve__reply);
SDT_PROBE_DECLARE(dq, , , resolve__failclosed);
SDT_PROBE_DECLARE(dq, , , resolve__unmarked);
SDT_PROBE_DECLARE(dq, , , resolve__locked);
SDT_PROBE_DECLARE(dq, , , resolve__served);
SDT_PROBE_DECLARE(dq, , , resolve__retire);
SDT_PROBE_DECLARE(dq, , , resolve__real);
SDT_PROBE_DECLARE(dq, , , resolve__symlink);
SDT_PROBE_DECLARE(dq, , , fop__local);
SDT_PROBE_DECLARE(dq, , , quota__wait);
SDT_PROBE_DECLARE(dq, , , postop__attr);

/* dq:::quota-wait's quota (args: queue, event, DQ_QUOTA_*, errno). */
#define	DQ_QUOTA_OBJECT		1	/* kern.dq.max_inflight_per_object */
#define	DQ_QUOTA_REQUESTER	2	/* kern.dq.max_inflight_per_requester */

/*
 * dq:::fop-local's operation: a fileop the kernel answered from the
 * identity or the descriptor, with no event (args: file, DQ_FOP_*, errno).
 */
#define	DQ_FOP_IOCTL		1
#define	DQ_FOP_FCNTL		2
#define	DQ_FOP_FADVISE		3
#define	DQ_FOP_SEEK		4
#define	DQ_FOP_PATHCONF		5
#define	DQ_FOP_STATFS		6

/* Tunables (dq_dev.c), kern.dq.* */
extern u_int dq_max_io;
extern u_int dq_queue_depth;
extern u_int dq_max_inflight_per_object;
extern u_int dq_max_inflight_per_requester;
extern u_int dq_max_objects;
extern int dq_default_deadline_ms;
extern u_int dq_max_inflight_bytes;
extern int dq_kernel_deadline_ms;	/* class 2/3 and lock-holding waits */

/* The page deadline when neither the policy nor the default sets one. */
#define	DQ_PAGE_DEADLINE_MS	30000

struct taskqueue;
extern struct taskqueue *dq_taskq;	/* async completions (dq_dev.c) */
extern int dq_pager_type;		/* the dq pager's objtype, or -1 */

struct dq_queue;
struct dq_object;
struct dq_observer;
struct dq_event_k;
struct dq_async;
struct vm_object;
struct vm_page;
int	dq_event_cmp(const struct dq_event_k *, const struct dq_event_k *);
int	dq_object_cmp(const struct dq_object *, const struct dq_object *);

/*
 * Reply data (D101): one refcounted buffer shared by the waiter and every
 * data observer's record, so a reply is copied in once and never copied
 * again under a lock.  dd_len is the controller's length; the allocation
 * is dd_len bytes rounded up to 8, zero padded, so a record copy can take
 * the padding from it.
 */
struct dq_data {
	u_int			 dd_refs;
	size_t			 dd_len;
	size_t			 dd_plen;	/* the reply without its post-op
						   block: what the operation
						   reads (dd_len without one) */
	bool			 dd_postop;	/* DQ_REPLY_F_POSTOP: a struct
						   dq_postop_attr ends dd_bytes */
	char			 dd_bytes[];
};

/*
 * A posted event.  ev_hdr and the body are one allocation; ev_size is the
 * record length (header + body) the controller reads.
 */
enum dq_event_state {
	DQ_EV_PENDING = 1,	/* posted, not yet read by the controller */
	DQ_EV_DELIVERED,	/* read, awaiting the reply */
	DQ_EV_REPLIED,		/* reply attached */
	DQ_EV_INTERRUPTED,	/* waiter gave up after delivery */
	DQ_EV_FAILED,		/* revoke, close, deadline or drop */
};

struct dq_event_k {
	TAILQ_ENTRY(dq_event_k)	 ev_link;	/* q_pending */
	RB_ENTRY(dq_event_k)	 ev_tree;	/* q_inflight */
	u_int			 ev_refs;
	enum dq_event_state	 ev_state;
	bool			 ev_waited;	/* a poster waits for a reply */
	bool			 ev_linked;	/* on q_pending or in q_inflight */
	struct cv		 ev_cv;
	int			 ev_errno;	/* reply errno or failure */
	struct dq_data		*ev_reply;	/* reply data; the waiter takes
						   the reference */
	bool			 ev_lock;	/* a LOCK: counted in o_locks */
	struct dq_async		*ev_async;	/* READ_ASYNC/WRITE_ASYNC */
	bool			 ev_pagein;	/* a pager READ (DQ_POST_FAULT):
						   a shrink may fail it */
	sbintime_t		 ev_deadline;	/* 0 = none */
	struct dq_object	*ev_object;	/* held; NULL for queue-level */
	struct dq_object	*ev_robj;	/* RESOLVE FD (1c-iii): the object
						   minted at the reply, linked,
						   holding its creation reference;
						   the waiter takes it, else
						   dq_event_rele retires it */
	struct fdswap		 ev_rswap;	/* RESOLVE SWAP: the file taken
						   from the controller at the
						   reply; the waiter takes it,
						   else dq_event_rele releases
						   it */
	uint64_t		 ev_requester;	/* per-requester quota key */
	size_t			 ev_size;
	struct dq_event		 ev_hdr;	/* body follows */
};

RB_HEAD(dq_inflight_tree, dq_event_k);
RB_PROTOTYPE(dq_inflight_tree, dq_event_k, ev_tree, dq_event_cmp);

/* Per-requester in-flight accounting (D60), keyed by nonce or pid. */
struct dq_requester {
	LIST_ENTRY(dq_requester) rq_link;
	uint64_t		 rq_key;
	u_int			 rq_inflight;
};
#define	DQ_REQUESTER_HASH	64

/*
 * An observer record: a copy of an event or a reply, maybe without data.
 * The header and the fixed body are inline; a data observer's WRITE record
 * holds the event instead of copying its data (or_ev: the body is read
 * from the event's own allocation, which never changes after the post) and
 * its REPLY record holds the reply buffer (or_data) as a second piece.
 * or_size is the whole record as the observer reads it.
 */
struct dq_obs_rec {
	TAILQ_ENTRY(dq_obs_rec)	 or_link;
	size_t			 or_size;
	size_t			 or_inline;	/* body bytes after or_hdr */
	struct dq_event_k	*or_ev;		/* held; body from the event */
	struct dq_data		*or_data;	/* held; second piece */
	struct dq_event		 or_hdr;	/* inline body follows */
};

struct dq_observer {
	LIST_ENTRY(dq_observer)	 ob_link;	/* q_observers */
	struct dq_queue		*ob_queue;	/* holds a q_refs */
	struct sx		 ob_rdsx;	/* one reader at a time */
	u_int			 ob_flags;	/* DQ_OBS_F_* */
	u_int			 ob_count;
	u_int			 ob_depth;
	bool			 ob_closed;	/* unlinked from the queue */
	uint64_t		 ob_seq;
	uint64_t		 ob_drops;
	TAILQ_HEAD(, dq_obs_rec) ob_pending;
	struct selinfo		 ob_sel;	/* knlist on q_mtx */
};

/*
 * An asynchronous page operation (B1-B3): a READ_ASYNC filling sendfile's
 * busy pages or a WRITE_ASYNC carrying share-busied dirty pages.  It owns
 * the event's allocation reference.  While da_posted it is on q_async
 * (under q_mtx) and its event is pending or delivered; a reply, the
 * deadline, a revoke or a close unlinks both and enqueues da_task, which
 * finishes the pages (dq_async_complete) and frees it.
 */
struct dq_async {
	TAILQ_ENTRY(dq_async)	 da_link;	/* q_async while posted */
	struct task		 da_task;
	struct dq_event_k	*da_ev;
	struct vm_object	*da_obj;
	sbintime_t		 da_deadline;
	size_t			 da_len;	/* bytes charged to q_async_bytes */
	bool			 da_write;
	bool			 da_posted;	/* on q_async */
	bool			 da_listref;	/* the task drops the list ref */
	bool			 da_interrupt;	/* failed after delivery */
	bool			 da_shrink;	/* failed by a shrink, which
						   waits for it (o_shrinkwait) */
	off_t			 da_offset;
	uint64_t		 da_invalgen;	/* o_invalgen at the post */
	void			(*da_iodone)(void *, struct vm_page **, int,
				    int);
	void			*da_arg;
	int			 da_count;
	struct vm_page		*da_pages[];
};

enum dq_object_state {
	DQ_OBJ_LIVE = 1,
	DQ_OBJ_REVOKED,
};

struct dq_object {
	struct mtx		 o_mtx;
	struct dq_queue		*o_queue;	/* holds a q_refs */
	struct file		*o_fp;		/* weak; NULL once dq_close has
						   begun */
	u_int			 o_notify;	/* o_mtx: replies telling the
						   policies about o_fp; dq_close
						   waits for them */
	u_int			 o_refs;
	uint64_t		 o_id;
	u_int			 o_kind;
	enum dq_object_state	 o_state;
	u_int			 o_inflight;	/* posted, not yet answered;
						   LOCK events excepted (B6) */
	u_int			 o_locks;	/* LOCK events posted, unanswered */
	u_int			 o_locked;	/* DQ_LOCKED_*: a LOCK of this
						   kind was ever posted (D14) */
#define	DQ_LOCKED_POSIX		0x1
#define	DQ_LOCKED_FLOCK		0x2
#define	DQ_LOCKED_OFD		0x4
	bool			 o_retired;	/* removed from q_objects */
	char			*o_target;	/* DQ_KIND_SYMLINK: the target
						   (M_DQ, NUL-terminated), fixed
						   before the object is linked */
	size_t			 o_targetlen;	/* == o_ident.di_size */
	struct dq_ident_file	 o_ident;
	struct dq_policy	 o_policy;
	struct rangelock	 o_rl;
	struct selinfo		 o_sel;		/* EVFILT_* knotes, on o_mtx */
	RB_ENTRY(dq_object)	 o_tree;	/* q_objects */
	/*
	 * The identity index (N6): objects of one (di_dev, di_ino) share a
	 * q_idhash bucket, so sibling walks touch only that bucket.  The
	 * indexed key is kept here, under q_mtx, because o_ident changes
	 * under o_mtx alone for the fields that are not the key.
	 */
	LIST_ENTRY(dq_object)	 o_idlink;	/* q_idhash, under q_mtx */
	uint64_t		 o_hdev;	/* indexed di_dev, under q_mtx */
	uint64_t		 o_hino;	/* indexed di_ino, under q_mtx */
	bool			 o_hashed;	/* on q_idhash */
	/*
	 * Pages (D102).  o_object is the pager object, created at mint with
	 * handle = o; it holds a reference on o, dropped from dq_taskq after
	 * pgo_dealloc (o_rele_task), and o holds a VM reference on it until
	 * dq_close (o_vmdropped).  Controller-side users (revoke, queue
	 * close, INVALIDATE, SETIDENT) count themselves in o_vmusers so the
	 * close does not drop that reference under them.
	 */
	struct vm_object	*o_object;
	bool			 o_closing;	/* B2: no new page I/O; VM object
						   lock and o_mtx to write */
	bool			 o_vmdropped;	/* o_mtx: dq_close dropped the VM
						   reference */
	bool			 o_again;	/* VM object lock: putpages said
						   AGAIN (msync retries) */
	u_int			 o_vmusers;	/* o_mtx */
	u_int			 o_async;	/* o_mtx: async ops posted, not
						   completed */
	u_int			 o_awrites;	/* o_mtx: of which WRITE_ASYNC */
	uint64_t		 o_async_done;	/* o_mtx: completions */
	uint64_t		 o_async_errs;	/* o_mtx: failed write completions */
	/*
	 * o_mtx: the byte ranges of the last DQ_ERRRING failed write-backs,
	 * by o_async_errs at the failure, so a flush reports only failures
	 * inside its own range (N8 of the review).
	 */
#define	DQ_ERRRING		8
	struct dq_errrec {
		uint64_t	 er_gen;
		off_t		 er_start;
		off_t		 er_end;
	}			 o_errring[DQ_ERRRING];
	uint64_t		 o_invalgen;	/* o_mtx: INVALIDATEs; a page-in
						   that saw it change re-reads */
	struct cv		 o_async_cv;	/* o_mtx: a completion */
	off_t			 o_vmsize;	/* the size object->size follows
						   and the pager serves (B10);
						   VM object lock and o_mtx to
						   write, either to read */
	u_int			 o_shrinkwait;	/* o_mtx: async ops a shrink
						   failed and waits for */
	bool			 o_closed;	/* last close: no new page-ins;
						   write-back continues (VM
						   object lock and o_mtx) */
	u_long			 o_writemappings; /* atomic: bytes mapped
						   shared and writable */
	struct task		 o_rele_task;	/* pgo_dealloc's release */
	struct timeout_task	 o_destroy;	/* deferred close (dq_taskq) */
	struct dq_event_k	*o_closeev;	/* its CLOSE, allocated ahead */
	sbintime_t		 o_destroy_deadline; /* the destroy task's */
};
#define	DQ_IDHASH		64

RB_HEAD(dq_object_tree, dq_object);
RB_PROTOTYPE(dq_object_tree, dq_object, o_tree, dq_object_cmp);

struct dq_queue {
	struct mtx		 q_mtx;
	struct sx		 q_rdsx;	/* serializes read(2) */
	u_int			 q_refs;
	u_int			 q_flags;
#define	DQ_Q_CLOSING		0x1	/* the controller is gone: fail */
#define	DQ_Q_DEAD		0x2	/* the die began: no owner, no entry */
#define	DQ_Q_DIED		0x4	/* the die's teardown is finished */
#define	DQ_Q_PINNED		0x8	/* opened on a pinned file */
	u_int			 q_qflags;	/* DQ_QF_* of the controller (q_mtx) */
	char			 q_space;	/* wait channel: a slot (D205) */
	struct proc		*q_owner;	/* the opening process, compared
						   and never dereferenced; NULL
						   once DEAD */
	struct thread		*q_dier;	/* runs the die; q_mtx */
	uint64_t		 q_gid;		/* kernel-wide, never reused */
	struct file		*q_file;	/* the opener's file, identity only */
	struct ucred		*q_cred;	/* controller credential */
	pid_t			 q_pid;		/* controller pid at open */
	TAILQ_HEAD(, dq_event_k) q_pending;
	struct dq_inflight_tree	 q_inflight;
	u_int			 q_depth;
	u_int			 q_count;
	u_int			 q_highwater;
	uint64_t		 q_bytes;
	uint64_t		 q_next_id;
	uint64_t		 q_seq;
	struct dq_object_tree	 q_objects;
	LIST_HEAD(dq_object_idlist, dq_object) q_idhash[DQ_IDHASH]; /* by (dev, ino) */
	uint64_t		 q_next_object;	/* q_mtx; ids are taken before
						   the object is linked (1c-iii) */
	u_int			 q_nobjects;
	u_int			 q_nobservers;
	LIST_HEAD(, dq_observer) q_observers;
	LIST_HEAD(, dq_requester) q_requesters[DQ_REQUESTER_HASH];
	struct selinfo		 q_sel;		/* knlist on q_mtx */
	struct dq_stats2	 q_stats;	/* GET_STATS is a projection */
	LIST_ENTRY(dq_queue)	 q_all;		/* dq_queues, under dq_mtx */
	/* Async page operations (B1, B3), under q_mtx. */
	TAILQ_HEAD(, dq_async)	 q_async;	/* posted, oldest first */
	uint64_t		 q_async_bytes;
	u_int			 q_nasync;
	struct callout		 q_callout;	/* earliest da_deadline; q_mtx */
	sbintime_t		 q_callout_at;	/* 0: not armed */
	struct dqres_binding	*q_binding;	/* attachments (1c), under q_mtx;
						   holds a q_refs */
};

#define	DQ_LOCK(q)		mtx_lock(&(q)->q_mtx)
#define	DQ_UNLOCK(q)		mtx_unlock(&(q)->q_mtx)
#define	DQ_LOCK_ASSERT(q)	mtx_assert(&(q)->q_mtx, MA_OWNED)
#define	DQO_LOCK(o)		mtx_lock(&(o)->o_mtx)
#define	DQO_UNLOCK(o)		mtx_unlock(&(o)->o_mtx)
#define	DQO_LOCK_ASSERT(o)	mtx_assert(&(o)->o_mtx, MA_OWNED)

/*
 * Test access (dq_testopen.c), declared and defined only in a kernel built
 * with options DQ_TEST_OPEN: a production kernel and its debug file do not
 * carry the name.  Whoever needs it includes opt_dq.h first.
 */
#ifdef DQ_TEST_OPEN
void	dq_testopen_bind(struct thread *);
#endif

/* Global state (dq_dev.c). */
extern struct mtx dq_mtx;
extern LIST_HEAD(dq_queue_list, dq_queue) dq_queues;
extern u_int dq_nqueues;
extern uint64_t dq_next_gid;

/* dq_queue.c */
struct dq_queue *dq_queue_create(struct thread *td, struct file *fp);
void	dq_queue_hold(struct dq_queue *q);
void	dq_queue_rele(struct dq_queue *q);
void	dq_queue_die(struct dq_queue *q);
void	dq_queue_close(struct dq_queue *q);
void	dq_queue_owner_gone(struct proc *p);
int	dq_queue_enter(struct dq_queue *q, struct thread *td);
int	dq_queue_read(struct dq_queue *q, struct uio *uio, int ioflag);
int	dq_queue_poll(struct dq_queue *q, int events, struct thread *td);
int	dq_queue_kqfilter(struct dq_queue *q, struct knote *kn);
int	dq_queue_mint(struct dq_queue *q, struct dq_mint_args *args,
	    struct thread *td);
int	dq_queue_mint_observer(struct dq_queue *q, struct dq_observer_args *,
	    struct thread *td);
int	dq_queue_reply(struct dq_queue *q, const struct dq_reply *r,
	    struct thread *td);
int	dq_queue_revoke(struct dq_queue *q, uint64_t object);
int	dq_queue_setident(struct dq_queue *q, struct dq_setident_args *args);
int	dq_queue_setpolicy(struct dq_queue *q, struct dq_setpolicy_args *);
int	dq_queue_push(struct dq_queue *q, const struct dq_push_args *args);
void	dq_queue_stats(struct dq_queue *q, struct dq_stats *st);
void	dq_queue_stats2(struct dq_queue *q, struct dq_stats2 *st);
int	dq_queue_set_depth(struct dq_queue *q, uint32_t depth);
int	dq_queue_flags(struct dq_queue *q, struct dq_queue_flags *qf);
bool	dq_caller_holds_queue(struct dq_queue *q, struct thread *td);

void	dq_object_hold(struct dq_object *o);
void	dq_object_rele(struct dq_object *o);
void	dq_object_retire(struct dq_object *o, struct thread *td);
void	dq_object_retire_ev(struct dq_object *o, struct thread *td,
	    struct dq_event_k *closeev);
void	dq_object_knote_siblings(struct dq_object *o, long hint);
void	dq_object_mark_locked(struct dq_object *o, u_int bit);
void	dq_object_cut(struct dq_object *o, off_t newsize, off_t pagecut);
void	dq_object_set_ident(struct dq_object *o,
	    const struct dq_ident_file *di, long hint);

void	dq_event_hold(struct dq_event_k *ev);
void	dq_event_rele(struct dq_event_k *ev);
struct dq_event_k *dq_event_alloc_flags(struct dq_object *o, uint32_t op,
	    const void *body, size_t bodylen, struct thread *td, bool kcaller,
	    int mflags);
int	dq_event_enqueue_locked(struct dq_queue *q, struct dq_event_k *ev);
sbintime_t dq_page_deadline(struct dq_object *o);
void	dq_data_hold(struct dq_data *dd);
void	dq_data_rele(struct dq_data *dd);

/*
 * Post an event on an object and wait for the answer.  On success *replyp
 * holds the reply data (NULL when the reply carried none; release with
 * dq_reply_free) and the reply's errno is in *errnop; the return value is
 * the kernel's own verdict (EIO for revoke/close/deadline/drop, EINTR/
 * ERESTART for a signal, EDEADLK).  DQ_POST_NODEADLINE waits without the
 * policy's deadline (LOCK: a blocked SETLKW is legitimate for any time);
 * DQ_POST_LOCK counts the event in o_locks, not o_inflight, so blocked
 * lockers never block readers (B6).
 */
#define	DQ_POST_NODEADLINE	0x1
#define	DQ_POST_LOCK		0x2
/*
 * DQ_POST_FAULT (B4): the wait of a page fault.  The deadline is always
 * set (dq_page_deadline); no signal abandons the wait (DQ_WAIT_FAULT):
 * the waiter sleeps in non-catching 100 ms slices, re-testing SIGKILL,
 * the process's exit and the event on every wake, so a fault during
 * SIGCHLD or SIGALRM is not SIGBUS (I12).  Abandonment posts INTERRUPT.
 */
#define	DQ_POST_FAULT		0x4
/*
 * How a requester waits (D192).  UNINTR: no signal ends the wait, only
 * the answer, the deadline, SIGKILL or the process exiting (a local file
 * system's I/O wait); CATCH: a signal ends it with EINTR or ERESTART (an
 * NFS intr mount, a lock wait); FAULT: UNINTR with the page deadline.
 */
#define	DQ_WAIT_UNINTR		0
#define	DQ_WAIT_CATCH		1
#define	DQ_WAIT_FAULT		2
int	dq_event_post_wait(struct dq_object *o, uint32_t op, const void *body,
	    size_t bodylen, struct thread *td, int flags,
	    struct dq_data **replyp, int *errnop);
void	dq_event_post_nowait(struct dq_queue *q, struct dq_object *o,
	    uint32_t op, const void *body, size_t bodylen, struct thread *td);
void	dq_reply_free(struct dq_data *reply);
/*
 * A queue-level event (RESOLVE) waited for by a requester with no object:
 * the per-requester quota, the EDEADLK scan, the depth, the deadline (0 =
 * none) and INTERRUPT as for any waited event; it catches signals only
 * when catching (DQ_QF_INTR).
 */
int	dq_event_post_wait_q(struct dq_queue *q, uint32_t op, const void *body,
	    size_t bodylen, struct thread *td, sbintime_t deadline,
	    bool catching, struct dq_data **replyp, int *errnop,
	    struct dq_object **robjp, struct fdswap *rswapp);
/* n slots of the queue were freed: wake that many waiters for one. */
void	dq_queue_slots_freed(struct dq_queue *q, u_int n);

/*
 * Objects created apart from their linking (MINT, and the RESOLVE FD reply
 * of 1c-iii, which mints before it knows the event is still there): create
 * holds the creation reference and takes the id; link (q_mtx) makes the
 * object visible; an object never linked is destroyed unlinked (its id is
 * never used).  An object linked but never bound to a file is retired
 * with dq_object_retire_unbound, which drops the creation reference.
 */
/* Fault injection (debug.dq.*): consume one of *counter, true if taken. */
bool	dq_fault_inject(u_int *counter);
extern u_int dq_fail_bind_enfile;
int	dq_object_create(struct dq_queue *q, u_int kind,
	    const struct dq_ident_file *ident, const struct dq_policy *pol,
	    struct dq_object **op);
void	dq_object_link_locked(struct dq_queue *q, struct dq_object *o);
void	dq_object_destroy_unlinked(struct dq_object *o);
void	dq_object_retire_unbound(struct dq_object *o, struct thread *td);

/* dq_resolve.c */
struct dqres_binding;
void	dq_resolve_init(void);
bool	dq_resolve_errno_allowed(uint32_t rop, int error);
bool	dq_resolve_errno_allowed_ev(const struct dq_resolve_body *rb, int error);
int	dq_resolve_reply_validate(const struct dq_event_k *ev, int rerrno,
	    const void *buf, size_t len);
int	dq_resolve_mint_prepare(struct dq_queue *q, uint64_t id,
	    struct dq_data *dd, struct dq_object **robjp, uint64_t **objectpp);
int	dq_resolve_swap_prepare(struct dq_queue *q, uint64_t id,
	    struct dq_data *dd, struct thread *td, struct fdswap *sw);
int	dq_queue_attach(struct dq_queue *q, const struct dq_attach_args *args,
	    struct thread *td);

/* dq_async.c */
int	dq_async_post(struct dq_object *o, struct vm_object *obj,
	    struct vm_page **ma, int count, off_t offset, size_t len,
	    bool write, void (*iodone)(void *, struct vm_page **, int, int),
	    void *arg);
void	dq_async_fail_locked(struct dq_queue *q, struct dq_async *da);
void	dq_async_replied_locked(struct dq_queue *q, struct dq_async *da);
void	dq_async_timeout(void *arg);
void	dq_async_queue_init(struct dq_queue *q);
bool	dq_async_wait(struct dq_object *o, sbintime_t deadline, bool all);
void	dq_object_cancel_async(struct dq_object *o);
bool	dq_object_vm_hold(struct dq_object *o, struct vm_object **objp);
void	dq_object_vm_drop(struct dq_object *o);
void	dq_object_vm_teardown(struct dq_object *o, bool close);
void	dq_object_sync_vmsize(struct dq_object *o);
void	dq_object_close_begin(struct dq_object *o);
void	dq_object_close_deferred(struct dq_object *o);
void	dq_async_cut_locked(struct dq_queue *q, struct dq_object *o,
	    off_t newsize);
void	dq_object_invalidate(struct dq_object *o, off_t offset, off_t len);

/* dq_pager.c */
int	dq_pager_register(void);
void	dq_pager_unregister(void);
#ifdef DQ_FAULT_INJECTION
/* dq_faultinj.c (options DQ_FAULT_INJECTION): test-kernel windows. */
void	dq_faultinj_swap_take_pause(void);
void	dq_faultinj_postop_apply_pause(void);
#endif
int	dq_object_vm_create(struct dq_object *o);
boolean_t dq_pager_flush(struct dq_object *o, struct vm_object *obj,
	    vm_ooffset_t offset, vm_size_t size, boolean_t syncio,
	    boolean_t invalidate);
void	dq_pager_write_resident(struct dq_object *o, off_t offset,
	    const char *data, size_t len);
void	dq_pager_fill_run(struct vm_page **ma, int count, const char *data,
	    size_t dlen);
void	dq_pager_zero_past(struct dq_object *o, struct vm_page **ma, int count,
	    off_t off);
uint64_t dq_object_invalgen(struct dq_object *o);
off_t	dq_object_vmsize(struct dq_object *o);

/* dq_file.c */
extern const struct fileops dq_fileops;
void	dq_file_init(void);
/* kind DQ_KIND_ANY: an ATTR/LINK identity (any S_IFMT, set-id allowed). */
#define	DQ_KIND_ANY		0
int	dq_ident_validate(u_int kind, const struct dq_ident_file *ident,
	    int *reason);
int	dq_policy_validate(const struct dq_policy *pol, int *reason);
int	dq_policy_validate_kind(u_int kind, const struct dq_policy *pol,
	    int *reason);
bool	dq_path_normalized(const char *path, size_t len);
int	dq_object_ident_check(struct dq_object *o,
	    const struct dq_ident_file *ident);
int	dq_file_object_setattr(struct file *fp, struct dq_setattr_body *sb,
	    struct ucred *cred, struct thread *td);
int	dq_file_target(struct file *fp, char **targetp, size_t *lenp);
uint32_t dq_file_kind(struct file *fp);
uint64_t dq_file_objid(struct file *fp);
int	dq_file_attach_under(struct file *cwdfp, struct file *rootfp);
int	dq_file_attach_start(struct file *fp, struct dq_queue *q);
int	dq_file_start(struct file *fp, struct dq_queue *q, struct thread *td,
	    uint32_t *kindp, uint64_t *objectp);
int	dq_file_install(struct thread *td, struct dq_object *o,
	    const struct dq_policy *pol, u_int mflags, int *fdp);
void	dq_file_knote(struct dq_object *o, long hint);
extern counter_u64_t dq_postop_ignored;	/* kern.dq.postop_ignored */
void	dq_object_postop(struct dq_object *o, uint32_t op,
	    const struct dq_data *reply, uint64_t minsize, size_t done);
int	dq_file_bind(struct thread *td, struct dq_object *o, int fflags,
	    struct file **fpp);

/* dq_dir.c (1c-iii-b) */
int	dq_dir_readdir(struct file *fp, struct dq_object *o, struct uio *uio,
	    off_t *basep, struct thread *td);
int	dq_readdir_reply_validate(const struct dq_event_k *ev, int rerrno,
	    const void *buf, size_t len);
bool	dq_readdir_errno_allowed(int error);

/* dq_observer.c */
extern const struct fileops dq_observer_fileops;
struct dq_observer *dq_observer_create(struct dq_queue *q, u_int flags);
int	dq_observer_install(struct thread *td, struct dq_observer *ob,
	    int *fdp);
void	dq_observer_fanout_event(struct dq_queue *q, struct dq_event_k *ev);
void	dq_observer_fanout_reply(struct dq_queue *q, uint64_t id, int error,
	    struct dq_data *data);
void	dq_observer_wakeup(struct dq_queue *q);
void	dq_observer_unlink_all(struct dq_queue *q);
void	dq_observer_close_ob(struct dq_observer *ob);

/* dq_observe.c (the dq.observe service) */
int	dq_observe_init(void);
void	dq_observe_uninit(void);

#endif /* !_DEV_DQ_DQ_VAR_H_ */
