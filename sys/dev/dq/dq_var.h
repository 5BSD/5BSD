/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: kernel-private structures.
 *
 * Lock order, outermost first:
 *   foffset -> rangelock -> FILEDESC_SLOCK (the EDEADLK scan, inside
 *   dq_event_post_wait) -> q_rdsx -> dq_mtx -> q_mtx -> o_mtx.
 * foffset and the rangelock are not witness locks and nothing takes them
 * under a filedesc lock; the scan is taken with no dq mutex held.  q_file
 * is compared by address while the queue is not CLOSING; CLOSING is set by
 * the cdevpriv destructor after the file's count hit zero, so a reused
 * address can give one false EDEADLK in that window (accepted).
 * Nothing sleeps under q_mtx or o_mtx except the ev_cv waits, which
 * release q_mtx.  copyin, copyout, uiomove and M_WAITOK allocations happen
 * with neither held; observer records are M_NOWAIT and a failure is a
 * counted drop.  Knote filters run under the knlist's mutex (o_mtx for an
 * object, q_mtx for a queue or an observer) and never take the other.
 */

#ifndef _DEV_DQ_DQ_VAR_H_
#define	_DEV_DQ_DQ_VAR_H_

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/rangelock.h>
#include <sys/sdt.h>
#include <sys/selinfo.h>
#include <sys/sx.h>
#include <sys/tree.h>

#include <dev/dq/dq.h>

MALLOC_DECLARE(M_DQ);

SDT_PROVIDER_DECLARE(dq);
SDT_PROBE_DECLARE(dq, , , queue__open);
SDT_PROBE_DECLARE(dq, , , queue__close);
SDT_PROBE_DECLARE(dq, , , mint);
SDT_PROBE_DECLARE(dq, , , revoke);
SDT_PROBE_DECLARE(dq, , , object__close);
SDT_PROBE_DECLARE(dq, , , event__post);
SDT_PROBE_DECLARE(dq, , , event__deliver);
SDT_PROBE_DECLARE(dq, , , event__reply);
SDT_PROBE_DECLARE(dq, , , event__drop);
SDT_PROBE_DECLARE(dq, , , event__interrupt);
SDT_PROBE_DECLARE(dq, , , event__deadline);
SDT_PROBE_DECLARE(dq, , , reply__late);

/* Tunables (dq_dev.c), kern.dq.* */
extern u_int dq_max_io;
extern u_int dq_queue_depth;
extern u_int dq_max_inflight_per_object;
extern u_int dq_max_inflight_per_requester;
extern u_int dq_max_objects;
extern int dq_default_deadline_ms;

struct dq_queue;
struct dq_object;
struct dq_observer;
struct dq_event_k;
int	dq_event_cmp(const struct dq_event_k *, const struct dq_event_k *);
int	dq_object_cmp(const struct dq_object *, const struct dq_object *);

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
	void			*ev_reply;	/* reply data, waiter frees */
	size_t			 ev_replylen;
	sbintime_t		 ev_deadline;	/* 0 = none */
	struct dq_object	*ev_object;	/* held; NULL for queue-level */
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

/* An observer record: a copy of an event or a reply, maybe without data. */
struct dq_obs_rec {
	TAILQ_ENTRY(dq_obs_rec)	 or_link;
	size_t			 or_size;
	struct dq_event		 or_hdr;	/* body follows */
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

enum dq_object_state {
	DQ_OBJ_LIVE = 1,
	DQ_OBJ_REVOKED,
};

struct dq_object {
	struct mtx		 o_mtx;
	struct dq_queue		*o_queue;	/* holds a q_refs */
	struct file		*o_fp;		/* weak; NULL after dq_close */
	u_int			 o_refs;
	uint64_t		 o_id;
	u_int			 o_kind;
	enum dq_object_state	 o_state;
	u_int			 o_inflight;	/* posted, not yet answered */
	bool			 o_retired;	/* removed from q_objects */
	struct dq_ident_file	 o_ident;
	struct dq_policy	 o_policy;
	struct rangelock	 o_rl;
	struct selinfo		 o_sel;		/* EVFILT_* knotes, on o_mtx */
	RB_ENTRY(dq_object)	 o_tree;	/* q_objects */
};

RB_HEAD(dq_object_tree, dq_object);
RB_PROTOTYPE(dq_object_tree, dq_object, o_tree, dq_object_cmp);

struct dq_queue {
	struct mtx		 q_mtx;
	struct sx		 q_rdsx;	/* serializes read(2) */
	u_int			 q_refs;
	u_int			 q_flags;
#define	DQ_Q_CLOSING		0x1
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
	uint64_t		 q_next_object;
	u_int			 q_nobjects;
	u_int			 q_nobservers;
	LIST_HEAD(, dq_observer) q_observers;
	LIST_HEAD(, dq_requester) q_requesters[DQ_REQUESTER_HASH];
	struct selinfo		 q_sel;		/* knlist on q_mtx */
	struct dq_stats		 q_stats;
	LIST_ENTRY(dq_queue)	 q_all;		/* dq_queues, under dq_mtx */
};

#define	DQ_LOCK(q)		mtx_lock(&(q)->q_mtx)
#define	DQ_UNLOCK(q)		mtx_unlock(&(q)->q_mtx)
#define	DQ_LOCK_ASSERT(q)	mtx_assert(&(q)->q_mtx, MA_OWNED)
#define	DQO_LOCK(o)		mtx_lock(&(o)->o_mtx)
#define	DQO_UNLOCK(o)		mtx_unlock(&(o)->o_mtx)
#define	DQO_LOCK_ASSERT(o)	mtx_assert(&(o)->o_mtx, MA_OWNED)

/* Global state (dq_dev.c). */
extern struct mtx dq_mtx;
extern LIST_HEAD(dq_queue_list, dq_queue) dq_queues;
extern u_int dq_nqueues;
extern uint64_t dq_next_gid;

/* dq_queue.c */
struct dq_queue *dq_queue_create(struct thread *td, struct file *fp);
void	dq_queue_hold(struct dq_queue *q);
void	dq_queue_rele(struct dq_queue *q);
void	dq_queue_close(struct dq_queue *q);
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
void	dq_queue_stats(struct dq_queue *q, struct dq_stats *st);
int	dq_queue_set_depth(struct dq_queue *q, uint32_t depth);
bool	dq_caller_holds_queue(struct dq_queue *q, struct thread *td);

void	dq_object_hold(struct dq_object *o);
void	dq_object_rele(struct dq_object *o);
void	dq_object_retire(struct dq_object *o, struct thread *td);

/*
 * Post an event on an object and wait for the answer.  On success
 * *replyp and *replylenp hold the reply data (free with dq_reply_free) and the
 * reply's errno is in *errnop; the return value is the kernel's own
 * verdict (EIO for revoke/close/deadline/drop, EINTR/ERESTART for a
 * signal, EDEADLK).
 */
int	dq_event_post_wait(struct dq_object *o, uint32_t op, const void *body,
	    size_t bodylen, struct thread *td, void **replyp,
	    size_t *replylenp, int *errnop);
void	dq_event_post_nowait(struct dq_queue *q, struct dq_object *o,
	    uint32_t op, const void *body, size_t bodylen, struct thread *td);
void	dq_reply_free(void *reply);

/* dq_file.c */
extern const struct fileops dq_fileops;
int	dq_ident_validate(u_int kind, const struct dq_ident_file *ident,
	    int *reason);
int	dq_policy_validate(const struct dq_policy *pol, int *reason);
int	dq_file_install(struct thread *td, struct dq_object *o,
	    const struct dq_policy *pol, int *fdp);
void	dq_file_knote(struct dq_object *o, long hint);

/* dq_observer.c */
extern const struct fileops dq_observer_fileops;
struct dq_observer *dq_observer_create(struct dq_queue *q, u_int flags);
int	dq_observer_install(struct thread *td, struct dq_observer *ob,
	    int *fdp);
void	dq_observer_fanout_event(struct dq_queue *q,
	    const struct dq_event_k *ev);
void	dq_observer_fanout_reply(struct dq_queue *q, uint64_t id, int error,
	    size_t len);
void	dq_observer_wakeup(struct dq_queue *q);
void	dq_observer_unlink_all(struct dq_queue *q);
void	dq_observer_close_ob(struct dq_observer *ob);

/* dq_observe.c (the dq.observe service) */
int	dq_observe_init(void);
void	dq_observe_uninit(void);

#endif /* !_DEV_DQ_DQ_VAR_H_ */
