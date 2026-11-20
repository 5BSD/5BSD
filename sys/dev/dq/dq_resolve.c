/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: resolution, stage 1c-i (design 11; D122-D153).
 *
 * The queue's half of an attachment: the binding a pwddesc's record names
 * (one per queue, refcounted, holding the queue), DQ_IOC_ATTACH, and the
 * consultation the kernel core (sys/kern/kern_dqres.c) asks for at every
 * lookup an attached process makes: a queue-level RESOLVE event, waited for
 * with the queue's deadline rules, answered PASS or an errno.  Fail closed
 * throughout (D136): a dead binding, a missed deadline and a lock the
 * requester must not hold while waiting all answer EIO without the
 * controller's word.  socket(2) and socketpair(2) (1c-ii, D139) are
 * consulted the same way with no path; a dead controller is EACCES to them,
 * which they can return, where a lookup gets EIO.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/counter.h>
#include <sys/fcntl.h>
#include <sys/dqres.h>
#include <sys/fdswap.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/refcount.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_kern.h>
#include <dev/dq/dq_var.h>

struct dqres_binding {
	u_int			 db_refs;
	struct dq_queue		*db_queue;	/* held */
};

static void
dq_binding_hold(struct dqres_binding *b)
{

	refcount_acquire(&b->db_refs);
}

static void
dq_binding_rele(struct dqres_binding *b)
{
	struct dq_queue *q;

	if (!refcount_release(&b->db_refs))
		return;
	q = b->db_queue;
	DQ_LOCK(q);
	if (q->q_binding == b)
		q->q_binding = NULL;
	DQ_UNLOCK(q);
	free(b, M_DQ);
	dq_queue_rele(q);
}

/* The queue's binding, created at its first ATTACH; returned held. */
static struct dqres_binding *
dq_binding_get(struct dq_queue *q)
{
	struct dqres_binding *b, *nb;

	nb = malloc(sizeof(*nb), M_DQ, M_WAITOK | M_ZERO);
	DQ_LOCK(q);
	b = q->q_binding;
	if (b != NULL && refcount_acquire_if_not_zero(&b->db_refs)) {
		DQ_UNLOCK(q);
		free(nb, M_DQ);
		return (b);
	}
	refcount_init(&nb->db_refs, 1);
	nb->db_queue = q;
	dq_queue_hold(q);
	q->q_binding = nb;
	DQ_UNLOCK(q);
	return (nb);
}

/*
 * System-wide witnesses of the two fail-closed counters, which outlive the
 * queue whose ds2_* copy dies with it (kern.dq.stats.*, read-only).
 */
SYSCTL_DECL(_kern_dq);
static SYSCTL_NODE(_kern_dq, OID_AUTO, stats, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "DescriptorQueue statistics of all queues");
static COUNTER_U64_DEFINE_EARLY(dq_gstat_resolve_failclosed);
SYSCTL_COUNTER_U64(_kern_dq_stats, OID_AUTO, resolve_failclosed, CTLFLAG_RD,
    &dq_gstat_resolve_failclosed,
    "Consultations refused without the controller's answer");
static COUNTER_U64_DEFINE_EARLY(dq_gstat_resolve_unmarked);
SYSCTL_COUNTER_U64(_kern_dq_stats, OID_AUTO, resolve_unmarked, CTLFLAG_RD,
    &dq_gstat_resolve_unmarked,
    "Kernel-space lookups by attached threads outside any intent or region");

static void
dq_binding_unmarked(struct dqres_binding *b)
{
	struct dq_queue *q;

	q = b->db_queue;
	DQ_LOCK(q);
	q->q_stats.ds2_resolve_unmarked++;
	DQ_UNLOCK(q);
	counter_u64_add(dq_gstat_resolve_unmarked, 1);
	SDT_PROBE1(dq, , , resolve__unmarked, q);
}

/* A two-path operation with mixed starts, fhlink into a served start (D170). */
static void
dq_binding_exdev(struct dqres_binding *b)
{
	struct dq_queue *q;

	q = b->db_queue;
	DQ_LOCK(q);
	q->q_stats.ds2_resolve_exdev++;
	DQ_UNLOCK(q);
}

static void
dq_resolve_failclosed(struct dq_queue *q, int why)
{

	DQ_LOCK(q);
	q->q_stats.ds2_resolve_failclosed++;
	DQ_UNLOCK(q);
	counter_u64_add(dq_gstat_resolve_failclosed, 1);
	SDT_PROBE2(dq, , , resolve__failclosed, q, why);
}

/* What a dead binding answers (D136): EIO to lookups, EACCES to sockets. */
static int
dq_resolve_dead_errno(const struct dqres_req *rq)
{

	return (rq->rq_op == DQ_ROP_SOCKET || rq->rq_op == DQ_ROP_SOCKETPAIR ?
	    EACCES : EIO);
}

/*
 * The wait guard (0c item 1): the requester must hold nothing a
 * controller could need while it waits.  Counters every kernel maintains
 * (shared lockmgr, sx and rw read locks), the sleep, critical and pin
 * states, and under INVARIANTS the full lock count, against what the
 * intent expects (0 everywhere in 1c-i).
 */
static bool
dq_resolve_may_wait(struct thread *td, const struct dqres_req *rq)
{

	if (td->td_lk_slocks + td->td_sx_slocks + td->td_rw_rlocks !=
	    (int)rq->rq_expected_locks)
		return (false);
	if (!THREAD_CAN_SLEEP() || td->td_critnest != 0 || td->td_pinned != 0)
		return (false);
#ifdef INVARIANTS
	if (td->td_locks != (int)rq->rq_expected_locks)
		return (false);
#endif
	return (true);
}

/*
 * The consultation (kern_dqres.c's dro_consult).  0 is PASS; an errno is
 * the controller's (allow-listed) or the kernel's own verdict.  ERESTART
 * leaves only when the core allowed it (D149); otherwise it is EINTR.
 */
static int
dq_resolve_consult(struct thread *td, struct dqres_binding *b,
    const struct dqres_req *rq, struct dqres_answer *ans)
{
	struct dq_queue *q;
	struct dq_resolve_body *rb;
	const struct dq_resolve_reply *rr;
	const struct dq_resolve_mint *rm;
	const struct dq_resolve_attr *ra;
	const struct dq_resolve_target *rt;
	struct dq_data *reply;
	struct dq_object *robj;
	struct fdswap rswap;
	sbintime_t deadline;
	size_t bodylen, strlen_;
	char *p;
	int error, rerror, ms;
	bool dead;

	bzero(ans, sizeof(*ans));
	q = b->db_queue;
	if ((q->q_flags & DQ_Q_CLOSING) != 0) {
		/* The controller is gone: fail closed (D136). */
		dq_resolve_failclosed(q, 1);
		return (dq_resolve_dead_errno(rq));
	}
	if (!dq_resolve_may_wait(td, rq)) {
		dq_resolve_failclosed(q, 2);
		SDT_PROBE2(dq, , , resolve__locked, q, rq->rq_op);
		return (EIO);
	}
	/*
	 * Standing rules (dq_standing.c): the controller's answer given in
	 * advance, with exactly the return value and ans its reply would
	 * have produced.  After the guard, so a refusal there stays counted
	 * and traced and the rules' readers hold no lock.
	 */
	switch (dq_standing_decide(q, rq, ans, &error)) {
	case DQ_SD_PASS:
		return (0);
	case DQ_SD_ERRNO:
		return (error);
	default:
		break;
	}
	/*
	 * SETATTR and TRUNCATE (D161): the setattr body follows the four
	 * strings at the next 8-byte boundary.
	 */
	strlen_ = roundup2(sizeof(*rb) + rq->rq_pathlen + 1 +
	    rq->rq_path2len + 1 + rq->rq_startpathlen + 1 +
	    rq->rq_startpath2len + 1 + rq->rq_rootpathlen + 1, 8);
	bodylen = strlen_ + (rq->rq_setattr != NULL ?
	    sizeof(struct dq_setattr_body) : 0);
	rb = malloc(bodylen, M_DQ, M_WAITOK | M_ZERO);
	if (rq->rq_setattr != NULL)
		memcpy((char *)rb + strlen_, rq->rq_setattr,
		    sizeof(struct dq_setattr_body));
	rb->drs_accept = rq->rq_accept;
	rb->drs_cmode = rq->rq_cmode;
	rb->drs_dev = rq->rq_dev;
	rb->drs_op = rq->rq_op;
	rb->drs_rflags = rq->rq_rflags;
	rb->drs_start_kind = rq->rq_start_kind;
	rb->drs_start = rq->rq_start;
	rb->drs_start2_kind = rq->rq_start2_kind;
	rb->drs_start2 = rq->rq_start2;
	rb->drs_flags = rq->rq_class;
	rb->drs_mode = rq->rq_mode;
	rb->drs_syscall = rq->rq_syscall;
	rb->drs_pathlen = rq->rq_pathlen;
	rb->drs_path2len = rq->rq_path2len;
	rb->drs_startpathlen = rq->rq_startpathlen;
	rb->drs_startpath2len = rq->rq_startpath2len;
	rb->drs_object = rq->rq_object;
	rb->drs_domain = rq->rq_domain;
	rb->drs_type = rq->rq_type;
	rb->drs_protocol = rq->rq_protocol;
	rb->drs_root = rq->rq_root;
	rb->drs_rootpathlen = rq->rq_rootpathlen;
	p = (char *)(rb + 1);
	memcpy(p, rq->rq_path, rq->rq_pathlen);
	p += rq->rq_pathlen + 1;
	if (rq->rq_path2len != 0)
		memcpy(p, rq->rq_path2, rq->rq_path2len);
	p += rq->rq_path2len + 1;
	if (rq->rq_startpathlen != 0)
		memcpy(p, rq->rq_startpath, rq->rq_startpathlen);
	p += rq->rq_startpathlen + 1;
	if (rq->rq_startpath2len != 0)
		memcpy(p, rq->rq_startpath2, rq->rq_startpath2len);
	p += rq->rq_startpath2len + 1;
	if (rq->rq_rootpathlen != 0)
		memcpy(p, rq->rq_rootpath, rq->rq_rootpathlen);

	/*
	 * The deadline (B1 of 1b and 0c item 1): the default for the
	 * requester's own paths (0 = none); a kernel consumer, a kernel
	 * lookup and a caller that holds a lock wait at most
	 * kern.dq.kernel_deadline_ms, never unbounded.
	 */
	ms = dq_default_deadline_ms;
	if (rq->rq_class != 1 || rq->rq_expected_locks != 0) {
		if (ms <= 0 || ms > dq_kernel_deadline_ms)
			ms = dq_kernel_deadline_ms;
		if (ms <= 0)
			ms = 1;
	}
	deadline = ms > 0 ? sbinuptime() + (sbintime_t)ms * SBT_1MS : 0;

	error = dq_event_post_wait_q(q, DQ_OP_RESOLVE, rb, bodylen, td,
	    deadline, &reply, &rerror, &robj, &rswap);
	free(rb, M_DQ);
	DQ_LOCK(q);
	q->q_stats.ds2_resolves++;
	if (rq->rq_class != 1)
		q->q_stats.ds2_resolve_kernel++;
	dead = (q->q_flags & DQ_Q_CLOSING) != 0;
	DQ_UNLOCK(q);
	if (error != 0) {
		if (error == EIO) {
			/* The queue closed under the wait, or a deadline. */
			dq_resolve_failclosed(q, 3);
			if (dead)
				error = dq_resolve_dead_errno(rq);
		}
		if (error == ERESTART && !rq->rq_may_restart)
			error = EINTR;
		return (error);
	}
	if (rerror != 0) {
		KASSERT(rswap.fs_fp == NULL, ("dq: errno reply with a file"));
		dq_reply_free(reply);
		/*
		 * link, fhlink and rename retry on EAGAIN (DQI_NO_ERESTART):
		 * a controller must not be able to make them loop.
		 */
		if (rerror == EAGAIN && rq->rq_no_erestart)
			rerror = EIO;
		SDT_PROBE3(dq, , , resolve__reply, q, rq->rq_op, rerror);
		return (rerror);
	}
	/*
	 * The reply path accepted a kind of rq_accept with its exact size
	 * (dq_resolve_reply_validate) and, for FD, linked the object it
	 * minted (robj, the creation reference, now the answer's).
	 */
	rr = (const struct dq_resolve_reply *)reply->dd_bytes;
	KASSERT((rq->rq_accept & DQ_RACCEPT(rr->drr_kind)) != 0,
	    ("dq: resolve kind %u outside %#x", rr->drr_kind, rq->rq_accept));
	KASSERT((robj != NULL) == (rr->drr_kind == DQ_RESOLVE_FD),
	    ("dq: resolve FD object"));
	KASSERT((rswap.fs_fp != NULL) == (rr->drr_kind == DQ_RESOLVE_SWAP),
	    ("dq: resolve SWAP file"));
	ans->da_kind = rr->drr_kind;
	ans->da_qgid = q->q_gid;
	switch (rr->drr_kind) {
	case DQ_RESOLVE_FD:
		rm = (const struct dq_resolve_mint *)(rr + 1);
		ans->da_obj = robj;
		ans->da_objid = robj->o_id;
		ans->da_mflags = rm->drm_flags;
		ans->da_okind = rm->drm_kind;
		ans->da_rights = rm->drm_policy.dp_rights;
		ans->da_ident = malloc(sizeof(*ans->da_ident), M_TEMP,
		    M_WAITOK);
		*ans->da_ident = rm->drm_ident;
		break;
	case DQ_RESOLVE_SWAP:
		/* The file taken at the reply (ev_rswap), now the answer's. */
		ans->da_swap = malloc(sizeof(*ans->da_swap), M_TEMP, M_WAITOK);
		*ans->da_swap = rswap;
		ans->da_swflags = ((const struct dq_resolve_swap *)
		    (rr + 1))->drw_flags;
		break;
	case DQ_RESOLVE_REAL:
		/* An absolute, normalized real path (D167). */
		rt = (const struct dq_resolve_target *)(rr + 1);
		ans->da_targetlen = rt->drt_len;
		ans->da_target = malloc(rt->drt_len + 1, M_TEMP, M_WAITOK);
		memcpy(ans->da_target, rt->drt_target, rt->drt_len + 1);
		break;
	case DQ_RESOLVE_ATTR:
	case DQ_RESOLVE_LINK:
		ra = (const struct dq_resolve_attr *)(rr + 1);
		ans->da_ident = malloc(sizeof(*ans->da_ident), M_TEMP,
		    M_WAITOK);
		*ans->da_ident = ra->dra_ident;
		if (rr->drr_kind == DQ_RESOLVE_LINK) {
			rt = (const struct dq_resolve_target *)(ra + 1);
			ans->da_targetlen = rt->drt_len;
			ans->da_target = malloc(rt->drt_len + 1, M_TEMP,
			    M_WAITOK);
			memcpy(ans->da_target, rt->drt_target, rt->drt_len + 1);
		}
		break;
	default:
		break;
	}
	/* rr points into reply: only ans is read from here on. */
	dq_reply_free(reply);
	DQ_LOCK(q);
	/* REAL is neither: dq:::resolve-real counts it. */
	if (ans->da_kind == DQ_RESOLVE_PASS)
		q->q_stats.ds2_resolve_pass++;
	else if (ans->da_kind != DQ_RESOLVE_REAL)
		q->q_stats.ds2_resolve_served++;
	DQ_UNLOCK(q);
	if ((rq->rq_rflags & DQ_RF_SYMLINK_RESTART) != 0)
		SDT_PROBE3(dq, , , resolve__symlink, q, rq->rq_op,
		    ans->da_kind);
	if (ans->da_kind == DQ_RESOLVE_REAL)
		SDT_PROBE3(dq, , , resolve__real, q, rq->rq_op,
		    ans->da_target);
	else if (ans->da_kind != DQ_RESOLVE_PASS)
		SDT_PROBE3(dq, , , resolve__served, q, rq->rq_op, ans->da_kind);
	SDT_PROBE3(dq, , , resolve__reply, q, rq->rq_op, 0);
	return (0);
}

/* dro_bind: the answer's object becomes a file of the requester (D159). */
static int
dq_resolve_bind(struct thread *td, struct dqres_answer *ans, int fflags,
    struct file **fpp)
{
	struct dq_object *o;

	o = ans->da_obj;
	ans->da_obj = NULL;
	KASSERT(o != NULL, ("dq: bind without an object"));
	return (dq_file_bind(td, o, fflags, fpp));
}

/* dro_answer_release: an FD answer nobody bound (D171). */
static void
dq_resolve_answer_release(struct thread *td, struct dqres_answer *ans)
{
	struct dq_object *o;

	o = ans->da_obj;
	ans->da_obj = NULL;
	if (o != NULL)
		dq_object_retire_unbound(o, td);
	/* A SWAP answer nobody installed, or what its install left. */
	if (ans->da_swap != NULL) {
		fdswap_release(ans->da_swap, td);
		free(ans->da_swap, M_TEMP);
		ans->da_swap = NULL;
	}
}

static int
dq_resolve_file_ident(struct file *fp, struct dq_ident_file *ident,
    uint64_t *qgidp, bool *closedp)
{
	struct dq_object *o;
	uint64_t id, nonce;
	int error;

	error = dq_file_ident(fp, ident, &id, &nonce);
	if (error != 0)
		return (error);
	o = fp->f_data;
	*qgidp = o->o_queue->q_gid;
	*closedp = (o->o_queue->q_flags & DQ_Q_CLOSING) != 0;
	return (0);
}

/*
 * dro_start (D162, D163): a served descriptor as a lookup start, against
 * the binding's queue (NULL when the caller is unattached).
 */
static int
dq_resolve_start(struct thread *td, struct dqres_binding *b, struct file *fp,
    uint32_t *kindp, uint64_t *objectp)
{

	return (dq_file_start(fp, b != NULL ? b->db_queue : NULL, td, kindp,
	    objectp));
}

/* dro_setattr: the object-level setattr, with no O_PATH gate (D160). */
static int
dq_resolve_setattr(struct thread *td, struct file *fp,
    struct dq_setattr_body *sb)
{

	return (dq_file_object_setattr(fp, sb, td->td_ucred, td));
}

/* dro_queue_closed: CLOSING is set before the queue leaves dq_queues. */
static bool
dq_resolve_queue_closed(uint64_t qgid)
{
	struct dq_queue *q;
	bool closed;

	closed = true;
	mtx_lock(&dq_mtx);
	LIST_FOREACH(q, &dq_queues, q_all) {
		if (q->q_gid == qgid) {
			closed = (atomic_load_int(&q->q_flags) &
			    DQ_Q_CLOSING) != 0;
			break;
		}
	}
	mtx_unlock(&dq_mtx);
	return (closed);
}

/*
 * The install gate of a SWAP answer (dro_swap_gate, finstall_refed_gate).
 * A queue that has died gives its attached processes nothing new: the
 * requester's descriptor-table entry is written with q_mtx held and
 * DQ_Q_CLOSING clear.  The flag is set under q_mtx, in the first section
 * of the queue's death, so an entry is either written before the queue
 * died or not written at all, however long the installing thread was
 * delayed after the reply.  The table lock is taken before q_mtx, the
 * order dq_caller_holds_queue already has; the binding holds the queue.
 */
static int
dq_swap_gate_enter(void *arg)
{
	struct dq_queue *q = arg;

	DQ_LOCK(q);
	if ((q->q_flags & DQ_Q_CLOSING) != 0) {
		DQ_UNLOCK(q);
		dq_resolve_failclosed(q, 1);
		return (EIO);
	}
	return (0);			/* q_mtx held until the exit */
}

static void
dq_swap_gate_exit(void *arg)
{

	DQ_UNLOCK((struct dq_queue *)arg);
}

static void
dq_resolve_swap_gate(struct dqres_binding *b, struct fdinstall_gate *g)
{

	g->fg_enter = dq_swap_gate_enter;
	g->fg_exit = dq_swap_gate_exit;
	g->fg_arg = b->db_queue;
}

static const struct dqres_ops dq_resolve_ops = {
	.dro_hold = dq_binding_hold,
	.dro_rele = dq_binding_rele,
	.dro_consult = dq_resolve_consult,
	.dro_unmarked = dq_binding_unmarked,
	.dro_exdev = dq_binding_exdev,
	.dro_bind = dq_resolve_bind,
	.dro_answer_release = dq_resolve_answer_release,
	.dro_file_ident = dq_resolve_file_ident,
	.dro_queue_closed = dq_resolve_queue_closed,
	.dro_owner_gone = dq_queue_owner_gone,
	.dro_start = dq_resolve_start,
	.dro_setattr = dq_resolve_setattr,
	.dro_target = dq_file_target,
	.dro_file_kind = dq_file_kind,
	.dro_file_objid = dq_file_objid,
	.dro_swap_gate = dq_resolve_swap_gate,
};

void
dq_resolve_init(void)
{

	dqres_register(&dq_resolve_ops);
}

/*
 * The errnos a RESOLVE reply may carry: for socket(2) and socketpair(2),
 * what they can fail with; for every lookup, what a lookup and the
 * operation behind it can fail with on a real filesystem.  Anything else
 * is EIO to the requester and counted (N5 of 1b).
 */
bool
dq_resolve_errno_allowed(uint32_t rop, int error)
{

	if (rop == DQ_ROP_SOCKET || rop == DQ_ROP_SOCKETPAIR) {
		switch (error) {
		case EPERM: case EACCES: case EAFNOSUPPORT:
		case EPROTONOSUPPORT: case EPROTOTYPE: case EOPNOTSUPP:
		case ENOBUFS: case EMFILE: case ENFILE:
			return (true);
		default:
			return (false);
		}
	}
	switch (error) {
	case EPERM: case ENOENT: case EIO: case ENXIO: case E2BIG:
	case ENOEXEC: case EACCES: case EBUSY: case EEXIST: case EXDEV:
	case ENODEV: case ENOTDIR: case EISDIR: case EINVAL: case ETXTBSY:
	case EFBIG: case ENOSPC: case EROFS: case EMLINK: case EAGAIN:
	case ENAMETOOLONG: case ENOTEMPTY: case ELOOP: case EDQUOT:
	case ESTALE: case EOPNOTSUPP: case EINTR: case EAFNOSUPPORT:
	case EPROTONOSUPPORT: case EADDRINUSE: case EADDRNOTAVAIL:
	case ECONNREFUSED: case EPROTOTYPE: case EFTYPE: case EAUTH:
	case ENOATTR: case EINTEGRITY:
		return (true);
	default:
		return (false);
	}
}

/*
 * The errno allow-list against the event (D158): ENOTCAPABLE only for a
 * lookup restricted to a subtree (STRICTREL, BENEATH, RINROOT), where a
 * real lookup can return it; elsewhere it is EIO and counted.
 */
bool
dq_resolve_errno_allowed_ev(const struct dq_resolve_body *rb, int error)
{

	if (error == ENOTCAPABLE)
		return (rb->drs_op != DQ_ROP_SOCKET &&
		    rb->drs_op != DQ_ROP_SOCKETPAIR &&
		    (rb->drs_rflags & (DQ_RF_STRICTREL | DQ_RF_BENEATH |
		    DQ_RF_RINROOT | DQ_RF_STRICTREL2 | DQ_RF_BENEATH2)) != 0);
	return (dq_resolve_errno_allowed(rb->drs_op, error));
}

static const struct dq_resolve_body *
dq_resolve_ev_body(const struct dq_event_k *ev)
{

	return ((const struct dq_resolve_body *)((const char *)&ev->ev_hdr +
	    sizeof(struct dq_event)));
}

/*
 * A symlink target or a REAL path in a reply: drt_len bytes (1 ..
 * DQ_PATH_MAX - 1, or 0 for a symlink target when emptyok) with no NUL,
 * then a NUL and zeros to the end of the reply, which is exactly the next
 * 8-byte boundary.  symlink(2) accepts an empty target, which readlink(2)
 * returns as 0 bytes and namei follows to ENOENT; a REAL path is never
 * empty.
 */
static int
dq_resolve_target_validate(const struct dq_resolve_target *rt, size_t avail,
    bool emptyok)
{
	size_t i, need;

	if (avail < sizeof(*rt) || rt->drt_pad0 != 0 ||
	    (rt->drt_len == 0 && !emptyok) || rt->drt_len >= DQ_PATH_MAX)
		return (EINVAL);
	need = roundup2(sizeof(*rt) + rt->drt_len + 1, 8);
	if (avail != need ||
	    strnlen(rt->drt_target, rt->drt_len + 1) != rt->drt_len)
		return (EINVAL);
	for (i = sizeof(*rt) + rt->drt_len; i < need; i++) {
		if (((const char *)rt)[i] != '\0')
			return (EINVAL);
	}
	return (0);
}

/*
 * The reply body of a RESOLVE (D128, D158): an errno carries none;
 * otherwise a struct dq_resolve_reply of a kind the event accepts
 * (drs_accept) with exactly that kind's payload.  Anything else is EINVAL
 * to the controller and the event stays in flight.  An FD answer's mint
 * was validated before the lock (dq_resolve_mint_prepare).
 */
int
dq_resolve_reply_validate(const struct dq_event_k *ev, int rerrno,
    const void *buf, size_t len)
{
	const struct dq_resolve_body *rb;
	const struct dq_resolve_reply *rr;
	const struct dq_resolve_attr *ra;
	const struct dq_resolve_target *rt;
	int reason;

	if (rerrno != 0)
		return (len == 0 ? 0 : EINVAL);
	if (len < sizeof(*rr))
		return (EINVAL);
	rb = dq_resolve_ev_body(ev);
	rr = buf;
	if (rr->drr_pad0 != 0 || rr->drr_kind >= 32 ||
	    (rb->drs_accept & DQ_RACCEPT(rr->drr_kind)) == 0)
		return (EINVAL);
	len -= sizeof(*rr);
	switch (rr->drr_kind) {
	case DQ_RESOLVE_PASS:
	case DQ_RESOLVE_OK:
		return (len == 0 ? 0 : EINVAL);
	case DQ_RESOLVE_FD:
		/*
		 * dq_resolve_mint_prepare validated the mint and a SYMLINK's
		 * target; the size is checked again against the kind.
		 */
		if (len < sizeof(struct dq_resolve_mint))
			return (EINVAL);
		if (((const struct dq_resolve_mint *)(rr + 1))->drm_kind !=
		    DQ_KIND_SYMLINK)
			return (len == sizeof(struct dq_resolve_mint) ? 0 :
			    EINVAL);
		return (dq_resolve_target_validate(
		    (const struct dq_resolve_target *)((const char *)(rr + 1) +
		    sizeof(struct dq_resolve_mint)),
		    len - sizeof(struct dq_resolve_mint), true));
	case DQ_RESOLVE_SWAP:
		/* dq_resolve_swap_prepare checked the contents. */
		return (len == sizeof(struct dq_resolve_swap) ? 0 : EINVAL);
	case DQ_RESOLVE_REAL:
		/* D167: an absolute, normalized real path. */
		if (dq_resolve_target_validate(
		    (const struct dq_resolve_target *)(rr + 1), len,
		    false) != 0)
			return (EINVAL);
		rt = (const struct dq_resolve_target *)(rr + 1);
		return (dq_path_normalized(rt->drt_target, rt->drt_len) ? 0 :
		    EINVAL);
	case DQ_RESOLVE_ATTR:
	case DQ_RESOLVE_LINK:
		if (len < sizeof(*ra))
			return (EINVAL);
		ra = (const struct dq_resolve_attr *)(rr + 1);
		if (ra->dra_flags != 0 || ra->dra_pad0 != 0 ||
		    dq_ident_validate(DQ_KIND_ANY, &ra->dra_ident,
		    &reason) != 0)
			return (EINVAL);
		if (rr->drr_kind == DQ_RESOLVE_ATTR)
			return (len == sizeof(*ra) ? 0 : EINVAL);
		/* LINK: a symlink whose size is the target's length. */
		if (!S_ISLNK(ra->dra_ident.di_mode) ||
		    dq_resolve_target_validate(
		    (const struct dq_resolve_target *)(ra + 1),
		    len - sizeof(*ra), true) != 0 ||
		    ra->dra_ident.di_size !=
		    ((const struct dq_resolve_target *)(ra + 1))->drt_len)
			return (EINVAL);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
dq_resolve_mint_reason(const struct dq_resolve_mint *rm, int reason,
    int error)
{
	int32_t r;

	if (rm->drm_reasonp != NULL) {
		r = reason;
		if (copyout(&r, rm->drm_reasonp, sizeof(r)) != 0 && error == 0)
			error = EFAULT;
	}
	return (error);
}

/*
 * An FD answer, before the queue lock (D130, D171): validate the mint,
 * peek that the event is delivered and accepts FD, create the object
 * unlinked, and hand its id (and DQ_REASON_NONE) to the controller.  A
 * refusal here is EINVAL with the reason (ESRCH for an event that is
 * gone, ENOMEM when the pager object cannot be made, EFAULT when the id
 * cannot be written) and leaves the event in flight.  On success
 * *robjp is the unlinked object; dq_queue_reply links it or destroys it.
 * The two pointers are cleared in dd, which observers copy.
 */
int
dq_resolve_mint_prepare(struct dq_queue *q, uint64_t id, struct dq_data *dd,
    struct dq_object **robjp, uint64_t **objectpp)
{
	struct dq_resolve_mint *rm;
	const struct dq_resolve_body *rb;
	struct dq_event_k key, *ev;
	struct dq_object *o;
	const struct dq_resolve_target *rt;
	uint64_t oid;
	uint32_t rop, mode, rflags;
	size_t extra;
	int error, reason;

	*robjp = NULL;
	*objectpp = NULL;
	/*
	 * The event first (review item 1): only a delivered RESOLVE event
	 * whose accept set has FD makes these bytes a mint.  Any other reply
	 * (a READ's data, a WRITE's count) is left to dq_reply_validate, as
	 * is a missing event (ESRCH there).
	 */
	key.ev_hdr.de_id = id;
	DQ_LOCK(q);
	ev = RB_FIND(dq_inflight_tree, &q->q_inflight, &key);
	if (ev == NULL || ev->ev_hdr.de_op != DQ_OP_RESOLVE ||
	    (dq_resolve_ev_body(ev)->drs_accept &
	    DQ_RACCEPT(DQ_RESOLVE_FD)) == 0) {
		DQ_UNLOCK(q);
		return (0);
	}
	rb = dq_resolve_ev_body(ev);
	rop = rb->drs_op;
	mode = rb->drs_mode;
	rflags = rb->drs_rflags;
	DQ_UNLOCK(q);
	if (dd->dd_len < sizeof(struct dq_resolve_reply) + sizeof(*rm))
		return (EINVAL);
	rm = (struct dq_resolve_mint *)(dd->dd_bytes +
	    sizeof(struct dq_resolve_reply));
	extra = dd->dd_len - sizeof(struct dq_resolve_reply) - sizeof(*rm);
	/*
	 * FILE (iii-a), DIR and SYMLINK (iii-b, D168).  A SYMLINK carries its
	 * target after the mint, its size the target's length, and answers
	 * only a lookup that does not follow a final symlink (O_NOFOLLOW,
	 * lchmod, ...): a following lookup would have gone through it.
	 */
	rt = NULL;
	switch (rm->drm_kind) {
	case DQ_KIND_FILE:
	case DQ_KIND_DIR:
		if (extra != 0)
			return (EINVAL);
		break;
	case DQ_KIND_SYMLINK:
		rt = (const struct dq_resolve_target *)(rm + 1);
		if (dq_resolve_target_validate(rt, extra, true) != 0)
			return (dq_resolve_mint_reason(rm, DQ_REASON_TARGET,
			    EINVAL));
		if ((rflags & DQ_RF_NOFOLLOW) == 0)
			return (dq_resolve_mint_reason(rm, DQ_REASON_KIND,
			    EINVAL));
		break;
	default:
		return (dq_resolve_mint_reason(rm, DQ_REASON_KIND, EINVAL));
	}
	error = dq_ident_validate(rm->drm_kind, &rm->drm_ident, &reason);
	if (error == 0)
		error = dq_policy_validate_kind(rm->drm_kind, &rm->drm_policy,
		    &reason);
	if (error == 0 && rt != NULL && rm->drm_ident.di_size != rt->drt_len) {
		reason = DQ_REASON_TARGET;
		error = EINVAL;
	}
	if (error != 0)
		return (dq_resolve_mint_reason(rm, reason, error));
	if ((rm->drm_flags & ~(DQ_MINT_F_WRITE | DQ_MINT_F_CREATED)) != 0 ||
	    ((rm->drm_flags & DQ_MINT_F_WRITE) != 0 &&
	    rm->drm_policy.dp_write != DQ_EVENT))
		return (dq_resolve_mint_reason(rm, DQ_REASON_FLAGS, EINVAL));
	/* DQ_MINT_F_CREATED only for an open that could create (D166). */
	if ((rm->drm_flags & DQ_MINT_F_CREATED) != 0 &&
	    (rop != DQ_ROP_OPEN || (mode & O_CREAT) == 0))
		return (dq_resolve_mint_reason(rm, DQ_REASON_FLAGS, EINVAL));
	/* A truncate's FD is written through: it must be writable. */
	if (rop == DQ_ROP_TRUNCATE && (rm->drm_flags & DQ_MINT_F_WRITE) == 0)
		return (dq_resolve_mint_reason(rm, DQ_REASON_FLAGS, EINVAL));

	error = dq_object_create(q, rm->drm_kind, &rm->drm_ident,
	    &rm->drm_policy, &o);
	if (error != 0)
		return (dq_resolve_mint_reason(rm, DQ_REASON_NONE, ENOMEM));
	if (rt != NULL) {
		/* Fixed before the object is visible (dq_file_target). */
		o->o_target = malloc(rt->drt_len + 1, M_DQ, M_WAITOK);
		memcpy(o->o_target, rt->drt_target, rt->drt_len + 1);
		o->o_targetlen = rt->drt_len;
	}
	oid = o->o_id;
	error = copyout(&oid, rm->drm_objectp, sizeof(oid));
	if (error == 0)
		error = dq_resolve_mint_reason(rm, DQ_REASON_NONE, 0);
	if (error != 0) {
		dq_object_destroy_unlinked(o);
		return (EFAULT);
	}
	*objectpp = rm->drm_objectp;
	rm->drm_objectp = NULL;		/* observers see no pointers */
	rm->drm_reasonp = NULL;
	*robjp = o;
	return (0);
}

/* fdswap_take's admit: the open layer's rule against the request. */
static int
dq_resolve_swap_admit(struct file *fp, const cap_rights_t *rights, void *arg)
{

	return (open_swap_admit(fp, *(const int *)arg, rights));
}

/*
 * A SWAP answer, before the queue lock: peek that the event is a
 * delivered RESOLVE that accepts SWAP and copy the request's open flags
 * (the kernel's copy, drs_mode); check the payload; then take the file
 * out of the replying process's table (fdswap_take: the transfer policy,
 * the sole-reference rule, and open_swap_admit against the request, all
 * under the table lock and before anything is consumed).  No dq lock is
 * held across the table lock: the order is table, then q_mtx.
 *
 * A refusal is the controller's errno (dq.h), consumes nothing and
 * leaves the event in flight; dq:::swap-refused carries it.  Any other
 * reply (not a RESOLVE that accepts SWAP, or an event that is gone) is
 * left to dq_reply_validate and the ESRCH path, with *sw empty.  On
 * success *sw holds the reference; dq_queue_reply links it to the event
 * or releases it.  drw_fd is cleared in dd, which observers copy: a
 * descriptor number of the controller means nothing to them.
 */
int
dq_resolve_swap_prepare(struct dq_queue *q, uint64_t id, struct dq_data *dd,
    struct thread *td, struct fdswap *sw)
{
	struct dq_resolve_swap *rw;
	const struct dq_resolve_body *rb;
	struct dq_event_k key, *ev;
	int error, mode;

	bzero(sw, sizeof(*sw));
	key.ev_hdr.de_id = id;
	DQ_LOCK(q);
	ev = RB_FIND(dq_inflight_tree, &q->q_inflight, &key);
	if (ev == NULL || ev->ev_hdr.de_op != DQ_OP_RESOLVE ||
	    (dq_resolve_ev_body(ev)->drs_accept &
	    DQ_RACCEPT(DQ_RESOLVE_SWAP)) == 0) {
		DQ_UNLOCK(q);
		return (0);
	}
	rb = dq_resolve_ev_body(ev);
	KASSERT(rb->drs_op == DQ_ROP_OPEN, ("dq: SWAP offered for op %u",
	    rb->drs_op));
	mode = (int)rb->drs_mode;
	DQ_UNLOCK(q);
	/* Everything dq_resolve_reply_validate refuses, before the take. */
	if (dd->dd_len != sizeof(struct dq_resolve_reply) + sizeof(*rw) ||
	    ((const struct dq_resolve_reply *)dd->dd_bytes)->drr_pad0 != 0) {
		error = EINVAL;
		goto refused;
	}
	rw = (struct dq_resolve_swap *)(dd->dd_bytes +
	    sizeof(struct dq_resolve_reply));
	if ((rw->drw_flags & ~DQ_SWAP_F_VALID) != 0 || rw->drw_spare[0] != 0 ||
	    rw->drw_spare[1] != 0 || rw->drw_spare[2] != 0 ||
	    ((rw->drw_flags & DQ_SWAP_F_CREATED) != 0 &&
	    (mode & (O_CREAT | O_PATH)) != O_CREAT)) {
		error = EINVAL;
		goto refused;
	}
	error = fdswap_take(td, rw->drw_fd,
	    (rw->drw_flags & DQ_SWAP_F_NOXFER) != 0 ? FDSWAP_NOXFER : 0,
	    dq_resolve_swap_admit, &mode, sw);
	if (error != 0)
		goto refused;
	rw->drw_fd = -1;
	return (0);
refused:
	SDT_PROBE3(dq, , , swap__refused, q, id, error);
	return (error);
}

/* An ATTACH start descriptor of q, held (none for -1). */
static int
dq_attach_start_get(struct thread *td, struct dq_queue *q, int fd,
    const cap_rights_t *rights, struct file **fpp)
{
	struct file *fp;
	int error;

	*fpp = NULL;
	if (fd == -1)
		return (0);
	error = fget(td, fd, rights, &fp);
	if (error != 0)
		return (error);
	error = dq_file_attach_start(fp, q);
	if (error != 0) {
		fdrop(fp, td);
		return (error);
	}
	*fpp = fp;
	return (0);
}

/*
 * DQ_IOC_ATTACH (D138, D148, D150).  The target comes from a process
 * descriptor, resolved as mac_capability_resolve_proc resolves one, and
 * is held while the core commits under its own locks.
 */
int
dq_queue_attach(struct dq_queue *q, const struct dq_attach_args *args,
    struct thread *td)
{
	struct dqres_binding *b;
	struct procdesc *pd;
	struct file *fp, *cwdfp, *rootfp;
	struct proc *p;
	int error;

	if (args->da_version != DQ_API_VERSION ||
	    (args->da_flags & ~DQ_ATTACH_F_NODIRS) != 0 || args->da_pad0 != 0)
		return (EINVAL);
	/*
	 * Served starts (D169): live served directories of this queue, held
	 * before any lock; -1 for none.
	 */
	cwdfp = rootfp = NULL;
	error = dq_attach_start_get(td, q, args->da_cwdfd, &cap_fchdir_rights,
	    &cwdfp);
	if (error == 0)
		error = dq_attach_start_get(td, q, args->da_rootfd,
		    &cap_fchroot_rights, &rootfp);
	/*
	 * With a root and no cwd the cwd is the root; a cwd must be the root
	 * or a served directory under it (D184).  A root whose reference
	 * count cannot take the cwd's too is EIO, as inheritance makes it a
	 * dead start (DR_CWD_DEAD) rather than a busy one.
	 */
	if (error == 0 && rootfp != NULL && cwdfp == NULL) {
		if (fhold(rootfp))
			cwdfp = rootfp;
		else
			error = EIO;
	} else if (error == 0 && rootfp != NULL && cwdfp != rootfp)
		error = dq_file_attach_under(cwdfp, rootfp);
	if (error != 0)
		goto drop_starts;
	error = fget(td, args->da_procfd, &cap_no_rights, &fp);
	if (error != 0)
		goto drop_starts;
	if (fp->f_type != DTYPE_PROCDESC) {
		fdrop(fp, td);
		error = EINVAL;
		goto drop_starts;
	}
	pd = fp->f_data;
	sx_slock(&proctree_lock);
	p = pd->pd_proc;
	if (p == NULL) {
		sx_sunlock(&proctree_lock);
		fdrop(fp, td);
		error = ESRCH;
		goto drop_starts;
	}
	PROC_LOCK(p);
	/* An exiting target cannot be held (or attached): ESRCH, as unreaped. */
	if ((p->p_flag & P_WEXIT) != 0) {
		PROC_UNLOCK(p);
		sx_sunlock(&proctree_lock);
		fdrop(fp, td);
		error = ESRCH;
		goto drop_starts;
	}
	_PHOLD(p);
	PROC_UNLOCK(p);
	sx_sunlock(&proctree_lock);

	DQ_LOCK(q);
	error = (q->q_flags & DQ_Q_CLOSING) != 0 ? ENXIO : 0;
	DQ_UNLOCK(q);
	if (error == 0) {
		b = dq_binding_get(q);
		error = dqres_attach(td, p, b, q->q_file, &cwdfp, &rootfp,
		    args->da_flags);
		dq_binding_rele(b);
	}
	if (error == 0) {
		DQ_LOCK(q);
		q->q_stats.ds2_attached++;
		DQ_UNLOCK(q);
		SDT_PROBE2(dq, , , attach, q, p->p_pid);
	}
	PRELE(p);
	fdrop(fp, td);
drop_starts:
	if (cwdfp != NULL)
		fdrop(cwdfp, td);
	if (rootfp != NULL)
		fdrop(rootfp, td);
	return (error);
}
