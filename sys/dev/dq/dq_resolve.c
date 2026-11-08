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
#include <sys/dqres.h>
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
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <dev/dq/dq.h>
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
    const struct dqres_req *rq)
{
	struct dq_queue *q;
	struct dq_resolve_body *rb;
	const struct dq_resolve_reply *rr;
	struct dq_data *reply;
	sbintime_t deadline;
	size_t bodylen;
	char *p;
	int error, rerror, ms;
	bool dead;

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
	bodylen = roundup2(sizeof(*rb) + rq->rq_pathlen + 1 +
	    rq->rq_path2len + 1 + rq->rq_startpathlen + 1 +
	    rq->rq_startpath2len + 1, 8);
	rb = malloc(bodylen, M_DQ, M_WAITOK | M_ZERO);
	rb->drs_op = rq->rq_op;
	rb->drs_rflags = rq->rq_rflags;
	rb->drs_start_kind = rq->rq_start_kind;
	rb->drs_start2_kind = rq->rq_start2_kind;
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
	    deadline, &reply, &rerror);
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
	/* The reply path accepted only PASS (1c-i). */
	rr = (const struct dq_resolve_reply *)reply->dd_bytes;
	KASSERT(rr->drr_kind == DQ_RESOLVE_PASS, ("dq: resolve kind"));
	dq_reply_free(reply);
	DQ_LOCK(q);
	q->q_stats.ds2_resolve_pass++;
	DQ_UNLOCK(q);
	SDT_PROBE3(dq, , , resolve__reply, q, rq->rq_op, 0);
	return (0);
}

static const struct dqres_ops dq_resolve_ops = {
	.dro_hold = dq_binding_hold,
	.dro_rele = dq_binding_rele,
	.dro_consult = dq_resolve_consult,
	.dro_unmarked = dq_binding_unmarked,
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
 * The reply body of a RESOLVE: an errno carries none; otherwise exactly a
 * struct dq_resolve_reply of kind PASS in 1c-i and 1c-ii.  Any other kind
 * (an FD for a socket included, stage 2) is EINVAL to the controller and
 * the event stays in flight (D128).
 */
int
dq_resolve_reply_validate(int rerrno, const void *buf, size_t len)
{
	const struct dq_resolve_reply *rr;

	if (rerrno != 0)
		return (len == 0 ? 0 : EINVAL);
	if (len != sizeof(*rr))
		return (EINVAL);
	rr = buf;
	if (rr->drr_kind != DQ_RESOLVE_PASS || rr->drr_pad0 != 0)
		return (EINVAL);
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
	struct file *fp;
	struct proc *p;
	int error;

	if (args->da_version != DQ_API_VERSION || args->da_flags != 0 ||
	    args->da_pad0 != 0)
		return (EINVAL);
	/* Served start directories are stage 1c-iii. */
	if (args->da_rootfd != -1 || args->da_cwdfd != -1)
		return (EINVAL);
	error = fget(td, args->da_procfd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_PROCDESC) {
		fdrop(fp, td);
		return (EINVAL);
	}
	pd = fp->f_data;
	sx_slock(&proctree_lock);
	p = pd->pd_proc;
	if (p == NULL) {
		sx_sunlock(&proctree_lock);
		fdrop(fp, td);
		return (ESRCH);
	}
	PROC_LOCK(p);
	/* An exiting target cannot be held (or attached): ESRCH, as unreaped. */
	if ((p->p_flag & P_WEXIT) != 0) {
		PROC_UNLOCK(p);
		sx_sunlock(&proctree_lock);
		fdrop(fp, td);
		return (ESRCH);
	}
	_PHOLD(p);
	PROC_UNLOCK(p);
	sx_sunlock(&proctree_lock);

	DQ_LOCK(q);
	error = (q->q_flags & DQ_Q_CLOSING) != 0 ? ENXIO : 0;
	DQ_UNLOCK(q);
	if (error == 0) {
		b = dq_binding_get(q);
		error = dqres_attach(td, p, b, q->q_file);
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
	return (error);
}
