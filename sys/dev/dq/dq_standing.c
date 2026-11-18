/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: standing rules (dq-standing-decisions, stage 1).
 *
 * A controller answers in advance the lookups it always answers the same
 * way.  A rule names a root (a directory, compared by pointer with the
 * lookup's process root), a normalized absolute path under it, exactly or
 * with every name beneath it, the operations it covers and the answer:
 * PASS, an errno, or ASK (post the event: an exception to a shorter rule).
 * Among the rules that fit an event the longest path decides.  The
 * consultation (dq_resolve_consult) asks here after the dead-controller
 * test and the wait guard, just before it would post; a rule's answer
 * leaves the consultation exactly as the reply it states in advance would
 * have, so nothing after it (the slot's PASS, the re-consultation at every
 * symbolic link, the walk's own checks, the errno order) can tell the two
 * apart.  A rule is a function of the root, the operation, the open's
 * class (read or write), the lookup class and the path text, nothing
 * else: every one of them is in the event the controller would have read.
 *
 * Locking.  q_st_lock is a non-sleepable rmlock and a leaf: it is never
 * held with q_mtx, a pwddesc, proc or vnode lock, and never across vhold,
 * vdrop, vrele or malloc.  Readers come from the consultation after the
 * wait guard, which proved they hold no lock; inside they only scan, count
 * and fire a probe.  Writers (ADD, DEL, FLUSH and the queue's death)
 * allocate and take the root's hold before the write lock and release what
 * they removed after it.  rm_wlock waits for the readers inside, so once
 * DEL or FLUSH returns no consultation that starts afterwards sees the
 * removed rule; one that matched it earlier is a reply sent before the
 * controller changed its mind.  The death flushes after DQ_Q_CLOSING is
 * set, which consultations test first: rules end with their controller.
 *
 * Lifetimes.  The consulting thread's binding holds the queue, so the
 * rules outlive every reader; the lock and the counters go with the queue's
 * last reference.  A rule holds its root with vhold only: the pointer is
 * never reused while the rule exists, a non-forced unmount is not blocked,
 * and a doomed root still compares equal (the walk then fails as it would).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/counter.h>
#include <sys/dqres.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rmlock.h>
#include <sys/sdt.h>
#include <sys/vnode.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_var.h>

/* The operations a rule may name (dq.4): every lookup with one path. */
#define	DQ_STANDING_OPS_ELIGIBLE					\
	(((1u << (DQ_ROP_MAX + 1)) - 2) &				\
	~(DQ_STANDING_OP(DQ_ROP_RENAME) | DQ_STANDING_OP(DQ_ROP_LINK) |	\
	DQ_STANDING_OP(DQ_ROP_SOCKET) | DQ_STANDING_OP(DQ_ROP_SOCKETPAIR) | \
	DQ_STANDING_OP(DQ_ROP_CONNECT) | DQ_STANDING_OP(DQ_ROP_BIND) |	\
	DQ_STANDING_OP(DQ_ROP_INTERNAL)))
CTASSERT(DQ_ROP_MAX < 32);

void
dq_standing_init(struct dq_queue *q)
{

	rm_init(&q->q_st_lock, "dq standing");
	q->q_st_pass = counter_u64_alloc(M_WAITOK);
	q->q_st_deny = counter_u64_alloc(M_WAITOK);
}

/* The queue's last reference: its death flushed the rules. */
void
dq_standing_fini(struct dq_queue *q)
{

	KASSERT(q->q_st_n == 0, ("dq: queue %p freed with %u standing rules",
	    q, q->q_st_n));
	counter_u64_free(q->q_st_deny);
	counter_u64_free(q->q_st_pass);
	rm_destroy(&q->q_st_lock);
}

uint64_t
dq_standing_count(struct dq_queue *q, bool deny)
{

	return (counter_u64_fetch(deny ? q->q_st_deny : q->q_st_pass));
}

/*
 * DQ_IOC_STANDING_ADD.  The errnos in dq.4's order: EINVAL for the rule
 * itself, then the root (EBADF, ENOTCAPABLE, EINVAL for a descriptor with
 * no vnode, such as a served one, ENOTDIR), then EEXIST and ENOSPC against
 * the queue's rules.  The queue's death cannot run meanwhile: the owner's
 * ioctl holds the file, and the owner goes single-threaded before it
 * disowns (dq_queue_owner_gone).
 */
int
dq_standing_add(struct dq_queue *q, struct dq_standing_rule *r,
    struct thread *td)
{
	struct dq_standing_k *k, *o;
	cap_rights_t rights;
	struct vnode *vp;
	struct pwd *pwd;
	uint64_t id;
	size_t len;
	u_int i, n;
	int error;

	if (r->dqs_version != DQ_API_VERSION ||
	    (r->dqs_flags & ~DQ_STANDING_F_VALID) != 0 ||
	    (r->dqs_action != DQ_STANDING_PASS &&
	    r->dqs_action != DQ_STANDING_ERRNO &&
	    r->dqs_action != DQ_STANDING_ASK) || r->dqs_pad0 != 0 ||
	    r->dqs_ops == 0 || (r->dqs_ops & ~DQ_STANDING_OPS_ELIGIBLE) != 0)
		return (EINVAL);
	len = r->dqs_pathlen;
	if (len >= DQ_PATH_MAX || r->dqs_path[len] != '\0' ||
	    strnlen(r->dqs_path, len) != len ||
	    !dq_path_normalized(r->dqs_path, len))
		return (EINVAL);
	/*
	 * One call: the allow-list special-cases only SOCKET and
	 * SOCKETPAIR, which no rule covers.  EAGAIN, EINTR and ENOTCAPABLE
	 * depend on the event (DQI_NO_ERESTART, a restricted lookup) and are
	 * refused.
	 */
	if (r->dqs_action == DQ_STANDING_ERRNO ? r->dqs_errno == EAGAIN ||
	    r->dqs_errno == EINTR || r->dqs_errno == ENOTCAPABLE ||
	    !dq_resolve_errno_allowed(DQ_ROP_OPEN, r->dqs_errno) :
	    r->dqs_errno != 0)
		return (EINVAL);

	/* The root, held with vhold; no lock is held here. */
	if (r->dqs_rootfd >= 0) {
		error = fgetvp(td, r->dqs_rootfd,
		    cap_rights_init_one(&rights, CAP_LOOKUP), &vp);
		if (error != 0)
			return (error);
		if (vp->v_type != VDIR) {
			vrele(vp);
			return (ENOTDIR);
		}
		vhold(vp);
		vrele(vp);
	} else if (r->dqs_rootfd == -1) {
		pwd = pwd_hold(td);
		vp = pwd->pwd_rdir;
		vhold(vp);
		pwd_drop(pwd);
	} else
		return (EBADF);

	k = malloc(sizeof(*k) + len + 1, M_DQ, M_WAITOK | M_ZERO);
	k->sk_root = vp;
	k->sk_ops = r->dqs_ops;
	k->sk_flags = r->dqs_flags;
	k->sk_action = r->dqs_action;
	k->sk_errno = r->dqs_errno;
	k->sk_len = len;
	memcpy(k->sk_path, r->dqs_path, len + 1);

	error = 0;
	id = 0;
	rm_wlock(&q->q_st_lock);
	KASSERT((q->q_flags & DQ_Q_CLOSING) == 0,
	    ("dq: standing rule added to closing queue %p", q));
	n = q->q_st_n;
	/* Sorted by root, then by path length, longest first. */
	for (i = 0; i < n; i++) {
		o = q->q_st_rule[i];
		if (o->sk_root == vp && o->sk_len == len &&
		    memcmp(o->sk_path, k->sk_path, len) == 0 &&
		    (o->sk_ops & k->sk_ops) != 0) {
			error = EEXIST;
			break;
		}
	}
	if (error == 0 && n == DQ_STANDING_MAX)
		error = ENOSPC;
	if (error == 0) {
		for (i = 0; i < n; i++) {
			o = q->q_st_rule[i];
			if ((uintptr_t)o->sk_root > (uintptr_t)vp ||
			    (o->sk_root == vp && o->sk_len < len))
				break;
		}
		memmove(&q->q_st_rule[i + 1], &q->q_st_rule[i],
		    (n - i) * sizeof(q->q_st_rule[0]));
		k->sk_id = id = ++q->q_st_next_id;
		q->q_st_rule[i] = k;
		atomic_store_int(&q->q_st_n, n + 1);
	}
	rm_wunlock(&q->q_st_lock);
	if (error != 0) {
		vdrop(vp);
		free(k, M_DQ);
		return (error);
	}
	r->dqs_id = id;
	SDT_PROBE4(dq, , , standing__change, q, DQ_STANDING_CHANGE_ADD, id,
	    n + 1);
	return (0);
}

/* DQ_IOC_STANDING_DEL: ESRCH for an id the queue has no rule of. */
int
dq_standing_del(struct dq_queue *q, uint64_t id)
{
	struct dq_standing_k *k;
	u_int i, n;

	k = NULL;
	rm_wlock(&q->q_st_lock);
	n = q->q_st_n;
	for (i = 0; i < n; i++) {
		if (q->q_st_rule[i]->sk_id == id) {
			k = q->q_st_rule[i];
			memmove(&q->q_st_rule[i], &q->q_st_rule[i + 1],
			    (n - i - 1) * sizeof(q->q_st_rule[0]));
			q->q_st_rule[n - 1] = NULL;
			atomic_store_int(&q->q_st_n, n - 1);
			break;
		}
	}
	rm_wunlock(&q->q_st_lock);
	if (k == NULL)
		return (ESRCH);
	vdrop(k->sk_root);
	free(k, M_DQ);
	SDT_PROBE4(dq, , , standing__change, q, DQ_STANDING_CHANGE_DEL, id,
	    n - 1);
	return (0);
}

/*
 * DQ_IOC_STANDING_FLUSH (what DQ_STANDING_CHANGE_FLUSH) and the queue's
 * death after DQ_Q_CLOSING (DQ_STANDING_CHANGE_DIE, which a queue without
 * rules does not report).  A queue without rules has nothing to remove: an
 * ADD that has not returned yet is ordered after the flush.
 */
void
dq_standing_flush(struct dq_queue *q, uint32_t what)
{
	struct dq_standing_k **gone;
	u_int i, n;

	if (atomic_load_int(&q->q_st_n) == 0) {
		if (what == DQ_STANDING_CHANGE_FLUSH)
			SDT_PROBE4(dq, , , standing__change, q, what, 0, 0);
		return;
	}
	gone = malloc(DQ_STANDING_MAX * sizeof(*gone), M_TEMP, M_WAITOK);
	rm_wlock(&q->q_st_lock);
	n = q->q_st_n;
	for (i = 0; i < n; i++) {
		gone[i] = q->q_st_rule[i];
		q->q_st_rule[i] = NULL;
	}
	atomic_store_int(&q->q_st_n, 0);
	rm_wunlock(&q->q_st_lock);
	for (i = 0; i < n; i++) {
		vdrop(gone[i]->sk_root);
		free(gone[i], M_DQ);
	}
	free(gone, M_TEMP);
	if (n != 0 || what == DQ_STANDING_CHANGE_FLUSH)
		SDT_PROBE4(dq, , , standing__change, q, what, 0, 0);
}

/*
 * The next component of the absolute path text[0, len) after *offp, in
 * (*cp, *clenp); false at its end.  Empty components and "." are skipped,
 * so "//a/./b/" reads as "a", "b".
 */
static bool
dq_st_next(const char *text, size_t len, size_t *offp, const char **cp,
    size_t *clenp)
{
	size_t i, start;

	i = *offp;
	while (i < len) {
		while (i < len && text[i] == '/')
			i++;
		start = i;
		while (i < len && text[i] != '/')
			i++;
		if (i == start || (i - start == 1 && text[start] == '.'))
			continue;
		*offp = i;
		*cp = text + start;
		*clenp = i - start;
		return (true);
	}
	*offp = len;
	return (false);
}

/* Has the text a ".." component?  Then no rule matches it. */
static bool
dq_st_dotdot(const char *text, size_t len)
{
	const char *c;
	size_t clen, off;

	off = 0;
	while (dq_st_next(text, len, &off, &c, &clen))
		if (clen == 2 && c[0] == '.' && c[1] == '.')
			return (true);
	return (false);
}

/*
 * Does the rule's path, component by component, equal the text (or, for
 * a subtree rule, lead it)?  The rule's path is normalized: "/" or
 * "/a/b", so "/usr/lib" never matches "/usr/lib32".
 */
static bool
dq_st_match(const struct dq_standing_k *k, const char *text, size_t len)
{
	const char *c;
	size_t clen, i, end, off;

	off = 0;
	for (i = 1; i < k->sk_len; i = end + 1) {
		for (end = i; end < k->sk_len && k->sk_path[end] != '/'; end++)
			;
		if (!dq_st_next(text, len, &off, &c, &clen) ||
		    clen != end - i || memcmp(c, &k->sk_path[i], clen) != 0)
			return (false);
	}
	if ((k->sk_flags & DQ_STANDING_F_SUBTREE) != 0)
		return (true);
	return (!dq_st_next(text, len, &off, &c, &clen));
}

/*
 * A read-class open: O_RDONLY without O_CREAT or O_TRUNC (O_EXEC,
 * O_SEARCH and O_PATH are read-class).  Any other open is covered only by
 * a rule with DQ_STANDING_F_OPEN_WRITE.
 */
static bool
dq_st_open_read(uint32_t mode)
{

	return ((mode & O_ACCMODE) == O_RDONLY &&
	    (mode & (O_CREAT | O_TRUNC)) == 0);
}

/*
 * The consultation's question, after the guard and before the post, for
 * an absolute name or absolute symbolic link target (a relative start
 * always posts):
 * DQ_SD_PASS (ans is a PASS of this queue), DQ_SD_ERRNO (*errorp) or
 * DQ_SD_NONE (post the event).  rq_st_root is the process root of an
 * eligible event, set by the core (kern_dqres.c); every other request
 * builder leaves it NULL, and the conditions it stands for are tested
 * again here, so a builder that sets it by mistake still posts.
 */
int
dq_standing_decide(struct dq_queue *q, const struct dqres_req *rq,
    struct dqres_answer *ans, int *errorp)
{
	struct rm_priotracker tracker;
	const struct dq_standing_k *k;
	uint32_t bit;
	u_int i, n;
	int sd, verdict;
	bool eligible, write;

	/* Absolute names only (dq-standing-decisions Q16, §4.9). */
	eligible = rq->rq_st_root != NULL && rq->rq_root == 0 &&
	    rq->rq_start_kind == DQ_START_REAL_ROOT &&
	    (rq->rq_rflags & (DQ_RF_RINROOT | DQ_RF_ABSTRACT)) == 0 &&
	    rq->rq_class != 2 && rq->rq_op <= DQ_ROP_MAX;
	/* A stale count is harmless: an ADD not yet returned promised nothing. */
	if (atomic_load_int(&q->q_st_n) == 0)
		return (DQ_SD_NONE);
	if (!eligible) {
		SDT_PROBE3(dq, , , standing__miss, q, rq->rq_op,
		    DQ_STANDING_MISS_INELIGIBLE);
		return (DQ_SD_NONE);
	}
	if (dq_st_dotdot(rq->rq_path, rq->rq_pathlen)) {
		SDT_PROBE3(dq, , , standing__miss, q, rq->rq_op,
		    DQ_STANDING_MISS_DOTDOT);
		return (DQ_SD_NONE);
	}
	bit = DQ_STANDING_OP(rq->rq_op);
	write = rq->rq_op == DQ_ROP_OPEN && !dq_st_open_read(rq->rq_mode);
	sd = DQ_SD_NONE;
	rm_rlock(&q->q_st_lock, &tracker);
	n = q->q_st_n;
	for (i = 0; i < n; i++) {
		k = q->q_st_rule[i];
		if (k->sk_root != rq->rq_st_root || (k->sk_ops & bit) == 0 ||
		    (write && (k->sk_flags & DQ_STANDING_F_OPEN_WRITE) == 0))
			continue;
		if (!dq_st_match(k, rq->rq_path, rq->rq_pathlen))
			continue;
		switch (k->sk_action) {
		case DQ_STANDING_PASS:
			KASSERT((rq->rq_accept & DQ_RACCEPT(DQ_RESOLVE_PASS)) != 0,
			    ("dq: standing PASS for an event without PASS"));
			counter_u64_add(q->q_st_pass, 1);
			sd = DQ_SD_PASS;
			verdict = 0;
			break;
		case DQ_STANDING_ERRNO:
			counter_u64_add(q->q_st_deny, 1);
			sd = DQ_SD_ERRNO;
			*errorp = verdict = k->sk_errno;
			break;
		default:
			verdict = -1;	/* ASK */
			break;
		}
		SDT_PROBE4(dq, , , standing__match, q, rq->rq_op, k->sk_id,
		    verdict);
		break;
	}
	if (i == n)
		SDT_PROBE3(dq, , , standing__miss, q, rq->rq_op,
		    DQ_STANDING_MISS_NOFIT);
	rm_runlock(&q->q_st_lock, &tracker);
	if (sd == DQ_SD_PASS) {
		ans->da_kind = DQ_RESOLVE_PASS;
		ans->da_qgid = q->q_gid;
	}
	return (sd);
}
