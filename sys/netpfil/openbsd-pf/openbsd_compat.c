/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Implementations of the OpenBSD kernel services used by OpenBSD PF:
 * pool(9), timeout(9), task(9), cpumem/counters, refcnt, SMR read
 * sections, mbuf lists/queues, interface hooks and route labels.
 */

#include "openbsd_compat.h"

#include <sys/module.h>

MALLOC_DEFINE(M_PF, "pf", "OpenBSD packet filter");

extern struct rwlock pf_lock, pf_state_lock;

int
obsd_pf_nosleep(void)
{
	return (rw_wowned(&pf_lock) || rw_wowned(&pf_state_lock));
}

struct sx	obsd_net_lock;
SX_SYSINIT(obsd_net_lock, &obsd_net_lock, "pf netlock");

long		obsd_nmbclust;
u_int32_t	obsd_tcp_iss;
int		obsd_ipmultipath, obsd_ip6_multipath, obsd_ip_directedbcast;

void
unhandled_af(int af)
{
	panic("unhandled af %d", af);
}

int
in_baddynamic(u_int16_t port, u_int16_t proto)
{
	/* 5BSD has no "bad dynamic" port reservation list. */
	return (0);
}

u_int16_t
stoeplitz_n32(u_int32_t n)
{
	/* pf_pkt_hash() already folds src^dst, so any good mix is fine. */
	n ^= n >> 16;
	n *= 0x7feb352dU;
	n ^= n >> 15;
	return ((u_int16_t)(n ^ (n >> 16)));
}

/* ------------------------------------------------------------------ */
/* pool(9) on UMA                                                      */
/* ------------------------------------------------------------------ */

void
pool_init(struct pool *pp, size_t size, u_int align, int ipl, int flags,
    const char *wchan, void *palloc)
{
	/* Pools are global; per-vnet initialisation calls this again. */
	if (pp->pr_zone != NULL)
		return;
	memset(pp, 0, sizeof(*pp));
	pp->pr_wchan = wchan;
	pp->pr_size = size;
	pp->pr_zone = uma_zcreate(wchan, size, NULL, NULL, NULL, NULL,
	    align ? align - 1 : UMA_ALIGN_PTR, 0);
}

void
pool_destroy(struct pool *pp)
{
	if (pp->pr_zone != NULL)
		uma_zdestroy(pp->pr_zone);
	pp->pr_zone = NULL;
}

void *
pool_get(struct pool *pp, int flags)
{
	void *v;
	int mflags;

	if (pp->pr_hardlimit != 0 && pp->pr_nout >= pp->pr_hardlimit) {
		pp->pr_nfail++;
		if ((flags & PR_LIMITFAIL) || (flags & PR_NOWAIT))
			return (NULL);
	}
	mflags = (flags & PR_WAITOK) ? M_WAITOK : M_NOWAIT;
	/* A caller that accepts failure does not sleep under pf's locks. */
	if ((flags & (PR_WAITOK | PR_LIMITFAIL)) == (PR_WAITOK | PR_LIMITFAIL) &&
	    obsd_pf_nosleep())
		mflags = M_NOWAIT;
	if (flags & PR_ZERO)
		mflags |= M_ZERO;
	v = uma_zalloc(pp->pr_zone, mflags);
	if (v == NULL) {
		pp->pr_nfail++;
		return (NULL);
	}
	atomic_add_int(&pp->pr_nout, 1);
	pp->pr_nget++;
	return (v);
}

void
pool_put(struct pool *pp, void *v)
{
	atomic_subtract_int(&pp->pr_nout, 1);
	pp->pr_nput++;
	uma_zfree(pp->pr_zone, v);
}

int
pool_sethardlimit(struct pool *pp, u_int n)
{
	if (n < pp->pr_nout)
		return (EBUSY);
	pp->pr_hardlimit = n;
	return (0);
}

/* ------------------------------------------------------------------ */
/* cpumem and counters                                                 */
/* ------------------------------------------------------------------ */

struct cpumem *
cpumem_malloc(size_t sz, struct malloc_type *type)
{
	struct cpumem *cm;
	int i;

	cm = malloc(sizeof(*cm), type, M_WAITOK | M_ZERO);
	cm->cm_sz = sz;
	CPU_FOREACH(i)
		cm->cm_mem[i] = malloc(sz, type, M_WAITOK | M_ZERO);
	return (cm);
}

void
cpumem_free(struct cpumem *cm, struct malloc_type *type, size_t sz)
{
	int i;

	if (cm == NULL)
		return;
	CPU_FOREACH(i)
		free(cm->cm_mem[i], type);
	free(cm, type);
}

void *
cpumem_first(struct cpumem_iter *i, struct cpumem *cm)
{
	for (i->cmi_cpu = 0; i->cmi_cpu <= mp_maxid; i->cmi_cpu++)
		if (cm->cm_mem[i->cmi_cpu] != NULL)
			return (cm->cm_mem[i->cmi_cpu]);
	return (NULL);
}

void *
cpumem_next(struct cpumem_iter *i, struct cpumem *cm)
{
	for (i->cmi_cpu++; i->cmi_cpu <= mp_maxid; i->cmi_cpu++)
		if (cm->cm_mem[i->cmi_cpu] != NULL)
			return (cm->cm_mem[i->cmi_cpu]);
	return (NULL);
}

/* An OpenBSD counter set is an array of counter(9) counters. */
struct cpumem *
counters_alloc(unsigned int n)
{
	struct cpumem *cm;
	counter_u64_t *c;
	unsigned int i;

	cm = malloc(sizeof(*cm), M_PF, M_WAITOK | M_ZERO);
	c = malloc(sizeof(*c) * n, M_PF, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++)
		c[i] = counter_u64_alloc(M_WAITOK);
	cm->cm_mem[0] = c;
	cm->cm_sz = n;
	return (cm);
}

void
counters_free(struct cpumem *cm, unsigned int n)
{
	counter_u64_t *c;
	unsigned int i;

	if (cm == NULL)
		return;
	c = cm->cm_mem[0];
	for (i = 0; i < n; i++)
		counter_u64_free(c[i]);
	free(c, M_PF);
	free(cm, M_PF);
}

void
counters_add(struct cpumem *cm, unsigned int i, uint64_t v)
{
	counter_u64_t *c = cm->cm_mem[0];

	counter_u64_add(c[i], v);
}

void
counters_read(struct cpumem *cm, uint64_t *out, unsigned int n,
    uint64_t *scratch)
{
	counter_u64_t *c = cm->cm_mem[0];
	unsigned int i;

	for (i = 0; i < n; i++)
		out[i] = counter_u64_fetch(c[i]);
}

void
counters_zero(struct cpumem *cm, unsigned int n)
{
	counter_u64_t *c = cm->cm_mem[0];
	unsigned int i;

	for (i = 0; i < n; i++)
		counter_u64_zero(c[i]);
}

/* ------------------------------------------------------------------ */
/* refcnt                                                              */
/* ------------------------------------------------------------------ */

void
refcnt_rele_wake(struct refcnt *r)
{
	if (refcount_release(&r->r_refs))
		wakeup_one(r);
}

void
refcnt_finalize(struct refcnt *r, const char *wmesg)
{
	if (refcount_release(&r->r_refs))
		return;
	while (refcount_load(&r->r_refs) > 0)
		tsleep(r, PWAIT, wmesg, hz / 100);
}

int
refcnt_shared(struct refcnt *r)
{
	return (refcount_load(&r->r_refs) > 1);
}

/* ------------------------------------------------------------------ */
/* timeout(9) and task(9)                                              */
/* ------------------------------------------------------------------ */

static struct taskqueue *obsd_tq;
static struct mtx obsd_lazy_mtx;
MTX_SYSINIT(obsd_lazy_mtx, &obsd_lazy_mtx, "pf lazy init", MTX_DEF);

struct taskq *const systq = (struct taskq *)1;
struct taskq *const systqmp = (struct taskq *)2;

static void
obsd_taskq_init(void *arg)
{
	obsd_tq = taskqueue_create("pf_taskq", M_WAITOK,
	    taskqueue_thread_enqueue, &obsd_tq);
	taskqueue_start_threads(&obsd_tq, 1, PI_NET, "pf taskq");
}
SYSINIT(obsd_taskq, SI_SUB_PROTO_FIREWALL, SI_ORDER_FIRST, obsd_taskq_init,
    NULL);

static void
obsd_task_run(void *arg, int pending)
{
	struct task *t = arg;

	/* pf state is per vnet: run in the vnet that queued the task. */
	CURVNET_SET(t->t_vnet != NULL ? t->t_vnet : vnet0);
	t->t_func(t->t_arg);
	CURVNET_RESTORE();
	/*
	 * OpenBSD task threads yield between tasks, which clears the
	 * SPCF_SHOULDYIELD condition pf's state purge checks; without it a
	 * self-requeueing task would spin here.
	 */
	maybe_yield();
}

static void
obsd_task_lazy_init(struct task *t)
{
	if (atomic_load_acq_int(&t->t_initialized))
		return;
	mtx_lock(&obsd_lazy_mtx);
	if (!t->t_initialized) {
		TASK_INIT(&t->t_task, 0, obsd_task_run, t);
		atomic_store_rel_int(&t->t_initialized, 1);
	}
	mtx_unlock(&obsd_lazy_mtx);
}

void
task_set(struct task *t, void (*fn)(void *), void *arg)
{
	t->t_func = fn;
	t->t_arg = arg;
	t->t_initialized = 0;
	obsd_task_lazy_init(t);
}

int
task_add(struct taskq *tq, struct task *t)
{
	int pending;

	obsd_task_lazy_init(t);
	t->t_vnet = curvnet;
	pending = task_pending(t);
	taskqueue_enqueue(obsd_tq, &t->t_task);
	return (!pending);
}

int
task_del(struct taskq *tq, struct task *t)
{
	u_int pending = 0;

	if (!t->t_initialized)
		return (0);
	taskqueue_cancel(obsd_tq, &t->t_task, &pending);
	return (pending != 0);
}

int
task_pending(struct task *t)
{
	return (t->t_initialized && t->t_task.ta_pending != 0);
}

void
taskq_barrier(struct taskq *tq)
{
	taskqueue_quiesce(obsd_tq);
}

void
taskq_del_barrier(struct taskq *tq, struct task *t)
{
	if (!t->t_initialized)
		return;
	taskqueue_cancel(obsd_tq, &t->t_task, NULL);
	taskqueue_drain(obsd_tq, &t->t_task);
}

struct taskq *
net_tq(unsigned int idx)
{
	return (systq);
}

void
net_tq_barriers(const char *wmesg)
{
	taskqueue_quiesce(obsd_tq);
}

static void
obsd_timeout_task(void *arg, int pending)
{
	struct timeout *to = arg;

	CURVNET_SET(to->to_vnet != NULL ? to->to_vnet : vnet0);
	to->to_func(to->to_arg);
	CURVNET_RESTORE();
}

static void
obsd_timeout_fire(void *arg)
{
	struct timeout *to = arg;

	taskqueue_enqueue(obsd_tq, &to->to_task);
}

static void
obsd_timeout_lazy_init(struct timeout *to)
{
	if (atomic_load_acq_int(&to->to_initialized))
		return;
	mtx_lock(&obsd_lazy_mtx);
	if (!to->to_initialized) {
		callout_init(&to->to_callout, 1);
		TASK_INIT(&to->to_task, 0, obsd_timeout_task, to);
		atomic_store_rel_int(&to->to_initialized, 1);
	}
	mtx_unlock(&obsd_lazy_mtx);
}

void
timeout_set(struct timeout *to, void (*fn)(void *), void *arg)
{
	to->to_func = fn;
	to->to_arg = arg;
	to->to_flags = 0;
	to->to_initialized = 0;
	obsd_timeout_lazy_init(to);
}

int
timeout_initialized(struct timeout *to)
{
	return (to->to_initialized);
}

static int
obsd_timeout_add_sbt(struct timeout *to, sbintime_t sbt)
{
	int pending;

	obsd_timeout_lazy_init(to);
	to->to_vnet = curvnet;
	pending = callout_pending(&to->to_callout);
	callout_reset_sbt(&to->to_callout, sbt, 0, obsd_timeout_fire, to, 0);
	return (!pending);
}

int
timeout_add(struct timeout *to, int ticks)
{
	return (obsd_timeout_add_sbt(to, tick_sbt * (ticks > 0 ? ticks : 1)));
}

int
timeout_add_sec(struct timeout *to, int secs)
{
	return (obsd_timeout_add_sbt(to, SBT_1S * (sbintime_t)secs));
}

int
timeout_add_msec(struct timeout *to, uint64_t msecs)
{
	return (obsd_timeout_add_sbt(to, SBT_1MS * (sbintime_t)msecs));
}

int
timeout_add_usec(struct timeout *to, uint64_t usecs)
{
	return (obsd_timeout_add_sbt(to, SBT_1US * (sbintime_t)usecs));
}

int
timeout_add_nsec(struct timeout *to, uint64_t nsecs)
{
	return (obsd_timeout_add_sbt(to, nstosbt(nsecs)));
}

int
timeout_del(struct timeout *to)
{
	int stopped = 0;

	if (!to->to_initialized)
		return (0);
	if (callout_stop(&to->to_callout) > 0)
		stopped = 1;
	if (taskqueue_cancel(obsd_tq, &to->to_task, NULL) == 0 &&
	    to->to_task.ta_pending)
		stopped = 1;
	return (stopped);
}

void
timeout_barrier(struct timeout *to)
{
	if (!to->to_initialized)
		return;
	callout_drain(&to->to_callout);
	taskqueue_drain(obsd_tq, &to->to_task);
}

int
timeout_del_barrier(struct timeout *to)
{
	int r = timeout_del(to);

	timeout_barrier(to);
	/*
	 * A handler that was running when the callout was drained may have
	 * re-armed it (pf_syncookie_rotate, pf purges); delete and wait
	 * again.  Callers tear down what the handler uses next (a VNET).
	 */
	while (timeout_pending(to)) {
		if (timeout_del(to))
			r = 1;
		timeout_barrier(to);
	}
	return (r);
}

int
timeout_pending(struct timeout *to)
{
	if (!to->to_initialized)
		return (0);
	return (callout_pending(&to->to_callout) ||
	    to->to_task.ta_pending != 0);
}

/* ------------------------------------------------------------------ */
/* SMR: read sections                                                 */
/* ------------------------------------------------------------------ */

/*
 * pf's SMR readers on the packet path already run inside the 5BSD net
 * epoch (pfil hooks).  Writers wait for that epoch.  Readers outside the
 * epoch (ioctl paths) only read pointers whose objects are additionally
 * reference counted (pfsync, pflow interfaces).
 */
void
smr_read_enter(void)
{
}

void
smr_read_leave(void)
{
}

void
smr_barrier(void)
{
	NET_EPOCH_WAIT();
}

void
smr_init(struct smr_entry *e)
{
	memset(e, 0, sizeof(*e));
}

static void
obsd_smr_cb(epoch_context_t ctx)
{
	struct smr_entry *e = __containerof(ctx, struct smr_entry, smr_ctx);

	e->smr_func(e->smr_arg);
}

void
smr_call(struct smr_entry *e, void (*fn)(void *), void *arg)
{
	e->smr_func = fn;
	e->smr_arg = arg;
	NET_EPOCH_CALL(obsd_smr_cb, &e->smr_ctx);
}

/* ------------------------------------------------------------------ */
/* mbuf lists and queues                                               */
/* ------------------------------------------------------------------ */

void
ml_init(struct mbuf_list *ml)
{
	ml->ml_head = ml->ml_tail = NULL;
	ml->ml_len = 0;
}

void
ml_enqueue(struct mbuf_list *ml, struct mbuf *m)
{
	if (ml->ml_tail == NULL)
		ml->ml_head = ml->ml_tail = m;
	else {
		ml->ml_tail->m_nextpkt = m;
		ml->ml_tail = m;
	}
	m->m_nextpkt = NULL;
	ml->ml_len++;
}

void
ml_enlist(struct mbuf_list *mla, struct mbuf_list *mlb)
{
	if (!ml_empty(mlb)) {
		if (ml_empty(mla))
			mla->ml_head = mlb->ml_head;
		else
			mla->ml_tail->m_nextpkt = mlb->ml_head;
		mla->ml_tail = mlb->ml_tail;
		mla->ml_len += mlb->ml_len;
		ml_init(mlb);
	}
}

struct mbuf *
ml_dequeue(struct mbuf_list *ml)
{
	struct mbuf *m;

	m = ml->ml_head;
	if (m != NULL) {
		ml->ml_head = m->m_nextpkt;
		if (ml->ml_head == NULL)
			ml->ml_tail = NULL;
		m->m_nextpkt = NULL;
		ml->ml_len--;
	}
	return (m);
}

struct mbuf *
ml_dechain(struct mbuf_list *ml)
{
	struct mbuf *m0;

	m0 = ml->ml_head;
	ml_init(ml);
	return (m0);
}

unsigned int
ml_purge(struct mbuf_list *ml)
{
	struct mbuf *m, *n;
	unsigned int len;

	for (m = ml->ml_head; m != NULL; m = n) {
		n = m->m_nextpkt;
		m_freem(m);
	}
	len = ml->ml_len;
	ml_init(ml);
	return (len);
}

unsigned int
ml_hdatalen(struct mbuf_list *ml)
{
	struct mbuf *m;

	m = ml->ml_head;
	if (m == NULL)
		return (0);
	KASSERT(ISSET(m->m_flags, M_PKTHDR));
	return (m->m_pkthdr.len);
}

void
mq_init(struct mbuf_queue *mq, u_int maxlen, int ipl)
{
	mtx_init(&mq->mq_mtx, ipl);
	ml_init(&mq->mq_list);
	mq->mq_maxlen = maxlen;
	mq->mq_drops = 0;
}

int
mq_push(struct mbuf_queue *mq, struct mbuf *m)
{
	struct mbuf *dropped = NULL;

	mtx_enter(&mq->mq_mtx);
	if (mq_len(mq) >= mq->mq_maxlen) {
		mq->mq_drops++;
		dropped = ml_dequeue(&mq->mq_list);
	}
	ml_enqueue(&mq->mq_list, m);
	mtx_leave(&mq->mq_mtx);
	if (dropped)
		m_freem(dropped);
	return (dropped != NULL);
}

int
mq_enqueue(struct mbuf_queue *mq, struct mbuf *m)
{
	int dropped = 0;

	mtx_enter(&mq->mq_mtx);
	if (mq_len(mq) < mq->mq_maxlen)
		ml_enqueue(&mq->mq_list, m);
	else {
		mq->mq_drops++;
		dropped = 1;
	}
	mtx_leave(&mq->mq_mtx);
	if (dropped)
		m_freem(m);
	return (dropped);
}

struct mbuf *
mq_dequeue(struct mbuf_queue *mq)
{
	struct mbuf *m;

	mtx_enter(&mq->mq_mtx);
	m = ml_dequeue(&mq->mq_list);
	mtx_leave(&mq->mq_mtx);
	return (m);
}

int
mq_enlist(struct mbuf_queue *mq, struct mbuf_list *ml)
{
	struct mbuf *m;
	int dropped = 0;

	mtx_enter(&mq->mq_mtx);
	if (mq_len(mq) < mq->mq_maxlen)
		ml_enlist(&mq->mq_list, ml);
	else {
		dropped = ml_len(ml);
		mq->mq_drops += dropped;
	}
	mtx_leave(&mq->mq_mtx);
	if (dropped) {
		while ((m = ml_dequeue(ml)) != NULL)
			m_freem(m);
	}
	return (dropped);
}

void
mq_delist(struct mbuf_queue *mq, struct mbuf_list *ml)
{
	mtx_enter(&mq->mq_mtx);
	*ml = mq->mq_list;
	ml_init(&mq->mq_list);
	mtx_leave(&mq->mq_mtx);
}

unsigned int
mq_purge(struct mbuf_queue *mq)
{
	struct mbuf_list ml;

	mq_delist(mq, &ml);
	return (ml_purge(&ml));
}

unsigned int
mq_hdatalen(struct mbuf_queue *mq)
{
	unsigned int hdatalen;

	mtx_enter(&mq->mq_mtx);
	hdatalen = ml_hdatalen(&mq->mq_list);
	mtx_leave(&mq->mq_mtx);
	return (hdatalen);
}

void
mq_set_maxlen(struct mbuf_queue *mq, u_int maxlen)
{
	mtx_enter(&mq->mq_mtx);
	mq->mq_maxlen = maxlen;
	mtx_leave(&mq->mq_mtx);
}

/* ------------------------------------------------------------------ */
/* Interfaces: references by index and per-interface hooks             */
/* ------------------------------------------------------------------ */

struct ifnet *
if_get(unsigned int idx)
{
	struct ifnet *ifp;
	struct epoch_tracker et;

	if (idx == 0)
		return (NULL);
	NET_EPOCH_ENTER(et);
	ifp = ifnet_byindex_ref(idx);
	NET_EPOCH_EXIT(et);
	return (ifp);
}

void
if_put(struct ifnet *ifp)
{
	if (ifp != NULL)
		if_rele(ifp);
}

struct obsd_ifhook {
	TAILQ_ENTRY(obsd_ifhook) h_entry;
	struct ifnet	*h_ifp;
	struct task	*h_task;
	int		 h_kind;
};
#define	OBSD_HOOK_ADDR		1
#define	OBSD_HOOK_DETACH	2
#define	OBSD_HOOK_LINK		3
static TAILQ_HEAD(, obsd_ifhook) obsd_ifhooks =
    TAILQ_HEAD_INITIALIZER(obsd_ifhooks);
/* A stack-owned departure token also covers VNET moves (not IFF_DYING). */
struct obsd_ifclosing {
	TAILQ_ENTRY(obsd_ifclosing) c_entry;
	struct ifnet *c_ifp;
};
static TAILQ_HEAD(, obsd_ifclosing) obsd_ifclosing =
    TAILQ_HEAD_INITIALIZER(obsd_ifclosing);
static struct mtx obsd_ifhook_mtx;
MTX_SYSINIT(obsd_ifhook_mtx, &obsd_ifhook_mtx, "pf ifhooks", MTX_DEF);

static void
obsd_hook_add(struct ifnet *ifp, struct task *t, int kind)
{
	struct obsd_ifhook *h;
	struct obsd_ifclosing *closing;

	/* pf adds hooks with its (non-sleepable) lock held. */
	h = malloc(sizeof(*h), M_PF, (obsd_pf_nosleep() ?
	    M_NOWAIT | M_USE_RESERVE : M_WAITOK) | M_ZERO);
	if (h == NULL) {
		printf("pf: no memory for an interface hook on %s\n",
		    ifp->if_xname);
		return;
	}
	h->h_ifp = ifp;
	h->h_task = t;
	h->h_kind = kind;
	mtx_lock(&obsd_ifhook_mtx);
	TAILQ_FOREACH(closing, &obsd_ifclosing, c_entry)
		if (closing->c_ifp == ifp)
			break;
	if ((ifp->if_flags & IFF_DYING) || closing != NULL) {
		mtx_unlock(&obsd_ifhook_mtx);
		free(h, M_PF);
		return;
	}
	{
		/* OpenBSD links the task itself: it is on a list at most once. */
		struct obsd_ifhook *o;

		TAILQ_FOREACH(o, &obsd_ifhooks, h_entry)
			if (o->h_ifp == ifp && o->h_task == t &&
			    o->h_kind == kind)
				break;
		if (o != NULL) {
			mtx_unlock(&obsd_ifhook_mtx);
			free(h, M_PF);
			return;
		}
	}
	TAILQ_INSERT_TAIL(&obsd_ifhooks, h, h_entry);
	mtx_unlock(&obsd_ifhook_mtx);
}

static void
obsd_hook_del(struct ifnet *ifp, struct task *t, int kind)
{
	struct obsd_ifhook *h, *n;

	mtx_lock(&obsd_ifhook_mtx);
	TAILQ_FOREACH_SAFE(h, &obsd_ifhooks, h_entry, n) {
		if (h->h_ifp == ifp && h->h_task == t && h->h_kind == kind) {
			TAILQ_REMOVE(&obsd_ifhooks, h, h_entry);
			free(h, M_PF);
		}
	}
	mtx_unlock(&obsd_ifhook_mtx);
	task_del(systq, t);
}

/* Run the hooks of one kind for an interface (called from eventhandlers). */
void	obsd_ifhooks_run(struct ifnet *, int);
void
obsd_ifhooks_run(struct ifnet *ifp, int kind)
{
	TAILQ_HEAD(, obsd_ifhook) detached = TAILQ_HEAD_INITIALIZER(detached);
	struct obsd_ifhook *h, *next;
	struct obsd_ifclosing closing = { .c_ifp = ifp };

	if (kind != OBSD_HOOK_DETACH) {
		mtx_lock(&obsd_ifhook_mtx);
		TAILQ_FOREACH(h, &obsd_ifhooks, h_entry)
			if (h->h_ifp == ifp && h->h_kind == kind)
				task_add(systq, h->h_task);
		mtx_unlock(&obsd_ifhook_mtx);
		return;
	}

	/*
	 * FreeBSD marks the interface IFF_DYING before this notification,
	 * so OpenBSD detach callbacks cannot use if_get() to find it and
	 * unregister their other hooks.  Remove every registration while
	 * excluding event producers, then drain callbacks before their
	 * owners can be freed.  Do not hold netlock while draining: the
	 * callbacks may need it.  OpenBSD runs detach hooks synchronously
	 * before removing the interface from its index map.
	 */
	/* Serialize closing with pfsync_up(), which registers under netlock. */
	NET_LOCK();
	mtx_lock(&obsd_ifhook_mtx);
	TAILQ_INSERT_TAIL(&obsd_ifclosing, &closing, c_entry);
	TAILQ_FOREACH_SAFE(h, &obsd_ifhooks, h_entry, next) {
		if (h->h_ifp == ifp) {
			TAILQ_REMOVE(&obsd_ifhooks, h, h_entry);
			TAILQ_INSERT_TAIL(&detached, h, h_entry);
		}
	}
	mtx_unlock(&obsd_ifhook_mtx);
	NET_UNLOCK();

	TAILQ_FOREACH(h, &detached, h_entry)
		taskq_del_barrier(systq, h->h_task);

	while ((h = TAILQ_FIRST(&detached)) != NULL) {
		TAILQ_REMOVE(&detached, h, h_entry);
		if (h->h_kind == OBSD_HOOK_DETACH) {
			NET_LOCK();
			h->h_task->t_func(h->h_task->t_arg);
			NET_UNLOCK();
		}
		free(h, M_PF);
	}

	mtx_lock(&obsd_ifhook_mtx);
	TAILQ_REMOVE(&obsd_ifclosing, &closing, c_entry);
	mtx_unlock(&obsd_ifhook_mtx);
}

void
if_addrhook_add(struct ifnet *ifp, struct task *t)
{
	obsd_hook_add(ifp, t, OBSD_HOOK_ADDR);
}

void
if_addrhook_del(struct ifnet *ifp, struct task *t)
{
	obsd_hook_del(ifp, t, OBSD_HOOK_ADDR);
}

void
if_detachhook_add(struct ifnet *ifp, struct task *t)
{
	obsd_hook_add(ifp, t, OBSD_HOOK_DETACH);
}

void
if_detachhook_del(struct ifnet *ifp, struct task *t)
{
	obsd_hook_del(ifp, t, OBSD_HOOK_DETACH);
}

void
if_linkstatehook_add(struct ifnet *ifp, struct task *t)
{
	obsd_hook_add(ifp, t, OBSD_HOOK_LINK);
}

void
if_linkstatehook_del(struct ifnet *ifp, struct task *t)
{
	obsd_hook_del(ifp, t, OBSD_HOOK_LINK);
}

/* ------------------------------------------------------------------ */
/* Route labels (OpenBSD rtlabel): a name <-> id registry for pf.      */
/* ------------------------------------------------------------------ */

struct obsd_rtlabel {
	TAILQ_ENTRY(obsd_rtlabel) rtl_entry;
	char		rtl_name[RTLABEL_LEN];
	u_int16_t	rtl_id;
	int		rtl_ref;
};
static TAILQ_HEAD(, obsd_rtlabel) obsd_rtlabels =
    TAILQ_HEAD_INITIALIZER(obsd_rtlabels);
static struct mtx obsd_rtlabel_mtx;
MTX_SYSINIT(obsd_rtlabel_mtx, &obsd_rtlabel_mtx, "pf rtlabels", MTX_DEF);

const char *
rtlabel_id2name(u_int16_t id, char *buf, size_t sz)
{
	struct obsd_rtlabel *l;
	const char *r = NULL;

	mtx_lock(&obsd_rtlabel_mtx);
	TAILQ_FOREACH(l, &obsd_rtlabels, rtl_entry)
		if (l->rtl_id == id) {
			strlcpy(buf, l->rtl_name, sz);
			r = buf;
			break;
		}
	mtx_unlock(&obsd_rtlabel_mtx);
	return (r);
}

u_int16_t
rtlabel_name2id(const char *name)
{
	struct obsd_rtlabel *l, *p;
	u_int16_t new_id = 1, id = 0;

	if (!name[0])
		return (0);
	mtx_lock(&obsd_rtlabel_mtx);
	TAILQ_FOREACH(l, &obsd_rtlabels, rtl_entry)
		if (strcmp(name, l->rtl_name) == 0) {
			l->rtl_ref++;
			id = l->rtl_id;
			goto out;
		}
	/* lowest free id */
	TAILQ_FOREACH(p, &obsd_rtlabels, rtl_entry) {
		if (p->rtl_id != new_id)
			break;
		new_id = p->rtl_id + 1;
	}
	if (new_id > 0xffff - 1)
		goto out;
	l = malloc(sizeof(*l), M_PF, M_NOWAIT | M_ZERO);
	if (l == NULL)
		goto out;
	strlcpy(l->rtl_name, name, sizeof(l->rtl_name));
	l->rtl_id = new_id;
	l->rtl_ref = 1;
	if (p != NULL)
		TAILQ_INSERT_BEFORE(p, l, rtl_entry);
	else
		TAILQ_INSERT_TAIL(&obsd_rtlabels, l, rtl_entry);
	id = l->rtl_id;
out:
	mtx_unlock(&obsd_rtlabel_mtx);
	return (id);
}

void
rtlabel_unref(u_int16_t id)
{
	struct obsd_rtlabel *l, *n;

	if (id == 0)
		return;
	mtx_lock(&obsd_rtlabel_mtx);
	TAILQ_FOREACH_SAFE(l, &obsd_rtlabels, rtl_entry, n)
		if (id == l->rtl_id) {
			if (--l->rtl_ref <= 0) {
				TAILQ_REMOVE(&obsd_rtlabels, l, rtl_entry);
				free(l, M_PF);
			}
			break;
		}
	mtx_unlock(&obsd_rtlabel_mtx);
}

/* OpenBSD rn_init() allocates the mask tree; pf calls it per vnet. */
void	obsd_rn_init(unsigned int);
void	obsd_rn_init_once(unsigned int);
void
obsd_rn_init_once(unsigned int keylen)
{
	static int done;

	if (atomic_cmpset_int(&done, 0, 1))
		obsd_rn_init(keylen);
}
