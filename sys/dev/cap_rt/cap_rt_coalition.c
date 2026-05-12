/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_coalition — capability-based resource group management.
 *
 * A cap_rt CALL service that groups capabilities (cap_rt instances),
 * processes, jails, sockets, and other fd-based resources.  State-change
 * events are emitted as CAP_RT_RECVMSG notifications.  Terminating the
 * coalition revokes all members:
 *
 *   - cap_rt members: cap_rt_instance_revoke()
 *   - processes: kern_psignal(SIGKILL)
 *   - jails: prison_remove()
 *   - sockets: soshutdown(SHUT_RDWR)
 *
 * Userspace API (via CAP_RT_CALL on coalition fd):
 *   COALITION_OP_ENLIST      — attach member fd
 *   COALITION_OP_JOIN        — self-join calling process
 *   COALITION_OP_ENLIST_SET  — attach multiple member fds
 *   COALITION_OP_TERMINATE   — kill all members
 *   COALITION_OP_STAT        — query coalition state
 *   COALITION_OP_SET_SIGNAL  — set termination signal
 *   COALITION_OP_GRACEFUL    — signal → grace → SIGKILL
 *   COALITION_OP_SET_DEADLINE — auto-terminate after timeout
 *   COALITION_OP_SET_WATCHDOG — dead-man switch
 *   COALITION_OP_HEARTBEAT   — reset watchdog
 *   COALITION_OP_SET_LEADER  — designate leader (death triggers term)
 *   COALITION_OP_RUSAGE      — aggregate resource usage
 *
 * Lock order:
 *   coalition_proc_hash_lock (rwlock, global)
 *     → co_sx (sx lock, per-coalition)
 *       → child co_sx (parent before child for nested coalitions)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/jail.h>
#include <sys/jaildesc.h>
#include <sys/limits.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <sys/eventhandler.h>
#include <sys/hash.h>
#include <sys/syslog.h>
#include <sys/socketvar.h>
#include <sys/sdt.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>

#include <machine/atomic.h>
#include <vm/uma.h>
#include <sys/resourcevar.h>
#include <sys/user.h>

#include "cap_rt.h"
#include "cap_rt_internal.h"
#include "cap_rt_coalition_proto.h"

/* ----------------------------------------------------------------
 * DTrace SDT probes
 * ---------------------------------------------------------------- */
SDT_PROVIDER_DEFINE(cap_rt_coalition);
SDT_PROBE_DEFINE1(cap_rt_coalition, , , create, "uint64_t");
SDT_PROBE_DEFINE2(cap_rt_coalition, , , enlist, "int", "int");
SDT_PROBE_DEFINE2(cap_rt_coalition, , , join, "pid_t", "int");
SDT_PROBE_DEFINE2(cap_rt_coalition, , , terminate, "u_int", "int");
SDT_PROBE_DEFINE1(cap_rt_coalition, , , close, "u_int");
SDT_PROBE_DEFINE1(cap_rt_coalition, , , member__exit, "pid_t");
SDT_PROBE_DEFINE1(cap_rt_coalition, , , leader__exit, "pid_t");
SDT_PROBE_DEFINE2(cap_rt_coalition, , , fork__inherit, "pid_t", "pid_t");
SDT_PROBE_DEFINE3(cap_rt_coalition, , , call__done,
    "uint32_t", "int", "sbintime_t");

MALLOC_DEFINE(M_COALITION, "cap_rt_coalition",
    "cap_rt coalition structures");

/* ----------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------- */

struct coalition_member {
	TAILQ_ENTRY(coalition_member)	cm_link;
	LIST_ENTRY(coalition_member)	cm_hash;	/* process hash */
	struct file		*cm_fp;		/* held reference (NULL for JOIN) */
	struct coalition	*cm_coalition;
	void			*cm_data;	/* proc ptr for process members */
	struct coalition	*cm_nested_co;	/* ref'd child coalition (nested only) */
	int			cm_dtype;
	char			cm_svc_name[CAP_RT_MAXNAME]; /* cap_rt service name */
};

struct coalition {
	struct sx		co_sx;
	TAILQ_HEAD(, coalition_member) co_members;
	u_int			co_flags;
	u_int			co_manual_grace_count;
	int			co_signal;
	u_int			co_nesting_depth;
	volatile u_int		co_member_count;
	u_int			co_refcount;
	/* Deadline */
	struct callout		co_deadline_callout;
	struct task		co_deadline_task;
	int			co_deadline_signal;
	uint32_t		co_deadline_grace_ms;
	/* Watchdog */
	struct callout		co_watchdog_callout;
	struct task		co_watchdog_task;
	uint32_t		co_watchdog_timeout_ms;
	/* Leader */
	struct coalition_member	*co_leader;
	pid_t			co_leader_pid;
	/* Cap_rt leader monitor — polls leader liveness */
	struct callout		co_leader_callout;
	struct task		co_leader_task;
	/* Back-reference for timer tasks */
	struct cap_rt_instance	*co_instance;
};

/* ----------------------------------------------------------------
 * Globals
 * ---------------------------------------------------------------- */

static struct cap_rt_service *coalition_svc;

static uma_zone_t coalition_zone;
static uma_zone_t coalition_member_zone;

static volatile u_int coalition_count;
static volatile u_int coalition_total_members;

/*
 * Global nested-operation lock.  Serializes:
 *   - Nested coalition enlistment (cycle check + insert)
 *   - coalition_revoke clearing ci_priv
 *
 * This prevents two races:
 *   1. ABBA deadlock: A←B and B←A both take parent co_sx then
 *      try to slock the other → deadlock.  The nest lock serializes
 *      all nested enlists so only one runs at a time.
 *   2. ci_priv TOCTOU: revoke clears ci_priv and frees the
 *      coalition while enlist reads it.  Both sides hold nest_lock,
 *      so the read and clear are mutually exclusive.
 */
static struct sx coalition_nest_lock;

/* Process hash for exit handler lookup */
#define	COALITION_PROC_HASH_SIZE	256
static LIST_HEAD(, coalition_member)
    coalition_proc_hash[COALITION_PROC_HASH_SIZE];
static struct rwlock coalition_proc_hash_lock;

static inline u_int
coalition_proc_hash_idx(struct proc *p)
{
	uintptr_t key = (uintptr_t)p;

	return (hash32_buf(&key, sizeof(key), 0) &
	    (COALITION_PROC_HASH_SIZE - 1));
}

/* Jail OSD for fork inheritance */
static u_int coalition_jail_osd_slot;

struct coalition_jail_osd {
	struct coalition	*cjo_coalition;
	struct coalition_member	*cjo_member;
	struct file		*cjo_fp;
	struct task		cjo_cleanup_task;
};

static eventhandler_tag coalition_fork_tag;
static eventhandler_tag coalition_exit_tag;

/*
 * Sysctl tunables — soft limits, best-effort enforcement.
 * Concurrent connect/enlist/fork can overshoot by the number
 * of racing threads.  This is acceptable for resource control;
 * hard enforcement would require a global lock on every admission.
 */
static u_int coalition_max = 0;		/* 0 = unlimited */
static u_int coalition_max_members = 0;

SYSCTL_NODE(_kern, OID_AUTO, cap_rt_coalition,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "cap_rt coalition");
SYSCTL_UINT(_kern_cap_rt_coalition, OID_AUTO, count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_count), 0,
    "Number of active coalitions");
SYSCTL_UINT(_kern_cap_rt_coalition, OID_AUTO, max, CTLFLAG_RW,
    &coalition_max, 0,
    "Maximum coalitions (0 = unlimited)");
SYSCTL_UINT(_kern_cap_rt_coalition, OID_AUTO, max_members, CTLFLAG_RW,
    &coalition_max_members, 0,
    "Maximum total members (0 = unlimited)");
SYSCTL_UINT(_kern_cap_rt_coalition, OID_AUTO, members, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &coalition_total_members), 0,
    "Total members across all coalitions");

/* Forward declarations */
static void	coalition_terminate_members_locked(struct coalition *co,
		    struct thread *td, bool skip_self, int sig_override);
static void	coalition_collect_external_members_locked(
		    struct coalition *co, struct file ***jail_fpsp,
		    int *jail_countp,
		    struct cap_rt_instance ***cap_rt_cisp,
		    int *cap_rt_countp);
static void	coalition_terminate_external_members(struct thread *td,
		    struct file **jail_fps, int jail_count,
		    struct cap_rt_instance **cap_rt_cis,
		    int cap_rt_count);
static int	coalition_terminate(struct coalition *co);
static void	coalition_deadline_callout_fn(void *arg);
static void	coalition_deadline_task_fn(void *context, int pending);
static void	coalition_watchdog_callout_fn(void *arg);
static void	coalition_watchdog_task_fn(void *context, int pending);
static void	coalition_leader_callout_fn(void *arg);
static void	coalition_leader_task_fn(void *context, int pending);
static void	coalition_jail_cleanup_task_fn(void *context, int pending);

/* Leader monitor polling interval: 100ms */
#define	COALITION_LEADER_POLL_TICKS	(hz / 10)

/* ----------------------------------------------------------------
 * Coalition lifecycle
 * ---------------------------------------------------------------- */

static void
coalition_ref(struct coalition *co)
{

	refcount_acquire(&co->co_refcount);
}

static void
coalition_free(struct coalition *co)
{

	KASSERT(TAILQ_EMPTY(&co->co_members),
	    ("coalition_free: members not empty"));
	KASSERT(co->co_refcount == 0,
	    ("coalition_free: refcount %u", co->co_refcount));
	sx_destroy(&co->co_sx);
	uma_zfree(coalition_zone, co);
	atomic_subtract_int(&coalition_count, 1);
}

static void
coalition_rel(struct coalition *co)
{

	if (refcount_release(&co->co_refcount))
		coalition_free(co);
}

static struct coalition *
coalition_alloc(void)
{
	struct coalition *co;

	co = uma_zalloc(coalition_zone, M_WAITOK | M_ZERO);
	sx_init_flags(&co->co_sx, "cap_rt_coalition", SX_DUPOK);
	TAILQ_INIT(&co->co_members);
	co->co_signal = SIGKILL;
	co->co_nesting_depth = 0;
	refcount_init(&co->co_refcount, 1);
	callout_init(&co->co_deadline_callout, 1);
	TASK_INIT(&co->co_deadline_task, 0, coalition_deadline_task_fn, co);
	callout_init(&co->co_watchdog_callout, 1);
	TASK_INIT(&co->co_watchdog_task, 0, coalition_watchdog_task_fn, co);
	callout_init(&co->co_leader_callout, 1);
	TASK_INIT(&co->co_leader_task, 0, coalition_leader_task_fn, co);
	atomic_add_int(&coalition_count, 1);
	return (co);
}

static void
coalition_update_grace_flag_locked(struct coalition *co)
{

	sx_assert(&co->co_sx, SA_XLOCKED);

	if ((co->co_flags & COF_TERMINATING) != 0) {
		co->co_flags &= ~COF_GRACE_ACTIVE;
		return;
	}

	if (co->co_manual_grace_count != 0 ||
	    (co->co_flags & COF_DEADLINE_GRACE) != 0)
		co->co_flags |= COF_GRACE_ACTIVE;
	else
		co->co_flags &= ~COF_GRACE_ACTIVE;
}

static int
coalition_timeout_ticks(uint32_t timeout_ms)
{
	uint32_t ticks_ms;

	if (timeout_ms == 0)
		return (0);

	ticks_ms = MSEC_2_TICKS(timeout_ms);
	if (ticks_ms > INT_MAX)
		return (INT_MAX);
	return ((int)ticks_ms);
}

static int
coalition_validate_member_rights(int dtype, const struct filecaps *fcaps)
{

	if (fcaps == NULL)
		return (0);

	switch (dtype) {
	case DTYPE_PROCDESC:
		return (cap_check(&fcaps->fc_rights, &cap_pdkill_rights));
	case DTYPE_JAILDESC:
		return (cap_check(&fcaps->fc_rights, &cap_jail_remove_rights));
	case DTYPE_SOCKET:
		return (cap_check(&fcaps->fc_rights, &cap_shutdown_rights));
	case DTYPE_SHM:
		return (cap_check(&fcaps->fc_rights, &cap_ftruncate_rights));
	default:
		return (0);
	}
}

static void
coalition_notify_event(struct coalition *co, uint32_t flags)
{
	struct coalition_event_msg ev;
	int error;

	if (co == NULL || co->co_instance == NULL || flags == 0)
		return;
	sx_assert(&co->co_sx, SA_XLOCKED);

	ev.flags = flags;
	error = cap_rt_notify(co->co_instance, &ev, sizeof(ev), NULL, NULL, 0);
	if (error != 0 && error != EAGAIN && error != ENOBUFS &&
	    error != ECONNRESET)
		log(LOG_NOTICE,
		    "cap_rt_coalition: event delivery failed: %d\n", error);
}

/* ----------------------------------------------------------------
 * Nested coalition detection
 * ---------------------------------------------------------------- */

static bool
coalition_is_nested(struct file *fp)
{
	struct cap_rt_instance *ci;

	if (fp == NULL || fp->f_type != DTYPE_CAP_RT)
		return (false);
	ci = fp->f_data;
	if (ci == NULL || ci->ci_service == NULL)
		return (false);
	return (ci->ci_service == coalition_svc);
}

/* ----------------------------------------------------------------
 * Jail OSD
 * ---------------------------------------------------------------- */

static int
coalition_jail_set_atomic(struct prison *pr, struct coalition *co,
    struct file *fp)
{
	struct coalition_jail_osd *cjo, *existing;

	if (coalition_jail_osd_slot == 0)
		return (ENXIO);

	cjo = malloc(sizeof(*cjo), M_COALITION, M_WAITOK);
	cjo->cjo_coalition = co;
	cjo->cjo_member = NULL;
	if (!fhold(fp)) {
		free(cjo, M_COALITION);
		return (EBADF);
	}
	cjo->cjo_fp = fp;
	TASK_INIT(&cjo->cjo_cleanup_task, 0, coalition_jail_cleanup_task_fn, cjo);

	prison_lock(pr);
	existing = osd_jail_get(pr, coalition_jail_osd_slot);
	if (existing != NULL) {
		prison_unlock(pr);
		fdrop(cjo->cjo_fp, NULL);
		free(cjo, M_COALITION);
		return (EBUSY);
	}
	osd_jail_set(pr, coalition_jail_osd_slot, cjo);
	prison_unlock(pr);
	return (0);
}

static void
coalition_jail_set_member(struct prison *pr, struct coalition_member *cm)
{
	struct coalition_jail_osd *cjo;

	if (coalition_jail_osd_slot == 0)
		return;
	prison_lock(pr);
	cjo = osd_jail_get(pr, coalition_jail_osd_slot);
	if (cjo != NULL)
		cjo->cjo_member = cm;
	prison_unlock(pr);
}

static void
coalition_jail_cleanup_task_fn(void *context, int pending __unused)
{
	struct coalition_jail_osd *cjo = context;
	struct coalition *co;
	struct coalition_member *cm;
	bool removed;
	bool was_leader;

	if (cjo == NULL)
		return;

	co = cjo->cjo_coalition;
	cm = NULL;
	removed = false;
	was_leader = false;

	if (co != NULL) {
		sx_xlock(&co->co_sx);
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_JAILDESC &&
			    cm->cm_fp == cjo->cjo_fp)
				break;
		}
		if (cm != NULL) {
			TAILQ_REMOVE(&co->co_members, cm, cm_link);
			cm->cm_link.tqe_prev = NULL;
			if ((co->co_flags & COF_HAS_LEADER) &&
			    co->co_leader == cm) {
				was_leader = true;
				co->co_leader = NULL;
				co->co_flags &= ~COF_HAS_LEADER;
			}
			coalition_notify_event(co, COALITION_NOTE_MEMBER_REMOVED);
			removed = true;
		}
		sx_xunlock(&co->co_sx);
	}

	if (was_leader) {
		SDT_PROBE1(cap_rt_coalition, , , leader__exit, 0);
		coalition_terminate(co);
	}

	if (removed) {
		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);
		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, NULL);
		if (cm->cm_data != NULL) {
			struct prison *pr = cm->cm_data;

			cm->cm_data = NULL;
			prison_free(pr);
		}
		uma_zfree(coalition_member_zone, cm);
		coalition_rel(co);
	}

	if (cjo->cjo_fp != NULL)
		fdrop(cjo->cjo_fp, NULL);
	if (co != NULL)
		coalition_rel(co);
	free(cjo, M_COALITION);
}

static void
coalition_jail_osd_dtor(void *value)
{
	struct coalition_jail_osd *cjo = value;
	struct coalition *co;

	if (cjo == NULL)
		return;

	co = cjo->cjo_coalition;

	if (cjo->cjo_member != NULL) {
		taskqueue_enqueue(taskqueue_thread, &cjo->cjo_cleanup_task);
		return;
	}

	if (cjo->cjo_fp != NULL)
		fdrop(cjo->cjo_fp, NULL);
	if (co != NULL)
		coalition_rel(co);
	free(cjo, M_COALITION);
}

/* ----------------------------------------------------------------
 * Jail termination
 * ---------------------------------------------------------------- */

static int
coalition_jail_terminate(struct file *fp)
{
	struct jaildesc *jd;
	struct prison *pr;

	KASSERT(fp != NULL && fp->f_data != NULL,
	    ("coalition_jail_terminate: bad fp"));

	jd = fp->f_data;
	JAILDESC_LOCK(jd);
	pr = jd->jd_prison;
	if (pr == NULL || !prison_isvalid(pr)) {
		JAILDESC_UNLOCK(jd);
		return (ENOENT);
	}
	prison_hold(pr);
	JAILDESC_UNLOCK(jd);

	sx_xlock(&allprison_lock);
	mtx_lock(&pr->pr_mtx);
	if (prison_isalive(pr)) {
		/* prison_remove() releases pr_mtx and allprison_lock */
		prison_remove(pr);
		/* Release the reference from prison_hold() above */
		prison_free(pr);
	} else {
		mtx_unlock(&pr->pr_mtx);
		sx_xunlock(&allprison_lock);
		prison_free(pr);
	}
	return (0);
}

/* ----------------------------------------------------------------
 * Member limit checks
 * ---------------------------------------------------------------- */

static int
coalition_check_limits(struct coalition *co)
{
	u_int max, cur;

	max = coalition_max_members;
	if (max != 0) {
		cur = atomic_load_acq_int(&coalition_total_members);
		if (cur >= max)
			return (ENOMEM);
	}
	(void)co;
	return (0);
}

/* ----------------------------------------------------------------
 * Process hash
 * ---------------------------------------------------------------- */

static void
coalition_proc_hash_insert(struct coalition_member *cm, struct proc *p)
{
	u_int idx;

	rw_assert(&coalition_proc_hash_lock, RA_WLOCKED);
	idx = coalition_proc_hash_idx(p);
	LIST_INSERT_HEAD(&coalition_proc_hash[idx], cm, cm_hash);
}

static struct coalition_member *
coalition_proc_hash_lookup(struct proc *p)
{
	struct coalition_member *cm;
	u_int idx;

	rw_assert(&coalition_proc_hash_lock, RA_LOCKED);
	idx = coalition_proc_hash_idx(p);
	LIST_FOREACH(cm, &coalition_proc_hash[idx], cm_hash) {
		if (cm->cm_data == p)
			return (cm);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 * Enlistment
 * ---------------------------------------------------------------- */

/*
 * Check whether 'target' appears anywhere in 'child's nested
 * coalition tree.  depth_limit bounds recursion so a malformed
 * existing graph cannot recurse indefinitely.
 *
 * Lock ordering: caller must NOT hold target->co_sx.
 * We acquire child->co_sx as reader, then recurse into
 * grandchildren (always child-before-grandchild order).
 */
static int
coalition_check_cycle(struct coalition *child, struct coalition *target,
    int depth_limit)
{
	struct coalition_member *cm;
	int error = 0;

	if (depth_limit <= 0)
		return (ELOOP);

	sx_slock(&child->co_sx);
	TAILQ_FOREACH(cm, &child->co_members, cm_link) {
		struct coalition *grandchild;

		grandchild = cm->cm_nested_co;
		if (grandchild == NULL)
			continue;

		if (grandchild == target) {
			error = ELOOP;
			break;
		}

		error = coalition_check_cycle(grandchild, target,
		    depth_limit - 1);
		if (error != 0)
			break;
	}
	sx_sunlock(&child->co_sx);
	return (error);
}

static int
coalition_validate_redepth_locked(struct coalition *co, u_int depth)
{
	struct coalition_member *cm;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (depth >= COALITION_MAX_NESTING)
		return (ELOOP);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct coalition *child;

		child = cm->cm_nested_co;
		if (child == NULL)
			continue;

		sx_xlock(&child->co_sx);
		error = coalition_validate_redepth_locked(child, depth + 1);
		sx_xunlock(&child->co_sx);
		if (error != 0)
			return (error);
	}

	return (0);
}

static void
coalition_apply_redepth_locked(struct coalition *co, u_int depth)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_XLOCKED);
	KASSERT(depth < COALITION_MAX_NESTING,
	    ("coalition depth overflow: %u", depth));

	co->co_nesting_depth = depth;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct coalition *child;

		child = cm->cm_nested_co;
		if (child == NULL)
			continue;

		sx_xlock(&child->co_sx);
		coalition_apply_redepth_locked(child, depth + 1);
		sx_xunlock(&child->co_sx);
	}
}

/*
 * Compute the maximum nesting depth below 'co'.
 * Returns 0 if no nested children, 1 if one level, etc.
 * Bounded by max_depth to prevent stack overflow.
 */
static bool
coalition_has_member(struct coalition *co, struct file *fp)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_LOCKED);
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_fp == fp)
			return (true);
	}
	return (false);
}

static int
coalition_enlist(struct coalition *co, struct thread *td, struct file *fp,
    const struct filecaps *fcaps)
{
	struct coalition_member *cm;
	int dtype, error;
	bool is_nested;

	dtype = fp->f_type;
	is_nested = coalition_is_nested(fp);

	error = coalition_validate_member_rights(dtype, fcaps);
	if (error != 0)
		return (error);

	/*
	 * For nested coalitions, defer the cycle check until after
	 * we hold co_sx (in the generic path below).  This makes
	 * the check-and-insert atomic, preventing concurrent
	 * opposite enlists (A←B and B←A) from both passing.
	 */

	error = coalition_check_limits(co);
	if (error != 0)
		return (error);

	if (!fhold(fp))
		return (EBADF);

	cm = uma_zalloc(coalition_member_zone, M_WAITOK | M_ZERO);
	cm->cm_dtype = dtype;
	cm->cm_svc_name[0] = '\0';

	/*
	 * For cap_rt members, record the service name (type).
	 */
	if (dtype == DTYPE_CAP_RT) {
		struct cap_rt_instance *ci = fp->f_data;

		if (ci != NULL && ci->ci_service != NULL)
			strlcpy(cm->cm_svc_name, ci->ci_service->csvc_name,
			    sizeof(cm->cm_svc_name));
	}

	if (dtype == DTYPE_PROCDESC) {
		struct procdesc *pd = fp->f_data;
		struct proc *p;

		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ESRCH);
		}
		sx_sunlock(&proctree_lock);

		cm->cm_data = p;

		/*
		 * Lock order: co_sx → hash_lock.
		 * Take co_sx first to match timer task paths.
		 */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ESHUTDOWN);
		}

		rw_wlock(&coalition_proc_hash_lock);
		if (coalition_proc_hash_lookup(p) != NULL) {
			rw_wunlock(&coalition_proc_hash_lock);
			sx_xunlock(&co->co_sx);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBUSY);
		}

		coalition_proc_hash_insert(cm, p);
		rw_wunlock(&coalition_proc_hash_lock);

	} else if (dtype == DTYPE_JAILDESC) {
		struct jaildesc *jd = fp->f_data;
		struct prison *pr;

		JAILDESC_LOCK(jd);
		pr = jd->jd_prison;
		if (pr == NULL || !prison_isvalid(pr)) {
			JAILDESC_UNLOCK(jd);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ENOENT);
		}
		prison_hold(pr);
		JAILDESC_UNLOCK(jd);

		cm->cm_data = pr;

		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			prison_free(pr);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ESHUTDOWN);
		}

			/*
			 * Take the OSD-owned coalition reference before
			 * publishing the OSD entry so the destructor always
			 * drops a live reference.
			 */
			coalition_ref(co);
			error = coalition_jail_set_atomic(pr, co, fp);
			if (error != 0) {
				coalition_rel(co);
				sx_xunlock(&co->co_sx);
			prison_free(pr);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (error);
		}

	} else if (is_nested) {
		/*
		 * Nested coalition enlistment.
		 *
		 * Take the global nest_lock to serialize against:
		 *   - Concurrent opposite enlists (prevents ABBA deadlock
		 *     on per-coalition locks)
		 *   - Concurrent co_revoke clearing ci_priv (prevents
		 *     use-after-free on child coalition)
		 *
		 * Under nest_lock: read ci_priv, ref the child, run
		 * cycle check.  Then take co_sx for the actual insert.
		 */
		struct cap_rt_instance *ci;
		struct coalition *nested_co;

		sx_xlock(&coalition_nest_lock);

		ci = fp->f_data;
		nested_co = cap_rt_instance_get_priv(ci);
		if (nested_co == NULL) {
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBADF);
		}
		coalition_ref(nested_co);

		if (nested_co == co) {
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EINVAL);
		}

		error = coalition_check_cycle(nested_co, co,
		    COALITION_MAX_NESTING);
		if (error != 0) {
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (error);
		}

		/* Cycle check passed — now take co_sx for insertion */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ESHUTDOWN);
		}

		if (coalition_has_member(co, fp)) {
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBUSY);
		}

		sx_xlock(&nested_co->co_sx);
		if (nested_co->co_nesting_depth != 0) {
			sx_xunlock(&nested_co->co_sx);
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBUSY);
		}

		error = coalition_validate_redepth_locked(nested_co,
		    co->co_nesting_depth + 1);
		if (error != 0) {
			sx_xunlock(&nested_co->co_sx);
			sx_xunlock(&co->co_sx);
			coalition_rel(nested_co);
			sx_xunlock(&coalition_nest_lock);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (error);
		}

		coalition_apply_redepth_locked(nested_co,
		    co->co_nesting_depth + 1);
		sx_xunlock(&nested_co->co_sx);

		cm->cm_nested_co = nested_co;
		/* ref transferred to cm_nested_co */
		sx_xunlock(&coalition_nest_lock);
	} else {
		/* Generic: cap_rt (non-nested), socket, shm, etc. */
		sx_xlock(&co->co_sx);
		if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (ESHUTDOWN);
		}

		if (coalition_has_member(co, fp)) {
			sx_xunlock(&co->co_sx);
			uma_zfree(coalition_member_zone, cm);
			fdrop(fp, td);
			return (EBUSY);
		}
	}

	/* Common member setup */
	cm->cm_fp = fp;
	cm->cm_coalition = co;
	TAILQ_INSERT_TAIL(&co->co_members, cm, cm_link);

	if (dtype == DTYPE_JAILDESC) {
		struct prison *pr = cm->cm_data;

		/*
		 * cm_data owns the prison_hold() taken during enlist and must
		 * keep that reference until member teardown.
		 */
		coalition_jail_set_member(pr, cm);
	}

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);
	sx_xunlock(&co->co_sx);

	SDT_PROBE2(cap_rt_coalition, , , enlist, dtype, 0);
	return (0);
}

/* ----------------------------------------------------------------
 * Self-join (process joins coalition without procdesc)
 * ---------------------------------------------------------------- */

static int
coalition_join(struct coalition *co, struct thread *td)
{
	struct coalition_member *cm;
	struct proc *p;
	int error;

	error = coalition_check_limits(co);
	if (error != 0)
		return (error);

	p = td->td_proc;
	cm = uma_zalloc(coalition_member_zone, M_WAITOK | M_ZERO);

	/*
	 * Lock order: co_sx → hash_lock.
	 */
	sx_xlock(&co->co_sx);
	if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		uma_zfree(coalition_member_zone, cm);
		return (ESHUTDOWN);
	}

	rw_wlock(&coalition_proc_hash_lock);
	if (coalition_proc_hash_lookup(p) != NULL) {
		rw_wunlock(&coalition_proc_hash_lock);
		sx_xunlock(&co->co_sx);
		uma_zfree(coalition_member_zone, cm);
		return (EBUSY);
	}

	cm->cm_data = p;
	cm->cm_fp = NULL;
	cm->cm_coalition = co;
	cm->cm_dtype = DTYPE_PROCDESC;

	coalition_proc_hash_insert(cm, p);
	rw_wunlock(&coalition_proc_hash_lock);
	TAILQ_INSERT_TAIL(&co->co_members, cm, cm_link);

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);

	sx_xunlock(&co->co_sx);

	SDT_PROBE2(cap_rt_coalition, , , join, p->p_pid, 0);
	return (0);
}

/* ----------------------------------------------------------------
 * Termination
 * ---------------------------------------------------------------- */

static void
coalition_signal_processes_locked(struct coalition *co, int sig)
{
	struct coalition_member *cm;

	sx_assert(&co->co_sx, SA_XLOCKED);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct proc *p;

		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;

		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL) {
				PROC_LOCK(p);
				sx_sunlock(&proctree_lock);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			} else {
				sx_sunlock(&proctree_lock);
			}
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL) {
				PROC_LOCK(p);
				kern_psignal(p, sig);
				PROC_UNLOCK(p);
			}
		}
	}
}

static u_int
coalition_count_process_members_locked(struct coalition *co)
{
	struct coalition_member *cm;
	u_int count;

	sx_assert(&co->co_sx, SA_XLOCKED);

	count = 0;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype == DTYPE_PROCDESC)
			count++;
	}
	return (count);
}

static u_int
coalition_count_live_procs_locked(struct coalition *co)
{
	struct coalition_member *cm;
	u_int count = 0;

	sx_assert(&co->co_sx, SA_XLOCKED);

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		struct proc *p;

		if (cm->cm_dtype != DTYPE_PROCDESC)
			continue;

		if (cm->cm_fp != NULL) {
			struct procdesc *pd = cm->cm_fp->f_data;

			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p != NULL) {
				PROC_LOCK(p);
				if ((p->p_flag & P_WEXIT) == 0)
					count++;
				PROC_UNLOCK(p);
			}
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_data != NULL) {
			p = (struct proc *)atomic_load_acq_ptr(
			    (uintptr_t *)&cm->cm_data);
			if (p != NULL) {
				PROC_LOCK(p);
				if ((p->p_flag & P_WEXIT) == 0)
					count++;
				PROC_UNLOCK(p);
			}
		}
	}
	return (count);
}

static void
coalition_collect_external_members_locked(struct coalition *co,
    struct file ***jail_fpsp, int *jail_countp,
    struct cap_rt_instance ***cap_rt_cisp, int *cap_rt_countp)
{
	struct coalition_member *cm;
	struct file **jail_fps;
	struct cap_rt_instance **cap_rt_cis;
	int jail_count, cap_rt_count, i;

	sx_assert(&co->co_sx, SA_XLOCKED);

	jail_count = 0;
	cap_rt_count = 0;
	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		if (cm->cm_dtype == DTYPE_JAILDESC && cm->cm_fp != NULL)
			jail_count++;
		else if (cm->cm_dtype == DTYPE_CAP_RT && cm->cm_fp != NULL)
			cap_rt_count++;
	}

	jail_fps = NULL;
	if (jail_count > 0) {
		jail_fps = malloc(jail_count * sizeof(struct file *),
		    M_COALITION, M_WAITOK);
		i = 0;
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_JAILDESC &&
			    cm->cm_fp != NULL && i < jail_count) {
				if (fhold(cm->cm_fp))
					jail_fps[i++] = cm->cm_fp;
			}
		}
		jail_count = i;
	}

	cap_rt_cis = NULL;
	if (cap_rt_count > 0) {
		cap_rt_cis = malloc(
		    cap_rt_count * sizeof(struct cap_rt_instance *),
		    M_COALITION, M_WAITOK);
		i = 0;
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_CAP_RT &&
			    cm->cm_fp != NULL && i < cap_rt_count) {
				struct cap_rt_instance *ci;

				ci = cm->cm_fp->f_data;
				if (ci != NULL) {
					cap_rt_instance_hold(ci);
					cap_rt_cis[i++] = ci;
				}
			}
		}
		cap_rt_count = i;
	}

	*jail_fpsp = jail_fps;
	*jail_countp = jail_count;
	*cap_rt_cisp = cap_rt_cis;
	*cap_rt_countp = cap_rt_count;
}

static void
coalition_terminate_external_members(struct thread *td, struct file **jail_fps,
    int jail_count, struct cap_rt_instance **cap_rt_cis, int cap_rt_count)
{
	int i;

	for (i = 0; i < cap_rt_count; i++) {
		cap_rt_instance_revoke(cap_rt_cis[i]);
		cap_rt_instance_rele(cap_rt_cis[i]);
	}
	if (cap_rt_cis != NULL)
		free(cap_rt_cis, M_COALITION);

	for (i = 0; i < jail_count; i++) {
		(void)coalition_jail_terminate(jail_fps[i]);
		fdrop(jail_fps[i], td);
	}
	if (jail_fps != NULL)
		free(jail_fps, M_COALITION);
}

/*
 * Must be called with co_sx held.
 * sig_override: if nonzero, use this signal instead of co_signal.
 * Used by graceful/deadline escalation to force SIGKILL.
 */
static void
coalition_terminate_members_locked(struct coalition *co, struct thread *td,
    bool skip_self, int sig_override)
{
	struct coalition_member *cm;
	struct proc *self;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (co->co_flags & COF_TERMINATING)
		return;
	co->co_flags |= COF_TERMINATING;
	coalition_notify_event(co, COALITION_NOTE_TERMINATING);

	/* Clean up leader tracking */
	co->co_leader = NULL;
	co->co_flags &= ~COF_HAS_LEADER;
	co->co_manual_grace_count = 0;
	coalition_update_grace_flag_locked(co);

	self = (skip_self && td != NULL) ? td->td_proc : NULL;

	TAILQ_FOREACH(cm, &co->co_members, cm_link) {
		/*
		 * Skip cap_rt and jail members — both must be
		 * terminated outside the lock to avoid deadlock.
		 * cap_rt: co_revoke can re-enter coalition_close_internal.
		 * jails: OSD destructor needs co_sx.
		 */
		if (cm->cm_dtype == DTYPE_CAP_RT)
			continue;
		if (cm->cm_dtype == DTYPE_JAILDESC)
			continue;

		/* Process members — use override or configured signal */
		if (cm->cm_dtype == DTYPE_PROCDESC) {
			struct proc *p;
			int sig = (sig_override != 0) ?
			    sig_override : co->co_signal;

			if (cm->cm_fp != NULL) {
				struct procdesc *pd = cm->cm_fp->f_data;

				sx_slock(&proctree_lock);
				p = pd->pd_proc;
				if (p != NULL) {
					PROC_LOCK(p);
					sx_sunlock(&proctree_lock);
					if (!(skip_self && p == self))
						kern_psignal(p, sig);
					PROC_UNLOCK(p);
				} else {
					sx_sunlock(&proctree_lock);
				}
			} else if (cm->cm_data != NULL) {
				p = (struct proc *)atomic_load_acq_ptr(
				    (uintptr_t *)&cm->cm_data);
				if (skip_self && p == self)
					continue;
				if (p != NULL) {
					PROC_LOCK(p);
					kern_psignal(p, sig);
					PROC_UNLOCK(p);
				}
			}
			continue;
		}

		/* Sockets */
		if (cm->cm_dtype == DTYPE_SOCKET && cm->cm_fp != NULL) {
			struct socket *so = cm->cm_fp->f_data;

			(void)soshutdown(so, SHUT_RDWR);
			continue;
		}

		/* SHM */
		if (cm->cm_dtype == DTYPE_SHM && cm->cm_fp != NULL) {
			(void)fo_truncate(cm->cm_fp, 0, td->td_ucred, td);
			continue;
		}
	}
}

static int
coalition_terminate(struct coalition *co)
{
	struct thread *td = curthread;
	struct file **jail_fps;
	struct cap_rt_instance **cap_rt_cis;
	int jail_count, cap_rt_count;

	sx_xlock(&co->co_sx);

	if (co->co_flags & COF_TERMINATING) {
		sx_xunlock(&co->co_sx);
		return (ESHUTDOWN);
	}

	coalition_collect_external_members_locked(co, &jail_fps,
	    &jail_count, &cap_rt_cis, &cap_rt_count);

	/* Terminate processes, sockets, shm under lock */
	coalition_terminate_members_locked(co, td, false, 0);
	sx_xunlock(&co->co_sx);

	coalition_terminate_external_members(td, jail_fps, jail_count,
	    cap_rt_cis, cap_rt_count);

	SDT_PROBE2(cap_rt_coalition, , , terminate,
	    atomic_load_acq_int(&co->co_member_count), 0);
	return (0);
}

static int
coalition_terminate_graceful(struct coalition *co, int sig, u_int timeout_ms)
{
	struct file **jail_fps;
	struct cap_rt_instance **cap_rt_cis;
	bool had_process_members;
	bool force_kill;
	int jail_count, cap_rt_count;

	u_int remaining, elapsed;

	if (sig <= 0 || sig >= NSIG)
		return (EINVAL);
	if (timeout_ms > 60000)
		timeout_ms = 60000;

	sx_xlock(&co->co_sx);
	if (co->co_flags & COF_TERMINATING) {
		sx_xunlock(&co->co_sx);
		return (ESHUTDOWN);
	}

	/* Freeze membership during grace period */
	co->co_manual_grace_count++;
	coalition_update_grace_flag_locked(co);
	had_process_members = (coalition_count_process_members_locked(co) != 0);

	coalition_signal_processes_locked(co, sig);

	elapsed = 0;
	while (elapsed < timeout_ms) {
		remaining = coalition_count_live_procs_locked(co);
		if (remaining == 0)
			break;
		sx_xunlock(&co->co_sx);
		u_int sleep_ms = (timeout_ms - elapsed);
		if (sleep_ms > 100)
			sleep_ms = 100;
		(void)pause_sbt("co_grace", SBT_1MS * sleep_ms,
		    0, C_HARDCLOCK);
		elapsed += sleep_ms;
		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			if (co->co_manual_grace_count > 0)
				co->co_manual_grace_count--;
			coalition_update_grace_flag_locked(co);
			sx_xunlock(&co->co_sx);
			return (0);
		}
	}

	force_kill = (coalition_count_live_procs_locked(co) != 0);
	if (co->co_manual_grace_count > 0)
		co->co_manual_grace_count--;
	coalition_update_grace_flag_locked(co);

	if (force_kill || !had_process_members) {
		/*
		 * If processes are still alive after grace, escalate to
		 * SIGKILL.  If there were never any process members, degrade
		 * graceful termination into an immediate full termination for
		 * the remaining member types.
		 */
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &cap_rt_cis, &cap_rt_count);
		coalition_terminate_members_locked(co, curthread, false,
		    force_kill ? SIGKILL : 0);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(curthread, jail_fps,
		    jail_count, cap_rt_cis, cap_rt_count);
	} else {
		/*
		 * All processes exited during grace period —
		 * coalition stays alive for reuse.
		 */
		sx_xunlock(&co->co_sx);
	}
	return (0);
}

static bool
coalition_deadline_disarm_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (!(co->co_flags & COF_DEADLINE_ACTIVE))
		return (false);

	co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
	coalition_update_grace_flag_locked(co);

	if (callout_stop(&co->co_deadline_callout))
		coalition_rel(co);

	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_deadline_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

static bool
coalition_watchdog_disarm_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);

	if (!(co->co_flags & COF_WATCHDOG_ACTIVE))
		return (false);

	co->co_flags &= ~COF_WATCHDOG_ACTIVE;

	if (callout_stop(&co->co_watchdog_callout))
		coalition_rel(co);

	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_watchdog_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

/* ----------------------------------------------------------------
 * Deadline timer
 * ---------------------------------------------------------------- */

static void
coalition_deadline_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct file **jail_fps = NULL;
	struct cap_rt_instance **cap_rt_cis = NULL;
	struct thread *td = curthread;
	int jail_count = 0, cap_rt_count = 0;
	int sig_override;

	sx_xlock(&co->co_sx);

	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_DEADLINE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	if (co->co_flags & COF_DEADLINE_GRACE) {
		/* Grace expired — escalate to SIGKILL */
		co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
		coalition_notify_event(co, COALITION_NOTE_DEADLINE_FIRED);
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &cap_rt_cis, &cap_rt_count);
		coalition_terminate_members_locked(co, td, false, SIGKILL);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(td, jail_fps, jail_count,
		    cap_rt_cis, cap_rt_count);
		coalition_rel(co);
		return;
		} else if (co->co_deadline_signal != 0 &&
		    co->co_deadline_grace_ms > 0) {
			coalition_signal_processes_locked(co, co->co_deadline_signal);
			coalition_notify_event(co,
			    COALITION_NOTE_DEADLINE_FIRED |
			    COALITION_NOTE_GRACE_STARTED);
			co->co_flags |= COF_DEADLINE_GRACE;
			coalition_update_grace_flag_locked(co);
			coalition_ref(co);
			callout_reset(&co->co_deadline_callout,
			    coalition_timeout_ticks(co->co_deadline_grace_ms),
			    coalition_deadline_callout_fn, co);
	} else {
		co->co_flags &= ~COF_DEADLINE_ACTIVE;
		coalition_notify_event(co, COALITION_NOTE_DEADLINE_FIRED);
		coalition_collect_external_members_locked(co, &jail_fps,
		    &jail_count, &cap_rt_cis, &cap_rt_count);
		sig_override = (co->co_deadline_signal != 0) ?
		    co->co_deadline_signal : SIGKILL;
		coalition_terminate_members_locked(co, td, false, sig_override);
		sx_xunlock(&co->co_sx);
		coalition_terminate_external_members(td, jail_fps, jail_count,
		    cap_rt_cis, cap_rt_count);
		coalition_rel(co);
		return;
	}

	sx_xunlock(&co->co_sx);
	coalition_rel(co);
}

static void
coalition_deadline_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_deadline_task);
}

/* ----------------------------------------------------------------
 * Watchdog timer
 * ---------------------------------------------------------------- */

static void
coalition_watchdog_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct file **jail_fps = NULL;
	struct cap_rt_instance **cap_rt_cis = NULL;
	int jail_count = 0, cap_rt_count = 0;

	sx_xlock(&co->co_sx);

	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_WATCHDOG_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	co->co_flags &= ~COF_WATCHDOG_ACTIVE;
	coalition_notify_event(co, COALITION_NOTE_WATCHDOG_FIRED);
	coalition_collect_external_members_locked(co, &jail_fps,
	    &jail_count, &cap_rt_cis, &cap_rt_count);
	coalition_terminate_members_locked(co, curthread, false, SIGKILL);
	sx_xunlock(&co->co_sx);
	coalition_terminate_external_members(curthread, jail_fps, jail_count,
	    cap_rt_cis, cap_rt_count);
	coalition_rel(co);
}

static void
coalition_watchdog_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_watchdog_task);
}

/* ----------------------------------------------------------------
 * Cap_rt leader monitor
 * ---------------------------------------------------------------- */

/*
 * Taskqueue handler: check if the cap_rt leader is still alive.
 * If dead, terminate the coalition immediately.  If still alive,
 * reschedule the monitor callout.
 */
static void
coalition_leader_task_fn(void *context, int pending __unused)
{
	struct coalition *co = context;
	struct coalition_member *leader;
	struct cap_rt_instance *ci;
	bool dead = false;

	sx_xlock(&co->co_sx);

	/* Bail if terminating or monitor was stopped */
	if ((co->co_flags & COF_TERMINATING) ||
	    !(co->co_flags & COF_LEADER_MONITOR)) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		sx_xunlock(&co->co_sx);
		coalition_rel(co);	/* monitor's ref */
		return;
	}

	leader = co->co_leader;
	if (leader == NULL || leader->cm_dtype != DTYPE_CAP_RT ||
	    leader->cm_fp == NULL) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		sx_xunlock(&co->co_sx);
		coalition_rel(co);
		return;
	}

	ci = leader->cm_fp->f_data;
	if (ci != NULL &&
	    (ci->ci_flags & (CAP_RT_SF_CLOSED | CAP_RT_SF_REVOKED)))
		dead = true;

	if (dead) {
		co->co_leader = NULL;
		co->co_flags &= ~(COF_HAS_LEADER | COF_LEADER_MONITOR);
		coalition_notify_event(co, COALITION_NOTE_LEADER_DIED);
		sx_xunlock(&co->co_sx);

		SDT_PROBE1(cap_rt_coalition, , , leader__exit, 0);
		coalition_terminate(co);
		coalition_rel(co);	/* monitor's ref */
	} else {
		/* Still alive — reschedule, keep ref */
		callout_reset(&co->co_leader_callout,
		    COALITION_LEADER_POLL_TICKS,
		    coalition_leader_callout_fn, co);
		sx_xunlock(&co->co_sx);
	}
}

static void
coalition_leader_callout_fn(void *arg)
{
	struct coalition *co = arg;

	taskqueue_enqueue(taskqueue_thread, &co->co_leader_task);
}

/*
 * Start or restart the cap_rt leader monitor.
 * Exactly one coalition reference is held while the monitor
 * is active (tracked by COF_LEADER_MONITOR flag).
 * Caller must hold co_sx.
 */
static void
coalition_leader_monitor_start_locked(struct coalition *co)
{

	sx_assert(&co->co_sx, SA_XLOCKED);
	if (!(co->co_flags & COF_LEADER_MONITOR)) {
		co->co_flags |= COF_LEADER_MONITOR;
		coalition_ref(co);
	}
	callout_reset(&co->co_leader_callout,
	    COALITION_LEADER_POLL_TICKS,
	    coalition_leader_callout_fn, co);
}

/*
 * Stop the monitor.  Clears the flag; the running task will
 * see the flag clear and release the ref.  If a task is
 * merely queued, cancel it and release the ref here.
 * Caller must hold co_sx.
 */
static bool
coalition_leader_monitor_stop_locked(struct coalition *co)
{
	u_int pending;
	int error;

	sx_assert(&co->co_sx, SA_XLOCKED);
	if (!(co->co_flags & COF_LEADER_MONITOR))
		return (false);
	co->co_flags &= ~COF_LEADER_MONITOR;
	if (callout_stop(&co->co_leader_callout))
		coalition_rel(co);
	pending = 0;
	error = taskqueue_cancel(taskqueue_thread, &co->co_leader_task,
	    &pending);
	if (pending != 0)
		coalition_rel(co);
	return (error == EBUSY);
}

/* ----------------------------------------------------------------
 * Process exit / fork eventhandlers
 * ---------------------------------------------------------------- */

static void
coalition_process_exit(void *arg __unused, struct proc *p)
{
	struct coalition_member *cm;
	struct coalition *co;
	bool was_leader = false;

	rw_wlock(&coalition_proc_hash_lock);
	cm = coalition_proc_hash_lookup(p);
	if (cm == NULL) {
		rw_wunlock(&coalition_proc_hash_lock);
		return;
	}

	SDT_PROBE1(cap_rt_coalition, , , member__exit, p->p_pid);

	co = cm->cm_coalition;
	coalition_ref(co);
	LIST_REMOVE(cm, cm_hash);
	cm->cm_hash.le_prev = NULL;
	rw_wunlock(&coalition_proc_hash_lock);

	/*
	 * Try to remove the member from the coalition's TAILQ.
	 * If tqe_prev is NULL, coalition_close_internal() already
	 * claimed this member — it owns the free.  We must not
	 * touch cm after releasing co_sx in that case.
	 */
	bool we_own_cm = false;

	sx_xlock(&co->co_sx);
	if (cm->cm_link.tqe_prev != NULL) {
		TAILQ_REMOVE(&co->co_members, cm, cm_link);
		cm->cm_link.tqe_prev = NULL;
		we_own_cm = true;

		if ((co->co_flags & COF_HAS_LEADER) &&
		    co->co_leader == cm) {
			was_leader = true;
			co->co_leader = NULL;
			co->co_flags &= ~COF_HAS_LEADER;
		}

		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);
		coalition_notify_event(co, COALITION_NOTE_MEMBER_REMOVED);
	}
	sx_xunlock(&co->co_sx);

	if (was_leader) {
		SDT_PROBE1(cap_rt_coalition, , , leader__exit, p->p_pid);
		coalition_terminate(co);
	}

	if (we_own_cm) {
		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, curthread);
		uma_zfree(coalition_member_zone, cm);
		coalition_rel(co);	/* member's ref */
	}
	coalition_rel(co);	/* our local ref */
}

static void
coalition_process_fork(void *arg __unused, struct proc *parent,
    struct proc *child, int flags __unused)
{
	struct coalition_member *pcm, *ccm;
	struct coalition *co;

	rw_rlock(&coalition_proc_hash_lock);
	pcm = coalition_proc_hash_lookup(parent);
	if (pcm == NULL) {
		rw_runlock(&coalition_proc_hash_lock);
		return;
	}
	co = pcm->cm_coalition;
	coalition_ref(co);
	rw_runlock(&coalition_proc_hash_lock);

	ccm = uma_zalloc(coalition_member_zone, M_WAITOK | M_ZERO);

	/*
	 * Lock order: co_sx → hash_lock.
	 */
	sx_xlock(&co->co_sx);

	if (co->co_flags & (COF_TERMINATING | COF_GRACE_ACTIVE)) {
		sx_xunlock(&co->co_sx);
		uma_zfree(coalition_member_zone, ccm);
		coalition_rel(co);
		return;
	}

	/* Enforce member limits — refuse fork inheritance if exceeded */
	if (coalition_check_limits(co) != 0) {
		sx_xunlock(&co->co_sx);
		uma_zfree(coalition_member_zone, ccm);
		coalition_rel(co);
		log(LOG_WARNING,
		    "cap_rt_coalition: fork denied by member limit\n");
		return;
	}

	ccm->cm_data = child;
	ccm->cm_fp = NULL;
	ccm->cm_coalition = co;
	ccm->cm_dtype = DTYPE_PROCDESC;

	rw_wlock(&coalition_proc_hash_lock);
	coalition_proc_hash_insert(ccm, child);
	rw_wunlock(&coalition_proc_hash_lock);
	TAILQ_INSERT_TAIL(&co->co_members, ccm, cm_link);

	atomic_add_int(&co->co_member_count, 1);
	atomic_add_int(&coalition_total_members, 1);
	coalition_ref(co);
	coalition_notify_event(co, COALITION_NOTE_MEMBER_ADDED);

	sx_xunlock(&co->co_sx);

	SDT_PROBE2(cap_rt_coalition, , , fork__inherit,
	    parent->p_pid, child->p_pid);
	coalition_rel(co);
}

/* ----------------------------------------------------------------
 * Close / cleanup (co_revoke)
 * ---------------------------------------------------------------- */

static void
coalition_close_internal(struct coalition *co, struct thread *td)
{
	struct coalition_member *cm, *cm_temp;
	struct coalition_member *cleanup_list, **cleanup_tailp;
	struct coalition_member *jail_list, **jail_tailp;

	if (co == NULL)
		return;

	SDT_PROBE1(cap_rt_coalition, , , close,
	    atomic_load_acq_int(&co->co_member_count));

	/*
	 * Drain pending callouts/tasks before acquiring locks to
	 * avoid deadlock.  callout_drain blocks until any running
	 * handler completes and prevents rescheduling.
	 */
	callout_drain(&co->co_deadline_callout);
	taskqueue_drain(taskqueue_thread, &co->co_deadline_task);
	callout_drain(&co->co_watchdog_callout);
	taskqueue_drain(taskqueue_thread, &co->co_watchdog_task);
	callout_drain(&co->co_leader_callout);
	taskqueue_drain(taskqueue_thread, &co->co_leader_task);

	/*
	 * Take co_sx alone first to release timer refs and
	 * terminate members (which takes proctree_lock internally).
	 * This avoids holding hash_lock across proctree_lock.
	 */
	sx_xlock(&co->co_sx);

	/*
	 * Release refs held by active timers.  The drains above
	 * ensure nothing is running, so we can safely check flags
	 * and release refs under the lock.
	 */
	if (co->co_flags & COF_DEADLINE_ACTIVE) {
		co->co_flags &= ~(COF_DEADLINE_ACTIVE | COF_DEADLINE_GRACE);
		coalition_rel(co);
	}
	if (co->co_flags & COF_WATCHDOG_ACTIVE) {
		co->co_flags &= ~COF_WATCHDOG_ACTIVE;
		coalition_rel(co);
	}
	if (co->co_flags & COF_LEADER_MONITOR) {
		co->co_flags &= ~COF_LEADER_MONITOR;
		coalition_rel(co);
	}

	coalition_terminate_members_locked(co, td, true, co->co_signal);
	sx_xunlock(&co->co_sx);

	/*
	 * Re-acquire co_sx to collect members.
	 * COF_TERMINATING is set, so no new members will be added.
	 */
	sx_xlock(&co->co_sx);

	/*
	 * Collect members into cleanup/jail lists.
	 * Mark every member as removed (tqe_prev = NULL) so the
	 * exit handler won't double-remove/double-free.
	 * Remove procdesc members from hash (acquire/release
	 * hash_lock per-member to avoid lock order issues).
	 */
	cleanup_list = NULL;
	cleanup_tailp = &cleanup_list;
	jail_list = NULL;
	jail_tailp = &jail_list;

	TAILQ_FOREACH_SAFE(cm, &co->co_members, cm_link, cm_temp) {
		TAILQ_REMOVE(&co->co_members, cm, cm_link);
		cm->cm_link.tqe_prev = NULL;	/* sentinel for exit handler */

		if (cm->cm_dtype == DTYPE_PROCDESC) {
			rw_wlock(&coalition_proc_hash_lock);
			if (cm->cm_hash.le_prev != NULL)
				LIST_REMOVE(cm, cm_hash);
			rw_wunlock(&coalition_proc_hash_lock);
		}

		if (cm->cm_dtype == DTYPE_JAILDESC) {
			*jail_tailp = cm;
			jail_tailp = (struct coalition_member **)
			    &cm->cm_link.tqe_next;
			continue;
		}

		*cleanup_tailp = cm;
		cleanup_tailp = (struct coalition_member **)
		    &cm->cm_link.tqe_next;
	}
	*cleanup_tailp = NULL;
	*jail_tailp = NULL;

	sx_xunlock(&co->co_sx);

	/* Clean up non-jail members (no locks held) */
	for (cm = cleanup_list; cm != NULL; ) {
		struct coalition_member *next =
		    (struct coalition_member *)cm->cm_link.tqe_next;

		atomic_subtract_int(&co->co_member_count, 1);
		atomic_subtract_int(&coalition_total_members, 1);

		/*
		 * Revoke cap_rt members before dropping our file reference so
		 * coalition close preserves terminate semantics and nested
		 * coalition members tear themselves down before the last close.
		 */
		if (cm->cm_dtype == DTYPE_CAP_RT && cm->cm_fp != NULL) {
			struct cap_rt_instance *ci = cm->cm_fp->f_data;

			if (ci != NULL)
				cap_rt_instance_revoke(ci);
		}

		/* Release nested coalition ref */
		if (cm->cm_nested_co != NULL)
			coalition_rel(cm->cm_nested_co);

		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, td);

		uma_zfree(coalition_member_zone, cm);
		coalition_rel(co);
		cm = next;
	}

	/* Clean up jail members (no locks held) */
	for (cm = jail_list; cm != NULL; ) {
		struct coalition_member *next =
		    (struct coalition_member *)cm->cm_link.tqe_next;
		struct jaildesc *jd;
		struct prison *pr;
		struct coalition_jail_osd *cjo;

		if (cm->cm_fp != NULL && cm->cm_fp->f_data != NULL) {
			jd = cm->cm_fp->f_data;
			JAILDESC_LOCK(jd);
			pr = jd->jd_prison;
			if (pr != NULL && prison_isvalid(pr)) {
				prison_hold(pr);
				JAILDESC_UNLOCK(jd);
				prison_lock(pr);
				cjo = osd_jail_get(pr,
				    coalition_jail_osd_slot);
				if (cjo != NULL)
					cjo->cjo_member = NULL;
				prison_unlock(pr);
				prison_free(pr);
			} else {
				JAILDESC_UNLOCK(jd);
			}
		}

			if (cm->cm_fp != NULL)
				(void)coalition_jail_terminate(cm->cm_fp);

			if (cm->cm_data != NULL) {
				pr = cm->cm_data;
				cm->cm_data = NULL;
				prison_free(pr);
			}

			atomic_subtract_int(&co->co_member_count, 1);
			atomic_subtract_int(&coalition_total_members, 1);

		if (cm->cm_fp != NULL)
			fdrop(cm->cm_fp, td);

		uma_zfree(coalition_member_zone, cm);
		coalition_rel(co);
		cm = next;
	}

	coalition_rel(co);
}

/* ----------------------------------------------------------------
 * cap_rt service callbacks
 * ---------------------------------------------------------------- */

static volatile uint64_t coalition_next_badge = 1;

static int
coalition_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	u_int max, cur;

	max = coalition_max;
	if (max != 0) {
		cur = atomic_load_acq_int(&coalition_count);
		if (cur >= max)
			return (ENOMEM);
	}

	*badge_out = atomic_fetchadd_64(&coalition_next_badge, 1);
	return (0);
}

static int
coalition_init(struct cap_rt_instance *s, void *arg __unused)
{
	struct coalition *co;

	co = coalition_alloc();
	co->co_instance = s;
	cap_rt_instance_set_priv(s, co);

	SDT_PROBE1(cap_rt_coalition, , , create,
	    cap_rt_instance_get_badge(s));
	return (0);
}

static int
coalition_call(struct cap_rt_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	struct coalition *co;
	const struct coalition_req_hdr *hdr;
	struct coalition_reply *rpl;
	sbintime_t start __unused;
	uint32_t op __unused;
	int error;
	size_t reply_avail;

	start = getsbinuptime();
	op = 0;
	error = 0;
	co = cap_rt_instance_get_priv(s);
	if (co == NULL) {
		error = EBADF;
		goto out;
	}

	if (reqlen < sizeof(struct coalition_req_hdr)) {
		error = EINVAL;
		goto out;
	}
	hdr = req;
	op = hdr->op;

	/* All replies are at least coalition_reply sized */
	if (*replylenp < sizeof(struct coalition_reply)) {
		error = EMSGSIZE;
		goto out;
	}

	reply_avail = *replylenp;
	rpl = reply;
	rpl->status = 0;
	*replylenp = sizeof(struct coalition_reply);

	switch (hdr->op) {
	case COALITION_OP_ENLIST:
		if (nfds < 1) {
			rpl->status = EINVAL;
			break;
		}
		rpl->status = coalition_enlist(co, curthread, fds[0],
		    fcaps != NULL ? &fcaps[0] : NULL);
		break;

	case COALITION_OP_ENLIST_SET:
	{
		struct coalition_enlist_set_reply *esr;
		int i;

		if (reply_avail < sizeof(*esr)) {
			*replylenp = sizeof(*esr);
			error = EMSGSIZE;
			goto out;
		}
		esr = reply;
		esr->status = 0;
		esr->enlisted = 0;
		*replylenp = sizeof(*esr);

		for (i = 0; i < nfds; i++) {
			esr->status = coalition_enlist(co, curthread, fds[i],
			    fcaps != NULL ? &fcaps[i] : NULL);
			if (esr->status != 0)
				break;
			esr->enlisted++;
		}
		break;
	}

	case COALITION_OP_JOIN:
		rpl->status = coalition_join(co, curthread);
		break;

	case COALITION_OP_TERMINATE:
		rpl->status = coalition_terminate(co);
		break;

	case COALITION_OP_STAT:
	{
		struct coalition_stat_reply *sr;
		struct coalition_member *cm;

		if (reply_avail < sizeof(*sr)) {
			*replylenp = sizeof(*sr);
			error = EMSGSIZE;
			goto out;
		}
		sr = reply;
		*replylenp = sizeof(*sr);

		sx_slock(&co->co_sx);
		sr->status = 0;
		sr->member_count = co->co_member_count;
		sr->flags = co->co_flags;
		sr->signal = co->co_signal;
		sr->nesting_depth = co->co_nesting_depth;
		sr->nested_count = 0;
		sr->cap_rt_count = 0;
		sr->process_count = 0;
		sr->jail_count = 0;
		sr->other_count = 0;

		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype == DTYPE_PROCDESC)
				sr->process_count++;
			else if (cm->cm_dtype == DTYPE_JAILDESC)
				sr->jail_count++;
			else if (cm->cm_nested_co != NULL)
				sr->nested_count++;
			else if (cm->cm_dtype == DTYPE_CAP_RT)
				sr->cap_rt_count++;
			else
				sr->other_count++;
		}
		sx_sunlock(&co->co_sx);
		break;
	}

	case COALITION_OP_SET_SIGNAL:
	{
		const struct coalition_set_signal_req *ssr;

		if (reqlen < sizeof(*ssr)) {
			rpl->status = EINVAL;
			break;
		}
		ssr = req;
		if (ssr->signal <= 0 || ssr->signal >= NSIG) {
			rpl->status = EINVAL;
			break;
		}
		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}
		co->co_signal = ssr->signal;
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_GRACEFUL:
	{
		const struct coalition_graceful_req *gr;

		if (reqlen < sizeof(*gr)) {
			rpl->status = EINVAL;
			break;
		}
		gr = req;
		rpl->status = coalition_terminate_graceful(co,
		    gr->signal, gr->timeout_ms);
		break;
	}

	case COALITION_OP_SET_DEADLINE:
	{
		const struct coalition_set_deadline_req *dr;
		bool need_drain = false;

		if (reqlen < sizeof(*dr)) {
			rpl->status = EINVAL;
			break;
		}
		dr = req;
		if (dr->timeout_ms != 0 && dr->signal != 0 &&
		    (dr->signal < 0 || dr->signal >= NSIG)) {
			rpl->status = EINVAL;
			break;
		}

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		/* Cancel existing deadline */
		if (co->co_flags & COF_DEADLINE_ACTIVE)
			need_drain = coalition_deadline_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_deadline_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}

			if (dr->timeout_ms == 0) {
				sx_xunlock(&co->co_sx);
				rpl->status = 0;
				break;
			}

			co->co_deadline_signal = dr->signal;
			co->co_deadline_grace_ms = dr->grace_ms;
			co->co_flags |= COF_DEADLINE_ACTIVE;
			co->co_flags &= ~COF_DEADLINE_GRACE;
			coalition_ref(co);
		callout_reset(&co->co_deadline_callout,
		    coalition_timeout_ticks(dr->timeout_ms),
		    coalition_deadline_callout_fn, co);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_SET_WATCHDOG:
	{
		const struct coalition_set_watchdog_req *wr;
		bool need_drain = false;

		if (reqlen < sizeof(*wr)) {
			rpl->status = EINVAL;
			break;
		}
		wr = req;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		if (co->co_flags & COF_WATCHDOG_ACTIVE)
			need_drain = coalition_watchdog_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_watchdog_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}

		if (wr->timeout_ms == 0) {
			sx_xunlock(&co->co_sx);
			rpl->status = 0;
			break;
		}

		co->co_watchdog_timeout_ms = wr->timeout_ms;
		co->co_flags |= COF_WATCHDOG_ACTIVE;
		coalition_ref(co);
		callout_reset(&co->co_watchdog_callout,
		    coalition_timeout_ticks(wr->timeout_ms),
		    coalition_watchdog_callout_fn, co);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_HEARTBEAT:
	{
		bool need_drain = false;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}
		if (!(co->co_flags & COF_WATCHDOG_ACTIVE)) {
			sx_xunlock(&co->co_sx);
			rpl->status = EINVAL;
			break;
		}
		need_drain = coalition_watchdog_disarm_locked(co);
		if (need_drain) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_watchdog_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
		}
		co->co_flags |= COF_WATCHDOG_ACTIVE;
		coalition_ref(co);
		callout_reset(&co->co_watchdog_callout,
		    coalition_timeout_ticks(co->co_watchdog_timeout_ms),
		    coalition_watchdog_callout_fn, co);
		sx_xunlock(&co->co_sx);
		rpl->status = 0;
			break;
	}

	case COALITION_OP_SET_LEADER:
	{
		struct coalition_member *cm;
		bool had_cap_rt_leader = false;
		bool need_drain = false;
		bool new_cap_rt_leader = false;

		sx_xlock(&co->co_sx);
		if (co->co_flags & COF_TERMINATING) {
			sx_xunlock(&co->co_sx);
			rpl->status = ESHUTDOWN;
			break;
		}

		/* Check if old leader has a monitor */
		if ((co->co_flags & COF_HAS_LEADER) &&
		    co->co_leader != NULL &&
		    co->co_leader->cm_dtype == DTYPE_CAP_RT)
			had_cap_rt_leader = true;

		/* Clear leader if no fd passed */
		if (nfds == 0) {
			if (had_cap_rt_leader)
				(void)coalition_leader_monitor_stop_locked(co);
			co->co_leader = NULL;
			co->co_leader_pid = 0;
			co->co_flags &= ~COF_HAS_LEADER;
			sx_xunlock(&co->co_sx);
			rpl->status = 0;
			break;
		}

		/* Find the fd in member list */
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_fp == fds[0])
				break;
		}
		if (cm == NULL) {
			/* Old monitor untouched on failure */
			sx_xunlock(&co->co_sx);
			rpl->status = ESRCH;
			break;
		}

		/* Extract leader tracking info */
		if (cm->cm_dtype == DTYPE_PROCDESC) {
			struct procdesc *pd;
			struct proc *p;

			pd = cm->cm_fp->f_data;
			sx_slock(&proctree_lock);
			p = pd->pd_proc;
			if (p == NULL) {
				sx_sunlock(&proctree_lock);
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
			PROC_LOCK(p);
			if ((p->p_flag & P_WEXIT) != 0) {
				PROC_UNLOCK(p);
				sx_sunlock(&proctree_lock);
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
			co->co_leader_pid = p->p_pid;
			PROC_UNLOCK(p);
			sx_sunlock(&proctree_lock);
		} else if (cm->cm_dtype == DTYPE_JAILDESC) {
			co->co_leader_pid = 0;
		} else if (cm->cm_dtype == DTYPE_CAP_RT) {
			co->co_leader_pid = 0;
			new_cap_rt_leader = true;
		} else {
			sx_xunlock(&co->co_sx);
			rpl->status = EINVAL;
			break;
		}

		/* Validation passed — stop old monitor, set new leader */
		if (had_cap_rt_leader)
			need_drain = coalition_leader_monitor_stop_locked(co);
		if (need_drain && new_cap_rt_leader) {
			sx_xunlock(&co->co_sx);
			taskqueue_drain(taskqueue_thread,
			    &co->co_leader_task);
			sx_xlock(&co->co_sx);
			if (co->co_flags & COF_TERMINATING) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESHUTDOWN;
				break;
			}
			/*
			 * The validated member may have been removed while
			 * we waited for the old monitor task to finish.
			 */
			if (cm->cm_coalition != co || cm->cm_link.tqe_prev == NULL) {
				sx_xunlock(&co->co_sx);
				rpl->status = ESRCH;
				break;
			}
		}

		co->co_leader = cm;
		co->co_flags |= COF_HAS_LEADER;

		if (new_cap_rt_leader)
			coalition_leader_monitor_start_locked(co);

		sx_xunlock(&co->co_sx);
		rpl->status = 0;
		break;
	}

	case COALITION_OP_RUSAGE:
	{
		struct coalition_rusage_reply *rr;
		struct coalition_member *cm;
		struct proc *p;
		struct kinfo_proc kp;

		if (reply_avail < sizeof(*rr)) {
			*replylenp = sizeof(*rr);
			return (EMSGSIZE);
		}
		rr = reply;
		*replylenp = sizeof(*rr);
		memset(rr, 0, sizeof(*rr));

		sx_slock(&co->co_sx);
		TAILQ_FOREACH(cm, &co->co_members, cm_link) {
			if (cm->cm_dtype != DTYPE_PROCDESC)
				continue;

			p = NULL;
			if (cm->cm_fp != NULL) {
				struct procdesc *pd = cm->cm_fp->f_data;

				if (pd != NULL) {
					sx_slock(&proctree_lock);
					p = pd->pd_proc;
					if (p != NULL)
						PROC_LOCK(p);
					if (p == NULL) {
						sx_sunlock(&proctree_lock);
					}
				}
			} else if (cm->cm_data != NULL) {
				sx_slock(&proctree_lock);
				p = (struct proc *)atomic_load_acq_ptr(
				    (uintptr_t *)&cm->cm_data);
				if (p != NULL)
					PROC_LOCK(p);
				if (p == NULL)
					sx_sunlock(&proctree_lock);
			}
			if (p == NULL)
				continue;

			if (p->p_state == PRS_ZOMBIE ||
			    (p->p_flag & P_WEXIT)) {
				PROC_UNLOCK(p);
				sx_sunlock(&proctree_lock);
				continue;
			}
			fill_kinfo_proc(p, &kp);
			PROC_UNLOCK(p);
			sx_sunlock(&proctree_lock);

			rr->nprocs++;
			rr->nthreads += kp.ki_numthreads;
			rr->rss_bytes +=
			    (uint64_t)kp.ki_rssize * PAGE_SIZE;
			rr->vsz_bytes += kp.ki_size;
			rr->user_usec +=
			    (uint64_t)kp.ki_rusage.ru_utime.tv_sec *
			    1000000 + kp.ki_rusage.ru_utime.tv_usec;
			rr->sys_usec +=
			    (uint64_t)kp.ki_rusage.ru_stime.tv_sec *
			    1000000 + kp.ki_rusage.ru_stime.tv_usec;
			rr->inblock += kp.ki_rusage.ru_inblock;
			rr->oublock += kp.ki_rusage.ru_oublock;
			rr->majflt += kp.ki_rusage.ru_majflt;
			rr->minflt += kp.ki_rusage.ru_minflt;
		}
		sx_sunlock(&co->co_sx);
		break;
	}

	default:
		rpl->status = EINVAL;
		break;
	}

out:
	SDT_PROBE3(cap_rt_coalition, , , call__done, op, error,
	    getsbinuptime() - start);
	return (error);
}

static void
coalition_revoke(struct cap_rt_instance *s, uint64_t badge __unused,
    enum cap_rt_revoke_reason reason __unused, void *arg __unused)
{
	struct coalition *co;

	/*
	 * Clear priv under nest_lock so that concurrent nested
	 * enlist reads of ci_priv are serialized against us.
	 * A nested enlist that reads ci_priv before our clear
	 * will see a valid pointer and ref the coalition before
	 * we free it.  One that reads after will see NULL.
	 */
	sx_xlock(&coalition_nest_lock);
	co = cap_rt_instance_get_priv(s);
	if (co == NULL) {
		sx_xunlock(&coalition_nest_lock);
		return;
	}
	sx_xlock(&co->co_sx);
	coalition_notify_event(co, COALITION_NOTE_TERMINATED);
	co->co_instance = NULL;
	sx_xunlock(&co->co_sx);
	cap_rt_instance_set_priv(s, NULL);
	sx_xunlock(&coalition_nest_lock);

	coalition_close_internal(co, curthread);
}

/* ----------------------------------------------------------------
 * Module init / fini
 * ---------------------------------------------------------------- */

static const struct cap_rt_ops coalition_ops = {
	.co_connect	= coalition_connect,
	.co_init	= coalition_init,
	.co_call	= coalition_call,
	.co_revoke	= coalition_revoke,
};

static int
coalition_mod_init(void)
{
	struct cap_rt_service_params p;
	int error, i;

	coalition_zone = uma_zcreate("cap_rt_coalition",
	    sizeof(struct coalition), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	coalition_member_zone = uma_zcreate("cap_rt_co_member",
	    sizeof(struct coalition_member), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	rw_init(&coalition_proc_hash_lock, "coalition_proc_hash");
	sx_init(&coalition_nest_lock, "coalition_nest");
	for (i = 0; i < COALITION_PROC_HASH_SIZE; i++)
		LIST_INIT(&coalition_proc_hash[i]);

	coalition_jail_osd_slot = osd_jail_register(
	    coalition_jail_osd_dtor, NULL);
	if (coalition_jail_osd_slot == 0) {
		error = ENOMEM;
		goto fail_osd;
	}

	coalition_fork_tag = EVENTHANDLER_REGISTER(process_fork,
	    coalition_process_fork, NULL, EVENTHANDLER_PRI_ANY);
	if (coalition_fork_tag == NULL) {
		error = ENOMEM;
		goto fail_fork;
	}

	coalition_exit_tag = EVENTHANDLER_REGISTER(process_exit,
	    coalition_process_exit, NULL, EVENTHANDLER_PRI_ANY);
	if (coalition_exit_tag == NULL) {
		error = ENOMEM;
		goto fail_exit;
	}

	memset(&p, 0, sizeof(p));
	p.name = "coalition";
	p.ops = &coalition_ops;
	p.flags = CAP_RT_SVC_KQUEUE;

	error = cap_rt_service_create(&p, &coalition_svc);
	if (error != 0)
		goto fail_svc;

	log(LOG_INFO, "cap_rt_coalition: loaded\n");
	return (0);

fail_svc:
	EVENTHANDLER_DEREGISTER(process_exit, coalition_exit_tag);
fail_exit:
	EVENTHANDLER_DEREGISTER(process_fork, coalition_fork_tag);
fail_fork:
	osd_jail_deregister(coalition_jail_osd_slot);
fail_osd:
	sx_destroy(&coalition_nest_lock);
	rw_destroy(&coalition_proc_hash_lock);
	uma_zdestroy(coalition_member_zone);
	uma_zdestroy(coalition_zone);
	return (error);
}

static int
coalition_modevent(module_t mod __unused, int type, void *arg __unused)
{

	switch (type) {
	case MOD_LOAD:
		return (coalition_mod_init());

	case MOD_UNLOAD:
		if (atomic_load_acq_int(&coalition_count) != 0) {
			log(LOG_WARNING,
			    "cap_rt_coalition: cannot unload, "
			    "%u active coalitions\n",
			    atomic_load_acq_int(&coalition_count));
			return (EBUSY);
		}

		cap_rt_service_destroy(coalition_svc);
		EVENTHANDLER_DEREGISTER(process_exit, coalition_exit_tag);
		EVENTHANDLER_DEREGISTER(process_fork, coalition_fork_tag);
		osd_jail_deregister(coalition_jail_osd_slot);
		sx_destroy(&coalition_nest_lock);
		rw_destroy(&coalition_proc_hash_lock);
		uma_zdestroy(coalition_member_zone);
		uma_zdestroy(coalition_zone);

		log(LOG_INFO, "cap_rt_coalition: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_coalition_mod = {
	"cap_rt_coalition",
	coalition_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_coalition, cap_rt_coalition_mod,
    SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cap_rt_coalition, 1);
MODULE_DEPEND(cap_rt_coalition, cap_rt, 1, 1, 1);
