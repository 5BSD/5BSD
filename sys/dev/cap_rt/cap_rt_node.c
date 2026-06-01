/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_node — capability service for process observation and control.
 *
 * Provides get/set operations on a process via CAP_RT_CALL with an
 * attached procdesc fd.  If no fd is attached, operates on the caller.
 *
 * This is a sync-only (co_call) service.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/cpuset.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/procctl.h>
#include <sys/racct.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/rtprio.h>
#include <sys/sched.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sdt.h>
#include <sys/ucred.h>

#include <vm/uma.h>

#include "cap_rt.h"
#include "cap_rt_label.h"
#include "cap_rt_node_proto.h"

SDT_PROVIDER_DEFINE(cap_rt_node);
SDT_PROBE_DEFINE6(cap_rt_node, , , call__done,
    "uint32_t", "pid_t", "pid_t", "uint32_t", "int", "sbintime_t");
SDT_PROBE_DEFINE3(cap_rt_node, , , deny,
    "const char *", "pid_t", "pid_t");

extern struct sx proctree_lock;

#define	NODE_REPLY_INIT(rp, replylenp) do {			\
	if (*(replylenp) < sizeof(*(rp)))			\
		return (EINVAL);				\
	*(replylenp) = sizeof(*(rp));				\
	memset((rp), 0, sizeof(*(rp)));				\
} while (0)

/* Verify wire-protocol constants match kernel definitions. */
_Static_assert(NODE_RTPRIO_REALTIME == RTP_PRIO_REALTIME,
    "NODE_RTPRIO_REALTIME != RTP_PRIO_REALTIME");
_Static_assert(NODE_RTPRIO_NORMAL == RTP_PRIO_NORMAL,
    "NODE_RTPRIO_NORMAL != RTP_PRIO_NORMAL");
_Static_assert(NODE_RTPRIO_IDLE == RTP_PRIO_IDLE,
    "NODE_RTPRIO_IDLE != RTP_PRIO_IDLE");
_Static_assert(NODE_RTPRIO_FIFO == RTP_PRIO_FIFO,
    "NODE_RTPRIO_FIFO != RTP_PRIO_FIFO");

static int
node_op_stat(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_stat_reply *rp = reply;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	rp->status = NODE_STATUS_OK;
	rp->pid = p->p_pid;
	rp->state = p->p_state;
	rp->numthreads = p->p_numthreads;
	rp->flags = p->p_flag & (P_TRACED | P_JAILED | P_WEXIT |
	    P_STOPPED_SIG | P_STOPPED_SINGLE);
	strlcpy(rp->name, p->p_comm, sizeof(rp->name));

	return (0);
}

static int
node_op_cred(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_cred_reply *rp = reply;
	struct ucred *cr;
	int i, ng;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	cr = p->p_ucred;
	rp->status = NODE_STATUS_OK;
	rp->uid = cr->cr_uid;
	rp->gid = cr->cr_gid;
	rp->ruid = cr->cr_ruid;
	rp->rgid = cr->cr_rgid;
	rp->prison_id = cr->cr_prison->pr_id;
	rp->nonce = cap_rt_proc_nonce(cr);

	ng = cr->cr_ngroups;
	if (ng > NODE_MAXGROUPS)
		ng = NODE_MAXGROUPS;
	rp->ngroups = ng;
	for (i = 0; i < ng; i++)
		rp->groups[i] = cr->cr_groups[i];

	return (0);
}

static int
node_op_rusage(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_rusage_reply *rp = reply;
	struct rusage ru;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	PROC_STATLOCK(p);
	rufetch(p, &ru);
	PROC_STATUNLOCK(p);

	rp->status = NODE_STATUS_OK;
	rp->utime_usec = (int64_t)ru.ru_utime.tv_sec * 1000000 +
	    ru.ru_utime.tv_usec;
	rp->stime_usec = (int64_t)ru.ru_stime.tv_sec * 1000000 +
	    ru.ru_stime.tv_usec;
	rp->maxrss = ru.ru_maxrss;
	rp->nvcsw = ru.ru_nvcsw;
	rp->nivcsw = ru.ru_nivcsw;
	rp->inblock = ru.ru_inblock;
	rp->oublock = ru.ru_oublock;

	return (0);
}

static int
node_op_get_rlimit(struct proc *p, uint32_t resource,
    void *reply, size_t *replylenp)
{
	struct node_rlimit_reply *rp = reply;
	struct rlimit rl;

	NODE_REPLY_INIT(rp, replylenp);

	if (resource >= RLIM_NLIMITS)
		return (EINVAL);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	lim_rlimit_proc(p, resource, &rl);

	rp->status = NODE_STATUS_OK;
	rp->resource = resource;
	rp->rlim_cur = rl.rlim_cur;
	rp->rlim_max = rl.rlim_max;

	return (0);
}

static int
node_op_set_rlimit(struct thread *td, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_rlimit_set *rs = req;
	struct node_rlimit_reply *rp = reply;
	struct rlimit rl;
	int error;

	if (reqlen < sizeof(*rs) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	if (rs->resource >= RLIM_NLIMITS)
		return (EINVAL);

	rl.rlim_cur = rs->rlim_cur;
	rl.rlim_max = rs->rlim_max;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (p->p_flag & P_WEXIT) {
		memset(rp, 0, sizeof(*rp));
		rp->status = NODE_STATUS_DEAD;
		rp->resource = rs->resource;
		*replylenp = sizeof(*rp);
		return (0);
	}
	_PHOLD(p);
	PROC_UNLOCK(p);

	error = kern_proc_setrlimit(td, p, rs->resource, &rl);

	PROC_LOCK(p);
	_PRELE(p);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		lim_rlimit_proc(p, rs->resource, &rl);
		rp->rlim_cur = rl.rlim_cur;
		rp->rlim_max = rl.rlim_max;
	} else {
		rp->status = NODE_STATUS_EPERM;
		SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"set-rlimit",
		    p->p_pid, curthread->td_proc->p_pid);
	}
	rp->resource = rs->resource;

	return (0);
}

static int
node_op_get_racct(struct proc *p, uint32_t resource,
    void *reply, size_t *replylenp)
{
	struct node_racct_reply *rp = reply;

	NODE_REPLY_INIT(rp, replylenp);

	if (resource > RACCT_MAX)
		return (EINVAL);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	rp->resource = resource;

#ifdef RACCT
	if (p->p_racct != NULL) {
		RACCT_LOCK();
		rp->usage = p->p_racct->r_resources[resource];
		RACCT_UNLOCK();
	}
	rp->limit = racct_get_limit(p, resource);
	rp->available = racct_get_available(p, resource);
	rp->status = NODE_STATUS_OK;
#else
	rp->status = NODE_STATUS_ERR;
#endif

	return (0);
}

static int
node_op_get_nice(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_nice_reply *rp = reply;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	rp->status = NODE_STATUS_OK;
	rp->nice = p->p_nice - NZERO;

	return (0);
}

static int
node_op_set_nice(struct thread *td __unused, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_nice_set *ns = req;
	struct node_nice_reply *rp = reply;
	int n;

	if (reqlen < sizeof(*ns) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	n = ns->nice;
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	sched_nice(p, n);

	memset(rp, 0, sizeof(*rp));
	rp->status = NODE_STATUS_OK;
	rp->nice = p->p_nice - NZERO;

	return (0);
}

static int
node_op_get_rtprio(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_rtprio_reply *rp = reply;
	struct rtprio rtp;
	struct thread *ttd;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	ttd = FIRST_THREAD_IN_PROC(p);
	if (ttd == NULL) {
		rp->status = NODE_STATUS_DEAD;
		return (0);
	}

	pri_to_rtp(ttd, &rtp);
	rp->status = NODE_STATUS_OK;
	rp->type = rtp.type;
	rp->prio = rtp.prio;

	return (0);
}

/*
 * Respect the same sysctl that kern_rtprio uses.
 */
static int
node_op_set_rtprio(struct thread *td __unused, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_rtprio_set *rs = req;
	struct node_rtprio_reply *rp = reply;
	struct rtprio rtp;
	struct thread *ttd;
	int error;

	if (reqlen < sizeof(*rs) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	switch (RTP_PRIO_BASE(rs->type)) {
	case RTP_PRIO_REALTIME:
	case RTP_PRIO_IDLE:
	case RTP_PRIO_NORMAL:
		break;
	default:
		return (EINVAL);
	}

	ttd = FIRST_THREAD_IN_PROC(p);
	if (ttd == NULL) {
		memset(rp, 0, sizeof(*rp));
		rp->status = NODE_STATUS_DEAD;
		return (0);
	}

	rtp.type = rs->type;
	rtp.prio = rs->prio;
	error = rtp_to_pri(&rtp, ttd);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		pri_to_rtp(ttd, &rtp);
		rp->status = NODE_STATUS_OK;
		rp->type = rtp.type;
		rp->prio = rtp.prio;
	} else {
		rp->status = NODE_STATUS_ERR;
	}

	return (0);
}

static int
node_op_get_pdeathsig(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_pdeathsig_reply *rp = reply;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	rp->status = NODE_STATUS_OK;
	rp->signal = p->p_pdeathsig;

	return (0);
}

static int
node_op_set_pdeathsig(struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_pdeathsig_set *ps = req;
	struct node_pdeathsig_reply *rp = reply;

	if (reqlen < sizeof(*ps) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	memset(rp, 0, sizeof(*rp));

	/*
	 * Unlike the kernel's pdeathsig_ctl (self-only), we allow
	 * remote targeting via procdesc.  The signal fires when the
	 * target's actual parent exits — typically the pdfork caller.
	 */
	if (ps->signal != 0 && !_SIG_VALID(ps->signal)) {
		rp->status = NODE_STATUS_ERR;
		return (0);
	}

	p->p_pdeathsig = ps->signal;
	rp->status = NODE_STATUS_OK;
	rp->signal = ps->signal;

	return (0);
}

static int
node_op_reap(struct thread *td, struct proc *p, int cmd,
    void *reply, size_t *replylenp)
{
	struct node_status_reply *rp = reply;
	int error;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (p != td->td_proc) {
		rp->status = NODE_STATUS_EPERM;
		return (0);
	}

	if (cmd == PROC_REAP_ACQUIRE && (p->p_flag & P_WEXIT)) {
		rp->status = NODE_STATUS_DEAD;
		return (0);
	}

	_PHOLD(p);
	PROC_UNLOCK(p);
	sx_xlock(&proctree_lock);
	PROC_LOCK(p);

	error = kern_procctl_single(td, p, cmd, NULL);

	sx_xunlock(&proctree_lock);
	_PRELE(p);

	rp->status = (error == 0) ? NODE_STATUS_OK : NODE_STATUS_ERR;
	if (rp->status != NODE_STATUS_OK)
		SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"reap",
		    p->p_pid, curthread->td_proc->p_pid);

	return (0);
}

static int
node_op_reap_status(struct thread *td, struct proc *p,
    void *reply, size_t *replylenp)
{
	struct node_reap_status_reply *rp = reply;
	struct procctl_reaper_status rs;
	int error;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	_PHOLD(p);
	PROC_UNLOCK(p);
	sx_slock(&proctree_lock);
	PROC_LOCK(p);

	error = kern_procctl_single(td, p, PROC_REAP_STATUS, &rs);

	sx_sunlock(&proctree_lock);
	_PRELE(p);
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->rs_flags = rs.rs_flags;
		rp->rs_children = rs.rs_children;
		rp->rs_descendants = rs.rs_descendants;
		rp->rs_reaper = rs.rs_reaper;
		rp->rs_pid = rs.rs_pid;
	} else {
		rp->status = NODE_STATUS_ERR;
	}

	return (0);
}

static int
node_op_reap_kill(struct thread *td, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_reap_kill_req *kr = req;
	struct node_reap_kill_reply *rp = reply;
	struct procctl_reaper_kill rk;
	int error;

	if (reqlen < sizeof(*kr) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (p != td->td_proc) {
		memset(rp, 0, sizeof(*rp));
		rp->status = NODE_STATUS_EPERM;
		return (0);
	}

	memset(&rk, 0, sizeof(rk));
	rk.rk_sig = kr->rk_sig;
	rk.rk_flags = kr->rk_flags;
	rk.rk_subtree = kr->rk_subtree;

	_PHOLD(p);
	PROC_UNLOCK(p);
	sx_slock(&proctree_lock);
	PROC_LOCK(p);

	error = kern_procctl_single(td, p, PROC_REAP_KILL, &rk);

	sx_sunlock(&proctree_lock);
	_PRELE(p);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->rk_killed = rk.rk_killed;
		rp->rk_fpid = rk.rk_fpid;
	} else {
		rp->status = (error == EPERM) ?
		    NODE_STATUS_EPERM : NODE_STATUS_ERR;
	}

	return (0);
}

static int
node_op_get_affinity(struct proc *p,
    void *reply, size_t *replylenp)
{
	struct node_affinity_reply *rp = reply;
	struct thread *ttd;
	cpuset_t mask;
	size_t sz;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	/*
	 * Build the process affinity as the union of all thread masks,
	 * matching kern_cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID).
	 * No PID lookup needed — we already hold the proc handle.
	 */
	CPU_ZERO(&mask);
	FOREACH_THREAD_IN_PROC(p, ttd) {
		thread_lock(ttd);
		CPU_OR(&mask, &mask, &ttd->td_cpuset->cs_mask);
		thread_unlock(ttd);
	}

	rp->status = NODE_STATUS_OK;
	sz = sizeof(cpuset_t);
	if (sz > NODE_CPUSET_MAXSIZE)
		sz = NODE_CPUSET_MAXSIZE;
	rp->size = sz;
	memcpy(rp->mask, &mask, sz);

	return (0);
}

static int
node_op_set_affinity(struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_affinity_set *as = req;
	struct node_affinity_reply *rp = reply;
	cpuset_t mask;
	int error;
	size_t sz;

	if (reqlen < sizeof(*as) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	sz = as->size;
	if (sz == 0 || sz > sizeof(cpuset_t))
		return (EINVAL);

	CPU_ZERO(&mask);
	memcpy(&mask, as->mask, sz);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (p->p_flag & P_WEXIT) {
		memset(rp, 0, sizeof(*rp));
		rp->status = NODE_STATUS_DEAD;
		*replylenp = sizeof(*rp);
		return (0);
	}

	/*
	 * cpuset_setproc_mask requires PROC_LOCK at entry but
	 * releases and reacquires it internally as needed.
	 * _PHOLD keeps the proc struct alive across unlock windows.
	 */
	_PHOLD(p);
	error = cpuset_setproc_mask(p, &mask);
	_PRELE(p);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->size = sz;
		memcpy(rp->mask, &mask, sz);
	} else {
		rp->status = NODE_STATUS_ERR;
		SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"set-affinity",
		    p->p_pid, curthread->td_proc->p_pid);
	}

	return (0);
}

/*
 * Procctl wrapper that provides the same locking contract as
 * kern_procctl(), but operates on a struct proc * directly
 * instead of looking up by PID.  Authority is in the node fd;
 * no DAC checks.
 */
static int
node_do_procctl(struct thread *td, struct proc *p, int com, void *data)
{
	int error;
	bool need_slock;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	/*
	 * Determine locking requirements from the command table.
	 * Authority comes from holding the node capability fd —
	 * no DAC/candebug checks.
	 */
	need_slock = false;
	switch (com) {
	case PROC_SPROTECT:
	case PROC_TRACE_CTL:
	case PROC_TRAPCAP_CTL:
	case PROC_NO_NEW_PRIVS_CTL:
	case PROC_LOGSIGEXIT_CTL:
		need_slock = true;
		break;
	default:
		break;
	}

	if (need_slock) {
		if (p->p_flag & P_WEXIT)
			return (ESRCH);
		_PHOLD(p);
		PROC_UNLOCK(p);
		sx_slock(&proctree_lock);
		PROC_LOCK(p);
	}

	error = kern_procctl_single(td, p, com, data);

	if (need_slock) {
		sx_sunlock(&proctree_lock);
		_PRELE(p);
	}

	return (error);
}

static int
node_op_get_procctl(struct thread *td, struct proc *p,
    uint32_t com, void *reply, size_t *replylenp)
{
	struct node_procctl_reply *rp = reply;
	int val, error;

	NODE_REPLY_INIT(rp, replylenp);

	/* Only allow status-query commands. */
	switch (com) {
	case PROC_TRACE_STATUS:
	case PROC_TRAPCAP_STATUS:
	case PROC_PDEATHSIG_STATUS:
	case PROC_ASLR_STATUS:
	case PROC_PROTMAX_STATUS:
	case PROC_STACKGAP_STATUS:
	case PROC_NO_NEW_PRIVS_STATUS:
	case PROC_WXMAP_STATUS:
	case PROC_LOGSIGEXIT_STATUS:
		break;
	default:
		return (EINVAL);
	}

	PROC_LOCK_ASSERT(p, MA_OWNED);

	val = 0;
	error = node_do_procctl(td, p, com, &val);

	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->com = com;
		rp->val = val;
	} else {
		rp->status = (error == EPERM) ?
		    NODE_STATUS_EPERM : NODE_STATUS_ERR;
	}

	return (0);
}

static int
node_op_set_procctl(struct thread *td, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_procctl_set *ps = req;
	struct node_procctl_reply *rp = reply;
	int val, error;

	if (reqlen < sizeof(*ps) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	/* Only allow safe set commands. */
	switch (ps->com) {
	case PROC_SPROTECT:
	case PROC_TRACE_CTL:
	case PROC_TRAPCAP_CTL:
	case PROC_PDEATHSIG_CTL:
	case PROC_ASLR_CTL:
	case PROC_PROTMAX_CTL:
	case PROC_STACKGAP_CTL:
	case PROC_NO_NEW_PRIVS_CTL:
	case PROC_WXMAP_CTL:
	case PROC_LOGSIGEXIT_CTL:
		break;
	default:
		return (EINVAL);
	}

	PROC_LOCK_ASSERT(p, MA_OWNED);

	val = ps->val;
	error = node_do_procctl(td, p, ps->com, &val);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->com = ps->com;
		rp->val = val;
	} else {
		rp->status = (error == EPERM) ?
		    NODE_STATUS_EPERM : NODE_STATUS_ERR;
	}

	return (0);
}

static int
node_op_set_cred(struct thread *td, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_cred_set *cs = req;
	struct node_cred_reply *rp = reply;
	struct setcred wcred;
	gid_t groups[NODE_CRED_MAXGROUPS];
	u_int flags;
	int error, ng;

	if (reqlen < sizeof(*cs) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	if (cs->flags == 0 || (cs->flags & ~(NODE_CREDF_UID |
	    NODE_CREDF_RUID | NODE_CREDF_SVUID | NODE_CREDF_GID |
	    NODE_CREDF_RGID | NODE_CREDF_SVGID | NODE_CREDF_GROUPS)) != 0)
		return (EINVAL);

	/* Map node flags to setcred flags. */
	flags = 0;
	wcred = (struct setcred)SETCRED_INITIALIZER;
	if (cs->flags & NODE_CREDF_UID) {
		flags |= SETCREDF_UID;
		wcred.sc_uid = cs->uid;
	}
	if (cs->flags & NODE_CREDF_RUID) {
		flags |= SETCREDF_RUID;
		wcred.sc_ruid = cs->ruid;
	}
	if (cs->flags & NODE_CREDF_SVUID) {
		flags |= SETCREDF_SVUID;
		wcred.sc_svuid = cs->svuid;
	}
	if (cs->flags & NODE_CREDF_GID) {
		flags |= SETCREDF_GID;
		wcred.sc_gid = cs->gid;
	}
	if (cs->flags & NODE_CREDF_RGID) {
		flags |= SETCREDF_RGID;
		wcred.sc_rgid = cs->rgid;
	}
	if (cs->flags & NODE_CREDF_SVGID) {
		flags |= SETCREDF_SVGID;
		wcred.sc_svgid = cs->svgid;
	}
	if (cs->flags & NODE_CREDF_GROUPS) {
		flags |= SETCREDF_SUPP_GROUPS;
		ng = cs->ngroups;
		if (ng > NODE_CRED_MAXGROUPS)
			return (EINVAL);
		memcpy(groups, cs->groups, ng * sizeof(gid_t));
		wcred.sc_supp_groups_nb = ng;
		wcred.sc_supp_groups = groups;
	}

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (p->p_flag & P_WEXIT) {
		memset(rp, 0, sizeof(*rp));
		rp->status = NODE_STATUS_DEAD;
		return (0);
	}

	/*
	 * kern_setcred_proc acquires PROC_LOCK internally.
	 * Release ours first; hold proc with _PHOLD.
	 */
	_PHOLD(p);
	PROC_UNLOCK(p);

	error = kern_setcred_proc(td, p, flags, &wcred);

	PROC_LOCK(p);
	_PRELE(p);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		struct ucred *cr = p->p_ucred;

		rp->status = NODE_STATUS_OK;
		rp->uid = cr->cr_uid;
		rp->gid = cr->cr_gid;
		rp->ruid = cr->cr_ruid;
		rp->rgid = cr->cr_rgid;
		rp->nonce = cap_rt_proc_nonce(cr);
	} else {
		rp->status = (error == EPERM || error == EACCES) ?
		    NODE_STATUS_EPERM : NODE_STATUS_ERR;
		if (rp->status == NODE_STATUS_EPERM)
			SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"set-cred",
			    p->p_pid, curthread->td_proc->p_pid);
	}

	return (0);
}

/*
 * SET_SESSION and SET_PGRP are self-only operations (enforced in the
 * dispatch).  They mirror sys_setsid() and sys_setpgid() exactly,
 * including the ERESTART retry loop and lock ordering.
 *
 * These must release PROC_LOCK before acquiring proctree_lock
 * (lock ordering: proctree_lock before PROC_LOCK).
 */
static int
node_op_set_session(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_session_reply *rp = reply;
	struct pgrp *pgrp, *newpgrp;
	struct session *newsess;
	int error;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	PROC_UNLOCK(p);

	/* Mirrors sys_setsid() exactly. */
	newpgrp = uma_zalloc(pgrp_zone, M_WAITOK);
	newsess = malloc(sizeof(*newsess), M_SESSION, M_WAITOK | M_ZERO);

again_sess:
	error = 0;
	sx_xlock(&proctree_lock);

	if (p->p_pgid == p->p_pid ||
	    (pgrp = pgfind(p->p_pid)) != NULL) {
		if (pgrp != NULL)
			PGRP_UNLOCK(pgrp);
		error = EPERM;
	} else {
		error = enterpgrp(p, p->p_pid, newpgrp, newsess);
		if (error == ERESTART)
			goto again_sess;
		MPASS(error == 0);
		newpgrp = NULL;
		newsess = NULL;
	}

	sx_xunlock(&proctree_lock);

	uma_zfree(pgrp_zone, newpgrp);
	free(newsess, M_SESSION);

	PROC_LOCK(p);

	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->sid = p->p_pid;
		rp->pgid = p->p_pid;
	} else {
		rp->status = NODE_STATUS_EPERM;
		SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"set-session",
		    p->p_pid, curthread->td_proc->p_pid);
	}

	return (0);
}

static int
node_op_set_pgrp(struct proc *p, const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_pgrp_set *ps = req;
	struct node_session_reply *rp = reply;
	struct pgrp *newpgrp, *pgrp;
	pid_t pgid;
	int error;

	if (reqlen < sizeof(*ps) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	pgid = ps->pgid;
	if (pgid == 0)
		pgid = p->p_pid;
	if (pgid < 0)
		return (EINVAL);

	PROC_UNLOCK(p);

	/* Mirrors sys_setpgid() exactly. */
	newpgrp = uma_zalloc(pgrp_zone, M_WAITOK);

again_pgrp:
	error = 0;
	sx_xlock(&proctree_lock);

	if (SESS_LEADER(p)) {
		error = EPERM;
	} else if ((pgrp = pgfind(pgid)) == NULL) {
		if (pgid == p->p_pid) {
			error = enterpgrp(p, pgid, newpgrp, NULL);
			if (error == ERESTART)
				goto again_pgrp;
			if (error == 0)
				newpgrp = NULL;
		} else {
			error = EPERM;
		}
	} else {
		if (pgrp == p->p_pgrp) {
			PGRP_UNLOCK(pgrp);
		} else if (pgrp->pg_session != p->p_session) {
			PGRP_UNLOCK(pgrp);
			error = EPERM;
		} else {
			PGRP_UNLOCK(pgrp);
			error = enterthispgrp(p, pgrp);
			if (error == ERESTART)
				goto again_pgrp;
		}
	}

	sx_xunlock(&proctree_lock);
	uma_zfree(pgrp_zone, newpgrp);

	PROC_LOCK(p);

	memset(rp, 0, sizeof(*rp));
	if (error == 0) {
		rp->status = NODE_STATUS_OK;
		rp->pgid = p->p_pgid;
	} else {
		rp->status = NODE_STATUS_EPERM;
		SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"set-pgrp",
		    p->p_pid, curthread->td_proc->p_pid);
	}

	return (0);
}

static int
node_op_get_umask(struct proc *p, void *reply, size_t *replylenp)
{
	struct node_umask_reply *rp = reply;
	struct pwddesc *pdp;

	NODE_REPLY_INIT(rp, replylenp);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	pdp = p->p_pd;

	PWDDESC_XLOCK(pdp);
	rp->mask = pdp->pd_cmask;
	PWDDESC_XUNLOCK(pdp);
	rp->status = NODE_STATUS_OK;

	return (0);
}

static int
node_op_set_umask(struct proc *p, const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_umask_set *us = req;
	struct node_umask_reply *rp = reply;
	struct pwddesc *pdp;

	if (reqlen < sizeof(*us) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	pdp = p->p_pd;

	memset(rp, 0, sizeof(*rp));
	PWDDESC_XLOCK(pdp);
	rp->mask = pdp->pd_cmask;
	pdp->pd_cmask = us->mask & ALLPERMS;
	PWDDESC_XUNLOCK(pdp);
	rp->status = NODE_STATUS_OK;

	return (0);
}

static int
node_op_set_login(struct thread *td __unused, struct proc *p,
    const void *req, size_t reqlen,
    void *reply, size_t *replylenp)
{
	const struct node_login_set *ls = req;
	struct node_login_reply *rp = reply;
	char logintmp[NODE_MAXLOGNAME];

	if (reqlen < sizeof(*ls) || *replylenp < sizeof(*rp))
		return (EINVAL);
	*replylenp = sizeof(*rp);

	PROC_LOCK_ASSERT(p, MA_OWNED);

	/*
	 * Force null-termination of the wire name before using it.
	 * ls->name is a fixed-size char array from untrusted input;
	 * if all bytes are non-NUL, strlcpy would scan past the buffer.
	 */
	memcpy(logintmp, ls->name, sizeof(logintmp));
	logintmp[sizeof(logintmp) - 1] = '\0';

	memset(rp, 0, sizeof(*rp));
	SESS_LOCK(p->p_session);
	strlcpy(p->p_session->s_login, logintmp,
	    sizeof(p->p_session->s_login));
	strlcpy(rp->name, p->p_session->s_login, sizeof(rp->name));
	SESS_UNLOCK(p->p_session);
	rp->status = NODE_STATUS_OK;

	return (0);
}

static int
node_call(struct cap_rt_instance *s __unused,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct node_request *nr;
	struct proc *p;
	sbintime_t start;
	pid_t target_pid;
	int error;

	start = getsbinuptime();

	if (reqlen < sizeof(*nr))
		return (EINVAL);

	nr = (const struct node_request *)req;

	/*
	 * No Capsicum rights check on the attached procdesc.
	 * Authority comes from holding the node service fd, not from
	 * the procdesc rights.  The procdesc is an opaque target
	 * identifier.  Narrow what the caller can do by narrowing
	 * the service fd (CAP_CAP_RT_SEND/RECV, revoke operations).
	 */
	error = cap_rt_resolve_proc(fds, nfds, &p);
	if (error == ESRCH) {
		if (*replylenp >= sizeof(uint32_t)) {
			*(uint32_t *)reply = NODE_STATUS_DEAD;
			*replylenp = sizeof(uint32_t);
			SDT_PROBE3(cap_rt_node, , , deny, (uintptr_t)"resolve-proc",
			    0, curthread->td_proc->p_pid);
			SDT_PROBE6(cap_rt_node, , , call__done, nr->op,
			    0, curthread->td_proc->p_pid, NODE_STATUS_DEAD,
			    0, getsbinuptime() - start);
			return (0);
		}
		SDT_PROBE6(cap_rt_node, , , call__done, nr->op, 0,
		    curthread->td_proc->p_pid, 0, error,
		    getsbinuptime() - start);
		return (error);
	}
	if (error != 0) {
		SDT_PROBE6(cap_rt_node, , , call__done, nr->op, 0,
		    curthread->td_proc->p_pid, 0, error,
		    getsbinuptime() - start);
		return (error);
	}

	target_pid = p->p_pid;

	/* p is PROC_LOCKed from here. */
	switch (nr->op) {
	case NODE_OP_STAT:
		error = node_op_stat(p, reply, replylenp);
		break;
	case NODE_OP_CRED:
		error = node_op_cred(p, reply, replylenp);
		break;
	case NODE_OP_RUSAGE:
		error = node_op_rusage(p, reply, replylenp);
		break;
	case NODE_OP_GET_RLIMIT:
		error = node_op_get_rlimit(p, nr->resource, reply, replylenp);
		break;
	case NODE_OP_SET_RLIMIT:
		error = node_op_set_rlimit(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_GET_RACCT:
		error = node_op_get_racct(p, nr->resource, reply, replylenp);
		break;
	case NODE_OP_GET_NICE:
		error = node_op_get_nice(p, reply, replylenp);
		break;
	case NODE_OP_SET_NICE:
		error = node_op_set_nice(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_GET_AFFINITY:
		error = node_op_get_affinity(p, reply, replylenp);
		break;
	case NODE_OP_SET_AFFINITY:
		error = node_op_set_affinity(p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_GET_PROCCTL:
		error = node_op_get_procctl(curthread, p, nr->resource,
		    reply, replylenp);
		break;
	case NODE_OP_SET_PROCCTL:
		error = node_op_set_procctl(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_SET_CRED:
		error = node_op_set_cred(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_SET_SESSION:
	case NODE_OP_SET_PGRP:
		/*
		 * setsid/setpgid require the target process's own thread
		 * context (enterpgrp asserts p == curproc for session
		 * creation).  These cannot be done remotely — the child
		 * must call them itself.  Return EOPNOTSUPP for remote
		 * targets; allow self-targeting.
		 */
		if (p != curthread->td_proc) {
			error = EOPNOTSUPP;
		} else if (nr->op == NODE_OP_SET_SESSION) {
			error = node_op_set_session(p, reply, replylenp);
		} else {
			error = node_op_set_pgrp(p, req, reqlen,
			    reply, replylenp);
		}
		break;
	case NODE_OP_GET_UMASK:
		error = node_op_get_umask(p, reply, replylenp);
		break;
	case NODE_OP_SET_UMASK:
		error = node_op_set_umask(p, req, reqlen, reply, replylenp);
		break;
	case NODE_OP_SET_LOGIN:
		error = node_op_set_login(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_GET_RTPRIO:
		error = node_op_get_rtprio(p, reply, replylenp);
		break;
	case NODE_OP_SET_RTPRIO:
		error = node_op_set_rtprio(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	/* Confinement operations */
	case NODE_OP_GET_PDEATHSIG:
		error = node_op_get_pdeathsig(p, reply, replylenp);
		break;
	case NODE_OP_SET_PDEATHSIG:
		error = node_op_set_pdeathsig(p, req, reqlen,
		    reply, replylenp);
		break;
	case NODE_OP_REAP_ACQUIRE:
		error = node_op_reap(curthread, p, PROC_REAP_ACQUIRE,
		    reply, replylenp);
		break;
	case NODE_OP_REAP_RELEASE:
		error = node_op_reap(curthread, p, PROC_REAP_RELEASE,
		    reply, replylenp);
		break;
	case NODE_OP_REAP_STATUS:
		error = node_op_reap_status(curthread, p, reply, replylenp);
		break;
	case NODE_OP_REAP_KILL:
		error = node_op_reap_kill(curthread, p, req, reqlen,
		    reply, replylenp);
		break;
	default:
		error = EINVAL;
		break;
	}

	PROC_UNLOCK(p);
	_PRELE(p);
	SDT_PROBE6(cap_rt_node, , , call__done, nr->op, target_pid,
	    curthread->td_proc->p_pid,
	    (error == 0 && *replylenp >= sizeof(uint32_t)) ?
	    *(const uint32_t *)reply : 0,
	    error, getsbinuptime() - start);
	return (error);
}

static struct cap_rt_ops node_ops = {
	.co_call = node_call,
};

static struct cap_rt_service *node_svc;

static int
cap_rt_node_modevent(module_t mod __unused, int type, void *data __unused)
{
	struct cap_rt_service_params params;
	int error;

	switch (type) {
	case MOD_LOAD:
		memset(&params, 0, sizeof(params));
		params.name = "node";
		params.ops = &node_ops;
		error = cap_rt_service_create(&params, &node_svc);
		if (error != 0)
			printf("cap_rt_node: create failed: %d\n", error);
		return (error);
	case MOD_UNLOAD:
		if (node_svc != NULL)
			cap_rt_service_destroy(node_svc);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_node_mod = {
	"cap_rt_node",
	cap_rt_node_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_node, cap_rt_node_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(cap_rt_node, cap_rt, 1, 1, 1);
