/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_capprotect — Capability Protection.
 *
 * Sync-only CAP_RT service.  Calling CP_OP_SHIELD with a flags bitmask
 * selectively protects the calling program (current process and all
 * fork descendants sharing the same nonce) via MACF:
 *
 *   CP_SF_PTRACE  — block ptrace attach
 *   CP_SF_SIGNAL  — block signals (SIGKILL/SIGCONT require own flags)
 *   CP_SF_VISIBLE — hide from ps/top/procfs/sysctl enumeration
 *   CP_SF_WAIT    — block wait4 from non-parent processes
 *   CP_SF_SIGKILL — block SIGKILL (unkillable)
 *   CP_SF_SIGCONT — block SIGCONT (unstoppable)
 *   CP_SF_SCHED   — block scheduling manipulation
 *   CP_SF_CORE    — suppress core dumps (prevent secret leakage)
 *   CP_SF_KTRACE  — block ktrace (passive information disclosure)
 *
 * Flags=0 enables all protections.
 * Closing the capability fd removes protection.
 *
 * CP_OP_MINT creates an access token that authorizes a specific
 * foreign program to interact with the shielded program despite
 * the shield.  The token holder must call CP_OP_AUTHORIZE to
 * activate it.
 *
 * Identity is based on the process nonce (from cap_rt_label).
 * The nonce is inherited across fork and rotates on exec.
 * Same-nonce processes (the fork family) are the same program
 * and can always interact freely — the shield only blocks
 * foreign programs (different nonce).
 *
 * Protocol (sync, via CALL):
 *   CP_OP_SHIELD:    protect calling program (flags in request)
 *   CP_OP_MINT:      create access token (returned as reply fd)
 *   CP_OP_AUTHORIZE: called on token fd, grants access to holder
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <machine/atomic.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/capsicum.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "cap_rt.h"
#include "cap_rt_label.h"

int	kern_chroot(struct thread *td, struct vnode *vp);
#include "cap_rt_capprotect_proto.h"

MALLOC_DEFINE(M_CAP_RT_CP, "cap_rt_cp", "cap_rt capability protection");

SDT_PROVIDER_DEFINE(cap_rt_capprotect);
SDT_PROBE_DEFINE3(cap_rt_capprotect, , , deny,
    "const char *", "uint64_t", "uint64_t");

/*
 * Per-instance state.
 *
 * Shield instances track the shielded process nonce.
 * Token instances track the target nonce they authorize access to.
 */
struct cp_priv {
	uint64_t	cp_target;	/* shielded nonce (shield) or target (token) */
	uint32_t	cp_flags;	/* CP_SF_* bitmask (shield instances) */
	volatile int	cp_is_token;	/* 1 if this is an access token (write-once) */
	volatile int	cp_active;	/* 1 if shield/auth is active (write-once) */
};

/*
 * Global tables — protected by cp_lock.
 *
 * Both tables use hash buckets keyed by nonce for O(1) lookup.
 * The visibility hook (mpo_cred_check_visible) fires once per
 * process per enumeration, so fast lookup matters under load.
 */
static struct mtx cp_lock;

#define	CP_HASH_SIZE	64	/* buckets, must be power of 2 */

/* Shield table: nonces that are shielded (refcounted). */
struct shield_entry {
	LIST_ENTRY(shield_entry) se_link;
	uint64_t	se_nonce;
	uint32_t	se_flags;
	int		se_refcnt;
};
static LIST_HEAD(, shield_entry) *cp_shield_hash;
static u_long cp_shield_hashmask;

/* Auth table: (accessor_nonce, target_nonce) pairs. */
struct auth_entry {
	LIST_ENTRY(auth_entry) ae_link;
	uint64_t	ae_accessor;
	uint64_t	ae_target;
	struct cap_rt_instance *ae_inst;
};
static LIST_HEAD(, auth_entry) *cp_auth_hash;
static u_long cp_auth_hashmask;

static struct cap_rt_service *cp_svc;
static volatile uint64_t cp_next_badge = 1;

/*
 * Fast-path: if no shields are active, MAC hooks return immediately
 * without touching the mutex.  Incremented in cp_shield_add,
 * decremented in cp_shield_remove (only when refcount hits 0).
 * Read without the lock — a stale read just means one extra
 * mutex cycle during a concurrent shield/unshield transition.
 */
static volatile int cp_active_shields;

#define	CP_SHIELD_BUCKET(nonce)	(&cp_shield_hash[(nonce) & cp_shield_hashmask])
#define	CP_AUTH_BUCKET(nonce)	(&cp_auth_hash[(nonce) & cp_auth_hashmask])

/*
 * Returns the shield flags for a nonce, or 0 if not shielded.
 */
static uint32_t
cp_shield_flags(uint64_t nonce)
{
	struct shield_entry *se;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(se, CP_SHIELD_BUCKET(nonce), se_link) {
		if (se->se_nonce == nonce)
			return (se->se_flags);
	}
	return (0);
}

static int
cp_is_authorized(uint64_t accessor, uint64_t target)
{
	struct auth_entry *ae;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(ae, CP_AUTH_BUCKET(target), ae_link) {
		if (ae->ae_accessor == accessor && ae->ae_target == target)
			return (1);
	}
	return (0);
}

static void
cp_shield_add(uint64_t nonce, uint32_t flags)
{
	struct shield_entry *se, *existing;

	se = malloc(sizeof(*se), M_CAP_RT_CP, M_WAITOK);
	se->se_nonce = nonce;
	se->se_flags = flags;
	se->se_refcnt = 1;

	mtx_lock(&cp_lock);
	LIST_FOREACH(existing, CP_SHIELD_BUCKET(nonce), se_link) {
		if (existing->se_nonce == nonce) {
			existing->se_refcnt++;
			existing->se_flags |= flags;
			mtx_unlock(&cp_lock);
			free(se, M_CAP_RT_CP);
			return;
		}
	}
	atomic_add_int(&cp_active_shields, 1);
	LIST_INSERT_HEAD(CP_SHIELD_BUCKET(nonce), se, se_link);
	mtx_unlock(&cp_lock);
}

static void
cp_shield_remove(uint64_t nonce)
{
	struct shield_entry *se;
	struct auth_entry *ae, *ae_tmp;

	mtx_lock(&cp_lock);
	LIST_FOREACH(se, CP_SHIELD_BUCKET(nonce), se_link) {
		if (se->se_nonce == nonce) {
			if (--se->se_refcnt > 0) {
				mtx_unlock(&cp_lock);
				return;
			}
			LIST_REMOVE(se, se_link);
			free(se, M_CAP_RT_CP);
			atomic_subtract_int(&cp_active_shields, 1);
			break;
		}
	}
	/* Remove all auth entries for this target (only when fully unshielded). */
	LIST_FOREACH_SAFE(ae, CP_AUTH_BUCKET(nonce), ae_link, ae_tmp) {
		if (ae->ae_target == nonce) {
			LIST_REMOVE(ae, ae_link);
			free(ae, M_CAP_RT_CP);
		}
	}
	mtx_unlock(&cp_lock);
}

static void
cp_auth_add(uint64_t accessor, uint64_t target, struct cap_rt_instance *inst)
{
	struct auth_entry *ae;

	ae = malloc(sizeof(*ae), M_CAP_RT_CP, M_WAITOK);
	ae->ae_accessor = accessor;
	ae->ae_target = target;
	ae->ae_inst = inst;

	mtx_lock(&cp_lock);
	LIST_INSERT_HEAD(CP_AUTH_BUCKET(target), ae, ae_link);
	mtx_unlock(&cp_lock);
}

static void
cp_auth_remove_by_inst(struct cap_rt_instance *inst)
{
	struct auth_entry *ae, *ae_tmp;
	u_long i;

	mtx_lock(&cp_lock);
	for (i = 0; i <= cp_auth_hashmask; i++) {
		LIST_FOREACH_SAFE(ae, &cp_auth_hash[i], ae_link, ae_tmp) {
			if (ae->ae_inst == inst) {
				LIST_REMOVE(ae, ae_link);
				free(ae, M_CAP_RT_CP);
			}
		}
	}
	mtx_unlock(&cp_lock);
}

/* ----------------------------------------------------------------
 * CAP_RT service operations
 * ---------------------------------------------------------------- */

static int
cp_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&cp_next_badge, 1);
	return (0);
}

static int
cp_init(struct cap_rt_instance *s, void *arg __unused)
{
	struct cp_priv *priv;

	priv = malloc(sizeof(*priv), M_CAP_RT_CP, M_WAITOK | M_ZERO);
	cap_rt_instance_set_priv(s, priv);
	return (0);
}

static int
cp_call(struct cap_rt_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply __unused, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct cp_request *cr;
	struct cp_priv *priv;
	uint64_t caller_nonce;

	if (reqlen < sizeof(struct cp_request))
		return (EINVAL);

	cr = (const struct cp_request *)req;
	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = cap_rt_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0)
		return (ENXIO);	/* cap_rt_label not loaded */

	switch (cr->op) {
	case CP_OP_SHIELD: {
		uint32_t flags;

		if (atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		if (atomic_load_acq_int(&priv->cp_active)) {
			/*
			 * Shield is one-shot per fd — flags are immutable
			 * once set.  To change flags, close and re-open.
			 */
			return (0);
		}
		flags = cr->flags;
		if (flags == 0)
			flags = CP_SF_ALL;
		if (flags & ~CP_SF_ALL)
			return (EINVAL);
		/*
		 * Write-once: set target and flags before activating.
		 * atomic_cmpset_int ensures only one caller wins the race.
		 */
		priv->cp_target = caller_nonce;
		priv->cp_flags = flags;
		if (!atomic_cmpset_int(&priv->cp_active, 0, 1))
			return (0);	/* lost race — already activated */
		cp_shield_add(priv->cp_target, flags);
		*replylenp = 0;
		return (0);
	}

	case CP_OP_MINT: {
		struct file *token_fp;
		struct cp_priv *tp;
		uint64_t target;
		int error;

		if (atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		if (!atomic_load_acq_int(&priv->cp_active))
			return (EINVAL);
		if (*reply_nfdsp < 1)
			return (EINVAL);
		target = priv->cp_target;

		error = cap_rt_mint_fp(cp_svc, 0, &token_fp);
		if (error != 0)
			return (error);

		tp = cap_rt_instance_get_priv(token_fp->f_data);
		if (tp != NULL) {
			tp->cp_is_token = 1;
			tp->cp_target = target;
		}

		reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		return (0);
	}

	case CP_OP_AUTHORIZE:
		if (!atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		if (!atomic_cmpset_int(&priv->cp_active, 0, 1))
			return (0);	/* already authorized */
		cp_auth_add(caller_nonce, priv->cp_target, s);
		*replylenp = 0;
		return (0);

	case CP_OP_CAPMODE: {
		struct ucred *newcred, *oldcred;
		struct proc *p;

		p = curthread->td_proc;

		/* Allocate before PROC_LOCK (crget does M_WAITOK) */
		newcred = crget();
		PROC_LOCK(p);

		if (p->p_ucred->cr_flags & CRED_FLAG_CAPMODE) {
			/* Already in capability mode — idempotent */
			PROC_UNLOCK(p);
			crfree(newcred);
			*replylenp = 0;
			return (0);
		}

		oldcred = crcopysafe(p, newcred);
		newcred->cr_flags |= CRED_FLAG_CAPMODE;
		proc_set_cred(p, newcred);
		PROC_UNLOCK(p);
		crfree(oldcred);

		*replylenp = 0;
		return (0);
	}

	case CP_OP_CHROOT: {
		struct file *dir_fp;
		struct vnode *vp;
		int error;

		if (nfds < 1 || fds[0] == NULL) {
			return (EINVAL);
		}
		dir_fp = fds[0];
		if (dir_fp->f_type != DTYPE_VNODE)
			return (EINVAL);

		vp = dir_fp->f_vnode;
		if (vp->v_type != VDIR)
			return (ENOTDIR);

		/*
		 * kern_chroot expects a locked+referenced vnode (as from
		 * namei) and releases both the lock and the reference.
		 * vn_lock only acquires the lock, so take an explicit
		 * vref to match kern_chroot's vrele/vput.
		 */
		vref(vp);
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = kern_chroot(curthread, vp);

		*replylenp = 0;
		return (error);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
cp_revoke(struct cap_rt_instance *s, uint64_t badge __unused,
    enum cap_rt_revoke_reason reason __unused, void *arg __unused)
{
	struct cp_priv *priv;

	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return;

	if (atomic_load_acq_int(&priv->cp_active)) {
		if (atomic_load_acq_int(&priv->cp_is_token)) {
			cp_auth_remove_by_inst(s);
		} else {
			cp_shield_remove(priv->cp_target);
		}
	}

	free(priv, M_CAP_RT_CP);
}

static const struct cap_rt_ops cp_ops = {
	.co_connect = cp_connect,
	.co_init = cp_init,
	.co_call = cp_call,
	.co_revoke = cp_revoke,
};

/* ----------------------------------------------------------------
 * MACF policy — selective enforcement based on shield flags
 *
 * Same-nonce (fork family) processes always pass through.
 * Only foreign programs (different nonce) are subject to the shield.
 *
 * Fast-path: if cp_active_shields == 0, no process on the system
 * is shielded and all hooks return immediately (~10ns) without
 * touching the mutex.
 * ---------------------------------------------------------------- */

static __inline int
cp_no_shields(void)
{

	return (atomic_load_int(&cp_active_shields) == 0);
}

/*
 * Shared helper for shield hooks that follow the standard pattern:
 * self-check, zero-nonce early-out, same-nonce early-out, fast-path,
 * lock, flag check, auth check, unlock, probe, return.
 */
static int
cp_check_shield(struct ucred *cred, struct proc *p, uint32_t flag,
    const char *name)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == p)
		return (0);

	target_nonce = cap_rt_proc_nonce(p->p_ucred);
	caller_nonce = cap_rt_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
		return (0);
	if (cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);
	if ((flags & flag) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	denied = !cp_is_authorized(caller_nonce, target_nonce);
	mtx_unlock(&cp_lock);
	if (denied) {
		SDT_PROBE3(cap_rt_capprotect, , , deny, name,
		    target_nonce, caller_nonce);
	}

	return (denied ? EACCES : 0);
}

static int
cp_mac_check_ptrace(struct ucred *cred, struct proc *p)
{

	return (cp_check_shield(cred, p, CP_SF_PTRACE, "ptrace"));
}

static int
cp_mac_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == p)
		return (0);

	target_nonce = cap_rt_proc_nonce(p->p_ucred);
	caller_nonce = cap_rt_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
		return (0);
	if (cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);

	if (signum == SIGKILL) {
		if ((flags & CP_SF_SIGKILL) == 0) {
			mtx_unlock(&cp_lock);
			return (0);
		}
	} else if (signum == SIGCONT) {
		if ((flags & CP_SF_SIGCONT) == 0) {
			mtx_unlock(&cp_lock);
			return (0);
		}
	} else {
		if ((flags & CP_SF_SIGNAL) == 0) {
			mtx_unlock(&cp_lock);
			return (0);
		}
	}

	denied = !cp_is_authorized(caller_nonce, target_nonce);
	mtx_unlock(&cp_lock);
	if (denied) {
		SDT_PROBE3(cap_rt_capprotect, , , deny, "signal",
		    target_nonce, caller_nonce);
	}

	return (denied ? EACCES : 0);
}

static int
cp_mac_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	uint64_t observer_nonce, target_nonce;
	uint32_t flags;

	if (cr1 == cr2)
		return (0);

	target_nonce = cap_rt_proc_nonce(cr2);
	if (target_nonce == 0)
		return (0);

	observer_nonce = cap_rt_proc_nonce(cr1);
	if (observer_nonce == 0)
		return (0);
	if (observer_nonce == target_nonce)
		return (0);
	if (cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);
	if ((flags & CP_SF_VISIBLE) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	if (cp_is_authorized(observer_nonce, target_nonce)) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	mtx_unlock(&cp_lock);
	SDT_PROBE3(cap_rt_capprotect, , , deny, "visible",
	    target_nonce, observer_nonce);

	return (ESRCH);
}

static int
cp_mac_proc_check_wait(struct ucred *cred, struct proc *p)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;

	if (p->p_pptr == curthread->td_proc)
		return (0);

	target_nonce = cap_rt_proc_nonce(p->p_ucred);
	caller_nonce = cap_rt_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
		return (0);
	if (cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);
	if ((flags & CP_SF_WAIT) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	if (cp_is_authorized(caller_nonce, target_nonce)) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	mtx_unlock(&cp_lock);
	SDT_PROBE3(cap_rt_capprotect, , , deny, "wait",
	    target_nonce, caller_nonce);

	return (EACCES);
}

static int
cp_mac_proc_check_sched(struct ucred *cred, struct proc *p)
{

	return (cp_check_shield(cred, p, CP_SF_SCHED, "sched"));
}

/*
 * Core dump — suppress if the process is shielded with CP_SF_CORE.
 * Core files expose full process memory (keys, tokens, plaintext).
 * No accessor/target comparison: the process is dumping itself.
 * PROC_LOCK held — MUST NOT sleep.
 */
static int
cp_mac_proc_check_core(struct ucred *cred __unused, struct proc *p)
{
	uint64_t nonce;
	uint32_t flags;

	if (cp_no_shields())
		return (0);

	nonce = cap_rt_proc_nonce(p->p_ucred);
	if (nonce == 0)
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(nonce);
	mtx_unlock(&cp_lock);
	if ((flags & CP_SF_CORE) != 0)
		SDT_PROBE3(cap_rt_capprotect, , , deny, "core", nonce, 0);

	return ((flags & CP_SF_CORE) ? EPERM : 0);
}

/*
 * ktrace — block passive monitoring of shielded processes.
 * ktrace records all syscalls, arguments, return values, and I/O.
 * Same accessor/target pattern as ptrace.
 * PROC_LOCK held — MUST NOT sleep.
 */
static int
cp_mac_proc_check_ktrace(struct ucred *cred, struct proc *p,
    int ops __unused)
{

	return (cp_check_shield(cred, p, CP_SF_KTRACE, "ktrace"));
}

/*
 * Suspend — block foreign processes from freezing shielded processes.
 * Gated on CP_SF_SIGNAL: if you're blocking signals, you're blocking
 * suspension.  The signal hook blocks SIGSTOP delivery; this hook
 * catches suspension that bypasses signal delivery.
 * PROC_LOCK held — MUST NOT sleep.
 */
static int
cp_mac_proc_check_suspend(struct ucred *cred, struct proc *p,
    int sig __unused)
{

	return (cp_check_shield(cred, p, CP_SF_SIGNAL, "suspend"));
}

/*
 * Self-restriction hooks — check the CALLER's own nonce shield.
 * These restrict what the shielded process itself can do, not what
 * others can do to it.
 */

static int
cp_check_self_restrict(struct ucred *cred, uint32_t flag, const char *name,
    int errcode)
{
	uint64_t nonce;
	uint32_t flags;

	nonce = cap_rt_proc_nonce(cred);
	if (nonce == 0 || cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(nonce);
	mtx_unlock(&cp_lock);

	if (flags & flag) {
		SDT_PROBE3(cap_rt_capprotect, , , deny, name,
		    nonce, (uint64_t)0);
		return (errcode);
	}

	return (0);
}

static int
cp_mac_priv_check(struct ucred *cred, int priv __unused)
{

	return (cp_check_self_restrict(cred, CP_SF_NOPRIVS, "priv", EPERM));
}

static int
cp_mac_check_fork(struct ucred *cred, int flags __unused)
{

	return (cp_check_self_restrict(cred, CP_SF_NOFORK, "fork", EPERM));
}

static int
cp_mac_file_check_receive(struct ucred *cred, struct file *fp __unused)
{

	return (cp_check_self_restrict(cred, CP_SF_NOFDRECV, "fd_receive",
	    EACCES));
}

/*
 * IPC lockdown — block SysV and POSIX IPC for shielded nonces.
 * One function handles all IPC hooks since the policy is binary.
 */
static int
cp_mac_ipc_deny(struct ucred *cred)
{
	uint64_t nonce;
	uint32_t flags;

	nonce = cap_rt_proc_nonce(cred);
	if (nonce == 0 || cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(nonce);
	mtx_unlock(&cp_lock);

	if (flags & CP_SF_NOIPC) {
		SDT_PROBE3(cap_rt_capprotect, , , deny, "ipc",
		    nonce, (uint64_t)0);
		return (EACCES);
	}

	return (0);
}

/* SysV shm wrappers */
static int
cp_mac_sysvshm_check_shmat(struct ucred *cred,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int shmflg __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvshm_check_shmctl(struct ucred *cred,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int cmd __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvshm_check_shmdt(struct ucred *cred,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvshm_check_shmget(struct ucred *cred,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int shmflg __unused)
{
	return (cp_mac_ipc_deny(cred));
}

/* SysV sem wrappers */
static int
cp_mac_sysvsem_check_semctl(struct ucred *cred,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused, int cmd __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvsem_check_semget(struct ucred *cred,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvsem_check_semop(struct ucred *cred,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused, size_t accesstype __unused)
{
	return (cp_mac_ipc_deny(cred));
}

/* SysV msg wrappers */
static int
cp_mac_sysvmsq_check_msqget(struct ucred *cred,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvmsq_check_msqsnd(struct ucred *cred,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvmsq_check_msqrcv(struct ucred *cred,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_sysvmsq_check_msqctl(struct ucred *cred,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused, int cmd __unused)
{
	return (cp_mac_ipc_deny(cred));
}

/* POSIX shm wrappers */
static int
cp_mac_posixshm_check_create(struct ucred *cred,
    const char *path __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static int
cp_mac_posixshm_check_open(struct ucred *cred,
    struct shmfd *shmfd __unused, struct label *shmlabel __unused,
    accmode_t accmode __unused)
{
	return (cp_mac_ipc_deny(cred));
}

/* POSIX sem wrappers */
static int
cp_mac_posixsem_check_open(struct ucred *cred,
    struct ksem *ks __unused, struct label *kslabel __unused)
{
	return (cp_mac_ipc_deny(cred));
}

static struct mac_policy_ops cp_mac_ops = {
	/* Existing shield hooks (protect target from foreign nonces) */
	.mpo_proc_check_debug = cp_mac_check_ptrace,
	.mpo_proc_check_signal = cp_mac_check_signal,
	.mpo_cred_check_visible = cp_mac_cred_check_visible,
	.mpo_proc_check_wait = cp_mac_proc_check_wait,
	.mpo_proc_check_sched = cp_mac_proc_check_sched,
	.mpo_proc_check_core = cp_mac_proc_check_core,
	.mpo_proc_check_ktrace = cp_mac_proc_check_ktrace,
	.mpo_proc_check_suspend = cp_mac_proc_check_suspend,
	/* Self-restriction hooks (restrict what shielded process can do) */
	.mpo_priv_check = cp_mac_priv_check,
	.mpo_proc_check_fork = cp_mac_check_fork,
	.mpo_file_check_receive = cp_mac_file_check_receive,
	/* IPC lockdown */
	.mpo_sysvshm_check_shmat = cp_mac_sysvshm_check_shmat,
	.mpo_sysvshm_check_shmctl = cp_mac_sysvshm_check_shmctl,
	.mpo_sysvshm_check_shmdt = cp_mac_sysvshm_check_shmdt,
	.mpo_sysvshm_check_shmget = cp_mac_sysvshm_check_shmget,
	.mpo_sysvsem_check_semctl = cp_mac_sysvsem_check_semctl,
	.mpo_sysvsem_check_semget = cp_mac_sysvsem_check_semget,
	.mpo_sysvsem_check_semop = cp_mac_sysvsem_check_semop,
	.mpo_sysvmsq_check_msqget = cp_mac_sysvmsq_check_msqget,
	.mpo_sysvmsq_check_msqsnd = cp_mac_sysvmsq_check_msqsnd,
	.mpo_sysvmsq_check_msqrcv = cp_mac_sysvmsq_check_msqrcv,
	.mpo_sysvmsq_check_msqctl = cp_mac_sysvmsq_check_msqctl,
	.mpo_posixshm_check_create = cp_mac_posixshm_check_create,
	.mpo_posixshm_check_open = cp_mac_posixshm_check_open,
	.mpo_posixsem_check_open = cp_mac_posixsem_check_open,
};

MAC_POLICY_SET(&cp_mac_ops, mac_cap_rt_capprotect, "CAP_RT capability protection",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
cap_rt_capprotect_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		cp_shield_hash = hashinit(CP_HASH_SIZE, M_CAP_RT_CP,
		    &cp_shield_hashmask);
		cp_auth_hash = hashinit(CP_HASH_SIZE, M_CAP_RT_CP,
		    &cp_auth_hashmask);
		mtx_init(&cp_lock, "cap_rt_capprotect", NULL, MTX_DEF);
		{
			struct cap_rt_service_params p = {
				.name = "capprotect",
				.ops = &cp_ops,
			};
			error = cap_rt_service_create(&p, &cp_svc);
		}
		if (error != 0) {
			mtx_destroy(&cp_lock);
			hashdestroy(cp_shield_hash, M_CAP_RT_CP, cp_shield_hashmask);
			hashdestroy(cp_auth_hash, M_CAP_RT_CP, cp_auth_hashmask);
			return (error);
		}
		if (bootverbose)
			printf("cap_rt_capprotect: loaded\n");
		return (0);

	case MOD_UNLOAD:
		/*
		 * NOTLATE MAC policies cannot be safely unloaded — the
		 * hooks remain in the static policy list and will be
		 * called after the module text is freed.  Always refuse.
		 */
		return (EBUSY);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_capprotect_mod = {
	"cap_rt_capprotect",
	cap_rt_capprotect_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_capprotect, cap_rt_capprotect_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cap_rt_capprotect, 1);
MODULE_DEPEND(cap_rt_capprotect, cap_rt, 1, 1, 1);
