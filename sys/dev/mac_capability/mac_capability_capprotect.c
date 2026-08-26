/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_capprotect — Capability Protection.
 *
 * Sync-only MAC_CAPABILITY service.  Calling CP_OP_SHIELD with a flags bitmask
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
 * Identity is based on the process nonce (from mac_capability_label).
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
#include <sys/eventhandler.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/procdesc.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <machine/atomic.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/capsicum.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "mac_capability.h"
#include "mac_capability_label.h"

int	kern_chroot(struct thread *td, struct vnode *vp);
#include "mac_capability_capprotect_proto.h"

MALLOC_DEFINE(M_MAC_CAPABILITY_CP, "mac_capability_cp", "mac_capability capability protection");

SDT_PROVIDER_DEFINE(mac_capability_capprotect);
SDT_PROBE_DEFINE3(mac_capability_capprotect, , , deny,
    "const char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(mac_capability_capprotect, , , allow,
    "const char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability_capprotect, , , state,
    "const char *", "uint64_t", "uint64_t", "uint32_t", "pid_t", "int");

/*
 * Per-instance state.
 *
 * Shield instances track the shielded process nonce.
 * Token instances track the target nonce they authorize access to.
 */
struct cp_priv {
	pid_t		cp_target;	/* shielded PID (shield) or target PID (token) */
	uint32_t	cp_flags;	/* CP_SF_* bitmask (token instances) */
	volatile int	cp_is_token;	/* int for atomic_cmpset_int */
	volatile int	cp_active;	/* int for atomic_cmpset_int */
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

/*
 * Shield table: shielded PROCESSES, keyed by PID, refcounted per flag.
 *
 * Protection is per-process, not per-nonce: a forked child does not inherit
 * its parent's shield, and an entry is dropped when the process exits (before
 * the PID can be reused).  se_protector records the PID that applied the shield
 * (the launcher, or the process itself) and is permitted to act on the target
 * for lifecycle control.
 */
struct shield_entry {
	LIST_ENTRY(shield_entry) se_link;
	pid_t		se_pid;		/* shielded process */
	pid_t		se_protector;	/* who applied it (launcher/self) */
	uint32_t	se_flags;
	u_int		se_flag_refs[32];
};
static LIST_HEAD(, shield_entry) *cp_shield_hash;
static u_long cp_shield_hashmask;

/* Auth table: (accessor_pid, target_pid) pairs. */
struct auth_entry {
	LIST_ENTRY(auth_entry) ae_link;
	pid_t		ae_accessor;
	pid_t		ae_target;
	uint32_t	ae_flags;
	struct mac_capability_instance *ae_inst;
};
static LIST_HEAD(, auth_entry) *cp_auth_hash;
static u_long cp_auth_hashmask;

static volatile u_int cp_auth_count;
static u_int cp_max_auth = 4096;

SYSCTL_NODE(_kern, OID_AUTO, mac_capability_capprotect,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "mac_capability capability protection");
SYSCTL_UINT(_kern_mac_capability_capprotect, OID_AUTO, max_auth, CTLFLAG_RDTUN,
    &cp_max_auth, 0,
    "Maximum authorization entries per nonce (0 = unlimited)");
SYSCTL_UINT(_kern_mac_capability_capprotect, OID_AUTO, auth_count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &cp_auth_count), 0,
    "Current number of authorization entries");

static struct mac_capability_service *cp_svc;
static volatile uint64_t cp_next_badge = 1;

/*
 * Fast-path: if no shields are active, MAC hooks return immediately
 * without touching the mutex.  Incremented in cp_shield_add,
 * decremented in cp_shield_remove (only when refcount hits 0).
 * Read without the lock — a stale read just means one extra
 * mutex cycle during a concurrent shield/unshield transition.
 */
static volatile int cp_active_shields;

#define	CP_SHIELD_BUCKET(pid)	(&cp_shield_hash[(u_long)(pid) & cp_shield_hashmask])
#define	CP_AUTH_BUCKET(pid)	(&cp_auth_hash[(u_long)(pid) & cp_auth_hashmask])

/*
 * Returns the shield flags for a PID, or 0 if not shielded.
 */
static uint32_t
cp_shield_flags(pid_t pid)
{
	struct shield_entry *se;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(se, CP_SHIELD_BUCKET(pid), se_link) {
		if (se->se_pid == pid)
			return (se->se_flags);
	}
	return (0);
}

/*
 * The PID that applied the shield on target may act on it (lifecycle control),
 * or 0 if the target is not shielded.
 */
static pid_t
cp_shield_protector(pid_t pid)
{
	struct shield_entry *se;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(se, CP_SHIELD_BUCKET(pid), se_link) {
		if (se->se_pid == pid)
			return (se->se_protector);
	}
	return (0);
}

static int
cp_is_authorized(pid_t accessor, pid_t target, uint32_t flag)
{
	struct auth_entry *ae;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(ae, CP_AUTH_BUCKET(target), ae_link) {
		if (ae->ae_accessor == accessor && ae->ae_target == target &&
		    (ae->ae_flags & flag) != 0)
			return (1);
	}
	return (0);
}

static void
cp_shield_ref_flags(struct shield_entry *se, uint32_t flags)
{
	uint32_t bit;
	u_int i;

	mtx_assert(&cp_lock, MA_OWNED);
	for (i = 0, bit = 1; i < nitems(se->se_flag_refs); i++, bit <<= 1) {
		if ((flags & bit) == 0)
			continue;
		se->se_flag_refs[i]++;
		se->se_flags |= bit;
	}
}

static void
cp_shield_add(pid_t pid, pid_t protector, uint32_t flags)
{
	struct shield_entry *se, *existing;

	se = malloc(sizeof(*se), M_MAC_CAPABILITY_CP, M_WAITOK);
	se->se_pid = pid;
	se->se_protector = protector;
	se->se_flags = 0;
	memset(se->se_flag_refs, 0, sizeof(se->se_flag_refs));

	mtx_lock(&cp_lock);
	LIST_FOREACH(existing, CP_SHIELD_BUCKET(pid), se_link) {
		if (existing->se_pid == pid) {
			cp_shield_ref_flags(existing, flags);
			mtx_unlock(&cp_lock);
			free(se, M_MAC_CAPABILITY_CP);
			return;
		}
	}
	cp_shield_ref_flags(se, flags);
	atomic_add_int(&cp_active_shields, 1);
	LIST_INSERT_HEAD(CP_SHIELD_BUCKET(pid), se, se_link);
	mtx_unlock(&cp_lock);
}

/*
 * Remove a process's shield entirely and all authorizations naming it.  Called
 * from the process-exit handler: protection is per-process and lasts exactly
 * the process's lifetime, so exit (not descriptor close) is what drops it.
 */
static void
cp_shield_remove_all(pid_t pid)
{
	struct shield_entry *se, *se_tmp;
	struct auth_entry *ae, *ae_tmp;

	mtx_lock(&cp_lock);
	LIST_FOREACH_SAFE(se, CP_SHIELD_BUCKET(pid), se_link, se_tmp) {
		if (se->se_pid == pid) {
			LIST_REMOVE(se, se_link);
			free(se, M_MAC_CAPABILITY_CP);
			atomic_subtract_int(&cp_active_shields, 1);
		}
	}
	/* Drop authorizations targeting the exiting process. */
	LIST_FOREACH_SAFE(ae, CP_AUTH_BUCKET(pid), ae_link, ae_tmp) {
		if (ae->ae_target == pid) {
			LIST_REMOVE(ae, ae_link);
			atomic_subtract_int(&cp_auth_count, 1);
			free(ae, M_MAC_CAPABILITY_CP);
		}
	}
	mtx_unlock(&cp_lock);
}

static int
cp_auth_add(pid_t accessor, pid_t target, uint32_t flags,
    struct mac_capability_instance *inst)
{
	struct auth_entry *ae, *existing;

	ae = malloc(sizeof(*ae), M_MAC_CAPABILITY_CP, M_WAITOK);
	ae->ae_accessor = accessor;
	ae->ae_target = target;
	ae->ae_flags = flags;
	ae->ae_inst = inst;

	mtx_lock(&cp_lock);
	/* Dedup: if an entry with same key exists, OR the flags. */
	LIST_FOREACH(existing, CP_AUTH_BUCKET(target), ae_link) {
		if (existing->ae_accessor == accessor &&
		    existing->ae_target == target &&
		    existing->ae_inst == inst) {
			existing->ae_flags |= flags;
			mtx_unlock(&cp_lock);
			free(ae, M_MAC_CAPABILITY_CP);
			return (0);
		}
	}
	/* Limit check: use global counter as a fast early-out. */
	if (cp_max_auth != 0 && cp_auth_count >= cp_max_auth) {
		mtx_unlock(&cp_lock);
		free(ae, M_MAC_CAPABILITY_CP);
		return (ENOSPC);
	}
	LIST_INSERT_HEAD(CP_AUTH_BUCKET(target), ae, ae_link);
	atomic_add_int(&cp_auth_count, 1);
	mtx_unlock(&cp_lock);
	return (0);
}

static void
cp_auth_remove_by_inst(struct mac_capability_instance *inst)
{
	struct auth_entry *ae, *ae_tmp;
	u_long i;

	mtx_lock(&cp_lock);
	for (i = 0; i <= cp_auth_hashmask; i++) {
		LIST_FOREACH_SAFE(ae, &cp_auth_hash[i], ae_link, ae_tmp) {
			if (ae->ae_inst == inst) {
				LIST_REMOVE(ae, ae_link);
				atomic_subtract_int(&cp_auth_count, 1);
				free(ae, M_MAC_CAPABILITY_CP);
			}
		}
	}
	mtx_unlock(&cp_lock);
}

static int
cp_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	return (MAC_CAPABILITY_CONNECT_BADGE(cp_next_badge, badge_out));
}

static int
cp_init(struct mac_capability_instance *s, void *arg __unused)
{
	struct cp_priv *priv;

	priv = malloc(sizeof(*priv), M_MAC_CAPABILITY_CP, M_WAITOK | M_ZERO);
	mac_capability_instance_set_priv(s, priv);
	return (0);
}

static int
cp_call(struct mac_capability_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply __unused, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct cp_request *cr;
	struct cp_priv *priv;
	pid_t caller_pid;

	if (reqlen < sizeof(struct cp_request))
		return (EINVAL);

	cr = (const struct cp_request *)req;
	priv = mac_capability_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_pid = curthread->td_proc->p_pid;

	switch (cr->op) {
	case CP_OP_SHIELD: {
		uint32_t flags;

		/* Shield the calling process itself (per-PID, dropped on exit). */
		if (atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		flags = cr->flags;
		if (flags == 0)
			flags = CP_SF_ALL;
		if (flags & ~CP_SF_ALL) {
			SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"shield-error",
			    caller_pid, caller_pid, flags,
			    curthread->td_proc->p_pid, EINVAL);
			return (EINVAL);
		}
		/* Record the most-recent target on the fd for MINT. */
		priv->cp_target = caller_pid;
		priv->cp_flags = flags;
		atomic_store_rel_int(&priv->cp_active, 1);
		cp_shield_add(caller_pid, caller_pid, flags);
		SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"shield",
		    caller_pid, caller_pid, flags,
		    curthread->td_proc->p_pid, 0);
		*replylenp = 0;
		return (0);
	}

	case CP_OP_PROTECT: {
		/*
		 * Launcher-applied protection: shield a target process named by
		 * an attached process descriptor.  Holding the target's procdesc
		 * is the authority to protect it; the caller becomes the target's
		 * protector and may act on it for lifecycle control.  The fd is a
		 * reusable authority — it may protect many targets.
		 */
		uint32_t flags;
		pid_t target_pid;

		if (atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		if (nfds < 1 || fds[0] == NULL ||
		    fds[0]->f_type != DTYPE_PROCDESC)
			return (EINVAL);
		flags = cr->flags;
		if (flags == 0)
			flags = CP_SF_ALL;
		if (flags & ~CP_SF_ALL)
			return (EINVAL);
		target_pid = procdesc_pid(fds[0]);
		if (target_pid <= 0)
			return (ESRCH);
		priv->cp_target = target_pid;
		priv->cp_flags = flags;
		atomic_store_rel_int(&priv->cp_active, 1);
		cp_shield_add(target_pid, caller_pid, flags);
		SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"protect",
		    target_pid, caller_pid, flags,
		    curthread->td_proc->p_pid, 0);
		*replylenp = 0;
		return (0);
	}

	case CP_OP_MINT: {
		struct file *token_fp;
		struct cp_priv *tp;
		pid_t target;
		uint32_t token_flags;
		int error;

		if (atomic_load_acq_int(&priv->cp_is_token))
			return (EINVAL);
		if (!atomic_load_acq_int(&priv->cp_active))
			return (EINVAL);
		if (*reply_nfdsp < 1)
			return (EINVAL);
		target = priv->cp_target;

		/*
		 * Narrow: if the caller requests specific flags,
		 * intersect with the shield's flags.  Zero means
		 * "all flags from the shield" (backward compat).
		 */
		token_flags = priv->cp_flags;
		if (cr->flags != 0) {
			if (cr->flags & ~token_flags)
				return (EINVAL);  /* requesting flags not shielded */
			token_flags = cr->flags;
		}

			error = mac_capability_mint_fp(cp_svc, 0, &token_fp);
			if (error != 0)
				return (error);

			tp = mac_capability_instance_get_priv(token_fp->f_data);
			if (tp != NULL) {
				tp->cp_is_token = 1;
				tp->cp_target = target;
				tp->cp_flags = token_flags;
			}

			reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"token-mint",
		    target, caller_pid, token_flags,
		    curthread->td_proc->p_pid, 0);
		return (0);
	}

		case CP_OP_AUTHORIZE: {
			int auth_error;

			if (!atomic_load_acq_int(&priv->cp_is_token))
				return (EINVAL);
			if (!atomic_cmpset_int(&priv->cp_active, 0, 1))
				return (0);	/* already authorized */
			auth_error = cp_auth_add(caller_pid, priv->cp_target,
			    priv->cp_flags, s);
			if (auth_error != 0) {
				atomic_cmpset_int(&priv->cp_active, 1, 0);
				return (auth_error);
			}
			SDT_PROBE6(mac_capability_capprotect, , , state,
			    "authorize", priv->cp_target, caller_pid,
			    priv->cp_flags, curthread->td_proc->p_pid, 0);
			*replylenp = 0;
			return (0);
		}

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

		SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"capmode",
		    caller_pid, caller_pid, 0,
		    curthread->td_proc->p_pid, 0);
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

		if (error == 0)
			SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"chroot",
			    caller_pid, caller_pid, 0,
			    curthread->td_proc->p_pid, 0);
		else
			SDT_PROBE6(mac_capability_capprotect, , , state, (uintptr_t)"chroot-error",
			    caller_pid, caller_pid, 0,
			    curthread->td_proc->p_pid, error);
		*replylenp = 0;
		return (error);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
cp_revoke(struct mac_capability_instance *s, uint64_t badge __unused,
    enum mac_capability_revoke_reason reason __unused, void *arg __unused)
{
	struct cp_priv *priv;

	priv = mac_capability_instance_get_priv(s);
	if (priv == NULL)
		return;

	/*
	 * A shield now lives for the protected process's lifetime and is
	 * dropped by the process-exit handler, not by closing the descriptor
	 * that applied it.  Only authorization tokens are tied to their
	 * instance and cleaned up here.
	 */
	if (atomic_load_acq_int(&priv->cp_active) &&
	    atomic_load_acq_int(&priv->cp_is_token)) {
		SDT_PROBE6(mac_capability_capprotect, , , state,
		    "token-remove", priv->cp_target, 0,
		    priv->cp_flags, curthread->td_proc->p_pid, 0);
		cp_auth_remove_by_inst(s);
	}

	free(priv, M_MAC_CAPABILITY_CP);
}

/*
 * Process exit: drop any shield on the exiting process (and authorizations
 * naming it) before its PID can be reused.  This is the sole lifetime bound on
 * a shield in the per-process model.
 */
static void
cp_process_exit(void *arg __unused, struct proc *p)
{

	if (atomic_load_int(&cp_active_shields) == 0)
		return;
	cp_shield_remove_all(p->p_pid);
}
static eventhandler_tag cp_exit_tag;

static const struct mac_capability_ops cp_ops = {
	.co_connect = cp_connect,
	.co_init = cp_init,
	.co_call = cp_call,
	.co_revoke = cp_revoke,
};

/*
 * MACF policy — selective enforcement based on shield flags.
 *
 * Same-nonce (fork family) processes always pass through.
 * Only foreign programs (different nonce) are subject to the shield.
 *
 * Fast-path: if cp_active_shields == 0, no process on the system
 * is shielded and all hooks return immediately (~10ns) without
 * touching the mutex.
 */

static __inline int
cp_no_shields(void)
{

	return (atomic_load_int(&cp_active_shields) == 0);
}

/*
 * Shared helper for shield hooks that protect a target PROCESS from others:
 * self-check, fast-path, look up the target PID's shield, allow the target's
 * protector and explicitly authorized accessors, otherwise deny.
 */
static int
cp_check_shield(struct ucred *cred __unused, struct proc *p, uint32_t flag,
    const char *name)
{
	pid_t caller_pid, target_pid;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == p)
		return (0);
	if (cp_no_shields())
		return (0);

	target_pid = p->p_pid;
	caller_pid = curthread->td_proc->p_pid;

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_pid);
	if ((flags & flag) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	denied = caller_pid != cp_shield_protector(target_pid) &&
	    !cp_is_authorized(caller_pid, target_pid, flag);
	mtx_unlock(&cp_lock);
	if (denied)
		SDT_PROBE3(mac_capability_capprotect, , , deny, name,
		    (uint64_t)target_pid, (uint64_t)caller_pid);
	else
		SDT_PROBE3(mac_capability_capprotect, , , allow, name,
		    (uint64_t)target_pid, (uint64_t)caller_pid);

	return (denied ? EACCES : 0);
}

static int
cp_mac_check_ptrace(struct ucred *cred, struct proc *p)
{

	return (cp_check_shield(cred, p, CP_SF_PTRACE, "ptrace"));
}

static int
cp_mac_check_signal(struct ucred *cred __unused, struct proc *p, int signum)
{
	pid_t caller_pid, target_pid;
	uint32_t flags, want;
	int denied;

	if (curthread->td_proc == p)
		return (0);
	if (cp_no_shields())
		return (0);

	target_pid = p->p_pid;
	caller_pid = curthread->td_proc->p_pid;

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_pid);
	want = signum == SIGKILL ? CP_SF_SIGKILL :
	    (signum == SIGCONT ? CP_SF_SIGCONT : CP_SF_SIGNAL);
	if ((flags & want) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	denied = caller_pid != cp_shield_protector(target_pid) &&
	    !cp_is_authorized(caller_pid, target_pid, want);
	mtx_unlock(&cp_lock);
	if (denied)
		SDT_PROBE3(mac_capability_capprotect, , , deny, (uintptr_t)"signal",
		    (uint64_t)target_pid, (uint64_t)caller_pid);
	else
		SDT_PROBE3(mac_capability_capprotect, , , allow, (uintptr_t)"signal",
		    (uint64_t)target_pid, (uint64_t)caller_pid);

	return (denied ? EACCES : 0);
}

/*
 * Visibility (CP_SF_VISIBLE) is not enforced in the per-process model: this
 * hook is credential-to-credential and a credential has no PID (it is shared
 * across processes), so the shielded target cannot be identified here.  Process
 * enumeration hiding, if reintroduced, needs a process-context hook rather than
 * mpo_cred_check_visible.  All other protections remain fully enforced.
 */
static int
cp_mac_cred_check_visible(struct ucred *cr1 __unused, struct ucred *cr2 __unused)
{

	return (0);
}

static int
cp_mac_proc_check_wait(struct ucred *cred, struct proc *p)
{

	/* The real parent may always wait for its child. */
	if (p->p_pptr == curthread->td_proc)
		return (0);
	return (cp_check_shield(cred, p, CP_SF_WAIT, "wait"));
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
	uint32_t flags;

	if (cp_no_shields())
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(p->p_pid);
	mtx_unlock(&cp_lock);
	if ((flags & CP_SF_CORE) != 0)
		SDT_PROBE3(mac_capability_capprotect, , , deny, (uintptr_t)"core",
		    (uint64_t)p->p_pid, 0);

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
cp_check_self_restrict(struct ucred *cred __unused, uint32_t flag,
    const char *name, int errcode)
{
	pid_t pid;
	uint32_t flags;

	if (cp_no_shields())
		return (0);
	pid = curthread->td_proc->p_pid;

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(pid);
	mtx_unlock(&cp_lock);

	if (flags & flag) {
		SDT_PROBE3(mac_capability_capprotect, , , deny, name,
		    (uint64_t)pid, (uint64_t)0);
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

static int
cp_mac_vnode_check_exec(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{

	return (cp_check_self_restrict(cred, CP_SF_NOEXEC, "exec", EPERM));
}

static int
cp_mac_socket_check_create(struct ucred *cred, int domain __unused,
    int type __unused, int protocol __unused)
{

	return (cp_check_self_restrict(cred, CP_SF_NOSOCK, "socket", EPERM));
}

/*
 * IPC lockdown — block SysV and POSIX IPC for shielded nonces.
 * One function handles all IPC hooks since the policy is binary.
 */
static int
cp_mac_ipc_deny(struct ucred *cred __unused)
{
	pid_t pid;
	uint32_t flags;

	if (cp_no_shields())
		return (0);
	pid = curthread->td_proc->p_pid;

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(pid);
	mtx_unlock(&cp_lock);

	if (flags & CP_SF_NOIPC) {
		SDT_PROBE3(mac_capability_capprotect, , , deny, (uintptr_t)"ipc",
		    (uint64_t)pid, (uint64_t)0);
		return (EACCES);
	}

	return (0);
}

/*
 * CP_IPC_CHECK — generate a one-liner MAC hook that delegates to
 * cp_mac_ipc_deny(cred).  All extra parameters are unused.
 */
#define	CP_IPC_CHECK(name, ...)						\
static int								\
name(struct ucred *cred, __VA_ARGS__)					\
{									\
	return (cp_mac_ipc_deny(cred));					\
}

/* SysV shm */
CP_IPC_CHECK(cp_mac_sysvshm_check_shmat,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int shmflg __unused)
CP_IPC_CHECK(cp_mac_sysvshm_check_shmctl,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int cmd __unused)
CP_IPC_CHECK(cp_mac_sysvshm_check_shmdt,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused)
CP_IPC_CHECK(cp_mac_sysvshm_check_shmget,
    struct shmid_kernel *shmsegptr __unused,
    struct label *shmseglabel __unused, int shmflg __unused)

/* SysV sem */
CP_IPC_CHECK(cp_mac_sysvsem_check_semctl,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused, int cmd __unused)
CP_IPC_CHECK(cp_mac_sysvsem_check_semget,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused)
CP_IPC_CHECK(cp_mac_sysvsem_check_semop,
    struct semid_kernel *semakptr __unused,
    struct label *semaklabel __unused, size_t accesstype __unused)

/* SysV msg */
CP_IPC_CHECK(cp_mac_sysvmsq_check_msqget,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
CP_IPC_CHECK(cp_mac_sysvmsq_check_msqsnd,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
CP_IPC_CHECK(cp_mac_sysvmsq_check_msqrcv,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused)
CP_IPC_CHECK(cp_mac_sysvmsq_check_msqctl,
    struct msqid_kernel *msqkptr __unused,
    struct label *msqklabel __unused, int cmd __unused)

/* POSIX shm */
CP_IPC_CHECK(cp_mac_posixshm_check_create,
    const char *path __unused)
CP_IPC_CHECK(cp_mac_posixshm_check_open,
    struct shmfd *shmfd __unused, struct label *shmlabel __unused,
    accmode_t accmode __unused)

/* POSIX sem */
CP_IPC_CHECK(cp_mac_posixsem_check_open,
    struct ksem *ks __unused, struct label *kslabel __unused)

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
	.mpo_vnode_check_exec = cp_mac_vnode_check_exec,
	.mpo_socket_check_create = cp_mac_socket_check_create,
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

MAC_POLICY_SET(&cp_mac_ops, mac_mac_capability_capprotect, "MAC_CAPABILITY capability protection",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

static int
mac_capability_capprotect_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		cp_shield_hash = hashinit(CP_HASH_SIZE, M_MAC_CAPABILITY_CP,
		    &cp_shield_hashmask);
		cp_auth_hash = hashinit(CP_HASH_SIZE, M_MAC_CAPABILITY_CP,
		    &cp_auth_hashmask);
		mtx_init(&cp_lock, "mac_capability_capprotect", NULL, MTX_DEF);
		{
			struct mac_capability_service_params p = {
				.name = "capprotect",
				.ops = &cp_ops,
				.flags = MAC_CAPABILITY_SVC_MINTABLE,
			};
			error = mac_capability_service_create(&p, &cp_svc);
		}
		if (error != 0) {
			mtx_destroy(&cp_lock);
			hashdestroy(cp_shield_hash, M_MAC_CAPABILITY_CP, cp_shield_hashmask);
			hashdestroy(cp_auth_hash, M_MAC_CAPABILITY_CP, cp_auth_hashmask);
			return (error);
		}
		cp_exit_tag = EVENTHANDLER_REGISTER(process_exit, cp_process_exit,
		    NULL, EVENTHANDLER_PRI_ANY);
		if (bootverbose)
			printf("mac_capability_capprotect: loaded\n");
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

static moduledata_t mac_capability_capprotect_mod = {
	"mac_capability_capprotect",
	mac_capability_capprotect_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_capprotect, mac_capability_capprotect_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(mac_capability_capprotect, 1);
MODULE_DEPEND(mac_capability_capprotect, mac_capability, 1, 1, 1);
