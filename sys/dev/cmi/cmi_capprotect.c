/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_capprotect — Capability Protection.
 *
 * Sync-only CMI service.  Calling CP_OP_SHIELD with a flags bitmask
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
 *
 * Flags=0 enables all protections.
 * Closing the capability fd removes protection.
 *
 * CP_OP_MINT creates an access token that authorizes a specific
 * foreign program to interact with the shielded program despite
 * the shield.  The token holder must call CP_OP_AUTHORIZE to
 * activate it.
 *
 * Identity is based on the process nonce (from cmi_label).
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
#include <sys/proc.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "cmi.h"
#include "cmi_label.h"
#include "cmi_capprotect_proto.h"

MALLOC_DEFINE(M_CMI_CP, "cmi_cp", "cmi capability protection");

/*
 * Per-instance state.
 *
 * Shield instances track the shielded process nonce.
 * Token instances track the target nonce they authorize access to.
 */
struct cp_priv {
	struct mtx	cp_mtx;
	uint64_t	cp_target;	/* shielded nonce (shield) or target (token) */
	uint32_t	cp_flags;	/* CP_SF_* bitmask (shield instances) */
	int		cp_is_token;	/* 1 if this is an access token */
	int		cp_active;	/* 1 if shield/auth is active */
};

/*
 * Global tables — protected by cp_lock.
 */
static struct mtx cp_lock;

/* Shield table: nonces that are shielded (refcounted). */
struct shield_entry {
	LIST_ENTRY(shield_entry) se_link;
	uint64_t	se_nonce;
	uint32_t	se_flags;
	int		se_refcnt;
};
static LIST_HEAD(, shield_entry) cp_shields =
    LIST_HEAD_INITIALIZER(cp_shields);

/* Auth table: (accessor_nonce, target_nonce) pairs. */
struct auth_entry {
	LIST_ENTRY(auth_entry) ae_link;
	uint64_t	ae_accessor;
	uint64_t	ae_target;
	struct cmi_instance *ae_inst;
};
static LIST_HEAD(, auth_entry) cp_auths =
    LIST_HEAD_INITIALIZER(cp_auths);

static struct cmi_service *cp_svc;
static volatile uint64_t cp_next_badge = 1;

/*
 * Returns the shield flags for a nonce, or 0 if not shielded.
 */
static uint32_t
cp_shield_flags(uint64_t nonce)
{
	struct shield_entry *se;

	mtx_assert(&cp_lock, MA_OWNED);
	LIST_FOREACH(se, &cp_shields, se_link) {
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
	LIST_FOREACH(ae, &cp_auths, ae_link) {
		if (ae->ae_accessor == accessor && ae->ae_target == target)
			return (1);
	}
	return (0);
}

static void
cp_shield_add(uint64_t nonce, uint32_t flags)
{
	struct shield_entry *se, *existing;

	se = malloc(sizeof(*se), M_CMI_CP, M_WAITOK);
	se->se_nonce = nonce;
	se->se_flags = flags;
	se->se_refcnt = 1;

	mtx_lock(&cp_lock);
	LIST_FOREACH(existing, &cp_shields, se_link) {
		if (existing->se_nonce == nonce) {
			existing->se_refcnt++;
			/* Flags are set by the first shield; additional
			 * fds only add a refcount hold. */
			mtx_unlock(&cp_lock);
			free(se, M_CMI_CP);
			return;
		}
	}
	LIST_INSERT_HEAD(&cp_shields, se, se_link);
	mtx_unlock(&cp_lock);
}

static void
cp_shield_remove(uint64_t nonce)
{
	struct shield_entry *se;
	struct auth_entry *ae, *ae_tmp;

	mtx_lock(&cp_lock);
	LIST_FOREACH(se, &cp_shields, se_link) {
		if (se->se_nonce == nonce) {
			if (--se->se_refcnt > 0) {
				mtx_unlock(&cp_lock);
				return;
			}
			LIST_REMOVE(se, se_link);
			free(se, M_CMI_CP);
			break;
		}
	}
	/* Remove all auth entries for this target (only when fully unshielded). */
	LIST_FOREACH_SAFE(ae, &cp_auths, ae_link, ae_tmp) {
		if (ae->ae_target == nonce) {
			LIST_REMOVE(ae, ae_link);
			free(ae, M_CMI_CP);
		}
	}
	mtx_unlock(&cp_lock);
}

static void
cp_auth_add(uint64_t accessor, uint64_t target, struct cmi_instance *inst)
{
	struct auth_entry *ae;

	ae = malloc(sizeof(*ae), M_CMI_CP, M_WAITOK);
	ae->ae_accessor = accessor;
	ae->ae_target = target;
	ae->ae_inst = inst;

	mtx_lock(&cp_lock);
	LIST_INSERT_HEAD(&cp_auths, ae, ae_link);
	mtx_unlock(&cp_lock);
}

static void
cp_auth_remove_by_inst(struct cmi_instance *inst)
{
	struct auth_entry *ae, *ae_tmp;

	mtx_lock(&cp_lock);
	LIST_FOREACH_SAFE(ae, &cp_auths, ae_link, ae_tmp) {
		if (ae->ae_inst == inst) {
			LIST_REMOVE(ae, ae_link);
			free(ae, M_CMI_CP);
		}
	}
	mtx_unlock(&cp_lock);
}

/* ----------------------------------------------------------------
 * CMI service operations
 * ---------------------------------------------------------------- */

static int
cp_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&cp_next_badge, 1);
	return (0);
}

static int
cp_init(struct cmi_instance *s, void *arg __unused)
{
	struct cp_priv *priv;

	priv = malloc(sizeof(*priv), M_CMI_CP, M_WAITOK | M_ZERO);
	mtx_init(&priv->cp_mtx, "cmi_cp_priv", NULL, MTX_DEF);
	cmi_instance_set_priv(s, priv);
	return (0);
}

static int
cp_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused, int nfds __unused,
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
	priv = cmi_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = cmi_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0)
		return (ENXIO);	/* cmi_label not loaded */

	mtx_lock(&priv->cp_mtx);

	switch (cr->op) {
	case CP_OP_SHIELD: {
		uint32_t flags;

		if (priv->cp_is_token) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		if (priv->cp_active) {
			/*
			 * Shield is one-shot per fd — flags are immutable
			 * once set.  To change flags, close and re-open.
			 */
			mtx_unlock(&priv->cp_mtx);
			return (0);
		}
		flags = cr->flags;
		if (flags == 0)
			flags = CP_SF_ALL;
		if (flags & ~CP_SF_ALL) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		priv->cp_target = caller_nonce;
		priv->cp_flags = flags;
		priv->cp_active = 1;
		mtx_unlock(&priv->cp_mtx);
		cp_shield_add(priv->cp_target, flags);
		*replylenp = 0;
		return (0);
	}

	case CP_OP_MINT: {
		struct file *token_fp;
		struct cp_priv *tp;
		uint64_t target;
		int error;

		if (priv->cp_is_token) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		if (!priv->cp_active) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		if (*reply_nfdsp < 1) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		target = priv->cp_target;
		mtx_unlock(&priv->cp_mtx);

		error = cmi_mint_fp(cp_svc, 0, &token_fp);
		if (error != 0)
			return (error);

		tp = cmi_instance_get_priv(token_fp->f_data);
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
		if (!priv->cp_is_token) {
			mtx_unlock(&priv->cp_mtx);
			return (EINVAL);
		}
		if (priv->cp_active) {
			mtx_unlock(&priv->cp_mtx);
			return (0);
		}
		priv->cp_active = 1;
		mtx_unlock(&priv->cp_mtx);
		cp_auth_add(caller_nonce, priv->cp_target, s);
		*replylenp = 0;
		return (0);

	default:
		mtx_unlock(&priv->cp_mtx);
		return (EOPNOTSUPP);
	}
}

static void
cp_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct cp_priv *priv;

	priv = cmi_instance_get_priv(s);
	if (priv == NULL)
		return;

	if (priv->cp_active) {
		if (priv->cp_is_token) {
			cp_auth_remove_by_inst(s);
		} else {
			cp_shield_remove(priv->cp_target);
		}
	}

	mtx_destroy(&priv->cp_mtx);
	free(priv, M_CMI_CP);
}

static const struct cmi_ops cp_ops = {
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
 * ---------------------------------------------------------------- */

static int
cp_mac_check_ptrace(struct ucred *cred, struct proc *p)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == NULL)
		return (0);
	if (curthread->td_proc == p)
		return (0);

	target_nonce = cmi_proc_nonce(p->p_ucred);
	caller_nonce = cmi_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);
	if ((flags & CP_SF_PTRACE) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	denied = !cp_is_authorized(caller_nonce, target_nonce);
	mtx_unlock(&cp_lock);

	return (denied ? EACCES : 0);
}

static int
cp_mac_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == NULL)
		return (0);
	if (curthread->td_proc == p)
		return (0);

	target_nonce = cmi_proc_nonce(p->p_ucred);
	caller_nonce = cmi_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
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

	return (denied ? EACCES : 0);
}

static int
cp_mac_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	uint64_t observer_nonce, target_nonce;
	uint32_t flags;

	if (cr1 == cr2)
		return (0);

	target_nonce = cmi_proc_nonce(cr2);
	if (target_nonce == 0)
		return (0);

	observer_nonce = cmi_proc_nonce(cr1);
	if (observer_nonce == 0)
		return (0);
	if (observer_nonce == target_nonce)
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

	return (ESRCH);
}

static int
cp_mac_proc_check_wait(struct ucred *cred, struct proc *p)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;

	if (curthread->td_proc == NULL)
		return (0);
	if (p->p_pptr == curthread->td_proc)
		return (0);

	target_nonce = cmi_proc_nonce(p->p_ucred);
	caller_nonce = cmi_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
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

	return (EACCES);
}

static int
cp_mac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	uint64_t caller_nonce, target_nonce;
	uint32_t flags;
	int denied;

	if (curthread->td_proc == NULL)
		return (0);
	if (curthread->td_proc == p)
		return (0);

	target_nonce = cmi_proc_nonce(p->p_ucred);
	caller_nonce = cmi_proc_nonce(cred);
	if (target_nonce == 0 || caller_nonce == 0)
		return (0);
	if (caller_nonce == target_nonce)
		return (0);

	mtx_lock(&cp_lock);
	flags = cp_shield_flags(target_nonce);
	if ((flags & CP_SF_SCHED) == 0) {
		mtx_unlock(&cp_lock);
		return (0);
	}
	denied = !cp_is_authorized(caller_nonce, target_nonce);
	mtx_unlock(&cp_lock);

	return (denied ? EACCES : 0);
}

static struct mac_policy_ops cp_mac_ops = {
	.mpo_proc_check_debug = cp_mac_check_ptrace,
	.mpo_proc_check_signal = cp_mac_check_signal,
	.mpo_cred_check_visible = cp_mac_cred_check_visible,
	.mpo_proc_check_wait = cp_mac_proc_check_wait,
	.mpo_proc_check_sched = cp_mac_proc_check_sched,
};

MAC_POLICY_SET(&cp_mac_ops, mac_cmi_capprotect, "CMI capability protection",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
cmi_capprotect_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&cp_lock, "cmi_capprotect", NULL, MTX_DEF);
		{
			struct cmi_service_params p = {
				.name = "capprotect",
				.ops = &cp_ops,
			};
			error = cmi_service_create(&p, &cp_svc);
		}
		if (error != 0) {
			mtx_destroy(&cp_lock);
			return (error);
		}
		if (bootverbose)
			printf("cmi_capprotect: loaded\n");
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

static moduledata_t cmi_capprotect_mod = {
	"cmi_capprotect",
	cmi_capprotect_modevent,
	NULL,
};

DECLARE_MODULE(cmi_capprotect, cmi_capprotect_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_capprotect, 1);
MODULE_DEPEND(cmi_capprotect, cmi, 1, 1, 1);
