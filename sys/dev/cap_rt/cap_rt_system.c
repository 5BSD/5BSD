/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * cap_rt_system — gate privileged system operations.
 *
 * Sync-only CAP_RT service.  Calling SYS_OP_CLAIM with a gates
 * bitmask prevents foreign nonces from performing the listed
 * operations via MACF hooks.  Same-nonce processes always pass.
 *
 * Token minting (SYS_OP_MINT + SYS_OP_AUTHORIZE) grants foreign
 * nonces selective access.  Closing the token fd revokes access.
 *
 * Fast-path: when no operations are claimed (sys_active_claims
 * is 0), all MACF hooks return immediately without touching the
 * mutex.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

#include "cap_rt.h"
#include "cap_rt_label.h"
#include "cap_rt_system_proto.h"

MALLOC_DEFINE(M_CAP_RT_SYS, "cap_rt_sys", "cap_rt system gates");

SDT_PROVIDER_DEFINE(cap_rt_system);
SDT_PROBE_DEFINE3(cap_rt_system, , , deny,
    "const char *", "uint64_t", "uint64_t");

/*
 * Per-instance state.
 */
struct sys_priv {
	uint32_t	sp_gates;	/* claimed gates (claim instances) */
	uint64_t	sp_owner;	/* claimer nonce */
	bool		sp_is_token;
	bool		sp_active;
};

/*
 * Global claim table — one entry per claimed gate set.
 * Protected by sys_lock.
 */
struct sys_claim {
	LIST_ENTRY(sys_claim)	sc_link;
	uint64_t		sc_nonce;
	uint32_t		sc_gates;
	int			sc_refcnt;
};

struct sys_auth {
	LIST_ENTRY(sys_auth)	sa_link;
	uint64_t		sa_accessor;
	uint64_t		sa_owner;
	uint32_t		sa_gates;
	struct cap_rt_instance	*sa_inst;
};

static struct mtx sys_lock;
static LIST_HEAD(, sys_claim) sys_claims =
    LIST_HEAD_INITIALIZER(sys_claims);
static LIST_HEAD(, sys_auth) sys_auths =
    LIST_HEAD_INITIALIZER(sys_auths);
static volatile int sys_active_claims;
static struct cap_rt_service *sys_svc;

static __inline int
sys_no_claims(void)
{

	return (atomic_load_int(&sys_active_claims) == 0);
}

/*
 * Check if any claim covers this gate and whether the caller
 * is authorized.  Returns 0 (allow) or EPERM (deny).
 */
static int
sys_check_gate(struct ucred *cred, uint32_t gate, const char *name)
{
	struct sys_claim *sc;
	struct sys_auth *sa;
	uint64_t caller_nonce;

	if (sys_no_claims())
		return (0);

	caller_nonce = cap_rt_proc_nonce(cred);

	mtx_lock(&sys_lock);

	/* Check if any claim covers this gate. */
	LIST_FOREACH(sc, &sys_claims, sc_link) {
		if (!(sc->sc_gates & gate))
			continue;
		/* Same nonce — always allow. */
		if (caller_nonce != 0 &&
		    caller_nonce == sc->sc_nonce) {
			mtx_unlock(&sys_lock);
			return (0);
		}
		/*
		 * Unlabeled (nonce 0) processes are denied when a
		 * gate is claimed -- they have no identity to authorize.
		 */
		if (caller_nonce == 0) {
			mtx_unlock(&sys_lock);
			SDT_PROBE3(cap_rt_system, , , deny, name,
			    sc->sc_nonce, (uint64_t)0);
			return (EPERM);
		}
		/* Foreign nonce — check authorization. */
		LIST_FOREACH(sa, &sys_auths, sa_link) {
			if (sa->sa_accessor == caller_nonce &&
			    sa->sa_owner == sc->sc_nonce &&
			    (sa->sa_gates & gate)) {
				mtx_unlock(&sys_lock);
				return (0);
			}
		}
		/* Denied. */
		mtx_unlock(&sys_lock);
		SDT_PROBE3(cap_rt_system, , , deny, name,
		    sc->sc_nonce, caller_nonce);
		return (EPERM);
	}

	mtx_unlock(&sys_lock);
	return (0);
}

/* ----------------------------------------------------------------
 * MACF hooks
 * ---------------------------------------------------------------- */

static int
sys_mac_kld_check_load(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused)
{

	return (sys_check_gate(cred, SYS_GATE_KLDLOAD, "kldload"));
}

static int
sys_mac_kld_check_unload(struct ucred *cred)
{

	return (sys_check_gate(cred, SYS_GATE_KLDUNLOAD, "kldunload"));
}

static int
sys_mac_kld_check_stat(struct ucred *cred)
{

	return (sys_check_gate(cred, SYS_GATE_KLDSTAT, "kldstat"));
}

static int
sys_mac_system_check_reboot(struct ucred *cred, int howto __unused)
{

	return (sys_check_gate(cred, SYS_GATE_REBOOT, "reboot"));
}

static int
sys_mac_system_check_swapon(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused)
{

	return (sys_check_gate(cred, SYS_GATE_SWAPON, "swapon"));
}

static int
sys_mac_system_check_swapoff(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused)
{

	return (sys_check_gate(cred, SYS_GATE_SWAPOFF, "swapoff"));
}

static int
sys_mac_system_check_sysctl(struct ucred *cred,
    struct sysctl_oid *oidp __unused, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{

	/* Only gate writes, not reads. */
	if (req == NULL || req->newptr == NULL)
		return (0);
	return (sys_check_gate(cred, SYS_GATE_SYSCTL, "sysctl"));
}

static int
sys_mac_kenv_check_set(struct ucred *cred, char *name __unused,
    char *value __unused)
{

	return (sys_check_gate(cred, SYS_GATE_KENV, "kenv_set"));
}

static int
sys_mac_kenv_check_unset(struct ucred *cred, char *name __unused)
{

	return (sys_check_gate(cred, SYS_GATE_KENV, "kenv_unset"));
}

static int
sys_mac_system_check_acct(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused)
{

	return (sys_check_gate(cred, SYS_GATE_ACCT, "acct"));
}

static int
sys_mac_system_check_auditon(struct ucred *cred, int cmd __unused)
{

	return (sys_check_gate(cred, SYS_GATE_AUDIT, "auditon"));
}

static int
sys_mac_system_check_auditctl(struct ucred *cred, struct vnode *vp __unused,
    struct label *vplabel __unused)
{

	return (sys_check_gate(cred, SYS_GATE_AUDIT, "auditctl"));
}

static int
sys_mac_kenv_check_dump(struct ucred *cred)
{

	return (sys_check_gate(cred, SYS_GATE_KENV_READ, "kenv_dump"));
}

static int
sys_mac_kenv_check_get(struct ucred *cred, char *name __unused)
{

	return (sys_check_gate(cred, SYS_GATE_KENV_READ, "kenv_get"));
}

/* ----------------------------------------------------------------
 * CAP_RT service operations
 * ---------------------------------------------------------------- */

static int
sys_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	*badge_out = 0;
	return (0);
}

static int
sys_init(struct cap_rt_instance *s, void *arg __unused)
{
	struct sys_priv *priv;

	priv = malloc(sizeof(*priv), M_CAP_RT_SYS, M_WAITOK | M_ZERO);
	cap_rt_instance_set_priv(s, priv);
	return (0);
}

static int
sys_call(struct cap_rt_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused,
    void *reply __unused, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct sys_request *sr;
	struct sys_priv *priv;
	uint64_t caller_nonce;

	if (reqlen < sizeof(struct sys_request))
		return (EINVAL);

	sr = (const struct sys_request *)req;
	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = cap_rt_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0)
		return (ENXIO);

	*replylenp = 0;

	switch (sr->op) {
	case SYS_OP_CLAIM: {
		struct sys_claim *sc, *existing;

		if (sr->gates == 0 || (sr->gates & ~SYS_GATE_ALL) != 0)
			return (EINVAL);

		sc = malloc(sizeof(*sc), M_CAP_RT_SYS, M_WAITOK);
		sc->sc_nonce = caller_nonce;
		sc->sc_gates = sr->gates;
		sc->sc_refcnt = 1;

		mtx_lock(&sys_lock);
		if (priv->sp_is_token || priv->sp_active) {
			mtx_unlock(&sys_lock);
			free(sc, M_CAP_RT_SYS);
			return (priv->sp_active ? 0 : EINVAL);
		}
		/* Check for existing claim from same nonce. */
		LIST_FOREACH(existing, &sys_claims, sc_link) {
			if (existing->sc_nonce == caller_nonce) {
				existing->sc_gates |= sr->gates;
				existing->sc_refcnt++;
				priv->sp_gates = sr->gates;
				priv->sp_owner = caller_nonce;
				priv->sp_active = true;
				mtx_unlock(&sys_lock);
				free(sc, M_CAP_RT_SYS);
				return (0);
			}
		}
		LIST_INSERT_HEAD(&sys_claims, sc, sc_link);
		atomic_add_int(&sys_active_claims, 1);
		priv->sp_gates = sr->gates;
		priv->sp_owner = caller_nonce;
		priv->sp_active = true;
		mtx_unlock(&sys_lock);
		return (0);
	}

	case SYS_OP_RELEASE: {
		struct sys_claim *sc;

		mtx_lock(&sys_lock);
		if (!priv->sp_active || priv->sp_is_token) {
			mtx_unlock(&sys_lock);
			return (EINVAL);
		}
		LIST_FOREACH(sc, &sys_claims, sc_link) {
			if (sc->sc_nonce == priv->sp_owner) {
				if (--sc->sc_refcnt <= 0) {
					LIST_REMOVE(sc, sc_link);
					atomic_subtract_int(
					    &sys_active_claims, 1);
					free(sc, M_CAP_RT_SYS);
				}
				break;
			}
		}
		priv->sp_active = false;
		mtx_unlock(&sys_lock);
		return (0);
	}

	case SYS_OP_MINT: {
		struct file *token_fp;
		struct sys_priv *tp;
		uint64_t mint_owner;
		uint32_t mint_gates;
		int error;

		mtx_lock(&sys_lock);
		if (priv->sp_is_token || !priv->sp_active) {
			mtx_unlock(&sys_lock);
			return (EINVAL);
		}
		/* Snapshot priv fields under lock. */
		mint_owner = priv->sp_owner;
		mint_gates = priv->sp_gates;
		mtx_unlock(&sys_lock);

		if (*reply_nfdsp < 1)
			return (EINVAL);

		error = cap_rt_mint_fp(sys_svc, 0, &token_fp);
		if (error != 0)
			return (error);

		tp = cap_rt_instance_get_priv(token_fp->f_data);
		if (tp != NULL) {
			tp->sp_is_token = true;
			tp->sp_owner = mint_owner;
			tp->sp_gates = mint_gates;
		}

		reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		return (0);
	}

	case SYS_OP_AUTHORIZE: {
		struct sys_auth *sa;

		sa = malloc(sizeof(*sa), M_CAP_RT_SYS, M_WAITOK | M_ZERO);

		mtx_lock(&sys_lock);
		if (!priv->sp_is_token) {
			mtx_unlock(&sys_lock);
			free(sa, M_CAP_RT_SYS);
			return (EINVAL);
		}
		if (priv->sp_active) {
			mtx_unlock(&sys_lock);
			free(sa, M_CAP_RT_SYS);
			return (0); /* already authorized */
		}

		sa->sa_accessor = caller_nonce;
		sa->sa_owner = priv->sp_owner;
		sa->sa_gates = priv->sp_gates;
		sa->sa_inst = s;
		LIST_INSERT_HEAD(&sys_auths, sa, sa_link);
		priv->sp_active = true;
		mtx_unlock(&sys_lock);
		return (0);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
sys_revoke(struct cap_rt_instance *s, uint64_t badge __unused,
    enum cap_rt_revoke_reason reason __unused, void *arg __unused)
{
	struct sys_priv *priv;
	struct sys_claim *sc;
	struct sys_auth *sa, *sa_tmp;

	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return;

	mtx_lock(&sys_lock);
	if (!priv->sp_active) {
		mtx_unlock(&sys_lock);
		free(priv, M_CAP_RT_SYS);
		return;
	}
	priv->sp_active = false;

	if (priv->sp_is_token) {
		/* Remove auth entries for this token. */
		LIST_FOREACH_SAFE(sa, &sys_auths, sa_link, sa_tmp) {
			if (sa->sa_inst == s) {
				LIST_REMOVE(sa, sa_link);
				free(sa, M_CAP_RT_SYS);
			}
		}
	} else {
		/* Release claim. */
		LIST_FOREACH(sc, &sys_claims, sc_link) {
			if (sc->sc_nonce == priv->sp_owner) {
				if (--sc->sc_refcnt <= 0) {
					LIST_REMOVE(sc, sc_link);
					atomic_subtract_int(
					    &sys_active_claims, 1);
					free(sc, M_CAP_RT_SYS);
				}
				break;
			}
		}
	}
	mtx_unlock(&sys_lock);

	free(priv, M_CAP_RT_SYS);
}

static const struct cap_rt_ops sys_ops = {
	.co_connect = sys_connect,
	.co_init = sys_init,
	.co_call = sys_call,
	.co_revoke = sys_revoke,
};

/* ----------------------------------------------------------------
 * MACF policy
 * ---------------------------------------------------------------- */

static struct mac_policy_ops sys_mac_ops = {
	.mpo_kld_check_load		= sys_mac_kld_check_load,
	.mpo_kld_check_unload		= sys_mac_kld_check_unload,
	.mpo_kld_check_stat		= sys_mac_kld_check_stat,
	.mpo_system_check_reboot	= sys_mac_system_check_reboot,
	.mpo_system_check_swapon	= sys_mac_system_check_swapon,
	.mpo_system_check_swapoff	= sys_mac_system_check_swapoff,
	.mpo_system_check_sysctl	= sys_mac_system_check_sysctl,
	.mpo_kenv_check_set		= sys_mac_kenv_check_set,
	.mpo_kenv_check_unset		= sys_mac_kenv_check_unset,
	.mpo_system_check_acct		= sys_mac_system_check_acct,
	.mpo_system_check_auditon	= sys_mac_system_check_auditon,
	.mpo_system_check_auditctl	= sys_mac_system_check_auditctl,
	.mpo_kenv_check_dump		= sys_mac_kenv_check_dump,
	.mpo_kenv_check_get		= sys_mac_kenv_check_get,
};

MAC_POLICY_SET(&sys_mac_ops, mac_cap_rt_system,
    "CAP_RT system operation gating",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
cap_rt_system_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	struct cap_rt_service_params p;
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&sys_lock, "cap_rt_system", NULL, MTX_DEF);
		memset(&p, 0, sizeof(p));
		p.name = "system";
		p.ops = &sys_ops;
		error = cap_rt_service_create(&p, &sys_svc);
		if (error != 0) {
			mtx_destroy(&sys_lock);
			return (error);
		}
		if (bootverbose)
			printf("cap_rt_system: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_system_mod = {
	"cap_rt_system",
	cap_rt_system_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_system, cap_rt_system_mod,
    SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(cap_rt_system, cap_rt, 1, 1, 1);
MODULE_VERSION(cap_rt_system, 1);
