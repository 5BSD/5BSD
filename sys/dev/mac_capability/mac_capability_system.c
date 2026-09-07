/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * mac_capability_system — gate privileged system operations.
 *
 * Sync-only MAC_CAPABILITY service.  Calling SYS_OP_CLAIM with a gates
 * bitmask prevents foreign nonces from performing the listed
 * operations via MACF hooks.  Same-nonce processes always pass.
 *
 * Token minting (SYS_OP_MINT + SYS_OP_AUTHORIZE) grants foreign
 * nonces selective access.  Closing the token fd revokes access.
 *
 * Unconfined compatibility callers retain the historical allow-by-default
 * behavior when no operation is claimed.  Capability-mode callers fail
 * closed: a matching claim owned by their nonce, or an authorization minted
 * by that owner, is required for every capability-enabled system gate.
 *
 * Module enumeration (kldstat/kldfind/modfind) is intentionally NOT
 * enforced: it is read-only and required by libdtrace/observability
 * tooling (dtrace(1) walks the kld syscalls to load kernel CTF), so
 * gating it would silently break the observability plane for every
 * foreign nonce, including root.  Only the mutating module operations
 * (KLDLOAD/KLDUNLOAD) are hooked.  The former enumeration gate bit
 * (0x0004) is retired: it is excluded from SYS_GATE_ALL, so a claim
 * carrying it is rejected as unknown.
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

#include "mac_capability.h"
#include "mac_capability_label.h"
#include "mac_capability_system_proto.h"

MALLOC_DEFINE(M_MAC_CAPABILITY_SYS, "mac_capability_sys", "mac_capability system gates");

SDT_PROVIDER_DEFINE(mac_capability_system);
SDT_PROBE_DEFINE3(mac_capability_system, , , deny,
    "const char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE3(mac_capability_system, , , allow,
    "const char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability_system, , , state,
    "const char *", "uint64_t", "uint64_t", "uint32_t", "pid_t", "int");

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
 * Global claim table — one entry per claiming nonce, refcounted per gate.
 * Protected by sys_lock.
 */
struct sys_claim {
	LIST_ENTRY(sys_claim)	sc_link;
	uint64_t		sc_nonce;
	uint32_t		sc_gates;
	u_int			sc_gate_refs[32];
};

struct sys_auth {
	LIST_ENTRY(sys_auth)	sa_link;
	uint64_t		sa_accessor;
	uint64_t		sa_owner;
	uint32_t		sa_gates;
	struct mac_capability_instance	*sa_inst;
};

static struct mtx sys_lock;
static LIST_HEAD(, sys_claim) sys_claims =
    LIST_HEAD_INITIALIZER(sys_claims);
static LIST_HEAD(, sys_auth) sys_auths =
    LIST_HEAD_INITIALIZER(sys_auths);
static volatile int sys_active_claims;
static volatile u_int sys_auth_count;
static struct mac_capability_service *sys_svc;

static u_int sys_max_auth = 4096;

SYSCTL_NODE(_kern, OID_AUTO, mac_capability_system,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "mac_capability system gates");
SYSCTL_UINT(_kern_mac_capability_system, OID_AUTO, max_auth, CTLFLAG_RW,
    &sys_max_auth, 0,
    "Maximum authorization entries per nonce (0 = unlimited)");
SYSCTL_UINT(_kern_mac_capability_system, OID_AUTO, auth_count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &sys_auth_count), 0,
    "Current number of authorization entries");

static void
sys_claim_ref_gates(struct sys_claim *sc, uint32_t gates)
{
	uint32_t bit;
	u_int i;

	mtx_assert(&sys_lock, MA_OWNED);
	for (i = 0, bit = 1; i < nitems(sc->sc_gate_refs); i++, bit <<= 1) {
		if ((gates & bit) == 0)
			continue;
		sc->sc_gate_refs[i]++;
		sc->sc_gates |= bit;
	}
}

static void
sys_claim_unref_gates(struct sys_claim *sc, uint32_t gates)
{
	uint32_t bit;
	u_int i;

	mtx_assert(&sys_lock, MA_OWNED);
	for (i = 0, bit = 1; i < nitems(sc->sc_gate_refs); i++, bit <<= 1) {
		if ((gates & bit) == 0 || sc->sc_gate_refs[i] == 0)
			continue;
		if (--sc->sc_gate_refs[i] == 0)
			sc->sc_gates &= ~bit;
	}
}

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
	bool capmode;

	capmode = (cred->cr_flags & CRED_FLAG_CAPMODE) != 0;
	if (sys_no_claims() && !capmode)
		return (0);

	caller_nonce = mac_capability_proc_nonce(cred);
	if (sys_no_claims()) {
		SDT_PROBE3(mac_capability_system, , , deny, name,
		    (uint64_t)0, caller_nonce);
		return (EPERM);
	}

	mtx_lock(&sys_lock);

	/*
	 * Scan ALL claims covering this gate before deciding — never make a
	 * terminal allow/deny on the first match.  A single gate may be claimed
	 * by more than one nonce; the caller is allowed if it owns ANY covering
	 * claim, or holds an authorization from the owner of ANY covering claim.
	 * Deciding on the first-enumerated claim alone (as this once did) would
	 * spuriously DENY a caller that owns, or is authorized against, a
	 * covering claim that happens to appear later in the list.
	 */
	bool gate_claimed = false;

	LIST_FOREACH(sc, &sys_claims, sc_link) {
		if (!(sc->sc_gates & gate))
			continue;
		gate_claimed = true;
		/* Same nonce — the caller owns a covering claim. */
		if (caller_nonce != 0 && caller_nonce == sc->sc_nonce) {
			mtx_unlock(&sys_lock);
			SDT_PROBE3(mac_capability_system, , , allow, name,
			    sc->sc_nonce, caller_nonce);
			return (0);
		}
		/*
		 * Foreign nonce — an authorization from THIS owner for the gate
		 * suffices.  A labeled caller may still own or be authorized
		 * against a later claim, so keep scanning on no match here; an
		 * unlabeled (nonce 0) caller has no identity to match or
		 * authorize and can only be denied, but that denial waits until
		 * the whole list confirms no covering claim admits it.
		 */
		if (caller_nonce != 0) {
			LIST_FOREACH(sa, &sys_auths, sa_link) {
				if (sa->sa_accessor == caller_nonce &&
				    sa->sa_owner == sc->sc_nonce &&
				    (sa->sa_gates & gate)) {
					mtx_unlock(&sys_lock);
					SDT_PROBE3(mac_capability_system, , ,
					    allow, name, sc->sc_nonce,
					    caller_nonce);
					return (0);
				}
			}
		}
	}

	if (gate_claimed) {
		/*
		 * The gate is claimed, but no covering claim is owned by the
		 * caller and no authorization admits it (an unlabeled caller
		 * lands here too).  Deny.
		 */
		mtx_unlock(&sys_lock);
		SDT_PROBE3(mac_capability_system, , , deny, name,
		    (uint64_t)0, caller_nonce);
		return (EPERM);
	}

	mtx_unlock(&sys_lock);
	if (capmode) {
		SDT_PROBE3(mac_capability_system, , , deny, name,
		    (uint64_t)0, caller_nonce);
		return (EPERM);
	}
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
    struct sysctl_oid *oidp, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{

	/* Only gate writes, not reads. */
	if (req == NULL || req->newptr == NULL)
		return (0);
	/*
	 * setproctitle(3) sets a process's own ps(1) title by WRITING
	 * kern.proc.args (KERN_PROC_ARGS).  The kernel handler for that node
	 * (sysctl_kern_proc_args) already restricts a write to the calling
	 * process itself (PGET_ISCURRENT), so titling is self-contained: it
	 * cannot touch another process or any real kernel tunable.  Exempt it
	 * from the sysctl gate so a born-in-capability-mode daemon shows its own
	 * name in ps rather than the "ld-elf.so.1 -f <fd> ..." loader argv.
	 * Every other sysctl write stays gated exactly as before.
	 */
	if (oidp != NULL && oidp->oid_number == KERN_PROC_ARGS) {
		struct sysctl_oid *parent = SYSCTL_PARENT(oidp);

		if (parent != NULL && parent->oid_number == KERN_PROC)
			return (0);	/* kern.proc.args: setproctitle self-write */
	}
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
 * MAC_CAPABILITY service operations
 * ---------------------------------------------------------------- */

static int
sys_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	*badge_out = 0;
	return (0);
}

static int
sys_init(struct mac_capability_instance *s, void *arg __unused)
{
	struct sys_priv *priv;

	priv = malloc(sizeof(*priv), M_MAC_CAPABILITY_SYS, M_WAITOK | M_ZERO);
	mac_capability_instance_set_priv(s, priv);
	return (0);
}

static int
sys_call(struct mac_capability_instance *s,
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
	priv = mac_capability_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = mac_capability_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0) {
		SDT_PROBE3(mac_capability_system, , , deny, (uintptr_t)"nonce",
		    (uint64_t)0, (uint64_t)0);
		return (ENXIO);
	}

	*replylenp = 0;

	switch (sr->op) {
	case SYS_OP_CLAIM: {
		struct sys_claim *sc, *existing;

			if (sr->gates == 0 || (sr->gates & ~SYS_GATE_ALL) != 0) {
				SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"claim-error",
				    caller_nonce, caller_nonce, sr->gates,
				    curthread->td_proc->p_pid, EINVAL);
				return (EINVAL);
			}

			sc = malloc(sizeof(*sc), M_MAC_CAPABILITY_SYS, M_WAITOK);
			sc->sc_nonce = caller_nonce;
			sc->sc_gates = 0;
			memset(sc->sc_gate_refs, 0, sizeof(sc->sc_gate_refs));

		mtx_lock(&sys_lock);
		if (priv->sp_is_token || priv->sp_active) {
			mtx_unlock(&sys_lock);
			free(sc, M_MAC_CAPABILITY_SYS);
			return (priv->sp_active ? 0 : EINVAL);
		}
		/* Check for existing claim from same nonce. */
			LIST_FOREACH(existing, &sys_claims, sc_link) {
				if (existing->sc_nonce == caller_nonce) {
					sys_claim_ref_gates(existing, sr->gates);
					priv->sp_gates = sr->gates;
					priv->sp_owner = caller_nonce;
					priv->sp_active = true;
				mtx_unlock(&sys_lock);
				free(sc, M_MAC_CAPABILITY_SYS);
				SDT_PROBE6(mac_capability_system, , , state,
				    "claim-ref", caller_nonce, caller_nonce,
				    sr->gates, curthread->td_proc->p_pid, 0);
				return (0);
				}
			}
			sys_claim_ref_gates(sc, sr->gates);
			LIST_INSERT_HEAD(&sys_claims, sc, sc_link);
			atomic_add_int(&sys_active_claims, 1);
		priv->sp_gates = sr->gates;
		priv->sp_owner = caller_nonce;
		priv->sp_active = true;
		mtx_unlock(&sys_lock);
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"claim",
		    caller_nonce, caller_nonce, sr->gates,
		    curthread->td_proc->p_pid, 0);
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
					sys_claim_unref_gates(sc, priv->sp_gates);
					if (sc->sc_gates == 0) {
						LIST_REMOVE(sc, sc_link);
						atomic_subtract_int(
						    &sys_active_claims, 1);
					free(sc, M_MAC_CAPABILITY_SYS);
				}
				break;
			}
		}
		priv->sp_active = false;
		mtx_unlock(&sys_lock);
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"release",
		    priv->sp_owner, caller_nonce, priv->sp_gates,
		    curthread->td_proc->p_pid, 0);
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

		/*
		 * Narrow: if the caller requests specific gates,
		 * intersect with the claim's gates.  Zero means
		 * "all gates from the claim" (backward compat).
		 */
		if (sr->gates != 0) {
			if (sr->gates & ~mint_gates)
				return (EINVAL);  /* requesting gates not owned */
			mint_gates = sr->gates;
		}

		if (*reply_nfdsp < 1)
			return (EINVAL);

		error = mac_capability_mint_fp(sys_svc, 0, &token_fp);
		if (error != 0)
			return (error);

		tp = mac_capability_instance_get_priv(token_fp->f_data);
		if (tp != NULL) {
			tp->sp_is_token = true;
			tp->sp_owner = mint_owner;
			tp->sp_gates = mint_gates;
		}

		reply_fds[0] = token_fp;
		*reply_nfdsp = 1;
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"token-mint",
		    mint_owner, caller_nonce, mint_gates,
		    curthread->td_proc->p_pid, 0);
		return (0);
	}

	case SYS_OP_AUTHORIZE: {
		struct sys_auth *sa, *existing;

		sa = malloc(sizeof(*sa), M_MAC_CAPABILITY_SYS, M_WAITOK | M_ZERO);

		mtx_lock(&sys_lock);
		if (!priv->sp_is_token) {
			mtx_unlock(&sys_lock);
			free(sa, M_MAC_CAPABILITY_SYS);
			return (EINVAL);
		}
		if (priv->sp_active) {
			mtx_unlock(&sys_lock);
			free(sa, M_MAC_CAPABILITY_SYS);
			return (0); /* already authorized */
		}

		/* Dedup: check for existing entry with same key. */
		LIST_FOREACH(existing, &sys_auths, sa_link) {
			if (existing->sa_accessor == caller_nonce &&
			    existing->sa_owner == priv->sp_owner &&
			    existing->sa_inst == s) {
				existing->sa_gates |= priv->sp_gates;
				priv->sp_active = true;
				mtx_unlock(&sys_lock);
				free(sa, M_MAC_CAPABILITY_SYS);
				return (0);
			}
		}
		/* Limit check: count entries for this accessor nonce. */
		if (sys_max_auth != 0) {
			u_int count = 0;

			LIST_FOREACH(existing, &sys_auths, sa_link) {
				if (existing->sa_accessor == caller_nonce)
					count++;
			}
			if (count >= sys_max_auth) {
				mtx_unlock(&sys_lock);
				free(sa, M_MAC_CAPABILITY_SYS);
				return (ENOSPC);
			}
		}

		sa->sa_accessor = caller_nonce;
		sa->sa_owner = priv->sp_owner;
		sa->sa_gates = priv->sp_gates;
		sa->sa_inst = s;
		LIST_INSERT_HEAD(&sys_auths, sa, sa_link);
		atomic_add_int(&sys_auth_count, 1);
		priv->sp_active = true;
		mtx_unlock(&sys_lock);
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"authorize",
		    priv->sp_owner, caller_nonce, priv->sp_gates,
		    curthread->td_proc->p_pid, 0);
		return (0);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
sys_revoke(struct mac_capability_instance *s, uint64_t badge __unused,
    enum mac_capability_revoke_reason reason __unused, void *arg __unused)
{
	struct sys_priv *priv;
	struct sys_claim *sc;
	struct sys_auth *sa, *sa_tmp;

	priv = mac_capability_instance_get_priv(s);
	if (priv == NULL)
		return;

	mtx_lock(&sys_lock);
	if (!priv->sp_active) {
		mtx_unlock(&sys_lock);
		free(priv, M_MAC_CAPABILITY_SYS);
		return;
	}
	priv->sp_active = false;

	if (priv->sp_is_token) {
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"token-remove",
		    priv->sp_owner, 0, priv->sp_gates,
		    curthread->td_proc->p_pid, 0);
		/* Remove auth entries for this token. */
		LIST_FOREACH_SAFE(sa, &sys_auths, sa_link, sa_tmp) {
			if (sa->sa_inst == s) {
				LIST_REMOVE(sa, sa_link);
				atomic_subtract_int(&sys_auth_count, 1);
				free(sa, M_MAC_CAPABILITY_SYS);
			}
		}
	} else {
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"claim-remove",
		    priv->sp_owner, 0, priv->sp_gates,
		    curthread->td_proc->p_pid, 0);
		/* Release claim. */
			LIST_FOREACH(sc, &sys_claims, sc_link) {
				if (sc->sc_nonce == priv->sp_owner) {
					sys_claim_unref_gates(sc, priv->sp_gates);
					if (sc->sc_gates == 0) {
						LIST_REMOVE(sc, sc_link);
						atomic_subtract_int(
						    &sys_active_claims, 1);
					free(sc, M_MAC_CAPABILITY_SYS);
				}
				break;
			}
		}
	}
	mtx_unlock(&sys_lock);

	free(priv, M_MAC_CAPABILITY_SYS);
}

static const struct mac_capability_ops sys_ops = {
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

MAC_POLICY_SET(&sys_mac_ops, mac_mac_capability_system,
    "MAC_CAPABILITY system operation gating",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
mac_capability_system_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	struct mac_capability_service_params p;
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&sys_lock, "mac_capability_system", NULL, MTX_DEF);
		memset(&p, 0, sizeof(p));
		p.name = "system";
		p.ops = &sys_ops;
		error = mac_capability_service_create(&p, &sys_svc);
		if (error != 0) {
			mtx_destroy(&sys_lock);
			return (error);
		}
		if (bootverbose)
			printf("mac_capability_system: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_system_mod = {
	"mac_capability_system",
	mac_capability_system_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_system, mac_capability_system_mod,
    SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(mac_capability_system, mac_capability, 1, 1, 1);
MODULE_VERSION(mac_capability_system, 1);
