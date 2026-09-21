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
#include <sys/syscallsubr.h>	/* kern_settime_gated, kern_jail_set_gated */
#include <sys/time.h>		/* struct timeval, CLOCK_REALTIME */
#include <sys/jail.h>		/* JAIL_* flags */
#include <sys/uio.h>		/* struct uio/iovec for the jail_set option vector */
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
	/*
	 * SYSCTL per-OID isolation (Phase 1).  NULL/0 => COARSE mode: the
	 * SYSCTL gate isolates every privileged sysctl write (current
	 * behavior).  Non-NULL => SCOPED: only the listed OID MIBs are
	 * isolated.  Allocated with the claim, freed on revoke/release.
	 */
	struct sys_sysctl_oid	*sc_sysctl_oids;
	u_int			sc_nsysctl_oids;
	/*
	 * SCOPED once any OID set has been established for this owner.  When
	 * false the SYSCTL gate (if held) is COARSE and isolates every OID.
	 * When true, only the OIDs in sc_sysctl_oids are isolated — even if
	 * that set has been subtracted down to empty (isolates nothing), which
	 * is deliberately distinct from coarse.
	 */
	bool			sc_sysctl_scoped;
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
    "Maximum total authorization entries across all nonces (0 = unlimited)");
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

/* Exact MIB equality of two isolated-OID descriptors. */
static __inline bool
sys_oid_equal(const struct sys_sysctl_oid *a, const struct sys_sysctl_oid *b)
{

	return (a->depth == b->depth &&
	    memcmp(a->mib, b->mib, (size_t)a->depth * sizeof(int)) == 0);
}

/* Is descriptor o already present in the first n entries of set? */
static bool
sys_oidset_contains(const struct sys_sysctl_oid *set, u_int n,
    const struct sys_sysctl_oid *o)
{
	u_int i;

	for (i = 0; i < n; i++)
		if (sys_oid_equal(&set[i], o))
			return (true);
	return (false);
}

/*
 * Parse the optional trailing sys_sysctl_oidset payload of a CLAIM/RELEASE
 * request, fail-closed.  No payload (reqlen == sizeof(sys_request)) yields
 * (*outp = NULL, *noutp = 0, return 0).  A well-formed payload yields a
 * freshly malloc'd, alignment-safe copy of the OID array (caller frees).  Any
 * malformation (short header, out-of-range noids/depth, length mismatch)
 * returns EINVAL and allocates nothing.
 */
static int
sys_parse_oidset(const void *req, size_t reqlen, struct sys_sysctl_oid **outp,
    u_int *noutp)
{
	const struct sys_sysctl_oidset *oset;
	struct sys_sysctl_oid *arr;
	uint32_t noids;
	size_t need;
	u_int i;

	*outp = NULL;
	*noutp = 0;
	if (reqlen <= sizeof(struct sys_request))
		return (0);			/* no payload => coarse */
	if (reqlen < sizeof(struct sys_request) + sizeof(uint32_t))
		return (EINVAL);
	oset = (const struct sys_sysctl_oidset *)((const char *)req +
	    sizeof(struct sys_request));
	memcpy(&noids, &oset->noids, sizeof(noids));
	if (noids < 1 || noids > SYS_SYSCTL_MAXOIDS)
		return (EINVAL);
	need = sizeof(struct sys_request) + sizeof(uint32_t) +
	    (size_t)noids * sizeof(struct sys_sysctl_oid);
	if (reqlen != need)
		return (EINVAL);
	arr = malloc((size_t)noids * sizeof(struct sys_sysctl_oid),
	    M_MAC_CAPABILITY_SYS, M_WAITOK);
	memcpy(arr, oset->oids, (size_t)noids * sizeof(struct sys_sysctl_oid));
	for (i = 0; i < noids; i++) {
		if (arr[i].depth < 1 || arr[i].depth > SYS_OID_MAXDEPTH) {
			free(arr, M_MAC_CAPABILITY_SYS);
			return (EINVAL);
		}
	}
	*outp = arr;
	*noutp = noids;
	return (0);
}

/*
 * Additively UNION the descriptors in add[0..nadd) into sc's isolated-OID set,
 * de-duplicating exact MIB matches (both against the existing set and within
 * add itself).  All-or-nothing: if applying the union would push the total set
 * size past SYS_SYSCTL_MAXOIDS, nothing is added and ENOSPC is returned.  sc
 * must already be scoped with backing storage of at least SYS_SYSCTL_MAXOIDS
 * entries.
 */
static int
sys_oidset_union(struct sys_claim *sc, const struct sys_sysctl_oid *add,
    u_int nadd)
{
	bool isnew[SYS_SYSCTL_MAXOIDS];
	u_int i, j, newcount;

	mtx_assert(&sys_lock, MA_OWNED);
	newcount = 0;
	for (i = 0; i < nadd; i++) {
		isnew[i] = true;
		if (sys_oidset_contains(sc->sc_sysctl_oids, sc->sc_nsysctl_oids,
		    &add[i])) {
			isnew[i] = false;
			continue;
		}
		for (j = 0; j < i; j++) {
			if (isnew[j] && sys_oid_equal(&add[j], &add[i])) {
				isnew[i] = false;
				break;
			}
		}
		if (isnew[i])
			newcount++;
	}
	if (sc->sc_nsysctl_oids + newcount > SYS_SYSCTL_MAXOIDS)
		return (ENOSPC);
	for (i = 0; i < nadd; i++) {
		if (isnew[i])
			sc->sc_sysctl_oids[sc->sc_nsysctl_oids++] = add[i];
	}
	return (0);
}

/*
 * Subtractively remove from sc's isolated-OID set every entry matching any
 * descriptor in rm[0..nrm).  The set may become empty (isolates nothing);
 * because sc stays scoped, that is distinct from coarse.
 */
static void
sys_oidset_subtract(struct sys_claim *sc, const struct sys_sysctl_oid *rm,
    u_int nrm)
{
	u_int i, w;

	mtx_assert(&sys_lock, MA_OWNED);
	w = 0;
	for (i = 0; i < sc->sc_nsysctl_oids; i++) {
		if (sys_oidset_contains(rm, nrm, &sc->sc_sysctl_oids[i]))
			continue;
		if (w != i)
			sc->sc_sysctl_oids[w] = sc->sc_sysctl_oids[i];
		w++;
	}
	sc->sc_nsysctl_oids = w;
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

/*
 * Strict "does the caller actively hold this gate" predicate for the PERFORM
 * ops (SYS_OP_SETTIME / SYS_OP_ADJTIME).
 *
 * sys_check_gate() above implements MACF-HOOK semantics: it ALLOWS an ambient
 * (non-capmode) caller when the gate is unclaimed, because the ambient syscall
 * it guards (settimeofday(2), kldload(2), ...) still runs its own priv_check(9)
 * — the hook only ADDS nonce isolation on top.  A perform op is different: it
 * executes the privileged primitive (kern_settime_gated/kern_adjtime_gated)
 * with NO priv_check behind it, so the claim IS the sole authority.  Reusing
 * sys_check_gate here would let ANY ambient process that can reach the "system"
 * service step the clock while the gate happens to be unclaimed — weaker than
 * the settimeofday(2) it replaces.
 *
 * So this returns 0 ONLY when the caller owns, or is authorized (via a minted +
 * authorized token) against, a claim covering `gate`.  An unclaimed gate, an
 * unlabeled (nonce-0) caller, and a labeled caller lacking the claim ALL deny
 * with EPERM — fail-closed, root included — exactly as
 * mac_capability_system_proto.h promises ("even root is denied unless holding
 * an authorized token").
 */
static int
sys_holds_gate(struct ucred *cred, uint32_t gate, const char *name)
{
	struct sys_claim *sc;
	struct sys_auth *sa;
	uint64_t caller_nonce;

	caller_nonce = mac_capability_proc_nonce(cred);
	if (caller_nonce == 0) {
		SDT_PROBE3(mac_capability_system, , , deny, name,
		    (uint64_t)0, (uint64_t)0);
		return (EPERM);
	}

	mtx_lock(&sys_lock);
	LIST_FOREACH(sc, &sys_claims, sc_link) {
		if (!(sc->sc_gates & gate))
			continue;
		/* Same nonce — the caller owns a covering claim. */
		if (caller_nonce == sc->sc_nonce) {
			mtx_unlock(&sys_lock);
			SDT_PROBE3(mac_capability_system, , , allow, name,
			    sc->sc_nonce, caller_nonce);
			return (0);
		}
		/* Foreign nonce — an authorization from THIS owner suffices. */
		LIST_FOREACH(sa, &sys_auths, sa_link) {
			if (sa->sa_accessor == caller_nonce &&
			    sa->sa_owner == sc->sc_nonce &&
			    (sa->sa_gates & gate)) {
				mtx_unlock(&sys_lock);
				SDT_PROBE3(mac_capability_system, , , allow,
				    name, sc->sc_nonce, caller_nonce);
				return (0);
			}
		}
	}
	mtx_unlock(&sys_lock);
	SDT_PROBE3(mac_capability_system, , , deny, name, (uint64_t)0,
	    caller_nonce);
	return (EPERM);
}

/*
 * Does this claim isolate the accessed sysctl OID (mib,depth)?
 *
 * True iff the claim covers SYS_GATE_SYSCTL AND either it is COARSE
 * (!sc_sysctl_scoped => isolates every OID, the back-compat case) or the
 * (mib,depth) exactly matches one of its stored OID MIBs.  This is the
 * SYSCTL-gate analogue of the plain "sc->sc_gates & gate" covering test used
 * by sys_check_gate; a never-scoped SYSCTL claim reduces to exactly that test,
 * so a coarse SYSCTL claim behaves identically to the old gate.
 */
static bool
sys_claim_isolates_oid(const struct sys_claim *sc, const int *mib, u_int depth)
{
	u_int i;

	mtx_assert(&sys_lock, MA_OWNED);
	if ((sc->sc_gates & SYS_GATE_SYSCTL) == 0)
		return (false);
	if (!sc->sc_sysctl_scoped)
		return (true);		/* coarse: isolates all OIDs */
	for (i = 0; i < sc->sc_nsysctl_oids; i++) {
		if (sc->sc_sysctl_oids[i].depth == depth &&
		    memcmp(sc->sc_sysctl_oids[i].mib, mib,
			(size_t)depth * sizeof(int)) == 0)
			return (true);
	}
	return (false);
}

/*
 * SYSCTL-gate decision, per-OID aware.  This is a faithful copy of
 * sys_check_gate's structure with a single substitution: the per-claim
 * "covering" test is sys_claim_isolates_oid(sc, mib, depth) instead of
 * (sc->sc_gates & gate).  Everything else — the sys_no_claims()/!capmode fast
 * path, nonce-0 handling, same-nonce allow, foreign-authorization allow (the
 * auth must carry SYS_GATE_SYSCTL), the "claimed but not admitted => EPERM",
 * the capmode fail-closed tail, and the allow/deny SDT probes — is identical.
 *
 * Back-compat: with only COARSE SYSCTL claims present, sys_claim_isolates_oid
 * returns (sc->sc_gates & SYS_GATE_SYSCTL) for every OID, so this function
 * makes byte-identical decisions to sys_check_gate(cred, SYS_GATE_SYSCTL).
 */
static int
sys_check_sysctl(struct ucred *cred, const int *mib, u_int depth,
    const char *name)
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
	 * Scan ALL claims that isolate this OID before deciding — same
	 * discipline as sys_check_gate (never make a terminal allow/deny on
	 * the first match).
	 */
	bool gate_claimed = false;

	LIST_FOREACH(sc, &sys_claims, sc_link) {
		if (!sys_claim_isolates_oid(sc, mib, depth))
			continue;
		gate_claimed = true;
		/* Same nonce — the caller owns a covering claim. */
		if (caller_nonce != 0 && caller_nonce == sc->sc_nonce) {
			mtx_unlock(&sys_lock);
			SDT_PROBE3(mac_capability_system, , , allow, name,
			    sc->sc_nonce, caller_nonce);
			return (0);
		}
		/* Foreign nonce — an authorization from THIS owner suffices. */
		if (caller_nonce != 0) {
			LIST_FOREACH(sa, &sys_auths, sa_link) {
				if (sa->sa_accessor == caller_nonce &&
				    sa->sa_owner == sc->sc_nonce &&
				    (sa->sa_gates & SYS_GATE_SYSCTL)) {
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

/*
 * Transiently clear CRED_FLAG_CAPMODE for a gate-authorized kernel operation
 * that must resolve a path (namei) the caller's capability mode would refuse
 * (kldload's module path, jail_set's root path).  The gate has already
 * authorized the operation, so it runs outside the caller's sandbox for the
 * duration; uid/prison are unchanged, only the capmode flag is suspended.
 * Returns the credential to hand to sys_capmode_restore() (NULL if the caller
 * was not in capmode, in which case restore is a no-op).
 */
static struct ucred *
sys_capmode_suspend(void)
{
	struct ucred *saved, *tmp;

	if ((curthread->td_ucred->cr_flags & CRED_FLAG_CAPMODE) == 0)
		return (NULL);
	tmp = crdup(curthread->td_ucred);
	tmp->cr_flags &= ~CRED_FLAG_CAPMODE;
	saved = curthread->td_ucred;
	curthread->td_ucred = tmp;
	return (saved);
}

static void
sys_capmode_restore(struct ucred *saved)
{
	struct ucred *tmp;

	if (saved == NULL)
		return;
	tmp = curthread->td_ucred;
	curthread->td_ucred = saved;
	crfree(tmp);
}

/*
 * Shared marshalling for the SYS_OP_JAIL_SET / SYS_OP_JAIL_GET perform ops (see
 * mac_capability_system_proto.h): parse the daemon's packed jail_set/jail_get
 * option vector into an iovec aliasing the (writable) request buffer, verify
 * the caller holds SYS_GATE_JAIL, then run kern_jail_set_gated() (create; under
 * a capmode suspend for the jail-root path namei) or kern_jail_get() (reuse/
 * list/describe; no path, no priv, so no suspend).  A "desc" param is the slot
 * the kernel fills with the descriptor fd (JAIL_*_DESC), installed in the
 * caller's fd table and returned in the reply; an owning descriptor removes the
 * jail on last close, so it is both the attach target and the lifetime anchor.
 */
static int
sys_jail_uio_call(const void *req, size_t reqlen, void *reply,
    size_t reply_cap, size_t *replylenp, bool is_set)
{
	const struct sys_jail_request *jr;
	struct iovec iov[2 * SYS_JAIL_MAXPARAMS];
	struct sys_jail_param *hdr[SYS_JAIL_MAXPARAMS];
	struct uio auio;
	struct sys_jail_reply jrep;
	struct ucred *saved;
	const uint8_t *p, *pend;
	uint64_t caller_nonce;
	uint32_t i, nparams, buflen, jail_flags;
	size_t resid;
	int desc_iov, error;

	if (reqlen < sizeof(struct sys_jail_request))
		return (EINVAL);
	jr = (const struct sys_jail_request *)req;
	nparams = jr->nparams;
	buflen = jr->buflen;
	jail_flags = jr->jail_flags;
	if (nparams < 1 || nparams > SYS_JAIL_MAXPARAMS ||
	    buflen == 0 || buflen > SYS_JAIL_MAXBUF)
		return (EINVAL);
	if (reqlen < sizeof(struct sys_jail_request) + (size_t)buflen)
		return (EINVAL);
	if (reply == NULL || reply_cap < sizeof(struct sys_jail_reply))
		return (EINVAL);
	/*
	 * Admit only creation/update/query with descriptor return.  Never
	 * JAIL_ATTACH (would attach the broker itself) nor the USE/AT
	 * descriptor-input paths (which would consume a fd from the broker's
	 * table).
	 */
	if ((jail_flags & ~(JAIL_CREATE | JAIL_UPDATE | JAIL_GET_DESC |
	    JAIL_OWN_DESC | JAIL_DYING)) != 0)
		return (EINVAL);

	p = (const uint8_t *)req + sizeof(struct sys_jail_request);
	pend = p + buflen;
	desc_iov = -1;
	for (i = 0; i < nparams; i++) {
		const struct sys_jail_param *pp;
		uint32_t nlen, vlen;
		char *name, *value;

		if ((size_t)(pend - p) < sizeof(struct sys_jail_param))
			return (EINVAL);
		pp = (const struct sys_jail_param *)p;
		hdr[i] = __DECONST(struct sys_jail_param *, pp);
		nlen = pp->name_len;
		vlen = pp->value_len;
		p += sizeof(struct sys_jail_param);
		if (nlen == 0 || (size_t)(pend - p) < nlen)
			return (EINVAL);
		name = __DECONST(char *, p);
		if (name[nlen - 1] != '\0')		/* NUL-terminated name */
			return (EINVAL);
		p += nlen;
		if ((size_t)(pend - p) < vlen)
			return (EINVAL);
		value = __DECONST(char *, p);
		p += vlen;

		iov[2 * i].iov_base = name;
		iov[2 * i].iov_len = nlen;
		iov[2 * i + 1].iov_base = value;
		iov[2 * i + 1].iov_len = vlen;

		if (nlen == sizeof("desc") && strcmp(name, "desc") == 0) {
			if (vlen != sizeof(int))
				return (EINVAL);
			desc_iov = 2 * i + 1;
		}
	}

	caller_nonce = mac_capability_proc_nonce(curthread->td_ucred);
	error = sys_holds_gate(curthread->td_ucred, SYS_GATE_JAIL, "jail");
	if (error != 0) {
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"jail-deny", caller_nonce, caller_nonce,
		    SYS_GATE_JAIL, curthread->td_proc->p_pid, error);
		return (error);
	}

	resid = 0;
	for (i = 0; i < 2 * nparams; i++)
		resid += iov[i].iov_len;
	memset(&auio, 0, sizeof(auio));
	auio.uio_iov = iov;
	auio.uio_iovcnt = (int)(2 * nparams);
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_td = curthread;
	auio.uio_resid = (ssize_t)resid;

	if (is_set) {
		saved = sys_capmode_suspend();	/* for the jail-root path namei */
		error = kern_jail_set_gated(curthread, &auio, jail_flags);
		sys_capmode_restore(saved);
	} else {
		/* jail_get matches by name/jid; no path namei, no priv check. */
		error = kern_jail_get(curthread, &auio, jail_flags);
	}
	if (error != 0)
		return (error);

	memset(&jrep, 0, sizeof(jrep));
	jrep.jid = (int32_t)curthread->td_retval[0];
	jrep.desc_fd = (desc_iov >= 0) ? *(int *)iov[desc_iov].iov_base : -1;
	/*
	 * kern_jail_set/get set td_retval[0] to the jid; reset it so the
	 * MAC_CAPABILITY_CALL ioctl returns 0 (success) rather than leaking the
	 * jid out as the ioctl's return value.  The jid travels in the reply.
	 */
	curthread->td_retval[0] = 0;
	memcpy(reply, &jrep, sizeof(jrep));
	*replylenp = sizeof(jrep);
	/*
	 * If the caller supplied room, append the packed param buffer -- with any
	 * values kern_jail_get() wrote back into it (path, host.hostname, ip*,
	 * vnet) -- after the fixed reply, so a LIST/describe caller can read the
	 * jail's parameters back.  Opportunistic: a create/reuse caller that only
	 * wants the jid + desc passes a small reply buffer and just gets those.
	 */
	if (reply_cap >= sizeof(jrep) + (size_t)buflen) {
		/*
		 * kern_jail_get() rewrote each output param's iov_len to the
		 * actual value length it produced (e.g. an ip4.addr array's real
		 * size, a hostname's real string length).  Fold those lengths
		 * back into the packed param headers so the caller can decode the
		 * returned values without a second size-probing round trip.
		 */
		if (!is_set) {
			for (i = 0; i < nparams; i++)
				hdr[i]->value_len =
				    (uint32_t)iov[2 * i + 1].iov_len;
		}
		memcpy((char *)reply + sizeof(jrep),
		    (const char *)req + sizeof(struct sys_jail_request), buflen);
		*replylenp = sizeof(jrep) + buflen;
	}
	SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"jail",
	    caller_nonce, caller_nonce, SYS_GATE_JAIL,
	    curthread->td_proc->p_pid, 0);
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
	 * The SYSCTL gate scopes PRIVILEGED, security-relevant writes.  An OID
	 * flagged CTLFLAG_ANYBODY is writable by any user by the kernel's own
	 * policy and is never a privileged tunable, so it is not gate-worthy:
	 *
	 *  - the CTL_SYSCTL magic resolution nodes (NAME2OID/NAME/NEXT/OIDFMT/
	 *    OIDDESCR/OIDLABEL) are CTLFLAG_ANYBODY and pass their query input via
	 *    the "new" buffer, so sysctlbyname(3)/sysctlnametomib(3) name lookups
	 *    look like writes but change no state -- gating them would break
	 *    sysctl name resolution for every foreign nonce whenever the SYSCTL
	 *    gate is claimed;
	 *  - kern.proc.args (setproctitle(3)) is CTLFLAG_ANYBODY and self-scoped
	 *    by its handler (PGET_ISCURRENT), so a born-in-capability-mode daemon
	 *    can still set its own ps(1) title.
	 *
	 * Every other (non-ANYBODY) write is already restricted by the kernel to
	 * PRIV_SYSCTL_WRITE holders; those privileged writes are exactly what the
	 * gate scopes, and they stay gated — but only for the specific OIDs the
	 * claim isolates (a coarse claim isolates them all; see sys_check_sysctl).
	 */
	if (oidp != NULL && (oidp->oid_kind & CTLFLAG_ANYBODY) != 0)
		return (0);

	/*
	 * Reconstruct the accessed OID's MIB by walking SYSCTL_PARENT from the
	 * leaf to the root.  The walk yields the numbers leaf-first; reverse
	 * them into root-first MIB order (the same order userland resolves with
	 * sysctlnametomib(3)).  Bounded by SYS_OID_MAXDEPTH == CTL_MAXNAME, so a
	 * pathological over-deep chain is simply truncated (it then matches no
	 * scoped entry — fail-safe — and is still gated by any coarse claim).
	 * The sysctl lock is held across MAC hooks, so the parent chain is
	 * stable during the walk.
	 */
	{
		int rev[SYS_OID_MAXDEPTH], mib[SYS_OID_MAXDEPTH];
		struct sysctl_oid *o;
		u_int depth, i;

		depth = 0;
		for (o = oidp; o != NULL && depth < SYS_OID_MAXDEPTH;
		    o = SYSCTL_PARENT(o))
			rev[depth++] = o->oid_number;
		for (i = 0; i < depth; i++)
			mib[i] = rev[depth - 1 - i];
		return (sys_check_sysctl(cred, mib, depth, "sysctl"));
	}
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
	size_t reply_cap;

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

	/*
	 * The dev layer hands us the caller's reply-buffer capacity in
	 * *replylenp (== ca->reply_len).  Snapshot it before we reset the
	 * field to the "no reply produced" default: an op that returns reply
	 * DATA (e.g. SYS_OP_ADJTIME) needs the capacity to validate the
	 * caller's buffer, and clobbering it here made the very first such op
	 * fail EINVAL.  Ops that produce no reply simply leave *replylenp 0.
	 */
	reply_cap = *replylenp;
	*replylenp = 0;

	switch (sr->op) {
	case SYS_OP_CLAIM: {
		struct sys_claim *sc, *existing, *target;
		struct sys_sysctl_oid *incoming, *storage;
		u_int nincoming;
		int error;

			if (sr->gates == 0 || (sr->gates & ~SYS_GATE_ALL) != 0) {
				SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"claim-error",
				    caller_nonce, caller_nonce, sr->gates,
				    curthread->td_proc->p_pid, EINVAL);
				return (EINVAL);
			}

			/*
			 * Parse the optional SYSCTL OID-set payload (fail-closed).
			 * A payload is only meaningful on a SYSCTL claim; carrying
			 * one without the SYSCTL gate is malformed.
			 */
			incoming = NULL;
			storage = NULL;
			nincoming = 0;
			error = sys_parse_oidset(req, reqlen, &incoming, &nincoming);
			if (error != 0) {
				SDT_PROBE6(mac_capability_system, , , state,
				    (uintptr_t)"claim-error", caller_nonce,
				    caller_nonce, sr->gates,
				    curthread->td_proc->p_pid, error);
				return (error);
			}
			if (nincoming > 0 && (sr->gates & SYS_GATE_SYSCTL) == 0) {
				free(incoming, M_MAC_CAPABILITY_SYS);
				return (EINVAL);
			}

			sc = malloc(sizeof(*sc), M_MAC_CAPABILITY_SYS,
			    M_WAITOK | M_ZERO);
			sc->sc_nonce = caller_nonce;
			/*
			 * Fixed-cap backing storage for a scoped set, allocated
			 * up front (before the lock) so the union can run under
			 * sys_lock without sleeping.  Freed below if unused.
			 */
			if (nincoming > 0)
				storage = malloc(SYS_SYSCTL_MAXOIDS *
				    sizeof(struct sys_sysctl_oid),
				    M_MAC_CAPABILITY_SYS, M_WAITOK | M_ZERO);

		mtx_lock(&sys_lock);
		if (priv->sp_is_token) {
			mtx_unlock(&sys_lock);
			free(sc, M_MAC_CAPABILITY_SYS);
			free(storage, M_MAC_CAPABILITY_SYS);
			free(incoming, M_MAC_CAPABILITY_SYS);
			return (EINVAL);
		}
		/*
		 * A re-CLAIM on an already-active instance is historically a
		 * no-op success — UNLESS it carries an OID payload (a runtime
		 * edit of this owner's scoped set) OR it adds gate bits the
		 * instance does not yet hold.  The latter lets one owner
		 * (capsule) accumulate several coarse gates on a single
		 * persistent connection — e.g. kldload for bsdextension AND
		 * settime for bsdtime — by falling through to the accumulate
		 * branch below.  Without this, a second differing claim would
		 * short-circuit here and the new bits would never be added, so
		 * a later mint of those bits would fail EINVAL.
		 */
		if (priv->sp_active && nincoming == 0 &&
		    (sr->gates & ~priv->sp_gates) == 0) {
			mtx_unlock(&sys_lock);
			free(sc, M_MAC_CAPABILITY_SYS);
			free(storage, M_MAC_CAPABILITY_SYS);
			return (0);
		}
		/* Find any existing claim from this nonce. */
		target = NULL;
			LIST_FOREACH(existing, &sys_claims, sc_link) {
				if (existing->sc_nonce == caller_nonce) {
					target = existing;
					break;
				}
			}
		if (target != NULL) {
			/*
			 * A re-CLAIM edits only the scoped OID set; it must not
			 * change an active instance's gate set (gates are ref'd
			 * once at first claim and released as a unit).  A differing
			 * gate set would be silently dropped below -- the ref is
			 * guarded by !sp_active -- yet the call would return 0.
			 * Reject it before any mutation instead of pretending the
			 * new gates took effect.
			 */
			if (nincoming > 0) {
				if (!target->sc_sysctl_scoped) {
					target->sc_sysctl_oids = storage;
					storage = NULL;
					target->sc_nsysctl_oids = 0;
					target->sc_sysctl_scoped = true;
				}
				error = sys_oidset_union(target, incoming,
				    nincoming);
				if (error != 0) {
					mtx_unlock(&sys_lock);
					free(sc, M_MAC_CAPABILITY_SYS);
					free(storage, M_MAC_CAPABILITY_SYS);
					free(incoming, M_MAC_CAPABILITY_SYS);
					return (error);
				}
			}
			/*
			 * Ref this instance's gates.  On the initial claim, ref
			 * the whole requested set.  On a re-claim by the same
			 * owner, ACCUMULATE: ref only the newly-added bits and
			 * extend the instance's set.  This lets one owner
			 * (capsule) hold several coarse gates on a single
			 * connection — e.g. kldload for bsdextension AND settime
			 * for bsdtime — and mint a scoped token for each.  Only
			 * the added bits are ref'd, so a later unref of the
			 * instance's full set stays balanced; the earlier
			 * reject-on-mismatch existed only because active
			 * instances did not ref new gates (silently dropping
			 * them), which accumulating now fixes directly.
			 */
			if (!priv->sp_active) {
				sys_claim_ref_gates(target, sr->gates);
				priv->sp_gates = sr->gates;
				priv->sp_owner = caller_nonce;
				priv->sp_active = true;
			} else {
				uint32_t added = sr->gates & ~priv->sp_gates;

				if (added != 0) {
					sys_claim_ref_gates(target, added);
					priv->sp_gates |= added;
				}
			}
			mtx_unlock(&sys_lock);
			free(sc, M_MAC_CAPABILITY_SYS);
			free(storage, M_MAC_CAPABILITY_SYS);
			free(incoming, M_MAC_CAPABILITY_SYS);
			SDT_PROBE6(mac_capability_system, , , state,
			    "claim-ref", caller_nonce, caller_nonce,
			    sr->gates, curthread->td_proc->p_pid, 0);
			return (0);
		}
		/* No existing claim: sc becomes the owner's claim. */
		if (nincoming > 0) {
			sc->sc_sysctl_oids = storage;
			storage = NULL;
			sc->sc_nsysctl_oids = 0;
			sc->sc_sysctl_scoped = true;
			error = sys_oidset_union(sc, incoming, nincoming);
			if (error != 0) {
				mtx_unlock(&sys_lock);
				free(sc->sc_sysctl_oids, M_MAC_CAPABILITY_SYS);
				free(sc, M_MAC_CAPABILITY_SYS);
				free(incoming, M_MAC_CAPABILITY_SYS);
				return (error);
			}
		}
		sys_claim_ref_gates(sc, sr->gates);
		LIST_INSERT_HEAD(&sys_claims, sc, sc_link);
		atomic_add_int(&sys_active_claims, 1);
		priv->sp_gates = sr->gates;
		priv->sp_owner = caller_nonce;
		priv->sp_active = true;
		mtx_unlock(&sys_lock);
		free(incoming, M_MAC_CAPABILITY_SYS);
		SDT_PROBE6(mac_capability_system, , , state, (uintptr_t)"claim",
		    caller_nonce, caller_nonce, sr->gates,
		    curthread->td_proc->p_pid, 0);
		return (0);
	}

	case SYS_OP_RELEASE: {
		struct sys_claim *sc;
		struct sys_sysctl_oid *rm;
		u_int nrm;
		int error;

		/* Parse the optional SYSCTL OID-set payload (fail-closed). */
		rm = NULL;
		nrm = 0;
		error = sys_parse_oidset(req, reqlen, &rm, &nrm);
		if (error != 0)
			return (error);
		if (nrm > 0 && (sr->gates & SYS_GATE_SYSCTL) == 0) {
			free(rm, M_MAC_CAPABILITY_SYS);
			return (EINVAL);
		}

		mtx_lock(&sys_lock);
		if (!priv->sp_active || priv->sp_is_token) {
			mtx_unlock(&sys_lock);
			free(rm, M_MAC_CAPABILITY_SYS);
			return (EINVAL);
		}

		if (nrm > 0) {
			/*
			 * Subtractive OID edit: remove exactly these OIDs from
			 * the owner's scoped set.  This does NOT release the
			 * whole SYSCTL claim; the set may shrink to empty (then
			 * isolates nothing, but stays scoped, i.e. not coarse).
			 */
			LIST_FOREACH(sc, &sys_claims, sc_link) {
				if (sc->sc_nonce == priv->sp_owner) {
					if (sc->sc_sysctl_scoped)
						sys_oidset_subtract(sc, rm, nrm);
					break;
				}
			}
			mtx_unlock(&sys_lock);
			free(rm, M_MAC_CAPABILITY_SYS);
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"release-oids", priv->sp_owner,
			    caller_nonce, sr->gates,
			    curthread->td_proc->p_pid, 0);
			return (0);
		}

		/* Empty payload: release the whole claim (historical). */
			LIST_FOREACH(sc, &sys_claims, sc_link) {
				if (sc->sc_nonce == priv->sp_owner) {
					sys_claim_unref_gates(sc, priv->sp_gates);
					if (sc->sc_gates == 0) {
						LIST_REMOVE(sc, sc_link);
						atomic_subtract_int(
						    &sys_active_claims, 1);
					free(sc->sc_sysctl_oids,
					    M_MAC_CAPABILITY_SYS);
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
				SDT_PROBE6(mac_capability_system, , , state,
				    (uintptr_t)"authorize-dedup", priv->sp_owner,
				    caller_nonce, priv->sp_gates,
				    curthread->td_proc->p_pid, 0);
				return (0);
			}
		}
		/*
		 * Global limit: bound the TOTAL number of authorization entries,
		 * not merely this accessor's.  A per-accessor cap is defeated by an
		 * attacker that fork+execs to rotate its nonce cheaply and authorizes
		 * under many distinct nonces, growing sys_auths (and the per-gate
		 * scan in sys_check_gate) without bound.  The global cap bounds both
		 * kernel memory and that scan.  O(1) via the sys_auth_count maintained
		 * under sys_lock at every insert/remove (0 = unlimited).
		 */
		if (sys_max_auth != 0 &&
		    atomic_load_int(&sys_auth_count) >= sys_max_auth) {
			mtx_unlock(&sys_lock);
			free(sa, M_MAC_CAPABILITY_SYS);
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"authorize-nospc", priv->sp_owner,
			    caller_nonce, priv->sp_gates,
			    curthread->td_proc->p_pid, ENOSPC);
			return (ENOSPC);
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

	case SYS_OP_SETTIME: {
		const struct sys_settime_request *str;
		struct timeval tv;
		int error;

		/*
		 * Perform a clock step in kernel context for a holder that owns
		 * (or is authorized against) a claim covering SYS_GATE_SETTIME.
		 * The gate claim replaces PRIV_SETTIMEOFDAY; the raw
		 * settimeofday(2) syscall stays refused in capability mode, so
		 * this never loosens the sandbox.
		 */
		if (reqlen < sizeof(struct sys_settime_request))
			return (EINVAL);
		str = (const struct sys_settime_request *)req;
		if (str->clockid != CLOCK_REALTIME)
			return (EINVAL);
		if (str->nsec < 0 || str->nsec >= 1000000000 || str->sec < 0)
			return (EINVAL);
		error = sys_holds_gate(curthread->td_ucred, SYS_GATE_SETTIME,
		    "settime");
		if (error != 0) {
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"settime-deny", caller_nonce,
			    caller_nonce, SYS_GATE_SETTIME,
			    curthread->td_proc->p_pid, error);
			return (error);
		}
		tv.tv_sec = (time_t)str->sec;
		tv.tv_usec = (suseconds_t)(str->nsec / 1000);
		error = kern_settime_gated(curthread, &tv);
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"settime", caller_nonce, caller_nonce,
		    SYS_GATE_SETTIME, curthread->td_proc->p_pid, error);
		return (error);
	}

	case SYS_OP_ADJTIME: {
		const struct sys_adjtime_request *atr;
		struct sys_adjtime_reply arep;
		struct timeval delta, old;
		int error;

		/* Clock slew; same SYS_GATE_SETTIME authority as SYS_OP_SETTIME. */
		if (reqlen < sizeof(struct sys_adjtime_request))
			return (EINVAL);
		if (reply == NULL ||
		    reply_cap < sizeof(struct sys_adjtime_reply))
			return (EINVAL);
		atr = (const struct sys_adjtime_request *)req;
		if (atr->delta_usec < -999999 || atr->delta_usec > 999999)
			return (EINVAL);
		error = sys_holds_gate(curthread->td_ucred, SYS_GATE_SETTIME,
		    "settime");
		if (error != 0) {
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"adjtime-deny", caller_nonce,
			    caller_nonce, SYS_GATE_SETTIME,
			    curthread->td_proc->p_pid, error);
			return (error);
		}
		delta.tv_sec = (time_t)atr->delta_sec;
		delta.tv_usec = (suseconds_t)atr->delta_usec;
		memset(&old, 0, sizeof(old));
		error = kern_adjtime_gated(curthread, &delta, &old);
		if (error != 0)
			return (error);
		memset(&arep, 0, sizeof(arep));
		arep.old_sec = (int64_t)old.tv_sec;
		arep.old_usec = (int64_t)old.tv_usec;
		memcpy(reply, &arep, sizeof(arep));
		*replylenp = sizeof(arep);
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"adjtime", caller_nonce, caller_nonce,
		    SYS_GATE_SETTIME, curthread->td_proc->p_pid, 0);
		return (0);
	}

	case SYS_OP_SYSCTL: {
		const struct sys_sysctl_request *sysr;
		void *newp, *oldp;
		size_t oldlen, retval;
		u_int depth, i;
		int mib[SYS_OID_MAXDEPTH];
		int error;

		/*
		 * Perform a sysctl read/write in kernel context for a holder of a
		 * SYS_GATE_SYSCTL claim covering this OID.  Capability mode confines
		 * the raw __sysctl(2) to CTLFLAG_CAPRD/CAPWR nodes, so a
		 * born-in-capmode broker cannot touch an arbitrary node directly;
		 * kernel_sysctl(SCTL_GATED) runs it THROUGH the held capability,
		 * skipping the capmode node confinement and PRIV_SYSCTL_WRITE while
		 * keeping securelevel + the MAC hook.  The raw syscall stays confined,
		 * so the sandbox is never loosened.
		 */
		if (reqlen < sizeof(struct sys_sysctl_request))
			return (EINVAL);
		sysr = (const struct sys_sysctl_request *)req;
		depth = sysr->depth;
		if (depth < 1 || depth > SYS_OID_MAXDEPTH)
			return (EINVAL);
		/* A write appends newlen bytes of new value after the header. */
		if (sysr->newlen > 0) {
			if (reqlen < sizeof(struct sys_sysctl_request) +
			    (size_t)sysr->newlen)
				return (EINVAL);
			newp = __DECONST(void *, (const char *)req +
			    sizeof(struct sys_sysctl_request));
		} else
			newp = NULL;
		/* The old value goes into the caller's reply buffer; bound it. */
		if (sysr->oldlen > reply_cap)
			return (EINVAL);
		if (sysr->oldlen > 0 && reply == NULL)
			return (EINVAL);
		for (i = 0; i < depth; i++)
			mib[i] = sysr->mib[i];

		/*
		 * Authorize: the caller must actively hold SYS_GATE_SYSCTL (own
		 * the claim, or hold an authorized token).  This is the coarse
		 * "may broker sysctls" authority -- deliberately NOT narrowed to a
		 * scoped claim's isolate set: switchboard only ever mints the sysctl
		 * gate in SCOPED form (a bare coarse claim would make the MACF hook
		 * isolate every sysctl write system-wide), yet a born-in-capmode
		 * broker must perform on arbitrary OIDs.  The isolate set governs
		 * only which OIDs are protected from OTHER nonces (sys_check_sysctl);
		 * which OIDs THIS broker may touch is bounded by its per-label
		 * config, not the claim.  The gate replaces PRIV_SYSCTL_WRITE.
		 */
		error = sys_holds_gate(curthread->td_ucred, SYS_GATE_SYSCTL,
		    "sysctl");
		if (error != 0) {
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"sysctl-deny", caller_nonce, caller_nonce,
			    SYS_GATE_SYSCTL, curthread->td_proc->p_pid, error);
			return (error);
		}

		oldp = (sysr->oldlen > 0) ? reply : NULL;
		oldlen = sysr->oldlen;
		retval = 0;
		error = kernel_sysctl(curthread, mib, depth, oldp,
		    (oldp != NULL) ? &oldlen : NULL, newp, (size_t)sysr->newlen,
		    &retval, SCTL_GATED);
		if (error != 0)
			return (error);
		*replylenp = (oldp != NULL) ? retval : 0;
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"sysctl", caller_nonce, caller_nonce,
		    SYS_GATE_SYSCTL, curthread->td_proc->p_pid, 0);
		return (0);
	}

	case SYS_OP_KLDLOAD: {
		const struct sys_kldload_request *klr;
		const char *name;
		struct sys_kldload_reply krep;
		int fileid, error;

		/*
		 * Load a kernel module in kernel context for a holder of
		 * SYS_GATE_KLDLOAD.  kldload(2) is capmode-enabled but runs
		 * priv_check(PRIV_KLD_LOAD), which the unprivileged capability
		 * user fails; kern_kldload_gated() lets the held gate stand in for
		 * that privilege (securelevel still applies).
		 */
		if (reqlen < sizeof(struct sys_kldload_request))
			return (EINVAL);
		klr = (const struct sys_kldload_request *)req;
		if (klr->namelen < 1 || klr->namelen > SYS_KLD_NAME_MAX)
			return (EINVAL);
		if (reqlen < sizeof(struct sys_kldload_request) +
		    (size_t)klr->namelen)
			return (EINVAL);
		if (reply == NULL || reply_cap < sizeof(struct sys_kldload_reply))
			return (EINVAL);
		name = (const char *)req + sizeof(struct sys_kldload_request);
		if (name[klr->namelen - 1] != '\0')	/* must be NUL-terminated */
			return (EINVAL);
		error = sys_holds_gate(curthread->td_ucred, SYS_GATE_KLDLOAD,
		    "kldload");
		if (error != 0) {
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"kldload-deny", caller_nonce, caller_nonce,
			    SYS_GATE_KLDLOAD, curthread->td_proc->p_pid, error);
			return (error);
		}
		fileid = -1;
		/*
		 * Perform the load outside the caller's capability-mode sandbox.
		 * The linker resolves the module against the kernel module path
		 * with a namei that vfs_lookup() refuses in capability mode
		 * (absolute paths are ENOTCAPABLE), so a born-in-capmode broker's
		 * gated load would otherwise fail to find any module.  The gate has
		 * already authorized the load (SYS_GATE_KLDLOAD, above), so run
		 * kern_kldload_gated() under a transient duplicate credential with
		 * CRED_FLAG_CAPMODE cleared, restored immediately after -- the same
		 * principle as SCTL_GATED lifting the capmode sysctl confinement.
		 * uid/prison are unchanged; only the sandbox flag is suspended, and
		 * only for this authorized kernel operation.
		 */
		{
			struct ucred *savedcred = NULL, *tmpcred;

			if ((curthread->td_ucred->cr_flags &
			    CRED_FLAG_CAPMODE) != 0) {
				tmpcred = crdup(curthread->td_ucred);
				tmpcred->cr_flags &= ~CRED_FLAG_CAPMODE;
				savedcred = curthread->td_ucred;
				curthread->td_ucred = tmpcred;
			}
			error = kern_kldload_gated(curthread, name, &fileid);
			if (savedcred != NULL) {
				tmpcred = curthread->td_ucred;
				curthread->td_ucred = savedcred;
				crfree(tmpcred);
			}
		}
		if (error != 0)
			return (error);
		memset(&krep, 0, sizeof(krep));
		krep.fileid = fileid;
		memcpy(reply, &krep, sizeof(krep));
		*replylenp = sizeof(krep);
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"kldload", caller_nonce, caller_nonce,
		    SYS_GATE_KLDLOAD, curthread->td_proc->p_pid, 0);
		return (0);
	}

	case SYS_OP_KLDUNLOAD: {
		const struct sys_kldunload_request *kur;
		int error;

		/* Unload for a holder of SYS_GATE_KLDUNLOAD (gate replaces priv). */
		if (reqlen < sizeof(struct sys_kldunload_request))
			return (EINVAL);
		kur = (const struct sys_kldunload_request *)req;
		error = sys_holds_gate(curthread->td_ucred, SYS_GATE_KLDUNLOAD,
		    "kldunload");
		if (error != 0) {
			SDT_PROBE6(mac_capability_system, , , state,
			    (uintptr_t)"kldunload-deny", caller_nonce,
			    caller_nonce, SYS_GATE_KLDUNLOAD,
			    curthread->td_proc->p_pid, error);
			return (error);
		}
		error = kern_kldunload_gated(curthread, kur->fileid, kur->flags);
		SDT_PROBE6(mac_capability_system, , , state,
		    (uintptr_t)"kldunload", caller_nonce, caller_nonce,
		    SYS_GATE_KLDUNLOAD, curthread->td_proc->p_pid, error);
		return (error);
	}

	case SYS_OP_JAIL_SET:
		return (sys_jail_uio_call(req, reqlen, reply, reply_cap,
		    replylenp, true));

	case SYS_OP_JAIL_GET:
		return (sys_jail_uio_call(req, reqlen, reply, reply_cap,
		    replylenp, false));

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
					free(sc->sc_sysctl_oids,
					    M_MAC_CAPABILITY_SYS);
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
