/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_file_isolation — Resource Isolation capability service.
 *
 * Allows processes to claim resources so that only processes sharing
 * the claimer's CAP_RT nonce can interact with them.
 *
 * Supported resource types:
 *
 *   Files/vnodes:  open, exec, unlink, link, rename, chmod, chown,
 *                  chflags, utimes, truncate, stat, access, readlink,
 *                  connect (AF_UNIX)
 *
 *   Directories:   lookup (gates access to entire subtree)
 *
 *   Network:       socket create (domain-wide), bind, connect
 *                  (per port/address/protocol/direction tuple)
 *
 * Claims are bound to the cap_rt instance fd.  When the instance is
 * revoked or closed, all claims are released automatically.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/imgact.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <netinet/in.h>

#include <security/mac/mac_policy.h>

#include <dev/cap_rt/cap_rt.h>
#include <dev/cap_rt/cap_rt_label.h>
#include <dev/cap_rt/cap_rt_file_isolation_proto.h>

static MALLOC_DEFINE(M_FILE_ISOLATION, "cap_rt_fi",
    "cap_rt file isolation");

/* ----------------------------------------------------------------
 * Isolation hash table
 * ---------------------------------------------------------------- */

#define	FI_HASH_SIZE	64

struct fi_claim {
	LIST_ENTRY(fi_claim)	fi_hashlink;	/* global hash bucket */
	LIST_ENTRY(fi_claim)	fi_instlink;	/* per-instance list */
	struct vnode		*fi_vp;		/* held vnode ref */
	uint64_t		 fi_nonce;	/* owning nonce */
	struct cap_rt_instance	*fi_inst;	/* owning instance */
};

/* ----------------------------------------------------------------
 * Network isolation hash table
 * ---------------------------------------------------------------- */

#define	FI_NET_HASH_SIZE	32

struct fi_net_claim {
	LIST_ENTRY(fi_net_claim) fn_hashlink;
	LIST_ENTRY(fi_net_claim) fn_instlink;
	int		fn_domain;	/* AF_INET, AF_INET6, 0=any */
	int		fn_protocol;	/* IPPROTO_TCP, etc., 0=any */
	uint16_t	fn_port;	/* network byte order, 0=any */
	uint8_t		fn_direction;	/* FI_NET_* bitmask */
	uint8_t		fn_prefix;	/* CIDR prefix, 0=any */
	struct in6_addr	fn_addr;	/* v6 or v4-mapped, zero=any */
	uint64_t	fn_nonce;
	struct cap_rt_instance *fn_inst;
};

struct fi_priv {
	LIST_HEAD(, fi_claim)	    fip_claims;	    /* vnode claims */
	LIST_HEAD(, fi_net_claim)   fip_net_claims; /* network claims */
};

static LIST_HEAD(, fi_claim)	*fi_hash;
static u_long			 fi_hashmask;
static struct rwlock		 fi_lock;
static volatile u_int		 fi_claim_count;	/* fast-path for file hooks */
static volatile u_int		 fi_dir_claim_count;	/* fast-path for lookup hook */

static LIST_HEAD(, fi_net_claim) *fi_net_hash;
static u_long			  fi_net_hashmask;
static struct rwlock		  fi_net_lock;
static volatile u_int		  fi_net_claim_count;	/* fast-path for socket hooks */
static struct cap_rt_service	*fi_svc;

static __inline u_long
fi_hash_vp(struct vnode *vp)
{

	return (((uintptr_t)vp >> 8) & fi_hashmask);
}

/*
 * Lookup a claim by vnode.  Caller must hold fi_lock (read or write).
 */
static struct fi_claim *
fi_claim_lookup(struct vnode *vp)
{
	struct fi_claim *c;

	LIST_FOREACH(c, &fi_hash[fi_hash_vp(vp)], fi_hashlink) {
		if (c->fi_vp == vp)
			return (c);
	}
	return (NULL);
}

/* ----------------------------------------------------------------
 * MACF enforcement — common check
 * ---------------------------------------------------------------- */

/*
 * Return EACCES if vp is isolated and cred's nonce does not match.
 * Returns 0 (allow) in all other cases.
 */
static int
fi_check_vp(struct ucred *cred, struct vnode *vp)
{
	struct fi_claim *c;
	uint64_t caller_nonce;

	if (atomic_load_acq_int(&fi_claim_count) == 0)
		return (0);

	caller_nonce = cap_rt_proc_nonce(cred);

	rw_rlock(&fi_lock);
	c = fi_claim_lookup(vp);
	if (c == NULL) {
		rw_runlock(&fi_lock);
		return (0);
	}
	if (caller_nonce != 0 && caller_nonce == c->fi_nonce) {
		rw_runlock(&fi_lock);
		return (0);
	}
	rw_runlock(&fi_lock);
	return (EACCES);
}

/* --- Content access --- */

static int
fi_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, accmode_t accmode __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{

	return (fi_check_vp(cred, vp));
}

/* --- Namespace mutation --- */

static int
fi_check_unlink(struct ucred *cred, struct vnode *dvp __unused,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_link(struct ucred *cred, struct vnode *dvp __unused,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_rename_from(struct ucred *cred, struct vnode *dvp __unused,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_rename_to(struct ucred *cred, struct vnode *dvp __unused,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, int samedir __unused,
    struct componentname *cnp __unused)
{

	if (vp == NULL)
		return (0);	/* target does not exist yet */
	return (fi_check_vp(cred, vp));
}

/* --- Metadata mutation --- */

static int
fi_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, mode_t mode __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, uid_t uid __unused,
    gid_t gid __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, u_long flags __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, struct timespec atime __unused,
    struct timespec mtime __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_truncate(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp(cred, vp));
}

/* --- Information disclosure --- */

static int
fi_check_stat(struct ucred *active_cred, struct ucred *file_cred __unused,
    struct vnode *vp, struct label *vplabel __unused)
{

	return (fi_check_vp(active_cred, vp));
}

static int
fi_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, accmode_t accmode __unused)
{

	return (fi_check_vp(cred, vp));
}

static int
fi_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp(cred, vp));
}

/* --- Directory traversal --- */

static int
fi_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct componentname *cnp __unused)
{
	struct fi_claim *c;
	uint64_t caller_nonce;

	/*
	 * Separate fast-path counter for directory claims.
	 * This hook fires on EVERY path component traversal, so
	 * it must be zero-cost when no directories are claimed —
	 * even if file claims exist.
	 */
	if (atomic_load_acq_int(&fi_dir_claim_count) == 0)
		return (0);

	caller_nonce = cap_rt_proc_nonce(cred);

	rw_rlock(&fi_lock);
	c = fi_claim_lookup(dvp);
	if (c == NULL) {
		rw_runlock(&fi_lock);
		return (0);
	}
	if (caller_nonce != 0 && caller_nonce == c->fi_nonce) {
		rw_runlock(&fi_lock);
		return (0);
	}
	rw_runlock(&fi_lock);
	return (EACCES);
}

/* --- Unix domain sockets --- */

static int
fi_check_uipc_connect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp(cred, vp));
}

/* ----------------------------------------------------------------
 * Network isolation — MACF hooks and helpers
 * ---------------------------------------------------------------- */

static __inline u_long
fi_net_hash_fn(uint16_t port, int domain)
{

	return (((u_long)port ^ (u_long)domain) & fi_net_hashmask);
}

static bool
fi_net_addr_is_wildcard(const struct in6_addr *addr)
{
	static const struct in6_addr zero_addr;

	return (memcmp(addr, &zero_addr, sizeof(*addr)) == 0);
}

static bool
fi_net_addr_prefix_match(const struct in6_addr *a, const struct in6_addr *b,
    uint8_t prefix)
{
	uint8_t full_bytes, rem_bits, mask;

	if (prefix >= 128)
		return (memcmp(a, b, sizeof(*a)) == 0);

	full_bytes = prefix / 8;
	rem_bits = prefix % 8;
	if (memcmp(a, b, full_bytes) != 0)
		return (false);
	if (rem_bits == 0)
		return (true);
	mask = (uint8_t)(0xff << (8 - rem_bits));
	return ((a->s6_addr[full_bytes] & mask) ==
	    (b->s6_addr[full_bytes] & mask));
}

static bool
fi_net_claim_addr_overlap(const struct fi_net_claim *existing,
    const struct fi_net_request *nr)
{
	struct in6_addr req_addr;
	uint8_t existing_prefix, req_prefix;

	memcpy(&req_addr, nr->addr, sizeof(req_addr));
	if (fi_net_addr_is_wildcard(&existing->fn_addr) ||
	    fi_net_addr_is_wildcard(&req_addr))
		return (true);

	existing_prefix = existing->fn_prefix == 0 ? 128 :
	    MIN(existing->fn_prefix, (uint8_t)128);
	req_prefix = nr->prefix == 0 ? 128 : MIN(nr->prefix, (uint8_t)128);

	return (fi_net_addr_prefix_match(&existing->fn_addr, &req_addr,
	    MIN(existing_prefix, req_prefix)));
}

/*
 * Compare address from sockaddr against a claim's address/prefix.
 * Returns true if the address matches the claim.
 * All-zero claim address means "any" (wildcard).
 */
static bool
fi_net_addr_match(const struct fi_net_claim *nc, struct sockaddr *sa)
{
	struct in6_addr sa_addr;

	/* All-zero = wildcard, matches anything */
	if (fi_net_addr_is_wildcard(&nc->fn_addr))
		return (true);

	if (sa == NULL)
		return (false);

	/* Extract address into v6 form */
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		/* Map to v4-mapped v6 */
		memset(&sa_addr, 0, sizeof(sa_addr));
		sa_addr.s6_addr[10] = 0xff;
		sa_addr.s6_addr[11] = 0xff;
		memcpy(&sa_addr.s6_addr[12], &sin->sin_addr, 4);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		sa_addr = sin6->sin6_addr;
	} else {
		return (false);
	}

	/* Exact match if no prefix specified */
	if (nc->fn_prefix == 0 || nc->fn_prefix >= 128)
		return (memcmp(&nc->fn_addr, &sa_addr, 16) == 0);

	/* CIDR prefix match */
	{
		uint8_t full_bytes = nc->fn_prefix / 8;
		uint8_t rem_bits = nc->fn_prefix % 8;

		if (memcmp(&nc->fn_addr, &sa_addr, full_bytes) != 0)
			return (false);
		if (rem_bits == 0)
			return (true);
		uint8_t mask = (uint8_t)(0xff << (8 - rem_bits));
		return ((nc->fn_addr.s6_addr[full_bytes] & mask) ==
		    (sa_addr.s6_addr[full_bytes] & mask));
	}
}

/*
 * Check whether (domain, protocol, addr, port, direction) matches
 * a network claim.  Fields set to 0 in the claim are wildcards.
 */
static int
fi_net_check(struct ucred *cred, int domain, int protocol,
    struct sockaddr *sa, uint8_t direction)
{
	struct fi_net_claim *nc;
	uint64_t caller_nonce;
	uint16_t port = 0;

	if (atomic_load_acq_int(&fi_net_claim_count) == 0)
		return (0);

	/* Extract port from sockaddr */
	if (sa != NULL) {
		if (sa->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;
			port = sin->sin_port;
		} else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
			port = sin6->sin6_port;
		}
	}

	caller_nonce = cap_rt_proc_nonce(cred);

	rw_rlock(&fi_net_lock);

	/*
	 * Probe all 4 wildcard combinations of (port, domain):
	 *   (port, domain)  — exact match
	 *   (0, domain)     — "any port on this domain"
	 *   (port, 0)       — "this port on any domain"
	 *   (0, 0)          — "anything"
	 *
	 * Two-pass logic:
	 *   1. If ANY matching claim has our nonce → allow immediately.
	 *   2. If claims exist but none match our nonce → EACCES.
	 *   3. If no claims match at all → allow (unclaimed resource).
	 */
	{
		u_long buckets[4];
		int nbuckets = 4, i, j;
		bool found_claim = false;
		bool dup;

		buckets[0] = fi_net_hash_fn(port, domain);
		buckets[1] = fi_net_hash_fn(0, domain);
		buckets[2] = fi_net_hash_fn(port, 0);
		buckets[3] = fi_net_hash_fn(0, 0);

		for (i = 0; i < nbuckets; i++) {
			dup = false;
			for (j = 0; j < i; j++) {
				if (buckets[j] == buckets[i]) {
					dup = true;
					break;
				}
			}
			if (dup)
				continue;

			LIST_FOREACH(nc, &fi_net_hash[buckets[i]],
			    fn_hashlink) {
				if (!(nc->fn_direction & direction))
					continue;
				if (nc->fn_domain != 0 &&
				    nc->fn_domain != domain)
					continue;
				if (nc->fn_protocol != 0 &&
				    nc->fn_protocol != protocol)
					continue;
				if (nc->fn_port != 0 &&
				    nc->fn_port != port)
					continue;
				if (!fi_net_addr_match(nc, sa))
					continue;
				/* Claim matches */
				if (caller_nonce != 0 &&
				    caller_nonce == nc->fn_nonce) {
					/* Our claim — allow */
					rw_runlock(&fi_net_lock);
					return (0);
				}
				found_claim = true;
			}
		}

		if (found_claim) {
			rw_runlock(&fi_net_lock);
			return (EACCES);
		}
	}

	rw_runlock(&fi_net_lock);
	return (0);
}

static int
fi_check_socket_create(struct ucred *cred, int domain, int type __unused,
    int protocol)
{
	struct fi_net_claim *nc;
	uint64_t caller_nonce;

	if (atomic_load_acq_int(&fi_net_claim_count) == 0)
		return (0);

	caller_nonce = cap_rt_proc_nonce(cred);

	/*
	 * Only enforce for domain-wide claims: port=0, addr=0, and
	 * direction=FI_NET_ANY.  This prevents per-port or per-address
	 * claims from accidentally blocking socket creation.
	 * Only a fully-wildcard "block all networking" claim triggers here.
	 */
	rw_rlock(&fi_net_lock);
	{
		static const struct in6_addr zero_addr;
		u_long buckets[2];
		int i;

		buckets[0] = fi_net_hash_fn(0, domain);
		buckets[1] = fi_net_hash_fn(0, 0);

		for (i = 0; i < 2; i++) {
			if (i == 1 && buckets[1] == buckets[0])
				continue;
			LIST_FOREACH(nc, &fi_net_hash[buckets[i]],
			    fn_hashlink) {
				if (nc->fn_domain != 0 &&
				    nc->fn_domain != domain)
					continue;
				if (nc->fn_protocol != 0 &&
				    nc->fn_protocol != protocol)
					continue;
				if (nc->fn_port != 0)
					continue;
				if (nc->fn_direction != FI_NET_ANY)
					continue;
				if (memcmp(&nc->fn_addr, &zero_addr,
				    sizeof(zero_addr)) != 0)
					continue;
				/* Fully-wild claim — check nonce */
				if (caller_nonce != 0 &&
				    caller_nonce == nc->fn_nonce) {
					rw_runlock(&fi_net_lock);
					return (0);
				}
				rw_runlock(&fi_net_lock);
				return (EACCES);
			}
		}
	}
	rw_runlock(&fi_net_lock);
	return (0);
}

static int
fi_check_socket_bind(struct ucred *cred, struct socket *so,
    struct label *solabel __unused, struct sockaddr *sa)
{
	int proto;

	if (sa == NULL)
		return (0);
	proto = so->so_proto->pr_protocol;
	return (fi_net_check(cred, sa->sa_family, proto, sa, FI_NET_BIND));
}

static int
fi_check_socket_connect(struct ucred *cred, struct socket *so,
    struct label *solabel __unused, struct sockaddr *sa)
{
	int proto;

	if (sa == NULL)
		return (0);
	proto = so->so_proto->pr_protocol;
	return (fi_net_check(cred, sa->sa_family, proto, sa, FI_NET_CONNECT));
}

/* listen and accept not hooked — bind is the enforcement point */

/* ----------------------------------------------------------------
 * Service operations
 * ---------------------------------------------------------------- */

static int
fi_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	static volatile uint64_t next_badge;

	*badge_out = atomic_fetchadd_64(&next_badge, 1);
	return (0);
}

static int
fi_init(struct cap_rt_instance *s, void *arg __unused)
{
	struct fi_priv *priv;

	priv = malloc(sizeof(*priv), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	LIST_INIT(&priv->fip_claims);
	LIST_INIT(&priv->fip_net_claims);
	cap_rt_instance_set_priv(s, priv);
	return (0);
}

static int
fi_do_claim(struct cap_rt_instance *s, struct fi_priv *priv,
    struct file *fp, uint64_t nonce)
{
	struct vnode *vp;
	struct fi_claim *c, *existing;

	vp = fp->f_vnode;
	if (vp == NULL)
		return (EINVAL);

	/* Pre-allocate outside the lock. */
	c = malloc(sizeof(*c), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	vref(vp);

	c->fi_vp = vp;
	c->fi_nonce = nonce;
	c->fi_inst = s;

	rw_wlock(&fi_lock);
	existing = fi_claim_lookup(vp);
	if (existing != NULL) {
		if (existing->fi_nonce != nonce) {
			rw_wunlock(&fi_lock);
			vrele(vp);
			free(c, M_FILE_ISOLATION);
			return (EBUSY);
		}
		/*
		 * Same nonce re-claim: transfer ownership to this
		 * instance so the claim's lifetime tracks the most
		 * recent claimer.
		 */
		LIST_REMOVE(existing, fi_instlink);
		LIST_INSERT_HEAD(&priv->fip_claims, existing, fi_instlink);
		existing->fi_inst = s;
		rw_wunlock(&fi_lock);
		vrele(vp);
		free(c, M_FILE_ISOLATION);
		return (0);
	}

	LIST_INSERT_HEAD(&fi_hash[fi_hash_vp(vp)], c, fi_hashlink);
	LIST_INSERT_HEAD(&priv->fip_claims, c, fi_instlink);
	atomic_add_int(&fi_claim_count, 1);
	if (vp->v_type == VDIR)
		atomic_add_int(&fi_dir_claim_count, 1);
	rw_wunlock(&fi_lock);
	return (0);
}

static int
fi_do_release(struct file *fp, uint64_t nonce)
{
	struct vnode *vp;
	struct fi_claim *c;

	vp = fp->f_vnode;
	if (vp == NULL)
		return (EINVAL);

	rw_wlock(&fi_lock);
	c = fi_claim_lookup(vp);
	if (c == NULL) {
		rw_wunlock(&fi_lock);
		return (ENOENT);
	}
	if (c->fi_nonce != nonce) {
		rw_wunlock(&fi_lock);
		return (EACCES);
	}
	LIST_REMOVE(c, fi_hashlink);
	LIST_REMOVE(c, fi_instlink);
	atomic_subtract_int(&fi_claim_count, 1);
	if (c->fi_vp->v_type == VDIR)
		atomic_subtract_int(&fi_dir_claim_count, 1);
	rw_wunlock(&fi_lock);

	vrele(c->fi_vp);
	free(c, M_FILE_ISOLATION);
	return (0);
}

static int
fi_do_query(struct file *fp, uint64_t nonce, struct fi_reply *rpl)
{
	struct vnode *vp;
	struct fi_claim *c;

	vp = fp->f_vnode;
	if (vp == NULL)
		return (EINVAL);

	rpl->flags = 0;

	rw_rlock(&fi_lock);
	c = fi_claim_lookup(vp);
	if (c != NULL) {
		rpl->flags |= FI_QF_CLAIMED;
		if (nonce != 0 && c->fi_nonce == nonce)
			rpl->flags |= FI_QF_MINE;
	}
	rw_runlock(&fi_lock);
	return (0);
}

/* ----------------------------------------------------------------
 * Network claim/release
 * ---------------------------------------------------------------- */

static int
fi_do_claim_net(struct cap_rt_instance *s, struct fi_priv *priv,
    const struct fi_net_request *nr, uint64_t nonce)
{
	struct fi_net_claim *nc, *existing;
	u_long bucket;

	bucket = fi_net_hash_fn(nr->port, nr->domain);

	/*
	 * Check for conflicts: reject if any existing claim from a
	 * different nonce would overlap.  Overlap means: the new claim
	 * could match a request that an existing claim also matches
	 * (either could be broader or narrower).
	 *
	 * Simplified rule: scan ALL claims.  If a foreign-nonce claim
	 * exists where (port matches or either is 0) AND (domain matches
	 * or either is 0) AND (directions overlap), reject with EBUSY.
	 */
	rw_wlock(&fi_net_lock);
	{
		u_long scan_buckets[4];
		int nb = 4, bi, bj;
		bool bdup;

		scan_buckets[0] = fi_net_hash_fn(nr->port, nr->domain);
		scan_buckets[1] = fi_net_hash_fn(0, nr->domain);
		scan_buckets[2] = fi_net_hash_fn(nr->port, 0);
		scan_buckets[3] = fi_net_hash_fn(0, 0);

		for (bi = 0; bi < nb; bi++) {
			bdup = false;
			for (bj = 0; bj < bi; bj++) {
				if (scan_buckets[bj] == scan_buckets[bi]) {
					bdup = true;
					break;
				}
			}
			if (bdup)
				continue;
			LIST_FOREACH(existing, &fi_net_hash[scan_buckets[bi]],
			    fn_hashlink) {
				/* Check overlap: ports */
				if (existing->fn_port != 0 &&
				    nr->port != 0 &&
				    existing->fn_port != nr->port)
					continue;
				/* Check overlap: domains */
				if (existing->fn_domain != 0 &&
				    nr->domain != 0 &&
				    existing->fn_domain != nr->domain)
					continue;
				/* Check overlap: directions */
				if (!(existing->fn_direction &
				    nr->direction))
					continue;
				/* Check overlap: protocols */
				if (existing->fn_protocol != 0 &&
				    nr->protocol != 0 &&
				    existing->fn_protocol != nr->protocol)
					continue;
				/* Check overlap: addresses/prefixes */
				if (!fi_net_claim_addr_overlap(existing, nr))
					continue;
				/* Overlapping claim exists */
				if (existing->fn_nonce != nonce) {
					/* Foreign nonce — conflict */
					rw_wunlock(&fi_net_lock);
					return (EBUSY);
				}
				/*
				 * Same nonce overlap — not a conflict.
				 * Same nonce can have multiple claims
				 * (e.g., port 80 + port 443).  Only
				 * treat as re-claim if exact match.
				 */
			}
		}
	}

	/*
	 * No foreign conflicts.  Check for exact same-nonce duplicate
	 * in the target bucket — if found, transfer ownership (re-claim).
	 */
	LIST_FOREACH(existing, &fi_net_hash[bucket], fn_hashlink) {
		if (existing->fn_nonce != nonce)
			continue;
		if (existing->fn_port != nr->port ||
		    existing->fn_domain != nr->domain ||
		    existing->fn_direction != nr->direction ||
		    existing->fn_protocol != nr->protocol ||
		    existing->fn_prefix != nr->prefix ||
		    memcmp(&existing->fn_addr, nr->addr, 16) != 0)
			continue;
		/* Exact re-claim — transfer to this instance */
		LIST_REMOVE(existing, fn_instlink);
		LIST_INSERT_HEAD(&priv->fip_net_claims, existing,
		    fn_instlink);
		existing->fn_inst = s;
		rw_wunlock(&fi_net_lock);
		return (0);
	}

	/* New claim — insert */
	nc = malloc(sizeof(*nc), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	nc->fn_domain = nr->domain;
	nc->fn_protocol = nr->protocol;
	nc->fn_port = nr->port;
	nc->fn_direction = nr->direction;
	nc->fn_prefix = nr->prefix;
	memcpy(&nc->fn_addr, nr->addr, sizeof(nc->fn_addr));
	nc->fn_nonce = nonce;
	nc->fn_inst = s;

	LIST_INSERT_HEAD(&fi_net_hash[bucket], nc, fn_hashlink);
	LIST_INSERT_HEAD(&priv->fip_net_claims, nc, fn_instlink);
	atomic_add_int(&fi_net_claim_count, 1);
	rw_wunlock(&fi_net_lock);

	return (0);
}

static int
fi_do_release_net(struct fi_priv *priv,
    const struct fi_net_request *nr, uint64_t nonce)
{
	struct fi_net_claim *nc;

	rw_wlock(&fi_net_lock);
	LIST_FOREACH(nc, &priv->fip_net_claims, fn_instlink) {
		if (nc->fn_nonce != nonce)
			continue;
		if (nc->fn_port != nr->port)
			continue;
		if (nc->fn_domain != nr->domain)
			continue;
		if (nc->fn_direction != nr->direction)
			continue;
		if (nc->fn_protocol != nr->protocol)
			continue;
		if (nc->fn_prefix != nr->prefix)
			continue;
		if (memcmp(&nc->fn_addr, nr->addr, 16) != 0)
			continue;
		/* Exact match — remove */
		LIST_REMOVE(nc, fn_hashlink);
		LIST_REMOVE(nc, fn_instlink);
		atomic_subtract_int(&fi_net_claim_count, 1);
		rw_wunlock(&fi_net_lock);
		free(nc, M_FILE_ISOLATION);
		return (0);
	}
	rw_wunlock(&fi_net_lock);
	return (ENOENT);
}

/* ----------------------------------------------------------------
 * Service call handler
 * ---------------------------------------------------------------- */

static int
fi_call(struct cap_rt_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct fi_request *fr;
	struct fi_reply *rpl;
	struct fi_priv *priv;
	uint64_t caller_nonce;

	if (reqlen < sizeof(uint32_t))	/* at least the op field */
		return (EINVAL);
	if (*replylenp < sizeof(struct fi_reply))
		return (EMSGSIZE);

	fr = req;
	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = cap_rt_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0)
		return (ENXIO);

	rpl = reply;
	rpl->flags = 0;
	rpl->_pad = 0;
	*replylenp = sizeof(struct fi_reply);

	switch (fr->op) {
	case FI_OP_CLAIM:
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_claim(s, priv, fds[0], caller_nonce));
	case FI_OP_RELEASE:
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_release(fds[0], caller_nonce));
	case FI_OP_QUERY:
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_query(fds[0], caller_nonce, rpl));

	case FI_OP_CLAIM_NET:
	{
		const struct fi_net_request *nr;

		if (reqlen < sizeof(struct fi_net_request))
			return (EINVAL);
		nr = (const struct fi_net_request *)req;
		if (nr->flags != 0 || nr->direction == 0 ||
		    (nr->direction & ~FI_NET_ANY) != 0 ||
		    nr->prefix > 128)
			return (EINVAL);
		return (fi_do_claim_net(s, priv, nr, caller_nonce));
	}
	case FI_OP_RELEASE_NET:
	{
		const struct fi_net_request *nr;

		if (reqlen < sizeof(struct fi_net_request))
			return (EINVAL);
		nr = (const struct fi_net_request *)req;
		if (nr->flags != 0 || nr->direction == 0 ||
		    (nr->direction & ~FI_NET_ANY) != 0 ||
		    nr->prefix > 128)
			return (EINVAL);
		return (fi_do_release_net(priv, nr, caller_nonce));
	}
	default:
		return (EOPNOTSUPP);
	}
}

static void
fi_revoke(struct cap_rt_instance *s, uint64_t badge __unused,
    enum cap_rt_revoke_reason reason __unused, void *arg __unused)
{
	struct fi_priv *priv;
	struct fi_claim *c;
	LIST_HEAD(, fi_claim) batch;

	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return;

	LIST_INIT(&batch);

	/*
	 * Collect all claims under the write lock, then release
	 * vnodes outside it — vrele() can sleep.
	 */
	rw_wlock(&fi_lock);
	while ((c = LIST_FIRST(&priv->fip_claims)) != NULL) {
		LIST_REMOVE(c, fi_hashlink);
		LIST_REMOVE(c, fi_instlink);
		atomic_subtract_int(&fi_claim_count, 1);
		if (c->fi_vp->v_type == VDIR)
			atomic_subtract_int(&fi_dir_claim_count, 1);
		LIST_INSERT_HEAD(&batch, c, fi_instlink);
	}
	rw_wunlock(&fi_lock);

	while ((c = LIST_FIRST(&batch)) != NULL) {
		LIST_REMOVE(c, fi_instlink);
		vrele(c->fi_vp);
		free(c, M_FILE_ISOLATION);
	}

	/* Release all network claims */
	{
		struct fi_net_claim *nc;

		rw_wlock(&fi_net_lock);
		while ((nc = LIST_FIRST(&priv->fip_net_claims)) != NULL) {
			LIST_REMOVE(nc, fn_hashlink);
			LIST_REMOVE(nc, fn_instlink);
			atomic_subtract_int(&fi_net_claim_count, 1);
			free(nc, M_FILE_ISOLATION);
		}
		rw_wunlock(&fi_net_lock);
	}

	free(priv, M_FILE_ISOLATION);
}

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static const struct cap_rt_ops fi_ops = {
	.co_connect	= fi_connect,
	.co_init	= fi_init,
	.co_call	= fi_call,
	.co_revoke	= fi_revoke,
};

static struct mac_policy_ops fi_mac_ops = {
	/* Content access */
	.mpo_vnode_check_open		= fi_check_open,
	.mpo_vnode_check_exec		= fi_check_exec,
	/* Namespace mutation */
	.mpo_vnode_check_unlink		= fi_check_unlink,
	.mpo_vnode_check_link		= fi_check_link,
	.mpo_vnode_check_rename_from	= fi_check_rename_from,
	.mpo_vnode_check_rename_to	= fi_check_rename_to,
	/* Metadata mutation */
	.mpo_vnode_check_setmode	= fi_check_setmode,
	.mpo_vnode_check_setowner	= fi_check_setowner,
	.mpo_vnode_check_setflags	= fi_check_setflags,
	.mpo_vnode_check_setutimes	= fi_check_setutimes,
	.mpo_vnode_check_truncate	= fi_check_truncate,
	/* Information disclosure */
	.mpo_vnode_check_stat		= fi_check_stat,
	.mpo_vnode_check_access		= fi_check_access,
	.mpo_vnode_check_readlink	= fi_check_readlink,
	/* Directory traversal */
	.mpo_vnode_check_lookup		= fi_check_lookup,
	/* Unix domain sockets */
	.mpo_vnode_check_uipc_connect	= fi_check_uipc_connect,
	/* Network isolation */
	.mpo_socket_check_create	= fi_check_socket_create,
	.mpo_socket_check_bind		= fi_check_socket_bind,
	.mpo_socket_check_connect	= fi_check_socket_connect,
};

MAC_POLICY_SET(&fi_mac_ops, mac_cap_rt_file_isolation,
    "CAP_RT file isolation enforcement",
    MPC_LOADTIME_FLAG_NOTLATE, NULL);

static int
cap_rt_file_isolation_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	struct cap_rt_service_params p;
	int error;

	switch (type) {
	case MOD_LOAD:
		fi_hash = hashinit(FI_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_hashmask);
		rw_init(&fi_lock, "cap_rt_file_isolation");

		fi_net_hash = hashinit(FI_NET_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_net_hashmask);
		rw_init(&fi_net_lock, "cap_rt_fi_net");

		memset(&p, 0, sizeof(p));
		p.name = "file_isolation";
		p.ops = &fi_ops;

		error = cap_rt_service_create(&p, &fi_svc);
		if (error != 0) {
			rw_destroy(&fi_lock);
			hashdestroy(fi_hash, M_FILE_ISOLATION,
			    fi_hashmask);
			return (error);
		}
		if (bootverbose)
			printf("cap_rt_file_isolation: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);		/* NOTLATE policy cannot unload */

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_file_isolation_mod = {
	"cap_rt_file_isolation",
	cap_rt_file_isolation_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_file_isolation, cap_rt_file_isolation_mod,
    SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_DEPEND(cap_rt_file_isolation, cap_rt, 1, 1, 1);
MODULE_VERSION(cap_rt_file_isolation, 1);
