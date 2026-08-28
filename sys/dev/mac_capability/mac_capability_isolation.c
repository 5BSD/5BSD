/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * mac_capability_isolation — resource isolation capability service.
 *
 * Allows processes to claim resources so that only processes sharing
 * the claimer's MAC_CAPABILITY nonce can interact with them.
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
 *                  Supported: AF_INET, AF_INET6, AF_BLUETOOTH
 *
 *   vsock:         socket create, bind, connect, and host provider ownership
 *                  (per CID/port/direction tuple for AF_VSOCK)
 *
 * Claims are bound to the mac_capability instance fd.  When the instance is
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
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/imgact.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <netinet/in.h>
#include <sys/vsock.h>
#include <sys/bitstring.h>
#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>
#include <netgraph/bluetooth/include/ng_btsocket.h>

#include <security/mac/mac_policy.h>

#include <dev/mac_capability/mac_capability.h>
#include <dev/mac_capability/mac_capability_label.h>
#include <dev/mac_capability/mac_capability_isolation_proto.h>

static MALLOC_DEFINE(M_FILE_ISOLATION, "mac_capability_fi",
    "mac_capability file isolation");

SDT_PROVIDER_DEFINE(mac_capability_isolation);
SDT_PROBE_DEFINE3(mac_capability_isolation, , , deny,
    "const char *", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(mac_capability_isolation, , , deny__action,
    "const char *", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , deny__net,
    "uint64_t", "uint64_t", "uint64_t", "int", "uint32_t", "uint16_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , deny__vsock,
    "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint32_t", "uint8_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , deny__jail,
    "uint64_t", "uint64_t", "uint64_t", "int", "const char *", "uint32_t");
SDT_PROBE_DEFINE5(mac_capability_isolation, , , allow__action,
    "const char *", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , allow__net,
    "uint64_t", "uint64_t", "uint64_t", "int", "uint32_t", "uint16_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , allow__vsock,
    "uint64_t", "uint64_t", "uint64_t", "uint64_t", "uint32_t", "uint8_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , allow__jail,
    "uint64_t", "uint64_t", "uint64_t", "int", "const char *", "uint32_t");
SDT_PROBE_DEFINE5(mac_capability_isolation, , , token__narrow,
    "const char *", "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(mac_capability_isolation, , , query,
    "const char *", "uint64_t", "uint64_t", "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(mac_capability_isolation, , , state,
    "const char *", "uint64_t", "uint64_t", "uint64_t", "int", "int");

/* ----------------------------------------------------------------
 * Isolation hash table
 * ---------------------------------------------------------------- */

#define	FI_HASH_SIZE	64

struct fi_claim {
	LIST_ENTRY(fi_claim)	fi_hashlink;	/* global hash bucket */
	LIST_ENTRY(fi_claim)	fi_instlink;	/* per-instance list */
	struct vnode		*fi_vp;		/* held vnode ref */
	uint64_t		 fi_nonce;	/* owning nonce */
	uint64_t		 fi_id;		/* unique claim id */
	struct mac_capability_instance	*fi_inst;	/* owning instance */
};

/* ----------------------------------------------------------------
 * Network isolation hash table
 * ---------------------------------------------------------------- */

#define	FI_NET_HASH_SIZE	32
struct fi_net_claim {
	LIST_ENTRY(fi_net_claim) fn_hashlink;
	LIST_ENTRY(fi_net_claim) fn_instlink;
	int		fn_domain;	/* AF_INET, AF_INET6, AF_BLUETOOTH, 0=any */
	int		fn_protocol;	/* IPPROTO_TCP, etc., 0=any */
	uint16_t	fn_port_min;	/* host byte order */
	uint16_t	fn_port_max;	/* host byte order */
	uint8_t		fn_direction;	/* FI_NET_* bitmask */
	uint8_t		fn_prefix;	/* CIDR prefix, 0=any */
	struct in6_addr	fn_addr;	/* v6 or v4-mapped, zero=any */
	uint64_t	fn_nonce;
	uint64_t	fn_id;
	struct mac_capability_instance *fn_inst;
};

/* ----------------------------------------------------------------
 * Jail isolation table
 * ---------------------------------------------------------------- */

struct fi_jail_claim {
	LIST_ENTRY(fi_jail_claim) fj_link;
	LIST_ENTRY(fi_jail_claim) fj_instlink;
	int32_t		fj_jid;
	uint32_t	fj_actions;
	char		fj_name[sizeof(((struct fi_jail_request *)0)->name)];
	uint64_t	fj_nonce;
	uint64_t	fj_id;
	struct mac_capability_instance *fj_inst;
};

/* ----------------------------------------------------------------
 * vsock isolation hash table
 * ---------------------------------------------------------------- */

#define	FI_VSOCK_HASH_SIZE	16

struct fi_vsock_claim {
	LIST_ENTRY(fi_vsock_claim) fv_hashlink;
	LIST_ENTRY(fi_vsock_claim) fv_instlink;
	uint64_t	fv_cid;		/* VSOCK_CID_ANY or specific */
	uint32_t	fv_port_min;	/* host byte order */
	uint32_t	fv_port_max;
	uint8_t		fv_direction;	/* FI_NET_* bitmask */
	uint64_t	fv_nonce;
	uint64_t	fv_id;
	struct mac_capability_instance *fv_inst;
};

struct fi_vsock_provider_label {
	uint64_t	fpl_owner;
	uint64_t	fpl_claim_id;
	bool		fpl_protected;
};

/*
 * Authorization table: (accessor_nonce, owner_nonce) pairs.
 * Keyed by owner_nonce (the claim holder).  When a MACF hook
 * finds a claim, it checks whether the caller's nonce is in the
 * auth table for that claim's nonce.
 *
 * Auth entries are bound to a token instance fd.  When the token
 * fd closes, the auth entry is removed automatically.
 */
#define	FI_AUTH_HASH_SIZE	32

struct fi_auth {
	LIST_ENTRY(fi_auth)	fa_link;
	uint64_t		fa_accessor;	/* authorized nonce */
	uint64_t		fa_owner;	/* claim owner nonce */
	uint64_t		fa_claim_id;	/* exact claim this token covers */
	uint64_t		fa_fs_actions;	/* FI_FS_* for vnode tokens */
	bool			fa_is_net;
	bool			fa_is_jail;
	bool			fa_is_vsock;
	struct fi_net_request	fa_net;
	struct fi_jail_request	fa_jail;
	struct fi_vsock_request	fa_vsock;
	struct mac_capability_instance	*fa_inst;	/* token instance (lifetime) */
};

struct fi_priv {
	LIST_HEAD(, fi_claim)	    fip_claims;	    /* vnode claims */
	LIST_HEAD(, fi_net_claim)   fip_net_claims; /* network claims */
	LIST_HEAD(, fi_jail_claim)  fip_jail_claims; /* jail claims */
	/* Token state (for instances created by FI_OP_MINT). */
	bool			    fip_is_token;
	uint64_t		    fip_token_owner; /* claim owner nonce */
	uint64_t		    fip_token_claim_id;
	uint64_t		    fip_token_fs_actions;
	bool			    fip_token_is_net;
	bool			    fip_token_is_jail;
	bool			    fip_token_is_vsock;
	struct fi_net_request	    fip_token_net;
	struct fi_jail_request	    fip_token_jail;
	struct fi_vsock_request	    fip_token_vsock;
	LIST_HEAD(, fi_vsock_claim) fip_vsock_claims;
};

static LIST_HEAD(, fi_claim)	*fi_hash;
static u_long			 fi_hashmask;
static struct rwlock		 fi_lock;
static volatile u_int		 fi_claim_count;	/* fast-path for file hooks */
static volatile u_int		 fi_dir_claim_count;	/* fast-path for lookup hook */
static volatile uint64_t	 fi_next_claim_id = 1;

static LIST_HEAD(, fi_auth)	*fi_auth_hash;
static u_long			 fi_auth_hashmask;
static struct rwlock		 fi_auth_lock;
static volatile u_int		 fi_auth_count;

static u_int fi_max_auth = 4096;

/*
 * Enforcement mode.  1 (default) enforces isolation.  0 is permissive/test
 * mode: every denial is still evaluated and traced through the DTrace deny
 * probes, but resource-ACCESS denials are downgraded to "allow", so
 * device-gated tests can open /dev/mac_capability and drive the plane
 * directly.  Ownership/management denials (claim release, mint, jail-claim
 * wrong-nonce) are NOT downgraded -- permissive access must never let a test
 * tamper with another principal's claims.  Boot-only (CTLFLAG_RDTUN): a
 * runtime compromise cannot flip it, and a test image opts in via
 * kern.mac_capability_isolation.enforce=0 in loader.conf.
 */
static int fi_enforce = 1;

SYSCTL_NODE(_kern, OID_AUTO, mac_capability_isolation,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "mac_capability isolation");
SYSCTL_UINT(_kern_mac_capability_isolation, OID_AUTO, max_auth, CTLFLAG_RDTUN,
    &fi_max_auth, 0,
    "Maximum total authorization entries (0 = unlimited)");
SYSCTL_UINT(_kern_mac_capability_isolation, OID_AUTO, auth_count, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &fi_auth_count), 0,
    "Current number of authorization entries");
SYSCTL_INT(_kern_mac_capability_isolation, OID_AUTO, enforce, CTLFLAG_RDTUN,
    &fi_enforce, 1,
    "Enforce isolation access denials (0 = permissive/test mode: trace but "
    "allow resource access; ownership checks stay enforced)");

/*
 * Downgrade a resource-access denial to "allow" in permissive mode.  Callers
 * emit the deny DTrace probe first, so the would-be denial stays observable.
 */
static __inline int
fi_deny(int error)
{
	return (fi_enforce ? error : 0);
}

static LIST_HEAD(, fi_jail_claim) fi_jail_claims;
static struct rwlock		 fi_jail_lock;
static volatile u_int		 fi_jail_claim_count;	/* fast-path for jail hooks */

static LIST_HEAD(, fi_vsock_claim) *fi_vsock_hash;
static u_long			    fi_vsock_hashmask;
static struct rwlock		    fi_vsock_lock;
static volatile u_int		    fi_vsock_claim_count;
static int			    fi_slot;

#define	FI_VSOCK_PROVIDER_SLOT(label)					\
	((struct fi_vsock_provider_label *)mac_label_get((label), fi_slot))
#define	FI_VSOCK_PROVIDER_SLOT_SET(label, value)				\
	mac_label_set((label), fi_slot, (uintptr_t)(value))

#define	FI_AUTH_BUCKET(nonce)	(&fi_auth_hash[(nonce) & fi_auth_hashmask])

static bool	fi_net_addr_match(const struct fi_net_claim *nc,
		    struct sockaddr *sa);
static bool	fi_net_claim_covers_request(const struct fi_net_claim *nc,
		    const struct fi_net_request *nr);
static int	fi_vsock_check(struct ucred *cred, struct sockaddr *sa,
		    uint8_t direction);
static int	fi_vsock_check_create(struct ucred *cred);

static uint64_t
fi_alloc_claim_id(void)
{
	uint64_t id;

	do {
		id = atomic_fetchadd_64(&fi_next_claim_id, 1);
	} while (id == 0);
	return (id);
}

static int
fi_is_authorized(uint64_t accessor, uint64_t owner, uint64_t claim_id,
    uint64_t actions)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id && !fa->fa_is_net &&
		    !fa->fa_is_jail &&
		    (fa->fa_fs_actions & actions) == actions)
			return (1);
	}
	return (0);
}

static bool
fi_jail_req_matches(const struct fi_jail_request *claim,
    const struct fi_jail_request *req)
{

	/*
	 * When the claim specifies both JID and name, require both keys
	 * to be present in the request and both to match.  This prevents
	 * a token for jail "authorityd.net" JID 5 from authorizing
	 * operations keyed only by JID 5 (which could be reused).
	 *
	 * Exception: FI_JAIL_CREATE requests may have JID 0 because the
	 * JID is not allocated until after creation succeeds.  When the
	 * request is create-only and carries no JID, match on name alone
	 * even if the claim has both keys.
	 *
	 * When only one key is specified in the claim, match on that key
	 * alone, requiring the request to also supply it.
	 */
	if (claim->jid != 0 && claim->name[0] != '\0') {
		if (req->jid == 0 && req->name[0] != '\0' &&
		    req->actions == FI_JAIL_CREATE) {
			/* Pre-create: JID unknown, match name only. */
			return (strcmp(claim->name, req->name) == 0);
		}
		/* Post-create: request must supply both keys. */
		return (req->jid == claim->jid &&
		    req->name[0] != '\0' &&
		    strcmp(claim->name, req->name) == 0);
	}
	/* Claim has one key — match on that key. */
	if (claim->jid != 0)
		return (req->jid != 0 && claim->jid == req->jid);
	if (claim->name[0] != '\0')
		return (req->name[0] != '\0' &&
		    strcmp(claim->name, req->name) == 0);
	return (false);
}

static bool
fi_jail_claim_matches(const struct fi_jail_claim *claim,
    const struct fi_jail_request *req)
{
	struct fi_jail_request cr;

	memset(&cr, 0, sizeof(cr));
	cr.jid = claim->fj_jid;
	cr.actions = claim->fj_actions;
	strlcpy(cr.name, claim->fj_name, sizeof(cr.name));
	return (fi_jail_req_matches(&cr, req));
}

static bool
fi_auth_jail_matches(const struct fi_auth *fa,
    const struct fi_jail_request *req)
{

	if (!fa->fa_is_jail)
		return (false);
	if ((fa->fa_jail.actions & req->actions) != req->actions)
		return (false);
	return (fi_jail_req_matches(&fa->fa_jail, req));
}

static int
fi_is_authorized_jail(uint64_t accessor, uint64_t owner, uint64_t claim_id,
    const struct fi_jail_request *req)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id &&
		    fi_auth_jail_matches(fa, req))
			return (1);
	}
	return (0);
}

static bool
fi_auth_net_matches(const struct fi_auth *fa, int domain, int protocol,
    struct sockaddr *sa, uint8_t direction)
{
	struct fi_net_claim ac;
	uint16_t port = 0, port_min, port_max;

	if (!fa->fa_is_net)
		return (false);
	if (sa != NULL) {
		if (sa->sa_family == AF_INET)
			port = ntohs(((struct sockaddr_in *)sa)->sin_port);
		else if (sa->sa_family == AF_INET6)
			port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		else if (sa->sa_family == AF_BLUETOOTH) {
			switch (protocol) {
			case BLUETOOTH_PROTO_L2CAP: {
				struct sockaddr_l2cap *sl2 =
				    (struct sockaddr_l2cap *)sa;

				/*
				 * Only read the PSM if the caller-supplied
				 * sockaddr is long enough to hold it; a short
				 * address leaves port 0 (wildcard) rather than
				 * over-reading the allocation.
				 */
				if (sa->sa_len == 0 || sa->sa_len >=
				    offsetof(struct sockaddr_l2cap, l2cap_psm) +
				    sizeof(sl2->l2cap_psm))
					port = ntohs(sl2->l2cap_psm);
				break;
			}
			case BLUETOOTH_PROTO_RFCOMM: {
				struct sockaddr_rfcomm *srf =
				    (struct sockaddr_rfcomm *)sa;

				if (sa->sa_len == 0 || sa->sa_len >=
				    offsetof(struct sockaddr_rfcomm,
				    rfcomm_channel) + sizeof(srf->rfcomm_channel))
					port = srf->rfcomm_channel;
				break;
			}
			case BLUETOOTH_PROTO_SCO:
			case BLUETOOTH_PROTO_ISO:
				/*
				 * SCO (sockaddr_sco) and ISO (sockaddr_iso)
				 * carry no PSM/channel, so there is no port to
				 * match on; isolation is enforced on the
				 * BD_ADDR alone (see fi_net_addr_match()).
				 */
				port = 0;
				break;
			default:
				port = 0;
				break;
			}
		}
	}
	port_min = ntohs(fa->fa_net.port_min);
	port_max = ntohs(fa->fa_net.port_max);
	if ((fa->fa_net.direction & direction) != direction)
		return (false);
	if (fa->fa_net.domain != 0 && fa->fa_net.domain != domain)
		return (false);
	if (fa->fa_net.protocol != 0 && protocol != 0 &&
	    fa->fa_net.protocol != protocol)
		return (false);
	if (port < port_min || port > port_max)
		return (false);

	memset(&ac, 0, sizeof(ac));
	ac.fn_domain = fa->fa_net.domain;
	ac.fn_protocol = fa->fa_net.protocol;
	ac.fn_port_min = port_min;
	ac.fn_port_max = port_max;
	ac.fn_direction = fa->fa_net.direction;
	ac.fn_prefix = fa->fa_net.prefix;
	memcpy(&ac.fn_addr, fa->fa_net.addr, sizeof(ac.fn_addr));
	return (fi_net_addr_match(&ac, sa));
}

static int
fi_is_authorized_net(uint64_t accessor, uint64_t owner, uint64_t claim_id,
    int domain, int protocol, struct sockaddr *sa, uint8_t direction)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id &&
		    fi_auth_net_matches(fa, domain, protocol, sa, direction))
			return (1);
	}
	return (0);
}

static int
fi_is_authorized_net_socket(uint64_t accessor, uint64_t owner,
    uint64_t claim_id, int domain, int protocol)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id && fa->fa_is_net &&
		    (fa->fa_net.domain == 0 || fa->fa_net.domain == domain) &&
		    (fa->fa_net.protocol == 0 || protocol == 0 ||
		    fa->fa_net.protocol == protocol))
			return (1);
	}
	return (0);
}

static bool
fi_auth_net_covers_request(const struct fi_auth *fa,
    const struct fi_net_request *nr)
{
	struct fi_net_claim ac;

	if (!fa->fa_is_net)
		return (false);

	memset(&ac, 0, sizeof(ac));
	ac.fn_domain = fa->fa_net.domain;
	ac.fn_protocol = fa->fa_net.protocol;
	ac.fn_port_min = ntohs(fa->fa_net.port_min);
	ac.fn_port_max = ntohs(fa->fa_net.port_max);
	ac.fn_direction = fa->fa_net.direction;
	ac.fn_prefix = fa->fa_net.prefix;
	memcpy(&ac.fn_addr, fa->fa_net.addr, sizeof(ac.fn_addr));
	return (fi_net_claim_covers_request(&ac, nr));
}

static int
fi_is_authorized_net_request(uint64_t accessor, uint64_t owner,
    uint64_t claim_id, const struct fi_net_request *nr)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id &&
		    fi_auth_net_covers_request(fa, nr))
			return (1);
	}
	return (0);
}

static int
fi_auth_add(uint64_t accessor, uint64_t owner, uint64_t claim_id,
    uint64_t fs_actions, const struct fi_net_request *net,
    const struct fi_jail_request *jail,
    const struct fi_vsock_request *vsock,
    struct mac_capability_instance *inst)
{
	struct fi_auth *fa, *existing;

	fa = malloc(sizeof(*fa), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	fa->fa_accessor = accessor;
	fa->fa_owner = owner;
	fa->fa_claim_id = claim_id;
	fa->fa_fs_actions = fs_actions;
	if (net != NULL) {
		fa->fa_is_net = true;
		fa->fa_net = *net;
	}
	if (jail != NULL) {
		fa->fa_is_jail = true;
		fa->fa_jail = *jail;
	}
	if (vsock != NULL) {
		fa->fa_is_vsock = true;
		fa->fa_vsock = *vsock;
	}
	fa->fa_inst = inst;

	rw_wlock(&fi_auth_lock);
	/* Dedup: check for existing entry with same key. */
	LIST_FOREACH(existing, FI_AUTH_BUCKET(owner), fa_link) {
		if (existing->fa_accessor == accessor &&
		    existing->fa_owner == owner &&
		    existing->fa_claim_id == claim_id &&
		    existing->fa_inst == inst &&
		    existing->fa_is_net == (net != NULL) &&
		    existing->fa_is_jail == (jail != NULL) &&
		    existing->fa_is_vsock == (vsock != NULL)) {
			rw_wunlock(&fi_auth_lock);
			free(fa, M_FILE_ISOLATION);
			return (0);
		}
	}
	/* Limit check: use global counter as a fast early-out. */
	if (fi_max_auth != 0 && fi_auth_count >= fi_max_auth) {
		rw_wunlock(&fi_auth_lock);
		free(fa, M_FILE_ISOLATION);
		return (ENOSPC);
	}
	LIST_INSERT_HEAD(FI_AUTH_BUCKET(owner), fa, fa_link);
	atomic_add_int(&fi_auth_count, 1);
	rw_wunlock(&fi_auth_lock);
	return (0);
}

static void
fi_auth_remove_by_inst(struct mac_capability_instance *inst)
{
	struct fi_auth *fa, *fa_tmp;
	u_long i;

	rw_wlock(&fi_auth_lock);
	for (i = 0; i <= fi_auth_hashmask; i++) {
		LIST_FOREACH_SAFE(fa, &fi_auth_hash[i], fa_link, fa_tmp) {
			if (fa->fa_inst == inst) {
				LIST_REMOVE(fa, fa_link);
				atomic_subtract_int(&fi_auth_count, 1);
				free(fa, M_FILE_ISOLATION);
			}
		}
	}
	rw_wunlock(&fi_auth_lock);
}

static LIST_HEAD(, fi_net_claim) *fi_net_hash;
static u_long			  fi_net_hashmask;
static struct rwlock		  fi_net_lock;
static volatile u_int		  fi_net_claim_count;	/* fast-path for socket hooks */
static struct mac_capability_service	*fi_svc;

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
 * Shared logic for vnode isolation checks.  Fast-path via the given
 * atomic claim counter, then rw_rlock fi_lock, lookup, nonce compare,
 * auth check, and deny with DTrace probe on mismatch.
 */
static int
fi_check_vp_common(struct ucred *cred, struct vnode *vp,
    volatile u_int *claim_count, const char *probe_name, uint64_t actions)
{
	struct fi_claim *c;
	uint64_t caller_nonce, owner_nonce, claim_id;

	if (atomic_load_acq_int(claim_count) == 0)
		return (0);

	caller_nonce = mac_capability_proc_nonce(cred);

	rw_rlock(&fi_lock);
	c = fi_claim_lookup(vp);
	if (c == NULL) {
		rw_runlock(&fi_lock);
		return (0);
	}
	owner_nonce = c->fi_nonce;
	claim_id = c->fi_id;
	if (caller_nonce != 0 && caller_nonce == owner_nonce) {
		SDT_PROBE5(mac_capability_isolation, , , allow__action,
		    probe_name, owner_nonce, caller_nonce, claim_id,
		    actions);
		rw_runlock(&fi_lock);
		return (0);
	}

	/* Keep the claim stable while consulting its authorization entry. */
	if (caller_nonce != 0) {
		rw_rlock(&fi_auth_lock);
		if (fi_is_authorized(caller_nonce, owner_nonce, claim_id,
		    actions)) {
			SDT_PROBE5(mac_capability_isolation, , , allow__action,
			    probe_name, owner_nonce, caller_nonce,
			    claim_id, actions);
			rw_runlock(&fi_auth_lock);
			rw_runlock(&fi_lock);
			return (0);
		}
		rw_runlock(&fi_auth_lock);
	}

	SDT_PROBE3(mac_capability_isolation, , , deny, probe_name,
	    owner_nonce, caller_nonce);
	SDT_PROBE5(mac_capability_isolation, , , deny__action, probe_name,
	    owner_nonce, caller_nonce, claim_id, actions);
	rw_runlock(&fi_lock);
	return (fi_deny(EACCES));
}

/*
 * Return EACCES if vp is isolated and cred's nonce does not match.
 * Returns 0 (allow) in all other cases.
 */
static int
fi_check_vp_action(struct ucred *cred, struct vnode *vp, uint64_t actions)
{

	return (fi_check_vp_common(cred, vp, &fi_claim_count, "vnode",
	    actions));
}

static uint64_t
fi_actions_from_accmode(accmode_t accmode)
{
	uint64_t actions;

	actions = 0;
	if ((accmode & VREAD) != 0)
		actions |= FI_FS_READ;
	if ((accmode & VWRITE) != 0)
		actions |= FI_FS_WRITE;
	if ((accmode & VAPPEND) != 0)
		actions |= FI_FS_APPEND;
	if ((accmode & VEXEC) != 0)
		actions |= FI_FS_EXEC;
	if ((accmode & VREAD_ATTRIBUTES) != 0)
		actions |= FI_FS_STAT;
	if ((accmode & (VWRITE_ATTRIBUTES | VWRITE_ACL | VWRITE_OWNER)) != 0)
		actions |= FI_FS_SETATTR;
	if (actions == 0)
		actions = FI_FS_STAT;
	return (actions);
}

/* --- Content access --- */

static int
fi_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, accmode_t accmode)
{
	/*
	 * unp_connectat() performs a synthetic VREAD | VWRITE open check on
	 * the socket vnode before invoking vnode_check_uipc_connect.  Content
	 * access masks do not describe a Unix-domain socket connection; the
	 * dedicated FI_FS_UIPC_CONNECT check below does.  Do not require an
	 * unrelated READ | WRITE token before that check can run.
	 */
	if (vp->v_type == VSOCK && accmode == (VREAD | VWRITE))
		return (0);

	return (fi_check_vp_action(cred, vp, fi_actions_from_accmode(accmode)));
}

static int
fi_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, struct image_params *imgp __unused,
    struct label *execlabel __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_EXEC));
}

/* --- Namespace mutation --- */

static int
fi_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{
	int error;

	/* Check directory: removing a name requires DELETE on the dir. */
	error = fi_check_vp_common(cred, dvp, &fi_dir_claim_count,
	    "unlink-dir", FI_FS_DELETE);
	if (error != 0)
		return (error);
	return (fi_check_vp_action(cred, vp, FI_FS_DELETE));
}

static int
fi_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{
	int error;

	/* Check destination directory: adding a name requires LINK on the dir. */
	error = fi_check_vp_common(cred, dvp, &fi_dir_claim_count,
	    "link-dir", FI_FS_LINK);
	if (error != 0)
		return (error);
	return (fi_check_vp_action(cred, vp, FI_FS_LINK));
}

static int
fi_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, struct componentname *cnp __unused)
{
	int error;

	/* Check source directory: moving a name out requires RENAME_FROM. */
	error = fi_check_vp_common(cred, dvp, &fi_dir_claim_count,
	    "rename-from-dir", FI_FS_RENAME_FROM);
	if (error != 0)
		return (error);
	return (fi_check_vp_action(cred, vp, FI_FS_RENAME_FROM));
}

static int
fi_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct vnode *vp,
    struct label *vplabel __unused, int samedir __unused,
    struct componentname *cnp __unused)
{
	int error;

	/* Check destination directory: moving a name in requires RENAME_TO. */
	error = fi_check_vp_common(cred, dvp, &fi_dir_claim_count,
	    "rename-to-dir", FI_FS_RENAME_TO);
	if (error != 0)
		return (error);
	if (vp == NULL)
		return (0);	/* target does not exist yet */
	return (fi_check_vp_action(cred, vp, FI_FS_RENAME_TO));
}

/* --- Metadata mutation --- */

static int
fi_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, mode_t mode __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_SETATTR));
}

static int
fi_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, uid_t uid __unused,
    gid_t gid __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_SETATTR));
}

static int
fi_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, u_long flags __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_SETATTR));
}

static int
fi_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, struct timespec atime __unused,
    struct timespec mtime __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_SETATTR));
}

static int
fi_check_truncate(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_TRUNCATE));
}

/* --- Information disclosure --- */

static int
fi_check_stat(struct ucred *active_cred, struct ucred *file_cred __unused,
    struct vnode *vp, struct label *vplabel __unused)
{

	return (fi_check_vp_action(active_cred, vp, FI_FS_STAT));
}

static int
fi_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused, accmode_t accmode)
{

	return (fi_check_vp_action(cred, vp, fi_actions_from_accmode(accmode)));
}

static int
fi_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_READ));
}

/* --- Directory traversal --- */

static int
fi_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct componentname *cnp __unused)
{

	/*
	 * Separate fast-path counter for directory claims.
	 * This hook fires on EVERY path component traversal, so
	 * it must be zero-cost when no directories are claimed —
	 * even if file claims exist.
	 */
	return (fi_check_vp_common(cred, dvp, &fi_dir_claim_count, "lookup",
	    FI_FS_LOOKUP));
}

/* --- Unix domain sockets --- */

static int
fi_check_uipc_connect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp_action(cred, vp, FI_FS_UIPC_CONNECT));
}

/* ----------------------------------------------------------------
 * Network isolation — MACF hooks and helpers
 * ---------------------------------------------------------------- */

static __inline u_long
fi_net_hash_fn(uint16_t port, int domain)
{

	return (((u_long)port ^ (u_long)domain) & fi_net_hashmask);
}

static __inline uint16_t
fi_net_hash_port(uint16_t port_min, uint16_t port_max)
{

	return (port_min == port_max ? port_min : 0);
}

static __inline bool
fi_net_port_in_range(const struct fi_net_claim *nc, uint16_t port)
{

	return (port >= nc->fn_port_min && port <= nc->fn_port_max);
}

static __inline bool
fi_net_port_ranges_overlap(uint16_t amin, uint16_t amax, uint16_t bmin,
    uint16_t bmax)
{

	return (amin <= bmax && bmin <= amax);
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

/*
 * Map a user-supplied prefix length to the v4-mapped v6 address space.
 * IPv4 addresses live at bytes 12-15 of the v6 address, so an IPv4
 * /24 must compare at bit offset 96+24=120, not bit 24.
 */
static uint8_t
fi_net_effective_prefix(int domain, uint8_t user_prefix)
{

	if (domain == AF_INET || domain == 0) {
		/*
		 * Heuristic: if the prefix fits in IPv4 range and the
		 * domain is AF_INET (or unspecified with small prefix),
		 * treat as IPv4 and offset into v4-mapped region.
		 */
		if (user_prefix == 0)
			return (128);
		if (user_prefix <= 32)
			return (96 + user_prefix);
		/* prefix > 32 for AF_INET is invalid; treat as exact */
		return (128);
	}
	if (domain == AF_BLUETOOTH) {
		/* BD_ADDR is 6 bytes = 48 bits; 0 means any */
		return (user_prefix == 0 ? 48 : MIN(user_prefix, (uint8_t)48));
	}
	/* AF_INET6: prefix is already correct */
	return (user_prefix == 0 ? 128 : MIN(user_prefix, (uint8_t)128));
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

	existing_prefix = fi_net_effective_prefix(existing->fn_domain,
	    existing->fn_prefix);
	req_prefix = fi_net_effective_prefix(nr->domain, nr->prefix);

	return (fi_net_addr_prefix_match(&existing->fn_addr, &req_addr,
	    MIN(existing_prefix, req_prefix)));
}

static bool
fi_net_claim_covers_request(const struct fi_net_claim *nc,
    const struct fi_net_request *nr)
{
	struct in6_addr req_addr;
	uint16_t port_min, port_max;
	uint8_t claim_prefix, req_prefix;

	if ((nc->fn_direction & nr->direction) != nr->direction)
		return (false);
	if (nc->fn_domain != 0 &&
	    (nr->domain == 0 || nc->fn_domain != nr->domain))
		return (false);
	if (nc->fn_protocol != 0 &&
	    (nr->protocol == 0 || nc->fn_protocol != nr->protocol))
		return (false);
	port_min = ntohs(nr->port_min);
	port_max = ntohs(nr->port_max);
	if (nc->fn_port_min > port_min || nc->fn_port_max < port_max)
		return (false);

	memcpy(&req_addr, nr->addr, sizeof(req_addr));
	if (fi_net_addr_is_wildcard(&nc->fn_addr))
		return (true);
	if (fi_net_addr_is_wildcard(&req_addr))
		return (false);

	claim_prefix = fi_net_effective_prefix(nc->fn_domain, nc->fn_prefix);
	req_prefix = fi_net_effective_prefix(nr->domain, nr->prefix);
	if (claim_prefix > req_prefix)
		return (false);
	return (fi_net_addr_prefix_match(&nc->fn_addr, &req_addr,
	    claim_prefix));
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
	} else if (sa->sa_family == AF_BLUETOOTH) {
		const uint8_t *bdaddr = NULL;

		switch (nc->fn_protocol) {
		case BLUETOOTH_PROTO_L2CAP: {
			struct sockaddr_l2cap *sl2 =
			    (struct sockaddr_l2cap *)sa;

			/*
			 * The MAC hook runs on the raw bind/connect sockaddr,
			 * whose length is caller-controlled and may be as small
			 * as the 2-byte header.  Reject a sockaddr too short to
			 * hold the BD_ADDR at its protocol-specific offset before
			 * dereferencing it, so a short address can't drive an
			 * out-of-bounds read past the allocation.
			 */
			if (sa->sa_len != 0 && sa->sa_len <
			    offsetof(struct sockaddr_l2cap, l2cap_bdaddr) +
			    sizeof(sl2->l2cap_bdaddr))
				return (false);
			bdaddr = sl2->l2cap_bdaddr.b;
			break;
		}
		case BLUETOOTH_PROTO_RFCOMM: {
			struct sockaddr_rfcomm *srf =
			    (struct sockaddr_rfcomm *)sa;

			if (sa->sa_len != 0 && sa->sa_len <
			    offsetof(struct sockaddr_rfcomm, rfcomm_bdaddr) +
			    sizeof(srf->rfcomm_bdaddr))
				return (false);
			bdaddr = srf->rfcomm_bdaddr.b;
			break;
		}
		case BLUETOOTH_PROTO_SCO: {
			struct sockaddr_sco *ssc =
			    (struct sockaddr_sco *)sa;

			if (sa->sa_len != 0 && sa->sa_len <
			    offsetof(struct sockaddr_sco, sco_bdaddr) +
			    sizeof(ssc->sco_bdaddr))
				return (false);
			bdaddr = ssc->sco_bdaddr.b;
			break;
		}
		case BLUETOOTH_PROTO_ISO: {
			struct sockaddr_iso *sis =
			    (struct sockaddr_iso *)sa;

			/*
			 * ISO sockaddr layout (sockaddr_iso) places the
			 * BD_ADDR after a 2-byte CIS/BIS handle, so iso_bdaddr
			 * sits at offset 4 -- unlike sockaddr_sco.  Reject a
			 * sockaddr too short to contain the full BD_ADDR before
			 * dereferencing it.
			 */
			if (sa->sa_len != 0 && sa->sa_len <
			    offsetof(struct sockaddr_iso, iso_bdaddr) +
			    sizeof(sis->iso_bdaddr))
				return (false);
			bdaddr = sis->iso_bdaddr.b;
			break;
		}
		default:
			return (false);
		}
		/* BD_ADDR stored in addr[0..5], rest zeroed */
		memset(&sa_addr, 0, sizeof(sa_addr));
		if (bdaddr != NULL)
			memcpy(&sa_addr, bdaddr, 6);
	} else {
		return (false);
	}

	/* CIDR prefix match — map user prefix to v4-mapped offset */
	{
		uint8_t prefix = fi_net_effective_prefix(nc->fn_domain,
		    nc->fn_prefix);
		uint8_t full_bytes, rem_bits;

		if (prefix >= 128)
			return (memcmp(&nc->fn_addr, &sa_addr, 16) == 0);

		full_bytes = prefix / 8;
		rem_bits = prefix % 8;

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
			port = ntohs(sin->sin_port);
		} else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
			port = ntohs(sin6->sin6_port);
		} else if (sa->sa_family == AF_BLUETOOTH) {
			switch (protocol) {
			case BLUETOOTH_PROTO_L2CAP: {
				struct sockaddr_l2cap *sl2 =
				    (struct sockaddr_l2cap *)sa;

				/*
				 * Only read the PSM if the caller-supplied
				 * sockaddr is long enough to hold it; a short
				 * address leaves port 0 (wildcard) rather than
				 * over-reading the allocation.
				 */
				if (sa->sa_len == 0 || sa->sa_len >=
				    offsetof(struct sockaddr_l2cap, l2cap_psm) +
				    sizeof(sl2->l2cap_psm))
					port = ntohs(sl2->l2cap_psm);
				break;
			}
			case BLUETOOTH_PROTO_RFCOMM: {
				struct sockaddr_rfcomm *srf =
				    (struct sockaddr_rfcomm *)sa;

				if (sa->sa_len == 0 || sa->sa_len >=
				    offsetof(struct sockaddr_rfcomm,
				    rfcomm_channel) + sizeof(srf->rfcomm_channel))
					port = srf->rfcomm_channel;
				break;
			}
			case BLUETOOTH_PROTO_SCO:
			case BLUETOOTH_PROTO_ISO:
				/*
				 * SCO/ISO have no PSM/channel; the claim
				 * matches on BD_ADDR only.
				 */
				port = 0;
				break;
			default:
				port = 0;
				break;
			}
		}
	}

	caller_nonce = mac_capability_proc_nonce(cred);

	rw_rlock(&fi_net_lock);
	/* Lock order for combined lookups is claim table, then auth table. */
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);

	/*
	 * Probe all 4 wildcard combinations of (port, domain):
	 *   (port, domain)  — exact match
	 *   (0, domain)     — "any port on this domain"
	 *   (port, 0)       — "this port on any domain"
	 *   (0, 0)          — "anything"
	 *
	 * Matching logic:
	 *   1. If ANY matching claim has our nonce → allow immediately.
	 *   2. If ANY matching claim authorizes our nonce → allow.
	 *   3. If claims exist but none match our nonce → EACCES.
	 *   4. If no claims match at all → allow (unclaimed resource).
	 */
	{
		u_long buckets[4];
		uint64_t denied_nonce, denied_id;
		int i, j;
		bool denied, dup;

		denied = false;
		denied_nonce = 0;
		denied_id = 0;

		buckets[0] = fi_net_hash_fn(port, domain);
		buckets[1] = fi_net_hash_fn(0, domain);
		buckets[2] = fi_net_hash_fn(port, 0);
		buckets[3] = fi_net_hash_fn(0, 0);

		for (i = 0; i < nitems(buckets); i++) {
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
				if (!fi_net_port_in_range(nc, port))
					continue;
				if (!fi_net_addr_match(nc, sa))
					continue;
				/* Claim matches */
				if (caller_nonce != 0 &&
				    caller_nonce == nc->fn_nonce) {
					SDT_PROBE6(mac_capability_isolation, , ,
					    allow__net, nc->fn_nonce,
					    caller_nonce, nc->fn_id,
					    domain,
					    ((uint32_t)protocol << 8) |
					    direction, port);
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_net_lock);
					return (0);
				}
				if (caller_nonce != 0 && fi_is_authorized_net(
				    caller_nonce, nc->fn_nonce, nc->fn_id, domain,
				    protocol, sa, direction)) {
					SDT_PROBE6(mac_capability_isolation, , ,
					    allow__net, nc->fn_nonce, caller_nonce,
					    nc->fn_id, domain,
					    ((uint32_t)protocol << 8) | direction,
					    port);
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_net_lock);
					return (0);
				}
				if (!denied) {
					denied = true;
					denied_nonce = nc->fn_nonce;
					denied_id = nc->fn_id;
				}
			}
		}

		if (denied) {
			/* Probe arguments compile out without KDTRACE_HOOKS. */
			(void)denied_nonce;
			(void)denied_id;
			SDT_PROBE3(mac_capability_isolation, , , deny,
			    (uintptr_t)"net", denied_nonce, caller_nonce);
			SDT_PROBE6(mac_capability_isolation, , , deny__net,
			    denied_nonce, caller_nonce, denied_id, domain,
			    ((uint32_t)protocol << 8) | direction, port);
			if (caller_nonce != 0)
				rw_runlock(&fi_auth_lock);
			rw_runlock(&fi_net_lock);
			return (fi_deny(EACCES));
		}
	}

	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_net_lock);
	return (0);
}

static int
fi_check_socket_create(struct ucred *cred, int domain, int type __unused,
    int protocol)
{
	struct fi_net_claim *nc;
	uint64_t caller_nonce, denied_id, denied_nonce;
	bool denied;

	if (domain == AF_VSOCK) {
		int error = fi_vsock_check_create(cred);
		if (error != 0)
			return (error);
	}
	/* Generic network claims cover only the families they can gate later. */
	if (domain != AF_INET && domain != AF_INET6 &&
	    domain != AF_BLUETOOTH)
		return (0);

	if (atomic_load_acq_int(&fi_net_claim_count) == 0)
		return (0);

	caller_nonce = mac_capability_proc_nonce(cred);
	denied = false;
	denied_id = 0;
	denied_nonce = 0;

	/*
	 * Only enforce for domain-wide claims: port=0, addr=0, and
	 * direction=FI_NET_ANY.  This prevents per-port or per-address
	 * claims from accidentally blocking socket creation.
	 * Only a fully-wildcard "block all networking" claim triggers here.
	 */
	rw_rlock(&fi_net_lock);
	/* Keep each wildcard claim stable across its authorization lookup. */
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
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
				/*
				 * Match if protocols are equal, either is
				 * wildcard (0), or caller used protocol=0
				 * (kernel default for the socket type).
				 */
				if (nc->fn_protocol != 0 &&
				    protocol != 0 &&
				    nc->fn_protocol != protocol)
					continue;
				if (nc->fn_port_min != 0 ||
				    nc->fn_port_max != UINT16_MAX)
					continue;
				if (nc->fn_direction != FI_NET_ANY)
					continue;
				if (memcmp(&nc->fn_addr, &zero_addr,
				    sizeof(zero_addr)) != 0)
					continue;
				/* Fully-wild claim — check nonce */
				if (caller_nonce != 0 &&
				    caller_nonce == nc->fn_nonce) {
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_net_lock);
					return (0);
				}
				/*
				 * Any token derived from this domain-wide claim
				 * permits creating an inert socket.  Its narrowed
				 * endpoint is still enforced by bind/connect below.
				 */
				if (caller_nonce != 0 && fi_is_authorized_net_socket(
				    caller_nonce, nc->fn_nonce, nc->fn_id, domain,
				    protocol)) {
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_net_lock);
					return (0);
				}
				if (!denied) {
					denied = true;
					denied_nonce = nc->fn_nonce;
					denied_id = nc->fn_id;
				}
			}
		}
	}
	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_net_lock);
	if (denied) {
		(void)denied_nonce;
		(void)denied_id;
		SDT_PROBE3(mac_capability_isolation, , , deny,
		    "socket_create", denied_nonce, caller_nonce);
		SDT_PROBE6(mac_capability_isolation, , , deny__net,
		    denied_nonce, caller_nonce, denied_id, domain,
		    ((uint32_t)protocol << 8) | FI_NET_ANY, 0);
		return (fi_deny(EACCES));
	}
	return (0);
}

static int
fi_check_socket_bind(struct ucred *cred, struct socket *so,
    struct label *solabel __unused, struct sockaddr *sa)
{
	int proto;

	if (sa == NULL)
		return (0);
	if (sa->sa_family == AF_VSOCK)
		return (fi_vsock_check(cred, sa, FI_NET_BIND));
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
	if (sa->sa_family == AF_VSOCK)
		return (fi_vsock_check(cred, sa, FI_NET_CONNECT));
	proto = so->so_proto->pr_protocol;
	return (fi_net_check(cred, sa->sa_family, proto, sa, FI_NET_CONNECT));
}

/* listen and accept not hooked — bind is the enforcement point */

/* ----------------------------------------------------------------
 * vsock isolation
 * ---------------------------------------------------------------- */

static __inline u_long
fi_vsock_hash_fn(uint32_t port, uint64_t cid)
{

	if (cid == VSOCK_CID_ANY)
		cid = 0;
	return (((u_long)port ^ (u_long)(cid >> 4)) & fi_vsock_hashmask);
}

static __inline uint32_t
fi_vsock_hash_port(uint32_t port_min, uint32_t port_max)
{

	return (port_min == port_max ? port_min : 0);
}

static __inline bool
fi_vsock_port_in_range(const struct fi_vsock_claim *vc, uint32_t port)
{

	return (port >= vc->fv_port_min && port <= vc->fv_port_max);
}

static bool
fi_vsock_cid_match(uint64_t claim_cid, uint64_t sa_cid)
{

	if (claim_cid == VSOCK_CID_ANY || sa_cid == VSOCK_CID_ANY)
		return (true);
	return (claim_cid == sa_cid);
}

static bool
fi_vsock_claim_covers_request(const struct fi_vsock_claim *vc,
    const struct fi_vsock_request *vr)
{

	if ((vc->fv_direction & vr->direction) != vr->direction)
		return (false);
	if (vc->fv_cid != VSOCK_CID_ANY &&
	    (vr->cid == VSOCK_CID_ANY || vc->fv_cid != vr->cid))
		return (false);
	if (vc->fv_port_min > vr->port_min || vc->fv_port_max < vr->port_max)
		return (false);
	return (true);
}

static bool
fi_vsock_claims_overlap(const struct fi_vsock_claim *existing,
    const struct fi_vsock_request *vr)
{
	bool direction_overlap;

	/*
	 * A provider owns the complete guest CID data path, so its claim
	 * overlaps bind/connect claims as well as another provider claim.
	 * Endpoint-only claims retain their independent direction semantics.
	 */
	direction_overlap =
	    ((existing->fv_direction | vr->direction) &
	    FI_VSOCK_PROVIDER) != 0 ||
	    (existing->fv_direction & vr->direction) != 0;
	if (!direction_overlap)
		return (false);
	if (existing->fv_cid != VSOCK_CID_ANY &&
	    vr->cid != VSOCK_CID_ANY &&
	    existing->fv_cid != vr->cid)
		return (false);
	if (existing->fv_port_min > vr->port_max ||
	    vr->port_min > existing->fv_port_max)
		return (false);
	return (true);
}

static bool
fi_auth_vsock_matches(const struct fi_auth *fa, uint64_t cid,
    uint32_t port, uint8_t direction)
{

	if (!fa->fa_is_vsock)
		return (false);
	if ((fa->fa_vsock.direction & direction) != direction)
		return (false);
	if (fa->fa_vsock.cid != VSOCK_CID_ANY &&
	    fa->fa_vsock.cid != cid)
		return (false);
	if (port < fa->fa_vsock.port_min || port > fa->fa_vsock.port_max)
		return (false);
	return (true);
}

static int
fi_is_authorized_vsock(uint64_t accessor, uint64_t owner, uint64_t claim_id,
    uint64_t cid, uint32_t port, uint8_t direction)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id &&
		    fi_auth_vsock_matches(fa, cid, port, direction))
			return (1);
	}
	return (0);
}

static int
fi_is_authorized_vsock_claim(uint64_t accessor, uint64_t owner,
    uint64_t claim_id)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id && fa->fa_is_vsock)
			return (1);
	}
	return (0);
}

static bool
fi_auth_vsock_covers_request(const struct fi_auth *fa,
    const struct fi_vsock_request *vr)
{

	if (!fa->fa_is_vsock)
		return (false);
	if ((fa->fa_vsock.direction & vr->direction) != vr->direction)
		return (false);
	if (fa->fa_vsock.cid != VSOCK_CID_ANY &&
	    (vr->cid == VSOCK_CID_ANY || fa->fa_vsock.cid != vr->cid))
		return (false);
	return (fa->fa_vsock.port_min <= vr->port_min &&
	    fa->fa_vsock.port_max >= vr->port_max);
}

static int
fi_is_authorized_vsock_request(uint64_t accessor, uint64_t owner,
    uint64_t claim_id, const struct fi_vsock_request *vr)
{
	struct fi_auth *fa;

	rw_assert(&fi_auth_lock, RA_RLOCKED);
	LIST_FOREACH(fa, FI_AUTH_BUCKET(owner), fa_link) {
		if (fa->fa_accessor == accessor && fa->fa_owner == owner &&
		    fa->fa_claim_id == claim_id &&
		    fi_auth_vsock_covers_request(fa, vr))
			return (1);
	}
	return (0);
}

static int
fi_vsock_check(struct ucred *cred, struct sockaddr *sa, uint8_t direction)
{
	struct fi_vsock_claim *vc;
	struct sockaddr_vm *svm;
	uint64_t caller_nonce, cid, denied_id, denied_nonce;
	uint32_t port;
	bool denied;

	if (atomic_load_acq_int(&fi_vsock_claim_count) == 0)
		return (0);

	if (sa == NULL || sa->sa_family != AF_VSOCK)
		return (0);
	/* The MAC hook sees the caller-controlled sockaddr before AF_VSOCK. */
	if (sa->sa_len != 0 && sa->sa_len < sizeof(*svm))
		return (0);

	svm = (struct sockaddr_vm *)sa;
	cid = svm->svm_cid;
	port = svm->svm_port;

	caller_nonce = mac_capability_proc_nonce(cred);
	denied = false;
	denied_nonce = 0;
	denied_id = 0;

	rw_rlock(&fi_vsock_lock);
	/* Lock order for combined lookups is claim table, then auth table. */
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
	{
		u_long buckets[FI_VSOCK_HASH_SIZE];
		int nbuckets, i, j;
		bool dup;

		/*
		 * A wildcard bind can be assigned any concrete local CID or
		 * ephemeral port by the protocol.  Scan every bucket so such a
		 * bind cannot evade an exact claim.  Concrete endpoints retain the
		 * four-bucket fast path (exact/range crossed with exact/wild CID).
		 */
		if (cid == VSOCK_CID_ANY || port == VSOCK_PORT_ANY) {
			nbuckets = fi_vsock_hashmask + 1;
			KASSERT((u_int)nbuckets <= nitems(buckets),
			    ("vsock hash grew beyond lookup array"));
			for (i = 0; i < nbuckets; i++)
				buckets[i] = i;
		} else {
			nbuckets = 4;
			buckets[0] = fi_vsock_hash_fn(port, cid);
			buckets[1] = fi_vsock_hash_fn(0, cid);
			buckets[2] = fi_vsock_hash_fn(port, 0);
			buckets[3] = fi_vsock_hash_fn(0, 0);
		}

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

			LIST_FOREACH(vc, &fi_vsock_hash[buckets[i]],
			    fv_hashlink) {
				if (!(vc->fv_direction & direction))
					continue;
				if (!fi_vsock_cid_match(vc->fv_cid, cid))
					continue;
				if (port != VSOCK_PORT_ANY &&
				    !fi_vsock_port_in_range(vc, port))
					continue;
				if (caller_nonce != 0 &&
				    caller_nonce == vc->fv_nonce) {
					SDT_PROBE6(mac_capability_isolation, , ,
					    allow__vsock, vc->fv_nonce,
					    caller_nonce, vc->fv_id, cid, port,
					    direction);
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_vsock_lock);
					return (0);
				}
				if (caller_nonce != 0 && fi_is_authorized_vsock(
				    caller_nonce, vc->fv_nonce, vc->fv_id, cid, port,
				    direction)) {
					SDT_PROBE6(mac_capability_isolation, , ,
					    allow__vsock, vc->fv_nonce, caller_nonce,
					    vc->fv_id, cid, port, direction);
					rw_runlock(&fi_auth_lock);
					rw_runlock(&fi_vsock_lock);
					return (0);
				}
				if (!denied) {
					denied = true;
					denied_nonce = vc->fv_nonce;
					denied_id = vc->fv_id;
				}
			}
		}
	}

	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_vsock_lock);
	if (denied) {
		/* SDT arguments compile out in kernels built without KDTRACE_HOOKS. */
		(void)denied_nonce;
		(void)denied_id;
		SDT_PROBE3(mac_capability_isolation, , , deny,
		    (uintptr_t)(direction == FI_NET_BIND ? "vsock_bind" :
		    "vsock_connect"), denied_nonce, caller_nonce);
		SDT_PROBE6(mac_capability_isolation, , , deny__vsock,
		    denied_nonce, caller_nonce, denied_id, cid, port, direction);
		return (fi_deny(EACCES));
	}
	return (0);
}

static int
fi_vsock_check_create(struct ucred *cred)
{
	struct fi_vsock_claim *vc;
	uint64_t caller_nonce, denied_id, denied_nonce;
	bool denied;

	if (atomic_load_acq_int(&fi_vsock_claim_count) == 0)
		return (0);

	caller_nonce = mac_capability_proc_nonce(cred);
	denied = false;
	denied_id = 0;
	denied_nonce = 0;

	rw_rlock(&fi_vsock_lock);
	/* Keep the claim stable while consulting its authorization entry. */
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
	{
		u_long bucket = fi_vsock_hash_fn(0, 0);

		LIST_FOREACH(vc, &fi_vsock_hash[bucket], fv_hashlink) {
			if (vc->fv_cid != VSOCK_CID_ANY)
				continue;
			if (vc->fv_port_min != 0 ||
			    vc->fv_port_max != UINT32_MAX)
				continue;
			if ((vc->fv_direction & FI_NET_ANY) != FI_NET_ANY)
				continue;
			if (caller_nonce != 0 &&
			    caller_nonce == vc->fv_nonce) {
				SDT_PROBE6(mac_capability_isolation, , ,
				    allow__vsock, vc->fv_nonce, caller_nonce,
				    vc->fv_id, VSOCK_CID_ANY, 0, FI_NET_ANY);
				rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_vsock_lock);
				return (0);
			}
			/*
			 * Any token derived from this domain-wide claim permits
			 * creating an inert socket.  Its narrowed CID, port, and
			 * direction are still enforced by bind/connect below.
			 */
			if (caller_nonce != 0 && fi_is_authorized_vsock_claim(
			    caller_nonce, vc->fv_nonce, vc->fv_id)) {
				SDT_PROBE6(mac_capability_isolation, , ,
				    allow__vsock, vc->fv_nonce, caller_nonce,
				    vc->fv_id, VSOCK_CID_ANY, 0, FI_NET_ANY);
				rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_vsock_lock);
				return (0);
			}
			if (!denied) {
				denied = true;
				denied_nonce = vc->fv_nonce;
				denied_id = vc->fv_id;
			}
		}
	}
	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_vsock_lock);
	if (denied) {
		(void)denied_nonce;
		(void)denied_id;
		SDT_PROBE3(mac_capability_isolation, , , deny,
		    "vsock_socket_create", denied_nonce, caller_nonce);
		SDT_PROBE6(mac_capability_isolation, , , deny__vsock,
		    denied_nonce, caller_nonce, denied_id, VSOCK_CID_ANY, 0,
		    FI_NET_ANY);
		return (fi_deny(EACCES));
	}
	return (0);
}

static int
fi_vsock_provider_init_label(struct label *label, int flag)
{
	struct fi_vsock_provider_label *pl;

	pl = malloc(sizeof(*pl), M_FILE_ISOLATION, flag | M_ZERO);
	if (pl == NULL)
		return (ENOMEM);
	FI_VSOCK_PROVIDER_SLOT_SET(label, pl);
	return (0);
}

static void
fi_vsock_provider_destroy_label(struct label *label)
{
	struct fi_vsock_provider_label *pl;

	pl = FI_VSOCK_PROVIDER_SLOT(label);
	FI_VSOCK_PROVIDER_SLOT_SET(label, NULL);
	free(pl, M_FILE_ISOLATION);
}

static int
fi_vsock_provider_check_attach(struct ucred *cred, uint64_t cid,
    struct label *label)
{
	struct fi_vsock_provider_label *pl;
	struct fi_vsock_claim *vc;
	struct fi_vsock_request vr;
	uint64_t caller_nonce, denied_id, denied_nonce;
	u_long i;
	bool claimed;

	pl = FI_VSOCK_PROVIDER_SLOT(label);
	if (pl == NULL)
		return (0);
	memset(pl, 0, sizeof(*pl));
	if (atomic_load_acq_int(&fi_vsock_claim_count) == 0)
		return (0);

	memset(&vr, 0, sizeof(vr));
	vr.cid = cid;
	vr.port_max = UINT32_MAX;
	vr.direction = FI_VSOCK_PROVIDER;
	caller_nonce = mac_capability_proc_nonce(cred);
	claimed = false;
	denied_nonce = 0;
	denied_id = 0;

	rw_rlock(&fi_vsock_lock);
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
	for (i = 0; i <= fi_vsock_hashmask; i++) {
		LIST_FOREACH(vc, &fi_vsock_hash[i], fv_hashlink) {
			if (!fi_vsock_cid_match(vc->fv_cid, cid))
				continue;
			claimed = true;
			if (!fi_vsock_claim_covers_request(vc, &vr))
				goto remember_denial;
			if (caller_nonce == vc->fv_nonce ||
			    (caller_nonce != 0 &&
			    fi_is_authorized_vsock_request(caller_nonce,
			    vc->fv_nonce, vc->fv_id, &vr))) {
				pl->fpl_owner = vc->fv_nonce;
				pl->fpl_claim_id = vc->fv_id;
				pl->fpl_protected = true;
				SDT_PROBE6(mac_capability_isolation, , ,
				    allow__vsock, vc->fv_nonce, caller_nonce,
				    vc->fv_id, cid, 0, FI_VSOCK_PROVIDER);
				if (caller_nonce != 0)
					rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_vsock_lock);
				return (0);
			}
remember_denial:
			if (denied_id == 0) {
				denied_nonce = vc->fv_nonce;
				denied_id = vc->fv_id;
			}
		}
	}
	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_vsock_lock);
	if (!claimed)
		return (0);
	(void)denied_nonce;
	(void)denied_id;
	SDT_PROBE3(mac_capability_isolation, , , deny,
	    "vsock_provider_attach", denied_nonce, caller_nonce);
	SDT_PROBE6(mac_capability_isolation, , , deny__vsock,
	    denied_nonce, caller_nonce, denied_id, cid, 0,
	    FI_VSOCK_PROVIDER);
	return (fi_deny(EACCES));
}

static int
fi_vsock_provider_check_access(struct ucred *cred, uint64_t cid,
    struct label *label)
{
	struct fi_vsock_provider_label *pl;
	struct fi_vsock_claim *vc;
	struct fi_vsock_request vr;
	uint64_t caller_nonce, denied_id, denied_nonce;
	u_long i;
	bool claimed;

	pl = FI_VSOCK_PROVIDER_SLOT(label);
	if (pl == NULL)
		return (0);
	/*
	 * A provider attached before a claim existed must not bypass a claim
	 * created later.  Unprotected labels therefore use a dynamic lookup.
	 * Labels attached under a claim stay pinned to that exact claim so
	 * closing it cannot silently turn a protected provider into an
	 * unrestricted one.
	 */
	if (!pl->fpl_protected &&
	    atomic_load_acq_int(&fi_vsock_claim_count) == 0)
		return (0);
	memset(&vr, 0, sizeof(vr));
	vr.cid = cid;
	vr.port_max = UINT32_MAX;
	vr.direction = FI_VSOCK_PROVIDER;
	caller_nonce = mac_capability_proc_nonce(cred);
	claimed = false;
	denied_nonce = pl->fpl_owner;
	denied_id = pl->fpl_claim_id;

	rw_rlock(&fi_vsock_lock);
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
	for (i = 0; i <= fi_vsock_hashmask; i++) {
		LIST_FOREACH(vc, &fi_vsock_hash[i], fv_hashlink) {
			if (pl->fpl_protected) {
				if (vc->fv_id != pl->fpl_claim_id ||
				    vc->fv_nonce != pl->fpl_owner)
					continue;
			} else if (!fi_vsock_cid_match(vc->fv_cid, cid)) {
				continue;
			}
			claimed = true;
			if (!fi_vsock_claim_covers_request(vc, &vr))
				goto remember_denial;
			if (caller_nonce == vc->fv_nonce ||
			    (caller_nonce != 0 &&
			    fi_is_authorized_vsock_request(caller_nonce,
			    vc->fv_nonce, vc->fv_id, &vr))) {
				if (caller_nonce != 0)
					rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_vsock_lock);
				return (0);
			}
remember_denial:
			if (denied_id == 0) {
				denied_nonce = vc->fv_nonce;
				denied_id = vc->fv_id;
			}
		}
	}
	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_vsock_lock);
	if (!pl->fpl_protected && !claimed)
		return (0);
	(void)denied_nonce;
	(void)denied_id;
	SDT_PROBE3(mac_capability_isolation, , , deny,
	    "vsock_provider_access", denied_nonce, caller_nonce);
	SDT_PROBE6(mac_capability_isolation, , , deny__vsock,
	    denied_nonce, caller_nonce, denied_id, cid, 0,
	    FI_VSOCK_PROVIDER);
	return (fi_deny(EACCES));
}

/* ----------------------------------------------------------------
 * Service operations
 * ---------------------------------------------------------------- */

static int
fi_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	static volatile uint64_t next_badge;

	return (MAC_CAPABILITY_CONNECT_BADGE(next_badge, badge_out));
}

static int
fi_init(struct mac_capability_instance *s, void *arg __unused)
{
	struct fi_priv *priv;

	priv = malloc(sizeof(*priv), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	LIST_INIT(&priv->fip_claims);
	LIST_INIT(&priv->fip_net_claims);
	LIST_INIT(&priv->fip_jail_claims);
	LIST_INIT(&priv->fip_vsock_claims);
	mac_capability_instance_set_priv(s, priv);
	return (0);
}

static int
fi_do_claim(struct mac_capability_instance *s, struct fi_priv *priv,
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
			SDT_PROBE3(mac_capability_isolation, , , deny,
			    "claim-conflict", nonce, existing->fi_nonce);
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
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"claim-move",
		    nonce, nonce, existing->fi_id, FI_OP_CLAIM, 0);
		return (0);
	}

	LIST_INSERT_HEAD(&fi_hash[fi_hash_vp(vp)], c, fi_hashlink);
	LIST_INSERT_HEAD(&priv->fip_claims, c, fi_instlink);
	c->fi_id = fi_alloc_claim_id();
	atomic_add_int(&fi_claim_count, 1);
	if (vp->v_type == VDIR)
		atomic_add_int(&fi_dir_claim_count, 1);
	rw_wunlock(&fi_lock);
	SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"claim",
	    nonce, nonce, c->fi_id, FI_OP_CLAIM, 0);
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
		SDT_PROBE3(mac_capability_isolation, , , deny,
		    "release-wrong-nonce", nonce, c->fi_nonce);
		return (EACCES);
	}
	LIST_REMOVE(c, fi_hashlink);
	LIST_REMOVE(c, fi_instlink);
	atomic_subtract_int(&fi_claim_count, 1);
	if (c->fi_vp->v_type == VDIR)
		atomic_subtract_int(&fi_dir_claim_count, 1);
	rw_wunlock(&fi_lock);

	vrele(c->fi_vp);
	SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"release",
	    nonce, nonce, c->fi_id, FI_OP_RELEASE, 0);
	free(c, M_FILE_ISOLATION);
	return (0);
}

static int
fi_do_query(struct file *fp, uint64_t nonce, uint64_t actions,
    struct fi_reply *rpl)
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
		if (nonce != 0 && c->fi_nonce == nonce) {
			rpl->flags |= FI_QF_MINE;
		} else if (nonce != 0) {
			rw_rlock(&fi_auth_lock);
			if (fi_is_authorized(nonce, c->fi_nonce, c->fi_id,
			    actions))
				rpl->flags |= FI_QF_AUTHORIZED;
			rw_runlock(&fi_auth_lock);
		}
	}
	rw_runlock(&fi_lock);
	return (0);
}

/* ----------------------------------------------------------------
 * Network claim/release
 * ---------------------------------------------------------------- */

static int
fi_do_claim_net(struct mac_capability_instance *s, struct fi_priv *priv,
    const struct fi_net_request *nr, uint64_t nonce)
{
	struct fi_net_claim *nc, *existing;
	u_long bucket;
	uint16_t port_min, port_max;

	port_min = ntohs(nr->port_min);
	port_max = ntohs(nr->port_max);
	bucket = fi_net_hash_fn(fi_net_hash_port(port_min, port_max),
	    nr->domain);

	/* Pre-allocate before taking the lock (M_WAITOK). */
	nc = malloc(sizeof(*nc), M_FILE_ISOLATION, M_WAITOK | M_ZERO);

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

		if (port_min != port_max) {
			nb = (int)fi_net_hashmask + 1;
		} else {
			scan_buckets[0] = fi_net_hash_fn(port_min,
			    nr->domain);
			scan_buckets[1] = fi_net_hash_fn(0, nr->domain);
			scan_buckets[2] = fi_net_hash_fn(port_min, 0);
			scan_buckets[3] = fi_net_hash_fn(0, 0);
		}

		for (bi = 0; bi < nb; bi++) {
			bdup = false;
			if (port_min == port_max) {
				for (bj = 0; bj < bi; bj++) {
					if (scan_buckets[bj] ==
					    scan_buckets[bi]) {
						bdup = true;
						break;
					}
				}
				if (bdup)
					continue;
			}
			LIST_FOREACH(existing, &fi_net_hash[
			    port_min == port_max ? scan_buckets[bi] : bi],
			    fn_hashlink) {
				/* Check overlap: ports */
				if (!fi_net_port_ranges_overlap(
				    existing->fn_port_min,
				    existing->fn_port_max, port_min, port_max))
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
					free(nc, M_FILE_ISOLATION);
					SDT_PROBE3(mac_capability_isolation, , , deny,
					    "net-claim-conflict", nonce,
					    existing->fn_nonce);
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
		if (existing->fn_port_min != port_min ||
		    existing->fn_port_max != port_max ||
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
		free(nc, M_FILE_ISOLATION);
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"net-claim-move",
		    nonce, nonce, existing->fn_id, FI_OP_CLAIM_NET, 0);
		return (0);
	}

	/* New claim — insert (nc was pre-allocated above) */
	nc->fn_domain = nr->domain;
	nc->fn_protocol = nr->protocol;
	nc->fn_port_min = port_min;
	nc->fn_port_max = port_max;
	nc->fn_direction = nr->direction;
	nc->fn_prefix = nr->prefix;
	memcpy(&nc->fn_addr, nr->addr, sizeof(nc->fn_addr));
	nc->fn_nonce = nonce;
	nc->fn_inst = s;
	nc->fn_id = fi_alloc_claim_id();

	LIST_INSERT_HEAD(&fi_net_hash[bucket], nc, fn_hashlink);
	LIST_INSERT_HEAD(&priv->fip_net_claims, nc, fn_instlink);
	atomic_add_int(&fi_net_claim_count, 1);
	rw_wunlock(&fi_net_lock);

	SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"net-claim",
	    nonce, nonce, nc->fn_id, FI_OP_CLAIM_NET, 0);
	return (0);
}

/*
 * Release a network claim.  Search the global hash by nonce (not by
 * instance), matching the vnode release model: any same-nonce instance
 * can release a claim.
 */
static int
fi_do_release_net(const struct fi_net_request *nr, uint64_t nonce)
{
	struct fi_net_claim *nc;
	u_long bucket;
	uint16_t port_min, port_max;

	port_min = ntohs(nr->port_min);
	port_max = ntohs(nr->port_max);
	bucket = fi_net_hash_fn(fi_net_hash_port(port_min, port_max),
	    nr->domain);

	rw_wlock(&fi_net_lock);
	LIST_FOREACH(nc, &fi_net_hash[bucket], fn_hashlink) {
		if (nc->fn_nonce != nonce)
			continue;
		if (nc->fn_port_min != port_min ||
		    nc->fn_port_max != port_max)
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
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"net-release",
		    nonce, nonce, nc->fn_id, FI_OP_RELEASE_NET, 0);
		free(nc, M_FILE_ISOLATION);
		return (0);
	}
	rw_wunlock(&fi_net_lock);
	return (ENOENT);
}

static int
fi_do_query_net(const struct fi_net_request *nr, uint64_t nonce,
    struct fi_reply *rpl)
{
	struct fi_net_claim *nc;
	u_long buckets[4];
	uint16_t port_min, port_max, hash_port;
	int i, j;
	bool dup;

	port_min = ntohs(nr->port_min);
	port_max = ntohs(nr->port_max);
	hash_port = fi_net_hash_port(port_min, port_max);

	buckets[0] = fi_net_hash_fn(hash_port, nr->domain);
	buckets[1] = fi_net_hash_fn(0, nr->domain);
	buckets[2] = fi_net_hash_fn(hash_port, 0);
	buckets[3] = fi_net_hash_fn(0, 0);

	rpl->flags = 0;
	rw_rlock(&fi_net_lock);
	if (nonce != 0)
		rw_rlock(&fi_auth_lock);
	for (i = 0; i < nitems(buckets); i++) {
		dup = false;
		for (j = 0; j < i; j++) {
			if (buckets[j] == buckets[i]) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;
		LIST_FOREACH(nc, &fi_net_hash[buckets[i]], fn_hashlink) {
			if (!fi_net_claim_covers_request(nc, nr))
				continue;
			rpl->flags |= FI_QF_CLAIMED;
			if (nonce != 0 && nc->fn_nonce == nonce) {
				rpl->flags |= FI_QF_MINE;
				rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_net_lock);
				return (0);
			}
			if (nonce != 0 && fi_is_authorized_net_request(nonce,
			    nc->fn_nonce, nc->fn_id, nr))
				rpl->flags |= FI_QF_AUTHORIZED;
		}
	}
	if (nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_net_lock);
	SDT_PROBE5(mac_capability_isolation, , , query, "net", nonce,
	    (uint64_t)0, (uint64_t)0, rpl->flags);
	return (0);
}

static int
fi_validate_jail_request(const void *req, size_t reqlen,
    struct fi_jail_request *out, bool need_actions)
{
	const struct fi_jail_request *jr;

	if (reqlen < sizeof(*jr))
		return (EINVAL);
	jr = req;
	if (jr->flags != 0 || jr->jid < 0)
		return (EINVAL);
	if (memchr(jr->name, '\0', sizeof(jr->name)) == NULL)
		return (ENAMETOOLONG);
	if (jr->jid == 0 && jr->name[0] == '\0')
		return (EINVAL);
	if (need_actions &&
	    (jr->actions == 0 || (jr->actions & ~FI_JAIL_ALL) != 0))
		return (EINVAL);
	/* Even when actions are optional, reject invalid bits. */
	if (!need_actions && jr->actions != 0 &&
	    (jr->actions & ~FI_JAIL_ALL) != 0)
		return (EINVAL);
	*out = *jr;
	return (0);
}

/*
 * Conflict predicate for jail claims.  Two claims overlap if they
 * share a JID or share a name, and their action masks intersect.
 * This is intentionally broader than request-matching: a claim for
 * {jid=5,name=A} must conflict with {jid=5,name=B} to prevent
 * a foreign process from claiming the same JID under a different name.
 */
static bool
fi_jail_claims_overlap(const struct fi_jail_claim *a,
    const struct fi_jail_request *b)
{
	uint32_t b_actions;

	b_actions = b->actions != 0 ? b->actions : FI_JAIL_ALL;
	if ((a->fj_actions & b_actions) == 0)
		return (false);

	/* Same JID (when both specify one). */
	if (a->fj_jid != 0 && b->jid != 0 && a->fj_jid == b->jid)
		return (true);
	/* Same name (when both specify one). */
	if (a->fj_name[0] != '\0' && b->name[0] != '\0' &&
	    strcmp(a->fj_name, b->name) == 0)
		return (true);
	return (false);
}

static int
fi_do_claim_jail(struct mac_capability_instance *s, struct fi_priv *priv,
    const struct fi_jail_request *jr, uint64_t nonce)
{
	struct fi_jail_claim *jc, *existing;

	jc = malloc(sizeof(*jc), M_FILE_ISOLATION, M_WAITOK | M_ZERO);
	jc->fj_jid = jr->jid;
	jc->fj_actions = jr->actions != 0 ? jr->actions : FI_JAIL_ALL;
	strlcpy(jc->fj_name, jr->name, sizeof(jc->fj_name));
	jc->fj_nonce = nonce;
	jc->fj_id = fi_alloc_claim_id();
	jc->fj_inst = s;

	rw_wlock(&fi_jail_lock);
	LIST_FOREACH(existing, &fi_jail_claims, fj_link) {
		if (!fi_jail_claims_overlap(existing, jr))
			continue;
		if (existing->fj_nonce != nonce) {
			rw_wunlock(&fi_jail_lock);
			free(jc, M_FILE_ISOLATION);
			SDT_PROBE3(mac_capability_isolation, , , deny,
			    "jail-claim-conflict", nonce,
			    existing->fj_nonce);
			return (EBUSY);
		}
		if (existing->fj_jid == jc->fj_jid &&
		    strcmp(existing->fj_name, jc->fj_name) == 0) {
			/* Same identity — merge action masks. */
			existing->fj_actions |= jc->fj_actions;
			if (existing->fj_inst != s) {
				LIST_REMOVE(existing, fj_instlink);
				LIST_INSERT_HEAD(&priv->fip_jail_claims,
				    existing, fj_instlink);
				existing->fj_inst = s;
			}
			rw_wunlock(&fi_jail_lock);
			free(jc, M_FILE_ISOLATION);
			return (0);
		}
	}

	LIST_INSERT_HEAD(&fi_jail_claims, jc, fj_link);
	LIST_INSERT_HEAD(&priv->fip_jail_claims, jc, fj_instlink);
	atomic_add_int(&fi_jail_claim_count, 1);
	rw_wunlock(&fi_jail_lock);
	SDT_PROBE6(mac_capability_isolation, , , state, "jail-claim",
	    nonce, nonce, jc->fj_id, FI_OP_CLAIM_JAIL, 0);
	return (0);
}

static int
fi_do_release_jail(const struct fi_jail_request *jr, uint64_t nonce)
{
	struct fi_jail_claim *jc;
	uint32_t release_actions;

	release_actions = jr->actions != 0 ? jr->actions : FI_JAIL_ALL;

	rw_wlock(&fi_jail_lock);
	LIST_FOREACH(jc, &fi_jail_claims, fj_link) {
		if (jc->fj_jid != jr->jid ||
		    strcmp(jc->fj_name, jr->name) != 0)
			continue;
		if (jc->fj_nonce != nonce) {
			rw_wunlock(&fi_jail_lock);
			return (EPERM);
		}
		jc->fj_actions &= ~release_actions;
		if (jc->fj_actions == 0) {
			LIST_REMOVE(jc, fj_link);
			LIST_REMOVE(jc, fj_instlink);
			atomic_subtract_int(&fi_jail_claim_count, 1);
			rw_wunlock(&fi_jail_lock);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "jail-release", nonce, nonce, jc->fj_id,
			    FI_OP_RELEASE_JAIL, 0);
			free(jc, M_FILE_ISOLATION);
		} else {
			rw_wunlock(&fi_jail_lock);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "jail-release-partial", nonce, nonce,
			    jc->fj_id, FI_OP_RELEASE_JAIL, 0);
		}
		return (0);
	}
	rw_wunlock(&fi_jail_lock);
	return (ENOENT);
}

static int
fi_do_query_jail(const struct fi_jail_request *jr, uint64_t nonce,
    struct fi_reply *rpl)
{
	struct fi_jail_claim *jc;

	rw_rlock(&fi_jail_lock);
	if (nonce != 0)
		rw_rlock(&fi_auth_lock);
	LIST_FOREACH(jc, &fi_jail_claims, fj_link) {
		if (!fi_jail_claim_matches(jc, jr))
			continue;
		rpl->flags |= FI_QF_CLAIMED;
		if (nonce != 0 && jc->fj_nonce == nonce) {
			rpl->flags |= FI_QF_MINE;
			rw_runlock(&fi_auth_lock);
			rw_runlock(&fi_jail_lock);
			SDT_PROBE5(mac_capability_isolation, , , query, "jail",
			    nonce, (uint64_t)0, (uint64_t)0, rpl->flags);
			return (0);
		}
		if (nonce != 0 && fi_is_authorized_jail(nonce,
		    jc->fj_nonce, jc->fj_id, jr))
			rpl->flags |= FI_QF_AUTHORIZED;
	}
	if (nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_jail_lock);
	SDT_PROBE5(mac_capability_isolation, , , query, "jail",
	    nonce, (uint64_t)0, (uint64_t)0, rpl->flags);
	return (0);
}

/* ----------------------------------------------------------------
 * vsock claim/release/query
 * ---------------------------------------------------------------- */

static int
fi_validate_vsock_request(const void *req, size_t reqlen,
    struct fi_vsock_request *out)
{
	const struct fi_vsock_request *vr;

	if (reqlen < sizeof(*vr))
		return (EINVAL);
	vr = (const struct fi_vsock_request *)req;
	if (vr->flags != 0)
		return (EINVAL);
	if (vr->cid > UINT32_MAX)
		return (EINVAL);
	if (vr->direction == 0 || (vr->direction & ~FI_VSOCK_ANY) != 0)
		return (EINVAL);
	if (vr->port_min > vr->port_max)
		return (EINVAL);
	if ((vr->direction & FI_VSOCK_PROVIDER) != 0 &&
	    (vr->cid == VSOCK_CID_ANY || vr->port_min != 0 ||
	    vr->port_max != UINT32_MAX))
		return (EINVAL);
	*out = *vr;
	return (0);
}

static int
fi_do_claim_vsock(struct mac_capability_instance *s, struct fi_priv *priv,
    const struct fi_vsock_request *vr, uint64_t nonce)
{
	struct fi_vsock_claim *vc, *existing;
	u_long bucket;
	uint32_t hash_port;

	hash_port = fi_vsock_hash_port(vr->port_min, vr->port_max);
	bucket = fi_vsock_hash_fn(hash_port, vr->cid);

	vc = malloc(sizeof(*vc), M_FILE_ISOLATION, M_WAITOK | M_ZERO);

	rw_wlock(&fi_vsock_lock);

	/* Scan for conflicts from foreign nonces. */
	{
		u_long i;

		for (i = 0; i <= fi_vsock_hashmask; i++) {
			LIST_FOREACH(existing, &fi_vsock_hash[i],
			    fv_hashlink) {
				if (!fi_vsock_claims_overlap(existing, vr))
					continue;
				if (existing->fv_nonce != nonce) {
					rw_wunlock(&fi_vsock_lock);
					free(vc, M_FILE_ISOLATION);
					return (EBUSY);
				}
			}
		}
	}

	/* Check for exact same-nonce duplicate — re-claim. */
	LIST_FOREACH(existing, &fi_vsock_hash[bucket], fv_hashlink) {
		if (existing->fv_nonce != nonce)
			continue;
		if (existing->fv_port_min != vr->port_min ||
		    existing->fv_port_max != vr->port_max ||
		    existing->fv_cid != vr->cid ||
		    existing->fv_direction != vr->direction)
			continue;
		/* Exact re-claim — transfer to this instance */
		LIST_REMOVE(existing, fv_instlink);
		LIST_INSERT_HEAD(&priv->fip_vsock_claims, existing,
		    fv_instlink);
		existing->fv_inst = s;
		SDT_PROBE6(mac_capability_isolation, , , state,
		    "vsock-reclaim", nonce, nonce, existing->fv_id,
		    FI_OP_CLAIM_VSOCK, 0);
		rw_wunlock(&fi_vsock_lock);
		free(vc, M_FILE_ISOLATION);
		return (0);
	}

	/* New claim */
	vc->fv_cid = vr->cid;
	vc->fv_port_min = vr->port_min;
	vc->fv_port_max = vr->port_max;
	vc->fv_direction = vr->direction;
	vc->fv_nonce = nonce;
	vc->fv_inst = s;
	vc->fv_id = fi_alloc_claim_id();

	LIST_INSERT_HEAD(&fi_vsock_hash[bucket], vc, fv_hashlink);
	LIST_INSERT_HEAD(&priv->fip_vsock_claims, vc, fv_instlink);
	atomic_add_int(&fi_vsock_claim_count, 1);
	SDT_PROBE6(mac_capability_isolation, , , state, "vsock-claim",
	    nonce, nonce, vc->fv_id, FI_OP_CLAIM_VSOCK, 0);
	rw_wunlock(&fi_vsock_lock);
	return (0);
}

static int
fi_do_release_vsock(const struct fi_vsock_request *vr, uint64_t nonce)
{
	struct fi_vsock_claim *vc;
	u_long bucket;
	uint32_t hash_port;

	hash_port = fi_vsock_hash_port(vr->port_min, vr->port_max);
	bucket = fi_vsock_hash_fn(hash_port, vr->cid);

	rw_wlock(&fi_vsock_lock);
	LIST_FOREACH(vc, &fi_vsock_hash[bucket], fv_hashlink) {
		if (vc->fv_nonce != nonce)
			continue;
		if (vc->fv_port_min != vr->port_min ||
		    vc->fv_port_max != vr->port_max)
			continue;
		if (vc->fv_cid != vr->cid)
			continue;
		if (vc->fv_direction != vr->direction)
			continue;
		LIST_REMOVE(vc, fv_hashlink);
		LIST_REMOVE(vc, fv_instlink);
		atomic_subtract_int(&fi_vsock_claim_count, 1);
		SDT_PROBE6(mac_capability_isolation, , , state,
		    "vsock-release", nonce, nonce, vc->fv_id,
		    FI_OP_RELEASE_VSOCK, 0);
		rw_wunlock(&fi_vsock_lock);
		free(vc, M_FILE_ISOLATION);
		return (0);
	}
	rw_wunlock(&fi_vsock_lock);
	return (ENOENT);
}

static int
fi_do_query_vsock(const struct fi_vsock_request *vr, uint64_t nonce,
    struct fi_reply *rpl)
{
	struct fi_vsock_claim *vc;
	u_long buckets[4];
	uint32_t hash_port;
	int i, j;
	bool dup;

	hash_port = fi_vsock_hash_port(vr->port_min, vr->port_max);

	buckets[0] = fi_vsock_hash_fn(hash_port, vr->cid);
	buckets[1] = fi_vsock_hash_fn(0, vr->cid);
	buckets[2] = fi_vsock_hash_fn(hash_port, 0);
	buckets[3] = fi_vsock_hash_fn(0, 0);

	rpl->flags = 0;
	rw_rlock(&fi_vsock_lock);
	if (nonce != 0)
		rw_rlock(&fi_auth_lock);
	for (i = 0; i < nitems(buckets); i++) {
		dup = false;
		for (j = 0; j < i; j++) {
			if (buckets[j] == buckets[i]) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;
		LIST_FOREACH(vc, &fi_vsock_hash[buckets[i]], fv_hashlink) {
			if (!fi_vsock_claim_covers_request(vc, vr))
				continue;
			rpl->flags |= FI_QF_CLAIMED;
			if (nonce != 0 && vc->fv_nonce == nonce) {
				rpl->flags |= FI_QF_MINE;
				rw_runlock(&fi_auth_lock);
				rw_runlock(&fi_vsock_lock);
				SDT_PROBE5(mac_capability_isolation, , , query,
				    "vsock", nonce, (uint64_t)0, (uint64_t)0,
				    rpl->flags);
				return (0);
			}
			if (nonce != 0 && fi_is_authorized_vsock_request(nonce,
			    vc->fv_nonce, vc->fv_id, vr))
				rpl->flags |= FI_QF_AUTHORIZED;
		}
	}
	if (nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_vsock_lock);
	SDT_PROBE5(mac_capability_isolation, , , query, "vsock", nonce,
	    (uint64_t)0, (uint64_t)0, rpl->flags);
	return (0);
}

/*
 * Validate a network claim/release request.  Returns 0 on success
 * and sets *nrp to the validated request pointer.
 */
static int
fi_validate_net_request(const void *req, size_t reqlen,
    struct fi_net_request *out)
{
	const struct fi_net_request *nr;
	uint16_t port_min, port_max;

	if (reqlen < sizeof(struct fi_net_request))
		return (EINVAL);
	nr = (const struct fi_net_request *)req;
	if (nr->flags != 0 || nr->direction == 0 ||
	    (nr->direction & ~FI_NET_ANY) != 0)
		return (EINVAL);
	/* Validate domain: AF_INET, AF_INET6, AF_BLUETOOTH, or 0 (wildcard) */
	if (nr->domain != 0 && nr->domain != AF_INET &&
	    nr->domain != AF_INET6 && nr->domain != AF_BLUETOOTH)
		return (EINVAL);
	/* Validate protocol and prefix per domain */
	if (nr->domain == AF_BLUETOOTH) {
		if (nr->protocol != 0 &&
		    nr->protocol != BLUETOOTH_PROTO_L2CAP &&
		    nr->protocol != BLUETOOTH_PROTO_RFCOMM &&
		    nr->protocol != BLUETOOTH_PROTO_SCO &&
		    nr->protocol != BLUETOOTH_PROTO_ISO)
			return (EINVAL);
		/* BD_ADDR prefix: only 0 (any) or 48 (exact) */
		if (nr->prefix != 0 && nr->prefix != 48)
			return (EINVAL);
	} else {
		/* Validate protocol: IPPROTO_TCP, IPPROTO_UDP, or 0 */
		if (nr->protocol != 0 && nr->protocol != IPPROTO_TCP &&
		    nr->protocol != IPPROTO_UDP)
			return (EINVAL);
		/* Validate prefix: IPv4 max /32, IPv6 max /128 */
		if (nr->domain == AF_INET && nr->prefix > 32)
			return (EINVAL);
		if (nr->prefix > 128)
			return (EINVAL);
	}
	port_min = ntohs(nr->port_min);
	port_max = ntohs(nr->port_max);
	if (port_min > port_max)
		return (EINVAL);
	*out = *nr;
	return (0);
}

/*
 * Mint a token fd, set it as a token with the given owner nonce,
 * and fill the reply fd slot.  Shared by FI_OP_MINT, FI_OP_MINT_NET,
 * FI_OP_MINT_JAIL, and FI_OP_MINT_VSOCK.
 */
static int
fi_mint_token(uint64_t caller_nonce, uint64_t claim_id, uint64_t fs_actions,
    const struct fi_net_request *net, const struct fi_jail_request *jail,
    const struct fi_vsock_request *vsock,
    struct file **reply_fds,
    int *reply_nfdsp, size_t *replylenp)
{
	struct file *token_fp;
	struct fi_priv *tp;
	int error;

	error = mac_capability_mint_fp(fi_svc, 0, &token_fp);
	if (error != 0) {
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"mint-error",
		    caller_nonce, caller_nonce, (uint64_t)0,
		    (net != NULL ? FI_OP_MINT_NET : FI_OP_MINT), error);
		return (error);
	}

	tp = mac_capability_instance_get_priv(token_fp->f_data);
	if (tp == NULL) {
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"mint-priv-null",
		    caller_nonce, caller_nonce, claim_id,
		    (net != NULL ? FI_OP_MINT_NET : FI_OP_MINT), ENOMEM);
		fdrop(token_fp, curthread);
		return (ENOMEM);
	}
	tp->fip_is_token = true;
	tp->fip_token_owner = caller_nonce;
	tp->fip_token_claim_id = claim_id;
	tp->fip_token_fs_actions = fs_actions;
	if (net != NULL) {
		tp->fip_token_is_net = true;
		tp->fip_token_net = *net;
	}
	if (jail != NULL) {
		tp->fip_token_is_jail = true;
		tp->fip_token_jail = *jail;
	}
	if (vsock != NULL) {
		tp->fip_token_is_vsock = true;
		tp->fip_token_vsock = *vsock;
	}

	reply_fds[0] = token_fp;
	*reply_nfdsp = 1;
	*replylenp = sizeof(struct fi_reply);

	if ((net == NULL && jail == NULL && vsock == NULL &&
	    fs_actions != FI_FS_ALL) ||
	    net != NULL || vsock != NULL ||
	    (jail != NULL && jail->actions != FI_JAIL_ALL)) {
		SDT_PROBE5(mac_capability_isolation, , , token__narrow,
		    (net != NULL ? "net" :
		    (jail != NULL ? "jail" :
		    (vsock != NULL ? "vsock" : "file"))),
		    caller_nonce, claim_id, fs_actions, (uint64_t)0);
	}

	SDT_PROBE6(mac_capability_isolation, , , state,
	    (net != NULL ? "net-token-mint" :
	    (jail != NULL ? "jail-token-mint" :
	    (vsock != NULL ? "vsock-token-mint" : "token-mint"))),
	    caller_nonce, caller_nonce, claim_id,
	    (net != NULL ? FI_OP_MINT_NET :
	    (jail != NULL ? FI_OP_MINT_JAIL :
	    (vsock != NULL ? FI_OP_MINT_VSOCK : FI_OP_MINT))), 0);
	return (0);
}

/* ----------------------------------------------------------------
 * Service call handler
 * ---------------------------------------------------------------- */

static int
fi_call(struct mac_capability_instance *s,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
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
	priv = mac_capability_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	caller_nonce = mac_capability_proc_nonce(curthread->td_ucred);
	if (caller_nonce == 0) {
		SDT_PROBE3(mac_capability_isolation, , , deny, (uintptr_t)"nonce",
		    (uint64_t)0, (uint64_t)0);
		return (ENXIO);
	}

	rpl = reply;
	rpl->flags = 0;
	rpl->_pad = 0;
	*replylenp = sizeof(struct fi_reply);

	switch (fr->op) {
	case FI_OP_CLAIM:
		if (reqlen < sizeof(struct fi_request) || fr->flags != 0)
			return (EINVAL);
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_claim(s, priv, fds[0], caller_nonce));
	case FI_OP_RELEASE:
		if (reqlen < sizeof(struct fi_request) || fr->flags != 0)
			return (EINVAL);
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_release(fds[0], caller_nonce));
	case FI_OP_QUERY:
		if (reqlen < sizeof(struct fi_request) || fr->flags != 0)
			return (EINVAL);
		if (fr->actions == 0 || (fr->actions & ~FI_FS_ALL) != 0)
			return (EINVAL);
		if (nfds < 1)
			return (EINVAL);
		return (fi_do_query(fds[0], caller_nonce, fr->actions, rpl));

	case FI_OP_CLAIM_NET:
	{
		struct fi_net_request nr;
		int error;

		error = fi_validate_net_request(req, reqlen, &nr);
		if (error != 0)
			return (error);
		return (fi_do_claim_net(s, priv, &nr, caller_nonce));
	}
	case FI_OP_RELEASE_NET:
	{
		struct fi_net_request nr;
		int error;

		error = fi_validate_net_request(req, reqlen, &nr);
		if (error != 0)
			return (error);
		return (fi_do_release_net(&nr, caller_nonce));
	}
	case FI_OP_QUERY_NET:
	{
		struct fi_net_request nr;
		int error;

		error = fi_validate_net_request(req, reqlen, &nr);
		if (error != 0)
			return (error);
		return (fi_do_query_net(&nr, caller_nonce, rpl));
	}
	case FI_OP_CLAIM_JAIL:
	{
		struct fi_jail_request jr;
		int error;

		error = fi_validate_jail_request(req, reqlen, &jr, false);
		if (error != 0)
			return (error);
		return (fi_do_claim_jail(s, priv, &jr, caller_nonce));
	}
	case FI_OP_RELEASE_JAIL:
	{
		struct fi_jail_request jr;
		int error;

		error = fi_validate_jail_request(req, reqlen, &jr, false);
		if (error != 0)
			return (error);
		return (fi_do_release_jail(&jr, caller_nonce));
	}
	case FI_OP_QUERY_JAIL:
	{
		struct fi_jail_request jr;
		int error;

		error = fi_validate_jail_request(req, reqlen, &jr, true);
		if (error != 0)
			return (error);
		return (fi_do_query_jail(&jr, caller_nonce, rpl));
	}
	case FI_OP_MINT: {
		struct fi_claim *mc;
		uint64_t actions, claim_id;
		int error;

		/*
		 * Mint an access token for a vnode claim.  The caller
		 * must supply a valid FI_FS_* actions mask and be the
		 * claim owner (nonce match).  Pass the target vnode fd
		 * in req_fds[0].
		 */
		if (reqlen < sizeof(struct fi_request) || fr->flags != 0)
			return (EINVAL);
		actions = fr->actions;
		if (actions == 0 || (actions & ~FI_FS_ALL) != 0)
			return (EINVAL);
		if (priv->fip_is_token)
			return (EINVAL);
		if (nfds < 1)
			return (EINVAL);
		if (*reply_nfdsp < 1)
			return (EINVAL);
		if (fds[0]->f_vnode == NULL)
			return (EINVAL);

		rw_rlock(&fi_lock);
		mc = fi_claim_lookup(fds[0]->f_vnode);
		if (mc == NULL) {
			rw_runlock(&fi_lock);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "mint-no-claim", caller_nonce,
			    (uint64_t)0, (uint64_t)0,
			    FI_OP_MINT, ENOENT);
			return (ENOENT);
		}
		if (mc->fi_nonce != caller_nonce) {
			uint64_t owner __unused = mc->fi_nonce;

			rw_runlock(&fi_lock);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "mint-wrong-nonce", caller_nonce,
			    owner, (uint64_t)0,
			    FI_OP_MINT, EPERM);
			return (EPERM);
		}
		claim_id = mc->fi_id;
		rw_runlock(&fi_lock);

		error = fi_mint_token(caller_nonce, claim_id, actions,
		    NULL, NULL, NULL, reply_fds, reply_nfdsp, replylenp);
		return (error);
	}

		case FI_OP_MINT_NET: {
			struct fi_net_request nr;
			int error;
			uint16_t port_min, port_max, hash_port;
			uint64_t claim_id;

			/*
			 * Mint an access token for a network claim.  The
			 * caller must own the exact endpoint claim described
			 * by the request payload.
			 */
			error = fi_validate_net_request(req, reqlen, &nr);
			if (error != 0)
				return (error);
			if (priv->fip_is_token)
				return (EINVAL);
			if (*reply_nfdsp < 1)
				return (EINVAL);

			/* Verify the caller owns the exact net claim. */
			{
				struct fi_net_claim *nc;
				bool found = false;
				u_long buckets[4];
				int i, j;

				port_min = ntohs(nr.port_min);
				port_max = ntohs(nr.port_max);
				hash_port = fi_net_hash_port(port_min, port_max);
				buckets[0] = fi_net_hash_fn(hash_port, nr.domain);
				buckets[1] = fi_net_hash_fn(0, nr.domain);
				buckets[2] = fi_net_hash_fn(hash_port, 0);
				buckets[3] = fi_net_hash_fn(0, 0);
				rw_rlock(&fi_net_lock);
				for (i = 0; i < nitems(buckets) && !found; i++) {
					bool dup = false;

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
						if (nc->fn_nonce != caller_nonce)
							continue;
						if (!fi_net_claim_covers_request(nc,
						    &nr))
							continue;
						claim_id = nc->fn_id;
						found = true;
						break;
					}
				}
				rw_runlock(&fi_net_lock);
				if (!found) {
					SDT_PROBE6(mac_capability_isolation, , , state,
					    "mint-net-no-claim", caller_nonce,
					    (uint64_t)0, (uint64_t)0,
					    FI_OP_MINT_NET, ENOENT);
					return (ENOENT);
				}
			}

			error = fi_mint_token(caller_nonce, claim_id, 0, &nr,
			    NULL, NULL, reply_fds, reply_nfdsp, replylenp);
			return (error);
		}

		case FI_OP_MINT_JAIL: {
			struct fi_jail_request jr;
			struct fi_jail_claim *jc;
			uint64_t claim_id;
			bool found;
			int error;

			error = fi_validate_jail_request(req, reqlen, &jr,
			    true);
			if (error != 0)
				return (error);
			if (priv->fip_is_token)
				return (EINVAL);
			if (*reply_nfdsp < 1)
				return (EINVAL);

			found = false;
			claim_id = 0;
			rw_rlock(&fi_jail_lock);
			LIST_FOREACH(jc, &fi_jail_claims, fj_link) {
				if (jc->fj_nonce != caller_nonce)
					continue;
				if ((jc->fj_actions & jr.actions) !=
				    jr.actions)
					continue;
				if (!fi_jail_claim_matches(jc, &jr))
					continue;
				claim_id = jc->fj_id;
				found = true;
				break;
			}
			rw_runlock(&fi_jail_lock);
			if (!found) {
				SDT_PROBE6(mac_capability_isolation, , , state,
				    "mint-jail-no-claim", caller_nonce,
				    (uint64_t)0, (uint64_t)0,
				    FI_OP_MINT_JAIL, ENOENT);
				return (ENOENT);
			}

			error = fi_mint_token(caller_nonce, claim_id, 0, NULL,
			    &jr, NULL, reply_fds, reply_nfdsp, replylenp);
			return (error);
		}

	case FI_OP_CLAIM_VSOCK:
	{
		struct fi_vsock_request vr;
		int error;

		error = fi_validate_vsock_request(req, reqlen, &vr);
		if (error != 0)
			return (error);
		return (fi_do_claim_vsock(s, priv, &vr, caller_nonce));
	}
	case FI_OP_RELEASE_VSOCK:
	{
		struct fi_vsock_request vr;
		int error;

		error = fi_validate_vsock_request(req, reqlen, &vr);
		if (error != 0)
			return (error);
		return (fi_do_release_vsock(&vr, caller_nonce));
	}
	case FI_OP_QUERY_VSOCK:
	{
		struct fi_vsock_request vr;
		int error;

		error = fi_validate_vsock_request(req, reqlen, &vr);
		if (error != 0)
			return (error);
		return (fi_do_query_vsock(&vr, caller_nonce, rpl));
	}

		case FI_OP_MINT_VSOCK: {
			struct fi_vsock_request vr;
			struct fi_vsock_claim *vc;
			uint64_t claim_id;
			bool found;
			int error;

			error = fi_validate_vsock_request(req, reqlen, &vr);
			if (error != 0)
				return (error);
			if (priv->fip_is_token)
				return (EINVAL);
			if (*reply_nfdsp < 1)
				return (EINVAL);

			found = false;
			claim_id = 0;
			rw_rlock(&fi_vsock_lock);
			{
				u_long buckets[4];
				uint32_t hash_port;
				int i, j;

				hash_port = fi_vsock_hash_port(vr.port_min,
				    vr.port_max);
				buckets[0] = fi_vsock_hash_fn(hash_port,
				    vr.cid);
				buckets[1] = fi_vsock_hash_fn(0, vr.cid);
				buckets[2] = fi_vsock_hash_fn(hash_port, 0);
				buckets[3] = fi_vsock_hash_fn(0, 0);

				for (i = 0; i < nitems(buckets) && !found;
				    i++) {
					bool dup = false;

					for (j = 0; j < i; j++) {
						if (buckets[j] == buckets[i]) {
							dup = true;
							break;
						}
					}
					if (dup)
						continue;
					LIST_FOREACH(vc,
					    &fi_vsock_hash[buckets[i]],
					    fv_hashlink) {
						if (vc->fv_nonce !=
						    caller_nonce)
							continue;
						if (!fi_vsock_claim_covers_request(
						    vc, &vr))
							continue;
						claim_id = vc->fv_id;
						found = true;
						break;
					}
				}
			}
			rw_runlock(&fi_vsock_lock);
			if (!found)
				return (ENOENT);

			error = fi_mint_token(caller_nonce, claim_id, 0,
			    NULL, NULL, &vr, reply_fds, reply_nfdsp,
			    replylenp);
			return (error);
		}

	case FI_OP_AUTHORIZE: {
		int error;

		/*
		 * Called on a token fd.  Adds the caller's nonce to
		 * the authorized set for the token's owner nonce.
		 * The authorization lasts until this token fd closes.
		 */
			if (!priv->fip_is_token)
				return (EINVAL);
			if (priv->fip_token_owner == 0)
				return (EINVAL);

			error = fi_auth_add(caller_nonce, priv->fip_token_owner,
			    priv->fip_token_claim_id, priv->fip_token_fs_actions,
			    priv->fip_token_is_net ? &priv->fip_token_net : NULL,
			    priv->fip_token_is_jail ?
			    &priv->fip_token_jail : NULL,
			    priv->fip_token_is_vsock ?
			    &priv->fip_token_vsock : NULL,
			    s);
		if (error != 0)
			return (error);
		SDT_PROBE6(mac_capability_isolation, , , state,
		    (priv->fip_token_is_net ? "net-authorize" :
		    (priv->fip_token_is_jail ? "jail-authorize" :
		    (priv->fip_token_is_vsock ? "vsock-authorize" :
		    "authorize"))),
		    priv->fip_token_owner, caller_nonce,
		    priv->fip_token_claim_id, FI_OP_AUTHORIZE, 0);
		*replylenp = sizeof(struct fi_reply);
		return (0);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
fi_revoke(struct mac_capability_instance *s, uint64_t badge __unused,
    enum mac_capability_revoke_reason reason __unused, void *arg __unused)
{
	struct fi_priv *priv;
	struct fi_claim *c;
	LIST_HEAD(, fi_claim) batch;

	priv = mac_capability_instance_get_priv(s);
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
		SDT_PROBE6(mac_capability_isolation, , , state, (uintptr_t)"claim-remove",
		    c->fi_nonce, 0, c->fi_id, FI_OP_RELEASE, 0);
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
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "net-claim-remove", nc->fn_nonce, 0, nc->fn_id,
			    FI_OP_RELEASE_NET, 0);
			free(nc, M_FILE_ISOLATION);
		}
		rw_wunlock(&fi_net_lock);
	}

	/* Release all jail claims */
	{
		struct fi_jail_claim *jc;

		rw_wlock(&fi_jail_lock);
		while ((jc = LIST_FIRST(&priv->fip_jail_claims)) != NULL) {
			LIST_REMOVE(jc, fj_link);
			LIST_REMOVE(jc, fj_instlink);
			atomic_subtract_int(&fi_jail_claim_count, 1);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "jail-claim-remove", jc->fj_nonce, 0, jc->fj_id,
			    FI_OP_RELEASE_JAIL, 0);
			free(jc, M_FILE_ISOLATION);
		}
		rw_wunlock(&fi_jail_lock);
	}

	/* Release all vsock claims */
	{
		struct fi_vsock_claim *vc;

		rw_wlock(&fi_vsock_lock);
		while ((vc = LIST_FIRST(&priv->fip_vsock_claims)) != NULL) {
			LIST_REMOVE(vc, fv_hashlink);
			LIST_REMOVE(vc, fv_instlink);
			atomic_subtract_int(&fi_vsock_claim_count, 1);
			SDT_PROBE6(mac_capability_isolation, , , state,
			    "vsock-claim-remove", vc->fv_nonce, 0, vc->fv_id,
			    FI_OP_RELEASE_VSOCK, 0);
			free(vc, M_FILE_ISOLATION);
		}
		rw_wunlock(&fi_vsock_lock);
	}

	/* Remove any auth entries created by this instance (token). */
	fi_auth_remove_by_inst(s);

	free(priv, M_FILE_ISOLATION);
}

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static const struct mac_capability_ops fi_ops = {
	.co_connect	= fi_connect,
	.co_init	= fi_init,
	.co_call	= fi_call,
	.co_revoke	= fi_revoke,
};

/*
 * File creation: if the parent directory is claimed by a nonce,
 * only that nonce can create files in it.  Same logic as lookup.
 */
static int
fi_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel __unused, struct componentname *cnp __unused,
    struct vattr *vap __unused)
{

	return (fi_check_vp_common(cred, dvp, &fi_dir_claim_count, "create",
	    FI_FS_CREATE));
}

static int
fi_check_jail_common(struct ucred *cred, int32_t jid, const char *name,
    uint32_t actions, const char *what)
{
	struct fi_jail_claim *jc;
	struct fi_jail_request req;
	uint64_t caller_nonce, denied_id, denied_nonce;
	char denied_name[sizeof(((struct fi_jail_request *)0)->name)];
	bool denied;

	if (atomic_load_acq_int(&fi_jail_claim_count) == 0)
		return (0);

	memset(&req, 0, sizeof(req));
	req.jid = jid;
	req.actions = actions;
	if (name != NULL)
		strlcpy(req.name, name, sizeof(req.name));

	caller_nonce = mac_capability_proc_nonce(cred);
	denied = false;
	denied_id = 0;
	denied_nonce = 0;
	denied_name[0] = '\0';
	rw_rlock(&fi_jail_lock);
	if (caller_nonce != 0)
		rw_rlock(&fi_auth_lock);
	LIST_FOREACH(jc, &fi_jail_claims, fj_link) {
		if ((jc->fj_actions & actions) != actions)
			continue;
		if (!fi_jail_claim_matches(jc, &req))
			continue;
		if (caller_nonce != 0 && caller_nonce == jc->fj_nonce) {
			SDT_PROBE6(mac_capability_isolation, , , allow__jail,
			    jc->fj_nonce, caller_nonce, jc->fj_id,
			    jid, what, actions);
			rw_runlock(&fi_auth_lock);
			rw_runlock(&fi_jail_lock);
			return (0);
		}
		if (caller_nonce != 0 && fi_is_authorized_jail(caller_nonce,
		    jc->fj_nonce, jc->fj_id, &req)) {
			SDT_PROBE6(mac_capability_isolation, , , allow__jail,
			    jc->fj_nonce, caller_nonce, jc->fj_id, jid, what,
			    actions);
			rw_runlock(&fi_auth_lock);
			rw_runlock(&fi_jail_lock);
			return (0);
		}
		if (!denied) {
			denied = true;
			denied_nonce = jc->fj_nonce;
			denied_id = jc->fj_id;
			strlcpy(denied_name, jc->fj_name, sizeof(denied_name));
		}
	}
	if (caller_nonce != 0)
		rw_runlock(&fi_auth_lock);
	rw_runlock(&fi_jail_lock);
	if (denied) {
		(void)denied_nonce;
		(void)denied_id;
		SDT_PROBE3(mac_capability_isolation, , , deny, what,
		    denied_nonce, caller_nonce);
		SDT_PROBE6(mac_capability_isolation, , , deny__jail,
		    denied_nonce, caller_nonce, denied_id, jid, denied_name,
		    actions);
		return (fi_deny(EACCES));
	}
	return (0);
}

static int
fi_check_prison_create(struct ucred *cred, struct vfsoptlist *opts,
    int flags __unused)
{
	char *name;
	char namebuf[sizeof(((struct fi_jail_request *)0)->name)];
	int error, jid, len;

	jid = 0;
	error = vfs_copyopt(opts, "jid", &jid, sizeof(jid));
	if (error != 0 && error != ENOENT)
		return (0);
	name = NULL;
	error = vfs_getopt(opts, "name", (void **)&name, &len);
	if (error != 0 && error != ENOENT)
		name = NULL;
	/*
	 * Bound the name to our buffer size.  vfs_getopt returns a
	 * pointer into the option list; ensure we have a NUL-terminated
	 * copy before passing to the matcher.
	 */
	if (name != NULL) {
		if (len <= 0 || (size_t)len >= sizeof(namebuf))
			name = NULL;
		else {
			memcpy(namebuf, name, (size_t)len);
			namebuf[len] = '\0';
			name = namebuf;
		}
	}
	if (jid == 0 && name == NULL)
		return (0);
	return (fi_check_jail_common(cred, jid, name, FI_JAIL_CREATE,
	    "jail_create"));
}

static int
fi_check_prison_get(struct ucred *cred, struct prison *pr,
    struct label *label __unused, struct vfsoptlist *opts __unused,
    int flags __unused)
{

	return (fi_check_jail_common(cred, pr->pr_id, pr->pr_name,
	    FI_JAIL_GET, "jail_get"));
}

static int
fi_check_prison_set(struct ucred *cred, struct prison *pr,
    struct label *label __unused, struct vfsoptlist *opts __unused,
    int flags __unused)
{

	return (fi_check_jail_common(cred, pr->pr_id, pr->pr_name,
	    FI_JAIL_SET, "jail_set"));
}

static int
fi_check_prison_remove(struct ucred *cred, struct prison *pr,
    struct label *label __unused)
{

	return (fi_check_jail_common(cred, pr->pr_id, pr->pr_name,
	    FI_JAIL_REMOVE, "jail_remove"));
}

static int
fi_check_prison_attach(struct ucred *cred, struct prison *pr,
    struct label *label __unused)
{

	return (fi_check_jail_common(cred, pr->pr_id, pr->pr_name,
	    FI_JAIL_ATTACH, "jail_attach"));
}

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
	.mpo_vnode_check_create		= fi_check_create,
	/* Unix domain sockets */
	.mpo_vnode_check_uipc_connect	= fi_check_uipc_connect,
	/* Network isolation */
	.mpo_socket_check_create	= fi_check_socket_create,
	.mpo_socket_check_bind		= fi_check_socket_bind,
	.mpo_socket_check_connect	= fi_check_socket_connect,
	/* Whole-CID host provider ownership */
	.mpo_vsock_provider_init_label = fi_vsock_provider_init_label,
	.mpo_vsock_provider_destroy_label = fi_vsock_provider_destroy_label,
	.mpo_vsock_provider_check_attach = fi_vsock_provider_check_attach,
	.mpo_vsock_provider_check_access = fi_vsock_provider_check_access,
	/* Jail isolation */
	.mpo_prison_check_create	= fi_check_prison_create,
	.mpo_prison_check_get		= fi_check_prison_get,
	.mpo_prison_check_set		= fi_check_prison_set,
	.mpo_prison_check_remove	= fi_check_prison_remove,
	.mpo_prison_check_attach	= fi_check_prison_attach,
};

/*
 * Isolation is enforced at open(2) time only.  File descriptors obtained
 * before a claim is established, or received via SCM_RIGHTS, remain
 * usable.  This is intentional: once a process holds a valid fd, the
 * capability model (Capsicum) governs further access, not isolation.
 */
MAC_POLICY_SET(&fi_mac_ops, mac_mac_capability_isolation,
    "MAC_CAPABILITY isolation enforcement",
    MPC_LOADTIME_FLAG_NOTLATE, &fi_slot);

static int
mac_capability_isolation_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	struct mac_capability_service_params p;
	int error;

	switch (type) {
	case MOD_LOAD:
		fi_hash = hashinit(FI_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_hashmask);
		rw_init(&fi_lock, "mac_capability_isolation");

		fi_net_hash = hashinit(FI_NET_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_net_hashmask);
		rw_init(&fi_net_lock, "mac_capability_fi_net");
		LIST_INIT(&fi_jail_claims);
		rw_init(&fi_jail_lock, "mac_capability_fi_jail");

		fi_vsock_hash = hashinit(FI_VSOCK_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_vsock_hashmask);
		rw_init(&fi_vsock_lock, "mac_capability_fi_vsock");

		fi_auth_hash = hashinit(FI_AUTH_HASH_SIZE, M_FILE_ISOLATION,
		    &fi_auth_hashmask);
		rw_init(&fi_auth_lock, "mac_capability_fi_auth");

		memset(&p, 0, sizeof(p));
		p.name = "isolation";
		p.ops = &fi_ops;

		error = mac_capability_service_create(&p, &fi_svc);
		if (error != 0) {
			rw_destroy(&fi_auth_lock);
			hashdestroy(fi_auth_hash, M_FILE_ISOLATION,
			    fi_auth_hashmask);
			rw_destroy(&fi_vsock_lock);
			hashdestroy(fi_vsock_hash, M_FILE_ISOLATION,
			    fi_vsock_hashmask);
			rw_destroy(&fi_jail_lock);
			rw_destroy(&fi_net_lock);
			hashdestroy(fi_net_hash, M_FILE_ISOLATION,
			    fi_net_hashmask);
			rw_destroy(&fi_lock);
			hashdestroy(fi_hash, M_FILE_ISOLATION,
			    fi_hashmask);
			return (error);
		}
		if (bootverbose)
			printf("mac_capability_isolation: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);		/* NOTLATE policy cannot unload */

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_isolation_mod = {
	"mac_capability_isolation",
	mac_capability_isolation_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_isolation, mac_capability_isolation_mod,
    SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_DEPEND(mac_capability_isolation, mac_capability, 1, 1, 1);
MODULE_VERSION(mac_capability_isolation, 1);
