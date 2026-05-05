/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Project5BSD
 *
 * cap_rt_file_isolation — File Isolation capability service.
 *
 * Fully isolates vnodes so that only processes sharing the claimer's
 * CAP_RT nonce can interact with them.  Enforced via MACF hooks on:
 *
 *   open, exec, unlink, link, rename, chmod, chown, chflags,
 *   utimes, truncate, stat, access, readlink, connect (AF_UNIX)
 *
 * Claims are keyed by vnode pointer (held via vref()).  This supports
 * device nodes, regular files, FIFOs, and Unix domain sockets
 * (connect is gated; bind creates a new vnode so cannot be gated).
 *
 * Claims are bound to the cap_rt instance fd.  When the instance is
 * revoked or closed, all its claims are released automatically.
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

struct fi_priv {
	LIST_HEAD(, fi_claim)	fip_claims;	/* claims owned by instance */
};

static LIST_HEAD(, fi_claim)	*fi_hash;
static u_long			 fi_hashmask;
static struct rwlock		 fi_lock;
static volatile u_int		 fi_claim_count;	/* fast-path check */
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

/* --- Unix domain sockets --- */

static int
fi_check_uipc_connect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel __unused)
{

	return (fi_check_vp(cred, vp));
}

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

	if (reqlen < sizeof(struct fi_request))
		return (EINVAL);
	if (*replylenp < sizeof(struct fi_reply))
		return (EMSGSIZE);

	fr = req;
	priv = cap_rt_instance_get_priv(s);
	if (priv == NULL)
		return (EINVAL);

	if (nfds < 1)
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
		return (fi_do_claim(s, priv, fds[0], caller_nonce));
	case FI_OP_RELEASE:
		return (fi_do_release(fds[0], caller_nonce));
	case FI_OP_QUERY:
		return (fi_do_query(fds[0], caller_nonce, rpl));
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
		LIST_INSERT_HEAD(&batch, c, fi_instlink);
	}
	rw_wunlock(&fi_lock);

	while ((c = LIST_FIRST(&batch)) != NULL) {
		LIST_REMOVE(c, fi_instlink);
		vrele(c->fi_vp);
		free(c, M_FILE_ISOLATION);
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
	/* Unix domain sockets */
	.mpo_vnode_check_uipc_connect	= fi_check_uipc_connect,
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
