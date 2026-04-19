/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_namespace — namespace management capability.
 *
 * Sync-only CMI service.  Each namespace instance represents
 * authority over a namespace (backed by FreeBSD jails).
 *
 * Two roles:
 *   Owner:  can create children, mint members, attach, remove, info
 *   Member: can attach, info only
 *
 * Protocol (sync, via CALL):
 *   NS_OP_INFO:     query caller's current namespace
 *   NS_OP_CREATE:   create child namespace (returns owner fd)
 *   NS_OP_ATTACH:   enter this namespace
 *   NS_OP_REMOVE:   destroy this namespace and all children
 *   NS_OP_MINT:     create member capability (returns member fd)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/jail.h>
#include <sys/jaildesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/ucred.h>
#include <sys/uio.h>

#include "cmi.h"

MALLOC_DEFINE(M_CMI_NS, "cmi_ns", "cmi namespace service");

#define	NS_OP_INFO	1	/* query current namespace */
#define	NS_OP_CREATE	2	/* create child, return owner fd */
#define	NS_OP_ATTACH	3	/* enter this namespace */
#define	NS_OP_REMOVE	4	/* destroy namespace + children */
#define	NS_OP_MINT	5	/* create member fd */

struct ns_request {
	uint32_t	op;
} __packed;

struct ns_create_request {
	uint32_t	op;		/* NS_OP_CREATE */
	char		hostname[256];	/* child hostname */
} __packed;

struct ns_info_reply {
	uint32_t	status;
	int		jid;
	char		name[256];	/* MAXHOSTNAMELEN */
};

#define	NS_ROLE_OWNER	1
#define	NS_ROLE_MEMBER	2

struct ns_priv {
	struct mtx	np_mtx;
	int		np_role;	/* NS_ROLE_* */
	int		np_jid;		/* jail ID this capability manages */
	int		np_privileged;	/* had PRIV_JAIL_ATTACH at connect */
};

static struct cmi_service *ns_svc;
static volatile uint64_t ns_next_badge = 1;

static int
ns_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{
	*badge_out = atomic_fetchadd_64(&ns_next_badge, 1);
	return (0);
}

static int
ns_init(struct cmi_instance *s, void *arg __unused)
{
	struct ns_priv *np;

	np = malloc(sizeof(*np), M_CMI_NS, M_WAITOK | M_ZERO);
	mtx_init(&np->np_mtx, "cmi_ns_priv", NULL, MTX_DEF);
	np->np_privileged =
	    (priv_check(curthread, PRIV_JAIL_ATTACH) == 0);
	cmi_instance_set_priv(s, np);
	return (0);
}

static int
ns_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused,
    void *reply, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct ns_request *nr;
	struct ns_priv *np;

	if (reqlen < sizeof(struct ns_request))
		return (EINVAL);

	nr = (const struct ns_request *)req;
	np = cmi_instance_get_priv(s);
	if (np == NULL)
		return (EINVAL);

	switch (nr->op) {
	case NS_OP_INFO: {
		struct ns_info_reply *info;
		struct prison *pr;

		if (*replylenp < sizeof(struct ns_info_reply))
			return (EINVAL);

		info = (struct ns_info_reply *)reply;
		memset(info, 0, sizeof(*info));
		pr = curthread->td_ucred->cr_prison;
		info->status = 0;
		info->jid = pr->pr_id;
		strlcpy(info->name, pr->pr_name, sizeof(info->name));
		*replylenp = sizeof(*info);
		return (0);
	}

	case NS_OP_CREATE: {
		const struct ns_create_request *cr;
		struct file *child_fp;
		struct ns_priv *child_np;
		struct iovec jiov[10];
		char path[] = "/";
		char name[512];
		int child_jid, error, persist, niov;
		int parent_jid;

		mtx_lock(&np->np_mtx);
		if (np->np_role != 0 && np->np_role != NS_ROLE_OWNER) {
			mtx_unlock(&np->np_mtx);
			return (EPERM);
		}
		if (!np->np_privileged) {
			mtx_unlock(&np->np_mtx);
			return (EPERM);
		}
		parent_jid = np->np_jid;
		mtx_unlock(&np->np_mtx);

		if (reqlen < sizeof(struct ns_create_request))
			return (EINVAL);
		if (*reply_nfdsp < 1)
			return (EINVAL);

		cr = (const struct ns_create_request *)req;

		/*
		 * Build the jail name.  If creating from an owner
		 * that has a jid, nest under that jail's name.
		 */
		if (parent_jid != 0) {
			struct prison *ppr;
			sx_slock(&allprison_lock);
			ppr = prison_find(parent_jid);
			if (ppr != NULL) {
				snprintf(name, sizeof(name), "%s.%s",
				    ppr->pr_name, cr->hostname);
				mtx_unlock(&ppr->pr_mtx);
			} else {
				strlcpy(name, cr->hostname, sizeof(name));
			}
			sx_sunlock(&allprison_lock);
		} else {
			strlcpy(name, cr->hostname, sizeof(name));
		}

		/* Create the namespace (jail). */
		persist = 1;
		niov = 0;
		jiov[niov].iov_base = __DECONST(void *, "path");
		jiov[niov++].iov_len = sizeof("path");
		jiov[niov].iov_base = path;
		jiov[niov++].iov_len = sizeof(path);
		jiov[niov].iov_base = __DECONST(void *, "name");
		jiov[niov++].iov_len = sizeof("name");
		jiov[niov].iov_base = name;
		jiov[niov++].iov_len = strlen(name) + 1;
		jiov[niov].iov_base = __DECONST(void *, "host.hostname");
		jiov[niov++].iov_len = sizeof("host.hostname");
		jiov[niov].iov_base = __DECONST(void *, cr->hostname);
		jiov[niov++].iov_len = strnlen(cr->hostname,
		    sizeof(cr->hostname)) + 1;
		jiov[niov].iov_base = __DECONST(void *, "persist");
		jiov[niov++].iov_len = sizeof("persist");
		jiov[niov].iov_base = &persist;
		jiov[niov++].iov_len = sizeof(persist);

		{
			struct uio uio;

			uio.uio_iov = jiov;
			uio.uio_iovcnt = niov;
			uio.uio_segflg = UIO_SYSSPACE;

			child_jid = kern_jail_set(curthread, &uio,
			    JAIL_CREATE);
			if (child_jid < 0)
				return (EINVAL);
		}

		/* Mint an owner capability for the child. */
		error = cmi_mint_fp(ns_svc, 0, &child_fp);
		if (error != 0) {
			struct prison *pr;
			sx_xlock(&allprison_lock);
			pr = prison_find(child_jid);
			if (pr != NULL)
				prison_remove(pr);
			else
				sx_xunlock(&allprison_lock);
			return (error);
		}

		child_np = cmi_instance_get_priv(child_fp->f_data);
		if (child_np != NULL) {
			mtx_lock(&child_np->np_mtx);
			child_np->np_role = NS_ROLE_OWNER;
			child_np->np_jid = child_jid;
			child_np->np_privileged = np->np_privileged;
			mtx_unlock(&child_np->np_mtx);
		}

		reply_fds[0] = child_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		return (0);
	}

	case NS_OP_ATTACH:
		/*
		 * Return the jid so the caller can call jail_attach(2)
		 * themselves.  The capability IS the authorization.
		 */
		mtx_lock(&np->np_mtx);
		if (np->np_jid == 0) {
			mtx_unlock(&np->np_mtx);
			return (EINVAL);
		}
		if (!np->np_privileged) {
			mtx_unlock(&np->np_mtx);
			return (EPERM);
		}
		if (*replylenp < sizeof(int)) {
			mtx_unlock(&np->np_mtx);
			return (EINVAL);
		}
		*(int *)reply = np->np_jid;
		*replylenp = sizeof(int);
		mtx_unlock(&np->np_mtx);
		return (0);

	case NS_OP_REMOVE: {
		struct prison *pr;

		mtx_lock(&np->np_mtx);
		if (np->np_role != NS_ROLE_OWNER) {
			mtx_unlock(&np->np_mtx);
			return (EPERM);
		}
		if (np->np_jid == 0) {
			mtx_unlock(&np->np_mtx);
			return (EINVAL);
		}
		int jid = np->np_jid;
		np->np_jid = 0;
		mtx_unlock(&np->np_mtx);

		sx_xlock(&allprison_lock);
		pr = prison_find(jid);
		if (pr != NULL) {
			/* prison_find returns with pr_mtx held.
			 * prison_remove needs both allprison_lock
			 * xlocked and pr_mtx locked. */
			prison_remove(pr);
			/* prison_remove drops both locks. */
		} else {
			sx_xunlock(&allprison_lock);
		}
		*replylenp = 0;
		return (0);
	}

	case NS_OP_MINT: {
		struct file *member_fp;
		struct ns_priv *member_np;
		int error;

		mtx_lock(&np->np_mtx);
		if (np->np_role != NS_ROLE_OWNER) {
			mtx_unlock(&np->np_mtx);
			return (EPERM);	/* only owners can mint */
		}
		if (np->np_jid == 0) {
			mtx_unlock(&np->np_mtx);
			return (EINVAL);
		}
		int jid = np->np_jid;
		mtx_unlock(&np->np_mtx);

		if (*reply_nfdsp < 1)
			return (EINVAL);

		error = cmi_mint_fp(ns_svc, 0, &member_fp);
		if (error != 0)
			return (error);

		member_np = cmi_instance_get_priv(member_fp->f_data);
		if (member_np != NULL) {
			mtx_lock(&member_np->np_mtx);
			member_np->np_role = NS_ROLE_MEMBER;
			member_np->np_jid = jid;
			member_np->np_privileged = np->np_privileged;
			mtx_unlock(&member_np->np_mtx);
		}

		reply_fds[0] = member_fp;
		*reply_nfdsp = 1;
		*replylenp = 0;
		return (0);
	}

	default:
		return (EOPNOTSUPP);
	}
}

static void
ns_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct ns_priv *np;

	np = cmi_instance_get_priv(s);
	if (np == NULL)
		return;

	/*
	 * If this is an owner and the namespace is still alive,
	 * destroy it.  This means close(owner_fd) kills the
	 * namespace — the capability IS the authority.
	 */
	mtx_lock(&np->np_mtx);
	if (np->np_role == NS_ROLE_OWNER && np->np_jid != 0) {
		struct prison *pr;
		int jid = np->np_jid;
		np->np_jid = 0;
		mtx_unlock(&np->np_mtx);
		sx_xlock(&allprison_lock);
		pr = prison_find(jid);
		if (pr != NULL)
			prison_remove(pr);
		else
			sx_xunlock(&allprison_lock);
	} else {
		mtx_unlock(&np->np_mtx);
	}

	mtx_destroy(&np->np_mtx);
	free(np, M_CMI_NS);
}

static const struct cmi_ops ns_ops = {
	.co_connect = ns_connect,
	.co_init = ns_init,
	.co_call = ns_call,
	.co_revoke = ns_revoke,
};

static int
cmi_namespace_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cmi_service_params p = {
				.name = "namespace",
				.ops = &ns_ops,
			};
			error = cmi_service_create(&p, &ns_svc);
		}
		if (error != 0) {
			printf("cmi_namespace: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("cmi_namespace: loaded\n");
		return (0);

	case MOD_UNLOAD:
		if (ns_svc != NULL)
			cmi_service_destroy(ns_svc);
		if (bootverbose)
			printf("cmi_namespace: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_namespace_mod = {
	"cmi_namespace",
	cmi_namespace_modevent,
	NULL,
};

DECLARE_MODULE(cmi_namespace, cmi_namespace_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_namespace, 1);
MODULE_DEPEND(cmi_namespace, cmi, 1, 1, 1);
