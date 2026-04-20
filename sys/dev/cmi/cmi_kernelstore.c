/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_kernelstore — shared capability-gated key-value store.
 *
 * Sync-only CMI service.  Connecting creates a new empty store.
 * The fd IS the credential — hold it, read/write.  Mint member
 * fds to share the store with other processes.  Last close
 * destroys the store and all its data.
 *
 * Two roles:
 *   Owner:  PUT, GET, DELETE, MINT
 *   Member: PUT, GET, DELETE
 *
 * Revoke: the owner receives the member fd from MINT.  Call
 * CMI_TERMINATE on that fd to revoke the member's access.
 *
 * Protocol (sync, via CALL):
 *   KSTORE_OP_PUT:     store value under key
 *   KSTORE_OP_GET:     retrieve value by key
 *   KSTORE_OP_DELETE:  remove a key
 *   KSTORE_OP_MINT:    create member fd (owner only)
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
#include <sys/queue.h>
#include <sys/ucred.h>

#include "cmi.h"
#include "cmi_kernelstore_proto.h"

MALLOC_DEFINE(M_CMI_KSTORE, "cmi_kstore", "cmi kernelstore");

#define	KS_ROLE_OWNER	1
#define	KS_ROLE_MEMBER	2

/*
 * Store — shared data structure.  Multiple instances point at the
 * same store.  Protected by ks_mtx.  Freed when ks_refcnt drops
 * to zero (last instance closes).
 */
struct ks_entry {
	LIST_ENTRY(ks_entry) ke_link;
	char		ke_key[KSTORE_KEY_MAX];
	void		*ke_data;
	size_t		ke_datalen;
};

struct ks_store {
	struct mtx	ks_mtx;
	LIST_HEAD(, ks_entry) ks_entries;
	int		ks_nentries;
	volatile u_int	ks_refcnt;
};

/*
 * Per-instance state.
 */
struct ks_priv {
	int		kp_role;
	struct ks_store	*kp_store;
};

static struct cmi_service *kstore_svc;
static volatile uint64_t kstore_next_badge = 1;

static struct ks_store *
ks_store_alloc(void)
{
	struct ks_store *store;

	store = malloc(sizeof(*store), M_CMI_KSTORE, M_WAITOK | M_ZERO);
	mtx_init(&store->ks_mtx, "cmi_kstore", NULL, MTX_DEF);
	LIST_INIT(&store->ks_entries);
	refcount_init(&store->ks_refcnt, 1);
	return (store);
}

static void
ks_store_hold(struct ks_store *store)
{

	refcount_acquire(&store->ks_refcnt);
}

static void
ks_store_rele(struct ks_store *store)
{
	struct ks_entry *ke;

	if (!refcount_release(&store->ks_refcnt))
		return;

	/* Last reference — free all entries. */
	while ((ke = LIST_FIRST(&store->ks_entries)) != NULL) {
		LIST_REMOVE(ke, ke_link);
		free(ke->ke_data, M_CMI_KSTORE);
		free(ke, M_CMI_KSTORE);
	}
	mtx_destroy(&store->ks_mtx);
	free(store, M_CMI_KSTORE);
}

static struct ks_entry *
ks_find(struct ks_store *store, const char *key)
{
	struct ks_entry *ke;

	mtx_assert(&store->ks_mtx, MA_OWNED);
	LIST_FOREACH(ke, &store->ks_entries, ke_link) {
		if (strncmp(ke->ke_key, key, KSTORE_KEY_MAX) == 0)
			return (ke);
	}
	return (NULL);
}

static int
kstore_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	*badge_out = atomic_fetchadd_64(&kstore_next_badge, 1);
	return (0);
}

static int
kstore_init(struct cmi_instance *s, void *arg __unused)
{
	struct ks_priv *kp;

	kp = malloc(sizeof(*kp), M_CMI_KSTORE, M_WAITOK | M_ZERO);
	kp->kp_role = KS_ROLE_OWNER;
	kp->kp_store = ks_store_alloc();
	cmi_instance_set_priv(s, kp);
	return (0);
}

static int
kstore_call(struct cmi_instance *s,
    const void *req, size_t reqlen,
    struct file **fds __unused, struct filecaps *fcaps __unused,
    int nfds __unused,
    void *reply, size_t *replylenp,
    struct file **reply_fds, int *reply_nfdsp,
    void *arg __unused)
{
	const struct kstore_request *kr;
	struct ks_priv *kp;
	struct ks_store *store;
	char key[KSTORE_KEY_MAX];

	if (reqlen < sizeof(struct kstore_request))
		return (EINVAL);

	kr = (const struct kstore_request *)req;
	kp = cmi_instance_get_priv(s);
	if (kp == NULL)
		return (EINVAL);
	store = kp->kp_store;

	/* NUL-terminate the key — userspace may fill it completely. */
	strlcpy(key, kr->key, sizeof(key));

	switch (kr->op) {
	case KSTORE_OP_PUT: {
		struct ks_entry *ke;
		struct kstore_status_reply *sr;
		const void *val;
		void *newdata, *olddata;
		size_t vallen;

		if (*replylenp < sizeof(struct kstore_status_reply)) {
			*replylenp = sizeof(struct kstore_status_reply);
			return (EMSGSIZE);
		}

		vallen = reqlen - sizeof(struct kstore_request);
		if (vallen > KSTORE_MAX_VALUE) {
			sr = (struct kstore_status_reply *)reply;
			sr->status = KSTORE_STATUS_TOOBIG;
			*replylenp = sizeof(*sr);
			return (0);
		}

		val = (const uint8_t *)req + sizeof(struct kstore_request);

		/* Pre-allocate outside the lock. */
		newdata = NULL;
		if (vallen > 0) {
			newdata = malloc(vallen, M_CMI_KSTORE, M_WAITOK);
			memcpy(newdata, val, vallen);
		}

		mtx_lock(&store->ks_mtx);
		ke = ks_find(store, key);
		if (ke != NULL) {
			/* Update existing. */
			olddata = ke->ke_data;
			ke->ke_data = newdata;
			ke->ke_datalen = vallen;
			mtx_unlock(&store->ks_mtx);
			free(olddata, M_CMI_KSTORE);
		} else {
			if (store->ks_nentries >= KSTORE_MAX_KEYS) {
				mtx_unlock(&store->ks_mtx);
				free(newdata, M_CMI_KSTORE);
				sr = (struct kstore_status_reply *)reply;
				sr->status = KSTORE_STATUS_FULL;
				*replylenp = sizeof(*sr);
				return (0);
			}
			ke = malloc(sizeof(*ke), M_CMI_KSTORE,
			    M_NOWAIT | M_ZERO);
			if (ke == NULL) {
				mtx_unlock(&store->ks_mtx);
				free(newdata, M_CMI_KSTORE);
				return (ENOMEM);
			}
			strlcpy(ke->ke_key, key, sizeof(ke->ke_key));
			ke->ke_data = newdata;
			ke->ke_datalen = vallen;
			LIST_INSERT_HEAD(&store->ks_entries, ke, ke_link);
			store->ks_nentries++;
			mtx_unlock(&store->ks_mtx);
		}

		sr = (struct kstore_status_reply *)reply;
		sr->status = KSTORE_STATUS_OK;
		*replylenp = sizeof(*sr);
		return (0);
	}

	case KSTORE_OP_GET: {
		struct ks_entry *ke;
		struct kstore_status_reply *sr;
		void *valbuf;
		size_t vallen, reply_len;

		if (*replylenp < sizeof(struct kstore_status_reply)) {
			*replylenp = sizeof(struct kstore_status_reply);
			return (EMSGSIZE);
		}

		mtx_lock(&store->ks_mtx);
		ke = ks_find(store, key);
		if (ke == NULL) {
			mtx_unlock(&store->ks_mtx);
			sr = (struct kstore_status_reply *)reply;
			sr->status = KSTORE_STATUS_NOTFOUND;
			*replylenp = sizeof(*sr);
			return (0);
		}
		vallen = ke->ke_datalen;
		mtx_unlock(&store->ks_mtx);

		/* Allocate, then re-lock to copy. */
		valbuf = NULL;
		if (vallen > 0) {
			valbuf = malloc(vallen, M_CMI_KSTORE, M_WAITOK);
			mtx_lock(&store->ks_mtx);
			ke = ks_find(store, key);
			if (ke == NULL || ke->ke_datalen != vallen) {
				mtx_unlock(&store->ks_mtx);
				free(valbuf, M_CMI_KSTORE);
				sr = (struct kstore_status_reply *)reply;
				sr->status = KSTORE_STATUS_NOTFOUND;
				*replylenp = sizeof(*sr);
				return (0);
			}
			memcpy(valbuf, ke->ke_data, vallen);
			mtx_unlock(&store->ks_mtx);
		}

		reply_len = sizeof(struct kstore_status_reply) + vallen;
		if (*replylenp < reply_len) {
			free(valbuf, M_CMI_KSTORE);
			*replylenp = reply_len;
			return (EMSGSIZE);
		}

		sr = (struct kstore_status_reply *)reply;
		sr->status = KSTORE_STATUS_OK;
		if (vallen > 0) {
			memcpy((uint8_t *)reply +
			    sizeof(struct kstore_status_reply),
			    valbuf, vallen);
			free(valbuf, M_CMI_KSTORE);
		}
		*replylenp = reply_len;
		return (0);
	}

	case KSTORE_OP_DELETE: {
		struct ks_entry *ke;
		struct kstore_status_reply *sr;

		if (*replylenp < sizeof(struct kstore_status_reply)) {
			*replylenp = sizeof(struct kstore_status_reply);
			return (EMSGSIZE);
		}

		mtx_lock(&store->ks_mtx);
		ke = ks_find(store, key);
		if (ke == NULL) {
			mtx_unlock(&store->ks_mtx);
			sr = (struct kstore_status_reply *)reply;
			sr->status = KSTORE_STATUS_NOTFOUND;
			*replylenp = sizeof(*sr);
			return (0);
		}
		LIST_REMOVE(ke, ke_link);
		store->ks_nentries--;
		mtx_unlock(&store->ks_mtx);

		free(ke->ke_data, M_CMI_KSTORE);
		free(ke, M_CMI_KSTORE);

		sr = (struct kstore_status_reply *)reply;
		sr->status = KSTORE_STATUS_OK;
		*replylenp = sizeof(*sr);
		return (0);
	}

	case KSTORE_OP_MINT: {
		struct file *member_fp;
		struct ks_priv *mkp;
		int error;

		if (kp->kp_role != KS_ROLE_OWNER)
			return (EPERM);
		if (*reply_nfdsp < 1)
			return (EINVAL);

		error = cmi_mint_fp(kstore_svc, 0, &member_fp);
		if (error != 0)
			return (error);

		mkp = cmi_instance_get_priv(member_fp->f_data);
		if (mkp != NULL) {
			/* Replace the fresh store with a ref to ours. */
			ks_store_rele(mkp->kp_store);
			ks_store_hold(store);
			mkp->kp_store = store;
			mkp->kp_role = KS_ROLE_MEMBER;
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
kstore_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct ks_priv *kp;

	kp = cmi_instance_get_priv(s);
	if (kp == NULL)
		return;

	ks_store_rele(kp->kp_store);
	free(kp, M_CMI_KSTORE);
}

static const struct cmi_ops kstore_ops = {
	.co_connect = kstore_connect,
	.co_init = kstore_init,
	.co_call = kstore_call,
	.co_revoke = kstore_revoke,
};

static int
cmi_kernelstore_modevent(module_t mod __unused, int type,
    void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cmi_service_params p = {
				.name = "kernelstore",
				.ops = &kstore_ops,
			};
			error = cmi_service_create(&p, &kstore_svc);
		}
		if (error != 0)
			return (error);
		if (bootverbose)
			printf("cmi_kernelstore: loaded\n");
		return (0);

	case MOD_UNLOAD:
		if (kstore_svc != NULL)
			cmi_service_destroy(kstore_svc);
		if (bootverbose)
			printf("cmi_kernelstore: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_kernelstore_mod = {
	"cmi_kernelstore",
	cmi_kernelstore_modevent,
	NULL,
};

DECLARE_MODULE(cmi_kernelstore, cmi_kernelstore_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
MODULE_VERSION(cmi_kernelstore, 1);
MODULE_DEPEND(cmi_kernelstore, cmi, 1, 1, 1);
