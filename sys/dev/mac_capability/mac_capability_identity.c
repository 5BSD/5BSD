/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_identity — capability service for querying program nonces.
 *
 * Provides two operations via MAC_CAPABILITY_CALL:
 *   IDENTITY_OP_SELF   — returns the caller's own nonce
 *   IDENTITY_OP_QUERY  — returns the nonce of a process whose procdesc
 *                        fd is attached to the call
 *
 * This is a sync-only (co_call) service.  The identity fd can be freely
 * passed to sandboxed children so they can discover their own identity.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/sx.h>
#include <sys/ucred.h>

#include "mac_capability.h"
#include "mac_capability_label.h"
#include "mac_capability_identity_proto.h"

extern struct sx proctree_lock;

/* ----------------------------------------------------------------
 * co_call handler
 * ---------------------------------------------------------------- */

static int
identity_call(struct mac_capability_instance *s __unused,
    const void *req, size_t reqlen,
    struct file **fds, struct filecaps *fcaps __unused, int nfds,
    void *reply, size_t *replylenp,
    struct file **reply_fds __unused, int *reply_nfdsp __unused,
    void *arg __unused)
{
	const struct identity_request *ir;
	struct identity_reply *rp;

	if (reqlen < sizeof(*ir) || *replylenp < sizeof(*rp))
		return (EINVAL);

	ir = (const struct identity_request *)req;
	rp = (struct identity_reply *)reply;
	*replylenp = sizeof(*rp);

	memset(rp, 0, sizeof(*rp));

	switch (ir->op) {
	case IDENTITY_OP_SELF:
		rp->nonce = mac_capability_proc_nonce(curthread->td_ucred);
		if (rp->nonce == 0) {
			rp->status = IDENTITY_STATUS_ERR;
			return (0);
		}
		rp->status = IDENTITY_STATUS_OK;
		return (0);

	case IDENTITY_OP_QUERY: {
		struct procdesc *pd;
		struct proc *p;

		if (nfds < 1 || fds[0] == NULL)
			return (EINVAL);
		if (fds[0]->f_type != DTYPE_PROCDESC)
			return (EINVAL);

		pd = fds[0]->f_data;

		sx_slock(&proctree_lock);
		p = pd->pd_proc;
		if (p == NULL) {
			sx_sunlock(&proctree_lock);
			rp->status = IDENTITY_STATUS_DEAD;
			return (0);
		}
		PROC_LOCK(p);
		sx_sunlock(&proctree_lock);
		rp->nonce = mac_capability_proc_nonce(p->p_ucred);
		PROC_UNLOCK(p);

		rp->status = (rp->nonce != 0) ?
		    IDENTITY_STATUS_OK : IDENTITY_STATUS_ERR;
		return (0);
	}
	default:
		return (EINVAL);
	}
}

/* ----------------------------------------------------------------
 * Service registration
 * ---------------------------------------------------------------- */

static struct mac_capability_ops identity_ops = {
	.co_call = identity_call,
};

static struct mac_capability_service *identity_svc;

static int
mac_capability_identity_modevent(module_t mod __unused, int type, void *data __unused)
{
	struct mac_capability_service_params params;
	int error;

	switch (type) {
	case MOD_LOAD:
		memset(&params, 0, sizeof(params));
		params.name = "identity";
		params.ops = &identity_ops;
		error = mac_capability_service_create(&params, &identity_svc);
		if (error != 0)
			printf("mac_capability_identity: create failed: %d\n", error);
		return (error);
	case MOD_UNLOAD:
		if (identity_svc != NULL)
			mac_capability_service_destroy(identity_svc);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_identity_mod = {
	"mac_capability_identity",
	mac_capability_identity_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_identity, mac_capability_identity_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
MODULE_DEPEND(mac_capability_identity, mac_capability, 1, 1, 1);
MODULE_VERSION(mac_capability_identity, 1);
