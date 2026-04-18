/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi_pair — bidirectional capability pair.
 *
 * Demonstrates:
 *   - cmi_mint_fp() to create a capability from handler context
 *   - cmi_notify() for peer-to-peer message forwarding
 *   - cmi_instance_revoke() when the peer closes
 *   - per-instance private data via cmi_instance_set_priv()
 *   - co_revoke for cleanup
 *   - reply with an attached fd (returning a new capability)
 *
 * Protocol:
 *   1. Connect to "pair" via CMI_CONNECT -> get capability A.
 *   2. Send PAIR_OP_CREATE via CMI_SENDMSG on A.
 *   3. Receive the reply via CMI_RECVMSG -- it carries capability B.
 *   4. Now A and B are connected: SENDMSG on A -> RECVMSG on B.
 *   5. Close either end -> the other gets ECONNRESET.
 *
 * After pairing, messages are forwarded to the peer via cmi_notify().
 * The sender gets no reply (fire-and-forget forwarding).
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

#include "cmi.h"

MALLOC_DEFINE(M_CMI_PAIR, "cmi_pair", "cmi capability pair");

#define	PAIR_OP_CREATE	1

struct cmi_cap_pair {
	struct mtx		pp_mtx;
	struct cmi_instance	*pp_a;
	struct cmi_instance	*pp_b;
	int			pp_dead;
};

static struct cmi_service *pair_svc;
static volatile uint64_t pair_next_badge = 1;

static int
pair_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	*badge_out = atomic_fetchadd_64(&pair_next_badge, 1);
	return (0);
}

static int
pair_handler(struct cmi_instance *s, const struct cmi_msg *msg,
    void *arg __unused)
{
	struct cmi_cap_pair *pp;
	struct cmi_instance *peer;
	struct file *peer_fp;
	uint64_t peer_badge;
	uint32_t op;
	int error;

	pp = cmi_instance_get_priv(s);

	if (pp == NULL) {
		/*
		 * Not yet paired.  Expect PAIR_OP_CREATE.
		 * Mint a peer capability and return it as an attached fd.
		 */
		if (cmi_msg_datalen(msg) < sizeof(uint32_t))
			return (EINVAL);
		memcpy(&op, cmi_msg_data(msg), sizeof(op));
		if (op != PAIR_OP_CREATE)
			return (EINVAL);

		peer_badge = atomic_fetchadd_64(&pair_next_badge, 1);
		error = cmi_mint_fp(pair_svc, peer_badge, &peer_fp);
		if (error != 0)
			return (error);
		peer = peer_fp->f_data;

		pp = malloc(sizeof(*pp), M_CMI_PAIR, M_WAITOK | M_ZERO);
		mtx_init(&pp->pp_mtx, "cmi_pair", NULL, MTX_DEF);
		pp->pp_a = s;
		pp->pp_b = peer;

		cmi_instance_set_priv(s, pp);
		cmi_instance_set_priv(peer, pp);

		error = cmi_reply(s, cmi_msg_token(msg), NULL, 0,
		    &peer_fp, NULL, 1);
		fdrop(peer_fp, curthread);
		return (error);
	}

	/* Already paired — forward to peer. */
	mtx_lock(&pp->pp_mtx);
	if (pp->pp_dead) {
		mtx_unlock(&pp->pp_mtx);
		return (ECONNRESET);
	}
	peer = (s == pp->pp_a) ? pp->pp_b : pp->pp_a;
	if (peer == NULL) {
		mtx_unlock(&pp->pp_mtx);
		return (ECONNRESET);
	}
	cmi_instance_hold(peer);
	mtx_unlock(&pp->pp_mtx);

	error = cmi_notify(peer, cmi_msg_data(msg),
	    cmi_msg_datalen(msg), cmi_msg_fds(msg),
	    cmi_msg_fcaps(msg), cmi_msg_nfds(msg));
	cmi_instance_rele(peer);

	return (error);
}

static void
pair_revoke(struct cmi_instance *s, uint64_t badge __unused,
    enum cmi_revoke_reason reason __unused, void *arg __unused)
{
	struct cmi_cap_pair *pp;
	struct cmi_instance *peer;

	pp = cmi_instance_get_priv(s);
	if (pp == NULL)
		return;

	mtx_lock(&pp->pp_mtx);

	if (s == pp->pp_a) {
		pp->pp_a = NULL;
		peer = pp->pp_b;
	} else {
		pp->pp_b = NULL;
		peer = pp->pp_a;
	}

	if (peer == NULL) {
		mtx_unlock(&pp->pp_mtx);
		mtx_destroy(&pp->pp_mtx);
		free(pp, M_CMI_PAIR);
		return;
	}

	if (!pp->pp_dead) {
		pp->pp_dead = 1;
		cmi_instance_hold(peer);
		mtx_unlock(&pp->pp_mtx);
		cmi_instance_revoke(peer);
		cmi_instance_rele(peer);
	} else {
		mtx_unlock(&pp->pp_mtx);
	}
}

static void
pair_fdclose(struct cmi_instance *s __unused, int fd __unused,
    struct thread *td __unused, void *arg __unused)
{
	/* No-op.  Exercises the co_fdclose path in the framework. */
}

static const struct cmi_ops pair_ops = {
	.co_connect = pair_connect,
	.co_handler = pair_handler,
	.co_revoke = pair_revoke,
	.co_fdclose = pair_fdclose,
};

static int
cmi_pair_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cmi_service_params p = {
				.name = "pair",
				.ops = &pair_ops,
			};
			error = cmi_service_create(&p, &pair_svc);
		}
		if (error != 0) {
			printf("cmi_pair: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("cmi_pair: loaded\n");
		return (0);

	case MOD_UNLOAD:
		if (pair_svc != NULL)
			cmi_service_destroy(pair_svc);
		if (bootverbose)
			printf("cmi_pair: unloaded\n");
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cmi_pair_mod = {
	"cmi_pair",
	cmi_pair_modevent,
	NULL,
};

DECLARE_MODULE(cmi_pair, cmi_pair_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cmi_pair, 1);
MODULE_DEPEND(cmi_pair, cmi, 1, 1, 1);
