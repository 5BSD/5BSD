/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_pair — bidirectional capability pair.
 *
 * Creates a connected pair of capability descriptors for
 * peer-to-peer messaging.  Messages forwarded between endpoints
 * preserve the original sender's credentials (badge, nonce, uid).
 * Closing either end revokes the other (ECONNRESET).
 *
 * Protocol:
 *   1. Connect to "pair" via CAP_RT_CONNECT -> get capability A.
 *   2. Send PAIR_OP_CREATE via CAP_RT_SENDMSG on A.
 *   3. Receive the reply via CAP_RT_RECVMSG -- it carries capability B.
 *   4. Now A and B are connected: SENDMSG on A -> RECVMSG on B.
 *   5. Close either end -> the other gets ECONNRESET.
 *
 * After pairing, messages are forwarded to the peer via cap_rt_forward().
 * The original sender metadata (badge, token, credential trailer) is
 * preserved.  The sender gets no reply (fire-and-forget forwarding).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/ucred.h>

#include "cap_rt.h"

MALLOC_DEFINE(M_CAP_RT_PAIR, "cap_rt_pair", "cap_rt capability pair");

SDT_PROVIDER_DEFINE(cap_rt_pair);
SDT_PROBE_DEFINE4(cap_rt_pair, , , handler__done,
    "uint32_t", "uint64_t", "int", "sbintime_t");

#define	PAIR_OP_CREATE	1

struct cap_rt_cap_pair {
	struct mtx		pp_mtx;
	struct cap_rt_instance	*pp_a;
	struct cap_rt_instance	*pp_b;
	int			pp_dead;
	volatile u_int		pp_refcnt;	/* 1 per endpoint */
};

static void
pair_free(struct cap_rt_cap_pair *pp)
{

	mtx_destroy(&pp->pp_mtx);
	free(pp, M_CAP_RT_PAIR);
}

static struct cap_rt_service *pair_svc;
static volatile uint64_t pair_next_badge = 1;

static int
pair_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	return (CAP_RT_CONNECT_BADGE(pair_next_badge, badge_out));
}

static int
pair_handler(struct cap_rt_instance *s, const struct cap_rt_msg *msg,
    void *arg __unused)
{
	struct cap_rt_cap_pair *pp;
	struct cap_rt_instance *peer;
	struct file *peer_fp;
	sbintime_t start __unused;
	uint64_t peer_badge;
	uint32_t op;
	int error;

	start = getsbinuptime();
	op = 0;
	pp = cap_rt_instance_get_priv(s);

	if (pp == NULL) {
		/*
		 * Not yet paired.  Expect PAIR_OP_CREATE.
		 * Mint a peer capability and return it as an attached fd.
		 */
		if (cap_rt_msg_datalen(msg) < sizeof(uint32_t))
		{
			error = EINVAL;
			goto out;
		}
		memcpy(&op, cap_rt_msg_data(msg), sizeof(op));
		if (op != PAIR_OP_CREATE) {
			error = EINVAL;
			goto out;
		}

		peer_badge = atomic_fetchadd_64(&pair_next_badge, 1);
		error = cap_rt_mint_fp(pair_svc, peer_badge, &peer_fp);
		if (error != 0)
			goto out;
		peer = peer_fp->f_data;

		pp = malloc(sizeof(*pp), M_CAP_RT_PAIR, M_WAITOK | M_ZERO);
		mtx_init(&pp->pp_mtx, "cap_rt_pair", NULL, MTX_DEF);
		pp->pp_a = s;
		pp->pp_b = peer;
		pp->pp_refcnt = 2;	/* one per endpoint */

		cap_rt_instance_set_priv(s, pp);
		cap_rt_instance_set_priv(peer, pp);

		error = cap_rt_reply(s, cap_rt_msg_token(msg), NULL, 0,
		    &peer_fp, NULL, 1);
		fdrop(peer_fp, curthread);
		goto out;
	}

	/* Already paired — forward to peer. */
	mtx_lock(&pp->pp_mtx);
	if (pp->pp_dead) {
		mtx_unlock(&pp->pp_mtx);
		error = ECONNRESET;
		goto out;
	}
	peer = (s == pp->pp_a) ? pp->pp_b : pp->pp_a;
	if (peer == NULL) {
		mtx_unlock(&pp->pp_mtx);
		error = ECONNRESET;
		goto out;
	}
	cap_rt_instance_hold(peer);
	mtx_unlock(&pp->pp_mtx);

	error = cap_rt_forward(peer, msg);
	cap_rt_instance_rele(peer);
out:
	SDT_PROBE4(cap_rt_pair, , , handler__done, op,
	    cap_rt_instance_get_badge(s), error, getsbinuptime() - start);
	return (error);
}

static void
pair_revoke(struct cap_rt_instance *s, uint64_t badge __unused,
    enum cap_rt_revoke_reason reason __unused, void *arg __unused)
{
	struct cap_rt_cap_pair *pp;
	struct cap_rt_instance *peer;
	bool do_revoke = false;
	bool last;

	pp = cap_rt_instance_get_priv(s);
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

	if (peer != NULL && !pp->pp_dead) {
		pp->pp_dead = 1;
		cap_rt_instance_hold(peer);
		do_revoke = true;
	}

	mtx_unlock(&pp->pp_mtx);

	if (do_revoke) {
		cap_rt_instance_revoke(peer);
		cap_rt_instance_rele(peer);
	}

	/* Last endpoint to detach frees the pair struct. */
	last = refcount_release(&pp->pp_refcnt);
	if (last)
		pair_free(pp);
}

static const struct cap_rt_ops pair_ops = {
	.co_connect = pair_connect,
	.co_handler = pair_handler,
	.co_revoke = pair_revoke,
};

static int
cap_rt_pair_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct cap_rt_service_params p = {
				.name = "pair",
				.ops = &pair_ops,
			};
			error = cap_rt_service_create(&p, &pair_svc);
		}
		if (error != 0) {
			printf("cap_rt_pair: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("cap_rt_pair: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t cap_rt_pair_mod = {
	"cap_rt_pair",
	cap_rt_pair_modevent,
	NULL,
};

DECLARE_MODULE(cap_rt_pair, cap_rt_pair_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(cap_rt_pair, 1);
MODULE_DEPEND(cap_rt_pair, cap_rt, 1, 1, 1);
