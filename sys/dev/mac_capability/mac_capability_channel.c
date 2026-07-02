/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability_channel — bidirectional capability channel.
 *
 * Creates a connected channel of capability descriptors for
 * peer-to-peer messaging.  Messages forwarded between endpoints
 * preserve the original sender's credentials (badge, nonce, uid).
 * Closing either end revokes the other (ECONNRESET).
 *
 * Protocol:
 *   1. Connect to "channel" via MAC_CAPABILITY_CONNECT -> get capability A.
 *   2. Send CHANNEL_OP_CREATE via MAC_CAPABILITY_SENDMSG on A.
 *   3. Receive the reply via MAC_CAPABILITY_RECVMSG -- it carries capability B.
 *   4. Now A and B are connected: SENDMSG on A -> RECVMSG on B.
 *   5. Close either end -> the other gets ECONNRESET.
 *
 * After connecting, messages are forwarded to the peer via mac_capability_forward().
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

#include "mac_capability.h"
#include "mac_capability_channel_proto.h"

MALLOC_DEFINE(M_MAC_CAPABILITY_CHANNEL, "mac_capability_channel", "mac_capability capability channel");

SDT_PROVIDER_DEFINE(mac_capability_channel);
SDT_PROBE_DEFINE3(mac_capability_channel, , , create,
    "uint64_t", "uint64_t", "int");
SDT_PROBE_DEFINE3(mac_capability_channel, , , forward,
    "uint64_t", "uint64_t", "size_t");
SDT_PROBE_DEFINE4(mac_capability_channel, , , handler__done,
    "uint32_t", "uint64_t", "int", "sbintime_t");
SDT_PROBE_DEFINE5(mac_capability_channel, , , state,
    "const char *", "uint32_t", "uint64_t", "int", "int");

struct mac_capability_cap_channel {
	struct mtx		cp_mtx;
	struct mac_capability_instance	*cp_a;
	struct mac_capability_instance	*cp_b;
	int			cp_dead;
	volatile u_int		cp_refcnt;	/* 1 per endpoint */
};

static void
channel_free(struct mac_capability_cap_channel *cp)
{

	mtx_destroy(&cp->cp_mtx);
	free(cp, M_MAC_CAPABILITY_CHANNEL);
}

static struct mac_capability_service *channel_svc;
static volatile uint64_t channel_next_badge = 1;

static int
channel_connect(struct ucred *cred __unused, void *arg __unused,
    uint64_t *badge_out)
{

	return (MAC_CAPABILITY_CONNECT_BADGE(channel_next_badge, badge_out));
}

static int
channel_handler(struct mac_capability_instance *s, const struct mac_capability_msg *msg,
    void *arg __unused)
{
	struct mac_capability_cap_channel *cp;
	struct mac_capability_instance *peer;
	struct file *peer_fp;
	sbintime_t start __unused;
	uint64_t peer_badge;
	uint32_t op;
	int error;

	start = getsbinuptime();
	op = 0;
	cp = mac_capability_instance_get_priv(s);

	if (cp == NULL) {
		/*
		 * Not yet connected.  Expect CHANNEL_OP_CREATE.
		 * Mint a peer capability and return it as an attached fd.
		 */
		if (mac_capability_msg_datalen(msg) < sizeof(uint32_t))
		{
			error = EINVAL;
			goto out;
		}
		memcpy(&op, mac_capability_msg_data(msg), sizeof(op));
		if (op != CHANNEL_OP_CREATE) {
			error = EINVAL;
			goto out;
		}

		peer_badge = atomic_fetchadd_64(&channel_next_badge, 1);
		error = mac_capability_mint_fp(channel_svc, peer_badge, &peer_fp);
		if (error != 0) {
			SDT_PROBE5(mac_capability_channel, , , state, (uintptr_t)"mint-error",
			    op, mac_capability_instance_get_badge(s), error, 0);
			goto out;
		}
		peer = peer_fp->f_data;

		cp = malloc(sizeof(*cp), M_MAC_CAPABILITY_CHANNEL, M_WAITOK | M_ZERO);
		mtx_init(&cp->cp_mtx, "mac_capability_channel", NULL, MTX_DEF);
		cp->cp_a = s;
		cp->cp_b = peer;
		cp->cp_refcnt = 2;	/* one per endpoint */

		mac_capability_instance_set_priv(s, cp);
		mac_capability_instance_set_priv(peer, cp);

		error = mac_capability_reply(s, mac_capability_msg_token(msg), NULL, 0,
		    &peer_fp, NULL, 1);
		fdrop(peer_fp, curthread);
		if (error == 0)
			SDT_PROBE3(mac_capability_channel, , , create,
			    mac_capability_instance_get_badge(s), peer_badge, 0);
		goto out;
	}

	/* Already connected — forward to peer. */
	mtx_lock(&cp->cp_mtx);
	if (cp->cp_dead) {
		mtx_unlock(&cp->cp_mtx);
		SDT_PROBE5(mac_capability_channel, , , state, (uintptr_t)"peer-dead",
		    0, mac_capability_instance_get_badge(s), ECONNRESET, 0);
		error = ECONNRESET;
		goto out;
	}
	peer = (s == cp->cp_a) ? cp->cp_b : cp->cp_a;
	if (peer == NULL) {
		mtx_unlock(&cp->cp_mtx);
		SDT_PROBE5(mac_capability_channel, , , state, (uintptr_t)"peer-dead",
		    0, mac_capability_instance_get_badge(s), ECONNRESET, 0);
		error = ECONNRESET;
		goto out;
	}
	mac_capability_instance_hold(peer);
	mtx_unlock(&cp->cp_mtx);

	SDT_PROBE3(mac_capability_channel, , , forward,
	    mac_capability_instance_get_badge(s), mac_capability_instance_get_badge(peer),
	    mac_capability_msg_datalen(msg));
	error = mac_capability_forward(peer, msg);
	mac_capability_instance_rele(peer);
out:
	SDT_PROBE4(mac_capability_channel, , , handler__done, op,
	    mac_capability_instance_get_badge(s), error, getsbinuptime() - start);
	return (error);
}

static void
channel_revoke(struct mac_capability_instance *s, uint64_t badge __unused,
    enum mac_capability_revoke_reason reason __unused, void *arg __unused)
{
	struct mac_capability_cap_channel *cp;
	struct mac_capability_instance *peer;
	bool do_revoke = false;
	bool last;

	cp = mac_capability_instance_get_priv(s);
	if (cp == NULL)
		return;

	mtx_lock(&cp->cp_mtx);

	if (s == cp->cp_a) {
		cp->cp_a = NULL;
		peer = cp->cp_b;
	} else {
		cp->cp_b = NULL;
		peer = cp->cp_a;
	}

	if (peer != NULL && !cp->cp_dead) {
		cp->cp_dead = 1;
		mac_capability_instance_hold(peer);
		do_revoke = true;
	}

	mtx_unlock(&cp->cp_mtx);

	if (do_revoke) {
		SDT_PROBE5(mac_capability_channel, , , state, (uintptr_t)"revoke",
		    0, mac_capability_instance_get_badge(s), 0, 0);
		mac_capability_instance_revoke(peer);
		mac_capability_instance_rele(peer);
	}

	/* Last endpoint to detach frees the channel struct. */
	last = refcount_release(&cp->cp_refcnt);
	if (last)
		channel_free(cp);
}

static const struct mac_capability_ops channel_ops = {
	.co_connect = channel_connect,
	.co_handler = channel_handler,
	.co_revoke = channel_revoke,
};

static int
mac_capability_channel_modevent(module_t mod __unused, int type, void *unused __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		{
			struct mac_capability_service_params p = {
				.name = "channel",
				.ops = &channel_ops,
				.flags = MAC_CAPABILITY_SVC_MINTABLE,
			};
			error = mac_capability_service_create(&p, &channel_svc);
		}
		if (error != 0) {
			printf("mac_capability_channel: failed: %d\n", error);
			return (error);
		}
		if (bootverbose)
			printf("mac_capability_channel: loaded\n");
		return (0);

	case MOD_UNLOAD:
		return (EBUSY);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mac_capability_channel_mod = {
	"mac_capability_channel",
	mac_capability_channel_modevent,
	NULL,
};

DECLARE_MODULE(mac_capability_channel, mac_capability_channel_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(mac_capability_channel, 1);
MODULE_DEPEND(mac_capability_channel, mac_capability, 1, 1, 1);
