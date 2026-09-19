/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd Friendship wiring (MshPRT_v1.1 Section 3.6.5 / 3.6.6,
 * usr.sbin/bluetooth/meshd): the Friend and Low Power node (LPN) roles driven
 * end to end over the bearer.
 *
 * The friendship engines (libmesh mesh_friend.c / mesh_lpn.c) are wired the same
 * way Directed Forwarding and Remote Provisioning were: meshd_bearer_rx decrypts
 * each inbound Network PDU with the managed-flooding credential and routes any
 * friendship Transport Control message to the Friend/LPN engine, and the node
 * tick drives the LPN poll cadence and the Friend Offer / PollTimeout timers.
 *
 * The live test runs a real two-node friendship (one Friend node, one LPN node)
 * over the capture-and-pump bearer used by meshd_df_test.c / meshd_rpr_test.c:
 * the Request / Offer / Poll / Update handshake establishes the friendship, and
 * a message injected off the network into the Friend Queue is delivered to the
 * LPN on its next Poll over the real encrypt -> bearer -> decrypt path.
 *
 * NOTE (as in the DF/RPR live tests): a meshd node spans 4 elements
 * (addr .. addr+3), so the LPN at 0x0001 owns 0x0001-0x0004; the Friend and the
 * off-network sender sit outside that range.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "mesh_cfg_model.h"
#include "mesh_friend.h"
#include "mesh_lpn.h"
#include "mesh_net.h"
#include "mesh_sim.h"
#include "mesh_transport.h"
#include "mesh_key_refresh.h"
#include "mesh_iv.h"
#include "mesh_rpl.h"
#include "mesh_crypto.h"
#include "spec_extref_mesh_net_credentials.h"

/* ================================================================
 * Capture-and-pump bearer (mirrors meshd_df_test.c df_cap_tx / df_pump).
 * ================================================================ */
#define	FR_MAXCAP	32
static struct fr_capframe {
	uint8_t			buf[64];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_cap[FR_MAXCAP];
static size_t g_ncap;

static int
fr_cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	if (g_ncap < FR_MAXCAP && len <= sizeof(g_cap[0].buf)) {
		memcpy(g_cap[g_ncap].buf, pdu, len);
		g_cap[g_ncap].len = len;
		g_cap[g_ncap].cls = cls;
		g_ncap++;
	}
	return (0);
}

/* Deliver every currently-captured Network PDU to node `to`.  Returns the
 * number of PDUs that node delivered to a model (meshd_bearer_rx == 1). */
static int
fr_pump(struct meshd_node *to)
{
	struct fr_capframe snap[FR_MAXCAP];
	size_t n, i;
	int delivered = 0;

	n = g_ncap;
	memcpy(snap, g_cap, n * sizeof(snap[0]));
	g_ncap = 0;
	for (i = 0; i < n; i++)
		if (snap[i].cls == MESHD_PDU_NET &&
		    meshd_bearer_rx(to, snap[i].buf, snap[i].len) == 1)
			delivered++;
	return (delivered);
}

static void
fr_tick(struct meshd_node *nd, uint64_t t)
{
	int ivc;

	ATF_REQUIRE(meshd_node_tick(nd, t, &ivc) >= 0);
}

/* Provision a node into the fixed shared subnet at addr with `features`. */
static void
fr_provision(struct meshd_node *nd, struct meshd_config *cfg, uint16_t addr,
    uint16_t features)
{

	meshd_config_defaults(cfg);
	memset(cfg->netkey, 0x33, 16);
	cfg->have_netkey = 1;
	memset(cfg->appkey, 0x44, 16);
	cfg->have_appkey = 1;
	cfg->netkey_index = 0;
	cfg->appkey_index = 0;
	cfg->unicast_addr = addr;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
	cfg->features = features;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
}

/* ================================================================
 * Config parsing + role enable + features reporting.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_config_and_features);
ATF_TC_BODY(friendship_config_and_features, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;

	/* "friend = 1" now parses (the old reject-on-1 is gone). */
	meshd_config_defaults(&fcfg);
	ATF_REQUIRE_EQ(0, meshd_config_parse_line(&fcfg, "friend 1"));
	ATF_CHECK((fcfg.features & MESH_CFG_FEATURE_FRIEND) != 0);
	ATF_REQUIRE_EQ(0, meshd_config_parse_line(&fcfg, "low_power 1"));
	ATF_CHECK((fcfg.features & MESH_CFG_FEATURE_LOW_POWER) != 0);
	ATF_REQUIRE_EQ(0, meshd_config_parse_line(&fcfg, "friend 0"));
	ATF_CHECK((fcfg.features & MESH_CFG_FEATURE_FRIEND) == 0);

	/* A Friend node comes up with the Friend role enabled (not "unsupported"). */
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	ATF_CHECK(friend->friend_enabled);
	ATF_CHECK_EQ(1, friend->cfg.friend);

	/* An LPN node comes up with the Low Power role enabled. */
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	ATF_CHECK(lpn->lpn_enabled);
	ATF_CHECK_EQ(MESH_LPN_ST_IDLE, lpn->lpn_fsm.state);
}

/* ================================================================
 * The "friend" / "low-power" control verbs.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_verbs);
ATF_TC_BODY(friendship_verbs, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_config cfg;
	char reply[128];
	char *av[3];

	fr_provision(nd, &cfg, 0x0100, 0);
	ATF_CHECK(!nd->friend_enabled);
	ATF_CHECK(!nd->lpn_enabled);

	/* friend on -> role enabled. */
	av[0] = (char *)(uintptr_t)"friend";
	av[1] = (char *)(uintptr_t)"on";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK friend on", 12));
	ATF_CHECK(nd->friend_enabled);

	/* friend status. */
	av[1] = (char *)(uintptr_t)"status";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK friend on", 12));

	/* friend off. */
	av[1] = (char *)(uintptr_t)"off";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK(!nd->friend_enabled);

	/* low-power on -> role enabled. */
	av[0] = (char *)(uintptr_t)"low-power";
	av[1] = (char *)(uintptr_t)"on";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK low-power on", 15));
	ATF_CHECK(nd->lpn_enabled);

	/* features verb reports Friend/LowPower live state. */
	av[0] = (char *)(uintptr_t)"features";
	ATF_CHECK_EQ(0, meshd_ctl_exec_client(nd, NULL, 1, av, reply,
	    sizeof(reply)));
	ATF_CHECK(strstr(reply, "LowPower=true") != NULL);
	ATF_CHECK(strstr(reply, "unsupported") == NULL);

	/* Bad sub-verb. */
	av[0] = (char *)(uintptr_t)"friend";
	av[1] = (char *)(uintptr_t)"bogus";
	ATF_CHECK_EQ(-1, meshd_ctl_exec_client(nd, NULL, 2, av, reply,
	    sizeof(reply)));
}


/*
 * Run the Request / Offer / Poll / Update handshake between a Friend and an
 * LPN over the capture-and-pump bearer, leaving both established and both
 * holding the friendship security material (Section 3.6.6.2).
 */
static void
fr_establish(struct meshd_node *friend, struct meshd_node *lpn)
{

	g_ncap = 0;
	fr_tick(lpn, 1000);
	ATF_REQUIRE(g_ncap >= 1);
	fr_pump(friend);
	g_ncap = 0;
	fr_tick(friend, 2000);
	ATF_REQUIRE(g_ncap >= 1);
	fr_pump(lpn);
	g_ncap = 0;
	fr_tick(lpn, 1600);
	ATF_REQUIRE(g_ncap >= 1);
	fr_pump(friend);
	ATF_REQUIRE_EQ(MESH_FRIEND_ST_ESTABLISHED, friend->friend_fsm.state);
	fr_pump(lpn);
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));
	ATF_REQUIRE(friend->self->have_friend_cred);
	ATF_REQUIRE(lpn->self->have_friend_cred);
	g_ncap = 0;
}

/* ================================================================
 * IM1: a PDU received under friendship credentials is RELAYED under the
 * managed flooding credentials.
 * ================================================================ */
/*
 * MshPRT_v1.1.1 Section 3.6.6.2: "OutMsg1 is sent secured using the friend
 * security material and therefore only the Friend node will receive and relay
 * this message.  When the Friend node relays OutMsg1, the message will be
 * retransmitted using the managed flooding security credentials."  Section
 * 3.4.6.3 Table 3.14 offers only "flooding" and "directed" as outbound
 * security material for a retransmitted Network PDU; no row emits friendship
 * material.
 *
 * Only the Friend and its own Low Power node hold the friendship credential,
 * so relaying under the credential that authenticated the PDU makes every
 * uplink message a Low Power node sends undecryptable by the rest of the
 * network - invisible without a real LPN in the test.
 */
ATF_TC_WITHOUT_HEAD(friendship_relay_uses_flooding_credentials);
ATF_TC_BODY(friendship_relay_uses_flooding_credentials, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_net_pdu in, out;
	uint8_t frame[MESH_NET_MAX_PDU];
	size_t flen;

	(void)tc;
	/*
	 * The Friend feature only.  MshPRT_v1.1.1 Section 3.6.6.1 makes Friend
	 * and Relay independent features, and Section 3.6.6.2 has the Friend
	 * relay what its Low Power node sends regardless: a Friend with the
	 * Relay feature disabled is a legal configuration that must not
	 * black-hole its LPN's uplink.
	 */
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);
	ATF_REQUIRE_EQ(0, friend->self->is_relay);
	/*
	 * The two credentials are distinct security material; the NID is only
	 * an indication, so the test also compares the keys.
	 */
	ATF_REQUIRE(memcmp(friend->self->friend_enckey, friend->self->enckey,
	    16) != 0);

	/*
	 * The Low Power node's uplink: an access message from the LPN to a
	 * third party, secured with the friendship material (which is what a
	 * conformant LPN transmits - only its Friend can receive it).  The
	 * transport payload is opaque here: 0x0055 is not the Friend's own
	 * address, so the Friend only relays it.
	 */
	memset(&in, 0, sizeof(in));
	in.nid = lpn->self->friend_nid;
	in.ctl = 0;
	in.ttl = 5;
	in.seq = 7;
	in.src = 0x0001;
	in.dst = 0x0055;
	in.transport[0] = 0x00;		/* unsegmented, AKF 0, AID 0 */
	memset(in.transport + 1, 0xA5, 8);
	in.transport_len = 9;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(lpn->self->friend_enckey,
	    lpn->self->friend_privkey, lpn->self->friend_nid, 0, &in, frame,
	    &flen));

	g_ncap = 0;
	(void)meshd_bearer_rx(friend, frame, flen);
	ATF_REQUIRE_MSG(g_ncap >= 1, "the Friend must relay its LPN's uplink");

	/* The relayed copy must be readable by the whole subnet. */
	ATF_CHECK_EQ_MSG(0, mesh_net_decrypt(friend->self->enckey,
	    friend->self->privkey, friend->self->nid, 0, g_cap[0].buf,
	    g_cap[0].len, &out),
	    "the relayed PDU must be secured with managed flooding material");
	ATF_CHECK_EQ(0x0001, out.src);
	ATF_CHECK_EQ(0x0055, out.dst);
	ATF_CHECK_EQ(7u, out.seq);
	ATF_CHECK_EQ(4, out.ttl);		/* TTL - 1 */
	ATF_CHECK_EQ(friend->self->nid, out.nid);
	ATF_CHECK_EQ(0, memcmp(out.transport, in.transport, in.transport_len));

	/* And it must NOT still be under the friendship credential. */
	ATF_CHECK_MSG(mesh_net_decrypt(friend->self->friend_enckey,
	    friend->self->friend_privkey, friend->self->friend_nid, 0,
	    g_cap[0].buf, g_cap[0].len, &out) != 0,
	    "only the Friend and the LPN hold the friendship credential");

	/*
	 * The friendship exemption sits after the TTL gate, not before it
	 * (Section 3.4.6.3: a Network PDU is relayed only with TTL >= 2).  A
	 * friendship PDU at TTL 1 is not forwarded - forwarding it would
	 * decrement 1 to 0 and, in the stacks that place the exemption first,
	 * underflow TTL 0 to 0xFF.
	 */
	in.ttl = 1;
	in.seq = 8;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(lpn->self->friend_enckey,
	    lpn->self->friend_privkey, lpn->self->friend_nid, 0, &in, frame,
	    &flen));
	g_ncap = 0;
	(void)meshd_bearer_rx(friend, frame, flen);
	ATF_CHECK_EQ_MSG(0u, g_ncap,
	    "TTL 1 is below the relay threshold, friendship credential or not");
}


/* ================================================================
 * IM2 / IM14: the Segment Acknowledgment OBO pair.
 * ================================================================ */
/*
 * MshPRT_v1.1.1 Section 3.5.3.4: "If the device is acting as a Friend node for
 * a Low Power node, then it shall reassemble segmented messages destined for
 * the Low Power node and act as described, except that it shall set the OBO
 * field to 1 in the Segment Acknowledgment message"; Section 3.5.3.5: a Low
 * Power node "does not send any Segment Acknowledgment messages".  Table 3.24
 * validates an acknowledgment when "either the source address ... matches the
 * destination address value stored by the lower transport layer, or the value
 * of the OBO field ... is 1".
 *
 * The two halves are one defect seen from both sides: without the OBO bit no
 * conformant originator accepts our Friend's acknowledgment, and without the
 * Table 3.24 alternative we accept no Friend's acknowledgment for any LPN we
 * send to.  Either way no segmented message completes between us and a Low
 * Power node.
 */
ATF_TC_WITHOUT_HEAD(friendship_segment_ack_obo);
ATF_TC_BODY(friendship_segment_ack_obo, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	MESH_HEAP(struct mesh_sim, src);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_node *sender;
	struct mesh_net_pdu np;
	struct mesh_seg_ack ack;
	struct mesh_lower lower;
	uint8_t netkey[16], appkey[16];
	uint8_t params[24];
	uint8_t seg[MESH_SEG_MAX][MESH_NET_MAX_PDU];
	size_t seglen[MESH_SEG_MAX], nseg, i;
	int acks = 0;

	(void)tc;
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);

	/*
	 * An off-network originator sends a segmented access message to the
	 * Low Power node.  24 parameter octets do not fit an unsegmented
	 * Upper Transport Access PDU, so the access layer segments it.
	 */
	memset(netkey, 0x33, sizeof(netkey));
	memset(appkey, 0x44, sizeof(appkey));
	ATF_REQUIRE_EQ(0, mesh_sim_init(src, netkey, appkey, 0));
	sender = mesh_sim_add_node(src, 0x00AA, 1);
	ATF_REQUIRE(sender != NULL);
	memset(params, 0x5C, sizeof(params));
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(src, sender, 0x0001, 0x8299,
	    params, sizeof(params), 5));
	nseg = src->n_tx;
	ATF_REQUIRE_MSG(nseg > 1, "the message must be segmented (%zu)", nseg);
	ATF_REQUIRE(nseg <= MESH_SEG_MAX);
	for (i = 0; i < nseg; i++) {
		seglen[i] = src->tx[i].len;
		memcpy(seg[i], src->tx[i].bytes, seglen[i]);
	}
	/* The originator is now waiting for an acknowledgment. */
	ATF_REQUIRE_EQ(1, sender->sar_tx[0].used);
	ATF_REQUIRE_EQ(0x0001, sender->sar_tx[0].dst);

	/* -- IM14: the Friend acknowledges on behalf of its LPN ------------ */
	g_ncap = 0;
	for (i = 0; i < nseg; i++)
		(void)meshd_bearer_rx(friend, seg[i], seglen[i]);
	ATF_REQUIRE_MSG(g_ncap >= 1,
	    "the Friend must acknowledge for its Low Power node");
	/*
	 * Find the (last, therefore complete) Segment Acknowledgment among the
	 * Friend's output and check the OBO field and the source address.
	 */
	memset(&ack, 0, sizeof(ack));
	for (i = 0; i < g_ncap; i++) {
		struct mesh_net_pdu a;

		if (mesh_net_decrypt(friend->self->enckey,
		    friend->self->privkey, friend->self->nid, 0, g_cap[i].buf,
		    g_cap[i].len, &a) != 0 || a.ctl != 1)
			continue;
		if (mesh_lower_parse(1, a.transport, a.transport_len,
		    &lower) != 0 || lower.seg || lower.opcode != 0x00)
			continue;
		if (mesh_seg_ack_parse(a.transport, a.transport_len,
		    &ack) != 0)
			continue;
		ATF_CHECK_EQ_MSG(0x0100, a.src,
		    "the Friend sources the acknowledgment from its own address");
		ATF_CHECK_EQ_MSG(0x00AA, a.dst,
		    "DST is the SRC of the first received segment");
		ATF_CHECK_EQ_MSG(1, ack.obo,
		    "a Friend acknowledging for a Low Power node sets OBO = 1");
		acks++;
		memcpy(&np, &a, sizeof(np));
	}
	ATF_REQUIRE_MSG(acks > 0, "no Segment Acknowledgment was emitted");
	ATF_CHECK_EQ_MSG(mesh_blockack_full((uint8_t)(nseg - 1)), ack.blockack,
	    "the last acknowledgment reports every segment as received");

	/* -- IM13: the Low Power node itself never acknowledges ------------ */
	g_ncap = 0;
	for (i = 0; i < nseg; i++)
		(void)meshd_bearer_rx(lpn, seg[i], seglen[i]);
	for (i = 0; i < g_ncap; i++) {
		struct mesh_net_pdu a;

		if (mesh_net_decrypt(lpn->self->enckey, lpn->self->privkey,
		    lpn->self->nid, 0, g_cap[i].buf, g_cap[i].len, &a) != 0)
			continue;
		ATF_CHECK_MSG(!(a.ctl == 1 && a.transport_len > 0 &&
		    (a.transport[0] & 0x7f) == 0x00),
		    "an established Low Power node sends no Segment Ack");
	}

	/* -- IM2: the originator accepts an acknowledgment with OBO = 1 ---- */
	{
		uint8_t frame[MESH_NET_MAX_PDU];
		size_t flen;

		ATF_REQUIRE_EQ(0, mesh_net_encrypt(friend->self->enckey,
		    friend->self->privkey, friend->self->nid, 0, &np, frame,
		    &flen));
		ATF_REQUIRE_EQ(0, mesh_sim_reinject(src, -1, frame, flen));
		(void)mesh_sim_step(src);
	}
	ATF_CHECK_EQ_MSG(0, sender->sar_tx[0].used,
	    "Table 3.24: an OBO acknowledgment from the Friend completes the "
	    "transmission even though its source is not the stored destination");
}

/* ================================================================
 * IM5: a Friend Update drives the Key Refresh phase only when it was
 * authenticated with the new NetKey.
 * ================================================================ */
/*
 * MshPRT_v1.1.1 Section 3.6.6.4.2 makes a Friend Update equivalent to a beacon
 * for the Flags octet, and Section 3.11.4.1 states the rule the flag obeys:
 * "Upon receiving a Secure Network beacon or a Mesh Private beacon with the Key
 * Refresh Flag set to 0 USING THE NEW NETKEY in Phase 1, the node shall
 * immediately transition to Phase 3, which effectively skips Phase 2."
 *
 * A Friend in Phase 1 emits exactly that flag under the OLD key, and the
 * friendship credential is itself derived from the old NetKey, so driving the
 * phase machine from any Friend Update collapses a Low Power node to Phase 3
 * on the first Update after a NetKey Update - revoking a key the rest of the
 * network is still transmitting on.
 */
ATF_TC_WITHOUT_HEAD(friendship_lpn_update_kr_needs_new_key);
ATF_TC_BODY(friendship_lpn_update_kr_needs_new_key, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_friend_update up;
	struct mesh_net_pdu np;
	uint8_t body[8], frame[MESH_NET_MAX_PDU], new_netkey[16], old_netkey[16];
	size_t blen, flen;

	(void)tc;
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);

	/* The Low Power node is given a new NetKey: Key Refresh Phase 1. */
	memcpy(old_netkey, lpn->self->netkey, 16);
	memset(new_netkey, 0x66, sizeof(new_netkey));
	ATF_REQUIRE_EQ(0, meshd_kr_begin(lpn, new_netkey));
	ATF_REQUIRE_EQ(MESH_KR_PHASE_1, meshd_kr_phase(lpn));
	ATF_REQUIRE(lpn->self->have_new_key);

	/* A Friend Update with Key Refresh Flag 0, secured with the OLD key. */
	memset(&up, 0, sizeof(up));
	up.key_refresh = 0;
	up.iv_update = 0;
	up.iv_index = lpn->self->iv.iv_index;
	up.md = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_update_build(&up, body, &blen));
	memset(&np, 0, sizeof(np));
	np.ctl = 1;
	np.ttl = 0;
	np.seq = 0x100;
	np.src = 0x0100;
	np.dst = 0x0001;
	memcpy(np.transport, body, blen);
	np.transport_len = blen;
	np.nid = lpn->self->nid;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(lpn->self->enckey,
	    lpn->self->privkey, lpn->self->nid, up.iv_index, &np, frame,
	    &flen));
	(void)meshd_bearer_rx(lpn, frame, flen);
	ATF_CHECK_EQ_MSG(MESH_KR_PHASE_1, meshd_kr_phase(lpn),
	    "a Friend Update under the old NetKey carries no phase transition");
	ATF_CHECK_EQ_MSG(0, memcmp(lpn->self->netkey, old_netkey, 16),
	    "the old NetKey must not be revoked by it");

	/* The same Update, secured with the NEW NetKey, does collapse to 3. */
	np.seq = 0x101;
	np.nid = lpn->self->new_nid;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(lpn->self->new_enckey,
	    lpn->self->new_privkey, lpn->self->new_nid, up.iv_index, &np, frame,
	    &flen));
	(void)meshd_bearer_rx(lpn, frame, flen);
	ATF_CHECK_EQ_MSG(0, memcmp(lpn->self->netkey, new_netkey, 16),
	    "Section 3.11.4.1: flag 0 under the new NetKey skips to Phase 3");
	ATF_CHECK_EQ(0, lpn->self->have_new_key);
}

/* ================================================================
 * Live two-node friendship: establishment + queued-message delivery.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_live_establish_and_deliver);
ATF_TC_BODY(friendship_live_establish_and_deliver, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	MESH_HEAP(struct mesh_sim, src);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_node *sender;
	uint8_t netkey[16], appkey[16];
	uint8_t msg[3] = { 0x82, 0x99, 0x5A };	/* a 2-octet-opcode access msg */
	uint8_t poll[64];
	size_t poll_len;
	size_t qbefore;
	int delivered;

	/* Friend at 0x0100 (outside the LPN's 0x0001-0x0004 element span). */
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	ATF_REQUIRE(friend->friend_enabled);
	ATF_REQUIRE(lpn->lpn_enabled);

	/* -- Establishment ------------------------------------------------- */

	/* LPN's first tick originates the Friend Request onto the bearer. */
	g_ncap = 0;
	fr_tick(lpn, 1000);
	ATF_CHECK_EQ(MESH_LPN_ST_REQUESTING, lpn->lpn_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);

	/* Request -> Friend: accepted, Friend Queue bound to the LPN. */
	fr_pump(friend);
	ATF_CHECK_EQ(MESH_FRIEND_ST_OFFERING, friend->friend_fsm.state);
	ATF_CHECK_EQ(0x0001, friend->friend_fsm.lpn_addr);

	/* Friend tick past the Offer Delay emits the Friend Offer. */
	g_ncap = 0;
	fr_tick(friend, 2000);
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHING, friend->friend_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);

	/* Offer -> LPN: collected. */
	fr_pump(lpn);
	ATF_CHECK(lpn->lpn_fsm.n_offers >= 1);

	/* LPN tick past the Offer window selects and sends the first Poll. */
	g_ncap = 0;
	fr_tick(lpn, 1600);
	ATF_CHECK_EQ(MESH_LPN_ST_ESTABLISHING, lpn->lpn_fsm.state);
	ATF_CHECK_EQ(0x0100, lpn->lpn_fsm.friend_addr);
	ATF_REQUIRE(g_ncap >= 1);
	poll_len = g_cap[0].len;
	ATF_REQUIRE(poll_len <= sizeof(poll));
	memcpy(poll, g_cap[0].buf, poll_len);

	/* Poll -> Friend: establishes the friendship, answers with a Friend
	 * Update (empty queue); Update -> LPN establishes the friendship. */
	fr_pump(friend);
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHED, friend->friend_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);		/* Friend emitted an Update */
	fr_pump(lpn);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));

	/* An authenticated replay of the first Poll must not emit another Update. */
	g_ncap = 0;
	ATF_CHECK_EQ(0, meshd_bearer_rx(friend, poll, poll_len));
	ATF_CHECK_EQ(0, g_ncap);

	/* -- Queued-message delivery -------------------------------------- */

	/*
	 * An off-network sender at 0x00AA (outside the LPN element span) emits an
	 * access message to the LPN, secured with the shared subnet + AppKey.
	 * Injecting that Network PDU into the Friend fills the Friend Queue.
	 */
	memset(netkey, 0x33, sizeof(netkey));
	memset(appkey, 0x44, sizeof(appkey));
	ATF_REQUIRE_EQ(0, mesh_sim_init(src, netkey, appkey, 0));
	sender = mesh_sim_add_node(src, 0x00AA, 1);
	ATF_REQUIRE(sender != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(src, sender, 0x0001, 0x8299,
	    &msg[2], 1, 5));
	ATF_REQUIRE(src->n_tx >= 1);
	/* Not addressed to the Friend's own models (returns 0), but the Friend
	 * Queue captures it for the LPN (one more entry than before). */
	qbefore = mesh_fq_count(&friend->friend_fsm.queue);
	(void)meshd_bearer_rx(friend, src->tx[0].bytes, src->tx[0].len);
	ATF_CHECK_EQ(qbefore + 1, mesh_fq_count(&friend->friend_fsm.queue));

	/* LPN's next cadence Poll pulls the queued message. */
	g_ncap = 0;
	fr_tick(lpn, 4000);
	ATF_CHECK_EQ(MESH_LPN_ST_ESTABLISHED, lpn->lpn_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);		/* a Poll was emitted */

	/* Poll -> Friend: dequeues and delivers the message to the LPN. */
	fr_pump(friend);
	ATF_REQUIRE(g_ncap >= 1);		/* Friend forwarded the message */
	delivered = fr_pump(lpn);

	/* The queued message reached the LPN over the real decrypt path. */
	ATF_CHECK_EQ(1, delivered);
	ATF_CHECK(lpn->self->rx.count > 0);
	ATF_CHECK_EQ(0x00AA, lpn->self->rx.src);
	ATF_CHECK_EQ(0x0001, lpn->self->rx.dst);
	ATF_CHECK_EQ(0x8299u, lpn->self->rx.opcode);
}

/* ================================================================
 * A queued message is delivered under the IV Index captured at ENQUEUE, not
 * the Friend's live TX index: an IV transition completing between enqueue and
 * the Poll must not remap the original (IV,SRC,SEQ).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_delivery_uses_enqueue_iv);
ATF_TC_BODY(friendship_delivery_uses_enqueue_iv, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	MESH_HEAP(struct mesh_sim, src);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_node *sender;
	const struct mesh_fq_entry *stored = NULL;
	uint8_t netkey[16], appkey[16];
	uint8_t msg[3] = { 0x82, 0x99, 0x5A };
	size_t qbefore, i;
	int delivered;

	/* Establish the friendship (condensed friendship_live_establish...). */
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	g_ncap = 0;
	fr_tick(lpn, 1000);			/* Friend Request */
	fr_pump(friend);
	g_ncap = 0;
	fr_tick(friend, 2000);			/* Friend Offer */
	fr_pump(lpn);
	g_ncap = 0;
	fr_tick(lpn, 1600);			/* first Poll */
	fr_pump(friend);			/* established + Update */
	fr_pump(lpn);
	ATF_REQUIRE_EQ(MESH_FRIEND_ST_ESTABLISHED, friend->friend_fsm.state);
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));

	/* Off-network sender enqueues a message at IV Index 0. */
	memset(netkey, 0x33, sizeof(netkey));
	memset(appkey, 0x44, sizeof(appkey));
	ATF_REQUIRE_EQ(0, mesh_sim_init(src, netkey, appkey, 0));
	sender = mesh_sim_add_node(src, 0x00AA, 1);
	ATF_REQUIRE(sender != NULL);
	ATF_REQUIRE_EQ(0, mesh_sim_send_access(src, sender, 0x0001, 0x8299,
	    &msg[2], 1, 5));
	ATF_REQUIRE(src->n_tx >= 1);
	qbefore = mesh_fq_count(&friend->friend_fsm.queue);
	(void)meshd_bearer_rx(friend, src->tx[0].bytes, src->tx[0].len);
	ATF_REQUIRE_EQ(qbefore + 1, mesh_fq_count(&friend->friend_fsm.queue));

	/* The stored entry captured the enqueue-time IV Index (0). */
	for (i = 0; i < MESH_FQ_MAX; i++) {
		const struct mesh_fq_entry *e =
		    &friend->friend_fsm.queue.entries[i];

		if (e->valid && !e->is_update && e->src == 0x00AA)
			stored = e;
	}
	ATF_REQUIRE(stored != NULL);
	ATF_CHECK_EQ(0u, stored->iv_index);

	/*
	 * The Friend's IV Update completes BETWEEN enqueue and delivery: its
	 * live TX index moves to 1 while the LPN (asleep) stays on 0.
	 */
	friend->self->iv.iv_index = 1;
	friend->self->iv.state = MESH_IV_NORMAL;

	/* LPN cadence Poll pulls the queued message. */
	g_ncap = 0;
	fr_tick(lpn, 4000);
	ATF_REQUIRE(g_ncap >= 1);
	fr_pump(friend);
	ATF_REQUIRE(g_ncap >= 1);
	/* The forwarded data PDU is secured at IV 0: its IVI bit is clear. */
	ATF_CHECK_EQ(0, g_cap[0].buf[0] >> 7);
	delivered = fr_pump(lpn);

	/* The LPN (still on IV 0) decrypts the exact original message. */
	ATF_CHECK_EQ(1, delivered);
	ATF_CHECK(lpn->self->rx.count > 0);
	ATF_CHECK_EQ(0x00AA, lpn->self->rx.src);
	ATF_CHECK_EQ(0x8299u, lpn->self->rx.opcode);
}

/*
 * Round-2 fix: Config Node Reset must also stop the node ORIGINATING as a
 * friendship role.  nd->lpn_enabled / nd->friend_enabled live outside nd->db,
 * so the reset's memset left them set and the tick's LPN FSM kept sending
 * Friend Requests / Polls (and the Friend role its Offers) on the credentials
 * the node had just been told to forget.
 */
ATF_TC_WITHOUT_HEAD(node_reset_stops_friendship_origination);
ATF_TC_BODY(node_reset_stops_friendship_origination, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx, .arg = NULL };
	struct meshd_bearer lbear = { .tx = fr_cap_tx, .arg = NULL };
	uint8_t msg[16], reply[64];
	size_t mlen, rlen;

	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	ATF_REQUIRE(friend->friend_enabled);
	ATF_REQUIRE(lpn->lpn_enabled);

	/* Establish far enough that both roles are live and originating. */
	g_ncap = 0;
	fr_tick(lpn, 1000);				/* Friend Request */
	ATF_REQUIRE_EQ(MESH_LPN_ST_REQUESTING, lpn->lpn_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);
	fr_pump(friend);
	ATF_REQUIRE_EQ(MESH_FRIEND_ST_OFFERING, friend->friend_fsm.state);

	/* Node Reset the LPN: role off, FSM back to IDLE, nothing on the air. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(msg, &mlen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(lpn, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(0, lpn->provisioned);
	ATF_CHECK_EQ(0, lpn->lpn_enabled);
	ATF_CHECK_EQ(MESH_LPN_ST_IDLE, lpn->lpn_fsm.state);
	ATF_CHECK_EQ(0, lpn->self->have_friend_cred);
	g_ncap = 0;
	fr_tick(lpn, 5000);
	fr_tick(lpn, 30000);
	ATF_CHECK_EQ(0, g_ncap);		/* no Friend Request, no Poll */

	/* Node Reset the Friend: role off, FSM reset, no Offer emitted. */
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(friend, msg, mlen, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(0, friend->provisioned);
	ATF_CHECK_EQ(0, friend->friend_enabled);
	ATF_CHECK_EQ(MESH_FRIEND_ST_IDLE, friend->friend_fsm.state);
	ATF_CHECK_EQ(0, friend->self->have_friend_cred);
	g_ncap = 0;
	fr_tick(friend, 5000);
	fr_tick(friend, 30000);
	ATF_CHECK_EQ(0, g_ncap);		/* no Offer, no Friend Update */
}


/* ================================================================
 * IM11: the Friend Queue stores Transport Control PDUs.
 * ================================================================ */
/*
 * MshPRT_v1.1.1 Section 3.5.5: "The Friend Queue stores Lower Transport PDUs
 * for a Low Power node.  No field of the Lower Transport PDU shall be changed
 * due to the message being in the Friend Queue.  The CTL, TTL, SEQ, SRC, and
 * DST fields shall be stored with the associated Lower Transport PDU."  CTL is
 * one of the fields that is STORED; it is not a filter on what may be stored.
 *
 * Excluding Control PDUs is not a cosmetic gap.  Section 3.5.3.5 - "When the
 * Low Power node feature is in use, reassembly is performed by a Friend node
 * and the Low Power node does not send any Segment Acknowledgment messages" -
 * means a Low Power node's own outbound segmented transfer can only ever be
 * acknowledged by a Segment Acknowledgment travelling to it through the Friend
 * Queue.  With Control PDUs dropped at enqueue that acknowledgment never
 * arrives and the transfer retransmits until its budget is exhausted.
 *
 * Driven end to end through meshd_send_access_raw(), meshd_bearer_rx() and
 * meshd_node_tick() - the daemon's origination, receive and cadence entry
 * points - with the real Poll handshake carrying the queued acknowledgment.
 */
ATF_TC_WITHOUT_HEAD(friendship_queue_stores_control_pdus);
ATF_TC_BODY(friendship_queue_stores_control_pdus, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_net_pdu np;
	struct mesh_seg_ack ack;
	uint8_t access[26], frame[MESH_NET_MAX_PDU];
	uint8_t lt[MESH_SEG_ACK_LEN];
	uint16_t seqzero;
	uint8_t segn;
	size_t flen, ltlen, i;
	uint64_t t;
	int delivered;

	(void)tc;
	fr_provision(friend, &fcfg, 0x0100, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);

	/*
	 * The Low Power node originates a segmented access message to a third
	 * party: a 2-octet opcode plus 24 parameter octets does not fit an
	 * unsegmented Upper Transport Access PDU.
	 */
	access[0] = 0x82;
	access[1] = 0x99;
	memset(access + 2, 0x71, sizeof(access) - 2);
	g_ncap = 0;
	ATF_REQUIRE(meshd_send_access_raw(lpn, 0x00AA, access,
	    sizeof(access)) >= 0);
	ATF_REQUIRE_MSG(lpn->self->sar_tx[0].used == 1,
	    "the Low Power node must have an outstanding segmented transfer");
	ATF_REQUIRE_EQ(0x00AA, lpn->self->sar_tx[0].dst);
	seqzero = lpn->self->sar_tx[0].seqzero;
	segn = lpn->self->sar_tx[0].segn;
	ATF_REQUIRE(segn >= 1);
	g_ncap = 0;

	/*
	 * The peer acknowledges every segment.  The acknowledgment is addressed
	 * to the Low Power node's unicast address, which is exactly the
	 * destination the Friend Queue serves, and OBO is 0 because the peer is
	 * answering the node that addressed it.
	 */
	memset(&ack, 0, sizeof(ack));
	ack.seqzero = seqzero;
	ack.blockack = mesh_blockack_full(segn);
	ack.obo = 0;
	ATF_REQUIRE_EQ(0, mesh_seg_ack_build(&ack, lt, &ltlen));
	memset(&np, 0, sizeof(np));
	np.nid = friend->self->nid;
	np.ctl = 1;
	np.ttl = 5;
	np.seq = 0x40;
	np.src = 0x00AA;
	np.dst = 0x0001;
	memcpy(np.transport, lt, ltlen);
	np.transport_len = ltlen;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(friend->self->enckey,
	    friend->self->privkey, friend->self->nid, 0, &np, frame, &flen));

	ATF_REQUIRE_EQ(0u, (unsigned)mesh_fq_count(&friend->friend_fsm.queue));
	(void)meshd_bearer_rx(friend, frame, flen);
	ATF_CHECK_EQ_MSG(1u, (unsigned)mesh_fq_count(&friend->friend_fsm.queue),
	    "a Segment Acknowledgment for the LPN must enter the Friend Queue");

	/*
	 * The Low Power node polls, the Friend answers with the queued
	 * acknowledgment, and the acknowledgment completes the LPN's own
	 * transfer.  This is the whole point of the queue accepting Control
	 * PDUs: Section 3.5.3.5 leaves the LPN no other way to be acknowledged.
	 */
	g_ncap = 0;
	delivered = 0;
	for (t = 3000; t <= 9000 && lpn->self->sar_tx[0].used; t += 500) {
		fr_tick(lpn, t);
		fr_pump(friend);
		/*
		 * The Friend's answer to the Poll is now in the capture.  Check
		 * it arrived with its CTL, SRC, SEQ and DST fields unchanged
		 * before pumping it into the Low Power node, because fr_pump()
		 * drains the capture.
		 */
		for (i = 0; i < g_ncap; i++) {
			struct mesh_net_pdu d;

			if (mesh_net_decrypt(friend->self->friend_enckey,
			    friend->self->friend_privkey,
			    friend->self->friend_nid, 0, g_cap[i].buf,
			    g_cap[i].len, &d) != 0)
				continue;
			if (d.ctl != 1 || d.src != 0x00AA || d.dst != 0x0001)
				continue;
			ATF_CHECK_EQ_MSG(0x40u, d.seq,
			    "Section 3.5.5: no field of the stored Lower "
			    "Transport PDU may change");
			ATF_CHECK_EQ_MSG(0, memcmp(d.transport, lt, ltlen),
			    "the stored Lower Transport PDU is delivered "
			    "verbatim");
			delivered = 1;
		}
		fr_pump(lpn);
	}
	ATF_CHECK_MSG(delivered,
	    "the queued Control PDU was never delivered to the LPN");
	ATF_CHECK_EQ_MSG(0, lpn->self->sar_tx[0].used,
	    "the queued Segment Acknowledgment must complete the LPN's "
	    "segmented transfer");
}

/* ================================================================
 * IM27: the Low Power node recovers a missed IV Update from a Friend Update.
 *
 * MshPRT_v1.1.1 Section 3.6.6.4.2, verbatim: "If the Low Power node receives a
 * Friend Update message, it shall process the Flags and IV Index fields using
 * the same rules as if they had been received in a Secure Network beacon."
 *
 * "The same rules" includes IV Index Recovery, and Section 3.11.6 names the
 * Low Power node as THE designated mechanism for exactly this case, .txt lines
 * 11614-11618, verbatim: "a device that stays away from the mesh network for
 * extended periods (for example, a battery-powered doorbell button) either
 * should be configured as a Low Power node so that it receives IV Index
 * updates from a Friend node ... or should have the Proxy Client role".
 *
 * The Friend Update path called the raw state machine instead of the wrapper,
 * so the LPN never armed recovery, never took the Table 3.86 sequence reset
 * and never flushed the replay list: an IV Index more than one ahead was
 * simply rejected, and the one device class the specification points at was
 * the one that could not rejoin.
 *
 * Driven entirely through the daemon: meshd_node_tick() drives the Poll and
 * meshd_bearer_rx() carries the Friend Update.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(friendship_lpn_recovers_iv_from_update);
ATF_TC_BODY(friendship_lpn_recovers_iv_from_update, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	struct mesh_friend_update up;
	struct mesh_net_pdu in;
	uint8_t body[MESH_FRIEND_UPDATE_LEN];
	uint8_t frame[MESH_NET_MAX_PDU];
	size_t blen, flen, i;
	int seen;

	(void)tc;
	fr_provision(friend, &fcfg, 0x0005, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);

	/*
	 * TEST SETUP, not behaviour under test.  Put the LPN in IV Update in
	 * Progress at IV Index 1 (so it transmits with 0 and accepts network
	 * PDUs secured with 1 or 0, Section 3.11.5), and give it some state a
	 * recovery has to clear.  The network has moved one index further on
	 * while the LPN slept: the Friend Update below announces IV Index 2
	 * with the IV Update flag still set, secured with IV Index 1 - which is
	 * exactly what a Friend that is itself in IV Update in Progress at 2
	 * transmits, and what the LPN can still decrypt.
	 *
	 * This is Table 3.86 row 3: Current IV Index + 1 while an update is
	 * already in progress.  The ordinary Section 3.11.5 procedure cannot
	 * explain it (the node is already updating), so it is an IV Index
	 * Recovery row, and it resets the sequence numbers.
	 */
	lpn->self->iv.iv_index = 1;
	lpn->self->iv.state = MESH_IV_UPDATE_IN_PROGRESS;
	lpn->self->seq = 4242;
	ATF_REQUIRE_EQ(1, mesh_rpl_commit(&lpn->self->rpl, 0x0102, 1, 7));
	seen = 0;
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		if (lpn->self->rpl_store[i].valid)
			seen = 1;
	ATF_REQUIRE_EQ_MSG(1, seen, "the replay list must start non-empty");

	memset(&up, 0, sizeof(up));
	up.key_refresh = 0;
	up.iv_update = 1;
	up.iv_index = 2;
	up.md = 0;
	ATF_REQUIRE_EQ(0, mesh_friend_update_build(&up, body, &blen));

	memset(&in, 0, sizeof(in));
	in.ivi = 1u & 1u;
	in.nid = lpn->self->friend_nid;
	in.ctl = 1;
	in.ttl = 0;
	in.seq = 100;
	in.src = 0x0005;
	in.dst = 0x0001;
	memcpy(in.transport, body, blen);
	in.transport_len = blen;
	ATF_REQUIRE_EQ(0, mesh_net_encrypt(lpn->self->friend_enckey,
	    lpn->self->friend_privkey, lpn->self->friend_nid, 1, &in, frame,
	    &flen));

	/* The daemon's bearer entry point carries it in. */
	(void)meshd_bearer_rx(lpn, frame, flen);

	ATF_CHECK_EQ_MSG(2u, lpn->self->iv.iv_index,
	    "the LPN must recover the missed IV Index (Section 3.11.6)");
	ATF_CHECK_EQ(MESH_IV_UPDATE_IN_PROGRESS, lpn->self->iv.state);
	ATF_CHECK_EQ_MSG(0u, lpn->self->seq,
	    "Table 3.86: the recovery resets the sequence numbers");
	for (i = 0; i < MESH_SIM_RPL_SIZE; i++)
		ATF_CHECK_EQ_MSG(0, lpn->self->rpl_store[i].valid,
		    "the replay list belongs to the abandoned IV epoch");
	ATF_CHECK_EQ_MSG(1, lpn->self->iv.recovery_done,
	    "the recovery must be recorded so the 192-hour hold starts");
	ATF_CHECK_EQ(0, lpn->self->iv.recovery_active);
}

/* ================================================================
 * IM30: friendship credentials follow the transmit key across Phase 2.
 *
 * MshPRT_v1.1.1 Section 3.9.6.3.1 derives the friendship security material
 * from the NetKey:
 *   "NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x01 || LPNAddress ||
 *    FriendAddress || LPNCounter || FriendCounter)"
 *
 * and Section 3.11.4.2 says of Key Refresh Phase 2, verbatim: "When in Phase
 * 2, the node shall only transmit messages and Secure Network beacons or Mesh
 * Private beacons using the new keys, shall receive messages using the old
 * keys and the new keys".  There is no exemption for friendship PDUs, so from
 * Phase 2 the Friend Update, Friend Poll, Subscription-List messages and every
 * queued delivery must be secured with the credential derived from the NEW
 * NetKey.  Re-deriving only at Phase 3 leaves a conformant peer unable to
 * decrypt anything on the friendship link for the whole of Phase 2.
 *
 * Section 3.11.4.1 pins the other side of the boundary: "During this phase,
 * the node shall transmit using the old keys and receive using both the old
 * keys and the new keys."  So Phase 1 must still use the OLD credential.
 *
 * The expected new-key material is built here from the specification's own
 * formula - mesh_k2() over a hand-assembled 9-octet P input laid out per
 * spec_extref_mesh_net_credentials.h's transcription of Section 3.9.6.3.1 -
 * rather than by calling the friendship-credential helper under test.
 *
 * Driven through meshd_foundation_recv() (Config NetKey Update and Key Refresh
 * Phase Set) and meshd_node_tick() / meshd_bearer_rx() (the Poll and Update).
 * ================================================================ */
static void
im30_expected_friend_material(const uint8_t netkey[16], uint16_t lpn_addr,
    uint16_t friend_addr, uint16_t lpn_counter, uint16_t friend_counter,
    uint8_t *nid, uint8_t *enc, uint8_t *priv)
{
	uint8_t pin[SPEC_EXTREF_MESH_K2_P_LEN_FRIENDSHIP];

	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_TAG] =
	    SPEC_EXTREF_MESH_K2_P_FRIENDSHIP;
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_ADDR] =
	    (uint8_t)(lpn_addr >> 8);
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_ADDR + 1] =
	    (uint8_t)lpn_addr;
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_ADDR] =
	    (uint8_t)(friend_addr >> 8);
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_ADDR + 1] =
	    (uint8_t)friend_addr;
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_COUNTER] =
	    (uint8_t)(lpn_counter >> 8);
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_LPN_COUNTER + 1] =
	    (uint8_t)lpn_counter;
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_COUNTER] =
	    (uint8_t)(friend_counter >> 8);
	pin[SPEC_EXTREF_MESH_K2_FRIEND_P_OFF_FRIEND_COUNTER + 1] =
	    (uint8_t)friend_counter;
	ATF_REQUIRE_EQ(0, mesh_k2(netkey, pin, sizeof(pin), nid, enc, priv));
}

/* Config NetKey Update / Key Refresh Phase Set through the node's own
 * foundation dispatch, which is where the Configuration Server hangs. */
static void
im30_netkey_update(struct meshd_node *nd, uint16_t net_idx,
    const uint8_t key[16])
{
	struct mesh_cfg_netkey nk;
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	uint16_t got_idx;
	uint8_t status;
	size_t req_len, st_len = 0;

	memset(&nk, 0, sizeof(nk));
	nk.net_idx = net_idx;
	memcpy(nk.key, key, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, req, &req_len));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, req, req_len, st,
	    sizeof(st), &st_len));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(st, st_len, &status,
	    &got_idx));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);
}

static void
im30_kr_phase_set(struct meshd_node *nd, uint16_t net_idx, uint8_t transition)
{
	uint8_t req[64], st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len = 0;

	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(net_idx, transition, req,
	    &req_len));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, req, req_len, st,
	    sizeof(st), &st_len));
}

/* Tick the node forward until it emits something, or give up. */
static void
im30_tick_until_tx(struct meshd_node *nd, uint64_t *t)
{
	int i;

	for (i = 0; i < 40 && g_ncap == 0; i++) {
		*t += 1000;
		fr_tick(nd, *t);
	}
}

ATF_TC_WITHOUT_HEAD(friendship_credentials_follow_phase2_key);
ATF_TC_BODY(friendship_credentials_follow_phase2_key, tc)
{
	MESH_HEAP(struct meshd_node, friend);
	MESH_HEAP(struct meshd_node, lpn);
	struct meshd_config fcfg, lcfg;
	struct meshd_bearer fbear = { .tx = fr_cap_tx };
	struct meshd_bearer lbear = { .tx = fr_cap_tx };
	uint8_t newkey[16];
	uint8_t xnid, xenc[16], xpriv[16];
	uint8_t old_nid;
	uint64_t t = 2000;

	(void)tc;
	fr_provision(friend, &fcfg, 0x0005, MESH_CFG_FEATURE_FRIEND);
	fr_provision(lpn, &lcfg, 0x0001, MESH_CFG_FEATURE_LOW_POWER);
	meshd_set_bearer(friend, &fbear);
	meshd_set_bearer(lpn, &lbear);
	fr_establish(friend, lpn);
	old_nid = friend->self->friend_nid;
	ATF_REQUIRE_EQ_MSG(0, friend->self->have_new_friend_cred,
	    "no Key Refresh yet, so only one friendship credential");

	/* The expected Phase-2 material, from the Section 3.9.6.3.1 formula. */
	memset(newkey, 0xA5, sizeof(newkey));
	im30_expected_friend_material(newkey, friend->self->fc_lpn_addr,
	    friend->self->fc_friend_addr, friend->self->fc_lpn_counter,
	    friend->self->fc_friend_counter, &xnid, xenc, xpriv);
	ATF_REQUIRE_MSG(xnid != old_nid,
	    "the two NetKeys must yield different friendship NIDs for this "
	    "test to have any content");

	/*
	 * Phase 1 (Section 3.11.4.1): the new NetKey is stored and the
	 * new-key friendship credential must exist from now on, because the
	 * node "shall ... receive using both the old keys and the new keys".
	 * Transmission still uses the old one.
	 */
	im30_netkey_update(friend, 0, newkey);
	im30_netkey_update(lpn, 0, newkey);
	ATF_CHECK_EQ_MSG(1, friend->self->have_new_friend_cred,
	    "Phase 1 must stage the new-key friendship credential");
	ATF_CHECK_EQ_MSG(xnid, friend->self->new_friend_nid,
	    "the staged credential must be k2(new NetKey, 0x01 || ...)");
	ATF_CHECK_EQ(0, memcmp(friend->self->new_friend_enckey, xenc, 16));
	ATF_CHECK_EQ(0, memcmp(friend->self->new_friend_privkey, xpriv, 16));

	g_ncap = 0;
	im30_tick_until_tx(lpn, &t);
	ATF_REQUIRE_MSG(g_ncap >= 1, "the LPN must poll in Phase 1");
	ATF_CHECK_EQ_MSG(old_nid,
	    g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK,
	    "Section 3.11.4.1: Phase 1 transmits with the OLD keys");
	/* Complete the Phase-1 exchange so no Poll is left outstanding. */
	fr_pump(friend);
	fr_pump(lpn);
	ATF_REQUIRE_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));

	/*
	 * Phase 2 (Section 3.11.4.2): "the node shall only transmit messages
	 * ... using the new keys".  THE GATE - both directions.
	 */
	im30_kr_phase_set(friend, 0, MESH_CFG_KR_TRANSITION_2);
	im30_kr_phase_set(lpn, 0, MESH_CFG_KR_TRANSITION_2);

	g_ncap = 0;
	im30_tick_until_tx(lpn, &t);
	ATF_REQUIRE_MSG(g_ncap >= 1, "the LPN must poll in Phase 2");
	ATF_CHECK_EQ_MSG(xnid, g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK,
	    "the LPN's Friend Poll must use the new-key friendship material");

	/*
	 * And the Friend's answer.  It must also still be able to DECRYPT the
	 * Poll it just received, which is the receive half of Section 3.11.4.2.
	 * fr_pump() consumes the captured Poll and leaves the Friend's answer
	 * in the capture buffer, so there is deliberately no g_ncap reset here.
	 */
	fr_pump(friend);
	ATF_REQUIRE_MSG(g_ncap >= 1,
	    "the Friend must accept a new-key Poll and answer it");
	ATF_CHECK_EQ_MSG(xnid, g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK,
	    "the Friend Update must use the new-key friendship material");

	/* The LPN accepts it, so the friendship survived the boundary. */
	fr_pump(lpn);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, friendship_config_and_features);
	ATF_TP_ADD_TC(tp, friendship_verbs);
	ATF_TP_ADD_TC(tp, friendship_relay_uses_flooding_credentials);
	ATF_TP_ADD_TC(tp, friendship_segment_ack_obo);
	ATF_TP_ADD_TC(tp, friendship_queue_stores_control_pdus);
	ATF_TP_ADD_TC(tp, friendship_lpn_update_kr_needs_new_key);
	ATF_TP_ADD_TC(tp, friendship_live_establish_and_deliver);
	ATF_TP_ADD_TC(tp, friendship_delivery_uses_enqueue_iv);
	ATF_TP_ADD_TC(tp, node_reset_stops_friendship_origination);
	ATF_TP_ADD_TC(tp, friendship_lpn_recovers_iv_from_update);
	ATF_TP_ADD_TC(tp, friendship_credentials_follow_phase2_key);

	return (atf_no_error());
}
