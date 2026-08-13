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
#include "mesh_sim.h"

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

	/* Poll -> Friend: establishes the friendship, answers with a Friend
	 * Update (empty queue); Update -> LPN establishes the friendship. */
	fr_pump(friend);
	ATF_CHECK_EQ(MESH_FRIEND_ST_ESTABLISHED, friend->friend_fsm.state);
	ATF_REQUIRE(g_ncap >= 1);		/* Friend emitted an Update */
	fr_pump(lpn);
	ATF_CHECK_EQ(1, mesh_lpn_fsm_established(&lpn->lpn_fsm));

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, friendship_config_and_features);
	ATF_TP_ADD_TC(tp, friendship_verbs);
	ATF_TP_ADD_TC(tp, friendship_live_establish_and_deliver);

	return (atf_no_error());
}
