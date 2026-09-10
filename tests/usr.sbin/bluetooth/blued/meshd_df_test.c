/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd Directed Forwarding wiring (finding 129,
 * usr.sbin/bluetooth/meshd): the DF Configuration Server model registered on the
 * foundation dispatch table, the "df" Config-Client verbs, and the Path Origin
 * discovery FSM driven from the "df discover" verb + node tick.
 *
 * The DF Configuration Server is exercised end to end over the same DevKey path
 * as the Config Server (mesh_cfgclient_test.c): the client seals a
 * Directed-Forwarding Configuration message to the server node, the server node
 * runs meshd_foundation_recv (which dispatches the DF opcode to the registered
 * handler) and seals a Status, and the client correlates it.  All nodes are
 * heap-allocated (the structs are large).
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
#include "meshd_persist.h"
#include "mesh_transport.h"
#include "mesh_cfg_model.h"
#include "mesh_df.h"
#include "mesh_net.h"
#include "mesh_sim.h"
#include "spec_extref_mesh_net_credentials.h"

/* ================================================================
 * Fixtures (mirrors mesh_cfgclient_test.c setup()/exchange()).
 * ================================================================ */

/*
 * CONTRACT CHANGE (round-3 finding 9): the Directed Control / Path Metric /
 * Wanted Lanes / Two Way Path / Path Echo Interval sub-states are keyed by
 * NetKeyIndex and now live on the subnet entry (nd->db.netkeys[i].df) instead
 * of one node-wide struct that subnet 1 overwrote for subnet 0.  These helpers
 * reach the primary subnet's block, which is what the old nd->df named.
 */
static struct meshd_df_subnet *
node_df(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++)
		if (nd->db.netkeys[i].valid &&
		    nd->db.netkeys[i].net_idx == net_idx)
			return (&nd->db.netkeys[i].df);
	return (NULL);
}

static struct meshd_df_subnet *
dev_df(struct meshd_node *nd)
{

	return (node_df(nd, nd->netkey_index));
}

static void
setup(struct meshd_node *client, struct meshd_node *dev,
    struct meshd_config *ccfg, struct meshd_config *dcfg,
    struct mesh_mgr_node **out_node, uint16_t addr)
{
	uint8_t uuid[16], dk[16];

	meshd_config_defaults(ccfg);
	memset(ccfg->netkey, 0x11, 16);
	ccfg->have_netkey = 1;
	memset(ccfg->appkey, 0x22, 16);
	ccfg->have_appkey = 1;
	ccfg->netkey_index = 0;
	ccfg->appkey_index = 0;
	ccfg->unicast_addr = 0x0001;
	ccfg->iv_index = 0;
	ccfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(client, ccfg));

	client->mgr = calloc(1, sizeof(*client->mgr));
	ATF_REQUIRE(client->mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(client->mgr, NULL, NULL));
	client->mgr_active = 1;

	memset(uuid, 0xD0, sizeof(uuid));
	memset(dk, 0x55, sizeof(dk));
	*out_node = mesh_mgr_add_node(client->mgr, uuid, addr, 1, dk, 0);
	ATF_REQUIRE(*out_node != NULL);

	meshd_config_defaults(dcfg);
	memcpy(dcfg->netkey, client->mgr->netkey, 16);
	dcfg->have_netkey = 1;
	memset(dcfg->appkey, 0x77, 16);
	dcfg->have_appkey = 1;
	dcfg->netkey_index = 0;
	dcfg->appkey_index = 0;
	dcfg->unicast_addr = addr;
	dcfg->iv_index = 0;
	dcfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(dev, dcfg));
}

static void
exchange(struct meshd_node *client, struct meshd_node *dev,
    struct mesh_mgr_node *node, const uint8_t *req, size_t req_len,
    uint32_t expect_op, uint8_t *status, size_t *status_len)
{
	uint8_t upper[MESH_UPPER_MAX], plain[MESH_ACCESS_MAX];
	uint8_t reply[MESH_ACCESS_MAX], rupper[MESH_UPPER_MAX];
	size_t ulen, plen, rlen, rulen, stlen;
	const uint8_t *st;
	uint32_t seq;

	ATF_REQUIRE_EQ(0, meshd_cfg_client_send(client, node->addr, req, req_len,
	    expect_op, 0, upper, &ulen, &seq));
	plen = sizeof(plain);
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(client->mgr, node, seq,
	    client->mgr->self_addr, node->addr, upper, ulen, plain, &plen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(dev, plain, plen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(node->devkey, 0, 0, 0, node->addr,
	    client->mgr->self_addr, client->mgr->iv_index, NULL, reply, rlen,
	    rupper, &rulen));
	ATF_REQUIRE_EQ(1, meshd_cfg_client_rx(client, 0, node->addr,
	    client->mgr->self_addr, rupper, rulen));
	ATF_REQUIRE_EQ(MESH_MGR_TXN_COMPLETE,
	    meshd_cfg_client_status(client, &st, &stlen));
	ATF_REQUIRE(st != NULL);
	ATF_REQUIRE(stlen <= MESH_ACCESS_MAX);
	memcpy(status, st, stlen);
	*status_len = stlen;
}

/* ================================================================
 * DF Configuration Server model registration (end to end).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_directed_control_e2e);
ATF_TC_BODY(df_directed_control_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_directed_control set, got;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Directed Control Set: turn directed forwarding + relay on. */
	memset(&set, 0, sizeof(set));
	set.net_idx = 0;
	set.directed_forwarding = 1;
	set.directed_relay = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(1, got.directed_forwarding);
	ATF_CHECK_EQ(1, got.directed_relay);
	/* The server model stored the state. */
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_forwarding);
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_relay);

	/* Directed Control Get reflects the stored state. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_build(0, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(1, got.directed_forwarding);
	free(client->mgr);
}

/*
 * Round-2 fix: a Directed Control Set field of 0xFF means "Do Not Process"
 * (MshPRT_v1.1.1 §4.2.26 ff. - the
 * foundation-model states are in the Protocol specification in Mesh 1.1, not
 * the Model one) - the stored value is kept, 0xFF itself is never
 * stored, meshd_df_enable() is not re-run, and the Status echoes the
 * resulting stored state.  A Prohibited field value drops the message.
 */
ATF_TC_WITHOUT_HEAD(df_directed_control_set_do_not_process);
ATF_TC_BODY(df_directed_control_set_do_not_process, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_directed_control set, got;
	uint8_t req[32], st[MESH_ACCESS_MAX], reply[MESH_ACCESS_MAX];
	size_t req_len, stlen, rlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Establish a known stored state: forwarding + relay on. */
	memset(&set, 0, sizeof(set));
	set.net_idx = 0;
	set.directed_forwarding = 1;
	set.directed_relay = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);

	/*
	 * All-0xFF Set: every field is preserved and no 0xFF is stored.
	 * meshd_df_enable() must not run either: it would reset the sim
	 * node's df_fn, which we plant as a sentinel.
	 */
	dev->self->df_fn = 1;
	set.directed_forwarding = 0xFF;
	set.directed_relay = 0xFF;
	set.directed_proxy = 0xFF;
	set.directed_proxy_use_directed_default = 0xFF;
	set.directed_friend = 0xFF;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	/* The Status echoes the preserved stored state, not the request. */
	ATF_CHECK_EQ(1, got.directed_forwarding);
	ATF_CHECK_EQ(1, got.directed_relay);
	ATF_CHECK_EQ(0, got.directed_proxy);
	ATF_CHECK_EQ(0, got.directed_friend);
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_forwarding);
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_relay);
	ATF_CHECK_EQ(0, dev_df(dev)->control.directed_proxy);
	ATF_CHECK_EQ(1, dev->self->df_fn);	/* df_enable did not run */

	/*
	 * CONTRACT CHANGE (round-3 finding 8b): re-asserting an ALREADY
	 * enabled Directed Forwarding is a no-op re-assert.  It used to call
	 * mesh_sim_set_df() again, which re-ran mesh_df_table_init() and wiped
	 * every established forwarding path (and reset df_fn) on each repeated
	 * Directed Control Set.  The engine is now only (re)initialised on a
	 * genuine disabled->enabled transition, so the df_fn sentinel and the
	 * forwarding table survive.
	 */
	set.directed_forwarding = 1;
	set.directed_relay = 0xFF;
	set.directed_proxy = 0xFF;
	set.directed_proxy_use_directed_default = 0xFF;
	set.directed_friend = 0xFF;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_CHECK_EQ(1, dev->self->df_fn);	/* table preserved */
	ATF_CHECK_EQ(1, dev->self->df_enabled);
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_relay);	/* preserved */

	/* A Prohibited field value (0x02) drops the message: no reply. */
	set.directed_forwarding = 2;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	rlen = 0;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(dev, req, req_len, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_forwarding);	/* unchanged */

	/*
	 * Coupled fields (MshMDL Table 4.199): Use Directed Default must be
	 * 0xFF whenever Directed Proxy is 0xFF -- a value that depends on a
	 * state this Set is not processing is Prohibited, so the message is
	 * dropped with no reply and nothing stored.  (The Config Client's
	 * "df set" verb builds to this rule; the server enforces it.)
	 */
	set.directed_forwarding = 0xFF;
	set.directed_relay = 0xFF;
	set.directed_proxy = 0xFF;
	set.directed_friend = 0xFF;
	set.directed_proxy_use_directed_default = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	rlen = 0;
	ATF_CHECK_EQ(-1, meshd_foundation_recv(dev, req, req_len, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(0, rlen);
	ATF_CHECK_EQ(0,
	    dev_df(dev)->control.directed_proxy_use_directed_default);
	/* 0x00 is equally Prohibited here, for the same reason. */
	set.directed_proxy_use_directed_default = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	ATF_CHECK_EQ(-1, meshd_foundation_recv(dev, req, req_len, reply,
	    sizeof(reply), &rlen));
	/* Proxy explicitly set: Use Directed Default may then carry a value. */
	set.directed_proxy = 1;
	set.directed_proxy_use_directed_default = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	ATF_CHECK_EQ(1, meshd_foundation_recv(dev, req, req_len, reply,
	    sizeof(reply), &rlen));
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_proxy);
	ATF_CHECK_EQ(1,
	    dev_df(dev)->control.directed_proxy_use_directed_default);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(df_path_metric_e2e);
ATF_TC_BODY(df_path_metric_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_path_metric set, got;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	memset(&set, 0, sizeof(set));
	set.net_idx = 0;
	set.metric_type = MESH_DF_METRIC_NODE_COUNT;
	set.lifetime = MESH_DF_LIFETIME_24_HOUR;
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_set_build(&set, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_PATH_METRIC_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_status_parse(st, stlen, &status,
	    &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(MESH_DF_LIFETIME_24_HOUR, got.lifetime);
	ATF_CHECK_EQ(MESH_DF_LIFETIME_24_HOUR, dev_df(dev)->metric.lifetime);
	free(client->mgr);
}

/* ================================================================
 * Unknown subnet (bad NetKeyIndex): Directed Control Set and Path Metric Get
 * both answer INVALID_NETKEY_INDEX, store nothing, and echo the index
 * (MshMDL 4.4.3.2).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_unknown_netkey_index);
ATF_TC_BODY(df_unknown_netkey_index, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_directed_control set, got;
	struct mesh_cfg_path_metric mgot;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Directed Control Set on unknown NetKeyIndex 0x07F: refused. */
	memset(&set, 0, sizeof(set));
	set.net_idx = 0x07F;			/* no such subnet */
	set.directed_forwarding = 0;		/* would DISABLE if mis-stored */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, status);
	ATF_CHECK_EQ(0x07F, got.net_idx);
	/*
	 * Nothing was stored on the primary subnet.  CONTRACT CHANGE (round-3
	 * finding 8/9): the sub-states are per-subnet and a freshly provisioned
	 * node advertises Directed Forwarding ENABLED, matching the engine that
	 * meshd_df_rpr_init() actually starts (previously Get answered
	 * "Disabled" while the relay branch was running).  So the Set carries
	 * Disable here: mis-storing it would flip the primary subnet off.
	 */
	ATF_CHECK_EQ(1, dev_df(dev)->control.directed_forwarding);
	ATF_CHECK_EQ(1, dev->self->df_enabled);

	/* Path Metric Get on the same unknown index: refused, zeroed state. */
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_get_build(0x07F, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_PATH_METRIC_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_status_parse(st, stlen, &status,
	    &mgot));
	ATF_CHECK_EQ(MESH_CFG_INVALID_NETKEY_INDEX, status);
	ATF_CHECK_EQ(0x07F, mgot.net_idx);
	ATF_CHECK_EQ(0, mgot.lifetime);

	/* Path Metric Get on the KNOWN primary subnet answers Success. */
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_get_build(0x000, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_PATH_METRIC_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_status_parse(st, stlen, &status,
	    &mgot));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0x000, mgot.net_idx);
	ATF_CHECK_EQ(dev_df(dev)->metric.lifetime, mgot.lifetime);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(df_lanes_two_way_echo_e2e);
ATF_TC_BODY(df_lanes_two_way_echo_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_wanted_lanes wl, glane;
	struct mesh_cfg_two_way_path tw, gtw;
	struct mesh_cfg_path_echo_interval pe, gpe;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Wanted Lanes. */
	memset(&wl, 0, sizeof(wl));
	wl.wanted_lanes = 3;
	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_set_build(&wl, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_WANTED_LANES_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_wanted_lanes_status_parse(st, stlen, &status,
	    &glane));
	ATF_CHECK_EQ(3, glane.wanted_lanes);
	ATF_CHECK_EQ(3, dev_df(dev)->lanes.wanted_lanes);

	/* Two Way Path. */
	memset(&tw, 0, sizeof(tw));
	tw.two_way_path = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_set_build(&tw, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_TWO_WAY_PATH_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_status_parse(st, stlen, &status,
	    &gtw));
	ATF_CHECK_EQ(1, gtw.two_way_path);
	ATF_CHECK_EQ(1, dev_df(dev)->two_way.two_way_path);

	/* Path Echo Interval. */
	memset(&pe, 0, sizeof(pe));
	pe.unicast_echo_interval = 0x14;
	pe.multicast_echo_interval = 0x28;
	ATF_REQUIRE_EQ(0, mesh_cfg_path_echo_interval_set_build(&pe, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_path_echo_interval_status_parse(st, stlen,
	    &status, &gpe));
	ATF_CHECK_EQ(0x14, gpe.unicast_echo_interval);
	ATF_CHECK_EQ(0x28, dev_df(dev)->echo.multicast_echo_interval);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(df_transmit_e2e);
ATF_TC_BODY(df_transmit_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_transmit set, got;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint32_t op;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	memset(&set, 0, sizeof(set));
	set.count = 2;
	set.interval_steps = 5;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_build(
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET, &set, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_transmit_parse(st, stlen, &op, &got));
	ATF_CHECK_EQ(MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS, op);
	ATF_CHECK_EQ(2, got.count);
	ATF_CHECK_EQ(5, got.interval_steps);
	ATF_CHECK_EQ(2, dev->df.net_transmit.count);
	free(client->mgr);
}

/* ================================================================
 * The "df" verb dispatcher.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_verb_dispatch);
ATF_TC_BODY(df_verb_dispatch, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	char reply[256];
	char *av[8];

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* get 0x0002 -> a well-formed Directed Control Get is sent (WAITING). */
	av[0] = (char *)(uintptr_t)"get";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(0, meshd_df_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK df get", 9));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING,
	    meshd_cfg_client_status(client, NULL, NULL));

	/* set 0x0002 on -> Directed Control Set path builds and sends. */
	av[0] = (char *)(uintptr_t)"set";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)"on";
	ATF_CHECK_EQ(0, meshd_df_client_verb(client, 3, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK df set", 9));

	/*
	 * "set" targets only forwarding/relay: the other three state fields
	 * must carry 0xFF "Do Not Process" (MshPRT Table 4.199) on the wire,
	 * not 0x00 (which would Disable them).
	 */
	{
		struct mesh_cfg_directed_control dc;

		ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_parse(
		    client->cfg_txn.req, client->cfg_txn.req_len, &dc));
		ATF_CHECK_EQ(1, dc.directed_forwarding);
		ATF_CHECK_EQ(1, dc.directed_relay);
		ATF_CHECK_EQ(0xFF, dc.directed_proxy);
		ATF_CHECK_EQ(0xFF, dc.directed_proxy_use_directed_default);
		ATF_CHECK_EQ(0xFF, dc.directed_friend);
	}

	/* control-set accepts 0, 1 and 0xFF per state field... */
	av[0] = (char *)(uintptr_t)"control-set";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)"0";
	av[3] = (char *)(uintptr_t)"1";
	av[4] = (char *)(uintptr_t)"0";
	av[5] = (char *)(uintptr_t)"0xFF";
	av[6] = (char *)(uintptr_t)"0xFF";
	av[7] = (char *)(uintptr_t)"0xFF";
	ATF_CHECK_EQ(0, meshd_df_client_verb(client, 8, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK df control-set", 17));
	/* ... and rejects the Prohibited 0x02-0xFE range. */
	av[5] = (char *)(uintptr_t)"2";
	ATF_CHECK_EQ(-1, meshd_df_client_verb(client, 8, av, 0, reply,
	    sizeof(reply)));

	/* metric-set 0x0002 0 2 -> builds and sends. */
	av[0] = (char *)(uintptr_t)"metric-set";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)"0";
	av[3] = (char *)(uintptr_t)"2";
	ATF_CHECK_EQ(0, meshd_df_client_verb(client, 4, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK df metric-set", 16));

	/* Unknown verb. */
	av[0] = (char *)(uintptr_t)"bogus";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(-1, meshd_df_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));

	/* Unknown destination node. */
	av[0] = (char *)(uintptr_t)"get";
	av[1] = (char *)(uintptr_t)"0x0099";
	ATF_CHECK_EQ(-1, meshd_df_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	free(client->mgr);
}

/* ================================================================
 * Live Directed Forwarding over the bearer (two nodes sharing a subnet).
 *
 * Each node's tx is captured; a captured Network PDU is shuttled to the peer
 * via meshd_bearer_rx, whose mesh_sim_step decrypts it, runs the sim's DF
 * relay/target/origin dispatch, and re-emits any Path Reply/Confirmation to the
 * capture buffer.  This exercises the real encrypt -> bearer -> decrypt ->
 * forward path, not a standalone FSM.
 * ================================================================ */
#define	DF_MAXCAP	32
static struct df_capframe {
	uint8_t			buf[64];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_cap[DF_MAXCAP];
static size_t g_ncap;

static int
df_cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	if (g_ncap < DF_MAXCAP && len <= sizeof(g_cap[0].buf)) {
		memcpy(g_cap[g_ncap].buf, pdu, len);
		g_cap[g_ncap].len = len;
		g_cap[g_ncap].cls = cls;
		g_ncap++;
	}
	return (0);
}

/* Deliver every currently-captured Network PDU to node `to`. */
static void
df_pump(struct meshd_node *to)
{
	struct df_capframe snap[DF_MAXCAP];
	size_t n, i;

	n = g_ncap;
	memcpy(snap, g_cap, n * sizeof(snap[0]));
	g_ncap = 0;
	for (i = 0; i < n; i++)
		if (snap[i].cls == MESHD_PDU_NET)
			(void)meshd_bearer_rx(to, snap[i].buf, snap[i].len);
}

/* Provision a node into a fixed shared subnet at addr. */
static void
df_provision(struct meshd_node *nd, struct meshd_config *cfg, uint16_t addr)
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
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
}

/*
 * As df_provision(), but on the NetKey of the specification's own sample data
 * (MshPRT_v1.1.1 Section 8.2), so the derived security material can be checked
 * against the published numbers rather than against our own arithmetic.
 */
static void
df_provision_sample_key(struct meshd_node *nd, struct meshd_config *cfg,
    uint16_t addr)
{
	static const uint8_t netkey[16] = SPEC_EXTREF_MESH_S82_NETKEY;

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, netkey, 16);
	cfg->have_netkey = 1;
	memset(cfg->appkey, 0x44, 16);
	cfg->have_appkey = 1;
	cfg->netkey_index = 0;
	cfg->appkey_index = 0;
	cfg->unicast_addr = addr;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, cfg));
}

/*
 * ================================================================
 * Finding 18: the directed security material, k2(NetKey, 0x02).
 *
 * MshPRT_v1.1.1 Section 3.9.6.3.1, .txt lines 10265-10269, verbatim:
 *   "The directed security material is derived from the directed security
 *    credentials using the following formula:
 *    NID || EncryptionKey || PrivacyKey=k2(NetKey, 0x02)
 *    For Network PDUs that are transmitted according to directed forwarding
 *    functionality, the directed security material is used."
 *
 * No reference implementation has directed forwarding, so the specification is
 * the sole oracle here.  Section 8.2 publishes the numbers, which is as close
 * to an external cross-check as this feature can get: the SAME NetKey yields
 * the flooding material of Section 8.2.2 and the directed material of Section
 * 8.2.4, with two DIFFERENT NIDs.  Provisioning the daemon on that NetKey and
 * reading back both credentials is therefore a numeric check, not a tautology.
 * ================================================================
 */
ATF_TC_WITHOUT_HEAD(df_directed_material_matches_sample_data);
ATF_TC_BODY(df_directed_material_matches_sample_data, tc)
{
	static const uint8_t f_enc[16] = SPEC_EXTREF_MESH_S822_FLOODING_ENCKEY;
	static const uint8_t f_priv[16] = SPEC_EXTREF_MESH_S822_FLOODING_PRIVKEY;
	static const uint8_t d_enc[16] = SPEC_EXTREF_MESH_S824_DIRECTED_ENCKEY;
	static const uint8_t d_priv[16] = SPEC_EXTREF_MESH_S824_DIRECTED_PRIVKEY;
	MESH_HEAP(struct meshd_node, a);
	struct meshd_config acfg;

	(void)tc;
	df_provision_sample_key(a, &acfg, 0x0001);

	/* Section 8.2.2: the managed flooding material was already right. */
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_S822_FLOODING_NID, a->self->nid,
	    "Section 8.2.2 flooding NID");
	ATF_CHECK_EQ(0, memcmp(a->self->enckey, f_enc, 16));
	ATF_CHECK_EQ(0, memcmp(a->self->privkey, f_priv, 16));

	/*
	 * Section 8.2.4: the directed material.  Before this fix the three
	 * fields did not exist and nothing anywhere in the tree fed 0x02 to
	 * k2(), so a directed forwarding node announced the flooding NID
	 * 0x68 where a conformant peer expects 0x0d.
	 */
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_S824_DIRECTED_NID,
	    a->self->directed_nid, "Section 8.2.4 directed NID");
	ATF_CHECK_EQ(0, memcmp(a->self->directed_enckey, d_enc, 16));
	ATF_CHECK_EQ(0, memcmp(a->self->directed_privkey, d_priv, 16));

	/* The two families must not collide, which is why the NID identifies. */
	ATF_CHECK(a->self->directed_nid != a->self->nid);
	ATF_CHECK(memcmp(a->self->directed_enckey, a->self->enckey, 16) != 0);
	ATF_CHECK(memcmp(a->self->directed_privkey, a->self->privkey, 16) != 0);
}

ATF_TC_WITHOUT_HEAD(df_discover_live_establishes);
ATF_TC_BODY(df_discover_live_establishes, tc)
{
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_config acfg, bcfg;
	struct meshd_bearer abear = { .tx = df_cap_tx };
	struct meshd_bearer bbear = { .tx = df_cap_tx };
	char reply[128];
	char *av[2];

	df_provision(a, &acfg, 0x0001);
	df_provision(b, &bcfg, 0x0005);
	meshd_set_bearer(a, &abear);
	meshd_set_bearer(b, &bbear);
	/* DF is enabled on both at setup. */
	ATF_REQUIRE(a->self->df_enabled);
	ATF_REQUIRE(b->self->df_enabled);

	/* Origin A discovers target B: the Path Request is emitted to the bearer. */
	g_ncap = 0;
	av[0] = (char *)(uintptr_t)"discover";
	av[1] = (char *)(uintptr_t)"0x0005";
	ATF_CHECK_EQ(0, meshd_df_client_verb(a, 2, av, 0, reply, sizeof(reply)));
	ATF_CHECK_EQ(MESH_DF_DISC_REQUEST_SENT, a->self->df_disc.state);
	ATF_REQUIRE(g_ncap >= 1);
	ATF_CHECK_EQ(MESHD_PDU_NET, g_cap[0].cls);

	/* Request -> B: B is the target, installs a reverse path and replies. */
	df_pump(b);
	ATF_CHECK(b->self->df_table.count >= 1);
	ATF_REQUIRE(g_ncap >= 1);		/* B emitted a Path Reply */

	/* Reply -> A: A confirms and the path is established. */
	df_pump(a);
	ATF_CHECK_EQ(MESH_DF_DISC_ESTABLISHED, a->self->df_disc.state);
	ATF_CHECK(a->self->df_table.count >= 1);

	/* Confirmation -> B: B installs the forward path. */
	df_pump(b);
	ATF_CHECK(b->self->df_table.count >= 1);
}

ATF_TC_WITHOUT_HEAD(df_discover_requires_bearer);
ATF_TC_BODY(df_discover_requires_bearer, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_config acfg;

	df_provision(a, &acfg, 0x0001);
	/* No bearer attached: origination cannot transmit. */
	ATF_CHECK_EQ(-1, meshd_df_discover_begin(a, 0x0005, 0));
	ATF_CHECK(a->self->df_disc.state != MESH_DF_DISC_REQUEST_SENT);
}

ATF_TC_WITHOUT_HEAD(df_discover_tick_timeout);
ATF_TC_BODY(df_discover_tick_timeout, tc)
{
	MESH_HEAP(struct meshd_node, a);
	struct meshd_config acfg;
	struct meshd_bearer abear = { .tx = df_cap_tx };
	int ivc;

	df_provision(a, &acfg, 0x0001);
	meshd_set_bearer(a, &abear);

	g_ncap = 0;
	ATF_REQUIRE_EQ(0, meshd_df_discover_begin(a, 0x0005, 1000));
	ATF_CHECK_EQ(MESH_DF_DISC_REQUEST_SENT, a->self->df_disc.state);

	/* No reply arrives; past the 30 s budget the node tick fails discovery. */
	ATF_REQUIRE(meshd_node_tick(a, 1000 + 30001, &ivc) >= 0);
	ATF_CHECK_EQ(MESH_DF_DISC_FAILED, a->self->df_disc.state);
}

/* ================================================================
 * Round-3 finding 8: an explicit Directed Forwarding DISABLE must actually
 * stop the engine and flush the forwarding table (there was no disable path at
 * all: the state stored 0 and Get reported Disabled while self->df_enabled
 * stayed 1 and the relay branch kept running), and mesh_sim_set_df() must stop
 * hard-setting directed relay/proxy/friend to 1 over the merged per-field
 * values.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_disable_stops_forwarding);
ATF_TC_BODY(df_disable_stops_forwarding, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_directed_control set, got;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	(void)tc;
	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);
	ATF_REQUIRE_EQ(1, dev->self->df_enabled);

	/* Enable forwarding + relay only: proxy and friend are Disabled. */
	memset(&set, 0, sizeof(set));
	set.net_idx = 0;
	set.directed_forwarding = 1;
	set.directed_relay = 1;
	set.directed_proxy = 0;
	set.directed_proxy_use_directed_default = 0;
	set.directed_friend = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_CHECK_EQ(1, dev->self->df_enabled);
	/*
	 * The merged per-field values reach the engine: mesh_sim_set_df() used
	 * to hard-set all three to 1 whatever the Set carried.
	 */
	ATF_CHECK_EQ(1, dev->self->df_feat.directed_relay);
	ATF_CHECK_EQ_MSG(0, dev->self->df_feat.directed_proxy,
	    "a Disabled directed proxy is not silently enabled");
	ATF_CHECK_EQ(0, dev->self->df_feat.directed_friend);

	/* Plant a forwarding-table entry and a sentinel. */
	dev->self->df_table.count = 1;
	dev->self->df_fn = 5;

	/* An explicit Disable really stops the engine and flushes the table. */
	set.directed_forwarding = 0;
	set.directed_relay = 0xFF;
	set.directed_proxy = 0xFF;
	set.directed_proxy_use_directed_default = 0xFF;
	set.directed_friend = 0xFF;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0, got.directed_forwarding);
	ATF_CHECK_EQ_MSG(0, dev->self->df_enabled,
	    "Get reporting Disabled now matches a stopped engine");
	ATF_CHECK_EQ(0, dev->df.enabled);
	ATF_CHECK_EQ_MSG(0u, (unsigned)dev->self->df_table.count,
	    "the forwarding table is flushed on disable");
	ATF_CHECK_EQ(0, dev->self->df_feat.directed_relay);

	/* Re-enabling starts a fresh engine. */
	set.directed_forwarding = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_CHECK_EQ(1, dev->self->df_enabled);
	free(client->mgr);
}

/*
 * Round-3 finding 9: the DF Configuration Server sub-states are per-subnet
 * states keyed by NetKeyIndex.  Configuring subnet 1 used to overwrite subnet
 * 0's single node-wide copy, so Get answered with the wrong subnet's values.
 */
ATF_TC_WITHOUT_HEAD(df_states_are_per_subnet);
ATF_TC_BODY(df_states_are_per_subnet, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_directed_control set, got;
	struct mesh_cfg_path_metric mset;
	struct mesh_cfg_netkey nk;
	uint8_t req[64], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	(void)tc;
	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Add a second subnet (NetKeyIndex 1). */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x001;
	memset(nk.key, 0x5c, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD,
	    &nk, req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_CFG_OP_NETKEY_STATUS,
	    st, &stlen);
	ATF_REQUIRE(node_df(dev, 0x001) != NULL);

	/* Subnet 0: forwarding on, relay on.  Subnet 1: everything off. */
	memset(&set, 0, sizeof(set));
	set.net_idx = 0x000;
	set.directed_forwarding = 1;
	set.directed_relay = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);

	set.net_idx = 0x001;
	set.directed_forwarding = 0;
	set.directed_relay = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);

	/* Subnet 0 is untouched by the subnet-1 Set. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_build(0x000, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0x000, got.net_idx);
	ATF_CHECK_EQ_MSG(1, got.directed_forwarding,
	    "configuring subnet 1 must not overwrite subnet 0");
	ATF_CHECK_EQ(1, got.directed_relay);

	/* Subnet 1 answers with its OWN values. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_build(0x001, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(MESH_CFG_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(0x001, got.net_idx);
	ATF_CHECK_EQ(0, got.directed_forwarding);
	ATF_CHECK_EQ(0, got.directed_relay);

	/* The engine stays on while ANY subnet has DF enabled. */
	ATF_CHECK_EQ(1, dev->self->df_enabled);

	/* Path Metric is per-subnet too. */
	memset(&mset, 0, sizeof(mset));
	mset.net_idx = 0x001;
	mset.metric_type = MESH_DF_METRIC_NODE_COUNT;
	mset.lifetime = MESH_DF_LIFETIME_24_HOUR;
	ATF_REQUIRE_EQ(0, mesh_cfg_path_metric_set_build(&mset, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_PATH_METRIC_STATUS, st, &stlen);
	ATF_CHECK_EQ(MESH_DF_LIFETIME_24_HOUR,
	    node_df(dev, 0x001)->metric.lifetime);
	ATF_CHECK_EQ_MSG(MESH_DF_LIFETIME_2_HOUR,
	    node_df(dev, 0x000)->metric.lifetime,
	    "subnet 0 keeps its own Path Metric");

	/* Disabling DF on the last enabled subnet stops the engine. */
	set.net_idx = 0x000;
	set.directed_forwarding = 0;
	set.directed_relay = 0;
	set.directed_proxy = 0;
	set.directed_proxy_use_directed_default = 0;
	set.directed_friend = 0;
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_set_build(&set, req,
	    &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_CHECK_EQ(0, dev->self->df_enabled);
	free(client->mgr);
}

/*
 * The path-discovery control messages go out under the DIRECTED material.
 *
 * MshPRT_v1.1.1 Sections 3.6.8.2.1 (PATH_REQUEST) and 3.6.8.2.3 (PATH_REPLY)
 * carry the same sentence, .txt lines 7373-7374 and 7593-7594, verbatim:
 *   "shall send the message using the directed security credentials of the
 *    subnet over which the message is sent and shall tag the message with the
 *    immutable-credentials tag."
 *
 * Driven through the daemon: "df discover" is the operator verb, and
 * meshd_bearer_rx() is the peer's receive entry point.  The assertions are on
 * the bytes that left the bearer, checked against the Section 8.2 sample
 * material - so this fails both if the wrong credential is selected and if the
 * receiving node cannot authenticate a directed-secured PDU at all.
 */
ATF_TC_WITHOUT_HEAD(df_path_discovery_uses_directed_credentials);
ATF_TC_BODY(df_path_discovery_uses_directed_credentials, tc)
{
	static const uint8_t f_enc[16] = SPEC_EXTREF_MESH_S822_FLOODING_ENCKEY;
	static const uint8_t f_priv[16] = SPEC_EXTREF_MESH_S822_FLOODING_PRIVKEY;
	static const uint8_t d_enc[16] = SPEC_EXTREF_MESH_S824_DIRECTED_ENCKEY;
	static const uint8_t d_priv[16] = SPEC_EXTREF_MESH_S824_DIRECTED_PRIVKEY;
	MESH_HEAP(struct meshd_node, a);
	MESH_HEAP(struct meshd_node, b);
	struct meshd_config acfg, bcfg;
	struct meshd_bearer abear = { .tx = df_cap_tx };
	struct meshd_bearer bbear = { .tx = df_cap_tx };
	struct mesh_net_pdu np;
	char reply[128];
	char *av[2];

	(void)tc;
	df_provision_sample_key(a, &acfg, 0x0001);
	df_provision_sample_key(b, &bcfg, 0x0005);
	meshd_set_bearer(a, &abear);
	meshd_set_bearer(b, &bbear);
	ATF_REQUIRE(a->self->df_enabled);
	ATF_REQUIRE(b->self->df_enabled);

	/* Origin A discovers target B. */
	g_ncap = 0;
	av[0] = (char *)(uintptr_t)"discover";
	av[1] = (char *)(uintptr_t)"0x0005";
	ATF_REQUIRE_EQ(0, meshd_df_client_verb(a, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_REQUIRE(g_ncap >= 1);
	ATF_REQUIRE_EQ(MESHD_PDU_NET, g_cap[0].cls);

	/*
	 * The IVI/NID octet on the wire.  Section 3.9.6.3.1: "The NID is a
	 * 7-bit value that identifies the security material that is used to
	 * secure this Network PDU."  Section 8.2.4 says that value is 0x0d for
	 * this NetKey; Section 8.2.2 says the flooding value is 0x68.
	 */
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_S824_DIRECTED_NID,
	    g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK,
	    "PATH_REQUEST must announce the directed NID");
	ATF_CHECK_MSG((g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK) !=
	    SPEC_EXTREF_MESH_S822_FLOODING_NID,
	    "PATH_REQUEST must not announce the flooding NID");

	/* It authenticates under the directed material and only under it. */
	ATF_CHECK_EQ_MSG(0, mesh_net_decrypt(d_enc, d_priv,
	    SPEC_EXTREF_MESH_S824_DIRECTED_NID, 0, g_cap[0].buf,
	    g_cap[0].len, &np),
	    "PATH_REQUEST must decrypt under the Section 8.2.4 material");
	/* And it really is the PATH_REQUEST to all-directed-forwarding-nodes. */
	ATF_CHECK_EQ(1, np.ctl);
	ATF_CHECK_EQ(SPEC_EXTREF_MESH_FIXED_GROUP_ALL_DF_NODES, np.dst);
	ATF_CHECK_EQ(MESH_DF_OP_PATH_REQUEST, np.transport[0] & 0x7f);
	/* mesh_net_decrypt() zeroes *out on failure, so this goes last. */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(f_enc, f_priv,
	    SPEC_EXTREF_MESH_S822_FLOODING_NID, 0, g_cap[0].buf,
	    g_cap[0].len, &np),
	    "PATH_REQUEST must not decrypt under the flooding material");

	/*
	 * B receives it - which it can only do by holding the directed
	 * credential as a receive candidate - and answers.  Its PATH_REPLY is
	 * directed too (Section 3.6.8.2.3).
	 */
	df_pump(b);
	ATF_REQUIRE_MSG(g_ncap >= 1, "target must answer the PATH_REQUEST");
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_S824_DIRECTED_NID,
	    g_cap[0].buf[0] & SPEC_EXTREF_MESH_NID_MASK,
	    "PATH_REPLY must announce the directed NID");
	ATF_CHECK_EQ_MSG(0, mesh_net_decrypt(d_enc, d_priv,
	    SPEC_EXTREF_MESH_S824_DIRECTED_NID, 0, g_cap[0].buf,
	    g_cap[0].len, &np),
	    "PATH_REPLY must decrypt under the Section 8.2.4 material");
	ATF_CHECK_EQ(MESH_DF_OP_PATH_REPLY, np.transport[0] & 0x7f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, df_directed_control_e2e);
	ATF_TP_ADD_TC(tp, df_directed_control_set_do_not_process);
	ATF_TP_ADD_TC(tp, df_path_metric_e2e);
	ATF_TP_ADD_TC(tp, df_unknown_netkey_index);
	ATF_TP_ADD_TC(tp, df_disable_stops_forwarding);
	ATF_TP_ADD_TC(tp, df_states_are_per_subnet);
	ATF_TP_ADD_TC(tp, df_lanes_two_way_echo_e2e);
	ATF_TP_ADD_TC(tp, df_transmit_e2e);
	ATF_TP_ADD_TC(tp, df_verb_dispatch);
	ATF_TP_ADD_TC(tp, df_discover_live_establishes);
	ATF_TP_ADD_TC(tp, df_discover_requires_bearer);
	ATF_TP_ADD_TC(tp, df_discover_tick_timeout);
	ATF_TP_ADD_TC(tp, df_directed_material_matches_sample_data);
	ATF_TP_ADD_TC(tp, df_path_discovery_uses_directed_credentials);

	return (atf_no_error());
}
