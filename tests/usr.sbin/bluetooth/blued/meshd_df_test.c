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

/* ================================================================
 * Fixtures (mirrors mesh_cfgclient_test.c setup()/exchange()).
 * ================================================================ */
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
	ATF_CHECK_EQ(1, dev->df.control.directed_forwarding);
	ATF_CHECK_EQ(1, dev->df.control.directed_relay);

	/* Directed Control Get reflects the stored state. */
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_get_build(0, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_DIRECTED_CONTROL_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_directed_control_status_parse(st, stlen,
	    &status, &got));
	ATF_CHECK_EQ(1, got.directed_forwarding);
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
	ATF_CHECK_EQ(MESH_DF_LIFETIME_24_HOUR, dev->df.metric.lifetime);
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
	ATF_CHECK_EQ(3, dev->df.lanes.wanted_lanes);

	/* Two Way Path. */
	memset(&tw, 0, sizeof(tw));
	tw.two_way_path = 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_set_build(&tw, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_CFG_OP_TWO_WAY_PATH_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_cfg_two_way_path_status_parse(st, stlen, &status,
	    &gtw));
	ATF_CHECK_EQ(1, gtw.two_way_path);
	ATF_CHECK_EQ(1, dev->df.two_way.two_way_path);

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
	ATF_CHECK_EQ(0x28, dev->df.echo.multicast_echo_interval);
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
 * Path Origin discovery FSM (df discover + node tick timeout).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_discovery_reply_establishes);
ATF_TC_BODY(df_discovery_reply_establishes, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_df_path_reply rep;
	uint8_t repbuf[64];
	size_t replen;
	char reply[128];
	char *av[3];

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* df discover 0x0005 -> Path Origin FSM enters REQUEST_SENT. */
	av[0] = (char *)(uintptr_t)"discover";
	av[1] = (char *)(uintptr_t)"0x0005";
	ATF_CHECK_EQ(0, meshd_df_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(1, client->df.disc_active);
	ATF_CHECK_EQ(MESH_DF_DISC_REQUEST_SENT, client->df.disc.state);

	/* A matching Path Reply (confirmation requested) drives -> ESTABLISHED. */
	memset(&rep, 0, sizeof(rep));
	rep.on_behalf_of_dependent_target = 0;
	rep.confirmation_request = 1;
	rep.forwarding_number = client->df.disc.forwarding_number;
	rep.path_origin = client->addr;
	rep.target.range_start = 0x0005;
	rep.target.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_reply_build(&rep, repbuf, &replen));
	/*
	 * The origin has no forwarding-table entry for its own reply, so the
	 * relay role drops it (MESH_DF_RECV_DROP); the discovery FSM still
	 * consumes it and advances to ESTABLISHED.
	 */
	(void)meshd_df_recv_control(client, 0x0005, client->addr, 5, 1,
	    MESH_DF_OP_PATH_REPLY, repbuf, replen, 10);
	ATF_CHECK_EQ(MESH_DF_DISC_ESTABLISHED, client->df.disc.state);
	ATF_CHECK_EQ(0, client->df.disc_active);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(df_discovery_tick_timeout);
ATF_TC_BODY(df_discovery_tick_timeout, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	int ivc;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	ATF_REQUIRE_EQ(0, meshd_df_discover_begin(client, 0x0005, 1000));
	ATF_CHECK_EQ(MESH_DF_DISC_REQUEST_SENT, client->df.disc.state);

	/* Before the 20 s budget: still REQUEST_SENT. */
	ATF_REQUIRE(meshd_node_tick(client, 1000 + 19999, &ivc) >= 0);
	ATF_CHECK_EQ(MESH_DF_DISC_REQUEST_SENT, client->df.disc.state);

	/* Past the budget: the tick fails the discovery. */
	ATF_REQUIRE(meshd_node_tick(client, 1000 + 20001, &ivc) >= 0);
	ATF_CHECK_EQ(MESH_DF_DISC_FAILED, client->df.disc.state);
	ATF_CHECK_EQ(0, client->df.disc_active);
	free(client->mgr);
}

/* ================================================================
 * Relay/target role: a Path Request installs a reverse forwarding entry.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(df_relay_installs_reverse_path);
ATF_TC_BODY(df_relay_installs_reverse_path, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_df_path_request req;
	uint8_t reqbuf[64];
	size_t reqlen;
	int rc;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Build a Path Request 0x0007 -> 0x0009 and relay it through dev. */
	memset(&req, 0, sizeof(req));
	req.forwarding_number = mesh_df_fn_next(0x40);
	req.metric_type = MESH_DF_METRIC_NODE_COUNT;
	req.lifetime = MESH_DF_LIFETIME_2_HOUR;
	req.path_metric = 0;
	req.destination = 0x0009;
	req.origin.range_start = 0x0007;
	req.origin.range_length = 1;
	ATF_REQUIRE_EQ(0, mesh_df_path_request_build(&req, reqbuf, &reqlen));

	rc = meshd_df_recv_control(dev, 0x0007, MESH_DF_ADDR_ALL_DIRECTED, 5, 1,
	    MESH_DF_OP_PATH_REQUEST, reqbuf, reqlen, 100);
	ATF_CHECK_EQ(MESH_DF_RECV_FORWARD, rc);
	/* The relay recorded a forwarding-table entry toward the origin. */
	ATF_CHECK(dev->df.node.table.count >= 1);
	free(client->mgr);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, df_directed_control_e2e);
	ATF_TP_ADD_TC(tp, df_path_metric_e2e);
	ATF_TP_ADD_TC(tp, df_lanes_two_way_echo_e2e);
	ATF_TP_ADD_TC(tp, df_transmit_e2e);
	ATF_TP_ADD_TC(tp, df_verb_dispatch);
	ATF_TP_ADD_TC(tp, df_discovery_reply_establishes);
	ATF_TP_ADD_TC(tp, df_discovery_tick_timeout);
	ATF_TP_ADD_TC(tp, df_relay_installs_reverse_path);

	return (atf_no_error());
}
