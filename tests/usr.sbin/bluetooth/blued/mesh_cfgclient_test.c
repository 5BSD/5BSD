/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd Config Client operability layer
 * (usr.sbin/bluetooth/meshd/meshd_cfgclient.c).
 *
 * meshd manages the network it created by sending acknowledged Configuration
 * messages to a provisioned node's primary element, sealed under that node's
 * DevKey, and correlating the returned Config *Status*.  These tests drive the
 * whole path end to end:
 *
 *     Config Client PDU builder -> meshd_cfg_client_send (seal + txn register)
 *         -> [node] mesh_mgr_devkey_open -> meshd_foundation_recv (Config
 *         Server) -> seal Status -> meshd_cfg_client_rx (txn complete) -> parse.
 *
 * The daemon transmit lands on a NULL bearer (dropped) in the test; the sealed
 * request is captured via the send out-parameters and shuttled to the server
 * node directly, mirroring cfg_exchange() in mesh_manager_test.c.  Also covers
 * the "cfg" verb dispatcher, manager-DB persistence and the OTA provisioning
 * verb guards.
 *
 * The libmesh / meshd structs are large, so every node / manager is
 * heap-allocated via MESH_HEAP - never on the test stack.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"

int ptap_meshd_cfg_result(struct meshd_node *, const char *, uint16_t,
    const uint8_t *, size_t, char *, size_t);
#include "meshd_persist.h"
#include "mesh_transport.h"
#include "mesh_cfg_model.h"
#include "spec_mesh_cfgclient_oracles.h"

/* ================================================================
 * Fixtures.
 * ================================================================ */

/*
 * Stand up a Config Client (a meshd node that has created a network) and a
 * Config Server node recorded in its roster at addr with a shared DevKey.  The
 * client's manager is heap-allocated and marked active; *out_node is the roster
 * entry the Config Client addresses.
 */
static void
setup(struct meshd_node *client, struct meshd_node *dev,
    struct meshd_config *ccfg, struct meshd_config *dcfg,
    struct mesh_mgr_node **out_node, uint16_t addr)
{
	uint8_t uuid[16], dk[16];

	/* The Config Client node is the Provisioner at unicast 0x0001. */
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

	/* Create the network: mints keys, sets self 0x0001, starts the roster. */
	client->mgr = calloc(1, sizeof(*client->mgr));
	ATF_REQUIRE(client->mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(client->mgr, NULL, NULL));
	client->mgr_active = 1;

	/* Record the Config Server node with a shared DevKey. */
	memset(uuid, 0xD0, sizeof(uuid));
	memset(dk, 0x55, sizeof(dk));
	*out_node = mesh_mgr_add_node(client->mgr, uuid, addr, 1, dk, 0);
	ATF_REQUIRE(*out_node != NULL);

	/* The server node runs the Configuration Server (meshd_foundation_recv). */
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

/*
 * Run one Config Client transaction end to end: send the request from the
 * client, have the server node process it and seal a Status, feed the Status
 * back to the client and require the transaction to complete.  Copies the
 * recovered Status Access PDU into status/status_len.
 */
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

	/* Node side: open under the DevKey, process, seal the Status reply. */
	plen = sizeof(plain);
	ATF_REQUIRE_EQ(0, mesh_mgr_devkey_open(client->mgr, node, seq,
	    client->mgr->self_addr, node->addr, upper, ulen, plain, &plen));
	ATF_REQUIRE_EQ(1, meshd_foundation_recv(dev, plain, plen, reply,
	    sizeof(reply), &rlen));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(node->devkey, 0, 0, 0, node->addr,
	    client->mgr->self_addr, client->mgr->iv_index, NULL, reply, rlen,
	    rupper, &rulen));

	/* Client side: correlate the Status and complete the transaction. */
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
 * End-to-end: request -> Config Server -> Status success.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(appkey_add_e2e);
ATF_TC_BODY(appkey_add_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	uint8_t req[64], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;
	uint16_t netidx, appidx;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(client->mgr, req,
	    &req_len));
	exchange(client, dev, node, req, req_len, BT_MESH_CFG_OP_APPKEY_STATUS, st,
	    &stlen);
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfg_appkey_status_zero), stlen);
	ATF_CHECK_EQ(0, memcmp(st, bt_mesh_cfg_appkey_status_zero, stlen));

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_status_parse(st, stlen, &status,
	    &netidx, &appidx));
	ATF_CHECK_EQ(BT_MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0u, appidx);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(model_bind_e2e);
ATF_TC_BODY(model_bind_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_cfg_model_id model;
	struct mesh_cfg_model_app app;
	uint8_t req[64], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t status;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* The AppKey must be added before it can be bound. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_appkey_add_pdu(client->mgr, req,
	    &req_len));
	exchange(client, dev, node, req, req_len, BT_MESH_CFG_OP_APPKEY_STATUS, st,
	    &stlen);

	/* Bind the AppKey to the Generic OnOff Server (SIG model 0x1000). */
	memset(&model, 0, sizeof(model));
	model.model_id = BT_MESH_MODEL_GENERIC_ONOFF_SERVER;
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_bind_pdu(client->mgr, 0x0002,
	    &model, req, &req_len));
	exchange(client, dev, node, req, req_len, BT_MESH_CFG_OP_MODEL_APP_STATUS,
	    st, &stlen);
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfg_model_app_status_onoff), stlen);
	ATF_CHECK_EQ(0, memcmp(st, bt_mesh_cfg_model_app_status_onoff, stlen));

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_model_app_status_parse(st, stlen, &status,
	    &app));
	ATF_CHECK_EQ(BT_MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(0x0002, app.elem_addr);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(node_reset_e2e);
ATF_TC_BODY(node_reset_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	uint8_t req[64], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_reset_pdu(client->mgr, req,
	    &req_len));
	exchange(client, dev, node, req, req_len, BT_MESH_CFG_OP_NODE_RESET_STATUS,
	    st, &stlen);
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfg_node_reset_status), stlen);
	ATF_CHECK_EQ(0, memcmp(st, bt_mesh_cfg_node_reset_status, stlen));
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_node_reset_status_parse(st, stlen));
	free(client->mgr);
}

/* ================================================================
 * The "cfg" verb dispatcher.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cfg_verb_dispatch);
ATF_TC_BODY(cfg_verb_dispatch, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	char reply[256];
	char *av[8];

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* appkey-add 0x0002 -> a well-formed request is sent (txn WAITING). */
	av[0] = (char *)(uintptr_t)"appkey-add";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK cfg appkey-add", 17));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING,
	    meshd_cfg_client_status(client, NULL, NULL));

	/* relay set 0x0002 1 3 -> Set path builds and sends. */
	av[0] = (char *)(uintptr_t)"relay";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)"1";
	av[3] = (char *)(uintptr_t)"3";
	ATF_CHECK_EQ(0, meshd_cfg_client_verb(client, 4, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK cfg relay", 12));

	/* Unknown verb. */
	av[0] = (char *)(uintptr_t)"bogus";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));

	/* Unknown destination node. */
	av[0] = (char *)(uintptr_t)"appkey-add";
	av[1] = (char *)(uintptr_t)"0x0099";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(cfg_verb_matrix);
ATF_TC_BODY(cfg_verb_matrix, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	char reply[256];
	static const char key[] = "00112233445566778899aabbccddeeff";
	static const struct {
		int argc;
		const char *argv[10];
	} cases[] = {
		{ 2, { "comp-get", "0x0002" } },
		{ 3, { "comp-get", "0x0002", "1" } },
		{ 2, { "appkey-update", "0x0002" } },
		{ 2, { "appkey-delete", "0x0002" } },
		{ 3, { "appkey-get", "0x0002", "0" } },
		{ 4, { "model-bind", "0x0002", "0x0002", "0x1000" } },
		{ 5, { "model-unbind", "0x0002", "0x0002", "0x1234",
		    "0x5678" } },
		{ 4, { "model-app-get", "0x0002", "0x0002", "0x1000" } },
		{ 5, { "model-app-get", "0x0002", "0x0002", "0x1234",
		    "0x5678" } },
		{ 5, { "sub-add", "0x0002", "0x0002", "0xc001", "0x1000" } },
		{ 5, { "sub-delete", "0x0002", "0x0002", "0xc001",
		    "0x1000" } },
		{ 6, { "sub-overwrite", "0x0002", "0x0002", "0xc001",
		    "0x1234", "0x5678" } },
		{ 4, { "sub-delete-all", "0x0002", "0x0002", "0x1000" } },
		{ 5, { "sub-va-add", "0x0002", "0x0002", key, "0x1000" } },
		{ 5, { "sub-va-delete", "0x0002", "0x0002", key, "0x1000" } },
		{ 6, { "sub-va-overwrite", "0x0002", "0x0002", key,
		    "0x1234", "0x5678" } },
		{ 4, { "sub-get", "0x0002", "0x0002", "0x1000" } },
		{ 5, { "sub-get", "0x0002", "0x0002", "0x1234", "0x5678" } },
		{ 8, { "pub-set", "0x0002", "0x0002", "0xc001", "0", "7",
		    "0", "0x1000" } },
		{ 8, { "pub-va-set", "0x0002", "0x0002", key, "0", "7", "0",
		    "0x1000" } },
		{ 4, { "pub-get", "0x0002", "0x0002", "0x1000" } },
		{ 4, { "netkey-add", "0x0002", "1", key } },
		{ 4, { "netkey-update", "0x0002", "1", key } },
		{ 3, { "netkey-delete", "0x0002", "1" } },
		{ 3, { "kr-phase-get", "0x0002", "0" } },
		{ 4, { "kr-phase-set", "0x0002", "0", "2" } },
		{ 2, { "beacon", "0x0002" } },
		{ 3, { "beacon", "0x0002", "1" } },
		{ 2, { "gatt-proxy", "0x0002" } },
		{ 3, { "friend", "0x0002", "1" } },
		{ 2, { "ttl", "0x0002" } },
		{ 3, { "ttl", "0x0002", "7" } },
		{ 2, { "relay", "0x0002" } },
		{ 2, { "nettransmit", "0x0002" } },
		{ 4, { "nettransmit", "0x0002", "3", "10" } },
		{ 3, { "node-identity-get", "0x0002", "0" } },
		{ 4, { "node-identity-set", "0x0002", "0", "1" } },
		{ 3, { "lpn-polltimeout-get", "0x0002", "0x1201" } },
		{ 2, { "hb-pub-get", "0x0002" } },
		{ 7, { "hb-pub-set", "0x0002", "0xc001", "1", "1", "7",
		    "0" } },
		{ 2, { "hb-sub-get", "0x0002" } },
		{ 5, { "hb-sub-set", "0x0002", "0x0001", "0xc001", "1" } },
		{ 2, { "node-reset", "0x0002" } },
	};
	char *av[10];
	struct mesh_node *self;
	size_t i, j;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);
	for (i = 0; i < nitems(cases); i++) {
		for (j = 0; j < (size_t)cases[i].argc; j++)
			av[j] = (char *)(uintptr_t)cases[i].argv[j];
		ATF_CHECK_MSG(meshd_cfg_client_verb(client, cases[i].argc, av,
		    i + 1, reply, sizeof(reply)) == 0, "%s: %s",
		    cases[i].argv[0], reply);
	}

	/*
	 * The daemon may retain its manager roster while its local simulated node
	 * is unavailable during shutdown/restart.  Every verb must surface the
	 * common send failure instead of reporting a successful transaction.
	 */
	self = client->self;
	client->self = NULL;
	for (i = 0; i < nitems(cases); i++) {
		for (j = 0; j < (size_t)cases[i].argc; j++)
			av[j] = (char *)(uintptr_t)cases[i].argv[j];
		ATF_CHECK_MSG(meshd_cfg_client_verb(client, cases[i].argc, av,
		    i + 100, reply, sizeof(reply)) == -1, "%s: %s",
		    cases[i].argv[0], reply);
		ATF_CHECK_MSG(strstr(reply, "send failed") != NULL, "%s: %s",
		    cases[i].argv[0], reply);
	}
	client->self = self;
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(cfg_engine_and_argument_guards);
ATF_TC_BODY(cfg_engine_and_argument_guards, tc)
{
	static const struct {
		int argc;
		const char *argv[10];
	} bad[] = {
		{ 3, { "comp-get", "0x0002", "256" } },
		{ 3, { "appkey-add", "0x0002", "extra" } },
		{ 3, { "appkey-get", "0x0002", "4096" } },
		{ 5, { "sub-add", "0x0002", "bad", "0xc001", "0x1000" } },
		{ 4, { "sub-delete-all", "0x0002", "bad", "0x1000" } },
		{ 5, { "sub-va-add", "0x0002", "2", "short", "0x1000" } },
		{ 4, { "sub-get", "0x0002", "bad", "0x1000" } },
		{ 8, { "pub-set", "0x0002", "2", "0xc001", "128", "0", "0",
		    "0x1000" } },
		{ 8, { "pub-va-set", "0x0002", "2", "short", "0", "0", "0",
		    "0x1000" } },
		{ 4, { "netkey-add", "0x0002", "1", "short" } },
		{ 3, { "netkey-delete", "0x0002", "4096" } },
		{ 3, { "kr-phase-get", "0x0002", "4096" } },
		{ 4, { "kr-phase-set", "0x0002", "0", "256" } },
		{ 4, { "beacon", "0x0002", "1", "extra" } },
		{ 3, { "relay", "0x0002", "1" } },
		{ 4, { "nettransmit", "0x0002", "8", "0" } },
		{ 3, { "node-identity-get", "0x0002", "4096" } },
		{ 4, { "node-identity-set", "0x0002", "0", "256" } },
		{ 3, { "lpn-polltimeout-get", "0x0002", "65536" } },
		{ 3, { "hb-pub-get", "0x0002", "extra" } },
		{ 7, { "hb-pub-set", "0x0002", "0xc001", "1", "1", "128", "0" } },
		{ 3, { "hb-sub-get", "0x0002", "extra" } },
		{ 5, { "hb-sub-set", "0x0002", "1", "0xc001", "256" } },
		{ 3, { "node-reset", "0x0002", "extra" } },
	};
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	const uint8_t *status;
	size_t status_len;
	char reply[128];
	char *av[10];
	uint8_t byte = 0, req[MESH_ACCESS_MAX];
	size_t req_len;
	size_t i, j;

	ATF_CHECK_EQ(-1, meshd_cfg_client_send(NULL, 1, &byte, 1, 1, 0,
	    NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, meshd_cfg_client_send(client, 1, NULL, 1, 1, 0,
	    NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, meshd_cfg_client_send(client, 1, &byte, 0, 1, 0,
	    NULL, NULL, NULL));
	ATF_CHECK_EQ(-1, meshd_cfg_client_rx(NULL, 0, 0, 0, &byte, 1));
	ATF_CHECK_EQ(-1, meshd_cfg_client_rx(client, 0, 0, 0, NULL, 1));
	ATF_CHECK_EQ(-1, meshd_cfg_client_tick(NULL, 0));
	ATF_CHECK_EQ(MESH_MGR_TXN_IDLE,
	    meshd_cfg_client_status(NULL, &status, &status_len));
	ATF_CHECK(status == NULL);
	ATF_CHECK_EQ(0, status_len);

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);
	ATF_CHECK_EQ(0, meshd_cfg_client_rx(client, 0, 0, 0, &byte, 1));
	ATF_CHECK_EQ(0, meshd_cfg_client_tick(client, 0));

	/* Drive the real retry deadline and retransmit path. */
	ATF_REQUIRE_EQ(0, mesh_mgr_cfg_u8_state_get_pdu(client->mgr,
	    BT_MESH_CFG_OP_DEFAULT_TTL_GET, req, &req_len));
	ATF_REQUIRE_EQ(0, meshd_cfg_client_send(client, node->addr, req, req_len,
	    BT_MESH_CFG_OP_DEFAULT_TTL_STATUS, 0, NULL, NULL, NULL));
	ATF_CHECK_EQ(0, meshd_cfg_client_tick(client,
	    MESHD_CFG_RETRY_MS - 1));
	ATF_CHECK_EQ(1, meshd_cfg_client_tick(client, MESHD_CFG_RETRY_MS));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING,
	    meshd_cfg_client_status(client, NULL, NULL));
	/* A vanished roster target leaves a waiting transaction untouched. */
	client->cfg_txn.node_addr = 0x0099;
	ATF_CHECK_EQ(0, meshd_cfg_client_tick(client,
	    MESHD_CFG_RETRY_MS * 2));
	ATF_CHECK_EQ(0, meshd_cfg_client_rx(client, 0, 0, 0, &byte, 1));
	client->cfg_txn.node_addr = node->addr;
	ATF_CHECK_EQ(1, meshd_cfg_client_tick(client,
	    MESHD_CFG_RETRY_MS * 2));
	ATF_CHECK_EQ(1, meshd_cfg_client_tick(client,
	    MESHD_CFG_RETRY_MS * 3));
	ATF_CHECK_EQ(0, meshd_cfg_client_tick(client,
	    MESHD_CFG_RETRY_MS * 4));
	ATF_CHECK_EQ(MESH_MGR_TXN_TIMEOUT,
	    meshd_cfg_client_status(client, NULL, NULL));

	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(NULL, 0, NULL, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 0, av, 0, reply,
	    sizeof(reply)));
	av[0] = (char *)(uintptr_t)"ttl";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 1, av, 0, reply,
	    sizeof(reply)));
	av[1] = (char *)(uintptr_t)"0x10000";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)"256";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 3, av, 0, reply,
	    sizeof(reply)));
	av[0] = (char *)(uintptr_t)"model-bind";
	av[2] = (char *)(uintptr_t)"0x0002";
	av[3] = (char *)(uintptr_t)"garbage";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 4, av, 0, reply,
	    sizeof(reply)));
	av[3] = (char *)(uintptr_t)"1";
	av[4] = (char *)(uintptr_t)"2";
	av[5] = (char *)(uintptr_t)"3";
	ATF_CHECK_EQ(-1, meshd_cfg_client_verb(client, 6, av, 0, reply,
	    sizeof(reply)));

	for (i = 0; i < nitems(bad); i++) {
		for (j = 0; j < (size_t)bad[i].argc; j++)
			av[j] = (char *)(uintptr_t)bad[i].argv[j];
		ATF_CHECK_MSG(meshd_cfg_client_verb(client, bad[i].argc, av, 0,
		    reply, sizeof(reply)) == -1, "verb=%s reply=%s",
		    bad[i].argv[0], reply);
		ATF_CHECK_MSG(strstr(reply, "bad usage/argument") != NULL ||
		    strstr(reply, "usage") != NULL, "verb=%s reply=%s",
		    bad[i].argv[0], reply);
	}
	free(client->mgr);
}

/* ================================================================
 * Engine guards.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(send_guards);
ATF_TC_BODY(send_guards, tc)
{
	MESH_HEAP(struct meshd_node, client);
	struct meshd_config ccfg;
	uint8_t req[8] = { 0x00 };

	meshd_config_defaults(&ccfg);
	memset(ccfg.netkey, 0x11, 16);
	ccfg.have_netkey = 1;
	memset(ccfg.appkey, 0x22, 16);
	ccfg.have_appkey = 1;
	ccfg.unicast_addr = 0x0001;
	ATF_REQUIRE_EQ(0, meshd_node_init(client, &ccfg));

	/* No network yet. */
	ATF_CHECK_EQ(-1, meshd_cfg_client_send(client, 0x0002, req, sizeof(req),
	    MESH_CFG_OP_APPKEY_STATUS, 0, NULL, NULL, NULL));

	/* Network but no such node. */
	client->mgr = calloc(1, sizeof(*client->mgr));
	ATF_REQUIRE(client->mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(client->mgr, NULL, NULL));
	client->mgr_active = 1;
	ATF_CHECK_EQ(-1, meshd_cfg_client_send(client, 0x0055, req, sizeof(req),
	    MESH_CFG_OP_APPKEY_STATUS, 0, NULL, NULL, NULL));
	free(client->mgr);
}

/* ================================================================
 * Manager-DB persistence (A2): the roster + DevKeys survive a save/load.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(mgr_persist_roundtrip);
ATF_TC_BODY(mgr_persist_roundtrip, tc)
{
	MESH_HEAP(struct mesh_mgr, mgr);
	MESH_HEAP(struct mesh_mgr, back);
	struct mesh_mgr_node *n, *r;
	uint8_t uuid[16], dk[16];
	uint16_t addr;
	char path[] = "./mesh_cfgclient_mgr.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	(void)close(fd);

	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(mgr, NULL, NULL));
	memset(uuid, 0xAB, sizeof(uuid));
	memset(dk, 0xCD, sizeof(dk));
	ATF_REQUIRE_EQ(0, mesh_mgr_alloc_unicast(mgr, 1, &addr));
	n = mesh_mgr_add_node(mgr, uuid, addr, 1, dk, 0x99);
	ATF_REQUIRE(n != NULL);

	ATF_REQUIRE_EQ(0, meshd_persist_mgr_save(path, mgr));
	ATF_REQUIRE_EQ(0, meshd_persist_mgr_load(path, back));

	ATF_CHECK_EQ(mesh_mgr_node_count(mgr), mesh_mgr_node_count(back));
	r = mesh_mgr_find_by_addr(back, addr);
	ATF_REQUIRE(r != NULL);
	ATF_CHECK_EQ(0, memcmp(r->devkey, dk, 16));
	ATF_CHECK_EQ(0, memcmp(r->uuid, uuid, 16));
	ATF_CHECK_EQ(0, memcmp(back->netkey, mgr->netkey, 16));

	/* A missing store loads as "fresh" (1), not an error. */
	(void)unlink(path);
	ATF_CHECK_EQ(1, meshd_persist_mgr_load(path, back));
}

/* ================================================================
 * OTA provisioning verb guards (A3).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ota_provision_guards);
ATF_TC_BODY(ota_provision_guards, tc)
{
	MESH_HEAP(struct meshd_node, client);
	struct meshd_config ccfg;
	uint8_t uuid[16];

	memset(uuid, 0x3C, sizeof(uuid));
	meshd_config_defaults(&ccfg);
	memset(ccfg.netkey, 0x11, 16);
	ccfg.have_netkey = 1;
	memset(ccfg.appkey, 0x22, 16);
	ccfg.have_appkey = 1;
	ccfg.unicast_addr = 0x0001;
	ATF_REQUIRE_EQ(0, meshd_node_init(client, &ccfg));

	/* No network: begin fails. */
	ATF_CHECK_EQ(-1, meshd_provision_ota_begin(client, uuid, 1, 0));
	/* Nothing pending: commit returns NULL. */
	ATF_CHECK(meshd_provision_ota_commit(client, 0) == NULL);

	/* With a network, begin opens the link and marks a target active. */
	client->mgr = calloc(1, sizeof(*client->mgr));
	ATF_REQUIRE(client->mgr != NULL);
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(client->mgr, NULL, NULL));
	client->mgr_active = 1;

	ATF_CHECK_EQ(0, meshd_provision_ota_begin(client, uuid, 1, 0));
	ATF_CHECK_EQ(1, client->prov_target_active);
	/* Only one provisioning at a time. */
	ATF_CHECK_EQ(-1, meshd_provision_ota_begin(client, uuid, 1, 0));
	/* The handshake is not done, so commit is not yet possible. */
	ATF_CHECK(meshd_provision_ota_commit(client, 0) == NULL);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(cfg_completed_status_format_matrix);
ATF_TC_BODY(cfg_completed_status_format_matrix, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_model_app app;
	struct mesh_cfg_model_sub sub;
	uint8_t status[MESH_ACCESS_MAX];
	char reply[256];
	size_t len;

	memset(nd, 0, sizeof(*nd));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "waiting", 2, NULL, 0,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "sent state=") != NULL);

	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_build(MESH_CFG_SUCCESS, 1, 2,
	    status, &len));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "appkey", 2, status, len,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "appidx=2") != NULL);

	memset(&app, 0, sizeof(app));
	app.elem_addr = 2;
	app.app_idx = 3;
	app.model.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_status_build(MESH_CFG_SUCCESS, &app,
	    status, &len));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "bind", 2, status, len,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "elem=0x0002") != NULL);

	memset(&sub, 0, sizeof(sub));
	sub.elem_addr = 2;
	sub.address = 0xc001;
	sub.model.model_id = 0x1000;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_build(MESH_CFG_SUCCESS, &sub,
	    status, &len));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "sub", 2, status, len,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "sub=0xc001") != NULL);

	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_build(MESH_CFG_SUCCESS, 4,
	    status, &len));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "netkey", 2, status, len,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "netidx=4") != NULL);

	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_status_build(status, &len));
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "reset", 2, status, len,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, " reset") != NULL);

	status[0] = 0x7f;
	ATF_CHECK_EQ(0, ptap_meshd_cfg_result(nd, "raw", 2, status, 1,
	    reply, sizeof(reply)));
	ATF_CHECK(strstr(reply, "1 octets") != NULL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, appkey_add_e2e);
	ATF_TP_ADD_TC(tp, model_bind_e2e);
	ATF_TP_ADD_TC(tp, node_reset_e2e);
	ATF_TP_ADD_TC(tp, cfg_verb_dispatch);
	ATF_TP_ADD_TC(tp, cfg_verb_matrix);
	ATF_TP_ADD_TC(tp, cfg_engine_and_argument_guards);
	ATF_TP_ADD_TC(tp, send_guards);
	ATF_TP_ADD_TC(tp, mgr_persist_roundtrip);
	ATF_TP_ADD_TC(tp, ota_provision_guards);
	ATF_TP_ADD_TC(tp, cfg_completed_status_format_matrix);
	return (atf_no_error());
}
