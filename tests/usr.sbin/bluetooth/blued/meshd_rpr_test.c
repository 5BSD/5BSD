/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd Remote Provisioning wiring (finding 128,
 * usr.sbin/bluetooth/meshd): the Remote Provisioning Server model registered on
 * the foundation dispatch table (Scan / Link / PDU control), the "remote-prov"
 * Client verbs, and the client scan/link FSM transitions.
 *
 * The RPR models operate under the target node's DevKey, so the Server model is
 * exercised end to end over the same DevKey path as the Config Server: the
 * client seals an RPR message to the server node, the server node runs
 * meshd_foundation_recv (which routes the RPR opcode to meshd_rpr_server_recv)
 * and seals the synchronous Status/Report, and the client correlates it.
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
#include "mesh_remote_prov.h"

/* ================================================================
 * Fixtures (mirrors mesh_cfgclient_test.c).
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
 * RPR Server model registration (end to end over the DevKey path).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpr_scan_caps_e2e);
ATF_TC_BODY(rpr_scan_caps_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_scan_caps caps;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	ATF_REQUIRE_EQ(0, mesh_rp_scan_caps_get_build(req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_RP_OP_SCAN_CAPABILITIES_STATUS, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_caps_status_parse(st, stlen, &caps));
	ATF_CHECK_EQ(MESH_RP_SCAN_FOUND_MAX, caps.max_scanned_items);
	ATF_CHECK_EQ(1, caps.active_scan);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_scan_start_stop_e2e);
ATF_TC_BODY(rpr_scan_start_stop_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_scan_start start;
	struct mesh_rp_scan_status ss;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Scan Start (general, two-item limit, 5 s). */
	memset(&start, 0, sizeof(start));
	start.scanned_items_limit = 2;
	start.timeout = 5;
	ATF_REQUIRE_EQ(0, mesh_rp_scan_start_build(&start, req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_RP_OP_SCAN_STATUS, st,
	    &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_status_parse(st, stlen, &ss));
	ATF_CHECK_EQ(MESH_RP_STATUS_SUCCESS, ss.status);
	ATF_CHECK(ss.scanning_state != MESH_RP_SCAN_IDLE);
	ATF_CHECK(mesh_rp_scan_server_scanning(&dev->rpr.scan_server));

	/* Scan Stop -> idle. */
	ATF_REQUIRE_EQ(0, mesh_rp_scan_stop_build(req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_RP_OP_SCAN_STATUS, st,
	    &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_scan_status_parse(st, stlen, &ss));
	ATF_CHECK_EQ(MESH_RP_SCAN_IDLE, ss.scanning_state);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_link_open_close_e2e);
ATF_TC_BODY(rpr_link_open_close_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_link_open op;
	struct mesh_rp_link_status ls;
	struct mesh_rp_link_report lr;
	uint8_t req[32], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Link Open (UUID form) -> server link OPENING. */
	memset(&op, 0, sizeof(op));
	memset(op.uuid, 0xA5, sizeof(op.uuid));
	op.has_timeout = 1;
	op.timeout = 10;
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_build(&op, req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_RP_OP_LINK_STATUS, st,
	    &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_parse(st, stlen, &ls));
	ATF_CHECK_EQ(MESH_RP_STATUS_SUCCESS, ls.status);
	ATF_CHECK_EQ(MESH_RP_LINK_OPENING, ls.rp_state);

	/* Link Close -> Link Report, server link back to IDLE. */
	ATF_REQUIRE_EQ(0, mesh_rp_link_close_build(MESH_RP_LINK_CLOSE_SUCCESS,
	    req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_RP_OP_LINK_REPORT, st,
	    &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_link_report_parse(st, stlen, &lr));
	ATF_CHECK_EQ(MESH_RP_LINK_IDLE, lr.rp_state);
	ATF_CHECK(!mesh_rp_server_link_is_active(&dev->rpr.server_link));
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_pdu_send_e2e);
ATF_TC_BODY(rpr_pdu_send_e2e, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_link_open op;
	struct mesh_rp_pdu_send snd;
	struct mesh_rp_link_status ls;
	uint8_t req[64], st[MESH_ACCESS_MAX];
	size_t req_len, stlen;
	uint8_t outnum;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* NPPI Link Open goes straight to ACTIVE (no separate bearer step). */
	memset(&op, 0, sizeof(op));
	op.has_nppi = 1;
	op.nppi_procedure = MESH_RP_NPPI_DEVICE_KEY_REFRESH;
	ATF_REQUIRE_EQ(0, mesh_rp_link_open_build(&op, req, &req_len));
	exchange(client, dev, node, req, req_len, MESH_RP_OP_LINK_STATUS, st,
	    &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_link_status_parse(st, stlen, &ls));
	ATF_CHECK_EQ(MESH_RP_LINK_ACTIVE, ls.rp_state);
	ATF_CHECK(mesh_rp_server_link_is_active(&dev->rpr.server_link));

	/* First PDU Send -> Outbound PDU Report number 1 (loopback delivery). */
	memset(&snd, 0, sizeof(snd));
	snd.outbound_pdu_number = 1;
	snd.prov_pdu[0] = 0x00;		/* Provisioning Invite (type 0x00) ... */
	snd.prov_pdu[1] = 0x00;		/* ... attention duration 0 s */
	snd.prov_len = 2;
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_send_build(&snd, req, &req_len));
	exchange(client, dev, node, req, req_len,
	    MESH_RP_OP_PDU_OUTBOUND_REPORT, st, &stlen);
	ATF_REQUIRE_EQ(0, mesh_rp_pdu_outbound_report_parse(st, stlen, &outnum));
	ATF_CHECK_EQ(1, outnum);
	free(client->mgr);
}

/* ================================================================
 * The "remote-prov" verb dispatcher + client FSM wiring.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(rpr_verb_dispatch);
ATF_TC_BODY(rpr_verb_dispatch, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	char reply[256];
	char *av[8];

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* caps 0x0002 -> Scan Capabilities Get is sent (txn WAITING). */
	av[0] = (char *)(uintptr_t)"caps";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK remote-prov caps", 19));
	ATF_CHECK_EQ(MESH_MGR_TXN_WAITING,
	    meshd_cfg_client_status(client, NULL, NULL));

	/* scan 0x0002 (general) -> Scan Start built and sent. */
	av[0] = (char *)(uintptr_t)"scan";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK remote-prov scan", 19));
	ATF_CHECK_EQ(0x0002, client->rpr.server_addr);

	/* link-open 0x0002 <uuid> -> client link enters OPENING, active. */
	av[0] = (char *)(uintptr_t)"link-open";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)
	    "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 3, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(1, client->rpr.client_active);
	ATF_CHECK_EQ(MESH_RP_LINK_OPENING, client->rpr.client_link.state);

	/* status (no dst) reports the FSM state. */
	av[0] = (char *)(uintptr_t)"status";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 1, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(0, strncmp(reply, "OK remote-prov status", 21));

	/* Unknown verb + unknown destination node. */
	av[0] = (char *)(uintptr_t)"bogus";
	av[1] = (char *)(uintptr_t)"0x0002";
	ATF_CHECK_EQ(-1, meshd_rpr_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	av[0] = (char *)(uintptr_t)"caps";
	av[1] = (char *)(uintptr_t)"0x0099";
	ATF_CHECK_EQ(-1, meshd_rpr_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_client_link_fsm);
ATF_TC_BODY(rpr_client_link_fsm, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_link_status ls;
	struct mesh_rp_link_report lr;
	char reply[128];
	char *av[3];

	setup(client, dev, &ccfg, &dcfg, &node, 0x0002);

	/* Open the client link via the verb. */
	av[0] = (char *)(uintptr_t)"link-open";
	av[1] = (char *)(uintptr_t)"0x0002";
	av[2] = (char *)(uintptr_t)
	    "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 3, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_EQ(MESH_RP_LINK_OPENING, client->rpr.client_link.state);

	/* Server accepts (Link Status), then the device bearer comes up. */
	memset(&ls, 0, sizeof(ls));
	ls.status = MESH_RP_STATUS_SUCCESS;
	ls.rp_state = MESH_RP_LINK_OPENING;
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_status(&client->rpr.client_link,
	    &ls));
	memset(&lr, 0, sizeof(lr));
	lr.status = MESH_RP_STATUS_SUCCESS;
	lr.rp_state = MESH_RP_LINK_ACTIVE;
	ATF_REQUIRE_EQ(0, mesh_rp_client_link_on_report(&client->rpr.client_link,
	    &lr));
	ATF_CHECK(mesh_rp_client_link_is_active(&client->rpr.client_link));
	free(client->mgr);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rpr_scan_caps_e2e);
	ATF_TP_ADD_TC(tp, rpr_scan_start_stop_e2e);
	ATF_TP_ADD_TC(tp, rpr_link_open_close_e2e);
	ATF_TP_ADD_TC(tp, rpr_pdu_send_e2e);
	ATF_TP_ADD_TC(tp, rpr_verb_dispatch);
	ATF_TP_ADD_TC(tp, rpr_client_link_fsm);

	return (atf_no_error());
}
