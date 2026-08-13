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

/* ================================================================
 * Live two-node Remote Provisioning over the bearer: the Server's unsolicited
 * Scan / Link / PDU Reports and the PDU tunnel travel as real network-encrypted,
 * DevKey-sealed messages shuttled between two meshd nodes sharing a subnet.
 *
 * The Server sits at 0x0010 - clear of the Client's 4-element unicast range
 * (0x0001..0x0004), so its messages are not mistaken for the Client's own
 * loopback by the receive pipeline.
 * ================================================================ */
#define	RPR_MAXCAP	32
static struct rpr_capframe {
	uint8_t			buf[128];
	size_t			len;
	enum meshd_pdu_class	cls;
} g_cap[RPR_MAXCAP];
static size_t g_ncap;

static int
rpr_cap_tx(void *arg, enum meshd_pdu_class cls, const uint8_t *pdu, size_t len)
{

	(void)arg;
	if (g_ncap < RPR_MAXCAP && len <= sizeof(g_cap[0].buf)) {
		memcpy(g_cap[g_ncap].buf, pdu, len);
		g_cap[g_ncap].len = len;
		g_cap[g_ncap].cls = cls;
		g_ncap++;
	}
	return (0);
}

/* Deliver every currently-captured Network PDU to node `to`. */
static void
rpr_pump(struct meshd_node *to)
{
	struct rpr_capframe snap[RPR_MAXCAP];
	size_t n, i;

	n = g_ncap;
	memcpy(snap, g_cap, n * sizeof(snap[0]));
	g_ncap = 0;
	for (i = 0; i < n; i++)
		if (snap[i].cls == MESHD_PDU_NET)
			(void)meshd_bearer_rx(to, snap[i].buf, snap[i].len);
}

/*
 * Stand up an RPR Client (manager) and Server node sharing one subnet, with the
 * Server holding the roster DevKey as its local DevKey so its sealed Reports
 * open on the Client.  Capturing bearers are attached to both.
 */
static void
rpr_live_setup(struct meshd_node *client, struct meshd_node *server,
    struct meshd_config *ccfg, struct meshd_config *scfg,
    struct mesh_mgr_node **out_node, uint16_t saddr,
    struct meshd_bearer *cbear, struct meshd_bearer *sbear)
{
	uint8_t netkey[16], appkey[16], dk[16], uuid[16];

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
	ATF_REQUIRE_EQ(0, mesh_mgr_create_network(client->mgr, netkey, appkey));
	client->mgr_active = 1;
	/* Align the client's sim node to the minted network key. */
	ATF_REQUIRE_EQ(0, meshd_node_restore(client, netkey, appkey, 0, 0x0001));

	memset(uuid, 0xD0, sizeof(uuid));
	memset(dk, 0x55, sizeof(dk));
	*out_node = mesh_mgr_add_node(client->mgr, uuid, saddr, 1, dk, 0);
	ATF_REQUIRE(*out_node != NULL);

	meshd_config_defaults(scfg);
	memcpy(scfg->netkey, netkey, 16);
	scfg->have_netkey = 1;
	memcpy(scfg->appkey, appkey, 16);
	scfg->have_appkey = 1;
	scfg->netkey_index = 0;
	scfg->appkey_index = 0;
	scfg->unicast_addr = saddr;
	scfg->iv_index = 0;
	scfg->default_ttl = 7;
	ATF_REQUIRE_EQ(0, meshd_node_init(server, scfg));
	server->have_local_devkey = 1;
	memcpy(server->local_devkey, dk, sizeof(dk));
	ATF_REQUIRE_EQ(0, meshd_node_restore(server, netkey, appkey, 0, saddr));

	cbear->tx = rpr_cap_tx;
	sbear->tx = rpr_cap_tx;
	meshd_set_bearer(client, cbear);
	meshd_set_bearer(server, sbear);
}

ATF_TC_WITHOUT_HEAD(rpr_scan_report_live);
ATF_TC_BODY(rpr_scan_report_live, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, server);
	struct meshd_config ccfg, scfg;
	struct meshd_bearer cbear, sbear;
	struct mesh_mgr_node *node;
	uint8_t dev_uuid[16];
	char reply[160];
	char *av[3];

	rpr_live_setup(client, server, &ccfg, &scfg, &node, 0x0010, &cbear,
	    &sbear);
	memset(dev_uuid, 0xAB, sizeof(dev_uuid));

	/* Client starts a scan on the Server (records the client addr there). */
	g_ncap = 0;
	av[0] = (char *)(uintptr_t)"scan";
	av[1] = (char *)(uintptr_t)"0x0010";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 2, av, 0, reply,
	    sizeof(reply)));
	rpr_pump(server);			/* Scan Start -> Server */
	ATF_CHECK_EQ(0x0001, server->rpr.client_addr);
	ATF_CHECK(mesh_rp_scan_server_scanning(&server->rpr.scan_server));
	rpr_pump(client);			/* Scan Status -> Client */

	/* The Server discovers a device and emits an unsolicited Scan Report. */
	ATF_REQUIRE_EQ(1, meshd_rpr_server_report_scan(server, dev_uuid, 0, -40,
	    0));
	rpr_pump(client);			/* Scan Report -> Client */

	/* The Client recorded the reported UUID and buffered the report. */
	ATF_CHECK(mesh_rp_scan_client_found(&client->rpr.scan_client, dev_uuid));
	ATF_CHECK(client->rpr.n_reports >= 1);

	/* "remote-prov reports" surfaces it over the control socket. */
	av[0] = (char *)(uintptr_t)"reports";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 1, av, 0, reply,
	    sizeof(reply)));
	ATF_CHECK_MSG(strstr(reply, "op=0x8055") != NULL, "%s", reply);
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_pdu_tunnel_live);
ATF_TC_BODY(rpr_pdu_tunnel_live, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, server);
	struct meshd_config ccfg, scfg;
	struct meshd_bearer cbear, sbear;
	struct mesh_mgr_node *node;
	uint8_t invite[2] = { 0x00, 0x05 };	/* Provisioning Invite */
	uint8_t dev_rsp[2] = { 0x00, 0x09 };	/* device's tunnelled PDU */
	char reply[96];
	char *av[4];

	rpr_live_setup(client, server, &ccfg, &scfg, &node, 0x0010, &cbear,
	    &sbear);

	/* Open a PB-Remote link Client -> Server. */
	g_ncap = 0;
	av[0] = (char *)(uintptr_t)"link-open";
	av[1] = (char *)(uintptr_t)"0x0010";
	av[2] = (char *)(uintptr_t)
	    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
	ATF_CHECK_EQ(0, meshd_rpr_client_verb(client, 3, av, 0, reply,
	    sizeof(reply)));
	rpr_pump(server);			/* Link Open -> Server (OPENING) */
	ATF_CHECK_EQ(0x0001, server->rpr.client_addr);
	rpr_pump(client);			/* Link Status -> Client */

	/* Server's device bearer comes up: unsolicited Link Report (ACTIVE). */
	ATF_REQUIRE_EQ(1, meshd_rpr_server_report_bearer(server));
	rpr_pump(client);			/* Link Report -> Client (ACTIVE) */
	ATF_CHECK(mesh_rp_client_link_is_active(&client->rpr.client_link));

	/* Client tunnels an outbound Provisioning PDU; Outbound Report returns. */
	ATF_REQUIRE_EQ(0, meshd_rpr_client_send_pdu(client, invite,
	    sizeof(invite), 0));
	rpr_pump(server);			/* PDU Send -> Server */
	rpr_pump(client);			/* PDU Outbound Report -> Client */
	ATF_CHECK_EQ(0, client->rpr.client_link.awaiting_outbound_report);

	/* Device returns a Provisioning PDU: Server emits a PDU Report. */
	ATF_REQUIRE_EQ(1, meshd_rpr_server_report_pdu(server, dev_rsp,
	    sizeof(dev_rsp)));
	rpr_pump(client);			/* PDU Report -> Client */
	ATF_CHECK_EQ(sizeof(dev_rsp), client->rpr.inbound_pdu_len);
	ATF_CHECK_EQ(0, memcmp(client->rpr.inbound_pdu, dev_rsp,
	    sizeof(dev_rsp)));
	free(client->mgr);
}

ATF_TC_WITHOUT_HEAD(rpr_client_rx_scan_report_unit);
ATF_TC_BODY(rpr_client_rx_scan_report_unit, tc)
{
	MESH_HEAP(struct meshd_node, client);
	MESH_HEAP(struct meshd_node, dev);
	struct meshd_config ccfg, dcfg;
	struct mesh_mgr_node *node;
	struct mesh_rp_scan_report rep;
	uint8_t dev_uuid[16], access[MESH_RP_MSG_MAX], upper[MESH_UPPER_MAX];
	size_t alen, ulen;

	setup(client, dev, &ccfg, &dcfg, &node, 0x0010);
	memset(dev_uuid, 0x7E, sizeof(dev_uuid));

	/* Build + DevKey-seal a Scan Report as the Server (0x0010) would. */
	memset(&rep, 0, sizeof(rep));
	rep.rssi = -50;
	memcpy(rep.uuid, dev_uuid, sizeof(rep.uuid));
	ATF_REQUIRE_EQ(0, mesh_rp_scan_report_build(&rep, access, &alen));
	ATF_REQUIRE_EQ(0, mesh_upper_encrypt(node->devkey, 0, 0, 0, node->addr,
	    client->mgr->self_addr, client->mgr->iv_index, NULL, access, alen,
	    upper, &ulen));

	/* The client-report receive path decodes + records it. */
	ATF_CHECK_EQ(1, meshd_rpr_client_rx(client, 0, node->addr,
	    client->mgr->self_addr, upper, ulen));
	ATF_CHECK(mesh_rp_scan_client_found(&client->rpr.scan_client, dev_uuid));
	ATF_CHECK(client->rpr.n_reports >= 1);
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
	ATF_TP_ADD_TC(tp, rpr_scan_report_live);
	ATF_TP_ADD_TC(tp, rpr_pdu_tunnel_live);
	ATF_TP_ADD_TC(tp, rpr_client_rx_scan_report_unit);

	return (atf_no_error());
}
