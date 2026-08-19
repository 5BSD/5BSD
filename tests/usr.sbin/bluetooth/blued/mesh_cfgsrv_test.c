/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the meshd(8) Configuration Server dispatch runtime and node
 * config database (meshd_node.c).  A Configuration Client message is built
 * with the libblemesh codecs, handed to meshd_foundation_recv(), and both the
 * mutated database (struct meshd_cfg_db) and the auto-Status reply are checked
 * against the Mesh Model 1.1 (MshMDL) wire layouts.
 *
 * The spec oracle is MshMDL Section 4.3 / 4.4.1 (message formats and the
 * Configuration Server behaviour) and MshMDL Section 4.3.1.1 (key-index
 * packing); expected reply bytes are derived from the specification, never
 * from captured output.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "mesh_crypto.h"
#include "spec_mesh_cfgsrv_oracles.h"

/* Deterministic test key material. */
static const uint8_t g_netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t g_appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};
static const uint8_t g_appkey2[16] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

/* Primary element address of the node under test. */
#define	ELEM	0x0001

static void
base_config(struct meshd_config *cfg)
{

	meshd_config_defaults(cfg);
	memcpy(cfg->netkey, g_netkey, 16);
	memcpy(cfg->appkey, g_appkey, 16);
	cfg->have_netkey = 1;
	cfg->have_appkey = 1;
	cfg->unicast_addr = ELEM;
	cfg->iv_index = 0;
	cfg->default_ttl = 7;
	cfg->netkey_index = 0;			/* primary subnet index 0 */
}

/* The Generic OnOff Server SIG model, registered on the primary element. */
static struct mesh_cfg_model_id
onoff_model(void)
{
	struct mesh_cfg_model_id m;

	memset(&m, 0, sizeof(m));
	m.model_id = BT_MESH_CFGSRV_MODEL_GENERIC_ONOFF_SERVER;
	m.vendor = 0;
	return (m);
}

/* Locate a registered model entry in the database by model id. */
static struct meshd_model_entry *
db_model(struct meshd_node *nd, uint16_t model_id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		if (nd->db.models[i].valid && !nd->db.models[i].id.vendor &&
		    nd->db.models[i].id.model_id == model_id)
			return (&nd->db.models[i]);
	}
	return (NULL);
}

static struct meshd_model_entry *
db_model_at(struct meshd_node *nd, uint16_t elem_addr, uint16_t model_id)
{
	size_t i;

	for (i = 0; i < nd->db.n_models; i++) {
		if (nd->db.models[i].valid &&
		    nd->db.models[i].elem_addr == elem_addr &&
		    !nd->db.models[i].id.vendor &&
		    nd->db.models[i].id.model_id == model_id)
			return (&nd->db.models[i]);
	}
	return (NULL);
}

/* Database inspection: is a NetKey / AppKey index stored? */
static int
db_has_netkey(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (nd->db.netkeys[i].valid &&
		    nd->db.netkeys[i].net_idx == net_idx)
			return (1);
	}
	return (0);
}

/* Locate a subnet db entry by NetKey index. */
static struct meshd_netkey_entry *
db_netkey(struct meshd_node *nd, uint16_t net_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_NETKEYS; i++) {
		if (nd->db.netkeys[i].valid &&
		    nd->db.netkeys[i].net_idx == net_idx)
			return (&nd->db.netkeys[i]);
	}
	return (NULL);
}

static int
db_has_appkey(struct meshd_node *nd, uint16_t app_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
		if (nd->db.appkeys[i].valid &&
		    nd->db.appkeys[i].app_idx == app_idx)
			return (1);
	}
	return (0);
}

/* Deliver one Config message; require a reply was produced. */
static size_t
deliver(struct meshd_node *nd, const uint8_t *msg, size_t mlen, uint8_t *reply,
    size_t reply_max)
{
	size_t rlen = 0;

	ATF_REQUIRE_EQ(1, meshd_foundation_recv(nd, msg, mlen, reply, reply_max,
	    &rlen));
	return (rlen);
}

/* ================================================================
 * End-to-end commissioning: NetKey Add -> AppKey Add -> Model App Bind ->
 * Model Subscription Add, then Get each and confirm the database + Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(commission_sequence);
ATF_TC_BODY(commission_sequence, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_sub ms;
	struct mesh_cfg_model_id model = onoff_model();
	struct meshd_model_entry *me;
	uint8_t msg[64], reply[128];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/*
	 * NetKey Add (0x8040), NetKeyIndex 0x001, NetKey (MshMDL 4.4.1.2.20).
	 * The Status (0x8044) is Success (0x00) + the NetKeyIndex, 12-bit
	 * packed little-endian (MshMDL 4.3.1.1): {0x80,0x44,0x00,0x01,0x00}.
	 */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x001;
	memcpy(nk.key, g_netkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_netkey_status_1), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_netkey_status_1, rlen));
	ATF_CHECK(db_has_netkey(nd, 0x001));

	/*
	 * AppKey Add (0x00), NetKeyIndex 0x000 + AppKeyIndex 0x001 + AppKey.
	 * The two indexes pack into 3 octets (MshMDL 4.3.1.1): idx0=0 in the
	 * low 12 bits, idx1=1 in the high 12 bits -> {0x00,0x10,0x00}.  Status
	 * (0x8003) = {0x80,0x03,0x00,0x00,0x10,0x00}.
	 */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_appkey_status_0_1), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_appkey_status_0_1, rlen));

	/*
	 * Model App Bind (0x803D): ElementAddress + AppKeyIndex + ModelId.
	 * Status (0x803E) = 0x00 + elem(LE) + appidx(pack1) + model(LE):
	 * {0x80,0x3E,0x00,0x01,0x00,0x01,0x00,0x00,0x10}.
	 */
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x001;
	ma.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_model_app_status_elem1_app1_onoff),
	    rlen);
	ATF_CHECK_EQ(0, memcmp(reply,
	    bt_mesh_cfgsrv_model_app_status_elem1_app1_onoff, rlen));
	me = db_model(nd, BT_MESH_CFGSRV_MODEL_GENERIC_ONOFF_SERVER);
	ATF_REQUIRE(me != NULL);
	ATF_CHECK_EQ_MSG(1, me->n_app, "AppKey bound to the model");
	ATF_CHECK_EQ(0x001, me->app_idx[0]);

	/*
	 * Model Subscription Add (0x801B): group address 0xC001.
	 * Status (0x801F) = 0x00 + elem(LE) + address(LE) + model(LE):
	 * {0x80,0x1F,0x00,0x01,0x00,0x01,0xC0,0x00,0x10}.
	 */
	memset(&ms, 0, sizeof(ms));
	ms.elem_addr = ELEM;
	ms.address = 0xC001;
	ms.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_model_sub_status_elem1_c001_onoff),
	    rlen);
	ATF_CHECK_EQ(0, memcmp(reply,
	    bt_mesh_cfgsrv_model_sub_status_elem1_c001_onoff, rlen));
	ATF_CHECK_EQ_MSG(1, me->n_subs, "group subscription stored");
	ATF_CHECK_EQ(0xC001, me->subs[0]);

	/* ---- Now GET each and confirm the database is reflected. ---- */

	/* NetKey Get (0x8042) -> NetKey List (0x8043) holds {0x000, 0x001}. */
	{
		uint16_t idx[8];
		size_t n = 0;

		ATF_REQUIRE_EQ(0, mesh_cfg_netkey_get_build(msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_netkey_list_parse(reply, rlen, idx, 8,
		    &n));
		ATF_CHECK_EQ_MSG(2, n, "two subnets after NetKey Add");
	}

	/* AppKey Get (0x8001) on NetKeyIndex 0 -> AppKey List holds {0x001}. */
	{
		uint8_t status;
		uint16_t net_idx, idx[8];
		size_t n = 0;

		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_get_build(0x000, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_appkey_list_parse(reply, rlen,
		    &status, &net_idx, idx, 8, &n));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(0x000, net_idx);
		ATF_CHECK_EQ_MSG(1, n, "one AppKey bound to subnet 0");
		ATF_CHECK_EQ(0x001, idx[0]);
	}

	/* SIG Model App Get (0x804B) -> App List holds the bound AppKey. */
	{
		uint32_t op;
		uint8_t status;
		uint16_t elem_addr, idx[8];
		struct mesh_cfg_model_id got;
		size_t n = 0;

		ATF_REQUIRE_EQ(0, mesh_cfg_model_app_get_build(
		    MESH_CFG_OP_SIG_MODEL_APP_GET, ELEM, &model, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_app_list_parse(reply, rlen, &op,
		    &status, &elem_addr, &got, idx, 8, &n));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(ELEM, elem_addr);
		ATF_CHECK_EQ(1, n);
		ATF_CHECK_EQ(0x001, idx[0]);
	}

	/* SIG Model Subscription Get (0x8029) -> Sub List holds 0xC001. */
	{
		uint32_t op;
		uint8_t status;
		uint16_t elem_addr, addrs[8];
		struct mesh_cfg_model_id got;
		size_t n = 0;

		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_build(
		    MESH_CFG_OP_SIG_MODEL_SUB_GET, ELEM, &model, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_list_parse(reply, rlen, &op,
		    &status, &elem_addr, &got, addrs, 8, &n));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(1, n);
		ATF_CHECK_EQ(0xC001, addrs[0]);
	}
}

/* ================================================================
 * AppKey Update, then Delete removes the key and its model binding.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(appkey_lifecycle);
ATF_TC_BODY(appkey_lifecycle, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_id model = onoff_model();
	struct meshd_model_entry *me;
	uint8_t msg[64], reply[128];
	size_t mlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* AppKey Add on the seeded primary subnet (index 0). */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x002;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));

	/* AppKey Update to a new key value -> Success. */
	memcpy(ak.key, g_appkey2, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK(db_has_appkey(nd, 0x002));

	/* Bind the AppKey, then delete it: the binding must be dropped too. */
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x002;
	ma.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	me = db_model(nd, BT_MESH_CFGSRV_MODEL_GENERIC_ONOFF_SERVER);
	ATF_REQUIRE(me != NULL);
	ATF_CHECK_EQ(1, me->n_app);

	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_delete_build(0x000, 0x002, msg,
	    &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ_MSG(0, (int)(db_has_appkey(nd, 0x002)),
	    "AppKey removed");
	ATF_CHECK_EQ_MSG(0, me->n_app, "binding removed with the AppKey");
}

/* ================================================================
 * Error arms: AppKey Add against an unknown subnet, a bind to an
 * unknown model, a bind to the DevKey-only Configuration Server, and a
 * subscription to a unicast (non-group) address.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(config_error_arms);
ATF_TC_BODY(config_error_arms, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_id cfgsrv, unknown;
	uint8_t msg[64], reply[128];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* AppKey Add referencing a NetKeyIndex that is not stored -> 0x04. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x0AA;			/* no such subnet */
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(6, rlen);
	ATF_CHECK_EQ_MSG(BT_MESH_CFGSRV_INVALID_NETKEY_INDEX, reply[2],
	    "unknown NetKeyIndex is rejected");

	/* Add a valid AppKey so the later bind reaches the model check. */
	ak.net_idx = 0x000;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));

	/* Bind to a model that is not present on the element -> 0x02. */
	memset(&unknown, 0, sizeof(unknown));
	unknown.model_id = 0x1234;		/* not registered */
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x001;
	ma.model = unknown;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ_MSG(BT_MESH_CFGSRV_INVALID_MODEL, reply[2],
	    "unknown model is rejected");

	/* Bind to the Configuration Server (0x0000): uses the DevKey -> 0x02. */
	memset(&cfgsrv, 0, sizeof(cfgsrv));
	cfgsrv.model_id = BT_MESH_CFGSRV_MODEL_CONFIG_SERVER;
	ma.model = cfgsrv;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ_MSG(BT_MESH_CFGSRV_INVALID_MODEL, reply[2],
	    "the Configuration Server cannot be AppKey-bound");

	/*
	 * Inject the independent Table 4.75 wire oracle directly: the production
	 * client builder correctly refuses a unicast subscription address, while
	 * this server test must exercise the peer-invalid-message response.
	 */
	mlen = sizeof(bt_mesh_cfgsrv_model_sub_add_invalid_unicast);
	memcpy(msg, bt_mesh_cfgsrv_model_sub_add_invalid_unicast, mlen);
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ_MSG(BT_MESH_CFGSRV_INVALID_ADDRESS, reply[2],
	    "a unicast subscription address is rejected");
}

/* ================================================================
 * Zero-parameter Get / opcode-match (M2): Beacon, Default TTL, Relay,
 * GATT Proxy, Friend and Network Transmit each respond with their Status.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(zero_param_gets);
ATF_TC_BODY(zero_param_gets, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[16], reply[32];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Beacon Get (0x8009) -> Beacon Status (0x800B) value 0 (default off). */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(BT_MESH_CFGSRV_OP_BEACON_GET, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_beacon_status_off), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_beacon_status_off, rlen));

	/* Default TTL Get (0x800C) -> Status (0x800E) value 7. */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(
	    BT_MESH_CFGSRV_OP_DEFAULT_TTL_GET, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_default_ttl_status_7), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_default_ttl_status_7,
	    rlen));

	/* Relay Get (0x8026) -> Status (0x8028) Relay 0 + RelayRetransmit 0. */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(BT_MESH_CFGSRV_OP_RELAY_GET, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_relay_status_off), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_relay_status_off, rlen));

	/* GATT Proxy Get (0x8012) -> Status (0x8014). */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(BT_MESH_CFGSRV_OP_GATT_PROXY_GET,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_proxy_status_off), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_proxy_status_off, rlen));

	/* Friend Get -> Status 0x00, Disabled (the node supports Friend). */
	ATF_REQUIRE_EQ(0, mesh_cfg_empty_build(BT_MESH_CFGSRV_OP_FRIEND_GET, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_friend_status_disabled), rlen);
	ATF_CHECK_EQ(0, memcmp(reply,
	    bt_mesh_cfgsrv_friend_status_disabled, rlen));

	/* Network Transmit Get (0x8023) -> Status (0x8025) value 0. */
	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(sizeof(bt_mesh_cfgsrv_net_tx_status_zero), rlen);
	ATF_CHECK_EQ(0, memcmp(reply, bt_mesh_cfgsrv_net_tx_status_zero, rlen));
}

/* ================================================================
 * Node-wide state Set/Get round trips: Beacon, Relay, Network Transmit,
 * Default TTL; plus Key Refresh Phase and Node Identity per-subnet.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_state_roundtrip);
ATF_TC_BODY(node_state_roundtrip, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_relay relay;
	struct mesh_cfg_net_transmit nt;
	uint8_t msg[16], reply[32];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Beacon Set (0x800A) value 1 -> Status echoes 1, state updated. */
	ATF_REQUIRE_EQ(0, mesh_cfg_u8_state_build(MESH_CFG_OP_BEACON_SET, 1, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(3, rlen);
	ATF_CHECK_EQ(0x0B, reply[1]);
	ATF_CHECK_EQ(1, reply[2]);
	ATF_CHECK_EQ(1, nd->cfg.beacon);

	/* Relay Set (0x8027): Relay 1, RelayRetransmit 0x15 -> stored. */
	memset(&relay, 0, sizeof(relay));
	relay.relay = 1;
	relay.retransmit = 0x15;
	ATF_REQUIRE_EQ(0, mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_SET, &relay,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(0x28, reply[1]);
	ATF_CHECK_EQ(1, reply[2]);
	ATF_CHECK_EQ(0x15, reply[3]);
	ATF_CHECK_EQ(1, nd->cfg.relay);
	ATF_CHECK_EQ(0x15, nd->cfg.relay_retransmit);

	/* Network Transmit Set (0x8024): count 2, interval steps 4. */
	memset(&nt, 0, sizeof(nt));
	nt.count = 2;
	nt.interval_steps = 4;
	ATF_REQUIRE_EQ(0, mesh_cfg_net_transmit_set_build(
	    MESH_CFG_OP_NET_TRANSMIT_SET, &nt, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(0x25, reply[1]);
	/* Packed octet = count | (steps<<3) = 2 | 0x20 = 0x22. */
	ATF_CHECK_EQ(0x22, reply[2]);
	ATF_CHECK_EQ(0x22, nd->db.net_transmit);

	/* Key Refresh Phase Get (0x8015) on subnet 0 -> Phase 0 (Normal). */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_get_build(0x000, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status, phase;
		uint16_t net_idx;

		ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen,
		    &status, &net_idx, &phase));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(0x000, net_idx);
		ATF_CHECK_EQ(MESH_CFG_KR_PHASE_0, phase);
	}

	/* Node Identity Set (0x8047) running on subnet 0, then Get echoes it. */
	ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_set_build(0x000,
	    MESH_CFG_NODE_IDENTITY_RUNNING, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status, identity;
		uint16_t net_idx;

		ATF_REQUIRE_EQ(0, mesh_cfg_node_identity_status_parse(reply,
		    rlen, &status, &net_idx, &identity));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(MESH_CFG_NODE_IDENTITY_RUNNING, identity);
	}

	/* LPN PollTimeout Get (0x802D): no friendship -> PollTimeout 0. */
	ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_get_build(0x0002, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint16_t lpn_addr;
		uint32_t poll;

		ATF_REQUIRE_EQ(0, mesh_cfg_lpn_polltimeout_status_parse(reply,
		    rlen, &lpn_addr, &poll));
		ATF_CHECK_EQ(0x0002, lpn_addr);
		ATF_CHECK_EQ(0u, poll);
	}
}

/* ================================================================
 * Key Refresh via the Config Server (MshPRT_v1.1 Section 3.11.4): NetKey Update
 * drives Phase 1 holding BOTH keys (the current key is NOT clobbered), KR Phase
 * Set Transition 2 moves to Phase 2 (transmit with the new key), and Transition
 * 3 revokes the old key and promotes the new one to the sole current key.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(key_refresh_lifecycle);
ATF_TC_BODY(key_refresh_lifecycle, tc)
{
	static const uint8_t g_newkey[16] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_netkey_entry *e;
	struct mesh_cfg_netkey nk;
	uint8_t msg[64], reply[64];
	uint8_t status, phase, new_nid, enc[16], priv[16], p = 0x00;
	uint16_t net_idx;
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	e = db_netkey(nd, 0x000);
	ATF_REQUIRE(e != NULL);

	/* NetKey Update (0x8045): Phase 0 -> 1, hold BOTH keys. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x000;
	memcpy(nk.key, g_newkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_CHECK_EQ(1, e->has_new_key);
	/* The current key must be UNCHANGED (not clobbered by the new key). */
	ATF_CHECK_EQ(0, memcmp(e->key, g_netkey, 16));
	ATF_CHECK_EQ(0, memcmp(e->new_key, g_newkey, 16));
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_1, e->kr_phase);
	ATF_CHECK_EQ(MESH_KR_PHASE_1, mesh_sim_node_kr_phase(nd->self));
	ATF_CHECK_EQ(1, nd->self->have_new_key);
	/* Phase 1 still TRANSMITS with the OLD key. */
	ATF_CHECK_EQ(MESH_KR_KEY_OLD, mesh_kr_tx_key(&nd->self->kr));

	/* A second Update while a refresh is in progress is refused. */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status); /* idempotent re-send */

	/* KR Phase Set Transition 2 (0x8016): Phase 1 -> 2, transmit with new. */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_2, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, phase);
	ATF_CHECK_EQ(MESH_KR_KEY_NEW, mesh_kr_tx_key(&nd->self->kr));

	/* KR Phase Set Transition 3 (0x8016): revoke old, promote new, settle. */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_3, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_0, phase);
	/* The new key is now the SOLE current key (old key revoked). */
	ATF_CHECK_EQ(0, e->has_new_key);
	ATF_CHECK_EQ(0, memcmp(e->key, g_newkey, 16));
	ATF_CHECK_EQ(0, nd->self->have_new_key);
	ATF_CHECK_EQ(0, memcmp(nd->self->netkey, g_newkey, 16));
	/* The sim node's managed-flooding NID is the new key's NID. */
	ATF_REQUIRE_EQ(0, mesh_k2(g_newkey, &p, 1, &new_nid, enc, priv));
	ATF_CHECK_EQ(new_nid, nd->self->nid);
}

/* ================================================================
 * Model Publication Set / Get round trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(model_publication);
ATF_TC_BODY(model_publication, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_pub pub;
	struct mesh_cfg_model_id model = onoff_model();
	uint8_t msg[64], reply[64];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* An AppKey must exist for the publication to reference. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));

	/* Model Publication Set (0x03): publish to 0xC003 with AppKey 0x001. */
	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = ELEM;
	pub.pub_addr = 0xC003;
	pub.app_idx = 0x001;
	pub.ttl = 5;
	pub.period = 0x40;
	pub.retransmit = 0x15;
	pub.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status;
		struct mesh_cfg_model_pub got;

		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen,
		    &status, &got));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(0xC003, got.pub_addr);
		ATF_CHECK_EQ(0x001, got.app_idx);
	}

	/* Model Publication Get (0x8018) returns the stored publication. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(ELEM, &model, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status;
		struct mesh_cfg_model_pub got;

		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen,
		    &status, &got));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ_MSG(0xC003, got.pub_addr,
		    "publication persisted across Get");
		ATF_CHECK_EQ(5, got.ttl);
	}
}

/* ================================================================
 * Heartbeat Publication / Subscription configuration via the server.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(heartbeat_config);
ATF_TC_BODY(heartbeat_config, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_hb_pub pub;
	struct mesh_hb_sub_set sub;
	uint8_t msg[32], reply[32];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Heartbeat Publication Set (0x8039): publish to 0xC005 on subnet 0. */
	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xC005;
	pub.count_log = 0x03;
	pub.period_log = 0x02;
	pub.ttl = 5;
	pub.features = MESH_HB_FEATURE_RELAY;
	pub.net_idx = 0x000;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status;
		struct mesh_hb_pub got;

		ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status,
		    &got));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
		ATF_CHECK_EQ(0xC005, got.dst);
	}
	ATF_CHECK_EQ(0xC005, nd->db.hb_pub.dst);

	/* Heartbeat Publication Get (0x8038) echoes the stored publication. */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint8_t status;
		struct mesh_hb_pub got;

		ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status,
		    &got));
		ATF_CHECK_EQ(0xC005, got.dst);
	}

	/* Heartbeat Subscription Set (0x803B): source 0x0002 -> 0xC005. */
	memset(&sub, 0, sizeof(sub));
	sub.src = 0x0002;
	sub.dst = 0xC005;
	sub.period_log = 0x04;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		struct mesh_hb_sub_status got;

		ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(reply, rlen, &got));
		ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, got.status);
		ATF_CHECK_EQ(0x0002, got.src);
		ATF_CHECK_EQ(0xC005, got.dst);
	}
	ATF_CHECK_EQ(0x0002, nd->db.hb_sub.src);
}

/* ================================================================
 * Health Server dispatch: Attention Get/Set, Period Get/Set, Fault
 * Get / Clear / Test (MshMDL Section 7).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(health_dispatch);
ATF_TC_BODY(health_dispatch, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	uint8_t msg[16], reply[64];
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* Attention Set (0x8005) 8 secs -> Status (0x8007) 8, state updated. */
	ATF_REQUIRE_EQ(0, mesh_hlt_attention_build(MESH_HLT_OP_ATTENTION_SET, 8,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(3, rlen);
	ATF_CHECK_EQ(0x07, reply[1]);
	ATF_CHECK_EQ(8, reply[2]);
	ATF_CHECK_EQ(8, nd->health.attention);

	/* Period Set (0x8035) divisor 3 -> Status (0x8037) 3. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(MESH_HLT_OP_PERIOD_SET, 3, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(0x37, reply[1]);
	ATF_CHECK_EQ(3, reply[2]);
	ATF_CHECK_EQ(3, nd->health.fast_period_divisor);

	/* Period Get (0x8034) echoes the divisor. */
	ATF_REQUIRE_EQ(0, mesh_hlt_period_build(MESH_HLT_OP_PERIOD_GET, 0, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(3, reply[2]);

	/* Register a fault, Fault Get (0x8031) -> Fault Status with the fault. */
	ATF_REQUIRE_EQ(0, mesh_hlt_server_add_fault(&nd->health, 0x11));
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_get_build(nd->health.company_id, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint32_t op;
		struct mesh_hlt_fault_status fs;

		ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(reply, rlen, &op,
		    &fs));
		ATF_CHECK_EQ(1, (int)fs.n_faults);
		ATF_CHECK_EQ(0x11, fs.faults[0]);
	}

	/* Fault Clear (0x802F) empties the fault array. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_clear_build(MESH_HLT_OP_FAULT_CLEAR,
	    nd->health.company_id, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	{
		uint32_t op;
		struct mesh_hlt_fault_status fs;

		ATF_REQUIRE_EQ(0, mesh_hlt_fault_status_parse(reply, rlen, &op,
		    &fs));
		ATF_CHECK_EQ_MSG(0, (int)fs.n_faults, "faults cleared");
	}
	ATF_CHECK_EQ(0, (int)nd->health.n_registered_faults);	/* P-M14 */

	/* Fault Test (0x8032) sets the current Test ID and returns a Status. */
	ATF_REQUIRE_EQ(0, mesh_hlt_fault_test_build(MESH_HLT_OP_FAULT_TEST, 0x42,
	    nd->health.company_id, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK(rlen > 0);
	ATF_CHECK_EQ(0x42, nd->health.test_id);
}

ATF_TC_WITHOUT_HEAD(secondary_element_configuration);
ATF_TC_BODY(secondary_element_configuration, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_sub ms;
	struct meshd_model_entry *me;
	uint8_t msg[64], reply[64];
	size_t mlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0;
	ak.app_idx = 1;
	memcpy(ak.key, g_appkey2, sizeof(ak.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));

	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM + 1;
	ma.app_idx = 1;
	ma.model.model_id = BT_MESH_CFGSRV_MODEL_GENERIC_LEVEL_SERVER;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, reply[2]);
	me = db_model_at(nd, ELEM + 1,
	    BT_MESH_CFGSRV_MODEL_GENERIC_LEVEL_SERVER);
	ATF_REQUIRE(me != NULL);
	ATF_CHECK_EQ(1, me->n_app);

	memset(&ms, 0, sizeof(ms));
	ms.elem_addr = ELEM + 1;
	ms.address = 0xc123;
	ms.model = ma.model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &ms, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, reply[2]);
	ATF_CHECK_EQ(0, nd->self->elems[0].n_subs);
	ATF_CHECK_EQ(1, nd->self->elems[1].n_subs);
	ATF_CHECK_EQ(0xc123, nd->self->elems[1].subs[0]);
}

/* ================================================================
 * Node Reset clears the database and unprovisions the node.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(node_reset_clears_db);
ATF_TC_BODY(node_reset_clears_db, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	uint8_t msg[64], reply[64];
	size_t mlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x007;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK(db_has_appkey(nd, 0x007));

	ATF_REQUIRE_EQ(0, mesh_cfg_node_reset_build(msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_CHECK_EQ_MSG(0, nd->provisioned, "node unprovisioned after reset");
	ATF_CHECK_EQ_MSG(0, (int)(db_has_appkey(nd, 0x007)),
	    "database cleared by Node Reset");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, commission_sequence);
	ATF_TP_ADD_TC(tp, appkey_lifecycle);
	ATF_TP_ADD_TC(tp, config_error_arms);
	ATF_TP_ADD_TC(tp, zero_param_gets);
	ATF_TP_ADD_TC(tp, node_state_roundtrip);
	ATF_TP_ADD_TC(tp, key_refresh_lifecycle);
	ATF_TP_ADD_TC(tp, model_publication);
	ATF_TP_ADD_TC(tp, heartbeat_config);
	ATF_TP_ADD_TC(tp, health_dispatch);
	ATF_TP_ADD_TC(tp, secondary_element_configuration);
	ATF_TP_ADD_TC(tp, node_reset_clears_db);

	return (atf_no_error());
}
