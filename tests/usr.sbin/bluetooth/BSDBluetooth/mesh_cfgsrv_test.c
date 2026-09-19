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
 * against the Mesh Protocol 1.1.1 wire layouts.
 *
 * The spec oracle is MshPRT_v1.1.1 Section 4.3 / 4.4.1 (message formats and
 * the Configuration Server behaviour) and Section 4.3.1.1 (key-index packing);
 * expected reply bytes are derived from the specification, never from captured
 * output.
 *
 * NOT MshMDL: in Mesh 1.1 the foundation models moved out of the Model
 * specification and into the Protocol specification.  MshMDL_v1.1.1 defines
 * none of the Configuration Server - `grep -ni netkey MshMDL_v1.1.1.txt`
 * returns nothing - so every MshMDL citation for foundation-model behaviour is
 * stale by construction.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "mesh_crypto.h"
#include "spec_mesh_cfgsrv_oracles.h"
#include "spec_extref_mesh_cfg_status_codes.h"

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
 * AppKey Update STAGES during Key Refresh Phase 1 (MshPRT_v1.1 Section 3.11.4
 * / MshMDL 4.3.2.38), TX-side: while staged the OLD AppKey stays live for
 * transmission, and the staged key is promoted (installed into the sim, i.e.
 * used for TX) only at the Phase 2 advance.  RX on the staged key during
 * Phase 1 is a documented limitation and is not asserted here.
 * ================================================================ */
static struct meshd_appkey_entry *
db_appkey(struct meshd_node *nd, uint16_t app_idx)
{
	size_t i;

	for (i = 0; i < MESHD_MAX_APPKEYS; i++) {
		if (nd->db.appkeys[i].valid &&
		    nd->db.appkeys[i].app_idx == app_idx)
			return (&nd->db.appkeys[i]);
	}
	return (NULL);
}

static struct mesh_sim_app_key *
sim_appkey(struct meshd_node *nd, uint16_t app_idx)
{
	size_t i;

	for (i = 0; i < nd->self->n_appkeys; i++) {
		if (nd->self->appkeys[i].valid &&
		    nd->self->appkeys[i].app_idx == app_idx)
			return (&nd->self->appkeys[i]);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(appkey_update_staging_tx);
ATF_TC_BODY(appkey_update_staging_tx, tc)
{
	static const uint8_t g_newnetkey[16] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_appkey_entry *ae;
	struct mesh_sim_app_key *sk;
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_netkey nk;
	uint8_t msg[64], reply[64];
	uint8_t status, phase;
	uint16_t net_idx, app_idx;
	size_t mlen, rlen;

	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* AppKey Add app_idx 2 with the OLD application key. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x002;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_REQUIRE_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ae = db_appkey(nd, 0x002);
	ATF_REQUIRE(ae != NULL);

	/* AppKey Update OUTSIDE Phase 1 with a different key is refused. */
	memcpy(ak.key, g_appkey2, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_CANNOT_UPDATE, status);
	ATF_CHECK_EQ(0, ae->has_new_key);

	/* NetKey Update drives the subnet into Key Refresh Phase 1. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x000;
	memcpy(nk.key, g_newnetkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(MESH_CFG_KR_PHASE_1, mesh_sim_node_kr_phase(nd->self));

	/* AppKey Update in Phase 1: SUCCESS, key STAGED, old key stays live. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_CHECK_EQ(1, ae->has_new_key);
	ATF_CHECK_EQ(0, memcmp(ae->key, g_appkey, 16));	/* old key still current */
	ATF_CHECK_EQ(0, memcmp(ae->new_key, g_appkey2, 16));
	/* TX-side: the sim (transmit) key is still the OLD AppKey. */
	sk = sim_appkey(nd, 0x002);
	ATF_REQUIRE(sk != NULL);
	ATF_CHECK_EQ(0, memcmp(sk->key, g_appkey, 16));

	/* Re-sending the SAME staged key is idempotent... */
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	/* ...while a DIFFERENT key cannot change the refresh. */
	ak.key[0] ^= 1;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &net_idx, &app_idx));
	ATF_CHECK_EQ(MESH_CFG_CANNOT_UPDATE, status);
	ATF_CHECK_EQ(0, memcmp(ae->new_key, g_appkey2, 16));

	/*
	 * Phase 2 switches TRANSMISSION to the new AppKey and keeps BOTH keys
	 * live for reception (MshPRT_v1.1.1 Section 3.11.4.2: "the node shall
	 * only transmit messages ... using the new keys, shall receive messages
	 * using the old keys and the new keys").  The old key is therefore
	 * still stored, and still the current one in the database, until
	 * Phase 3.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_2, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_REQUIRE_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_REQUIRE_EQ(MESH_CFG_KR_PHASE_2, phase);
	ATF_CHECK_EQ(1, ae->has_new_key);
	ATF_CHECK_EQ(0, memcmp(ae->key, g_appkey, 16));
	sk = sim_appkey(nd, 0x002);
	ATF_REQUIRE(sk != NULL);
	ATF_CHECK_EQ_MSG(1, sk->have_new_key,
	    "Phase 2 keeps the old AppKey as a receive candidate");
	ATF_CHECK_EQ(0, memcmp(sk->key, g_appkey, 16));
	ATF_CHECK_EQ(0, memcmp(sk->new_key, g_appkey2, 16));

	/*
	 * Phase 3 revokes the old keys (Section 3.11.4.3): the staged AppKey
	 * becomes the only one, in the database and in the transport.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_3, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_REQUIRE_EQ(BT_MESH_CFGSRV_SUCCESS, status);
	ATF_CHECK_EQ(0, ae->has_new_key);
	ATF_CHECK_EQ(0, memcmp(ae->key, g_appkey2, 16));
	sk = sim_appkey(nd, 0x002);
	ATF_REQUIRE(sk != NULL);
	ATF_CHECK_EQ(0, sk->have_new_key);
	ATF_CHECK_EQ(0, memcmp(sk->key, g_appkey2, 16));
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

	/*
	 * ...and it must be BOUND to the model.  MshPRT_v1.1.1 Table 4.313
	 * makes "the AppKey identified by AppKeyIndex is not known to the node
	 * or is not bound to the model identified by the ModelIdentifier" an
	 * Invalid AppKey Index error, so a publication cannot be configured
	 * against a key the model has no binding for.  This fixture previously
	 * omitted the bind and expected Success; the round trip it exercises is
	 * unchanged, and the refusal path it used to depend on is now asserted
	 * on its own by model_publication_appkey_must_be_bound below.
	 */
	{
		struct mesh_cfg_model_app ma;

		memset(&ma, 0, sizeof(ma));
		ma.elem_addr = ELEM;
		ma.app_idx = 0x001;
		ma.model = model;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(
		    MESH_CFG_OP_MODEL_APP_BIND, &ma, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	}

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
	/*
	 * CONTRACT CHANGE (round-3 finding 4): the Heartbeat Subscription is
	 * kept only on the sim node - the copy mesh_hb_sub_receive() counts
	 * into - so the Status's Count/MinHops/MaxHops actually move.  The old
	 * meshd-side nd->db.hb_sub copy is gone.
	 */
	ATF_CHECK_EQ(0x0002, nd->self->hb_sub.src);
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

/* ================================================================
 * Round-3 finding 4: the Heartbeat Subscription Status must report the LIVE
 * received-message counters.  The Status was rendered from a meshd-side copy
 * (nd->db.hb_sub) while only the sim node's copy (nd->self->hb_sub, fed by
 * mesh_hb_sub_receive) ever counted anything, so Count/MinHops/MaxHops were
 * permanently 0x0000 / 0x7F / 0x00.  Finding 10 additionally requires that a
 * REJECTED Set leave a live subscription (and its counters) untouched, instead
 * of destroying it while answering Invalid Address.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(heartbeat_subscription_counts);
ATF_TC_BODY(heartbeat_subscription_counts, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_hb_sub_set sub;
	struct mesh_hb_sub_status got;
	uint8_t msg[16], reply[64];
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	memset(&sub, 0, sizeof(sub));
	sub.src = 0x0002;
	sub.dst = 0xC005;
	sub.period_log = 0x08;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(reply, rlen, &got));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, got.status);
	ATF_CHECK_EQ(1, nd->self->hb_sub_active);

	/* Two Heartbeats arrive at 1 and 3 hops. */
	ATF_REQUIRE_EQ(1, mesh_hb_sub_receive(&nd->self->hb_sub, 0x0002,
	    0xC005, 0x7f, 0x7f));
	ATF_REQUIRE_EQ(1, mesh_hb_sub_receive(&nd->self->hb_sub, 0x0002,
	    0xC005, 0x7f, 0x7d));

	/* The Status now reports them. */
	ATF_REQUIRE_EQ(0, mesh_hb_sub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(reply, rlen, &got));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, got.status);
	ATF_CHECK_EQ(0x0002, got.src);
	ATF_CHECK_EQ(0xC005, got.dst);
	ATF_CHECK_EQ_MSG(0x02, got.count_log, "two Heartbeats were counted");
	ATF_CHECK_EQ(1, got.min_hops);
	ATF_CHECK_EQ(3, got.max_hops);

	/*
	 * A Set with a Prohibited Source (a group address) is answered Invalid
	 * Address and must NOT destroy the live subscription or its counters
	 * (finding 10: mesh_hb_sub_apply used to memset before validating).
	 */
	{
		uint8_t params[5];

		/*
		 * mesh_hb_sub_set_build() refuses to emit a Prohibited Source,
		 * so build the wire form by hand - this is what a
		 * non-conforming peer would send.
		 */
		params[0] = 0x01; params[1] = 0xC0;	/* src 0xC001, group */
		params[2] = 0x05; params[3] = 0xC0;	/* dst 0xC005 */
		params[4] = 0x08;			/* PeriodLog */
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
		    MESH_CFG_OP_HB_SUB_SET, params, sizeof(params), msg,
		    &mlen));
	}
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(reply, rlen, &got));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_INVALID_ADDRESS, got.status);
	ATF_CHECK_EQ_MSG(0x0002, nd->self->hb_sub.src,
	    "a rejected Set leaves the live subscription intact");
	ATF_CHECK_EQ(2, nd->self->hb_sub.count);
	ATF_CHECK_EQ(1, nd->self->hb_sub.min_hops);
	ATF_CHECK_EQ(3, nd->self->hb_sub.max_hops);

	/* The disabling form (Source 0) is accepted and resets the counters. */
	sub.src = 0x0000;
	sub.dst = 0x0000;
	sub.period_log = 0x00;
	ATF_REQUIRE_EQ(0, mesh_hb_sub_set_build(&sub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_sub_status_parse(reply, rlen, &got));
	ATF_CHECK_EQ(BT_MESH_CFGSRV_SUCCESS, got.status);
	ATF_CHECK_EQ(0, nd->self->hb_sub.count);
	ATF_CHECK_EQ(0, got.min_hops);
	ATF_CHECK_EQ(0, got.max_hops);
	meshd_node_fini(nd);
}


/* ================================================================
 * IM19 / IM15: the Model Publication AppKeyIndex must be bound to the model,
 * and a refused Set zeroes every field it did not store.
 * ================================================================ */
/*
 * MshPRT_v1.1.1 Table 4.313, error conditions for the Model Publication state:
 * "The AppKey identified by AppKeyIndex is not known to the node OR IS NOT
 * BOUND TO THE MODEL identified by the ModelIdentifier" -> Invalid AppKey
 * Index.  Validating only the node-wide AppKey list answers Success to a
 * set-publication-before-bind and the model then never publishes: the access
 * layer's per-model binding check (Section 3.7.3, Figure 3.72) drops every
 * publish, with the Configuration Client believing it configured the node.
 *
 * And Section 4.4.1.2.7: a Config Model Publication Set "that is not
 * successfully processed ... shall respond with a Config Model Publication
 * Status message setting the ElementAddress and ModelIdentifier fields to the
 * corresponding fields of the incoming message, setting the Status field to a
 * status code ... AND SETTING ALL OTHER FIELDS TO 0x00".  Echoing the
 * requested PublishAddress, AppKeyIndex, TTL, period and retransmit back with
 * a failure status reports state the node never stored - the request was
 * refused - which every negative publication cell on a conformance tester
 * reads as state.
 *
 * Driven through meshd_foundation_recv(), the daemon's Configuration Server
 * entry point.
 */
ATF_TC_WITHOUT_HEAD(model_publication_appkey_must_be_bound);
ATF_TC_BODY(model_publication_appkey_must_be_bound, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_pub pub, got;
	struct mesh_cfg_model_id model = onoff_model();
	uint8_t msg[64], reply[64], status;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* The AppKey is known to the node, but bound to no model. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

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
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_INVALID_APPKEY_INDEX, status,
	    "Table 4.313: an AppKey not bound to the model is Invalid AppKey "
	    "Index, not Success");

	/* IM15: the refusal echoes only ElementAddress and ModelIdentifier. */
	ATF_CHECK_EQ_MSG(ELEM, got.elem_addr, "ElementAddress is echoed");
	ATF_CHECK_EQ_MSG(model.model_id, got.model.model_id,
	    "ModelIdentifier is echoed");
	ATF_CHECK_EQ_MSG(0u, got.pub_addr,
	    "a refused Set stored no PublishAddress and must report none");
	ATF_CHECK_EQ_MSG(0u, got.app_idx, "AppKeyIndex must be zeroed");
	ATF_CHECK_EQ_MSG(0u, got.ttl, "PublishTTL must be zeroed");
	ATF_CHECK_EQ_MSG(0u, got.period, "PublishPeriod must be zeroed");
	ATF_CHECK_EQ_MSG(0u, got.retransmit,
	    "PublishRetransmit must be zeroed");

	/* And nothing was stored: a Get reports an unassigned publication. */
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(ELEM, &model, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ_MSG(0u, got.pub_addr, "the refused Set stored nothing");

	/* Once the key is bound to the model, the same Set succeeds. */
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x001;
	ma.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_SUCCESS, status,
	    "a bound AppKeyIndex is accepted");
	ATF_CHECK_EQ(0xC003, got.pub_addr);
	ATF_CHECK_EQ(0x001, got.app_idx);
	ATF_CHECK_EQ(5, got.ttl);

	meshd_node_fini(nd);
}


/* ================================================================
 * IM16 / IM24 / IM31: the Heartbeat Publication Status.
 * ================================================================ */
/*
 * Three sentences of MshPRT_v1.1.1 Section 4.4.1.2.15, each its own defect.
 *
 * IM16 - Table 4.323 maps the CountLog field value to the Heartbeat
 * Publication Count state: 0x11 is 0xFFFE and 0xFF is 0xFFFF.  Section 4.2.18.2
 * decrements a Count "greater than or equal to 0x0001 or less than or equal to
 * 0xFFFE" after each publication and never decrements 0xFFFF, so 0x11 is a
 * BOUNDED 65534-message heartbeat and 0xFF is an unbounded one.  Decoding 0x11
 * as 0xFFFF turns the first into the second, and it shows in the very next
 * Status because 0xFFFF re-encodes to a CountLog of 0xFF.
 *
 * IM24 - "When an element receives a Config Heartbeat Publication Set message
 * that is not successfully processed ... it shall respond with a Config
 * Heartbeat Publication Status message, setting the Destination, CountLog,
 * PeriodLog, and TTL fields to the values of corresponding fields of the
 * incoming message."  Note that this is the OPPOSITE of the Model Publication
 * rule in Section 4.4.1.2.7, which zeroes the fields of a refused request;
 * both are "shall", and each has to be implemented as written.
 *
 * IM31 - "When the Destination field is set to the unassigned address, the
 * values of the CountLog, PeriodLog, TTL, and Features fields shall be set to
 * 0x00 and NetKeyIndex field shall be set to 0x0000."
 *
 * Driven through meshd_foundation_recv(), the daemon's Configuration Server
 * entry point.
 */
ATF_TC_WITHOUT_HEAD(heartbeat_publication_status_fields);
ATF_TC_BODY(heartbeat_publication_status_fields, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_hb_pub pub, got;
	uint8_t msg[32], reply[64], status;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* IM16: a CountLog of 0x11 is a bounded count and reads back as 0x11. */
	memset(&pub, 0, sizeof(pub));
	pub.dst = 0xC005;
	pub.count_log = 0x11;
	pub.period_log = 0x05;
	pub.ttl = 7;
	pub.features = MESH_HB_FEATURE_RELAY;
	pub.net_idx = cfg.netkey_index;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ_MSG(0x11, got.count_log,
	    "Table 4.323: CountLog 0x11 is the Count state 0xFFFE, a bounded "
	    "65534-message heartbeat, and must not read back as the unbounded "
	    "0xFF");
	ATF_CHECK_EQ(0xC005, got.dst);

	/* A Get agrees. */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ_MSG(0x11, got.count_log, "the Get reports it too");

	/*
	 * IM24: a Set naming a NetKeyIndex the node does not hold is refused
	 * with Invalid NetKey Index (Table 4.321), and the Status echoes the
	 * INCOMING Destination, CountLog, PeriodLog and TTL - not the state
	 * that is still configured from the accepted Set above.
	 */
	pub.dst = 0xC009;
	pub.count_log = 0x03;
	pub.period_log = 0x02;
	pub.ttl = 4;
	pub.net_idx = 0x0AB;		/* not a subnet this node holds */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ_MSG(MESH_CFG_INVALID_NETKEY_INDEX, status,
	    "an unknown NetKeyIndex is refused");
	ATF_CHECK_EQ_MSG(0xC009, got.dst,
	    "a refused Set echoes the incoming Destination");
	ATF_CHECK_EQ_MSG(0x03, got.count_log,
	    "a refused Set echoes the incoming CountLog");
	ATF_CHECK_EQ_MSG(0x02, got.period_log,
	    "a refused Set echoes the incoming PeriodLog");
	ATF_CHECK_EQ_MSG(4, got.ttl,
	    "a refused Set echoes the incoming TTL");

	/* The refusal changed nothing: the earlier publication still stands. */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ(0xC005, got.dst);

	/*
	 * IM31: disabling the publication with an unassigned Destination zeroes
	 * CountLog, PeriodLog, TTL, Features and NetKeyIndex in the Status,
	 * rather than reading back a period and a TTL for a publication that
	 * will never be sent.
	 */
	memset(&pub, 0, sizeof(pub));
	pub.dst = MESH_ADDR_UNASSIGNED;
	pub.count_log = 0x04;
	pub.period_log = 0x06;
	pub.ttl = 6;
	pub.features = MESH_HB_FEATURE_FRIEND;
	pub.net_idx = cfg.netkey_index;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ(MESH_CFG_SUCCESS, status);
	ATF_CHECK_EQ(MESH_ADDR_UNASSIGNED, got.dst);
	ATF_CHECK_EQ_MSG(0u, got.count_log, "CountLog is zeroed when disabled");
	ATF_CHECK_EQ_MSG(0u, got.period_log,
	    "PeriodLog is zeroed when disabled");
	ATF_CHECK_EQ_MSG(0u, got.ttl, "TTL is zeroed when disabled");
	ATF_CHECK_EQ_MSG(0u, got.features, "Features are zeroed when disabled");
	ATF_CHECK_EQ_MSG(0u, got.net_idx, "NetKeyIndex is zeroed when disabled");

	/* And the Get reports the same zeroed view. */
	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ(MESH_ADDR_UNASSIGNED, got.dst);
	ATF_CHECK_EQ_MSG(0u, got.period_log, "the Get reports it too");
	ATF_CHECK_EQ_MSG(0u, got.ttl, "the Get reports it too");

	meshd_node_fini(nd);
}

/* ================================================================
 * IM21: Config AppKey Add for an AppKeyIndex already bound to a DIFFERENT
 * NetKeyIndex answers Invalid NetKey Index, not Invalid Binding.
 *
 * MshPRT_v1.1.1 Table 4.317 carries both rows, and they are scoped to
 * different messages, verbatim:
 *   "The NetKeyIndexAndAppKeyIndex combination is not valid for a Config
 *    AppKey Update message"                              -> Invalid Binding
 *   "The key identified by the AppKeyIndex is already bound to a different
 *    NetKeyIndex for a Config AppKey Add message"        -> Invalid NetKey Index
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(im21_appkey_add_rebind_status);
ATF_TC_BODY(im21_appkey_add_rebind_status, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	struct mesh_cfg_appkey ak;
	uint8_t msg[64], reply[64], status;
	uint16_t got_net, got_app;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* A second subnet to rebind onto. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x001;
	memset(nk.key, 0x5b, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/* AppKey 0x001 bound to subnet 0. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey2, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	/* THE GATE: the same AppKeyIndex, offered against subnet 1. */
	ak.net_idx = 0x001;
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &got_net, &got_app));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_INVALID_NETKEY_INDEX, status,
	    "Table 4.317: a rebinding Add is Invalid NetKey Index (0x04)");
	ATF_CHECK_MSG(status != SPEC_EXTREF_MESH_STATUS_INVALID_BINDING,
	    "Invalid Binding (0x11) is scoped to a Config AppKey Update");
	/* Section 4.4.1.2.10 echoes the incoming key-index pair. */
	ATF_CHECK_EQ(0x001, got_net);
	ATF_CHECK_EQ(0x001, got_app);

	/* The Update arm keeps Invalid Binding for the same shape. */
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE,
	    &ak, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_status_parse(reply, rlen, &status,
	    &got_net, &got_app));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_INVALID_BINDING, status,
	    "Table 4.317: for an Update the same shape IS Invalid Binding");

	meshd_node_fini(nd);
}

/* ================================================================
 * IM22: Config NetKey Update legality, MshPRT_v1.1.1 Section 3.11.4, verbatim:
 *
 *   "The node shall successfully process a Config NetKey Update message for a
 *    valid NetKeyIndex if one of the following conditions is met:
 *    - The Key Refresh procedure has not been started and the received NetKey
 *      value is different from the current NetKey value.
 *    - The Key Refresh procedure is in Phase 1 and the received NetKey value
 *      is the same as the new NetKey value.
 *    Otherwise, the Config NetKey Update message shall generate an error."
 *
 * Table 4.316 supplies the error: "The requested update operation cannot be
 * performed due to general constraints" -> Cannot Update.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(im22_netkey_update_legality);
ATF_TC_BODY(im22_netkey_update_legality, tc)
{
	static const uint8_t newkey[16] = {
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0
	};
	static const uint8_t otherkey[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	uint8_t msg[64], reply[64], status, phase;
	uint16_t net_idx;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x000;

	/*
	 * THE GATE, part one.  Phase 0 with the CURRENT key: condition 1
	 * requires a DIFFERENT value, so neither condition is met.  This
	 * answered Success in every phase.
	 */
	memcpy(nk.key, g_netkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_CANNOT_UPDATE, status,
	    "an Update carrying the current key is not a legal Update");
	ATF_CHECK_EQ_MSG(MESH_KR_PHASE_NORMAL,
	    mesh_sim_node_kr_phase(nd->self),
	    "and it must not have started a Key Refresh");

	/* Condition 1 met: Phase 0, different key -> Phase 1. */
	memcpy(nk.key, newkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(SPEC_EXTREF_MESH_STATUS_SUCCESS, status);
	ATF_REQUIRE_EQ(MESH_KR_PHASE_1, mesh_sim_node_kr_phase(nd->self));

	/* Condition 2 met: Phase 1, the same new key -> Success, idempotent. */
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(SPEC_EXTREF_MESH_STATUS_SUCCESS, status);

	/* Phase 1 with a THIRD key: condition 2 not met. */
	memcpy(nk.key, otherkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ(SPEC_EXTREF_MESH_STATUS_CANNOT_UPDATE, status);

	/* Advance to Phase 2. */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_2, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_REQUIRE_EQ(MESH_CFG_KR_PHASE_2, phase);

	/*
	 * THE GATE, part two.  Phase 2 carrying the STAGED key: condition 2
	 * requires Phase 1, so this is an error.  "Do I hold a staged key?" as
	 * a proxy for the phase answered Success here, and a Configuration
	 * Manager sequencing on it believed it had distributed a key.
	 */
	memcpy(nk.key, newkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_CANNOT_UPDATE, status,
	    "an Update in Phase 2 meets neither Section 3.11.4 condition");

	meshd_node_fini(nd);
}

/* ================================================================
 * IM38: Config Key Refresh Phase Set answers Success only for a transition
 * Table 4.31 actually defines.
 *
 * Table 4.31's rows are (Old State, Transition): (0x00, 0x03), (0x01, 0x02),
 * (0x01, 0x03), (0x02, 0x02) and (0x02, 0x03).  Section 4.3.2.59 on the
 * Transition field, verbatim: "The Transition field shall identify the Key
 * Refresh Phase Transitions (see Section 4.2.15, Table 4.31) allowed for each
 * given starting state.  All other transition values are Prohibited."  The one
 * pair absent from the table is (0x00, 0x02).
 *
 * Section 4.3.2.60 pins the two no-op rows that ARE in the table, verbatim:
 * "The Status Code shall be Success if the received request was redundant (the
 * requested phase transition has already occurred), with no further action
 * taken."
 *
 * INTERPRETATION: Table 4.320 lists only Invalid NetKey Index, so the
 * specification supplies no status code for a Prohibited Transition; Cannot
 * Update is chosen (Zephyr's answer; BlueZ answers nothing).  Section
 * 4.4.1.2.14 fixes the Phase field of a failing Status at 0x00.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(im38_kr_phase_set_transition_table);
ATF_TC_BODY(im38_kr_phase_set_transition_table, tc)
{
	static const uint8_t newkey[16] = {
		0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0
	};
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	uint8_t msg[64], reply[64], status, phase;
	uint16_t net_idx;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/*
	 * THE GATE: (Old State 0x00, Transition 0x02) is the one pair Table
	 * 4.31 does not define.  It answered Success with the phase unchanged.
	 */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_2, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_CANNOT_UPDATE, status,
	    "Transition 2 from Phase 0 is not a row of Table 4.31");
	ATF_CHECK_EQ_MSG(MESH_CFG_KR_PHASE_0, phase,
	    "Section 4.4.1.2.14: a failing Status carries Phase 0x00");
	ATF_CHECK_EQ(0x000, net_idx);

	/* (0x00, 0x03) IS a row - "does not cause any state change" - Success. */
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_3, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "Transition 3 from Phase 0 is a defined no-op row");
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_0, phase);

	/* (0x01, 0x02) -> 0x02, and then (0x02, 0x02) is a defined no-op. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x000;
	memcpy(nk.key, newkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE,
	    &nk, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_set_build(0x000,
	    MESH_CFG_KR_TRANSITION_2, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ(SPEC_EXTREF_MESH_STATUS_SUCCESS, status);
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, phase);

	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_kr_phase_status_parse(reply, rlen, &status,
	    &net_idx, &phase));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "Transition 2 from Phase 2 is a defined no-op row");
	ATF_CHECK_EQ(MESH_CFG_KR_PHASE_2, phase);

	meshd_node_fini(nd);
}

/* ================================================================
 * IM33: a Prohibited Publish TTL never reaches the state, and never reaches
 * our own Status.
 *
 * MshPRT_v1.1.1 Section 4.2.3.5, Table 4.22: 0x00-0x7F is the value,
 * 0x80-0xFE is Prohibited, 0xFF is "Use Default TTL".  Table 4.313 defines no
 * error condition for a Prohibited Publish TTL, so the message is malformed
 * and is dropped without a Status rather than refused with one.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(im33_publish_ttl_prohibited);
ATF_TC_BODY(im33_publish_ttl_prohibited, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_pub pub, got;
	struct mesh_cfg_model_id model = onoff_model();
	uint8_t msg[64], reply[64], status;
	size_t mlen, rlen = 0;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* An AppKey bound to the model, so TTL is the only thing under test. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x001;
	ma.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = ELEM;
	pub.pub_addr = 0xC005;
	pub.app_idx = 0x001;
	pub.period = 0x40;
	pub.retransmit = 0x15;
	pub.model = model;

	/* The boundary values Table 4.22 allows. */
	pub.ttl = 0x7f;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "Publish TTL 0x7F is the top of the legal range");
	ATF_CHECK_EQ(0x7f, got.ttl);

	pub.ttl = 0xff;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "Publish TTL 0xFF is Use Default TTL");
	ATF_CHECK_EQ(0xff, got.ttl);

	/*
	 * THE GATE: the two ends and the middle of the Prohibited range.  Each
	 * must be dropped - no Status at all - and must leave the stored
	 * publication as the legal 0xFF Set left it.
	 */
	{
		static const uint8_t bad[] = { 0x80, 0xC0, 0xFE };
		size_t i;

		for (i = 0; i < sizeof(bad); i++) {
			pub.ttl = bad[i];
			ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub,
			    msg, &mlen));
			rlen = 0;
			/*
			 * meshd_foundation_recv() reports "no reply produced"
			 * as -1; the message is dropped at the codec, exactly
			 * as a malformed one is.
			 */
			ATF_CHECK_EQ_MSG(-1, meshd_foundation_recv(nd, msg,
			    mlen, reply, sizeof(reply), &rlen),
			    "Publish TTL 0x%02x is Prohibited (Table 4.22)",
			    bad[i]);
			ATF_CHECK_EQ_MSG(0u, (unsigned)rlen,
			    "a Prohibited Publish TTL must not be echoed in a "
			    "Config Model Publication Status");
		}
	}

	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(ELEM, &model, msg,
	    &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &got));
	ATF_CHECK_EQ_MSG(0xff, got.ttl,
	    "no Prohibited value may have reached the Publish TTL state");

	meshd_node_fini(nd);
}

/* ================================================================
 * IM35: Config NetKey Delete disables a Heartbeat Publication bound to the
 * deleted subnet.
 *
 * MshPRT_v1.1.1 Section 4.4.1.2.9, verbatim: "When NetKey used in Heartbeat
 * Publication is deleted as a result of the processing of the Config NetKey
 * Delete message, the Publication for the appropriate NetKey shall be
 * disabled."  Section 4.2.18.1 makes an unassigned Destination the disabled
 * state.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(im35_netkey_delete_disables_heartbeat);
ATF_TC_BODY(im35_netkey_delete_disables_heartbeat, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_netkey nk;
	struct mesh_hb_pub hp, got;
	uint8_t msg[64], reply[64], status;
	uint16_t net_idx;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* A second subnet, and a Heartbeat Publication bound to it. */
	memset(&nk, 0, sizeof(nk));
	nk.net_idx = 0x001;
	memset(nk.key, 0x6c, sizeof(nk.key));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &nk,
	    msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE(rlen > 2 && reply[2] == MESH_CFG_SUCCESS);

	memset(&hp, 0, sizeof(hp));
	hp.dst = 0xC00A;
	hp.count_log = 0x03;
	hp.period_log = 0x02;
	hp.ttl = 5;
	hp.features = 0x000f;
	hp.net_idx = 0x001;
	ATF_REQUIRE_EQ(0, mesh_hb_pub_set_build(&hp, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_REQUIRE_EQ(MESH_CFG_SUCCESS, status);
	ATF_REQUIRE_EQ(0xC00A, got.dst);
	ATF_REQUIRE_EQ(0x001, got.net_idx);
	ATF_REQUIRE_EQ(0xC00A, nd->self->hb_pub.dst);

	/*
	 * THE GATE.  Deleting subnet 1 must disable the publication.  The
	 * request is secured with the primary subnet, so the "shall not be
	 * deleted using a message secured with this NetKey" rule does not
	 * apply.
	 */
	nd->rx_secure_net_idx = 0x000;
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_delete_build(0x001, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_netkey_status_parse(reply, rlen, &status,
	    &net_idx));
	ATF_REQUIRE_EQ(SPEC_EXTREF_MESH_STATUS_SUCCESS, status);

	ATF_REQUIRE_EQ(0, mesh_hb_pub_get_build(msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_hb_pub_status_parse(reply, rlen, &status, &got));
	ATF_CHECK_EQ_MSG(MESH_ADDR_UNASSIGNED, got.dst,
	    "the publication must be disabled with the deleted NetKey");
	ATF_CHECK_EQ_MSG(0x000, got.net_idx,
	    "and must not keep reporting the deleted NetKey Index");
	ATF_CHECK_EQ_MSG(MESH_ADDR_UNASSIGNED, nd->self->hb_pub.dst,
	    "the engine's periodic Heartbeat timer must be disarmed too");

	meshd_node_fini(nd);
}

/* ================================================================
 * Finding 34: status codes 0x07 "Invalid Publish Parameters" (Table 4.313's
 * first row) and 0x08 "Not a Subscribe Model" (Table 4.315's first row).
 *
 * Neither table says WHICH models "do not support the publish mechanism" or
 * "do not support subscription mechanism".  The rule applied here is DERIVED,
 * not quoted, and the derivation is recorded in full beside
 * meshd_model_appkey_capable() in meshd_node.c:
 *
 *   MshPRT_v1.1.1 Section 3.7.3.2 delivers a message to a model instance only
 *   when "either the access layer security of the model instance is using
 *   application keys, and the model instance is bound to the AppKey ..., or
 *   the access layer security of the model is using the DevKey, and the DevKey
 *   was used to secure the message."  The arms are exclusive.  A publication
 *   needs an AppKey bound to the model (Table 4.313's Invalid AppKey Index
 *   row), and delivery to a subscribed group or virtual address sits under the
 *   application-key arm of that same disjunction.  So on a device-key-secured
 *   model both are structurally inert - stored, reported, never used.
 *
 * Section 4.4.1.1 fixes the Configuration Server's own security: "The access
 * layer security on the Configuration Server model shall use the device key."
 * Section 4.4.9.1 does the same for the Bridge Configuration Server.  Those
 * two are therefore the models this node advertises that can hold neither.
 * ================================================================ */

/* A model identifier for a SIG model id. */
static struct mesh_cfg_model_id
sig_model(uint16_t id)
{
	struct mesh_cfg_model_id m;

	memset(&m, 0, sizeof(m));
	m.model_id = id;
	m.vendor = 0;
	return (m);
}

ATF_TC_WITHOUT_HEAD(devkey_model_is_not_a_subscribe_model);
ATF_TC_BODY(devkey_model_is_not_a_subscribe_model, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_model_sub sub, st;
	struct mesh_cfg_model_sub_va sub_va;
	struct mesh_cfg_model_id model;
	struct meshd_model_entry *me;
	uint8_t msg[64], reply[128], status;
	uint16_t addrs[8], elem_addr;
	uint32_t op;
	size_t mlen, rlen, n, k;
	static const uint16_t devkey_models[] = {
		0x0000,			/* Configuration Server, §4.4.1.1 */
		0x0008,			/* Bridge Config Server, §4.4.9.1 */
	};

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	for (k = 0; k < nitems(devkey_models); k++) {
		model = sig_model(devkey_models[k]);
		me = db_model(nd, devkey_models[k]);
		ATF_REQUIRE_MSG(me != NULL, "model %04x must be registered",
		    devkey_models[k]);

		/* Subscription Add -> Not a Subscribe Model (Table 4.315). */
		memset(&sub, 0, sizeof(sub));
		sub.elem_addr = ELEM;
		sub.address = 0xC001;
		sub.model = model;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(
		    MESH_CFG_OP_MODEL_SUB_ADD, &sub, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(reply, rlen,
		    &status, &st));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_NOT_A_SUBSCRIBE_MODEL,
		    status, "model %04x Subscription Add status %02x",
		    devkey_models[k], status);
		ATF_CHECK_EQ_MSG(0u, (unsigned)me->n_subs,
		    "nothing may be stored on a refused subscription");

		/* Virtual-address Subscription Add: same table, same code. */
		memset(&sub_va, 0, sizeof(sub_va));
		sub_va.elem_addr = ELEM;
		memset(sub_va.label, 0x5a, sizeof(sub_va.label));
		sub_va.model = model;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_va_build(
		    MESH_CFG_OP_MODEL_SUB_VA_ADD, &sub_va, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(reply, rlen,
		    &status, &st));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_NOT_A_SUBSCRIBE_MODEL,
		    status, "model %04x Subscription VA Add status %02x",
		    devkey_models[k], status);
		ATF_CHECK_EQ_MSG(0u, (unsigned)me->n_subs,
		    "nothing may be stored on a refused subscription");

		/* Delete All. */
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_del_all_build(ELEM,
		    &model, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(reply, rlen,
		    &status, &st));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_NOT_A_SUBSCRIBE_MODEL,
		    status, "model %04x Subscription Delete All status %02x",
		    devkey_models[k], status);

		/* Subscription Get: the List message carries the same code. */
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_get_build(
		    MESH_CFG_OP_SIG_MODEL_SUB_GET, ELEM, &model, msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		n = 0;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_list_parse(reply, rlen,
		    &op, &status, &elem_addr, &model, addrs, nitems(addrs),
		    &n));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_NOT_A_SUBSCRIBE_MODEL,
		    status, "model %04x Subscription Get status %02x",
		    devkey_models[k], status);
	}

	meshd_node_fini(nd);
}

ATF_TC_WITHOUT_HEAD(devkey_model_has_invalid_publish_parameters);
ATF_TC_BODY(devkey_model_has_invalid_publish_parameters, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_model_pub pub, out;
	struct mesh_cfg_model_pub_va pub_va;
	struct mesh_cfg_model_id model;
	struct meshd_model_entry *me;
	uint8_t msg[64], reply[128], status;
	size_t mlen, rlen, k;
	static const uint16_t devkey_models[] = { 0x0000, 0x0008 };

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	for (k = 0; k < nitems(devkey_models); k++) {
		model = sig_model(devkey_models[k]);
		me = db_model(nd, devkey_models[k]);
		ATF_REQUIRE(me != NULL);

		/* Publication Set -> Invalid Publish Parameters. */
		memset(&pub, 0, sizeof(pub));
		pub.elem_addr = ELEM;
		pub.pub_addr = 0xC002;
		pub.app_idx = 0x000;
		pub.ttl = 0x07;
		pub.model = model;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg,
		    &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen,
		    &status, &out));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_INVALID_PUBLISH_PARAMS,
		    status, "model %04x Publication Set status %02x",
		    devkey_models[k], status);
		ATF_CHECK_EQ_MSG(0, me->has_pub,
		    "no publication may be stored on a refused Set");

		/* Virtual-address Publication Set: same row of Table 4.313. */
		memset(&pub_va, 0, sizeof(pub_va));
		pub_va.elem_addr = ELEM;
		memset(pub_va.label, 0x5a, sizeof(pub_va.label));
		pub_va.app_idx = 0x000;
		pub_va.ttl = 0x07;
		pub_va.model = model;
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_va_set_build(&pub_va, msg,
		    &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen,
		    &status, &out));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_INVALID_PUBLISH_PARAMS,
		    status, "model %04x Publication VA Set status %02x",
		    devkey_models[k], status);
		ATF_CHECK_EQ_MSG(0, me->has_pub,
		    "no publication may be stored on a refused Set");

		/*
		 * Publication Get.  Section 4.4.1.2.7: a Get "that is not
		 * successfully processed (i.e., it results in an error
		 * condition listed in Table 4.313)" answers with the Status
		 * carrying that code "and setting all other fields to 0x00".
		 */
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_get_build(ELEM, &model,
		    msg, &mlen));
		rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen,
		    &status, &out));
		ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_INVALID_PUBLISH_PARAMS,
		    status, "model %04x Publication Get status %02x",
		    devkey_models[k], status);
		ATF_CHECK_EQ_MSG(0u, (unsigned)out.pub_addr,
		    "all other fields are 0x00 on the error Status");
	}

	meshd_node_fini(nd);
}

/*
 * The control that keeps the derived rule honest: an AppKey-secured
 * application model keeps BOTH capabilities.  Section 3.7.3.2's application-key
 * arm applies to it, so a publication and a subscription on it are live state
 * and must still be accepted.
 */
ATF_TC_WITHOUT_HEAD(appkey_model_keeps_publish_and_subscribe);
ATF_TC_BODY(appkey_model_keeps_publish_and_subscribe, tc)
{
	struct meshd_config cfg;
	MESH_HEAP(struct meshd_node, nd);
	struct mesh_cfg_appkey ak;
	struct mesh_cfg_model_app ma;
	struct mesh_cfg_model_sub sub, st;
	struct mesh_cfg_model_pub pub, out;
	struct mesh_cfg_model_id model = onoff_model();
	uint8_t msg[64], reply[128], status;
	size_t mlen, rlen;

	(void)tc;
	base_config(&cfg);
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));

	/* AppKey Add + Model App Bind, so the publication has a bound key. */
	memset(&ak, 0, sizeof(ak));
	ak.net_idx = 0x000;
	ak.app_idx = 0x001;
	memcpy(ak.key, g_appkey, 16);
	ATF_REQUIRE_EQ(0, mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &ak,
	    msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));
	memset(&ma, 0, sizeof(ma));
	ma.elem_addr = ELEM;
	ma.app_idx = 0x001;
	ma.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND,
	    &ma, msg, &mlen));
	(void)deliver(nd, msg, mlen, reply, sizeof(reply));

	memset(&sub, 0, sizeof(sub));
	sub.elem_addr = ELEM;
	sub.address = 0xC003;
	sub.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD,
	    &sub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_sub_status_parse(reply, rlen, &status,
	    &st));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "an AppKey-secured model still subscribes (status %02x)", status);

	memset(&pub, 0, sizeof(pub));
	pub.elem_addr = ELEM;
	pub.pub_addr = 0xC004;
	pub.app_idx = 0x001;
	pub.ttl = 0x07;
	pub.model = model;
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_set_build(&pub, msg, &mlen));
	rlen = deliver(nd, msg, mlen, reply, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_cfg_model_pub_status_parse(reply, rlen, &status,
	    &out));
	ATF_CHECK_EQ_MSG(SPEC_EXTREF_MESH_STATUS_SUCCESS, status,
	    "an AppKey-secured model still publishes (status %02x)", status);

	meshd_node_fini(nd);
}


ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, commission_sequence);
	ATF_TP_ADD_TC(tp, devkey_model_is_not_a_subscribe_model);
	ATF_TP_ADD_TC(tp, devkey_model_has_invalid_publish_parameters);
	ATF_TP_ADD_TC(tp, appkey_model_keeps_publish_and_subscribe);
	ATF_TP_ADD_TC(tp, appkey_lifecycle);
	ATF_TP_ADD_TC(tp, config_error_arms);
	ATF_TP_ADD_TC(tp, zero_param_gets);
	ATF_TP_ADD_TC(tp, node_state_roundtrip);
	ATF_TP_ADD_TC(tp, key_refresh_lifecycle);
	ATF_TP_ADD_TC(tp, appkey_update_staging_tx);
	ATF_TP_ADD_TC(tp, model_publication);
	ATF_TP_ADD_TC(tp, model_publication_appkey_must_be_bound);
	ATF_TP_ADD_TC(tp, heartbeat_publication_status_fields);
	ATF_TP_ADD_TC(tp, heartbeat_config);
	ATF_TP_ADD_TC(tp, heartbeat_subscription_counts);
	ATF_TP_ADD_TC(tp, health_dispatch);
	ATF_TP_ADD_TC(tp, secondary_element_configuration);
	ATF_TP_ADD_TC(tp, node_reset_clears_db);
	ATF_TP_ADD_TC(tp, im21_appkey_add_rebind_status);
	ATF_TP_ADD_TC(tp, im22_netkey_update_legality);
	ATF_TP_ADD_TC(tp, im33_publish_ttl_prohibited);
	ATF_TP_ADD_TC(tp, im35_netkey_delete_disables_heartbeat);
	ATF_TP_ADD_TC(tp, im38_kr_phase_set_transition_table);

	return (atf_no_error());
}
