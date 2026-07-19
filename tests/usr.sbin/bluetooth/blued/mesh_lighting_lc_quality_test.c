/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <atf-c.h>
#include <string.h>

#include "mesh_lighting.h"
#include "spec_oracles.h"

/*
 * Local libmesh storage contract, not a Bluetooth Mesh wire requirement.
 * Keep these test-side values separate so a production-header change is
 * visible instead of silently resizing the test vectors with the code.
 */
#define TEST_LC_STORE_MAX_PROPERTIES	18
#define TEST_LC_STORE_VALUE_MAX		4

#define DEFINE_LC_OPCODE_ORACLE(name, value) \
	TEST_MESH_OP_LIGHT_LC_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHT_LC_OPCODES(DEFINE_LC_OPCODE_ORACLE)
};
#undef DEFINE_LC_OPCODE_ORACLE

static void
lc_fixture(struct mesh_light_lc_srv *lc, struct mesh_light_lightness_srv *ll,
    struct mesh_gen_onoff_srv *onoff, struct mesh_gen_level_srv *level,
    struct mesh_model *models, struct mesh_element *el)
{

	mesh_gen_onoff_srv_init(onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(level, 0);
	mesh_light_lightness_srv_init(ll, onoff, level);
	ll->last = 1000;
	mesh_light_lc_srv_init(lc, ll);
	models[0] = mesh_light_lc_srv_model(lc);
	models[1] = mesh_light_lc_setup_srv_model(lc);
	memset(el, 0, sizeof(*el));
	el->addr = 2;
	el->models = models;
	el->n_models = 2;
}

ATF_TC_WITHOUT_HEAD(lc_property_store_edges);
ATF_TC_BODY(lc_property_store_edges, tc)
{
	struct mesh_light_lc_srv lc;
	uint8_t value[TEST_LC_STORE_VALUE_MAX + 1];
	size_t i;

	ATF_CHECK_EQ(TEST_LC_STORE_MAX_PROPERTIES,
	    MESH_LIGHT_LC_MAX_PROPERTIES);
	ATF_CHECK_EQ(TEST_LC_STORE_VALUE_MAX,
	    MESH_LIGHT_LC_PROPERTY_VALUE_MAX);
	mesh_light_lc_srv_init(&lc, NULL);
	/* 0xA5 and the property IDs are non-normative storage sentinels. */
	memset(value, 0xa5, sizeof(value));

	ATF_CHECK_EQ(-1, mesh_light_lc_property_set(NULL, 1, value, 1));
	ATF_CHECK_EQ(-1, mesh_light_lc_property_set(&lc, 0, value, 1));
	ATF_CHECK_EQ(-1, mesh_light_lc_property_set(&lc, 1, NULL, 1));
	ATF_CHECK_EQ(-1, mesh_light_lc_property_set(&lc, 1, value,
	    sizeof(value)));

	for (i = 0; i < TEST_LC_STORE_MAX_PROPERTIES; i++) {
		value[0] = (uint8_t)i;
		ATF_REQUIRE_EQ(0, mesh_light_lc_property_set(&lc,
		    (uint16_t)(0x100 + i), value, 1));
	}
	ATF_CHECK_EQ(TEST_LC_STORE_MAX_PROPERTIES, lc.n_properties);
	ATF_CHECK_EQ(-1, mesh_light_lc_property_set(&lc, 0x200, value, 1));

	value[0] = 0x11;
	value[1] = 0x22;
	ATF_REQUIRE_EQ(0, mesh_light_lc_property_set(&lc, 0x100, value, 2));
	ATF_CHECK_EQ(TEST_LC_STORE_MAX_PROPERTIES, lc.n_properties);
	ATF_CHECK_EQ(2, lc.properties[0].len);
	ATF_CHECK_EQ(0x11, lc.properties[0].value[0]);
	ATF_CHECK_EQ(0x22, lc.properties[0].value[1]);
	ATF_REQUIRE_EQ(0, mesh_light_lc_property_set(&lc, 0x100, NULL, 0));
	ATF_CHECK_EQ(0, lc.properties[0].len);
}

ATF_TC_WITHOUT_HEAD(lc_protocol_edges);
ATF_TC_BODY(lc_protocol_edges, tc)
{
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_lc_cli cli;
	struct mesh_light_lc_onoff_set set;
	struct mesh_light_lc_srv lc;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16], raw[8], value[BT_GSS_PERCEIVED_LIGHTNESS_SIZE] = {
	    0x34, 0x12 };
	uint8_t too_long[5] = { 0, 1, 2, 3, 4 };
	size_t plen;

#define CHECK_LC_OPCODE(name, value) \
	ATF_CHECK_EQ_MSG((value), MESH_OP_LIGHT_LC_##name, \
	    "Assigned Numbers Light LC " #name " opcode");
	BT_ASSIGNED_MESH_LIGHT_LC_OPCODES(CHECK_LC_OPCODE)
#undef CHECK_LC_OPCODE

	lc_fixture(&lc, &lightness, &onoff, &level, models, &el);
	mesh_light_lc_cli_init(&cli);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(TEST_MESH_OP_LIGHT_LC_MODE_GET, 0,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_MODE_STATUS, reply.opcode);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&cli, reply.opcode,
	    reply.params, reply.params_len));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_OFF, cli.mode);
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON + 1;
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_recv(&cli,
	    TEST_MESH_OP_LIGHT_LC_MODE_STATUS, raw,
	    BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_OFF, cli.mode);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_LIGHT_LC_OM_ENABLED, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_OM_SET_UNACK, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_OM_ENABLED, ap.params[0]);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_OM_ENABLED, lc.occupancy_mode);
	ATF_CHECK_EQ(0, reply.opcode);
	ATF_CHECK_EQ(0, reply.params_len);

	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_LIGHT_LC_MODE_ON + 1, 1, pdu, &plen));
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_LIGHT_LC_OM_ENABLED + 1, 1, pdu, &plen));

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_LIGHT_LC_MODE_ON, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_MODE_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_ON, ap.params[0]);

	memset(&set, 0, sizeof(set));
	set.light_onoff = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* TID 0x7a is a non-normative transaction sentinel. */
	set.tid = 0x7a;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&set, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_ONOFF_SET_BASE_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_ON, ap.params[0]);
	ATF_CHECK_EQ(0x7a, ap.params[1]);

	set.transition.has_transition = 1;
	set.transition.transition_time = BT_MMDL111_TRANSITION_ONE_SECOND;
	/* Delay 9 is a non-normative encoding sentinel (45 ms). */
	set.transition.delay = 9;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&set, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_ONOFF_SET_TRANSITION_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_ONE_SECOND, ap.params[2]);
	ATF_CHECK_EQ(9, ap.params[3]);
	set.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&set, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_light_onoff_set(NULL, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_get(TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    0, pdu, &plen));
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_property_set(
	    BT_MMDL111_LC_PROPERTY_ID_PROHIBITED, value, 1, 1, pdu,
	    &plen));
	cli.property_id = 0x1234;
	cli.property_len = 1;
	raw[0] = 0x00;
	raw[1] = 0x00;
	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_recv(&cli,
	    TEST_MESH_OP_LIGHT_LC_PROPERTY_STATUS, raw,
	    BT_MMDL111_LC_PROPERTY_ID_SIZE));
	ATF_CHECK_EQ(0x1234, cli.property_id);
	ATF_CHECK_EQ(1, cli.property_len);

	/* Mode and Occupancy Mode have exactly one parameter in MMDL 1.1. */
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* 0x55 is a non-normative trailing-octet sentinel. */
	raw[1] = 0x55;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_MODE_SET,
	    raw, 2, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	/* Light OnOff permits only the mandatory pair or the full optional pair. */
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* 0x56 is a non-normative TID sentinel. */
	raw[1] = 0x56;
	raw[2] = 0x01;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET, raw, 3, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	raw[2] = BT_MMDL111_TRANSITION_STEPS_MASK;
	raw[3] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET, raw,
	    BT_MMDL111_LC_ONOFF_SET_TRANSITION_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	/* A transitioning Light OnOff Status carries present, target, remaining. */
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_OFF;
	raw[1] = BT_MMDL111_LIGHT_LC_MODE_ON;
	raw[2] = BT_MMDL111_TRANSITION_ONE_SECOND;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&cli,
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS, raw,
	    BT_MMDL111_LC_ONOFF_STATUS_TRANSITION_LEN));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_OFF, cli.light_onoff);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_ON, cli.target_light_onoff);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_ONE_SECOND, cli.remaining_time);
	ATF_CHECK_EQ(1, cli.has_target);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, value,
	    sizeof(value), 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&cli, reply.opcode,
	    reply.params, reply.params_len));
	ATF_CHECK_EQ(BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, cli.property_id);
	ATF_CHECK_EQ(sizeof(value), cli.property_len);
	ATF_CHECK_EQ(0, memcmp(value, cli.property, sizeof(value)));

	/* 0x99 is a non-normative update sentinel within the uint16 value. */
	value[0] = 0x99;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, value, sizeof(value), 1,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&cli, reply.opcode,
	    reply.params, reply.params_len));
	ATF_CHECK_EQ(BT_GSS_PERCEIVED_LIGHTNESS_SIZE, cli.property_len);
	ATF_CHECK_EQ(0x99, cli.property[0]);
	ATF_CHECK_EQ(1, lc.n_properties);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, NULL, 0, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	ATF_REQUIRE_EQ(-1, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, too_long,
	    sizeof(too_long), 1, pdu, &plen));

	raw[0] = 0x2e;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_PROPERTY_SET,
	    raw, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	raw[0] = 0x00;
	raw[1] = 0x00;
	raw[2] = 0x99;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_PROPERTY_SET,
	    raw, 3, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	raw[0] = 0x2e;
	raw[1] = 0x00;
	memcpy(raw + 2, too_long, sizeof(too_long));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_PROPERTY_SET,
	    raw, 7, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, lc_property_store_edges);
	ATF_TP_ADD_TC(tp, lc_protocol_edges);
	return (atf_no_error());
}
